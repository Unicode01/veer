//go:build linux

package app

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestKernelFlowPurgeRetryStateRetainsFailedTargetsAndUnionsNewTargets(t *testing.T) {
	first := kernelFlowPurgeTarget{RuleID: 41, RuleRevision: 1001, IfIndex: 55}
	second := kernelFlowPurgeTarget{RuleID: 42, RuleRevision: 1002, IfIndex: 66}
	state := kernelFlowPurgeRetryState{}
	calls := 0

	corrections, deleted, err := state.run(map[kernelFlowPurgeTarget]struct{}{first: {}}, func(targets map[kernelFlowPurgeTarget]struct{}) (map[uint32]kernelRuleStats, int, error) {
		calls++
		if len(targets) != 1 {
			t.Fatalf("first purge target count = %d, want 1", len(targets))
		}
		if _, ok := targets[first]; !ok {
			t.Fatalf("first purge targets = %#v, want %#v", targets, first)
		}
		return map[uint32]kernelRuleStats{41: {TCPActiveConns: -1}}, 1, errors.New("partial purge")
	})
	if err == nil {
		t.Fatal("first purge error = nil, want failure")
	}
	if deleted != 1 || corrections[41].TCPActiveConns != -1 {
		t.Fatalf("first purge result = deleted:%d corrections:%+v, want partial result retained", deleted, corrections)
	}
	if _, ok := state.snapshot()[first]; !ok {
		t.Fatal("failed purge target was not retained")
	}

	corrections, deleted, err = state.run(map[kernelFlowPurgeTarget]struct{}{second: {}}, func(targets map[kernelFlowPurgeTarget]struct{}) (map[uint32]kernelRuleStats, int, error) {
		calls++
		if len(targets) != 2 {
			t.Fatalf("retry purge target count = %d, want failed and new targets", len(targets))
		}
		if _, ok := targets[first]; !ok {
			t.Fatalf("retry purge targets = %#v, missing failed target", targets)
		}
		if _, ok := targets[second]; !ok {
			t.Fatalf("retry purge targets = %#v, missing new target", targets)
		}
		return map[uint32]kernelRuleStats{}, 0, nil
	})
	if err != nil {
		t.Fatalf("retry purge error = %v", err)
	}
	if deleted != 0 || len(corrections) != 0 {
		t.Fatalf("retry purge result = deleted:%d corrections:%+v, want empty success", deleted, corrections)
	}
	if calls != 2 {
		t.Fatalf("purge calls = %d, want 2", calls)
	}
	if got := state.snapshot(); len(got) != 0 {
		t.Fatalf("pending purge targets after success = %#v, want empty", got)
	}
}

func TestKernelFlowPurgeRetryStateCoalescesCoveredScopedTargets(t *testing.T) {
	state := kernelFlowPurgeRetryState{}
	state.add(map[kernelFlowPurgeTarget]struct{}{
		{RuleID: 41, RuleRevision: 1001, IfIndex: 55}: {},
		{RuleID: 41, RuleRevision: 1001, IfIndex: 66}: {},
		{RuleID: 41, RuleRevision: 1002, IfIndex: 77}: {},
	})
	state.add(map[kernelFlowPurgeTarget]struct{}{
		{RuleID: 41, RuleRevision: 1001}: {},
	})

	wantRevision := kernelFlowPurgeTarget{RuleID: 41, RuleRevision: 1001}
	wantOtherRevision := kernelFlowPurgeTarget{RuleID: 41, RuleRevision: 1002, IfIndex: 77}
	got := state.snapshot()
	if len(got) != 2 {
		t.Fatalf("coalesced targets = %#v, want full revision plus other scoped revision", got)
	}
	if _, ok := got[wantRevision]; !ok {
		t.Fatalf("coalesced targets = %#v, missing %#v", got, wantRevision)
	}
	if _, ok := got[wantOtherRevision]; !ok {
		t.Fatalf("coalesced targets = %#v, missing %#v", got, wantOtherRevision)
	}

	state.add(map[kernelFlowPurgeTarget]struct{}{
		{RuleID: 41}: {},
		{RuleID: 41, RuleRevision: 1003, IfIndex: 88}: {},
	})
	got = state.snapshot()
	wantRule := kernelFlowPurgeTarget{RuleID: 41}
	if len(got) != 1 {
		t.Fatalf("wildcard-coalesced targets = %#v, want one rule wildcard", got)
	}
	if _, ok := got[wantRule]; !ok {
		t.Fatalf("wildcard-coalesced targets = %#v, missing %#v", got, wantRule)
	}
}

func TestKernelHotRestartMetadataRoundTripsCandidateIDsAndPendingPurges(t *testing.T) {
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())
	rule := Rule{
		ID:                 700,
		InInterface:        "tap100i0",
		InIP:               "0.0.0.0",
		OutInterface:       "vmbr0",
		OutSourceIP:        "198.51.100.20",
		Protocol:           "tcp",
		Enabled:            true,
		kernelLogKind:      workerKindEgressNAT,
		kernelLogOwnerID:   -3,
		kernelOwnerKey:     pluginForwardRuleOwnerKey("example", "record-a"),
		kernelMode:         kernelModeEgressNAT,
		kernelNATType:      egressNATTypeFullCone,
		kernelRedirectMode: egressNATRedirectModePreparedL2,
	}
	target := kernelFlowPurgeTarget{RuleID: 699, RuleRevision: 0xabc, IfIndex: 66}
	meta := kernelHotRestartMetadataWithRuleState(
		kernelHotRestartTCMetadata(nil, "object"),
		[]Rule{rule},
		map[kernelFlowPurgeTarget]struct{}{target: {}},
	)
	if err := writeKernelHotRestartMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}

	rules := readKernelHotRestartCandidateRules(kernelEngineTC)
	if len(rules) != 1 {
		t.Fatalf("hot restart candidate count = %d, want 1", len(rules))
	}
	if rules[0].ID != rule.ID || kernelCandidateIdentityForRule(rules[0]) != kernelCandidateIdentityForRule(rule) {
		t.Fatalf("hot restart candidate = %+v, want identity and id from %+v", rules[0], rule)
	}
	pending := readKernelHotRestartFlowPurgeTargets(kernelEngineTC)
	if len(pending) != 1 {
		t.Fatalf("hot restart pending purge count = %d, want 1", len(pending))
	}
	if _, ok := pending[target]; !ok {
		t.Fatalf("hot restart pending purges = %#v, want %#v", pending, target)
	}
}

func TestKernelHotRestartMetadataReadsLegacyPendingFlowPurgeWithoutIfIndex(t *testing.T) {
	var meta kernelHotRestartMetadata
	if err := json.Unmarshal([]byte(`{
		"engine":"tc",
		"pending_flow_purges":[{"rule_id":699,"rule_revision":2748}]
	}`), &meta); err != nil {
		t.Fatalf("unmarshal legacy hot restart metadata: %v", err)
	}
	want := kernelFlowPurgeTarget{RuleID: 699, RuleRevision: 2748}
	got := kernelFlowPurgeTargetsFromHotRestartMetadata(meta)
	if len(got) != 1 {
		t.Fatalf("legacy pending purge targets = %#v, want one target", got)
	}
	if _, ok := got[want]; !ok {
		t.Fatalf("legacy pending purge targets = %#v, want %#v", got, want)
	}
}

func TestStableKernelCandidateIDsAvoidTCAndXDPPurgeForUnchangedRule(t *testing.T) {
	previousCandidate := kernelRuleIDTestCandidate(workerKindEgressNAT, -2, 62, "tap100i0", 0, "tcp")
	previousCandidate.rule.kernelMode = kernelModeEgressNAT
	desiredCandidate := kernelRuleIDTestCandidate(workerKindEgressNAT, -2, 72, "tap100i0", 0, "tcp")
	desiredCandidate.rule.kernelMode = kernelModeEgressNAT
	desired := []kernelCandidateRule{desiredCandidate}
	if err := stabilizeKernelCandidateRuleIDs(desired, []Rule{previousCandidate.rule}); err != nil {
		t.Fatalf("stabilizeKernelCandidateRuleIDs() error = %v", err)
	}
	if desired[0].rule.ID != previousCandidate.rule.ID {
		t.Fatalf("stable candidate id = %d, want %d", desired[0].rule.ID, previousCandidate.rule.ID)
	}

	oldTC := preparedKernelRule{
		rule:  previousCandidate.rule,
		key:   tcRuleKeyV4{IfIndex: 4, Proto: 6},
		value: tcRuleValueV4{RuleID: uint32(previousCandidate.rule.ID), OutIfIndex: 5, NATAddr: 7},
	}
	newTC := oldTC
	newTC.rule = desired[0].rule
	newTC.value.RuleID = uint32(desired[0].rule.ID)
	if got := collectPreparedKernelRuleFlowPurgeTargets([]preparedKernelRule{oldTC}, []preparedKernelRule{newTC}); len(got) != 0 {
		t.Fatalf("tc flow purge targets = %#v, want none for stable candidate", got)
	}

	oldXDP := preparedXDPKernelRule{
		rule:    previousCandidate.rule,
		keyV4:   tcRuleKeyV4{IfIndex: 4, Proto: 6},
		valueV4: xdpRuleValueV4{RuleID: uint32(previousCandidate.rule.ID), OutIfIndex: 5, NATAddr: 7},
	}
	newXDP := oldXDP
	newXDP.rule = desired[0].rule
	newXDP.valueV4.RuleID = uint32(desired[0].rule.ID)
	if got := collectPreparedXDPKernelRuleFlowPurgeTargets([]preparedXDPKernelRule{oldXDP}, []preparedXDPKernelRule{newXDP}); len(got) != 0 {
		t.Fatalf("xdp flow purge targets = %#v, want none for stable candidate", got)
	}
}

func TestKernelDeferredFlowRulesBecomeThePurgeBaselineForReturningRules(t *testing.T) {
	unchanged := preparedKernelRule{
		rule:  Rule{ID: 71, Protocol: "tcp"},
		key:   tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 20022, Proto: 6},
		value: tcRuleValueV4{RuleID: 71, BackendAddr: 2, BackendPort: 22, OutIfIndex: 3},
	}
	recreated := preparedKernelRule{
		rule:  Rule{ID: 72, Protocol: "udp"},
		key:   tcRuleKeyV4{IfIndex: 9, Proto: 17},
		value: tcRuleValueV4{RuleID: 72, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT, OutIfIndex: 3, NATAddr: 5},
	}
	removed := preparedKernelRule{
		rule:  Rule{ID: 73, Protocol: "tcp"},
		key:   tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 20080, Proto: 6},
		value: tcRuleValueV4{RuleID: 73, BackendAddr: 2, BackendPort: 80, OutIfIndex: 3},
	}
	recreatedRevision := mustPreparedKernelRuleFlowRevision(t, recreated)
	removedRevision := mustPreparedKernelRuleFlowRevision(t, removed)

	var drained kernelDeferredFlowRules[preparedKernelRule]
	if got := drained.baseline(nil); got != nil {
		t.Fatalf("empty baseline = %#v, want nil", got)
	}
	drained.record([]preparedKernelRule{unchanged, recreated, removed}, time.Unix(100, 0))

	// The interface behind rule 72 came back with a new ifindex, rule 73 did
	// not come back, and rule 71 returned exactly as it was.
	returned := recreated
	returned.key.IfIndex = 10
	got := collectPreparedKernelRuleFlowPurgeTargets(drained.baseline(nil), []preparedKernelRule{unchanged, returned})
	assertKernelFlowPurgeTargets(t, got, kernelFlowPurgeTarget{RuleID: 72, RuleRevision: recreatedRevision}, kernelFlowPurgeTarget{RuleID: 73, RuleRevision: removedRevision})

	// Without the drained baseline nothing would be purged at all.
	if targets := collectPreparedKernelRuleFlowPurgeTargets(nil, []preparedKernelRule{unchanged, returned}); len(targets) != 0 {
		t.Fatalf("purge targets without a baseline = %#v, want none", targets)
	}
}

func TestKernelDeferredFlowRulesExpireEachRuleAfterItsOwnGrace(t *testing.T) {
	var deferred kernelDeferredFlowRules[preparedKernelRule]
	start := time.Unix(100, 0)
	if got := deferred.expire(start.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("an empty set expired %#v", got)
	}
	deferred.record([]preparedKernelRule{{rule: Rule{ID: 1}}}, start)
	deferred.record([]preparedKernelRule{{rule: Rule{ID: 2}}}, start.Add(10*time.Second))
	if got := deferred.expire(start.Add(kernelDeferredFlowGrace - time.Second)); len(got) != 0 {
		t.Fatalf("rules expired before the grace: %#v", got)
	}
	// A later record must not extend an earlier one.
	got := deferred.expire(start.Add(kernelDeferredFlowGrace))
	if len(got) != 1 || got[0].rule.ID != 1 {
		t.Fatalf("expired at the first grace = %#v, want only rule 1", got)
	}
	current := []preparedKernelRule{{rule: Rule{ID: 3}}}
	if baseline := deferred.baseline(current); len(baseline) != 2 || baseline[0].rule.ID != 2 || baseline[1].rule.ID != 3 {
		t.Fatalf("baseline with current rules = %#v", baseline)
	}
	deferred.reset()
	if len(deferred.baseline(current)) != 1 || len(deferred.expire(start.Add(time.Hour))) != 0 {
		t.Fatal("reset left deferred rules behind")
	}
}

func TestEgressNATGuardDefersFlowPurgeUntilTheExitReturnsOrTheGraceEnds(t *testing.T) {
	rule := Rule{ID: 81, InInterface: "lan0", OutInterface: "wan0", Protocol: "tcp", kernelMode: kernelModeEgressNAT}
	working := preparedKernelRule{
		rule: rule, inIfIndex: 10, outIfIndex: 3, replyIfIndexes: []int{3},
		key:   tcRuleKeyV4{IfIndex: 10, Proto: 6},
		value: tcRuleValueV4{RuleID: 81, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT, OutIfIndex: 3, NATAddr: 5},
	}
	guard := preparedKernelRule{
		rule: rule, inIfIndex: 10, outIfIndex: 10,
		key:   working.key,
		value: tcRuleValueV4{RuleID: 81, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT | kernelRuleFlagDrop, OutIfIndex: 10},
	}
	workingTarget := kernelFlowPurgeTarget{RuleID: 81, RuleRevision: mustPreparedKernelRuleFlowRevision(t, working)}
	allLinks := func(int) bool { return true }
	start := time.Unix(1000, 0)

	// The exit lost its address: the guard replaces the rule, its flows wait.
	plan := planPreparedKernelRuleFlowPurge(nil, []preparedKernelRule{working}, []preparedKernelRule{guard}, start, allLinks)
	if len(plan.targets) != 0 || len(plan.deferred) != 1 || plan.deferred[0].rule.value.NATAddr != 5 || !plan.deferred[0].at.Equal(start) {
		t.Fatalf("guard plan = %+v, want the working rule deferred without purge", plan)
	}

	// Still guarded later: the rule stays deferred from the first moment.
	later := planPreparedKernelRuleFlowPurge(plan.deferred, []preparedKernelRule{guard}, []preparedKernelRule{guard}, start.Add(10*time.Second), allLinks)
	if len(later.targets) != 0 || len(later.deferred) != 1 || !later.deferred[0].at.Equal(start) {
		t.Fatalf("still guarded plan = %+v, want the deferral kept from its start", later)
	}

	// The same address came back: nothing is purged and the deferral ends.
	back := planPreparedKernelRuleFlowPurge(later.deferred, []preparedKernelRule{guard}, []preparedKernelRule{working}, start.Add(20*time.Second), allLinks)
	if len(back.targets) != 0 || len(back.deferred) != 0 {
		t.Fatalf("returning rule plan = %+v, want connections kept", back)
	}

	// A different address came back: the old contract's flows go.
	changed := working
	changed.value.NATAddr = 6
	moved := planPreparedKernelRuleFlowPurge(later.deferred, []preparedKernelRule{guard}, []preparedKernelRule{changed}, start.Add(20*time.Second), allLinks)
	assertKernelFlowPurgeTargets(t, moved.targets, workingTarget)
	if len(moved.deferred) != 0 {
		t.Fatalf("changed rule kept a deferral: %+v", moved.deferred)
	}

	// The NAT was removed while guarded.
	removed := planPreparedKernelRuleFlowPurge(later.deferred, []preparedKernelRule{guard}, nil, start.Add(20*time.Second), allLinks)
	assertKernelFlowPurgeTargets(t, removed.targets, workingTarget)

	// The grace ran out while still guarded.
	expired := planPreparedKernelRuleFlowPurge(later.deferred, []preparedKernelRule{guard}, []preparedKernelRule{guard}, start.Add(kernelDeferredFlowGrace), allLinks)
	assertKernelFlowPurgeTargets(t, expired.targets, workingTarget)
	if len(expired.deferred) != 0 {
		t.Fatalf("expired deferral kept: %+v", expired.deferred)
	}

	// The exit interface itself is gone: its flows can never be used again.
	exitGone := func(ifindex int) bool { return ifindex != 3 }
	gone := planPreparedKernelRuleFlowPurge(nil, []preparedKernelRule{working}, []preparedKernelRule{guard}, start, exitGone)
	assertKernelFlowPurgeTargets(t, gone.targets, workingTarget)
	if len(gone.deferred) != 0 {
		t.Fatalf("rule of a deleted exit was deferred: %+v", gone.deferred)
	}

	// A guard with another rule ID does not shelter this rule's flows.
	otherGuard := guard
	otherGuard.rule.ID = 82
	otherGuard.value.RuleID = 82
	other := planPreparedKernelRuleFlowPurge(nil, []preparedKernelRule{working}, []preparedKernelRule{otherGuard}, start, allLinks)
	assertKernelFlowPurgeTargets(t, other.targets, workingTarget)
}

func TestKernelFlowPurgeTargetsIgnoreDropGuards(t *testing.T) {
	guard := preparedKernelRule{
		rule:  Rule{ID: 91, InInterface: "lan0", Protocol: "udp", kernelMode: kernelModeEgressNAT},
		key:   tcRuleKeyV4{IfIndex: 10, Proto: 17},
		value: tcRuleValueV4{RuleID: 91, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT | kernelRuleFlagDrop, OutIfIndex: 10},
	}
	if got := collectPreparedKernelRuleFlowPurgeTargets([]preparedKernelRule{guard}, nil); len(got) != 0 {
		t.Fatalf("purge targets for a removed guard = %#v, want none", got)
	}
}

func TestKernelHandoffPurgesDeferredRules(t *testing.T) {
	deferred := preparedKernelRule{
		rule:  Rule{ID: 95, Protocol: "tcp"},
		key:   tcRuleKeyV4{IfIndex: 10, Proto: 6},
		value: tcRuleValueV4{RuleID: 95, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT, OutIfIndex: 3, NATAddr: 5},
	}
	rt := &linuxKernelRuleRuntime{}
	pending := kernelFlowPurgeTarget{RuleID: 96, RuleRevision: 7}
	rt.flowPurgeRetry.add(map[kernelFlowPurgeTarget]struct{}{pending: {}})
	rt.deferredFlows.record([]preparedKernelRule{deferred}, time.Unix(1, 0))
	got := rt.pendingFlowPurgesForHandoffLocked()
	assertKernelFlowPurgeTargets(t, got, pending, kernelFlowPurgeTarget{RuleID: 95, RuleRevision: mustPreparedKernelRuleFlowRevision(t, deferred)})
}

func TestBridgePathHoldKeepsTheBridgePathOnlyForItsOwnSessions(t *testing.T) {
	member := preparedKernelRule{
		rule:       Rule{ID: 61, OutInterface: "vmbr1", OutIP: "198.18.0.2", Protocol: "tcp"},
		outIfIndex: 12,
		key:        tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 2222, Proto: 6},
		value:      tcRuleValueV4{RuleID: 61, BackendAddr: 7, BackendPort: 22, Flags: kernelRuleFlagFullNAT | kernelRuleFlagBridgeL2, OutIfIndex: 12, NATAddr: 9},
	}
	path, ok := heldKernelBridgePath(member, nil, 11, member.rule.OutIP)
	if !ok || path.outIfIndex != 11 || path.flags != 0 {
		t.Fatalf("held path for a member-path rule = %+v, %v, want the bridge path", path, ok)
	}
	onBridge := member
	onBridge.outIfIndex = 11
	onBridge.value.Flags = kernelRuleFlagFullNAT
	onBridge.value.OutIfIndex = 11
	if _, ok := heldKernelBridgePath(onBridge, nil, 11, member.rule.OutIP); ok {
		t.Fatal("a bridge-path rule without a previous member path was held")
	}

	// Sessions on the member path itself, or none at all, need no hold.
	memberRevision := mustPreparedKernelRuleFlowRevision(t, member)
	hold := newKernelBridgePathHold(func(uint32) map[uint64]struct{} {
		return map[uint64]struct{}{memberRevision: {}}
	})
	if _, ok := hold.apply(newKernelPrepareContext(false, false, false), member.rule, []preparedKernelRule{member}, nil); ok || hold.heldRevisions() != nil {
		t.Fatal("rule was held although its sessions already use the prepared path")
	}
	if got := withoutPreparedKernelRuleRevisions(map[uint64]struct{}{memberRevision: {}, 5: {}}, []preparedKernelRule{member}); len(got) != 1 {
		t.Fatalf("foreign revisions = %#v, want only the other revision", got)
	}
	var none *kernelBridgePathHold
	if _, ok := none.apply(nil, member.rule, []preparedKernelRule{member}, nil); ok || none.heldRevisions() != nil {
		t.Fatal("a nil hold held a rule")
	}
}

func mustPreparedKernelRuleFlowRevision(t *testing.T, item preparedKernelRule) uint64 {
	t.Helper()
	revision, err := preparedKernelRuleFlowRevision(item)
	if err != nil || revision == 0 {
		t.Fatalf("flow revision = %d, %v", revision, err)
	}
	return revision
}

func assertKernelFlowPurgeTargets(t *testing.T, got map[kernelFlowPurgeTarget]struct{}, want ...kernelFlowPurgeTarget) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("purge targets = %#v, want %#v", got, want)
	}
	for _, target := range want {
		if _, ok := got[target]; !ok {
			t.Fatalf("purge targets = %#v, want %#v", got, want)
		}
	}
}
