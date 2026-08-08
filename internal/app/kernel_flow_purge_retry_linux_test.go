//go:build linux

package app

import (
	"errors"
	"testing"
)

func TestKernelFlowPurgeRetryStateRetainsFailedTargetsAndUnionsNewTargets(t *testing.T) {
	first := kernelFlowPurgeTarget{RuleID: 41, RuleRevision: 1001}
	second := kernelFlowPurgeTarget{RuleID: 42, RuleRevision: 1002}
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
	target := kernelFlowPurgeTarget{RuleID: 699, RuleRevision: 0xabc}
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
