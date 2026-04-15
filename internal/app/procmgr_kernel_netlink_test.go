package app

import (
	"strings"
	"testing"
	"time"
)

type stubNetlinkFallbackRuntime struct {
	assignments map[int64]string
}

func (s *stubNetlinkFallbackRuntime) Available() (bool, string) {
	return true, "ready"
}

func (s *stubNetlinkFallbackRuntime) SupportsRule(rule Rule) (bool, string) {
	return true, ""
}

func (s *stubNetlinkFallbackRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	nextAssignments := make(map[int64]string, len(rules))
	for _, rule := range rules {
		results[rule.ID] = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		nextAssignments[rule.ID] = kernelEngineTC
	}
	s.assignments = nextAssignments
	return results, nil
}

func (s *stubNetlinkFallbackRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (s *stubNetlinkFallbackRuntime) Maintain() error {
	return nil
}

func (s *stubNetlinkFallbackRuntime) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(s.assignments))
	for id, engine := range s.assignments {
		out[id] = engine
	}
	return out
}

func (s *stubNetlinkFallbackRuntime) Close() error {
	return nil
}

func TestIsNetlinkTriggeredKernelFallbackReason(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   bool
	}{
		{
			name:   "neighbor missing",
			reason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 192.0.2.10 on "eno1"; tc: skipped`,
			want:   true,
		},
		{
			name:   "fdb missing",
			reason: `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			want:   true,
		},
		{
			name:   "pressure",
			reason: `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNetlinkTriggeredKernelFallbackReason(tc.reason); got != tc.want {
				t.Fatalf("isNetlinkTriggeredKernelFallbackReason(%q) = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

func TestSummarizeNetlinkTriggeredKernelFallbacksLocked(t *testing.T) {
	pm := &ProcessManager{
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			},
			2: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 192.0.2.10 on "eno1"; tc: skipped`,
			},
			3: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{
			4: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr2": no forwarding database entry matched the backend MAC`,
			},
		},
	}

	got := pm.summarizeNetlinkTriggeredKernelFallbacksLocked()
	want := "rules=2 ranges=1 reasons=fdb_missing=2,neighbor_missing=1"
	if got != want {
		t.Fatalf("summarizeNetlinkTriggeredKernelFallbacksLocked() = %q, want %q", got, want)
	}
}

func TestNextKernelNetlinkRetryState(t *testing.T) {
	now := time.Unix(100, 0)
	retry, at := nextKernelNetlinkRetryState(time.Time{}, now, "rules=1 ranges=0 reasons=neighbor_missing=1")
	if !retry || !at.Equal(now) {
		t.Fatalf("first retry = (%v, %v), want true at now", retry, at)
	}

	retry, at = nextKernelNetlinkRetryState(at, now.Add(kernelNetlinkRetryDebounce/2), "rules=1 ranges=0 reasons=neighbor_missing=1")
	if retry {
		t.Fatal("retry unexpectedly allowed inside debounce window")
	}

	retry, at = nextKernelNetlinkRetryState(at, now.Add(kernelNetlinkRetryDebounce), "rules=1 ranges=0 reasons=neighbor_missing=1")
	if !retry || !at.Equal(now.Add(kernelNetlinkRetryDebounce)) {
		t.Fatalf("retry after debounce = (%v, %v), want true at debounce boundary", retry, at)
	}

	retry, nextAt := nextKernelNetlinkRetryState(at, now.Add(kernelNetlinkRetryDebounce+time.Second), "")
	if retry || !nextAt.Equal(at) {
		t.Fatalf("empty summary = (%v, %v), want false with unchanged timestamp", retry, nextAt)
	}
}

func TestMergeKernelNetlinkRecoverySummaries(t *testing.T) {
	got := mergeKernelNetlinkRecoverySummaries(
		"rules=1 ranges=0 reasons=neighbor_missing=1",
		"",
		"egress_nat_parents=vmbr1",
	)
	want := "rules=1 ranges=0 reasons=neighbor_missing=1; egress_nat_parents=vmbr1"
	if got != want {
		t.Fatalf("mergeKernelNetlinkRecoverySummaries() = %q, want %q", got, want)
	}
}

func TestSummarizeDynamicEgressNATParentInterfaces(t *testing.T) {
	got := summarizeDynamicEgressNATParentInterfaces(map[string]struct{}{
		"vmbr1": {},
		"vmbr0": {},
		"vmbr2": {},
		"vmbr3": {},
	})
	want := "egress_nat_parents=vmbr0,vmbr1,vmbr2,+1"
	if got != want {
		t.Fatalf("summarizeDynamicEgressNATParentInterfaces() = %q, want %q", got, want)
	}
}

func TestKernelNetlinkTriggerMatchesDynamicEgressNATParentsWithoutHintsIsConservative(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("link")

	got := kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger, map[string]struct{}{
		"vmbr1": {},
		"vmbr0": {},
	})

	if len(got) != 2 {
		t.Fatalf("len(matches) = %d, want 2", len(got))
	}
	if _, ok := got["vmbr0"]; !ok {
		t.Fatal("matches missing vmbr0")
	}
	if _, ok := got["vmbr1"]; !ok {
		t.Fatal("matches missing vmbr1")
	}
}

func TestKernelNetlinkTriggerMatchesDynamicEgressNATParentsFiltersUnrelatedInterfaces(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addInterfaceName("eno2")
	trigger.addLinkNeighborInterface("eno2")
	trigger.addLinkFDBInterface("vmbr9")

	got := kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger, map[string]struct{}{
		"vmbr1": {},
	})
	if len(got) != 0 {
		t.Fatalf("matches = %#v, want none", got)
	}
}

func TestKernelNetlinkTriggerMatchesDynamicEgressNATParentsReturnsMatchedSubset(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addInterfaceName("eno2")
	trigger.addLinkNeighborInterface("tap100i0")
	trigger.addLinkFDBInterface("vmbr1")

	got := kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger, map[string]struct{}{
		"vmbr1": {},
		"vmbr2": {},
	})
	if len(got) != 1 {
		t.Fatalf("len(matches) = %d, want 1", len(got))
	}
	if _, ok := got["vmbr1"]; !ok {
		t.Fatal("matches missing vmbr1")
	}
}

func TestQueueKernelNetlinkRecoveryLockedCoalescesPendingWork(t *testing.T) {
	pm := &ProcessManager{
		kernelNetlinkRecoverWake: make(chan struct{}, 1),
	}
	firstAt := time.Unix(100, 0)
	secondAt := firstAt.Add(2 * time.Second)

	firstTrigger := newKernelNetlinkRecoveryTrigger("neighbor")
	firstTrigger.addInterfaceName("eno2")
	firstTrigger.addBackendIP("198.51.100.31")
	wake := pm.queueKernelNetlinkRecoveryLocked("neighbor", "rules=1 ranges=0 reasons=neighbor_missing=1", firstTrigger, secondAt)
	if wake == nil {
		t.Fatal("queueKernelNetlinkRecoveryLocked() returned nil wake channel")
	}
	secondTrigger := newKernelNetlinkRecoveryTrigger("fdb")
	secondTrigger.addInterfaceName("vmbr1")
	secondTrigger.addBackendMAC("02:00:5e:10:00:31")
	pm.queueKernelNetlinkRecoveryLocked("fdb", "rules=1 ranges=1 reasons=fdb_missing=2", secondTrigger, firstAt)

	source, summary, trigger, requestedAt, ok := pm.takePendingKernelNetlinkRecovery()
	if !ok {
		t.Fatal("takePendingKernelNetlinkRecovery() = false, want queued work")
	}
	if source != "neighbor,fdb" {
		t.Fatalf("pending source = %q, want merged source list", source)
	}
	if summary != "rules=1 ranges=1 reasons=fdb_missing=2" {
		t.Fatalf("pending summary = %q, want latest summary", summary)
	}
	if !requestedAt.Equal(firstAt) {
		t.Fatalf("pending requestedAt = %v, want earliest queue time %v", requestedAt, firstAt)
	}
	if !trigger.hasSource("neighbor") || !trigger.hasSource("fdb") {
		t.Fatalf("pending trigger sources = %#v, want merged neighbor+fdb", trigger.sources)
	}
	if !trigger.matchesOutInterface("eno2") || !trigger.matchesOutInterface("vmbr1") {
		t.Fatalf("pending trigger interface names = %#v, want merged interface hints", trigger.interfaceNames)
	}
	if !trigger.matchesBackendIP("198.51.100.31") {
		t.Fatalf("pending trigger backend IPs = %#v, want merged backend IP hint", trigger.backendIPs)
	}
	if !trigger.matchesBackendMAC("02:00:5e:10:00:31") {
		t.Fatalf("pending trigger backend MACs = %#v, want merged backend MAC hint", trigger.backendMACs)
	}
	if _, _, _, _, ok := pm.takePendingKernelNetlinkRecovery(); ok {
		t.Fatal("takePendingKernelNetlinkRecovery() still returned work after draining queue")
	}
}

func TestSummarizeKernelNetlinkRecoveryTrigger(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno2")
	trigger.addInterfaceName("vmbr1")
	trigger.addLinkIndex(11)
	trigger.addLinkNeighborInterface("eno2")
	trigger.addLinkNeighborIndex(11)
	trigger.addLinkFDBInterface("vmbr1")
	trigger.addLinkFDBIndex(7)
	trigger.addBackendIP("198.51.100.31")
	trigger.addBackendMAC("02:00:5e:10:00:31")

	got := summarizeKernelNetlinkRecoveryTrigger(trigger)
	want := "if=eno2,vmbr1; ifindex=11; neigh_if=eno2; neigh_ifindex=11; fdb_if=vmbr1; fdb_ifindex=7; backend_ip=198.51.100.31; backend_mac=02:00:5e:10:00:31"
	if got != want {
		t.Fatalf("summarizeKernelNetlinkRecoveryTrigger() = %q, want %q", got, want)
	}
}

func TestSummarizeKernelNetlinkRecoveryTriggerCompactsLongLists(t *testing.T) {
	trigger := kernelNetlinkRecoveryTrigger{
		interfaceNames: map[string]struct{}{
			"eno1":  {},
			"eno2":  {},
			"eno3":  {},
			"eno10": {},
		},
	}

	got := summarizeKernelNetlinkRecoveryTrigger(trigger)
	want := "if=eno1,eno10,eno2,+1"
	if got != want {
		t.Fatalf("summarizeKernelNetlinkRecoveryTrigger() = %q, want %q", got, want)
	}
}

func TestKernelNetlinkRecoveryTriggerMatchesLinkBridgeMemberHints(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addLinkNeighborInterface("eno2")
	trigger.addLinkFDBInterface("vmbr1")

	neighborMemberPlan := ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "neighbor_missing",
			OutInterface: "eno2",
		},
		FallbackReason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.51 on "eno2"; tc: skipped`,
	}
	neighborBridgePlan := ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "neighbor_missing",
			OutInterface: "vmbr1",
		},
		FallbackReason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.52 on "vmbr1"; tc: skipped`,
	}
	fdbBridgePlan := ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "fdb_missing",
			OutInterface: "vmbr1",
		},
		FallbackReason: `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
	}

	if !trigger.matchesPlan(neighborMemberPlan) {
		t.Fatal("member link trigger did not match neighbor fallback on changed member interface")
	}
	if trigger.matchesPlan(neighborBridgePlan) {
		t.Fatal("member link trigger unexpectedly matched bridge neighbor fallback")
	}
	if !trigger.matchesPlan(fdbBridgePlan) {
		t.Fatal("member link trigger did not match FDB fallback on owning bridge")
	}
}

func TestKernelNetlinkRecoveryTriggerMatchesLinkBridgeMasterHints(t *testing.T) {
	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addLinkNeighborInterface("vmbr1")
	trigger.addLinkFDBInterface("vmbr1")

	neighborBridgePlan := ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "neighbor_missing",
			OutInterface: "vmbr1",
		},
		FallbackReason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.61 on "vmbr1"; tc: skipped`,
	}
	fdbBridgePlan := ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "fdb_missing",
			OutInterface: "vmbr1",
		},
		FallbackReason: `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
	}

	if !trigger.matchesPlan(neighborBridgePlan) {
		t.Fatal("bridge link trigger did not match bridge neighbor fallback")
	}
	if !trigger.matchesPlan(fdbBridgePlan) {
		t.Fatal("bridge link trigger did not match bridge FDB fallback")
	}
}

func TestKernelNetlinkLinkSnapshotChanged(t *testing.T) {
	base := kernelNetlinkLinkSnapshot{
		Name:        "eno2",
		LinkType:    "device",
		MasterIndex: 10,
		AdminUp:     true,
		LowerUp:     true,
		OperState:   "up",
	}
	tests := []struct {
		name string
		next kernelNetlinkLinkSnapshot
		want bool
	}{
		{
			name: "unchanged",
			next: base,
			want: false,
		},
		{
			name: "master changed",
			next: kernelNetlinkLinkSnapshot{
				Name:        "eno2",
				LinkType:    "device",
				MasterIndex: 20,
				AdminUp:     true,
				LowerUp:     true,
				OperState:   "up",
			},
			want: true,
		},
		{
			name: "carrier changed",
			next: kernelNetlinkLinkSnapshot{
				Name:        "eno2",
				LinkType:    "device",
				MasterIndex: 10,
				AdminUp:     true,
				LowerUp:     false,
				OperState:   "up",
			},
			want: true,
		},
		{
			name: "operstate changed",
			next: kernelNetlinkLinkSnapshot{
				Name:        "eno2",
				LinkType:    "device",
				MasterIndex: 10,
				AdminUp:     true,
				LowerUp:     true,
				OperState:   "dormant",
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelNetlinkLinkSnapshotChanged(base, tc.next); got != tc.want {
				t.Fatalf("kernelNetlinkLinkSnapshotChanged() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestApplyKernelNetlinkLinkStateUpdateSuppressesUnchangedNoise(t *testing.T) {
	states := map[int]kernelNetlinkLinkSnapshot{
		11: {
			Name:        "eno2",
			LinkType:    "device",
			MasterIndex: 7,
			AdminUp:     true,
			LowerUp:     true,
			OperState:   "up",
		},
	}
	if applyKernelNetlinkLinkStateUpdate(states, 11, states[11], false) {
		t.Fatal("applyKernelNetlinkLinkStateUpdate() returned true for unchanged snapshot noise")
	}
	if !applyKernelNetlinkLinkStateUpdate(states, 11, kernelNetlinkLinkSnapshot{
		Name:        "eno2",
		LinkType:    "device",
		MasterIndex: 7,
		AdminUp:     true,
		LowerUp:     false,
		OperState:   "down",
	}, false) {
		t.Fatal("applyKernelNetlinkLinkStateUpdate() returned false for meaningful link change")
	}
	if !applyKernelNetlinkLinkStateUpdate(states, 11, kernelNetlinkLinkSnapshot{}, true) {
		t.Fatal("applyKernelNetlinkLinkStateUpdate() returned false for link delete")
	}
	if _, ok := states[11]; ok {
		t.Fatal("applyKernelNetlinkLinkStateUpdate() did not delete link state")
	}
}

func TestHandleKernelNetlinkRecoveryEventFallsBackToFullRedistribute(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.30",
		InPort:       12001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.30",
		OutPort:      22001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.31",
		InPort:       12002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.31",
		OutPort:      22002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}

	rt := &stubNetlinkFallbackRuntime{
		assignments: map[int64]string{
			id1: kernelEngineTC,
		},
	}
	pm := &ProcessManager{
		db:                db,
		cfg:               &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:     rt,
		kernelRules:       map[int64]bool{id1: true},
		kernelRanges:      map[int64]bool{},
		kernelRuleEngines: map[int64]string{id1: kernelEngineTC},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(id1): {kind: workerKindRule, id: id1},
		},
		rulePlans: map[int64]ruleDataplanePlan{
			id1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineKernel,
			},
			id2: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.31 on "eno2"; tc: skipped`,
			},
		},
		rangePlans:       map[int64]rangeDataplanePlan{},
		redistributeWake: make(chan struct{}, 1),
	}

	pm.handleKernelNetlinkRecoveryEvent("neighbor")

	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want true after incremental retry fallback")
	}
	if pm.kernelIncrementalRetryCount != 1 {
		t.Fatalf("kernelIncrementalRetryCount = %d, want 1", pm.kernelIncrementalRetryCount)
	}
	if pm.kernelIncrementalRetryFallbackCount != 1 {
		t.Fatalf("kernelIncrementalRetryFallbackCount = %d, want 1", pm.kernelIncrementalRetryFallbackCount)
	}
	if pm.lastKernelIncrementalRetryAt.IsZero() {
		t.Fatal("lastKernelIncrementalRetryAt = zero, want recorded timestamp")
	}
	if !strings.Contains(pm.lastKernelIncrementalRetryResult, "cannot retain current kernel owners") {
		t.Fatalf("lastKernelIncrementalRetryResult = %q, want retain-current-owners fallback detail", pm.lastKernelIncrementalRetryResult)
	}
	if pm.kernelRetryCount != 1 {
		t.Fatalf("kernelRetryCount = %d, want 1", pm.kernelRetryCount)
	}
	if pm.lastKernelRetryReason != "rules=1 ranges=0 reasons=neighbor_missing=1" {
		t.Fatalf("lastKernelRetryReason = %q, want netlink retry summary", pm.lastKernelRetryReason)
	}
}

func TestHandleKernelNetlinkRecoveryEventQueuesAsyncRetry(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.40",
		InPort:       13001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.40",
		OutPort:      23001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.41",
		InPort:       13002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.41",
		OutPort:      23002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}

	stop := make(chan struct{})
	wake := make(chan struct{}, 1)
	pm := &ProcessManager{
		db:                       db,
		cfg:                      &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:            &stubNetlinkFallbackRuntime{assignments: map[int64]string{id1: kernelEngineTC}},
		kernelRules:              map[int64]bool{id1: true},
		kernelRanges:             map[int64]bool{},
		kernelRuleEngines:        map[int64]string{id1: kernelEngineTC},
		kernelFlowOwners:         map[uint32]kernelCandidateOwner{uint32(id1): {kind: workerKindRule, id: id1}},
		rulePlans:                map[int64]ruleDataplanePlan{id1: {KernelEligible: true, EffectiveEngine: ruleEngineKernel}, id2: {KernelEligible: true, EffectiveEngine: ruleEngineUserspace, FallbackReason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.41 on "eno2"; tc: skipped`}},
		rangePlans:               map[int64]rangeDataplanePlan{},
		redistributeWake:         make(chan struct{}, 1),
		kernelNetlinkStop:        stop,
		kernelNetlinkRecoverWake: wake,
	}

	pm.handleKernelNetlinkRecoveryEvent("neighbor")

	if pm.redistributePending {
		t.Fatal("redistributePending = true before async recovery loop ran, want queued work only")
	}

	pm.mu.Lock()
	pending := pm.kernelNetlinkRecoverPending
	pendingSource := pm.kernelNetlinkRecoverSource
	pendingSummary := pm.kernelNetlinkRecoverSummary
	pm.mu.Unlock()
	if !pending {
		t.Fatal("kernelNetlinkRecoverPending = false, want queued async retry")
	}
	if pendingSource != "neighbor" {
		t.Fatalf("kernelNetlinkRecoverSource = %q, want neighbor", pendingSource)
	}
	if pendingSummary != "rules=1 ranges=0 reasons=neighbor_missing=1" {
		t.Fatalf("kernelNetlinkRecoverSummary = %q, want queued retry summary", pendingSummary)
	}

	done := make(chan struct{})
	go func() {
		pm.runKernelNetlinkRecoveryLoop(stop, wake)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		pm.mu.Lock()
		redistributePending := pm.redistributePending
		retryCount := pm.kernelIncrementalRetryCount
		pending = pm.kernelNetlinkRecoverPending
		pm.mu.Unlock()
		if redistributePending && retryCount == 1 && !pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("async netlink recovery loop did not process queued work in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runKernelNetlinkRecoveryLoop() did not exit after stop")
	}
}

func TestHandleKernelNetlinkRecoveryTriggerLinkChangeForDynamicEgressNATQueuesIncrementalRefresh(t *testing.T) {
	pm := &ProcessManager{
		cfg:                      &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:            &stubNetlinkFallbackRuntime{},
		redistributeWake:         make(chan struct{}, 1),
		dynamicEgressNATParents:  map[string]struct{}{"vmbr1": {}},
		rulePlans:                map[int64]ruleDataplanePlan{},
		rangePlans:               map[int64]rangeDataplanePlan{},
		kernelNetlinkRecoverWake: make(chan struct{}, 1),
	}

	pm.handleKernelNetlinkRecoveryTrigger(newKernelNetlinkRecoveryTrigger("link"))

	if pm.redistributePending {
		t.Fatal("redistributePending = true, want queued incremental refresh for parent-scope egress nat link change")
	}
	if !pm.kernelNetlinkRecoverPending {
		t.Fatal("kernelNetlinkRecoverPending = false, want queued incremental refresh")
	}
	if pm.kernelRetryCount != 1 {
		t.Fatalf("kernelRetryCount = %d, want 1", pm.kernelRetryCount)
	}
	if pm.lastKernelRetryReason != "egress_nat_parents=vmbr1" {
		t.Fatalf("lastKernelRetryReason = %q, want parent-scope egress nat summary", pm.lastKernelRetryReason)
	}
	if pm.kernelNetlinkRecoverSource != "link" {
		t.Fatalf("kernelNetlinkRecoverSource = %q, want link", pm.kernelNetlinkRecoverSource)
	}
	if pm.kernelNetlinkRecoverSummary != "egress_nat_parents=vmbr1" {
		t.Fatalf("kernelNetlinkRecoverSummary = %q, want parent-scope egress nat summary", pm.kernelNetlinkRecoverSummary)
	}
}

func TestHandleKernelNetlinkRecoveryTriggerLinkChangeWithActiveKernelOwnersQueuesFullRedistribute(t *testing.T) {
	db := openTestDB(t)
	id, err := dbAddRule(db, &Rule{
		InInterface:      "vmbr1",
		InIP:             "0.0.0.0",
		InPort:           10000,
		OutInterface:     "eno1",
		OutIP:            "203.0.113.10",
		OutPort:          10000,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	pm := &ProcessManager{
		db:               db,
		cfg:              &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:    &stubNetlinkFallbackRuntime{},
		kernelRules:      map[int64]bool{id: true},
		kernelRanges:     map[int64]bool{},
		kernelEgressNATs: map[int64]bool{},
		redistributeWake: make(chan struct{}, 1),
	}

	pm.handleKernelNetlinkRecoveryTrigger(newKernelNetlinkRecoveryTrigger("link"))

	if !pm.redistributePending {
		t.Fatal("redistributePending = false, want full re-evaluation after active kernel link change")
	}
	if pm.kernelRetryCount != 1 {
		t.Fatalf("kernelRetryCount = %d, want 1", pm.kernelRetryCount)
	}
	if !strings.Contains(pm.lastKernelRetryReason, "active_kernel_entries=1") {
		t.Fatalf("lastKernelRetryReason = %q, want active kernel summary", pm.lastKernelRetryReason)
	}
	if pm.kernelIncrementalRetryCount != 1 {
		t.Fatalf("kernelIncrementalRetryCount = %d, want 1", pm.kernelIncrementalRetryCount)
	}
	if !strings.Contains(pm.lastKernelIncrementalRetryResult, "link change requires full kernel re-evaluation") {
		t.Fatalf("lastKernelIncrementalRetryResult = %q, want forced full re-evaluation detail", pm.lastKernelIncrementalRetryResult)
	}
}

func TestHandleKernelNetlinkRecoveryTriggerLinkChangeWithUnrelatedActiveKernelOwnersSkipsFullRedistribute(t *testing.T) {
	db := openTestDB(t)
	id, err := dbAddRule(db, &Rule{
		InInterface:      "vmbr1",
		InIP:             "0.0.0.0",
		InPort:           10000,
		OutInterface:     "eno1",
		OutIP:            "203.0.113.10",
		OutPort:          10000,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	pm := &ProcessManager{
		db:               db,
		cfg:              &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:    &stubNetlinkFallbackRuntime{},
		kernelRules:      map[int64]bool{id: true},
		kernelRanges:     map[int64]bool{},
		kernelEgressNATs: map[int64]bool{},
		redistributeWake: make(chan struct{}, 1),
	}

	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addInterfaceName("tap104i0")
	trigger.addLinkNeighborInterface("tap104i0")
	trigger.addLinkFDBInterface("vmbr9")
	pm.handleKernelNetlinkRecoveryTrigger(trigger)

	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false for unrelated active kernel link change")
	}
	if pm.kernelRetryCount != 1 {
		t.Fatalf("kernelRetryCount = %d, want 1", pm.kernelRetryCount)
	}
	if pm.kernelIncrementalRetryCount != 0 {
		t.Fatalf("kernelIncrementalRetryCount = %d, want 0 when link change does not match any active owner", pm.kernelIncrementalRetryCount)
	}
	if pm.lastKernelIncrementalRetryResult != "" {
		t.Fatalf("lastKernelIncrementalRetryResult = %q, want empty when no incremental retry was needed", pm.lastKernelIncrementalRetryResult)
	}
}

func TestHandleKernelNetlinkRecoveryTriggerLinkChangeForUnrelatedDynamicEgressNATSkipsRedistribute(t *testing.T) {
	pm := &ProcessManager{
		cfg:                      &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		kernelRuntime:            &stubNetlinkFallbackRuntime{},
		redistributeWake:         make(chan struct{}, 1),
		dynamicEgressNATParents:  map[string]struct{}{"vmbr1": {}},
		rulePlans:                map[int64]ruleDataplanePlan{},
		rangePlans:               map[int64]rangeDataplanePlan{},
		kernelNetlinkRecoverWake: make(chan struct{}, 1),
	}

	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addInterfaceName("eno2")
	trigger.addLinkNeighborInterface("eno2")
	trigger.addLinkFDBInterface("vmbr9")
	pm.handleKernelNetlinkRecoveryTrigger(trigger)

	if pm.redistributePending {
		t.Fatal("redistributePending = true, want false for unrelated link change")
	}
	if pm.kernelNetlinkRecoverPending {
		t.Fatal("kernelNetlinkRecoverPending = true, want no queued recovery for unrelated link change without fallback summary")
	}
	if pm.kernelRetryCount != 0 {
		t.Fatalf("kernelRetryCount = %d, want 0", pm.kernelRetryCount)
	}
	if pm.lastKernelRetryReason != "" {
		t.Fatalf("lastKernelRetryReason = %q, want empty", pm.lastKernelRetryReason)
	}
}

func TestShouldLogKernelNetlinkRecoveryResult(t *testing.T) {
	tests := []struct {
		name   string
		result kernelIncrementalRetryResult
		want   bool
	}{
		{
			name: "clean recovery suppressed",
			result: kernelIncrementalRetryResult{
				handled:             true,
				recoveredRuleOwners: 1,
			},
			want: false,
		},
		{
			name: "cooldown skip logged",
			result: kernelIncrementalRetryResult{
				handled:            true,
				cooldownRuleOwners: 1,
			},
			want: true,
		},
		{
			name: "backoff logged",
			result: kernelIncrementalRetryResult{
				handled:           true,
				backoffRuleOwners: 1,
			},
			want: true,
		},
		{
			name: "no recovery logged",
			result: kernelIncrementalRetryResult{
				handled: true,
			},
			want: true,
		},
		{
			name: "incremental fallback logged",
			result: kernelIncrementalRetryResult{
				handled: false,
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldLogKernelNetlinkRecoveryResult(tc.result); got != tc.want {
				t.Fatalf("shouldLogKernelNetlinkRecoveryResult(%+v) = %v, want %v", tc.result, got, tc.want)
			}
		})
	}
}
