package app

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type incrementalKernelRetryCall struct {
	retainedByEngine map[string][]Rule
	newRules         []Rule
}

type stubIncrementalKernelRuntime struct {
	assignments        map[int64]string
	supportedRules     map[int64]bool
	retainedRules      map[int64][]Rule
	retainedEgressNATs map[int64][]Rule
	incrementalCalls   []incrementalKernelRetryCall
	incrementalResults map[int64]kernelRuleApplyResult
	pressure           kernelRuntimePressureSnapshot
	snapshot           kernelRuleStatsSnapshot
	snapshotErr        error
	snapshotCalls      int
}

func (s *stubIncrementalKernelRuntime) Available() (bool, string) {
	return true, "ready"
}

func (s *stubIncrementalKernelRuntime) SupportsRule(rule Rule) (bool, string) {
	if s.supportedRules == nil || s.supportedRules[rule.ID] {
		return true, ""
	}
	return false, "unsupported"
}

func (s *stubIncrementalKernelRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	nextAssignments := make(map[int64]string, len(rules))
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		result, ok := s.incrementalResults[rule.ID]
		if !ok {
			result = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		}
		if result.Error == "" {
			engine := result.Engine
			if engine == "" {
				engine = kernelEngineTC
			}
			result.Engine = engine
			if !result.Running {
				result.Running = true
			}
			nextAssignments[rule.ID] = engine
		}
		results[rule.ID] = result
	}
	s.assignments = nextAssignments
	return results, nil
}

func (s *stubIncrementalKernelRuntime) ReconcileRetainingAssignments(retainedByEngine map[string][]Rule, newRules []Rule) (map[int64]kernelRuleApplyResult, error) {
	call := incrementalKernelRetryCall{
		retainedByEngine: cloneKernelRuleMap(retainedByEngine),
		newRules:         append([]Rule(nil), newRules...),
	}
	s.incrementalCalls = append(s.incrementalCalls, call)

	nextAssignments := make(map[int64]string)
	for engine, rules := range retainedByEngine {
		for _, rule := range rules {
			nextAssignments[rule.ID] = engine
		}
	}

	results := make(map[int64]kernelRuleApplyResult, len(newRules))
	for _, rule := range newRules {
		result, ok := s.incrementalResults[rule.ID]
		if !ok {
			result = kernelRuleApplyResult{Running: true, Engine: kernelEngineTC}
		}
		if result.Error == "" {
			engine := result.Engine
			if engine == "" {
				engine = kernelEngineTC
			}
			result.Engine = engine
			if !result.Running {
				result.Running = true
			}
			nextAssignments[rule.ID] = engine
		}
		results[rule.ID] = result
	}
	s.assignments = nextAssignments
	return results, nil
}

func (s *stubIncrementalKernelRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	s.snapshotCalls++
	if s.snapshotErr != nil {
		return emptyKernelRuleStatsSnapshot(), s.snapshotErr
	}
	if len(s.snapshot.ByRuleID) == 0 {
		return emptyKernelRuleStatsSnapshot(), nil
	}
	return s.snapshot, nil
}

func (s *stubIncrementalKernelRuntime) Maintain() error {
	return nil
}

func (s *stubIncrementalKernelRuntime) SnapshotAssignments() map[int64]string {
	out := make(map[int64]string, len(s.assignments))
	for id, engine := range s.assignments {
		out[id] = engine
	}
	return out
}

func (s *stubIncrementalKernelRuntime) Close() error {
	return nil
}

func (s *stubIncrementalKernelRuntime) retainedKernelRuleCandidates(rule Rule) ([]Rule, bool) {
	items, ok := s.retainedRules[rule.ID]
	if !ok {
		return nil, false
	}
	return append([]Rule(nil), items...), true
}

func (s *stubIncrementalKernelRuntime) retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool) {
	return nil, false
}

func (s *stubIncrementalKernelRuntime) retainedKernelEgressNATCandidates(item EgressNAT) ([]Rule, bool) {
	items, ok := s.retainedEgressNATs[item.ID]
	if !ok {
		return nil, false
	}
	return append([]Rule(nil), items...), true
}

func (s *stubIncrementalKernelRuntime) pressureSnapshot() kernelRuntimePressureSnapshot {
	return s.pressure
}

func cloneKernelRuleMap(src map[string][]Rule) map[string][]Rule {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string][]Rule, len(src))
	for engine, rules := range src {
		dst[engine] = append([]Rule(nil), rules...)
	}
	return dst
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRecoversOwnersIncrementally(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.10",
		InPort:       10001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.10",
		OutPort:      20001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.11",
		InPort:       10002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.11",
		OutPort:      20002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.11 on "eno2"; tc: skipped`,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() attempted = false, want true")
	}
	if !strings.Contains(result.detail, "rule_owners=1") || !strings.Contains(result.detail, "entries=1") {
		t.Fatalf("retryNetlinkTriggeredKernelFallbackOwners() detail = %q, want recovered rule owner summary", result.detail)
	}
	if result.retainedRuleOwners != 1 || result.retainedRangeOwners != 0 {
		t.Fatalf("retained owners = rules:%d ranges:%d, want 1/0", result.retainedRuleOwners, result.retainedRangeOwners)
	}
	if result.matchedRuleOwners != 1 || result.matchedRangeOwners != 0 {
		t.Fatalf("matched owners = rules:%d ranges:%d, want 1/0", result.matchedRuleOwners, result.matchedRangeOwners)
	}
	if result.attemptedRuleOwners != 1 || result.attemptedRangeOwners != 0 {
		t.Fatalf("attempted owners = rules:%d ranges:%d, want 1/0", result.attemptedRuleOwners, result.attemptedRangeOwners)
	}
	if result.recoveredRuleOwners != 1 || result.recoveredRangeOwners != 0 {
		t.Fatalf("recovered owners = rules:%d ranges:%d, want 1/0", result.recoveredRuleOwners, result.recoveredRangeOwners)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	if got := rt.incrementalCalls[0].retainedByEngine[kernelEngineTC]; len(got) != 1 || got[0].ID != rule1.ID {
		t.Fatalf("retained tc rules = %#v, want rule 1 pinned on tc", got)
	}
	if got := rt.incrementalCalls[0].newRules; len(got) != 1 || got[0].ID != rule2.ID {
		t.Fatalf("incremental new rules = %#v, want only recovered rule 2", got)
	}
	if !pm.kernelRules[rule1.ID] || !pm.kernelRules[rule2.ID] {
		t.Fatalf("kernelRules = %#v, want both rule owners active", pm.kernelRules)
	}
	if got := pm.rulePlans[rule2.ID]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("rule 2 plan = %+v, want kernel with cleared fallback", got)
	}
	if got := pm.kernelRuleEngines[rule2.ID]; got != kernelEngineTC {
		t.Fatalf("rule 2 kernel engine = %q, want %q", got, kernelEngineTC)
	}
	if len(pm.ruleWorkers) != 0 || len(pm.rangeWorkers) != 0 {
		t.Fatalf("userspace workers unexpectedly changed: rule=%d range=%d", len(pm.ruleWorkers), len(pm.rangeWorkers))
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersAllowsRuleRecoveryWhileEgressNATActive(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tuntap"},
			{Name: "eno1", Kind: "device"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.30",
		InPort:       11001,
		OutInterface: "vmbr0",
		OutIP:        "198.51.100.30",
		OutPort:      21001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.31",
		InPort:       11002,
		OutInterface: "vmbr0",
		OutIP:        "198.51.100.31",
		OutPort:      21002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	item := EgressNAT{
		ParentInterface: "vmbr0",
		OutInterface:    "eno1",
		OutSourceIP:     "203.0.113.10",
		Protocol:        "tcp",
		Enabled:         true,
	}
	natID, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}
	item.ID = natID
	item.Protocol = "tcp"
	item.NATType = egressNATTypeSymmetric

	retainedEgressRule := Rule{
		ID:               5001,
		InInterface:      "tap100i0",
		InIP:             "0.0.0.0",
		InPort:           0,
		OutInterface:     "eno1",
		OutIP:            "0.0.0.0",
		OutSourceIP:      "203.0.113.10",
		OutPort:          0,
		Protocol:         "tcp",
		Enabled:          true,
		kernelMode:       kernelModeEgressNAT,
		kernelNATType:    egressNATTypeSymmetric,
		kernelLogKind:    workerKindEgressNAT,
		kernelLogOwnerID: natID,
	}

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID:              kernelEngineTC,
			retainedEgressRule.ID: kernelEngineTC,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		retainedEgressNATs: map[int64][]Rule{
			natID: {retainedEgressRule},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{rule1.ID: true},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{natID: true},
		kernelRuleEngines:      map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{natID: kernelEngineTC},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID):              {kind: workerKindRule, id: rule1.ID},
			uint32(retainedEgressRule.ID): {kind: workerKindEgressNAT, id: natID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.31 on "vmbr0"; tc: skipped`,
	}
	pm.egressNATPlans[natID] = ruleDataplanePlan{
		PreferredEngine: ruleEngineKernel,
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute with active egress nat")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() attempted = false, want true")
	}
	if result.recoveredRuleOwners != 1 || result.recoveredRangeOwners != 0 {
		t.Fatalf("recovered owners = rules:%d ranges:%d, want 1/0", result.recoveredRuleOwners, result.recoveredRangeOwners)
	}
	if !pm.kernelRules[rule1.ID] || !pm.kernelRules[rule2.ID] {
		t.Fatalf("kernelRules = %#v, want both rule owners active", pm.kernelRules)
	}
	if !pm.kernelEgressNATs[natID] {
		t.Fatalf("kernelEgressNATs = %#v, want nat %d retained", pm.kernelEgressNATs, natID)
	}
	if got := pm.egressNATPlans[natID]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("egress nat plan = %+v, want kernel with cleared fallback", got)
	}
	if got := pm.kernelEgressNATEngines[natID]; got != kernelEngineTC {
		t.Fatalf("egress nat kernel engine = %q, want %q", got, kernelEngineTC)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	gotRetained := rt.incrementalCalls[0].retainedByEngine[kernelEngineTC]
	if len(gotRetained) != 2 {
		t.Fatalf("retained tc rules = %#v, want 2 retained entries", gotRetained)
	}
	foundRule := false
	foundEgress := false
	for _, item := range gotRetained {
		switch item.ID {
		case rule1.ID:
			foundRule = true
		case retainedEgressRule.ID:
			foundEgress = true
		}
	}
	if !foundRule || !foundEgress {
		t.Fatalf("retained tc rules = %#v, want rule %d and egress synthetic rule %d", gotRetained, rule1.ID, retainedEgressRule.ID)
	}
	if got := rt.incrementalCalls[0].newRules; len(got) != 1 || got[0].ID != rule2.ID {
		t.Fatalf("incremental new rules = %#v, want only recovered rule 2", got)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRefreshesActiveKernelRuleOnAddrChange(t *testing.T) {
	db := openTestDB(t)

	rule := Rule{
		InInterface:  "eno9",
		InIP:         "192.0.2.51",
		InPort:       15001,
		OutInterface: "eno1",
		OutIP:        "198.51.100.51",
		OutPort:      25001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}
	rule.ID = ruleID
	rule.kernelLogKind = workerKindRule
	rule.kernelLogOwnerID = ruleID

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{},
	}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 1},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{rule.ID: true},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{},
		kernelRuleEngines:      map[int64]string{rule.ID: kernelEngineTC},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule.ID): {kind: workerKindRule, id: rule.ID},
		},
	}
	pm.rulePlans[rule.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
		AddrRefresh: kernelAddressRefreshMetadata{
			OutInterface: "eno1",
			Family:       ipFamilyIPv4,
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("addr")
	trigger.addInterfaceName("eno1")
	trigger.addAddrFamily(ipFamilyIPv4)

	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() handled = false, want true")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() attempted = false, want true")
	}
	if result.matchedRuleOwners != 1 || result.attemptedRuleOwners != 1 || result.recoveredRuleOwners != 1 {
		t.Fatalf("rule owner counts = matched:%d attempted:%d recovered:%d, want 1/1/1", result.matchedRuleOwners, result.attemptedRuleOwners, result.recoveredRuleOwners)
	}
	if got := rt.assignments[rule.ID]; got != kernelEngineTC {
		t.Fatalf("runtime assignments = %#v, want refreshed rule %d on %q", rt.assignments, rule.ID, kernelEngineTC)
	}
	if !pm.kernelRules[rule.ID] {
		t.Fatalf("kernelRules = %#v, want rule %d active after addr refresh", pm.kernelRules, rule.ID)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRecoversSourceIPFallbackOnAddrChange(t *testing.T) {
	db := openTestDB(t)

	rule := Rule{
		InInterface:  "eno9",
		InIP:         "192.0.2.52",
		InPort:       15002,
		OutInterface: "eno1",
		OutIP:        "198.51.100.52",
		OutSourceIP:  "198.51.100.10",
		OutPort:      25002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule() error = %v", err)
	}
	rule.ID = ruleID

	rt := &stubIncrementalKernelRuntime{}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 1},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{},
		kernelRuleEngines:      map[int64]string{},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{},
		kernelFlowOwners:       map[uint32]kernelCandidateOwner{},
	}
	pm.rulePlans[rule.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  "outbound source IP is not assigned to the selected outbound interface",
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "source_ip_unassigned",
			OutInterface: "eno1",
		},
		AddrRefresh: kernelAddressRefreshMetadata{
			OutInterface: "eno1",
			Family:       ipFamilyIPv4,
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("addr")
	trigger.addInterfaceName("eno1")
	trigger.addAddrFamily(ipFamilyIPv4)

	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() handled = false, want true")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() attempted = false, want true")
	}
	if result.matchedRuleOwners != 1 || result.attemptedRuleOwners != 1 || result.recoveredRuleOwners != 1 {
		t.Fatalf("rule owner counts = matched:%d attempted:%d recovered:%d, want 1/1/1", result.matchedRuleOwners, result.attemptedRuleOwners, result.recoveredRuleOwners)
	}
	if got := rt.assignments[rule.ID]; got != kernelEngineTC {
		t.Fatalf("runtime assignments = %#v, want recovered rule %d on %q", rt.assignments, rule.ID, kernelEngineTC)
	}
	if !pm.kernelRules[rule.ID] {
		t.Fatalf("kernelRules = %#v, want rule %d recovered into kernel", pm.kernelRules, rule.ID)
	}
	if got := pm.rulePlans[rule.ID]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("rule plan = %+v, want kernel engine with cleared fallback after addr recovery", got)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRecoversMatchedEgressNATFallbackIncrementally(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
			{Name: "eno1", Kind: "device"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	rule := Rule{
		InInterface:  "eno9",
		InIP:         "192.0.2.41",
		InPort:       14001,
		OutInterface: "eno8",
		OutIP:        "198.51.100.41",
		OutPort:      24001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule(rule) error = %v", err)
	}
	rule.ID = ruleID
	rule.kernelLogKind = workerKindRule
	rule.kernelLogOwnerID = ruleID

	item := EgressNAT{
		ParentInterface: "vmbr1",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
		OutSourceIP:     "203.0.113.40",
		Protocol:        "tcp",
		Enabled:         true,
	}
	natID, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			ruleID: kernelEngineTC,
		},
		retainedRules: map[int64][]Rule{
			ruleID: {rule},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{ruleID: true},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{},
		kernelRuleEngines:      map[int64]string{ruleID: kernelEngineTC},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(ruleID): {kind: workerKindRule, id: ruleID},
		},
	}
	pm.rulePlans[ruleID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.egressNATPlans[natID] = ruleDataplanePlan{
		PreferredEngine: ruleEngineKernel,
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.40 on "eno1"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "neighbor_missing",
			OutInterface: "eno1",
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno1")
	trigger.addBackendIP("198.51.100.40")

	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() unexpectedly requested full redistribute for matched egress nat fallback owner")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() attempted = false, want true")
	}
	if result.matchedEgressNATs != 1 || result.attemptedEgressNATs != 1 || result.recoveredEgressNATs != 1 {
		t.Fatalf("egress nat retry counts = matched:%d attempted:%d recovered:%d, want 1/1/1", result.matchedEgressNATs, result.attemptedEgressNATs, result.recoveredEgressNATs)
	}
	if !pm.kernelEgressNATs[natID] {
		t.Fatalf("kernelEgressNATs = %#v, want nat %d active", pm.kernelEgressNATs, natID)
	}
	if got := pm.egressNATPlans[natID]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("egress nat plan = %+v, want kernel with cleared fallback", got)
	}
	if got := pm.kernelEgressNATEngines[natID]; got != kernelEngineTC {
		t.Fatalf("egress nat kernel engine = %q, want %q", got, kernelEngineTC)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	retained := rt.incrementalCalls[0].retainedByEngine[kernelEngineTC]
	if len(retained) != 1 || retained[0].ID != ruleID {
		t.Fatalf("retained tc rules = %#v, want retained forward rule %d", retained, ruleID)
	}
	newRules := rt.incrementalCalls[0].newRules
	if len(newRules) != 1 {
		t.Fatalf("incremental new rules = %#v, want 1 recovered egress nat rule", newRules)
	}
	if newRules[0].kernelLogKind != workerKindEgressNAT || newRules[0].kernelLogOwnerID != natID {
		t.Fatalf("incremental new rule = %+v, want egress nat owner %d", newRules[0], natID)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersPreservesEgressNATCooldownAndBackoff(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
			{Name: "eno1", Kind: "device"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	rule := Rule{
		InInterface:  "eno9",
		InIP:         "192.0.2.51",
		InPort:       15001,
		OutInterface: "eno8",
		OutIP:        "198.51.100.51",
		OutPort:      25001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule(rule) error = %v", err)
	}
	rule.ID = ruleID
	rule.kernelLogKind = workerKindRule
	rule.kernelLogOwnerID = ruleID

	item := EgressNAT{
		ParentInterface: "vmbr1",
		ChildInterface:  "tap100i0",
		OutInterface:    "eno1",
		OutSourceIP:     "203.0.113.41",
		Protocol:        "tcp",
		Enabled:         true,
	}
	natID, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	syntheticRuleID := ruleID + 1
	owner := kernelCandidateOwner{kind: workerKindEgressNAT, id: natID}
	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			ruleID: kernelEngineTC,
		},
		retainedRules: map[int64][]Rule{
			ruleID: {rule},
		},
		incrementalResults: map[int64]kernelRuleApplyResult{
			syntheticRuleID: {Error: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.41 on "eno1"; tc: skipped`},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{ruleID: true},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{},
		kernelRuleEngines:      map[int64]string{ruleID: kernelEngineTC},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(ruleID): {kind: workerKindRule, id: ruleID},
		},
	}
	pm.rulePlans[ruleID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.egressNATPlans[natID] = ruleDataplanePlan{
		PreferredEngine: ruleEngineKernel,
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.41 on "eno1"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "neighbor_missing",
			OutInterface: "eno1",
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno1")
	trigger.addBackendIP("198.51.100.41")

	first := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !first.handled || first.recoveredEgressNATs != 0 {
		t.Fatalf("first retry result = %+v, want handled without recovery", first)
	}
	if !strings.Contains(first.detail, "backoff_egress_nat_owners=1") {
		t.Fatalf("first retry detail = %q, want egress nat backoff owner count", first.detail)
	}
	if first.backoffScope != "egress_nat_ids=1" {
		t.Fatalf("backoff scope = %q, want %q", first.backoffScope, "egress_nat_ids=1")
	}
	pm.mu.Lock()
	firstCooldown, ok := pm.kernelNetlinkOwnerRetryCooldownUntil[owner]
	firstFailureCount := pm.kernelNetlinkOwnerRetryFailures[owner]
	pm.mu.Unlock()
	if !ok || !firstCooldown.Until.After(time.Now()) {
		t.Fatalf("egress nat owner cooldown = %v, want active cooldown after failed retry", firstCooldown)
	}
	if firstCooldown.Source != "neighbor" {
		t.Fatalf("egress nat owner cooldown source = %q, want %q", firstCooldown.Source, "neighbor")
	}
	if firstFailureCount != 1 {
		t.Fatalf("egress nat owner failure count after first retry = %d, want 1", firstFailureCount)
	}

	second := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !second.handled || second.cooldownEgressNATs != 1 {
		t.Fatalf("second retry result = %+v, want cooldown skip for egress nat owner", second)
	}
	if second.cooldownScope != "egress_nat_ids=1" {
		t.Fatalf("cooldown scope = %q, want %q", second.cooldownScope, "egress_nat_ids=1")
	}

	pm.mu.Lock()
	pm.kernelNetlinkOwnerRetryCooldownUntil[owner] = kernelNetlinkOwnerRetryCooldownState{
		Until:  time.Now().Add(-time.Second),
		Source: "neighbor",
	}
	pm.mu.Unlock()
	rt.incrementalResults = nil

	third := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !third.handled || third.recoveredEgressNATs != 1 {
		t.Fatalf("third retry result = %+v, want recovered egress nat owner after cooldown expiry", third)
	}
	pm.mu.Lock()
	_, stillCooling := pm.kernelNetlinkOwnerRetryCooldownUntil[owner]
	_, stillFailing := pm.kernelNetlinkOwnerRetryFailures[owner]
	pm.mu.Unlock()
	if stillCooling {
		t.Fatal("egress nat owner cooldown still present after successful recovery")
	}
	if stillFailing {
		t.Fatal("egress nat owner failure count still present after successful recovery")
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRefreshesDynamicEgressNATOwnersOnLinkChange(t *testing.T) {
	db := openTestDB(t)

	oldLoad := loadInterfaceInfosForEgressNATTests
	loadInterfaceInfosForEgressNATTests = func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "vmbr1", Kind: "bridge"},
			{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
			{Name: "tap101i0", Parent: "vmbr1", Kind: "tuntap"},
			{Name: "eno1", Kind: "device"},
		}, nil
	}
	defer func() {
		loadInterfaceInfosForEgressNATTests = oldLoad
	}()

	rule := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.50",
		InPort:       15001,
		OutInterface: "vmbr1",
		OutIP:        "198.51.100.50",
		OutPort:      25001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	ruleID, err := dbAddRule(db, &rule)
	if err != nil {
		t.Fatalf("dbAddRule(rule) error = %v", err)
	}
	rule.ID = ruleID
	rule.kernelLogKind = workerKindRule
	rule.kernelLogOwnerID = ruleID

	item := EgressNAT{
		ParentInterface: "vmbr1",
		OutInterface:    "eno1",
		OutSourceIP:     "203.0.113.20",
		Protocol:        "tcp",
		Enabled:         true,
	}
	natID, err := dbAddEgressNAT(db, &item)
	if err != nil {
		t.Fatalf("dbAddEgressNAT() error = %v", err)
	}

	oldEgressRule := Rule{
		ID:               5001,
		InInterface:      "tap100i0",
		InIP:             "0.0.0.0",
		InPort:           0,
		OutInterface:     "eno1",
		OutIP:            "0.0.0.0",
		OutSourceIP:      "203.0.113.20",
		OutPort:          0,
		Protocol:         "tcp",
		Enabled:          true,
		kernelMode:       kernelModeEgressNAT,
		kernelNATType:    egressNATTypeSymmetric,
		kernelLogKind:    workerKindEgressNAT,
		kernelLogOwnerID: natID,
	}

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			ruleID:           kernelEngineTC,
			oldEgressRule.ID: kernelEngineTC,
		},
		retainedRules: map[int64][]Rule{
			ruleID: {rule},
		},
		retainedEgressNATs: map[int64][]Rule{
			natID: {oldEgressRule},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:            make(map[int]*WorkerInfo),
		rangeWorkers:           make(map[int]*WorkerInfo),
		db:                     db,
		cfg:                    &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:              map[int64]ruleDataplanePlan{},
		rangePlans:             map[int64]rangeDataplanePlan{},
		egressNATPlans:         map[int64]ruleDataplanePlan{},
		kernelRuntime:          rt,
		kernelRules:            map[int64]bool{ruleID: true},
		kernelRanges:           map[int64]bool{},
		kernelEgressNATs:       map[int64]bool{natID: true},
		kernelRuleEngines:      map[int64]string{ruleID: kernelEngineTC},
		kernelRangeEngines:     map[int64]string{},
		kernelEgressNATEngines: map[int64]string{natID: kernelEngineTC},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(ruleID):           {kind: workerKindRule, id: ruleID},
			uint32(oldEgressRule.ID): {kind: workerKindEgressNAT, id: natID},
		},
	}
	pm.rulePlans[ruleID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.egressNATPlans[natID] = ruleDataplanePlan{
		PreferredEngine: ruleEngineKernel,
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}

	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addInterfaceName("vmbr1")

	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() unexpectedly requested full redistribute for dynamic egress nat refresh")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() attempted = false, want true")
	}
	if result.recoveredEgressNATs != 1 {
		t.Fatalf("recovered egress nat owners = %d, want 1", result.recoveredEgressNATs)
	}
	if !pm.kernelEgressNATs[natID] {
		t.Fatalf("kernelEgressNATs = %#v, want nat %d active", pm.kernelEgressNATs, natID)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	retained := rt.incrementalCalls[0].retainedByEngine[kernelEngineTC]
	if len(retained) != 1 || retained[0].ID != ruleID {
		t.Fatalf("retained tc rules = %#v, want only retained forward rule %d", retained, ruleID)
	}
	newRules := rt.incrementalCalls[0].newRules
	if len(newRules) != 2 {
		t.Fatalf("incremental new rules = %#v, want 2 refreshed egress nat rules", newRules)
	}
	targets := map[string]struct{}{}
	for _, item := range newRules {
		if item.kernelLogKind != workerKindEgressNAT || item.kernelLogOwnerID != natID {
			t.Fatalf("incremental new rule = %+v, want egress nat owner %d", item, natID)
		}
		targets[item.InInterface] = struct{}{}
	}
	if _, ok := targets["tap100i0"]; !ok {
		t.Fatalf("new egress nat targets = %#v, want tap100i0 present", targets)
	}
	if _, ok := targets["tap101i0"]; !ok {
		t.Fatalf("new egress nat targets = %#v, want tap101i0 present", targets)
	}
	if _, ok := pm.kernelFlowOwners[uint32(oldEgressRule.ID)]; ok {
		t.Fatalf("kernelFlowOwners still contains old egress rule id %d: %#v", oldEgressRule.ID, pm.kernelFlowOwners)
	}
	egressEntries := 0
	for _, owner := range pm.kernelFlowOwners {
		if owner.kind == workerKindEgressNAT && owner.id == natID {
			egressEntries++
		}
	}
	if egressEntries != 2 {
		t.Fatalf("kernelFlowOwners egress entry count = %d, want 2", egressEntries)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersTargetsMatchingNeighborTrigger(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.15",
		InPort:       10101,
		OutInterface: "eno2",
		OutIP:        "198.51.100.15",
		OutPort:      20101,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.16",
		InPort:       10102,
		OutInterface: "eno2",
		OutIP:        "198.51.100.16",
		OutPort:      20102,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rule3 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.17",
		InPort:       10103,
		OutInterface: "eno3",
		OutIP:        "198.51.100.17",
		OutPort:      20103,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id3, err := dbAddRule(db, &rule3)
	if err != nil {
		t.Fatalf("dbAddRule(rule3) error = %v", err)
	}
	rule3.ID = id3

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
			rule3.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.16 on "eno2"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno2", BackendIP: "198.51.100.16"},
	}
	pm.rulePlans[rule3.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.17 on "eno3"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno3", BackendIP: "198.51.100.17"},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno2")
	trigger.addBackendIP("198.51.100.16")
	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() unexpectedly requested full redistribute")
	}
	if result.matchedRuleOwners != 1 || result.matchedRangeOwners != 0 {
		t.Fatalf("matched owners = rules:%d ranges:%d, want 1/0", result.matchedRuleOwners, result.matchedRangeOwners)
	}
	if result.attemptedRuleOwners != 1 || result.attemptedRangeOwners != 0 {
		t.Fatalf("attempted owners = rules:%d ranges:%d, want 1/0", result.attemptedRuleOwners, result.attemptedRangeOwners)
	}
	if result.recoveredRuleOwners != 1 {
		t.Fatalf("recovered rule owners = %d, want 1 targeted owner", result.recoveredRuleOwners)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	if got := rt.incrementalCalls[0].newRules; len(got) != 1 || got[0].ID != rule2.ID {
		t.Fatalf("incremental new rules = %#v, want only targeted rule 2", got)
	}
	if pm.kernelRules[rule3.ID] {
		t.Fatalf("kernelRules = %#v, did not expect unrelated rule 3 to re-enter kernel", pm.kernelRules)
	}
	if got := pm.rulePlans[rule3.ID]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 3 plan = %+v, want userspace unchanged for unmatched trigger", got)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersTargetsMatchingFDBTrigger(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.18",
		InPort:       10201,
		OutInterface: "eno2",
		OutIP:        "198.51.100.18",
		OutPort:      20201,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.19",
		InPort:       10202,
		OutInterface: "vmbr1",
		OutIP:        "198.51.100.19",
		OutPort:      20202,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rule3 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.20",
		InPort:       10203,
		OutInterface: "vmbr1",
		OutIP:        "198.51.100.20",
		OutPort:      20203,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id3, err := dbAddRule(db, &rule3)
	if err != nil {
		t.Fatalf("dbAddRule(rule3) error = %v", err)
	}
	rule3.ID = id3

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
			rule3.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "fdb_missing",
			OutInterface: "vmbr1",
			BackendIP:    "198.51.100.19",
			BackendMAC:   "02:00:5e:10:00:19",
		},
	}
	pm.rulePlans[rule3.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "fdb_missing",
			OutInterface: "vmbr1",
			BackendIP:    "198.51.100.20",
			BackendMAC:   "02:00:5e:10:00:20",
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("fdb")
	trigger.addInterfaceName("vmbr1")
	trigger.addBackendMAC("02:00:5e:10:00:19")
	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() unexpectedly requested full redistribute")
	}
	if result.recoveredRuleOwners != 1 {
		t.Fatalf("recovered rule owners = %d, want 1 targeted owner", result.recoveredRuleOwners)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	if got := rt.incrementalCalls[0].newRules; len(got) != 1 || got[0].ID != rule2.ID {
		t.Fatalf("incremental new rules = %#v, want only targeted rule 2", got)
	}
	if pm.kernelRules[rule3.ID] {
		t.Fatalf("kernelRules = %#v, did not expect unrelated rule 3 to re-enter kernel", pm.kernelRules)
	}
	if got := pm.rulePlans[rule3.ID]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 3 plan = %+v, want userspace unchanged for unmatched FDB trigger", got)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersTargetsLinkBridgeMemberTrigger(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.21",
		InPort:       10301,
		OutInterface: "eno2",
		OutIP:        "198.51.100.21",
		OutPort:      20301,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.22",
		InPort:       10302,
		OutInterface: "eno2",
		OutIP:        "198.51.100.22",
		OutPort:      20302,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rule3 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.23",
		InPort:       10303,
		OutInterface: "vmbr1",
		OutIP:        "198.51.100.23",
		OutPort:      20303,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id3, err := dbAddRule(db, &rule3)
	if err != nil {
		t.Fatalf("dbAddRule(rule3) error = %v", err)
	}
	rule3.ID = id3

	rule4 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.24",
		InPort:       10304,
		OutInterface: "vmbr1",
		OutIP:        "198.51.100.24",
		OutPort:      20304,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id4, err := dbAddRule(db, &rule4)
	if err != nil {
		t.Fatalf("dbAddRule(rule4) error = %v", err)
	}
	rule4.ID = id4

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
			rule3.ID: true,
			rule4.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.22 on "eno2"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno2", BackendIP: "198.51.100.22"},
	}
	pm.rulePlans[rule3.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.23 on "vmbr1"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "vmbr1", BackendIP: "198.51.100.23"},
	}
	pm.rulePlans[rule4.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
		TransientFallback: kernelTransientFallbackMetadata{
			ReasonClass:  "fdb_missing",
			OutInterface: "vmbr1",
			BackendIP:    "198.51.100.24",
			BackendMAC:   "02:00:5e:10:00:24",
		},
	}

	trigger := newKernelNetlinkRecoveryTrigger("link")
	trigger.addLinkNeighborInterface("eno2")
	trigger.addLinkFDBInterface("vmbr1")
	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwnersForTrigger() unexpectedly requested full redistribute")
	}
	if result.recoveredRuleOwners != 2 {
		t.Fatalf("recovered rule owners = %d, want 2 targeted owners", result.recoveredRuleOwners)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls = %d, want 1", len(rt.incrementalCalls))
	}
	if got := rt.incrementalCalls[0].newRules; len(got) != 2 {
		t.Fatalf("incremental new rules = %#v, want two targeted owners", got)
	}
	gotIDs := map[int64]bool{}
	for _, rule := range rt.incrementalCalls[0].newRules {
		gotIDs[rule.ID] = true
	}
	if !gotIDs[rule2.ID] || !gotIDs[rule4.ID] || gotIDs[rule3.ID] {
		t.Fatalf("incremental new rule IDs = %#v, want rule2 and rule4 only", gotIDs)
	}
	if pm.kernelRules[rule3.ID] {
		t.Fatalf("kernelRules = %#v, did not expect bridge neighbor-only rule 3 to re-enter kernel", pm.kernelRules)
	}
	if got := pm.rulePlans[rule3.ID]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 3 plan = %+v, want userspace unchanged for unmatched bridge neighbor fallback", got)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRespectsPressureHold(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.20",
		InPort:       11001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.20",
		OutPort:      21001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.21",
		InPort:       11002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.21",
		OutPort:      21002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		pressure: kernelRuntimePressureSnapshot{
			Engine:          kernelEngineTC,
			Level:           kernelRuntimePressureLevelHold,
			Active:          true,
			Reason:          "kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, keeping existing kernel owners and routing new owners to userspace until usage drops below 85%",
			AssignedEntries: 1,
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.21 on "eno2"; tc: skipped`,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute under hold pressure")
	}
	if !result.attempted {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() attempted = false, want true under hold pressure")
	}
	if result.recoveredRuleOwners != 0 || result.recoveredRangeOwners != 0 {
		t.Fatalf("recovered owners = rules:%d ranges:%d, want 0/0 under hold pressure", result.recoveredRuleOwners, result.recoveredRangeOwners)
	}
	if result.retainedRuleOwners != 1 || result.retainedRangeOwners != 0 {
		t.Fatalf("retained owners = rules:%d ranges:%d, want 1/0 under hold pressure", result.retainedRuleOwners, result.retainedRangeOwners)
	}
	if len(rt.incrementalCalls) != 0 {
		t.Fatalf("incremental reconcile calls = %d, want 0 when pressure policy blocks new owners", len(rt.incrementalCalls))
	}
	if !pm.kernelRules[rule1.ID] {
		t.Fatalf("kernelRules = %#v, want retained rule 1 to stay active", pm.kernelRules)
	}
	if pm.kernelRules[rule2.ID] {
		t.Fatalf("kernelRules = %#v, did not expect rule 2 to re-enter kernel under hold pressure", pm.kernelRules)
	}
	if got := pm.rulePlans[rule2.ID]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 2 plan = %+v, want userspace retained under hold pressure", got)
	}
	if !strings.Contains(result.detail, "no recoverable owners") {
		t.Fatalf("retryNetlinkTriggeredKernelFallbackOwners() detail = %q, want no recoverable owners message", result.detail)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersSkipsOwnerCooldown(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.25",
		InPort:       10401,
		OutInterface: "eno2",
		OutIP:        "198.51.100.25",
		OutPort:      20401,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.26",
		InPort:       10402,
		OutInterface: "eno2",
		OutIP:        "198.51.100.26",
		OutPort:      20402,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	owner2 := kernelCandidateOwner{kind: workerKindRule, id: rule2.ID}
	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
		kernelNetlinkOwnerRetryCooldownUntil: map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState{
			owner2: {Until: time.Now().Add(time.Minute), Source: "neighbor"},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.26 on "eno2"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno2", BackendIP: "198.51.100.26"},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno2")
	trigger.addBackendIP("198.51.100.26")
	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !result.handled || !result.attempted {
		t.Fatalf("retry result = %+v, want handled attempted cooldown skip", result)
	}
	if result.cooldownRuleOwners != 1 || result.cooldownRangeOwners != 0 {
		t.Fatalf("cooldown owners = rules:%d ranges:%d, want 1/0", result.cooldownRuleOwners, result.cooldownRangeOwners)
	}
	if len(rt.incrementalCalls) != 0 {
		t.Fatalf("incremental reconcile calls = %d, want 0 while owner cooldown is active", len(rt.incrementalCalls))
	}
	if !strings.Contains(result.detail, "owner cooldown") {
		t.Fatalf("result detail = %q, want owner cooldown message", result.detail)
	}
	if result.cooldownSummary != "neighbor=1" {
		t.Fatalf("cooldown summary = %q, want %q", result.cooldownSummary, "neighbor=1")
	}
	if result.cooldownScope != "rule_ids=2" {
		t.Fatalf("cooldown scope = %q, want %q", result.cooldownScope, "rule_ids=2")
	}
	if !strings.Contains(result.detail, "cooldown_reasons=neighbor=1") {
		t.Fatalf("result detail = %q, want cooldown summary suffix", result.detail)
	}
	if pm.kernelRules[rule2.ID] {
		t.Fatalf("kernelRules = %#v, did not expect cooled down owner to re-enter kernel", pm.kernelRules)
	}
}

func TestActiveKernelNetlinkOwnerRetryCooldownWindow(t *testing.T) {
	now := time.Now()
	nextExpiry := now.Add(2 * time.Second)
	clearAt := now.Add(5 * time.Second)
	next, clear := activeKernelNetlinkOwnerRetryCooldownWindow(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState{
		{kind: workerKindRule, id: 1}:  {Until: nextExpiry, Source: "neighbor"},
		{kind: workerKindRange, id: 2}: {Until: clearAt, Source: "fdb"},
		{kind: workerKindRule, id: 3}:  {Until: now.Add(-time.Second), Source: "link"},
	}, now)
	if !next.Equal(nextExpiry) {
		t.Fatalf("next cooldown expiry = %v, want %v", next, nextExpiry)
	}
	if !clear.Equal(clearAt) {
		t.Fatalf("cooldown clear at = %v, want %v", clear, clearAt)
	}
}

func TestKernelNetlinkOwnerRetryCooldownDurationBackoff(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{failures: 0, want: kernelNetlinkOwnerRetryCooldown},
		{failures: 1, want: kernelNetlinkOwnerRetryCooldown},
		{failures: 2, want: 12 * time.Second},
		{failures: 3, want: 24 * time.Second},
		{failures: 4, want: kernelNetlinkOwnerRetryCooldownMax},
		{failures: 8, want: kernelNetlinkOwnerRetryCooldownMax},
	}
	for _, tc := range cases {
		if got := kernelNetlinkOwnerRetryCooldownDuration(tc.failures); got != tc.want {
			t.Fatalf("cooldown duration(%d) = %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersRecordsAndClearsOwnerCooldown(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.27",
		InPort:       10411,
		OutInterface: "eno2",
		OutIP:        "198.51.100.27",
		OutPort:      20411,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.28",
		InPort:       10412,
		OutInterface: "eno2",
		OutIP:        "198.51.100.28",
		OutPort:      20412,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	owner2 := kernelCandidateOwner{kind: workerKindRule, id: rule2.ID}
	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		incrementalResults: map[int64]kernelRuleApplyResult{
			rule2.ID: {Error: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.28 on "eno2"; tc: skipped`},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.28 on "eno2"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno2", BackendIP: "198.51.100.28"},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno2")
	trigger.addBackendIP("198.51.100.28")

	first := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !first.handled || first.recoveredRuleOwners != 0 {
		t.Fatalf("first retry result = %+v, want handled without recovery", first)
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls after failure = %d, want 1", len(rt.incrementalCalls))
	}
	pm.mu.Lock()
	firstCooldown, ok := pm.kernelNetlinkOwnerRetryCooldownUntil[owner2]
	firstFailureCount := pm.kernelNetlinkOwnerRetryFailures[owner2]
	pm.mu.Unlock()
	if !ok || !firstCooldown.Until.After(time.Now()) {
		t.Fatalf("owner cooldown = %v, want active cooldown after failed retry", firstCooldown)
	}
	if firstCooldown.Source != "neighbor" {
		t.Fatalf("owner cooldown source = %q, want %q", firstCooldown.Source, "neighbor")
	}
	if firstFailureCount != 1 {
		t.Fatalf("owner failure count after first retry = %d, want 1", firstFailureCount)
	}
	if !strings.Contains(first.detail, "backoff_rule_owners=1") {
		t.Fatalf("first retry detail = %q, want backoff owner count", first.detail)
	}
	if !strings.Contains(first.detail, "backoff_reasons=neighbor=1") {
		t.Fatalf("first retry detail = %q, want backoff reason summary", first.detail)
	}
	if !strings.Contains(first.detail, "backoff_max_failures=1") {
		t.Fatalf("first retry detail = %q, want backoff failure streak", first.detail)
	}
	if first.backoffScope != "rule_ids=2" {
		t.Fatalf("backoff scope = %q, want %q", first.backoffScope, "rule_ids=2")
	}

	rt.incrementalResults = nil
	second := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !second.handled || second.cooldownRuleOwners != 1 {
		t.Fatalf("second retry result = %+v, want cooldown skip", second)
	}
	if second.cooldownSummary != "neighbor=1" {
		t.Fatalf("second cooldown summary = %q, want %q", second.cooldownSummary, "neighbor=1")
	}
	if len(rt.incrementalCalls) != 1 {
		t.Fatalf("incremental reconcile calls after cooldown skip = %d, want still 1", len(rt.incrementalCalls))
	}

	pm.mu.Lock()
	pm.kernelNetlinkOwnerRetryCooldownUntil[owner2] = kernelNetlinkOwnerRetryCooldownState{
		Until:  time.Now().Add(-time.Second),
		Source: "neighbor",
	}
	pm.mu.Unlock()

	third := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !third.handled || third.recoveredRuleOwners != 1 {
		t.Fatalf("third retry result = %+v, want recovered owner after cooldown expiry", third)
	}
	if len(rt.incrementalCalls) != 2 {
		t.Fatalf("incremental reconcile calls after cooldown expiry = %d, want 2", len(rt.incrementalCalls))
	}
	pm.mu.Lock()
	_, stillCooling := pm.kernelNetlinkOwnerRetryCooldownUntil[owner2]
	_, stillFailing := pm.kernelNetlinkOwnerRetryFailures[owner2]
	pm.mu.Unlock()
	if stillCooling {
		t.Fatal("owner cooldown still present after successful recovery")
	}
	if stillFailing {
		t.Fatal("owner failure count still present after successful recovery")
	}
	if !pm.kernelRules[rule2.ID] {
		t.Fatalf("kernelRules = %#v, want recovered owner back in kernel", pm.kernelRules)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersEscalatesOwnerCooldownAfterRepeatedFailures(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.41",
		InPort:       10421,
		OutInterface: "eno2",
		OutIP:        "198.51.100.41",
		OutPort:      20421,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.42",
		InPort:       10422,
		OutInterface: "eno2",
		OutIP:        "198.51.100.42",
		OutPort:      20422,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	owner2 := kernelCandidateOwner{kind: workerKindRule, id: rule2.ID}
	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		incrementalResults: map[int64]kernelRuleApplyResult{
			rule2.ID: {Error: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.42 on "eno2"; tc: skipped`},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:    true,
		EffectiveEngine:   ruleEngineUserspace,
		FallbackReason:    `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.42 on "eno2"; tc: skipped`,
		TransientFallback: kernelTransientFallbackMetadata{ReasonClass: "neighbor_missing", OutInterface: "eno2", BackendIP: "198.51.100.42"},
	}

	trigger := newKernelNetlinkRecoveryTrigger("neighbor")
	trigger.addInterfaceName("eno2")
	trigger.addBackendIP("198.51.100.42")

	firstStarted := time.Now()
	first := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !first.handled || first.recoveredRuleOwners != 0 {
		t.Fatalf("first retry result = %+v, want handled without recovery", first)
	}
	pm.mu.Lock()
	firstCooldown := pm.kernelNetlinkOwnerRetryCooldownUntil[owner2]
	firstFailureCount := pm.kernelNetlinkOwnerRetryFailures[owner2]
	pm.kernelNetlinkOwnerRetryCooldownUntil[owner2] = kernelNetlinkOwnerRetryCooldownState{
		Until:  time.Now().Add(-time.Second),
		Source: firstCooldown.Source,
	}
	pm.mu.Unlock()
	firstDuration := firstCooldown.Until.Sub(firstStarted)
	if firstFailureCount != 1 {
		t.Fatalf("owner failure count after first failure = %d, want 1", firstFailureCount)
	}

	secondStarted := time.Now()
	second := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	if !second.handled || second.recoveredRuleOwners != 0 {
		t.Fatalf("second retry result = %+v, want handled without recovery", second)
	}
	pm.mu.Lock()
	secondCooldown := pm.kernelNetlinkOwnerRetryCooldownUntil[owner2]
	secondFailureCount := pm.kernelNetlinkOwnerRetryFailures[owner2]
	pm.mu.Unlock()
	secondDuration := secondCooldown.Until.Sub(secondStarted)
	if secondFailureCount != 2 {
		t.Fatalf("owner failure count after second failure = %d, want 2", secondFailureCount)
	}
	if secondDuration <= firstDuration {
		t.Fatalf("second cooldown duration = %v, want greater than first %v", secondDuration, firstDuration)
	}
	if secondDuration < kernelNetlinkOwnerRetryCooldownDuration(2)-time.Second {
		t.Fatalf("second cooldown duration = %v, want around %v", secondDuration, kernelNetlinkOwnerRetryCooldownDuration(2))
	}
	if !strings.Contains(second.detail, "backoff_max_failures=2") {
		t.Fatalf("second retry detail = %q, want escalated backoff failure streak", second.detail)
	}
	if !strings.Contains(second.detail, "backoff_max_delay=12s") {
		t.Fatalf("second retry detail = %q, want escalated backoff duration", second.detail)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersSkipsSharedProxyRefresh(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddSite(db, &Site{
		Domain:       "example.com",
		ListenIP:     "198.51.100.50",
		BackendIP:    "192.0.2.50",
		BackendHTTP:  80,
		BackendHTTPS: 443,
		Enabled:      true,
	}); err != nil {
		t.Fatalf("dbAddSite() error = %v", err)
	}

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
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

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
	rule2.ID = id2

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.31 on "eno2"; tc: skipped`,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute")
	}
	if pm.sharedProxy != nil {
		t.Fatalf("sharedProxy = %#v, want nil because incremental kernel retry should not touch site proxy state", pm.sharedProxy)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersSkipsStatsRefreshWithoutRecoveredOwners(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.60",
		InPort:       14001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.60",
		OutPort:      24001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.61",
		InPort:       14002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.61",
		OutPort:      24002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}

	prevSnapshotAt := time.Now()
	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			id2:      true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		pressure: kernelRuntimePressureSnapshot{
			Engine:          kernelEngineTC,
			Level:           kernelRuntimePressureLevelHold,
			Active:          true,
			Reason:          "kernel dataplane pressure: hold",
			AssignedEntries: 1,
		},
		snapshot: kernelRuleStatsSnapshot{
			ByRuleID: map[uint32]kernelRuleStats{
				uint32(rule1.ID): {
					TCPActiveConns: 99,
				},
			},
		},
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
		kernelRuleStats: map[int64]RuleStatsReport{
			rule1.ID: {
				RuleID:      rule1.ID,
				ActiveConns: 7,
				TotalConns:  13,
			},
		},
		kernelStatsSnapshot: kernelRuleStatsSnapshot{
			ByRuleID: map[uint32]kernelRuleStats{
				uint32(rule1.ID): {
					TCPActiveConns: 7,
				},
			},
		},
		kernelStatsAt:         prevSnapshotAt.Add(-2 * time.Second),
		kernelStatsSnapshotAt: prevSnapshotAt,
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[id2] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.61 on "eno2"; tc: skipped`,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute")
	}
	if rt.snapshotCalls != 0 {
		t.Fatalf("SnapshotStats() calls = %d, want 0 when no owners recovered", rt.snapshotCalls)
	}
	if got := pm.kernelRuleStats[rule1.ID]; got.ActiveConns != 7 || got.TotalConns != 13 {
		t.Fatalf("retained kernel stats = %+v, want preserved counters", got)
	}
	if got := pm.kernelStatsSnapshot.ByRuleID[uint32(rule1.ID)]; got.TCPActiveConns != 7 {
		t.Fatalf("retained kernel snapshot = %+v, want preserved snapshot counts", got)
	}
	if !pm.kernelStatsSnapshotAt.Equal(prevSnapshotAt) {
		t.Fatalf("kernelStatsSnapshotAt = %v, want preserved %v", pm.kernelStatsSnapshotAt, prevSnapshotAt)
	}
}

func TestRetryNetlinkTriggeredKernelFallbackOwnersPreservesRetainedStatsOnRefreshFailure(t *testing.T) {
	db := openTestDB(t)

	rule1 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.70",
		InPort:       15001,
		OutInterface: "eno2",
		OutIP:        "198.51.100.70",
		OutPort:      25001,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id1, err := dbAddRule(db, &rule1)
	if err != nil {
		t.Fatalf("dbAddRule(rule1) error = %v", err)
	}
	rule1.ID = id1
	rule1.kernelLogKind = workerKindRule
	rule1.kernelLogOwnerID = id1

	rule2 := Rule{
		InInterface:  "eno1",
		InIP:         "192.0.2.71",
		InPort:       15002,
		OutInterface: "eno2",
		OutIP:        "198.51.100.71",
		OutPort:      25002,
		Protocol:     "tcp",
		Enabled:      true,
	}
	id2, err := dbAddRule(db, &rule2)
	if err != nil {
		t.Fatalf("dbAddRule(rule2) error = %v", err)
	}
	rule2.ID = id2

	rt := &stubIncrementalKernelRuntime{
		assignments: map[int64]string{
			rule1.ID: kernelEngineTC,
		},
		supportedRules: map[int64]bool{
			rule1.ID: true,
			rule2.ID: true,
		},
		retainedRules: map[int64][]Rule{
			rule1.ID: {rule1},
		},
		snapshotErr: errors.New("snapshot failed"),
	}

	pm := &ProcessManager{
		ruleWorkers:        make(map[int]*WorkerInfo),
		rangeWorkers:       make(map[int]*WorkerInfo),
		db:                 db,
		cfg:                &Config{DefaultEngine: ruleEngineKernel, MaxWorkers: 3},
		rulePlans:          map[int64]ruleDataplanePlan{},
		rangePlans:         map[int64]rangeDataplanePlan{},
		kernelRuntime:      rt,
		kernelRules:        map[int64]bool{rule1.ID: true},
		kernelRanges:       map[int64]bool{},
		kernelRuleEngines:  map[int64]string{rule1.ID: kernelEngineTC},
		kernelRangeEngines: map[int64]string{},
		kernelFlowOwners: map[uint32]kernelCandidateOwner{
			uint32(rule1.ID): {kind: workerKindRule, id: rule1.ID},
		},
		kernelRuleStats: map[int64]RuleStatsReport{
			rule1.ID: {
				RuleID:        rule1.ID,
				ActiveConns:   11,
				TotalConns:    22,
				NatTableSize:  3,
				RejectedConns: 1,
			},
		},
		kernelStatsSnapshot: kernelRuleStatsSnapshot{
			ByRuleID: map[uint32]kernelRuleStats{
				uint32(rule1.ID): {
					TCPActiveConns: 11,
					UDPNatEntries:  3,
					TotalConns:     22,
				},
			},
		},
		kernelStatsAt:         time.Now().Add(-3 * time.Second),
		kernelStatsSnapshotAt: time.Now(),
	}
	pm.rulePlans[rule1.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineKernel,
	}
	pm.rulePlans[rule2.ID] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 198.51.100.71 on "eno2"; tc: skipped`,
	}

	result := pm.retryNetlinkTriggeredKernelFallbackOwners()
	if !result.handled {
		t.Fatal("retryNetlinkTriggeredKernelFallbackOwners() unexpectedly requested full redistribute")
	}
	if result.recoveredRuleOwners != 1 {
		t.Fatalf("recovered rule owners = %d, want 1", result.recoveredRuleOwners)
	}
	if rt.snapshotCalls != 1 {
		t.Fatalf("SnapshotStats() calls = %d, want 1 when owners recovered", rt.snapshotCalls)
	}
	if got := pm.kernelRuleStats[rule1.ID]; got.ActiveConns != 11 || got.TotalConns != 22 || got.NatTableSize != 3 {
		t.Fatalf("retained kernel stats after refresh failure = %+v, want preserved counters", got)
	}
	if got := pm.kernelRuleStats[rule2.ID]; got.RuleID != rule2.ID {
		t.Fatalf("recovered kernel stats entry = %+v, want zero-initialized rule 2 placeholder", got)
	}
	if pm.kernelStatsLastError != "snapshot failed" {
		t.Fatalf("kernelStatsLastError = %q, want snapshot failure", pm.kernelStatsLastError)
	}
}
