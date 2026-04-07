package app

import "testing"

type stubKernelHandoffRuntime struct {
	ruleRetain      map[int64][]Rule
	rangeRetain     map[int64][]Rule
	egressNATRetain map[int64][]Rule
}

func (s stubKernelHandoffRuntime) Available() (bool, string) {
	return true, "ready"
}

func (s stubKernelHandoffRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (s stubKernelHandoffRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (s stubKernelHandoffRuntime) Maintain() error {
	return nil
}

func (s stubKernelHandoffRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (s stubKernelHandoffRuntime) Close() error {
	return nil
}

func (s stubKernelHandoffRuntime) retainedKernelRuleCandidates(rule Rule) ([]Rule, bool) {
	items, ok := s.ruleRetain[rule.ID]
	return items, ok
}

func (s stubKernelHandoffRuntime) retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool) {
	items, ok := s.rangeRetain[pr.ID]
	return items, ok
}

func (s stubKernelHandoffRuntime) retainedKernelEgressNATCandidates(item EgressNAT) ([]Rule, bool) {
	items, ok := s.egressNATRetain[item.ID]
	return items, ok
}

func TestCollectKernelToUserspaceRuleIDs(t *testing.T) {
	rules := []Rule{
		{ID: 1, Enabled: true},
		{ID: 2, Enabled: true},
		{ID: 3, Enabled: false},
	}
	previous := map[int64]bool{1: true, 2: true, 3: true}
	plans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineUserspace},
		2: {EffectiveEngine: ruleEngineKernel},
		3: {EffectiveEngine: ruleEngineUserspace},
	}

	got := collectKernelToUserspaceRuleIDs(rules, previous, plans)
	if len(got) != 1 {
		t.Fatalf("collectKernelToUserspaceRuleIDs() len = %d, want 1", len(got))
	}
	if _, ok := got[1]; !ok {
		t.Fatal("collectKernelToUserspaceRuleIDs() missing rule 1")
	}
}

func TestCollectRuleWorkerIndexesForIDs(t *testing.T) {
	assignments := [][]Rule{
		{{ID: 10}, {ID: 11}},
		{{ID: 12}},
		{{ID: 13}, {ID: 14}},
	}
	ids := map[int64]struct{}{
		11: {},
		14: {},
	}

	got := collectRuleWorkerIndexesForIDs(assignments, ids)
	if len(got) != 2 || got[0] != 0 || got[1] != 2 {
		t.Fatalf("collectRuleWorkerIndexesForIDs() = %#v, want []int{0, 2}", got)
	}
}

func TestPreserveKernelOwnersOnWarmupTimeout(t *testing.T) {
	runtime := stubKernelHandoffRuntime{
		ruleRetain: map[int64][]Rule{
			1: {{ID: 1001, kernelLogKind: workerKindRule, kernelLogOwnerID: 1}},
		},
		rangeRetain: map[int64][]Rule{
			10: {{ID: 2001, kernelLogKind: workerKindRange, kernelLogOwnerID: 10}},
		},
	}
	rules := []Rule{
		{ID: 1, Enabled: true},
		{ID: 2, Enabled: true},
	}
	ranges := []PortRange{
		{ID: 10, Enabled: true},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineUserspace, FallbackReason: "warmup pending"},
		2: {EffectiveEngine: ruleEngineUserspace, FallbackReason: "warmup pending"},
	}
	rangePlans := map[int64]rangeDataplanePlan{
		10: {EffectiveEngine: ruleEngineUserspace, FallbackReason: "warmup pending"},
	}

	candidates, preservedRules, preservedRanges, remainingRules, remainingRanges := preserveKernelOwnersOnWarmupTimeout(
		runtime,
		rules,
		ranges,
		nil,
		map[int64]struct{}{1: {}, 2: {}},
		map[int64]struct{}{10: {}},
		rulePlans,
		rangePlans,
	)

	if preservedRules != 1 || preservedRanges != 1 {
		t.Fatalf("preserved counts = rules:%d ranges:%d, want 1/1", preservedRules, preservedRanges)
	}
	if remainingRules != 1 || remainingRanges != 0 {
		t.Fatalf("remaining counts = rules:%d ranges:%d, want 1/0", remainingRules, remainingRanges)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2 retained candidates", len(candidates))
	}
	if got := rulePlans[1]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("rule 1 plan = %+v, want kernel with cleared fallback", got)
	}
	if got := rulePlans[2]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 2 plan = %+v, want userspace retained", got)
	}
	if got := rangePlans[10]; got.EffectiveEngine != ruleEngineKernel || got.FallbackReason != "" {
		t.Fatalf("range 10 plan = %+v, want kernel with cleared fallback", got)
	}
}

func TestPreserveKernelOwnersOnWarmupTimeoutSkipsConflictingCandidateIDs(t *testing.T) {
	runtime := stubKernelHandoffRuntime{
		ruleRetain: map[int64][]Rule{
			1: {{ID: 1001, kernelLogKind: workerKindRule, kernelLogOwnerID: 1}},
		},
	}
	rules := []Rule{{ID: 1, Enabled: true}}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineUserspace, FallbackReason: "warmup pending"},
	}

	candidates, preservedRules, preservedRanges, remainingRules, remainingRanges := preserveKernelOwnersOnWarmupTimeout(
		runtime,
		rules,
		nil,
		[]kernelCandidateRule{{owner: kernelCandidateOwner{kind: workerKindRule, id: 99}, rule: Rule{ID: 1001}}},
		map[int64]struct{}{1: {}},
		nil,
		rulePlans,
		nil,
	)

	if preservedRules != 0 || preservedRanges != 0 {
		t.Fatalf("preserved counts = rules:%d ranges:%d, want 0/0", preservedRules, preservedRanges)
	}
	if remainingRules != 1 || remainingRanges != 0 {
		t.Fatalf("remaining counts = rules:%d ranges:%d, want 1/0", remainingRules, remainingRanges)
	}
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want original candidate only", len(candidates))
	}
	if got := rulePlans[1]; got.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("rule 1 plan = %+v, want userspace retained", got)
	}
}
