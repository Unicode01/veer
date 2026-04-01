package app

import "testing"

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
