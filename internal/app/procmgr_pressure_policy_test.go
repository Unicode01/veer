package app

import "testing"

func TestApplyKernelPressurePolicyHoldPreservesPreviousOwners(t *testing.T) {
	candidates := []kernelCandidateRule{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 101}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 2}, rule: Rule{ID: 102}},
		{owner: kernelCandidateOwner{kind: workerKindRange, id: 3}, rule: Rule{ID: 103}},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineKernel},
		2: {EffectiveEngine: ruleEngineKernel},
	}
	rangePlans := map[int64]rangeDataplanePlan{
		3: {EffectiveEngine: ruleEngineKernel},
	}

	applyKernelPressurePolicy(
		kernelRuntimePressureSnapshot{
			Level:  kernelRuntimePressureLevelHold,
			Active: true,
			Reason: "kernel dataplane pressure: hold",
		},
		candidates,
		map[int64]bool{1: true},
		nil,
		rulePlans,
		rangePlans,
	)

	if rulePlans[1].EffectiveEngine != ruleEngineKernel {
		t.Fatal("hold pressure moved previous rule owner out of kernel, want preserved")
	}
	if rulePlans[2].EffectiveEngine != ruleEngineUserspace {
		t.Fatal("hold pressure kept new rule owner in kernel, want userspace fallback")
	}
	if rangePlans[3].EffectiveEngine != ruleEngineUserspace {
		t.Fatal("hold pressure kept new range owner in kernel, want userspace fallback")
	}
}

func TestApplyKernelPressurePolicyShedFallsBackStableSubset(t *testing.T) {
	candidates := []kernelCandidateRule{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 101}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 105}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 106}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 107}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 108}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 109}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 2}, rule: Rule{ID: 102}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 3}, rule: Rule{ID: 103}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 4}, rule: Rule{ID: 104}},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineKernel},
		2: {EffectiveEngine: ruleEngineKernel},
		3: {EffectiveEngine: ruleEngineKernel},
		4: {EffectiveEngine: ruleEngineKernel},
	}

	applyKernelPressurePolicy(
		kernelRuntimePressureSnapshot{
			Level:  kernelRuntimePressureLevelShed,
			Active: true,
			Reason: "kernel dataplane pressure: shed",
		},
		candidates,
		map[int64]bool{1: true, 2: true, 3: true, 4: true},
		nil,
		rulePlans,
		nil,
	)

	if rulePlans[1].EffectiveEngine != ruleEngineKernel {
		t.Fatal("shed pressure moved heavy rule owner out of kernel, want preserved")
	}
	if rulePlans[2].EffectiveEngine != ruleEngineKernel {
		t.Fatal("shed pressure moved rule 2 out of kernel before target fallback entries were met, want preserved")
	}
	for _, id := range []int64{3, 4} {
		if rulePlans[id].EffectiveEngine != ruleEngineUserspace {
			t.Fatalf("shed pressure kept rule %d in kernel, want userspace fallback to meet target entry budget", id)
		}
	}
}

func TestApplyKernelPressurePolicyShedDropsNewOwnersBeforePreviousOnes(t *testing.T) {
	candidates := []kernelCandidateRule{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 101}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 102}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 2}, rule: Rule{ID: 103}},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineKernel},
		2: {EffectiveEngine: ruleEngineKernel},
	}

	applyKernelPressurePolicy(
		kernelRuntimePressureSnapshot{
			Level:  kernelRuntimePressureLevelShed,
			Active: true,
			Reason: "kernel dataplane pressure: shed",
		},
		candidates,
		map[int64]bool{1: true},
		nil,
		rulePlans,
		nil,
	)

	if rulePlans[1].EffectiveEngine != ruleEngineKernel {
		t.Fatal("shed pressure moved previous owner out of kernel before exhausting new-owner fallback")
	}
	if rulePlans[2].EffectiveEngine != ruleEngineUserspace {
		t.Fatal("shed pressure kept new owner in kernel, want userspace fallback first")
	}
}

func TestKernelPressureShedTargetEntries(t *testing.T) {
	got := kernelPressureShedTargetEntries([]kernelPressureOwnerInfo{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, entries: 5},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 2}, entries: 1},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 3}, entries: 1},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 4}, entries: 1},
	})
	if got != 2 {
		t.Fatalf("kernelPressureShedTargetEntries() = %d, want 2", got)
	}
}

func TestCollectKernelPressureOwnersAggregatesEntries(t *testing.T) {
	candidates := []kernelCandidateRule{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 101}},
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 102}},
		{owner: kernelCandidateOwner{kind: workerKindRange, id: 2}, rule: Rule{ID: 201}},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineKernel},
	}
	rangePlans := map[int64]rangeDataplanePlan{
		2: {EffectiveEngine: ruleEngineKernel},
	}

	owners := collectKernelPressureOwners(candidates, map[int64]bool{1: true}, map[int64]bool{2: true}, rulePlans, rangePlans)
	if len(owners) != 2 {
		t.Fatalf("collectKernelPressureOwners() len = %d, want 2", len(owners))
	}
	if owners[0].owner.kind != workerKindRange || owners[0].entries != 1 {
		t.Fatalf("collectKernelPressureOwners() first owner = %+v, want range entries=1", owners[0])
	}
	if owners[1].owner.kind != workerKindRule || owners[1].entries != 2 {
		t.Fatalf("collectKernelPressureOwners() second owner = %+v, want rule entries=2", owners[1])
	}
}

func TestApplyKernelPressurePolicyFullFallsBackAllOwners(t *testing.T) {
	candidates := []kernelCandidateRule{
		{owner: kernelCandidateOwner{kind: workerKindRule, id: 1}, rule: Rule{ID: 101}},
		{owner: kernelCandidateOwner{kind: workerKindRange, id: 2}, rule: Rule{ID: 102}},
	}
	rulePlans := map[int64]ruleDataplanePlan{
		1: {EffectiveEngine: ruleEngineKernel},
	}
	rangePlans := map[int64]rangeDataplanePlan{
		2: {EffectiveEngine: ruleEngineKernel},
	}

	applyKernelPressurePolicy(
		kernelRuntimePressureSnapshot{
			Level:  kernelRuntimePressureLevelFull,
			Active: true,
			Reason: "kernel dataplane pressure: full",
		},
		candidates,
		map[int64]bool{1: true},
		map[int64]bool{2: true},
		rulePlans,
		rangePlans,
	)

	if rulePlans[1].EffectiveEngine != ruleEngineUserspace {
		t.Fatal("full pressure kept rule owner in kernel, want userspace fallback")
	}
	if rangePlans[2].EffectiveEngine != ruleEngineUserspace {
		t.Fatal("full pressure kept range owner in kernel, want userspace fallback")
	}
}
