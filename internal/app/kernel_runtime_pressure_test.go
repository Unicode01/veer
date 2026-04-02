package app

import "testing"

type stubPressureRuntime struct {
	pressure kernelRuntimePressureSnapshot
}

func (s stubPressureRuntime) Available() (bool, string) {
	return true, "ready"
}

func (s stubPressureRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (s stubPressureRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (s stubPressureRuntime) Maintain() error {
	return nil
}

func (s stubPressureRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (s stubPressureRuntime) Close() error {
	return nil
}

func (s stubPressureRuntime) pressureSnapshot() kernelRuntimePressureSnapshot {
	return s.pressure
}

func TestKernelRuntimeNeedsRedistributeRequiresAssignedEntries(t *testing.T) {
	rt := stubPressureRuntime{
		pressure: kernelRuntimePressureSnapshot{
			Level:           kernelRuntimePressureLevelShed,
			Active:          true,
			Reason:          "kernel dataplane pressure",
			AssignedEntries: 4,
		},
	}
	need, reason := kernelRuntimeNeedsRedistribute(rt)
	if !need {
		t.Fatal("kernelRuntimeNeedsRedistribute() = false, want true")
	}
	if reason == "" {
		t.Fatal("kernelRuntimeNeedsRedistribute() reason = empty, want non-empty")
	}

	rt.pressure.Level = kernelRuntimePressureLevelHold
	need, _ = kernelRuntimeNeedsRedistribute(rt)
	if need {
		t.Fatal("kernelRuntimeNeedsRedistribute() = true for hold pressure, want false")
	}

	rt.pressure.Level = kernelRuntimePressureLevelShed
	rt.pressure.AssignedEntries = 0
	need, _ = kernelRuntimeNeedsRedistribute(rt)
	if need {
		t.Fatal("kernelRuntimeNeedsRedistribute() = true without assigned entries, want false")
	}

	rt.pressure.Active = false
	rt.pressure.Level = kernelRuntimePressureLevelNone
	rt.pressure.AssignedEntries = 2
	need, _ = kernelRuntimeNeedsRedistribute(rt)
	if need {
		t.Fatal("kernelRuntimeNeedsRedistribute() = true without active pressure, want false")
	}
}

func TestKernelRuntimePressureCleared(t *testing.T) {
	previous := kernelRuntimePressureSnapshot{
		Level:  kernelRuntimePressureLevelHold,
		Active: true,
		Reason: "kernel dataplane pressure",
		Engine: kernelEngineTC,
	}
	current := kernelRuntimePressureSnapshot{}
	if !kernelRuntimePressureCleared(previous, current) {
		t.Fatal("kernelRuntimePressureCleared() = false, want true for active -> inactive transition")
	}

	if kernelRuntimePressureCleared(kernelRuntimePressureSnapshot{}, current) {
		t.Fatal("kernelRuntimePressureCleared() = true, want false when previous snapshot was inactive")
	}

	if kernelRuntimePressureCleared(previous, kernelRuntimePressureSnapshot{Level: kernelRuntimePressureLevelHold, Active: true}) {
		t.Fatal("kernelRuntimePressureCleared() = true, want false when pressure remains active")
	}
}
