package app

import "testing"

type stubKernelSupportRuntime struct {
	available     bool
	availableText string
	supported     bool
	supportText   string
}

func (rt stubKernelSupportRuntime) Available() (bool, string) {
	return rt.available, rt.availableText
}

func (rt stubKernelSupportRuntime) SupportsRule(rule Rule) (bool, string) {
	return rt.supported, rt.supportText
}

func (rt stubKernelSupportRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return map[int64]kernelRuleApplyResult{}, nil
}

func (rt stubKernelSupportRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt stubKernelSupportRuntime) Maintain() error {
	return nil
}

func (rt stubKernelSupportRuntime) SnapshotAssignments() map[int64]string {
	return map[int64]string{}
}

func (rt stubKernelSupportRuntime) Close() error {
	return nil
}

func TestRuleDataplanePlannerUsesKernelRuntimeSupporter(t *testing.T) {
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{
		available: true,
		supported: true,
	}, ruleEngineKernel)

	plan := planner.Plan(Rule{
		ID:               1,
		InInterface:      "missing-in",
		InIP:             "192.0.2.10",
		InPort:           8080,
		OutInterface:     "missing-out",
		OutIP:            "192.0.2.20",
		OutPort:          80,
		Protocol:         "tcp",
		EnginePreference: ruleEngineKernel,
	})

	if !plan.KernelEligible {
		t.Fatalf("KernelEligible = false, want true")
	}
	if plan.KernelReason != "" {
		t.Fatalf("KernelReason = %q, want empty", plan.KernelReason)
	}
	if plan.EffectiveEngine != ruleEngineKernel {
		t.Fatalf("EffectiveEngine = %q, want %q", plan.EffectiveEngine, ruleEngineKernel)
	}
	if plan.FallbackReason != "" {
		t.Fatalf("FallbackReason = %q, want empty", plan.FallbackReason)
	}
}

func TestRuleDataplanePlannerPrefersKernelRuntimeSupportReason(t *testing.T) {
	wantReason := `xdp: needs learned neighbor; tc: skipped`
	planner := newRuleDataplanePlanner(stubKernelSupportRuntime{
		available:   true,
		supported:   false,
		supportText: wantReason,
	}, ruleEngineKernel)

	plan := planner.Plan(Rule{
		ID:               1,
		InInterface:      "eno1",
		InIP:             "192.0.2.10",
		InPort:           8080,
		OutInterface:     "eno2",
		OutIP:            "192.0.2.20",
		OutPort:          80,
		Protocol:         "tcp",
		EnginePreference: ruleEngineKernel,
	})

	if plan.KernelEligible {
		t.Fatal("KernelEligible = true, want false")
	}
	if plan.KernelReason != wantReason {
		t.Fatalf("KernelReason = %q, want %q", plan.KernelReason, wantReason)
	}
	if plan.EffectiveEngine != ruleEngineUserspace {
		t.Fatalf("EffectiveEngine = %q, want %q", plan.EffectiveEngine, ruleEngineUserspace)
	}
	if plan.FallbackReason != wantReason {
		t.Fatalf("FallbackReason = %q, want %q", plan.FallbackReason, wantReason)
	}
}
