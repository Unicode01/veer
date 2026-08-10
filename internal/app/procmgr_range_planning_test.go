package app

import "testing"

type countingKernelSupportRuntime struct {
	supportCalls int
}

func (rt *countingKernelSupportRuntime) Available() (bool, string) {
	return true, "counting kernel runtime"
}

func (rt *countingKernelSupportRuntime) SupportsRule(rule Rule) (bool, string) {
	rt.supportCalls++
	return true, ""
}

func (rt *countingKernelSupportRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return nil, nil
}

func (rt *countingKernelSupportRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (rt *countingKernelSupportRuntime) Maintain() error {
	return nil
}

func (rt *countingKernelSupportRuntime) SnapshotAssignments() map[int64]string {
	return nil
}

func (rt *countingKernelSupportRuntime) Close() error {
	return nil
}

func TestBuildKernelCandidateRulesSamplesRangeEligibilityPerProtocol(t *testing.T) {
	rt := &countingKernelSupportRuntime{}
	planner := newRuleDataplanePlanner(rt, ruleEngineKernel)
	pr := benchmarkPortRange(1, 10000, 32, "tcp+udp")

	candidates, _, rangePlans := buildKernelCandidateRules(nil, []PortRange{pr}, planner, 65536)

	if got, want := rt.supportCalls, 2; got != want {
		t.Fatalf("SupportsRule() calls = %d, want %d", got, want)
	}
	if got, want := len(candidates), 64; got != want {
		t.Fatalf("candidate count = %d, want %d", got, want)
	}
	plan, ok := rangePlans[pr.ID]
	if !ok {
		t.Fatalf("range plan missing for range %d", pr.ID)
	}
	if plan.EffectiveEngine != ruleEngineKernel {
		t.Fatalf("range plan effective engine = %q, want %q", plan.EffectiveEngine, ruleEngineKernel)
	}
}

func TestBuildKernelCandidateRulesReservesRetainedEntriesBeforePlanning(t *testing.T) {
	rt := &countingKernelSupportRuntime{}
	planner := newRuleDataplanePlanner(rt, ruleEngineKernel)
	rule := Rule{
		ID:               1,
		InInterface:      "eno1",
		InIP:             "192.0.2.10",
		InPort:           10022,
		OutInterface:     "vmbr1",
		OutIP:            "198.51.100.10",
		OutPort:          22,
		Protocol:         "tcp",
		Enabled:          true,
		EnginePreference: ruleEngineKernel,
	}

	candidates, rulePlans, _ := buildKernelCandidateRulesWithReservedEntries(
		[]Rule{rule},
		nil,
		planner,
		1,
		1,
	)

	if len(candidates) != 0 {
		t.Fatalf("candidate count = %d, want 0 after the retained entry consumes fixed capacity", len(candidates))
	}
	plan := rulePlans[rule.ID]
	if plan.EffectiveEngine != ruleEngineUserspace || plan.FallbackReason == "" {
		t.Fatalf("rule plan = %+v, want capacity fallback after reserving the retained entry", plan)
	}
}
