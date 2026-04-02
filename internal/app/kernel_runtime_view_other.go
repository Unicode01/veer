//go:build !linux

package app

import "strings"

func (pm *ProcessManager) snapshotKernelRuntime() KernelRuntimeResponse {
	resp := KernelRuntimeResponse{
		Available:       false,
		AvailableReason: "kernel dataplane requires Linux",
		DefaultEngine:   ruleEngineAuto,
		ConfiguredOrder: defaultKernelEngineOrder(),
		Engines:         []KernelEngineRuntimeView{},
	}
	if pm == nil {
		return resp
	}
	if pm.cfg != nil {
		resp.DefaultEngine = pm.cfg.DefaultEngine
		resp.ConfiguredOrder = normalizeKernelEngineOrder(pm.cfg.KernelEngineOrder)
		resp.TrafficStats = pm.cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTraffic)
	}
	pm.mu.Lock()
	resp.ActiveRuleCount = len(pm.kernelRules)
	resp.ActiveRangeCount = len(pm.kernelRanges)
	resp.KernelFallbackRuleCount, resp.TransientFallbackRuleCount = countRulePlanFallbacks(pm.rulePlans)
	resp.KernelFallbackRangeCount, resp.TransientFallbackRangeCount = countRangePlanFallbacks(pm.rangePlans)
	resp.TransientFallbackSummary = summarizeTransientKernelFallbacks(pm.rulePlans, pm.rangePlans)
	resp.RetryPending = strings.TrimSpace(resp.TransientFallbackSummary) != ""
	pm.mu.Unlock()
	return resp
}

func countRulePlanFallbacks(plans map[int64]ruleDataplanePlan) (int, int) {
	total := 0
	transient := 0
	for _, plan := range plans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		total++
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			transient++
		}
	}
	return total, transient
}

func countRangePlanFallbacks(plans map[int64]rangeDataplanePlan) (int, int) {
	total := 0
	transient := 0
	for _, plan := range plans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		total++
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			transient++
		}
	}
	return total, transient
}

func summarizeTransientKernelFallbacks(rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) string {
	ruleCount := 0
	rangeCount := 0
	for _, plan := range rulePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			ruleCount++
		}
	}
	for _, plan := range rangePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if isTransientKernelFallbackReason(plan.FallbackReason) {
			rangeCount++
		}
	}
	if ruleCount == 0 && rangeCount == 0 {
		return ""
	}
	return "transient kernel fallbacks present"
}
