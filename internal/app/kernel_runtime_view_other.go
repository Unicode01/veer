//go:build !linux

package app

import (
	"strings"
	"time"
)

func snapshotKernelRuntimeEngines(rt kernelRuleRuntime) []KernelEngineRuntimeView {
	return nil
}

func kernelRuntimeIdleDegradedRebuildReason(view KernelEngineRuntimeView) string {
	return ""
}

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
		resp.TCDiagnosticsVerbose = pm.cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTCDiagVerbose)
		resp.TCDiagnostics = pm.cfg.ExperimentalFeatureEnabled(experimentalFeatureKernelTCDiag) || resp.TCDiagnosticsVerbose
		resp.KernelRulesMapConfiguredLimit = pm.cfg.KernelRulesMapLimit
		resp.KernelFlowsMapConfiguredLimit = pm.cfg.KernelFlowsMapLimit
		resp.KernelNATMapConfiguredLimit = pm.cfg.KernelNATMapLimit
		resp.KernelRulesMapCapacityMode = kernelRulesMapCapacityMode(pm.cfg.KernelRulesMapLimit)
		resp.KernelFlowsMapCapacityMode = kernelFlowsMapCapacityMode(pm.cfg.KernelFlowsMapLimit)
		resp.KernelNATMapCapacityMode = kernelNATMapCapacityMode(pm.cfg.KernelNATMapLimit)
	}
	profile := currentKernelAdaptiveMapProfile()
	resp.KernelMapProfile = kernelAdaptiveMapProfileName(profile)
	resp.KernelMapTotalMemoryBytes = profile.totalMemoryBytes
	resp.KernelRulesMapBaseLimit = kernelRulesMapBaseLimit
	resp.KernelFlowsMapBaseLimit = profile.flowsBaseLimit
	resp.KernelNATMapBaseLimit = profile.natBaseLimit
	resp.KernelEgressNATAutoFloor = profile.egressNATAutoFloor
	if resp.KernelRulesMapCapacityMode == "" {
		resp.KernelRulesMapCapacityMode = kernelRulesMapCapacityMode(0)
	}
	if resp.KernelFlowsMapCapacityMode == "" {
		resp.KernelFlowsMapCapacityMode = kernelFlowsMapCapacityMode(0)
	}
	if resp.KernelNATMapCapacityMode == "" {
		resp.KernelNATMapCapacityMode = kernelNATMapCapacityMode(0)
	}
	now := time.Now()
	pm.mu.Lock()
	resp.ActiveRuleCount = len(pm.kernelRules)
	resp.ActiveRangeCount = len(pm.kernelRanges)
	resp.KernelFallbackRuleCount, resp.TransientFallbackRuleCount = countRulePlanFallbacks(pm.rulePlans)
	resp.KernelFallbackRangeCount, resp.TransientFallbackRangeCount = countRangePlanFallbacks(pm.rangePlans)
	resp.TransientFallbackSummary = summarizeTransientKernelFallbacks(pm.rulePlans, pm.rangePlans)
	resp.RetryPending = strings.TrimSpace(resp.TransientFallbackSummary) != ""
	resp.KernelRetryCount = pm.kernelRetryCount
	resp.LastKernelRetryAt = pm.lastKernelRetryAt
	resp.LastKernelRetryReason = pm.lastKernelRetryReason
	resp.KernelIncrementalRetryCount = pm.kernelIncrementalRetryCount
	resp.KernelIncrementalRetryFallbackCount = pm.kernelIncrementalRetryFallbackCount
	resp.CooldownRuleOwnerCount, resp.CooldownRangeOwnerCount = countActiveKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, now)
	resp.CooldownSummary = summarizeActiveKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, now)
	resp.CooldownNextExpiryAt, resp.CooldownClearAt = activeKernelNetlinkOwnerRetryCooldownWindow(pm.kernelNetlinkOwnerRetryCooldownUntil, now)
	resp.LastKernelIncrementalRetryAt = pm.lastKernelIncrementalRetryAt
	resp.LastKernelIncrementalRetryResult = pm.lastKernelIncrementalRetryResult
	resp.LastKernelIncrementalRetryMatchedRuleOwners = pm.lastKernelIncrementalRetryMatchedRuleOwners
	resp.LastKernelIncrementalRetryMatchedRangeOwners = pm.lastKernelIncrementalRetryMatchedRangeOwners
	resp.LastKernelIncrementalRetryAttemptedRuleOwners = pm.lastKernelIncrementalRetryAttemptedRuleOwners
	resp.LastKernelIncrementalRetryAttemptedRangeOwners = pm.lastKernelIncrementalRetryAttemptedRangeOwners
	resp.LastKernelIncrementalRetryRetainedRuleOwners = pm.lastKernelIncrementalRetryRetainedRuleOwners
	resp.LastKernelIncrementalRetryRetainedRangeOwners = pm.lastKernelIncrementalRetryRetainedRangeOwners
	resp.LastKernelIncrementalRetryRecoveredRuleOwners = pm.lastKernelIncrementalRetryRecoveredRuleOwners
	resp.LastKernelIncrementalRetryRecoveredRangeOwners = pm.lastKernelIncrementalRetryRecoveredRangeOwners
	resp.LastKernelIncrementalRetryCooldownRuleOwners = pm.lastKernelIncrementalRetryCooldownRuleOwners
	resp.LastKernelIncrementalRetryCooldownRangeOwners = pm.lastKernelIncrementalRetryCooldownRangeOwners
	resp.LastKernelIncrementalRetryCooldownSummary = pm.lastKernelIncrementalRetryCooldownSummary
	resp.LastKernelIncrementalRetryCooldownScope = pm.lastKernelIncrementalRetryCooldownScope
	resp.LastKernelIncrementalRetryBackoffRuleOwners = pm.lastKernelIncrementalRetryBackoffRuleOwners
	resp.LastKernelIncrementalRetryBackoffRangeOwners = pm.lastKernelIncrementalRetryBackoffRangeOwners
	resp.LastKernelIncrementalRetryBackoffSummary = pm.lastKernelIncrementalRetryBackoffSummary
	resp.LastKernelIncrementalRetryBackoffScope = pm.lastKernelIncrementalRetryBackoffScope
	resp.LastKernelIncrementalRetryBackoffMaxFailures = pm.lastKernelIncrementalRetryBackoffMaxFailures
	resp.LastKernelIncrementalRetryBackoffMaxDelayMs = pm.lastKernelIncrementalRetryBackoffMaxDelay.Milliseconds()
	resp.KernelNetlinkRecoverPending = pm.kernelNetlinkRecoverPending
	resp.KernelNetlinkRecoverSource = pm.kernelNetlinkRecoverSource
	resp.KernelNetlinkRecoverSummary = pm.kernelNetlinkRecoverSummary
	resp.KernelNetlinkRecoverRequestedAt = pm.kernelNetlinkRecoverRequestedAt
	resp.KernelNetlinkRecoverTriggerSummary = summarizeKernelNetlinkRecoveryTrigger(pm.kernelNetlinkRecoverTrigger)
	resp.LastKernelAttachmentIssue = pm.lastKernelAttachmentIssue
	resp.LastKernelAttachmentHealAt = pm.kernelAttachmentHealAt
	resp.LastKernelAttachmentHealSummary = pm.lastKernelAttachmentHealSummary
	resp.LastKernelAttachmentHealError = pm.lastKernelAttachmentHealError
	resp.LastStatsSnapshotAt = pm.kernelStatsSnapshotAt
	resp.LastStatsSnapshotMs = pm.kernelStatsLastDuration.Milliseconds()
	resp.LastStatsSnapshotError = pm.kernelStatsLastError
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
