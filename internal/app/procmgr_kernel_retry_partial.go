package app

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type kernelIncrementalRetryResult struct {
	attempted            bool
	handled              bool
	detail               string
	matchedRuleOwners    int
	matchedRangeOwners   int
	matchedEgressNATs    int
	attemptedRuleOwners  int
	attemptedRangeOwners int
	attemptedEgressNATs  int
	retainedRuleOwners   int
	retainedRangeOwners  int
	retainedEgressNATs   int
	recoveredRuleOwners  int
	recoveredRangeOwners int
	recoveredEgressNATs  int
	cooldownRuleOwners   int
	cooldownRangeOwners  int
	cooldownEgressNATs   int
	cooldownSummary      string
	cooldownScope        string
	backoffRuleOwners    int
	backoffRangeOwners   int
	backoffEgressNATs    int
	backoffSummary       string
	backoffScope         string
	backoffMaxFailures   int
	backoffMaxDuration   time.Duration
}

type kernelNetlinkOwnerRetryCooldownState struct {
	Until  time.Time
	Source string
}

func retainKernelRuleStatsReports(prev map[int64]RuleStatsReport, active map[int64]bool) map[int64]RuleStatsReport {
	stats := make(map[int64]RuleStatsReport, len(active))
	for id := range active {
		if item, ok := prev[id]; ok {
			item.RuleID = id
			stats[id] = item
			continue
		}
		stats[id] = RuleStatsReport{RuleID: id}
	}
	return stats
}

func retainKernelRangeStatsReports(prev map[int64]RangeStatsReport, active map[int64]bool) map[int64]RangeStatsReport {
	stats := make(map[int64]RangeStatsReport, len(active))
	for id := range active {
		if item, ok := prev[id]; ok {
			item.RangeID = id
			stats[id] = item
			continue
		}
		stats[id] = RangeStatsReport{RangeID: id}
	}
	return stats
}

func retainKernelEgressNATStatsReports(prev map[int64]EgressNATStatsReport, active map[int64]bool) map[int64]EgressNATStatsReport {
	stats := make(map[int64]EgressNATStatsReport, len(active))
	for id := range active {
		if item, ok := prev[id]; ok {
			item.EgressNATID = id
			stats[id] = item
			continue
		}
		stats[id] = EgressNATStatsReport{EgressNATID: id}
	}
	return stats
}

func retainKernelStatsSnapshot(prev kernelRuleStatsSnapshot, previousOwners map[uint32]kernelCandidateOwner, nextOwners map[uint32]kernelCandidateOwner) kernelRuleStatsSnapshot {
	snapshot := emptyKernelRuleStatsSnapshot()
	if len(prev.ByRuleID) == 0 || len(previousOwners) == 0 || len(nextOwners) == 0 {
		return snapshot
	}
	for ruleID, counts := range prev.ByRuleID {
		prevOwner, ok := previousOwners[ruleID]
		if !ok {
			continue
		}
		nextOwner, ok := nextOwners[ruleID]
		if !ok || nextOwner != prevOwner {
			continue
		}
		snapshot.ByRuleID[ruleID] = counts
	}
	return snapshot
}

func (pm *ProcessManager) snapshotUserspaceAssignments() ([][]Rule, [][]PortRange) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	ruleAssignments := make([][]Rule, maxWorkerIndex(pm.ruleWorkers)+1)
	for idx, wi := range pm.ruleWorkers {
		if wi == nil || idx < 0 {
			continue
		}
		ruleAssignments[idx] = append([]Rule(nil), wi.rules...)
	}

	rangeAssignments := make([][]PortRange, maxWorkerIndex(pm.rangeWorkers)+1)
	for idx, wi := range pm.rangeWorkers {
		if wi == nil || idx < 0 {
			continue
		}
		rangeAssignments[idx] = append([]PortRange(nil), wi.ranges...)
	}

	return ruleAssignments, rangeAssignments
}

func maxWorkerIndex[T any](workers map[int]T) int {
	max := -1
	for idx := range workers {
		if idx > max {
			max = idx
		}
	}
	return max
}

func kernelIncrementalRetryCooldownDetailSuffix(ruleOwners int, rangeOwners int, egressNATs int) string {
	if ruleOwners == 0 && rangeOwners == 0 && egressNATs == 0 {
		return ""
	}
	return fmt.Sprintf(
		" cooldown_rule_owners=%d cooldown_range_owners=%d cooldown_egress_nat_owners=%d",
		ruleOwners,
		rangeOwners,
		egressNATs,
	)
}

func kernelIncrementalRetryCooldownSummaryDetailSuffix(summary string) string {
	summary = strings.TrimSpace(summary)
	if summary == "" {
		return ""
	}
	return " cooldown_reasons=" + summary
}

func kernelIncrementalRetryBackoffDetailSuffix(ruleOwners int, rangeOwners int, egressNATs int, summary string, maxFailures int, maxDuration time.Duration) string {
	if ruleOwners == 0 && rangeOwners == 0 && egressNATs == 0 && strings.TrimSpace(summary) == "" && maxFailures == 0 && maxDuration <= 0 {
		return ""
	}
	suffix := fmt.Sprintf(
		" backoff_rule_owners=%d backoff_range_owners=%d backoff_egress_nat_owners=%d",
		ruleOwners,
		rangeOwners,
		egressNATs,
	)
	if summary = strings.TrimSpace(summary); summary != "" {
		suffix += " backoff_reasons=" + summary
	}
	if maxFailures > 0 {
		suffix += fmt.Sprintf(" backoff_max_failures=%d", maxFailures)
	}
	if maxDuration > 0 {
		suffix += " backoff_max_delay=" + maxDuration.String()
	}
	return suffix
}

func summarizeKernelIncrementalRetryOwnerIDs(label string, ids map[int64]struct{}) string {
	if len(ids) == 0 {
		return ""
	}
	values := make([]int64, 0, len(ids))
	for id := range ids {
		if id <= 0 {
			continue
		}
		values = append(values, id)
	}
	if len(values) == 0 {
		return ""
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	parts := make([]string, 0, 4)
	limit := len(values)
	if limit > 3 {
		limit = 3
	}
	for _, id := range values[:limit] {
		parts = append(parts, fmt.Sprintf("%d", id))
	}
	if len(values) > limit {
		parts = append(parts, fmt.Sprintf("+%d", len(values)-limit))
	}
	return fmt.Sprintf("%s=%s", label, strings.Join(parts, ","))
}

func summarizeKernelIncrementalRetryOwnerScope(owners []kernelCandidateOwner) string {
	if len(owners) == 0 {
		return ""
	}
	ruleIDs := make(map[int64]struct{})
	rangeIDs := make(map[int64]struct{})
	egressNATIDs := make(map[int64]struct{})
	for _, owner := range owners {
		if owner.id <= 0 {
			continue
		}
		switch owner.kind {
		case workerKindRule:
			ruleIDs[owner.id] = struct{}{}
		case workerKindRange:
			rangeIDs[owner.id] = struct{}{}
		case workerKindEgressNAT:
			egressNATIDs[owner.id] = struct{}{}
		}
	}
	parts := make([]string, 0, 3)
	if item := summarizeKernelIncrementalRetryOwnerIDs("rule_ids", ruleIDs); item != "" {
		parts = append(parts, item)
	}
	if item := summarizeKernelIncrementalRetryOwnerIDs("range_ids", rangeIDs); item != "" {
		parts = append(parts, item)
	}
	if item := summarizeKernelIncrementalRetryOwnerIDs("egress_nat_ids", egressNATIDs); item != "" {
		parts = append(parts, item)
	}
	return strings.Join(parts, "; ")
}

func (pm *ProcessManager) retryNetlinkTriggeredKernelFallbackOwners() kernelIncrementalRetryResult {
	return pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(kernelNetlinkRecoveryTrigger{})
}

func (pm *ProcessManager) retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger kernelNetlinkRecoveryTrigger) kernelIncrementalRetryResult {
	if pm == nil || pm.kernelRuntime == nil || pm.db == nil {
		return kernelIncrementalRetryResult{handled: true}
	}

	pm.redistributeMu.Lock()
	defer pm.redistributeMu.Unlock()

	now := time.Now()
	currentKernelRules := make(map[int64]bool)
	currentKernelRanges := make(map[int64]bool)
	currentKernelEgressNATs := make(map[int64]bool)
	matchedRuleOwners := make(map[int64]struct{})
	matchedRangeOwners := make(map[int64]struct{})
	matchedEgressNATOwners := make(map[int64]struct{})
	cooldownEgressNATOwners := make(map[int64]struct{})
	retryOwners := make(map[kernelCandidateOwner]struct{})
	unmatchedRuleFallbackPlans := make(map[int64]ruleDataplanePlan)
	unmatchedRangeFallbackPlans := make(map[int64]rangeDataplanePlan)
	unmatchedEgressNATFallbackPlans := make(map[int64]ruleDataplanePlan)
	cooldownUntil := map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState{}
	failureCounts := map[kernelCandidateOwner]int{}
	cooldownRuleOwners := 0
	cooldownRangeOwners := 0
	cooldownSummaryCounts := make(map[string]int)
	cooldownOwners := make([]kernelCandidateOwner, 0)
	backoffRuleOwners := 0
	backoffRangeOwners := 0
	backoffSummaryCounts := make(map[string]int)
	backoffOwners := make([]kernelCandidateOwner, 0)
	backoffMaxFailures := 0
	backoffMaxDuration := time.Duration(0)
	result := kernelIncrementalRetryResult{}
	trigger = normalizeKernelNetlinkRecoveryTrigger(trigger)

	pm.mu.Lock()
	cooldownUntil = cloneActiveKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, now)
	if cooldownUntil == nil {
		cooldownUntil = make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState)
	}
	failureCounts = cloneKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures)
	if failureCounts == nil {
		failureCounts = make(map[kernelCandidateOwner]int)
	}
	for id, ok := range pm.kernelRules {
		if ok {
			currentKernelRules[id] = true
		}
	}
	for id, ok := range pm.kernelRanges {
		if ok {
			currentKernelRanges[id] = true
		}
	}
	for id, ok := range pm.kernelEgressNATs {
		if ok {
			currentKernelEgressNATs[id] = true
		}
	}
	for id, plan := range pm.rulePlans {
		owner := kernelCandidateOwner{kind: workerKindRule, id: id}
		matched := false
		if trigger.matchesPlan(plan) {
			matched = true
		} else if triggerMatchesAddrRefreshPlan(trigger, plan) && (currentKernelRules[id] || isAddrTriggeredKernelFallbackPlan(plan)) {
			matched = true
		}
		if matched {
			if _, counted := matchedRuleOwners[id]; !counted {
				matchedRuleOwners[id] = struct{}{}
				result.matchedRuleOwners++
			}
			if state, ok := cooldownUntil[owner]; ok && state.Until.After(now) {
				cooldownRuleOwners++
				cooldownOwners = append(cooldownOwners, owner)
				source := strings.TrimSpace(state.Source)
				if source == "" {
					source = kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger, plan)
				}
				cooldownSummaryCounts[source]++
			} else {
				retryOwners[owner] = struct{}{}
			}
			continue
		}
		if isNetlinkTriggeredKernelFallbackPlan(plan) {
			unmatchedRuleFallbackPlans[id] = plan
		}
	}
	for id, plan := range pm.rangePlans {
		owner := kernelCandidateOwner{kind: workerKindRange, id: id}
		matched := false
		if trigger.matchesPlan(plan) {
			matched = true
		} else if triggerMatchesAddrRefreshPlan(trigger, plan) && (currentKernelRanges[id] || isAddrTriggeredKernelFallbackPlan(plan)) {
			matched = true
		}
		if matched {
			if _, counted := matchedRangeOwners[id]; !counted {
				matchedRangeOwners[id] = struct{}{}
				result.matchedRangeOwners++
			}
			if state, ok := cooldownUntil[owner]; ok && state.Until.After(now) {
				cooldownRangeOwners++
				cooldownOwners = append(cooldownOwners, owner)
				source := strings.TrimSpace(state.Source)
				if source == "" {
					source = kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger, plan)
				}
				cooldownSummaryCounts[source]++
			} else {
				retryOwners[owner] = struct{}{}
			}
			continue
		}
		if isNetlinkTriggeredKernelFallbackPlan(plan) {
			unmatchedRangeFallbackPlans[id] = plan
		}
	}
	for id, plan := range pm.egressNATPlans {
		owner := kernelCandidateOwner{kind: workerKindEgressNAT, id: id}
		matched := false
		switch {
		case triggerMatchesEgressNATFallbackPlan(trigger, plan):
			matched = true
		case id > 0 && triggerMatchesAddrRefreshPlan(trigger, plan) && (currentKernelEgressNATs[id] || isAddrTriggeredKernelFallbackPlan(plan)):
			matched = true
		}
		if matched {
			if _, ok := matchedEgressNATOwners[id]; !ok {
				matchedEgressNATOwners[id] = struct{}{}
				result.matchedEgressNATs++
			}
			if state, ok := cooldownUntil[owner]; ok && state.Until.After(now) {
				if _, counted := cooldownEgressNATOwners[id]; !counted {
					cooldownEgressNATOwners[id] = struct{}{}
					result.cooldownEgressNATs++
					cooldownOwners = append(cooldownOwners, owner)
					source := strings.TrimSpace(state.Source)
					if source == "" {
						source = kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger, plan)
					}
					cooldownSummaryCounts[source]++
				}
			} else {
				retryOwners[owner] = struct{}{}
			}
			continue
		}
		if isNetlinkTriggeredKernelFallbackPlan(plan) {
			unmatchedEgressNATFallbackPlans[id] = plan
		}
	}
	pm.mu.Unlock()

	if len(retryOwners) == 0 && !trigger.hasSource("link") {
		if cooldownRuleOwners == 0 && cooldownRangeOwners == 0 && result.cooldownEgressNATs == 0 {
			return kernelIncrementalRetryResult{handled: true}
		}
		result.attempted = true
		result.handled = true
		result.cooldownRuleOwners = cooldownRuleOwners
		result.cooldownRangeOwners = cooldownRangeOwners
		result.cooldownSummary = summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(cooldownSummaryCounts)
		result.cooldownScope = summarizeKernelIncrementalRetryOwnerScope(cooldownOwners)
		result.detail = fmt.Sprintf(
			"incremental retry skipped due to owner cooldown%s%s",
			kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
			kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
		)
		pm.mu.Lock()
		pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(cooldownUntil, now, pm.rulePlans, pm.rangePlans, pm.egressNATPlans)
		pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(failureCounts, pm.rulePlans, pm.rangePlans, pm.egressNATPlans)
		pm.mu.Unlock()
		return result
	}

	result.attempted = true
	result.handled = true
	result.cooldownRuleOwners = cooldownRuleOwners
	result.cooldownRangeOwners = cooldownRangeOwners
	result.cooldownSummary = summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(cooldownSummaryCounts)
	result.cooldownScope = summarizeKernelIncrementalRetryOwnerScope(cooldownOwners)

	rules, err := dbGetRules(pm.db)
	if err != nil {
		result.handled = false
		result.detail = fmt.Sprintf("load rules: %v", err)
		return result
	}
	ranges, err := dbGetRanges(pm.db)
	if err != nil {
		result.handled = false
		result.detail = fmt.Sprintf("load ranges: %v", err)
		return result
	}
	egressNATs, err := dbGetEgressNATs(pm.db)
	if err != nil {
		result.handled = false
		result.detail = fmt.Sprintf("load egress nats: %v", err)
		return result
	}
	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		result.handled = false
		result.detail = fmt.Sprintf("load managed networks: %v", err)
		return result
	}

	defaultEngine := ruleEngineAuto
	maxWorkers := 0
	planner := (*ruleDataplanePlanner)(nil)
	configuredKernelRulesMapLimit := 0
	if pm.cfg != nil {
		defaultEngine = pm.cfg.DefaultEngine
		maxWorkers = pm.cfg.MaxWorkers
		configuredKernelRulesMapLimit = pm.cfg.KernelRulesMapLimit
	}
	planner = newRuleDataplanePlanner(pm.kernelRuntime, defaultEngine)
	kernelPressure := snapshotKernelRuntimePressure(pm.kernelRuntime)
	egressNATSnapshot := egressNATInterfaceSnapshot{}
	dynamicEgressNATParents := map[string]struct{}{}
	if len(egressNATs) > 0 || len(managedNetworks) > 0 {
		egressNATSnapshot = loadEgressNATInterfaceSnapshot()
	}
	if len(egressNATs) > 0 {
		egressNATs = normalizeEgressNATItemsWithSnapshot(egressNATs, egressNATSnapshot)
	}
	if len(managedNetworks) > 0 {
		managedNetworkCompiled := compileManagedNetworkRuntime(managedNetworks, nil, egressNATs, egressNATSnapshot.Infos)
		if len(managedNetworkCompiled.EgressNATs) > 0 {
			egressNATs = append(egressNATs, managedNetworkCompiled.EgressNATs...)
		}
	}
	dynamicEgressNATParents = collectDynamicEgressNATParentsWithSnapshot(egressNATs, egressNATSnapshot)
	dynamicRetryEgressNATOwners := collectDynamicEgressNATOwnersForTrigger(trigger, egressNATs, egressNATSnapshot)
	for id := range dynamicRetryEgressNATOwners {
		owner := kernelCandidateOwner{kind: workerKindEgressNAT, id: id}
		if _, ok := matchedEgressNATOwners[id]; !ok {
			matchedEgressNATOwners[id] = struct{}{}
			result.matchedEgressNATs++
		}
		if _, ok := retryOwners[owner]; ok {
			continue
		}
		if state, ok := cooldownUntil[owner]; ok && state.Until.After(now) {
			if _, counted := cooldownEgressNATOwners[id]; counted {
				continue
			}
			cooldownEgressNATOwners[id] = struct{}{}
			result.cooldownEgressNATs++
			cooldownOwners = append(cooldownOwners, owner)
			source := strings.TrimSpace(state.Source)
			if source == "" {
				source = kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger, kernelOwnerDataplanePlan(owner, nil, nil, pm.egressNATPlans))
			}
			cooldownSummaryCounts[source]++
			continue
		}
		retryOwners[owner] = struct{}{}
	}

	if len(retryOwners) == 0 {
		if trigger.hasSource("link") && (len(currentKernelRules) > 0 || len(currentKernelRanges) > 0 || len(currentKernelEgressNATs) > 0) {
			result.attempted = true
			result.handled = false
			result.cooldownRuleOwners = cooldownRuleOwners
			result.cooldownRangeOwners = cooldownRangeOwners
			result.cooldownSummary = summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(cooldownSummaryCounts)
			result.cooldownScope = summarizeKernelIncrementalRetryOwnerScope(cooldownOwners)
			result.detail = fmt.Sprintf(
				"link change requires full kernel re-evaluation of active owners (rule_owners=%d range_owners=%d egress_nat_owners=%d)%s%s",
				len(currentKernelRules),
				len(currentKernelRanges),
				len(currentKernelEgressNATs),
				kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
				kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
			)
			return result
		}
		if cooldownRuleOwners == 0 && cooldownRangeOwners == 0 && result.cooldownEgressNATs == 0 {
			return kernelIncrementalRetryResult{handled: true}
		}
		result.attempted = true
		result.handled = true
		result.cooldownRuleOwners = cooldownRuleOwners
		result.cooldownRangeOwners = cooldownRangeOwners
		result.cooldownSummary = summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(cooldownSummaryCounts)
		result.cooldownScope = summarizeKernelIncrementalRetryOwnerScope(cooldownOwners)
		result.detail = fmt.Sprintf(
			"incremental retry skipped due to owner cooldown%s%s",
			kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
			kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
		)
		pm.mu.Lock()
		pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(cooldownUntil, now, pm.rulePlans, pm.rangePlans, pm.egressNATPlans)
		pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(failureCounts, pm.rulePlans, pm.rangePlans, pm.egressNATPlans)
		pm.mu.Unlock()
		return result
	}

	candidates, rulePlans, rangePlans := buildKernelCandidateRules(rules, ranges, planner, configuredKernelRulesMapLimit)
	applyKernelOwnerConstraints(candidates, rulePlans, rangePlans)
	applyKernelPressurePolicy(kernelPressure, candidates, currentKernelRules, currentKernelRanges, rulePlans, rangePlans)
	preserveUnmatchedNetlinkFallbackPlans(unmatchedRuleFallbackPlans, unmatchedRangeFallbackPlans, rulePlans, rangePlans)

	activeRuleRangeKernelCandidateCount := countActiveKernelCandidates(candidates, rulePlans, rangePlans, nil)
	maxCandidateRuleID := int64(0)
	for _, rule := range rules {
		if rule.ID > maxCandidateRuleID {
			maxCandidateRuleID = rule.ID
		}
	}
	for _, candidate := range candidates {
		if candidate.rule.ID > maxCandidateRuleID {
			maxCandidateRuleID = candidate.rule.ID
		}
	}
	nextSyntheticID := maxCandidateRuleID + 1
	egressNATCandidates, egressNATPlans := buildEgressNATKernelCandidatesWithSnapshot(
		egressNATs,
		planner,
		configuredKernelRulesMapLimit,
		activeRuleRangeKernelCandidateCount,
		&nextSyntheticID,
		egressNATSnapshot,
	)
	preserveUnmatchedNetlinkFallbackEgressPlans(unmatchedEgressNATFallbackPlans, egressNATPlans)

	allKernelCandidates := make([]kernelCandidateRule, 0, len(candidates)+len(egressNATCandidates))
	allKernelCandidates = append(allKernelCandidates, candidates...)
	allKernelCandidates = append(allKernelCandidates, egressNATCandidates...)
	activeCandidates := filterActiveKernelCandidates(allKernelCandidates, rulePlans, rangePlans, egressNATPlans)
	retryCandidates := filterKernelCandidatesByOwners(activeCandidates, retryOwners, rulePlans, rangePlans, egressNATPlans)
	result.attemptedRuleOwners, result.attemptedRangeOwners, result.attemptedEgressNATs = countKernelCandidateOwnersByKind(retryCandidates)
	retryRequiresKernelMutation := hasActiveKernelOwnersMatchingRetryOwners(
		retryOwners,
		currentKernelRules,
		currentKernelRanges,
		currentKernelEgressNATs,
	)

	retainedByEngine := map[string][]Rule{}
	retainedCandidates := make([]kernelCandidateRule, 0)
	retainedSummary := kernelRetainedAssignmentSummary{}
	if len(currentKernelRules) > 0 || len(currentKernelRanges) > 0 || len(currentKernelEgressNATs) > 0 {
		retainer, ok := pm.kernelRuntime.(kernelHandoffRetentionRuntime)
		if !ok || retainer == nil {
			result.handled = false
			result.detail = "incremental kernel retry cannot retain current kernel owners"
			return result
		}
		retainedByEngine, retainedCandidates, retainedSummary, err = buildRetainedKernelAssignments(
			rules,
			ranges,
			egressNATs,
			filterCurrentKernelOwnerIDsExcluding(currentKernelRules, retryOwners, workerKindRule),
			filterCurrentKernelOwnerIDsExcluding(currentKernelRanges, retryOwners, workerKindRange),
			filterCurrentKernelOwnerIDsExcluding(currentKernelEgressNATs, retryOwners, workerKindEgressNAT),
			rulePlans,
			rangePlans,
			egressNATPlans,
			groupKernelCandidatesByOwner(activeCandidates),
			retainer,
			pm.kernelRuntime.SnapshotAssignments(),
		)
		if err != nil {
			result.handled = false
			result.detail = err.Error()
			return result
		}
		result.retainedRuleOwners = retainedSummary.ruleOwners
		result.retainedRangeOwners = retainedSummary.rangeOwners
		result.retainedEgressNATs = retainedSummary.egressNATOwners
	}
	retainedKernelOwners := retainedSummary.ruleOwners > 0 || retainedSummary.rangeOwners > 0 || retainedSummary.egressNATOwners > 0

	if len(retryCandidates) == 0 && !retryRequiresKernelMutation {
		result.detail = fmt.Sprintf(
			"incremental retry found no recoverable owners under current policy (retained_rule_owners=%d retained_range_owners=%d retained_egress_nat_owners=%d)%s%s",
			result.retainedRuleOwners,
			result.retainedRangeOwners,
			result.retainedEgressNATs,
			kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
			kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
		)
		pm.mu.Lock()
		pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(cooldownUntil, time.Now(), rulePlans, rangePlans, egressNATPlans)
		pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(failureCounts, rulePlans, rangePlans, egressNATPlans)
		pm.mu.Unlock()
		return result
	}

	activeRetryCandidates := retryCandidates
	for {
		results, err := reconcileIncrementalKernelRetry(pm.kernelRuntime, retainedByEngine, activeRetryCandidates)
		if err != nil {
			result.handled = false
			result.detail = err.Error()
			return result
		}

		ownerFailures := collectKernelOwnerFailures(activeRetryCandidates, results, nil)
		if len(ownerFailures) == 0 {
			break
		}
		failureAt := time.Now()
		ownerMetadata := collectKernelOwnerFallbackMetadata(activeRetryCandidates, ownerFailures)
		for owner, reason := range ownerFailures {
			applyKernelOwnerFallbackWithMetadata(owner, reason, ownerMetadata[owner], rulePlans, rangePlans, egressNATPlans)
			failureCounts[owner] = nextKernelNetlinkOwnerRetryFailureCount(failureCounts[owner])
			source := kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger, kernelOwnerDataplanePlan(owner, rulePlans, rangePlans, egressNATPlans))
			backoffSummaryCounts[source]++
			backoffOwners = append(backoffOwners, owner)
			switch owner.kind {
			case workerKindRule:
				backoffRuleOwners++
			case workerKindRange:
				backoffRangeOwners++
			case workerKindEgressNAT:
				result.backoffEgressNATs++
			}
			if failureCounts[owner] > backoffMaxFailures {
				backoffMaxFailures = failureCounts[owner]
			}
			backoffDuration := kernelNetlinkOwnerRetryCooldownDuration(failureCounts[owner])
			if backoffDuration > backoffMaxDuration {
				backoffMaxDuration = backoffDuration
			}
			cooldownUntil[owner] = kernelNetlinkOwnerRetryCooldownState{
				Until:  failureAt.Add(backoffDuration),
				Source: source,
			}
		}
		activeRetryCandidates = filterKernelCandidatesByOwners(activeCandidates, retryOwners, rulePlans, rangePlans, egressNATPlans)
		if len(activeRetryCandidates) == 0 {
			break
		}
	}

	finalActiveCandidates := make([]kernelCandidateRule, 0, len(retainedCandidates)+len(activeRetryCandidates))
	finalActiveCandidates = append(finalActiveCandidates, retainedCandidates...)
	finalActiveCandidates = append(finalActiveCandidates, activeRetryCandidates...)

	kernelAssignments := map[int64]string{}
	if pm.kernelRuntime != nil {
		kernelAssignments = pm.kernelRuntime.SnapshotAssignments()
	}

	kernelAppliedRuleEngines := make(map[int64]string)
	kernelAppliedRangeEngines := make(map[int64]string)
	kernelAppliedEgressNATEngines := make(map[int64]string)
	kernelAppliedRules := make(map[int64]bool)
	kernelAppliedRanges := make(map[int64]bool)
	kernelAppliedEgressNATs := make(map[int64]bool)
	kernelFlowOwners := make(map[uint32]kernelCandidateOwner, len(finalActiveCandidates))
	for _, candidate := range finalActiveCandidates {
		if candidate.rule.ID <= 0 || candidate.rule.ID > int64(^uint32(0)) {
			continue
		}
		engine := kernelAssignments[candidate.rule.ID]
		if engine == "" {
			continue
		}
		kernelFlowOwners[uint32(candidate.rule.ID)] = candidate.owner
		if candidate.owner.kind == workerKindRule {
			kernelAppliedRules[candidate.owner.id] = true
			kernelAppliedRuleEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRuleEngines[candidate.owner.id], engine)
			continue
		}
		if candidate.owner.kind == workerKindEgressNAT {
			kernelAppliedEgressNATs[candidate.owner.id] = true
			kernelAppliedEgressNATEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedEgressNATEngines[candidate.owner.id], engine)
			continue
		}
		kernelAppliedRanges[candidate.owner.id] = true
		kernelAppliedRangeEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRangeEngines[candidate.owner.id], engine)
	}

	result.recoveredRuleOwners, result.recoveredRangeOwners, result.recoveredEgressNATs = countKernelCandidateOwnersByKind(activeRetryCandidates)
	refreshKernelStats := pm.kernelRuntime != nil && (result.recoveredRuleOwners > 0 || result.recoveredRangeOwners > 0 || result.recoveredEgressNATs > 0)
	for _, candidate := range activeRetryCandidates {
		delete(cooldownUntil, candidate.owner)
		delete(failureCounts, candidate.owner)
	}
	result.backoffRuleOwners = backoffRuleOwners
	result.backoffRangeOwners = backoffRangeOwners
	result.backoffSummary = summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(backoffSummaryCounts)
	result.backoffScope = summarizeKernelIncrementalRetryOwnerScope(backoffOwners)
	result.backoffMaxFailures = backoffMaxFailures
	result.backoffMaxDuration = backoffMaxDuration

	pm.mu.Lock()
	prevKernelRuleStats := cloneRuleStatsReports(pm.kernelRuleStats)
	prevKernelRangeStats := cloneRangeStatsReports(pm.kernelRangeStats)
	prevKernelEgressNATStats := cloneEgressNATStatsReports(pm.kernelEgressNATStats)
	prevKernelFlowOwners := make(map[uint32]kernelCandidateOwner, len(pm.kernelFlowOwners))
	for id, owner := range pm.kernelFlowOwners {
		prevKernelFlowOwners[id] = owner
	}
	preservedKernelStatsAt := pm.kernelStatsAt
	preservedKernelSnapshotAt := pm.kernelStatsSnapshotAt
	preservedKernelSnapshot := retainKernelStatsSnapshot(pm.kernelStatsSnapshot, prevKernelFlowOwners, kernelFlowOwners)

	pm.rulePlans = rulePlans
	pm.rangePlans = rangePlans
	pm.egressNATPlans = egressNATPlans
	pm.dynamicEgressNATParents = dynamicEgressNATParents
	pm.kernelRules = kernelAppliedRules
	pm.kernelRanges = kernelAppliedRanges
	pm.kernelEgressNATs = kernelAppliedEgressNATs
	pm.kernelRuleEngines = kernelAppliedRuleEngines
	pm.kernelRangeEngines = kernelAppliedRangeEngines
	pm.kernelEgressNATEngines = kernelAppliedEgressNATEngines
	pm.kernelFlowOwners = kernelFlowOwners
	pm.kernelRuleStats = retainKernelRuleStatsReports(prevKernelRuleStats, kernelAppliedRules)
	pm.kernelRangeStats = retainKernelRangeStatsReports(prevKernelRangeStats, kernelAppliedRanges)
	pm.kernelEgressNATStats = retainKernelEgressNATStatsReports(prevKernelEgressNATStats, kernelAppliedEgressNATs)
	pm.kernelStatsSnapshot = preservedKernelSnapshot
	if retainedKernelOwners {
		pm.kernelStatsAt = preservedKernelStatsAt
	} else {
		pm.kernelStatsAt = time.Time{}
	}
	if refreshKernelStats {
		pm.kernelStatsSnapshotAt = time.Time{}
	} else {
		pm.kernelStatsSnapshotAt = preservedKernelSnapshotAt
	}
	pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(cooldownUntil, time.Now(), rulePlans, rangePlans, egressNATPlans)
	pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(failureCounts, rulePlans, rangePlans, egressNATPlans)
	pm.mu.Unlock()

	currentRuleAssignments, currentRangeAssignments := pm.snapshotUserspaceAssignments()
	enabledRules, enabledRanges, ruleAssignments, rangeAssignments := buildUserspaceAssignments(rules, ranges, rulePlans, rangePlans, maxWorkers)
	userspaceAssignmentsChanged := !ruleAssignmentSlicesEqual(currentRuleAssignments, ruleAssignments) ||
		!rangeAssignmentSlicesEqual(currentRangeAssignments, rangeAssignments)
	if userspaceAssignmentsChanged {
		pm.updateTransparentRouting(enabledRules, enabledRanges)
		pm.applyRuleAssignments(ruleAssignments)
		pm.applyRangeAssignments(rangeAssignments)
	}
	if refreshKernelStats {
		pm.refreshKernelStatsCache()
	}
	if result.recoveredRuleOwners == 0 && result.recoveredRangeOwners == 0 && result.recoveredEgressNATs == 0 {
		if result.attemptedEgressNATs > 0 {
			result.detail = fmt.Sprintf(
				"incremental retry refreshed egress_nat_owners=%d entries=%d retained_rule_owners=%d retained_range_owners=%d retained_egress_nat_owners=%d%s%s%s",
				result.attemptedEgressNATs,
				len(activeRetryCandidates),
				result.retainedRuleOwners,
				result.retainedRangeOwners,
				result.retainedEgressNATs,
				kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
				kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
				kernelIncrementalRetryBackoffDetailSuffix(result.backoffRuleOwners, result.backoffRangeOwners, result.backoffEgressNATs, result.backoffSummary, result.backoffMaxFailures, result.backoffMaxDuration),
			)
			return result
		}
		result.detail = fmt.Sprintf(
			"incremental retry completed without recovered owners (retained_rule_owners=%d retained_range_owners=%d retained_egress_nat_owners=%d)%s%s%s",
			result.retainedRuleOwners,
			result.retainedRangeOwners,
			result.retainedEgressNATs,
			kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
			kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
			kernelIncrementalRetryBackoffDetailSuffix(result.backoffRuleOwners, result.backoffRangeOwners, result.backoffEgressNATs, result.backoffSummary, result.backoffMaxFailures, result.backoffMaxDuration),
		)
		return result
	}
	result.detail = fmt.Sprintf(
		"incremental retry recovered rule_owners=%d range_owners=%d egress_nat_owners=%d entries=%d retained_rule_owners=%d retained_range_owners=%d retained_egress_nat_owners=%d%s%s%s",
		result.recoveredRuleOwners,
		result.recoveredRangeOwners,
		result.recoveredEgressNATs,
		len(activeRetryCandidates),
		result.retainedRuleOwners,
		result.retainedRangeOwners,
		result.retainedEgressNATs,
		kernelIncrementalRetryCooldownDetailSuffix(result.cooldownRuleOwners, result.cooldownRangeOwners, result.cooldownEgressNATs),
		kernelIncrementalRetryCooldownSummaryDetailSuffix(result.cooldownSummary),
		kernelIncrementalRetryBackoffDetailSuffix(result.backoffRuleOwners, result.backoffRangeOwners, result.backoffEgressNATs, result.backoffSummary, result.backoffMaxFailures, result.backoffMaxDuration),
	)
	return result
}

type kernelRetainedAssignmentSummary struct {
	ruleOwners      int
	rangeOwners     int
	egressNATOwners int
}

func isNetlinkTriggeredKernelFallbackPlan(plan ruleDataplanePlan) bool {
	return plan.KernelEligible && plan.EffectiveEngine != ruleEngineKernel && isNetlinkTriggeredKernelFallbackReason(plan.FallbackReason)
}

func isAddrTriggeredKernelRefreshReason(reason string) bool {
	return normalizeTransientKernelFallbackReason(reason) == "source_ip_unassigned"
}

func isAddrTriggeredKernelFallbackPlan(plan ruleDataplanePlan) bool {
	return plan.KernelEligible && plan.EffectiveEngine != ruleEngineKernel && isAddrTriggeredKernelRefreshReason(plan.FallbackReason)
}

func isKernelIncrementalRetryCooldownPlan(plan ruleDataplanePlan) bool {
	return isNetlinkTriggeredKernelFallbackPlan(plan) || isAddrTriggeredKernelFallbackPlan(plan)
}

func triggerMatchesAddrRefreshPlan(trigger kernelNetlinkRecoveryTrigger, plan ruleDataplanePlan) bool {
	if !trigger.hasSource("addr") {
		return false
	}
	outInterface := normalizeKernelTransientFallbackInterface(plan.AddrRefresh.OutInterface)
	if outInterface == "" {
		return false
	}
	return trigger.matchesOutInterface(outInterface) && trigger.matchesAddrFamily(plan.AddrRefresh.Family)
}

func preserveUnmatchedNetlinkFallbackPlans(prevRulePlans map[int64]ruleDataplanePlan, prevRangePlans map[int64]rangeDataplanePlan, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan) {
	for id, prev := range prevRulePlans {
		current, ok := rulePlans[id]
		if !ok || current.EffectiveEngine != ruleEngineKernel || !current.KernelEligible {
			continue
		}
		rulePlans[id] = prev
	}
	for id, prev := range prevRangePlans {
		current, ok := rangePlans[id]
		if !ok || current.EffectiveEngine != ruleEngineKernel || !current.KernelEligible {
			continue
		}
		rangePlans[id] = prev
	}
}

func preserveUnmatchedNetlinkFallbackEgressPlans(prevEgressNATPlans map[int64]ruleDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) {
	for id, prev := range prevEgressNATPlans {
		current, ok := egressNATPlans[id]
		if !ok || current.EffectiveEngine != ruleEngineKernel || !current.KernelEligible {
			continue
		}
		egressNATPlans[id] = prev
	}
}

func collectDynamicEgressNATOwnersForTrigger(trigger kernelNetlinkRecoveryTrigger, items []EgressNAT, snapshot egressNATInterfaceSnapshot) map[int64]struct{} {
	if len(items) == 0 || !trigger.hasSource("link") {
		return nil
	}
	matchedParents := kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger, collectDynamicEgressNATParentsWithSnapshot(items, snapshot))
	if len(matchedParents) == 0 {
		return nil
	}

	out := make(map[int64]struct{})
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if snapshot.Err == nil {
			item = normalizeEgressNATScope(item, snapshot.IfaceByName)
		}
		parent := normalizeKernelTransientFallbackInterface(item.ParentInterface)
		if _, ok := matchedParents[parent]; !ok {
			continue
		}
		if strings.TrimSpace(item.ParentInterface) == "" || strings.TrimSpace(item.ChildInterface) != "" {
			continue
		}
		out[item.ID] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func triggerMatchesEgressNATFallbackPlan(trigger kernelNetlinkRecoveryTrigger, plan ruleDataplanePlan) bool {
	if !isNetlinkTriggeredKernelFallbackPlan(plan) {
		return false
	}
	reasonClass := strings.TrimSpace(plan.TransientFallback.ReasonClass)
	if reasonClass == "" {
		reasonClass = normalizeTransientKernelFallbackReason(plan.FallbackReason)
	}
	if trigger.hasSource("netlink") {
		return true
	}
	if trigger.hasSource("link") && reasonClass == "neighbor_missing" {
		return trigger.matchesLinkNeighborInterface(plan.TransientFallback.OutInterface)
	}
	if trigger.hasSource("link") && reasonClass == "fdb_missing" {
		return trigger.matchesLinkFDBInterface(plan.TransientFallback.OutInterface)
	}
	if trigger.hasSource("neighbor") && reasonClass == "neighbor_missing" {
		return trigger.matchesOutInterface(plan.TransientFallback.OutInterface)
	}
	if trigger.hasSource("fdb") && reasonClass == "fdb_missing" {
		return trigger.matchesOutInterface(plan.TransientFallback.OutInterface)
	}
	return len(trigger.sources) == 0
}

func kernelNetlinkOwnerRetryCooldownSourceForPlan(trigger kernelNetlinkRecoveryTrigger, plan ruleDataplanePlan) string {
	reasonClass := strings.TrimSpace(plan.TransientFallback.ReasonClass)
	if reasonClass == "" {
		reasonClass = normalizeTransientKernelFallbackReason(plan.FallbackReason)
	}
	if trigger.hasSource("addr") {
		return "addr"
	}
	if trigger.hasSource("link") {
		return "link"
	}
	if trigger.hasSource("neighbor") && reasonClass == "neighbor_missing" {
		return "neighbor"
	}
	if trigger.hasSource("fdb") && reasonClass == "fdb_missing" {
		return "fdb"
	}
	if trigger.hasSource("netlink") {
		switch reasonClass {
		case "neighbor_missing":
			return "neighbor"
		case "fdb_missing":
			return "fdb"
		default:
			return "netlink"
		}
	}
	switch reasonClass {
	case "neighbor_missing":
		return "neighbor"
	case "fdb_missing":
		return "fdb"
	default:
		if len(trigger.sources) > 0 {
			return "mixed"
		}
		return "unknown"
	}
}

func summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	order := []string{"addr", "neighbor", "fdb", "link", "netlink", "mixed", "unknown"}
	parts := make([]string, 0, len(counts))
	seen := make(map[string]struct{}, len(order))
	for _, key := range order {
		if counts[key] <= 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
		seen[key] = struct{}{}
	}
	extra := make([]string, 0, len(counts))
	for key, value := range counts {
		if value <= 0 {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		extra = append(extra, fmt.Sprintf("%s=%d", key, value))
	}
	sort.Strings(extra)
	parts = append(parts, extra...)
	return strings.Join(parts, ",")
}

func kernelOwnerDataplanePlan(owner kernelCandidateOwner, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) ruleDataplanePlan {
	if owner.kind == workerKindRule {
		return rulePlans[owner.id]
	}
	if owner.kind == workerKindEgressNAT {
		return egressNATPlans[owner.id]
	}
	return rangePlans[owner.id]
}

func cloneActiveKernelNetlinkOwnerRetryCooldowns(src map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, now time.Time) map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState {
	if len(src) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, len(src))
	for owner, state := range src {
		if !state.Until.After(now) {
			continue
		}
		out[owner] = state
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneKernelNetlinkOwnerRetryFailures(src map[kernelCandidateOwner]int) map[kernelCandidateOwner]int {
	if len(src) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]int, len(src))
	for owner, failures := range src {
		if failures <= 0 {
			continue
		}
		out[owner] = failures
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func syncKernelNetlinkOwnerRetryCooldowns(cooldowns map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, now time.Time, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState {
	if len(cooldowns) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, len(cooldowns))
	for owner, state := range cooldowns {
		if !state.Until.After(now) {
			continue
		}
		switch owner.kind {
		case workerKindRule:
			if !isKernelIncrementalRetryCooldownPlan(rulePlans[owner.id]) {
				continue
			}
		case workerKindRange:
			if !isKernelIncrementalRetryCooldownPlan(rangePlans[owner.id]) {
				continue
			}
		case workerKindEgressNAT:
			if !isKernelIncrementalRetryCooldownPlan(egressNATPlans[owner.id]) {
				continue
			}
		default:
			continue
		}
		out[owner] = state
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func syncKernelNetlinkOwnerRetryFailures(failures map[kernelCandidateOwner]int, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) map[kernelCandidateOwner]int {
	if len(failures) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]int, len(failures))
	for owner, count := range failures {
		if count <= 0 {
			continue
		}
		switch owner.kind {
		case workerKindRule:
			if !isKernelIncrementalRetryCooldownPlan(rulePlans[owner.id]) {
				continue
			}
		case workerKindRange:
			if !isKernelIncrementalRetryCooldownPlan(rangePlans[owner.id]) {
				continue
			}
		case workerKindEgressNAT:
			if !isKernelIncrementalRetryCooldownPlan(egressNATPlans[owner.id]) {
				continue
			}
		default:
			continue
		}
		out[owner] = count
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func nextKernelNetlinkOwnerRetryFailureCount(prev int) int {
	if prev < 0 {
		return 1
	}
	return prev + 1
}

func kernelNetlinkOwnerRetryCooldownDuration(failures int) time.Duration {
	if failures <= 1 {
		return kernelNetlinkOwnerRetryCooldown
	}
	duration := kernelNetlinkOwnerRetryCooldown
	for attempt := 1; attempt < failures; attempt++ {
		if duration >= kernelNetlinkOwnerRetryCooldownMax {
			return kernelNetlinkOwnerRetryCooldownMax
		}
		duration *= 2
		if duration >= kernelNetlinkOwnerRetryCooldownMax {
			return kernelNetlinkOwnerRetryCooldownMax
		}
	}
	return duration
}

func countActiveKernelNetlinkOwnerRetryCooldowns(cooldowns map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, now time.Time) (int, int) {
	if len(cooldowns) == 0 {
		return 0, 0
	}
	if now.IsZero() {
		now = time.Now()
	}
	ruleOwners := 0
	rangeOwners := 0
	for owner, state := range cooldowns {
		if !state.Until.After(now) {
			continue
		}
		switch owner.kind {
		case workerKindRule:
			ruleOwners++
		case workerKindRange:
			rangeOwners++
		}
	}
	return ruleOwners, rangeOwners
}

func summarizeActiveKernelNetlinkOwnerRetryCooldowns(cooldowns map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, now time.Time) string {
	if len(cooldowns) == 0 {
		return ""
	}
	if now.IsZero() {
		now = time.Now()
	}
	counts := make(map[string]int)
	for _, state := range cooldowns {
		if !state.Until.After(now) {
			continue
		}
		source := strings.TrimSpace(state.Source)
		if source == "" {
			source = "unknown"
		}
		counts[source]++
	}
	return summarizeKernelNetlinkOwnerRetryCooldownSourceCounts(counts)
}

func activeKernelNetlinkOwnerRetryCooldownWindow(cooldowns map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState, now time.Time) (time.Time, time.Time) {
	if len(cooldowns) == 0 {
		return time.Time{}, time.Time{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	nextExpiry := time.Time{}
	clearAt := time.Time{}
	for _, state := range cooldowns {
		if !state.Until.After(now) {
			continue
		}
		if nextExpiry.IsZero() || state.Until.Before(nextExpiry) {
			nextExpiry = state.Until
		}
		if clearAt.IsZero() || state.Until.After(clearAt) {
			clearAt = state.Until
		}
	}
	return nextExpiry, clearAt
}

func groupKernelCandidatesByOwner(candidates []kernelCandidateRule) map[kernelCandidateOwner][]kernelCandidateRule {
	if len(candidates) == 0 {
		return nil
	}
	grouped := make(map[kernelCandidateOwner][]kernelCandidateRule)
	for _, candidate := range candidates {
		grouped[candidate.owner] = append(grouped[candidate.owner], candidate)
	}
	return grouped
}

func filterKernelCandidatesByOwners(candidates []kernelCandidateRule, owners map[kernelCandidateOwner]struct{}, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan) []kernelCandidateRule {
	if len(candidates) == 0 || len(owners) == 0 {
		return nil
	}
	out := make([]kernelCandidateRule, 0)
	for _, candidate := range candidates {
		if _, ok := owners[candidate.owner]; !ok {
			continue
		}
		if kernelOwnerEffectiveEngine(candidate.owner, rulePlans, rangePlans, egressNATPlans) != ruleEngineKernel {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func filterCurrentKernelOwnerIDsExcluding(current map[int64]bool, owners map[kernelCandidateOwner]struct{}, kind string) map[int64]bool {
	if len(current) == 0 {
		return nil
	}
	out := make(map[int64]bool, len(current))
	for id, active := range current {
		if !active {
			continue
		}
		if _, ok := owners[kernelCandidateOwner{kind: kind, id: id}]; ok {
			continue
		}
		out[id] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hasActiveKernelOwnersMatchingRetryOwners(owners map[kernelCandidateOwner]struct{}, currentKernelRules map[int64]bool, currentKernelRanges map[int64]bool, currentKernelEgressNATs map[int64]bool) bool {
	if len(owners) == 0 {
		return false
	}
	for owner := range owners {
		switch owner.kind {
		case workerKindRule:
			if currentKernelRules[owner.id] {
				return true
			}
		case workerKindRange:
			if currentKernelRanges[owner.id] {
				return true
			}
		case workerKindEgressNAT:
			if currentKernelEgressNATs[owner.id] {
				return true
			}
		}
	}
	return false
}

func buildRetainedKernelAssignments(rules []Rule, ranges []PortRange, egressNATs []EgressNAT, currentKernelRules map[int64]bool, currentKernelRanges map[int64]bool, currentKernelEgressNATs map[int64]bool, rulePlans map[int64]ruleDataplanePlan, rangePlans map[int64]rangeDataplanePlan, egressNATPlans map[int64]ruleDataplanePlan, desiredByOwner map[kernelCandidateOwner][]kernelCandidateRule, retainer kernelHandoffRetentionRuntime, assignments map[int64]string) (map[string][]Rule, []kernelCandidateRule, kernelRetainedAssignmentSummary, error) {
	retainedByEngine := make(map[string][]Rule)
	retainedCandidates := make([]kernelCandidateRule, 0)
	seenRuleIDs := make(map[int64]struct{})
	summary := kernelRetainedAssignmentSummary{}

	rulesByID := make(map[int64]Rule, len(rules))
	for _, rule := range rules {
		rulesByID[rule.ID] = rule
	}
	rangesByID := make(map[int64]PortRange, len(ranges))
	for _, pr := range ranges {
		rangesByID[pr.ID] = pr
	}
	egressNATByID := make(map[int64]EgressNAT, len(egressNATs))
	for _, item := range egressNATs {
		egressNATByID[item.ID] = item
	}

	for id := range currentKernelRules {
		rule, ok := rulesByID[id]
		if !ok {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active rule owner %d is no longer present", id)
		}
		if rulePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active rule owner %d changed target engine", id)
		}
		owner := kernelCandidateOwner{kind: workerKindRule, id: id}
		retained, ok := retainer.retainedKernelRuleCandidates(rule)
		if !ok || !retainedKernelCandidatesMatchDesired(retained, desiredByOwner[owner], owner) {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active rule owner %d cannot be retained in place", id)
		}
		for _, item := range retained {
			if err := appendRetainedKernelAssignment(retainedByEngine, assignments, seenRuleIDs, item); err != nil {
				return nil, nil, summary, err
			}
			retainedCandidates = append(retainedCandidates, kernelCandidateRule{owner: owner, rule: item})
		}
		summary.ruleOwners++
	}

	for id := range currentKernelRanges {
		pr, ok := rangesByID[id]
		if !ok {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active range owner %d is no longer present", id)
		}
		if rangePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active range owner %d changed target engine", id)
		}
		owner := kernelCandidateOwner{kind: workerKindRange, id: id}
		retained, ok := retainer.retainedKernelRangeCandidates(pr)
		if !ok || !retainedKernelCandidatesMatchDesired(retained, desiredByOwner[owner], owner) {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active range owner %d cannot be retained in place", id)
		}
		for _, item := range retained {
			if err := appendRetainedKernelAssignment(retainedByEngine, assignments, seenRuleIDs, item); err != nil {
				return nil, nil, summary, err
			}
			retainedCandidates = append(retainedCandidates, kernelCandidateRule{owner: owner, rule: item})
		}
		summary.rangeOwners++
	}

	for id := range currentKernelEgressNATs {
		item, ok := egressNATByID[id]
		if !ok {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active egress nat owner %d is no longer present", id)
		}
		if egressNATPlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active egress nat owner %d changed target engine", id)
		}
		owner := kernelCandidateOwner{kind: workerKindEgressNAT, id: id}
		retained, ok := retainer.retainedKernelEgressNATCandidates(item)
		if !ok || !retainedKernelCandidatesMatchDesired(retained, desiredByOwner[owner], owner) {
			return nil, nil, summary, fmt.Errorf("incremental kernel retry requires full redistribute: active egress nat owner %d cannot be retained in place", id)
		}
		for _, retainedItem := range retained {
			if err := appendRetainedKernelAssignment(retainedByEngine, assignments, seenRuleIDs, retainedItem); err != nil {
				return nil, nil, summary, err
			}
			retainedCandidates = append(retainedCandidates, kernelCandidateRule{owner: owner, rule: retainedItem})
		}
		summary.egressNATOwners++
	}

	return retainedByEngine, retainedCandidates, summary, nil
}

func appendRetainedKernelAssignment(retainedByEngine map[string][]Rule, assignments map[int64]string, seenRuleIDs map[int64]struct{}, rule Rule) error {
	if _, exists := seenRuleIDs[rule.ID]; exists {
		return fmt.Errorf("incremental kernel retry requires full redistribute: duplicate retained kernel rule id %d", rule.ID)
	}
	engine := assignments[rule.ID]
	if engine == "" {
		return fmt.Errorf("incremental kernel retry requires full redistribute: retained kernel rule %d lost its engine assignment", rule.ID)
	}
	seenRuleIDs[rule.ID] = struct{}{}
	retainedByEngine[engine] = append(retainedByEngine[engine], rule)
	return nil
}

func retainedKernelCandidatesMatchDesired(retained []Rule, desired []kernelCandidateRule, owner kernelCandidateOwner) bool {
	if len(retained) == 0 || len(retained) != len(desired) {
		return false
	}

	desiredRules := make([]Rule, 0, len(desired))
	for _, candidate := range desired {
		if candidate.owner != owner {
			return false
		}
		desiredRules = append(desiredRules, candidate.rule)
	}
	matchedDesired := make([]bool, len(desiredRules))

	for _, item := range retained {
		if item.kernelLogKind != owner.kind || item.kernelLogOwnerID != owner.id {
			return false
		}
		matched := false
		for idx, want := range desiredRules {
			if matchedDesired[idx] {
				continue
			}
			if !sameRetainedKernelRuleDataplaneIgnoringID(item, want) {
				continue
			}
			matchedDesired[idx] = true
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func sameRetainedKernelRuleDataplane(a Rule, b Rule) bool {
	return a.ID == b.ID &&
		sameRetainedKernelRuleDataplaneIgnoringID(a, b)
}

func sameRetainedKernelRuleDataplaneIgnoringID(a Rule, b Rule) bool {
	return a.InInterface == b.InInterface &&
		a.InIP == b.InIP &&
		a.InPort == b.InPort &&
		a.OutInterface == b.OutInterface &&
		a.OutIP == b.OutIP &&
		a.OutSourceIP == b.OutSourceIP &&
		a.OutPort == b.OutPort &&
		a.Protocol == b.Protocol &&
		a.Transparent == b.Transparent &&
		a.kernelMode == b.kernelMode &&
		a.kernelNATType == b.kernelNATType &&
		a.kernelLogKind == b.kernelLogKind &&
		a.kernelLogOwnerID == b.kernelLogOwnerID
}

func reconcileIncrementalKernelRetry(runtime kernelRuleRuntime, retainedByEngine map[string][]Rule, retryCandidates []kernelCandidateRule) (map[int64]kernelRuleApplyResult, error) {
	retryRules := kernelCandidateRules(retryCandidates)
	if totalRetainedKernelAssignments(retainedByEngine) == 0 {
		return runtime.Reconcile(retryRules)
	}
	retainedRuntime, ok := runtime.(kernelRetainedAssignmentRuntime)
	if !ok || retainedRuntime == nil {
		return nil, fmt.Errorf("incremental kernel retry cannot retain current kernel assignments on this runtime")
	}
	return retainedRuntime.ReconcileRetainingAssignments(retainedByEngine, retryRules)
}

func totalRetainedKernelAssignments(retainedByEngine map[string][]Rule) int {
	total := 0
	for _, rules := range retainedByEngine {
		total += len(rules)
	}
	return total
}

func countKernelCandidateOwnersByKind(candidates []kernelCandidateRule) (int, int, int) {
	rules := make(map[int64]struct{})
	ranges := make(map[int64]struct{})
	egressNATs := make(map[int64]struct{})
	for _, candidate := range candidates {
		if candidate.owner.kind == workerKindRule {
			rules[candidate.owner.id] = struct{}{}
			continue
		}
		if candidate.owner.kind == workerKindEgressNAT {
			egressNATs[candidate.owner.id] = struct{}{}
			continue
		}
		if candidate.owner.kind == workerKindRange {
			ranges[candidate.owner.id] = struct{}{}
		}
	}
	return len(rules), len(ranges), len(egressNATs)
}
