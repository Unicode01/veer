package app

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

var loadIPv6AssignmentsForManagedNetworkReload = dbGetIPv6Assignments

func (pm *ProcessManager) requestManagedNetworkRuntimeReload(delay time.Duration, names ...string) {
	pm.requestManagedNetworkRuntimeReloadWithSource(delay, "", names...)
}

func (pm *ProcessManager) requestManagedNetworkRuntimeReloadWithSource(delay time.Duration, source string, names ...string) {
	if pm == nil {
		return
	}
	if delay < 0 {
		delay = 0
	}
	dueAt := time.Now().Add(delay)

	pm.mu.Lock()
	if pm.shuttingDown {
		pm.mu.Unlock()
		return
	}
	switch {
	case !pm.managedRuntimeReloadPending:
		pm.managedRuntimeReloadDueAt = dueAt
	case delay <= 0:
		if pm.managedRuntimeReloadDueAt.IsZero() || dueAt.Before(pm.managedRuntimeReloadDueAt) {
			pm.managedRuntimeReloadDueAt = dueAt
		}
	default:
		if pm.managedRuntimeReloadDueAt.IsZero() || dueAt.After(pm.managedRuntimeReloadDueAt) {
			pm.managedRuntimeReloadDueAt = dueAt
		}
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if pm.managedRuntimeReloadInterfaces == nil {
			pm.managedRuntimeReloadInterfaces = make(map[string]struct{})
		}
		pm.managedRuntimeReloadInterfaces[name] = struct{}{}
	}
	pm.managedRuntimeReloadPending = true
	pm.managedRuntimeReloadLastRequestedAt = time.Now()
	pm.managedRuntimeReloadLastRequestSource = normalizeManagedNetworkRuntimeReloadSource(source)
	pm.managedRuntimeReloadLastRequestSummary = summarizeManagedRuntimeReloadInterfaces(pm.managedRuntimeReloadInterfaces)
	wake := pm.managedRuntimeReloadWake
	pm.mu.Unlock()

	if wake != nil {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
}

func (pm *ProcessManager) markManagedNetworkRuntimeReloadStarted() {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	pm.managedRuntimeReloadLastStartedAt = time.Now()
	pm.managedRuntimeReloadLastCompletedAt = time.Time{}
	pm.managedRuntimeReloadLastResult = ""
	pm.managedRuntimeReloadLastAppliedSummary = ""
	pm.managedRuntimeReloadLastError = ""
	pm.mu.Unlock()
}

func (pm *ProcessManager) markManagedNetworkRuntimeReloadCompleted(result string, appliedSummary string, err error) {
	if pm == nil {
		return
	}
	pm.mu.Lock()
	pm.managedRuntimeReloadLastCompletedAt = time.Now()
	pm.managedRuntimeReloadLastResult = strings.TrimSpace(result)
	pm.managedRuntimeReloadLastAppliedSummary = strings.TrimSpace(appliedSummary)
	if err != nil {
		pm.managedRuntimeReloadLastError = err.Error()
	} else {
		pm.managedRuntimeReloadLastError = ""
	}
	pm.mu.Unlock()
}

func appendManagedNetworkRuntimeReloadIssue(issues []string, scope string, err error) []string {
	if err == nil {
		return issues
	}
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return append(issues, err.Error())
	}
	return append(issues, fmt.Sprintf("%s: %v", scope, err))
}

func managedNetworkRuntimeReloadCompletion(issues []string) (string, error) {
	if len(issues) == 0 {
		return "success", nil
	}
	cleaned := make([]string, 0, len(issues))
	seen := make(map[string]struct{}, len(issues))
	for _, issue := range issues {
		issue = strings.TrimSpace(issue)
		if issue == "" {
			continue
		}
		if _, ok := seen[issue]; ok {
			continue
		}
		seen[issue] = struct{}{}
		cleaned = append(cleaned, issue)
	}
	if len(cleaned) == 0 {
		return "success", nil
	}
	return "partial", fmt.Errorf("%s", strings.Join(cleaned, "; "))
}

func mergeManagedNetworkRuntimeReloadError(existing string, scope string, err error) error {
	issues := make([]string, 0, 2)
	existing = strings.TrimSpace(existing)
	if existing != "" {
		for _, issue := range strings.Split(existing, ";") {
			issue = strings.TrimSpace(issue)
			if issue != "" {
				issues = append(issues, issue)
			}
		}
	}
	issues = appendManagedNetworkRuntimeReloadIssue(issues, scope, err)
	_, mergedErr := managedNetworkRuntimeReloadCompletion(issues)
	return mergedErr
}

func (pm *ProcessManager) noteManagedNetworkRuntimeReloadIssue(scope string, err error) {
	if pm == nil || err == nil {
		return
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.managedRuntimeReloadLastError = strings.TrimSpace(mergeManagedNetworkRuntimeReloadError(pm.managedRuntimeReloadLastError, scope, err).Error())
	result := strings.TrimSpace(pm.managedRuntimeReloadLastResult)
	switch result {
	case "", "success":
		pm.managedRuntimeReloadLastResult = "partial"
	}
}

func (pm *ProcessManager) managedRuntimeReloadLoop() {
	defer close(pm.managedRuntimeReloadDone)

	var timer *time.Timer
	for {
		pm.mu.Lock()
		pending := pm.managedRuntimeReloadPending
		dueAt := pm.managedRuntimeReloadDueAt
		wake := pm.managedRuntimeReloadWake
		shutdownCh := pm.shutdownCh
		shuttingDown := pm.shuttingDown
		pm.mu.Unlock()

		if shuttingDown {
			if timer != nil {
				stopTimer(timer)
			}
			return
		}

		if !pending {
			if timer != nil {
				stopTimer(timer)
				timer = nil
			}
			if wake == nil {
				return
			}
			select {
			case <-shutdownCh:
				return
			case _, ok := <-wake:
				if !ok {
					return
				}
			}
			continue
		}

		if wait := time.Until(dueAt); wait > 0 {
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				resetTimer(timer, wait)
			}
			select {
			case <-shutdownCh:
				stopTimer(timer)
				return
			case _, ok := <-wake:
				if !ok {
					stopTimer(timer)
					return
				}
				continue
			case <-timer.C:
			}
		}

		pm.mu.Lock()
		if pm.shuttingDown {
			pm.mu.Unlock()
			if timer != nil {
				stopTimer(timer)
			}
			return
		}
		if !pm.managedRuntimeReloadPending {
			pm.mu.Unlock()
			continue
		}
		if !pm.managedRuntimeReloadDueAt.IsZero() && time.Now().Before(pm.managedRuntimeReloadDueAt) {
			pm.mu.Unlock()
			continue
		}
		pm.managedRuntimeReloadPending = false
		pm.managedRuntimeReloadDueAt = time.Time{}
		reloadInterfaces := cloneManagedNetworkInterfaceSet(pm.managedRuntimeReloadInterfaces)
		reloadSource := pm.managedRuntimeReloadLastRequestSource
		pm.managedRuntimeReloadInterfaces = nil
		pm.mu.Unlock()

		pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, managedNetworkRuntimeInterfaceNamesFromSet(reloadInterfaces)...)
		if summary := summarizeManagedRuntimeReloadInterfaces(reloadInterfaces); summary != "" {
			log.Printf("managed network runtime: auto reload triggered by link change on %s", summary)
		}
		pm.markManagedNetworkRuntimeReloadStarted()
		var reloadRepairErr error
		if pm.shouldAutoRepairManagedNetworkRuntimeReload(reloadSource) {
			repairResult, repairErr := repairManagedNetworkHostStateForProcessManager(pm)
			pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, managedNetworkRepairResultInterfaceNames(repairResult)...)
			if repairSummary := summarizeManagedNetworkRepairResult(repairResult); repairSummary != "" {
				log.Printf("managed network runtime: auto repair applied %s", repairSummary)
			}
			if repairErr != nil {
				log.Printf("managed network runtime: auto repair before reload failed: %v", repairErr)
				reloadRepairErr = repairErr
			}
		}
		if err := pm.reloadManagedNetworkRuntimeOnly(); err != nil {
			pm.markManagedNetworkRuntimeReloadCompleted("fallback", "", err)
			log.Printf("managed network runtime reload: targeted reload failed, falling back to full redistribute: %v", err)
			pm.requestRedistributeWorkers(0)
			continue
		}
		pm.noteManagedNetworkRuntimeReloadIssue("managed network auto repair", reloadRepairErr)
	}
}

func (pm *ProcessManager) reloadManagedNetworkRuntimeOnly() error {
	if pm == nil {
		return nil
	}
	if pm.db == nil {
		return fmt.Errorf("managed network runtime reload requires database access")
	}

	pm.redistributeMu.Lock()
	defer pm.redistributeMu.Unlock()

	managedNetworks, err := dbGetManagedNetworks(pm.db)
	if err != nil {
		return fmt.Errorf("load managed networks: %w", err)
	}
	managedNetworkReservations, err := dbGetManagedNetworkReservations(pm.db)
	if err != nil {
		return fmt.Errorf("load managed network reservations: %w", err)
	}
	reloadIssues := make([]string, 0, 2)
	if pm.managedNetworkRuntime != nil {
		if err := pm.managedNetworkRuntime.Reconcile(managedNetworks, managedNetworkReservations); err != nil {
			log.Printf("managed network runtime reconcile: %v", err)
			reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "managed network runtime reconcile", err)
		}
	}

	explicitEgressNATs, err := dbGetEgressNATs(pm.db)
	if err != nil {
		return fmt.Errorf("load egress nats: %w", err)
	}
	ipv6Assignments, ipv6AssignmentLoadErr := loadIPv6AssignmentsForManagedNetworkReload(pm.db)
	if ipv6AssignmentLoadErr != nil {
		log.Printf("load ipv6 assignments: %v", ipv6AssignmentLoadErr)
		reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "load ipv6 assignments", ipv6AssignmentLoadErr)
	}

	egressNATSnapshot := egressNATInterfaceSnapshot{}
	needsManagedNetworkCompilation := len(managedNetworks) > 0
	if len(explicitEgressNATs) > 0 || needsManagedNetworkCompilation {
		egressNATSnapshot = loadEgressNATInterfaceSnapshot()
	}
	if needsManagedNetworkCompilation && egressNATSnapshot.Err != nil {
		log.Printf("managed network runtime: interface inventory unavailable: %v", egressNATSnapshot.Err)
		reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "managed network interface inventory", egressNATSnapshot.Err)
	}
	explicitEgressNATs = normalizeEgressNATItemsWithSnapshot(explicitEgressNATs, egressNATSnapshot)
	managedNetworkCompiled := compileManagedNetworkRuntime(managedNetworks, ipv6Assignments, explicitEgressNATs, egressNATSnapshot.Infos)
	for _, warning := range managedNetworkCompiled.Warnings {
		log.Printf("managed network runtime: %s", warning)
	}

	effectiveIPv6Assignments := append([]IPv6Assignment(nil), ipv6Assignments...)
	if len(managedNetworkCompiled.IPv6Assignments) > 0 {
		effectiveIPv6Assignments = append(effectiveIPv6Assignments, managedNetworkCompiled.IPv6Assignments...)
	}

	effectiveEgressNATs := append([]EgressNAT(nil), explicitEgressNATs...)
	if len(managedNetworkCompiled.EgressNATs) > 0 {
		effectiveEgressNATs = append(effectiveEgressNATs, managedNetworkCompiled.EgressNATs...)
	}
	dynamicEgressNATParents := collectDynamicEgressNATParentsWithSnapshot(effectiveEgressNATs, egressNATSnapshot)
	managedNetworkInterfaces := cloneManagedNetworkInterfaceSet(managedNetworkCompiled.RedistributeIfaces)
	reloadSummary := summarizeManagedNetworkRuntimeReload(managedNetworks, managedNetworkReservations, effectiveIPv6Assignments, managedNetworkCompiled.EgressNATs)
	pm.suppressManagedNetworkRuntimeReloadForInterfaces(managedNetworkSelfEventSuppressFor, collectManagedNetworkRuntimeTouchedInterfaces(managedNetworks, effectiveIPv6Assignments, managedNetworkCompiled)...)

	if ipv6AssignmentLoadErr == nil {
		if pm.ipv6Runtime != nil {
			if err := pm.ipv6Runtime.Reconcile(effectiveIPv6Assignments); err != nil {
				log.Printf("ipv6 assignment runtime reconcile: %v", err)
				reloadIssues = appendManagedNetworkRuntimeReloadIssue(reloadIssues, "ipv6 assignment runtime reconcile", err)
			}
		}
		ipv6Interfaces, ipv6ConfiguredCount := collectIPv6AssignmentInterfaceNames(effectiveIPv6Assignments)
		for name := range managedNetworkCompiled.RedistributeIfaces {
			if ipv6Interfaces == nil {
				ipv6Interfaces = make(map[string]struct{})
			}
			ipv6Interfaces[name] = struct{}{}
		}
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.ipv6AssignmentsConfigured = ipv6ConfiguredCount > 0 || len(managedNetworkCompiled.RedistributeIfaces) > 0
		pm.ipv6AssignmentInterfaces = ipv6Interfaces
		pm.mu.Unlock()
	} else {
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.mu.Unlock()
	}
	reloadResult, reloadErr := managedNetworkRuntimeReloadCompletion(reloadIssues)

	if pm.kernelRuntime == nil || pm.cfg == nil {
		pm.mu.Lock()
		pm.managedNetworkInterfaces = managedNetworkInterfaces
		pm.dynamicEgressNATParents = dynamicEgressNATParents
		pm.mu.Unlock()
		if reloadSummary != "" {
			log.Printf("managed network runtime: targeted reload applied %s", reloadSummary)
		}
		pm.markManagedNetworkRuntimeReloadCompleted(reloadResult, reloadSummary, reloadErr)
		return nil
	}

	if err := pm.reconcileManagedNetworkAutoEgressNATs(explicitEgressNATs, managedNetworkCompiled.EgressNATs, dynamicEgressNATParents, egressNATSnapshot); err != nil {
		return err
	}
	if reloadSummary != "" {
		log.Printf("managed network runtime: targeted reload applied %s", reloadSummary)
	}
	pm.markManagedNetworkRuntimeReloadCompleted(reloadResult, reloadSummary, reloadErr)
	return nil
}

func summarizeManagedNetworkRuntimeReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation, effectiveIPv6Assignments []IPv6Assignment, autoEgressNATs []EgressNAT) string {
	parts := make([]string, 0, 8)

	enabledNetworks := 0
	bridges := make(map[string]struct{})
	reservationsByNetwork := make(map[int64][]ManagedNetworkReservation)
	for _, item := range reservations {
		if item.ManagedNetworkID <= 0 {
			continue
		}
		reservationsByNetwork[item.ManagedNetworkID] = append(reservationsByNetwork[item.ManagedNetworkID], item)
	}
	dhcpv4Bridges := make(map[string]struct{})
	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled {
			continue
		}
		enabledNetworks++
		if bridge := strings.TrimSpace(network.Bridge); bridge != "" {
			bridges[bridge] = struct{}{}
		}
		if !network.IPv4Enabled {
			continue
		}
		plan, err := buildManagedNetworkIPv4Plan(network, reservationsByNetwork[network.ID])
		if err != nil {
			continue
		}
		if bridge := strings.TrimSpace(plan.Bridge); bridge != "" {
			dhcpv4Bridges[bridge] = struct{}{}
		}
	}
	if enabledNetworks > 0 {
		parts = append(parts, fmt.Sprintf("networks=%d", enabledNetworks))
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(bridges); summary != "" {
		parts = append(parts, "bridges="+summary)
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(dhcpv4Bridges); summary != "" {
		parts = append(parts, "dhcpv4="+summary)
	}

	routes := make(map[ipv6AssignmentRouteSpec]struct{})
	proxies := make(map[ipv6AssignmentProxySpec]struct{})
	raTargets := make(map[string]struct{})
	dhcpv6Targets := make(map[string]struct{})
	for _, item := range effectiveIPv6Assignments {
		if !item.Enabled {
			continue
		}
		plan, err := buildIPv6AssignmentRuntimePlan(item)
		if err != nil {
			continue
		}
		routes[ipv6AssignmentRouteSpec{
			Prefix:          plan.AssignedPrefix,
			TargetInterface: plan.TargetInterface,
		}] = struct{}{}
		if plan.NeedsProxyNDP {
			proxies[ipv6AssignmentProxySpec{
				ParentInterface: plan.ParentInterface,
				Address:         plan.ProxyAddress,
			}] = struct{}{}
		}
		if plan.NeedsRADvertise || plan.Intent.kind == ipv6AssignmentIntentSingleAddress {
			raTargets[plan.TargetInterface] = struct{}{}
		}
		if plan.Intent.kind == ipv6AssignmentIntentSingleAddress {
			dhcpv6Targets[plan.TargetInterface] = struct{}{}
		}
	}
	if len(routes) > 0 {
		parts = append(parts, fmt.Sprintf("ipv6_routes=%d", len(routes)))
	}
	if len(proxies) > 0 {
		parts = append(parts, fmt.Sprintf("proxy_ndp=%d", len(proxies)))
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(raTargets); summary != "" {
		parts = append(parts, "ra="+summary)
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(dhcpv6Targets); summary != "" {
		parts = append(parts, "dhcpv6="+summary)
	}

	autoEgressNATCount := 0
	autoEgressParents := make(map[string]struct{})
	for _, item := range autoEgressNATs {
		if !item.Enabled {
			continue
		}
		autoEgressNATCount++
		if parent := strings.TrimSpace(item.ParentInterface); parent != "" {
			autoEgressParents[parent] = struct{}{}
		}
	}
	if autoEgressNATCount > 0 {
		part := fmt.Sprintf("auto_egress_nat=%d", autoEgressNATCount)
		if summary := summarizeManagedRuntimeReloadInterfaces(autoEgressParents); summary != "" {
			part += "(" + summary + ")"
		}
		parts = append(parts, part)
	}

	return strings.Join(parts, " ")
}

func collectManagedNetworkRuntimeTouchedInterfaces(managedNetworks []ManagedNetwork, effectiveIPv6Assignments []IPv6Assignment, compiled managedNetworkRuntimeCompilation) []string {
	names := make([]string, 0, len(managedNetworks)*4+len(effectiveIPv6Assignments)*2)
	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled {
			continue
		}
		names = append(names, network.Bridge, network.UplinkInterface, network.IPv6ParentInterface)
		if preview, ok := compiled.Previews[network.ID]; ok {
			names = append(names, preview.ChildInterfaces...)
		}
	}
	for _, item := range effectiveIPv6Assignments {
		if !item.Enabled {
			continue
		}
		names = append(names, item.ParentInterface, item.TargetInterface)
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(names...)
}

func cloneManagedNetworkInterfaceSet(src map[string]struct{}) map[string]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]struct{}, len(src))
	for name := range src {
		if name == "" {
			continue
		}
		dst[name] = struct{}{}
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func summarizeManagedRuntimeReloadInterfaces(src map[string]struct{}) string {
	if len(src) == 0 {
		return ""
	}
	items := make([]string, 0, len(src))
	for name := range src {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		items = append(items, name)
	}
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	if len(items) > 3 {
		items = append(items[:3], fmt.Sprintf("+%d", len(items)-3))
	}
	return strings.Join(items, ",")
}

func (pm *ProcessManager) reconcileManagedNetworkAutoEgressNATs(explicitEgressNATs []EgressNAT, autoEgressNATs []EgressNAT, dynamicEgressNATParents map[string]struct{}, snapshot egressNATInterfaceSnapshot) error {
	if pm == nil || pm.kernelRuntime == nil || pm.cfg == nil {
		return nil
	}

	rules, err := dbGetRules(pm.db)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	ranges, err := dbGetRanges(pm.db)
	if err != nil {
		return fmt.Errorf("load ranges: %w", err)
	}

	currentRulePlans, currentRangePlans, currentEgressNATPlans, currentKernelRules, currentKernelRanges, currentKernelEgressNATs, prevKernelRuleStats, prevKernelRangeStats, prevKernelEgressNATStats, prevKernelFlowOwners, prevKernelStatsSnapshot, prevKernelStatsAt, prevKernelStatsSnapshotAt :=
		pm.snapshotManagedNetworkKernelReloadState()

	retainer, ok := pm.kernelRuntime.(kernelHandoffRetentionRuntime)
	if !ok || retainer == nil {
		return fmt.Errorf("managed network runtime reload requires kernel assignment retention support")
	}

	currentExplicitKernelEgressNATs := filterPositiveKernelOwnerIDs(currentKernelEgressNATs)
	retainedDesiredByOwner, maxRuleID, retainedEntries, err := buildManagedNetworkRetainedKernelDesiredByOwner(
		rules,
		ranges,
		explicitEgressNATs,
		currentKernelRules,
		currentKernelRanges,
		currentExplicitKernelEgressNATs,
		currentRulePlans,
		currentRangePlans,
		currentEgressNATPlans,
		retainer,
	)
	if err != nil {
		return err
	}

	planner := newRuleDataplanePlanner(pm.kernelRuntime, pm.cfg.DefaultEngine)
	nextSyntheticID := maxRuleID + 1
	autoCandidates, autoPlans := buildEgressNATKernelCandidatesWithSnapshot(
		autoEgressNATs,
		planner,
		pm.cfg.KernelRulesMapLimit,
		retainedEntries,
		&nextSyntheticID,
		snapshot,
	)
	autoCandidateOwners := ownerSetFromKernelCandidates(autoCandidates)
	desiredByOwner := mergeKernelCandidateGroups(retainedDesiredByOwner, groupKernelCandidatesByOwner(autoCandidates))
	egressNATPlans := mergeManagedNetworkReloadEgressNATPlans(currentEgressNATPlans, autoPlans)

	currentKernelAssignments := pm.kernelRuntime.SnapshotAssignments()
	retainedByEngine, retainedCandidates, retainedSummary, err := buildRetainedKernelAssignments(
		rules,
		ranges,
		append(append([]EgressNAT(nil), explicitEgressNATs...), autoEgressNATs...),
		currentKernelRules,
		currentKernelRanges,
		currentExplicitKernelEgressNATs,
		currentRulePlans,
		currentRangePlans,
		egressNATPlans,
		desiredByOwner,
		retainer,
		currentKernelAssignments,
	)
	if err != nil {
		return err
	}

	retryCandidates := filterKernelCandidatesByOwners(autoCandidates, autoCandidateOwners, nil, nil, egressNATPlans)
	needsKernelRefresh := len(retryCandidates) > 0 || len(currentKernelEgressNATs) != len(currentExplicitKernelEgressNATs)
	if totalRetainedKernelAssignments(retainedByEngine) == 0 && len(retryCandidates) == 0 && !needsKernelRefresh {
		pm.mu.Lock()
		pm.dynamicEgressNATParents = dynamicEgressNATParents
		pm.egressNATPlans = egressNATPlans
		pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, time.Now(), currentRulePlans, currentRangePlans, egressNATPlans)
		pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures, currentRulePlans, currentRangePlans, egressNATPlans)
		pm.mu.Unlock()
		return nil
	}

	activeRetryCandidates := retryCandidates
	for {
		results, err := reconcileIncrementalKernelRetry(pm.kernelRuntime, retainedByEngine, activeRetryCandidates)
		if len(activeRetryCandidates) == 0 {
			break
		}
		ownerFailures := collectKernelOwnerFailures(activeRetryCandidates, results, err)
		if len(ownerFailures) == 0 {
			break
		}
		ownerMetadata := collectKernelOwnerFallbackMetadata(activeRetryCandidates, ownerFailures)
		for owner, reason := range ownerFailures {
			applyKernelOwnerFallbackWithMetadata(owner, reason, ownerMetadata[owner], nil, nil, egressNATPlans)
		}
		activeRetryCandidates = filterKernelCandidatesByOwners(autoCandidates, autoCandidateOwners, nil, nil, egressNATPlans)
	}

	finalActiveCandidates := make([]kernelCandidateRule, 0, len(retainedCandidates)+len(activeRetryCandidates))
	finalActiveCandidates = append(finalActiveCandidates, retainedCandidates...)
	finalActiveCandidates = append(finalActiveCandidates, activeRetryCandidates...)

	kernelAssignments := pm.kernelRuntime.SnapshotAssignments()
	kernelAppliedRuleEngines, kernelAppliedRangeEngines, kernelAppliedEgressNATEngines, kernelAppliedRules, kernelAppliedRanges, kernelAppliedEgressNATs, kernelFlowOwners :=
		buildAppliedKernelOwnerState(finalActiveCandidates, kernelAssignments)

	preservedKernelSnapshot := retainKernelStatsSnapshot(prevKernelStatsSnapshot, prevKernelFlowOwners, kernelFlowOwners)
	pm.mu.Lock()
	pm.rulePlans = currentRulePlans
	pm.rangePlans = currentRangePlans
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
	if retainedSummary.ruleOwners > 0 || retainedSummary.rangeOwners > 0 || retainedSummary.egressNATOwners > 0 {
		pm.kernelStatsAt = prevKernelStatsAt
	} else {
		pm.kernelStatsAt = time.Time{}
	}
	if len(activeRetryCandidates) > 0 {
		pm.kernelStatsSnapshotAt = time.Time{}
	} else {
		pm.kernelStatsSnapshotAt = prevKernelStatsSnapshotAt
	}
	pm.kernelNetlinkOwnerRetryCooldownUntil = syncKernelNetlinkOwnerRetryCooldowns(pm.kernelNetlinkOwnerRetryCooldownUntil, time.Now(), currentRulePlans, currentRangePlans, egressNATPlans)
	pm.kernelNetlinkOwnerRetryFailures = syncKernelNetlinkOwnerRetryFailures(pm.kernelNetlinkOwnerRetryFailures, currentRulePlans, currentRangePlans, egressNATPlans)
	pm.mu.Unlock()

	if len(activeRetryCandidates) > 0 {
		pm.refreshKernelStatsCache()
	}
	return nil
}

func (pm *ProcessManager) snapshotManagedNetworkKernelReloadState() (
	map[int64]ruleDataplanePlan,
	map[int64]rangeDataplanePlan,
	map[int64]ruleDataplanePlan,
	map[int64]bool,
	map[int64]bool,
	map[int64]bool,
	map[int64]RuleStatsReport,
	map[int64]RangeStatsReport,
	map[int64]EgressNATStatsReport,
	map[uint32]kernelCandidateOwner,
	kernelRuleStatsSnapshot,
	time.Time,
	time.Time,
) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	rulePlans := cloneRuleDataplanePlans(pm.rulePlans)
	rangePlans := cloneRangeDataplanePlans(pm.rangePlans)
	egressNATPlans := cloneRuleDataplanePlans(pm.egressNATPlans)
	kernelRules := cloneKernelOwnerMap(pm.kernelRules)
	kernelRanges := cloneKernelOwnerMap(pm.kernelRanges)
	kernelEgressNATs := cloneKernelOwnerMap(pm.kernelEgressNATs)
	ruleStats := cloneRuleStatsReports(pm.kernelRuleStats)
	rangeStats := cloneRangeStatsReports(pm.kernelRangeStats)
	egressNATStats := cloneEgressNATStatsReports(pm.kernelEgressNATStats)
	kernelFlowOwners := cloneKernelFlowOwnerMap(pm.kernelFlowOwners)
	return rulePlans, rangePlans, egressNATPlans, kernelRules, kernelRanges, kernelEgressNATs, ruleStats, rangeStats, egressNATStats, kernelFlowOwners, pm.kernelStatsSnapshot, pm.kernelStatsAt, pm.kernelStatsSnapshotAt
}

func cloneRuleDataplanePlans(src map[int64]ruleDataplanePlan) map[int64]ruleDataplanePlan {
	if len(src) == 0 {
		return map[int64]ruleDataplanePlan{}
	}
	dst := make(map[int64]ruleDataplanePlan, len(src))
	for id, plan := range src {
		dst[id] = plan
	}
	return dst
}

func cloneRangeDataplanePlans(src map[int64]rangeDataplanePlan) map[int64]rangeDataplanePlan {
	if len(src) == 0 {
		return map[int64]rangeDataplanePlan{}
	}
	dst := make(map[int64]rangeDataplanePlan, len(src))
	for id, plan := range src {
		dst[id] = plan
	}
	return dst
}

func cloneKernelOwnerMap(src map[int64]bool) map[int64]bool {
	if len(src) == 0 {
		return map[int64]bool{}
	}
	dst := make(map[int64]bool, len(src))
	for id, active := range src {
		dst[id] = active
	}
	return dst
}

func cloneKernelFlowOwnerMap(src map[uint32]kernelCandidateOwner) map[uint32]kernelCandidateOwner {
	if len(src) == 0 {
		return map[uint32]kernelCandidateOwner{}
	}
	dst := make(map[uint32]kernelCandidateOwner, len(src))
	for id, owner := range src {
		dst[id] = owner
	}
	return dst
}

func filterPositiveKernelOwnerIDs(src map[int64]bool) map[int64]bool {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int64]bool)
	for id, active := range src {
		if !active || id <= 0 {
			continue
		}
		dst[id] = true
	}
	if len(dst) == 0 {
		return nil
	}
	return dst
}

func buildManagedNetworkRetainedKernelDesiredByOwner(
	rules []Rule,
	ranges []PortRange,
	explicitEgressNATs []EgressNAT,
	currentKernelRules map[int64]bool,
	currentKernelRanges map[int64]bool,
	currentExplicitKernelEgressNATs map[int64]bool,
	rulePlans map[int64]ruleDataplanePlan,
	rangePlans map[int64]rangeDataplanePlan,
	egressNATPlans map[int64]ruleDataplanePlan,
	retainer kernelHandoffRetentionRuntime,
) (map[kernelCandidateOwner][]kernelCandidateRule, int64, int, error) {
	desiredByOwner := make(map[kernelCandidateOwner][]kernelCandidateRule)
	maxRuleID := int64(0)
	for _, rule := range rules {
		if rule.ID > maxRuleID {
			maxRuleID = rule.ID
		}
	}

	rulesByID := make(map[int64]Rule, len(rules))
	for _, rule := range rules {
		rulesByID[rule.ID] = rule
	}
	rangesByID := make(map[int64]PortRange, len(ranges))
	for _, pr := range ranges {
		rangesByID[pr.ID] = pr
	}
	egressNATByID := make(map[int64]EgressNAT, len(explicitEgressNATs))
	for _, item := range explicitEgressNATs {
		egressNATByID[item.ID] = item
	}

	retainedEntries := 0
	appendRetainedOwner := func(owner kernelCandidateOwner, items []Rule) {
		if len(items) == 0 {
			return
		}
		candidates := make([]kernelCandidateRule, 0, len(items))
		for _, item := range items {
			candidates = append(candidates, kernelCandidateRule{owner: owner, rule: item})
			if item.ID > maxRuleID {
				maxRuleID = item.ID
			}
		}
		desiredByOwner[owner] = candidates
		retainedEntries += len(candidates)
	}

	for id, active := range currentKernelRules {
		if !active {
			continue
		}
		rule, ok := rulesByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d is no longer present", id)
		}
		if rulePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelRuleCandidates(rule)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active rule owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindRule, id: id}, retained)
	}
	for id, active := range currentKernelRanges {
		if !active {
			continue
		}
		pr, ok := rangesByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d is no longer present", id)
		}
		if rangePlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelRangeCandidates(pr)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active range owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindRange, id: id}, retained)
	}
	for id, active := range currentExplicitKernelEgressNATs {
		if !active {
			continue
		}
		item, ok := egressNATByID[id]
		if !ok {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d is no longer present", id)
		}
		if egressNATPlans[id].EffectiveEngine != ruleEngineKernel {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d changed target engine", id)
		}
		retained, ok := retainer.retainedKernelEgressNATCandidates(item)
		if !ok || len(retained) == 0 {
			return nil, 0, 0, fmt.Errorf("managed network runtime reload requires full redistribute: active egress nat owner %d cannot be retained in place", id)
		}
		appendRetainedOwner(kernelCandidateOwner{kind: workerKindEgressNAT, id: id}, retained)
	}

	return desiredByOwner, maxRuleID, retainedEntries, nil
}

func mergeManagedNetworkReloadEgressNATPlans(current map[int64]ruleDataplanePlan, autoPlans map[int64]ruleDataplanePlan) map[int64]ruleDataplanePlan {
	merged := make(map[int64]ruleDataplanePlan, len(current)+len(autoPlans))
	for id, plan := range current {
		if id < 0 {
			continue
		}
		merged[id] = plan
	}
	for id, plan := range autoPlans {
		merged[id] = plan
	}
	return merged
}

func mergeKernelCandidateGroups(base map[kernelCandidateOwner][]kernelCandidateRule, extra map[kernelCandidateOwner][]kernelCandidateRule) map[kernelCandidateOwner][]kernelCandidateRule {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	merged := make(map[kernelCandidateOwner][]kernelCandidateRule, len(base)+len(extra))
	for owner, candidates := range base {
		merged[owner] = append([]kernelCandidateRule(nil), candidates...)
	}
	for owner, candidates := range extra {
		merged[owner] = append([]kernelCandidateRule(nil), candidates...)
	}
	return merged
}

func ownerSetFromKernelCandidates(candidates []kernelCandidateRule) map[kernelCandidateOwner]struct{} {
	if len(candidates) == 0 {
		return nil
	}
	out := make(map[kernelCandidateOwner]struct{})
	for _, candidate := range candidates {
		out[candidate.owner] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildAppliedKernelOwnerState(finalActiveCandidates []kernelCandidateRule, kernelAssignments map[int64]string) (
	map[int64]string,
	map[int64]string,
	map[int64]string,
	map[int64]bool,
	map[int64]bool,
	map[int64]bool,
	map[uint32]kernelCandidateOwner,
) {
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
		switch candidate.owner.kind {
		case workerKindRule:
			kernelAppliedRules[candidate.owner.id] = true
			kernelAppliedRuleEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRuleEngines[candidate.owner.id], engine)
		case workerKindRange:
			kernelAppliedRanges[candidate.owner.id] = true
			kernelAppliedRangeEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedRangeEngines[candidate.owner.id], engine)
		case workerKindEgressNAT:
			kernelAppliedEgressNATs[candidate.owner.id] = true
			kernelAppliedEgressNATEngines[candidate.owner.id] = mergeKernelEngineName(kernelAppliedEgressNATEngines[candidate.owner.id], engine)
		}
	}
	return kernelAppliedRuleEngines, kernelAppliedRangeEngines, kernelAppliedEgressNATEngines, kernelAppliedRules, kernelAppliedRanges, kernelAppliedEgressNATs, kernelFlowOwners
}
