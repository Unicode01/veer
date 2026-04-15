//go:build linux

package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	kernelRuntimeMapCountCacheTTL       = 2 * time.Second
	kernelRuntimeMapDetailCacheTTL      = 10 * time.Second
	kernelRuntimeInterfaceLabelCacheTTL = 30 * time.Second
	kernelRuntimeMapCountBatchSize      = 4096
)

type kernelRuntimeMapCountSnapshot struct {
	sampledAt       time.Time
	detailSampledAt time.Time
	rulesEntries    int
	rulesEntriesV4  int
	rulesEntriesV6  int
	flowsEntries    int
	flowsEntriesV4  int
	flowsEntriesV6  int
	natEntries      int
	natEntriesV4    int
	natEntriesV6    int
}

type kernelRuntimeMapRefs struct {
	rulesV4               *ebpf.Map
	rulesV6               *ebpf.Map
	flowsV4               *ebpf.Map
	flowsV6               *ebpf.Map
	flowsOldV4            *ebpf.Map
	flowsOldV6            *ebpf.Map
	natV4                 *ebpf.Map
	natV6                 *ebpf.Map
	natOldV4              *ebpf.Map
	natOldV6              *ebpf.Map
	occupancy             *ebpf.Map
	tcFlowMigrationState  *ebpf.Map
	xdpFlowMigrationState *ebpf.Map
}

type kernelRuntimeMapSnapshot struct {
	source kernelRuntimeMapRefs
	refs   kernelRuntimeMapRefs
	stats  *ebpf.Map
	diag   *ebpf.Map
}

type kernelRuntimeRuleCounter func(kernelRuntimeMapRefs, int) (int, error)

type kernelRuntimeInterfaceLabelCacheEntry struct {
	label     string
	sampledAt time.Time
}

var kernelRuntimeInterfaceLabelCache sync.Map
var kernelRuntimeBatchLookupSupport sync.Map

func cloneKernelRuntimeMap(m *ebpf.Map, label string) (*ebpf.Map, error) {
	if m == nil {
		return nil, nil
	}
	cloned, err := m.Clone()
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", label, err)
	}
	return cloned, nil
}

func cloneKernelRuntimeMapRefs(refs kernelRuntimeMapRefs) (kernelRuntimeMapRefs, error) {
	cloned := kernelRuntimeMapRefs{}
	var err error
	if cloned.rulesV4, err = cloneKernelRuntimeMap(refs.rulesV4, kernelRulesMapNameV4); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.rulesV6, err = cloneKernelRuntimeMap(refs.rulesV6, kernelRulesMapNameV6); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.flowsV4, err = cloneKernelRuntimeMap(refs.flowsV4, kernelFlowsMapNameV4); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.flowsV6, err = cloneKernelRuntimeMap(refs.flowsV6, kernelFlowsMapNameV6); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.flowsOldV4, err = cloneKernelRuntimeMap(refs.flowsOldV4, kernelTCFlowsOldMapNameV4); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.flowsOldV6, err = cloneKernelRuntimeMap(refs.flowsOldV6, kernelTCFlowsOldMapNameV6); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.natV4, err = cloneKernelRuntimeMap(refs.natV4, kernelNatPortsMapNameV4); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.natV6, err = cloneKernelRuntimeMap(refs.natV6, kernelNatPortsMapNameV6); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.natOldV4, err = cloneKernelRuntimeMap(refs.natOldV4, kernelTCNatPortsOldMapNameV4); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.natOldV6, err = cloneKernelRuntimeMap(refs.natOldV6, kernelTCNatPortsOldMapNameV6); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.occupancy, err = cloneKernelRuntimeMap(refs.occupancy, kernelOccupancyMapName); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.tcFlowMigrationState, err = cloneKernelRuntimeMap(refs.tcFlowMigrationState, kernelTCFlowMigrationStateMapName); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	if cloned.xdpFlowMigrationState, err = cloneKernelRuntimeMap(refs.xdpFlowMigrationState, kernelXDPFlowMigrationStateMapName); err != nil {
		closeKernelRuntimeMapRefs(cloned)
		return kernelRuntimeMapRefs{}, err
	}
	return cloned, nil
}

func closeKernelRuntimeMapRefs(refs kernelRuntimeMapRefs) {
	for _, m := range []*ebpf.Map{
		refs.rulesV4,
		refs.rulesV6,
		refs.flowsV4,
		refs.flowsV6,
		refs.flowsOldV4,
		refs.flowsOldV6,
		refs.natV4,
		refs.natV6,
		refs.natOldV4,
		refs.natOldV6,
		refs.occupancy,
		refs.tcFlowMigrationState,
		refs.xdpFlowMigrationState,
	} {
		if m != nil {
			_ = m.Close()
		}
	}
}

func snapshotKernelRuntimeMaps(coll *ebpf.Collection, cloneStats bool, cloneDiag bool) (kernelRuntimeMapSnapshot, error) {
	snapshot := kernelRuntimeMapSnapshot{
		source: kernelRuntimeMapRefsFromCollection(coll),
	}
	var err error
	if snapshot.refs, err = cloneKernelRuntimeMapRefs(snapshot.source); err != nil {
		snapshot.Close()
		return kernelRuntimeMapSnapshot{}, err
	}
	if cloneStats {
		if snapshot.stats, err = cloneKernelRuntimeMap(snapshotCollectionMap(coll, kernelStatsMapName), kernelStatsMapName); err != nil {
			snapshot.Close()
			return kernelRuntimeMapSnapshot{}, err
		}
	}
	if cloneDiag {
		if snapshot.diag, err = cloneKernelRuntimeMap(snapshotCollectionMap(coll, kernelDiagMapName), kernelDiagMapName); err != nil {
			snapshot.Close()
			return kernelRuntimeMapSnapshot{}, err
		}
	}
	return snapshot, nil
}

func snapshotCollectionMap(coll *ebpf.Collection, name string) *ebpf.Map {
	if coll == nil || coll.Maps == nil {
		return nil
	}
	return coll.Maps[name]
}

func (snapshot kernelRuntimeMapSnapshot) Close() {
	closeKernelRuntimeMapRefs(snapshot.refs)
	if snapshot.stats != nil {
		_ = snapshot.stats.Close()
	}
	if snapshot.diag != nil {
		_ = snapshot.diag.Close()
	}
}

func (pm *ProcessManager) snapshotKernelRuntime() KernelRuntimeResponse {
	return pm.snapshotKernelRuntimeWithForce(false)
}

func (pm *ProcessManager) snapshotKernelRuntimeWithForce(force bool) KernelRuntimeResponse {
	resp := KernelRuntimeResponse{
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
	if pm.kernelRuntime != nil {
		resp.Available, resp.AvailableReason = pm.kernelRuntime.Available()
	}

	now := time.Now()
	pm.mu.Lock()
	resp.ActiveRuleCount = len(pm.kernelRules)
	resp.ActiveRangeCount = len(pm.kernelRanges)
	resp.KernelFallbackRuleCount, resp.TransientFallbackRuleCount = countRulePlanFallbacks(pm.rulePlans)
	resp.KernelFallbackRangeCount, resp.TransientFallbackRangeCount = countRangePlanFallbacks(pm.rangePlans)
	resp.TransientFallbackSummary = pm.summarizeTransientKernelFallbacksLocked()
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
	resp.DismissedNoteKeys = pm.snapshotKernelRuntimeDismissedNoteKeysLocked()
	resp.LastStatsSnapshotAt = pm.kernelStatsSnapshotAt
	resp.LastStatsSnapshotMs = pm.kernelStatsLastDuration.Milliseconds()
	resp.LastStatsSnapshotError = pm.kernelStatsLastError
	pm.mu.Unlock()

	resp.Engines = snapshotKernelRuntimeEnginesWithForce(pm.kernelRuntime, force)
	if force {
		if available, reason, ok := kernelRuntimeAvailabilityFromViews(resp.ConfiguredOrder, resp.Engines); ok {
			resp.Available = available
			resp.AvailableReason = reason
		}
	}
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

func snapshotKernelRuntimeEngines(rt kernelRuleRuntime) []KernelEngineRuntimeView {
	return snapshotKernelRuntimeEnginesWithForce(rt, false)
}

func snapshotKernelRuntimeEnginesWithForce(rt kernelRuleRuntime, force bool) []KernelEngineRuntimeView {
	switch current := rt.(type) {
	case *orderedKernelRuleRuntime:
		return current.snapshotKernelRuntimeEnginesWithForce(force)
	case *linuxKernelRuleRuntime:
		return []KernelEngineRuntimeView{current.snapshotRuntimeViewWithForce(force)}
	case *xdpKernelRuleRuntime:
		return []KernelEngineRuntimeView{current.snapshotRuntimeViewWithForce(force)}
	default:
		return []KernelEngineRuntimeView{}
	}
}

func (rt *orderedKernelRuleRuntime) snapshotKernelRuntimeEngines() []KernelEngineRuntimeView {
	return rt.snapshotKernelRuntimeEnginesWithForce(false)
}

func (rt *orderedKernelRuleRuntime) snapshotKernelRuntimeEnginesWithForce(force bool) []KernelEngineRuntimeView {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	views := make([]KernelEngineRuntimeView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, snapshotKernelEngineRuntimeViewWithForce(entry.name, entry.rt, force))
	}
	return views
}

func snapshotKernelEngineRuntimeView(name string, rt kernelRuleRuntime) KernelEngineRuntimeView {
	return snapshotKernelEngineRuntimeViewWithForce(name, rt, false)
}

func snapshotKernelEngineRuntimeViewWithForce(name string, rt kernelRuleRuntime, force bool) KernelEngineRuntimeView {
	switch current := rt.(type) {
	case *linuxKernelRuleRuntime:
		view := current.snapshotRuntimeViewWithForce(force)
		if view.Name == "" {
			view.Name = name
		}
		return view
	case *xdpKernelRuleRuntime:
		view := current.snapshotRuntimeViewWithForce(force)
		if view.Name == "" {
			view.Name = name
		}
		return view
	default:
		available := false
		reason := ""
		if rt != nil {
			available, reason = rt.Available()
		}
		return KernelEngineRuntimeView{
			Name:            name,
			Available:       available,
			AvailableReason: reason,
		}
	}
}

func kernelRuntimeAvailabilityFromViews(order []string, views []KernelEngineRuntimeView) (bool, string, bool) {
	if len(views) == 0 {
		return false, "", false
	}

	byName := make(map[string]KernelEngineRuntimeView, len(views))
	for _, view := range views {
		name := strings.TrimSpace(view.Name)
		if name == "" {
			continue
		}
		byName[name] = view
	}

	ordered := normalizeKernelEngineOrder(order)
	if len(ordered) == 0 {
		for _, view := range views {
			if strings.TrimSpace(view.Name) != "" {
				ordered = append(ordered, view.Name)
			}
		}
	}
	if len(ordered) == 0 {
		return false, "", false
	}

	failures := make([]string, 0, len(ordered))
	for _, name := range ordered {
		view, ok := byName[name]
		if !ok {
			continue
		}
		reason := strings.TrimSpace(view.AvailableReason)
		if view.Available {
			if reason == "" {
				reason = "ready"
			}
			if len(failures) > 0 {
				return true, fmt.Sprintf("selected %s kernel engine: %s (skipped: %s)", name, reason, strings.Join(failures, "; ")), true
			}
			return true, fmt.Sprintf("selected %s kernel engine: %s", name, reason), true
		}
		if reason == "" {
			reason = "unavailable"
		}
		failures = append(failures, fmt.Sprintf("%s=%s", name, reason))
	}
	if len(failures) == 0 {
		return false, "", false
	}
	return false, "no kernel dataplane engines available: " + strings.Join(failures, "; "), true
}

func applyKernelRuntimePressureView(view *KernelEngineRuntimeView, pressure kernelRuntimePressureState) {
	if view == nil || !pressure.level.active() {
		return
	}
	view.PressureActive = true
	view.PressureLevel = string(pressure.level)
	view.PressureReason = pressure.reason
}

func overrideKernelRuntimePressureView(view *KernelEngineRuntimeView, pressure kernelRuntimePressureState) {
	if view == nil {
		return
	}
	view.PressureActive = false
	view.PressureLevel = ""
	view.PressureReason = ""
	applyKernelRuntimePressureView(view, pressure)
}

func overrideKernelRuntimeAvailabilityView(view *KernelEngineRuntimeView, runtimeAvailable bool, runtimeReason string, pressure kernelRuntimePressureState) {
	if view == nil {
		return
	}
	view.Available = runtimeAvailable
	view.AvailableReason = runtimeReason
	if runtimeAvailable && pressure.level.blocksKernelAvailability() {
		view.Available = false
		view.AvailableReason = pressure.reason
	}
}

func kernelRuntimePressureStateForRuntimeView(previousLevel kernelRuntimePressureLevel, refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, includeNAT bool) kernelRuntimePressureState {
	return buildKernelRuntimePressureStateFromDetailedCounts(previousLevel, refs, counts, includeNAT)
}

func (rt *linuxKernelRuleRuntime) snapshotRuntimeView() KernelEngineRuntimeView {
	return rt.snapshotRuntimeViewWithForce(false)
}

func (rt *linuxKernelRuleRuntime) snapshotRuntimeViewWithForce(force bool) KernelEngineRuntimeView {
	now := time.Now()
	rt.mu.Lock()
	available, reason := rt.currentAvailabilityLockedWithForce(now, force)
	runtimeAvailable := rt.available
	runtimeAvailableReason := rt.availableReason
	pressure := rt.pressureState
	actualCapacities := rt.currentMapCapacitiesLocked()
	counts := rt.currentRuntimeMapCountsLockedWithForce(now, force)
	degraded := tcKernelRuntimeDegradedState(
		len(rt.preparedRules),
		actualCapacities,
		counts,
		rt.rulesMapLimit,
		rt.flowsMapLimit,
		rt.natMapLimit,
		preparedKernelRulesNeedEgressNATAutoMapFloors(rt.preparedRules),
		rt.degradedSource,
	)
	rt.observability.updateDegraded(degraded.active, now)
	obs := rt.observability.snapshot()

	view := KernelEngineRuntimeView{
		Name:               kernelEngineTC,
		Available:          available,
		AvailableReason:    reason,
		Degraded:           degraded.active,
		DegradedReason:     degraded.reason,
		Loaded:             rt.coll != nil,
		ActiveEntries:      len(rt.preparedRules),
		Attachments:        len(rt.attachments),
		RulesMapCapacity:   actualCapacities.Rules,
		FlowsMapCapacity:   actualCapacities.Flows,
		NATMapCapacity:     actualCapacities.NATPorts,
		LastReconcileMode:  rt.lastReconcileMode,
		TrafficStats:       rt.enableTrafficStats,
		Diagnostics:        rt.enableDiagnostics,
		DiagnosticsVerbose: rt.enableDiagVerbose,
	}
	applyKernelRuntimePressureView(&view, pressure)
	applyKernelRuntimeObservabilityView(&view, obs)
	preparedRules := append([]preparedKernelRule(nil), rt.preparedRules...)
	attachments := append([]kernelAttachment(nil), rt.attachments...)
	coll := rt.coll
	mode := rt.attachmentMode
	expectedAttachments := expectedKernelAttachmentsForPreparedRules(coll, preparedRules, mode)
	mapSnapshot, mapErr := snapshotKernelRuntimeMaps(coll, false, true)
	rt.mu.Unlock()
	defer mapSnapshot.Close()

	view.Attachments = len(attachments)
	view.AttachmentSummary = describeKernelAttachments(attachments)
	view.AttachmentMode = tcAttachmentMode(attachments, mode)
	if len(preparedRules) == 0 {
		view.AttachmentsHealthy = true
	} else {
		view.AttachmentsHealthy = kernelExpectedAttachmentsHealthy(
			expectedAttachments,
			len(attachments),
			kernelAttachmentObservations(kernelAttachmentKeys(expectedAttachments)),
		)
	}
	rt.mu.Lock()
	rt.observability.observeAttachmentsHealthy(view.AttachmentsHealthy, now)
	applyKernelRuntimeObservabilityView(&view, rt.observability.snapshot())
	rt.mu.Unlock()

	applyKernelRuntimeMapCounts(&view, counts, true)
	if mapErr == nil {
		if !counts.detailsFresh(now) {
			counts = countTCKernelRuntimeMapEntryDetails(now, mapSnapshot.refs, counts, true)
			rt.updateRuntimeMapCountCache(mapSnapshot.source, counts)
		}
		applyKernelRuntimeMapCounts(&view, counts, true)
		applyKernelRuntimeMapBreakdown(&view, mapSnapshot.refs, counts, true)
		applyKernelRuntimeDiagView(&view, snapshotKernelRuntimeDiagFromMap(mapSnapshot.diag))
		if force {
			forcedPressure := kernelRuntimePressureStateForRuntimeView(pressure.level, mapSnapshot.refs, counts, true)
			overrideKernelRuntimePressureView(&view, forcedPressure)
			overrideKernelRuntimeAvailabilityView(&view, runtimeAvailable, runtimeAvailableReason, forcedPressure)
		}
	} else if strings.TrimSpace(view.DiagSnapshotError) == "" {
		view.DiagSnapshotError = mapErr.Error()
	}

	return view
}

func (rt *xdpKernelRuleRuntime) snapshotRuntimeView() KernelEngineRuntimeView {
	return rt.snapshotRuntimeViewWithForce(false)
}

func (rt *xdpKernelRuleRuntime) snapshotRuntimeViewWithForce(force bool) KernelEngineRuntimeView {
	now := time.Now()
	rt.mu.Lock()
	available, reason := rt.currentAvailabilityLockedWithForce(now, force)
	runtimeAvailable := rt.available
	runtimeAvailableReason := rt.availableReason
	pressure := rt.pressureState
	actualCapacities := rt.currentMapCapacitiesLocked()
	counts := rt.currentRuntimeMapCountsLockedWithForce(now, force)
	counts, useNATMaps := xdpRuntimeNATStateForDecision(rt.preparedRules, kernelRuntimeMapRefsFromCollection(rt.coll), counts, "xdp dataplane runtime view")
	degraded := xdpKernelRuntimeDegradedState(len(rt.preparedRules), actualCapacities, counts, rt.rulesMapLimit, rt.flowsMapLimit, rt.natMapLimit, useNATMaps, rt.degradedSource)
	rt.observability.updateDegraded(degraded.active, now)
	obs := rt.observability.snapshot()

	view := KernelEngineRuntimeView{
		Name:              kernelEngineXDP,
		Available:         available,
		AvailableReason:   reason,
		Degraded:          degraded.active,
		DegradedReason:    degraded.reason,
		Loaded:            rt.coll != nil,
		ActiveEntries:     len(rt.preparedRules),
		Attachments:       len(rt.attachments),
		RulesMapCapacity:  actualCapacities.Rules,
		FlowsMapCapacity:  actualCapacities.Flows,
		LastReconcileMode: rt.lastReconcileMode,
		TrafficStats:      rt.prepareOptions.enableTrafficStats,
	}
	if useNATMaps {
		view.NATMapCapacity = actualCapacities.NATPorts
	}
	applyKernelRuntimePressureView(&view, pressure)
	applyKernelRuntimeObservabilityView(&view, obs)
	preparedRules := append([]preparedXDPKernelRule(nil), rt.preparedRules...)
	attachments := append([]xdpAttachment(nil), rt.attachments...)
	programID := rt.programID
	coll := rt.coll
	mapSnapshot, mapErr := snapshotKernelRuntimeMaps(coll, false, true)
	rt.mu.Unlock()
	defer mapSnapshot.Close()

	view.Attachments = len(attachments)
	view.AttachmentSummary = describeXDPAttachments(attachments)
	view.AttachmentMode = xdpAttachmentMode(attachments)
	requiredIfIndices := collectXDPInterfaces(preparedRules)
	view.AttachmentsHealthy = len(preparedRules) == 0 || xdpAttachmentsHealthy(requiredIfIndices, attachments, programID)
	rt.mu.Lock()
	rt.observability.observeAttachmentsHealthy(view.AttachmentsHealthy, now)
	applyKernelRuntimeObservabilityView(&view, rt.observability.snapshot())
	rt.mu.Unlock()

	applyKernelRuntimeMapCounts(&view, counts, useNATMaps)
	if mapErr == nil {
		if !counts.detailsFresh(now) {
			counts = countXDPKernelRuntimeMapEntryDetails(now, mapSnapshot.refs, counts)
			rt.updateRuntimeMapCountCache(mapSnapshot.source, counts)
		}
		applyKernelRuntimeMapCounts(&view, counts, useNATMaps)
		applyKernelRuntimeMapBreakdown(&view, mapSnapshot.refs, counts, useNATMaps)
		applyKernelRuntimeDiagView(&view, snapshotKernelRuntimeDiagFromMap(mapSnapshot.diag))
		if force {
			forcedPressure := kernelRuntimePressureStateForRuntimeView(pressure.level, mapSnapshot.refs, counts, useNATMaps)
			overrideKernelRuntimePressureView(&view, forcedPressure)
			overrideKernelRuntimeAvailabilityView(&view, runtimeAvailable, runtimeAvailableReason, forcedPressure)
		}
	} else if strings.TrimSpace(view.DiagSnapshotError) == "" {
		view.DiagSnapshotError = mapErr.Error()
	}

	return view
}

func preparedKernelInterfaceRuleSets(prepared []preparedKernelRule) (map[int][]int64, map[int][]int64) {
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	for _, item := range prepared {
		forwardIfRules[item.inIfIndex] = append(forwardIfRules[item.inIfIndex], item.rule.ID)
		replyIfRules[item.outIfIndex] = append(replyIfRules[item.outIfIndex], item.rule.ID)
	}
	return forwardIfRules, replyIfRules
}

func describeKernelAttachments(attachments []kernelAttachment) string {
	if len(attachments) == 0 {
		return "none"
	}
	labels := make([]string, 0, len(attachments))
	for _, att := range attachments {
		if att.filter == nil || att.filter.Attrs() == nil {
			continue
		}
		attrs := att.filter.Attrs()
		label := fmt.Sprintf("%s/%s", kernelRuntimeInterfaceLabel(attrs.LinkIndex), kernelAttachmentProgramLabel(attrs.Handle, attrs.Priority))
		labels = append(labels, label)
	}
	if len(labels) == 0 {
		return fmt.Sprintf("%d attachment(s)", len(attachments))
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func describeXDPAttachments(attachments []xdpAttachment) string {
	if len(attachments) == 0 {
		return "none"
	}
	labels := make([]string, 0, len(attachments))
	for _, att := range attachments {
		labels = append(labels, fmt.Sprintf("%s(%s)", kernelRuntimeInterfaceLabel(att.ifindex), xdpAttachFlagsLabel(att.flags)))
	}
	sort.Strings(labels)
	return strings.Join(labels, ", ")
}

func xdpAttachmentMode(attachments []xdpAttachment) string {
	if len(attachments) == 0 {
		return ""
	}
	hasDriver := false
	hasGeneric := false
	for _, att := range attachments {
		switch att.flags {
		case nl.XDP_FLAGS_DRV_MODE:
			hasDriver = true
		case nl.XDP_FLAGS_SKB_MODE:
			hasGeneric = true
		default:
			return "mixed"
		}
	}
	switch {
	case hasDriver && hasGeneric:
		return "mixed"
	case hasDriver:
		return "driver"
	case hasGeneric:
		return "generic"
	default:
		return ""
	}
}

func tcAttachmentMode(attachments []kernelAttachment, mode kernelTCAttachmentProgramMode) string {
	if len(attachments) == 0 {
		return ""
	}
	switch mode {
	case kernelTCAttachmentProgramModeLegacy, kernelTCAttachmentProgramModeDispatchV4:
		return string(mode)
	default:
		return ""
	}
}

func kernelRuntimeInterfaceLabel(ifindex int) string {
	if ifindex <= 0 {
		return fmt.Sprintf("ifindex=%d", ifindex)
	}
	now := time.Now()
	if cached, ok := kernelRuntimeInterfaceLabelCache.Load(ifindex); ok {
		entry, ok := cached.(kernelRuntimeInterfaceLabelCacheEntry)
		if ok && now.Sub(entry.sampledAt) < kernelRuntimeInterfaceLabelCacheTTL {
			return entry.label
		}
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil || link == nil || link.Attrs() == nil {
		return fmt.Sprintf("ifindex=%d", ifindex)
	}
	label := fmt.Sprintf("%s(%d)", link.Attrs().Name, ifindex)
	kernelRuntimeInterfaceLabelCache.Store(ifindex, kernelRuntimeInterfaceLabelCacheEntry{
		label:     label,
		sampledAt: now,
	})
	return label
}

func kernelAttachmentProgramLabel(handle uint32, priority uint16) string {
	switch {
	case handle == netlink.MakeHandle(0, kernelForwardFilterHandle) || priority == kernelForwardFilterPrio:
		return "forward"
	case handle == netlink.MakeHandle(0, kernelForwardFilterHandleV6) || priority == kernelForwardFilterPrioV6:
		return "forward_v6"
	case handle == netlink.MakeHandle(0, kernelReplyFilterHandle) || priority == kernelReplyFilterPrio:
		return "reply"
	case handle == netlink.MakeHandle(0, kernelReplyFilterHandleV6) || priority == kernelReplyFilterPrioV6:
		return "reply_v6"
	default:
		return fmt.Sprintf("handle=%d", handle)
	}
}

type kernelAttachmentLookupGroup struct {
	linkIndex int
	parent    uint32
}

type kernelAttachmentExpectation struct {
	key       kernelAttachmentKey
	name      string
	programID int
}

type kernelAttachmentObservation struct {
	present      bool
	isBPF        bool
	name         string
	programID    int
	directAction bool
}

func expectedKernelAttachmentIdentity(name string, prog *ebpf.Program) kernelAttachmentExpectation {
	return kernelAttachmentExpectation{
		name:      name,
		programID: int(kernelProgramID(prog)),
	}
}

func kernelAttachmentExpectationForPlan(plan kernelAttachmentPlan) kernelAttachmentExpectation {
	item := expectedKernelAttachmentIdentity(plan.name, plan.prog)
	item.key = plan.key
	return item
}

func expectedKernelAttachments(plans []kernelAttachmentPlan) []kernelAttachmentExpectation {
	expected := make([]kernelAttachmentExpectation, 0, len(plans))
	for _, plan := range plans {
		expected = append(expected, kernelAttachmentExpectationForPlan(plan))
	}
	return expected
}

func kernelAttachmentKeys(expected []kernelAttachmentExpectation) []kernelAttachmentKey {
	keys := make([]kernelAttachmentKey, 0, len(expected))
	for _, item := range expected {
		keys = append(keys, item.key)
	}
	return keys
}

func expectedKernelAttachmentsForPreparedRules(coll *ebpf.Collection, prepared []preparedKernelRule, mode kernelTCAttachmentProgramMode) []kernelAttachmentExpectation {
	forwardIfRules, replyIfRules := preparedKernelInterfaceRuleSets(prepared)
	programs := kernelAttachmentProgramsForPreparedRules(coll, prepared, mode)
	return expectedKernelAttachments(desiredKernelAttachmentPlansDualStack(
		forwardIfRules,
		replyIfRules,
		programs.forwardProg,
		programs.replyProg,
		programs.forwardProgV6,
		programs.replyProgV6,
	))
}

func kernelAttachmentObservationMatchesExpectation(observed kernelAttachmentObservation, expected kernelAttachmentExpectation) bool {
	if !observed.present || !observed.isBPF || !observed.directAction {
		return false
	}
	if expected.programID > 0 && observed.programID > 0 && observed.programID != expected.programID {
		return false
	}
	if strings.TrimSpace(expected.name) != "" && strings.TrimSpace(observed.name) != "" && observed.name != expected.name {
		return false
	}
	return true
}

func kernelExpectedAttachmentsHealthy(expected []kernelAttachmentExpectation, attachmentCount int, observed map[kernelAttachmentKey]kernelAttachmentObservation) bool {
	if len(expected) > attachmentCount {
		return false
	}
	for _, item := range expected {
		if !kernelAttachmentObservationMatchesExpectation(observed[item.key], item) {
			return false
		}
	}
	return true
}

func kernelAttachmentObservations(keys []kernelAttachmentKey) map[kernelAttachmentKey]kernelAttachmentObservation {
	observed := make(map[kernelAttachmentKey]kernelAttachmentObservation, len(keys))
	if len(keys) == 0 {
		return observed
	}

	grouped := make(map[kernelAttachmentLookupGroup]map[kernelAttachmentKey]struct{})
	for _, key := range keys {
		group := kernelAttachmentLookupGroup{linkIndex: key.linkIndex, parent: key.parent}
		if grouped[group] == nil {
			grouped[group] = make(map[kernelAttachmentKey]struct{})
		}
		grouped[group][key] = struct{}{}
	}

	for group, expected := range grouped {
		link, err := netlink.LinkByIndex(group.linkIndex)
		if err != nil {
			continue
		}
		filters, err := netlink.FilterList(link, group.parent)
		if err != nil {
			continue
		}
		for _, filter := range filters {
			attrs := filter.Attrs()
			if attrs == nil {
				continue
			}
			key := kernelAttachmentKey{
				linkIndex: attrs.LinkIndex,
				parent:    attrs.Parent,
				priority:  attrs.Priority,
				handle:    attrs.Handle,
			}
			if _, ok := expected[key]; !ok {
				continue
			}
			item := kernelAttachmentObservation{present: true}
			if bpf, ok := filter.(*netlink.BpfFilter); ok && bpf != nil {
				item.isBPF = true
				item.name = strings.TrimSpace(bpf.Name)
				item.programID = bpf.Id
				item.directAction = bpf.DirectAction
			}
			observed[key] = item
		}
	}

	return observed
}

func kernelAttachmentPresence(keys []kernelAttachmentKey) map[kernelAttachmentKey]bool {
	present := make(map[kernelAttachmentKey]bool, len(keys))
	for key, item := range kernelAttachmentObservations(keys) {
		if item.present {
			present[key] = true
		}
	}
	return present
}

func countTCRuleMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcRuleKeyV4
	var value tcRuleValueV4
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countTCRuleMapEntriesV6(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcRuleKeyV6
	var value tcRuleValueV6
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countXDPRuleMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcRuleKeyV4
	var value xdpRuleValueV4
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countXDPRuleMapEntriesV6(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcRuleKeyV6
	var value xdpRuleValueV6
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countTCKernelRuntimeRuleEntries(refs kernelRuntimeMapRefs, _ int) (int, error) {
	total := 0
	if refs.rulesV4 != nil {
		count, err := countTCRuleMapEntries(refs.rulesV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.rulesV6 != nil {
		count, err := countTCRuleMapEntriesV6(refs.rulesV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func countXDPKernelRuntimeRuleEntries(refs kernelRuntimeMapRefs, _ int) (int, error) {
	total := 0
	if refs.rulesV4 != nil {
		count, err := countXDPRuleMapEntries(refs.rulesV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.rulesV6 != nil {
		count, err := countXDPRuleMapEntriesV6(refs.rulesV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func countXDPFlowMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	var batchErr error
	if supported, known := kernelRuntimeBatchLookupSupportForType(m.Type()); !known || supported {
		count, supported, err := countXDPFlowMapEntriesBatch(m)
		if err == nil {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), true)
			return count, nil
		}
		if !supported {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), false)
		} else {
			batchErr = err
		}
	}
	count, err := countXDPFlowMapEntriesIter(m)
	if err == nil {
		return count, nil
	}
	if batchErr != nil {
		return 0, fmt.Errorf("count xdp flow map entries: batch lookup failed: %v; iterate fallback failed: %w", batchErr, err)
	}
	return 0, err
}

func countKernelFlowMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	var batchErr error
	if supported, known := kernelRuntimeBatchLookupSupportForType(m.Type()); !known || supported {
		count, supported, err := countKernelFlowMapEntriesBatch(m)
		if err == nil {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), true)
			return count, nil
		}
		if !supported {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), false)
		} else {
			batchErr = err
		}
	}
	count, err := countKernelFlowMapEntriesIter(m)
	if err == nil {
		return count, nil
	}
	if batchErr != nil {
		return 0, fmt.Errorf("count kernel flow map entries: batch lookup failed: %v; iterate fallback failed: %w", batchErr, err)
	}
	return 0, err
}

func countKernelFlowMapEntriesV6(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	var batchErr error
	if supported, known := kernelRuntimeBatchLookupSupportForType(m.Type()); !known || supported {
		count, supported, err := countKernelFlowMapEntriesBatchV6(m)
		if err == nil {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), true)
			return count, nil
		}
		if !supported {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), false)
		} else {
			batchErr = err
		}
	}
	count, err := countKernelFlowMapEntriesIterV6(m)
	if err == nil {
		return count, nil
	}
	if batchErr != nil {
		return 0, fmt.Errorf("count kernel ipv6 flow map entries: batch lookup failed: %v; iterate fallback failed: %w", batchErr, err)
	}
	return 0, err
}

func countXDPFlowMapEntriesBatch(m *ebpf.Map) (int, bool, error) {
	cursor := ebpf.MapBatchCursor{}
	keys := make([]tcFlowKeyV4, kernelRuntimeMapCountBatchSize)
	values := make([]xdpFlowValueV4, kernelRuntimeMapCountBatchSize)
	count := 0
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if count == 0 && errors.Is(err, ebpf.ErrNotSupported) {
				return 0, false, nil
			}
			return 0, true, err
		}
		count += n
		if n == 0 || errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true, nil
		}
	}
}

func countKernelFlowMapEntriesBatch(m *ebpf.Map) (int, bool, error) {
	cursor := ebpf.MapBatchCursor{}
	keys := make([]tcFlowKeyV4, kernelRuntimeMapCountBatchSize)
	values := make([]tcFlowValueV4, kernelRuntimeMapCountBatchSize)
	count := 0
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if count == 0 && errors.Is(err, ebpf.ErrNotSupported) {
				return 0, false, nil
			}
			return 0, true, err
		}
		count += n
		if n == 0 || errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true, nil
		}
	}
}

func countKernelFlowMapEntriesBatchV6(m *ebpf.Map) (int, bool, error) {
	cursor := ebpf.MapBatchCursor{}
	keys := make([]tcFlowKeyV6, kernelRuntimeMapCountBatchSize)
	values := make([]tcFlowValueV6, kernelRuntimeMapCountBatchSize)
	count := 0
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if count == 0 && errors.Is(err, ebpf.ErrNotSupported) {
				return 0, false, nil
			}
			return 0, true, err
		}
		count += n
		if n == 0 || errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true, nil
		}
	}
}

func countXDPFlowMapEntriesIter(m *ebpf.Map) (int, error) {
	iter := m.Iterate()
	count := 0
	var key tcFlowKeyV4
	var value xdpFlowValueV4
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countKernelFlowMapEntriesIter(m *ebpf.Map) (int, error) {
	iter := m.Iterate()
	count := 0
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countKernelFlowMapEntriesIterV6(m *ebpf.Map) (int, error) {
	iter := m.Iterate()
	count := 0
	var key tcFlowKeyV6
	var value tcFlowValueV6
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countKernelNATMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	var batchErr error
	if supported, known := kernelRuntimeBatchLookupSupportForType(m.Type()); !known || supported {
		count, supported, err := countKernelNATMapEntriesBatch(m)
		if err == nil {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), true)
			return count, nil
		}
		if !supported {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), false)
		} else {
			batchErr = err
		}
	}
	count, err := countKernelNATMapEntriesIter(m)
	if err == nil {
		return count, nil
	}
	if batchErr != nil {
		return 0, fmt.Errorf("count kernel nat map entries: batch lookup failed: %v; iterate fallback failed: %w", batchErr, err)
	}
	return 0, err
}

func countKernelNATMapEntriesV6(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	var batchErr error
	if supported, known := kernelRuntimeBatchLookupSupportForType(m.Type()); !known || supported {
		count, supported, err := countKernelNATMapEntriesBatchV6(m)
		if err == nil {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), true)
			return count, nil
		}
		if !supported {
			kernelRuntimeBatchLookupSupport.Store(m.Type(), false)
		} else {
			batchErr = err
		}
	}
	count, err := countKernelNATMapEntriesIterV6(m)
	if err == nil {
		return count, nil
	}
	if batchErr != nil {
		return 0, fmt.Errorf("count kernel ipv6 nat map entries: batch lookup failed: %v; iterate fallback failed: %w", batchErr, err)
	}
	return 0, err
}

func countKernelNATMapEntriesBatch(m *ebpf.Map) (int, bool, error) {
	cursor := ebpf.MapBatchCursor{}
	keys := make([]tcNATPortKeyV4, kernelRuntimeMapCountBatchSize)
	values := make([]uint32, kernelRuntimeMapCountBatchSize)
	count := 0
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if count == 0 && errors.Is(err, ebpf.ErrNotSupported) {
				return 0, false, nil
			}
			return 0, true, err
		}
		count += n
		if n == 0 || errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true, nil
		}
	}
}

func countKernelNATMapEntriesBatchV6(m *ebpf.Map) (int, bool, error) {
	cursor := ebpf.MapBatchCursor{}
	keys := make([]tcNATPortKeyV6, kernelRuntimeMapCountBatchSize)
	values := make([]uint32, kernelRuntimeMapCountBatchSize)
	count := 0
	for {
		n, err := m.BatchLookup(&cursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if count == 0 && errors.Is(err, ebpf.ErrNotSupported) {
				return 0, false, nil
			}
			return 0, true, err
		}
		count += n
		if n == 0 || errors.Is(err, ebpf.ErrKeyNotExist) {
			return count, true, nil
		}
	}
}

func countKernelNATMapEntriesIter(m *ebpf.Map) (int, error) {
	iter := m.Iterate()
	count := 0
	var key tcNATPortKeyV4
	var value uint32
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countKernelNATMapEntriesIterV6(m *ebpf.Map) (int, error) {
	iter := m.Iterate()
	count := 0
	var key tcNATPortKeyV6
	var value uint32
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func (refs kernelRuntimeMapRefs) hasRules() bool {
	return refs.rulesV4 != nil || refs.rulesV6 != nil
}

func (refs kernelRuntimeMapRefs) hasFlows() bool {
	return refs.flowsV4 != nil || refs.flowsV6 != nil || refs.flowsOldV4 != nil || refs.flowsOldV6 != nil
}

func (refs kernelRuntimeMapRefs) hasNAT() bool {
	return refs.natV4 != nil || refs.natV6 != nil || refs.natOldV4 != nil || refs.natOldV6 != nil
}

func lookupKernelFlowMigrationStateFlags(m *ebpf.Map) (uint32, bool, error) {
	if m == nil {
		return 0, false, nil
	}
	key := uint32(0)
	var flags uint32
	if err := m.Lookup(key, &flags); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, true, nil
		}
		return 0, true, err
	}
	return flags, true, nil
}

func kernelRuntimeMapTotalCapacity(maps ...*ebpf.Map) int {
	total := 0
	for _, m := range maps {
		if m == nil {
			continue
		}
		total += int(m.MaxEntries())
	}
	return total
}

func kernelRuntimeRuleMapCapacity(refs kernelRuntimeMapRefs) int {
	return kernelRuntimeMapTotalCapacity(refs.rulesV4, refs.rulesV6)
}

func kernelRuntimeTCOldFlowMigrationFlags(refs kernelRuntimeMapRefs) uint32 {
	flags, err := tcEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
	if err == nil {
		return flags
	}
	flags, err = tcOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
	if err == nil {
		return flags
	}
	return 0
}

func kernelRuntimeXDPOldFlowMigrationFlags(refs kernelRuntimeMapRefs) uint32 {
	flags, err := xdpEffectiveOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
	if err == nil {
		return flags
	}
	flags, err = xdpOldFlowMigrationFlagsFromRuntimeMapRefs(refs)
	if err == nil {
		return flags
	}
	return 0
}

func kernelRuntimeFlowMapCapacityBreakdown(refs kernelRuntimeMapRefs) (int, int, int, int) {
	tcFlags := kernelRuntimeTCOldFlowMigrationFlags(refs)
	xdpFlags := kernelRuntimeXDPOldFlowMigrationFlags(refs)

	activeV4 := kernelRuntimeMapCapacity(refs.flowsV4)
	oldV4 := 0
	if tcFlags&tcFlowMigrationFlagV4Old != 0 || xdpFlags&xdpFlowMigrationFlagV4Old != 0 {
		oldV4 = kernelRuntimeMapCapacity(refs.flowsOldV4)
	}

	activeV6 := kernelRuntimeMapCapacity(refs.flowsV6)
	oldV6 := 0
	if tcFlags&tcFlowMigrationFlagV6Old != 0 || xdpFlags&xdpFlowMigrationFlagV6Old != 0 {
		oldV6 = kernelRuntimeMapCapacity(refs.flowsOldV6)
	}

	return activeV4, oldV4, activeV6, oldV6
}

func kernelRuntimeFlowMapCapacities(refs kernelRuntimeMapRefs) (int, int) {
	activeV4, oldV4, activeV6, oldV6 := kernelRuntimeFlowMapCapacityBreakdown(refs)
	return activeV4 + oldV4, activeV6 + oldV6
}

func kernelRuntimeNATMapCapacityBreakdown(refs kernelRuntimeMapRefs) (int, int, int, int) {
	tcFlags := kernelRuntimeTCOldFlowMigrationFlags(refs)
	xdpFlags := kernelRuntimeXDPOldFlowMigrationFlags(refs)

	activeV4 := kernelRuntimeMapCapacity(refs.natV4)
	oldV4 := 0
	if tcFlags&tcFlowMigrationFlagV4Old != 0 || xdpFlags&xdpFlowMigrationFlagV4Old != 0 {
		oldV4 = kernelRuntimeMapCapacity(refs.natOldV4)
	}

	activeV6 := kernelRuntimeMapCapacity(refs.natV6)
	oldV6 := 0
	if tcFlags&tcFlowMigrationFlagV6Old != 0 || xdpFlags&xdpFlowMigrationFlagV6Old != 0 {
		oldV6 = kernelRuntimeMapCapacity(refs.natOldV6)
	}

	return activeV4, oldV4, activeV6, oldV6
}

func kernelRuntimeNATMapCapacities(refs kernelRuntimeMapRefs) (int, int) {
	activeV4, oldV4, activeV6, oldV6 := kernelRuntimeNATMapCapacityBreakdown(refs)
	return activeV4 + oldV4, activeV6 + oldV6
}

func kernelRuntimeFlowMapCapacity(refs kernelRuntimeMapRefs) int {
	v4, v6 := kernelRuntimeFlowMapCapacities(refs)
	return v4 + v6
}

func kernelRuntimeNATMapCapacity(refs kernelRuntimeMapRefs) int {
	v4, v6 := kernelRuntimeNATMapCapacities(refs)
	return v4 + v6
}

func kernelRuntimeMapCapacity(m *ebpf.Map) int {
	if m == nil {
		return 0
	}
	return int(m.MaxEntries())
}

func firstNonNilMap(maps ...*ebpf.Map) *ebpf.Map {
	for _, m := range maps {
		if m != nil {
			return m
		}
	}
	return nil
}

func countKernelRuntimeFlowEntriesExact(refs kernelRuntimeMapRefs) (int, error) {
	total := 0
	if refs.flowsV4 != nil {
		count, err := countKernelRuntimeFlowEntriesExactV4(refs.flowsV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.flowsV6 != nil {
		count, err := countKernelFlowMapEntriesV6(refs.flowsV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.flowsOldV4 != nil {
		count, err := countKernelRuntimeFlowEntriesExactV4(refs.flowsOldV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.flowsOldV6 != nil {
		count, err := countKernelFlowMapEntriesV6(refs.flowsOldV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func countKernelRuntimeFlowEntriesExactV4(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	count, kernelErr := countKernelFlowMapEntries(m)
	if kernelErr == nil {
		return count, nil
	}
	count, xdpErr := countXDPFlowMapEntries(m)
	if xdpErr == nil {
		return count, nil
	}
	return 0, fmt.Errorf("count runtime ipv4 flow map entries: tc decode failed: %v; xdp decode failed: %w", kernelErr, xdpErr)
}

func countKernelRuntimeNATEntriesExact(refs kernelRuntimeMapRefs) (int, error) {
	total := 0
	if refs.natV4 != nil {
		count, err := countKernelNATMapEntries(refs.natV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.natV6 != nil {
		count, err := countKernelNATMapEntriesV6(refs.natV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.natOldV4 != nil {
		count, err := countKernelNATMapEntries(refs.natOldV4)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if refs.natOldV6 != nil {
		count, err := countKernelNATMapEntriesV6(refs.natOldV6)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func countTCKernelRuntimeMapEntryDetails(now time.Time, refs kernelRuntimeMapRefs, cached kernelRuntimeMapCountSnapshot, includeNAT bool) kernelRuntimeMapCountSnapshot {
	counts := cached
	exact := true

	rulesTotal := 0
	if refs.rulesV4 == nil {
		counts.rulesEntriesV4 = 0
	} else if count, err := countTCRuleMapEntries(refs.rulesV4); err == nil {
		counts.rulesEntriesV4 = count
		rulesTotal += count
	} else {
		exact = false
	}
	if refs.rulesV6 == nil {
		counts.rulesEntriesV6 = 0
	} else if count, err := countTCRuleMapEntriesV6(refs.rulesV6); err == nil {
		counts.rulesEntriesV6 = count
		rulesTotal += count
	} else {
		exact = false
	}
	if refs.hasRules() && exact {
		counts.rulesEntries = rulesTotal
	}

	flowsExact := true
	flowsTotal := 0
	if refs.flowsV4 == nil {
		counts.flowsEntriesV4 = 0
	} else if count, err := countKernelFlowMapEntries(refs.flowsV4); err == nil {
		counts.flowsEntriesV4 = count
	} else {
		flowsExact = false
		exact = false
	}
	if refs.flowsOldV4 != nil {
		if count, err := countKernelFlowMapEntries(refs.flowsOldV4); err == nil {
			counts.flowsEntriesV4 += count
		} else {
			flowsExact = false
			exact = false
		}
	}
	flowsTotal += counts.flowsEntriesV4
	if refs.flowsV6 == nil {
		counts.flowsEntriesV6 = 0
	} else if count, err := countKernelFlowMapEntriesV6(refs.flowsV6); err == nil {
		counts.flowsEntriesV6 = count
	} else {
		flowsExact = false
		exact = false
	}
	if refs.flowsOldV6 != nil {
		if count, err := countKernelFlowMapEntriesV6(refs.flowsOldV6); err == nil {
			counts.flowsEntriesV6 += count
		} else {
			flowsExact = false
			exact = false
		}
	}
	flowsTotal += counts.flowsEntriesV6
	if refs.hasFlows() && flowsExact {
		counts.flowsEntries = flowsTotal
	}

	if includeNAT {
		natExact := true
		natTotal := 0
		if refs.natV4 == nil {
			counts.natEntriesV4 = 0
		} else if count, err := countKernelNATMapEntries(refs.natV4); err == nil {
			counts.natEntriesV4 = count
			natTotal += count
		} else {
			natExact = false
			exact = false
		}
		if refs.natOldV4 != nil {
			if count, err := countKernelNATMapEntries(refs.natOldV4); err == nil {
				counts.natEntriesV4 += count
				natTotal += count
			} else {
				natExact = false
				exact = false
			}
		}
		if refs.natV6 == nil {
			counts.natEntriesV6 = 0
		} else if count, err := countKernelNATMapEntriesV6(refs.natV6); err == nil {
			counts.natEntriesV6 = count
			natTotal += count
		} else {
			natExact = false
			exact = false
		}
		if refs.natOldV6 != nil {
			if count, err := countKernelNATMapEntriesV6(refs.natOldV6); err == nil {
				counts.natEntriesV6 += count
				natTotal += count
			} else {
				natExact = false
				exact = false
			}
		}
		if refs.hasNAT() && natExact {
			counts.natEntries = natTotal
		}
	} else {
		counts.natEntries = 0
		counts.natEntriesV4 = 0
		counts.natEntriesV6 = 0
	}

	if exact {
		counts.detailSampledAt = now
	}
	return counts
}

func countXDPKernelRuntimeMapEntryDetails(now time.Time, refs kernelRuntimeMapRefs, cached kernelRuntimeMapCountSnapshot) kernelRuntimeMapCountSnapshot {
	counts := cached
	exact := true

	if refs.rulesV4 == nil {
		counts.rulesEntriesV4 = 0
	} else if count, err := countXDPRuleMapEntries(refs.rulesV4); err == nil {
		counts.rulesEntriesV4 = count
	} else {
		exact = false
	}
	if refs.rulesV6 == nil {
		counts.rulesEntriesV6 = 0
	} else if count, err := countXDPRuleMapEntriesV6(refs.rulesV6); err == nil {
		counts.rulesEntriesV6 = count
	} else {
		exact = false
	}
	if exact {
		counts.rulesEntries = counts.rulesEntriesV4 + counts.rulesEntriesV6
	}

	flowsExact := true
	flowsTotal := 0
	if refs.flowsV4 == nil {
		counts.flowsEntriesV4 = 0
	} else if count, err := countXDPFlowMapEntries(refs.flowsV4); err == nil {
		counts.flowsEntriesV4 = count
	} else {
		flowsExact = false
		exact = false
	}
	if refs.flowsOldV4 != nil {
		if count, err := countXDPFlowMapEntries(refs.flowsOldV4); err == nil {
			counts.flowsEntriesV4 += count
		} else {
			flowsExact = false
			exact = false
		}
	}
	flowsTotal += counts.flowsEntriesV4
	if refs.flowsV6 == nil {
		counts.flowsEntriesV6 = 0
	} else if count, err := countKernelFlowMapEntriesV6(refs.flowsV6); err == nil {
		counts.flowsEntriesV6 = count
	} else {
		flowsExact = false
		exact = false
	}
	if refs.flowsOldV6 != nil {
		if count, err := countKernelFlowMapEntriesV6(refs.flowsOldV6); err == nil {
			counts.flowsEntriesV6 += count
		} else {
			flowsExact = false
			exact = false
		}
	}
	flowsTotal += counts.flowsEntriesV6
	if refs.hasFlows() && flowsExact {
		counts.flowsEntries = flowsTotal
	}

	natExact := true
	natTotal := 0
	if refs.natV4 == nil {
		counts.natEntriesV4 = 0
	} else if count, err := countKernelNATMapEntries(refs.natV4); err == nil {
		counts.natEntriesV4 = count
		natTotal += count
	} else {
		natExact = false
		exact = false
	}
	if refs.natOldV4 != nil {
		if count, err := countKernelNATMapEntries(refs.natOldV4); err == nil {
			counts.natEntriesV4 += count
			natTotal += count
		} else {
			natExact = false
			exact = false
		}
	}
	if refs.natV6 == nil {
		counts.natEntriesV6 = 0
	} else if count, err := countKernelNATMapEntriesV6(refs.natV6); err == nil {
		counts.natEntriesV6 = count
		natTotal += count
	} else {
		natExact = false
		exact = false
	}
	if refs.natOldV6 != nil {
		if count, err := countKernelNATMapEntriesV6(refs.natOldV6); err == nil {
			counts.natEntriesV6 += count
			natTotal += count
		} else {
			natExact = false
			exact = false
		}
	}
	if refs.hasNAT() && natExact {
		counts.natEntries = natTotal
	}

	if exact {
		counts.detailSampledAt = now
	}
	return counts
}

func kernelRuntimeBatchLookupSupportForType(mapType ebpf.MapType) (bool, bool) {
	value, ok := kernelRuntimeBatchLookupSupport.Load(mapType)
	if !ok {
		return false, false
	}
	supported, ok := value.(bool)
	if !ok {
		return false, false
	}
	return supported, true
}

func (s kernelRuntimeMapCountSnapshot) fresh(now time.Time) bool {
	return !s.sampledAt.IsZero() && now.Sub(s.sampledAt) < kernelRuntimeMapCountCacheTTL
}

func (s kernelRuntimeMapCountSnapshot) detailsFresh(now time.Time) bool {
	return !s.detailSampledAt.IsZero() && now.Sub(s.detailSampledAt) < kernelRuntimeMapDetailCacheTTL
}

func kernelRuntimeMapRefsFromCollection(coll *ebpf.Collection) kernelRuntimeMapRefs {
	if coll == nil || coll.Maps == nil {
		return kernelRuntimeMapRefs{}
	}
	return kernelRuntimeMapRefs{
		rulesV4:               coll.Maps[kernelRulesMapNameV4],
		rulesV6:               coll.Maps[kernelRulesMapNameV6],
		flowsV4:               coll.Maps[kernelFlowsMapNameV4],
		flowsV6:               coll.Maps[kernelFlowsMapNameV6],
		flowsOldV4:            firstNonNilMap(coll.Maps[kernelTCFlowsOldMapNameV4], coll.Maps[kernelXDPFlowsOldMapNameV4]),
		flowsOldV6:            firstNonNilMap(coll.Maps[kernelTCFlowsOldMapNameV6], coll.Maps[kernelXDPFlowsOldMapNameV6]),
		natV4:                 coll.Maps[kernelNatPortsMapNameV4],
		natV6:                 coll.Maps[kernelNatPortsMapNameV6],
		natOldV4:              coll.Maps[kernelTCNatPortsOldMapNameV4],
		natOldV6:              coll.Maps[kernelTCNatPortsOldMapNameV6],
		occupancy:             coll.Maps[kernelOccupancyMapName],
		tcFlowMigrationState:  coll.Maps[kernelTCFlowMigrationStateMapName],
		xdpFlowMigrationState: coll.Maps[kernelXDPFlowMigrationStateMapName],
	}
}

func kernelRuntimeMapRefsEqual(a, b kernelRuntimeMapRefs) bool {
	return a.rulesV4 == b.rulesV4 &&
		a.rulesV6 == b.rulesV6 &&
		a.flowsV4 == b.flowsV4 &&
		a.flowsV6 == b.flowsV6 &&
		a.flowsOldV4 == b.flowsOldV4 &&
		a.flowsOldV6 == b.flowsOldV6 &&
		a.natV4 == b.natV4 &&
		a.natV6 == b.natV6 &&
		a.natOldV4 == b.natOldV4 &&
		a.natOldV6 == b.natOldV6 &&
		a.occupancy == b.occupancy &&
		a.tcFlowMigrationState == b.tcFlowMigrationState &&
		a.xdpFlowMigrationState == b.xdpFlowMigrationState
}

func (rt *linuxKernelRuleRuntime) currentRuntimeMapCountsLocked(now time.Time) kernelRuntimeMapCountSnapshot {
	return rt.currentRuntimeMapCountsLockedWithForce(now, false)
}

func (rt *linuxKernelRuleRuntime) currentRuntimeMapCountsLockedWithForce(now time.Time, force bool) kernelRuntimeMapCountSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	counts := rt.runtimeMapCounts
	if force || !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, kernelRuntimeMapRefsFromCollection(rt.coll), counts, nil, len(rt.preparedRules), true)
		rt.runtimeMapCounts = counts
	}
	return counts
}

func (rt *xdpKernelRuleRuntime) currentRuntimeMapCountsLocked(now time.Time) kernelRuntimeMapCountSnapshot {
	return rt.currentRuntimeMapCountsLockedWithForce(now, false)
}

func (rt *xdpKernelRuleRuntime) currentRuntimeMapCountsLockedWithForce(now time.Time, force bool) kernelRuntimeMapCountSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	counts := rt.runtimeMapCounts
	if force || !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, kernelRuntimeMapRefsFromCollection(rt.coll), counts, nil, len(rt.preparedRules), true)
		rt.runtimeMapCounts = counts
	}
	return counts
}

func countKernelRuntimeMapEntries(now time.Time, refs kernelRuntimeMapRefs, cached kernelRuntimeMapCountSnapshot, countRules kernelRuntimeRuleCounter, rulesEntriesHint int, includeNAT bool) kernelRuntimeMapCountSnapshot {
	counts := cached
	counts.sampledAt = now

	if !refs.hasRules() {
		counts.rulesEntries = 0
	} else if countRules == nil {
		counts.rulesEntries = max(0, rulesEntriesHint)
	} else if count, err := countRules(refs, rulesEntriesHint); err == nil {
		counts.rulesEntries = count
	}

	if !refs.hasFlows() {
		counts.flowsEntries = 0
	} else {
		usedOccupancy := false
		if refs.occupancy != nil {
			if flowEntries, natEntries, err := snapshotKernelRuntimeOccupancyEntries(refs, includeNAT); err == nil {
				counts.flowsEntries = flowEntries
				if includeNAT {
					counts.natEntries = natEntries
				} else {
					counts.natEntries = 0
				}
				usedOccupancy = true
			}
		}
		if !usedOccupancy {
			if count, err := countKernelRuntimeFlowEntriesExact(refs); err == nil {
				counts.flowsEntries = count
			}
			if includeNAT {
				if !refs.hasNAT() {
					counts.natEntries = 0
				} else if count, err := countKernelRuntimeNATEntriesExact(refs); err == nil {
					counts.natEntries = count
				}
			} else {
				counts.natEntries = 0
			}
		}
	}

	if !refs.hasFlows() && includeNAT {
		if !refs.hasNAT() {
			counts.natEntries = 0
		} else if count, err := countKernelRuntimeNATEntriesExact(refs); err == nil {
			counts.natEntries = count
		}
	} else if !includeNAT {
		counts.natEntries = 0
	}

	return counts
}

func applyKernelRuntimeMapCounts(view *KernelEngineRuntimeView, counts kernelRuntimeMapCountSnapshot, includeNAT bool) {
	if view == nil {
		return
	}
	view.RulesMapEntries = counts.rulesEntries
	view.FlowsMapEntries = counts.flowsEntries
	if includeNAT {
		view.NATMapEntries = counts.natEntries
	}
}

func applyKernelRuntimeMapBreakdown(view *KernelEngineRuntimeView, refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, includeNAT bool) {
	if view == nil {
		return
	}
	view.RulesMapEntriesV4 = counts.rulesEntriesV4
	view.RulesMapCapacityV4 = kernelRuntimeMapCapacity(refs.rulesV4)
	view.RulesMapEntriesV6 = counts.rulesEntriesV6
	view.RulesMapCapacityV6 = kernelRuntimeMapCapacity(refs.rulesV6)
	view.FlowsMapEntriesV4 = counts.flowsEntriesV4
	view.FlowsMapEntriesV6 = counts.flowsEntriesV6
	view.FlowsMapCapacityV4, view.FlowsMapOldCapacityV4, view.FlowsMapCapacityV6, view.FlowsMapOldCapacityV6 = kernelRuntimeFlowMapCapacityBreakdown(refs)
	if includeNAT {
		view.NATMapEntriesV4 = counts.natEntriesV4
		view.NATMapEntriesV6 = counts.natEntriesV6
		view.NATMapCapacityV4, view.NATMapOldCapacityV4, view.NATMapCapacityV6, view.NATMapOldCapacityV6 = kernelRuntimeNATMapCapacityBreakdown(refs)
	}
}

func kernelAttachmentsHealthy(forwardIfRules map[int][]int64, replyIfRules map[int][]int64, attachments []kernelAttachment, forwardProg *ebpf.Program, replyProg *ebpf.Program, forwardProgV6 *ebpf.Program, replyProgV6 *ebpf.Program) bool {
	expected := expectedKernelAttachments(desiredKernelAttachmentPlansDualStack(
		forwardIfRules,
		replyIfRules,
		forwardProg,
		replyProg,
		forwardProgV6,
		replyProgV6,
	))
	keys := make([]kernelAttachmentKey, 0, len(expected))
	for _, item := range expected {
		keys = append(keys, item.key)
	}
	return kernelExpectedAttachmentsHealthy(expected, len(attachments), kernelAttachmentObservations(keys))
}

func xdpAttachmentsHealthy(requiredIfIndices []int, attachments []xdpAttachment, programID uint32) bool {
	if len(requiredIfIndices) > len(attachments) {
		return false
	}
	required := make(map[int]struct{}, len(requiredIfIndices))
	for _, ifindex := range requiredIfIndices {
		required[ifindex] = struct{}{}
	}
	for _, att := range attachments {
		if _, ok := required[att.ifindex]; !ok {
			return false
		}
		if !xdpAttachmentExists(att, programID) {
			return false
		}
	}
	return true
}

func (rt *linuxKernelRuleRuntime) invalidateRuntimeMapCountCacheLocked() {
	rt.runtimeMapCounts = kernelRuntimeMapCountSnapshot{}
}

func (rt *xdpKernelRuleRuntime) invalidateRuntimeMapCountCacheLocked() {
	rt.runtimeMapCounts = kernelRuntimeMapCountSnapshot{}
}

func (rt *linuxKernelRuleRuntime) updateRuntimeMapCountCache(refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if kernelRuntimeMapRefsEqual(refs, kernelRuntimeMapRefsFromCollection(rt.coll)) {
		rt.runtimeMapCounts = counts
	}
}

func (rt *xdpKernelRuleRuntime) updateRuntimeMapCountCache(refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if kernelRuntimeMapRefsEqual(refs, kernelRuntimeMapRefsFromCollection(rt.coll)) {
		rt.runtimeMapCounts = counts
	}
}
