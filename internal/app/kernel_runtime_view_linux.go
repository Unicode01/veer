//go:build linux

package app

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const (
	kernelRuntimeMapCountCacheTTL       = 2 * time.Second
	kernelRuntimeInterfaceLabelCacheTTL = 30 * time.Second
)

type kernelRuntimeMapCountSnapshot struct {
	sampledAt    time.Time
	rulesEntries int
	flowsEntries int
	natEntries   int
}

type kernelRuntimeMapRefs struct {
	rules *ebpf.Map
	flows *ebpf.Map
	nat   *ebpf.Map
}

type kernelRuntimeInterfaceLabelCacheEntry struct {
	label     string
	sampledAt time.Time
}

var kernelRuntimeInterfaceLabelCache sync.Map

func (pm *ProcessManager) snapshotKernelRuntime() KernelRuntimeResponse {
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
	resp.LastStatsSnapshotAt = pm.kernelStatsSnapshotAt
	resp.LastStatsSnapshotMs = pm.kernelStatsLastDuration.Milliseconds()
	resp.LastStatsSnapshotError = pm.kernelStatsLastError
	pm.mu.Unlock()

	resp.Engines = snapshotKernelRuntimeEngines(pm.kernelRuntime)
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
	switch current := rt.(type) {
	case *orderedKernelRuleRuntime:
		return current.snapshotKernelRuntimeEngines()
	case *linuxKernelRuleRuntime:
		return []KernelEngineRuntimeView{current.snapshotRuntimeView()}
	case *xdpKernelRuleRuntime:
		return []KernelEngineRuntimeView{current.snapshotRuntimeView()}
	default:
		return []KernelEngineRuntimeView{}
	}
}

func (rt *orderedKernelRuleRuntime) snapshotKernelRuntimeEngines() []KernelEngineRuntimeView {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	views := make([]KernelEngineRuntimeView, 0, len(entries))
	for _, entry := range entries {
		views = append(views, snapshotKernelEngineRuntimeView(entry.name, entry.rt))
	}
	return views
}

func snapshotKernelEngineRuntimeView(name string, rt kernelRuleRuntime) KernelEngineRuntimeView {
	switch current := rt.(type) {
	case *linuxKernelRuleRuntime:
		view := current.snapshotRuntimeView()
		if view.Name == "" {
			view.Name = name
		}
		return view
	case *xdpKernelRuleRuntime:
		view := current.snapshotRuntimeView()
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

func applyKernelRuntimePressureView(view *KernelEngineRuntimeView, pressure kernelRuntimePressureState) {
	if view == nil || !pressure.level.active() {
		return
	}
	view.PressureActive = true
	view.PressureLevel = string(pressure.level)
	view.PressureReason = pressure.reason
}

func (rt *linuxKernelRuleRuntime) snapshotRuntimeView() KernelEngineRuntimeView {
	now := time.Now()
	rt.mu.Lock()
	available, reason := rt.currentAvailabilityLocked(now)
	pressure := rt.pressureState
	actualCapacities := rt.currentMapCapacitiesLocked()
	degraded := tcKernelRuntimeDegradedState(len(rt.preparedRules), actualCapacities, rt.rulesMapLimit, rt.flowsMapLimit, rt.natMapLimit, rt.degradedSource)
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
	forwardProgramID := 0
	replyProgramID := 0
	coll := rt.coll
	if coll != nil {
		forwardProgramID = int(kernelProgramID(coll.Programs[kernelForwardProgramName]))
		replyProgramID = int(kernelProgramID(coll.Programs[kernelReplyProgramName]))
	}
	mapRefs := kernelRuntimeMapRefsFromCollection(coll)
	cachedCounts := rt.runtimeMapCounts
	rt.mu.Unlock()

	view.Attachments = len(attachments)
	view.AttachmentSummary = describeKernelAttachments(attachments)
	forwardIfRules, replyIfRules := preparedKernelInterfaceRuleSets(preparedRules)
	view.AttachmentsHealthy = len(preparedRules) == 0 || kernelAttachmentsHealthy(forwardIfRules, replyIfRules, attachments, forwardProgramID, replyProgramID)
	rt.mu.Lock()
	rt.observability.observeAttachmentsHealthy(view.AttachmentsHealthy, now)
	applyKernelRuntimeObservabilityView(&view, rt.observability.snapshot())
	rt.mu.Unlock()

	counts := cachedCounts
	if !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, mapRefs, cachedCounts, countTCRuleMapEntries, true)
		rt.updateRuntimeMapCountCache(mapRefs, counts)
	}
	applyKernelRuntimeMapCounts(&view, counts, true)
	if coll != nil {
		applyKernelRuntimeDiagView(&view, snapshotKernelRuntimeDiag(coll))
	}

	return view
}

func (rt *xdpKernelRuleRuntime) snapshotRuntimeView() KernelEngineRuntimeView {
	now := time.Now()
	rt.mu.Lock()
	available, reason := rt.currentAvailabilityLocked(now)
	pressure := rt.pressureState
	actualCapacities := rt.currentMapCapacitiesLocked()
	degraded := xdpKernelRuntimeDegradedState(len(rt.preparedRules), actualCapacities, rt.rulesMapLimit, rt.flowsMapLimit, rt.degradedSource)
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
	applyKernelRuntimePressureView(&view, pressure)
	applyKernelRuntimeObservabilityView(&view, obs)
	preparedRules := append([]preparedXDPKernelRule(nil), rt.preparedRules...)
	attachments := append([]xdpAttachment(nil), rt.attachments...)
	programID := rt.programID
	mapRefs := kernelRuntimeMapRefsFromCollection(rt.coll)
	cachedCounts := rt.runtimeMapCounts
	rt.mu.Unlock()

	view.Attachments = len(attachments)
	view.AttachmentSummary = describeXDPAttachments(attachments)
	requiredIfIndices := collectXDPInterfaces(preparedRules)
	view.AttachmentsHealthy = len(preparedRules) == 0 || xdpAttachmentsHealthy(requiredIfIndices, attachments, programID)
	rt.mu.Lock()
	rt.observability.observeAttachmentsHealthy(view.AttachmentsHealthy, now)
	applyKernelRuntimeObservabilityView(&view, rt.observability.snapshot())
	rt.mu.Unlock()

	counts := cachedCounts
	if !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, mapRefs, cachedCounts, countXDPRuleMapEntries, false)
		rt.updateRuntimeMapCountCache(mapRefs, counts)
	}
	applyKernelRuntimeMapCounts(&view, counts, false)

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
	case handle == netlink.MakeHandle(0, kernelReplyFilterHandle) || priority == kernelReplyFilterPrio:
		return "reply"
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

func expectedKernelAttachments(forwardIfRules map[int][]int64, replyIfRules map[int][]int64, forwardProgramID int, replyProgramID int) []kernelAttachmentExpectation {
	expected := make([]kernelAttachmentExpectation, 0, len(forwardIfRules)+len(replyIfRules))
	for ifindex := range forwardIfRules {
		expected = append(expected, kernelAttachmentExpectation{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  kernelForwardFilterPrio,
				handle:    netlink.MakeHandle(0, kernelForwardFilterHandle),
			},
			name:      kernelForwardProgramName,
			programID: forwardProgramID,
		})
	}
	for ifindex := range replyIfRules {
		expected = append(expected, kernelAttachmentExpectation{
			key: kernelAttachmentKey{
				linkIndex: ifindex,
				parent:    netlink.HANDLE_MIN_INGRESS,
				priority:  kernelReplyFilterPrio,
				handle:    netlink.MakeHandle(0, kernelReplyFilterHandle),
			},
			name:      kernelReplyProgramName,
			programID: replyProgramID,
		})
	}
	return expected
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

func countKernelFlowMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func countKernelNATMapEntries(m *ebpf.Map) (int, error) {
	if m == nil {
		return 0, nil
	}
	iter := m.Iterate()
	count := 0
	var key tcNATPortKeyV4
	var value uint32
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

func (s kernelRuntimeMapCountSnapshot) fresh(now time.Time) bool {
	return !s.sampledAt.IsZero() && now.Sub(s.sampledAt) < kernelRuntimeMapCountCacheTTL
}

func kernelRuntimeMapRefsFromCollection(coll *ebpf.Collection) kernelRuntimeMapRefs {
	if coll == nil || coll.Maps == nil {
		return kernelRuntimeMapRefs{}
	}
	return kernelRuntimeMapRefs{
		rules: coll.Maps[kernelRulesMapName],
		flows: coll.Maps[kernelFlowsMapName],
		nat:   coll.Maps[kernelNatPortsMapName],
	}
}

func kernelRuntimeMapRefsEqual(a, b kernelRuntimeMapRefs) bool {
	return a.rules == b.rules && a.flows == b.flows && a.nat == b.nat
}

func countKernelRuntimeMapEntries(now time.Time, refs kernelRuntimeMapRefs, cached kernelRuntimeMapCountSnapshot, countRules func(*ebpf.Map) (int, error), includeNAT bool) kernelRuntimeMapCountSnapshot {
	counts := cached
	counts.sampledAt = now

	if refs.rules == nil {
		counts.rulesEntries = 0
	} else if count, err := countRules(refs.rules); err == nil {
		counts.rulesEntries = count
	}

	if refs.flows == nil {
		counts.flowsEntries = 0
	} else if count, err := countKernelFlowMapEntries(refs.flows); err == nil {
		counts.flowsEntries = count
	}

	if includeNAT {
		if refs.nat == nil {
			counts.natEntries = 0
		} else if count, err := countKernelNATMapEntries(refs.nat); err == nil {
			counts.natEntries = count
		}
	} else {
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

func kernelAttachmentsHealthy(forwardIfRules map[int][]int64, replyIfRules map[int][]int64, attachments []kernelAttachment, forwardProgramID int, replyProgramID int) bool {
	expected := expectedKernelAttachments(forwardIfRules, replyIfRules, forwardProgramID, replyProgramID)
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
