package app

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
)

type kernelNetlinkRecoveryTrigger struct {
	interfaceNames         map[string]struct{}
	linkIndexes            map[int]struct{}
	linkNeighborInterfaces map[string]struct{}
	linkNeighborIndexes    map[int]struct{}
	linkFDBInterfaces      map[string]struct{}
	linkFDBIndexes         map[int]struct{}
	addrFamilies           map[string]struct{}
	backendIPs             map[string]struct{}
	backendMACs            map[string]struct{}
	sources                map[string]struct{}
}

type kernelNetlinkLinkSnapshot struct {
	Name        string
	LinkType    string
	MasterIndex int
	AdminUp     bool
	LowerUp     bool
	OperState   string
}

func newKernelNetlinkRecoveryTrigger(source string) kernelNetlinkRecoveryTrigger {
	var trigger kernelNetlinkRecoveryTrigger
	trigger.addSource(source)
	return trigger
}

func (trigger *kernelNetlinkRecoveryTrigger) addSource(source string) {
	if trigger == nil {
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return
	}
	if trigger.sources == nil {
		trigger.sources = make(map[string]struct{})
	}
	trigger.sources[source] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addInterfaceName(name string) {
	if trigger == nil {
		return
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return
	}
	if trigger.interfaceNames == nil {
		trigger.interfaceNames = make(map[string]struct{})
	}
	trigger.interfaceNames[name] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addLinkIndex(index int) {
	if trigger == nil || index <= 0 {
		return
	}
	if trigger.linkIndexes == nil {
		trigger.linkIndexes = make(map[int]struct{})
	}
	trigger.linkIndexes[index] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addLinkNeighborInterface(name string) {
	if trigger == nil {
		return
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return
	}
	if trigger.linkNeighborInterfaces == nil {
		trigger.linkNeighborInterfaces = make(map[string]struct{})
	}
	trigger.linkNeighborInterfaces[name] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addLinkNeighborIndex(index int) {
	if trigger == nil || index <= 0 {
		return
	}
	if trigger.linkNeighborIndexes == nil {
		trigger.linkNeighborIndexes = make(map[int]struct{})
	}
	trigger.linkNeighborIndexes[index] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addLinkFDBInterface(name string) {
	if trigger == nil {
		return
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return
	}
	if trigger.linkFDBInterfaces == nil {
		trigger.linkFDBInterfaces = make(map[string]struct{})
	}
	trigger.linkFDBInterfaces[name] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addLinkFDBIndex(index int) {
	if trigger == nil || index <= 0 {
		return
	}
	if trigger.linkFDBIndexes == nil {
		trigger.linkFDBIndexes = make(map[int]struct{})
	}
	trigger.linkFDBIndexes[index] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addAddrFamily(family string) {
	if trigger == nil {
		return
	}
	family = strings.TrimSpace(strings.ToLower(family))
	if family != ipFamilyIPv4 && family != ipFamilyIPv6 {
		return
	}
	if trigger.addrFamilies == nil {
		trigger.addrFamilies = make(map[string]struct{})
	}
	trigger.addrFamilies[family] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addBackendIP(value string) {
	if trigger == nil {
		return
	}
	ip := normalizeKernelTransientFallbackBackendIP(value)
	if ip == "" {
		return
	}
	if trigger.backendIPs == nil {
		trigger.backendIPs = make(map[string]struct{})
	}
	trigger.backendIPs[ip] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) addBackendMAC(value string) {
	if trigger == nil {
		return
	}
	mac := normalizeKernelTransientFallbackBackendMAC(value)
	if mac == "" {
		return
	}
	if trigger.backendMACs == nil {
		trigger.backendMACs = make(map[string]struct{})
	}
	trigger.backendMACs[mac] = struct{}{}
}

func (trigger *kernelNetlinkRecoveryTrigger) merge(other kernelNetlinkRecoveryTrigger) {
	if trigger == nil {
		return
	}
	for name := range other.interfaceNames {
		trigger.addInterfaceName(name)
	}
	for index := range other.linkIndexes {
		trigger.addLinkIndex(index)
	}
	for name := range other.linkNeighborInterfaces {
		trigger.addLinkNeighborInterface(name)
	}
	for index := range other.linkNeighborIndexes {
		trigger.addLinkNeighborIndex(index)
	}
	for name := range other.linkFDBInterfaces {
		trigger.addLinkFDBInterface(name)
	}
	for index := range other.linkFDBIndexes {
		trigger.addLinkFDBIndex(index)
	}
	for family := range other.addrFamilies {
		trigger.addAddrFamily(family)
	}
	for ip := range other.backendIPs {
		trigger.addBackendIP(ip)
	}
	for mac := range other.backendMACs {
		trigger.addBackendMAC(mac)
	}
	for source := range other.sources {
		trigger.addSource(source)
	}
}

func (trigger kernelNetlinkRecoveryTrigger) clone() kernelNetlinkRecoveryTrigger {
	var out kernelNetlinkRecoveryTrigger
	out.merge(trigger)
	return out
}

func (trigger kernelNetlinkRecoveryTrigger) hasSource(source string) bool {
	if len(trigger.sources) == 0 {
		return false
	}
	_, ok := trigger.sources[strings.TrimSpace(source)]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) hasInterfaceHints() bool {
	return len(trigger.interfaceNames) > 0 || len(trigger.linkIndexes) > 0
}

func (trigger kernelNetlinkRecoveryTrigger) matchesOutInterface(name string) bool {
	if !trigger.hasInterfaceHints() {
		return true
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return true
	}
	_, ok := trigger.interfaceNames[name]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) hasLinkNeighborHints() bool {
	return len(trigger.linkNeighborInterfaces) > 0 || len(trigger.linkNeighborIndexes) > 0
}

func (trigger kernelNetlinkRecoveryTrigger) matchesLinkNeighborInterface(name string) bool {
	if !trigger.hasLinkNeighborHints() {
		return trigger.matchesOutInterface(name)
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return true
	}
	_, ok := trigger.linkNeighborInterfaces[name]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) hasLinkFDBHints() bool {
	return len(trigger.linkFDBInterfaces) > 0 || len(trigger.linkFDBIndexes) > 0
}

func (trigger kernelNetlinkRecoveryTrigger) matchesLinkFDBInterface(name string) bool {
	if !trigger.hasLinkFDBHints() {
		return trigger.matchesOutInterface(name)
	}
	name = normalizeKernelTransientFallbackInterface(name)
	if name == "" {
		return true
	}
	_, ok := trigger.linkFDBInterfaces[name]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) matchesBackendIP(ip string) bool {
	if len(trigger.backendIPs) == 0 {
		return true
	}
	ip = normalizeKernelTransientFallbackBackendIP(ip)
	if ip == "" {
		return true
	}
	_, ok := trigger.backendIPs[ip]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) matchesBackendMAC(mac string) bool {
	if len(trigger.backendMACs) == 0 {
		return true
	}
	mac = normalizeKernelTransientFallbackBackendMAC(mac)
	if mac == "" {
		return false
	}
	_, ok := trigger.backendMACs[mac]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) matchesAddrFamily(family string) bool {
	if len(trigger.addrFamilies) == 0 {
		return true
	}
	family = strings.TrimSpace(strings.ToLower(family))
	if family == "" {
		return true
	}
	_, ok := trigger.addrFamilies[family]
	return ok
}

func (trigger kernelNetlinkRecoveryTrigger) matchesPlan(plan ruleDataplanePlan) bool {
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
		return trigger.matchesOutInterface(plan.TransientFallback.OutInterface) &&
			trigger.matchesBackendIP(plan.TransientFallback.BackendIP)
	}
	if trigger.hasSource("fdb") && reasonClass == "fdb_missing" {
		return trigger.matchesOutInterface(plan.TransientFallback.OutInterface) &&
			trigger.matchesBackendMAC(plan.TransientFallback.BackendMAC)
	}
	return len(trigger.sources) == 0
}

func kernelNetlinkLinkSnapshotChanged(prev kernelNetlinkLinkSnapshot, next kernelNetlinkLinkSnapshot) bool {
	return prev.Name != next.Name ||
		prev.LinkType != next.LinkType ||
		prev.MasterIndex != next.MasterIndex ||
		prev.AdminUp != next.AdminUp ||
		prev.LowerUp != next.LowerUp ||
		prev.OperState != next.OperState
}

func applyKernelNetlinkLinkStateUpdate(states map[int]kernelNetlinkLinkSnapshot, index int, snapshot kernelNetlinkLinkSnapshot, deleted bool) bool {
	if index <= 0 {
		return true
	}
	if states == nil {
		return true
	}
	prev, hadPrev := states[index]
	if deleted {
		delete(states, index)
		return true
	}
	states[index] = snapshot
	if !hadPrev {
		return true
	}
	return kernelNetlinkLinkSnapshotChanged(prev, snapshot)
}

func isNetlinkTriggeredKernelFallbackReason(reason string) bool {
	switch normalizeTransientKernelFallbackReason(reason) {
	case "neighbor_missing", "fdb_missing":
		return true
	default:
		return false
	}
}

func (pm *ProcessManager) summarizeNetlinkTriggeredKernelFallbacksLocked() string {
	ruleCount := 0
	rangeCount := 0
	reasonCounts := make(map[string]int)

	for _, plan := range pm.rulePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if !isNetlinkTriggeredKernelFallbackReason(plan.FallbackReason) {
			continue
		}
		ruleCount++
		reasonCounts[normalizeTransientKernelFallbackReason(plan.FallbackReason)]++
	}
	for _, plan := range pm.rangePlans {
		if plan.EffectiveEngine == ruleEngineKernel || !plan.KernelEligible {
			continue
		}
		if !isNetlinkTriggeredKernelFallbackReason(plan.FallbackReason) {
			continue
		}
		rangeCount++
		reasonCounts[normalizeTransientKernelFallbackReason(plan.FallbackReason)]++
	}
	if ruleCount == 0 && rangeCount == 0 {
		return ""
	}

	reasons := make([]string, 0, len(reasonCounts))
	for reason, count := range reasonCounts {
		reasons = append(reasons, fmt.Sprintf("%s=%d", reason, count))
	}
	sort.Strings(reasons)
	return fmt.Sprintf("rules=%d ranges=%d reasons=%s", ruleCount, rangeCount, strings.Join(reasons, ","))
}

func (pm *ProcessManager) summarizeActiveKernelLinkRecoveryLocked() string {
	if pm == nil {
		return ""
	}

	ruleCount := 0
	rangeCount := 0
	egressNATCount := 0
	for _, ok := range pm.kernelRules {
		if ok {
			ruleCount++
		}
	}
	for _, ok := range pm.kernelRanges {
		if ok {
			rangeCount++
		}
	}
	for _, ok := range pm.kernelEgressNATs {
		if ok {
			egressNATCount++
		}
	}
	total := ruleCount + rangeCount + egressNATCount
	if total == 0 {
		return ""
	}
	return fmt.Sprintf("active_kernel_entries=%d(rule_owners=%d range_owners=%d egress_nat_owners=%d)", total, ruleCount, rangeCount, egressNATCount)
}

func (pm *ProcessManager) summarizeKernelAddrRefreshLocked(trigger kernelNetlinkRecoveryTrigger) string {
	if pm == nil || !trigger.hasSource("addr") {
		return ""
	}

	activeRuleOwners := 0
	fallbackRuleOwners := 0
	for id, plan := range pm.rulePlans {
		if !triggerMatchesAddrRefreshPlan(trigger, plan) {
			continue
		}
		if pm.kernelRules[id] {
			activeRuleOwners++
			continue
		}
		if isAddrTriggeredKernelFallbackPlan(plan) {
			fallbackRuleOwners++
		}
	}

	activeRangeOwners := 0
	fallbackRangeOwners := 0
	for id, plan := range pm.rangePlans {
		if !triggerMatchesAddrRefreshPlan(trigger, plan) {
			continue
		}
		if pm.kernelRanges[id] {
			activeRangeOwners++
			continue
		}
		if isAddrTriggeredKernelFallbackPlan(plan) {
			fallbackRangeOwners++
		}
	}

	activeEgressNATOwners := 0
	fallbackEgressNATOwners := 0
	for id, plan := range pm.egressNATPlans {
		if id <= 0 || !triggerMatchesAddrRefreshPlan(trigger, plan) {
			continue
		}
		if pm.kernelEgressNATs[id] {
			activeEgressNATOwners++
			continue
		}
		if isAddrTriggeredKernelFallbackPlan(plan) {
			fallbackEgressNATOwners++
		}
	}

	if activeRuleOwners == 0 && fallbackRuleOwners == 0 &&
		activeRangeOwners == 0 && fallbackRangeOwners == 0 &&
		activeEgressNATOwners == 0 && fallbackEgressNATOwners == 0 {
		return ""
	}

	parts := make([]string, 0, 6)
	if activeRuleOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_active_rule_owners=%d", activeRuleOwners))
	}
	if fallbackRuleOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_fallback_rule_owners=%d", fallbackRuleOwners))
	}
	if activeRangeOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_active_range_owners=%d", activeRangeOwners))
	}
	if fallbackRangeOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_fallback_range_owners=%d", fallbackRangeOwners))
	}
	if activeEgressNATOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_active_egress_nat_owners=%d", activeEgressNATOwners))
	}
	if fallbackEgressNATOwners > 0 {
		parts = append(parts, fmt.Sprintf("addr_fallback_egress_nat_owners=%d", fallbackEgressNATOwners))
	}
	return strings.Join(parts, " ")
}

func nextKernelNetlinkRetryState(lastRetryAt time.Time, now time.Time, summary string) (bool, time.Time) {
	if strings.TrimSpace(summary) == "" {
		return false, lastRetryAt
	}
	if now.IsZero() {
		now = time.Now()
	}
	if lastRetryAt.IsZero() || now.Sub(lastRetryAt) >= kernelNetlinkRetryDebounce {
		return true, now
	}
	return false, lastRetryAt
}

func mergeKernelNetlinkRecoverySummaries(parts ...string) string {
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		items = append(items, part)
	}
	return strings.Join(items, "; ")
}

func mergeKernelNetlinkRecoverySources(existing string, next string) string {
	existing = strings.TrimSpace(existing)
	next = strings.TrimSpace(next)
	if existing == "" {
		return next
	}
	if next == "" || existing == next {
		return existing
	}
	for _, part := range strings.Split(existing, ",") {
		if strings.TrimSpace(part) == next {
			return existing
		}
	}
	return existing + "," + next
}

func summarizeKernelNetlinkRecoveryStringHints(label string, values map[string]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	items := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		items = append(items, value)
	}
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	if len(items) > 3 {
		items = append(items[:3], fmt.Sprintf("+%d", len(items)-3))
	}
	return fmt.Sprintf("%s=%s", label, strings.Join(items, ","))
}

func summarizeKernelNetlinkRecoveryIndexHints(label string, values map[int]struct{}) string {
	if len(values) == 0 {
		return ""
	}
	items := make([]int, 0, len(values))
	for value := range values {
		if value <= 0 {
			continue
		}
		items = append(items, value)
	}
	if len(items) == 0 {
		return ""
	}
	sort.Ints(items)
	labels := make([]string, 0, min(len(items), 4))
	limit := len(items)
	if limit > 3 {
		limit = 3
	}
	for _, value := range items[:limit] {
		labels = append(labels, fmt.Sprintf("%d", value))
	}
	if len(items) > limit {
		labels = append(labels, fmt.Sprintf("+%d", len(items)-limit))
	}
	return fmt.Sprintf("%s=%s", label, strings.Join(labels, ","))
}

func summarizeDynamicEgressNATParentInterfaces(parents map[string]struct{}) string {
	if len(parents) == 0 {
		return ""
	}
	return summarizeKernelNetlinkRecoveryStringHints("egress_nat_parents", parents)
}

func cloneKernelStringHintSet(values map[string]struct{}) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for value := range values {
		value = normalizeKernelTransientFallbackInterface(value)
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func kernelNetlinkTriggerHasLinkHints(trigger kernelNetlinkRecoveryTrigger) bool {
	return len(trigger.interfaceNames) > 0 ||
		len(trigger.linkIndexes) > 0 ||
		len(trigger.linkNeighborInterfaces) > 0 ||
		len(trigger.linkNeighborIndexes) > 0 ||
		len(trigger.linkFDBInterfaces) > 0 ||
		len(trigger.linkFDBIndexes) > 0
}

func kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger kernelNetlinkRecoveryTrigger, parents map[string]struct{}) map[string]struct{} {
	if len(parents) == 0 {
		return nil
	}

	normalizedParents := cloneKernelStringHintSet(parents)
	if len(normalizedParents) == 0 {
		return nil
	}

	normalizedTrigger := normalizeKernelNetlinkRecoveryTrigger(trigger)
	matches := make(map[string]struct{})
	for _, hints := range []map[string]struct{}{
		normalizedTrigger.interfaceNames,
		normalizedTrigger.linkNeighborInterfaces,
		normalizedTrigger.linkFDBInterfaces,
	} {
		for name := range hints {
			name = normalizeKernelTransientFallbackInterface(name)
			if _, ok := normalizedParents[name]; ok {
				matches[name] = struct{}{}
			}
		}
	}
	if len(matches) > 0 {
		return matches
	}

	if !kernelNetlinkTriggerHasLinkHints(trigger) {
		return normalizedParents
	}

	// Link delete/update notifications can arrive with only ifindex hints, and the
	// master relationship may already be gone by the time we attempt resolution.
	if len(trigger.linkIndexes) > 0 && len(normalizedTrigger.interfaceNames) == 0 {
		return normalizedParents
	}
	if len(trigger.linkNeighborIndexes) > 0 && len(normalizedTrigger.linkNeighborInterfaces) == 0 {
		return normalizedParents
	}
	if len(trigger.linkFDBIndexes) > 0 && len(normalizedTrigger.linkFDBInterfaces) == 0 {
		return normalizedParents
	}

	return nil
}

func summarizeKernelNetlinkRecoveryTrigger(trigger kernelNetlinkRecoveryTrigger) string {
	parts := make([]string, 0, 8)
	for _, part := range []string{
		summarizeKernelNetlinkRecoveryStringHints("if", trigger.interfaceNames),
		summarizeKernelNetlinkRecoveryIndexHints("ifindex", trigger.linkIndexes),
		summarizeKernelNetlinkRecoveryStringHints("neigh_if", trigger.linkNeighborInterfaces),
		summarizeKernelNetlinkRecoveryIndexHints("neigh_ifindex", trigger.linkNeighborIndexes),
		summarizeKernelNetlinkRecoveryStringHints("fdb_if", trigger.linkFDBInterfaces),
		summarizeKernelNetlinkRecoveryIndexHints("fdb_ifindex", trigger.linkFDBIndexes),
		summarizeKernelNetlinkRecoveryStringHints("family", trigger.addrFamilies),
		summarizeKernelNetlinkRecoveryStringHints("backend_ip", trigger.backendIPs),
		summarizeKernelNetlinkRecoveryStringHints("backend_mac", trigger.backendMACs),
	} {
		if part == "" {
			continue
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

func (pm *ProcessManager) queueKernelNetlinkRecoveryLocked(source string, summary string, trigger kernelNetlinkRecoveryTrigger, requestedAt time.Time) chan struct{} {
	if pm == nil || pm.kernelNetlinkRecoverWake == nil {
		return nil
	}
	pm.kernelNetlinkRecoverPending = true
	pm.kernelNetlinkRecoverSource = mergeKernelNetlinkRecoverySources(pm.kernelNetlinkRecoverSource, source)
	pm.kernelNetlinkRecoverTrigger.merge(trigger)
	if trimmedSummary := strings.TrimSpace(summary); trimmedSummary != "" {
		pm.kernelNetlinkRecoverSummary = trimmedSummary
	}
	if pm.kernelNetlinkRecoverRequestedAt.IsZero() || (!requestedAt.IsZero() && requestedAt.Before(pm.kernelNetlinkRecoverRequestedAt)) {
		pm.kernelNetlinkRecoverRequestedAt = requestedAt
	}
	return pm.kernelNetlinkRecoverWake
}

func (pm *ProcessManager) takePendingKernelNetlinkRecovery() (source string, summary string, trigger kernelNetlinkRecoveryTrigger, requestedAt time.Time, ok bool) {
	if pm == nil {
		return "", "", kernelNetlinkRecoveryTrigger{}, time.Time{}, false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.kernelNetlinkRecoverPending {
		return "", "", kernelNetlinkRecoveryTrigger{}, time.Time{}, false
	}
	source = strings.TrimSpace(pm.kernelNetlinkRecoverSource)
	summary = strings.TrimSpace(pm.kernelNetlinkRecoverSummary)
	trigger = pm.kernelNetlinkRecoverTrigger.clone()
	requestedAt = pm.kernelNetlinkRecoverRequestedAt
	pm.kernelNetlinkRecoverPending = false
	pm.kernelNetlinkRecoverSource = ""
	pm.kernelNetlinkRecoverSummary = ""
	pm.kernelNetlinkRecoverTrigger = kernelNetlinkRecoveryTrigger{}
	pm.kernelNetlinkRecoverRequestedAt = time.Time{}
	return source, summary, trigger, requestedAt, true
}

func (pm *ProcessManager) runKernelNetlinkRecoveryLoop(stop <-chan struct{}, wake <-chan struct{}) {
	if pm == nil || wake == nil {
		return
	}
	for {
		select {
		case <-stop:
			return
		case _, ok := <-wake:
			if !ok {
				return
			}
		}

		for {
			source, summary, trigger, requestedAt, ok := pm.takePendingKernelNetlinkRecovery()
			if !ok {
				break
			}
			pm.runKernelNetlinkRecovery(source, summary, trigger, requestedAt)
			select {
			case <-stop:
				return
			default:
			}
		}
	}
}

func (pm *ProcessManager) runKernelNetlinkRecovery(source string, summary string, trigger kernelNetlinkRecoveryTrigger, requestedAt time.Time) {
	if pm == nil {
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "netlink"
	}
	summary = strings.TrimSpace(summary)

	result := pm.retryNetlinkTriggeredKernelFallbackOwnersForTrigger(trigger)
	pm.observeKernelIncrementalRetry(requestedAt, result)

	summarySuffix := ""
	if summary != "" {
		summarySuffix = fmt.Sprintf(" (%s)", summary)
	}
	if result.handled {
		if result.detail != "" && shouldLogKernelNetlinkRecoveryResult(result) {
			log.Printf("kernel dataplane retry: %s change observed, %s%s", source, result.detail, summarySuffix)
		}
		return
	}
	if result.detail != "" {
		log.Printf("kernel dataplane retry: %s change observed, incremental recovery unavailable: %s; falling back to full re-evaluation%s", source, result.detail, summarySuffix)
	} else {
		log.Printf("kernel dataplane retry: %s change observed, incremental recovery unavailable; falling back to full re-evaluation%s", source, summarySuffix)
	}
	pm.requestRedistributeWorkers(0)
}

func shouldLogKernelNetlinkRecoveryResult(result kernelIncrementalRetryResult) bool {
	if !result.handled {
		return true
	}
	if result.backoffRuleOwners > 0 || result.backoffRangeOwners > 0 || result.backoffEgressNATs > 0 {
		return true
	}
	if result.cooldownRuleOwners > 0 || result.cooldownRangeOwners > 0 || result.cooldownEgressNATs > 0 {
		return true
	}
	return result.recoveredRuleOwners == 0 && result.recoveredRangeOwners == 0 && result.recoveredEgressNATs == 0
}

func (pm *ProcessManager) handleKernelNetlinkRecoveryEvent(source string) {
	pm.handleKernelNetlinkRecoveryTrigger(newKernelNetlinkRecoveryTrigger(source))
}

func (pm *ProcessManager) handleKernelNetlinkRecoveryTrigger(trigger kernelNetlinkRecoveryTrigger) {
	if pm == nil {
		return
	}

	now := time.Now()
	summary := ""
	shouldRetry := false
	var wake chan struct{}
	source := triggerSourceLabel(trigger)

	pm.mu.Lock()
	pm.kernelAttachmentCheckAt = time.Time{}
	if pm.kernelRuntime != nil {
		if !trigger.hasSource("addr") || len(trigger.sources) > 1 {
			summary = pm.summarizeNetlinkTriggeredKernelFallbacksLocked()
		}
		if trigger.hasSource("addr") {
			summary = mergeKernelNetlinkRecoverySummaries(summary, pm.summarizeKernelAddrRefreshLocked(trigger))
		}
		if trigger.hasSource("link") {
			// Parent-scope egress NAT depends on live child-interface inventory. Link
			// changes on tracked parents should enter the incremental recovery queue so
			// only the affected egress owners are refreshed in place.
			dynamicParents := kernelNetlinkTriggerMatchesDynamicEgressNATParents(trigger, pm.dynamicEgressNATParents)
			dynamicSummary := summarizeDynamicEgressNATParentInterfaces(dynamicParents)
			if dynamicSummary != "" {
				summary = mergeKernelNetlinkRecoverySummaries(summary, dynamicSummary)
			}
			if activeSummary := pm.summarizeActiveKernelLinkRecoveryLocked(); activeSummary != "" {
				summary = mergeKernelNetlinkRecoverySummaries(summary, activeSummary)
			}
		}
		shouldRetry, pm.kernelNetlinkRetryAt = nextKernelNetlinkRetryState(pm.kernelNetlinkRetryAt, now, summary)
		if shouldRetry {
			pm.kernelRetryAt = now
			pm.kernelRetryCount++
			pm.lastKernelRetryAt = now
			pm.lastKernelRetryReason = summary
			wake = pm.queueKernelNetlinkRecoveryLocked(source, summary, trigger, now)
		}
	}
	pm.mu.Unlock()

	if shouldRetry {
		if wake != nil {
			select {
			case wake <- struct{}{}:
			default:
			}
			return
		}
		pm.runKernelNetlinkRecovery(source, summary, trigger, now)
	}
}

func triggerSourceLabel(trigger kernelNetlinkRecoveryTrigger) string {
	if len(trigger.sources) == 0 {
		return ""
	}
	parts := make([]string, 0, len(trigger.sources))
	for source := range trigger.sources {
		parts = append(parts, source)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (pm *ProcessManager) observeKernelIncrementalRetry(now time.Time, result kernelIncrementalRetryResult) {
	if pm == nil || !result.attempted {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}

	pm.mu.Lock()
	pm.kernelIncrementalRetryCount++
	pm.lastKernelIncrementalRetryAt = now
	pm.lastKernelIncrementalRetryResult = result.detail
	pm.lastKernelIncrementalRetryMatchedRuleOwners = result.matchedRuleOwners
	pm.lastKernelIncrementalRetryMatchedRangeOwners = result.matchedRangeOwners
	pm.lastKernelIncrementalRetryAttemptedRuleOwners = result.attemptedRuleOwners
	pm.lastKernelIncrementalRetryAttemptedRangeOwners = result.attemptedRangeOwners
	pm.lastKernelIncrementalRetryRetainedRuleOwners = result.retainedRuleOwners
	pm.lastKernelIncrementalRetryRetainedRangeOwners = result.retainedRangeOwners
	pm.lastKernelIncrementalRetryRecoveredRuleOwners = result.recoveredRuleOwners
	pm.lastKernelIncrementalRetryRecoveredRangeOwners = result.recoveredRangeOwners
	pm.lastKernelIncrementalRetryCooldownRuleOwners = result.cooldownRuleOwners
	pm.lastKernelIncrementalRetryCooldownRangeOwners = result.cooldownRangeOwners
	pm.lastKernelIncrementalRetryCooldownSummary = result.cooldownSummary
	pm.lastKernelIncrementalRetryCooldownScope = result.cooldownScope
	pm.lastKernelIncrementalRetryBackoffRuleOwners = result.backoffRuleOwners
	pm.lastKernelIncrementalRetryBackoffRangeOwners = result.backoffRangeOwners
	pm.lastKernelIncrementalRetryBackoffSummary = result.backoffSummary
	pm.lastKernelIncrementalRetryBackoffScope = result.backoffScope
	pm.lastKernelIncrementalRetryBackoffMaxFailures = result.backoffMaxFailures
	pm.lastKernelIncrementalRetryBackoffMaxDelay = result.backoffMaxDuration
	if !result.handled {
		pm.kernelIncrementalRetryFallbackCount++
	}
	pm.mu.Unlock()
}
