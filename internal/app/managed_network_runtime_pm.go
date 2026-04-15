package app

import (
	"strings"
	"time"
)

func (pm *ProcessManager) shouldReloadManagedNetworkRuntimeForInterface(name string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	hasManagedRuntime := len(pm.managedNetworkInterfaces) > 0
	hasIPv6Runtime := pm.ipv6AssignmentsConfigured
	if !hasManagedRuntime && !hasIPv6Runtime {
		return false
	}

	name = strings.TrimSpace(name)
	if isManagedNetworkDynamicGuestLink(name) {
		return true
	}
	if name == "" {
		return true
	}
	if _, ok := pm.managedNetworkInterfaces[name]; ok {
		return true
	}
	_, ok := pm.ipv6AssignmentInterfaces[name]
	return ok
}

func normalizeManagedNetworkRuntimeReloadSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "manual"
	}
	return source
}

func managedNetworkRuntimeReloadSourceLabel(source string) string {
	switch normalizeManagedNetworkRuntimeReloadSource(source) {
	case "link_change":
		return "link change"
	case "addr_change":
		return "address change"
	case "drift_check":
		return "state drift"
	case "manual":
		return "manual request"
	default:
		return strings.ReplaceAll(normalizeManagedNetworkRuntimeReloadSource(source), "_", " ")
	}
}

func managedNetworkRuntimeReloadPostApplySuppressFor(source string) time.Duration {
	if normalizeManagedNetworkRuntimeReloadSource(source) == "link_change" {
		return managedNetworkLinkChangeSuppressFor
	}
	return 0
}

func managedNetworkRuntimeReloadSourceHonorsSuppression(source string) bool {
	switch normalizeManagedNetworkRuntimeReloadSource(source) {
	case "link_change", "addr_change":
		return true
	default:
		return false
	}
}

func (pm *ProcessManager) shouldAutoRepairManagedNetworkRuntimeReload(source string) bool {
	if pm == nil {
		return false
	}
	if normalizeManagedNetworkRuntimeReloadSource(source) != "link_change" {
		return false
	}
	if pm.cfg == nil {
		return true
	}
	return pm.cfg.ManagedNetworkAutoRepairEnabled()
}

func (pm *ProcessManager) snapshotManagedNetworkRuntimeReloadStatus() ManagedNetworkRuntimeReloadStatus {
	if pm == nil {
		return ManagedNetworkRuntimeReloadStatus{}
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	return ManagedNetworkRuntimeReloadStatus{
		Pending:            pm.managedRuntimeReloadPending,
		DueAt:              pm.managedRuntimeReloadDueAt,
		LastRequestedAt:    pm.managedRuntimeReloadLastRequestedAt,
		LastRequestSource:  pm.managedRuntimeReloadLastRequestSource,
		LastRequestSummary: pm.managedRuntimeReloadLastRequestSummary,
		LastStartedAt:      pm.managedRuntimeReloadLastStartedAt,
		LastCompletedAt:    pm.managedRuntimeReloadLastCompletedAt,
		LastResult:         pm.managedRuntimeReloadLastResult,
		LastAppliedSummary: pm.managedRuntimeReloadLastAppliedSummary,
		LastError:          pm.managedRuntimeReloadLastError,
	}
}

func uniqueManagedNetworkRuntimeInterfaceNames(names ...string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func managedNetworkRuntimeInterfaceNamesFromSet(items map[string]struct{}) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for name := range items {
		out = append(out, name)
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(out...)
}

func (pm *ProcessManager) suppressManagedNetworkRuntimeReloadForInterfaces(duration time.Duration, names ...string) {
	if pm == nil || duration <= 0 {
		return
	}
	names = uniqueManagedNetworkRuntimeInterfaceNames(names...)
	if len(names) == 0 {
		return
	}

	now := time.Now()
	until := now.Add(duration)

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.managedRuntimeReloadSuppressUntil == nil {
		pm.managedRuntimeReloadSuppressUntil = make(map[string]time.Time)
	}
	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}
	for _, name := range names {
		if current := pm.managedRuntimeReloadSuppressUntil[name]; current.Before(until) {
			pm.managedRuntimeReloadSuppressUntil[name] = until
		}
	}
}

func (pm *ProcessManager) filterSuppressedManagedNetworkRuntimeInterfaces(names ...string) []string {
	if pm == nil {
		return uniqueManagedNetworkRuntimeInterfaceNames(names...)
	}
	names = uniqueManagedNetworkRuntimeInterfaceNames(names...)
	if len(names) == 0 {
		return nil
	}

	now := time.Now()
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		if until, ok := pm.managedRuntimeReloadSuppressUntil[name]; ok && until.After(now) {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (pm *ProcessManager) filterSuppressedManagedNetworkRuntimeInterfaceSetLocked(items map[string]struct{}, now time.Time) map[string]struct{} {
	if pm == nil {
		return cloneManagedNetworkInterfaceSet(items)
	}
	if len(items) == 0 {
		return nil
	}
	for name, expiry := range pm.managedRuntimeReloadSuppressUntil {
		if !expiry.After(now) {
			delete(pm.managedRuntimeReloadSuppressUntil, name)
		}
	}
	filtered := make(map[string]struct{}, len(items))
	for name := range items {
		if until, ok := pm.managedRuntimeReloadSuppressUntil[name]; ok && until.After(now) {
			continue
		}
		filtered[name] = struct{}{}
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func (pm *ProcessManager) requestManagedNetworkRuntimeReloadForRelevantInterfaces(source string, names ...string) bool {
	if pm == nil {
		return false
	}
	rawNames := uniqueManagedNetworkRuntimeInterfaceNames(names...)
	uniqueNames := pm.filterSuppressedManagedNetworkRuntimeInterfaces(rawNames...)
	for _, candidate := range uniqueNames {
		if pm.shouldReloadManagedNetworkRuntimeForInterface(candidate) {
			pm.requestManagedNetworkRuntimeReloadWithSource(managedNetworkReloadDebounce, source, uniqueNames...)
			return true
		}
	}
	if len(rawNames) > 0 {
		return false
	}
	if pm.shouldReloadManagedNetworkRuntimeForInterface("") {
		pm.requestManagedNetworkRuntimeReloadWithSource(managedNetworkReloadDebounce, source)
		return true
	}
	return false
}
