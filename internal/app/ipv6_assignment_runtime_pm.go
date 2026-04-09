package app

import "strings"

func (pm *ProcessManager) shouldRedistributeIPv6AssignmentsForInterface(name string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.ipv6AssignmentsConfigured {
		return false
	}
	name = strings.TrimSpace(name)
	if isManagedNetworkDynamicGuestLink(name) {
		return true
	}
	if name == "" || len(pm.ipv6AssignmentInterfaces) == 0 {
		return true
	}
	_, ok := pm.ipv6AssignmentInterfaces[name]
	return ok
}

func isManagedNetworkDynamicGuestLink(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	_, _, ok := parseManagedNetworkProxmoxGuestPort(name)
	if ok {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), "tap")
}

func (pm *ProcessManager) snapshotIPv6AssignmentRuntimeStats() map[int64]ipv6AssignmentRuntimeStats {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	rt := pm.ipv6Runtime
	pm.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.SnapshotStats()
}

func (pm *ProcessManager) snapshotManagedNetworkRuntimeStatus() map[int64]managedNetworkRuntimeStatus {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	rt := pm.managedNetworkRuntime
	pm.mu.Unlock()
	if rt == nil {
		return nil
	}
	return rt.SnapshotStatus()
}
