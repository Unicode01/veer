package app

import (
	"sort"
	"strings"
	"time"
)

const (
	networkInterfaceMissingGrace = 10 * time.Second
	networkInventoryRetryDelay   = 1 * time.Second
)

type networkInterfaceMissingState struct {
	Info              InterfaceInfo
	FirstMissingAt    time.Time
	FullConfirmations int
}

func cloneInterfaceInfo(info InterfaceInfo) InterfaceInfo {
	info.Addrs = append([]string(nil), info.Addrs...)
	return info
}

func cloneInterfaceInfoMap(src map[string]InterfaceInfo) map[string]InterfaceInfo {
	if len(src) == 0 {
		return make(map[string]InterfaceInfo)
	}
	dst := make(map[string]InterfaceInfo, len(src))
	for name, info := range src {
		dst[name] = cloneInterfaceInfo(info)
	}
	return dst
}

func interfaceInfoMapToSortedSlice(src map[string]InterfaceInfo) []InterfaceInfo {
	if len(src) == 0 {
		return nil
	}
	out := make([]InterfaceInfo, 0, len(src))
	for _, info := range src {
		out = append(out, cloneInterfaceInfo(info))
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i].Name, out[j].Name) < 0
	})
	return out
}

func networkInterfaceTopologyTemporarilyMissing(previous, current InterfaceInfo) bool {
	return strings.TrimSpace(previous.Parent) != "" && strings.TrimSpace(current.Parent) == ""
}

func (pm *ProcessManager) stabilizeNetworkInterfaceSnapshot(snapshot egressNATInterfaceSnapshot) egressNATInterfaceSnapshot {
	return pm.stabilizeNetworkInterfaceSnapshotAt(snapshot, time.Now())
}

func (pm *ProcessManager) stabilizeNetworkInterfaceSnapshotAt(snapshot egressNATInterfaceSnapshot, now time.Time) egressNATInterfaceSnapshot {
	if pm == nil {
		return snapshot
	}
	if now.IsZero() {
		now = time.Now()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.stableInterfaceInfos == nil {
		pm.stableInterfaceInfos = make(map[string]InterfaceInfo)
	}
	if pm.missingInterfaceStates == nil {
		pm.missingInterfaceStates = make(map[string]networkInterfaceMissingState)
	}

	if snapshot.Err != nil {
		if !pm.shuttingDown {
			dueAt := now.Add(networkInventoryRetryDelay)
			if pm.networkInventoryStableRecheckAt.IsZero() || dueAt.Before(pm.networkInventoryStableRecheckAt) {
				pm.networkInventoryStableRecheckAt = dueAt
			}
		}
		return newEgressNATInterfaceSnapshot(interfaceInfoMapToSortedSlice(pm.stableInterfaceInfos), nil)
	}

	current := make(map[string]InterfaceInfo, len(snapshot.Infos))
	for _, raw := range snapshot.Infos {
		info := cloneInterfaceInfo(raw)
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		info.Name = name
		current[name] = info
	}

	for name, info := range current {
		previous, hadPrevious := pm.stableInterfaceInfos[name]
		if hadPrevious && networkInterfaceTopologyTemporarilyMissing(previous, info) {
			pm.noteNetworkInterfaceMissingLocked(name, previous, now)
			continue
		}
		pm.stableInterfaceInfos[name] = info
		delete(pm.missingInterfaceStates, name)
	}

	for name, previous := range cloneInterfaceInfoMap(pm.stableInterfaceInfos) {
		if _, ok := current[name]; ok {
			continue
		}
		pm.noteNetworkInterfaceMissingLocked(name, previous, now)
	}

	for name, state := range pm.missingInterfaceStates {
		if now.Sub(state.FirstMissingAt) < networkInterfaceMissingGrace || state.FullConfirmations < 2 {
			continue
		}
		delete(pm.missingInterfaceStates, name)
		if currentInfo, ok := current[name]; ok {
			pm.stableInterfaceInfos[name] = currentInfo
		} else {
			delete(pm.stableInterfaceInfos, name)
		}
	}

	pm.scheduleNetworkInventoryStableRecheckLocked(now)
	return newEgressNATInterfaceSnapshot(interfaceInfoMapToSortedSlice(pm.stableInterfaceInfos), nil)
}

func (pm *ProcessManager) noteNetworkInterfaceMissingLocked(name string, info InterfaceInfo, now time.Time) {
	state, ok := pm.missingInterfaceStates[name]
	if !ok {
		state = networkInterfaceMissingState{
			Info:              cloneInterfaceInfo(info),
			FirstMissingAt:    now,
			FullConfirmations: 1,
		}
	} else {
		state.FullConfirmations++
	}
	pm.missingInterfaceStates[name] = state
	pm.stableInterfaceInfos[name] = cloneInterfaceInfo(state.Info)
}

func (pm *ProcessManager) scheduleNetworkInventoryStableRecheckLocked(now time.Time) {
	if pm.shuttingDown || len(pm.missingInterfaceStates) == 0 {
		pm.networkInventoryStableRecheckAt = time.Time{}
		return
	}
	var dueAt time.Time
	for _, state := range pm.missingInterfaceStates {
		candidate := state.FirstMissingAt.Add(networkInterfaceMissingGrace)
		if !candidate.After(now) {
			candidate = now.Add(networkInventoryRetryDelay)
		}
		if dueAt.IsZero() || candidate.Before(dueAt) {
			dueAt = candidate
		}
	}
	pm.networkInventoryStableRecheckAt = dueAt
}

func (pm *ProcessManager) takeNetworkInventoryStableRecheck(now time.Time) bool {
	if pm == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.shuttingDown || pm.networkInventoryStableRecheckAt.IsZero() || now.Before(pm.networkInventoryStableRecheckAt) {
		return false
	}
	pm.networkInventoryStableRecheckAt = time.Time{}
	return true
}
