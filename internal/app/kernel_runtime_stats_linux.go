//go:build linux

package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	kernelFlowMaintenanceTargetPasses = 8
	kernelFlowMaintenanceBudgetMin    = 4096
	kernelFlowMaintenanceBudgetMax    = 65536
	kernelFlowMaintenanceBatchSize    = 2048
)

type staleKernelFlow struct {
	key   tcFlowKeyV4
	value tcFlowValueV4
}

type staleKernelFlowV6 struct {
	key   tcFlowKeyV6
	value tcFlowValueV6
}

func kernelFlowValueFromXDP(value xdpFlowValueV4) tcFlowValueV4 {
	return tcFlowValueV4{
		RuleID:           value.RuleID,
		FrontAddr:        value.FrontAddr,
		ClientAddr:       value.ClientAddr,
		NATAddr:          value.NATAddr,
		InIfIndex:        value.InIfIndex,
		FrontPort:        value.FrontPort,
		ClientPort:       value.ClientPort,
		NATPort:          value.NATPort,
		Flags:            value.Flags,
		LastSeenNS:       value.LastSeenNS,
		FrontCloseSeenNS: value.FrontCloseSeenNS,
		RuleRevision:     value.RuleRevision,
		SessionID:        value.SessionID,
	}
}

type kernelStatsValueV4 struct {
	TotalConns     uint64
	TCPActiveConns uint64
	UDPNatEntries  uint64
	ICMPNatEntries uint64
	BytesIn        uint64
	BytesOut       uint64
}

type kernelFlowPruneState struct {
	batchCursor       ebpf.MapBatchCursor
	batchCursorV6     ebpf.MapBatchCursor
	batchSupported    bool
	batchSupportKnown bool
	fullCursor        tcFlowKeyV4
	fullCursorV6      tcFlowKeyV6
	fullCursorValid   bool
	fullCursorValidV6 bool
	keys              []tcFlowKeyV4
	keysV6            []tcFlowKeyV6
	values            []tcFlowValueV4
	xdpValues         []xdpFlowValueV4
	valuesV6          []tcFlowValueV6
}

type kernelNATPruneState struct {
	activeV4 map[kernelNATReservationOwnerV4]struct{}
	oldV4    map[kernelNATReservationOwnerV4]struct{}
	activeV6 map[kernelNATReservationOwnerV6]struct{}
	oldV6    map[kernelNATReservationOwnerV6]struct{}
}

func (state kernelNATPruneState) clone() kernelNATPruneState {
	return kernelNATPruneState{
		activeV4: cloneKernelNATCandidates(state.activeV4),
		oldV4:    cloneKernelNATCandidates(state.oldV4),
		activeV6: cloneKernelNATCandidates(state.activeV6),
		oldV6:    cloneKernelNATCandidates(state.oldV6),
	}
}

func cloneKernelNATCandidates[K comparable](src map[K]struct{}) map[K]struct{} {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[K]struct{}, len(src))
	for key := range src {
		dst[key] = struct{}{}
	}
	return dst
}

var (
	kernelPossibleCPUsOnce sync.Once
	kernelPossibleCPUs     int
	kernelPossibleCPUsErr  error
)

func snapshotKernelStatsFromMap(statsMap *ebpf.Map, corrections map[uint32]kernelRuleStats) (kernelRuleStatsSnapshot, error) {
	snapshot := emptyKernelRuleStatsSnapshot()
	if statsMap == nil {
		return snapshot, nil
	}

	statsIter := statsMap.Iterate()
	if kernelMapHasPerCPUValue(statsMap.Type()) {
		possibleCPUs, err := kernelPossibleCPUCount()
		if err != nil {
			return emptyKernelRuleStatsSnapshot(), fmt.Errorf("resolve possible cpu count for kernel stats: %w", err)
		}
		var ruleID uint32
		values := make([]kernelStatsValueV4, possibleCPUs)
		for statsIter.Next(&ruleID, values) {
			snapshot.ByRuleID[ruleID] = kernelRuleStatsFromValue(aggregateKernelPerCPUStats(values))
		}
	} else {
		var ruleID uint32
		var value kernelStatsValueV4
		for statsIter.Next(&ruleID, &value) {
			snapshot.ByRuleID[ruleID] = kernelRuleStatsFromValue(value)
		}
	}
	if err := statsIter.Err(); err != nil {
		return emptyKernelRuleStatsSnapshot(), fmt.Errorf("iterate kernel stats map: %w", err)
	}

	applyKernelStatsCorrections(snapshot.ByRuleID, corrections)
	return snapshot, nil
}

func pruneStaleKernelFlowsMap(rulesMap, flowsMap, natPortsMap *ebpf.Map, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if flowsMap == nil {
		return map[uint32]kernelRuleStats{}, kernelFlowPruneMetrics{}, nil
	}

	nowNS, haveNow := kernelMonotonicNowNS()
	if budget <= 0 {
		budget = kernelFlowMaintenanceBudgetMin
	}
	metrics := kernelFlowPruneMetrics{Budget: budget}
	if state == nil {
		return pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if !state.batchSupportKnown || state.batchSupported {
		corrections, pruneMetrics, err := pruneStaleKernelFlowsBatch(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
		if err == nil {
			state.batchSupportKnown = true
			state.batchSupported = true
			return corrections, pruneMetrics, nil
		}
		state.reset()
		state.batchSupportKnown = true
		state.batchSupported = false
		log.Printf("kernel dataplane maintenance: batch flow scan unavailable, falling back to full scan: %v", err)
	}
	return pruneStaleKernelFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
}

func pruneStaleXDPFlowsMap(rulesMap, flowsMap, natPortsMap *ebpf.Map, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if flowsMap == nil {
		return map[uint32]kernelRuleStats{}, kernelFlowPruneMetrics{}, nil
	}

	nowNS, haveNow := kernelMonotonicNowNS()
	if budget <= 0 {
		budget = kernelFlowMaintenanceBudgetMin
	}
	metrics := kernelFlowPruneMetrics{Budget: budget}
	if state == nil {
		return pruneStaleXDPFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if !state.batchSupportKnown || state.batchSupported {
		corrections, pruneMetrics, err := pruneStaleXDPFlowsBatch(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
		if err == nil {
			state.batchSupportKnown = true
			state.batchSupported = true
			return corrections, pruneMetrics, nil
		}
		state.reset()
		state.batchSupportKnown = true
		state.batchSupported = false
		log.Printf("xdp dataplane maintenance: batch flow scan unavailable, falling back to full scan: %v", err)
	}
	return pruneStaleXDPFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
}

func applyKernelStatsCorrections(dst map[uint32]kernelRuleStats, corrections map[uint32]kernelRuleStats) {
	if len(corrections) == 0 {
		return
	}
	for ruleID, delta := range corrections {
		current := dst[ruleID]
		current.TCPActiveConns = clampKernelStatDelta(current.TCPActiveConns, delta.TCPActiveConns)
		current.UDPNatEntries = clampKernelStatDelta(current.UDPNatEntries, delta.UDPNatEntries)
		current.ICMPNatEntries = clampKernelStatDelta(current.ICMPNatEntries, delta.ICMPNatEntries)
		current.TotalConns = clampKernelStatDelta(current.TotalConns, delta.TotalConns)
		current.BytesIn = clampKernelStatDelta(current.BytesIn, delta.BytesIn)
		current.BytesOut = clampKernelStatDelta(current.BytesOut, delta.BytesOut)
		dst[ruleID] = current
	}
}

func clampKernelStatDelta(current int64, delta int64) int64 {
	next := current + delta
	if next < 0 {
		return 0
	}
	return next
}

func mergeKernelStatsCorrections(dst map[uint32]kernelRuleStats, delta map[uint32]kernelRuleStats) {
	if len(delta) == 0 {
		return
	}
	for ruleID, item := range delta {
		current := dst[ruleID]
		current.TCPActiveConns += item.TCPActiveConns
		current.UDPNatEntries += item.UDPNatEntries
		current.ICMPNatEntries += item.ICMPNatEntries
		current.TotalConns += item.TotalConns
		current.BytesIn += item.BytesIn
		current.BytesOut += item.BytesOut
		dst[ruleID] = current
	}
}

func cloneKernelStatsCorrections(src map[uint32]kernelRuleStats) map[uint32]kernelRuleStats {
	if len(src) == 0 {
		return map[uint32]kernelRuleStats{}
	}
	dst := make(map[uint32]kernelRuleStats, len(src))
	for ruleID, item := range src {
		dst[ruleID] = item
	}
	return dst
}

func snapshotKernelStatsValues(statsMap *ebpf.Map) (map[uint32]kernelStatsValueV4, error) {
	out := make(map[uint32]kernelStatsValueV4)
	if statsMap == nil {
		return out, nil
	}

	iter := statsMap.Iterate()
	if kernelMapHasPerCPUValue(statsMap.Type()) {
		possibleCPUs, err := kernelPossibleCPUCount()
		if err != nil {
			return nil, fmt.Errorf("resolve possible cpu count for kernel stats snapshot: %w", err)
		}
		var ruleID uint32
		values := make([]kernelStatsValueV4, possibleCPUs)
		for iter.Next(&ruleID, values) {
			out[ruleID] = aggregateKernelPerCPUStats(values)
		}
	} else {
		var ruleID uint32
		var value kernelStatsValueV4
		for iter.Next(&ruleID, &value) {
			out[ruleID] = value
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate kernel stats map: %w", err)
	}
	return out, nil
}

func lookupKernelStatsValue(statsMap *ebpf.Map, ruleID uint32) (kernelStatsValueV4, bool, error) {
	if statsMap == nil {
		return kernelStatsValueV4{}, false, nil
	}
	if kernelMapHasPerCPUValue(statsMap.Type()) {
		possibleCPUs, err := kernelPossibleCPUCount()
		if err != nil {
			return kernelStatsValueV4{}, false, fmt.Errorf("resolve possible cpu count for kernel stats lookup: %w", err)
		}
		values := make([]kernelStatsValueV4, possibleCPUs)
		if err := statsMap.Lookup(&ruleID, values); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return kernelStatsValueV4{}, false, nil
			}
			return kernelStatsValueV4{}, false, fmt.Errorf("lookup kernel stats for rule %d: %w", ruleID, err)
		}
		return aggregateKernelPerCPUStats(values), true, nil
	}

	var value kernelStatsValueV4
	if err := statsMap.Lookup(&ruleID, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return kernelStatsValueV4{}, false, nil
		}
		return kernelStatsValueV4{}, false, fmt.Errorf("lookup kernel stats for rule %d: %w", ruleID, err)
	}
	return value, true, nil
}

func copyKernelStatsMap(dst *ebpf.Map, src *ebpf.Map) error {
	if dst == nil || src == nil {
		return nil
	}

	iter := src.Iterate()
	srcPerCPU := kernelMapHasPerCPUValue(src.Type())
	dstPerCPU := kernelMapHasPerCPUValue(dst.Type())
	if srcPerCPU || dstPerCPU {
		possibleCPUs, err := kernelPossibleCPUCount()
		if err != nil {
			return fmt.Errorf("resolve possible cpu count for kernel stats copy: %w", err)
		}
		if srcPerCPU {
			var ruleID uint32
			values := make([]kernelStatsValueV4, possibleCPUs)
			for iter.Next(&ruleID, values) {
				if dstPerCPU {
					if err := dst.Put(ruleID, values); err != nil {
						return fmt.Errorf("copy kernel stats for rule %d: %w", ruleID, err)
					}
					continue
				}
				if err := dst.Put(ruleID, aggregateKernelPerCPUStats(values)); err != nil {
					return fmt.Errorf("copy kernel stats for rule %d: %w", ruleID, err)
				}
			}
		} else {
			var ruleID uint32
			var value kernelStatsValueV4
			perCPUValue := make([]kernelStatsValueV4, possibleCPUs)
			for iter.Next(&ruleID, &value) {
				if !dstPerCPU {
					if err := dst.Put(ruleID, value); err != nil {
						return fmt.Errorf("copy kernel stats for rule %d: %w", ruleID, err)
					}
					continue
				}
				clearKernelStatsValues(perCPUValue)
				perCPUValue[0] = value
				if err := dst.Put(ruleID, perCPUValue); err != nil {
					return fmt.Errorf("copy kernel stats for rule %d: %w", ruleID, err)
				}
			}
		}
	} else {
		var ruleID uint32
		var value kernelStatsValueV4
		for iter.Next(&ruleID, &value) {
			if err := dst.Put(ruleID, value); err != nil {
				return fmt.Errorf("copy kernel stats for rule %d: %w", ruleID, err)
			}
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate source kernel stats map: %w", err)
	}
	return nil
}

func mergeKernelLiveStateSnapshot(dst *kernelFlowLiveStateSnapshot, src kernelFlowLiveStateSnapshot) {
	if dst == nil {
		return
	}
	dst.FlowEntries += src.FlowEntries
	for ruleID, value := range src.ByRuleID {
		current := dst.ByRuleID[ruleID]
		current.TotalConns += value.TotalConns
		current.TCPActiveConns += value.TCPActiveConns
		current.UDPNatEntries += value.UDPNatEntries
		current.ICMPNatEntries += value.ICMPNatEntries
		current.BytesIn += value.BytesIn
		current.BytesOut += value.BytesOut
		dst.ByRuleID[ruleID] = current
	}
	if dst.UsedNATV4 != nil {
		for owner := range src.UsedNATV4 {
			dst.UsedNATV4[owner] = struct{}{}
		}
	}
	if dst.UsedNATV6 != nil {
		for owner := range src.UsedNATV6 {
			dst.UsedNATV6[owner] = struct{}{}
		}
	}
}

func snapshotKernelLiveStateFromRuntimeMapRefs(refs kernelRuntimeMapRefs, includeNAT bool) (kernelFlowLiveStateSnapshot, error) {
	// Runtime snapshots retain owners by bank; avoid also keeping a duplicate aggregate owner set.
	out := newKernelFlowLiveStateSnapshot(false)
	if refs.flowsV4 != nil {
		live, err := snapshotKernelLiveStateFromFlows(refs.rulesV4, refs.flowsV4, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.activeV4 = live.UsedNATV4
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsOldV4 != nil {
		live, err := snapshotKernelLiveStateFromFlows(refs.rulesV4, refs.flowsOldV4, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.oldV4 = live.UsedNATV4
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsV6 != nil {
		live, err := snapshotKernelLiveStateFromFlowsV6(refs.rulesV6, refs.flowsV6, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.activeV6 = live.UsedNATV6
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsOldV6 != nil {
		live, err := snapshotKernelLiveStateFromFlowsV6(refs.rulesV6, refs.flowsOldV6, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.oldV6 = live.UsedNATV6
		mergeKernelLiveStateSnapshot(&out, live)
	}
	return out, nil
}

func snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs kernelRuntimeMapRefs, includeNAT bool) (kernelFlowLiveStateSnapshot, error) {
	// Runtime snapshots retain owners by bank; avoid also keeping a duplicate aggregate owner set.
	out := newKernelFlowLiveStateSnapshot(false)
	if refs.flowsV4 != nil {
		live, err := snapshotXDPKernelLiveStateFromFlows(refs.rulesV4, refs.flowsV4, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.activeV4 = live.UsedNATV4
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsOldV4 != nil {
		live, err := snapshotXDPKernelLiveStateFromFlows(refs.rulesV4, refs.flowsOldV4, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.oldV4 = live.UsedNATV4
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsV6 != nil {
		live, err := snapshotKernelLiveStateFromFlowsV6(refs.rulesV6, refs.flowsV6, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.activeV6 = live.UsedNATV6
		mergeKernelLiveStateSnapshot(&out, live)
	}
	if refs.flowsOldV6 != nil {
		live, err := snapshotKernelLiveStateFromFlowsV6(refs.rulesV6, refs.flowsOldV6, includeNAT)
		if err != nil {
			return kernelFlowLiveStateSnapshot{}, err
		}
		out.NATByBank.oldV6 = live.UsedNATV6
		mergeKernelLiveStateSnapshot(&out, live)
	}
	return out, nil
}

func snapshotKernelLiveStateFromFlows(rulesMap *ebpf.Map, flowsMap *ebpf.Map, includeNAT bool) (kernelFlowLiveStateSnapshot, error) {
	out := newKernelFlowLiveStateSnapshot(includeNAT)
	if flowsMap == nil {
		return out, nil
	}

	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		out.FlowEntries++
		if includeNAT {
			if owner, ok := kernelUsedNATReservation(value.SessionID, rulesMap, key, value); ok {
				out.UsedNATV4[owner] = struct{}{}
			}
		}
		if !kernelFlowCountsTowardLiveGauge(value) {
			continue
		}
		item := out.ByRuleID[value.RuleID]
		if kernelFlowUsesUDPAccounting(key.Proto) {
			item.UDPNatEntries++
		} else if kernelFlowUsesICMPAccounting(key.Proto) {
			item.ICMPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		out.ByRuleID[value.RuleID] = item
	}
	if err := iter.Err(); err != nil {
		return kernelFlowLiveStateSnapshot{}, fmt.Errorf("iterate kernel flows map for live counts: %w", err)
	}
	return out, nil
}

func snapshotXDPKernelLiveStateFromFlows(rulesMap *ebpf.Map, flowsMap *ebpf.Map, includeNAT bool) (kernelFlowLiveStateSnapshot, error) {
	out := newKernelFlowLiveStateSnapshot(includeNAT)
	if flowsMap == nil {
		return out, nil
	}

	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var raw xdpFlowValueV4
	for iter.Next(&key, &raw) {
		value := kernelFlowValueFromXDP(raw)
		out.FlowEntries++
		if includeNAT {
			if owner, ok := kernelUsedNATReservation(value.SessionID, rulesMap, key, value); ok {
				out.UsedNATV4[owner] = struct{}{}
			}
		}
		if !kernelFlowCountsTowardLiveGauge(value) {
			continue
		}
		item := out.ByRuleID[value.RuleID]
		if kernelFlowUsesUDPAccounting(key.Proto) {
			item.UDPNatEntries++
		} else if kernelFlowUsesICMPAccounting(key.Proto) {
			item.ICMPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		out.ByRuleID[value.RuleID] = item
	}
	if err := iter.Err(); err != nil {
		return kernelFlowLiveStateSnapshot{}, fmt.Errorf("iterate xdp flows map for live counts: %w", err)
	}
	return out, nil
}

func snapshotKernelLiveStateFromFlowsV6(rulesMap *ebpf.Map, flowsMap *ebpf.Map, includeNAT bool) (kernelFlowLiveStateSnapshot, error) {
	out := newKernelFlowLiveStateSnapshot(includeNAT)
	if flowsMap == nil {
		return out, nil
	}

	iter := flowsMap.Iterate()
	var key tcFlowKeyV6
	var value tcFlowValueV6
	for iter.Next(&key, &value) {
		out.FlowEntries++
		if includeNAT {
			if owner, ok := kernelUsedNATReservationV6(value.SessionID, rulesMap, key, value); ok {
				out.UsedNATV6[owner] = struct{}{}
			}
		}
		if !kernelFlowCountsTowardLiveGaugeV6(value) {
			continue
		}
		item := out.ByRuleID[value.RuleID]
		if kernelFlowUsesUDPAccounting(key.Proto) {
			item.UDPNatEntries++
		} else if kernelFlowUsesICMPAccounting(key.Proto) {
			item.ICMPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		out.ByRuleID[value.RuleID] = item
	}
	if err := iter.Err(); err != nil {
		return kernelFlowLiveStateSnapshot{}, fmt.Errorf("iterate kernel ipv6 flows map for live counts: %w", err)
	}
	return out, nil
}

func kernelUsedNATReservation(sessionID uint64, rulesMap *ebpf.Map, key tcFlowKeyV4, value tcFlowValueV4) (kernelNATReservationOwnerV4, bool) {
	if value.Flags&kernelFlowFlagFullNAT == 0 || value.NATAddr == 0 || value.NATPort == 0 {
		return kernelNATReservationOwnerV4{}, false
	}

	natKey := tcNATPortKeyV4{
		NATAddr: value.NATAddr,
		NATPort: value.NATPort,
		Proto:   key.Proto,
	}
	if value.Flags&kernelFlowFlagFrontEntry == 0 {
		natKey.IfIndex = key.IfIndex
		return kernelNATReservationOwnerV4{Key: natKey, SessionID: sessionID}, true
	}

	ruleValue, ok := lookupRuleValueForFrontFlow(rulesMap, key)
	if !ok || ruleValue.OutIfIndex == 0 {
		return kernelNATReservationOwnerV4{}, false
	}
	natKey.IfIndex = ruleValue.OutIfIndex
	return kernelNATReservationOwnerV4{Key: natKey, SessionID: sessionID}, true
}

func kernelUsedNATReservationV6(sessionID uint64, rulesMap *ebpf.Map, key tcFlowKeyV6, value tcFlowValueV6) (kernelNATReservationOwnerV6, bool) {
	if value.Flags&kernelFlowFlagFullNAT == 0 || value.NATAddr == [16]byte{} || value.NATPort == 0 {
		return kernelNATReservationOwnerV6{}, false
	}

	natKey := tcNATPortKeyV6{
		NATAddr: value.NATAddr,
		NATPort: value.NATPort,
		Proto:   key.Proto,
	}
	if value.Flags&kernelFlowFlagFrontEntry == 0 {
		natKey.IfIndex = key.IfIndex
		return kernelNATReservationOwnerV6{Key: natKey, SessionID: sessionID}, true
	}

	ruleValue, ok := lookupRuleValueForFrontFlowV6(rulesMap, key)
	if !ok || ruleValue.OutIfIndex == 0 {
		return kernelNATReservationOwnerV6{}, false
	}
	natKey.IfIndex = ruleValue.OutIfIndex
	return kernelNATReservationOwnerV6{Key: natKey, SessionID: sessionID}, true
}

func kernelFlowCountsTowardLiveGauge(value tcFlowValueV4) bool {
	if value.RuleID == 0 {
		return false
	}
	if value.Flags&kernelFlowFlagCounted == 0 {
		return false
	}
	if value.Flags&kernelFlowFlagFullNAT != 0 && value.Flags&kernelFlowFlagFrontEntry != 0 {
		return false
	}
	return true
}

func kernelFlowCountsTowardLiveGaugeV6(value tcFlowValueV6) bool {
	if value.RuleID == 0 {
		return false
	}
	if value.Flags&kernelFlowFlagCounted == 0 {
		return false
	}
	if value.Flags&kernelFlowFlagFullNAT != 0 && value.Flags&kernelFlowFlagFrontEntry != 0 {
		return false
	}
	return true
}

func kernelFlowUsesDatagramAccounting(proto uint8) bool {
	return proto == unix.IPPROTO_UDP || proto == unix.IPPROTO_ICMP
}

func kernelFlowUsesUDPAccounting(proto uint8) bool {
	return proto == unix.IPPROTO_UDP
}

func kernelFlowUsesICMPAccounting(proto uint8) bool {
	return proto == unix.IPPROTO_ICMP
}

func kernelDatagramFlowIdleTimeout(proto uint8) uint64 {
	if proto == unix.IPPROTO_ICMP {
		return kernelICMPFlowIdleTimeout
	}
	return kernelUDPFlowIdleTimeout
}

func kernelLiveStatsCorrection(observed map[uint32]kernelStatsValueV4, live map[uint32]kernelStatsValueV4) map[uint32]kernelRuleStats {
	if len(observed) == 0 && len(live) == 0 {
		return map[uint32]kernelRuleStats{}
	}

	ids := make(map[uint32]struct{}, len(observed)+len(live))
	for ruleID := range observed {
		ids[ruleID] = struct{}{}
	}
	for ruleID := range live {
		ids[ruleID] = struct{}{}
	}

	out := make(map[uint32]kernelRuleStats)
	for ruleID := range ids {
		observedItem := observed[ruleID]
		liveItem := live[ruleID]
		delta := kernelRuleStats{
			TCPActiveConns: int64(liveItem.TCPActiveConns) - int64(observedItem.TCPActiveConns),
			UDPNatEntries:  int64(liveItem.UDPNatEntries) - int64(observedItem.UDPNatEntries),
			ICMPNatEntries: int64(liveItem.ICMPNatEntries) - int64(observedItem.ICMPNatEntries),
		}
		if delta.TCPActiveConns == 0 && delta.UDPNatEntries == 0 && delta.ICMPNatEntries == 0 {
			continue
		}
		out[ruleID] = delta
	}
	return out
}

func reconcileKernelStatsCorrectionFromRuntimeMaps(statsMap *ebpf.Map, refs kernelRuntimeMapRefs) (map[uint32]kernelRuleStats, error) {
	live, err := snapshotKernelLiveStateFromRuntimeMapRefs(refs, false)
	if err != nil {
		return nil, err
	}
	return reconcileKernelStatsCorrectionFromSnapshot(statsMap, live.ByRuleID)
}

func reconcileKernelStatsCorrectionFromSnapshot(statsMap *ebpf.Map, live map[uint32]kernelStatsValueV4) (map[uint32]kernelRuleStats, error) {
	observed, err := snapshotKernelStatsValues(statsMap)
	if err != nil {
		return nil, err
	}
	return kernelLiveStatsCorrection(observed, live), nil
}

func reconcileKernelStatsCorrectionFromCandidates(statsMap *ebpf.Map, live map[uint32]kernelStatsValueV4, current map[uint32]kernelRuleStats) (map[uint32]kernelRuleStats, error) {
	candidates := make(map[uint32]struct{}, len(live)+len(current))
	for ruleID := range live {
		candidates[ruleID] = struct{}{}
	}
	for ruleID, correction := range current {
		if correction.TCPActiveConns == 0 && correction.UDPNatEntries == 0 && correction.ICMPNatEntries == 0 {
			continue
		}
		candidates[ruleID] = struct{}{}
	}
	if len(candidates) == 0 {
		return map[uint32]kernelRuleStats{}, nil
	}

	observed := make(map[uint32]kernelStatsValueV4, len(candidates))
	for ruleID := range candidates {
		value, ok, err := lookupKernelStatsValue(statsMap, ruleID)
		if err != nil {
			return nil, err
		}
		if ok {
			observed[ruleID] = value
		}
	}
	return kernelLiveStatsCorrection(observed, live), nil
}

func syncKernelLiveStatsCorrections(dst map[uint32]kernelRuleStats, exact map[uint32]kernelRuleStats) {
	if dst == nil {
		return
	}

	ids := make(map[uint32]struct{}, len(dst)+len(exact))
	for ruleID, current := range dst {
		if current.TCPActiveConns == 0 && current.UDPNatEntries == 0 && current.ICMPNatEntries == 0 {
			continue
		}
		ids[ruleID] = struct{}{}
	}
	for ruleID := range exact {
		ids[ruleID] = struct{}{}
	}

	for ruleID := range ids {
		current := dst[ruleID]
		next := exact[ruleID]
		current.TCPActiveConns = next.TCPActiveConns
		current.UDPNatEntries = next.UDPNatEntries
		current.ICMPNatEntries = next.ICMPNatEntries
		if current == (kernelRuleStats{}) {
			delete(dst, ruleID)
			continue
		}
		dst[ruleID] = current
	}
}

func kernelStatsCorrectionsEqual(a map[uint32]kernelRuleStats, b map[uint32]kernelRuleStats) bool {
	if len(a) != len(b) {
		return false
	}
	for ruleID, value := range a {
		if b[ruleID] != value {
			return false
		}
	}
	return true
}

func pruneOrphanKernelNATReservations(natPortsMap *ebpf.Map, used map[kernelNATReservationOwnerV4]struct{}, previous map[kernelNATReservationOwnerV4]struct{}) (int, int, map[kernelNATReservationOwnerV4]struct{}, error) {
	if natPortsMap == nil {
		return 0, 0, nil, nil
	}

	iter := natPortsMap.Iterate()
	var candidates []kernelNATReservationOwnerV4
	var key tcNATPortKeyV4
	var value tcNATPortValue
	remaining := 0
	for iter.Next(&key, &value) {
		owner := kernelNATReservationOwnerV4{Key: key, SessionID: value.SessionID}
		if _, ok := used[owner]; ok {
			remaining++
			continue
		}
		candidates = append(candidates, owner)
	}
	if err := iter.Err(); err != nil {
		return 0, 0, nil, fmt.Errorf("iterate kernel nat map: %w", err)
	}

	next := make(map[kernelNATReservationOwnerV4]struct{})
	deleted := 0
	for _, owner := range candidates {
		if _, ok := previous[owner]; !ok {
			next[owner] = struct{}{}
			remaining++
			continue
		}
		var current tcNATPortValue
		if err := natPortsMap.Lookup(owner.Key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return remaining, deleted, next, fmt.Errorf("revalidate orphan nat reservation: %w", err)
		}
		if current.SessionID != owner.SessionID {
			next[kernelNATReservationOwnerV4{Key: owner.Key, SessionID: current.SessionID}] = struct{}{}
			remaining++
			continue
		}
		if err := natPortsMap.Delete(owner.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return remaining, deleted, next, fmt.Errorf("delete orphan nat reservation: %w", err)
		}
		deleted++
	}
	if len(next) == 0 {
		next = nil
	}
	return remaining, deleted, next, nil
}

func pruneOrphanKernelNATReservationsV6(natPortsMap *ebpf.Map, used map[kernelNATReservationOwnerV6]struct{}, previous map[kernelNATReservationOwnerV6]struct{}) (int, int, map[kernelNATReservationOwnerV6]struct{}, error) {
	if natPortsMap == nil {
		return 0, 0, nil, nil
	}

	iter := natPortsMap.Iterate()
	var candidates []kernelNATReservationOwnerV6
	var key tcNATPortKeyV6
	var value tcNATPortValue
	remaining := 0
	for iter.Next(&key, &value) {
		owner := kernelNATReservationOwnerV6{Key: key, SessionID: value.SessionID}
		if _, ok := used[owner]; ok {
			remaining++
			continue
		}
		candidates = append(candidates, owner)
	}
	if err := iter.Err(); err != nil {
		return 0, 0, nil, fmt.Errorf("iterate kernel IPv6 nat map: %w", err)
	}

	next := make(map[kernelNATReservationOwnerV6]struct{})
	deleted := 0
	for _, owner := range candidates {
		if _, ok := previous[owner]; !ok {
			next[owner] = struct{}{}
			remaining++
			continue
		}
		var current tcNATPortValue
		if err := natPortsMap.Lookup(owner.Key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return remaining, deleted, next, fmt.Errorf("revalidate orphan IPv6 nat reservation: %w", err)
		}
		if current.SessionID != owner.SessionID {
			next[kernelNATReservationOwnerV6{Key: owner.Key, SessionID: current.SessionID}] = struct{}{}
			remaining++
			continue
		}
		if err := natPortsMap.Delete(owner.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return remaining, deleted, next, fmt.Errorf("delete orphan IPv6 nat reservation: %w", err)
		}
		deleted++
	}
	if len(next) == 0 {
		next = nil
	}
	return remaining, deleted, next, nil
}

func pruneOrphanKernelNATBanks(refs kernelRuntimeMapRefs, used kernelNATBankUsage, state kernelNATPruneState) (int, int, kernelNATPruneState, error) {
	nextState := state.clone()
	natEntries := 0
	deleted := 0

	for _, item := range []struct {
		m         *ebpf.Map
		used      map[kernelNATReservationOwnerV4]struct{}
		previous  map[kernelNATReservationOwnerV4]struct{}
		storeNext func(map[kernelNATReservationOwnerV4]struct{})
	}{
		{refs.natV4, used.activeV4, nextState.activeV4, func(next map[kernelNATReservationOwnerV4]struct{}) { nextState.activeV4 = next }},
		{refs.natOldV4, used.oldV4, nextState.oldV4, func(next map[kernelNATReservationOwnerV4]struct{}) { nextState.oldV4 = next }},
	} {
		remaining, itemDeleted, next, err := pruneOrphanKernelNATReservations(item.m, item.used, item.previous)
		if err != nil {
			return 0, 0, state, err
		}
		item.storeNext(next)
		natEntries += remaining
		deleted += itemDeleted
	}

	for _, item := range []struct {
		m         *ebpf.Map
		used      map[kernelNATReservationOwnerV6]struct{}
		previous  map[kernelNATReservationOwnerV6]struct{}
		storeNext func(map[kernelNATReservationOwnerV6]struct{})
	}{
		{refs.natV6, used.activeV6, nextState.activeV6, func(next map[kernelNATReservationOwnerV6]struct{}) { nextState.activeV6 = next }},
		{refs.natOldV6, used.oldV6, nextState.oldV6, func(next map[kernelNATReservationOwnerV6]struct{}) { nextState.oldV6 = next }},
	} {
		remaining, itemDeleted, next, err := pruneOrphanKernelNATReservationsV6(item.m, item.used, item.previous)
		if err != nil {
			return 0, 0, state, err
		}
		item.storeNext(next)
		natEntries += remaining
		deleted += itemDeleted
	}

	return natEntries, deleted, nextState, nil
}

func kernelRuleStatsFromValue(value kernelStatsValueV4) kernelRuleStats {
	return kernelRuleStats{
		TCPActiveConns: int64(value.TCPActiveConns),
		UDPNatEntries:  int64(value.UDPNatEntries),
		ICMPNatEntries: int64(value.ICMPNatEntries),
		TotalConns:     int64(value.TotalConns),
		BytesIn:        int64(value.BytesIn),
		BytesOut:       int64(value.BytesOut),
	}
}

func kernelPossibleCPUCount() (int, error) {
	kernelPossibleCPUsOnce.Do(func() {
		kernelPossibleCPUs, kernelPossibleCPUsErr = ebpf.PossibleCPU()
		if kernelPossibleCPUsErr == nil && kernelPossibleCPUs <= 0 {
			kernelPossibleCPUs = 1
		}
	})
	return kernelPossibleCPUs, kernelPossibleCPUsErr
}

func kernelMapHasPerCPUValue(typ ebpf.MapType) bool {
	switch typ {
	case ebpf.PerCPUHash, ebpf.PerCPUArray, ebpf.LRUCPUHash, ebpf.PerCPUCGroupStorage:
		return true
	default:
		return false
	}
}

func aggregateKernelPerCPUStats(values []kernelStatsValueV4) kernelStatsValueV4 {
	var out kernelStatsValueV4
	for _, value := range values {
		out.TotalConns += value.TotalConns
		out.TCPActiveConns += value.TCPActiveConns
		out.UDPNatEntries += value.UDPNatEntries
		out.ICMPNatEntries += value.ICMPNatEntries
		out.BytesIn += value.BytesIn
		out.BytesOut += value.BytesOut
	}
	return out
}

func clearKernelStatsValues(values []kernelStatsValueV4) {
	for i := range values {
		values[i] = kernelStatsValueV4{}
	}
}

func kernelFlowMaintenanceBudgetForCapacity(capacity int) int {
	if capacity <= 0 {
		return kernelFlowMaintenanceBudgetMin
	}
	budget := (capacity + kernelFlowMaintenanceTargetPasses - 1) / kernelFlowMaintenanceTargetPasses
	if budget < kernelFlowMaintenanceBudgetMin {
		return kernelFlowMaintenanceBudgetMin
	}
	if budget > kernelFlowMaintenanceBudgetMax {
		return kernelFlowMaintenanceBudgetMax
	}
	return budget
}

func (state *kernelFlowPruneState) reset() {
	if state == nil {
		return
	}
	state.batchCursor = ebpf.MapBatchCursor{}
	state.batchCursorV6 = ebpf.MapBatchCursor{}
	state.fullCursor = tcFlowKeyV4{}
	state.fullCursorV6 = tcFlowKeyV6{}
	state.fullCursorValid = false
	state.fullCursorValidV6 = false
	state.keys = nil
	state.keysV6 = nil
	state.values = nil
	state.xdpValues = nil
	state.valuesV6 = nil
}

func (state *kernelFlowPruneState) ensureBuffers(size int) ([]tcFlowKeyV4, []tcFlowValueV4) {
	if cap(state.keys) < size {
		state.keys = make([]tcFlowKeyV4, size)
	} else {
		state.keys = state.keys[:size]
	}
	if cap(state.values) < size {
		state.values = make([]tcFlowValueV4, size)
	} else {
		state.values = state.values[:size]
	}
	return state.keys, state.values
}

func (state *kernelFlowPruneState) ensureXDPBuffers(size int) ([]tcFlowKeyV4, []xdpFlowValueV4) {
	if cap(state.keys) < size {
		state.keys = make([]tcFlowKeyV4, size)
	} else {
		state.keys = state.keys[:size]
	}
	if cap(state.xdpValues) < size {
		state.xdpValues = make([]xdpFlowValueV4, size)
	} else {
		state.xdpValues = state.xdpValues[:size]
	}
	return state.keys, state.xdpValues
}

func (state *kernelFlowPruneState) ensureBuffersV6(size int) ([]tcFlowKeyV6, []tcFlowValueV6) {
	if cap(state.keysV6) < size {
		state.keysV6 = make([]tcFlowKeyV6, size)
	} else {
		state.keysV6 = state.keysV6[:size]
	}
	if cap(state.valuesV6) < size {
		state.valuesV6 = make([]tcFlowValueV6, size)
	} else {
		state.valuesV6 = state.valuesV6[:size]
	}
	return state.keysV6, state.valuesV6
}

func pruneStaleKernelFlowsBatch(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	corrections := make(map[uint32]kernelRuleStats)
	remaining := metrics.Budget

	for remaining > 0 {
		size := min(remaining, kernelFlowMaintenanceBatchSize)
		keys, values := state.ensureBuffers(size)
		n, err := flowsMap.BatchLookup(&state.batchCursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, err
		}
		if n == 0 {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}

		for i := 0; i < n; i++ {
			value := values[i]
			if value.RuleID == 0 {
				continue
			}
			metrics.Scanned++
			if kernelFlowDeleteReason(keys[i], value, nowNS, haveNow) != "" {
				metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: keys[i], value: value}, corrections)
			}
		}

		remaining -= n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}
	}

	return corrections, metrics, nil
}

func pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	var staleFlows []staleKernelFlow
	corrections := make(map[uint32]kernelRuleStats)

	for iter.Next(&key, &value) {
		if value.RuleID == 0 {
			continue
		}
		metrics.Scanned++
		if kernelFlowDeleteReason(key, value, nowNS, haveNow) != "" {
			staleFlows = append(staleFlows, staleKernelFlow{key: key, value: value})
		}
	}

	if err := iter.Err(); err != nil {
		return nil, metrics, fmt.Errorf("iterate kernel flows map: %w", err)
	}

	for _, stale := range staleFlows {
		metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, stale, corrections)
	}
	return corrections, metrics, nil
}

func pruneStaleKernelFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if state == nil {
		return pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if metrics.Budget <= 0 {
		metrics.Budget = kernelFlowMaintenanceBudgetMin
	}

	corrections := make(map[uint32]kernelRuleStats)
	var current tcFlowKeyV4
	if state.fullCursorValid {
		current = state.fullCursor
	} else {
		if err := flowsMap.NextKey(nil, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				state.fullCursorValid = false
				state.fullCursor = tcFlowKeyV4{}
				return corrections, metrics, nil
			}
			return nil, metrics, fmt.Errorf("iterate kernel flows map: %w", err)
		}
	}

	for scanned := 0; scanned < metrics.Budget; {
		var next tcFlowKeyV4
		nextValid := false
		if err := flowsMap.NextKey(current, &next); err == nil {
			nextValid = true
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, fmt.Errorf("iterate kernel flows map: %w", err)
		}

		var value tcFlowValueV4
		if err := flowsMap.Lookup(current, &value); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if !nextValid {
					state.fullCursorValid = false
					state.fullCursor = tcFlowKeyV4{}
					return corrections, metrics, nil
				}
				current = next
				state.fullCursor = current
				state.fullCursorValid = true
				continue
			}
			return nil, metrics, fmt.Errorf("lookup kernel flow during fallback scan: %w", err)
		}

		if value.RuleID != 0 {
			metrics.Scanned++
			if kernelFlowDeleteReason(current, value, nowNS, haveNow) != "" {
				metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: current, value: value}, corrections)
			}
		}
		scanned++

		if !nextValid {
			state.fullCursorValid = false
			state.fullCursor = tcFlowKeyV4{}
			return corrections, metrics, nil
		}
		current = next
		state.fullCursor = current
		state.fullCursorValid = true
	}

	return corrections, metrics, nil
}

func pruneStaleXDPFlowsBatch(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	corrections := make(map[uint32]kernelRuleStats)
	remaining := metrics.Budget

	for remaining > 0 {
		size := min(remaining, kernelFlowMaintenanceBatchSize)
		keys, values := state.ensureXDPBuffers(size)
		n, err := flowsMap.BatchLookup(&state.batchCursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, err
		}
		if n == 0 {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}

		for i := 0; i < n; i++ {
			value := kernelFlowValueFromXDP(values[i])
			if value.RuleID == 0 {
				continue
			}
			metrics.Scanned++
			if kernelFlowDeleteReason(keys[i], value, nowNS, haveNow) != "" {
				metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: keys[i], value: value}, corrections)
			}
		}

		remaining -= n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}
	}

	return corrections, metrics, nil
}

func pruneStaleXDPFlowsFullInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var raw xdpFlowValueV4
	var staleFlows []staleKernelFlow
	corrections := make(map[uint32]kernelRuleStats)

	for iter.Next(&key, &raw) {
		value := kernelFlowValueFromXDP(raw)
		if value.RuleID == 0 {
			continue
		}
		metrics.Scanned++
		if kernelFlowDeleteReason(key, value, nowNS, haveNow) != "" {
			staleFlows = append(staleFlows, staleKernelFlow{key: key, value: value})
		}
	}

	if err := iter.Err(); err != nil {
		return nil, metrics, fmt.Errorf("iterate xdp flows map: %w", err)
	}

	for _, stale := range staleFlows {
		metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, stale, corrections)
	}
	return corrections, metrics, nil
}

func pruneStaleXDPFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if state == nil {
		return pruneStaleXDPFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if metrics.Budget <= 0 {
		metrics.Budget = kernelFlowMaintenanceBudgetMin
	}

	corrections := make(map[uint32]kernelRuleStats)
	var current tcFlowKeyV4
	if state.fullCursorValid {
		current = state.fullCursor
	} else {
		if err := flowsMap.NextKey(nil, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				state.fullCursorValid = false
				state.fullCursor = tcFlowKeyV4{}
				return corrections, metrics, nil
			}
			return nil, metrics, fmt.Errorf("iterate xdp flows map: %w", err)
		}
	}

	for scanned := 0; scanned < metrics.Budget; {
		var next tcFlowKeyV4
		nextValid := false
		if err := flowsMap.NextKey(current, &next); err == nil {
			nextValid = true
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, fmt.Errorf("iterate xdp flows map: %w", err)
		}

		var raw xdpFlowValueV4
		if err := flowsMap.Lookup(current, &raw); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if !nextValid {
					state.fullCursorValid = false
					state.fullCursor = tcFlowKeyV4{}
					return corrections, metrics, nil
				}
				current = next
				state.fullCursor = current
				state.fullCursorValid = true
				continue
			}
			return nil, metrics, fmt.Errorf("lookup xdp flow during fallback scan: %w", err)
		}

		value := kernelFlowValueFromXDP(raw)
		if value.RuleID != 0 {
			metrics.Scanned++
			if kernelFlowDeleteReason(current, value, nowNS, haveNow) != "" {
				metrics.Deleted += deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: current, value: value}, corrections)
			}
		}
		scanned++

		if !nextValid {
			state.fullCursorValid = false
			state.fullCursor = tcFlowKeyV4{}
			return corrections, metrics, nil
		}
		current = next
		state.fullCursor = current
		state.fullCursorValid = true
	}

	return corrections, metrics, nil
}

func pruneStaleKernelFlowsV6InCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if flowsMap == nil {
		return map[uint32]kernelRuleStats{}, kernelFlowPruneMetrics{}, nil
	}

	nowNS, haveNow := kernelMonotonicNowNS()
	if budget <= 0 {
		budget = kernelFlowMaintenanceBudgetMin
	}
	metrics := kernelFlowPruneMetrics{Budget: budget}
	if state == nil {
		return pruneStaleKernelFlowsV6FullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if !state.batchSupportKnown || state.batchSupported {
		corrections, pruneMetrics, err := pruneStaleKernelFlowsBatchV6(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
		if err == nil {
			state.batchSupportKnown = true
			state.batchSupported = true
			return corrections, pruneMetrics, nil
		}
		state.batchCursorV6 = ebpf.MapBatchCursor{}
		state.fullCursorV6 = tcFlowKeyV6{}
		state.fullCursorValidV6 = false
		state.keysV6 = nil
		state.valuesV6 = nil
		state.batchSupportKnown = true
		state.batchSupported = false
		log.Printf("kernel dataplane maintenance: batch IPv6 flow scan unavailable, falling back to full scan: %v", err)
	}
	return pruneStaleKernelFlowsIncrementalV6InCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, metrics)
}

func pruneStaleKernelFlowsBatchV6(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	corrections := make(map[uint32]kernelRuleStats)
	remaining := metrics.Budget

	for remaining > 0 {
		size := min(remaining, kernelFlowMaintenanceBatchSize)
		keys, values := state.ensureBuffersV6(size)
		n, err := flowsMap.BatchLookup(&state.batchCursorV6, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, err
		}
		if n == 0 {
			state.batchCursorV6 = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}

		for i := 0; i < n; i++ {
			value := values[i]
			if value.RuleID == 0 {
				continue
			}
			metrics.Scanned++
			if kernelFlowShouldDeleteV6(keys[i], value, nowNS, haveNow) {
				metrics.Deleted += deleteStaleKernelFlowV6(rulesMap, flowsMap, natPortsMap, staleKernelFlowV6{key: keys[i], value: value}, corrections)
			}
		}

		remaining -= n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			state.batchCursorV6 = ebpf.MapBatchCursor{}
			return corrections, metrics, nil
		}
	}

	return corrections, metrics, nil
}

func pruneStaleKernelFlowsV6FullInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	iter := flowsMap.Iterate()
	var key tcFlowKeyV6
	var value tcFlowValueV6
	var staleFlows []staleKernelFlowV6
	corrections := make(map[uint32]kernelRuleStats)

	for iter.Next(&key, &value) {
		if value.RuleID == 0 {
			continue
		}
		metrics.Scanned++
		if kernelFlowShouldDeleteV6(key, value, nowNS, haveNow) {
			staleFlows = append(staleFlows, staleKernelFlowV6{key: key, value: value})
		}
	}
	if err := iter.Err(); err != nil {
		return nil, metrics, fmt.Errorf("iterate kernel IPv6 flows map: %w", err)
	}

	for _, stale := range staleFlows {
		metrics.Deleted += deleteStaleKernelFlowV6(rulesMap, flowsMap, natPortsMap, stale, corrections)
	}
	return corrections, metrics, nil
}

func pruneStaleKernelFlowsIncrementalV6InCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, metrics kernelFlowPruneMetrics) (map[uint32]kernelRuleStats, kernelFlowPruneMetrics, error) {
	if state == nil {
		return pruneStaleKernelFlowsV6FullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, metrics)
	}
	if metrics.Budget <= 0 {
		metrics.Budget = kernelFlowMaintenanceBudgetMin
	}

	corrections := make(map[uint32]kernelRuleStats)
	var current tcFlowKeyV6
	if state.fullCursorValidV6 {
		current = state.fullCursorV6
	} else {
		if err := flowsMap.NextKey(nil, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				state.fullCursorValidV6 = false
				state.fullCursorV6 = tcFlowKeyV6{}
				return corrections, metrics, nil
			}
			return nil, metrics, fmt.Errorf("iterate kernel IPv6 flows map: %w", err)
		}
	}

	for scanned := 0; scanned < metrics.Budget; {
		var next tcFlowKeyV6
		nextValid := false
		if err := flowsMap.NextKey(current, &next); err == nil {
			nextValid = true
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, metrics, fmt.Errorf("iterate kernel IPv6 flows map: %w", err)
		}

		var value tcFlowValueV6
		if err := flowsMap.Lookup(current, &value); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if !nextValid {
					state.fullCursorValidV6 = false
					state.fullCursorV6 = tcFlowKeyV6{}
					return corrections, metrics, nil
				}
				current = next
				state.fullCursorV6 = current
				state.fullCursorValidV6 = true
				continue
			}
			return nil, metrics, fmt.Errorf("lookup kernel IPv6 flow during fallback scan: %w", err)
		}

		if value.RuleID != 0 {
			metrics.Scanned++
			if kernelFlowShouldDeleteV6(current, value, nowNS, haveNow) {
				metrics.Deleted += deleteStaleKernelFlowV6(rulesMap, flowsMap, natPortsMap, staleKernelFlowV6{key: current, value: value}, corrections)
			}
		}
		scanned++

		if !nextValid {
			state.fullCursorValidV6 = false
			state.fullCursorV6 = tcFlowKeyV6{}
			return corrections, metrics, nil
		}
		current = next
		state.fullCursorV6 = current
		state.fullCursorValidV6 = true
	}

	return corrections, metrics, nil
}

func kernelFlowShouldDelete(key tcFlowKeyV4, value tcFlowValueV4, nowNS uint64, haveNow bool) bool {
	return kernelFlowDeleteReason(key, value, nowNS, haveNow) != ""
}

func kernelFlowDeleteReason(key tcFlowKeyV4, value tcFlowValueV4, nowNS uint64, haveNow bool) string {
	if value.Flags&kernelFlowFlagFrontEntry != 0 && value.Flags&kernelFlowFlagFullNAT == 0 {
		return "front_entry_without_fullnat"
	}
	if value.Flags&kernelFlowFlagFullNAT != 0 && (value.NATAddr == 0 || value.NATPort == 0) {
		return "fullnat_missing_nat"
	}
	if value.Flags&(kernelFlowFlagFullNAT|kernelFlowFlagFrontEntry) == (kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry) {
		return ""
	}
	if !haveNow {
		return ""
	}
	if value.LastSeenNS == 0 || nowNS < value.LastSeenNS {
		return "invalid_last_seen"
	}

	ageNS := nowNS - value.LastSeenNS
	if kernelFlowUsesDatagramAccounting(key.Proto) {
		if ageNS > kernelDatagramFlowIdleTimeout(key.Proto) {
			return "datagram_idle_timeout"
		}
		return ""
	}

	if value.Flags&kernelFlowFlagReplySeen == 0 {
		if ageNS > kernelTCPUnrepliedTimeout {
			return "tcp_unreplied_timeout"
		}
		return ""
	}
	if value.Flags&(kernelFlowFlagFrontClosing|kernelFlowFlagReplyClosing) == (kernelFlowFlagFrontClosing | kernelFlowFlagReplyClosing) {
		closeSeenNS := value.FrontCloseSeenNS
		if closeSeenNS == 0 {
			closeSeenNS = value.LastSeenNS
		}
		if nowNS >= closeSeenNS && (nowNS-closeSeenNS) > kernelTCPClosingGraceNS {
			return "tcp_closing_grace_expired"
		}
		return ""
	}
	if ageNS > kernelTCPFlowIdleTimeout {
		return "tcp_idle_timeout"
	}
	return ""
}

func kernelFlowShouldDeleteV6(key tcFlowKeyV6, value tcFlowValueV6, nowNS uint64, haveNow bool) bool {
	if value.Flags&kernelFlowFlagFrontEntry != 0 && value.Flags&kernelFlowFlagFullNAT == 0 {
		return true
	}
	if value.Flags&kernelFlowFlagFullNAT != 0 && (value.NATAddr == [16]byte{} || value.NATPort == 0) {
		return true
	}
	if value.Flags&(kernelFlowFlagFullNAT|kernelFlowFlagFrontEntry) == (kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry) {
		return false
	}
	if !haveNow {
		return false
	}
	if value.LastSeenNS == 0 || nowNS < value.LastSeenNS {
		return true
	}

	ageNS := nowNS - value.LastSeenNS
	if kernelFlowUsesDatagramAccounting(key.Proto) {
		return ageNS > kernelDatagramFlowIdleTimeout(key.Proto)
	}
	if value.Flags&kernelFlowFlagReplySeen == 0 {
		return ageNS > kernelTCPUnrepliedTimeout
	}
	if value.Flags&(kernelFlowFlagFrontClosing|kernelFlowFlagReplyClosing) == (kernelFlowFlagFrontClosing | kernelFlowFlagReplyClosing) {
		closeSeenNS := value.FrontCloseSeenNS
		if closeSeenNS == 0 {
			closeSeenNS = value.LastSeenNS
		}
		return nowNS >= closeSeenNS && (nowNS-closeSeenNS) > kernelTCPClosingGraceNS
	}
	return ageNS > kernelTCPFlowIdleTimeout
}

func deleteStaleKernelFlow(_ *ebpf.Map, flowsMap, natPortsMap *ebpf.Map, stale staleKernelFlow, corrections map[uint32]kernelRuleStats) int {
	return deleteKernelFlowSession(flowsMap, natPortsMap, stale, corrections, true)
}

func deleteKernelFlowSession(flowsMap, natPortsMap *ebpf.Map, stale staleKernelFlow, corrections map[uint32]kernelRuleStats, requireExactValue bool) int {
	current, ok, err := lookupKernelFlowValue(flowsMap, stale.key)
	if err != nil {
		log.Printf("kernel dataplane maintenance: revalidate stale flow failed: proto=%d ifindex=%d sport=%d dport=%d err=%v", stale.key.Proto, stale.key.IfIndex, stale.key.SrcPort, stale.key.DstPort, err)
		return 0
	}
	if !ok || current.RuleID != stale.value.RuleID || current.RuleRevision != stale.value.RuleRevision || current.SessionID != stale.value.SessionID {
		return 0
	}
	if requireExactValue && current != stale.value {
		return 0
	}
	if err := flowsMap.Delete(stale.key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("kernel dataplane maintenance: delete stale flow failed: proto=%d ifindex=%d src=%d dst=%d sport=%d dport=%d err=%v",
				stale.key.Proto, stale.key.IfIndex, stale.key.SrcAddr, stale.key.DstAddr, stale.key.SrcPort, stale.key.DstPort, err)
		}
		return 0
	}

	deleted := 1
	if current.Flags&kernelFlowFlagCounted != 0 {
		item := corrections[current.RuleID]
		if kernelFlowUsesUDPAccounting(stale.key.Proto) {
			item.UDPNatEntries--
		} else if kernelFlowUsesICMPAccounting(stale.key.Proto) {
			item.ICMPNatEntries--
		} else {
			item.TCPActiveConns--
		}
		corrections[current.RuleID] = item
	}

	if current.Flags&kernelFlowFlagFullNAT == 0 {
		return deleted
	}

	if current.Flags&kernelFlowFlagFrontEntry == 0 {
		frontKey := tcFlowKeyV4{
			IfIndex: current.InIfIndex,
			SrcAddr: current.ClientAddr,
			DstAddr: current.FrontAddr,
			SrcPort: current.ClientPort,
			DstPort: current.FrontPort,
			Proto:   stale.key.Proto,
		}
		if current.Flags&kernelFlowFlagFullCone != 0 {
			frontKey.DstAddr = 0
			frontKey.DstPort = 0
		}
		if pair, pairOK, pairErr := lookupKernelFlowValue(flowsMap, frontKey); pairErr == nil && pairOK && pair.SessionID == current.SessionID {
			if err := flowsMap.Delete(frontKey); err == nil {
				deleted++
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("kernel dataplane maintenance: delete stale front flow failed: proto=%d ifindex=%d sport=%d dport=%d err=%v", frontKey.Proto, frontKey.IfIndex, frontKey.SrcPort, frontKey.DstPort, err)
			}
		}
		deleteStaleKernelNATReservation(natPortsMap, tcNATPortKeyV4{
			IfIndex: stale.key.IfIndex,
			NATAddr: current.NATAddr,
			NATPort: current.NATPort,
			Proto:   stale.key.Proto,
		}, current.SessionID)
	}
	return deleted
}

func deleteStaleKernelFlowV6(_ *ebpf.Map, flowsMap, natPortsMap *ebpf.Map, stale staleKernelFlowV6, corrections map[uint32]kernelRuleStats) int {
	return deleteKernelFlowSessionV6(flowsMap, natPortsMap, stale, corrections, true)
}

func deleteKernelFlowSessionV6(flowsMap, natPortsMap *ebpf.Map, stale staleKernelFlowV6, corrections map[uint32]kernelRuleStats, requireExactValue bool) int {
	var current tcFlowValueV6
	if flowsMap == nil {
		return 0
	}
	if err := flowsMap.Lookup(stale.key, &current); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("kernel dataplane maintenance: revalidate stale IPv6 flow failed: proto=%d ifindex=%d sport=%d dport=%d err=%v", stale.key.Proto, stale.key.IfIndex, stale.key.SrcPort, stale.key.DstPort, err)
		}
		return 0
	}
	if current.RuleID != stale.value.RuleID || current.RuleRevision != stale.value.RuleRevision || current.SessionID != stale.value.SessionID {
		return 0
	}
	if requireExactValue && current != stale.value {
		return 0
	}
	if err := flowsMap.Delete(stale.key); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("kernel dataplane maintenance: delete stale IPv6 flow failed: proto=%d ifindex=%d sport=%d dport=%d err=%v", stale.key.Proto, stale.key.IfIndex, stale.key.SrcPort, stale.key.DstPort, err)
		}
		return 0
	}

	deleted := 1
	if current.Flags&kernelFlowFlagCounted != 0 {
		item := corrections[current.RuleID]
		if kernelFlowUsesUDPAccounting(stale.key.Proto) {
			item.UDPNatEntries--
		} else if kernelFlowUsesICMPAccounting(stale.key.Proto) {
			item.ICMPNatEntries--
		} else {
			item.TCPActiveConns--
		}
		corrections[current.RuleID] = item
	}

	if current.Flags&kernelFlowFlagFullNAT == 0 {
		return deleted
	}

	if current.Flags&kernelFlowFlagFrontEntry == 0 {
		frontKey := tcFlowKeyV6{
			IfIndex: current.InIfIndex,
			SrcAddr: current.ClientAddr,
			DstAddr: current.FrontAddr,
			SrcPort: current.ClientPort,
			DstPort: current.FrontPort,
			Proto:   stale.key.Proto,
		}
		if current.Flags&kernelFlowFlagFullCone != 0 {
			frontKey.DstAddr = [16]byte{}
			frontKey.DstPort = 0
		}
		var pair tcFlowValueV6
		if err := flowsMap.Lookup(frontKey, &pair); err == nil && pair.SessionID == current.SessionID {
			if err := flowsMap.Delete(frontKey); err == nil {
				deleted++
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("kernel dataplane maintenance: delete stale IPv6 front flow failed: proto=%d ifindex=%d sport=%d dport=%d err=%v", frontKey.Proto, frontKey.IfIndex, frontKey.SrcPort, frontKey.DstPort, err)
			}
		}
		deleteStaleKernelNATReservationV6(natPortsMap, tcNATPortKeyV6{
			IfIndex: stale.key.IfIndex,
			NATAddr: current.NATAddr,
			NATPort: current.NATPort,
			Proto:   stale.key.Proto,
		}, current.SessionID)
	}
	return deleted
}

func lookupKernelFlowValue(flowsMap *ebpf.Map, key tcFlowKeyV4) (tcFlowValueV4, bool, error) {
	if flowsMap == nil {
		return tcFlowValueV4{}, false, nil
	}
	if flowsMap.ValueSize() == uint32(binary.Size(xdpFlowValueV4{})) {
		var raw xdpFlowValueV4
		if err := flowsMap.Lookup(key, &raw); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return tcFlowValueV4{}, false, nil
			}
			return tcFlowValueV4{}, false, err
		}
		return kernelFlowValueFromXDP(raw), true, nil
	}
	var value tcFlowValueV4
	if err := flowsMap.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return tcFlowValueV4{}, false, nil
		}
		return tcFlowValueV4{}, false, err
	}
	return value, true, nil
}

func lookupRuleValueForFrontFlow(rulesMap *ebpf.Map, frontKey tcFlowKeyV4) (tcRuleValueV4, bool) {
	if rulesMap == nil {
		return tcRuleValueV4{}, false
	}

	ruleKey := tcRuleKeyV4{
		IfIndex: frontKey.IfIndex,
		DstAddr: frontKey.DstAddr,
		DstPort: frontKey.DstPort,
		Proto:   frontKey.Proto,
	}
	var ruleValue tcRuleValueV4
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}

	ruleKey.DstAddr = 0
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}
	ruleKey.DstPort = 0
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}
	return tcRuleValueV4{}, false
}

func lookupRuleValueForFrontFlowV6(rulesMap *ebpf.Map, frontKey tcFlowKeyV6) (tcRuleValueV6, bool) {
	if rulesMap == nil {
		return tcRuleValueV6{}, false
	}

	ruleKey := tcRuleKeyV6{
		IfIndex: frontKey.IfIndex,
		DstAddr: frontKey.DstAddr,
		DstPort: frontKey.DstPort,
		Proto:   frontKey.Proto,
	}
	var ruleValue tcRuleValueV6
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}

	ruleKey.DstAddr = [16]byte{}
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}
	ruleKey.DstAddr = frontKey.DstAddr
	ruleKey.DstPort = 0
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}
	ruleKey.DstAddr = [16]byte{}
	if err := rulesMap.Lookup(ruleKey, &ruleValue); err == nil {
		return ruleValue, true
	}
	return tcRuleValueV6{}, false
}

func deleteStaleKernelNATReservation(natPortsMap *ebpf.Map, natKey tcNATPortKeyV4, sessionID uint64) {
	if natPortsMap == nil || natKey.NATAddr == 0 || natKey.NATPort == 0 {
		return
	}
	var current tcNATPortValue
	if err := natPortsMap.Lookup(natKey, &current); err != nil || current.SessionID != sessionID {
		return
	}
	if err := natPortsMap.Delete(natKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("kernel dataplane maintenance: delete stale nat reservation failed: proto=%d ifindex=%d nat_addr=%d nat_port=%d err=%v",
			natKey.Proto,
			natKey.IfIndex,
			natKey.NATAddr,
			natKey.NATPort,
			err,
		)
	}
}

func deleteStaleKernelNATReservationV6(natPortsMap *ebpf.Map, natKey tcNATPortKeyV6, sessionID uint64) {
	if natPortsMap == nil || natKey.NATAddr == [16]byte{} || natKey.NATPort == 0 {
		return
	}
	var current tcNATPortValue
	if err := natPortsMap.Lookup(natKey, &current); err != nil || current.SessionID != sessionID {
		return
	}
	if err := natPortsMap.Delete(natKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf(
			"kernel dataplane maintenance: delete stale IPv6 nat reservation failed: proto=%d ifindex=%d nat_port=%d err=%v",
			natKey.Proto,
			natKey.IfIndex,
			natKey.NATPort,
			err,
		)
	}
}
