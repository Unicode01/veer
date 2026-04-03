//go:build linux

package app

import (
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

type kernelStatsValueV4 struct {
	TotalConns     uint64
	TCPActiveConns uint64
	UDPNatEntries  uint64
	BytesIn        uint64
	BytesOut       uint64
}

type kernelFlowPruneState struct {
	batchCursor       ebpf.MapBatchCursor
	batchSupported    bool
	batchSupportKnown bool
	fullCursor        tcFlowKeyV4
	fullCursorValid   bool
	keys              []tcFlowKeyV4
	values            []tcFlowValueV4
}

var (
	kernelPossibleCPUsOnce sync.Once
	kernelPossibleCPUs     int
	kernelPossibleCPUsErr  error
)

func snapshotKernelStatsFromCollection(coll *ebpf.Collection, corrections map[uint32]kernelRuleStats) (kernelRuleStatsSnapshot, error) {
	snapshot := emptyKernelRuleStatsSnapshot()
	if coll == nil || coll.Maps == nil {
		return snapshot, nil
	}

	statsMap := coll.Maps[kernelStatsMapName]
	if statsMap != nil {
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
	}

	applyKernelStatsCorrections(snapshot.ByRuleID, corrections)
	return snapshot, nil
}

func pruneStaleKernelFlowsInCollection(coll *ebpf.Collection, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, error) {
	if coll == nil || coll.Maps == nil {
		return map[uint32]kernelRuleStats{}, nil
	}

	flowsMap := coll.Maps[kernelFlowsMapName]
	if flowsMap == nil {
		return map[uint32]kernelRuleStats{}, nil
	}

	rulesMap := coll.Maps[kernelRulesMapName]
	natPortsMap := coll.Maps[kernelNatPortsMapName]
	nowNS, haveNow := kernelMonotonicNowNS()
	if budget <= 0 {
		budget = kernelFlowMaintenanceBudgetMin
	}
	if state == nil {
		return pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow)
	}
	if !state.batchSupportKnown || state.batchSupported {
		corrections, err := pruneStaleKernelFlowsBatch(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, budget)
		if err == nil {
			state.batchSupportKnown = true
			state.batchSupported = true
			return corrections, nil
		}
		state.reset()
		state.batchSupportKnown = true
		state.batchSupported = false
		log.Printf("kernel dataplane maintenance: batch flow scan unavailable, falling back to full scan: %v", err)
	}
	return pruneStaleKernelFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow, state, budget)
}

func applyKernelStatsCorrections(dst map[uint32]kernelRuleStats, corrections map[uint32]kernelRuleStats) {
	if len(corrections) == 0 {
		return
	}
	for ruleID, delta := range corrections {
		current := dst[ruleID]
		current.TCPActiveConns = clampKernelStatDelta(current.TCPActiveConns, delta.TCPActiveConns)
		current.UDPNatEntries = clampKernelStatDelta(current.UDPNatEntries, delta.UDPNatEntries)
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

func snapshotKernelLiveCountsFromFlows(flowsMap *ebpf.Map) (map[uint32]kernelStatsValueV4, error) {
	out := make(map[uint32]kernelStatsValueV4)
	if flowsMap == nil {
		return out, nil
	}

	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	for iter.Next(&key, &value) {
		if !kernelFlowCountsTowardLiveGauge(value) {
			continue
		}
		item := out[value.RuleID]
		if key.Proto == unix.IPPROTO_UDP {
			item.UDPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		out[value.RuleID] = item
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate kernel flows map for live counts: %w", err)
	}
	return out, nil
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
		}
		if delta.TCPActiveConns == 0 && delta.UDPNatEntries == 0 {
			continue
		}
		out[ruleID] = delta
	}
	return out
}

func reconcileKernelStatsCorrectionFromMaps(statsMap *ebpf.Map, flowsMap *ebpf.Map) (map[uint32]kernelRuleStats, error) {
	observed, err := snapshotKernelStatsValues(statsMap)
	if err != nil {
		return nil, err
	}
	live, err := snapshotKernelLiveCountsFromFlows(flowsMap)
	if err != nil {
		return nil, err
	}
	return kernelLiveStatsCorrection(observed, live), nil
}

func kernelRuleStatsFromValue(value kernelStatsValueV4) kernelRuleStats {
	return kernelRuleStats{
		TCPActiveConns: int64(value.TCPActiveConns),
		UDPNatEntries:  int64(value.UDPNatEntries),
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
	state.fullCursor = tcFlowKeyV4{}
	state.fullCursorValid = false
	state.keys = nil
	state.values = nil
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

func pruneStaleKernelFlowsBatch(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, error) {
	corrections := make(map[uint32]kernelRuleStats)
	remaining := budget

	for remaining > 0 {
		size := min(remaining, kernelFlowMaintenanceBatchSize)
		keys, values := state.ensureBuffers(size)
		n, err := flowsMap.BatchLookup(&state.batchCursor, keys, values, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, err
		}
		if n == 0 {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, nil
		}

		for i := 0; i < n; i++ {
			value := values[i]
			if value.RuleID == 0 {
				continue
			}
			if kernelFlowShouldDelete(keys[i], value, nowNS, haveNow) {
				deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: keys[i], value: value}, corrections)
			}
		}

		remaining -= n
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			state.batchCursor = ebpf.MapBatchCursor{}
			return corrections, nil
		}
	}

	return corrections, nil
}

func pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool) (map[uint32]kernelRuleStats, error) {
	iter := flowsMap.Iterate()
	var key tcFlowKeyV4
	var value tcFlowValueV4
	var staleFlows []staleKernelFlow
	corrections := make(map[uint32]kernelRuleStats)

	for iter.Next(&key, &value) {
		if value.RuleID == 0 {
			continue
		}
		if kernelFlowShouldDelete(key, value, nowNS, haveNow) {
			staleFlows = append(staleFlows, staleKernelFlow{key: key, value: value})
		}
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate kernel flows map: %w", err)
	}

	for _, stale := range staleFlows {
		deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, stale, corrections)
	}
	return corrections, nil
}

func pruneStaleKernelFlowsIncrementalInCollection(rulesMap, flowsMap, natPortsMap *ebpf.Map, nowNS uint64, haveNow bool, state *kernelFlowPruneState, budget int) (map[uint32]kernelRuleStats, error) {
	if state == nil {
		return pruneStaleKernelFlowsFullInCollection(rulesMap, flowsMap, natPortsMap, nowNS, haveNow)
	}
	if budget <= 0 {
		budget = kernelFlowMaintenanceBudgetMin
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
				return corrections, nil
			}
			return nil, fmt.Errorf("iterate kernel flows map: %w", err)
		}
	}

	for scanned := 0; scanned < budget; {
		var next tcFlowKeyV4
		nextValid := false
		if err := flowsMap.NextKey(current, &next); err == nil {
			nextValid = true
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("iterate kernel flows map: %w", err)
		}

		var value tcFlowValueV4
		if err := flowsMap.Lookup(current, &value); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				if !nextValid {
					state.fullCursorValid = false
					state.fullCursor = tcFlowKeyV4{}
					return corrections, nil
				}
				current = next
				state.fullCursor = current
				state.fullCursorValid = true
				continue
			}
			return nil, fmt.Errorf("lookup kernel flow during fallback scan: %w", err)
		}

		if value.RuleID != 0 && kernelFlowShouldDelete(current, value, nowNS, haveNow) {
			deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap, staleKernelFlow{key: current, value: value}, corrections)
		}
		scanned++

		if !nextValid {
			state.fullCursorValid = false
			state.fullCursor = tcFlowKeyV4{}
			return corrections, nil
		}
		current = next
		state.fullCursor = current
		state.fullCursorValid = true
	}

	return corrections, nil
}

func kernelFlowShouldDelete(key tcFlowKeyV4, value tcFlowValueV4, nowNS uint64, haveNow bool) bool {
	if value.Flags&kernelFlowFlagFrontEntry != 0 && value.Flags&kernelFlowFlagFullNAT == 0 {
		return true
	}
	if value.Flags&kernelFlowFlagFullNAT != 0 && (value.NATAddr == 0 || value.NATPort == 0) {
		return true
	}
	if !haveNow {
		return false
	}
	if value.LastSeenNS == 0 || nowNS < value.LastSeenNS {
		return true
	}

	ageNS := nowNS - value.LastSeenNS
	if key.Proto == unix.IPPROTO_UDP {
		return ageNS > kernelUDPFlowIdleTimeout
	}

	if value.Flags&kernelFlowFlagReplySeen == 0 {
		return ageNS > kernelTCPUnrepliedTimeout
	}
	if value.Flags&kernelFlowFlagFrontClosing != 0 {
		closeSeenNS := value.FrontCloseSeenNS
		if closeSeenNS == 0 {
			closeSeenNS = value.LastSeenNS
		}
		return nowNS >= closeSeenNS && (nowNS-closeSeenNS) > kernelTCPClosingGraceNS
	}
	return ageNS > kernelTCPFlowIdleTimeout
}

func deleteStaleKernelFlow(rulesMap, flowsMap, natPortsMap *ebpf.Map, stale staleKernelFlow, corrections map[uint32]kernelRuleStats) {
	if stale.value.Flags&kernelFlowFlagCounted != 0 {
		item := corrections[stale.value.RuleID]
		if stale.key.Proto == unix.IPPROTO_UDP {
			item.UDPNatEntries--
		} else {
			item.TCPActiveConns--
		}
		corrections[stale.value.RuleID] = item
	}

	if err := flowsMap.Delete(stale.key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("kernel dataplane maintenance: delete stale flow failed: proto=%d ifindex=%d src=%d dst=%d sport=%d dport=%d err=%v",
			stale.key.Proto,
			stale.key.IfIndex,
			stale.key.SrcAddr,
			stale.key.DstAddr,
			stale.key.SrcPort,
			stale.key.DstPort,
			err,
		)
	}

	if stale.value.Flags&kernelFlowFlagFullNAT == 0 {
		return
	}

	if stale.value.Flags&kernelFlowFlagFrontEntry == 0 {
		frontKey := tcFlowKeyV4{
			IfIndex: stale.value.InIfIndex,
			SrcAddr: stale.value.ClientAddr,
			DstAddr: stale.value.FrontAddr,
			SrcPort: stale.value.ClientPort,
			DstPort: stale.value.FrontPort,
			Proto:   stale.key.Proto,
		}
		if err := flowsMap.Delete(frontKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			log.Printf("kernel dataplane maintenance: delete stale front flow failed: proto=%d ifindex=%d src=%d dst=%d sport=%d dport=%d err=%v",
				frontKey.Proto,
				frontKey.IfIndex,
				frontKey.SrcAddr,
				frontKey.DstAddr,
				frontKey.SrcPort,
				frontKey.DstPort,
				err,
			)
		}
		deleteStaleKernelNATReservation(natPortsMap, tcNATPortKeyV4{
			IfIndex: stale.key.IfIndex,
			NATAddr: stale.value.NATAddr,
			NATPort: stale.value.NATPort,
			Proto:   stale.key.Proto,
		})
		return
	}

	ruleValue, ok := lookupRuleValueForFrontFlow(rulesMap, stale.key)
	if !ok {
		return
	}

	replyKey := tcFlowKeyV4{
		IfIndex: ruleValue.OutIfIndex,
		SrcAddr: ruleValue.BackendAddr,
		DstAddr: stale.value.NATAddr,
		SrcPort: ruleValue.BackendPort,
		DstPort: stale.value.NATPort,
		Proto:   stale.key.Proto,
	}
	if err := flowsMap.Delete(replyKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		log.Printf("kernel dataplane maintenance: delete stale reply flow failed: proto=%d ifindex=%d src=%d dst=%d sport=%d dport=%d err=%v",
			replyKey.Proto,
			replyKey.IfIndex,
			replyKey.SrcAddr,
			replyKey.DstAddr,
			replyKey.SrcPort,
			replyKey.DstPort,
			err,
		)
	}
	deleteStaleKernelNATReservation(natPortsMap, tcNATPortKeyV4{
		IfIndex: ruleValue.OutIfIndex,
		NATAddr: stale.value.NATAddr,
		NATPort: stale.value.NATPort,
		Proto:   stale.key.Proto,
	})
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
	return tcRuleValueV4{}, false
}

func deleteStaleKernelNATReservation(natPortsMap *ebpf.Map, natKey tcNATPortKeyV4) {
	if natPortsMap == nil || natKey.NATAddr == 0 || natKey.NATPort == 0 {
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
