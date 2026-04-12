//go:build linux

package app

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type kernelOccupancyValueV4 struct {
	FlowEntries  int64
	NatEntries   int64
	FlowCapacity uint32
	NatCapacity  uint32
	Pad          uint32
	PadEnd       [4]byte
}

type kernelFlowLiveStateSnapshot struct {
	ByRuleID    map[uint32]kernelStatsValueV4
	UsedNAT     map[tcNATPortKeyV4]struct{}
	FlowEntries int
}

func newKernelFlowLiveStateSnapshot(includeNAT bool) kernelFlowLiveStateSnapshot {
	out := kernelFlowLiveStateSnapshot{
		ByRuleID: make(map[uint32]kernelStatsValueV4),
	}
	if includeNAT {
		out.UsedNAT = make(map[tcNATPortKeyV4]struct{})
	}
	return out
}

func clampKernelOccupancyEntries(entries int64, capacity uint32) int {
	if entries <= 0 {
		return 0
	}
	if capacity > 0 && entries > int64(capacity) {
		entries = int64(capacity)
	}
	if entries > int64(^uint(0)>>1) {
		return int(^uint(0) >> 1)
	}
	return int(entries)
}

func normalizeKernelOccupancyCapacity(capacity int) uint32 {
	if capacity <= 0 {
		return 0
	}
	if capacity > int(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(capacity)
}

func snapshotKernelOccupancyEntriesWithCapacities(occupancyMap *ebpf.Map, flowCapacity int, natCapacity int, includeNAT bool) (int, int, error) {
	if occupancyMap == nil {
		return 0, 0, errors.New("kernel occupancy map unavailable")
	}

	key := uint32(0)
	var value kernelOccupancyValueV4
	if err := occupancyMap.Lookup(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("lookup kernel occupancy map: %w", err)
	}

	flowCapacityU32 := value.FlowCapacity
	if flowCapacityU32 == 0 {
		flowCapacityU32 = normalizeKernelOccupancyCapacity(flowCapacity)
	}
	natCapacityU32 := value.NatCapacity
	if natCapacityU32 == 0 {
		natCapacityU32 = normalizeKernelOccupancyCapacity(natCapacity)
	}

	flowsEntries := clampKernelOccupancyEntries(value.FlowEntries, flowCapacityU32)
	natEntries := 0
	if includeNAT {
		natEntries = clampKernelOccupancyEntries(value.NatEntries, natCapacityU32)
	}
	return flowsEntries, natEntries, nil
}

func snapshotKernelOccupancyEntries(occupancyMap *ebpf.Map, flowsMap *ebpf.Map, natMap *ebpf.Map, includeNAT bool) (int, int, error) {
	flowCapacity := 0
	if flowsMap != nil {
		flowCapacity = int(flowsMap.MaxEntries())
	}
	natCapacity := 0
	if natMap != nil {
		natCapacity = int(natMap.MaxEntries())
	}
	return snapshotKernelOccupancyEntriesWithCapacities(occupancyMap, flowCapacity, natCapacity, includeNAT)
}

func snapshotKernelRuntimeOccupancyEntries(refs kernelRuntimeMapRefs, includeNAT bool) (int, int, error) {
	return snapshotKernelOccupancyEntriesWithCapacities(
		refs.occupancy,
		kernelRuntimeFlowMapCapacity(refs),
		kernelRuntimeNATMapCapacity(refs),
		includeNAT,
	)
}

func syncKernelOccupancyMap(occupancyMap *ebpf.Map, flowsEntries int, natEntries int, flowCapacity int, natCapacity int) error {
	if occupancyMap == nil {
		return nil
	}
	if flowsEntries < 0 {
		flowsEntries = 0
	}
	if natEntries < 0 {
		natEntries = 0
	}
	if flowCapacity < 0 {
		flowCapacity = 0
	}
	if natCapacity < 0 {
		natCapacity = 0
	}
	if flowCapacity > int(^uint32(0)) {
		flowCapacity = int(^uint32(0))
	}
	if natCapacity > int(^uint32(0)) {
		natCapacity = int(^uint32(0))
	}

	key := uint32(0)
	value := kernelOccupancyValueV4{
		FlowEntries:  int64(flowsEntries),
		NatEntries:   int64(natEntries),
		FlowCapacity: uint32(flowCapacity),
		NatCapacity:  uint32(natCapacity),
	}
	if err := occupancyMap.Put(key, value); err != nil {
		return fmt.Errorf("sync kernel occupancy map: %w", err)
	}
	return nil
}

func syncKernelOccupancyMapForCollection(coll *ebpf.Collection, flowsEntries int, natEntries int) error {
	if coll == nil || coll.Maps == nil {
		return nil
	}
	refs := kernelRuntimeMapRefsFromCollection(coll)
	occupancyMap := refs.occupancy
	if occupancyMap == nil {
		return nil
	}

	return syncKernelOccupancyMap(
		occupancyMap,
		flowsEntries,
		natEntries,
		kernelRuntimeFlowMapCapacity(refs),
		kernelRuntimeNATMapCapacity(refs),
	)
}

func syncKernelOccupancyMapForRuntimeRefs(refs kernelRuntimeMapRefs, flowsEntries int, natEntries int) error {
	return syncKernelOccupancyMap(
		refs.occupancy,
		flowsEntries,
		natEntries,
		kernelRuntimeFlowMapCapacity(refs),
		kernelRuntimeNATMapCapacity(refs),
	)
}

func syncKernelOccupancyMapFromCollectionExact(coll *ebpf.Collection, includeNAT bool) error {
	if coll == nil || coll.Maps == nil {
		return nil
	}

	refs := kernelRuntimeMapRefsFromCollection(coll)
	flowsEntries, err := countKernelRuntimeFlowEntriesExact(refs)
	if err != nil {
		return err
	}
	natEntries := 0
	if includeNAT {
		natEntries, err = countKernelRuntimeNATEntriesExact(refs)
		if err != nil {
			return err
		}
	}
	return syncKernelOccupancyMapForCollection(coll, flowsEntries, natEntries)
}
