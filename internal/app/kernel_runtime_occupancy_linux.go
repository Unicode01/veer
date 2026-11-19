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
	ByRuleID           map[uint32]kernelStatsValueV4
	UsedNATV4          map[kernelNATReservationOwnerV4]struct{}
	UsedNATV6          map[kernelNATReservationOwnerV6]struct{}
	UsedNATPeersV4     map[kernelNATPeerOwnerV4]struct{}
	UsedNATPeersV6     map[kernelNATPeerOwnerV6]struct{}
	NATByBank          kernelNATBankUsage
	OrphanFrontsByBank kernelFlowOrphanBankSnapshot
	FlowEntries        int
	orphanFrontsV4     map[staleKernelFlow]struct{}
	orphanFrontsV6     map[staleKernelFlowV6]struct{}
}

type kernelNATBankUsage struct {
	activeV4      map[kernelNATReservationOwnerV4]struct{}
	oldV4         map[kernelNATReservationOwnerV4]struct{}
	activeV6      map[kernelNATReservationOwnerV6]struct{}
	oldV6         map[kernelNATReservationOwnerV6]struct{}
	peersActiveV4 map[kernelNATPeerOwnerV4]struct{}
	peersOldV4    map[kernelNATPeerOwnerV4]struct{}
	peersActiveV6 map[kernelNATPeerOwnerV6]struct{}
	peersOldV6    map[kernelNATPeerOwnerV6]struct{}
}

type kernelNATReservationOwnerV4 struct {
	Key       tcNATPortKeyV4
	SessionID uint64
}

type kernelNATReservationOwnerV6 struct {
	Key       tcNATPortKeyV6
	SessionID uint64
}

// kernelNATPeerOwner is the flow session a NAT peer entry belongs to.
type kernelNATPeerOwner[K comparable] struct {
	Key       K
	SessionID uint64
}

type kernelNATPeerOwnerV4 = kernelNATPeerOwner[tcNATPeerKeyV4]
type kernelNATPeerOwnerV6 = kernelNATPeerOwner[tcNATPeerKeyV6]

// kernelNATPeerKey is a NAT peer map key; class gives the key of the shared
// port it uses.
type kernelNATPeerKey[C comparable] interface {
	comparable
	class() C
}

func (key tcNATPeerKeyV4) class() tcNATPortKeyV4 { return key.Port }

func (key tcNATPeerKeyV6) class() tcNATPortKeyV6 { return key.Port }

// kernelNATBankMaps are one bank's NAT maps of one address family: the port
// classes and the mappings on shared ports.
type kernelNATBankMaps struct {
	ports *ebpf.Map
	peers *ebpf.Map
}

func (refs kernelRuntimeMapRefs) natBankV4() kernelNATBankMaps {
	return kernelNATBankMaps{ports: refs.natV4, peers: refs.natPeersV4}
}

func (refs kernelRuntimeMapRefs) natOldBankV4() kernelNATBankMaps {
	return kernelNATBankMaps{ports: refs.natOldV4, peers: refs.natPeersOldV4}
}

func (refs kernelRuntimeMapRefs) natBankV6() kernelNATBankMaps {
	return kernelNATBankMaps{ports: refs.natV6, peers: refs.natPeersV6}
}

func (refs kernelRuntimeMapRefs) natOldBankV6() kernelNATBankMaps {
	return kernelNATBankMaps{ports: refs.natOldV6, peers: refs.natPeersOldV6}
}

func newKernelFlowLiveStateSnapshot(includeNAT bool) kernelFlowLiveStateSnapshot {
	out := kernelFlowLiveStateSnapshot{
		ByRuleID: make(map[uint32]kernelStatsValueV4),
	}
	if includeNAT {
		out.UsedNATV4 = make(map[kernelNATReservationOwnerV4]struct{})
		out.UsedNATV6 = make(map[kernelNATReservationOwnerV6]struct{})
		out.UsedNATPeersV4 = make(map[kernelNATPeerOwnerV4]struct{})
		out.UsedNATPeersV6 = make(map[kernelNATPeerOwnerV6]struct{})
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
	if uint64(capacity) > uint64(^uint32(0)) {
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

	key := uint32(0)
	value := kernelOccupancyValueV4{
		FlowEntries:  int64(flowsEntries),
		NatEntries:   int64(natEntries),
		FlowCapacity: normalizeKernelOccupancyCapacity(flowCapacity),
		NatCapacity:  normalizeKernelOccupancyCapacity(natCapacity),
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
