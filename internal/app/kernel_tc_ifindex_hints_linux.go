//go:build linux

package app

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// These mirror FORWARD_TC_IFINDEX_HINT_* in forward-tc-bpf.c.
const (
	kernelTCIfindexHintsMapName = "tc_ifindex_hints"

	kernelTCIfindexHintRuleExact   uint32 = 0x1
	kernelTCIfindexHintRuleAnyAddr uint32 = 0x2
	kernelTCIfindexHintRuleAnyPort uint32 = 0x4
	kernelTCIfindexHintRuleAny     uint32 = 0x8
	kernelTCIfindexHintRuleV6Shift        = 4
	kernelTCIfindexHintHasParent   uint32 = 0x100
	kernelTCIfindexHintKnown       uint32 = 0x80000000
)

// kernelTCIfindexHints tells the TC programs, per ifindex, which rule key
// forms exist and whether a reply parent is mapped, so they can skip lookups
// that cannot match. The hints may claim more than the maps hold, never less:
// they are widened before rules or parents are added and narrowed only after
// the maps have changed.
type kernelTCIfindexHints map[uint32]uint32

func kernelTCRuleFormHint(anyAddr bool, anyPort bool) uint32 {
	switch {
	case anyAddr && anyPort:
		return kernelTCIfindexHintRuleAny
	case anyAddr:
		return kernelTCIfindexHintRuleAnyAddr
	case anyPort:
		return kernelTCIfindexHintRuleAnyPort
	default:
		return kernelTCIfindexHintRuleExact
	}
}

func (h kernelTCIfindexHints) addPreparedRules(prepared []preparedKernelRule) error {
	batches, err := buildPreparedKernelRuleBatches(prepared)
	if err != nil {
		return err
	}
	for _, key := range batches.v4Keys {
		h[key.IfIndex] |= kernelTCRuleFormHint(key.DstAddr == 0, key.DstPort == 0)
	}
	for _, key := range batches.v6Keys {
		h[key.IfIndex] |= kernelTCRuleFormHint(key.DstAddr == [16]byte{}, key.DstPort == 0) << kernelTCIfindexHintRuleV6Shift
	}
	return nil
}

func (h kernelTCIfindexHints) addParents(parents map[uint32]uint32) {
	for child := range parents {
		h[child] |= kernelTCIfindexHintHasParent
	}
}

func buildKernelTCIfindexHints(prepared []preparedKernelRule, parents map[uint32]uint32) (kernelTCIfindexHints, error) {
	hints := make(kernelTCIfindexHints)
	if err := hints.addPreparedRules(prepared); err != nil {
		return nil, err
	}
	hints.addParents(parents)
	return hints, nil
}

func readKernelIfParentMap(m *ebpf.Map) (map[uint32]uint32, error) {
	parents := make(map[uint32]uint32)
	if m == nil {
		return parents, nil
	}
	iter := m.Iterate()
	var child uint32
	var parent uint32
	for iter.Next(&child, &parent) {
		parents[child] = parent
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate kernel reply parent map: %w", err)
	}
	return parents, nil
}

// syncKernelTCIfindexHintsMap marks every ifindex the map covers as known with
// the given hints. Objects without the map are left alone.
func syncKernelTCIfindexHintsMap(m *ebpf.Map, hints kernelTCIfindexHints) error {
	if m == nil {
		return nil
	}
	size := m.MaxEntries()
	keys := make([]uint32, size)
	values := make([]uint32, size)
	for i := range keys {
		keys[i] = uint32(i)
		values[i] = kernelTCIfindexHintKnown | hints[uint32(i)]
	}
	if err := updateKernelMapEntries(m, keys, values); err != nil {
		return fmt.Errorf("update tc ifindex hints: %w", err)
	}
	return nil
}

// widenKernelTCIfindexHints covers both the rules and parents the collection
// holds now and the ones about to be written, so no lookup that may match is
// skipped while the maps change.
func widenKernelTCIfindexHints(coll *ebpf.Collection, current []preparedKernelRule, next []preparedKernelRule, nextParents map[uint32]uint32) error {
	if coll == nil || coll.Maps[kernelTCIfindexHintsMapName] == nil {
		return nil
	}
	currentParents, err := readKernelIfParentMap(coll.Maps[kernelIfParentMapName])
	if err != nil {
		return err
	}
	hints, err := buildKernelTCIfindexHints(current, currentParents)
	if err != nil {
		return err
	}
	if err := hints.addPreparedRules(next); err != nil {
		return err
	}
	hints.addParents(nextParents)
	return syncKernelTCIfindexHintsMap(coll.Maps[kernelTCIfindexHintsMapName], hints)
}

// narrowKernelTCIfindexHints matches the hints to the rules the rule maps
// already hold and to the parent map as it stands. A failure leaves wider
// hints in place, which only costs lookups.
func narrowKernelTCIfindexHints(coll *ebpf.Collection, prepared []preparedKernelRule) error {
	if coll == nil || coll.Maps[kernelTCIfindexHintsMapName] == nil {
		return nil
	}
	parents, err := readKernelIfParentMap(coll.Maps[kernelIfParentMapName])
	if err != nil {
		return err
	}
	hints, err := buildKernelTCIfindexHints(prepared, parents)
	if err != nil {
		return err
	}
	return syncKernelTCIfindexHintsMap(coll.Maps[kernelTCIfindexHintsMapName], hints)
}
