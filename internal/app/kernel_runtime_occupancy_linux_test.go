//go:build linux

package app

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestClampKernelOccupancyEntries(t *testing.T) {
	tests := []struct {
		name     string
		entries  int64
		capacity uint32
		want     int
	}{
		{name: "negative", entries: -3, capacity: 64, want: 0},
		{name: "zero", entries: 0, capacity: 64, want: 0},
		{name: "within capacity", entries: 17, capacity: 64, want: 17},
		{name: "clamped to capacity", entries: 128, capacity: 64, want: 64},
		{name: "no capacity", entries: 9, capacity: 0, want: 9},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampKernelOccupancyEntries(tc.entries, tc.capacity); got != tc.want {
				t.Fatalf("clampKernelOccupancyEntries(%d, %d) = %d, want %d", tc.entries, tc.capacity, got, tc.want)
			}
		})
	}
}

func TestSyncKernelOccupancyMapForRuntimeRefs(t *testing.T) {
	occupancy := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelOccupancyMapName,
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelOccupancyValueV4{})),
		MaxEntries: 1,
	})
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 64,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 32,
	})

	refs := kernelRuntimeMapRefs{
		occupancy: occupancy,
		flowsV4:   flows,
		natV4:     nat,
	}
	if err := syncKernelOccupancyMapForRuntimeRefs(refs, 11, 7); err != nil {
		t.Fatalf("syncKernelOccupancyMapForRuntimeRefs() error = %v", err)
	}

	key := uint32(0)
	var value kernelOccupancyValueV4
	if err := occupancy.Lookup(key, &value); err != nil {
		t.Fatalf("occupancy.Lookup() error = %v", err)
	}
	if value.FlowEntries != 11 || value.NatEntries != 7 {
		t.Fatalf("occupancy entries = %+v, want flow=11 nat=7", value)
	}
	if value.FlowCapacity != 64 || value.NatCapacity != 32 {
		t.Fatalf("occupancy capacities = flow=%d nat=%d, want 64/32", value.FlowCapacity, value.NatCapacity)
	}
}
