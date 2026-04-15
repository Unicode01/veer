//go:build linux

package app

import (
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestBuildKernelRuntimePressureStateLevels(t *testing.T) {
	cases := []struct {
		name          string
		previousLevel kernelRuntimePressureLevel
		flowsEntries  int
		wantLevel     kernelRuntimePressureLevel
		wantText      string
	}{
		{
			name:         "below hold watermark stays clear",
			flowsEntries: 91,
			wantLevel:    kernelRuntimePressureLevelNone,
		},
		{
			name:         "hold watermark keeps existing owners",
			flowsEntries: 92,
			wantLevel:    kernelRuntimePressureLevelHold,
			wantText:     "keeping existing kernel owners",
		},
		{
			name:         "shed watermark drops subset",
			flowsEntries: 96,
			wantLevel:    kernelRuntimePressureLevelShed,
			wantText:     "shedding a subset of kernel owners",
		},
		{
			name:         "full watermark routes all owners out",
			flowsEntries: 99,
			wantLevel:    kernelRuntimePressureLevelFull,
			wantText:     "routing all kernel owners to userspace",
		},
		{
			name:          "active pressure holds until release watermark",
			previousLevel: kernelRuntimePressureLevelShed,
			flowsEntries:  90,
			wantLevel:     kernelRuntimePressureLevelHold,
			wantText:      "keeping existing kernel owners",
		},
		{
			name:          "pressure clears below release watermark",
			previousLevel: kernelRuntimePressureLevelHold,
			flowsEntries:  84,
			wantLevel:     kernelRuntimePressureLevelNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := buildKernelRuntimePressureState(tc.previousLevel, tc.flowsEntries, 100, 0, 0, false)
			if state.level != tc.wantLevel {
				t.Fatalf("buildKernelRuntimePressureState() level = %q, want %q", state.level, tc.wantLevel)
			}
			if tc.wantLevel == kernelRuntimePressureLevelNone {
				if state.active {
					t.Fatalf("buildKernelRuntimePressureState() active = true, want false for level %q", tc.wantLevel)
				}
				return
			}
			if !state.active {
				t.Fatalf("buildKernelRuntimePressureState() active = false, want true for level %q", tc.wantLevel)
			}
			if !strings.Contains(state.reason, tc.wantText) {
				t.Fatalf("buildKernelRuntimePressureState() reason = %q, want substring %q", state.reason, tc.wantText)
			}
		})
	}
}

func TestBuildKernelRuntimePressureStateUsesNATPressure(t *testing.T) {
	state := buildKernelRuntimePressureState(kernelRuntimePressureLevelNone, 8, 100, 96, 100, true)
	if state.level != kernelRuntimePressureLevelShed {
		t.Fatalf("buildKernelRuntimePressureState() level = %q, want %q", state.level, kernelRuntimePressureLevelShed)
	}
	if !state.active {
		t.Fatal("buildKernelRuntimePressureState() active = false, want true")
	}
	if !strings.Contains(state.reason, "nat ") {
		t.Fatalf("buildKernelRuntimePressureState() reason = %q, want NAT pressure detail", state.reason)
	}
	if !strings.Contains(state.reason, "shedding a subset of kernel owners") {
		t.Fatalf("buildKernelRuntimePressureState() reason = %q, want shed guidance", state.reason)
	}
}

func TestTCKernelRuntimePressureUsesExactCountsWhenOccupancyIsZero(t *testing.T) {
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
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 1,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err := flows.Put(tcFlowKeyV4{IfIndex: 1}, tcFlowValueV4{RuleID: 1}); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}
	if err := nat.Put(tcNATPortKeyV4{IfIndex: 1}, uint32(1)); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	rt := &linuxKernelRuleRuntime{
		available:        true,
		coll:             &ebpf.Collection{Maps: map[string]*ebpf.Map{kernelOccupancyMapName: occupancy, kernelFlowsMapNameV4: flows, kernelNatPortsMapNameV4: nat}},
		preparedRules:    []preparedKernelRule{{rule: Rule{ID: 1}}},
		flowsMapCapacity: 1,
		natMapCapacity:   1,
	}

	state := rt.refreshPressureLocked(time.Now())
	if state.level != kernelRuntimePressureLevelFull {
		t.Fatalf("refreshPressureLocked() level = %q, want %q", state.level, kernelRuntimePressureLevelFull)
	}
	if state.flowsEntries != 1 || state.natEntries != 1 {
		t.Fatalf("refreshPressureLocked() entries = flows:%d nat:%d, want 1/1", state.flowsEntries, state.natEntries)
	}
}

func TestXDPKernelRuntimePressureUsesExactFlowCountsWhenOccupancyIsZero(t *testing.T) {
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
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 1,
	})
	if err := flows.Put(tcFlowKeyV4{IfIndex: 1}, xdpFlowValueV4{RuleID: 1}); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}

	rt := &xdpKernelRuleRuntime{
		available:        true,
		coll:             &ebpf.Collection{Maps: map[string]*ebpf.Map{kernelOccupancyMapName: occupancy, kernelFlowsMapNameV4: flows}},
		preparedRules:    []preparedXDPKernelRule{{rule: Rule{ID: 1}}},
		flowsMapCapacity: 1,
	}

	state := rt.refreshPressureLocked(time.Now())
	if state.level != kernelRuntimePressureLevelFull {
		t.Fatalf("refreshPressureLocked() level = %q, want %q", state.level, kernelRuntimePressureLevelFull)
	}
	if state.flowsEntries != 1 {
		t.Fatalf("refreshPressureLocked() flowsEntries = %d, want 1", state.flowsEntries)
	}
}
