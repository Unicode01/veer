//go:build linux

package app

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

func TestTCKernelRuntimeDegradedState(t *testing.T) {
	state := tcKernelRuntimeDegradedState(
		40000,
		kernelMapCapacities{
			Rules:    65536,
			Flows:    131072,
			NATPorts: 131072,
		},
		kernelRuntimeMapCountSnapshot{},
		0,
		0,
		0,
		false,
		kernelRuntimeDegradedSourceHotRestart,
	)
	if !state.active {
		t.Fatal("tcKernelRuntimeDegradedState() = inactive, want active")
	}
	if !strings.Contains(state.reason, kernelFlowsMapName) {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want flows map detail", state.reason)
	}
	if !strings.Contains(state.reason, kernelNatPortsMapName) {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want nat map detail", state.reason)
	}
}

func TestKernelRuntimeDegradedStateSkipsZeroPreparedEntries(t *testing.T) {
	state := tcKernelRuntimeDegradedState(
		0,
		kernelMapCapacities{
			Rules:    16384,
			Flows:    65536,
			NATPorts: 65536,
		},
		kernelRuntimeMapCountSnapshot{},
		0,
		0,
		0,
		false,
		kernelRuntimeDegradedSourceNone,
	)
	if state.active {
		t.Fatalf("tcKernelRuntimeDegradedState() = active with zero prepared entries, want inactive: %+v", state)
	}
}

func TestXDPKernelRuntimeDegradedStateIgnoresSatisfiedCapacity(t *testing.T) {
	state := xdpKernelRuntimeDegradedState(
		16384,
		kernelMapCapacities{
			Rules: 16384,
			Flows: 262144,
		},
		kernelRuntimeMapCountSnapshot{},
		0,
		0,
		0,
		false,
		kernelRuntimeDegradedSourceNone,
	)
	if state.active {
		t.Fatalf("xdpKernelRuntimeDegradedState() = active with sufficient capacity, want inactive: %+v", state)
	}
}

func TestTCKernelRuntimeDegradedStateMentionsHotRestart(t *testing.T) {
	state := tcKernelRuntimeDegradedState(
		40000,
		kernelMapCapacities{
			Rules:    65536,
			Flows:    131072,
			NATPorts: 131072,
		},
		kernelRuntimeMapCountSnapshot{},
		0,
		0,
		0,
		false,
		kernelRuntimeDegradedSourceHotRestart,
	)
	if !strings.Contains(state.reason, "hot restart") {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want hot restart hint", state.reason)
	}
	if !strings.Contains(state.reason, "cold restart") {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want cold restart guidance", state.reason)
	}
}

func TestTCKernelRuntimeDegradedStateUsesEgressNATAutoMapFloor(t *testing.T) {
	autoFloor := kernelAdaptiveEgressNATAutoMapFloor()
	actualCapacity := autoFloor / 2
	if actualCapacity <= 0 {
		actualCapacity = 1
	}

	state := tcKernelRuntimeDegradedState(
		128,
		kernelMapCapacities{
			Rules:    16384,
			Flows:    actualCapacity,
			NATPorts: actualCapacity,
		},
		kernelRuntimeMapCountSnapshot{},
		0,
		0,
		0,
		true,
		kernelRuntimeDegradedSourceNone,
	)
	if !state.active {
		t.Fatalf(
			"tcKernelRuntimeDegradedState() = inactive, want active when egress nat auto floor=%d raises desired flow/nat capacity above actual=%d",
			autoFloor,
			actualCapacity,
		)
	}
	if !strings.Contains(state.reason, kernelFlowsMapName) {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want flows map detail", state.reason)
	}
	if !strings.Contains(state.reason, kernelNatPortsMapName) {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want nat map detail", state.reason)
	}
}

func TestTCKernelRuntimeDegradedStateUsesLiveOccupancyForAdaptiveGrowth(t *testing.T) {
	state := tcKernelRuntimeDegradedState(
		8,
		kernelMapCapacities{
			Rules:    16384,
			Flows:    262144,
			NATPorts: 262144,
		},
		kernelRuntimeMapCountSnapshot{
			flowsEntries: 200000,
			natEntries:   200000,
		},
		0,
		0,
		0,
		false,
		kernelRuntimeDegradedSourceLivePreserve,
	)
	if !state.active {
		t.Fatal("tcKernelRuntimeDegradedState() = inactive, want active when live occupancy requires a larger adaptive flow/nat map")
	}
	if !strings.Contains(state.reason, "desired=524288") {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want occupancy-driven desired capacity", state.reason)
	}
}

func TestKernelRuntimeCanGrowMapsWhenIdle(t *testing.T) {
	actual := kernelMapCapacities{Rules: 16384, Flows: 131072, NATPorts: 131072}
	desired := kernelMapCapacities{Rules: 16384, Flows: 262144, NATPorts: 262144}
	if !kernelRuntimeCanGrowMapsWhenIdle(actual, desired, kernelRuntimeMapCountSnapshot{}, true) {
		t.Fatal("kernelRuntimeCanGrowMapsWhenIdle() = false, want true when flow/nat maps are empty")
	}
	if kernelRuntimeCanGrowMapsWhenIdle(actual, desired, kernelRuntimeMapCountSnapshot{flowsEntries: 1}, true) {
		t.Fatal("kernelRuntimeCanGrowMapsWhenIdle() = true with live flows, want false")
	}
	if kernelRuntimeCanGrowMapsWhenIdle(actual, desired, kernelRuntimeMapCountSnapshot{natEntries: 1}, true) {
		t.Fatal("kernelRuntimeCanGrowMapsWhenIdle() = true with live nat entries, want false")
	}
}

func TestKernelRuntimeCountsForIdleGrowthDecisionUsesExactCountsWhenCacheIsZero(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  4,
		MaxEntries: 16,
	})
	if err := flows.Put(tcFlowKeyV4{IfIndex: 1}, tcFlowValueV4{RuleID: 1}); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}
	if err := nat.Put(tcNATPortKeyV4{IfIndex: 1}, uint32(1)); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	got := kernelRuntimeCountsForIdleGrowthDecision(
		kernelRuntimeMapRefs{flowsV4: flows, natV4: nat},
		kernelRuntimeMapCountSnapshot{},
		true,
		"test",
	)
	if got.flowsEntries != 1 {
		t.Fatalf("flowsEntries = %d, want 1", got.flowsEntries)
	}
	if got.natEntries != 1 {
		t.Fatalf("natEntries = %d, want 1", got.natEntries)
	}
}

func TestKernelRuntimeIdleDegradedRebuildReason(t *testing.T) {
	view := KernelEngineRuntimeView{
		Name:            kernelEngineTC,
		Loaded:          true,
		ActiveEntries:   8,
		Degraded:        true,
		FlowsMapEntries: 0,
		NATMapEntries:   0,
	}
	if reason := kernelRuntimeIdleDegradedRebuildReason(view); reason == "" {
		t.Fatal("kernelRuntimeIdleDegradedRebuildReason() = empty, want auto-heal reason")
	}
	view.NATMapEntries = 3
	if reason := kernelRuntimeIdleDegradedRebuildReason(view); reason != "" {
		t.Fatalf("kernelRuntimeIdleDegradedRebuildReason() = %q with live nat entries, want empty", reason)
	}

	view = KernelEngineRuntimeView{
		Name:            kernelEngineXDP,
		Loaded:          true,
		ActiveEntries:   8,
		Degraded:        true,
		FlowsMapEntries: 0,
		NATMapEntries:   3,
	}
	if reason := kernelRuntimeIdleDegradedRebuildReason(view); reason != "" {
		t.Fatalf("kernelRuntimeIdleDegradedRebuildReason() = %q for xdp with live nat entries, want empty", reason)
	}
}
