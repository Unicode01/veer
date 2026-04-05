//go:build linux

package app

import (
	"strings"
	"testing"
)

func TestTCKernelRuntimeDegradedState(t *testing.T) {
	state := tcKernelRuntimeDegradedState(
		40000,
		kernelMapCapacities{
			Rules:    65536,
			Flows:    131072,
			NATPorts: 131072,
		},
		0,
		0,
		0,
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
		0,
		0,
		0,
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
			Flows: 131072,
		},
		0,
		0,
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
		0,
		0,
		0,
		kernelRuntimeDegradedSourceHotRestart,
	)
	if !strings.Contains(state.reason, "hot restart") {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want hot restart hint", state.reason)
	}
	if !strings.Contains(state.reason, "cold restart") {
		t.Fatalf("tcKernelRuntimeDegradedState() reason = %q, want cold restart guidance", state.reason)
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
}
