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
	)
	if state.active {
		t.Fatalf("xdpKernelRuntimeDegradedState() = active with sufficient capacity, want inactive: %+v", state)
	}
}
