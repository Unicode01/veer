//go:build linux

package app

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestApplyKernelMapCapacitiesWithOccupancySetsOptionalIPv6Maps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:         &ebpf.MapSpec{Name: kernelRulesMapNameV4},
			kernelRulesMapNameV6:         &ebpf.MapSpec{Name: kernelRulesMapNameV6},
			kernelStatsMapName:           &ebpf.MapSpec{Name: kernelStatsMapName},
			kernelFlowsMapNameV4:         &ebpf.MapSpec{Name: kernelFlowsMapNameV4},
			kernelFlowsMapNameV6:         &ebpf.MapSpec{Name: kernelFlowsMapNameV6},
			kernelTCFlowsOldMapNameV4:    &ebpf.MapSpec{Name: kernelTCFlowsOldMapNameV4},
			kernelTCFlowsOldMapNameV6:    &ebpf.MapSpec{Name: kernelTCFlowsOldMapNameV6},
			kernelNatPortsMapNameV4:      &ebpf.MapSpec{Name: kernelNatPortsMapNameV4},
			kernelNatPortsMapNameV6:      &ebpf.MapSpec{Name: kernelNatPortsMapNameV6},
			kernelTCNatPortsOldMapNameV4: &ebpf.MapSpec{Name: kernelTCNatPortsOldMapNameV4},
			kernelTCNatPortsOldMapNameV6: &ebpf.MapSpec{Name: kernelTCNatPortsOldMapNameV6},
		},
	}

	capacities, err := applyKernelMapCapacitiesWithOccupancy(spec, 0, 0, 0, 64, kernelRuntimeMapCountSnapshot{}, true, false, false)
	if err != nil {
		t.Fatalf("applyKernelMapCapacitiesWithOccupancy() error = %v", err)
	}
	if capacities.Rules <= 0 || capacities.Flows <= 0 || capacities.NATPorts <= 0 {
		t.Fatalf("applyKernelMapCapacitiesWithOccupancy() capacities = %+v, want positive capacities", capacities)
	}
	if got := spec.Maps[kernelRulesMapNameV4].MaxEntries; got != uint32(capacities.Rules) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelRulesMapNameV4, got, capacities.Rules)
	}
	if got := spec.Maps[kernelRulesMapNameV6].MaxEntries; got != uint32(capacities.Rules) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelRulesMapNameV6, got, capacities.Rules)
	}
	if got := spec.Maps[kernelFlowsMapNameV4].MaxEntries; got != uint32(capacities.Flows) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelFlowsMapNameV4, got, capacities.Flows)
	}
	if got := spec.Maps[kernelFlowsMapNameV6].MaxEntries; got != uint32(capacities.Flows) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelFlowsMapNameV6, got, capacities.Flows)
	}
	if got := spec.Maps[kernelTCFlowsOldMapNameV4].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelTCFlowsOldMapNameV4, got, kernelOldBankPlaceholderEntries)
	}
	if got := spec.Maps[kernelTCFlowsOldMapNameV6].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelTCFlowsOldMapNameV6, got, kernelOldBankPlaceholderEntries)
	}
	if got := spec.Maps[kernelNatPortsMapNameV4].MaxEntries; got != uint32(capacities.NATPorts) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelNatPortsMapNameV4, got, capacities.NATPorts)
	}
	if got := spec.Maps[kernelNatPortsMapNameV6].MaxEntries; got != uint32(capacities.NATPorts) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelNatPortsMapNameV6, got, capacities.NATPorts)
	}
	if got := spec.Maps[kernelTCNatPortsOldMapNameV4].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelTCNatPortsOldMapNameV4, got, kernelOldBankPlaceholderEntries)
	}
	if got := spec.Maps[kernelTCNatPortsOldMapNameV6].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelTCNatPortsOldMapNameV6, got, kernelOldBankPlaceholderEntries)
	}
}

func TestApplyKernelMapCapacitiesWithOccupancySetsOptionalXDPFlowBanks(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:       &ebpf.MapSpec{Name: kernelRulesMapNameV4},
			kernelStatsMapName:         &ebpf.MapSpec{Name: kernelStatsMapName},
			kernelFlowsMapNameV4:       &ebpf.MapSpec{Name: kernelFlowsMapNameV4},
			kernelXDPFlowsOldMapNameV4: &ebpf.MapSpec{Name: kernelXDPFlowsOldMapNameV4},
			kernelXDPFlowsOldMapNameV6: &ebpf.MapSpec{Name: kernelXDPFlowsOldMapNameV6},
		},
	}

	_, err := applyKernelMapCapacitiesWithOccupancy(spec, 0, 0, 0, 64, kernelRuntimeMapCountSnapshot{}, false, false, false)
	if err != nil {
		t.Fatalf("applyKernelMapCapacitiesWithOccupancy() error = %v", err)
	}
	if got := spec.Maps[kernelXDPFlowsOldMapNameV4].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelXDPFlowsOldMapNameV4, got, kernelOldBankPlaceholderEntries)
	}
	if got := spec.Maps[kernelXDPFlowsOldMapNameV6].MaxEntries; got != uint32(kernelOldBankPlaceholderEntries) {
		t.Fatalf("%s MaxEntries = %d, want %d", kernelXDPFlowsOldMapNameV6, got, kernelOldBankPlaceholderEntries)
	}
}

func TestApplyKernelMapCapacitiesWithOccupancyAllowsSpecWithoutIPv6Maps(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:         &ebpf.MapSpec{Name: kernelRulesMapNameV4},
			kernelStatsMapName:           &ebpf.MapSpec{Name: kernelStatsMapName},
			kernelFlowsMapNameV4:         &ebpf.MapSpec{Name: kernelFlowsMapNameV4},
			kernelNatPortsMapNameV4:      &ebpf.MapSpec{Name: kernelNatPortsMapNameV4},
			kernelTCFlowsOldMapNameV4:    &ebpf.MapSpec{Name: kernelTCFlowsOldMapNameV4},
			kernelTCNatPortsOldMapNameV4: &ebpf.MapSpec{Name: kernelTCNatPortsOldMapNameV4},
		},
	}

	if _, err := applyKernelMapCapacitiesWithOccupancy(spec, 0, 0, 0, 32, kernelRuntimeMapCountSnapshot{}, true, false, false); err != nil {
		t.Fatalf("applyKernelMapCapacitiesWithOccupancy() error = %v, want nil", err)
	}
}
