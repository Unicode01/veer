//go:build linux

package app

import (
	"forward/internal/kernelcap"
	"github.com/cilium/ebpf"
)

type kernelMapCapacities = kernelcap.MapCapacities

// Keep old-bank map symbols loadable without reserving a full spare bank in steady-state.
const kernelOldBankPlaceholderEntries = kernelcap.OldBankPlaceholderEntries

func desiredKernelMapCapacitiesWithOccupancy(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts kernelRuntimeMapCountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool) kernelMapCapacities {
	return kernelcap.DesiredMapCapacitiesWithOccupancy(
		rulesConfiguredLimit,
		flowsConfiguredLimit,
		natConfiguredLimit,
		requestedEntries,
		toKernelCapCountSnapshot(counts),
		includeNAT,
		adaptiveFlows,
		adaptiveNAT,
		toKernelCapAdaptiveMapProfile(currentKernelAdaptiveMapProfile()),
	)
}

func applyKernelMapCapacitiesWithOccupancy(spec *ebpf.CollectionSpec, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts kernelRuntimeMapCountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool) (kernelMapCapacities, error) {
	return kernelcap.ApplyMapCapacitiesWithOccupancy(
		spec,
		rulesConfiguredLimit,
		flowsConfiguredLimit,
		natConfiguredLimit,
		requestedEntries,
		toKernelCapCountSnapshot(counts),
		includeNAT,
		adaptiveFlows,
		adaptiveNAT,
		toKernelCapAdaptiveMapProfile(currentKernelAdaptiveMapProfile()),
		kernelCapMapNames(),
	)
}

func setKernelCollectionMapCapacity(spec *ebpf.CollectionSpec, name string, capacity int, required bool, label string) error {
	return kernelcap.SetCollectionMapCapacity(spec, name, capacity, required, label)
}

func kernelMapReusableWithCapacity(m *ebpf.Map, desiredLimit int) bool {
	return kernelcap.MapReusableWithCapacity(m, desiredLimit)
}

func toKernelCapCountSnapshot(counts kernelRuntimeMapCountSnapshot) kernelcap.CountSnapshot {
	return kernelcap.CountSnapshot{
		FlowsEntries: counts.flowsEntries,
		NATEntries:   counts.natEntries,
	}
}

func kernelCapMapNames() kernelcap.MapNames {
	return kernelcap.MapNames{
		Rules:           kernelRulesMapName,
		Stats:           kernelStatsMapName,
		RulesV6:         kernelRulesMapNameV6,
		Flows:           kernelFlowsMapName,
		FlowsV6:         kernelFlowsMapNameV6,
		TCFlowsOldV4:    kernelTCFlowsOldMapNameV4,
		TCFlowsOldV6:    kernelTCFlowsOldMapNameV6,
		XDPFlowsOldV4:   kernelXDPFlowsOldMapNameV4,
		XDPFlowsOldV6:   kernelXDPFlowsOldMapNameV6,
		NATPorts:        kernelNatPortsMapName,
		NATPortsV6:      kernelNatPortsMapNameV6,
		TCNATPortsOldV4: kernelTCNatPortsOldMapNameV4,
		TCNATPortsOldV6: kernelTCNatPortsOldMapNameV6,
	}
}
