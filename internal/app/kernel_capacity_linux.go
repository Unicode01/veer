//go:build linux

package app

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type kernelMapCapacities struct {
	Rules    int
	Flows    int
	NATPorts int
}

// Keep old-bank map symbols loadable without reserving a full spare bank in steady-state.
const kernelOldBankPlaceholderEntries = 1

func desiredKernelMapCapacities(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, includeNAT bool) kernelMapCapacities {
	return desiredKernelMapCapacitiesWithOccupancy(rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, requestedEntries, kernelRuntimeMapCountSnapshot{}, includeNAT, false, false)
}

func desiredKernelMapCapacitiesWithOccupancy(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts kernelRuntimeMapCountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool) kernelMapCapacities {
	flowsBaseLimit := kernelAdaptiveFlowsMapBaseLimit()
	natBaseLimit := kernelAdaptiveNATMapBaseLimit()
	capacities := kernelMapCapacities{
		Rules: effectiveKernelRulesMapLimit(rulesConfiguredLimit, requestedEntries),
		Flows: effectiveKernelFlowsMapLimit(flowsConfiguredLimit, requestedEntries),
	}
	if adaptiveFlows {
		if liveDriven := adaptiveKernelMapLimitForLiveEntries(counts.flowsEntries, flowsBaseLimit, kernelFlowsMapAdaptiveMaxLimit); liveDriven > capacities.Flows {
			capacities.Flows = liveDriven
		}
	}
	if includeNAT {
		capacities.NATPorts = effectiveKernelNATMapLimit(natConfiguredLimit, requestedEntries)
		if adaptiveNAT {
			if liveDriven := adaptiveKernelMapLimitForLiveEntries(counts.natEntries, natBaseLimit, kernelNATMapAdaptiveMaxLimit); liveDriven > capacities.NATPorts {
				capacities.NATPorts = liveDriven
			}
		}
	}
	return capacities
}

func applyKernelMapCapacities(spec *ebpf.CollectionSpec, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, includeNAT bool) (kernelMapCapacities, error) {
	return applyKernelMapCapacitiesWithOccupancy(spec, rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, requestedEntries, kernelRuntimeMapCountSnapshot{}, includeNAT, false, false)
}

func applyKernelMapCapacitiesWithOccupancy(spec *ebpf.CollectionSpec, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, counts kernelRuntimeMapCountSnapshot, includeNAT bool, adaptiveFlows bool, adaptiveNAT bool) (kernelMapCapacities, error) {
	if spec == nil {
		return kernelMapCapacities{}, fmt.Errorf("kernel collection spec is missing")
	}

	capacities := desiredKernelMapCapacitiesWithOccupancy(rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, requestedEntries, counts, includeNAT, adaptiveFlows, adaptiveNAT)

	for _, name := range []string{kernelRulesMapName, kernelStatsMapName} {
		if err := setKernelCollectionMapCapacity(spec, name, capacities.Rules, true, "kernel rules"); err != nil {
			return kernelMapCapacities{}, err
		}
	}
	if err := setKernelCollectionMapCapacity(spec, kernelRulesMapNameV6, capacities.Rules, false, "kernel IPv6 rules"); err != nil {
		return kernelMapCapacities{}, err
	}

	if err := setKernelCollectionMapCapacity(spec, kernelFlowsMapName, capacities.Flows, true, "kernel flows"); err != nil {
		return kernelMapCapacities{}, err
	}
	if err := setKernelCollectionMapCapacity(spec, kernelFlowsMapNameV6, capacities.Flows, false, "kernel IPv6 flows"); err != nil {
		return kernelMapCapacities{}, err
	}
	if err := setKernelCollectionMapCapacity(spec, kernelTCFlowsOldMapNameV4, kernelOldBankPlaceholderEntries, false, "tc old IPv4 flows"); err != nil {
		return kernelMapCapacities{}, err
	}
	if err := setKernelCollectionMapCapacity(spec, kernelTCFlowsOldMapNameV6, kernelOldBankPlaceholderEntries, false, "tc old IPv6 flows"); err != nil {
		return kernelMapCapacities{}, err
	}
	if err := setKernelCollectionMapCapacity(spec, kernelXDPFlowsOldMapNameV4, kernelOldBankPlaceholderEntries, false, "xdp old IPv4 flows"); err != nil {
		return kernelMapCapacities{}, err
	}
	if err := setKernelCollectionMapCapacity(spec, kernelXDPFlowsOldMapNameV6, kernelOldBankPlaceholderEntries, false, "xdp old IPv6 flows"); err != nil {
		return kernelMapCapacities{}, err
	}

	if includeNAT {
		if err := setKernelCollectionMapCapacity(spec, kernelNatPortsMapName, capacities.NATPorts, true, "kernel nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelNatPortsMapNameV6, capacities.NATPorts, false, "kernel IPv6 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelTCNatPortsOldMapNameV4, kernelOldBankPlaceholderEntries, false, "tc old IPv4 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelTCNatPortsOldMapNameV6, kernelOldBankPlaceholderEntries, false, "tc old IPv6 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
	} else {
		if err := setKernelCollectionMapCapacity(spec, kernelNatPortsMapName, kernelOldBankPlaceholderEntries, false, "kernel nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelNatPortsMapNameV6, kernelOldBankPlaceholderEntries, false, "kernel IPv6 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelTCNatPortsOldMapNameV4, kernelOldBankPlaceholderEntries, false, "tc old IPv4 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
		if err := setKernelCollectionMapCapacity(spec, kernelTCNatPortsOldMapNameV6, kernelOldBankPlaceholderEntries, false, "tc old IPv6 nat ports"); err != nil {
			return kernelMapCapacities{}, err
		}
	}

	return capacities, nil
}

func setKernelCollectionMapCapacity(spec *ebpf.CollectionSpec, name string, capacity int, required bool, label string) error {
	if spec == nil {
		return fmt.Errorf("kernel collection spec is missing")
	}
	item := spec.Maps[name]
	if item == nil {
		if required {
			return fmt.Errorf("kernel collection spec is missing map %q", name)
		}
		return nil
	}
	if uint64(capacity) > uint64(^uint32(0)) {
		if label == "" {
			label = "kernel map"
		}
		return fmt.Errorf("%s capacity %d exceeds uint32 limit", label, capacity)
	}
	item.MaxEntries = uint32(capacity)
	return nil
}

func kernelMapReusableWithCapacity(m *ebpf.Map, desiredLimit int) bool {
	if m == nil {
		return false
	}
	return int(m.MaxEntries()) >= desiredLimit
}
