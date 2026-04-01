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

func desiredKernelMapCapacities(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, includeNAT bool) kernelMapCapacities {
	capacities := kernelMapCapacities{
		Rules: effectiveKernelRulesMapLimit(rulesConfiguredLimit, requestedEntries),
		Flows: effectiveKernelFlowsMapLimit(flowsConfiguredLimit, requestedEntries),
	}
	if includeNAT {
		capacities.NATPorts = effectiveKernelNATMapLimit(natConfiguredLimit, requestedEntries)
	}
	return capacities
}

func applyKernelMapCapacities(spec *ebpf.CollectionSpec, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, requestedEntries int, includeNAT bool) (kernelMapCapacities, error) {
	if spec == nil {
		return kernelMapCapacities{}, fmt.Errorf("kernel collection spec is missing")
	}

	capacities := desiredKernelMapCapacities(rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, requestedEntries, includeNAT)

	for _, name := range []string{kernelRulesMapName, kernelStatsMapName} {
		item := spec.Maps[name]
		if item == nil {
			return kernelMapCapacities{}, fmt.Errorf("kernel collection spec is missing map %q", name)
		}
		if uint64(capacities.Rules) > uint64(^uint32(0)) {
			return kernelMapCapacities{}, fmt.Errorf("kernel rules map capacity %d exceeds uint32 limit", capacities.Rules)
		}
		item.MaxEntries = uint32(capacities.Rules)
	}

	flows := spec.Maps[kernelFlowsMapName]
	if flows == nil {
		return kernelMapCapacities{}, fmt.Errorf("kernel collection spec is missing map %q", kernelFlowsMapName)
	}
	if uint64(capacities.Flows) > uint64(^uint32(0)) {
		return kernelMapCapacities{}, fmt.Errorf("kernel flows map capacity %d exceeds uint32 limit", capacities.Flows)
	}
	flows.MaxEntries = uint32(capacities.Flows)

	if includeNAT {
		nat := spec.Maps[kernelNatPortsMapName]
		if nat == nil {
			return kernelMapCapacities{}, fmt.Errorf("kernel collection spec is missing map %q", kernelNatPortsMapName)
		}
		if uint64(capacities.NATPorts) > uint64(^uint32(0)) {
			return kernelMapCapacities{}, fmt.Errorf("kernel nat ports map capacity %d exceeds uint32 limit", capacities.NATPorts)
		}
		nat.MaxEntries = uint32(capacities.NATPorts)
	}

	return capacities, nil
}

func kernelMapReusableWithCapacity(m *ebpf.Map, desiredLimit int) bool {
	if m == nil {
		return false
	}
	return int(m.MaxEntries()) >= desiredLimit
}
