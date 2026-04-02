//go:build linux

package app

import (
	"fmt"
	"strings"
)

type kernelRuntimeDegradedState struct {
	active bool
	reason string
}

func (rt *xdpKernelRuleRuntime) currentMapCapacitiesLocked() kernelMapCapacities {
	capacities := kernelMapCapacities{
		Rules: rt.rulesMapCapacity,
		Flows: rt.flowsMapCapacity,
	}
	if rt.coll == nil || rt.coll.Maps == nil {
		return capacities
	}
	if rulesMap := rt.coll.Maps[kernelRulesMapName]; rulesMap != nil {
		capacities.Rules = int(rulesMap.MaxEntries())
	}
	if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
		capacities.Flows = int(flowsMap.MaxEntries())
	}
	return capacities
}

func tcKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int) kernelRuntimeDegradedState {
	desired := desiredKernelMapCapacities(rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit, preparedEntries, true)
	return buildKernelRuntimeDegradedState(preparedEntries, actual, desired, true)
}

func xdpKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, rulesConfiguredLimit int, flowsConfiguredLimit int) kernelRuntimeDegradedState {
	desired := desiredKernelMapCapacities(rulesConfiguredLimit, flowsConfiguredLimit, 0, preparedEntries, false)
	return buildKernelRuntimeDegradedState(preparedEntries, actual, desired, false)
}

func buildKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, desired kernelMapCapacities, includeNAT bool) kernelRuntimeDegradedState {
	if preparedEntries <= 0 {
		return kernelRuntimeDegradedState{}
	}

	parts := make([]string, 0, 2)
	if actual.Flows > 0 && desired.Flows > actual.Flows {
		parts = append(parts, fmt.Sprintf("%s capacity=%d below desired=%d", kernelFlowsMapName, actual.Flows, desired.Flows))
	}
	if includeNAT && actual.NATPorts > 0 && desired.NATPorts > actual.NATPorts {
		parts = append(parts, fmt.Sprintf("%s capacity=%d below desired=%d", kernelNatPortsMapName, actual.NATPorts, desired.NATPorts))
	}
	if len(parts) == 0 {
		return kernelRuntimeDegradedState{}
	}

	return kernelRuntimeDegradedState{
		active: true,
		reason: fmt.Sprintf(
			"degraded until restart: %s; restart is required to apply larger preserved maps without breaking active sessions",
			strings.Join(parts, ", "),
		),
	}
}
