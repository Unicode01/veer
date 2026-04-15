//go:build linux

package app

import (
	"fmt"
	"log"
	"strings"
	"time"
)

type kernelRuntimeDegradedState struct {
	active bool
	reason string
}

const (
	kernelRuntimeDegradedSourceNone         = ""
	kernelRuntimeDegradedSourceHotRestart   = "hot_restart"
	kernelRuntimeDegradedSourceLivePreserve = "live_preserve"
)

func (rt *xdpKernelRuleRuntime) currentMapCapacitiesLocked() kernelMapCapacities {
	capacities := kernelMapCapacities{
		Rules:    rt.rulesMapCapacity,
		Flows:    rt.flowsMapCapacity,
		NATPorts: rt.natMapCapacity,
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
	if natMap := rt.coll.Maps[kernelNatPortsMapName]; natMap != nil {
		capacities.NATPorts = int(natMap.MaxEntries())
	}
	return capacities
}

func preparedKernelRulesNeedEgressNATAutoMapFloors(prepared []preparedKernelRule) bool {
	for _, item := range prepared {
		if isKernelEgressNATRule(item.rule) || isKernelEgressNATPassthroughRule(item.rule) {
			return true
		}
	}
	return false
}

func tcKernelRuntimeConfiguredMapLimits(rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, useEgressNATAutoFloors bool) (int, int, int) {
	flowsConfiguredLimit, natConfiguredLimit = kernelEgressNATAutoMapFloors(flowsConfiguredLimit, natConfiguredLimit, useEgressNATAutoFloors)
	return rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit
}

func (rt *linuxKernelRuleRuntime) shouldPreferFreshMapGrowthLocked(desired kernelMapCapacities) bool {
	actual := rt.currentMapCapacitiesLocked()
	if !kernelRuntimeNeedsMapGrowth(actual, desired, true) {
		return false
	}
	counts := rt.currentRuntimeMapCountsLocked(time.Now())
	if rt.coll != nil && rt.coll.Maps != nil {
		counts = kernelRuntimeCountsForIdleGrowthDecision(
			kernelRuntimeMapRefsFromCollection(rt.coll),
			counts,
			true,
			"kernel dataplane map growth",
		)
	}
	return kernelRuntimeCanGrowMapsWhenIdle(actual, desired, counts, true)
}

func (rt *xdpKernelRuleRuntime) shouldPreferFreshMapGrowthLocked(desired kernelMapCapacities) bool {
	actual := rt.currentMapCapacitiesLocked()
	includeNAT := desired.NATPorts > 0
	if !kernelRuntimeNeedsMapGrowth(actual, desired, includeNAT) {
		return false
	}
	counts := rt.currentRuntimeMapCountsLocked(time.Now())
	if rt.coll != nil && rt.coll.Maps != nil {
		counts = kernelRuntimeCountsForIdleGrowthDecision(
			kernelRuntimeMapRefsFromCollection(rt.coll),
			counts,
			includeNAT,
			"xdp dataplane map growth",
		)
	}
	return kernelRuntimeCanGrowMapsWhenIdle(actual, desired, counts, includeNAT)
}

func tcKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, counts kernelRuntimeMapCountSnapshot, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, useEgressNATAutoFloors bool, source string) kernelRuntimeDegradedState {
	rulesConfiguredLimit, flowsConfiguredLimit, natConfiguredLimit = tcKernelRuntimeConfiguredMapLimits(
		rulesConfiguredLimit,
		flowsConfiguredLimit,
		natConfiguredLimit,
		useEgressNATAutoFloors,
	)
	desired := desiredKernelMapCapacitiesWithOccupancy(
		rulesConfiguredLimit,
		flowsConfiguredLimit,
		natConfiguredLimit,
		preparedEntries,
		counts,
		true,
		normalizeKernelFlowsMapLimit(flowsConfiguredLimit) == 0 || useEgressNATAutoFloors,
		normalizeKernelNATMapLimit(natConfiguredLimit) == 0 || useEgressNATAutoFloors,
	)
	return buildKernelRuntimeDegradedState(preparedEntries, actual, desired, true, source)
}

func xdpKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, counts kernelRuntimeMapCountSnapshot, rulesConfiguredLimit int, flowsConfiguredLimit int, natConfiguredLimit int, includeNAT bool, source string) kernelRuntimeDegradedState {
	desired := desiredKernelMapCapacitiesWithOccupancy(
		rulesConfiguredLimit,
		flowsConfiguredLimit,
		natConfiguredLimit,
		preparedEntries,
		counts,
		includeNAT,
		normalizeKernelFlowsMapLimit(flowsConfiguredLimit) == 0,
		includeNAT && normalizeKernelNATMapLimit(natConfiguredLimit) == 0,
	)
	return buildKernelRuntimeDegradedState(preparedEntries, actual, desired, includeNAT, source)
}

func buildKernelRuntimeDegradedState(preparedEntries int, actual kernelMapCapacities, desired kernelMapCapacities, includeNAT bool, source string) kernelRuntimeDegradedState {
	if preparedEntries <= 0 {
		return kernelRuntimeDegradedState{}
	}

	parts := kernelRuntimeMapGrowthDetails(actual, desired, includeNAT)
	if len(parts) == 0 {
		return kernelRuntimeDegradedState{}
	}

	suffix := "restart is required to apply larger preserved maps without breaking active sessions"
	switch source {
	case kernelRuntimeDegradedSourceHotRestart:
		suffix = "hot restart preserved smaller flow maps to keep existing sessions alive; a cold restart is required to grow capacity"
	case kernelRuntimeDegradedSourceLivePreserve:
		suffix = "live updates kept smaller flow maps to avoid breaking active sessions; the runtime can self-heal after flows drain or via a cold restart"
	}

	return kernelRuntimeDegradedState{
		active: true,
		reason: fmt.Sprintf(
			"degraded: %s; %s",
			strings.Join(parts, ", "),
			suffix,
		),
	}
}

func kernelRuntimeMapGrowthDetails(actual kernelMapCapacities, desired kernelMapCapacities, includeNAT bool) []string {
	parts := make([]string, 0, 2)
	if actual.Flows > 0 && desired.Flows > actual.Flows {
		parts = append(parts, fmt.Sprintf("%s capacity=%d below desired=%d", kernelFlowsMapName, actual.Flows, desired.Flows))
	}
	if includeNAT && actual.NATPorts > 0 && desired.NATPorts > actual.NATPorts {
		parts = append(parts, fmt.Sprintf("%s capacity=%d below desired=%d", kernelNatPortsMapName, actual.NATPorts, desired.NATPorts))
	}
	return parts
}

func kernelRuntimeNeedsMapGrowth(actual kernelMapCapacities, desired kernelMapCapacities, includeNAT bool) bool {
	return len(kernelRuntimeMapGrowthDetails(actual, desired, includeNAT)) > 0
}

func kernelRuntimeCanGrowMapsWhenIdle(actual kernelMapCapacities, desired kernelMapCapacities, counts kernelRuntimeMapCountSnapshot, includeNAT bool) bool {
	flowsNeedGrowth := actual.Flows > 0 && desired.Flows > actual.Flows
	natNeedGrowth := includeNAT && actual.NATPorts > 0 && desired.NATPorts > actual.NATPorts
	if !flowsNeedGrowth && !natNeedGrowth {
		return false
	}
	if flowsNeedGrowth && counts.flowsEntries > 0 {
		return false
	}
	if natNeedGrowth && counts.natEntries > 0 {
		return false
	}
	return true
}

func kernelRuntimeCountsForIdleGrowthDecision(refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, includeNAT bool, context string) kernelRuntimeMapCountSnapshot {
	if counts.flowsEntries <= 0 {
		if exactFlows, err := countKernelRuntimeFlowEntriesExact(refs); err != nil {
			log.Printf("%s: exact flow entry count failed, using cached flow count=%d: %v", context, counts.flowsEntries, err)
		} else {
			counts.flowsEntries = exactFlows
		}
	}
	if includeNAT && counts.natEntries <= 0 {
		if exactNAT, err := countKernelRuntimeNATEntriesExact(refs); err != nil {
			log.Printf("%s: exact nat entry count failed, using cached nat count=%d: %v", context, counts.natEntries, err)
		} else {
			counts.natEntries = exactNAT
		}
	}
	return counts
}

func kernelRuntimeIdleDegradedRebuildReason(view KernelEngineRuntimeView) string {
	if !view.Degraded || !view.Loaded || view.ActiveEntries <= 0 || view.PressureActive {
		return ""
	}
	if view.FlowsMapEntries > 0 {
		return ""
	}
	if view.NATMapEntries > 0 {
		return ""
	}
	return fmt.Sprintf("%s degraded runtime is idle and eligible for fresh map growth", view.Name)
}
