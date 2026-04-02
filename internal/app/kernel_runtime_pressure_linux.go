//go:build linux

package app

import (
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	kernelRuntimePressureSampleTTL           = 5 * time.Second
	kernelRuntimePressureHoldWatermarkPct    = 92
	kernelRuntimePressureShedWatermarkPct    = 96
	kernelRuntimePressureFullWatermarkPct    = 99
	kernelRuntimePressureReleaseWatermarkPct = 85
)

type kernelRuntimePressureState struct {
	sampledAt     time.Time
	level         kernelRuntimePressureLevel
	active        bool
	reason        string
	flowsEntries  int
	flowsCapacity int
	natEntries    int
	natCapacity   int
}

func (rt *linuxKernelRuleRuntime) currentAvailabilityLocked(now time.Time) (bool, string) {
	if !rt.available {
		return false, rt.availableReason
	}
	pressure := rt.refreshPressureLocked(now)
	if pressure.level.blocksKernelAvailability() {
		return false, pressure.reason
	}
	return true, rt.availableReason
}

func (rt *xdpKernelRuleRuntime) currentAvailabilityLocked(now time.Time) (bool, string) {
	if !rt.available {
		return false, rt.availableReason
	}
	pressure := rt.refreshPressureLocked(now)
	if pressure.level.blocksKernelAvailability() {
		return false, pressure.reason
	}
	return true, rt.availableReason
}

func (rt *linuxKernelRuleRuntime) pressureSnapshot() kernelRuntimePressureSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	pressure := rt.refreshPressureLocked(time.Now())
	return kernelRuntimePressureSnapshot{
		Engine:          kernelEngineTC,
		Level:           pressure.level,
		Active:          pressure.active,
		Reason:          pressure.reason,
		AssignedEntries: len(rt.preparedRules),
		SampledAt:       pressure.sampledAt,
		FlowsEntries:    pressure.flowsEntries,
		FlowsCapacity:   pressure.flowsCapacity,
		NATEntries:      pressure.natEntries,
		NATCapacity:     pressure.natCapacity,
	}
}

func (rt *xdpKernelRuleRuntime) pressureSnapshot() kernelRuntimePressureSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	pressure := rt.refreshPressureLocked(time.Now())
	return kernelRuntimePressureSnapshot{
		Engine:          kernelEngineXDP,
		Level:           pressure.level,
		Active:          pressure.active,
		Reason:          pressure.reason,
		AssignedEntries: len(rt.preparedRules),
		SampledAt:       pressure.sampledAt,
		FlowsEntries:    pressure.flowsEntries,
		FlowsCapacity:   pressure.flowsCapacity,
	}
}

func (rt *orderedKernelRuleRuntime) pressureSnapshot() kernelRuntimePressureSnapshot {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	var firstActive kernelRuntimePressureSnapshot
	for _, entry := range entries {
		aware, ok := entry.rt.(kernelPressureAwareRuntime)
		if !ok || aware == nil {
			continue
		}
		snapshot := aware.pressureSnapshot()
		if snapshot.Engine == "" {
			snapshot.Engine = entry.name
		}
		if !snapshot.Active {
			continue
		}
		if snapshot.AssignedEntries > 0 {
			return snapshot
		}
		if !firstActive.Active {
			firstActive = snapshot
		}
	}
	return firstActive
}

func (rt *linuxKernelRuleRuntime) refreshPressureLocked(now time.Time) kernelRuntimePressureState {
	if !rt.available || rt.coll == nil || rt.coll.Maps == nil {
		rt.pressureState = kernelRuntimePressureState{}
		return rt.pressureState
	}
	if !rt.pressureState.sampledAt.IsZero() && now.Sub(rt.pressureState.sampledAt) < kernelRuntimePressureSampleTTL {
		return rt.pressureState
	}

	counts := rt.runtimeMapCounts
	if !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, kernelRuntimeMapRefsFromCollection(rt.coll), counts, countTCRuleMapEntries, true)
		rt.runtimeMapCounts = counts
	}
	capacities := rt.currentMapCapacitiesLocked()
	next := buildKernelRuntimePressureState(rt.pressureState.level, counts.flowsEntries, capacities.Flows, counts.natEntries, capacities.NATPorts, true)
	next.sampledAt = now
	logKernelRuntimePressureTransition(kernelEngineTC, rt.pressureState, next)
	rt.pressureState = next
	return rt.pressureState
}

func (rt *xdpKernelRuleRuntime) refreshPressureLocked(now time.Time) kernelRuntimePressureState {
	if !rt.available || rt.coll == nil || rt.coll.Maps == nil {
		rt.pressureState = kernelRuntimePressureState{}
		return rt.pressureState
	}
	if !rt.pressureState.sampledAt.IsZero() && now.Sub(rt.pressureState.sampledAt) < kernelRuntimePressureSampleTTL {
		return rt.pressureState
	}

	counts := rt.runtimeMapCounts
	if !counts.fresh(now) {
		counts = countKernelRuntimeMapEntries(now, kernelRuntimeMapRefsFromCollection(rt.coll), counts, countXDPRuleMapEntries, false)
		rt.runtimeMapCounts = counts
	}
	flowsCapacity := rt.flowsMapCapacity
	if rt.coll != nil && rt.coll.Maps != nil {
		if flowsMap := rt.coll.Maps[kernelFlowsMapName]; flowsMap != nil {
			flowsCapacity = int(flowsMap.MaxEntries())
		}
	}
	next := buildKernelRuntimePressureState(rt.pressureState.level, counts.flowsEntries, flowsCapacity, 0, 0, false)
	next.sampledAt = now
	logKernelRuntimePressureTransition(kernelEngineXDP, rt.pressureState, next)
	rt.pressureState = next
	return rt.pressureState
}

func buildKernelRuntimePressureState(previousLevel kernelRuntimePressureLevel, flowsEntries int, flowsCapacity int, natEntries int, natCapacity int, includeNAT bool) kernelRuntimePressureState {
	state := kernelRuntimePressureState{
		flowsEntries:  flowsEntries,
		flowsCapacity: flowsCapacity,
		natEntries:    natEntries,
		natCapacity:   natCapacity,
	}
	flowsLevel := kernelRuntimePressureLevelForUsage(flowsEntries, flowsCapacity, previousLevel)
	natLevel := kernelRuntimePressureLevelNone
	if includeNAT {
		natLevel = kernelRuntimePressureLevelForUsage(natEntries, natCapacity, previousLevel)
	}
	level := maxKernelRuntimePressureLevel(flowsLevel, natLevel)
	if !level.active() {
		return state
	}

	parts := make([]string, 0, 2)
	if flowsLevel.active() {
		parts = append(parts, fmt.Sprintf("flows %s", kernelRuntimePressureUsage(flowsEntries, flowsCapacity)))
	}
	if natLevel.active() {
		parts = append(parts, fmt.Sprintf("nat %s", kernelRuntimePressureUsage(natEntries, natCapacity)))
	}

	state.level = level
	state.active = true
	state.reason = kernelRuntimePressureReason(level, strings.Join(parts, ", "))
	return state
}

func kernelRuntimePressureReason(level kernelRuntimePressureLevel, usage string) string {
	switch level {
	case kernelRuntimePressureLevelHold:
		return fmt.Sprintf(
			"kernel dataplane pressure: %s exceeded %d%% high watermark, keeping existing kernel owners and routing new owners to userspace until usage drops below %d%%",
			usage,
			kernelRuntimePressureHoldWatermarkPct,
			kernelRuntimePressureReleaseWatermarkPct,
		)
	case kernelRuntimePressureLevelShed:
		return fmt.Sprintf(
			"kernel dataplane pressure: %s exceeded %d%% shed watermark, shedding a subset of kernel owners and routing new owners to userspace until usage drops below %d%%",
			usage,
			kernelRuntimePressureShedWatermarkPct,
			kernelRuntimePressureReleaseWatermarkPct,
		)
	case kernelRuntimePressureLevelFull:
		return fmt.Sprintf(
			"kernel dataplane pressure: %s exceeded %d%% saturation watermark, routing all kernel owners to userspace until usage drops below %d%%",
			usage,
			kernelRuntimePressureFullWatermarkPct,
			kernelRuntimePressureReleaseWatermarkPct,
		)
	default:
		return ""
	}
}

func kernelRuntimePressureLevelForUsage(entries int, capacity int, previousLevel kernelRuntimePressureLevel) kernelRuntimePressureLevel {
	if capacity <= 0 || entries <= 0 {
		return kernelRuntimePressureLevelNone
	}
	switch {
	case entries >= kernelRuntimePressureThreshold(capacity, kernelRuntimePressureFullWatermarkPct):
		return kernelRuntimePressureLevelFull
	case entries >= kernelRuntimePressureThreshold(capacity, kernelRuntimePressureShedWatermarkPct):
		return kernelRuntimePressureLevelShed
	case previousLevel.active() && entries >= kernelRuntimePressureThreshold(capacity, kernelRuntimePressureReleaseWatermarkPct):
		return kernelRuntimePressureLevelHold
	case entries >= kernelRuntimePressureThreshold(capacity, kernelRuntimePressureHoldWatermarkPct):
		return kernelRuntimePressureLevelHold
	default:
		return kernelRuntimePressureLevelNone
	}
}

func kernelRuntimePressureThreshold(capacity int, watermark int) int {
	if capacity <= 0 {
		return 0
	}
	threshold := (capacity*watermark + 99) / 100
	if threshold < 1 {
		return 1
	}
	return threshold
}

func kernelRuntimePressureUsage(entries int, capacity int) string {
	if capacity <= 0 {
		return fmt.Sprintf("%d/0", entries)
	}
	return fmt.Sprintf("%d/%d (%.1f%%)", entries, capacity, (float64(entries)*100)/float64(capacity))
}

func logKernelRuntimePressureTransition(engine string, previous kernelRuntimePressureState, next kernelRuntimePressureState) {
	switch {
	case next.active && (!previous.active || previous.reason != next.reason):
		log.Printf("%s dataplane pressure: %s", engine, next.reason)
	case previous.active && !next.active:
		log.Printf("%s dataplane pressure cleared: %s", engine, kernelRuntimePressureStateSummary(next))
	}
}

func kernelRuntimePressureStateSummary(state kernelRuntimePressureState) string {
	parts := []string{
		fmt.Sprintf("level=%s", kernelRuntimePressureLevelLabel(state.level)),
		fmt.Sprintf("flows=%s", kernelRuntimePressureUsage(state.flowsEntries, state.flowsCapacity)),
	}
	if state.natCapacity > 0 {
		parts = append(parts, fmt.Sprintf("nat=%s", kernelRuntimePressureUsage(state.natEntries, state.natCapacity)))
	}
	return strings.Join(parts, " ")
}

func kernelRuntimePressureLevelLabel(level kernelRuntimePressureLevel) string {
	if level == kernelRuntimePressureLevelNone {
		return "none"
	}
	return string(level)
}

func maxKernelRuntimePressureLevel(left kernelRuntimePressureLevel, right kernelRuntimePressureLevel) kernelRuntimePressureLevel {
	if kernelRuntimePressureLevelRank(right) > kernelRuntimePressureLevelRank(left) {
		return right
	}
	return left
}

func kernelRuntimePressureLevelRank(level kernelRuntimePressureLevel) int {
	switch level {
	case kernelRuntimePressureLevelHold:
		return 1
	case kernelRuntimePressureLevelShed:
		return 2
	case kernelRuntimePressureLevelFull:
		return 3
	default:
		return 0
	}
}

func (rt *linuxKernelRuleRuntime) invalidatePressureStateLocked() {
	rt.pressureState = kernelRuntimePressureState{}
}

func (rt *xdpKernelRuleRuntime) invalidatePressureStateLocked() {
	rt.pressureState = kernelRuntimePressureState{}
}
