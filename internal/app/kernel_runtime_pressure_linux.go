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

type kernelRuntimePressureUsageSample struct {
	label    string
	entries  int
	capacity int
}

func (rt *linuxKernelRuleRuntime) currentAvailabilityLocked(now time.Time) (bool, string) {
	return rt.currentAvailabilityLockedWithForce(now, false)
}

func (rt *linuxKernelRuleRuntime) currentAvailabilityLockedWithForce(now time.Time, force bool) (bool, string) {
	if !rt.available {
		return false, rt.availableReason
	}
	pressure := rt.refreshPressureLockedWithForce(now, force)
	if pressure.level.blocksKernelAvailability() {
		return false, pressure.reason
	}
	return true, rt.availableReason
}

func (rt *xdpKernelRuleRuntime) currentAvailabilityLocked(now time.Time) (bool, string) {
	return rt.currentAvailabilityLockedWithForce(now, false)
}

func (rt *xdpKernelRuleRuntime) currentAvailabilityLockedWithForce(now time.Time, force bool) (bool, string) {
	if !rt.available {
		return false, rt.availableReason
	}
	pressure := rt.refreshPressureLockedWithForce(now, force)
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
		NATEntries:      pressure.natEntries,
		NATCapacity:     pressure.natCapacity,
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
	return rt.refreshPressureLockedWithForce(now, false)
}

func (rt *linuxKernelRuleRuntime) refreshPressureLockedWithForce(now time.Time, force bool) kernelRuntimePressureState {
	if !rt.available || rt.coll == nil || rt.coll.Maps == nil {
		rt.pressureState = kernelRuntimePressureState{}
		rt.observability.updatePressure(false, now)
		return rt.pressureState
	}
	if len(rt.preparedRules) == 0 {
		rt.pressureState = kernelRuntimePressureState{}
		rt.observability.updatePressure(false, now)
		return rt.pressureState
	}
	if !force && !rt.pressureState.sampledAt.IsZero() && now.Sub(rt.pressureState.sampledAt) < kernelRuntimePressureSampleTTL {
		return rt.pressureState
	}

	refs := kernelRuntimeMapRefsFromCollection(rt.coll)
	counts := rt.currentRuntimeMapCountsLockedWithForce(now, force)
	counts = countTCKernelRuntimeMapEntryDetails(now, refs, counts, true)
	counts = kernelRuntimeCountsForIdleGrowthDecision(refs, counts, true, "kernel dataplane pressure")
	rt.runtimeMapCounts = counts
	next := buildKernelRuntimePressureStateFromDetailedCounts(rt.pressureState.level, refs, counts, true)
	next.sampledAt = now
	logKernelRuntimePressureTransition(kernelEngineTC, rt.pressureState, next)
	rt.pressureState = next
	rt.observability.updatePressure(next.active, now)
	return rt.pressureState
}

func (rt *xdpKernelRuleRuntime) refreshPressureLocked(now time.Time) kernelRuntimePressureState {
	return rt.refreshPressureLockedWithForce(now, false)
}

func (rt *xdpKernelRuleRuntime) refreshPressureLockedWithForce(now time.Time, force bool) kernelRuntimePressureState {
	if !rt.available || rt.coll == nil || rt.coll.Maps == nil {
		rt.pressureState = kernelRuntimePressureState{}
		rt.observability.updatePressure(false, now)
		return rt.pressureState
	}
	if len(rt.preparedRules) == 0 {
		rt.pressureState = kernelRuntimePressureState{}
		rt.observability.updatePressure(false, now)
		return rt.pressureState
	}
	if !force && !rt.pressureState.sampledAt.IsZero() && now.Sub(rt.pressureState.sampledAt) < kernelRuntimePressureSampleTTL {
		return rt.pressureState
	}

	refs := kernelRuntimeMapRefsFromCollection(rt.coll)
	counts := rt.currentRuntimeMapCountsLockedWithForce(now, force)
	counts = countXDPKernelRuntimeMapEntryDetails(now, refs, counts)
	counts = kernelRuntimeCountsForIdleGrowthDecision(refs, counts, false, "xdp dataplane pressure")
	counts, includeNAT := xdpRuntimeNATStateForDecision(rt.preparedRules, refs, counts, "xdp dataplane pressure")
	rt.runtimeMapCounts = counts
	next := buildKernelRuntimePressureStateFromDetailedCounts(rt.pressureState.level, refs, counts, includeNAT)
	next.sampledAt = now
	logKernelRuntimePressureTransition(kernelEngineXDP, rt.pressureState, next)
	rt.pressureState = next
	rt.observability.updatePressure(next.active, now)
	return rt.pressureState
}

func buildKernelRuntimePressureState(previousLevel kernelRuntimePressureLevel, flowsEntries int, flowsCapacity int, natEntries int, natCapacity int, includeNAT bool) kernelRuntimePressureState {
	flowSamples := []kernelRuntimePressureUsageSample{{
		label:    "flows",
		entries:  flowsEntries,
		capacity: flowsCapacity,
	}}
	natSamples := []kernelRuntimePressureUsageSample{}
	if includeNAT {
		natSamples = append(natSamples, kernelRuntimePressureUsageSample{
			label:    "nat",
			entries:  natEntries,
			capacity: natCapacity,
		})
	}
	return buildKernelRuntimePressureStateFromSamples(previousLevel, flowSamples, natSamples)
}

func buildKernelRuntimePressureStateFromDetailedCounts(previousLevel kernelRuntimePressureLevel, refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, includeNAT bool) kernelRuntimePressureState {
	flowSamples, natSamples := kernelRuntimePressureSamplesFromDetailedCounts(refs, counts, includeNAT)
	state := buildKernelRuntimePressureStateFromSamples(previousLevel, flowSamples, natSamples)
	if state.active {
		return state
	}

	flowsCapacity := kernelRuntimeFlowMapCapacity(refs)
	natCapacity := 0
	if includeNAT {
		natCapacity = kernelRuntimeNATMapCapacity(refs)
	}
	fallback := buildKernelRuntimePressureState(previousLevel, counts.flowsEntries, flowsCapacity, counts.natEntries, natCapacity, includeNAT)
	if kernelRuntimePressureLevelRank(fallback.level) > kernelRuntimePressureLevelRank(state.level) {
		return fallback
	}
	if state.flowsCapacity == 0 {
		state.flowsEntries = counts.flowsEntries
		state.flowsCapacity = flowsCapacity
	}
	if includeNAT && state.natCapacity == 0 {
		state.natEntries = counts.natEntries
		state.natCapacity = natCapacity
	}
	return state
}

func buildKernelRuntimePressureStateFromSamples(previousLevel kernelRuntimePressureLevel, flowSamples []kernelRuntimePressureUsageSample, natSamples []kernelRuntimePressureUsageSample) kernelRuntimePressureState {
	flowsLevel, flowSample := kernelRuntimePressureMaxSample(previousLevel, flowSamples)
	natLevel, natSample := kernelRuntimePressureMaxSample(previousLevel, natSamples)
	level := maxKernelRuntimePressureLevel(flowsLevel, natLevel)

	state := kernelRuntimePressureState{
		flowsEntries:  flowSample.entries,
		flowsCapacity: flowSample.capacity,
		natEntries:    natSample.entries,
		natCapacity:   natSample.capacity,
	}
	if !level.active() {
		return state
	}

	parts := make([]string, 0, 2)
	if flowsLevel.active() {
		parts = append(parts, kernelRuntimePressureUsageSampleText(flowSample))
	}
	if natLevel.active() {
		parts = append(parts, kernelRuntimePressureUsageSampleText(natSample))
	}

	state.level = level
	state.active = true
	state.reason = kernelRuntimePressureReason(level, strings.Join(parts, ", "))
	return state
}

func kernelRuntimePressureSamplesFromDetailedCounts(refs kernelRuntimeMapRefs, counts kernelRuntimeMapCountSnapshot, includeNAT bool) ([]kernelRuntimePressureUsageSample, []kernelRuntimePressureUsageSample) {
	flows := make([]kernelRuntimePressureUsageSample, 0, 2)
	flowsCapV4, flowsOldCapV4, flowsCapV6, flowsOldCapV6 := kernelRuntimeFlowMapCapacityBreakdown(refs)
	if capacity := flowsCapV4 + flowsOldCapV4; capacity > 0 {
		flows = append(flows, kernelRuntimePressureUsageSample{
			label:    "flows ipv4",
			entries:  counts.flowsEntriesV4,
			capacity: capacity,
		})
	}
	if capacity := flowsCapV6 + flowsOldCapV6; capacity > 0 {
		flows = append(flows, kernelRuntimePressureUsageSample{
			label:    "flows ipv6",
			entries:  counts.flowsEntriesV6,
			capacity: capacity,
		})
	}

	nats := make([]kernelRuntimePressureUsageSample, 0, 2)
	if includeNAT {
		natCapV4, natOldCapV4, natCapV6, natOldCapV6 := kernelRuntimeNATMapCapacityBreakdown(refs)
		if capacity := natCapV4 + natOldCapV4; capacity > 0 {
			nats = append(nats, kernelRuntimePressureUsageSample{
				label:    "nat ipv4",
				entries:  counts.natEntriesV4,
				capacity: capacity,
			})
		}
		if capacity := natCapV6 + natOldCapV6; capacity > 0 {
			nats = append(nats, kernelRuntimePressureUsageSample{
				label:    "nat ipv6",
				entries:  counts.natEntriesV6,
				capacity: capacity,
			})
		}
	}
	return flows, nats
}

func kernelRuntimePressureMaxSample(previousLevel kernelRuntimePressureLevel, samples []kernelRuntimePressureUsageSample) (kernelRuntimePressureLevel, kernelRuntimePressureUsageSample) {
	bestLevel := kernelRuntimePressureLevelNone
	bestSample := kernelRuntimePressureUsageSample{}
	bestUsage := -1.0
	for _, sample := range samples {
		level := kernelRuntimePressureLevelForUsage(sample.entries, sample.capacity, previousLevel)
		usage := kernelRuntimePressureUsageRatio(sample.entries, sample.capacity)
		if kernelRuntimePressureLevelRank(level) > kernelRuntimePressureLevelRank(bestLevel) ||
			(kernelRuntimePressureLevelRank(level) == kernelRuntimePressureLevelRank(bestLevel) && usage > bestUsage) {
			bestLevel = level
			bestSample = sample
			bestUsage = usage
		}
	}
	return bestLevel, bestSample
}

func kernelRuntimePressureUsageSampleText(sample kernelRuntimePressureUsageSample) string {
	if strings.TrimSpace(sample.label) == "" {
		return kernelRuntimePressureUsage(sample.entries, sample.capacity)
	}
	return fmt.Sprintf("%s %s", sample.label, kernelRuntimePressureUsage(sample.entries, sample.capacity))
}

func kernelRuntimePressureUsageRatio(entries int, capacity int) float64 {
	if capacity <= 0 {
		return 0
	}
	return float64(entries) / float64(capacity)
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
