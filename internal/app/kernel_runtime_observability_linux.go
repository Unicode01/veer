//go:build linux

package app

import "time"

type kernelFlowPruneMetrics struct {
	Budget  int
	Scanned int
	Deleted int
}

type kernelRuntimeObservabilitySnapshot struct {
	PressureSince              time.Time
	DegradedSince              time.Time
	LastMaintainAt             time.Time
	LastMaintainMs             int64
	LastMaintainError          string
	LastPruneBudget            int
	LastPruneScanned           int
	LastPruneDeleted           int
	AttachmentsUnhealthyCount  int
	LastAttachmentsUnhealthyAt time.Time
}

type kernelRuntimeObservabilityState struct {
	pressureSince              time.Time
	degradedSince              time.Time
	lastMaintainAt             time.Time
	lastMaintainDuration       time.Duration
	lastMaintainError          string
	lastPruneBudget            int
	lastPruneScanned           int
	lastPruneDeleted           int
	attachmentsHealthy         bool
	attachmentsHealthyKnown    bool
	attachmentsUnhealthyCount  int
	lastAttachmentsUnhealthyAt time.Time
}

func (state *kernelRuntimeObservabilityState) updatePressure(active bool, now time.Time) {
	if state == nil {
		return
	}
	if active {
		if state.pressureSince.IsZero() {
			state.pressureSince = now
		}
		return
	}
	state.pressureSince = time.Time{}
}

func (state *kernelRuntimeObservabilityState) updateDegraded(active bool, now time.Time) {
	if state == nil {
		return
	}
	if active {
		if state.degradedSince.IsZero() {
			state.degradedSince = now
		}
		return
	}
	state.degradedSince = time.Time{}
}

func (state *kernelRuntimeObservabilityState) observeAttachmentsHealthy(healthy bool, now time.Time) {
	if state == nil {
		return
	}
	if !healthy {
		if !state.attachmentsHealthyKnown || state.attachmentsHealthy {
			state.attachmentsUnhealthyCount++
			state.lastAttachmentsUnhealthyAt = now
		}
		state.attachmentsHealthy = false
		state.attachmentsHealthyKnown = true
		return
	}
	state.attachmentsHealthy = true
	state.attachmentsHealthyKnown = true
}

func (state *kernelRuntimeObservabilityState) recordMaintain(start time.Time, duration time.Duration, prune kernelFlowPruneMetrics, err error) {
	if state == nil {
		return
	}
	state.lastMaintainAt = start
	state.lastMaintainDuration = duration
	state.lastPruneBudget = prune.Budget
	state.lastPruneScanned = prune.Scanned
	state.lastPruneDeleted = prune.Deleted
	if err != nil {
		state.lastMaintainError = err.Error()
		return
	}
	state.lastMaintainError = ""
}

func (state *kernelRuntimeObservabilityState) snapshot() kernelRuntimeObservabilitySnapshot {
	if state == nil {
		return kernelRuntimeObservabilitySnapshot{}
	}
	snapshot := kernelRuntimeObservabilitySnapshot{
		PressureSince:              state.pressureSince,
		DegradedSince:              state.degradedSince,
		LastMaintainAt:             state.lastMaintainAt,
		LastMaintainError:          state.lastMaintainError,
		LastPruneBudget:            state.lastPruneBudget,
		LastPruneScanned:           state.lastPruneScanned,
		LastPruneDeleted:           state.lastPruneDeleted,
		AttachmentsUnhealthyCount:  state.attachmentsUnhealthyCount,
		LastAttachmentsUnhealthyAt: state.lastAttachmentsUnhealthyAt,
	}
	if state.lastMaintainDuration > 0 {
		snapshot.LastMaintainMs = state.lastMaintainDuration.Milliseconds()
	}
	return snapshot
}

func applyKernelRuntimeObservabilityView(view *KernelEngineRuntimeView, snapshot kernelRuntimeObservabilitySnapshot) {
	if view == nil {
		return
	}
	view.PressureSince = snapshot.PressureSince
	view.DegradedSince = snapshot.DegradedSince
	view.LastMaintainAt = snapshot.LastMaintainAt
	view.LastMaintainMs = snapshot.LastMaintainMs
	view.LastMaintainError = snapshot.LastMaintainError
	view.LastPruneBudget = snapshot.LastPruneBudget
	view.LastPruneScanned = snapshot.LastPruneScanned
	view.LastPruneDeleted = snapshot.LastPruneDeleted
	view.AttachmentsUnhealthyCount = snapshot.AttachmentsUnhealthyCount
	view.LastAttachmentsUnhealthyAt = snapshot.LastAttachmentsUnhealthyAt
}
