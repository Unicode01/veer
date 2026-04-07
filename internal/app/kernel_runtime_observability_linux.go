//go:build linux

package app

import (
	"strings"
	"time"
)

type kernelFlowPruneMetrics struct {
	Budget  int
	Scanned int
	Deleted int
}

type kernelReconcileMetrics struct {
	RequestEntries    int
	PreparedEntries   int
	AppliedEntries    int
	Upserts           int
	Deletes           int
	Attaches          int
	Detaches          int
	Preserved         int
	FlowPurgeDeleted  int
	PrepareDuration   time.Duration
	AttachDuration    time.Duration
	FlowPurgeDuration time.Duration
}

type kernelRuntimeObservabilitySnapshot struct {
	PressureSince                 time.Time
	DegradedSince                 time.Time
	LastReconcileAt               time.Time
	LastReconcileMs               int64
	LastReconcileError            string
	LastReconcileRequestEntries   int
	LastReconcilePreparedEntries  int
	LastReconcileAppliedEntries   int
	LastReconcileUpserts          int
	LastReconcileDeletes          int
	LastReconcileAttaches         int
	LastReconcileDetaches         int
	LastReconcilePreserved        int
	LastReconcileFlowPurgeDeleted int
	LastReconcilePrepareMs        int64
	LastReconcileAttachMs         int64
	LastReconcileFlowPurgeMs      int64
	LastMaintainAt                time.Time
	LastMaintainMs                int64
	LastMaintainError             string
	LastPruneBudget               int
	LastPruneScanned              int
	LastPruneDeleted              int
	AttachmentsUnhealthyCount     int
	LastAttachmentsUnhealthyAt    time.Time
}

type kernelRuntimeObservabilityState struct {
	pressureSince                  time.Time
	degradedSince                  time.Time
	lastReconcileAt                time.Time
	lastReconcileDuration          time.Duration
	lastReconcileError             string
	lastReconcileRequestEntries    int
	lastReconcilePreparedEntries   int
	lastReconcileAppliedEntries    int
	lastReconcileUpserts           int
	lastReconcileDeletes           int
	lastReconcileAttaches          int
	lastReconcileDetaches          int
	lastReconcilePreserved         int
	lastReconcileFlowPurgeDeleted  int
	lastReconcilePrepareDuration   time.Duration
	lastReconcileAttachDuration    time.Duration
	lastReconcileFlowPurgeDuration time.Duration
	lastMaintainAt                 time.Time
	lastMaintainDuration           time.Duration
	lastMaintainError              string
	lastPruneBudget                int
	lastPruneScanned               int
	lastPruneDeleted               int
	attachmentsHealthy             bool
	attachmentsHealthyKnown        bool
	attachmentsUnhealthyCount      int
	lastAttachmentsUnhealthyAt     time.Time
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

func (state *kernelRuntimeObservabilityState) recordReconcile(start time.Time, duration time.Duration, metrics kernelReconcileMetrics, err error, results map[int64]kernelRuleApplyResult) {
	if state == nil {
		return
	}
	state.lastReconcileAt = start
	state.lastReconcileDuration = duration
	state.lastReconcileRequestEntries = metrics.RequestEntries
	state.lastReconcilePreparedEntries = metrics.PreparedEntries
	state.lastReconcileAppliedEntries = metrics.AppliedEntries
	state.lastReconcileUpserts = metrics.Upserts
	state.lastReconcileDeletes = metrics.Deletes
	state.lastReconcileAttaches = metrics.Attaches
	state.lastReconcileDetaches = metrics.Detaches
	state.lastReconcilePreserved = metrics.Preserved
	state.lastReconcileFlowPurgeDeleted = metrics.FlowPurgeDeleted
	state.lastReconcilePrepareDuration = metrics.PrepareDuration
	state.lastReconcileAttachDuration = metrics.AttachDuration
	state.lastReconcileFlowPurgeDuration = metrics.FlowPurgeDuration
	state.lastReconcileError = summarizeKernelReconcileError(err, results)
}

func summarizeKernelReconcileError(err error, results map[int64]kernelRuleApplyResult) string {
	if err != nil {
		return err.Error()
	}
	for _, result := range results {
		text := strings.TrimSpace(result.Error)
		if text == "" {
			continue
		}
		return text
	}
	return ""
}

func (state *kernelRuntimeObservabilityState) snapshot() kernelRuntimeObservabilitySnapshot {
	if state == nil {
		return kernelRuntimeObservabilitySnapshot{}
	}
	snapshot := kernelRuntimeObservabilitySnapshot{
		PressureSince:                 state.pressureSince,
		DegradedSince:                 state.degradedSince,
		LastReconcileAt:               state.lastReconcileAt,
		LastReconcileError:            state.lastReconcileError,
		LastReconcileRequestEntries:   state.lastReconcileRequestEntries,
		LastReconcilePreparedEntries:  state.lastReconcilePreparedEntries,
		LastReconcileAppliedEntries:   state.lastReconcileAppliedEntries,
		LastReconcileUpserts:          state.lastReconcileUpserts,
		LastReconcileDeletes:          state.lastReconcileDeletes,
		LastReconcileAttaches:         state.lastReconcileAttaches,
		LastReconcileDetaches:         state.lastReconcileDetaches,
		LastReconcilePreserved:        state.lastReconcilePreserved,
		LastReconcileFlowPurgeDeleted: state.lastReconcileFlowPurgeDeleted,
		LastMaintainAt:                state.lastMaintainAt,
		LastMaintainError:             state.lastMaintainError,
		LastPruneBudget:               state.lastPruneBudget,
		LastPruneScanned:              state.lastPruneScanned,
		LastPruneDeleted:              state.lastPruneDeleted,
		AttachmentsUnhealthyCount:     state.attachmentsUnhealthyCount,
		LastAttachmentsUnhealthyAt:    state.lastAttachmentsUnhealthyAt,
	}
	if state.lastMaintainDuration > 0 {
		snapshot.LastMaintainMs = state.lastMaintainDuration.Milliseconds()
	}
	if state.lastReconcileDuration > 0 {
		snapshot.LastReconcileMs = state.lastReconcileDuration.Milliseconds()
	}
	if state.lastReconcilePrepareDuration > 0 {
		snapshot.LastReconcilePrepareMs = state.lastReconcilePrepareDuration.Milliseconds()
	}
	if state.lastReconcileAttachDuration > 0 {
		snapshot.LastReconcileAttachMs = state.lastReconcileAttachDuration.Milliseconds()
	}
	if state.lastReconcileFlowPurgeDuration > 0 {
		snapshot.LastReconcileFlowPurgeMs = state.lastReconcileFlowPurgeDuration.Milliseconds()
	}
	return snapshot
}

func applyKernelRuntimeObservabilityView(view *KernelEngineRuntimeView, snapshot kernelRuntimeObservabilitySnapshot) {
	if view == nil {
		return
	}
	view.PressureSince = snapshot.PressureSince
	view.DegradedSince = snapshot.DegradedSince
	view.LastReconcileAt = snapshot.LastReconcileAt
	view.LastReconcileMs = snapshot.LastReconcileMs
	view.LastReconcileError = snapshot.LastReconcileError
	view.LastReconcileRequestEntries = snapshot.LastReconcileRequestEntries
	view.LastReconcilePreparedEntries = snapshot.LastReconcilePreparedEntries
	view.LastReconcileAppliedEntries = snapshot.LastReconcileAppliedEntries
	view.LastReconcileUpserts = snapshot.LastReconcileUpserts
	view.LastReconcileDeletes = snapshot.LastReconcileDeletes
	view.LastReconcileAttaches = snapshot.LastReconcileAttaches
	view.LastReconcileDetaches = snapshot.LastReconcileDetaches
	view.LastReconcilePreserved = snapshot.LastReconcilePreserved
	view.LastReconcileFlowPurgeDeleted = snapshot.LastReconcileFlowPurgeDeleted
	view.LastReconcilePrepareMs = snapshot.LastReconcilePrepareMs
	view.LastReconcileAttachMs = snapshot.LastReconcileAttachMs
	view.LastReconcileFlowPurgeMs = snapshot.LastReconcileFlowPurgeMs
	view.LastMaintainAt = snapshot.LastMaintainAt
	view.LastMaintainMs = snapshot.LastMaintainMs
	view.LastMaintainError = snapshot.LastMaintainError
	view.LastPruneBudget = snapshot.LastPruneBudget
	view.LastPruneScanned = snapshot.LastPruneScanned
	view.LastPruneDeleted = snapshot.LastPruneDeleted
	view.AttachmentsUnhealthyCount = snapshot.AttachmentsUnhealthyCount
	view.LastAttachmentsUnhealthyAt = snapshot.LastAttachmentsUnhealthyAt
}
