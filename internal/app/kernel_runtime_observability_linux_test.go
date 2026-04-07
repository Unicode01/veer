//go:build linux

package app

import (
	"testing"
	"time"
)

func TestKernelRuntimeObservabilityRecordReconcileUsesApplyResultError(t *testing.T) {
	state := &kernelRuntimeObservabilityState{}
	startedAt := time.Now().Add(-150 * time.Millisecond)
	metrics := kernelReconcileMetrics{
		RequestEntries:    5,
		PreparedEntries:   4,
		AppliedEntries:    4,
		Upserts:           3,
		Deletes:           1,
		Attaches:          2,
		Detaches:          1,
		Preserved:         6,
		FlowPurgeDeleted:  9,
		PrepareDuration:   11 * time.Millisecond,
		AttachDuration:    17 * time.Millisecond,
		FlowPurgeDuration: 23 * time.Millisecond,
	}

	state.recordReconcile(startedAt, 123*time.Millisecond, metrics, nil, map[int64]kernelRuleApplyResult{
		7: {Error: "attach failed"},
	})

	snapshot := state.snapshot()
	if snapshot.LastReconcileAt.IsZero() {
		t.Fatal("LastReconcileAt is zero")
	}
	if snapshot.LastReconcileMs != 123 {
		t.Fatalf("LastReconcileMs = %d, want 123", snapshot.LastReconcileMs)
	}
	if snapshot.LastReconcileError != "attach failed" {
		t.Fatalf("LastReconcileError = %q, want %q", snapshot.LastReconcileError, "attach failed")
	}
	if snapshot.LastReconcileRequestEntries != metrics.RequestEntries {
		t.Fatalf("LastReconcileRequestEntries = %d, want %d", snapshot.LastReconcileRequestEntries, metrics.RequestEntries)
	}
	if snapshot.LastReconcilePreparedEntries != metrics.PreparedEntries {
		t.Fatalf("LastReconcilePreparedEntries = %d, want %d", snapshot.LastReconcilePreparedEntries, metrics.PreparedEntries)
	}
	if snapshot.LastReconcileAppliedEntries != metrics.AppliedEntries {
		t.Fatalf("LastReconcileAppliedEntries = %d, want %d", snapshot.LastReconcileAppliedEntries, metrics.AppliedEntries)
	}
	if snapshot.LastReconcileUpserts != metrics.Upserts {
		t.Fatalf("LastReconcileUpserts = %d, want %d", snapshot.LastReconcileUpserts, metrics.Upserts)
	}
	if snapshot.LastReconcileDeletes != metrics.Deletes {
		t.Fatalf("LastReconcileDeletes = %d, want %d", snapshot.LastReconcileDeletes, metrics.Deletes)
	}
	if snapshot.LastReconcileAttaches != metrics.Attaches {
		t.Fatalf("LastReconcileAttaches = %d, want %d", snapshot.LastReconcileAttaches, metrics.Attaches)
	}
	if snapshot.LastReconcileDetaches != metrics.Detaches {
		t.Fatalf("LastReconcileDetaches = %d, want %d", snapshot.LastReconcileDetaches, metrics.Detaches)
	}
	if snapshot.LastReconcilePreserved != metrics.Preserved {
		t.Fatalf("LastReconcilePreserved = %d, want %d", snapshot.LastReconcilePreserved, metrics.Preserved)
	}
	if snapshot.LastReconcileFlowPurgeDeleted != metrics.FlowPurgeDeleted {
		t.Fatalf("LastReconcileFlowPurgeDeleted = %d, want %d", snapshot.LastReconcileFlowPurgeDeleted, metrics.FlowPurgeDeleted)
	}
	if snapshot.LastReconcilePrepareMs != metrics.PrepareDuration.Milliseconds() {
		t.Fatalf("LastReconcilePrepareMs = %d, want %d", snapshot.LastReconcilePrepareMs, metrics.PrepareDuration.Milliseconds())
	}
	if snapshot.LastReconcileAttachMs != metrics.AttachDuration.Milliseconds() {
		t.Fatalf("LastReconcileAttachMs = %d, want %d", snapshot.LastReconcileAttachMs, metrics.AttachDuration.Milliseconds())
	}
	if snapshot.LastReconcileFlowPurgeMs != metrics.FlowPurgeDuration.Milliseconds() {
		t.Fatalf("LastReconcileFlowPurgeMs = %d, want %d", snapshot.LastReconcileFlowPurgeMs, metrics.FlowPurgeDuration.Milliseconds())
	}
}
