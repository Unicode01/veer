package app

import (
	"testing"
	"time"
)

func TestKernelSkipLoggerSnapshotAggregatesByReason(t *testing.T) {
	logger := newKernelSkipLogger("xdp")
	logger.Add(Rule{ID: 1}, errString("xdp dataplane currently supports only transparent rules"))
	logger.Add(Rule{ID: 2}, errString("xdp dataplane currently supports only transparent rules"))
	logger.Add(Rule{ID: 2}, errString("xdp dataplane currently supports only transparent rules"))
	logger.Add(Rule{ID: 9, kernelLogKind: "range", kernelLogOwnerID: 9}, errString("xdp dataplane currently supports only transparent rules"))

	snapshot := logger.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("Snapshot() line count = %d, want 1", len(snapshot))
	}

	want := "xdp dataplane skipped: xdp dataplane currently supports only transparent rules"
	if _, ok := snapshot[want]; !ok {
		t.Fatalf("Snapshot() missing line %q, got %#v", want, snapshot)
	}
}

func TestLogKernelLineSetOnceKeepsSeenLines(t *testing.T) {
	seen := logKernelLineSetOnce(nil, map[string]struct{}{
		"first":  {},
		"second": {},
	})
	if len(seen) != 2 {
		t.Fatalf("logKernelLineSetOnce() first call len = %d, want 2", len(seen))
	}

	seen = logKernelLineSetOnce(seen, nil)
	if len(seen) != 2 {
		t.Fatalf("logKernelLineSetOnce() nil next len = %d, want 2", len(seen))
	}

	seen = logKernelLineSetOnce(seen, map[string]struct{}{
		"second": {},
		"third":  {},
	})
	if len(seen) != 3 {
		t.Fatalf("logKernelLineSetOnce() second call len = %d, want 3", len(seen))
	}
	if _, ok := seen["first"]; !ok {
		t.Fatal("logKernelLineSetOnce() lost previously seen line")
	}
}

func TestKernelCountLogStateShouldLog(t *testing.T) {
	var state kernelCountLogState
	now := time.Unix(100, 0)

	if !state.ShouldLog(1, now, time.Minute) {
		t.Fatal("first non-zero count should log")
	}
	if state.ShouldLog(1, now.Add(30*time.Second), time.Minute) {
		t.Fatal("repeated count inside debounce window should be suppressed")
	}
	if !state.ShouldLog(2, now.Add(40*time.Second), time.Minute) {
		t.Fatal("count change should log immediately")
	}
	if state.ShouldLog(0, now.Add(50*time.Second), time.Minute) {
		t.Fatal("zero count should reset state without logging")
	}
	if !state.ShouldLog(2, now.Add(55*time.Second), time.Minute) {
		t.Fatal("same count should log again after reset")
	}
	if state.ShouldLog(2, now.Add(56*time.Second), time.Minute) {
		t.Fatal("same count immediately after reset log should still be suppressed")
	}
	if !state.ShouldLog(2, now.Add(2*time.Minute), time.Minute) {
		t.Fatal("persistent count should log again after repeat window")
	}
}
