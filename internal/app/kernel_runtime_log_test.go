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

func TestKernelCountLogStateReportsATrickleOncePerInterval(t *testing.T) {
	var state kernelCountLogState
	now := time.Unix(100, 0)
	steps := []struct {
		at    time.Duration
		count int
		total int
		log   bool
	}{
		{at: 0, count: 0}, // nothing removed yet
		{at: 10 * time.Second, count: 3, total: 3, log: true}, // the first removal reports at once
		{at: 40 * time.Second, count: 5},                      // counts that differ do not break the limit
		{at: 50 * time.Second, count: 0},                      // nor does a pass that removed nothing
		{at: 60 * time.Second, count: 7},
		{at: 70 * time.Second, count: 1, total: 13, log: true}, // a minute on: everything since the last line
		{at: 80 * time.Second, count: 0},
		{at: 100 * time.Second, count: 2},
		{at: 130 * time.Second, count: 0, total: 2, log: true}, // a quiet pass still reports what is pending
		{at: 400 * time.Second, count: 0},                      // nothing pending, nothing to say
		{at: 500 * time.Second, count: 4, total: 4, log: true}, // after a quiet spell, at once again
	}
	for _, step := range steps {
		total, ok := state.Observe(step.count, now.Add(step.at), time.Minute)
		if ok != step.log || total != step.total {
			t.Fatalf("at %v count %d: Observe = %d, %v; want %d, %v", step.at, step.count, total, ok, step.total, step.log)
		}
	}
}
