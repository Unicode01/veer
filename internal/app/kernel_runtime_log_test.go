package app

import "testing"

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

type errString string

func (e errString) Error() string { return string(e) }
