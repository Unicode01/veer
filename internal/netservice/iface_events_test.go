package netservice

import (
	"testing"
	"time"
)

func TestInterfaceCheckGateSkipsChecksWhileNothingChanged(t *testing.T) {
	SetInterfaceEventsAvailable(true)
	t.Cleanup(func() { SetInterfaceEventsAvailable(false) })
	calls := 0
	check := func(result bool) func() bool {
		return func() bool { calls++; return result }
	}
	var gate interfaceCheckGate
	now := time.Unix(1000, 0)
	if gate.run(now, check(false)) || calls != 1 {
		t.Fatalf("first check: calls = %d", calls)
	}
	if gate.run(now.Add(time.Second), check(false)) || calls != 1 {
		t.Fatalf("a check without a change ran: calls = %d", calls)
	}
	NoteInterfaceChange()
	if gate.run(now.Add(2*time.Second), check(false)) || calls != 2 {
		t.Fatalf("a check after a change was skipped: calls = %d", calls)
	}
	if gate.run(now.Add(2*time.Second+interfaceRecheckEvery), check(false)) || calls != 3 {
		t.Fatalf("the safety recheck did not run: calls = %d", calls)
	}
	// A check that wants a reopen is repeated until it no longer does.
	NoteInterfaceChange()
	if !gate.run(now.Add(3*interfaceRecheckEvery), check(true)) || calls != 4 {
		t.Fatalf("reopen not reported: calls = %d", calls)
	}
	if !gate.run(now.Add(3*interfaceRecheckEvery), check(true)) || calls != 5 {
		t.Fatalf("a check that wanted a reopen was skipped: calls = %d", calls)
	}
	// Without the event source every check runs.
	SetInterfaceEventsAvailable(false)
	gate = interfaceCheckGate{}
	gate.run(now, check(false))
	gate.run(now, check(false))
	if calls != 7 {
		t.Fatalf("checks without events: calls = %d, want 7", calls)
	}
}
