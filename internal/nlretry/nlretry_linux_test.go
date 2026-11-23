//go:build linux

package nlretry

import (
	"errors"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestDoRetriesAnInterruptedDump(t *testing.T) {
	calls := 0
	got, err := Do(func() (int, error) {
		calls++
		if calls < 3 {
			return -1, netlink.ErrDumpInterrupted
		}
		return 7, nil
	})
	if err != nil || got != 7 || calls != 3 {
		t.Fatalf("Do = %d, %v after %d dumps; want 7 after 3", got, err, calls)
	}
}

func TestDoReturnsOtherErrorsAtOnce(t *testing.T) {
	want := errors.New("no such device")
	calls := 0
	_, err := Do(func() (int, error) {
		calls++
		return 0, want
	})
	if !errors.Is(err, want) || calls != 1 {
		t.Fatalf("Do = %v after %d dumps; want %v after 1", err, calls, want)
	}
}

func TestDoGivesUpAfterItsAttempts(t *testing.T) {
	calls := 0
	got, err := Do(func() ([]int, error) {
		calls++
		return []int{1}, netlink.ErrDumpInterrupted
	})
	if got != nil || !errors.Is(err, netlink.ErrDumpInterrupted) || calls != attempts {
		t.Fatalf("Do = %v, %v after %d dumps; want nil and the interruption after %d", got, err, calls, attempts)
	}
}
