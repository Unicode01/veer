package app

import (
	"testing"
	"time"
)

func TestScheduleKernelDegradedIdleRebuildCheckThrottlesHealthyRuntime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	due, checkedAt := scheduleKernelDegradedIdleRebuildCheck(time.Time{}, now, true)
	if !due || !checkedAt.Equal(now) {
		t.Fatalf("initial check = due:%t at:%v, want due at %v", due, checkedAt, now)
	}

	due, nextCheckedAt := scheduleKernelDegradedIdleRebuildCheck(checkedAt, now.Add(kernelDegradedRebuildCooldown-time.Millisecond), true)
	if due || !nextCheckedAt.Equal(checkedAt) {
		t.Fatalf("check before cooldown = due:%t at:%v, want throttled at %v", due, nextCheckedAt, checkedAt)
	}

	wantNext := now.Add(kernelDegradedRebuildCooldown)
	due, nextCheckedAt = scheduleKernelDegradedIdleRebuildCheck(checkedAt, wantNext, true)
	if !due || !nextCheckedAt.Equal(wantNext) {
		t.Fatalf("check after cooldown = due:%t at:%v, want due at %v", due, nextCheckedAt, wantNext)
	}
}

func TestScheduleKernelDegradedIdleRebuildCheckSkipsMissingRuntime(t *testing.T) {
	lastCheckedAt := time.Unix(1_700_000_000, 0)
	due, checkedAt := scheduleKernelDegradedIdleRebuildCheck(lastCheckedAt, lastCheckedAt.Add(2*kernelDegradedRebuildCooldown), false)
	if due || !checkedAt.Equal(lastCheckedAt) {
		t.Fatalf("missing runtime check = due:%t at:%v, want skipped at %v", due, checkedAt, lastCheckedAt)
	}
}
