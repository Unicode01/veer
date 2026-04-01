package app

import (
	"testing"
	"time"
)

func TestShouldRefreshKernelStatsLockedRequiresRecentDemand(t *testing.T) {
	now := time.Now()
	pm := &ProcessManager{
		kernelRuntime: stubKernelStatsRuntime{},
		kernelRules:   map[int64]bool{1: true},
	}

	if pm.shouldRefreshKernelStatsLocked(now) {
		t.Fatal("shouldRefreshKernelStatsLocked() = true without demand")
	}

	pm.kernelStatsDemandAt = now.Add(-(kernelStatsDemandWindow + time.Second))
	if pm.shouldRefreshKernelStatsLocked(now) {
		t.Fatal("shouldRefreshKernelStatsLocked() = true with expired demand")
	}

	pm.kernelStatsDemandAt = now
	pm.kernelStatsAt = now.Add(-(kernelStatsRefreshInterval + time.Second))
	if !pm.shouldRefreshKernelStatsLocked(now) {
		t.Fatal("shouldRefreshKernelStatsLocked() = false, want true with recent demand and stale cache")
	}

	pm.kernelStatsAt = now
	if pm.shouldRefreshKernelStatsLocked(now) {
		t.Fatal("shouldRefreshKernelStatsLocked() = true with fresh cache")
	}
}
