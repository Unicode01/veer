//go:build linux

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKernelHotRestartSkipStatsRequested(t *testing.T) {
	marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
	t.Setenv(forwardHotRestartMarkerEnv, marker)

	skipMarker := marker + ".skip-stats"
	if got := kernelHotRestartSkipStatsMarkerPath(); got != skipMarker {
		t.Fatalf("kernelHotRestartSkipStatsMarkerPath() = %q, want %q", got, skipMarker)
	}
	if kernelHotRestartSkipStatsRequested() {
		t.Fatal("kernelHotRestartSkipStatsRequested() = true, want false without marker file")
	}

	if err := os.WriteFile(skipMarker, []byte("1"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", skipMarker, err)
	}
	if !kernelHotRestartSkipStatsRequested() {
		t.Fatal("kernelHotRestartSkipStatsRequested() = false, want true with marker file")
	}
}
