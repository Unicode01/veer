//go:build linux

package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxIPv6AssignmentNetOpsPreserveIPv6AssignmentStateOnClose(t *testing.T) {
	ops := newLinuxIPv6AssignmentNetOps()

	t.Run("env unset", func(t *testing.T) {
		t.Setenv(forwardHotRestartMarkerEnv, "")
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatal("PreserveIPv6AssignmentStateOnClose() = true, want false when marker env is unset")
		}
	})

	t.Run("marker missing", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = true, want false when marker %q is missing", marker)
		}
	})

	t.Run("marker present", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", marker, err)
		}
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if !ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = false, want true when marker %q exists", marker)
		}
	})
}
