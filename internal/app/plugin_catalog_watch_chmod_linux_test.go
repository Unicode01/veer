//go:build linux

package app

import (
	"os"
	"testing"
	"time"
)

// The probation check builds a package manager every five seconds, and each
// one prepares the plugins directory. Preparing a directory that already has
// its mode must not look like a catalog change to the update monitor.
func TestPluginPackageDirectoryPreparationLeavesTheCatalogWatchQuiet(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	w, err := openPluginCatalogWatcher(root)
	if err != nil {
		t.Skipf("inotify unavailable: %v", err)
	}
	defer w.Close()
	_ = w.takeChange()

	for i := 0; i < 3; i++ {
		if err := ensurePluginPackageDirectory(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if w.takeChange() {
		t.Fatal("preparing an unchanged plugins directory reported a catalog change")
	}

	if err := ensurePluginPackageDirectory(root, 0o750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatalf("mode = %v, want 0750", info.Mode().Perm())
	}
	deadline := time.Now().Add(5 * time.Second)
	for !w.takeChange() {
		if time.Now().After(deadline) {
			t.Fatal("a real mode change was not seen")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
