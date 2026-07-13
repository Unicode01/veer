//go:build linux

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigTightensSensitiveFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"web_token":"test-token"}`), 0o644); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("loadConfig(): %v", err)
	}
	assertPrivateRuntimeFileMode(t, path)
}

func TestInitDBTightensSensitiveFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forward.db")
	db, err := initDB(path)
	if err != nil {
		t.Fatalf("initDB(): %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}

	assertPrivateRuntimeFileMode(t, path)
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			assertPrivateRuntimeFileMode(t, path+suffix)
		} else if !os.IsNotExist(err) {
			t.Fatalf("Lstat(%s): %v", path+suffix, err)
		}
	}
}

func TestInitDBRejectsSymbolicLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.db")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatalf("WriteFile(): %v", err)
	}
	link := filepath.Join(dir, "forward.db")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Symlink unavailable: %v", err)
	}

	if db, err := initDB(link); err == nil {
		_ = db.Close()
		t.Fatal("initDB() error = nil, want symbolic-link rejection")
	} else if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("initDB() error = %q, want symbolic-link rejection", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile(target): %v", err)
	}
	if string(data) != "unchanged" {
		t.Fatalf("target content = %q, want unchanged", data)
	}
}

func assertPrivateRuntimeFileMode(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode(%s) = %#o, want 0600", path, got)
	}
}
