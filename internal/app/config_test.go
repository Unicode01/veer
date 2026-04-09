package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaultsManagedNetworkAutoRepairEnabled(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token"
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if !cfg.ManagedNetworkAutoRepairEnabled() {
		t.Fatal("ManagedNetworkAutoRepairEnabled() = false, want true by default")
	}
}

func TestLoadConfigAllowsDisablingManagedNetworkAutoRepair(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{
  "web_port": 8080,
  "web_token": "test-token",
  "managed_network_auto_repair": false
}`), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.ManagedNetworkAutoRepairEnabled() {
		t.Fatal("ManagedNetworkAutoRepairEnabled() = true, want false when explicitly disabled")
	}
}
