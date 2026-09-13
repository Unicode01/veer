package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPluginCatalogScanCacheRetainsFullContentVerification(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.js")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Unix(123, 0), time.Unix(123, 0)); err != nil {
			t.Fatal(err)
		}
	}
	write("one")
	cache := &pluginCatalogFingerprintCache{}
	now := time.Now()
	first, err := cache.fingerprint(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cache.fingerprint(dir, now.Add(time.Second)); err != nil || got != first {
		t.Fatalf("unchanged scan = %s, %v", got, err)
	}
	write("two")
	full, err := buildPluginDirectoryFingerprint(dir)
	if err != nil || full == first {
		t.Fatalf("uncached candidate validation missed content change: %v", err)
	}
	if got, err := cache.fingerprint(dir, now.Add(pluginCatalogFullScanEvery)); err != nil || got != full {
		t.Fatalf("periodic verification missed preserved-metadata edit: %v", err)
	}
	write("longer")
	if got, err := cache.fingerprint(dir, now.Add(pluginCatalogFullScanEvery+time.Second)); err != nil || got == full {
		t.Fatalf("metadata change not detected immediately: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.fingerprint(dir, now.Add(pluginCatalogFullScanEvery+2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(cache.files) != 0 {
		t.Fatal("removed file retained in cache")
	}
}

func TestPluginCatalogScanDoesNotBlockMonitorAndCoalesces(t *testing.T) {
	pm := &ProcessManager{cfg: pluginsEnabledTestConfig(&Config{PluginsDir: t.TempDir()})}
	pm.pluginCatalogUpdateMu.Lock()
	pm.startPluginCatalogDriftCheck()
	pm.startPluginCatalogDriftCheck()
	pm.mu.Lock()
	running := pm.pluginCatalogScanRunning
	pm.shuttingDown = true
	pm.mu.Unlock()
	pm.pluginCatalogUpdateMu.Unlock()
	if !running {
		t.Fatal("background scan was not reserved")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		pm.mu.Lock()
		running = pm.pluginCatalogScanRunning
		checked := !pm.pluginCatalogCheckAt.IsZero()
		pm.mu.Unlock()
		if !running {
			if checked {
				t.Fatal("scan published results after shutdown")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background scan did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}
