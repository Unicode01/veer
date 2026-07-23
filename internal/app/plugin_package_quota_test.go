package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPluginPackageInstalledAndStagingQuotas(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.cfg.PluginsMaxInstalled = 1
	if err := os.Mkdir(filepath.Join(manager.pluginsRoot, "existing_plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := manager.enforcePluginPackageInstalledQuota(1); err == nil || !strings.Contains(err.Error(), "installed plugin limit") {
		t.Fatalf("installed quota error = %v", err)
	}

	manager.cfg.PluginsMaxStaged = 1
	stageID := strings.Repeat("a", 32)
	stageDir := filepath.Join(manager.stateRoot, "staging", stageID)
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stage := PluginPackageStage{ID: stageID, PluginID: "existing_plugin", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}
	if err := writePluginPackageJSONAtomic(filepath.Join(stageDir, pluginPackageStageMetadataFile), pluginPackageStageRecord{Stage: stage}, false); err != nil {
		t.Fatal(err)
	}
	if err := manager.enforcePluginPackageStageQuota(); err == nil || !strings.Contains(err.Error(), "staging limit") {
		t.Fatalf("staging quota error = %v", err)
	}
}

func TestPluginPackageStorageQuotaPrunesOldUnprotectedHistory(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.cfg.PluginsStorageLimitMB = 1
	pluginID := "quota_plugin"
	if err := os.Mkdir(filepath.Join(manager.pluginsRoot, pluginID), 0o700); err != nil {
		t.Fatal(err)
	}
	writePluginPackageQuotaFile(t, filepath.Join(manager.pluginsRoot, pluginID, "current.bin"), 96<<10)

	type historyFixture struct {
		id        string
		createdAt string
	}
	histories := []historyFixture{
		{id: "20260101T010101.000000000Z-aaaaaaaa", createdAt: "2026-01-01T01:01:01Z"},
		{id: "20260201T010101.000000000Z-bbbbbbbb", createdAt: "2026-02-01T01:01:01Z"},
		{id: "20260301T010101.000000000Z-cccccccc", createdAt: "2026-03-01T01:01:01Z"},
	}
	for _, history := range histories {
		historyDir := filepath.Join(manager.stateRoot, "history", pluginID, history.id)
		pluginDir := filepath.Join(historyDir, "plugin")
		if err := os.MkdirAll(pluginDir, 0o700); err != nil {
			t.Fatal(err)
		}
		writePluginPackageQuotaFile(t, filepath.Join(pluginDir, "payload.bin"), 400<<10)
		entry := PluginPackageHistoryEntry{
			ID: history.id, PluginID: pluginID, Version: "1.0.0", CreatedAt: history.createdAt, Reason: "quota test",
		}
		if err := writePluginPackageJSONAtomic(filepath.Join(historyDir, pluginPackageHistoryMetadataFile), entry, false); err != nil {
			t.Fatal(err)
		}
	}
	probation := PluginPackageProbation{
		PluginID: pluginID, Version: "2.0.0", PreviousHistoryID: histories[0].id,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	}
	if err := writePluginPackageJSONAtomic(filepath.Join(manager.stateRoot, "probation", pluginID+pluginPackageProbationFileSuffix), probation, false); err != nil {
		t.Fatal(err)
	}

	if err := manager.enforcePluginPackageStorageQuota(96 << 10); err != nil {
		t.Fatal(err)
	}
	oldest := filepath.Join(manager.stateRoot, "history", pluginID, histories[0].id)
	middle := filepath.Join(manager.stateRoot, "history", pluginID, histories[1].id)
	newest := filepath.Join(manager.stateRoot, "history", pluginID, histories[2].id)
	if _, err := os.Stat(oldest); err != nil {
		t.Fatalf("probation-protected history was removed: %v", err)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Fatalf("newest history was removed: %v", err)
	}
	if _, err := os.Stat(middle); !os.IsNotExist(err) {
		t.Fatalf("old unprotected history remains: %v", err)
	}
}

func TestPluginPackageStorageQuotaRejectsWhenNothingCanBePruned(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.cfg.PluginsStorageLimitMB = 1
	writePluginPackageQuotaFile(t, filepath.Join(manager.pluginsRoot, "large.bin"), 900<<10)
	if err := manager.enforcePluginPackageStorageQuota(200 << 10); err == nil || !strings.Contains(err.Error(), "storage quota exceeded") {
		t.Fatalf("storage quota error = %v", err)
	}
}

func writePluginPackageQuotaFile(t *testing.T, path string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- private test path.
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
