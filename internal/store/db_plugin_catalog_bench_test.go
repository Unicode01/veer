package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkPluginCatalogReadModel(b *testing.B) {
	db, err := InitDB(filepath.Join(b.TempDir(), "plugin-catalog.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	pluginIDs := make([]string, 32)
	for i := range pluginIDs {
		pluginID := fmt.Sprintf("plugin_%02d", i)
		pluginIDs[i] = pluginID
		record := PluginRecord{
			PluginID: pluginID, ResourceID: "settings", RecordKey: "default", DataJSON: `{"enabled":true}`, Enabled: true,
		}
		if _, err := AddPluginRecord(db, &record); err != nil {
			b.Fatal(err)
		}
		if err := AddPluginOperation(db, PluginOperation{
			OperationID: fmt.Sprintf("%032x", i+1), PluginID: pluginID, OperationKey: "apply",
			Kind: "router.apply", Status: "pending", InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`,
		}); err != nil {
			b.Fatal(err)
		}
		if err := AddPluginOwnedResource(db, PluginOwnedResource{
			PluginID: pluginID, ResourceType: "link", ResourceKey: pluginID + "_link", MetadataJSON: `{}`,
		}); err != nil {
			b.Fatal(err)
		}
	}
	now := time.Now().UnixMilli()

	b.Run("per_plugin", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := GetGlobalPluginRecordStorageUsage(db); err != nil {
				b.Fatal(err)
			}
			for _, pluginID := range pluginIDs {
				if _, err := GetPluginRecordStorageUsage(db, pluginID); err != nil {
					b.Fatal(err)
				}
				if _, err := PluginOperationStatusCounts(db, pluginID); err != nil {
					b.Fatal(err)
				}
				if _, err := CountResumablePluginOperations(db, pluginID, now); err != nil {
					b.Fatal(err)
				}
				if _, err := PluginOperationStorageBytes(db, pluginID); err != nil {
					b.Fatal(err)
				}
				if _, err := GetPluginOwnedResources(db, pluginID); err != nil {
					b.Fatal(err)
				}
				if _, err := GetPluginRecords(db, pluginID, "settings"); err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("batched", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := GetPluginRecordStorageUsages(db); err != nil {
				b.Fatal(err)
			}
			if _, err := PluginOperationSummaries(db, pluginIDs, now); err != nil {
				b.Fatal(err)
			}
			if _, err := GetPluginOwnedResourcesByPluginIDs(db, pluginIDs); err != nil {
				b.Fatal(err)
			}
			if _, err := GetPluginRecordsByPluginIDs(db, pluginIDs, "settings"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
