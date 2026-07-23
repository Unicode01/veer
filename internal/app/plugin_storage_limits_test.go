package app

import (
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginRecordStorageQuotaRejectsGrowingUpdate(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	limits := pluginResourceLimitsFromConfig(nil)
	original := store.PluginRecord{PluginID: "quota", ResourceID: "settings", RecordKey: "default", DataJSON: `{"v":"ok"}`, Enabled: true}
	limits.PluginDatabaseBytes = store.PluginRecordStorageBytes(original) + 8
	limits.GlobalDatabaseBytes = 1 << 20
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := ensurePluginRecordStorageQuota(tx, original.PluginID, nil, original, limits); err != nil {
		t.Fatalf("initial quota check: %v", err)
	}
	if _, err := store.AddPluginRecord(tx, &original); err != nil {
		t.Fatal(err)
	}
	previous, err := store.GetPluginRecord(tx, original.PluginID, original.ResourceID, original.RecordKey)
	if err != nil {
		t.Fatal(err)
	}
	next := original
	next.DataJSON = `{"v":"this update is larger than the remaining quota"}`
	if err := ensurePluginRecordStorageQuota(tx, original.PluginID, previous, next, limits); err == nil || !strings.Contains(err.Error(), "plugin database quota exceeded") {
		t.Fatalf("growing update quota error = %v", err)
	}
}

func TestPluginRecordStorageQuotaRejectsGlobalOverflow(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	first := store.PluginRecord{PluginID: "first", ResourceID: "settings", RecordKey: "default", DataJSON: `{}`, Enabled: true}
	second := store.PluginRecord{PluginID: "second", ResourceID: "settings", RecordKey: "default", DataJSON: `{}`, Enabled: true}
	limits := pluginResourceLimitsFromConfig(nil)
	limits.PluginDatabaseBytes = 1 << 20
	limits.GlobalDatabaseBytes = store.PluginRecordStorageBytes(first) + 8
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := ensurePluginRecordStorageQuota(tx, first.PluginID, nil, first, limits); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPluginRecord(tx, &first); err != nil {
		t.Fatal(err)
	}
	if err := ensurePluginRecordStorageQuota(tx, second.PluginID, nil, second, limits); err == nil || !strings.Contains(err.Error(), "global plugin database quota exceeded") {
		t.Fatalf("global quota error = %v", err)
	}
}

func TestPluginRecordStorageUsageCountsStoredBytes(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	record := store.PluginRecord{PluginID: "usage", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":"test"}`, Enabled: true}
	if _, err := store.AddPluginRecord(db, &record); err != nil {
		t.Fatal(err)
	}
	usage, err := store.GetPluginRecordStorageUsage(db, record.PluginID)
	if err != nil {
		t.Fatal(err)
	}
	if usage.Records != 1 || usage.Bytes != store.PluginRecordStorageBytes(record) {
		t.Fatalf("storage usage = %+v, want records=1 bytes=%d", usage, store.PluginRecordStorageBytes(record))
	}
}

func TestPluginDatabaseStorageUsageIncludesDurableOperations(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	record := store.PluginRecord{PluginID: "usage", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":"test"}`, Enabled: true}
	if _, err := store.AddPluginRecord(db, &record); err != nil {
		t.Fatal(err)
	}
	operation := store.PluginOperation{
		OperationID: "00000000000000000000000000000001", PluginID: record.PluginID, OperationKey: "apply",
		Kind: "router.apply", Status: "pending", InputJSON: `{}`, StateJSON: `{}`, ResultJSON: `null`, ErrorJSON: `null`,
	}
	if err := store.AddPluginOperation(db, operation); err != nil {
		t.Fatal(err)
	}
	wantBytes := store.PluginRecordStorageBytes(record) + store.PluginOperationStoredBytes(operation)
	for label, usageFn := range map[string]func() (store.PluginRecordStorageUsage, error){
		"plugin": func() (store.PluginRecordStorageUsage, error) {
			return store.GetPluginRecordStorageUsage(db, record.PluginID)
		},
		"global": func() (store.PluginRecordStorageUsage, error) {
			return store.GetGlobalPluginRecordStorageUsage(db)
		},
	} {
		usage, err := usageFn()
		if err != nil {
			t.Fatal(err)
		}
		if usage.Records != 2 || usage.Bytes != wantBytes {
			t.Fatalf("%s storage usage = %+v, want records=2 bytes=%d", label, usage, wantBytes)
		}
	}
}
