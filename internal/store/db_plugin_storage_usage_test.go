package store

import (
	"path/filepath"
	"testing"
)

func TestGetPluginRecordStorageUsagesMatchesScopedAccounting(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "storage-usage.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	records := []PluginRecord{
		{PluginID: "alpha", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":1}`, Enabled: true},
		{PluginID: "beta", ResourceID: "settings", RecordKey: "default", DataJSON: `{"value":2}`, Enabled: true},
	}
	for i := range records {
		if _, err := AddPluginRecord(db, &records[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := AddPluginOperation(db, PluginOperation{
		OperationID: "00000000000000000000000000000001", PluginID: "alpha", OperationKey: "apply",
		Kind: "test.run", Status: "pending", InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`,
	}); err != nil {
		t.Fatal(err)
	}

	byPlugin, global, err := GetPluginRecordStorageUsages(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(byPlugin) != 2 {
		t.Fatalf("plugin usage count = %d, want 2", len(byPlugin))
	}
	for _, pluginID := range []string{"alpha", "beta"} {
		want, err := GetPluginRecordStorageUsage(db, pluginID)
		if err != nil {
			t.Fatal(err)
		}
		if got := byPlugin[pluginID]; got != want {
			t.Fatalf("%s usage = %+v, want %+v", pluginID, got, want)
		}
	}
	wantGlobal, err := GetGlobalPluginRecordStorageUsage(db)
	if err != nil {
		t.Fatal(err)
	}
	if global != wantGlobal {
		t.Fatalf("global usage = %+v, want %+v", global, wantGlobal)
	}
}

func TestGetPluginRecordsByPluginIDsScopesAndOrdersResults(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "records-by-plugins.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	items := []PluginRecord{
		{PluginID: "alpha", ResourceID: "hooks", RecordKey: "first", DataJSON: `{}`, Enabled: true},
		{PluginID: "beta", ResourceID: "hooks", RecordKey: "only", DataJSON: `{}`, Enabled: true},
		{PluginID: "alpha", ResourceID: "other", RecordKey: "skip", DataJSON: `{}`, Enabled: true},
		{PluginID: "alpha", ResourceID: "hooks", RecordKey: "second", DataJSON: `{}`, Enabled: true},
		{PluginID: "ignored", ResourceID: "hooks", RecordKey: "skip", DataJSON: `{}`, Enabled: true},
	}
	for i := range items {
		if _, err := AddPluginRecord(db, &items[i]); err != nil {
			t.Fatal(err)
		}
	}

	records, err := GetPluginRecordsByPluginIDs(db, []string{" beta ", "alpha", "missing", "alpha", ""}, "hooks")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("plugin count = %d, want 3", len(records))
	}
	if got := records["alpha"]; len(got) != 2 || got[0].RecordKey != "first" || got[1].RecordKey != "second" {
		t.Fatalf("alpha records = %+v", got)
	}
	if got := records["beta"]; len(got) != 1 || got[0].RecordKey != "only" {
		t.Fatalf("beta records = %+v", got)
	}
	if got := records["missing"]; got == nil || len(got) != 0 {
		t.Fatalf("missing records = %#v, want non-nil empty slice", got)
	}
}
