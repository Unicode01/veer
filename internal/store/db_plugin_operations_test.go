package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPluginOperationClaimUsesRevisionCAS(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "operations.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	item := PluginOperation{
		OperationID: "00000000000000000000000000000001", PluginID: "plugin", OperationKey: "default",
		Kind: "router.apply", Status: "pending", InputJSON: `{}`, StateJSON: `{}`, ResultJSON: `null`, ErrorJSON: `null`,
	}
	if err := AddPluginOperation(db, item); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- ClaimPluginOperation(db, "plugin", item.OperationID, `null`, 1, time.Now().UnixMilli())
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	stale := 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, sql.ErrNoRows) {
			stale++
		} else {
			t.Fatalf("claim error = %v", err)
		}
	}
	if successes != 1 || stale != 1 {
		t.Fatalf("claim outcomes success=%d stale=%d", successes, stale)
	}
	claimed, err := PluginOperationByID(db, "plugin", item.OperationID)
	if err != nil || claimed == nil || claimed.Status != "running" || claimed.Attempts != 1 || claimed.Revision != 2 {
		t.Fatalf("claimed operation = %+v, err=%v", claimed, err)
	}
}

func TestDeletePluginDataPurgesPluginOperations(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "operations-purge.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, pluginID := range []string{"remove", "keep"} {
		if err := AddPluginOperation(db, PluginOperation{
			OperationID: pluginID + "000000000000000000000000000", PluginID: pluginID, OperationKey: "default",
			Kind: "test.run", Status: "pending", InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := DeletePluginData(db, "remove"); err != nil {
		t.Fatal(err)
	}
	if count, err := CountPluginOperations(db, "remove"); err != nil || count != 0 {
		t.Fatalf("removed operation count = %d, err=%v", count, err)
	}
	if count, err := CountPluginOperations(db, "keep"); err != nil || count != 1 {
		t.Fatalf("kept operation count = %d, err=%v", count, err)
	}
}

func TestPluginOperationStoredBytesMatchesDatabaseAccounting(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "operations-accounting.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	item := PluginOperation{
		OperationID: "00000000000000000000000000000001", PluginID: "plugin", OperationKey: "default",
		Kind: "router.apply", Status: "pending", Phase: "prepare", InputJSON: `{"input":1}`,
		StateJSON: `{"state":2}`, ResultJSON: `null`, ErrorJSON: `null`,
	}
	if err := AddPluginOperation(db, item); err != nil {
		t.Fatal(err)
	}
	used, err := PluginOperationStorageBytes(db, item.PluginID)
	if err != nil {
		t.Fatal(err)
	}
	if want := PluginOperationStoredBytes(item); used != want {
		t.Fatalf("operation storage bytes = %d, want %d", used, want)
	}
}
