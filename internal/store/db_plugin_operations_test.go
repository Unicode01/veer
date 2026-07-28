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

func TestPluginOperationSummariesBatchByPlugin(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "operation-summaries.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Now().UnixMilli()
	items := []PluginOperation{
		{OperationID: "00000000000000000000000000000001", PluginID: "alpha", OperationKey: "pending", Kind: "test.run", Status: "pending", InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`},
		{OperationID: "00000000000000000000000000000002", PluginID: "alpha", OperationKey: "retry", Kind: "test.run", Status: "retry_wait", NextAttemptUnixMS: now + 60_000, InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`},
		{OperationID: "00000000000000000000000000000003", PluginID: "alpha", OperationKey: "complete", Kind: "test.run", Status: "completed", InputJSON: `null`, StateJSON: `null`, ResultJSON: `{"ok":true}`, ErrorJSON: `null`},
		{OperationID: "00000000000000000000000000000004", PluginID: "beta", OperationKey: "running", Kind: "test.run", Status: "running", InputJSON: `null`, StateJSON: `{"step":1}`, ResultJSON: `null`, ErrorJSON: `null`},
		{OperationID: "00000000000000000000000000000005", PluginID: "ignored", OperationKey: "pending", Kind: "test.run", Status: "pending", InputJSON: `null`, StateJSON: `null`, ResultJSON: `null`, ErrorJSON: `null`},
	}
	for _, item := range items {
		if err := AddPluginOperation(db, item); err != nil {
			t.Fatal(err)
		}
	}

	summaries, err := PluginOperationSummaries(db, []string{" beta ", "alpha", "missing", "alpha", ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 3 {
		t.Fatalf("summary count = %d, want 3", len(summaries))
	}
	alpha := summaries["alpha"]
	if alpha.Total != 3 || alpha.Resumable != 1 || alpha.ByStatus["pending"] != 1 || alpha.ByStatus["retry_wait"] != 1 || alpha.ByStatus["completed"] != 1 {
		t.Fatalf("alpha summary = %+v", alpha)
	}
	alphaBytes, err := PluginOperationStorageBytes(db, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if alpha.Bytes != alphaBytes {
		t.Fatalf("alpha bytes = %d, want %d", alpha.Bytes, alphaBytes)
	}
	beta := summaries["beta"]
	if beta.Total != 1 || beta.Resumable != 1 || beta.ByStatus["running"] != 1 {
		t.Fatalf("beta summary = %+v", beta)
	}
	missing := summaries["missing"]
	if missing.Total != 0 || missing.Resumable != 0 || missing.Bytes != 0 || len(missing.ByStatus) != 0 {
		t.Fatalf("missing summary = %+v", missing)
	}
}
