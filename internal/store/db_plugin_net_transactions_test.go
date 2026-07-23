package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestPluginNetTransactionCRUD(t *testing.T) {
	db, err := InitDB(filepath.Join(t.TempDir(), "transactions.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	record := PluginNetTransaction{
		TransactionID: "tx-1", PluginID: "plugin-a", Kind: "route", StateJSON: `{"version":1}`, StartedCount: 0,
	}
	if err := AddPluginNetTransaction(db, record); err != nil {
		t.Fatal(err)
	}
	if err := AddPluginNetTransaction(db, record); err == nil {
		t.Fatal("duplicate transaction ID was accepted")
	}
	if err := UpdatePluginNetTransactionStarted(db, record.TransactionID, 2); err != nil {
		t.Fatal(err)
	}
	got, err := PluginNetTransactionOrNil(db, record.TransactionID)
	if err != nil || got == nil || got.StartedCount != 2 || got.PluginID != record.PluginID {
		t.Fatalf("transaction = %+v, err=%v", got, err)
	}
	items, err := GetPluginNetTransactions(db)
	if err != nil || len(items) != 1 || items[0].TransactionID != record.TransactionID {
		t.Fatalf("transactions = %+v, err=%v", items, err)
	}
	if err := DeletePluginNetTransaction(db, record.TransactionID); err != nil {
		t.Fatal(err)
	}
	if got, err := PluginNetTransactionOrNil(db, record.TransactionID); err != nil || got != nil {
		t.Fatalf("deleted transaction = %+v, err=%v", got, err)
	}
	for _, err := range []error{
		UpdatePluginNetTransactionStarted(db, record.TransactionID, 1),
		DeletePluginNetTransaction(db, record.TransactionID),
	} {
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("missing transaction error = %v, want sql.ErrNoRows", err)
		}
	}
}
