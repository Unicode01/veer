package store

import (
	"database/sql"
	"errors"
)

const pluginNetTransactionColumns = `id, transaction_id, plugin_id, kind, state_json, started_count, created_at, updated_at`

func scanPluginNetTransaction(sc interface{ Scan(...interface{}) error }) (PluginNetTransaction, error) {
	var item PluginNetTransaction
	err := sc.Scan(
		&item.ID,
		&item.TransactionID,
		&item.PluginID,
		&item.Kind,
		&item.StateJSON,
		&item.StartedCount,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	return item, err
}

func AddPluginNetTransaction(db RuleStore, item PluginNetTransaction) error {
	_, err := db.Exec(
		`INSERT INTO plugin_net_transactions (transaction_id, plugin_id, kind, state_json, started_count, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, `+pluginNowSQL+`, `+pluginNowSQL+`)`,
		item.TransactionID, item.PluginID, item.Kind, item.StateJSON, item.StartedCount,
	)
	return err
}

func UpdatePluginNetTransactionStarted(db RuleStore, transactionID string, startedCount int) error {
	result, err := db.Exec(
		`UPDATE plugin_net_transactions SET started_count = ?, updated_at = `+pluginNowSQL+` WHERE transaction_id = ?`,
		startedCount, transactionID,
	)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func GetPluginNetTransactions(db RuleStore) ([]PluginNetTransaction, error) {
	rows, err := db.Query(`SELECT ` + pluginNetTransactionColumns + ` FROM plugin_net_transactions ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginNetTransaction, 0)
	for rows.Next() {
		item, err := scanPluginNetTransaction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func PluginNetTransactionOrNil(db RuleStore, transactionID string) (*PluginNetTransaction, error) {
	item, err := scanPluginNetTransaction(db.QueryRow(
		`SELECT `+pluginNetTransactionColumns+` FROM plugin_net_transactions WHERE transaction_id = ?`, transactionID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func DeletePluginNetTransaction(db RuleStore, transactionID string) error {
	result, err := db.Exec(`DELETE FROM plugin_net_transactions WHERE transaction_id = ?`, transactionID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	return nil
}
