package store

import (
	"database/sql"
	"errors"
	"fmt"
)

var ErrPluginResourceMigrationPending = errors.New("plugin resource migration is pending")

const (
	pluginResourceSchemaColumns    = `id, plugin_id, resource_id, schema_version, schema_digest, status, transaction_id, updated_at`
	pluginResourceMigrationColumns = `id, transaction_id, plugin_id, resource_id, previous_schema_exists, previous_schema_version, previous_schema_digest, records_json, runtime_status_json, created_at`
)

func scanPluginResourceSchemaState(sc interface{ Scan(...interface{}) error }) (PluginResourceSchemaState, error) {
	var state PluginResourceSchemaState
	err := sc.Scan(&state.ID, &state.PluginID, &state.ResourceID, &state.SchemaVersion, &state.SchemaDigest, &state.Status, &state.TransactionID, &state.UpdatedAt)
	return state, err
}

func scanPluginResourceMigration(sc interface{ Scan(...interface{}) error }) (PluginResourceMigration, error) {
	var migration PluginResourceMigration
	var previousExists int
	err := sc.Scan(
		&migration.ID,
		&migration.TransactionID,
		&migration.PluginID,
		&migration.ResourceID,
		&previousExists,
		&migration.PreviousSchemaVersion,
		&migration.PreviousSchemaDigest,
		&migration.RecordsJSON,
		&migration.RuntimeStatusJSON,
		&migration.CreatedAt,
	)
	migration.PreviousSchemaExists = previousExists != 0
	return migration, err
}

func PluginResourceSchemaStateOrNil(db RuleStore, pluginID, resourceID string) (*PluginResourceSchemaState, error) {
	state, err := scanPluginResourceSchemaState(db.QueryRow(
		`SELECT `+pluginResourceSchemaColumns+` FROM plugin_resource_schemas WHERE plugin_id = ? AND resource_id = ?`,
		pluginID, resourceID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func UpsertPluginResourceSchemaState(db RuleStore, state PluginResourceSchemaState) error {
	if state.Status == "" {
		state.Status = "active"
	}
	_, err := db.Exec(
		`INSERT INTO plugin_resource_schemas (plugin_id, resource_id, schema_version, schema_digest, status, transaction_id, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, `+pluginNowSQL+`)
		 ON CONFLICT(plugin_id, resource_id) DO UPDATE SET
		   schema_version = excluded.schema_version,
		   schema_digest = excluded.schema_digest,
		   status = excluded.status,
		   transaction_id = excluded.transaction_id,
		   updated_at = `+pluginNowSQL,
		state.PluginID, state.ResourceID, state.SchemaVersion, state.SchemaDigest, state.Status, state.TransactionID,
	)
	return err
}

func DeletePluginResourceSchemaState(db RuleStore, pluginID, resourceID string) error {
	_, err := db.Exec(`DELETE FROM plugin_resource_schemas WHERE plugin_id = ? AND resource_id = ?`, pluginID, resourceID)
	return err
}

func EnsurePluginResourceMutationAllowed(db RuleStore, pluginID, resourceID string) error {
	return EnsurePluginResourceMutationAllowedForTransaction(db, pluginID, resourceID, "")
}

func EnsurePluginResourceMutationAllowedForTransaction(db RuleStore, pluginID, resourceID, transactionID string) error {
	state, err := PluginResourceSchemaStateOrNil(db, pluginID, resourceID)
	if err != nil {
		return err
	}
	if state != nil && (state.Status != "active" || state.TransactionID != "") {
		if transactionID != "" && state.Status == "pending" && state.TransactionID == transactionID {
			return nil
		}
		return fmt.Errorf("%w: %s/%s", ErrPluginResourceMigrationPending, pluginID, resourceID)
	}
	return nil
}

func AddPluginResourceMigration(db RuleStore, migration PluginResourceMigration) error {
	_, err := db.Exec(
		`INSERT INTO plugin_resource_migrations
		 (transaction_id, plugin_id, resource_id, previous_schema_exists, previous_schema_version, previous_schema_digest, records_json, runtime_status_json, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, `+pluginNowSQL+`)`,
		migration.TransactionID,
		migration.PluginID,
		migration.ResourceID,
		boolToInt(migration.PreviousSchemaExists),
		migration.PreviousSchemaVersion,
		migration.PreviousSchemaDigest,
		migration.RecordsJSON,
		migration.RuntimeStatusJSON,
	)
	return err
}

func GetPluginResourceMigrations(db RuleStore, transactionID string) ([]PluginResourceMigration, error) {
	query := `SELECT ` + pluginResourceMigrationColumns + ` FROM plugin_resource_migrations`
	args := []interface{}{}
	if transactionID != "" {
		query += ` WHERE transaction_id = ?`
		args = append(args, transactionID)
	}
	query += ` ORDER BY id ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginResourceMigration, 0)
	for rows.Next() {
		migration, err := scanPluginResourceMigration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, migration)
	}
	return out, rows.Err()
}

func DeletePluginResourceMigrations(db RuleStore, transactionID string) error {
	_, err := db.Exec(`DELETE FROM plugin_resource_migrations WHERE transaction_id = ?`, transactionID)
	return err
}

func DeletePluginRecordsForResource(db RuleStore, pluginID, resourceID string) error {
	_, err := db.Exec(`DELETE FROM plugin_records WHERE plugin_id = ? AND resource_id = ?`, pluginID, resourceID)
	return err
}

func AddPluginRecordExact(db RuleStore, item PluginRecord) error {
	if item.ID <= 0 {
		_, err := AddPluginRecord(db, &item)
		return err
	}
	_, err := db.Exec(
		`INSERT INTO plugin_records
		 (id, plugin_id, resource_id, record_key, data_json, enabled, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		item.ID, item.PluginID, item.ResourceID, item.RecordKey, item.DataJSON, boolToInt(item.Enabled), item.Revision, item.CreatedAt, item.UpdatedAt,
	)
	return err
}
