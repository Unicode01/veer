package store

import (
	"database/sql"
	"errors"
)

const pluginOperationAccountingOverheadBytes = 128

const pluginOperationColumns = `id, operation_id, plugin_id, operation_key, kind, status, phase,
	input_json, state_json, result_json, error_json, attempts, revision, next_attempt_unix_ms, created_at, updated_at`

func scanPluginOperation(sc interface{ Scan(...interface{}) error }) (PluginOperation, error) {
	var item PluginOperation
	err := sc.Scan(
		&item.ID,
		&item.OperationID,
		&item.PluginID,
		&item.OperationKey,
		&item.Kind,
		&item.Status,
		&item.Phase,
		&item.InputJSON,
		&item.StateJSON,
		&item.ResultJSON,
		&item.ErrorJSON,
		&item.Attempts,
		&item.Revision,
		&item.NextAttemptUnixMS,
		&item.CreatedAt,
		&item.UpdatedAt,
	)
	return item, err
}

func AddPluginOperation(db RuleStore, item PluginOperation) error {
	_, err := db.Exec(
		`INSERT INTO plugin_operations
		 (operation_id, plugin_id, operation_key, kind, status, phase, input_json, state_json,
		  result_json, error_json, attempts, revision, next_attempt_unix_ms, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, `+pluginNowSQL+`, `+pluginNowSQL+`)`,
		item.OperationID, item.PluginID, item.OperationKey, item.Kind, item.Status, item.Phase,
		item.InputJSON, item.StateJSON, item.ResultJSON, item.ErrorJSON, item.Attempts, item.NextAttemptUnixMS,
	)
	return err
}

func PluginOperationByID(db RuleStore, pluginID, operationID string) (*PluginOperation, error) {
	item, err := scanPluginOperation(db.QueryRow(
		`SELECT `+pluginOperationColumns+` FROM plugin_operations WHERE plugin_id = ? AND operation_id = ?`,
		pluginID, operationID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func PluginOperationByKey(db RuleStore, pluginID, operationKey string) (*PluginOperation, error) {
	item, err := scanPluginOperation(db.QueryRow(
		`SELECT `+pluginOperationColumns+` FROM plugin_operations WHERE plugin_id = ? AND operation_key = ?`,
		pluginID, operationKey,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func GetPluginOperations(db RuleStore, pluginID, kind, status string, limit int) ([]PluginOperation, error) {
	rows, err := db.Query(
		`SELECT `+pluginOperationColumns+` FROM plugin_operations
		 WHERE plugin_id = ? AND (? = '' OR kind = ?) AND (? = '' OR status = ?)
		 ORDER BY id ASC LIMIT ?`,
		pluginID, kind, kind, status, status, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginOperation, 0)
	for rows.Next() {
		item, err := scanPluginOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetAllPluginOperations(db RuleStore) ([]PluginOperation, error) {
	rows, err := db.Query(`SELECT ` + pluginOperationColumns + ` FROM plugin_operations ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginOperation, 0)
	for rows.Next() {
		item, err := scanPluginOperation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func CountPluginOperations(db RuleStore, pluginID string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM plugin_operations WHERE plugin_id = ?`, pluginID).Scan(&count)
	return count, err
}

func PluginOperationStatusCounts(db RuleStore, pluginID string) (map[string]int, error) {
	rows, err := db.Query(`SELECT status, COUNT(*) FROM plugin_operations WHERE plugin_id = ? GROUP BY status`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		out[status] = count
	}
	return out, rows.Err()
}

func CountResumablePluginOperations(db RuleStore, pluginID string, nowUnixMS int64) (int, error) {
	var count int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM plugin_operations
		 WHERE plugin_id = ? AND (status IN ('pending', 'running') OR (status = 'retry_wait' AND next_attempt_unix_ms <= ?))`,
		pluginID, nowUnixMS,
	).Scan(&count)
	return count, err
}

func PluginOperationStorageBytes(db RuleStore, pluginID string) (int64, error) {
	var bytes int64
	err := db.QueryRow(`SELECT COALESCE(SUM(
		length(CAST(operation_id AS BLOB)) + length(CAST(operation_key AS BLOB)) +
		length(CAST(kind AS BLOB)) + length(CAST(phase AS BLOB)) +
		length(CAST(input_json AS BLOB)) + length(CAST(state_json AS BLOB)) +
		length(CAST(result_json AS BLOB)) + length(CAST(error_json AS BLOB)) + ?
	), 0) FROM plugin_operations WHERE plugin_id = ?`, pluginOperationAccountingOverheadBytes, pluginID).Scan(&bytes)
	return bytes, err
}

func PluginOperationStoredBytes(item PluginOperation) int64 {
	return int64(len(item.OperationID) + len(item.OperationKey) + len(item.Kind) + len(item.Phase) +
		len(item.InputJSON) + len(item.StateJSON) + len(item.ResultJSON) + len(item.ErrorJSON) +
		pluginOperationAccountingOverheadBytes)
}

func ClaimPluginOperation(db RuleStore, pluginID, operationID, errorJSON string, expectedRevision, nowUnixMS int64) error {
	result, err := db.Exec(
		`UPDATE plugin_operations
		 SET status = 'running', attempts = attempts + 1, revision = revision + 1,
		     next_attempt_unix_ms = 0, error_json = ?, updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND operation_id = ? AND revision = ?
		   AND (status IN ('pending', 'running') OR (status = 'retry_wait' AND next_attempt_unix_ms <= ?))`,
		errorJSON, pluginID, operationID, expectedRevision, nowUnixMS,
	)
	return requirePluginOperationMutation(result, err)
}

func CheckpointPluginOperation(db RuleStore, item PluginOperation, expectedRevision int64) error {
	result, err := db.Exec(
		`UPDATE plugin_operations
		 SET status = 'running', phase = ?, state_json = ?, revision = revision + 1, updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND operation_id = ? AND revision = ? AND status = 'running'`,
		item.Phase, item.StateJSON, item.PluginID, item.OperationID, expectedRevision,
	)
	return requirePluginOperationMutation(result, err)
}

func TransitionPluginOperation(db RuleStore, item PluginOperation, expectedRevision int64) error {
	result, err := db.Exec(
		`UPDATE plugin_operations
		 SET status = ?, phase = ?, state_json = ?, result_json = ?, error_json = ?,
		     next_attempt_unix_ms = ?, revision = revision + 1, updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND operation_id = ? AND revision = ? AND status = 'running'`,
		item.Status, item.Phase, item.StateJSON, item.ResultJSON, item.ErrorJSON,
		item.NextAttemptUnixMS, item.PluginID, item.OperationID, expectedRevision,
	)
	return requirePluginOperationMutation(result, err)
}

func RestartPluginOperation(db RuleStore, item PluginOperation, expectedRevision int64) error {
	result, err := db.Exec(
		`UPDATE plugin_operations
		 SET kind = ?, status = 'pending', phase = '', input_json = ?, state_json = ?,
		     result_json = ?, error_json = ?, attempts = 0,
		     next_attempt_unix_ms = 0, revision = revision + 1, updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND operation_id = ? AND revision = ?
		   AND status IN ('completed', 'failed', 'cancelled')`,
		item.Kind, item.InputJSON, item.StateJSON, item.ResultJSON, item.ErrorJSON,
		item.PluginID, item.OperationID, expectedRevision,
	)
	return requirePluginOperationMutation(result, err)
}

func DeletePluginOperation(db RuleStore, pluginID, operationID string) error {
	result, err := db.Exec(
		`DELETE FROM plugin_operations
		 WHERE plugin_id = ? AND operation_id = ? AND status IN ('completed', 'failed', 'cancelled')`,
		pluginID, operationID,
	)
	return requirePluginOperationMutation(result, err)
}

func RewritePluginOperationPayloads(db RuleStore, item PluginOperation) error {
	result, err := db.Exec(
		`UPDATE plugin_operations SET input_json = ?, state_json = ?, result_json = ?, error_json = ? WHERE id = ?`,
		item.InputJSON, item.StateJSON, item.ResultJSON, item.ErrorJSON, item.ID,
	)
	return requirePluginOperationMutation(result, err)
}

func requirePluginOperationMutation(result sql.Result, err error) error {
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
