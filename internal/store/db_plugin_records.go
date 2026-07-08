package store

import (
	"database/sql"
	"errors"
)

const (
	pluginRecordColumns        = `id, plugin_id, resource_id, record_key, data_json, enabled, revision, created_at, updated_at`
	pluginRuntimeStatusColumns = `id, plugin_id, target_type, target_id, status, revision, applied_revision, last_error, updated_at`
	pluginNowSQL               = `strftime('%Y-%m-%dT%H:%M:%fZ','now')`
)

func scanPluginRecord(sc interface{ Scan(...interface{}) error }) (PluginRecord, error) {
	var item PluginRecord
	var enabled int
	err := sc.Scan(&item.ID, &item.PluginID, &item.ResourceID, &item.RecordKey, &item.DataJSON, &enabled, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
	item.Enabled = enabled != 0
	return item, err
}

func scanPluginRuntimeStatus(sc interface{ Scan(...interface{}) error }) (PluginRuntimeStatus, error) {
	var item PluginRuntimeStatus
	err := sc.Scan(&item.ID, &item.PluginID, &item.TargetType, &item.TargetID, &item.Status, &item.Revision, &item.AppliedRevision, &item.LastError, &item.UpdatedAt)
	return item, err
}

func AddPluginRecord(db RuleStore, item *PluginRecord) (int64, error) {
	res, err := db.Exec(
		`INSERT INTO plugin_records (plugin_id, resource_id, record_key, data_json, enabled, revision, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 1, `+pluginNowSQL+`, `+pluginNowSQL+`)`,
		item.PluginID, item.ResourceID, item.RecordKey, item.DataJSON, boolToInt(item.Enabled),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func UpdatePluginRecord(db RuleStore, item *PluginRecord) error {
	res, err := db.Exec(
		`UPDATE plugin_records
		 SET data_json = ?, enabled = ?, revision = revision + 1, updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND resource_id = ? AND record_key = ?`,
		item.DataJSON, boolToInt(item.Enabled), item.PluginID, item.ResourceID, item.RecordKey,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func DeletePluginRecord(db RuleStore, pluginID, resourceID, recordKey string) error {
	res, err := db.Exec(`DELETE FROM plugin_records WHERE plugin_id = ? AND resource_id = ? AND record_key = ?`, pluginID, resourceID, recordKey)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func GetPluginRecord(db RuleStore, pluginID, resourceID, recordKey string) (*PluginRecord, error) {
	item, err := scanPluginRecord(db.QueryRow(`SELECT `+pluginRecordColumns+` FROM plugin_records WHERE plugin_id = ? AND resource_id = ? AND record_key = ?`, pluginID, resourceID, recordKey))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func GetPluginRecords(db RuleStore, pluginID, resourceID string) ([]PluginRecord, error) {
	rows, err := db.Query(`SELECT `+pluginRecordColumns+` FROM plugin_records WHERE plugin_id = ? AND resource_id = ? ORDER BY id ASC`, pluginID, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PluginRecord
	for rows.Next() {
		item, err := scanPluginRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetPluginRecordsPage(db RuleStore, pluginID, resourceID string, limit, offset int) ([]PluginRecord, error) {
	rows, err := db.Query(`SELECT `+pluginRecordColumns+` FROM plugin_records WHERE plugin_id = ? AND resource_id = ? ORDER BY id ASC LIMIT ? OFFSET ?`, pluginID, resourceID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PluginRecord
	for rows.Next() {
		item, err := scanPluginRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetPluginRecordsByResource(db RuleStore, resourceID string) ([]PluginRecord, error) {
	rows, err := db.Query(`SELECT `+pluginRecordColumns+` FROM plugin_records WHERE resource_id = ? ORDER BY plugin_id ASC, id ASC`, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PluginRecord
	for rows.Next() {
		item, err := scanPluginRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func CountPluginRecords(db RuleStore, pluginID, resourceID string) (int, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_records WHERE plugin_id = ? AND resource_id = ?`, pluginID, resourceID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func BumpPluginResourcePending(db RuleStore, pluginID, resourceID string) error {
	return UpsertPluginRuntimeStatus(db, PluginRuntimeStatus{
		PluginID:   pluginID,
		TargetType: "resource",
		TargetID:   resourceID,
		Status:     "pending",
		LastError:  "",
	})
}

func UpsertPluginRuntimeStatus(db RuleStore, item PluginRuntimeStatus) error {
	if item.Status == "" {
		item.Status = "idle"
	}
	_, err := db.Exec(
		`INSERT INTO plugin_runtime_status (plugin_id, target_type, target_id, status, revision, applied_revision, last_error, updated_at)
		 VALUES (?, ?, ?, ?, 1, ?, ?, `+pluginNowSQL+`)
		 ON CONFLICT(plugin_id, target_type, target_id) DO UPDATE SET
		   status = excluded.status,
		   revision = plugin_runtime_status.revision + 1,
		   applied_revision = CASE
		     WHEN excluded.applied_revision > 0 THEN excluded.applied_revision
		     ELSE plugin_runtime_status.applied_revision
		   END,
		   last_error = excluded.last_error,
		   updated_at = `+pluginNowSQL,
		item.PluginID, item.TargetType, item.TargetID, item.Status, item.AppliedRevision, item.LastError,
	)
	return err
}

func MarkPluginRuntimeError(db RuleStore, pluginID, targetType, targetID, message string) error {
	_, err := db.Exec(
		`INSERT INTO plugin_runtime_status (plugin_id, target_type, target_id, status, revision, applied_revision, last_error, updated_at)
		 VALUES (?, ?, ?, 'error', 1, 0, ?, `+pluginNowSQL+`)
		 ON CONFLICT(plugin_id, target_type, target_id) DO UPDATE SET
		   status = 'error',
		   last_error = excluded.last_error,
		   updated_at = `+pluginNowSQL,
		pluginID, targetType, targetID, message,
	)
	return err
}

func MarkPluginRuntimeApplied(db RuleStore, pluginID, targetType, targetID string, appliedRevision int64) error {
	res, err := db.Exec(
		`UPDATE plugin_runtime_status
		 SET status = 'applied', applied_revision = ?, last_error = '', updated_at = `+pluginNowSQL+`
		 WHERE plugin_id = ? AND target_type = ? AND target_id = ?`,
		appliedRevision, pluginID, targetType, targetID,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func GetPluginRuntimeStatus(db RuleStore, pluginID, targetType, targetID string) (*PluginRuntimeStatus, error) {
	item, err := scanPluginRuntimeStatus(db.QueryRow(`SELECT `+pluginRuntimeStatusColumns+` FROM plugin_runtime_status WHERE plugin_id = ? AND target_type = ? AND target_id = ?`, pluginID, targetType, targetID))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func GetPluginRuntimeStatuses(db RuleStore, pluginID string) ([]PluginRuntimeStatus, error) {
	rows, err := db.Query(`SELECT `+pluginRuntimeStatusColumns+` FROM plugin_runtime_status WHERE plugin_id = ? ORDER BY target_type ASC, target_id ASC`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PluginRuntimeStatus
	for rows.Next() {
		item, err := scanPluginRuntimeStatus(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func DeletePluginRuntimeStatus(db RuleStore, pluginID, targetType, targetID string) error {
	res, err := db.Exec(`DELETE FROM plugin_runtime_status WHERE plugin_id = ? AND target_type = ? AND target_id = ?`, pluginID, targetType, targetID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func PluginRuntimeStatusOrNil(db RuleStore, pluginID, targetType, targetID string) (*PluginRuntimeStatus, error) {
	item, err := GetPluginRuntimeStatus(db, pluginID, targetType, targetID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}
