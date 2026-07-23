package store

import (
	"fmt"
	"strings"
	"time"
)

const (
	pluginLogRetentionPerPlugin = 5000
	pluginLogRetentionGlobal    = 50000
)

func AddPluginLogs(db RuleStore, items []PluginLog) error {
	if db == nil || len(items) == 0 {
		return nil
	}
	var query strings.Builder
	query.WriteString(`INSERT INTO plugin_logs (plugin_id, level, message, fields_json, event, worker, created_at) VALUES `)
	args := make([]interface{}, 0, len(items)*7)
	pluginIDs := make(map[string]struct{})
	for i, item := range items {
		if i > 0 {
			query.WriteByte(',')
		}
		query.WriteString(`(?, ?, ?, ?, ?, ?, ?)`)
		if item.FieldsJSON == "" {
			item.FieldsJSON = "{}"
		}
		if item.CreatedAt == "" {
			item.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		}
		args = append(args, item.PluginID, item.Level, item.Message, item.FieldsJSON, item.Event, item.Worker, item.CreatedAt)
		pluginIDs[item.PluginID] = struct{}{}
	}
	if _, err := db.Exec(query.String(), args...); err != nil {
		return err
	}
	for pluginID := range pluginIDs {
		if _, err := db.Exec(
			`DELETE FROM plugin_logs
			 WHERE plugin_id = ? AND id <= COALESCE((
				 SELECT id FROM plugin_logs WHERE plugin_id = ? ORDER BY id DESC LIMIT 1 OFFSET ?
			 ), 0)`,
			pluginID, pluginID, pluginLogRetentionPerPlugin,
		); err != nil {
			return err
		}
	}
	_, err := db.Exec(
		`DELETE FROM plugin_logs
		 WHERE id <= COALESCE((SELECT id FROM plugin_logs ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`,
		pluginLogRetentionGlobal,
	)
	return err
}

func GetPluginLogs(db RuleStore, pluginID, level string, limit int, beforeID int64) ([]PluginLog, error) {
	if db == nil {
		return []PluginLog{}, nil
	}
	if limit <= 0 || limit > 500 {
		return nil, fmt.Errorf("plugin log limit must be between 1 and 500")
	}
	query := `SELECT id, plugin_id, level, message, fields_json, event, worker, created_at
		FROM plugin_logs WHERE plugin_id = ?`
	args := []interface{}{pluginID}
	if level != "" {
		query += ` AND level = ?`
		args = append(args, level)
	}
	if beforeID > 0 {
		query += ` AND id < ?`
		args = append(args, beforeID)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginLog, 0, limit)
	for rows.Next() {
		var item PluginLog
		if err := rows.Scan(&item.ID, &item.PluginID, &item.Level, &item.Message, &item.FieldsJSON, &item.Event, &item.Worker, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func CountPluginLogs(db RuleStore, pluginID string) (uint64, error) {
	if db == nil {
		return 0, nil
	}
	var count uint64
	if err := db.QueryRow(`SELECT COUNT(*) FROM plugin_logs WHERE plugin_id = ?`, pluginID).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
