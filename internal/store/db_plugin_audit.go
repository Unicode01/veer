package store

import "fmt"

const pluginAuditLogRetention = 10000

func AddPluginAuditLog(db RuleStore, item PluginAuditLog) error {
	if db == nil {
		return nil
	}
	if item.Actor == "" {
		item.Actor = "system"
	}
	if item.DetailsJSON == "" {
		item.DetailsJSON = "{}"
	}
	if _, err := db.Exec(
		`INSERT INTO plugin_audit_logs (plugin_id, operation, actor, outcome, details_json, created_at)
		 VALUES (?, ?, ?, ?, ?, `+pluginNowSQL+`)`,
		item.PluginID, item.Operation, item.Actor, item.Outcome, item.DetailsJSON,
	); err != nil {
		return err
	}
	_, err := db.Exec(
		`DELETE FROM plugin_audit_logs
		 WHERE id <= COALESCE((SELECT id FROM plugin_audit_logs ORDER BY id DESC LIMIT 1 OFFSET ?), 0)`,
		pluginAuditLogRetention,
	)
	return err
}

func GetPluginAuditLogs(db RuleStore, pluginID string, limit int, beforeID int64) ([]PluginAuditLog, error) {
	if limit <= 0 || limit > 500 {
		return nil, fmt.Errorf("plugin audit limit must be between 1 and 500")
	}
	query := `SELECT id, plugin_id, operation, actor, outcome, details_json, created_at FROM plugin_audit_logs WHERE 1 = 1`
	args := make([]interface{}, 0, 3)
	if pluginID != "" {
		query += ` AND plugin_id = ?`
		args = append(args, pluginID)
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
	out := make([]PluginAuditLog, 0, limit)
	for rows.Next() {
		var item PluginAuditLog
		if err := rows.Scan(&item.ID, &item.PluginID, &item.Operation, &item.Actor, &item.Outcome, &item.DetailsJSON, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
