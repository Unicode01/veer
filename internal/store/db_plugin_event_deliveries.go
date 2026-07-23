package store

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	PluginEventDeliveryPending = "pending"
	PluginEventDeliveryDead    = "dead"
)

type PluginEventDelivery struct {
	ID                int64
	DeliveryID        string
	PluginID          string
	SubscriptionID    string
	Topic             string
	Sequence          uint64
	PublishedAt       string
	SourcePlugin      string
	TargetPlugin      string
	ResourceID        string
	SchemaVersion     int
	PayloadJSON       string
	Attempts          int
	MaxAttempts       int
	NextAttemptUnixMS int64
	Status            string
	LastError         string
	CreatedAt         string
	UpdatedAt         string
}

const pluginEventDeliveryColumns = `id, delivery_id, plugin_id, subscription_id, topic, sequence,
	published_at, source_plugin, target_plugin, resource_id, schema_version, payload_json,
	attempts, max_attempts, next_attempt_unix_ms, status, last_error, created_at, updated_at`

func CreatePluginEventDeliveries(db *sql.DB, deliveries []PluginEventDelivery, perPluginLimit, globalLimit int) error {
	if db == nil {
		return fmt.Errorf("plugin event delivery store is unavailable")
	}
	if len(deliveries) == 0 {
		return nil
	}
	if perPluginLimit < 1 || globalLimit < perPluginLimit {
		return fmt.Errorf("plugin event delivery limits are invalid")
	}
	counts := make(map[string]int)
	for i := range deliveries {
		if err := validatePluginEventDelivery(deliveries[i]); err != nil {
			return fmt.Errorf("plugin event delivery %d: %w", i, err)
		}
		counts[deliveries[i].PluginID]++
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var globalCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM plugin_event_deliveries`).Scan(&globalCount); err != nil {
		return err
	}
	if globalCount+len(deliveries) > globalLimit {
		return fmt.Errorf("global durable event record limit %d reached", globalLimit)
	}
	for pluginID, addition := range counts {
		var current int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM plugin_event_deliveries WHERE plugin_id = ?`, pluginID).Scan(&current); err != nil {
			return err
		}
		if current+addition > perPluginLimit {
			return fmt.Errorf("plugin %s durable event record limit %d reached", pluginID, perPluginLimit)
		}
	}
	for _, item := range deliveries {
		if _, err := tx.Exec(
			`INSERT INTO plugin_event_deliveries
			 (delivery_id, plugin_id, subscription_id, topic, sequence, published_at, source_plugin,
			  target_plugin, resource_id, schema_version, payload_json, attempts, max_attempts,
			  next_attempt_unix_ms, status, last_error, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, '', `+pluginNowSQL+`, `+pluginNowSQL+`)`,
			item.DeliveryID, item.PluginID, item.SubscriptionID, item.Topic, item.Sequence,
			item.PublishedAt, item.SourcePlugin, item.TargetPlugin, item.ResourceID,
			item.SchemaVersion, item.PayloadJSON, item.MaxAttempts, item.NextAttemptUnixMS,
			PluginEventDeliveryPending,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func GetDuePluginEventDeliveries(db RuleStore, pluginID, subscriptionID string, nowUnixMS int64, limit int) ([]PluginEventDelivery, error) {
	if db == nil {
		return nil, fmt.Errorf("plugin event delivery store is unavailable")
	}
	if limit < 1 {
		return []PluginEventDelivery{}, nil
	}
	rows, err := db.Query(
		`SELECT `+pluginEventDeliveryColumns+`
		   FROM plugin_event_deliveries
		  WHERE plugin_id = ? AND subscription_id = ? AND status = ? AND next_attempt_unix_ms <= ?
		  ORDER BY id ASC LIMIT ?`,
		pluginID, subscriptionID, PluginEventDeliveryPending, nowUnixMS, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PluginEventDelivery, 0, limit)
	for rows.Next() {
		item, err := scanPluginEventDelivery(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func GetPluginEventDelivery(db RuleStore, pluginID, deliveryID string) (*PluginEventDelivery, error) {
	if db == nil {
		return nil, fmt.Errorf("plugin event delivery store is unavailable")
	}
	item, err := scanPluginEventDelivery(db.QueryRow(
		`SELECT `+pluginEventDeliveryColumns+` FROM plugin_event_deliveries WHERE plugin_id = ? AND delivery_id = ?`,
		pluginID, deliveryID,
	))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func GetDeadPluginEventDeliveries(db RuleStore, pluginID string, limit int) ([]PluginEventDelivery, error) {
	if db == nil {
		return nil, fmt.Errorf("plugin event delivery store is unavailable")
	}
	if limit < 1 {
		return []PluginEventDelivery{}, nil
	}
	rows, err := db.Query(
		`SELECT `+pluginEventDeliveryColumns+`
		   FROM plugin_event_deliveries
		  WHERE plugin_id = ? AND status = ? ORDER BY id DESC LIMIT ?`,
		pluginID, PluginEventDeliveryDead, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PluginEventDelivery, 0, limit)
	for rows.Next() {
		item, err := scanPluginEventDelivery(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func ListDeadPluginEventDeliveries(db RuleStore, pluginID string, beforeID int64, limit int) ([]PluginEventDelivery, error) {
	if db == nil {
		return nil, fmt.Errorf("plugin event delivery store is unavailable")
	}
	if limit < 1 {
		return []PluginEventDelivery{}, nil
	}
	query := `SELECT ` + pluginEventDeliveryColumns + ` FROM plugin_event_deliveries WHERE status = ?`
	args := []any{PluginEventDeliveryDead}
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
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
	items := make([]PluginEventDelivery, 0, limit)
	for rows.Next() {
		item, err := scanPluginEventDelivery(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func DeletePluginEventDelivery(db RuleStore, pluginID, deliveryID string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("plugin event delivery store is unavailable")
	}
	result, err := db.Exec(`DELETE FROM plugin_event_deliveries WHERE plugin_id = ? AND delivery_id = ?`, pluginID, deliveryID)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func DeleteDeadPluginEventDelivery(db RuleStore, pluginID, deliveryID string) (bool, error) {
	if db == nil {
		return false, fmt.Errorf("plugin event delivery store is unavailable")
	}
	result, err := db.Exec(
		`DELETE FROM plugin_event_deliveries WHERE plugin_id = ? AND delivery_id = ? AND status = ?`,
		pluginID, deliveryID, PluginEventDeliveryDead,
	)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count > 0, err
}

func MarkPluginEventDeliveryFailure(db RuleStore, pluginID, deliveryID string, attempts int, nextAttemptUnixMS int64, dead bool, lastError string) error {
	if db == nil {
		return fmt.Errorf("plugin event delivery store is unavailable")
	}
	status := PluginEventDeliveryPending
	if dead {
		status = PluginEventDeliveryDead
	}
	lastError = strings.TrimSpace(lastError)
	if len(lastError) > 4096 {
		lastError = lastError[:4096]
	}
	result, err := db.Exec(
		`UPDATE plugin_event_deliveries
		    SET attempts = ?, next_attempt_unix_ms = ?, status = ?, last_error = ?, updated_at = `+pluginNowSQL+`
		  WHERE plugin_id = ? AND delivery_id = ? AND status = ?`,
		attempts, nextAttemptUnixMS, status, lastError, pluginID, deliveryID, PluginEventDeliveryPending,
	)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("plugin event delivery %s is no longer pending", deliveryID)
	}
	return nil
}

func RetryDeadPluginEventDelivery(db RuleStore, pluginID, deliveryID string, nowUnixMS int64) (*PluginEventDelivery, error) {
	item, err := GetPluginEventDelivery(db, pluginID, deliveryID)
	if err != nil {
		return nil, err
	}
	if item.Status != PluginEventDeliveryDead {
		return nil, fmt.Errorf("plugin event delivery %s is not dead-lettered", deliveryID)
	}
	result, err := db.Exec(
		`UPDATE plugin_event_deliveries
		    SET attempts = 0, next_attempt_unix_ms = ?, status = ?, last_error = '', updated_at = `+pluginNowSQL+`
		  WHERE plugin_id = ? AND delivery_id = ? AND status = ?`,
		nowUnixMS, PluginEventDeliveryPending, pluginID, deliveryID, PluginEventDeliveryDead,
	)
	if err != nil {
		return nil, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if count != 1 {
		return nil, fmt.Errorf("plugin event delivery %s changed while retrying", deliveryID)
	}
	item.Attempts = 0
	item.NextAttemptUnixMS = nowUnixMS
	item.Status = PluginEventDeliveryPending
	item.LastError = ""
	return item, nil
}

func CountPluginEventDeliveries(db RuleStore, pluginID, subscriptionID, status string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("plugin event delivery store is unavailable")
	}
	query := `SELECT COUNT(*) FROM plugin_event_deliveries WHERE plugin_id = ? AND status = ?`
	args := []any{pluginID, status}
	if subscriptionID != "" {
		query += ` AND subscription_id = ?`
		args = append(args, subscriptionID)
	}
	var count int64
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func validatePluginEventDelivery(item PluginEventDelivery) error {
	if len(item.DeliveryID) != 32 {
		return fmt.Errorf("delivery id is invalid")
	}
	if _, err := hex.DecodeString(item.DeliveryID); err != nil {
		return fmt.Errorf("delivery id is invalid")
	}
	if strings.TrimSpace(item.PluginID) == "" || strings.TrimSpace(item.SubscriptionID) == "" {
		return fmt.Errorf("identity is invalid")
	}
	if strings.TrimSpace(item.Topic) == "" || strings.TrimSpace(item.PublishedAt) == "" {
		return fmt.Errorf("event metadata is incomplete")
	}
	if item.Sequence > uint64(^uint64(0)>>1) || item.SchemaVersion < 1 || item.MaxAttempts < 1 || item.NextAttemptUnixMS < 0 {
		return fmt.Errorf("delivery policy is invalid")
	}
	if !json.Valid([]byte(item.PayloadJSON)) {
		return fmt.Errorf("payload is invalid JSON")
	}
	return nil
}

type pluginEventDeliveryScanner interface {
	Scan(dest ...any) error
}

func scanPluginEventDelivery(scanner pluginEventDeliveryScanner) (PluginEventDelivery, error) {
	var item PluginEventDelivery
	var sequence int64
	err := scanner.Scan(
		&item.ID, &item.DeliveryID, &item.PluginID, &item.SubscriptionID, &item.Topic, &sequence,
		&item.PublishedAt, &item.SourcePlugin, &item.TargetPlugin, &item.ResourceID,
		&item.SchemaVersion, &item.PayloadJSON, &item.Attempts, &item.MaxAttempts,
		&item.NextAttemptUnixMS, &item.Status, &item.LastError, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return PluginEventDelivery{}, err
	}
	if sequence < 0 {
		return PluginEventDelivery{}, fmt.Errorf("plugin event delivery sequence is invalid")
	}
	item.Sequence = uint64(sequence)
	return item, nil
}
