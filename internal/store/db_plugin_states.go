package store

import (
	"database/sql"
	"sync/atomic"
)

const pluginStateColumns = `id, plugin_id, enabled, updated_at`

// pluginStateGeneration counts writes to plugin_states, so a reader can keep
// a plugin's enabled state and look it up again only after a write.
var pluginStateGeneration atomic.Uint64

// PluginStateGeneration returns the plugin_states write count. Read it before
// the state it guards: a write after that read makes the cached state stale.
func PluginStateGeneration() uint64 { return pluginStateGeneration.Load() }

func scanPluginState(sc interface{ Scan(...interface{}) error }) (PluginState, error) {
	var item PluginState
	var enabled int
	err := sc.Scan(&item.ID, &item.PluginID, &enabled, &item.UpdatedAt)
	item.Enabled = enabled != 0
	return item, err
}

func SetPluginEnabled(db RuleStore, pluginID string, enabled bool) error {
	_, err := db.Exec(
		`INSERT INTO plugin_states (plugin_id, enabled, updated_at)
		 VALUES (?, ?, `+pluginNowSQL+`)
		 ON CONFLICT(plugin_id) DO UPDATE SET
		   enabled = excluded.enabled,
		   updated_at = `+pluginNowSQL,
		pluginID, boolToInt(enabled),
	)
	pluginStateGeneration.Add(1)
	return err
}

func GetPluginState(db RuleStore, pluginID string) (*PluginState, error) {
	item, err := scanPluginState(db.QueryRow(`SELECT `+pluginStateColumns+` FROM plugin_states WHERE plugin_id = ?`, pluginID))
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func PluginStateOrNil(db RuleStore, pluginID string) (*PluginState, error) {
	item, err := GetPluginState(db, pluginID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return item, err
}

func GetPluginStates(db RuleStore) ([]PluginState, error) {
	rows, err := db.Query(`SELECT ` + pluginStateColumns + ` FROM plugin_states ORDER BY plugin_id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PluginState
	for rows.Next() {
		item, err := scanPluginState(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
