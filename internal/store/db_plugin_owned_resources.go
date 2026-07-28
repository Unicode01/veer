package store

import (
	"database/sql"
	"errors"
	"fmt"
)

const pluginOwnedResourceColumns = `id, plugin_id, resource_type, resource_key, metadata_json, created_at, updated_at`

func scanPluginOwnedResource(sc interface{ Scan(...interface{}) error }) (PluginOwnedResource, error) {
	var item PluginOwnedResource
	err := sc.Scan(&item.ID, &item.PluginID, &item.ResourceType, &item.ResourceKey, &item.MetadataJSON, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

func PluginOwnedResourceOrNil(db RuleStore, resourceType, resourceKey string) (*PluginOwnedResource, error) {
	item, err := scanPluginOwnedResource(db.QueryRow(
		`SELECT `+pluginOwnedResourceColumns+` FROM plugin_owned_resources WHERE resource_type = ? AND resource_key = ?`,
		resourceType, resourceKey,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func AddPluginOwnedResource(db RuleStore, item PluginOwnedResource) error {
	_, err := db.Exec(
		`INSERT INTO plugin_owned_resources (plugin_id, resource_type, resource_key, metadata_json, created_at, updated_at)
		 VALUES (?, ?, ?, ?, `+pluginNowSQL+`, `+pluginNowSQL+`)`,
		item.PluginID, item.ResourceType, item.ResourceKey, item.MetadataJSON,
	)
	return err
}

func UpdatePluginOwnedResource(db RuleStore, pluginID, resourceType, resourceKey, metadataJSON string) error {
	result, err := db.Exec(
		`UPDATE plugin_owned_resources
		    SET metadata_json = ?, updated_at = `+pluginNowSQL+`
		  WHERE plugin_id = ? AND resource_type = ? AND resource_key = ?`,
		metadataJSON, pluginID, resourceType, resourceKey,
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

func GetPluginOwnedResources(db RuleStore, pluginID string) ([]PluginOwnedResource, error) {
	query := `SELECT ` + pluginOwnedResourceColumns + ` FROM plugin_owned_resources`
	args := []interface{}{}
	if pluginID != "" {
		query += ` WHERE plugin_id = ?`
		args = append(args, pluginID)
	}
	query += ` ORDER BY id ASC`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PluginOwnedResource, 0)
	for rows.Next() {
		item, err := scanPluginOwnedResource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetPluginOwnedResourcesByPluginIDs(db RuleStore, pluginIDs []string) (map[string][]PluginOwnedResource, error) {
	pluginIDs = normalizeNonEmptyStringValues(pluginIDs)
	out := make(map[string][]PluginOwnedResource, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		out[pluginID] = []PluginOwnedResource{}
	}
	for start := 0; start < len(pluginIDs); start += dbByIDQueryChunkSize {
		end := min(start+dbByIDQueryChunkSize, len(pluginIDs))
		chunk := pluginIDs[start:end]
		rows, err := db.Query(fmt.Sprintf(
			`SELECT %s FROM plugin_owned_resources WHERE plugin_id IN (%s) ORDER BY plugin_id, id ASC`,
			pluginOwnedResourceColumns, dbSQLPlaceholders(len(chunk)),
		), dbStringArgs(chunk)...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			item, err := scanPluginOwnedResource(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			out[item.PluginID] = append(out[item.PluginID], item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

func DeletePluginOwnedResource(db RuleStore, pluginID, resourceType, resourceKey string) error {
	result, err := db.Exec(
		`DELETE FROM plugin_owned_resources WHERE plugin_id = ? AND resource_type = ? AND resource_key = ?`,
		pluginID, resourceType, resourceKey,
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
