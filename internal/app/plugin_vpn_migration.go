package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const legacyVPNPluginID = "wireguard_mesh"
const vpnPluginID = "vpn_core"

// Explicit local migration: disable the old plugin and remove its code before
// running this command. Never transfer a live network/process lease to a new ID.
func runVPNPluginMigrationCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("plugin migrate-vpn", flag.ContinueOnError)
	flags.SetOutput(stderr)
	database := flags.String("database", "forward.db", "existing Veer database")
	plugins := flags.String("plugins-dir", defaultPluginsDir, "installed plugins directory")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("migrate-vpn accepts no positional arguments")
	}
	applyInstallStateDefaults(flags, database, plugins, stderr)
	if info, err := os.Lstat(*database); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("migration requires an existing regular database")
	}
	root, err := filepath.Abs(*plugins)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(root, legacyVPNPluginID)); !os.IsNotExist(err) {
		return fmt.Errorf("disable the old plugin and move plugins/%s outside the scanned directory first", legacyVPNPluginID)
	}
	db, err := initDB(*database)
	if err != nil {
		return err
	}
	defer db.Close()
	count, err := migrateVPNPluginIdentity(db, root)
	if err != nil {
		return err
	}
	return writePluginPackageCLIJSON(stdout, map[string]any{"from": legacyVPNPluginID, "to": vpnPluginID, "records": count})
}

func migrateVPNPluginIdentity(db *sql.DB, pluginsRoot string) (int, error) {
	secretStore, err := newPluginSecretStore(db)
	if err != nil {
		return 0, err
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var enabled, count int
	err = tx.QueryRow(`SELECT enabled FROM plugin_states WHERE plugin_id = ?`, legacyVPNPluginID).Scan(&enabled)
	stateMissing := err == sql.ErrNoRows
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if enabled != 0 {
		return 0, fmt.Errorf("disable the old VPN plugin before migrating")
	}
	if err := tx.QueryRow(`SELECT count(*) FROM plugin_records WHERE plugin_id = ? AND resource_id = '__kv' AND record_key LIKE 'lease_%'`, legacyVPNPluginID).Scan(&count); err != nil {
		return 0, err
	}
	if count != 0 {
		return 0, fmt.Errorf("old VPN leases remain; finish teardown with the old plugin before migrating")
	}
	tables := []string{"plugin_records", "plugin_states", "plugin_runtime_status", "plugin_resource_schemas", "plugin_resource_migrations", "plugin_owned_resources", "plugin_net_transactions", "plugin_operations", "plugin_event_deliveries"}
	var total int
	for _, table := range tables {
		if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE plugin_id = ?`, legacyVPNPluginID).Scan(&count); err != nil {
			return 0, err
		}
		total += count
	}
	if total > 0 {
		if stateMissing {
			return 0, fmt.Errorf("explicitly disable the old VPN plugin before migrating its data")
		}
		for _, table := range tables {
			if err := tx.QueryRow(`SELECT count(*) FROM `+table+` WHERE plugin_id = ?`, vpnPluginID).Scan(&count); err != nil {
				return 0, err
			}
			if count != 0 {
				return 0, fmt.Errorf("%s already has state in %s; refusing to merge identities", vpnPluginID, table)
			}
		}
	}
	type record struct {
		id                  int64
		resource, key, data string
	}
	rows, err := tx.Query(`SELECT id, resource_id, record_key, data_json FROM plugin_records WHERE plugin_id = ?`, legacyVPNPluginID)
	if err != nil {
		return 0, err
	}
	var records []record
	for rows.Next() {
		var r record
		if err := rows.Scan(&r.id, &r.resource, &r.key, &r.data); err != nil {
			rows.Close()
			return 0, err
		}
		records = append(records, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	oldCores := filepath.Join(pluginsRoot+".veer-state", "cores", legacyVPNPluginID)
	newCores := filepath.Join(pluginsRoot+".veer-state", "cores", vpnPluginID)
	for _, r := range records {
		data := r.data
		if r.resource == pluginControlSecretResourceID {
			plain, _, err := secretStore.decryptRecordData(legacyVPNPluginID, PluginResource{ID: r.resource}, r.key, data)
			if err != nil {
				return 0, err
			}
			data, err = secretStore.encryptRecordData(vpnPluginID, PluginResource{ID: r.resource}, r.key, plain)
			if err != nil {
				return 0, err
			}
		} else if r.resource == "profiles" {
			var value map[string]any
			if err := json.Unmarshal([]byte(data), &value); err != nil {
				return 0, err
			}
			if path, ok := value["core_path"].(string); ok && pathWithinRoot(oldCores, path) {
				rel, err := filepath.Rel(oldCores, path)
				if err != nil {
					return 0, err
				}
				value["core_path"] = filepath.Join(newCores, rel)
				encoded, err := json.Marshal(value)
				if err != nil {
					return 0, err
				}
				data = string(encoded)
			}
		}
		if _, err = tx.Exec(`UPDATE plugin_records SET data_json = ? WHERE id = ?`, data, r.id); err != nil {
			return 0, err
		}
	}
	if total > 0 {
		for _, table := range append(tables, "plugin_logs", "plugin_audit_logs") {
			if _, err = tx.Exec(`UPDATE `+table+` SET plugin_id = ? WHERE plugin_id = ?`, vpnPluginID, legacyVPNPluginID); err != nil {
				return 0, err
			}
		}
		if _, err = tx.Exec(`UPDATE plugin_event_deliveries SET source_plugin = ? WHERE source_plugin = ?`, vpnPluginID, legacyVPNPluginID); err != nil {
			return 0, err
		}
		// Teardown leaves WAN records for stable LAN/NAT references. Preserve the
		// WAN keys and interface names, changing only their driver identity.
		if _, err = tx.Exec(`UPDATE plugin_records SET data_json = json_set(data_json, '$.driver_plugin', ?) WHERE plugin_id = 'wan_core' AND json_valid(data_json) AND json_extract(data_json, '$.driver_plugin') = ?`, vpnPluginID, legacyVPNPluginID); err != nil {
			return 0, err
		}
	}
	finish, err := moveVPNCoreDirectory(oldCores, newCores)
	if err != nil {
		return 0, err
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	if err = finish(); err != nil {
		return 0, err
	}
	return len(records), nil
}

// The marker makes a crash between the filesystem rename and SQLite commit
// retryable. It contains no credentials; ambiguous pre-existing targets fail.
func moveVPNCoreDirectory(oldPath, newPath string) (func() error, error) {
	noop := func() error { return nil }
	parent := filepath.Dir(oldPath)
	if _, err := os.Lstat(parent); os.IsNotExist(err) {
		return noop, nil
	}
	// Resolve every existing ancestor: moving through a symlink could affect
	// unrelated core stores even though the lexical paths are within the root.
	for path := parent; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("VPN core store must not contain symlinks")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	marker := filepath.Join(parent, ".vpn-id-migration")
	markerData := legacyVPNPluginID + "->" + vpnPluginID + "\n"
	marked := false
	if data, info, err := readBoundedRegularFileAtPath(marker, 128, false); err == nil {
		if !info.Mode().IsRegular() || string(data) != markerData {
			return nil, fmt.Errorf("invalid VPN migration marker")
		}
		marked = true
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	oldInfo, oldErr := os.Lstat(oldPath)
	newInfo, newErr := os.Lstat(newPath)
	for _, item := range []struct {
		info os.FileInfo
		err  error
	}{{oldInfo, oldErr}, {newInfo, newErr}} {
		if item.err != nil && !os.IsNotExist(item.err) {
			return nil, item.err
		}
		if item.err == nil && (!item.info.IsDir() || item.info.Mode()&os.ModeSymlink != 0) {
			return nil, fmt.Errorf("VPN core owner path must be a directory")
		}
	}
	if oldErr == nil && newErr == nil {
		return nil, fmt.Errorf("both VPN core directories exist; refusing to overwrite")
	}
	if oldErr != nil && !marked {
		return noop, nil
	}
	if marked && oldErr != nil && newErr != nil {
		return nil, fmt.Errorf("pending VPN migration has lost both core directories")
	}
	if !marked {
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := io.Copy(f, strings.NewReader(markerData))
		syncErr := f.Sync()
		closeErr := f.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return nil, err
		}
	}
	if oldErr == nil {
		if err := os.Rename(oldPath, newPath); err != nil {
			return nil, err
		}
	}
	return func() error { return os.Remove(marker) }, nil
}
