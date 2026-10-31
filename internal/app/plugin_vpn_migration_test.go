package app

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func vpnMigrationFixture(t *testing.T) (*sql.DB, string, *pluginSecretStore) {
	t.Helper()
	dir := t.TempDir()
	db, err := initDB(filepath.Join(dir, "forward.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ss, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetPluginEnabled(db, legacyVPNPluginID, false); err != nil {
		t.Fatal(err)
	}
	return db, filepath.Join(dir, "plugins"), ss
}

func addVPNMigrationRecord(t *testing.T, db *sql.DB, plugin, resource, key, data string) {
	t.Helper()
	_, err := store.AddPluginRecord(db, &store.PluginRecord{PluginID: plugin, ResourceID: resource, RecordKey: key, DataJSON: data, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVPNPluginMigrationPreservesEncryptedSecretsProfilesCoresAndWANReferences(t *testing.T) {
	db, root, ss := vpnMigrationFixture(t)
	oldDir := filepath.Join(root+".veer-state", "cores", legacyVPNPluginID)
	versionDir := filepath.Join(oldDir, "mihomo", runtime.GOOS+"-"+runtime.GOARCH, "vtest")
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "mihomo"), []byte("unchanged-binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writePluginBinaryJSON(versionDir, "manifest.json", pluginBinaryInfo{Version: "vtest", Executable: "mihomo", Bytes: int64(len("unchanged-binary"))}); err != nil {
		t.Fatal(err)
	}
	plain := `"sensitive-private-key"`
	cipher, err := ss.encryptRecordData(legacyVPNPluginID, PluginResource{ID: "__secret"}, "private_home", plain)
	if err != nil {
		t.Fatal(err)
	}
	addVPNMigrationRecord(t, db, legacyVPNPluginID, "__secret", "private_home", cipher)
	profileJSON, err := json.Marshal(map[string]any{"slot": 2, "addresses": []string{"10.77.0.1/32"}, "core_path": filepath.Join(versionDir, "mihomo")})
	if err != nil {
		t.Fatal(err)
	}
	addVPNMigrationRecord(t, db, legacyVPNPluginID, "profiles", "home", string(profileJSON))
	addVPNMigrationRecord(t, db, "wan_core", "profiles", "wg_home", `{"driver_plugin":"wireguard_mesh","local_interface":"veerwg2"}`)
	count, err := migrateVPNPluginIdentity(db, root)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("records=%d", count)
	}
	r, err := store.GetPluginRecord(db, vpnPluginID, "__secret", "private_home")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, encrypted, err := ss.decryptRecordData(vpnPluginID, PluginResource{ID: "__secret"}, r.RecordKey, r.DataJSON)
	if err != nil || !encrypted || decrypted != plain {
		t.Fatalf("secret was not rebound: encrypted=%v err=%v", encrypted, err)
	}
	if strings.Contains(r.DataJSON, "sensitive-private-key") || r.DataJSON == cipher {
		t.Fatal("secret was exposed or AAD was not changed")
	}
	if _, _, err := ss.decryptRecordData(legacyVPNPluginID, PluginResource{ID: "__secret"}, r.RecordKey, r.DataJSON); err == nil {
		t.Fatal("new ciphertext accepts old identity")
	}
	wan, err := store.GetPluginRecord(db, "wan_core", "profiles", "wg_home")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wan.DataJSON, `"driver_plugin":"vpn_core"`) || !strings.Contains(wan.DataJSON, "veerwg2") {
		t.Fatalf("WAN reference changed incorrectly: %s", wan.DataJSON)
	}
	newDir := filepath.Join(root+".veer-state", "cores", vpnPluginID, "mihomo", runtime.GOOS+"-"+runtime.GOARCH)
	info, err := readPluginBinaryVersion(newDir, "vtest")
	if err != nil {
		t.Fatalf("migrated core metadata: %v", err)
	}
	profile, err := store.GetPluginRecord(db, vpnPluginID, "profiles", "home")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal([]byte(profile.DataJSON), &value); err != nil {
		t.Fatal(err)
	}
	if value["core_path"] != info.Path {
		t.Fatal("explicit managed core path was not migrated")
	}
	data, err := os.ReadFile(info.Path)
	if err != nil || string(data) != "unchanged-binary" {
		t.Fatal("managed core lost")
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Fatal("legacy core directory remains")
	}
	state, err := store.GetPluginState(db, vpnPluginID)
	if err != nil || state.Enabled {
		t.Fatal("migration enabled a disabled plugin")
	}
	if _, err := migrateVPNPluginIdentity(db, root); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
}

func TestVPNPluginMigrationRefusesLiveLeasesAndTargetState(t *testing.T) {
	for _, kind := range []string{"enabled", "lease", "target", "cipher"} {
		t.Run(kind, func(t *testing.T) {
			db, root, _ := vpnMigrationFixture(t)
			addVPNMigrationRecord(t, db, legacyVPNPluginID, "profiles", "home", `{"slot":1}`)
			switch kind {
			case "enabled":
				store.SetPluginEnabled(db, legacyVPNPluginID, true)
			case "lease":
				addVPNMigrationRecord(t, db, legacyVPNPluginID, "__kv", "lease_home", `{"active":true}`)
			case "target":
				addVPNMigrationRecord(t, db, vpnPluginID, "profiles", "home", `{"slot":2}`)
			case "cipher":
				addVPNMigrationRecord(t, db, legacyVPNPluginID, "__secret", "private_home", `{"$veer_secret":{"v":1}}`)
			}
			if _, err := migrateVPNPluginIdentity(db, root); err == nil {
				t.Fatal("unsafe migration accepted")
			}
			if _, err := store.GetPluginRecord(db, legacyVPNPluginID, "profiles", "home"); err != nil {
				t.Fatal("failed migration modified source")
			}
		})
	}
}

func TestVPNPluginMigrationCoreConflictsRollbackDatabaseAndCrashCanRetry(t *testing.T) {
	for _, conflict := range []bool{true, false} {
		t.Run(map[bool]string{true: "conflict", false: "crash_retry"}[conflict], func(t *testing.T) {
			db, root, _ := vpnMigrationFixture(t)
			addVPNMigrationRecord(t, db, legacyVPNPluginID, "profiles", "home", `{"slot":1}`)
			parent := filepath.Join(root+".veer-state", "cores")
			if err := os.MkdirAll(filepath.Join(parent, vpnPluginID), 0700); err != nil {
				t.Fatal(err)
			}
			if conflict {
				if err := os.MkdirAll(filepath.Join(parent, legacyVPNPluginID), 0700); err != nil {
					t.Fatal(err)
				}
				if _, err := migrateVPNPluginIdentity(db, root); err == nil {
					t.Fatal("core overwrite accepted")
				}
				if _, err := store.GetPluginRecord(db, legacyVPNPluginID, "profiles", "home"); err != nil {
					t.Fatal("database committed before filesystem check")
				}
			} else {
				if err := os.WriteFile(filepath.Join(parent, ".vpn-id-migration"), []byte(legacyVPNPluginID+"->"+vpnPluginID+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := migrateVPNPluginIdentity(db, root); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(filepath.Join(parent, ".vpn-id-migration")); !os.IsNotExist(err) {
					t.Fatal("migration marker remains")
				}
			}
		})
	}
}
