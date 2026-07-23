package app

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginSecretsEncryptAtRestAndSurviveRuntimeRestart(t *testing.T) {
	db := openTestDB(t)
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	resource := PluginResource{ID: "settings", SecretFields: []string{"password"}}
	plaintext := `{"username":"alice","password":"plain-password"}`
	encrypted, err := secrets.encryptRecordData("secret_plugin", resource, "default", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encrypted, "plain-password") || !strings.Contains(encrypted, pluginSecretEnvelopeField) {
		t.Fatalf("encrypted record = %s", encrypted)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "secret_plugin", ResourceID: resource.ID, RecordKey: "default", DataJSON: encrypted, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	restarted, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.GetPluginRecord(db, "secret_plugin", resource.ID, "default")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := restarted.decryptRecord(*record, resource)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(decrypted.DataJSON, `"username":"alice"`) || !strings.Contains(decrypted.DataJSON, `"password":"plain-password"`) {
		t.Fatalf("decrypted record = %s, want original fields", decrypted.DataJSON)
	}
	if _, _, err := restarted.decryptRecordData("secret_plugin", resource, "other-key", encrypted); err == nil || !strings.Contains(err.Error(), "authenticate plugin secret") {
		t.Fatalf("decrypt with changed AAD error = %v", err)
	}
	if secrets.keyPath == "" {
		t.Fatal("file-backed test database did not create a persistent key path")
	}
	info, err := os.Lstat(secrets.keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("plugin secret key file = %+v, err=%v", info, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("plugin secret key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestPluginSecretKeyringRejectsSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "keyring.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadOrCreatePluginSecretKeyring(link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("loadOrCreatePluginSecretKeyring(symlink) error = %v, want regular-file rejection", err)
	}
}

func TestPluginSecretsMigratePlaintextAndRotate(t *testing.T) {
	db := openTestDB(t)
	for _, item := range []store.PluginRecord{
		{PluginID: "secret_plugin", ResourceID: pluginControlSecretResourceID, RecordKey: "token", DataJSON: `"plain-token"`, Enabled: true},
		{PluginID: "secret_plugin", ResourceID: "settings", RecordKey: "default", DataJSON: `{"username":"alice","password":"plain-password"}`, Enabled: true},
	} {
		current := item
		if _, err := store.AddPluginRecord(db, &current); err != nil {
			t.Fatal(err)
		}
	}
	resource := PluginResource{ID: "settings", SecretFields: []string{"password"}}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "secret_plugin"}, Resources: []PluginResource{resource},
	}}}
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := secrets.activeID
	if err := secrets.migratePluginSecrets(catalog); err != nil {
		t.Fatal(err)
	}
	assertPluginSecretsEncryptedAndReadable(t, db, secrets, resource, oldKey)

	result, err := secrets.rotate(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if result.ActiveKey == "" || result.ActiveKey == oldKey {
		t.Fatalf("rotation result = %+v, old key = %s", result, oldKey)
	}
	assertPluginSecretsEncryptedAndReadable(t, db, secrets, resource, result.ActiveKey)
	reloaded, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.activeID != result.ActiveKey || len(reloaded.keys) != 1 {
		t.Fatalf("reloaded keyring active=%s keys=%d, want %s/1", reloaded.activeID, len(reloaded.keys), result.ActiveKey)
	}
}

func TestPluginSecretRotationRejectsPendingResourceMigration(t *testing.T) {
	db := openTestDB(t)
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddPluginResourceMigration(db, store.PluginResourceMigration{
		TransactionID: "0123456789abcdef0123456789abcdef", PluginID: "secret_plugin", ResourceID: "settings", RecordsJSON: `[]`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.rotate(PluginCatalog{}); err == nil || !strings.Contains(err.Error(), "pending resource migration") {
		t.Fatalf("rotate with pending migration error = %v", err)
	}
}

func TestPluginSecretRejectsMalformedEnvelope(t *testing.T) {
	db := openTestDB(t)
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := secrets.encryptJSON("secret_plugin", "settings", "default", "password", []byte(`"value"`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope pluginSecretEnvelopeObject
	if err := json.Unmarshal(encrypted, &envelope); err != nil || envelope.Secret == nil {
		t.Fatalf("decode encrypted envelope = %+v, err=%v", envelope, err)
	}
	envelope.Secret.Nonce = base64.StdEncoding.EncodeToString([]byte{1})
	malformedNonce, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := secrets.decryptJSON("secret_plugin", "settings", "default", "password", malformedNonce); !found || err == nil || !strings.Contains(err.Error(), "nonce has length") {
		t.Fatalf("decrypt malformed nonce found=%v error=%v", found, err)
	}

	envelope.Secret.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
	envelope.Secret.Ciphertext = base64.StdEncoding.EncodeToString([]byte{1})
	shortCiphertext, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := secrets.decryptJSON("secret_plugin", "settings", "default", "password", shortCiphertext); !found || err == nil || !strings.Contains(err.Error(), "shorter than the authentication tag") {
		t.Fatalf("decrypt short ciphertext found=%v error=%v", found, err)
	}

	withUnknownField := append(encrypted[:len(encrypted)-1], []byte(`,"unexpected":true}`)...)
	if _, found, err := secrets.decryptJSON("secret_plugin", "settings", "default", "password", withUnknownField); !found || err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decrypt envelope with unknown field found=%v error=%v", found, err)
	}
}

func TestPluginSecretMigrationIgnoresForgedEnvelopeOutsideSecretContracts(t *testing.T) {
	db := openTestDB(t)
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	forged := `{"$veer_secret":{"v":1,"kid":"00000000000000000000000000000000","nonce":"AA==","ciphertext":"AA=="}}`
	records := []store.PluginRecord{
		{PluginID: "ordinary_plugin", ResourceID: "settings", RecordKey: "whole", DataJSON: forged, Enabled: true},
		{PluginID: "ordinary_plugin", ResourceID: "settings", RecordKey: "nested", DataJSON: `{"payload":` + forged + `}`, Enabled: true},
	}
	for _, item := range records {
		current := item
		if _, err := store.AddPluginRecord(db, &current); err != nil {
			t.Fatal(err)
		}
	}
	if err := secrets.migratePluginSecrets(PluginCatalog{}); err != nil {
		t.Fatalf("migrate with forged ordinary envelopes: %v", err)
	}
	for _, expected := range records {
		record, err := store.GetPluginRecord(db, expected.PluginID, expected.ResourceID, expected.RecordKey)
		if err != nil || record.DataJSON != expected.DataJSON {
			t.Fatalf("ordinary record %s after migration = %+v, err=%v", expected.RecordKey, record, err)
		}
	}

	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "secret_plugin", ResourceID: "settings", RecordKey: "default", DataJSON: `{"password":` + forged + `}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "secret_plugin"},
		Resources:      []PluginResource{{ID: "settings", SecretFields: []string{"password"}}},
	}}}
	if err := secrets.migratePluginSecrets(catalog); err == nil || !strings.Contains(err.Error(), "key 00000000000000000000000000000000 is unavailable") {
		t.Fatalf("declared secret with forged envelope error = %v", err)
	}
}

func TestPluginSecretRotationRecoversTransitionalKeyring(t *testing.T) {
	db := openTestDB(t)
	resource := PluginResource{ID: "settings", SecretFields: []string{"password"}}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "secret_plugin"}, Resources: []PluginResource{resource},
	}}}
	secrets, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := `{"username":"alice","password":"plain-password"}`
	encrypted, err := secrets.encryptRecordData("secret_plugin", resource, "default", plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "secret_plugin", ResourceID: resource.ID, RecordKey: "default", DataJSON: encrypted, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	secretValue, err := secrets.encryptRecordData("secret_plugin", PluginResource{ID: pluginControlSecretResourceID}, "token", `"plain-token"`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "secret_plugin", ResourceID: pluginControlSecretResourceID, RecordKey: "token", DataJSON: secretValue, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	transitionKey := bytes.Repeat([]byte{0x5a}, pluginSecretMasterKeyBytes)
	transitionID := pluginSecretKeyID(transitionKey)
	secrets.mu.Lock()
	secrets.activeID = transitionID
	secrets.keys[transitionID] = append([]byte(nil), transitionKey...)
	keyringKeys := make(map[string]string, len(secrets.keys))
	for id, key := range secrets.keys {
		keyringKeys[id] = base64.StdEncoding.EncodeToString(key)
	}
	secrets.mu.Unlock()
	if err := writePluginSecretKeyringAtomic(secrets.keyPath, pluginSecretKeyringFile{
		Version: pluginSecretKeyringVersion, ActiveKey: transitionID, Keys: keyringKeys,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := secrets.rotate(catalog)
	if err != nil {
		t.Fatalf("rotate after interrupted transition: %v", err)
	}
	if result.ActiveKey == "" || result.ActiveKey == transitionID {
		t.Fatalf("rotation result after transition recovery = %+v", result)
	}
	assertPluginSecretsEncryptedAndReadable(t, db, secrets, resource, result.ActiveKey)
	reloaded, err := newPluginSecretStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.activeID != result.ActiveKey || len(reloaded.keys) != 1 {
		t.Fatalf("reloaded recovered keyring active=%s keys=%d, want %s/1", reloaded.activeID, len(reloaded.keys), result.ActiveKey)
	}
}

func assertPluginSecretsEncryptedAndReadable(t *testing.T, db *sql.DB, secrets *pluginSecretStore, resource PluginResource, activeKey string) {
	t.Helper()
	secretRecord, err := store.GetPluginRecord(db, "secret_plugin", pluginControlSecretResourceID, "token")
	if err != nil {
		t.Fatal(err)
	}
	settingsRecord, err := store.GetPluginRecord(db, "secret_plugin", resource.ID, "default")
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []*store.PluginRecord{secretRecord, settingsRecord} {
		if strings.Contains(record.DataJSON, "plain-") || !strings.Contains(record.DataJSON, pluginSecretEnvelopeField) {
			t.Fatalf("raw record %s/%s is not encrypted: %s", record.ResourceID, record.RecordKey, record.DataJSON)
		}
	}
	var whole pluginSecretEnvelopeObject
	if err := json.Unmarshal([]byte(secretRecord.DataJSON), &whole); err != nil || whole.Secret == nil || whole.Secret.KeyID != activeKey {
		t.Fatalf("whole secret envelope = %+v, err=%v", whole, err)
	}
	decryptedSecret, err := secrets.decryptRecord(*secretRecord, PluginResource{ID: pluginControlSecretResourceID})
	if err != nil || decryptedSecret.DataJSON != `"plain-token"` {
		t.Fatalf("decrypted secret = %+v, err=%v", decryptedSecret, err)
	}
	decryptedSettings, err := secrets.decryptRecord(*settingsRecord, resource)
	if err != nil || !strings.Contains(decryptedSettings.DataJSON, `"password":"plain-password"`) {
		t.Fatalf("decrypted settings = %+v, err=%v", decryptedSettings, err)
	}
}
