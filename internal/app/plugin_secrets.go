package app

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	storepkg "github.com/Unicode01/veer/internal/store"
)

const (
	pluginSecretKeyringVersion  = 1
	pluginSecretEnvelopeVersion = 1
	pluginSecretMasterKeyBytes  = 32
	pluginSecretKeyFileSuffix   = ".veer-secrets.key"
	pluginSecretEnvelopeField   = "$veer_secret"
	pluginSecretAADDomain       = "veer-plugin-secret-v1\x00"
	pluginSecretKeyringMaxBytes = 64 << 10
	pluginSecretKeyringMaxKeys  = 8
)

type pluginSecretKeyringFile struct {
	Version   int               `json:"version"`
	ActiveKey string            `json:"active_key"`
	Keys      map[string]string `json:"keys"`
	UpdatedAt string            `json:"updated_at"`
}

type pluginSecretEnvelope struct {
	Version    int    `json:"v"`
	KeyID      string `json:"kid"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type pluginSecretEnvelopeObject struct {
	Secret *pluginSecretEnvelope `json:"$veer_secret"`
}

type pluginSecretStore struct {
	operationMu sync.RWMutex
	mu          sync.RWMutex
	db          *sql.DB
	keyPath     string
	activeID    string
	keys        map[string][]byte
}

type pluginSecretRotationResult struct {
	ActiveKey string `json:"active_key"`
	RotatedAt string `json:"rotated_at"`
}

var pluginSecretKeyFileMu sync.Mutex

func newPluginSecretStore(db *sql.DB) (*pluginSecretStore, error) {
	if db == nil {
		return nil, nil
	}
	databasePath, err := pluginSecretDatabasePath(db)
	if err != nil {
		return nil, err
	}
	store := &pluginSecretStore{db: db, keys: make(map[string][]byte)}
	if databasePath == "" {
		key := make([]byte, pluginSecretMasterKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate ephemeral plugin secret key: %w", err)
		}
		store.activeID = pluginSecretKeyID(key)
		store.keys[store.activeID] = key
		return store, nil
	}
	store.keyPath = databasePath + pluginSecretKeyFileSuffix
	pluginSecretKeyFileMu.Lock()
	defer pluginSecretKeyFileMu.Unlock()
	keyring, err := loadOrCreatePluginSecretKeyring(store.keyPath)
	if err != nil {
		return nil, err
	}
	store.activeID = keyring.ActiveKey
	for id, encoded := range keyring.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != pluginSecretMasterKeyBytes || pluginSecretKeyID(key) != id {
			return nil, fmt.Errorf("plugin secret key %s failed integrity validation", id)
		}
		store.keys[id] = append([]byte(nil), key...)
	}
	if _, ok := store.keys[store.activeID]; !ok {
		return nil, fmt.Errorf("plugin secret active key %s is missing", store.activeID)
	}
	return store, nil
}

func pluginSecretDatabasePath(db *sql.DB) (string, error) {
	rows, err := db.Query(`PRAGMA database_list`)
	if err != nil {
		return "", fmt.Errorf("query plugin secret database path: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name, path string
		if err := rows.Scan(&sequence, &name, &path); err != nil {
			return "", err
		}
		if name == "main" {
			if strings.TrimSpace(path) == "" {
				return "", nil
			}
			absolute, err := filepath.Abs(path)
			if err != nil {
				return "", err
			}
			return absolute, nil
		}
	}
	return "", rows.Err()
}

func loadOrCreatePluginSecretKeyring(path string) (pluginSecretKeyringFile, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	parent := filepath.Dir(absPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return pluginSecretKeyringFile{}, err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	defer root.Close()
	name := filepath.Base(absPath)
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		key := make([]byte, pluginSecretMasterKeyBytes)
		if _, err := rand.Read(key); err != nil {
			return pluginSecretKeyringFile{}, err
		}
		id := pluginSecretKeyID(key)
		keyring := pluginSecretKeyringFile{
			Version: pluginSecretKeyringVersion, ActiveKey: id,
			Keys: map[string]string{id: base64.StdEncoding.EncodeToString(key)}, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}
		if err := writePluginSecretKeyringAtomic(absPath, keyring); err != nil {
			return pluginSecretKeyringFile{}, err
		}
		return keyring, nil
	}
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return pluginSecretKeyringFile{}, fmt.Errorf("plugin secret key path must be a regular file")
	}
	file, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return pluginSecretKeyringFile{}, fmt.Errorf("plugin secret key path changed while opening")
	}
	if openedInfo.Size() <= 0 || openedInfo.Size() > pluginSecretKeyringMaxBytes {
		return pluginSecretKeyringFile{}, fmt.Errorf("plugin secret keyring size is invalid")
	}
	if err := file.Chmod(0o600); err != nil {
		return pluginSecretKeyringFile{}, fmt.Errorf("secure plugin secret key permissions: %w", err)
	}
	data, _, err := readBoundedRegularFile(file, pluginSecretKeyringMaxBytes)
	if err != nil {
		return pluginSecretKeyringFile{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var keyring pluginSecretKeyringFile
	if err := decoder.Decode(&keyring); err != nil {
		return pluginSecretKeyringFile{}, fmt.Errorf("decode plugin secret keyring: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return pluginSecretKeyringFile{}, fmt.Errorf("plugin secret keyring contains trailing JSON")
		}
		return pluginSecretKeyringFile{}, fmt.Errorf("decode plugin secret keyring trailer: %w", err)
	}
	if err := validatePluginSecretKeyring(keyring); err != nil {
		return pluginSecretKeyringFile{}, err
	}
	return keyring, nil
}

func writePluginSecretKeyringAtomic(path string, keyring pluginSecretKeyringFile) error {
	if err := validatePluginSecretKeyring(keyring); err != nil {
		return err
	}
	data, err := json.MarshalIndent(keyring, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".veer-secrets-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := true
	defer func() {
		_ = temp.Close()
		if cleanup {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func validatePluginSecretKeyring(keyring pluginSecretKeyringFile) error {
	if keyring.Version != pluginSecretKeyringVersion || len(keyring.ActiveKey) != 32 || len(keyring.Keys) == 0 || len(keyring.Keys) > pluginSecretKeyringMaxKeys {
		return fmt.Errorf("plugin secret keyring is invalid")
	}
	if _, ok := keyring.Keys[keyring.ActiveKey]; !ok {
		return fmt.Errorf("plugin secret active key %s is missing", keyring.ActiveKey)
	}
	for id, encoded := range keyring.Keys {
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != pluginSecretMasterKeyBytes || pluginSecretKeyID(key) != id {
			return fmt.Errorf("plugin secret key %s failed integrity validation", id)
		}
	}
	return nil
}

func pluginSecretKeyID(key []byte) string {
	digest := sha256.Sum256(key)
	return hex.EncodeToString(digest[:16])
}

func (store *pluginSecretStore) encryptJSON(pluginID, resourceID, recordKey, path string, plaintext []byte) (json.RawMessage, error) {
	if store == nil {
		return nil, fmt.Errorf("plugin secret store is unavailable")
	}
	store.mu.RLock()
	keyID := store.activeID
	key := append([]byte(nil), store.keys[keyID]...)
	store.mu.RUnlock()
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, pluginSecretAAD(pluginID, resourceID, recordKey, path))
	return json.Marshal(pluginSecretEnvelopeObject{Secret: &pluginSecretEnvelope{
		Version: pluginSecretEnvelopeVersion, KeyID: keyID,
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}})
}

func (store *pluginSecretStore) decryptJSON(pluginID, resourceID, recordKey, path string, value json.RawMessage) (json.RawMessage, bool, error) {
	envelope, found, err := decodePluginSecretEnvelope(value)
	if !found {
		return append(json.RawMessage(nil), value...), false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if envelope.Version != pluginSecretEnvelopeVersion {
		return nil, true, fmt.Errorf("unsupported plugin secret envelope version %d", envelope.Version)
	}
	store.mu.RLock()
	key := append([]byte(nil), store.keys[envelope.KeyID]...)
	store.mu.RUnlock()
	if len(key) != pluginSecretMasterKeyBytes {
		return nil, true, fmt.Errorf("plugin secret key %s is unavailable", envelope.KeyID)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, true, fmt.Errorf("decode plugin secret nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, true, fmt.Errorf("decode plugin secret ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, true, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, true, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, true, fmt.Errorf("plugin secret nonce has length %d, want %d", len(nonce), aead.NonceSize())
	}
	if len(ciphertext) < aead.Overhead() {
		return nil, true, fmt.Errorf("plugin secret ciphertext is shorter than the authentication tag")
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, pluginSecretAAD(pluginID, resourceID, recordKey, path))
	if err != nil {
		return nil, true, fmt.Errorf("authenticate plugin secret %s/%s/%s: %w", pluginID, resourceID, recordKey, err)
	}
	if !json.Valid(plaintext) {
		return nil, true, fmt.Errorf("decrypted plugin secret is not valid JSON")
	}
	return json.RawMessage(plaintext), true, nil
}

func decodePluginSecretEnvelope(value json.RawMessage) (*pluginSecretEnvelope, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(value, &fields); err != nil || fields == nil {
		return nil, false, nil
	}
	if _, ok := fields[pluginSecretEnvelopeField]; !ok {
		return nil, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var object pluginSecretEnvelopeObject
	if err := decoder.Decode(&object); err != nil {
		return nil, true, fmt.Errorf("decode plugin secret envelope: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, true, fmt.Errorf("plugin secret envelope contains trailing JSON")
	}
	if object.Secret == nil || len(object.Secret.KeyID) != 32 || object.Secret.Nonce == "" || object.Secret.Ciphertext == "" {
		return nil, true, fmt.Errorf("plugin secret envelope is invalid")
	}
	if _, err := hex.DecodeString(object.Secret.KeyID); err != nil {
		return nil, true, fmt.Errorf("plugin secret envelope key id is invalid")
	}
	return object.Secret, true, nil
}

func pluginSecretAAD(pluginID, resourceID, recordKey, path string) []byte {
	return []byte(pluginSecretAADDomain + pluginID + "\x00" + resourceID + "\x00" + recordKey + "\x00" + path)
}

func (store *pluginSecretStore) encryptRecordData(pluginID string, resource PluginResource, recordKey, dataJSON string) (string, error) {
	store.operationMu.RLock()
	defer store.operationMu.RUnlock()
	return store.encryptRecordDataUnlocked(pluginID, resource, recordKey, dataJSON)
}

func (store *pluginSecretStore) encryptRecordDataUnlocked(pluginID string, resource PluginResource, recordKey, dataJSON string) (string, error) {
	if resource.ID == pluginControlSecretResourceID {
		encrypted, err := store.encryptJSON(pluginID, resource.ID, recordKey, "$", []byte(dataJSON))
		return string(encrypted), err
	}
	if len(resource.SecretFields) == 0 {
		return dataJSON, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(dataJSON), &object); err != nil || object == nil {
		return "", fmt.Errorf("resource with secret_fields must contain a JSON object")
	}
	secretFields := pluginSecretFieldSet(resource)
	for key, value := range object {
		if _, secret := secretFields[strings.ToLower(key)]; !secret {
			continue
		}
		if _, encrypted, err := store.decryptJSON(pluginID, resource.ID, recordKey, key, value); err != nil {
			return "", err
		} else if encrypted {
			continue
		}
		encrypted, err := store.encryptJSON(pluginID, resource.ID, recordKey, key, value)
		if err != nil {
			return "", err
		}
		object[key] = encrypted
	}
	out, err := json.Marshal(object)
	return string(out), err
}

func (store *pluginSecretStore) decryptRecordData(pluginID string, resource PluginResource, recordKey, dataJSON string) (string, bool, error) {
	store.operationMu.RLock()
	defer store.operationMu.RUnlock()
	return store.decryptRecordDataUnlocked(pluginID, resource, recordKey, dataJSON)
}

func (store *pluginSecretStore) decryptRecordDataUnlocked(pluginID string, resource PluginResource, recordKey, dataJSON string) (string, bool, error) {
	if resource.ID == pluginControlSecretResourceID {
		value, encrypted, err := store.decryptJSON(pluginID, resource.ID, recordKey, "$", json.RawMessage(dataJSON))
		return string(value), encrypted, err
	}
	if len(resource.SecretFields) == 0 {
		return dataJSON, false, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(dataJSON), &object); err != nil || object == nil {
		return "", false, fmt.Errorf("resource with secret_fields must contain a JSON object")
	}
	secretFields := pluginSecretFieldSet(resource)
	changed := false
	for key, value := range object {
		if _, secret := secretFields[strings.ToLower(key)]; !secret {
			continue
		}
		plaintext, encrypted, err := store.decryptJSON(pluginID, resource.ID, recordKey, key, value)
		if err != nil {
			return "", false, err
		}
		if encrypted {
			object[key] = plaintext
			changed = true
		}
	}
	if !changed {
		return dataJSON, false, nil
	}
	out, err := json.Marshal(object)
	return string(out), true, err
}

func pluginSecretFieldSet(resource PluginResource) map[string]struct{} {
	out := make(map[string]struct{}, len(resource.SecretFields))
	for _, field := range resource.SecretFields {
		out[strings.ToLower(strings.TrimSpace(field))] = struct{}{}
	}
	return out
}

func (store *pluginSecretStore) decryptRecord(record storepkg.PluginRecord, resource PluginResource) (storepkg.PluginRecord, error) {
	dataJSON, _, err := store.decryptRecordData(record.PluginID, resource, record.RecordKey, record.DataJSON)
	if err != nil {
		return storepkg.PluginRecord{}, err
	}
	record.DataJSON = dataJSON
	return record, nil
}

func (store *pluginSecretStore) decryptRecords(records []storepkg.PluginRecord, resource PluginResource) ([]storepkg.PluginRecord, error) {
	out := make([]storepkg.PluginRecord, 0, len(records))
	for _, record := range records {
		decrypted, err := store.decryptRecord(record, resource)
		if err != nil {
			return nil, err
		}
		out = append(out, decrypted)
	}
	return out, nil
}

func (rt *gojaPluginControlRuntime) requirePluginSecretStore() (*pluginSecretStore, error) {
	if rt == nil {
		return nil, fmt.Errorf("plugin secret store is unavailable")
	}
	if rt.secretStoreErr != nil {
		return nil, rt.secretStoreErr
	}
	if rt.secretStore == nil {
		return nil, fmt.Errorf("plugin secret store is unavailable")
	}
	return rt.secretStore, nil
}

func pluginSecretStoreForRequest(db *sql.DB, pm *ProcessManager) (*pluginSecretStore, error) {
	if pm != nil && pm.pluginControlRuntime != nil {
		if rt, ok := pm.pluginControlRuntime.(*gojaPluginControlRuntime); ok {
			return rt.requirePluginSecretStore()
		}
	}
	return newPluginSecretStore(db)
}

func decryptPluginRecordForRequest(db *sql.DB, pm *ProcessManager, record storepkg.PluginRecord, resource PluginResource) (storepkg.PluginRecord, error) {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return record, nil
	}
	secrets, err := pluginSecretStoreForRequest(db, pm)
	if err != nil {
		return storepkg.PluginRecord{}, err
	}
	return secrets.decryptRecord(record, resource)
}

func decryptPluginRecordsForRequest(db *sql.DB, pm *ProcessManager, records []storepkg.PluginRecord, resource PluginResource) ([]storepkg.PluginRecord, error) {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return records, nil
	}
	secrets, err := pluginSecretStoreForRequest(db, pm)
	if err != nil {
		return nil, err
	}
	return secrets.decryptRecords(records, resource)
}

func encryptPluginRecordDataForRequest(db *sql.DB, pm *ProcessManager, pluginID string, resource PluginResource, recordKey, dataJSON string) (string, error) {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return dataJSON, nil
	}
	secrets, err := pluginSecretStoreForRequest(db, pm)
	if err != nil {
		return "", err
	}
	return secrets.encryptRecordData(pluginID, resource, recordKey, dataJSON)
}

func (h *pluginControlHost) pluginSecretStore(api string) *pluginSecretStore {
	if h == nil || h.runtime == nil {
		h.throwf("%s: plugin secret store is unavailable", api)
	}
	store, err := h.runtime.requirePluginSecretStore()
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return store
}

func (h *pluginControlHost) decryptPluginRecord(record storepkg.PluginRecord, resource PluginResource, api string) storepkg.PluginRecord {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return record
	}
	decrypted, err := h.pluginSecretStore(api).decryptRecord(record, resource)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return decrypted
}

func (h *pluginControlHost) decryptPluginRecords(records []storepkg.PluginRecord, resource PluginResource, api string) []storepkg.PluginRecord {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return records
	}
	decrypted, err := h.pluginSecretStore(api).decryptRecords(records, resource)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return decrypted
}

func (h *pluginControlHost) encryptPluginRecordData(pluginID string, resource PluginResource, recordKey, dataJSON, api string) string {
	if resource.ID != pluginControlSecretResourceID && len(resource.SecretFields) == 0 {
		return dataJSON
	}
	encrypted, err := h.pluginSecretStore(api).encryptRecordData(pluginID, resource, recordKey, dataJSON)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return encrypted
}

func (store *pluginSecretStore) migratePluginSecrets(catalog PluginCatalog) error {
	store.operationMu.Lock()
	defer store.operationMu.Unlock()
	if err := store.migratePluginSecretsUnlocked(catalog); err != nil {
		return err
	}
	pluginSecretKeyFileMu.Lock()
	defer pluginSecretKeyFileMu.Unlock()
	return store.finalizeTransitionalKeyringLocked(time.Now().UTC())
}

func (store *pluginSecretStore) migratePluginSecretsUnlocked(catalog PluginCatalog) error {
	if store == nil || store.db == nil {
		return nil
	}
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[int64]struct{})
	secretRecords, err := storepkg.GetPluginRecordsByResource(tx, pluginControlSecretResourceID)
	if err != nil {
		return err
	}
	secretResource := PluginResource{ID: pluginControlSecretResourceID}
	if err := store.migratePluginSecretRecordSet(tx, secretRecords, secretResource, seen); err != nil {
		return err
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin {
			continue
		}
		for _, resource := range plugin.Resources {
			if len(resource.SecretFields) == 0 {
				continue
			}
			records, err := storepkg.GetPluginRecords(tx, plugin.ID, resource.ID)
			if err != nil {
				return err
			}
			if err := store.migratePluginSecretRecordSet(tx, records, resource, seen); err != nil {
				return err
			}
		}
	}
	allRecords, err := storepkg.GetAllPluginRecords(tx)
	if err != nil {
		return err
	}
	for _, record := range allRecords {
		if _, ok := seen[record.ID]; ok {
			continue
		}
		updated, changed, err := store.reencryptDiscoveredEnvelopes(record)
		if err != nil {
			return err
		}
		if changed {
			if err := storepkg.RewritePluginRecordData(tx, record.ID, updated); err != nil {
				return err
			}
		}
	}
	operations, err := storepkg.GetAllPluginOperations(tx)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		updated, changed, err := store.reencryptPluginOperation(operation)
		if err != nil {
			return err
		}
		if changed {
			if err := storepkg.RewritePluginOperationPayloads(tx, updated); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (store *pluginSecretStore) migratePluginSecretsForPlugin(plugin LoadedPlugin) error {
	if store == nil || store.db == nil {
		return nil
	}
	store.operationMu.Lock()
	defer store.operationMu.Unlock()
	tx, err := store.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	seen := make(map[int64]struct{})
	for _, resource := range plugin.Resources {
		if len(resource.SecretFields) == 0 {
			continue
		}
		records, err := storepkg.GetPluginRecords(tx, plugin.ID, resource.ID)
		if err != nil {
			return err
		}
		if err := store.migratePluginSecretRecordSet(tx, records, resource, seen); err != nil {
			return err
		}
	}
	operations, err := storepkg.GetPluginOperations(tx, plugin.ID, "", "", pluginOperationMaxRecordsPerPlugin)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		updated, changed, err := store.reencryptPluginOperation(operation)
		if err != nil {
			return err
		}
		if changed {
			if err := storepkg.RewritePluginOperationPayloads(tx, updated); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (store *pluginSecretStore) reencryptPluginOperation(operation storepkg.PluginOperation) (storepkg.PluginOperation, bool, error) {
	changed := false
	fields := map[string]*string{
		"input": &operation.InputJSON, "state": &operation.StateJSON,
		"result": &operation.ResultJSON, "error": &operation.ErrorJSON,
	}
	store.mu.RLock()
	active := store.activeID
	store.mu.RUnlock()
	for field, target := range fields {
		raw := json.RawMessage(*target)
		if keyID, ok := pluginSecretEnvelopeKeyID(raw); ok && keyID == active {
			continue
		}
		plaintext := append(json.RawMessage(nil), raw...)
		decoded, encrypted, err := store.decryptJSON(operation.PluginID, pluginOperationSecretResourceID, operation.OperationID, field, raw)
		if err != nil {
			return storepkg.PluginOperation{}, false, err
		}
		if encrypted {
			plaintext = decoded
		}
		if !json.Valid(plaintext) {
			return storepkg.PluginOperation{}, false, fmt.Errorf("plugin operation %s field %s is invalid JSON", operation.OperationID, field)
		}
		ciphertext, err := store.encryptJSON(operation.PluginID, pluginOperationSecretResourceID, operation.OperationID, field, plaintext)
		if err != nil {
			return storepkg.PluginOperation{}, false, err
		}
		*target = string(ciphertext)
		changed = true
	}
	return operation, changed, nil
}

func (store *pluginSecretStore) migratePluginSecretRecordSet(tx *sql.Tx, records []storepkg.PluginRecord, resource PluginResource, seen map[int64]struct{}) error {
	for _, record := range records {
		if _, ok := seen[record.ID]; ok {
			continue
		}
		seen[record.ID] = struct{}{}
		plaintext, encrypted, err := store.decryptRecordDataUnlocked(record.PluginID, resource, record.RecordKey, record.DataJSON)
		if err != nil {
			return err
		}
		if encrypted && store.recordUsesActiveKey(record.DataJSON, resource) {
			continue
		}
		encryptedJSON, err := store.encryptRecordDataUnlocked(record.PluginID, resource, record.RecordKey, plaintext)
		if err != nil {
			return err
		}
		if encryptedJSON != record.DataJSON {
			if err := storepkg.RewritePluginRecordData(tx, record.ID, encryptedJSON); err != nil {
				return err
			}
		}
	}
	return nil
}

func (store *pluginSecretStore) recordUsesActiveKey(dataJSON string, resource PluginResource) bool {
	store.mu.RLock()
	active := store.activeID
	store.mu.RUnlock()
	if resource.ID == pluginControlSecretResourceID {
		var envelope pluginSecretEnvelopeObject
		return json.Unmarshal([]byte(dataJSON), &envelope) == nil && envelope.Secret != nil && envelope.Secret.KeyID == active
	}
	var object map[string]json.RawMessage
	if json.Unmarshal([]byte(dataJSON), &object) != nil {
		return false
	}
	fields := pluginSecretFieldSet(resource)
	for key, value := range object {
		if _, secret := fields[strings.ToLower(key)]; !secret {
			continue
		}
		var envelope pluginSecretEnvelopeObject
		if json.Unmarshal(value, &envelope) != nil || envelope.Secret == nil || envelope.Secret.KeyID != active {
			return false
		}
	}
	return true
}

func (store *pluginSecretStore) reencryptDiscoveredEnvelopes(record storepkg.PluginRecord) (string, bool, error) {
	store.mu.RLock()
	active := store.activeID
	store.mu.RUnlock()
	raw := json.RawMessage(record.DataJSON)
	if keyID, ok := pluginSecretEnvelopeKeyID(raw); ok {
		if keyID == active {
			return record.DataJSON, false, nil
		}
		plaintext, _, err := store.decryptJSON(record.PluginID, record.ResourceID, record.RecordKey, "$", raw)
		if err != nil {
			return record.DataJSON, false, nil
		}
		encrypted, err := store.encryptJSON(record.PluginID, record.ResourceID, record.RecordKey, "$", plaintext)
		return string(encrypted), true, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return record.DataJSON, false, nil
	}
	changed := false
	for field, value := range object {
		keyID, ok := pluginSecretEnvelopeKeyID(value)
		if !ok || keyID == active {
			continue
		}
		plaintext, _, err := store.decryptJSON(record.PluginID, record.ResourceID, record.RecordKey, field, value)
		if err != nil {
			continue
		}
		encrypted, err := store.encryptJSON(record.PluginID, record.ResourceID, record.RecordKey, field, plaintext)
		if err != nil {
			return "", false, err
		}
		object[field] = encrypted
		changed = true
	}
	if !changed {
		return record.DataJSON, false, nil
	}
	out, err := json.Marshal(object)
	return string(out), true, err
}

func pluginSecretEnvelopeKeyID(raw json.RawMessage) (string, bool) {
	envelope, found, err := decodePluginSecretEnvelope(raw)
	if !found || err != nil {
		return "", false
	}
	return envelope.KeyID, true
}

func (store *pluginSecretStore) rotate(catalog PluginCatalog) (pluginSecretRotationResult, error) {
	if store == nil || store.db == nil || store.keyPath == "" {
		return pluginSecretRotationResult{}, fmt.Errorf("persistent plugin secret key rotation is unavailable")
	}
	store.operationMu.Lock()
	defer store.operationMu.Unlock()
	pending, err := storepkg.GetPluginResourceMigrations(store.db, "")
	if err != nil {
		return pluginSecretRotationResult{}, err
	}
	if len(pending) > 0 {
		return pluginSecretRotationResult{}, fmt.Errorf("plugin secret rotation is blocked by %d pending resource migration(s)", len(pending))
	}
	key := make([]byte, pluginSecretMasterKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return pluginSecretRotationResult{}, err
	}
	newID := pluginSecretKeyID(key)
	rotatedAt := time.Now().UTC()

	pluginSecretKeyFileMu.Lock()
	defer pluginSecretKeyFileMu.Unlock()
	store.mu.RLock()
	keyCount := len(store.keys)
	store.mu.RUnlock()
	if keyCount > 1 {
		if err := store.migratePluginSecretsUnlocked(catalog); err != nil {
			return pluginSecretRotationResult{}, fmt.Errorf("recover transitional plugin secret keyring: %w", err)
		}
		if err := store.finalizeTransitionalKeyringLocked(rotatedAt); err != nil {
			return pluginSecretRotationResult{}, fmt.Errorf("recover transitional plugin secret keyring: %w", err)
		}
	}
	store.mu.RLock()
	allKeys := make(map[string]string, len(store.keys)+1)
	for id, existing := range store.keys {
		allKeys[id] = base64.StdEncoding.EncodeToString(existing)
	}
	store.mu.RUnlock()
	allKeys[newID] = base64.StdEncoding.EncodeToString(key)
	transitional := pluginSecretKeyringFile{
		Version: pluginSecretKeyringVersion, ActiveKey: newID, Keys: allKeys, UpdatedAt: rotatedAt.Format(time.RFC3339Nano),
	}
	if err := writePluginSecretKeyringAtomic(store.keyPath, transitional); err != nil {
		return pluginSecretRotationResult{}, err
	}
	store.mu.Lock()
	store.activeID = newID
	store.keys[newID] = append([]byte(nil), key...)
	store.mu.Unlock()
	if err := store.migratePluginSecretsUnlocked(catalog); err != nil {
		return pluginSecretRotationResult{}, fmt.Errorf("re-encrypt plugin secrets: %w", err)
	}
	if err := store.finalizeTransitionalKeyringLocked(rotatedAt); err != nil {
		return pluginSecretRotationResult{}, fmt.Errorf("finalize plugin secret keyring: %w", err)
	}
	return pluginSecretRotationResult{ActiveKey: newID, RotatedAt: rotatedAt.Format(time.RFC3339Nano)}, nil
}

func (store *pluginSecretStore) finalizeTransitionalKeyringLocked(updatedAt time.Time) error {
	if store == nil || store.keyPath == "" {
		return nil
	}
	store.mu.RLock()
	if len(store.keys) <= 1 {
		store.mu.RUnlock()
		return nil
	}
	activeID := store.activeID
	activeKey := append([]byte(nil), store.keys[activeID]...)
	store.mu.RUnlock()
	if len(activeKey) != pluginSecretMasterKeyBytes {
		return fmt.Errorf("plugin secret active key %s is unavailable", activeID)
	}
	keyring := pluginSecretKeyringFile{
		Version: pluginSecretKeyringVersion, ActiveKey: activeID,
		Keys: map[string]string{activeID: base64.StdEncoding.EncodeToString(activeKey)}, UpdatedAt: updatedAt.Format(time.RFC3339Nano),
	}
	if err := writePluginSecretKeyringAtomic(store.keyPath, keyring); err != nil {
		return err
	}
	store.mu.Lock()
	store.keys = map[string][]byte{activeID: activeKey}
	store.mu.Unlock()
	return nil
}

func (store *pluginSecretStore) status() map[string]any {
	if store == nil {
		return map[string]any{"available": false}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return map[string]any{
		"available": true, "persistent": store.keyPath != "", "active_key": store.activeID, "key_count": len(store.keys),
	}
}
