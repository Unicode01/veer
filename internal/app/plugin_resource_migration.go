package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const pluginResourceMigrationMaxJSONBytes = 16 << 20

type pluginResourceMigrationTransactionRuntime interface {
	BeginPluginResourceMigrationTransaction() error
	BeginPluginResourceMigrationTransactionWithID(string) error
	PluginResourceMigrationTransactionID() string
	CommitPluginResourceMigrationTransaction() error
	RollbackPluginResourceMigrationTransaction() error
}

type pluginResourceMigrationResult struct {
	Records []pluginResourceMigrationOutputRecord
}

type pluginResourceMigrationOutputRecord struct {
	Key      string
	DataJSON string
	Enabled  bool
}

type pluginResourceMigrationJSONResult struct {
	Records []pluginResourceMigrationJSONRecord `json:"records"`
}

type pluginResourceMigrationJSONRecord struct {
	Key     string          `json:"key"`
	Data    json.RawMessage `json:"data"`
	Enabled *bool           `json:"enabled,omitempty"`
}

func (h *pluginControlHost) exportResourceMigrationResult(value goja.Value, resource *PluginResource) (pluginResourceMigrationResult, error) {
	if resource == nil {
		return pluginResourceMigrationResult{}, fmt.Errorf("resource migration is missing its resource contract")
	}
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return pluginResourceMigrationResult{}, fmt.Errorf("onResourceMigrate must return an object containing records")
	}
	raw, err := json.Marshal(value.Export())
	if err != nil {
		return pluginResourceMigrationResult{}, fmt.Errorf("resource migration result is not JSON serializable: %w", err)
	}
	if len(raw) > pluginResourceMigrationMaxJSONBytes {
		return pluginResourceMigrationResult{}, fmt.Errorf("resource migration result exceeds %d bytes", pluginResourceMigrationMaxJSONBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var result pluginResourceMigrationJSONResult
	if err := decoder.Decode(&result); err != nil {
		return pluginResourceMigrationResult{}, fmt.Errorf("decode resource migration result: %w", err)
	}
	if result.Records == nil {
		return pluginResourceMigrationResult{}, fmt.Errorf("resource migration result must contain a records array")
	}
	if len(result.Records) > pluginResourceMaxRecords(*resource) {
		return pluginResourceMigrationResult{}, fmt.Errorf("resource migration returned more than %d records", pluginResourceMaxRecords(*resource))
	}
	out := pluginResourceMigrationResult{Records: make([]pluginResourceMigrationOutputRecord, 0, len(result.Records))}
	seen := make(map[string]struct{}, len(result.Records))
	for i, item := range result.Records {
		key, err := pluginPathToken(item.Key)
		if err != nil {
			return pluginResourceMigrationResult{}, fmt.Errorf("resource migration record %d key: %w", i, err)
		}
		if _, duplicate := seen[key]; duplicate {
			return pluginResourceMigrationResult{}, fmt.Errorf("resource migration returned duplicate key %q", key)
		}
		seen[key] = struct{}{}
		dataJSON, err := pluginRecordDataJSON(item.Data, *resource)
		if err != nil {
			return pluginResourceMigrationResult{}, fmt.Errorf("resource migration record %s: %w", key, err)
		}
		enabled := true
		if item.Enabled != nil {
			enabled = *item.Enabled
		}
		out.Records = append(out.Records, pluginResourceMigrationOutputRecord{Key: key, DataJSON: dataJSON, Enabled: enabled})
	}
	return out, nil
}

func (rt *gojaPluginControlRuntime) BeginPluginResourceMigrationTransaction() error {
	if rt == nil || rt.db == nil {
		return nil
	}
	id, err := newPluginPackageID()
	if err != nil {
		return err
	}
	return rt.BeginPluginResourceMigrationTransactionWithID(id)
}

func (rt *gojaPluginControlRuntime) BeginPluginResourceMigrationTransactionWithID(id string) error {
	if rt == nil || rt.db == nil {
		return nil
	}
	id = strings.TrimSpace(strings.ToLower(id))
	if err := validatePluginPackageID(id); err != nil {
		return fmt.Errorf("invalid plugin resource migration transaction id: %w", err)
	}
	rt.migrationMu.Lock()
	defer rt.migrationMu.Unlock()
	if rt.migrationTransaction != "" {
		return fmt.Errorf("plugin resource migration transaction %s is already active", rt.migrationTransaction)
	}
	rt.migrationTransaction = id
	rt.migrationDeferred = true
	return nil
}

func (rt *gojaPluginControlRuntime) PluginResourceMigrationTransactionID() string {
	return rt.currentPluginResourceMigrationTransaction()
}

func (rt *gojaPluginControlRuntime) beginImplicitPluginResourceMigrationTransaction() (string, bool, error) {
	if rt == nil || rt.db == nil {
		return "", false, nil
	}
	rt.migrationMu.Lock()
	defer rt.migrationMu.Unlock()
	if rt.migrationTransaction != "" {
		return rt.migrationTransaction, false, nil
	}
	id, err := newPluginPackageID()
	if err != nil {
		return "", false, err
	}
	rt.migrationTransaction = id
	rt.migrationDeferred = false
	return id, true, nil
}

func (rt *gojaPluginControlRuntime) currentPluginResourceMigrationTransaction() string {
	rt.migrationMu.Lock()
	defer rt.migrationMu.Unlock()
	return rt.migrationTransaction
}

func (rt *gojaPluginControlRuntime) preparePluginResourceMutation(transactionID string, plugin LoadedPlugin, resource PluginResource) error {
	if rt == nil || rt.db == nil {
		return fmt.Errorf("plugin resource store is unavailable")
	}
	if transactionID == "" {
		return store.EnsurePluginResourceMutationAllowed(rt.db, plugin.ID, resource.ID)
	}
	rt.migrationMu.Lock()
	activeTransaction := rt.migrationTransaction
	rt.migrationMu.Unlock()
	if activeTransaction != transactionID {
		return fmt.Errorf("plugin resource migration transaction is no longer active")
	}
	state, err := store.PluginResourceSchemaStateOrNil(rt.db, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	if state != nil && (state.Status != "active" || state.TransactionID != "") {
		return store.EnsurePluginResourceMutationAllowedForTransaction(rt.db, plugin.ID, resource.ID, transactionID)
	}
	records, err := store.GetPluginRecords(rt.db, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	journalResource := resource
	if state != nil {
		journalResource.SchemaVersion = state.SchemaVersion
		journalResource.SchemaDigest = state.SchemaDigest
	}
	return stagePluginResourceMigration(
		rt.db,
		transactionID,
		plugin,
		journalResource,
		state,
		records,
		pluginResourceMigrationResult{Records: pluginResourceMigrationOutputFromStored(records)},
		pluginResourceLimitsFromConfig(rt.cfg),
	)
}

func (h *pluginControlHost) preparePluginResourceMutation(plugin LoadedPlugin, resource PluginResource) error {
	if h == nil || h.db == nil {
		return fmt.Errorf("plugin resource store is unavailable")
	}
	if h.resourceMutationTransaction == "" {
		return store.EnsurePluginResourceMutationAllowed(h.db, plugin.ID, resource.ID)
	}
	if h.runtime == nil {
		return fmt.Errorf("plugin control runtime is unavailable")
	}
	return h.runtime.preparePluginResourceMutation(h.resourceMutationTransaction, plugin, resource)
}

func (h *pluginControlHost) ensurePluginResourceMutationAllowed(db store.RuleStore, plugin LoadedPlugin, resource PluginResource) error {
	return store.EnsurePluginResourceMutationAllowedForTransaction(db, plugin.ID, resource.ID, h.resourceMutationTransaction)
}

func (rt *gojaPluginControlRuntime) CommitPluginResourceMigrationTransaction() error {
	if rt == nil || rt.db == nil {
		return nil
	}
	rt.migrationMu.Lock()
	id := rt.migrationTransaction
	rt.migrationMu.Unlock()
	if id == "" {
		return nil
	}
	if err := commitPluginResourceMigrationTransaction(rt.db, id); err != nil {
		return err
	}
	rt.clearPluginResourceMigrationTransaction(id)
	return nil
}

func (rt *gojaPluginControlRuntime) RollbackPluginResourceMigrationTransaction() error {
	if rt == nil || rt.db == nil {
		return nil
	}
	rt.migrationMu.Lock()
	id := rt.migrationTransaction
	rt.migrationMu.Unlock()
	if id == "" {
		return nil
	}
	if err := rollbackPluginResourceMigrationTransaction(rt.db, id); err != nil {
		return err
	}
	rt.clearPluginResourceMigrationTransaction(id)
	return nil
}

func (rt *gojaPluginControlRuntime) clearPluginResourceMigrationTransaction(id string) {
	rt.migrationMu.Lock()
	if rt.migrationTransaction == id {
		rt.migrationTransaction = ""
		rt.migrationDeferred = false
	}
	rt.migrationMu.Unlock()
}

func (rt *gojaPluginControlRuntime) ensurePluginResourceSchemas(plugin LoadedPlugin) error {
	if rt == nil || rt.db == nil {
		return nil
	}
	transactionID := rt.currentPluginResourceMigrationTransaction()
	if transactionID == "" {
		return fmt.Errorf("plugin resource schema reconciliation has no transaction")
	}
	for _, resource := range plugin.Resources {
		if err := rt.ensurePluginResourceSchema(plugin, resource, transactionID); err != nil {
			return fmt.Errorf("resource %s schema migration: %w", resource.ID, err)
		}
	}
	return nil
}

func (rt *gojaPluginControlRuntime) ensurePluginResourceSchema(plugin LoadedPlugin, resource PluginResource, transactionID string) error {
	state, err := store.PluginResourceSchemaStateOrNil(rt.db, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	if state != nil && (state.Status != "active" || state.TransactionID != "") {
		if state.Status == "pending" && state.TransactionID == transactionID && state.SchemaVersion == resource.SchemaVersion && state.SchemaDigest == resource.SchemaDigest {
			return nil
		}
		return fmt.Errorf("another migration %s is pending", state.TransactionID)
	}
	if state != nil && state.SchemaVersion == resource.SchemaVersion {
		if state.SchemaDigest != resource.SchemaDigest {
			return fmt.Errorf("schema changed without increasing schema_version %d", resource.SchemaVersion)
		}
		return nil
	}

	storedRecords, err := store.GetPluginRecords(rt.db, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	records := storedRecords
	if len(resource.SecretFields) > 0 {
		secrets, err := rt.requirePluginSecretStore()
		if err != nil {
			return err
		}
		records, err = secrets.decryptRecords(storedRecords, resource)
		if err != nil {
			return err
		}
	}
	if len(records) > pluginResourceMaxRecords(resource) {
		return fmt.Errorf("stored record count %d exceeds resource limit %d", len(records), pluginResourceMaxRecords(resource))
	}
	fromVersion := 0
	fromDigest := ""
	if state != nil {
		fromVersion = state.SchemaVersion
		fromDigest = state.SchemaDigest
	}
	input := make([]PluginResourceRecord, 0, len(records))
	validationErr := error(nil)
	for _, record := range records {
		input = append(input, PluginResourceRecord{
			Key: record.RecordKey, Data: json.RawMessage(record.DataJSON), Enabled: record.Enabled, Revision: record.Revision, UpdatedAt: record.UpdatedAt,
		})
		if validationErr == nil {
			validationErr = validatePluginResourceData(resource, []byte(record.DataJSON))
		}
	}
	result, err := rt.runPluginControlResult(plugin, pluginControlEvent{
		Kind:      "resource_migrate",
		Resource:  &resource,
		Records:   input,
		Migration: &pluginControlResourceMigrationEvent{FromVersion: fromVersion, ToVersion: resource.SchemaVersion, FromDigest: fromDigest, ToDigest: resource.SchemaDigest},
	}, true)
	if err != nil {
		return err
	}
	output := pluginResourceMigrationResult{Records: pluginResourceMigrationOutputFromStored(records)}
	if result.handled {
		var ok bool
		output, ok = result.value.(pluginResourceMigrationResult)
		if !ok {
			return fmt.Errorf("onResourceMigrate returned an invalid result")
		}
	} else if validationErr != nil {
		return fmt.Errorf("stored records do not match the new schema and onResourceMigrate is not exported: %w", validationErr)
	}
	storageOutput, err := rt.pluginResourceMigrationStorageOutput(plugin, resource, storedRecords, records, output)
	if err != nil {
		return err
	}
	return stagePluginResourceMigration(rt.db, transactionID, plugin, resource, state, storedRecords, storageOutput, pluginResourceLimitsFromConfig(rt.cfg))
}

func (rt *gojaPluginControlRuntime) pluginResourceMigrationStorageOutput(
	plugin LoadedPlugin,
	resource PluginResource,
	storedRecords []store.PluginRecord,
	plaintextRecords []store.PluginRecord,
	result pluginResourceMigrationResult,
) (pluginResourceMigrationResult, error) {
	if len(resource.SecretFields) == 0 {
		return result, nil
	}
	secrets, err := rt.requirePluginSecretStore()
	if err != nil {
		return pluginResourceMigrationResult{}, err
	}
	storedByKey := make(map[string]store.PluginRecord, len(storedRecords))
	plaintextByKey := make(map[string]store.PluginRecord, len(plaintextRecords))
	for _, record := range storedRecords {
		storedByKey[record.RecordKey] = record
	}
	for _, record := range plaintextRecords {
		plaintextByKey[record.RecordKey] = record
	}
	out := pluginResourceMigrationResult{Records: make([]pluginResourceMigrationOutputRecord, 0, len(result.Records))}
	for _, item := range result.Records {
		stored, hadStored := storedByKey[item.Key]
		plaintext, hadPlaintext := plaintextByKey[item.Key]
		if hadStored && hadPlaintext && plaintext.DataJSON == item.DataJSON && plaintext.Enabled == item.Enabled {
			_, encrypted, decryptErr := secrets.decryptRecordData(plugin.ID, resource, item.Key, stored.DataJSON)
			if decryptErr != nil {
				return pluginResourceMigrationResult{}, decryptErr
			}
			if encrypted {
				item.DataJSON = stored.DataJSON
				out.Records = append(out.Records, item)
				continue
			}
		}
		encrypted, err := secrets.encryptRecordData(plugin.ID, resource, item.Key, item.DataJSON)
		if err != nil {
			return pluginResourceMigrationResult{}, err
		}
		item.DataJSON = encrypted
		out.Records = append(out.Records, item)
	}
	return out, nil
}

func pluginResourceMigrationOutputFromStored(records []store.PluginRecord) []pluginResourceMigrationOutputRecord {
	out := make([]pluginResourceMigrationOutputRecord, 0, len(records))
	for _, record := range records {
		out = append(out, pluginResourceMigrationOutputRecord{Key: record.RecordKey, DataJSON: record.DataJSON, Enabled: record.Enabled})
	}
	return out
}

func stagePluginResourceMigration(db *sql.DB, transactionID string, plugin LoadedPlugin, resource PluginResource, previousState *store.PluginResourceSchemaState, previousRecords []store.PluginRecord, result pluginResourceMigrationResult, limitValues ...PluginResourceLimits) error {
	limits := pluginResourceLimitsFromConfig(nil)
	if len(limitValues) > 0 {
		limits = limitValues[0]
	}
	backupJSON, err := json.Marshal(previousRecords)
	if err != nil {
		return err
	}
	if len(backupJSON) > pluginResourceMigrationMaxJSONBytes {
		return fmt.Errorf("resource migration backup exceeds %d bytes", pluginResourceMigrationMaxJSONBytes)
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	currentState, err := store.PluginResourceSchemaStateOrNil(tx, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	if !equalPluginResourceSchemaState(previousState, currentState) {
		return fmt.Errorf("resource schema state changed while migration was prepared")
	}
	currentRecords, err := store.GetPluginRecords(tx, plugin.ID, resource.ID)
	if err != nil {
		return err
	}
	if !equalStoredPluginRecords(previousRecords, currentRecords) {
		return fmt.Errorf("resource records changed while migration was prepared")
	}
	previousRuntimeStatus, err := store.PluginRuntimeStatusOrNil(tx, plugin.ID, "resource", resource.ID)
	if err != nil {
		return err
	}
	runtimeStatusJSON, err := json.Marshal(previousRuntimeStatus)
	if err != nil {
		return err
	}
	migration := store.PluginResourceMigration{
		TransactionID:     transactionID,
		PluginID:          plugin.ID,
		ResourceID:        resource.ID,
		RecordsJSON:       string(backupJSON),
		RuntimeStatusJSON: string(runtimeStatusJSON),
	}
	if previousState != nil {
		migration.PreviousSchemaExists = true
		migration.PreviousSchemaVersion = previousState.SchemaVersion
		migration.PreviousSchemaDigest = previousState.SchemaDigest
	}
	if err := store.AddPluginResourceMigration(tx, migration); err != nil {
		return err
	}
	if !pluginResourceMigrationMatchesStored(result.Records, previousRecords) {
		if err := replacePluginResourceRecordsForMigration(tx, plugin.ID, resource.ID, previousRecords, result.Records, limits); err != nil {
			return err
		}
	}
	if err := store.UpsertPluginResourceSchemaState(tx, store.PluginResourceSchemaState{
		PluginID: plugin.ID, ResourceID: resource.ID, SchemaVersion: resource.SchemaVersion, SchemaDigest: resource.SchemaDigest,
		Status: "pending", TransactionID: transactionID,
	}); err != nil {
		return err
	}
	return tx.Commit()
}

func replacePluginResourceRecordsForMigration(tx store.RuleStore, pluginID, resourceID string, previous []store.PluginRecord, output []pluginResourceMigrationOutputRecord, limits PluginResourceLimits) error {
	if err := store.DeletePluginRecordsForResource(tx, pluginID, resourceID); err != nil {
		return err
	}
	previousByKey := make(map[string]store.PluginRecord, len(previous))
	for _, record := range previous {
		previousByKey[record.RecordKey] = record
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, item := range output {
		record := store.PluginRecord{PluginID: pluginID, ResourceID: resourceID, RecordKey: item.Key, DataJSON: item.DataJSON, Enabled: item.Enabled}
		if old, ok := previousByKey[item.Key]; ok {
			record.ID = old.ID
			record.Revision = old.Revision
			record.CreatedAt = old.CreatedAt
			record.UpdatedAt = old.UpdatedAt
			if old.DataJSON != item.DataJSON || old.Enabled != item.Enabled {
				record.Revision++
				record.UpdatedAt = now
			}
		}
		if err := ensurePluginRecordStorageQuota(tx, pluginID, nil, record, limits); err != nil {
			return err
		}
		if err := store.AddPluginRecordExact(tx, record); err != nil {
			return err
		}
	}
	return nil
}

func commitPluginResourceMigrationTransaction(db *sql.DB, transactionID string) error {
	if db == nil || transactionID == "" {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	migrations, err := store.GetPluginResourceMigrations(tx, transactionID)
	if err != nil {
		return err
	}
	for _, migration := range migrations {
		state, err := store.PluginResourceSchemaStateOrNil(tx, migration.PluginID, migration.ResourceID)
		if err != nil {
			return err
		}
		if state == nil || state.Status != "pending" || state.TransactionID != transactionID {
			return fmt.Errorf("pending schema state is missing for %s/%s", migration.PluginID, migration.ResourceID)
		}
		state.Status = "active"
		state.TransactionID = ""
		if err := store.UpsertPluginResourceSchemaState(tx, *state); err != nil {
			return err
		}
	}
	if err := store.DeletePluginResourceMigrations(tx, transactionID); err != nil {
		return err
	}
	return tx.Commit()
}

func rollbackPluginResourceMigrationTransaction(db *sql.DB, transactionID string) error {
	if db == nil || transactionID == "" {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	migrations, err := store.GetPluginResourceMigrations(tx, transactionID)
	if err != nil {
		return err
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].ID > migrations[j].ID })
	for _, migration := range migrations {
		state, err := store.PluginResourceSchemaStateOrNil(tx, migration.PluginID, migration.ResourceID)
		if err != nil {
			return err
		}
		if state == nil || state.Status != "pending" || state.TransactionID != transactionID {
			return fmt.Errorf("pending schema state is missing for %s/%s", migration.PluginID, migration.ResourceID)
		}
		var records []store.PluginRecord
		if err := json.Unmarshal([]byte(migration.RecordsJSON), &records); err != nil {
			return fmt.Errorf("decode migration backup for %s/%s: %w", migration.PluginID, migration.ResourceID, err)
		}
		if err := store.DeletePluginRecordsForResource(tx, migration.PluginID, migration.ResourceID); err != nil {
			return err
		}
		for _, record := range records {
			if record.PluginID != migration.PluginID || record.ResourceID != migration.ResourceID {
				return fmt.Errorf("migration backup identity mismatch for %s/%s", migration.PluginID, migration.ResourceID)
			}
			if err := store.AddPluginRecordExact(tx, record); err != nil {
				return err
			}
		}
		if migration.RuntimeStatusJSON != "" {
			var runtimeStatus *store.PluginRuntimeStatus
			if err := json.Unmarshal([]byte(migration.RuntimeStatusJSON), &runtimeStatus); err != nil {
				return fmt.Errorf("decode runtime status backup for %s/%s: %w", migration.PluginID, migration.ResourceID, err)
			}
			if runtimeStatus == nil {
				if err := store.DeletePluginRuntimeStatusIfExists(tx, migration.PluginID, "resource", migration.ResourceID); err != nil {
					return err
				}
			} else {
				if runtimeStatus.PluginID != migration.PluginID || runtimeStatus.TargetType != "resource" || runtimeStatus.TargetID != migration.ResourceID {
					return fmt.Errorf("runtime status backup identity mismatch for %s/%s", migration.PluginID, migration.ResourceID)
				}
				if err := store.RestorePluginRuntimeStatus(tx, runtimeStatus); err != nil {
					return err
				}
			}
		}
		if migration.PreviousSchemaExists {
			if err := store.UpsertPluginResourceSchemaState(tx, store.PluginResourceSchemaState{
				PluginID: migration.PluginID, ResourceID: migration.ResourceID, SchemaVersion: migration.PreviousSchemaVersion,
				SchemaDigest: migration.PreviousSchemaDigest, Status: "active",
			}); err != nil {
				return err
			}
		} else if err := store.DeletePluginResourceSchemaState(tx, migration.PluginID, migration.ResourceID); err != nil {
			return err
		}
	}
	if err := store.DeletePluginResourceMigrations(tx, transactionID); err != nil {
		return err
	}
	return tx.Commit()
}

func recoverPendingPluginResourceMigrations(db *sql.DB) error {
	if db == nil {
		return nil
	}
	migrations, err := store.GetPluginResourceMigrations(db, "")
	if err != nil {
		return err
	}
	transactions := make(map[string]struct{})
	for _, migration := range migrations {
		if strings.TrimSpace(migration.TransactionID) == "" {
			return fmt.Errorf("plugin resource migration has an empty transaction id")
		}
		transactions[migration.TransactionID] = struct{}{}
	}
	ids := make([]string, 0, len(transactions))
	for id := range transactions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := rollbackPluginResourceMigrationTransaction(db, id); err != nil {
			return fmt.Errorf("recover plugin resource migration %s: %w", id, err)
		}
	}
	return nil
}

func equalPluginResourceSchemaState(left, right *store.PluginResourceSchemaState) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.PluginID == right.PluginID && left.ResourceID == right.ResourceID && left.SchemaVersion == right.SchemaVersion &&
		left.SchemaDigest == right.SchemaDigest && left.Status == right.Status && left.TransactionID == right.TransactionID
}

func equalStoredPluginRecords(left, right []store.PluginRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func pluginResourceMigrationMatchesStored(output []pluginResourceMigrationOutputRecord, stored []store.PluginRecord) bool {
	if len(output) != len(stored) {
		return false
	}
	for i := range output {
		if output[i].Key != stored[i].RecordKey || output[i].DataJSON != stored[i].DataJSON || output[i].Enabled != stored[i].Enabled {
			return false
		}
	}
	return true
}

func pluginResourceMigrationErrorIsPending(err error) bool {
	return errors.Is(err, store.ErrPluginResourceMigrationPending)
}
