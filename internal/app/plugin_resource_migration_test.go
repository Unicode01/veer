package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginResourceMigrationCommitsAfterSuccessfulReconcile(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	writeResourceMigrationPlugin(t, dir, "1.0.0", 1, migrationSchemaV1, ``)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "migration_plugin", ResourceID: "profiles", RecordKey: "default", DataJSON: `{"name":"edge"}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	writeResourceMigrationPlugin(t, dir, "2.0.0", 2, migrationSchemaV2, `
exports.onResourceMigrate = function (ctx) {
  return {records: ctx.records.map(function (record) {
    return {key: record.key, data: {name: record.data.name, port: 443}, enabled: record.enabled};
  })};
};
`)
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	state, err := store.PluginResourceSchemaStateOrNil(db, "migration_plugin", "profiles")
	if err != nil || state == nil || state.SchemaVersion != 2 || state.Status != "active" || state.TransactionID != "" {
		t.Fatalf("schema state after migration = %+v, err=%v", state, err)
	}
	record, err := store.GetPluginRecord(db, "migration_plugin", "profiles", "default")
	if err != nil {
		t.Fatal(err)
	}
	if record.DataJSON != `{"name":"edge","port":443}` || record.Revision != 2 {
		t.Fatalf("record after migration = %+v", record)
	}
	assertNoPluginResourceMigrations(t, db)
}

func TestPluginResourceMigrationRollsBackWhenReconcileFails(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	writeResourceMigrationPlugin(t, dir, "1.0.0", 1, migrationSchemaV1, ``)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "migration_plugin", ResourceID: "profiles", RecordKey: "default", DataJSON: `{"name":"edge"}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
		PluginID: "migration_plugin", TargetType: "resource", TargetID: "profiles", Status: "applied", AppliedRevision: 7,
	}); err != nil {
		t.Fatal(err)
	}
	statusBefore, err := store.GetPluginRuntimeStatus(db, "migration_plugin", "resource", "profiles")
	if err != nil {
		t.Fatal(err)
	}

	writeResourceMigrationPlugin(t, dir, "2.0.0", 2, migrationSchemaV2, `
exports.onResourceMigrate = function (ctx) {
  return {records: ctx.records.map(function (record) {
    return {key: record.key, data: {name: record.data.name, port: 443}, enabled: record.enabled};
  })};
};
exports.onReconcile = function () {
  resources.set("profiles", "default", {name: "changed", port: 8443});
  throw new Error("injected reconcile failure");
};
`)
	snapshot := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := snapshot.stateFor("migration_plugin")
	if !ok || !strings.Contains(state.Error, "injected reconcile failure") {
		t.Fatalf("failed migration snapshot = %+v", snapshot)
	}
	schemaState, err := store.PluginResourceSchemaStateOrNil(db, "migration_plugin", "profiles")
	if err != nil || schemaState == nil || schemaState.SchemaVersion != 1 || schemaState.Status != "active" {
		t.Fatalf("schema state after rollback = %+v, err=%v", schemaState, err)
	}
	record, err := store.GetPluginRecord(db, "migration_plugin", "profiles", "default")
	if err != nil || record.DataJSON != `{"name":"edge"}` || record.Revision != 1 {
		t.Fatalf("record after rollback = %+v, err=%v", record, err)
	}
	statusAfter, err := store.GetPluginRuntimeStatus(db, "migration_plugin", "resource", "profiles")
	if err != nil || *statusAfter != *statusBefore {
		t.Fatalf("runtime status after rollback = %+v, err=%v; want %+v", statusAfter, err, statusBefore)
	}
	assertNoPluginResourceMigrations(t, db)
}

func TestPluginResourceMigrationSurvivesCrashAndBlocksConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir, WebToken: "migration-token"})
	writeResourceMigrationPlugin(t, dir, "1.0.0", 1, migrationSchemaV1, ``)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: "migration_plugin", ResourceID: "profiles", RecordKey: "default", DataJSON: `{"name":"edge"}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	writeResourceMigrationPlugin(t, dir, "2.0.0", 2, migrationSchemaV2, `
exports.onResourceMigrate = function (ctx) {
  return {records: ctx.records.map(function (record) {
    return {key: record.key, data: {name: record.data.name, port: 443}, enabled: record.enabled};
  })};
};
exports.onReconcile = function () {
  resources.set("profiles", "default", {name: "pending", port: 443});
};
`)
	if err := runtime.BeginPluginResourceMigrationTransaction(); err != nil {
		t.Fatal(err)
	}
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	state, err := store.PluginResourceSchemaStateOrNil(db, "migration_plugin", "profiles")
	if err != nil || state == nil || state.Status != "pending" || state.TransactionID == "" {
		t.Fatalf("pending schema state = %+v, err=%v", state, err)
	}
	pendingRecord, err := store.GetPluginRecord(db, "migration_plugin", "profiles", "default")
	if err != nil || pendingRecord.DataJSON != `{"name":"pending","port":443}` {
		t.Fatalf("record written by migration owner = %+v, err=%v", pendingRecord, err)
	}

	handler := buildAPIHandler(cfg, db, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/plugins/migration_plugin/resources/profiles/default", strings.NewReader(`{"data":{"name":"changed","port":8443}}`))
	req.Header.Set("Authorization", "Bearer migration-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "migration is pending") {
		t.Fatalf("write during pending migration status = %d body=%s", rec.Code, rec.Body.String())
	}

	if err := recoverPendingPluginResourceMigrations(db); err != nil {
		t.Fatalf("recoverPendingPluginResourceMigrations() error = %v", err)
	}
	if err := runtime.RollbackPluginResourceMigrationTransaction(); err != nil {
		t.Fatalf("clear recovered runtime migration: %v", err)
	}
	state, err = store.PluginResourceSchemaStateOrNil(db, "migration_plugin", "profiles")
	if err != nil || state == nil || state.SchemaVersion != 1 || state.Status != "active" {
		t.Fatalf("schema state after crash recovery = %+v, err=%v", state, err)
	}
	record, err := store.GetPluginRecord(db, "migration_plugin", "profiles", "default")
	if err != nil || record.DataJSON != `{"name":"edge"}` {
		t.Fatalf("record after crash recovery = %+v, err=%v", record, err)
	}
	assertNoPluginResourceMigrations(t, db)
}

func TestPluginResourceSchemaChangeRequiresVersionBump(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	writeResourceMigrationPlugin(t, dir, "1.0.0", 1, migrationSchemaV1, ``)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	writeResourceMigrationPlugin(t, dir, "1.1.0", 1, migrationSchemaV2, ``)
	snapshot := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := snapshot.stateFor("migration_plugin")
	if !ok || !strings.Contains(state.Error, "schema changed without increasing schema_version") {
		t.Fatalf("same-version schema change snapshot = %+v", snapshot)
	}
}

func TestPluginResourceMigrationCannotUseSideEffectAPIs(t *testing.T) {
	dir := t.TempDir()
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	writeResourceMigrationPlugin(t, dir, "1.0.0", 1, migrationSchemaV1, ``)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	assertPluginReconcileSuccess(t, runtime, loadPluginCatalogWithState(cfg, db), "migration_plugin")
	writeResourceMigrationPlugin(t, dir, "2.0.0", 2, migrationSchemaV2, `
exports.onResourceMigrate = function (ctx) {
  kv.set("forbidden", true);
  return {records: []};
};
`)
	snapshot := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := snapshot.stateFor("migration_plugin")
	if !ok || !strings.Contains(state.Error, "unavailable during plugin resource migration") {
		t.Fatalf("migration side effect snapshot = %+v", snapshot)
	}
}

const migrationSchemaV1 = `{
  type: "object",
  required: ["name"],
  properties: {name: {type: "string", minLength: 1}},
  additionalProperties: false
}`

const migrationSchemaV2 = `{
  type: "object",
  required: ["name", "port"],
  properties: {
    name: {type: "string", minLength: 1},
    port: {type: "integer", minimum: 1, maximum: 65535}
  },
  additionalProperties: false
}`

func writeResourceMigrationPlugin(t *testing.T, dir, version string, schemaVersion int, schema, handlers string) {
	t.Helper()
	manifest := fmt.Sprintf(`{
  "api_version": "v1",
  "id": "migration_plugin",
  "name": "Migration Plugin",
  "version": %q,
  "kind": "control",
  "control": {"main": "control.js", "permissions": ["plugin.register", "kv", "resource"]}
}`, version)
	writeTestPlugin(t, dir, "migration_plugin", manifest)
	control := fmt.Sprintf(`
plugin.resource({
  id: "profiles",
  methods: ["list", "get", "create", "update", "delete"],
  control_methods: ["list", "get", "create", "update", "delete"],
  schema_version: %d,
  schema: %s
});
exports.onReconcile = function () {};
%s
`, schemaVersion, schema, handlers)
	writePluginControlScript(t, dir, "migration_plugin", control)
}

func assertPluginReconcileSuccess(t *testing.T, runtime *gojaPluginControlRuntime, catalog PluginCatalog, pluginID string) {
	t.Helper()
	snapshot := runtime.Reconcile(catalog)
	state, ok := snapshot.stateFor(pluginID)
	if !ok || state.Error != "" {
		data, _ := json.Marshal(snapshot)
		t.Fatalf("plugin reconcile failed: %s", data)
	}
}

func assertNoPluginResourceMigrations(t *testing.T, db store.RuleStore) {
	t.Helper()
	migrations, err := store.GetPluginResourceMigrations(db, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 0 {
		t.Fatalf("pending resource migrations = %+v", migrations)
	}
}
