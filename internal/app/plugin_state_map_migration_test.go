package app

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestPluginGojaEBPFStateMigrationCopiesInBoundedBatches(t *testing.T) {
	dir := t.TempDir()
	writePluginStateMigrationTestPlugin(t, dir, "state_migrate", `
exports.onEBPFStateMigrate = function (ctx) {
  var migration = ctx.ebpf_migration;
  if (migration.protocol_version !== 1 || migration.max_entries !== 256 || migration.max_bytes !== 1048576) {
    throw new Error("unexpected migration protocol");
  }
  var page = ebpf.mapScan(migration.source_map, {cursor:migration.cursor, limit:1, max_bytes:migration.max_bytes});
  if (page.entries.length) {
    ebpf.mapTransaction({operations:page.entries.map(function (entry) {
      return {op:"put", map:migration.target_map, key:entry.key, value:entry.value + "00"};
    })});
  }
  return {done:page.done, cursor:page.cursor, processed:page.entries.length};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := newPluginStateMigrationMapControllerTest()
	controller.put("", "sessions_v1", []byte{1}, []byte{10})
	controller.put("", "sessions_v1", []byte{2}, []byte{11})
	controller.put("", "sessions_v1", []byte{3}, []byte{12})
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "state_migrate")
	applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())

	migration := testPluginEBPFStateMigration("state_migrate")
	completed, failures := runtime.ApplyPluginEBPFStateMigrations(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"state_migrate": {Mode: pluginRuntimeModeDataplane, Attached: true},
	}}, []PluginEBPFStateMigration{migration})
	if len(failures) != 0 || len(completed) != 1 || completed[0] != migration {
		t.Fatalf("migration result completed=%+v failures=%+v", completed, failures)
	}
	if controller.scanCalls != 3 || controller.transactionCalls != 3 {
		t.Fatalf("migration calls scan=%d transaction=%d, want 3/3", controller.scanCalls, controller.transactionCalls)
	}
	for key, want := range map[byte][]byte{1: {10, 0}, 2: {11, 0}, 3: {12, 0}} {
		got, err := controller.GetPluginMapValue("state_migrate", "", "sessions_v2", []byte{key})
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("target key %d = %x, %v, want %x", key, got, err, want)
		}
	}
}

func TestPluginGojaEBPFStateMigrationRejectsIncompleteHandlers(t *testing.T) {
	tests := []struct {
		name    string
		handler string
		want    string
	}{
		{name: "missing", handler: "", want: "does not export onEBPFStateMigrate"},
		{name: "missing_done", handler: `exports.onEBPFStateMigrate = function () { return {cursor:"01", processed:1}; };`, want: "must include done"},
		{name: "stalled", handler: `exports.onEBPFStateMigrate = function () { return {done:false, cursor:"01", processed:0}; };`, want: "incomplete migration must report processed entries"},
		{name: "unchanged_cursor", handler: `exports.onEBPFStateMigrate = function (ctx) { return {done:false, cursor:"01", processed:1}; };`, want: "unchanged cursor"},
		{name: "completed_cursor", handler: `exports.onEBPFStateMigrate = function () { return {done:true, cursor:"01", processed:1}; };`, want: "completed migration must return an empty cursor"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginStateMigrationTestPlugin(t, dir, "state_migrate_"+test.name, test.handler)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			db := openTestDB(t)
			runtime := newPluginControlRuntime(db, cfg, newPluginStateMigrationMapControllerTest()).(*gojaPluginControlRuntime)
			t.Cleanup(func() { _ = runtime.Close() })
			catalog := loadPluginCatalogWithState(cfg, db)
			pluginID := "state_migrate_" + test.name
			assertPluginReconcileSuccess(t, runtime, catalog, pluginID)
			applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())
			_, failures := runtime.ApplyPluginEBPFStateMigrations(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
				pluginID: {Mode: pluginRuntimeModeDataplane, Attached: true},
			}}, []PluginEBPFStateMigration{testPluginEBPFStateMigration(pluginID)})
			if failures[pluginID] == nil || !strings.Contains(failures[pluginID].Error(), test.want) {
				t.Fatalf("migration failure = %v, want %q", failures[pluginID], test.want)
			}
		})
	}
}

func TestPluginGojaEBPFStateMigrationPropagatesMapTransactionFailure(t *testing.T) {
	dir := t.TempDir()
	writePluginStateMigrationTestPlugin(t, dir, "state_migrate_failure", `
exports.onEBPFStateMigrate = function (ctx) {
  var migration = ctx.ebpf_migration;
  var page = ebpf.mapScan(migration.source_map, {cursor:migration.cursor, limit:1});
  ebpf.mapTransaction({operations:[{op:"put", map:migration.target_map, key:page.entries[0].key, value:page.entries[0].value}]});
  return {done:page.done, cursor:page.cursor, processed:page.entries.length};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := newPluginStateMigrationMapControllerTest()
	controller.put("", "sessions_v1", []byte{1}, []byte{10})
	controller.transactionErr = errors.New("injected migration transaction failure")
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "state_migrate_failure")
	applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())
	_, failures := runtime.ApplyPluginEBPFStateMigrations(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"state_migrate_failure": {Mode: pluginRuntimeModeDataplane, Attached: true},
	}}, []PluginEBPFStateMigration{testPluginEBPFStateMigration("state_migrate_failure")})
	if failures["state_migrate_failure"] == nil || !strings.Contains(failures["state_migrate_failure"].Error(), "injected migration transaction failure") {
		t.Fatalf("migration failure = %v", failures["state_migrate_failure"])
	}
	if controller.transactionCalls != 1 {
		t.Fatalf("transaction calls = %d, want 1", controller.transactionCalls)
	}
}

func TestPluginStateMapMigrationRollbackRequiresPreservedSource(t *testing.T) {
	previous := map[string]PluginObjectStateMap{
		"sessions_v1": {Name: "sessions_v1", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
		"sessions_v2": {Name: "sessions_v2", Policy: pluginObjectMapMigrate, SchemaVersion: 2, MigrateFrom: "sessions_v1"},
	}
	if !pluginStateMapMigrationRollbackAllowed(previous["sessions_v2"], previous, map[string]PluginObjectStateMap{
		"sessions_v1": {Name: "sessions_v1", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
	}) {
		t.Fatal("rollback to the preserved source schema should be allowed")
	}
	for name, next := range map[string]map[string]PluginObjectStateMap{
		"missing_source":        {},
		"reset_source":          {"sessions_v1": {Name: "sessions_v1", Policy: pluginObjectMapReset}},
		"changed_source_schema": {"sessions_v1": {Name: "sessions_v1", Policy: pluginObjectMapPreserve, SchemaVersion: 3}},
	} {
		t.Run(name, func(t *testing.T) {
			if pluginStateMapMigrationRollbackAllowed(previous["sessions_v2"], previous, next) {
				t.Fatalf("unsafe rollback accepted for %+v", next)
			}
		})
	}
}

func writePluginStateMigrationTestPlugin(t *testing.T, dir, pluginID, handler string) {
	t.Helper()
	writeTestPlugin(t, dir, pluginID, fmt.Sprintf(`{
  "api_version":"v1","id":%q,"name":"State Migration Plugin","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["ebpf.map_read","ebpf.map_write"]}
}`, pluginID))
	writePluginControlScript(t, dir, pluginID, "exports.onReconcile = function () {};\n"+handler)
}

func testPluginEBPFStateMigration(pluginID string) PluginEBPFStateMigration {
	return PluginEBPFStateMigration{
		PluginID: pluginID, SourceMap: "sessions_v1", TargetMap: "sessions_v2", FromSchemaVersion: 1, ToSchemaVersion: 2,
	}
}

type pluginStateMigrationMapControllerTest struct {
	maps             map[string]map[string][]byte
	scanCalls        int
	transactionCalls int
	transactionErr   error
}

func newPluginStateMigrationMapControllerTest() *pluginStateMigrationMapControllerTest {
	return &pluginStateMigrationMapControllerTest{maps: make(map[string]map[string][]byte)}
}

func (c *pluginStateMigrationMapControllerTest) mapKey(objectID, mapName string) string {
	return objectID + "\x00" + mapName
}

func (c *pluginStateMigrationMapControllerTest) put(objectID, mapName string, key, value []byte) {
	slot := c.mapKey(objectID, mapName)
	if c.maps[slot] == nil {
		c.maps[slot] = make(map[string][]byte)
	}
	c.maps[slot][string(key)] = append([]byte(nil), value...)
}

func (c *pluginStateMigrationMapControllerTest) GetPluginMapValue(_, objectID, mapName string, key []byte) ([]byte, error) {
	value, ok := c.maps[c.mapKey(objectID, mapName)][string(key)]
	if !ok {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	return append([]byte(nil), value...), nil
}

func (c *pluginStateMigrationMapControllerTest) PutPluginMapValue(_, objectID, mapName string, key, value []byte) error {
	c.put(objectID, mapName, key, value)
	return nil
}

func (c *pluginStateMigrationMapControllerTest) DeletePluginMapValue(_, objectID, mapName string, key []byte) error {
	delete(c.maps[c.mapKey(objectID, mapName)], string(key))
	return nil
}

func (c *pluginStateMigrationMapControllerTest) ClearPluginMap(_, objectID, mapName string) error {
	delete(c.maps, c.mapKey(objectID, mapName))
	return nil
}

func (c *pluginStateMigrationMapControllerTest) ScanPluginMap(_, objectID, mapName string, request pluginEBPFMapScanRequest) (pluginEBPFMapScanResult, error) {
	c.scanCalls++
	records := c.maps[c.mapKey(objectID, mapName)]
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	start := 0
	if len(request.Cursor) > 0 {
		start = sort.SearchStrings(keys, string(request.Cursor))
		if start < len(keys) && keys[start] == string(request.Cursor) {
			start++
		}
	}
	result := pluginEBPFMapScanResult{}
	bytesUsed := 0
	for index := start; index < len(keys) && len(result.Entries) < request.Limit; index++ {
		key := []byte(keys[index])
		value := records[keys[index]]
		if bytesUsed+len(key)+len(value) > request.MaxBytes {
			break
		}
		result.Entries = append(result.Entries, pluginEBPFMapScanEntry{Key: append([]byte(nil), key...), Value: append([]byte(nil), value...)})
		bytesUsed += len(key) + len(value)
	}
	result.Done = start+len(result.Entries) >= len(keys)
	if !result.Done && len(result.Entries) > 0 {
		result.Cursor = append([]byte(nil), result.Entries[len(result.Entries)-1].Key...)
	}
	return result, nil
}

func (c *pluginStateMigrationMapControllerTest) TransactionPluginMaps(_ string, request pluginEBPFMapTransactionRequest) error {
	c.transactionCalls++
	if c.transactionErr != nil {
		return c.transactionErr
	}
	for _, mutation := range request.Operations {
		switch mutation.Operation {
		case pluginEBPFMapMutationPut:
			c.put(mutation.ObjectID, mutation.MapName, mutation.Key, mutation.Value)
		case pluginEBPFMapMutationDelete:
			delete(c.maps[c.mapKey(mutation.ObjectID, mutation.MapName)], string(mutation.Key))
		default:
			return fmt.Errorf("unexpected mutation %q", mutation.Operation)
		}
	}
	return nil
}
