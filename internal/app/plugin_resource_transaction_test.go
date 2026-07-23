package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginResourceTransactionCommitsAllOrNothing(t *testing.T) {
	dir := t.TempDir()
	writePluginResourceTransactionFixture(t, dir, false)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "transaction_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "transaction_plugin")
	action := plugin.Actions[0]

	_, err := runtime.QueryPluginAction(plugin, action, json.RawMessage(`{
  "operations": [
    {"op":"set","resource":"alpha","key":"default","data":{"value":1}},
    {"op":"set","resource":"beta","key":"default","data":{"value":2}}
  ]
}`))
	if err != nil {
		t.Fatalf("initial transaction error = %v", err)
	}
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "alpha", "default", `{"value":1}`)
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "beta", "default", `{"value":2}`)

	_, err = runtime.QueryPluginAction(plugin, action, json.RawMessage(`{
  "operations": [
    {"op":"set","resource":"alpha","key":"default","data":{"value":10}},
    {"op":"set","resource":"beta","key":"default","data":{"value":"invalid"}}
  ]
}`))
	if err == nil || !strings.Contains(err.Error(), "does not match schema") {
		t.Fatalf("invalid transaction error = %v", err)
	}
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "alpha", "default", `{"value":1}`)
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "beta", "default", `{"value":2}`)
}

func TestPluginResourceTransactionRestoresDatabaseAndRuntimeOnApplyFailure(t *testing.T) {
	dir := t.TempDir()
	writePluginResourceTransactionFixture(t, dir, true)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "transaction_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "transaction_plugin")
	action := plugin.Actions[0]
	_, err := runtime.QueryPluginAction(plugin, action, json.RawMessage(`{
  "operations": [
    {"op":"set","resource":"alpha","key":"default","data":{"value":1}},
    {"op":"set","resource":"beta","key":"default","data":{"value":2,"fail":false}}
  ],
  "apply": true
}`))
	if err != nil {
		t.Fatalf("seed transaction error = %v", err)
	}

	_, err = runtime.QueryPluginAction(plugin, action, json.RawMessage(`{
  "operations": [
    {"op":"set","resource":"alpha","key":"default","data":{"value":10}},
    {"op":"set","resource":"beta","key":"default","data":{"value":20,"fail":true}}
  ],
  "apply": true
}`))
	if err == nil || !strings.Contains(err.Error(), "injected beta apply failure") || !strings.Contains(err.Error(), "changes rolled back") {
		t.Fatalf("failing apply transaction error = %v", err)
	}
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "alpha", "default", `{"value":1}`)
	assertPluginResourceRecordJSON(t, db, "transaction_plugin", "beta", "default", `{"fail":false,"value":2}`)
}

func TestPluginCrossResourceTransactionEnforcesAccessAndIsAtomic(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "target_plugin", `{
  "api_version":"v1","id":"target_plugin","name":"Target","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "target_plugin", `
plugin.resource({id:"settings", methods:["list","get","create","update","delete"], schema:{type:"object",required:["value"],properties:{value:{type:"integer"}},additionalProperties:false}});
exports.onReconcile = function () {};
`)
	writeTestPlugin(t, dir, "orchestrator", `{
  "api_version":"v1","id":"orchestrator","name":"Orchestrator","version":"1.0.0","kind":"control",
  "dependencies":[{"id":"target_plugin","version":"^1.0.0"}],
  "control":{
    "main":"control.js",
    "permissions":["plugin.register","plugin.resource"],
    "resource_access":[{"plugin":"target_plugin","resource":"settings","methods":["create","update","delete"]}]
  }
}`)
	writePluginControlScript(t, dir, "orchestrator", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onAction = function (ctx) { return plugins.resources.transaction(ctx.payload.operations, {apply:false}); };
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	snapshot := runtime.Reconcile(catalog)
	for _, id := range []string{"target_plugin", "orchestrator"} {
		state, ok := snapshot.stateFor(id)
		if !ok || state.Error != "" {
			t.Fatalf("%s reconcile state = %+v", id, state)
		}
	}
	orchestrator := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "orchestrator")
	_, err := runtime.QueryPluginAction(orchestrator, orchestrator.Actions[0], json.RawMessage(`{
  "operations":[
    {"op":"set","plugin":"target_plugin","resource":"settings","key":"one","data":{"value":1}},
    {"op":"set","plugin":"target_plugin","resource":"settings","key":"two","data":{"value":2}}
  ]
}`))
	if err != nil {
		t.Fatalf("cross-plugin transaction error = %v", err)
	}
	assertPluginResourceRecordJSON(t, db, "target_plugin", "settings", "one", `{"value":1}`)
	assertPluginResourceRecordJSON(t, db, "target_plugin", "settings", "two", `{"value":2}`)

	_, err = runtime.QueryPluginAction(orchestrator, orchestrator.Actions[0], json.RawMessage(`{
  "operations":[
    {"op":"set","plugin":"target_plugin","resource":"settings","key":"one","data":{"value":10}},
    {"op":"set","plugin":"target_plugin","resource":"settings","key":"two","data":{"value":"invalid"}}
  ]
}`))
	if err == nil {
		t.Fatal("invalid cross-plugin transaction error = nil")
	}
	assertPluginResourceRecordJSON(t, db, "target_plugin", "settings", "one", `{"value":1}`)
	assertPluginResourceRecordJSON(t, db, "target_plugin", "settings", "two", `{"value":2}`)
}

func writePluginResourceTransactionFixture(t *testing.T, dir string, runtimeApply bool) {
	t.Helper()
	writeTestPlugin(t, dir, "transaction_plugin", `{
  "api_version":"v1","id":"transaction_plugin","name":"Transaction Plugin","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","resource"]}
}`)
	runtimeUpdate := "manual"
	applyHandler := ""
	if runtimeApply {
		runtimeUpdate = "runtime_apply"
		applyHandler = `
exports.onResourceApply = function (ctx) {
  if (ctx.resource.id !== "beta") return;
  for (var i = 0; i < ctx.records.length; i++) {
    if (ctx.records[i].data && ctx.records[i].data.fail === true) throw new Error("injected beta apply failure");
  }
};`
	}
	writePluginControlScript(t, dir, "transaction_plugin", `
plugin.resource({id:"alpha", methods:["list","get","create","update","delete"], control_methods:["list","get","create","update","delete"], runtime_update:"`+runtimeUpdate+`", schema:{type:"object",required:["value"],properties:{value:{type:"integer"}},additionalProperties:false}});
plugin.resource({id:"beta", methods:["list","get","create","update","delete"], control_methods:["list","get","create","update","delete"], runtime_update:"`+runtimeUpdate+`", schema:{type:"object",required:["value"],properties:{value:{type:"integer"},fail:{type:"boolean"}},additionalProperties:false}});
plugin.action({id:"apply", runtime_update:"runtime_query", max_payload_bytes:1048576});
exports.onReconcile = function () {};
exports.onAction = function (ctx) { return resources.transaction(ctx.payload.operations, {apply:ctx.payload.apply === true}); };
`+applyHandler)
}

func transactionPluginWithRuntimeSurfaceForTest(t *testing.T, runtime *gojaPluginControlRuntime, catalog PluginCatalog, pluginID string) LoadedPlugin {
	t.Helper()
	applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())
	plugin := relationshipPluginByIDValue(catalog, pluginID)
	if plugin == nil {
		t.Fatalf("plugin %s not found", pluginID)
	}
	return *plugin
}

func assertPluginResourceRecordJSON(t *testing.T, db store.RuleStore, pluginID, resourceID, key, expected string) {
	t.Helper()
	record, err := store.GetPluginRecord(db, pluginID, resourceID, key)
	if err != nil {
		t.Fatalf("get %s/%s/%s: %v", pluginID, resourceID, key, err)
	}
	if record.DataJSON != expected {
		t.Fatalf("%s/%s/%s data = %s, want %s", pluginID, resourceID, key, record.DataJSON, expected)
	}
}
