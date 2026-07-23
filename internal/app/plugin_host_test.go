package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

// TestPluginHostProcessEntrypoint is the subprocess entrypoint used by
// isolated plugin-host tests. os.Exit prevents the test runner from writing
// PASS output into the framed protocol stream.
func TestPluginHostProcessEntrypoint(t *testing.T) {
	if os.Getenv("VEER_PLUGIN_HOST_TEST") != "1" {
		return
	}
	if err := runPluginHostProcess(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "plugin host: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func isolatedPluginsTestConfig(cfg *Config) *Config {
	cfg = pluginsEnabledTestConfig(cfg)
	enabled := true
	cfg.PluginsIsolationSetting = &enabled
	cfg.pluginHostTestMode = true
	return cfg
}

func TestPluginHostIsolationKeepsPersistentState(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_state", `{
  "api_version":"v1",
  "id":"isolated_state",
  "name":"Isolated State",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv"]}
}`)
	writePluginControlScript(t, dir, "isolated_state", `
var topLevelRuns = 1;
var calls = 0;
exports.onAction = function () {
  calls++;
  kv.set('state', {top_level_runs: topLevelRuns, calls: calls});
};
`)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_state")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	for i := 0; i < 2; i++ {
		if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"top_level_runs":1`, `"calls":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("state = %s, want %s", record.DataJSON, want)
		}
	}
	clients := isolatedPluginHostClientsForTest(runtime, plugin.ID)
	if len(clients) != 1 || clients[0].PID() <= 0 {
		t.Fatalf("isolated clients = %+v, want one live process", clients)
	}
}

func TestPluginHostIsolationPreservesNumericResourceValues(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_numbers", `{
  "api_version":"v1",
  "id":"isolated_numbers",
  "name":"Isolated Numbers",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "resources":[{
    "id":"plans",
    "methods":["list","get"],
    "control_methods":["list","get","create","update","delete"],
    "runtime_update":"manual"
  }],
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["resource"]}
}`)
	writePluginControlScript(t, dir, "isolated_numbers", `
exports.onAction = function () {
  var next = {index: 5, ratio: 1.5, nested: {count: 2}};
  var current = resources.get('plans', 'default');
  var data = current && current.data;
  if (!data || typeof data.index !== 'number' || data.index !== next.index ||
      typeof data.ratio !== 'number' || data.ratio !== next.ratio ||
      !data.nested || typeof data.nested.count !== 'number' || data.nested.count !== next.nested.count) {
    resources.set('plans', 'default', next, true, true);
  }
};
`)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_numbers")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	for i := 0; i < 2; i++ {
		if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, plugin.ID, "plans", "default")
	if err != nil {
		t.Fatalf("GetPluginRecord(plans/default) error = %v", err)
	}
	if record.Revision != 1 {
		t.Fatalf("plans/default revision = %d, want 1 after unchanged isolated reconcile", record.Revision)
	}
}

func TestPluginHostIsolationPreservesNumericByteArrays(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_crypto", `{
  "api_version":"v1",
  "id":"isolated_crypto",
  "name":"Isolated Crypto",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["crypto","kv"]}
}`)
	writePluginControlScript(t, dir, "isolated_crypto", `
exports.onAction = function () {
  var digest = crypto.md5([0, 7, 127, 255], 'password', {hex:'01020304'});
  kv.set('result', {digest:digest, length:digest.length});
};
`)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_crypto")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("isolated crypto action: %v", err)
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "result")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.DataJSON, `"length":32`) {
		t.Fatalf("isolated crypto result = %s", record.DataJSON)
	}
}

func TestPluginHostIsolationLoadsRelativeControlModulesInMainAndWorker(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_modules", `{
  "api_version":"v1",
  "id":"isolated_modules",
  "name":"Isolated Modules",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv","worker"]}
}`)
	writePluginControlScript(t, dir, "isolated_modules", `
var counter = require('./lib/counter');
exports.onAction = function () {
  var main = counter.next();
  var child = worker.call('jobs', 'onWork', {});
  kv.set('state', {main: main, worker: child.value});
};
exports.onWork = function () { return {value: counter.next()}; };
`)
	moduleDir := filepath.Join(dir, "isolated_modules", "lib")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "counter.js"), []byte(`
var value = 0;
module.exports.next = function () { value++; return value; };
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_modules")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	for i := 0; i < 2; i++ {
		if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"main":2`, `"worker":2`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("module state = %s, want %s", record.DataJSON, want)
		}
	}
	if clients := isolatedPluginHostClientsForTest(runtime, plugin.ID); len(clients) != 2 {
		t.Fatalf("isolated module clients = %d, want main and worker", len(clients))
	}
}

func TestPluginHostIsolationBrokersTypedServiceDiscoveryAndCall(t *testing.T) {
	dir := t.TempDir()
	writePluginServiceProviderForTest(t, dir, "wan_provider", "1.2.0")
	writePluginServiceConsumerForTest(t, dir, "wan_provider", true)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginRuntimeSnapshot(&catalog, runtime.Reconcile(catalog))
	consumer := pluginByIDForTest(t, catalog, "service_consumer")
	result, err := runtime.QueryPluginAction(consumer, pluginActionByIDForTest(t, consumer, "run"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("isolated typed service call: %v", err)
	}
	raw, _ := json.Marshal(result)
	for _, want := range []string{`"plugin_id":"wan_provider"`, `"service":"wan.adapter"`, `"value":"alpha"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("isolated typed service result = %s, missing %s", raw, want)
		}
	}
	if clients := isolatedPluginHostClientsForTest(runtime, "service_consumer"); len(clients) != 1 || clients[0].PID() <= 0 {
		t.Fatalf("isolated service consumer clients = %+v, want one live process", clients)
	}
}

func TestPluginHostIsolationBrokersBoundedEBPFReads(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_ebpf", `{
  "api_version":"v1",
  "id":"isolated_ebpf",
  "name":"Isolated eBPF",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"read","runtime_update":"runtime_query"}],
  "control":{"main":"control.js","permissions":["ebpf.map_read"]}
}`)
	writePluginControlScript(t, dir, "isolated_ebpf", `
exports.onAction = function () {
  return {
    scan: ebpf.mapScan('stats', {limit:1, max_bytes:32}),
    ring: ebpf.ringRead('events', {max_records:1, max_bytes:32, timeout_ms:25})
  };
};
`)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_ebpf")
	controller := &pluginControlMapControllerTest{
		scanResult: pluginEBPFMapScanResult{Entries: []pluginEBPFMapScanEntry{{Key: []byte{1}, Value: []byte{2}}}, Done: true},
		ringResult: pluginEBPFRingReadResult{Records: []pluginEBPFRingRecord{{RawSample: []byte{3, 4}}}, Bytes: 2},
	}
	runtime := newPluginControlRuntime(openTestDB(t), cfg, controller).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	raw, _ := json.Marshal(result)
	for _, want := range []string{`"key":"01"`, `"value":"02"`, `"data":"0304"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("isolated result = %s, want %s", raw, want)
		}
	}
	if len(controller.calls) != 2 || !strings.HasPrefix(controller.calls[0], "scan:isolated_ebpf:") || !strings.HasPrefix(controller.calls[1], "ring:isolated_ebpf:") {
		t.Fatalf("broker calls = %+v, want scan/ring", controller.calls)
	}
}

func TestPluginHostIsolationBrokersEBPFStateMigrationProgress(t *testing.T) {
	dir := t.TempDir()
	writePluginStateMigrationTestPlugin(t, dir, "isolated_state_migrate", `
exports.onEBPFStateMigrate = function (ctx) {
  var migration = ctx.ebpf_migration;
  var page = ebpf.mapScan(migration.source_map, {cursor:migration.cursor, limit:1});
  if (page.entries.length) {
    ebpf.mapTransaction({operations:page.entries.map(function (entry) {
      return {op:"put", map:migration.target_map, key:entry.key, value:entry.value + "00"};
    })});
  }
  return {done:page.done, cursor:page.cursor, processed:page.entries.length};
};`)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := newPluginStateMigrationMapControllerTest()
	controller.put("", "sessions_v1", []byte{1}, []byte{10})
	controller.put("", "sessions_v1", []byte{2}, []byte{11})
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "isolated_state_migrate")
	applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())
	completed, failures := runtime.ApplyPluginEBPFStateMigrations(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"isolated_state_migrate": {Mode: pluginRuntimeModeDataplane, Attached: true},
	}}, []PluginEBPFStateMigration{testPluginEBPFStateMigration("isolated_state_migrate")})
	if len(failures) != 0 || len(completed) != 1 {
		t.Fatalf("isolated migration completed=%+v failures=%+v", completed, failures)
	}
	if controller.scanCalls != 2 || controller.transactionCalls != 2 {
		t.Fatalf("isolated migration calls scan=%d transaction=%d, want 2/2", controller.scanCalls, controller.transactionCalls)
	}
}

func TestPluginHostIsolationRestrictsEBPFStateMigrationCapabilities(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_state_migrate_scope", `{
  "api_version":"v1","id":"isolated_state_migrate_scope","name":"Isolated Migration Scope","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["ebpf.map_read","ebpf.map_write","kv"]}
}`)
	writePluginControlScript(t, dir, "isolated_state_migrate_scope", `
exports.onReconcile = function () {};
exports.onEBPFStateMigrate = function () {
  kv.set("forbidden", {value:true});
  return {done:true, cursor:"", processed:0};
};`)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, newPluginStateMigrationMapControllerTest()).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "isolated_state_migrate_scope")
	applyPluginRuntimeSnapshot(&catalog, runtime.Snapshot())
	_, failures := runtime.ApplyPluginEBPFStateMigrations(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"isolated_state_migrate_scope": {Mode: pluginRuntimeModeDataplane, Attached: true},
	}}, []PluginEBPFStateMigration{testPluginEBPFStateMigration("isolated_state_migrate_scope")})
	err := failures["isolated_state_migrate_scope"]
	if err == nil || !strings.Contains(err.Error(), "permission kv is unavailable during eBPF state migration") {
		t.Fatalf("isolated migration capability error = %v", err)
	}
}

func TestPluginHostIsolationBrokersNamespaceAndTunTapWithoutFDs(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_tuntap", `{
  "api_version":"v1",
  "id":"isolated_tuntap",
  "name":"Isolated TUN/TAP",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_query"}],
  "control":{"main":"control.js","permissions":["net.namespace","net.tuntap"],
    "namespace_access":["veer-*"],
    "net_access":[{"interfaces":["tun*"],"operations":["tuntap"]}]}
}`)
	writePluginControlScript(t, dir, "isolated_tuntap", `
exports.onAction = function () {
  var ns = net.namespace.ensure({name:'veer-isolated'});
  var device = net.tuntap.ensure({name:'tun0', namespace:'veer-isolated', mode:'tun'});
  var packet = net.tuntap.read({name:'tun0', namespace:'veer-isolated', timeout_ms:10});
  return {namespace:ns, device:device, packet:packet};
};
`)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_tuntap")
	provider := newPluginControlNetworkProviderTest()
	runtime := newPluginControlRuntime(openTestDB(t), cfg, nil).(*gojaPluginControlRuntime)
	runtime.netAdmin = provider
	t.Cleanup(func() { _ = runtime.Close() })
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	raw, _ := json.Marshal(result)
	for _, want := range []string{`"name":"veer-isolated"`, `"name":"tun0"`, `"data":"45000014"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("isolated provider result = %s, want %s", raw, want)
		}
	}
}

func TestPluginHostIsolationUsesPersistentWorkerProcess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_worker", `{
  "api_version":"v1",
  "id":"isolated_worker",
  "name":"Isolated Worker",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv","worker"]}
}`)
	writePluginControlScript(t, dir, "isolated_worker", `
var workerCalls = 0;
exports.onAction = function () {
  kv.set('worker_state', worker.call('stateful', 'onWorkerCall', {}));
};
exports.onWorkerCall = function () {
  workerCalls++;
  return {calls: workerCalls};
};
`)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_worker")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	for i := 0; i < 2; i++ {
		if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatalf("ApplyPluginAction(%d) error = %v", i, err)
		}
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "worker_state")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.DataJSON, `"calls":2`) {
		t.Fatalf("worker state = %s, want calls=2", record.DataJSON)
	}
	clients := isolatedPluginHostClientsForTest(runtime, plugin.ID)
	if len(clients) != 2 || clients[0].PID() == clients[1].PID() {
		t.Fatalf("isolated clients = %+v, want separate control and worker processes", clients)
	}
}

func TestPluginHostIsolationSupportsNestedResourceApply(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_nested", `{
  "api_version":"v1",
  "id":"isolated_nested",
  "name":"Isolated Nested",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "resources":[{
    "id":"settings",
    "methods":["list","get","create","update"],
    "runtime_update":"runtime_apply"
  }],
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv","resource"]}
}`)
	writePluginControlScript(t, dir, "isolated_nested", `
var applies = 0;
exports.onAction = function () {
  resources.set('settings', 'main', {name: 'nested'}, true, true);
};
exports.onResourceApply = function (ctx) {
  applies++;
  kv.set('nested_state', {resource: ctx.resource.id, count: ctx.records.length, applies: applies});
};
`)

	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_nested")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "nested_state")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"resource":"settings"`, `"count":1`, `"applies":1`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("nested state = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginHostIsolationTerminatesInfiniteLoop(t *testing.T) {
	cfg := isolatedPluginsTestConfig(&Config{})
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "isolated_loop", Control: &PluginControl{Main: "control.js"},
	}}
	client, err := startPluginHostClient(cfg, plugin, "control", "", `exports.onAction = function () { for (;;) {} };`, nil)
	if err != nil {
		t.Fatalf("startPluginHostClient() error = %v", err)
	}
	defer client.Close()
	started := time.Now()
	_, err = client.runEvent(pluginHostEventRequest{Handler: "onAction", TimeoutMS: 200, Context: map[string]any{}}, nil, time.Now().Add(time.Second), false)
	if !errors.Is(err, errPluginHostProcessExited) {
		t.Fatalf("runEvent() error = %v, want process exit", err)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("infinite loop termination took %s", elapsed)
	}
}

func TestPluginHostIsolationContainsMemoryExhaustion(t *testing.T) {
	if os.Getenv("VEER_PLUGIN_OOM_TEST") != "1" {
		t.Skip("set VEER_PLUGIN_OOM_TEST=1 to run the isolated OOM check")
	}
	cfg := isolatedPluginsTestConfig(&Config{})
	plugin := LoadedPlugin{PluginManifest: PluginManifest{
		ID: "isolated_oom", Control: &PluginControl{Main: "control.js"},
	}}
	source := `exports.onAction = function () {
  var blocks = [];
  for (;;) blocks.push(new Uint8Array(4 * 1024 * 1024));
};`
	client, err := startPluginHostClient(cfg, plugin, "control", "", source, nil)
	if err != nil {
		t.Fatalf("startPluginHostClient() error = %v", err)
	}
	defer client.Close()
	_, err = client.runEvent(
		pluginHostEventRequest{Handler: "onAction", TimeoutMS: 12000, Context: map[string]any{}},
		nil,
		time.Now().Add(15*time.Second),
		false,
	)
	if !errors.Is(err, errPluginHostProcessExited) {
		t.Fatalf("memory exhaustion error = %v, want isolated process exit", err)
	}
}

func TestPluginHostIsolationDiscardsTimerJournalOnFatalExit(t *testing.T) {
	db := openTestDB(t)
	cfg := isolatedPluginsTestConfig(&Config{})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "timer_guard", Control: &PluginControl{Main: "control.js"}}}
	runtime.mu.Lock()
	if runtime.plugins == nil {
		runtime.plugins = make(map[string]LoadedPlugin)
	}
	runtime.plugins[plugin.ID] = plugin
	runtime.mu.Unlock()
	host := &pluginControlHost{vm: goja.New(), runtime: runtime, plugin: plugin}
	_, _, _, err := host.runRemoteEvent(pluginControlEvent{Kind: "action", Action: &PluginAction{ID: "apply"}}, false, func(pluginHostEventRequest) (pluginHostEventResponse, error) {
		host.timerOps = append(host.timerOps, pluginControlTimerOperation{
			op:   pluginControlTimerOperationSet,
			spec: pluginControlTimerSpec{Name: "must_not_commit", Kind: pluginControlTimerKindTimeout, Delay: time.Hour, Payload: json.RawMessage(`{}`)},
		})
		return pluginHostEventResponse{Handled: true}, pluginHostProcessError(errors.New("injected fatal exit"))
	})
	if !errors.Is(err, errPluginHostProcessExited) {
		t.Fatalf("runRemoteEvent() error = %v, want process exit", err)
	}
	if timers := runtime.pluginTimerList(plugin.ID); len(timers) != 0 {
		t.Fatalf("timers after fatal exit = %+v, want none", timers)
	}
}

func TestPluginHostIsolationBacksOffAndRestartsAfterCrash(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_restart", `{
  "api_version":"v1",
  "id":"isolated_restart",
  "name":"Isolated Restart",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv"]}
}`)
	writePluginControlScript(t, dir, "isolated_restart", `
var calls = 0;
exports.onAction = function () {
  calls++;
  kv.set('state', {calls: calls});
};
`)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "isolated_restart")
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	apply := func() error {
		return runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	}
	if err := apply(); err != nil {
		t.Fatalf("initial action error = %v", err)
	}
	clients := isolatedPluginHostClientsForTest(runtime, plugin.ID)
	if len(clients) != 1 {
		t.Fatalf("initial clients = %d, want 1", len(clients))
	}
	oldClient := clients[0]
	oldPID := oldClient.PID()
	if err := oldClient.command.Process.Kill(); err != nil {
		t.Fatalf("kill plugin host: %v", err)
	}
	select {
	case <-oldClient.done:
	case <-time.After(3 * time.Second):
		t.Fatal("plugin host did not exit after kill")
	}
	if err := apply(); !errors.Is(err, errPluginHostProcessExited) {
		t.Fatalf("first action after crash error = %v, want process exit", err)
	}
	if err := apply(); err == nil || !strings.Contains(err.Error(), "restart backoff active") {
		t.Fatalf("backoff action error = %v", err)
	}
	time.Sleep(pluginHostRestartMinBackoff + 100*time.Millisecond)
	if err := apply(); err != nil {
		t.Fatalf("action after backoff error = %v", err)
	}
	clients = isolatedPluginHostClientsForTest(runtime, plugin.ID)
	if len(clients) != 1 || clients[0].PID() == oldPID {
		t.Fatalf("restarted clients = %+v, old pid = %d", clients, oldPID)
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.DataJSON, `"calls":1`) {
		t.Fatalf("state after restart = %s, want non-replayed fresh call", record.DataJSON)
	}
	isolation := runtime.pluginHostIsolationSnapshot(plugin.ID)
	if !isolation.Enabled || isolation.RestartCount != 1 || isolation.ProcessCount != 1 {
		t.Fatalf("isolation state = %+v", isolation)
	}
}

func TestPluginHostIsolationTransactionalUpgradeRestoresState(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_upgrade", `{
  "api_version":"v1",
  "id":"isolated_upgrade",
  "name":"Isolated Upgrade",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "actions":[{"id":"apply","runtime_update":"runtime_apply"}],
  "control":{"main":"control.js","permissions":["kv"]}
}`)
	writeVersion := func(version int) {
		t.Helper()
		writePluginControlScript(t, dir, "isolated_upgrade", fmt.Sprintf(`
var build = %d;
var calls = 0;
exports.onAction = function () { calls++; kv.set('state', {build: build, calls: calls}); };
exports.onUpgradeSnapshot = function () { return {calls: calls}; };
exports.onUpgradeRestore = function (ctx) { calls = (ctx.upgrade.state || {}).calls || 0; };
`, version))
	}
	writeVersion(1)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginRuntimeSnapshot(&catalog, runtime.Reconcile(catalog))
	plugin := pluginByIDForTest(t, catalog, "isolated_upgrade")
	action := pluginActionByIDForTest(t, plugin, "apply")
	for i := 0; i < 2; i++ {
		if err := runtime.ApplyPluginAction(plugin, action, json.RawMessage(`{}`)); err != nil {
			t.Fatalf("v1 action %d error = %v", i, err)
		}
	}
	writeVersion(2)
	catalog = loadPluginCatalogWithState(cfg, db)
	snapshot := runtime.Reconcile(catalog)
	if state, ok := snapshot.stateFor(plugin.ID); !ok || state.Error != "" {
		t.Fatalf("upgrade state = %+v, ok=%t", state, ok)
	}
	applyPluginRuntimeSnapshot(&catalog, snapshot)
	plugin = pluginByIDForTest(t, catalog, plugin.ID)
	action = pluginActionByIDForTest(t, plugin, "apply")
	if err := runtime.ApplyPluginAction(plugin, action, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("v2 action error = %v", err)
	}
	record, err := store.GetPluginRecord(db, plugin.ID, pluginControlKVResourceID, "state")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"build":2`, `"calls":3`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("upgraded state = %s, want %s", record.DataJSON, want)
		}
	}
}

func TestPluginPackageStageValidatesCandidateInIsolatedHost(t *testing.T) {
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: t.TempDir()})
	manager, err := newPluginPackageManager(cfg, openTestDB(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID:          "isolated_package",
		Version:     "1.0.0",
		Permissions: []string{"plugin.register"},
		Control: `
plugin.action({id: 'apply', runtime_update: 'none'});
exports.onReconcile = function () {};
`,
	})
	stage, err := manager.Stage(bytes.NewReader(archive), "", "")
	if err != nil {
		t.Fatalf("Stage() error = %v", err)
	}
	if stage.PluginID != "isolated_package" || stage.Version != "1.0.0" {
		t.Fatalf("stage = %+v", stage)
	}
}

func isolatedPluginHostClientsForTest(runtime *gojaPluginControlRuntime, pluginID string) []*pluginHostClient {
	runtime.mu.Lock()
	vms := make([]*pluginControlVM, 0)
	for _, vm := range runtime.controlVMs {
		if vm.pluginID == pluginID {
			vms = append(vms, vm)
		}
	}
	for _, vm := range runtime.pluginWorkers {
		if vm.pluginID == pluginID {
			vms = append(vms, vm)
		}
	}
	runtime.mu.Unlock()
	clients := make([]*pluginHostClient, 0, len(vms))
	for _, vm := range vms {
		if client := vm.currentPluginHost(); client != nil {
			clients = append(clients, client)
		}
	}
	return clients
}
