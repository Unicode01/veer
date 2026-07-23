package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

func TestPluginOperationsLifecyclePersistsEncryptedCASState(t *testing.T) {
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := operationTestPlugin("operation_lifecycle")
	host := operationTestHost(t, runtime, plugin, false)

	value, err := host.vm.RunString(`
var op = operations.begin({key: 'router_default', kind: 'router.apply', input: {password: 'secret-value'}, state: {step: 0}});
op = operations.claim(op.id, op.revision);
op = operations.checkpoint(op.id, op.revision, {phase: 'wan_ready', state: {step: 1}});
op = operations.retry(op.id, op.revision, {phase: 'wan_ready', state: {step: 1}, error: 'temporary failure', delay_ms: 0});
op = operations.claim(op.id, op.revision);
op = operations.complete(op.id, op.revision, {status: 'applied'});
op;
`)
	if err != nil {
		t.Fatal(err)
	}
	result := value.Export().(map[string]any)
	if result["status"] != "completed" || result["phase"] != "wan_ready" || fmt.Sprint(result["attempts"]) != "2" {
		t.Fatalf("completed operation = %+v", result)
	}
	if fmt.Sprint(result["revision"]) != "6" {
		t.Fatalf("operation revision = %v, want 6", result["revision"])
	}

	raw, err := store.PluginOperationByKey(db, plugin.ID, "router_default")
	if err != nil || raw == nil {
		t.Fatalf("stored operation = %+v, err=%v", raw, err)
	}
	for label, value := range map[string]string{
		"input": raw.InputJSON, "state": raw.StateJSON, "result": raw.ResultJSON, "error": raw.ErrorJSON,
	} {
		if strings.Contains(value, "secret-value") || !strings.Contains(value, pluginSecretEnvelopeField) {
			t.Fatalf("stored %s is not an encrypted envelope: %s", label, value)
		}
	}

	reloaded := operationTestHost(t, runtime, plugin, false)
	loaded, err := reloaded.vm.RunString(`operations.getByKey('router_default')`)
	if err != nil {
		t.Fatal(err)
	}
	loadedResult := loaded.Export().(map[string]any)
	input := loadedResult["input"].(map[string]any)
	if input["password"] != "secret-value" || loadedResult["status"] != "completed" {
		t.Fatalf("reloaded operation = %+v", loadedResult)
	}
	if _, err := reloaded.vm.RunString(`operations.claim(operations.getByKey('router_default').id, 1)`); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale claim error = %v", err)
	}

	restarted, err := reloaded.vm.RunString(`operations.begin({key:'router_default', kind:'router.apply', input:{password:'next'}, state:{step:0}, restart:true})`)
	if err != nil {
		t.Fatal(err)
	}
	restartedResult := restarted.Export().(map[string]any)
	if restartedResult["status"] != "pending" || fmt.Sprint(restartedResult["attempts"]) != "0" {
		t.Fatalf("restarted operation = %+v", restartedResult)
	}
}

func TestPluginOperationsResumeFilteringAndTerminalRemoval(t *testing.T) {
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	host := operationTestHost(t, runtime, operationTestPlugin("operation_resume"), false)

	if _, err := host.vm.RunString(`
var pending = operations.begin({key:'pending', kind:'test.run'});
var running = operations.begin({key:'running', kind:'test.run'});
running = operations.claim(running.id, running.revision);
var delayed = operations.begin({key:'delayed', kind:'test.run'});
delayed = operations.claim(delayed.id, delayed.revision);
delayed = operations.retry(delayed.id, delayed.revision, {error:'later', delay_ms:60000});
var complete = operations.begin({key:'complete', kind:'test.run'});
complete = operations.claim(complete.id, complete.revision);
complete = operations.complete(complete.id, complete.revision, {ok:true});
`); err != nil {
		t.Fatal(err)
	}
	value, err := host.vm.RunString(`operations.list({kind:'test.run', resumable:true, limit:10}).map(function (item) { return item.key; }).join(',')`)
	if err != nil {
		t.Fatal(err)
	}
	if got := value.String(); got != "pending,running" {
		t.Fatalf("resumable operations = %q", got)
	}
	if _, err := host.vm.RunString(`operations.remove(operations.getByKey('running').id)`); err == nil || !strings.Contains(err.Error(), "nonterminal") {
		t.Fatalf("nonterminal remove error = %v", err)
	}
	if _, err := host.vm.RunString(`operations.remove(operations.getByKey('complete').id)`); err != nil {
		t.Fatal(err)
	}
	if value, err := host.vm.RunString(`operations.getByKey('complete')`); err != nil || !goja.IsNull(value) {
		t.Fatalf("removed operation = %v, err=%v", value, err)
	}
}

func TestPluginOperationsRequirePermissionMainVMAndBoundedPayload(t *testing.T) {
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })

	noPermission := operationTestPlugin("operation_denied")
	noPermission.Control.Permissions = nil
	host := operationTestHost(t, runtime, noPermission, false)
	if _, err := host.vm.RunString(`operations.list()`); err == nil || !strings.Contains(err.Error(), "permission operation is required") {
		t.Fatalf("permission error = %v", err)
	}

	worker := operationTestHost(t, runtime, operationTestPlugin("operation_worker"), true)
	if _, err := worker.vm.RunString(`operations.list()`); err == nil || !strings.Contains(err.Error(), "main VM") {
		t.Fatalf("worker operation error = %v", err)
	}

	bounded := operationTestHost(t, runtime, operationTestPlugin("operation_bounded"), false)
	bounded.vm.Set("oversized", strings.Repeat("x", pluginOperationMaxFieldBytes+1))
	if _, err := bounded.vm.RunString(`operations.begin({key:'large', kind:'test.run', input:oversized})`); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized operation error = %v", err)
	}
}

func TestPluginOperationsRespectCombinedDatabaseQuotas(t *testing.T) {
	for _, test := range []struct {
		name          string
		recordPlugin  string
		pluginLimitMB int
		globalLimitMB int
		wantError     string
	}{
		{name: "plugin", recordPlugin: "operation_quota", pluginLimitMB: 1, globalLimitMB: 2, wantError: "plugin database quota exceeded"},
		{name: "global", recordPlugin: "other_plugin", pluginLimitMB: 1, globalLimitMB: 1, wantError: "global plugin database quota exceeded"},
	} {
		t.Run(test.name, func(t *testing.T) {
			db := openTestDB(t)
			largeRecord := store.PluginRecord{
				PluginID: test.recordPlugin, ResourceID: "settings", RecordKey: "large",
				DataJSON: `{"padding":"` + strings.Repeat("x", 900<<10) + `"}`, Enabled: true,
			}
			if _, err := store.AddPluginRecord(db, &largeRecord); err != nil {
				t.Fatal(err)
			}
			cfg := pluginsEnabledTestConfig(&Config{PluginsResourceLimits: PluginResourceLimitConfig{
				PluginDatabaseMB: test.pluginLimitMB, GlobalDatabaseMB: test.globalLimitMB,
			}})
			runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			t.Cleanup(func() { _ = runtime.Close() })
			plugin := operationTestPlugin("operation_quota")
			host := operationTestHost(t, runtime, plugin, false)
			host.vm.Set("largeInput", strings.Repeat("y", 200<<10))
			if _, err := host.vm.RunString(`operations.begin({key:'large', kind:'test.run', input:{value:largeInput}})`); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("operations.begin quota error = %v, want %q", err, test.wantError)
			}
			if count, err := store.CountPluginOperations(db, plugin.ID); err != nil || count != 0 {
				t.Fatalf("operation count after rejected write = %d, err=%v", count, err)
			}
		})
	}
}

func TestPluginOperationSecretsRotateWithoutLosingState(t *testing.T) {
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := operationTestPlugin("operation_rotate")
	host := operationTestHost(t, runtime, plugin, false)
	if _, err := host.vm.RunString(`operations.begin({key:'rotate', kind:'test.run', input:{token:'private'}})`); err != nil {
		t.Fatal(err)
	}
	before, err := store.PluginOperationByKey(db, plugin.ID, "rotate")
	if err != nil || before == nil {
		t.Fatalf("operation before rotation = %+v, err=%v", before, err)
	}
	var envelope pluginSecretEnvelopeObject
	if err := json.Unmarshal([]byte(before.InputJSON), &envelope); err != nil || envelope.Secret == nil {
		t.Fatalf("input envelope before rotation = %s, err=%v", before.InputJSON, err)
	}
	oldKey := envelope.Secret.KeyID

	catalog := PluginCatalog{Plugins: []LoadedPlugin{plugin}}
	if _, err := runtime.secretStore.rotate(catalog); err != nil {
		t.Fatal(err)
	}
	after, err := store.PluginOperationByKey(db, plugin.ID, "rotate")
	if err != nil || after == nil {
		t.Fatalf("operation after rotation = %+v, err=%v", after, err)
	}
	if err := json.Unmarshal([]byte(after.InputJSON), &envelope); err != nil || envelope.Secret == nil || envelope.Secret.KeyID == oldKey {
		t.Fatalf("input envelope after rotation = %s, err=%v", after.InputJSON, err)
	}
	value, err := host.vm.RunString(`operations.getByKey('rotate').input.token`)
	if err != nil || value.String() != "private" {
		t.Fatalf("decrypted operation after rotation = %v, err=%v", value, err)
	}
}

func TestPluginOperationsCrossIsolatedHostBoundary(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "isolated_operations", `{
  "api_version":"v1",
  "id":"isolated_operations",
  "name":"Isolated Operations",
  "version":"1.0.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["operation"]}
}`)
	writePluginControlScript(t, dir, "isolated_operations", `
exports.onReconcile = function () {
  var op = operations.begin({key:'resume', kind:'test.run', input:{secret:'hidden'}, state:{step:0}});
  if (!op.resumable) return;
  op = operations.claim(op.id, op.revision);
  op = operations.checkpoint(op.id, op.revision, {phase:'applied', state:{step:1}});
  operations.complete(op.id, op.revision, {ok:true});
};
`)

	db := openTestDB(t)
	cfg := isolatedPluginsTestConfig(&Config{PluginsDir: dir})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	snapshot := runtime.Reconcile(loadPluginCatalogWithState(cfg, db))
	state, ok := snapshot.stateFor("isolated_operations")
	if !ok || state.Error != "" {
		t.Fatalf("isolated operation plugin state = %+v", state)
	}
	if state.Operations == nil || state.Operations.Total != 1 || state.Operations.ByStatus["completed"] != 1 || state.Operations.Bytes == 0 {
		t.Fatalf("isolated operation runtime snapshot = %+v", state.Operations)
	}
	item, err := store.PluginOperationByKey(db, "isolated_operations", "resume")
	if err != nil || item == nil || item.Status != "completed" || strings.Contains(item.InputJSON, "hidden") {
		t.Fatalf("isolated stored operation = %+v, err=%v", item, err)
	}
}

func TestPluginOperationsRejectCorruptCiphertext(t *testing.T) {
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{}), nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := operationTestPlugin("operation_corrupt")
	host := operationTestHost(t, runtime, plugin, false)
	if _, err := host.vm.RunString(`operations.begin({key:'corrupt', kind:'test.run', input:{secret:'private'}})`); err != nil {
		t.Fatal(err)
	}
	item, err := store.PluginOperationByKey(db, plugin.ID, "corrupt")
	if err != nil || item == nil {
		t.Fatalf("stored operation = %+v, err=%v", item, err)
	}
	item.InputJSON = corruptPluginOperationCiphertextForTest(t, item.InputJSON)
	if err := store.RewritePluginOperationPayloads(db, *item); err != nil {
		t.Fatal(err)
	}
	if _, err := host.vm.RunString(`operations.getByKey('corrupt')`); err == nil || !strings.Contains(err.Error(), "authenticate plugin secret") {
		t.Fatalf("corrupt operation read error = %v", err)
	}
}

func TestPluginOperationWritesDoNotRaceSecretRotation(t *testing.T) {
	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{})
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	plugin := operationTestPlugin("operation_rotation_race")

	const writers = 12
	hosts := make([]*pluginControlHost, writers)
	for i := range hosts {
		hosts[i] = operationTestHost(t, runtime, plugin, false)
	}
	start := make(chan struct{})
	errors := make(chan error, writers+1)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := hosts[index].vm.RunString(fmt.Sprintf(`operations.begin({key:'op_%d', kind:'test.run', input:{secret:'value_%d'}})`, index, index))
			if err != nil {
				errors <- err
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := runtime.secretStore.rotate(PluginCatalog{Plugins: []LoadedPlugin{plugin}}); err != nil {
			errors <- err
		}
	}()
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}

	host := operationTestHost(t, runtime, plugin, false)
	value, err := host.vm.RunString(`operations.list({limit:100}).every(function (item) { return /^value_[0-9]+$/.test(item.input.secret); })`)
	if err != nil || !value.ToBoolean() {
		t.Fatalf("operations after concurrent rotation = %v, err=%v", value, err)
	}
}

func operationTestPlugin(id string) LoadedPlugin {
	return LoadedPlugin{PluginManifest: PluginManifest{
		ID:      id,
		Control: &PluginControl{Main: "control.js", Permissions: []string{"operation"}},
	}}
}

func operationTestHost(t *testing.T, runtime *gojaPluginControlRuntime, plugin LoadedPlugin, worker bool) *pluginControlHost {
	t.Helper()
	host := &pluginControlHost{
		vm: goja.New(), db: runtime.db, cfg: runtime.cfg, runtime: runtime, plugin: plugin, workerVM: worker,
	}
	if err := host.install(); err != nil {
		t.Fatal(err)
	}
	return host
}

func corruptPluginOperationCiphertextForTest(t *testing.T, value string) string {
	t.Helper()
	var envelope pluginSecretEnvelopeObject
	if err := json.Unmarshal([]byte(value), &envelope); err != nil || envelope.Secret == nil {
		t.Fatalf("decode operation envelope = %+v, err=%v", envelope, err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Secret.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		t.Fatalf("decode operation ciphertext bytes=%d, err=%v", len(ciphertext), err)
	}
	ciphertext[len(ciphertext)-1] ^= 0x01
	envelope.Secret.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
