package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPluginGojaEBPFMapTransactionUsesController(t *testing.T) {
	dir := t.TempDir()
	writeEBPFMapTransactionPlugin(t, dir, "map_tx", `
exports.onAction = function () {
  return ebpf.mapTransaction({
    operations: [
      {op:"put", map:"config", key:"01000000", value:"1400000000000000"},
      {op:"delete", map:"config", key:"02000000"}
    ],
    commit: {map:"selector", key:"00000000", value:"01000000"}
  });
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := &pluginControlMapTransactionControllerTest{pluginControlMapControllerTest: &pluginControlMapControllerTest{}}
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "map_tx")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "map_tx")
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"committed":true`, `"operations":2`, `"status":"completed"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("transaction result = %s, missing %s", data, want)
		}
	}
	request := controller.request
	if len(request.Operations) != 2 || request.Commit == nil {
		t.Fatalf("controller request = %+v", request)
	}
	if got := fmt.Sprintf("%s:%s:%x:%x", request.Operations[0].Operation, request.Operations[0].MapName, request.Operations[0].Key, request.Operations[0].Value); got != "put:config:01000000:1400000000000000" {
		t.Fatalf("first mutation = %s", got)
	}
	if request.Commit.MapName != "selector" || fmt.Sprintf("%x", request.Commit.Value) != "01000000" {
		t.Fatalf("commit = %+v", request.Commit)
	}
}

func TestPluginGojaEBPFMapTransactionRejectsDuplicateBeforeController(t *testing.T) {
	dir := t.TempDir()
	writeEBPFMapTransactionPlugin(t, dir, "map_tx_duplicate", `
exports.onAction = function () {
  return ebpf.mapTransaction({operations: [
    {op:"put", map:"config", key:"01000000", value:"0100000000000000"},
    {op:"delete", map:"config", key:"01000000"}
  ]});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := &pluginControlMapTransactionControllerTest{pluginControlMapControllerTest: &pluginControlMapControllerTest{}}
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "map_tx_duplicate")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "map_tx_duplicate")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "duplicate map slot") {
		t.Fatalf("transaction error = %v, want duplicate slot", err)
	}
	if controller.called != 0 {
		t.Fatalf("controller calls = %d, want zero", controller.called)
	}
}

func TestPluginGojaEBPFMapTransactionPropagatesControllerFailure(t *testing.T) {
	dir := t.TempDir()
	writeEBPFMapTransactionPlugin(t, dir, "map_tx_failure", `
exports.onAction = function () {
  return ebpf.mapTransaction({operations: [
    {op:"put", map:"config", key:"01000000", value:"0100000000000000"}
  ]});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	controller := &pluginControlMapTransactionControllerTest{
		pluginControlMapControllerTest: &pluginControlMapControllerTest{},
		err:                            errors.New("injected map transaction failure"),
	}
	runtime := newPluginControlRuntime(db, cfg, controller).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "map_tx_failure")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "map_tx_failure")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "injected map transaction failure") {
		t.Fatalf("transaction error = %v", err)
	}
}

func writeEBPFMapTransactionPlugin(t *testing.T, dir, pluginID, handler string) {
	t.Helper()
	writeTestPlugin(t, dir, pluginID, `{
  "api_version":"v1","id":"`+pluginID+`","name":"Map Transaction Plugin","version":"1.0.0","kind":"control",
  "actions":[{"id":"apply","runtime_update":"runtime_query"}],
  "control":{"main":"control.js","permissions":["ebpf.map_write"]}
}`)
	writePluginControlScript(t, dir, pluginID, `exports.onReconcile = function () {};`+handler)
}

type pluginControlMapTransactionControllerTest struct {
	*pluginControlMapControllerTest
	request pluginEBPFMapTransactionRequest
	err     error
	called  int
}

func (c *pluginControlMapTransactionControllerTest) TransactionPluginMaps(_ string, request pluginEBPFMapTransactionRequest) error {
	c.called++
	c.request = clonePluginEBPFMapTransactionRequestForTest(request)
	return c.err
}

func clonePluginEBPFMapTransactionRequestForTest(request pluginEBPFMapTransactionRequest) pluginEBPFMapTransactionRequest {
	out := pluginEBPFMapTransactionRequest{Operations: make([]pluginEBPFMapMutation, len(request.Operations))}
	for index := range request.Operations {
		out.Operations[index] = request.Operations[index]
		out.Operations[index].Key = append([]byte(nil), request.Operations[index].Key...)
		out.Operations[index].Value = append([]byte(nil), request.Operations[index].Value...)
	}
	if request.Commit != nil {
		commit := *request.Commit
		commit.Key = append([]byte(nil), request.Commit.Key...)
		commit.Value = append([]byte(nil), request.Commit.Value...)
		out.Commit = &commit
	}
	return out
}
