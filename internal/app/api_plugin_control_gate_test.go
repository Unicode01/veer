package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginResourceAPIAllowsPrivilegedLabRuntimeApplyByDefault(t *testing.T) {
	dir := t.TempDir()
	writePrivilegedLabRuntimePluginForAPITest(t, dir)

	db := openTestDB(t)
	applyRuntime := &pluginRuntimeApplyTestRuntime{}
	cfg := pluginsEnabledTestConfig(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir})

	pm := &ProcessManager{cfg: cfg, kernelRuntime: applyRuntime}
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/priv_lab/resources/bindings", strings.NewReader(`{"key":"alpha","data":{"name":"alpha"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST privileged lab resource status = %d, want %d: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	if len(applyRuntime.resourceCalls) != 1 {
		t.Fatalf("resource apply calls = %d, want 1", len(applyRuntime.resourceCalls))
	}
	if !pluginRuntimeApplyResourceCallHasKey(applyRuntime.resourceCalls[0], "alpha") {
		t.Fatalf("resource apply records = %+v, want alpha record", applyRuntime.resourceCalls[0].records)
	}
}

func TestPluginActionAPIAllowsPrivilegedLabRuntimeApplyByDefault(t *testing.T) {
	dir := t.TempDir()
	writePrivilegedLabRuntimePluginForAPITest(t, dir)

	db := openTestDB(t)
	applyRuntime := &pluginRuntimeApplyTestRuntime{}
	cfg := pluginsEnabledTestConfig(&Config{
		WebBind:    "127.0.0.1",
		WebPort:    8080,
		WebToken:   "test-token",
		PluginsDir: dir})

	pm := &ProcessManager{cfg: cfg, kernelRuntime: applyRuntime}
	handler := buildAPIHandler(cfg, db, pm)

	req := httptest.NewRequest(http.MethodPost, "/api/plugins/priv_lab/actions/apply", strings.NewReader(`{"payload":{"source":"test"}}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST privileged lab action status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if len(applyRuntime.actionCalls) != 1 || !strings.Contains(string(applyRuntime.actionCalls[0].payload), "test") {
		t.Fatalf("action apply calls = %+v, want one allowed payload", applyRuntime.actionCalls)
	}
}

func TestPluginRuntimeUpdateAcceptsLabEgressNATPlansWithoutProcessManager(t *testing.T) {
	db := openTestDB(t)
	plugin := LoadedPlugin{
		PluginManifest: PluginManifest{
			ID:        "lab_router",
			Stability: pluginStabilityLab,
		},
		Resources: []PluginResource{{
			ID:            pluginEgressNATPlansResourceID,
			RuntimeUpdate: "manual",
		}},
		Status: pluginStatusActive,
	}
	resource := plugin.Resources[0]
	if err := applyPluginResourceRuntimeUpdate(db, nil, plugin, resource); err != nil {
		t.Fatalf("applyPluginResourceRuntimeUpdate(lab egress plan) error = %v", err)
	}
	action := PluginAction{ID: "noop", RuntimeUpdate: "none"}
	if err := applyPluginActionRuntimeUpdate(db, nil, plugin, action, json.RawMessage(`{}`)); err != nil {
		t.Fatalf("applyPluginActionRuntimeUpdate(lab egress plan) error = %v", err)
	}
}

func TestPluginCatalogActiveEgressNATPlanAllowsLabByDefault(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{
		{
			PluginManifest: PluginManifest{
				ID:        "lab_router",
				Stability: pluginStabilityLab,
			},
			Resources: []PluginResource{{ID: pluginEgressNATPlansResourceID}},
			Status:    pluginStatusActive,
		},
	}}
	if !pluginCatalogHasActiveEgressNATPlansResource(catalog, pluginsEnabledTestConfig(&Config{})) {
		t.Fatal("pluginCatalogHasActiveEgressNATPlansResource(default lab) = false, want true")
	}

	catalog.Plugins[0].Stability = pluginStabilityStable
	if !pluginCatalogHasActiveEgressNATPlansResource(catalog, pluginsEnabledTestConfig(&Config{})) {
		t.Fatal("pluginCatalogHasActiveEgressNATPlansResource(stable) = false, want true")
	}

	catalog.Plugins[0].Status = pluginStatusError
	if pluginCatalogHasActiveEgressNATPlansResource(catalog, pluginsEnabledTestConfig(&Config{})) {
		t.Fatal("pluginCatalogHasActiveEgressNATPlansResource(inactive stable) = true, want false")
	}
}

func TestPluginReconcileHandlesLabEgressNATPlanByDefault(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "lab_router", `{
  "api_version": "v1",
  "id": "lab_router",
  "name": "Lab Router",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "resources": [{
    "id": "egress_nat_plans",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "manual"
  }]
}`)
	pm := &ProcessManager{
		db:  openTestDB(t),
		cfg: pluginsEnabledTestConfig(&Config{PluginsDir: dir}),
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("reconcilePluginsForRuntime() panicked for lab plan: %v", recovered)
		}
	}()
	pm.reconcilePluginsForRuntime()
}

func writePrivilegedLabRuntimePluginForAPITest(t *testing.T, dir string) {
	t.Helper()

	writeTestPlugin(t, dir, "priv_lab", `{
  "api_version": "v1",
  "id": "priv_lab",
  "name": "Privileged Lab",
  "version": "0.1.0",
  "kind": "control",
  "stability": "lab",
  "resources": [{
    "id": "bindings",
    "methods": ["list", "get", "create", "update", "delete"],
    "runtime_update": "runtime_apply",
    "max_records": 8
  }],
  "actions": [{
    "id": "apply",
    "runtime_update": "runtime_apply"
  }],
  "control": {
    "main": "control.js",
    "permissions": ["net.l2"],
    "net_access": [{
      "interfaces": ["eth*"],
      "operations": ["l2"]
    }]
  }
}`)
	writePluginControlScript(t, dir, "priv_lab", `exports.onAction = function () {};`)
}

func pluginRuntimeApplyResourceCallHasKey(call pluginRuntimeApplyResourceCall, key string) bool {
	for _, record := range call.records {
		if record.Key == key {
			return true
		}
	}
	return false
}
