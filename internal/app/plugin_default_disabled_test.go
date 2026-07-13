package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPluginsDefaultDisabledDoNotScanAndCoreAPIStaysAvailable(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "disabled_plugin", `{
  "api_version": "v1",
  "id": "disabled_plugin",
  "name": "Disabled Plugin",
  "version": "0.1.0",
  "kind": "control",
  "control": {"main": "control.js", "permissions": ["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "disabled_plugin", `throw new Error("must not execute");`)

	cfg := &Config{WebToken: "test-token", PluginsDir: dir}
	if cfg.PluginsEnabled() {
		t.Fatal("PluginsEnabled() = true, want explicit opt-in")
	}
	catalog := loadPluginCatalogWithControlRegistration(cfg)
	if catalog.ExternalPluginsEnabled {
		t.Fatal("ExternalPluginsEnabled = true, want false")
	}
	if len(catalog.Plugins) != 1 || !catalog.Plugins[0].Builtin {
		t.Fatalf("catalog plugins = %+v, want builtin Veer Core only", catalog.Plugins)
	}
	nilCatalog := loadPluginCatalog(nil)
	if nilCatalog.ExternalPluginsEnabled || len(nilCatalog.Plugins) != 1 || !nilCatalog.Plugins[0].Builtin {
		t.Fatalf("nil-config catalog = %+v, want disabled external plugins and builtin core", nilCatalog)
	}
	fingerprint, err := buildPluginCatalogFingerprint(cfg)
	if err != nil {
		t.Fatalf("buildPluginCatalogFingerprint() error = %v", err)
	}
	if fingerprint != "plugins-disabled" {
		t.Fatalf("plugin fingerprint = %q, want plugins-disabled", fingerprint)
	}
	snapshotDir, snapshotFingerprint, err := snapshotPluginCatalogDirectory(cfg)
	if err != nil {
		t.Fatalf("snapshotPluginCatalogDirectory() error = %v", err)
	}
	if snapshotDir != "" || snapshotFingerprint != "plugins-disabled" {
		t.Fatalf("disabled plugin snapshot = dir %q fingerprint %q, want no directory and plugins-disabled", snapshotDir, snapshotFingerprint)
	}
	if pluginForwardRulePlansEnabled(cfg) || pluginEgressNATPlansEnabled(cfg) || pluginDHCPv4PlansEnabled(cfg) || pluginIPv6AssignmentPlansEnabled(cfg) {
		t.Fatal("plugin plans enabled without explicit opt-in")
	}
	if pluginForwardRulePlansEnabled(nil) || pluginEgressNATPlansEnabled(nil) || pluginDHCPv4PlansEnabled(nil) || pluginIPv6AssignmentPlansEnabled(nil) {
		t.Fatal("plugin plans enabled for nil config")
	}

	db := openTestDB(t)
	pm := &ProcessManager{db: db, cfg: cfg}
	handler := buildAPIHandler(cfg, db, pm)
	for _, path := range []string{
		"/api/plugins",
		"/api/rules",
		"/api/sites",
		"/api/ranges",
		"/api/egress-nats",
		"/api/managed-networks",
		"/api/ipv6-assignments",
		"/api/tags",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d: %s", path, rec.Code, http.StatusOK, rec.Body.String())
		}
		if path == "/api/plugins" {
			var response struct {
				ExternalPluginsEnabled bool `json:"external_plugins_enabled"`
				Plugins                []struct {
					ID      string `json:"id"`
					Builtin bool   `json:"builtin"`
				} `json:"plugins"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
				t.Fatalf("decode plugin catalog: %v", err)
			}
			if response.ExternalPluginsEnabled || len(response.Plugins) != 1 || !response.Plugins[0].Builtin {
				t.Fatalf("plugin API catalog = %+v, want disabled external plugins and builtin core", response)
			}
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/plugins/disabled_plugin/assets/index.html", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled plugin asset status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	for _, test := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/plugins/disabled_plugin/state"},
		{method: http.MethodGet, path: "/api/plugins/disabled_plugin/resources/settings"},
		{method: http.MethodPost, path: "/api/plugins/disabled_plugin/actions/apply"},
	} {
		req := httptest.NewRequest(test.method, test.path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s %s status = %d, want %d", test.method, test.path, rec.Code, http.StatusNotFound)
		}
	}
}

func TestPluginsCanBeEnabledExplicitly(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "enabled_plugin", `{
  "api_version": "v1",
  "id": "enabled_plugin",
  "name": "Enabled Plugin",
  "version": "0.1.0"
}`)

	catalog := loadPluginCatalog(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	if !catalog.ExternalPluginsEnabled {
		t.Fatal("ExternalPluginsEnabled = false, want true after explicit opt-in")
	}
	if len(catalog.Plugins) != 2 || catalog.Plugins[1].ID != "enabled_plugin" {
		t.Fatalf("catalog plugins = %+v, want builtin plus enabled_plugin", catalog.Plugins)
	}
}
