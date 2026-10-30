package app

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginRemoteInstallPolicy(t *testing.T) {
	cfg := &Config{WebToken: "web-token", PluginAdminToken: "admin-token", PluginsDir: t.TempDir()}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	for _, path := range []string{
		"/api/plugins/reload", "/api/plugin-packages/stage", "/api/plugin-packages/apply",
		"/api/plugin-packages/apply-batch", "/api/plugin-packages/rollback", "/api/plugin-packages/uninstall",
		"/api/plugin-trust", "/api/plugin-repositories", "/api/plugin-repositories/refresh",
		"/api/plugin-repositories/stage", "/api/plugin-repositories/plan", "/api/plugin-repository-policies",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("Authorization", "Bearer web-token")
			req.Header.Set(pluginAdminTokenHeader, "admin-token")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "plugins_remote_install_enabled") {
				t.Fatalf("disabled route returned %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
	for _, path := range []string{"/api/plugins", "/api/plugin-admin/status", "/api/plugin-packages/history?plugin_id=demo", "/api/plugin-audit"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer web-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("plugin inspection %s returned %d: %s", path, rec.Code, rec.Body.String())
		}
	}
	if cfg.PluginRemoteInstallEnabled() || !cfg.PluginExecEnabled() {
		t.Fatal("default must allow local exec and disable remote installation")
	}
	cfg.PluginsRemoteInstallEnabled = true
	if cfg.PluginExecEnabled() {
		t.Fatal("remote installation must disable exec")
	}
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "policy_plugin", Version: "1.0.0"})
	req := httptest.NewRequest(http.MethodPost, "/api/plugin-packages/stage", bytes.NewReader(archive))
	req.Header.Set("Authorization", "Bearer web-token")
	req.Header.Set(pluginAdminTokenHeader, "admin-token")
	cfg.PluginsRequireSigned = new(bool)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("enabled install returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRemotePluginPackageCannotAcquireExec(t *testing.T) {
	manager := newPluginPackageManagerForTest(t)
	manager.cfg.PluginsRemoteInstallEnabled = true
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
		ID: "exec_package", Version: "1.0.0", Permissions: []string{"exec"},
		Control: `exports.onReconcile = function () {};`,
	})
	if _, err := manager.Stage(bytes.NewReader(archive)); err == nil || !strings.Contains(err.Error(), "cannot request exec") {
		t.Fatalf("remote exec package admission: %v", err)
	}
}
