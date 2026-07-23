package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPluginStructuredLogsRedactSensitiveFields(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "log_plugin", `{
  "api_version": "v1",
  "id": "log_plugin",
  "name": "Log Plugin",
  "version": "1.0.0",
  "kind": "control",
  "control": {"main": "control.js", "permissions": ["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "log_plugin", `
plugin.action({id: 'write_log', runtime_update: 'runtime_apply'});
exports.onAction = function () {
  log.warn('dial failed', {
    interface: 'eth0',
    password: 'plain-password',
    nested: {access_token: 'plain-token', attempt: 2}
  });
};
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "log_plugin")
	rt := newPluginControlRuntime(openTestDB(t), cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	if err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "write_log"), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("ApplyPluginAction() error = %v", err)
	}
	logs, state := rt.pluginLogEntries("log_plugin", "warn", 10)
	if len(logs) != 1 || state.Entries != 1 || state.Dropped != 0 {
		t.Fatalf("logs/state = %+v/%+v", logs, state)
	}
	raw, err := json.Marshal(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "plain-password") || strings.Contains(text, "plain-token") {
		t.Fatalf("structured log leaked sensitive data: %s", text)
	}
	for _, want := range []string{`"password":"__redacted__"`, `"access_token":"__redacted__"`, `"interface":"eth0"`, `"attempt":2`} {
		if !strings.Contains(text, want) {
			t.Fatalf("structured log = %s, want %s", text, want)
		}
	}
	health := rt.pluginControlHealthSnapshot("log_plugin")
	if health.LogEntries != 1 || health.DroppedLogs != 0 {
		t.Fatalf("health log metrics = %+v", health)
	}
}

func TestPluginStructuredLogRateLimitAndAPI(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "rate_logs", `{
  "api_version": "v1",
  "id": "rate_logs",
  "name": "Rate Logs",
  "version": "1.0.0",
  "kind": "control",
  "control": {"main": "control.js"}
}`)
	writePluginControlScript(t, dir, "rate_logs", ``)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	rt := newPluginControlRuntime(openTestDB(t), cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	for i := 0; i < pluginLogRateLimit+7; i++ {
		rt.appendPluginLog(PluginLogEntry{PluginID: "rate_logs", Level: "info", Message: "entry"})
	}
	logs, state := rt.pluginLogEntries("rate_logs", "", pluginLogMaxListLimit)
	if len(logs) != pluginLogRateLimit || state.Entries != pluginLogRateLimit || state.Dropped != 7 {
		t.Fatalf("rate-limited logs/state = %d/%+v", len(logs), state)
	}

	pm := &ProcessManager{cfg: cfg, pluginControlRuntime: rt}
	req := httptest.NewRequest(http.MethodGet, "/api/plugins/rate_logs/logs?limit=3&level=info", nil)
	rec := httptest.NewRecorder()
	handlePluginLogsAPI(rec, req, cfg, nil, pm, []string{"rate_logs", "logs"})
	if rec.Code != http.StatusOK {
		t.Fatalf("logs API status = %d: %s", rec.Code, rec.Body.String())
	}
	var response pluginLogsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.PluginID != "rate_logs" || len(response.Logs) != 3 || response.State.Dropped != 7 {
		t.Fatalf("logs API response = %+v", response)
	}
}

func TestPluginStructuredLogsPersistAcrossRuntimeRestart(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "persistent_logs", `{
  "api_version": "v1",
  "id": "persistent_logs",
  "name": "Persistent Logs",
  "version": "1.0.0",
  "kind": "control",
  "control": {"main": "control.js"}
}`)
	writePluginControlScript(t, dir, "persistent_logs", ``)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	first := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	first.appendPluginLog(PluginLogEntry{PluginID: "persistent_logs", Level: "info", Message: "first"})
	first.appendPluginLog(PluginLogEntry{PluginID: "persistent_logs", Level: "error", Message: "second", Fields: map[string]any{"attempt": 2}})
	if err := first.Close(); err != nil {
		t.Fatalf("Close(first runtime) error = %v", err)
	}

	second := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = second.Close() })
	pm := &ProcessManager{cfg: cfg, pluginControlRuntime: second}
	request := func(path string) pluginLogsResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handlePluginLogsAPI(rec, req, cfg, db, pm, []string{"persistent_logs", "logs"})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d: %s", path, rec.Code, rec.Body.String())
		}
		var response pluginLogsResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}

	all := request("/api/plugins/persistent_logs/logs?limit=10")
	if len(all.Logs) != 2 || all.Logs[0].Message != "second" || all.Logs[1].Message != "first" || all.State.Entries != 2 {
		t.Fatalf("persistent logs = %+v", all)
	}
	if all.Logs[0].Sequence == 0 || all.Logs[1].Sequence == 0 || all.Logs[0].Sequence <= all.Logs[1].Sequence {
		t.Fatalf("persistent log sequences = %+v, want descending database IDs", all.Logs)
	}
	older := request("/api/plugins/persistent_logs/logs?limit=10&before_id=" + strconv.FormatUint(all.Logs[0].Sequence, 10))
	if len(older.Logs) != 1 || older.Logs[0].Message != "first" {
		t.Fatalf("persistent log cursor response = %+v", older)
	}
}
