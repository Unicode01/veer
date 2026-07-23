package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginActionSchemasValidateHTTPRequestsAndQueryResponses(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "schema_action", `{
  "api_version": "v1",
  "id": "schema_action",
  "name": "Schema Action",
  "version": "1.0.0",
  "kind": "control",
  "control": {"main": "control.js", "permissions": ["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "schema_action", `
var calls = 0;
plugin.action({
  id: 'lookup',
  runtime_update: 'runtime_query',
  request_schema_version: 2,
  request_schema: {
    type: 'object',
    required: ['value'],
    properties: {value: {type: 'integer'}},
    additionalProperties: false
  },
  response_schema_version: 3,
  response_schema: {
    type: 'object',
    required: ['value', 'calls'],
    properties: {value: {type: 'integer'}, calls: {type: 'integer'}},
    additionalProperties: false
  }
});
plugin.action({
  id: 'broken_result',
  runtime_update: 'runtime_query',
  response_schema: {
    type: 'object',
    required: ['value'],
    properties: {value: {type: 'integer'}},
    additionalProperties: false
  }
});
exports.onAction = function (ctx) {
  calls++;
  if (ctx.action.id === 'broken_result') return {value: 'not-an-integer'};
  return {value: ctx.payload.value, calls: calls};
};
`)

	db := openTestDB(t)
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "test-token", PluginsDir: dir})
	pm := &ProcessManager{db: db, cfg: cfg}
	pm.pluginControlRuntime = newPluginControlRuntime(db, cfg, pm)
	t.Cleanup(func() { _ = pm.pluginControlRuntime.Close() })
	handler := buildAPIHandler(cfg, db, pm)

	request := func(action, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/schema_action/actions/"+action, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	invalid := request("lookup", `{"payload":{"value":"bad"}}`)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "does not match schema") {
		t.Fatalf("invalid action response = %d %s", invalid.Code, invalid.Body.String())
	}

	valid := request("lookup", `{"payload":{"value":7}}`)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid action response = %d %s", valid.Code, valid.Body.String())
	}
	var response pluginActionResponse
	if err := json.NewDecoder(valid.Body).Decode(&response); err != nil {
		t.Fatalf("decode valid action response: %v", err)
	}
	result, ok := response.Result.(map[string]any)
	if !ok || result["value"] != float64(7) || result["calls"] != float64(1) {
		t.Fatalf("valid action result = %#v, want value=7 calls=1", response.Result)
	}

	broken := request("broken_result", `{"payload":{}}`)
	if broken.Code != http.StatusInternalServerError || !strings.Contains(broken.Body.String(), "response value does not match schema") {
		t.Fatalf("broken action response = %d %s", broken.Code, broken.Body.String())
	}

	catalog := loadPluginCatalogWithControlRegistration(cfg)
	plugin := pluginByIDForTest(t, catalog, "schema_action")
	action := pluginActionByIDForTest(t, plugin, "lookup")
	if action.RequestSchemaVersion != 2 || action.ResponseSchemaVersion != 3 || len(action.RequestSchemaDigest) != 64 || len(action.ResponseSchemaDigest) != 64 {
		t.Fatalf("normalized action schema contract = %+v", action)
	}
}

func TestPluginActionAndEventSchemaVersionsAreImmutable(t *testing.T) {
	nonQuery := PluginAction{ID: "apply", RuntimeUpdate: "runtime_apply", ResponseSchema: json.RawMessage(`{"type":"object"}`)}
	if err := normalizePluginAction(&nonQuery); err == nil || !strings.Contains(err.Error(), "only for runtime_query") {
		t.Fatalf("non-query response schema error = %v", err)
	}

	normalizedAction := func(version int, schema string) PluginAction {
		t.Helper()
		action := PluginAction{
			ID: "lookup", RuntimeUpdate: "runtime_query", RequestSchemaVersion: version,
			RequestSchema: json.RawMessage(schema),
		}
		if err := normalizePluginAction(&action); err != nil {
			t.Fatalf("normalize action: %v", err)
		}
		return action
	}
	normalizedSubscription := func(version int, schema string) PluginEventSubscription {
		t.Helper()
		plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "schema_events", Control: &PluginControl{Permissions: []string{"event", "worker"}}}}
		subscription := PluginEventSubscription{
			ID: "updates", Topic: "plugin.schema_events.updated", SchemaVersion: version, Schema: json.RawMessage(schema),
		}
		if err := normalizePluginEventSubscription(plugin, &subscription); err != nil {
			t.Fatalf("normalize subscription: %v", err)
		}
		return subscription
	}

	previous := LoadedPlugin{
		Actions:            []PluginAction{normalizedAction(1, `{"type":"object","properties":{"value":{"type":"integer"}}}`)},
		EventSubscriptions: []PluginEventSubscription{normalizedSubscription(1, `{"type":"object","properties":{"value":{"type":"integer"}}}`)},
	}
	candidate := LoadedPlugin{
		Actions:            []PluginAction{normalizedAction(1, `{"type":"object","properties":{"value":{"type":"string"}}}`)},
		EventSubscriptions: []PluginEventSubscription{normalizedSubscription(1, `{"type":"object","properties":{"value":{"type":"string"}}}`)},
	}
	if err := validatePluginActionContractUpgrade(previous, candidate); err == nil || !strings.Contains(err.Error(), "without increasing schema_version 1") {
		t.Fatalf("same-version action schema change error = %v", err)
	}
	if err := validatePluginEventContractUpgrade(previous, candidate); err == nil || !strings.Contains(err.Error(), "without increasing schema_version 1") {
		t.Fatalf("same-version event schema change error = %v", err)
	}

	candidate.Actions[0] = normalizedAction(2, `{"type":"object","properties":{"value":{"type":"string"}}}`)
	candidate.EventSubscriptions[0] = normalizedSubscription(2, `{"type":"object","properties":{"value":{"type":"string"}}}`)
	if err := validatePluginActionContractUpgrade(previous, candidate); err != nil {
		t.Fatalf("versioned action schema change: %v", err)
	}
	if err := validatePluginEventContractUpgrade(previous, candidate); err != nil {
		t.Fatalf("versioned event schema change: %v", err)
	}
}
