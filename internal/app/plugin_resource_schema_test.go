package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginResourceSchemaNormalizesAndValidatesData(t *testing.T) {
	resource := PluginResource{
		ID: "profiles",
		Schema: json.RawMessage(`{
  "type": "object",
  "required": ["name", "port"],
  "properties": {
    "name": {"type": "string", "minLength": 1},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535},
    "address": {"type": "string", "format": "ipv4"}
  },
  "additionalProperties": false
}`),
	}
	if err := normalizePluginResource(&resource); err != nil {
		t.Fatalf("normalizePluginResource() error = %v", err)
	}
	if resource.SchemaVersion != 1 || len(resource.SchemaDigest) != 64 || len(resource.Schema) == 0 {
		t.Fatalf("normalized schema resource = %+v", resource)
	}
	if err := validatePluginResourceData(resource, []byte(`{"name":"edge","port":443,"address":"192.0.2.1"}`)); err != nil {
		t.Fatalf("validate valid data: %v", err)
	}
	for _, invalid := range []string{
		`{"name":"edge"}`,
		`{"name":"edge","port":70000}`,
		`{"name":"edge","port":443,"address":"not-an-ip"}`,
		`{"name":"edge","port":443,"extra":true}`,
	} {
		if err := validatePluginResourceData(resource, []byte(invalid)); err == nil || !strings.Contains(err.Error(), "does not match schema") {
			t.Fatalf("validatePluginResourceData(%s) error = %v", invalid, err)
		}
	}
}

func TestPluginResourceSchemaRejectsUnsafeOrInvalidSchemas(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema string
		want   string
	}{
		{name: "scalar", schema: `true`, want: "JSON object"},
		{name: "invalid", schema: `{`, want: "valid JSON"},
		{name: "external ref", schema: `{"$ref":"file:///etc/passwd"}`, want: "external schema reference"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resource := PluginResource{ID: "settings", Schema: json.RawMessage(test.schema)}
			if err := normalizePluginResource(&resource); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("normalizePluginResource() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPluginResourceSchemaIsEnforcedByHTTPAPI(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "schema_plugin", `{
  "api_version": "v1",
  "id": "schema_plugin",
  "name": "Schema Plugin",
  "version": "1.0.0",
  "kind": "control",
  "control": {"main": "control.js", "permissions": ["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "schema_plugin", `
plugin.resource({
  id: "profiles",
  methods: ["list", "get", "create", "update", "delete"],
  schema_version: 3,
  schema: {
    type: "object",
    required: ["name", "enabled"],
    properties: {
      name: {type: "string", minLength: 1},
      enabled: {type: "boolean"}
    },
    additionalProperties: false
  }
});
`)
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "schema-token", PluginsDir: dir})
	db := openTestDB(t)
	handler := buildAPIHandler(cfg, db, nil)

	request := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/schema_plugin/resources/profiles", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer schema-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	invalid := request(`{"key":"default","data":{"name":"edge","enabled":"yes"}}`)
	if invalid.Code != http.StatusBadRequest || !strings.Contains(invalid.Body.String(), "does not match schema") {
		t.Fatalf("invalid schema write status = %d body=%s", invalid.Code, invalid.Body.String())
	}
	valid := request(`{"key":"default","data":{"name":"edge","enabled":true}}`)
	if valid.Code != http.StatusCreated {
		t.Fatalf("valid schema write status = %d body=%s", valid.Code, valid.Body.String())
	}

	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	plugin := relationshipPluginByIDValue(catalog, "schema_plugin")
	if plugin == nil || len(plugin.Resources) != 1 || plugin.Resources[0].SchemaVersion != 3 || len(plugin.Resources[0].SchemaDigest) != 64 {
		t.Fatalf("schema plugin catalog = %+v", plugin)
	}
}
