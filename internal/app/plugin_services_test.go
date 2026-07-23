package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginRuntimeSurfaceClonePreservesIndependentServices(t *testing.T) {
	surface := PluginRuntimeSurface{Services: []PluginService{{
		ID: "wan.adapter", Version: "1.0.0", Actions: []string{"apply"}, Resources: []string{"status"},
	}}}
	clone := clonePluginRuntimeSurface(surface)
	if len(clone.Services) != 1 || clone.Services[0].ID != "wan.adapter" {
		t.Fatalf("cloned services = %+v", clone.Services)
	}
	clone.Services[0].Actions[0] = "changed"
	clone.Services[0].Resources[0] = "changed"
	if surface.Services[0].Actions[0] != "apply" || surface.Services[0].Resources[0] != "status" {
		t.Fatalf("service endpoint slices alias their source: source=%+v clone=%+v", surface.Services, clone.Services)
	}
}

func TestPluginServiceRegistrationRejectsUnknownEndpoints(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "invalid_service", `{
  "api_version":"v1",
  "id":"invalid_service",
  "name":"Invalid Service",
  "version":"1.0.0",
  "kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, "invalid_service", `
plugin.service({id:'wan.adapter', version:'1.0.0', actions:['missing']});
`)
	catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	plugin := pluginByIDForTest(t, catalog, "invalid_service")
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "references undeclared action missing") {
		t.Fatalf("invalid service plugin = status:%s error:%q", plugin.Status, plugin.Error)
	}
}

func TestPluginServiceDiscoveryFiltersAuthorizedEndpointsAndCallsProvider(t *testing.T) {
	dir := t.TempDir()
	writePluginServiceProviderForTest(t, dir, "wan_provider", "1.2.0")
	writePluginServiceConsumerForTest(t, dir, "wan_provider", true)

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginRuntimeSnapshot(&catalog, runtime.Reconcile(catalog))
	consumer := pluginByIDForTest(t, catalog, "service_consumer")
	result, err := runtime.QueryPluginAction(consumer, pluginActionByIDForTest(t, consumer, "run"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	raw, _ := json.Marshal(result)
	for _, want := range []string{
		`"plugin_id":"wan_provider"`, `"id":"wan.adapter"`, `"version":"1.2.0"`,
		`"actions":["echo"]`, `"resources":["status"]`, `"value":"alpha"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("service result = %s, missing %s", raw, want)
		}
	}
	if strings.Contains(string(raw), `"hidden"`) {
		t.Fatalf("service result exposed unauthorized endpoint: %s", raw)
	}
}

func TestPluginServiceResolutionRejectsAmbiguousAndDisabledProviders(t *testing.T) {
	dir := t.TempDir()
	writePluginServiceProviderForTest(t, dir, "wan_provider", "1.2.0")
	writePluginServiceProviderForTest(t, dir, "wan_provider_two", "1.3.0")
	writePluginServiceConsumerForTest(t, dir, "", false)

	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = runtime.Close() })
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginRuntimeSnapshot(&catalog, runtime.Reconcile(catalog))
	consumer := pluginByIDForTest(t, catalog, "service_consumer")
	_, err := runtime.QueryPluginAction(consumer, pluginActionByIDForTest(t, consumer, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "ambiguous across providers wan_provider, wan_provider_two") {
		t.Fatalf("ambiguous service error = %v", err)
	}

	if err := store.SetPluginEnabled(db, "wan_provider_two", false); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.QueryPluginAction(consumer, pluginActionByIDForTest(t, consumer, "run"), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("resolve after disabling second provider: %v", err)
	}
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), `"plugin_id":"wan_provider"`) {
		t.Fatalf("resolved provider after disable = %s", raw)
	}

	if err := store.SetPluginEnabled(db, "wan_provider", false); err != nil {
		t.Fatal(err)
	}
	_, err = runtime.QueryPluginAction(consumer, pluginActionByIDForTest(t, consumer, "run"), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "no authorized provider satisfies service wan.adapter") {
		t.Fatalf("disabled providers error = %v", err)
	}
}

func TestPluginServiceContractUpgradeRequiresSemanticVersioning(t *testing.T) {
	base := LoadedPlugin{PluginManifest: PluginManifest{ID: "provider", Version: "1.0.0"}}
	base.Actions = []PluginAction{{ID: "apply", RuntimeUpdate: "runtime_apply"}, {ID: "status", RuntimeUpdate: "runtime_query"}}
	base.Services = []PluginService{{ID: "wan.adapter", Version: "1.0.0", Actions: []string{"apply", "status"}}}

	changed := base
	changed.Version = "1.1.0"
	changed.Actions = append([]PluginAction(nil), base.Actions...)
	changed.Actions[0].MaxPayloadBytes = 2048
	changed.Services = clonePluginServices(base.Services)
	if err := validatePluginServiceContractUpgrade(base, changed); err == nil || !strings.Contains(err.Error(), "contract changed without increasing service version") {
		t.Fatalf("unchanged service version error = %v", err)
	}
	changed.Services[0].Version = "1.1.0"
	if err := validatePluginServiceContractUpgrade(base, changed); err != nil {
		t.Fatalf("versioned service contract change: %v", err)
	}

	removedEndpoint := changed
	removedEndpoint.Services = clonePluginServices(changed.Services)
	removedEndpoint.Services[0].Actions = []string{"apply"}
	if err := validatePluginServiceContractUpgrade(base, removedEndpoint); err == nil || !strings.Contains(err.Error(), "removed an endpoint") {
		t.Fatalf("same-major endpoint removal error = %v", err)
	}
	removedEndpoint.Services[0].Version = "2.0.0"
	if err := validatePluginServiceContractUpgrade(base, removedEndpoint); err != nil {
		t.Fatalf("major-version endpoint removal: %v", err)
	}

	removedService := base
	removedService.Version = "1.1.0"
	removedService.Services = nil
	if err := validatePluginServiceContractUpgrade(base, removedService); err == nil || !strings.Contains(err.Error(), "removed without increasing plugin major") {
		t.Fatalf("service removal error = %v", err)
	}
	removedService.Version = "2.0.0"
	if err := validatePluginServiceContractUpgrade(base, removedService); err != nil {
		t.Fatalf("major-version service removal: %v", err)
	}
}

func writePluginServiceProviderForTest(t *testing.T, dir, id, version string) {
	t.Helper()
	writeTestPlugin(t, dir, id, `{
  "api_version":"v1",
  "id":"`+id+`",
  "name":"Service Provider",
  "version":"1.0.0",
  "kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register"]}
}`)
	writePluginControlScript(t, dir, id, `
plugin.action({id:'echo', runtime_update:'runtime_query'});
plugin.action({id:'hidden', runtime_update:'runtime_query'});
plugin.resource({id:'status', methods:['list','get'], runtime_update:'manual'});
plugin.resource({id:'internal', methods:['list','get'], runtime_update:'manual'});
plugin.service({
  id:'wan.adapter', version:'`+version+`',
  actions:['echo','hidden'], resources:['status','internal']
});
exports.onAction = function (ctx) { return {value:ctx.payload.value, provider:'`+id+`'}; };
`)
}

func writePluginServiceConsumerForTest(t *testing.T, dir, provider string, call bool) {
	t.Helper()
	providers := []string{"wan_provider", "wan_provider_two"}
	if provider != "" {
		providers = []string{provider}
	}
	actionAccess := make([]string, 0, len(providers))
	resourceAccess := make([]string, 0, len(providers))
	for _, id := range providers {
		actionAccess = append(actionAccess, `{"plugin":"`+id+`","actions":["echo"]}`)
		resourceAccess = append(resourceAccess, `{"plugin":"`+id+`","resource":"status","methods":["list","get"]}`)
	}
	writeTestPlugin(t, dir, "service_consumer", `{
  "api_version":"v1",
  "id":"service_consumer",
  "name":"Service Consumer",
  "version":"1.0.0",
  "kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["plugin.register","plugin.action","plugin.resource"],
    "action_access":[`+strings.Join(actionAccess, ",")+`],
    "resource_access":[`+strings.Join(resourceAccess, ",")+`]
  }
}`)
	providerField := ""
	if provider != "" {
		providerField = ", provider:'" + provider + "'"
	}
	body := `var selected = plugins.services.resolve({service:'wan.adapter', version:'^1.0.0'` + providerField + `});`
	if call {
		body += `var called = plugins.services.call({service:'wan.adapter', version:'^1.0.0'` + providerField + `, action:'echo', payload:{value:'alpha'}});` +
			`return {providers:plugins.services.list({service:'wan.adapter'}), selected:selected, called:called, ` +
			`js_shape:{plugin_id:selected.plugin_id, service_id:selected.service.id, actions:selected.service.actions, resources:selected.service.resources}};`
	} else {
		body += `return selected;`
	}
	writePluginControlScript(t, dir, "service_consumer", `
plugin.action({id:'run', runtime_update:'runtime_query'});
exports.onAction = function () { `+body+` };
`)
}
