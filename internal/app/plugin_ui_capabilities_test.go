package app

import (
	"reflect"
	"strings"
	"testing"
)

func TestPluginUIRegistrationNormalizesLeastPrivilegeCapabilities(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "ui_capabilities", `{
  "api_version":"v1",
  "id":"ui_capabilities",
  "name":"UI Capabilities",
  "version":"0.1.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["plugin.register","ui"]}
}`)
	writePluginControlScript(t, dir, "ui_capabilities", `
plugin.resource({id: 'profiles', methods: ['list', 'get', 'create', 'update'], runtime_update: 'manual'});
plugin.action({id: 'apply', runtime_update: 'runtime_apply'});
ui.register({
  static_dir: 'ui', entry: 'index.html', page: 'test', page_title: 'Test',
  resources: [{resource: 'profiles', methods: ['update', 'list']}],
  actions: ['apply']
});
`)

	catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	plugin := pluginByIDForTest(t, catalog, "ui_capabilities")
	if plugin.Status != pluginStatusActive || plugin.UI == nil {
		t.Fatalf("plugin = %+v, want active plugin with UI", plugin)
	}
	wantResources := []PluginUIResourceAccess{{Resource: "profiles", Methods: []string{"list", "update"}}}
	if !reflect.DeepEqual(plugin.UI.Resources, wantResources) {
		t.Fatalf("ui resources = %#v, want %#v", plugin.UI.Resources, wantResources)
	}
	if !reflect.DeepEqual(plugin.UI.Actions, []string{"apply"}) {
		t.Fatalf("ui actions = %#v, want [apply]", plugin.UI.Actions)
	}
}

func TestPluginUIRegistrationRejectsCapabilityEscalation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		script  string
		message string
	}{
		{
			name: "undeclared resource",
			script: `
ui.register({static_dir: 'ui', entry: 'index.html', resources: [{resource: 'missing', methods: ['list']}]});
`,
			message: `ui.resources references undeclared resource "missing"`,
		},
		{
			name: "unexposed method",
			script: `
plugin.resource({id: 'status', methods: ['list', 'get'], runtime_update: 'manual'});
ui.register({static_dir: 'ui', entry: 'index.html', resources: [{resource: 'status', methods: ['delete']}]});
`,
			message: `ui.resources method delete is not exposed by resource "status"`,
		},
		{
			name: "undeclared action",
			script: `
ui.register({static_dir: 'ui', entry: 'index.html', actions: ['missing']});
`,
			message: `ui.actions references undeclared action "missing"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestPlugin(t, dir, "ui_denied", `{
  "api_version":"v1",
  "id":"ui_denied",
  "name":"UI Denied",
  "version":"0.1.0",
  "kind":"control",
  "stability":"lab",
  "control":{"main":"control.js","permissions":["plugin.register","ui"]}
}`)
			writePluginControlScript(t, dir, "ui_denied", tc.script)
			catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
			plugin := pluginByIDForTest(t, catalog, "ui_denied")
			if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, tc.message) {
				t.Fatalf("plugin = %+v, want error containing %q", plugin, tc.message)
			}
		})
	}
}

func TestPluginUICrossResourceAccessMustBeControlSubset(t *testing.T) {
	t.Parallel()

	ui := &PluginUI{ResourceAccess: []PluginResourceAccess{{
		Plugin: "wan_core", Resource: "status", Methods: []string{"list"},
	}}}
	if err := normalizePluginUI(ui); err != nil {
		t.Fatalf("normalizePluginUI() error = %v", err)
	}
	plugin := &LoadedPlugin{
		PluginManifest: PluginManifest{Control: &PluginControl{ResourceAccess: []PluginResourceAccess{{
			Plugin: "wan_core", Resource: "status", Methods: []string{"get"},
		}}}},
		UI: ui,
	}
	if err := validatePluginUIAccess(plugin); err == nil || !strings.Contains(err.Error(), "is not granted by control.resource_access") {
		t.Fatalf("validatePluginUIAccess() error = %v, want control subset rejection", err)
	}
}
