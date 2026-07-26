package app

import (
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestNormalizePluginHookNetfilterPlacement(t *testing.T) {
	hook := PluginHook{
		ID:            "firewall",
		Engine:        pluginEngineNetfilter,
		NetfilterHook: "LOCAL_IN",
		Namespace:     "",
		Program:       "dataplane:firewall",
		Mode:          "drop",
	}

	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("normalizePluginHook() error = %v", err)
	}
	if hook.Attach != "none" || hook.Stage != "" || hook.Family != "inet" || hook.NetfilterHook != "input" || hook.Phase != "filter" || hook.Namespace != "host" {
		t.Fatalf("normalized placement = %+v", hook)
	}
}

func TestNormalizePluginObjectRejectsMixedDataplaneEngines(t *testing.T) {
	object := PluginObject{
		ID:   "mixed",
		Path: "mixed.o",
		Programs: []PluginObjectProgram{
			{ID: "tc_filter", Section: "tc/filter", Type: kernelEngineTC},
			{ID: "nf_filter", Section: "netfilter/filter", Type: pluginEngineNetfilter},
		},
	}

	err := normalizePluginObject(&object)
	if err == nil || !strings.Contains(err.Error(), "cannot mix tc and netfilter") {
		t.Fatalf("normalizePluginObject() error = %v, want mixed-engine rejection", err)
	}
}

func TestNormalizePluginHookNetfilterRejectsAttachTargets(t *testing.T) {
	tests := []struct {
		name string
		hook PluginHook
		want string
	}{
		{
			name: "generic interfaces",
			hook: PluginHook{ID: "firewall", Engine: pluginEngineNetfilter, NetfilterHook: "forward", Program: "dataplane:firewall", Interfaces: []string{"eth0"}},
			want: "match input/output interfaces inside the plugin program",
		},
		{
			name: "tc attach",
			hook: PluginHook{ID: "firewall", Engine: pluginEngineNetfilter, Attach: "ingress", NetfilterHook: "forward", Program: "dataplane:firewall"},
			want: "do not use attach targets",
		},
		{
			name: "tc stage",
			hook: PluginHook{ID: "firewall", Engine: pluginEngineNetfilter, Stage: pluginPipelineDirectionForward, NetfilterHook: "forward", Program: "dataplane:firewall"},
			want: "use hook and phase instead of stage",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := normalizePluginHook(&test.hook); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("normalizePluginHook() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestNormalizePluginHookRejectsNetfilterPlacementOnOtherEngines(t *testing.T) {
	for _, engine := range []string{kernelEngineTC, kernelEngineXDP, "control"} {
		t.Run(engine, func(t *testing.T) {
			hook := PluginHook{
				ID:            "wrong-placement",
				Engine:        engine,
				Stage:         pluginPipelineDirectionForward,
				Program:       "dataplane:program",
				NetfilterHook: "forward",
			}
			if engine == "control" {
				hook.Program = ""
			}
			if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), "only available to netfilter") {
				t.Fatalf("normalizePluginHook() error = %v", err)
			}
		})
	}
}

func TestPluginRequiredHostFeaturesInfersNetfilterPipeline(t *testing.T) {
	plugin := LoadedPlugin{Hooks: []PluginHook{{Engine: pluginEngineNetfilter}}}
	features := pluginRequiredHostFeatures(plugin)
	if !containsString(features, "dataplane.netfilter_pipeline.v1") {
		t.Fatalf("required features = %v", features)
	}
}

func TestApplyPluginHookBindingsDoesNotInjectInterfacesIntoNetfilterHook(t *testing.T) {
	db := openTestDB(t)
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID:   "firewall",
		ResourceID: pluginHookBindingsResourceID,
		RecordKey:  "nf-input",
		DataJSON:   `{"hook_id":"nf-input","interfaces":["eth0"]}`,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("AddPluginRecord(hook_bindings) error = %v", err)
	}
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "firewall"},
		Status:         pluginStatusActive,
		Resources: []PluginResource{{
			ID: pluginHookBindingsResourceID,
		}},
		Hooks: []PluginHook{{
			ID:            "nf-input",
			Engine:        pluginEngineNetfilter,
			NetfilterHook: "input",
			Namespace:     "host",
		}},
	}}}

	catalog = applyPluginHookBindingsFromDB(catalog, db)
	if len(catalog.Plugins[0].Hooks) != 1 || len(catalog.Plugins[0].Hooks[0].Interfaces) != 0 {
		t.Fatalf("netfilter hooks = %+v, want enabled hook without interface attachment metadata", catalog.Plugins[0].Hooks)
	}
}

func TestPluginControlNetfilterHookRequiresNamespacePermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "nf_namespace_denied", `{
  "api_version":"v1","id":"nf_namespace_denied","name":"NF Namespace Denied","version":"1.0.0","kind":"pipeline",
  "control":{"main":"control.js","permissions":["hook.attach"]}
}`)
	writePluginControlScript(t, dir, "nf_namespace_denied", `
hooks.attach({id:"filter",engine:"netfilter",family:"ipv4",hook:"output",namespace:"veer-denied",program:"filter:nf_filter"});
`)

	catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "permission net.namespace is required") {
		t.Fatalf("plugin = %+v, want net.namespace permission error", plugin)
	}
}

func TestPluginControlNetfilterHookEnforcesNamespaceAccess(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "nf_namespace_scope", `{
  "api_version":"v1","id":"nf_namespace_scope","name":"NF Namespace Scope","version":"1.0.0","kind":"pipeline",
  "control":{"main":"control.js","permissions":["hook.attach","net.namespace"],"namespace_access":["veer-ok"]}
}`)
	writePluginControlScript(t, dir, "nf_namespace_scope", `
hooks.attach({id:"filter",engine:"netfilter",family:"ipv4",hook:"output",namespace:"veer-denied",program:"filter:nf_filter"});
`)

	catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	plugin := catalog.Plugins[1]
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "namespace_access") {
		t.Fatalf("plugin = %+v, want namespace_access error", plugin)
	}
}
