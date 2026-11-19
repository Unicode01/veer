package app

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

// TestBundledBindingAdaptersNeverRunAsGlobalHooks loads the bundled plugins
// that bind their TC/XDP hooks through a hook_bindings resource. Until a
// binding record names an interface, none of their hooks may run: a hook
// without interfaces runs on every interface, which turns the core flow cache
// off everywhere and pins the core to its TC engine. pppoe_client used to
// leave two hooks global before its first dial.
func TestBundledBindingAdaptersNeverRunAsGlobalHooks(t *testing.T) {
	pluginsDir, err := filepath.Abs(filepath.Join("..", "..", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	catalog := loadPluginCatalogWithControlRegistration(pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir}))
	objects := map[string]string{
		"firewall":     "firewall/firewall.o",
		"pppoe_client": "pppoe_client/pppoe_tunnel.o",
		"vpn_core":     "vpn_core/tunnel_adapter.o",
	}
	var adapters []LoadedPlugin
	for _, plugin := range catalog.Plugins {
		object, ok := objects[plugin.ID]
		if !ok {
			continue
		}
		if plugin.Compatibility != nil && len(plugin.Compatibility.OS) > 0 && !slices.Contains(plugin.Compatibility.OS, runtime.GOOS) {
			continue
		}
		if plugin.Status != pluginStatusActive {
			// Objects are build products; a plugin whose object was not
			// built here cannot register its hooks.
			if _, err := os.Stat(filepath.Join(pluginsDir, filepath.FromSlash(object))); err != nil {
				t.Logf("%s skipped: %s is not built", plugin.ID, object)
				continue
			}
			t.Fatalf("%s did not load: status=%s error=%q reason=%q", plugin.ID, plugin.Status, plugin.Error, plugin.Runtime.Reason)
		}
		if !pluginHasResource(plugin, pluginHookBindingsResourceID) {
			t.Fatalf("%s declares no %s resource", plugin.ID, pluginHookBindingsResourceID)
		}
		dataplaneHooks := 0
		for _, hook := range plugin.Hooks {
			if hook.Engine != kernelEngineTC && hook.Engine != kernelEngineXDP {
				continue
			}
			dataplaneHooks++
			if !hook.BindingRequired {
				t.Errorf("%s hook %s has no binding_required: unbound it would run on every interface", plugin.ID, hook.ID)
			}
		}
		if dataplaneHooks == 0 {
			t.Fatalf("%s registered no TC or XDP hooks", plugin.ID)
		}
		adapters = append(adapters, plugin)
	}
	if len(adapters) == 0 {
		t.Skip("no binding adapter could load; build the plugin eBPF objects first")
	}

	// The bindings filter rewrites the hooks of the catalog it is given.
	first := adapters[0]
	first.Hooks = append([]PluginHook(nil), first.Hooks...)
	var hookID string
	for _, hook := range first.Hooks {
		if hook.Engine == kernelEngineTC || hook.Engine == kernelEngineXDP {
			hookID = hook.ID
			break
		}
	}

	db := openTestDB(t)
	unbound := applyPluginHookBindingsFromDB(PluginCatalog{Plugins: append([]LoadedPlugin(nil), adapters...)}, db)
	for _, plugin := range unbound.Plugins {
		for _, hook := range plugin.Hooks {
			if hook.Engine == kernelEngineTC || hook.Engine == kernelEngineXDP {
				t.Errorf("%s hook %s is active without a binding record (interfaces %v)", plugin.ID, hook.ID, hook.Interfaces)
			}
		}
	}

	// A binding brings the hook back on exactly the named interface.
	if _, err := store.AddPluginRecord(db, &store.PluginRecord{
		PluginID: first.ID, ResourceID: pluginHookBindingsResourceID, RecordKey: hookID,
		DataJSON: `{"hook_id":"` + hookID + `","interfaces":["eth9"]}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	bound := applyPluginHookBindingsFromDB(PluginCatalog{Plugins: []LoadedPlugin{first}}, db)
	found := false
	for _, hook := range bound.Plugins[0].Hooks {
		if hook.ID != hookID {
			continue
		}
		found = true
		if len(hook.Interfaces) != 1 || hook.Interfaces[0] != "eth9" {
			t.Fatalf("%s hook %s interfaces = %v, want [eth9]", first.ID, hookID, hook.Interfaces)
		}
	}
	if !found {
		t.Fatalf("%s hook %s stays inactive with a binding record", first.ID, hookID)
	}
}
