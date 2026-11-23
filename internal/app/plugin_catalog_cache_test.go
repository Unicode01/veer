package app

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func cachedCatalogTestManifest(version string) string {
	return `{
  "api_version": "v1",
  "id": "cached_plugin",
  "name": "Cached Plugin",
  "version": "` + version + `",
  "kind": "pipeline"
}`
}

func newCachedCatalogTestManager(t *testing.T) (*ProcessManager, string) {
	t.Helper()
	dir := t.TempDir()
	writeTestPlugin(t, dir, "cached_plugin", cachedCatalogTestManifest("1.0.0"))
	pm := &ProcessManager{
		db:               openTestDB(t),
		cfg:              pluginsEnabledTestConfig(&Config{PluginsDir: dir}),
		redistributeWake: make(chan struct{}, 1),
	}
	pm.initializePluginCatalogSnapshot()
	t.Cleanup(pm.cleanupPluginCatalogSnapshot)
	pm.mu.Lock()
	applied := pm.pluginCatalogAppliedDir
	pm.mu.Unlock()
	if applied == "" {
		t.Fatal("initializePluginCatalogSnapshot() left no applied snapshot")
	}
	return pm, applied
}

func cachedCatalogTestPlugin(t *testing.T, catalog PluginCatalog) LoadedPlugin {
	t.Helper()
	for _, plugin := range catalog.Plugins {
		if plugin.ID == "cached_plugin" {
			return plugin
		}
	}
	t.Fatalf("catalog has no cached_plugin: %+v", catalog.Plugins)
	return LoadedPlugin{}
}

func TestPluginCatalogCacheReadsAppliedSnapshotOnce(t *testing.T) {
	pm, applied := newCachedCatalogTestManager(t)
	first := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg))
	if first.Version != "1.0.0" || first.Status != pluginStatusActive {
		t.Fatalf("first read = %s %s, want active 1.0.0", first.Version, first.Status)
	}

	// The applied snapshot is private and never edited in place; editing it
	// here shows whether a read goes back to disk.
	writeTestPlugin(t, applied, "cached_plugin", cachedCatalogTestManifest("9.9.9"))
	for name, catalog := range map[string]PluginCatalog{
		"control surface": pm.pluginCatalogWithControlSurface(pm.cfg),
		"api view":        pm.pluginCatalogWithConfig(pm.cfg),
	} {
		if got := cachedCatalogTestPlugin(t, catalog).Version; got != "1.0.0" {
			t.Fatalf("%s after a snapshot edit = %s, want the cached 1.0.0", name, got)
		}
	}

	pm.invalidatePluginCatalogCache()
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "9.9.9" {
		t.Fatalf("read after invalidation = %s, want 9.9.9", got)
	}
}

func TestPluginCatalogCacheFollowsEnabledState(t *testing.T) {
	pm, _ := newCachedCatalogTestManager(t)
	if plugin := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)); !plugin.Enabled {
		t.Fatalf("plugin before disable = %+v, want enabled", plugin)
	}
	if err := store.SetPluginEnabled(pm.db, "cached_plugin", false); err != nil {
		t.Fatal(err)
	}
	plugin := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg))
	if plugin.Enabled || plugin.Status != pluginStatusDisabled {
		t.Fatalf("plugin after disable = enabled %v status %s, want disabled", plugin.Enabled, plugin.Status)
	}
	if err := store.SetPluginEnabled(pm.db, "cached_plugin", true); err != nil {
		t.Fatal(err)
	}
	if plugin := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)); !plugin.Enabled || plugin.Status != pluginStatusActive {
		t.Fatalf("plugin after enable = enabled %v status %s, want active", plugin.Enabled, plugin.Status)
	}
}

func TestPluginCatalogCacheFollowsAppliedUpdate(t *testing.T) {
	pm, _ := newCachedCatalogTestManager(t)
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "1.0.0" {
		t.Fatalf("initial version = %s, want 1.0.0", got)
	}
	writeTestPlugin(t, pm.cfg.PluginsDir, "cached_plugin", cachedCatalogTestManifest("2.0.0"))
	if !pm.detectPluginCatalogDrift() {
		t.Fatal("detectPluginCatalogDrift() = false after the plugin changed")
	}
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "1.0.0" {
		t.Fatalf("version before apply = %s, want the applied 1.0.0", got)
	}
	if err := pm.applyPluginCatalogUpdateSelection([]string{"cached_plugin"}); err != nil {
		t.Fatalf("applyPluginCatalogUpdateSelection() error = %v", err)
	}
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "2.0.0" {
		t.Fatalf("version after apply = %s, want 2.0.0", got)
	}
}

func TestPluginCatalogCacheCopiesAreIndependent(t *testing.T) {
	pm, _ := newCachedCatalogTestManager(t)
	catalog := pm.pluginCatalogWithControlSurface(pm.cfg)
	for i := range catalog.Plugins {
		catalog.Plugins[i].Name = "changed"
		catalog.Plugins[i].Capabilities = append(catalog.Plugins[i].Capabilities[:0:0], "changed")
		if len(catalog.Plugins[i].Hooks) > 0 {
			catalog.Plugins[i].Hooks[0].ID = "changed"
		}
	}
	catalog.Plugins = catalog.Plugins[:1]
	next := pm.pluginCatalogWithControlSurface(pm.cfg)
	plugin := cachedCatalogTestPlugin(t, next)
	if plugin.Name != "Cached Plugin" {
		t.Fatalf("cached plugin name = %q after a caller changed its copy", plugin.Name)
	}
	if next.Plugins[0].Hooks[0].ID == "changed" {
		t.Fatal("built-in hook changed in the cache through a caller's copy")
	}
}

func TestPluginCatalogCacheReadsConfiguredDirectoryWithoutSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "cached_plugin", cachedCatalogTestManifest("1.0.0"))
	pm := &ProcessManager{db: openTestDB(t), cfg: pluginsEnabledTestConfig(&Config{PluginsDir: dir})}
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "1.0.0" {
		t.Fatalf("version = %s, want 1.0.0", got)
	}
	writeTestPlugin(t, dir, "cached_plugin", cachedCatalogTestManifest("1.1.0"))
	if got := cachedCatalogTestPlugin(t, pm.pluginCatalogWithControlSurface(pm.cfg)).Version; got != "1.1.0" {
		t.Fatalf("version after an edit = %s, want 1.1.0 read from the configured directory", got)
	}
}

func TestClonePluginCatalogSharesNothing(t *testing.T) {
	ui := &PluginUI{Entry: "index.html", Actions: []string{"a"}}
	catalog := PluginCatalog{
		HotReload: &PluginCatalogHotReload{Updates: []PluginCatalogUpdate{{PluginID: "x", appliedSource: "x"}}},
		Plugins: []LoadedPlugin{{
			PluginManifest: PluginManifest{
				ID:            "x",
				Compatibility: &PluginCompatibility{Features: []string{"f"}},
				Control: &PluginControl{
					Permissions: []string{"p"},
					Library:     map[string]PluginNativeLibrary{"t": {Path: "lib.so"}},
				},
			},
			Hooks:         []PluginHook{{ID: "h", Interfaces: []string{"eth0"}}},
			UI:            ui,
			ResourceUsage: &PluginResourceUsage{LimitWarnings: []string{"w"}},
			rootDir:       "/root",
		}},
	}
	want := clonePluginCatalog(catalog)
	got := clonePluginCatalog(catalog)
	if !reflect.DeepEqual(got, catalog) {
		t.Fatalf("clone differs from the original:\n%+v\n%+v", got, catalog)
	}
	got.HotReload.Updates[0].PluginID = "y"
	got.Plugins[0].Compatibility.Features[0] = "y"
	got.Plugins[0].Control.Permissions[0] = "y"
	got.Plugins[0].Control.Library["t"] = PluginNativeLibrary{Path: "y"}
	got.Plugins[0].Hooks[0].Interfaces[0] = "y"
	got.Plugins[0].UI.Actions[0] = "y"
	got.Plugins[0].ResourceUsage.LimitWarnings[0] = "y"
	if !reflect.DeepEqual(catalog, want) {
		t.Fatalf("changing a clone changed the original:\n%+v", catalog)
	}
	if got.Plugins[0].rootDir != "/root" || got.HotReload.Updates[0].appliedSource != "x" {
		t.Fatal("clone lost unexported fields")
	}
}

// TestPluginCatalogTypesCloneDeeply keeps clonePluginCatalog sound: it copies
// unexported fields by value, so none of them may hold a reference.
func TestPluginCatalogTypesCloneDeeply(t *testing.T) {
	seen := make(map[reflect.Type]bool)
	var problems []string
	var walk func(reflect.Type, string)
	walk = func(t reflect.Type, path string) {
		if seen[t] {
			return
		}
		seen[t] = true
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t.Elem(), path+"[]")
		case reflect.Map:
			walk(t.Key(), path+"{key}")
			walk(t.Elem(), path+"{}")
		case reflect.Struct:
			for i := 0; i < t.NumField(); i++ {
				field := t.Field(i)
				if !field.IsExported() && pluginCopyPlanFor(field.Type).references {
					problems = append(problems, path+"."+field.Name+" ("+field.Type.String()+")")
					continue
				}
				walk(field.Type, path+"."+field.Name)
			}
		}
	}
	walk(reflect.TypeOf(PluginCatalog{}), "PluginCatalog")
	if len(problems) > 0 {
		t.Fatalf("unexported fields that clonePluginCatalog would share:\n%s", strings.Join(problems, "\n"))
	}
}

func BenchmarkPluginCatalogCachedRead(b *testing.B) {
	root, err := filepath.Abs(filepath.Join("..", "..", "plugins"))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := os.Stat(root); err != nil {
		b.Skip("bundled plugins are not in this tree")
	}
	pm := &ProcessManager{db: openTestDB(b), cfg: pluginsEnabledTestConfig(&Config{PluginsDir: root})}
	pm.initializePluginCatalogSnapshot()
	b.Cleanup(pm.cleanupPluginCatalogSnapshot)
	b.Run("uncached", func(b *testing.B) {
		cfg, _ := pm.appliedPluginCatalogConfig(pm.cfg)
		for i := 0; i < b.N; i++ {
			_ = loadPluginCatalogWithState(cfg, pm.db)
		}
	})
	b.Run("cached", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, _ = pm.pluginCatalogWithState(pm.cfg)
		}
	})
}
