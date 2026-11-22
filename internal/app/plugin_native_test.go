package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNativeManifestOnlyPlugin(t *testing.T, pluginsDir, id, control string) {
	t.Helper()
	pluginDir := filepath.Join(pluginsDir, id)
	if err := os.MkdirAll(filepath.Join(pluginDir, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "lib", "lib"+id+".so"), []byte("not a real library"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{
  "api_version": "v1",
  "id": "` + id + `",
  "name": "Native Test",
  "version": "1.0.0",
  "kind": "control",
  "stability": "lab",
  "control": ` + control + `
}`
	if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNativePluginManifestRegistersSurface(t *testing.T) {
	dir := t.TempDir()
	writeNativeManifestOnlyPlugin(t, dir, "native_surface", `{
    "library": {"x86_64-linux-gnu": {"path": "lib/libnative_surface.so"}},
    "permissions": ["kv", "plugin.register", "resource", "event"],
    "register": {
      "capabilities": ["wan"],
      "resources": [{"id": "sessions", "methods": ["list", "get"], "control_methods": ["list", "get", "create", "update", "delete"]}],
      "actions": [
        {"id": "apply", "runtime_update": "runtime_apply"},
        {"id": "status", "runtime_update": "runtime_query", "when": {"feature": "no.such.feature"}},
        {"id": "fallback", "runtime_update": "runtime_query", "when": {"not_feature": "no.such.feature"}},
        {"id": "both", "runtime_update": "runtime_query", "when": {"feature": "control.native.v1", "not_feature": "no.such.feature"}},
        {"id": "neither", "runtime_update": "runtime_query", "when": {"feature": "control.native.v1", "not_feature": "control.native.v1"}}
      ]
    }
  }`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	plugin := loadTestPluginByID(t, cfg, "native_surface")
	if !pluginUsesNativeControl(plugin) {
		t.Fatalf("plugin is not native")
	}
	ids := make([]string, 0, len(plugin.Actions))
	for _, action := range plugin.Actions {
		ids = append(ids, action.ID)
	}
	if strings.Join(ids, ",") != "apply,fallback,both" {
		t.Fatalf("actions = %v, want apply,fallback,both (runtime %+v)", ids, plugin.Runtime)
	}
	if len(plugin.Resources) != 1 || plugin.Resources[0].ID != "sessions" {
		t.Fatalf("resources = %+v", plugin.Resources)
	}
	if strings.Join(plugin.Capabilities, ",") != "wan" {
		t.Fatalf("capabilities = %v", plugin.Capabilities)
	}
}

func TestNativePluginManifestValidation(t *testing.T) {
	cases := map[string]string{
		"main and library": `{"main": "control.js", "library": {"x86_64-linux-gnu": {"path": "lib/x.so"}}}`,
		"unknown target":   `{"library": {"riscv64-linux-gnu": {"path": "lib/x.so"}}}`,
		"bad worker":       `{"library": {"x86_64-linux-gnu": {"path": "lib/x.so"}}, "worker": "Bad Name"}`,
		"bad when":         `{"library": {"x86_64-linux-gnu": {"path": "lib/x.so"}}, "register": {"actions": [{"id": "a", "when": {}}]}}`,
		"escaping path":    `{"library": {"x86_64-linux-gnu": {"path": "../x.so"}}}`,
		"register on js":   `{"main": "control.js", "register": {"capabilities": ["wan"]}}`,
	}
	for name, control := range cases {
		t.Run(name, func(t *testing.T) {
			var parsed PluginControl
			if err := decodeStrictJSONForTest(control, &parsed); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := normalizePluginControl(&parsed); err == nil {
				t.Fatalf("normalizePluginControl(%s) succeeded, want an error", control)
			}
		})
	}
}

func TestNativePluginLibraryHashIsVerified(t *testing.T) {
	dir := t.TempDir()
	writeNativeManifestOnlyPlugin(t, dir, "native_hash", `{
    "library": {"x86_64-linux-gnu": {"path": "lib/libnative_hash.so", "sha256": "`+strings.Repeat("0", 64)+`"}},
    "permissions": ["kv"]
  }`)
	catalog := loadPluginCatalog(pluginsEnabledTestConfig(&Config{PluginsDir: dir}))
	for _, plugin := range catalog.Plugins {
		if plugin.ID == "native_hash" {
			if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "sha256 mismatch") {
				t.Fatalf("plugin status = %s error = %q, want a sha256 mismatch", plugin.Status, plugin.Error)
			}
			return
		}
	}
	t.Fatalf("native_hash not in catalog")
}

func decodeStrictJSONForTest(data string, target any) error {
	decoder := json.NewDecoder(strings.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
