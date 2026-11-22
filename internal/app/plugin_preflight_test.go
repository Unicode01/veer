package app

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePluginPreflightInstall(t *testing.T, config string, plugins map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if config != "" {
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, manifest := range plugins {
		pluginDir := filepath.Join(dir, "plugins", name)
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, pluginManifestFile), []byte(manifest), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pluginDir, "control.js"), []byte("export function register() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runPluginPreflightForTest(t *testing.T, dir string) pluginPreflightReport {
	t.Helper()
	var stdout, stderr bytes.Buffer
	handled, err := runPluginPackageCLI([]string{"plugin", "preflight", "--json", "--install-dir", dir}, &stdout, &stderr)
	if !handled || err != nil {
		t.Fatalf("plugin preflight: handled=%v err=%v stderr=%s", handled, err, stderr.String())
	}
	var report pluginPreflightReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode report %s: %v", stdout.String(), err)
	}
	return report
}

const pluginPreflightScriptManifest = `{
  "api_version": "v1",
  "id": "old_js",
  "name": "Old JS",
  "version": "1.0.0",
  "kind": "control",
  "stability": "lab",
  "control": {"main": "control.js", "permissions": ["kv"]}
}`

func TestPluginPreflightBlocksControlScripts(t *testing.T) {
	// A manifest the catalog cannot load at all (an unknown api_version
	// here) is still recognized as a JavaScript plugin from its raw
	// control section.
	unloadable := strings.Replace(strings.Replace(pluginPreflightScriptManifest, `"v1"`, `"v0"`, 1), "old_js", "older_js", 1)
	dir := writePluginPreflightInstall(t, `{"plugins_enabled": true}`, map[string]string{
		"old_js":   pluginPreflightScriptManifest,
		"older_js": unloadable,
	})
	report := runPluginPreflightForTest(t, dir)
	if report.Verdict != pluginPreflightBlocked || report.PluginsDir != filepath.Join(dir, "plugins") {
		t.Fatalf("report = %+v, want blocked for %s", report, filepath.Join(dir, "plugins"))
	}
	got := map[string]pluginPreflightPlugin{}
	for _, plugin := range report.Plugins {
		got[plugin.Dir] = plugin
	}
	for _, dirName := range []string{"old_js", "older_js"} {
		plugin, ok := got[dirName]
		if !ok || plugin.Status != pluginPreflightBlocked || plugin.Problem != pluginPreflightControlScript || plugin.ID != dirName || plugin.Version != "1.0.0" {
			t.Fatalf("%s = %+v (all %+v), want blocked control_script", dirName, plugin, report.Plugins)
		}
	}
}

func TestPluginPreflightSkipsWhenPluginsDoNotRun(t *testing.T) {
	plugins := map[string]string{"old_js": pluginPreflightScriptManifest}
	for name, config := range map[string]string{
		"no config":        "",
		"plugins disabled": `{"plugins_enabled": false}`,
		"plugins unset":    `{"web_port": 8080}`,
	} {
		t.Run(name, func(t *testing.T) {
			report := runPluginPreflightForTest(t, writePluginPreflightInstall(t, config, plugins))
			if report.Verdict != pluginPreflightOK || len(report.Plugins) != 0 || len(report.Notes) == 0 {
				t.Fatalf("report = %+v, want ok with a note and no plugins", report)
			}
		})
	}
}

func TestPluginPreflightAbsolutePluginsDir(t *testing.T) {
	plugins := writePluginPreflightInstall(t, "", map[string]string{"old_js": pluginPreflightScriptManifest})
	config, _ := json.Marshal(map[string]any{"plugins_enabled": true, "plugins_dir": filepath.Join(plugins, "plugins")})
	report := runPluginPreflightForTest(t, writePluginPreflightInstall(t, string(config), nil))
	if report.Verdict != pluginPreflightBlocked || report.PluginsDir != filepath.Join(plugins, "plugins") {
		t.Fatalf("report = %+v, want the absolute plugins_dir checked", report)
	}
}

func TestClassifyPluginPreflightNativePlugins(t *testing.T) {
	native := func(libraryPath string) LoadedPlugin {
		plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "wan_core", Version: "1.8.0"}, Source: "wan_core", rootDir: "/x"}
		plugin.Control = &PluginControl{Library: map[string]PluginNativeLibrary{
			"x86_64-linux-gnu":   {Path: "lib/x86_64-linux-gnu/libwan_core.so"},
			"aarch64-linux-musl": {Path: "lib/aarch64-linux-musl/libwan_core.so"},
		}}
		plugin.nativeLibraryPath = libraryPath
		return plugin
	}
	declarative := LoadedPlugin{PluginManifest: PluginManifest{ID: "ui_only"}, rootDir: "/x"}
	declarative.Control = &PluginControl{Register: &PluginNativeRegistration{}}
	broken := native("")
	broken.Status, broken.Error = pluginStatusError, "requires wan_core >= 2"
	for _, tc := range []struct {
		name    string
		plugin  LoadedPlugin
		worker  bool
		status  string
		problem string
	}{
		{"runs", native("/x/lib/libwan_core.so"), true, pluginPreflightOK, ""},
		{"no worker", native("/x/lib/libwan_core.so"), false, pluginPreflightBlocked, pluginPreflightNoWorker},
		{"no build for this host", native(""), true, pluginPreflightBlocked, pluginPreflightNoLibrary},
		{"declarative plugins need no worker", declarative, false, pluginPreflightOK, ""},
		{"no control at all", LoadedPlugin{PluginManifest: PluginManifest{ID: "pipeline_only"}, rootDir: "/x"}, false, pluginPreflightOK, ""},
		{"catalog errors only warn", broken, true, pluginPreflightWarning, pluginPreflightCatalogError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPluginPreflight(tc.plugin, "/plugins", "x86_64-linux-musl", tc.worker)
			if got.Status != tc.status || got.Problem != tc.problem {
				t.Fatalf("classify = %+v, want %s %s", got, tc.status, tc.problem)
			}
			if tc.problem == pluginPreflightNoLibrary && !strings.Contains(got.Reason, "x86_64-linux-musl") {
				t.Fatalf("reason %q does not name the host", got.Reason)
			}
		})
	}
}

func TestPluginPreflightTextReport(t *testing.T) {
	dir := writePluginPreflightInstall(t, `{"plugins_enabled": true}`, map[string]string{"old_js": pluginPreflightScriptManifest})
	var stdout, stderr bytes.Buffer
	if _, err := runPluginPackageCLI([]string{"plugin", "preflight", "--install-dir", dir}, &stdout, &stderr); err != nil {
		t.Fatalf("plugin preflight: %v (%s)", err, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, "BLOCKED   old_js 1.0.0: control script control.js") || !strings.Contains(text, "verdict:  blocked - 1 installed plugin(s)") {
		t.Fatalf("text report:\n%s", text)
	}
}
