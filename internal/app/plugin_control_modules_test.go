package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

func TestPluginControlModuleLoaderCachesRelativeModulesAndCycles(t *testing.T) {
	root := t.TempDir()
	writePluginControlModuleTestFile(t, root, "control.js", `
var stateA = require('./lib/state');
var stateB = require('./lib/state.js');
var cycle = require('./lib/cycle/a');
module.exports.result = function () {
  return {same: stateA === stateB, loads: stateA.loads, nested: stateA.nested, cycle: cycle};
};
`)
	writePluginControlModuleTestFile(t, root, "lib/state.js", `
if (typeof moduleLoadCount === 'undefined') moduleLoadCount = 0;
moduleLoadCount++;
module.exports = {loads: moduleLoadCount, nested: require('./nested').value};
`)
	writePluginControlModuleTestFile(t, root, "lib/nested/index.js", `module.exports = {value: 'nested-ok'};`)
	writePluginControlModuleTestFile(t, root, "lib/cycle/a.js", `
exports.name = 'a';
var b = require('./b');
exports.from_b = b.name;
exports.b_saw = b.from_a;
`)
	writePluginControlModuleTestFile(t, root, "lib/cycle/b.js", `
exports.name = 'b';
var a = require('./a');
exports.from_a = a.name;
`)

	plugin := pluginControlModuleTestPlugin(t, root)
	runtime := goja.New()
	exports := runtime.NewObject()
	module := runtime.NewObject()
	if err := module.Set("exports", exports); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Set("exports", exports); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Set("module", module); err != nil {
		t.Fatal(err)
	}
	mainID, err := pluginControlMainModuleID(plugin)
	if err != nil {
		t.Fatal(err)
	}
	if err := installPluginControlModuleLoader(runtime, mainID, module, func(referrer, request string) (pluginControlModuleSource, error) {
		return resolvePluginControlModule(plugin, referrer, request)
	}); err != nil {
		t.Fatal(err)
	}
	source, err := readPluginControlScript(plugin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.RunScript(mainID, source); err != nil {
		t.Fatal(err)
	}
	resultFunction, ok := goja.AssertFunction(module.Get("exports").ToObject(runtime).Get("result"))
	if !ok {
		t.Fatal("main module result export is not callable")
	}
	result, err := resultFunction(goja.Undefined())
	if err != nil {
		t.Fatal(err)
	}
	value, ok := result.Export().(map[string]any)
	if !ok {
		t.Fatalf("result = %#v", result.Export())
	}
	if value["same"] != true || value["loads"] != int64(1) || value["nested"] != "nested-ok" {
		t.Fatalf("module result = %#v", value)
	}
	cycle, ok := value["cycle"].(map[string]any)
	if !ok || cycle["name"] != "a" || cycle["from_b"] != "b" || cycle["b_saw"] != "a" {
		t.Fatalf("cycle result = %#v", value["cycle"])
	}
}

func TestPluginControlModuleResolverRejectsBareAndEscapingPaths(t *testing.T) {
	root := t.TempDir()
	writePluginControlModuleTestFile(t, root, "control.js", `module.exports = {};`)
	plugin := pluginControlModuleTestPlugin(t, root)
	for _, request := range []string{"fs", "/absolute.js", "../outside.js", ".\\windows.js", "./config.json"} {
		if _, err := resolvePluginControlModule(plugin, "control.js", request); err == nil {
			t.Fatalf("resolvePluginControlModule(%q) succeeded", request)
		}
	}
}

func TestPluginControlModuleResolverRejectsOversizedModule(t *testing.T) {
	root := t.TempDir()
	writePluginControlModuleTestFile(t, root, "control.js", `module.exports = {};`)
	writePluginControlModuleTestFile(t, root, "large.js", strings.Repeat("x", pluginControlModuleMaxBytes+1))
	plugin := pluginControlModuleTestPlugin(t, root)
	if _, err := resolvePluginControlModule(plugin, "control.js", "./large"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized module error = %v", err)
	}
}

func TestPluginControlModuleLoaderRetriesFailedModuleWithoutPoisoningCache(t *testing.T) {
	runtime := goja.New()
	mainModule := runtime.NewObject()
	if err := mainModule.Set("exports", runtime.NewObject()); err != nil {
		t.Fatal(err)
	}
	resolves := 0
	if err := installPluginControlModuleLoader(runtime, "control.js", mainModule, func(_, _ string) (pluginControlModuleSource, error) {
		resolves++
		if resolves == 1 {
			return pluginControlModuleSource{ID: "retry.js", Source: `throw new Error("first load fails");`}, nil
		}
		return pluginControlModuleSource{ID: "retry.js", Source: `module.exports = {value: "ok"};`}, nil
	}); err != nil {
		t.Fatal(err)
	}
	value, err := runtime.RunString(`
var firstFailed = false;
try { require('./retry'); } catch (error) { firstFailed = true; }
var retry = require('./retry');
({firstFailed: firstFailed, value: retry.value});
`)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.Export().(map[string]any)
	if !ok || result["firstFailed"] != true || result["value"] != "ok" || resolves != 2 {
		t.Fatalf("retry result = %#v, resolves=%d", value.Export(), resolves)
	}
}

func TestNormalizePluginControlModuleIDRejectsNativeAbsoluteOrVolumePath(t *testing.T) {
	for _, value := range []string{"/absolute.js", `\\absolute.js`} {
		if _, err := normalizePluginControlModuleID(value); err == nil {
			t.Fatalf("normalizePluginControlModuleID(%q) succeeded", value)
		}
	}
	if filepath.VolumeName(filepath.FromSlash("C:/absolute.js")) != "" {
		if _, err := normalizePluginControlModuleID("C:/absolute.js"); err == nil {
			t.Fatal("native volume path was accepted")
		}
	}
}

func TestPluginControlMainModuleIDUsesResolvedBasenameWithoutPluginRoot(t *testing.T) {
	plugin := LoadedPlugin{
		PluginManifest:  PluginManifest{Control: &PluginControl{}},
		controlMainPath: filepath.Join(t.TempDir(), "control.js"),
	}
	moduleID, err := pluginControlMainModuleID(plugin)
	if err != nil {
		t.Fatal(err)
	}
	if moduleID != "control.js" {
		t.Fatalf("module id = %q, want control.js", moduleID)
	}
}

func pluginControlModuleTestPlugin(t *testing.T, root string) LoadedPlugin {
	t.Helper()
	mainPath, err := filepath.EvalSymlinks(filepath.Join(root, "control.js"))
	if err != nil {
		t.Fatal(err)
	}
	return LoadedPlugin{
		PluginManifest:  PluginManifest{ID: "module_test", Control: &PluginControl{Main: "control.js"}},
		rootDir:         root,
		controlMainPath: mainPath,
	}
}

func writePluginControlModuleTestFile(t *testing.T, root, name, value string) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
