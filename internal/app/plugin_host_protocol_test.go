package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPluginHostJSONValueRejectsTrailingJSON(t *testing.T) {
	if _, err := decodePluginHostJSONValue(json.RawMessage(`{"ok":true}[]`)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing value error = %v", err)
	}
}

func TestPluginHostJSONDepthLimit(t *testing.T) {
	var value any = map[string]any{"leaf": true}
	for i := 0; i <= pluginHostMaxJSONDepth; i++ {
		value = map[string]any{"next": value}
	}
	if err := validatePluginHostJSONValue(value, 0); err == nil || !strings.Contains(err.Error(), "nesting exceeds") {
		t.Fatalf("depth error = %v", err)
	}
}

// A handler name must be the script's own export, not an inherited
// property such as constructor.
func TestPluginControlScriptRejectsInheritedHandler(t *testing.T) {
	plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "handler_guard", Control: &PluginControl{Main: "control.js"}}}
	plugin.rootDir = t.TempDir()
	host := &pluginControlHost{vm: nil, plugin: plugin}
	script, err := newGojaTestControlScript(host, plugin, `exports.onAction = function () {};`, time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	_, err = script.run(pluginHostEventRequest{Handler: "constructor", Context: map[string]any{}}, time.Now().Add(time.Second))
	if err == nil || !strings.Contains(err.Error(), "does not export constructor") {
		t.Fatalf("constructor handler error = %v", err)
	}
}
