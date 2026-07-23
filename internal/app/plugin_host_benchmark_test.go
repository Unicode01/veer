package app

import (
	"testing"
	"time"

	"github.com/dop251/goja"
)

func BenchmarkPluginControlNoopEvent(b *testing.B) {
	b.Run("in_process", func(b *testing.B) {
		vm := goja.New()
		exports := vm.NewObject()
		module := vm.NewObject()
		if err := exports.Set("onAction", func(goja.FunctionCall) goja.Value { return goja.Undefined() }); err != nil {
			b.Fatal(err)
		}
		if err := module.Set("exports", exports); err != nil {
			b.Fatal(err)
		}
		host := &pluginControlHost{
			vm: vm, module: module,
			plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: "bench_plugin", Control: &PluginControl{Main: "control.js"}}},
		}
		event := pluginControlEvent{Kind: "action", Action: &PluginAction{ID: "apply"}}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, _, err := host.runEvent(event, false); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("isolated_process", func(b *testing.B) {
		cfg := isolatedPluginsTestConfig(&Config{})
		plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "bench_plugin", Control: &PluginControl{Main: "control.js"}}}
		client, err := startPluginHostClient(cfg, plugin, "control", "", `exports.onAction = function () {};`, nil)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(client.Close)
		request := pluginHostEventRequest{Handler: "onAction", Context: map[string]any{}}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := client.runEvent(request, nil, time.Now().Add(pluginControlTimeout), false); err != nil {
				b.Fatal(err)
			}
		}
	})
}
