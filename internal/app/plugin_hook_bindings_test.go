package app

import (
	"database/sql"
	"reflect"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestRequiredPluginHookBindingsNeverBecomeGlobal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		data     string
		disabled bool
		storage  string
		want     []string
	}{
		{name: "first load"},
		{name: "nil database", storage: "nil"},
		{name: "failed database read", storage: "closed"},
		{name: "undeclared resource", storage: "undeclared"},
		{name: "disabled", data: `{"interfaces":["vpn0"]}`, disabled: true},
		{name: "empty interfaces", data: `{"interfaces":[]}`},
		{name: "invalid interfaces", data: `{"interfaces":["bad name"]}`},
		{name: "invalid JSON", data: `{`},
		{name: "wrong hook", data: `{"hook_id":"other","interfaces":["vpn0"]}`},
		{name: "bound", data: `{"interfaces":["vpn0","peer0"]}`, want: []string{"peer0", "vpn0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var db *sql.DB
			if tc.storage != "nil" {
				db = openTestDB(t)
				if tc.data != "" {
					if _, err := store.AddPluginRecord(db, &store.PluginRecord{PluginID: "adapter", ResourceID: pluginHookBindingsResourceID, RecordKey: "link", DataJSON: tc.data, Enabled: !tc.disabled}); err != nil {
						t.Fatal(err)
					}
				}
				if tc.storage == "closed" {
					_ = db.Close()
				}
			}
			for _, engine := range []string{kernelEngineTC, kernelEngineXDP} {
				for _, fallback := range [][]string{nil, {"old0"}} {
					plugin := LoadedPlugin{PluginManifest: PluginManifest{ID: "adapter"}, Status: pluginStatusActive,
						Resources: []PluginResource{{ID: pluginHookBindingsResourceID}},
						Hooks: []PluginHook{
							{ID: "link", Engine: engine, BindingRequired: true, Interfaces: fallback},
							{ID: "global", Engine: kernelEngineTC},
							{ID: "static", Engine: kernelEngineTC, Interfaces: []string{"eth0"}},
						}}
					if tc.storage == "undeclared" {
						plugin.Resources = nil
					}
					got := applyPluginHookBindingsFromDB(PluginCatalog{Plugins: []LoadedPlugin{plugin}}, db).Plugins[0].Hooks
					want := plugin.Hooks[1:]
					if tc.want != nil {
						hook := plugin.Hooks[0]
						hook.Interfaces = tc.want
						want = append([]PluginHook{hook}, want...)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("engine=%s fallback=%v hooks=%+v, want %+v", engine, fallback, got, want)
					}
				}
			}
		})
	}
}

func TestRequiredPluginHookBindingEngineAndFeature(t *testing.T) {
	for _, engine := range []string{kernelEngineTC, kernelEngineXDP, "control", pluginEngineNetfilter} {
		hook := PluginHook{ID: "link", Engine: engine, Stage: "pre_forward", Program: "adapter:forward", BindingRequired: true}
		if engine == pluginEngineNetfilter {
			hook.Stage = ""
			hook.NetfilterHook = "forward"
		}
		err := normalizePluginHook(&hook)
		if wantErr := engine != kernelEngineTC && engine != kernelEngineXDP; (err != nil) != wantErr {
			t.Fatalf("engine=%s error=%v, want error=%v", engine, err, wantErr)
		}
	}
	features := pluginRequiredHostFeatures(LoadedPlugin{Hooks: []PluginHook{{BindingRequired: true}}})
	if !reflect.DeepEqual(features, []string{"dataplane.hook_bindings.v1"}) {
		t.Fatalf("required features = %v", features)
	}
}
