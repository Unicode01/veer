package app

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestWANWithdrawalPreservesBoundaryIdentityForRetry(t *testing.T) {
	for _, mode := range []string{"direct", "segmented_veth"} {
		t.Run(mode, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "wan_core")
			copyDirForTest(t, filepath.Join("..", "..", "plugins", "wan_core"), dir)
			plugin, err := loadPluginFromDir(dir, "wan_core")
			if err != nil {
				t.Fatal(err)
			}
			plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
			var prepare PluginAction
			for _, a := range plugin.Actions {
				if a.ID == "prepare_handoff" {
					prepare = a
				}
			}
			db := openTestDB(t)
			rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(dir)}), nil).(*gojaPluginControlRuntime)
			rt.netAdmin = &pluginControlNetAdminTest{}
			t.Cleanup(func() { _ = rt.Close() })
			payload, _ := json.Marshal(map[string]any{"wan_id": "vpn", "driver_plugin": "vpn_core", "local_interface": "veerlocal0", "pipeline_interface": "veerpipe0", "handoff_mode": mode, "state": "prepared", "usable": false})
			if err := rt.ApplyPluginAction(plugin, prepare, payload); err != nil {
				t.Fatal(err)
			}
			read := func() map[string]any {
				t.Helper()
				record, err := store.GetPluginRecord(db, "wan_core", "status", "vpn")
				if err != nil {
					t.Fatal(err)
				}
				var value map[string]any
				if err := json.Unmarshal([]byte(record.DataJSON), &value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := read()
			for _, enabled := range []bool{false, true} {
				if err := rt.ApplyPluginResourceData(plugin, pluginResourceByIDForTest(t, plugin, "sessions"), []PluginResourceRecord{{Key: "vpn", Enabled: enabled, Data: payload}}); err != nil {
					t.Fatal(err)
				}
				after := read()
				for _, field := range []string{"local_ifindex", "local_mac", "pipeline_ifindex", "pipeline_mac"} {
					want := before[field]
					if want == nil {
						if field == "pipeline_ifindex" {
							want = float64(0)
						} else {
							want = ""
						}
					}
					if after[field] != want {
						t.Fatalf("withdrawal lost %s: before=%v after=%v", field, before, after)
					}
				}
				if err := rt.ApplyPluginAction(plugin, prepare, payload); err != nil {
					t.Fatalf("retry: %v", err)
				}
			}
		})
	}
}
