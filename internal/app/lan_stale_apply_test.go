package app

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

// lan_core profiles are runtime_update manual, so the host does not send them
// resource_apply events by itself today. onResourceApply must still not act on
// a snapshot that a teardown or an API delete has overtaken: a stale enabled
// profile would recreate the bridge, re-enslave its ports and re-enable the
// plans of a LAN that is gone, and nothing would tear them down again.
func TestBundledLANCoreStaleProfileSnapshotAfterTeardownAndDelete(t *testing.T) {
	requireNativePluginRuntimeForTest(t, "lan_core", "wan_core")
	dir := filepath.Join(t.TempDir(), "lan_core")
	copyDirForTest(t, filepath.Join("..", "..", "plugins", "lan_core"), dir)
	plugin, err := loadPluginFromDir(dir, "lan_core")
	if err != nil {
		t.Fatal(err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	profiles := pluginResourceByIDForTest(t, plugin, "profiles")
	apply := pluginActionByIDForTest(t, plugin, "apply_network")
	teardown := pluginActionByIDForTest(t, plugin, "teardown")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(dir)}), nil).(*pluginControlManager)
	controller := &pluginControlNetAdminTest{
		listNames: []string{"brlan0", "lanp0"},
		getErrors: map[string]error{"brlan0": fmt.Errorf("link not found")},
	}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })
	resources := []string{"profiles", "status", "egress_nat_plans", "ipv6_assignment_plans", "dhcpv4_plans"}

	snapshot := func() []PluginResourceRecord {
		t.Helper()
		records, err := loadPluginResourceRecordsWithSecretStore(db, nil, plugin, profiles)
		if err != nil || len(records) != 1 {
			t.Fatalf("profiles snapshot = %+v, %v", records, err)
		}
		return records
	}
	resurrected := func(calls []string) []string {
		var out []string
		for _, call := range calls {
			for _, prefix := range []string{"ensureBridge:", "setMaster:", "addrReplace:"} {
				if strings.HasPrefix(call, prefix) {
					out = append(out, call)
				}
			}
		}
		return out
	}
	enabledRecords := func() []string {
		t.Helper()
		var out []string
		for _, resource := range resources {
			records, err := store.GetPluginRecords(db, "lan_core", resource)
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				if record.Enabled {
					out = append(out, resource+"/"+record.RecordKey)
				}
			}
		}
		return out
	}

	if err := rt.ApplyPluginAction(plugin, apply, json.RawMessage(`{"lan_id":"lab","bridge":"brlan0","ports":["lanp0"],`+
		`"addresses":["192.168.100.1/24"],"wan_egress_interface":"veerwan0","auto_egress_nat":true,"dhcpv4_enabled":true}`)); err != nil {
		t.Fatalf("apply_network: %v", err)
	}
	live := snapshot()
	if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(`{"lan_id":"lab"}`)); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if !containsString(controller.calls, "delete:brlan0") {
		t.Fatalf("teardown did not delete the plugin-created bridge: %v", controller.calls)
	}
	withdrawn := snapshot()
	if !live[0].Enabled || withdrawn[0].Enabled || withdrawn[0].Revision <= live[0].Revision {
		t.Fatalf("teardown did not withdraw the profile: live=%+v withdrawn=%+v", live[0], withdrawn[0])
	}

	// A snapshot taken before the teardown must not bring the LAN back.
	controller.calls = nil
	if err := rt.ApplyPluginResourceData(plugin, profiles, live); err != nil {
		t.Fatalf("stale live snapshot apply after teardown: %v", err)
	}
	if calls := resurrected(controller.calls); len(calls) != 0 {
		t.Fatalf("stale live snapshot after teardown rebuilt the bridge: %v", calls)
	}
	if enabled := enabledRecords(); len(enabled) != 0 {
		t.Fatalf("stale live snapshot after teardown re-enabled records: %v", enabled)
	}
	if record, err := store.GetPluginRecord(db, "lan_core", "status", "lab"); err != nil || !strings.Contains(record.DataJSON, `"phase":"deleted"`) {
		t.Fatalf("status/lab after stale live snapshot = %+v, %v; want phase deleted", record, err)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 0 {
		t.Fatalf("stale live snapshot after teardown armed timers: %+v", timers)
	}

	// The profile is then deleted through the API, which leaves the
	// control-only status and plan records behind.
	if err := store.DeletePluginRecord(db, "lan_core", "profiles", "lab"); err != nil {
		t.Fatal(err)
	}
	before := staleApplyRecordsForTest(t, db, "lan_core", resources...)
	controller.calls = nil
	for _, stale := range []struct {
		name    string
		records []PluginResourceRecord
	}{{"withdrawn", withdrawn}, {"live", live}} {
		if err := rt.ApplyPluginResourceData(plugin, profiles, stale.records); err != nil {
			t.Fatalf("stale %s snapshot apply after delete: %v", stale.name, err)
		}
		if after := staleApplyRecordsForTest(t, db, "lan_core", resources...); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Fatalf("stale %s snapshot after delete changed records:\nbefore:\n%s\nafter:\n%s",
				stale.name, strings.Join(before, "\n"), strings.Join(after, "\n"))
		}
	}
	if len(controller.calls) != 0 {
		t.Fatalf("stale snapshots after delete touched the network: %v", controller.calls)
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 0 {
		t.Fatalf("stale snapshots after delete armed timers: %+v", timers)
	}
}
