package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

// The host loads a resource_apply snapshot before the event waits for the
// plugin queue. A teardown with forget can run in that gap (for example after
// a wan_repair tick while vpn_core deletes a profile). Applying the stale
// snapshot afterwards must not resurrect any record or boundary of the
// forgotten WAN.
func TestWANStaleSessionSnapshotAfterForgetLeavesNoRecords(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, filepath.Join("..", "..", "plugins", "wan_core"), dir)
	plugin, err := loadPluginFromDir(dir, "wan_core")
	if err != nil {
		t.Fatal(err)
	}
	plugin = pluginWithRuntimeSurfaceForTest(t, plugin)
	actions := map[string]PluginAction{}
	for _, action := range plugin.Actions {
		actions[action.ID] = action
	}
	sessions := pluginResourceByIDForTest(t, plugin, "sessions")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(dir)}), nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	session := map[string]any{"wan_id": "vpn", "driver": "mihomo", "driver_plugin": "vpn_core", "profile_key": "mh1",
		"real_interface": "vtunmh1", "local_interface": "veervpn2", "handoff_mode": "direct", "ipv4": "10.78.2.1"}
	call := func(id string, fields map[string]any) {
		t.Helper()
		payload := map[string]any{}
		for k, v := range session {
			payload[k] = v
		}
		for k, v := range fields {
			payload[k] = v
		}
		data, _ := json.Marshal(payload)
		if err := rt.ApplyPluginAction(plugin, actions[id], data); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	snapshot := func() []PluginResourceRecord {
		t.Helper()
		records, err := loadPluginResourceRecordsWithSecretStore(db, nil, plugin, sessions)
		if err != nil || len(records) != 1 {
			t.Fatalf("session snapshot = %+v, %v", records, err)
		}
		return records
	}
	leftovers := func() []string {
		t.Helper()
		var out []string
		for _, resource := range []string{"profiles", "sessions", "status"} {
			records, err := store.GetPluginRecords(db, "wan_core", resource)
			if err != nil {
				t.Fatal(err)
			}
			for _, record := range records {
				out = append(out, resource+"/"+record.RecordKey+": "+record.DataJSON)
			}
		}
		return out
	}

	call("apply_session", map[string]any{"state": "up", "usable": true})
	live := snapshot()
	down := map[string]any{"state": "down", "usable": false}
	call("teardown", down)
	withdrawn := snapshot()
	if withdrawn[0].Enabled || withdrawn[0].Revision <= live[0].Revision {
		t.Fatalf("teardown did not withdraw the session: live=%+v withdrawn=%+v", live[0], withdrawn[0])
	}
	down["forget"] = true
	call("teardown", down)
	if left := leftovers(); len(left) != 0 {
		t.Fatalf("forget left records:\n%s", strings.Join(left, "\n"))
	}
	calls := len(controller.calls)
	for name, records := range map[string][]PluginResourceRecord{"withdrawn": withdrawn, "live": live} {
		if err := rt.ApplyPluginResourceData(plugin, sessions, records); err != nil {
			t.Fatalf("stale %s snapshot apply: %v", name, err)
		}
		if left := leftovers(); len(left) != 0 {
			t.Fatalf("stale %s snapshot recreated records:\n%s", name, strings.Join(left, "\n"))
		}
	}
	if extra := controller.calls[calls:]; len(extra) != 0 {
		t.Fatalf("stale snapshots touched the network: %v", extra)
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 0 {
		t.Fatalf("stale snapshots armed timers: %+v", timers)
	}
}
