package app

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

// vtolocal links use runtime_apply, so the host loads a resource_apply
// snapshot (after an API mutation or a vtolocal_repair tick) before the event
// waits for the plugin queue. A teardown, or a teardown followed by an API
// delete of the link, can run in that gap. Applying the stale snapshot
// afterwards must not bring back the dummy, its addresses and routes, or the
// deleted link record.
func TestBundledVToLocalStaleLinkSnapshotAfterTeardownAndDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "vtolocal")
	copyDirForTest(t, filepath.Join("..", "..", "plugins", "vtolocal"), dir)
	plugin, err := loadPluginFromDir(dir, "vtolocal")
	if err != nil {
		t.Fatal(err)
	}
	links := pluginResourceByIDForTest(t, plugin, "links")
	apply := pluginActionByIDForTest(t, plugin, "apply")
	teardown := pluginActionByIDForTest(t, plugin, "teardown")
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(dir)}), nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	rt.netAdmin = controller
	t.Cleanup(func() { _ = rt.Close() })

	snapshot := func() []PluginResourceRecord {
		t.Helper()
		records, err := loadPluginResourceRecordsWithSecretStore(db, nil, plugin, links)
		if err != nil || len(records) != 1 {
			t.Fatalf("links snapshot = %+v, %v", records, err)
		}
		return records
	}
	resurrected := func(calls []string) []string {
		var out []string
		for _, call := range calls {
			for _, prefix := range []string{"ensureDummy:", "addrReplace:", "routeReplace:"} {
				if strings.HasPrefix(call, prefix) {
					out = append(out, call)
				}
			}
		}
		return out
	}

	if err := rt.ApplyPluginAction(plugin, apply, json.RawMessage(`{"profile_key":"lab","local_interface":"veerlocal3",`+
		`"addresses":["169.254.253.3/32"],"routes":[{"dst":"10.99.0.0/16","dev":"veerlocal3"}]}`)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	live := snapshot()
	if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(`{"profile_key":"lab"}`)); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	withdrawn := snapshot()
	if !live[0].Enabled || withdrawn[0].Enabled || withdrawn[0].Revision <= live[0].Revision {
		t.Fatalf("teardown did not withdraw the link: live=%+v withdrawn=%+v", live[0], withdrawn[0])
	}

	// A snapshot taken before the teardown must not bring the dummy back.
	controller.calls = nil
	if err := rt.ApplyPluginResourceData(plugin, links, live); err != nil {
		t.Fatalf("stale live snapshot apply after teardown: %v", err)
	}
	if calls := resurrected(controller.calls); len(calls) != 0 {
		t.Fatalf("stale live snapshot after teardown rebuilt the link: %v", calls)
	}
	if record, err := store.GetPluginRecord(db, "vtolocal", "links", "lab"); err != nil || record.Enabled {
		t.Fatalf("links/lab after stale live snapshot = %+v, %v; want disabled", record, err)
	}
	if record, err := store.GetPluginRecord(db, "vtolocal", "status", "lab"); err != nil || !strings.Contains(record.DataJSON, `"phase":"deleted"`) {
		t.Fatalf("status/lab after stale live snapshot = %+v, %v; want phase deleted", record, err)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("stale live snapshot after teardown armed timers: %+v", timers)
	}

	// The link record is then deleted through the API, which leaves the
	// control-only status record behind.
	if err := store.DeletePluginRecord(db, "vtolocal", "links", "lab"); err != nil {
		t.Fatal(err)
	}
	before := staleApplyRecordsForTest(t, db, "vtolocal", "links", "status")
	controller.calls = nil
	for _, stale := range []struct {
		name    string
		records []PluginResourceRecord
	}{{"withdrawn", withdrawn}, {"live", live}} {
		if err := rt.ApplyPluginResourceData(plugin, links, stale.records); err != nil {
			t.Fatalf("stale %s snapshot apply after delete: %v", stale.name, err)
		}
		if after := staleApplyRecordsForTest(t, db, "vtolocal", "links", "status"); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Fatalf("stale %s snapshot after delete changed records:\nbefore:\n%s\nafter:\n%s",
				stale.name, strings.Join(before, "\n"), strings.Join(after, "\n"))
		}
	}
	if len(controller.calls) != 0 {
		t.Fatalf("stale snapshots after delete touched the network: %v", controller.calls)
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("stale snapshots after delete armed timers: %+v", timers)
	}
}

// staleApplyRecordsForTest lists a plugin's stored records as sorted
// "resource/key enabled=... rev=...: data" lines.
func staleApplyRecordsForTest(t *testing.T, db store.RuleStore, pluginID string, resources ...string) []string {
	t.Helper()
	var out []string
	for _, resource := range resources {
		records, err := store.GetPluginRecords(db, pluginID, resource)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			out = append(out, fmt.Sprintf("%s/%s enabled=%t rev=%d: %s",
				resource, record.RecordKey, record.Enabled, record.Revision, record.DataJSON))
		}
	}
	sort.Strings(out)
	return out
}
