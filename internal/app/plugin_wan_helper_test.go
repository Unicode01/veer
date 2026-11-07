package app

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestBundledWANCoreHelperBoundaryMigrationAndIsolation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, filepath.Join("..", "..", "plugins", "wan_core"), root)
	plugin, err := loadPluginFromDir(root, "wan_core")
	if err != nil {
		t.Fatal(err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(root)}), nil).(*gojaPluginControlRuntime)
	other := pluginControlNetLinkInfo{Name: "veerother", IfIndex: 999, Kind: "dummy", MTU: 1420, Up: true}
	admin := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"veerother": other}}
	rt.netAdmin = admin
	t.Cleanup(func() { _ = rt.Close() })
	apply := pluginActionByIDForTest(t, plugin, "apply_session")
	payload := json.RawMessage(`{"wan_id":"helper","driver":"pppoe","driver_plugin":"pppoe_client","state":"up","usable":true,"local_interface":"veerlocal0","handoff_mode":"direct_gro","mtu":1492,"ipv4":"198.51.100.2","ipv4_peer":"198.51.100.1","ipv6_link_local":"fe80::2","ipv6_peer_link_local":"fe80::1","pd_prefix":"2001:db8:1::/64","peer_mac":"02:00:00:00:01:01","install_default_route_v6":true}`)
	if err := rt.ApplyPluginAction(plugin, apply, payload); err != nil {
		t.Fatal(err)
	}
	if link := admin.links["veerlocal0"]; link.Kind != "veerwan" {
		t.Fatalf("boundary = %+v", link)
	}
	if len(admin.links) != 2 {
		t.Fatalf("unexpected peer: %+v", admin.links)
	}
	status := func() string {
		record, err := store.GetPluginRecord(db, "wan_core", "status", "helper")
		if err != nil {
			t.Fatal(err)
		}
		return record.DataJSON
	}
	for _, want := range []string{`"handoff_mode":"direct_gro"`, `"pipeline_interface":""`, `"gateway":"fe80::1"`, `"src":"2001:db8:1::/64"`} {
		if !strings.Contains(status(), want) {
			t.Fatalf("status lacks %s: %s", want, status())
		}
	}
	admin.calls = nil
	admin.ensureVethErrors = map[string]error{"veerlocal0": fmt.Errorf("injected create failure")}
	err = rt.ApplyPluginAction(plugin, apply, json.RawMessage(`{"key":"helper","handoff_mode":"segmented_veth","pipeline_interface":"veerpipe0"}`))
	if err == nil || !strings.Contains(err.Error(), "previous WAN handoff restored") {
		t.Fatalf("migration error = %v", err)
	}
	if admin.links["veerlocal0"].Kind != "veerwan" || !strings.Contains(status(), `"handoff_mode":"direct_gro"`) {
		t.Fatalf("rollback lost helper boundary: %s", status())
	}
	if !containsString(admin.calls, "ensureHelperWAN:veerlocal0:1492:true") {
		t.Fatalf("rollback calls: %v", admin.calls)
	}
	if err := rt.ApplyPluginAction(plugin, pluginActionByIDForTest(t, plugin, "teardown"), json.RawMessage(`{"key":"helper"}`)); err != nil {
		t.Fatal(err)
	}
	if _, exists := admin.links["veerlocal0"]; exists {
		t.Fatal("teardown leaked helper boundary")
	}
	if !reflect.DeepEqual(admin.links["veerother"], other) {
		t.Fatal("unrelated WAN was modified")
	}
}
