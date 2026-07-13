//go:build linux

package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"

	"github.com/vishvananda/netlink"
)

// These tests touch the host network namespace. They are opt-in because they
// create and delete Linux bridge/dummy/veth links to validate real plugin net.admin
// behavior, not just the mocked control-plane path.
const pluginIntegrationEnableEnv = "FORWARD_RUN_PLUGIN_INTEGRATION_TEST"

func TestPluginWANCoreLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "wan_core")
	defer rt.Close()

	local := pluginIntegrationLinkName("veerl")
	defer deletePluginIntegrationLinkQuietly(t, local)

	session := fmt.Sprintf(`{
		"wan_id":"itest",
		"state":"up",
		"usable":true,
		"driver":"integration",
		"driver_plugin":"test",
		"real_interface":"eth-test",
		"local_interface":%q,
		"ipv4":"169.254.240.1",
		"mtu":1400
	}`, local)
	addPluginIntegrationRecord(t, db, plugin.ID, "sessions", "itest", session, true)

	resource := pluginResourceByIDForTest(t, plugin, "sessions")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(session),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	assertPluginIntegrationDummy(t, local, 1400)
	assertPluginIntegrationLinkHasCIDR(t, local, "169.254.240.1/32")
	waitForPluginRecordContainingForTest(t, db, "wan_core", "status", "itest", 2*time.Second, `"phase":"applied"`, `"veer_parent_interface":`)

	if err := deletePluginIntegrationLink(local); err != nil {
		t.Fatalf("delete wan local dummy %s: %v", local, err)
	}
	firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	assertPluginIntegrationDummy(t, local, 1400)

	updatedSession := fmt.Sprintf(`{
		"wan_id":"itest",
		"state":"up",
		"usable":true,
		"driver":"integration",
		"driver_plugin":"test",
		"real_interface":"eth-test",
		"local_interface":%q,
		"ipv4":"169.254.240.2",
		"mtu":1400
	}`, local)
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(updatedSession),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core updated session) error = %v", err)
	}
	assertPluginIntegrationLinkHasCIDR(t, local, "169.254.240.2/32")
	assertPluginIntegrationLinkLacksCIDR(t, local, "169.254.240.1/32")

	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(updatedSession),
		Enabled: false,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core disabled session) error = %v", err)
	}
	assertPluginIntegrationDummy(t, local, 1400)
	assertPluginIntegrationLinkLacksCIDR(t, local, "169.254.240.2/32")

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"wan_id":"itest","local_interface":%q}`, local))); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
	}
	assertPluginIntegrationLinkAbsent(t, local)
	record, err := store.GetPluginRecord(db, "wan_core", "sessions", "itest")
	if err != nil {
		t.Fatalf("GetPluginRecord(wan_core sessions/itest) error = %v", err)
	}
	if record.Enabled {
		t.Fatalf("wan_core sessions/itest enabled = true, want false after teardown")
	}
	if timers := rt.pluginTimerList("wan_core"); len(timers) != 0 {
		t.Fatalf("wan_core timers after teardown = %+v, want none", timers)
	}
}

func TestPluginVToLocalLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "vtolocal")
	defer rt.Close()

	local := pluginIntegrationLinkName("veerl")
	defer deletePluginIntegrationLinkQuietly(t, local)

	link := fmt.Sprintf(`{
		"profile_key":"itest",
		"local_interface":%q,
		"addresses":["169.254.241.1/32"],
		"mtu":1400
	}`, local)
	addPluginIntegrationRecord(t, db, plugin.ID, "links", "itest", link, true)

	resource := pluginResourceByIDForTest(t, plugin, "links")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(link),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	assertPluginIntegrationDummy(t, local, 1400)
	assertPluginIntegrationLinkHasCIDR(t, local, "169.254.241.1/32")

	if err := deletePluginIntegrationLink(local); err != nil {
		t.Fatalf("delete vtolocal dummy %s: %v", local, err)
	}
	firePluginTimerForTest(t, rt, "vtolocal", "vtolocal_repair")
	assertPluginIntegrationDummy(t, local, 1400)

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"profile_key":"itest","local_interface":%q}`, local))); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
	}
	assertPluginIntegrationLinkAbsent(t, local)
	record, err := store.GetPluginRecord(db, "vtolocal", "links", "itest")
	if err != nil {
		t.Fatalf("GetPluginRecord(vtolocal links/itest) error = %v", err)
	}
	if record.Enabled {
		t.Fatalf("vtolocal links/itest enabled = true, want false after teardown")
	}
	if timers := rt.pluginTimerList("vtolocal"); len(timers) != 0 {
		t.Fatalf("vtolocal timers after teardown = %+v, want none", timers)
	}
}

func TestPluginLANCoreLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "lan_core")
	defer rt.Close()

	bridge := pluginIntegrationLinkName("brl")
	port := pluginIntegrationLinkName("fwp")
	portPeer := pluginIntegrationLinkName("fwq")
	wan := pluginIntegrationLinkName("fww")
	wanPeer := pluginIntegrationLinkName("fwx")
	defer deletePluginIntegrationLinkQuietly(t, bridge)
	defer deletePluginIntegrationLinkQuietly(t, port)
	defer deletePluginIntegrationLinkQuietly(t, portPeer)
	defer deletePluginIntegrationLinkQuietly(t, wan)
	defer deletePluginIntegrationLinkQuietly(t, wanPeer)

	createPluginIntegrationVeth(t, port, portPeer)
	createPluginIntegrationVeth(t, wan, wanPeer)

	profile := fmt.Sprintf(`{
		"lan_id":"itest",
		"bridge":%q,
		"ports":[%q],
		"addresses":["192.0.2.1/24"],
		"wan_egress_interface":%q,
		"wan_egress_source_ip":"192.0.2.254",
		"auto_egress_nat":true,
		"protocol":"tcp+udp",
		"nat_type":"symmetric",
		"mtu":1500
	}`, bridge, port, wan)
	addPluginIntegrationRecord(t, db, plugin.ID, "profiles", "itest", profile, true)

	resource := pluginResourceByIDForTest(t, plugin, "profiles")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(profile),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core profiles) error = %v", err)
	}
	assertPluginIntegrationBridge(t, bridge, 1500)
	assertPluginIntegrationLinkMaster(t, port, bridge)
	assertPluginIntegrationLinkHasCIDR(t, bridge, "192.0.2.1/24")
	waitForPluginRecordContainingForTest(t, db, "lan_core", "status", "itest", 2*time.Second, `"phase":"applied"`, `"bridge":`+strconv.Quote(bridge))
	plan := waitForPluginRecordContainingForTest(t, db, "lan_core", "egress_nat_plans", "itest", 2*time.Second, `"enabled":true`, `"redirect_mode":""`, `"out_interface":`+strconv.Quote(wan))
	if !plan.Enabled {
		t.Fatalf("lan_core egress_nat_plans/itest record enabled = false, want true")
	}

	if err := deletePluginIntegrationLink(bridge); err != nil {
		t.Fatalf("delete lan bridge %s: %v", bridge, err)
	}
	firePluginTimerForTest(t, rt, "lan_core", "lan_repair")
	assertPluginIntegrationBridge(t, bridge, 1500)
	assertPluginIntegrationLinkMaster(t, port, bridge)

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"lan_id":"itest","bridge":%q,"ports":[%q],"wan_egress_interface":%q}`, bridge, port, wan))); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	assertPluginIntegrationLinkAbsent(t, bridge)
	profileRecord, err := store.GetPluginRecord(db, "lan_core", "profiles", "itest")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core profiles/itest) error = %v", err)
	}
	if profileRecord.Enabled {
		t.Fatalf("lan_core profiles/itest enabled = true, want false after teardown")
	}
	planRecord, err := store.GetPluginRecord(db, "lan_core", "egress_nat_plans", "itest")
	if err != nil {
		t.Fatalf("GetPluginRecord(lan_core egress_nat_plans/itest) error = %v", err)
	}
	if planRecord.Enabled {
		t.Fatalf("lan_core egress_nat_plans/itest enabled = true, want false after teardown")
	}
	if timers := rt.pluginTimerList("lan_core"); len(timers) != 0 {
		t.Fatalf("lan_core timers after teardown = %+v, want none", timers)
	}
}

func TestPluginActionApplyPersistsAndRepairsLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	t.Run("wan_core", func(t *testing.T) {
		plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "wan_core")
		defer rt.Close()

		local := pluginIntegrationLinkName("veerl")
		defer deletePluginIntegrationLinkQuietly(t, local)

		action := pluginActionByIDForTest(t, plugin, "apply_session")
		payload := fmt.Sprintf(`{
			"wan_id":"action",
			"state":"up",
			"usable":true,
			"driver":"integration",
			"driver_plugin":"test",
			"real_interface":"eth-test",
			"local_interface":%q,
			"addresses":["169.254.242.1/32"],
			"mtu":1400
		}`, local)
		if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(payload)); err != nil {
			t.Fatalf("ApplyPluginAction(wan_core apply_session) error = %v", err)
		}
		assertPluginIntegrationDummy(t, local, 1400)
		assertPluginIntegrationEnabledRecord(t, db, "wan_core", "sessions", "action")
		assertPluginIntegrationEnabledRecord(t, db, "wan_core", "profiles", "action")
		assertPluginIntegrationTimer(t, rt, "wan_core", "wan_repair")

		if err := deletePluginIntegrationLink(local); err != nil {
			t.Fatalf("delete action wan local dummy %s: %v", local, err)
		}
		firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
		assertPluginIntegrationDummy(t, local, 1400)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"wan_id":"action","local_interface":%q}`, local))); err != nil {
			t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
		}
		assertPluginIntegrationLinkAbsent(t, local)
	})

	t.Run("vtolocal", func(t *testing.T) {
		plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "vtolocal")
		defer rt.Close()

		local := pluginIntegrationLinkName("veerl")
		defer deletePluginIntegrationLinkQuietly(t, local)

		action := pluginActionByIDForTest(t, plugin, "apply")
		payload := fmt.Sprintf(`{
			"profile_key":"action",
			"local_interface":%q,
			"addresses":["169.254.243.1/32"],
			"mtu":1400
		}`, local)
		if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(payload)); err != nil {
			t.Fatalf("ApplyPluginAction(vtolocal apply) error = %v", err)
		}
		assertPluginIntegrationDummy(t, local, 1400)
		assertPluginIntegrationEnabledRecord(t, db, "vtolocal", "links", "action")
		assertPluginIntegrationTimer(t, rt, "vtolocal", "vtolocal_repair")

		if err := deletePluginIntegrationLink(local); err != nil {
			t.Fatalf("delete action vtolocal dummy %s: %v", local, err)
		}
		firePluginTimerForTest(t, rt, "vtolocal", "vtolocal_repair")
		assertPluginIntegrationDummy(t, local, 1400)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"profile_key":"action","local_interface":%q}`, local))); err != nil {
			t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
		}
		assertPluginIntegrationLinkAbsent(t, local)
	})

	t.Run("lan_core", func(t *testing.T) {
		plugin, db, rt := loadPluginIntegrationControlRuntimeForTest(t, "lan_core")
		defer rt.Close()

		bridge := pluginIntegrationLinkName("bra")
		port := pluginIntegrationLinkName("fwp")
		portPeer := pluginIntegrationLinkName("fwq")
		wan := pluginIntegrationLinkName("fww")
		wanPeer := pluginIntegrationLinkName("fwx")
		defer deletePluginIntegrationLinkQuietly(t, bridge)
		defer deletePluginIntegrationLinkQuietly(t, port)
		defer deletePluginIntegrationLinkQuietly(t, portPeer)
		defer deletePluginIntegrationLinkQuietly(t, wan)
		defer deletePluginIntegrationLinkQuietly(t, wanPeer)

		createPluginIntegrationVeth(t, port, portPeer)
		createPluginIntegrationVeth(t, wan, wanPeer)

		action := pluginActionByIDForTest(t, plugin, "apply_network")
		payload := fmt.Sprintf(`{
			"lan_id":"action",
			"bridge":%q,
			"ports":[%q],
			"addresses":["192.0.3.1/24"],
			"wan_egress_interface":%q,
			"wan_egress_source_ip":"192.0.3.254",
			"auto_egress_nat":true,
			"protocol":"tcp+udp",
			"mtu":1500
		}`, bridge, port, wan)
		if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(payload)); err != nil {
			t.Fatalf("ApplyPluginAction(lan_core apply_network) error = %v", err)
		}
		assertPluginIntegrationBridge(t, bridge, 1500)
		assertPluginIntegrationLinkMaster(t, port, bridge)
		assertPluginIntegrationEnabledRecord(t, db, "lan_core", "profiles", "action")
		assertPluginIntegrationEnabledRecord(t, db, "lan_core", "egress_nat_plans", "action")
		assertPluginIntegrationTimer(t, rt, "lan_core", "lan_repair")

		if err := deletePluginIntegrationLink(bridge); err != nil {
			t.Fatalf("delete action lan bridge %s: %v", bridge, err)
		}
		firePluginTimerForTest(t, rt, "lan_core", "lan_repair")
		assertPluginIntegrationBridge(t, bridge, 1500)
		assertPluginIntegrationLinkMaster(t, port, bridge)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"lan_id":"action","bridge":%q,"ports":[%q],"wan_egress_interface":%q}`, bridge, port, wan))); err != nil {
			t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
		}
		assertPluginIntegrationLinkAbsent(t, bridge)
	})
}

func TestPluginLANCoreResolvesWANCoreStatusLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	pluginsRoot := t.TempDir()
	for _, pluginID := range []string{"wan_core", "lan_core"} {
		sourceDir := filepath.Join(findRepoRoot(t), "plugins", pluginID)
		copyDirForTest(t, sourceDir, filepath.Join(pluginsRoot, pluginID))
	}
	cfg := &Config{PluginsDir: pluginsRoot}
	wanPlugin, err := loadPluginFromDir(filepath.Join(pluginsRoot, "wan_core"), "wan_core")
	if err != nil {
		t.Fatalf("load wan_core bundled plugin: %v", err)
	}
	lanPlugin, err := loadPluginFromDir(filepath.Join(pluginsRoot, "lan_core"), "lan_core")
	if err != nil {
		t.Fatalf("load lan_core bundled plugin: %v", err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer rt.Close()

	wanLocal := pluginIntegrationLinkName("veerl")
	bridge := pluginIntegrationLinkName("brl")
	port := pluginIntegrationLinkName("fwp")
	portPeer := pluginIntegrationLinkName("fwq")
	defer deletePluginIntegrationLinkQuietly(t, wanLocal)
	defer deletePluginIntegrationLinkQuietly(t, bridge)
	defer deletePluginIntegrationLinkQuietly(t, port)
	defer deletePluginIntegrationLinkQuietly(t, portPeer)

	wanAction := pluginActionByIDForTest(t, wanPlugin, "apply_session")
	wanPayload := fmt.Sprintf(`{
		"wan_id":"wan-a",
		"state":"up",
		"usable":true,
		"driver":"integration",
		"driver_plugin":"test",
		"real_interface":"eth-test",
		"local_interface":%q,
		"addresses":["169.254.244.1/32"],
		"ipv4":"192.0.2.254",
		"mtu":1400
	}`, wanLocal)
	if err := rt.ApplyPluginAction(wanPlugin, wanAction, json.RawMessage(wanPayload)); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core apply_session) error = %v", err)
	}
	assertPluginIntegrationDummy(t, wanLocal, 1400)
	waitForPluginRecordContainingForTest(t, db, "wan_core", "status", "wan-a", 2*time.Second, `"phase":"applied"`, `"egress_nat_parent_interface":`+strconv.Quote(wanLocal), `"egress_nat_redirect_mode":""`)

	createPluginIntegrationVeth(t, port, portPeer)
	lanAction := pluginActionByIDForTest(t, lanPlugin, "apply_network")
	lanPayload := fmt.Sprintf(`{
		"lan_id":"lan-a",
		"bridge":%q,
		"ports":[%q],
		"addresses":["192.0.4.1/24"],
		"wan_ref":"wan-a",
		"auto_egress_nat":true,
		"protocol":"tcp+udp",
		"nat_type":"symmetric",
		"mtu":1500
	}`, bridge, port)
	if err := rt.ApplyPluginAction(lanPlugin, lanAction, json.RawMessage(lanPayload)); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core apply_network) error = %v", err)
	}
	assertPluginIntegrationBridge(t, bridge, 1500)
	assertPluginIntegrationLinkMaster(t, port, bridge)
	waitForPluginRecordContainingForTest(t, db, "lan_core", "status", "lan-a", 2*time.Second, `"phase":"applied"`, `"resolved":true`, `"interface":`+strconv.Quote(wanLocal))
	plan := waitForPluginRecordContainingForTest(t, db, "lan_core", "egress_nat_plans", "lan-a", 2*time.Second, `"enabled":true`, `"out_interface":`+strconv.Quote(wanLocal), `"out_source_ip":"192.0.2.254"`, `"redirect_mode":""`)
	if !plan.Enabled {
		t.Fatalf("lan_core egress_nat_plans/lan-a enabled = false, want true after resolving wan_core status")
	}
}

func TestPluginControlNetEnsureVethRejectsMismatchedExistingPeersLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	host := pluginIntegrationLinkName("fva")
	peer := pluginIntegrationLinkName("fvb")
	hostPeer := pluginIntegrationLinkName("fvc")
	peerPeer := pluginIntegrationLinkName("fvd")
	defer deletePluginIntegrationLinkQuietly(t, host)
	defer deletePluginIntegrationLinkQuietly(t, peer)
	defer deletePluginIntegrationLinkQuietly(t, hostPeer)
	defer deletePluginIntegrationLinkQuietly(t, peerPeer)

	createPluginIntegrationVeth(t, host, hostPeer)
	createPluginIntegrationVeth(t, peer, peerPeer)

	admin := linuxPluginControlNetAdmin{}
	_, err := admin.LinkEnsureVeth(pluginControlNetVethRequest{
		Host: host,
		Peer: peer,
		MTU:  1400,
		Up:   true,
	})
	if err == nil || !strings.Contains(err.Error(), "are not a pair") {
		t.Fatalf("LinkEnsureVeth(%s,%s) error = %v, want not-a-pair rejection", host, peer, err)
	}

	assertPluginIntegrationVethPair(t, host, hostPeer, 0)
	assertPluginIntegrationVethPair(t, peer, peerPeer, 0)
}

func TestPluginControlNetEnsureMacvlanLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	parent := pluginIntegrationLinkName("fmp")
	peer := pluginIntegrationLinkName("fmq")
	child := pluginIntegrationLinkName("fmm")
	defer deletePluginIntegrationLinkQuietly(t, child)
	defer deletePluginIntegrationLinkQuietly(t, parent)
	defer deletePluginIntegrationLinkQuietly(t, peer)
	createPluginIntegrationVeth(t, parent, peer)

	admin := linuxPluginControlNetAdmin{}
	req := pluginControlNetMacvlanRequest{
		Name:   child,
		Parent: parent,
		Mode:   "bridge",
		MAC:    "02:11:22:33:44:55",
		MTU:    1400,
		Up:     true,
	}
	first, err := admin.LinkEnsureMacvlan(req)
	if err != nil {
		t.Fatalf("LinkEnsureMacvlan(first) error = %v", err)
	}
	if !first.Created || first.Link.Kind != "macvlan" || first.Link.Parent != parent || first.Link.MAC != req.MAC || first.Link.MTU != req.MTU || !first.Link.Up {
		t.Fatalf("LinkEnsureMacvlan(first) = %+v, want created bridge macvlan on %s", first, parent)
	}
	second, err := admin.LinkEnsureMacvlan(req)
	if err != nil {
		t.Fatalf("LinkEnsureMacvlan(second) error = %v", err)
	}
	if second.Created {
		t.Fatalf("LinkEnsureMacvlan(second) Created = true, want reuse")
	}

	bad := req
	bad.MAC = "02:11:22:33:44:66"
	if _, err := admin.LinkEnsureMacvlan(bad); err == nil || !strings.Contains(err.Error(), "mac is") {
		t.Fatalf("LinkEnsureMacvlan(mismatched MAC) error = %v, want mismatch rejection", err)
	}
}

func TestPluginControlNetSetGSOLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	name := pluginIntegrationLinkName("fgs")
	defer deletePluginIntegrationLinkQuietly(t, name)
	admin := linuxPluginControlNetAdmin{}
	if _, err := admin.LinkEnsureDummy(pluginControlNetDummyRequest{Name: name, MTU: 1492, Up: true}); err != nil {
		t.Fatalf("LinkEnsureDummy(%s) error = %v", name, err)
	}
	info, err := admin.LinkSetGSO(pluginControlNetGSORequest{Interface: name, MaxSize: 1492, MaxSegs: 1})
	if err != nil {
		t.Fatalf("LinkSetGSO(%s) error = %v", name, err)
	}
	if info.GSOMaxSize != 1492 || info.GSOMaxSegs != 1 {
		t.Fatalf("LinkSetGSO(%s) info = %+v, want max_size=1492 max_segs=1", name, info)
	}
}

func requirePluginLinuxIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(pluginIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run plugin Linux integration tests", pluginIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("plugin Linux integration tests require root")
	}
}

func assertPluginIntegrationEnabledRecord(t *testing.T, db *sql.DB, pluginID, resourceID, key string) {
	t.Helper()
	record, err := store.GetPluginRecord(db, pluginID, resourceID, key)
	if err != nil {
		t.Fatalf("GetPluginRecord(%s %s/%s) error = %v", pluginID, resourceID, key, err)
	}
	if !record.Enabled {
		t.Fatalf("%s %s/%s enabled = false, want true", pluginID, resourceID, key)
	}
}

func assertPluginIntegrationTimer(t *testing.T, rt *gojaPluginControlRuntime, pluginID, timerName string) {
	t.Helper()
	timers := rt.pluginTimerList(pluginID)
	if len(timers) != 1 || timers[0]["name"] != timerName || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("%s timers = %+v, want %s interval", pluginID, timers, timerName)
	}
}

func loadPluginIntegrationControlRuntimeForTest(t *testing.T, pluginID string) (LoadedPlugin, *sql.DB, *gojaPluginControlRuntime) {
	t.Helper()

	pluginsRoot := t.TempDir()
	sourceDir := filepath.Join(findRepoRoot(t), "plugins", pluginID)
	pluginDir := filepath.Join(pluginsRoot, pluginID)
	copyDirForTest(t, sourceDir, pluginDir)

	plugin, err := loadPluginFromDir(pluginDir, pluginID)
	if err != nil {
		t.Fatalf("load %s bundled plugin: %v", pluginID, err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: pluginsRoot}, nil).(*gojaPluginControlRuntime)
	return plugin, db, rt
}

func addPluginIntegrationRecord(t *testing.T, db *sql.DB, pluginID, resourceID, key, dataJSON string, enabled bool) {
	t.Helper()
	item := store.PluginRecord{
		PluginID:   pluginID,
		ResourceID: resourceID,
		RecordKey:  key,
		DataJSON:   compactPluginIntegrationJSONForTest(t, dataJSON),
		Enabled:    enabled,
	}
	if _, err := store.AddPluginRecord(db, &item); err != nil {
		t.Fatalf("AddPluginRecord(%s/%s/%s) error = %v", pluginID, resourceID, key, err)
	}
}

func compactPluginIntegrationJSONForTest(t *testing.T, data string) string {
	t.Helper()
	out, err := canonicalPluginRecordJSON([]byte(data))
	if err != nil {
		t.Fatalf("canonicalPluginRecordJSON(%s) error = %v", data, err)
	}
	return out
}

func pluginIntegrationLinkName(prefix string) string {
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	if len(suffix) > 7 {
		suffix = suffix[len(suffix)-7:]
	}
	name := strings.ToLower(prefix + suffix)
	if len(name) > linuxInterfaceNameMaxBytes {
		return name[:linuxInterfaceNameMaxBytes]
	}
	return name
}

func createPluginIntegrationVeth(t *testing.T, host, peer string) {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = host
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peer}); err != nil {
		t.Fatalf("create veth %s<->%s: %v", host, peer, err)
	}
	if err := netlink.LinkSetUp(pluginIntegrationMustLink(t, host)); err != nil {
		t.Fatalf("set %s up: %v", host, err)
	}
	if err := netlink.LinkSetUp(pluginIntegrationMustLink(t, peer)); err != nil {
		t.Fatalf("set %s up: %v", peer, err)
	}
}

func assertPluginIntegrationVethPair(t *testing.T, host, peer string, mtu int) {
	t.Helper()
	hostLink := pluginIntegrationMustLink(t, host)
	peerLink := pluginIntegrationMustLink(t, peer)
	if hostLink.Type() != "veth" || peerLink.Type() != "veth" {
		t.Fatalf("link pair %s/%s types = %s/%s, want veth/veth", host, peer, hostLink.Type(), peerLink.Type())
	}
	if mtu > 0 && (hostLink.Attrs().MTU != mtu || peerLink.Attrs().MTU != mtu) {
		t.Fatalf("link pair %s/%s mtu = %d/%d, want %d", host, peer, hostLink.Attrs().MTU, peerLink.Attrs().MTU, mtu)
	}
}

func assertPluginIntegrationDummy(t *testing.T, name string, mtu int) {
	t.Helper()
	link := pluginIntegrationMustLink(t, name)
	if link.Type() != "dummy" {
		t.Fatalf("link %s type = %s, want dummy", name, link.Type())
	}
	if mtu > 0 && link.Attrs().MTU != mtu {
		t.Fatalf("dummy %s mtu = %d, want %d", name, link.Attrs().MTU, mtu)
	}
}

func assertPluginIntegrationBridge(t *testing.T, name string, mtu int) {
	t.Helper()
	link := pluginIntegrationMustLink(t, name)
	if link.Type() != "bridge" {
		t.Fatalf("link %s type = %s, want bridge", name, link.Type())
	}
	if mtu > 0 && link.Attrs().MTU != mtu {
		t.Fatalf("bridge %s mtu = %d, want %d", name, link.Attrs().MTU, mtu)
	}
}

func assertPluginIntegrationLinkMaster(t *testing.T, linkName, masterName string) {
	t.Helper()
	link := pluginIntegrationMustLink(t, linkName)
	master := pluginIntegrationMustLink(t, masterName)
	if link.Attrs().MasterIndex != master.Attrs().Index {
		t.Fatalf("link %s master index = %d, want %s index %d", linkName, link.Attrs().MasterIndex, masterName, master.Attrs().Index)
	}
}

func assertPluginIntegrationLinkHasCIDR(t *testing.T, name, cidr string) {
	t.Helper()
	link := pluginIntegrationMustLink(t, name)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("AddrList(%s) error = %v", name, err)
	}
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.String() == cidr {
			return
		}
	}
	t.Fatalf("link %s addresses = %+v, missing %s", name, addrs, cidr)
}

func assertPluginIntegrationLinkLacksCIDR(t *testing.T, name, cidr string) {
	t.Helper()
	link := pluginIntegrationMustLink(t, name)
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatalf("AddrList(%s) error = %v", name, err)
	}
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.String() == cidr {
			t.Fatalf("link %s still has stale address %s", name, cidr)
		}
	}
}

func assertPluginIntegrationLinkAbsent(t *testing.T, name string) {
	t.Helper()
	_, err := netlink.LinkByName(name)
	if !pluginControlNetLinkNotFound(err) {
		t.Fatalf("LinkByName(%s) error = %v, want not found", name, err)
	}
}

func pluginIntegrationMustLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%s) error = %v", name, err)
	}
	return link
}

func deletePluginIntegrationLink(name string) error {
	link, err := netlink.LinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func deletePluginIntegrationLinkQuietly(t *testing.T, name string) {
	t.Helper()
	if err := deletePluginIntegrationLink(name); err != nil {
		t.Logf("cleanup link %s: %v", name, err)
	}
}
