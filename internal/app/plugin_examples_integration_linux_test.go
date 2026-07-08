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

	"forward/internal/store"

	"github.com/vishvananda/netlink"
)

// These tests touch the host network namespace. They are opt-in because they
// create and delete Linux bridge/veth links to validate real plugin net.admin
// behavior, not just the mocked control-plane path.
const pluginExampleIntegrationEnableEnv = "FORWARD_RUN_PLUGIN_EXAMPLE_TEST"

func TestPluginExampleWANCoreLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "wan_core")
	defer rt.Close()

	host := pluginExampleLinkName("fwdh")
	vtap := pluginExampleLinkName("fwdv")
	defer deletePluginExampleLinkQuietly(t, host)
	defer deletePluginExampleLinkQuietly(t, vtap)

	session := fmt.Sprintf(`{
		"wan_id":"itest",
		"state":"up",
		"usable":true,
		"driver":"integration",
		"driver_plugin":"test",
		"real_interface":"eth-test",
		"host_interface":%q,
		"vtap_interface":%q,
		"host_addresses":["169.254.240.1/30"],
		"vtap_addresses":["169.254.240.2/30"],
		"mtu":1400
	}`, host, vtap)
	addPluginExampleRecord(t, db, plugin.ID, "sessions", "itest", session, true)

	resource := pluginResourceByIDForTest(t, plugin, "sessions")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(session),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(wan_core sessions) error = %v", err)
	}
	assertPluginExampleVethPair(t, host, vtap, 1400)
	assertPluginExampleLinkHasCIDR(t, host, "169.254.240.1/30")
	assertPluginExampleLinkHasCIDR(t, vtap, "169.254.240.2/30")
	waitForPluginRecordContainingForTest(t, db, "wan_core", "status", "itest", 2*time.Second, `"phase":"applied"`, `"forward_parent_interface":`)

	if err := deletePluginExampleLink(host); err != nil {
		t.Fatalf("delete wan host veth %s: %v", host, err)
	}
	firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	assertPluginExampleVethPair(t, host, vtap, 1400)

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"wan_id":"itest","host_interface":%q,"vtap_interface":%q}`, host, vtap))); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
	}
	assertPluginExampleLinkAbsent(t, host)
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

func TestPluginExampleVToLocalLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "vtolocal")
	defer rt.Close()

	host := pluginExampleLinkName("fwdh")
	vtap := pluginExampleLinkName("fwdv")
	defer deletePluginExampleLinkQuietly(t, host)
	defer deletePluginExampleLinkQuietly(t, vtap)

	link := fmt.Sprintf(`{
		"profile_key":"itest",
		"host_interface":%q,
		"vtap_interface":%q,
		"host_addresses":["169.254.241.1/30"],
		"vtap_addresses":["169.254.241.2/30"],
		"mtu":1400
	}`, host, vtap)
	addPluginExampleRecord(t, db, plugin.ID, "links", "itest", link, true)

	resource := pluginResourceByIDForTest(t, plugin, "links")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(link),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(vtolocal links) error = %v", err)
	}
	assertPluginExampleVethPair(t, host, vtap, 1400)
	assertPluginExampleLinkHasCIDR(t, host, "169.254.241.1/30")
	assertPluginExampleLinkHasCIDR(t, vtap, "169.254.241.2/30")

	if err := deletePluginExampleLink(host); err != nil {
		t.Fatalf("delete vtolocal host veth %s: %v", host, err)
	}
	firePluginTimerForTest(t, rt, "vtolocal", "vtolocal_repair")
	assertPluginExampleVethPair(t, host, vtap, 1400)

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"profile_key":"itest","host_interface":%q,"vtap_interface":%q}`, host, vtap))); err != nil {
		t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
	}
	assertPluginExampleLinkAbsent(t, host)
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

func TestPluginExampleLANCoreLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "lan_core")
	defer rt.Close()

	bridge := pluginExampleLinkName("brl")
	port := pluginExampleLinkName("fwp")
	portPeer := pluginExampleLinkName("fwq")
	wan := pluginExampleLinkName("fww")
	wanPeer := pluginExampleLinkName("fwx")
	defer deletePluginExampleLinkQuietly(t, bridge)
	defer deletePluginExampleLinkQuietly(t, port)
	defer deletePluginExampleLinkQuietly(t, portPeer)
	defer deletePluginExampleLinkQuietly(t, wan)
	defer deletePluginExampleLinkQuietly(t, wanPeer)

	createPluginExampleVeth(t, port, portPeer)
	createPluginExampleVeth(t, wan, wanPeer)

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
	addPluginExampleRecord(t, db, plugin.ID, "profiles", "itest", profile, true)

	resource := pluginResourceByIDForTest(t, plugin, "profiles")
	if err := rt.ApplyPluginResourceData(plugin, resource, []PluginResourceRecord{{
		Key:     "itest",
		Data:    json.RawMessage(profile),
		Enabled: true,
	}}); err != nil {
		t.Fatalf("ApplyPluginResourceData(lan_core profiles) error = %v", err)
	}
	assertPluginExampleBridge(t, bridge, 1500)
	assertPluginExampleLinkMaster(t, port, bridge)
	assertPluginExampleLinkHasCIDR(t, bridge, "192.0.2.1/24")
	waitForPluginRecordContainingForTest(t, db, "lan_core", "status", "itest", 2*time.Second, `"phase":"applied"`, `"bridge":`+strconv.Quote(bridge))
	plan := waitForPluginRecordContainingForTest(t, db, "lan_core", "egress_nat_plans", "itest", 2*time.Second, `"enabled":true`, `"redirect_mode":""`, `"out_interface":`+strconv.Quote(wan))
	if !plan.Enabled {
		t.Fatalf("lan_core egress_nat_plans/itest record enabled = false, want true")
	}

	if err := deletePluginExampleLink(bridge); err != nil {
		t.Fatalf("delete lan bridge %s: %v", bridge, err)
	}
	firePluginTimerForTest(t, rt, "lan_core", "lan_repair")
	assertPluginExampleBridge(t, bridge, 1500)
	assertPluginExampleLinkMaster(t, port, bridge)

	action := pluginActionByIDForTest(t, plugin, "teardown")
	if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(fmt.Sprintf(`{"lan_id":"itest","bridge":%q,"ports":[%q],"wan_egress_interface":%q}`, bridge, port, wan))); err != nil {
		t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
	}
	assertPluginExampleLinkAbsent(t, bridge)
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

func TestPluginExampleActionApplyPersistsAndRepairsLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	t.Run("wan_core", func(t *testing.T) {
		plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "wan_core")
		defer rt.Close()

		host := pluginExampleLinkName("fwdh")
		vtap := pluginExampleLinkName("fwdv")
		defer deletePluginExampleLinkQuietly(t, host)
		defer deletePluginExampleLinkQuietly(t, vtap)

		action := pluginActionByIDForTest(t, plugin, "apply_session")
		payload := fmt.Sprintf(`{
			"wan_id":"action",
			"state":"up",
			"usable":true,
			"driver":"integration",
			"driver_plugin":"test",
			"real_interface":"eth-test",
			"host_interface":%q,
			"vtap_interface":%q,
			"host_addresses":["169.254.242.1/30"],
			"vtap_addresses":["169.254.242.2/30"],
			"mtu":1400
		}`, host, vtap)
		if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(payload)); err != nil {
			t.Fatalf("ApplyPluginAction(wan_core apply_session) error = %v", err)
		}
		assertPluginExampleVethPair(t, host, vtap, 1400)
		assertPluginExampleEnabledRecord(t, db, "wan_core", "sessions", "action")
		assertPluginExampleEnabledRecord(t, db, "wan_core", "profiles", "action")
		assertPluginExampleTimer(t, rt, "wan_core", "wan_repair")

		if err := deletePluginExampleLink(host); err != nil {
			t.Fatalf("delete action wan host veth %s: %v", host, err)
		}
		firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
		assertPluginExampleVethPair(t, host, vtap, 1400)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"wan_id":"action","host_interface":%q,"vtap_interface":%q}`, host, vtap))); err != nil {
			t.Fatalf("ApplyPluginAction(wan_core teardown) error = %v", err)
		}
		assertPluginExampleLinkAbsent(t, host)
	})

	t.Run("vtolocal", func(t *testing.T) {
		plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "vtolocal")
		defer rt.Close()

		host := pluginExampleLinkName("fwdh")
		vtap := pluginExampleLinkName("fwdv")
		defer deletePluginExampleLinkQuietly(t, host)
		defer deletePluginExampleLinkQuietly(t, vtap)

		action := pluginActionByIDForTest(t, plugin, "apply")
		payload := fmt.Sprintf(`{
			"profile_key":"action",
			"host_interface":%q,
			"vtap_interface":%q,
			"host_addresses":["169.254.243.1/30"],
			"vtap_addresses":["169.254.243.2/30"],
			"mtu":1400
		}`, host, vtap)
		if err := rt.ApplyPluginAction(plugin, action, json.RawMessage(payload)); err != nil {
			t.Fatalf("ApplyPluginAction(vtolocal apply) error = %v", err)
		}
		assertPluginExampleVethPair(t, host, vtap, 1400)
		assertPluginExampleEnabledRecord(t, db, "vtolocal", "links", "action")
		assertPluginExampleTimer(t, rt, "vtolocal", "vtolocal_repair")

		if err := deletePluginExampleLink(host); err != nil {
			t.Fatalf("delete action vtolocal host veth %s: %v", host, err)
		}
		firePluginTimerForTest(t, rt, "vtolocal", "vtolocal_repair")
		assertPluginExampleVethPair(t, host, vtap, 1400)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"profile_key":"action","host_interface":%q,"vtap_interface":%q}`, host, vtap))); err != nil {
			t.Fatalf("ApplyPluginAction(vtolocal teardown) error = %v", err)
		}
		assertPluginExampleLinkAbsent(t, host)
	})

	t.Run("lan_core", func(t *testing.T) {
		plugin, db, rt := loadPluginExampleControlRuntimeForTest(t, "lan_core")
		defer rt.Close()

		bridge := pluginExampleLinkName("bra")
		port := pluginExampleLinkName("fwp")
		portPeer := pluginExampleLinkName("fwq")
		wan := pluginExampleLinkName("fww")
		wanPeer := pluginExampleLinkName("fwx")
		defer deletePluginExampleLinkQuietly(t, bridge)
		defer deletePluginExampleLinkQuietly(t, port)
		defer deletePluginExampleLinkQuietly(t, portPeer)
		defer deletePluginExampleLinkQuietly(t, wan)
		defer deletePluginExampleLinkQuietly(t, wanPeer)

		createPluginExampleVeth(t, port, portPeer)
		createPluginExampleVeth(t, wan, wanPeer)

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
		assertPluginExampleBridge(t, bridge, 1500)
		assertPluginExampleLinkMaster(t, port, bridge)
		assertPluginExampleEnabledRecord(t, db, "lan_core", "profiles", "action")
		assertPluginExampleEnabledRecord(t, db, "lan_core", "egress_nat_plans", "action")
		assertPluginExampleTimer(t, rt, "lan_core", "lan_repair")

		if err := deletePluginExampleLink(bridge); err != nil {
			t.Fatalf("delete action lan bridge %s: %v", bridge, err)
		}
		firePluginTimerForTest(t, rt, "lan_core", "lan_repair")
		assertPluginExampleBridge(t, bridge, 1500)
		assertPluginExampleLinkMaster(t, port, bridge)

		teardown := pluginActionByIDForTest(t, plugin, "teardown")
		if err := rt.ApplyPluginAction(plugin, teardown, json.RawMessage(fmt.Sprintf(`{"lan_id":"action","bridge":%q,"ports":[%q],"wan_egress_interface":%q}`, bridge, port, wan))); err != nil {
			t.Fatalf("ApplyPluginAction(lan_core teardown) error = %v", err)
		}
		assertPluginExampleLinkAbsent(t, bridge)
	})
}

func TestPluginExampleLANCoreResolvesWANCoreStatusLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	pluginsRoot := t.TempDir()
	for _, pluginID := range []string{"wan_core", "lan_core"} {
		sourceDir := filepath.Join(findRepoRoot(t), "examples", "plugins", pluginID)
		copyDirForTest(t, sourceDir, filepath.Join(pluginsRoot, pluginID))
	}
	cfg := &Config{PluginsDir: pluginsRoot}
	wanPlugin, err := loadPluginFromDir(filepath.Join(pluginsRoot, "wan_core"), "wan_core")
	if err != nil {
		t.Fatalf("load wan_core example plugin: %v", err)
	}
	lanPlugin, err := loadPluginFromDir(filepath.Join(pluginsRoot, "lan_core"), "lan_core")
	if err != nil {
		t.Fatalf("load lan_core example plugin: %v", err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer rt.Close()

	wanHost := pluginExampleLinkName("fwdh")
	wanVTap := pluginExampleLinkName("fwdv")
	bridge := pluginExampleLinkName("brl")
	port := pluginExampleLinkName("fwp")
	portPeer := pluginExampleLinkName("fwq")
	defer deletePluginExampleLinkQuietly(t, wanHost)
	defer deletePluginExampleLinkQuietly(t, wanVTap)
	defer deletePluginExampleLinkQuietly(t, bridge)
	defer deletePluginExampleLinkQuietly(t, port)
	defer deletePluginExampleLinkQuietly(t, portPeer)

	wanAction := pluginActionByIDForTest(t, wanPlugin, "apply_session")
	wanPayload := fmt.Sprintf(`{
		"wan_id":"wan-a",
		"state":"up",
		"usable":true,
		"driver":"integration",
		"driver_plugin":"test",
		"real_interface":"eth-test",
		"host_interface":%q,
		"vtap_interface":%q,
		"host_addresses":["169.254.244.1/30"],
		"vtap_addresses":["169.254.244.2/30"],
		"ipv4":"192.0.2.254",
		"mtu":1400
	}`, wanHost, wanVTap)
	if err := rt.ApplyPluginAction(wanPlugin, wanAction, json.RawMessage(wanPayload)); err != nil {
		t.Fatalf("ApplyPluginAction(wan_core apply_session) error = %v", err)
	}
	assertPluginExampleVethPair(t, wanHost, wanVTap, 1400)
	waitForPluginRecordContainingForTest(t, db, "wan_core", "status", "wan-a", 2*time.Second, `"phase":"applied"`, `"egress_nat_parent_interface":`+strconv.Quote(wanHost), `"egress_nat_redirect_mode":"prepared_l2"`)

	createPluginExampleVeth(t, port, portPeer)
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
	assertPluginExampleBridge(t, bridge, 1500)
	assertPluginExampleLinkMaster(t, port, bridge)
	waitForPluginRecordContainingForTest(t, db, "lan_core", "status", "lan-a", 2*time.Second, `"phase":"applied"`, `"resolved":true`, `"interface":`+strconv.Quote(wanHost))
	plan := waitForPluginRecordContainingForTest(t, db, "lan_core", "egress_nat_plans", "lan-a", 2*time.Second, `"enabled":true`, `"out_interface":`+strconv.Quote(wanHost), `"out_source_ip":"192.0.2.254"`, `"redirect_mode":"prepared_l2"`)
	if !plan.Enabled {
		t.Fatalf("lan_core egress_nat_plans/lan-a enabled = false, want true after resolving wan_core status")
	}
}

func TestPluginControlNetEnsureVethRejectsMismatchedExistingPeersLinuxIntegration(t *testing.T) {
	requirePluginExampleLinuxIntegration(t)

	host := pluginExampleLinkName("fva")
	peer := pluginExampleLinkName("fvb")
	hostPeer := pluginExampleLinkName("fvc")
	peerPeer := pluginExampleLinkName("fvd")
	defer deletePluginExampleLinkQuietly(t, host)
	defer deletePluginExampleLinkQuietly(t, peer)
	defer deletePluginExampleLinkQuietly(t, hostPeer)
	defer deletePluginExampleLinkQuietly(t, peerPeer)

	createPluginExampleVeth(t, host, hostPeer)
	createPluginExampleVeth(t, peer, peerPeer)

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

	assertPluginExampleVethPair(t, host, hostPeer, 0)
	assertPluginExampleVethPair(t, peer, peerPeer, 0)
}

func requirePluginExampleLinuxIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(pluginExampleIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run plugin example Linux integration tests", pluginExampleIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("plugin example Linux integration tests require root")
	}
}

func assertPluginExampleEnabledRecord(t *testing.T, db *sql.DB, pluginID, resourceID, key string) {
	t.Helper()
	record, err := store.GetPluginRecord(db, pluginID, resourceID, key)
	if err != nil {
		t.Fatalf("GetPluginRecord(%s %s/%s) error = %v", pluginID, resourceID, key, err)
	}
	if !record.Enabled {
		t.Fatalf("%s %s/%s enabled = false, want true", pluginID, resourceID, key)
	}
}

func assertPluginExampleTimer(t *testing.T, rt *gojaPluginControlRuntime, pluginID, timerName string) {
	t.Helper()
	timers := rt.pluginTimerList(pluginID)
	if len(timers) != 1 || timers[0]["name"] != timerName || timers[0]["kind"] != pluginControlTimerKindInterval {
		t.Fatalf("%s timers = %+v, want %s interval", pluginID, timers, timerName)
	}
}

func loadPluginExampleControlRuntimeForTest(t *testing.T, pluginID string) (LoadedPlugin, *sql.DB, *gojaPluginControlRuntime) {
	t.Helper()

	pluginsRoot := t.TempDir()
	sourceDir := filepath.Join(findRepoRoot(t), "examples", "plugins", pluginID)
	pluginDir := filepath.Join(pluginsRoot, pluginID)
	copyDirForTest(t, sourceDir, pluginDir)

	plugin, err := loadPluginFromDir(pluginDir, pluginID)
	if err != nil {
		t.Fatalf("load %s example plugin: %v", pluginID, err)
	}
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, &Config{PluginsDir: pluginsRoot}, nil).(*gojaPluginControlRuntime)
	return plugin, db, rt
}

func addPluginExampleRecord(t *testing.T, db *sql.DB, pluginID, resourceID, key, dataJSON string, enabled bool) {
	t.Helper()
	item := store.PluginRecord{
		PluginID:   pluginID,
		ResourceID: resourceID,
		RecordKey:  key,
		DataJSON:   compactPluginExampleJSONForTest(t, dataJSON),
		Enabled:    enabled,
	}
	if _, err := store.AddPluginRecord(db, &item); err != nil {
		t.Fatalf("AddPluginRecord(%s/%s/%s) error = %v", pluginID, resourceID, key, err)
	}
}

func compactPluginExampleJSONForTest(t *testing.T, data string) string {
	t.Helper()
	out, err := canonicalPluginRecordJSON([]byte(data))
	if err != nil {
		t.Fatalf("canonicalPluginRecordJSON(%s) error = %v", data, err)
	}
	return out
}

func pluginExampleLinkName(prefix string) string {
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

func createPluginExampleVeth(t *testing.T, host, peer string) {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = host
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peer}); err != nil {
		t.Fatalf("create veth %s<->%s: %v", host, peer, err)
	}
	if err := netlink.LinkSetUp(pluginExampleMustLink(t, host)); err != nil {
		t.Fatalf("set %s up: %v", host, err)
	}
	if err := netlink.LinkSetUp(pluginExampleMustLink(t, peer)); err != nil {
		t.Fatalf("set %s up: %v", peer, err)
	}
}

func assertPluginExampleVethPair(t *testing.T, host, peer string, mtu int) {
	t.Helper()
	hostLink := pluginExampleMustLink(t, host)
	peerLink := pluginExampleMustLink(t, peer)
	if hostLink.Type() != "veth" || peerLink.Type() != "veth" {
		t.Fatalf("link pair %s/%s types = %s/%s, want veth/veth", host, peer, hostLink.Type(), peerLink.Type())
	}
	if mtu > 0 && (hostLink.Attrs().MTU != mtu || peerLink.Attrs().MTU != mtu) {
		t.Fatalf("link pair %s/%s mtu = %d/%d, want %d", host, peer, hostLink.Attrs().MTU, peerLink.Attrs().MTU, mtu)
	}
}

func assertPluginExampleBridge(t *testing.T, name string, mtu int) {
	t.Helper()
	link := pluginExampleMustLink(t, name)
	if link.Type() != "bridge" {
		t.Fatalf("link %s type = %s, want bridge", name, link.Type())
	}
	if mtu > 0 && link.Attrs().MTU != mtu {
		t.Fatalf("bridge %s mtu = %d, want %d", name, link.Attrs().MTU, mtu)
	}
}

func assertPluginExampleLinkMaster(t *testing.T, linkName, masterName string) {
	t.Helper()
	link := pluginExampleMustLink(t, linkName)
	master := pluginExampleMustLink(t, masterName)
	if link.Attrs().MasterIndex != master.Attrs().Index {
		t.Fatalf("link %s master index = %d, want %s index %d", linkName, link.Attrs().MasterIndex, masterName, master.Attrs().Index)
	}
}

func assertPluginExampleLinkHasCIDR(t *testing.T, name, cidr string) {
	t.Helper()
	link := pluginExampleMustLink(t, name)
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

func assertPluginExampleLinkAbsent(t *testing.T, name string) {
	t.Helper()
	_, err := netlink.LinkByName(name)
	if !pluginControlNetLinkNotFound(err) {
		t.Fatalf("LinkByName(%s) error = %v, want not found", name, err)
	}
}

func pluginExampleMustLink(t *testing.T, name string) netlink.Link {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName(%s) error = %v", name, err)
	}
	return link
}

func deletePluginExampleLink(name string) error {
	link, err := netlink.LinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func deletePluginExampleLinkQuietly(t *testing.T, name string) {
	t.Helper()
	if err := deletePluginExampleLink(name); err != nil {
		t.Logf("cleanup link %s: %v", name, err)
	}
}
