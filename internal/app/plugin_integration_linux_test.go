//go:build linux

package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
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

func TestPluginNetPolicyProviderLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	admin := linuxPluginControlNetAdmin{}
	parent := pluginIntegrationLinkName("fwp")
	vlanName := pluginIntegrationLinkName("fwv")
	vrfName := pluginIntegrationLinkName("fwr")
	defer deletePluginIntegrationLinkQuietly(t, vrfName)
	defer deletePluginIntegrationLinkQuietly(t, vlanName)
	defer deletePluginIntegrationLinkQuietly(t, parent)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = parent
	attrs.MTU = 1500
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Fatalf("create policy test parent: %v", err)
	}
	if err := admin.LinkSetUp(parent, true); err != nil {
		t.Fatal(err)
	}
	vlan, err := admin.LinkEnsureVLAN(pluginControlNetVLANRequest{Name: vlanName, Parent: parent, VLANID: 120, Protocol: "802.1q", MTU: 1500, Up: true})
	if err != nil {
		t.Fatalf("ensure vlan: %v", err)
	}
	if !vlan.Created || vlan.Link.VLANID != 120 || vlan.Link.Parent != parent {
		t.Fatalf("vlan result = %+v", vlan)
	}
	vrf, err := admin.LinkEnsureVRF(pluginControlNetVRFRequest{Name: vrfName, Table: 12001, Up: true})
	if err != nil {
		t.Fatalf("ensure vrf: %v", err)
	}
	if !vrf.Created || vrf.Link.VRFTable != 12001 {
		t.Fatalf("vrf result = %+v", vrf)
	}
	if _, err := admin.LinkSetMaster(pluginControlNetMasterRequest{Link: vlanName, Master: vrfName, Up: true}); err != nil {
		t.Fatalf("attach vlan to vrf: %v", err)
	}

	priority := 12000 + os.Getpid()%1000
	rule := pluginControlNetRuleRequest{Family: "ipv4", Priority: priority, Table: 12001, IIF: parent, Mark: 17, Mask: 255, HasMask: true}
	if err := admin.RuleReplace(rule); err != nil {
		t.Fatalf("replace policy rule: %v", err)
	}
	defer admin.RuleDelete(rule)
	rules, err := admin.RuleSnapshot(rule)
	if err != nil || len(rules) != 1 {
		t.Fatalf("policy rule snapshot = %+v, err=%v", rules, err)
	}

	neighbor := pluginControlNetNeighRequest{Interface: parent, IP: "192.0.2.1", MAC: "02:00:00:00:70:01", State: "permanent"}
	if err := admin.NeighReplace(neighbor); err != nil {
		t.Fatalf("replace static neighbor: %v", err)
	}
	defer admin.NeighDelete(neighbor)
	neighbors, err := admin.NeighSnapshot(neighbor)
	if err != nil || len(neighbors) != 1 || neighbors[0].Request.MAC != neighbor.MAC {
		t.Fatalf("neighbor snapshot = %+v, err=%v", neighbors, err)
	}
}

func TestPluginNetPolicyTransactionsLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	interfaceName := pluginIntegrationLinkName("host")
	defer deletePluginIntegrationLinkQuietly(t, interfaceName)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = interfaceName
	attrs.MTU = 1500
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Fatalf("create transaction test link: %v", err)
	}
	admin := linuxPluginControlNetAdmin{}
	if err := admin.LinkSetUp(interfaceName, true); err != nil {
		t.Fatal(err)
	}

	table := 13000 + os.Getpid()%1000
	priority := 13000 + os.Getpid()%1000
	routeA := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Dev: interfaceName, Table: table}
	routeB := pluginControlNetRouteRequest{Dst: "203.0.113.0/24", Dev: interfaceName, Table: table}
	rule := pluginControlNetRuleRequest{Family: "ipv4", Priority: priority, Table: table, IIF: interfaceName}
	neighbor := pluginControlNetNeighRequest{Interface: interfaceName, IP: "192.0.2.1", MAC: "02:00:00:00:71:01", State: "permanent"}
	defer admin.RouteDelete(routeA)
	defer admin.RouteDelete(routeB)
	defer admin.RuleDelete(rule)
	defer admin.NeighDelete(neighbor)

	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_policy_transaction", fmt.Sprintf(`
exports.onAction = function () {
  net.route.transaction([
    {op:"replace", request:{dst:"198.51.100.0/24", dev:%q, table:%d}},
    {op:"replace", request:{dst:"203.0.113.0/24", dev:%q, table:%d}}
  ]);
  net.rule.transaction([
    {op:"replace", request:{family:"ipv4", priority:%d, table:%d, iif:%q}}
  ]);
  return net.neigh.transaction([
    {op:"replace", request:{interface:%q, ip:"192.0.2.1", mac:"02:00:00:00:71:01", state:"permanent"}}
  ]);
};`, interfaceName, table, interfaceName, table, priority, table, interfaceName, interfaceName))
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_policy_transaction")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_policy_transaction")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("apply policy transactions: %v", err)
	}

	assertPluginNetPolicyTransactionState(t, admin, routeA, rule, neighbor, true)
	if routes, err := admin.RouteSnapshot(routeB); err != nil || len(routes) != 1 {
		t.Fatalf("second route snapshot = %+v, err=%v", routes, err)
	}
	owned, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(owned) != 4 {
		t.Fatalf("transaction ownership = %+v, err=%v, want 4", owned, err)
	}

	runtime.Reconcile(PluginCatalog{})
	assertPluginNetPolicyTransactionState(t, admin, routeA, rule, neighbor, false)
	if routes, err := admin.RouteSnapshot(routeB); err != nil || len(routes) != 0 {
		t.Fatalf("second route after unload = %+v, err=%v", routes, err)
	}
	owned, err = store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(owned) != 0 {
		t.Fatalf("transaction ownership after unload = %+v, err=%v", owned, err)
	}
}

func TestPluginMultipathRouteLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	left := pluginIntegrationLinkName("fwml")
	right := pluginIntegrationLinkName("fwmr")
	defer deletePluginIntegrationLinkQuietly(t, right)
	defer deletePluginIntegrationLinkQuietly(t, left)

	for _, item := range []struct {
		name string
		cidr string
	}{
		{name: left, cidr: "192.0.2.1/24"},
		{name: right, cidr: "192.0.3.1/24"},
	} {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = item.name
		attrs.MTU = 1500
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
			t.Fatalf("create multipath link %s: %v", item.name, err)
		}
		link, err := netlink.LinkByName(item.name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatalf("set multipath link %s up: %v", item.name, err)
		}
		addr, err := netlink.ParseAddr(item.cidr)
		if err != nil {
			t.Fatalf("configure multipath link %s address: %v", item.name, err)
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			t.Fatalf("configure multipath link %s address: %v", item.name, err)
		}
	}

	admin := linuxPluginControlNetAdmin{}
	table := 15000 + os.Getpid()%1000
	original := pluginControlNetRouteRequest{
		Dst: "198.51.100.0/24", Table: table, Metric: 10,
		Nexthops: []pluginControlNetRouteNexthop{
			{Dev: left, Gateway: "192.0.2.2", Weight: 1},
			{Dev: right, Gateway: "192.0.3.2", Weight: 2, Onlink: true},
		},
	}
	updated := original
	updated.Nexthops = []pluginControlNetRouteNexthop{
		{Dev: left, Gateway: "192.0.2.2", Weight: 3},
		{Dev: right, Gateway: "192.0.3.2", Weight: 1},
	}
	defer admin.RouteDelete(updated)
	defer admin.RouteDelete(original)

	if err := admin.RouteReplace(original); err != nil {
		t.Fatalf("replace multipath route: %v", err)
	}
	states, err := admin.RouteSnapshot(original)
	if err != nil || len(states) != 1 || len(states[0].Nexthops) != 2 {
		t.Fatalf("multipath snapshot = %+v, err=%v", states, err)
	}
	if !pluginControlRouteRequestMatchesState(original, states[0]) {
		t.Fatalf("multipath state does not match request: request=%+v state=%+v", original, states[0])
	}
	if states[0].Nexthops[0].DevIfIndex < 1 || states[0].Nexthops[1].DevIfIndex < 1 {
		t.Fatalf("multipath snapshot is missing interface identity: %+v", states[0].Nexthops)
	}

	if err := admin.RouteReplace(updated); err != nil {
		t.Fatalf("update multipath route: %v", err)
	}
	if err := admin.RouteDelete(updated); err != nil {
		t.Fatalf("delete updated multipath route: %v", err)
	}
	if err := admin.RouteRestore(states); err != nil {
		t.Fatalf("restore multipath route: %v", err)
	}
	restored, err := admin.RouteSnapshot(original)
	if err != nil || len(restored) != 1 || !pluginControlRouteRequestMatchesState(original, restored[0]) {
		t.Fatalf("restored multipath route = %+v, err=%v", restored, err)
	}
}

func TestPluginNamespaceTunTapLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	admin, ok := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	if !ok {
		t.Fatal("linux network provider is unavailable")
	}
	namespace := pluginIntegrationLinkName("fwns")
	defer func() {
		admin.TunTapCloseAll("integration")
		_ = admin.NamespaceDelete(namespace, pluginControlNetNamespaceIdentity{})
	}()

	nsResult, err := admin.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: namespace, LoopbackUp: true})
	if err != nil || !nsResult.Created || nsResult.Info.Identity.Inode == 0 {
		t.Fatalf("ensure namespace = %+v, err=%v", nsResult, err)
	}
	if current, present, err := admin.NamespaceLookup(namespace); err != nil || !present || !pluginControlNamespaceIdentityEqual(current.Identity, nsResult.Info.Identity) {
		t.Fatalf("namespace lookup = %+v, present=%t, err=%v", current, present, err)
	}

	device, err := admin.TunTapEnsure("integration", pluginControlNetTunTapRequest{
		Name: "fwtun0", Namespace: namespace, Mode: "tun", MTU: 1400, Up: true,
	})
	if err != nil || !device.Created || device.Info.IfIndex < 1 || device.Info.MTU != 1400 {
		t.Fatalf("ensure TUN = %+v, err=%v", device, err)
	}
	if err := linuxPluginRunInNamespace(namespace, func() error {
		link, err := netlink.LinkByName("fwtun0")
		if err != nil {
			return err
		}
		addr, err := netlink.ParseAddr("198.18.0.1/24")
		if err != nil {
			return err
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return err
		}
		conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: 19000})
		if err != nil {
			return err
		}
		defer conn.Close()
		_, err = conn.Write([]byte("veer-tuntap-probe"))
		return err
	}); err != nil {
		t.Fatalf("generate namespace packet: %v", err)
	}
	var packet pluginControlNetTunTapPacket
	deadline := time.Now().Add(2 * time.Second)
	for attempts := 0; attempts < 16 && time.Now().Before(deadline); attempts++ {
		packet, err = admin.TunTapRead("integration", pluginControlNetTunTapReadRequest{
			Name: "fwtun0", Namespace: namespace, MaxBytes: pluginControlTunTapMaxPacketBytes, Timeout: 200 * time.Millisecond,
		})
		if err != nil {
			break
		}
		if len(packet.Packet) >= 20 && packet.Packet[0]>>4 == 4 {
			break
		}
	}
	if err != nil || len(packet.Packet) < 20 || packet.Packet[0]>>4 != 4 {
		t.Fatalf("read IPv4 TUN packet: bytes=%d timed_out=%t err=%v", len(packet.Packet), packet.TimedOut, err)
	}
	if written, err := admin.TunTapWrite("integration", pluginControlNetTunTapWriteRequest{
		Name: "fwtun0", Namespace: namespace, Packet: packet.Packet,
	}); err != nil || written != len(packet.Packet) {
		t.Fatalf("write TUN packet: bytes=%d err=%v", written, err)
	}
	if err := admin.NamespaceDelete(namespace, nsResult.Info.Identity); err == nil || !strings.Contains(err.Error(), "open managed TUN/TAP") {
		t.Fatalf("namespace deletion with open TUN error = %v", err)
	}
	if err := admin.TunTapClose("integration", pluginControlNetTunTapCloseRequest{
		Name: "fwtun0", Namespace: namespace, IfIndex: device.Info.IfIndex,
	}); err != nil {
		t.Fatalf("close TUN: %v", err)
	}
	if err := admin.NamespaceDelete(namespace, nsResult.Info.Identity); err != nil {
		t.Fatalf("delete namespace: %v", err)
	}
	if _, present, err := admin.NamespaceLookup(namespace); err != nil || present {
		t.Fatalf("namespace still present=%t err=%v", present, err)
	}
}

func TestPluginNamespaceTunTapCrashRecoveryLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	namespace := pluginIntegrationLinkName("fwnc")
	admin := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	defer func() { _ = admin.NamespaceDelete(namespace, pluginControlNetNamespaceIdentity{}) }()

	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "netns-crash.db")
	db, err := store.InitDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(testDir, "ready")
	var childOutput bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run", "^TestPluginNamespaceTunTapCrashRecoveryHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"VEER_PLUGIN_NETNS_CRASH_HELPER=1",
		"VEER_PLUGIN_NETNS_CRASH_DB="+dbPath,
		"VEER_PLUGIN_NETNS_CRASH_NAME="+namespace,
		"VEER_PLUGIN_NETNS_CRASH_READY="+readyPath,
	)
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("netns crash helper did not become ready: %s", childOutput.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	if _, present, err := admin.NamespaceLookup(namespace); err != nil || !present {
		t.Fatalf("namespace after SIGKILL present=%t err=%v", present, err)
	}
	if err := linuxPluginRunInNamespace(namespace, func() error {
		_, lookupErr := netlink.LinkByName("fwtun0")
		if lookupErr == nil {
			return fmt.Errorf("TUN survived owner process SIGKILL")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	db, err = store.InitDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const pluginID = "netns_crash_linux"
	owned, err := store.GetPluginOwnedResources(db, pluginID)
	if err != nil || len(owned) != 2 {
		t.Fatalf("owned resources after SIGKILL = %+v, err=%v", owned, err)
	}
	if err := cleanupPluginOwnedResources(db, admin, pluginID); err != nil {
		t.Fatalf("recover namespace ownership: %v", err)
	}
	if _, present, err := admin.NamespaceLookup(namespace); err != nil || present {
		t.Fatalf("namespace after recovery present=%t err=%v", present, err)
	}
	owned, err = store.GetPluginOwnedResources(db, pluginID)
	if err != nil || len(owned) != 0 {
		t.Fatalf("owned resources after recovery = %+v, err=%v", owned, err)
	}
}

func TestPluginNamespaceTunTapCrashRecoveryHelperProcess(t *testing.T) {
	if os.Getenv("VEER_PLUGIN_NETNS_CRASH_HELPER") != "1" {
		return
	}
	if err := runPluginNamespaceTunTapCrashRecoveryHelper(); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func runPluginNamespaceTunTapCrashRecoveryHelper() error {
	db, err := store.InitDB(os.Getenv("VEER_PLUGIN_NETNS_CRASH_DB"))
	if err != nil {
		return err
	}
	admin := newPluginControlNetAdmin().(*linuxPluginControlNetAdmin)
	namespace := os.Getenv("VEER_PLUGIN_NETNS_CRASH_NAME")
	const pluginID = "netns_crash_linux"
	nsResult, err := admin.NamespaceEnsure(pluginControlNetNamespaceRequest{Name: namespace, LoopbackUp: true})
	if err != nil {
		return err
	}
	if err := addPluginOwnedNetworkResource(db, pluginID, pluginOwnedResourceTypeNamespace, namespace, pluginOwnedNamespaceClaim{
		Name: namespace, Identity: nsResult.Info.Identity, BootID: pluginOwnershipBootID,
	}); err != nil {
		return err
	}
	device, err := admin.TunTapEnsure(pluginID, pluginControlNetTunTapRequest{Name: "fwtun0", Namespace: namespace, Mode: "tun", Up: true})
	if err != nil {
		return err
	}
	key := pluginControlTunTapResourceKey(namespace, "fwtun0")
	if err := addPluginOwnedNetworkResource(db, pluginID, pluginOwnedResourceTypeTunTap, key, pluginOwnedTunTapClaim{
		Name: "fwtun0", Namespace: namespace, Mode: "tun", IfIndex: device.Info.IfIndex,
		NamespaceIdentity: nsResult.Info.Identity, BootID: pluginOwnershipBootID,
	}); err != nil {
		return err
	}
	if err := os.WriteFile(os.Getenv("VEER_PLUGIN_NETNS_CRASH_READY"), []byte("ready"), 0o600); err != nil {
		return err
	}
	return nil
}

func TestPluginNetTransactionCrashRecoveryLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)
	interfaceName := pluginIntegrationLinkName("fwcr")
	neighborInterface := pluginIntegrationLinkName("fwcn")
	defer deletePluginIntegrationLinkQuietly(t, interfaceName)
	defer deletePluginIntegrationLinkQuietly(t, neighborInterface)

	attrs := netlink.NewLinkAttrs()
	attrs.Name = interfaceName
	attrs.MTU = 1500
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Fatalf("create crash recovery test link: %v", err)
	}
	neighborAttrs := netlink.NewLinkAttrs()
	neighborAttrs.Name = neighborInterface
	neighborAttrs.MTU = 1500
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: neighborAttrs}); err != nil {
		t.Fatalf("create crash recovery neighbor link: %v", err)
	}
	admin := linuxPluginControlNetAdmin{}
	if err := admin.LinkSetUp(interfaceName, true); err != nil {
		t.Fatal(err)
	}
	if err := admin.LinkSetUp(neighborInterface, true); err != nil {
		t.Fatal(err)
	}
	if err := admin.AddrReplace(pluginControlNetAddrRequest{Interface: interfaceName, CIDR: "192.0.2.1/24"}); err != nil {
		t.Fatal(err)
	}
	if err := admin.AddrReplace(pluginControlNetAddrRequest{Interface: neighborInterface, CIDR: "192.0.3.1/24"}); err != nil {
		t.Fatal(err)
	}

	table := 14000 + os.Getpid()%1000
	priority := 14000 + os.Getpid()%1000
	routeOld := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Table: table, Nexthops: []pluginControlNetRouteNexthop{
		{Dev: interfaceName, Gateway: "192.0.2.2", Weight: 1},
		{Dev: neighborInterface, Gateway: "192.0.3.2", Weight: 2},
	}}
	routeNew := routeOld
	routeNew.Nexthops = []pluginControlNetRouteNexthop{
		{Dev: interfaceName, Gateway: "192.0.2.3", Weight: 3},
		{Dev: neighborInterface, Gateway: "192.0.3.3", Weight: 1},
	}
	rule := pluginControlNetRuleRequest{Family: "ipv4", Priority: priority, Table: table, IIF: interfaceName}
	neighborOld := pluginControlNetNeighRequest{Interface: neighborInterface, IP: "192.0.3.9", MAC: "02:00:00:00:72:01", State: "permanent"}
	neighborNew := neighborOld
	neighborNew.MAC = "02:00:00:00:72:02"
	defer admin.RouteDelete(routeOld)
	defer admin.RuleDelete(rule)
	defer admin.NeighDelete(neighborOld)

	if err := admin.RouteReplace(routeOld); err != nil {
		t.Fatalf("create original route: %v", err)
	}
	netlinkRule, err := pluginControlNetRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	netlinkRule.Protocol = 99
	if err := netlink.RuleAdd(netlinkRule); err != nil {
		t.Fatalf("create original policy rule: %v", err)
	}
	if err := admin.NeighReplace(neighborOld); err != nil {
		t.Fatalf("create original neighbor: %v", err)
	}

	testDir := t.TempDir()
	dbPath := filepath.Join(testDir, "crash.db")
	db, err := store.InitDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(testDir, "ready")
	var childOutput bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run", "^TestPluginNetTransactionCrashRecoveryHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"VEER_PLUGIN_NET_CRASH_HELPER=1",
		"VEER_PLUGIN_NET_CRASH_DB="+dbPath,
		"VEER_PLUGIN_NET_CRASH_LINK="+interfaceName,
		"VEER_PLUGIN_NET_CRASH_NEIGH_LINK="+neighborInterface,
		"VEER_PLUGIN_NET_CRASH_TABLE="+strconv.Itoa(table),
		"VEER_PLUGIN_NET_CRASH_PRIORITY="+strconv.Itoa(priority),
		"VEER_PLUGIN_NET_CRASH_READY="+readyPath,
	)
	cmd.Stdout = &childOutput
	cmd.Stderr = &childOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("crash helper did not become ready: %s", childOutput.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	db, err = store.InitDB(dbPath)
	if err != nil {
		t.Fatalf("reopen database after SIGKILL: %v", err)
	}
	defer db.Close()
	pending, err := store.GetPluginNetTransactions(db)
	if err != nil || len(pending) != 3 {
		t.Fatalf("pending transactions after SIGKILL = %+v, err=%v, want 3", pending, err)
	}
	assertPluginCrashJournalSnapshots(t, pending, routeOld, uint8(99), neighborOld.MAC)
	assertPluginCrashRoute(t, admin, routeNew)
	assertPluginCrashRuleProtocol(t, admin, rule, 0)
	assertPluginCrashNeighborMAC(t, admin, neighborNew, neighborNew.MAC)

	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatalf("recover transactions after SIGKILL: %v", err)
	}
	assertPluginCrashRoute(t, admin, routeOld)
	assertPluginCrashRuleProtocol(t, admin, rule, 99)
	assertPluginCrashNeighborMAC(t, admin, neighborOld, neighborOld.MAC)
	assertNoPluginNetTransactions(t, db)
	owned, err := store.GetPluginOwnedResources(db, "crash_recovery_linux")
	if err != nil || len(owned) != 0 {
		t.Fatalf("owned resources after crash recovery = %+v, err=%v, want none", owned, err)
	}
}

func assertPluginCrashJournalSnapshots(t *testing.T, records []store.PluginNetTransaction, routeRequest pluginControlNetRouteRequest, ruleProtocol uint8, neighborMAC string) {
	t.Helper()
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		var state pluginNetTransactionState
		if err := json.Unmarshal([]byte(record.StateJSON), &state); err != nil {
			t.Fatalf("decode %s crash journal: %v", record.Kind, err)
		}
		if len(state.Entries) != 1 {
			t.Fatalf("%s crash journal entries = %+v, want one", record.Kind, state.Entries)
		}
		entry := state.Entries[0]
		switch record.Kind {
		case pluginNetTransactionKindRoute:
			if len(entry.RouteOriginal) != 1 || !pluginControlRouteRequestMatchesState(routeRequest, entry.RouteOriginal[0]) {
				t.Fatalf("route crash snapshot = %+v, want %+v", entry.RouteOriginal, routeRequest)
			}
		case pluginNetTransactionKindRule:
			if len(entry.RuleOriginal) != 1 || entry.RuleOriginal[0].Protocol != ruleProtocol {
				t.Fatalf("rule crash snapshot = %+v, want protocol %d", entry.RuleOriginal, ruleProtocol)
			}
		case pluginNetTransactionKindNeighbor:
			if len(entry.NeighOriginal) != 1 || entry.NeighOriginal[0].Request.MAC != neighborMAC {
				t.Fatalf("neighbor crash snapshot = %+v, want MAC %s", entry.NeighOriginal, neighborMAC)
			}
		default:
			t.Fatalf("unexpected crash journal kind %q", record.Kind)
		}
		seen[record.Kind] = true
	}
	for _, kind := range []string{pluginNetTransactionKindRoute, pluginNetTransactionKindRule, pluginNetTransactionKindNeighbor} {
		if !seen[kind] {
			t.Fatalf("missing %s crash journal", kind)
		}
	}
}

func TestPluginNetTransactionCrashRecoveryHelperProcess(t *testing.T) {
	if os.Getenv("VEER_PLUGIN_NET_CRASH_HELPER") != "1" {
		return
	}
	if err := runPluginNetTransactionCrashRecoveryHelper(); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func runPluginNetTransactionCrashRecoveryHelper() error {
	db, err := store.InitDB(os.Getenv("VEER_PLUGIN_NET_CRASH_DB"))
	if err != nil {
		return err
	}
	admin := linuxPluginControlNetAdmin{}
	interfaceName := os.Getenv("VEER_PLUGIN_NET_CRASH_LINK")
	neighborInterface := os.Getenv("VEER_PLUGIN_NET_CRASH_NEIGH_LINK")
	table, err := strconv.Atoi(os.Getenv("VEER_PLUGIN_NET_CRASH_TABLE"))
	if err != nil {
		return err
	}
	priority, err := strconv.Atoi(os.Getenv("VEER_PLUGIN_NET_CRASH_PRIORITY"))
	if err != nil {
		return err
	}
	const pluginID = "crash_recovery_linux"
	lease := func(resourceType, resourceKey string) error {
		return store.AddPluginOwnedResource(db, store.PluginOwnedResource{
			PluginID: pluginID, ResourceType: resourceType, ResourceKey: resourceKey, MetadataJSON: `{"version":1}`,
		})
	}

	route := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Table: table, Nexthops: []pluginControlNetRouteNexthop{
		{Dev: interfaceName, Gateway: "192.0.2.3", Weight: 3},
		{Dev: neighborInterface, Gateway: "192.0.3.3", Weight: 1},
	}}
	routeOriginal, err := admin.RouteSnapshot(route)
	if err != nil {
		return err
	}
	routeItem := pluginControlNetRouteBatchItem{request: route, present: true, original: routeOriginal}
	routeTransaction, err := beginPluginRouteNetTransaction(db, pluginID, []pluginControlNetRouteBatchItem{routeItem})
	if err != nil {
		return err
	}
	if err := markPluginNetTransactionStarted(db, routeTransaction, 1); err != nil {
		return err
	}
	if err := admin.RouteReplace(route); err != nil {
		return err
	}
	if err := lease(pluginOwnedResourceTypeRoute, pluginControlNetRouteLeaseKey(route)); err != nil {
		return err
	}

	rule := pluginControlNetRuleRequest{Family: "ipv4", Priority: priority, Table: table, IIF: interfaceName}
	ruleOriginal, err := admin.RuleSnapshot(rule)
	if err != nil {
		return err
	}
	ruleItem := pluginControlNetRuleBatchItem{request: rule, present: true, original: ruleOriginal}
	ruleTransaction, err := beginPluginRuleNetTransaction(db, pluginID, []pluginControlNetRuleBatchItem{ruleItem})
	if err != nil {
		return err
	}
	if err := markPluginNetTransactionStarted(db, ruleTransaction, 1); err != nil {
		return err
	}
	if err := admin.RuleReplace(rule); err != nil {
		return err
	}
	if err := lease(pluginOwnedResourceTypeRule, pluginControlNetRuleLeaseKey(rule)); err != nil {
		return err
	}

	neighbor := pluginControlNetNeighRequest{Interface: neighborInterface, IP: "192.0.3.9", MAC: "02:00:00:00:72:02", State: "permanent"}
	neighborOriginal, err := admin.NeighSnapshot(neighbor)
	if err != nil {
		return err
	}
	neighborItem := pluginControlNetNeighBatchItem{request: neighbor, present: true, original: neighborOriginal}
	neighborTransaction, err := beginPluginNeighNetTransaction(db, pluginID, []pluginControlNetNeighBatchItem{neighborItem})
	if err != nil {
		return err
	}
	if err := markPluginNetTransactionStarted(db, neighborTransaction, 1); err != nil {
		return err
	}
	if err := admin.NeighReplace(neighbor); err != nil {
		return err
	}
	if err := lease(pluginOwnedResourceTypeNeighbor, pluginControlNetNeighLeaseKey(neighbor)); err != nil {
		return err
	}

	return os.WriteFile(os.Getenv("VEER_PLUGIN_NET_CRASH_READY"), []byte("ready\n"), 0o600)
}

func assertPluginCrashRoute(t *testing.T, admin linuxPluginControlNetAdmin, request pluginControlNetRouteRequest) {
	t.Helper()
	states, err := admin.RouteSnapshot(request)
	if err != nil || len(states) != 1 || !pluginControlRouteRequestMatchesState(request, states[0]) {
		t.Fatalf("route state = %+v, err=%v, want %+v", states, err, request)
	}
}

func assertPluginCrashRuleProtocol(t *testing.T, admin linuxPluginControlNetAdmin, request pluginControlNetRuleRequest, want uint8) {
	t.Helper()
	states, err := admin.RuleSnapshot(request)
	if err != nil || len(states) != 1 || states[0].Protocol != want {
		t.Fatalf("policy rule state = %+v, err=%v, want protocol %d", states, err, want)
	}
}

func assertPluginCrashNeighborMAC(t *testing.T, admin linuxPluginControlNetAdmin, request pluginControlNetNeighRequest, want string) {
	t.Helper()
	states, err := admin.NeighSnapshot(request)
	if err != nil || len(states) != 1 || states[0].Request.MAC != want {
		t.Fatalf("neighbor state = %+v, err=%v, want MAC %s", states, err, want)
	}
}

func assertPluginNetPolicyTransactionState(
	t *testing.T,
	admin linuxPluginControlNetAdmin,
	route pluginControlNetRouteRequest,
	rule pluginControlNetRuleRequest,
	neighbor pluginControlNetNeighRequest,
	present bool,
) {
	t.Helper()
	routes, routeErr := admin.RouteSnapshot(route)
	rules, ruleErr := admin.RuleSnapshot(rule)
	neighbors, neighborErr := admin.NeighSnapshot(neighbor)
	want := 0
	if present {
		want = 1
	}
	if routeErr != nil || len(routes) != want {
		t.Fatalf("route state = %+v, err=%v, want %d", routes, routeErr, want)
	}
	if ruleErr != nil || len(rules) != want {
		t.Fatalf("rule state = %+v, err=%v, want %d", rules, ruleErr, want)
	}
	if neighborErr != nil || len(neighbors) != want {
		t.Fatalf("neighbor state = %+v, err=%v, want %d", neighbors, neighborErr, want)
	}
}

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
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: pluginsRoot})
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

func TestPluginControlNetAddrReplaceIdempotentLinuxIntegration(t *testing.T) {
	requirePluginLinuxIntegration(t)

	interfaceName := pluginIntegrationLinkName("fwai")
	defer deletePluginIntegrationLinkQuietly(t, interfaceName)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = interfaceName
	attrs.MTU = 1500
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
		t.Fatalf("create address idempotency link: %v", err)
	}
	admin := linuxPluginControlNetAdmin{}
	if err := admin.LinkSetUp(interfaceName, true); err != nil {
		t.Fatalf("set address idempotency link up: %v", err)
	}
	request := pluginControlNetAddrRequest{Interface: interfaceName, CIDR: "192.0.2.31/24"}
	if err := admin.AddrReplace(request); err != nil {
		t.Fatalf("initial AddrReplace() error = %v", err)
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		t.Fatalf("resolve address idempotency link: %v", err)
	}

	updates := make(chan netlink.AddrUpdate, 16)
	done := make(chan struct{})
	if err := netlink.AddrSubscribeWithOptions(updates, done, netlink.AddrSubscribeOptions{}); err != nil {
		close(done)
		t.Fatalf("subscribe address updates: %v", err)
	}
	defer close(done)
	if err := admin.AddrReplace(request); err != nil {
		t.Fatalf("unchanged AddrReplace() error = %v", err)
	}

	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case update := <-updates:
			if update.LinkIndex == link.Attrs().Index && update.LinkAddress.String() == request.CIDR {
				t.Fatalf("unchanged AddrReplace emitted netlink update: %+v", update)
			}
		case <-timer.C:
			return
		}
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
	rt := newPluginControlRuntime(db, pluginsEnabledTestConfig(&Config{PluginsDir: pluginsRoot}), nil).(*gojaPluginControlRuntime)
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
