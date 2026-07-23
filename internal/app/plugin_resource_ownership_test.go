package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginCreatedLinkOwnershipIsCleanedWhenPluginDisappears(t *testing.T) {
	dir := t.TempDir()
	writeOwnedLinkPlugin(t, dir, `
exports.onAction = function () {
  var result = net.link.ensureDummy({name:"veerowned0", mtu:1500, up:true});
  return {created:result.created, owned:net.link.owned()};
};
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "owned_link_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "owned_link_plugin")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("create owned link: %v", err)
	}
	owned, err := store.GetPluginOwnedResources(db, "owned_link_plugin")
	if err != nil || len(owned) != 1 || owned[0].ResourceKey != "veerowned0" {
		t.Fatalf("owned resources = %+v, err=%v", owned, err)
	}
	runtime.Reconcile(PluginCatalog{})
	owned, err = store.GetPluginOwnedResources(db, "owned_link_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("owned resources after removal = %+v, err=%v", owned, err)
	}
	if !containsPluginNetAdminCall(controller.calls, "delete:veerowned0") {
		t.Fatalf("net admin calls = %+v, want owned link deletion", controller.calls)
	}
}

func TestPluginExistingLinkIsNotClaimedOrDeleted(t *testing.T) {
	dir := t.TempDir()
	writeOwnedLinkPlugin(t, dir, `
exports.onAction = function () { return net.link.ensureDummy({name:"veerexisting0", mtu:1500, up:true}); };
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"veerexisting0": {Name: "veerexisting0", Kind: "dummy", IfIndex: 42, MTU: 1500, Up: true},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "owned_link_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "owned_link_plugin")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owned, err := store.GetPluginOwnedResources(db, "owned_link_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("pre-existing link ownership = %+v, err=%v", owned, err)
	}
	runtime.Reconcile(PluginCatalog{})
	if containsPluginNetAdminCall(controller.calls, "delete:veerexisting0") {
		t.Fatalf("pre-existing link was deleted: %+v", controller.calls)
	}
}

func TestPluginCanReleaseCreatedLinkOwnership(t *testing.T) {
	dir := t.TempDir()
	writeOwnedLinkPlugin(t, dir, `
exports.onAction = function () {
  net.link.ensureDummy({name:"veerreleased0", mtu:1500, up:true});
  net.link.release("veerreleased0");
  return {owned:net.link.owned()};
};
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "owned_link_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "owned_link_plugin")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	runtime.Reconcile(PluginCatalog{})
	if containsPluginNetAdminCall(controller.calls, "delete:veerreleased0") {
		t.Fatalf("released link was deleted: %+v", controller.calls)
	}
}

func TestPluginCannotTakeOverAnotherPluginsOwnedLink(t *testing.T) {
	dir := t.TempDir()
	writeOwnedLinkPlugin(t, dir, `exports.onAction = function () { net.link.ensureDummy({name:"veershared0", mtu:1500, up:true}); };`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	runtime.netAdmin = &pluginControlNetAdminTest{}
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "owned_link_plugin")
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "other_plugin", ResourceType: pluginOwnedResourceTypeLink, ResourceKey: "veershared0", MetadataJSON: `{"name":"veershared0","kind":"dummy"}`,
	}); err != nil {
		t.Fatal(err)
	}
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "owned_link_plugin")
	_, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "owned by plugin other_plugin") {
		t.Fatalf("ownership takeover error = %v", err)
	}
}

func TestPluginOwnedLinkCleanupFailureRetainsLedgerForRetry(t *testing.T) {
	db := openTestDB(t)
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "retry_plugin", ResourceType: pluginOwnedResourceTypeLink, ResourceKey: "veerretry0", MetadataJSON: `{"name":"veerretry0","kind":"dummy"}`,
	}); err != nil {
		t.Fatal(err)
	}
	controller := &pluginControlNetAdminTest{
		links: map[string]pluginControlNetLinkInfo{
			"veerretry0": {Name: "veerretry0", IfIndex: 88, Kind: "dummy", MTU: 1500, Up: true},
		},
		deleteErrors: map[string]error{"veerretry0": errors.New("injected delete failure")},
	}
	if err := cleanupPluginOwnedLinks(db, controller, "retry_plugin"); err == nil || !strings.Contains(err.Error(), "injected delete failure") {
		t.Fatalf("first cleanup error = %v", err)
	}
	owned, err := store.GetPluginOwnedResources(db, "retry_plugin")
	if err != nil || len(owned) != 1 {
		t.Fatalf("ledger after failed cleanup = %+v, err=%v", owned, err)
	}
	delete(controller.deleteErrors, "veerretry0")
	if err := cleanupPluginOwnedLinks(db, controller, "retry_plugin"); err != nil {
		t.Fatalf("retry cleanup error = %v", err)
	}
	owned, err = store.GetPluginOwnedResources(db, "retry_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("ledger after cleanup retry = %+v, err=%v", owned, err)
	}
}

func TestPluginHostNetworkMutationsAreLeasedAndRestored(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "lease_plugin", `
exports.onAction = function () {
  net.link.setMaster({link:"host0", master:"br0", up:true});
  net.link.setMTU("host0", 1400);
  net.link.setARP("host0", false);
  net.link.setPromiscuous("host0", true);
  net.link.setOffloads("host0", {gro:false});
  net.link.setGSO("host0", {max_size:1400, max_segs:1});
  net.addr.replace({interface:"host0", cidr:"192.0.2.10/24"});
  net.route.replace({dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100});
  net.rule.delete({family:"ipv4", priority:1000, table:100, src:"192.0.2.0/24", iif:"host0"});
  net.neigh.delete({interface:"host0", ip:"192.0.2.1"});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	originalRoute := pluginControlNetRouteState{Dst: "0.0.0.0/0", Gateway: "192.0.2.254", Dev: "host0", DevIfIndex: 50, Table: 100}
	ruleRequest := pluginControlNetRuleRequest{Family: "ipv4", Priority: 1000, Table: 100, Src: "192.0.2.0/24", IIF: "host0"}
	neighborRequest := pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", State: "permanent"}
	controller := &pluginControlNetAdminTest{
		links: map[string]pluginControlNetLinkInfo{
			"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, MAC: "02:00:00:00:50:01", Up: false, ARP: true, GSOMaxSize: 65536, GSOMaxSegs: 64},
			"br0":   {Name: "br0", IfIndex: 51, Kind: "bridge", MTU: 1500, MAC: "02:00:00:00:51:01", Up: true, ARP: true},
		},
		offloads: map[string]map[string]bool{"host0": {"gro": true}},
		routeSnapshots: map[string][]pluginControlNetRouteState{
			pluginControlNetRouteLeaseKey(pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Dev: "host0", Table: 100}): {originalRoute},
		},
		ruleSnapshots: map[string][]pluginControlNetRuleState{
			pluginControlNetRuleLeaseKey(ruleRequest): {{Request: ruleRequest}},
		},
		neighSnapshots: map[string][]pluginControlNetNeighState{
			pluginControlNetNeighLeaseKey(neighborRequest): {{Request: pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:50:02", State: "permanent"}, LinkIfIndex: 50}},
		},
	}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "lease_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "lease_plugin")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatalf("apply leased network mutation: %v", err)
	}
	owned, err := store.GetPluginOwnedResources(db, "lease_plugin")
	if err != nil || len(owned) != 11 {
		t.Fatalf("leased resources = %+v, err=%v, want 11", owned, err)
	}
	runtime.Reconcile(PluginCatalog{})
	owned, err = store.GetPluginOwnedResources(db, "lease_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("leased resources after cleanup = %+v, err=%v", owned, err)
	}
	for _, want := range []string{
		"routeDelete:0.0.0.0/0:host0:192.0.2.1:100:0", "routeRestore:1",
		"ruleRestore:1", "neighRestore:1",
		"addrDelete:host0:192.0.2.10/24", "clearMaster:host0", "setUp:host0:false",
		"setMTU:host0:1500", "setARP:host0:true", "setPromiscuous:host0:false",
		"setOffloads:host0:gro=true", "setGSO:host0:65536:64",
	} {
		if !containsPluginNetAdminCall(controller.calls, want) {
			t.Fatalf("net admin calls = %+v, missing restore %s", controller.calls, want)
		}
	}
}

func TestPluginNetworkLeaseRejectsCrossPluginTakeover(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "lease_owner", `exports.onAction = function () { net.link.setMTU("host0", 1400); };`)
	writeNetworkLeasePlugin(t, dir, "lease_contender", `exports.onAction = function () { net.link.setMTU("host0", 1300); };`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	runtime.netAdmin = &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, MAC: "02:00:00:00:50:01", Up: true, ARP: true},
	}}
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "lease_owner")
	owner := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "lease_owner")
	contender := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "lease_contender")
	if _, err := runtime.QueryPluginAction(owner, owner.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	_, err := runtime.QueryPluginAction(contender, contender.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "owned by plugin lease_owner") {
		t.Fatalf("cross-plugin lease error = %v", err)
	}
}

func TestPluginNetworkLeaseReleasesWhenStateReturnsToOriginal(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "release_plugin", `
exports.onAction = function () {
  net.link.setMTU("host0", 1400);
  net.link.setMTU("host0", 1500);
  net.addr.replace({interface:"host0", cidr:"192.0.2.10/24"});
  net.addr.delete({interface:"host0", cidr:"192.0.2.10/24"});
  net.route.replace({dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100});
  net.route.delete({dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	runtime.netAdmin = &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, MAC: "02:00:00:00:50:01", Up: true, ARP: true},
	}}
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "release_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "release_plugin")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owned, err := store.GetPluginOwnedResources(db, "release_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("restored leases = %+v, err=%v, want none", owned, err)
	}
}

func TestPluginNetworkLeaseFromPreviousBootIsDiscarded(t *testing.T) {
	previousBootID := pluginOwnershipBootID
	pluginOwnershipBootID = "current-boot"
	t.Cleanup(func() { pluginOwnershipBootID = previousBootID })
	db := openTestDB(t)
	metadata, err := json.Marshal(pluginOwnedLinkMutation{
		Version: 1, BootID: "previous-boot", Interface: "host0", Property: "mtu", Original: json.RawMessage(`1500`),
		OriginalIfIndex: 50, OriginalKind: "device", OriginalMAC: "02:00:00:00:50:01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "boot_plugin", ResourceType: pluginOwnedResourceTypeLinkState, ResourceKey: "host0/mtu", MetadataJSON: string(metadata),
	}); err != nil {
		t.Fatal(err)
	}
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 9000, MAC: "02:00:00:00:50:01", Up: true},
	}}
	if err := cleanupPluginOwnedResources(db, controller, "boot_plugin"); err != nil {
		t.Fatal(err)
	}
	if containsPluginNetAdminCall(controller.calls, "setMTU:host0:1500") {
		t.Fatalf("previous-boot state was restored: %+v", controller.calls)
	}
	owned, err := store.GetPluginOwnedResources(db, "boot_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("previous-boot lease = %+v, err=%v", owned, err)
	}
}

func TestPluginNetworkLeaseAPIListsAndRestoresOwnedMutation(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "lease_api", `
exports.onAction = function () {
  net.link.setMTU("host0", 1400);
  var before = net.lease.list();
  var result = net.lease.restore(before[0].type, before[0].key);
  return {before:before.length, restored:result.restored, after:net.lease.list().length};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, MAC: "02:00:00:00:50:01", Up: true},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "lease_api")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "lease_api")
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"before":1`) || !strings.Contains(string(raw), `"restored":true`) || !strings.Contains(string(raw), `"after":0`) {
		t.Fatalf("lease API result = %s", raw)
	}
	if !containsPluginNetAdminCall(controller.calls, "setMTU:host0:1500") {
		t.Fatalf("net admin calls = %+v, missing lease restoration", controller.calls)
	}
}

func TestPluginOwnedResourceIdentityChangeDoesNotTouchReplacementLink(t *testing.T) {
	db := openTestDB(t)
	metadata, err := json.Marshal(pluginOwnedLinkMutation{
		Version: 1, Interface: "host0", Property: "mtu", Original: json.RawMessage(`1500`),
		OriginalIfIndex: 50, OriginalKind: "device", OriginalMAC: "02:00:00:00:50:01",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "identity_plugin", ResourceType: pluginOwnedResourceTypeLinkState, ResourceKey: "host0/mtu", MetadataJSON: string(metadata),
	}); err != nil {
		t.Fatal(err)
	}
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 99, Kind: "device", MTU: 9000, MAC: "02:00:00:00:99:01", Up: true},
	}}
	if err := cleanupPluginOwnedResources(db, controller, "identity_plugin"); err != nil {
		t.Fatal(err)
	}
	if containsPluginNetAdminCall(controller.calls, "setMTU:host0:1500") {
		t.Fatalf("replacement interface was modified: %+v", controller.calls)
	}
	owned, err := store.GetPluginOwnedResources(db, "identity_plugin")
	if err != nil || len(owned) != 0 {
		t.Fatalf("stale identity lease = %+v, err=%v", owned, err)
	}
}

func TestPluginCannotDeleteUnownedHostLink(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "delete_plugin", `exports.onAction = function () { net.link.delete("host0"); };`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "delete_plugin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "delete_plugin")
	_, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "only links created and owned") {
		t.Fatalf("delete unowned link error = %v", err)
	}
	if containsPluginNetAdminCall(controller.calls, "delete:host0") {
		t.Fatalf("unowned link was deleted: %+v", controller.calls)
	}
}

func writeOwnedLinkPlugin(t *testing.T, dir, handler string) {
	t.Helper()
	writeTestPlugin(t, dir, "owned_link_plugin", `{
  "api_version":"v1","id":"owned_link_plugin","name":"Owned Link Plugin","version":"1.0.0","kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["plugin.register","net.admin"],
    "net_access":[{"interfaces":["veer*"],"operations":["link.create","link.delete","link.read"]}]
  }
}`)
	writePluginControlScript(t, dir, "owned_link_plugin", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
`+handler)
}

func writeNetworkLeasePlugin(t *testing.T, dir, pluginID, handler string) {
	t.Helper()
	writeTestPlugin(t, dir, pluginID, `{
  "api_version":"v1","id":"`+pluginID+`","name":"Network Lease Plugin","version":"1.0.0","kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["plugin.register","net.admin"],
    "net_access":[
      {"interfaces":["host*"],"operations":["addr.write","link.delete","link.master","link.offload","link.read","link.state","neigh.write","route.write","rule.write"]},
      {"interfaces":["br*"],"operations":["link.master","link.read"]}
    ]
  }
}`)
	writePluginControlScript(t, dir, pluginID, `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
`+handler)
}

func containsPluginNetAdminCall(calls []string, expected string) bool {
	for _, call := range calls {
		if call == expected {
			return true
		}
	}
	return false
}
