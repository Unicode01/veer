package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

type pluginControlNetworkProviderTest struct {
	*pluginControlNetAdminTest
	namespaces map[string]pluginControlNetNamespaceInfo
	devices    map[string]pluginControlNetTunTapInfo
	owners     map[string]string
	readPacket []byte
	calls      []string
	activeNS   string
}

func (p *pluginControlNetworkProviderTest) RunInNamespace(name string, fn func() error) error {
	previous := p.activeNS
	p.activeNS = name
	p.calls = append(p.calls, "namespace.enter:"+name)
	defer func() {
		p.calls = append(p.calls, "namespace.exit:"+name)
		p.activeNS = previous
	}()
	return fn()
}

func newPluginControlNetworkProviderTest() *pluginControlNetworkProviderTest {
	return &pluginControlNetworkProviderTest{
		pluginControlNetAdminTest: &pluginControlNetAdminTest{},
		namespaces:                make(map[string]pluginControlNetNamespaceInfo),
		devices:                   make(map[string]pluginControlNetTunTapInfo),
		owners:                    make(map[string]string),
		readPacket:                []byte{0x45, 0, 0, 20},
	}
}

func (p *pluginControlNetworkProviderTest) NamespaceLookup(name string) (pluginControlNetNamespaceInfo, bool, error) {
	item, ok := p.namespaces[name]
	return item, ok, nil
}

func (p *pluginControlNetworkProviderTest) NamespaceList() ([]pluginControlNetNamespaceInfo, error) {
	out := make([]pluginControlNetNamespaceInfo, 0, len(p.namespaces))
	for _, item := range p.namespaces {
		out = append(out, item)
	}
	return out, nil
}

func (p *pluginControlNetworkProviderTest) NamespaceEnsure(req pluginControlNetNamespaceRequest) (pluginControlNetNamespaceResult, error) {
	if item, ok := p.namespaces[req.Name]; ok {
		return pluginControlNetNamespaceResult{Info: item}, nil
	}
	item := pluginControlNetNamespaceInfo{Name: req.Name, Identity: pluginControlNetNamespaceIdentity{Device: 7, Inode: uint64(100 + len(p.namespaces))}}
	p.namespaces[req.Name] = item
	p.calls = append(p.calls, "namespace.ensure:"+req.Name)
	return pluginControlNetNamespaceResult{Info: item, Created: true}, nil
}

func (p *pluginControlNetworkProviderTest) NamespaceDelete(name string, identity pluginControlNetNamespaceIdentity) error {
	item, ok := p.namespaces[name]
	if !ok {
		return nil
	}
	if (identity.Device != 0 || identity.Inode != 0) && !pluginControlNamespaceIdentityEqual(item.Identity, identity) {
		return fmt.Errorf("namespace changed identity")
	}
	delete(p.namespaces, name)
	p.calls = append(p.calls, "namespace.delete:"+name)
	return nil
}

func (p *pluginControlNetworkProviderTest) TunTapEnsure(owner string, req pluginControlNetTunTapRequest) (pluginControlNetTunTapResult, error) {
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	if item, ok := p.devices[key]; ok {
		if p.owners[key] != owner {
			return pluginControlNetTunTapResult{}, fmt.Errorf("owner conflict")
		}
		return pluginControlNetTunTapResult{Info: item}, nil
	}
	item := pluginControlNetTunTapInfo{Name: req.Name, Namespace: req.Namespace, Mode: req.Mode, IfIndex: 55, MTU: 1500, Up: true}
	p.devices[key] = item
	p.owners[key] = owner
	p.calls = append(p.calls, "tuntap.ensure:"+key)
	return pluginControlNetTunTapResult{Info: item, Created: true}, nil
}

func (p *pluginControlNetworkProviderTest) TunTapClose(owner string, req pluginControlNetTunTapCloseRequest) error {
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	if currentOwner := p.owners[key]; currentOwner != "" && currentOwner != owner {
		return fmt.Errorf("owner conflict")
	}
	delete(p.devices, key)
	delete(p.owners, key)
	p.calls = append(p.calls, "tuntap.close:"+key)
	return nil
}

func (p *pluginControlNetworkProviderTest) TunTapRead(owner string, req pluginControlNetTunTapReadRequest) (pluginControlNetTunTapPacket, error) {
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	if p.owners[key] != owner {
		return pluginControlNetTunTapPacket{}, fmt.Errorf("device is not open")
	}
	p.calls = append(p.calls, "tuntap.read:"+key)
	return pluginControlNetTunTapPacket{Packet: append([]byte(nil), p.readPacket...)}, nil
}

func (p *pluginControlNetworkProviderTest) TunTapWrite(owner string, req pluginControlNetTunTapWriteRequest) (int, error) {
	key := pluginControlTunTapResourceKey(req.Namespace, req.Name)
	if p.owners[key] != owner {
		return 0, fmt.Errorf("device is not open")
	}
	p.calls = append(p.calls, "tuntap.write:"+key)
	return len(req.Packet), nil
}

func (p *pluginControlNetworkProviderTest) TunTapList(owner string) []pluginControlNetTunTapInfo {
	out := make([]pluginControlNetTunTapInfo, 0)
	for key, item := range p.devices {
		if p.owners[key] == owner {
			out = append(out, item)
		}
	}
	return out
}

func (p *pluginControlNetworkProviderTest) TunTapCloseAll(owner string) {
	for key, currentOwner := range p.owners {
		if owner == "" || owner == currentOwner {
			delete(p.devices, key)
			delete(p.owners, key)
		}
	}
}

func TestNormalizePluginManifestRequiresScopedNamespaceProviderAccess(t *testing.T) {
	manifest := PluginManifest{
		APIVersion: "v1", ID: "netns_scope", Name: "Netns Scope", Version: "1.0.0", Kind: "control",
		Control: &PluginControl{Main: "control.js", Permissions: []string{"net.namespace"}},
	}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "namespace_access is required") {
		t.Fatalf("missing namespace_access error = %v", err)
	}
	manifest.Control.NamespaceAccess = []string{"veer-*"}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("valid namespace manifest: %v", err)
	}

	manifest.Control.Permissions = []string{"net.tuntap"}
	manifest.Control.NetAccess = []PluginNetAccess{{Interfaces: []string{"tun*"}, Operations: []string{"tuntap"}}}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("valid TUN/TAP manifest: %v", err)
	}
	manifest.Control.NetAccess[0].Operations = []string{"link.read"}
	if err := normalizePluginManifest(&manifest); err == nil || !strings.Contains(err.Error(), "requires net.admin") {
		t.Fatalf("cross-permission net_access error = %v", err)
	}
}

func TestPluginControlNamespaceAndTunTapLifecycle(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "net_provider", `{
  "api_version":"v1","id":"net_provider","name":"Net Provider","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","net.namespace","net.tuntap"],
    "namespace_access":["veer-*"],
    "net_access":[{"interfaces":["tun*"],"operations":["tuntap"]}]}
}`)
	writePluginControlScript(t, dir, "net_provider", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
exports.onAction = function () {
  var ns = net.namespace.ensure({name:"veer-test", loopback_up:true});
  var device = net.tuntap.ensure({name:"tun0", namespace:"veer-test", mode:"tun", mtu:1400});
  var write = net.tuntap.write({name:"tun0", namespace:"veer-test", data:"45000014"});
  var read = net.tuntap.read({name:"tun0", namespace:"veer-test", timeout_ms:10});
  return {namespace:ns, device:device, write:write, read:read};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	provider := newPluginControlNetworkProviderTest()
	runtime.netAdmin = provider
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_provider")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_provider")
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), `"data":"45000014"`) || !strings.Contains(string(encoded), `"bytes":4`) {
		t.Fatalf("provider action result = %s", encoded)
	}
	owned, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(owned) != 2 {
		t.Fatalf("owned provider resources = %+v, err=%v", owned, err)
	}

	runtime.Reconcile(PluginCatalog{})
	wantTail := []string{"tuntap.close:veer-test/tun0", "namespace.delete:veer-test"}
	if len(provider.calls) < 2 || strings.Join(provider.calls[len(provider.calls)-2:], ",") != strings.Join(wantTail, ",") {
		t.Fatalf("cleanup calls = %+v, want tail %+v", provider.calls, wantTail)
	}
	remaining, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining provider ownership = %+v, err=%v", remaining, err)
	}
}

func TestPluginControlTunTapRejectsUndeclaredNamespaceBeforeProvider(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "net_provider_denied", `{
  "api_version":"v1","id":"net_provider_denied","name":"Net Provider Denied","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","net.tuntap"],
    "namespace_access":["veer-ok"],
    "net_access":[{"interfaces":["tun*"],"operations":["tuntap"]}]}
}`)
	writePluginControlScript(t, dir, "net_provider_denied", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
exports.onAction = function () { return net.tuntap.ensure({name:"tun0", namespace:"veer-denied", mode:"tun"}); };`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	provider := newPluginControlNetworkProviderTest()
	runtime.netAdmin = provider
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_provider_denied")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_provider_denied")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "namespace_access") {
		t.Fatalf("namespace denial = %v", err)
	}
	if len(provider.calls) != 0 {
		t.Fatalf("denied request reached provider: %+v", provider.calls)
	}
}

func TestPluginControlScopedNamespaceNetAdminLifecycle(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "netns_admin", `{
  "api_version":"v1","id":"netns_admin","name":"Netns Admin","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","net.admin","net.namespace"],
    "namespace_access":["veer-test"],
    "net_access":[{"interfaces":["nsdummy0","eth0"],"operations":["link.create","link.read","addr.write","route.write","rule.write","neigh.write"]}]}
}`)
	writePluginControlScript(t, dir, "netns_admin", `
plugin.action({id:"apply", runtime_update:"runtime_apply"});
exports.onReconcile = function () {};
exports.onAction = function () {
  net.link.ensureDummy({namespace:"veer-test", name:"nsdummy0", mtu:1400, up:true});
  net.addr.replace({namespace:"veer-test", interface:"eth0", cidr:"192.0.2.1/24"});
  net.route.replace({namespace:"veer-test", dst:"198.51.100.0/24", dev:"eth0", table:100});
  net.rule.replace({namespace:"veer-test", family:"ipv4", priority:1000, table:100, iif:"eth0"});
  net.neigh.replace({namespace:"veer-test", interface:"eth0", ip:"192.0.2.2", mac:"02:00:00:00:00:02"});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	provider := newPluginControlNetworkProviderTest()
	provider.namespaces["veer-test"] = pluginControlNetNamespaceInfo{
		Name: "veer-test", Identity: pluginControlNetNamespaceIdentity{Device: 7, Inode: 101},
	}
	runtime.netAdmin = provider
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "netns_admin")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "netns_admin")
	if err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if provider.activeNS != "" {
		t.Fatalf("provider namespace leaked after action: %q", provider.activeNS)
	}
	entered := 0
	for _, call := range provider.calls {
		if call == "namespace.enter:veer-test" {
			entered++
		}
	}
	if entered < 10 {
		t.Fatalf("scoped operations did not consistently enter namespace: calls=%+v", provider.calls)
	}
	owned, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(owned) < 5 {
		t.Fatalf("scoped owned resources = %+v, err=%v", owned, err)
	}
	for _, item := range owned {
		if item.ResourceType == pluginOwnedResourceTypeLink || item.ResourceType == pluginOwnedResourceTypeAddress ||
			item.ResourceType == pluginOwnedResourceTypeRoute || item.ResourceType == pluginOwnedResourceTypeRule || item.ResourceType == pluginOwnedResourceTypeNeighbor {
			if !strings.HasPrefix(item.ResourceKey, "veer-test/") {
				t.Fatalf("scoped resource key %q does not include namespace", item.ResourceKey)
			}
		}
	}
	runtime.Reconcile(PluginCatalog{})
	remaining, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining scoped ownership = %+v, err=%v", remaining, err)
	}
}

func TestCleanupScopedNetworkLeaseSkipsReplacedNamespace(t *testing.T) {
	db := openTestDB(t)
	provider := newPluginControlNetworkProviderTest()
	provider.namespaces["veer-test"] = pluginControlNetNamespaceInfo{
		Name: "veer-test", Identity: pluginControlNetNamespaceIdentity{Device: 7, Inode: 202},
	}
	provider.links = map[string]pluginControlNetLinkInfo{
		"nsdummy0": {Name: "nsdummy0", IfIndex: 44, Kind: "dummy", MAC: "02:00:00:00:00:44"},
	}
	metadata, err := json.Marshal(pluginOwnedLinkClaim{
		BootID: pluginOwnershipBootID, Namespace: "veer-test",
		NamespaceIdentity: pluginControlNetNamespaceIdentity{Device: 7, Inode: 101},
		Name:              "nsdummy0", Kind: "dummy", IfIndex: 44, MAC: "02:00:00:00:00:44",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "netns_owner", ResourceType: pluginOwnedResourceTypeLink,
		ResourceKey: pluginControlNetScopedResourceKey("veer-test", "nsdummy0"), MetadataJSON: string(metadata),
	}); err != nil {
		t.Fatal(err)
	}
	if err := cleanupPluginOwnedResources(db, provider, "netns_owner"); err != nil {
		t.Fatal(err)
	}
	for _, call := range provider.calls {
		if call == "delete:nsdummy0" || call == "namespace.enter:veer-test" {
			t.Fatalf("cleanup touched replacement namespace: %+v", provider.calls)
		}
	}
	remaining, err := store.GetPluginOwnedResources(db, "netns_owner")
	if err != nil || len(remaining) != 0 {
		t.Fatalf("replacement namespace lease was not retired: %+v err=%v", remaining, err)
	}
}

func TestPluginControlNetTransactionRejectsMixedNamespaces(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "netns_mixed_tx", `{
  "api_version":"v1","id":"netns_mixed_tx","name":"Netns Mixed Transaction","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","net.admin","net.namespace"],
    "namespace_access":["veer-a","veer-b"],
    "net_access":[{"interfaces":["eth0"],"operations":["route.write"]}]}
}`)
	writePluginControlScript(t, dir, "netns_mixed_tx", `
plugin.action({id:"apply", runtime_update:"runtime_apply"});
exports.onReconcile = function () {};
exports.onAction = function () {
  net.route.transaction([
    {op:"replace", request:{namespace:"veer-a", dst:"192.0.2.0/24", dev:"eth0", table:100}},
    {op:"replace", request:{namespace:"veer-b", dst:"198.51.100.0/24", dev:"eth0", table:100}}
  ]);
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	provider := newPluginControlNetworkProviderTest()
	provider.namespaces["veer-a"] = pluginControlNetNamespaceInfo{Name: "veer-a", Identity: pluginControlNetNamespaceIdentity{Device: 7, Inode: 101}}
	provider.namespaces["veer-b"] = pluginControlNetNamespaceInfo{Name: "veer-b", Identity: pluginControlNetNamespaceIdentity{Device: 7, Inode: 102}}
	runtime.netAdmin = provider
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "netns_mixed_tx")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "netns_mixed_tx")
	err := runtime.ApplyPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "same namespace") {
		t.Fatalf("mixed namespace transaction error = %v", err)
	}
	if len(provider.calls) != 0 {
		t.Fatalf("mixed namespace transaction reached provider: %+v", provider.calls)
	}
}
