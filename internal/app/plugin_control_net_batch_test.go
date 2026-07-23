package app

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginControlNetTransactionsApplyAllGroups(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_batch", `
exports.onAction = function () {
  return {
    route: net.route.transaction([
      {op:"replace", request:{dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100}},
      {op:"delete", request:{dst:"198.51.100.0/24", dev:"host0", table:100}}
    ]),
    rule: net.rule.transaction([
      {op:"replace", request:{family:"ipv4", priority:1000, table:100, src:"192.0.2.0/24", iif:"host0"}}
    ]),
    neigh: net.neigh.transaction([
      {op:"replace", request:{interface:"host0", ip:"192.0.2.1", mac:"02:00:00:00:00:02", state:"permanent"}}
    ])
  };
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_batch")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_batch")
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("network transactions: %v", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"route":{"operations":2,"status":"completed"}`, `"rule":{"operations":1,"status":"completed"}`, `"neigh":{"operations":1,"status":"completed"}`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("transaction result = %s, missing %s", data, want)
		}
	}
	owned, err := store.GetPluginOwnedResources(db, "net_batch")
	if err != nil || len(owned) != 3 {
		t.Fatalf("owned resources = %+v, err=%v, want 3", owned, err)
	}
	assertNoPluginNetTransactions(t, db)
}

func TestPluginControlNetTransactionReleasesRestoredAbsentLease(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_batch_release", `
exports.onAction = function () {
  var route = {dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100};
  net.route.replace(route);
  return net.route.transaction([{op:"delete", request:route}]);
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	runtime.netAdmin = &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
	}}
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_batch_release")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_batch_release")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owned, err := store.GetPluginOwnedResources(db, "net_batch_release")
	if err != nil || len(owned) != 0 {
		t.Fatalf("restored route lease = %+v, err=%v, want none", owned, err)
	}
}

func TestPluginControlNetTransactionsRollbackOnMutationFailure(t *testing.T) {
	tests := []struct {
		name      string
		handler   string
		configure func(*pluginControlNetBatchAdminTest)
		wantCalls []string
	}{
		{
			name: "route",
			handler: `exports.onAction = function () { return net.route.transaction([
  {op:"replace", request:{dst:"198.51.100.0/24", dev:"host0", table:100}},
  {op:"replace", request:{dst:"203.0.113.0/24", dev:"host0", table:100}}
]); };`,
			configure: func(controller *pluginControlNetBatchAdminTest) {
				req := pluginControlNetRouteRequest{Dst: "203.0.113.0/24", Dev: "host0", Table: 100}
				controller.routeReplaceErrors = map[string]error{pluginControlNetRouteLeaseKey(req): errors.New("injected route failure")}
			},
			wantCalls: []string{"routeDelete:203.0.113.0/24:host0::100:0", "routeDelete:198.51.100.0/24:host0::100:0"},
		},
		{
			name: "rule",
			handler: `exports.onAction = function () { return net.rule.transaction([
  {op:"replace", request:{family:"ipv4", priority:1000, table:100, iif:"host0"}},
  {op:"replace", request:{family:"ipv4", priority:1001, table:100, iif:"host0"}}
]); };`,
			configure: func(controller *pluginControlNetBatchAdminTest) {
				req := pluginControlNetRuleRequest{Family: "ipv4", Priority: 1001, Table: 100, IIF: "host0"}
				controller.ruleReplaceErrors = map[string]error{pluginControlNetRuleLeaseKey(req): errors.New("injected rule failure")}
			},
			wantCalls: []string{"ruleDelete:ipv4|1001|100|||0|0|false|host0||false", "ruleDelete:ipv4|1000|100|||0|0|false|host0||false"},
		},
		{
			name: "neighbor",
			handler: `exports.onAction = function () { return net.neigh.transaction([
  {op:"replace", request:{interface:"host0", ip:"192.0.2.1", mac:"02:00:00:00:00:02"}},
  {op:"replace", request:{interface:"host0", ip:"192.0.2.2", mac:"02:00:00:00:00:03"}}
]); };`,
			configure: func(controller *pluginControlNetBatchAdminTest) {
				req := pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.2", State: "permanent"}
				controller.neighReplaceErrors = map[string]error{pluginControlNetNeighLeaseKey(req): errors.New("injected neighbor failure")}
			},
			wantCalls: []string{"neighDelete:host0|192.0.2.2|0", "neighDelete:host0|192.0.2.1|0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pluginID := "net_batch_" + tt.name
			writeNetworkLeasePlugin(t, dir, pluginID, tt.handler)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			db := openTestDB(t)
			runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			controller := &pluginControlNetBatchAdminTest{pluginControlNetAdminTest: &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
				"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
			}}}
			tt.configure(controller)
			runtime.netAdmin = controller
			defer runtime.Close()
			catalog := loadPluginCatalogWithState(cfg, db)
			assertPluginReconcileSuccess(t, runtime, catalog, pluginID)
			plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, pluginID)
			if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("transaction error = %v, want injected failure", err)
			}
			owned, err := store.GetPluginOwnedResources(db, pluginID)
			if err != nil || len(owned) != 0 {
				t.Fatalf("owned resources after rollback = %+v, err=%v", owned, err)
			}
			for _, want := range tt.wantCalls {
				if !containsPluginNetAdminCall(controller.calls, want) {
					t.Fatalf("net admin calls = %+v, missing rollback %s", controller.calls, want)
				}
			}
			assertNoPluginNetTransactions(t, db)
		})
	}
}

func assertNoPluginNetTransactions(t *testing.T, db store.RuleStore) {
	t.Helper()
	transactions, err := store.GetPluginNetTransactions(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(transactions) != 0 {
		t.Fatalf("pending plugin network transactions = %+v, want none", transactions)
	}
}

func TestPluginControlNetTransactionPreflightRejectsWithoutMutation(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_batch_preflight", `
exports.onAction = function () {
  return net.route.transaction([
    {op:"replace", request:{dst:"198.51.100.0/24", dev:"host0", table:100}},
    {op:"replace", request:{dst:"203.0.113.0/24", dev:"host0", table:100}}
  ]);
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_batch_preflight")
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: "other_plugin", ResourceType: pluginOwnedResourceTypeRoute,
		ResourceKey: pluginControlNetRouteLeaseKey(pluginControlNetRouteRequest{Dst: "203.0.113.0/24", Dev: "host0", Table: 100}), MetadataJSON: `{}`,
	}); err != nil {
		t.Fatal(err)
	}
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_batch_preflight")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "owned by plugin other_plugin") {
		t.Fatalf("preflight error = %v", err)
	}
	for _, call := range controller.calls {
		if strings.HasPrefix(call, "routeReplace:") || strings.HasPrefix(call, "routeDelete:") {
			t.Fatalf("preflight mutated network state: %+v", controller.calls)
		}
	}
}

func TestPluginControlNetTransactionValidationRejectsBeforeNetAdminCalls(t *testing.T) {
	tests := []struct {
		name    string
		handler string
		want    string
	}{
		{name: "empty", handler: `exports.onAction = function () { return net.route.transaction([]); };`, want: "operation count must be between 1 and 128"},
		{name: "too_many", handler: `exports.onAction = function () {
  var operations = [];
  for (var i = 0; i < 129; i++) operations.push({op:"replace", request:{dst:"198.51." + i + ".0/24", dev:"host0", table:100}});
  return net.route.transaction(operations);
};`, want: "operation count must be between 1 and 128"},
		{name: "duplicate", handler: `exports.onAction = function () { return net.route.transaction([
  {op:"replace", request:{dst:"198.51.100.0/24", dev:"host0", table:100}},
  {op:"delete", request:{dst:"198.51.100.0/24", dev:"host0", table:100}}
]); };`, want: "duplicate route slot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			pluginID := "net_batch_validate_" + tt.name
			writeNetworkLeasePlugin(t, dir, pluginID, tt.handler)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			db := openTestDB(t)
			runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			controller := &pluginControlNetAdminTest{}
			runtime.netAdmin = controller
			defer runtime.Close()
			catalog := loadPluginCatalogWithState(cfg, db)
			assertPluginReconcileSuccess(t, runtime, catalog, pluginID)
			plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, pluginID)
			if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
			if len(controller.calls) != 0 {
				t.Fatalf("validation reached net admin: %+v", controller.calls)
			}
		})
	}
}

func TestPluginControlNetTransactionPermissionDenialPrecedesNetAdminCalls(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "net_batch_denied", `{
  "api_version":"v1","id":"net_batch_denied","name":"Denied Network Batch","version":"1.0.0","kind":"control",
  "control":{
    "main":"control.js",
    "permissions":["plugin.register","net.admin"],
    "net_access":[{"interfaces":["host*"],"operations":["link.read"]}]
  }
}`)
	writePluginControlScript(t, dir, "net_batch_denied", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
exports.onAction = function () {
  return net.route.transaction([{op:"replace", request:{dst:"198.51.100.0/24", dev:"host0", table:100}}]);
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_batch_denied")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_batch_denied")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "route.write") {
		t.Fatalf("permission error = %v", err)
	}
	if len(controller.calls) != 0 {
		t.Fatalf("permission denial reached net admin: %+v", controller.calls)
	}
}

type pluginControlNetBatchAdminTest struct {
	*pluginControlNetAdminTest
	routeReplaceErrors map[string]error
	ruleReplaceErrors  map[string]error
	neighReplaceErrors map[string]error
}

func (c *pluginControlNetBatchAdminTest) RouteReplace(req pluginControlNetRouteRequest) error {
	_ = c.pluginControlNetAdminTest.RouteReplace(req)
	return c.routeReplaceErrors[pluginControlNetRouteLeaseKey(req)]
}

func (c *pluginControlNetBatchAdminTest) RuleReplace(req pluginControlNetRuleRequest) error {
	_ = c.pluginControlNetAdminTest.RuleReplace(req)
	return c.ruleReplaceErrors[pluginControlNetRuleLeaseKey(req)]
}

func (c *pluginControlNetBatchAdminTest) NeighReplace(req pluginControlNetNeighRequest) error {
	_ = c.pluginControlNetAdminTest.NeighReplace(req)
	return c.neighReplaceErrors[pluginControlNetNeighLeaseKey(req)]
}
