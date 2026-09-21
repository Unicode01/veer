package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// Unlike the generic call-recording fake, this controller models persisted
// kernel state so repeated repair passes can be checked for actual mutations.
type bundledRepairNetAdmin struct{ pluginControlNetAdminTest }

func (c *bundledRepairNetAdmin) RouteReplace(req pluginControlNetRouteRequest) error {
	if err := c.pluginControlNetAdminTest.RouteReplace(req); err != nil {
		return err
	}
	if c.routeSnapshots == nil {
		c.routeSnapshots = make(map[string][]pluginControlNetRouteState)
	}
	c.routeSnapshots[pluginControlNetRouteLeaseKey(req)] = []pluginControlNetRouteState{{
		Namespace: req.Namespace, Dst: req.Dst, Gateway: req.Gateway, Dev: req.Dev,
		DevIfIndex: c.linkInfo(req.Dev).IfIndex, Src: req.Src, Table: req.Table, Metric: req.Metric, Scope: req.Scope,
	}}
	return nil
}

func (c *bundledRepairNetAdmin) RuleReplace(req pluginControlNetRuleRequest) error {
	if err := c.pluginControlNetAdminTest.RuleReplace(req); err != nil {
		return err
	}
	if c.ruleSnapshots == nil {
		c.ruleSnapshots = make(map[string][]pluginControlNetRuleState)
	}
	c.ruleSnapshots[pluginControlNetRuleLeaseKey(req)] = []pluginControlNetRuleState{{Request: req}}
	return nil
}

func (c *bundledRepairNetAdmin) NeighReplace(req pluginControlNetNeighRequest) error {
	if err := c.pluginControlNetAdminTest.NeighReplace(req); err != nil {
		return err
	}
	if c.neighSnapshots == nil {
		c.neighSnapshots = make(map[string][]pluginControlNetNeighState)
	}
	c.neighSnapshots[pluginControlNetNeighLeaseKey(req)] = []pluginControlNetNeighState{{Request: req, LinkIfIndex: c.linkInfo(req.Interface).IfIndex}}
	return nil
}

func newBundledWANRepairFixture(t testing.TB) (*gojaPluginControlRuntime, *bundledRepairNetAdmin) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "wan_core")
	copyDirForTest(t, filepath.Join("..", "..", "plugins", "wan_core"), root)
	plugin, err := loadPluginFromDir(root, "wan_core")
	if err != nil {
		t.Fatal(err)
	}
	rt := newPluginControlRuntime(openTestDB(t), pluginsEnabledTestConfig(&Config{PluginsDir: filepath.Dir(root)}), nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	controller := &bundledRepairNetAdmin{}
	rt.netAdmin = controller
	payload := json.RawMessage(`{
  "key":"default","driver":"pppoe","state":"up","usable":true,
  "local_interface":"veerlocal0","pipeline_interface":"veerpipe0",
  "ipv4":"192.0.2.2","ipv4_peer":"192.0.2.1","ipv6":"2001:db8::2",
  "ipv6_link_local":"fe80::2","ipv6_gateway":"fe80::1","peer_mac":"02:00:00:00:00:01",
  "pd_prefix":"2001:db8:100::/56","install_default_route_v6":true,
  "interface_preparation":{"local_gso":{"max_size":1492,"max_segs":1},
    "local_offloads":{"sg":false,"tso":false,"gso":false},"pipeline_offloads":{"gro":false,"lro":false}}
}`)
	if err := rt.ApplyPluginAction(plugin, PluginAction{ID: "apply_session", RuntimeUpdate: "runtime_apply"}, payload); err != nil {
		t.Fatal(err)
	}
	controller.calls = nil
	return rt, controller
}

func bundledRepairWriteCount(calls []string) int {
	count := 0
	for _, call := range calls {
		for _, prefix := range []string{"setOffloads:", "setGSO:", "addrReplace:", "routeReplace:", "ruleReplace:", "neighReplace:"} {
			if strings.HasPrefix(call, prefix) {
				count++
			}
		}
	}
	return count
}

func TestBundledWANRepairSkipsStableWritesAndRepairsDrift(t *testing.T) {
	rt, controller := newBundledWANRepairFixture(t)
	const untouched = "2000-01-01 00:00:00"
	if _, err := rt.db.Exec(`UPDATE plugin_owned_resources SET updated_at = ? WHERE plugin_id = 'wan_core'`, untouched); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	}
	if writes := bundledRepairWriteCount(controller.calls); writes != 0 {
		t.Fatalf("stable repair made %d network writes: %v", writes, controller.calls)
	}
	var changedLeases int
	if err := rt.db.QueryRow(`SELECT COUNT(*) FROM plugin_owned_resources WHERE plugin_id = 'wan_core' AND updated_at <> ?`, untouched).Scan(&changedLeases); err != nil || changedLeases != 0 {
		t.Fatalf("stable repair rewrote %d ownership leases: %v", changedLeases, err)
	}
	controller.calls = nil
	controller.routeSnapshots = nil
	controller.ruleSnapshots = nil
	controller.neighSnapshots = nil
	info := controller.links["veerlocal0"]
	info.Addresses, info.GSOMaxSize = nil, 65536
	controller.links["veerlocal0"] = info
	controller.offloads["veerpipe0"]["gro"] = true
	firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	for _, prefix := range []string{"setOffloads:", "setGSO:", "addrReplace:", "routeReplace:", "ruleReplace:", "neighReplace:"} {
		if countStringsWithPrefix(controller.calls, prefix) == 0 {
			t.Fatalf("repair failed to restore drift in %s: %v", prefix, controller.calls)
		}
	}
	controller.calls = nil
	firePluginTimerForTest(t, rt, "wan_core", "wan_repair")
	if writes := bundledRepairWriteCount(controller.calls); writes != 0 {
		t.Fatalf("recovered repair made %d writes", writes)
	}
}

func BenchmarkBundledWANStableRepair(b *testing.B) {
	rt, controller := newBundledWANRepairFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	writes := 0
	for i := 0; i < b.N; i++ {
		controller.calls = nil
		firePluginTimerForTest(b, rt, "wan_core", "wan_repair")
		writes += bundledRepairWriteCount(controller.calls)
	}
	b.ReportMetric(float64(writes)/float64(b.N), "writes/op")
}
