package app

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

// countPluginNetStoreWrites makes the database count the rows written to the
// recovery journal and to the lease table.
func countPluginNetStoreWrites(t *testing.T, db *sql.DB) func() (journal, leases int) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE test_net_writes (journal INTEGER NOT NULL, leases INTEGER NOT NULL)`,
		`INSERT INTO test_net_writes VALUES (0, 0)`,
		`CREATE TRIGGER test_journal_insert AFTER INSERT ON plugin_net_transactions BEGIN UPDATE test_net_writes SET journal = journal + 1; END`,
		`CREATE TRIGGER test_journal_update AFTER UPDATE ON plugin_net_transactions BEGIN UPDATE test_net_writes SET journal = journal + 1; END`,
		`CREATE TRIGGER test_journal_delete AFTER DELETE ON plugin_net_transactions BEGIN UPDATE test_net_writes SET journal = journal + 1; END`,
		`CREATE TRIGGER test_lease_insert AFTER INSERT ON plugin_owned_resources BEGIN UPDATE test_net_writes SET leases = leases + 1; END`,
		`CREATE TRIGGER test_lease_update AFTER UPDATE ON plugin_owned_resources BEGIN UPDATE test_net_writes SET leases = leases + 1; END`,
		`CREATE TRIGGER test_lease_delete AFTER DELETE ON plugin_owned_resources BEGIN UPDATE test_net_writes SET leases = leases + 1; END`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	return func() (int, int) {
		t.Helper()
		var journal, leases int
		if err := db.QueryRow(`SELECT journal, leases FROM test_net_writes`).Scan(&journal, &leases); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE test_net_writes SET journal = 0, leases = 0`); err != nil {
			t.Fatal(err)
		}
		return journal, leases
	}
}

func pluginNetMutationCalls(calls []string) []string {
	var out []string
	for _, call := range calls {
		if strings.Contains(call, "Replace:") || strings.Contains(call, "Delete:") {
			out = append(out, call)
		}
	}
	return out
}

// A repair pass re-asserts routes, rules and neighbours every tick. Once
// they hold, the pass must not touch the kernel or the store: no journal
// row, no lease write. A slot that drifted still goes through the journal.
func TestPluginNetReplaceThatChangesNothingWritesNothing(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_noop", `
exports.onAction = function () {
  net.route.replace({dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100});
  net.rule.replace({family:"ipv4", priority:1000, table:100, src:"192.0.2.0/24", iif:"host0"});
  net.neigh.replace({interface:"host0", ip:"192.0.2.1", mac:"02:00:00:00:00:02", state:"permanent"});
  net.route.transaction([
    {op:"replace", request:{dst:"198.51.100.0/24", gateway:"192.0.2.1", dev:"host0", table:100}},
    {op:"replace", request:{dst:"203.0.113.0/24", gateway:"192.0.2.1", dev:"host0", table:100}}
  ]);
  return {};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	writes := countPluginNetStoreWrites(t, db)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &bundledRepairNetAdmin{pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{
		"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
	}}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_noop")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_noop")
	run := func() []string {
		t.Helper()
		before := len(controller.calls)
		if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		return pluginNetMutationCalls(controller.calls[before:])
	}

	if mutations := run(); len(mutations) != 5 {
		t.Fatalf("first pass mutations = %v, want the 5 entries created", mutations)
	}
	if journal, leases := writes(); journal == 0 || leases == 0 {
		t.Fatalf("first pass wrote journal=%d leases=%d; want both", journal, leases)
	}
	leases, err := store.GetPluginOwnedResources(db, "net_noop")
	if err != nil || len(leases) != 5 {
		t.Fatalf("leases = %+v, err=%v, want 5", leases, err)
	}

	for pass := 0; pass < 2; pass++ {
		if mutations := run(); len(mutations) != 0 {
			t.Fatalf("pass %d mutated the kernel: %v", pass, mutations)
		}
		if journal, leaseWrites := writes(); journal != 0 || leaseWrites != 0 {
			t.Fatalf("pass %d wrote journal=%d leases=%d; want nothing", pass, journal, leaseWrites)
		}
	}
	after, err := store.GetPluginOwnedResources(db, "net_noop")
	if err != nil || !reflect.DeepEqual(after, leases) {
		t.Fatalf("leases changed on a pass that changed nothing:\n%+v\n%+v", after, leases)
	}

	// The default route drifted: that slot goes through the journal again.
	key := pluginControlNetRouteLeaseKey(pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Gateway: "192.0.2.1", Dev: "host0", Table: 100})
	if len(controller.routeSnapshots[key]) != 1 {
		t.Fatalf("route snapshot for %s missing: %+v", key, controller.routeSnapshots)
	}
	controller.routeSnapshots[key][0].Gateway = "192.0.2.9"
	if mutations := run(); len(mutations) != 1 || !strings.HasPrefix(mutations[0], "routeReplace:0.0.0.0/0:host0:192.0.2.1") {
		t.Fatalf("drifted pass mutations = %v, want the default route replaced", mutations)
	}
	if journal, _ := writes(); journal == 0 {
		t.Fatalf("a drifted route was replaced without a recovery journal")
	}
	assertNoPluginNetTransactions(t, db)
}

// The kernel snapshot of a neighbour carries neither the namespace nor the
// ifindex guard the transaction sets on its request; neither may make an
// unchanged neighbour look different.
func TestPluginNeighMatchIgnoresTheTransactionGuard(t *testing.T) {
	state := pluginControlNetNeighState{
		Request:     pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:00:02", State: "permanent"},
		LinkIfIndex: 50,
	}
	req := pluginControlNetNeighRequest{expectedIfIndex: 50, Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:00:02", State: "permanent"}
	if !pluginControlNeighRequestMatchesState(req, state) {
		t.Fatalf("guarded request %+v does not match its snapshot %+v", req, state)
	}
	req.MAC = "02:00:00:00:00:03"
	if pluginControlNeighRequestMatchesState(req, state) {
		t.Fatalf("a neighbour with another MAC matched")
	}
}

// A slot that already held what the plugin asks before the plugin ever
// claimed it gets a lease that the release drops at once. Re-asserting it
// writes nothing either.
func TestPluginNetReplaceOfAnEntryThatAlreadyExistedWritesNothing(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "net_noop_existing", `
exports.onAction = function () {
  net.route.replace({dst:"0.0.0.0/0", gateway:"192.0.2.1", dev:"host0", table:100});
  return {};
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	writes := countPluginNetStoreWrites(t, db)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	request := pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Gateway: "192.0.2.1", Dev: "host0", Table: 100}
	controller := &bundledRepairNetAdmin{pluginControlNetAdminTest{
		links: map[string]pluginControlNetLinkInfo{
			"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true},
		},
		routeSnapshots: map[string][]pluginControlNetRouteState{
			pluginControlNetRouteLeaseKey(request): {{Dst: "0.0.0.0/0", Gateway: "192.0.2.1", Dev: "host0", DevIfIndex: 50, Table: 100}},
		},
	}}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "net_noop_existing")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "net_noop_existing")
	for pass := 0; pass < 2; pass++ {
		before := len(controller.calls)
		if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
		if mutations := pluginNetMutationCalls(controller.calls[before:]); len(mutations) != 0 {
			t.Fatalf("pass %d mutated the kernel: %v", pass, mutations)
		}
		if journal, leases := writes(); journal != 0 || leases != 0 {
			t.Fatalf("pass %d wrote journal=%d leases=%d; want nothing", pass, journal, leases)
		}
	}
	if leases, err := store.GetPluginOwnedResources(db, "net_noop_existing"); err != nil || len(leases) != 0 {
		t.Fatalf("leases = %+v, err=%v; want none for a route the plugin did not change", leases, err)
	}
}
