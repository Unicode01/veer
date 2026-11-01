package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

type auditRollbackFailAdmin struct{ *pluginControlNetAdminTest }

func (a *auditRollbackFailAdmin) RouteReplace(r pluginControlNetRouteRequest) error {
	return errors.New("injected apply failure")
}
func (a *auditRollbackFailAdmin) RuleReplace(r pluginControlNetRuleRequest) error {
	return errors.New("injected apply failure")
}
func (a *auditRollbackFailAdmin) NeighReplace(r pluginControlNetNeighRequest) error {
	return errors.New("injected apply failure")
}
func (a *auditRollbackFailAdmin) RouteDelete(r pluginControlNetRouteRequest) error {
	return errors.New("injected rollback failure")
}
func (a *auditRollbackFailAdmin) RuleDelete(r pluginControlNetRuleRequest) error {
	return errors.New("injected rollback failure")
}
func (a *auditRollbackFailAdmin) NeighDelete(r pluginControlNetNeighRequest) error {
	return errors.New("injected rollback failure")
}

func TestPluginNetFailedRollbackPreservesRecoveryState(t *testing.T) {
	for _, tc := range []struct{ kind, body string }{
		{"route", `net.route.transaction([{op:"replace",request:{dst:"198.51.100.0/24",dev:"host0",table:100}}])`},
		{"rule", `net.rule.transaction([{op:"replace",request:{family:"ipv4",priority:1000,table:100,iif:"host0"}}])`},
		{"neighbor", `net.neigh.transaction([{op:"replace",request:{interface:"host0",ip:"192.0.2.1",mac:"02:00:00:00:00:02"}}])`},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := t.TempDir()
			id := "audit_" + tc.kind
			writeNetworkLeasePlugin(t, dir, id, `exports.onAction=function(){return `+tc.body+`;};`)
			cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
			db := openTestDB(t)
			rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
			rt.netAdmin = &auditRollbackFailAdmin{&pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true, ARP: true}}}}
			defer rt.Close()
			catalog := loadPluginCatalogWithState(cfg, db)
			assertPluginReconcileSuccess(t, rt, catalog, id)
			p := transactionPluginWithRuntimeSurfaceForTest(t, rt, catalog, id)
			_, err := rt.QueryPluginAction(p, p.Actions[0], json.RawMessage(`{}`))
			if err == nil || !strings.Contains(err.Error(), "injected rollback failure") {
				t.Fatalf("wrong injection result: %v", err)
			}
			journals, err := store.GetPluginNetTransactions(db)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := store.GetPluginOwnedResources(db, id)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("failed rollback left journals=%d ownership=%d", len(journals), len(owned))
			if len(journals) == 0 {
				t.Error("recovery journal was deleted despite failed rollback")
			}
			if len(owned) == 0 {
				t.Error("ownership was released despite failed kernel cleanup")
			}
		})
	}
}

type pluginNetSelectiveRecoveryAdmin struct {
	*pluginControlNetAdminTest
	failed string
}

func (a *pluginNetSelectiveRecoveryAdmin) RouteDelete(req pluginControlNetRouteRequest) error {
	if req.Dst == a.failed {
		return fmt.Errorf("injected failure for %s", req.Dst)
	}
	return a.pluginControlNetAdminTest.RouteDelete(req)
}

func TestPluginNetRecoveryPersistsIndependentProgress(t *testing.T) {
	db := openTestDB(t)
	bad := auditJournalEntry("route")
	good := auditJournalEntry("route")
	goodReq := *good.RouteRequest
	goodReq.Dst = "203.0.113.0/24"
	good.RouteRequest = &goodReq
	good.ResourceKey = pluginControlNetRouteLeaseKey(goodReq)
	record := addPendingPluginNetTransactionForTest(t, db, "partial", "route", 2, []pluginNetTransactionEntry{bad, good})
	for _, entry := range []pluginNetTransactionEntry{bad, good} {
		if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "partial", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: `{"version":1}`}); err != nil {
			t.Fatal(err)
		}
	}
	admin := &pluginNetSelectiveRecoveryAdmin{pluginControlNetAdminTest: &pluginControlNetAdminTest{}, failed: bad.RouteRequest.Dst}
	if err := recoverPendingPluginNetTransactions(db, admin); err == nil {
		t.Fatal("missing injected error")
	}
	pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID)
	if err != nil || pending == nil {
		t.Fatalf("journal=%+v %v", pending, err)
	}
	state, err := decodePluginNetTransactionState(pending)
	if err != nil {
		t.Fatal(err)
	}
	if state.Entries[0].Resolved || !state.Entries[1].Resolved {
		t.Fatalf("incorrect durable progress: %+v", state.Entries)
	}
	if lease, err := store.PluginOwnedResourceOrNil(db, bad.ResourceType, bad.ResourceKey); err != nil || lease == nil {
		t.Fatalf("failed slot lost ownership: %+v %v", lease, err)
	}
	if err := checkPendingPluginNetResources(db, "partial", []pluginOwnedResourceRef{{good.ResourceType, good.ResourceKey}}); err != nil {
		t.Fatalf("healthy slot blocked: %v", err)
	}
	if err := checkPendingPluginNetResources(db, "partial", []pluginOwnedResourceRef{{bad.ResourceType, bad.ResourceKey}}); err == nil {
		t.Fatal("failed slot not fenced")
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "healthy_new_owner", ResourceType: good.ResourceType, ResourceKey: good.ResourceKey, MetadataJSON: `{"version":1}`}); err != nil {
		t.Fatal(err)
	}
	admin.calls = nil
	admin.failed = ""
	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatal(err)
	}
	for _, call := range admin.calls {
		if strings.Contains(call, goodReq.Dst) {
			t.Fatalf("replayed resolved healthy slot: %v", admin.calls)
		}
	}
	lease, err := store.PluginOwnedResourceOrNil(db, good.ResourceType, good.ResourceKey)
	if err != nil || lease == nil || lease.PluginID != "healthy_new_owner" {
		t.Fatalf("healthy replacement changed: %+v %v", lease, err)
	}
	assertNoPluginNetTransactions(t, db)
}

func TestPluginNetRecoveryInterfaceGeneration(t *testing.T) {
	original := pluginControlNetLinkInfo{Name: "host0", IfIndex: 50, Kind: "dummy", MAC: "02:00:00:00:00:01", MTU: 1500, Up: true}
	for _, kind := range []string{"route", "rule", "neighbor"} {
		for _, scenario := range []string{"down", "mtu_address_change", "removed", "recreated", "kind_reused_index", "mac_reused_index"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				db := openTestDB(t)
				entry := auditJournalEntry(kind)
				entry.LinkIdentities = []pluginNetTransactionLinkIdentity{{Name: original.Name, IfIndex: original.IfIndex, Kind: original.Kind, MAC: original.MAC}}
				addPendingPluginNetTransactionForTest(t, db, "generation", kind, 1, []pluginNetTransactionEntry{entry})
				current := original
				wantMutation := false
				switch scenario {
				case "down":
					current.Up = false
					wantMutation = true
				case "mtu_address_change":
					current.MTU = 1300
					current.Addresses = []string{"198.51.100.1/24"}
					wantMutation = true
				case "recreated":
					current.IfIndex++
				case "kind_reused_index":
					current.Kind = "veth"
				case "mac_reused_index":
					current.MAC = "02:00:00:00:00:02"
				}
				admin := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"host0": current}}
				if scenario == "removed" {
					delete(admin.links, "host0")
				}
				if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
					t.Fatal(err)
				}
				if (len(admin.calls) > 0) != wantMutation {
					t.Fatalf("unsafe or missing recovery calls: %v", admin.calls)
				}
				assertNoPluginNetTransactions(t, db)
			})
		}
	}
}

func TestPluginNetRecoveryDoesNotReleaseNewGenerationLease(t *testing.T) {
	db := openTestDB(t)
	entry := auditJournalEntry("route")
	entry.LinkIdentities = []pluginNetTransactionLinkIdentity{{Name: "host0", IfIndex: 50}}
	addPendingPluginNetTransactionForTest(t, db, "same_plugin", "route", 1, []pluginNetTransactionEntry{entry})
	metadata := fmt.Sprintf(`{"version":1,"boot_id":%q,"dev_ifindex":51}`, pluginOwnershipBootID)
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "same_plugin", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: metadata}); err != nil {
		t.Fatal(err)
	}
	admin := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"host0": {Name: "host0", IfIndex: 51}}}
	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatal(err)
	}
	lease, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
	if err != nil || lease == nil || lease.MetadataJSON != metadata || len(admin.calls) > 0 {
		t.Fatalf("new generation affected: %+v %v calls=%v", lease, err, admin.calls)
	}
}

func TestPluginNetResourceLocksIsolateSlotsAndReleaseEntries(t *testing.T) {
	db := &sql.DB{}
	a := []pluginOwnedResourceRef{{pluginOwnedResourceTypeRoute, "a"}, {pluginOwnedResourceTypeRoute, "a"}}
	b := []pluginOwnedResourceRef{{pluginOwnedResourceTypeRoute, "b"}}
	releaseA := lockPluginNetResources(db, a)
	acquiredA := make(chan struct{})
	doneA, doneB := make(chan struct{}), make(chan struct{})
	go func() {
		release := lockPluginNetResources(db, a)
		close(acquiredA)
		release()
		close(doneA)
	}()
	go func() {
		release := lockPluginNetResources(db, b)
		release()
		close(doneB)
	}()
	select {
	case <-doneB:
	case <-time.After(time.Second):
		t.Fatal("independent slot blocked")
	}
	select {
	case <-acquiredA:
		t.Fatal("overlapping slot was not serialized")
	default:
	}
	releaseA()
	select {
	case <-doneA:
	case <-time.After(time.Second):
		t.Fatal("slot lock did not release")
	}
	// Both goroutines must finish the entire release, including reference
	// bookkeeping. Reacquiring the slot only waits for its mutex unlock.
	pluginNetResourceLocks.Lock()
	defer pluginNetResourceLocks.Unlock()
	for key := range pluginNetResourceLocks.items {
		if key.db == db {
			t.Fatalf("lock entry leaked: %+v", key)
		}
	}
}

func auditJournalEntry(kind string) pluginNetTransactionEntry {
	switch kind {
	case "route":
		r := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Dev: "host0", Table: 100}
		return pluginNetTransactionEntry{Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: pluginControlNetRouteLeaseKey(r), RouteRequest: &r}
	case "rule":
		r := pluginControlNetRuleRequest{Family: "ipv4", Priority: 1000, Table: 100, IIF: "host0"}
		return pluginNetTransactionEntry{Present: true, ResourceType: pluginOwnedResourceTypeRule, ResourceKey: pluginControlNetRuleLeaseKey(r), RuleRequest: &r}
	default:
		r := pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:00:02", State: "permanent"}
		return pluginNetTransactionEntry{Present: true, ResourceType: pluginOwnedResourceTypeNeighbor, ResourceKey: pluginControlNetNeighLeaseKey(r), NeighRequest: &r}
	}
}
func TestPluginNetRecoveryPreservesNewOwner(t *testing.T) {
	for _, kind := range []string{"route", "rule", "neighbor"} {
		t.Run(kind, func(t *testing.T) {
			db := openTestDB(t)
			entry := auditJournalEntry(kind)
			addPendingPluginNetTransactionForTest(t, db, "old_plugin", kind, 1, []pluginNetTransactionEntry{entry})
			if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "new_plugin", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: `{"version":1}`}); err != nil {
				t.Fatal(err)
			}
			admin := &pluginControlNetAdminTest{}
			err := recoverPendingPluginNetTransactions(db, admin)
			if err != nil {
				t.Fatalf("discard superseded recovery: %v", err)
			}
			lease, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
			if err != nil || lease == nil || lease.PluginID != "new_plugin" {
				t.Fatalf("new owner changed: %+v, %v", lease, err)
			}
			if len(admin.calls) != 0 {
				t.Errorf("mutated foreign owner's kernel state before detecting conflict: %v", admin.calls)
			}
		})
	}
}
func TestPluginNetRecoveryUnwindsOverlappingJournals(t *testing.T) {
	db := openTestDB(t)
	entry := auditJournalEntry("route")
	id := "audit_overlap"
	addPendingPluginNetTransactionForTest(t, db, id, "route", 1, []pluginNetTransactionEntry{entry})
	entry.LeaseBefore = pluginNetLeaseSnapshot{Exists: true, PluginID: id, MetadataJSON: `{"version":1,"marker":"intermediate"}`}
	raw := mustPluginNetTransactionStateJSONForTest(t, []pluginNetTransactionEntry{entry})
	if err := store.AddPluginNetTransaction(db, store.PluginNetTransaction{TransactionID: "second-journal", PluginID: id, Kind: "route", StateJSON: raw, StartedCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: id, ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: `{"version":1,"marker":"latest"}`}); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingPluginNetTransactions(db, &pluginControlNetAdminTest{}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
	if err != nil {
		t.Fatal(err)
	}
	if lease != nil {
		t.Errorf("recovery resurrected intermediate lease instead of pre-transaction absence: %s", lease.MetadataJSON)
	}
}
func TestPluginNetPurgeRequiresRecovery(t *testing.T) {
	db := openTestDB(t)
	id := "audit_purge"
	addPendingPluginNetTransactionForTest(t, db, id, "route", 1, []pluginNetTransactionEntry{auditJournalEntry("route")})
	if err := store.DeletePluginData(db, id); err == nil {
		t.Fatal("purge discarded unresolved recovery")
	}
	rows, err := store.GetPluginNetTransactions(db)
	if err != nil || len(rows) != 1 {
		t.Fatalf("pending journals = %+v, %v", rows, err)
	}
	if err := recoverPendingPluginNetTransactions(db, &pluginControlNetAdminTest{}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeletePluginData(db, id); err != nil {
		t.Fatal(err)
	}
	assertNoPluginNetTransactions(t, db)
}

func TestPluginNetRecoveryWaitsForUnstartedOperation(t *testing.T) {
	db := openTestDB(t)
	entry := auditJournalEntry("route")
	record := addPendingPluginNetTransactionForTest(t, db, "active", "route", 0, []pluginNetTransactionEntry{entry})
	unlock := lockPluginNetResources(db, []pluginOwnedResourceRef{{entry.ResourceType, entry.ResourceKey}})
	done := make(chan error, 1)
	go func() { done <- recoverPendingPluginNetTransactions(db, nil) }()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("recovery bypassed active operation: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	current, err := store.PluginNetTransactionOrNil(db, record.TransactionID)
	unlock()
	if err != nil || current == nil {
		t.Fatalf("active journal was removed: %+v %v", current, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not resume")
	}
	assertNoPluginNetTransactions(t, db)
}

func TestPluginNetRecoveryMalformedNewerJournalIsolatesPluginKind(t *testing.T) {
	db := openTestDB(t)
	entry := auditJournalEntry("route")
	older := addPendingPluginNetTransactionForTest(t, db, "bad", "route", 1, []pluginNetTransactionEntry{entry})
	newer := store.PluginNetTransaction{TransactionID: "corrupt", PluginID: "bad", Kind: "route", StartedCount: 1, StateJSON: "invalid"}
	if err := store.AddPluginNetTransaction(db, newer); err != nil {
		t.Fatal(err)
	}
	other := addPendingPluginNetTransactionForTest(t, db, "good", "neighbor", 1, []pluginNetTransactionEntry{auditJournalEntry("neighbor")})
	admin := &pluginControlNetAdminTest{}
	if err := recoverPendingPluginNetTransactions(db, admin); err == nil {
		t.Fatal("corruption hidden")
	}
	for _, id := range []string{older.TransactionID, newer.TransactionID} {
		if record, err := store.PluginNetTransactionOrNil(db, id); err != nil || record == nil {
			t.Fatalf("unsafe older recovery: %s %v", id, err)
		}
	}
	if record, err := store.PluginNetTransactionOrNil(db, other.TransactionID); err != nil || record != nil {
		t.Fatalf("unrelated recovery blocked: %+v %v", record, err)
	}
	for _, call := range admin.calls {
		if strings.HasPrefix(call, "route") {
			t.Fatalf("corrupt journal did not fence older route: %v", admin.calls)
		}
	}
}

func TestPluginNetFailedNewerRecoveryFencesOlderSnapshot(t *testing.T) {
	db := openTestDB(t)
	bad, good := auditJournalEntry("route"), auditJournalEntry("neighbor")
	old := addPendingPluginNetTransactionForTest(t, db, "same", "route", 1, []pluginNetTransactionEntry{bad})
	addPendingPluginNetTransactionForTest(t, db, "newer", "route", 1, []pluginNetTransactionEntry{bad})
	addPendingPluginNetTransactionForTest(t, db, "other", "neighbor", 1, []pluginNetTransactionEntry{good})
	admin := &pluginNetSelectiveRecoveryAdmin{pluginControlNetAdminTest: &pluginControlNetAdminTest{}, failed: bad.RouteRequest.Dst}
	if err := recoverPendingPluginNetTransactions(db, admin); err == nil {
		t.Fatal("injected error hidden")
	}
	if record, err := store.PluginNetTransactionOrNil(db, old.TransactionID); err != nil || record == nil {
		t.Fatal("older snapshot bypassed newer failure")
	}
	for _, call := range admin.calls {
		if strings.HasPrefix(call, "routeRestore") {
			t.Fatalf("restore after failed delete: %v", admin.calls)
		}
	}
	if err := checkPendingPluginNetResources(db, "other", []pluginOwnedResourceRef{{good.ResourceType, good.ResourceKey}}); err != nil {
		t.Fatalf("unrelated slot fenced: %v", err)
	}
	admin.failed = ""
	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatal(err)
	}
	assertNoPluginNetTransactions(t, db)
}

func TestPluginNetCleanupFailureRetainsDependentInterface(t *testing.T) {
	db := openTestDB(t)
	admin := &pluginNetSelectiveRecoveryAdmin{pluginControlNetAdminTest: &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"host0": {Name: "host0", IfIndex: 50, Kind: "dummy"}}}, failed: "198.51.100.0/24"}
	req := *auditJournalEntry("route").RouteRequest
	req.Dev = "host0"
	routeJSON, _ := json.Marshal(pluginOwnedRouteMutation{Version: 1, Current: req, CurrentPresent: true, DevIfIndex: 50})
	for _, item := range []store.PluginOwnedResource{
		{PluginID: "cleanup", ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: pluginControlNetRouteLeaseKey(req), MetadataJSON: string(routeJSON)},
		{PluginID: "cleanup", ResourceType: pluginOwnedResourceTypeLink, ResourceKey: "host0", MetadataJSON: `{"name":"host0","ifindex":50,"kind":"dummy"}`},
		{PluginID: "cleanup", ResourceType: pluginOwnedResourceTypeLink, ResourceKey: "already_missing", MetadataJSON: `{"name":"already_missing","ifindex":51,"kind":"dummy"}`},
	} {
		if err := store.AddPluginOwnedResource(db, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := cleanupPluginOwnedResources(db, admin, "cleanup"); err == nil {
		t.Fatal("injected error hidden")
	}
	if _, present := admin.links["host0"]; !present {
		t.Fatal("failed route's interface was removed")
	}
	if item, err := store.PluginOwnedResourceOrNil(db, pluginOwnedResourceTypeLink, "already_missing"); err != nil || item != nil {
		t.Fatal("unrelated cleanup blocked")
	}
	admin.failed = ""
	if err := cleanupPluginOwnedResources(db, admin, "cleanup"); err != nil {
		t.Fatal(err)
	}
	if items, err := store.GetPluginOwnedResources(db, "cleanup"); err != nil || len(items) != 0 {
		t.Fatalf("leaked ownership: %+v %v", items, err)
	}
}

func TestPluginNetLegacyRecoveryRequiresRecordedInterfaceIdentity(t *testing.T) {
	for _, scenario := range []string{"unchanged", "recreated", "unrecorded"} {
		t.Run(scenario, func(t *testing.T) {
			db := openTestDB(t)
			entry := auditJournalEntry("route")
			state, _ := json.Marshal(pluginNetTransactionState{Version: 1, Entries: []pluginNetTransactionEntry{entry}})
			if err := store.AddPluginNetTransaction(db, store.PluginNetTransaction{TransactionID: "legacy", PluginID: "legacy", Kind: "route", StateJSON: string(state), StartedCount: 1}); err != nil {
				t.Fatal(err)
			}
			if scenario != "unrecorded" {
				metadata := fmt.Sprintf(`{"version":1,"boot_id":%q,"dev_ifindex":50}`, pluginOwnershipBootID)
				if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "legacy", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: metadata}); err != nil {
					t.Fatal(err)
				}
			}
			index := 50
			if scenario == "recreated" {
				index = 51
			}
			admin := &pluginControlNetAdminTest{links: map[string]pluginControlNetLinkInfo{"host0": {Name: "host0", IfIndex: index}}}
			err := recoverPendingPluginNetTransactions(db, admin)
			if scenario == "unrecorded" {
				if err == nil || len(admin.calls) > 0 {
					t.Fatalf("unrecorded legacy recovery guessed today's interface: %v %v", err, admin.calls)
				}
				if pending, _ := store.GetPluginNetTransactions(db); len(pending) != 1 {
					t.Fatal("unsafe journal discarded")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if (len(admin.calls) > 0) != (scenario == "unchanged") {
					t.Fatalf("unexpected legacy mutations: %v", admin.calls)
				}
				assertNoPluginNetTransactions(t, db)
			}
		})
	}
}

func TestPluginNetRecoveryPreservesSamePluginNewerLease(t *testing.T) {
	db := openTestDB(t)
	entry := auditJournalEntry("route")
	addPendingPluginNetTransactionForTest(t, db, "same", "route", 1, []pluginNetTransactionEntry{entry})
	newer := *entry.RouteRequest
	newer.Dev = "host1"
	raw, _ := json.Marshal(pluginOwnedRouteMutation{Version: 1, Current: newer, CurrentPresent: true})
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{PluginID: "same", ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: string(raw)}); err != nil {
		t.Fatal(err)
	}
	admin := &pluginControlNetAdminTest{}
	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatal(err)
	}
	current, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
	if err != nil || current == nil || current.MetadataJSON != string(raw) || len(admin.calls) > 0 {
		t.Fatalf("newer same-plugin lease changed: %+v %v %v", current, err, admin.calls)
	}
	assertNoPluginNetTransactions(t, db)
}
