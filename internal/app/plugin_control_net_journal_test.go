package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestRecoverPendingPluginNetTransactionsRestoresKernelAndLease(t *testing.T) {
	tests := []struct {
		kind        string
		entry       pluginNetTransactionEntry
		wantDelete  string
		wantRestore string
	}{
		{
			kind: pluginNetTransactionKindRoute,
			entry: func() pluginNetTransactionEntry {
				req := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Gateway: "192.0.2.2", Dev: "host0", Table: 100}
				return pluginNetTransactionEntry{
					Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: pluginControlNetRouteLeaseKey(req),
					RouteRequest:  &req,
					RouteOriginal: []pluginControlNetRouteState{{Dst: "198.51.100.0/24", Gateway: "192.0.2.1", Dev: "host0", Table: 100}},
				}
			}(),
			wantDelete:  "routeDelete:198.51.100.0/24:host0:192.0.2.2:100:0",
			wantRestore: "routeRestore:1",
		},
		{
			kind: pluginNetTransactionKindRule,
			entry: func() pluginNetTransactionEntry {
				req := pluginControlNetRuleRequest{Family: "ipv4", Priority: 1000, Table: 100, Src: "192.0.2.0/24", IIF: "host0"}
				return pluginNetTransactionEntry{
					Present: true, ResourceType: pluginOwnedResourceTypeRule, ResourceKey: pluginControlNetRuleLeaseKey(req),
					RuleRequest: &req, RuleOriginal: []pluginControlNetRuleState{{Request: req}},
				}
			}(),
			wantDelete:  "ruleDelete:ipv4|1000|100|192.0.2.0/24||0|0|false|host0||false",
			wantRestore: "ruleRestore:1",
		},
		{
			kind: pluginNetTransactionKindNeighbor,
			entry: func() pluginNetTransactionEntry {
				req := pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:00:02", State: "permanent"}
				return pluginNetTransactionEntry{
					Present: true, ResourceType: pluginOwnedResourceTypeNeighbor, ResourceKey: pluginControlNetNeighLeaseKey(req),
					NeighRequest:  &req,
					NeighOriginal: []pluginControlNetNeighState{{Request: pluginControlNetNeighRequest{Interface: "host0", IP: "192.0.2.1", MAC: "02:00:00:00:00:01", State: "permanent"}}},
				}
			}(),
			wantDelete:  "neighDelete:host0|192.0.2.1|0",
			wantRestore: "neighRestore:1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			db := openTestDB(t)
			const pluginID = "crash_recovery"
			const oldMetadata = `{"version":1,"state":"old"}`
			tt.entry.LeaseBefore = pluginNetLeaseSnapshot{Exists: true, PluginID: pluginID, MetadataJSON: oldMetadata}
			if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
				PluginID: pluginID, ResourceType: tt.entry.ResourceType, ResourceKey: tt.entry.ResourceKey,
				MetadataJSON: `{"version":1,"state":"new"}`,
			}); err != nil {
				t.Fatal(err)
			}
			record := addPendingPluginNetTransactionForTest(t, db, pluginID, tt.kind, 1, []pluginNetTransactionEntry{tt.entry})
			admin := &pluginControlNetAdminTest{}
			if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{tt.wantDelete, tt.wantRestore} {
				if !containsPluginNetAdminCall(admin.calls, want) {
					t.Fatalf("recovery calls = %+v, missing %q", admin.calls, want)
				}
			}
			lease, err := store.PluginOwnedResourceOrNil(db, tt.entry.ResourceType, tt.entry.ResourceKey)
			if err != nil || lease == nil || lease.MetadataJSON != oldMetadata {
				t.Fatalf("restored lease = %+v, err=%v", lease, err)
			}
			if pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID); err != nil || pending != nil {
				t.Fatalf("pending journal = %+v, err=%v, want none", pending, err)
			}
		})
	}
}

func TestRecoverPendingPluginMultipathRouteTransaction(t *testing.T) {
	db := openTestDB(t)
	const pluginID = "multipath_crash_recovery"
	req := pluginControlNetRouteRequest{
		Dst: "198.51.100.0/24", Table: 100, Metric: 10,
		Nexthops: []pluginControlNetRouteNexthop{
			{Dev: "host0", Gateway: "192.0.2.2", Weight: 1},
			{Dev: "host1", Gateway: "192.0.3.2", Weight: 2},
		},
	}
	original := pluginControlNetRouteState{
		Dst: req.Dst, Table: req.Table, Metric: req.Metric,
		Nexthops: []pluginControlNetRouteNexthopState{
			{Dev: "host0", DevIfIndex: 50, Gateway: "192.0.2.1", Weight: 1},
			{Dev: "host1", DevIfIndex: 51, Gateway: "192.0.3.1", Weight: 1},
		},
	}
	key := pluginControlNetRouteLeaseKey(req)
	const previousMetadata = `{"version":1,"state":"previous"}`
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: pluginID, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: key, MetadataJSON: `{"version":1,"state":"current"}`,
	}); err != nil {
		t.Fatal(err)
	}
	entry := pluginNetTransactionEntry{
		Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: key,
		LeaseBefore:  pluginNetLeaseSnapshot{Exists: true, PluginID: pluginID, MetadataJSON: previousMetadata},
		RouteRequest: &req, RouteOriginal: []pluginControlNetRouteState{original},
	}
	record := addPendingPluginNetTransactionForTest(t, db, pluginID, pluginNetTransactionKindRoute, 1, []pluginNetTransactionEntry{entry})
	admin := &pluginControlNetAdminTest{}
	if err := recoverPendingPluginNetTransactions(db, admin); err != nil {
		t.Fatal(err)
	}
	if !containsPluginNetAdminCall(admin.calls, "routeDelete:198.51.100.0/24:::100:10") || !containsPluginNetAdminCall(admin.calls, "routeRestore:1") {
		t.Fatalf("multipath recovery calls = %+v", admin.calls)
	}
	lease, err := store.PluginOwnedResourceOrNil(db, pluginOwnedResourceTypeRoute, key)
	if err != nil || lease == nil || lease.MetadataJSON != previousMetadata {
		t.Fatalf("restored multipath lease = %+v, err=%v", lease, err)
	}
	if pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID); err != nil || pending != nil {
		t.Fatalf("pending multipath journal = %+v, err=%v", pending, err)
	}
}

func TestRecoverPendingPluginNetTransactionRemovesLeaseThatDidNotExist(t *testing.T) {
	db := openTestDB(t)
	const pluginID = "crash_absent_lease"
	req := pluginControlNetRouteRequest{Dst: "203.0.113.0/24", Dev: "host0", Table: 100}
	entry := pluginNetTransactionEntry{
		Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: pluginControlNetRouteLeaseKey(req), RouteRequest: &req,
	}
	if err := store.AddPluginOwnedResource(db, store.PluginOwnedResource{
		PluginID: pluginID, ResourceType: entry.ResourceType, ResourceKey: entry.ResourceKey, MetadataJSON: `{"version":1}`,
	}); err != nil {
		t.Fatal(err)
	}
	addPendingPluginNetTransactionForTest(t, db, pluginID, pluginNetTransactionKindRoute, 1, []pluginNetTransactionEntry{entry})
	if err := recoverPendingPluginNetTransactions(db, &pluginControlNetAdminTest{}); err != nil {
		t.Fatal(err)
	}
	lease, err := store.PluginOwnedResourceOrNil(db, entry.ResourceType, entry.ResourceKey)
	if err != nil || lease != nil {
		t.Fatalf("lease after recovery = %+v, err=%v, want none", lease, err)
	}
}

func TestRecoverPendingPluginNetTransactionFailureRetainsJournal(t *testing.T) {
	db := openTestDB(t)
	req := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Dev: "host0", Table: 100}
	entry := pluginNetTransactionEntry{
		Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: pluginControlNetRouteLeaseKey(req), RouteRequest: &req,
		RouteOriginal: []pluginControlNetRouteState{{Dst: req.Dst, Dev: req.Dev, Table: req.Table}},
	}
	record := addPendingPluginNetTransactionForTest(t, db, "recovery_failure", pluginNetTransactionKindRoute, 1, []pluginNetTransactionEntry{entry})
	admin := &failingPluginNetRecoveryAdmin{
		pluginControlNetAdminTest: &pluginControlNetAdminTest{},
		routeRestoreErr:           errors.New("injected restore failure"),
	}
	if err := recoverPendingPluginNetTransactions(db, admin); err == nil || !strings.Contains(err.Error(), "injected restore failure") {
		t.Fatalf("recovery error = %v", err)
	}
	if pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID); err != nil || pending == nil {
		t.Fatalf("pending journal = %+v, err=%v, want retained", pending, err)
	}
}

func TestRecoverPendingPluginNetTransactionRejectsMalformedJournalWithoutMutation(t *testing.T) {
	tests := []struct {
		name      string
		stateJSON string
		want      string
	}{
		{name: "trailing_json", stateJSON: `{"version":1,"entries":[]} {}`, want: "trailing"},
		{name: "wrong_resource_key", stateJSON: mustPluginNetTransactionStateJSONForTest(t, []pluginNetTransactionEntry{{
			Present: true, ResourceType: pluginOwnedResourceTypeRoute, ResourceKey: "wrong",
			RouteRequest: func() *pluginControlNetRouteRequest {
				req := pluginControlNetRouteRequest{Dst: "198.51.100.0/24", Dev: "host0", Table: 100}
				return &req
			}(),
		}}), want: "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := openTestDB(t)
			record := store.PluginNetTransaction{
				TransactionID: "malformed-" + tt.name, PluginID: "malformed", Kind: pluginNetTransactionKindRoute,
				StateJSON: tt.stateJSON, StartedCount: 1,
			}
			if err := store.AddPluginNetTransaction(db, record); err != nil {
				t.Fatal(err)
			}
			admin := &pluginControlNetAdminTest{}
			if err := recoverPendingPluginNetTransactions(db, admin); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("recovery error = %v, want %q", err, tt.want)
			}
			if len(admin.calls) != 0 {
				t.Fatalf("malformed recovery mutated network: %+v", admin.calls)
			}
			if pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID); err != nil || pending == nil {
				t.Fatalf("pending journal = %+v, err=%v, want retained", pending, err)
			}
		})
	}
}

func TestRecoverPendingPluginNetTransactionDeletesUnstartedJournalWithoutAdmin(t *testing.T) {
	db := openTestDB(t)
	record := store.PluginNetTransaction{
		TransactionID: "unstarted", PluginID: "unstarted", Kind: "invalid", StateJSON: "not-json", StartedCount: 0,
	}
	if err := store.AddPluginNetTransaction(db, record); err != nil {
		t.Fatal(err)
	}
	if err := recoverPendingPluginNetTransactions(db, nil); err != nil {
		t.Fatal(err)
	}
	if pending, err := store.PluginNetTransactionOrNil(db, record.TransactionID); err != nil || pending != nil {
		t.Fatalf("pending journal = %+v, err=%v, want none", pending, err)
	}
}

type failingPluginNetRecoveryAdmin struct {
	*pluginControlNetAdminTest
	routeRestoreErr error
}

func (a *failingPluginNetRecoveryAdmin) RouteRestore(states []pluginControlNetRouteState) error {
	a.calls = append(a.calls, fmt.Sprintf("routeRestore:%d", len(states)))
	return a.routeRestoreErr
}

func addPendingPluginNetTransactionForTest(t *testing.T, db *sql.DB, pluginID, kind string, started int, entries []pluginNetTransactionEntry) store.PluginNetTransaction {
	t.Helper()
	record := store.PluginNetTransaction{
		TransactionID: fmt.Sprintf("%s-%s-%d", pluginID, kind, started), PluginID: pluginID, Kind: kind,
		StateJSON: mustPluginNetTransactionStateJSONForTest(t, entries), StartedCount: started,
	}
	if err := store.AddPluginNetTransaction(db, record); err != nil {
		t.Fatal(err)
	}
	return record
}

func mustPluginNetTransactionStateJSONForTest(t *testing.T, entries []pluginNetTransactionEntry) string {
	t.Helper()
	raw, err := json.Marshal(pluginNetTransactionState{Version: pluginNetTransactionJournalVersion, Entries: entries})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
