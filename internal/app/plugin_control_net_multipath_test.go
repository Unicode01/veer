package app

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginControlRouteRequestNormalizesMultipath(t *testing.T) {
	req, err := validatePluginControlRouteRequest(pluginControlNetRouteRequest{
		Dst: "default", Metric: 10,
		Nexthops: []pluginControlNetRouteNexthop{
			{Dev: " host1 ", Gateway: "192.0.2.2", Weight: 2, Onlink: true},
			{Dev: "host0", Gateway: "192.0.2.1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Dst != "0.0.0.0/0" || req.Table != 254 || req.Metric != 10 {
		t.Fatalf("normalized route = %+v", req)
	}
	wantNexthops := []pluginControlNetRouteNexthop{
		{Dev: "host0", Gateway: "192.0.2.1", Weight: 1},
		{Dev: "host1", Gateway: "192.0.2.2", Weight: 2, Onlink: true},
	}
	if !reflect.DeepEqual(req.Nexthops, wantNexthops) {
		t.Fatalf("normalized nexthops = %+v, want %+v", req.Nexthops, wantNexthops)
	}
	if got := pluginControlNetRouteLeaseKey(req); got != "0.0.0.0/0|254|10" {
		t.Fatalf("route lease key = %q", got)
	}
	if got := pluginControlNetRouteInterfaces(req); !reflect.DeepEqual(got, []string{"host0", "host1"}) {
		t.Fatalf("route interfaces = %+v", got)
	}
}

func TestPluginControlRouteRequestRejectsUnsafeMultipath(t *testing.T) {
	tests := []struct {
		name string
		req  pluginControlNetRouteRequest
		want string
	}{
		{
			name: "mixed single and multipath",
			req:  pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Dev: "host0", Nexthops: []pluginControlNetRouteNexthop{{Dev: "host1"}}},
			want: "cannot be combined",
		},
		{
			name: "family mismatch",
			req:  pluginControlNetRouteRequest{Dst: "::/0", Nexthops: []pluginControlNetRouteNexthop{{Dev: "host0", Gateway: "192.0.2.1"}}},
			want: "does not match destination address family",
		},
		{
			name: "duplicate path",
			req:  pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Nexthops: []pluginControlNetRouteNexthop{{Dev: "host0"}, {Dev: "host0", Weight: 2}}},
			want: "duplicates dev/gateway",
		},
		{
			name: "invalid weight",
			req:  pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Nexthops: []pluginControlNetRouteNexthop{{Dev: "host0", Weight: 257}}},
			want: "weight must be between 1 and 256",
		},
		{
			name: "onlink without gateway",
			req:  pluginControlNetRouteRequest{Dst: "0.0.0.0/0", Nexthops: []pluginControlNetRouteNexthop{{Dev: "host0", Onlink: true}}},
			want: "onlink requires gateway",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := validatePluginControlRouteRequest(tt.req); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validation error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPluginControlMultipathRouteIsLeasedAndRestored(t *testing.T) {
	dir := t.TempDir()
	writeNetworkLeasePlugin(t, dir, "multipath_route", `
exports.onAction = function () {
  return net.route.transaction([{op:"replace", request:{
    dst:"198.51.100.0/24", table:100, metric:10,
    nexthops:[
      {dev:"host1", gateway:"192.0.3.2", weight:2},
      {dev:"host0", gateway:"192.0.2.2", weight:1, onlink:true}
    ]
  }}]);
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	request := pluginControlNetRouteRequest{
		Dst: "198.51.100.0/24", Table: 100, Metric: 10,
		Nexthops: []pluginControlNetRouteNexthop{
			{Dev: "host0", Gateway: "192.0.2.2", Weight: 1, Onlink: true},
			{Dev: "host1", Gateway: "192.0.3.2", Weight: 2},
		},
	}
	original := pluginControlNetRouteState{
		Dst: request.Dst, Table: request.Table, Metric: request.Metric,
		Nexthops: []pluginControlNetRouteNexthopState{
			{Dev: "host0", DevIfIndex: 50, Gateway: "192.0.2.1", Weight: 1},
			{Dev: "host1", DevIfIndex: 51, Gateway: "192.0.3.1", Weight: 1},
		},
	}
	controller := &pluginControlNetAdminTest{
		links: map[string]pluginControlNetLinkInfo{
			"host0": {Name: "host0", IfIndex: 50, Kind: "device", MTU: 1500, Up: true},
			"host1": {Name: "host1", IfIndex: 51, Kind: "device", MTU: 1500, Up: true},
		},
		routeSnapshots: map[string][]pluginControlNetRouteState{pluginControlNetRouteLeaseKey(request): {original}},
	}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "multipath_route")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "multipath_route")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	owned, err := store.GetPluginOwnedResources(db, plugin.ID)
	if err != nil || len(owned) != 1 {
		t.Fatalf("owned routes = %+v, err=%v", owned, err)
	}
	var metadata pluginOwnedRouteMutation
	if err := json.Unmarshal([]byte(owned[0].MetadataJSON), &metadata); err != nil {
		t.Fatal(err)
	}
	if len(metadata.Current.Nexthops) != 2 || !reflect.DeepEqual(metadata.LinkIdentities, []pluginOwnedRouteLinkIdentity{{Dev: "host0", IfIndex: 50}, {Dev: "host1", IfIndex: 51}}) {
		t.Fatalf("multipath ownership = %+v", metadata)
	}
	runtime.Reconcile(PluginCatalog{})
	if !containsPluginNetAdminCall(controller.calls, "routeRestore:1") || !containsPluginNetAdminCall(controller.calls, "routeDelete:198.51.100.0/24:::100:10") {
		t.Fatalf("multipath restore calls = %+v", controller.calls)
	}
}

func TestPluginControlMultipathRouteChecksEveryInterfacePermission(t *testing.T) {
	dir := t.TempDir()
	writeTestPlugin(t, dir, "multipath_denied", `{
  "api_version":"v1","id":"multipath_denied","name":"Multipath Denied","version":"1.0.0","kind":"control",
  "control":{"main":"control.js","permissions":["plugin.register","net.admin"],
    "net_access":[{"interfaces":["host0"],"operations":["link.read","route.write"]}]}
}`)
	writePluginControlScript(t, dir, "multipath_denied", `
plugin.action({id:"apply", runtime_update:"runtime_query"});
exports.onReconcile = function () {};
exports.onAction = function () {
  return net.route.replace({dst:"0.0.0.0/0", nexthops:[{dev:"host0"},{dev:"host1"}]});
};`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	runtime := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	controller := &pluginControlNetAdminTest{}
	runtime.netAdmin = controller
	defer runtime.Close()
	catalog := loadPluginCatalogWithState(cfg, db)
	assertPluginReconcileSuccess(t, runtime, catalog, "multipath_denied")
	plugin := transactionPluginWithRuntimeSurfaceForTest(t, runtime, catalog, "multipath_denied")
	if _, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`)); err == nil || !strings.Contains(err.Error(), "host1") {
		t.Fatalf("permission error = %v", err)
	}
	if len(controller.calls) != 0 {
		t.Fatalf("permission denial reached net admin: %+v", controller.calls)
	}
}
