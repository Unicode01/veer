//go:build linux

package app

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestPluginNetlinkRouteEventPayloadResolvesInterfaces(t *testing.T) {
	loopback, err := netlink.LinkByName("lo")
	if err != nil || loopback == nil || loopback.Attrs() == nil {
		t.Skipf("loopback interface unavailable: %v", err)
	}
	payload := pluginNetlinkRouteEventPayload(netlink.RouteUpdate{
		Type: unix.RTM_NEWROUTE,
		Route: netlink.Route{
			Family:    unix.AF_INET,
			LinkIndex: loopback.Attrs().Index,
			Table:     unix.RT_TABLE_MAIN,
			Priority:  10,
		},
	})
	if payload["operation"] != "update" || payload["destination"] != "0.0.0.0/0" {
		t.Fatalf("route payload = %+v", payload)
	}
	if payload["interface"] != "lo" || payload["interface_resolution_complete"] != true {
		t.Fatalf("route interface payload = %+v", payload)
	}
	interfaces, ok := payload["interfaces"].([]string)
	if !ok || len(interfaces) != 1 || interfaces[0] != "lo" {
		t.Fatalf("route interfaces = %#v", payload["interfaces"])
	}
}

func TestPluginNetlinkRouteEventPayloadFailsClosedOnUnknownInterface(t *testing.T) {
	payload := pluginNetlinkRouteEventPayload(netlink.RouteUpdate{
		Type: unix.RTM_DELROUTE,
		Route: netlink.Route{
			Family:    unix.AF_INET6,
			LinkIndex: 1 << 30,
		},
	})
	if payload["operation"] != "delete" || payload["destination"] != "::/0" {
		t.Fatalf("route payload = %+v", payload)
	}
	if payload["interface_resolution_complete"] != false {
		t.Fatalf("unresolved route payload did not fail closed: %+v", payload)
	}
}

func TestPluginNetlinkMonitorDeliversAuthorizedRouteEvent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a disposable link and route")
	}
	name := fmt.Sprintf("vrtevt%d", os.Getpid()%100000)
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	createdLink := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(createdLink); err != nil {
		t.Skipf("create disposable dummy link: %v", err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		_ = netlink.LinkDel(createdLink)
		t.Fatalf("resolve disposable dummy link: %v", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		_ = netlink.LinkDel(link)
		t.Fatalf("set disposable dummy link up: %v", err)
	}
	_, destination, _ := net.ParseCIDR("198.51.100.0/24")
	route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: destination, Table: 49001, Priority: 77}
	defer func() {
		_ = netlink.RouteDel(route)
		_ = netlink.LinkDel(link)
	}()

	dir := t.TempDir()
	writeTestPlugin(t, dir, "route_events", fmt.Sprintf(`{
  "api_version": "v1",
  "id": "route_events",
  "name": "Route Events",
  "version": "1.0.0",
  "kind": "control",
  "control": {
    "main": "control.js",
    "permissions": ["event", "kv", "net.admin", "plugin.register", "worker"],
    "net_access": [{"interfaces":[%q],"operations":["link.read"]}]
  }
}`, name))
	writePluginControlScript(t, dir, "route_events", `
events.subscribe({id:'routes',topic:'net.route',worker:'routes'});
exports.onEvent = function (ctx) { kv.set('last_route', ctx.event.payload); };
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	rt := newPluginControlRuntime(db, cfg, nil).(*gojaPluginControlRuntime)
	t.Cleanup(func() { _ = rt.Close() })
	snapshot := rt.Reconcile(loadPluginCatalogWithControlRegistrationAndState(cfg, db))
	if state, ok := snapshot.Plugins["route_events"]; !ok || state.Error != "" {
		t.Fatalf("route event plugin reconcile state = %+v, present=%t", state, ok)
	}

	pm := &ProcessManager{pluginControlRuntime: rt}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		pm.runKernelNetlinkMonitor(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("netlink monitor did not stop")
		}
	}()
	time.Sleep(150 * time.Millisecond)
	if err := netlink.RouteReplace(route); err != nil {
		t.Fatalf("create disposable route: %v", err)
	}
	record := waitForPluginEventRecord(t, db, "route_events", "last_route")
	for _, want := range []string{`"operation":"update"`, `"destination":"198.51.100.0/24"`, `"interface":"` + name + `"`, `"table":49001`} {
		if !strings.Contains(record.DataJSON, want) {
			t.Fatalf("route event data = %s, want %s", record.DataJSON, want)
		}
	}
}
