//go:build linux

package app

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const pluginIPv6PlanIntegrationEnableEnv = "FORWARD_RUN_PLUGIN_IPV6_PLAN_TEST"
const pluginIPv6PlanIntegrationHelperEnv = "FORWARD_PLUGIN_IPV6_PLAN_HELPER"

func TestPluginIPv6AssignmentPlanLinuxIntegration(t *testing.T) {
	if os.Getenv(pluginIPv6PlanIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run plugin IPv6 plan integration test", pluginIPv6PlanIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	if os.Getenv(pluginIPv6PlanIntegrationHelperEnv) != "1" {
		runPluginIPv6PlanIntegrationInNetNS(t)
		return
	}

	setPluginIPv6PlanIntegrationLinkUp(t, "lo")
	parent := addPluginIPv6PlanIntegrationDummy(t, "veerwan0")
	bridge := addPluginIPv6PlanIntegrationBridge(t, "br-lan")
	addPluginIPv6PlanIntegrationAddress(t, bridge, "fe80::1/64")

	ops := newLinuxIPv6AssignmentNetOps()
	rt := newManagedIPv6AssignmentRuntime(ops)
	assignment := IPv6Assignment{
		ID:              1,
		ParentInterface: parent.Attrs().Name,
		TargetInterface: bridge.Attrs().Name,
		ParentPrefix:    "2001:db8:120::/60",
		AssignedPrefix:  "2001:db8:120:5::/64",
		Enabled:         true,
		upstreamRouted:  true,
		gatewayCIDR:     "2001:db8:120:5::1/60",
		rejectPrefix:    "2001:db8:120::/60",
		dnsServers:      []string{"2001:4860:4860::8888", "2400:3200::1"},
	}
	if err := rt.Reconcile([]IPv6Assignment{assignment}); err != nil {
		t.Fatalf("Reconcile(routed PD) error = %v", err)
	}

	assertPluginIPv6PlanIntegrationAddress(t, bridge, "2001:db8:120:5::1", 60, true)
	assertPluginIPv6PlanIntegrationRoute(t, "2001:db8:120:5::/64", bridge.Attrs().Index, unix.RTN_UNICAST)
	assertPluginIPv6PlanIntegrationRoute(t, "2001:db8:120::/60", 0, unix.RTN_UNREACHABLE)
	_, advertises := ops.SnapshotIPv6AssignmentCounters()[bridge.Attrs().Name]
	if !advertises {
		t.Fatal("router advertiser was not created for br-lan")
	}
	waitForPluginIPv6PlanIntegrationRA(t, ops, bridge.Attrs().Name)
	advertisementCount := ops.SnapshotIPv6AssignmentCounters()[bridge.Attrs().Name].RAAdvertisementCount

	assignment.ParentPrefix = "2001:db8:130::/60"
	assignment.AssignedPrefix = "2001:db8:130:7::/64"
	assignment.gatewayCIDR = "2001:db8:130:7::1/60"
	assignment.rejectPrefix = "2001:db8:130::/60"
	if err := rt.Reconcile([]IPv6Assignment{assignment}); err != nil {
		t.Fatalf("Reconcile(rotated PD) error = %v", err)
	}
	assertPluginIPv6PlanIntegrationAddress(t, bridge, "2001:db8:130:7::1", 60, true)
	assertPluginIPv6PlanIntegrationAddressAbsent(t, bridge, "2001:db8:120:5::1")
	assertPluginIPv6PlanIntegrationRoute(t, "2001:db8:130:7::/64", bridge.Attrs().Index, unix.RTN_UNICAST)
	assertPluginIPv6PlanIntegrationRoute(t, "2001:db8:130::/60", 0, unix.RTN_UNREACHABLE)
	assertPluginIPv6PlanIntegrationRouteAbsent(t, "2001:db8:120:5::/64")
	assertPluginIPv6PlanIntegrationRouteAbsent(t, "2001:db8:120::/60")
	waitForPluginIPv6PlanIntegrationRAAfter(t, ops, bridge.Attrs().Name, advertisementCount)

	if err := rt.Reconcile(nil); err != nil {
		t.Fatalf("Reconcile(nil) error = %v", err)
	}
	assertPluginIPv6PlanIntegrationAddressAbsent(t, bridge, "2001:db8:130:7::1")
	assertPluginIPv6PlanIntegrationRouteAbsent(t, "2001:db8:130:7::/64")
	assertPluginIPv6PlanIntegrationRouteAbsent(t, "2001:db8:130::/60")
	_, advertises = ops.SnapshotIPv6AssignmentCounters()[bridge.Attrs().Name]
	if advertises {
		t.Fatal("router advertiser remains after plan removal")
	}
}

func runPluginIPv6PlanIntegrationInNetNS(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare is required for isolated network namespace integration")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	cmd := exec.Command("unshare", "--net", executable,
		"-test.run=^TestPluginIPv6AssignmentPlanLinuxIntegration$",
		"-test.count=1",
		"-test.v")
	cmd.Env = append(os.Environ(), pluginIPv6PlanIntegrationHelperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated integration subprocess: %v\n%s", err, strings.TrimSpace(string(output)))
	}
	t.Logf("isolated integration subprocess passed:\n%s", strings.TrimSpace(string(output)))
}

func addPluginIPv6PlanIntegrationDummy(t *testing.T, name string) netlink.Link {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	link := &netlink.Dummy{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("add dummy %s: %v", name, err)
	}
	setPluginIPv6PlanIntegrationLinkUp(t, name)
	created, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("resolve created dummy %s: %v", name, err)
	}
	return created
}

func addPluginIPv6PlanIntegrationBridge(t *testing.T, name string) netlink.Link {
	t.Helper()
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	link := &netlink.Bridge{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatalf("add bridge %s: %v", name, err)
	}
	setPluginIPv6PlanIntegrationLinkUp(t, name)
	created, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("resolve created bridge %s: %v", name, err)
	}
	return created
}

func setPluginIPv6PlanIntegrationLinkUp(t *testing.T, name string) {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("resolve link %s: %v", name, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatalf("set link %s up: %v", name, err)
	}
}

func addPluginIPv6PlanIntegrationAddress(t *testing.T, link netlink.Link, cidr string) {
	t.Helper()
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		t.Fatalf("parse address %s: %v", cidr, err)
	}
	addr.Flags |= unix.IFA_F_NODAD
	if err := netlink.AddrReplace(link, addr); err != nil {
		t.Fatalf("add address %s to %s: %v", cidr, link.Attrs().Name, err)
	}
}

func waitForPluginIPv6PlanIntegrationRA(t *testing.T, ops *linuxIPv6AssignmentNetOps, targetInterface string) {
	waitForPluginIPv6PlanIntegrationRAAfter(t, ops, targetInterface, 0)
}

func waitForPluginIPv6PlanIntegrationRAAfter(t *testing.T, ops *linuxIPv6AssignmentNetOps, targetInterface string, previousCount uint64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		counter := ops.SnapshotIPv6AssignmentCounters()[targetInterface]
		if counter.RAStatus == "error" {
			t.Fatalf("router advertisement failed: %s", counter.RAStatusDetail)
		}
		if counter.RAAdvertisementCount > previousCount {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	counter := ops.SnapshotIPv6AssignmentCounters()[targetInterface]
	t.Fatalf("router advertisement did not advance past %d: count=%d status=%s detail=%s", previousCount, counter.RAAdvertisementCount, counter.RAStatus, counter.RAStatusDetail)
}

func assertPluginIPv6PlanIntegrationAddress(t *testing.T, link netlink.Link, address string, prefixLen int, noPrefixRoute bool) {
	t.Helper()
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		t.Fatalf("list IPv6 addresses on %s: %v", link.Attrs().Name, err)
	}
	wantIP := net.ParseIP(address)
	for _, addr := range addrs {
		if addr.IP == nil || !addr.IP.Equal(wantIP) || addr.IPNet == nil {
			continue
		}
		gotPrefixLen, _ := addr.IPNet.Mask.Size()
		if gotPrefixLen != prefixLen {
			t.Fatalf("address %s prefix length = %d, want %d", address, gotPrefixLen, prefixLen)
		}
		if got := addr.Flags&unix.IFA_F_NOPREFIXROUTE != 0; got != noPrefixRoute {
			t.Fatalf("address %s noprefixroute = %t, want %t", address, got, noPrefixRoute)
		}
		return
	}
	t.Fatalf("address %s/%d not found on %s: %+v", address, prefixLen, link.Attrs().Name, addrs)
}

func assertPluginIPv6PlanIntegrationAddressAbsent(t *testing.T, link netlink.Link, address string) {
	t.Helper()
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		t.Fatalf("list IPv6 addresses on %s: %v", link.Attrs().Name, err)
	}
	wantIP := net.ParseIP(address)
	for _, addr := range addrs {
		if addr.IP != nil && addr.IP.Equal(wantIP) {
			t.Fatalf("address %s remains on %s", address, link.Attrs().Name)
		}
	}
}

func assertPluginIPv6PlanIntegrationRoute(t *testing.T, prefix string, linkIndex int, routeType int) {
	t.Helper()
	_, wantPrefix, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("parse expected route %s: %v", prefix, err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Dst: wantPrefix}, netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatalf("list route %s: %v", prefix, err)
	}
	for _, route := range routes {
		if route.Dst == nil || route.Dst.String() != wantPrefix.String() || route.Type != routeType {
			continue
		}
		if linkIndex != 0 && route.LinkIndex != linkIndex {
			continue
		}
		return
	}
	t.Fatalf("route %s type=%d link=%d not found: %+v", prefix, routeType, linkIndex, routes)
}

func assertPluginIPv6PlanIntegrationRouteAbsent(t *testing.T, prefix string) {
	t.Helper()
	_, wantPrefix, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("parse expected route %s: %v", prefix, err)
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Dst: wantPrefix}, netlink.RT_FILTER_DST)
	if err != nil {
		t.Fatalf("list route %s: %v", prefix, err)
	}
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == wantPrefix.String() {
			t.Fatalf("route %s remains: %+v", prefix, route)
		}
	}
}
