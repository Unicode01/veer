//go:build linux

package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Unicode01/veer/internal/netservice"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestLinuxIPv6AssignmentNetOpsPreserveIPv6AssignmentStateOnClose(t *testing.T) {
	ops := newLinuxIPv6AssignmentNetOps()

	t.Run("env unset", func(t *testing.T) {
		t.Setenv(forwardHotRestartMarkerEnv, "")
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatal("PreserveIPv6AssignmentStateOnClose() = true, want false when marker env is unset")
		}
	})

	t.Run("marker missing", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = true, want false when marker %q is missing", marker)
		}
	})

	t.Run("marker present", func(t *testing.T) {
		marker := filepath.Join(t.TempDir(), ".hot-restart-kernel")
		if err := os.WriteFile(marker, []byte("1"), 0o644); err != nil {
			t.Fatalf("WriteFile(%q) error = %v", marker, err)
		}
		t.Setenv(forwardHotRestartMarkerEnv, marker)
		if !ops.PreserveIPv6AssignmentStateOnClose() {
			t.Fatalf("PreserveIPv6AssignmentStateOnClose() = false, want true when marker %q exists", marker)
		}
	})
}

// TestLinuxIPv6AssignmentRouteFollowsDestroyedBridgePort reproduces a guest
// on a bridge: the route of its /128 goes to the bridge, and destroying the
// guest's tap must not leave that route behind, whether or not this process
// installed it. The sweep then removes what an older version left.
func TestLinuxIPv6AssignmentRouteFollowsDestroyedBridgePort(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the Linux IPv6 assignment route test", ipv6AssignmentIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	bridgeName := "v6rb" + suffix
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}
	if err := netlink.LinkAdd(bridge); err != nil {
		t.Skipf("create bridge: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(bridge) })
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", bridgeName, "disable_ipv6"), []byte("0"), 0o644)
	if err := netlink.LinkSetUp(bridge); err != nil {
		t.Fatal(err)
	}
	addPort := func(name string) {
		t.Helper()
		port := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
		if err := netlink.LinkAdd(port); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if l, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(l)
			}
		})
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetMaster(link, bridge); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	removePort := func(name string) {
		t.Helper()
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Fatal(err)
		}
	}
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		t.Fatal(err)
	}
	routesOnBridge := func() map[string]int {
		t.Helper()
		routes, err := netlink.RouteList(bridgeLink, unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]int{}
		for _, route := range routes {
			if route.Dst != nil {
				out[ipv6AssignmentRouteKey(route.Dst)] = int(route.Protocol)
			}
		}
		return out
	}

	const first = "2001:db8:7ad3::a/128"
	ops := newLinuxIPv6AssignmentNetOps()
	addPort("v6ta" + suffix)
	spec := ipv6AssignmentRouteSpec{Prefix: first, TargetInterface: "v6ta" + suffix}
	if err := ops.EnsureIPv6Route(spec); err != nil {
		t.Fatal(err)
	}
	if proto, ok := routesOnBridge()[first]; !ok || proto != unix.RTPROT_STATIC {
		t.Fatalf("routes on %s = %v, want %s proto static", bridgeName, routesOnBridge(), first)
	}
	removePort("v6ta" + suffix)
	if err := ops.DeleteIPv6Route(spec); err != nil {
		t.Fatal(err)
	}
	if _, ok := routesOnBridge()[first]; ok {
		t.Fatalf("route %s of the destroyed port stayed on %s", first, bridgeName)
	}

	// A route this process never installed (a hot-restart predecessor's):
	// a fresh ops instance finds it by its exact prefix.
	const second = "2001:db8:7ad3::b/128"
	addPort("v6tb" + suffix)
	predecessor := ipv6AssignmentRouteSpec{Prefix: second, TargetInterface: "v6tb" + suffix}
	if err := newLinuxIPv6AssignmentNetOps().EnsureIPv6Route(predecessor); err != nil {
		t.Fatal(err)
	}
	removePort("v6tb" + suffix)
	if err := newLinuxIPv6AssignmentNetOps().DeleteIPv6Route(predecessor); err != nil {
		t.Fatal(err)
	}
	if _, ok := routesOnBridge()[second]; ok {
		t.Fatalf("route %s stayed on %s after a successor deleted it", second, bridgeName)
	}

	// The sweep removes static assignment-shaped routes nothing uses, and
	// only those: not a used one, not another protocol, not one outside the
	// parent prefix or of another length.
	add := func(cidr string, protocol int) {
		t.Helper()
		_, dst, _ := net.ParseCIDR(cidr)
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: bridgeLink.Attrs().Index, Dst: dst, Protocol: netlink.RouteProtocol(protocol)}); err != nil {
			t.Fatalf("add %s: %v", cidr, err)
		}
	}
	add("2001:db8:7ad3::c/128", unix.RTPROT_STATIC)
	add("2001:db8:7ad3::d/128", unix.RTPROT_STATIC)
	add("2001:db8:7ad3::e/128", unix.RTPROT_BOOT)
	add("2001:db8:9999::f/128", unix.RTPROT_STATIC)
	add("2001:db8:7ad3:1::/64", unix.RTPROT_STATIC)
	_, parent, _ := net.ParseCIDR("2001:db8:7ad3::/64")
	scopes := []ipv6AssignmentRouteSweepScope{{Bridge: bridgeName, ParentPrefix: parent, PrefixLen: 128}}
	keep := map[string]struct{}{"2001:db8:7ad3::d/128": {}}
	if err := ops.SweepIPv6AssignmentRoutes(scopes, keep); err != nil {
		t.Fatal(err)
	}
	got := routesOnBridge()
	for _, gone := range []string{"2001:db8:7ad3::c/128"} {
		if _, ok := got[gone]; ok {
			t.Fatalf("sweep left %s: %v", gone, got)
		}
	}
	for _, kept := range []string{"2001:db8:7ad3::d/128", "2001:db8:7ad3::e/128", "2001:db8:9999::f/128", "2001:db8:7ad3:1::/64"} {
		if _, ok := got[kept]; !ok {
			t.Fatalf("sweep removed %s: %v", kept, got)
		}
	}
}

// TestLinuxIPv6AssignmentWithDestroyedTargetWaits covers guests destroyed
// while the interface inventory still plans their assignments: the reconcile
// must not fail on the missing tap, and the route and proxy of the assignment
// go away at once instead of when the inventory drops it.
func TestLinuxIPv6AssignmentWithDestroyedTargetWaits(t *testing.T) {
	if os.Getenv(ipv6AssignmentIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run the Linux IPv6 assignment route test", ipv6AssignmentIntegrationEnableEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	const proxyNDPAll = "/proc/sys/net/ipv6/conf/all/proxy_ndp"
	if previous, err := os.ReadFile(proxyNDPAll); err == nil {
		t.Cleanup(func() { _ = os.WriteFile(proxyNDPAll, previous, 0o644) })
	}
	suffix := fmt.Sprintf("%04x", uint16(time.Now().UnixNano()))
	bridgeName := "v6db" + suffix
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}
	if err := netlink.LinkAdd(bridge); err != nil {
		t.Skipf("create bridge: %v", err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(bridge) })
	_ = os.WriteFile(filepath.Join("/proc/sys/net/ipv6/conf", bridgeName, "disable_ipv6"), []byte("0"), 0o644)
	if err := netlink.LinkSetUp(bridge); err != nil {
		t.Fatal(err)
	}
	bridgeLink, err := netlink.LinkByName(bridgeName)
	if err != nil {
		t.Fatal(err)
	}
	portNames := []string{"v6da" + suffix, "v6dc" + suffix}
	for _, name := range portNames {
		port := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name, MasterIndex: bridgeLink.Attrs().Index}, PeerName: name + "p"}
		if err := netlink.LinkAdd(port); err != nil {
			t.Fatal(err)
		}
		name := name
		t.Cleanup(func() {
			if l, err := netlink.LinkByName(name); err == nil {
				_ = netlink.LinkDel(l)
			}
		})
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}

	plans := make([]netservice.IPv6AssignmentPlan, 0, len(portNames))
	for i, name := range portNames {
		address := fmt.Sprintf("2001:db8:7ad4::%x", 0xa+i)
		plans = append(plans, netservice.IPv6AssignmentPlan{
			ID:              int64(i + 1),
			ParentInterface: bridgeName,
			TargetInterface: name,
			ParentPrefix:    "2001:db8:7ad4::/64",
			AssignedPrefix:  address + "/128",
			AssignedAddress: address,
			ProxyAddress:    address,
			NeedsProxyNDP:   true,
		})
	}
	ops := newLinuxIPv6AssignmentNetOps()
	rt := netservice.NewIPv6AssignmentRuntime(ops)
	t.Cleanup(func() { _ = rt.Close(false) })
	state := func() (routes map[string]bool, proxies map[string]bool) {
		t.Helper()
		routes, proxies = map[string]bool{}, map[string]bool{}
		list, err := netlink.RouteList(bridgeLink, unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range list {
			if route.Dst != nil {
				routes[ipv6AssignmentRouteKey(route.Dst)] = true
			}
		}
		neighs, err := netlink.NeighProxyList(bridgeLink.Attrs().Index, unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		for _, neigh := range neighs {
			proxies[neigh.IP.String()] = true
		}
		return routes, proxies
	}

	if err := rt.Reconcile(plans, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	routes, proxies := state()
	if !routes["2001:db8:7ad4::a/128"] || !routes["2001:db8:7ad4::b/128"] || !proxies["2001:db8:7ad4::a"] || !proxies["2001:db8:7ad4::b"] {
		t.Fatalf("applied state routes=%v proxies=%v, want both assignments", routes, proxies)
	}

	destroyed, err := netlink.LinkByName(portNames[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkDel(destroyed); err != nil {
		t.Fatal(err)
	}
	if !ops.IPv6InterfaceGone(portNames[0]) || ops.IPv6InterfaceGone(portNames[1]) || ops.IPv6InterfaceGone("lo") {
		t.Fatal("IPv6InterfaceGone() misreports which interfaces exist")
	}
	for _, phase := range []string{"first", "second"} {
		if err := rt.Reconcile(plans, nil); err != nil {
			t.Fatalf("%s Reconcile() with %s destroyed error = %v, want its assignment to wait", phase, portNames[0], err)
		}
		routes, proxies = state()
		if routes["2001:db8:7ad4::a/128"] || proxies["2001:db8:7ad4::a"] {
			t.Fatalf("%s reconcile: destroyed guest still has routes=%v proxies=%v", phase, routes, proxies)
		}
		if !routes["2001:db8:7ad4::b/128"] || !proxies["2001:db8:7ad4::b"] {
			t.Fatalf("%s reconcile: live guest lost routes=%v proxies=%v", phase, routes, proxies)
		}
		stats := rt.SnapshotStats()
		if stats[1].RuntimeStatus != "draining" || stats[2].RuntimeStatus != "running" {
			t.Fatalf("%s reconcile: stats = %+v, want 1 draining and 2 running", phase, stats)
		}
	}

	// The guest restarts: its tap comes back under the same name with a new
	// ifindex. The runtime reports it, and the next reconcile restores the
	// route and proxy.
	if got := rt.ReturnedDormantTargets(); len(got) != 0 {
		t.Fatalf("ReturnedDormantTargets() = %v while %s is gone, want none", got, portNames[0])
	}
	recreated := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: portNames[0], MasterIndex: bridgeLink.Attrs().Index}, PeerName: portNames[0] + "p"}
	if err := netlink.LinkAdd(recreated); err != nil {
		t.Fatal(err)
	}
	if link, err := netlink.LinkByName(portNames[0]); err != nil {
		t.Fatal(err)
	} else if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	if got := rt.ReturnedDormantTargets(); len(got) != 1 || got[0] != portNames[0] {
		t.Fatalf("ReturnedDormantTargets() = %v after %s came back, want it", got, portNames[0])
	}
	if err := rt.Reconcile(plans, nil); err != nil {
		t.Fatalf("Reconcile() after %s came back error = %v", portNames[0], err)
	}
	routes, proxies = state()
	if !routes["2001:db8:7ad4::a/128"] || !proxies["2001:db8:7ad4::a"] || !routes["2001:db8:7ad4::b/128"] || !proxies["2001:db8:7ad4::b"] {
		t.Fatalf("after the guest restarted: routes=%v proxies=%v, want both assignments back", routes, proxies)
	}
	if stats := rt.SnapshotStats(); stats[1].RuntimeStatus != "running" || stats[2].RuntimeStatus != "running" {
		t.Fatalf("after the guest restarted: stats = %+v, want both running", stats)
	}
	if got := rt.DormantTargets(); len(got) != 0 {
		t.Fatalf("DormantTargets() = %v after the guest restarted, want none", got)
	}
}
