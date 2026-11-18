//go:build linux

package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

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
