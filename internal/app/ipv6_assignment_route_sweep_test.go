package app

import (
	"net"
	"reflect"
	"strconv"
	"testing"
)

func TestManagedNetworkIPv6RouteSweepScopes(t *testing.T) {
	network := func(name, mode, prefix string, mutate func(*ManagedNetwork)) ManagedNetwork {
		item := ManagedNetwork{
			ID: 1, Name: name, Enabled: true, Bridge: name,
			IPv6Enabled: true, IPv6ParentInterface: "vmbr0", IPv6ParentPrefix: prefix, IPv6AssignmentMode: mode,
		}
		if mutate != nil {
			mutate(&item)
		}
		return item
	}
	scopes := managedNetworkIPv6RouteSweepScopes([]ManagedNetwork{
		network("vmbr1", managedNetworkIPv6AssignmentModeSingle128, "2607:5300:203:7ad3::/64", nil),
		network("vmbr2", managedNetworkIPv6AssignmentModePrefix64, "2001:db8:100::/56", nil),
		network("off", managedNetworkIPv6AssignmentModeSingle128, "2001:db8:1::/64", func(n *ManagedNetwork) { n.Enabled = false }),
		network("v4only", managedNetworkIPv6AssignmentModeSingle128, "2001:db8:2::/64", func(n *ManagedNetwork) { n.IPv6Enabled = false }),
		network("noprefix", managedNetworkIPv6AssignmentModeSingle128, "", nil),
		// A /64 parent cannot hand out /64 prefixes below itself.
		network("flat", managedNetworkIPv6AssignmentModePrefix64, "2001:db8:3::/64", nil),
	})
	got := map[string]string{}
	for _, scope := range scopes {
		ones, _ := scope.ParentPrefix.Mask.Size()
		got[scope.Bridge] = scope.ParentPrefix.IP.String() + "/" + strconv.Itoa(ones) + " len " + strconv.Itoa(scope.PrefixLen)
	}
	want := map[string]string{
		"vmbr1": "2607:5300:203:7ad3::/64 len 128",
		"vmbr2": "2001:db8:100::/56 len 64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scopes = %v, want %v", got, want)
	}
}

func TestIPv6AssignmentRoutePrefixesInUse(t *testing.T) {
	keep := ipv6AssignmentRoutePrefixesInUse([]IPv6Assignment{
		{ID: 1, Enabled: true, AssignedPrefix: "2607:5300:203:7ad3::a/128"},
		{ID: 2, Enabled: true, Address: "2607:5300:203:7ad3:0:0:0:b", PrefixLen: 128},
		{ID: 3, Enabled: false, AssignedPrefix: "2607:5300:203:7ad3::c/128"},
		{ID: 4, Enabled: true, AssignedPrefix: "2001:db8:100:1::/64"},
	})
	want := map[string]struct{}{
		"2607:5300:203:7ad3::a/128": {},
		"2607:5300:203:7ad3::b/128": {},
		"2001:db8:100:1::/64":       {},
	}
	if !reflect.DeepEqual(keep, want) {
		t.Fatalf("keep = %v, want %v (a disabled assignment keeps no route)", keep, want)
	}
	_, prefix, _ := net.ParseCIDR("2607:5300:203:7ad3::a/128")
	if _, ok := keep[ipv6AssignmentRouteKey(prefix)]; !ok {
		t.Fatal("route keys of a netlink-style prefix and an assignment differ")
	}
}

type fakeIPv6AssignmentRouteSweeperOps struct {
	fakeIPv6AssignmentNetOps
	scopes [][]ipv6AssignmentRouteSweepScope
	keeps  []map[string]struct{}
}

func (ops *fakeIPv6AssignmentRouteSweeperOps) SweepIPv6AssignmentRoutes(scopes []ipv6AssignmentRouteSweepScope, keep map[string]struct{}) error {
	ops.scopes = append(ops.scopes, scopes)
	ops.keeps = append(ops.keeps, keep)
	return nil
}

func TestManagedIPv6AssignmentRuntimeSweepsStaleRoutesOfManagedBridges(t *testing.T) {
	ops := &fakeIPv6AssignmentRouteSweeperOps{}
	rt := newManagedIPv6AssignmentRuntime(ops)
	sweeper, ok := rt.(ipv6AssignmentStaleRouteSweeper)
	if !ok {
		t.Fatal("the managed IPv6 assignment runtime cannot sweep stale routes")
	}
	networks := []ManagedNetwork{{
		ID: 1, Name: "guests", Enabled: true, Bridge: "vmbr1",
		IPv6Enabled: true, IPv6ParentInterface: "vmbr0", IPv6ParentPrefix: "2607:5300:203:7ad3::/64",
		IPv6AssignmentMode: managedNetworkIPv6AssignmentModeSingle128,
	}}
	items := []IPv6Assignment{{ID: 7, Enabled: true, ParentInterface: "vmbr0", TargetInterface: "tap101i0", ParentPrefix: "2607:5300:203:7ad3::/64", AssignedPrefix: "2607:5300:203:7ad3::7/128"}}
	if err := sweeper.SweepStaleRoutes(networks, items); err != nil {
		t.Fatal(err)
	}
	if len(ops.scopes) != 1 || len(ops.scopes[0]) != 1 || ops.scopes[0][0].Bridge != "vmbr1" || ops.scopes[0][0].PrefixLen != 128 {
		t.Fatalf("sweep scopes = %+v", ops.scopes)
	}
	if _, kept := ops.keeps[0]["2607:5300:203:7ad3::7/128"]; !kept || len(ops.keeps[0]) != 1 {
		t.Fatalf("sweep keeps %v, want only the live assignment", ops.keeps[0])
	}

	// No managed network with IPv6: nothing to sweep, the ops are not called.
	if err := sweeper.SweepStaleRoutes(nil, items); err != nil || len(ops.scopes) != 1 {
		t.Fatalf("sweep without managed networks: err=%v calls=%d", err, len(ops.scopes))
	}
}
