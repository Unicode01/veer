package app

import (
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeIPv6AssignmentNetOps struct {
	forwardingCalls      int
	forwardingInterfaces []string
	forwardingErrors     map[string]error
	acceptRAInterfaces   []string
	acceptRAErrors       map[string]error
	proxyNDPEnable       []string
	ensureRoutes         []ipv6AssignmentRouteSpec
	deleteRoutes         []ipv6AssignmentRouteSpec
	ensureProxies        []ipv6AssignmentProxySpec
	deleteProxies        []ipv6AssignmentProxySpec
	ensureRAs            []ipv6AssignmentRAConfig
	ensureRAErrors       map[string]error
	deleteRAs            []string
	ensureDHCPv6         []ipv6AssignmentDHCPv6Config
	ensureDHCPv6Errors   map[string]error
	deleteDHCPv6         []string
	preserveOnClose      bool
	counters             map[string]ipv6AssignmentRuntimeCounter
}

type fakeIPv6AssignmentRuntime struct {
	reconcileCalls int
	lastItems      []IPv6Assignment
	reconcileErr   error
	closeCalls     int
	stats          map[int64]ipv6AssignmentRuntimeStats
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6ForwardingEnabled() error {
	ops.forwardingCalls++
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6ForwardingEnabledOnInterface(interfaceName string) error {
	ops.forwardingInterfaces = append(ops.forwardingInterfaces, interfaceName)
	if err := ops.forwardingErrors[interfaceName]; err != nil {
		return err
	}
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6AcceptRAEnabled(interfaceName string) error {
	ops.acceptRAInterfaces = append(ops.acceptRAInterfaces, interfaceName)
	if err := ops.acceptRAErrors[interfaceName]; err != nil {
		return err
	}
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6ProxyNDPEnabled(parentInterface string) error {
	ops.proxyNDPEnable = append(ops.proxyNDPEnable, parentInterface)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6Route(spec ipv6AssignmentRouteSpec) error {
	ops.ensureRoutes = append(ops.ensureRoutes, spec)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) DeleteIPv6Route(spec ipv6AssignmentRouteSpec) error {
	ops.deleteRoutes = append(ops.deleteRoutes, spec)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6Proxy(spec ipv6AssignmentProxySpec) error {
	ops.ensureProxies = append(ops.ensureProxies, spec)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) DeleteIPv6Proxy(spec ipv6AssignmentProxySpec) error {
	ops.deleteProxies = append(ops.deleteProxies, spec)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6RA(config ipv6AssignmentRAConfig) error {
	ops.ensureRAs = append(ops.ensureRAs, config)
	if err := ops.ensureRAErrors[config.TargetInterface]; err != nil {
		return err
	}
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) DeleteIPv6RA(targetInterface string) error {
	ops.deleteRAs = append(ops.deleteRAs, targetInterface)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) EnsureIPv6DHCPv6(config ipv6AssignmentDHCPv6Config) error {
	ops.ensureDHCPv6 = append(ops.ensureDHCPv6, config)
	if err := ops.ensureDHCPv6Errors[config.TargetInterface]; err != nil {
		return err
	}
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) DeleteIPv6DHCPv6(targetInterface string) error {
	ops.deleteDHCPv6 = append(ops.deleteDHCPv6, targetInterface)
	return nil
}

func (ops *fakeIPv6AssignmentNetOps) SnapshotIPv6AssignmentCounters() map[string]ipv6AssignmentRuntimeCounter {
	if len(ops.counters) == 0 {
		return nil
	}
	out := make(map[string]ipv6AssignmentRuntimeCounter, len(ops.counters))
	for targetInterface, counter := range ops.counters {
		out[targetInterface] = counter
	}
	return out
}

func (ops *fakeIPv6AssignmentNetOps) PreserveIPv6AssignmentStateOnClose() bool {
	return ops.preserveOnClose
}

func (rt *fakeIPv6AssignmentRuntime) Reconcile(items []IPv6Assignment) error {
	rt.reconcileCalls++
	rt.lastItems = append([]IPv6Assignment(nil), items...)
	return rt.reconcileErr
}

func (rt *fakeIPv6AssignmentRuntime) Close() error {
	rt.closeCalls++
	return nil
}

func (rt *fakeIPv6AssignmentRuntime) SnapshotStats() map[int64]ipv6AssignmentRuntimeStats {
	if len(rt.stats) == 0 {
		return nil
	}
	out := make(map[int64]ipv6AssignmentRuntimeStats, len(rt.stats))
	for id, stat := range rt.stats {
		out[id] = stat
	}
	return out
}

func TestBuildIPv6AssignmentRuntimePlanSingleAddressUsesProxyNDP(t *testing.T) {
	t.Parallel()

	plan, err := buildIPv6AssignmentRuntimePlan(IPv6Assignment{
		ID:              1,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2402:db8::/64",
		AssignedPrefix:  "2402:db8::10/128",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("buildIPv6AssignmentRuntimePlan() error = %v", err)
	}
	if !plan.NeedsForwarding {
		t.Fatal("NeedsForwarding = false, want true")
	}
	if !plan.NeedsProxyNDP {
		t.Fatal("NeedsProxyNDP = false, want true for /128")
	}
	if plan.NeedsRADvertise {
		t.Fatal("NeedsRADvertise = true, want false for /128")
	}
	if plan.ProxyAddress != "2402:db8::10" {
		t.Fatalf("ProxyAddress = %q, want %q", plan.ProxyAddress, "2402:db8::10")
	}
	if plan.Intent.kind != ipv6AssignmentIntentSingleAddress {
		t.Fatalf("intent.kind = %q, want %q", plan.Intent.kind, ipv6AssignmentIntentSingleAddress)
	}
}

func TestBuildIPv6AssignmentRuntimePlanDelegatedPrefixUsesRouteOnly(t *testing.T) {
	t.Parallel()

	plan, err := buildIPv6AssignmentRuntimePlan(IPv6Assignment{
		ID:              2,
		ParentInterface: "vmbr0",
		TargetInterface: "tap101i0",
		ParentPrefix:    "2402:db8:100::/48",
		AssignedPrefix:  "2402:db8:100:1::/64",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("buildIPv6AssignmentRuntimePlan() error = %v", err)
	}
	if !plan.NeedsForwarding {
		t.Fatal("NeedsForwarding = false, want true")
	}
	if plan.NeedsProxyNDP {
		t.Fatal("NeedsProxyNDP = true, want false for delegated prefix")
	}
	if !plan.NeedsRADvertise {
		t.Fatal("NeedsRADvertise = false, want true for /64 delegated prefix")
	}
	if plan.Intent.kind != ipv6AssignmentIntentDelegatedPrefix {
		t.Fatalf("intent.kind = %q, want %q", plan.Intent.kind, ipv6AssignmentIntentDelegatedPrefix)
	}
	if plan.Intent.addressing != ipv6AssignmentAddressingSLAACRecommended {
		t.Fatalf("intent.addressing = %q, want %q", plan.Intent.addressing, ipv6AssignmentAddressingSLAACRecommended)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcileCleansUpRemovedState(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{}
	rt := newManagedIPv6AssignmentRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() = nil")
	}

	items := []IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2402:db8::/64",
			AssignedPrefix:  "2402:db8::10/128",
			Enabled:         true,
		},
	}
	if err := rt.Reconcile(items); err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	if ops.forwardingCalls != 1 {
		t.Fatalf("forwardingCalls = %d, want 1", ops.forwardingCalls)
	}
	if len(ops.ensureRoutes) != 1 || ops.ensureRoutes[0].Prefix != "2402:db8::10/128" {
		t.Fatalf("ensureRoutes = %+v, want route for 2402:db8::10/128", ops.ensureRoutes)
	}
	if len(ops.ensureProxies) != 1 || ops.ensureProxies[0].Address != "2402:db8::10" {
		t.Fatalf("ensureProxies = %+v, want proxy for 2402:db8::10", ops.ensureProxies)
	}
	if len(ops.ensureRAs) != 1 || !ops.ensureRAs[0].Managed || ops.ensureRAs[0].TargetInterface != "tap100i0" {
		t.Fatalf("ensureRAs = %+v, want managed RA on tap100i0", ops.ensureRAs)
	}
	if len(ops.forwardingInterfaces) != 2 {
		t.Fatalf("forwardingInterfaces = %+v, want vmbr0 and tap100i0", ops.forwardingInterfaces)
	}
	if len(ops.acceptRAInterfaces) != 1 || ops.acceptRAInterfaces[0] != "vmbr0" {
		t.Fatalf("acceptRAInterfaces = %+v, want vmbr0", ops.acceptRAInterfaces)
	}
	if len(ops.ensureRAs[0].Routes) != 1 || ops.ensureRAs[0].Routes[0] != "2402:db8::/64" {
		t.Fatalf("ensureRAs = %+v, want route 2402:db8::/64 for tap100i0", ops.ensureRAs)
	}
	if len(ops.ensureDHCPv6) != 1 || ops.ensureDHCPv6[0].TargetInterface != "tap100i0" || len(ops.ensureDHCPv6[0].Addresses) != 1 || ops.ensureDHCPv6[0].Addresses[0] != "2402:db8::10" {
		t.Fatalf("ensureDHCPv6 = %+v, want DHCPv6 for 2402:db8::10 on tap100i0", ops.ensureDHCPv6)
	}

	ops.ensureRoutes = nil
	ops.ensureProxies = nil
	ops.ensureRAs = nil
	ops.ensureDHCPv6 = nil
	if err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              2,
			ParentInterface: "vmbr0",
			TargetInterface: "tap101i0",
			ParentPrefix:    "2402:db8:100::/48",
			AssignedPrefix:  "2402:db8:100:1::/64",
			Enabled:         true,
		},
	}); err != nil {
		t.Fatalf("second Reconcile() error = %v", err)
	}
	if len(ops.ensureRoutes) != 1 || ops.ensureRoutes[0].Prefix != "2402:db8:100:1::/64" {
		t.Fatalf("ensureRoutes = %+v, want route for 2402:db8:100:1::/64", ops.ensureRoutes)
	}
	if len(ops.ensureRAs) != 1 || ops.ensureRAs[0].TargetInterface != "tap101i0" {
		t.Fatalf("ensureRAs = %+v, want RA for tap101i0", ops.ensureRAs)
	}
	if len(ops.ensureRAs[0].Prefixes) != 1 || ops.ensureRAs[0].Prefixes[0] != "2402:db8:100:1::/64" {
		t.Fatalf("ensureRAs = %+v, want prefix 2402:db8:100:1::/64", ops.ensureRAs)
	}
	if len(ops.ensureDHCPv6) != 0 {
		t.Fatalf("ensureDHCPv6 = %+v, want no DHCPv6 for delegated /64", ops.ensureDHCPv6)
	}
	if len(ops.ensureProxies) != 0 {
		t.Fatalf("ensureProxies = %+v, want none for delegated prefix", ops.ensureProxies)
	}
	if len(ops.deleteRoutes) != 1 || ops.deleteRoutes[0].Prefix != "2402:db8::10/128" {
		t.Fatalf("deleteRoutes = %+v, want cleanup for old /128 route", ops.deleteRoutes)
	}
	if len(ops.deleteProxies) != 1 || ops.deleteProxies[0].Address != "2402:db8::10" {
		t.Fatalf("deleteProxies = %+v, want cleanup for old proxy", ops.deleteProxies)
	}
	if len(ops.deleteRAs) != 1 || ops.deleteRAs[0] != "tap100i0" {
		t.Fatalf("deleteRAs = %+v, want cleanup for previous RA state on tap100i0", ops.deleteRAs)
	}
	if len(ops.deleteDHCPv6) != 1 || ops.deleteDHCPv6[0] != "tap100i0" {
		t.Fatalf("deleteDHCPv6 = %+v, want cleanup for previous DHCPv6 state on tap100i0", ops.deleteDHCPv6)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcileFollowsCurrentParentPrefix(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForTests
	loadHostNetworkInterfacesForTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{
						Family:    ipFamilyIPv6,
						IP:        "2402:db8:200::1",
						CIDR:      "2402:db8:200::/64",
						PrefixLen: 64,
					},
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{}
	rt := newManagedIPv6AssignmentRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() = nil")
	}

	err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2402:db8:100::/64",
			AssignedPrefix:  "2402:db8:100::1234/128",
			Enabled:         true,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(ops.ensureRoutes) != 1 || ops.ensureRoutes[0].Prefix != "2402:db8:200::1234/128" {
		t.Fatalf("ensureRoutes = %+v, want rebased route for 2402:db8:200::1234/128", ops.ensureRoutes)
	}
	if len(ops.ensureProxies) != 1 || ops.ensureProxies[0].Address != "2402:db8:200::1234" {
		t.Fatalf("ensureProxies = %+v, want rebased proxy for 2402:db8:200::1234", ops.ensureProxies)
	}
	if len(ops.ensureRAs) != 1 || len(ops.ensureRAs[0].Routes) != 1 || ops.ensureRAs[0].Routes[0] != "2402:db8:200::/64" {
		t.Fatalf("ensureRAs = %+v, want rebased parent route 2402:db8:200::/64", ops.ensureRAs)
	}
	if len(ops.ensureDHCPv6) != 1 || len(ops.ensureDHCPv6[0].Addresses) != 1 || ops.ensureDHCPv6[0].Addresses[0] != "2402:db8:200::1234" {
		t.Fatalf("ensureDHCPv6 = %+v, want rebased address 2402:db8:200::1234", ops.ensureDHCPv6)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcilePrefersSameParentPrefixClass(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForTests
	loadHostNetworkInterfacesForTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "eno1",
				Addresses: []HostInterfaceAddress{
					{
						Family:    ipFamilyIPv6,
						IP:        "240e:390:6cee:f541::1",
						CIDR:      "240e:390:6cee:f541::/64",
						PrefixLen: 64,
					},
					{
						Family:    ipFamilyIPv6,
						IP:        "fd7b:90b5:394d:1::1",
						CIDR:      "fd7b:90b5:394d:1::/64",
						PrefixLen: 64,
					},
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{}
	rt := newManagedIPv6AssignmentRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() = nil")
	}

	err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "eno1",
			TargetInterface: "tap100i0",
			ParentPrefix:    "240e:390:6cee:f540::/64",
			AssignedPrefix:  "240e:390:6cee:f540::48f/128",
			Enabled:         true,
		},
	})
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(ops.ensureRoutes) != 1 || ops.ensureRoutes[0].Prefix != "240e:390:6cee:f541::48f/128" {
		t.Fatalf("ensureRoutes = %+v, want rebased public route for 240e:390:6cee:f541::48f/128", ops.ensureRoutes)
	}
	if len(ops.ensureProxies) != 1 || ops.ensureProxies[0].Address != "240e:390:6cee:f541::48f" {
		t.Fatalf("ensureProxies = %+v, want rebased public proxy for 240e:390:6cee:f541::48f", ops.ensureProxies)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcileRejectsAmbiguousCurrentParentPrefix(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForTests
	loadHostNetworkInterfacesForTests = func() ([]HostNetworkInterface, error) {
		return []HostNetworkInterface{
			{
				Name: "vmbr0",
				Addresses: []HostInterfaceAddress{
					{
						Family:    ipFamilyIPv6,
						IP:        "2402:db8:200::1",
						CIDR:      "2402:db8:200::/64",
						PrefixLen: 64,
					},
					{
						Family:    ipFamilyIPv6,
						IP:        "2402:db8:300::1",
						CIDR:      "2402:db8:300::/64",
						PrefixLen: 64,
					},
				},
			},
		}, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{}
	rt := newManagedIPv6AssignmentRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() = nil")
	}

	err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2402:db8:100::/64",
			AssignedPrefix:  "2402:db8:100::1234/128",
			Enabled:         true,
		},
	})
	if err == nil {
		t.Fatal("Reconcile() error = nil, want ambiguous current parent prefix error")
	}
	if !strings.Contains(err.Error(), "multiple current matching IPv6 /64 prefixes exist") {
		t.Fatalf("Reconcile() error = %v, want ambiguous current prefix detail", err)
	}
	if len(ops.ensureRoutes) != 0 || len(ops.ensureProxies) != 0 || len(ops.ensureRAs) != 0 || len(ops.ensureDHCPv6) != 0 {
		t.Fatalf("runtime applied state despite ambiguous parent prefix: routes=%+v proxies=%+v ra=%+v dhcp=%+v", ops.ensureRoutes, ops.ensureProxies, ops.ensureRAs, ops.ensureDHCPv6)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcileScopesTargetRuntimeErrors(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{
		ensureRAErrors: map[string]error{
			"tap100i0": errors.New("ra failed"),
		},
		counters: map[string]ipv6AssignmentRuntimeCounter{
			"tap100i0": {
				RAStatus:     "running",
				DHCPv6Status: "running",
			},
			"tap200i0": {
				RAStatus: "running",
			},
		},
	}
	rt, ok := newManagedIPv6AssignmentRuntime(ops).(*managedIPv6AssignmentRuntime)
	if !ok || rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() did not return managed runtime")
	}

	err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2402:db8::/64",
			AssignedPrefix:  "2402:db8::10/128",
			Enabled:         true,
		},
		{
			ID:              2,
			ParentInterface: "vmbr1",
			TargetInterface: "tap200i0",
			ParentPrefix:    "2402:db8:1::/48",
			AssignedPrefix:  "2402:db8:1:1::/64",
			Enabled:         true,
		},
	})
	if err == nil {
		t.Fatal("Reconcile() error = nil, want target-specific RA failure")
	}
	if !strings.Contains(err.Error(), "advertise ipv6 on tap100i0") {
		t.Fatalf("Reconcile() error = %v, want tap100i0 RA failure detail", err)
	}

	stats := rt.SnapshotStats()
	if stats[1].RuntimeStatus != "error" {
		t.Fatalf("stats[1] = %+v, want error for tap100i0 assignment", stats[1])
	}
	if !strings.Contains(stats[1].RuntimeDetail, "advertise ipv6 on tap100i0") {
		t.Fatalf("stats[1].RuntimeDetail = %q, want tap100i0 failure detail", stats[1].RuntimeDetail)
	}
	if stats[2].RuntimeStatus != "running" {
		t.Fatalf("stats[2] = %+v, want running for unrelated tap200i0 assignment", stats[2])
	}
	if strings.Contains(stats[2].RuntimeDetail, "tap100i0") {
		t.Fatalf("stats[2].RuntimeDetail = %q, want no unrelated tap100i0 failure detail", stats[2].RuntimeDetail)
	}
}

func TestManagedIPv6AssignmentRuntimeReconcileScopesParentInterfaceErrors(t *testing.T) {
	oldLoad := loadHostNetworkInterfacesForIPv6AssignmentTests
	loadHostNetworkInterfacesForIPv6AssignmentTests = func() ([]HostNetworkInterface, error) {
		return nil, nil
	}
	t.Cleanup(func() {
		loadHostNetworkInterfacesForIPv6AssignmentTests = oldLoad
	})

	ops := &fakeIPv6AssignmentNetOps{
		acceptRAErrors: map[string]error{
			"vmbr0": errors.New("accept_ra failed"),
		},
		counters: map[string]ipv6AssignmentRuntimeCounter{
			"tap100i0": {
				RAStatus:     "running",
				DHCPv6Status: "running",
			},
			"tap200i0": {
				RAStatus:     "running",
				DHCPv6Status: "running",
			},
		},
	}
	rt, ok := newManagedIPv6AssignmentRuntime(ops).(*managedIPv6AssignmentRuntime)
	if !ok || rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() did not return managed runtime")
	}

	err := rt.Reconcile([]IPv6Assignment{
		{
			ID:              1,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2402:db8::/64",
			AssignedPrefix:  "2402:db8::10/128",
			Enabled:         true,
		},
		{
			ID:              2,
			ParentInterface: "vmbr1",
			TargetInterface: "tap200i0",
			ParentPrefix:    "2402:db8:1::/64",
			AssignedPrefix:  "2402:db8:1::20/128",
			Enabled:         true,
		},
	})
	if err == nil {
		t.Fatal("Reconcile() error = nil, want parent-specific accept_ra failure")
	}
	if !strings.Contains(err.Error(), "enable ipv6 accept_ra on vmbr0") {
		t.Fatalf("Reconcile() error = %v, want vmbr0 accept_ra failure detail", err)
	}

	stats := rt.SnapshotStats()
	if stats[1].RuntimeStatus != "error" {
		t.Fatalf("stats[1] = %+v, want error for vmbr0-backed assignment", stats[1])
	}
	if !strings.Contains(stats[1].RuntimeDetail, "enable ipv6 accept_ra on vmbr0") {
		t.Fatalf("stats[1].RuntimeDetail = %q, want vmbr0 failure detail", stats[1].RuntimeDetail)
	}
	if stats[2].RuntimeStatus != "running" {
		t.Fatalf("stats[2] = %+v, want running for vmbr1-backed assignment", stats[2])
	}
	if strings.Contains(stats[2].RuntimeDetail, "vmbr0") {
		t.Fatalf("stats[2].RuntimeDetail = %q, want no unrelated vmbr0 failure detail", stats[2].RuntimeDetail)
	}
}

func TestManagedIPv6AssignmentRuntimeCloseRemovesAppliedState(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6AssignmentNetOps{}
	rt, ok := newManagedIPv6AssignmentRuntime(ops).(*managedIPv6AssignmentRuntime)
	if !ok || rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() did not return managed runtime")
	}
	rt.routes[ipv6AssignmentRouteSpec{Prefix: "2402:db8::10/128", TargetInterface: "tap100i0"}] = struct{}{}
	rt.proxies[ipv6AssignmentProxySpec{ParentInterface: "vmbr0", Address: "2402:db8::10"}] = struct{}{}
	rt.advertisements["tap100i0"] = ipv6AssignmentRAConfig{TargetInterface: "tap100i0", Routes: []string{"2402:db8::/64"}}
	rt.dhcpv6["tap100i0"] = ipv6AssignmentDHCPv6Config{TargetInterface: "tap100i0", Addresses: []string{"2402:db8::10"}}

	if err := rt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(ops.deleteRoutes) != 1 || ops.deleteRoutes[0].Prefix != "2402:db8::10/128" {
		t.Fatalf("deleteRoutes = %+v, want cleanup for applied route", ops.deleteRoutes)
	}
	if len(ops.deleteProxies) != 1 || ops.deleteProxies[0].Address != "2402:db8::10" {
		t.Fatalf("deleteProxies = %+v, want cleanup for applied proxy", ops.deleteProxies)
	}
	if len(ops.deleteRAs) != 1 || ops.deleteRAs[0] != "tap100i0" {
		t.Fatalf("deleteRAs = %+v, want cleanup for applied RA", ops.deleteRAs)
	}
	if len(ops.deleteDHCPv6) != 1 || ops.deleteDHCPv6[0] != "tap100i0" {
		t.Fatalf("deleteDHCPv6 = %+v, want cleanup for applied DHCPv6", ops.deleteDHCPv6)
	}
}

func TestManagedIPv6AssignmentRuntimeClosePreservesAppliedStateOnHotRestart(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6AssignmentNetOps{preserveOnClose: true}
	rt, ok := newManagedIPv6AssignmentRuntime(ops).(*managedIPv6AssignmentRuntime)
	if !ok || rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() did not return managed runtime")
	}
	rt.routes[ipv6AssignmentRouteSpec{Prefix: "2402:db8::10/128", TargetInterface: "tap100i0"}] = struct{}{}
	rt.proxies[ipv6AssignmentProxySpec{ParentInterface: "vmbr0", Address: "2402:db8::10"}] = struct{}{}
	rt.advertisements["tap100i0"] = ipv6AssignmentRAConfig{TargetInterface: "tap100i0", Routes: []string{"2402:db8::/64"}}
	rt.dhcpv6["tap100i0"] = ipv6AssignmentDHCPv6Config{TargetInterface: "tap100i0", Addresses: []string{"2402:db8::10"}}

	if err := rt.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if len(ops.deleteRoutes) != 0 {
		t.Fatalf("deleteRoutes = %+v, want none while preserving hot restart state", ops.deleteRoutes)
	}
	if len(ops.deleteProxies) != 0 {
		t.Fatalf("deleteProxies = %+v, want none while preserving hot restart state", ops.deleteProxies)
	}
	if len(ops.deleteRAs) != 0 {
		t.Fatalf("deleteRAs = %+v, want none while preserving hot restart state", ops.deleteRAs)
	}
	if len(ops.deleteDHCPv6) != 0 {
		t.Fatalf("deleteDHCPv6 = %+v, want none while preserving hot restart state", ops.deleteDHCPv6)
	}
	if len(rt.routes) != 0 || len(rt.proxies) != 0 || len(rt.advertisements) != 0 || len(rt.dhcpv6) != 0 {
		t.Fatalf("runtime state not cleared after preserve close: routes=%d proxies=%d ra=%d dhcp=%d", len(rt.routes), len(rt.proxies), len(rt.advertisements), len(rt.dhcpv6))
	}
}

func TestManagedIPv6AssignmentRuntimeSnapshotStatsMapsInterfaceCountersToAssignments(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6AssignmentNetOps{
		counters: map[string]ipv6AssignmentRuntimeCounter{
			"tap100i0": {
				RAAdvertisementCount: 9,
				DHCPv6ReplyCount:     4,
			},
			"tap200i0": {
				RAAdvertisementCount: 3,
			},
		},
	}
	rt, ok := newManagedIPv6AssignmentRuntime(ops).(*managedIPv6AssignmentRuntime)
	if !ok || rt == nil {
		t.Fatal("newManagedIPv6AssignmentRuntime() did not return managed runtime")
	}
	rt.assignmentStates = map[int64]ipv6AssignmentRuntimeEntryState{
		1: {
			TargetInterface: "tap100i0",
			AdvertisesRA:    true,
			ServesDHCPv6:    true,
		},
		2: {
			TargetInterface: "tap100i0",
			AdvertisesRA:    true,
		},
		3: {
			TargetInterface: "tap200i0",
		},
	}

	stats := rt.SnapshotStats()
	if stats[1].RAAdvertisementCount != 9 || stats[1].DHCPv6ReplyCount != 4 {
		t.Fatalf("stats[1] = %+v, want RA=9 DHCPv6=4", stats[1])
	}
	if stats[2].RAAdvertisementCount != 9 || stats[2].DHCPv6ReplyCount != 0 {
		t.Fatalf("stats[2] = %+v, want RA=9 DHCPv6=0", stats[2])
	}
	if stats[3].RAAdvertisementCount != 0 || stats[3].DHCPv6ReplyCount != 0 {
		t.Fatalf("stats[3] = %+v, want zero counters for route-only assignment", stats[3])
	}
}

func TestCollectIPv6AssignmentInterfaceNamesIgnoresDisabledAssignments(t *testing.T) {
	t.Parallel()

	names, count := collectIPv6AssignmentInterfaceNames([]IPv6Assignment{
		{
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			Enabled:         true,
		},
		{
			ParentInterface: "vmbr1",
			TargetInterface: "tap101i0",
			Enabled:         false,
		},
	})
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	if _, ok := names["vmbr0"]; !ok {
		t.Fatalf("names = %+v, want vmbr0", names)
	}
	if _, ok := names["tap100i0"]; !ok {
		t.Fatalf("names = %+v, want tap100i0", names)
	}
	if _, ok := names["vmbr1"]; ok {
		t.Fatalf("names = %+v, disabled interface vmbr1 should be absent", names)
	}
}

func TestProcessManagerShouldRedistributeIPv6AssignmentsForInterface(t *testing.T) {
	t.Parallel()

	pm := &ProcessManager{
		ipv6AssignmentsConfigured: true,
		ipv6AssignmentInterfaces: map[string]struct{}{
			"vmbr0":    {},
			"tap100i0": {},
		},
	}
	if !pm.shouldRedistributeIPv6AssignmentsForInterface("vmbr0") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(vmbr0) = false, want true")
	}
	if pm.shouldRedistributeIPv6AssignmentsForInterface("eno1") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(eno1) = true, want false")
	}
	if !pm.shouldRedistributeIPv6AssignmentsForInterface("fwpr100p0") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(fwpr100p0) = false, want true for dynamic guest link")
	}
	if !pm.shouldRedistributeIPv6AssignmentsForInterface("fwln100i0") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(fwln100i0) = false, want true for dynamic guest link")
	}
	if !pm.shouldRedistributeIPv6AssignmentsForInterface("tap200i0") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(tap200i0) = false, want true for dynamic guest link")
	}
	if !pm.shouldRedistributeIPv6AssignmentsForInterface("") {
		t.Fatal("shouldRedistributeIPv6AssignmentsForInterface(\"\") = false, want true when interface name is unavailable")
	}
}

func TestRedistributeWorkersReconcilesIPv6Assignments(t *testing.T) {
	db := openTestDB(t)

	if _, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ID:              0,
		ParentInterface: "vmbr0",
		TargetInterface: "tap100i0",
		ParentPrefix:    "2402:db8::/64",
		AssignedPrefix:  "2402:db8::10/128",
		Enabled:         true,
	}); err != nil {
		t.Fatalf("seed enabled assignment: %v", err)
	}
	if _, err := dbAddIPv6Assignment(db, &IPv6Assignment{
		ID:              0,
		ParentInterface: "vmbr1",
		TargetInterface: "tap101i0",
		ParentPrefix:    "2402:db8:1::/64",
		AssignedPrefix:  "2402:db8:1::20/128",
		Enabled:         false,
	}); err != nil {
		t.Fatalf("seed disabled assignment: %v", err)
	}

	fakeRuntime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		db:                                   db,
		cfg:                                  &Config{DefaultEngine: "auto"},
		rulePlans:                            make(map[int64]ruleDataplanePlan),
		rangePlans:                           make(map[int64]rangeDataplanePlan),
		egressNATPlans:                       make(map[int64]ruleDataplanePlan),
		dynamicEgressNATParents:              make(map[string]struct{}),
		ipv6Runtime:                          fakeRuntime,
		ipv6AssignmentInterfaces:             make(map[string]struct{}),
		kernelRules:                          make(map[int64]bool),
		kernelRanges:                         make(map[int64]bool),
		kernelEgressNATs:                     make(map[int64]bool),
		kernelRuleEngines:                    make(map[int64]string),
		kernelRangeEngines:                   make(map[int64]string),
		kernelEgressNATEngines:               make(map[int64]string),
		kernelFlowOwners:                     make(map[uint32]kernelCandidateOwner),
		kernelRuleStats:                      make(map[int64]RuleStatsReport),
		kernelRangeStats:                     make(map[int64]RangeStatsReport),
		kernelEgressNATStats:                 make(map[int64]EgressNATStatsReport),
		kernelNetlinkOwnerRetryCooldownUntil: make(map[kernelCandidateOwner]kernelNetlinkOwnerRetryCooldownState),
		kernelNetlinkOwnerRetryFailures:      make(map[kernelCandidateOwner]int),
		lastRulePlanLog:                      make(map[int64]string),
		lastRangePlanLog:                     make(map[int64]string),
	}

	pm.redistributeWorkers()

	if fakeRuntime.reconcileCalls != 1 {
		t.Fatalf("reconcileCalls = %d, want 1", fakeRuntime.reconcileCalls)
	}
	if len(fakeRuntime.lastItems) != 2 {
		t.Fatalf("lastItems = %+v, want 2 assignments", fakeRuntime.lastItems)
	}
	if !pm.ipv6AssignmentsConfigured {
		t.Fatal("ipv6AssignmentsConfigured = false, want true")
	}
	if _, ok := pm.ipv6AssignmentInterfaces["vmbr0"]; !ok {
		t.Fatalf("ipv6AssignmentInterfaces = %+v, want vmbr0", pm.ipv6AssignmentInterfaces)
	}
	if _, ok := pm.ipv6AssignmentInterfaces["tap100i0"]; !ok {
		t.Fatalf("ipv6AssignmentInterfaces = %+v, want tap100i0", pm.ipv6AssignmentInterfaces)
	}
	if _, ok := pm.ipv6AssignmentInterfaces["vmbr1"]; ok {
		t.Fatalf("ipv6AssignmentInterfaces = %+v, disabled vmbr1 should be absent", pm.ipv6AssignmentInterfaces)
	}
}

func TestStopAllClosesIPv6AssignmentRuntime(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	fakeRuntime := &fakeIPv6AssignmentRuntime{}
	pm := &ProcessManager{
		listener:    listener,
		ipv6Runtime: fakeRuntime,
	}

	pm.stopAll()
	if fakeRuntime.closeCalls != 1 {
		t.Fatalf("closeCalls = %d, want 1", fakeRuntime.closeCalls)
	}
}
