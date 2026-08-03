package netservice

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeIPv6RuntimeOps struct {
	forwardingCalls      int
	forwardingInterfaces []string
	acceptRAInterfaces   []string
	proxyNDPInterfaces   []string
	ensureRoutes         []IPv6RouteSpec
	deleteRoutes         []IPv6RouteSpec
	ensureAddresses      []IPv6AddressSpec
	deleteAddresses      []IPv6AddressSpec
	ensureRejectRoutes   []IPv6RejectRouteSpec
	deleteRejectRoutes   []IPv6RejectRouteSpec
	ensureProxies        []IPv6ProxySpec
	deleteProxies        []IPv6ProxySpec
	ensureRAs            []RAConfig
	deleteRAs            []string
	ensureDHCPv6         []DHCPv6Config
	deleteDHCPv6         []string
	acceptRAErrors       map[string]error
	ensureRAErrors       map[string]error
	counters             map[string]IPv6RuntimeCounter
	deleteErr            error
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6ForwardingEnabled() error {
	ops.forwardingCalls++
	return nil
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6ForwardingEnabledOnInterface(name string) error {
	ops.forwardingInterfaces = append(ops.forwardingInterfaces, name)
	return nil
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6AcceptRAEnabled(name string) error {
	ops.acceptRAInterfaces = append(ops.acceptRAInterfaces, name)
	return ops.acceptRAErrors[name]
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6ProxyNDPEnabled(name string) error {
	ops.proxyNDPInterfaces = append(ops.proxyNDPInterfaces, name)
	return nil
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6Route(spec IPv6RouteSpec) error {
	ops.ensureRoutes = append(ops.ensureRoutes, spec)
	return nil
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6Route(spec IPv6RouteSpec) error {
	ops.deleteRoutes = append(ops.deleteRoutes, spec)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6Address(spec IPv6AddressSpec) error {
	ops.ensureAddresses = append(ops.ensureAddresses, spec)
	return nil
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6Address(spec IPv6AddressSpec) error {
	ops.deleteAddresses = append(ops.deleteAddresses, spec)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6RejectRoute(spec IPv6RejectRouteSpec) error {
	ops.ensureRejectRoutes = append(ops.ensureRejectRoutes, spec)
	return nil
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6RejectRoute(spec IPv6RejectRouteSpec) error {
	ops.deleteRejectRoutes = append(ops.deleteRejectRoutes, spec)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6Proxy(spec IPv6ProxySpec) error {
	ops.ensureProxies = append(ops.ensureProxies, spec)
	return nil
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6Proxy(spec IPv6ProxySpec) error {
	ops.deleteProxies = append(ops.deleteProxies, spec)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6RA(config RAConfig) error {
	ops.ensureRAs = append(ops.ensureRAs, config)
	return ops.ensureRAErrors[config.TargetInterface]
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6RA(name string) error {
	ops.deleteRAs = append(ops.deleteRAs, name)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) EnsureIPv6DHCPv6(config DHCPv6Config) error {
	ops.ensureDHCPv6 = append(ops.ensureDHCPv6, config)
	return nil
}

func (ops *fakeIPv6RuntimeOps) DeleteIPv6DHCPv6(name string) error {
	ops.deleteDHCPv6 = append(ops.deleteDHCPv6, name)
	return ops.deleteErr
}

func (ops *fakeIPv6RuntimeOps) SnapshotIPv6AssignmentCounters() map[string]IPv6RuntimeCounter {
	return ops.counters
}

func testIPv6RuntimePlans() []IPv6AssignmentPlan {
	return []IPv6AssignmentPlan{
		{
			ID:              1,
			ParentInterface: "wan0",
			TargetInterface: "lan0",
			ParentPrefix:    "2001:db8::/64",
			AssignedPrefix:  "2001:db8::10/128",
			AssignedAddress: "2001:db8::10",
			ProxyAddress:    "2001:db8::10",
			GatewayCIDR:     "2001:db8::1/64",
			RejectPrefix:    "2001:db8::/65",
			DNSServers:      []string{"2001:4860:4860::8888", "2001:4860:4860::8888"},
			NeedsForwarding: true,
			NeedsProxyNDP:   true,
			IsSingleAddress: true,
		},
		{
			ID:              2,
			ParentInterface: "wan0",
			TargetInterface: "lan0",
			ParentPrefix:    "2001:db8::/48",
			AssignedPrefix:  "2001:db8:0:1::/64",
			DNSServers:      []string{"2001:4860:4860::8844"},
			NeedsForwarding: true,
			NeedsRA:         true,
		},
	}
}

func TestIPv6AssignmentRuntimeReconcileAndRemoveState(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6RuntimeOps{}
	rt := NewIPv6AssignmentRuntime(ops)
	if err := rt.Reconcile(testIPv6RuntimePlans(), nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if ops.forwardingCalls != 1 {
		t.Fatalf("forwardingCalls = %d, want 1", ops.forwardingCalls)
	}
	if !sameStrings(ops.forwardingInterfaces, []string{"lan0", "wan0"}) {
		t.Fatalf("forwardingInterfaces = %v", ops.forwardingInterfaces)
	}
	if !sameStrings(ops.acceptRAInterfaces, []string{"wan0"}) || !sameStrings(ops.proxyNDPInterfaces, []string{"wan0"}) {
		t.Fatalf("parent setup = accept_ra:%v proxy_ndp:%v", ops.acceptRAInterfaces, ops.proxyNDPInterfaces)
	}
	if len(ops.ensureRoutes) != 2 || len(ops.ensureAddresses) != 1 || len(ops.ensureRejectRoutes) != 1 || len(ops.ensureProxies) != 1 {
		t.Fatalf("L3 state = routes:%v addresses:%v rejects:%v proxies:%v", ops.ensureRoutes, ops.ensureAddresses, ops.ensureRejectRoutes, ops.ensureProxies)
	}
	if len(ops.ensureRAs) != 1 {
		t.Fatalf("ensureRAs = %v, want one merged config", ops.ensureRAs)
	}
	ra := ops.ensureRAs[0]
	if !ra.Managed || !slices.Equal(ra.Prefixes, []string{"2001:db8:0:1::/64"}) || !slices.Equal(ra.Routes, []string{"2001:db8::/64"}) || !slices.Equal(ra.DNSServers, []string{"2001:4860:4860::8844", "2001:4860:4860::8888"}) {
		t.Fatalf("merged RA = %+v", ra)
	}
	if len(ops.ensureDHCPv6) != 1 || !slices.Equal(ops.ensureDHCPv6[0].Addresses, []string{"2001:db8::10"}) {
		t.Fatalf("ensureDHCPv6 = %+v", ops.ensureDHCPv6)
	}

	if err := rt.Reconcile(nil, nil); err != nil {
		t.Fatalf("Reconcile(empty) error = %v", err)
	}
	if len(ops.deleteRoutes) != 2 || len(ops.deleteAddresses) != 1 || len(ops.deleteRejectRoutes) != 1 || len(ops.deleteProxies) != 1 || !slices.Equal(ops.deleteRAs, []string{"lan0"}) || !slices.Equal(ops.deleteDHCPv6, []string{"lan0"}) {
		t.Fatalf("cleanup = routes:%v addresses:%v rejects:%v proxies:%v ra:%v dhcpv6:%v", ops.deleteRoutes, ops.deleteAddresses, ops.deleteRejectRoutes, ops.deleteProxies, ops.deleteRAs, ops.deleteDHCPv6)
	}
}

func TestIPv6AssignmentRuntimeRetriesFailedDeletes(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6RuntimeOps{}
	rt := NewIPv6AssignmentRuntime(ops)
	if err := rt.Reconcile(testIPv6RuntimePlans(), nil); err != nil {
		t.Fatalf("Reconcile(create) error = %v", err)
	}

	ops.deleteErr = errors.New("temporary delete failure")
	if err := rt.Reconcile(nil, nil); err == nil || !strings.Contains(err.Error(), "temporary delete failure") {
		t.Fatalf("Reconcile(failed delete) error = %v", err)
	}
	assertIPv6DeleteCallCounts(t, ops, 2, 1, 1, 1, 1, 1)

	ops.deleteErr = nil
	if err := rt.Reconcile(nil, nil); err != nil {
		t.Fatalf("Reconcile(retry delete) error = %v", err)
	}
	assertIPv6DeleteCallCounts(t, ops, 4, 2, 2, 2, 2, 2)

	if err := rt.Reconcile(nil, nil); err != nil {
		t.Fatalf("Reconcile(after delete) error = %v", err)
	}
	assertIPv6DeleteCallCounts(t, ops, 4, 2, 2, 2, 2, 2)
}

func assertIPv6DeleteCallCounts(t *testing.T, ops *fakeIPv6RuntimeOps, routes, addresses, rejects, proxies, ras, dhcpv6 int) {
	t.Helper()
	if len(ops.deleteRoutes) != routes || len(ops.deleteAddresses) != addresses || len(ops.deleteRejectRoutes) != rejects || len(ops.deleteProxies) != proxies || len(ops.deleteRAs) != ras || len(ops.deleteDHCPv6) != dhcpv6 {
		t.Fatalf("delete calls = routes:%d addresses:%d rejects:%d proxies:%d ra:%d dhcpv6:%d, want %d/%d/%d/%d/%d/%d", len(ops.deleteRoutes), len(ops.deleteAddresses), len(ops.deleteRejectRoutes), len(ops.deleteProxies), len(ops.deleteRAs), len(ops.deleteDHCPv6), routes, addresses, rejects, proxies, ras, dhcpv6)
	}
}

func TestIPv6AssignmentRuntimeAppliesSyntheticNegativeID(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6RuntimeOps{counters: map[string]IPv6RuntimeCounter{
		"lan0": {RAStatus: "running"},
	}}
	rt := NewIPv6AssignmentRuntime(ops)
	const syntheticID int64 = -42
	if err := rt.Reconcile([]IPv6AssignmentPlan{{
		ID:              syntheticID,
		ParentInterface: "wan0",
		TargetInterface: "lan0",
		ParentPrefix:    "2001:db8::/48",
		AssignedPrefix:  "2001:db8:0:1::/64",
		NeedsForwarding: true,
		NeedsRA:         true,
	}}, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(ops.ensureRoutes) != 1 || ops.ensureRoutes[0].Prefix != "2001:db8:0:1::/64" || len(ops.ensureRAs) != 1 {
		t.Fatalf("synthetic assignment was not applied: routes=%+v ra=%+v", ops.ensureRoutes, ops.ensureRAs)
	}
	if stat, ok := rt.SnapshotStats()[syntheticID]; !ok || stat.RuntimeStatus != "running" {
		t.Fatalf("synthetic assignment stats = %+v, present=%t", stat, ok)
	}
}

func TestIPv6AssignmentRuntimeScopesErrorsAndStats(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6RuntimeOps{
		acceptRAErrors: map[string]error{"wan0": errors.New("accept_ra failed")},
		ensureRAErrors: map[string]error{"lan0": errors.New("ra failed")},
		counters: map[string]IPv6RuntimeCounter{
			"lan0": {RAAdvertisementCount: 7, DHCPv6ReplyCount: 3, RAStatus: "running", DHCPv6Status: "draining", DHCPv6StatusDetail: "stopping"},
			"lan1": {RAAdvertisementCount: 2, RAStatus: "running"},
		},
	}
	plans := append(testIPv6RuntimePlans(), IPv6AssignmentPlan{
		ID:              3,
		ParentInterface: "wan1",
		TargetInterface: "lan1",
		ParentPrefix:    "2001:db8:2::/48",
		AssignedPrefix:  "2001:db8:2:1::/64",
		NeedsForwarding: true,
		NeedsRA:         true,
	})
	rt := NewIPv6AssignmentRuntime(ops)
	err := rt.Reconcile(plans, []IPv6AssignmentPlanIssue{{ID: 4, Summary: "assignment #4 invalid", Detail: "invalid plan"}})
	if err == nil || !strings.Contains(err.Error(), "accept_ra failed") || !strings.Contains(err.Error(), "advertise ipv6 on lan0") || !strings.Contains(err.Error(), "assignment #4 invalid") {
		t.Fatalf("Reconcile() error = %v", err)
	}

	stats := rt.SnapshotStats()
	if stats[1].RuntimeStatus != "error" || stats[1].RAAdvertisementCount != 7 || stats[1].DHCPv6ReplyCount != 3 {
		t.Fatalf("stats[1] = %+v", stats[1])
	}
	if !strings.Contains(stats[1].RuntimeDetail, "accept_ra failed") || !strings.Contains(stats[1].RuntimeDetail, "ra failed") {
		t.Fatalf("stats[1].RuntimeDetail = %q", stats[1].RuntimeDetail)
	}
	if stats[3].RuntimeStatus != "running" || stats[3].RAAdvertisementCount != 2 || strings.Contains(stats[3].RuntimeDetail, "lan0") {
		t.Fatalf("stats[3] = %+v", stats[3])
	}
	if stats[4].RuntimeStatus != "error" || stats[4].RuntimeDetail != "invalid plan" {
		t.Fatalf("stats[4] = %+v", stats[4])
	}
}

func TestIPv6AssignmentRuntimeReportsUnreadyAndRouteOnlyStates(t *testing.T) {
	t.Parallel()

	ops := &fakeIPv6RuntimeOps{counters: map[string]IPv6RuntimeCounter{}}
	rt := NewIPv6AssignmentRuntime(ops)
	if err := rt.Reconcile([]IPv6AssignmentPlan{
		{ID: 1, TargetInterface: "lan0", AssignedPrefix: "2001:db8::/64", NeedsRA: true},
		{ID: 2, TargetInterface: "lan1", AssignedPrefix: "2001:db8:1::/64"},
	}, nil); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	stats := rt.SnapshotStats()
	if stats[1].RuntimeStatus != "draining" {
		t.Fatalf("stats[1] = %+v, want unready advertiser to drain", stats[1])
	}
	if stats[2].RuntimeStatus != "running" || stats[2].RuntimeDetail != "route/proxy only" {
		t.Fatalf("stats[2] = %+v, want route-only state", stats[2])
	}
}

func TestIPv6AssignmentRuntimeCloseHonorsPreserve(t *testing.T) {
	t.Parallel()

	preservedOps := &fakeIPv6RuntimeOps{}
	preserved := NewIPv6AssignmentRuntime(preservedOps)
	if err := preserved.Reconcile(testIPv6RuntimePlans(), nil); err != nil {
		t.Fatalf("Reconcile(preserved) error = %v", err)
	}
	if err := preserved.Close(true); err != nil {
		t.Fatalf("Close(true) error = %v", err)
	}
	if len(preservedOps.deleteRoutes)+len(preservedOps.deleteProxies)+len(preservedOps.deleteRAs)+len(preservedOps.deleteDHCPv6) != 0 {
		t.Fatalf("preserved runtime removed state: %+v", preservedOps)
	}
	if stats := preserved.SnapshotStats(); len(stats) != 0 {
		t.Fatalf("preserved runtime retained bookkeeping: %+v", stats)
	}

	cleanupOps := &fakeIPv6RuntimeOps{}
	cleanup := NewIPv6AssignmentRuntime(cleanupOps)
	if err := cleanup.Reconcile(testIPv6RuntimePlans(), nil); err != nil {
		t.Fatalf("Reconcile(cleanup) error = %v", err)
	}
	if err := cleanup.Close(false); err != nil {
		t.Fatalf("Close(false) error = %v", err)
	}
	if len(cleanupOps.deleteRoutes) != 2 || len(cleanupOps.deleteProxies) != 1 || len(cleanupOps.deleteRAs) != 1 || len(cleanupOps.deleteDHCPv6) != 1 {
		t.Fatalf("cleanup did not remove state: %+v", cleanupOps)
	}
}

func sameStrings(got []string, want []string) bool {
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}
