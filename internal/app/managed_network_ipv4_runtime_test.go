package app

import (
	"strings"
	"testing"
)

type fakeManagedNetworkNetOps struct {
	forwardingCalls      int
	forwardingInterfaces []string
	ensureInterfaces     []managedNetworkInterfaceSpec
	ensureAddresses      []managedNetworkIPv4AddressSpec
	deleteAddresses      []managedNetworkIPv4AddressSpec
	ensureDHCPv4         []managedNetworkDHCPv4Config
	deleteDHCPv4         []string
	snapshotStates       map[string]managedNetworkDHCPv4RuntimeState
}

func (ops *fakeManagedNetworkNetOps) EnsureIPv4ForwardingEnabled() error {
	ops.forwardingCalls++
	return nil
}

func (ops *fakeManagedNetworkNetOps) EnsureIPv4ForwardingEnabledOnInterface(interfaceName string) error {
	ops.forwardingInterfaces = append(ops.forwardingInterfaces, interfaceName)
	return nil
}

func (ops *fakeManagedNetworkNetOps) EnsureManagedNetworkInterface(spec managedNetworkInterfaceSpec) error {
	ops.ensureInterfaces = append(ops.ensureInterfaces, spec)
	return nil
}

func (ops *fakeManagedNetworkNetOps) EnsureManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error {
	ops.ensureAddresses = append(ops.ensureAddresses, spec)
	return nil
}

func (ops *fakeManagedNetworkNetOps) DeleteManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error {
	ops.deleteAddresses = append(ops.deleteAddresses, spec)
	return nil
}

func (ops *fakeManagedNetworkNetOps) EnsureManagedNetworkDHCPv4(config managedNetworkDHCPv4Config) error {
	ops.ensureDHCPv4 = append(ops.ensureDHCPv4, config)
	return nil
}

func (ops *fakeManagedNetworkNetOps) DeleteManagedNetworkDHCPv4(bridge string) error {
	ops.deleteDHCPv4 = append(ops.deleteDHCPv4, bridge)
	return nil
}

func (ops *fakeManagedNetworkNetOps) SnapshotManagedNetworkDHCPv4States() map[string]managedNetworkDHCPv4RuntimeState {
	if len(ops.snapshotStates) == 0 {
		return nil
	}
	out := make(map[string]managedNetworkDHCPv4RuntimeState, len(ops.snapshotStates))
	for bridge, state := range ops.snapshotStates {
		out[bridge] = state
	}
	return out
}

func TestBuildManagedNetworkIPv4PlanDerivesGatewayAndPool(t *testing.T) {
	t.Parallel()

	plan, err := buildManagedNetworkIPv4Plan(ManagedNetwork{
		ID:              1,
		Name:            "lab",
		Bridge:          "vmbr0",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		IPv4DNSServers:  "1.1.1.1, 8.8.8.8",
		Enabled:         true,
	}, nil)
	if err != nil {
		t.Fatalf("buildManagedNetworkIPv4Plan() error = %v", err)
	}
	if plan.AddressSpec.CIDR != "192.0.2.1/24" {
		t.Fatalf("AddressSpec.CIDR = %q, want %q", plan.AddressSpec.CIDR, "192.0.2.1/24")
	}
	if plan.DHCPv4.Gateway != "192.0.2.1" {
		t.Fatalf("Gateway = %q, want %q", plan.DHCPv4.Gateway, "192.0.2.1")
	}
	if plan.DHCPv4.PoolStart != "192.0.2.2" || plan.DHCPv4.PoolEnd != "192.0.2.254" {
		t.Fatalf("Pool = %s-%s, want 192.0.2.2-192.0.2.254", plan.DHCPv4.PoolStart, plan.DHCPv4.PoolEnd)
	}
	if strings.Join(plan.DHCPv4.DNSServers, ",") != "1.1.1.1,8.8.8.8" {
		t.Fatalf("DNSServers = %v, want [1.1.1.1 8.8.8.8]", plan.DHCPv4.DNSServers)
	}
	if !plan.NeedsForwarding {
		t.Fatal("NeedsForwarding = false, want true when uplink is set")
	}
}

func TestManagedIPv4NetworkRuntimeReconcileCreatesAndDeletesState(t *testing.T) {
	t.Parallel()

	ops := &fakeManagedNetworkNetOps{}
	rt := newManagedIPv4NetworkRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv4NetworkRuntime() = nil")
	}

	err := rt.Reconcile([]ManagedNetwork{{
		ID:              1,
		Name:            "lab",
		Bridge:          "vmbr0",
		BridgeMTU:       9000,
		BridgeVLANAware: true,
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		IPv4PoolStart:   "192.0.2.100",
		IPv4PoolEnd:     "192.0.2.120",
		IPv4DNSServers:  "1.1.1.1",
		Enabled:         true,
	}}, nil)
	if err != nil {
		t.Fatalf("first Reconcile() error = %v", err)
	}
	if ops.forwardingCalls != 1 {
		t.Fatalf("forwardingCalls = %d, want 1", ops.forwardingCalls)
	}
	if len(ops.ensureAddresses) != 1 || ops.ensureAddresses[0].InterfaceName != "vmbr0" {
		t.Fatalf("ensureAddresses = %+v, want vmbr0 address", ops.ensureAddresses)
	}
	if len(ops.ensureInterfaces) != 1 || ops.ensureInterfaces[0].Name != "vmbr0" || ops.ensureInterfaces[0].Mode != managedNetworkBridgeModeCreate {
		t.Fatalf("ensureInterfaces = %+v, want create vmbr0", ops.ensureInterfaces)
	}
	if ops.ensureInterfaces[0].BridgeMTU != 9000 || !ops.ensureInterfaces[0].BridgeVLANAware {
		t.Fatalf("ensureInterfaces = %+v, want bridge mtu=9000 vlan-aware=true", ops.ensureInterfaces)
	}
	if len(ops.ensureDHCPv4) != 1 || ops.ensureDHCPv4[0].Bridge != "vmbr0" {
		t.Fatalf("ensureDHCPv4 = %+v, want vmbr0 dhcp config", ops.ensureDHCPv4)
	}

	err = rt.Reconcile(nil, nil)
	if err != nil {
		t.Fatalf("second Reconcile() error = %v", err)
	}
	if len(ops.deleteDHCPv4) != 1 || ops.deleteDHCPv4[0] != "vmbr0" {
		t.Fatalf("deleteDHCPv4 = %v, want [vmbr0]", ops.deleteDHCPv4)
	}
	if len(ops.deleteAddresses) != 1 || ops.deleteAddresses[0].InterfaceName != "vmbr0" {
		t.Fatalf("deleteAddresses = %+v, want vmbr0 address removal", ops.deleteAddresses)
	}
}

func TestManagedIPv4NetworkRuntimeSnapshotStatusRefreshesLiveDHCPState(t *testing.T) {
	t.Parallel()

	ops := &fakeManagedNetworkNetOps{}
	rt := newManagedIPv4NetworkRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv4NetworkRuntime() = nil")
	}

	err := rt.Reconcile([]ManagedNetwork{{
		ID:              1,
		Name:            "lab",
		Bridge:          "vmbr0",
		UplinkInterface: "eno1",
		IPv4Enabled:     true,
		IPv4CIDR:        "192.0.2.1/24",
		Enabled:         true,
	}}, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}

	status := rt.SnapshotStatus()
	if status[1].RuntimeStatus != "draining" || status[1].RuntimeDetail != "waiting for dhcpv4 listener" {
		t.Fatalf("initial status = %+v, want waiting for listener", status[1])
	}

	ops.snapshotStates = map[string]managedNetworkDHCPv4RuntimeState{
		"vmbr0": {
			Status:     "running",
			Detail:     "listening for dhcpv4 (replies=2)",
			ReplyCount: 2,
		},
	}

	status = rt.SnapshotStatus()
	if status[1].RuntimeStatus != "running" || status[1].RuntimeDetail != "listening for dhcpv4 (replies=2)" || status[1].DHCPv4ReplyCount != 2 {
		t.Fatalf("refreshed status = %+v, want live dhcp state", status[1])
	}
}

func TestBuildManagedNetworkIPv4PlanRejectsGatewayMismatch(t *testing.T) {
	t.Parallel()

	_, err := buildManagedNetworkIPv4Plan(ManagedNetwork{
		ID:          1,
		Name:        "lab",
		Bridge:      "vmbr0",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		IPv4Gateway: "192.0.2.254",
		Enabled:     true,
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "ipv4_gateway must match") {
		t.Fatalf("error = %v, want gateway mismatch", err)
	}
}

func TestManagedIPv4NetworkRuntimeReconcileEnsuresInterfaceForIPv6OnlyManagedNetwork(t *testing.T) {
	t.Parallel()

	ops := &fakeManagedNetworkNetOps{}
	rt := newManagedIPv4NetworkRuntime(ops)
	if rt == nil {
		t.Fatal("newManagedIPv4NetworkRuntime() = nil")
	}

	err := rt.Reconcile([]ManagedNetwork{{
		ID:          1,
		Name:        "lab-v6",
		Bridge:      "vmbr9",
		IPv4Enabled: false,
		IPv6Enabled: true,
		Enabled:     true,
	}}, nil)
	if err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if len(ops.ensureInterfaces) != 1 || ops.ensureInterfaces[0].Name != "vmbr9" || ops.ensureInterfaces[0].Mode != managedNetworkBridgeModeCreate {
		t.Fatalf("ensureInterfaces = %+v, want create vmbr9", ops.ensureInterfaces)
	}
	if len(ops.ensureAddresses) != 0 {
		t.Fatalf("ensureAddresses = %+v, want none for ipv6-only network", ops.ensureAddresses)
	}
	if len(ops.ensureDHCPv4) != 0 {
		t.Fatalf("ensureDHCPv4 = %+v, want none for ipv6-only network", ops.ensureDHCPv4)
	}
}

func TestBuildManagedNetworkIPv4PlanIncludesReservations(t *testing.T) {
	t.Parallel()

	plan, err := buildManagedNetworkIPv4Plan(ManagedNetwork{
		ID:          7,
		Name:        "lab",
		Bridge:      "vmbr7",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	}, []ManagedNetworkReservation{{
		ID:               11,
		ManagedNetworkID: 7,
		MACAddress:       "aa:bb:cc:dd:ee:ff",
		IPv4Address:      "192.0.2.10",
		Remark:           "vm100",
	}})
	if err != nil {
		t.Fatalf("buildManagedNetworkIPv4Plan() error = %v", err)
	}
	if len(plan.DHCPv4.Reservations) != 1 {
		t.Fatalf("Reservations = %+v, want 1 reservation", plan.DHCPv4.Reservations)
	}
	if plan.DHCPv4.Reservations[0].MACAddress != "aa:bb:cc:dd:ee:ff" || plan.DHCPv4.Reservations[0].IPv4Address != "192.0.2.10" {
		t.Fatalf("Reservation = %+v, want MAC/IP preserved", plan.DHCPv4.Reservations[0])
	}
}

func TestBuildManagedNetworkIPv4PlanPreservesExistingBridgeMode(t *testing.T) {
	t.Parallel()

	plan, err := buildManagedNetworkIPv4Plan(ManagedNetwork{
		ID:          9,
		Name:        "lab",
		BridgeMode:  managedNetworkBridgeModeExisting,
		Bridge:      "eno2",
		IPv4Enabled: true,
		IPv4CIDR:    "192.0.2.1/24",
		Enabled:     true,
	}, nil)
	if err != nil {
		t.Fatalf("buildManagedNetworkIPv4Plan() error = %v", err)
	}
	if plan.BridgeMode != managedNetworkBridgeModeExisting {
		t.Fatalf("BridgeMode = %q, want %q", plan.BridgeMode, managedNetworkBridgeModeExisting)
	}
}
