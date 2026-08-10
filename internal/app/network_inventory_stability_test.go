package app

import (
	"errors"
	"testing"
	"time"
)

func interfaceNamesFromSnapshot(snapshot egressNATInterfaceSnapshot) map[string]InterfaceInfo {
	out := make(map[string]InterfaceInfo, len(snapshot.Infos))
	for _, info := range snapshot.Infos {
		out[info.Name] = info
	}
	return out
}

func TestStableNetworkInventoryRetainsMissingInterfaceUntilGraceThenRemovesIt(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(1000, 0)
	full := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil)
	pm.stabilizeNetworkInterfaceSnapshotAt(full, startedAt)

	missing := newEgressNATInterfaceSnapshot([]InterfaceInfo{{Name: "vmbr1", Kind: "bridge"}}, nil)
	stable := pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(time.Second))
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; !ok {
		t.Fatal("stable inventory removed tap100i0 on the first complete missing snapshot")
	}
	state := pm.missingInterfaceStates["tap100i0"]
	if state.FullConfirmations != 1 {
		t.Fatalf("missing confirmations = %d, want 1", state.FullConfirmations)
	}
	wantRecheck := startedAt.Add(time.Second + networkInterfaceMissingGrace)
	if !pm.networkInventoryStableRecheckAt.Equal(wantRecheck) {
		t.Fatalf("stable recheck = %v, want %v", pm.networkInventoryStableRecheckAt, wantRecheck)
	}

	stable = pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(9*time.Second))
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; !ok {
		t.Fatal("stable inventory removed tap100i0 inside the grace period")
	}

	stable = pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(12*time.Second))
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; ok {
		t.Fatal("stable inventory retained tap100i0 after grace and repeated complete confirmation")
	}
	if _, ok := pm.missingInterfaceStates["tap100i0"]; ok {
		t.Fatal("missing state remained after stable removal")
	}
}

func TestStableNetworkInventoryReadFailureDoesNotConfirmRemoval(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(2000, 0)
	pm.stabilizeNetworkInterfaceSnapshotAt(newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil), startedAt)
	missing := newEgressNATInterfaceSnapshot([]InterfaceInfo{{Name: "vmbr1", Kind: "bridge"}}, nil)
	pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(time.Second))

	stable := pm.stabilizeNetworkInterfaceSnapshotAt(
		newEgressNATInterfaceSnapshot(nil, errors.New("netlink dump interrupted")),
		startedAt.Add(12*time.Second),
	)
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; !ok {
		t.Fatal("failed inventory read removed tap100i0")
	}
	if got := pm.missingInterfaceStates["tap100i0"].FullConfirmations; got != 1 {
		t.Fatalf("missing confirmations after failed read = %d, want 1", got)
	}

	stable = pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(13*time.Second))
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; ok {
		t.Fatal("second successful missing inventory did not remove expired tap100i0")
	}
}

func TestStableNetworkInventoryReadFailureSchedulesRetryWithoutMissingState(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(2500, 0)
	pm.stabilizeNetworkInterfaceSnapshotAt(newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil), startedAt)

	stable := pm.stabilizeNetworkInterfaceSnapshotAt(
		newEgressNATInterfaceSnapshot(nil, errors.New("netlink dump interrupted")),
		startedAt.Add(time.Second),
	)
	if _, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]; !ok {
		t.Fatal("failed inventory read discarded the stable tap100i0 cache")
	}
	if len(pm.missingInterfaceStates) != 0 {
		t.Fatalf("failed inventory read created missing confirmations: %#v", pm.missingInterfaceStates)
	}
	wantRecheck := startedAt.Add(time.Second + networkInventoryRetryDelay)
	if !pm.networkInventoryStableRecheckAt.Equal(wantRecheck) {
		t.Fatalf("stable recheck = %v, want failed-read retry at %v", pm.networkInventoryStableRecheckAt, wantRecheck)
	}
}

func TestStableNetworkInventoryRecoveryClearsMissingStateImmediately(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(3000, 0)
	full := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil)
	pm.stabilizeNetworkInterfaceSnapshotAt(full, startedAt)
	pm.stabilizeNetworkInterfaceSnapshotAt(
		newEgressNATInterfaceSnapshot([]InterfaceInfo{{Name: "vmbr1", Kind: "bridge"}}, nil),
		startedAt.Add(time.Second),
	)

	recovered := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap", Addrs: []string{"192.0.2.10"}},
	}, nil)
	stable := pm.stabilizeNetworkInterfaceSnapshotAt(recovered, startedAt.Add(5*time.Second))
	if _, ok := pm.missingInterfaceStates["tap100i0"]; ok {
		t.Fatal("recovered tap100i0 still has missing state")
	}
	if !pm.networkInventoryStableRecheckAt.IsZero() {
		t.Fatalf("stable recheck remained scheduled after recovery: %v", pm.networkInventoryStableRecheckAt)
	}
	if got := interfaceNamesFromSnapshot(stable)["tap100i0"].Addrs; len(got) != 1 || got[0] != "192.0.2.10" {
		t.Fatalf("recovered interface data = %#v, want refreshed address", got)
	}
}

func TestStableNetworkInventoryPreservesProxmoxGuestAssociationAcrossTopologyJitter(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(4000, 0)
	full := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "fwbr100i0", Kind: "bridge"},
		{Name: "fwpr100p0", Parent: "vmbr1", Kind: "veth"},
		{Name: "fwln100i0", Parent: "fwbr100i0", Kind: "veth"},
		{Name: "tap100i0", Parent: "fwbr100i0", Kind: "tuntap"},
	}, nil)
	pm.stabilizeNetworkInterfaceSnapshotAt(full, startedAt)

	current := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "fwbr100i0", Kind: "bridge"},
		{Name: "fwpr100p0", Kind: "veth"},
		{Name: "fwln100i0", Parent: "fwbr100i0", Kind: "veth"},
	}, nil)
	stable := pm.stabilizeNetworkInterfaceSnapshotAt(current, startedAt.Add(time.Second))
	inventory := buildManagedNetworkInterfaceInventory(stable.Infos, true)
	targets := collectManagedNetworkIPv6TargetNamesFromInventory("vmbr1", "", inventory)
	if len(targets) != 1 || targets[0] != "tap100i0" {
		t.Fatalf("stable Proxmox guest targets = %#v, want tap100i0", targets)
	}
	if pm.missingInterfaceStates["fwpr100p0"].FullConfirmations != 1 {
		t.Fatal("detached fwpr100p0 topology was not placed in the confirmation window")
	}
	if pm.missingInterfaceStates["tap100i0"].FullConfirmations != 1 {
		t.Fatal("missing tap100i0 was not placed in the confirmation window")
	}
}

func TestStableNetworkInventoryAcceptsConfirmedDetachedTopologyAfterGrace(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(4500, 0)
	pm.stabilizeNetworkInterfaceSnapshotAt(newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil), startedAt)
	detached := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Kind: "tuntap"},
	}, nil)

	stable := pm.stabilizeNetworkInterfaceSnapshotAt(detached, startedAt.Add(time.Second))
	if got := interfaceNamesFromSnapshot(stable)["tap100i0"].Parent; got != "vmbr1" {
		t.Fatalf("parent during grace = %q, want vmbr1", got)
	}
	stable = pm.stabilizeNetworkInterfaceSnapshotAt(detached, startedAt.Add(12*time.Second))
	info, ok := interfaceNamesFromSnapshot(stable)["tap100i0"]
	if !ok {
		t.Fatal("confirmed detached interface was removed instead of adopting its current topology")
	}
	if info.Parent != "" {
		t.Fatalf("parent after grace = %q, want confirmed detached topology", info.Parent)
	}
	if _, ok := pm.missingInterfaceStates["tap100i0"]; ok {
		t.Fatal("confirmed detached topology retained a missing state")
	}
}

func TestStableManagedNetworkInventoryKeepsThenRemovesAutoIPv6Assignment(t *testing.T) {
	pm := &ProcessManager{}
	startedAt := time.Unix(5000, 0)
	network := ManagedNetwork{
		ID:                  1,
		Name:                "lab",
		Bridge:              "vmbr1",
		IPv6Enabled:         true,
		IPv6ParentInterface: "eno1",
		IPv6ParentPrefix:    "2001:db8:100::/56",
		IPv6AssignmentMode:  managedNetworkIPv6AssignmentModePrefix64,
		Enabled:             true,
	}
	full := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "eno1", Kind: "device"},
		{Name: "vmbr1", Kind: "bridge"},
		{Name: "tap100i0", Parent: "vmbr1", Kind: "tuntap"},
	}, nil)
	pm.stabilizeNetworkInterfaceSnapshotAt(full, startedAt)
	missing := newEgressNATInterfaceSnapshot([]InterfaceInfo{
		{Name: "eno1", Kind: "device"},
		{Name: "vmbr1", Kind: "bridge"},
	}, nil)

	stable := pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(time.Second))
	compiled := compileManagedNetworkRuntime([]ManagedNetwork{network}, nil, nil, stable.Infos)
	if len(compiled.IPv6Assignments) != 1 || compiled.IPv6Assignments[0].TargetInterface != "tap100i0" {
		t.Fatalf("IPv6 assignments inside grace = %#v, want retained tap100i0 assignment", compiled.IPv6Assignments)
	}

	stable = pm.stabilizeNetworkInterfaceSnapshotAt(missing, startedAt.Add(12*time.Second))
	compiled = compileManagedNetworkRuntime([]ManagedNetwork{network}, nil, nil, stable.Infos)
	if len(compiled.IPv6Assignments) != 0 {
		t.Fatalf("IPv6 assignments after confirmed removal = %#v, want none", compiled.IPv6Assignments)
	}

	network.Enabled = false
	compiled = compileManagedNetworkRuntime([]ManagedNetwork{network}, nil, nil, full.Infos)
	if len(compiled.IPv6Assignments) != 0 {
		t.Fatalf("disabled network retained IPv6 assignments: %#v", compiled.IPv6Assignments)
	}
}
