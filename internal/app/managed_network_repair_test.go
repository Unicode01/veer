package app

import (
	"reflect"
	"testing"
)

func TestParseManagedNetworkPVEBridgeBindings(t *testing.T) {
	t.Parallel()

	got := parseManagedNetworkPVEBridgeBindings("100", `
# comment
net0: virtio=BC:24:11:31:53:DB,bridge=vmbr1,firewall=1
net1: virtio=BC:24:11:31:53:DC,bridge=vmbr2,tag=20
scsi0: local-lvm:vm-100-disk-0
net2: virtio=BC:24:11:31:53:DD,bridge=none
`)
	if len(got) != 2 {
		t.Fatalf("len(bindings) = %d, want 2", len(got))
	}
	if got[0].VMID != "100" || got[0].Slot != "0" || got[0].Bridge != "vmbr1" {
		t.Fatalf("bindings[0] = %+v, want vmid=100 slot=0 bridge=vmbr1", got[0])
	}
	if got[1].VMID != "100" || got[1].Slot != "1" || got[1].Bridge != "vmbr2" {
		t.Fatalf("bindings[1] = %+v, want vmid=100 slot=1 bridge=vmbr2", got[1])
	}
}

func TestManagedNetworkRepairResultInterfaceNames(t *testing.T) {
	t.Parallel()

	got := managedNetworkRepairResultInterfaceNames(managedNetworkRepairResult{
		Bridges:    []string{"vmbr1"},
		GuestLinks: []string{"fwpr100p0->vmbr1", "tap100i0->vmbr1"},
	})
	if len(got) != 3 {
		t.Fatalf("len(managedNetworkRepairResultInterfaceNames()) = %d, want 3 (%v)", len(got), got)
	}
	if got[0] != "vmbr1" || got[1] != "fwpr100p0" || got[2] != "tap100i0" {
		t.Fatalf("managedNetworkRepairResultInterfaceNames() = %v, want [vmbr1 fwpr100p0 tap100i0]", got)
	}
}

func TestManagedNetworkPVEGuestLinkCandidatesIncludesLXCVeth(t *testing.T) {
	t.Parallel()

	got := managedNetworkPVEGuestLinkCandidates(managedNetworkPVEBridgeBinding{
		VMID: "101",
		Slot: "0",
	})
	want := []string{"fwpr101p0", "tap101i0", "veth101i0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("managedNetworkPVEGuestLinkCandidates() = %v, want %v", got, want)
	}
}

func TestDetectManagedNetworkDetachedPVEGuestLinkSupportsLXCVeth(t *testing.T) {
	t.Parallel()

	detached, name := detectManagedNetworkDetachedPVEGuestLink(
		managedNetworkPVEBridgeBinding{VMID: "101", Slot: "0", Bridge: "vmbr1"},
		"vmbr1",
		map[string]string{
			"veth101i0": "vmbr9",
		},
	)
	if !detached || name != "veth101i0" {
		t.Fatalf("detectManagedNetworkDetachedPVEGuestLink() = (%v, %q), want (true, %q)", detached, name, "veth101i0")
	}
}
