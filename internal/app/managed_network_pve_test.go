package app

import "testing"

func TestParseManagedNetworkPVEGuestNICsIncludesGuestMetadata(t *testing.T) {
	t.Parallel()

	got := parseManagedNetworkPVEGuestNICs("100", `
name: web-100
net0: virtio=BC:24:11:31:53:DB,bridge=vmbr1,firewall=1
net1: virtio=BC:24:11:31:53:DC,bridge=vmbr2,tag=20
net2: virtio=BC:24:11:31:53:DD,bridge=none
`)
	if len(got) != 3 {
		t.Fatalf("len(parseManagedNetworkPVEGuestNICs()) = %d, want 3", len(got))
	}
	if got[0].VMID != "100" || got[0].GuestName != "web-100" || got[0].ConfigKey != "net0" || got[0].Bridge != "vmbr1" || got[0].MACAddress != "bc:24:11:31:53:db" {
		t.Fatalf("nics[0] = %+v, want vmid=100 guest=web-100 key=net0 bridge=vmbr1 mac=bc:24:11:31:53:db", got[0])
	}
	if got[2].ConfigKey != "net2" || got[2].Bridge != "" {
		t.Fatalf("nics[2] = %+v, want bridge empty for bridge=none", got[2])
	}
}

func TestEnrichManagedNetworkDiscoveredMACsWithPVEGuestNICsMatchesVMIDSlotAndMAC(t *testing.T) {
	t.Parallel()

	got := enrichManagedNetworkDiscoveredMACsWithPVEGuestNICs(
		[]managedNetworkDiscoveredMAC{{
			ManagedNetworkID: 7,
			ChildInterface:   "fwpr100p0",
			MACAddress:       "bc:24:11:31:53:db",
		}},
		[]managedNetworkPVEGuestNIC{{
			VMID:       "100",
			GuestName:  "web-100",
			Slot:       "0",
			ConfigKey:  "net0",
			Bridge:     "vmbr1",
			MACAddress: "bc:24:11:31:53:db",
		}},
	)
	if len(got) != 1 {
		t.Fatalf("len(enrichManagedNetworkDiscoveredMACsWithPVEGuestNICs()) = %d, want 1", len(got))
	}
	if got[0].PVEVMID != "100" || got[0].PVEGuestName != "web-100" || got[0].PVEGuestNIC != "net0" {
		t.Fatalf("items[0] = %+v, want vmid=100 guest=web-100 nic=net0", got[0])
	}
}
