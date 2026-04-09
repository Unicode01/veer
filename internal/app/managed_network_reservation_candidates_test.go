package app

import "testing"

func TestBuildManagedNetworkReservationCandidatesSuggestsFreeIPsAndMarksReserved(t *testing.T) {
	t.Parallel()

	items := buildManagedNetworkReservationCandidates(
		[]ManagedNetwork{{
			ID:            7,
			Name:          "vm100-lan",
			Bridge:        "vmbr10",
			IPv4Enabled:   true,
			IPv4CIDR:      "10.0.0.1/24",
			IPv4PoolStart: "10.0.0.100",
			IPv4PoolEnd:   "10.0.0.101",
			Enabled:       true,
		}},
		[]ManagedNetworkReservation{{
			ID:               12,
			ManagedNetworkID: 7,
			MACAddress:       "aa:bb:cc:dd:ee:ff",
			IPv4Address:      "10.0.0.100",
			Remark:           "vm100",
		}},
		[]managedNetworkDiscoveredMAC{
			{ManagedNetworkID: 7, ChildInterface: "tap100i0", MACAddress: "aa:bb:cc:dd:ee:ff", PVEVMID: "100", PVEGuestName: "web-100", PVEGuestNIC: "net0"},
			{ManagedNetworkID: 7, ChildInterface: "tap101i0", MACAddress: "aa:bb:cc:dd:ee:11", PVEVMID: "101", PVEGuestName: "db-101", PVEGuestNIC: "net0"},
			{ManagedNetworkID: 7, ChildInterface: "tap102i0", MACAddress: "aa:bb:cc:dd:ee:22"},
		},
	)

	if len(items) != 3 {
		t.Fatalf("len(items) = %d, want 3", len(items))
	}
	if items[0].Status != managedNetworkReservationCandidateStatusReserved || items[0].ExistingReservationID != 12 || items[0].SuggestedIPv4 != "10.0.0.100" {
		t.Fatalf("items[0] = %+v, want reserved existing lease", items[0])
	}
	if len(items[0].IPv4Candidates) != 1 || items[0].IPv4Candidates[0] != "10.0.0.100" {
		t.Fatalf("items[0].IPv4Candidates = %#v, want [10.0.0.100]", items[0].IPv4Candidates)
	}
	if items[0].SuggestedRemark != "web-100 / net0" || items[0].PVEGuestName != "web-100" || items[0].PVEVMID != "100" {
		t.Fatalf("items[0] = %+v, want pve metadata and remark", items[0])
	}
	if items[1].Status != managedNetworkReservationCandidateStatusAvailable || items[1].SuggestedIPv4 != "10.0.0.101" {
		t.Fatalf("items[1] = %+v, want available 10.0.0.101", items[1])
	}
	if len(items[1].IPv4Candidates) != 1 || items[1].IPv4Candidates[0] != "10.0.0.101" {
		t.Fatalf("items[1].IPv4Candidates = %#v, want [10.0.0.101]", items[1].IPv4Candidates)
	}
	if items[1].SuggestedRemark != "db-101 / net0" {
		t.Fatalf("items[1] = %+v, want suggested remark db-101 / net0", items[1])
	}
	if items[2].Status != managedNetworkReservationCandidateStatusUnavailable || items[2].SuggestedIPv4 != "" {
		t.Fatalf("items[2] = %+v, want unavailable without free IP", items[2])
	}
	if len(items[2].IPv4Candidates) != 0 {
		t.Fatalf("items[2].IPv4Candidates = %#v, want none for unavailable candidate", items[2].IPv4Candidates)
	}
}

func TestDedupeManagedNetworkDiscoveredMACsPrefersRicherPVEGuestMetadata(t *testing.T) {
	t.Parallel()

	got := dedupeManagedNetworkDiscoveredMACs([]managedNetworkDiscoveredMAC{
		{ManagedNetworkID: 7, ChildInterface: "fwpr100p0", MACAddress: "aa:bb:cc:dd:ee:ff", ObservedIPv4s: []string{"192.168.4.6"}},
		{ManagedNetworkID: 7, ChildInterface: "tap100i0", MACAddress: "aa:bb:cc:dd:ee:ff", PVEVMID: "100", PVEGuestName: "web-100", PVEGuestNIC: "net0"},
	})
	if len(got) != 1 {
		t.Fatalf("len(dedupeManagedNetworkDiscoveredMACs()) = %d, want 1", len(got))
	}
	if got[0].ChildInterface != "tap100i0" || got[0].PVEGuestName != "web-100" {
		t.Fatalf("dedupeManagedNetworkDiscoveredMACs() = %+v, want tap100i0 with guest metadata", got)
	}
	if len(got[0].ObservedIPv4s) != 1 || got[0].ObservedIPv4s[0] != "192.168.4.6" {
		t.Fatalf("dedupeManagedNetworkDiscoveredMACs().ObservedIPv4s = %#v, want [192.168.4.6]", got[0].ObservedIPv4s)
	}
}

func TestBuildManagedNetworkReservationCandidatesPrefersChildInterfaceIPv4(t *testing.T) {
	t.Parallel()

	items := buildManagedNetworkReservationCandidatesWithInfos(
		[]ManagedNetwork{{
			ID:            7,
			Name:          "vm101-lan",
			Bridge:        "vmbr10",
			IPv4Enabled:   true,
			IPv4CIDR:      "192.168.4.1/24",
			IPv4PoolStart: "192.168.4.2",
			IPv4PoolEnd:   "192.168.4.50",
			Enabled:       true,
		}},
		nil,
		[]managedNetworkDiscoveredMAC{
			{ManagedNetworkID: 7, ChildInterface: "tap101i0", MACAddress: "aa:bb:cc:dd:ee:11", PVEVMID: "101"},
		},
		[]InterfaceInfo{
			{Name: "tap101i0", Addrs: []string{"192.168.4.3"}},
		},
	)

	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].Status != managedNetworkReservationCandidateStatusAvailable {
		t.Fatalf("items[0].Status = %q, want %q", items[0].Status, managedNetworkReservationCandidateStatusAvailable)
	}
	if items[0].SuggestedIPv4 != "192.168.4.3" {
		t.Fatalf("items[0].SuggestedIPv4 = %q, want 192.168.4.3", items[0].SuggestedIPv4)
	}
	if len(items[0].IPv4Candidates) < 2 {
		t.Fatalf("items[0].IPv4Candidates = %#v, want observed ip plus additional pool candidates", items[0].IPv4Candidates)
	}
	if items[0].IPv4Candidates[0] != "192.168.4.3" {
		t.Fatalf("items[0].IPv4Candidates[0] = %q, want 192.168.4.3", items[0].IPv4Candidates[0])
	}
	foundPoolCandidate := false
	for _, candidate := range items[0].IPv4Candidates[1:] {
		if candidate == "192.168.4.2" {
			foundPoolCandidate = true
			break
		}
	}
	if !foundPoolCandidate {
		t.Fatalf("items[0].IPv4Candidates = %#v, want to include pool fallback 192.168.4.2", items[0].IPv4Candidates)
	}
}

func TestBuildManagedNetworkReservationCandidatesPrefersObservedGuestIPv4OverPoolFallback(t *testing.T) {
	t.Parallel()

	items := buildManagedNetworkReservationCandidatesWithInfos(
		[]ManagedNetwork{{
			ID:            7,
			Name:          "vm104-lan",
			Bridge:        "vmbr0",
			IPv4Enabled:   true,
			IPv4CIDR:      "192.168.4.1/24",
			IPv4PoolStart: "192.168.4.5",
			IPv4PoolEnd:   "192.168.4.50",
			Enabled:       true,
		}},
		nil,
		[]managedNetworkDiscoveredMAC{{
			ManagedNetworkID: 7,
			ChildInterface:   "tap104i0",
			MACAddress:       "bc:24:11:84:f5:2c",
			ObservedIPv4s:    []string{"192.168.4.6"},
			PVEVMID:          "104",
			PVEGuestName:     "SelfWindows",
			PVEGuestNIC:      "net0",
		}},
		nil,
	)

	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	if items[0].SuggestedIPv4 != "192.168.4.6" {
		t.Fatalf("items[0].SuggestedIPv4 = %q, want 192.168.4.6", items[0].SuggestedIPv4)
	}
	if len(items[0].IPv4Candidates) < 2 {
		t.Fatalf("items[0].IPv4Candidates = %#v, want observed ip plus pool fallback", items[0].IPv4Candidates)
	}
	if items[0].IPv4Candidates[0] != "192.168.4.6" {
		t.Fatalf("items[0].IPv4Candidates[0] = %q, want 192.168.4.6", items[0].IPv4Candidates[0])
	}
	if items[0].IPv4Candidates[1] != "192.168.4.5" {
		t.Fatalf("items[0].IPv4Candidates[1] = %q, want 192.168.4.5", items[0].IPv4Candidates[1])
	}
}
