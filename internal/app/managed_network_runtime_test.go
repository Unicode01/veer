package app

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestCompileManagedNetworkRuntimeGeneratesIPv6AssignmentsAndAutoEgressNAT(t *testing.T) {
	t.Parallel()

	compiled := compileManagedNetworkRuntime(
		[]ManagedNetwork{{
			ID:                  1,
			Name:                "lab",
			Bridge:              "vmbr0",
			UplinkInterface:     "eno1",
			IPv6Enabled:         true,
			IPv6ParentInterface: "vmbr0",
			IPv6ParentPrefix:    "2001:db8:100::/64",
			IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
			AutoEgressNAT:       true,
			Enabled:             true,
		}},
		nil,
		nil,
		[]InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tap"},
			{Name: "tap101i0", Parent: "vmbr0", Kind: "tap"},
			{Name: "vmbr0", Kind: "bridge"},
		},
	)

	if len(compiled.Warnings) != 0 {
		t.Fatalf("Warnings = %v, want none", compiled.Warnings)
	}
	if len(compiled.IPv6Assignments) != 2 {
		t.Fatalf("len(IPv6Assignments) = %d, want 2", len(compiled.IPv6Assignments))
	}
	if len(compiled.EgressNATs) != 1 {
		t.Fatalf("len(EgressNATs) = %d, want 1", len(compiled.EgressNATs))
	}
	if _, ok := compiled.RedistributeIfaces["vmbr0"]; !ok {
		t.Fatalf("RedistributeIfaces = %v, want vmbr0", compiled.RedistributeIfaces)
	}
	if _, ok := compiled.RedistributeIfaces["eno1"]; !ok {
		t.Fatalf("RedistributeIfaces = %v, want eno1", compiled.RedistributeIfaces)
	}

	seenTargets := make(map[string]string)
	for _, item := range compiled.IPv6Assignments {
		if item.ParentInterface != "vmbr0" {
			t.Fatalf("ParentInterface = %q, want vmbr0", item.ParentInterface)
		}
		if item.ParentPrefix != "2001:db8:100::/64" {
			t.Fatalf("ParentPrefix = %q, want 2001:db8:100::/64", item.ParentPrefix)
		}
		if item.PrefixLen != 128 || !strings.HasSuffix(item.AssignedPrefix, "/128") {
			t.Fatalf("assignment = %+v, want single /128 assignment", item)
		}
		if current, ok := seenTargets[item.TargetInterface]; ok {
			t.Fatalf("duplicate target %s with prefixes %s and %s", item.TargetInterface, current, item.AssignedPrefix)
		}
		seenTargets[item.TargetInterface] = item.AssignedPrefix
	}
	if len(seenTargets) != 2 || seenTargets["tap100i0"] == "" || seenTargets["tap101i0"] == "" {
		t.Fatalf("generated targets = %v, want tap100i0 and tap101i0", seenTargets)
	}
	if seenTargets["tap100i0"] == seenTargets["tap101i0"] {
		t.Fatalf("generated prefixes = %v, want unique assignments", seenTargets)
	}

	item := compiled.EgressNATs[0]
	if item.ParentInterface != "vmbr0" || item.OutInterface != "eno1" {
		t.Fatalf("EgressNAT = %+v, want vmbr0 -> eno1", item)
	}
	if item.Protocol != "tcp+udp+icmp" {
		t.Fatalf("Protocol = %q, want tcp+udp+icmp", item.Protocol)
	}
}

func TestCompileManagedNetworkRuntimePrefersExplicitIPv6AssignmentPerTarget(t *testing.T) {
	t.Parallel()

	compiled := compileManagedNetworkRuntime(
		[]ManagedNetwork{{
			ID:                  1,
			Name:                "lab",
			Bridge:              "vmbr0",
			IPv6Enabled:         true,
			IPv6ParentInterface: "vmbr0",
			IPv6ParentPrefix:    "2001:db8:100::/64",
			IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
			Enabled:             true,
		}},
		[]IPv6Assignment{{
			ID:              99,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2001:db8:100::/64",
			AssignedPrefix:  "2001:db8:100::1234/128",
			Enabled:         true,
		}},
		nil,
		[]InterfaceInfo{
			{Name: "tap100i0", Parent: "vmbr0", Kind: "tap"},
			{Name: "tap101i0", Parent: "vmbr0", Kind: "tap"},
			{Name: "vmbr0", Kind: "bridge"},
		},
	)

	if len(compiled.IPv6Assignments) != 1 {
		t.Fatalf("len(IPv6Assignments) = %d, want 1", len(compiled.IPv6Assignments))
	}
	if got := compiled.IPv6Assignments[0].TargetInterface; got != "tap101i0" {
		t.Fatalf("TargetInterface = %q, want tap101i0", got)
	}
	if len(compiled.Warnings) != 1 || !strings.Contains(compiled.Warnings[0], "#99 (2001:db8:100::1234/128)") {
		t.Fatalf("Warnings = %v, want explicit-assignment skip warning", compiled.Warnings)
	}
	preview := compiled.Previews[1]
	if len(preview.Warnings) != 1 || !strings.Contains(preview.Warnings[0], "#99 (2001:db8:100::1234/128)") {
		t.Fatalf("preview.Warnings = %v, want explicit-assignment skip warning", preview.Warnings)
	}
}

func TestCompileManagedNetworkRuntimeResolvesProxmoxFirewallPortToTapForIPv6(t *testing.T) {
	t.Parallel()

	compiled := compileManagedNetworkRuntime(
		[]ManagedNetwork{{
			ID:                  1,
			Name:                "lab",
			Bridge:              "vmbr0",
			IPv6Enabled:         true,
			IPv6ParentInterface: "vmbr0",
			IPv6ParentPrefix:    "2001:db8:100::/64",
			IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
			Enabled:             true,
		}},
		nil,
		nil,
		[]InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "fwpr100p0", Parent: "vmbr0", Kind: "veth"},
			{Name: "fwbr100i0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "fwbr100i0", Kind: "tap"},
			{Name: "fwln100i0", Parent: "fwbr100i0", Kind: "veth"},
			{Name: "tap101i0", Parent: "vmbr0", Kind: "tap"},
		},
	)

	if len(compiled.IPv6Assignments) != 2 {
		t.Fatalf("len(IPv6Assignments) = %d, want 2", len(compiled.IPv6Assignments))
	}

	seenTargets := make(map[string]struct{}, len(compiled.IPv6Assignments))
	for _, item := range compiled.IPv6Assignments {
		seenTargets[item.TargetInterface] = struct{}{}
	}
	if _, ok := seenTargets["tap100i0"]; !ok {
		t.Fatalf("generated targets = %v, want tap100i0", seenTargets)
	}
	if _, ok := seenTargets["tap101i0"]; !ok {
		t.Fatalf("generated targets = %v, want tap101i0", seenTargets)
	}
	if _, ok := seenTargets["fwpr100p0"]; ok {
		t.Fatalf("generated targets = %v, want fwpr100p0 to resolve to tap100i0", seenTargets)
	}

	preview := compiled.Previews[1]
	if !reflect.DeepEqual(preview.ChildInterfaces, []string{"tap100i0", "tap101i0"}) {
		t.Fatalf("preview.ChildInterfaces = %v, want [tap100i0 tap101i0]", preview.ChildInterfaces)
	}
}

func TestCompileManagedNetworkRuntimePrefersExplicitTapAssignmentOverResolvedFirewallPort(t *testing.T) {
	t.Parallel()

	compiled := compileManagedNetworkRuntime(
		[]ManagedNetwork{{
			ID:                  1,
			Name:                "lab",
			Bridge:              "vmbr0",
			IPv6Enabled:         true,
			IPv6ParentInterface: "vmbr0",
			IPv6ParentPrefix:    "2001:db8:100::/64",
			IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
			Enabled:             true,
		}},
		[]IPv6Assignment{{
			ID:              99,
			ParentInterface: "vmbr0",
			TargetInterface: "tap100i0",
			ParentPrefix:    "2001:db8:100::/64",
			AssignedPrefix:  "2001:db8:100::1234/128",
			Enabled:         true,
		}},
		nil,
		[]InterfaceInfo{
			{Name: "vmbr0", Kind: "bridge"},
			{Name: "fwpr100p0", Parent: "vmbr0", Kind: "veth"},
			{Name: "fwbr100i0", Kind: "bridge"},
			{Name: "tap100i0", Parent: "fwbr100i0", Kind: "tap"},
			{Name: "tap101i0", Parent: "vmbr0", Kind: "tap"},
		},
	)

	if len(compiled.IPv6Assignments) != 1 {
		t.Fatalf("len(IPv6Assignments) = %d, want 1", len(compiled.IPv6Assignments))
	}
	if got := compiled.IPv6Assignments[0].TargetInterface; got != "tap101i0" {
		t.Fatalf("TargetInterface = %q, want tap101i0", got)
	}
}

func TestCompileManagedNetworkRuntimeSkipsOverlappingAutoEgressNAT(t *testing.T) {
	t.Parallel()

	compiled := compileManagedNetworkRuntime(
		[]ManagedNetwork{{
			ID:              1,
			Name:            "lab",
			Bridge:          "vmbr0",
			UplinkInterface: "eno1",
			AutoEgressNAT:   true,
			Enabled:         true,
		}},
		nil,
		[]EgressNAT{{
			ID:              10,
			ParentInterface: "vmbr0",
			OutInterface:    "eno1",
			Protocol:        "tcp+udp",
			NATType:         egressNATTypeSymmetric,
			Enabled:         true,
		}},
		[]InterfaceInfo{
			{Name: "eno1", Kind: "device"},
			{Name: "vmbr0", Kind: "bridge"},
		},
	)

	if len(compiled.EgressNATs) != 0 {
		t.Fatalf("len(EgressNATs) = %d, want 0 due to overlap", len(compiled.EgressNATs))
	}
	if len(compiled.Warnings) == 0 || !strings.Contains(compiled.Warnings[0], "overlaps egress nat #10") {
		t.Fatalf("Warnings = %v, want overlap warning", compiled.Warnings)
	}
}

func TestParseManagedNetworkProxmoxGuestPort(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    string
		wantVMID string
		wantSlot string
		wantOK   bool
	}{
		{name: "tap", input: "tap100i0", wantVMID: "100", wantSlot: "0", wantOK: true},
		{name: "firewall peer", input: "fwpr101p1", wantVMID: "101", wantSlot: "1", wantOK: true},
		{name: "firewall link", input: "fwln202i0", wantVMID: "202", wantSlot: "0", wantOK: true},
		{name: "trim spaces", input: "  tap303i2  ", wantVMID: "303", wantSlot: "2", wantOK: true},
		{name: "missing slot", input: "tap100i", wantOK: false},
		{name: "bad separator", input: "tap100x0", wantOK: false},
		{name: "uppercase prefix", input: "Tap100i0", wantOK: false},
		{name: "nondigit suffix", input: "fwpr100p0a", wantOK: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotVMID, gotSlot, gotOK := parseManagedNetworkProxmoxGuestPort(tc.input)
			if gotOK != tc.wantOK {
				t.Fatalf("parseManagedNetworkProxmoxGuestPort(%q) ok = %v, want %v", tc.input, gotOK, tc.wantOK)
			}
			if gotVMID != tc.wantVMID || gotSlot != tc.wantSlot {
				t.Fatalf("parseManagedNetworkProxmoxGuestPort(%q) = (%q, %q), want (%q, %q)", tc.input, gotVMID, gotSlot, tc.wantVMID, tc.wantSlot)
			}
		})
	}
}

func TestManagedNetworkUsedIPv6PrefixIndexSingle128(t *testing.T) {
	t.Parallel()

	_, broader, err := normalizeIPv6Prefix("2001:db8:100::/64")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(broader) error = %v", err)
	}
	_, exact, err := normalizeIPv6Prefix("2001:db8:100::1234/128")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(exact) error = %v", err)
	}
	_, other, err := normalizeIPv6Prefix("2001:db8:101::1234/128")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(other) error = %v", err)
	}

	index := newManagedNetworkUsedIPv6PrefixIndex(managedNetworkIPv6AssignmentModeSingle128, []*net.IPNet{broader, exact})
	if !index.overlaps(exact, []*net.IPNet{broader, exact}) {
		t.Fatal("single_128 index should report exact /128 overlap")
	}
	if !index.overlaps(broader, []*net.IPNet{broader, exact}) {
		t.Fatal("single_128 index should fall back for non-/128 candidates")
	}
	if index.overlaps(other, []*net.IPNet{broader, exact}) {
		t.Fatal("single_128 index reported overlap for unrelated /128")
	}
}

func TestManagedNetworkUsedIPv6PrefixIndexPrefix64(t *testing.T) {
	t.Parallel()

	_, broader, err := normalizeIPv6Prefix("2001:db8:100::/56")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(broader) error = %v", err)
	}
	_, exact, err := normalizeIPv6Prefix("2001:db8:100:1::/64")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(exact) error = %v", err)
	}
	_, narrower, err := normalizeIPv6Prefix("2001:db8:100:2::1234/128")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(narrower) error = %v", err)
	}
	_, other, err := normalizeIPv6Prefix("2001:db8:101:1::/64")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix(other) error = %v", err)
	}

	index := newManagedNetworkUsedIPv6PrefixIndex(managedNetworkIPv6AssignmentModePrefix64, []*net.IPNet{broader, exact, narrower})
	if !index.overlaps(exact, []*net.IPNet{broader, exact, narrower}) {
		t.Fatal("prefix_64 index should report exact /64 overlap")
	}
	if !index.overlaps(narrower, []*net.IPNet{broader, exact, narrower}) {
		t.Fatal("prefix_64 index should fall back for non-/64 candidates")
	}
	if index.overlaps(other, []*net.IPNet{broader, exact, narrower}) {
		t.Fatal("prefix_64 index reported overlap for unrelated /64")
	}
}

func TestAllocateManagedNetworkSingleIPv6(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		parent     string
		hashValue  uint64
		wantPrefix string
	}{
		{
			name:       "slash64 keeps lower 64 bits",
			parent:     "2001:db8:100::/64",
			hashValue:  1,
			wantPrefix: "2001:db8:100::1/128",
		},
		{
			name:       "slash120 masks to last octet",
			parent:     "2001:db8:100::/120",
			hashValue:  0x1234,
			wantPrefix: "2001:db8:100::34/128",
		},
		{
			name:       "slash127 allows zero",
			parent:     "2001:db8:100::/127",
			hashValue:  0,
			wantPrefix: "2001:db8:100::/128",
		},
		{
			name:       "slash80 preserves parent bits",
			parent:     "2001:db8:100:200::/80",
			hashValue:  0x1122334455667788,
			wantPrefix: "2001:db8:100:200:0:3344:5566:7788/128",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, parent, err := normalizeIPv6Prefix(tc.parent)
			if err != nil {
				t.Fatalf("normalizeIPv6Prefix(%q) error = %v", tc.parent, err)
			}
			gotPrefix, gotNet, err := allocateManagedNetworkSingleIPv6(parent, tc.hashValue)
			if err != nil {
				t.Fatalf("allocateManagedNetworkSingleIPv6(%q, %d) error = %v", tc.parent, tc.hashValue, err)
			}
			if gotPrefix != tc.wantPrefix {
				t.Fatalf("allocateManagedNetworkSingleIPv6(%q, %d) = %q, want %q", tc.parent, tc.hashValue, gotPrefix, tc.wantPrefix)
			}
			if gotNet == nil || gotNet.String() != tc.wantPrefix {
				t.Fatalf("allocated net = %v, want %q", gotNet, tc.wantPrefix)
			}
		})
	}
}
