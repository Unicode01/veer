//go:build linux

package app

import (
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestPrepareXDPKernelRulesDoesNotPreRejectFullNAT(t *testing.T) {
	rule := Rule{
		ID:           1,
		InInterface:  "missing-in",
		InIP:         "192.0.2.10",
		InPort:       8443,
		OutInterface: "missing-out",
		OutIP:        "198.51.100.20",
		OutPort:      443,
		OutSourceIP:  "198.51.100.30",
		Protocol:     "tcp",
		Transparent:  false,
	}

	_, _, _, results, _ := prepareXDPKernelRules([]Rule{rule}, xdpPrepareOptions{}, nil, false)
	result, ok := results[rule.ID]
	if !ok {
		t.Fatalf("missing prepare result for rule %d", rule.ID)
	}
	if result.Error == "" {
		t.Fatalf("prepare result error = empty, want failure from interface resolution")
	}
	if strings.Contains(result.Error, "supports only transparent rules") {
		t.Fatalf("prepare result error = %q, want non-transparent XDP preparation to continue past the old hard gate", result.Error)
	}
	if !strings.Contains(result.Error, `resolve inbound interface "missing-in"`) {
		t.Fatalf("prepare result error = %q, want inbound interface resolution failure", result.Error)
	}
}

func TestPrepareXDPKernelRulesDoesNotPreRejectEgressNATTCP(t *testing.T) {
	rule := Rule{
		ID:            1,
		InInterface:   "missing-in",
		InIP:          "0.0.0.0",
		OutInterface:  "missing-out",
		OutIP:         "0.0.0.0",
		OutPort:       0,
		OutSourceIP:   "198.51.100.30",
		Protocol:      "tcp",
		Transparent:   false,
		kernelMode:    kernelModeEgressNAT,
		kernelNATType: egressNATTypeSymmetric,
	}

	_, _, _, results, _ := prepareXDPKernelRules([]Rule{rule}, xdpPrepareOptions{}, nil, false)
	result, ok := results[rule.ID]
	if !ok {
		t.Fatalf("missing prepare result for rule %d", rule.ID)
	}
	if result.Error == "" {
		t.Fatalf("prepare result error = empty, want failure from interface resolution")
	}
	if strings.Contains(result.Error, "does not support egress nat takeover") {
		t.Fatalf("prepare result error = %q, want egress nat XDP preparation to continue past the old hard gate", result.Error)
	}
	if !strings.Contains(result.Error, `resolve inbound interface "missing-in"`) {
		t.Fatalf("prepare result error = %q, want inbound interface resolution failure", result.Error)
	}
}

func TestPrepareXDPKernelRulesDoesNotPreRejectEgressNATICMP(t *testing.T) {
	rule := Rule{
		ID:            1,
		InInterface:   "missing-in",
		InIP:          "0.0.0.0",
		OutInterface:  "missing-out",
		OutIP:         "0.0.0.0",
		OutPort:       0,
		OutSourceIP:   "198.51.100.30",
		Protocol:      "icmp",
		Transparent:   false,
		kernelMode:    kernelModeEgressNAT,
		kernelNATType: egressNATTypeSymmetric,
	}

	_, _, _, results, _ := prepareXDPKernelRules([]Rule{rule}, xdpPrepareOptions{}, nil, false)
	result, ok := results[rule.ID]
	if !ok {
		t.Fatalf("missing prepare result for rule %d", rule.ID)
	}
	if result.Error == "" {
		t.Fatalf("prepare result error = empty, want failure from interface resolution")
	}
	if strings.Contains(result.Error, "supports only single-protocol TCP/UDP") {
		t.Fatalf("prepare result error = %q, want ICMP egress nat XDP preparation to continue past protocol gating", result.Error)
	}
	if !strings.Contains(result.Error, `resolve inbound interface "missing-in"`) {
		t.Fatalf("prepare result error = %q, want inbound interface resolution failure", result.Error)
	}
}

func TestXDPUnsupportedEgressNATInboundReason(t *testing.T) {
	if reason := xdpUnsupportedEgressNATInboundReason(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 1}}); reason != "" {
		t.Fatalf("xdpUnsupportedEgressNATInboundReason(device) = %q, want empty", reason)
	}

	reason := xdpUnsupportedEgressNATInboundReason(&netlink.Device{
		LinkAttrs: netlink.LinkAttrs{Index: 2, MasterIndex: 10},
	})
	if !strings.Contains(reason, "bridge-enslaved inbound interfaces") {
		t.Fatalf("xdpUnsupportedEgressNATInboundReason(bridge-slave) = %q, want bridge-slave rejection", reason)
	}
}

func TestXDPVethNATRedirectGuardReasonForRelease(t *testing.T) {
	reason := xdpVethNATRedirectGuardReasonForRelease("5.10.0-39-amd64")
	if !strings.Contains(reason, "nat redirect over veth is disabled") {
		t.Fatalf("xdpVethNATRedirectGuardReasonForRelease(5.10) = %q, want legacy-kernel rejection", reason)
	}
	if !strings.Contains(reason, "kernel 5.11+") {
		t.Fatalf("xdpVethNATRedirectGuardReasonForRelease(5.10) = %q, want upgrade hint", reason)
	}
}

func TestXDPVethNATRedirectGuardReasonForReleaseAllowsModernKernel(t *testing.T) {
	if reason := xdpVethNATRedirectGuardReasonForRelease("6.1.0-17-amd64"); reason != "" {
		t.Fatalf("xdpVethNATRedirectGuardReasonForRelease(6.1) = %q, want empty", reason)
	}
}

func TestXDPPreferGenericAttach(t *testing.T) {
	if !xdpPreferGenericAttach(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: 1}}) {
		t.Fatal("xdpPreferGenericAttach(veth) = false, want true")
	}

	if !xdpPreferGenericAttach(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 2, MasterIndex: 10}}) {
		t.Fatal("xdpPreferGenericAttach(bridge-slave) = false, want true")
	}

	if xdpPreferGenericAttach(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 3}}) {
		t.Fatal("xdpPreferGenericAttach(device) = true, want false")
	}
}

func TestKernelPreparedAddrIPv4Uint32(t *testing.T) {
	addr, err := kernelPreparedAddrFromIP(net.ParseIP("198.51.100.20"), ipFamilyIPv4)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP() error = %v", err)
	}
	got, err := addr.ipv4Uint32()
	if err != nil {
		t.Fatalf("ipv4Uint32() error = %v", err)
	}
	want := ipv4BytesToUint32(net.ParseIP("198.51.100.20"))
	if got != want {
		t.Fatalf("ipv4Uint32() = %#x, want %#x", got, want)
	}
}

func TestValidateXDPCollectionSpecRequiresIPv6MapSet(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelXDPProgramName:                 &ebpf.ProgramSpec{},
			kernelXDPProgramV4Name:               &ebpf.ProgramSpec{},
			kernelXDPProgramV6Name:               &ebpf.ProgramSpec{},
			kernelXDPProgramV4TransparentName:    &ebpf.ProgramSpec{},
			kernelXDPProgramV4FullNATForwardName: &ebpf.ProgramSpec{},
			kernelXDPProgramV4FullNATReplyName:   &ebpf.ProgramSpec{},
			kernelXDPProgramV6FullNATForwardName: &ebpf.ProgramSpec{},
			kernelXDPProgramV6FullNATReplyName:   &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:               &ebpf.MapSpec{},
			kernelFlowsMapNameV4:               &ebpf.MapSpec{Type: ebpf.Hash},
			kernelStatsMapName:                 &ebpf.MapSpec{},
			kernelXDPRedirectMapName:           &ebpf.MapSpec{},
			kernelXDPProgramChainMapName:       &ebpf.MapSpec{},
			kernelXDPFIBScratchMapName:         &ebpf.MapSpec{},
			kernelXDPFlowScratchV4MapName:      &ebpf.MapSpec{},
			kernelXDPFlowAuxScratchV4MapName:   &ebpf.MapSpec{},
			kernelXDPFlowScratchV6MapName:      &ebpf.MapSpec{},
			kernelXDPFlowAuxScratchV6MapName:   &ebpf.MapSpec{},
			kernelXDPDispatchScratchV4MapName:  &ebpf.MapSpec{},
			kernelXDPDispatchScratchV6MapName:  &ebpf.MapSpec{},
			kernelXDPFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelXDPFlowsOldMapNameV4:         &ebpf.MapSpec{Type: ebpf.Hash},
			kernelXDPFlowsOldMapNameV6:         &ebpf.MapSpec{Type: ebpf.Hash},
		},
	}

	if err := validateXDPCollectionSpec(spec); err == nil {
		t.Fatal("validateXDPCollectionSpec() error = nil, want missing IPv6 map set error")
	}

	spec.Maps[kernelRulesMapNameV6] = &ebpf.MapSpec{}
	spec.Maps[kernelFlowsMapNameV6] = &ebpf.MapSpec{Type: ebpf.Hash}
	if err := validateXDPCollectionSpec(spec); err != nil {
		t.Fatalf("validateXDPCollectionSpec() error = %v, want nil with dual-stack map set", err)
	}
}

func TestValidateXDPCollectionSpecRejectsLRUFlowBanks(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			kernelXDPProgramName:                 &ebpf.ProgramSpec{},
			kernelXDPProgramV4Name:               &ebpf.ProgramSpec{},
			kernelXDPProgramV6Name:               &ebpf.ProgramSpec{},
			kernelXDPProgramV4TransparentName:    &ebpf.ProgramSpec{},
			kernelXDPProgramV4FullNATForwardName: &ebpf.ProgramSpec{},
			kernelXDPProgramV4FullNATReplyName:   &ebpf.ProgramSpec{},
			kernelXDPProgramV6FullNATForwardName: &ebpf.ProgramSpec{},
			kernelXDPProgramV6FullNATReplyName:   &ebpf.ProgramSpec{},
		},
		Maps: map[string]*ebpf.MapSpec{
			kernelRulesMapNameV4:               &ebpf.MapSpec{},
			kernelFlowsMapNameV4:               &ebpf.MapSpec{Type: ebpf.LRUHash},
			kernelStatsMapName:                 &ebpf.MapSpec{},
			kernelXDPRedirectMapName:           &ebpf.MapSpec{},
			kernelXDPProgramChainMapName:       &ebpf.MapSpec{},
			kernelXDPFIBScratchMapName:         &ebpf.MapSpec{},
			kernelXDPFlowScratchV4MapName:      &ebpf.MapSpec{},
			kernelXDPFlowAuxScratchV4MapName:   &ebpf.MapSpec{},
			kernelXDPFlowScratchV6MapName:      &ebpf.MapSpec{},
			kernelXDPFlowAuxScratchV6MapName:   &ebpf.MapSpec{},
			kernelXDPDispatchScratchV4MapName:  &ebpf.MapSpec{},
			kernelXDPDispatchScratchV6MapName:  &ebpf.MapSpec{},
			kernelXDPFlowMigrationStateMapName: &ebpf.MapSpec{},
			kernelRulesMapNameV6:               &ebpf.MapSpec{},
			kernelFlowsMapNameV6:               &ebpf.MapSpec{Type: ebpf.Hash},
			kernelXDPFlowsOldMapNameV4:         &ebpf.MapSpec{Type: ebpf.Hash},
			kernelXDPFlowsOldMapNameV6:         &ebpf.MapSpec{Type: ebpf.Hash},
		},
	}

	if err := validateXDPCollectionSpec(spec); err == nil {
		t.Fatal("validateXDPCollectionSpec() error = nil, want flow map type rejection")
	}
}

func TestLoadEmbeddedXDPCollectionSpecUsesHashFlowBanks(t *testing.T) {
	for _, enableTrafficStats := range []bool{false, true} {
		spec, err := loadEmbeddedXDPCollectionSpec(enableTrafficStats)
		if err != nil {
			t.Fatalf("loadEmbeddedXDPCollectionSpec(%t) error = %v", enableTrafficStats, err)
		}
		for _, name := range []string{
			kernelFlowsMapNameV4,
			kernelFlowsMapNameV6,
			kernelXDPFlowsOldMapNameV4,
			kernelXDPFlowsOldMapNameV6,
		} {
			if got := spec.Maps[name].Type; got != ebpf.Hash {
				t.Fatalf("loadEmbeddedXDPCollectionSpec(%t) map %q type = %v, want %v", enableTrafficStats, name, got, ebpf.Hash)
			}
		}
	}
}

func TestLookupXDPCollectionPiecesRejectsIncompleteIPv6MapSet(t *testing.T) {
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelXDPProgramName:                 &ebpf.Program{},
			kernelXDPProgramV4Name:               &ebpf.Program{},
			kernelXDPProgramV6Name:               &ebpf.Program{},
			kernelXDPProgramV4TransparentName:    &ebpf.Program{},
			kernelXDPProgramV4FullNATForwardName: &ebpf.Program{},
			kernelXDPProgramV4FullNATReplyName:   &ebpf.Program{},
			kernelXDPProgramV6FullNATForwardName: &ebpf.Program{},
			kernelXDPProgramV6FullNATReplyName:   &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:               &ebpf.Map{},
			kernelFlowsMapNameV4:               &ebpf.Map{},
			kernelXDPFlowsOldMapNameV4:         &ebpf.Map{},
			kernelRulesMapNameV6:               &ebpf.Map{},
			kernelXDPFlowMigrationStateMapName: &ebpf.Map{},
			kernelXDPProgramChainMapName:       &ebpf.Map{},
		},
	}

	if _, err := lookupXDPCollectionPieces(coll); err == nil {
		t.Fatal("lookupXDPCollectionPieces() error = nil, want incomplete IPv6 map set error")
	}
}

func TestLookupXDPCollectionPiecesIncludesLocalIPv4MapWhenPresent(t *testing.T) {
	localMap := &ebpf.Map{}
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{
			kernelXDPProgramName:                 &ebpf.Program{},
			kernelXDPProgramV4Name:               &ebpf.Program{},
			kernelXDPProgramV6Name:               &ebpf.Program{},
			kernelXDPProgramV4TransparentName:    &ebpf.Program{},
			kernelXDPProgramV4FullNATForwardName: &ebpf.Program{},
			kernelXDPProgramV4FullNATReplyName:   &ebpf.Program{},
			kernelXDPProgramV6FullNATForwardName: &ebpf.Program{},
			kernelXDPProgramV6FullNATReplyName:   &ebpf.Program{},
		},
		Maps: map[string]*ebpf.Map{
			kernelRulesMapNameV4:               &ebpf.Map{},
			kernelFlowsMapNameV4:               &ebpf.Map{},
			kernelXDPFlowsOldMapNameV4:         &ebpf.Map{},
			kernelRulesMapNameV6:               &ebpf.Map{},
			kernelFlowsMapNameV6:               &ebpf.Map{},
			kernelXDPFlowsOldMapNameV6:         &ebpf.Map{},
			kernelXDPRedirectMapName:           &ebpf.Map{},
			kernelXDPFlowMigrationStateMapName: &ebpf.Map{},
			kernelXDPProgramChainMapName:       &ebpf.Map{},
			kernelLocalIPv4MapName:             localMap,
		},
	}

	pieces, err := lookupXDPCollectionPieces(coll)
	if err != nil {
		t.Fatalf("lookupXDPCollectionPieces() error = %v, want nil", err)
	}
	if pieces.localIPv4s != localMap {
		t.Fatalf("lookupXDPCollectionPieces() localIPv4s = %p, want %p", pieces.localIPv4s, localMap)
	}
}

func TestBuildPreparedXDPKernelRuleBatchesSplitsFamilies(t *testing.T) {
	in6 := net.ParseIP("2001:db8::10").To16()
	out6 := net.ParseIP("2001:db8::20").To16()
	if in6 == nil || out6 == nil {
		t.Fatal("parse IPv6 fixtures")
	}
	var dstAddr6 kernelPreparedAddr
	var backendAddr6 kernelPreparedAddr
	var ruleBackendAddr6 [16]byte
	copy(dstAddr6[:], in6)
	copy(backendAddr6[:], out6)
	copy(ruleBackendAddr6[:], out6)

	prepared := []preparedXDPKernelRule{
		{
			rule: Rule{ID: 1, InIP: "192.0.2.10", OutIP: "198.51.100.20"},
			spec: kernelPreparedRuleSpec{
				Family:      ipFamilyIPv4,
				DstAddr:     kernelPreparedAddrFromIPv4Uint32(0xc000020a),
				BackendAddr: kernelPreparedAddrFromIPv4Uint32(0xc6336414),
			},
			keyV4: tcRuleKeyV4{IfIndex: 2, DstPort: 80, Proto: 6},
			valueV4: xdpRuleValueV4{
				RuleID:      1,
				BackendAddr: 0xc6336414,
				BackendPort: 8080,
				OutIfIndex:  3,
			},
		},
		{
			rule: Rule{ID: 2, InIP: "2001:db8::10", OutIP: "2001:db8::20"},
			spec: kernelPreparedRuleSpec{
				Family:      ipFamilyIPv6,
				DstAddr:     dstAddr6,
				BackendAddr: backendAddr6,
			},
			keyV6: tcRuleKeyV6{IfIndex: 5, DstPort: 443, Proto: 17},
			valueV6: xdpRuleValueV6{
				RuleID:      2,
				BackendAddr: ruleBackendAddr6,
				BackendPort: 8443,
				OutIfIndex:  6,
			},
		},
	}

	batches, err := buildPreparedXDPKernelRuleBatches(prepared)
	if err != nil {
		t.Fatalf("buildPreparedXDPKernelRuleBatches() error = %v", err)
	}
	if len(batches.v4Keys) != 1 || len(batches.v4Values) != 1 {
		t.Fatalf("IPv4 batch sizes = %d/%d, want 1/1", len(batches.v4Keys), len(batches.v4Values))
	}
	if len(batches.v6Keys) != 1 || len(batches.v6Values) != 1 {
		t.Fatalf("IPv6 batch sizes = %d/%d, want 1/1", len(batches.v6Keys), len(batches.v6Values))
	}
	if batches.v4Values[0].RuleID != 1 || batches.v6Values[0].RuleID != 2 {
		t.Fatalf("unexpected batched rule ids: v4=%d v6=%d", batches.v4Values[0].RuleID, batches.v6Values[0].RuleID)
	}
}

func TestNewXDPKernelRuleRuntimeDisablesGenericAttachByDefault(t *testing.T) {
	rt, ok := newXDPKernelRuleRuntime(nil).(*xdpKernelRuleRuntime)
	if !ok {
		t.Fatal("newXDPKernelRuleRuntime(nil) did not return *xdpKernelRuleRuntime")
	}
	if rt.allowGenericAttach {
		t.Fatal("allowGenericAttach = true, want false by default")
	}

	rt, ok = newXDPKernelRuleRuntime(&Config{
		Experimental: map[string]bool{
			experimentalFeatureXDPGeneric: true,
		},
	}).(*xdpKernelRuleRuntime)
	if !ok {
		t.Fatal("newXDPKernelRuleRuntime(config) did not return *xdpKernelRuleRuntime")
	}
	if !rt.allowGenericAttach {
		t.Fatal("allowGenericAttach = false, want true when xdp_generic is enabled")
	}
}

func TestXDPAttachOrderHonorsGenericExperiment(t *testing.T) {
	tests := []struct {
		name           string
		link           netlink.Link
		oldAttachments []xdpAttachment
		allowGeneric   bool
		want           []int
	}{
		{
			name:         "device defaults to driver only when generic disabled",
			link:         &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 1}},
			allowGeneric: false,
			want:         []int{nl.XDP_FLAGS_DRV_MODE},
		},
		{
			name:         "veth stays driver only when generic disabled",
			link:         &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: 2}},
			allowGeneric: false,
			want:         []int{nl.XDP_FLAGS_DRV_MODE},
		},
		{
			name:         "veth prefers generic when explicitly enabled",
			link:         &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Index: 3}},
			allowGeneric: true,
			want:         []int{nl.XDP_FLAGS_SKB_MODE, nl.XDP_FLAGS_DRV_MODE},
		},
		{
			name:         "bridge slave prefers generic when explicitly enabled",
			link:         &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 5, MasterIndex: 99}},
			allowGeneric: true,
			want:         []int{nl.XDP_FLAGS_SKB_MODE, nl.XDP_FLAGS_DRV_MODE},
		},
		{
			name: "existing generic attachment stays preferred when explicitly enabled",
			link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 4}},
			oldAttachments: []xdpAttachment{
				{ifindex: 4, flags: nl.XDP_FLAGS_SKB_MODE},
			},
			allowGeneric: true,
			want:         []int{nl.XDP_FLAGS_SKB_MODE, nl.XDP_FLAGS_DRV_MODE},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := xdpAttachOrder(tc.link, tc.oldAttachments, tc.allowGeneric); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("xdpAttachOrder() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestXDPGenericAttachmentExperimentalReason(t *testing.T) {
	got := xdpGenericAttachmentExperimentalReason()
	want := `xdp dataplane generic/mixed attachment requires experimental feature "xdp_generic"`
	if got != want {
		t.Fatalf("xdpGenericAttachmentExperimentalReason() = %q, want %q", got, want)
	}
}
