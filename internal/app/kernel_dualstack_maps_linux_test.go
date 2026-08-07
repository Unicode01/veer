//go:build linux

package app

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestKernelPreparedRuleMapNames(t *testing.T) {
	rules, flows, nat, err := kernelPreparedRuleMapNames(ipFamilyIPv4)
	if err != nil {
		t.Fatalf("kernelPreparedRuleMapNames(ipv4) error = %v", err)
	}
	if rules != kernelRulesMapNameV4 || flows != kernelFlowsMapNameV4 || nat != kernelNatPortsMapNameV4 {
		t.Fatalf("kernelPreparedRuleMapNames(ipv4) = (%q, %q, %q), want (%q, %q, %q)", rules, flows, nat, kernelRulesMapNameV4, kernelFlowsMapNameV4, kernelNatPortsMapNameV4)
	}

	rules, flows, nat, err = kernelPreparedRuleMapNames(ipFamilyIPv6)
	if err != nil {
		t.Fatalf("kernelPreparedRuleMapNames(ipv6) error = %v", err)
	}
	if rules != kernelRulesMapNameV6 || flows != kernelFlowsMapNameV6 || nat != kernelNatPortsMapNameV6 {
		t.Fatalf("kernelPreparedRuleMapNames(ipv6) = (%q, %q, %q), want (%q, %q, %q)", rules, flows, nat, kernelRulesMapNameV6, kernelFlowsMapNameV6, kernelNatPortsMapNameV6)
	}

	_, _, _, err = kernelPreparedRuleMapNames("bogus")
	if err == nil {
		t.Fatal("kernelPreparedRuleMapNames(bogus) error = nil, want invalid-family rejection")
	}
}

func TestEncodePreparedKernelRuleV6(t *testing.T) {
	item := preparedKernelRule{
		rule: Rule{
			ID:       7,
			InPort:   443,
			OutPort:  8443,
			Protocol: "tcp",
		},
		inIfIndex:  4,
		outIfIndex: 9,
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv6,
			DstAddr:     mustKernelPreparedAddr(t, "2001:db8::10", ipFamilyIPv6),
			BackendAddr: mustKernelPreparedAddr(t, "2001:db8::20", ipFamilyIPv6),
			NATAddr:     mustKernelPreparedAddr(t, "2001:db8::30", ipFamilyIPv6),
		},
		value: tcRuleValueV4{
			Flags:      kernelRuleFlagFullNAT | kernelRuleFlagTrafficStats,
			OutIfIndex: 9,
			SrcMAC:     [6]byte{0, 1, 2, 3, 4, 5},
			DstMAC:     [6]byte{6, 7, 8, 9, 10, 11},
		},
	}

	key, value, err := encodePreparedKernelRuleV6(item)
	if err != nil {
		t.Fatalf("encodePreparedKernelRuleV6() error = %v", err)
	}
	if key.IfIndex != 4 || key.DstPort != 443 || key.Proto != kernelRuleProtocol("tcp") {
		t.Fatalf("encoded key = %+v, want ifindex=4 dstport=443 proto=tcp", key)
	}
	if key.DstAddr != item.spec.DstAddr {
		t.Fatalf("encoded dst addr = %v, want %v", key.DstAddr, item.spec.DstAddr)
	}
	if value.RuleID != 7 || value.BackendPort != 8443 || value.OutIfIndex != 9 {
		t.Fatalf("encoded value = %+v, want rule/out metadata preserved", value)
	}
	if value.BackendAddr != item.spec.BackendAddr || value.NATAddr != item.spec.NATAddr {
		t.Fatalf("encoded value addresses = %+v, want spec-derived backend/nat addresses", value)
	}
	if value.Flags != item.value.Flags || value.SrcMAC != item.value.SrcMAC || value.DstMAC != item.value.DstMAC {
		t.Fatalf("encoded value dataplane extras = %+v, want flags/macs preserved", value)
	}
}

func TestEncodePreparedKernelRuleV6RejectsIPv4Spec(t *testing.T) {
	_, _, err := encodePreparedKernelRuleV6(preparedKernelRule{
		rule: Rule{ID: 1, Protocol: "tcp"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
	})
	if err == nil {
		t.Fatal("encodePreparedKernelRuleV6() error = nil, want family rejection")
	}
}

func TestKernelDualstackMapStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(tcRuleKeyV4{}); got != 12 {
		t.Fatalf("sizeof(tcRuleKeyV4) = %d, want 12", got)
	}
	if got := unsafe.Sizeof(tcRuleValueV4{}); got != 56 {
		t.Fatalf("sizeof(tcRuleValueV4) = %d, want 56", got)
	}
	if got := unsafe.Sizeof(tcFlowKeyV4{}); got != 20 {
		t.Fatalf("sizeof(tcFlowKeyV4) = %d, want 20", got)
	}
	if got := unsafe.Sizeof(tcFlowValueV4{}); got != 64 {
		t.Fatalf("sizeof(tcFlowValueV4) = %d, want 64", got)
	}
	if got := unsafe.Sizeof(tcNATPortKeyV4{}); got != 12 {
		t.Fatalf("sizeof(tcNATPortKeyV4) = %d, want 12", got)
	}
	if got := unsafe.Sizeof(tcNATPortValue{}); got != 16 {
		t.Fatalf("sizeof(tcNATPortValue) = %d, want 16", got)
	}
	if got := unsafe.Sizeof(kernelLocalMACValue{}); got != 8 {
		t.Fatalf("sizeof(kernelLocalMACValue) = %d, want 8", got)
	}
	if got := unsafe.Sizeof(tcRuleKeyV6{}); got != 24 {
		t.Fatalf("sizeof(tcRuleKeyV6) = %d, want 24", got)
	}
	if got := unsafe.Sizeof(tcRuleValueV6{}); got != 64 {
		t.Fatalf("sizeof(tcRuleValueV6) = %d, want 64", got)
	}
	if got := unsafe.Sizeof(tcFlowKeyV6{}); got != 44 {
		t.Fatalf("sizeof(tcFlowKeyV6) = %d, want 44", got)
	}
	if got := unsafe.Sizeof(tcFlowValueV6{}); got != 112 {
		t.Fatalf("sizeof(tcFlowValueV6) = %d, want 112", got)
	}
	if got := unsafe.Sizeof(tcNATPortKeyV6{}); got != 24 {
		t.Fatalf("sizeof(tcNATPortKeyV6) = %d, want 24", got)
	}
	if got := unsafe.Sizeof(xdpRuleValueV4{}); got != 40 {
		t.Fatalf("sizeof(xdpRuleValueV4) = %d, want 40", got)
	}
	if got := unsafe.Sizeof(xdpRuleValueV6{}); got != 64 {
		t.Fatalf("sizeof(xdpRuleValueV6) = %d, want 64", got)
	}
	if got := unsafe.Sizeof(xdpFlowValueV4{}); got != 72 {
		t.Fatalf("sizeof(xdpFlowValueV4) = %d, want 72", got)
	}
	if got := binary.Size(kernelOccupancyValueV4{}); got != 32 {
		t.Fatalf("binary.Size(kernelOccupancyValueV4) = %d, want 32", got)
	}
	if got := unsafe.Sizeof(kernelOccupancyValueV4{}); got != 32 {
		t.Fatalf("sizeof(kernelOccupancyValueV4) = %d, want 32", got)
	}
}

func TestSamePreparedKernelRuleDataplaneDetectsSpecDifference(t *testing.T) {
	base := preparedKernelRule{
		rule:       Rule{ID: 9, Protocol: "tcp"},
		inIfIndex:  1,
		outIfIndex: 2,
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv4,
			DstAddr:     mustKernelPreparedAddr(t, "198.51.100.10", ipFamilyIPv4),
			BackendAddr: mustKernelPreparedAddr(t, "192.0.2.20", ipFamilyIPv4),
		},
		key:   tcRuleKeyV4{IfIndex: 1, DstAddr: 1, DstPort: 443, Proto: 6},
		value: tcRuleValueV4{RuleID: 9, BackendAddr: 2, BackendPort: 8443, OutIfIndex: 2},
	}
	diff := base
	diff.spec.Family = ipFamilyIPv6
	diff.spec.DstAddr = mustKernelPreparedAddr(t, "2001:db8::10", ipFamilyIPv6)
	diff.spec.BackendAddr = mustKernelPreparedAddr(t, "2001:db8::20", ipFamilyIPv6)

	if samePreparedKernelRuleDataplane(base, diff) {
		t.Fatal("samePreparedKernelRuleDataplane() = true, want false when prepared spec changes")
	}
}

func TestKernelPreparedRuleFamilyFallsBackToRuleIPs(t *testing.T) {
	item := preparedKernelRule{
		rule: Rule{
			InIP:  "2001:db8::10",
			OutIP: "2001:db8::20",
		},
	}
	if got := kernelPreparedRuleFamily(item); got != ipFamilyIPv6 {
		t.Fatalf("kernelPreparedRuleFamily() = %q, want %q", got, ipFamilyIPv6)
	}
}

func TestPreparedXDPKernelRuleFlowRevisionNormalizesXDPFlags(t *testing.T) {
	base := preparedXDPKernelRule{
		rule:  Rule{ID: 17, Protocol: "udp"},
		spec:  kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		keyV4: tcRuleKeyV4{IfIndex: 3, DstAddr: 0xc0000201, DstPort: 443, Proto: 17},
		valueV4: xdpRuleValueV4{
			RuleID:      17,
			BackendAddr: 0xc0000202,
			BackendPort: 8443,
			Flags:       xdpRuleFlagFullNAT | xdpRuleFlagEgressNAT,
			OutIfIndex:  4,
			NATAddr:     0xc0000203,
		},
	}
	if err := assignPreparedXDPKernelRuleRevision(&base); err != nil {
		t.Fatalf("assignPreparedXDPKernelRuleRevision(base) error = %v", err)
	}

	nonFlowChange := base
	nonFlowChange.valueV4.Revision = 0
	nonFlowChange.valueV4.Flags |= xdpRuleFlagBridgeL2 | xdpRuleFlagBridgeIngressL2 | xdpRuleFlagTrafficStats | xdpRuleFlagPreparedL2
	if err := assignPreparedXDPKernelRuleRevision(&nonFlowChange); err != nil {
		t.Fatalf("assignPreparedXDPKernelRuleRevision(non-flow flags) error = %v", err)
	}
	if nonFlowChange.valueV4.Revision != base.valueV4.Revision {
		t.Fatalf("non-flow XDP flags changed revision from %#x to %#x", base.valueV4.Revision, nonFlowChange.valueV4.Revision)
	}

	fullCone := base
	fullCone.valueV4.Revision = 0
	fullCone.valueV4.Flags |= xdpRuleFlagFullCone
	if err := assignPreparedXDPKernelRuleRevision(&fullCone); err != nil {
		t.Fatalf("assignPreparedXDPKernelRuleRevision(full-cone) error = %v", err)
	}
	if fullCone.valueV4.Revision == base.valueV4.Revision {
		t.Fatalf("full-cone XDP flag kept revision %#x, want flow contract change", base.valueV4.Revision)
	}
}

func mustKernelPreparedAddr(t *testing.T, literal string, family string) kernelPreparedAddr {
	t.Helper()
	addr, err := kernelPreparedAddrFromIP(parseIPLiteral(literal), family)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP(%q, %q): %v", literal, family, err)
	}
	return addr
}
