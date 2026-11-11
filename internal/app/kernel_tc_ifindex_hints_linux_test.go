//go:build linux

package app

import (
	"maps"
	"testing"
)

func TestBuildKernelTCIfindexHintsCoversEveryRuleFormAndParent(t *testing.T) {
	v4 := func(id int64, ifindex uint32, dst uint32, port uint16) preparedKernelRule {
		return preparedKernelRule{
			rule: Rule{ID: id, Protocol: "tcp"},
			spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
			key:  tcRuleKeyV4{IfIndex: ifindex, DstAddr: dst, DstPort: port, Proto: 6},
		}
	}
	v6 := func(id int64, ifindex int, dst string, port int) preparedKernelRule {
		item := preparedKernelRule{
			rule:      Rule{ID: id, Protocol: "udp", InPort: port},
			inIfIndex: ifindex,
			spec:      kernelPreparedRuleSpec{Family: ipFamilyIPv6},
		}
		if dst != "" {
			item.spec.DstAddr = mustKernelPreparedAddr(t, dst, ipFamilyIPv6)
		}
		return item
	}
	prepared := []preparedKernelRule{
		v4(1, 3, 0xc0000201, 443),
		v4(2, 3, 0, 0),
		v4(3, 5, 0, 8080),
		v4(4, 5, 0xc0000202, 0),
		v6(5, 7, "2001:db8::10", 53),
		v6(6, 7, "", 0),
		v6(7, 3, "", 53),
	}

	hints, err := buildKernelTCIfindexHints(prepared, map[uint32]uint32{9: 5, 3: 2})
	if err != nil {
		t.Fatalf("buildKernelTCIfindexHints() error = %v", err)
	}
	want := kernelTCIfindexHints{
		3: kernelTCIfindexHintRuleExact | kernelTCIfindexHintRuleAny |
			kernelTCIfindexHintRuleAnyAddr<<kernelTCIfindexHintRuleV6Shift | kernelTCIfindexHintHasParent,
		5: kernelTCIfindexHintRuleAnyAddr | kernelTCIfindexHintRuleAnyPort,
		7: (kernelTCIfindexHintRuleExact | kernelTCIfindexHintRuleAny) << kernelTCIfindexHintRuleV6Shift,
		9: kernelTCIfindexHintHasParent,
	}
	if !maps.Equal(hints, want) {
		t.Fatalf("buildKernelTCIfindexHints() = %#v, want %#v", hints, want)
	}
	for ifindex, value := range hints {
		if value&kernelTCIfindexHintKnown != 0 {
			t.Fatalf("hints[%d] = %#x carries the known bit before it is written", ifindex, value)
		}
	}
}

func TestBuildKernelTCIfindexHintsRejectsUnencodableRule(t *testing.T) {
	bad := preparedKernelRule{
		rule: Rule{ID: 0, Protocol: "tcp"},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv6},
	}
	if _, err := buildKernelTCIfindexHints([]preparedKernelRule{bad}, nil); err == nil {
		t.Fatal("buildKernelTCIfindexHints() error = nil, want an error for a rule the maps cannot hold")
	}
}
