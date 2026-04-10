//go:build linux

package app

import (
	"net"
	"testing"
)

func TestSameKernelRuleDataplaneConfig(t *testing.T) {
	base := Rule{
		ID:           101,
		InInterface:  "vmbr0",
		InIP:         "0.0.0.0",
		InPort:       10022,
		OutInterface: "vmbr1",
		OutIP:        "192.0.2.5",
		OutSourceIP:  "198.51.100.10",
		OutPort:      22,
		Protocol:     "tcp",
		Transparent:  false,
		Remark:       "ignored",
		Tag:          "ignored",
	}
	same := base
	same.Remark = "changed"
	same.Tag = "changed"
	if !sameKernelRuleDataplaneConfig(base, same) {
		t.Fatal("sameKernelRuleDataplaneConfig() = false, want true when only remark/tag changed")
	}
	same.ID = 202
	if !sameKernelRuleDataplaneConfig(base, same) {
		t.Fatal("sameKernelRuleDataplaneConfig() = false, want true when only synthetic id changed")
	}

	diff := base
	diff.OutSourceIP = "198.51.100.11"
	if sameKernelRuleDataplaneConfig(base, diff) {
		t.Fatal("sameKernelRuleDataplaneConfig() = true, want false when dataplane fields changed")
	}
}

func TestSameKernelRuleOwnerDataplaneConfig(t *testing.T) {
	base := Rule{
		ID:               1001,
		InInterface:      "vmbr0",
		InIP:             "198.51.100.10",
		InPort:           20022,
		OutInterface:     "vmbr1",
		OutIP:            "192.0.2.6",
		OutPort:          22,
		Protocol:         "tcp",
		Transparent:      true,
		kernelLogKind:    workerKindRange,
		kernelLogOwnerID: 88,
	}

	same := base
	same.ID = 1002
	if !sameKernelRuleOwnerDataplaneConfig(base, same) {
		t.Fatal("sameKernelRuleOwnerDataplaneConfig() = false, want true when only synthetic id changed")
	}

	diffOwner := same
	diffOwner.kernelLogOwnerID = 89
	if sameKernelRuleOwnerDataplaneConfig(base, diffOwner) {
		t.Fatal("sameKernelRuleOwnerDataplaneConfig() = true, want false when owner changed")
	}
}

func TestShouldReuseKernelRuleAfterPrepareFailure(t *testing.T) {
	rule := Rule{
		ID:               7,
		InInterface:      "vmbr0",
		InIP:             "198.51.100.10",
		InPort:           20022,
		OutInterface:     "vmbr1",
		OutIP:            "192.0.2.6",
		OutPort:          22,
		Protocol:         "tcp",
		Transparent:      true,
		kernelLogKind:    workerKindRange,
		kernelLogOwnerID: 55,
	}

	if !shouldReuseKernelRuleAfterPrepareFailure(rule, rule, `resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`, true) {
		t.Fatal("shouldReuseKernelRuleAfterPrepareFailure() = false, want true for transient failure with unchanged rule")
	}
	syntheticShift := rule
	syntheticShift.ID = 7001
	if !shouldReuseKernelRuleAfterPrepareFailure(rule, syntheticShift, `resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`, true) {
		t.Fatal("shouldReuseKernelRuleAfterPrepareFailure() = false, want true when only synthetic id changed")
	}
	if shouldReuseKernelRuleAfterPrepareFailure(rule, rule, `create kernel collection: verifier rejected program`, true) {
		t.Fatal("shouldReuseKernelRuleAfterPrepareFailure() = true, want false for non-transient failure")
	}
	changed := rule
	changed.OutIP = "192.0.2.7"
	if shouldReuseKernelRuleAfterPrepareFailure(rule, changed, `resolve outbound path on "vmbr1": no learned IPv4 neighbor entry was found`, true) {
		t.Fatal("shouldReuseKernelRuleAfterPrepareFailure() = true, want false when rule config changed")
	}
	if shouldReuseKernelRuleAfterPrepareFailure(rule, rule, `resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`, false) {
		t.Fatal("shouldReuseKernelRuleAfterPrepareFailure() = true, want false when transient reuse is disabled")
	}
}

func TestMatchDesiredKernelRuleAllowsSyntheticIDDrift(t *testing.T) {
	current := Rule{
		ID:               1001,
		InInterface:      "vmbr0",
		InIP:             "198.51.100.10",
		InPort:           20022,
		OutInterface:     "vmbr1",
		OutIP:            "192.0.2.6",
		OutPort:          22,
		Protocol:         "tcp",
		Transparent:      true,
		kernelLogKind:    workerKindRange,
		kernelLogOwnerID: 55,
	}
	desired := current
	desired.ID = 2001

	matched, ok := matchDesiredKernelRule(indexKernelRulesByMatchKey([]Rule{desired}), current)
	if !ok {
		t.Fatal("matchDesiredKernelRule() = false, want true when only synthetic id changed")
	}
	if matched.ID != desired.ID {
		t.Fatalf("matchDesiredKernelRule() id = %d, want %d", matched.ID, desired.ID)
	}
}

func TestSamePreparedKernelRuleDataplane(t *testing.T) {
	baseRule := Rule{
		ID:           11,
		InInterface:  "vmbr0",
		InIP:         "198.51.100.10",
		InPort:       20022,
		OutInterface: "vmbr1",
		OutIP:        "192.0.2.6",
		OutPort:      22,
		Protocol:     "tcp",
		Transparent:  true,
		Remark:       "before",
		Tag:          "before",
	}
	base := preparedKernelRule{
		rule:       baseRule,
		inIfIndex:  2,
		outIfIndex: 3,
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 1,
			DstPort: 20022,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      11,
			BackendAddr: 2,
			BackendPort: 22,
			OutIfIndex:  3,
		},
	}

	same := base
	same.rule.Remark = "after"
	same.rule.Tag = "after"
	if !samePreparedKernelRuleDataplane(base, same) {
		t.Fatal("samePreparedKernelRuleDataplane() = false, want true when only metadata changed")
	}

	diff := base
	diff.value.BackendPort = 2222
	if samePreparedKernelRuleDataplane(base, diff) {
		t.Fatal("samePreparedKernelRuleDataplane() = true, want false when dataplane changes")
	}
}

func TestSamePreparedXDPKernelRuleDataplane(t *testing.T) {
	baseRule := Rule{
		ID:           12,
		InInterface:  "eno1",
		InIP:         "0.0.0.0",
		InPort:       10022,
		OutInterface: "vmbr1",
		OutIP:        "192.0.2.5",
		OutPort:      22,
		Protocol:     "tcp",
		Transparent:  true,
		Remark:       "before",
	}
	base := preparedXDPKernelRule{
		rule:       baseRule,
		inIfIndex:  5,
		outIfIndex: 8,
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv4,
			DstAddr:     kernelPreparedAddrFromIPv4Uint32(0),
			BackendAddr: kernelPreparedAddrFromIPv4Uint32(9),
		},
		keyV4: tcRuleKeyV4{
			IfIndex: 5,
			DstPort: 10022,
			Proto:   6,
		},
		valueV4: xdpRuleValueV4{
			RuleID:      12,
			BackendAddr: 9,
			BackendPort: 22,
			OutIfIndex:  8,
		},
	}

	same := base
	same.rule.Remark = "after"
	if !samePreparedXDPKernelRuleDataplane(base, same) {
		t.Fatal("samePreparedXDPKernelRuleDataplane() = false, want true when only metadata changed")
	}

	diff := base
	diff.keyV4.DstPort = 10023
	if samePreparedXDPKernelRuleDataplane(base, diff) {
		t.Fatal("samePreparedXDPKernelRuleDataplane() = true, want false when dataplane changes")
	}
}

func TestSamePreparedXDPKernelRuleDataplaneIPv6(t *testing.T) {
	inAddr := net.ParseIP("2001:db8::10").To16()
	backendAddr := net.ParseIP("2001:db8::20").To16()
	natAddr := net.ParseIP("2001:db8::30").To16()
	if inAddr == nil || backendAddr == nil || natAddr == nil {
		t.Fatal("parse IPv6 fixtures")
	}

	var dst kernelPreparedAddr
	var backend kernelPreparedAddr
	var nat kernelPreparedAddr
	var valueBackend [16]byte
	var valueNAT [16]byte
	copy(dst[:], inAddr)
	copy(backend[:], backendAddr)
	copy(nat[:], natAddr)
	copy(valueBackend[:], backendAddr)
	copy(valueNAT[:], natAddr)

	baseRule := Rule{
		ID:           13,
		InInterface:  "eno1",
		InIP:         "2001:db8::10",
		InPort:       10022,
		OutInterface: "vmbr1",
		OutIP:        "2001:db8::20",
		OutPort:      22,
		OutSourceIP:  "2001:db8::30",
		Protocol:     "udp",
		Transparent:  false,
		Remark:       "before",
	}
	base := preparedXDPKernelRule{
		rule:       baseRule,
		inIfIndex:  5,
		outIfIndex: 8,
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv6,
			DstAddr:     dst,
			BackendAddr: backend,
			NATAddr:     nat,
		},
		keyV6: tcRuleKeyV6{
			IfIndex: 5,
			DstAddr: [16]byte(dst),
			DstPort: 10022,
			Proto:   17,
		},
		valueV6: xdpRuleValueV6{
			RuleID:      13,
			BackendAddr: valueBackend,
			BackendPort: 22,
			Flags:       xdpRuleFlagFullNAT,
			OutIfIndex:  8,
			NATAddr:     valueNAT,
		},
	}

	same := base
	same.rule.Remark = "after"
	if !samePreparedXDPKernelRuleDataplane(base, same) {
		t.Fatal("samePreparedXDPKernelRuleDataplane() = false, want true for IPv6 when only metadata changed")
	}

	diff := base
	diff.valueV6.NATAddr[15]++
	if samePreparedXDPKernelRuleDataplane(base, diff) {
		t.Fatal("samePreparedXDPKernelRuleDataplane() = true, want false when IPv6 dataplane changes")
	}
}

func TestDiffPreparedKernelRulesIgnoresMetadataOnlyChanges(t *testing.T) {
	base := preparedKernelRule{
		rule: Rule{
			ID:           21,
			InInterface:  "vmbr0",
			InIP:         "198.51.100.10",
			InPort:       20022,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.6",
			OutPort:      22,
			Protocol:     "tcp",
			Transparent:  true,
			Remark:       "before",
		},
		inIfIndex:  2,
		outIfIndex: 3,
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 1,
			DstPort: 20022,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      21,
			BackendAddr: 2,
			BackendPort: 22,
			OutIfIndex:  3,
		},
	}

	next := base
	next.rule.Remark = "after"
	next.rule.Tag = "after"

	diff, err := diffPreparedKernelRules([]preparedKernelRule{base}, []preparedKernelRule{next})
	if err != nil {
		t.Fatalf("diffPreparedKernelRules() error = %v", err)
	}
	if kernelDualStackRuleMapDiffUpsertCount(diff) != 0 {
		t.Fatalf("diffPreparedKernelRules() upserts = %d, want 0", kernelDualStackRuleMapDiffUpsertCount(diff))
	}
	if kernelDualStackRuleMapDiffDeleteCount(diff) != 0 {
		t.Fatalf("diffPreparedKernelRules() deletes = %d, want 0", kernelDualStackRuleMapDiffDeleteCount(diff))
	}
}

func TestDiffPreparedKernelRulesDetectsUpsertsAndDeletes(t *testing.T) {
	oldA := preparedKernelRule{
		rule: Rule{ID: 31},
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 1,
			DstPort: 20022,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      31,
			BackendAddr: 11,
			BackendPort: 22,
		},
	}
	oldB := preparedKernelRule{
		rule: Rule{ID: 32},
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 1,
			DstPort: 20023,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      32,
			BackendAddr: 12,
			BackendPort: 22,
		},
	}
	nextA := oldA
	nextA.value.BackendPort = 2222
	nextC := preparedKernelRule{
		rule: Rule{ID: 33},
		key: tcRuleKeyV4{
			IfIndex: 3,
			DstAddr: 1,
			DstPort: 30022,
			Proto:   17,
		},
		value: tcRuleValueV4{
			RuleID:      33,
			BackendAddr: 13,
			BackendPort: 53,
		},
	}

	diff, err := diffPreparedKernelRules(
		[]preparedKernelRule{oldA, oldB},
		[]preparedKernelRule{nextA, nextC},
	)
	if err != nil {
		t.Fatalf("diffPreparedKernelRules() error = %v", err)
	}
	if kernelDualStackRuleMapDiffUpsertCount(diff) != 2 {
		t.Fatalf("diffPreparedKernelRules() upserts = %d, want 2", kernelDualStackRuleMapDiffUpsertCount(diff))
	}
	if kernelDualStackRuleMapDiffDeleteCount(diff) != 1 {
		t.Fatalf("diffPreparedKernelRules() deletes = %d, want 1", kernelDualStackRuleMapDiffDeleteCount(diff))
	}

	upserts := make(map[tcRuleKeyV4]tcRuleValueV4, len(diff.v4.upserts))
	for _, item := range diff.v4.upserts {
		upserts[item.key] = item.value
	}
	if got, ok := upserts[nextA.key]; !ok || got.BackendPort != 2222 {
		t.Fatalf("diffPreparedKernelRules() missing updated key %#v, got %#v", nextA.key, got)
	}
	if got, ok := upserts[nextC.key]; !ok || got.RuleID != 33 {
		t.Fatalf("diffPreparedKernelRules() missing new key %#v, got %#v", nextC.key, got)
	}
	if diff.v4.deletes[0] != oldB.key {
		t.Fatalf("diffPreparedKernelRules() delete key = %#v, want %#v", diff.v4.deletes[0], oldB.key)
	}
}

func TestDiffPreparedKernelRulesDetectsIPv6UpsertsAndDeletes(t *testing.T) {
	dstA, err := kernelPreparedAddrFromIP(net.ParseIP("2001:db8::10"), ipFamilyIPv6)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP(dstA) error = %v", err)
	}
	dstB, err := kernelPreparedAddrFromIP(net.ParseIP("2001:db8::11"), ipFamilyIPv6)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP(dstB) error = %v", err)
	}
	backendA, err := kernelPreparedAddrFromIP(net.ParseIP("2001:db8::20"), ipFamilyIPv6)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP(backendA) error = %v", err)
	}
	backendB, err := kernelPreparedAddrFromIP(net.ParseIP("2001:db8::21"), ipFamilyIPv6)
	if err != nil {
		t.Fatalf("kernelPreparedAddrFromIP(backendB) error = %v", err)
	}

	oldA := preparedKernelRule{
		rule: Rule{ID: 41, InIP: "2001:db8::10", OutIP: "2001:db8::20", InPort: 443, OutPort: 8443, Protocol: "tcp"},
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv6,
			DstAddr:     dstA,
			BackendAddr: backendA,
		},
		inIfIndex:  2,
		outIfIndex: 3,
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstPort: 443,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      41,
			BackendPort: 8443,
			OutIfIndex:  3,
		},
	}
	oldB := preparedKernelRule{
		rule: Rule{ID: 42, InIP: "2001:db8::11", OutIP: "2001:db8::21", InPort: 53, OutPort: 53, Protocol: "udp"},
		spec: kernelPreparedRuleSpec{
			Family:      ipFamilyIPv6,
			DstAddr:     dstB,
			BackendAddr: backendB,
		},
		inIfIndex:  2,
		outIfIndex: 3,
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstPort: 53,
			Proto:   17,
		},
		value: tcRuleValueV4{
			RuleID:      42,
			BackendPort: 53,
			OutIfIndex:  3,
		},
	}
	nextA := oldA
	nextA.rule.OutPort = 9443

	diff, err := diffPreparedKernelRules([]preparedKernelRule{oldA, oldB}, []preparedKernelRule{nextA})
	if err != nil {
		t.Fatalf("diffPreparedKernelRules() error = %v", err)
	}
	if len(diff.v4.upserts) != 0 || len(diff.v4.deletes) != 0 {
		t.Fatalf("diffPreparedKernelRules() unexpected IPv4 diff = %+v", diff.v4)
	}
	if len(diff.v6.upserts) != 1 {
		t.Fatalf("diffPreparedKernelRules() IPv6 upserts = %d, want 1", len(diff.v6.upserts))
	}
	if len(diff.v6.deletes) != 1 {
		t.Fatalf("diffPreparedKernelRules() IPv6 deletes = %d, want 1", len(diff.v6.deletes))
	}
	if diff.v6.upserts[0].value.BackendPort != 9443 {
		t.Fatalf("diffPreparedKernelRules() IPv6 upsert backend port = %d, want 9443", diff.v6.upserts[0].value.BackendPort)
	}
	oldBKey, _, err := encodePreparedKernelRuleV6(oldB)
	if err != nil {
		t.Fatalf("encodePreparedKernelRuleV6(oldB) error = %v", err)
	}
	if diff.v6.deletes[0] != oldBKey {
		t.Fatalf("diffPreparedKernelRules() IPv6 delete key = %#v, want %#v", diff.v6.deletes[0], oldBKey)
	}
}

func TestCollectPreparedKernelRuleFlowPurgeIDsIgnoresMetadataOnlyChanges(t *testing.T) {
	base := preparedKernelRule{
		rule: Rule{
			ID:           41,
			InInterface:  "vmbr0",
			InIP:         "198.51.100.10",
			InPort:       20022,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.6",
			OutPort:      22,
			Protocol:     "tcp",
			Remark:       "before",
		},
		inIfIndex:  2,
		outIfIndex: 3,
		key: tcRuleKeyV4{
			IfIndex: 2,
			DstAddr: 1,
			DstPort: 20022,
			Proto:   6,
		},
		value: tcRuleValueV4{
			RuleID:      41,
			BackendAddr: 2,
			BackendPort: 22,
			OutIfIndex:  3,
		},
	}

	next := base
	next.rule.Remark = "after"
	next.rule.Tag = "after"

	if got := collectPreparedKernelRuleFlowPurgeIDs([]preparedKernelRule{base}, []preparedKernelRule{next}); len(got) != 0 {
		t.Fatalf("collectPreparedKernelRuleFlowPurgeIDs() = %#v, want no purge ids", got)
	}
}

func TestCollectPreparedKernelRuleFlowPurgeIDsMarksRemovedAndChangedRules(t *testing.T) {
	unchangedOld := preparedKernelRule{
		rule:  Rule{ID: 51, Protocol: "tcp"},
		key:   tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 10001, Proto: 6},
		value: tcRuleValueV4{RuleID: 51, BackendAddr: 2, BackendPort: 80, OutIfIndex: 3},
	}
	changedOld := preparedKernelRule{
		rule:  Rule{ID: 52, Protocol: "udp"},
		key:   tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 10002, Proto: 17},
		value: tcRuleValueV4{RuleID: 52, BackendAddr: 3, BackendPort: 53, OutIfIndex: 3},
	}
	removedOld := preparedKernelRule{
		rule:  Rule{ID: 53, Protocol: "tcp"},
		key:   tcRuleKeyV4{IfIndex: 4, DstAddr: 1, DstPort: 10003, Proto: 6},
		value: tcRuleValueV4{RuleID: 53, BackendAddr: 4, BackendPort: 22, OutIfIndex: 5},
	}

	unchangedNew := unchangedOld
	changedNew := changedOld
	changedNew.value.BackendPort = 5353

	got := collectPreparedKernelRuleFlowPurgeIDs(
		[]preparedKernelRule{unchangedOld, changedOld, removedOld},
		[]preparedKernelRule{unchangedNew, changedNew},
	)

	if len(got) != 2 {
		t.Fatalf("len(collectPreparedKernelRuleFlowPurgeIDs()) = %d, want 2", len(got))
	}
	if _, ok := got[52]; !ok {
		t.Fatalf("collectPreparedKernelRuleFlowPurgeIDs() missing changed rule id 52: %#v", got)
	}
	if _, ok := got[53]; !ok {
		t.Fatalf("collectPreparedKernelRuleFlowPurgeIDs() missing removed rule id 53: %#v", got)
	}
	if _, ok := got[51]; ok {
		t.Fatalf("collectPreparedKernelRuleFlowPurgeIDs() unexpectedly marked unchanged rule id 51: %#v", got)
	}
}

func TestCollectPreparedKernelRuleFlowPurgeIDsIgnoresSyntheticRuleIDDrift(t *testing.T) {
	oldRule := preparedKernelRule{
		rule: Rule{
			ID:               62,
			Protocol:         "tcp",
			kernelMode:       kernelModeEgressNAT,
			kernelLogKind:    workerKindEgressNAT,
			kernelLogOwnerID: 9,
			InInterface:      "tap100i0",
			OutInterface:     "vmbr0",
			OutSourceIP:      "15.235.165.86",
		},
		key: tcRuleKeyV4{IfIndex: 4, DstAddr: 0, DstPort: 0, Proto: 6},
		value: tcRuleValueV4{
			RuleID:     62,
			OutIfIndex: 5,
			NATAddr:    7,
		},
	}
	newRule := oldRule
	newRule.rule.ID = 72
	newRule.value.RuleID = 72

	if got := collectPreparedKernelRuleFlowPurgeIDs([]preparedKernelRule{oldRule}, []preparedKernelRule{newRule}); len(got) != 0 {
		t.Fatalf("collectPreparedKernelRuleFlowPurgeIDs() = %#v, want no purge ids when only synthetic rule ids drift", got)
	}
}

func TestPreparedKernelRulesNeedAttachmentResetForEgressNATChanges(t *testing.T) {
	mainRule := preparedKernelRule{
		rule: Rule{ID: 61, Protocol: "tcp"},
		key:  tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 10001, Proto: 6},
		value: tcRuleValueV4{
			RuleID:      61,
			BackendAddr: 2,
			BackendPort: 80,
			OutIfIndex:  3,
		},
	}
	egressRule := preparedKernelRule{
		rule: Rule{
			ID:               62,
			Protocol:         "tcp",
			kernelMode:       kernelModeEgressNAT,
			kernelLogKind:    workerKindEgressNAT,
			kernelLogOwnerID: 9,
		},
		key: tcRuleKeyV4{IfIndex: 4, DstAddr: 0, DstPort: 0, Proto: 6},
		value: tcRuleValueV4{
			RuleID:     62,
			OutIfIndex: 5,
			NATAddr:    7,
		},
	}
	sameEgressWithNewSyntheticID := egressRule
	sameEgressWithNewSyntheticID.rule.ID = 72
	sameEgressWithNewSyntheticID.value.RuleID = 72
	changedMainRule := mainRule
	changedMainRule.value.BackendPort = 8080

	if !preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{mainRule, egressRule}, []preparedKernelRule{mainRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = false, want true when egress nat entries are removed")
	}
	if !preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{mainRule}, []preparedKernelRule{mainRule, egressRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = false, want true when egress nat entries are added")
	}
	if preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{mainRule}, []preparedKernelRule{mainRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = true, want false when no egress nat entries are involved")
	}
	if preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{mainRule, egressRule}, []preparedKernelRule{changedMainRule, egressRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = true, want false when only non-egress entries change")
	}
	if preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{mainRule, egressRule}, []preparedKernelRule{mainRule, sameEgressWithNewSyntheticID}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = true, want false when only egress synthetic rule ids drift")
	}
}

func TestPreparedKernelRulesNeedAttachmentResetWhenDispatchRequirementChanges(t *testing.T) {
	transparentRule := preparedKernelRule{
		rule: Rule{ID: 81, Protocol: "tcp", Transparent: true},
		spec: kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		key:  tcRuleKeyV4{IfIndex: 2, DstAddr: 1, DstPort: 10001, Proto: 6},
		value: tcRuleValueV4{
			RuleID:      81,
			BackendAddr: 2,
			BackendPort: 80,
			OutIfIndex:  3,
		},
	}
	fullNATRule := transparentRule
	fullNATRule.rule.ID = 82
	fullNATRule.rule.Transparent = false
	fullNATRule.value.RuleID = 82
	fullNATRule.value.Flags = kernelRuleFlagFullNAT
	fullNATRule.value.NATAddr = 7

	if !preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{transparentRule}, []preparedKernelRule{fullNATRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = false, want true when IPv4 rules start requiring dispatcher mode")
	}
	if !preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{fullNATRule}, []preparedKernelRule{transparentRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = false, want true when IPv4 rules stop requiring dispatcher mode")
	}
	if preparedKernelRulesNeedAttachmentReset([]preparedKernelRule{fullNATRule}, []preparedKernelRule{fullNATRule}) {
		t.Fatal("preparedKernelRulesNeedAttachmentReset() = true, want false when dispatcher requirement is unchanged")
	}
}
