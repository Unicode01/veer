//go:build linux

package app

import "testing"

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
		key: tcRuleKeyV4{
			IfIndex: 5,
			DstPort: 10022,
			Proto:   6,
		},
		value: xdpRuleValueV4{
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
	diff.key.DstPort = 10023
	if samePreparedXDPKernelRuleDataplane(base, diff) {
		t.Fatal("samePreparedXDPKernelRuleDataplane() = true, want false when dataplane changes")
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

	diff := diffPreparedKernelRules([]preparedKernelRule{base}, []preparedKernelRule{next})
	if len(diff.upserts) != 0 {
		t.Fatalf("diffPreparedKernelRules() upserts = %d, want 0", len(diff.upserts))
	}
	if len(diff.deletes) != 0 {
		t.Fatalf("diffPreparedKernelRules() deletes = %d, want 0", len(diff.deletes))
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

	diff := diffPreparedKernelRules(
		[]preparedKernelRule{oldA, oldB},
		[]preparedKernelRule{nextA, nextC},
	)
	if len(diff.upserts) != 2 {
		t.Fatalf("diffPreparedKernelRules() upserts = %d, want 2", len(diff.upserts))
	}
	if len(diff.deletes) != 1 {
		t.Fatalf("diffPreparedKernelRules() deletes = %d, want 1", len(diff.deletes))
	}

	upserts := make(map[tcRuleKeyV4]tcRuleValueV4, len(diff.upserts))
	for _, item := range diff.upserts {
		upserts[item.key] = item.value
	}
	if got, ok := upserts[nextA.key]; !ok || got.BackendPort != 2222 {
		t.Fatalf("diffPreparedKernelRules() missing updated key %#v, got %#v", nextA.key, got)
	}
	if got, ok := upserts[nextC.key]; !ok || got.RuleID != 33 {
		t.Fatalf("diffPreparedKernelRules() missing new key %#v, got %#v", nextC.key, got)
	}
	if diff.deletes[0] != oldB.key {
		t.Fatalf("diffPreparedKernelRules() delete key = %#v, want %#v", diff.deletes[0], oldB.key)
	}
}
