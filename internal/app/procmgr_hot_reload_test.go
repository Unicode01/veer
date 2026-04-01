package app

import "testing"

func TestRulesEqualIgnoresMetadataOnlyChanges(t *testing.T) {
	base := []Rule{{
		ID:               11,
		InInterface:      "vmbr0",
		InIP:             "198.51.100.10",
		InPort:           20022,
		OutInterface:     "vmbr1",
		OutIP:            "192.0.2.6",
		OutSourceIP:      "198.51.100.10",
		OutPort:          22,
		Protocol:         "tcp",
		Remark:           "before",
		Tag:              "before",
		Enabled:          true,
		Transparent:      false,
		EnginePreference: ruleEngineAuto,
		kernelLogKind:    "rule",
		kernelLogOwnerID: 11,
	}}

	same := append([]Rule(nil), base...)
	same[0].Remark = "after"
	same[0].Tag = "after"
	same[0].EnginePreference = ruleEngineUserspace
	same[0].kernelLogKind = "range"
	same[0].kernelLogOwnerID = 99

	if !rulesEqual(base, same) {
		t.Fatal("rulesEqual() = false, want true when only metadata changed")
	}

	same[0].OutSourceIP = "198.51.100.11"
	if rulesEqual(base, same) {
		t.Fatal("rulesEqual() = true, want false when dataplane fields changed")
	}
}

func TestRangesEqualIgnoresMetadataOnlyChanges(t *testing.T) {
	base := []PortRange{{
		ID:           21,
		InInterface:  "vmbr0",
		InIP:         "198.51.100.10",
		StartPort:    10000,
		EndPort:      10010,
		OutInterface: "vmbr1",
		OutIP:        "192.0.2.6",
		OutSourceIP:  "198.51.100.10",
		OutStartPort: 20000,
		Protocol:     "tcp",
		Remark:       "before",
		Tag:          "before",
		Enabled:      true,
		Transparent:  false,
	}}

	same := append([]PortRange(nil), base...)
	same[0].Remark = "after"
	same[0].Tag = "after"
	if !rangesEqual(base, same) {
		t.Fatal("rangesEqual() = false, want true when only metadata changed")
	}

	same[0].OutStartPort = 21000
	if rangesEqual(base, same) {
		t.Fatal("rangesEqual() = true, want false when dataplane fields changed")
	}
}

func TestBuildUserspaceAssignmentsKeepsExistingRuleSlotsStable(t *testing.T) {
	rules := []Rule{
		{ID: 10, Enabled: true},
		{ID: 20, Enabled: true},
		{ID: 40, Enabled: true},
	}

	_, _, before, _ := buildUserspaceAssignments(rules, nil, nil, nil, 5)
	beforeSlots := flattenRuleAssignmentSlots(before)

	rules = append(rules, Rule{ID: 30, Enabled: true})
	_, _, after, _ := buildUserspaceAssignments(rules, nil, nil, nil, 5)
	afterSlots := flattenRuleAssignmentSlots(after)

	for _, id := range []int64{10, 20, 40} {
		if beforeSlots[id] != afterSlots[id] {
			t.Fatalf("rule %d moved worker slot: before=%d after=%d", id, beforeSlots[id], afterSlots[id])
		}
	}
}

func TestBuildUserspaceAssignmentsKeepsExistingRangeSlotsStable(t *testing.T) {
	ranges := []PortRange{
		{ID: 10, Enabled: true},
		{ID: 20, Enabled: true},
		{ID: 40, Enabled: true},
	}

	_, _, _, before := buildUserspaceAssignments(nil, ranges, nil, nil, 5)
	beforeSlots := flattenRangeAssignmentSlots(before)

	ranges = append(ranges, PortRange{ID: 30, Enabled: true})
	_, _, _, after := buildUserspaceAssignments(nil, ranges, nil, nil, 5)
	afterSlots := flattenRangeAssignmentSlots(after)

	for _, id := range []int64{10, 20, 40} {
		if beforeSlots[id] != afterSlots[id] {
			t.Fatalf("range %d moved worker slot: before=%d after=%d", id, beforeSlots[id], afterSlots[id])
		}
	}
}

func flattenRuleAssignmentSlots(assignments [][]Rule) map[int64]int {
	out := make(map[int64]int)
	for idx, rules := range assignments {
		for _, rule := range rules {
			out[rule.ID] = idx
		}
	}
	return out
}

func flattenRangeAssignmentSlots(assignments [][]PortRange) map[int64]int {
	out := make(map[int64]int)
	for idx, ranges := range assignments {
		for _, pr := range ranges {
			out[pr.ID] = idx
		}
	}
	return out
}
