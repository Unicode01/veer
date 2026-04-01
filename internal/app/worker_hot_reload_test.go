package app

import "testing"

func TestDiffRuleConfigsKeepsOnlyDataplaneEquivalentRules(t *testing.T) {
	current := map[int64]Rule{
		1: {
			ID:               1,
			InInterface:      "vmbr0",
			InIP:             "198.51.100.10",
			InPort:           20022,
			OutInterface:     "vmbr1",
			OutIP:            "192.0.2.6",
			OutSourceIP:      "198.51.100.10",
			OutPort:          22,
			Protocol:         "tcp",
			Transparent:      false,
			Remark:           "before",
			Tag:              "before",
			EnginePreference: ruleEngineAuto,
		},
		2: {
			ID:           2,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			InPort:       30022,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.7",
			OutPort:      22,
			Protocol:     "tcp",
			Transparent:  true,
		},
	}

	desired := []Rule{
		{
			ID:               1,
			InInterface:      "vmbr0",
			InIP:             "198.51.100.10",
			InPort:           20022,
			OutInterface:     "vmbr1",
			OutIP:            "192.0.2.6",
			OutSourceIP:      "198.51.100.10",
			OutPort:          22,
			Protocol:         "tcp",
			Transparent:      false,
			Remark:           "after",
			Tag:              "after",
			EnginePreference: ruleEngineKernel,
		},
		{
			ID:           2,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			InPort:       30022,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.8",
			OutPort:      22,
			Protocol:     "tcp",
			Transparent:  true,
		},
		{
			ID:           3,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			InPort:       40022,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.9",
			OutPort:      22,
			Protocol:     "tcp",
			Transparent:  true,
		},
	}

	keepIDs, startRules, stopIDs, desiredMap := diffRuleConfigs(current, desired)
	if len(keepIDs) != 1 {
		t.Fatalf("diffRuleConfigs() keepIDs len = %d, want 1", len(keepIDs))
	}
	if _, ok := keepIDs[1]; !ok {
		t.Fatal("diffRuleConfigs() missing keep id 1")
	}
	if len(startRules) != 2 || startRules[0].ID != 2 || startRules[1].ID != 3 {
		t.Fatalf("diffRuleConfigs() startRules = %#v, want ids [2 3]", startRules)
	}
	if len(stopIDs) != 1 || stopIDs[0] != 2 {
		t.Fatalf("diffRuleConfigs() stopIDs = %#v, want [2]", stopIDs)
	}
	if len(desiredMap) != 3 {
		t.Fatalf("diffRuleConfigs() desiredMap len = %d, want 3", len(desiredMap))
	}
}

func TestDiffRangeConfigsKeepsOnlyDataplaneEquivalentRanges(t *testing.T) {
	current := map[int64]PortRange{
		1: {
			ID:           1,
			InInterface:  "vmbr0",
			InIP:         "198.51.100.10",
			StartPort:    10000,
			EndPort:      10010,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.6",
			OutSourceIP:  "198.51.100.10",
			OutStartPort: 20000,
			Protocol:     "tcp",
			Transparent:  false,
			Remark:       "before",
		},
		2: {
			ID:           2,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			StartPort:    20000,
			EndPort:      20010,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.7",
			OutStartPort: 30000,
			Protocol:     "udp",
			Transparent:  true,
		},
	}

	desired := []PortRange{
		{
			ID:           1,
			InInterface:  "vmbr0",
			InIP:         "198.51.100.10",
			StartPort:    10000,
			EndPort:      10010,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.6",
			OutSourceIP:  "198.51.100.10",
			OutStartPort: 20000,
			Protocol:     "tcp",
			Transparent:  false,
			Remark:       "after",
			Tag:          "after",
		},
		{
			ID:           2,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			StartPort:    20000,
			EndPort:      20010,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.8",
			OutStartPort: 30000,
			Protocol:     "udp",
			Transparent:  true,
		},
		{
			ID:           3,
			InInterface:  "vmbr0",
			InIP:         "0.0.0.0",
			StartPort:    30000,
			EndPort:      30010,
			OutInterface: "vmbr1",
			OutIP:        "192.0.2.9",
			OutStartPort: 40000,
			Protocol:     "tcp",
			Transparent:  true,
		},
	}

	keepIDs, startRanges, stopIDs, desiredMap := diffRangeConfigs(current, desired)
	if len(keepIDs) != 1 {
		t.Fatalf("diffRangeConfigs() keepIDs len = %d, want 1", len(keepIDs))
	}
	if _, ok := keepIDs[1]; !ok {
		t.Fatal("diffRangeConfigs() missing keep id 1")
	}
	if len(startRanges) != 2 || startRanges[0].ID != 2 || startRanges[1].ID != 3 {
		t.Fatalf("diffRangeConfigs() startRanges = %#v, want ids [2 3]", startRanges)
	}
	if len(stopIDs) != 1 || stopIDs[0] != 2 {
		t.Fatalf("diffRangeConfigs() stopIDs = %#v, want [2]", stopIDs)
	}
	if len(desiredMap) != 3 {
		t.Fatalf("diffRangeConfigs() desiredMap len = %d, want 3", len(desiredMap))
	}
}
