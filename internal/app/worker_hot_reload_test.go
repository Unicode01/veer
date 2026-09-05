package app

import (
	"fmt"
	"net"
	"testing"
)

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

func TestRetryMissingRuleBindingsRestartsUnboundUnchangedRule(t *testing.T) {
	rule := Rule{ID: 7, InIP: "127.0.0.1", InPort: 10007, OutIP: "127.0.0.1", OutPort: 22, Protocol: "tcp", Enabled: true}
	keep := map[int64]struct{}{rule.ID: {}}
	start, stop := retryUnavailableRuleBindings(keep, nil, nil, []Rule{rule}, map[int64]*ruleBinding{})
	if len(start) != 1 || start[0].ID != rule.ID {
		t.Fatalf("retry start rules = %+v, want rule %d", start, rule.ID)
	}
	if len(stop) != 0 {
		t.Fatalf("retry stop rules = %+v, want none without a live binding", stop)
	}
	if _, ok := keep[rule.ID]; ok {
		t.Fatalf("rule %d remained in keep set without a live binding", rule.ID)
	}
}

func TestRetryRuleBindingWithoutGroupRestarts(t *testing.T) {
	rule := Rule{ID: 8, Protocol: "tcp+udp"}
	keep := map[int64]struct{}{rule.ID: {}}
	bindings := map[int64]*ruleBinding{rule.ID: {}}
	start, stop := retryUnavailableRuleBindings(keep, nil, nil, []Rule{rule}, bindings)
	if len(start) != 1 || start[0].ID != rule.ID || len(stop) != 1 || stop[0] != rule.ID {
		t.Fatalf("degraded rule retry = start:%+v stop:%+v, want rule %d restarted", start, stop, rule.ID)
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

func TestRetryMissingRangeBindingsRestartsUnboundUnchangedRange(t *testing.T) {
	pr := PortRange{ID: 9, InIP: "127.0.0.1", StartPort: 10009, EndPort: 10010, OutIP: "127.0.0.1", OutStartPort: 22, Protocol: "tcp", Enabled: true}
	keep := map[int64]struct{}{pr.ID: {}}
	start, stop := retryUnavailableRangeBindings(keep, nil, nil, []PortRange{pr}, map[int64]*rangeBinding{})
	if len(start) != 1 || start[0].ID != pr.ID {
		t.Fatalf("retry start ranges = %+v, want range %d", start, pr.ID)
	}
	if len(stop) != 0 {
		t.Fatalf("retry stop ranges = %+v, want none without a live binding", stop)
	}
	if _, ok := keep[pr.ID]; ok {
		t.Fatalf("range %d remained in keep set without a live binding", pr.ID)
	}
}

func TestRetryRangeBindingWithoutGroupRestarts(t *testing.T) {
	pr := PortRange{ID: 10, Protocol: "tcp"}
	keep := map[int64]struct{}{pr.ID: {}}
	bindings := map[int64]*rangeBinding{pr.ID: {}}
	start, stop := retryUnavailableRangeBindings(keep, nil, nil, []PortRange{pr}, bindings)
	if len(start) != 1 || start[0].ID != pr.ID || len(stop) != 1 || stop[0] != pr.ID {
		t.Fatalf("degraded range retry = start:%+v stop:%+v, want range %d restarted", start, stop, pr.ID)
	}
}

func TestRuleBindingReportsDegradedTCPUDPListener(t *testing.T) {
	udp := reserveUDPWithFreeTCPForTest(t)
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port

	binding, degradedErr, err := startRuleBindingWithDegradedState(0, Rule{
		ID: 11, InIP: "127.0.0.1", InPort: port, OutIP: "127.0.0.1", OutPort: 9, Protocol: "tcp+udp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRuleBindingWithDegradedState() error = %v", err)
	}
	t.Cleanup(binding.Stop)
	if degradedErr == nil {
		t.Fatal("degraded error = nil, want occupied UDP listener failure")
	}
}

func TestRangeBindingReportsDegradedPortListener(t *testing.T) {
	occupied, startPort, endPort := reserveAdjacentTCPPortsForTest(t)
	defer occupied.Close()

	binding, degradedErr, err := startRangeBindingWithDegradedState(0, PortRange{
		ID: 12, InIP: "127.0.0.1", StartPort: startPort, EndPort: endPort, OutIP: "127.0.0.1", OutStartPort: 9, Protocol: "tcp",
	}, &ruleStats{})
	if err != nil {
		t.Fatalf("startRangeBindingWithDegradedState() error = %v", err)
	}
	t.Cleanup(binding.Stop)
	if degradedErr == nil {
		t.Fatal("degraded error = nil, want occupied range port failure")
	}
}

func reserveAdjacentTCPPortsForTest(t *testing.T) (net.Listener, int, int) {
	t.Helper()
	for attempt := 0; attempt < 32; attempt++ {
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Skipf("listen tcp4 on 127.0.0.1 unavailable: %v", err)
		}
		port := occupied.Addr().(*net.TCPAddr).Port
		for _, adjacent := range []int{port - 1, port + 1} {
			if adjacent <= 0 || adjacent > 65535 {
				continue
			}
			probe, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(adjacent)))
			if err != nil {
				continue
			}
			_ = probe.Close()
			if adjacent < port {
				return occupied, adjacent, port
			}
			return occupied, port, adjacent
		}
		_ = occupied.Close()
	}
	t.Skip("could not reserve adjacent TCP ports for range test")
	return nil, 0, 0
}
