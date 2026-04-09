package app

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

var (
	benchmarkKernelCandidatesSink       []kernelCandidateRule
	benchmarkManagedNetworkStatusesSink []ManagedNetworkStatus
	benchmarkManagedNetworkCompileSink  managedNetworkRuntimeCompilation
	benchmarkControlPlaneCountSink      int
)

type benchmarkKernelRuntime struct{}

func (benchmarkKernelRuntime) Available() (bool, string) {
	return true, "benchmark kernel runtime"
}

func (benchmarkKernelRuntime) SupportsRule(rule Rule) (bool, string) {
	switch rule.Protocol {
	case "tcp", "udp":
		return true, ""
	default:
		return false, "unsupported protocol"
	}
}

func (benchmarkKernelRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	return nil, nil
}

func (benchmarkKernelRuntime) SnapshotStats() (kernelRuleStatsSnapshot, error) {
	return emptyKernelRuleStatsSnapshot(), nil
}

func (benchmarkKernelRuntime) Maintain() error {
	return nil
}

func (benchmarkKernelRuntime) SnapshotAssignments() map[int64]string {
	return nil
}

func (benchmarkKernelRuntime) Close() error {
	return nil
}

type benchmarkManagedNetworkFixture struct {
	db                *sql.DB
	items             []ManagedNetwork
	infos             []InterfaceInfo
	explicitIPv6      []IPv6Assignment
	explicitEgressNAT []EgressNAT
	pm                *ProcessManager
}

func BenchmarkBuildKernelCandidateRules(b *testing.B) {
	planner := newRuleDataplanePlanner(benchmarkKernelRuntime{}, ruleEngineKernel)
	const configuredKernelRulesMapLimit = 65536
	benchmarks := []struct {
		name   string
		rules  []Rule
		ranges []PortRange
	}{
		{
			name:  "rules_4096_tcp_udp",
			rules: benchmarkRules(4096, "tcp+udp"),
		},
		{
			name: "range_2048_tcp_udp",
			ranges: []PortRange{
				benchmarkPortRange(1, 10000, 2048, "tcp+udp"),
			},
		},
	}

	for _, bench := range benchmarks {
		b.Run(bench.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				candidates, rulePlans, rangePlans := buildKernelCandidateRules(bench.rules, bench.ranges, planner, configuredKernelRulesMapLimit)
				benchmarkKernelCandidatesSink = candidates
				benchmarkControlPlaneCountSink = len(rulePlans) + len(rangePlans)
			}
		})
	}
}

func BenchmarkFilterActiveKernelCandidates(b *testing.B) {
	planner := newRuleDataplanePlanner(benchmarkKernelRuntime{}, ruleEngineKernel)
	const configuredKernelRulesMapLimit = 65536
	rules := benchmarkRules(12000, "tcp+udp")
	candidates, rulePlans, rangePlans := buildKernelCandidateRules(rules, nil, planner, configuredKernelRulesMapLimit)
	for idx, rule := range rules {
		if idx%2 != 0 {
			continue
		}
		plan := rulePlans[rule.ID]
		plan.EffectiveEngine = ruleEngineUserspace
		rulePlans[rule.ID] = plan
	}
	buf := make([]kernelCandidateRule, 0, len(candidates))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		active := filterActiveKernelCandidatesInto(buf, candidates, rulePlans, rangePlans, nil)
		buf = active[:0]
		benchmarkKernelCandidatesSink = active
		benchmarkControlPlaneCountSink = len(active)
	}
}

func BenchmarkCompileManagedNetworkRuntime(b *testing.B) {
	fixture := newBenchmarkManagedNetworkFixture(b, 32, 8, 4)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiled := compileManagedNetworkRuntime(fixture.items, fixture.explicitIPv6, fixture.explicitEgressNAT, fixture.infos)
		benchmarkManagedNetworkCompileSink = compiled
		benchmarkControlPlaneCountSink = len(compiled.IPv6Assignments) + len(compiled.EgressNATs)
	}
}

func BenchmarkBuildManagedNetworkStatuses(b *testing.B) {
	fixture := newBenchmarkManagedNetworkFixture(b, 32, 8, 4)
	oldLoad := loadInterfaceInfosForManagedNetworkPreviewTests
	loadInterfaceInfosForManagedNetworkPreviewTests = func() ([]InterfaceInfo, error) {
		return cloneBenchmarkInterfaceInfos(fixture.infos), nil
	}
	b.Cleanup(func() {
		loadInterfaceInfosForManagedNetworkPreviewTests = oldLoad
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statuses, err := buildManagedNetworkStatuses(fixture.db, fixture.items, fixture.pm)
		if err != nil {
			b.Fatalf("buildManagedNetworkStatuses() error = %v", err)
		}
		benchmarkManagedNetworkStatusesSink = statuses
		benchmarkControlPlaneCountSink = len(statuses)
	}
}

func newBenchmarkManagedNetworkFixture(tb testing.TB, networkCount int, childrenPerNetwork int, reservationsPerNetwork int) benchmarkManagedNetworkFixture {
	tb.Helper()

	db := openBenchmarkDB(tb)
	infos := benchmarkManagedNetworkInterfaceInfos(networkCount, childrenPerNetwork)
	for i := 0; i < networkCount; i++ {
		subnetOctet := i + 1
		bridge := fmt.Sprintf("vmbr%d", i)
		item := ManagedNetwork{
			Name:                fmt.Sprintf("network-%d", i),
			BridgeMode:          managedNetworkBridgeModeExisting,
			Bridge:              bridge,
			UplinkInterface:     "eno1",
			IPv4Enabled:         true,
			IPv4CIDR:            fmt.Sprintf("192.168.%d.1/24", subnetOctet),
			IPv4Gateway:         fmt.Sprintf("192.168.%d.1", subnetOctet),
			IPv4PoolStart:       fmt.Sprintf("192.168.%d.10", subnetOctet),
			IPv4PoolEnd:         fmt.Sprintf("192.168.%d.200", subnetOctet),
			IPv4DNSServers:      "1.1.1.1,8.8.8.8",
			IPv6Enabled:         true,
			IPv6ParentInterface: "eno1",
			IPv6ParentPrefix:    fmt.Sprintf("2001:db8:%x::/64", subnetOctet),
			IPv6AssignmentMode:  managedNetworkIPv6AssignmentModeSingle128,
			Enabled:             true,
		}
		id, err := dbAddManagedNetwork(db, &item)
		if err != nil {
			tb.Fatalf("dbAddManagedNetwork() error = %v", err)
		}
		item.ID = id
		for child := 0; child < reservationsPerNetwork; child++ {
			reservation := ManagedNetworkReservation{
				ManagedNetworkID: id,
				MACAddress:       benchmarkMACAddress(i, child),
				IPv4Address:      fmt.Sprintf("192.168.%d.%d", subnetOctet, 10+child),
				Remark:           fmt.Sprintf("reservation-%d-%d", i, child),
			}
			if _, err := dbAddManagedNetworkReservation(db, &reservation); err != nil {
				tb.Fatalf("dbAddManagedNetworkReservation() error = %v", err)
			}
		}
		egressNAT := EgressNAT{
			ParentInterface: bridge,
			OutInterface:    "eno1",
			Protocol:        "tcp+udp",
			NATType:         egressNATTypeSymmetric,
			Enabled:         true,
		}
		if _, err := dbAddEgressNAT(db, &egressNAT); err != nil {
			tb.Fatalf("dbAddEgressNAT() error = %v", err)
		}
	}

	items, err := dbGetManagedNetworks(db)
	if err != nil {
		tb.Fatalf("dbGetManagedNetworks() error = %v", err)
	}
	explicitIPv6, err := dbGetIPv6Assignments(db)
	if err != nil {
		tb.Fatalf("dbGetIPv6Assignments() error = %v", err)
	}
	explicitEgressNAT, err := dbGetEgressNATs(db)
	if err != nil {
		tb.Fatalf("dbGetEgressNATs() error = %v", err)
	}

	compiled := compileManagedNetworkRuntime(items, explicitIPv6, explicitEgressNAT, infos)
	managedStatuses := make(map[int64]managedNetworkRuntimeStatus, len(items))
	ipv6Stats := make(map[int64]ipv6AssignmentRuntimeStats)
	for _, item := range items {
		managedStatuses[item.ID] = managedNetworkRuntimeStatus{
			RuntimeStatus:    "running",
			RuntimeDetail:    "listening for dhcpv4",
			DHCPv4ReplyCount: 1024,
		}
		preview := compiled.Previews[item.ID]
		for _, assignmentID := range preview.GeneratedIPv6AssignmentIDs {
			ipv6Stats[assignmentID] = ipv6AssignmentRuntimeStats{
				RuntimeStatus:        "running",
				RuntimeDetail:        "router advertisement: active",
				RAAdvertisementCount: 256,
				DHCPv6ReplyCount:     128,
			}
		}
	}

	return benchmarkManagedNetworkFixture{
		db:                db,
		items:             items,
		infos:             infos,
		explicitIPv6:      explicitIPv6,
		explicitEgressNAT: explicitEgressNAT,
		pm: &ProcessManager{
			managedNetworkRuntime: &fakeManagedNetworkRuntime{statuses: managedStatuses},
			ipv6Runtime:           &fakeIPv6AssignmentRuntime{stats: ipv6Stats},
		},
	}
}

func openBenchmarkDB(tb testing.TB) *sql.DB {
	tb.Helper()

	dir := tb.TempDir()
	db, err := initDB(filepath.Join(dir, "forward-benchmark.db"))
	if err != nil {
		tb.Fatalf("initDB() error = %v", err)
	}
	tb.Cleanup(func() {
		_ = db.Close()
	})
	return db
}

func benchmarkRules(count int, protocol string) []Rule {
	out := make([]Rule, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, Rule{
			ID:               int64(i + 1),
			InInterface:      "eno1",
			InIP:             "198.19.0.1",
			InPort:           10000 + i,
			OutInterface:     "eno2",
			OutIP:            "203.0.113.10",
			OutPort:          20000 + i,
			Protocol:         protocol,
			Remark:           "benchmark",
			Enabled:          true,
			EnginePreference: ruleEngineKernel,
		})
	}
	return out
}

func benchmarkPortRange(id int64, startPort int, width int, protocol string) PortRange {
	return PortRange{
		ID:           id,
		InInterface:  "eno1",
		InIP:         "198.19.0.1",
		StartPort:    startPort,
		EndPort:      startPort + width - 1,
		OutInterface: "eno2",
		OutIP:        "203.0.113.20",
		OutStartPort: 30000,
		Protocol:     protocol,
		Remark:       "benchmark",
		Enabled:      true,
	}
}

func benchmarkManagedNetworkInterfaceInfos(networkCount int, childrenPerNetwork int) []InterfaceInfo {
	out := make([]InterfaceInfo, 0, 1+networkCount*(childrenPerNetwork+1))
	out = append(out, InterfaceInfo{
		Name:  "eno1",
		Kind:  "device",
		Addrs: []string{"198.51.100.1"},
	})
	for i := 0; i < networkCount; i++ {
		bridge := fmt.Sprintf("vmbr%d", i)
		out = append(out, InterfaceInfo{
			Name: bridge,
			Kind: "bridge",
		})
		for child := 0; child < childrenPerNetwork; child++ {
			vmid := 1000 + (i * childrenPerNetwork) + child
			out = append(out, InterfaceInfo{
				Name:   fmt.Sprintf("tap%di0", vmid),
				Parent: bridge,
				Kind:   "tap",
			})
		}
	}
	return out
}

func cloneBenchmarkInterfaceInfos(infos []InterfaceInfo) []InterfaceInfo {
	if len(infos) == 0 {
		return nil
	}
	out := make([]InterfaceInfo, len(infos))
	for i, info := range infos {
		out[i] = info
		if len(info.Addrs) > 0 {
			out[i].Addrs = append([]string(nil), info.Addrs...)
		}
	}
	return out
}

func benchmarkMACAddress(network int, reservation int) string {
	return fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", (network>>8)&0xff, network&0xff, reservation&0xff, (network+reservation)&0xff)
}
