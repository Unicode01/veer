//go:build linux

package app

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestAggregateKernelPerCPUStats(t *testing.T) {
	values := []kernelStatsValueV4{
		{TotalConns: 10, TCPActiveConns: 3, UDPNatEntries: 4, ICMPNatEntries: 1, BytesIn: 100, BytesOut: 200},
		{TotalConns: 5, TCPActiveConns: 2, UDPNatEntries: 1, ICMPNatEntries: 2, BytesIn: 30, BytesOut: 40},
		{TotalConns: 7, TCPActiveConns: 1, UDPNatEntries: 6, ICMPNatEntries: 3, BytesIn: 70, BytesOut: 80},
	}

	got := aggregateKernelPerCPUStats(values)
	want := kernelStatsValueV4{
		TotalConns:     22,
		TCPActiveConns: 6,
		UDPNatEntries:  11,
		ICMPNatEntries: 6,
		BytesIn:        200,
		BytesOut:       320,
	}
	if got != want {
		t.Fatalf("aggregateKernelPerCPUStats() = %+v, want %+v", got, want)
	}
}

func TestKernelFlowMaintenanceBudgetForCapacity(t *testing.T) {
	cases := []struct {
		name     string
		capacity int
		want     int
	}{
		{name: "default minimum", capacity: 0, want: kernelFlowMaintenanceBudgetMin},
		{name: "minimum clamp", capacity: 1024, want: kernelFlowMaintenanceBudgetMin},
		{name: "mid range", capacity: 131072, want: 16384},
		{name: "maximum clamp", capacity: 1048576, want: kernelFlowMaintenanceBudgetMax},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kernelFlowMaintenanceBudgetForCapacity(tc.capacity)
			if got != tc.want {
				t.Fatalf("kernelFlowMaintenanceBudgetForCapacity(%d) = %d, want %d", tc.capacity, got, tc.want)
			}
		})
	}
}

func TestKernelFlowCountsTowardLiveGauge(t *testing.T) {
	cases := []struct {
		name  string
		value tcFlowValueV4
		want  bool
	}{
		{
			name:  "missing rule id",
			value: tcFlowValueV4{},
			want:  false,
		},
		{
			name: "uncounted transparent flow",
			value: tcFlowValueV4{
				RuleID: 1,
			},
			want: false,
		},
		{
			name: "counted transparent flow",
			value: tcFlowValueV4{
				RuleID: 1,
				Flags:  kernelFlowFlagCounted,
			},
			want: true,
		},
		{
			name: "counted fullnat front flow ignored",
			value: tcFlowValueV4{
				RuleID: 1,
				Flags:  kernelFlowFlagCounted | kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry,
			},
			want: false,
		},
		{
			name: "counted fullnat reply flow counted",
			value: tcFlowValueV4{
				RuleID: 1,
				Flags:  kernelFlowFlagCounted | kernelFlowFlagFullNAT,
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelFlowCountsTowardLiveGauge(tc.value); got != tc.want {
				t.Fatalf("kernelFlowCountsTowardLiveGauge() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestKernelFlowCountsTowardLiveGaugeV6(t *testing.T) {
	cases := []struct {
		name  string
		value tcFlowValueV6
		want  bool
	}{
		{
			name:  "missing rule id",
			value: tcFlowValueV6{},
			want:  false,
		},
		{
			name: "uncounted flow",
			value: tcFlowValueV6{
				RuleID: 1,
			},
			want: false,
		},
		{
			name: "counted flow",
			value: tcFlowValueV6{
				RuleID: 1,
				Flags:  kernelFlowFlagCounted,
			},
			want: true,
		},
		{
			name: "front fullnat flow ignored",
			value: tcFlowValueV6{
				RuleID: 1,
				Flags:  kernelFlowFlagCounted | kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry,
			},
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelFlowCountsTowardLiveGaugeV6(tc.value); got != tc.want {
				t.Fatalf("kernelFlowCountsTowardLiveGaugeV6() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestMergeKernelLiveStateSnapshot(t *testing.T) {
	dst := newKernelFlowLiveStateSnapshot(true)
	dst.ByRuleID[1] = kernelStatsValueV4{TCPActiveConns: 1}
	dst.UsedNATV4[kernelNATReservationOwnerV4{Key: tcNATPortKeyV4{IfIndex: 2, NATAddr: 3, NATPort: 4, Proto: unix.IPPROTO_UDP}, SessionID: 11}] = struct{}{}
	dst.UsedNATV6[kernelNATReservationOwnerV6{Key: tcNATPortKeyV6{IfIndex: 5, NATAddr: [16]byte{1}, NATPort: 6, Proto: unix.IPPROTO_TCP}, SessionID: 12}] = struct{}{}
	dst.FlowEntries = 2

	src := newKernelFlowLiveStateSnapshot(true)
	src.ByRuleID[1] = kernelStatsValueV4{UDPNatEntries: 2}
	src.ByRuleID[2] = kernelStatsValueV4{ICMPNatEntries: 3}
	src.UsedNATV4[kernelNATReservationOwnerV4{Key: tcNATPortKeyV4{IfIndex: 7, NATAddr: 8, NATPort: 9, Proto: unix.IPPROTO_TCP}, SessionID: 21}] = struct{}{}
	src.UsedNATV6[kernelNATReservationOwnerV6{Key: tcNATPortKeyV6{IfIndex: 10, NATAddr: [16]byte{2}, NATPort: 11, Proto: unix.IPPROTO_UDP}, SessionID: 22}] = struct{}{}
	src.FlowEntries = 5

	mergeKernelLiveStateSnapshot(&dst, src)

	if dst.FlowEntries != 7 {
		t.Fatalf("mergeKernelLiveStateSnapshot() flow entries = %d, want 7", dst.FlowEntries)
	}
	if got := dst.ByRuleID[1]; got.TCPActiveConns != 1 || got.UDPNatEntries != 2 {
		t.Fatalf("mergeKernelLiveStateSnapshot() rule 1 = %+v, want tcp=1 udp=2", got)
	}
	if got := dst.ByRuleID[2]; got.ICMPNatEntries != 3 {
		t.Fatalf("mergeKernelLiveStateSnapshot() rule 2 = %+v, want icmp=3", got)
	}
	if len(dst.UsedNATV4) != 2 {
		t.Fatalf("mergeKernelLiveStateSnapshot() used nat v4 len = %d, want 2", len(dst.UsedNATV4))
	}
	if len(dst.UsedNATV6) != 2 {
		t.Fatalf("mergeKernelLiveStateSnapshot() used nat v6 len = %d, want 2", len(dst.UsedNATV6))
	}
}

func TestKernelLiveStatsCorrection(t *testing.T) {
	observed := map[uint32]kernelStatsValueV4{
		1: {TCPActiveConns: 10, UDPNatEntries: 4, ICMPNatEntries: 3, TotalConns: 100, BytesIn: 2000, BytesOut: 3000},
		2: {TCPActiveConns: 1},
	}
	live := map[uint32]kernelStatsValueV4{
		1: {TCPActiveConns: 3, UDPNatEntries: 2, ICMPNatEntries: 1},
		3: {UDPNatEntries: 5, ICMPNatEntries: 2},
	}

	got := kernelLiveStatsCorrection(observed, live)
	want := map[uint32]kernelRuleStats{
		1: {TCPActiveConns: -7, UDPNatEntries: -2, ICMPNatEntries: -2},
		2: {TCPActiveConns: -1},
		3: {UDPNatEntries: 5, ICMPNatEntries: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("kernelLiveStatsCorrection() len = %d, want %d", len(got), len(want))
	}
	for ruleID, expected := range want {
		if got[ruleID] != expected {
			t.Fatalf("kernelLiveStatsCorrection()[%d] = %+v, want %+v", ruleID, got[ruleID], expected)
		}
	}
}

func TestKernelLiveStatsCorrectionTracksProtocolSpecificCounts(t *testing.T) {
	observed := map[uint32]kernelStatsValueV4{
		7: {TCPActiveConns: 5, UDPNatEntries: 5, ICMPNatEntries: 4},
	}
	live := map[uint32]kernelStatsValueV4{}
	flows := []struct {
		key   tcFlowKeyV4
		value tcFlowValueV4
	}{
		{
			key: tcFlowKeyV4{Proto: unix.IPPROTO_TCP},
			value: tcFlowValueV4{
				RuleID: 7,
				Flags:  kernelFlowFlagCounted,
			},
		},
		{
			key: tcFlowKeyV4{Proto: unix.IPPROTO_UDP},
			value: tcFlowValueV4{
				RuleID: 7,
				Flags:  kernelFlowFlagCounted,
			},
		},
		{
			key: tcFlowKeyV4{Proto: unix.IPPROTO_ICMP},
			value: tcFlowValueV4{
				RuleID: 7,
				Flags:  kernelFlowFlagCounted,
			},
		},
		{
			key: tcFlowKeyV4{Proto: unix.IPPROTO_TCP},
			value: tcFlowValueV4{
				RuleID: 7,
				Flags:  kernelFlowFlagCounted | kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry,
			},
		},
	}

	for _, flow := range flows {
		if !kernelFlowCountsTowardLiveGauge(flow.value) {
			continue
		}
		item := live[flow.value.RuleID]
		if kernelFlowUsesUDPAccounting(flow.key.Proto) {
			item.UDPNatEntries++
		} else if kernelFlowUsesICMPAccounting(flow.key.Proto) {
			item.ICMPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		live[flow.value.RuleID] = item
	}

	got := kernelLiveStatsCorrection(observed, live)
	want := kernelRuleStats{TCPActiveConns: -4, UDPNatEntries: -4, ICMPNatEntries: -3}
	if got[7] != want {
		t.Fatalf("kernelLiveStatsCorrection()[7] = %+v, want %+v", got[7], want)
	}
}

func TestReconcileKernelStatsCorrectionFromCandidates(t *testing.T) {
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 32,
	})

	for ruleID, value := range map[uint32]kernelStatsValueV4{
		1:  {TCPActiveConns: 10},
		2:  {UDPNatEntries: 4},
		99: {TCPActiveConns: 30},
	} {
		if err := stats.Put(ruleID, value); err != nil {
			t.Fatalf("stats.Put(%d) error = %v", ruleID, err)
		}
	}

	live := map[uint32]kernelStatsValueV4{
		1: {TCPActiveConns: 3},
		3: {TCPActiveConns: 2},
	}
	current := map[uint32]kernelRuleStats{
		2: {UDPNatEntries: -1},
	}

	got, err := reconcileKernelStatsCorrectionFromCandidates(stats, live, current)
	if err != nil {
		t.Fatalf("reconcileKernelStatsCorrectionFromCandidates() error = %v", err)
	}

	want := map[uint32]kernelRuleStats{
		1: {TCPActiveConns: -7},
		2: {UDPNatEntries: -4},
		3: {TCPActiveConns: 2},
	}
	if len(got) != len(want) {
		t.Fatalf("reconcileKernelStatsCorrectionFromCandidates() len = %d, want %d", len(got), len(want))
	}
	for ruleID, expected := range want {
		if got[ruleID] != expected {
			t.Fatalf("reconcileKernelStatsCorrectionFromCandidates()[%d] = %+v, want %+v", ruleID, got[ruleID], expected)
		}
	}
	if _, ok := got[99]; ok {
		t.Fatal("reconcileKernelStatsCorrectionFromCandidates() unexpectedly included non-candidate rule 99")
	}
}

func TestMergeKernelStatsCorrectionsIncludesICMP(t *testing.T) {
	dst := map[uint32]kernelRuleStats{
		9: {
			TCPActiveConns: 1,
			UDPNatEntries:  2,
			ICMPNatEntries: 3,
			TotalConns:     4,
			BytesIn:        5,
			BytesOut:       6,
		},
	}
	delta := map[uint32]kernelRuleStats{
		9: {
			TCPActiveConns: 10,
			UDPNatEntries:  20,
			ICMPNatEntries: 30,
			TotalConns:     40,
			BytesIn:        50,
			BytesOut:       60,
		},
	}

	mergeKernelStatsCorrections(dst, delta)

	want := kernelRuleStats{
		TCPActiveConns: 11,
		UDPNatEntries:  22,
		ICMPNatEntries: 33,
		TotalConns:     44,
		BytesIn:        55,
		BytesOut:       66,
	}
	if got := dst[9]; got != want {
		t.Fatalf("mergeKernelStatsCorrections()[9] = %+v, want %+v", got, want)
	}
}

func TestPruneOrphanKernelNATReservationsTracksRemainingEntries(t *testing.T) {
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})

	usedKey := tcNATPortKeyV4{IfIndex: 2, NATAddr: 3, NATPort: 4, Proto: unix.IPPROTO_TCP}
	staleKey := tcNATPortKeyV4{IfIndex: 5, NATAddr: 6, NATPort: 7, Proto: unix.IPPROTO_UDP}
	usedOwner := kernelNATReservationOwnerV4{Key: usedKey, SessionID: 101}
	staleOwner := kernelNATReservationOwnerV4{Key: staleKey, SessionID: 202}
	for _, owner := range []kernelNATReservationOwnerV4{usedOwner, staleOwner} {
		if err := nat.Put(owner.Key, tcNATPortValue{RuleID: 1, SessionID: owner.SessionID}); err != nil {
			t.Fatalf("nat.Put(%+v) error = %v", owner.Key, err)
		}
	}

	used := map[kernelNATReservationOwnerV4]struct{}{usedOwner: {}}
	remaining, deleted, candidates, err := pruneOrphanKernelNATReservations(nat, used, nil)
	if err != nil {
		t.Fatalf("pruneOrphanKernelNATReservations() error = %v", err)
	}
	if remaining != 2 || deleted != 0 {
		t.Fatalf("first pass remaining/deleted = %d/%d, want 2/0", remaining, deleted)
	}
	if _, ok := candidates[staleOwner]; !ok || len(candidates) != 1 {
		t.Fatalf("first pass candidates = %+v, want stale owner", candidates)
	}

	replacementOwner := kernelNATReservationOwnerV4{Key: staleKey, SessionID: 303}
	if err := nat.Put(staleKey, tcNATPortValue{RuleID: 2, SessionID: replacementOwner.SessionID}); err != nil {
		t.Fatalf("replace stale reservation: %v", err)
	}
	remaining, deleted, candidates, err = pruneOrphanKernelNATReservations(nat, used, candidates)
	if err != nil {
		t.Fatalf("pruneOrphanKernelNATReservations(replaced) error = %v", err)
	}
	if remaining != 2 || deleted != 0 {
		t.Fatalf("replacement pass remaining/deleted = %d/%d, want 2/0", remaining, deleted)
	}
	if _, ok := candidates[replacementOwner]; !ok || len(candidates) != 1 {
		t.Fatalf("replacement pass candidates = %+v, want replacement owner", candidates)
	}

	remaining, deleted, _, err = pruneOrphanKernelNATReservations(nat, used, candidates)
	if err != nil {
		t.Fatalf("pruneOrphanKernelNATReservations(confirm) error = %v", err)
	}
	if remaining != 1 || deleted != 1 {
		t.Fatalf("confirmation pass remaining/deleted = %d/%d, want 1/1", remaining, deleted)
	}
	if count, err := countKernelNATMapEntries(nat); err != nil {
		t.Fatalf("countKernelNATMapEntries() error = %v", err)
	} else if count != 1 {
		t.Fatalf("countKernelNATMapEntries() = %d, want 1", count)
	}
}

func TestKernelFlowShouldDeleteUsesProtocolSpecificDatagramIdleTimeout(t *testing.T) {
	cases := []struct {
		name  string
		proto uint8
		ageNS uint64
		want  bool
	}{
		{
			name:  "icmp expires quickly",
			proto: unix.IPPROTO_ICMP,
			ageNS: kernelICMPFlowIdleTimeout + 1,
			want:  true,
		},
		{
			name:  "icmp within timeout survives",
			proto: unix.IPPROTO_ICMP,
			ageNS: kernelICMPFlowIdleTimeout,
			want:  false,
		},
		{
			name:  "udp keeps longer timeout",
			proto: unix.IPPROTO_UDP,
			ageNS: kernelICMPFlowIdleTimeout + 1,
			want:  false,
		},
		{
			name:  "udp still expires eventually",
			proto: unix.IPPROTO_UDP,
			ageNS: kernelUDPFlowIdleTimeout + 1,
			want:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kernelFlowShouldDelete(
				tcFlowKeyV4{Proto: tc.proto},
				tcFlowValueV4{
					RuleID:     1,
					Flags:      kernelFlowFlagFullNAT,
					NATAddr:    1,
					NATPort:    1,
					LastSeenNS: 1,
				},
				1+tc.ageNS,
				true,
			)
			if got != tc.want {
				t.Fatalf("kernelFlowShouldDelete(proto=%d, age=%d) = %t, want %t", tc.proto, tc.ageNS, got, tc.want)
			}
		})
	}
}

func TestKernelFlowShouldDeleteTCPClosingLifecycle(t *testing.T) {
	key := tcFlowKeyV4{Proto: unix.IPPROTO_TCP}
	base := tcFlowValueV4{
		RuleID:     1,
		Flags:      kernelFlowFlagFullNAT | kernelFlowFlagReplySeen,
		NATAddr:    1,
		NATPort:    1,
		LastSeenNS: 1,
	}

	if got := kernelFlowDeleteReason(key, base, 1+10*60*1000000000+1, true); got != "" {
		t.Fatalf("established flow after ten minutes delete reason = %q, want none", got)
	}
	if got := kernelFlowDeleteReason(key, base, 1+kernelTCPFlowIdleTimeout+1, true); got != "tcp_idle_timeout" {
		t.Fatalf("established flow after idle timeout delete reason = %q, want tcp_idle_timeout", got)
	}

	oneSided := base
	oneSided.Flags |= kernelFlowFlagFrontClosing
	oneSided.FrontCloseSeenNS = 2
	if got := kernelFlowDeleteReason(key, oneSided, 2+kernelTCPClosingGraceNS+1, true); got != "" {
		t.Fatalf("one-sided FIN delete reason = %q, want none", got)
	}

	bothSides := oneSided
	bothSides.Flags |= kernelFlowFlagReplyClosing
	if got := kernelFlowDeleteReason(key, bothSides, 2+kernelTCPClosingGraceNS, true); got != "" {
		t.Fatalf("two-sided FIN at grace boundary delete reason = %q, want none", got)
	}
	if got := kernelFlowDeleteReason(key, bothSides, 2+kernelTCPClosingGraceNS+1, true); got != "tcp_closing_grace_expired" {
		t.Fatalf("two-sided FIN after grace delete reason = %q, want tcp_closing_grace_expired", got)
	}

	front := bothSides
	front.Flags |= kernelFlowFlagFrontEntry
	if got := kernelFlowDeleteReason(key, front, 2+kernelTCPFlowIdleTimeout+1, true); got != "" {
		t.Fatalf("full-NAT front entry delete reason = %q, want reply entry to own pruning", got)
	}
}

func TestSnapshotXDPKernelLiveStateFromRuntimeMapRefsCountsV4Flows(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 16,
	})

	replyKey := tcFlowKeyV4{IfIndex: 5, SrcAddr: 10, DstAddr: 20, SrcPort: 1234, DstPort: 20000, Proto: unix.IPPROTO_TCP}
	replyValue := xdpFlowValueV4{
		RuleID:     7,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT,
		NATAddr:    30,
		NATPort:    20000,
		LastSeenNS: 2,
	}
	if err := flows.Put(replyKey, replyValue); err != nil {
		t.Fatalf("flows.Put(reply) error = %v", err)
	}

	frontKey := tcFlowKeyV4{IfIndex: 5, SrcAddr: 11, DstAddr: 21, SrcPort: 2345, DstPort: 10000, Proto: unix.IPPROTO_TCP}
	frontValue := xdpFlowValueV4{
		RuleID:     7,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry,
		NATAddr:    30,
		NATPort:    20000,
		LastSeenNS: 2,
	}
	if err := flows.Put(frontKey, frontValue); err != nil {
		t.Fatalf("flows.Put(front) error = %v", err)
	}

	live, err := snapshotXDPKernelLiveStateFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsV4: flows}, true)
	if err != nil {
		t.Fatalf("snapshotXDPKernelLiveStateFromRuntimeMapRefs() error = %v", err)
	}
	if live.FlowEntries != 2 {
		t.Fatalf("live.FlowEntries = %d, want 2", live.FlowEntries)
	}
	if got := live.ByRuleID[7]; got.TCPActiveConns != 1 || got.UDPNatEntries != 0 || got.ICMPNatEntries != 0 {
		t.Fatalf("live.ByRuleID[7] = %+v, want tcp=1", got)
	}
	if len(live.NATByBank.activeV4) != 1 {
		t.Fatalf("len(live.NATByBank.activeV4) = %d, want 1", len(live.NATByBank.activeV4))
	}
	if live.UsedNATV4 != nil {
		t.Fatalf("runtime snapshot retained duplicate aggregate NAT owners: %d", len(live.UsedNATV4))
	}
}

func TestSnapshotKernelLiveStateFromFlowsV6TracksNATReservations(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
		MaxEntries: 16,
	})

	key := tcFlowKeyV6{IfIndex: 6, SrcAddr: [16]byte{1}, DstAddr: [16]byte{2}, SrcPort: 1234, DstPort: 20000, Proto: unix.IPPROTO_TCP}
	value := tcFlowValueV6{
		RuleID:     21,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT,
		NATAddr:    [16]byte{3},
		NATPort:    20000,
		LastSeenNS: 2,
	}
	if err := flows.Put(key, value); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}

	live, err := snapshotKernelLiveStateFromFlowsV6(nil, flows, true)
	if err != nil {
		t.Fatalf("snapshotKernelLiveStateFromFlowsV6() error = %v", err)
	}
	if live.FlowEntries != 1 {
		t.Fatalf("live.FlowEntries = %d, want 1", live.FlowEntries)
	}
	if got := live.ByRuleID[21]; got.TCPActiveConns != 1 {
		t.Fatalf("live.ByRuleID[21] = %+v, want tcp=1", got)
	}
	if len(live.UsedNATV6) != 1 {
		t.Fatalf("len(live.UsedNATV6) = %d, want 1", len(live.UsedNATV6))
	}
}

func TestPruneStaleXDPFlowsMapDeletesInvalidFlow(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
		MaxEntries: 16,
	})

	key := tcFlowKeyV4{IfIndex: 5, SrcAddr: 10, DstAddr: 20, SrcPort: 1234, DstPort: 20000, Proto: unix.IPPROTO_TCP}
	value := xdpFlowValueV4{
		RuleID:     11,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT,
		NATAddr:    30,
		NATPort:    20000,
		InIfIndex:  5,
		FrontAddr:  40,
		ClientAddr: 50,
		FrontPort:  10000,
		ClientPort: 1234,
	}
	if err := flows.Put(key, value); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}

	corrections, metrics, err := pruneStaleXDPFlowsMap(nil, flows, nil, &kernelFlowPruneState{}, 1)
	if err != nil {
		t.Fatalf("pruneStaleXDPFlowsMap() error = %v", err)
	}
	if metrics.Deleted != 1 {
		t.Fatalf("metrics.Deleted = %d, want 1", metrics.Deleted)
	}
	if got := corrections[11]; got.TCPActiveConns != -1 {
		t.Fatalf("corrections[11] = %+v, want tcp=-1", got)
	}
	if count, err := countXDPFlowMapEntries(flows); err != nil {
		t.Fatalf("countXDPFlowMapEntries() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countXDPFlowMapEntries() = %d, want 0", count)
	}
}

func TestDeleteStaleKernelFlowV6DeletesNATReservation(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})

	replyKey := tcFlowKeyV6{IfIndex: 8, SrcAddr: [16]byte{1}, DstAddr: [16]byte{2}, SrcPort: 80, DstPort: 20000, Proto: unix.IPPROTO_TCP}
	const sessionID = uint64(31001)
	replyValue := tcFlowValueV6{
		RuleID:     31,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT,
		NATAddr:    [16]byte{3},
		NATPort:    20000,
		InIfIndex:  5,
		FrontAddr:  [16]byte{4},
		ClientAddr: [16]byte{5},
		FrontPort:  443,
		ClientPort: 12345,
		LastSeenNS: 1,
		SessionID:  sessionID,
	}
	frontKey := tcFlowKeyV6{IfIndex: 5, SrcAddr: [16]byte{5}, DstAddr: [16]byte{4}, SrcPort: 12345, DstPort: 443, Proto: unix.IPPROTO_TCP}
	frontValue := tcFlowValueV6{
		RuleID:     31,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry,
		NATAddr:    [16]byte{3},
		NATPort:    20000,
		InIfIndex:  5,
		FrontAddr:  [16]byte{4},
		ClientAddr: [16]byte{5},
		FrontPort:  443,
		ClientPort: 12345,
		LastSeenNS: 1,
		SessionID:  sessionID,
	}
	natKey := tcNATPortKeyV6{IfIndex: 8, NATAddr: [16]byte{3}, NATPort: 20000, Proto: unix.IPPROTO_TCP}

	for _, item := range []struct {
		key   tcFlowKeyV6
		value tcFlowValueV6
	}{
		{key: replyKey, value: replyValue},
		{key: frontKey, value: frontValue},
	} {
		if err := flows.Put(item.key, item.value); err != nil {
			t.Fatalf("flows.Put(%+v) error = %v", item.key, err)
		}
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: 31, SessionID: sessionID}); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	corrections := map[uint32]kernelRuleStats{}
	deleteStaleKernelFlowV6(nil, flows, nat, staleKernelFlowV6{key: replyKey, value: replyValue}, corrections)

	if got := corrections[31]; got.TCPActiveConns != -1 {
		t.Fatalf("corrections[31] = %+v, want tcp=-1", got)
	}
	if count, err := countKernelFlowMapEntriesV6(flows); err != nil {
		t.Fatalf("countKernelFlowMapEntriesV6() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelFlowMapEntriesV6() = %d, want 0", count)
	}
	if count, err := countKernelNATMapEntriesV6(nat); err != nil {
		t.Fatalf("countKernelNATMapEntriesV6() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelNATMapEntriesV6() = %d, want 0", count)
	}
}

func TestPurgeKernelFlowsForRuleIDsPurgesIPv6State(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV6,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})

	replyKey := tcFlowKeyV6{IfIndex: 9, SrcAddr: [16]byte{1}, DstAddr: [16]byte{2}, SrcPort: 80, DstPort: 21000, Proto: unix.IPPROTO_TCP}
	const sessionID = uint64(41001)
	replyValue := tcFlowValueV6{
		RuleID:     41,
		Flags:      kernelFlowFlagCounted | kernelFlowFlagFullNAT,
		NATAddr:    [16]byte{3},
		NATPort:    21000,
		InIfIndex:  6,
		FrontAddr:  [16]byte{4},
		ClientAddr: [16]byte{5},
		FrontPort:  443,
		ClientPort: 34567,
		SessionID:  sessionID,
	}
	natKey := tcNATPortKeyV6{IfIndex: 9, NATAddr: [16]byte{3}, NATPort: 21000, Proto: unix.IPPROTO_TCP}
	if err := flows.Put(replyKey, replyValue); err != nil {
		t.Fatalf("flows.Put() error = %v", err)
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: 41, SessionID: sessionID}); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	corrections, deleted, err := purgeKernelFlowsForRuleIDs(kernelRuntimeMapRefs{
		flowsV6: flows,
		natV6:   nat,
	}, map[uint32]struct{}{41: {}})
	if err != nil {
		t.Fatalf("purgeKernelFlowsForRuleIDs() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}
	if got := corrections[41]; got.TCPActiveConns != -1 {
		t.Fatalf("corrections[41] = %+v, want tcp=-1", got)
	}
	if count, err := countKernelFlowMapEntriesV6(flows); err != nil {
		t.Fatalf("countKernelFlowMapEntriesV6() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelFlowMapEntriesV6() = %d, want 0", count)
	}
	if count, err := countKernelNATMapEntriesV6(nat); err != nil {
		t.Fatalf("countKernelNATMapEntriesV6() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelNATMapEntriesV6() = %d, want 0", count)
	}
}

func TestPurgeKernelFlowsForTargetsMatchesExactRevisionAcrossTCBanks(t *testing.T) {
	newFlowMap := func(name string) *ebpf.Map {
		return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
			ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
			MaxEntries: 16,
		})
	}
	active := newFlowMap(kernelFlowsMapName)
	old := newFlowMap(kernelTCFlowsOldMapNameV4)
	const (
		ruleID      = uint32(51)
		oldRevision = uint64(5101)
		newRevision = uint64(5102)
	)
	oldActiveKey := tcFlowKeyV4{IfIndex: 1, SrcAddr: 1, DstAddr: 2, SrcPort: 1001, DstPort: 80, Proto: unix.IPPROTO_TCP}
	newActiveKey := tcFlowKeyV4{IfIndex: 1, SrcAddr: 3, DstAddr: 4, SrcPort: 1002, DstPort: 80, Proto: unix.IPPROTO_TCP}
	oldBankKey := tcFlowKeyV4{IfIndex: 2, SrcAddr: 5, DstAddr: 6, SrcPort: 1003, DstPort: 80, Proto: unix.IPPROTO_TCP}
	for _, item := range []struct {
		m        *ebpf.Map
		key      tcFlowKeyV4
		revision uint64
	}{
		{active, oldActiveKey, oldRevision},
		{active, newActiveKey, newRevision},
		{old, oldBankKey, oldRevision},
	} {
		if err := item.m.Put(item.key, tcFlowValueV4{RuleID: ruleID, RuleRevision: item.revision, SessionID: uint64(item.key.SrcPort)}); err != nil {
			t.Fatalf("flow map Put(%+v) error = %v", item.key, err)
		}
	}

	_, deleted, err := purgeKernelFlowsForTargets(kernelRuntimeMapRefs{flowsV4: active, flowsOldV4: old}, map[kernelFlowPurgeTarget]struct{}{
		{RuleID: ruleID, RuleRevision: oldRevision}: {},
	}, false)
	if err != nil {
		t.Fatalf("purgeKernelFlowsForTargets() error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	if count, err := countKernelFlowMapEntries(active); err != nil {
		t.Fatalf("countKernelFlowMapEntries(active) error = %v", err)
	} else if count != 1 {
		t.Fatalf("countKernelFlowMapEntries(active) = %d, want 1", count)
	}
	if count, err := countKernelFlowMapEntries(old); err != nil {
		t.Fatalf("countKernelFlowMapEntries(old) error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelFlowMapEntries(old) = %d, want 0", count)
	}
	var preserved tcFlowValueV4
	if err := active.Lookup(newActiveKey, &preserved); err != nil {
		t.Fatalf("active.Lookup(new revision) error = %v", err)
	}
	if preserved.RuleRevision != newRevision {
		t.Fatalf("preserved revision = %d, want %d", preserved.RuleRevision, newRevision)
	}
}

func TestPurgeKernelFlowsForTargetsMatchesExactRevisionAcrossXDPBanks(t *testing.T) {
	newFlowMap := func(name string) *ebpf.Map {
		return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
			Name:       name,
			Type:       ebpf.Hash,
			KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
			ValueSize:  uint32(unsafe.Sizeof(xdpFlowValueV4{})),
			MaxEntries: 16,
		})
	}
	active := newFlowMap(kernelFlowsMapName)
	old := newFlowMap(kernelXDPFlowsOldMapNameV4)
	const (
		ruleID      = uint32(61)
		oldRevision = uint64(6101)
		newRevision = uint64(6102)
	)
	oldActiveKey := tcFlowKeyV4{IfIndex: 3, SrcAddr: 1, DstAddr: 2, SrcPort: 2001, DstPort: 443, Proto: unix.IPPROTO_TCP}
	newActiveKey := tcFlowKeyV4{IfIndex: 3, SrcAddr: 3, DstAddr: 4, SrcPort: 2002, DstPort: 443, Proto: unix.IPPROTO_TCP}
	oldBankKey := tcFlowKeyV4{IfIndex: 4, SrcAddr: 5, DstAddr: 6, SrcPort: 2003, DstPort: 443, Proto: unix.IPPROTO_TCP}
	for _, item := range []struct {
		m        *ebpf.Map
		key      tcFlowKeyV4
		revision uint64
	}{
		{active, oldActiveKey, oldRevision},
		{active, newActiveKey, newRevision},
		{old, oldBankKey, oldRevision},
	} {
		if err := item.m.Put(item.key, xdpFlowValueV4{RuleID: ruleID, RuleRevision: item.revision, SessionID: uint64(item.key.SrcPort)}); err != nil {
			t.Fatalf("xdp flow map Put(%+v) error = %v", item.key, err)
		}
	}

	_, deleted, err := purgeKernelFlowsForTargets(kernelRuntimeMapRefs{flowsV4: active, flowsOldV4: old}, map[kernelFlowPurgeTarget]struct{}{
		{RuleID: ruleID, RuleRevision: oldRevision}: {},
	}, true)
	if err != nil {
		t.Fatalf("purgeKernelFlowsForTargets(xdp) error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	if count, err := countXDPFlowMapEntries(active); err != nil {
		t.Fatalf("countXDPFlowMapEntries(active) error = %v", err)
	} else if count != 1 {
		t.Fatalf("countXDPFlowMapEntries(active) = %d, want 1", count)
	}
	if count, err := countXDPFlowMapEntries(old); err != nil {
		t.Fatalf("countXDPFlowMapEntries(old) error = %v", err)
	} else if count != 0 {
		t.Fatalf("countXDPFlowMapEntries(old) = %d, want 0", count)
	}
	var preserved xdpFlowValueV4
	if err := active.Lookup(newActiveKey, &preserved); err != nil {
		t.Fatalf("active.Lookup(new xdp revision) error = %v", err)
	}
	if preserved.RuleRevision != newRevision {
		t.Fatalf("preserved xdp revision = %d, want %d", preserved.RuleRevision, newRevision)
	}
}

func TestDeleteStaleKernelFlowPreservesReplacementOwners(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})
	replyKey := tcFlowKeyV4{IfIndex: 9, SrcAddr: 1, DstAddr: 2, SrcPort: 80, DstPort: 22000, Proto: unix.IPPROTO_TCP}
	frontKey := tcFlowKeyV4{IfIndex: 5, SrcAddr: 5, DstAddr: 4, SrcPort: 34567, DstPort: 443, Proto: unix.IPPROTO_TCP}
	staleReply := tcFlowValueV4{
		RuleID: 71, Flags: kernelFlowFlagFullNAT, NATAddr: 3, NATPort: 22000,
		InIfIndex: 5, FrontAddr: 4, ClientAddr: 5, FrontPort: 443, ClientPort: 34567,
		RuleRevision: 7101, SessionID: 71001,
	}
	replacementFront := staleReply
	replacementFront.Flags |= kernelFlowFlagFrontEntry
	replacementFront.RuleRevision = 7102
	replacementFront.SessionID = 71002
	natKey := tcNATPortKeyV4{IfIndex: 9, NATAddr: 3, NATPort: 22000, Proto: unix.IPPROTO_TCP}
	if err := flows.Put(replyKey, staleReply); err != nil {
		t.Fatalf("flows.Put(reply) error = %v", err)
	}
	if err := flows.Put(frontKey, replacementFront); err != nil {
		t.Fatalf("flows.Put(replacement front) error = %v", err)
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: 71, SessionID: replacementFront.SessionID}); err != nil {
		t.Fatalf("nat.Put(replacement) error = %v", err)
	}

	deleted := deleteStaleKernelFlow(nil, flows, nat, staleKernelFlow{key: replyKey, value: staleReply}, map[uint32]kernelRuleStats{})
	if deleted != 1 {
		t.Fatalf("deleted = %d, want only stale reply", deleted)
	}
	var gotFront tcFlowValueV4
	if err := flows.Lookup(frontKey, &gotFront); err != nil {
		t.Fatalf("flows.Lookup(replacement front) error = %v", err)
	}
	if gotFront.SessionID != replacementFront.SessionID {
		t.Fatalf("replacement front session = %d, want %d", gotFront.SessionID, replacementFront.SessionID)
	}
	var gotNAT tcNATPortValue
	if err := nat.Lookup(natKey, &gotNAT); err != nil {
		t.Fatalf("nat.Lookup(replacement) error = %v", err)
	}
	if gotNAT.SessionID != replacementFront.SessionID {
		t.Fatalf("replacement nat session = %d, want %d", gotNAT.SessionID, replacementFront.SessionID)
	}

	replacementReply := staleReply
	replacementReply.RuleRevision = 7102
	replacementReply.SessionID = 71003
	if err := flows.Put(replyKey, replacementReply); err != nil {
		t.Fatalf("flows.Put(replacement reply) error = %v", err)
	}
	deleted = deleteStaleKernelFlow(nil, flows, nat, staleKernelFlow{key: replyKey, value: staleReply}, map[uint32]kernelRuleStats{})
	if deleted != 0 {
		t.Fatalf("replacement reply deleted = %d, want 0", deleted)
	}
	var gotReply tcFlowValueV4
	if err := flows.Lookup(replyKey, &gotReply); err != nil {
		t.Fatalf("flows.Lookup(replacement reply) error = %v", err)
	}
	if gotReply.SessionID != replacementReply.SessionID {
		t.Fatalf("replacement reply session = %d, want %d", gotReply.SessionID, replacementReply.SessionID)
	}
}

func TestDeleteStaleKernelFlowDeletesFullConeFront(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelNatPortsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})
	const sessionID = uint64(81001)
	replyKey := tcFlowKeyV4{IfIndex: 9, SrcAddr: 8, DstAddr: 3, SrcPort: 53, DstPort: 23000, Proto: unix.IPPROTO_UDP}
	replyValue := tcFlowValueV4{
		RuleID: 81, Flags: kernelFlowFlagFullNAT | kernelFlowFlagFullCone,
		NATAddr: 3, NATPort: 23000, InIfIndex: 5, ClientAddr: 6, ClientPort: 40000,
		RuleRevision: 8101, SessionID: sessionID,
	}
	frontKey := tcFlowKeyV4{IfIndex: 5, SrcAddr: 6, SrcPort: 40000, Proto: unix.IPPROTO_UDP}
	frontValue := replyValue
	frontValue.Flags |= kernelFlowFlagFrontEntry
	natKey := tcNATPortKeyV4{IfIndex: 9, NATAddr: 3, NATPort: 23000, Proto: unix.IPPROTO_UDP}
	if err := flows.Put(replyKey, replyValue); err != nil {
		t.Fatalf("flows.Put(reply) error = %v", err)
	}
	if err := flows.Put(frontKey, frontValue); err != nil {
		t.Fatalf("flows.Put(full-cone front) error = %v", err)
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: 81, SessionID: sessionID}); err != nil {
		t.Fatalf("nat.Put() error = %v", err)
	}

	deleted := deleteStaleKernelFlow(nil, flows, nat, staleKernelFlow{key: replyKey, value: replyValue}, map[uint32]kernelRuleStats{})
	if deleted != 2 {
		t.Fatalf("deleted = %d, want reply and full-cone front", deleted)
	}
	if count, err := countKernelFlowMapEntries(flows); err != nil {
		t.Fatalf("countKernelFlowMapEntries() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelFlowMapEntries() = %d, want 0", count)
	}
	if count, err := countKernelNATMapEntries(nat); err != nil {
		t.Fatalf("countKernelNATMapEntries() error = %v", err)
	} else if count != 0 {
		t.Fatalf("countKernelNATMapEntries() = %d, want 0", count)
	}
}

func TestPruneOrphanKernelNATBanksIsolatesIPv4Ownership(t *testing.T) {
	engines := []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	}
	for _, engine := range engines {
		for _, liveBank := range []string{"active", "old"} {
			t.Run(engine.name+"/"+liveBank, func(t *testing.T) {
				flowValueSize := uint32(unsafe.Sizeof(tcFlowValueV4{}))
				if engine.xdp {
					flowValueSize = uint32(unsafe.Sizeof(xdpFlowValueV4{}))
				}
				newFlowMap := func(name string) *ebpf.Map {
					return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
						Name:       name,
						Type:       ebpf.Hash,
						KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
						ValueSize:  flowValueSize,
						MaxEntries: 16,
					})
				}
				newNATMap := func(name string) *ebpf.Map {
					return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
						Name:       name,
						Type:       ebpf.Hash,
						KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
						ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
						MaxEntries: 16,
					})
				}

				activeFlows := newFlowMap("active_flow_v4")
				oldFlows := newFlowMap("old_flow_v4")
				activeNAT := newNATMap("active_nat_v4")
				oldNAT := newNATMap("old_nat_v4")
				flowKey := tcFlowKeyV4{
					IfIndex: 9,
					SrcAddr: 1,
					DstAddr: 2,
					SrcPort: 443,
					DstPort: 32000,
					Proto:   unix.IPPROTO_TCP,
				}
				const sessionID = uint64(0x101010101)
				flowValue := tcFlowValueV4{
					RuleID:       101,
					Flags:        kernelFlowFlagFullNAT | kernelFlowFlagCounted | kernelFlowFlagReplySeen,
					NATAddr:      3,
					NATPort:      32000,
					LastSeenNS:   1,
					RuleRevision: 10101,
					SessionID:    sessionID,
				}
				liveFlows := activeFlows
				if liveBank == "old" {
					liveFlows = oldFlows
				}
				if engine.xdp {
					if err := liveFlows.Put(flowKey, xdpFlowValueV4{
						RuleID:       flowValue.RuleID,
						Flags:        flowValue.Flags,
						NATAddr:      flowValue.NATAddr,
						NATPort:      flowValue.NATPort,
						LastSeenNS:   flowValue.LastSeenNS,
						RuleRevision: flowValue.RuleRevision,
						SessionID:    flowValue.SessionID,
					}); err != nil {
						t.Fatalf("put xdp flow: %v", err)
					}
				} else if err := liveFlows.Put(flowKey, flowValue); err != nil {
					t.Fatalf("put tc flow: %v", err)
				}

				natKey := tcNATPortKeyV4{IfIndex: flowKey.IfIndex, NATAddr: flowValue.NATAddr, NATPort: flowValue.NATPort, Proto: flowKey.Proto}
				natValue := tcNATPortValue{RuleID: flowValue.RuleID, SessionID: sessionID}
				for _, natMap := range []*ebpf.Map{activeNAT, oldNAT} {
					if err := natMap.Put(natKey, natValue); err != nil {
						t.Fatalf("put nat reservation: %v", err)
					}
				}

				refs := kernelRuntimeMapRefs{
					flowsV4:    activeFlows,
					flowsOldV4: oldFlows,
					natV4:      activeNAT,
					natOldV4:   oldNAT,
				}
				var live kernelFlowLiveStateSnapshot
				var err error
				if engine.xdp {
					live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs, true)
				} else {
					live, err = snapshotKernelLiveStateFromRuntimeMapRefs(refs, true)
				}
				if err != nil {
					t.Fatalf("snapshot live state: %v", err)
				}
				if got, want := len(live.NATByBank.activeV4), 0; liveBank == "active" {
					want = 1
					if got != want {
						t.Fatalf("active bank used owners = %d, want %d", got, want)
					}
				} else if got != want {
					t.Fatalf("active bank used owners = %d, want %d", got, want)
				}
				if got, want := len(live.NATByBank.oldV4), 0; liveBank == "old" {
					want = 1
					if got != want {
						t.Fatalf("old bank used owners = %d, want %d", got, want)
					}
				} else if got != want {
					t.Fatalf("old bank used owners = %d, want %d", got, want)
				}

				natEntries, deleted, state, err := pruneOrphanKernelNATBanks(refs, live.NATByBank, kernelNATPruneState{})
				if err != nil {
					t.Fatalf("first bank prune: %v", err)
				}
				if natEntries != 2 || deleted != 0 {
					t.Fatalf("first bank prune entries/deleted = %d/%d, want 2/0", natEntries, deleted)
				}
				natEntries, deleted, _, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, state)
				if err != nil {
					t.Fatalf("second bank prune: %v", err)
				}
				if natEntries != 1 || deleted != 1 {
					t.Fatalf("second bank prune entries/deleted = %d/%d, want 1/1", natEntries, deleted)
				}
				activeCount, err := countKernelNATMapEntries(activeNAT)
				if err != nil {
					t.Fatalf("count active NAT: %v", err)
				}
				oldCount, err := countKernelNATMapEntries(oldNAT)
				if err != nil {
					t.Fatalf("count old NAT: %v", err)
				}
				if liveBank == "active" && (activeCount != 1 || oldCount != 0) {
					t.Fatalf("active/old NAT counts = %d/%d, want 1/0", activeCount, oldCount)
				}
				if liveBank == "old" && (activeCount != 0 || oldCount != 1) {
					t.Fatalf("active/old NAT counts = %d/%d, want 0/1", activeCount, oldCount)
				}
			})
		}
	}
}

func TestPruneOrphanKernelNATBanksIsolatesIPv6Ownership(t *testing.T) {
	for _, snapshotKind := range []string{"tc", "xdp"} {
		for _, liveBank := range []string{"active", "old"} {
			t.Run(snapshotKind+"/"+liveBank, func(t *testing.T) {
				newFlowMap := func(name string) *ebpf.Map {
					return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
						Name:       name,
						Type:       ebpf.Hash,
						KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
						ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
						MaxEntries: 16,
					})
				}
				newNATMap := func(name string) *ebpf.Map {
					return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
						Name:       name,
						Type:       ebpf.Hash,
						KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
						ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
						MaxEntries: 16,
					})
				}

				activeFlows := newFlowMap("active_flow_v6")
				oldFlows := newFlowMap("old_flow_v6")
				activeNAT := newNATMap("active_nat_v6")
				oldNAT := newNATMap("old_nat_v6")
				flowKey := tcFlowKeyV6{
					IfIndex: 11,
					SrcAddr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 1},
					DstAddr: [16]byte{0x20, 0x01, 0x0d, 0xb8, 2},
					SrcPort: 443,
					DstPort: 33000,
					Proto:   unix.IPPROTO_TCP,
				}
				const sessionID = uint64(0x202020202)
				flowValue := tcFlowValueV6{
					RuleID:       202,
					Flags:        kernelFlowFlagFullNAT | kernelFlowFlagCounted | kernelFlowFlagReplySeen,
					NATAddr:      [16]byte{0x20, 0x01, 0x0d, 0xb8, 3},
					NATPort:      33000,
					LastSeenNS:   1,
					RuleRevision: 20202,
					SessionID:    sessionID,
				}
				liveFlows := activeFlows
				if liveBank == "old" {
					liveFlows = oldFlows
				}
				if err := liveFlows.Put(flowKey, flowValue); err != nil {
					t.Fatalf("put IPv6 flow: %v", err)
				}

				natKey := tcNATPortKeyV6{IfIndex: flowKey.IfIndex, NATAddr: flowValue.NATAddr, NATPort: flowValue.NATPort, Proto: flowKey.Proto}
				natValue := tcNATPortValue{RuleID: flowValue.RuleID, SessionID: sessionID}
				for _, natMap := range []*ebpf.Map{activeNAT, oldNAT} {
					if err := natMap.Put(natKey, natValue); err != nil {
						t.Fatalf("put IPv6 NAT reservation: %v", err)
					}
				}

				refs := kernelRuntimeMapRefs{
					flowsV6:    activeFlows,
					flowsOldV6: oldFlows,
					natV6:      activeNAT,
					natOldV6:   oldNAT,
				}
				var live kernelFlowLiveStateSnapshot
				var err error
				if snapshotKind == "xdp" {
					live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs, true)
				} else {
					live, err = snapshotKernelLiveStateFromRuntimeMapRefs(refs, true)
				}
				if err != nil {
					t.Fatalf("snapshot IPv6 live state: %v", err)
				}
				if got, want := len(live.NATByBank.activeV6), 0; liveBank == "active" {
					want = 1
					if got != want {
						t.Fatalf("active IPv6 bank used owners = %d, want %d", got, want)
					}
				} else if got != want {
					t.Fatalf("active IPv6 bank used owners = %d, want %d", got, want)
				}
				if got, want := len(live.NATByBank.oldV6), 0; liveBank == "old" {
					want = 1
					if got != want {
						t.Fatalf("old IPv6 bank used owners = %d, want %d", got, want)
					}
				} else if got != want {
					t.Fatalf("old IPv6 bank used owners = %d, want %d", got, want)
				}

				natEntries, deleted, state, err := pruneOrphanKernelNATBanks(refs, live.NATByBank, kernelNATPruneState{})
				if err != nil {
					t.Fatalf("first IPv6 bank prune: %v", err)
				}
				if natEntries != 2 || deleted != 0 {
					t.Fatalf("first IPv6 bank prune entries/deleted = %d/%d, want 2/0", natEntries, deleted)
				}
				natEntries, deleted, _, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, state)
				if err != nil {
					t.Fatalf("second IPv6 bank prune: %v", err)
				}
				if natEntries != 1 || deleted != 1 {
					t.Fatalf("second IPv6 bank prune entries/deleted = %d/%d, want 1/1", natEntries, deleted)
				}
				activeCount, err := countKernelNATMapEntriesV6(activeNAT)
				if err != nil {
					t.Fatalf("count active IPv6 NAT: %v", err)
				}
				oldCount, err := countKernelNATMapEntriesV6(oldNAT)
				if err != nil {
					t.Fatalf("count old IPv6 NAT: %v", err)
				}
				if liveBank == "active" && (activeCount != 1 || oldCount != 0) {
					t.Fatalf("active/old IPv6 NAT counts = %d/%d, want 1/0", activeCount, oldCount)
				}
				if liveBank == "old" && (activeCount != 0 || oldCount != 1) {
					t.Fatalf("active/old IPv6 NAT counts = %d/%d, want 0/1", activeCount, oldCount)
				}
			})
		}
	}
}
