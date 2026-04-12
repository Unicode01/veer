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
	dst.UsedNAT[tcNATPortKeyV4{IfIndex: 2, NATAddr: 3, NATPort: 4, Proto: unix.IPPROTO_UDP}] = struct{}{}
	dst.FlowEntries = 2

	src := newKernelFlowLiveStateSnapshot(false)
	src.ByRuleID[1] = kernelStatsValueV4{UDPNatEntries: 2}
	src.ByRuleID[2] = kernelStatsValueV4{ICMPNatEntries: 3}
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
	if len(dst.UsedNAT) != 1 {
		t.Fatalf("mergeKernelLiveStateSnapshot() used nat len = %d, want 1", len(dst.UsedNAT))
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

	live, err := snapshotXDPKernelLiveStateFromRuntimeMapRefs(kernelRuntimeMapRefs{flowsV4: flows})
	if err != nil {
		t.Fatalf("snapshotXDPKernelLiveStateFromRuntimeMapRefs() error = %v", err)
	}
	if live.FlowEntries != 2 {
		t.Fatalf("live.FlowEntries = %d, want 2", live.FlowEntries)
	}
	if got := live.ByRuleID[7]; got.TCPActiveConns != 1 || got.UDPNatEntries != 0 || got.ICMPNatEntries != 0 {
		t.Fatalf("live.ByRuleID[7] = %+v, want tcp=1", got)
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

	corrections, metrics, err := pruneStaleXDPFlowsMap(nil, flows, &kernelFlowPruneState{}, 1)
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
