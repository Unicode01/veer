//go:build linux

package app

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAggregateKernelPerCPUStats(t *testing.T) {
	values := []kernelStatsValueV4{
		{TotalConns: 10, TCPActiveConns: 3, UDPNatEntries: 4, BytesIn: 100, BytesOut: 200},
		{TotalConns: 5, TCPActiveConns: 2, UDPNatEntries: 1, BytesIn: 30, BytesOut: 40},
		{TotalConns: 7, TCPActiveConns: 1, UDPNatEntries: 6, BytesIn: 70, BytesOut: 80},
	}

	got := aggregateKernelPerCPUStats(values)
	want := kernelStatsValueV4{
		TotalConns:     22,
		TCPActiveConns: 6,
		UDPNatEntries:  11,
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

func TestKernelLiveStatsCorrection(t *testing.T) {
	observed := map[uint32]kernelStatsValueV4{
		1: {TCPActiveConns: 10, UDPNatEntries: 4, TotalConns: 100, BytesIn: 2000, BytesOut: 3000},
		2: {TCPActiveConns: 1},
	}
	live := map[uint32]kernelStatsValueV4{
		1: {TCPActiveConns: 3, UDPNatEntries: 2},
		3: {UDPNatEntries: 5},
	}

	got := kernelLiveStatsCorrection(observed, live)
	want := map[uint32]kernelRuleStats{
		1: {TCPActiveConns: -7, UDPNatEntries: -2},
		2: {TCPActiveConns: -1},
		3: {UDPNatEntries: 5},
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
		7: {TCPActiveConns: 5, UDPNatEntries: 5},
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
		if flow.key.Proto == unix.IPPROTO_UDP {
			item.UDPNatEntries++
		} else {
			item.TCPActiveConns++
		}
		live[flow.value.RuleID] = item
	}

	got := kernelLiveStatsCorrection(observed, live)
	want := kernelRuleStats{TCPActiveConns: -4, UDPNatEntries: -4}
	if got[7] != want {
		t.Fatalf("kernelLiveStatsCorrection()[7] = %+v, want %+v", got[7], want)
	}
}
