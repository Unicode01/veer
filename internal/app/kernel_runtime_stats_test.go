//go:build linux

package app

import "testing"

func TestAggregateKernelPerCPUStats(t *testing.T) {
	values := []kernelStatsValueV4{
		{TotalConns: 10, TCPActiveConns: 3, UDPNatEntries: 4},
		{TotalConns: 5, TCPActiveConns: 2, UDPNatEntries: 1},
		{TotalConns: 7, TCPActiveConns: 1, UDPNatEntries: 6},
	}

	got := aggregateKernelPerCPUStats(values)
	want := kernelStatsValueV4{
		TotalConns:     22,
		TCPActiveConns: 6,
		UDPNatEntries:  11,
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
