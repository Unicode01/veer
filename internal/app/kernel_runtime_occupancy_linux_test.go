//go:build linux

package app

import "testing"

func TestClampKernelOccupancyEntries(t *testing.T) {
	tests := []struct {
		name     string
		entries  int64
		capacity uint32
		want     int
	}{
		{name: "negative", entries: -3, capacity: 64, want: 0},
		{name: "zero", entries: 0, capacity: 64, want: 0},
		{name: "within capacity", entries: 17, capacity: 64, want: 17},
		{name: "clamped to capacity", entries: 128, capacity: 64, want: 64},
		{name: "no capacity", entries: 9, capacity: 0, want: 9},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampKernelOccupancyEntries(tc.entries, tc.capacity); got != tc.want {
				t.Fatalf("clampKernelOccupancyEntries(%d, %d) = %d, want %d", tc.entries, tc.capacity, got, tc.want)
			}
		})
	}
}
