package app

import "testing"

func TestNormalizeKernelNATPortRangeDefaults(t *testing.T) {
	min, max, err := normalizeKernelNATPortRange(0, 0)
	if err != nil {
		t.Fatalf("normalizeKernelNATPortRange(0, 0) error = %v", err)
	}
	if min != kernelDefaultNATPortMin || max != kernelDefaultNATPortMax {
		t.Fatalf("normalizeKernelNATPortRange(0, 0) = (%d, %d), want (%d, %d)", min, max, kernelDefaultNATPortMin, kernelDefaultNATPortMax)
	}
}

func TestNormalizeKernelNATPortRangePartialOverride(t *testing.T) {
	min, max, err := normalizeKernelNATPortRange(30000, 0)
	if err != nil {
		t.Fatalf("normalizeKernelNATPortRange(30000, 0) error = %v", err)
	}
	if min != 30000 || max != kernelDefaultNATPortMax {
		t.Fatalf("normalizeKernelNATPortRange(30000, 0) = (%d, %d), want (30000, %d)", min, max, kernelDefaultNATPortMax)
	}
}

func TestNormalizeKernelNATPortRangeRejectsInvalidBounds(t *testing.T) {
	cases := []struct {
		name string
		min  int
		max  int
	}{
		{name: "too_low", min: 1000, max: 2000},
		{name: "too_high", min: 20000, max: 70000},
		{name: "reversed", min: 40000, max: 30000},
	}
	for _, tc := range cases {
		if _, _, err := normalizeKernelNATPortRange(tc.min, tc.max); err == nil {
			t.Fatalf("normalizeKernelNATPortRange(%d, %d) error = nil, want failure for %s", tc.min, tc.max, tc.name)
		}
	}
}
