package netutil

import "testing"

func TestKernelNATPortWindowSkipsTheHostEphemeralRange(t *testing.T) {
	for _, tc := range []struct {
		name             string
		poolMin, poolMax int
		ephMin, ephMax   int
		wantMin, wantMax int
		wantShared       bool
	}{
		// Linux's default ephemeral range against the default pool.
		{"default", 20000, 65535, 32768, 60999, 20000, 32767, false},
		{"upper part larger", 30000, 65535, 32768, 40000, 40001, 65535, false},
		{"tie keeps the lower part", 1100, 1300, 1150, 1250, 1100, 1149, false},
		{"pool below the range", 20000, 30000, 32768, 60999, 20000, 30000, false},
		{"pool above the range", 61000, 65535, 32768, 60999, 61000, 65535, false},
		{"pool inside the range", 40000, 50000, 32768, 60999, 40000, 50000, true},
		{"pool equals the range", 32768, 60999, 32768, 60999, 32768, 60999, true},
		{"range unknown", 20000, 65535, 0, 0, 20000, 65535, false},
		{"range inverted", 20000, 65535, 50000, 40000, 20000, 65535, false},
	} {
		min, max, shared := KernelNATPortWindow(tc.poolMin, tc.poolMax, tc.ephMin, tc.ephMax)
		if min != tc.wantMin || max != tc.wantMax || shared != tc.wantShared {
			t.Errorf("%s: KernelNATPortWindow(%d-%d, %d-%d) = %d-%d shared=%v, want %d-%d shared=%v",
				tc.name, tc.poolMin, tc.poolMax, tc.ephMin, tc.ephMax, min, max, shared, tc.wantMin, tc.wantMax, tc.wantShared)
		}
	}
}
