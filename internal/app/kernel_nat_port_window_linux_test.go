//go:build linux

package app

import (
	"errors"
	"testing"
)

func stubHostEphemeralPortRange(t *testing.T, low, high int, err error) {
	t.Helper()
	previous := readHostEphemeralPortRange
	readHostEphemeralPortRange = func() (int, int, error) { return low, high, err }
	t.Cleanup(func() { readHostEphemeralPortRange = previous })
}

func TestTCKernelNATPortWindowAvoidsHostEphemeralPorts(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cfg              *Config
		low, high        int
		err              error
		wantMin, wantMax int
	}{
		{"default pool", &Config{}, 32768, 60999, nil, 20000, 32767},
		{"nil config", nil, 32768, 60999, nil, 20000, 32767},
		{"pool above the range", &Config{KernelNATPortMin: 61000, KernelNATPortMax: 65535}, 32768, 60999, nil, 61000, 65535},
		{"upper part larger", &Config{KernelNATPortMin: 30000, KernelNATPortMax: 65535}, 32768, 40000, nil, 40001, 65535},
		{"pool inside the range stays", &Config{KernelNATPortMin: 40000, KernelNATPortMax: 50000}, 32768, 60999, nil, 40000, 50000},
		{"range unreadable", &Config{}, 0, 0, errors.New("no procfs"), 20000, 65535},
	} {
		stubHostEphemeralPortRange(t, tc.low, tc.high, tc.err)
		rt := newTCKernelRuleRuntime(tc.cfg)
		if rt.natPortMin != tc.wantMin || rt.natPortMax != tc.wantMax {
			t.Errorf("%s: tc nat ports %d-%d, want %d-%d", tc.name, rt.natPortMin, rt.natPortMax, tc.wantMin, tc.wantMax)
		}
	}
}
