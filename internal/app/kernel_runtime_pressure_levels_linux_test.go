//go:build linux

package app

import (
	"strings"
	"testing"
)

func TestBuildKernelRuntimePressureStateLevels(t *testing.T) {
	cases := []struct {
		name          string
		previousLevel kernelRuntimePressureLevel
		flowsEntries  int
		wantLevel     kernelRuntimePressureLevel
		wantText      string
	}{
		{
			name:         "below hold watermark stays clear",
			flowsEntries: 91,
			wantLevel:    kernelRuntimePressureLevelNone,
		},
		{
			name:         "hold watermark keeps existing owners",
			flowsEntries: 92,
			wantLevel:    kernelRuntimePressureLevelHold,
			wantText:     "keeping existing kernel owners",
		},
		{
			name:         "shed watermark drops subset",
			flowsEntries: 96,
			wantLevel:    kernelRuntimePressureLevelShed,
			wantText:     "shedding a subset of kernel owners",
		},
		{
			name:         "full watermark routes all owners out",
			flowsEntries: 99,
			wantLevel:    kernelRuntimePressureLevelFull,
			wantText:     "routing all kernel owners to userspace",
		},
		{
			name:          "active pressure holds until release watermark",
			previousLevel: kernelRuntimePressureLevelShed,
			flowsEntries:  90,
			wantLevel:     kernelRuntimePressureLevelHold,
			wantText:      "keeping existing kernel owners",
		},
		{
			name:          "pressure clears below release watermark",
			previousLevel: kernelRuntimePressureLevelHold,
			flowsEntries:  84,
			wantLevel:     kernelRuntimePressureLevelNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := buildKernelRuntimePressureState(tc.previousLevel, tc.flowsEntries, 100, 0, 0, false)
			if state.level != tc.wantLevel {
				t.Fatalf("buildKernelRuntimePressureState() level = %q, want %q", state.level, tc.wantLevel)
			}
			if tc.wantLevel == kernelRuntimePressureLevelNone {
				if state.active {
					t.Fatalf("buildKernelRuntimePressureState() active = true, want false for level %q", tc.wantLevel)
				}
				return
			}
			if !state.active {
				t.Fatalf("buildKernelRuntimePressureState() active = false, want true for level %q", tc.wantLevel)
			}
			if !strings.Contains(state.reason, tc.wantText) {
				t.Fatalf("buildKernelRuntimePressureState() reason = %q, want substring %q", state.reason, tc.wantText)
			}
		})
	}
}
