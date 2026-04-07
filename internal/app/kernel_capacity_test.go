package app

import "testing"

func withKernelAdaptiveMapProfileForTest(profile kernelAdaptiveMapProfile, fn func()) {
	prevProfile := kernelAdaptiveMapProfileOverride
	prevSet := kernelAdaptiveMapProfileOverrideSet
	kernelAdaptiveMapProfileOverride = profile
	kernelAdaptiveMapProfileOverrideSet = true
	defer func() {
		kernelAdaptiveMapProfileOverride = prevProfile
		kernelAdaptiveMapProfileOverrideSet = prevSet
	}()
	fn()
}

func TestEffectiveKernelRulesMapLimitAdaptive(t *testing.T) {
	cases := []struct {
		name       string
		configured int
		requested  int
		want       int
	}{
		{name: "default floor", configured: 0, requested: 0, want: kernelRulesMapBaseLimit},
		{name: "keep base bucket", configured: 0, requested: 20000, want: 32768},
		{name: "next bucket", configured: 0, requested: 40000, want: 65536},
		{name: "adaptive ceiling", configured: 0, requested: 300000, want: kernelRulesMapAdaptiveMaxLimit},
		{name: "fixed override", configured: 20000, requested: 5000, want: 20000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveKernelRulesMapLimit(tc.configured, tc.requested)
			if got != tc.want {
				t.Fatalf("effectiveKernelRulesMapLimit(%d, %d) = %d, want %d", tc.configured, tc.requested, got, tc.want)
			}
		})
	}
}

func TestKernelRulesCapacityReason(t *testing.T) {
	gotAdaptive := kernelRulesCapacityReason(0, 300000)
	wantAdaptive := "adaptive kernel rules map capacity 262144 is lower than requested entries 300000"
	if gotAdaptive != wantAdaptive {
		t.Fatalf("adaptive reason = %q, want %q", gotAdaptive, wantAdaptive)
	}

	gotFixed := kernelRulesCapacityReason(20000, 30000)
	wantFixed := "kernel rules map capacity 20000 is lower than requested entries 30000"
	if gotFixed != wantFixed {
		t.Fatalf("fixed reason = %q, want %q", gotFixed, wantFixed)
	}
}

func TestKernelEgressNATAutoMapFloors(t *testing.T) {
	withKernelAdaptiveMapProfileForTest(defaultKernelAdaptiveMapProfile(), func() {
		flows, nat := kernelEgressNATAutoMapFloors(0, 0, false)
		if flows != 0 || nat != 0 {
			t.Fatalf("kernelEgressNATAutoMapFloors() without egress nat = (%d, %d), want (0, 0)", flows, nat)
		}

		flows, nat = kernelEgressNATAutoMapFloors(0, 0, true)
		if flows != kernelEgressNATAutoMapFloor || nat != kernelEgressNATAutoMapFloor {
			t.Fatalf(
				"kernelEgressNATAutoMapFloors() default = (%d, %d), want (%d, %d)",
				flows,
				nat,
				kernelEgressNATAutoMapFloor,
				kernelEgressNATAutoMapFloor,
			)
		}

		flows, nat = kernelEgressNATAutoMapFloors(524288, 0, true)
		if flows != 524288 || nat != kernelEgressNATAutoMapFloor {
			t.Fatalf("kernelEgressNATAutoMapFloors() mixed override = (%d, %d), want (524288, %d)", flows, nat, kernelEgressNATAutoMapFloor)
		}

		flows, nat = kernelEgressNATAutoMapFloors(131072, 131072, true)
		if flows != 131072 || nat != 131072 {
			t.Fatalf("kernelEgressNATAutoMapFloors() explicit limits = (%d, %d), want (131072, 131072)", flows, nat)
		}
	})
}

func TestAdaptiveKernelMapLimitForLiveEntries(t *testing.T) {
	if got := adaptiveKernelMapLimitForLiveEntries(0, kernelFlowsMapBaseLimit, kernelFlowsMapAdaptiveMaxLimit); got != 0 {
		t.Fatalf("adaptiveKernelMapLimitForLiveEntries(0, ...) = %d, want 0", got)
	}
	if got := adaptiveKernelMapLimitForLiveEntries(180000, kernelFlowsMapBaseLimit, kernelFlowsMapAdaptiveMaxLimit); got != kernelFlowsMapBaseLimit {
		t.Fatalf("adaptiveKernelMapLimitForLiveEntries(180000, ...) = %d, want %d", got, kernelFlowsMapBaseLimit)
	}
	if got := adaptiveKernelMapLimitForLiveEntries(200000, kernelFlowsMapBaseLimit, kernelFlowsMapAdaptiveMaxLimit); got != 524288 {
		t.Fatalf("adaptiveKernelMapLimitForLiveEntries(200000, ...) = %d, want 524288", got)
	}
	if got := adaptiveKernelMapLimitForLiveEntries(900000, kernelFlowsMapBaseLimit, kernelFlowsMapAdaptiveMaxLimit); got != kernelFlowsMapAdaptiveMaxLimit {
		t.Fatalf("adaptiveKernelMapLimitForLiveEntries(900000, ...) = %d, want %d", got, kernelFlowsMapAdaptiveMaxLimit)
	}
}

func TestKernelAdaptiveMapProfileForTotalMemory(t *testing.T) {
	cases := []struct {
		name             string
		totalMemoryBytes uint64
		wantFlowsBase    int
		wantNATBase      int
		wantEgressFloor  int
	}{
		{name: "unknown defaults", totalMemoryBytes: 0, wantFlowsBase: 262144, wantNATBase: 262144, wantEgressFloor: 262144},
		{name: "small memory", totalMemoryBytes: (1 << 30) + (512 << 20), wantFlowsBase: 65536, wantNATBase: 65536, wantEgressFloor: 65536},
		{name: "mid memory", totalMemoryBytes: 4 << 30, wantFlowsBase: 131072, wantNATBase: 131072, wantEgressFloor: 131072},
		{name: "large memory", totalMemoryBytes: 8 << 30, wantFlowsBase: 262144, wantNATBase: 262144, wantEgressFloor: 262144},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := kernelAdaptiveMapProfileForTotalMemory(tc.totalMemoryBytes)
			if got.flowsBaseLimit != tc.wantFlowsBase || got.natBaseLimit != tc.wantNATBase || got.egressNATAutoFloor != tc.wantEgressFloor {
				t.Fatalf(
					"kernelAdaptiveMapProfileForTotalMemory(%d) = flows:%d nat:%d floor:%d, want flows:%d nat:%d floor:%d",
					tc.totalMemoryBytes,
					got.flowsBaseLimit,
					got.natBaseLimit,
					got.egressNATAutoFloor,
					tc.wantFlowsBase,
					tc.wantNATBase,
					tc.wantEgressFloor,
				)
			}
		})
	}
}

func TestKernelAdaptiveMapProfileName(t *testing.T) {
	cases := []struct {
		name    string
		profile kernelAdaptiveMapProfile
		want    string
	}{
		{
			name: "default",
			profile: kernelAdaptiveMapProfile{
				flowsBaseLimit:     kernelFlowsMapBaseLimit,
				natBaseLimit:       kernelNATMapBaseLimit,
				egressNATAutoFloor: kernelEgressNATAutoMapFloor,
			},
			want: kernelAdaptiveMapProfileDefault,
		},
		{
			name: "small",
			profile: kernelAdaptiveMapProfile{
				totalMemoryBytes:   1 << 30,
				flowsBaseLimit:     65536,
				natBaseLimit:       65536,
				egressNATAutoFloor: 65536,
			},
			want: kernelAdaptiveMapProfileSmall,
		},
		{
			name: "medium",
			profile: kernelAdaptiveMapProfile{
				totalMemoryBytes:   4 << 30,
				flowsBaseLimit:     131072,
				natBaseLimit:       131072,
				egressNATAutoFloor: 131072,
			},
			want: kernelAdaptiveMapProfileMedium,
		},
		{
			name: "large",
			profile: kernelAdaptiveMapProfile{
				totalMemoryBytes:   16 << 30,
				flowsBaseLimit:     kernelFlowsMapBaseLimit,
				natBaseLimit:       kernelNATMapBaseLimit,
				egressNATAutoFloor: kernelEgressNATAutoMapFloor,
			},
			want: kernelAdaptiveMapProfileLarge,
		},
		{
			name: "custom",
			profile: kernelAdaptiveMapProfile{
				flowsBaseLimit:     196608,
				natBaseLimit:       131072,
				egressNATAutoFloor: 98304,
			},
			want: kernelAdaptiveMapProfileCustom,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelAdaptiveMapProfileName(tc.profile); got != tc.want {
				t.Fatalf("kernelAdaptiveMapProfileName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveKernelMapLimitsUseAdaptiveStartupProfile(t *testing.T) {
	withKernelAdaptiveMapProfileForTest(kernelAdaptiveMapProfile{
		flowsBaseLimit:     65536,
		natBaseLimit:       65536,
		egressNATAutoFloor: 65536,
	}, func() {
		if got := effectiveKernelFlowsMapLimit(0, 1); got != 65536 {
			t.Fatalf("effectiveKernelFlowsMapLimit(0, 1) = %d, want 65536", got)
		}
		if got := effectiveKernelNATMapLimit(0, 1); got != 65536 {
			t.Fatalf("effectiveKernelNATMapLimit(0, 1) = %d, want 65536", got)
		}
		if flows, nat := kernelEgressNATAutoMapFloors(0, 0, true); flows != 65536 || nat != 65536 {
			t.Fatalf("kernelEgressNATAutoMapFloors() = (%d, %d), want (65536, 65536)", flows, nat)
		}
		if got := effectiveKernelFlowsMapLimit(131072, 1); got != 131072 {
			t.Fatalf("effectiveKernelFlowsMapLimit(explicit) = %d, want 131072", got)
		}
		if got := effectiveKernelNATMapLimit(131072, 1); got != 131072 {
			t.Fatalf("effectiveKernelNATMapLimit(explicit) = %d, want 131072", got)
		}
	})
}
