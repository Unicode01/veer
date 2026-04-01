package app

import "testing"

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
