package app

import "testing"

func TestIsTransientKernelFallbackReason(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   bool
	}{
		{
			name:   "neighbor missing",
			reason: `xdp: xdp dataplane outbound bridge support requires experimental feature "bridge_xdp"; tc: resolve outbound path on "vmbr1": no learned IPv4 neighbor entry was found; ensure the backend has recent traffic or ARP state`,
			want:   true,
		},
		{
			name:   "fdb missing",
			reason: `xdp: xdp dataplane outbound bridge support requires experimental feature "bridge_xdp"; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			want:   true,
		},
		{
			name:   "xdp neighbor missing",
			reason: `xdp: xdp dataplane requires a learned IPv4 neighbor entry for 192.0.2.10 on "eno1"; tc: skipped`,
			want:   true,
		},
		{
			name:   "table pressure",
			reason: `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
			want:   false,
		},
		{
			name:   "non transient tc verifier failure",
			reason: `xdp: xdp dataplane currently supports only transparent rules; tc: create kernel collection: verifier rejected program`,
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientKernelFallbackReason(tc.reason); got != tc.want {
				t.Fatalf("isTransientKernelFallbackReason(%q) = %v, want %v", tc.reason, got, tc.want)
			}
		})
	}
}

func TestHasTransientKernelFallbacksLocked(t *testing.T) {
	pm := &ProcessManager{
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{},
	}
	if !pm.hasTransientKernelFallbacksLocked() {
		t.Fatal("hasTransientKernelFallbacksLocked() = false, want true")
	}

	pm.rulePlans[1] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: skip; tc: verifier rejected program`,
	}
	if pm.hasTransientKernelFallbacksLocked() {
		t.Fatal("hasTransientKernelFallbacksLocked() = true, want false")
	}

	pm.rulePlans[1] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
	}
	if pm.hasTransientKernelFallbacksLocked() {
		t.Fatal("hasTransientKernelFallbacksLocked() = true for pressure fallback, want false")
	}
}
