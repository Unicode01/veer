package app

import "testing"

func TestHasPressureTriggeredKernelFallbacksLocked(t *testing.T) {
	pm := &ProcessManager{
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `kernel dataplane pressure: flows 242000/262144 (92.3%) exceeded 92% high watermark, routing new sessions back to userspace until usage drops below 85%`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{},
	}
	if !pm.hasPressureTriggeredKernelFallbacksLocked() {
		t.Fatal("hasPressureTriggeredKernelFallbacksLocked() = false, want true")
	}

	pm.rulePlans[1] = ruleDataplanePlan{
		KernelEligible:  true,
		EffectiveEngine: ruleEngineUserspace,
		FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
	}
	if pm.hasPressureTriggeredKernelFallbacksLocked() {
		t.Fatal("hasPressureTriggeredKernelFallbacksLocked() = true, want false for non-pressure fallback")
	}
}
