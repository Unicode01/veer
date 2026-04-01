package app

import (
	"testing"
	"time"
)

func TestSummarizeTransientKernelFallbacksLocked(t *testing.T) {
	pm := &ProcessManager{
		rulePlans: map[int64]ruleDataplanePlan{
			1: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no forwarding database entry matched the backend MAC`,
			},
			2: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr1": no learned IPv4 neighbor entry was found; ensure the backend has recent traffic or ARP state`,
			},
		},
		rangePlans: map[int64]rangeDataplanePlan{
			3: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  `xdp: skip; tc: resolve outbound path on "vmbr2": no forwarding database entry matched the backend MAC`,
			},
		},
	}

	got := pm.summarizeTransientKernelFallbacksLocked()
	want := "rules=2 ranges=1 reasons=fdb_missing=2,neighbor_missing=1"
	if got != want {
		t.Fatalf("summarizeTransientKernelFallbacksLocked() = %q, want %q", got, want)
	}
}

func TestTakeKernelRetryLogLineLocked(t *testing.T) {
	pm := &ProcessManager{}
	now := time.Unix(100, 0)
	summary := "rules=2 ranges=0 reasons=fdb_missing=2"

	line := pm.takeKernelRetryLogLineLocked(summary, now)
	if line == "" {
		t.Fatal("takeKernelRetryLogLineLocked() returned empty line on first summary")
	}

	if line := pm.takeKernelRetryLogLineLocked(summary, now.Add(time.Minute)); line != "" {
		t.Fatalf("takeKernelRetryLogLineLocked() = %q, want empty line for repeated summary before rate limit", line)
	}

	if line := pm.takeKernelRetryLogLineLocked(summary, now.Add(kernelFallbackRetryLogEvery+time.Second)); line == "" {
		t.Fatal("takeKernelRetryLogLineLocked() returned empty line after rate limit elapsed")
	}

	if line := pm.takeKernelRetryLogLineLocked("", now.Add(kernelFallbackRetryLogEvery+2*time.Second)); line != "" {
		t.Fatalf("takeKernelRetryLogLineLocked() = %q, want empty line when summary cleared", line)
	}

	if pm.lastKernelRetryLog != "" || !pm.kernelRetryLogAt.IsZero() {
		t.Fatal("takeKernelRetryLogLineLocked() did not reset retry log state after summary cleared")
	}
}
