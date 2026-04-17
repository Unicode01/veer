package app

import (
	"fmt"
	"syscall"
	"testing"
	"time"
)

func TestKernelAdaptiveMaintenanceStateShouldRunFull(t *testing.T) {
	var state kernelAdaptiveMaintenanceState
	for i := 0; i < kernelMaintenanceFullScanEvery-1; i++ {
		if state.shouldRunFull(false) {
			t.Fatalf("pass %d unexpectedly requested full maintenance", i+1)
		}
	}
	if !state.shouldRunFull(false) {
		t.Fatal("expected periodic full maintenance on cadence boundary")
	}

	state.requestFull()
	if !state.shouldRunFull(false) {
		t.Fatal("requestFull() did not force the next full maintenance pass")
	}
	if state.shouldRunFull(false) {
		t.Fatal("forced full maintenance should reset cadence")
	}
	if !state.shouldRunFull(true) {
		t.Fatal("pressure-active maintenance should always run a full pass")
	}
}

func TestKernelAdaptiveMaintenanceStateAdaptsCadence(t *testing.T) {
	var state kernelAdaptiveMaintenanceState

	state.observeFull(false, true, false)
	if got := state.fullScanCadence(); got != kernelMaintenanceFullScanEvery {
		t.Fatalf("cadence after first clean full = %d, want %d", got, kernelMaintenanceFullScanEvery)
	}

	state.observeFull(false, true, false)
	if got := state.fullScanCadence(); got != kernelMaintenanceFullScanEvery+1 {
		t.Fatalf("cadence after second clean full = %d, want %d", got, kernelMaintenanceFullScanEvery+1)
	}

	state.observeFull(false, true, true)
	if got := state.fullScanCadence(); got != kernelMaintenanceFullScanMinEvery {
		t.Fatalf("cadence after drift = %d, want %d", got, kernelMaintenanceFullScanMinEvery)
	}

	state.observeFull(true, true, false)
	if got := state.fullScanCadence(); got != kernelMaintenanceFullScanMinEvery {
		t.Fatalf("pressure-active clean full should keep cadence at %d, got %d", kernelMaintenanceFullScanMinEvery, got)
	}
}

func TestSummarizeUnhealthyKernelAttachments(t *testing.T) {
	summary := summarizeUnhealthyKernelAttachments([]kernelAttachmentHealthSnapshot{
		{Engine: kernelEngineTC, ActiveEntries: 4, Healthy: false},
		{Engine: kernelEngineXDP, ActiveEntries: 0, Healthy: false},
		{Engine: kernelEngineXDP, ActiveEntries: 2, Healthy: true},
	})
	if summary != "tc(active_entries=4)" {
		t.Fatalf("summary = %q, want tc(active_entries=4)", summary)
	}
}

func TestSummarizeKernelAttachmentHealResults(t *testing.T) {
	summary := summarizeKernelAttachmentHealResults([]kernelAttachmentHealResult{
		{Engine: kernelEngineTC, Reattached: 1},
		{Engine: kernelEngineXDP, Detached: 2},
		{Engine: "  ", Reattached: 0, Detached: 0},
	})
	if summary != "tc(reattach=1 detach=0), xdp(reattach=0 detach=2)" {
		t.Fatalf("summary = %q, want sorted repair summary", summary)
	}
}

func TestKernelAttachmentHealOutcomeSummary(t *testing.T) {
	tests := []struct {
		name           string
		rawSummary     string
		remainingIssue string
		want           string
	}{
		{
			name:       "keeps explicit repair summary",
			rawSummary: "tc(reattach=1 detach=0)",
			want:       "tc(reattach=1 detach=0)",
		},
		{
			name: "describes cleared issue without changes",
			want: "issue cleared without targeted attachment changes",
		},
		{
			name:           "describes no-op repair",
			remainingIssue: "tc(active_entries=4)",
			want:           "no targeted attachment changes applied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelAttachmentHealOutcomeSummary(tc.rawSummary, tc.remainingIssue); got != tc.want {
				t.Fatalf("kernelAttachmentHealOutcomeSummary() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKernelAttachmentHealErrorRequiresRedistribute(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "missing device errno skips redistribute",
			err:  fmt.Errorf("repair attachment: %w", syscall.Errno(19)),
			want: false,
		},
		{
			name: "missing device text skips redistribute",
			err:  fmt.Errorf("repair attachment on ifindex 17: no such device"),
			want: false,
		},
		{
			name: "other errors still redistribute",
			err:  fmt.Errorf("repair attachment: %w", syscall.Errno(1)),
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := kernelAttachmentHealErrorRequiresRedistribute(tc.err); got != tc.want {
				t.Fatalf("kernelAttachmentHealErrorRequiresRedistribute(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNextKernelAttachmentHealState(t *testing.T) {
	now := time.Unix(100, 0)
	nextIssue, recovered, heal, healAt := nextKernelAttachmentHealState("", time.Time{}, now, "tc(active_entries=4)")
	if nextIssue != "tc(active_entries=4)" || recovered != "" || !heal || !healAt.Equal(now) {
		t.Fatalf("first issue = (%q, %q, %v, %v), want current issue + heal", nextIssue, recovered, heal, healAt)
	}

	nextIssue, recovered, heal, healAt = nextKernelAttachmentHealState(nextIssue, healAt, now.Add(kernelAttachmentHealBackoff/2), nextIssue)
	if recovered != "" || heal {
		t.Fatalf("backoff window unexpectedly requested heal: recovered=%q heal=%v", recovered, heal)
	}

	nextIssue, recovered, heal, healAt = nextKernelAttachmentHealState(nextIssue, healAt, now.Add(kernelAttachmentHealBackoff), nextIssue)
	if nextIssue != "tc(active_entries=4)" || recovered != "" || !heal || !healAt.Equal(now.Add(kernelAttachmentHealBackoff)) {
		t.Fatalf("backoff expiry state = (%q, %q, %v, %v), want current issue + heal at expiry", nextIssue, recovered, heal, healAt)
	}

	nextIssue, recovered, heal, healAt = nextKernelAttachmentHealState(nextIssue, healAt, now.Add(kernelAttachmentHealBackoff), "")
	if nextIssue != "" || recovered == "" || heal || !healAt.Equal(now.Add(kernelAttachmentHealBackoff)) {
		t.Fatalf("recovery state = (%q, %q, %v, %v), want cleared issue with recovery notice and unchanged heal timestamp", nextIssue, recovered, heal, healAt)
	}
}
