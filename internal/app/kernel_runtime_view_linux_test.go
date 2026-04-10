//go:build linux

package app

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func TestKernelExpectedAttachmentsHealthyRequiresMatchingProgramIdentity(t *testing.T) {
	key := kernelAttachmentKey{
		linkIndex: 7,
		parent:    netlink.HANDLE_MIN_INGRESS,
		priority:  kernelForwardFilterPrio,
		handle:    netlink.MakeHandle(0, kernelForwardFilterHandle),
	}
	expected := []kernelAttachmentExpectation{{
		key:       key,
		name:      kernelForwardProgramName,
		programID: 101,
	}}

	tests := []struct {
		name        string
		attachments int
		observed    map[kernelAttachmentKey]kernelAttachmentObservation
		want        bool
	}{
		{
			name:        "matching program id",
			attachments: 1,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true, isBPF: true, name: kernelForwardProgramName, programID: 101, directAction: true},
			},
			want: true,
		},
		{
			name:        "wrong program id",
			attachments: 1,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true, isBPF: true, name: kernelForwardProgramName, programID: 202, directAction: true},
			},
			want: false,
		},
		{
			name:        "name fallback when id unavailable",
			attachments: 1,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true, isBPF: true, name: kernelForwardProgramName, programID: 0, directAction: true},
			},
			want: true,
		},
		{
			name:        "non direct action filter",
			attachments: 1,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true, isBPF: true, name: kernelForwardProgramName, programID: 101, directAction: false},
			},
			want: false,
		},
		{
			name:        "non bpf filter",
			attachments: 1,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true},
			},
			want: false,
		},
		{
			name:        "insufficient attachment count",
			attachments: 0,
			observed: map[kernelAttachmentKey]kernelAttachmentObservation{
				key: {present: true, isBPF: true, name: kernelForwardProgramName, programID: 101, directAction: true},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := kernelExpectedAttachmentsHealthy(expected, tc.attachments, tc.observed)
			if got != tc.want {
				t.Fatalf("kernelExpectedAttachmentsHealthy() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestKernelAttachmentObservationMatchesExpectationRejectsWrongName(t *testing.T) {
	expected := kernelAttachmentExpectation{
		key:       kernelAttachmentKey{},
		name:      kernelReplyProgramName,
		programID: 0,
	}
	observed := kernelAttachmentObservation{
		present:      true,
		isBPF:        true,
		name:         kernelForwardProgramName,
		programID:    0,
		directAction: true,
	}
	if kernelAttachmentObservationMatchesExpectation(observed, expected) {
		t.Fatal("kernelAttachmentObservationMatchesExpectation() = true, want false for mismatched program name")
	}
}

func TestApplyKernelRuntimeDiagView(t *testing.T) {
	view := KernelEngineRuntimeView{}
	applyKernelRuntimeDiagView(&view, kernelRuntimeDiagSnapshot{
		FIBNonSuccess:                       4,
		RedirectNeighUsed:                   2,
		RedirectDrop:                        3,
		NATReserveFail:                      5,
		NATSelfHealInsert:                   6,
		FlowUpdateFail:                      7,
		NATUpdateFail:                       8,
		RewriteFail:                         9,
		NATProbeRound2Used:                  10,
		NATProbeRound3Used:                  11,
		ReplyFlowRecreated:                  12,
		TCPCloseDelete:                      13,
		XDPV4TransparentEnter:               14,
		XDPV4FullNATForwardEnter:            15,
		XDPV4FullNATReplyEnter:              16,
		XDPRedirectInvoked:                  17,
		XDPV4TransparentReplyFlowHit:        18,
		XDPV4TransparentForwardRuleHit:      19,
		XDPV4TransparentNoMatchPass:         20,
		XDPV4TransparentReplyClosingHandled: 21,
		LastError:                           "diag lookup failed",
	})

	if view.DiagFIBNonSuccess != 4 || view.DiagRedirectDrop != 3 || view.DiagNATReserveFail != 5 || view.DiagReplyFlowRecreated != 12 {
		t.Fatalf("diag counters not applied: %+v", view)
	}
	if view.DiagRedirectNeighUsed != 2 || view.DiagNATSelfHealInsert != 6 || view.DiagFlowUpdateFail != 7 || view.DiagNATUpdateFail != 8 {
		t.Fatalf("verbose diag counters not applied: %+v", view)
	}
	if view.DiagRewriteFail != 9 || view.DiagNATProbeRound2Used != 10 || view.DiagNATProbeRound3Used != 11 || view.DiagTCPCloseDelete != 13 {
		t.Fatalf("probe/rewrite diag counters not applied: %+v", view)
	}
	if view.DiagXDPV4TransparentEnter != 14 || view.DiagXDPV4FullNATForwardEnter != 15 || view.DiagXDPV4FullNATReplyEnter != 16 || view.DiagXDPRedirectInvoked != 17 {
		t.Fatalf("xdp hit counters not applied: %+v", view)
	}
	if view.DiagXDPV4TransparentReplyFlowHit != 18 || view.DiagXDPV4TransparentForwardRuleHit != 19 || view.DiagXDPV4TransparentNoMatchPass != 20 || view.DiagXDPV4TransparentReplyClosingHandled != 21 {
		t.Fatalf("xdp transparent detail counters not applied: %+v", view)
	}
	if view.DiagSnapshotError != "diag lookup failed" {
		t.Fatalf("diag snapshot error = %q, want propagated error", view.DiagSnapshotError)
	}
}

func TestKernelRuntimeMapCountSnapshotDetailsFresh(t *testing.T) {
	now := time.Now()
	snapshot := kernelRuntimeMapCountSnapshot{detailSampledAt: now}
	if !snapshot.detailsFresh(now.Add(kernelRuntimeMapDetailCacheTTL / 2)) {
		t.Fatal("detailsFresh() = false, want true within detail cache ttl")
	}
	if snapshot.detailsFresh(now.Add(kernelRuntimeMapDetailCacheTTL + time.Millisecond)) {
		t.Fatal("detailsFresh() = true, want false after detail cache ttl")
	}
}

func TestApplyKernelRuntimeMapBreakdown(t *testing.T) {
	view := KernelEngineRuntimeView{}
	counts := kernelRuntimeMapCountSnapshot{
		rulesEntriesV4: 3,
		rulesEntriesV6: 2,
		flowsEntriesV4: 11,
		flowsEntriesV6: 5,
		natEntriesV4:   7,
		natEntriesV6:   1,
	}

	applyKernelRuntimeMapBreakdown(&view, kernelRuntimeMapRefs{}, counts, true)

	if view.RulesMapEntriesV4 != 3 || view.RulesMapEntriesV6 != 2 {
		t.Fatalf("rules breakdown = %d/%d, want 3/2", view.RulesMapEntriesV4, view.RulesMapEntriesV6)
	}
	if view.FlowsMapEntriesV4 != 11 || view.FlowsMapEntriesV6 != 5 {
		t.Fatalf("flows breakdown = %d/%d, want 11/5", view.FlowsMapEntriesV4, view.FlowsMapEntriesV6)
	}
	if view.NATMapEntriesV4 != 7 || view.NATMapEntriesV6 != 1 {
		t.Fatalf("nat breakdown = %d/%d, want 7/1", view.NATMapEntriesV4, view.NATMapEntriesV6)
	}
}

func TestApplyKernelRuntimeMapBreakdownSkipsNATWhenDisabled(t *testing.T) {
	view := KernelEngineRuntimeView{}
	counts := kernelRuntimeMapCountSnapshot{
		natEntriesV4: 9,
		natEntriesV6: 4,
	}

	applyKernelRuntimeMapBreakdown(&view, kernelRuntimeMapRefs{}, counts, false)

	if view.NATMapEntriesV4 != 0 || view.NATMapEntriesV6 != 0 || view.NATMapCapacityV4 != 0 || view.NATMapCapacityV6 != 0 {
		t.Fatalf("nat breakdown populated with includeNAT=false: %+v", view)
	}
}

func TestKernelRuntimeMapRefsEqualTracksDualStackMaps(t *testing.T) {
	rulesV4 := &ebpf.Map{}
	rulesV6 := &ebpf.Map{}

	a := kernelRuntimeMapRefs{rulesV4: rulesV4, rulesV6: rulesV6}
	b := kernelRuntimeMapRefs{rulesV4: rulesV4, rulesV6: rulesV6}
	if !kernelRuntimeMapRefsEqual(a, b) {
		t.Fatal("kernelRuntimeMapRefsEqual() = false, want true for identical dual-stack refs")
	}

	b.rulesV6 = &ebpf.Map{}
	if kernelRuntimeMapRefsEqual(a, b) {
		t.Fatal("kernelRuntimeMapRefsEqual() = true, want false when IPv6 map ref differs")
	}
}

func TestXDPAttachmentMode(t *testing.T) {
	tests := []struct {
		name        string
		attachments []xdpAttachment
		want        string
	}{
		{
			name: "none",
			want: "",
		},
		{
			name: "driver",
			attachments: []xdpAttachment{
				{ifindex: 1, flags: nl.XDP_FLAGS_DRV_MODE},
				{ifindex: 2, flags: nl.XDP_FLAGS_DRV_MODE},
			},
			want: "driver",
		},
		{
			name: "generic",
			attachments: []xdpAttachment{
				{ifindex: 1, flags: nl.XDP_FLAGS_SKB_MODE},
			},
			want: "generic",
		},
		{
			name: "mixed",
			attachments: []xdpAttachment{
				{ifindex: 1, flags: nl.XDP_FLAGS_DRV_MODE},
				{ifindex: 2, flags: nl.XDP_FLAGS_SKB_MODE},
			},
			want: "mixed",
		},
		{
			name: "unknown flags collapse to mixed",
			attachments: []xdpAttachment{
				{ifindex: 1, flags: 0},
			},
			want: "mixed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := xdpAttachmentMode(tc.attachments); got != tc.want {
				t.Fatalf("xdpAttachmentMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTCAttachmentMode(t *testing.T) {
	tests := []struct {
		name        string
		attachments []kernelAttachment
		mode        kernelTCAttachmentProgramMode
		want        string
	}{
		{
			name: "none",
			mode: kernelTCAttachmentProgramModeLegacy,
			want: "",
		},
		{
			name:        "legacy",
			attachments: []kernelAttachment{{}},
			mode:        kernelTCAttachmentProgramModeLegacy,
			want:        "legacy",
		},
		{
			name:        "dispatch",
			attachments: []kernelAttachment{{}},
			mode:        kernelTCAttachmentProgramModeDispatchV4,
			want:        "dispatch_v4",
		},
		{
			name:        "unknown",
			attachments: []kernelAttachment{{}},
			mode:        kernelTCAttachmentProgramMode("unexpected"),
			want:        "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcAttachmentMode(tc.attachments, tc.mode); got != tc.want {
				t.Fatalf("tcAttachmentMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCountKernelRuntimeMapEntriesUsesIPv6RuleCounter(t *testing.T) {
	now := time.Now()
	refs := kernelRuntimeMapRefs{rulesV6: &ebpf.Map{}}
	counts := countKernelRuntimeMapEntries(
		now,
		refs,
		kernelRuntimeMapCountSnapshot{},
		func(current kernelRuntimeMapRefs, _ int) (int, error) {
			if current.rulesV6 == nil {
				t.Fatal("countRules() received refs without IPv6 rules map")
			}
			return 7, nil
		},
		3,
		false,
	)
	if counts.rulesEntries != 7 {
		t.Fatalf("countKernelRuntimeMapEntries() rules = %d, want 7", counts.rulesEntries)
	}
	if counts.flowsEntries != 0 || counts.natEntries != 0 {
		t.Fatalf("countKernelRuntimeMapEntries() flows/nat = %d/%d, want 0/0", counts.flowsEntries, counts.natEntries)
	}
}

func TestCountKernelRuntimeMapEntriesUsesHintForIPv6RulesWithoutCounter(t *testing.T) {
	now := time.Now()
	counts := countKernelRuntimeMapEntries(
		now,
		kernelRuntimeMapRefs{rulesV6: &ebpf.Map{}},
		kernelRuntimeMapCountSnapshot{},
		nil,
		5,
		false,
	)
	if counts.rulesEntries != 5 {
		t.Fatalf("countKernelRuntimeMapEntries() rules = %d, want 5", counts.rulesEntries)
	}
}
