//go:build linux

package app

import (
	"testing"

	"github.com/vishvananda/netlink"
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
		FIBNonSuccess:      4,
		RedirectNeighUsed:  2,
		RedirectDrop:       3,
		NATReserveFail:     5,
		NATSelfHealInsert:  6,
		FlowUpdateFail:     7,
		NATUpdateFail:      8,
		RewriteFail:        9,
		NATProbeRound2Used: 10,
		NATProbeRound3Used: 11,
		ReplyFlowRecreated: 12,
		TCPCloseDelete:     13,
		LastError:          "diag lookup failed",
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
	if view.DiagSnapshotError != "diag lookup failed" {
		t.Fatalf("diag snapshot error = %q, want propagated error", view.DiagSnapshotError)
	}
}
