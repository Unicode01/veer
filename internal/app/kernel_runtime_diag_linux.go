//go:build linux

package app

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type kernelDiagValueV4 struct {
	FIBNonSuccess                       uint64
	RedirectNeighUsed                   uint64
	RedirectDrop                        uint64
	NATReserveFail                      uint64
	NATSelfHealInsert                   uint64
	FlowUpdateFail                      uint64
	NATUpdateFail                       uint64
	RewriteFail                         uint64
	NATProbeRound2Used                  uint64
	NATProbeRound3Used                  uint64
	ReplyFlowRecreated                  uint64
	TCPCloseDelete                      uint64
	XDPV4TransparentEnter               uint64
	XDPV4FullNATForwardEnter            uint64
	XDPV4FullNATReplyEnter              uint64
	XDPRedirectInvoked                  uint64
	XDPV4TransparentReplyFlowHit        uint64
	XDPV4TransparentForwardRuleHit      uint64
	XDPV4TransparentNoMatchPass         uint64
	XDPV4TransparentReplyClosingHandled uint64
}

type kernelRuntimeDiagSnapshot struct {
	FIBNonSuccess                       uint64
	RedirectNeighUsed                   uint64
	RedirectDrop                        uint64
	NATReserveFail                      uint64
	NATSelfHealInsert                   uint64
	FlowUpdateFail                      uint64
	NATUpdateFail                       uint64
	RewriteFail                         uint64
	NATProbeRound2Used                  uint64
	NATProbeRound3Used                  uint64
	ReplyFlowRecreated                  uint64
	TCPCloseDelete                      uint64
	XDPV4TransparentEnter               uint64
	XDPV4FullNATForwardEnter            uint64
	XDPV4FullNATReplyEnter              uint64
	XDPRedirectInvoked                  uint64
	XDPV4TransparentReplyFlowHit        uint64
	XDPV4TransparentForwardRuleHit      uint64
	XDPV4TransparentNoMatchPass         uint64
	XDPV4TransparentReplyClosingHandled uint64
	LastError                           string
}

func snapshotKernelDiagFromCollection(coll *ebpf.Collection) (kernelDiagValueV4, error) {
	if coll == nil || coll.Maps == nil {
		return kernelDiagValueV4{}, nil
	}
	diagMap := coll.Maps[kernelDiagMapName]
	if diagMap == nil {
		return kernelDiagValueV4{}, nil
	}

	key := uint32(0)
	if kernelMapHasPerCPUValue(diagMap.Type()) {
		possibleCPUs, err := kernelPossibleCPUCount()
		if err != nil {
			return kernelDiagValueV4{}, fmt.Errorf("resolve possible cpu count for kernel diag: %w", err)
		}
		values := make([]kernelDiagValueV4, possibleCPUs)
		if err := diagMap.Lookup(&key, values); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return kernelDiagValueV4{}, nil
			}
			return kernelDiagValueV4{}, fmt.Errorf("lookup kernel diag map: %w", err)
		}
		return aggregateKernelPerCPUDiag(values), nil
	}

	var value kernelDiagValueV4
	if err := diagMap.Lookup(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return kernelDiagValueV4{}, nil
		}
		return kernelDiagValueV4{}, fmt.Errorf("lookup kernel diag map: %w", err)
	}
	return value, nil
}

func snapshotKernelRuntimeDiag(coll *ebpf.Collection) kernelRuntimeDiagSnapshot {
	value, err := snapshotKernelDiagFromCollection(coll)
	if err != nil {
		return kernelRuntimeDiagSnapshot{LastError: err.Error()}
	}
	return kernelRuntimeDiagSnapshot{
		FIBNonSuccess:                       value.FIBNonSuccess,
		RedirectNeighUsed:                   value.RedirectNeighUsed,
		RedirectDrop:                        value.RedirectDrop,
		NATReserveFail:                      value.NATReserveFail,
		NATSelfHealInsert:                   value.NATSelfHealInsert,
		FlowUpdateFail:                      value.FlowUpdateFail,
		NATUpdateFail:                       value.NATUpdateFail,
		RewriteFail:                         value.RewriteFail,
		NATProbeRound2Used:                  value.NATProbeRound2Used,
		NATProbeRound3Used:                  value.NATProbeRound3Used,
		ReplyFlowRecreated:                  value.ReplyFlowRecreated,
		TCPCloseDelete:                      value.TCPCloseDelete,
		XDPV4TransparentEnter:               value.XDPV4TransparentEnter,
		XDPV4FullNATForwardEnter:            value.XDPV4FullNATForwardEnter,
		XDPV4FullNATReplyEnter:              value.XDPV4FullNATReplyEnter,
		XDPRedirectInvoked:                  value.XDPRedirectInvoked,
		XDPV4TransparentReplyFlowHit:        value.XDPV4TransparentReplyFlowHit,
		XDPV4TransparentForwardRuleHit:      value.XDPV4TransparentForwardRuleHit,
		XDPV4TransparentNoMatchPass:         value.XDPV4TransparentNoMatchPass,
		XDPV4TransparentReplyClosingHandled: value.XDPV4TransparentReplyClosingHandled,
	}
}

func applyKernelRuntimeDiagView(view *KernelEngineRuntimeView, snapshot kernelRuntimeDiagSnapshot) {
	if view == nil {
		return
	}
	view.DiagFIBNonSuccess = snapshot.FIBNonSuccess
	view.DiagRedirectNeighUsed = snapshot.RedirectNeighUsed
	view.DiagRedirectDrop = snapshot.RedirectDrop
	view.DiagNATReserveFail = snapshot.NATReserveFail
	view.DiagNATSelfHealInsert = snapshot.NATSelfHealInsert
	view.DiagFlowUpdateFail = snapshot.FlowUpdateFail
	view.DiagNATUpdateFail = snapshot.NATUpdateFail
	view.DiagRewriteFail = snapshot.RewriteFail
	view.DiagNATProbeRound2Used = snapshot.NATProbeRound2Used
	view.DiagNATProbeRound3Used = snapshot.NATProbeRound3Used
	view.DiagReplyFlowRecreated = snapshot.ReplyFlowRecreated
	view.DiagTCPCloseDelete = snapshot.TCPCloseDelete
	view.DiagXDPV4TransparentEnter = snapshot.XDPV4TransparentEnter
	view.DiagXDPV4FullNATForwardEnter = snapshot.XDPV4FullNATForwardEnter
	view.DiagXDPV4FullNATReplyEnter = snapshot.XDPV4FullNATReplyEnter
	view.DiagXDPRedirectInvoked = snapshot.XDPRedirectInvoked
	view.DiagXDPV4TransparentReplyFlowHit = snapshot.XDPV4TransparentReplyFlowHit
	view.DiagXDPV4TransparentForwardRuleHit = snapshot.XDPV4TransparentForwardRuleHit
	view.DiagXDPV4TransparentNoMatchPass = snapshot.XDPV4TransparentNoMatchPass
	view.DiagXDPV4TransparentReplyClosingHandled = snapshot.XDPV4TransparentReplyClosingHandled
	view.DiagSnapshotError = snapshot.LastError
}

func aggregateKernelPerCPUDiag(values []kernelDiagValueV4) kernelDiagValueV4 {
	var out kernelDiagValueV4
	for _, value := range values {
		out.FIBNonSuccess += value.FIBNonSuccess
		out.RedirectNeighUsed += value.RedirectNeighUsed
		out.RedirectDrop += value.RedirectDrop
		out.NATReserveFail += value.NATReserveFail
		out.NATSelfHealInsert += value.NATSelfHealInsert
		out.FlowUpdateFail += value.FlowUpdateFail
		out.NATUpdateFail += value.NATUpdateFail
		out.RewriteFail += value.RewriteFail
		out.NATProbeRound2Used += value.NATProbeRound2Used
		out.NATProbeRound3Used += value.NATProbeRound3Used
		out.ReplyFlowRecreated += value.ReplyFlowRecreated
		out.TCPCloseDelete += value.TCPCloseDelete
		out.XDPV4TransparentEnter += value.XDPV4TransparentEnter
		out.XDPV4FullNATForwardEnter += value.XDPV4FullNATForwardEnter
		out.XDPV4FullNATReplyEnter += value.XDPV4FullNATReplyEnter
		out.XDPRedirectInvoked += value.XDPRedirectInvoked
		out.XDPV4TransparentReplyFlowHit += value.XDPV4TransparentReplyFlowHit
		out.XDPV4TransparentForwardRuleHit += value.XDPV4TransparentForwardRuleHit
		out.XDPV4TransparentNoMatchPass += value.XDPV4TransparentNoMatchPass
		out.XDPV4TransparentReplyClosingHandled += value.XDPV4TransparentReplyClosingHandled
	}
	return out
}
