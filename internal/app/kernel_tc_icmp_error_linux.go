//go:build linux

package app

import "fmt"

// ICMP errors about egress NAT flows (destination unreachable, time exceeded,
// parameter problem) quote the packet they report as it was where the error
// was raised. The IPv4 parsers of the core reject them; the core then hands
// them to icmp_error_forward_v4 (on the hooks where LAN hosts send) or
// icmp_error_reply_v4 (on the hooks where replies arrive), which undo the
// NAT on the error and the quote so it reaches the host the flow belongs to.
const (
	kernelTCICMPErrorChainMapName     = "tc_icmp_error_chain_v4"
	kernelICMPErrorForwardProgramName = "icmp_error_forward_v4"
	kernelICMPErrorReplyProgramName   = "icmp_error_reply_v4"
	tcICMPErrorChainIndexForward      = 0
	tcICMPErrorChainIndexReply        = 1
)

// configureKernelTCICMPErrorChain installs the translators. An object built
// before them has no chain, and its errors keep passing to the stack.
func configureKernelTCICMPErrorChain(pieces kernelCollectionPieces) error {
	if pieces.icmpErrorChainV4 == nil || pieces.icmpErrorForwardProg == nil || pieces.icmpErrorReplyProg == nil {
		return nil
	}
	if err := pieces.icmpErrorChainV4.Put(uint32(tcICMPErrorChainIndexForward), uint32(pieces.icmpErrorForwardProg.FD())); err != nil {
		return fmt.Errorf("install tc ICMP error forward translator: %w", err)
	}
	if err := pieces.icmpErrorChainV4.Put(uint32(tcICMPErrorChainIndexReply), uint32(pieces.icmpErrorReplyProg.FD())); err != nil {
		return fmt.Errorf("install tc ICMP error reply translator: %w", err)
	}
	return nil
}
