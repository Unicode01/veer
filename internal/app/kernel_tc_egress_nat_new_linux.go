//go:build linux

package app

import "fmt"

// New egress NAT flows are opened by a program of their own, which the
// dispatcher tail calls when it finds no flow for a packet. Probing for a free
// NAT port is most of what the verifier walks on that path, so keeping the
// probes out of the egress NAT program leaves it far from the 1M-instruction
// limit. Plugins own the free slots of tc_prog_chain_v4, so the program has a
// chain of its own, like the ICMP error translators.
const (
	kernelTCEgressNATNewChainMapName     = "tc_egress_nat_new_chain_v4"
	kernelForwardEgressNATNewProgramName = "forward_ingress_v4_egress_nat_new"
	tcEgressNATNewChainIndex             = 0
)

// configureKernelTCEgressNATNewChain installs the program that opens egress
// NAT flows. Without it, an egress NAT rule passes no new flow.
func configureKernelTCEgressNATNewChain(pieces kernelCollectionPieces) error {
	if pieces.egressNATNewChainV4 == nil || pieces.forwardEgressNATNewProg == nil {
		return fmt.Errorf("tc object is missing the egress NAT new-flow program (%s)", kernelForwardEgressNATNewProgramName)
	}
	if err := pieces.egressNATNewChainV4.Put(uint32(tcEgressNATNewChainIndex), uint32(pieces.forwardEgressNATNewProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 egress NAT new-flow tail-call target: %w", err)
	}
	return nil
}
