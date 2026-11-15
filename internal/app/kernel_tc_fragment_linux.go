//go:build linux

package app

import "fmt"

// Only the first fragment of an IPv4 datagram carries the ports the NAT
// translates by. The core translates it like any packet and records in
// tc_fragments_v4 where it went; the IPv4 parsers reject the later fragments,
// and the core hands them to fragment_forward_v4 (on the hooks where LAN
// hosts send) or fragment_reply_v4 (on the hooks where replies arrive),
// which give them the same addresses and send them the same way.
const (
	kernelTCFragmentChainMapName     = "tc_fragment_chain_v4"
	kernelTCFragmentsMapName         = "tc_fragments_v4"
	kernelFragmentForwardProgramName = "fragment_forward_v4"
	kernelFragmentReplyProgramName   = "fragment_reply_v4"
	tcFragmentChainIndexForward      = 0
	tcFragmentChainIndexReply        = 1
)

// tcFragmentKeyV4 mirrors struct tc_fragment_key_v4: the later fragments of
// a datagram as they arrive, addresses and IP ID in network byte order.
type tcFragmentKeyV4 struct {
	IfIndex uint32
	SrcAddr uint32
	DstAddr uint32
	ID      uint16
	Proto   uint8
	Pad     uint8
}

// tcFragmentValueV4 mirrors struct tc_fragment_value_v4: where the first
// fragment went, addresses in host byte order.
type tcFragmentValueV4 struct {
	ExpiresNS  uint64
	OutIfIndex uint32
	SrcAddr    uint32
	DstAddr    uint32
	Action     uint32
}

// configureKernelTCFragmentChain installs the later-fragment programs. An
// object built before them has no chain, and those fragments keep passing to
// the stack.
func configureKernelTCFragmentChain(pieces kernelCollectionPieces) error {
	if pieces.fragmentChainV4 == nil || pieces.fragmentForwardProg == nil || pieces.fragmentReplyProg == nil {
		return nil
	}
	if err := pieces.fragmentChainV4.Put(uint32(tcFragmentChainIndexForward), uint32(pieces.fragmentForwardProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 later-fragment forward program: %w", err)
	}
	if err := pieces.fragmentChainV4.Put(uint32(tcFragmentChainIndexReply), uint32(pieces.fragmentReplyProg.FD())); err != nil {
		return fmt.Errorf("install tc IPv4 later-fragment reply program: %w", err)
	}
	return nil
}
