//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// The flow maps hand a deleted element to the next insert at once, so a
// packet can find its flow and then read another flow's entry from the same
// memory (see copy_flow_v4 in forward_common.h). Such a lookup must count as
// finding nothing: before, a client's last ACK was sent with the next
// connection's NAT port, and the server's reset to it closed that connection.
// The test stands an entry naming another NAT port under a reply's key, the
// way the reused memory reads, and checks the reply is not translated by it.
func TestTCReplyDispatchIgnoresFlowEntryOfAnotherFlow(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelReplyDispatchProgramName)
	prog := coll.Programs[kernelReplyDispatchProgramName]
	flows := coll.Maps[kernelFlowsMapName]
	if flows == nil {
		t.Fatalf("%s has no %s map", kernelReplyDispatchProgramName, kernelFlowsMapName)
	}
	now, ok := kernelMonotonicNowNS()
	if !ok {
		t.Skip("CLOCK_MONOTONIC is unavailable")
	}
	// BPF_PROG_TEST_RUN runs on the loopback device unless told otherwise.
	const arrival = 1
	routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
	client := net.IPv4(192, 168, 10, 2)
	remote := net.IPv4(198, 51, 100, 7)
	natAddr := net.IPv4(203, 0, 113, 1)
	key := tcFlowKeyV4{
		IfIndex: arrival,
		SrcAddr: ipv4ToHostOrderForTest(remote),
		DstAddr: ipv4ToHostOrderForTest(natAddr),
		SrcPort: 443,
		DstPort: 40000,
		Proto:   syscall.IPPROTO_UDP,
	}

	cases := []struct {
		name       string
		natPort    uint16
		clientPort uint16
		translated bool
	}{
		{name: "entry of the reply's flow", natPort: 40000, clientPort: 51000, translated: true},
		{name: "entry reused by another flow", natPort: 40001, clientPort: 52000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := tcFlowValueV4{
				RuleID:     7,
				FrontAddr:  ipv4ToHostOrderForTest(remote),
				ClientAddr: ipv4ToHostOrderForTest(client),
				NATAddr:    ipv4ToHostOrderForTest(natAddr),
				InIfIndex:  arrival,
				FrontPort:  443,
				ClientPort: tc.clientPort,
				NATPort:    tc.natPort,
				Flags:      kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagReplySeen,
				// Outside the fast-path window, so the full path runs.
				LastSeenNS:   now - 2_000_000_000,
				RuleRevision: 1,
				SessionID:    0x5eed,
			}
			if err := flows.Put(key, value); err != nil {
				t.Fatalf("write reply entry: %v", err)
			}
			t.Cleanup(func() {
				var k tcFlowKeyV4
				var v tcFlowValueV4
				iter := flows.Iterate()
				var keys []tcFlowKeyV4
				for iter.Next(&k, &v) {
					keys = append(keys, k)
				}
				for _, k := range keys {
					_ = flows.Delete(k)
				}
			})

			frame := flowCacheTestFrame(routerMAC, remote, natAddr, 443, 40000)
			out := make([]byte, len(frame)+64)
			ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
			if err != nil {
				t.Fatalf("run %s: %v", kernelReplyDispatchProgramName, err)
			}
			out = out[:len(frame)]
			if !tc.translated {
				if ret != tcActUnspec {
					t.Fatalf("%s returned %d, want TC_ACT_UNSPEC", kernelReplyDispatchProgramName, int32(ret))
				}
				if !bytes.Equal(out, frame) {
					t.Fatal("a reply was translated by an entry of another flow")
				}
				return
			}
			if got := net.IP(out[30:34]); !got.Equal(client) {
				t.Fatalf("destination = %v, want the client %v (returned %d)", got, client, int32(ret))
			}
			if got := binary.BigEndian.Uint16(out[36:38]); got != tc.clientPort {
				t.Fatalf("destination port = %d, want %d", got, tc.clientPort)
			}
		})
	}
}
