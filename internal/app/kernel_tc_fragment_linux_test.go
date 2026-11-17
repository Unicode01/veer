//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
)

// fragmentTestFrames builds an IPv4 UDP datagram split in two: the first
// fragment carries the UDP header, the later one only data.
func fragmentTestFrames(dstMAC net.HardwareAddr, src, dst net.IP, srcPort, dstPort, id uint16) (first, later []byte) {
	first = flowCacheTestFrame(dstMAC, src, dst, srcPort, dstPort)
	ip := first[14:34]
	binary.BigEndian.PutUint16(ip[4:6], id)
	binary.BigEndian.PutUint16(ip[6:8], 0x2000) // MF
	// The UDP length covers the whole datagram.
	binary.BigEndian.PutUint16(first[38:40], uint16(len(first)-34+64))
	binary.BigEndian.PutUint16(ip[10:12], ipv4HeaderChecksumForTest(ip))

	payload := []byte("the rest of the datagram, no ports here......................!!")
	later = make([]byte, 14+20+len(payload))
	copy(later[0:14], first[0:14])
	lip := later[14:34]
	lip[0] = 0x45
	binary.BigEndian.PutUint16(lip[2:4], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(lip[4:6], id)
	binary.BigEndian.PutUint16(lip[6:8], uint16((len(first)-34)/8))
	lip[8] = 64
	lip[9] = syscall.IPPROTO_UDP
	copy(lip[12:16], src.To4())
	copy(lip[16:20], dst.To4())
	binary.BigEndian.PutUint16(lip[10:12], ipv4HeaderChecksumForTest(lip))
	copy(later[34:], payload)
	return first, later
}

// Only the first fragment of a datagram carries the ports the NAT translates
// by. The reply dispatcher translates it and records where it went; the later
// fragments, which the core cannot parse, get the same addresses from
// fragment_reply_v4. Fragments of other datagrams, of a datagram whose first
// fragment was dropped, and of an expired record are left alone or dropped.
func TestTCLaterFragmentsFollowTheirFirstFragment(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelReplyDispatchProgramName, kernelFragmentReplyProgramName)
	dispatch := coll.Programs[kernelReplyDispatchProgramName]
	fragment := coll.Programs[kernelFragmentReplyProgramName]
	flows := coll.Maps[kernelFlowsMapName]
	fragments := coll.Maps[kernelTCFragmentsMapName]
	if flows == nil || fragments == nil {
		t.Fatalf("missing maps: %s=%v %s=%v", kernelFlowsMapName, flows, kernelTCFragmentsMapName, fragments)
	}
	now, ok := kernelMonotonicNowNS()
	if !ok {
		t.Skip("CLOCK_MONOTONIC is unavailable")
	}
	// BPF_PROG_TEST_RUN runs on the loopback device unless told otherwise.
	const arrival = 1
	const id = 0x4242
	routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
	client := net.IPv4(192, 168, 10, 2)
	remote := net.IPv4(198, 51, 100, 7)
	natAddr := net.IPv4(203, 0, 113, 1)

	if err := flows.Put(tcFlowKeyV4{
		IfIndex: arrival,
		SrcAddr: ipv4ToHostOrderForTest(remote),
		DstAddr: ipv4ToHostOrderForTest(natAddr),
		SrcPort: 443,
		DstPort: 40000,
		Proto:   syscall.IPPROTO_UDP,
	}, tcFlowValueV4{
		RuleID:       7,
		FrontAddr:    ipv4ToHostOrderForTest(remote),
		ClientAddr:   ipv4ToHostOrderForTest(client),
		NATAddr:      ipv4ToHostOrderForTest(natAddr),
		InIfIndex:    arrival,
		FrontPort:    443,
		ClientPort:   51000,
		NATPort:      40000,
		Flags:        kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagReplySeen,
		LastSeenNS:   now - 2_000_000_000,
		RuleRevision: 1,
		SessionID:    0x5eed,
	}); err != nil {
		t.Fatalf("write reply entry: %v", err)
	}

	first, later := fragmentTestFrames(routerMAC, remote, natAddr, 443, 40000, id)
	run := func(prog *ebpf.Program, frame []byte) (uint32, []byte) {
		t.Helper()
		out := make([]byte, len(frame)+64)
		ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return ret, out[:len(frame)]
	}

	_, out := run(dispatch, first)
	if got := net.IP(out[30:34]); !got.Equal(client) {
		t.Fatalf("first fragment destination = %v, want the client %v", got, client)
	}
	key := tcFragmentKeyV4{
		IfIndex: arrival,
		SrcAddr: binary.NativeEndian.Uint32(remote.To4()),
		DstAddr: binary.NativeEndian.Uint32(natAddr.To4()),
		ID:      binary.NativeEndian.Uint16([]byte{id >> 8, id & 0xff}),
		Proto:   syscall.IPPROTO_UDP,
	}
	var recorded tcFragmentValueV4
	if err := fragments.Lookup(key, &recorded); err != nil {
		t.Fatalf("the first fragment left no record: %v", err)
	}
	if recorded.DstAddr != ipv4ToHostOrderForTest(client) || recorded.SrcAddr != ipv4ToHostOrderForTest(remote) ||
		recorded.OutIfIndex != arrival || recorded.Action != 0 {
		t.Fatalf("record = %+v, want the client %v from %v via %d", recorded, client, remote, arrival)
	}

	t.Run("later fragment", func(t *testing.T) {
		ret, out := run(fragment, later)
		if ret != tcActRedirect {
			t.Fatalf("%s returned %d, want TC_ACT_REDIRECT", kernelFragmentReplyProgramName, int32(ret))
		}
		if got := net.IP(out[30:34]); !got.Equal(client) {
			t.Fatalf("destination = %v, want the client %v", got, client)
		}
		if got := net.IP(out[26:30]); !got.Equal(remote) {
			t.Fatalf("source = %v, want %v unchanged", got, remote)
		}
		if got, want := binary.BigEndian.Uint16(out[24:26]), ipv4HeaderChecksumForTest(out[14:34]); got != want {
			t.Fatalf("IP checksum = %#04x, want %#04x", got, want)
		}
		if !bytes.Equal(out[34:], later[34:]) {
			t.Fatal("the fragment's data changed")
		}
	})

	t.Run("fragment of another datagram", func(t *testing.T) {
		_, other := fragmentTestFrames(routerMAC, remote, natAddr, 443, 40000, id+1)
		ret, out := run(fragment, other)
		if ret != tcActUnspec || !bytes.Equal(out, other) {
			t.Fatalf("returned %d, changed=%t; want TC_ACT_UNSPEC and the frame untouched", int32(ret), !bytes.Equal(out, other))
		}
	})

	t.Run("first fragment dropped", func(t *testing.T) {
		dropped := recorded
		dropped.Action = 1
		if err := fragments.Put(key, dropped); err != nil {
			t.Fatalf("write record: %v", err)
		}
		if ret, _ := run(fragment, later); ret != tcActShot {
			t.Fatalf("returned %d, want TC_ACT_SHOT", int32(ret))
		}
	})

	t.Run("expired record", func(t *testing.T) {
		// Long expired: the program's clock is not compared with this one.
		expired := recorded
		expired.ExpiresNS = 1
		if err := fragments.Put(key, expired); err != nil {
			t.Fatalf("write record: %v", err)
		}
		ret, out := run(fragment, later)
		if ret != tcActUnspec || !bytes.Equal(out, later) {
			current, _ := kernelMonotonicNowNS()
			t.Fatalf("returned %d, changed=%t; want TC_ACT_UNSPEC and the frame untouched (record set to expire at %d by the program, now %d)",
				int32(ret), !bytes.Equal(out, later), recorded.ExpiresNS, current)
		}
	})
}

// tcFlowFlagTrafficStatsForTest is FORWARD_FLOW_FLAG_TRAFFIC_STATS, which the
// datapath sets on the flows of a rule that counts traffic.
const tcFlowFlagTrafficStatsForTest = 0x40

// With traffic stats on, a reply counts its UDP payload into its rule, from
// the length in its UDP header. The later fragments of a datagram are not
// counted, so its first fragment counts the whole datagram rather than the
// part it carries. With stats off nothing counts.
func TestTCTrafficStatsCountAUDPFirstFragmentsWholeDatagram(t *testing.T) {
	for _, trafficStats := range []bool{true, false} {
		t.Run(fmt.Sprintf("traffic stats %t", trafficStats), func(t *testing.T) {
			coll := loadTCProgramsWithStatsForTest(t, trafficStats, kernelReplyDispatchProgramName)
			dispatch := coll.Programs[kernelReplyDispatchProgramName]
			flows := coll.Maps[kernelFlowsMapName]
			stats := coll.Maps[kernelStatsMapName]
			if flows == nil || stats == nil {
				t.Fatalf("missing maps: %s=%v %s=%v", kernelFlowsMapName, flows, kernelStatsMapName, stats)
			}
			now, ok := kernelMonotonicNowNS()
			if !ok {
				t.Skip("CLOCK_MONOTONIC is unavailable")
			}
			// BPF_PROG_TEST_RUN runs on the loopback device unless told otherwise.
			const arrival = 1
			const ruleID = 9
			routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
			client := net.IPv4(192, 168, 10, 2)
			remote := net.IPv4(198, 51, 100, 7)
			natAddr := net.IPv4(203, 0, 113, 1)
			if err := flows.Put(tcFlowKeyV4{
				IfIndex: arrival,
				SrcAddr: ipv4ToHostOrderForTest(remote),
				DstAddr: ipv4ToHostOrderForTest(natAddr),
				SrcPort: 443,
				DstPort: 40000,
				Proto:   syscall.IPPROTO_UDP,
			}, tcFlowValueV4{
				RuleID:       ruleID,
				FrontAddr:    ipv4ToHostOrderForTest(remote),
				ClientAddr:   ipv4ToHostOrderForTest(client),
				NATAddr:      ipv4ToHostOrderForTest(natAddr),
				InIfIndex:    arrival,
				FrontPort:    443,
				ClientPort:   51000,
				NATPort:      40000,
				Flags:        kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagReplySeen | tcFlowFlagTrafficStatsForTest,
				LastSeenNS:   now - 2_000_000_000,
				RuleRevision: 1,
				SessionID:    0x5eed,
			}); err != nil {
				t.Fatalf("write reply entry: %v", err)
			}

			bytesOut := func() uint64 {
				t.Helper()
				var perCPU []kernelStatsValueV4
				if err := stats.Lookup(uint32(ruleID), &perCPU); err != nil {
					if errors.Is(err, ebpf.ErrKeyNotExist) {
						return 0
					}
					t.Fatalf("read rule stats: %v", err)
				}
				var sum uint64
				for _, v := range perCPU {
					sum += v.BytesOut
				}
				return sum
			}
			run := func(frame []byte) {
				t.Helper()
				out := make([]byte, len(frame)+64)
				if _, err := dispatch.Run(&ebpf.RunOptions{Data: frame, DataOut: out}); err != nil {
					t.Fatalf("run: %v", err)
				}
				if got := net.IP(out[30:34]); !got.Equal(client) {
					t.Fatalf("destination = %v, want the client %v", got, client)
				}
			}

			whole := flowCacheTestFrame(routerMAC, remote, natAddr, 443, 40000)
			run(whole)
			want := uint64(0)
			if trafficStats {
				want = uint64(binary.BigEndian.Uint16(whole[38:40])) - 8
			}
			if got := bytesOut(); got != want {
				t.Fatalf("after a whole datagram the rule counted %d bytes out, want %d", got, want)
			}

			first, _ := fragmentTestFrames(routerMAC, remote, natAddr, 443, 40000, 0x4343)
			run(first)
			if trafficStats {
				want += uint64(binary.BigEndian.Uint16(first[38:40])) - 8
			}
			if got := bytesOut(); got != want {
				t.Fatalf("after a first fragment the rule counted %d bytes out, want %d (the whole datagram)", got, want)
			}
		})
	}
}
