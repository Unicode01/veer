//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"math"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	tcActShot     = 2
	tcActRedirect = 7
	tcActUnspec   = math.MaxUint32 // TC_ACT_UNSPEC (-1)
)

// loadTCProgramsForTest loads the named programs of the embedded TC object
// with only the maps they use, hash maps cut down to test size.
func loadTCProgramsForTest(t *testing.T, names ...string) *ebpf.Collection {
	t.Helper()
	return loadTCProgramsWithStatsForTest(t, false, names...)
}

// loadTCProgramsWithStatsForTest is loadTCProgramsForTest with traffic stats
// set at load time, as veer sets them.
func loadTCProgramsWithStatsForTest(t *testing.T, trafficStats bool, names ...string) *ebpf.Collection {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	spec, err := loadEmbeddedKernelCollectionSpec(trafficStats)
	if err != nil {
		t.Skipf("embedded tc object is unavailable: %v", err)
	}
	programs := make(map[string]*ebpf.ProgramSpec, len(names))
	maps := make(map[string]*ebpf.MapSpec)
	for _, name := range names {
		progSpec := spec.Programs[name]
		if progSpec == nil {
			t.Fatalf("embedded tc object has no %s program", name)
		}
		programs[name] = progSpec
		for _, ins := range progSpec.Instructions {
			if m := spec.Maps[ins.Reference()]; m != nil {
				maps[ins.Reference()] = m
			}
		}
	}
	for _, m := range maps {
		if (m.Type == ebpf.Hash || m.Type == ebpf.LRUHash) && m.MaxEntries > 4096 {
			m.MaxEntries = 4096
		}
	}
	for name, v := range spec.Variables {
		if maps[v.SectionName] == nil {
			delete(spec.Variables, name)
		}
	}
	spec.Programs = programs
	spec.Maps = maps
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load %v: %v", names, err)
	}
	t.Cleanup(coll.Close)
	return coll
}

// flowCacheTestFrame builds an untagged IPv4 UDP frame.
func flowCacheTestFrame(dstMAC net.HardwareAddr, src, dst net.IP, srcPort, dstPort uint16) []byte {
	payload := []byte("veer flow cache test payload....")
	frame := make([]byte, 14+20+8+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8] = 64
	ip[9] = syscall.IPPROTO_UDP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipv4HeaderChecksumForTest(ip))
	udp := frame[34:42]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(frame[42:], payload)
	return frame
}

func ipv4HeaderChecksumForTest(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		if i == 10 {
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func ipv4ToHostOrderForTest(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

// flowFastStampForTest mirrors flow_fast_stamp_v4.
func flowFastStampForTest(lastSeenNS uint64, generation uint32) uint32 {
	return (uint32(lastSeenNS) ^ generation*0x9e3779b9) | 1
}

func monotonicNowNSForTest(t *testing.T) uint64 {
	t.Helper()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatalf("read the monotonic clock: %v", err)
	}
	return uint64(ts.Nano())
}

func flowCacheHitsForTest(t *testing.T, diagMap *ebpf.Map) uint64 {
	t.Helper()
	var values []kernelDiagValueV4
	if err := diagMap.Lookup(uint32(0), &values); err != nil {
		t.Fatalf("read diag counters: %v", err)
	}
	return aggregateKernelPerCPUDiag(values).FlowCacheHit
}

// The dispatchers send a packet straight from its flow entry's fast-path
// record only when the packet arrives like the recorded one did: same port
// and destination MAC, a current record (window and generation), a length
// the next hop takes and, for a full-cone front entry, the recorded
// destination. A reply entering a bridge port finds its entry under the
// port's parent. Everything else goes on to the full dispatcher. Egress NAT
// flows, port forwards with full NAT (whose forward record names the
// backend) and the replies of transparent port forwards are served.
func TestTCFlowCacheServesOnlyMatchingPackets(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelForwardDispatchProgramName, kernelReplyDispatchProgramName)
	forwardProg := coll.Programs[kernelForwardDispatchProgramName]
	replyProg := coll.Programs[kernelReplyDispatchProgramName]
	flowsMap := coll.Maps[kernelFlowsMapNameV4]
	stateMap := coll.Maps[kernelTCFlowCacheStateMapName]
	parentMap := coll.Maps[kernelIfParentMapName]
	diagMap := coll.Maps[kernelDiagMapName]
	hintsMap := coll.Maps[kernelTCIfindexHintsMapName]
	if flowsMap == nil || stateMap == nil || parentMap == nil || diagMap == nil || hintsMap == nil {
		t.Fatalf("dispatcher maps: flows=%v state=%v parent=%v diag=%v hints=%v", flowsMap, stateMap, parentMap, diagMap, hintsMap)
	}
	// BPF_PROG_TEST_RUN runs on the loopback device unless told otherwise.
	const arrival = 1
	const parent = 9
	const generation = 3
	if err := stateMap.Put(uint32(0), tcFlowCacheStateV4{Generation: generation, Enabled: 1}); err != nil {
		t.Fatalf("write cache state: %v", err)
	}
	routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
	otherMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xbb}
	nextHopMAC := [6]byte{0x02, 0, 0, 0, 0, 0xcc}
	outMAC := [6]byte{0x02, 0, 0, 0, 0, 0xdd}
	client := net.IPv4(192, 0, 2, 10)
	remote := net.IPv4(198, 51, 100, 7)
	natAddr := net.IPv4(203, 0, 113, 1)
	backend := net.IPv4(10, 0, 0, 5)
	const clientPort, remotePort, natPort, backendPort = 51000, 443, 40000, 8443
	// For port forwards, remote is the front address the client connects to.
	const (
		egressNAT = iota
		portForward
		transparent
	)

	type testCase struct {
		name     string
		kind     int
		reply    bool
		fullCone bool
		dstMAC   net.HardwareAddr
		keyIf    uint32
		parentOf map[uint32]uint32
		hints    uint32
		mutate   func(*tcFlowValueV4, uint64)
		hit      bool
	}
	// Entries are stamped a little in the past: the BPF clock can read
	// behind user space's monotonic clock, and the window check, rightly,
	// does not trust a last_seen_ns from its future.
	const recently = 200_000_000
	restamp := func(generation uint32, ago uint64) func(*tcFlowValueV4, uint64) {
		return func(v *tcFlowValueV4, now uint64) {
			v.LastSeenNS = now - ago
			v.Fast.Stamp = flowFastStampForTest(v.LastSeenNS, generation)
		}
	}
	cases := []testCase{
		{name: "reply", reply: true, keyIf: arrival, hit: true},
		{name: "reply under the port's parent", reply: true, keyIf: parent, parentOf: map[uint32]uint32{arrival: parent}, hit: true},
		{name: "reply from another port", reply: true, keyIf: parent, parentOf: map[uint32]uint32{arrival: parent}, mutate: func(v *tcFlowValueV4, _ uint64) { v.Fast.InIfIndex = 4 }},
		{name: "reply for another MAC", reply: true, keyIf: arrival, dstMAC: otherMAC},
		{name: "reply after the window", reply: true, keyIf: arrival, mutate: restamp(generation, 2_000_000_000)},
		{name: "reply under a stale generation", reply: true, keyIf: arrival, mutate: restamp(generation-1, recently)},
		{name: "reply while the record is written", reply: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.Fast.Stamp = 0 }},
		{name: "reply of a closing flow", reply: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.Flags |= kernelFlowFlagReplyClosing }},
		{name: "reply too long for the next hop", reply: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.Fast.MaxLen = 59 }},
		{name: "forward", keyIf: arrival, hit: true},
		{name: "forward for another MAC", keyIf: arrival, dstMAC: otherMAC},
		{name: "forward of another session", keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.ClientPort = clientPort + 1 }},
		{name: "full-cone forward", fullCone: true, keyIf: arrival, hit: true},
		{name: "full-cone forward to another destination", fullCone: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.Fast.DstAddr++ }},
		{name: "full-cone forward on an interface without full-cone rules", fullCone: true, keyIf: arrival,
			hints: kernelTCIfindexHintKnown | kernelTCIfindexHintRuleAny},
		{name: "port forward", kind: portForward, keyIf: arrival, hit: true},
		{name: "port forward for another MAC", kind: portForward, keyIf: arrival, dstMAC: otherMAC},
		{name: "port forward reply", kind: portForward, reply: true, keyIf: arrival, hit: true},
		{name: "port forward reply under a stale generation", kind: portForward, reply: true, keyIf: arrival, mutate: restamp(generation-1, recently)},
		{name: "transparent reply", kind: transparent, reply: true, keyIf: arrival, hit: true},
		{name: "transparent reply under the port's parent", kind: transparent, reply: true, keyIf: parent, parentOf: map[uint32]uint32{arrival: parent}, hit: true},
		{name: "transparent reply of a closing flow", kind: transparent, reply: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.Flags |= kernelFlowFlagReplyClosing }},
		{name: "transparent reply to another client", kind: transparent, reply: true, keyIf: arrival, mutate: func(v *tcFlowValueV4, _ uint64) { v.ClientPort = clientPort + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := monotonicNowNSForTest(t)
			seen := now - recently
			var key tcFlowKeyV4
			value := tcFlowValueV4{
				ClientAddr: ipv4ToHostOrderForTest(client),
				ClientPort: clientPort,
				FrontAddr:  ipv4ToHostOrderForTest(remote),
				FrontPort:  remotePort,
				NATAddr:    ipv4ToHostOrderForTest(natAddr),
				NATPort:    natPort,
				Flags:      kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT,
				LastSeenNS: seen,
				SessionID:  77,
				Fast: tcFlowFastV4{
					Stamp:      flowFastStampForTest(seen, generation),
					OutIfIndex: 42,
					InIfIndex:  arrival,
					MaxLen:     1500,
					DMAC:       nextHopMAC,
					SMAC:       outMAC,
				},
			}
			copy(value.Fast.InDMAC[:], routerMAC)
			var frame []byte
			dstMAC := routerMAC
			if tc.dstMAC != nil {
				dstMAC = tc.dstMAC
			}
			switch tc.kind {
			case portForward:
				value.Flags = kernelFlowFlagFullNAT
			case transparent:
				value.Flags = 0
				value.NATAddr, value.NATPort = 0, 0
			}
			// Where the reply comes from: the remote host, or a port forward's backend.
			replySrc, replySrcPort := remote, uint16(remotePort)
			if tc.kind != egressNAT {
				replySrc, replySrcPort = backend, backendPort
			}
			if tc.reply && tc.kind == transparent {
				value.InIfIndex = 7
				key = tcFlowKeyV4{IfIndex: tc.keyIf, SrcAddr: ipv4ToHostOrderForTest(backend), DstAddr: ipv4ToHostOrderForTest(client),
					SrcPort: backendPort, DstPort: clientPort, Proto: syscall.IPPROTO_UDP}
				frame = flowCacheTestFrame(dstMAC, backend, client, backendPort, clientPort)
			} else if tc.reply {
				value.InIfIndex = 7
				key = tcFlowKeyV4{IfIndex: tc.keyIf, SrcAddr: ipv4ToHostOrderForTest(replySrc), DstAddr: ipv4ToHostOrderForTest(natAddr),
					SrcPort: replySrcPort, DstPort: natPort, Proto: syscall.IPPROTO_UDP}
				frame = flowCacheTestFrame(dstMAC, replySrc, natAddr, replySrcPort, natPort)
			} else {
				value.Flags |= kernelFlowFlagFrontEntry
				value.InIfIndex = arrival
				key = tcFlowKeyV4{IfIndex: tc.keyIf, SrcAddr: ipv4ToHostOrderForTest(client), DstAddr: ipv4ToHostOrderForTest(remote),
					SrcPort: clientPort, DstPort: remotePort, Proto: syscall.IPPROTO_UDP}
				if tc.fullCone {
					value.Flags |= kernelFlowFlagFullCone
					value.Fast.DstAddr = ipv4ToHostOrderForTest(remote)
					key.DstAddr, key.DstPort = 0, 0
				}
				if tc.kind == portForward {
					value.Fast.DstAddr, value.Fast.DstPort = ipv4ToHostOrderForTest(backend), backendPort
				}
				frame = flowCacheTestFrame(dstMAC, client, remote, clientPort, remotePort)
			}
			if tc.mutate != nil {
				tc.mutate(&value, now)
			}
			if err := flowsMap.Put(key, value); err != nil {
				t.Fatalf("write flow entry: %v", err)
			}
			t.Cleanup(func() { _ = flowsMap.Delete(key) })
			for child, p := range tc.parentOf {
				if err := parentMap.Put(child, p); err != nil {
					t.Fatalf("write parent mapping: %v", err)
				}
				child := child
				t.Cleanup(func() { _ = parentMap.Delete(child) })
			}
			if err := hintsMap.Put(uint32(arrival), tc.hints); err != nil {
				t.Fatalf("write interface hints: %v", err)
			}
			t.Cleanup(func() { _ = hintsMap.Put(uint32(arrival), uint32(0)) })

			prog := forwardProg
			if tc.reply {
				prog = replyProg
			}
			before := flowCacheHitsForTest(t, diagMap)
			out := make([]byte, len(frame)+64)
			ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			hits := flowCacheHitsForTest(t, diagMap) - before
			if !tc.hit {
				if hits != 0 {
					t.Fatalf("flow cache served a packet its record does not describe (returned %d)", int32(ret))
				}
				// The forward dispatcher finds no rule for it and passes it on untouched.
				if !tc.reply && (ret != tcActUnspec || !bytes.Equal(out[:len(frame)], frame)) {
					t.Fatalf("declined forward packet: returned %d, changed %t", int32(ret), !bytes.Equal(out[:len(frame)], frame))
				}
				return
			}
			if hits != 1 || ret != tcActRedirect {
				t.Fatalf("returned %d with %d flow cache hits, want a redirect from the record", int32(ret), hits)
			}
			out = out[:len(frame)]
			if !bytes.Equal(out[0:6], nextHopMAC[:]) || !bytes.Equal(out[6:12], outMAC[:]) {
				t.Fatalf("MACs = %x -> %x, want %x -> %x", out[6:12], out[0:6], outMAC, nextHopMAC)
			}
			wantSrc, wantSrcPort, wantDst, wantDstPort := natAddr, uint16(natPort), remote, uint16(remotePort)
			if tc.kind == portForward {
				wantDst, wantDstPort = backend, backendPort
			}
			if tc.reply {
				// Every reply leaves from the address the client sent to.
				wantSrc, wantSrcPort, wantDst, wantDstPort = remote, remotePort, client, clientPort
			}
			if got := net.IP(out[26:30]); !got.Equal(wantSrc) {
				t.Fatalf("source = %v, want %v", got, wantSrc)
			}
			if got := binary.BigEndian.Uint16(out[34:36]); got != wantSrcPort {
				t.Fatalf("source port = %d, want %d", got, wantSrcPort)
			}
			if got := net.IP(out[30:34]); !got.Equal(wantDst) {
				t.Fatalf("destination = %v, want %v", got, wantDst)
			}
			if got := binary.BigEndian.Uint16(out[36:38]); got != wantDstPort {
				t.Fatalf("destination port = %d, want %d", got, wantDstPort)
			}
			if got, want := binary.BigEndian.Uint16(out[24:26]), ipv4HeaderChecksumForTest(out[14:34]); got != want {
				t.Fatalf("IPv4 checksum = %#04x, want %#04x", got, want)
			}
		})
	}
}

// flowCacheTestFrameV6 builds an untagged IPv6 UDP frame.
func flowCacheTestFrameV6(dstMAC net.HardwareAddr, src, dst net.IP, srcPort, dstPort uint16) []byte {
	payload := []byte("veer flow cache test payload....")
	frame := make([]byte, 14+40+8+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	ip := frame[14:54]
	binary.BigEndian.PutUint32(ip[0:4], 6<<28)
	binary.BigEndian.PutUint16(ip[4:6], uint16(8+len(payload)))
	ip[6] = syscall.IPPROTO_UDP
	ip[7] = 64
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())
	udp := frame[54:62]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	copy(frame[62:], payload)
	return frame
}

// The IPv6 programs serve port forwards from their records too: a forward
// packet translated to the backend its record names, a reply back to the
// client from the address it sent to. A packet the record does not describe
// goes on to the full path.
func TestTCFlowCacheV6ServesOnlyMatchingPackets(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelForwardProgramNameV6, kernelReplyProgramNameV6)
	forwardProg := coll.Programs[kernelForwardProgramNameV6]
	replyProg := coll.Programs[kernelReplyProgramNameV6]
	flowsMap := coll.Maps[kernelFlowsMapNameV6]
	stateMap := coll.Maps[kernelTCFlowCacheStateMapName]
	diagMap := coll.Maps[kernelDiagMapName]
	if flowsMap == nil || stateMap == nil || diagMap == nil {
		t.Fatalf("IPv6 program maps: flows=%v state=%v diag=%v", flowsMap, stateMap, diagMap)
	}
	const arrival = 1
	const generation = 5
	if err := stateMap.Put(uint32(0), tcFlowCacheStateV4{Generation: generation, Enabled: 1}); err != nil {
		t.Fatalf("write cache state: %v", err)
	}
	routerMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa}
	otherMAC := net.HardwareAddr{0x02, 0, 0, 0, 0, 0xbb}
	nextHopMAC := [6]byte{0x02, 0, 0, 0, 0, 0xcc}
	outMAC := [6]byte{0x02, 0, 0, 0, 0, 0xdd}
	client := net.ParseIP("2001:db8:1::10")
	front := net.ParseIP("2001:db8:2::1")
	natAddr := net.ParseIP("2001:db8:3::1")
	backend := net.ParseIP("2001:db8:4::5")
	const clientPort, frontPort, natPort, backendPort = 51000, 443, 40000, 8443
	addr16 := func(ip net.IP) (out [16]byte) { copy(out[:], ip.To16()); return out }

	const recently = 200_000_000
	cases := []struct {
		name   string
		reply  bool
		dstMAC net.HardwareAddr
		mutate func(*tcFlowValueV6, uint64)
		hit    bool
	}{
		{name: "forward", hit: true},
		{name: "forward for another MAC", dstMAC: otherMAC},
		{name: "forward under a stale generation", mutate: func(v *tcFlowValueV6, now uint64) {
			v.LastSeenNS = now - recently
			v.Fast.Stamp = flowFastStampForTest(v.LastSeenNS, generation-1)
		}},
		{name: "forward after the window", mutate: func(v *tcFlowValueV6, now uint64) {
			v.LastSeenNS = now - 2_000_000_000
			v.Fast.Stamp = flowFastStampForTest(v.LastSeenNS, generation)
		}},
		{name: "forward too long for the next hop", mutate: func(v *tcFlowValueV6, _ uint64) { v.Fast.MaxLen = 60 }},
		{name: "reply", reply: true, hit: true},
		{name: "reply of a closing flow", reply: true, mutate: func(v *tcFlowValueV6, _ uint64) { v.Flags |= kernelFlowFlagReplyClosing }},
		{name: "reply from another port", reply: true, mutate: func(v *tcFlowValueV6, _ uint64) { v.Fast.InIfIndex = 4 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := monotonicNowNSForTest(t)
			seen := now - recently
			value := tcFlowValueV6{
				ClientAddr: addr16(client),
				ClientPort: clientPort,
				FrontAddr:  addr16(front),
				FrontPort:  frontPort,
				NATAddr:    addr16(natAddr),
				NATPort:    natPort,
				Flags:      kernelFlowFlagFullNAT,
				LastSeenNS: seen,
				SessionID:  77,
				Fast: tcFlowFastV6{
					Stamp:      flowFastStampForTest(seen, generation),
					OutIfIndex: 42,
					InIfIndex:  arrival,
					MaxLen:     1500,
					DMAC:       nextHopMAC,
					SMAC:       outMAC,
				},
			}
			copy(value.Fast.InDMAC[:], routerMAC)
			dstMAC := routerMAC
			if tc.dstMAC != nil {
				dstMAC = tc.dstMAC
			}
			var key tcFlowKeyV6
			var frame []byte
			if tc.reply {
				value.InIfIndex = 7
				key = tcFlowKeyV6{IfIndex: arrival, SrcAddr: addr16(backend), DstAddr: addr16(natAddr), SrcPort: backendPort, DstPort: natPort, Proto: syscall.IPPROTO_UDP}
				frame = flowCacheTestFrameV6(dstMAC, backend, natAddr, backendPort, natPort)
			} else {
				value.Flags |= kernelFlowFlagFrontEntry
				value.InIfIndex = arrival
				value.Fast.DstAddr, value.Fast.DstPort = addr16(backend), backendPort
				key = tcFlowKeyV6{IfIndex: arrival, SrcAddr: addr16(client), DstAddr: addr16(front), SrcPort: clientPort, DstPort: frontPort, Proto: syscall.IPPROTO_UDP}
				frame = flowCacheTestFrameV6(dstMAC, client, front, clientPort, frontPort)
			}
			if tc.mutate != nil {
				tc.mutate(&value, now)
			}
			if err := flowsMap.Put(key, value); err != nil {
				t.Fatalf("write flow entry: %v", err)
			}
			t.Cleanup(func() { _ = flowsMap.Delete(key) })

			prog := forwardProg
			if tc.reply {
				prog = replyProg
			}
			before := flowCacheHitsForTest(t, diagMap)
			out := make([]byte, len(frame)+64)
			ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			hits := flowCacheHitsForTest(t, diagMap) - before
			if !tc.hit {
				if hits != 0 {
					t.Fatalf("flow cache served a packet its record does not describe (returned %d)", int32(ret))
				}
				return
			}
			if hits != 1 || ret != tcActRedirect {
				t.Fatalf("returned %d with %d flow cache hits, want a redirect from the record", int32(ret), hits)
			}
			out = out[:len(frame)]
			if !bytes.Equal(out[0:6], nextHopMAC[:]) || !bytes.Equal(out[6:12], outMAC[:]) {
				t.Fatalf("MACs = %x -> %x, want %x -> %x", out[6:12], out[0:6], outMAC, nextHopMAC)
			}
			wantSrc, wantSrcPort, wantDst, wantDstPort := natAddr, uint16(natPort), backend, uint16(backendPort)
			if tc.reply {
				wantSrc, wantSrcPort, wantDst, wantDstPort = front, frontPort, client, clientPort
			}
			if got := net.IP(out[22:38]); !got.Equal(wantSrc) {
				t.Fatalf("source = %v, want %v", got, wantSrc)
			}
			if got := net.IP(out[38:54]); !got.Equal(wantDst) {
				t.Fatalf("destination = %v, want %v", got, wantDst)
			}
			if got := binary.BigEndian.Uint16(out[54:56]); got != wantSrcPort {
				t.Fatalf("source port = %d, want %d", got, wantSrcPort)
			}
			if got := binary.BigEndian.Uint16(out[56:58]); got != wantDstPort {
				t.Fatalf("destination port = %d, want %d", got, wantDstPort)
			}
		})
	}
}
