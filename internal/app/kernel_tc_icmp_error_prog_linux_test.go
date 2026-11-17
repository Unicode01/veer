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

var (
	icmpErrorTestClient = net.IPv4(192, 0, 2, 10).To4()
	icmpErrorTestRemote = net.IPv4(198, 51, 100, 7).To4()
	icmpErrorTestRouter = net.IPv4(198, 51, 100, 1).To4()
	icmpErrorTestNAT    = net.IPv4(203, 0, 113, 1).To4()
	icmpErrorTestOther  = net.IPv4(203, 0, 113, 9).To4()
)

const (
	icmpErrorTestClientPort = 51000
	icmpErrorTestRemotePort = 53
	icmpErrorTestNATPort    = 40000
	icmpErrorTestRuleID     = 7
	// BPF_PROG_TEST_RUN runs on the loopback device.
	icmpErrorTestIfIndex = 1
)

func onesComplementSumForTest(parts ...[]byte) uint16 {
	var sum uint32
	for _, part := range parts {
		for i := 0; i < len(part); i += 2 {
			word := uint32(part[i]) << 8
			if i+1 < len(part) {
				word |= uint32(part[i+1])
			}
			sum += word
		}
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum)
}

func checksumForTest(parts ...[]byte) uint16 {
	return ^onesComplementSumForTest(parts...)
}

func pseudoHeaderForTest(src, dst net.IP, proto uint8, length int) []byte {
	header := make([]byte, 12)
	copy(header[0:4], src.To4())
	copy(header[4:8], dst.To4())
	header[9] = proto
	binary.BigEndian.PutUint16(header[10:12], uint16(length))
	return header
}

func ipv4PacketForTest(src, dst net.IP, proto uint8, l4 []byte) []byte {
	packet := make([]byte, 20+len(l4))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], src.To4())
	copy(packet[16:20], dst.To4())
	binary.BigEndian.PutUint16(packet[10:12], checksumForTest(packet[:20]))
	copy(packet[20:], l4)
	return packet
}

// quotedPacketForTest builds a whole small packet to quote, so every
// checksum in the quote can be checked after the translation.
func quotedPacketForTest(proto uint8, src, dst net.IP, sport, dport uint16) []byte {
	var l4 []byte
	switch proto {
	case syscall.IPPROTO_UDP:
		l4 = make([]byte, 8+12)
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
		copy(l4[8:], "quoted udp..")
		binary.BigEndian.PutUint16(l4[6:8], checksumForTest(pseudoHeaderForTest(src, dst, proto, len(l4)), l4))
	case syscall.IPPROTO_TCP:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint32(l4[4:8], 0x01020304)
		l4[12] = 5 << 4
		l4[13] = 0x02
		binary.BigEndian.PutUint16(l4[14:16], 64240)
		binary.BigEndian.PutUint16(l4[16:18], checksumForTest(pseudoHeaderForTest(src, dst, proto, len(l4)), l4))
	case syscall.IPPROTO_ICMP:
		l4 = make([]byte, 8+12)
		l4[0] = 8
		binary.BigEndian.PutUint16(l4[4:6], sport)
		binary.BigEndian.PutUint16(l4[6:8], 1)
		copy(l4[8:], "quoted echo.")
		binary.BigEndian.PutUint16(l4[2:4], checksumForTest(l4))
	}
	return ipv4PacketForTest(src, dst, proto, l4)
}

func icmpErrorFrameForTest(outerSrc, outerDst net.IP, icmpType, code uint8, quoted []byte) []byte {
	message := make([]byte, 8+len(quoted))
	message[0] = icmpType
	message[1] = code
	copy(message[8:], quoted)
	binary.BigEndian.PutUint16(message[2:4], checksumForTest(message))
	frame := make([]byte, 14)
	copy(frame[0:6], net.HardwareAddr{0x02, 0, 0, 0, 0, 0xaa})
	copy(frame[6:12], net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	return append(frame, ipv4PacketForTest(outerSrc, outerDst, syscall.IPPROTO_ICMP, message)...)
}

// checkTranslatedICMPErrorForTest checks the outer addresses and every
// checksum of a translated error, and returns the quoted packet.
func checkTranslatedICMPErrorForTest(t *testing.T, frame []byte, outerSrc, outerDst net.IP) []byte {
	t.Helper()
	outer := frame[14:]
	if got := checksumForTest(outer[:20]); got != 0 {
		t.Fatalf("outer IPv4 checksum does not verify (residue %#04x)", got)
	}
	if !net.IP(outer[12:16]).Equal(outerSrc) || !net.IP(outer[16:20]).Equal(outerDst) {
		t.Fatalf("outer %v -> %v, want %v -> %v", net.IP(outer[12:16]), net.IP(outer[16:20]), outerSrc, outerDst)
	}
	message := outer[20:]
	if got := checksumForTest(message); got != 0 {
		t.Fatalf("ICMP checksum does not verify (residue %#04x)", got)
	}
	quoted := message[8:]
	if got := checksumForTest(quoted[:20]); got != 0 {
		t.Fatalf("quoted IPv4 checksum does not verify (residue %#04x)", got)
	}
	src, dst, proto := net.IP(quoted[12:16]), net.IP(quoted[16:20]), quoted[9]
	l4 := quoted[20:]
	switch proto {
	case syscall.IPPROTO_UDP, syscall.IPPROTO_TCP:
		if got := checksumForTest(pseudoHeaderForTest(src, dst, proto, len(l4)), l4); got != 0 {
			t.Fatalf("quoted L4 checksum does not verify (residue %#04x)", got)
		}
	case syscall.IPPROTO_ICMP:
		if got := checksumForTest(l4); got != 0 {
			t.Fatalf("quoted ICMP checksum does not verify (residue %#04x)", got)
		}
	}
	return quoted
}

func putICMPErrorFlowForTest(t *testing.T, flows *ebpf.Map, key tcFlowKeyV4, flags uint16) {
	t.Helper()
	value := tcFlowValueV4{
		RuleID:     icmpErrorTestRuleID,
		FrontAddr:  ipv4ToHostOrderForTest(icmpErrorTestRemote),
		ClientAddr: ipv4ToHostOrderForTest(icmpErrorTestClient),
		NATAddr:    ipv4ToHostOrderForTest(icmpErrorTestNAT),
		InIfIndex:  icmpErrorTestIfIndex,
		FrontPort:  icmpErrorTestRemotePort,
		ClientPort: icmpErrorTestClientPort,
		NATPort:    icmpErrorTestNATPort,
		Flags:      flags,
	}
	if key.Proto == syscall.IPPROTO_ICMP {
		value.FrontPort = 0
	}
	if err := flows.Put(key, value); err != nil {
		t.Fatalf("write flow: %v", err)
	}
	t.Cleanup(func() { _ = flows.Delete(key) })
}

func runICMPErrorProgramForTest(t *testing.T, prog *ebpf.Program, frame []byte) (uint32, []byte) {
	t.Helper()
	out := make([]byte, len(frame)+64)
	ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return ret, out[:len(frame)]
}

// Errors from the WAN about a packet a LAN host sent through egress NAT go
// back to that host, with the quote showing the packet as the host sent it.
func TestTCICMPErrorReplyTranslatesToTheLANHost(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelICMPErrorReplyProgramName)
	prog := coll.Programs[kernelICMPErrorReplyProgramName]
	flows := coll.Maps[kernelFlowsMapName]
	if flows == nil {
		t.Fatal("flows map is unavailable")
	}
	nat, remote := ipv4ToHostOrderForTest(icmpErrorTestNAT), ipv4ToHostOrderForTest(icmpErrorTestRemote)
	replyKey := func(proto uint8, wildcard bool) tcFlowKeyV4 {
		key := tcFlowKeyV4{IfIndex: icmpErrorTestIfIndex, SrcAddr: remote, DstAddr: nat, SrcPort: icmpErrorTestRemotePort, DstPort: icmpErrorTestNATPort, Proto: proto}
		if proto == syscall.IPPROTO_ICMP {
			key.SrcPort = 0
		}
		if wildcard {
			key.SrcAddr, key.SrcPort = 0, 0
		}
		return key
	}
	const replyFlags = kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagReplySeen
	for _, tc := range []struct {
		name     string
		proto    uint8
		icmpType uint8
		code     uint8
		wildcard bool
	}{
		{name: "udp port unreachable", proto: syscall.IPPROTO_UDP, icmpType: 3, code: 3},
		{name: "tcp time exceeded", proto: syscall.IPPROTO_TCP, icmpType: 11},
		{name: "udp fragmentation needed", proto: syscall.IPPROTO_UDP, icmpType: 3, code: 4},
		{name: "echo request time exceeded", proto: syscall.IPPROTO_ICMP, icmpType: 11},
		{name: "full cone udp", proto: syscall.IPPROTO_UDP, icmpType: 3, code: 3, wildcard: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := uint16(replyFlags)
			if tc.wildcard {
				flags |= kernelFlowFlagFullCone
			}
			putICMPErrorFlowForTest(t, flows, replyKey(tc.proto, tc.wildcard), flags)
			quoted := quotedPacketForTest(tc.proto, icmpErrorTestNAT, icmpErrorTestRemote, icmpErrorTestNATPort, icmpErrorTestRemotePort)
			frame := icmpErrorFrameForTest(icmpErrorTestRouter, icmpErrorTestNAT, tc.icmpType, tc.code, quoted)
			ret, out := runICMPErrorProgramForTest(t, prog, frame)
			if ret != tcActRedirect {
				t.Fatalf("%s returned %d, want redirect", kernelICMPErrorReplyProgramName, int32(ret))
			}
			got := checkTranslatedICMPErrorForTest(t, out, icmpErrorTestRouter, icmpErrorTestClient)
			if !net.IP(got[12:16]).Equal(icmpErrorTestClient) || !net.IP(got[16:20]).Equal(icmpErrorTestRemote) {
				t.Fatalf("quoted %v -> %v, want %v -> %v", net.IP(got[12:16]), net.IP(got[16:20]), icmpErrorTestClient, icmpErrorTestRemote)
			}
			port := binary.BigEndian.Uint16(got[20:22])
			if tc.proto == syscall.IPPROTO_ICMP {
				port = binary.BigEndian.Uint16(got[24:26])
			}
			if port != icmpErrorTestClientPort {
				t.Fatalf("quoted source port %d, want %d", port, icmpErrorTestClientPort)
			}
			if out[14+20] != tc.icmpType || out[14+21] != tc.code {
				t.Fatalf("ICMP type/code = %d/%d, want %d/%d", out[14+20], out[14+21], tc.icmpType, tc.code)
			}
		})
	}

	putICMPErrorFlowForTest(t, flows, replyKey(syscall.IPPROTO_UDP, false), replyFlags)
	declined := []struct {
		name  string
		frame []byte
	}{
		{name: "error for another address", frame: icmpErrorFrameForTest(icmpErrorTestRouter, icmpErrorTestOther, 3, 3,
			quotedPacketForTest(syscall.IPPROTO_UDP, icmpErrorTestNAT, icmpErrorTestRemote, icmpErrorTestNATPort, icmpErrorTestRemotePort))},
		{name: "no flow", frame: icmpErrorFrameForTest(icmpErrorTestRouter, icmpErrorTestNAT, 3, 3,
			quotedPacketForTest(syscall.IPPROTO_UDP, icmpErrorTestNAT, icmpErrorTestRemote, icmpErrorTestNATPort+1, icmpErrorTestRemotePort))},
		{name: "quoted echo reply", frame: func() []byte {
			quoted := quotedPacketForTest(syscall.IPPROTO_ICMP, icmpErrorTestNAT, icmpErrorTestRemote, icmpErrorTestNATPort, 0)
			quoted[20] = 0
			return icmpErrorFrameForTest(icmpErrorTestRouter, icmpErrorTestNAT, 3, 3, quoted)
		}()},
		{name: "echo request", frame: icmpErrorFrameForTest(icmpErrorTestRouter, icmpErrorTestNAT, 8, 0,
			quotedPacketForTest(syscall.IPPROTO_UDP, icmpErrorTestNAT, icmpErrorTestRemote, icmpErrorTestNATPort, icmpErrorTestRemotePort))},
	}
	for _, tc := range declined {
		t.Run(tc.name, func(t *testing.T) {
			ret, out := runICMPErrorProgramForTest(t, prog, tc.frame)
			if ret != tcActUnspec {
				t.Fatalf("%s returned %d, want TC_ACT_UNSPEC", kernelICMPErrorReplyProgramName, int32(ret))
			}
			if !bytes.Equal(out, tc.frame) {
				t.Fatal("a declined error was changed")
			}
		})
	}
}

// An error a LAN host sends about a packet it received through egress NAT
// goes to the remote host, with the quote showing that packet as the remote
// host sent it.
func TestTCICMPErrorForwardTranslatesToTheRemoteHost(t *testing.T) {
	coll := loadTCProgramsForTest(t, kernelICMPErrorForwardProgramName)
	prog := coll.Programs[kernelICMPErrorForwardProgramName]
	flows := coll.Maps[kernelFlowsMapName]
	rules := coll.Maps[kernelRulesMapName]
	if flows == nil || rules == nil {
		t.Fatal("flows or rules map is unavailable")
	}
	client, remote := ipv4ToHostOrderForTest(icmpErrorTestClient), ipv4ToHostOrderForTest(icmpErrorTestRemote)
	ruleKey := tcRuleKeyV4{IfIndex: icmpErrorTestIfIndex, Proto: syscall.IPPROTO_UDP}
	putRule := func() {
		t.Helper()
		rule := tcRuleValueV4{
			RuleID:     icmpErrorTestRuleID,
			Flags:      kernelRuleFlagEgressNAT,
			OutIfIndex: icmpErrorTestIfIndex,
			NATAddr:    ipv4ToHostOrderForTest(icmpErrorTestNAT),
		}
		if err := rules.Put(ruleKey, rule); err != nil {
			t.Fatalf("write rule: %v", err)
		}
	}
	errorFrame := func() []byte {
		// The datagram the LAN host received after the NAT, and its reply.
		quoted := quotedPacketForTest(syscall.IPPROTO_UDP, icmpErrorTestRemote, icmpErrorTestClient, icmpErrorTestRemotePort, icmpErrorTestClientPort)
		return icmpErrorFrameForTest(icmpErrorTestClient, icmpErrorTestRemote, 3, 3, quoted)
	}
	const frontFlags = kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry | kernelFlowFlagEgressNAT | kernelFlowFlagReplySeen
	for _, tc := range []struct {
		name     string
		wildcard bool
	}{
		{name: "symmetric"},
		{name: "full cone", wildcard: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			putRule()
			t.Cleanup(func() { _ = rules.Delete(ruleKey) })
			key := tcFlowKeyV4{IfIndex: icmpErrorTestIfIndex, SrcAddr: client, DstAddr: remote, SrcPort: icmpErrorTestClientPort, DstPort: icmpErrorTestRemotePort, Proto: syscall.IPPROTO_UDP}
			flags := uint16(frontFlags)
			if tc.wildcard {
				key.DstAddr, key.DstPort = 0, 0
				flags |= kernelFlowFlagFullCone
			}
			putICMPErrorFlowForTest(t, flows, key, flags)
			ret, out := runICMPErrorProgramForTest(t, prog, errorFrame())
			if ret != tcActRedirect {
				t.Fatalf("%s returned %d, want redirect", kernelICMPErrorForwardProgramName, int32(ret))
			}
			got := checkTranslatedICMPErrorForTest(t, out, icmpErrorTestNAT, icmpErrorTestRemote)
			if !net.IP(got[12:16]).Equal(icmpErrorTestRemote) || !net.IP(got[16:20]).Equal(icmpErrorTestNAT) {
				t.Fatalf("quoted %v -> %v, want %v -> %v", net.IP(got[12:16]), net.IP(got[16:20]), icmpErrorTestRemote, icmpErrorTestNAT)
			}
			if port := binary.BigEndian.Uint16(got[22:24]); port != icmpErrorTestNATPort {
				t.Fatalf("quoted destination port %d, want %d", port, icmpErrorTestNATPort)
			}
		})
	}

	t.Run("no rule", func(t *testing.T) {
		key := tcFlowKeyV4{IfIndex: icmpErrorTestIfIndex, SrcAddr: client, DstAddr: remote, SrcPort: icmpErrorTestClientPort, DstPort: icmpErrorTestRemotePort, Proto: syscall.IPPROTO_UDP}
		putICMPErrorFlowForTest(t, flows, key, frontFlags)
		frame := errorFrame()
		ret, out := runICMPErrorProgramForTest(t, prog, frame)
		if ret != tcActUnspec || !bytes.Equal(out, frame) {
			t.Fatalf("%s returned %d and changed=%t, want TC_ACT_UNSPEC and no change", kernelICMPErrorForwardProgramName, int32(ret), !bytes.Equal(out, frame))
		}
	})
}
