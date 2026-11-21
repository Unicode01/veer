//go:build linux

package app

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Firewall 1.1 stages, run with BPF_PROG_TEST_RUN like
// plugin_firewall_prog_linux_test.go: ICMP and IP-protocol policies,
// catch-all policies, the baseline checks, sets (blocklists, policy source
// sets, add_to_set) and connection tracking with the tc_egress program.
// Layouts follow plugins/firewall/lib/compile.js; TestFirewallExtMapKeysMatchCompiler
// pins them to the compiler's bytes.

const (
	fwProtoICMP   = 2
	fwProtoICMPv6 = 3
	fwProtoIP     = 4

	fwGCT        = 1
	fwGBogon     = 2
	fwGBadFlags  = 4
	fwGDropFrags = 8
	fwGProto     = 64

	fwPxNewOnly = 1
	fwPxAddSet  = 2

	fwSetBogon = 0xfff0

	fwGcntEstablished = 0
	fwGcntRelated     = 1
	fwGcntEssential   = 2
	fwGcntBlocklist   = 3
	fwGcntCTNew       = 8
	fwGcntSetAdd      = 11
	fwGcntSetFull     = 12
)

func fwSetKey(id uint16, cidr string) []byte {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ones, _ := network.Mask.Size()
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, uint32(32+ones))
	if v4 := network.IP.To4(); v4 != nil {
		b[4] = 4
		copy(b[8:], v4)
	} else {
		b[4] = 6
		copy(b[8:], network.IP.To16())
	}
	binary.BigEndian.PutUint16(b[6:], id)
	return b
}

func fwSetValue(expiresNS uint64, kind uint32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint64(b, expiresNS)
	binary.LittleEndian.PutUint32(b[8:], kind)
	return b
}

// fwCTKey is struct fw_ct_key: the connection as its packets leave.
func fwCTKey(proto uint8, laddr string, lport uint16, raddr string, rport uint16) []byte {
	b := make([]byte, 40)
	l, r := net.ParseIP(laddr), net.ParseIP(raddr)
	b[0], b[1] = 6, proto
	if l.To4() != nil {
		b[0] = 4
		copy(b[8:], l.To4())
		copy(b[24:], r.To4())
	} else {
		copy(b[8:], l.To16())
		copy(b[24:], r.To16())
	}
	binary.BigEndian.PutUint16(b[2:], lport)
	binary.BigEndian.PutUint16(b[4:], rport)
	return b
}

func TestFirewallExtMapKeysMatchCompiler(t *testing.T) {
	// Literals from plugins/firewall/test-compile.test.js.
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{fwSetKey(5, "203.0.113.0/24"), "380000000400" + "0005" + "cb007100" + "000000000000000000000000"},
		{fwSetKey(5, "2001:db8::/32"), "400000000600" + "0005" + "20010db8" + "000000000000000000000000"},
		{fwSetValue(5000*1000000, 2), "00f2052a01000000" + "02000000" + "00000000"},
		{fwPortKey(0, fwProtoICMP, 8<<8, 8), "1800000000020800"},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Fatalf("key = %s, want %s", got, tc.want)
		}
	}
}

func monotonicNS(t testing.TB) uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// gcfg writes fw_gcfg of a generation: flags, the catch-all class and the
// blocklist sets.
func (r *firewallTestRig) gcfg(gen uint8, flags uint32, anyClass uint16, blocks ...uint16) {
	value := make([]byte, 16)
	binary.LittleEndian.PutUint32(value, flags)
	binary.LittleEndian.PutUint16(value[4:], anyClass)
	value[6] = uint8(len(blocks))
	for i, id := range blocks {
		binary.LittleEndian.PutUint16(value[8+2*i:], id)
	}
	r.put("fw_gcfg", uint32(gen), value)
}

type fwPext struct {
	flags      uint8
	sets       []uint16
	actions    []uint8 // 0 allow, 1 drop
	addSet     uint16
	addSeconds uint32
	v6Prefix   uint8
}

func (r *firewallTestRig) pext(gen uint8, slot uint32, px fwPext) {
	value := make([]byte, 40)
	value[0] = px.flags
	value[1] = uint8(len(px.sets))
	binary.LittleEndian.PutUint16(value[2:], px.addSet)
	binary.LittleEndian.PutUint32(value[4:], px.addSeconds)
	for i, id := range px.sets {
		binary.LittleEndian.PutUint16(value[8+2*i:], id)
		value[16+i] = px.actions[i]
	}
	value[20] = px.v6Prefix
	for i := 0; i < 16; i++ {
		bits := int(px.v6Prefix) - 8*i
		switch {
		case bits >= 8:
			value[24+i] = 0xff
		case bits > 0:
			value[24+i] = byte(0xff << (8 - bits))
		}
	}
	r.put("fw_pext", uint32(gen)*256+slot, value)
}

func (r *firewallTestRig) setElement(id uint16, cidr string, expiresNS uint64) {
	r.put("fw_sets", fwSetKey(id, cidr), fwSetValue(expiresNS, 1))
}

func (r *firewallTestRig) hasSetElement(id uint16, cidr string) bool {
	value := make([]byte, 16)
	return r.coll.Maps["fw_sets"].Lookup(fwSetKey(id, cidr), &value) == nil
}

func (r *firewallTestRig) gcounter(counter uint32) uint64 {
	r.t.Helper()
	var values []uint64
	if err := r.coll.Maps["fw_gstats"].Lookup(counter, &values); err != nil {
		r.t.Fatalf("read global counter: %v", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}

// protect maps one fw_ports value (ICMP type<<8|code, IP protocol<<8) of
// proto to class; TCP/UDP go through protectPorts and the bitmap.
func (r *firewallTestRig) protect(gen, proto uint8, value uint16, prefix int, class uint32) {
	r.put("fw_ports", fwPortKey(gen, proto, value, prefix), class)
}

// egress runs tc_firewall_egress on frame, as it leaves ifindex.
func (r *firewallTestRig) egress(frame []byte) {
	r.t.Helper()
	prog := r.coll.Programs["tc_firewall_egress"]
	if prog == nil {
		r.t.Fatal("firewall.o has no program tc_firewall_egress")
	}
	ret, err := prog.Run(&ebpf.RunOptions{Data: frame, Context: make([]byte, 192)})
	if err != nil {
		r.t.Fatalf("run egress: %v", err)
	}
	if int32(ret) != -1 {
		r.t.Fatalf("egress verdict = %d, want TC_ACT_UNSPEC", int32(ret))
	}
}

func fwICMP(src, dst string, typ, code uint8, rest []byte) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	copy(b[4:], rest)
	if net.ParseIP(src).To4() != nil {
		return fwEthernet(0x0800, nil, fwIPv4(src, dst, 1, 0, b))
	}
	return fwEthernet(0x86dd, nil, fwIPv6(src, dst, nil, 0, 58, b))
}

// fwICMPError is an ICMP error from router about the packet quoted: an IP
// packet this host sent, of which it carries the header and 8 bytes.
func fwICMPError(router, dst string, typ, code uint8, quoted []byte) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	b = append(b, quoted...)
	if net.ParseIP(router).To4() != nil {
		return fwEthernet(0x0800, nil, fwIPv4(router, dst, 1, 0, b))
	}
	return fwEthernet(0x86dd, nil, fwIPv6(router, dst, nil, 0, 58, b))
}

func fwUDP(src, dst string, sport, dport uint16) []byte {
	b := fwL4Bytes(fwL4{17, sport, dport})
	if net.ParseIP(src).To4() != nil {
		return fwEthernet(0x0800, nil, fwIPv4(src, dst, 17, 0, b))
	}
	return fwEthernet(0x86dd, nil, fwIPv6(src, dst, nil, 0, 17, b))
}

// TestFirewallProgramProtocolsAndCatchAll, generation 0:
//
//	slot 1  icmp echo-request, default drop; allow 203.0.113.0/24
//	slot 2  ip protocol 47 (GRE), default drop; allow 198.51.100.1
//	slot 3  catch-all, default drop; allow 192.0.2.0/24
//	slot 4  tcp 22, default allow
func TestFirewallProgramProtocolsAndCatchAll(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramProtocolsAndCatchAll)
}

func testFirewallProgramProtocolsAndCatchAll(t *testing.T, r *firewallTestRig) {
	const gen = 0
	r.protect(gen, fwProtoICMP, 8<<8, 8, 1)
	r.class(gen, 1, 1, false)
	r.policy(gen, 1, true)
	r.source(gen, 1, "203.0.113.0/24", false)
	r.protect(gen, fwProtoIP, 47<<8, 8, 2)
	r.class(gen, 2, 2, false)
	r.policy(gen, 2, true)
	r.source(gen, 2, "198.51.100.1/32", false)
	r.class(gen, 3, 3, false)
	r.policy(gen, 3, true)
	r.source(gen, 3, "192.0.2.0/24", false)
	r.protectPorts(gen, fwProtoTCP, 22, 22, 4)
	r.class(gen, 4, 4, false)
	r.policy(gen, 4, false)
	r.gcfg(gen, fwGProto, 3)
	r.setConfig(gen, fwCfgActive|fwCfgLoaded)

	gre := func(src string) []byte {
		return fwEthernet(0x0800, nil, fwIPv4(src, "10.0.0.1", 47, 0, make([]byte, 8)))
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"echo request allowed", fwICMP("203.0.113.9", "10.0.0.1", 8, 0, nil), fwVerdictPass},
		{"echo request dropped", fwICMP("8.8.8.8", "10.0.0.1", 8, 0, nil), fwVerdictDrop},
		{"other icmp falls to the catch-all", fwICMP("8.8.8.8", "10.0.0.1", 13, 0, nil), fwVerdictDrop},
		{"catch-all allows its sources", fwICMP("192.0.2.9", "10.0.0.1", 13, 0, nil), fwVerdictPass},
		{"packet too big always passes", fwICMP("8.8.8.8", "10.0.0.1", 3, 4, nil), fwVerdictPass},
		{"neighbour solicitation always passes", fwICMP("fe80::1", "fe80::2", 135, 0, nil), fwVerdictPass},
		{"icmpv6 echo falls to the catch-all", fwICMP("2001:db9::1", "2001:db8::2", 128, 0, nil), fwVerdictDrop},
		{"dhcp reply always passes", fwUDP("8.8.8.8", "10.0.0.1", 67, 68), fwVerdictPass},
		{"dhcpv6 reply always passes", fwUDP("fe80::1", "fe80::2", 547, 546), fwVerdictPass},
		{"gre allowed", gre("198.51.100.1"), fwVerdictPass},
		{"gre dropped", gre("198.51.100.2"), fwVerdictDrop},
		{"unprotected port falls to the catch-all", fwTCP("8.8.8.8", "10.0.0.1", 40000, 80, 0x02), fwVerdictDrop},
		{"protected port keeps its policy", fwTCP("8.8.8.8", "10.0.0.1", 40000, 22, 0x02), fwVerdictPass},
		{"udp falls to the catch-all", fwUDP("8.8.8.8", "10.0.0.1", 40000, 53), fwVerdictDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.run(tc.frame, 0); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}
	if r.gcounter(fwGcntEssential) != 4 {
		t.Fatalf("essential = %d, want 4", r.gcounter(fwGcntEssential))
	}
	// Without FW_G_PROTO the ICMP and GRE classes are not looked up: the
	// catch-all decides, as for a rule set without such policies.
	r.gcfg(gen, 0, 3)
	if got := r.run(fwICMP("203.0.113.9", "10.0.0.1", 8, 0, nil), 0); got != fwVerdictDrop {
		t.Fatalf("echo without the proto flag = %d, want the catch-all's drop", got)
	}
}

// TestFirewallProgramBaseline: invalid TCP flags, fragments and bogon
// sources, with no policy at all; trusted sources and DHCPv4 clients asking
// for an address (from 0.0.0.0) are exempt from the bogon check.
func TestFirewallProgramBaseline(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramBaseline)
}

func testFirewallProgramBaseline(t *testing.T, r *firewallTestRig) {
	const gen = 1
	r.setElement(fwSetBogon, "10.0.0.0/8", 0)
	r.setElement(fwSetBogon, "fc00::/7", 0)
	r.setElement(fwSetBogon, "0.0.0.0/8", 0)
	r.source(gen, 0, "10.9.9.9/32", false)
	r.gcfg(gen, fwGBadFlags|fwGDropFrags|fwGBogon, 0)
	r.setConfig(gen, fwCfgLoaded)
	frag := func(off uint16) []byte {
		return fwEthernet(0x0800, nil, fwIPv4("8.8.8.8", "192.0.2.1", 17, off, fwL4Bytes(fwL4{17, 1, 2})))
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"syn", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x02), fwVerdictPass},
		{"syn fin", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x03), fwVerdictDrop},
		{"syn rst", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x06), fwVerdictDrop},
		{"null", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x00), fwVerdictDrop},
		{"fin without ack", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x01), fwVerdictDrop},
		{"fin ack", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x11), fwVerdictPass},
		{"xmas", fwTCP("8.8.8.8", "192.0.2.1", 1, 80, 0x29), fwVerdictDrop},
		{"first fragment", frag(0x2000), fwVerdictDrop},
		{"later fragment", frag(0x0010), fwVerdictDrop},
		{"ipv6 fragment", fwV6("2001:db8::1", "2001:db8::2", []uint8{44}, 0x0001, fwL4{17, 1, 2}), fwVerdictDrop},
		{"bogon source", fwUDP("10.1.2.3", "192.0.2.1", 1, 53), fwVerdictDrop},
		{"bogon ipv6 source", fwUDP("fd00::1", "2001:db8::2", 1, 53), fwVerdictDrop},
		{"trusted bogon source", fwUDP("10.9.9.9", "192.0.2.1", 1, 53), fwVerdictPass},
		{"routable source", fwUDP("8.8.8.8", "192.0.2.1", 1, 53), fwVerdictPass},
		{"dhcp discover from 0.0.0.0", fwUDP("0.0.0.0", "255.255.255.255", 68, 67), fwVerdictPass},
		{"other udp from 0.0.0.0", fwUDP("0.0.0.0", "192.0.2.1", 68, 53), fwVerdictDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.run(tc.frame, 0); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestFirewallProgramSets, generation 0:
//
//	set 1  blocklist: 198.51.100.0/24, plus 198.51.101.200 expired
//	set 2  office 203.0.113.0/24; set 3  bad 203.0.113.66
//	slot 1 tcp 22, default drop; sources: 203.0.113.70 drop (CIDR), then
//	       set 3 drop, set 2 allow
//	slot 2 tcp 23, default drop, add_to_set 1 for an hour, IPv6 as /64
//	trusted 198.51.100.9
func TestFirewallProgramSets(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramSets)
}

func testFirewallProgramSets(t *testing.T, r *firewallTestRig) {
	const gen = 0
	now := monotonicNS(t)
	r.setElement(1, "198.51.100.0/24", 0)
	r.setElement(1, "198.51.101.200/32", now-1e9)
	r.setElement(2, "203.0.113.0/24", 0)
	r.setElement(3, "203.0.113.66/32", now+3600e9)
	r.protectPorts(gen, fwProtoTCP, 22, 22, 1)
	r.class(gen, 1, 1, false)
	r.policy(gen, 1, true)
	r.source(gen, 1, "203.0.113.70/32", true)
	r.pext(gen, 1, fwPext{sets: []uint16{3, 2}, actions: []uint8{1, 0}})
	r.protectPorts(gen, fwProtoTCP, 23, 23, 2)
	r.class(gen, 2, 2, false)
	r.policy(gen, 2, true)
	r.pext(gen, 2, fwPext{flags: fwPxAddSet, addSet: 1, addSeconds: 3600, v6Prefix: 64})
	r.source(gen, 0, "198.51.100.9/32", false)
	r.gcfg(gen, 0, 0, 1)
	r.setConfig(gen, fwCfgActive|fwCfgLoaded)

	for _, tc := range []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"blocklisted on an unprotected port", fwTCP("198.51.100.5", "10.0.0.1", 1, 80, 0x10), fwVerdictDrop},
		{"blocklisted icmp", fwICMP("198.51.100.5", "10.0.0.1", 0, 0, nil), fwVerdictDrop},
		{"trusted beats the blocklist", fwTCP("198.51.100.9", "10.0.0.1", 1, 80, 0x10), fwVerdictPass},
		{"expired element", fwTCP("198.51.101.200", "10.0.0.1", 1, 80, 0x10), fwVerdictPass},
		{"office set allows", fwTCP("203.0.113.5", "10.0.0.1", 1, 22, 0x02), fwVerdictPass},
		{"earlier set drops first", fwTCP("203.0.113.66", "10.0.0.1", 1, 22, 0x02), fwVerdictDrop},
		{"prefix entries win over sets", fwTCP("203.0.113.70", "10.0.0.1", 1, 22, 0x02), fwVerdictDrop},
		{"in no set: default", fwTCP("8.8.8.8", "10.0.0.1", 1, 22, 0x02), fwVerdictDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.run(tc.frame, 0); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}

	// The honeypot: a SYN to 23 drops and lists the source, which the
	// blocklist then drops on every port.
	if r.run(fwTCP("8.8.4.4", "10.0.0.1", 1, 80, 0x02), 0) != fwVerdictPass {
		t.Fatal("8.8.4.4 blocked before touching the honeypot")
	}
	// A SYN-ACK to the honeypot (a reply to someone else's spoofed SYN) drops
	// without listing its sender.
	if r.run(fwTCP("8.8.4.4", "10.0.0.1", 1, 23, 0x12), 0) != fwVerdictDrop || r.hasSetElement(1, "8.8.4.4/32") {
		t.Fatal("a SYN-ACK to the honeypot listed its sender")
	}
	if r.run(fwTCP("8.8.4.4", "10.0.0.1", 1, 23, 0x02), 0) != fwVerdictDrop || !r.hasSetElement(1, "8.8.4.4/32") {
		t.Fatal("the honeypot SYN did not list 8.8.4.4")
	}
	if r.run(fwTCP("8.8.4.4", "10.0.0.1", 1, 80, 0x02), 0) != fwVerdictDrop {
		t.Fatal("8.8.4.4 still reaches port 80 after the honeypot")
	}
	if r.run(fwTCP("2001:db8:1:2:3::4", "2001:db8::1", 1, 23, 0x02), 0) != fwVerdictDrop || !r.hasSetElement(1, "2001:db8:1:2::/64") {
		t.Fatal("the honeypot did not list the IPv6 source as its /64")
	}
	if r.run(fwTCP("2001:db8:1:2:ffff::1", "2001:db8::1", 1, 80, 0x02), 0) != fwVerdictDrop {
		t.Fatal("another address of the listed /64 still gets through")
	}
	// An expired element the control script has not pruned yet gives way
	// to the new one.
	if r.run(fwTCP("198.51.101.200", "10.0.0.1", 1, 23, 0x02), 0) != fwVerdictDrop {
		t.Fatal("the honeypot SYN from 198.51.101.200 passed")
	}
	if r.run(fwTCP("198.51.101.200", "10.0.0.1", 1, 80, 0x10), 0) != fwVerdictDrop {
		t.Fatal("198.51.101.200 was not listed again over its expired element")
	}
	if got, full := r.gcounter(fwGcntSetAdd), r.gcounter(fwGcntSetFull); got != 3 || full != 0 {
		t.Fatalf("set adds = %d, failed = %d, want 3 and 0", got, full)
	}
}

// TestFirewallProgramNewOnly: slot 1 tcp 2222, default drop, only new
// connections judged.
func TestFirewallProgramNewOnly(t *testing.T) {
	forEachFirewallProgram(t, func(t *testing.T, r *firewallTestRig) {
		r.protectPorts(0, fwProtoTCP, 2222, 2222, 1)
		r.class(0, 1, 1, false)
		r.policy(0, 1, true)
		r.pext(0, 1, fwPext{flags: fwPxNewOnly})
		r.setConfig(0, fwCfgActive|fwCfgLoaded)
		for flags, want := range map[byte]uint32{0x02: fwVerdictDrop, 0x12: fwVerdictPass, 0x10: fwVerdictPass, 0x18: fwVerdictPass, 0x04: fwVerdictPass} {
			if got := r.run(fwTCP("8.8.8.8", "10.0.0.1", 1, 2222, flags), 0); got != want {
				t.Fatalf("flags %#x: verdict = %d, want %d", flags, got, want)
			}
		}
	})
}

// TestFirewallProgramConnectionTracking: a catch-all policy drops everything
// (generation 0, connection tracking on, slot 1); udp 51820 has its own
// policy (slot 2, default allow), so replies from it open nothing. The
// egress program records what this side opens; their replies pass.
func TestFirewallProgramConnectionTracking(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramConnectionTracking)
}

func testFirewallProgramConnectionTracking(t *testing.T, r *firewallTestRig) {
	const gen = 0
	r.class(gen, 1, 1, false)
	r.policy(gen, 1, true)
	r.protectPorts(gen, fwProtoUDP, 51820, 51820, 2)
	r.class(gen, 2, 2, false)
	r.policy(gen, 2, false)
	r.setElement(7, "198.51.100.66/32", 0)
	r.gcfg(gen, fwGCT, 1, 7)
	r.setConfig(gen, fwCfgActive|fwCfgLoaded)

	const local, remote = "192.0.2.1", "203.0.113.5"
	expect := func(name string, frame []byte, want uint32) {
		t.Helper()
		if got := r.run(frame, 0); got != want {
			t.Fatalf("%s: verdict = %d, want %d", name, got, want)
		}
	}
	// TCP: only this side's SYN opens an entry.
	expect("reply before the SYN", fwTCP(remote, local, 443, 40000, 0x12), fwVerdictDrop)
	r.egress(fwTCP(local, remote, 40000, 443, 0x02))
	expect("syn-ack", fwTCP(remote, local, 443, 40000, 0x12), fwVerdictPass)
	expect("data", fwTCP(remote, local, 443, 40000, 0x18), fwVerdictPass)
	expect("other port", fwTCP(remote, local, 443, 40001, 0x10), fwVerdictDrop)
	expect("other peer", fwTCP("203.0.113.6", local, 443, 40000, 0x10), fwVerdictDrop)
	// A connection that came in never gets an entry from its replies.
	r.egress(fwTCP(local, remote, 22, 50000, 0x12))
	r.egress(fwTCP(local, remote, 22, 50000, 0x10))
	expect("inbound connection stays judged", fwTCP(remote, local, 50000, 22, 0x10), fwVerdictDrop)

	// UDP: any outgoing packet opens one, unless it leaves a port a UDP
	// policy covers.
	r.egress(fwUDP(local, "198.51.100.53", 33333, 53))
	expect("dns answer", fwUDP("198.51.100.53", local, 53, 33333), fwVerdictPass)
	r.egress(fwUDP(local, remote, 51820, 60000))
	if got := r.gcounter(fwGcntCTNew); got != 2 {
		t.Fatalf("entries opened = %d, want 2 (the SYN and the DNS query)", got)
	}

	// ICMP: echo replies to this side's requests, and errors about its
	// connections.
	r.egress(fwICMP(local, remote, 8, 0, []byte{0x12, 0x34}))
	expect("echo reply", fwICMP(remote, local, 0, 0, []byte{0x12, 0x34}), fwVerdictPass)
	expect("echo reply, other id", fwICMP(remote, local, 0, 0, []byte{0x12, 0x35}), fwVerdictDrop)
	quoted := fwIPv4(local, remote, 6, 0, fwL4Bytes(fwL4{6, 40000, 443}))[:28]
	expect("unreachable about the connection", fwICMPError("198.18.0.1", local, 3, 1, quoted), fwVerdictPass)
	other := fwIPv4(local, remote, 6, 0, fwL4Bytes(fwL4{6, 40009, 443}))[:28]
	expect("unreachable about something else", fwICMPError("198.18.0.1", local, 3, 1, other), fwVerdictDrop)
	if r.gcounter(fwGcntRelated) != 1 {
		t.Fatalf("related = %d, want 1", r.gcounter(fwGcntRelated))
	}

	// IPv6 the same way.
	r.egress(fwTCP("2001:db8::1", "2001:db8:5::5", 40000, 443, 0x02))
	expect("ipv6 syn-ack", fwTCP("2001:db8:5::5", "2001:db8::1", 443, 40000, 0x12), fwVerdictPass)

	// Blocklists still apply to tracked connections.
	r.egress(fwTCP(local, "198.51.100.66", 40002, 443, 0x02))
	expect("blocklisted peer", fwTCP("198.51.100.66", local, 443, 40002, 0x12), fwVerdictDrop)

	// Idle entries expire: a day for TCP, 120 s after a FIN.
	key := fwCTKey(fwProtoTCP, local, 40000, remote, 443)
	value := make([]byte, 16)
	binary.LittleEndian.PutUint64(value, monotonicNS(t)-86401e9)
	r.put("fw_ct", key, value)
	expect("expired", fwTCP(remote, local, 443, 40000, 0x10), fwVerdictDrop)
	r.egress(fwTCP(local, remote, 40000, 443, 0x02))
	r.egress(fwTCP(local, remote, 40000, 443, 0x11))
	if err := r.coll.Maps["fw_ct"].Lookup(key, &value); err != nil || binary.LittleEndian.Uint32(value[8:]) != 1 {
		t.Fatalf("after the FIN the entry is %x (%v), want it closing", value, err)
	}
	binary.LittleEndian.PutUint64(value, monotonicNS(t)-121e9)
	r.put("fw_ct", key, value)
	expect("closed and idle", fwTCP(remote, local, 443, 40000, 0x10), fwVerdictDrop)
	if r.gcounter(fwGcntEstablished) == 0 || r.gcounter(fwGcntBlocklist) != 1 {
		t.Fatalf("established = %d, blocklist = %d", r.gcounter(fwGcntEstablished), r.gcounter(fwGcntBlocklist))
	}

	// With tracking off the egress program records nothing.
	r.gcfg(gen, 0, 1)
	r.egress(fwTCP(local, remote, 40100, 443, 0x02))
	if err := r.coll.Maps["fw_ct"].Lookup(fwCTKey(fwProtoTCP, local, 40100, remote, 443), &value); err == nil {
		t.Fatal("the egress program recorded a connection with tracking off")
	}
}
