//go:build linux

package app

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Runs both entry points of plugins/firewall/firewall.o, xdp_firewall and
// tc_firewall, with BPF_PROG_TEST_RUN against crafted frames. Map contents
// follow the layouts plugins/firewall/lib/compile.js writes;
// TestFirewallMapKeysMatchCompiler pins both to the same bytes.

const (
	fwVerdictDrop = 1
	fwVerdictPass = 2 // also what an empty dispatcher continue slot returns

	fwCfgHasL3  = 1
	fwCfgActive = 2
	fwCfgLoaded = 4

	fwProtoTCP = 0
	fwProtoUDP = 1

	fwCntPass    = 0
	fwCntDrop    = 1
	fwCntTrusted = 2
	fwCntEvasive = 3
)

func fwPortKey(gen, proto uint8, port uint16, prefix int) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, uint32(16+prefix))
	b[4], b[5] = gen, proto
	binary.BigEndian.PutUint16(b[6:], port)
	return b
}

func fwAddrKey(gen uint8, id uint16, cidr string) []byte {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	ones, _ := network.Mask.Size()
	addr := network.IP.To4()
	if addr == nil {
		addr = network.IP.To16()
	}
	b := make([]byte, 8+len(addr))
	binary.LittleEndian.PutUint32(b, uint32(32+ones))
	b[4] = gen
	binary.BigEndian.PutUint16(b[6:], id)
	copy(b[8:], addr)
	return b
}

func TestFirewallMapKeysMatchCompiler(t *testing.T) {
	// Literals from plugins/firewall/test-compile.test.js.
	for _, tc := range []struct {
		got  []byte
		want string
	}{
		{fwPortKey(1, fwProtoTCP, 22, 16), "2000000001000016"},
		{fwPortKey(1, fwProtoTCP, 10022, 15), "1f00000001002726"},
		{fwAddrKey(1, 1, "203.0.113.0/24"), "3800000001000001cb007100"},
		{fwAddrKey(1, 0, "192.0.2.10/32"), "4000000001000000c000020a"},
		{fwAddrKey(1, 2, "2001:db8::/32"), "400000000100000220010db8000000000000000000000000"},
	} {
		if got := hex.EncodeToString(tc.got); got != tc.want {
			t.Fatalf("key = %s, want %s", got, tc.want)
		}
	}
}

// firewallTestRig runs one entry point of firewall.o: xdp_firewall, or
// tc_firewall, the hook's tc_fallback for interfaces without native XDP. Both
// share the maps and the filter code; run translates TC verdicts into the XDP
// ones, so every test states its expectations once.
type firewallTestRig struct {
	t    *testing.T
	coll *ebpf.Collection
	prog *ebpf.Program
	tc   bool
}

// forEachFirewallProgram runs test as subtests "xdp" and "tc", each against
// freshly loaded maps.
func forEachFirewallProgram(t *testing.T, test func(t *testing.T, r *firewallTestRig)) {
	for _, mode := range []string{"xdp", "tc"} {
		t.Run(mode, func(t *testing.T) {
			test(t, loadFirewallTestRig(t, mode == "tc"))
		})
	}
}

func loadFirewallTestRig(t *testing.T, tc bool) *firewallTestRig {
	t.Helper()
	path := filepath.Join(findRepoRoot(t), "plugins", "firewall", "firewall.o")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not built (scripts/build-plugin-ebpf.sh): %v", path, err)
	}
	if os.Geteuid() != 0 {
		t.Skip("loading BPF programs needs root")
	}
	_ = rlimit.RemoveMemlock()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load firewall.o: %v", err)
	}
	t.Cleanup(coll.Close)
	name := "xdp_firewall"
	if tc {
		name = "tc_firewall"
	}
	prog := coll.Programs[name]
	if prog == nil {
		t.Fatalf("firewall.o has no program %s", name)
	}
	return &firewallTestRig{t: t, coll: coll, prog: prog, tc: tc}
}

func (r *firewallTestRig) put(mapName string, key, value any) {
	r.t.Helper()
	if err := r.coll.Maps[mapName].Put(key, value); err != nil {
		r.t.Fatalf("put %s: %v", mapName, err)
	}
}

func (r *firewallTestRig) setConfig(gen, flags uint32) {
	value := make([]byte, 8)
	binary.LittleEndian.PutUint32(value, gen)
	binary.LittleEndian.PutUint32(value[4:], flags)
	r.put("fw_cfg", uint32(0), value)
}

func (r *firewallTestRig) protectPorts(gen, proto uint8, from, to uint16, class uint32) {
	for port := uint32(from); port <= uint32(to); port++ {
		index := uint32(gen)*2048 + uint32(proto)*1024 + port>>6
		var word uint64
		_ = r.coll.Maps["fw_port_bits"].Lookup(index, &word)
		word |= 1 << (port & 63)
		r.put("fw_port_bits", index, word)
		r.put("fw_ports", fwPortKey(gen, proto, uint16(port), 16), class)
	}
}

func (r *firewallTestRig) class(gen uint8, id uint32, anyPolicy uint16, scoped bool) {
	value := make([]byte, 4)
	binary.LittleEndian.PutUint16(value, anyPolicy)
	if scoped {
		value[2] = 1
	}
	r.put("fw_class", uint32(gen)*1024+id, value)
}

func (r *firewallTestRig) policy(gen uint8, slot uint32, defaultDrop bool) {
	value := []byte{1, 0, 0, 0}
	if defaultDrop {
		value[1] = 1
	}
	r.put("fw_policy", uint32(gen)*256+slot, value)
}

func (r *firewallTestRig) source(gen uint8, slot uint16, cidr string, drop bool) {
	value := []byte{0, 0, 0, 0}
	if drop {
		value[0] = 1
	}
	key := fwAddrKey(gen, slot, cidr)
	name := "fw_src4"
	if len(key) == 24 {
		name = "fw_src6"
	}
	r.put(name, key, value)
}

func (r *firewallTestRig) destination(gen uint8, class uint16, cidr string, slot uint32) {
	key := fwAddrKey(gen, class, cidr)
	name := "fw_dst4"
	if len(key) == 24 {
		name = "fw_dst6"
	}
	r.put(name, key, slot)
}

func (r *firewallTestRig) counter(slot, counter uint32) uint64 {
	r.t.Helper()
	var values []uint64
	if err := r.coll.Maps["fw_stats"].Lookup(slot*4+counter, &values); err != nil {
		r.t.Fatalf("read counter: %v", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}

// fwTCMinFrame is the shortest IPv4 frame BPF_PROG_RUN takes for a TC program:
// it refuses one whose IP header is cut (EINVAL), whatever the program does.
const fwTCMinFrame = 34

// run returns fwVerdictDrop or fwVerdictPass; for TC, TC_ACT_SHOT and
// TC_ACT_UNSPEC. Any other TC verdict comes back as 1000 + the verdict.
func (r *firewallTestRig) run(frame []byte, ingressIfindex uint32) uint32 {
	r.t.Helper()
	if r.tc {
		// XDP runs deliver on lo unless told otherwise; so does this.
		if ingressIfindex == 0 {
			ingressIfindex = 1
		}
		ctx := make([]byte, 192) // struct __sk_buff
		binary.LittleEndian.PutUint32(ctx[36:], ingressIfindex)
		ret, err := r.prog.Run(&ebpf.RunOptions{Data: frame, Context: ctx})
		if err != nil {
			r.t.Fatalf("run: %v", err)
		}
		switch int32(ret) {
		case 2: // TC_ACT_SHOT
			return fwVerdictDrop
		case -1: // TC_ACT_UNSPEC: on to the Veer core
			return fwVerdictPass
		}
		return 1000 + ret
	}
	opts := &ebpf.RunOptions{Data: frame}
	if ingressIfindex != 0 {
		ctx := make([]byte, 24) // struct xdp_md: data, data_end, data_meta, ingress_ifindex, rx_queue_index, egress_ifindex
		binary.LittleEndian.PutUint32(ctx[4:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(ctx[12:], ingressIfindex)
		opts.Context = ctx
	}
	ret, err := r.prog.Run(opts)
	if err != nil {
		r.t.Fatalf("run: %v", err)
	}
	return ret
}

// --- frames ---

type fwL4 struct {
	proto    uint8 // 6 or 17
	src, dst uint16
}

func fwL4Bytes(l4 fwL4) []byte {
	if l4.proto == 6 {
		b := make([]byte, 20)
		binary.BigEndian.PutUint16(b, l4.src)
		binary.BigEndian.PutUint16(b[2:], l4.dst)
		b[12] = 5 << 4
		b[13] = 0x02 // SYN
		return b
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, l4.src)
	binary.BigEndian.PutUint16(b[2:], l4.dst)
	binary.BigEndian.PutUint16(b[4:], 8)
	return b
}

func fwIPv4(src, dst string, proto uint8, fragOff uint16, payload []byte) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(20+len(payload)))
	binary.BigEndian.PutUint16(b[6:], fragOff)
	b[8], b[9] = 64, proto
	copy(b[12:], net.ParseIP(src).To4())
	copy(b[16:], net.ParseIP(dst).To4())
	return append(b, payload...)
}

// ext lists extension headers (next-header values) between the fixed header
// and l4; a 44 is a fragment header with fragOff.
func fwIPv6(src, dst string, ext []uint8, fragOff uint16, l4proto uint8, payload []byte) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	b[7] = 64
	copy(b[8:], net.ParseIP(src).To16())
	copy(b[24:], net.ParseIP(dst).To16())
	var chain []byte
	for i, kind := range ext {
		next := l4proto
		if i+1 < len(ext) {
			next = ext[i+1]
		}
		h := make([]byte, 8)
		h[0] = next
		if kind == 44 {
			binary.BigEndian.PutUint16(h[2:], fragOff)
		}
		chain = append(chain, h...)
	}
	if len(ext) > 0 {
		b[6] = ext[0]
	} else {
		b[6] = l4proto
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(chain)+len(payload)))
	b = append(b, chain...)
	return append(b, payload...)
}

func fwEthernet(ethertype uint16, tags []uint16, payload []byte) []byte {
	b := []byte{0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2}
	for i, outer := range tags {
		tpid := uint16(0x8100)
		if i == 0 && len(tags) == 2 {
			tpid = 0x88a8
		}
		b = binary.BigEndian.AppendUint16(b, tpid)
		b = binary.BigEndian.AppendUint16(b, outer)
	}
	b = binary.BigEndian.AppendUint16(b, ethertype)
	return append(b, payload...)
}

func fwPPPoE(pppProto uint16, payload []byte) []byte {
	h := []byte{0x11, 0x00, 0x00, 0x01, 0, 0}
	binary.BigEndian.PutUint16(h[4:], uint16(2+len(payload)))
	h = binary.BigEndian.AppendUint16(h, pppProto)
	return fwEthernet(0x8864, nil, append(h, payload...))
}

func fwV4(src, dst string, l4 fwL4) []byte {
	return fwEthernet(0x0800, nil, fwIPv4(src, dst, l4.proto, 0, fwL4Bytes(l4)))
}

func fwV6(src, dst string, ext []uint8, fragOff uint16, l4 fwL4) []byte {
	return fwEthernet(0x86dd, nil, fwIPv6(src, dst, ext, fragOff, l4.proto, fwL4Bytes(l4)))
}

// TestFirewallProgramVerdicts loads one rule set into generation 1:
//
//	slot 1  tcp 23390, any destination, default drop; allow 203.0.113.0/24
//	        but drop 203.0.113.66
//	slot 2  tcp+udp 22 to 198.51.100.7 only, default drop; allow 192.0.2.0/24
//	slot 3  tcp 443 to 2001:db8:1::443 only, default drop; allow 2001:db8::/32
//	trusted 192.0.2.10 and 2001:db8:ffff::1
func TestFirewallProgramVerdicts(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramVerdicts)
}

func testFirewallProgramVerdicts(t *testing.T, r *firewallTestRig) {
	const gen = 1
	r.protectPorts(gen, fwProtoTCP, 23390, 23390, 1)
	r.class(gen, 1, 1, false)
	r.policy(gen, 1, true)
	r.source(gen, 1, "203.0.113.0/24", false)
	r.source(gen, 1, "203.0.113.66/32", true)

	r.protectPorts(gen, fwProtoTCP, 22, 22, 2)
	r.protectPorts(gen, fwProtoUDP, 22, 22, 2)
	r.class(gen, 2, 0, true)
	r.destination(gen, 2, "198.51.100.7/32", 2)
	r.policy(gen, 2, true)
	r.source(gen, 2, "192.0.2.0/24", false)

	r.protectPorts(gen, fwProtoTCP, 443, 443, 3)
	r.class(gen, 3, 0, true)
	r.destination(gen, 3, "2001:db8:1::443/128", 3)
	r.policy(gen, 3, true)
	r.source(gen, 3, "2001:db8::/32", false)

	r.source(gen, 0, "192.0.2.10/32", false)
	r.source(gen, 0, "2001:db8:ffff::1/128", false)
	r.setConfig(gen, fwCfgActive|fwCfgLoaded|fwCfgHasL3)

	rdp := fwL4{6, 40000, 23390}
	ssh := fwL4{6, 40000, 22}
	sshUDP := fwL4{17, 40000, 22}
	https := fwL4{6, 40000, 443}
	ipv4Frag := func(src, dst string, l4 fwL4, off uint16, payload []byte) []byte {
		if payload == nil {
			payload = fwL4Bytes(l4)
		}
		return fwEthernet(0x0800, nil, fwIPv4(src, dst, l4.proto, off, payload))
	}

	for _, tc := range []struct {
		name    string
		frame   []byte
		ifindex uint32
		want    uint32
	}{
		{"allowed source", fwV4("203.0.113.5", "10.0.0.1", rdp), 0, fwVerdictPass},
		{"longer drop prefix wins", fwV4("203.0.113.66", "10.0.0.1", rdp), 0, fwVerdictDrop},
		{"default drop", fwV4("8.8.8.8", "10.0.0.1", rdp), 0, fwVerdictDrop},
		{"trusted source", fwV4("192.0.2.10", "10.0.0.1", rdp), 0, fwVerdictPass},
		{"other protocol on the port", fwV4("8.8.8.8", "10.0.0.1", fwL4{17, 40000, 23390}), 0, fwVerdictPass},
		{"unprotected port", fwV4("8.8.8.8", "10.0.0.1", fwL4{6, 40000, 80}), 0, fwVerdictPass},
		{"scoped destination", fwV4("8.8.8.8", "198.51.100.7", ssh), 0, fwVerdictDrop},
		{"other destination", fwV4("8.8.8.8", "198.51.100.8", ssh), 0, fwVerdictPass},
		{"scoped udp allowed", fwV4("192.0.2.20", "198.51.100.7", sshUDP), 0, fwVerdictPass},
		{"vlan", fwEthernet(0x0800, []uint16{10}, fwIPv4("8.8.8.8", "10.0.0.1", 6, 0, fwL4Bytes(rdp))), 0, fwVerdictDrop},
		{"qinq", fwEthernet(0x0800, []uint16{100, 10}, fwIPv4("8.8.8.8", "10.0.0.1", 6, 0, fwL4Bytes(rdp))), 0, fwVerdictDrop},
		{"pppoe session ipv4", fwPPPoE(0x0021, fwIPv4("8.8.8.8", "10.0.0.1", 6, 0, fwL4Bytes(rdp))), 0, fwVerdictDrop},
		{"pppoe lcp", fwPPPoE(0xc021, make([]byte, 20)), 0, fwVerdictPass},
		{"pppoe discovery", fwEthernet(0x8863, nil, make([]byte, 20)), 0, fwVerdictPass},
		{"ipv4 first fragment", ipv4Frag("8.8.8.8", "10.0.0.1", rdp, 0x2000, nil), 0, fwVerdictDrop},
		{"ipv4 later fragment", ipv4Frag("8.8.8.8", "10.0.0.1", rdp, 0x2001, nil), 0, fwVerdictPass},
		{"ipv4 first fragment hiding its ports", ipv4Frag("8.8.8.8", "10.0.0.1", rdp, 0x2000, []byte{0x9c}), 0, fwVerdictDrop},
		// A TCP first fragment that ends before the flags would carry a SYN
		// past the SYN limit, so it is evasive even from an allowed source.
		{"ipv4 first fragment hiding its tcp flags", ipv4Frag("203.0.113.5", "10.0.0.1", rdp, 0x2000, fwL4Bytes(rdp)[:8]), 0, fwVerdictDrop},
		{"ipv4 unfragmented without tcp flags", ipv4Frag("203.0.113.5", "10.0.0.1", rdp, 0, fwL4Bytes(rdp)[:8]), 0, fwVerdictPass},
		{"ipv6 allowed", fwV6("2001:db8::5", "2001:db8:1::443", nil, 0, https), 0, fwVerdictPass},
		{"ipv6 default drop", fwV6("2001:db9::5", "2001:db8:1::443", nil, 0, https), 0, fwVerdictDrop},
		{"ipv6 trusted", fwV6("2001:db8:ffff::1", "2001:db8:1::443", nil, 0, https), 0, fwVerdictPass},
		{"ipv6 behind extension headers", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{0, 60}, 0, https), 0, fwVerdictDrop},
		{"ipv6 first fragment", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{44}, 0x0001, https), 0, fwVerdictDrop},
		{"ipv6 later fragment", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{44}, 0x0008, https), 0, fwVerdictPass},
		{"ipv6 first fragment hiding its tcp flags", fwEthernet(0x86dd, nil, fwIPv6("2001:db8::5", "2001:db8:1::443", []uint8{44}, 0x0001, 6, fwL4Bytes(https)[:8])), 0, fwVerdictDrop},
		{"ipv6 too many extension headers", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{0, 60, 60, 60, 60, 60, 60}, 0, https), 0, fwVerdictDrop},
		{"truncated", fwV4("8.8.8.8", "10.0.0.1", rdp)[:30], 0, fwVerdictPass},
		// Cut inside the ports (no ports, so it passes), and inside the TCP
		// header after them (the ports suffice for a verdict). On TC the
		// first parse of each runs short; the verdict comes from the second
		// parse, after the pull.
		{"truncated ports", fwV4("8.8.8.8", "10.0.0.1", rdp)[:36], 0, fwVerdictPass},
		{"truncated tcp flags", fwV4("8.8.8.8", "10.0.0.1", rdp)[:40], 0, fwVerdictDrop},
	} {
		// BPF_PROG_RUN refuses TC frames under fwTCMinFrame bytes whose IP
		// header is cut, whatever the program does, so the TC run leaves such
		// frames out; the release gate counts a skipped subtest as a failure.
		if r.tc && len(tc.frame) < fwTCMinFrame {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if got := r.run(tc.frame, tc.ifindex); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}

	// BPF_PROG_TEST_RUN delivers on lo (ifindex 1) unless told otherwise;
	// marked as an L3 interface, its frames start at the IP header.
	r.put("fw_ifaces", uint32(1), uint32(1))
	for _, tc := range []struct {
		name  string
		frame []byte
		want  uint32
	}{
		{"l3 interface", fwIPv4("8.8.8.8", "10.0.0.1", 6, 0, fwL4Bytes(rdp)), fwVerdictDrop},
		{"l3 interface allowed", fwIPv4("203.0.113.5", "10.0.0.1", 6, 0, fwL4Bytes(rdp)), fwVerdictPass},
		{"l3 interface ipv6", fwIPv6("2001:db9::5", "2001:db8:1::443", nil, 0, 6, fwL4Bytes(https)), fwVerdictDrop},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := r.run(tc.frame, 1); got != tc.want {
				t.Fatalf("verdict = %d, want %d", got, tc.want)
			}
		})
	}
	if err := r.coll.Maps["fw_ifaces"].Delete(uint32(1)); err != nil {
		t.Fatalf("unmark lo: %v", err)
	}

	// A GRO aggregate or an skb from a frag-based driver can keep its L4
	// header in a page fragment, past data_end; tc_firewall then pulls the
	// headers in and parses again. BPF_PROG_RUN builds a TC program's skb
	// from one linear buffer, so it cannot produce such an skb. The truncated
	// cases above take the same branch: the parse runs short, and "truncated
	// tcp flags" and the fragment hiding its ports reach their drop only
	// through the second parse. Bulk TCP through the tc fallback in
	// TestFirewallPluginThroughput covers real aggregates.

	if got := r.counter(1, fwCntTrusted); got != 1 {
		t.Fatalf("slot 1 trusted = %d, want 1", got)
	}
	if got := r.counter(0, fwCntEvasive); got != 4 {
		t.Fatalf("evasive drops = %d, want 4", got)
	}
	if r.counter(1, fwCntDrop) == 0 || r.counter(1, fwCntPass) == 0 {
		t.Fatal("slot 1 counted no pass or no drop")
	}

	// Generation 0 is empty: switching to it lets everything through, and
	// without an active policy an evasive packet passes too.
	r.setConfig(0, fwCfgLoaded)
	for name, frame := range map[string][]byte{
		"default drop": fwV4("8.8.8.8", "10.0.0.1", rdp),
		"evasive":      fwV6("2001:db9::5", "2001:db8:1::443", []uint8{0, 60, 60, 60, 60, 60, 60}, 0, https),
	} {
		if got := r.run(frame, 0); got != fwVerdictPass {
			t.Fatalf("%s under the empty generation: verdict = %d, want pass", name, got)
		}
	}
}

func TestFirewallProgramWithoutConfigPasses(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramWithoutConfigPasses)
}

func testFirewallProgramWithoutConfigPasses(t *testing.T, r *firewallTestRig) {
	if got := r.run(fwV4("8.8.8.8", "10.0.0.1", fwL4{6, 1, 22}), 0); got != fwVerdictPass {
		t.Fatalf("verdict = %d, want pass", got)
	}
	if r.coll.Maps["fw_cfg"] == nil {
		t.Fatal(errors.New("fw_cfg missing"))
	}
}

// --- SYN limits, bans and the drop log (P1) ---

const (
	fwPolicyValid = 1
	fwPolicyLimit = 2

	fwLcntBan    = 0
	fwLcntRate   = 1
	fwLcntLogged = 2
	fwLcntLost   = 3

	fwReasonACL  = 1
	fwReasonBan  = 2
	fwReasonRate = 3
)

// limitedPolicy writes a policy with a SYN limit the way compile.js does.
func (r *firewallTestRig) limitedPolicy(gen uint8, slot uint32, defaultDrop bool, maxNew, window, ban uint32, v6Prefix uint8) {
	value := []byte{fwPolicyValid | fwPolicyLimit, 0, 0, 0}
	if defaultDrop {
		value[1] = 1
	}
	r.put("fw_policy", uint32(gen)*256+slot, value)
	limit := make([]byte, 32)
	binary.LittleEndian.PutUint32(limit, maxNew)
	binary.LittleEndian.PutUint32(limit[4:], window)
	binary.LittleEndian.PutUint32(limit[8:], ban)
	limit[12] = v6Prefix
	for i := 0; i < 16; i++ {
		bits := int(v6Prefix) - i*8
		switch {
		case bits >= 8:
			limit[16+i] = 0xff
		case bits > 0:
			limit[16+i] = byte(0xff << (8 - bits))
		}
	}
	r.put("fw_limit", uint32(gen)*256+slot, limit)
}

func (r *firewallTestRig) setLog(intervalNS, toleranceNS uint64) {
	value := make([]byte, 16)
	binary.LittleEndian.PutUint64(value, intervalNS)
	binary.LittleEndian.PutUint64(value[8:], toleranceNS)
	r.put("fw_log_cfg", uint32(0), value)
}

func (r *firewallTestRig) lcounter(slot, counter uint32) uint64 {
	r.t.Helper()
	var values []uint64
	if err := r.coll.Maps["fw_lstats"].Lookup(slot*4+counter, &values); err != nil {
		r.t.Fatalf("read limit counter: %v", err)
	}
	var total uint64
	for _, v := range values {
		total += v
	}
	return total
}

func fwLimitKeyBytes(slot uint16, src string, prefix int) []byte {
	ip := net.ParseIP(src)
	key := make([]byte, 20)
	if v4 := ip.To4(); v4 != nil {
		key[0], key[1] = 4, 32
		copy(key[4:], v4)
	} else {
		key[0], key[1] = 6, byte(prefix)
		copy(key[4:], ip.Mask(net.CIDRMask(prefix, 128)))
	}
	binary.LittleEndian.PutUint16(key[2:], slot)
	return key
}

func (r *firewallTestRig) banned(slot uint16, src string, prefix int) bool {
	var until uint64
	return r.coll.Maps["fw_ban"].Lookup(fwLimitKeyBytes(slot, src, prefix), &until) == nil
}

// fwTCP is a TCP segment with the given flags (fwL4Bytes always sends a SYN).
func fwTCP(src, dst string, sport, dport uint16, flags byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b, sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12] = 5 << 4
	b[13] = flags
	if net.ParseIP(src).To4() != nil {
		return fwEthernet(0x0800, nil, fwIPv4(src, dst, 6, 0, b))
	}
	return fwEthernet(0x86dd, nil, fwIPv6(src, dst, nil, 0, 6, b))
}

// TestFirewallProgramSynLimit: slot 1 guards tcp 2222 (default allow) with at
// most 3 SYNs per 60 s and a 30 s ban, IPv6 counted per /64; slot 2 guards
// tcp 2223 with the same limit and no ban; 203.0.113.66 is on slot 1's drop
// list and 192.0.2.10 is trusted.
func TestFirewallProgramSynLimit(t *testing.T) {
	forEachFirewallProgram(t, testFirewallProgramSynLimit)
}

func testFirewallProgramSynLimit(t *testing.T, r *firewallTestRig) {
	const gen = 1
	r.protectPorts(gen, fwProtoTCP, 2222, 2222, 1)
	r.class(gen, 1, 1, false)
	r.limitedPolicy(gen, 1, false, 3, 60, 30, 64)
	r.source(gen, 1, "203.0.113.66/32", true)
	r.protectPorts(gen, fwProtoTCP, 2223, 2223, 2)
	r.class(gen, 2, 2, false)
	r.limitedPolicy(gen, 2, false, 3, 60, 0, 64)
	r.source(gen, 0, "192.0.2.10/32", false)
	r.setConfig(gen, fwCfgActive|fwCfgLoaded)
	r.setLog(1, 1<<40) // log every drop

	const syn, ack, synAck = 0x02, 0x10, 0x12
	send := func(src string, dport uint16, flags byte) uint32 {
		t.Helper()
		return r.run(fwTCP(src, "10.0.0.1", 40000, dport, flags), 0)
	}
	expect := func(what string, got, want uint32) {
		t.Helper()
		if got != want {
			t.Fatalf("%s: verdict %d, want %d", what, got, want)
		}
	}

	for i := 0; i < 3; i++ {
		expect("SYN within the limit", send("203.0.113.5", 2222, syn), fwVerdictPass)
	}
	expect("SYN over the limit", send("203.0.113.5", 2222, syn), fwVerdictDrop)
	if !r.banned(1, "203.0.113.5", 32) {
		t.Fatal("source over the limit was not banned")
	}
	expect("banned source, established segment", send("203.0.113.5", 2222, ack), fwVerdictDrop)
	expect("banned source, other policy", send("203.0.113.5", 2223, syn), fwVerdictPass)
	if got := r.lcounter(1, fwLcntRate); got != 1 {
		t.Fatalf("rate drops = %d, want 1", got)
	}
	if got := r.lcounter(1, fwLcntBan); got != 1 {
		t.Fatalf("ban drops = %d, want 1", got)
	}

	for i := 0; i < 10; i++ {
		expect("segments without a lone SYN do not count", send("203.0.113.6", 2222, ack), fwVerdictPass)
		expect("SYN-ACK does not count", send("203.0.113.6", 2222, synAck), fwVerdictPass)
		expect("trusted source", send("192.0.2.10", 2222, syn), fwVerdictPass)
	}
	expect("ACL drop list", send("203.0.113.66", 2222, syn), fwVerdictDrop)
	if r.lcounter(1, fwLcntRate) != 1 {
		t.Fatal("ACL drops counted as rate drops")
	}

	// IPv6 sources share a counter per /64.
	expect("v6 a", send("2001:db8:1::1", 2222, syn), fwVerdictPass)
	expect("v6 b", send("2001:db8:1::2", 2222, syn), fwVerdictPass)
	expect("v6 a again", send("2001:db8:1::1", 2222, syn), fwVerdictPass)
	expect("v6 b over the /64 limit", send("2001:db8:1::2", 2222, syn), fwVerdictDrop)
	expect("other /64", send("2001:db8:2::1", 2222, syn), fwVerdictPass)
	if !r.banned(1, "2001:db8:1::99", 64) {
		t.Fatal("the /64 was not banned")
	}

	// An expired ban is ignored.
	r.put("fw_ban", fwLimitKeyBytes(1, "203.0.113.9", 32), uint64(1))
	expect("expired ban", send("203.0.113.9", 2222, ack), fwVerdictPass)

	// Without ban_seconds only the SYNs over the limit are dropped.
	for i := 0; i < 3; i++ {
		expect("no-ban SYN within the limit", send("203.0.113.7", 2223, syn), fwVerdictPass)
	}
	expect("no-ban SYN over the limit", send("203.0.113.7", 2223, syn), fwVerdictDrop)
	expect("no-ban established segment", send("203.0.113.7", 2223, ack), fwVerdictPass)
	if r.banned(2, "203.0.113.7", 32) {
		t.Fatal("ban_seconds 0 banned the source")
	}

	// Every drop above was logged: rate x3 (v4, v6, no-ban), ban x1, ACL x1.
	reader, err := ringbuf.NewReader(r.coll.Maps["fw_events"])
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reasons := map[uint8]int{}
	var rateEvent []byte
	for {
		reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record.RawSample) < 56 {
			t.Fatalf("event of %d bytes", len(record.RawSample))
		}
		reason := record.RawSample[14]
		reasons[reason]++
		if reason == fwReasonRate && rateEvent == nil {
			rateEvent = append([]byte(nil), record.RawSample...)
		}
	}
	if reasons[fwReasonRate] != 3 || reasons[fwReasonBan] != 1 || reasons[fwReasonACL] != 1 {
		t.Fatalf("logged reasons = %v", reasons)
	}
	if binary.LittleEndian.Uint16(rateEvent[12:]) != 1 || rateEvent[15] != 4 || binary.BigEndian.Uint16(rateEvent[20:]) != 2222 ||
		!net.IP(rateEvent[24:28]).Equal(net.ParseIP("203.0.113.5")) || !net.IP(rateEvent[40:44]).Equal(net.ParseIP("10.0.0.1")) {
		t.Fatalf("rate event = %x", rateEvent)
	}
	if got := r.lcounter(0, fwLcntLogged); got != 5 {
		t.Fatalf("logged = %d, want 5", got)
	}

	// One event per second per CPU, no burst: a run of drops logs at most
	// one per CPU it lands on.
	r.setLog(1_000_000_000, 0)
	before := r.lcounter(0, fwLcntLogged)
	for i := 0; i < 20; i++ {
		expect("ACL drop", send("203.0.113.66", 2222, syn), fwVerdictDrop)
	}
	if delta := r.lcounter(0, fwLcntLogged) - before; delta < 1 || delta > uint64(runtime.NumCPU()) {
		t.Fatalf("rate-limited log wrote %d events for 20 drops", delta)
	}
	// Logging off.
	r.setLog(0, 0)
	before = r.lcounter(0, fwLcntLogged)
	expect("ACL drop", send("203.0.113.66", 2222, syn), fwVerdictDrop)
	if r.lcounter(0, fwLcntLogged) != before {
		t.Fatal("logged with the log off")
	}
	if r.lcounter(0, fwLcntLost) != 0 {
		t.Fatal("events lost to a full ring")
	}
}
