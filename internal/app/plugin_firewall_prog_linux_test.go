//go:build linux

package app

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Runs plugins/firewall/firewall.o with BPF_PROG_TEST_RUN against crafted
// frames. Map contents follow the layouts plugins/firewall/lib/compile.js
// writes; TestFirewallMapKeysMatchCompiler pins both to the same bytes.

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

type firewallTestRig struct {
	t    *testing.T
	coll *ebpf.Collection
	prog *ebpf.Program
}

func loadFirewallTestRig(t *testing.T) *firewallTestRig {
	t.Helper()
	path := filepath.Join(findRepoRoot(t), "plugins", "firewall", "firewall.o")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s not built (scripts/build-plugin-ebpf.sh): %v", path, err)
	}
	if os.Geteuid() != 0 {
		t.Skip("loading XDP programs needs root")
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
	return &firewallTestRig{t: t, coll: coll, prog: coll.Programs["xdp_firewall"]}
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

func (r *firewallTestRig) run(frame []byte, ingressIfindex uint32) uint32 {
	r.t.Helper()
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
	r := loadFirewallTestRig(t)
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
		{"ipv6 allowed", fwV6("2001:db8::5", "2001:db8:1::443", nil, 0, https), 0, fwVerdictPass},
		{"ipv6 default drop", fwV6("2001:db9::5", "2001:db8:1::443", nil, 0, https), 0, fwVerdictDrop},
		{"ipv6 trusted", fwV6("2001:db8:ffff::1", "2001:db8:1::443", nil, 0, https), 0, fwVerdictPass},
		{"ipv6 behind extension headers", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{0, 60}, 0, https), 0, fwVerdictDrop},
		{"ipv6 first fragment", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{44}, 0x0001, https), 0, fwVerdictDrop},
		{"ipv6 later fragment", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{44}, 0x0008, https), 0, fwVerdictPass},
		{"ipv6 too many extension headers", fwV6("2001:db9::5", "2001:db8:1::443", []uint8{0, 60, 60, 60, 60, 60, 60}, 0, https), 0, fwVerdictDrop},
		{"truncated", fwV4("8.8.8.8", "10.0.0.1", rdp)[:30], 0, fwVerdictPass},
	} {
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

	if got := r.counter(1, fwCntTrusted); got != 1 {
		t.Fatalf("slot 1 trusted = %d, want 1", got)
	}
	if got := r.counter(0, fwCntEvasive); got != 2 {
		t.Fatalf("evasive drops = %d, want 2", got)
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
	r := loadFirewallTestRig(t)
	if got := r.run(fwV4("8.8.8.8", "10.0.0.1", fwL4{6, 1, 22}), 0); got != fwVerdictPass {
		t.Fatalf("verdict = %d, want pass", got)
	}
	if r.coll.Maps["fw_cfg"] == nil {
		t.Fatal(errors.New("fw_cfg missing"))
	}
}
