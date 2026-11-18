//go:build linux

package app

import (
	"encoding/binary"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// BenchmarkFirewallProgram times plugins/firewall/firewall.o per packet with
// BPF_PROG_TEST_RUN: Repeat is b.N, so ns/op is the cost of one packet,
// including the empty tail call to the next plugin. The active generation
// holds a deployment-sized rule set (see installFirewallBenchRules); map
// contents use the layouts plugin_firewall_prog_linux_test.go pins against
// plugins/firewall/lib/compile.js. scripts/verify-plugin-release.sh
// (performance) gates the medians.
func BenchmarkFirewallProgram(b *testing.B) {
	if os.Getenv("VEER_RUN_XDP_PLUGIN_BENCH") != "1" {
		b.Skip("set VEER_RUN_XDP_PLUGIN_BENCH=1 to run the privileged XDP firewall benchmark")
	}
	if os.Geteuid() != 0 {
		b.Skip("root privileges are required")
	}
	r := loadFirewallBenchRig(b)
	const gen = 1
	r.installRules(gen)
	r.installSynLimitedPolicy(gen)

	ssh := fwL4{6, 40000, 22}
	vlanAllowed := fwEthernet(0x0800, []uint16{10}, fwIPv4("203.0.113.5", "10.0.0.1", ssh.proto, 0, fwL4Bytes(ssh)))
	for _, tc := range []struct {
		name   string
		frame  []byte
		loaded bool
		want   uint32
	}{
		// fw_cfg still zero: generation 0 is empty, so the port bitmap
		// lets the packet through before any LPM lookup.
		{"not_loaded", fwV4("8.8.8.8", "10.0.0.1", ssh), false, fwVerdictPass},
		{"unprotected_port_v4", fwV4("8.8.8.8", "10.0.0.1", fwL4{6, 40000, 80}), true, fwVerdictPass},
		{"allowed_source_v4", fwV4("203.0.113.5", "10.0.0.1", ssh), true, fwVerdictPass},
		{"dropped_source_v4", fwV4("8.8.8.8", "10.0.0.1", ssh), true, fwVerdictDrop},
		{"trusted_source_v4", fwV4("192.0.2.10", "10.0.0.1", ssh), true, fwVerdictPass},
		{"allowed_source_v6", fwV6("2001:db8:100::5", "2001:db8:1::22", nil, 0, ssh), true, fwVerdictPass},
		{"dropped_source_v6", fwV6("2001:db9::5", "2001:db8:1::22", nil, 0, ssh), true, fwVerdictDrop},
		{"vlan_allowed_source_v4", vlanAllowed, true, fwVerdictPass},
		// A SYN-limited policy: an established segment looks up the ban;
		// a SYN also counts in its window (the limit never trips here).
		{"limited_established_v4", fwTCP("203.0.113.5", "10.0.0.1", 40000, firewallBenchLimitedPort, 0x10), true, fwVerdictPass},
		{"limited_syn_v4", fwTCP("203.0.113.5", "10.0.0.1", 40000, firewallBenchLimitedPort, 0x02), true, fwVerdictPass},
	} {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			if tc.loaded {
				r.setConfig(b, gen, fwCfgActive|fwCfgLoaded)
			} else {
				r.setConfig(b, 0, 0)
			}
			// Each source probe passes or drops for one reason only: the
			// probes sit outside every generated prefix, and slot 1 drops
			// unlisted sources, so a missing allow or trusted entry flips
			// the verdict instead of timing the wrong path.
			if got := r.run(b, tc.frame, 1); got != tc.want {
				b.Fatalf("verdict = %d, want %d", got, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			if got := r.run(b, tc.frame, b.N); got != tc.want {
				b.Fatalf("timed verdict = %d, want %d", got, tc.want)
			}
		})
	}
}

type firewallBenchRig struct {
	b    *testing.B
	coll *ebpf.Collection
	prog *ebpf.Program
	bits map[uint32]uint64
}

func loadFirewallBenchRig(b *testing.B) *firewallBenchRig {
	b.Helper()
	path := filepath.Join(firewallBenchRepoRoot(b), "plugins", "firewall", "firewall.o")
	if _, err := os.Stat(path); err != nil {
		b.Fatalf("%s not built (scripts/build-plugin-ebpf.sh): %v", path, err)
	}
	_ = rlimit.RemoveMemlock()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		b.Fatalf("load spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		b.Fatalf("load firewall.o: %v", err)
	}
	b.Cleanup(coll.Close)
	prog := coll.Programs["xdp_firewall"]
	if prog == nil {
		b.Fatal("firewall.o has no xdp_firewall program")
	}
	return &firewallBenchRig{b: b, coll: coll, prog: prog, bits: map[uint32]uint64{}}
}

func firewallBenchRepoRoot(b *testing.B) string {
	b.Helper()
	dir, err := os.Getwd()
	if err != nil {
		b.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		next := filepath.Dir(dir)
		if next == dir {
			b.Fatal("repo root not found")
		}
		dir = next
	}
}

const firewallBenchLimitedPort = 9

// installSynLimitedPolicy adds slot and class 250 on tcp 9, default allow,
// with a SYN limit no benchmark run reaches.
func (r *firewallBenchRig) installSynLimitedPolicy(gen uint8) {
	const slot, class = 250, 250
	index := uint32(gen)*2048 + firewallBenchLimitedPort>>6
	var word uint64
	_ = r.coll.Maps["fw_port_bits"].Lookup(index, &word)
	word |= 1 << (firewallBenchLimitedPort & 63)
	r.put("fw_port_bits", index, word)
	r.put("fw_ports", fwPortKey(gen, fwProtoTCP, firewallBenchLimitedPort, 16), uint32(class))
	cls := make([]byte, 4)
	binary.LittleEndian.PutUint16(cls, slot)
	r.put("fw_class", uint32(gen)*1024+class, cls)
	r.put("fw_policy", uint32(gen)*256+slot, []byte{3, 0, 0, 0})
	limit := make([]byte, 32)
	binary.LittleEndian.PutUint32(limit, 0xffffffff)
	binary.LittleEndian.PutUint32(limit[4:], 3600)
	binary.LittleEndian.PutUint32(limit[8:], 60)
	limit[12] = 64
	for i := 16; i < 24; i++ {
		limit[i] = 0xff
	}
	r.put("fw_limit", uint32(gen)*256+slot, limit)
}

func (r *firewallBenchRig) put(mapName string, key, value any) {
	r.b.Helper()
	if err := r.coll.Maps[mapName].Put(key, value); err != nil {
		r.b.Fatalf("put %s: %v", mapName, err)
	}
}

// setConfig takes the sub-benchmark's b: put reports through the parent's.
func (r *firewallBenchRig) setConfig(b *testing.B, gen, flags uint32) {
	b.Helper()
	value := make([]byte, 8)
	binary.LittleEndian.PutUint32(value, gen)
	binary.LittleEndian.PutUint32(value[4:], flags)
	if err := r.coll.Maps["fw_cfg"].Put(uint32(0), value); err != nil {
		b.Fatalf("put fw_cfg: %v", err)
	}
}

func (r *firewallBenchRig) run(b *testing.B, frame []byte, repeat int) uint32 {
	b.Helper()
	ret, err := r.prog.Run(&ebpf.RunOptions{Data: frame, Repeat: uint32(repeat)})
	if err != nil {
		b.Fatalf("run: %v", err)
	}
	return ret
}

type firewallBenchPolicy struct {
	slot        uint16
	protos      []uint8
	ports       [][2]uint16
	dsts        []string // non-empty: scoped to these destinations
	defaultDrop bool
	sources     []string // allowed
	drops       []string // dropped
	random4     int      // generated IPv4 source prefixes, mostly allowed
	random6     int      // generated IPv6 source prefixes, mostly allowed
}

// installRules writes one generation the way compile.js would for a busy
// host: 32 policies over 35 single ports and 7 ranges (tcp, udp, tcp+udp,
// two scoped to destinations), 1534 IPv4 and 90 IPv6 source prefixes, 1002
// and 66 of them on policy 1 (tcp 22), and six trusted sources. The
// policies cover disjoint ports, so each is its own port class and its
// class id is its slot.
func (r *firewallBenchRig) installRules(gen uint8) {
	r.b.Helper()
	tcp := []uint8{fwProtoTCP}
	udp := []uint8{fwProtoUDP}
	both := []uint8{fwProtoTCP, fwProtoUDP}
	single := func(ports ...uint16) [][2]uint16 {
		out := make([][2]uint16, len(ports))
		for i, port := range ports {
			out[i] = [2]uint16{port, port}
		}
		return out
	}
	policies := []firewallBenchPolicy{
		{slot: 1, protos: tcp, ports: single(22), defaultDrop: true,
			sources: []string{"203.0.113.0/24", "2001:db8:100::/48"},
			drops:   []string{"203.0.113.66/32", "2001:db8:100:bad::/64"},
			random4: 1000, random6: 64},
		{slot: 2, protos: tcp, ports: single(21), defaultDrop: true, random4: 16},
		{slot: 3, protos: tcp, ports: single(25, 465, 587), defaultDrop: true, random4: 24},
		{slot: 4, protos: both, ports: single(53), dsts: []string{"10.0.0.53/32", "2001:db8:1::53/128"}, defaultDrop: true, random4: 16, random6: 4},
		{slot: 5, protos: tcp, ports: single(110, 143), defaultDrop: true, random4: 12},
		{slot: 6, protos: tcp, ports: single(389, 636), defaultDrop: true, random4: 8},
		{slot: 7, protos: tcp, ports: single(443), dsts: []string{"10.0.1.0/24", "2001:db8:1:443::/64"}, defaultDrop: true, random4: 32, random6: 8},
		{slot: 8, protos: udp, ports: single(500, 4500), defaultDrop: true, random4: 16},
		{slot: 9, protos: tcp, ports: single(993, 995), defaultDrop: true, random4: 12},
		{slot: 10, protos: tcp, ports: single(1433), defaultDrop: true, random4: 8},
		{slot: 11, protos: udp, ports: single(1194), defaultDrop: true, random4: 24},
		{slot: 12, protos: tcp, ports: single(1521), defaultDrop: true, random4: 8},
		{slot: 13, protos: both, ports: single(2049, 111), defaultDrop: true, random4: 8},
		{slot: 14, protos: tcp, ports: single(3306, 33060), defaultDrop: true, random4: 16},
		{slot: 15, protos: both, ports: single(3389), defaultDrop: true, random4: 24, random6: 4},
		{slot: 16, protos: tcp, ports: single(5432), defaultDrop: true, random4: 16},
		{slot: 17, protos: tcp, ports: [][2]uint16{{5900, 5910}}, defaultDrop: true, random4: 12},
		{slot: 18, protos: tcp, ports: single(6379), defaultDrop: true, random4: 8},
		{slot: 19, protos: tcp, ports: single(8006), defaultDrop: true, random4: 16, random6: 4},
		{slot: 20, protos: tcp, ports: single(8080), defaultDrop: true, random4: 16},
		{slot: 21, protos: tcp, ports: single(8443), random4: 32}, // default allow, mostly a drop list
		{slot: 22, protos: tcp, ports: [][2]uint16{{9000, 9099}}, defaultDrop: true, random4: 16},
		{slot: 23, protos: tcp, ports: single(9200, 9300), defaultDrop: true, random4: 8},
		{slot: 24, protos: tcp, ports: [][2]uint16{{10000, 10999}}, defaultDrop: true, random4: 24},
		{slot: 25, protos: tcp, ports: single(11211), defaultDrop: true, random4: 8},
		{slot: 26, protos: udp, ports: [][2]uint16{{27015, 27030}}, random4: 48}, // default allow
		{slot: 27, protos: tcp, ports: single(25565), random4: 32},               // default allow
		{slot: 28, protos: udp, ports: single(51820), defaultDrop: true, random4: 16, random6: 4},
		{slot: 29, protos: tcp, ports: single(6443, 10250), defaultDrop: true, random4: 16},
		{slot: 30, protos: tcp, ports: [][2]uint16{{2379, 2380}}, defaultDrop: true, random4: 8},
		{slot: 31, protos: tcp, ports: [][2]uint16{{7000, 7999}}, defaultDrop: true, random4: 16},
		{slot: 32, protos: both, ports: [][2]uint16{{60000, 60100}}, defaultDrop: true, random4: 16},
	}
	// No generated prefix may cover a probe source: each probe's verdict
	// must come from the entry the benchmark case names.
	avoid := []net.IP{
		net.ParseIP("8.8.8.8"), net.ParseIP("203.0.113.5"), net.ParseIP("192.0.2.10"),
		net.ParseIP("2001:db8:100::5"), net.ParseIP("2001:db9::5"),
	}
	rng := rand.New(rand.NewSource(1))
	for _, p := range policies {
		r.installPolicy(gen, p, rng, avoid)
	}
	for index, word := range r.bits {
		r.put("fw_port_bits", index, word)
	}
	for _, cidr := range []string{
		"192.0.2.10/32", "192.0.2.11/32", "198.51.100.0/29", "100.64.0.0/26",
		"2001:db8:ffff::1/128", "2001:db8:fffe::/64",
	} {
		r.source(gen, 0, cidr, false)
	}
}

func (r *firewallBenchRig) installPolicy(gen uint8, p firewallBenchPolicy, rng *rand.Rand, avoid []net.IP) {
	r.b.Helper()
	class := uint32(p.slot)
	for _, proto := range p.protos {
		for _, span := range p.ports {
			for _, prefix := range firewallBenchPortPrefixes(span[0], span[1]) {
				r.put("fw_ports", fwPortKey(gen, proto, prefix.port, prefix.bits), class)
			}
			for port := uint32(span[0]); port <= uint32(span[1]); port++ {
				r.bits[uint32(gen)*2048+uint32(proto)*1024+port>>6] |= 1 << (port & 63)
			}
		}
	}
	classValue := make([]byte, 4)
	if len(p.dsts) == 0 {
		binary.LittleEndian.PutUint16(classValue, p.slot)
	} else {
		classValue[2] = 1
	}
	r.put("fw_class", uint32(gen)*1024+class, classValue)
	for _, cidr := range p.dsts {
		key := fwAddrKey(gen, p.slot, cidr)
		name := "fw_dst4"
		if len(key) == 24 {
			name = "fw_dst6"
		}
		r.put(name, key, uint32(p.slot))
	}
	policy := []byte{1, 0, 0, 0}
	if p.defaultDrop {
		policy[1] = 1
	}
	r.put("fw_policy", uint32(gen)*256+uint32(p.slot), policy)

	seen := map[string]bool{}
	for _, cidr := range p.sources {
		seen[cidr] = true
		r.source(gen, p.slot, cidr, false)
	}
	for _, cidr := range p.drops {
		seen[cidr] = true
		r.source(gen, p.slot, cidr, true)
	}
	for _, v6 := range []bool{false, true} {
		want := p.random4
		if v6 {
			want = p.random6
		}
		for added := 0; added < want; {
			cidr := firewallBenchRandomPrefix(rng, v6)
			if seen[cidr] || firewallBenchCovers(cidr, avoid) {
				continue
			}
			seen[cidr] = true
			// A default-drop policy mostly lists allowed sources, a
			// default-allow one mostly dropped sources.
			drop := rng.Intn(10) == 0
			if !p.defaultDrop {
				drop = !drop
			}
			r.source(gen, p.slot, cidr, drop)
			added++
		}
	}
}

func (r *firewallBenchRig) source(gen uint8, slot uint16, cidr string, drop bool) {
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

type firewallBenchPortPrefix struct {
	port uint16
	bits int
}

// firewallBenchPortPrefixes splits [lo, hi] into aligned power-of-two
// blocks, as portPrefixes in compile.js does.
func firewallBenchPortPrefixes(lo, hi uint16) []firewallBenchPortPrefix {
	var out []firewallBenchPortPrefix
	for a, b := uint32(lo), uint32(hi); a <= b; {
		size := uint32(1)
		for size < 65536 && a%(size*2) == 0 && a+size*2-1 <= b {
			size *= 2
		}
		bits := 0
		for uint32(1)<<bits < size {
			bits++
		}
		out = append(out, firewallBenchPortPrefix{port: uint16(a), bits: 16 - bits})
		a += size
	}
	return out
}

// firewallBenchRandomPrefix returns a public-looking prefix with a length
// mix typical of allow lists: mostly /24 and host routes for IPv4, /32 to
// /64 and hosts for IPv6.
func firewallBenchRandomPrefix(rng *rand.Rand, v6 bool) string {
	if v6 {
		ip := make(net.IP, 16)
		binary.BigEndian.PutUint64(ip, rng.Uint64())
		binary.BigEndian.PutUint64(ip[8:], rng.Uint64())
		ip[0] = 0x20 | ip[0]&0x1f // 2000::/3
		lengths := []int{29, 32, 32, 36, 40, 44, 48, 48, 48, 56, 64, 64, 128}
		mask := net.CIDRMask(lengths[rng.Intn(len(lengths))], 128)
		return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
	}
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, rng.Uint32())
	ip[0] = 1 + byte(rng.Intn(223)) // 1.0.0.0 - 223.255.255.255
	lengths := []int{12, 16, 18, 20, 22, 23, 24, 24, 24, 24, 24, 26, 28, 29, 32, 32, 32, 32}
	mask := net.CIDRMask(lengths[rng.Intn(len(lengths))], 32)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

func firewallBenchCovers(cidr string, addrs []net.IP) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	for _, addr := range addrs {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}
