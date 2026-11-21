//go:build linux

package app

import (
	"encoding/binary"
	"math/rand"
	"os"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
)

// BenchmarkFirewallProgramStages times the firewall 1.1 stages per packet,
// like BenchmarkFirewallProgram and on top of the same deployment-sized rule
// set: connection tracking (a catch-all policy with the reply of a tracked
// connection, and without), blocklist sets of 1000 prefixes, bogon sources,
// reverse-path checks, an ICMP policy, policy source sets, and the
// tc_egress program that records connections.
//
// The reverse-path case needs a route lookup on an interface with
// forwarding on; VEER_FIREWALL_BENCH_IFINDEX names one (run the benchmark in
// a namespace with net.ipv4.ip_forward=1, a dummy interface and a default
// route through it), or the case is left out.
func BenchmarkFirewallProgramStages(b *testing.B) {
	if os.Getenv("VEER_RUN_XDP_PLUGIN_BENCH") != "1" {
		b.Skip("set VEER_RUN_XDP_PLUGIN_BENCH=1 to run the privileged XDP firewall benchmark")
	}
	if os.Geteuid() != 0 {
		b.Skip("root privileges are required")
	}
	r := loadFirewallBenchRig(b)
	const gen = 1
	r.installRules(gen)
	egress := r.coll.Programs["tc_firewall_egress"]
	if egress == nil {
		b.Fatal("firewall.o has no tc_firewall_egress program")
	}

	// Catch-all policy: slot and class 240, default drop.
	const catchAll = 240
	r.benchClass(gen, catchAll, catchAll)
	r.put("fw_policy", uint32(gen)*256+catchAll, []byte{1, 1, 0, 0})
	// ICMP echo requests: slot and class 241, default drop, 203.0.113.0/24 allowed.
	const icmp = 241
	r.put("fw_ports", fwPortKey(gen, fwProtoICMP, 8<<8, 8), uint32(icmp))
	r.benchClass(gen, icmp, icmp)
	r.put("fw_policy", uint32(gen)*256+icmp, []byte{1, 1, 0, 0})
	r.source(gen, icmp, "203.0.113.0/24", false)
	// tcp 2300: slot and class 242, default drop, sources by sets 11 (miss)
	// then 12 (hit).
	const sets = 242
	r.benchPort(gen, fwProtoTCP, 2300, sets)
	r.benchClass(gen, sets, sets)
	r.put("fw_policy", uint32(gen)*256+sets, []byte{1, 1, 0, 0})
	px := make([]byte, 40)
	px[1] = 2
	binary.LittleEndian.PutUint16(px[8:], 11)
	binary.LittleEndian.PutUint16(px[10:], 12)
	r.put("fw_pext", uint32(gen)*256+sets, px)
	r.put("fw_sets", fwSetKey(12, "203.0.113.0/24"), fwSetValue(0, 1))
	// Blocklist set 10: 1000 random prefixes plus 198.51.100.66; bogons.
	rng := rand.New(rand.NewSource(5))
	for i := 0; i < 1000; i++ {
		r.put("fw_sets", fwSetKey(10, firewallBenchRandomPrefix(rng, i%10 == 9)), fwSetValue(0, 1))
	}
	r.put("fw_sets", fwSetKey(10, "198.51.100.66/32"), fwSetValue(0, 1))
	r.put("fw_sets", fwSetKey(11, "100.100.0.0/16"), fwSetValue(0, 1))
	for _, cidr := range []string{"0.0.0.0/8", "127.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "203.0.113.0/24", "224.0.0.0/3",
		"10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::/128", "::1/128", "2001:db8::/32", "fc00::/7", "ff00::/8"} {
		r.put("fw_sets", fwSetKey(fwSetBogon, cidr), fwSetValue(0, 1))
	}
	// Tracked connections: 10.0.0.1:40000 -> 198.51.100.20:443 and its IPv6
	// twin, plus the one the egress cases refresh.
	tracked := make([]byte, 16)
	binary.LittleEndian.PutUint64(tracked, monotonicNS(b)+3600e9) // never refreshed during the run
	r.put("fw_ct", fwCTKey(fwProtoTCP, "10.0.0.1", 40000, "198.51.100.20", 443), tracked)
	r.put("fw_ct", fwCTKey(fwProtoTCP, "2001:db8:1::22", 40000, "2001:db8:5::20", 443), tracked)
	r.put("fw_ct", fwCTKey(fwProtoTCP, "10.0.0.1", 40001, "198.51.100.20", 443), tracked)

	ifindex := 0
	if v, err := strconv.Atoi(os.Getenv("VEER_FIREWALL_BENCH_IFINDEX")); err == nil && v > 0 {
		ifindex = v
	}
	reply4 := fwTCP("198.51.100.20", "10.0.0.1", 443, 40000, 0x10)
	reply6 := fwTCP("2001:db8:5::20", "2001:db8:1::22", 443, 40000, 0x10)
	unprotected := fwTCP("8.8.8.8", "10.0.0.1", 40000, 80, 0x10)
	for _, tc := range []struct {
		name    string
		flags   uint32
		any     uint16
		blocks  []uint16
		frame   []byte
		egress  bool
		ifindex bool
		want    uint32
	}{
		{name: "base_unprotected_v4", frame: unprotected, want: fwVerdictPass},
		{name: "ct_on_unprotected_v4", flags: fwGCT, frame: unprotected, want: fwVerdictPass},
		{name: "ct_established_v4", flags: fwGCT, any: catchAll, frame: reply4, want: fwVerdictPass},
		{name: "ct_established_v6", flags: fwGCT, any: catchAll, frame: reply6, want: fwVerdictPass},
		{name: "ct_untracked_drop_v4", flags: fwGCT, any: catchAll, frame: fwTCP("198.51.100.21", "10.0.0.1", 443, 40000, 0x10), want: fwVerdictDrop},
		{name: "catchall_no_ct_drop_v4", any: catchAll, frame: reply4, want: fwVerdictDrop},
		{name: "blocklist_pass_v4", blocks: []uint16{10}, frame: unprotected, want: fwVerdictPass},
		{name: "blocklist_drop_v4", blocks: []uint16{10}, frame: fwTCP("198.51.100.66", "10.0.0.1", 40000, 80, 0x10), want: fwVerdictDrop},
		{name: "blocklist_pass_v6", blocks: []uint16{10}, frame: fwTCP("2001:db8:5::20", "2001:db8:1::22", 40000, 80, 0x10), want: fwVerdictPass},
		{name: "bogon_pass_v4", flags: fwGBogon, frame: unprotected, want: fwVerdictPass},
		{name: "bogon_drop_v4", flags: fwGBogon, frame: fwTCP("10.1.2.3", "10.0.0.1", 40000, 80, 0x10), want: fwVerdictDrop},
		{name: "bad_flags_pass_v4", flags: fwGBadFlags, frame: unprotected, want: fwVerdictPass},
		{name: "urpf_strict_pass_v4", flags: 32, frame: unprotected, ifindex: true, want: fwVerdictPass},
		{name: "urpf_loose_pass_v4", flags: 16, frame: unprotected, ifindex: true, want: fwVerdictPass},
		{name: "icmp_allowed_v4", flags: fwGProto, frame: fwICMP("203.0.113.9", "10.0.0.1", 8, 0, nil), want: fwVerdictPass},
		{name: "icmp_dropped_v4", flags: fwGProto, frame: fwICMP("8.8.8.8", "10.0.0.1", 8, 0, nil), want: fwVerdictDrop},
		{name: "source_set_allowed_v4", frame: fwTCP("203.0.113.5", "10.0.0.1", 40000, 2300, 0x02), want: fwVerdictPass},
		{name: "egress_ct_off", egress: true, frame: fwTCP("10.0.0.1", "198.51.100.20", 40001, 443, 0x10)},
		{name: "egress_tracked_v4", flags: fwGCT, egress: true, frame: fwTCP("10.0.0.1", "198.51.100.20", 40001, 443, 0x10)},
		{name: "egress_untracked_ack_v4", flags: fwGCT, egress: true, frame: fwTCP("10.0.0.1", "198.51.100.20", 40002, 443, 0x10)},
	} {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			if tc.ifindex && ifindex == 0 {
				b.Skip("VEER_FIREWALL_BENCH_IFINDEX is not set")
			}
			r.setConfig(b, gen, fwCfgActive|fwCfgLoaded)
			value := make([]byte, 16)
			binary.LittleEndian.PutUint32(value, tc.flags)
			binary.LittleEndian.PutUint16(value[4:], tc.any)
			value[6] = uint8(len(tc.blocks))
			for i, id := range tc.blocks {
				binary.LittleEndian.PutUint16(value[8+2*i:], id)
			}
			if err := r.coll.Maps["fw_gcfg"].Put(uint32(gen), value); err != nil {
				b.Fatal(err)
			}
			opts := &ebpf.RunOptions{Data: tc.frame, Repeat: 1}
			prog := r.prog
			if tc.egress {
				prog = egress
				opts.Context = make([]byte, 192)
			} else if tc.ifindex {
				ctx := make([]byte, 24)
				binary.LittleEndian.PutUint32(ctx[4:], uint32(len(tc.frame)))
				binary.LittleEndian.PutUint32(ctx[12:], uint32(ifindex))
				opts.Context = ctx
			}
			ret, err := prog.Run(opts)
			if err != nil {
				b.Fatalf("run: %v", err)
			}
			if !tc.egress && ret != tc.want {
				b.Fatalf("verdict = %d, want %d", ret, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			opts.Repeat = uint32(b.N)
			if _, err := prog.Run(opts); err != nil {
				b.Fatalf("timed run: %v", err)
			}
		})
	}
}

func (r *firewallBenchRig) benchClass(gen uint8, id uint32, slot uint16) {
	value := make([]byte, 4)
	binary.LittleEndian.PutUint16(value, slot)
	r.put("fw_class", uint32(gen)*1024+id, value)
}

func (r *firewallBenchRig) benchPort(gen, proto uint8, port uint16, class uint32) {
	index := uint32(gen)*2048 + uint32(proto)*1024 + uint32(port)>>6
	var word uint64
	_ = r.coll.Maps["fw_port_bits"].Lookup(index, &word)
	word |= 1 << (port & 63)
	r.put("fw_port_bits", index, word)
	r.put("fw_ports", fwPortKey(gen, proto, port, 16), class)
}
