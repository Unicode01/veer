//go:build linux

package app

import (
	"errors"
	"net"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func hairpinTestIPv4(t *testing.T, text string) uint32 {
	t.Helper()
	ip := net.ParseIP(text).To4()
	if ip == nil {
		t.Fatalf("invalid IPv4 %q", text)
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// hairpinTestNoSource fails the test if a source address is resolved: only
// transparent forwards need one.
func hairpinTestNoSource(t *testing.T) func(preparedKernelRule) (uint32, error) {
	return func(item preparedKernelRule) (uint32, error) {
		t.Fatalf("source address resolved for full NAT forward %d", item.rule.ID)
		return 0, nil
	}
}

func hairpinTestEgressNATItem() preparedKernelRule {
	return preparedKernelRule{
		rule:      Rule{ID: 1, Protocol: "tcp"},
		inIfIndex: 20,
		spec:      kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		key:       tcRuleKeyV4{IfIndex: 20, Proto: unix.IPPROTO_TCP},
		value:     tcRuleValueV4{RuleID: 1, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT},
	}
}

func hairpinTestForwardItem(t *testing.T, id int64, inAddr string, port uint16, flags uint16) preparedKernelRule {
	t.Helper()
	dst := uint32(0)
	if inAddr != "" {
		dst = hairpinTestIPv4(t, inAddr)
	}
	return preparedKernelRule{
		rule:      Rule{ID: id, Protocol: "tcp", InInterface: "uplink0", OutInterface: "vmbr1", OutIP: "192.0.2.11"},
		inIfIndex: 10,
		spec:      kernelPreparedRuleSpec{Family: ipFamilyIPv4},
		key:       tcRuleKeyV4{IfIndex: 10, DstAddr: dst, DstPort: port, Proto: unix.IPPROTO_TCP},
		value: tcRuleValueV4{
			RuleID:      uint32(id),
			BackendAddr: hairpinTestIPv4(t, "192.0.2.11"),
			BackendPort: 22,
			Flags:       flags,
			OutIfIndex:  30,
			NATAddr:     hairpinTestIPv4(t, "192.0.2.1"),
		},
	}
}

func TestBuildKernelHairpinEntriesListsHostForwardsForEgressNATGuests(t *testing.T) {
	public := hairpinTestIPv4(t, "203.0.113.5")
	forward := hairpinTestForwardItem(t, 2, "203.0.113.5", 65001, kernelRuleFlagFullNAT)
	noAddrs := func(int) []uint32 { t.Fatal("addresses read for a forward on a fixed address"); return nil }

	// Without egress NAT no guest can hairpin.
	if entries, notes := buildKernelHairpinEntries([]preparedKernelRule{forward}, hairpinTestNoSource(t), noAddrs); len(entries) != 0 || len(notes) != 0 {
		t.Fatalf("entries without egress NAT = %v, notes %v; want none", entries, notes)
	}

	passthrough := hairpinTestForwardItem(t, 3, "203.0.113.5", 65003, kernelRuleFlagPassthrough)
	drop := hairpinTestForwardItem(t, 4, "203.0.113.5", 65004, kernelRuleFlagFullNAT|kernelRuleFlagDrop)
	ipv6 := hairpinTestForwardItem(t, 5, "203.0.113.5", 65005, kernelRuleFlagFullNAT)
	ipv6.spec.Family = ipFamilyIPv6
	entries, notes := buildKernelHairpinEntries([]preparedKernelRule{hairpinTestEgressNATItem(), forward, passthrough, drop, ipv6}, hairpinTestNoSource(t), noAddrs)
	if len(notes) != 0 {
		t.Fatalf("notes = %v, want none", notes)
	}
	wantValue := forward.value
	wantValue.HairpinInIfIndex = 10
	want := map[tcHairpinKeyV4]tcRuleValueV4{
		{DstAddr: public, DstPort: 65001, Proto: unix.IPPROTO_TCP}: wantValue,
	}
	if !reflect.DeepEqual(entries, want) {
		t.Fatalf("entries = %+v, want only the full NAT forward %+v, naming its inbound interface", entries, want)
	}
}

func TestBuildKernelHairpinEntriesExpandsAnyAddressForwards(t *testing.T) {
	forward := hairpinTestForwardItem(t, 2, "", 65001, kernelRuleFlagFullNAT)
	first, second := hairpinTestIPv4(t, "203.0.113.5"), hairpinTestIPv4(t, "203.0.113.6")
	entries, _ := buildKernelHairpinEntries([]preparedKernelRule{hairpinTestEgressNATItem(), forward}, hairpinTestNoSource(t), func(ifindex int) []uint32 {
		if ifindex != 10 {
			t.Fatalf("addresses read for ifindex %d, want the inbound interface 10", ifindex)
		}
		return []uint32{first, second}
	})
	if len(entries) != 2 {
		t.Fatalf("entries = %+v, want one per address of the inbound interface", entries)
	}
	for _, addr := range []uint32{first, second} {
		if _, ok := entries[tcHairpinKeyV4{DstAddr: addr, DstPort: 65001, Proto: unix.IPPROTO_TCP}]; !ok {
			t.Fatalf("entries = %+v, missing address %08x", entries, addr)
		}
	}
}

func TestBuildKernelHairpinEntriesSourceNATsTransparentForwards(t *testing.T) {
	transparent := hairpinTestForwardItem(t, 2, "203.0.113.5", 65001, 0)
	transparent.value.NATAddr = 0
	unusable := hairpinTestForwardItem(t, 3, "203.0.113.5", 65002, 0)
	unusable.value.NATAddr = 0
	gateway := hairpinTestIPv4(t, "192.0.2.1")
	sourceOf := func(item preparedKernelRule) (uint32, error) {
		if item.rule.ID == 3 {
			return 0, errors.New("no address on the outbound interface")
		}
		return gateway, nil
	}

	entries, notes := buildKernelHairpinEntries([]preparedKernelRule{hairpinTestEgressNATItem(), transparent, unusable}, sourceOf, nil)
	got, ok := entries[tcHairpinKeyV4{DstAddr: hairpinTestIPv4(t, "203.0.113.5"), DstPort: 65001, Proto: unix.IPPROTO_TCP}]
	if !ok {
		t.Fatalf("entries = %+v, notes %v; want the transparent forward", entries, notes)
	}
	if got.Flags&kernelRuleFlagFullNAT == 0 || got.NATAddr != gateway {
		t.Fatalf("hairpin value = %+v, want full NAT from the outbound interface's address", got)
	}
	if got.RuleID != 2 || got.BackendAddr != transparent.value.BackendAddr || got.OutIfIndex != transparent.value.OutIfIndex {
		t.Fatalf("hairpin value = %+v, want the forward's rule, backend and outbound interface", got)
	}
	if len(entries) != 1 || len(notes) != 1 {
		t.Fatalf("entries = %+v, notes %v; want the forward with no usable source address left out and noted", entries, notes)
	}
}

func TestKernelHairpinAddrsGatesOnFewAddresses(t *testing.T) {
	entries := make(map[tcHairpinKeyV4]tcRuleValueV4)
	for i := 0; i < 3; i++ {
		entries[tcHairpinKeyV4{DstAddr: 300 - uint32(i), DstPort: 1}] = tcRuleValueV4{}
		entries[tcHairpinKeyV4{DstAddr: 300 - uint32(i), DstPort: 2}] = tcRuleValueV4{}
	}
	if got := kernelHairpinAddrs(entries); got.Count != 3 || got.Addrs[0] != 298 || got.Addrs[2] != 300 || got.Addrs[3] != 0 {
		t.Fatalf("addrs = %+v, want three sorted distinct addresses", got)
	}
	for i := uint32(0); i < kernelHairpinAddrSlots+2; i++ {
		entries[tcHairpinKeyV4{DstAddr: 1000 + i}] = tcRuleValueV4{}
	}
	// More addresses than slots: the count says so and the programs look up
	// every egress NAT packet's destination.
	if got := kernelHairpinAddrs(entries); got.Count != 3+kernelHairpinAddrSlots+2 {
		t.Fatalf("addrs count = %d, want every distinct address counted", got.Count)
	}
}

func TestKernelTCIfindexHintsMarkEgressNATInterfacesForHairpin(t *testing.T) {
	hints := make(kernelTCIfindexHints)
	if err := hints.addPreparedRules([]preparedKernelRule{hairpinTestEgressNATItem(), hairpinTestForwardItem(t, 2, "203.0.113.5", 65001, kernelRuleFlagFullNAT)}); err != nil {
		t.Fatalf("addPreparedRules() error = %v", err)
	}
	if hints[20]&kernelTCIfindexHintHairpin == 0 {
		t.Fatalf("egress NAT interface hints = %#x, want the hairpin hint", hints[20])
	}
	if hints[10]&kernelTCIfindexHintHairpin != 0 {
		t.Fatalf("forward interface hints = %#x, want no hairpin hint", hints[10])
	}
}
