//go:build linux

package app

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type orphanFlowV4TestFixture struct {
	xdp        bool
	rules      *ebpf.Map
	flows      *ebpf.Map
	nat        *ebpf.Map
	refs       kernelRuntimeMapRefs
	ruleKey    tcRuleKeyV4
	ruleValue  tcRuleValueV4
	frontKey   tcFlowKeyV4
	frontValue tcFlowValueV4
	replyKey   tcFlowKeyV4
	natKey     tcNATPortKeyV4
}

func newOrphanFlowV4TestFixture(t *testing.T, xdp bool, bank string, egressNAT bool) orphanFlowV4TestFixture {
	t.Helper()
	ruleValueSize := uint32(unsafe.Sizeof(tcRuleValueV4{}))
	flowValueSize := uint32(unsafe.Sizeof(tcFlowValueV4{}))
	if xdp {
		ruleValueSize = uint32(unsafe.Sizeof(xdpRuleValueV4{}))
		flowValueSize = uint32(unsafe.Sizeof(xdpFlowValueV4{}))
	}
	rules := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_rule_v4",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcRuleKeyV4{})),
		ValueSize:  ruleValueSize,
		MaxEntries: 16,
	})
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_flow_v4",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  flowValueSize,
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_nat_v4",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})

	ruleKey := tcRuleKeyV4{
		IfIndex: 5,
		DstAddr: 0x0a000101,
		DstPort: 443,
		Proto:   unix.IPPROTO_UDP,
	}
	ruleValue := tcRuleValueV4{
		RuleID:      101,
		BackendAddr: 0x0a000202,
		BackendPort: 8443,
		Flags:       kernelRuleFlagFullNAT,
		OutIfIndex:  9,
		NATAddr:     0x0a000303,
		Revision:    10101,
	}
	if egressNAT {
		ruleValue.Flags |= kernelRuleFlagEgressNAT
	}
	putOrphanFlowTestRuleV4(t, rules, xdp, ruleKey, ruleValue)

	frontKey := tcFlowKeyV4{
		IfIndex: 5,
		SrcAddr: 0x0a000404,
		DstAddr: ruleKey.DstAddr,
		SrcPort: 55000,
		DstPort: ruleKey.DstPort,
		Proto:   ruleKey.Proto,
	}
	frontValue := tcFlowValueV4{
		RuleID:       ruleValue.RuleID,
		FrontAddr:    frontKey.DstAddr,
		ClientAddr:   frontKey.SrcAddr,
		NATAddr:      ruleValue.NATAddr,
		InIfIndex:    frontKey.IfIndex,
		FrontPort:    frontKey.DstPort,
		ClientPort:   frontKey.SrcPort,
		NATPort:      32001,
		Flags:        kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry | kernelFlowFlagCounted,
		LastSeenNS:   0,
		RuleRevision: ruleValue.Revision,
		SessionID:    0x101010101,
	}
	putOrphanFlowTestValueV4(t, flows, xdp, frontKey, frontValue)

	replyKey := tcFlowKeyV4{
		IfIndex: ruleValue.OutIfIndex,
		SrcAddr: ruleValue.BackendAddr,
		DstAddr: frontValue.NATAddr,
		SrcPort: ruleValue.BackendPort,
		DstPort: frontValue.NATPort,
		Proto:   frontKey.Proto,
	}
	if egressNAT {
		replyKey.SrcAddr = frontValue.FrontAddr
		replyKey.SrcPort = frontValue.FrontPort
	}
	natKey := tcNATPortKeyV4{
		IfIndex: ruleValue.OutIfIndex,
		NATAddr: frontValue.NATAddr,
		NATPort: frontValue.NATPort,
		Proto:   frontKey.Proto,
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: ruleValue.RuleID, SessionID: frontValue.SessionID}); err != nil {
		t.Fatalf("put IPv4 NAT reservation: %v", err)
	}

	refs := kernelRuntimeMapRefs{rulesV4: rules}
	if bank == "old" {
		refs.flowsOldV4 = flows
		refs.natOldV4 = nat
	} else {
		refs.flowsV4 = flows
		refs.natV4 = nat
	}
	return orphanFlowV4TestFixture{
		xdp:        xdp,
		rules:      rules,
		flows:      flows,
		nat:        nat,
		refs:       refs,
		ruleKey:    ruleKey,
		ruleValue:  ruleValue,
		frontKey:   frontKey,
		frontValue: frontValue,
		replyKey:   replyKey,
		natKey:     natKey,
	}
}

func (fixture orphanFlowV4TestFixture) snapshot(t *testing.T) kernelFlowLiveStateSnapshot {
	t.Helper()
	var (
		live kernelFlowLiveStateSnapshot
		err  error
	)
	if fixture.xdp {
		live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(fixture.refs, true)
	} else {
		live, err = snapshotKernelLiveStateFromRuntimeMapRefs(fixture.refs, true)
	}
	if err != nil {
		t.Fatalf("snapshot IPv4 orphan flow fixture: %v", err)
	}
	return live
}

func (fixture orphanFlowV4TestFixture) putFront(t *testing.T, value tcFlowValueV4) {
	t.Helper()
	putOrphanFlowTestValueV4(t, fixture.flows, fixture.xdp, fixture.frontKey, value)
}

func (fixture orphanFlowV4TestFixture) putReply(t *testing.T) {
	t.Helper()
	replyValue := fixture.frontValue
	replyValue.Flags &^= kernelFlowFlagFrontEntry
	putOrphanFlowTestValueV4(t, fixture.flows, fixture.xdp, fixture.replyKey, replyValue)
}

func (fixture *orphanFlowV4TestFixture) makeFullCone(t *testing.T) {
	t.Helper()
	if err := fixture.flows.Delete(fixture.frontKey); err != nil {
		t.Fatalf("remove ordinary IPv4 front before full-cone setup: %v", err)
	}
	if err := fixture.rules.Delete(fixture.ruleKey); err != nil {
		t.Fatalf("remove ordinary IPv4 rule before full-cone setup: %v", err)
	}
	fixture.ruleKey.DstAddr = 0
	fixture.ruleKey.DstPort = 0
	fixture.ruleValue.Flags |= kernelRuleFlagFullCone
	putOrphanFlowTestRuleV4(t, fixture.rules, fixture.xdp, fixture.ruleKey, fixture.ruleValue)
	fixture.frontKey.DstAddr = 0
	fixture.frontKey.DstPort = 0
	fixture.frontValue.FrontAddr = 0
	fixture.frontValue.FrontPort = 0
	fixture.frontValue.Flags |= kernelFlowFlagFullCone
	fixture.replyKey.SrcAddr = 0
	fixture.replyKey.SrcPort = 0
	fixture.putFront(t, fixture.frontValue)
}

func putOrphanFlowTestValueV4(t *testing.T, flows *ebpf.Map, xdp bool, key tcFlowKeyV4, value tcFlowValueV4) {
	t.Helper()
	if !xdp {
		if err := flows.Put(key, value); err != nil {
			t.Fatalf("put TC IPv4 flow: %v", err)
		}
		return
	}
	raw := xdpFlowValueV4{
		RuleID:           value.RuleID,
		FrontAddr:        value.FrontAddr,
		ClientAddr:       value.ClientAddr,
		NATAddr:          value.NATAddr,
		InIfIndex:        value.InIfIndex,
		FrontPort:        value.FrontPort,
		ClientPort:       value.ClientPort,
		NATPort:          value.NATPort,
		Flags:            value.Flags,
		LastSeenNS:       value.LastSeenNS,
		FrontCloseSeenNS: value.FrontCloseSeenNS,
		RuleRevision:     value.RuleRevision,
		SessionID:        value.SessionID,
	}
	if err := flows.Put(key, raw); err != nil {
		t.Fatalf("put XDP IPv4 flow: %v", err)
	}
}

func putOrphanFlowTestRuleV4(t *testing.T, rules *ebpf.Map, xdp bool, key tcRuleKeyV4, value tcRuleValueV4) {
	t.Helper()
	if !xdp {
		if err := rules.Put(key, value); err != nil {
			t.Fatalf("put TC IPv4 rule: %v", err)
		}
		return
	}
	var flags uint16
	if value.Flags&kernelRuleFlagFullNAT != 0 {
		flags |= xdpRuleFlagFullNAT
	}
	if value.Flags&kernelRuleFlagEgressNAT != 0 {
		flags |= xdpRuleFlagEgressNAT
	}
	if value.Flags&kernelRuleFlagFullCone != 0 {
		flags |= xdpRuleFlagFullCone
	}
	raw := xdpRuleValueV4{
		RuleID:      value.RuleID,
		BackendAddr: value.BackendAddr,
		BackendPort: value.BackendPort,
		Flags:       flags,
		OutIfIndex:  value.OutIfIndex,
		NATAddr:     value.NATAddr,
		Revision:    value.Revision,
	}
	if err := rules.Put(key, raw); err != nil {
		t.Fatalf("put XDP IPv4 rule: %v", err)
	}
}

type orphanFlowV6TestFixture struct {
	xdp        bool
	rules      *ebpf.Map
	flows      *ebpf.Map
	nat        *ebpf.Map
	refs       kernelRuntimeMapRefs
	ruleKey    tcRuleKeyV6
	ruleValue  tcRuleValueV6
	frontKey   tcFlowKeyV6
	frontValue tcFlowValueV6
	replyKey   tcFlowKeyV6
	natKey     tcNATPortKeyV6
}

func newOrphanFlowV6TestFixture(t *testing.T, xdp bool, bank string) orphanFlowV6TestFixture {
	t.Helper()
	ruleValueSize := uint32(unsafe.Sizeof(tcRuleValueV6{}))
	if xdp {
		ruleValueSize = uint32(unsafe.Sizeof(xdpRuleValueV6{}))
	}
	rules := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_rule_v6",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcRuleKeyV6{})),
		ValueSize:  ruleValueSize,
		MaxEntries: 16,
	})
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_flow_v6",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
		MaxEntries: 16,
	})
	nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       "orph_nat_v6",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 16,
	})
	addr := func(group, host byte) [16]byte {
		return [16]byte{0x20, 0x01, 0x0d, 0xb8, group, host}
	}
	ruleKey := tcRuleKeyV6{
		IfIndex: 6,
		DstAddr: addr(1, 1),
		DstPort: 443,
		Proto:   unix.IPPROTO_UDP,
	}
	ruleValue := tcRuleValueV6{
		RuleID:      201,
		BackendAddr: addr(2, 2),
		BackendPort: 8443,
		Flags:       kernelRuleFlagFullNAT,
		OutIfIndex:  10,
		NATAddr:     addr(3, 3),
		Revision:    20101,
	}
	putOrphanFlowTestRuleV6(t, rules, xdp, ruleKey, ruleValue)
	frontKey := tcFlowKeyV6{
		IfIndex: 6,
		SrcAddr: addr(4, 4),
		DstAddr: ruleKey.DstAddr,
		SrcPort: 55001,
		DstPort: ruleKey.DstPort,
		Proto:   ruleKey.Proto,
	}
	frontValue := tcFlowValueV6{
		RuleID:       ruleValue.RuleID,
		FrontAddr:    frontKey.DstAddr,
		ClientAddr:   frontKey.SrcAddr,
		NATAddr:      ruleValue.NATAddr,
		InIfIndex:    frontKey.IfIndex,
		FrontPort:    frontKey.DstPort,
		ClientPort:   frontKey.SrcPort,
		NATPort:      32002,
		Flags:        kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry | kernelFlowFlagCounted,
		LastSeenNS:   0,
		RuleRevision: ruleValue.Revision,
		SessionID:    0x202020202,
	}
	if err := flows.Put(frontKey, frontValue); err != nil {
		t.Fatalf("put IPv6 front flow: %v", err)
	}
	replyKey := tcFlowKeyV6{
		IfIndex: ruleValue.OutIfIndex,
		SrcAddr: ruleValue.BackendAddr,
		DstAddr: frontValue.NATAddr,
		SrcPort: ruleValue.BackendPort,
		DstPort: frontValue.NATPort,
		Proto:   frontKey.Proto,
	}
	natKey := tcNATPortKeyV6{
		IfIndex: ruleValue.OutIfIndex,
		NATAddr: frontValue.NATAddr,
		NATPort: frontValue.NATPort,
		Proto:   frontKey.Proto,
	}
	if err := nat.Put(natKey, tcNATPortValue{RuleID: ruleValue.RuleID, SessionID: frontValue.SessionID}); err != nil {
		t.Fatalf("put IPv6 NAT reservation: %v", err)
	}
	refs := kernelRuntimeMapRefs{rulesV6: rules}
	if bank == "old" {
		refs.flowsOldV6 = flows
		refs.natOldV6 = nat
	} else {
		refs.flowsV6 = flows
		refs.natV6 = nat
	}
	return orphanFlowV6TestFixture{
		xdp:        xdp,
		rules:      rules,
		flows:      flows,
		nat:        nat,
		refs:       refs,
		ruleKey:    ruleKey,
		ruleValue:  ruleValue,
		frontKey:   frontKey,
		frontValue: frontValue,
		replyKey:   replyKey,
		natKey:     natKey,
	}
}

func (fixture orphanFlowV6TestFixture) snapshot(t *testing.T) kernelFlowLiveStateSnapshot {
	t.Helper()
	var (
		live kernelFlowLiveStateSnapshot
		err  error
	)
	if fixture.xdp {
		live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(fixture.refs, true)
	} else {
		live, err = snapshotKernelLiveStateFromRuntimeMapRefs(fixture.refs, true)
	}
	if err != nil {
		t.Fatalf("snapshot IPv6 orphan flow fixture: %v", err)
	}
	return live
}

func (fixture orphanFlowV6TestFixture) putReply(t *testing.T) {
	t.Helper()
	replyValue := fixture.frontValue
	replyValue.Flags &^= kernelFlowFlagFrontEntry
	if err := fixture.flows.Put(fixture.replyKey, replyValue); err != nil {
		t.Fatalf("put IPv6 reply flow: %v", err)
	}
}

func putOrphanFlowTestRuleV6(t *testing.T, rules *ebpf.Map, xdp bool, key tcRuleKeyV6, value tcRuleValueV6) {
	t.Helper()
	if !xdp {
		if err := rules.Put(key, value); err != nil {
			t.Fatalf("put TC IPv6 rule: %v", err)
		}
		return
	}
	raw := xdpRuleValueV6{
		RuleID:      value.RuleID,
		BackendAddr: value.BackendAddr,
		BackendPort: value.BackendPort,
		Flags:       xdpRuleFlagFullNAT,
		OutIfIndex:  value.OutIfIndex,
		NATAddr:     value.NATAddr,
		Revision:    value.Revision,
	}
	if err := rules.Put(key, raw); err != nil {
		t.Fatalf("put XDP IPv6 rule: %v", err)
	}
}

func TestPruneOrphanKernelFlowFrontUsesProtocolTimeouts(t *testing.T) {
	nowNS := uint64(kernelTCPFlowIdleTimeout + kernelUDPFlowIdleTimeout + 1000)
	tests := []struct {
		name       string
		proto      uint8
		extraFlags uint16
		ageNS      uint64
		want       bool
	}{
		{name: "established TCP at boundary", proto: unix.IPPROTO_TCP, extraFlags: kernelFlowFlagReplySeen, ageNS: kernelTCPFlowIdleTimeout},
		{name: "established TCP expired", proto: unix.IPPROTO_TCP, extraFlags: kernelFlowFlagReplySeen, ageNS: kernelTCPFlowIdleTimeout + 1, want: true},
		{name: "unreplied TCP expired", proto: unix.IPPROTO_TCP, ageNS: kernelTCPUnrepliedTimeout + 1, want: true},
		{name: "UDP at boundary", proto: unix.IPPROTO_UDP, ageNS: kernelUDPFlowIdleTimeout},
		{name: "UDP expired", proto: unix.IPPROTO_UDP, ageNS: kernelUDPFlowIdleTimeout + 1, want: true},
		{name: "ICMP expired", proto: unix.IPPROTO_ICMP, ageNS: kernelICMPFlowIdleTimeout + 1, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			flags := uint16(kernelFlowFlagFullNAT | kernelFlowFlagFrontEntry)
			flags |= test.extraFlags
			valueV4 := tcFlowValueV4{
				RuleID:     1,
				NATAddr:    1,
				NATPort:    1,
				Flags:      flags,
				LastSeenNS: nowNS - test.ageNS,
			}
			if got := kernelOrphanFrontShouldDelete(tcFlowKeyV4{Proto: test.proto}, valueV4, nowNS, true); got != test.want {
				t.Fatalf("IPv4 orphan timeout decision = %t, want %t", got, test.want)
			}
			valueV6 := tcFlowValueV6{
				RuleID:     1,
				NATAddr:    [16]byte{1},
				NATPort:    1,
				Flags:      flags,
				LastSeenNS: nowNS - test.ageNS,
			}
			if got := kernelOrphanFrontShouldDeleteV6(tcFlowKeyV6{Proto: test.proto}, valueV6, nowNS, true); got != test.want {
				t.Fatalf("IPv6 orphan timeout decision = %t, want %t", got, test.want)
			}
		})
	}
}

func TestPruneOrphanKernelFlowFrontBanksIPv4AcrossEnginesAndBanks(t *testing.T) {
	for _, engine := range []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	} {
		for _, bank := range []string{"active", "old"} {
			t.Run(engine.name+"/"+bank, func(t *testing.T) {
				fixture := newOrphanFlowV4TestFixture(t, engine.xdp, bank, false)
				fixture.putReply(t)
				paired := fixture.snapshot(t)
				if got := len(paired.OrphanFrontsByBank.activeV4) + len(paired.OrphanFrontsByBank.oldV4); got != 0 {
					t.Fatalf("paired IPv4 orphan fronts = %d, want 0", got)
				}
				if err := fixture.flows.Delete(fixture.replyKey); err != nil {
					t.Fatalf("remove IPv4 reply flow: %v", err)
				}

				live := fixture.snapshot(t)
				current := live.OrphanFrontsByBank.activeV4
				if bank == "old" {
					current = live.OrphanFrontsByBank.oldV4
				}
				candidate := staleKernelFlow{key: fixture.frontKey, value: fixture.frontValue}
				if _, ok := current[candidate]; !ok || len(current) != 1 {
					t.Fatalf("IPv4 orphan candidates = %+v, want front flow", current)
				}

				activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
					fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
				)
				if err != nil {
					t.Fatalf("mark IPv4 orphan front: %v", err)
				}
				if deleted != 0 {
					t.Fatalf("first IPv4 orphan pass deleted = %d, want 0", deleted)
				}
				marked := activeState.orphanFrontsV4
				if bank == "old" {
					marked = oldState.orphanFrontsV4
				}
				if _, ok := marked[candidate]; !ok || len(marked) != 1 {
					t.Fatalf("marked IPv4 orphan candidates = %+v, want front flow", marked)
				}

				_, _, deleted, err = pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
				if err != nil {
					t.Fatalf("confirm IPv4 orphan front: %v", err)
				}
				if deleted != 1 {
					t.Fatalf("second IPv4 orphan pass deleted = %d, want 1", deleted)
				}
				if _, ok, err := lookupKernelFlowValue(fixture.flows, fixture.frontKey); err != nil || ok {
					t.Fatalf("IPv4 front survived confirmed prune: ok=%t err=%v", ok, err)
				}
				var natValue tcNATPortValue
				if err := fixture.nat.Lookup(fixture.natKey, &natValue); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("IPv4 NAT reservation survived confirmed prune: value=%+v err=%v", natValue, err)
				}
			})
		}
	}
}

func TestPruneOrphanKernelFlowFrontBanksIPv6AcrossEnginesAndBanks(t *testing.T) {
	for _, engine := range []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	} {
		for _, bank := range []string{"active", "old"} {
			t.Run(engine.name+"/"+bank, func(t *testing.T) {
				fixture := newOrphanFlowV6TestFixture(t, engine.xdp, bank)
				fixture.putReply(t)
				paired := fixture.snapshot(t)
				if got := len(paired.OrphanFrontsByBank.activeV6) + len(paired.OrphanFrontsByBank.oldV6); got != 0 {
					t.Fatalf("paired IPv6 orphan fronts = %d, want 0", got)
				}
				if err := fixture.flows.Delete(fixture.replyKey); err != nil {
					t.Fatalf("remove IPv6 reply flow: %v", err)
				}

				live := fixture.snapshot(t)
				current := live.OrphanFrontsByBank.activeV6
				if bank == "old" {
					current = live.OrphanFrontsByBank.oldV6
				}
				candidate := staleKernelFlowV6{key: fixture.frontKey, value: fixture.frontValue}
				if _, ok := current[candidate]; !ok || len(current) != 1 {
					t.Fatalf("IPv6 orphan candidates = %+v, want front flow", current)
				}

				activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
					fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
				)
				if err != nil {
					t.Fatalf("mark IPv6 orphan front: %v", err)
				}
				if deleted != 0 {
					t.Fatalf("first IPv6 orphan pass deleted = %d, want 0", deleted)
				}
				marked := activeState.orphanFrontsV6
				if bank == "old" {
					marked = oldState.orphanFrontsV6
				}
				if _, ok := marked[candidate]; !ok || len(marked) != 1 {
					t.Fatalf("marked IPv6 orphan candidates = %+v, want front flow", marked)
				}

				_, _, deleted, err = pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
				if err != nil {
					t.Fatalf("confirm IPv6 orphan front: %v", err)
				}
				if deleted != 1 {
					t.Fatalf("second IPv6 orphan pass deleted = %d, want 1", deleted)
				}
				var frontValue tcFlowValueV6
				if err := fixture.flows.Lookup(fixture.frontKey, &frontValue); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("IPv6 front survived confirmed prune: value=%+v err=%v", frontValue, err)
				}
				var natValue tcNATPortValue
				if err := fixture.nat.Lookup(fixture.natKey, &natValue); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("IPv6 NAT reservation survived confirmed prune: value=%+v err=%v", natValue, err)
				}
			})
		}
	}
}

func TestPruneOrphanKernelFlowFrontProtectsReplyRebuiltAfterSnapshot(t *testing.T) {
	for _, engine := range []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	} {
		for _, mode := range []struct {
			name     string
			fullCone bool
		}{
			{name: "egress"},
			{name: "full-cone", fullCone: true},
		} {
			t.Run("ipv4/"+engine.name+"/"+mode.name, func(t *testing.T) {
				fixture := newOrphanFlowV4TestFixture(t, engine.xdp, "active", true)
				if mode.fullCone {
					fixture.makeFullCone(t)
				}
				live := fixture.snapshot(t)
				activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
					fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
				)
				if err != nil || deleted != 0 {
					t.Fatalf("mark IPv4 race candidate: deleted=%d err=%v", deleted, err)
				}

				live = fixture.snapshot(t)
				fixture.putReply(t)
				activeState, oldState, deleted, err = pruneOrphanKernelFlowFrontBanks(
					fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
				)
				if err != nil || deleted != 0 {
					t.Fatalf("revalidate rebuilt IPv4 reply: deleted=%d err=%v", deleted, err)
				}
				if len(activeState.orphanFrontsV4) != 0 {
					t.Fatalf("rebuilt IPv4 reply left stale confirmation state: %+v", activeState.orphanFrontsV4)
				}
				if _, ok, err := lookupKernelFlowValue(fixture.flows, fixture.frontKey); err != nil || !ok {
					t.Fatalf("rebuilt IPv4 reply did not protect front: ok=%t err=%v", ok, err)
				}

				if err := fixture.flows.Delete(fixture.replyKey); err != nil {
					t.Fatalf("remove rebuilt IPv4 reply: %v", err)
				}
				live = fixture.snapshot(t)
				activeState, oldState, deleted, err = pruneOrphanKernelFlowFrontBanks(
					fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
				)
				if err != nil || deleted != 0 {
					t.Fatalf("remark IPv4 orphan after reply loss: deleted=%d err=%v", deleted, err)
				}
				_, _, deleted, err = pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
				if err != nil || deleted != 1 {
					t.Fatalf("reconfirm IPv4 orphan after reply loss: deleted=%d err=%v", deleted, err)
				}
			})
		}

		t.Run("ipv6/"+engine.name, func(t *testing.T) {
			fixture := newOrphanFlowV6TestFixture(t, engine.xdp, "active")
			live := fixture.snapshot(t)
			activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
				fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
			)
			if err != nil || deleted != 0 {
				t.Fatalf("mark IPv6 race candidate: deleted=%d err=%v", deleted, err)
			}

			live = fixture.snapshot(t)
			fixture.putReply(t)
			activeState, oldState, deleted, err = pruneOrphanKernelFlowFrontBanks(
				fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
			)
			if err != nil || deleted != 0 {
				t.Fatalf("revalidate rebuilt IPv6 reply: deleted=%d err=%v", deleted, err)
			}
			if len(activeState.orphanFrontsV6) != 0 {
				t.Fatalf("rebuilt IPv6 reply left stale confirmation state: %+v", activeState.orphanFrontsV6)
			}
			var frontValue tcFlowValueV6
			if err := fixture.flows.Lookup(fixture.frontKey, &frontValue); err != nil {
				t.Fatalf("rebuilt IPv6 reply did not protect front: %v", err)
			}

			if err := fixture.flows.Delete(fixture.replyKey); err != nil {
				t.Fatalf("remove rebuilt IPv6 reply: %v", err)
			}
			live = fixture.snapshot(t)
			activeState, oldState, deleted, err = pruneOrphanKernelFlowFrontBanks(
				fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
			)
			if err != nil || deleted != 0 {
				t.Fatalf("remark IPv6 orphan after reply loss: deleted=%d err=%v", deleted, err)
			}
			_, _, deleted, err = pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
			if err != nil || deleted != 1 {
				t.Fatalf("reconfirm IPv6 orphan after reply loss: deleted=%d err=%v", deleted, err)
			}
		})
	}
}

func TestPruneOrphanKernelFlowFrontConfirmationResetsWhenFrontChanges(t *testing.T) {
	fixture := newOrphanFlowV4TestFixture(t, false, "active", false)
	live := fixture.snapshot(t)
	activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
		fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
	)
	if err != nil || deleted != 0 {
		t.Fatalf("mark original IPv4 front: deleted=%d err=%v", deleted, err)
	}

	replacement := fixture.frontValue
	replacement.SessionID++
	fixture.putFront(t, replacement)
	if err := fixture.nat.Put(fixture.natKey, tcNATPortValue{RuleID: replacement.RuleID, SessionID: replacement.SessionID}); err != nil {
		t.Fatalf("replace IPv4 NAT owner: %v", err)
	}
	live = fixture.snapshot(t)
	activeState, oldState, deleted, err = pruneOrphanKernelFlowFrontBanks(
		fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
	)
	if err != nil || deleted != 0 {
		t.Fatalf("replacement session reused old confirmation: deleted=%d err=%v", deleted, err)
	}
	replacementCandidate := staleKernelFlow{key: fixture.frontKey, value: replacement}
	if _, ok := activeState.orphanFrontsV4[replacementCandidate]; !ok || len(activeState.orphanFrontsV4) != 1 {
		t.Fatalf("replacement session confirmation state = %+v, want only replacement", activeState.orphanFrontsV4)
	}

	staleSnapshot := live
	refreshed := replacement
	nowNS, haveNow := kernelMonotonicNowNS()
	if !haveNow {
		t.Fatal("monotonic clock unavailable")
	}
	refreshed.LastSeenNS = nowNS
	fixture.putFront(t, refreshed)
	activeState, _, deleted, err = pruneOrphanKernelFlowFrontBanks(
		fixture.refs, staleSnapshot.OrphanFrontsByBank, activeState, oldState,
	)
	if err != nil || deleted != 0 {
		t.Fatalf("refreshed IPv4 front was deleted: deleted=%d err=%v", deleted, err)
	}
	if len(activeState.orphanFrontsV4) != 0 {
		t.Fatalf("refreshed IPv4 front retained confirmation state: %+v", activeState.orphanFrontsV4)
	}
	if current, ok, err := lookupKernelFlowValue(fixture.flows, fixture.frontKey); err != nil || !ok || current != refreshed {
		t.Fatalf("refreshed IPv4 front changed during revalidation: ok=%t value=%+v err=%v", ok, current, err)
	}
}

func TestPruneOrphanKernelFlowFrontProtectsRuleAndNATReplacement(t *testing.T) {
	t.Run("rule revision", func(t *testing.T) {
		fixture := newOrphanFlowV4TestFixture(t, false, "active", false)
		live := fixture.snapshot(t)
		activeState, oldState, deleted, err := pruneOrphanKernelFlowFrontBanks(
			fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
		)
		if err != nil || deleted != 0 {
			t.Fatalf("mark IPv4 front before rule transition: deleted=%d err=%v", deleted, err)
		}
		replacementRule := fixture.ruleValue
		replacementRule.Revision++
		replacementRule.OutIfIndex++
		putOrphanFlowTestRuleV4(t, fixture.rules, false, fixture.ruleKey, replacementRule)
		activeState, _, deleted, err = pruneOrphanKernelFlowFrontBanks(
			fixture.refs, live.OrphanFrontsByBank, activeState, oldState,
		)
		if err != nil || deleted != 0 {
			t.Fatalf("rule transition deleted old front: deleted=%d err=%v", deleted, err)
		}
		if len(activeState.orphanFrontsV4) != 1 {
			t.Fatalf("rule transition confirmation state length = %d, want 1", len(activeState.orphanFrontsV4))
		}
		if _, ok, err := lookupKernelFlowValue(fixture.flows, fixture.frontKey); err != nil || !ok {
			t.Fatalf("rule transition did not protect front: ok=%t err=%v", ok, err)
		}
	})

	t.Run("IPv4 NAT owner", func(t *testing.T) {
		fixture := newOrphanFlowV4TestFixture(t, true, "active", false)
		live := fixture.snapshot(t)
		activeState, oldState, _, err := pruneOrphanKernelFlowFrontBanks(
			fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
		)
		if err != nil {
			t.Fatalf("mark IPv4 front before NAT replacement: %v", err)
		}
		replacement := tcNATPortValue{RuleID: 999, SessionID: fixture.frontValue.SessionID + 1}
		if err := fixture.nat.Put(fixture.natKey, replacement); err != nil {
			t.Fatalf("replace IPv4 NAT owner: %v", err)
		}
		_, _, deleted, err := pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
		if err != nil || deleted != 1 {
			t.Fatalf("prune IPv4 front after NAT replacement: deleted=%d err=%v", deleted, err)
		}
		var current tcNATPortValue
		if err := fixture.nat.Lookup(fixture.natKey, &current); err != nil || current != replacement {
			t.Fatalf("IPv4 replacement NAT owner changed: value=%+v err=%v", current, err)
		}
	})

	t.Run("IPv6 NAT owner", func(t *testing.T) {
		fixture := newOrphanFlowV6TestFixture(t, true, "active")
		live := fixture.snapshot(t)
		activeState, oldState, _, err := pruneOrphanKernelFlowFrontBanks(
			fixture.refs, live.OrphanFrontsByBank, kernelFlowPruneState{}, kernelFlowPruneState{},
		)
		if err != nil {
			t.Fatalf("mark IPv6 front before NAT replacement: %v", err)
		}
		replacement := tcNATPortValue{RuleID: 999, SessionID: fixture.frontValue.SessionID + 1}
		if err := fixture.nat.Put(fixture.natKey, replacement); err != nil {
			t.Fatalf("replace IPv6 NAT owner: %v", err)
		}
		_, _, deleted, err := pruneOrphanKernelFlowFrontBanks(fixture.refs, live.OrphanFrontsByBank, activeState, oldState)
		if err != nil || deleted != 1 {
			t.Fatalf("prune IPv6 front after NAT replacement: deleted=%d err=%v", deleted, err)
		}
		var current tcNATPortValue
		if err := fixture.nat.Lookup(fixture.natKey, &current); err != nil || current != replacement {
			t.Fatalf("IPv6 replacement NAT owner changed: value=%+v err=%v", current, err)
		}
	})
}
