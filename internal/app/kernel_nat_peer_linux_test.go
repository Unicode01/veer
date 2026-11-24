//go:build linux

package app

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestNATPeerMapLayoutsMatchBPF(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		size  uintptr
	}{
		{name: "nat_peer_key_v4", value: tcNATPeerKeyV4{}, size: 20},
		{name: "nat_peer_key_v6", value: tcNATPeerKeyV6{}, size: 44},
		{name: "nat_peer_value", value: tcNATPeerValue{}, size: 16},
	} {
		if got := binary.Size(tc.value); got != int(tc.size) {
			t.Errorf("binary.Size(%s) = %d, want %d", tc.name, got, tc.size)
		}
	}
	if got := unsafe.Sizeof(tcNATPeerKeyV4{}); got != 20 {
		t.Errorf("unsafe.Sizeof(tcNATPeerKeyV4) = %d, want 20 (no implicit padding)", got)
	}
	if got := unsafe.Sizeof(tcNATPeerKeyV6{}); got != 44 {
		t.Errorf("unsafe.Sizeof(tcNATPeerKeyV6) = %d, want 44 (no implicit padding)", got)
	}
	// The class key leads the peer key, so the datapath passes a peer key's
	// first bytes to nat_ports lookups.
	if got := unsafe.Offsetof(tcNATPeerKeyV4{}.PeerAddr); got != unsafe.Sizeof(tcNATPortKeyV4{}) {
		t.Errorf("tcNATPeerKeyV4.PeerAddr offset = %d, want %d", got, unsafe.Sizeof(tcNATPortKeyV4{}))
	}
	if got := unsafe.Offsetof(tcNATPeerKeyV6{}.PeerAddr); got != unsafe.Sizeof(tcNATPortKeyV6{}) {
		t.Errorf("tcNATPeerKeyV6.PeerAddr offset = %d, want %d", got, unsafe.Sizeof(tcNATPortKeyV6{}))
	}
}

func TestNATPeerMapsArePartOfEveryABIContract(t *testing.T) {
	for _, tc := range []struct {
		engine    string
		contracts []kernelMapABIContract
	}{
		{engine: "tc", contracts: tcKernelMapABIContracts()},
		{engine: "xdp", contracts: xdpKernelMapABIContracts()},
	} {
		names := make(map[string]kernelMapABIContract, len(tc.contracts))
		for _, contract := range tc.contracts {
			names[contract.name] = contract
		}
		for _, name := range []string{kernelNatPeersMapNameV4, kernelTCNatPeersOldMapNameV4} {
			if _, ok := names[name].key.(tcNATPeerKeyV4); !ok {
				t.Errorf("%s contract for %s has key %T, want tcNATPeerKeyV4", tc.engine, name, names[name].key)
			}
		}
		for _, name := range []string{kernelNatPeersMapNameV6, kernelTCNatPeersOldMapNameV6} {
			if _, ok := names[name].key.(tcNATPeerKeyV6); !ok {
				t.Errorf("%s contract for %s has key %T, want tcNATPeerKeyV6", tc.engine, name, names[name].key)
			}
		}
	}
}

func TestKernelReplyFlowKeyNamesTheNATPeer(t *testing.T) {
	front := tcFlowValueV4{
		FrontAddr: 0xc6130002,
		NATAddr:   0xc6130001,
		FrontPort: 443,
		NATPort:   24500,
	}
	egress := tcRuleValueV4{OutIfIndex: 7, Flags: kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT}
	forward := tcRuleValueV4{OutIfIndex: 8, Flags: kernelRuleFlagFullNAT, BackendAddr: 0x0a000005, BackendPort: 8080}

	for _, tc := range []struct {
		name string
		rule tcRuleValueV4
		want tcNATPeerKeyV4
	}{
		{
			// An egress NAT flow shares its port with flows to other destinations.
			name: "egress NAT",
			rule: egress,
			want: tcNATPeerKeyV4{
				Port:     tcNATPortKeyV4{IfIndex: 7, NATAddr: 0xc6130001, NATPort: 24500, Proto: unix.IPPROTO_TCP},
				PeerAddr: 0xc6130002,
				PeerPort: 443,
			},
		},
		{
			// A port forward's peer is its backend, so one rule never shares.
			name: "port forward",
			rule: forward,
			want: tcNATPeerKeyV4{
				Port:     tcNATPortKeyV4{IfIndex: 8, NATAddr: 0xc6130001, NATPort: 24500, Proto: unix.IPPROTO_TCP},
				PeerAddr: 0x0a000005,
				PeerPort: 8080,
			},
		},
	} {
		reply := kernelReplyFlowKeyFromFrontV4(tc.rule, front, unix.IPPROTO_TCP)
		if got := kernelNATPeerKeyFromReplyV4(reply); got != tc.want {
			t.Errorf("%s: peer key = %+v, want %+v", tc.name, got, tc.want)
		}
	}

	frontV6 := tcFlowValueV6{NATAddr: [16]byte{0x20, 0x01, 15: 1}, NATPort: 24501}
	ruleV6 := tcRuleValueV6{OutIfIndex: 9, BackendAddr: [16]byte{0xfd, 15: 5}, BackendPort: 8443}
	wantV6 := tcNATPeerKeyV6{
		Port:     tcNATPortKeyV6{IfIndex: 9, NATAddr: frontV6.NATAddr, NATPort: 24501, Proto: unix.IPPROTO_UDP},
		PeerAddr: ruleV6.BackendAddr,
		PeerPort: 8443,
	}
	if got := kernelNATPeerKeyFromReplyV6(kernelReplyFlowKeyFromFrontV6(ruleV6, frontV6, unix.IPPROTO_UDP)); got != wantV6 {
		t.Errorf("IPv6 peer key = %+v, want %+v", got, wantV6)
	}
}

func newNATPortsTestMapV4(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
		MaxEntries: 32,
	})
}

func newNATPeersTestMapV4(t *testing.T, name string) *ebpf.Map {
	t.Helper()
	return newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       name,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcNATPeerKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcNATPeerValue{})),
		MaxEntries: 32,
	})
}

func natPortModeForTest(t *testing.T, ports *ebpf.Map, key tcNATPortKeyV4) (uint32, bool) {
	t.Helper()
	var value tcNATPortValue
	if err := ports.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, false
		}
		t.Fatalf("lookup nat port %+v: %v", key, err)
	}
	return value.Mode, true
}

func TestReclaimKernelSharedNATPortsDrainsBeforeDeleting(t *testing.T) {
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	key := func(port uint16) tcNATPortKeyV4 {
		return tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: port, Proto: unix.IPPROTO_UDP}
	}
	used, unused, drainedElsewhere, exclusive := key(24001), key(24002), key(24003), key(24004)
	for _, item := range []struct {
		key   tcNATPortKeyV4
		value tcNATPortValue
	}{
		{used, tcNATPortValue{RuleID: 1, Mode: kernelNATPortShared}},
		{unused, tcNATPortValue{RuleID: 1, Mode: kernelNATPortShared}},
		{drainedElsewhere, tcNATPortValue{RuleID: 1, Mode: kernelNATPortDraining}},
		{exclusive, tcNATPortValue{RuleID: 2, Mode: kernelNATPortExclusive, SessionID: 77}},
	} {
		if err := ports.Put(item.key, item.value); err != nil {
			t.Fatalf("ports.Put(%+v) error = %v", item.key, err)
		}
	}

	inUse := map[tcNATPortKeyV4]struct{}{used: {}}
	deleted, marked, err := reclaimKernelSharedNATPorts(ports, inUse, nil)
	if err != nil {
		t.Fatalf("first pass error = %v", err)
	}
	if deleted != 0 {
		t.Fatalf("first pass deleted %d ports, want 0: a port is only deleted a pass after it drains", deleted)
	}
	if _, ok := marked[unused]; !ok || len(marked) != 2 {
		t.Fatalf("first pass marked %v, want the unused port and the one drained by another process", marked)
	}
	for _, tc := range []struct {
		key  tcNATPortKeyV4
		mode uint32
	}{
		{used, kernelNATPortShared},
		{unused, kernelNATPortDraining},
		{drainedElsewhere, kernelNATPortDraining},
		{exclusive, kernelNATPortExclusive},
	} {
		if mode, ok := natPortModeForTest(t, ports, tc.key); !ok || mode != tc.mode {
			t.Fatalf("after the first pass port %d mode = %d (present %v), want %d", tc.key.NATPort, mode, ok, tc.mode)
		}
	}

	// A mapping took the draining port between the passes: it serves again.
	inUse = map[tcNATPortKeyV4]struct{}{used: {}, unused: {}}
	deleted, marked, err = reclaimKernelSharedNATPorts(ports, inUse, marked)
	if err != nil {
		t.Fatalf("second pass error = %v", err)
	}
	if deleted != 1 || len(marked) != 0 {
		t.Fatalf("second pass deleted/marked = %d/%v, want 1/none", deleted, marked)
	}
	if mode, ok := natPortModeForTest(t, ports, unused); !ok || mode != kernelNATPortShared {
		t.Fatalf("port taken while draining has mode %d (present %v), want shared", mode, ok)
	}
	if _, ok := natPortModeForTest(t, ports, drainedElsewhere); ok {
		t.Fatal("a port still unused a pass after draining was kept")
	}
	if mode, ok := natPortModeForTest(t, ports, exclusive); !ok || mode != kernelNATPortExclusive {
		t.Fatalf("exclusive port mode = %d (present %v), want it untouched", mode, ok)
	}
}

func TestPruneOrphanKernelNATPeersConfirmsBeforeDeleting(t *testing.T) {
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)
	class := tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: 24001, Proto: unix.IPPROTO_TCP}
	usedOwner := kernelNATPeerOwnerV4{Key: tcNATPeerKeyV4{Port: class, PeerAddr: 0xc6130002, PeerPort: 80}, SessionID: 11}
	staleOwner := kernelNATPeerOwnerV4{Key: tcNATPeerKeyV4{Port: class, PeerAddr: 0xc6130003, PeerPort: 80}, SessionID: 22}
	for _, owner := range []kernelNATPeerOwnerV4{usedOwner, staleOwner} {
		if err := peers.Put(owner.Key, tcNATPeerValue{RuleID: 1, SessionID: owner.SessionID}); err != nil {
			t.Fatalf("peers.Put(%+v) error = %v", owner.Key, err)
		}
	}
	used := map[kernelNATPeerOwnerV4]struct{}{usedOwner: {}}

	remaining, deleted, candidates, inUse, err := pruneOrphanKernelNATPeers[tcNATPeerKeyV4, tcNATPortKeyV4](peers, used, nil)
	if err != nil {
		t.Fatalf("first pass error = %v", err)
	}
	if remaining != 2 || deleted != 0 || len(candidates) != 1 {
		t.Fatalf("first pass remaining/deleted/candidates = %d/%d/%v, want 2/0/the stale peer", remaining, deleted, candidates)
	}
	if _, ok := inUse[class]; !ok {
		t.Fatal("first pass lost the shared port both peers use")
	}

	// A new flow reused the stale entry's key with another session: keep it.
	replacement := kernelNATPeerOwnerV4{Key: staleOwner.Key, SessionID: 33}
	if err := peers.Put(replacement.Key, tcNATPeerValue{RuleID: 1, SessionID: replacement.SessionID}); err != nil {
		t.Fatalf("replace stale peer: %v", err)
	}
	remaining, deleted, candidates, _, err = pruneOrphanKernelNATPeers[tcNATPeerKeyV4, tcNATPortKeyV4](peers, used, candidates)
	if err != nil {
		t.Fatalf("replacement pass error = %v", err)
	}
	if remaining != 2 || deleted != 0 {
		t.Fatalf("replacement pass remaining/deleted = %d/%d, want 2/0", remaining, deleted)
	}
	if _, ok := candidates[replacement]; !ok || len(candidates) != 1 {
		t.Fatalf("replacement pass candidates = %v, want the replacement", candidates)
	}

	remaining, deleted, _, inUse, err = pruneOrphanKernelNATPeers[tcNATPeerKeyV4, tcNATPortKeyV4](peers, used, candidates)
	if err != nil {
		t.Fatalf("confirmation pass error = %v", err)
	}
	if remaining != 1 || deleted != 1 {
		t.Fatalf("confirmation pass remaining/deleted = %d/%d, want 1/1", remaining, deleted)
	}
	if _, ok := inUse[class]; !ok {
		t.Fatal("the used peer no longer keeps its shared port")
	}
}

func TestPruneOrphanKernelNATReservationsLeavesSharedPorts(t *testing.T) {
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	shared := tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: 24001, Proto: unix.IPPROTO_TCP}
	if err := ports.Put(shared, tcNATPortValue{RuleID: 1, Mode: kernelNATPortShared}); err != nil {
		t.Fatalf("ports.Put() error = %v", err)
	}
	var candidates map[kernelNATReservationOwnerV4]struct{}
	for pass := 0; pass < 3; pass++ {
		remaining, deleted, next, err := pruneOrphanKernelNATReservations(ports, nil, candidates)
		if err != nil {
			t.Fatalf("pass %d error = %v", pass, err)
		}
		if remaining != 0 || deleted != 0 || len(next) != 0 {
			t.Fatalf("pass %d remaining/deleted/candidates = %d/%d/%v, want a shared port neither counted nor pruned", pass, remaining, deleted, next)
		}
		candidates = next
	}
	if _, ok := natPortModeForTest(t, ports, shared); !ok {
		t.Fatal("the exclusive-port prune deleted a shared port")
	}
}

// A shared port outlives its last mapping by two maintenance passes: the
// orphan peer goes on the second pass that finds it, which drains the port,
// and the next pass deletes it.
func TestPruneOrphanKernelNATBanksReclaimsSharedPortAfterItsLastMapping(t *testing.T) {
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)
	refs := kernelRuntimeMapRefs{natV4: ports, natPeersV4: peers}

	class := tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: 24001, Proto: unix.IPPROTO_UDP}
	exclusiveKey := tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: 24002, Proto: unix.IPPROTO_UDP}
	owner := kernelNATPeerOwnerV4{Key: tcNATPeerKeyV4{Port: class, PeerAddr: 0xc6130002, PeerPort: 53}, SessionID: 5}
	exclusiveOwner := kernelNATReservationOwnerV4{Key: exclusiveKey, SessionID: 6}
	if err := ports.Put(class, tcNATPortValue{RuleID: 1, Mode: kernelNATPortShared}); err != nil {
		t.Fatal(err)
	}
	if err := ports.Put(exclusiveKey, tcNATPortValue{RuleID: 2, SessionID: exclusiveOwner.SessionID}); err != nil {
		t.Fatal(err)
	}
	if err := peers.Put(owner.Key, tcNATPeerValue{RuleID: 1, SessionID: owner.SessionID}); err != nil {
		t.Fatal(err)
	}

	used := kernelNATBankUsage{
		activeV4:      map[kernelNATReservationOwnerV4]struct{}{exclusiveOwner: {}},
		peersActiveV4: map[kernelNATPeerOwnerV4]struct{}{owner: {}},
	}
	natEntries, deleted, reclaimed, state, err := pruneOrphanKernelNATBanks(refs, used, kernelNATPruneState{})
	if err != nil {
		t.Fatalf("pass with a live mapping error = %v", err)
	}
	if natEntries != 2 || deleted != 0 || reclaimed != 0 {
		t.Fatalf("pass with a live mapping entries/deleted/reclaimed = %d/%d/%d, want 2/0/0: mappings, not the shared port, count", natEntries, deleted, reclaimed)
	}
	if mode, _ := natPortModeForTest(t, ports, class); mode != kernelNATPortShared {
		t.Fatalf("shared port mode = %d while a mapping uses it, want shared", mode)
	}

	used.peersActiveV4 = nil
	for pass, want := range []struct {
		entries, deleted, reclaimed int
		mode                        uint32
		present                     bool
	}{
		{entries: 2, mode: kernelNATPortShared, present: true},               // the orphan peer becomes a candidate
		{entries: 1, deleted: 1, mode: kernelNATPortDraining, present: true}, // it goes, and the port drains
		{entries: 1, reclaimed: 1, present: false},                           // the drained port goes
	} {
		natEntries, deleted, reclaimed, state, err = pruneOrphanKernelNATBanks(refs, used, state)
		if err != nil {
			t.Fatalf("pass %d error = %v", pass, err)
		}
		if natEntries != want.entries || deleted != want.deleted || reclaimed != want.reclaimed {
			t.Fatalf("pass %d entries/deleted/reclaimed = %d/%d/%d, want %d/%d/%d", pass, natEntries, deleted, reclaimed, want.entries, want.deleted, want.reclaimed)
		}
		mode, present := natPortModeForTest(t, ports, class)
		if present != want.present || (present && mode != want.mode) {
			t.Fatalf("pass %d shared port mode = %d (present %v), want %d (present %v)", pass, mode, present, want.mode, want.present)
		}
	}
	if _, ok := natPortModeForTest(t, ports, exclusiveKey); !ok {
		t.Fatal("the reclaim deleted an exclusive port in use")
	}
}

// When a mapping ends the datapath deletes its peer entry itself and leaves
// the shared port for maintenance to reclaim. That happens for every
// connection through a port forward, so it must not count as an orphan:
// orphans mark the pass as having found drift and are logged.
func TestPruneOrphanKernelNATBanksDoesNotCountRoutineReclaimsAsOrphans(t *testing.T) {
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)
	refs := kernelRuntimeMapRefs{natV4: ports, natPeersV4: peers}

	var state kernelNATPruneState
	orphans, reclaimed := 0, 0
	for i := range 3 {
		class := tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: uint16(25000 + i), Proto: unix.IPPROTO_TCP}
		if err := ports.Put(class, tcNATPortValue{RuleID: 1, Mode: kernelNATPortShared}); err != nil {
			t.Fatal(err)
		}
	}
	for pass := range 2 {
		_, deleted, passReclaimed, next, err := pruneOrphanKernelNATBanks(refs, kernelNATBankUsage{}, state)
		if err != nil {
			t.Fatalf("pass %d error = %v", pass, err)
		}
		state = next
		orphans += deleted
		reclaimed += passReclaimed
	}
	if orphans != 0 || reclaimed != 3 {
		t.Fatalf("orphans/reclaimed = %d/%d, want 0/3", orphans, reclaimed)
	}
}

func TestDeleteKernelFlowSessionReleasesNATPeer(t *testing.T) {
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)

	const sessionID = uint64(4242)
	replyKey := tcFlowKeyV4{IfIndex: 9, SrcAddr: 0xc6130002, DstAddr: 0xc6130001, SrcPort: 53, DstPort: 24001, Proto: unix.IPPROTO_UDP}
	replyValue := tcFlowValueV4{
		RuleID:     7,
		FrontAddr:  0xc6130002,
		ClientAddr: 0xc6120002,
		NATAddr:    0xc6130001,
		InIfIndex:  4,
		FrontPort:  53,
		ClientPort: 40000,
		NATPort:    24001,
		Flags:      kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagNATPeer | kernelFlowFlagCounted,
		LastSeenNS: 1,
		SessionID:  sessionID,
	}
	frontKey := tcFlowKeyV4{IfIndex: 4, SrcAddr: 0xc6120002, DstAddr: 0xc6130002, SrcPort: 40000, DstPort: 53, Proto: unix.IPPROTO_UDP}
	frontValue := replyValue
	frontValue.Flags = kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagNATPeer | kernelFlowFlagFrontEntry
	for _, item := range []struct {
		key   tcFlowKeyV4
		value tcFlowValueV4
	}{{replyKey, replyValue}, {frontKey, frontValue}} {
		if err := flows.Put(item.key, item.value); err != nil {
			t.Fatal(err)
		}
	}
	class := tcNATPortKeyV4{IfIndex: 9, NATAddr: 0xc6130001, NATPort: 24001, Proto: unix.IPPROTO_UDP}
	peerKey := tcNATPeerKeyV4{Port: class, PeerAddr: 0xc6130002, PeerPort: 53}
	otherPeer := tcNATPeerKeyV4{Port: class, PeerAddr: 0xc6130003, PeerPort: 53}
	if err := ports.Put(class, tcNATPortValue{RuleID: 7, Mode: kernelNATPortShared}); err != nil {
		t.Fatal(err)
	}
	if err := peers.Put(peerKey, tcNATPeerValue{RuleID: 7, SessionID: sessionID}); err != nil {
		t.Fatal(err)
	}
	if err := peers.Put(otherPeer, tcNATPeerValue{RuleID: 7, SessionID: sessionID + 1}); err != nil {
		t.Fatal(err)
	}

	corrections := map[uint32]kernelRuleStats{}
	deleted, err := deleteKernelFlowSessionWithError(flows, kernelNATBankMaps{ports: ports, peers: peers}, staleKernelFlow{key: replyKey, value: replyValue}, corrections, true)
	if err != nil || deleted != 2 {
		t.Fatalf("deleteKernelFlowSessionWithError() = %d, %v; want both flow entries", deleted, err)
	}
	var value tcNATPeerValue
	if err := peers.Lookup(peerKey, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("the deleted flow's peer entry is still there (err %v)", err)
	}
	if err := peers.Lookup(otherPeer, &value); err != nil {
		t.Fatalf("another flow's peer entry on the same port went too: %v", err)
	}
	if mode, ok := natPortModeForTest(t, ports, class); !ok || mode != kernelNATPortShared {
		t.Fatalf("shared port mode = %d (present %v) after a release, want it kept shared for the reclaim", mode, ok)
	}
}

func TestSnapshotKernelLiveStateRecordsNATPeerOwners(t *testing.T) {
	rules := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelRulesMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcRuleKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcRuleValueV4{})),
		MaxEntries: 8,
	})
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 16,
	})
	// An egress NAT rule matches every destination on its interface.
	if err := rules.Put(tcRuleKeyV4{IfIndex: 4, Proto: unix.IPPROTO_UDP}, tcRuleValueV4{
		RuleID:     7,
		Flags:      kernelRuleFlagFullNAT | kernelRuleFlagEgressNAT,
		OutIfIndex: 9,
		NATAddr:    0xc6130001,
	}); err != nil {
		t.Fatal(err)
	}
	value := tcFlowValueV4{
		RuleID:     7,
		FrontAddr:  0xc6130002,
		ClientAddr: 0xc6120002,
		NATAddr:    0xc6130001,
		InIfIndex:  4,
		FrontPort:  53,
		ClientPort: 40000,
		NATPort:    24001,
		Flags:      kernelFlowFlagFullNAT | kernelFlowFlagEgressNAT | kernelFlowFlagNATPeer,
		LastSeenNS: 1,
		SessionID:  99,
	}
	front := value
	front.Flags |= kernelFlowFlagFrontEntry
	if err := flows.Put(tcFlowKeyV4{IfIndex: 4, SrcAddr: 0xc6120002, DstAddr: 0xc6130002, SrcPort: 40000, DstPort: 53, Proto: unix.IPPROTO_UDP}, front); err != nil {
		t.Fatal(err)
	}
	if err := flows.Put(tcFlowKeyV4{IfIndex: 9, SrcAddr: 0xc6130002, DstAddr: 0xc6130001, SrcPort: 53, DstPort: 24001, Proto: unix.IPPROTO_UDP}, value); err != nil {
		t.Fatal(err)
	}

	live, err := snapshotKernelLiveStateFromFlows(rules, flows, true)
	if err != nil {
		t.Fatalf("snapshotKernelLiveStateFromFlows() error = %v", err)
	}
	want := kernelNATPeerOwnerV4{
		Key: tcNATPeerKeyV4{
			Port:     tcNATPortKeyV4{IfIndex: 9, NATAddr: 0xc6130001, NATPort: 24001, Proto: unix.IPPROTO_UDP},
			PeerAddr: 0xc6130002,
			PeerPort: 53,
		},
		SessionID: 99,
	}
	if _, ok := live.UsedNATPeersV4[want]; !ok || len(live.UsedNATPeersV4) != 1 {
		t.Fatalf("UsedNATPeersV4 = %v, want only %+v from both entries", live.UsedNATPeersV4, want)
	}
	if len(live.UsedNATV4) != 0 {
		t.Fatalf("UsedNATV4 = %v, want no exclusive port for a flow on a shared one", live.UsedNATV4)
	}
}

func TestKernelHotRestartPreservesNATPeerMapsWithTheirBank(t *testing.T) {
	all := func(string) bool { return true }
	tcNames := kernelTCHotRestartPreservedMapNames(all, tcFlowMigrationFlagV4Old|tcFlowMigrationFlagV6Old, true)
	for _, name := range []string{kernelNatPeersMapNameV4, kernelNatPeersMapNameV6, kernelTCNatPeersOldMapNameV4, kernelTCNatPeersOldMapNameV6} {
		if !slices.Contains(tcNames, name) {
			t.Errorf("tc preserved maps %v lack %s", tcNames, name)
		}
	}
	// Without old banks, the old peer maps stay behind with them.
	tcNames = kernelTCHotRestartPreservedMapNames(all, 0, true)
	if slices.Contains(tcNames, kernelTCNatPeersOldMapNameV4) || !slices.Contains(tcNames, kernelNatPeersMapNameV4) {
		t.Errorf("tc preserved maps without old banks = %v, want the active peer maps only", tcNames)
	}
	xdpNames := kernelXDPHotRestartPreservedMapNames(all, xdpFlowMigrationFlagV4Old, true, true)
	for _, name := range []string{kernelNatPeersMapNameV4, kernelTCNatPeersOldMapNameV4} {
		if !slices.Contains(xdpNames, name) {
			t.Errorf("xdp preserved maps %v lack %s", xdpNames, name)
		}
	}
	if names := kernelXDPHotRestartPreservedMapNames(all, 0, false, true); slices.Contains(names, kernelNatPeersMapNameV4) {
		t.Errorf("xdp preserved maps without NAT entries = %v, want no NAT maps", names)
	}
	for _, flexible := range []map[string]bool{kernelTCHotRestartFlexibleCapacityMaps(), kernelXDPHotRestartFlexibleCapacityMaps()} {
		for _, name := range []string{kernelNatPeersMapNameV4, kernelNatPeersMapNameV6, kernelTCNatPeersOldMapNameV4, kernelTCNatPeersOldMapNameV6} {
			if !flexible[name] {
				t.Errorf("%s is adopted only at the desired capacity", name)
			}
		}
	}
}

func pinTCHotRestartMapsForNATPeerTest(t *testing.T, maps map[string]*ebpf.Map) {
	t.Helper()
	bpfRoot := requireKernelHotRestartBPFStateRoot(t)
	t.Setenv(forwardBPFStateDirEnv, bpfRoot)
	t.Setenv(forwardRuntimeStateDirEnv, t.TempDir())
	clearKernelHotRestartState(kernelEngineTC)
	t.Cleanup(func() { clearKernelHotRestartState(kernelEngineTC) })
	if err := pinKernelHotRestartMaps(kernelEngineTC, maps); err != nil {
		t.Fatalf("pinKernelHotRestartMaps() error = %v", err)
	}
	meta := kernelHotRestartMetadataWithABI(kernelHotRestartTCMetadata(nil, "old-object"), kernelTCHotRestartCompatToken(false))
	if err := writeKernelHotRestartMetadata(kernelEngineTC, meta); err != nil {
		t.Fatalf("writeKernelHotRestartMetadata() error = %v", err)
	}
}

func newHotRestartFlowAndStatsMapsForNATPeerTest(t *testing.T) (*ebpf.Map, *ebpf.Map) {
	t.Helper()
	flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelFlowsMapName,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 64,
	})
	stats := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelStatsMapName,
		Type:       ebpf.PerCPUHash,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(kernelStatsValueV4{})),
		MaxEntries: 128,
	})
	return flows, stats
}

// A hot restart moves a predecessor's active banks to the successor's old
// ones; the mappings on shared ports move with the flows that hold them.
func TestLoadTCKernelHotRestartStateMovesNATPeersWithTheirBank(t *testing.T) {
	flows, stats := newHotRestartFlowAndStatsMapsForNATPeerTest(t)
	nat := newNATPortsTestMapV4(t, kernelNatPortsMapName)
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)
	pinTCHotRestartMapsForNATPeerTest(t, map[string]*ebpf.Map{
		kernelFlowsMapName:      flows,
		kernelNatPortsMapName:   nat,
		kernelNatPeersMapNameV4: peers,
		kernelStatsMapName:      stats,
	})

	state, err := loadTCKernelHotRestartState(kernelMapCapacities{Rules: 128, Flows: 128, NATPorts: 128}, kernelTCHotRestartValidationOptions("new-object", false))
	if err != nil || state == nil {
		t.Fatalf("loadTCKernelHotRestartState() = %v, %v; want promoted old-bank state", state, err)
	}
	defer state.close()

	if state.replacements[kernelTCNatPeersOldMapNameV4] == nil {
		t.Fatalf("replacements = %v, want the active peer map as the old one", state.replacementMapNames())
	}
	if state.replacements[kernelNatPeersMapNameV4] != nil {
		t.Fatalf("replacements = %v, want a fresh active peer map", state.replacementMapNames())
	}
}

// A predecessor whose old banks still drain hands both peer banks over as
// they are.
func TestLoadTCKernelHotRestartStateKeepsNATPeerBanks(t *testing.T) {
	flows, stats := newHotRestartFlowAndStatsMapsForNATPeerTest(t)
	flowsOld := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
		Name:       kernelTCFlowsOldMapNameV4,
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
		ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV4{})),
		MaxEntries: 32,
	})
	pinTCHotRestartMapsForNATPeerTest(t, map[string]*ebpf.Map{
		kernelFlowsMapName:           flows,
		kernelNatPortsMapName:        newNATPortsTestMapV4(t, kernelNatPortsMapName),
		kernelNatPeersMapNameV4:      newNATPeersTestMapV4(t, kernelNatPeersMapNameV4),
		kernelTCFlowsOldMapNameV4:    flowsOld,
		kernelTCNatPortsOldMapNameV4: newNATPortsTestMapV4(t, kernelTCNatPortsOldMapNameV4),
		kernelTCNatPeersOldMapNameV4: newNATPeersTestMapV4(t, kernelTCNatPeersOldMapNameV4),
		kernelStatsMapName:           stats,
	})

	state, err := loadTCKernelHotRestartState(kernelMapCapacities{Rules: 128, Flows: 128, NATPorts: 128}, kernelTCHotRestartValidationOptions("new-object", false))
	if err != nil || state == nil {
		t.Fatalf("loadTCKernelHotRestartState() = %v, %v; want the preserved dual-bank state", state, err)
	}
	defer state.close()
	for _, name := range []string{kernelNatPeersMapNameV4, kernelTCNatPeersOldMapNameV4} {
		if state.replacements[name] == nil {
			t.Fatalf("replacements = %v, want %s", state.replacementMapNames(), name)
		}
	}
}

// NAT entries count mappings: exclusive ports and peer entries. The shared
// ports the peers use are reported apart and count as no mapping.
func TestCountKernelRuntimeNATEntriesCountsMappings(t *testing.T) {
	ports := newNATPortsTestMapV4(t, kernelNatPortsMapNameV4)
	peers := newNATPeersTestMapV4(t, kernelNatPeersMapNameV4)
	oldPeers := newNATPeersTestMapV4(t, kernelTCNatPeersOldMapNameV4)
	key := func(port uint16) tcNATPortKeyV4 {
		return tcNATPortKeyV4{IfIndex: 3, NATAddr: 0xc6130001, NATPort: port, Proto: unix.IPPROTO_TCP}
	}
	for port, mode := range map[uint16]uint32{24001: kernelNATPortExclusive, 24002: kernelNATPortShared, 24003: kernelNATPortShared, 24004: kernelNATPortDraining} {
		if err := ports.Put(key(port), tcNATPortValue{RuleID: 1, Mode: mode, SessionID: uint64(port)}); err != nil {
			t.Fatal(err)
		}
	}
	for i, m := range []*ebpf.Map{peers, peers, oldPeers} {
		peer := tcNATPeerKeyV4{Port: key(24002), PeerAddr: 0xc6130002 + uint32(i), PeerPort: 443}
		if err := m.Put(peer, tcNATPeerValue{RuleID: 1, SessionID: uint64(100 + i)}); err != nil {
			t.Fatal(err)
		}
	}
	refs := kernelRuntimeMapRefs{natV4: ports, natPeersV4: peers, natPeersOldV4: oldPeers}

	if got, err := countKernelRuntimeNATEntriesExact(refs); err != nil || got != 4 {
		t.Fatalf("countKernelRuntimeNATEntriesExact() = %d, %v; want 4 (one exclusive port, three peers)", got, err)
	}
	var counts kernelRuntimeMapCountSnapshot
	if !countKernelRuntimeNATEntryDetails(refs, &counts) {
		t.Fatal("countKernelRuntimeNATEntryDetails() could not read the maps")
	}
	if counts.natEntries != 4 || counts.natEntriesV4 != 4 || counts.natEntriesV6 != 0 || counts.natPeerEntries != 3 || counts.natSharedPorts != 3 {
		t.Fatalf("detail counts = %+v, want 4 mappings of which 3 peers, on 3 shared or draining ports", counts)
	}
	if got, err := countKernelNATMapEntries(ports); err != nil || got != 1 {
		t.Fatalf("countKernelNATMapEntries() = %d, %v; want only the exclusive port", got, err)
	}
}
