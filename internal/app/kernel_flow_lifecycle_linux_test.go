//go:build linux

package app

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestKernelFlowLifecycleMatrixAcrossBanks(t *testing.T) {
	engines := []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	}

	for _, engine := range engines {
		for _, bank := range []string{"active", "old"} {
			t.Run(engine.name+"/"+bank, func(t *testing.T) {
				flowValueSize := uint32(unsafe.Sizeof(tcFlowValueV4{}))
				if engine.xdp {
					flowValueSize = uint32(unsafe.Sizeof(xdpFlowValueV4{}))
				}
				flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
					Name:       "life_flow_v4",
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV4{})),
					ValueSize:  flowValueSize,
					MaxEntries: 32,
				})
				nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
					Name:       "life_nat_v4",
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV4{})),
					ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
					MaxEntries: 16,
				})

				putFlow := func(key tcFlowKeyV4, value tcFlowValueV4) {
					t.Helper()
					if !engine.xdp {
						if err := flows.Put(key, value); err != nil {
							t.Fatalf("put tc flow: %v", err)
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
						t.Fatalf("put xdp flow: %v", err)
					}
				}

				type fullNATSession struct {
					reply tcFlowKeyV4
					front tcFlowKeyV4
					nat   tcNATPortKeyV4
				}
				putFullNATSession := func(proto uint8, ruleID uint32, sessionID uint64, lastSeenNS uint64) fullNATSession {
					t.Helper()
					offset := uint32(sessionID)
					value := tcFlowValueV4{
						RuleID:       ruleID,
						FrontAddr:    0x0a100000 + offset,
						ClientAddr:   0x0a200000 + offset,
						NATAddr:      0x0a300000 + offset,
						InIfIndex:    5,
						FrontPort:    uint16(10000 + offset),
						ClientPort:   uint16(20000 + offset),
						NATPort:      uint16(30000 + offset),
						Flags:        kernelFlowFlagFullNAT | kernelFlowFlagCounted,
						LastSeenNS:   lastSeenNS,
						RuleRevision: uint64(ruleID)*100 + 1,
						SessionID:    sessionID,
					}
					if proto == unix.IPPROTO_TCP {
						value.Flags |= kernelFlowFlagReplySeen
					}
					replyKey := tcFlowKeyV4{
						IfIndex: 9,
						SrcAddr: 0x0a400000 + offset,
						DstAddr: value.NATAddr,
						SrcPort: uint16(40000 + offset),
						DstPort: value.NATPort,
						Proto:   proto,
					}
					frontKey := tcFlowKeyV4{
						IfIndex: value.InIfIndex,
						SrcAddr: value.ClientAddr,
						DstAddr: value.FrontAddr,
						SrcPort: value.ClientPort,
						DstPort: value.FrontPort,
						Proto:   proto,
					}
					putFlow(replyKey, value)
					frontValue := value
					frontValue.Flags |= kernelFlowFlagFrontEntry
					putFlow(frontKey, frontValue)
					natKey := tcNATPortKeyV4{
						IfIndex: replyKey.IfIndex,
						NATAddr: value.NATAddr,
						NATPort: value.NATPort,
						Proto:   proto,
					}
					if err := nat.Put(natKey, tcNATPortValue{RuleID: ruleID, SessionID: sessionID}); err != nil {
						t.Fatalf("put nat reservation: %v", err)
					}
					return fullNATSession{reply: replyKey, front: frontKey, nat: natKey}
				}

				nowNS := uint64(kernelTCPFlowIdleTimeout + kernelUDPFlowIdleTimeout + 1000)
				liveTCP := putFullNATSession(unix.IPPROTO_TCP, 101, 101, nowNS-kernelTCPFlowIdleTimeout)
				staleTCP := putFullNATSession(unix.IPPROTO_TCP, 102, 102, nowNS-kernelTCPFlowIdleTimeout-1)
				liveUDP := putFullNATSession(unix.IPPROTO_UDP, 201, 201, nowNS-kernelUDPFlowIdleTimeout)
				staleUDP := putFullNATSession(unix.IPPROTO_UDP, 202, 202, nowNS-kernelUDPFlowIdleTimeout-1)

				liveICMPKey := tcFlowKeyV4{IfIndex: 7, SrcAddr: 1, DstAddr: 2, SrcPort: 301, Proto: unix.IPPROTO_ICMP}
				staleICMPKey := tcFlowKeyV4{IfIndex: 7, SrcAddr: 3, DstAddr: 4, SrcPort: 302, Proto: unix.IPPROTO_ICMP}
				putFlow(liveICMPKey, tcFlowValueV4{
					RuleID: 301, Flags: kernelFlowFlagCounted, LastSeenNS: nowNS - kernelICMPFlowIdleTimeout,
					RuleRevision: 30101, SessionID: 301,
				})
				putFlow(staleICMPKey, tcFlowValueV4{
					RuleID: 302, Flags: kernelFlowFlagCounted, LastSeenNS: nowNS - kernelICMPFlowIdleTimeout - 1,
					RuleRevision: 30201, SessionID: 302,
				})

				metrics := kernelFlowPruneMetrics{Budget: 32}
				var (
					corrections map[uint32]kernelRuleStats
					err         error
				)
				if engine.xdp {
					corrections, metrics, err = pruneStaleXDPFlowsFullInCollection(nil, flows, nat, nowNS, true, metrics)
				} else {
					corrections, metrics, err = pruneStaleKernelFlowsFullInCollection(nil, flows, nat, nowNS, true, metrics)
				}
				if err != nil {
					t.Fatalf("prune lifecycle matrix: %v", err)
				}
				if metrics.Scanned != 10 || metrics.Deleted != 5 {
					t.Fatalf("prune metrics scanned/deleted = %d/%d, want 10/5", metrics.Scanned, metrics.Deleted)
				}
				for _, item := range []struct {
					ruleID uint32
					field  int64
				}{
					{ruleID: 102, field: corrections[102].TCPActiveConns},
					{ruleID: 202, field: corrections[202].UDPNatEntries},
					{ruleID: 302, field: corrections[302].ICMPNatEntries},
				} {
					if item.field != -1 {
						t.Fatalf("rule %d correction = %d, want -1", item.ruleID, item.field)
					}
				}

				countFlows := func() int {
					t.Helper()
					if engine.xdp {
						count, err := countXDPFlowMapEntries(flows)
						if err != nil {
							t.Fatalf("count xdp flows: %v", err)
						}
						return count
					}
					count, err := countKernelFlowMapEntries(flows)
					if err != nil {
						t.Fatalf("count tc flows: %v", err)
					}
					return count
				}
				if got := countFlows(); got != 5 {
					t.Fatalf("remaining flows = %d, want 5", got)
				}
				if got, err := countKernelNATMapEntries(nat); err != nil {
					t.Fatalf("count remaining nat reservations: %v", err)
				} else if got != 2 {
					t.Fatalf("remaining nat reservations = %d, want 2", got)
				}
				for _, key := range []tcFlowKeyV4{liveTCP.reply, liveTCP.front, liveUDP.reply, liveUDP.front, liveICMPKey} {
					if _, ok, err := lookupKernelFlowValue(flows, key); err != nil || !ok {
						t.Fatalf("live flow %+v missing after prune: ok=%t err=%v", key, ok, err)
					}
				}
				for _, key := range []tcFlowKeyV4{staleTCP.reply, staleTCP.front, staleUDP.reply, staleUDP.front, staleICMPKey} {
					if _, ok, err := lookupKernelFlowValue(flows, key); err != nil || ok {
						t.Fatalf("stale flow %+v survived prune: ok=%t err=%v", key, ok, err)
					}
				}
				for _, key := range []tcNATPortKeyV4{liveTCP.nat, liveUDP.nat} {
					var value tcNATPortValue
					if err := nat.Lookup(key, &value); err != nil {
						t.Fatalf("live nat reservation %+v missing: %v", key, err)
					}
				}

				refs := kernelRuntimeMapRefs{}
				if bank == "active" {
					refs.flowsV4 = flows
					refs.natV4 = nat
				} else {
					refs.flowsOldV4 = flows
					refs.natOldV4 = nat
				}
				snapshot := func() kernelFlowLiveStateSnapshot {
					t.Helper()
					var (
						live kernelFlowLiveStateSnapshot
						err  error
					)
					if engine.xdp {
						live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs, true)
					} else {
						live, err = snapshotKernelLiveStateFromRuntimeMapRefs(refs, true)
					}
					if err != nil {
						t.Fatalf("snapshot lifecycle maps: %v", err)
					}
					return live
				}
				live := snapshot()
				if live.FlowEntries != 5 {
					t.Fatalf("snapshot flow entries = %d, want 5", live.FlowEntries)
				}
				if bank == "active" && (len(live.NATByBank.activeV4) != 2 || len(live.NATByBank.oldV4) != 0) {
					t.Fatalf("active/old owner counts = %d/%d, want 2/0", len(live.NATByBank.activeV4), len(live.NATByBank.oldV4))
				}
				if bank == "old" && (len(live.NATByBank.activeV4) != 0 || len(live.NATByBank.oldV4) != 2) {
					t.Fatalf("active/old owner counts = %d/%d, want 0/2", len(live.NATByBank.activeV4), len(live.NATByBank.oldV4))
				}

				const recoveredSessionID = uint64(401)
				recoveredNATKey := tcNATPortKeyV4{
					IfIndex: 10, NATAddr: 0x0a500001, NATPort: 30401, Proto: unix.IPPROTO_TCP,
				}
				if err := nat.Put(recoveredNATKey, tcNATPortValue{RuleID: 401, SessionID: recoveredSessionID}); err != nil {
					t.Fatalf("put recoverable orphan nat reservation: %v", err)
				}
				live = snapshot()
				natEntries, deleted, pruneState, err := pruneOrphanKernelNATBanks(refs, live.NATByBank, kernelNATPruneState{})
				if err != nil {
					t.Fatalf("mark orphan nat reservation: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("orphan mark entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}

				recoveredFlowKey := tcFlowKeyV4{
					IfIndex: recoveredNATKey.IfIndex, SrcAddr: 50, DstAddr: recoveredNATKey.NATAddr,
					SrcPort: 443, DstPort: recoveredNATKey.NATPort, Proto: recoveredNATKey.Proto,
				}
				putFlow(recoveredFlowKey, tcFlowValueV4{
					RuleID: 401, NATAddr: recoveredNATKey.NATAddr, NATPort: recoveredNATKey.NATPort,
					Flags:      kernelFlowFlagFullNAT | kernelFlowFlagCounted | kernelFlowFlagReplySeen,
					LastSeenNS: nowNS, RuleRevision: 40101, SessionID: recoveredSessionID,
				})
				live = snapshot()
				natEntries, deleted, pruneState, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("cancel recovered orphan deletion: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("orphan recovery entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}

				if err := flows.Delete(recoveredFlowKey); err != nil {
					t.Fatalf("remove recovered flow for orphan confirmation: %v", err)
				}
				live = snapshot()
				natEntries, deleted, pruneState, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("remark missing orphan nat reservation: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("orphan remark entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}
				natEntries, deleted, _, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("confirm missing orphan nat reservation: %v", err)
				}
				if natEntries != 2 || deleted != 1 {
					t.Fatalf("orphan confirmation entries/deleted = %d/%d, want 2/1", natEntries, deleted)
				}
				var recoveredNAT tcNATPortValue
				if err := nat.Lookup(recoveredNATKey, &recoveredNAT); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("confirmed orphan nat reservation lookup error = %v, want key not exist (value=%+v)", err, recoveredNAT)
				}
			})
		}
	}
}

func TestKernelIPv6FlowLifecycleMatrixAcrossBanks(t *testing.T) {
	engines := []struct {
		name string
		xdp  bool
	}{
		{name: "tc"},
		{name: "xdp", xdp: true},
	}

	for _, engine := range engines {
		for _, bank := range []string{"active", "old"} {
			t.Run(engine.name+"/"+bank, func(t *testing.T) {
				flows := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
					Name:       "life_flow_v6",
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(tcFlowKeyV6{})),
					ValueSize:  uint32(unsafe.Sizeof(tcFlowValueV6{})),
					MaxEntries: 32,
				})
				nat := newKernelHotRestartTestMap(t, &ebpf.MapSpec{
					Name:       "life_nat_v6",
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(tcNATPortKeyV6{})),
					ValueSize:  uint32(unsafe.Sizeof(tcNATPortValue{})),
					MaxEntries: 16,
				})

				addr := func(group byte, host uint64) [16]byte {
					return [16]byte{0x20, 0x01, 0x0d, 0xb8, group, byte(host >> 8), byte(host)}
				}
				type fullNATSession struct {
					reply tcFlowKeyV6
					front tcFlowKeyV6
					nat   tcNATPortKeyV6
				}
				putFullNATSession := func(proto uint8, ruleID uint32, sessionID uint64, lastSeenNS uint64) fullNATSession {
					t.Helper()
					value := tcFlowValueV6{
						RuleID:       ruleID,
						FrontAddr:    addr(1, sessionID),
						ClientAddr:   addr(2, sessionID),
						NATAddr:      addr(3, sessionID),
						InIfIndex:    5,
						FrontPort:    uint16(10000 + sessionID),
						ClientPort:   uint16(20000 + sessionID),
						NATPort:      uint16(30000 + sessionID),
						Flags:        kernelFlowFlagFullNAT | kernelFlowFlagCounted,
						LastSeenNS:   lastSeenNS,
						RuleRevision: uint64(ruleID)*100 + 1,
						SessionID:    sessionID,
					}
					if proto == unix.IPPROTO_TCP {
						value.Flags |= kernelFlowFlagReplySeen
					}
					replyKey := tcFlowKeyV6{
						IfIndex: 9,
						SrcAddr: addr(4, sessionID),
						DstAddr: value.NATAddr,
						SrcPort: uint16(40000 + sessionID),
						DstPort: value.NATPort,
						Proto:   proto,
					}
					frontKey := tcFlowKeyV6{
						IfIndex: value.InIfIndex,
						SrcAddr: value.ClientAddr,
						DstAddr: value.FrontAddr,
						SrcPort: value.ClientPort,
						DstPort: value.FrontPort,
						Proto:   proto,
					}
					if err := flows.Put(replyKey, value); err != nil {
						t.Fatalf("put IPv6 reply flow: %v", err)
					}
					frontValue := value
					frontValue.Flags |= kernelFlowFlagFrontEntry
					if err := flows.Put(frontKey, frontValue); err != nil {
						t.Fatalf("put IPv6 front flow: %v", err)
					}
					natKey := tcNATPortKeyV6{
						IfIndex: replyKey.IfIndex,
						NATAddr: value.NATAddr,
						NATPort: value.NATPort,
						Proto:   proto,
					}
					if err := nat.Put(natKey, tcNATPortValue{RuleID: ruleID, SessionID: sessionID}); err != nil {
						t.Fatalf("put IPv6 nat reservation: %v", err)
					}
					return fullNATSession{reply: replyKey, front: frontKey, nat: natKey}
				}

				nowNS := uint64(kernelTCPFlowIdleTimeout + kernelUDPFlowIdleTimeout + 1000)
				liveTCP := putFullNATSession(unix.IPPROTO_TCP, 501, 501, nowNS-kernelTCPFlowIdleTimeout)
				staleTCP := putFullNATSession(unix.IPPROTO_TCP, 502, 502, nowNS-kernelTCPFlowIdleTimeout-1)
				liveUDP := putFullNATSession(unix.IPPROTO_UDP, 601, 601, nowNS-kernelUDPFlowIdleTimeout)
				staleUDP := putFullNATSession(unix.IPPROTO_UDP, 602, 602, nowNS-kernelUDPFlowIdleTimeout-1)

				metrics := kernelFlowPruneMetrics{Budget: 32}
				corrections, metrics, err := pruneStaleKernelFlowsV6FullInCollection(nil, flows, nat, nowNS, true, metrics)
				if err != nil {
					t.Fatalf("prune IPv6 lifecycle matrix: %v", err)
				}
				if metrics.Scanned != 8 || metrics.Deleted != 4 {
					t.Fatalf("IPv6 prune metrics scanned/deleted = %d/%d, want 8/4", metrics.Scanned, metrics.Deleted)
				}
				if got := corrections[502].TCPActiveConns; got != -1 {
					t.Fatalf("IPv6 TCP correction = %d, want -1", got)
				}
				if got := corrections[602].UDPNatEntries; got != -1 {
					t.Fatalf("IPv6 UDP correction = %d, want -1", got)
				}
				if got, err := countKernelFlowMapEntriesV6(flows); err != nil {
					t.Fatalf("count remaining IPv6 flows: %v", err)
				} else if got != 4 {
					t.Fatalf("remaining IPv6 flows = %d, want 4", got)
				}
				if got, err := countKernelNATMapEntriesV6(nat); err != nil {
					t.Fatalf("count remaining IPv6 nat reservations: %v", err)
				} else if got != 2 {
					t.Fatalf("remaining IPv6 nat reservations = %d, want 2", got)
				}
				for _, key := range []tcFlowKeyV6{liveTCP.reply, liveTCP.front, liveUDP.reply, liveUDP.front} {
					var value tcFlowValueV6
					if err := flows.Lookup(key, &value); err != nil {
						t.Fatalf("live IPv6 flow %+v missing after prune: %v", key, err)
					}
				}
				for _, key := range []tcFlowKeyV6{staleTCP.reply, staleTCP.front, staleUDP.reply, staleUDP.front} {
					var value tcFlowValueV6
					if err := flows.Lookup(key, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("stale IPv6 flow %+v survived prune: %v", key, err)
					}
				}

				refs := kernelRuntimeMapRefs{}
				if bank == "active" {
					refs.flowsV6 = flows
					refs.natV6 = nat
				} else {
					refs.flowsOldV6 = flows
					refs.natOldV6 = nat
				}
				snapshot := func() kernelFlowLiveStateSnapshot {
					t.Helper()
					var (
						live kernelFlowLiveStateSnapshot
						err  error
					)
					if engine.xdp {
						live, err = snapshotXDPKernelLiveStateFromRuntimeMapRefs(refs, true)
					} else {
						live, err = snapshotKernelLiveStateFromRuntimeMapRefs(refs, true)
					}
					if err != nil {
						t.Fatalf("snapshot IPv6 lifecycle maps: %v", err)
					}
					return live
				}
				live := snapshot()
				if live.FlowEntries != 4 {
					t.Fatalf("IPv6 snapshot flow entries = %d, want 4", live.FlowEntries)
				}
				if bank == "active" && (len(live.NATByBank.activeV6) != 2 || len(live.NATByBank.oldV6) != 0) {
					t.Fatalf("IPv6 active/old owner counts = %d/%d, want 2/0", len(live.NATByBank.activeV6), len(live.NATByBank.oldV6))
				}
				if bank == "old" && (len(live.NATByBank.activeV6) != 0 || len(live.NATByBank.oldV6) != 2) {
					t.Fatalf("IPv6 active/old owner counts = %d/%d, want 0/2", len(live.NATByBank.activeV6), len(live.NATByBank.oldV6))
				}

				const recoveredSessionID = uint64(701)
				recoveredNATKey := tcNATPortKeyV6{
					IfIndex: 10, NATAddr: addr(5, recoveredSessionID), NATPort: 30701, Proto: unix.IPPROTO_TCP,
				}
				if err := nat.Put(recoveredNATKey, tcNATPortValue{RuleID: 701, SessionID: recoveredSessionID}); err != nil {
					t.Fatalf("put recoverable IPv6 nat reservation: %v", err)
				}
				live = snapshot()
				natEntries, deleted, pruneState, err := pruneOrphanKernelNATBanks(refs, live.NATByBank, kernelNATPruneState{})
				if err != nil {
					t.Fatalf("mark orphan IPv6 nat reservation: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("IPv6 orphan mark entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}

				recoveredFlowKey := tcFlowKeyV6{
					IfIndex: recoveredNATKey.IfIndex, SrcAddr: addr(6, recoveredSessionID), DstAddr: recoveredNATKey.NATAddr,
					SrcPort: 443, DstPort: recoveredNATKey.NATPort, Proto: recoveredNATKey.Proto,
				}
				if err := flows.Put(recoveredFlowKey, tcFlowValueV6{
					RuleID: 701, NATAddr: recoveredNATKey.NATAddr, NATPort: recoveredNATKey.NATPort,
					Flags:      kernelFlowFlagFullNAT | kernelFlowFlagCounted | kernelFlowFlagReplySeen,
					LastSeenNS: nowNS, RuleRevision: 70101, SessionID: recoveredSessionID,
				}); err != nil {
					t.Fatalf("put recovered IPv6 flow: %v", err)
				}
				live = snapshot()
				natEntries, deleted, pruneState, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("cancel recovered IPv6 orphan deletion: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("IPv6 orphan recovery entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}

				if err := flows.Delete(recoveredFlowKey); err != nil {
					t.Fatalf("remove recovered IPv6 flow for orphan confirmation: %v", err)
				}
				live = snapshot()
				natEntries, deleted, pruneState, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("remark missing IPv6 orphan nat reservation: %v", err)
				}
				if natEntries != 3 || deleted != 0 {
					t.Fatalf("IPv6 orphan remark entries/deleted = %d/%d, want 3/0", natEntries, deleted)
				}
				natEntries, deleted, _, err = pruneOrphanKernelNATBanks(refs, live.NATByBank, pruneState)
				if err != nil {
					t.Fatalf("confirm missing IPv6 orphan nat reservation: %v", err)
				}
				if natEntries != 2 || deleted != 1 {
					t.Fatalf("IPv6 orphan confirmation entries/deleted = %d/%d, want 2/1", natEntries, deleted)
				}
				var recoveredNAT tcNATPortValue
				if err := nat.Lookup(recoveredNATKey, &recoveredNAT); !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("confirmed IPv6 orphan lookup error = %v, want key not exist (value=%+v)", err, recoveredNAT)
				}
			})
		}
	}
}
