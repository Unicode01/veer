//go:build linux

package app

import (
	"bytes"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// A full-NAT rule toward a bridge reaches its backend either through the
// bridge itself or straight through the member port that the bridge learned
// for the backend. The two paths are different flow contracts: the datapath
// keys reply flows and NAT ports by the out interface and drops a session
// whose revision no longer matches its rule. Switching paths therefore ends
// every session on the old one. That happens when a recreated member port has
// not been learned yet (sessions start on the bridge path, then the member
// path becomes resolvable) and when the bridge forgets an idle backend (the
// member path stops resolving while its sessions are still open).
//
// kernelBridgePathHold keeps such a rule on the path its live sessions use.
// The bridge path always works; a member path is kept only while the member is
// still in the bridge and the neighbor table does not name another MAC for
// the backend. Once those sessions end, maintenance asks for a reconcile and
// the rule moves to the path it would have taken.
type kernelBridgePathHold struct {
	live  func(ruleID uint32) map[uint64]struct{}
	held  kernelFlowRevisionSet
	lines []string
}

type kernelFlowRevisionKey struct {
	RuleID   uint32
	Revision uint64
}

type kernelFlowRevisionSet map[kernelFlowRevisionKey]struct{}

func newKernelBridgePathHold(live func(ruleID uint32) map[uint64]struct{}) *kernelBridgePathHold {
	return &kernelBridgePathHold{live: live}
}

func (hold *kernelBridgePathHold) heldRevisions() kernelFlowRevisionSet {
	if hold == nil || len(hold.held) == 0 {
		return nil
	}
	return hold.held
}

// apply returns the rule's items re-prepared on the path its live sessions
// use, or false when the prepared items can stay as they are.
func (hold *kernelBridgePathHold) apply(ctx *kernelPrepareContext, rule Rule, items []preparedKernelRule, previousByKey map[kernelRuleMatchKey][]preparedKernelRule) ([]preparedKernelRule, bool) {
	if hold == nil || hold.live == nil || ctx == nil || len(items) == 0 || rule.Transparent ||
		isKernelEgressNATRule(rule) || isKernelEgressNATPassthroughRule(rule) ||
		rule.ID <= 0 || rule.ID > int64(^uint32(0)) {
		return nil, false
	}
	next := items[0]
	if kernelPreparedRuleFamily(next) != ipFamilyIPv4 || next.value.Flags&kernelRuleFlagFullNAT == 0 {
		return nil, false
	}
	ruleID := uint32(rule.ID)
	foreign := hold.live(ruleID)
	if len(foreign) == 0 {
		return nil, false
	}
	foreign = withoutPreparedKernelRuleRevisions(foreign, items)
	if len(foreign) == 0 {
		return nil, false
	}

	outLink, err := ctx.linkByName(rule.OutInterface)
	if err != nil || outLink == nil || outLink.Attrs() == nil || !isXDPBridgeLink(outLink) {
		return nil, false
	}
	bridgeIndex := outLink.Attrs().Index
	var previous []preparedKernelRule
	for _, item := range previousByKey[kernelRuleMatchKeyFor(rule)] {
		if item.rule.ID == rule.ID {
			previous = append(previous, item)
		}
	}
	path, ok := heldKernelBridgePath(next, previous, bridgeIndex, rule.OutIP)
	if !ok {
		return nil, false
	}

	if ctx.heldPaths == nil {
		ctx.heldPaths = make(map[int64]preparedKernelPath)
	}
	ctx.heldPaths[rule.ID] = path
	held, err := prepareKernelRule(ctx, rule)
	delete(ctx.heldPaths, rule.ID)
	if err != nil || len(held) == 0 {
		return nil, false
	}
	var revisions []uint64
	for i := range held {
		if err := assignPreparedKernelRuleRevision(&held[i]); err != nil {
			return nil, false
		}
		revisions = append(revisions, held[i].value.Revision)
	}
	// Holding only helps when the held path is the contract the sessions use;
	// a rule whose backend or NAT address changed has nothing to hold.
	for _, revision := range revisions {
		if _, ok := foreign[revision]; !ok {
			return nil, false
		}
	}
	if hold.held == nil {
		hold.held = make(kernelFlowRevisionSet)
	}
	for _, revision := range revisions {
		hold.held[kernelFlowRevisionKey{RuleID: ruleID, Revision: revision}] = struct{}{}
	}
	hold.lines = append(hold.lines, fmt.Sprintf("kernel dataplane: rule %d keeps its %s path while sessions use it", rule.ID, describeKernelBridgePath(path, bridgeIndex)))
	return held, true
}

// logKernelPathHolds logs holds that were not in effect at the previous
// reconcile, so a lasting hold is reported once.
func logKernelPathHolds(previous map[string]struct{}, hold *kernelBridgePathHold) map[string]struct{} {
	if hold == nil || len(hold.lines) == 0 {
		return nil
	}
	current := make(map[string]struct{}, len(hold.lines))
	for _, line := range hold.lines {
		current[line] = struct{}{}
		if _, ok := previous[line]; !ok {
			log.Print(line)
		}
	}
	return current
}

func withoutPreparedKernelRuleRevisions(revisions map[uint64]struct{}, items []preparedKernelRule) map[uint64]struct{} {
	out := make(map[uint64]struct{}, len(revisions))
	for revision := range revisions {
		out[revision] = struct{}{}
	}
	for _, item := range items {
		if revision, err := preparedKernelRuleFlowRevision(item); err == nil {
			delete(out, revision)
		}
	}
	return out
}

// heldKernelBridgePath returns the path to hold instead of next's.
func heldKernelBridgePath(next preparedKernelRule, previous []preparedKernelRule, bridgeIndex int, backendIP string) (preparedKernelPath, bool) {
	nextOnMember := next.value.Flags&kernelRuleFlagBridgeL2 != 0
	if nextOnMember {
		// The bridge path never depends on what the bridge learned.
		return preparedKernelPath{outIfIndex: bridgeIndex}, true
	}
	if next.outIfIndex != bridgeIndex {
		return preparedKernelPath{}, false
	}
	for _, item := range previous {
		if item.value.Flags&kernelRuleFlagBridgeL2 == 0 || item.outIfIndex <= 0 {
			continue
		}
		member, err := netlink.LinkByIndex(item.outIfIndex)
		if err != nil || member == nil || member.Attrs() == nil || member.Attrs().MasterIndex != bridgeIndex {
			return preparedKernelPath{}, false
		}
		if backendMovedFromMAC(bridgeIndex, backendIP, item.value.DstMAC) {
			return preparedKernelPath{}, false
		}
		return preparedKernelPath{
			outIfIndex: item.outIfIndex,
			flags:      kernelRuleFlagBridgeL2,
			srcMAC:     item.value.SrcMAC,
			dstMAC:     item.value.DstMAC,
		}, true
	}
	return preparedKernelPath{}, false
}

// backendMovedFromMAC reports whether the bridge's neighbor table now names a
// different MAC for the backend. A missing entry is not a move: idle backends
// age out of the tables while their sessions are still open.
func backendMovedFromMAC(bridgeIndex int, backendIP string, mac [6]byte) bool {
	ip := net.ParseIP(backendIP).To4()
	if ip == nil {
		return true
	}
	target, err := lookupBridgeNeighborTarget(bridgeIndex, ip)
	if err != nil || len(target.mac) == 0 {
		return false
	}
	current := hardwareAddrToArray(target.mac)
	return !bytes.Equal(current[:], mac[:])
}

func describeKernelBridgePath(path preparedKernelPath, bridgeIndex int) string {
	if path.outIfIndex == bridgeIndex {
		return fmt.Sprintf("bridge (%s)", kernelRuntimeInterfaceLabel(bridgeIndex))
	}
	return fmt.Sprintf("member port (%s)", kernelRuntimeInterfaceLabel(path.outIfIndex))
}

// scanKernelFlowRevisions lists the rule revisions that still own flows.
func scanKernelFlowRevisions(refs kernelRuntimeMapRefs) (map[uint32]map[uint64]struct{}, error) {
	out := make(map[uint32]map[uint64]struct{})
	add := func(ruleID uint32, revision uint64) {
		if ruleID == 0 || revision == 0 {
			return
		}
		revisions := out[ruleID]
		if revisions == nil {
			revisions = make(map[uint64]struct{})
			out[ruleID] = revisions
		}
		revisions[revision] = struct{}{}
	}
	for _, flows := range []*ebpf.Map{refs.flowsV4, refs.flowsOldV4} {
		if flows == nil {
			continue
		}
		iter := flows.Iterate()
		var key tcFlowKeyV4
		var value tcFlowValueV4
		for iter.Next(&key, &value) {
			add(value.RuleID, value.RuleRevision)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate IPv4 flows for live revisions: %w", err)
		}
	}
	for _, flows := range []*ebpf.Map{refs.flowsV6, refs.flowsOldV6} {
		if flows == nil {
			continue
		}
		iter := flows.Iterate()
		var key tcFlowKeyV6
		var value tcFlowValueV6
		for iter.Next(&key, &value) {
			add(value.RuleID, value.RuleRevision)
		}
		if err := iter.Err(); err != nil {
			return nil, fmt.Errorf("iterate IPv6 flows for live revisions: %w", err)
		}
	}
	return out, nil
}

// newBridgePathHoldLocked scans the flow maps at most once per reconcile, and
// only when a rule could switch bridge paths.
func (rt *linuxKernelRuleRuntime) newBridgePathHoldLocked() *kernelBridgePathHold {
	if rt.coll == nil {
		return nil
	}
	refs := kernelRuntimeMapRefsFromCollection(rt.coll)
	var live map[uint32]map[uint64]struct{}
	scanned := false
	return newKernelBridgePathHold(func(ruleID uint32) map[uint64]struct{} {
		if !scanned {
			scanned = true
			var err error
			live, err = scanKernelFlowRevisions(refs)
			if err != nil {
				log.Printf("kernel dataplane reconcile: read live flow revisions for bridge path hold: %v", err)
				live = nil
			}
		}
		return live[ruleID]
	})
}

// checkBridgePathHoldsLocked asks for a reconcile once a held path has no
// sessions left, so the rule can move to the path it would have taken.
func (rt *linuxKernelRuleRuntime) checkBridgePathHoldsLocked() {
	if len(rt.pathHolds) == 0 || rt.coll == nil {
		return
	}
	live, err := scanKernelFlowRevisions(kernelRuntimeMapRefsFromCollection(rt.coll))
	if err != nil {
		log.Printf("kernel dataplane maintenance: read live flow revisions for bridge path hold: %v", err)
		return
	}
	for key := range rt.pathHolds {
		if _, ok := live[key.RuleID][key.Revision]; ok {
			continue
		}
		log.Printf("kernel dataplane maintenance: sessions holding rule %d on its bridge path ended, re-evaluating its path", key.RuleID)
		rt.pathHolds = nil
		rt.pathHoldReleased = true
		return
	}
}

func (rt *linuxKernelRuleRuntime) takeKernelPathHoldRelease() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	released := rt.pathHoldReleased
	rt.pathHoldReleased = false
	return released
}

func (rt *orderedKernelRuleRuntime) takeKernelPathHoldRelease() bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	released := false
	for _, entry := range rt.entries {
		if releaser, ok := entry.rt.(kernelPathHoldReleaser); ok && releaser.takeKernelPathHoldRelease() {
			released = true
		}
	}
	return released
}
