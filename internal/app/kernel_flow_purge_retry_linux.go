//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/vishvananda/netlink"
)

// Some rules leave the dataplane only for a moment. A drain removes every rule
// at once, and an egress NAT whose exit loses its address is replaced by a drop
// guard until the address returns. Their flows stay for this grace so that a
// rule coming back unchanged keeps its connections. A rule that comes back with
// a different contract, or not at all, has its flows purged.
const kernelDeferredFlowGrace = 30 * time.Second

type kernelDeferredFlowRule[T any] struct {
	rule T
	at   time.Time
}

// kernelDeferredFlowRules holds rules that left the dataplane but whose flows
// were kept. They are part of the next reconcile's purge baseline; without
// them the flows of a rule that returns changed, or never returns, would only
// leave by idle timeout.
type kernelDeferredFlowRules[T any] struct {
	items []kernelDeferredFlowRule[T]
}

func (d *kernelDeferredFlowRules[T]) record(rules []T, now time.Time) {
	for _, rule := range rules {
		d.items = append(d.items, kernelDeferredFlowRule[T]{rule: rule, at: now})
	}
}

func (d *kernelDeferredFlowRules[T]) rules() []T {
	if len(d.items) == 0 {
		return nil
	}
	out := make([]T, 0, len(d.items))
	for _, item := range d.items {
		out = append(out, item.rule)
	}
	return out
}

// baseline returns the rules whose flows may still be in the maps: the
// deferred rules followed by current.
func (d *kernelDeferredFlowRules[T]) baseline(current []T) []T {
	if len(d.items) == 0 {
		return current
	}
	return append(d.rules(), current...)
}

// expire removes the rules whose grace ran out and returns them.
func (d *kernelDeferredFlowRules[T]) expire(now time.Time) []T {
	var expired []T
	kept := d.items[:0]
	for _, item := range d.items {
		if now.Sub(item.at) >= kernelDeferredFlowGrace {
			expired = append(expired, item.rule)
			continue
		}
		kept = append(kept, item)
	}
	d.items = kept
	if len(d.items) == 0 {
		d.items = nil
	}
	return expired
}

func (d *kernelDeferredFlowRules[T]) replace(items []kernelDeferredFlowRule[T]) {
	d.items = append([]kernelDeferredFlowRule[T](nil), items...)
}

func (d *kernelDeferredFlowRules[T]) reset() {
	d.items = nil
}

// kernelFlowPurgePlan is what a reconcile does with the flows of the rules it
// replaces: purge targets now, and rules whose purge waits for the grace.
type kernelFlowPurgePlan struct {
	targets  map[kernelFlowPurgeTarget]struct{}
	deferred []kernelDeferredFlowRule[preparedKernelRule]
}

type kernelGuardedRuleKey struct {
	match  kernelRuleMatchKey
	ruleID int64
}

// planPreparedKernelRuleFlowPurge decides what happens to the flows of the
// deferred and current rules when next replaces them. An egress NAT whose exit
// lost its address becomes a drop guard; the flows of its last working
// contract stay for the grace, so an address that comes back unchanged costs
// no connection. The guard drops forward traffic meanwhile, so nothing leaks
// through the host's default route. Deferral needs every interface the flows
// are keyed on to still exist: flows of a deleted interface can never be used
// again, and the interface returns with a new index and a new contract anyway.
func planPreparedKernelRuleFlowPurge(deferred []kernelDeferredFlowRule[preparedKernelRule], current []preparedKernelRule, next []preparedKernelRule, now time.Time, linkExists func(int) bool) kernelFlowPurgePlan {
	candidates := make([]kernelDeferredFlowRule[preparedKernelRule], 0, len(deferred)+len(current))
	candidates = append(candidates, deferred...)
	for _, item := range current {
		candidates = append(candidates, kernelDeferredFlowRule[preparedKernelRule]{rule: item, at: now})
	}
	base := make([]preparedKernelRule, 0, len(candidates))
	for _, candidate := range candidates {
		base = append(base, candidate.rule)
	}
	plan := kernelFlowPurgePlan{targets: collectPreparedKernelRuleFlowPurgeTargets(base, next)}
	if len(plan.targets) == 0 {
		return plan
	}
	guarded := guardedPreparedKernelRules(next)
	if len(guarded) == 0 {
		return plan
	}
	for _, candidate := range candidates {
		item := candidate.rule
		if item.value.Flags&kernelRuleFlagDrop != 0 || now.Sub(candidate.at) >= kernelDeferredFlowGrace {
			continue
		}
		if _, ok := guarded[kernelGuardedRuleKey{match: kernelRuleMatchKeyFor(item.rule), ruleID: item.rule.ID}]; !ok {
			continue
		}
		revision, err := preparedKernelRuleFlowRevision(item)
		if err != nil || revision == 0 {
			continue
		}
		target := kernelFlowPurgeTarget{RuleID: uint32(item.rule.ID), RuleRevision: revision}
		if _, ok := plan.targets[target]; !ok || !preparedKernelRuleFlowLinksExist(item, linkExists) {
			continue
		}
		delete(plan.targets, target)
		plan.deferred = append(plan.deferred, candidate)
	}
	return plan
}

// guardedPreparedKernelRules returns the rules next prepares only as drop
// guards.
func guardedPreparedKernelRules(next []preparedKernelRule) map[kernelGuardedRuleKey]struct{} {
	var guarded map[kernelGuardedRuleKey]struct{}
	for _, item := range next {
		if item.value.Flags&kernelRuleFlagDrop == 0 {
			continue
		}
		if guarded == nil {
			guarded = make(map[kernelGuardedRuleKey]struct{})
		}
		guarded[kernelGuardedRuleKey{match: kernelRuleMatchKeyFor(item.rule), ruleID: item.rule.ID}] = struct{}{}
	}
	for _, item := range next {
		if item.value.Flags&kernelRuleFlagDrop == 0 {
			delete(guarded, kernelGuardedRuleKey{match: kernelRuleMatchKeyFor(item.rule), ruleID: item.rule.ID})
		}
	}
	return guarded
}

func preparedKernelRuleFlowLinksExist(item preparedKernelRule, linkExists func(int) bool) bool {
	if linkExists == nil {
		return false
	}
	indexes := append([]int{item.inIfIndex, item.outIfIndex}, item.replyIfIndexes...)
	for _, ifindex := range indexes {
		if ifindex > 0 && !linkExists(ifindex) {
			return false
		}
	}
	return true
}

func kernelLinkIndexExists(ifindex int) bool {
	_, err := netlink.LinkByIndex(ifindex)
	return err == nil
}

func (rt *linuxKernelRuleRuntime) expireDeferredFlowRulesLocked(now time.Time) {
	targets := collectPreparedKernelRuleFlowPurgeTargets(rt.deferredFlows.expire(now), nil)
	if len(targets) > 0 {
		rt.flowPurgeRetry.add(targets)
		log.Printf("kernel dataplane maintenance: rules did not return within %s, purging flows for %d flow purge target(s)", kernelDeferredFlowGrace, len(targets))
	}
}

func (rt *xdpKernelRuleRuntime) expireDeferredFlowRulesLocked(now time.Time) {
	targets := collectPreparedXDPKernelRuleFlowPurgeTargets(rt.deferredFlows.expire(now), nil)
	if len(targets) > 0 {
		rt.flowPurgeRetry.add(targets)
		log.Printf("xdp dataplane maintenance: rules did not return within %s, purging flows for %d flow purge target(s)", kernelDeferredFlowGrace, len(targets))
	}
}

// pendingFlowPurgesForHandoffLocked hands the deferred rules to a hot-restart
// successor as ordinary purges: the successor does not inherit the grace.
func (rt *linuxKernelRuleRuntime) pendingFlowPurgesForHandoffLocked() map[kernelFlowPurgeTarget]struct{} {
	pending := rt.flowPurgeRetry.snapshot()
	return mergeKernelFlowPurgeTargets(pending, collectPreparedKernelRuleFlowPurgeTargets(rt.deferredFlows.rules(), nil))
}

func (rt *xdpKernelRuleRuntime) pendingFlowPurgesForHandoffLocked() map[kernelFlowPurgeTarget]struct{} {
	pending := rt.flowPurgeRetry.snapshot()
	return mergeKernelFlowPurgeTargets(pending, collectPreparedXDPKernelRuleFlowPurgeTargets(rt.deferredFlows.rules(), nil))
}

func mergeKernelFlowPurgeTargets(into map[kernelFlowPurgeTarget]struct{}, from map[kernelFlowPurgeTarget]struct{}) map[kernelFlowPurgeTarget]struct{} {
	if len(from) == 0 {
		return into
	}
	if into == nil {
		into = make(map[kernelFlowPurgeTarget]struct{}, len(from))
	}
	for target := range from {
		into[target] = struct{}{}
	}
	return into
}

type kernelFlowPurgeFunc func(map[kernelFlowPurgeTarget]struct{}) (map[uint32]kernelRuleStats, int, error)

type kernelFlowPurgeRetryState struct {
	targets map[kernelFlowPurgeTarget]struct{}
}

func (state *kernelFlowPurgeRetryState) add(targets map[kernelFlowPurgeTarget]struct{}) {
	if state == nil || len(targets) == 0 {
		return
	}
	if state.targets == nil {
		state.targets = make(map[kernelFlowPurgeTarget]struct{}, len(targets))
	}
	for target := range targets {
		if target.RuleID == 0 {
			continue
		}
		wildcard := kernelFlowPurgeTarget{RuleID: target.RuleID}
		if target.RuleRevision != 0 {
			if _, covered := state.targets[wildcard]; covered {
				continue
			}
		}
		if target.IfIndex != 0 {
			fullRevision := kernelFlowPurgeTarget{RuleID: target.RuleID, RuleRevision: target.RuleRevision}
			if _, covered := state.targets[fullRevision]; covered {
				continue
			}
		}
		for pending := range state.targets {
			if pending.RuleID != target.RuleID {
				continue
			}
			if target.RuleRevision == 0 || (target.IfIndex == 0 && pending.RuleRevision == target.RuleRevision) {
				delete(state.targets, pending)
			}
		}
		state.targets[target] = struct{}{}
	}
}

func (state *kernelFlowPurgeRetryState) snapshot() map[kernelFlowPurgeTarget]struct{} {
	if state == nil || len(state.targets) == 0 {
		return nil
	}
	out := make(map[kernelFlowPurgeTarget]struct{}, len(state.targets))
	for target := range state.targets {
		out[target] = struct{}{}
	}
	return out
}

func (state *kernelFlowPurgeRetryState) run(newTargets map[kernelFlowPurgeTarget]struct{}, purge kernelFlowPurgeFunc) (map[uint32]kernelRuleStats, int, error) {
	state.add(newTargets)
	targets := state.snapshot()
	if len(targets) == 0 || purge == nil {
		return map[uint32]kernelRuleStats{}, 0, nil
	}
	corrections, deleted, err := purge(targets)
	if corrections == nil {
		corrections = make(map[uint32]kernelRuleStats)
	}
	if err == nil {
		for target := range targets {
			delete(state.targets, target)
		}
		if len(state.targets) == 0 {
			state.targets = nil
		}
	}
	return corrections, deleted, err
}

func (state *kernelFlowPurgeRetryState) reset() {
	if state != nil {
		state.targets = nil
	}
}

func (rt *linuxKernelRuleRuntime) retryPendingFlowPurgesLocked() (int, error) {
	if rt == nil || rt.coll == nil || len(rt.flowPurgeRetry.targets) == 0 {
		return 0, nil
	}
	corrections, deleted, purgeErr := rt.flowPurgeRetry.run(nil, func(targets map[kernelFlowPurgeTarget]struct{}) (map[uint32]kernelRuleStats, int, error) {
		return purgeKernelFlowsForTargets(kernelRuntimeMapRefsFromCollection(rt.coll), targets, false)
	})
	if deleted > 0 {
		settleKernelTCFlowCache(rt.coll.Maps[kernelTCFlowCacheStateMapName])
	}
	mergeKernelStatsCorrections(rt.statsCorrection, corrections)
	var syncErr error
	if deleted > 0 || purgeErr != nil {
		syncErr = syncKernelOccupancyMapFromCollectionExact(rt.coll, true)
	}
	if err := errors.Join(purgeErr, syncErr); err != nil {
		return deleted, fmt.Errorf("retry pending tc flow purge: %w", err)
	}
	return deleted, nil
}

func (rt *xdpKernelRuleRuntime) retryPendingFlowPurgesLocked() (int, error) {
	if rt == nil || rt.coll == nil || len(rt.flowPurgeRetry.targets) == 0 {
		return 0, nil
	}
	refs := kernelRuntimeMapRefsFromCollection(rt.coll)
	corrections, deleted, purgeErr := rt.flowPurgeRetry.run(nil, func(targets map[kernelFlowPurgeTarget]struct{}) (map[uint32]kernelRuleStats, int, error) {
		return purgeKernelFlowsForTargets(refs, targets, true)
	})
	mergeKernelStatsCorrections(rt.statsCorrection, corrections)
	var syncErr error
	if deleted > 0 || purgeErr != nil {
		syncErr = syncKernelOccupancyMapFromCollectionExact(rt.coll, refs.hasNAT())
	}
	if err := errors.Join(purgeErr, syncErr); err != nil {
		return deleted, fmt.Errorf("retry pending xdp flow purge: %w", err)
	}
	return deleted, nil
}
