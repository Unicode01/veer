//go:build linux

package app

import (
	"errors"
	"fmt"
)

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
