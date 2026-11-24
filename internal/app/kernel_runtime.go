package app

import (
	"strings"
	"sync/atomic"
)

// kernelReconcileGate marks the reconciles of a runtime that holds its lock
// for a whole reconcile, which loads and verifies programs and can take
// seconds on a small machine. Views that only show state answer from their
// last result while one runs instead of waiting behind it.
type kernelReconcileGate struct {
	running atomic.Int32
}

// begin marks a reconcile; call the returned function when it ends.
func (g *kernelReconcileGate) begin() func() {
	g.running.Add(1)
	return func() { g.running.Add(-1) }
}

func (g *kernelReconcileGate) active() bool {
	return g.running.Load() > 0
}

// kernelReconcileProgressRuntime is a runtime that reports a running reconcile.
type kernelReconcileProgressRuntime interface {
	reconcileInProgress() bool
}

func kernelRuntimeReconcileInProgress(rt kernelRuleRuntime) bool {
	progress, ok := rt.(kernelReconcileProgressRuntime)
	return ok && progress.reconcileInProgress()
}

type kernelRuleApplyResult struct {
	Running bool
	Engine  string
	Error   string
}

type kernelRuleStats struct {
	TCPActiveConns int64
	UDPNatEntries  int64
	ICMPNatEntries int64
	TotalConns     int64
	BytesIn        int64
	BytesOut       int64
}

type kernelRuleStatsSnapshot struct {
	ByRuleID map[uint32]kernelRuleStats
}

func emptyKernelRuleStatsSnapshot() kernelRuleStatsSnapshot {
	return kernelRuleStatsSnapshot{ByRuleID: make(map[uint32]kernelRuleStats)}
}

type kernelRuleRuntime interface {
	Available() (bool, string)
	Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error)
	SnapshotStats() (kernelRuleStatsSnapshot, error)
	Maintain() error
	SnapshotAssignments() map[int64]string
	Close() error
}

// kernelPathHoldReleaser reports that a rule kept on an out path by its live
// sessions may now move; the caller should reconcile again.
type kernelPathHoldReleaser interface {
	takeKernelPathHoldRelease() bool
}

type kernelRuleRuntimeWithPluginCatalog interface {
	ReconcileWithPluginCatalog(rules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error)
}

type kernelRuleSupportRuntime interface {
	SupportsRule(rule Rule) (bool, string)
}

type kernelHandoffRetentionRuntime interface {
	retainedKernelRuleCandidates(rule Rule) ([]Rule, bool)
	retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool)
	retainedKernelEgressNATCandidates(item EgressNAT) ([]Rule, bool)
}

type kernelRuleIDSnapshotRuntime interface {
	snapshotKernelCandidateRules() []Rule
}

type kernelRetainedAssignmentRuntime interface {
	ReconcileRetainingAssignments(retainedByEngine map[string][]Rule, newRules []Rule) (map[int64]kernelRuleApplyResult, error)
}

type kernelRetainedAssignmentRuntimeWithPluginCatalog interface {
	ReconcileRetainingAssignmentsWithPluginCatalog(retainedByEngine map[string][]Rule, newRules []Rule, catalog PluginCatalog) (map[int64]kernelRuleApplyResult, error)
}

const (
	kernelEngineXDP = "xdp"
	kernelEngineTC  = "tc"
)

func defaultKernelEngineOrder() []string {
	return []string{kernelEngineTC}
}

func normalizeKernelEngineOrder(values []string) []string {
	if len(values) == 0 {
		return defaultKernelEngineOrder()
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		name := strings.ToLower(strings.TrimSpace(raw))
		switch name {
		case kernelEngineXDP, kernelEngineTC:
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			out = append(out, name)
		}
	}

	if len(out) == 0 {
		return defaultKernelEngineOrder()
	}
	return out
}
