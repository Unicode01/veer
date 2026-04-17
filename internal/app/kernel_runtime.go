package app

import "strings"

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

type kernelRuleSupportRuntime interface {
	SupportsRule(rule Rule) (bool, string)
}

type kernelHandoffRetentionRuntime interface {
	retainedKernelRuleCandidates(rule Rule) ([]Rule, bool)
	retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool)
	retainedKernelEgressNATCandidates(item EgressNAT) ([]Rule, bool)
}

type kernelRetainedAssignmentRuntime interface {
	ReconcileRetainingAssignments(retainedByEngine map[string][]Rule, newRules []Rule) (map[int64]kernelRuleApplyResult, error)
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
