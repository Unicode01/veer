package app

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
