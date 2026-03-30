package main

type kernelRuleApplyResult struct {
	Running bool
	Error   string
}

type kernelRuleStats struct {
	TCPActiveConns int64
	UDPNatEntries  int64
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
	Close() error
}
