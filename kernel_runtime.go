package main

type kernelRuleApplyResult struct {
	Running bool
	Error   string
}

type kernelRuleRuntime interface {
	Available() (bool, string)
	Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error)
	Close() error
}
