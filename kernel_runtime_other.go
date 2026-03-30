//go:build !linux

package main

type unavailableKernelRuleRuntime struct {
	reason string
}

func newKernelRuleRuntime() kernelRuleRuntime {
	return unavailableKernelRuleRuntime{reason: "kernel dataplane requires Linux"}
}

func (rt unavailableKernelRuleRuntime) Available() (bool, string) {
	return false, rt.reason
}

func (rt unavailableKernelRuleRuntime) Reconcile(rules []Rule) (map[int64]kernelRuleApplyResult, error) {
	results := make(map[int64]kernelRuleApplyResult, len(rules))
	for _, rule := range rules {
		results[rule.ID] = kernelRuleApplyResult{Error: rt.reason}
	}
	return results, nil
}

func (rt unavailableKernelRuleRuntime) Close() error {
	return nil
}
