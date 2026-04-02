//go:build linux

package app

type kernelRuleMatchKey struct {
	kind         string
	ownerID      int64
	inInterface  string
	inIP         string
	inPort       int
	outInterface string
	outIP        string
	outSourceIP  string
	outPort      int
	protocol     string
	transparent  bool
}

func sameKernelRuleDataplaneConfig(a, b Rule) bool {
	return a.InInterface == b.InInterface &&
		a.InIP == b.InIP &&
		a.InPort == b.InPort &&
		a.OutInterface == b.OutInterface &&
		a.OutIP == b.OutIP &&
		a.OutSourceIP == b.OutSourceIP &&
		a.OutPort == b.OutPort &&
		a.Protocol == b.Protocol &&
		a.Transparent == b.Transparent
}

func sameKernelRuleOwnerDataplaneConfig(a, b Rule) bool {
	return kernelRuleLogKind(a) == kernelRuleLogKind(b) &&
		kernelRuleLogOwnerID(a) == kernelRuleLogOwnerID(b) &&
		sameKernelRuleDataplaneConfig(a, b)
}

func kernelRuleMatchKeyFor(rule Rule) kernelRuleMatchKey {
	return kernelRuleMatchKey{
		kind:         kernelRuleLogKind(rule),
		ownerID:      kernelRuleLogOwnerID(rule),
		inInterface:  rule.InInterface,
		inIP:         rule.InIP,
		inPort:       rule.InPort,
		outInterface: rule.OutInterface,
		outIP:        rule.OutIP,
		outSourceIP:  rule.OutSourceIP,
		outPort:      rule.OutPort,
		protocol:     rule.Protocol,
		transparent:  rule.Transparent,
	}
}

func indexKernelRulesByMatchKey(rules []Rule) map[kernelRuleMatchKey]Rule {
	if len(rules) == 0 {
		return nil
	}
	index := make(map[kernelRuleMatchKey]Rule, len(rules))
	for _, rule := range rules {
		index[kernelRuleMatchKeyFor(rule)] = rule
	}
	return index
}

func matchDesiredKernelRule(desiredByKey map[kernelRuleMatchKey]Rule, current Rule) (Rule, bool) {
	if len(desiredByKey) == 0 {
		return Rule{}, false
	}
	desired, ok := desiredByKey[kernelRuleMatchKeyFor(current)]
	if !ok {
		return Rule{}, false
	}
	if !sameKernelRuleOwnerDataplaneConfig(desired, current) {
		return Rule{}, false
	}
	return desired, true
}

func shouldReuseKernelRuleAfterPrepareFailure(rule Rule, previousRule Rule, reason string, allowTransientReuse bool) bool {
	if !allowTransientReuse || !sameKernelRuleOwnerDataplaneConfig(rule, previousRule) {
		return false
	}
	return isTransientKernelFallbackReason(reason)
}

func samePreparedKernelRuleDataplane(a, b preparedKernelRule) bool {
	return sameKernelRuleDataplaneConfig(a.rule, b.rule) &&
		a.inIfIndex == b.inIfIndex &&
		a.outIfIndex == b.outIfIndex &&
		a.key == b.key &&
		a.value == b.value
}

func samePreparedXDPKernelRuleDataplane(a, b preparedXDPKernelRule) bool {
	return sameKernelRuleDataplaneConfig(a.rule, b.rule) &&
		a.inIfIndex == b.inIfIndex &&
		a.outIfIndex == b.outIfIndex &&
		a.key == b.key &&
		a.value == b.value
}
