//go:build linux

package app

type kernelRuleMatchKey struct {
	kind          string
	ownerID       int64
	inInterface   string
	inIP          string
	inPort        int
	outInterface  string
	outIP         string
	outSourceIP   string
	outPort       int
	protocol      string
	transparent   bool
	kernelMode    string
	kernelNATType string
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
		a.Transparent == b.Transparent &&
		a.kernelMode == b.kernelMode &&
		a.kernelNATType == b.kernelNATType
}

func sameKernelRuleOwnerDataplaneConfig(a, b Rule) bool {
	return kernelRuleLogKind(a) == kernelRuleLogKind(b) &&
		kernelRuleLogOwnerID(a) == kernelRuleLogOwnerID(b) &&
		sameKernelRuleDataplaneConfig(a, b)
}

func kernelRuleMatchKeyFor(rule Rule) kernelRuleMatchKey {
	return kernelRuleMatchKey{
		kind:          kernelRuleLogKind(rule),
		ownerID:       kernelRuleLogOwnerID(rule),
		inInterface:   rule.InInterface,
		inIP:          rule.InIP,
		inPort:        rule.InPort,
		outInterface:  rule.OutInterface,
		outIP:         rule.OutIP,
		outSourceIP:   rule.OutSourceIP,
		outPort:       rule.OutPort,
		protocol:      rule.Protocol,
		transparent:   rule.Transparent,
		kernelMode:    rule.kernelMode,
		kernelNATType: rule.kernelNATType,
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
		sameKernelReplyIfIndexes(a.replyIfIndexes, b.replyIfIndexes) &&
		sameKernelIfParentMappings(a.replyIfParents, b.replyIfParents) &&
		sameKernelPreparedRuleSpec(a.spec, b.spec) &&
		a.key == b.key &&
		a.value == b.value
}

func samePreparedKernelRuleDataplaneIgnoringRuleID(a, b preparedKernelRule) bool {
	if !sameKernelRuleDataplaneConfig(a.rule, b.rule) ||
		a.inIfIndex != b.inIfIndex ||
		a.outIfIndex != b.outIfIndex ||
		!sameKernelReplyIfIndexes(a.replyIfIndexes, b.replyIfIndexes) ||
		!sameKernelIfParentMappings(a.replyIfParents, b.replyIfParents) ||
		!sameKernelPreparedRuleSpec(a.spec, b.spec) ||
		a.key != b.key {
		return false
	}
	left := a.value
	right := b.value
	left.RuleID = 0
	right.RuleID = 0
	return left == right
}

func samePreparedKernelRuleFlowContinuity(a, b preparedKernelRule) bool {
	if !sameKernelRuleDataplaneConfig(a.rule, b.rule) ||
		a.inIfIndex != b.inIfIndex ||
		a.outIfIndex != b.outIfIndex ||
		!sameKernelReplyIfIndexes(a.replyIfIndexes, b.replyIfIndexes) ||
		!sameKernelIfParentMappings(a.replyIfParents, b.replyIfParents) ||
		!sameKernelPreparedRuleSpec(a.spec, b.spec) ||
		a.key != b.key {
		return false
	}
	left := a.value
	right := b.value
	left.RuleID = 0
	right.RuleID = 0
	left.Flags &^= kernelRuleFlagTrafficStats
	right.Flags &^= kernelRuleFlagTrafficStats
	return left == right
}

func sameKernelReplyIfIndexes(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameKernelIfParentMappings(a, b []kernelIfParentMapping) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func samePreparedXDPKernelRuleDataplane(a, b preparedXDPKernelRule) bool {
	if !sameKernelRuleDataplaneConfig(a.rule, b.rule) ||
		a.inIfIndex != b.inIfIndex ||
		a.outIfIndex != b.outIfIndex ||
		!sameKernelPreparedRuleSpec(a.spec, b.spec) {
		return false
	}
	switch xdpPreparedRuleFamily(a) {
	case ipFamilyIPv6:
		return xdpPreparedRuleFamily(b) == ipFamilyIPv6 &&
			a.keyV6 == b.keyV6 &&
			a.valueV6 == b.valueV6
	default:
		return xdpPreparedRuleFamily(b) == ipFamilyIPv4 &&
			a.keyV4 == b.keyV4 &&
			a.valueV4 == b.valueV4
	}
}
