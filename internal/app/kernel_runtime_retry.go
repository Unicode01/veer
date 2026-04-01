//go:build linux

package app

func sameKernelRuleDataplaneConfig(a, b Rule) bool {
	return a.ID == b.ID &&
		a.InInterface == b.InInterface &&
		a.InIP == b.InIP &&
		a.InPort == b.InPort &&
		a.OutInterface == b.OutInterface &&
		a.OutIP == b.OutIP &&
		a.OutSourceIP == b.OutSourceIP &&
		a.OutPort == b.OutPort &&
		a.Protocol == b.Protocol &&
		a.Transparent == b.Transparent
}

func shouldReuseKernelRuleAfterPrepareFailure(rule Rule, previousRule Rule, reason string, allowTransientReuse bool) bool {
	if !allowTransientReuse || !sameKernelRuleDataplaneConfig(rule, previousRule) {
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
