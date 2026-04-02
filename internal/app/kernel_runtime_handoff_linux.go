//go:build linux

package app

func (rt *orderedKernelRuleRuntime) retainedKernelRuleCandidates(rule Rule) ([]Rule, bool) {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	for _, entry := range entries {
		retainer, ok := entry.rt.(kernelHandoffRetentionRuntime)
		if !ok || retainer == nil {
			continue
		}
		if candidates, ok := retainer.retainedKernelRuleCandidates(rule); ok {
			return candidates, true
		}
	}
	return nil, false
}

func (rt *orderedKernelRuleRuntime) retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool) {
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	rt.mu.Unlock()

	for _, entry := range entries {
		retainer, ok := entry.rt.(kernelHandoffRetentionRuntime)
		if !ok || retainer == nil {
			continue
		}
		if candidates, ok := retainer.retainedKernelRangeCandidates(pr); ok {
			return candidates, true
		}
	}
	return nil, false
}

func (rt *linuxKernelRuleRuntime) retainedKernelRuleCandidates(rule Rule) ([]Rule, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	items := collectPreparedKernelOwnerRules(rt.preparedRules, workerKindRule, rule.ID)
	if !activeOwnerRulesMatchRule(items, rule) {
		return nil, false
	}
	return cloneRuleSlice(items), true
}

func (rt *linuxKernelRuleRuntime) retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	items := collectPreparedKernelOwnerRules(rt.preparedRules, workerKindRange, pr.ID)
	if !activeOwnerRulesMatchRange(items, pr) {
		return nil, false
	}
	return cloneRuleSlice(items), true
}

func (rt *xdpKernelRuleRuntime) retainedKernelRuleCandidates(rule Rule) ([]Rule, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	items := collectPreparedXDPOwnerRules(rt.preparedRules, workerKindRule, rule.ID)
	if !activeOwnerRulesMatchRule(items, rule) {
		return nil, false
	}
	return cloneRuleSlice(items), true
}

func (rt *xdpKernelRuleRuntime) retainedKernelRangeCandidates(pr PortRange) ([]Rule, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	items := collectPreparedXDPOwnerRules(rt.preparedRules, workerKindRange, pr.ID)
	if !activeOwnerRulesMatchRange(items, pr) {
		return nil, false
	}
	return cloneRuleSlice(items), true
}

func collectPreparedKernelOwnerRules(prepared []preparedKernelRule, kind string, ownerID int64) []Rule {
	if len(prepared) == 0 || ownerID <= 0 {
		return nil
	}
	out := make([]Rule, 0)
	for _, item := range prepared {
		if kernelRuleLogKind(item.rule) != kind || kernelRuleLogOwnerID(item.rule) != ownerID {
			continue
		}
		out = append(out, item.rule)
	}
	return out
}

func collectPreparedXDPOwnerRules(prepared []preparedXDPKernelRule, kind string, ownerID int64) []Rule {
	if len(prepared) == 0 || ownerID <= 0 {
		return nil
	}
	out := make([]Rule, 0)
	for _, item := range prepared {
		if kernelRuleLogKind(item.rule) != kind || kernelRuleLogOwnerID(item.rule) != ownerID {
			continue
		}
		out = append(out, item.rule)
	}
	return out
}

func sameKernelRuleDataplaneFields(a Rule, b Rule) bool {
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

func cloneRuleSlice(src []Rule) []Rule {
	if len(src) == 0 {
		return nil
	}
	dst := make([]Rule, len(src))
	copy(dst, src)
	return dst
}

func activeOwnerRulesMatchRule(items []Rule, rule Rule) bool {
	variants := kernelProtocolVariants(rule.Protocol)
	if len(items) == 0 || len(variants) == 0 || len(items) != len(variants) {
		return false
	}

	seen := make(map[string]bool, len(variants))
	for _, item := range items {
		expected := rule
		expected.Protocol = item.Protocol
		if !sameKernelRuleDataplaneFields(item, expected) {
			return false
		}
		seen[item.Protocol] = true
	}
	for _, variant := range variants {
		if !seen[variant] {
			return false
		}
	}
	return true
}

func activeOwnerRulesMatchRange(items []Rule, pr PortRange) bool {
	variants := kernelProtocolVariants(pr.Protocol)
	portCount := pr.EndPort - pr.StartPort + 1
	if len(items) == 0 || len(variants) == 0 || portCount <= 0 || len(items) != portCount*len(variants) {
		return false
	}

	allowedProtocols := make(map[string]struct{}, len(variants))
	seen := make(map[string]map[int]struct{}, len(variants))
	for _, variant := range variants {
		allowedProtocols[variant] = struct{}{}
		seen[variant] = make(map[int]struct{}, portCount)
	}

	for _, item := range items {
		if _, ok := allowedProtocols[item.Protocol]; !ok {
			return false
		}
		if item.InInterface != pr.InInterface ||
			item.InIP != pr.InIP ||
			item.OutInterface != pr.OutInterface ||
			item.OutIP != pr.OutIP ||
			item.OutSourceIP != pr.OutSourceIP ||
			item.Transparent != pr.Transparent {
			return false
		}
		if item.InPort < pr.StartPort || item.InPort > pr.EndPort {
			return false
		}
		offset := item.InPort - pr.StartPort
		if item.OutPort != pr.OutStartPort+offset {
			return false
		}
		if _, exists := seen[item.Protocol][item.InPort]; exists {
			return false
		}
		seen[item.Protocol][item.InPort] = struct{}{}
	}

	for _, variant := range variants {
		for port := pr.StartPort; port <= pr.EndPort; port++ {
			if _, ok := seen[variant][port]; !ok {
				return false
			}
		}
	}
	return true
}
