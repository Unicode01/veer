package app

import (
	"net"
	"strings"
)

const (
	ruleEngineAuto      = "auto"
	ruleEngineUserspace = "userspace"
	ruleEngineKernel    = "kernel"
	kernelFlowsMapLimit = 131072
)

type hostInterfaceAddrs map[string]map[string]struct{}

func loadHostInterfaceAddrs() (hostInterfaceAddrs, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make(hostInterfaceAddrs, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			result[iface.Name] = map[string]struct{}{}
			continue
		}

		ipSet := make(map[string]struct{})
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP == nil || ipnet.IP.To4() == nil {
				continue
			}
			ipSet[ipnet.IP.String()] = struct{}{}
		}
		result[iface.Name] = ipSet
	}

	return result, nil
}

type ruleDataplane interface {
	Name() string
	Available() (bool, string)
	SupportsRule(rule Rule) (bool, string)
}

type userspaceRuleDataplane struct{}

func (userspaceRuleDataplane) Name() string {
	return ruleEngineUserspace
}

func (userspaceRuleDataplane) Available() (bool, string) {
	return true, ""
}

func (userspaceRuleDataplane) SupportsRule(rule Rule) (bool, string) {
	return true, ""
}

type tcEBPFRuleDataplane struct {
	hostAddrs hostInterfaceAddrs
	hostErr   string
	available bool
	reason    string
}

func (dp tcEBPFRuleDataplane) Name() string {
	return ruleEngineKernel
}

func (dp tcEBPFRuleDataplane) Available() (bool, string) {
	return dp.available, dp.reason
}

func (dp tcEBPFRuleDataplane) SupportsRule(rule Rule) (bool, string) {
	if dp.hostErr != "" {
		return false, "kernel dataplane could not inspect host interfaces"
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return false, "kernel dataplane currently supports only single-protocol TCP/UDP rules"
	}
	if strings.TrimSpace(rule.InInterface) == "" {
		return false, "kernel dataplane requires an explicit inbound interface"
	}
	if strings.TrimSpace(rule.OutInterface) == "" {
		return false, "kernel dataplane requires an explicit outbound interface"
	}
	inIP := net.ParseIP(strings.TrimSpace(rule.InIP)).To4()
	if inIP == nil {
		return false, "kernel dataplane requires a valid inbound IPv4 address"
	}
	if net.ParseIP(strings.TrimSpace(rule.OutIP)).To4() == nil {
		return false, "kernel dataplane requires an explicit outbound IPv4 address"
	}
	outSourceIP := strings.TrimSpace(rule.OutSourceIP)
	if outSourceIP != "" {
		ip4 := net.ParseIP(outSourceIP).To4()
		if ip4 == nil {
			return false, "kernel dataplane requires a valid outbound source IPv4 address"
		}
		if ip4.IsLoopback() || ip4.IsUnspecified() {
			return false, "kernel dataplane requires a specific non-loopback outbound source IPv4 address"
		}
		if rule.Transparent {
			return false, "kernel dataplane does not support fixed source IP with transparent rules"
		}
	}
	if !rule.Transparent {
		outIfaceAddrs, ok := dp.hostAddrs[rule.OutInterface]
		if !ok {
			return false, "kernel dataplane cannot resolve the outbound interface"
		}
		if outSourceIP != "" {
			if _, ok := outIfaceAddrs[outSourceIP]; !ok {
				return false, "outbound source IP is not assigned to the selected outbound interface"
			}
		} else {
			hasOutboundIPv4 := false
			for addr := range outIfaceAddrs {
				ip4 := net.ParseIP(addr).To4()
				if ip4 == nil || ip4.IsLoopback() {
					continue
				}
				hasOutboundIPv4 = true
				break
			}
			if !hasOutboundIPv4 {
				return false, "kernel dataplane requires an outbound interface IPv4 address for full-NAT"
			}
		}
	}
	ifaceAddrs, ok := dp.hostAddrs[rule.InInterface]
	if !ok {
		return false, "kernel dataplane cannot resolve the inbound interface"
	}
	if inIP.String() == "0.0.0.0" {
		return true, ""
	}
	if _, ok := ifaceAddrs[inIP.String()]; !ok {
		return false, "inbound IP is not assigned to the selected inbound interface"
	}
	return true, ""
}

type ruleDataplanePlan struct {
	PreferredEngine string
	EffectiveEngine string
	KernelEligible  bool
	KernelReason    string
	FallbackReason  string
}

type rangeDataplanePlan = ruleDataplanePlan

type ruleDataplanePlanner struct {
	userspace     ruleDataplane
	kernel        ruleDataplane
	defaultEngine string
}

func newRuleDataplanePlanner(kernelRuntime kernelRuleRuntime, defaultEngine string) *ruleDataplanePlanner {
	hostAddrs, err := loadHostInterfaceAddrs()
	hostErr := ""
	if err != nil {
		hostErr = err.Error()
	}
	available := false
	reason := "kernel dataplane is not enabled in this build yet"
	if kernelRuntime != nil {
		available, reason = kernelRuntime.Available()
	}

	return &ruleDataplanePlanner{
		userspace:     userspaceRuleDataplane{},
		defaultEngine: normalizeRuleEnginePreference(defaultEngine),
		kernel: tcEBPFRuleDataplane{
			hostAddrs: hostAddrs,
			hostErr:   hostErr,
			available: available,
			reason:    reason,
		},
	}
}

func (p *ruleDataplanePlanner) Plan(rule Rule) ruleDataplanePlan {
	preferred := p.resolvePreferredEngine(rule.EnginePreference)
	plan := ruleDataplanePlan{
		PreferredEngine: preferred,
		EffectiveEngine: ruleEngineUserspace,
	}

	kernelEligible, kernelReason := p.kernel.SupportsRule(rule)
	kernelAvailable, kernelUnavailableReason := p.kernel.Available()
	plan.KernelEligible = kernelEligible
	plan.KernelReason = kernelReason

	switch preferred {
	case ruleEngineKernel:
		if kernelEligible && kernelAvailable {
			plan.EffectiveEngine = ruleEngineKernel
			return plan
		}
		if !kernelEligible {
			plan.FallbackReason = kernelReason
		} else {
			plan.FallbackReason = kernelUnavailableReason
		}
	case ruleEngineAuto:
		if kernelEligible && kernelAvailable {
			plan.EffectiveEngine = ruleEngineKernel
		} else if !kernelEligible {
			plan.FallbackReason = kernelReason
		} else if !kernelAvailable {
			plan.FallbackReason = kernelUnavailableReason
		}
	}

	return plan
}

func (p *ruleDataplanePlanner) resolvePreferredEngine(rulePreference string) string {
	preferred := normalizeRuleEnginePreference(rulePreference)
	if preferred != ruleEngineAuto {
		return preferred
	}

	if p.defaultEngine == ruleEngineUserspace || p.defaultEngine == ruleEngineKernel {
		return p.defaultEngine
	}
	return ruleEngineAuto
}

func (p *ruleDataplanePlanner) PlanAll(rules []Rule) map[int64]ruleDataplanePlan {
	plans := make(map[int64]ruleDataplanePlan, len(rules))
	for _, rule := range rules {
		plans[rule.ID] = p.Plan(rule)
	}
	return plans
}

func applyKernelRuleSetConstraints(rules []Rule, plans map[int64]ruleDataplanePlan) map[int64]ruleDataplanePlan {
	type backendKey struct {
		OutIP    string
		OutPort  int
		Protocol string
	}

	grouped := make(map[backendKey][]int64)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !rule.Transparent {
			continue
		}
		plan, ok := plans[rule.ID]
		if !ok || plan.EffectiveEngine != ruleEngineKernel {
			continue
		}
		key := backendKey{
			OutIP:    strings.TrimSpace(rule.OutIP),
			OutPort:  rule.OutPort,
			Protocol: strings.ToLower(strings.TrimSpace(rule.Protocol)),
		}
		grouped[key] = append(grouped[key], rule.ID)
	}

	for _, ids := range grouped {
		if len(ids) < 2 {
			continue
		}
		for _, id := range ids {
			plan := plans[id]
			plan.EffectiveEngine = ruleEngineUserspace
			plan.FallbackReason = "transparent kernel dataplane requires a unique backend endpoint per active rule"
			plans[id] = plan
		}
	}

	return plans
}

func normalizeRuleEnginePreference(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ruleEngineAuto:
		return ruleEngineAuto
	case ruleEngineUserspace:
		return ruleEngineUserspace
	case ruleEngineKernel:
		return ruleEngineKernel
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func isValidRuleEnginePreference(value string) bool {
	switch normalizeRuleEnginePreference(value) {
	case ruleEngineAuto, ruleEngineUserspace, ruleEngineKernel:
		return true
	default:
		return false
	}
}
