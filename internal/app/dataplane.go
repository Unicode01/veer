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
			var ip net.IP
			switch item := addr.(type) {
			case *net.IPNet:
				ip = item.IP
			case *net.IPAddr:
				ip = item.IP
			}
			if !isVisibleInterfaceIP(ip) {
				continue
			}
			ipSet[canonicalIPLiteral(ip)] = struct{}{}
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

type kernelRuntimeRuleDataplane struct {
	supporter kernelRuleSupportRuntime
	fallback  ruleDataplane
	available bool
	reason    string
}

func (dp tcEBPFRuleDataplane) Name() string {
	return ruleEngineKernel
}

func (dp tcEBPFRuleDataplane) Available() (bool, string) {
	return dp.available, dp.reason
}

func (dp kernelRuntimeRuleDataplane) Name() string {
	return ruleEngineKernel
}

func (dp kernelRuntimeRuleDataplane) Available() (bool, string) {
	return dp.available, dp.reason
}

func (dp kernelRuntimeRuleDataplane) SupportsRule(rule Rule) (bool, string) {
	if dp.supporter != nil {
		return dp.supporter.SupportsRule(rule)
	}
	if dp.fallback != nil {
		return dp.fallback.SupportsRule(rule)
	}
	return false, "kernel dataplane could not evaluate rule eligibility"
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
	PreferredEngine   string
	EffectiveEngine   string
	KernelEligible    bool
	KernelReason      string
	FallbackReason    string
	TransientFallback kernelTransientFallbackMetadata
}

type rangeDataplanePlan = ruleDataplanePlan

type kernelTransientFallbackMetadata struct {
	ReasonClass  string
	OutInterface string
	BackendIP    string
	BackendMAC   string
}

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

	fallbackKernel := tcEBPFRuleDataplane{
		hostAddrs: hostAddrs,
		hostErr:   hostErr,
		available: available,
		reason:    reason,
	}
	kernel := ruleDataplane(fallbackKernel)
	if supporter, ok := kernelRuntime.(kernelRuleSupportRuntime); ok && supporter != nil {
		kernel = kernelRuntimeRuleDataplane{
			supporter: supporter,
			fallback:  fallbackKernel,
			available: available,
			reason:    reason,
		}
	}

	return &ruleDataplanePlanner{
		userspace:     userspaceRuleDataplane{},
		defaultEngine: normalizeRuleEnginePreference(defaultEngine),
		kernel:        kernel,
	}
}

func (p *ruleDataplanePlanner) Plan(rule Rule) ruleDataplanePlan {
	preferred := p.resolvePreferredEngine(rule.EnginePreference)
	plan := ruleDataplanePlan{
		PreferredEngine: preferred,
		EffectiveEngine: ruleEngineUserspace,
	}

	kernelReason := kernelRuleFamilyFallbackReason(rule)
	kernelEligible := false
	if kernelReason == "" {
		kernelEligible, kernelReason = p.kernel.SupportsRule(rule)
	}
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
	plan.TransientFallback = kernelTransientFallbackMetadataForRule(rule, plan.FallbackReason)

	return plan
}

func kernelRuleFamilyFallbackReason(rule Rule) string {
	if ipLiteralPairIsMixedFamily(rule.InIP, rule.OutIP) {
		return "kernel dataplane does not support mixed IPv4/IPv6 forwarding"
	}
	if ipLiteralUsesIPv6(rule.InIP, rule.OutIP) {
		return "kernel dataplane currently supports only IPv4 rules"
	}
	return ""
}

func kernelTransientFallbackMetadataForRule(rule Rule, reason string) kernelTransientFallbackMetadata {
	reasonClass := normalizeTransientKernelFallbackReason(reason)
	switch reasonClass {
	case "neighbor_missing", "fdb_missing":
		metadata := kernelTransientFallbackMetadata{
			ReasonClass:  reasonClass,
			OutInterface: normalizeKernelTransientFallbackInterface(rule.OutInterface),
			BackendIP:    normalizeKernelTransientFallbackBackendIP(rule.OutIP),
		}
		if reasonClass == "fdb_missing" {
			metadata.BackendMAC = resolveKernelTransientFallbackBackendMAC(rule, reasonClass)
		}
		return metadata
	default:
		return kernelTransientFallbackMetadata{}
	}
}

func normalizeKernelTransientFallbackInterface(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func normalizeKernelTransientFallbackBackendIP(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	if ip := net.ParseIP(text); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
		return ip.String()
	}
	return text
}

func normalizeKernelTransientFallbackBackendMAC(value string) string {
	text := strings.TrimSpace(value)
	if text == "" {
		return ""
	}
	hw, err := net.ParseMAC(text)
	if err != nil || len(hw) < 6 {
		return ""
	}
	return strings.ToLower(hw.String())
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
