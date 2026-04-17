package app

import (
	"net"
	"strings"
)

const (
	ruleEngineAuto      = "auto"
	ruleEngineUserspace = "userspace"
	ruleEngineKernel    = "kernel"
	kernelFlowsMapLimit = 262144
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
	if isKernelEgressNATPassthroughRule(rule) {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
			return false, "kernel dataplane currently supports only single-protocol TCP/UDP/ICMP egress nat rules"
		}
		if strings.TrimSpace(rule.InInterface) == "" {
			return false, "kernel dataplane requires an explicit inbound interface"
		}
		if strings.TrimSpace(rule.OutInterface) == "" {
			return false, "kernel dataplane requires an explicit outbound interface"
		}
		if _, ok := dp.hostAddrs[rule.InInterface]; !ok {
			return false, "kernel dataplane cannot resolve the inbound interface"
		}
		if strings.TrimSpace(rule.InIP) == "" || strings.TrimSpace(rule.InIP) == "0.0.0.0" {
			return false, "kernel dataplane passthrough guard requires a specific inbound IPv4 address"
		}
		if ip4 := net.ParseIP(strings.TrimSpace(rule.InIP)).To4(); ip4 == nil {
			return false, "kernel dataplane passthrough guard requires a valid inbound IPv4 address"
		}
		if rule.InPort != 0 || rule.OutPort != 0 {
			return false, "kernel dataplane passthrough guard requires wildcard TCP/UDP port matching"
		}
		if rule.Transparent {
			return false, "kernel dataplane passthrough guard does not support transparent mode"
		}
		if _, ok := dp.hostAddrs[rule.OutInterface]; !ok {
			return false, "kernel dataplane cannot resolve the outbound interface"
		}
		return true, ""
	}
	if isKernelEgressNATRule(rule) {
		if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "icmp" {
			return false, "kernel dataplane currently supports only single-protocol TCP/UDP/ICMP egress nat rules"
		}
		if strings.TrimSpace(rule.InInterface) == "" {
			return false, "kernel dataplane requires an explicit inbound interface"
		}
		if strings.TrimSpace(rule.OutInterface) == "" {
			return false, "kernel dataplane requires an explicit outbound interface"
		}
		if _, ok := dp.hostAddrs[rule.InInterface]; !ok {
			return false, "kernel dataplane cannot resolve the inbound interface"
		}
		if strings.TrimSpace(rule.InIP) != "0.0.0.0" || rule.InPort != 0 {
			return false, "kernel dataplane egress nat takeover requires wildcard inbound IPv4/port matching"
		}
		if rule.Transparent {
			return false, "kernel dataplane egress nat takeover does not support transparent mode"
		}
		ifaceAddrs, ok := dp.hostAddrs[rule.OutInterface]
		if !ok {
			return false, "kernel dataplane cannot resolve the outbound interface"
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
			if _, ok := ifaceAddrs[outSourceIP]; !ok {
				return false, "outbound source IP is not assigned to the selected outbound interface"
			}
			return true, ""
		}
		hasOutboundIPv4 := false
		for addr := range ifaceAddrs {
			ip4 := net.ParseIP(addr).To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			hasOutboundIPv4 = true
			break
		}
		if !hasOutboundIPv4 {
			return false, "kernel dataplane requires an outbound interface IPv4 address for egress nat takeover"
		}
		return true, ""
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
	AddrRefresh       kernelAddressRefreshMetadata
}

type rangeDataplanePlan = ruleDataplanePlan

type kernelTransientFallbackMetadata struct {
	ReasonClass  string
	OutInterface string
	BackendIP    string
	BackendMAC   string
}

type kernelAddressRefreshMetadata struct {
	OutInterface string
	Family       string
}

type ruleDataplanePlanner struct {
	userspace               ruleDataplane
	kernel                  ruleDataplane
	defaultEngine           string
	kernelAvailable         bool
	kernelUnavailableReason string
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
		userspace:               userspaceRuleDataplane{},
		defaultEngine:           normalizeRuleEnginePreference(defaultEngine),
		kernel:                  kernel,
		kernelAvailable:         available,
		kernelUnavailableReason: reason,
	}
}

func (p *ruleDataplanePlanner) Plan(rule Rule) ruleDataplanePlan {
	return p.planWithPreferredAndKernelReason(rule, p.resolvePreferredEngine(rule.EnginePreference), kernelRuleFamilyFallbackReason(rule))
}

func (p *ruleDataplanePlanner) planWithPreferredAndKernelReason(rule Rule, preferred string, kernelReason string) ruleDataplanePlan {
	plan := ruleDataplanePlan{
		PreferredEngine: preferred,
		EffectiveEngine: ruleEngineUserspace,
		AddrRefresh:     kernelAddressRefreshMetadataForRule(rule),
	}

	kernelEligible := false
	if kernelReason == "" {
		kernelEligible, kernelReason = p.kernel.SupportsRule(rule)
	}
	plan.KernelEligible = kernelEligible
	plan.KernelReason = kernelReason

	switch preferred {
	case ruleEngineKernel:
		if kernelEligible && p.kernelAvailable {
			plan.EffectiveEngine = ruleEngineKernel
			return plan
		}
		if !kernelEligible {
			plan.FallbackReason = kernelReason
		} else {
			plan.FallbackReason = p.kernelUnavailableReason
		}
	case ruleEngineAuto:
		if kernelEligible && p.kernelAvailable {
			plan.EffectiveEngine = ruleEngineKernel
		} else if !kernelEligible {
			plan.FallbackReason = kernelReason
		} else if !p.kernelAvailable {
			plan.FallbackReason = p.kernelUnavailableReason
		}
	}
	plan.TransientFallback = kernelTransientFallbackMetadataForRule(rule, plan.FallbackReason)

	return plan
}

func kernelRuleFamilyFallbackReason(rule Rule) string {
	return kernelRuleFamilyFallbackReasonFromIPs(rule.InIP, rule.OutIP, rule.Transparent)
}

func kernelRuleFamilyFallbackReasonFromIPs(inIP string, outIP string, transparent bool) string {
	pair := analyzeIPLiteralPair(inIP, outIP)
	if pair.mixedFamily() {
		return "kernel dataplane does not support mixed IPv4/IPv6 forwarding"
	}
	if transparent && pair.usesIPv6() {
		return "kernel dataplane currently does not support transparent IPv6 rules"
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
	case "source_ip_unassigned":
		return kernelTransientFallbackMetadata{
			ReasonClass:  reasonClass,
			OutInterface: normalizeKernelTransientFallbackInterface(rule.OutInterface),
		}
	default:
		return kernelTransientFallbackMetadata{}
	}
}

func kernelAddressRefreshMetadataForRule(rule Rule) kernelAddressRefreshMetadata {
	if strings.TrimSpace(rule.OutInterface) == "" || rule.Transparent {
		return kernelAddressRefreshMetadata{}
	}

	family := ipLiteralFamily(rule.OutSourceIP)
	if family == "" {
		if isKernelEgressNATRule(rule) || isKernelEgressNATPassthroughRule(rule) {
			family = ipFamilyIPv4
		} else {
			pair := analyzeIPLiteralPair(rule.InIP, rule.OutIP)
			switch {
			case pair.firstFamily != "" && pair.secondFamily == "":
				family = pair.firstFamily
			case pair.secondFamily != "" && pair.firstFamily == "":
				family = pair.secondFamily
			case pair.firstFamily == pair.secondFamily:
				family = pair.firstFamily
			}
		}
	}

	return kernelAddressRefreshMetadata{
		OutInterface: normalizeKernelTransientFallbackInterface(rule.OutInterface),
		Family:       family,
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
