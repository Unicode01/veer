package app

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

const (
	workerKindEgressNAT             = "egress_nat"
	kernelModeEgressNAT             = "egress_nat"
	kernelModeEgressNATPassthrough  = "egress_nat_passthrough"
	egressNATTypeSymmetric          = "symmetric"
	egressNATTypeFullCone           = "full_cone"
	egressNATRedirectModePreparedL2 = "prepared_l2"
	egressNATFullyOverriddenReason  = "all eligible child interfaces and protocols are covered by more specific egress nat rules"
)

const (
	protocolMaskTCP = 1 << iota
	protocolMaskUDP
	protocolMaskICMP
)

var loadInterfaceInfosForEgressNATTests func() ([]InterfaceInfo, error)

type egressNATInterfaceSnapshot struct {
	Infos       []InterfaceInfo
	IfaceByName map[string]InterfaceInfo
	Err         error
}

func protocolMaskFromString(protocol string) int {
	text := strings.ToLower(strings.TrimSpace(protocol))
	if text == "" {
		return 0
	}

	mask := 0
	fields := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case '+', ',', '/', '|':
			return true
		default:
			return r == ' ' || r == '\t' || r == '\n' || r == '\r'
		}
	})
	if len(fields) == 0 {
		return 0
	}

	for _, field := range fields {
		switch strings.TrimSpace(field) {
		case "tcp":
			mask |= protocolMaskTCP
		case "udp":
			mask |= protocolMaskUDP
		case "icmp":
			mask |= protocolMaskICMP
		default:
			return 0
		}
	}
	return mask
}

func protocolNamesFromMask(mask int) []string {
	out := make([]string, 0, 3)
	if mask&protocolMaskTCP != 0 {
		out = append(out, "tcp")
	}
	if mask&protocolMaskUDP != 0 {
		out = append(out, "udp")
	}
	if mask&protocolMaskICMP != 0 {
		out = append(out, "icmp")
	}
	return out
}

func canonicalProtocolString(mask int) string {
	return strings.Join(protocolNamesFromMask(mask), "+")
}

func normalizeEgressNATProtocol(protocol string) string {
	mask := protocolMaskFromString(protocol)
	if mask != 0 {
		return canonicalProtocolString(mask)
	}
	if strings.TrimSpace(protocol) == "" {
		return "tcp+udp"
	}
	return strings.ToLower(strings.TrimSpace(protocol))
}

func normalizeEgressNATType(natType string) string {
	switch strings.ToLower(strings.TrimSpace(natType)) {
	case "", egressNATTypeSymmetric:
		return egressNATTypeSymmetric
	case egressNATTypeFullCone:
		return egressNATTypeFullCone
	default:
		return strings.ToLower(strings.TrimSpace(natType))
	}
}

func isValidEgressNATType(natType string) bool {
	switch normalizeEgressNATType(natType) {
	case egressNATTypeSymmetric, egressNATTypeFullCone:
		return true
	default:
		return false
	}
}

func normalizeEgressNATRedirectMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		return ""
	case egressNATRedirectModePreparedL2, "raw_l2", "vtap":
		return egressNATRedirectModePreparedL2
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func isValidEgressNATRedirectMode(mode string) bool {
	switch normalizeEgressNATRedirectMode(mode) {
	case "", egressNATRedirectModePreparedL2:
		return true
	default:
		return false
	}
}

func expandEgressNATProtocols(protocol string) []string {
	return protocolNamesFromMask(protocolMaskFromString(protocol))
}

func isValidEgressNATProtocol(protocol string) bool {
	return protocolMaskFromString(protocol) != 0
}

func isKernelEgressNATRule(rule Rule) bool {
	return rule.kernelMode == kernelModeEgressNAT
}

func isKernelEgressNATPassthroughRule(rule Rule) bool {
	return rule.kernelMode == kernelModeEgressNATPassthrough
}

func loadEgressNATInterfaceInfos() ([]InterfaceInfo, error) {
	loadInfos := loadInterfaceInfos
	if loadInterfaceInfosForEgressNATTests != nil {
		loadInfos = loadInterfaceInfosForEgressNATTests
	}
	return loadInfos()
}

func newEgressNATInterfaceSnapshot(infos []InterfaceInfo, err error) egressNATInterfaceSnapshot {
	snapshot := egressNATInterfaceSnapshot{Err: err}
	if err != nil {
		return snapshot
	}
	snapshot.Infos = infos
	snapshot.IfaceByName = buildInterfaceInfoMap(infos)
	return snapshot
}

func loadEgressNATInterfaceSnapshot() egressNATInterfaceSnapshot {
	infos, err := loadEgressNATInterfaceInfos()
	return newEgressNATInterfaceSnapshot(infos, err)
}

func normalizeEgressNATScope(item EgressNAT, ifaceByName map[string]InterfaceInfo) EgressNAT {
	item.ParentInterface = strings.TrimSpace(item.ParentInterface)
	item.ChildInterface = strings.TrimSpace(item.ChildInterface)
	if item.ChildInterface != "" {
		return item
	}

	info, ok := ifaceByName[item.ParentInterface]
	if !ok || !isEgressNATSingleTargetInterface(info) {
		return item
	}
	if strings.TrimSpace(info.Parent) == "" {
		return item
	}

	item.ParentInterface = strings.TrimSpace(info.Parent)
	item.ChildInterface = strings.TrimSpace(info.Name)
	return item
}

func normalizeEgressNATItems(items []EgressNAT, infos []InterfaceInfo) []EgressNAT {
	if len(items) == 0 {
		return nil
	}

	ifaceByName := buildInterfaceInfoMap(infos)
	out := make([]EgressNAT, len(items))
	for i, item := range items {
		out[i] = normalizeEgressNATScope(item, ifaceByName)
	}
	return out
}

func normalizeEgressNATItemsWithSnapshot(items []EgressNAT, snapshot egressNATInterfaceSnapshot) []EgressNAT {
	if snapshot.Err != nil {
		out := make([]EgressNAT, len(items))
		copy(out, items)
		return out
	}
	return normalizeEgressNATItems(items, snapshot.Infos)
}

// Compile child overrides before filtering retained/retry owners. An enabled
// child reserves its protocols even when its interface or outbound is missing:
// a failed selected exit must never silently fall back to the parent exit.
func compileEgressNATSubsets(items []EgressNAT, snapshot egressNATInterfaceSnapshot) []EgressNAT {
	items = normalizeEgressNATItemsWithSnapshot(items, snapshot)
	if len(items) == 0 {
		return items
	}
	byParent := make(map[string]map[string]int)
	for _, item := range items {
		if !item.Enabled || item.ChildInterface == "" {
			continue
		}
		if byParent[item.ParentInterface] == nil {
			byParent[item.ParentInterface] = make(map[string]int)
		}
		byParent[item.ParentInterface][item.ChildInterface] |= protocolMaskFromString(normalizeEgressNATProtocol(item.Protocol))
	}
	out := append([]EgressNAT(nil), items...)
	for i, item := range items {
		if item.ChildInterface != "" {
			out[i].subsetOverrides = nil
			continue
		}
		// Preserve a projection made from the complete plan when this call only
		// receives owners remaining after transient retention or retry filtering.
		if len(item.subsetOverrides) == 0 && len(byParent[item.ParentInterface]) == 0 {
			continue
		}
		overrides := make(map[string]int, len(item.subsetOverrides)+len(byParent[item.ParentInterface]))
		for name, mask := range item.subsetOverrides {
			overrides[name] = mask
		}
		for name, mask := range byParent[item.ParentInterface] {
			overrides[name] |= mask
		}
		out[i].subsetOverrides = overrides
	}
	return out
}

func egressNATTargetProtocolMask(item EgressNAT, target string) int {
	return protocolMaskFromString(normalizeEgressNATProtocol(item.Protocol)) &^ item.subsetOverrides[target]
}

func egressNATTargetProtocolEnabled(item EgressNAT, target, protocol string) bool {
	return egressNATTargetProtocolMask(item, target)&protocolMaskFromString(protocol) != 0
}

func normalizeEgressNATItemsWithCurrentInterfaces(items []EgressNAT) []EgressNAT {
	return normalizeEgressNATItemsWithSnapshot(items, loadEgressNATInterfaceSnapshot())
}

func egressNATUsesSingleTargetParent(item EgressNAT, ifaceByName map[string]InterfaceInfo) bool {
	if strings.TrimSpace(item.ChildInterface) != "" {
		return false
	}
	info, ok := ifaceByName[strings.TrimSpace(item.ParentInterface)]
	if !ok {
		return false
	}
	return isEgressNATSingleTargetInterface(info)
}

func collectDynamicEgressNATParents(items []EgressNAT) map[string]struct{} {
	return collectDynamicEgressNATParentsWithSnapshot(items, loadEgressNATInterfaceSnapshot())
}

func collectDynamicEgressNATParentsWithSnapshot(items []EgressNAT, snapshot egressNATInterfaceSnapshot) map[string]struct{} {
	out := make(map[string]struct{})
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		if snapshot.Err == nil {
			item = normalizeEgressNATScope(item, snapshot.IfaceByName)
		}
		parent := normalizeKernelTransientFallbackInterface(item.ParentInterface)
		if parent == "" {
			continue
		}
		out[parent] = struct{}{}
	}
	return out
}

func isEgressNATAttachableChild(info InterfaceInfo) bool {
	if strings.TrimSpace(info.Parent) == "" {
		return false
	}
	// A physical device enslaved to a bridge is a valid ingress target. The
	// single-target check treats devices with a parent as bridge scopes, so run
	// it against a copy without the already-validated parent relationship.
	info.Parent = ""
	return isEgressNATSingleTargetInterface(info)
}

func isEgressNATSingleTargetInterface(info InterfaceInfo) bool {
	name := strings.TrimSpace(info.Name)
	if name == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(info.Kind)) {
	case "bridge":
		return false
	case "device":
		if strings.EqualFold(name, "lo") {
			return false
		}
		if strings.TrimSpace(info.Parent) != "" {
			return false
		}
		return true
	default:
		return true
	}
}

func resolveEgressNATTargetInterfaces(item EgressNAT, infos []InterfaceInfo) ([]InterfaceInfo, error) {
	ifaceByName := buildInterfaceInfoMap(infos)
	item = normalizeEgressNATScope(item, ifaceByName)
	parentName := strings.TrimSpace(item.ParentInterface)
	if parentName == "" {
		return nil, fmt.Errorf("parent_interface is required")
	}
	if _, ok := ifaceByName[parentName]; !ok {
		return nil, fmt.Errorf("parent_interface does not exist on this host")
	}

	childName := strings.TrimSpace(item.ChildInterface)
	if childName != "" {
		childInfo, ok := ifaceByName[childName]
		if !ok {
			return nil, fmt.Errorf("child_interface does not exist on this host")
		}
		if strings.TrimSpace(childInfo.Parent) != parentName {
			return nil, fmt.Errorf("child_interface is not attached to the selected parent_interface")
		}
		return []InterfaceInfo{childInfo}, nil
	}

	parentInfo := ifaceByName[parentName]
	if isEgressNATSingleTargetInterface(parentInfo) {
		return []InterfaceInfo{parentInfo}, nil
	}

	targets := make([]InterfaceInfo, 0)
	outName := strings.TrimSpace(item.OutInterface)
	for _, info := range infos {
		if strings.TrimSpace(info.Parent) != parentName {
			continue
		}
		if !isEgressNATAttachableChild(info) {
			continue
		}
		if outName != "" && strings.EqualFold(strings.TrimSpace(info.Name), outName) {
			continue
		}
		targets = append(targets, info)
	}
	sort.Slice(targets, func(i, j int) bool {
		return strings.Compare(targets[i].Name, targets[j].Name) < 0
	})
	if len(targets) == 0 {
		return nil, fmt.Errorf("parent_interface has no eligible child interfaces for egress nat takeover")
	}
	return targets, nil
}

func listEgressNATBypassIPv4s(infos []InterfaceInfo) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, info := range infos {
		for _, addr := range info.Addrs {
			ip4 := net.ParseIP(strings.TrimSpace(addr)).To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() {
				continue
			}
			text := ip4.String()
			if _, ok := seen[text]; ok {
				continue
			}
			seen[text] = struct{}{}
			out = append(out, text)
		}
	}
	sort.Strings(out)
	return out
}

func parseEgressNATIPv4Uint32(text string) (uint32, error) {
	ip4 := net.ParseIP(strings.TrimSpace(text)).To4()
	if ip4 == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}
	return ipv4BytesToUint32(ip4), nil
}

// kernelEgressNATLocalInventory is what the kernel egress NAT leaves to the
// host: packets for its own addresses (Addrs), and packets for the networks
// directly connected to its interfaces (Networks: true where the kernel
// routes them untranslated, false for the networks of egress NAT uplinks).
// The most specific network wins, so an uplink's network inside a larger
// LAN network is still translated.
type kernelEgressNATLocalInventory struct {
	Addrs    map[uint32]uint8
	Networks map[netip.Prefix]bool
}

func (inv kernelEgressNATLocalInventory) empty() bool {
	return len(inv.Addrs) == 0 && len(inv.Networks) == 0
}

func buildKernelEgressNATLocalInventory(rules []Rule) (kernelEgressNATLocalInventory, error) {
	return buildKernelEgressNATLocalInventoryWithSnapshot(rules, loadEgressNATInterfaceSnapshot())
}

func buildKernelEgressNATLocalInventoryWithSnapshot(rules []Rule, snapshot egressNATInterfaceSnapshot) (kernelEgressNATLocalInventory, error) {
	uplinks := make(map[string]struct{})
	for _, rule := range rules {
		if isKernelEgressNATRule(rule) {
			uplinks[strings.TrimSpace(rule.OutInterface)] = struct{}{}
		}
	}
	if len(uplinks) == 0 {
		return kernelEgressNATLocalInventory{Addrs: map[uint32]uint8{}, Networks: map[netip.Prefix]bool{}}, nil
	}

	if snapshot.Err != nil {
		return kernelEgressNATLocalInventory{}, snapshot.Err
	}
	addresses := listEgressNATBypassIPv4s(snapshot.Infos)
	inv := kernelEgressNATLocalInventory{
		Addrs:    make(map[uint32]uint8, len(addresses)),
		Networks: listEgressNATLocalNetworks(snapshot.Infos, uplinks),
	}
	for _, addr := range addresses {
		value, err := parseEgressNATIPv4Uint32(addr)
		if err != nil {
			return kernelEgressNATLocalInventory{}, fmt.Errorf("parse local IPv4 %q: %w", addr, err)
		}
		inv.Addrs[value] = 1
	}
	return inv, nil
}

// listEgressNATLocalNetworks maps each IPv4 network directly connected to an
// interface to whether egress NAT leaves it to the kernel: true unless the
// interface is an egress NAT uplink, or the bridge or parent link of one (an
// uplink may be a port or VLAN of the device holding the address). A network
// on both kinds of interface stays translated. Host routes (/32) and
// loopback networks are left out.
func listEgressNATLocalNetworks(infos []InterfaceInfo, uplinks map[string]struct{}) map[netip.Prefix]bool {
	isUplink := make(map[string]bool, len(uplinks))
	for _, info := range infos {
		if _, ok := uplinks[info.Name]; !ok {
			continue
		}
		isUplink[info.Name] = true
		if parent := strings.TrimSpace(info.Parent); parent != "" {
			isUplink[parent] = true
		}
	}
	out := make(map[netip.Prefix]bool)
	for _, info := range infos {
		for _, text := range info.IPv4Networks {
			prefix, err := netip.ParsePrefix(strings.TrimSpace(text))
			if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 32 {
				continue
			}
			prefix = prefix.Masked()
			if prefix.Addr().IsLoopback() {
				continue
			}
			routed := !isUplink[info.Name]
			if current, ok := out[prefix]; ok {
				routed = routed && current
			}
			out[prefix] = routed
		}
	}
	return out
}

func buildEgressNATSyntheticRule(item EgressNAT, childInterface string, id int64, proto string) Rule {
	return Rule{
		ID:                 id,
		InInterface:        strings.TrimSpace(childInterface),
		InIP:               "0.0.0.0",
		InPort:             0,
		OutInterface:       item.OutInterface,
		OutIP:              "0.0.0.0",
		OutSourceIP:        item.OutSourceIP,
		OutPort:            0,
		Protocol:           proto,
		Enabled:            item.Enabled,
		Transparent:        false,
		EnginePreference:   ruleEngineKernel,
		kernelMode:         kernelModeEgressNAT,
		kernelNATType:      normalizeEgressNATType(item.NATType),
		kernelRedirectMode: normalizeEgressNATRedirectMode(item.RedirectMode),
	}
}

func activeOwnerRulesMatchEgressNAT(items []Rule, item EgressNAT) bool {
	variants := expandEgressNATProtocols(item.Protocol)
	if !item.Enabled || len(items) == 0 || len(variants) == 0 {
		return false
	}

	allowedProtocols := make(map[string]struct{}, len(variants))
	for _, variant := range variants {
		allowedProtocols[variant] = struct{}{}
	}
	seen := make(map[string]struct{}, len(items))
	protocolsByTarget := make(map[string]map[string]struct{}, len(items)/len(variants))
	for _, rule := range items {
		if _, ok := allowedProtocols[rule.Protocol]; !ok || strings.TrimSpace(rule.InInterface) == "" {
			return false
		}
		if !egressNATTargetProtocolEnabled(item, rule.InInterface, rule.Protocol) {
			return false
		}
		if rule.InIP != "0.0.0.0" || rule.InPort != 0 ||
			rule.OutInterface != strings.TrimSpace(item.OutInterface) ||
			rule.OutIP != "0.0.0.0" ||
			rule.OutSourceIP != strings.TrimSpace(item.OutSourceIP) ||
			rule.OutPort != 0 || rule.Transparent ||
			rule.kernelMode != kernelModeEgressNAT ||
			rule.kernelNATType != normalizeEgressNATType(item.NATType) ||
			rule.kernelRedirectMode != normalizeEgressNATRedirectMode(item.RedirectMode) {
			return false
		}
		target := strings.TrimSpace(rule.InInterface)
		key := target + "\x00" + rule.Protocol
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		if protocolsByTarget[target] == nil {
			protocolsByTarget[target] = make(map[string]struct{}, len(variants))
		}
		protocolsByTarget[target][rule.Protocol] = struct{}{}
	}
	for target, protocols := range protocolsByTarget {
		mask := 0
		for protocol := range protocols {
			mask |= protocolMaskFromString(protocol)
		}
		if mask != egressNATTargetProtocolMask(item, target) {
			return false
		}
	}
	return true
}

func buildEgressNATKernelCandidates(items []EgressNAT, planner *ruleDataplanePlanner, configuredKernelRulesMapLimit int, reservedKernelEntries int, nextSyntheticID *int64) ([]kernelCandidateRule, map[int64]ruleDataplanePlan) {
	return buildEgressNATKernelCandidatesWithSnapshot(items, planner, configuredKernelRulesMapLimit, reservedKernelEntries, nextSyntheticID, loadEgressNATInterfaceSnapshot())
}

func enabledEgressNATIDs(items []EgressNAT) map[int64]bool {
	ids := make(map[int64]bool)
	for _, item := range items {
		if item.Enabled {
			ids[item.ID] = true
		}
	}
	return ids
}

func buildEgressNATKernelCandidatesWithSnapshot(items []EgressNAT, planner *ruleDataplanePlanner, configuredKernelRulesMapLimit int, reservedKernelEntries int, nextSyntheticID *int64, snapshot egressNATInterfaceSnapshot) ([]kernelCandidateRule, map[int64]ruleDataplanePlan) {
	items = compileEgressNATSubsets(items, snapshot)
	plans := make(map[int64]ruleDataplanePlan, len(items))
	candidates := make([]kernelCandidateRule, 0, len(items)*2)
	if planner == nil {
		return candidates, plans
	}

	for _, item := range items {
		owner := kernelCandidateOwner{kind: workerKindEgressNAT, id: item.ID}
		protocols := expandEgressNATProtocols(item.Protocol)
		if len(protocols) == 0 {
			plans[item.ID] = ruleDataplanePlan{
				PreferredEngine: ruleEngineKernel,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  "protocol must include one or more of tcp, udp, icmp",
			}
			continue
		}
		acc := newKernelOwnerPlanAccumulator(ruleEngineKernel)

		if snapshot.Err != nil {
			plans[item.ID] = ruleDataplanePlan{
				PreferredEngine: ruleEngineKernel,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  snapshot.Err.Error(),
			}
			continue
		}

		targetInfos, err := resolveEgressNATTargetInterfaces(item, snapshot.Infos)
		if err != nil {
			plans[item.ID] = ruleDataplanePlan{
				PreferredEngine: ruleEngineKernel,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  err.Error(),
			}
			continue
		}

		if item.Enabled {
			candidates = growKernelCandidateBuffer(candidates, len(targetInfos)*len(protocols))
		}
		candidateStart := len(candidates)
		selectedProtocols := 0
		for _, target := range targetInfos {
			for _, proto := range protocols {
				if !egressNATTargetProtocolEnabled(item, target.Name, proto) {
					continue
				}
				selectedProtocols++
				id, err := allocateSyntheticKernelRuleID(nextSyntheticID)
				if err != nil {
					acc.Add(ruleDataplanePlan{
						PreferredEngine: ruleEngineKernel,
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					continue
				}
				rule := buildEgressNATSyntheticRule(item, target.Name, id, proto)
				annotateKernelCandidateRule(&rule, owner)
				acc.Add(planner.planWithPreferredAndKernelReason(rule, ruleEngineKernel, ""))
				if item.Enabled {
					candidates = append(candidates, kernelCandidateRule{owner: owner, rule: rule})
				}
			}
		}
		if selectedProtocols == 0 && item.Enabled {
			plans[item.ID] = ruleDataplanePlan{
				PreferredEngine: ruleEngineKernel,
				EffectiveEngine: ruleEngineKernel,
				KernelEligible:  true,
				KernelReason:    egressNATFullyOverriddenReason,
			}
			continue
		}

		plan := acc.Result()
		// An unavailable configured exit must not fall through to the host's
		// default route. Manual NATs do not carry a plugin redirect mode, so
		// keep every enabled NAT's ingress/protocol selectors as drop guards.
		if item.Enabled && !plan.KernelEligible && planner.kernelAvailable {
			for i := candidateStart; i < len(candidates); i++ {
				candidates[i].rule.kernelUnavailable = true
			}
			plan.EffectiveEngine = ruleEngineKernel
		}
		if item.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			neededEntries := len(candidates) - candidateStart
			requestedEntries := reservedKernelEntries + neededEntries
			if requestedEntries > effectiveKernelRulesMapLimit(configuredKernelRulesMapLimit, requestedEntries) {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(configuredKernelRulesMapLimit, requestedEntries)
				}
			} else {
				reservedKernelEntries += neededEntries
				plans[item.ID] = plan
				continue
			}
		}
		candidates = candidates[:candidateStart]
		plans[item.ID] = plan
	}

	return candidates, plans
}
