package app

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	workerKindEgressNAT            = "egress_nat"
	kernelModeEgressNAT            = "egress_nat"
	kernelModeEgressNATPassthrough = "egress_nat_passthrough"
	egressNATTypeSymmetric         = "symmetric"
	egressNATTypeFullCone          = "full_cone"
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

func egressNATAppliesToAllChildren(item EgressNAT, ifaceByName map[string]InterfaceInfo) bool {
	item = normalizeEgressNATScope(item, ifaceByName)
	return strings.TrimSpace(item.ParentInterface) != "" && strings.TrimSpace(item.ChildInterface) == ""
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
	return binary.BigEndian.Uint32(ip4), nil
}

func buildKernelEgressNATLocalIPv4Set(rules []Rule) (map[uint32]uint8, error) {
	return buildKernelEgressNATLocalIPv4SetWithSnapshot(rules, loadEgressNATInterfaceSnapshot())
}

func buildKernelEgressNATLocalIPv4SetWithSnapshot(rules []Rule, snapshot egressNATInterfaceSnapshot) (map[uint32]uint8, error) {
	hasEgressNAT := false
	for _, rule := range rules {
		if isKernelEgressNATRule(rule) {
			hasEgressNAT = true
			break
		}
	}
	if !hasEgressNAT {
		return map[uint32]uint8{}, nil
	}

	if snapshot.Err != nil {
		return nil, snapshot.Err
	}
	addresses := listEgressNATBypassIPv4s(snapshot.Infos)
	out := make(map[uint32]uint8, len(addresses))
	for _, addr := range addresses {
		value, err := parseEgressNATIPv4Uint32(addr)
		if err != nil {
			return nil, fmt.Errorf("parse local IPv4 %q: %w", addr, err)
		}
		out[value] = 1
	}
	return out, nil
}

func buildEgressNATSyntheticRule(item EgressNAT, childInterface string, id int64, proto string) Rule {
	return Rule{
		ID:               id,
		InInterface:      strings.TrimSpace(childInterface),
		InIP:             "0.0.0.0",
		InPort:           0,
		OutInterface:     item.OutInterface,
		OutIP:            "0.0.0.0",
		OutSourceIP:      item.OutSourceIP,
		OutPort:          0,
		Protocol:         proto,
		Enabled:          item.Enabled,
		Transparent:      false,
		EnginePreference: ruleEngineKernel,
		kernelMode:       kernelModeEgressNAT,
		kernelNATType:    normalizeEgressNATType(item.NATType),
	}
}

func buildEgressNATPassthroughRule(item EgressNAT, childInterface string, localIP string, id int64, proto string) Rule {
	return Rule{
		ID:               id,
		InInterface:      strings.TrimSpace(childInterface),
		InIP:             strings.TrimSpace(localIP),
		InPort:           0,
		OutInterface:     item.OutInterface,
		OutIP:            "0.0.0.0",
		OutSourceIP:      item.OutSourceIP,
		OutPort:          0,
		Protocol:         proto,
		Enabled:          item.Enabled,
		Transparent:      false,
		EnginePreference: ruleEngineKernel,
		kernelMode:       kernelModeEgressNATPassthrough,
		kernelNATType:    normalizeEgressNATType(item.NATType),
	}
}

func buildEgressNATKernelCandidates(items []EgressNAT, planner *ruleDataplanePlanner, configuredKernelRulesMapLimit int, reservedKernelEntries int, usedIDs map[int64]struct{}, nextSyntheticID *int64) ([]kernelCandidateRule, map[int64]ruleDataplanePlan) {
	return buildEgressNATKernelCandidatesWithSnapshot(items, planner, configuredKernelRulesMapLimit, reservedKernelEntries, usedIDs, nextSyntheticID, loadEgressNATInterfaceSnapshot())
}

func buildEgressNATKernelCandidatesWithSnapshot(items []EgressNAT, planner *ruleDataplanePlanner, configuredKernelRulesMapLimit int, reservedKernelEntries int, usedIDs map[int64]struct{}, nextSyntheticID *int64, snapshot egressNATInterfaceSnapshot) ([]kernelCandidateRule, map[int64]ruleDataplanePlan) {
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
		entryPlans := make([]ruleDataplanePlan, 0)
		entryCandidates := make([]kernelCandidateRule, 0)

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

		for _, target := range targetInfos {
			for _, proto := range protocols {
				id, err := allocateSyntheticKernelRuleID(nextSyntheticID, usedIDs)
				if err != nil {
					entryPlans = append(entryPlans, ruleDataplanePlan{
						PreferredEngine: ruleEngineKernel,
						EffectiveEngine: ruleEngineUserspace,
						FallbackReason:  err.Error(),
					})
					continue
				}
				rule := buildEgressNATSyntheticRule(item, target.Name, id, proto)
				annotateKernelCandidateRule(&rule, owner)
				entryPlans = append(entryPlans, planner.Plan(rule))
				entryCandidates = append(entryCandidates, kernelCandidateRule{owner: owner, rule: rule})
			}
		}

		plan := aggregateKernelOwnerPlan(ruleEngineKernel, entryPlans)
		if item.Enabled && plan.EffectiveEngine == ruleEngineKernel {
			neededEntries := len(entryCandidates)
			requestedEntries := reservedKernelEntries + neededEntries
			if requestedEntries > effectiveKernelRulesMapLimit(configuredKernelRulesMapLimit, requestedEntries) {
				plan.EffectiveEngine = ruleEngineUserspace
				if plan.FallbackReason == "" {
					plan.FallbackReason = kernelRulesCapacityReason(configuredKernelRulesMapLimit, requestedEntries)
				}
			} else {
				candidates = append(candidates, entryCandidates...)
				reservedKernelEntries += neededEntries
			}
		}
		plans[item.ID] = plan
	}

	return candidates, plans
}
