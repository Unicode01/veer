package app

import (
	"fmt"
	"net"
	"strings"
)

type ipv6AssignmentIntent struct {
	kind       string
	addressing string
	prefixLen  int
}

const (
	ipv6AssignmentIntentSingleAddress   = "single_address"
	ipv6AssignmentIntentDelegatedPrefix = "delegated_prefix"

	ipv6AssignmentAddressingStatic           = "static"
	ipv6AssignmentAddressingSLAACRecommended = "slaac_recommended"
	ipv6AssignmentAddressingManualDelegation = "manual_delegation"
)

var loadHostNetworkInterfacesForIPv6AssignmentTests func() ([]HostNetworkInterface, error)

func loadIPv6AssignmentHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	load := loadCurrentHostNetworkInterfaces
	if loadHostNetworkInterfacesForIPv6AssignmentTests != nil {
		load = loadHostNetworkInterfacesForIPv6AssignmentTests
	}
	return load()
}

func normalizeSpecificIPv6(value string) (string, net.IP, error) {
	ip := parseIPLiteral(value)
	if ip == nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 address")
	}
	if ip.To4() != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 address")
	}
	ip = ip.To16()
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return "", nil, fmt.Errorf("must be a specific non-loopback IPv6 address")
	}
	return canonicalIPLiteral(ip), ip, nil
}

func normalizeIPv6Prefix(value string) (string, *net.IPNet, error) {
	text := strings.TrimSpace(value)
	if text == "" {
		return "", nil, fmt.Errorf("is required")
	}
	ip, prefix, err := net.ParseCIDR(text)
	if err != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	if ip == nil || ip.To4() != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	ip = ip.To16()
	if ip == nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	prefix = &net.IPNet{IP: ip.Mask(prefix.Mask), Mask: prefix.Mask}
	if prefix.IP == nil || prefix.IP.To4() != nil {
		return "", nil, fmt.Errorf("must be a valid IPv6 CIDR prefix")
	}
	return prefix.String(), prefix, nil
}

func normalizeIPv6AssignmentLegacyPrefix(address string, prefixLen int) (string, *net.IPNet, error) {
	text := strings.TrimSpace(address)
	if text == "" {
		return "", nil, fmt.Errorf("is required")
	}
	if strings.Contains(text, "/") {
		return normalizeIPv6Prefix(text)
	}
	_, ip, err := normalizeSpecificIPv6(text)
	if err != nil {
		return "", nil, err
	}
	if prefixLen == 0 {
		prefixLen = 128
	}
	if prefixLen < 1 || prefixLen > 128 {
		return "", nil, fmt.Errorf("must be between 1 and 128")
	}
	mask := net.CIDRMask(prefixLen, 128)
	if mask == nil {
		return "", nil, fmt.Errorf("must be between 1 and 128")
	}
	prefix := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	return prefix.String(), prefix, nil
}

func hydrateIPv6AssignmentCompatibilityFields(item *IPv6Assignment) {
	if item == nil {
		return
	}
	item.ParentInterface = strings.TrimSpace(item.ParentInterface)
	item.TargetInterface = strings.TrimSpace(item.TargetInterface)
	item.ParentPrefix = strings.TrimSpace(item.ParentPrefix)
	item.AssignedPrefix = strings.TrimSpace(item.AssignedPrefix)
	item.Address = strings.TrimSpace(item.Address)
	item.Remark = strings.TrimSpace(item.Remark)

	var (
		normalized string
		prefix     *net.IPNet
		err        error
	)
	if item.AssignedPrefix != "" {
		normalized, prefix, err = normalizeIPv6Prefix(item.AssignedPrefix)
	} else if item.Address != "" {
		normalized, prefix, err = normalizeIPv6AssignmentLegacyPrefix(item.Address, item.PrefixLen)
	}
	if err != nil || prefix == nil {
		return
	}

	item.AssignedPrefix = normalized
	item.Address = canonicalIPLiteral(prefix.IP)
	ones, _ := prefix.Mask.Size()
	item.PrefixLen = ones
}

func normalizeIPv6AssignmentRequestedPrefix(item IPv6Assignment) (string, *net.IPNet, string, error) {
	assignedPrefix := strings.TrimSpace(item.AssignedPrefix)
	if assignedPrefix != "" {
		normalized, prefix, err := normalizeIPv6Prefix(assignedPrefix)
		return normalized, prefix, "assigned_prefix", err
	}
	if strings.TrimSpace(item.Address) == "" {
		return "", nil, "assigned_prefix", fmt.Errorf("is required")
	}
	normalized, prefix, err := normalizeIPv6AssignmentLegacyPrefix(item.Address, item.PrefixLen)
	field := "address"
	if err != nil && err.Error() == "must be between 1 and 128" {
		field = "prefix_len"
	}
	return normalized, prefix, field, err
}

// classifyIPv6AssignmentIntent captures the intended target-side use semantics.
// Runtime code must route or delegate this prefix to the target instead of
// binding it onto the host-side target interface.
func classifyIPv6AssignmentIntent(prefix *net.IPNet) ipv6AssignmentIntent {
	intent := ipv6AssignmentIntent{
		kind:       ipv6AssignmentIntentDelegatedPrefix,
		addressing: ipv6AssignmentAddressingManualDelegation,
	}
	if prefix == nil {
		return intent
	}
	ones, bits := prefix.Mask.Size()
	intent.prefixLen = ones
	if ones < 0 || bits != 128 {
		return intent
	}
	if ones == 128 {
		intent.kind = ipv6AssignmentIntentSingleAddress
		intent.addressing = ipv6AssignmentAddressingStatic
		return intent
	}
	if ones == 64 {
		intent.addressing = ipv6AssignmentAddressingSLAACRecommended
	}
	return intent
}

func ipv6PrefixContainsPrefix(parent, child *net.IPNet) bool {
	if parent == nil || child == nil {
		return false
	}
	parentOnes, parentBits := parent.Mask.Size()
	childOnes, childBits := child.Mask.Size()
	if parentOnes < 0 || childOnes < 0 || parentBits != 128 || childBits != 128 {
		return false
	}
	if childOnes < parentOnes {
		return false
	}
	return parent.Contains(child.IP)
}

func ipv6PrefixesOverlap(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func hostNetworkInterfaceIPv6Prefixes(item HostNetworkInterface) []string {
	if len(item.Addresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(item.Addresses))
	seen := make(map[string]struct{}, len(item.Addresses))
	for _, address := range item.Addresses {
		if address.Family != ipFamilyIPv6 {
			continue
		}
		prefix := strings.TrimSpace(address.CIDR)
		if prefix == "" {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

type ipv6ParentPrefixSelectionClass string

const (
	ipv6ParentPrefixSelectionClassOther  ipv6ParentPrefixSelectionClass = "other"
	ipv6ParentPrefixSelectionClassPublic ipv6ParentPrefixSelectionClass = "public"
	ipv6ParentPrefixSelectionClassULA    ipv6ParentPrefixSelectionClass = "ula"
)

type ipv6ParentPrefixCandidate struct {
	text   string
	prefix *net.IPNet
}

func isIPv6ULA(ip net.IP) bool {
	ip = ip.To16()
	return len(ip) == net.IPv6len && ip.To4() == nil && (ip[0]&0xfe) == 0xfc
}

func classifyIPv6ParentPrefixSelection(prefix *net.IPNet) ipv6ParentPrefixSelectionClass {
	if prefix == nil || prefix.IP == nil {
		return ipv6ParentPrefixSelectionClassOther
	}
	ip := prefix.IP.Mask(prefix.Mask).To16()
	if len(ip) != net.IPv6len || ip.To4() != nil {
		return ipv6ParentPrefixSelectionClassOther
	}
	switch {
	case isIPv6ULA(ip):
		return ipv6ParentPrefixSelectionClassULA
	case ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast():
		return ipv6ParentPrefixSelectionClassPublic
	default:
		return ipv6ParentPrefixSelectionClassOther
	}
}

func selectCurrentIPv6ParentPrefix(item HostNetworkInterface, stored *net.IPNet) (string, *net.IPNet, error) {
	if stored == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	storedText := stored.String()
	if hostNetworkInterfaceHasPrefix(item, storedText) {
		return storedText, cloneIPv6Net(stored), nil
	}
	storedOnes, storedBits := stored.Mask.Size()
	if storedOnes < 0 || storedBits != 128 {
		return "", nil, fmt.Errorf("parent prefix %s must be a valid IPv6 prefix", storedText)
	}

	candidates := make([]ipv6ParentPrefixCandidate, 0)
	for _, prefixText := range hostNetworkInterfaceIPv6Prefixes(item) {
		normalized, prefix, err := normalizeIPv6Prefix(prefixText)
		if err != nil || prefix == nil {
			continue
		}
		ones, bits := prefix.Mask.Size()
		if ones != storedOnes || bits != 128 {
			continue
		}
		candidates = append(candidates, ipv6ParentPrefixCandidate{text: normalized, prefix: prefix})
	}

	candidates = filterIPv6ParentPrefixCandidatesByClass(candidates, classifyIPv6ParentPrefixSelection(stored))
	if len(candidates) == 0 {
		return "", nil, fmt.Errorf("parent prefix %s is not present on %s and no current matching IPv6 /%d prefix is available", storedText, strings.TrimSpace(item.Name), storedOnes)
	}
	switch len(candidates) {
	case 1:
		if candidates[0].prefix == nil {
			return "", nil, fmt.Errorf("current parent prefix %s on %s is invalid", strings.TrimSpace(candidates[0].text), strings.TrimSpace(item.Name))
		}
		return candidates[0].text, cloneIPv6Net(candidates[0].prefix), nil
	default:
		names := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			names = append(names, candidate.text)
		}
		return "", nil, fmt.Errorf("parent prefix %s is not present on %s and multiple current matching IPv6 /%d prefixes exist: %s", storedText, strings.TrimSpace(item.Name), storedOnes, strings.Join(names, ", "))
	}
}

func filterIPv6ParentPrefixCandidatesByClass(candidates []ipv6ParentPrefixCandidate, wantClass ipv6ParentPrefixSelectionClass) []ipv6ParentPrefixCandidate {
	if len(candidates) == 0 || wantClass == ipv6ParentPrefixSelectionClassOther {
		return candidates
	}
	filtered := make([]ipv6ParentPrefixCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if classifyIPv6ParentPrefixSelection(candidate.prefix) != wantClass {
			continue
		}
		filtered = append(filtered, candidate)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func ipv6PrefixBitIsSet(ip net.IP, bitPos int) bool {
	ip = ip.To16()
	if len(ip) != net.IPv6len || bitPos < 0 || bitPos >= 128 {
		return false
	}
	byteIndex := bitPos / 8
	bitIndex := 7 - (bitPos % 8)
	return ip[byteIndex]&(1<<bitIndex) != 0
}

func rebaseIPv6PrefixWithinParent(storedParent *net.IPNet, currentParent *net.IPNet, assigned *net.IPNet) (*net.IPNet, error) {
	if storedParent == nil || currentParent == nil || assigned == nil {
		return nil, fmt.Errorf("stored parent, current parent, and assigned prefix are required")
	}
	storedOnes, storedBits := storedParent.Mask.Size()
	currentOnes, currentBits := currentParent.Mask.Size()
	assignedOnes, assignedBits := assigned.Mask.Size()
	if storedOnes < 0 || currentOnes < 0 || assignedOnes < 0 || storedBits != 128 || currentBits != 128 || assignedBits != 128 {
		return nil, fmt.Errorf("all prefixes must be valid IPv6 prefixes")
	}
	if storedOnes != currentOnes {
		return nil, fmt.Errorf("parent prefix length changed from /%d to /%d", storedOnes, currentOnes)
	}
	if assignedOnes < storedOnes {
		return nil, fmt.Errorf("assigned prefix %s is shorter than parent prefix %s", assigned.String(), storedParent.String())
	}

	ip := append(net.IP(nil), currentParent.IP.Mask(currentParent.Mask)...)
	if len(ip) != net.IPv6len {
		ip = append(net.IP(nil), currentParent.IP.To16()...)
	}
	if len(ip) != net.IPv6len {
		return nil, fmt.Errorf("current parent prefix %s must use a valid IPv6 address", currentParent.String())
	}
	assignedIP := assigned.IP.Mask(assigned.Mask).To16()
	if len(assignedIP) != net.IPv6len {
		return nil, fmt.Errorf("assigned prefix %s must use a valid IPv6 address", assigned.String())
	}
	for bitPos := storedOnes; bitPos < 128; bitPos++ {
		managedNetworkSetBit(ip, bitPos, ipv6PrefixBitIsSet(assignedIP, bitPos))
	}
	ip = ip.Mask(net.CIDRMask(assignedOnes, 128))
	return &net.IPNet{
		IP:   append(net.IP(nil), ip...),
		Mask: append(net.IPMask(nil), assigned.Mask...),
	}, nil
}

func resolveIPv6AssignmentForCurrentHost(item IPv6Assignment, ifaceByName map[string]HostNetworkInterface) (IPv6Assignment, bool, error) {
	hydrateIPv6AssignmentCompatibilityFields(&item)
	if len(ifaceByName) == 0 {
		return item, false, nil
	}
	parentInterface := strings.TrimSpace(item.ParentInterface)
	if parentInterface == "" {
		return item, false, nil
	}
	iface, ok := ifaceByName[parentInterface]
	if !ok {
		return item, false, nil
	}

	parentPrefixText := strings.TrimSpace(item.ParentPrefix)
	if parentPrefixText == "" {
		return item, false, nil
	}
	normalizedParentPrefix, storedParent, err := normalizeIPv6Prefix(parentPrefixText)
	if err != nil || storedParent == nil {
		return item, false, nil
	}
	if hostNetworkInterfaceHasPrefix(iface, normalizedParentPrefix) {
		return item, false, nil
	}

	currentParentText, currentParent, err := selectCurrentIPv6ParentPrefix(iface, storedParent)
	if err != nil {
		return item, false, err
	}
	assignedPrefixText, assignedPrefix, _, err := normalizeIPv6AssignmentRequestedPrefix(item)
	if err != nil || assignedPrefix == nil {
		return item, false, nil
	}
	rebasedAssigned, err := rebaseIPv6PrefixWithinParent(storedParent, currentParent, assignedPrefix)
	if err != nil {
		return item, false, err
	}
	item.ParentPrefix = currentParentText
	item.AssignedPrefix = rebasedAssigned.String()
	item.Address = canonicalIPLiteral(rebasedAssigned.IP)
	item.PrefixLen, _ = rebasedAssigned.Mask.Size()
	if item.AssignedPrefix == assignedPrefixText && item.ParentPrefix == normalizedParentPrefix {
		return item, false, nil
	}
	return item, true, nil
}

func hostNetworkInterfaceHasPrefix(item HostNetworkInterface, prefix string) bool {
	for _, address := range item.Addresses {
		if address.Family != ipFamilyIPv6 {
			continue
		}
		if address.CIDR == prefix {
			return true
		}
	}
	return false
}

func hostNetworkHasAddress(items []HostNetworkInterface, address string) bool {
	for _, item := range items {
		for _, current := range item.Addresses {
			if current.IP == address {
				return true
			}
		}
	}
	return false
}

func normalizeAndValidateIPv6Assignment(item IPv6Assignment, scope string, requireID bool, ifaceByName map[string]HostNetworkInterface, hostIfaces []HostNetworkInterface, existing []IPv6Assignment) (IPv6Assignment, []ruleValidationIssue) {
	item.ParentInterface = strings.TrimSpace(item.ParentInterface)
	item.TargetInterface = strings.TrimSpace(item.TargetInterface)
	item.ParentPrefix = strings.TrimSpace(item.ParentPrefix)
	item.AssignedPrefix = strings.TrimSpace(item.AssignedPrefix)
	item.Address = strings.TrimSpace(item.Address)
	item.Remark = strings.TrimSpace(item.Remark)

	var issues []ruleValidationIssue
	if requireID {
		if item.ID <= 0 {
			issues = appendRuleIssue(issues, scope, 0, item.ID, "id", "is required")
		}
	} else if item.ID != 0 {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "id", "must be omitted when creating an ipv6 assignment")
	}

	if item.ParentInterface == "" {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "parent_interface", "is required")
	}
	if item.TargetInterface == "" {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "target_interface", "is required")
	}
	if item.ParentInterface != "" {
		if _, ok := ifaceByName[item.ParentInterface]; !ok {
			issues = appendRuleIssue(issues, scope, 0, item.ID, "parent_interface", "interface does not exist on this host")
		}
	}
	if item.TargetInterface != "" {
		if _, ok := ifaceByName[item.TargetInterface]; !ok {
			issues = appendRuleIssue(issues, scope, 0, item.ID, "target_interface", "interface does not exist on this host")
		}
	}
	if item.ParentInterface != "" && item.TargetInterface != "" && item.ParentInterface == item.TargetInterface {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "target_interface", "must be different from parent_interface")
	}

	var prefixNet *net.IPNet
	if normalized, parsed, err := normalizeIPv6Prefix(item.ParentPrefix); err != nil {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "parent_prefix", err.Error())
	} else {
		item.ParentPrefix = normalized
		prefixNet = parsed
	}

	var assignedPrefixNet *net.IPNet
	if normalized, parsed, field, err := normalizeIPv6AssignmentRequestedPrefix(item); err != nil {
		issues = appendRuleIssue(issues, scope, 0, item.ID, field, err.Error())
	} else {
		item.AssignedPrefix = normalized
		assignedPrefixNet = parsed
		item.Address = canonicalIPLiteral(parsed.IP)
		item.PrefixLen, _ = parsed.Mask.Size()
	}
	intent := classifyIPv6AssignmentIntent(assignedPrefixNet)

	if item.ParentInterface != "" && item.ParentPrefix != "" {
		iface, ok := ifaceByName[item.ParentInterface]
		if ok && !hostNetworkInterfaceHasPrefix(iface, item.ParentPrefix) {
			issues = appendRuleIssue(issues, scope, 0, item.ID, "parent_prefix", "must exist on the selected parent_interface")
		}
	}
	if prefixNet != nil && assignedPrefixNet != nil && !ipv6PrefixContainsPrefix(prefixNet, assignedPrefixNet) {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "assigned_prefix", "must be contained within parent_prefix")
	}
	if intent.kind == ipv6AssignmentIntentSingleAddress && item.Address != "" && hostNetworkHasAddress(hostIfaces, item.Address) {
		issues = appendRuleIssue(issues, scope, 0, item.ID, "address", "is already assigned on the host")
	}

	for _, current := range existing {
		if current.ID == item.ID {
			continue
		}
		hydrateIPv6AssignmentCompatibilityFields(&current)
		if current.AssignedPrefix == "" || assignedPrefixNet == nil {
			continue
		}
		_, currentPrefixNet, err := normalizeIPv6Prefix(current.AssignedPrefix)
		if err != nil {
			continue
		}
		if ipv6PrefixesOverlap(assignedPrefixNet, currentPrefixNet) {
			issues = appendRuleIssue(issues, scope, 0, item.ID, "assigned_prefix", fmt.Sprintf("overlaps with ipv6 assignment #%d", current.ID))
		}
	}

	hydrateIPv6AssignmentCompatibilityFields(&item)
	return item, issues
}
