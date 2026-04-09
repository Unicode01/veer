package app

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type managedNetworkRuntimeCompilation struct {
	IPv6Assignments    []IPv6Assignment
	EgressNATs         []EgressNAT
	RedistributeIfaces map[string]struct{}
	Previews           map[int64]managedNetworkRuntimePreview
	Warnings           []string
}

type managedNetworkRuntimePreview struct {
	ChildInterfaces              []string
	GeneratedIPv6AssignmentCount int
	GeneratedIPv6AssignmentIDs   []int64
	GeneratedEgressNAT           bool
	Warnings                     []string
}

type managedNetworkExplicitIPv6Target struct {
	ID             int64
	AssignedPrefix string
}

type managedNetworkInterfaceInventory struct {
	infos                 []InterfaceInfo
	ifaceByName           map[string]InterfaceInfo
	childTargetsByBridge  map[string][]managedNetworkChildTarget
	dedupeTargetsByBridge map[string]bool
}

type managedNetworkChildTarget struct {
	childName  string
	targetName string
}

type managedNetworkUsedIPv6PrefixIndex struct {
	mode     string
	exact128 map[[16]byte]struct{}
	exact64  map[[16]byte]struct{}
	broader  []*net.IPNet
	narrower []*net.IPNet
	generic  []*net.IPNet
}

var (
	managedNetworkIPv6FullMask     = net.CIDRMask(128, 128)
	managedNetworkIPv6Prefix64Mask = net.CIDRMask(64, 128)
)

func compileManagedNetworkRuntime(managedNetworks []ManagedNetwork, explicitIPv6 []IPv6Assignment, explicitEgressNATs []EgressNAT, infos []InterfaceInfo) managedNetworkRuntimeCompilation {
	if len(managedNetworks) == 0 {
		return managedNetworkRuntimeCompilation{}
	}

	inventory := buildManagedNetworkInterfaceInventory(infos, managedNetworkNeedsInterfaceInfoMap(managedNetworks))
	return compileManagedNetworkRuntimeWithInventory(managedNetworks, explicitIPv6, explicitEgressNATs, inventory)
}

func compileManagedNetworkRuntimeWithInventory(managedNetworks []ManagedNetwork, explicitIPv6 []IPv6Assignment, explicitEgressNATs []EgressNAT, inventory managedNetworkInterfaceInventory) managedNetworkRuntimeCompilation {
	if len(managedNetworks) == 0 {
		return managedNetworkRuntimeCompilation{}
	}

	explicitTargets := collectExplicitManagedNetworkIPv6Targets(explicitIPv6)
	usedPrefixes := collectManagedNetworkUsedIPv6Prefixes(explicitIPv6)
	redistributeIfaces := collectManagedNetworkRedistributeInterfaces(managedNetworks)
	networks := append([]ManagedNetwork(nil), managedNetworks...)
	slices.SortFunc(networks, func(a, b ManagedNetwork) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})
	for i := range networks {
		networks[i] = normalizeManagedNetwork(networks[i])
	}

	estimatedIPv6Assignments := 0
	estimatedSingle128Assignments := 0
	estimatedPrefix64Assignments := 0
	estimatedAutoEgressNATs := 0
	for _, network := range networks {
		if !network.Enabled {
			continue
		}
		if network.IPv6Enabled {
			count := countManagedNetworkIPv6TargetsFromInventory(network.Bridge, network.UplinkInterface, inventory)
			estimatedIPv6Assignments += count
			switch network.IPv6AssignmentMode {
			case managedNetworkIPv6AssignmentModeSingle128:
				estimatedSingle128Assignments += count
			case managedNetworkIPv6AssignmentModePrefix64:
				estimatedPrefix64Assignments += count
			}
		}
		if network.AutoEgressNAT {
			estimatedAutoEgressNATs++
		}
	}

	var (
		single128UsedPrefixIndex *managedNetworkUsedIPv6PrefixIndex
		prefix64UsedPrefixIndex  *managedNetworkUsedIPv6PrefixIndex
	)
	getUsedPrefixIndex := func(mode string) *managedNetworkUsedIPv6PrefixIndex {
		switch mode {
		case managedNetworkIPv6AssignmentModeSingle128:
			if single128UsedPrefixIndex == nil {
				single128UsedPrefixIndex = newManagedNetworkUsedIPv6PrefixIndexWithCapacity(mode, usedPrefixes, estimatedSingle128Assignments)
			}
			return single128UsedPrefixIndex
		case managedNetworkIPv6AssignmentModePrefix64:
			if prefix64UsedPrefixIndex == nil {
				prefix64UsedPrefixIndex = newManagedNetworkUsedIPv6PrefixIndexWithCapacity(mode, usedPrefixes, estimatedPrefix64Assignments)
			}
			return prefix64UsedPrefixIndex
		default:
			return nil
		}
	}

	var compiled managedNetworkRuntimeCompilation
	compiled.RedistributeIfaces = redistributeIfaces
	compiled.Previews = make(map[int64]managedNetworkRuntimePreview, len(networks))
	if estimatedIPv6Assignments > 0 {
		compiled.IPv6Assignments = make([]IPv6Assignment, 0, estimatedIPv6Assignments)
	}
	if estimatedAutoEgressNATs > 0 {
		compiled.EgressNATs = make([]EgressNAT, 0, estimatedAutoEgressNATs)
	}
	claimedTargets := make(map[string]struct{}, estimatedIPv6Assignments)
	activeEgressNATs := make([]EgressNAT, len(explicitEgressNATs), len(explicitEgressNATs)+estimatedAutoEgressNATs)
	copy(activeEgressNATs, explicitEgressNATs)

	for _, network := range networks {
		childNames := collectManagedNetworkIPv6TargetNamesFromInventory(network.Bridge, network.UplinkInterface, inventory)
		preview := managedNetworkRuntimePreview{
			ChildInterfaces: childNames,
		}
		if !network.Enabled {
			compiled.Previews[network.ID] = preview
			continue
		}

		if network.IPv6Enabled {
			usedPrefixIndex := getUsedPrefixIndex(network.IPv6AssignmentMode)
			parentInterface, parentPrefixText, parentPrefix, warnings := prepareManagedNetworkIPv6Parent(network)
			assignments, moreWarnings, allocatedPrefixes := buildManagedNetworkIPv6AssignmentsPrepared(network, childNames, parentInterface, parentPrefixText, parentPrefix, explicitTargets, claimedTargets, usedPrefixes, usedPrefixIndex)
			if len(moreWarnings) > 0 {
				warnings = append(warnings, moreWarnings...)
			}
			compiled.IPv6Assignments = append(compiled.IPv6Assignments, assignments...)
			compiled.Warnings = append(compiled.Warnings, warnings...)
			preview.GeneratedIPv6AssignmentCount = len(assignments)
			if len(assignments) > 0 {
				preview.GeneratedIPv6AssignmentIDs = make([]int64, len(assignments))
				for i, assignment := range assignments {
					preview.GeneratedIPv6AssignmentIDs[i] = assignment.ID
				}
			}
			preview.Warnings = warnings
			usedPrefixes = append(usedPrefixes, allocatedPrefixes...)
			for _, prefix := range allocatedPrefixes {
				if single128UsedPrefixIndex != nil && single128UsedPrefixIndex != usedPrefixIndex {
					single128UsedPrefixIndex.add(prefix)
				}
				if prefix64UsedPrefixIndex != nil && prefix64UsedPrefixIndex != usedPrefixIndex {
					prefix64UsedPrefixIndex.add(prefix)
				}
			}
		}
		if network.AutoEgressNAT {
			item, warning := buildManagedNetworkAutoEgressNAT(network, inventory.ifaceMap(), activeEgressNATs)
			if warning != "" {
				compiled.Warnings = append(compiled.Warnings, warning)
				preview.Warnings = append(preview.Warnings, warning)
			}
			if item.ID != 0 {
				compiled.EgressNATs = append(compiled.EgressNATs, item)
				activeEgressNATs = append(activeEgressNATs, item)
				preview.GeneratedEgressNAT = true
			}
		}
		compiled.Previews[network.ID] = preview
	}

	if len(compiled.RedistributeIfaces) == 0 {
		compiled.RedistributeIfaces = nil
	}
	return compiled
}

func managedNetworkNeedsInterfaceInfoMap(items []ManagedNetwork) bool {
	for _, item := range items {
		if item.AutoEgressNAT {
			return true
		}
	}
	return false
}

func buildManagedNetworkInterfaceInventory(infos []InterfaceInfo, prebuildIfaceByName bool) managedNetworkInterfaceInventory {
	inventory := managedNetworkInterfaceInventory{infos: infos}
	if len(infos) == 0 {
		return inventory
	}
	if prebuildIfaceByName {
		inventory.ifaceByName = buildInterfaceInfoMap(infos)
	}
	getIfaceByName := func() map[string]InterfaceInfo {
		return inventory.ifaceMap()
	}

	childTargetsByBridge := make(map[string][]managedNetworkChildTarget)
	var dedupeTargetsByBridge map[string]bool
	for _, info := range infos {
		bridge := strings.TrimSpace(info.Parent)
		if bridge == "" {
			continue
		}
		if !isEgressNATAttachableChild(info) {
			continue
		}
		childName := strings.TrimSpace(info.Name)
		if childName == "" {
			continue
		}
		targetName := childName
		if managedNetworkPortMayResolveToTap(childName) {
			targetName = resolveManagedNetworkIPv6TargetName(info, getIfaceByName())
		}
		if targetName != childName {
			if dedupeTargetsByBridge == nil {
				dedupeTargetsByBridge = make(map[string]bool)
			}
			dedupeTargetsByBridge[bridge] = true
		}
		childTargetsByBridge[bridge] = append(childTargetsByBridge[bridge], managedNetworkChildTarget{
			childName:  childName,
			targetName: targetName,
		})
	}
	if len(childTargetsByBridge) == 0 {
		return inventory
	}
	for bridge := range childTargetsByBridge {
		slices.SortFunc(childTargetsByBridge[bridge], func(a, b managedNetworkChildTarget) int {
			return strings.Compare(a.childName, b.childName)
		})
	}
	inventory.childTargetsByBridge = childTargetsByBridge
	inventory.dedupeTargetsByBridge = dedupeTargetsByBridge
	return inventory
}

func (inventory *managedNetworkInterfaceInventory) ifaceMap() map[string]InterfaceInfo {
	if inventory == nil {
		return nil
	}
	if inventory.ifaceByName == nil && len(inventory.infos) > 0 {
		inventory.ifaceByName = buildInterfaceInfoMap(inventory.infos)
	}
	return inventory.ifaceByName
}

func managedNetworkPortMayResolveToTap(name string) bool {
	return strings.HasPrefix(name, "fwpr") || strings.HasPrefix(name, "fwln")
}

func collectManagedNetworkRedistributeInterfaces(items []ManagedNetwork) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{})
	for _, item := range items {
		item = normalizeManagedNetwork(item)
		if !item.Enabled {
			continue
		}
		for _, name := range []string{item.Bridge, item.UplinkInterface, item.IPv6ParentInterface} {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			out[name] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func collectManagedNetworkChildInterfaces(bridge string, uplink string, infos []InterfaceInfo) []InterfaceInfo {
	bridge = strings.TrimSpace(bridge)
	uplink = strings.TrimSpace(uplink)
	if bridge == "" || len(infos) == 0 {
		return nil
	}

	children := make([]InterfaceInfo, 0)
	for _, info := range infos {
		if strings.TrimSpace(info.Parent) != bridge {
			continue
		}
		if uplink != "" && strings.EqualFold(strings.TrimSpace(info.Name), uplink) {
			continue
		}
		if !isEgressNATAttachableChild(info) {
			continue
		}
		children = append(children, info)
	}
	slices.SortFunc(children, func(a, b InterfaceInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return children
}

func collectManagedNetworkIPv6TargetInterfaces(bridge string, uplink string, infos []InterfaceInfo) []InterfaceInfo {
	return collectManagedNetworkIPv6TargetInterfacesFromInventory(bridge, uplink, buildManagedNetworkInterfaceInventory(infos, false))
}

func collectManagedNetworkIPv6TargetNamesFromInventory(bridge string, uplink string, inventory managedNetworkInterfaceInventory) []string {
	bridge = strings.TrimSpace(bridge)
	uplink = strings.TrimSpace(uplink)
	if bridge == "" {
		return nil
	}

	entries := inventory.childTargetsByBridge[bridge]
	if len(entries) == 0 {
		return nil
	}

	names := make([]string, 0, countManagedNetworkIPv6TargetsFromEntries(entries, uplink, inventory.dedupeTargetsByBridge[bridge]))
	if !inventory.dedupeTargetsByBridge[bridge] {
		for _, entry := range entries {
			if uplink != "" && strings.EqualFold(entry.childName, uplink) {
				continue
			}
			names = append(names, entry.targetName)
		}
		if len(names) == 0 {
			return nil
		}
		return names
	}

	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if uplink != "" && strings.EqualFold(entry.childName, uplink) {
			continue
		}
		if _, ok := seen[entry.targetName]; ok {
			continue
		}
		seen[entry.targetName] = struct{}{}
		names = append(names, entry.targetName)
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

func countManagedNetworkIPv6TargetsFromInventory(bridge string, uplink string, inventory managedNetworkInterfaceInventory) int {
	bridge = strings.TrimSpace(bridge)
	uplink = strings.TrimSpace(uplink)
	if bridge == "" {
		return 0
	}
	return countManagedNetworkIPv6TargetsFromEntries(inventory.childTargetsByBridge[bridge], uplink, inventory.dedupeTargetsByBridge[bridge])
}

func countManagedNetworkIPv6TargetsFromEntries(entries []managedNetworkChildTarget, uplink string, dedupe bool) int {
	if len(entries) == 0 {
		return 0
	}
	if !dedupe {
		count := 0
		for _, entry := range entries {
			if uplink != "" && strings.EqualFold(entry.childName, uplink) {
				continue
			}
			count++
		}
		return count
	}

	count := 0
	for i, entry := range entries {
		if uplink != "" && strings.EqualFold(entry.childName, uplink) {
			continue
		}
		duplicate := false
		for j := 0; j < i; j++ {
			if uplink != "" && strings.EqualFold(entries[j].childName, uplink) {
				continue
			}
			if entries[j].targetName == entry.targetName {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		count++
	}
	return count
}

func collectManagedNetworkIPv6TargetInterfacesFromInventory(bridge string, uplink string, inventory managedNetworkInterfaceInventory) []InterfaceInfo {
	bridge = strings.TrimSpace(bridge)
	uplink = strings.TrimSpace(uplink)
	if bridge == "" {
		return nil
	}

	entries := inventory.childTargetsByBridge[bridge]
	if len(entries) == 0 {
		return nil
	}

	if !inventory.dedupeTargetsByBridge[bridge] {
		targets := make([]InterfaceInfo, 0, len(entries))
		ifaceByName := inventory.ifaceMap()
		for _, entry := range entries {
			if uplink != "" && strings.EqualFold(entry.childName, uplink) {
				continue
			}
			target, ok := ifaceByName[entry.targetName]
			if !ok {
				target = InterfaceInfo{Name: entry.targetName}
			}
			targets = append(targets, target)
		}
		if len(targets) == 0 {
			return nil
		}
		return targets
	}

	targets := make([]InterfaceInfo, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	ifaceByName := inventory.ifaceMap()
	for _, entry := range entries {
		if uplink != "" && strings.EqualFold(entry.childName, uplink) {
			continue
		}
		if _, ok := seen[entry.targetName]; ok {
			continue
		}
		seen[entry.targetName] = struct{}{}
		target, ok := ifaceByName[entry.targetName]
		if !ok {
			target = InterfaceInfo{Name: entry.targetName}
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil
	}
	slices.SortFunc(targets, func(a, b InterfaceInfo) int {
		return strings.Compare(a.Name, b.Name)
	})
	return targets
}

func resolveManagedNetworkIPv6TargetName(child InterfaceInfo, ifaceByName map[string]InterfaceInfo) string {
	name := strings.TrimSpace(child.Name)
	if name == "" || len(ifaceByName) == 0 {
		return name
	}
	vmid, slot, ok := parseManagedNetworkProxmoxGuestPort(name)
	if !ok {
		return name
	}
	tapName := "tap" + vmid + "i" + slot
	tap, ok := ifaceByName[tapName]
	if !ok || strings.TrimSpace(tap.Name) == "" {
		return name
	}
	if !isManagedNetworkIPv6GuestFacingInterface(tap) {
		return name
	}
	return strings.TrimSpace(tap.Name)
}

func parseManagedNetworkProxmoxGuestPort(name string) (string, string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", "", false
	}

	prefixLen := 0
	switch {
	case strings.HasPrefix(name, "tap"):
		prefixLen = 3
	case strings.HasPrefix(name, "fwpr"), strings.HasPrefix(name, "fwln"):
		prefixLen = 4
	default:
		return "", "", false
	}

	vmidStart := prefixLen
	vmidEnd := vmidStart
	for vmidEnd < len(name) && name[vmidEnd] >= '0' && name[vmidEnd] <= '9' {
		vmidEnd++
	}
	if vmidEnd == vmidStart || vmidEnd >= len(name) {
		return "", "", false
	}
	switch name[vmidEnd] {
	case 'i', 'p':
	default:
		return "", "", false
	}
	slotStart := vmidEnd + 1
	if slotStart >= len(name) {
		return "", "", false
	}
	for idx := slotStart; idx < len(name); idx++ {
		if name[idx] < '0' || name[idx] > '9' {
			return "", "", false
		}
	}
	return name[vmidStart:vmidEnd], name[slotStart:], true
}

func isManagedNetworkIPv6GuestFacingInterface(info InterfaceInfo) bool {
	name := strings.TrimSpace(info.Name)
	if name == "" {
		return false
	}
	kind := strings.ToLower(strings.TrimSpace(info.Kind))
	switch kind {
	case "bridge":
		return false
	case "device":
		return false
	}
	return strings.HasPrefix(strings.ToLower(name), "tap")
}

func collectExplicitManagedNetworkIPv6Targets(items []IPv6Assignment) map[string][]managedNetworkExplicitIPv6Target {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string][]managedNetworkExplicitIPv6Target)
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		hydrateIPv6AssignmentCompatibilityFields(&item)
		target := strings.TrimSpace(item.TargetInterface)
		if target == "" {
			continue
		}
		out[target] = append(out[target], managedNetworkExplicitIPv6Target{
			ID:             item.ID,
			AssignedPrefix: strings.TrimSpace(item.AssignedPrefix),
		})
	}
	if len(out) == 0 {
		return nil
	}
	for target := range out {
		slices.SortFunc(out[target], func(a, b managedNetworkExplicitIPv6Target) int {
			if a.ID != b.ID {
				if a.ID < b.ID {
					return -1
				}
				return 1
			}
			return strings.Compare(a.AssignedPrefix, b.AssignedPrefix)
		})
	}
	return out
}

func collectManagedNetworkUsedIPv6Prefixes(items []IPv6Assignment) []*net.IPNet {
	if len(items) == 0 {
		return nil
	}
	out := make([]*net.IPNet, 0, len(items))
	for _, item := range items {
		if !item.Enabled {
			continue
		}
		hydrateIPv6AssignmentCompatibilityFields(&item)
		if strings.TrimSpace(item.AssignedPrefix) == "" {
			continue
		}
		_, prefix, err := normalizeIPv6Prefix(item.AssignedPrefix)
		if err != nil || prefix == nil {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

func buildManagedNetworkIPv6Assignments(network ManagedNetwork, childNames []string, explicitTargets map[string][]managedNetworkExplicitIPv6Target, claimedTargets map[string]struct{}, usedPrefixes []*net.IPNet) ([]IPv6Assignment, []string) {
	assignments, warnings, _ := buildManagedNetworkIPv6AssignmentsDetailed(network, childNames, explicitTargets, claimedTargets, usedPrefixes, nil)
	return assignments, warnings
}

func buildManagedNetworkIPv6AssignmentsDetailed(network ManagedNetwork, childNames []string, explicitTargets map[string][]managedNetworkExplicitIPv6Target, claimedTargets map[string]struct{}, usedPrefixes []*net.IPNet, usedPrefixIndex *managedNetworkUsedIPv6PrefixIndex) ([]IPv6Assignment, []string, []*net.IPNet) {
	parentInterface, parentPrefixText, parentPrefix, warnings := prepareManagedNetworkIPv6Parent(network)
	assignments, moreWarnings, allocatedPrefixes := buildManagedNetworkIPv6AssignmentsPrepared(network, childNames, parentInterface, parentPrefixText, parentPrefix, explicitTargets, claimedTargets, usedPrefixes, usedPrefixIndex)
	if len(moreWarnings) > 0 {
		warnings = append(warnings, moreWarnings...)
	}
	return assignments, warnings, allocatedPrefixes
}

func prepareManagedNetworkIPv6Parent(network ManagedNetwork) (string, string, *net.IPNet, []string) {
	parentPrefixText := strings.TrimSpace(network.IPv6ParentPrefix)
	parentInterface := strings.TrimSpace(network.IPv6ParentInterface)
	if parentInterface == "" {
		return "", "", nil, []string{fmt.Sprintf("managed network #%d (%s): ipv6 enabled but ipv6_parent_interface is empty", network.ID, network.Name)}
	}
	if parentPrefixText == "" {
		return parentInterface, "", nil, []string{fmt.Sprintf("managed network #%d (%s): ipv6 enabled but ipv6_parent_prefix is empty", network.ID, network.Name)}
	}
	parentPrefixText, parentPrefix, err := normalizeIPv6Prefix(parentPrefixText)
	if err != nil {
		return parentInterface, "", nil, []string{fmt.Sprintf("managed network #%d (%s): invalid ipv6_parent_prefix: %v", network.ID, network.Name, err)}
	}
	return parentInterface, parentPrefixText, parentPrefix, nil
}

func buildManagedNetworkIPv6AssignmentsPrepared(network ManagedNetwork, childNames []string, parentInterface string, parentPrefixText string, parentPrefix *net.IPNet, explicitTargets map[string][]managedNetworkExplicitIPv6Target, claimedTargets map[string]struct{}, usedPrefixes []*net.IPNet, usedPrefixIndex *managedNetworkUsedIPv6PrefixIndex) ([]IPv6Assignment, []string, []*net.IPNet) {
	if parentInterface == "" || parentPrefix == nil {
		return nil, nil, nil
	}
	if usedPrefixIndex == nil {
		usedPrefixIndex = newManagedNetworkUsedIPv6PrefixIndex(network.IPv6AssignmentMode, usedPrefixes)
	}

	assignments := make([]IPv6Assignment, 0, len(childNames))
	allocatedPrefixes := make([]*net.IPNet, 0, len(childNames))
	warnings := make([]string, 0)
	for _, childName := range childNames {
		childName = strings.TrimSpace(childName)
		if childName == "" {
			continue
		}
		if targets := explicitTargets[childName]; len(targets) > 0 {
			warnings = append(warnings, managedNetworkExplicitIPv6TargetWarning(network, childName, targets))
			continue
		}
		if _, ok := claimedTargets[childName]; ok {
			warnings = append(warnings, fmt.Sprintf("managed network #%d (%s): skip child %s because it is already claimed by another managed network", network.ID, network.Name, childName))
			continue
		}

		assignedPrefix, assignedNet, err := allocateManagedNetworkIPv6Prefix(network, childName, parentPrefix, usedPrefixes, usedPrefixIndex)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("managed network #%d (%s): skip child %s: %v", network.ID, network.Name, childName, err))
			continue
		}

		item := IPv6Assignment{
			ID:              managedNetworkSyntheticID("ipv6", network.ID, childName),
			ParentInterface: parentInterface,
			TargetInterface: childName,
			ParentPrefix:    parentPrefixText,
			AssignedPrefix:  assignedPrefix,
			Address:         managedNetworkPrefixAddress(assignedPrefix),
			Remark:          buildManagedNetworkIPv6Remark(network, childName),
			Enabled:         true,
		}
		switch network.IPv6AssignmentMode {
		case managedNetworkIPv6AssignmentModeSingle128:
			item.PrefixLen = 128
		case managedNetworkIPv6AssignmentModePrefix64:
			item.PrefixLen = 64
		default:
			item.PrefixLen, _ = assignedNet.Mask.Size()
		}
		assignments = append(assignments, item)
		allocatedPrefixes = append(allocatedPrefixes, assignedNet)
		usedPrefixes = append(usedPrefixes, assignedNet)
		usedPrefixIndex.add(assignedNet)
		claimedTargets[childName] = struct{}{}
	}

	return assignments, warnings, allocatedPrefixes
}

func managedNetworkExplicitIPv6TargetWarning(network ManagedNetwork, childName string, targets []managedNetworkExplicitIPv6Target) string {
	if len(targets) == 0 {
		return fmt.Sprintf("managed network #%d (%s): skip child %s because an explicit ipv6 assignment already targets this interface", network.ID, network.Name, childName)
	}
	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		part := fmt.Sprintf("#%d", target.ID)
		if prefix := strings.TrimSpace(target.AssignedPrefix); prefix != "" {
			part += " (" + prefix + ")"
		}
		parts = append(parts, part)
	}
	label := "assignment"
	verb := "targets"
	if len(parts) > 1 {
		label = "assignments"
		verb = "target"
	}
	return fmt.Sprintf(
		"managed network #%d (%s): skip child %s because explicit ipv6 %s %s already %s this interface",
		network.ID,
		network.Name,
		childName,
		label,
		strings.Join(parts, ", "),
		verb,
	)
}

func buildManagedNetworkIPv6Remark(network ManagedNetwork, childName string) string {
	name := strings.TrimSpace(network.Name)
	if name == "" {
		return "managed network " + strings.TrimSpace(childName)
	}
	return name + " / " + strings.TrimSpace(childName)
}

func managedNetworkPrefixAddress(prefixText string) string {
	if idx := strings.LastIndexByte(prefixText, '/'); idx > 0 {
		return prefixText[:idx]
	}
	return prefixText
}

func managedNetworkIPv6PrefixOverlaps(prefix *net.IPNet, used []*net.IPNet) bool {
	for _, current := range used {
		if ipv6PrefixesOverlap(prefix, current) {
			return true
		}
	}
	return false
}

func newManagedNetworkUsedIPv6PrefixIndex(mode string, used []*net.IPNet) *managedNetworkUsedIPv6PrefixIndex {
	return newManagedNetworkUsedIPv6PrefixIndexWithCapacity(mode, used, 0)
}

func newManagedNetworkUsedIPv6PrefixIndexWithCapacity(mode string, used []*net.IPNet, additionalExact int) *managedNetworkUsedIPv6PrefixIndex {
	index := &managedNetworkUsedIPv6PrefixIndex{mode: mode}
	if additionalExact > 0 {
		exactCapacity := len(used) + additionalExact
		switch mode {
		case managedNetworkIPv6AssignmentModeSingle128:
			index.exact128 = make(map[[16]byte]struct{}, exactCapacity)
		case managedNetworkIPv6AssignmentModePrefix64:
			index.exact64 = make(map[[16]byte]struct{}, exactCapacity)
		}
	}
	for _, prefix := range used {
		index.add(prefix)
	}
	return index
}

func (index *managedNetworkUsedIPv6PrefixIndex) add(prefix *net.IPNet) {
	if index == nil || prefix == nil {
		return
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		index.generic = append(index.generic, prefix)
		return
	}
	switch index.mode {
	case managedNetworkIPv6AssignmentModeSingle128:
		if ones == 128 {
			key, ok := managedNetworkIPv6AddressKey(prefix.IP)
			if !ok {
				index.generic = append(index.generic, prefix)
				return
			}
			if index.exact128 == nil {
				index.exact128 = make(map[[16]byte]struct{})
			}
			index.exact128[key] = struct{}{}
			return
		}
		if ones < 128 {
			index.broader = append(index.broader, prefix)
			return
		}
	case managedNetworkIPv6AssignmentModePrefix64:
		if ones == 64 {
			key, ok := managedNetworkIPv6AddressKey(prefix.IP)
			if !ok {
				index.generic = append(index.generic, prefix)
				return
			}
			if index.exact64 == nil {
				index.exact64 = make(map[[16]byte]struct{})
			}
			index.exact64[key] = struct{}{}
			return
		}
		if ones < 64 {
			index.broader = append(index.broader, prefix)
			return
		}
		if ones > 64 {
			index.narrower = append(index.narrower, prefix)
			return
		}
	}
	index.generic = append(index.generic, prefix)
}

func (index *managedNetworkUsedIPv6PrefixIndex) overlaps(prefix *net.IPNet, used []*net.IPNet) bool {
	if index == nil || prefix == nil {
		return managedNetworkIPv6PrefixOverlaps(prefix, used)
	}
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		return managedNetworkIPv6PrefixOverlaps(prefix, used)
	}

	switch index.mode {
	case managedNetworkIPv6AssignmentModeSingle128:
		if ones != 128 {
			return managedNetworkIPv6PrefixOverlaps(prefix, used)
		}
		if key, ok := managedNetworkIPv6AddressKey(prefix.IP); ok {
			if _, exists := index.exact128[key]; exists {
				return true
			}
		}
		for _, current := range index.broader {
			if current.Contains(prefix.IP) {
				return true
			}
		}
	case managedNetworkIPv6AssignmentModePrefix64:
		if ones != 64 {
			return managedNetworkIPv6PrefixOverlaps(prefix, used)
		}
		if key, ok := managedNetworkIPv6AddressKey(prefix.IP); ok {
			if _, exists := index.exact64[key]; exists {
				return true
			}
		}
		for _, current := range index.broader {
			if current.Contains(prefix.IP) {
				return true
			}
		}
		for _, current := range index.narrower {
			if prefix.Contains(current.IP) {
				return true
			}
		}
	default:
		return managedNetworkIPv6PrefixOverlaps(prefix, used)
	}

	for _, current := range index.generic {
		if ipv6PrefixesOverlap(prefix, current) {
			return true
		}
	}
	return false
}

func managedNetworkIPv6AddressKey(ip net.IP) ([16]byte, bool) {
	var key [16]byte
	if len(ip) < net.IPv6len {
		return key, false
	}
	copy(key[:], ip[len(ip)-net.IPv6len:])
	return key, true
}

func allocateManagedNetworkIPv6Prefix(network ManagedNetwork, childName string, parentPrefix *net.IPNet, usedPrefixes []*net.IPNet, usedPrefixIndex *managedNetworkUsedIPv6PrefixIndex) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	hashValue := managedNetworkHash(network.ID, childName)
	for probe := 0; probe < 4096; probe++ {
		value := hashValue + uint64(probe)
		var (
			prefixText string
			prefixNet  *net.IPNet
			err        error
		)
		switch network.IPv6AssignmentMode {
		case managedNetworkIPv6AssignmentModeSingle128:
			prefixText, prefixNet, err = allocateManagedNetworkSingleIPv6(parentPrefix, value)
		case managedNetworkIPv6AssignmentModePrefix64:
			prefixText, prefixNet, err = allocateManagedNetworkDelegatedIPv6Prefix(parentPrefix, value)
		default:
			return "", nil, fmt.Errorf("unsupported ipv6 assignment mode %q", network.IPv6AssignmentMode)
		}
		if err != nil {
			return "", nil, err
		}
		if !usedPrefixIndex.overlaps(prefixNet, usedPrefixes) {
			return prefixText, prefixNet, nil
		}
	}
	return "", nil, fmt.Errorf("no free ipv6 allocation slot remains inside %s", parentPrefix.String())
}

func allocateManagedNetworkSingleIPv6(parentPrefix *net.IPNet, hashValue uint64) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	ones, bits := parentPrefix.Mask.Size()
	if ones < 0 || bits != 128 || ones >= 128 {
		return "", nil, fmt.Errorf("parent prefix must leave room for /128 assignments")
	}

	hostBits := 128 - ones
	value := hashValue
	if hostBits <= 64 {
		mask := managedNetworkBitMask(hostBits)
		value &= mask
		if hostBits > 1 && value == 0 {
			value = 1
		}
	}

	ip := applyManagedNetworkLowBits(parentPrefix.IP, value, ones, 128)
	prefix := &net.IPNet{IP: ip, Mask: managedNetworkIPv6FullMask}
	return managedNetworkPrefixText(ip, "/128"), prefix, nil
}

func allocateManagedNetworkDelegatedIPv6Prefix(parentPrefix *net.IPNet, hashValue uint64) (string, *net.IPNet, error) {
	if parentPrefix == nil {
		return "", nil, fmt.Errorf("parent prefix is required")
	}
	ones, bits := parentPrefix.Mask.Size()
	if ones < 0 || bits != 128 {
		return "", nil, fmt.Errorf("parent prefix must be a valid IPv6 prefix")
	}
	if ones >= 64 {
		return "", nil, fmt.Errorf("parent prefix must be shorter than /64 for prefix_64 mode")
	}

	subnetBits := 64 - ones
	value := hashValue & managedNetworkBitMask(subnetBits)
	ip := applyManagedNetworkHighBits(parentPrefix.IP, value, ones, 64)
	ip = ip.Mask(managedNetworkIPv6Prefix64Mask)
	prefix := &net.IPNet{IP: ip, Mask: managedNetworkIPv6Prefix64Mask}
	return managedNetworkPrefixText(ip, "/64"), prefix, nil
}

func managedNetworkPrefixText(ip net.IP, suffix string) string {
	if key, ok := managedNetworkIPv6AddressKey(ip); ok {
		var buf [48]byte
		out := netip.AddrFrom16(key).AppendTo(buf[:0])
		out = append(out, suffix...)
		return string(out)
	}
	return canonicalIPLiteral(ip) + suffix
}

func buildManagedNetworkAutoEgressNAT(network ManagedNetwork, ifaceByName map[string]InterfaceInfo, existing []EgressNAT) (EgressNAT, string) {
	bridge := strings.TrimSpace(network.Bridge)
	uplink := strings.TrimSpace(network.UplinkInterface)
	if bridge == "" {
		return EgressNAT{}, fmt.Sprintf("managed network #%d (%s): auto egress nat enabled but bridge is empty", network.ID, network.Name)
	}
	if uplink == "" {
		return EgressNAT{}, fmt.Sprintf("managed network #%d (%s): auto egress nat enabled but uplink_interface is empty", network.ID, network.Name)
	}

	item := EgressNAT{
		ID:              managedNetworkSyntheticID("egress_nat", network.ID, bridge),
		ParentInterface: bridge,
		OutInterface:    uplink,
		Protocol:        "tcp+udp+icmp",
		NATType:         egressNATTypeSymmetric,
		Enabled:         true,
	}
	item = normalizeEgressNATScope(item, ifaceByName)
	for _, current := range existing {
		if !current.Enabled {
			continue
		}
		current = normalizeEgressNATScope(current, ifaceByName)
		if !egressNATScopesOverlap(item, current, ifaceByName) {
			continue
		}
		return EgressNAT{}, fmt.Sprintf("managed network #%d (%s): skip auto egress nat because it overlaps egress nat #%d", network.ID, network.Name, current.ID)
	}
	return item, ""
}

func managedNetworkSyntheticID(kind string, networkID int64, key string) int64 {
	value := managedNetworkHash(networkID, kind+":"+strings.TrimSpace(key))
	id := int64(value & 0x3fffffffffffffff)
	if id == 0 {
		id = networkID + 1
	}
	return -id
}

func managedNetworkHash(networkID int64, key string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strconv.FormatInt(networkID, 10)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(key)))
	return h.Sum64()
}

func managedNetworkBitMask(bits int) uint64 {
	switch {
	case bits <= 0:
		return 0
	case bits >= 64:
		return ^uint64(0)
	default:
		return (uint64(1) << bits) - 1
	}
}

func applyManagedNetworkLowBits(baseIP net.IP, value uint64, prefixLen int, totalBits int) net.IP {
	if totalBits == 128 {
		if ip := applyManagedNetworkLowBitsIPv6(baseIP, value, prefixLen); len(ip) == net.IPv6len {
			return ip
		}
	}
	ip := append(net.IP(nil), baseIP.Mask(net.CIDRMask(prefixLen, totalBits))...)
	if len(ip) != net.IPv6len {
		ip = append(net.IP(nil), baseIP.To16()...)
	}
	for i := 0; i < 64; i++ {
		bitPos := totalBits - 1 - i
		if bitPos < prefixLen {
			break
		}
		managedNetworkSetBit(ip, bitPos, (value>>i)&1 == 1)
	}
	return ip
}

func applyManagedNetworkLowBitsIPv6(baseIP net.IP, value uint64, prefixLen int) net.IP {
	ip := baseIP.To16()
	if len(ip) != net.IPv6len {
		return nil
	}

	out := append(net.IP(nil), ip...)
	switch {
	case prefixLen <= 0:
		for i := range out {
			out[i] = 0
		}
	case prefixLen < 128:
		fullBytes := prefixLen / 8
		remBits := prefixLen % 8
		if remBits != 0 {
			out[fullBytes] &= byte(0xff << (8 - remBits))
			fullBytes++
		}
		for i := fullBytes; i < len(out); i++ {
			out[i] = 0
		}
	}

	var low [8]byte
	binary.BigEndian.PutUint64(low[:], value)
	if prefixLen <= 64 {
		copy(out[8:], low[:])
		return out
	}
	if prefixLen >= 128 {
		return out
	}

	keepBits := prefixLen - 64
	keepBytes := keepBits / 8
	keepRemainder := keepBits % 8
	target := out[8:]
	if keepRemainder == 0 {
		copy(target[keepBytes:], low[keepBytes:])
		return out
	}

	mask := byte(0xff << (8 - keepRemainder))
	target[keepBytes] = (target[keepBytes] & mask) | (low[keepBytes] &^ mask)
	copy(target[keepBytes+1:], low[keepBytes+1:])
	return out
}

func applyManagedNetworkHighBits(baseIP net.IP, value uint64, prefixLen int, targetPrefixLen int) net.IP {
	ip := append(net.IP(nil), baseIP.Mask(net.CIDRMask(prefixLen, 128))...)
	if len(ip) != net.IPv6len {
		ip = append(net.IP(nil), baseIP.To16()...)
	}
	availableBits := targetPrefixLen - prefixLen
	for i := 0; i < availableBits && i < 64; i++ {
		bitPos := targetPrefixLen - 1 - i
		managedNetworkSetBit(ip, bitPos, (value>>i)&1 == 1)
	}
	return ip
}

func managedNetworkSetBit(ip net.IP, bitPos int, on bool) {
	if len(ip) != net.IPv6len || bitPos < 0 || bitPos >= 128 {
		return
	}
	byteIndex := bitPos / 8
	bitIndex := 7 - (bitPos % 8)
	if on {
		ip[byteIndex] |= 1 << bitIndex
		return
	}
	ip[byteIndex] &^= 1 << bitIndex
}
