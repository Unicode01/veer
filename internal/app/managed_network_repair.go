package app

import (
	"fmt"
	"strings"
)

type managedNetworkPVEBridgeBinding struct {
	VMID   string
	Slot   string
	Bridge string
}

type managedNetworkRepairResult struct {
	Bridges    []string
	GuestLinks []string
}

var repairManagedNetworkHostStateForTests func([]ManagedNetwork) (managedNetworkRepairResult, error)

func repairManagedNetworkHostStateWithHook(items []ManagedNetwork) (managedNetworkRepairResult, error) {
	if repairManagedNetworkHostStateForTests != nil {
		return repairManagedNetworkHostStateForTests(items)
	}
	return repairManagedNetworkHostState(items)
}

func summarizeManagedNetworkRepairResult(result managedNetworkRepairResult) string {
	parts := make([]string, 0, 2)
	if summary := summarizeManagedRuntimeReloadInterfaces(stringSliceToSet(result.Bridges)); summary != "" {
		parts = append(parts, "bridges="+summary)
	}
	if summary := summarizeManagedRuntimeReloadInterfaces(stringSliceToSet(result.GuestLinks)); summary != "" {
		parts = append(parts, "guest_links="+summary)
	}
	return strings.Join(parts, " ")
}

func managedNetworkRepairResultInterfaceNames(result managedNetworkRepairResult) []string {
	names := make([]string, 0, len(result.Bridges)+len(result.GuestLinks)*2)
	names = append(names, result.Bridges...)
	for _, item := range result.GuestLinks {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "->", 2)
		names = append(names, strings.TrimSpace(parts[0]))
		if len(parts) == 2 {
			names = append(names, strings.TrimSpace(parts[1]))
		}
	}
	return uniqueManagedNetworkRuntimeInterfaceNames(names...)
}

func stringSliceToSet(items []string) map[string]struct{} {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out[item] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseManagedNetworkPVEBridgeBindings(vmid string, content string) []managedNetworkPVEBridgeBinding {
	nics := parseManagedNetworkPVEGuestNICs(vmid, content)
	if len(nics) == 0 {
		return nil
	}
	out := make([]managedNetworkPVEBridgeBinding, 0)
	for _, nic := range nics {
		bridge := strings.TrimSpace(nic.Bridge)
		if bridge == "" {
			continue
		}
		out = append(out, managedNetworkPVEBridgeBinding{
			VMID:   strings.TrimSpace(nic.VMID),
			Slot:   strings.TrimSpace(nic.Slot),
			Bridge: bridge,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func parseManagedNetworkPVEBridgeFromConfigValue(value string) string {
	for _, token := range strings.Split(value, ",") {
		part := strings.TrimSpace(token)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(kv[0]), "bridge") {
			continue
		}
		bridge := strings.TrimSpace(kv[1])
		if bridge == "" || strings.EqualFold(bridge, "none") {
			return ""
		}
		return bridge
	}
	return ""
}

func buildManagedNetworkRepairInterfaceParentMap(infos []InterfaceInfo) map[string]string {
	if len(infos) == 0 {
		return nil
	}
	out := make(map[string]string, len(infos))
	for _, info := range infos {
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		out[name] = strings.TrimSpace(info.Parent)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildManagedNetworkRepairIssueMap(items []ManagedNetwork, ifaceParentByName map[string]string) map[int64][]string {
	if len(items) == 0 {
		return nil
	}

	bindings, _ := loadManagedNetworkPVEBridgeBindings()
	bindingsByBridge := make(map[string][]managedNetworkPVEBridgeBinding)
	for _, binding := range bindings {
		bridge := strings.TrimSpace(binding.Bridge)
		if bridge == "" {
			continue
		}
		bindingsByBridge[bridge] = append(bindingsByBridge[bridge], binding)
	}

	out := make(map[int64][]string)
	for _, item := range items {
		item = normalizeManagedNetwork(item)
		if !item.Enabled || item.ID <= 0 {
			continue
		}
		bridge := strings.TrimSpace(item.Bridge)
		if bridge == "" {
			continue
		}

		issues := make([]string, 0)
		if _, ok := ifaceParentByName[bridge]; !ok {
			issues = append(issues, fmt.Sprintf("bridge %s is missing from current host interfaces", bridge))
		}

		for _, binding := range bindingsByBridge[bridge] {
			if detached, name := detectManagedNetworkDetachedPVEGuestLink(binding, bridge, ifaceParentByName); detached {
				issues = append(issues, fmt.Sprintf("guest link %s is not attached to %s", name, bridge))
			}
		}

		if len(issues) > 1 {
			issues = sortAndDedupeStrings(issues)
		}
		if len(issues) > 0 {
			out[item.ID] = issues
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func detectManagedNetworkDetachedPVEGuestLink(binding managedNetworkPVEBridgeBinding, bridge string, ifaceParentByName map[string]string) (bool, string) {
	bridge = strings.TrimSpace(bridge)
	if bridge == "" || len(ifaceParentByName) == 0 {
		return false, ""
	}
	for _, candidate := range managedNetworkPVEGuestLinkCandidates(binding) {
		parent, ok := ifaceParentByName[candidate]
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parent), bridge) {
			return false, ""
		}
		return true, candidate
	}
	return false, ""
}

func managedNetworkPVEGuestLinkCandidates(binding managedNetworkPVEBridgeBinding) []string {
	vmid := strings.TrimSpace(binding.VMID)
	slot := strings.TrimSpace(binding.Slot)
	if vmid == "" || slot == "" {
		return nil
	}
	return []string{
		"fwpr" + vmid + "p" + slot,
		"tap" + vmid + "i" + slot,
		"veth" + vmid + "i" + slot,
	}
}
