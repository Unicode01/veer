package managednet

import (
	"fmt"
	"sort"
	"strings"
)

func normalizeManagedNetworkReservation(item ManagedNetworkReservation) ManagedNetworkReservation {
	item.MACAddress = strings.TrimSpace(item.MACAddress)
	item.IPv4Address = strings.TrimSpace(item.IPv4Address)
	item.Remark = strings.TrimSpace(item.Remark)
	return item
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

func sortAndDedupeStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func uniqueInterfaceNames(names ...string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func summarizeInterfaceSet(src map[string]struct{}) string {
	if len(src) == 0 {
		return ""
	}
	items := make([]string, 0, len(src))
	for name := range src {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		items = append(items, name)
	}
	if len(items) == 0 {
		return ""
	}
	sort.Strings(items)
	if len(items) > 3 {
		items = append(items[:3], fmt.Sprintf("+%d", len(items)-3))
	}
	return strings.Join(items, ",")
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
	sort.Slice(children, func(i, j int) bool {
		return strings.Compare(children[i].Name, children[j].Name) < 0
	})
	return children
}
