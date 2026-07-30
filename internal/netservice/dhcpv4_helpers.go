//go:build linux

package netservice

import (
	"net"
	"sort"
	"strings"
)

func sortAndDedupeStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
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

func collectManagedNetworkChildInterfaces(bridge string, uplink string, infos []InterfaceInfo) []InterfaceInfo {
	bridge = strings.TrimSpace(bridge)
	uplink = strings.TrimSpace(uplink)
	if bridge == "" {
		return nil
	}
	children := make([]InterfaceInfo, 0)
	for _, info := range infos {
		name := strings.TrimSpace(info.Name)
		if strings.TrimSpace(info.Parent) != bridge || name == "" || strings.EqualFold(name, uplink) {
			continue
		}
		kind := strings.ToLower(strings.TrimSpace(info.Kind))
		if kind == "bridge" || kind == "device" {
			continue
		}
		children = append(children, info)
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	return children
}

func isManagedNetworkDynamicGuestLink(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	prefixLength := 0
	separator := byte(0)
	switch {
	case strings.HasPrefix(name, "tap"):
		prefixLength, separator = 3, 'i'
	case strings.HasPrefix(name, "veth"):
		prefixLength, separator = 4, 'i'
	case strings.HasPrefix(name, "fwpr"):
		prefixLength, separator = 4, 'p'
	case strings.HasPrefix(name, "fwln"):
		prefixLength, separator = 4, 'i'
	default:
		return strings.HasPrefix(strings.ToLower(name), "tap")
	}
	separatorIndex := prefixLength
	for separatorIndex < len(name) && name[separatorIndex] >= '0' && name[separatorIndex] <= '9' {
		separatorIndex++
	}
	if separatorIndex == prefixLength || separatorIndex >= len(name) || name[separatorIndex] != separator {
		return strings.HasPrefix(strings.ToLower(name), "tap")
	}
	if separatorIndex+1 >= len(name) {
		return false
	}
	for index := separatorIndex + 1; index < len(name); index++ {
		if name[index] < '0' || name[index] > '9' {
			return false
		}
	}
	return true
}

func managedNetworkIPv4LiteralToUint32(value string) uint32 {
	return managedNetworkIPv4ToUint32(parseIPLiteral(value))
}

func managedNetworkIPv4ToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIPv4(value uint32) net.IP {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}
