package netinfo

import (
	"net"
	"sort"
)

const (
	ipFamilyIPv4 = "ipv4"
	ipFamilyIPv6 = "ipv6"
)

func canonicalIPLiteral(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func isVisibleInterfaceIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func ipFamilyForIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		return ipFamilyIPv4
	}
	if ip.To16() != nil {
		return ipFamilyIPv6
	}
	return ""
}

func normalizeHostInterfaceAddress(ip net.IP, ipNet *net.IPNet) (HostInterfaceAddress, bool) {
	if ipNet == nil || ip == nil {
		return HostInterfaceAddress{}, false
	}
	ip = normalizeHostInterfaceAddressIP(ip)
	if !isVisibleInterfaceIP(ip) {
		return HostInterfaceAddress{}, false
	}
	ones, bits := ipNet.Mask.Size()
	if ones < 0 || bits <= 0 {
		return HostInterfaceAddress{}, false
	}
	networkIP := ip.Mask(ipNet.Mask)
	if networkIP == nil {
		return HostInterfaceAddress{}, false
	}
	return HostInterfaceAddress{
		Family:    ipFamilyForIP(ip),
		IP:        canonicalIPLiteral(ip),
		CIDR:      (&net.IPNet{IP: networkIP, Mask: ipNet.Mask}).String(),
		PrefixLen: ones,
	}, true
}

func normalizeHostInterfaceAddressIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func sortHostInterfaceAddresses(items []HostInterfaceAddress) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Family != items[j].Family {
			return items[i].Family < items[j].Family
		}
		if items[i].IP != items[j].IP {
			return items[i].IP < items[j].IP
		}
		if items[i].CIDR != items[j].CIDR {
			return items[i].CIDR < items[j].CIDR
		}
		return items[i].PrefixLen < items[j].PrefixLen
	})
}
