package app

import (
	"net"
	"sort"
)

var loadHostNetworkInterfacesForTests func() ([]HostNetworkInterface, error)

func loadCurrentHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	load := loadHostNetworkInterfaces
	if loadHostNetworkInterfacesForTests != nil {
		load = loadHostNetworkInterfacesForTests
	}
	return load()
}

func buildHostNetworkInterfaceMap(items []HostNetworkInterface) map[string]HostNetworkInterface {
	if len(items) == 0 {
		return map[string]HostNetworkInterface{}
	}
	out := make(map[string]HostNetworkInterface, len(items))
	for _, item := range items {
		out[item.Name] = item
	}
	return out
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
		Family:    ipLiteralFamily(canonicalIPLiteral(ip)),
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
