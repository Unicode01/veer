//go:build !linux

package app

import (
	"net"
	"sort"
)

func loadHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make([]HostNetworkInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		item := HostNetworkInterface{
			Name: iface.Name,
		}
		addrs, err := iface.Addrs()
		if err == nil {
			seen := make(map[string]struct{})
			for _, addr := range addrs {
				var ip net.IP
				var ipNet *net.IPNet
				switch current := addr.(type) {
				case *net.IPNet:
					ip = current.IP
					ipNet = current
				case *net.IPAddr:
					ip = current.IP
				}
				address, ok := normalizeHostInterfaceAddress(ip, ipNet)
				if !ok {
					continue
				}
				key := address.CIDR + "|" + address.IP
				if _, exists := seen[key]; exists {
					continue
				}
				seen[key] = struct{}{}
				item.Addresses = append(item.Addresses, address)
			}
		}
		if len(item.Addresses) > 0 {
			sortHostInterfaceAddresses(item.Addresses)
		}
		result = append(result, item)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}
