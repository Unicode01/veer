//go:build !linux

package app

import (
	"net"
	"sort"
)

func loadInterfaceInfos() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	result := make([]InterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		info := InterfaceInfo{Name: iface.Name}
		if err == nil {
			seen := make(map[string]struct{})
			for _, addr := range addrs {
				var ip net.IP
				switch item := addr.(type) {
				case *net.IPNet:
					ip = item.IP
				case *net.IPAddr:
					ip = item.IP
				}
				if !isVisibleInterfaceIP(ip) {
					continue
				}
				text := canonicalIPLiteral(ip)
				if _, ok := seen[text]; ok {
					continue
				}
				seen[text] = struct{}{}
				info.Addrs = append(info.Addrs, text)
			}
		}
		if len(info.Addrs) > 0 {
			sort.Strings(info.Addrs)
		}
		result = append(result, info)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}
