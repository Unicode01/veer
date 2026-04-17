//go:build linux

package netinfo

import (
	"net"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func LoadHostNetworkInterfaces() ([]HostNetworkInterface, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	nameByIndex := make(map[int]string, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || strings.TrimSpace(attrs.Name) == "" {
			continue
		}
		nameByIndex[attrs.Index] = attrs.Name
	}
	defaultIPv4ByIndex := loadHostDefaultRouteLinkIndexes(unix.AF_INET)
	defaultIPv6ByIndex := loadHostDefaultRouteLinkIndexes(unix.AF_INET6)

	result := make([]HostNetworkInterface, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || strings.TrimSpace(attrs.Name) == "" {
			continue
		}

		item := HostNetworkInterface{
			Name:             attrs.Name,
			Kind:             strings.TrimSpace(link.Type()),
			DefaultIPv4Route: hostLinkIndexMarked(defaultIPv4ByIndex, attrs.Index),
			DefaultIPv6Route: hostLinkIndexMarked(defaultIPv6ByIndex, attrs.Index),
		}
		if attrs.MasterIndex > 0 {
			item.Parent = nameByIndex[attrs.MasterIndex]
		} else if attrs.ParentIndex > 0 {
			item.Parent = nameByIndex[attrs.ParentIndex]
		}

		addrs, err := netlink.AddrList(link, unix.AF_UNSPEC)
		if err == nil {
			seen := make(map[string]struct{})
			for _, addr := range addrs {
				address, ok := normalizeHostInterfaceAddress(addr.IP, addr.IPNet)
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

func loadHostDefaultRouteLinkIndexes(family int) map[int]struct{} {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{}, 0)
	if err != nil {
		return nil
	}
	return collectHostDefaultRouteLinkIndexes(routes)
}

func collectHostDefaultRouteLinkIndexes(routes []netlink.Route) map[int]struct{} {
	if len(routes) == 0 {
		return nil
	}

	out := make(map[int]struct{})
	for _, route := range routes {
		if !hostRouteUsesMainTable(route) || !hostRouteIsDefault(route) {
			continue
		}
		if route.LinkIndex > 0 {
			out[route.LinkIndex] = struct{}{}
		}
		for _, nextHop := range route.MultiPath {
			if nextHop == nil || nextHop.LinkIndex <= 0 {
				continue
			}
			out[nextHop.LinkIndex] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func hostRouteUsesMainTable(route netlink.Route) bool {
	return route.Table == 0 || route.Table == unix.RT_TABLE_MAIN
}

func hostRouteIsDefault(route netlink.Route) bool {
	if route.Dst == nil {
		return true
	}
	ones, bits := route.Dst.Mask.Size()
	if ones != 0 || bits <= 0 {
		return false
	}
	ip := route.Dst.IP
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.Equal(net.IPv4zero)
	}
	ip = ip.To16()
	return ip != nil && ip.Equal(net.IPv6zero)
}

func hostLinkIndexMarked(items map[int]struct{}, index int) bool {
	if len(items) == 0 || index <= 0 {
		return false
	}
	_, ok := items[index]
	return ok
}
