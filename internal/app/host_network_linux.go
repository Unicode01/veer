//go:build linux

package app

import (
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func loadHostNetworkInterfaces() ([]HostNetworkInterface, error) {
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

	result := make([]HostNetworkInterface, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || strings.TrimSpace(attrs.Name) == "" {
			continue
		}

		item := HostNetworkInterface{
			Name: attrs.Name,
			Kind: strings.TrimSpace(link.Type()),
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
