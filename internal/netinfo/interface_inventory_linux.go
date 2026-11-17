//go:build linux

package netinfo

import (
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func LoadInterfaceInfos() ([]InterfaceInfo, error) {
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

	result := make([]InterfaceInfo, 0, len(links))
	for _, link := range links {
		attrs := link.Attrs()
		if attrs == nil || strings.TrimSpace(attrs.Name) == "" {
			continue
		}

		info := InterfaceInfo{
			Name: attrs.Name,
			Kind: strings.TrimSpace(link.Type()),
		}
		if attrs.MasterIndex > 0 {
			info.Parent = nameByIndex[attrs.MasterIndex]
		} else if attrs.ParentIndex > 0 {
			info.Parent = nameByIndex[attrs.ParentIndex]
		}

		addrs, err := netlink.AddrList(link, unix.AF_UNSPEC)
		if err == nil {
			seen := make(map[string]struct{})
			seenNetworks := make(map[string]struct{})
			for _, addr := range addrs {
				if !isVisibleInterfaceIP(addr.IP) {
					continue
				}
				if address, ok := normalizeHostInterfaceAddress(addr.IP, addr.IPNet); ok && address.Family == ipFamilyIPv4 {
					if _, dup := seenNetworks[address.CIDR]; !dup {
						seenNetworks[address.CIDR] = struct{}{}
						info.IPv4Networks = append(info.IPv4Networks, address.CIDR)
					}
				}
				text := canonicalIPLiteral(addr.IP)
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
		if len(info.IPv4Networks) > 0 {
			sort.Strings(info.IPv4Networks)
		}
		result = append(result, info)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}
