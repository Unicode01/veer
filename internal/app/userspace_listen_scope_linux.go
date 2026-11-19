//go:build linux

package app

import (
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// userspaceUplinkProbe stands for "the internet" in the route lookups below;
// nothing is sent to it.
var userspaceUplinkProbe = map[int]net.IP{
	netlink.FAMILY_V4: net.ParseIP("1.1.1.1"),
	netlink.FAMILY_V6: net.ParseIP("2606:4700:4700::1111"),
}

// lookupUserspaceSecondaryUplink reports whether iface has a default route of
// its own, in any table, while the routing decision for an answer from ip to
// the internet leaves by another interface.
func lookupUserspaceSecondaryUplink(iface string, ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	link, err := netlink.LinkByName(iface)
	if err != nil || link.Attrs() == nil {
		return false
	}
	index := link.Attrs().Index
	family := netlink.FAMILY_V4
	if addr.To4() == nil {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false
	}
	hasDefault := false
	for _, route := range routes {
		if route.Type != unix.RTN_UNICAST || !isDefaultRouteDst(route.Dst) {
			continue
		}
		if route.LinkIndex == index {
			hasDefault = true
			break
		}
		for _, hop := range route.MultiPath {
			if hop != nil && hop.LinkIndex == index {
				hasDefault = true
				break
			}
		}
		if hasDefault {
			break
		}
	}
	if !hasDefault {
		return false
	}
	best, err := netlink.RouteGetWithOptions(userspaceUplinkProbe[family], &netlink.RouteGetOptions{SrcAddr: addr})
	if err != nil || len(best) == 0 {
		// It has a default route but answers from ip have none: keep the
		// binding, which is what made them leave by it.
		return true
	}
	return best[0].LinkIndex != index
}

func isDefaultRouteDst(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, _ := dst.Mask.Size()
	return ones == 0
}
