//go:build linux

package app

import (
	"net"

	"github.com/vishvananda/netlink"
)

// lookupUserspaceRouteIface returns the interface the main routing decision
// sends packets for ip through, or "" when there is none.
func lookupUserspaceRouteIface(ip net.IP) string {
	routes, err := netlink.RouteGet(ip)
	if err != nil || len(routes) == 0 || routes[0].LinkIndex <= 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(routes[0].LinkIndex)
	if err != nil {
		return ""
	}
	return iface.Name
}
