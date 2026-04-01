//go:build linux

package app

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func validateXDPDirectTarget(outLink netlink.Link, rule Rule) error {
	if outLink == nil || outLink.Attrs() == nil {
		return fmt.Errorf("xdp dataplane cannot resolve the outbound interface")
	}

	backendIP := net.ParseIP(strings.TrimSpace(rule.OutIP)).To4()
	if backendIP == nil {
		return fmt.Errorf("xdp dataplane requires an explicit outbound IPv4 address")
	}

	routes, err := netlink.RouteGetWithOptions(backendIP, &netlink.RouteGetOptions{
		OifIndex: outLink.Attrs().Index,
	})
	if err != nil {
		return fmt.Errorf("xdp dataplane requires a resolved route to %s on %q: %w", backendIP.String(), rule.OutInterface, err)
	}
	if len(routes) == 0 {
		return fmt.Errorf("xdp dataplane requires a resolved route to %s on %q", backendIP.String(), rule.OutInterface)
	}

	var selected *netlink.Route
	for i := range routes {
		if routes[i].LinkIndex == 0 || routes[i].LinkIndex == outLink.Attrs().Index {
			selected = &routes[i]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf(
			"xdp dataplane route to %s resolved to %s instead of selected outbound interface %q",
			backendIP.String(),
			xdpInterfaceLabel(routes[0].LinkIndex),
			rule.OutInterface,
		)
	}

	nextHopIP := backendIP
	if gw := selected.Gw.To4(); gw != nil && !gw.IsUnspecified() {
		nextHopIP = gw
	}
	return validateXDPNeighbor(outLink.Attrs().Index, nextHopIP, rule.OutInterface)
}

func resolveXDPDirectTarget(outLink netlink.Link, rule Rule) (xdpBridgeTarget, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane cannot resolve the outbound interface")
	}

	backendIP := net.ParseIP(strings.TrimSpace(rule.OutIP)).To4()
	if backendIP == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane requires an explicit outbound IPv4 address")
	}

	routes, err := netlink.RouteGetWithOptions(backendIP, &netlink.RouteGetOptions{
		OifIndex: outLink.Attrs().Index,
	})
	if err != nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane requires a resolved route to %s on %q: %w", backendIP.String(), rule.OutInterface, err)
	}
	if len(routes) == 0 {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane requires a resolved route to %s on %q", backendIP.String(), rule.OutInterface)
	}

	var selected *netlink.Route
	for i := range routes {
		if routes[i].LinkIndex == 0 || routes[i].LinkIndex == outLink.Attrs().Index {
			selected = &routes[i]
			break
		}
	}
	if selected == nil {
		return xdpBridgeTarget{}, fmt.Errorf(
			"xdp dataplane route to %s resolved to %s instead of selected outbound interface %q",
			backendIP.String(),
			xdpInterfaceLabel(routes[0].LinkIndex),
			rule.OutInterface,
		)
	}

	nextHopIP := backendIP
	if gw := selected.Gw.To4(); gw != nil && !gw.IsUnspecified() {
		nextHopIP = gw
	}
	neighborMAC, err := resolveXDPNeighborMAC(outLink.Attrs().Index, nextHopIP, rule.OutInterface)
	if err != nil {
		return xdpBridgeTarget{}, err
	}

	if !isValidHardwareAddr(outLink.Attrs().HardwareAddr) {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane could not determine a valid source MAC on %q", rule.OutInterface)
	}

	return xdpBridgeTarget{
		outIfIndex: outLink.Attrs().Index,
		srcMAC:     hardwareAddrToArray(outLink.Attrs().HardwareAddr),
		dstMAC:     hardwareAddrToArray(neighborMAC),
	}, nil
}

func validateXDPNeighbor(ifindex int, ip net.IP, ifName string) error {
	_, err := resolveXDPNeighborMAC(ifindex, ip, ifName)
	return err
}

func resolveXDPNeighborMAC(ifindex int, ip net.IP, ifName string) (net.HardwareAddr, error) {
	if ifindex <= 0 {
		return nil, fmt.Errorf("xdp dataplane cannot resolve the outbound interface index")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("xdp dataplane requires an IPv4 neighbor on %q", ifName)
	}

	neighbors, err := netlink.NeighList(ifindex, unix.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("xdp dataplane cannot inspect IPv4 neighbors on %q: %w", ifName, err)
	}
	for _, neigh := range neighbors {
		if neigh.IP == nil || !neigh.IP.Equal(ip4) {
			continue
		}
		if !isValidHardwareAddr(neigh.HardwareAddr) {
			continue
		}
		return append(net.HardwareAddr(nil), neigh.HardwareAddr...), nil
	}

	return nil, fmt.Errorf("xdp dataplane requires a learned IPv4 neighbor entry for %s on %q", ip4.String(), ifName)
}
