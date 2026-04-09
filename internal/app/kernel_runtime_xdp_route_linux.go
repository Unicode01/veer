//go:build linux

package app

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func validateXDPDirectTarget(outLink netlink.Link, rule Rule, family string) error {
	if outLink == nil || outLink.Attrs() == nil {
		return fmt.Errorf("xdp dataplane cannot resolve the outbound interface")
	}

	backendIP := normalizeKernelFamilyIP(net.ParseIP(strings.TrimSpace(rule.OutIP)), family)
	if backendIP == nil {
		return fmt.Errorf("xdp dataplane requires an explicit outbound %s address", kernelFamilyLabel(family))
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
	if gw := normalizeKernelFamilyIP(selected.Gw, family); gw != nil && !gw.IsUnspecified() {
		nextHopIP = gw
	}
	return validateXDPNeighbor(outLink.Attrs().Index, nextHopIP, rule.OutInterface, family)
}

func resolveXDPDirectTarget(outLink netlink.Link, rule Rule, family string) (xdpBridgeTarget, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane cannot resolve the outbound interface")
	}

	backendIP := normalizeKernelFamilyIP(net.ParseIP(strings.TrimSpace(rule.OutIP)), family)
	if backendIP == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane requires an explicit outbound %s address", kernelFamilyLabel(family))
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
	if gw := normalizeKernelFamilyIP(selected.Gw, family); gw != nil && !gw.IsUnspecified() {
		nextHopIP = gw
	}
	neighborMAC, err := resolveXDPNeighborMAC(outLink.Attrs().Index, nextHopIP, rule.OutInterface, family)
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

func validateXDPNeighbor(ifindex int, ip net.IP, ifName string, family string) error {
	_, err := resolveXDPNeighborMAC(ifindex, ip, ifName, family)
	return err
}

func resolveXDPNeighborMAC(ifindex int, ip net.IP, ifName string, family string) (net.HardwareAddr, error) {
	if ifindex <= 0 {
		return nil, fmt.Errorf("xdp dataplane cannot resolve the outbound interface index")
	}
	ip = normalizeKernelFamilyIP(ip, family)
	if ip == nil {
		return nil, fmt.Errorf("xdp dataplane requires a %s neighbor on %q", kernelFamilyLabel(family), ifName)
	}

	af := unix.AF_INET
	if family == ipFamilyIPv6 {
		af = unix.AF_INET6
	}
	neighbors, err := netlink.NeighList(ifindex, af)
	if err != nil {
		return nil, fmt.Errorf("xdp dataplane cannot inspect %s neighbors on %q: %w", kernelFamilyLabel(family), ifName, err)
	}
	for _, neigh := range neighbors {
		if neigh.IP == nil || !neigh.IP.Equal(ip) {
			continue
		}
		if !isValidHardwareAddr(neigh.HardwareAddr) {
			continue
		}
		return append(net.HardwareAddr(nil), neigh.HardwareAddr...), nil
	}

	return nil, fmt.Errorf("xdp dataplane requires a learned %s neighbor entry for %s on %q", kernelFamilyLabel(family), ip.String(), ifName)
}
