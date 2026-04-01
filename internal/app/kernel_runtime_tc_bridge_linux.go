//go:build linux

package app

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

type tcBridgeTarget struct {
	outIfIndex int
	srcMAC     [6]byte
	dstMAC     [6]byte
}

func resolveTCInboundLinks(inLink netlink.Link) ([]netlink.Link, error) {
	if inLink == nil || inLink.Attrs() == nil {
		return nil, fmt.Errorf("kernel dataplane cannot resolve the inbound interface")
	}
	return []netlink.Link{inLink}, nil
}

func resolveTCBridgeTarget(outLink netlink.Link, rule Rule) (tcBridgeTarget, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return tcBridgeTarget{}, fmt.Errorf("kernel dataplane cannot resolve the outbound interface")
	}
	if !isXDPBridgeLink(outLink) {
		return tcBridgeTarget{}, fmt.Errorf("kernel dataplane outbound bridge resolution requires a bridge interface")
	}

	backendIP := net.ParseIP(rule.OutIP).To4()
	if backendIP == nil {
		return tcBridgeTarget{}, fmt.Errorf("kernel dataplane bridge egress requires an explicit outbound IPv4 address")
	}

	backendMAC, err := lookupBridgeNeighborMAC(outLink.Attrs().Index, backendIP)
	if err != nil {
		return tcBridgeTarget{}, err
	}
	memberLink, err := lookupBridgeFDBPort(outLink.Attrs().Index, backendMAC)
	if err != nil {
		return tcBridgeTarget{}, err
	}
	if memberLink == nil || memberLink.Attrs() == nil {
		return tcBridgeTarget{}, fmt.Errorf("bridge forwarding database returned an invalid member link")
	}
	srcMAC, err := selectBridgeSourceMAC(outLink, memberLink)
	if err != nil {
		return tcBridgeTarget{}, err
	}

	return tcBridgeTarget{
		outIfIndex: memberLink.Attrs().Index,
		srcMAC:     srcMAC,
		dstMAC:     hardwareAddrToArray(backendMAC),
	}, nil
}

func resolveTCOutboundPath(outLink netlink.Link, rule Rule) (preparedKernelPath, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return preparedKernelPath{}, fmt.Errorf("kernel dataplane cannot resolve the outbound interface")
	}

	path := preparedKernelPath{
		outIfIndex: outLink.Attrs().Index,
	}
	if !isXDPBridgeLink(outLink) {
		return path, nil
	}

	direct, err := isTCBridgeDirectTarget(outLink, rule.OutIP)
	if err != nil {
		return preparedKernelPath{}, err
	}
	if !direct {
		return path, nil
	}

	target, err := resolveTCBridgeTarget(outLink, rule)
	if err != nil {
		if shouldFallbackTCBridgeFastPath(err) {
			return path, nil
		}
		return preparedKernelPath{}, err
	}
	path.outIfIndex = target.outIfIndex
	path.flags |= kernelRuleFlagBridgeL2
	path.srcMAC = target.srcMAC
	path.dstMAC = target.dstMAC
	return path, nil
}

func shouldFallbackTCBridgeFastPath(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(err.Error()))
	if text == "" {
		return false
	}
	return strings.Contains(text, "no learned ipv4 neighbor entry was found") ||
		strings.Contains(text, "no forwarding database entry matched the backend mac") ||
		strings.Contains(text, "bridge forwarding database returned an invalid member link") ||
		strings.Contains(text, "bridge dataplane could not determine a valid source mac address") ||
		strings.Contains(text, "nested bridge member") ||
		strings.Contains(text, "supports only device/veth bridge members")
}

func isTCBridgeDirectTarget(outLink netlink.Link, backendIP string) (bool, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return false, fmt.Errorf("kernel dataplane cannot resolve the outbound interface")
	}

	ip4 := net.ParseIP(strings.TrimSpace(backendIP)).To4()
	if ip4 == nil {
		return false, fmt.Errorf("kernel dataplane requires an explicit outbound IPv4 address")
	}

	routes, err := netlink.RouteGetWithOptions(ip4, &netlink.RouteGetOptions{
		OifIndex: outLink.Attrs().Index,
	})
	if err != nil {
		return false, fmt.Errorf("resolve outbound bridge route to %s on %q: %w", ip4.String(), outLink.Attrs().Name, err)
	}
	if len(routes) == 0 {
		return false, fmt.Errorf("resolve outbound bridge route to %s on %q: no matching route", ip4.String(), outLink.Attrs().Name)
	}

	matched, direct := classifyTCBridgeRoutes(routes, outLink.Attrs().Index)
	if !matched {
		return false, nil
	}
	return direct, nil
}

func classifyTCBridgeRoutes(routes []netlink.Route, outIfIndex int) (matched bool, direct bool) {
	for _, route := range routes {
		if route.LinkIndex != 0 && route.LinkIndex != outIfIndex {
			continue
		}
		if gw := route.Gw.To4(); gw != nil && !gw.IsUnspecified() {
			return true, false
		}
		return true, true
	}
	return false, false
}
