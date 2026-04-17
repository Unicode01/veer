//go:build linux

package app

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type xdpBridgeTarget struct {
	outIfIndex int
	srcMAC     [6]byte
	dstMAC     [6]byte
}

type bridgeNeighborTarget struct {
	mac       net.HardwareAddr
	linkIndex int
}

func resolveXDPInboundLinks(inLink netlink.Link, rule Rule, opts xdpPrepareOptions) ([]netlink.Link, error) {
	_ = rule
	if inLink == nil || inLink.Attrs() == nil {
		return nil, fmt.Errorf("xdp dataplane cannot resolve the inbound interface")
	}
	if xdpLinkTypeAllowed(inLink.Type()) {
		return []netlink.Link{inLink}, nil
	}
	if !isXDPBridgeLink(inLink) {
		return nil, fmt.Errorf("xdp dataplane currently supports only native-capable inbound interfaces (device/veth); got %q", inLink.Type())
	}
	if !opts.enableBridge {
		return nil, fmt.Errorf("xdp dataplane inbound bridge support requires experimental feature %q", experimentalFeatureBridgeXDP)
	}
	return nil, fmt.Errorf("xdp dataplane inbound bridge interfaces are not supported on the current kernel path; use tc for bridge ingress rules")
}

func resolveXDPBridgeTarget(outLink netlink.Link, rule Rule, opts xdpPrepareOptions) (xdpBridgeTarget, error) {
	if outLink == nil || outLink.Attrs() == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane cannot resolve the outbound interface")
	}
	if !opts.enableBridge {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane outbound bridge support requires experimental feature %q", experimentalFeatureBridgeXDP)
	}
	if !isXDPBridgeLink(outLink) {
		return xdpBridgeTarget{}, fmt.Errorf("xdp dataplane currently supports only native-capable outbound interfaces (device/veth); got %q", outLink.Type())
	}

	backendIP := net.ParseIP(strings.TrimSpace(rule.OutIP)).To4()
	if backendIP == nil {
		return xdpBridgeTarget{}, fmt.Errorf("xdp bridge dataplane requires an explicit outbound IPv4 address")
	}

	neighborTarget, err := lookupBridgeNeighborTarget(outLink.Attrs().Index, backendIP)
	if err != nil {
		return xdpBridgeTarget{}, fmt.Errorf("resolve bridge neighbor for %s on %q: %w", backendIP.String(), rule.OutInterface, err)
	}
	backendMAC := neighborTarget.mac

	memberLink, err := resolveBridgeMemberLink(outLink.Attrs().Index, neighborTarget, backendMAC)
	if err != nil {
		return xdpBridgeTarget{}, fmt.Errorf("resolve bridge forwarding port for %s on %q: %w", backendMAC.String(), rule.OutInterface, err)
	}
	if memberLink == nil || memberLink.Attrs() == nil {
		return xdpBridgeTarget{}, fmt.Errorf("bridge forwarding database returned an invalid member link")
	}
	if strings.EqualFold(strings.TrimSpace(memberLink.Type()), "bridge") {
		return xdpBridgeTarget{}, fmt.Errorf("bridge forwarding database resolved nested bridge member %q, which is not supported", memberLink.Attrs().Name)
	}
	if !xdpLinkTypeAllowed(memberLink.Type()) {
		return xdpBridgeTarget{}, fmt.Errorf("xdp bridge egress currently supports only device/veth bridge members; resolved %q (%s)", memberLink.Attrs().Name, memberLink.Type())
	}

	srcMAC, err := selectBridgeSourceMAC(outLink, memberLink)
	if err != nil {
		return xdpBridgeTarget{}, err
	}

	return xdpBridgeTarget{
		outIfIndex: memberLink.Attrs().Index,
		srcMAC:     srcMAC,
		dstMAC:     hardwareAddrToArray(backendMAC),
	}, nil
}

func lookupBridgeNeighborMAC(bridgeIndex int, backendIP net.IP) (net.HardwareAddr, error) {
	target, err := lookupBridgeNeighborTarget(bridgeIndex, backendIP)
	if err != nil {
		return nil, err
	}
	return target.mac, nil
}

func lookupBridgeNeighborTarget(bridgeIndex int, backendIP net.IP) (bridgeNeighborTarget, error) {
	memberIndexes, err := listTCBridgeMemberIndexes(bridgeIndex)
	if err != nil {
		return bridgeNeighborTarget{}, err
	}
	neighbors, err := netlink.NeighList(bridgeIndex, unix.AF_INET)
	if err != nil {
		return bridgeNeighborTarget{}, err
	}
	if target, ok := matchBridgeNeighborTarget(neighbors, bridgeIndex, memberIndexes, backendIP); ok {
		return target, nil
	}

	neighbors, err = netlink.NeighList(0, unix.AF_INET)
	if err != nil {
		return bridgeNeighborTarget{}, err
	}
	if target, ok := matchBridgeNeighborTarget(neighbors, bridgeIndex, memberIndexes, backendIP); ok {
		return target, nil
	}
	return bridgeNeighborTarget{}, fmt.Errorf("no learned IPv4 neighbor entry was found; ensure the backend has recent traffic or ARP state")
}

func matchBridgeNeighborTarget(neighbors []netlink.Neigh, bridgeIndex int, memberIndexes map[int]struct{}, backendIP net.IP) (bridgeNeighborTarget, bool) {
	for _, neigh := range neighbors {
		if neigh.IP == nil || !neigh.IP.Equal(backendIP) {
			continue
		}
		if neigh.LinkIndex != bridgeIndex && neigh.MasterIndex != bridgeIndex {
			if _, ok := memberIndexes[neigh.LinkIndex]; !ok {
				continue
			}
		}
		if !isValidHardwareAddr(neigh.HardwareAddr) {
			continue
		}
		linkIndex := 0
		if neigh.LinkIndex > 0 && neigh.LinkIndex != bridgeIndex {
			linkIndex = neigh.LinkIndex
		}
		return bridgeNeighborTarget{
			mac:       append(net.HardwareAddr(nil), neigh.HardwareAddr...),
			linkIndex: linkIndex,
		}, true
	}
	return bridgeNeighborTarget{}, false
}

func resolveBridgeMemberLink(bridgeIndex int, target bridgeNeighborTarget, backendMAC net.HardwareAddr) (netlink.Link, error) {
	if target.linkIndex > 0 {
		link, err := netlink.LinkByIndex(target.linkIndex)
		if err == nil && link != nil && link.Attrs() != nil {
			if link.Attrs().MasterIndex == bridgeIndex {
				return link, nil
			}
		}
	}
	return lookupBridgeFDBPort(bridgeIndex, backendMAC)
}

func lookupBridgeFDBPort(bridgeIndex int, backendMAC net.HardwareAddr) (netlink.Link, error) {
	entries, err := netlink.NeighListExecute(netlink.Ndmsg{Family: unix.AF_BRIDGE})
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !bytes.Equal(entry.HardwareAddr, backendMAC) {
			continue
		}
		if entry.Flags&netlink.NTF_SELF != 0 {
			continue
		}

		link, err := netlink.LinkByIndex(entry.LinkIndex)
		if err != nil {
			continue
		}
		if link == nil || link.Attrs() == nil {
			continue
		}
		if link.Attrs().MasterIndex != bridgeIndex && entry.MasterIndex != bridgeIndex {
			continue
		}
		return link, nil
	}

	return nil, fmt.Errorf("no forwarding database entry matched the backend MAC")
}

func selectBridgeSourceMAC(bridgeLink, memberLink netlink.Link) ([6]byte, error) {
	if bridgeLink != nil && bridgeLink.Attrs() != nil && isValidHardwareAddr(bridgeLink.Attrs().HardwareAddr) {
		return hardwareAddrToArray(bridgeLink.Attrs().HardwareAddr), nil
	}
	if memberLink != nil && memberLink.Attrs() != nil && isValidHardwareAddr(memberLink.Attrs().HardwareAddr) {
		return hardwareAddrToArray(memberLink.Attrs().HardwareAddr), nil
	}
	return [6]byte{}, fmt.Errorf("bridge dataplane could not determine a valid source MAC address")
}

func hardwareAddrToArray(hw net.HardwareAddr) [6]byte {
	var out [6]byte
	if len(hw) >= len(out) {
		copy(out[:], hw[:len(out)])
	}
	return out
}

func isValidHardwareAddr(hw net.HardwareAddr) bool {
	if len(hw) < 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if hw[i] != 0 {
			return true
		}
	}
	return false
}

func isXDPBridgeLink(link netlink.Link) bool {
	if link == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(link.Type()), "bridge")
}
