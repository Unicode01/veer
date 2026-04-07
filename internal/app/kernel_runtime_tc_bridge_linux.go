//go:build linux

package app

import (
	"fmt"
	"net"
	"sort"
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

	neighborTarget, err := lookupBridgeNeighborTarget(outLink.Attrs().Index, backendIP)
	if err != nil {
		return tcBridgeTarget{}, err
	}
	backendMAC := neighborTarget.mac
	memberLink, err := resolveBridgeMemberLink(outLink.Attrs().Index, neighborTarget, backendMAC)
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

	memberIndexes, err := listTCBridgeMemberIndexes(outLink.Attrs().Index)
	if err != nil {
		return false, fmt.Errorf("resolve outbound bridge members for %q: %w", outLink.Attrs().Name, err)
	}
	matched, direct := classifyTCBridgeRoutesWithMembers(routes, outLink.Attrs().Index, memberIndexes)
	if !matched {
		return false, nil
	}
	return direct, nil
}

func classifyTCBridgeRoutes(routes []netlink.Route, outIfIndex int) (matched bool, direct bool) {
	return classifyTCBridgeRoutesWithMembers(routes, outIfIndex, nil)
}

func classifyTCBridgeRoutesWithMembers(routes []netlink.Route, outIfIndex int, memberIndexes map[int]struct{}) (matched bool, direct bool) {
	for _, route := range routes {
		if route.LinkIndex != 0 && route.LinkIndex != outIfIndex {
			if _, ok := memberIndexes[route.LinkIndex]; !ok {
				continue
			}
		}
		if gw := route.Gw.To4(); gw != nil && !gw.IsUnspecified() {
			return true, false
		}
		return true, true
	}
	return false, false
}

func listTCBridgeMemberIndexes(bridgeIndex int) (map[int]struct{}, error) {
	links, err := listTCBridgeMemberLinks(bridgeIndex)
	if err != nil {
		return nil, err
	}
	indexes := make(map[int]struct{}, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		indexes[link.Attrs().Index] = struct{}{}
	}
	return indexes, nil
}

func listTCBridgeMemberLinks(bridgeIndex int) ([]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	members := make([]netlink.Link, 0, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		if link.Attrs().MasterIndex != bridgeIndex {
			continue
		}
		members = append(members, link)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].Attrs().Index != members[j].Attrs().Index {
			return members[i].Attrs().Index < members[j].Attrs().Index
		}
		return members[i].Attrs().Name < members[j].Attrs().Name
	})
	return members, nil
}

func resolveTCReplyAttachments(outLink netlink.Link, outIfIndex int) ([]int, []kernelIfParentMapping, error) {
	if outIfIndex <= 0 {
		return nil, nil, fmt.Errorf("kernel dataplane cannot resolve reply interfaces")
	}

	replyIfIndexes := []int{outIfIndex}
	if outLink == nil || outLink.Attrs() == nil || !isXDPBridgeLink(outLink) || outIfIndex != outLink.Attrs().Index {
		return replyIfIndexes, nil, nil
	}

	members, err := listTCBridgeMemberLinks(outLink.Attrs().Index)
	if err != nil {
		return nil, nil, err
	}
	parents := make([]kernelIfParentMapping, 0, len(members))
	seen := map[int]struct{}{outIfIndex: {}}
	for _, link := range members {
		if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
			continue
		}
		if _, ok := seen[link.Attrs().Index]; ok {
			continue
		}
		seen[link.Attrs().Index] = struct{}{}
		replyIfIndexes = append(replyIfIndexes, link.Attrs().Index)
		parents = append(parents, kernelIfParentMapping{
			ifindex:       link.Attrs().Index,
			parentIfIndex: outIfIndex,
		})
	}
	sort.Ints(replyIfIndexes)
	return replyIfIndexes, parents, nil
}

func resolveTCBridgeParentMapping(link netlink.Link) (kernelIfParentMapping, bool) {
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 || link.Attrs().MasterIndex <= 0 {
		return kernelIfParentMapping{}, false
	}
	parent, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
	if err != nil || parent == nil || parent.Attrs() == nil || !isXDPBridgeLink(parent) {
		return kernelIfParentMapping{}, false
	}
	return kernelIfParentMapping{
		ifindex:       link.Attrs().Index,
		parentIfIndex: parent.Attrs().Index,
	}, true
}
