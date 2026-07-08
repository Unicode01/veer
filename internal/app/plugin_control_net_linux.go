//go:build linux

package app

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newPluginControlNetAdmin() pluginControlNetAdmin {
	return linuxPluginControlNetAdmin{}
}

type linuxPluginControlNetAdmin struct{}

func (linuxPluginControlNetAdmin) LinkGet(name string) (pluginControlNetLinkInfo, error) {
	link, err := netlink.LinkByName(strings.TrimSpace(name))
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	return pluginControlNetLinkInfoFromLink(link)
}

func (linuxPluginControlNetAdmin) LinkList() ([]pluginControlNetLinkInfo, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetLinkInfo, 0, len(links))
	for _, link := range links {
		info, err := pluginControlNetLinkInfoFromLink(link)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

func (admin linuxPluginControlNetAdmin) LinkEnsureVeth(req pluginControlNetVethRequest) (pluginControlNetVethResult, error) {
	hostName := strings.TrimSpace(req.Host)
	peerName := strings.TrimSpace(req.Peer)
	if hostName == "" || peerName == "" {
		return pluginControlNetVethResult{}, fmt.Errorf("host and peer are required")
	}
	host, hostErr := netlink.LinkByName(hostName)
	peer, peerErr := netlink.LinkByName(peerName)
	hostMissing := pluginControlNetLinkNotFound(hostErr)
	peerMissing := pluginControlNetLinkNotFound(peerErr)
	if hostErr != nil && !hostMissing {
		return pluginControlNetVethResult{}, fmt.Errorf("resolve host link %q: %w", hostName, hostErr)
	}
	if peerErr != nil && !peerMissing {
		return pluginControlNetVethResult{}, fmt.Errorf("resolve peer link %q: %w", peerName, peerErr)
	}
	if hostMissing != peerMissing {
		return pluginControlNetVethResult{}, fmt.Errorf("veth pair is partially present: host_exists=%t peer_exists=%t", !hostMissing, !peerMissing)
	}
	if hostMissing && peerMissing {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = hostName
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: attrs, PeerName: peerName}); err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("create veth %s<->%s: %w", hostName, peerName, err)
		}
		var err error
		host, err = netlink.LinkByName(hostName)
		if err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("resolve created host link %q: %w", hostName, err)
		}
		peer, err = netlink.LinkByName(peerName)
		if err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("resolve created peer link %q: %w", peerName, err)
		}
	} else if host.Type() != "veth" || peer.Type() != "veth" {
		return pluginControlNetVethResult{}, fmt.Errorf("existing links must both be veth devices")
	} else if err := pluginControlNetValidateVethPeers(host, peer); err != nil {
		return pluginControlNetVethResult{}, err
	}

	if req.MTU > 0 {
		if err := netlink.LinkSetMTU(host, req.MTU); err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("set host mtu: %w", err)
		}
		if err := netlink.LinkSetMTU(peer, req.MTU); err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("set peer mtu: %w", err)
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(host); err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("set host up: %w", err)
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return pluginControlNetVethResult{}, fmt.Errorf("set peer up: %w", err)
		}
	}

	hostInfo, err := admin.LinkGet(hostName)
	if err != nil {
		return pluginControlNetVethResult{}, err
	}
	peerInfo, err := admin.LinkGet(peerName)
	if err != nil {
		return pluginControlNetVethResult{}, err
	}
	hostInfo.PeerName = peerInfo.Name
	hostInfo.PeerIfIndex = peerInfo.IfIndex
	peerInfo.PeerName = hostInfo.Name
	peerInfo.PeerIfIndex = hostInfo.IfIndex
	return pluginControlNetVethResult{Host: hostInfo, Peer: peerInfo}, nil
}

func pluginControlNetValidateVethPeers(host netlink.Link, peer netlink.Link) error {
	if host == nil || host.Attrs() == nil || peer == nil || peer.Attrs() == nil {
		return fmt.Errorf("invalid veth pair")
	}
	hostPeerIndex, err := netlink.VethPeerIndex(&netlink.Veth{LinkAttrs: *host.Attrs()})
	if err != nil {
		return fmt.Errorf("verify veth peer for %q: %w", host.Attrs().Name, err)
	}
	peerPeerIndex, err := netlink.VethPeerIndex(&netlink.Veth{LinkAttrs: *peer.Attrs()})
	if err != nil {
		return fmt.Errorf("verify veth peer for %q: %w", peer.Attrs().Name, err)
	}
	if hostPeerIndex != peer.Attrs().Index || peerPeerIndex != host.Attrs().Index {
		return fmt.Errorf("existing veth links %q and %q are not a pair", host.Attrs().Name, peer.Attrs().Name)
	}
	return nil
}

func (admin linuxPluginControlNetAdmin) LinkEnsureBridge(req pluginControlNetBridgeRequest) (pluginControlNetLinkInfo, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return pluginControlNetLinkInfo{}, fmt.Errorf("name is required")
	}
	link, err := netlink.LinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: attrs}); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("create bridge %s: %w", name, err)
		}
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("resolve bridge %q: %w", name, err)
	}
	if link.Type() != "bridge" {
		return pluginControlNetLinkInfo{}, fmt.Errorf("existing link %q is %s, want bridge", name, link.Type())
	}
	if req.MTU > 0 {
		if err := netlink.LinkSetMTU(link, req.MTU); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("set bridge mtu: %w", err)
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("set bridge up: %w", err)
		}
	}
	return admin.LinkGet(name)
}

func (linuxPluginControlNetAdmin) LinkDelete(name string) error {
	link, err := netlink.LinkByName(strings.TrimSpace(name))
	if pluginControlNetLinkNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func (admin linuxPluginControlNetAdmin) LinkSetMaster(req pluginControlNetMasterRequest) (pluginControlNetLinkInfo, error) {
	linkName := strings.TrimSpace(req.Link)
	masterName := strings.TrimSpace(req.Master)
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("resolve link %q: %w", linkName, err)
	}
	master, err := netlink.LinkByName(masterName)
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("resolve master %q: %w", masterName, err)
	}
	if master.Type() != "bridge" {
		return pluginControlNetLinkInfo{}, fmt.Errorf("master %q is %s, want bridge", masterName, master.Type())
	}
	if link.Attrs().MasterIndex != master.Attrs().Index {
		if link.Attrs().MasterIndex != 0 {
			return pluginControlNetLinkInfo{}, fmt.Errorf("link %q is already enslaved to %q", linkName, pluginControlNetLinkNameByIndex(link.Attrs().MasterIndex))
		}
		if err := netlink.LinkSetMaster(link, master); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("set %s master %s: %w", linkName, masterName, err)
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("set link up: %w", err)
		}
	}
	return admin.LinkGet(linkName)
}

func (admin linuxPluginControlNetAdmin) LinkClearMaster(name string) (pluginControlNetLinkInfo, error) {
	linkName := strings.TrimSpace(name)
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	if link.Attrs().MasterIndex != 0 {
		if err := netlink.LinkSetNoMaster(link); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("clear %s master: %w", linkName, err)
		}
	}
	return admin.LinkGet(linkName)
}

func (linuxPluginControlNetAdmin) LinkSetUp(name string, up bool) error {
	link, err := netlink.LinkByName(strings.TrimSpace(name))
	if err != nil {
		return err
	}
	if up {
		return netlink.LinkSetUp(link)
	}
	return netlink.LinkSetDown(link)
}

func (linuxPluginControlNetAdmin) LinkSetMTU(name string, mtu int) error {
	link, err := netlink.LinkByName(strings.TrimSpace(name))
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func (linuxPluginControlNetAdmin) LinkSetOffloads(req pluginControlNetOffloadRequest) error {
	name := strings.TrimSpace(req.Interface)
	if name == "" {
		return fmt.Errorf("interface is required")
	}
	if _, err := netlink.LinkByName(name); err != nil {
		return err
	}
	if len(req.Features) == 0 {
		return fmt.Errorf("features are required")
	}
	if _, err := exec.LookPath("ethtool"); err != nil {
		return fmt.Errorf("ethtool not found: %w", err)
	}
	features := make([]string, 0, len(req.Features))
	for feature := range req.Features {
		if !isAllowedPluginControlOffloadFeature(feature) {
			return fmt.Errorf("unsupported offload feature %q", feature)
		}
		features = append(features, feature)
	}
	sort.Strings(features)
	args := []string{"-K", name}
	for _, feature := range features {
		state := "off"
		if req.Features[feature] {
			state = "on"
		}
		args = append(args, feature, state)
	}
	out, err := exec.Command("ethtool", args...).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = err.Error()
		}
		return fmt.Errorf("ethtool -K %s failed: %s", name, text)
	}
	return nil
}

func (linuxPluginControlNetAdmin) AddrReplace(req pluginControlNetAddrRequest) error {
	link, err := netlink.LinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(strings.TrimSpace(req.CIDR))
	if err != nil {
		return err
	}
	return netlink.AddrReplace(link, addr)
}

func (linuxPluginControlNetAdmin) AddrDelete(req pluginControlNetAddrRequest) error {
	link, err := netlink.LinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(strings.TrimSpace(req.CIDR))
	if err != nil {
		return err
	}
	if err := netlink.AddrDel(link, addr); err != nil && !pluginControlNetAddrNotFound(err) {
		return err
	}
	return nil
}

func (linuxPluginControlNetAdmin) RouteReplace(req pluginControlNetRouteRequest) error {
	route, err := pluginControlNetRoute(req)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(route)
}

func (linuxPluginControlNetAdmin) RouteDelete(req pluginControlNetRouteRequest) error {
	route, err := pluginControlNetRoute(req)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(route); err != nil && !pluginControlNetRouteNotFound(err) {
		return err
	}
	return nil
}

func pluginControlNetLinkInfoFromLink(link netlink.Link) (pluginControlNetLinkInfo, error) {
	if link == nil || link.Attrs() == nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("invalid link")
	}
	attrs := link.Attrs()
	addrs, err := netlink.AddrList(link, unix.AF_UNSPEC)
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	addrTexts := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IPNet != nil {
			addrTexts = append(addrTexts, addr.IPNet.String())
		}
	}
	info := pluginControlNetLinkInfo{
		Name:          attrs.Name,
		IfIndex:       attrs.Index,
		Kind:          link.Type(),
		MTU:           attrs.MTU,
		MAC:           attrs.HardwareAddr.String(),
		Up:            attrs.Flags&net.FlagUp != 0,
		OperState:     attrs.OperState.String(),
		Addresses:     addrTexts,
		MasterIfIndex: attrs.MasterIndex,
	}
	if attrs.ParentIndex > 0 {
		info.Parent = pluginControlNetLinkNameByIndex(attrs.ParentIndex)
	}
	if attrs.MasterIndex > 0 {
		info.MasterName = pluginControlNetLinkNameByIndex(attrs.MasterIndex)
	}
	return info, nil
}

func pluginControlNetRoute(req pluginControlNetRouteRequest) (*netlink.Route, error) {
	var dst *net.IPNet
	var err error
	if !pluginControlNetIsDefaultRoute(req.Dst) {
		dst, err = pluginControlNetParseCIDR(req.Dst)
		if err != nil {
			return nil, fmt.Errorf("dst: %w", err)
		}
	}
	linkIndex := 0
	if strings.TrimSpace(req.Dev) != "" {
		link, err := netlink.LinkByName(strings.TrimSpace(req.Dev))
		if err != nil {
			return nil, fmt.Errorf("dev %q: %w", req.Dev, err)
		}
		linkIndex = link.Attrs().Index
	}
	var gw net.IP
	if strings.TrimSpace(req.Gateway) != "" {
		gw = net.ParseIP(strings.TrimSpace(req.Gateway))
		if gw == nil {
			return nil, fmt.Errorf("gateway must be an IP address")
		}
	}
	var src net.IP
	if strings.TrimSpace(req.Src) != "" {
		src = net.ParseIP(strings.TrimSpace(req.Src))
		if src == nil {
			return nil, fmt.Errorf("src must be an IP address")
		}
	}
	table := req.Table
	if table == 0 {
		table = unix.RT_TABLE_MAIN
	}
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
		Gw:        gw,
		Src:       src,
		Table:     table,
		Priority:  req.Metric,
	}
	if req.Scope != 0 {
		route.Scope = netlink.Scope(req.Scope)
	}
	return route, nil
}

func pluginControlNetIsDefaultRoute(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "" || value == "default" || value == "0.0.0.0/0" || value == "::/0"
}

func pluginControlNetParseCIDR(value string) (*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("value is required")
	}
	if strings.Contains(value, "/") {
		_, ipnet, err := net.ParseCIDR(value)
		return ipnet, err
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("must be an IP address or CIDR")
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
}

func pluginControlNetLinkNameByIndex(index int) string {
	link, err := netlink.LinkByIndex(index)
	if err != nil || link == nil || link.Attrs() == nil {
		return ""
	}
	return link.Attrs().Name
}

func pluginControlNetLinkNotFound(err error) bool {
	if err == nil {
		return false
	}
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "link not found") || strings.Contains(text, "no such network interface")
}

func pluginControlNetAddrNotFound(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "cannot assign requested address") || strings.Contains(text, "no such process")
}

func pluginControlNetRouteNotFound(err error) bool {
	if err == nil {
		return false
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no such process") || strings.Contains(text, "not found")
}
