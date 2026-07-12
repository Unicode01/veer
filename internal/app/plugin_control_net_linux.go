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
	created := false
	cleanupCreated := func(cause error) (pluginControlNetVethResult, error) {
		if created {
			if cleanupLink, err := netlink.LinkByName(hostName); err == nil {
				_ = netlink.LinkDel(cleanupLink)
			}
		}
		return pluginControlNetVethResult{}, cause
	}
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
		created = true
		var err error
		host, err = netlink.LinkByName(hostName)
		if err != nil {
			return cleanupCreated(fmt.Errorf("resolve created host link %q: %w", hostName, err))
		}
		peer, err = netlink.LinkByName(peerName)
		if err != nil {
			return cleanupCreated(fmt.Errorf("resolve created peer link %q: %w", peerName, err))
		}
	} else if host.Type() != "veth" || peer.Type() != "veth" {
		return pluginControlNetVethResult{}, fmt.Errorf("existing links must both be veth devices")
	} else if err := pluginControlNetValidateVethPeers(host, peer); err != nil {
		return pluginControlNetVethResult{}, err
	}

	if req.MTU > 0 {
		if err := netlink.LinkSetMTU(host, req.MTU); err != nil {
			return cleanupCreated(fmt.Errorf("set host mtu: %w", err))
		}
		if err := netlink.LinkSetMTU(peer, req.MTU); err != nil {
			return cleanupCreated(fmt.Errorf("set peer mtu: %w", err))
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(host); err != nil {
			return cleanupCreated(fmt.Errorf("set host up: %w", err))
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return cleanupCreated(fmt.Errorf("set peer up: %w", err))
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
	return pluginControlNetVethResult{Host: hostInfo, Peer: peerInfo, Created: created}, nil
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

func (admin linuxPluginControlNetAdmin) LinkEnsureDummy(req pluginControlNetDummyRequest) (pluginControlNetDummyResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return pluginControlNetDummyResult{}, fmt.Errorf("name is required")
	}
	created := false
	link, err := netlink.LinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: attrs}); err != nil {
			return pluginControlNetDummyResult{}, fmt.Errorf("create dummy %s: %w", name, err)
		}
		created = true
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return pluginControlNetDummyResult{}, fmt.Errorf("resolve dummy %q: %w", name, err)
	}
	cleanupCreated := func(cause error) (pluginControlNetDummyResult, error) {
		if created {
			_ = netlink.LinkDel(link)
		}
		return pluginControlNetDummyResult{}, cause
	}
	if _, ok := link.(*netlink.Dummy); !ok || link.Type() != "dummy" {
		return cleanupCreated(fmt.Errorf("existing link %q is %s, want dummy", name, link.Type()))
	}
	if req.MTU > 0 && link.Attrs().MTU != req.MTU {
		if err := netlink.LinkSetMTU(link, req.MTU); err != nil {
			return cleanupCreated(fmt.Errorf("set dummy mtu: %w", err))
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return cleanupCreated(fmt.Errorf("set dummy up: %w", err))
		}
	}
	info, err := admin.LinkGet(name)
	if err != nil {
		return cleanupCreated(err)
	}
	return pluginControlNetDummyResult{Link: info, Created: created}, nil
}

func (admin linuxPluginControlNetAdmin) LinkEnsureMacvlan(req pluginControlNetMacvlanRequest) (pluginControlNetMacvlanResult, error) {
	name := strings.TrimSpace(req.Name)
	parentName := strings.TrimSpace(req.Parent)
	if name == "" || parentName == "" {
		return pluginControlNetMacvlanResult{}, fmt.Errorf("name and parent are required")
	}
	parent, err := netlink.LinkByName(parentName)
	if err != nil {
		return pluginControlNetMacvlanResult{}, fmt.Errorf("resolve parent link %q: %w", parentName, err)
	}
	mode, err := pluginControlNetMacvlanMode(req.Mode)
	if err != nil {
		return pluginControlNetMacvlanResult{}, err
	}
	var hardwareAddr net.HardwareAddr
	if strings.TrimSpace(req.MAC) != "" {
		normalizedMAC, normalizeErr := normalizePluginControlUnicastMAC(req.MAC)
		if normalizeErr != nil {
			return pluginControlNetMacvlanResult{}, normalizeErr
		}
		hardwareAddr, _ = net.ParseMAC(normalizedMAC)
	}

	created := false
	link, err := netlink.LinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		attrs.ParentIndex = parent.Attrs().Index
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if len(hardwareAddr) != 0 {
			attrs.HardwareAddr = hardwareAddr
		}
		if err := netlink.LinkAdd(&netlink.Macvlan{LinkAttrs: attrs, Mode: mode}); err != nil {
			return pluginControlNetMacvlanResult{}, fmt.Errorf("create macvlan %s on %s: %w", name, parentName, err)
		}
		created = true
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return pluginControlNetMacvlanResult{}, fmt.Errorf("resolve macvlan %q: %w", name, err)
	}
	cleanupCreated := func(cause error) (pluginControlNetMacvlanResult, error) {
		if created {
			_ = netlink.LinkDel(link)
		}
		return pluginControlNetMacvlanResult{}, cause
	}
	macvlan, ok := link.(*netlink.Macvlan)
	if !ok || link.Type() != "macvlan" {
		return cleanupCreated(fmt.Errorf("existing link %q is %s, want macvlan", name, link.Type()))
	}
	if link.Attrs().ParentIndex != parent.Attrs().Index {
		return cleanupCreated(fmt.Errorf("existing macvlan %q parent is %q, want %q", name, pluginControlNetLinkNameByIndex(link.Attrs().ParentIndex), parentName))
	}
	if macvlan.Mode != mode {
		return cleanupCreated(fmt.Errorf("existing macvlan %q mode is %s, want %s", name, pluginControlNetMacvlanModeName(macvlan.Mode), pluginControlNetMacvlanModeName(mode)))
	}
	if len(hardwareAddr) != 0 && !strings.EqualFold(link.Attrs().HardwareAddr.String(), hardwareAddr.String()) {
		return cleanupCreated(fmt.Errorf("existing macvlan %q mac is %s, want %s", name, link.Attrs().HardwareAddr, hardwareAddr))
	}
	if req.MTU > 0 && link.Attrs().MTU != req.MTU {
		if err := netlink.LinkSetMTU(link, req.MTU); err != nil {
			return cleanupCreated(fmt.Errorf("set macvlan mtu: %w", err))
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return cleanupCreated(fmt.Errorf("set macvlan up: %w", err))
		}
	}
	info, err := admin.LinkGet(name)
	if err != nil {
		return cleanupCreated(err)
	}
	return pluginControlNetMacvlanResult{Link: info, Created: created}, nil
}

func pluginControlNetMacvlanMode(value string) (netlink.MacvlanMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "bridge":
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	default:
		return netlink.MACVLAN_MODE_DEFAULT, fmt.Errorf("unsupported macvlan mode %q", value)
	}
}

func pluginControlNetMacvlanModeName(mode netlink.MacvlanMode) string {
	switch mode {
	case netlink.MACVLAN_MODE_BRIDGE:
		return "bridge"
	case netlink.MACVLAN_MODE_PRIVATE:
		return "private"
	case netlink.MACVLAN_MODE_VEPA:
		return "vepa"
	case netlink.MACVLAN_MODE_PASSTHRU:
		return "passthru"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
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

func (admin linuxPluginControlNetAdmin) LinkSetARP(name string, enabled bool) (pluginControlNetLinkInfo, error) {
	name = strings.TrimSpace(name)
	link, err := netlink.LinkByName(name)
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	if enabled {
		err = netlink.LinkSetARPOn(link)
	} else {
		err = netlink.LinkSetARPOff(link)
	}
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	return admin.LinkGet(name)
}

func (admin linuxPluginControlNetAdmin) LinkSetPromiscuous(name string, enabled bool) (pluginControlNetLinkInfo, error) {
	name = strings.TrimSpace(name)
	link, err := netlink.LinkByName(name)
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	if enabled {
		err = netlink.SetPromiscOn(link)
	} else {
		err = netlink.SetPromiscOff(link)
	}
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	return admin.LinkGet(name)
}

func (linuxPluginControlNetAdmin) LinkGetOffloads(name string) (map[string]bool, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("interface is required")
	}
	if _, err := netlink.LinkByName(name); err != nil {
		return nil, err
	}
	if _, err := exec.LookPath("ethtool"); err != nil {
		return nil, fmt.Errorf("ethtool not found: %w", err)
	}
	out, err := exec.Command("ethtool", "-k", name).CombinedOutput()
	if err != nil {
		text := strings.TrimSpace(string(out))
		if text == "" {
			text = err.Error()
		}
		return nil, fmt.Errorf("ethtool -k %s failed: %s", name, text)
	}
	features := parsePluginControlOffloadFeatures(string(out))
	if len(features) == 0 {
		return nil, fmt.Errorf("ethtool -k %s returned no supported feature state", name)
	}
	return features, nil
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

func (admin linuxPluginControlNetAdmin) LinkSetGSO(req pluginControlNetGSORequest) (pluginControlNetLinkInfo, error) {
	name := strings.TrimSpace(req.Interface)
	if name == "" {
		return pluginControlNetLinkInfo{}, fmt.Errorf("interface is required")
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	if req.MaxSize < 576 || req.MaxSize > 65536 {
		return pluginControlNetLinkInfo{}, fmt.Errorf("max_size must be between 576 and 65536")
	}
	if req.MaxSegs < 1 || req.MaxSegs > 65535 {
		return pluginControlNetLinkInfo{}, fmt.Errorf("max_segs must be between 1 and 65535")
	}
	previousMaxSize := int(link.Attrs().GSOMaxSize)
	if err := netlink.LinkSetGSOMaxSize(link, req.MaxSize); err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("set gso max size: %w", err)
	}
	if err := netlink.LinkSetGSOMaxSegs(link, req.MaxSegs); err != nil {
		if previousMaxSize > 0 {
			_ = netlink.LinkSetGSOMaxSize(link, previousMaxSize)
		}
		return pluginControlNetLinkInfo{}, fmt.Errorf("set gso max segments: %w", err)
	}
	return admin.LinkGet(name)
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
		ARP:           attrs.RawFlags&unix.IFF_NOARP == 0,
		OperState:     attrs.OperState.String(),
		Addresses:     addrTexts,
		MasterIfIndex: attrs.MasterIndex,
		Promiscuous:   attrs.Promisc > 0,
		GSOMaxSize:    int(attrs.GSOMaxSize),
		GSOMaxSegs:    int(attrs.GSOMaxSegs),
	}
	if attrs.Statistics != nil {
		info.Statistics = &pluginControlNetLinkStatistics{
			RXPackets: attrs.Statistics.RxPackets,
			TXPackets: attrs.Statistics.TxPackets,
			RXBytes:   attrs.Statistics.RxBytes,
			TXBytes:   attrs.Statistics.TxBytes,
			RXErrors:  attrs.Statistics.RxErrors,
			TXErrors:  attrs.Statistics.TxErrors,
			RXDropped: attrs.Statistics.RxDropped,
			TXDropped: attrs.Statistics.TxDropped,
		}
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
