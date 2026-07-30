//go:build linux

package app

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const pluginControlNetLinkLookupAttempts = 8

func newPluginControlNetAdmin() pluginControlNetAdmin {
	return &linuxPluginControlNetAdmin{provider: newLinuxPluginNetworkProvider()}
}

type linuxPluginControlNetAdmin struct {
	provider *linuxPluginNetworkProvider
}

func (admin *linuxPluginControlNetAdmin) RunInNamespace(name string, fn func() error) error {
	if admin == nil || fn == nil {
		return fmt.Errorf("network namespace operation is unavailable")
	}
	name, err := validatePluginControlNamespaceName(name, false)
	if err != nil {
		return err
	}
	return linuxPluginRunInNamespace(name, fn)
}

func (linuxPluginControlNetAdmin) LinkGet(name string) (pluginControlNetLinkInfo, error) {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(name))
	if err != nil {
		return pluginControlNetLinkInfo{}, err
	}
	return pluginControlNetLinkInfoFromLink(link)
}

func (linuxPluginControlNetAdmin) LinkLookup(name string) (pluginControlNetLinkInfo, bool, error) {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(name))
	if pluginControlNetLinkNotFound(err) {
		return pluginControlNetLinkInfo{}, false, nil
	}
	if err != nil {
		return pluginControlNetLinkInfo{}, false, err
	}
	info, err := pluginControlNetLinkInfoFromLink(link)
	return info, err == nil, err
}

func pluginControlNetLinkByName(name string) (netlink.Link, error) {
	request, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("resolve link %q: %w", name, err)
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("resolve link %q: %w", name, err)
	}
	defer unix.Close(socket)
	if err := unix.IoctlIfreq(socket, unix.SIOCGIFINDEX, request); err != nil {
		if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENXIO) {
			return nil, fmt.Errorf("link not found: %s", name)
		}
		return nil, fmt.Errorf("resolve link %q index: %w", name, err)
	}
	return pluginControlNetLinkByIndex(int(request.Uint32()))
}

func pluginControlNetLinkByIndex(index int) (netlink.Link, error) {
	return pluginControlNetRetryLinkLookup(func() (netlink.Link, error) {
		return netlink.LinkByIndex(index)
	})
}

func pluginControlNetRetryLinkLookup(lookup func() (netlink.Link, error)) (netlink.Link, error) {
	return pluginControlNetRetryDump(lookup)
}

func pluginControlNetRetryDump[T any](operation func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := 0; attempt < pluginControlNetLinkLookupAttempts; attempt++ {
		value, err := operation()
		if err == nil {
			return value, nil
		}
		if !errors.Is(err, nl.ErrDumpInterrupted) {
			return zero, err
		}
		lastErr = err
		if attempt+1 < pluginControlNetLinkLookupAttempts {
			time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
		}
	}
	return zero, lastErr
}

func (linuxPluginControlNetAdmin) LinkList() ([]pluginControlNetLinkInfo, error) {
	links, err := pluginControlNetRetryDump(netlink.LinkList)
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
	host, hostErr := pluginControlNetLinkByName(hostName)
	peer, peerErr := pluginControlNetLinkByName(peerName)
	created := false
	cleanupCreated := func(cause error) (pluginControlNetVethResult, error) {
		if created {
			if cleanupLink, err := pluginControlNetLinkByName(hostName); err == nil {
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
		host, err = pluginControlNetLinkByName(hostName)
		if err != nil {
			return cleanupCreated(fmt.Errorf("resolve created host link %q: %w", hostName, err))
		}
		peer, err = pluginControlNetLinkByName(peerName)
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
	link, err := pluginControlNetLinkByName(name)
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
		link, err = pluginControlNetLinkByName(name)
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
	parent, err := pluginControlNetLinkByName(parentName)
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
	link, err := pluginControlNetLinkByName(name)
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
		link, err = pluginControlNetLinkByName(name)
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

func (admin linuxPluginControlNetAdmin) LinkEnsureVLAN(req pluginControlNetVLANRequest) (pluginControlNetVLANResult, error) {
	name := strings.TrimSpace(req.Name)
	parentName := strings.TrimSpace(req.Parent)
	if name == "" || parentName == "" {
		return pluginControlNetVLANResult{}, fmt.Errorf("name and parent are required")
	}
	parent, err := pluginControlNetLinkByName(parentName)
	if err != nil {
		return pluginControlNetVLANResult{}, fmt.Errorf("resolve parent link %q: %w", parentName, err)
	}
	protocol := netlink.StringToVlanProtocol(strings.ToLower(strings.TrimSpace(req.Protocol)))
	if protocol == netlink.VLAN_PROTOCOL_UNKNOWN {
		return pluginControlNetVLANResult{}, fmt.Errorf("unsupported vlan protocol %q", req.Protocol)
	}
	created := false
	link, err := pluginControlNetLinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		attrs.ParentIndex = parent.Attrs().Index
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if err := netlink.LinkAdd(&netlink.Vlan{LinkAttrs: attrs, VlanId: req.VLANID, VlanProtocol: protocol}); err != nil {
			return pluginControlNetVLANResult{}, fmt.Errorf("create vlan %s on %s: %w", name, parentName, err)
		}
		created = true
		link, err = pluginControlNetLinkByName(name)
	}
	if err != nil {
		return pluginControlNetVLANResult{}, fmt.Errorf("resolve vlan %q: %w", name, err)
	}
	cleanupCreated := func(cause error) (pluginControlNetVLANResult, error) {
		if created {
			_ = netlink.LinkDel(link)
		}
		return pluginControlNetVLANResult{}, cause
	}
	vlan, ok := link.(*netlink.Vlan)
	if !ok || link.Type() != "vlan" {
		return cleanupCreated(fmt.Errorf("existing link %q is %s, want vlan", name, link.Type()))
	}
	if link.Attrs().ParentIndex != parent.Attrs().Index {
		return cleanupCreated(fmt.Errorf("existing vlan %q parent is %q, want %q", name, pluginControlNetLinkNameByIndex(link.Attrs().ParentIndex), parentName))
	}
	if vlan.VlanId != req.VLANID || vlan.VlanProtocol != protocol {
		return cleanupCreated(fmt.Errorf("existing vlan %q is id=%d protocol=%s, want id=%d protocol=%s", name, vlan.VlanId, vlan.VlanProtocol, req.VLANID, protocol))
	}
	if req.MTU > 0 && link.Attrs().MTU != req.MTU {
		if err := netlink.LinkSetMTU(link, req.MTU); err != nil {
			return cleanupCreated(fmt.Errorf("set vlan mtu: %w", err))
		}
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return cleanupCreated(fmt.Errorf("set vlan up: %w", err))
		}
	}
	info, err := admin.LinkGet(name)
	if err != nil {
		return cleanupCreated(err)
	}
	return pluginControlNetVLANResult{Link: info, Created: created}, nil
}

func (admin linuxPluginControlNetAdmin) LinkEnsureVRF(req pluginControlNetVRFRequest) (pluginControlNetVRFResult, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" || req.Table == 0 {
		return pluginControlNetVRFResult{}, fmt.Errorf("name and table are required")
	}
	created := false
	link, err := pluginControlNetLinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if err := netlink.LinkAdd(&netlink.Vrf{LinkAttrs: attrs, Table: req.Table}); err != nil {
			return pluginControlNetVRFResult{}, fmt.Errorf("create vrf %s: %w", name, err)
		}
		created = true
		link, err = pluginControlNetLinkByName(name)
	}
	if err != nil {
		return pluginControlNetVRFResult{}, fmt.Errorf("resolve vrf %q: %w", name, err)
	}
	cleanupCreated := func(cause error) (pluginControlNetVRFResult, error) {
		if created {
			_ = netlink.LinkDel(link)
		}
		return pluginControlNetVRFResult{}, cause
	}
	vrf, ok := link.(*netlink.Vrf)
	if !ok || link.Type() != "vrf" {
		return cleanupCreated(fmt.Errorf("existing link %q is %s, want vrf", name, link.Type()))
	}
	if vrf.Table != req.Table {
		return cleanupCreated(fmt.Errorf("existing vrf %q table is %d, want %d", name, vrf.Table, req.Table))
	}
	if req.Up {
		if err := netlink.LinkSetUp(link); err != nil {
			return cleanupCreated(fmt.Errorf("set vrf up: %w", err))
		}
	}
	info, err := admin.LinkGet(name)
	if err != nil {
		return cleanupCreated(err)
	}
	return pluginControlNetVRFResult{Link: info, Created: created}, nil
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
	created := false
	link, err := pluginControlNetLinkByName(name)
	if pluginControlNetLinkNotFound(err) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if req.MTU > 0 {
			attrs.MTU = req.MTU
		}
		if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: attrs}); err != nil {
			return pluginControlNetLinkInfo{}, fmt.Errorf("create bridge %s: %w", name, err)
		}
		created = true
		link, err = pluginControlNetLinkByName(name)
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
	info, err := admin.LinkGet(name)
	info.Created = created
	return info, err
}

func (linuxPluginControlNetAdmin) LinkDelete(name string) error {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(name))
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
	link, err := pluginControlNetLinkByName(linkName)
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("resolve link %q: %w", linkName, err)
	}
	master, err := pluginControlNetLinkByName(masterName)
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("resolve master %q: %w", masterName, err)
	}
	if master.Type() != "bridge" && master.Type() != "vrf" {
		return pluginControlNetLinkInfo{}, fmt.Errorf("master %q is %s, want bridge or vrf", masterName, master.Type())
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
	link, err := pluginControlNetLinkByName(linkName)
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
	link, err := pluginControlNetLinkByName(strings.TrimSpace(name))
	if err != nil {
		return err
	}
	if up {
		return netlink.LinkSetUp(link)
	}
	return netlink.LinkSetDown(link)
}

func (linuxPluginControlNetAdmin) LinkSetMTU(name string, mtu int) error {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(name))
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func (admin linuxPluginControlNetAdmin) LinkSetARP(name string, enabled bool) (pluginControlNetLinkInfo, error) {
	name = strings.TrimSpace(name)
	link, err := pluginControlNetLinkByName(name)
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
	link, err := pluginControlNetLinkByName(name)
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
	if _, err := pluginControlNetLinkByName(name); err != nil {
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
	if _, err := pluginControlNetLinkByName(name); err != nil {
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
	link, err := pluginControlNetLinkByName(name)
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
	updated, err := pluginControlNetLinkByIndex(link.Attrs().Index)
	if err != nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("inspect updated link: %w", err)
	}
	return pluginControlNetLinkInfoFromLink(updated)
}

func (linuxPluginControlNetAdmin) AddrReplace(req pluginControlNetAddrRequest) error {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(strings.TrimSpace(req.CIDR))
	if err != nil {
		return err
	}
	current, err := pluginControlNetRetryDump(func() ([]netlink.Addr, error) {
		return netlink.AddrList(link, netlink.FAMILY_ALL)
	})
	if err != nil {
		return fmt.Errorf("list addresses on %s: %w", strings.TrimSpace(req.Interface), err)
	}
	wanted := ""
	if addr.IPNet != nil {
		wanted = addr.IPNet.String()
	}
	for _, existing := range current {
		if wanted != "" && existing.IPNet != nil && existing.IPNet.String() == wanted {
			return nil
		}
	}
	return netlink.AddrReplace(link, addr)
}

func (linuxPluginControlNetAdmin) AddrDelete(req pluginControlNetAddrRequest) error {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(req.Interface))
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

func (linuxPluginControlNetAdmin) RouteSnapshot(req pluginControlNetRouteRequest) ([]pluginControlNetRouteState, error) {
	desired, err := pluginControlNetRoute(req)
	if err != nil {
		return nil, err
	}
	family := pluginControlNetRouteFamily(desired)
	routes, err := pluginControlNetRetryDump(func() ([]netlink.Route, error) {
		return netlink.RouteListFiltered(family, &netlink.Route{Table: desired.Table}, netlink.RT_FILTER_TABLE)
	})
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetRouteState, 0)
	for _, route := range routes {
		if !pluginControlNetRouteOccupiesSlot(route, *desired, req) {
			continue
		}
		state, err := pluginControlNetRouteStateFromRoute(route, family)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	sort.Slice(out, func(i, j int) bool {
		left := pluginControlNetRouteStateSortKey(out[i])
		right := pluginControlNetRouteStateSortKey(out[j])
		return left < right
	})
	return out, nil
}

func (linuxPluginControlNetAdmin) RouteRestore(states []pluginControlNetRouteState) error {
	for _, state := range states {
		route, err := pluginControlNetRouteFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.RouteReplace(route); err != nil {
			return err
		}
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

func (linuxPluginControlNetAdmin) RuleSnapshot(req pluginControlNetRuleRequest) ([]pluginControlNetRuleState, error) {
	desired, err := pluginControlNetRule(req)
	if err != nil {
		return nil, err
	}
	rules, err := pluginControlNetRetryDump(func() ([]netlink.Rule, error) {
		return netlink.RuleList(desired.Family)
	})
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetRuleState, 0, 1)
	for _, rule := range rules {
		if !pluginControlNetRuleMatches(rule, *desired) {
			continue
		}
		state, err := pluginControlNetRuleStateFromRule(rule)
		if err != nil {
			return nil, err
		}
		out = append(out, state)
	}
	return out, nil
}

func (linuxPluginControlNetAdmin) RuleRestore(states []pluginControlNetRuleState) error {
	for _, state := range states {
		rule, err := pluginControlNetRuleFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.RuleAdd(rule); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	return nil
}

func (admin linuxPluginControlNetAdmin) RuleReplace(req pluginControlNetRuleRequest) error {
	states, err := admin.RuleSnapshot(req)
	if err != nil {
		return err
	}
	for _, state := range states {
		rule, err := pluginControlNetRuleFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.RuleDel(rule); err != nil && !pluginControlNetMutationNotFound(err) {
			return err
		}
	}
	rule, err := pluginControlNetRule(req)
	if err != nil {
		return err
	}
	return netlink.RuleAdd(rule)
}

func (admin linuxPluginControlNetAdmin) RuleDelete(req pluginControlNetRuleRequest) error {
	states, err := admin.RuleSnapshot(req)
	if err != nil {
		return err
	}
	for _, state := range states {
		rule, err := pluginControlNetRuleFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.RuleDel(rule); err != nil && !pluginControlNetMutationNotFound(err) {
			return err
		}
	}
	return nil
}

func pluginControlNetRule(req pluginControlNetRuleRequest) (*netlink.Rule, error) {
	family, err := pluginControlNetAddressFamily(req.Family)
	if err != nil {
		return nil, err
	}
	rule := netlink.NewRule()
	rule.Family = family
	rule.Priority = req.Priority
	rule.Table = req.Table
	rule.Mark = req.Mark
	if req.HasMask {
		mask := req.Mask
		rule.Mask = &mask
	}
	rule.IifName = req.IIF
	rule.OifName = req.OIF
	rule.Invert = req.Invert
	if req.Src != "" {
		_, rule.Src, err = net.ParseCIDR(req.Src)
		if err != nil {
			return nil, fmt.Errorf("src: %w", err)
		}
	}
	if req.Dst != "" {
		_, rule.Dst, err = net.ParseCIDR(req.Dst)
		if err != nil {
			return nil, fmt.Errorf("dst: %w", err)
		}
	}
	return rule, nil
}

func pluginControlNetRuleMatches(got, want netlink.Rule) bool {
	if got.Family != want.Family || got.Priority != want.Priority || got.Table != want.Table || got.Mark != want.Mark ||
		got.IifName != want.IifName || got.OifName != want.OifName || got.Invert != want.Invert {
		return false
	}
	if !pluginControlNetOptionalIPNetEqual(got.Src, want.Src) || !pluginControlNetOptionalIPNetEqual(got.Dst, want.Dst) {
		return false
	}
	gotMask := ^uint32(0)
	wantMask := ^uint32(0)
	if got.Mask != nil {
		gotMask = *got.Mask
	}
	if want.Mask != nil {
		wantMask = *want.Mask
	}
	return gotMask == wantMask
}

func pluginControlNetOptionalIPNetEqual(left, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.String() == right.String()
}

func pluginControlNetRuleStateFromRule(rule netlink.Rule) (pluginControlNetRuleState, error) {
	if rule.Tos != 0 || rule.TunID != 0 || rule.Goto > 0 || rule.Flow > 0 || rule.SuppressIfgroup >= 0 ||
		rule.SuppressPrefixlen >= 0 || rule.Dport != nil || rule.Sport != nil || rule.IPProto != 0 || rule.UIDRange != nil {
		return pluginControlNetRuleState{}, fmt.Errorf("policy rule contains advanced selectors that cannot be leased safely")
	}
	family, err := pluginControlNetAddressFamilyName(rule.Family)
	if err != nil {
		return pluginControlNetRuleState{}, err
	}
	req := pluginControlNetRuleRequest{
		Family: family, Priority: rule.Priority, Table: rule.Table, Mark: rule.Mark,
		IIF: rule.IifName, OIF: rule.OifName, Invert: rule.Invert,
	}
	if rule.Src != nil {
		req.Src = rule.Src.String()
	}
	if rule.Dst != nil {
		req.Dst = rule.Dst.String()
	}
	if rule.Mask != nil {
		req.HasMask = true
		req.Mask = *rule.Mask
	}
	return pluginControlNetRuleState{Request: req, Protocol: rule.Protocol, Type: rule.Type}, nil
}

func pluginControlNetRuleFromState(state pluginControlNetRuleState) (*netlink.Rule, error) {
	rule, err := pluginControlNetRule(state.Request)
	if err != nil {
		return nil, err
	}
	rule.Protocol = state.Protocol
	rule.Type = state.Type
	return rule, nil
}

func (linuxPluginControlNetAdmin) NeighSnapshot(req pluginControlNetNeighRequest) ([]pluginControlNetNeighState, error) {
	link, ip, family, err := pluginControlNetNeighTarget(req)
	if err != nil {
		return nil, err
	}
	neighbors, err := pluginControlNetRetryDump(func() ([]netlink.Neigh, error) {
		return netlink.NeighList(link.Attrs().Index, family)
	})
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetNeighState, 0, 1)
	for _, neighbor := range neighbors {
		if !neighbor.IP.Equal(ip) || neighbor.Vlan != req.VLAN {
			continue
		}
		if neighbor.State&unix.NUD_PERMANENT == 0 && neighbor.State&unix.NUD_NOARP == 0 {
			return nil, fmt.Errorf("existing neighbor %s on %s is dynamic and cannot be leased safely", ip, req.Interface)
		}
		stateName, err := pluginControlNetNeighStateName(neighbor.State)
		if err != nil {
			return nil, err
		}
		if len(neighbor.HardwareAddr) != 6 {
			return nil, fmt.Errorf("existing static neighbor %s on %s has no usable ethernet address", ip, req.Interface)
		}
		out = append(out, pluginControlNetNeighState{
			Request: pluginControlNetNeighRequest{
				Interface: req.Interface, IP: ip.String(), MAC: neighbor.HardwareAddr.String(), State: stateName, VLAN: neighbor.Vlan,
			},
			Family: family, LinkIfIndex: link.Attrs().Index, Flags: neighbor.Flags, FlagsExt: neighbor.FlagsExt, Type: neighbor.Type,
		})
	}
	return out, nil
}

func (linuxPluginControlNetAdmin) NeighRestore(states []pluginControlNetNeighState) error {
	for _, state := range states {
		neighbor, err := pluginControlNetNeighFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.NeighSet(neighbor); err != nil {
			return err
		}
	}
	return nil
}

func (linuxPluginControlNetAdmin) NeighReplace(req pluginControlNetNeighRequest) error {
	neighbor, err := pluginControlNetNeigh(req)
	if err != nil {
		return err
	}
	return netlink.NeighSet(neighbor)
}

func (admin linuxPluginControlNetAdmin) NeighDelete(req pluginControlNetNeighRequest) error {
	states, err := admin.NeighSnapshot(req)
	if err != nil {
		return err
	}
	for _, state := range states {
		neighbor, err := pluginControlNetNeighFromState(state)
		if err != nil {
			return err
		}
		if err := netlink.NeighDel(neighbor); err != nil && !pluginControlNetMutationNotFound(err) {
			return err
		}
	}
	return nil
}

func (linuxPluginControlNetAdmin) NeighList(req pluginControlNetReadRequest) ([]pluginControlNetNeighborInfo, error) {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return nil, err
	}
	family := unix.AF_UNSPEC
	switch req.Family {
	case "ipv4":
		family = unix.AF_INET
	case "ipv6":
		family = unix.AF_INET6
	}
	neighbors, err := pluginControlNetRetryDump(func() ([]netlink.Neigh, error) {
		return netlink.NeighList(link.Attrs().Index, family)
	})
	if err != nil {
		return nil, err
	}
	out := make([]pluginControlNetNeighborInfo, 0, len(neighbors))
	for _, neighbor := range neighbors {
		if neighbor.IP == nil {
			continue
		}
		familyName, err := pluginControlNetAddressFamilyName(neighbor.Family)
		if err != nil {
			continue
		}
		out = append(out, pluginControlNetNeighborInfo{
			Interface: req.Interface,
			IP:        neighbor.IP.String(),
			MAC:       neighbor.HardwareAddr.String(),
			Family:    familyName,
			State:     pluginControlNetReadableNeighStateName(neighbor.State),
			VLAN:      neighbor.Vlan,
			Flags:     neighbor.Flags,
			FlagsExt:  neighbor.FlagsExt,
			Type:      neighbor.Type,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].IP < out[j].IP
	})
	return out, nil
}

func (linuxPluginControlNetAdmin) BridgeFDBList(req pluginControlNetReadRequest) ([]pluginControlNetFDBInfo, error) {
	target, err := pluginControlNetLinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return nil, err
	}
	links, err := pluginControlNetRetryDump(netlink.LinkList)
	if err != nil {
		return nil, err
	}
	linkByIndex := make(map[int]netlink.Link, len(links))
	for _, link := range links {
		if link != nil && link.Attrs() != nil {
			linkByIndex[link.Attrs().Index] = link
		}
	}
	entries, err := pluginControlNetRetryDump(func() ([]netlink.Neigh, error) {
		return netlink.NeighListExecute(netlink.Ndmsg{Family: unix.AF_BRIDGE})
	})
	if err != nil {
		return nil, err
	}
	targetIndex := target.Attrs().Index
	targetIsBridge := strings.EqualFold(strings.TrimSpace(target.Type()), "bridge")
	out := make([]pluginControlNetFDBInfo, 0)
	for _, entry := range entries {
		entryLink := linkByIndex[entry.LinkIndex]
		if entryLink == nil || entryLink.Attrs() == nil {
			continue
		}
		masterIndex := entry.MasterIndex
		if masterIndex <= 0 {
			masterIndex = entryLink.Attrs().MasterIndex
		}
		if targetIsBridge {
			if masterIndex != targetIndex && entry.LinkIndex != targetIndex {
				continue
			}
		} else if entry.LinkIndex != targetIndex {
			continue
		}
		bridgeName := ""
		if master := linkByIndex[masterIndex]; master != nil && master.Attrs() != nil {
			bridgeName = strings.TrimSpace(master.Attrs().Name)
		}
		out = append(out, pluginControlNetFDBInfo{
			Interface: strings.TrimSpace(entryLink.Attrs().Name),
			Bridge:    bridgeName,
			MAC:       entry.HardwareAddr.String(),
			State:     pluginControlNetReadableNeighStateName(entry.State),
			VLAN:      entry.Vlan,
			Flags:     entry.Flags,
			FlagsExt:  entry.FlagsExt,
			Type:      entry.Type,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		if out[i].VLAN != out[j].VLAN {
			return out[i].VLAN < out[j].VLAN
		}
		return out[i].MAC < out[j].MAC
	})
	return out, nil
}

func pluginControlNetReadableNeighStateName(value int) string {
	states := []struct {
		value int
		name  string
	}{
		{unix.NUD_INCOMPLETE, "incomplete"},
		{unix.NUD_REACHABLE, "reachable"},
		{unix.NUD_STALE, "stale"},
		{unix.NUD_DELAY, "delay"},
		{unix.NUD_PROBE, "probe"},
		{unix.NUD_FAILED, "failed"},
		{unix.NUD_NOARP, "noarp"},
		{unix.NUD_PERMANENT, "permanent"},
	}
	parts := make([]string, 0, 2)
	for _, state := range states {
		if value&state.value != 0 {
			parts = append(parts, state.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

func pluginControlNetNeigh(req pluginControlNetNeighRequest) (*netlink.Neigh, error) {
	link, ip, family, err := pluginControlNetNeighTarget(req)
	if err != nil {
		return nil, err
	}
	mac, err := net.ParseMAC(req.MAC)
	if err != nil || len(mac) != 6 {
		return nil, fmt.Errorf("mac must be a 6-byte address")
	}
	state, err := pluginControlNetNeighStateValue(req.State)
	if err != nil {
		return nil, err
	}
	return &netlink.Neigh{
		LinkIndex: link.Attrs().Index, Family: family, State: state, Type: unix.RTN_UNICAST,
		IP: ip, HardwareAddr: mac, Vlan: req.VLAN,
	}, nil
}

func pluginControlNetNeighTarget(req pluginControlNetNeighRequest) (netlink.Link, net.IP, int, error) {
	link, err := pluginControlNetLinkByName(strings.TrimSpace(req.Interface))
	if err != nil {
		return nil, nil, 0, err
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		return nil, nil, 0, fmt.Errorf("invalid neighbor ip")
	}
	family := unix.AF_INET6
	if ip.To4() != nil {
		family = unix.AF_INET
		ip = ip.To4()
	}
	return link, ip, family, nil
}

func pluginControlNetNeighFromState(state pluginControlNetNeighState) (*netlink.Neigh, error) {
	neighbor, err := pluginControlNetNeigh(state.Request)
	if err != nil {
		return nil, err
	}
	if state.LinkIfIndex > 0 && neighbor.LinkIndex != state.LinkIfIndex {
		return nil, fmt.Errorf("neighbor interface identity changed")
	}
	neighbor.Family = state.Family
	neighbor.Flags = state.Flags
	neighbor.FlagsExt = state.FlagsExt
	neighbor.Type = state.Type
	return neighbor, nil
}

func pluginControlNetNeighStateValue(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "permanent":
		return unix.NUD_PERMANENT, nil
	case "noarp":
		return unix.NUD_NOARP, nil
	default:
		return 0, fmt.Errorf("neighbor state must be permanent or noarp")
	}
}

func pluginControlNetNeighStateName(value int) (string, error) {
	if value&unix.NUD_PERMANENT != 0 {
		return "permanent", nil
	}
	if value&unix.NUD_NOARP != 0 {
		return "noarp", nil
	}
	return "", fmt.Errorf("unsupported neighbor state %d", value)
}

func pluginControlNetAddressFamily(value string) (int, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ipv4", "inet", "4":
		return unix.AF_INET, nil
	case "ipv6", "inet6", "6":
		return unix.AF_INET6, nil
	default:
		return 0, fmt.Errorf("family must be ipv4 or ipv6")
	}
}

func pluginControlNetAddressFamilyName(value int) (string, error) {
	switch value {
	case unix.AF_INET:
		return "ipv4", nil
	case unix.AF_INET6:
		return "ipv6", nil
	default:
		return "", fmt.Errorf("unsupported address family %d", value)
	}
}

func pluginControlNetMutationNotFound(err error) bool {
	return errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH)
}

func pluginControlNetRouteFamily(route *netlink.Route) int {
	if route != nil {
		if route.Family == netlink.FAMILY_V6 {
			return netlink.FAMILY_V6
		}
		if route.Dst != nil && route.Dst.IP.To4() == nil {
			return netlink.FAMILY_V6
		}
		if route.Gw != nil && route.Gw.To4() == nil {
			return netlink.FAMILY_V6
		}
		if route.Src != nil && route.Src.To4() == nil {
			return netlink.FAMILY_V6
		}
		for _, nexthop := range route.MultiPath {
			if nexthop != nil && nexthop.Gw != nil && nexthop.Gw.To4() == nil {
				return netlink.FAMILY_V6
			}
		}
	}
	return netlink.FAMILY_V4
}

func pluginControlNetRouteOccupiesSlot(route, desired netlink.Route, req pluginControlNetRouteRequest) bool {
	if route.Table != desired.Table || route.Priority != desired.Priority || route.Tos != desired.Tos {
		return false
	}
	if !pluginControlNetIPNetEqual(route.Dst, desired.Dst) {
		return false
	}
	if len(desired.MultiPath) == 0 && desired.LinkIndex != 0 && route.LinkIndex != desired.LinkIndex {
		return false
	}
	if req.Scope != 0 && route.Scope != desired.Scope {
		return false
	}
	return true
}

func pluginControlNetIPNetEqual(left, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.String() == right.String()
}

func pluginControlNetRouteStateFromRoute(route netlink.Route, family int) (pluginControlNetRouteState, error) {
	if route.MPLSDst != nil || route.NewDst != nil || route.Encap != nil || route.Via != nil || route.ILinkIndex != 0 {
		return pluginControlNetRouteState{}, fmt.Errorf("route slot contains an advanced route that cannot be leased safely")
	}
	dst := "0.0.0.0/0"
	if family == netlink.FAMILY_V6 {
		dst = "::/0"
	}
	if route.Dst != nil {
		dst = route.Dst.String()
	}
	dev := ""
	if len(route.MultiPath) > 0 && (route.LinkIndex != 0 || len(route.Gw) != 0) {
		return pluginControlNetRouteState{}, fmt.Errorf("multipath route contains conflicting single-path attributes")
	}
	if route.LinkIndex > 0 {
		dev = pluginControlNetLinkNameByIndex(route.LinkIndex)
		if dev == "" {
			return pluginControlNetRouteState{}, fmt.Errorf("resolve route interface index %d", route.LinkIndex)
		}
	}
	nexthops := make([]pluginControlNetRouteNexthopState, 0, len(route.MultiPath))
	for index, nexthop := range route.MultiPath {
		if nexthop == nil || nexthop.LinkIndex < 1 || nexthop.Hops < 0 || nexthop.Hops > 255 || nexthop.NewDst != nil || nexthop.Encap != nil || nexthop.Via != nil {
			return pluginControlNetRouteState{}, fmt.Errorf("multipath route nexthop %d is invalid or uses unsupported attributes", index)
		}
		nexthopDev := pluginControlNetLinkNameByIndex(nexthop.LinkIndex)
		if nexthopDev == "" {
			return pluginControlNetRouteState{}, fmt.Errorf("resolve route nexthop interface index %d", nexthop.LinkIndex)
		}
		nexthops = append(nexthops, pluginControlNetRouteNexthopState{
			Gateway: pluginControlNetIPString(nexthop.Gw), Dev: nexthopDev, DevIfIndex: nexthop.LinkIndex,
			Weight: nexthop.Hops + 1, Onlink: nexthop.Flags&int(netlink.FLAG_ONLINK) != 0, Flags: nexthop.Flags,
		})
	}
	sort.Slice(nexthops, func(i, j int) bool {
		return pluginControlNetRouteNexthopStateSortKey(nexthops[i]) < pluginControlNetRouteNexthopStateSortKey(nexthops[j])
	})
	return pluginControlNetRouteState{
		Dst: dst, Gateway: pluginControlNetIPString(route.Gw), Dev: dev, DevIfIndex: route.LinkIndex, Src: pluginControlNetIPString(route.Src),
		Table: route.Table, Metric: route.Priority, Scope: int(route.Scope), Protocol: int(route.Protocol), Type: route.Type,
		TOS: route.Tos, Flags: route.Flags, Realm: route.Realm, MTU: route.MTU, MTULock: route.MTULock,
		Window: route.Window, RTT: route.Rtt, RTTVar: route.RttVar, SSThresh: route.Ssthresh, Cwnd: route.Cwnd,
		AdvMSS: route.AdvMSS, Reordering: route.Reordering, Hoplimit: route.Hoplimit, InitCwnd: route.InitCwnd,
		Features: route.Features, RtoMin: route.RtoMin, RtoMinLock: route.RtoMinLock, InitRwnd: route.InitRwnd,
		QuickACK: route.QuickACK, Congctl: route.Congctl, FastOpenNoCookie: route.FastOpenNoCookie, Nexthops: nexthops,
	}, nil
}

func pluginControlNetRouteNexthopStateSortKey(nexthop pluginControlNetRouteNexthopState) string {
	return fmt.Sprintf("%s\x00%s\x00%03d\x00%010d", nexthop.Dev, nexthop.Gateway, nexthop.Weight, nexthop.Flags)
}

func pluginControlNetRouteStateSortKey(state pluginControlNetRouteState) string {
	parts := make([]string, 0, len(state.Nexthops))
	for _, nexthop := range state.Nexthops {
		parts = append(parts, pluginControlNetRouteNexthopStateSortKey(nexthop))
	}
	return fmt.Sprintf("%s|%s|%s|%d|%d|%s", state.Dst, state.Dev, state.Gateway, state.Table, state.Metric, strings.Join(parts, ","))
}

func pluginControlNetIPString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func pluginControlNetRouteFromState(state pluginControlNetRouteState) (*netlink.Route, error) {
	req, err := pluginControlNetRouteRequestForState(state)
	if err != nil {
		return nil, err
	}
	route, err := pluginControlNetRoute(req)
	if err != nil {
		return nil, err
	}
	if state.DevIfIndex > 0 && route.LinkIndex != state.DevIfIndex {
		return nil, fmt.Errorf("route interface %s changed identity", state.Dev)
	}
	if len(route.MultiPath) != len(state.Nexthops) {
		return nil, fmt.Errorf("route nexthop count changed")
	}
	for index := range route.MultiPath {
		if state.Nexthops[index].DevIfIndex > 0 && route.MultiPath[index].LinkIndex != state.Nexthops[index].DevIfIndex {
			return nil, fmt.Errorf("route nexthop interface %s changed identity", state.Nexthops[index].Dev)
		}
		route.MultiPath[index].Flags = state.Nexthops[index].Flags
	}
	route.Protocol = netlink.RouteProtocol(state.Protocol)
	route.Type = state.Type
	route.Tos = state.TOS
	route.Flags = state.Flags
	route.Realm = state.Realm
	route.MTU = state.MTU
	route.MTULock = state.MTULock
	route.Window = state.Window
	route.Rtt = state.RTT
	route.RttVar = state.RTTVar
	route.Ssthresh = state.SSThresh
	route.Cwnd = state.Cwnd
	route.AdvMSS = state.AdvMSS
	route.Reordering = state.Reordering
	route.Hoplimit = state.Hoplimit
	route.InitCwnd = state.InitCwnd
	route.Features = state.Features
	route.RtoMin = state.RtoMin
	route.RtoMinLock = state.RtoMinLock
	route.InitRwnd = state.InitRwnd
	route.QuickACK = state.QuickACK
	route.Congctl = state.Congctl
	route.FastOpenNoCookie = state.FastOpenNoCookie
	return route, nil
}

func pluginControlNetLinkInfoFromLink(link netlink.Link) (pluginControlNetLinkInfo, error) {
	if link == nil || link.Attrs() == nil {
		return pluginControlNetLinkInfo{}, fmt.Errorf("invalid link")
	}
	attrs := link.Attrs()
	addrs, err := pluginControlNetRetryDump(func() ([]netlink.Addr, error) {
		return netlink.AddrList(link, unix.AF_UNSPEC)
	})
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
	switch typed := link.(type) {
	case *netlink.Vlan:
		info.VLANID = typed.VlanId
		info.VLANProtocol = typed.VlanProtocol.String()
	case *netlink.Vrf:
		info.VRFTable = typed.Table
	}
	return info, nil
}

func pluginControlNetRoute(req pluginControlNetRouteRequest) (*netlink.Route, error) {
	req, err := validatePluginControlRouteRequest(req)
	if err != nil {
		return nil, err
	}
	var dst *net.IPNet
	if !pluginControlNetIsDefaultRoute(req.Dst) {
		dst, err = pluginControlNetParseCIDR(req.Dst)
		if err != nil {
			return nil, fmt.Errorf("dst: %w", err)
		}
	}
	linkIndex := 0
	if strings.TrimSpace(req.Dev) != "" {
		link, err := pluginControlNetLinkByName(strings.TrimSpace(req.Dev))
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
	multipath := make([]*netlink.NexthopInfo, 0, len(req.Nexthops))
	for _, nexthop := range req.Nexthops {
		link, err := pluginControlNetLinkByName(nexthop.Dev)
		if err != nil {
			return nil, fmt.Errorf("nexthop dev %q: %w", nexthop.Dev, err)
		}
		info := &netlink.NexthopInfo{LinkIndex: link.Attrs().Index, Hops: nexthop.Weight - 1}
		if nexthop.Gateway != "" {
			info.Gw = net.ParseIP(nexthop.Gateway)
		}
		if nexthop.Onlink {
			info.Flags |= int(netlink.FLAG_ONLINK)
		}
		multipath = append(multipath, info)
	}
	route := &netlink.Route{
		LinkIndex: linkIndex,
		Dst:       dst,
		Gw:        gw,
		Src:       src,
		Table:     table,
		Priority:  req.Metric,
		MultiPath: multipath,
	}
	_, familyNetwork, _ := net.ParseCIDR(req.Dst)
	if familyNetwork != nil && familyNetwork.IP.To4() == nil {
		route.Family = netlink.FAMILY_V6
	} else {
		route.Family = netlink.FAMILY_V4
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
	link, err := pluginControlNetLinkByIndex(index)
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
