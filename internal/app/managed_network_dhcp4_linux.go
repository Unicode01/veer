//go:build linux

package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"forward/internal/hotrestart"
	"hash/fnv"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	dhcpv4ClientPort          = 68
	dhcpv4ServerPort          = 67
	dhcpv4BootReply           = 2
	dhcpv4HWTypeEthernet      = 1
	dhcpv4MagicCookie         = 0x63825363
	dhcpv4OptionSubnetMask    = 1
	dhcpv4OptionRouter        = 3
	dhcpv4OptionDNS           = 6
	dhcpv4OptionRequestedIP   = 50
	dhcpv4OptionLeaseTime     = 51
	dhcpv4OptionMessageType   = 53
	dhcpv4OptionServerID      = 54
	dhcpv4OptionRenewalTime   = 58
	dhcpv4OptionRebindingTime = 59
	dhcpv4OptionClientID      = 61
	dhcpv4OptionEnd           = 255

	dhcpv4MessageDiscover = 1
	dhcpv4MessageOffer    = 2
	dhcpv4MessageRequest  = 3
	dhcpv4MessageDecline  = 4
	dhcpv4MessageAck      = 5
	dhcpv4MessageNak      = 6
	dhcpv4MessageRelease  = 7
	dhcpv4MessageInform   = 8

	dhcpv4LeaseTime       = 24 * time.Hour
	dhcpv4RenewTime       = 12 * time.Hour
	dhcpv4RebindTime      = 21 * time.Hour
	dhcpv4TroubleLogEvery = 5 * time.Minute
	dhcpv4MinMessageSize  = 300
	ipv4ProtocolUDP       = 17
)

var (
	dhcpv4BroadcastIP                              = net.IPv4bcast
	dhcpv4BroadcastMAC                             = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	errDHCPv4NAK                                   = errors.New("dhcpv4 nak")
	loadInterfaceInfosForManagedNetworkDHCPv4Tests func() ([]InterfaceInfo, error)
	lookupManagedNetworkDHCPv4InterfaceForTests    func(string) (*net.Interface, error)
)

func newManagedNetworkRuntime() managedNetworkRuntime {
	return newManagedIPv4NetworkRuntime(newLinuxManagedNetworkNetOps())
}

func managedNetworkPreserveStateOnClose() bool {
	markerPath := kernelHotRestartMarkerPath()
	if strings.TrimSpace(markerPath) == "" {
		return false
	}
	_, err := os.Stat(markerPath)
	return err == nil
}

func userspaceWorkerPreserveOnClose() bool {
	return hotrestart.ShouldPreserveOnClose(kernelHotRestartMarkerPath())
}

const (
	packetSocketIPv4VersionIHLByteOffset = 14
	packetSocketIPv4ProtocolOffset       = 14 + 9
	packetSocketIPv4UDPSourcePortOffset  = 14 + 20
	packetSocketIPv4UDPDestPortOffset    = 14 + 22
)

type managedNetworkDHCPv4Server struct {
	mu             sync.Mutex
	config         managedNetworkDHCPv4Config
	stopCh         chan struct{}
	doneCh         chan struct{}
	currentFDs     []int
	stickyIfaces   []string
	listeningSince time.Time
	leases         map[string]managedNetworkDHCPv4Lease
	ipOwners       map[string]string
	lastIssueText  string
	lastIssueAt    time.Time
	lastSeenText   string
	lastSeenAt     time.Time
	replyTotal     uint64
	lastReplyAt    time.Time
}

type linuxManagedNetworkNetOps struct {
	mu     sync.Mutex
	dhcpv4 map[string]*managedNetworkDHCPv4Server
}

func newLinuxManagedNetworkNetOps() *linuxManagedNetworkNetOps {
	return &linuxManagedNetworkNetOps{
		dhcpv4: make(map[string]*managedNetworkDHCPv4Server),
	}
}

func (ops *linuxManagedNetworkNetOps) EnsureIPv4ForwardingEnabled() error {
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4", "ip_forward"), "1\n"); err != nil {
		return err
	}
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf/all", "forwarding"), "1\n"); err != nil {
		return err
	}
	return writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf/default", "forwarding"), "1\n")
}

func (ops *linuxManagedNetworkNetOps) EnsureIPv4ForwardingEnabledOnInterface(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf", interfaceName, "forwarding"), "1\n"); err != nil {
		return err
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil || link == nil || link.Attrs() == nil || link.Attrs().MasterIndex <= 0 {
		return nil
	}
	master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
	if err != nil || master == nil || master.Attrs() == nil || strings.TrimSpace(master.Attrs().Name) == "" {
		return nil
	}
	return writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf", master.Attrs().Name, "forwarding"), "1\n")
}

func (ops *linuxManagedNetworkNetOps) EnsureManagedNetworkInterface(spec managedNetworkInterfaceSpec) error {
	interfaceName := strings.TrimSpace(spec.Name)
	mode := normalizeManagedNetworkBridgeMode(spec.Mode)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if !errors.As(err, &linkNotFound) {
			return err
		}
		if mode == managedNetworkBridgeModeExisting {
			return fmt.Errorf("interface %q does not exist", interfaceName)
		}
		attrs := netlink.LinkAttrs{Name: interfaceName}
		if spec.BridgeMTU > 0 {
			attrs.MTU = spec.BridgeMTU
		}
		bridge := &netlink.Bridge{
			LinkAttrs: attrs,
		}
		bridge.VlanFiltering = &spec.BridgeVLANAware
		if err := netlink.LinkAdd(bridge); err != nil {
			return err
		}
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			return err
		}
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", interfaceName)
	}
	if mode == managedNetworkBridgeModeCreate && !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return fmt.Errorf("interface %q already exists and is not a bridge", interfaceName)
	}
	if mode == managedNetworkBridgeModeCreate {
		if spec.BridgeMTU > 0 && link.Attrs().MTU != spec.BridgeMTU {
			if err := netlink.LinkSetMTU(link, spec.BridgeMTU); err != nil {
				return err
			}
		}
		if bridge, ok := link.(*netlink.Bridge); ok {
			if bridge.VlanFiltering == nil || *bridge.VlanFiltering != spec.BridgeVLANAware {
				if err := netlink.BridgeSetVlanFiltering(bridge, spec.BridgeVLANAware); err != nil {
					return err
				}
			}
		}
	}
	if !managedNetworkLinkAdminUp(link) {
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}
	return nil
}

func (ops *linuxManagedNetworkNetOps) EnsureManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error {
	link, addr, err := linuxManagedNetworkIPv4AddressFromSpec(spec)
	if err != nil {
		return err
	}
	present, err := linuxManagedNetworkHasIPv4Address(link, addr)
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	return netlink.AddrReplace(link, addr)
}

func (ops *linuxManagedNetworkNetOps) DeleteManagedNetworkIPv4Address(spec managedNetworkIPv4AddressSpec) error {
	link, addr, err := linuxManagedNetworkIPv4AddressFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	if err := netlink.AddrDel(link, addr); err != nil {
		return nil
	}
	return nil
}

func (ops *linuxManagedNetworkNetOps) EnsureManagedNetworkDHCPv4(config managedNetworkDHCPv4Config) error {
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	server := ops.dhcpv4[config.Bridge]
	if server == nil {
		server = newManagedNetworkDHCPv4Server(config)
		ops.dhcpv4[config.Bridge] = server
		ops.mu.Unlock()
		server.start()
		log.Printf("managed network runtime: dhcpv4 enabled on %s (gateway=%s pool=%s-%s dns=%v reservations=%d)", config.Bridge, config.Gateway, config.PoolStart, config.PoolEnd, config.DNSServers, len(config.Reservations))
		return nil
	}
	changed := server.update(config)
	ops.mu.Unlock()
	if !changed {
		return nil
	}
	log.Printf("managed network runtime: dhcpv4 updated on %s (gateway=%s pool=%s-%s dns=%v reservations=%d)", config.Bridge, config.Gateway, config.PoolStart, config.PoolEnd, config.DNSServers, len(config.Reservations))
	return nil
}

func (ops *linuxManagedNetworkNetOps) DeleteManagedNetworkDHCPv4(bridge string) error {
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	server := ops.dhcpv4[bridge]
	if server != nil {
		delete(ops.dhcpv4, bridge)
	}
	ops.mu.Unlock()
	if server != nil {
		server.stop()
	}
	return nil
}

func (ops *linuxManagedNetworkNetOps) SnapshotManagedNetworkDHCPv4States() map[string]managedNetworkDHCPv4RuntimeState {
	if ops == nil {
		return nil
	}

	ops.mu.Lock()
	servers := make(map[string]*managedNetworkDHCPv4Server, len(ops.dhcpv4))
	for bridge, server := range ops.dhcpv4 {
		servers[bridge] = server
	}
	ops.mu.Unlock()

	if len(servers) == 0 {
		return nil
	}

	states := make(map[string]managedNetworkDHCPv4RuntimeState, len(servers))
	for bridge, server := range servers {
		states[bridge] = server.snapshotStatus()
	}
	return states
}

func linuxManagedNetworkIPv4AddressFromSpec(spec managedNetworkIPv4AddressSpec) (netlink.Link, *netlink.Addr, error) {
	ifaceName := strings.TrimSpace(spec.InterfaceName)
	if ifaceName == "" {
		return nil, nil, fmt.Errorf("interface is required")
	}
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, nil, fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(spec.CIDR))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return nil, nil, fmt.Errorf("invalid ipv4 cidr %q", spec.CIDR)
	}
	return link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: prefix.Mask},
	}, nil
}

func linuxManagedNetworkHasIPv4Address(link netlink.Link, want *netlink.Addr) (bool, error) {
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return false, fmt.Errorf("interface is unavailable")
	}
	if want == nil || want.IPNet == nil || want.IPNet.IP == nil || want.IPNet.IP.To4() == nil {
		return false, fmt.Errorf("ipv4 address is required")
	}
	wantCIDR := (&net.IPNet{IP: want.IPNet.IP.To4(), Mask: want.IPNet.Mask}).String()
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.IPNet == nil || addr.IPNet.IP == nil || addr.IPNet.IP.To4() == nil {
			continue
		}
		if (&net.IPNet{IP: addr.IPNet.IP.To4(), Mask: addr.IPNet.Mask}).String() == wantCIDR {
			return true, nil
		}
	}
	return false, nil
}

func managedNetworkLinkAdminUp(link netlink.Link) bool {
	if link == nil || link.Attrs() == nil {
		return false
	}
	return link.Attrs().RawFlags&unix.IFF_UP != 0
}

func writeLinuxIPv4Sysctl(path string, value string) error {
	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) == strings.TrimSpace(value) {
		return nil
	}
	return os.WriteFile(path, []byte(value), 0o644)
}

type managedNetworkDHCPv4Lease struct {
	ClientKey string
	IP        string
	ExpiresAt time.Time
}

type managedNetworkDHCPv4State struct {
	IfIndex       int
	IfName        string
	BridgeIfIndex int
	MAC           net.HardwareAddr
	Config        managedNetworkDHCPv4Config
}

type managedNetworkDHCPv4Frame struct {
	SrcMAC  net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	Payload []byte
}

type parsedManagedNetworkDHCPv4Message struct {
	Op          byte
	HType       byte
	HLen        byte
	XID         uint32
	Flags       uint16
	CIAddr      net.IP
	YIAddr      net.IP
	SIAddr      net.IP
	GIAddr      net.IP
	CHAddr      net.HardwareAddr
	MessageType byte
	RequestedIP net.IP
	ServerID    net.IP
	ClientID    []byte
	RawPacket   []byte
}

func newManagedNetworkDHCPv4Server(config managedNetworkDHCPv4Config) *managedNetworkDHCPv4Server {
	return &managedNetworkDHCPv4Server{
		config:   config,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		leases:   make(map[string]managedNetworkDHCPv4Lease),
		ipOwners: make(map[string]string),
	}
}

func (srv *managedNetworkDHCPv4Server) start() {
	go srv.run()
}

func managedNetworkDHCPv4ConfigsEqual(a managedNetworkDHCPv4Config, b managedNetworkDHCPv4Config) bool {
	if a.Bridge != b.Bridge ||
		a.UplinkInterface != b.UplinkInterface ||
		a.ServerCIDR != b.ServerCIDR ||
		a.ServerIP != b.ServerIP ||
		a.Gateway != b.Gateway ||
		a.PoolStart != b.PoolStart ||
		a.PoolEnd != b.PoolEnd {
		return false
	}
	if len(a.DNSServers) != len(b.DNSServers) {
		return false
	}
	for i := range a.DNSServers {
		if a.DNSServers[i] != b.DNSServers[i] {
			return false
		}
	}
	if len(a.Reservations) != len(b.Reservations) {
		return false
	}
	for i := range a.Reservations {
		if a.Reservations[i] != b.Reservations[i] {
			return false
		}
	}
	return true
}

func (srv *managedNetworkDHCPv4Server) update(config managedNetworkDHCPv4Config) bool {
	if srv == nil {
		return false
	}
	srv.mu.Lock()
	if managedNetworkDHCPv4ConfigsEqual(srv.config, config) {
		srv.mu.Unlock()
		return false
	}
	srv.config = config
	srv.mu.Unlock()
	return true
}

func (srv *managedNetworkDHCPv4Server) snapshot() managedNetworkDHCPv4Config {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	reservations := append([]managedNetworkDHCPv4Reservation(nil), srv.config.Reservations...)
	return managedNetworkDHCPv4Config{
		Bridge:          srv.config.Bridge,
		UplinkInterface: srv.config.UplinkInterface,
		ServerCIDR:      srv.config.ServerCIDR,
		ServerIP:        srv.config.ServerIP,
		Gateway:         srv.config.Gateway,
		PoolStart:       srv.config.PoolStart,
		PoolEnd:         srv.config.PoolEnd,
		DNSServers:      append([]string(nil), srv.config.DNSServers...),
		Reservations:    reservations,
	}
}

func (srv *managedNetworkDHCPv4Server) stop() {
	if srv == nil {
		return
	}
	close(srv.stopCh)
	srv.mu.Lock()
	fds := append([]int(nil), srv.currentFDs...)
	srv.currentFDs = nil
	srv.mu.Unlock()
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
	<-srv.doneCh
}

type managedNetworkDHCPv4Socket struct {
	state managedNetworkDHCPv4State
	fd    int
}

func (srv *managedNetworkDHCPv4Server) snapshotStickyInterfaces() []string {
	if srv == nil {
		return nil
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return append([]string(nil), srv.stickyIfaces...)
}

func (srv *managedNetworkDHCPv4Server) setStickyInterfaces(names []string) {
	if srv == nil {
		return
	}
	srv.mu.Lock()
	srv.stickyIfaces = managedNetworkDHCPv4FilterStickyInterfaces(names)
	srv.mu.Unlock()
}

func (srv *managedNetworkDHCPv4Server) run() {
	defer close(srv.doneCh)

	for {
		select {
		case <-srv.stopCh:
			return
		default:
		}

		config := srv.snapshot()
		sockets, err := openManagedNetworkDHCPv4Sockets(config, srv.snapshotStickyInterfaces())
		if err != nil {
			srv.logIssue(fmt.Sprintf("open socket: %v", err))
			select {
			case <-srv.stopCh:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}
		srv.setStickyInterfaces(managedNetworkDHCPv4StickyInterfacesFromSockets(sockets))

		srv.mu.Lock()
		srv.currentFDs = make([]int, 0, len(sockets))
		for _, socket := range sockets {
			srv.currentFDs = append(srv.currentFDs, socket.fd)
		}
		srv.listeningSince = time.Now()
		srv.mu.Unlock()

		func() {
			defer func() {
				srv.mu.Lock()
				srv.currentFDs = nil
				srv.mu.Unlock()
				for _, socket := range sockets {
					_ = unix.Close(socket.fd)
				}
			}()

			pollFDs := make([]unix.PollFd, len(sockets))
			for i, socket := range sockets {
				pollFDs[i] = unix.PollFd{
					Fd:     int32(socket.fd),
					Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP | unix.POLLNVAL,
				}
			}

			for {
				select {
				case <-srv.stopCh:
					return
				default:
				}

				ready, err := unix.Poll(pollFDs, 2000)
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						select {
						case <-srv.stopCh:
							return
						default:
						}
						continue
					}
					srv.logIssue(fmt.Sprintf("poll: %v", err))
					return
				}
				if ready == 0 {
					if managedNetworkDHCPv4SocketsNeedReopen(config, sockets) {
						return
					}
					continue
				}

				reopen := false
				for i, pollFD := range pollFDs {
					if pollFD.Revents == 0 {
						continue
					}
					frame, err := readManagedNetworkDHCPv4Frame(sockets[i].fd)
					if err != nil {
						if errors.Is(err, unix.EINTR) {
							select {
							case <-srv.stopCh:
								return
							default:
							}
							continue
						}
						if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
							if managedNetworkDHCPv4SocketNeedsReopen(sockets[i].state) {
								reopen = true
								break
							}
							continue
						}
						if errors.Is(err, unix.EBADF) {
							select {
							case <-srv.stopCh:
								return
							default:
							}
						}
						srv.logIssue(fmt.Sprintf("read: %v", err))
						reopen = true
						break
					}

					state := sockets[i].state
					state.Config = srv.snapshot()
					srv.logSeenMessage(fmt.Sprintf("recv on %s from %s", state.IfName, frame.SrcIP.String()))
					sent, err := srv.handleMessage(state, frame)
					if err != nil {
						srv.logIssue(err.Error())
						continue
					}
					if sent {
						srv.mu.Lock()
						srv.replyTotal++
						srv.mu.Unlock()
					}
				}
				if reopen || managedNetworkDHCPv4SocketsNeedReopen(config, sockets) {
					return
				}
			}
		}()

		select {
		case <-srv.stopCh:
			return
		default:
		}
	}
}

func (srv *managedNetworkDHCPv4Server) logIssue(text string) {
	if srv == nil {
		return
	}
	now := time.Now()
	if text != srv.lastIssueText || srv.lastIssueAt.IsZero() || now.Sub(srv.lastIssueAt) >= dhcpv4TroubleLogEvery {
		srv.lastIssueText = text
		srv.lastIssueAt = now
		log.Printf("managed network dhcpv4 on %s: %s", srv.snapshot().Bridge, text)
	}
}

func (srv *managedNetworkDHCPv4Server) logSeenMessage(text string) {
	if srv == nil {
		return
	}
	now := time.Now()
	if text != srv.lastSeenText || srv.lastSeenAt.IsZero() || now.Sub(srv.lastSeenAt) >= time.Second {
		srv.lastSeenText = text
		srv.lastSeenAt = now
		log.Printf("managed network dhcpv4 on %s: %s", srv.snapshot().Bridge, text)
	}
}

func openManagedNetworkDHCPv4Sockets(config managedNetworkDHCPv4Config, stickyIfaces []string) ([]managedNetworkDHCPv4Socket, error) {
	bridgeName := strings.TrimSpace(config.Bridge)
	if bridgeName == "" {
		return nil, fmt.Errorf("bridge is required")
	}
	listenInterfaces, err := resolveManagedNetworkDHCPv4ListenInterfaces(config, stickyIfaces)
	if err != nil {
		return nil, err
	}
	bridgeIface, err := lookupManagedNetworkDHCPv4Interface(bridgeName)
	if err != nil {
		return nil, err
	}
	if len(bridgeIface.HardwareAddr) < 6 {
		return nil, fmt.Errorf("bridge %q has no usable ethernet address", bridgeName)
	}

	sockets := make([]managedNetworkDHCPv4Socket, 0, len(listenInterfaces))
	for _, interfaceName := range listenInterfaces {
		iface, fd, err := openPacketListenerSocket(interfaceName, 2*time.Second, buildManagedNetworkDHCPv4SocketFilter())
		if err != nil {
			for _, socket := range sockets {
				_ = unix.Close(socket.fd)
			}
			return nil, err
		}
		sockets = append(sockets, managedNetworkDHCPv4Socket{
			state: managedNetworkDHCPv4State{
				IfIndex:       iface.Index,
				IfName:        iface.Name,
				BridgeIfIndex: bridgeIface.Index,
				MAC:           append(net.HardwareAddr(nil), bridgeIface.HardwareAddr...),
				Config:        config,
			},
			fd: fd,
		})
	}
	return sockets, nil
}

func resolveManagedNetworkDHCPv4ListenInterfaces(config managedNetworkDHCPv4Config, stickyIfaces []string) ([]string, error) {
	bridgeName := strings.TrimSpace(config.Bridge)
	if bridgeName == "" {
		return nil, fmt.Errorf("bridge is required")
	}
	infos, err := loadManagedNetworkDHCPv4InterfaceInfos()
	if err != nil {
		infos = nil
	}
	listenInterfaces := resolveManagedNetworkDHCPv4ListenInterfacesWithInfos(config, infos, stickyIfaces, managedNetworkDHCPv4InterfaceExists)
	if len(listenInterfaces) == 0 {
		return []string{bridgeName}, nil
	}
	return listenInterfaces, nil
}

func managedNetworkDHCPv4SocketsNeedReopen(config managedNetworkDHCPv4Config, sockets []managedNetworkDHCPv4Socket) bool {
	desired, err := resolveManagedNetworkDHCPv4ListenInterfaces(config, managedNetworkDHCPv4StickyInterfacesFromSockets(sockets))
	if err != nil {
		return false
	}
	current := make([]string, 0, len(sockets))
	for _, socket := range sockets {
		if managedNetworkDHCPv4SocketNeedsReopen(socket.state) {
			return true
		}
		current = append(current, socket.state.IfName)
	}
	current = sortAndDedupeStrings(current)
	if len(current) != len(desired) {
		return true
	}
	for i := range current {
		if current[i] != desired[i] {
			return true
		}
	}
	return false
}

func buildManagedNetworkDHCPv4SocketFilter() []bpf.Instruction {
	return buildPacketSocketEqualityFilter([]packetSocketEqualityCheck{
		{Offset: packetSocketEtherTypeOffset, Size: 2, Value: 0x0800},
		{Offset: packetSocketIPv4ProtocolOffset, Size: 1, Value: ipv4ProtocolUDP},
		{Offset: packetSocketIPv4UDPSourcePortOffset, Size: 2, Value: dhcpv4ClientPort},
		{Offset: packetSocketIPv4UDPDestPortOffset, Size: 2, Value: dhcpv4ServerPort},
	})
}

func managedNetworkDHCPv4SocketNeedsReopen(state managedNetworkDHCPv4State) bool {
	if state.IfName == "" {
		return false
	}
	iface, err := lookupManagedNetworkDHCPv4Interface(state.IfName)
	if err != nil || iface == nil || iface.Index <= 0 {
		return true
	}
	if iface.Index != state.IfIndex {
		return true
	}
	bridgeName := strings.TrimSpace(state.Config.Bridge)
	if bridgeName == "" {
		return false
	}
	bridgeIface, err := lookupManagedNetworkDHCPv4Interface(bridgeName)
	if err != nil || bridgeIface == nil || bridgeIface.Index <= 0 {
		return true
	}
	if state.BridgeIfIndex > 0 && bridgeIface.Index != state.BridgeIfIndex {
		return true
	}
	return len(state.MAC) >= 6 && len(bridgeIface.HardwareAddr) >= 6 && !bytes.Equal([]byte(state.MAC), []byte(bridgeIface.HardwareAddr))
}

func loadManagedNetworkDHCPv4InterfaceInfos() ([]InterfaceInfo, error) {
	if loadInterfaceInfosForManagedNetworkDHCPv4Tests != nil {
		return loadInterfaceInfosForManagedNetworkDHCPv4Tests()
	}
	return loadInterfaceInfos()
}

func lookupManagedNetworkDHCPv4Interface(name string) (*net.Interface, error) {
	if lookupManagedNetworkDHCPv4InterfaceForTests != nil {
		return lookupManagedNetworkDHCPv4InterfaceForTests(name)
	}
	return net.InterfaceByName(name)
}

func managedNetworkDHCPv4InterfaceExists(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	iface, err := lookupManagedNetworkDHCPv4Interface(name)
	return err == nil && iface != nil && iface.Index > 0
}

func managedNetworkDHCPv4StickyInterfacesFromSockets(sockets []managedNetworkDHCPv4Socket) []string {
	if len(sockets) == 0 {
		return nil
	}
	names := make([]string, 0, len(sockets))
	for _, socket := range sockets {
		name := strings.TrimSpace(socket.state.IfName)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return managedNetworkDHCPv4FilterStickyInterfaces(names)
}

func managedNetworkDHCPv4FilterStickyInterfaces(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range sortAndDedupeStrings(names) {
		if isManagedNetworkDynamicGuestLink(name) {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resolveManagedNetworkDHCPv4ListenInterfacesWithInfos(config managedNetworkDHCPv4Config, infos []InterfaceInfo, stickyIfaces []string, exists func(string) bool) []string {
	bridgeName := strings.TrimSpace(config.Bridge)
	if bridgeName == "" {
		return nil
	}
	children := collectManagedNetworkChildInterfaces(bridgeName, config.UplinkInterface, infos)
	names := make([]string, 0, len(children)+len(stickyIfaces))
	for _, child := range children {
		name := strings.TrimSpace(child.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}

	if len(stickyIfaces) > 0 {
		ifaceByName := buildInterfaceInfoMap(infos)
		for _, name := range managedNetworkDHCPv4FilterStickyInterfaces(stickyIfaces) {
			if exists != nil && !exists(name) {
				continue
			}
			if info, ok := ifaceByName[name]; ok {
				parent := strings.TrimSpace(info.Parent)
				if parent != "" && !strings.EqualFold(parent, bridgeName) {
					continue
				}
			}
			names = append(names, name)
		}
	}

	names = sortAndDedupeStrings(names)
	if len(names) == 0 {
		return []string{bridgeName}
	}
	return names
}

func readManagedNetworkDHCPv4Frame(fd int) (managedNetworkDHCPv4Frame, error) {
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return managedNetworkDHCPv4Frame{}, err
		}
		frame, ok := parseManagedNetworkDHCPv4Frame(buf[:n])
		if ok {
			return frame, nil
		}
	}
}

func parseManagedNetworkDHCPv4Frame(frame []byte) (managedNetworkDHCPv4Frame, bool) {
	if len(frame) < 14+20+8+240 {
		return managedNetworkDHCPv4Frame{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return managedNetworkDHCPv4Frame{}, false
	}
	ipHeader := frame[14:]
	if version := ipHeader[0] >> 4; version != 4 {
		return managedNetworkDHCPv4Frame{}, false
	}
	ihl := int(ipHeader[0]&0x0f) * 4
	if ihl < 20 || len(ipHeader) < ihl+8 {
		return managedNetworkDHCPv4Frame{}, false
	}
	if ipHeader[9] != ipv4ProtocolUDP {
		return managedNetworkDHCPv4Frame{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(ipHeader[2:4]))
	if totalLen < ihl+8 || totalLen > len(ipHeader) {
		return managedNetworkDHCPv4Frame{}, false
	}
	udp := ipHeader[ihl:totalLen]
	if binary.BigEndian.Uint16(udp[0:2]) != dhcpv4ClientPort || binary.BigEndian.Uint16(udp[2:4]) != dhcpv4ServerPort {
		return managedNetworkDHCPv4Frame{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return managedNetworkDHCPv4Frame{}, false
	}
	srcIP := net.IP(append([]byte(nil), ipHeader[12:16]...))
	dstIP := net.IP(append([]byte(nil), ipHeader[16:20]...))
	return managedNetworkDHCPv4Frame{
		SrcMAC:  append(net.HardwareAddr(nil), frame[6:12]...),
		SrcIP:   srcIP,
		DstIP:   dstIP,
		Payload: append([]byte(nil), udp[8:udpLen]...),
	}, true
}

func (srv *managedNetworkDHCPv4Server) handleMessage(state managedNetworkDHCPv4State, frame managedNetworkDHCPv4Frame) (bool, error) {
	msg, err := parseManagedNetworkDHCPv4Message(frame.Payload)
	if err != nil {
		return false, err
	}
	if msg.HType != dhcpv4HWTypeEthernet || msg.HLen < 6 || len(msg.CHAddr) < 6 {
		return false, nil
	}
	if msg.GIAddr != nil && !msg.GIAddr.Equal(net.IPv4zero) {
		return false, nil
	}

	var (
		responseType byte
		leaseIP      string
	)
	switch msg.MessageType {
	case dhcpv4MessageDiscover:
		leaseIP, err = srv.offerLease(state.Config, msg)
		if err != nil {
			return false, err
		}
		responseType = dhcpv4MessageOffer
	case dhcpv4MessageRequest:
		serverID := canonicalIPLiteral(msg.ServerID)
		if serverID != "" && serverID != strings.TrimSpace(state.Config.ServerIP) {
			return false, nil
		}
		leaseIP, err = srv.ackLease(state.Config, msg)
		if err != nil {
			if errors.Is(err, errDHCPv4NAK) {
				responseType = dhcpv4MessageNak
				break
			}
			return false, err
		}
		responseType = dhcpv4MessageAck
	case dhcpv4MessageRelease, dhcpv4MessageDecline:
		srv.releaseLease(msg)
		return false, nil
	default:
		return false, nil
	}

	reply, err := buildManagedNetworkDHCPv4Reply(state.Config, msg, responseType, leaseIP)
	if err != nil {
		return false, err
	}
	dstIP, dstMAC := managedNetworkDHCPv4ReplyDestination(msg, frame, responseType, leaseIP)
	if err := writeManagedNetworkDHCPv4Reply(state, dstIP, dstMAC, reply); err != nil {
		return false, err
	}
	srv.mu.Lock()
	srv.lastReplyAt = time.Now()
	srv.mu.Unlock()
	return true, nil
}

func (srv *managedNetworkDHCPv4Server) snapshotStatus() managedNetworkDHCPv4RuntimeState {
	if srv == nil {
		return managedNetworkDHCPv4RuntimeState{}
	}

	srv.mu.Lock()
	replyCount := srv.replyTotal
	lastSeenAt := srv.lastSeenAt
	lastReplyAt := srv.lastReplyAt
	lastIssueText := srv.lastIssueText
	lastIssueAt := srv.lastIssueAt
	listeningSince := srv.listeningSince
	listening := len(srv.currentFDs) > 0
	srv.mu.Unlock()

	healthyAt := listeningSince
	if lastSeenAt.After(healthyAt) {
		healthyAt = lastSeenAt
	}
	if lastReplyAt.After(healthyAt) {
		healthyAt = lastReplyAt
	}

	state := managedNetworkDHCPv4RuntimeState{ReplyCount: replyCount}
	switch {
	case lastIssueText != "" && lastIssueAt.After(healthyAt):
		state.Status = "error"
		state.Detail = lastIssueText
	case listening:
		state.Status = "running"
		state.Detail = fmt.Sprintf("listening for dhcpv4 (replies=%d)", replyCount)
	default:
		state.Status = "draining"
		state.Detail = "waiting for dhcpv4 listener"
	}
	return state
}

func parseManagedNetworkDHCPv4Message(packet []byte) (parsedManagedNetworkDHCPv4Message, error) {
	if len(packet) < 240 {
		return parsedManagedNetworkDHCPv4Message{}, fmt.Errorf("short dhcpv4 message")
	}
	msg := parsedManagedNetworkDHCPv4Message{
		Op:        packet[0],
		HType:     packet[1],
		HLen:      packet[2],
		XID:       binary.BigEndian.Uint32(packet[4:8]),
		Flags:     binary.BigEndian.Uint16(packet[10:12]),
		CIAddr:    net.IP(append([]byte(nil), packet[12:16]...)),
		YIAddr:    net.IP(append([]byte(nil), packet[16:20]...)),
		SIAddr:    net.IP(append([]byte(nil), packet[20:24]...)),
		GIAddr:    net.IP(append([]byte(nil), packet[24:28]...)),
		RawPacket: append([]byte(nil), packet...),
	}
	hlen := int(msg.HLen)
	if hlen > 16 {
		hlen = 16
	}
	if hlen > 0 {
		msg.CHAddr = append(net.HardwareAddr(nil), packet[28:28+hlen]...)
	}
	if binary.BigEndian.Uint32(packet[236:240]) != dhcpv4MagicCookie {
		return parsedManagedNetworkDHCPv4Message{}, fmt.Errorf("missing dhcpv4 magic cookie")
	}
	options := packet[240:]
	for len(options) > 0 {
		code := options[0]
		options = options[1:]
		if code == 0 {
			continue
		}
		if code == dhcpv4OptionEnd {
			break
		}
		if len(options) < 1 {
			return parsedManagedNetworkDHCPv4Message{}, fmt.Errorf("invalid dhcpv4 option length")
		}
		length := int(options[0])
		options = options[1:]
		if length > len(options) {
			return parsedManagedNetworkDHCPv4Message{}, fmt.Errorf("invalid dhcpv4 option length")
		}
		value := append([]byte(nil), options[:length]...)
		options = options[length:]
		switch code {
		case dhcpv4OptionMessageType:
			if len(value) >= 1 {
				msg.MessageType = value[0]
			}
		case dhcpv4OptionRequestedIP:
			if len(value) == 4 {
				msg.RequestedIP = net.IP(append([]byte(nil), value...))
			}
		case dhcpv4OptionServerID:
			if len(value) == 4 {
				msg.ServerID = net.IP(append([]byte(nil), value...))
			}
		case dhcpv4OptionClientID:
			msg.ClientID = value
		}
	}
	return msg, nil
}

func buildManagedNetworkDHCPv4Reply(config managedNetworkDHCPv4Config, msg parsedManagedNetworkDHCPv4Message, responseType byte, leaseIP string) ([]byte, error) {
	serverIP := parseIPLiteral(config.ServerIP).To4()
	if serverIP == nil {
		return nil, fmt.Errorf("invalid dhcpv4 server ip %q", config.ServerIP)
	}
	var yiaddr net.IP
	if responseType == dhcpv4MessageOffer || responseType == dhcpv4MessageAck {
		yiaddr = parseIPLiteral(leaseIP).To4()
		if yiaddr == nil {
			return nil, fmt.Errorf("invalid dhcpv4 lease ip %q", leaseIP)
		}
	}
	out := make([]byte, 240)
	out[0] = dhcpv4BootReply
	out[1] = dhcpv4HWTypeEthernet
	out[2] = 6
	binary.BigEndian.PutUint32(out[4:8], msg.XID)
	binary.BigEndian.PutUint16(out[10:12], msg.Flags)
	if yiaddr != nil {
		copy(out[16:20], yiaddr)
	}
	copy(out[20:24], serverIP)
	copy(out[28:28+len(msg.CHAddr)], msg.CHAddr)
	binary.BigEndian.PutUint32(out[236:240], dhcpv4MagicCookie)

	out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionMessageType, []byte{responseType})...)
	out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionServerID, serverIP)...)
	if responseType != dhcpv4MessageNak {
		mask := parseManagedNetworkIPv4Mask(config.ServerCIDR)
		if len(mask) == 4 {
			out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionSubnetMask, mask)...)
		}
		router := parseIPLiteral(config.Gateway).To4()
		if router != nil {
			out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionRouter, router)...)
		}
		if len(config.DNSServers) > 0 {
			dns := make([]byte, 0, len(config.DNSServers)*4)
			for _, item := range config.DNSServers {
				if ip := parseIPLiteral(item).To4(); ip != nil {
					dns = append(dns, ip...)
				}
			}
			if len(dns) > 0 {
				out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionDNS, dns)...)
			}
		}
		leaseSeconds := make([]byte, 4)
		binary.BigEndian.PutUint32(leaseSeconds, uint32(dhcpv4LeaseTime/time.Second))
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionLeaseTime, leaseSeconds)...)
		renewSeconds := make([]byte, 4)
		binary.BigEndian.PutUint32(renewSeconds, uint32(dhcpv4RenewTime/time.Second))
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionRenewalTime, renewSeconds)...)
		rebindSeconds := make([]byte, 4)
		binary.BigEndian.PutUint32(rebindSeconds, uint32(dhcpv4RebindTime/time.Second))
		out = append(out, buildManagedNetworkDHCPv4Option(dhcpv4OptionRebindingTime, rebindSeconds)...)
	}
	out = append(out, dhcpv4OptionEnd)
	if len(out) < dhcpv4MinMessageSize {
		out = append(out, make([]byte, dhcpv4MinMessageSize-len(out))...)
	}
	return out, nil
}

func buildManagedNetworkDHCPv4Option(code byte, value []byte) []byte {
	out := make([]byte, 2+len(value))
	out[0] = code
	out[1] = byte(len(value))
	copy(out[2:], value)
	return out
}

func parseManagedNetworkIPv4Mask(cidr string) []byte {
	_, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || len(prefix.Mask) != 4 {
		return nil
	}
	return append([]byte(nil), prefix.Mask...)
}

func managedNetworkDHCPv4ReplyDestination(msg parsedManagedNetworkDHCPv4Message, frame managedNetworkDHCPv4Frame, responseType byte, leaseIP string) (net.IP, net.HardwareAddr) {
	if responseType == dhcpv4MessageNak || responseType == dhcpv4MessageOffer {
		return append(net.IP(nil), dhcpv4BroadcastIP...), append(net.HardwareAddr(nil), dhcpv4BroadcastMAC...)
	}
	if msg.Flags&0x8000 != 0 {
		return append(net.IP(nil), dhcpv4BroadcastIP...), append(net.HardwareAddr(nil), dhcpv4BroadcastMAC...)
	}
	if ciaddr := msg.CIAddr.To4(); ciaddr != nil && !ciaddr.Equal(net.IPv4zero) && len(msg.CHAddr) >= 6 {
		return append(net.IP(nil), ciaddr...), append(net.HardwareAddr(nil), msg.CHAddr...)
	}
	if lease := parseIPLiteral(leaseIP).To4(); lease != nil && len(msg.CHAddr) >= 6 {
		return append(net.IP(nil), dhcpv4BroadcastIP...), append(net.HardwareAddr(nil), dhcpv4BroadcastMAC...)
	}
	if len(frame.SrcMAC) >= 6 {
		return append(net.IP(nil), dhcpv4BroadcastIP...), append(net.HardwareAddr(nil), dhcpv4BroadcastMAC...)
	}
	return append(net.IP(nil), dhcpv4BroadcastIP...), append(net.HardwareAddr(nil), dhcpv4BroadcastMAC...)
}

func writeManagedNetworkDHCPv4Reply(state managedNetworkDHCPv4State, dstIP net.IP, dstMAC net.HardwareAddr, payload []byte) error {
	frame, err := buildManagedNetworkDHCPv4ReplyFrame(state, dstIP, dstMAC, payload)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IP)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], dstMAC[:6])
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  managedNetworkDHCPv4ReplyIfIndex(state),
		Protocol: htonsUnix(unix.ETH_P_IP),
		Halen:    6,
		Addr:     addr,
	})
}

func managedNetworkDHCPv4ReplyIfIndex(state managedNetworkDHCPv4State) int {
	if state.IfIndex > 0 {
		return state.IfIndex
	}
	return state.BridgeIfIndex
}

func buildManagedNetworkDHCPv4ReplyFrame(state managedNetworkDHCPv4State, dstIP net.IP, dstMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	if len(state.MAC) < 6 {
		return nil, fmt.Errorf("interface %q has no usable ethernet address", state.IfName)
	}
	if len(dstMAC) < 6 {
		return nil, fmt.Errorf("invalid dhcpv4 destination mac")
	}
	srcIP := parseIPLiteral(state.Config.ServerIP).To4()
	if srcIP == nil {
		return nil, fmt.Errorf("invalid dhcpv4 server ip %q", state.Config.ServerIP)
	}
	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return nil, fmt.Errorf("invalid dhcpv4 destination ip %q", dstIP.String())
	}
	udpLen := 8 + len(payload)
	if udpLen > 0xffff {
		return nil, fmt.Errorf("dhcpv4 payload too large: %d", len(payload))
	}
	totalLen := 20 + udpLen
	frame := make([]byte, 14+totalLen)
	copy(frame[0:6], dstMAC[:6])
	copy(frame[6:12], state.MAC[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ipHeader := frame[14 : 14+20]
	ipHeader[0] = 0x45
	ipHeader[8] = 64
	ipHeader[9] = ipv4ProtocolUDP
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	copy(ipHeader[12:16], srcIP)
	copy(ipHeader[16:20], dstIP4)
	binary.BigEndian.PutUint16(ipHeader[10:12], managedNetworkDHCPv4Checksum(ipHeader))

	udp := frame[14+20:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv4ServerPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv4ClientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], managedNetworkDHCPv4UDPChecksum(srcIP, dstIP4, udp))
	return frame, nil
}

func managedNetworkDHCPv4Checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func managedNetworkDHCPv4UDPChecksum(srcIP net.IP, dstIP net.IP, udp []byte) uint16 {
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}
	buf := make([]byte, 0, 12+len(udp))
	buf = append(buf, src...)
	buf = append(buf, dst...)
	buf = append(buf, 0, ipv4ProtocolUDP)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(udp)))
	buf = append(buf, length...)
	buf = append(buf, udp...)
	checksum := managedNetworkDHCPv4Checksum(buf)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func (srv *managedNetworkDHCPv4Server) offerLease(config managedNetworkDHCPv4Config, msg parsedManagedNetworkDHCPv4Message) (string, error) {
	return srv.allocateLease(config, msg, false)
}

func (srv *managedNetworkDHCPv4Server) ackLease(config managedNetworkDHCPv4Config, msg parsedManagedNetworkDHCPv4Message) (string, error) {
	return srv.allocateLease(config, msg, true)
}

func (srv *managedNetworkDHCPv4Server) allocateLease(config managedNetworkDHCPv4Config, msg parsedManagedNetworkDHCPv4Message, strict bool) (string, error) {
	clientKey := managedNetworkDHCPv4ClientKey(msg)
	if clientKey == "" {
		return "", fmt.Errorf("missing dhcpv4 client identity")
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	now := time.Now()
	srv.cleanupExpiredLeasesLocked(now)

	start := managedNetworkIPv4LiteralToUint32(config.PoolStart)
	end := managedNetworkIPv4LiteralToUint32(config.PoolEnd)
	if start == 0 || end == 0 || start > end {
		return "", fmt.Errorf("invalid dhcpv4 pool")
	}
	reservedIP := managedNetworkDHCPv4ReservedIP(config, msg)
	if reservedIP != "" {
		requested := managedNetworkDHCPv4RequestedIP(msg)
		if strict && requested != "" && requested != reservedIP {
			return "", errDHCPv4NAK
		}
		srv.storeLeaseLocked(clientKey, reservedIP, now)
		return reservedIP, nil
	}
	if lease, ok := srv.leases[clientKey]; ok && lease.IP != "" {
		if ip := parseIPLiteral(lease.IP).To4(); ip != nil {
			value := managedNetworkIPv4ToUint32(ip)
			if value >= start && value <= end && !managedNetworkDHCPv4IPReserved(config, lease.IP) {
				srv.storeLeaseLocked(clientKey, lease.IP, now)
				if strict {
					requested := managedNetworkDHCPv4RequestedIP(msg)
					if requested != "" && requested != lease.IP {
						if managedNetworkDHCPv4IPReserved(config, requested) {
							return "", errDHCPv4NAK
						}
						if owner := srv.ipOwners[requested]; owner != "" && owner != clientKey {
							return "", errDHCPv4NAK
						}
						if requestedValue := managedNetworkIPv4LiteralToUint32(requested); requestedValue < start || requestedValue > end {
							return "", errDHCPv4NAK
						}
						srv.storeLeaseLocked(clientKey, requested, now)
					}
				}
				return srv.leases[clientKey].IP, nil
			}
		}
		srv.deleteLeaseLocked(clientKey)
	}

	requested := managedNetworkDHCPv4RequestedIP(msg)
	if strict && requested != "" {
		requestedValue := managedNetworkIPv4LiteralToUint32(requested)
		if requestedValue < start || requestedValue > end {
			return "", errDHCPv4NAK
		}
		if managedNetworkDHCPv4IPReserved(config, requested) {
			return "", errDHCPv4NAK
		}
		if owner := srv.ipOwners[requested]; owner != "" && owner != clientKey {
			return "", errDHCPv4NAK
		}
		srv.storeLeaseLocked(clientKey, requested, now)
		return requested, nil
	}

	if !strict && requested != "" {
		requestedValue := managedNetworkIPv4LiteralToUint32(requested)
		if requestedValue >= start && requestedValue <= end {
			if !managedNetworkDHCPv4IPReserved(config, requested) {
				if owner := srv.ipOwners[requested]; owner == "" || owner == clientKey {
					srv.storeLeaseLocked(clientKey, requested, now)
					return requested, nil
				}
			}
		}
	}

	size := end - start + 1
	startOffset := managedNetworkDHCPv4LeaseOffset(clientKey, size)
	for probe := uint32(0); probe < size; probe++ {
		value := start + ((startOffset + probe) % size)
		ip := uint32ToIPv4(value).String()
		if managedNetworkDHCPv4IPReserved(config, ip) {
			continue
		}
		owner := srv.ipOwners[ip]
		if owner != "" && owner != clientKey {
			continue
		}
		srv.storeLeaseLocked(clientKey, ip, now)
		return ip, nil
	}
	if strict {
		return "", errDHCPv4NAK
	}
	return "", fmt.Errorf("dhcpv4 pool is exhausted")
}

func (srv *managedNetworkDHCPv4Server) storeLeaseLocked(clientKey string, ip string, now time.Time) {
	if clientKey == "" || strings.TrimSpace(ip) == "" {
		return
	}
	if current, ok := srv.leases[clientKey]; ok && current.IP != "" && current.IP != ip && srv.ipOwners[current.IP] == clientKey {
		delete(srv.ipOwners, current.IP)
	}
	if owner := srv.ipOwners[ip]; owner != "" && owner != clientKey {
		delete(srv.leases, owner)
		delete(srv.ipOwners, ip)
	}
	srv.leases[clientKey] = managedNetworkDHCPv4Lease{
		ClientKey: clientKey,
		IP:        ip,
		ExpiresAt: now.Add(dhcpv4LeaseTime),
	}
	srv.ipOwners[ip] = clientKey
}

func (srv *managedNetworkDHCPv4Server) deleteLeaseLocked(clientKey string) {
	lease, ok := srv.leases[clientKey]
	if !ok {
		return
	}
	delete(srv.leases, clientKey)
	if srv.ipOwners[lease.IP] == clientKey {
		delete(srv.ipOwners, lease.IP)
	}
}

func managedNetworkDHCPv4ReservedIP(config managedNetworkDHCPv4Config, msg parsedManagedNetworkDHCPv4Message) string {
	macAddress := managedNetworkDHCPv4ClientMAC(msg)
	if macAddress == "" {
		return ""
	}
	for _, item := range config.Reservations {
		if strings.EqualFold(strings.TrimSpace(item.MACAddress), macAddress) {
			return strings.TrimSpace(item.IPv4Address)
		}
	}
	return ""
}

func managedNetworkDHCPv4IPReserved(config managedNetworkDHCPv4Config, ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	for _, item := range config.Reservations {
		if strings.TrimSpace(item.IPv4Address) == ip {
			return true
		}
	}
	return false
}

func managedNetworkDHCPv4ClientMAC(msg parsedManagedNetworkDHCPv4Message) string {
	if len(msg.CHAddr) < 6 {
		return ""
	}
	return strings.ToLower(msg.CHAddr.String())
}

func (srv *managedNetworkDHCPv4Server) releaseLease(msg parsedManagedNetworkDHCPv4Message) {
	clientKey := managedNetworkDHCPv4ClientKey(msg)
	if clientKey == "" {
		return
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.deleteLeaseLocked(clientKey)
}

func (srv *managedNetworkDHCPv4Server) cleanupExpiredLeasesLocked(now time.Time) {
	for clientKey, lease := range srv.leases {
		if lease.ExpiresAt.IsZero() || now.Before(lease.ExpiresAt) {
			continue
		}
		delete(srv.leases, clientKey)
		if srv.ipOwners[lease.IP] == clientKey {
			delete(srv.ipOwners, lease.IP)
		}
	}
}

func managedNetworkDHCPv4ClientKey(msg parsedManagedNetworkDHCPv4Message) string {
	if len(msg.ClientID) > 0 {
		return "id:" + string(msg.ClientID)
	}
	if len(msg.CHAddr) >= 6 {
		return "mac:" + strings.ToLower(msg.CHAddr.String())
	}
	return ""
}

func managedNetworkDHCPv4RequestedIP(msg parsedManagedNetworkDHCPv4Message) string {
	if ip := msg.RequestedIP.To4(); ip != nil && !ip.Equal(net.IPv4zero) {
		return ip.String()
	}
	if ip := msg.CIAddr.To4(); ip != nil && !ip.Equal(net.IPv4zero) {
		return ip.String()
	}
	return ""
}

func managedNetworkDHCPv4LeaseOffset(clientKey string, size uint32) uint32 {
	if size == 0 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(clientKey))
	return h.Sum32() % size
}
