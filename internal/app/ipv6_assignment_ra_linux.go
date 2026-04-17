//go:build linux

package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	ipv6RAHopLimit            = 255
	ipv6RACurHopLimit         = 64
	ipv6RARouterLifetime      = 1800 * time.Second
	ipv6RAValidLifetime       = 24 * time.Hour
	ipv6RAPreferredLifetime   = 4 * time.Hour
	ipv6RAAdvertisementPeriod = 30 * time.Second
	ipv6RATroubleLogEvery     = 5 * time.Minute
	ipv6NextHeaderICMPv6      = 58
	icmpv6TypeRouterSolicit   = 133
)

var ipv6AllNodesLinkLocal = net.ParseIP("ff02::1")

type ipv6RouterAdvertiser struct {
	mu               sync.Mutex
	config           ipv6AssignmentRAConfig
	stopCh           chan struct{}
	wakeCh           chan struct{}
	doneCh           chan struct{}
	rsDoneCh         chan struct{}
	currentRSFD      int
	rsListeningSince time.Time
	lastIssueText    string
	lastIssueAt      time.Time
	lastRSIssue      string
	lastRSIssueAt    time.Time
	lastRSSeenAt     time.Time
	sendCount        uint64
	lastSendAt       time.Time
}

func newIPv6RouterAdvertiser(config ipv6AssignmentRAConfig) *ipv6RouterAdvertiser {
	return &ipv6RouterAdvertiser{
		config:      config,
		stopCh:      make(chan struct{}),
		wakeCh:      make(chan struct{}, 1),
		doneCh:      make(chan struct{}),
		rsDoneCh:    make(chan struct{}),
		currentRSFD: -1,
	}
}

func (adv *ipv6RouterAdvertiser) start() {
	go adv.run()
	go adv.listenForRouterSolicitations()
}

func (adv *ipv6RouterAdvertiser) update(config ipv6AssignmentRAConfig) {
	if adv == nil {
		return
	}
	adv.mu.Lock()
	adv.config = config
	adv.mu.Unlock()
	adv.trigger()
}

func (adv *ipv6RouterAdvertiser) trigger() {
	if adv == nil {
		return
	}
	select {
	case adv.wakeCh <- struct{}{}:
	default:
	}
}

func (adv *ipv6RouterAdvertiser) stop() {
	if adv == nil {
		return
	}
	close(adv.stopCh)
	adv.mu.Lock()
	currentRSFD := adv.currentRSFD
	adv.currentRSFD = -1
	adv.mu.Unlock()
	if currentRSFD >= 0 {
		_ = unix.Close(currentRSFD)
	}
	<-adv.doneCh
	<-adv.rsDoneCh
}

func (adv *ipv6RouterAdvertiser) snapshot() ipv6AssignmentRAConfig {
	adv.mu.Lock()
	defer adv.mu.Unlock()
	return ipv6AssignmentRAConfig{
		TargetInterface: adv.config.TargetInterface,
		Managed:         adv.config.Managed,
		Prefixes:        append([]string(nil), adv.config.Prefixes...),
		Routes:          append([]string(nil), adv.config.Routes...),
	}
}

func (adv *ipv6RouterAdvertiser) run() {
	defer close(adv.doneCh)

	ticker := time.NewTicker(ipv6RAAdvertisementPeriod)
	defer ticker.Stop()

	adv.send()
	for {
		select {
		case <-adv.stopCh:
			return
		case <-adv.wakeCh:
			adv.send()
		case <-ticker.C:
			adv.send()
		}
	}
}

func (adv *ipv6RouterAdvertiser) listenForRouterSolicitations() {
	defer close(adv.rsDoneCh)

	buf := make([]byte, 2048)
	for {
		config := adv.snapshot()
		state, fd, err := openIPv6RouterSolicitationSocket(config)
		if err != nil {
			adv.logRouterSolicitationIssue(fmt.Sprintf("open socket: %v", err))
			select {
			case <-adv.stopCh:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		func() {
			adv.mu.Lock()
			adv.currentRSFD = fd
			adv.rsListeningSince = time.Now()
			adv.lastRSIssue = ""
			adv.lastRSIssueAt = time.Time{}
			adv.mu.Unlock()
			defer unix.Close(fd)
			defer func() {
				adv.mu.Lock()
				if adv.currentRSFD == fd {
					adv.currentRSFD = -1
				}
				adv.mu.Unlock()
			}()
			for {
				select {
				case <-adv.stopCh:
					return
				default:
				}

				n, _, err := unix.Recvfrom(fd, buf, 0)
				if err != nil {
					if errors.Is(err, unix.EINTR) {
						select {
						case <-adv.stopCh:
							return
						default:
						}
						continue
					}
					if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
						if routerSolicitationSocketNeedsReopen(state) {
							return
						}
						continue
					}
					adv.logRouterSolicitationIssue(fmt.Sprintf("read: %v", err))
					return
				}
				if isIPv6RouterSolicitationFrame(buf[:n]) {
					now := time.Now()
					if adv.lastRSSeenAt.IsZero() || now.Sub(adv.lastRSSeenAt) >= time.Second {
						adv.lastRSSeenAt = now
						log.Printf("ipv6 assignment router solicitation received on %s", state.IfName)
					}
					adv.mu.Lock()
					adv.lastRSIssue = ""
					adv.lastRSIssueAt = time.Time{}
					adv.mu.Unlock()
					adv.trigger()
				}
			}
		}()
		select {
		case <-adv.stopCh:
			return
		default:
		}
	}
}

func (adv *ipv6RouterAdvertiser) logRouterSolicitationIssue(text string) {
	if adv == nil {
		return
	}
	now := time.Now()
	if text != adv.lastRSIssue || adv.lastRSIssueAt.IsZero() || now.Sub(adv.lastRSIssueAt) >= ipv6RATroubleLogEvery {
		adv.lastRSIssue = text
		adv.lastRSIssueAt = now
		log.Printf("ipv6 assignment router solicitation listener on %s: %s", adv.snapshot().TargetInterface, text)
	}
}

func (adv *ipv6RouterAdvertiser) send() {
	config := adv.snapshot()
	if err := sendIPv6RouterAdvertisement(config); err != nil {
		now := time.Now()
		text := err.Error()
		if text != adv.lastIssueText || adv.lastIssueAt.IsZero() || now.Sub(adv.lastIssueAt) >= ipv6RATroubleLogEvery {
			adv.lastIssueText = text
			adv.lastIssueAt = now
			log.Printf("ipv6 assignment router advertisement on %s: %v", config.TargetInterface, err)
		}
		return
	}
	adv.lastIssueText = ""
	adv.lastIssueAt = time.Time{}
	adv.mu.Lock()
	adv.sendCount++
	adv.lastSendAt = time.Now()
	adv.mu.Unlock()
}

type ipv6RouterAdvertisementRuntimeState struct {
	Status    string
	Detail    string
	SendCount uint64
}

func (adv *ipv6RouterAdvertiser) snapshotStatus() ipv6RouterAdvertisementRuntimeState {
	if adv == nil {
		return ipv6RouterAdvertisementRuntimeState{}
	}

	adv.mu.Lock()
	sendCount := adv.sendCount
	lastSendAt := adv.lastSendAt
	lastIssueText := adv.lastIssueText
	lastIssueAt := adv.lastIssueAt
	lastRSIssue := adv.lastRSIssue
	lastRSIssueAt := adv.lastRSIssueAt
	lastRSSeenAt := adv.lastRSSeenAt
	listening := adv.currentRSFD >= 0
	rsListeningSince := adv.rsListeningSince
	adv.mu.Unlock()

	sendHealthyAt := lastSendAt
	rsHealthyAt := rsListeningSince
	if lastRSSeenAt.After(rsHealthyAt) {
		rsHealthyAt = lastRSSeenAt
	}

	state := ipv6RouterAdvertisementRuntimeState{SendCount: sendCount}
	switch {
	case lastIssueText != "" && lastIssueAt.After(sendHealthyAt):
		state.Status = "error"
		state.Detail = lastIssueText
	case lastRSIssue != "" && lastRSIssueAt.After(rsHealthyAt):
		state.Status = "draining"
		state.Detail = "router solicitation listener: " + lastRSIssue
	case listening || !lastSendAt.IsZero():
		state.Status = "running"
		state.Detail = fmt.Sprintf("router advertisements active (sent=%d)", sendCount)
	default:
		state.Status = "draining"
		state.Detail = "waiting for router advertisement runtime"
	}
	return state
}

type ipv6RouterSolicitationState struct {
	IfIndex int
	IfName  string
}

type ipv6RouterAdvertisementState struct {
	IfIndex int
	IfName  string
	MTU     int
	MAC     net.HardwareAddr
	SrcIP   net.IP
	DstIP   net.IP
	Config  ipv6AssignmentRAConfig
}

func resolveIPv6RouterAdvertisementState(config ipv6AssignmentRAConfig) (ipv6RouterAdvertisementState, error) {
	iface, err := net.InterfaceByName(config.TargetInterface)
	if err != nil {
		return ipv6RouterAdvertisementState{}, err
	}
	if iface == nil || iface.Index <= 0 {
		return ipv6RouterAdvertisementState{}, fmt.Errorf("interface %q is unavailable", config.TargetInterface)
	}
	identity, err := resolveIPv6ControlIdentity(config.TargetInterface)
	if err != nil {
		return ipv6RouterAdvertisementState{}, err
	}
	return ipv6RouterAdvertisementState{
		IfIndex: iface.Index,
		IfName:  iface.Name,
		MTU:     iface.MTU,
		MAC:     append(net.HardwareAddr(nil), identity.SourceMAC...),
		SrcIP:   append(net.IP(nil), identity.SourceIP...),
		DstIP:   append(net.IP(nil), ipv6AllNodesLinkLocal.To16()...),
		Config: ipv6AssignmentRAConfig{
			TargetInterface: config.TargetInterface,
			Managed:         config.Managed,
			Prefixes:        append([]string(nil), config.Prefixes...),
			Routes:          append([]string(nil), config.Routes...),
		},
	}, nil
}

func selectIPv6LinkLocalAddress(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, raw := range addrs {
		ipNet, ok := raw.(*net.IPNet)
		if !ok || ipNet == nil {
			continue
		}
		ip := ipNet.IP.To16()
		if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
			continue
		}
		return append(net.IP(nil), ip...), nil
	}
	return nil, fmt.Errorf("interface %q has no IPv6 link-local address yet", iface.Name)
}

func openIPv6RouterSolicitationSocket(config ipv6AssignmentRAConfig) (ipv6RouterSolicitationState, int, error) {
	iface, fd, err := openIPv6PacketListenerSocket(config.TargetInterface, 2*time.Second, buildIPv6RouterSolicitationSocketFilter())
	if err != nil {
		return ipv6RouterSolicitationState{}, -1, err
	}
	return ipv6RouterSolicitationState{
		IfIndex: iface.Index,
		IfName:  iface.Name,
	}, fd, nil
}

func buildIPv6RouterSolicitationSocketFilter() []bpf.Instruction {
	return buildPacketSocketEqualityFilter([]packetSocketEqualityCheck{
		{Offset: packetSocketEtherTypeOffset, Size: 2, Value: 0x86dd},
		{Offset: packetSocketIPv6NextHeaderOffset, Size: 1, Value: ipv6NextHeaderICMPv6},
		{Offset: packetSocketIPv6HopLimitOffset, Size: 1, Value: ipv6RAHopLimit},
		{Offset: packetSocketIPv6ICMPTypeOffset, Size: 1, Value: icmpv6TypeRouterSolicit},
	})
}

func routerSolicitationSocketNeedsReopen(state ipv6RouterSolicitationState) bool {
	if state.IfName == "" {
		return false
	}
	iface, err := net.InterfaceByName(state.IfName)
	if err != nil || iface == nil || iface.Index <= 0 {
		return true
	}
	return iface.Index != state.IfIndex
}

func isIPv6RouterSolicitationFrame(frame []byte) bool {
	if len(frame) < 14+40+8 {
		return false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86dd {
		return false
	}
	ipv6Header := frame[14:]
	if version := ipv6Header[0] >> 4; version != 6 {
		return false
	}
	if ipv6Header[6] != ipv6NextHeaderICMPv6 {
		return false
	}
	if ipv6Header[7] != ipv6RAHopLimit {
		return false
	}
	icmp := ipv6Header[40:]
	return len(icmp) >= 8 && icmp[0] == icmpv6TypeRouterSolicit && icmp[1] == 0
}

func sendIPv6RouterAdvertisement(config ipv6AssignmentRAConfig) error {
	state, err := resolveIPv6RouterAdvertisementState(config)
	if err != nil {
		return err
	}
	payload, err := buildIPv6RouterAdvertisementPayload(state)
	if err != nil {
		return err
	}
	frame, err := buildIPv6RouterAdvertisementFrame(state, payload)
	if err != nil {
		return err
	}
	return sendIPv6RouterAdvertisementFrame(state, frame)
}

func buildIPv6RouterAdvertisementPayload(state ipv6RouterAdvertisementState) ([]byte, error) {
	body := make([]byte, 12)
	body[0] = ipv6RACurHopLimit
	if state.Config.Managed {
		body[1] |= 0x80
	}
	binary.BigEndian.PutUint16(body[2:4], uint16(ipv6RARouterLifetime/time.Second))
	for _, prefixText := range state.Config.Prefixes {
		_, prefix, err := net.ParseCIDR(prefixText)
		if err != nil || prefix == nil {
			return nil, fmt.Errorf("invalid router advertisement prefix %q", prefixText)
		}
		ones, bits := prefix.Mask.Size()
		if ones != 64 || bits != 128 {
			return nil, fmt.Errorf("router advertisements require /64 prefixes, got %q", prefixText)
		}
		body = append(body, buildIPv6PrefixInfoOption(prefix, ipv6RAValidLifetime, ipv6RAPreferredLifetime)...)
	}
	for _, routeText := range state.Config.Routes {
		_, route, err := net.ParseCIDR(routeText)
		if err != nil || route == nil {
			return nil, fmt.Errorf("invalid router advertisement route %q", routeText)
		}
		body = append(body, buildIPv6RouteInfoOption(route, ipv6RARouterLifetime)...)
	}
	if len(state.MAC) >= 6 {
		body = append(body, buildIPv6SourceLLAOption(state.MAC)...)
	}
	if state.MTU > 0 {
		body = append(body, buildIPv6MTUOption(state.MTU)...)
	}
	return (&icmp.Message{
		Type: ipv6.ICMPTypeRouterAdvertisement,
		Code: 0,
		Body: &icmp.RawBody{Data: body},
	}).Marshal(icmp.IPv6PseudoHeader(state.SrcIP, state.DstIP))
}

func buildIPv6RouterAdvertisementFrame(state ipv6RouterAdvertisementState, payload []byte) ([]byte, error) {
	if len(state.MAC) < 6 {
		return nil, fmt.Errorf("interface %q has no usable ethernet address", state.IfName)
	}
	if len(payload) > 0xffff {
		return nil, fmt.Errorf("router advertisement payload too large: %d", len(payload))
	}

	frame := make([]byte, 14+40+len(payload))
	copy(frame[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	copy(frame[6:12], state.MAC[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14 : 14+40]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(len(payload)))
	ipv6Header[6] = 58
	ipv6Header[7] = ipv6RAHopLimit
	copy(ipv6Header[8:24], state.SrcIP.To16())
	copy(ipv6Header[24:40], state.DstIP.To16())

	copy(frame[14+40:], payload)
	return frame, nil
}

func sendIPv6RouterAdvertisementFrame(state ipv6RouterAdvertisementState, frame []byte) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IPV6)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01})
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  state.IfIndex,
		Protocol: htonsUnix(unix.ETH_P_IPV6),
		Halen:    6,
		Addr:     addr,
	})
}

func htonsUnix(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func buildIPv6PrefixInfoOption(prefix *net.IPNet, validLifetime, preferredLifetime time.Duration) []byte {
	option := make([]byte, 32)
	option[0] = 3
	option[1] = 4
	option[2] = 64
	option[3] = 0xc0
	binary.BigEndian.PutUint32(option[4:8], uint32(validLifetime/time.Second))
	binary.BigEndian.PutUint32(option[8:12], uint32(preferredLifetime/time.Second))
	copy(option[16:32], prefix.IP.To16())
	return option
}

func buildIPv6RouteInfoOption(prefix *net.IPNet, lifetime time.Duration) []byte {
	ones, bits := prefix.Mask.Size()
	if bits != 128 || ones < 0 {
		return nil
	}

	prefixBytes := 0
	switch {
	case ones == 0:
		prefixBytes = 0
	case ones <= 64:
		prefixBytes = 8
	default:
		prefixBytes = 16
	}

	optionLen := 8 + prefixBytes
	option := make([]byte, optionLen)
	option[0] = 24
	option[1] = byte(optionLen / 8)
	option[2] = byte(ones)
	binary.BigEndian.PutUint32(option[4:8], uint32(lifetime/time.Second))
	if prefixBytes > 0 {
		copy(option[8:], prefix.IP.To16()[:prefixBytes])
	}
	return option
}

func buildIPv6SourceLLAOption(mac net.HardwareAddr) []byte {
	option := make([]byte, 8)
	option[0] = 1
	option[1] = 1
	copy(option[2:], mac)
	return option
}

func buildIPv6MTUOption(mtu int) []byte {
	option := make([]byte, 8)
	option[0] = 5
	option[1] = 1
	binary.BigEndian.PutUint32(option[4:8], uint32(mtu))
	return option
}
