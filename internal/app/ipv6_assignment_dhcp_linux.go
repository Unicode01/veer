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

	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	dhcpv6ClientPort        = 546
	dhcpv6ServerPort        = 547
	dhcpv6MessageSolicit    = 1
	dhcpv6MessageAdvertise  = 2
	dhcpv6MessageRequest    = 3
	dhcpv6MessageConfirm    = 4
	dhcpv6MessageRenew      = 5
	dhcpv6MessageRebind     = 6
	dhcpv6MessageReply      = 7
	dhcpv6OptionClientID    = 1
	dhcpv6OptionServerID    = 2
	dhcpv6OptionIANA        = 3
	dhcpv6OptionIAAddr      = 5
	dhcpv6DUIDTypeLL        = 3
	dhcpv6HWTypeEthernet    = 1
	dhcpv6T1                = 1 * time.Hour
	dhcpv6T2                = 2 * time.Hour
	dhcpv6PreferredLifetime = 4 * time.Hour
	dhcpv6ValidLifetime     = 24 * time.Hour
	dhcpv6TroubleLogEvery   = 5 * time.Minute
	ipv6NextHeaderUDP       = 17
)

var dhcpv6AllServersAndRelays = net.ParseIP("ff02::1:2")

type ipv6DHCPv6Server struct {
	mu             sync.Mutex
	config         ipv6AssignmentDHCPv6Config
	stopCh         chan struct{}
	doneCh         chan struct{}
	currentFD      int
	listeningSince time.Time
	lastIssueText  string
	lastIssueAt    time.Time
	lastSeenText   string
	lastSeenAt     time.Time
	replyTotal     uint64
	lastReplyAt    time.Time
}

func newIPv6DHCPv6Server(config ipv6AssignmentDHCPv6Config) *ipv6DHCPv6Server {
	return &ipv6DHCPv6Server{
		config:    config,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		currentFD: -1,
	}
}

func (srv *ipv6DHCPv6Server) start() {
	go srv.run()
}

func (srv *ipv6DHCPv6Server) update(config ipv6AssignmentDHCPv6Config) {
	if srv == nil {
		return
	}
	srv.mu.Lock()
	srv.config = config
	srv.mu.Unlock()
}

func (srv *ipv6DHCPv6Server) stop() {
	if srv == nil {
		return
	}
	close(srv.stopCh)
	srv.mu.Lock()
	currentFD := srv.currentFD
	srv.currentFD = -1
	srv.mu.Unlock()
	if currentFD >= 0 {
		_ = unix.Close(currentFD)
	}
	<-srv.doneCh
}

func (srv *ipv6DHCPv6Server) snapshot() ipv6AssignmentDHCPv6Config {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return ipv6AssignmentDHCPv6Config{
		TargetInterface: srv.config.TargetInterface,
		Addresses:       append([]string(nil), srv.config.Addresses...),
	}
}

func (srv *ipv6DHCPv6Server) run() {
	defer close(srv.doneCh)

	for {
		select {
		case <-srv.stopCh:
			return
		default:
		}

		config := srv.snapshot()
		state, fd, err := openIPv6DHCPv6Socket(config)
		if err != nil {
			srv.logIssue(fmt.Sprintf("open socket: %v", err))
			select {
			case <-srv.stopCh:
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}

		func() {
			srv.mu.Lock()
			srv.currentFD = fd
			srv.listeningSince = time.Now()
			srv.mu.Unlock()
			defer unix.Close(fd)
			defer func() {
				srv.mu.Lock()
				if srv.currentFD == fd {
					srv.currentFD = -1
				}
				srv.mu.Unlock()
			}()
			for {
				select {
				case <-srv.stopCh:
					return
				default:
				}

				frame, err := readIPv6DHCPv6Frame(fd)
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
						if dhcpv6SocketNeedsReopen(state) {
							return
						}
						continue
					}
					srv.logIssue(fmt.Sprintf("read: %v", err))
					return
				}
				state.Config = srv.snapshot()
				srv.logSeenMessage(fmt.Sprintf("recv from %s", frame.SrcIP.String()))
				sent, err := handleIPv6DHCPv6Message(state, frame.SrcIP, frame.SrcMAC, frame.Payload)
				if err != nil {
					srv.logIssue(err.Error())
					continue
				}
				if sent {
					srv.mu.Lock()
					srv.replyTotal++
					srv.lastReplyAt = time.Now()
					srv.mu.Unlock()
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

func (srv *ipv6DHCPv6Server) logIssue(text string) {
	if srv == nil {
		return
	}
	now := time.Now()
	if text != srv.lastIssueText || srv.lastIssueAt.IsZero() || now.Sub(srv.lastIssueAt) >= dhcpv6TroubleLogEvery {
		srv.lastIssueText = text
		srv.lastIssueAt = now
		log.Printf("ipv6 assignment dhcpv6 on %s: %s", srv.snapshot().TargetInterface, text)
	}
}

func (srv *ipv6DHCPv6Server) logSeenMessage(text string) {
	if srv == nil {
		return
	}
	now := time.Now()
	if text != srv.lastSeenText || srv.lastSeenAt.IsZero() || now.Sub(srv.lastSeenAt) >= time.Second {
		srv.lastSeenText = text
		srv.lastSeenAt = now
		log.Printf("ipv6 assignment dhcpv6 on %s: %s", srv.snapshot().TargetInterface, text)
	}
}

type ipv6DHCPv6RuntimeState struct {
	Status     string
	Detail     string
	ReplyCount uint64
}

func (srv *ipv6DHCPv6Server) snapshotStatus() ipv6DHCPv6RuntimeState {
	if srv == nil {
		return ipv6DHCPv6RuntimeState{}
	}

	srv.mu.Lock()
	replyCount := srv.replyTotal
	lastSeenAt := srv.lastSeenAt
	lastReplyAt := srv.lastReplyAt
	lastIssueText := srv.lastIssueText
	lastIssueAt := srv.lastIssueAt
	listening := srv.currentFD >= 0
	listeningSince := srv.listeningSince
	srv.mu.Unlock()

	healthyAt := listeningSince
	if lastSeenAt.After(healthyAt) {
		healthyAt = lastSeenAt
	}
	if lastReplyAt.After(healthyAt) {
		healthyAt = lastReplyAt
	}

	state := ipv6DHCPv6RuntimeState{ReplyCount: replyCount}
	switch {
	case lastIssueText != "" && lastIssueAt.After(healthyAt):
		state.Status = "error"
		state.Detail = lastIssueText
	case listening:
		state.Status = "running"
		state.Detail = fmt.Sprintf("dhcpv6 listener active (replies=%d)", replyCount)
	default:
		state.Status = "draining"
		state.Detail = "waiting for dhcpv6 listener"
	}
	return state
}

type ipv6DHCPv6State struct {
	IfIndex int
	IfName  string
	MAC     net.HardwareAddr
	SrcIP   net.IP
	DUID    []byte
	Config  ipv6AssignmentDHCPv6Config
}

type ipv6DHCPv6Frame struct {
	SrcMAC  net.HardwareAddr
	SrcIP   net.IP
	Payload []byte
}

func openIPv6DHCPv6Socket(config ipv6AssignmentDHCPv6Config) (ipv6DHCPv6State, int, error) {
	iface, fd, err := openIPv6PacketListenerSocket(config.TargetInterface, 2*time.Second, buildIPv6DHCPv6SocketFilter())
	if err != nil {
		return ipv6DHCPv6State{}, -1, err
	}
	identity, err := resolveIPv6ControlIdentity(config.TargetInterface)
	if err != nil {
		unix.Close(fd)
		return ipv6DHCPv6State{}, -1, err
	}
	return ipv6DHCPv6State{
		IfIndex: iface.Index,
		IfName:  iface.Name,
		MAC:     append(net.HardwareAddr(nil), identity.SourceMAC...),
		SrcIP:   append(net.IP(nil), identity.SourceIP...),
		DUID:    buildDHCPv6DUID(identity.SourceMAC),
		Config: ipv6AssignmentDHCPv6Config{
			TargetInterface: config.TargetInterface,
			Addresses:       append([]string(nil), config.Addresses...),
		},
	}, fd, nil
}

func buildIPv6DHCPv6SocketFilter() []bpf.Instruction {
	return buildPacketSocketEqualityFilter([]packetSocketEqualityCheck{
		{Offset: packetSocketEtherTypeOffset, Size: 2, Value: 0x86dd},
		{Offset: packetSocketIPv6NextHeaderOffset, Size: 1, Value: ipv6NextHeaderUDP},
		{Offset: packetSocketIPv6UDPSourcePortOffset, Size: 2, Value: dhcpv6ClientPort},
		{Offset: packetSocketIPv6UDPDestPortOffset, Size: 2, Value: dhcpv6ServerPort},
	})
}

type parsedDHCPv6Message struct {
	Type      byte
	TxID      [3]byte
	ClientID  []byte
	ServerID  []byte
	IAIDs     [][]byte
	RawPacket []byte
}

func parseDHCPv6Message(packet []byte) (parsedDHCPv6Message, error) {
	if len(packet) < 4 {
		return parsedDHCPv6Message{}, fmt.Errorf("short dhcpv6 message")
	}
	msg := parsedDHCPv6Message{
		Type:      packet[0],
		RawPacket: append([]byte(nil), packet...),
	}
	copy(msg.TxID[:], packet[1:4])
	options := packet[4:]
	for len(options) >= 4 {
		code := binary.BigEndian.Uint16(options[0:2])
		length := int(binary.BigEndian.Uint16(options[2:4]))
		options = options[4:]
		if length > len(options) {
			return parsedDHCPv6Message{}, fmt.Errorf("invalid dhcpv6 option length")
		}
		value := append([]byte(nil), options[:length]...)
		options = options[length:]
		switch code {
		case dhcpv6OptionClientID:
			msg.ClientID = value
		case dhcpv6OptionServerID:
			msg.ServerID = value
		case dhcpv6OptionIANA:
			if len(value) >= 12 {
				msg.IAIDs = append(msg.IAIDs, append([]byte(nil), value[:4]...))
			}
		}
	}
	return msg, nil
}

func dhcpv6SocketNeedsReopen(state ipv6DHCPv6State) bool {
	if state.IfName == "" {
		return false
	}
	iface, err := net.InterfaceByName(state.IfName)
	if err != nil || iface == nil || iface.Index <= 0 {
		return true
	}
	return iface.Index != state.IfIndex
}

func readIPv6DHCPv6Frame(fd int) (ipv6DHCPv6Frame, error) {
	buf := make([]byte, 2048)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return ipv6DHCPv6Frame{}, err
		}
		frame, ok := parseIPv6DHCPv6Frame(buf[:n])
		if ok {
			return frame, nil
		}
	}
}

func parseIPv6DHCPv6Frame(frame []byte) (ipv6DHCPv6Frame, bool) {
	if len(frame) < 14+40+8+4 {
		return ipv6DHCPv6Frame{}, false
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x86dd {
		return ipv6DHCPv6Frame{}, false
	}
	ipv6Header := frame[14:]
	if version := ipv6Header[0] >> 4; version != 6 {
		return ipv6DHCPv6Frame{}, false
	}
	if ipv6Header[6] != ipv6NextHeaderUDP {
		return ipv6DHCPv6Frame{}, false
	}
	srcIP := net.IP(append([]byte(nil), ipv6Header[8:24]...))
	dstIP := net.IP(append([]byte(nil), ipv6Header[24:40]...))
	if !dstIP.Equal(dhcpv6AllServersAndRelays.To16()) {
		return ipv6DHCPv6Frame{}, false
	}
	udp := ipv6Header[40:]
	if len(udp) < 8 {
		return ipv6DHCPv6Frame{}, false
	}
	if binary.BigEndian.Uint16(udp[0:2]) != dhcpv6ClientPort || binary.BigEndian.Uint16(udp[2:4]) != dhcpv6ServerPort {
		return ipv6DHCPv6Frame{}, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLen < 8 || udpLen > len(udp) {
		return ipv6DHCPv6Frame{}, false
	}
	return ipv6DHCPv6Frame{
		SrcMAC:  append(net.HardwareAddr(nil), frame[6:12]...),
		SrcIP:   srcIP,
		Payload: append([]byte(nil), udp[8:udpLen]...),
	}, true
}

func handleIPv6DHCPv6Message(state ipv6DHCPv6State, remoteIP net.IP, remoteMAC net.HardwareAddr, packet []byte) (bool, error) {
	msg, err := parseDHCPv6Message(packet)
	if err != nil {
		return false, err
	}
	if len(msg.ClientID) == 0 {
		return false, nil
	}
	if len(msg.ServerID) > 0 && string(msg.ServerID) != string(state.DUID) {
		return false, nil
	}
	responseType := byte(0)
	switch msg.Type {
	case dhcpv6MessageSolicit:
		responseType = dhcpv6MessageAdvertise
	case dhcpv6MessageRequest, dhcpv6MessageConfirm, dhcpv6MessageRenew, dhcpv6MessageRebind:
		responseType = dhcpv6MessageReply
	default:
		return false, nil
	}
	reply, err := buildDHCPv6Response(state, msg, responseType)
	if err != nil {
		return false, err
	}
	if err := writeIPv6DHCPv6Reply(state, remoteIP, remoteMAC, msg.ClientID, reply); err != nil {
		return false, err
	}
	return true, nil
}

func buildDHCPv6Response(state ipv6DHCPv6State, msg parsedDHCPv6Message, responseType byte) ([]byte, error) {
	if len(state.Config.Addresses) == 0 {
		return nil, fmt.Errorf("no assigned /128 address available")
	}
	out := []byte{responseType, msg.TxID[0], msg.TxID[1], msg.TxID[2]}
	out = append(out, buildDHCPv6Option(dhcpv6OptionServerID, state.DUID)...)
	out = append(out, buildDHCPv6Option(dhcpv6OptionClientID, msg.ClientID)...)

	iaids := msg.IAIDs
	if len(iaids) == 0 {
		iaids = [][]byte{{0, 0, 0, 0}}
	}
	for _, iaid := range iaids {
		iana := make([]byte, 12)
		copy(iana[:4], iaid)
		binary.BigEndian.PutUint32(iana[4:8], uint32(dhcpv6T1/time.Second))
		binary.BigEndian.PutUint32(iana[8:12], uint32(dhcpv6T2/time.Second))
		for _, addressText := range state.Config.Addresses {
			ip := parseIPLiteral(addressText)
			if ip == nil || ip.To4() != nil {
				return nil, fmt.Errorf("invalid dhcpv6 address %q", addressText)
			}
			addrOption := make([]byte, 24)
			copy(addrOption[:16], ip.To16())
			binary.BigEndian.PutUint32(addrOption[16:20], uint32(dhcpv6PreferredLifetime/time.Second))
			binary.BigEndian.PutUint32(addrOption[20:24], uint32(dhcpv6ValidLifetime/time.Second))
			iana = append(iana, buildDHCPv6Option(dhcpv6OptionIAAddr, addrOption)...)
		}
		out = append(out, buildDHCPv6Option(dhcpv6OptionIANA, iana)...)
	}
	return out, nil
}

func buildDHCPv6Option(code uint16, value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint16(out[0:2], code)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(value)))
	copy(out[4:], value)
	return out
}

func buildDHCPv6DUID(mac net.HardwareAddr) []byte {
	out := make([]byte, 4+len(mac))
	binary.BigEndian.PutUint16(out[0:2], dhcpv6DUIDTypeLL)
	binary.BigEndian.PutUint16(out[2:4], dhcpv6HWTypeEthernet)
	copy(out[4:], mac)
	return out
}

func writeIPv6DHCPv6Reply(state ipv6DHCPv6State, remoteIP net.IP, remoteMAC net.HardwareAddr, clientID []byte, payload []byte) error {
	dstIP := append(net.IP(nil), remoteIP...)
	if dstIP = dstIP.To16(); dstIP == nil || dstIP.To4() != nil {
		return fmt.Errorf("invalid dhcpv6 remote ip %q", remoteIP.String())
	}
	dstMAC, err := resolveIPv6DHCPv6RemoteMAC(state.IfIndex, dstIP, remoteMAC, clientID)
	if err != nil {
		return err
	}
	frame, err := buildIPv6DHCPv6ReplyFrame(state, dstIP, dstMAC, payload)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htonsUnix(unix.ETH_P_IPV6)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var addr [8]byte
	copy(addr[:], dstMAC[:6])
	return unix.Sendto(fd, frame, 0, &unix.SockaddrLinklayer{
		Ifindex:  state.IfIndex,
		Protocol: htonsUnix(unix.ETH_P_IPV6),
		Halen:    6,
		Addr:     addr,
	})
}

func resolveIPv6DHCPv6RemoteMAC(ifIndex int, dstIP net.IP, remoteMAC net.HardwareAddr, clientID []byte) (net.HardwareAddr, error) {
	if len(remoteMAC) >= 6 {
		return append(net.HardwareAddr(nil), remoteMAC...), nil
	}
	if hw := lookupIPv6DHCPv6NeighborMAC(ifIndex, dstIP); len(hw) >= 6 {
		return hw, nil
	}
	if hw := parseDHCPv6ClientHardwareAddr(clientID); len(hw) >= 6 {
		return hw, nil
	}
	return nil, fmt.Errorf("unable to resolve dhcpv6 client mac for %s", dstIP.String())
}

func lookupIPv6DHCPv6NeighborMAC(ifIndex int, dstIP net.IP) net.HardwareAddr {
	neighbors, err := netlink.NeighList(ifIndex, unix.AF_INET6)
	if err != nil {
		return nil
	}
	for _, neigh := range neighbors {
		if neigh.IP == nil || !neigh.IP.Equal(dstIP) || len(neigh.HardwareAddr) < 6 {
			continue
		}
		return append(net.HardwareAddr(nil), neigh.HardwareAddr...)
	}
	return nil
}

func parseDHCPv6ClientHardwareAddr(clientID []byte) net.HardwareAddr {
	if len(clientID) < 4 {
		return nil
	}
	duidType := binary.BigEndian.Uint16(clientID[0:2])
	hwType := binary.BigEndian.Uint16(clientID[2:4])
	if hwType != dhcpv6HWTypeEthernet {
		return nil
	}
	switch duidType {
	case 1:
		if len(clientID) < 8+6 {
			return nil
		}
		return append(net.HardwareAddr(nil), clientID[8:]...)
	case dhcpv6DUIDTypeLL:
		if len(clientID) < 4+6 {
			return nil
		}
		return append(net.HardwareAddr(nil), clientID[4:]...)
	default:
		return nil
	}
}

func buildIPv6DHCPv6ReplyFrame(state ipv6DHCPv6State, dstIP net.IP, dstMAC net.HardwareAddr, payload []byte) ([]byte, error) {
	if len(state.MAC) < 6 {
		return nil, fmt.Errorf("interface %q has no usable ethernet address", state.IfName)
	}
	if len(dstMAC) < 6 {
		return nil, fmt.Errorf("invalid dhcpv6 destination mac for %s", dstIP.String())
	}
	src := state.SrcIP.To16()
	dst := dstIP.To16()
	if src == nil || src.To4() != nil {
		return nil, fmt.Errorf("invalid dhcpv6 source ip %q", state.SrcIP.String())
	}
	if dst == nil || dst.To4() != nil {
		return nil, fmt.Errorf("invalid dhcpv6 destination ip %q", dstIP.String())
	}

	udpLen := 8 + len(payload)
	if udpLen > 0xffff {
		return nil, fmt.Errorf("dhcpv6 payload too large: %d", len(payload))
	}

	frame := make([]byte, 14+40+udpLen)
	copy(frame[0:6], dstMAC[:6])
	copy(frame[6:12], state.MAC[:6])
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)

	ipv6Header := frame[14 : 14+40]
	ipv6Header[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Header[4:6], uint16(udpLen))
	ipv6Header[6] = 17
	ipv6Header[7] = 64
	copy(ipv6Header[8:24], src)
	copy(ipv6Header[24:40], dst)

	udp := frame[14+40:]
	binary.BigEndian.PutUint16(udp[0:2], dhcpv6ServerPort)
	binary.BigEndian.PutUint16(udp[2:4], dhcpv6ClientPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv6Reply(src, dst, udp))
	return frame, nil
}

func udpChecksumIPv6Reply(src net.IP, dst net.IP, udp []byte) uint16 {
	sumLen := 40 + len(udp)
	buf := make([]byte, 0, sumLen)
	buf = append(buf, src.To16()...)
	buf = append(buf, dst.To16()...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(udp)))
	buf = append(buf, length...)
	buf = append(buf, 0, 0, 0, 17)
	buf = append(buf, udp...)
	checksum := internetChecksumDHCPv6(buf)
	if checksum == 0 {
		return 0xffff
	}
	return checksum
}

func internetChecksumDHCPv6(data []byte) uint16 {
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
