//go:build linux

package socketio

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func ControlBindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		})
		return err
	}
}

func ControlTransparent(clientIP net.IP, outIface string) func(network, address string, c syscall.RawConn) error {
	_ = clientIP
	const ipTransparent = 19 // IP_TRANSPARENT
	return func(network, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipTransparent, 1)
			if err != nil {
				return
			}
			if outIface != "" {
				_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, outIface)
			}
		})
		return err
	}
}

func EnableUDPReplyPacketInfo(conn *net.UDPConn) error {
	if conn == nil {
		return fmt.Errorf("udp socket is nil")
	}
	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || localAddr == nil {
		return fmt.Errorf("udp local addr unavailable")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		if localAddr.IP != nil && localAddr.IP.To4() == nil && localAddr.IP.To16() != nil {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVPKTINFO, 1)
			return
		}
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_PKTINFO, 1)
	}); err != nil {
		return fmt.Errorf("control udp socket: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("enable udp packet info: %w", sockErr)
	}
	return nil
}

func UDPReplyPacketInfoBufferSize() int {
	size4 := unix.CmsgSpace(unix.SizeofInet4Pktinfo)
	size6 := unix.CmsgSpace(unix.SizeofInet6Pktinfo)
	if size6 > size4 {
		return size6
	}
	return size4
}

func ReadUDPWithReplyInfo(conn *net.UDPConn, payload []byte, oob []byte) (int, *net.UDPAddr, ReplyInfo, error) {
	n, oobn, _, src, err := conn.ReadMsgUDP(payload, oob)
	if err != nil {
		return 0, nil, ReplyInfo{}, err
	}

	info := ReplyInfo{SourceIP: listenerLocalIP(conn)}
	if oobn <= 0 {
		return n, src, info, nil
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return n, src, info, nil
	}
	for _, msg := range msgs {
		switch {
		case msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_PKTINFO && len(msg.Data) >= unix.SizeofInet4Pktinfo:
			pkt := *(*unix.Inet4Pktinfo)(unsafe.Pointer(&msg.Data[0]))
			info.IfIndex = int(pkt.Ifindex)

			if !isZeroIPBytes(pkt.Addr[:]) {
				info.SourceIP = net.IPv4(pkt.Addr[0], pkt.Addr[1], pkt.Addr[2], pkt.Addr[3]).To4()
				return n, src, info, nil
			}
			if !isZeroIPBytes(pkt.Spec_dst[:]) {
				info.SourceIP = net.IPv4(pkt.Spec_dst[0], pkt.Spec_dst[1], pkt.Spec_dst[2], pkt.Spec_dst[3]).To4()
				return n, src, info, nil
			}
			return n, src, info, nil
		case msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_PKTINFO && len(msg.Data) >= unix.SizeofInet6Pktinfo:
			pkt := *(*unix.Inet6Pktinfo)(unsafe.Pointer(&msg.Data[0]))
			info.IfIndex = int(pkt.Ifindex)
			if !isZeroIPBytes(pkt.Addr[:]) {
				info.SourceIP = append(net.IP(nil), pkt.Addr[:]...)
			}
			return n, src, info, nil
		}
	}

	return n, src, info, nil
}

func WriteUDPWithReplyInfo(conn *net.UDPConn, payload []byte, dst *net.UDPAddr, info ReplyInfo) (int, error) {
	if dst == nil {
		return 0, fmt.Errorf("udp reply target is nil")
	}

	if !ReplyInfoHasSourceIP(info) && info.IfIndex == 0 {
		return conn.WriteToUDP(payload, dst)
	}

	family := udpNetworkForIP(dst.IP)
	if ReplyInfoHasSourceIP(info) {
		family = udpNetworkForIP(info.SourceIP)
	}

	var control []byte
	switch family {
	case "udp6":
		pkt := &unix.Inet6Pktinfo{}
		if ReplyInfoHasSourceIP(info) {
			copy(pkt.Addr[:], info.SourceIP.To16())
		}
		if info.IfIndex > 0 {
			pkt.Ifindex = uint32(info.IfIndex)
		}
		control = unix.PktInfo6(pkt)
	default:
		pkt := &unix.Inet4Pktinfo{}
		if ip4 := info.SourceIP.To4(); ip4 != nil && !ip4.IsUnspecified() {
			copy(pkt.Spec_dst[:], ip4)
		}
		if info.IfIndex > 0 {
			pkt.Ifindex = int32(info.IfIndex)
		}
		control = unix.PktInfo4(pkt)
	}

	n, _, err := conn.WriteMsgUDP(payload, control, dst)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func isZeroIPBytes(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}
