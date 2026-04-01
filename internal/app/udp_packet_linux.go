//go:build linux

package app

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

func enableUDPReplyPacketInfo(conn *net.UDPConn) error {
	if conn == nil {
		return fmt.Errorf("udp socket is nil")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var sockErr error
	if err := rawConn.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_PKTINFO, 1)
	}); err != nil {
		return fmt.Errorf("control udp socket: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("enable IP_PKTINFO: %w", sockErr)
	}
	return nil
}

func udpReplyPacketInfoBufferSize() int {
	return unix.CmsgSpace(unix.SizeofInet4Pktinfo)
}

func readUDPWithReplyInfo(conn *net.UDPConn, payload []byte, oob []byte) (int, *net.UDPAddr, udpReplyInfo, error) {
	n, oobn, _, src, err := conn.ReadMsgUDP(payload, oob)
	if err != nil {
		return 0, nil, udpReplyInfo{}, err
	}

	info := udpReplyInfo{sourceIP: udpListenerLocalIPv4(conn)}
	if oobn <= 0 {
		return n, src, info, nil
	}

	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return n, src, info, nil
	}
	for _, msg := range msgs {
		if msg.Header.Level != unix.SOL_IP || msg.Header.Type != unix.IP_PKTINFO || len(msg.Data) < unix.SizeofInet4Pktinfo {
			continue
		}
		pkt := *(*unix.Inet4Pktinfo)(unsafe.Pointer(&msg.Data[0]))
		info.ifIndex = int(pkt.Ifindex)

		if !isZeroIPv4Bytes(pkt.Addr[:]) {
			info.sourceIP = net.IPv4(pkt.Addr[0], pkt.Addr[1], pkt.Addr[2], pkt.Addr[3]).To4()
			return n, src, info, nil
		}
		if !isZeroIPv4Bytes(pkt.Spec_dst[:]) {
			info.sourceIP = net.IPv4(pkt.Spec_dst[0], pkt.Spec_dst[1], pkt.Spec_dst[2], pkt.Spec_dst[3]).To4()
			return n, src, info, nil
		}
		return n, src, info, nil
	}

	return n, src, info, nil
}

func writeUDPWithReplyInfo(conn *net.UDPConn, payload []byte, dst *net.UDPAddr, info udpReplyInfo) (int, error) {
	if dst == nil {
		return 0, fmt.Errorf("udp reply target is nil")
	}

	if !udpReplyInfoHasSourceIP(info) && info.ifIndex == 0 {
		return conn.WriteToUDP(payload, dst)
	}

	pkt := &unix.Inet4Pktinfo{}
	if ip4 := info.sourceIP.To4(); ip4 != nil && !ip4.IsUnspecified() {
		copy(pkt.Spec_dst[:], ip4)
	}
	if info.ifIndex > 0 {
		pkt.Ifindex = int32(info.ifIndex)
	}

	n, _, err := conn.WriteMsgUDP(payload, unix.PktInfo4(pkt), dst)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func isZeroIPv4Bytes(b []byte) bool {
	if len(b) < 4 {
		return true
	}
	return b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0
}
