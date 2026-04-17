package socketio

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type ReplyInfo struct {
	SourceIP net.IP
	IfIndex  int
}

func ReplyKey(src *net.UDPAddr, reply ReplyInfo) string {
	if src == nil {
		return ""
	}

	key := src.String()
	if ReplyInfoHasSourceIP(reply) {
		key += "|" + canonicalIPLiteral(reply.SourceIP)
	} else {
		key += "|"
	}
	if reply.IfIndex > 0 {
		key += "|" + strconv.Itoa(reply.IfIndex)
	}
	return key
}

func listenerLocalIP(conn *net.UDPConn) net.IP {
	if conn == nil {
		return nil
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return nil
	}
	ip := append(net.IP(nil), addr.IP...)
	if ip == nil || ip.IsUnspecified() {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return append(net.IP(nil), ip4...)
	}
	return ip
}

func ReplyInfoHasSourceIP(info ReplyInfo) bool {
	return info.SourceIP != nil && !info.SourceIP.IsUnspecified()
}

func ResolveDialSourceIP(sourceIP string) (net.IP, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return nil, nil
	}
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid outbound source IP %q", sourceIP)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, nil
	}
	return ip, nil
}

func ConfigureOutboundTCPDialer(dialer *net.Dialer, outIface, sourceIP string) error {
	if dialer == nil {
		return nil
	}
	sourceAddr, err := ResolveDialSourceIP(sourceIP)
	if err != nil {
		return err
	}
	if sourceAddr != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: sourceAddr, Port: 0}
	}
	dialer.Control = ControlBindToDevice(outIface)
	return nil
}

func DialOutboundUDP(targetAddr *net.UDPAddr, outIface, sourceIP string, bufferSize int) (*net.UDPConn, error) {
	dialer := net.Dialer{}
	if err := ConfigureOutboundTCPDialer(&dialer, outIface, sourceIP); err != nil {
		return nil, err
	}
	if udpLocal, ok := dialer.LocalAddr.(*net.TCPAddr); ok && udpLocal != nil {
		dialer.LocalAddr = &net.UDPAddr{IP: udpLocal.IP, Port: 0}
	}

	network := "udp"
	if targetAddr != nil {
		network = udpNetworkForIP(targetAddr.IP)
	}

	conn, err := dialer.Dial(network, targetAddr.String())
	if err != nil {
		return nil, err
	}
	udpConn := conn.(*net.UDPConn)
	_ = ConfigureUDPConnBuffers(udpConn, bufferSize)
	return udpConn, nil
}

func ConfigureUDPConnBuffers(conn *net.UDPConn, bufferSize int) error {
	if conn == nil || bufferSize <= 0 {
		return nil
	}

	var firstErr error
	if err := conn.SetReadBuffer(bufferSize); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := conn.SetWriteBuffer(bufferSize); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func canonicalIPLiteral(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func udpNetworkForIP(ip net.IP) string {
	if ip == nil {
		return "udp"
	}
	if ip.To4() != nil {
		return "udp4"
	}
	if ip.To16() != nil {
		return "udp6"
	}
	return "udp"
}
