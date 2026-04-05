package app

import (
	"fmt"
	"net"
	"strings"
)

func resolveDialSourceIP(sourceIP string) (net.IP, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return nil, nil
	}
	ip := parseIPLiteral(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid outbound source IP %q", sourceIP)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, nil
	}
	return ip, nil
}

func configureOutboundTCPDialer(dialer *net.Dialer, outIface, sourceIP string) error {
	if dialer == nil {
		return nil
	}
	sourceAddr, err := resolveDialSourceIP(sourceIP)
	if err != nil {
		return err
	}
	if sourceAddr != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: sourceAddr, Port: 0}
	}
	dialer.Control = controlBindToDevice(outIface)
	return nil
}

func dialOutboundUDP(targetAddr *net.UDPAddr, outIface, sourceIP string) (*net.UDPConn, error) {
	dialer := net.Dialer{}
	if err := configureOutboundTCPDialer(&dialer, outIface, sourceIP); err != nil {
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
	_ = configureUDPConnBuffers(udpConn)
	return udpConn, nil
}

func configureUDPConnBuffers(conn *net.UDPConn) error {
	if conn == nil {
		return nil
	}

	var firstErr error
	if err := conn.SetReadBuffer(udpSocketBufferSize); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := conn.SetWriteBuffer(udpSocketBufferSize); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
