package app

import (
	"fmt"
	"net"
	"strings"
)

func resolveDialSourceIPv4(sourceIP string) (net.IP, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if sourceIP == "" {
		return nil, nil
	}
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid outbound source IPv4 %q", sourceIP)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("invalid outbound source IPv4 %q", sourceIP)
	}
	return ip4, nil
}

func configureOutboundTCPDialer(dialer *net.Dialer, outIface, sourceIP string) error {
	if dialer == nil {
		return nil
	}
	ip4, err := resolveDialSourceIPv4(sourceIP)
	if err != nil {
		return err
	}
	if ip4 != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: ip4, Port: 0}
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
	if targetAddr != nil && targetAddr.IP != nil && targetAddr.IP.To4() != nil {
		network = "udp4"
	}

	conn, err := dialer.Dial(network, targetAddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}
