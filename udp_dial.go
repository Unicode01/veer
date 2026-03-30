package main

import "net"

func dialOutboundUDP(targetAddr *net.UDPAddr, outIface string) (*net.UDPConn, error) {
	dialer := net.Dialer{
		Control: controlBindToDevice(outIface),
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
