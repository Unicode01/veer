//go:build !linux

package app

import "net"

func enableUDPReplyPacketInfo(conn *net.UDPConn) error {
	return nil
}

func udpReplyPacketInfoBufferSize() int {
	return 0
}

func readUDPWithReplyInfo(conn *net.UDPConn, payload []byte, _ []byte) (int, *net.UDPAddr, udpReplyInfo, error) {
	n, src, err := conn.ReadFromUDP(payload)
	return n, src, udpReplyInfo{sourceIP: udpListenerLocalIP(conn)}, err
}

func writeUDPWithReplyInfo(conn *net.UDPConn, payload []byte, dst *net.UDPAddr, _ udpReplyInfo) (int, error) {
	return conn.WriteToUDP(payload, dst)
}
