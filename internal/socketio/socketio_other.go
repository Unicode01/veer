//go:build !linux

package socketio

import (
	"net"
	"syscall"
)

func ControlBindToDevice(_ string) func(network, address string, c syscall.RawConn) error {
	return nil
}

func ControlTransparent(_ net.IP, _ string) func(network, address string, c syscall.RawConn) error {
	return nil
}

func EnableUDPReplyPacketInfo(_ *net.UDPConn) error {
	return nil
}

func UDPReplyPacketInfoBufferSize() int {
	return 0
}

func ReadUDPWithReplyInfo(conn *net.UDPConn, payload []byte, _ []byte) (int, *net.UDPAddr, ReplyInfo, error) {
	n, src, err := conn.ReadFromUDP(payload)
	return n, src, ReplyInfo{SourceIP: listenerLocalIP(conn)}, err
}

func WriteUDPWithReplyInfo(conn *net.UDPConn, payload []byte, dst *net.UDPAddr, _ ReplyInfo) (int, error) {
	return conn.WriteToUDP(payload, dst)
}
