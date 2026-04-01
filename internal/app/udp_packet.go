package app

import (
	"net"
	"strconv"
)

type udpReplyInfo struct {
	sourceIP net.IP
	ifIndex  int
}

func udpReplyKey(src *net.UDPAddr, reply udpReplyInfo) string {
	if src == nil {
		return ""
	}

	key := src.String()
	if ip4 := reply.sourceIP.To4(); ip4 != nil {
		key += "|" + ip4.String()
	} else {
		key += "|"
	}
	if reply.ifIndex > 0 {
		key += "|" + strconv.Itoa(reply.ifIndex)
	}
	return key
}

func udpListenerLocalIPv4(conn *net.UDPConn) net.IP {
	if conn == nil {
		return nil
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr == nil {
		return nil
	}
	ip4 := addr.IP.To4()
	if ip4 == nil || ip4.IsUnspecified() {
		return nil
	}
	return append(net.IP(nil), ip4...)
}

func udpReplyInfoHasSourceIP(info udpReplyInfo) bool {
	ip4 := info.sourceIP.To4()
	return ip4 != nil && !ip4.IsUnspecified()
}
