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
	if udpReplyInfoHasSourceIP(reply) {
		key += "|" + canonicalIPLiteral(reply.sourceIP)
	} else {
		key += "|"
	}
	if reply.ifIndex > 0 {
		key += "|" + strconv.Itoa(reply.ifIndex)
	}
	return key
}

func udpListenerLocalIP(conn *net.UDPConn) net.IP {
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

func udpReplyInfoHasSourceIP(info udpReplyInfo) bool {
	return info.sourceIP != nil && !info.sourceIP.IsUnspecified()
}
