package app

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	ipFamilyIPv4 = "ipv4"
	ipFamilyIPv6 = "ipv6"
)

type ipLiteralPairInfo struct {
	firstFamily  string
	secondFamily string
}

func normalizeIPLiteral(value string) (string, error) {
	ip := parseIPLiteral(value)
	if ip == nil {
		return "", fmt.Errorf("must be a valid IP address")
	}
	return canonicalIPLiteral(ip), nil
}

func parseIPLiteral(value string) net.IP {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil
	}
	return net.ParseIP(text)
}

func parseIPLiteralAddr(value string) (netip.Addr, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
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

func ipLiteralFamilyFromAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() || addr.Is4In6() {
		return ipFamilyIPv4
	}
	return ipFamilyIPv6
}

func ipLiteralFamily(value string) string {
	addr, ok := parseIPLiteralAddr(value)
	if !ok {
		return ""
	}
	return ipLiteralFamilyFromAddr(addr)
}

func ipLiteralIsWildcard(value string) bool {
	addr, ok := parseIPLiteralAddr(value)
	return ok && addr.IsUnspecified()
}

func analyzeIPLiteralPair(a, b string) ipLiteralPairInfo {
	info := ipLiteralPairInfo{}
	if addr, ok := parseIPLiteralAddr(a); ok {
		info.firstFamily = ipLiteralFamilyFromAddr(addr)
	}
	if addr, ok := parseIPLiteralAddr(b); ok {
		info.secondFamily = ipLiteralFamilyFromAddr(addr)
	}
	return info
}

func (info ipLiteralPairInfo) mixedFamily() bool {
	return info.firstFamily != "" && info.secondFamily != "" && info.firstFamily != info.secondFamily
}

func (info ipLiteralPairInfo) usesIPv6() bool {
	return info.firstFamily == ipFamilyIPv6 || info.secondFamily == ipFamilyIPv6
}

func ipLiteralUsesIPv6(values ...string) bool {
	for _, value := range values {
		if ipLiteralFamily(value) == ipFamilyIPv6 {
			return true
		}
	}
	return false
}

func ipLiteralPairIsPureIPv4(a, b string) bool {
	return ipLiteralFamily(a) == ipFamilyIPv4 && ipLiteralFamily(b) == ipFamilyIPv4
}

func ipLiteralPairIsMixedFamily(a, b string) bool {
	return analyzeIPLiteralPair(a, b).mixedFamily()
}

func isVisibleInterfaceIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func tcpListenNetworkForIP(bindIP string) string {
	switch ipLiteralFamily(bindIP) {
	case ipFamilyIPv6:
		return "tcp6"
	case ipFamilyIPv4:
		return "tcp4"
	default:
		return "tcp"
	}
}

func tcpListenNetworkForAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	return tcpListenNetworkForIP(host)
}

func udpListenNetworkForIP(bindIP string) string {
	switch ipLiteralFamily(bindIP) {
	case ipFamilyIPv6:
		return "udp6"
	case ipFamilyIPv4:
		return "udp4"
	default:
		return "udp"
	}
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
