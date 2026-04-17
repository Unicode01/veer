package netutil

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

type IPLiteralPairInfo struct {
	FirstFamily  string
	SecondFamily string
}

func NormalizeIPLiteral(value string) (string, error) {
	ip := ParseIPLiteral(value)
	if ip == nil {
		return "", fmt.Errorf("must be a valid IP address")
	}
	return CanonicalIPLiteral(ip), nil
}

func ParseIPLiteral(value string) net.IP {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil
	}
	return net.ParseIP(text)
}

func ParseIPLiteralAddr(value string) (netip.Addr, bool) {
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

func CanonicalIPLiteral(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func IPLiteralFamilyFromAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	if addr.Is4() || addr.Is4In6() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

func IPLiteralFamily(value string) string {
	addr, ok := ParseIPLiteralAddr(value)
	if !ok {
		return ""
	}
	return IPLiteralFamilyFromAddr(addr)
}

func IPLiteralIsWildcard(value string) bool {
	addr, ok := ParseIPLiteralAddr(value)
	return ok && addr.IsUnspecified()
}

func AnalyzeIPLiteralPair(a, b string) IPLiteralPairInfo {
	info := IPLiteralPairInfo{}
	if addr, ok := ParseIPLiteralAddr(a); ok {
		info.FirstFamily = IPLiteralFamilyFromAddr(addr)
	}
	if addr, ok := ParseIPLiteralAddr(b); ok {
		info.SecondFamily = IPLiteralFamilyFromAddr(addr)
	}
	return info
}

func (info IPLiteralPairInfo) MixedFamily() bool {
	return info.FirstFamily != "" && info.SecondFamily != "" && info.FirstFamily != info.SecondFamily
}

func (info IPLiteralPairInfo) UsesIPv6() bool {
	return info.FirstFamily == FamilyIPv6 || info.SecondFamily == FamilyIPv6
}

func IPLiteralPairIsPureIPv4(a, b string) bool {
	return IPLiteralFamily(a) == FamilyIPv4 && IPLiteralFamily(b) == FamilyIPv4
}

func IsVisibleInterfaceIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}

func TCPListenNetworkForIP(bindIP string) string {
	switch IPLiteralFamily(bindIP) {
	case FamilyIPv6:
		return "tcp6"
	case FamilyIPv4:
		return "tcp4"
	default:
		return "tcp"
	}
}

func TCPListenNetworkForAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	return TCPListenNetworkForIP(host)
}

func UDPListenNetworkForIP(bindIP string) string {
	switch IPLiteralFamily(bindIP) {
	case FamilyIPv6:
		return "udp6"
	case FamilyIPv4:
		return "udp4"
	default:
		return "udp"
	}
}

func UDPNetworkForIP(ip net.IP) string {
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

func IPv4BytesToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
