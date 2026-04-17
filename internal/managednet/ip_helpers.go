package managednet

import (
	"errors"
	"net"
	"strings"
)

func normalizeManagedNetworkReservationMACAddress(value string) (string, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(value))
	if err != nil || len(hw) != 6 {
		return "", errors.New("must be a valid Ethernet MAC address")
	}
	return strings.ToLower(hw.String()), nil
}

func parseIPLiteral(value string) net.IP {
	text := strings.TrimSpace(value)
	if text == "" {
		return nil
	}
	return net.ParseIP(text)
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

func isVisibleInterfaceIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip.To4() == nil && ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
