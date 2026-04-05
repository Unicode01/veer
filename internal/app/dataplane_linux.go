//go:build linux

package app

import (
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

func resolveKernelTransientFallbackBackendMAC(rule Rule, reasonClass string) string {
	if reasonClass != "fdb_missing" {
		return ""
	}
	if strings.TrimSpace(rule.OutInterface) == "" {
		return ""
	}
	backendIP := net.ParseIP(strings.TrimSpace(rule.OutIP)).To4()
	if backendIP == nil {
		return ""
	}

	link, err := netlink.LinkByName(strings.TrimSpace(rule.OutInterface))
	if err != nil || link == nil || link.Attrs() == nil || !isXDPBridgeLink(link) {
		return ""
	}
	backendMAC, err := lookupBridgeNeighborMAC(link.Attrs().Index, backendIP)
	if err != nil || !isValidHardwareAddr(backendMAC) {
		return ""
	}
	return normalizeKernelTransientFallbackBackendMAC(backendMAC.String())
}
