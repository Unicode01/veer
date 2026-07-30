//go:build linux

package netservice

import (
	"net"

	"github.com/Unicode01/veer/internal/netinfo"
	"github.com/Unicode01/veer/internal/netutil"
)

type managedNetworkDHCPv4Reservation = DHCPv4Reservation
type managedNetworkDHCPv4Config = DHCPv4Config
type managedNetworkDHCPv4RuntimeState = DHCPv4RuntimeState
type ipv6AssignmentRAConfig = RAConfig
type ipv6AssignmentDHCPv6Config = DHCPv6Config
type InterfaceInfo = netinfo.InterfaceInfo

func parseIPLiteral(value string) net.IP {
	return netutil.ParseIPLiteral(value)
}

func canonicalIPLiteral(ip net.IP) string {
	return netutil.CanonicalIPLiteral(ip)
}

func buildInterfaceInfoMap(items []InterfaceInfo) map[string]InterfaceInfo {
	out := make(map[string]InterfaceInfo, len(items))
	for _, item := range items {
		out[item.Name] = item
	}
	return out
}
