//go:build !linux

package app

import "net"

func lookupUserspaceRouteIface(net.IP) string {
	return ""
}
