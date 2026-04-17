//go:build linux

package managednet

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func CanSkipAddrReload(managedNetworks []ManagedNetwork, reservations []ManagedNetworkReservation) bool {
	_ = reservations
	if len(managedNetworks) == 0 {
		return true
	}

	for _, network := range managedNetworks {
		network = normalizeManagedNetwork(network)
		if !network.Enabled || !network.IPv4Enabled {
			continue
		}
		serverCIDR, _, _, err := normalizeManagedNetworkIPv4CIDR(network.IPv4CIDR)
		if err != nil {
			return false
		}
		link, addr, err := linuxIPv4AddressFromCIDR(network.Bridge, serverCIDR)
		if err != nil {
			return false
		}
		present, err := linuxHasIPv4Address(link, addr)
		if err != nil || !present {
			return false
		}
	}

	return true
}

func linuxIPv4AddressFromCIDR(interfaceName string, cidr string) (netlink.Link, *netlink.Addr, error) {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return nil, nil, fmt.Errorf("interface is required")
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, nil, fmt.Errorf("interface %q is unavailable", interfaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return nil, nil, fmt.Errorf("invalid ipv4 cidr %q", cidr)
	}
	return link, &netlink.Addr{
		IPNet: &net.IPNet{IP: ip.To4(), Mask: prefix.Mask},
	}, nil
}

func linuxHasIPv4Address(link netlink.Link, want *netlink.Addr) (bool, error) {
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return false, fmt.Errorf("interface is unavailable")
	}
	if want == nil || want.IPNet == nil || want.IPNet.IP == nil || want.IPNet.IP.To4() == nil {
		return false, fmt.Errorf("ipv4 address is required")
	}
	wantCIDR := (&net.IPNet{IP: want.IPNet.IP.To4(), Mask: want.IPNet.Mask}).String()
	addrs, err := netlink.AddrList(link, unix.AF_INET)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if addr.IPNet == nil || addr.IPNet.IP == nil || addr.IPNet.IP.To4() == nil {
			continue
		}
		if (&net.IPNet{IP: addr.IPNet.IP.To4(), Mask: addr.IPNet.Mask}).String() == wantCIDR {
			return true, nil
		}
	}
	return false, nil
}
