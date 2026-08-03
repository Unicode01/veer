//go:build linux

package managednet

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Unicode01/veer/internal/netservice"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type linuxNetOps struct {
	dhcpv4 *netservice.DHCPv4Manager
}

func NewLinuxNetOps() NetOps {
	return &linuxNetOps{dhcpv4: netservice.NewDHCPv4Manager()}
}

func (ops *linuxNetOps) EnsureIPv4ForwardingEnabled() error {
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4", "ip_forward"), "1\n"); err != nil {
		return err
	}
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf/all", "forwarding"), "1\n"); err != nil {
		return err
	}
	return writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf/default", "forwarding"), "1\n")
}

func (ops *linuxNetOps) EnsureIPv4ForwardingEnabledOnInterface(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}
	if err := writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf", interfaceName, "forwarding"), "1\n"); err != nil {
		return err
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil || link == nil || link.Attrs() == nil || link.Attrs().MasterIndex <= 0 {
		return nil
	}
	master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
	if err != nil || master == nil || master.Attrs() == nil || strings.TrimSpace(master.Attrs().Name) == "" {
		return nil
	}
	return writeLinuxIPv4Sysctl(filepath.Join("/proc/sys/net/ipv4/conf", master.Attrs().Name, "forwarding"), "1\n")
}

func (ops *linuxNetOps) EnsureManagedNetworkInterface(spec InterfaceSpec) error {
	interfaceName := strings.TrimSpace(spec.Name)
	mode := normalizeManagedNetworkBridgeMode(spec.Mode)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if !errors.As(err, &linkNotFound) {
			return err
		}
		if mode == BridgeModeExisting {
			return fmt.Errorf("interface %q does not exist", interfaceName)
		}
		attrs := netlink.LinkAttrs{Name: interfaceName}
		if spec.BridgeMTU > 0 {
			attrs.MTU = spec.BridgeMTU
		}
		bridge := &netlink.Bridge{LinkAttrs: attrs}
		bridge.VlanFiltering = &spec.BridgeVLANAware
		if err := netlink.LinkAdd(bridge); err != nil {
			return err
		}
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			return err
		}
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return fmt.Errorf("interface %q is unavailable", interfaceName)
	}
	if mode == BridgeModeCreate && !strings.EqualFold(strings.TrimSpace(link.Type()), "bridge") {
		return fmt.Errorf("interface %q already exists and is not a bridge", interfaceName)
	}
	if mode == BridgeModeCreate {
		if spec.BridgeMTU > 0 && link.Attrs().MTU != spec.BridgeMTU {
			if err := netlink.LinkSetMTU(link, spec.BridgeMTU); err != nil {
				return err
			}
		}
		if bridge, ok := link.(*netlink.Bridge); ok {
			if bridge.VlanFiltering == nil || *bridge.VlanFiltering != spec.BridgeVLANAware {
				if err := netlink.BridgeSetVlanFiltering(bridge, spec.BridgeVLANAware); err != nil {
					return err
				}
			}
		}
	}
	if !managedNetworkLinkAdminUp(link) {
		if err := netlink.LinkSetUp(link); err != nil {
			return err
		}
	}
	return nil
}

func (ops *linuxNetOps) EnsureManagedNetworkIPv4Address(spec IPv4AddressSpec) error {
	link, addr, err := linuxManagedNetworkIPv4AddressFromSpec(spec)
	if err != nil {
		return err
	}
	present, err := linuxManagedNetworkHasIPv4Address(link, addr)
	if err != nil {
		return err
	}
	if present {
		return nil
	}
	return netlink.AddrReplace(link, addr)
}

func (ops *linuxNetOps) DeleteManagedNetworkIPv4Address(spec IPv4AddressSpec) error {
	link, addr, err := linuxManagedNetworkIPv4AddressFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	if err := netlink.AddrDel(link, addr); err != nil {
		if managedNetworkIPv4AddressDeleteErrorIsAbsent(err) {
			return nil
		}
		return err
	}
	return nil
}

func managedNetworkIPv4AddressDeleteErrorIsAbsent(err error) bool {
	return errors.Is(err, unix.ESRCH) ||
		errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.EADDRNOTAVAIL)
}

func (ops *linuxNetOps) EnsureManagedNetworkDHCPv4(config DHCPv4Config) error {
	if ops == nil || ops.dhcpv4 == nil {
		return nil
	}
	return ops.dhcpv4.Ensure(config)
}

func (ops *linuxNetOps) DeleteManagedNetworkDHCPv4(bridge string) error {
	if ops == nil || ops.dhcpv4 == nil {
		return nil
	}
	return ops.dhcpv4.Delete(bridge)
}

func (ops *linuxNetOps) SnapshotManagedNetworkDHCPv4States() map[string]DHCPv4RuntimeState {
	if ops == nil || ops.dhcpv4 == nil {
		return nil
	}
	return ops.dhcpv4.Snapshot()
}

func linuxManagedNetworkIPv4AddressFromSpec(spec IPv4AddressSpec) (netlink.Link, *netlink.Addr, error) {
	ifaceName := strings.TrimSpace(spec.InterfaceName)
	if ifaceName == "" {
		return nil, nil, fmt.Errorf("interface is required")
	}
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, nil, fmt.Errorf("interface %q is unavailable", ifaceName)
	}
	ip, prefix, err := net.ParseCIDR(strings.TrimSpace(spec.CIDR))
	if err != nil || prefix == nil || ip == nil || ip.To4() == nil {
		return nil, nil, fmt.Errorf("invalid ipv4 cidr %q", spec.CIDR)
	}
	return link, &netlink.Addr{IPNet: &net.IPNet{IP: ip.To4(), Mask: prefix.Mask}}, nil
}

func linuxManagedNetworkHasIPv4Address(link netlink.Link, want *netlink.Addr) (bool, error) {
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

func managedNetworkLinkAdminUp(link netlink.Link) bool {
	return link != nil && link.Attrs() != nil && link.Attrs().RawFlags&unix.IFF_UP != 0
}

func writeLinuxIPv4Sysctl(path string, value string) error {
	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) == strings.TrimSpace(value) {
		return nil
	}
	return os.WriteFile(path, []byte(value), 0o644)
}
