//go:build linux

package app

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/Unicode01/veer/internal/netservice"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newIPv6AssignmentRuntime() ipv6AssignmentRuntime {
	return newManagedIPv6AssignmentRuntime(newLinuxIPv6AssignmentNetOps())
}

type linuxIPv6AssignmentNetOps struct {
	services *netservice.IPv6Manager
}

func newLinuxIPv6AssignmentNetOps() *linuxIPv6AssignmentNetOps {
	return &linuxIPv6AssignmentNetOps{services: netservice.NewIPv6Manager()}
}

func (ops *linuxIPv6AssignmentNetOps) PreserveIPv6AssignmentStateOnClose() bool {
	markerPath := kernelHotRestartMarkerPath()
	if strings.TrimSpace(markerPath) == "" {
		log.Printf("ipv6 assignment runtime: hot restart preserve disabled on close (%s/%s is not set)", veerHotRestartMarkerEnv, forwardHotRestartMarkerEnv)
		return false
	}
	if _, err := os.Stat(markerPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Printf("ipv6 assignment runtime: hot restart preserve disabled on close (marker %s is not present)", markerPath)
		} else {
			log.Printf("ipv6 assignment runtime: hot restart preserve disabled on close (stat %s: %v)", markerPath, err)
		}
		return false
	}
	return true
}

func (ops *linuxIPv6AssignmentNetOps) SnapshotIPv6AssignmentCounters() map[string]ipv6AssignmentRuntimeCounter {
	if ops == nil || ops.services == nil {
		return nil
	}
	return ops.services.Snapshot()
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6ForwardingEnabled() error {
	if err := writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf/all", "forwarding"), "1\n"); err != nil {
		return err
	}
	return writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf/default", "forwarding"), "1\n")
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6ForwardingEnabledOnInterface(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}
	if err := writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf", interfaceName, "forwarding"), "1\n"); err != nil {
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
	return writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf", master.Attrs().Name, "forwarding"), "1\n")
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6AcceptRAEnabled(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("interface is required")
	}
	return writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf", interfaceName, "accept_ra"), "2\n")
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6ProxyNDPEnabled(parentInterface string) error {
	parentInterface = strings.TrimSpace(parentInterface)
	if parentInterface == "" {
		return fmt.Errorf("parent interface is required")
	}
	if err := writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf/all", "proxy_ndp"), "1\n"); err != nil {
		return err
	}
	return writeLinuxIPv6Sysctl(filepath.Join("/proc/sys/net/ipv6/conf", parentInterface, "proxy_ndp"), "1\n")
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6Route(spec ipv6AssignmentRouteSpec) error {
	route, err := linuxIPv6AssignmentRouteFromSpec(spec)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(route)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6Route(spec ipv6AssignmentRouteSpec) error {
	route, err := linuxIPv6AssignmentRouteFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	if err := netlink.RouteDel(route); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6Address(spec ipv6AssignmentAddressSpec) error {
	link, addr, err := linuxIPv6AssignmentAddressFromSpec(spec)
	if err != nil {
		return err
	}
	return netlink.AddrReplace(link, addr)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6Address(spec ipv6AssignmentAddressSpec) error {
	link, addr, err := linuxIPv6AssignmentAddressFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	if err := netlink.AddrDel(link, addr); err != nil && !errors.Is(err, unix.EADDRNOTAVAIL) && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6RejectRoute(spec ipv6AssignmentRejectRouteSpec) error {
	route, err := linuxIPv6AssignmentRejectRouteFromSpec(spec)
	if err != nil {
		return err
	}
	return netlink.RouteReplace(route)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6RejectRoute(spec ipv6AssignmentRejectRouteSpec) error {
	route, err := linuxIPv6AssignmentRejectRouteFromSpec(spec)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6Proxy(spec ipv6AssignmentProxySpec) error {
	neigh, err := linuxIPv6AssignmentProxyFromSpec(spec)
	if err != nil {
		return err
	}
	return netlink.NeighSet(neigh)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6Proxy(spec ipv6AssignmentProxySpec) error {
	neigh, err := linuxIPv6AssignmentProxyFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			return nil
		}
		return err
	}
	if err := netlink.NeighDel(neigh); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return err
	}
	return nil
}

func linuxIPv6AssignmentRouteFromSpec(spec ipv6AssignmentRouteSpec) (*netlink.Route, error) {
	prefixText := strings.TrimSpace(spec.Prefix)
	if prefixText == "" {
		return nil, fmt.Errorf("assigned prefix is required")
	}
	_, prefix, err := net.ParseCIDR(prefixText)
	if err != nil || prefix == nil || prefix.IP == nil || prefix.IP.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 route prefix %q", prefixText)
	}
	targetInterface := strings.TrimSpace(spec.TargetInterface)
	if targetInterface == "" {
		return nil, fmt.Errorf("target interface is required")
	}
	link, err := resolveIPv6AssignmentRouteLink(targetInterface)
	if err != nil {
		return nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, fmt.Errorf("target interface %q is unavailable", targetInterface)
	}
	return &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       cloneIPv6Net(prefix),
		Family:    unix.AF_INET6,
		Protocol:  unix.RTPROT_STATIC,
	}, nil
}

func linuxIPv6AssignmentAddressFromSpec(spec ipv6AssignmentAddressSpec) (netlink.Link, *netlink.Addr, error) {
	targetInterface := strings.TrimSpace(spec.TargetInterface)
	if targetInterface == "" {
		return nil, nil, fmt.Errorf("target interface is required")
	}
	link, err := netlink.LinkByName(targetInterface)
	if err != nil {
		return nil, nil, err
	}
	addr, err := netlink.ParseAddr(strings.TrimSpace(spec.CIDR))
	if err != nil || addr == nil || addr.IPNet == nil || addr.IPNet.IP == nil || addr.IPNet.IP.To4() != nil {
		return nil, nil, fmt.Errorf("invalid ipv6 gateway cidr %q", spec.CIDR)
	}
	addr.Flags |= unix.IFA_F_NOPREFIXROUTE
	return link, addr, nil
}

func linuxIPv6AssignmentRejectRouteFromSpec(spec ipv6AssignmentRejectRouteSpec) (*netlink.Route, error) {
	prefixText := strings.TrimSpace(spec.Prefix)
	_, prefix, err := net.ParseCIDR(prefixText)
	if err != nil || prefix == nil || prefix.IP == nil || prefix.IP.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 reject prefix %q", prefixText)
	}
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return nil, fmt.Errorf("resolve loopback interface: %w", err)
	}
	return &netlink.Route{
		LinkIndex: loopback.Attrs().Index,
		Dst:       cloneIPv6Net(prefix),
		Family:    unix.AF_INET6,
		Table:     unix.RT_TABLE_MAIN,
		Protocol:  unix.RTPROT_STATIC,
		Priority:  1<<31 - 1,
		Type:      unix.RTN_UNREACHABLE,
	}, nil
}

func resolveIPv6AssignmentRouteLink(targetInterface string) (netlink.Link, error) {
	link, err := netlink.LinkByName(targetInterface)
	if err != nil {
		return nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, fmt.Errorf("target interface %q is unavailable", targetInterface)
	}
	if link.Attrs().MasterIndex <= 0 {
		return link, nil
	}
	master, err := netlink.LinkByIndex(link.Attrs().MasterIndex)
	if err != nil {
		return nil, err
	}
	if master == nil || master.Attrs() == nil || master.Attrs().Index <= 0 {
		return nil, fmt.Errorf("master interface for %q is unavailable", targetInterface)
	}
	return master, nil
}

func linuxIPv6AssignmentProxyFromSpec(spec ipv6AssignmentProxySpec) (*netlink.Neigh, error) {
	parentInterface := strings.TrimSpace(spec.ParentInterface)
	if parentInterface == "" {
		return nil, fmt.Errorf("parent interface is required")
	}
	address := parseIPLiteral(spec.Address)
	if address == nil || address.To4() != nil {
		return nil, fmt.Errorf("invalid ipv6 proxy address %q", spec.Address)
	}
	link, err := netlink.LinkByName(parentInterface)
	if err != nil {
		return nil, err
	}
	if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
		return nil, fmt.Errorf("parent interface %q is unavailable", parentInterface)
	}
	return &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    unix.AF_INET6,
		IP:        address.To16(),
		State:     netlink.NUD_PERMANENT,
		Flags:     netlink.NTF_PROXY,
	}, nil
}

func writeLinuxIPv6Sysctl(path string, value string) error {
	current, err := os.ReadFile(path)
	if err == nil && strings.TrimSpace(string(current)) == strings.TrimSpace(value) {
		return nil
	}
	return os.WriteFile(path, []byte(value), 0o644)
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6RA(config ipv6AssignmentRAConfig) error {
	if ops == nil || ops.services == nil {
		return nil
	}
	return ops.services.EnsureRA(config)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6RA(targetInterface string) error {
	if ops == nil || ops.services == nil {
		return nil
	}
	return ops.services.DeleteRA(targetInterface)
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6DHCPv6(config ipv6AssignmentDHCPv6Config) error {
	if ops == nil || ops.services == nil {
		return nil
	}
	return ops.services.EnsureDHCPv6(config)
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6DHCPv6(targetInterface string) error {
	if ops == nil || ops.services == nil {
		return nil
	}
	return ops.services.DeleteDHCPv6(targetInterface)
}
