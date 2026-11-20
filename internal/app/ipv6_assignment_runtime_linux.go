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
	"sync"

	"github.com/Unicode01/veer/internal/netservice"
	"github.com/Unicode01/veer/internal/nlretry"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newIPv6AssignmentRuntime() ipv6AssignmentRuntime {
	return newManagedIPv6AssignmentRuntime(newLinuxIPv6AssignmentNetOps())
}

type linuxIPv6AssignmentNetOps struct {
	services *netservice.IPv6Manager

	// routeLinks remembers the link each route went to: the bridge when the
	// target is a bridge port. Once a guest's tap is gone its name no longer
	// resolves, and only this tells where its route still is.
	routesMu   sync.Mutex
	routeLinks map[ipv6AssignmentRouteSpec]int
}

func newLinuxIPv6AssignmentNetOps() *linuxIPv6AssignmentNetOps {
	return &linuxIPv6AssignmentNetOps{services: netservice.NewIPv6Manager(), routeLinks: make(map[ipv6AssignmentRouteSpec]int)}
}

func (ops *linuxIPv6AssignmentNetOps) rememberRouteLink(spec ipv6AssignmentRouteSpec, linkIndex int) {
	ops.routesMu.Lock()
	defer ops.routesMu.Unlock()
	if ops.routeLinks == nil {
		ops.routeLinks = make(map[ipv6AssignmentRouteSpec]int)
	}
	if linkIndex > 0 {
		ops.routeLinks[spec] = linkIndex
	} else {
		delete(ops.routeLinks, spec)
	}
}

func (ops *linuxIPv6AssignmentNetOps) rememberedRouteLink(spec ipv6AssignmentRouteSpec) int {
	ops.routesMu.Lock()
	defer ops.routesMu.Unlock()
	return ops.routeLinks[spec]
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

// IPv6InterfaceGone reports whether no interface is named name, such as the
// tap of a destroyed guest. A lookup that fails for another reason does not
// count.
func (ops *linuxIPv6AssignmentNetOps) IPv6InterfaceGone(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	_, err := nlretry.LinkByName(name)
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound)
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
	link, err := nlretry.LinkByName(interfaceName)
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
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			// The target interface is gone, so the route it had on its
			// bridge leads nowhere.
			if cleanupErr := ops.deleteOrphanIPv6AssignmentRoute(spec); cleanupErr != nil {
				log.Printf("ipv6 assignment runtime: remove route %s of missing %s: %v", spec.Prefix, spec.TargetInterface, cleanupErr)
			}
		}
		return err
	}
	if err := netlink.RouteReplace(route); err != nil {
		return err
	}
	if previous := ops.rememberedRouteLink(spec); previous > 0 && previous != route.LinkIndex {
		// The target moved to another bridge: drop the route on the old one.
		stale := *route
		stale.LinkIndex = previous
		if err := netlink.RouteDel(&stale); err != nil && !errors.Is(err, unix.ESRCH) {
			log.Printf("ipv6 assignment runtime: remove route %s from its previous link %d: %v", spec.Prefix, previous, err)
		}
	}
	ops.rememberRouteLink(spec, route.LinkIndex)
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6Route(spec ipv6AssignmentRouteSpec) error {
	route, err := linuxIPv6AssignmentRouteFromSpec(spec)
	if err != nil {
		var linkNotFound netlink.LinkNotFoundError
		if errors.As(err, &linkNotFound) {
			// A destroyed guest's tap: its route stays on the bridge it was
			// a port of until removed here.
			return ops.deleteOrphanIPv6AssignmentRoute(spec)
		}
		return err
	}
	if previous := ops.rememberedRouteLink(spec); previous > 0 {
		route.LinkIndex = previous
	}
	if err := netlink.RouteDel(route); err != nil {
		if errors.Is(err, unix.ESRCH) {
			ops.rememberRouteLink(spec, 0)
			return nil
		}
		return err
	}
	ops.rememberRouteLink(spec, 0)
	return nil
}

// deleteOrphanIPv6AssignmentRoute removes the route of spec after its target
// interface disappeared: on the link it was installed on when that is known,
// otherwise any route this runtime would have installed for exactly that
// prefix (static, unicast, main table, no gateway).
func (ops *linuxIPv6AssignmentNetOps) deleteOrphanIPv6AssignmentRoute(spec ipv6AssignmentRouteSpec) error {
	_, prefix, err := net.ParseCIDR(strings.TrimSpace(spec.Prefix))
	if err != nil || prefix == nil || prefix.IP.To4() != nil {
		return nil
	}
	linkIndex := ops.rememberedRouteLink(spec)
	routes, err := nlretry.RouteListFiltered(unix.AF_INET6, &netlink.Route{Dst: prefix, Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	var failures []error
	for i := range routes {
		route := &routes[i]
		if !isIPv6AssignmentRoute(route, prefix, prefix.Mask) || (linkIndex > 0 && route.LinkIndex != linkIndex) {
			continue
		}
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
			failures = append(failures, err)
			continue
		}
		log.Printf("ipv6 assignment runtime: removed route %s (its target %s is gone)", spec.Prefix, spec.TargetInterface)
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	ops.rememberRouteLink(spec, 0)
	return nil
}

// isIPv6AssignmentRoute tells whether route has the shape of the routes this
// runtime installs (see linuxIPv6AssignmentRouteFromSpec), with a destination
// inside parent and the prefix length of mask.
func isIPv6AssignmentRoute(route *netlink.Route, parent *net.IPNet, mask net.IPMask) bool {
	if route == nil || route.Dst == nil || route.Dst.IP.To4() != nil || route.Gw != nil || route.LinkIndex <= 0 {
		return false
	}
	if route.Protocol != unix.RTPROT_STATIC || (route.Type != 0 && route.Type != unix.RTN_UNICAST) {
		return false
	}
	if route.Table != 0 && route.Table != unix.RT_TABLE_MAIN {
		return false
	}
	ones, bits := route.Dst.Mask.Size()
	wantOnes, wantBits := mask.Size()
	return ones == wantOnes && bits == wantBits && parent.Contains(route.Dst.IP)
}

// SweepIPv6AssignmentRoutes removes assignment routes no assignment uses any
// more from each scope's bridge: those a predecessor left across a hot
// restart, or an older version left when a guest was destroyed.
func (ops *linuxIPv6AssignmentNetOps) SweepIPv6AssignmentRoutes(scopes []ipv6AssignmentRouteSweepScope, keep map[string]struct{}) error {
	var failures []error
	for _, scope := range scopes {
		link, err := nlretry.LinkByName(scope.Bridge)
		if err != nil {
			var linkNotFound netlink.LinkNotFoundError
			if !errors.As(err, &linkNotFound) {
				failures = append(failures, fmt.Errorf("%s: %w", scope.Bridge, err))
			}
			continue
		}
		routes, err := nlretry.RouteList(link, unix.AF_INET6)
		if err != nil {
			failures = append(failures, fmt.Errorf("list routes on %s: %w", scope.Bridge, err))
			continue
		}
		mask := net.CIDRMask(scope.PrefixLen, 128)
		for i := range routes {
			route := &routes[i]
			if !isIPv6AssignmentRoute(route, scope.ParentPrefix, mask) {
				continue
			}
			key := ipv6AssignmentRouteKey(route.Dst)
			if _, used := keep[key]; used {
				continue
			}
			if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) {
				failures = append(failures, fmt.Errorf("remove %s from %s: %w", key, scope.Bridge, err))
				continue
			}
			log.Printf("ipv6 assignment runtime: removed stale route %s dev %s (no assignment uses it)", key, scope.Bridge)
		}
	}
	return errors.Join(failures...)
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
	link, err := nlretry.LinkByName(targetInterface)
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
	loopback, err := nlretry.LinkByName("lo")
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
	link, err := nlretry.LinkByName(targetInterface)
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
	link, err := nlretry.LinkByName(parentInterface)
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
