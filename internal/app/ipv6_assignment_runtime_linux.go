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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func newIPv6AssignmentRuntime() ipv6AssignmentRuntime {
	return newManagedIPv6AssignmentRuntime(newLinuxIPv6AssignmentNetOps())
}

type linuxIPv6AssignmentNetOps struct {
	mu          sync.Mutex
	advertisers map[string]*ipv6RouterAdvertiser
	dhcpv6      map[string]*ipv6DHCPv6Server
}

func newLinuxIPv6AssignmentNetOps() *linuxIPv6AssignmentNetOps {
	return &linuxIPv6AssignmentNetOps{
		advertisers: make(map[string]*ipv6RouterAdvertiser),
		dhcpv6:      make(map[string]*ipv6DHCPv6Server),
	}
}

func (ops *linuxIPv6AssignmentNetOps) PreserveIPv6AssignmentStateOnClose() bool {
	markerPath := kernelHotRestartMarkerPath()
	if strings.TrimSpace(markerPath) == "" {
		log.Printf("ipv6 assignment runtime: hot restart preserve disabled on close (%s is not set)", forwardHotRestartMarkerEnv)
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
	if ops == nil {
		return nil
	}

	ops.mu.Lock()
	advertisers := make(map[string]*ipv6RouterAdvertiser, len(ops.advertisers))
	for targetInterface, adv := range ops.advertisers {
		advertisers[targetInterface] = adv
	}
	servers := make(map[string]*ipv6DHCPv6Server, len(ops.dhcpv6))
	for targetInterface, srv := range ops.dhcpv6 {
		servers[targetInterface] = srv
	}
	ops.mu.Unlock()

	if len(advertisers) == 0 && len(servers) == 0 {
		return nil
	}

	counters := make(map[string]ipv6AssignmentRuntimeCounter, len(advertisers)+len(servers))
	for targetInterface, adv := range advertisers {
		counter := counters[targetInterface]
		status := adv.snapshotStatus()
		counter.RAAdvertisementCount = status.SendCount
		counter.RAStatus = status.Status
		counter.RAStatusDetail = status.Detail
		counters[targetInterface] = counter
	}
	for targetInterface, srv := range servers {
		counter := counters[targetInterface]
		status := srv.snapshotStatus()
		counter.DHCPv6ReplyCount = status.ReplyCount
		counter.DHCPv6Status = status.Status
		counter.DHCPv6StatusDetail = status.Detail
		counters[targetInterface] = counter
	}
	return counters
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
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	adv := ops.advertisers[config.TargetInterface]
	if adv == nil {
		adv = newIPv6RouterAdvertiser(config)
		ops.advertisers[config.TargetInterface] = adv
		adv.start()
		log.Printf("ipv6 assignment runtime: router advertisement enabled on %s (managed=%t prefixes=%v routes=%v)", config.TargetInterface, config.Managed, config.Prefixes, config.Routes)
	} else {
		adv.update(config)
		log.Printf("ipv6 assignment runtime: router advertisement updated on %s (managed=%t prefixes=%v routes=%v)", config.TargetInterface, config.Managed, config.Prefixes, config.Routes)
	}
	ops.mu.Unlock()
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6RA(targetInterface string) error {
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	adv := ops.advertisers[targetInterface]
	if adv != nil {
		delete(ops.advertisers, targetInterface)
	}
	ops.mu.Unlock()
	if adv != nil {
		adv.stop()
	}
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) EnsureIPv6DHCPv6(config ipv6AssignmentDHCPv6Config) error {
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	server := ops.dhcpv6[config.TargetInterface]
	if server == nil {
		server = newIPv6DHCPv6Server(config)
		ops.dhcpv6[config.TargetInterface] = server
		ops.mu.Unlock()
		server.start()
		log.Printf("ipv6 assignment runtime: dhcpv6 enabled on %s (addresses=%v)", config.TargetInterface, config.Addresses)
		return nil
	}
	server.update(config)
	ops.mu.Unlock()
	log.Printf("ipv6 assignment runtime: dhcpv6 updated on %s (addresses=%v)", config.TargetInterface, config.Addresses)
	return nil
}

func (ops *linuxIPv6AssignmentNetOps) DeleteIPv6DHCPv6(targetInterface string) error {
	if ops == nil {
		return nil
	}
	ops.mu.Lock()
	server := ops.dhcpv6[targetInterface]
	if server != nil {
		delete(ops.dhcpv6, targetInterface)
	}
	ops.mu.Unlock()
	if server != nil {
		server.stop()
	}
	return nil
}
