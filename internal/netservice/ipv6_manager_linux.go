//go:build linux

package netservice

import (
	"log"
	"sync"
)

type IPv6Manager struct {
	mu          sync.Mutex
	advertisers map[string]*ipv6RouterAdvertiser
	dhcpv6      map[string]*ipv6DHCPv6Server
}

func NewIPv6Manager() *IPv6Manager {
	return &IPv6Manager{
		advertisers: make(map[string]*ipv6RouterAdvertiser),
		dhcpv6:      make(map[string]*ipv6DHCPv6Server),
	}
}

func (manager *IPv6Manager) EnsureRA(config RAConfig) error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	advertiser := manager.advertisers[config.TargetInterface]
	if advertiser == nil {
		advertiser = newIPv6RouterAdvertiser(config)
		manager.advertisers[config.TargetInterface] = advertiser
		advertiser.start()
		manager.mu.Unlock()
		log.Printf("network service: router advertisement enabled on %s (managed=%t prefixes=%v routes=%v dns=%v)", config.TargetInterface, config.Managed, config.Prefixes, config.Routes, config.DNSServers)
		return nil
	}
	changed := advertiser.update(config)
	manager.mu.Unlock()
	if changed {
		log.Printf("network service: router advertisement updated on %s (managed=%t prefixes=%v routes=%v dns=%v)", config.TargetInterface, config.Managed, config.Prefixes, config.Routes, config.DNSServers)
	}
	return nil
}

func (manager *IPv6Manager) DeleteRA(targetInterface string) error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	advertiser := manager.advertisers[targetInterface]
	delete(manager.advertisers, targetInterface)
	manager.mu.Unlock()
	if advertiser != nil {
		advertiser.stop()
	}
	return nil
}

func (manager *IPv6Manager) EnsureDHCPv6(config DHCPv6Config) error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	server := manager.dhcpv6[config.TargetInterface]
	if server == nil {
		server = newIPv6DHCPv6Server(config)
		manager.dhcpv6[config.TargetInterface] = server
		server.start()
		manager.mu.Unlock()
		log.Printf("network service: dhcpv6 enabled on %s (addresses=%v dns=%v)", config.TargetInterface, config.Addresses, config.DNSServers)
		return nil
	}
	changed := server.update(config)
	manager.mu.Unlock()
	if changed {
		log.Printf("network service: dhcpv6 updated on %s (addresses=%v dns=%v)", config.TargetInterface, config.Addresses, config.DNSServers)
	}
	return nil
}

func (manager *IPv6Manager) DeleteDHCPv6(targetInterface string) error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	server := manager.dhcpv6[targetInterface]
	delete(manager.dhcpv6, targetInterface)
	manager.mu.Unlock()
	if server != nil {
		server.stop()
	}
	return nil
}

func (manager *IPv6Manager) Snapshot() map[string]IPv6RuntimeCounter {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	advertisers := make(map[string]*ipv6RouterAdvertiser, len(manager.advertisers))
	for targetInterface, advertiser := range manager.advertisers {
		advertisers[targetInterface] = advertiser
	}
	servers := make(map[string]*ipv6DHCPv6Server, len(manager.dhcpv6))
	for targetInterface, server := range manager.dhcpv6 {
		servers[targetInterface] = server
	}
	manager.mu.Unlock()
	if len(advertisers) == 0 && len(servers) == 0 {
		return nil
	}

	counters := make(map[string]IPv6RuntimeCounter, len(advertisers)+len(servers))
	for targetInterface, advertiser := range advertisers {
		counter := counters[targetInterface]
		status := advertiser.snapshotStatus()
		counter.RAAdvertisementCount = status.SendCount
		counter.RAStatus = status.Status
		counter.RAStatusDetail = status.Detail
		counters[targetInterface] = counter
	}
	for targetInterface, server := range servers {
		counter := counters[targetInterface]
		status := server.snapshotStatus()
		counter.DHCPv6ReplyCount = status.ReplyCount
		counter.DHCPv6Status = status.Status
		counter.DHCPv6StatusDetail = status.Detail
		counters[targetInterface] = counter
	}
	return counters
}

func (manager *IPv6Manager) Close() error {
	if manager == nil {
		return nil
	}
	manager.mu.Lock()
	advertisers := manager.advertisers
	servers := manager.dhcpv6
	manager.advertisers = make(map[string]*ipv6RouterAdvertiser)
	manager.dhcpv6 = make(map[string]*ipv6DHCPv6Server)
	manager.mu.Unlock()
	for _, advertiser := range advertisers {
		advertiser.stop()
	}
	for _, server := range servers {
		server.stop()
	}
	return nil
}
