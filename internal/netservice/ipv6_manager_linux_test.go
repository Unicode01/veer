//go:build linux

package netservice

import (
	"strings"
	"testing"
	"time"
)

func TestIPv6ManagerIgnoresEquivalentRuntimeUpdates(t *testing.T) {
	t.Parallel()

	manager := NewIPv6Manager()
	raConfig := RAConfig{
		TargetInterface: "br-lan",
		Prefixes:        []string{"2001:db8:100::/64"},
	}
	advertiser := newIPv6RouterAdvertiser(raConfig)
	manager.advertisers[raConfig.TargetInterface] = advertiser

	if err := manager.EnsureRA(cloneIPv6AssignmentRAConfig(raConfig)); err != nil {
		t.Fatalf("EnsureRA(equivalent) error = %v", err)
	}
	select {
	case <-advertiser.wakeCh:
		t.Fatal("EnsureRA(equivalent) triggered an immediate advertisement")
	default:
	}
	changedRA := cloneIPv6AssignmentRAConfig(raConfig)
	changedRA.DNSServers = []string{"2001:4860:4860::8888"}
	if err := manager.EnsureRA(changedRA); err != nil {
		t.Fatalf("EnsureRA(changed) error = %v", err)
	}
	select {
	case <-advertiser.wakeCh:
	default:
		t.Fatal("EnsureRA(changed) did not trigger an immediate advertisement")
	}

	dhcpConfig := DHCPv6Config{
		TargetInterface: "br-lan",
		Addresses:       []string{"2001:db8:100::10"},
	}
	server := newIPv6DHCPv6Server(dhcpConfig)
	manager.dhcpv6[dhcpConfig.TargetInterface] = server
	if err := manager.EnsureDHCPv6(cloneIPv6AssignmentDHCPv6Config(dhcpConfig)); err != nil {
		t.Fatalf("EnsureDHCPv6(equivalent) error = %v", err)
	}
	changedDHCP := cloneIPv6AssignmentDHCPv6Config(dhcpConfig)
	changedDHCP.DNSServers = []string{"2001:4860:4860::8888"}
	if err := manager.EnsureDHCPv6(changedDHCP); err != nil {
		t.Fatalf("EnsureDHCPv6(changed) error = %v", err)
	}
	if got := server.snapshot().DNSServers; len(got) != 1 || got[0] != "2001:4860:4860::8888" {
		t.Fatalf("DHCPv6 runtime config DNS = %v", got)
	}
}

// A PPPoE redial disables the LAN assignment while the WAN is down and
// brings the new delegated prefix back as a new advertiser.
func TestIPv6ManagerDeprecatesThePrefixOfAStoppedAdvertiser(t *testing.T) {
	t.Parallel()

	manager := NewIPv6Manager()
	const iface = "veerra-nonexist"
	ensure := func(prefix string) *ipv6RouterAdvertiser {
		t.Helper()
		if err := manager.EnsureRA(RAConfig{TargetInterface: iface, Prefixes: []string{prefix}}); err != nil {
			t.Fatalf("EnsureRA(%s) error = %v", prefix, err)
		}
		manager.mu.Lock()
		defer manager.mu.Unlock()
		return manager.advertisers[iface]
	}
	deprecated := func(advertiser *ipv6RouterAdvertiser) string {
		return strings.Join(advertiser.deprecatedPrefixes(time.Now()), ",")
	}

	ensure("2001:db8:1::/64")
	if err := manager.DeleteRA(iface); err != nil {
		t.Fatalf("DeleteRA() error = %v", err)
	}
	renumbered := ensure("2001:db8:2::/64")
	if got := deprecated(renumbered); got != "2001:db8:1::/64" {
		t.Fatalf("new advertiser deprecates %q, want the prefix of the stopped one", got)
	}
	if err := manager.DeleteRA(iface); err != nil {
		t.Fatalf("DeleteRA() error = %v", err)
	}
	back := ensure("2001:db8:1::/64")
	if got := deprecated(back); got != "2001:db8:2::/64" {
		t.Fatalf("advertiser for the returning prefix deprecates %q, want only the replaced prefix", got)
	}
	if err := manager.DeleteRA(iface); err != nil {
		t.Fatalf("DeleteRA() error = %v", err)
	}
	if err := manager.EnsureRA(RAConfig{TargetInterface: "veerra-other", Prefixes: []string{"2001:db8:9::/64"}}); err != nil {
		t.Fatalf("EnsureRA(other) error = %v", err)
	}
	manager.mu.Lock()
	other := manager.advertisers["veerra-other"]
	manager.mu.Unlock()
	if got := deprecated(other); got != "" {
		t.Fatalf("advertiser on another interface deprecates %q, want nothing", got)
	}
	if err := manager.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
