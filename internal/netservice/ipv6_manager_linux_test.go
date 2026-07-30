//go:build linux

package netservice

import "testing"

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
