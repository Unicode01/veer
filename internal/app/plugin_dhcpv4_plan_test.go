package app

import (
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestCompilePluginDHCPv4PlanBuildsDHCPOnlyManagedNetwork(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginDHCPv4PlansResourceID,
		RecordKey:  "lan-a",
		DataJSON:   `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","pool_start":"192.168.50.100","pool_end":"192.168.50.200","dns_servers":["8.8.8.8","1.1.1.1"],"enabled":true}`,
		Enabled:    true,
	}

	items, warnings := compilePluginDHCPv4PlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	item := items[0]
	if item.ID >= 0 || item.BridgeMode != managedNetworkBridgeModeExisting || !item.skipIPv4AddressManagement {
		t.Fatalf("item = %+v, want negative-ID DHCP-only existing bridge plan", item)
	}
	if item.IPv4CIDR != "192.168.50.1/24" || item.IPv4PoolStart != "192.168.50.100" || item.IPv4PoolEnd != "192.168.50.200" {
		t.Fatalf("item IPv4 config = %+v", item)
	}
	if item.IPv4DNSServers != "1.1.1.1,8.8.8.8" {
		t.Fatalf("IPv4DNSServers = %q, want canonical order", item.IPv4DNSServers)
	}
}

func TestCompilePluginDHCPv4PlanRejectsConflictingBridgeAndInvalidDNS(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginDHCPv4PlansResourceID,
		RecordKey:  "default",
		DataJSON:   `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","dns_servers":["1.1.1.1"],"enabled":true}`,
		Enabled:    true,
	}
	items, warnings := compilePluginDHCPv4PlansWithWarnings([]store.PluginRecord{record}, []ManagedNetwork{{
		ID:          7,
		Bridge:      "br-lan",
		IPv4Enabled: true,
		Enabled:     true,
	}})
	if len(items) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "already served") {
		t.Fatalf("items=%+v warnings=%v, want bridge conflict", items, warnings)
	}

	record.DataJSON = `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","dns_servers":["2001:db8::53"],"enabled":true}`
	items, warnings = compilePluginDHCPv4PlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "ipv4_dns_servers") {
		t.Fatalf("items=%+v warnings=%v, want IPv6 DNS rejection", items, warnings)
	}
}

func TestCompilePluginDHCPv4PlanRejectsMoreThanEightDNSServers(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginDHCPv4PlansResourceID,
		RecordKey:  "too-many-dns",
		DataJSON:   `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","dns_servers":["192.0.2.1","192.0.2.2","192.0.2.3","192.0.2.4","192.0.2.5","192.0.2.6","192.0.2.7","192.0.2.8","192.0.2.9"],"enabled":true}`,
		Enabled:    true,
	}

	items, warnings := compilePluginDHCPv4PlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "more than 8") {
		t.Fatalf("items=%+v warnings=%v, want DNS count rejection", items, warnings)
	}
}

func TestCompilePluginDHCPv4PlanBuildsReservations(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginDHCPv4PlansResourceID,
		RecordKey:  "reserved",
		DataJSON:   `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","pool_start":"192.168.50.100","pool_end":"192.168.50.200","reservations":[{"mac_address":"02-00-00-00-00-02","ipv4_address":"192.168.50.20","remark":"vm 2"},{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.10"}],"enabled":true}`,
		Enabled:    true,
	}

	networks, reservations, warnings := compilePluginDHCPv4PlansAndReservationsWithWarnings([]store.PluginRecord{record}, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(networks) != 1 || len(reservations) != 2 {
		t.Fatalf("networks=%+v reservations=%+v", networks, reservations)
	}
	if reservations[0].ManagedNetworkID != networks[0].ID || reservations[1].ManagedNetworkID != networks[0].ID {
		t.Fatalf("reservation ownership = %+v, want network %d", reservations, networks[0].ID)
	}
	if reservations[0].MACAddress != "02:00:00:00:00:01" || reservations[0].IPv4Address != "192.168.50.10" {
		t.Fatalf("first reservation = %+v, want normalized and sorted", reservations[0])
	}
	if reservations[1].Remark != "vm 2" || reservations[0].ID >= 0 || reservations[1].ID >= 0 {
		t.Fatalf("reservations = %+v, want deterministic synthetic records", reservations)
	}
}

func TestCompilePluginDHCPv4PlanRejectsInvalidReservations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		items    string
		contains string
	}{
		{name: "duplicate mac", items: `[{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.10"},{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.11"}]`, contains: "duplicates"},
		{name: "duplicate ip", items: `[{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.10"},{"mac_address":"02:00:00:00:00:02","ipv4_address":"192.168.50.10"}]`, contains: "duplicates"},
		{name: "outside subnet", items: `[{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.51.10"}]`, contains: "inside ipv4_cidr"},
		{name: "gateway", items: `[{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.1"}]`, contains: "gateway address"},
		{name: "broadcast", items: `[{"mac_address":"02:00:00:00:00:01","ipv4_address":"192.168.50.255"}]`, contains: "usable host"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			record := store.PluginRecord{
				PluginID:   "lan_core",
				ResourceID: pluginDHCPv4PlansResourceID,
				RecordKey:  tc.name,
				DataJSON:   `{"bridge":"br-lan","ipv4_cidr":"192.168.50.1/24","reservations":` + tc.items + `,"enabled":true}`,
				Enabled:    true,
			}
			networks, reservations, warnings := compilePluginDHCPv4PlansAndReservationsWithWarnings([]store.PluginRecord{record}, nil)
			if len(networks) != 0 || len(reservations) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], tc.contains) {
				t.Fatalf("networks=%+v reservations=%+v warnings=%v", networks, reservations, warnings)
			}
		})
	}
}
