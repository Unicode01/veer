package app

import (
	"strings"
	"testing"

	"forward/internal/store"
)

func TestPluginIPv6SubnetByIndexSelectsRequested64(t *testing.T) {
	t.Parallel()

	_, parent, err := normalizeIPv6Prefix("240e:390:6aad:d550::/60")
	if err != nil {
		t.Fatalf("normalizeIPv6Prefix() error = %v", err)
	}
	subnet, err := pluginIPv6SubnetByIndex(parent, 64, 5)
	if err != nil {
		t.Fatalf("pluginIPv6SubnetByIndex() error = %v", err)
	}
	if got := subnet.String(); got != "240e:390:6aad:d555::/64" {
		t.Fatalf("pluginIPv6SubnetByIndex() = %q, want 240e:390:6aad:d555::/64", got)
	}
	if _, err := pluginIPv6SubnetByIndex(parent, 64, 16); err == nil {
		t.Fatal("pluginIPv6SubnetByIndex(index=16) error = nil, want capacity rejection")
	}
}

func TestCompilePluginIPv6AssignmentPlanBuildsRoutedPDState(t *testing.T) {
	t.Parallel()

	records := []store.PluginRecord{{
		PluginID:   "lan_core",
		ResourceID: pluginIPv6AssignmentPlansResourceID,
		RecordKey:  "lan-a",
		DataJSON: `{
			"parent_interface":"fwdlocal0",
			"target_interface":"br-lan",
			"parent_prefix":"240e:390:6aad:d550::/60",
			"assigned_prefix_length":64,
			"subnet_index":5,
			"upstream_routed":true,
			"configure_gateway":true,
			"reject_unassigned":true,
			"dns_servers":["2400:3200::1","2001:4860:4860::8888"],
			"enabled":true
		}`,
		Enabled: true,
	}}

	items, warnings := compilePluginIPv6AssignmentPlansWithWarnings(records, nil)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	if len(items) != 1 {
		t.Fatalf("len(items) = %d, want 1", len(items))
	}
	item := items[0]
	if item.ID >= 0 || item.ParentPrefix != "240e:390:6aad:d550::/60" || item.AssignedPrefix != "240e:390:6aad:d555::/64" {
		t.Fatalf("item = %+v, want stable synthetic /64 assignment", item)
	}
	if !item.upstreamRouted || item.gatewayCIDR != "240e:390:6aad:d555::1/60" || item.rejectPrefix != "240e:390:6aad:d550::/60" {
		t.Fatalf("runtime metadata = routed:%t gateway:%q reject:%q", item.upstreamRouted, item.gatewayCIDR, item.rejectPrefix)
	}
	if strings.Join(item.dnsServers, ",") != "2001:4860:4860::8888,2400:3200::1" {
		t.Fatalf("dnsServers = %v, want canonical IPv6 DNS list", item.dnsServers)
	}

	resolved, changed, err := resolveIPv6AssignmentForCurrentHost(item, map[string]HostNetworkInterface{
		"fwdlocal0": {
			Name: "fwdlocal0",
			Addresses: []HostInterfaceAddress{{
				Family: ipFamilyIPv6,
				CIDR:   "2001:db8:ffff::/64",
			}},
		},
	})
	if err != nil || changed || resolved.ParentPrefix != item.ParentPrefix || resolved.AssignedPrefix != item.AssignedPrefix {
		t.Fatalf("resolve routed item = %+v changed=%t err=%v, want unchanged", resolved, changed, err)
	}
}

func TestCompilePluginIPv6AssignmentPlanRejectsNonIPv6OrLinkLocalDNS(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginIPv6AssignmentPlansResourceID,
		RecordKey:  "bad-dns",
		DataJSON:   `{"parent_interface":"wan0","target_interface":"br-lan","parent_prefix":"2001:db8:100::/56","assigned_prefix":"2001:db8:100:1::/64","dns_servers":["1.1.1.1"],"upstream_routed":true,"enabled":true}`,
		Enabled:    true,
	}
	items, warnings := compilePluginIPv6AssignmentPlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 0 || len(warnings) != 1 || !strings.Contains(warnings[0], "dns_servers") {
		t.Fatalf("items=%+v warnings=%v, want IPv4 DNS rejection", items, warnings)
	}

	record.DataJSON = `{"parent_interface":"wan0","target_interface":"br-lan","parent_prefix":"2001:db8:100::/56","assigned_prefix":"2001:db8:100:1::/64","dns_servers":["fe80::1"],"upstream_routed":true,"enabled":true}`
	items, warnings = compilePluginIPv6AssignmentPlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 0 || len(warnings) != 1 {
		t.Fatalf("items=%+v warnings=%v, want link-local DNS rejection", items, warnings)
	}
}

func TestCompilePluginIPv6AssignmentPlanAcceptsMatchingExplicitSubnetIndex(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginIPv6AssignmentPlansResourceID,
		RecordKey:  "lan-five",
		DataJSON:   `{"parent_interface":"fwdlocal0","target_interface":"br-lan","parent_prefix":"240e:390:6aad:d550::/60","assigned_prefix":"240e:390:6aad:d555::/64","subnet_index":5,"upstream_routed":true,"enabled":true}`,
		Enabled:    true,
	}
	items, warnings := compilePluginIPv6AssignmentPlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 1 || len(warnings) != 0 || items[0].AssignedPrefix != "240e:390:6aad:d555::/64" {
		t.Fatalf("items=%+v warnings=%v, want matching explicit subnet index accepted", items, warnings)
	}

	record.DataJSON = `{"parent_interface":"fwdlocal0","target_interface":"br-lan","parent_prefix":"240e:390:6aad:d550::/60","assigned_prefix":"240e:390:6aad:d554::/64","subnet_index":5,"upstream_routed":true,"enabled":true}`
	items, warnings = compilePluginIPv6AssignmentPlansWithWarnings([]store.PluginRecord{record}, nil)
	if len(items) != 0 || len(warnings) != 1 {
		t.Fatalf("items=%+v warnings=%v, want mismatched explicit subnet index rejected", items, warnings)
	}
}

func TestCompilePluginIPv6AssignmentPlanRejectsOverlap(t *testing.T) {
	t.Parallel()

	record := store.PluginRecord{
		PluginID:   "lan_core",
		ResourceID: pluginIPv6AssignmentPlansResourceID,
		RecordKey:  "lan-a",
		DataJSON:   `{"parent_interface":"wan0","target_interface":"br-lan","parent_prefix":"2001:db8:100::/56","assigned_prefix":"2001:db8:100:1::/64","upstream_routed":true,"enabled":true}`,
		Enabled:    true,
	}
	existing := []IPv6Assignment{{
		ID:              7,
		ParentInterface: "wan0",
		TargetInterface: "vmbr0",
		ParentPrefix:    "2001:db8:100::/56",
		AssignedPrefix:  "2001:db8:100:1::/64",
		Enabled:         true,
	}}
	items, warnings := compilePluginIPv6AssignmentPlansWithWarnings([]store.PluginRecord{record}, existing)
	if len(items) != 0 || len(warnings) != 1 {
		t.Fatalf("items=%+v warnings=%v, want one overlap warning", items, warnings)
	}
}
