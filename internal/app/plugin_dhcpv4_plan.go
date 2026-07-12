package app

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"forward/internal/store"
)

const pluginDHCPv4PlansResourceID = "dhcpv4_plans"

type pluginDHCPv4Plan struct {
	Bridge     string   `json:"bridge"`
	IPv4CIDR   string   `json:"ipv4_cidr"`
	Gateway    string   `json:"gateway"`
	PoolStart  string   `json:"pool_start"`
	PoolEnd    string   `json:"pool_end"`
	DNSServers []string `json:"dns_servers"`
	Remark     string   `json:"remark"`
	Enabled    bool     `json:"enabled"`
}

func loadActivePluginDHCPv4PlanRecords(db sqlRuleStore, cfg *Config) ([]store.PluginRecord, error) {
	if !pluginDHCPv4PlansEnabled(cfg) {
		return nil, nil
	}
	activePlugins := activePluginDHCPv4PlanPluginIDs(db, cfg)
	if len(activePlugins) == 0 {
		return nil, nil
	}
	records, err := store.GetPluginRecordsByResource(db, pluginDHCPv4PlansResourceID)
	if err != nil {
		return nil, err
	}
	filtered := records[:0]
	for _, record := range records {
		if _, ok := activePlugins[record.PluginID]; ok {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

func compilePluginDHCPv4PlansWithWarnings(records []store.PluginRecord, existing []ManagedNetwork) ([]ManagedNetwork, []string) {
	if len(records) == 0 {
		return nil, nil
	}

	usedIDs := make(map[int64]struct{}, len(existing)+len(records))
	usedBridges := make(map[string]string, len(existing)+len(records))
	for _, item := range existing {
		usedIDs[item.ID] = struct{}{}
		item = normalizeManagedNetwork(item)
		if item.Enabled && item.IPv4Enabled && item.Bridge != "" {
			usedBridges[item.Bridge] = fmt.Sprintf("managed network #%d", item.ID)
		}
	}

	sortedRecords := append([]store.PluginRecord(nil), records...)
	sort.Slice(sortedRecords, func(i, j int) bool {
		if sortedRecords[i].PluginID != sortedRecords[j].PluginID {
			return sortedRecords[i].PluginID < sortedRecords[j].PluginID
		}
		return sortedRecords[i].RecordKey < sortedRecords[j].RecordKey
	})

	out := make([]ManagedNetwork, 0, len(sortedRecords))
	warnings := make([]string, 0)
	for _, record := range sortedRecords {
		item, warning := pluginDHCPv4PlanRecordToItem(record, usedIDs, usedBridges)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if item.ID == 0 {
			continue
		}
		out = append(out, item)
		usedIDs[item.ID] = struct{}{}
		usedBridges[item.Bridge] = fmt.Sprintf("plugin %s/%s", record.PluginID, record.RecordKey)
	}
	return out, warnings
}

func pluginDHCPv4PlanRecordToItem(record store.PluginRecord, usedIDs map[int64]struct{}, usedBridges map[string]string) (ManagedNetwork, string) {
	pluginID := strings.TrimSpace(record.PluginID)
	key := strings.TrimSpace(record.RecordKey)
	scope := fmt.Sprintf("plugin %s/%s", pluginID, key)
	if !record.Enabled {
		return ManagedNetwork{}, ""
	}

	var plan pluginDHCPv4Plan
	if err := json.Unmarshal([]byte(record.DataJSON), &plan); err != nil {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if !plan.Enabled {
		return ManagedNetwork{}, ""
	}

	bridge := strings.TrimSpace(plan.Bridge)
	if err := validatePluginControlInterfaceName(bridge, "bridge"); err != nil {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if owner := usedBridges[bridge]; owner != "" {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: bridge %s is already served by %s", scope, bridge, owner)
	}

	id := pluginDHCPv4SyntheticID(pluginID, key)
	if _, exists := usedIDs[id]; exists {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: synthetic id collision", scope)
	}
	dnsServers := make([]string, 0, len(plan.DNSServers))
	for _, value := range plan.DNSServers {
		value = strings.TrimSpace(value)
		if value != "" {
			dnsServers = append(dnsServers, value)
		}
	}
	item := ManagedNetwork{
		ID:                        id,
		Name:                      scope,
		BridgeMode:                managedNetworkBridgeModeExisting,
		Bridge:                    bridge,
		IPv4Enabled:               true,
		IPv4CIDR:                  strings.TrimSpace(plan.IPv4CIDR),
		IPv4Gateway:               strings.TrimSpace(plan.Gateway),
		IPv4PoolStart:             strings.TrimSpace(plan.PoolStart),
		IPv4PoolEnd:               strings.TrimSpace(plan.PoolEnd),
		IPv4DNSServers:            strings.Join(dnsServers, ","),
		IPv6Enabled:               false,
		AutoEgressNAT:             false,
		Remark:                    strings.TrimSpace(plan.Remark),
		Enabled:                   true,
		skipIPv4AddressManagement: true,
	}
	compiled, err := buildManagedNetworkIPv4Plan(item, nil)
	if err != nil {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if len(compiled.DHCPv4.DNSServers) > 8 {
		return ManagedNetwork{}, fmt.Sprintf("%s: skip dhcpv4 plan: dns_servers cannot contain more than 8 addresses", scope)
	}
	item.IPv4CIDR = compiled.AddressSpec.CIDR
	item.IPv4Gateway = compiled.DHCPv4.Gateway
	item.IPv4PoolStart = compiled.DHCPv4.PoolStart
	item.IPv4PoolEnd = compiled.DHCPv4.PoolEnd
	item.IPv4DNSServers = strings.Join(compiled.DHCPv4.DNSServers, ",")
	return item, ""
}

func pluginDHCPv4PlansEnabled(cfg *Config) bool {
	return cfg == nil || cfg.PluginsEnabled()
}

func activePluginDHCPv4PlanPluginIDs(db sqlRuleStore, cfg *Config) map[string]struct{} {
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	out := make(map[string]struct{})
	for _, plugin := range catalog.Plugins {
		if pluginDHCPv4PlansResourceActive(plugin, cfg) {
			out[plugin.ID] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func pluginCatalogHasActiveDHCPv4PlansResource(catalog PluginCatalog, cfg *Config) bool {
	for _, plugin := range catalog.Plugins {
		if pluginDHCPv4PlansResourceActive(plugin, cfg) {
			return true
		}
	}
	return false
}

func pluginDHCPv4PlansResourceActive(plugin LoadedPlugin, cfg *Config) bool {
	return plugin.Status == pluginStatusActive && pluginHasDHCPv4PlansResource(plugin) && pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func pluginHasDHCPv4PlansResource(plugin LoadedPlugin) bool {
	for _, resource := range plugin.Resources {
		if resource.ID == pluginDHCPv4PlansResourceID {
			return true
		}
	}
	return false
}

func pluginResourceAffectsCoreDHCPv4(resource PluginResource) bool {
	return resource.ID == pluginDHCPv4PlansResourceID
}

func pluginDHCPv4SyntheticID(pluginID, key string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("plugin_dhcpv4"))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(pluginID)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(strings.TrimSpace(key)))
	id := int64(h.Sum64() & 0x3fffffffffffffff)
	if id == 0 {
		id = 1
	}
	return -id
}
