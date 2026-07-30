package app

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const pluginDHCPv4PlansResourceID = "dhcpv4_plans"

type pluginDHCPv4Plan struct {
	Bridge       string                        `json:"bridge"`
	IPv4CIDR     string                        `json:"ipv4_cidr"`
	Gateway      string                        `json:"gateway"`
	PoolStart    string                        `json:"pool_start"`
	PoolEnd      string                        `json:"pool_end"`
	DNSServers   []string                      `json:"dns_servers"`
	Reservations []pluginDHCPv4PlanReservation `json:"reservations,omitempty"`
	Remark       string                        `json:"remark"`
	Enabled      bool                          `json:"enabled"`
}

type pluginDHCPv4PlanReservation struct {
	MACAddress  string `json:"mac_address"`
	IPv4Address string `json:"ipv4_address"`
	Remark      string `json:"remark,omitempty"`
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
	networks, _, warnings := compilePluginDHCPv4PlansAndReservationsWithWarnings(records, existing)
	return networks, warnings
}

func compilePluginDHCPv4PlansAndReservationsWithWarnings(records []store.PluginRecord, existing []ManagedNetwork) ([]ManagedNetwork, []ManagedNetworkReservation, []string) {
	if len(records) == 0 {
		return nil, nil, nil
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
	reservations := make([]ManagedNetworkReservation, 0)
	warnings := make([]string, 0)
	for _, record := range sortedRecords {
		item, itemReservations, warning := pluginDHCPv4PlanRecordToItem(record, usedIDs, usedBridges)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if item.ID == 0 {
			continue
		}
		out = append(out, item)
		reservations = append(reservations, itemReservations...)
		usedIDs[item.ID] = struct{}{}
		usedBridges[item.Bridge] = fmt.Sprintf("plugin %s/%s", record.PluginID, record.RecordKey)
	}
	return out, reservations, warnings
}

func pluginDHCPv4PlanRecordToItem(record store.PluginRecord, usedIDs map[int64]struct{}, usedBridges map[string]string) (ManagedNetwork, []ManagedNetworkReservation, string) {
	pluginID := strings.TrimSpace(record.PluginID)
	key := strings.TrimSpace(record.RecordKey)
	scope := fmt.Sprintf("plugin %s/%s", pluginID, key)
	if !record.Enabled {
		return ManagedNetwork{}, nil, ""
	}

	var plan pluginDHCPv4Plan
	if err := json.Unmarshal([]byte(record.DataJSON), &plan); err != nil {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if !plan.Enabled {
		return ManagedNetwork{}, nil, ""
	}

	bridge := strings.TrimSpace(plan.Bridge)
	if err := validatePluginControlInterfaceName(bridge, "bridge"); err != nil {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if owner := usedBridges[bridge]; owner != "" {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: bridge %s is already served by %s", scope, bridge, owner)
	}

	id := pluginDHCPv4SyntheticID(pluginID, key)
	if _, exists := usedIDs[id]; exists {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: synthetic id collision", scope)
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
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	if len(compiled.DHCPv4.DNSServers) > 8 {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: dns_servers cannot contain more than 8 addresses", scope)
	}
	item.IPv4CIDR = compiled.AddressSpec.CIDR
	item.IPv4Gateway = compiled.DHCPv4.Gateway
	item.IPv4PoolStart = compiled.DHCPv4.PoolStart
	item.IPv4PoolEnd = compiled.DHCPv4.PoolEnd
	item.IPv4DNSServers = strings.Join(compiled.DHCPv4.DNSServers, ",")
	reservations, err := compilePluginDHCPv4Reservations(pluginID, key, item.ID, compiled, plan.Reservations)
	if err != nil {
		return ManagedNetwork{}, nil, fmt.Sprintf("%s: skip dhcpv4 plan: %v", scope, err)
	}
	return item, reservations, ""
}

func compilePluginDHCPv4Reservations(pluginID, key string, managedNetworkID int64, plan managedNetworkIPv4Plan, items []pluginDHCPv4PlanReservation) ([]ManagedNetworkReservation, error) {
	if len(items) == 0 {
		return nil, nil
	}
	_, serverIP, subnet, err := normalizeManagedNetworkIPv4CIDR(plan.AddressSpec.CIDR)
	if err != nil || subnet == nil {
		return nil, fmt.Errorf("cannot validate reservations against ipv4_cidr")
	}
	seenMACs := make(map[string]struct{}, len(items))
	seenIPs := make(map[string]struct{}, len(items))
	out := make([]ManagedNetworkReservation, 0, len(items))
	for index, raw := range items {
		macAddress, err := normalizeManagedNetworkReservationMACAddress(raw.MACAddress)
		if err != nil {
			return nil, fmt.Errorf("reservations[%d].mac_address %s", index, err)
		}
		if _, exists := seenMACs[macAddress]; exists {
			return nil, fmt.Errorf("reservations[%d].mac_address duplicates %s", index, macAddress)
		}
		ipv4Address, err := normalizeManagedNetworkIPv4Literal(raw.IPv4Address)
		if err != nil {
			return nil, fmt.Errorf("reservations[%d].ipv4_address %s", index, err)
		}
		ip := parseIPLiteral(ipv4Address).To4()
		if ip == nil || !subnet.Contains(ip) {
			return nil, fmt.Errorf("reservations[%d].ipv4_address must stay inside ipv4_cidr", index)
		}
		if ipv4Address == serverIP {
			return nil, fmt.Errorf("reservations[%d].ipv4_address must not use the gateway address", index)
		}
		if isManagedNetworkIPv4ReservedHost(ip, subnet.IP.To4(), subnet.Mask) {
			return nil, fmt.Errorf("reservations[%d].ipv4_address must use a usable host address", index)
		}
		if _, exists := seenIPs[ipv4Address]; exists {
			return nil, fmt.Errorf("reservations[%d].ipv4_address duplicates %s", index, ipv4Address)
		}
		seenMACs[macAddress] = struct{}{}
		seenIPs[ipv4Address] = struct{}{}
		out = append(out, ManagedNetworkReservation{
			ID:               pluginDHCPv4SyntheticID(pluginID, key+":reservation:"+macAddress),
			ManagedNetworkID: managedNetworkID,
			MACAddress:       macAddress,
			IPv4Address:      ipv4Address,
			Remark:           strings.TrimSpace(raw.Remark),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IPv4Address != out[j].IPv4Address {
			return out[i].IPv4Address < out[j].IPv4Address
		}
		return out[i].MACAddress < out[j].MACAddress
	})
	return out, nil
}

func pluginDHCPv4PlansEnabled(cfg *Config) bool {
	return cfg != nil && cfg.PluginsEnabled()
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
