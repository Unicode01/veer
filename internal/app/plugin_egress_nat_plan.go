package app

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"

	"forward/internal/store"
)

const pluginEgressNATPlansResourceID = "egress_nat_plans"

type pluginEgressNATPlan struct {
	ParentInterface string `json:"parent_interface"`
	ChildInterface  string `json:"child_interface"`
	OutInterface    string `json:"out_interface"`
	OutSourceIP     string `json:"out_source_ip"`
	Protocol        string `json:"protocol"`
	NATType         string `json:"nat_type"`
	RedirectMode    string `json:"redirect_mode"`
	Enabled         bool   `json:"enabled"`
}

func loadPluginEgressNATPlans(db sqlRuleStore, cfg *Config, existing []EgressNAT, snapshot egressNATInterfaceSnapshot) ([]EgressNAT, []string, error) {
	records, err := loadActivePluginEgressNATPlanRecords(db, cfg)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, nil
	}
	items, warnings := compilePluginEgressNATPlansWithWarnings(records, existing, snapshot)
	return items, warnings, nil
}

func loadActivePluginEgressNATPlanRecords(db sqlRuleStore, cfg *Config) ([]store.PluginRecord, error) {
	if !pluginEgressNATPlansEnabled(cfg) {
		return nil, nil
	}
	activePlugins := activePluginEgressNATPlanPluginIDs(db, cfg)
	if len(activePlugins) == 0 {
		return nil, nil
	}
	records, err := store.GetPluginRecordsByResource(db, pluginEgressNATPlansResourceID)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	filtered := records[:0]
	for _, record := range records {
		if _, ok := activePlugins[record.PluginID]; ok {
			filtered = append(filtered, record)
		}
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	return filtered, nil
}

func compilePluginEgressNATPlans(records []store.PluginRecord, existing []EgressNAT, snapshot egressNATInterfaceSnapshot) []EgressNAT {
	items, _ := compilePluginEgressNATPlansWithWarnings(records, existing, snapshot)
	return items
}

func compilePluginEgressNATPlansWithWarnings(records []store.PluginRecord, existing []EgressNAT, snapshot egressNATInterfaceSnapshot) ([]EgressNAT, []string) {
	if len(records) == 0 {
		return nil, nil
	}

	active := make([]EgressNAT, 0, len(existing)+len(records))
	usedIDs := make(map[int64]struct{}, len(existing)+len(records))
	for _, item := range existing {
		usedIDs[item.ID] = struct{}{}
		if item.Enabled {
			active = append(active, normalizeEgressNATScope(item, snapshot.IfaceByName))
		}
	}

	out := make([]EgressNAT, 0, len(records))
	warnings := make([]string, 0)
	for _, record := range records {
		item, warning := pluginEgressNATPlanRecordToItem(record, active, usedIDs, snapshot)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if item.ID == 0 {
			continue
		}
		out = append(out, item)
		active = append(active, normalizeEgressNATScope(item, snapshot.IfaceByName))
		usedIDs[item.ID] = struct{}{}
	}
	return out, warnings
}

func pluginEgressNATPlanRecordToItem(record store.PluginRecord, existing []EgressNAT, usedIDs map[int64]struct{}, snapshot egressNATInterfaceSnapshot) (EgressNAT, string) {
	pluginID := strings.TrimSpace(record.PluginID)
	key := strings.TrimSpace(record.RecordKey)
	scope := fmt.Sprintf("plugin %s/%s", pluginID, key)
	if !record.Enabled {
		return EgressNAT{}, ""
	}

	var plan pluginEgressNATPlan
	if err := json.Unmarshal([]byte(record.DataJSON), &plan); err != nil {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: %v", scope, err)
	}
	if !plan.Enabled {
		return EgressNAT{}, ""
	}

	item := EgressNAT{
		ID:              pluginEgressNATSyntheticID(pluginID, key),
		ParentInterface: strings.TrimSpace(plan.ParentInterface),
		ChildInterface:  strings.TrimSpace(plan.ChildInterface),
		OutInterface:    strings.TrimSpace(plan.OutInterface),
		OutSourceIP:     strings.TrimSpace(plan.OutSourceIP),
		Protocol:        normalizeEgressNATProtocol(plan.Protocol),
		NATType:         normalizeEgressNATType(plan.NATType),
		RedirectMode:    normalizeEgressNATRedirectMode(plan.RedirectMode),
		Enabled:         true,
	}
	if item.ParentInterface == "" {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: parent_interface is required", scope)
	}
	if item.OutInterface == "" {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: out_interface is required", scope)
	}
	if !isValidEgressNATProtocol(item.Protocol) {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: invalid protocol %q", scope, plan.Protocol)
	}
	if !isValidEgressNATType(item.NATType) {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: invalid nat_type %q", scope, plan.NATType)
	}
	if !isValidEgressNATRedirectMode(item.RedirectMode) {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: invalid redirect_mode %q", scope, plan.RedirectMode)
	}
	if _, exists := usedIDs[item.ID]; exists {
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan: synthetic id collision", scope)
	}

	item = normalizeEgressNATScope(item, snapshot.IfaceByName)
	for _, current := range existing {
		if !current.Enabled {
			continue
		}
		if !ruleProtocolsOverlap(item.Protocol, normalizeEgressNATProtocol(current.Protocol)) {
			continue
		}
		if !egressNATScopesOverlap(item, current, snapshot.IfaceByName) {
			continue
		}
		return EgressNAT{}, fmt.Sprintf("%s: skip egress nat plan because it overlaps egress nat #%d", scope, current.ID)
	}
	return item, ""
}

func pluginEgressNATPlansEnabled(cfg *Config) bool {
	return cfg == nil || cfg.PluginsEnabled()
}

func activePluginEgressNATPlanPluginIDs(db sqlRuleStore, cfg *Config) map[string]struct{} {
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	out := make(map[string]struct{})
	for _, plugin := range catalog.Plugins {
		if pluginEgressNATPlansResourceActive(plugin, cfg) {
			out[plugin.ID] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func pluginCatalogHasActiveEgressNATPlansResource(catalog PluginCatalog, cfg *Config) bool {
	for _, plugin := range catalog.Plugins {
		if pluginEgressNATPlansResourceActive(plugin, cfg) {
			return true
		}
	}
	return false
}

func pluginEgressNATPlansResourceActive(plugin LoadedPlugin, cfg *Config) bool {
	if plugin.Status != pluginStatusActive || !pluginHasEgressNATPlansResource(plugin) {
		return false
	}
	return pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func pluginHasEgressNATPlansResource(plugin LoadedPlugin) bool {
	for _, resource := range plugin.Resources {
		if resource.ID == pluginEgressNATPlansResourceID {
			return true
		}
	}
	return false
}

func pluginResourceAffectsCoreEgressNAT(resource PluginResource) bool {
	return resource.ID == pluginEgressNATPlansResourceID
}

func pluginCoreResourceStabilityAllowed(plugin LoadedPlugin, cfg *Config) bool {
	stability := strings.TrimSpace(strings.ToLower(plugin.Stability))
	if stability == "" {
		stability = pluginStabilityLab
	}
	switch stability {
	case pluginStabilityStable, pluginStabilityPreview, pluginStabilityLab:
		return true
	default:
		return false
	}
}

func pluginEgressNATSyntheticID(pluginID, key string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("plugin_egress_nat"))
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
