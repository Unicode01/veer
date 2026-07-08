package app

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"forward/internal/store"
)

const pluginForwardRulePlansResourceID = "forward_rule_plans"

type pluginForwardRulePlan struct {
	InInterface      string `json:"in_interface"`
	InIP             string `json:"in_ip"`
	InPort           int    `json:"in_port"`
	OutInterface     string `json:"out_interface"`
	OutIP            string `json:"out_ip"`
	OutSourceIP      string `json:"out_source_ip"`
	OutPort          int    `json:"out_port"`
	Protocol         string `json:"protocol"`
	Remark           string `json:"remark"`
	Tag              string `json:"tag"`
	Enabled          bool   `json:"enabled"`
	Transparent      bool   `json:"transparent"`
	EnginePreference string `json:"engine_preference"`
}

func loadActivePluginForwardRulePlanRecords(db sqlRuleStore, cfg *Config) ([]store.PluginRecord, error) {
	if !pluginForwardRulePlansEnabled(cfg) {
		return nil, nil
	}
	activePlugins := activePluginForwardRulePlanPluginIDs(cfg)
	if len(activePlugins) == 0 {
		return nil, nil
	}
	records, err := store.GetPluginRecordsByResource(db, pluginForwardRulePlansResourceID)
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

func loadPluginForwardRules(db sqlRuleStore, cfg *Config, existingRules []Rule, existingSites []Site, existingRanges []PortRange, nextID *int64) ([]Rule, []string, error) {
	records, err := loadActivePluginForwardRulePlanRecords(db, cfg)
	if err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return nil, nil, nil
	}
	knownIfaces, hostAddrs, err := loadHostValidationData()
	if err != nil {
		return nil, nil, err
	}
	rules, warnings := compilePluginForwardRulePlansWithWarnings(records, existingRules, existingSites, existingRanges, knownIfaces, hostAddrs, nextID)
	return rules, warnings, nil
}

func compilePluginForwardRulePlansWithWarnings(records []store.PluginRecord, existingRules []Rule, existingSites []Site, existingRanges []PortRange, knownIfaces map[string]struct{}, hostAddrs hostInterfaceAddrs, nextID *int64) ([]Rule, []string) {
	if len(records) == 0 {
		return nil, nil
	}
	if nextID == nil {
		start := maxRuleID(existingRules) + 1
		nextID = &start
	}
	if *nextID <= 0 {
		*nextID = maxRuleID(existingRules) + 1
	}

	activeRules := make([]Rule, 0, len(existingRules)+len(records))
	usedIDs := make(map[int64]struct{}, len(existingRules)+len(records))
	for _, rule := range existingRules {
		usedIDs[rule.ID] = struct{}{}
		if rule.Enabled {
			activeRules = append(activeRules, rule)
		}
	}

	out := make([]Rule, 0, len(records))
	warnings := make([]string, 0)
	for _, record := range records {
		rule, warning := pluginForwardRulePlanRecordToRule(record, activeRules, existingSites, existingRanges, usedIDs, knownIfaces, hostAddrs, nextID)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if rule.ID == 0 {
			continue
		}
		out = append(out, rule)
		activeRules = append(activeRules, rule)
		usedIDs[rule.ID] = struct{}{}
	}
	return out, warnings
}

func pluginForwardRulePlanRecordToRule(record store.PluginRecord, existingRules []Rule, existingSites []Site, existingRanges []PortRange, usedIDs map[int64]struct{}, knownIfaces map[string]struct{}, hostAddrs hostInterfaceAddrs, nextID *int64) (Rule, string) {
	pluginID := strings.TrimSpace(record.PluginID)
	key := strings.TrimSpace(record.RecordKey)
	scope := fmt.Sprintf("plugin %s/%s", pluginID, key)
	if !record.Enabled {
		return Rule{}, ""
	}

	var plan pluginForwardRulePlan
	if err := json.Unmarshal([]byte(record.DataJSON), &plan); err != nil {
		return Rule{}, fmt.Sprintf("%s: skip forward rule plan: %v", scope, err)
	}
	if !plan.Enabled {
		return Rule{}, ""
	}

	rule := Rule{
		InInterface:      strings.TrimSpace(plan.InInterface),
		InIP:             strings.TrimSpace(plan.InIP),
		InPort:           plan.InPort,
		OutInterface:     strings.TrimSpace(plan.OutInterface),
		OutIP:            strings.TrimSpace(plan.OutIP),
		OutSourceIP:      strings.TrimSpace(plan.OutSourceIP),
		OutPort:          plan.OutPort,
		Protocol:         strings.TrimSpace(plan.Protocol),
		Remark:           strings.TrimSpace(plan.Remark),
		Tag:              strings.TrimSpace(plan.Tag),
		Enabled:          true,
		Transparent:      plan.Transparent,
		EnginePreference: strings.TrimSpace(plan.EnginePreference),
	}
	normalized, issues := normalizeAndValidateRule(rule, "plugin", 1, false, knownIfaces, hostAddrs)
	if len(issues) > 0 {
		return Rule{}, fmt.Sprintf("%s: skip forward rule plan: %s", scope, summarizeRuleIssues(issues))
	}
	id, err := allocatePluginForwardSyntheticRuleID(nextID, usedIDs)
	if err != nil {
		return Rule{}, fmt.Sprintf("%s: skip forward rule plan: %v", scope, err)
	}
	normalized.ID = id
	normalized.Enabled = true

	ruleStates := projectExistingRuleStates(existingRules)
	ruleStates = append(ruleStates, projectedRuleState{
		Rule:         normalized,
		ContentScope: "create",
		ContentIndex: 1,
		EnableScope:  "create",
		EnableIndex:  1,
	})
	if issues := detectProjectedConflicts(ruleStates, projectExistingSiteStates(existingSites), projectExistingRangeStates(existingRanges)); len(issues) > 0 {
		return Rule{}, fmt.Sprintf("%s: skip forward rule plan: %s", scope, summarizeRuleIssues(issues))
	}
	return normalized, ""
}

func allocatePluginForwardSyntheticRuleID(nextID *int64, usedIDs map[int64]struct{}) (int64, error) {
	if nextID == nil {
		return 0, fmt.Errorf("synthetic rule id allocator is unavailable")
	}
	if *nextID <= 0 {
		*nextID = 1
	}
	for {
		if *nextID == math.MaxInt64 {
			return 0, fmt.Errorf("synthetic rule id space exhausted")
		}
		id := *nextID
		*nextID = *nextID + 1
		if id <= 0 {
			continue
		}
		if _, exists := usedIDs[id]; exists {
			continue
		}
		return id, nil
	}
}

func pluginForwardRulePlansEnabled(cfg *Config) bool {
	return cfg == nil || cfg.PluginsEnabled()
}

func activePluginForwardRulePlanPluginIDs(cfg *Config) map[string]struct{} {
	catalog := loadPluginCatalogWithControlRegistration(cfg)
	out := make(map[string]struct{})
	for _, plugin := range catalog.Plugins {
		if pluginForwardRulePlansResourceActive(plugin, cfg) {
			out[plugin.ID] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func pluginCatalogHasActiveForwardRulePlansResource(catalog PluginCatalog, cfg *Config) bool {
	for _, plugin := range catalog.Plugins {
		if pluginForwardRulePlansResourceActive(plugin, cfg) {
			return true
		}
	}
	return false
}

func pluginForwardRulePlansResourceActive(plugin LoadedPlugin, cfg *Config) bool {
	if plugin.Status != pluginStatusActive || !pluginHasForwardRulePlansResource(plugin) {
		return false
	}
	return pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func pluginHasForwardRulePlansResource(plugin LoadedPlugin) bool {
	for _, resource := range plugin.Resources {
		if resource.ID == pluginForwardRulePlansResourceID {
			return true
		}
	}
	return false
}

func pluginResourceAffectsCoreForwardRules(resource PluginResource) bool {
	return resource.ID == pluginForwardRulePlansResourceID
}

func maxRuleID(rules []Rule) int64 {
	maxID := int64(0)
	for _, rule := range rules {
		if rule.ID > maxID {
			maxID = rule.ID
		}
	}
	return maxID
}
