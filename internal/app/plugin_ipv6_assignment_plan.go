package app

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const pluginIPv6AssignmentPlansResourceID = "ipv6_assignment_plans"

type pluginIPv6AssignmentPlan struct {
	ParentInterface   string   `json:"parent_interface"`
	TargetInterface   string   `json:"target_interface"`
	ParentPrefix      string   `json:"parent_prefix"`
	AssignedPrefix    string   `json:"assigned_prefix"`
	AssignedPrefixLen int      `json:"assigned_prefix_length"`
	SubnetIndex       uint64   `json:"subnet_index"`
	UpstreamRouted    bool     `json:"upstream_routed"`
	ConfigureGateway  bool     `json:"configure_gateway"`
	RejectUnassigned  bool     `json:"reject_unassigned"`
	DNSServers        []string `json:"dns_servers"`
	Remark            string   `json:"remark"`
	Enabled           bool     `json:"enabled"`
}

func loadActivePluginIPv6AssignmentPlanRecordsWithCatalog(db sqlRuleStore, cfg *Config, catalog *PluginCatalog) ([]store.PluginRecord, error) {
	if !pluginIPv6AssignmentPlansEnabled(cfg) {
		return nil, nil
	}
	return loadActivePluginCoreResourceRecords(db, cfg, catalog, pluginIPv6AssignmentPlansResourceID, pluginIPv6AssignmentPlansResourceActive)
}

func compilePluginIPv6AssignmentPlansWithWarnings(records []store.PluginRecord, existing []IPv6Assignment) ([]IPv6Assignment, []string) {
	if len(records) == 0 {
		return nil, nil
	}

	active := make([]IPv6Assignment, 0, len(existing)+len(records))
	usedIDs := make(map[int64]struct{}, len(existing)+len(records))
	for _, item := range existing {
		usedIDs[item.ID] = struct{}{}
		if item.Enabled {
			active = append(active, item)
		}
	}

	out := make([]IPv6Assignment, 0, len(records))
	warnings := make([]string, 0)
	for _, record := range records {
		item, warning := pluginIPv6AssignmentPlanRecordToItem(record, active, usedIDs)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if item.ID == 0 {
			continue
		}
		out = append(out, item)
		active = append(active, item)
		usedIDs[item.ID] = struct{}{}
	}
	return out, warnings
}

func pluginIPv6AssignmentPlanRecordToItem(record store.PluginRecord, existing []IPv6Assignment, usedIDs map[int64]struct{}) (IPv6Assignment, string) {
	pluginID := strings.TrimSpace(record.PluginID)
	key := strings.TrimSpace(record.RecordKey)
	scope := fmt.Sprintf("plugin %s/%s", pluginID, key)
	if !record.Enabled {
		return IPv6Assignment{}, ""
	}

	var plan pluginIPv6AssignmentPlan
	if err := json.Unmarshal([]byte(record.DataJSON), &plan); err != nil {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: %v", scope, err)
	}
	if !plan.Enabled {
		return IPv6Assignment{}, ""
	}

	parentInterface := strings.TrimSpace(plan.ParentInterface)
	targetInterface := strings.TrimSpace(plan.TargetInterface)
	if parentInterface == "" {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: parent_interface is required", scope)
	}
	if targetInterface == "" {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: target_interface is required", scope)
	}
	if parentInterface == targetInterface {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: target_interface must differ from parent_interface", scope)
	}

	parentPrefix, parentNet, err := normalizeIPv6Prefix(plan.ParentPrefix)
	if err != nil {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: invalid parent_prefix: %v", scope, err)
	}
	assignedPrefix := strings.TrimSpace(plan.AssignedPrefix)
	var assignedNet *net.IPNet
	if assignedPrefix == "" {
		prefixLen := plan.AssignedPrefixLen
		if prefixLen == 0 {
			prefixLen = 64
		}
		assignedNet, err = pluginIPv6SubnetByIndex(parentNet, prefixLen, plan.SubnetIndex)
		if err != nil {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: %v", scope, err)
		}
		assignedPrefix = assignedNet.String()
	} else {
		if plan.AssignedPrefixLen != 0 {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: assigned_prefix cannot be combined with assigned_prefix_length", scope)
		}
		assignedPrefix, assignedNet, err = normalizeIPv6Prefix(assignedPrefix)
		if err != nil {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: invalid assigned_prefix: %v", scope, err)
		}
		if plan.SubnetIndex != 0 {
			assignedLen, _ := assignedNet.Mask.Size()
			expected, subnetErr := pluginIPv6SubnetByIndex(parentNet, assignedLen, plan.SubnetIndex)
			if subnetErr != nil || expected.String() != assignedPrefix {
				return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: assigned_prefix does not match subnet_index %d", scope, plan.SubnetIndex)
			}
		}
	}
	if !ipv6PrefixContainsPrefix(parentNet, assignedNet) {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: assigned_prefix must be contained within parent_prefix", scope)
	}

	id := pluginIPv6AssignmentSyntheticID(pluginID, key)
	if _, exists := usedIDs[id]; exists {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: synthetic id collision", scope)
	}
	assignedLen, _ := assignedNet.Mask.Size()
	dnsServers, err := normalizePluginIPv6DNSServers(plan.DNSServers)
	if err != nil {
		return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: %v", scope, err)
	}
	item := IPv6Assignment{
		ID:              id,
		ParentInterface: parentInterface,
		TargetInterface: targetInterface,
		ParentPrefix:    parentPrefix,
		AssignedPrefix:  assignedPrefix,
		Address:         canonicalIPLiteral(assignedNet.IP),
		PrefixLen:       assignedLen,
		Remark:          strings.TrimSpace(plan.Remark),
		Enabled:         true,
		upstreamRouted:  plan.UpstreamRouted,
		dnsServers:      dnsServers,
	}
	if item.Remark == "" {
		item.Remark = fmt.Sprintf("plugin %s/%s", pluginID, key)
	}
	if plan.ConfigureGateway {
		parentLen, _ := parentNet.Mask.Size()
		item.gatewayCIDR, err = pluginIPv6GatewayCIDR(assignedNet, parentLen)
		if err != nil {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: %v", scope, err)
		}
	}
	if plan.RejectUnassigned {
		if !plan.UpstreamRouted {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan: reject_unassigned requires upstream_routed", scope)
		}
		parentLen, _ := parentNet.Mask.Size()
		if parentLen < assignedLen {
			item.rejectPrefix = parentPrefix
		}
	}

	for _, current := range existing {
		if !current.Enabled {
			continue
		}
		hydrateIPv6AssignmentCompatibilityFields(&current)
		_, currentNet, err := normalizeIPv6Prefix(current.AssignedPrefix)
		if err != nil || currentNet == nil {
			continue
		}
		if ipv6PrefixesOverlap(assignedNet, currentNet) {
			return IPv6Assignment{}, fmt.Sprintf("%s: skip ipv6 assignment plan because assigned_prefix overlaps ipv6 assignment #%d", scope, current.ID)
		}
	}
	return item, ""
}

func normalizePluginIPv6DNSServers(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() != nil || ip.To16() == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("dns_servers contains invalid downstream IPv6 DNS address %q", value)
		}
		normalized := canonicalIPLiteral(ip.To16())
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
		if len(out) > 8 {
			return nil, fmt.Errorf("dns_servers cannot contain more than 8 addresses")
		}
	}
	sort.Strings(out)
	return out, nil
}

func pluginIPv6SubnetByIndex(parent *net.IPNet, prefixLen int, index uint64) (*net.IPNet, error) {
	if parent == nil || parent.IP == nil || parent.IP.To4() != nil {
		return nil, fmt.Errorf("parent_prefix must be IPv6")
	}
	parentLen, bits := parent.Mask.Size()
	if parentLen < 0 || bits != 128 || prefixLen < parentLen || prefixLen > 128 {
		return nil, fmt.Errorf("assigned_prefix_length must be between /%d and /128", parentLen)
	}
	extraBits := prefixLen - parentLen
	if extraBits > 64 {
		return nil, fmt.Errorf("assigned subnet selection wider than 64 bits is not supported")
	}
	if extraBits == 0 && index != 0 {
		return nil, fmt.Errorf("subnet_index must be zero when prefix lengths are equal")
	}
	if extraBits > 0 && extraBits < 64 && index >= uint64(1)<<uint(extraBits) {
		return nil, fmt.Errorf("subnet_index %d exceeds /%d capacity", index, prefixLen)
	}

	ip := append(net.IP(nil), parent.IP.Mask(parent.Mask).To16()...)
	for offset := 0; offset < extraBits; offset++ {
		if index&(uint64(1)<<uint(extraBits-1-offset)) == 0 {
			continue
		}
		bit := parentLen + offset
		ip[bit/8] |= byte(1 << uint(7-bit%8))
	}
	mask := net.CIDRMask(prefixLen, 128)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}, nil
}

func pluginIPv6GatewayCIDR(prefix *net.IPNet, displayPrefixLen int) (string, error) {
	if prefix == nil || prefix.IP == nil || prefix.IP.To4() != nil {
		return "", fmt.Errorf("assigned_prefix must be IPv6")
	}
	prefixLen, bits := prefix.Mask.Size()
	if prefixLen < 0 || bits != 128 || prefixLen >= 128 {
		return "", fmt.Errorf("configure_gateway requires an assigned prefix shorter than /128")
	}
	if displayPrefixLen < 0 || displayPrefixLen > prefixLen {
		return "", fmt.Errorf("gateway prefix length must be between /0 and /%d", prefixLen)
	}
	ip := append(net.IP(nil), prefix.IP.Mask(prefix.Mask).To16()...)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
	if !prefix.Contains(ip) {
		return "", fmt.Errorf("assigned_prefix has no usable gateway address")
	}
	return fmt.Sprintf("%s/%d", canonicalIPLiteral(ip), displayPrefixLen), nil
}

func pluginIPv6AssignmentPlansEnabled(cfg *Config) bool {
	return cfg != nil && cfg.PluginsEnabled()
}

func pluginIPv6AssignmentPlansResourceActive(plugin LoadedPlugin, cfg *Config) bool {
	return plugin.Status == pluginStatusActive && pluginHasIPv6AssignmentPlansResource(plugin) && pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func pluginHasIPv6AssignmentPlansResource(plugin LoadedPlugin) bool {
	for _, resource := range plugin.Resources {
		if resource.ID == pluginIPv6AssignmentPlansResourceID {
			return true
		}
	}
	return false
}

func pluginResourceAffectsCoreIPv6Assignments(resource PluginResource) bool {
	return resource.ID == pluginIPv6AssignmentPlansResourceID
}

func pluginIPv6AssignmentSyntheticID(pluginID, key string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("plugin_ipv6_assignment"))
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
