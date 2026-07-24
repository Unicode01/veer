package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

const (
	pluginNetAccessMaxEntries = 128
	pluginNetScopeMaxEntries  = 256
)

var pluginManifestRuntimeFields = map[string]struct{}{
	"actions":            {},
	"builtin":            {},
	"capabilities":       {},
	"hooks":              {},
	"metadata":           {},
	"objects":            {},
	"resources":          {},
	"services":           {},
	"ui":                 {},
	"virtual_interfaces": {},
}

var pluginManifestStaticFields = map[string]struct{}{
	"api_version":   {},
	"compatibility": {},
	"conflicts":     {},
	"control":       {},
	"dependencies":  {},
	"description":   {},
	"id":            {},
	"kind":          {},
	"name":          {},
	"stability":     {},
	"version":       {},
}

func (manifest *PluginManifest) UnmarshalJSON(data []byte) error {
	type rawPluginManifest PluginManifest
	if err := rejectPluginDuplicateJSONKeys(data); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for field := range fields {
		if _, forbidden := pluginManifestRuntimeFields[field]; forbidden {
			return fmt.Errorf("manifest field %q is runtime-owned; register it from control.js instead", field)
		}
		if _, allowed := pluginManifestStaticFields[field]; !allowed {
			return fmt.Errorf("unknown manifest field %q", field)
		}
	}
	var raw rawPluginManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	*manifest = PluginManifest(raw)
	return nil
}

func normalizePluginManifest(manifest *PluginManifest) error {
	manifest.APIVersion = strings.TrimSpace(strings.ToLower(manifest.APIVersion))
	if manifest.APIVersion == "" {
		manifest.APIVersion = pluginAPIVersionV1
	}
	if manifest.APIVersion != pluginAPIVersionV1 {
		return fmt.Errorf("unsupported api_version %q", manifest.APIVersion)
	}

	manifest.ID = strings.TrimSpace(strings.ToLower(manifest.ID))
	if !pluginIDPattern.MatchString(manifest.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	if reservedBuiltinPluginID(manifest.ID) {
		return fmt.Errorf("id %q is reserved for the built-in Veer pipeline", manifest.ID)
	}

	manifest.Name = strings.TrimSpace(manifest.Name)
	if manifest.Name == "" {
		return fmt.Errorf("name is required")
	}
	manifest.Version = strings.TrimSpace(manifest.Version)
	if manifest.Version == "" {
		return fmt.Errorf("version is required")
	}
	version, err := normalizePluginSemanticVersion(manifest.Version)
	if err != nil {
		return fmt.Errorf("version: %w", err)
	}
	manifest.Version = version
	manifest.Description = strings.TrimSpace(manifest.Description)
	manifest.Kind = strings.TrimSpace(strings.ToLower(manifest.Kind))
	if manifest.Kind == "" {
		manifest.Kind = "pipeline"
	}
	if !validPluginKind(manifest.Kind) {
		return fmt.Errorf("kind must be one of pipeline, control, ui")
	}
	manifest.Stability = strings.TrimSpace(strings.ToLower(manifest.Stability))
	if manifest.Stability == "" {
		manifest.Stability = pluginStabilityLab
	}
	if !validPluginStability(manifest.Stability) {
		return fmt.Errorf("stability must be one of lab, preview, stable, deprecated")
	}
	if err := normalizePluginCompatibility(manifest.Compatibility); err != nil {
		return fmt.Errorf("compatibility: %w", err)
	}
	if err := normalizePluginDependencies(manifest.ID, manifest.Dependencies); err != nil {
		return fmt.Errorf("dependencies: %w", err)
	}
	if err := normalizePluginConflicts(manifest.ID, manifest.Conflicts); err != nil {
		return fmt.Errorf("conflicts: %w", err)
	}
	if err := validatePluginRelationshipOverlap(manifest.Dependencies, manifest.Conflicts); err != nil {
		return err
	}

	if manifest.Control != nil {
		if err := normalizePluginControl(manifest.Control); err != nil {
			return fmt.Errorf("control: %w", err)
		}
		if manifest.Control.Main == "" && len(manifest.Control.Permissions) == 0 {
			manifest.Control = nil
		}
	}
	return nil
}

func normalizePluginControl(control *PluginControl) error {
	var err error
	control.Main, err = normalizePluginRelativePath(control.Main)
	if err != nil {
		return fmt.Errorf("main: %w", err)
	}
	if control.Main == "" {
		return fmt.Errorf("main is required")
	}
	control.SHA256 = strings.TrimSpace(strings.ToLower(control.SHA256))
	if control.SHA256 != "" && !pluginHashPattern.MatchString(control.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	control.ResolvedSHA256 = ""
	permissions, err := normalizePluginTokens(control.Permissions, "permission")
	if err != nil {
		return err
	}
	for _, permission := range permissions {
		if !validPluginControlPermission(permission) {
			return fmt.Errorf("permission %q must be one of blob, crypto, ebpf.load, ebpf.map_read, ebpf.map_write, event, hook.attach, kv, metrics, net.admin, net.dns, net.http, net.l2, net.namespace, net.tcp, net.tuntap, net.udp, operation, plugin.action, plugin.event, plugin.register, plugin.resource, resource, secret, timer, ui, worker", permission)
		}
	}
	control.Permissions = permissions
	if err := normalizePluginResourceAccess(control.ResourceAccess); err != nil {
		return fmt.Errorf("resource_access: %w", err)
	}
	if len(control.ResourceAccess) > 0 {
		hasPluginResource := false
		for _, permission := range permissions {
			if permission == "plugin.resource" {
				hasPluginResource = true
				break
			}
		}
		if !hasPluginResource {
			return fmt.Errorf("resource_access requires plugin.resource permission")
		}
	}
	if err := normalizePluginActionAccess(control.ActionAccess); err != nil {
		return fmt.Errorf("action_access: %w", err)
	}
	if len(control.ActionAccess) > 0 {
		hasPluginAction := false
		for _, permission := range permissions {
			if permission == "plugin.action" {
				hasPluginAction = true
				break
			}
		}
		if !hasPluginAction {
			return fmt.Errorf("action_access requires plugin.action permission")
		}
	}
	if err := normalizePluginEventAccess(control.EventAccess); err != nil {
		return fmt.Errorf("event_access: %w", err)
	}
	if len(control.EventAccess) > 0 {
		hasEvent := false
		hasPluginEvent := false
		hasWorker := false
		for _, permission := range permissions {
			switch permission {
			case "event":
				hasEvent = true
			case "plugin.event":
				hasPluginEvent = true
			case "worker":
				hasWorker = true
			}
		}
		if !hasPluginEvent {
			return fmt.Errorf("event_access requires plugin.event permission")
		}
		if !hasEvent || !hasWorker {
			return fmt.Errorf("event_access requires event and worker permissions")
		}
	}
	if err := normalizePluginNetAccess(control.NetAccess); err != nil {
		return fmt.Errorf("net_access: %w", err)
	}
	control.NamespaceAccess, err = normalizePluginNamespacePatterns(control.NamespaceAccess)
	if err != nil {
		return fmt.Errorf("namespace_access: %w", err)
	}
	hasNetAdmin := false
	hasNetDNS := false
	hasNetHTTP := false
	hasNetL2 := false
	hasNetTCP := false
	hasNetUDP := false
	hasNetNamespace := false
	hasNetTunTap := false
	for _, permission := range permissions {
		switch permission {
		case "net.admin":
			hasNetAdmin = true
		case "net.dns":
			hasNetDNS = true
		case "net.http":
			hasNetHTTP = true
		case "net.l2":
			hasNetL2 = true
		case "net.tcp":
			hasNetTCP = true
		case "net.udp":
			hasNetUDP = true
		case "net.namespace":
			hasNetNamespace = true
		case "net.tuntap":
			hasNetTunTap = true
		}
	}
	if (hasNetAdmin || hasNetDNS || hasNetHTTP || hasNetL2 || hasNetTCP || hasNetUDP || hasNetTunTap) && len(control.NetAccess) == 0 {
		return fmt.Errorf("net_access is required when a network data or administration permission is declared")
	}
	if (hasNetNamespace || hasNetTunTap) && len(control.NamespaceAccess) == 0 {
		return fmt.Errorf("namespace_access is required when net.namespace or net.tuntap permission is declared")
	}
	if len(control.NamespaceAccess) > 0 && !hasNetNamespace && !hasNetTunTap {
		return fmt.Errorf("namespace_access requires net.namespace or net.tuntap permission")
	}
	for _, access := range control.NetAccess {
		for _, operation := range access.Operations {
			if operation == "dns" {
				if !hasNetDNS {
					return fmt.Errorf("net_access operation %q requires net.dns permission", operation)
				}
				continue
			}
			if operation == "http" {
				if !hasNetHTTP {
					return fmt.Errorf("net_access operation %q requires net.http permission", operation)
				}
				continue
			}
			if operation == "l2" {
				if !hasNetL2 {
					return fmt.Errorf("net_access operation %q requires net.l2 permission", operation)
				}
				continue
			}
			if operation == "udp" {
				if !hasNetUDP {
					return fmt.Errorf("net_access operation %q requires net.udp permission", operation)
				}
				continue
			}
			if operation == "tcp" {
				if !hasNetTCP {
					return fmt.Errorf("net_access operation %q requires net.tcp permission", operation)
				}
				continue
			}
			if operation == "tuntap" {
				if !hasNetTunTap {
					return fmt.Errorf("net_access operation %q requires net.tuntap permission", operation)
				}
				continue
			}
			if !hasNetAdmin {
				return fmt.Errorf("net_access operation %q requires net.admin permission", operation)
			}
		}
	}
	return nil
}

func normalizePluginNamespacePatterns(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if len(value) > 63 || strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") {
			return nil, fmt.Errorf("namespace pattern %q contains invalid characters or exceeds 63 bytes", value)
		}
		for _, part := range strings.Split(value, "*") {
			if part == "" {
				continue
			}
			for _, char := range part {
				if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' || char == '-' || char == '.' {
					continue
				}
				return nil, fmt.Errorf("namespace pattern %q contains invalid characters", value)
			}
		}
		if value == "." || value == ".." {
			return nil, fmt.Errorf("namespace pattern %q is reserved", value)
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("namespace patterns cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginResourceAccess(access []PluginResourceAccess) error {
	if len(access) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		item.Plugin = strings.TrimSpace(strings.ToLower(item.Plugin))
		if !pluginIDPattern.MatchString(item.Plugin) {
			return fmt.Errorf("[%d].plugin must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(item.Plugin) {
			return fmt.Errorf("[%d].plugin %q is reserved for the built-in Veer pipeline", i, item.Plugin)
		}
		item.Resource = strings.TrimSpace(strings.ToLower(item.Resource))
		if pluginControlReservedResourceID(item.Resource) {
			return fmt.Errorf("[%d].resource %q is reserved for plugin control internals", i, item.Resource)
		}
		if !pluginTokenPattern.MatchString(item.Resource) {
			return fmt.Errorf("[%d].resource must match %s", i, pluginTokenPattern.String())
		}
		methods, err := normalizePluginResourceAccessMethods(item.Methods)
		if err != nil {
			return fmt.Errorf("[%d].methods: %w", i, err)
		}
		item.Methods = methods
		key := item.Plugin + "/" + item.Resource
		if _, exists := seen[key]; exists {
			return fmt.Errorf("[%d]: duplicate resource access %s", i, key)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].Plugin == access[j].Plugin {
			return access[i].Resource < access[j].Resource
		}
		return access[i].Plugin < access[j].Plugin
	})
	return nil
}

func normalizePluginResourceAccessMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("methods cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !validPluginResourceMethod(value) {
			return nil, fmt.Errorf("method %q must be one of list, get, create, update, delete", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("methods cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginActionAccess(access []PluginActionAccess) error {
	if len(access) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		item.Plugin = strings.TrimSpace(strings.ToLower(item.Plugin))
		if !pluginIDPattern.MatchString(item.Plugin) {
			return fmt.Errorf("[%d].plugin must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(item.Plugin) {
			return fmt.Errorf("[%d].plugin %q is reserved for the built-in Veer pipeline", i, item.Plugin)
		}
		actions, err := normalizePluginActionAccessActions(item.Actions)
		if err != nil {
			return fmt.Errorf("[%d].actions: %w", i, err)
		}
		item.Actions = actions
		for _, action := range item.Actions {
			key := item.Plugin + "/" + action
			if _, exists := seen[key]; exists {
				return fmt.Errorf("[%d]: duplicate action access %s", i, key)
			}
			seen[key] = struct{}{}
		}
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].Plugin == access[j].Plugin {
			return strings.Join(access[i].Actions, ",") < strings.Join(access[j].Actions, ",")
		}
		return access[i].Plugin < access[j].Plugin
	})
	return nil
}

func normalizePluginActionAccessActions(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("actions cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !pluginTokenPattern.MatchString(value) {
			return nil, fmt.Errorf("action must match %s", pluginTokenPattern.String())
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("actions cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginEventAccess(access []PluginEventAccess) error {
	if len(access) == 0 {
		return nil
	}
	if len(access) > pluginEventMaxAccessEntries {
		return fmt.Errorf("cannot contain more than %d entries", pluginEventMaxAccessEntries)
	}
	seen := make(map[string]struct{})
	topicCount := 0
	for i := range access {
		item := &access[i]
		item.Plugin = strings.TrimSpace(strings.ToLower(item.Plugin))
		if !pluginIDPattern.MatchString(item.Plugin) {
			return fmt.Errorf("[%d].plugin must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(item.Plugin) {
			return fmt.Errorf("[%d].plugin %q is reserved for the built-in Veer pipeline", i, item.Plugin)
		}
		if len(item.TopicPrefixes) == 0 {
			return fmt.Errorf("[%d].topic_prefixes cannot be empty", i)
		}
		if topicCount > pluginEventMaxAccessTopics-len(item.TopicPrefixes) {
			return fmt.Errorf("topic_prefixes cannot contain more than %d entries in total", pluginEventMaxAccessTopics)
		}
		topicCount += len(item.TopicPrefixes)
		prefixes := make([]string, 0, len(item.TopicPrefixes))
		for j, value := range item.TopicPrefixes {
			prefix := normalizePluginEventTopic(value)
			if prefix == pluginEventTopicPluginLifecycle {
				return fmt.Errorf("[%d].topic_prefixes[%d] %q is reserved for the Veer lifecycle event", i, j, prefix)
			}
			source, ok := pluginCustomEventSource(prefix)
			if !ok || source != item.Plugin {
				return fmt.Errorf("[%d].topic_prefixes[%d] must be plugin.%s or one of its child topics", i, j, item.Plugin)
			}
			key := item.Plugin + "\x00" + prefix
			if _, exists := seen[key]; exists {
				return fmt.Errorf("[%d].topic_prefixes[%d]: duplicate event access %s", i, j, prefix)
			}
			seen[key] = struct{}{}
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		item.TopicPrefixes = prefixes
	}
	sort.Slice(access, func(i, j int) bool {
		if access[i].Plugin == access[j].Plugin {
			return strings.Join(access[i].TopicPrefixes, ",") < strings.Join(access[j].TopicPrefixes, ",")
		}
		return access[i].Plugin < access[j].Plugin
	})
	return nil
}

func normalizePluginNetAccess(access []PluginNetAccess) error {
	if len(access) == 0 {
		return nil
	}
	if len(access) > pluginNetAccessMaxEntries {
		return fmt.Errorf("cannot contain more than %d entries", pluginNetAccessMaxEntries)
	}
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		interfaces, err := normalizePluginInterfacePatterns(item.Interfaces)
		if err != nil {
			return fmt.Errorf("[%d].interfaces: %w", i, err)
		}
		operations, err := normalizePluginNetOperations(item.Operations)
		if err != nil {
			return fmt.Errorf("[%d].operations: %w", i, err)
		}
		item.Interfaces = interfaces
		item.Operations = operations
		item.RemoteHosts, err = normalizePluginRemoteHosts(item.RemoteHosts)
		if err != nil {
			return fmt.Errorf("[%d].remote_hosts: %w", i, err)
		}
		item.RemoteCIDRs, err = normalizePluginRemoteCIDRs(item.RemoteCIDRs)
		if err != nil {
			return fmt.Errorf("[%d].remote_cidrs: %w", i, err)
		}
		item.RemotePorts, err = normalizePluginRemotePorts(item.RemotePorts)
		if err != nil {
			return fmt.Errorf("[%d].remote_ports: %w", i, err)
		}
		if len(item.RemoteHosts) > 0 {
			for _, operation := range operations {
				if operation == "tcp" || operation == "udp" {
					return fmt.Errorf("[%d].remote_hosts cannot scope %s because the raw socket API requires IP addresses", i, operation)
				}
			}
		}
		if (len(item.RemoteHosts) > 0 || len(item.RemoteCIDRs) > 0 || len(item.RemotePorts) > 0) && !pluginNetOperationsContainRemoteEndpoint(operations) {
			return fmt.Errorf("[%d]: remote endpoint scope requires dns, http, tcp, or udp operation", i)
		}
		keyData, _ := json.Marshal(item)
		key := string(keyData)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("[%d]: duplicate net access entry", i)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(access, func(i, j int) bool {
		leftData, _ := json.Marshal(access[i])
		rightData, _ := json.Marshal(access[j])
		left := string(leftData)
		right := string(rightData)
		return left < right
	})
	return nil
}

func normalizePluginRemoteHosts(values []string) ([]string, error) {
	if len(values) > pluginNetScopeMaxEntries {
		return nil, fmt.Errorf("cannot contain more than %d entries", pluginNetScopeMaxEntries)
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(value, ".")))
		if value == "" {
			continue
		}
		if value == "*" {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				out = append(out, value)
			}
			continue
		}
		if strings.HasPrefix(value, "*.") {
			if strings.Contains(value[2:], "*") {
				return nil, fmt.Errorf("host pattern %q may contain only one leading wildcard", value)
			}
			if _, err := normalizePluginControlDNSName(value[2:], false); err != nil {
				return nil, fmt.Errorf("host pattern %q is invalid", value)
			}
		} else {
			if strings.Contains(value, "*") {
				return nil, fmt.Errorf("host pattern %q may use a wildcard only as the complete leftmost label", value)
			}
			if _, err := normalizePluginControlDNSName(value, false); err != nil {
				return nil, fmt.Errorf("host %q is invalid", value)
			}
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginRemoteCIDRs(values []string) ([]string, error) {
	if len(values) > pluginNetScopeMaxEntries {
		return nil, fmt.Errorf("cannot contain more than %d entries", pluginNetScopeMaxEntries)
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		var prefix netip.Prefix
		var err error
		if strings.Contains(value, "/") {
			prefix, err = netip.ParsePrefix(value)
		} else {
			var address netip.Addr
			address, err = netip.ParseAddr(value)
			if err == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			}
		}
		if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("CIDR %q is invalid or non-canonical", value)
		}
		normalized := prefix.Masked().String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginRemotePorts(values []int) ([]int, error) {
	if len(values) > pluginNetScopeMaxEntries {
		return nil, fmt.Errorf("cannot contain more than %d entries", pluginNetScopeMaxEntries)
	}
	seen := make(map[int]struct{}, len(values))
	out := make([]int, 0, len(values))
	for _, value := range values {
		if value < 1 || value > 65535 {
			return nil, fmt.Errorf("port %d is outside 1..65535", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out, nil
}

func pluginNetOperationsContainRemoteEndpoint(operations []string) bool {
	for _, operation := range operations {
		switch operation {
		case "dns", "http", "tcp", "udp":
			return true
		}
	}
	return false
}

func normalizePluginInterfacePatterns(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("interfaces cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") || len(value) > 64 {
			return nil, fmt.Errorf("interface pattern %q contains invalid characters", value)
		}
		if !strings.Contains(value, "*") && len(value) > linuxInterfaceNameMaxBytes {
			return nil, fmt.Errorf("interface pattern %q exceeds %d bytes", value, linuxInterfaceNameMaxBytes)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("interfaces cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginNetOperations(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("operations cannot be empty")
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !validPluginNetOperation(value) {
			return nil, fmt.Errorf("operation %q must be one of addr.write, dns, http, l2, link.create, link.delete, link.master, link.offload, link.read, link.state, neigh.write, route.write, rule.write, tcp, tuntap, udp", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("operations cannot be empty")
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginResource(resource *PluginResource) error {
	resource.ID = strings.TrimSpace(strings.ToLower(resource.ID))
	if pluginControlReservedResourceID(resource.ID) {
		return fmt.Errorf("id %q is reserved for plugin control internals", resource.ID)
	}
	if !pluginTokenPattern.MatchString(resource.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	resource.Description = strings.TrimSpace(resource.Description)
	methods, err := normalizePluginResourceMethods(resource.Methods)
	if err != nil {
		return err
	}
	resource.Methods = methods
	if resource.ControlMethods != nil {
		controlMethods, err := normalizePluginResourceMethodsExplicit(resource.ControlMethods, "control_methods")
		if err != nil {
			return err
		}
		resource.ControlMethods = controlMethods
	}
	resource.RuntimeUpdate = strings.TrimSpace(strings.ToLower(resource.RuntimeUpdate))
	if resource.RuntimeUpdate == "" {
		resource.RuntimeUpdate = "none"
	}
	if !validPluginResourceRuntimeUpdate(resource.RuntimeUpdate) {
		return fmt.Errorf("runtime_update must be one of none, manual, plugin_reconcile, runtime_apply")
	}
	if resource.MaxRecords <= 0 {
		resource.MaxRecords = pluginResourceDefaultMaxRecords
	}
	if resource.MaxRecords > pluginResourceHardMaxRecords {
		return fmt.Errorf("max_records exceeds %d", pluginResourceHardMaxRecords)
	}
	if resource.MaxRecordBytes <= 0 {
		resource.MaxRecordBytes = pluginResourceDefaultMaxRecordBytes
	}
	if resource.MaxRecordBytes > pluginResourceHardMaxRecordBytes {
		return fmt.Errorf("max_record_bytes exceeds %d", pluginResourceHardMaxRecordBytes)
	}
	secretFields, err := normalizePluginTokens(resource.SecretFields, "secret field")
	if err != nil {
		return err
	}
	resource.SecretFields = secretFields
	if err := normalizePluginResourceSchema(resource); err != nil {
		return err
	}
	return nil
}

func normalizePluginResourceMethods(values []string) ([]string, error) {
	if len(values) == 0 {
		values = []string{"list"}
	}
	return normalizePluginResourceMethodsExplicit(values, "methods")
}

func normalizePluginResourceMethodsExplicit(values []string, label string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !validPluginResourceMethod(value) {
			return nil, fmt.Errorf("method %q must be one of list, get, create, update, delete", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s cannot be empty", label)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginAction(action *PluginAction) error {
	action.ID = strings.TrimSpace(strings.ToLower(action.ID))
	if !pluginTokenPattern.MatchString(action.ID) {
		return fmt.Errorf("id must match %s", pluginTokenPattern.String())
	}
	action.Description = strings.TrimSpace(action.Description)
	action.RuntimeUpdate = strings.TrimSpace(strings.ToLower(action.RuntimeUpdate))
	if action.RuntimeUpdate == "" {
		action.RuntimeUpdate = "none"
	}
	if !validPluginActionRuntimeUpdate(action.RuntimeUpdate) {
		return fmt.Errorf("runtime_update must be one of none, plugin_reconcile, runtime_apply, runtime_query")
	}
	if action.MaxPayloadBytes <= 0 {
		action.MaxPayloadBytes = pluginActionDefaultMaxPayloadBytes
	}
	if action.MaxPayloadBytes > pluginActionHardMaxPayloadBytes {
		return fmt.Errorf("max_payload_bytes exceeds %d", pluginActionHardMaxPayloadBytes)
	}
	if err := normalizePluginActionSchemas(action); err != nil {
		return err
	}
	return nil
}

func normalizePluginObject(object *PluginObject) error {
	object.ID = strings.TrimSpace(strings.ToLower(object.ID))
	if !pluginIDPattern.MatchString(object.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	object.Path = strings.TrimSpace(object.Path)
	object.SelectedArch = ""
	if object.Path != "" && !strings.HasPrefix(object.Path, "builtin:") {
		cleanPath, err := normalizePluginRelativePath(object.Path)
		if err != nil {
			return fmt.Errorf("path: %w", err)
		}
		if cleanPath == "" {
			return fmt.Errorf("path is required")
		}
		object.Path = cleanPath
	}
	object.SHA256 = strings.TrimSpace(strings.ToLower(object.SHA256))
	if object.Path == "" && object.SHA256 != "" {
		return fmt.Errorf("sha256 requires path when no fallback object is declared")
	}
	if object.SHA256 != "" && !pluginHashPattern.MatchString(object.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	if len(object.Variants) > 16 {
		return fmt.Errorf("variants exceed the limit of 16")
	}
	seenArchitectures := make(map[string]struct{}, len(object.Variants))
	for i := range object.Variants {
		variant := &object.Variants[i]
		variant.Architecture = normalizePluginObjectArchitecture(variant.Architecture)
		if !pluginTokenPattern.MatchString(variant.Architecture) {
			return fmt.Errorf("variants[%d].architecture must match %s", i, pluginTokenPattern.String())
		}
		if _, exists := seenArchitectures[variant.Architecture]; exists {
			return fmt.Errorf("variants[%d]: duplicate architecture %q", i, variant.Architecture)
		}
		seenArchitectures[variant.Architecture] = struct{}{}
		cleanPath, err := normalizePluginRelativePath(strings.TrimSpace(variant.Path))
		if err != nil {
			return fmt.Errorf("variants[%d].path: %w", i, err)
		}
		if cleanPath == "" {
			return fmt.Errorf("variants[%d].path is required", i)
		}
		variant.Path = cleanPath
		variant.SHA256 = strings.TrimSpace(strings.ToLower(variant.SHA256))
		if variant.SHA256 != "" && !pluginHashPattern.MatchString(variant.SHA256) {
			return fmt.Errorf("variants[%d].sha256 must be a lowercase 64-character hex digest", i)
		}
	}
	if object.Path == "" && len(object.Variants) == 0 {
		return fmt.Errorf("path or variants is required")
	}
	object.Description = strings.TrimSpace(object.Description)

	seenPrograms := make(map[string]struct{}, len(object.Programs))
	for i := range object.Programs {
		if err := normalizePluginObjectProgram(&object.Programs[i]); err != nil {
			return fmt.Errorf("programs[%d]: %w", i, err)
		}
		if _, exists := seenPrograms[object.Programs[i].ID]; exists {
			return fmt.Errorf("programs[%d]: duplicate id %q", i, object.Programs[i].ID)
		}
		seenPrograms[object.Programs[i].ID] = struct{}{}
	}
	if len(object.StateMaps) > pluginObjectStateMapLimit {
		return fmt.Errorf("state_maps exceed the limit of %d", pluginObjectStateMapLimit)
	}
	seenStateMaps := make(map[string]struct{}, len(object.StateMaps))
	for i := range object.StateMaps {
		stateMap := &object.StateMaps[i]
		stateMap.Name = strings.TrimSpace(stateMap.Name)
		if !pluginBPFMapPattern.MatchString(stateMap.Name) {
			return fmt.Errorf("state_maps[%d].name must match %s", i, pluginBPFMapPattern.String())
		}
		if _, reserved := pluginControlReservedMapNames[stateMap.Name]; reserved {
			return fmt.Errorf("state_maps[%d].name %q is reserved by Veer", i, stateMap.Name)
		}
		if _, duplicate := seenStateMaps[stateMap.Name]; duplicate {
			return fmt.Errorf("state_maps[%d]: duplicate map %q", i, stateMap.Name)
		}
		seenStateMaps[stateMap.Name] = struct{}{}
		stateMap.Policy = strings.TrimSpace(strings.ToLower(stateMap.Policy))
		stateMap.MigrateFrom = strings.TrimSpace(stateMap.MigrateFrom)
		switch stateMap.Policy {
		case pluginObjectMapPreserve:
			if stateMap.SchemaVersion < 1 || stateMap.SchemaVersion > pluginObjectMapSchemaVersionMax {
				return fmt.Errorf("state_maps[%d].schema_version must be between 1 and %d for preserve policy", i, pluginObjectMapSchemaVersionMax)
			}
			if stateMap.MigrateFrom != "" {
				return fmt.Errorf("state_maps[%d].migrate_from is only valid for migrate policy", i)
			}
		case pluginObjectMapReset:
			if stateMap.SchemaVersion != 0 {
				return fmt.Errorf("state_maps[%d].schema_version must be omitted for reset policy", i)
			}
			if stateMap.MigrateFrom != "" {
				return fmt.Errorf("state_maps[%d].migrate_from is only valid for migrate policy", i)
			}
		case pluginObjectMapMigrate:
			if stateMap.SchemaVersion < 1 || stateMap.SchemaVersion > pluginObjectMapSchemaVersionMax {
				return fmt.Errorf("state_maps[%d].schema_version must be between 1 and %d for migrate policy", i, pluginObjectMapSchemaVersionMax)
			}
			if !pluginBPFMapPattern.MatchString(stateMap.MigrateFrom) || stateMap.MigrateFrom == stateMap.Name {
				return fmt.Errorf("state_maps[%d].migrate_from must name a different declared state map", i)
			}
			if _, reserved := pluginControlReservedMapNames[stateMap.MigrateFrom]; reserved {
				return fmt.Errorf("state_maps[%d].migrate_from %q is reserved by Veer", i, stateMap.MigrateFrom)
			}
		default:
			return fmt.Errorf("state_maps[%d].policy must be preserve, migrate, or reset", i)
		}
	}
	stateMapContracts := make(map[string]PluginObjectStateMap, len(object.StateMaps))
	for _, stateMap := range object.StateMaps {
		stateMapContracts[stateMap.Name] = stateMap
	}
	for i, stateMap := range object.StateMaps {
		if stateMap.Policy != pluginObjectMapMigrate {
			continue
		}
		source, exists := stateMapContracts[stateMap.MigrateFrom]
		if !exists || source.Policy != pluginObjectMapPreserve {
			return fmt.Errorf("state_maps[%d].migrate_from %q must be declared with preserve policy", i, stateMap.MigrateFrom)
		}
		if source.SchemaVersion >= stateMap.SchemaVersion {
			return fmt.Errorf("state_maps[%d] migration schema_version %d must be greater than source %s version %d", i, stateMap.SchemaVersion, source.Name, source.SchemaVersion)
		}
	}
	sort.Slice(object.StateMaps, func(i, j int) bool { return object.StateMaps[i].Name < object.StateMaps[j].Name })
	return nil
}

func pluginObjectStateMapsEqual(left, right []PluginObjectStateMap) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func normalizePluginObjectArchitecture(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "x86_64", "x64":
		return "amd64"
	case "aarch64":
		return "arm64"
	case "armv6", "armv6l", "armv7", "armv7l", "armhf":
		return "arm"
	default:
		return value
	}
}

func normalizePluginObjectProgram(program *PluginObjectProgram) error {
	program.ID = strings.TrimSpace(strings.ToLower(program.ID))
	if !pluginIDPattern.MatchString(program.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	program.Section = strings.TrimSpace(program.Section)
	if program.Section == "" {
		return fmt.Errorf("section is required")
	}
	if strings.Contains(program.Section, "\x00") || len(program.Section) > 128 {
		return fmt.Errorf("section contains invalid characters")
	}
	program.Type = strings.TrimSpace(strings.ToLower(program.Type))
	if program.Type == "" {
		program.Type = kernelEngineTC
	}
	if !validPluginObjectProgramType(program.Type) {
		return fmt.Errorf("type must be one of tc, xdp, control")
	}
	return nil
}

func normalizePluginVirtualInterface(vif *PluginVirtualInterface) error {
	vif.ID = strings.TrimSpace(strings.ToLower(vif.ID))
	if !pluginIDPattern.MatchString(vif.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	vif.Type = strings.TrimSpace(strings.ToLower(vif.Type))
	if vif.Type == "" {
		vif.Type = "logical"
	}
	if !pluginTokenPattern.MatchString(vif.Type) {
		return fmt.Errorf("type must match %s", pluginTokenPattern.String())
	}
	vif.Description = strings.TrimSpace(vif.Description)
	return nil
}

func normalizePluginHook(hook *PluginHook) error {
	hook.ID = strings.TrimSpace(strings.ToLower(hook.ID))
	if !pluginIDPattern.MatchString(hook.ID) {
		return fmt.Errorf("id must match %s", pluginIDPattern.String())
	}
	hook.Engine = strings.TrimSpace(strings.ToLower(hook.Engine))
	if !validPluginHookEngine(hook.Engine) {
		return fmt.Errorf("engine must be one of tc, xdp, control")
	}
	hook.Attach = strings.TrimSpace(strings.ToLower(hook.Attach))
	if hook.Attach == "" {
		if hook.Engine == "control" {
			hook.Attach = "none"
		} else {
			hook.Attach = "ingress"
		}
	}
	if !validPluginHookAttach(hook.Attach) {
		return fmt.Errorf("attach must be one of ingress, egress, both, none")
	}
	hook.Stage = strings.TrimSpace(strings.ToLower(hook.Stage))
	if !pluginTokenPattern.MatchString(hook.Stage) {
		return fmt.Errorf("stage must match %s", pluginTokenPattern.String())
	}
	if hook.Engine != "control" && !validPluginDataplaneHookStage(hook.Stage) {
		return fmt.Errorf("stage must be one of forward, reply, pre_forward, post_lookup, post_apply, pre_reply, post_reply, post_reply_apply")
	}
	if hook.Priority < -100000 || hook.Priority > 100000 {
		return fmt.Errorf("priority out of range")
	}
	before, err := normalizePluginHookOrderReferences(hook.Before, "before")
	if err != nil {
		return err
	}
	after, err := normalizePluginHookOrderReferences(hook.After, "after")
	if err != nil {
		return err
	}
	if err := validatePluginHookOrderReferenceSets(before, after); err != nil {
		return err
	}
	hook.Before = before
	hook.After = after
	hook.Program = strings.TrimSpace(hook.Program)
	if hook.Engine != "control" && hook.Program == "" {
		return fmt.Errorf("program is required for tc/xdp hooks")
	}
	if strings.Contains(hook.Program, "\x00") || len(hook.Program) > 160 {
		return fmt.Errorf("program contains invalid characters")
	}
	hook.Mode = strings.TrimSpace(strings.ToLower(hook.Mode))
	if hook.Mode == "" {
		if hook.Engine == "control" {
			hook.Mode = "control"
		} else {
			hook.Mode = "observe"
		}
	}
	if !validPluginHookMode(hook.Mode) {
		return fmt.Errorf("mode must be one of observe, rewrite, redirect, drop, control")
	}
	context, err := normalizePluginTokens(hook.Context, "context")
	if err != nil {
		return err
	}
	for _, item := range context {
		if !validPluginHookContext(item) {
			return fmt.Errorf("context %q must be one of %s, %s", item, pluginHookContextTCPluginCtxV4, pluginHookContextTCPluginCtxV6)
		}
	}
	hook.Context = context
	packetMetadata, err := normalizePluginPacketMetadataBindings(hook.PacketMetadata)
	if err != nil {
		return err
	}
	if len(packetMetadata) > 0 && hook.Engine != kernelEngineTC {
		return fmt.Errorf("packet_metadata is only available to tc hooks")
	}
	hook.PacketMetadata = packetMetadata
	interfaces, err := normalizePluginInterfaceNames(hook.Interfaces)
	if err != nil {
		return err
	}
	hook.Interfaces = interfaces
	return nil
}

func normalizePluginPacketMetadataBindings(values []PluginPacketMetadataBinding) ([]PluginPacketMetadataBinding, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) > pluginPacketMetadataBindingLimit {
		return nil, fmt.Errorf("packet_metadata exceeds the limit of %d", pluginPacketMetadataBindingLimit)
	}
	seenSlots := make(map[int]struct{}, len(values))
	out := make([]PluginPacketMetadataBinding, 0, len(values))
	for index, raw := range values {
		binding := raw
		if binding.Slot < 0 || binding.Slot >= pluginPacketMetadataBindingLimit {
			return nil, fmt.Errorf("packet_metadata[%d].slot must be between 0 and %d", index, pluginPacketMetadataBindingLimit-1)
		}
		if _, exists := seenSlots[binding.Slot]; exists {
			return nil, fmt.Errorf("packet_metadata contains duplicate local slot %d", binding.Slot)
		}
		seenSlots[binding.Slot] = struct{}{}
		binding.Namespace = strings.TrimSpace(strings.ToLower(binding.Namespace))
		parts := strings.Split(binding.Namespace, "/")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) != 2 || !pluginIDPattern.MatchString(parts[0]) || !pluginTokenPattern.MatchString(parts[1]) {
			return nil, fmt.Errorf("packet_metadata[%d].namespace must use plugin_id/name", index)
		}
		binding.Namespace = parts[0] + "/" + parts[1]
		if binding.SchemaVersion == 0 {
			binding.SchemaVersion = 1
		}
		if binding.SchemaVersion < 1 || binding.SchemaVersion > pluginObjectMapSchemaVersionMax {
			return nil, fmt.Errorf("packet_metadata[%d].schema_version must be between 1 and %d", index, pluginObjectMapSchemaVersionMax)
		}
		if binding.MaxBytes == 0 {
			binding.MaxBytes = pluginPacketMetadataPayloadMaxBytes
		}
		if binding.MaxBytes < 1 || binding.MaxBytes > pluginPacketMetadataPayloadMaxBytes {
			return nil, fmt.Errorf("packet_metadata[%d].max_bytes must be between 1 and %d", index, pluginPacketMetadataPayloadMaxBytes)
		}
		binding.Access = strings.TrimSpace(strings.ToLower(binding.Access))
		if binding.Access == "" {
			binding.Access = pluginPacketMetadataAccessRead
		}
		if binding.Access != pluginPacketMetadataAccessRead && binding.Access != pluginPacketMetadataAccessReadWrite {
			return nil, fmt.Errorf("packet_metadata[%d].access must be one of %s, %s", index, pluginPacketMetadataAccessRead, pluginPacketMetadataAccessReadWrite)
		}
		out = append(out, binding)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slot < out[j].Slot })
	return out, nil
}

func normalizePluginUI(ui *PluginUI) error {
	var err error
	ui.StaticDir, err = normalizePluginRelativePath(ui.StaticDir)
	if err != nil {
		return fmt.Errorf("static_dir: %w", err)
	}
	ui.Entry, err = normalizePluginRelativePath(ui.Entry)
	if err != nil {
		return fmt.Errorf("entry: %w", err)
	}
	ui.Page = strings.TrimSpace(strings.ToLower(ui.Page))
	if ui.Page != "" {
		if !pluginIDPattern.MatchString(ui.Page) {
			return fmt.Errorf("page must match %s", pluginIDPattern.String())
		}
		switch ui.Page {
		case "plugins", "diagnostics":
			return fmt.Errorf("page %q is reserved", ui.Page)
		}
	}
	ui.PageTitle = strings.TrimSpace(ui.PageTitle)
	if strings.Contains(ui.PageTitle, "\x00") || len(ui.PageTitle) > 64 {
		return fmt.Errorf("page_title contains invalid characters")
	}
	ui.SHA256 = strings.TrimSpace(strings.ToLower(ui.SHA256))
	if ui.SHA256 != "" && !pluginHashPattern.MatchString(ui.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase 64-character hex digest")
	}
	if err := normalizePluginUIResourceAccess(ui.Resources); err != nil {
		return fmt.Errorf("resources: %w", err)
	}
	if len(ui.Actions) > 0 {
		actions, err := normalizePluginActionAccessActions(ui.Actions)
		if err != nil {
			return fmt.Errorf("actions: %w", err)
		}
		ui.Actions = actions
	}
	if err := normalizePluginResourceAccess(ui.ResourceAccess); err != nil {
		return fmt.Errorf("resource_access: %w", err)
	}
	for i, access := range ui.ResourceAccess {
		for _, method := range access.Methods {
			if method != "list" && method != "get" {
				return fmt.Errorf("resource_access[%d].methods: cross-plugin UI access supports only list and get", i)
			}
		}
	}
	ui.ResolvedSHA256 = ""
	return nil
}

func normalizePluginUIResourceAccess(access []PluginUIResourceAccess) error {
	seen := make(map[string]struct{}, len(access))
	for i := range access {
		item := &access[i]
		item.Resource = strings.TrimSpace(strings.ToLower(item.Resource))
		if pluginControlReservedResourceID(item.Resource) {
			return fmt.Errorf("[%d].resource %q is reserved for plugin control internals", i, item.Resource)
		}
		if !pluginTokenPattern.MatchString(item.Resource) {
			return fmt.Errorf("[%d].resource must match %s", i, pluginTokenPattern.String())
		}
		methods, err := normalizePluginResourceAccessMethods(item.Methods)
		if err != nil {
			return fmt.Errorf("[%d].methods: %w", i, err)
		}
		item.Methods = methods
		if _, exists := seen[item.Resource]; exists {
			return fmt.Errorf("[%d]: duplicate resource access %s", i, item.Resource)
		}
		seen[item.Resource] = struct{}{}
	}
	sort.Slice(access, func(i, j int) bool { return access[i].Resource < access[j].Resource })
	return nil
}

func normalizePluginTokens(values []string, label string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if !pluginTokenPattern.MatchString(value) {
			return nil, fmt.Errorf("%s %q must match %s", label, value, pluginTokenPattern.String())
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func normalizePluginInterfaceNames(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "\x00") || strings.ContainsAny(value, "/\\ \t\r\n") || len(value) > linuxInterfaceNameMaxBytes {
			return nil, fmt.Errorf("interface %q contains invalid characters", value)
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out, nil
}

func validPluginKind(value string) bool {
	switch value {
	case "pipeline", "control", "ui":
		return true
	default:
		return false
	}
}

func validPluginStability(value string) bool {
	switch value {
	case pluginStabilityLab, pluginStabilityPreview, pluginStabilityStable, pluginStabilityDeprecated:
		return true
	default:
		return false
	}
}

func validPluginHookEngine(value string) bool {
	switch value {
	case kernelEngineTC, kernelEngineXDP, "control":
		return true
	default:
		return false
	}
}

func validPluginObjectProgramType(value string) bool {
	switch value {
	case kernelEngineTC, kernelEngineXDP, "control":
		return true
	default:
		return false
	}
}

func validPluginHookAttach(value string) bool {
	switch value {
	case "ingress", "egress", "both", "none":
		return true
	default:
		return false
	}
}

func validPluginHookMode(value string) bool {
	switch value {
	case "observe", "rewrite", "redirect", "drop", "control":
		return true
	default:
		return false
	}
}

func validPluginHookContext(value string) bool {
	switch value {
	case pluginHookContextTCPluginCtxV4, pluginHookContextTCPluginCtxV6:
		return true
	default:
		return false
	}
}

func validPluginResourceMethod(value string) bool {
	switch value {
	case "list", "get", "create", "update", "delete":
		return true
	default:
		return false
	}
}

func validPluginResourceRuntimeUpdate(value string) bool {
	switch value {
	case "none", "manual", "plugin_reconcile", "runtime_apply":
		return true
	default:
		return false
	}
}

func validPluginActionRuntimeUpdate(value string) bool {
	switch value {
	case "none", "plugin_reconcile", "runtime_apply", "runtime_query":
		return true
	default:
		return false
	}
}

func validPluginControlPermission(value string) bool {
	switch value {
	case "blob", "crypto", "ebpf.load", "ebpf.map_read", "ebpf.map_write", "event", "hook.attach", "kv", "metrics", "net.admin", "net.dns", "net.http", "net.l2", "net.namespace", "net.tcp", "net.tuntap", "net.udp", "operation", "plugin.action", "plugin.event", "plugin.register", "plugin.resource", "resource", "secret", "timer", "ui", "worker":
		return true
	default:
		return false
	}
}

func validPluginDataplaneHookStage(value string) bool {
	switch value {
	case pluginPipelineDirectionForward,
		pluginPipelineDirectionReply,
		pluginPipelineStagePreForward,
		pluginPipelineStagePostLookup,
		pluginPipelineStagePostApply,
		pluginPipelineStagePreReply,
		pluginPipelineStagePostReply,
		pluginPipelineStageReplyApply:
		return true
	default:
		return false
	}
}

func validPluginNetOperation(value string) bool {
	switch value {
	case "addr.write", "dns", "http", "l2", "link.create", "link.delete", "link.master", "link.offload", "link.read", "link.state", "neigh.write", "route.write", "rule.write", "tcp", "tuntap", "udp":
		return true
	default:
		return false
	}
}
