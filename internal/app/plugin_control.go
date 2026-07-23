package app

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
)

func resolvePluginControl(plugin *LoadedPlugin) error {
	if plugin == nil || plugin.Control == nil || plugin.Control.Main == "" {
		return nil
	}
	data, _, err := readPluginRootedRegularFile(plugin.rootDir, plugin.Control.Main, pluginControlMaxSize)
	if err != nil {
		if pluginPathEscapesRoot(err) {
			return fmt.Errorf("control.main escapes plugin root")
		}
		return fmt.Errorf("control.main: %w", err)
	}
	mainPath := filepath.Join(plugin.rootDir, filepath.FromSlash(plugin.Control.Main))
	cleanRoot, err := filepath.Abs(plugin.rootDir)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(cleanRoot)
	if err != nil {
		return fmt.Errorf("resolve plugin root: %w", err)
	}
	cleanMain, err := filepath.Abs(mainPath)
	if err != nil {
		return fmt.Errorf("resolve control.main: %w", err)
	}
	if !pathWithinRoot(cleanRoot, cleanMain) {
		return fmt.Errorf("control.main escapes plugin root")
	}
	realMain, err := filepath.EvalSymlinks(cleanMain)
	if err != nil {
		return fmt.Errorf("control.main: %w", err)
	}
	if !pathWithinRoot(realRoot, realMain) {
		return fmt.Errorf("control.main escapes plugin root")
	}
	got := fmt.Sprintf("%x", sha256.Sum256(data))
	plugin.Control.ResolvedSHA256 = got
	if pluginControlSHA256Required(*plugin) && plugin.Control.SHA256 == "" {
		return fmt.Errorf("control.sha256 is required for stable or preview control scripts")
	}
	if plugin.Control.SHA256 != "" && plugin.Control.SHA256 != got {
		return fmt.Errorf("control.sha256 mismatch")
	}
	plugin.controlMainPath = realMain
	return nil
}

func pluginControlSHA256Required(plugin LoadedPlugin) bool {
	if plugin.Builtin {
		return false
	}
	switch strings.TrimSpace(strings.ToLower(plugin.Stability)) {
	case pluginStabilityStable, pluginStabilityPreview:
		return true
	default:
		return false
	}
}

func pluginControlHasPermission(plugin LoadedPlugin, permission string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, value := range plugin.Control.Permissions {
		if value == permission {
			return true
		}
	}
	return false
}

func pluginControlHasResourceAccess(plugin LoadedPlugin, targetPluginID string, resourceID string, method string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, access := range plugin.Control.ResourceAccess {
		if access.Plugin != targetPluginID || access.Resource != resourceID {
			continue
		}
		for _, value := range access.Methods {
			if value == method {
				return true
			}
		}
	}
	return false
}

func pluginControlHasActionAccess(plugin LoadedPlugin, targetPluginID string, actionID string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, access := range plugin.Control.ActionAccess {
		if access.Plugin != targetPluginID {
			continue
		}
		for _, value := range access.Actions {
			if value == actionID {
				return true
			}
		}
	}
	return false
}

func pluginControlHasEventAccess(plugin LoadedPlugin, sourcePluginID string, topic string) bool {
	if plugin.Control == nil || !pluginControlHasPermission(plugin, "plugin.event") {
		return false
	}
	for _, access := range plugin.Control.EventAccess {
		if access.Plugin != sourcePluginID {
			continue
		}
		for _, prefix := range access.TopicPrefixes {
			if pluginEventTopicWithinPrefix(topic, prefix) {
				return true
			}
		}
	}
	return false
}

func pluginControlStabilityAllowed(plugin LoadedPlugin, cfg *Config) (bool, string) {
	stability := strings.TrimSpace(strings.ToLower(plugin.Stability))
	if stability == "" {
		stability = pluginStabilityLab
	}
	switch stability {
	case pluginStabilityStable, pluginStabilityPreview, pluginStabilityLab:
		return true, ""
	case pluginStabilityDeprecated:
		return false, "plugin stability is deprecated; control execution is disabled"
	default:
		return false, "plugin stability is unknown; control execution is disabled"
	}
}

func pluginControlRegistrationAllowed(plugin LoadedPlugin) (bool, string) {
	stability := strings.TrimSpace(strings.ToLower(plugin.Stability))
	if stability == "" {
		stability = pluginStabilityLab
	}
	switch stability {
	case pluginStabilityStable, pluginStabilityPreview, pluginStabilityLab:
		return true, ""
	case pluginStabilityDeprecated:
		return false, "plugin stability is deprecated; control registration is disabled"
	default:
		return false, "plugin stability is unknown; control registration is disabled"
	}
}

func pluginControlReservedResourceID(resourceID string) bool {
	switch resourceID {
	case pluginControlKVResourceID, pluginControlSecretResourceID:
		return true
	default:
		return false
	}
}

func pluginControlHasNetAccess(plugin LoadedPlugin, operation string, interfaceName string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, access := range plugin.Control.NetAccess {
		if !pluginNetAccessHasOperation(access, operation) {
			continue
		}
		for _, pattern := range access.Interfaces {
			if pluginInterfacePatternMatches(pattern, interfaceName) {
				return true
			}
		}
	}
	return false
}

type pluginControlNetEndpointPolicy struct {
	Authorized bool
	AnyIP      bool
	Prefixes   []netip.Prefix
}

func pluginControlNetEndpointPolicyFor(plugin LoadedPlugin, operation, interfaceName, host string, ip net.IP, port int) (pluginControlNetEndpointPolicy, error) {
	policy := pluginControlNetEndpointPolicy{}
	if plugin.Control == nil {
		return policy, fmt.Errorf("network access %s on interface %s is not declared", operation, interfaceName)
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, access := range plugin.Control.NetAccess {
		if !pluginNetAccessHasOperation(access, operation) || !pluginNetAccessMatchesInterface(access, interfaceName) {
			continue
		}
		if !pluginNetAccessMatchesRemoteHost(access, host) || !pluginNetAccessMatchesRemotePort(access, port) {
			continue
		}
		policy.Authorized = true
		if len(access.RemoteCIDRs) == 0 {
			policy.AnyIP = true
			policy.Prefixes = nil
			break
		}
		for _, value := range access.RemoteCIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err == nil {
				policy.Prefixes = append(policy.Prefixes, prefix)
			}
		}
	}
	if !policy.Authorized {
		return policy, fmt.Errorf("network endpoint access %s on interface %s for %s is not declared", operation, interfaceName, pluginControlNetEndpointLabel(host, ip, port))
	}
	if ip != nil && !policy.AllowsIP(ip) {
		return policy, fmt.Errorf("network endpoint access %s on interface %s for %s is outside remote_cidrs", operation, interfaceName, pluginControlNetEndpointLabel(host, ip, port))
	}
	return policy, nil
}

func (policy pluginControlNetEndpointPolicy) AllowsIP(ip net.IP) bool {
	if !policy.Authorized || ip == nil {
		return false
	}
	if policy.AnyIP {
		return true
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, prefix := range policy.Prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func pluginNetAccessMatchesInterface(access PluginNetAccess, interfaceName string) bool {
	for _, pattern := range access.Interfaces {
		if pluginInterfacePatternMatches(pattern, interfaceName) {
			return true
		}
	}
	return false
}

func pluginNetAccessMatchesRemoteHost(access PluginNetAccess, host string) bool {
	if len(access.RemoteHosts) == 0 {
		return true
	}
	if host == "" {
		return false
	}
	for _, pattern := range access.RemoteHosts {
		if pattern == "*" || pattern == host {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]
			if len(host) > len(suffix) && strings.HasSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

func pluginNetAccessMatchesRemotePort(access PluginNetAccess, port int) bool {
	if len(access.RemotePorts) == 0 {
		return true
	}
	for _, allowed := range access.RemotePorts {
		if allowed == port {
			return true
		}
	}
	return false
}

func pluginControlNetEndpointLabel(host string, ip net.IP, port int) string {
	value := host
	if ip != nil {
		value = ip.String()
	}
	if value == "" {
		value = "<unspecified>"
	}
	if port > 0 {
		return net.JoinHostPort(value, fmt.Sprintf("%d", port))
	}
	return value
}

func pluginControlHasAnyNetAccess(plugin LoadedPlugin, operation string) bool {
	if plugin.Control == nil {
		return false
	}
	for _, access := range plugin.Control.NetAccess {
		if pluginNetAccessHasOperation(access, operation) && len(access.Interfaces) > 0 {
			return true
		}
	}
	return false
}

func pluginControlHasNamespaceAccess(plugin LoadedPlugin, namespace string) bool {
	if plugin.Control == nil {
		return false
	}
	namespace = normalizePluginControlNamespace(namespace)
	for _, pattern := range plugin.Control.NamespaceAccess {
		if pluginInterfacePatternMatches(pattern, namespace) {
			return true
		}
	}
	return false
}

func normalizePluginControlNamespace(namespace string) string {
	namespace = strings.TrimSpace(strings.ToLower(namespace))
	if namespace == "" {
		return "host"
	}
	return namespace
}

func pluginNetAccessHasOperation(access PluginNetAccess, operation string) bool {
	for _, value := range access.Operations {
		if value == operation {
			return true
		}
	}
	return false
}

func pluginInterfacePatternMatches(pattern string, interfaceName string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == interfaceName
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(interfaceName[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	if !strings.HasSuffix(pattern, "*") {
		last := ""
		for i := len(parts) - 1; i >= 0; i-- {
			if parts[i] != "" {
				last = parts[i]
				break
			}
		}
		if last != "" && !strings.HasSuffix(interfaceName, last) {
			return false
		}
	}
	return true
}
