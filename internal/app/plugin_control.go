package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func resolvePluginControl(plugin *LoadedPlugin) error {
	if plugin == nil || plugin.Control == nil || plugin.Control.Main == "" {
		return nil
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
	info, err := os.Stat(realMain)
	if err != nil {
		return fmt.Errorf("control.main: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("control.main is a directory")
	}
	if info.Size() > pluginControlMaxSize {
		return fmt.Errorf("control.main exceeds %d bytes", pluginControlMaxSize)
	}
	got, err := sha256File(realMain)
	if err != nil {
		return fmt.Errorf("hash control.main: %w", err)
	}
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
