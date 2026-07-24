package app

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
)

const pluginManifestRelationshipLimit = 64

var pluginRuntimeFeatures = []string{
	"control.goja.v1",
	"control.modules.v1",
	"control.action_schema.v1",
	"control.blobs.v1",
	"control.cross_plugin_events.v1",
	"control.durable_events.v1",
	"control.event_schema.v1",
	"control.events.v1",
	"control.hot_reload",
	"control.http_client.v1",
	"control.metrics.v1",
	"control.net_admin",
	"control.net_offloads.v1",
	"control.dns_client.v1",
	"control.net_events.v1",
	"control.net_leases.v1",
	"control.net_multipath.v1",
	"control.netns_provider.v1",
	"control.netns_scoped.v1",
	"control.net_policy.v1",
	"control.net_transactions.v1",
	"control.durable_operations.v1",
	"control.tuntap_provider.v1",
	"control.plugin_interop",
	"control.typed_services.v1",
	"control.process_isolation.v1",
	"control.raw_l2",
	"control.resource_schema.v1",
	"control.resource_limits.v1",
	"control.resource_transactions.v1",
	"control.secrets.aead.v1",
	"control.socket_events.v1",
	"control.sockets",
	"control.workers",
	"dataplane.packet_metadata.v1",
	"dataplane.tc_pipeline.v2",
	"dataplane.hook_order.v1",
	"dataplane.xdp_pipeline.v1",
	"ebpf.bounded_reads.v1",
	"ebpf.map_transactions.v1",
	"ebpf.ring_push.v1",
	"ebpf.private_maps",
	"ebpf.map_state.v1",
	"ebpf.map_migration.v1",
	"ebpf.object_variants.v1",
	"plans.core.v1",
	"ui.assets.v1",
	"ui.bridge.v1",
	"ui.capabilities.v1",
}

type pluginHostEnvironment struct {
	RuntimeVersion string
	ControlAPIABI  int
	TCPipelineABI  int
	OS             string
	Arch           string
	KernelRelease  string
	Features       map[string]struct{}
}

func currentPluginHostEnvironment() pluginHostEnvironment {
	features := make(map[string]struct{}, len(pluginRuntimeFeatures))
	for _, feature := range pluginRuntimeFeatures {
		if runtime.GOOS != "linux" && (feature == "control.netns_provider.v1" || feature == "control.netns_scoped.v1" || feature == "control.tuntap_provider.v1") {
			continue
		}
		features[feature] = struct{}{}
	}
	return pluginHostEnvironment{
		RuntimeVersion: pluginRuntimeVersion,
		ControlAPIABI:  pluginControlAPIABI,
		TCPipelineABI:  pluginTCPipelineABI,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		KernelRelease:  currentPluginKernelRelease(),
		Features:       features,
	}
}

func normalizePluginSemanticVersion(value string) (string, error) {
	value = strings.TrimSpace(value)
	version, err := semver.StrictNewVersion(value)
	if err != nil {
		return "", fmt.Errorf("must be a semantic version such as 1.2.3: %w", err)
	}
	return version.String(), nil
}

func normalizePluginVersionConstraint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "*"
	}
	if _, err := semver.NewConstraint(value); err != nil {
		return "", fmt.Errorf("invalid semantic version constraint %q: %w", value, err)
	}
	return value, nil
}

func normalizePluginCompatibility(compatibility *PluginCompatibility) error {
	if compatibility == nil {
		return nil
	}
	var err error
	if strings.TrimSpace(compatibility.Runtime) != "" {
		compatibility.Runtime, err = normalizePluginVersionConstraint(compatibility.Runtime)
		if err != nil {
			return fmt.Errorf("runtime: %w", err)
		}
	}
	if compatibility.TCPipelineABI < 0 {
		return fmt.Errorf("tc_pipeline_abi cannot be negative")
	}
	if compatibility.ControlAPIABI < 0 {
		return fmt.Errorf("control_api_abi cannot be negative")
	}
	compatibility.OS, err = normalizePluginTokens(compatibility.OS, "operating system")
	if err != nil {
		return fmt.Errorf("os: %w", err)
	}
	compatibility.Architectures, err = normalizePluginTokens(compatibility.Architectures, "architecture")
	if err != nil {
		return fmt.Errorf("architectures: %w", err)
	}
	if strings.TrimSpace(compatibility.Kernel) != "" {
		compatibility.Kernel, err = normalizePluginVersionConstraint(compatibility.Kernel)
		if err != nil {
			return fmt.Errorf("kernel: %w", err)
		}
	}
	compatibility.Features, err = normalizePluginTokens(compatibility.Features, "feature")
	if err != nil {
		return fmt.Errorf("features: %w", err)
	}
	return nil
}

func normalizePluginDependencies(pluginID string, dependencies []PluginDependency) error {
	if len(dependencies) > pluginManifestRelationshipLimit {
		return fmt.Errorf("cannot contain more than %d entries", pluginManifestRelationshipLimit)
	}
	seen := make(map[string]struct{}, len(dependencies))
	for i := range dependencies {
		dependency := &dependencies[i]
		dependency.ID = strings.TrimSpace(strings.ToLower(dependency.ID))
		if !pluginIDPattern.MatchString(dependency.ID) {
			return fmt.Errorf("[%d].id must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(dependency.ID) {
			return fmt.Errorf("[%d].id %q is reserved; use compatibility.features for host capabilities", i, dependency.ID)
		}
		if dependency.ID == pluginID {
			return fmt.Errorf("[%d].id cannot reference the plugin itself", i)
		}
		if _, exists := seen[dependency.ID]; exists {
			return fmt.Errorf("[%d]: duplicate dependency %q", i, dependency.ID)
		}
		seen[dependency.ID] = struct{}{}
		version, err := normalizePluginVersionConstraint(dependency.Version)
		if err != nil {
			return fmt.Errorf("[%d].version: %w", i, err)
		}
		dependency.Version = version
	}
	sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].ID < dependencies[j].ID })
	return nil
}

func normalizePluginConflicts(pluginID string, conflicts []PluginConflict) error {
	if len(conflicts) > pluginManifestRelationshipLimit {
		return fmt.Errorf("cannot contain more than %d entries", pluginManifestRelationshipLimit)
	}
	seen := make(map[string]struct{}, len(conflicts))
	for i := range conflicts {
		conflict := &conflicts[i]
		conflict.ID = strings.TrimSpace(strings.ToLower(conflict.ID))
		if !pluginIDPattern.MatchString(conflict.ID) {
			return fmt.Errorf("[%d].id must match %s", i, pluginIDPattern.String())
		}
		if reservedBuiltinPluginID(conflict.ID) {
			return fmt.Errorf("[%d].id %q is reserved", i, conflict.ID)
		}
		if conflict.ID == pluginID {
			return fmt.Errorf("[%d].id cannot reference the plugin itself", i)
		}
		if _, exists := seen[conflict.ID]; exists {
			return fmt.Errorf("[%d]: duplicate conflict %q", i, conflict.ID)
		}
		seen[conflict.ID] = struct{}{}
		version, err := normalizePluginVersionConstraint(conflict.Version)
		if err != nil {
			return fmt.Errorf("[%d].version: %w", i, err)
		}
		conflict.Version = version
	}
	sort.Slice(conflicts, func(i, j int) bool { return conflicts[i].ID < conflicts[j].ID })
	return nil
}

func validatePluginRelationshipOverlap(dependencies []PluginDependency, conflicts []PluginConflict) error {
	dependencyIDs := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		dependencyIDs[dependency.ID] = struct{}{}
	}
	for _, conflict := range conflicts {
		if _, exists := dependencyIDs[conflict.ID]; exists {
			return fmt.Errorf("plugin %q cannot be both a dependency and a conflict", conflict.ID)
		}
	}
	return nil
}

func resolvePluginCatalogRelationships(catalog PluginCatalog, env pluginHostEnvironment) PluginCatalog {
	clearPluginResolutionErrors(&catalog)

	byID := make(map[string]*LoadedPlugin, len(catalog.Plugins))
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		byID[plugin.ID] = plugin
		if plugin.Builtin || !plugin.Enabled || plugin.Status != pluginStatusActive {
			continue
		}
		if err := checkPluginCompatibility(*plugin, env); err != nil {
			markPluginResolutionError(plugin, err.Error())
		}
	}

	conflictErrors := make(map[string][]string)
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if !pluginAvailableForRelationship(*plugin) {
			continue
		}
		for _, conflict := range plugin.Conflicts {
			target, exists := byID[conflict.ID]
			if !exists || !pluginAvailableForRelationship(*target) || !pluginVersionSatisfies(target.Version, conflict.Version) {
				continue
			}
			conflictErrors[plugin.ID] = append(conflictErrors[plugin.ID], fmt.Sprintf("conflicts with %s %s", target.ID, target.Version))
			conflictErrors[target.ID] = append(conflictErrors[target.ID], fmt.Sprintf("conflicts with %s %s", plugin.ID, plugin.Version))
		}
	}
	for pluginID, issues := range conflictErrors {
		sort.Strings(issues)
		markPluginResolutionError(byID[pluginID], strings.Join(issues, "; "))
	}

	resolveRequiredPluginDependencies(catalog.Plugins, byID)
	for _, cycle := range requiredPluginDependencyCycles(catalog.Plugins, byID) {
		message := "required dependency cycle: " + strings.Join(cycle, " -> ")
		for _, pluginID := range cycle[:len(cycle)-1] {
			markPluginResolutionError(byID[pluginID], message)
		}
	}
	resolveRequiredPluginDependencies(catalog.Plugins, byID)
	return catalog
}

func clearPluginResolutionErrors(catalog *PluginCatalog) {
	if catalog == nil {
		return
	}
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if !plugin.resolutionError || plugin.Builtin || !plugin.Enabled {
			continue
		}
		plugin.Status = pluginStatusActive
		plugin.Runtime = externalPluginRuntimeState()
		plugin.Error = ""
		plugin.resolutionError = false
	}
}

func checkPluginCompatibility(plugin LoadedPlugin, env pluginHostEnvironment) error {
	compatibility := plugin.Compatibility
	if compatibility == nil {
		return nil
	}
	if compatibility.Runtime != "" && !pluginVersionSatisfies(env.RuntimeVersion, compatibility.Runtime) {
		return fmt.Errorf("requires Veer plugin runtime %s, host is %s", compatibility.Runtime, env.RuntimeVersion)
	}
	if compatibility.ControlAPIABI != 0 && compatibility.ControlAPIABI != env.ControlAPIABI {
		return fmt.Errorf("requires control API ABI %d, host provides %d", compatibility.ControlAPIABI, env.ControlAPIABI)
	}
	if compatibility.TCPipelineABI != 0 && compatibility.TCPipelineABI != env.TCPipelineABI {
		return fmt.Errorf("requires TC pipeline ABI %d, host provides %d", compatibility.TCPipelineABI, env.TCPipelineABI)
	}
	if len(compatibility.OS) > 0 && !pluginStringSliceContains(compatibility.OS, env.OS) {
		return fmt.Errorf("requires operating system %s, host is %s", strings.Join(compatibility.OS, ","), env.OS)
	}
	if len(compatibility.Architectures) > 0 && !pluginStringSliceContains(compatibility.Architectures, env.Arch) {
		return fmt.Errorf("requires architecture %s, host is %s", strings.Join(compatibility.Architectures, ","), env.Arch)
	}
	if compatibility.Kernel != "" {
		if strings.TrimSpace(env.KernelRelease) == "" {
			return fmt.Errorf("requires kernel %s, host kernel release is unavailable", compatibility.Kernel)
		}
		if !pluginVersionSatisfies(env.KernelRelease, compatibility.Kernel) {
			return fmt.Errorf("requires kernel %s, host is %s", compatibility.Kernel, env.KernelRelease)
		}
	}
	missingFeatures := make([]string, 0)
	for _, feature := range compatibility.Features {
		if _, ok := env.Features[feature]; !ok {
			missingFeatures = append(missingFeatures, feature)
		}
	}
	if len(missingFeatures) > 0 {
		return fmt.Errorf("host is missing required features: %s", strings.Join(missingFeatures, ", "))
	}
	return nil
}

func pluginVersionSatisfies(version string, constraint string) bool {
	parsedVersion, err := semver.NewVersion(strings.TrimSpace(version))
	if err != nil {
		return false
	}
	parsedConstraint, err := semver.NewConstraint(strings.TrimSpace(constraint))
	if err != nil {
		return false
	}
	return parsedConstraint.Check(parsedVersion)
}

func pluginStringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pluginAvailableForRelationship(plugin LoadedPlugin) bool {
	return !plugin.Builtin && plugin.Enabled && plugin.Status == pluginStatusActive
}

func pluginExecutable(plugin LoadedPlugin) bool {
	return !plugin.Builtin && plugin.Status == pluginStatusActive
}

func markPluginResolutionError(plugin *LoadedPlugin, message string) {
	if plugin == nil || plugin.Builtin || !plugin.Enabled || plugin.Status == pluginStatusDisabled {
		return
	}
	plugin.Status = pluginStatusError
	plugin.Runtime = invalidPluginRuntimeState()
	plugin.Runtime.Reason = "plugin compatibility or dependency resolution failed"
	plugin.Error = strings.TrimSpace(message)
	plugin.staticDir = ""
	plugin.AssetBasePath = ""
	plugin.resolutionError = true
}

func resolveRequiredPluginDependencies(plugins []LoadedPlugin, byID map[string]*LoadedPlugin) {
	for {
		changed := false
		for i := range plugins {
			plugin := byID[plugins[i].ID]
			if !pluginAvailableForRelationship(*plugin) {
				continue
			}
			for _, dependency := range plugin.Dependencies {
				if dependency.Optional {
					continue
				}
				target, exists := byID[dependency.ID]
				switch {
				case !exists:
					markPluginResolutionError(plugin, fmt.Sprintf("required dependency %s %s is not installed", dependency.ID, dependency.Version))
				case !target.Enabled || target.Status == pluginStatusDisabled:
					markPluginResolutionError(plugin, fmt.Sprintf("required dependency %s is disabled", dependency.ID))
				case target.Status != pluginStatusActive:
					markPluginResolutionError(plugin, fmt.Sprintf("required dependency %s is unavailable: %s", dependency.ID, strings.TrimSpace(target.Error)))
				case !pluginVersionSatisfies(target.Version, dependency.Version):
					markPluginResolutionError(plugin, fmt.Sprintf("required dependency %s version %s does not satisfy %s", dependency.ID, target.Version, dependency.Version))
				default:
					continue
				}
				changed = true
				break
			}
		}
		if !changed {
			return
		}
	}
}

func requiredPluginDependencyCycles(plugins []LoadedPlugin, byID map[string]*LoadedPlugin) [][]string {
	state := make(map[string]uint8)
	stack := make([]string, 0)
	stackIndex := make(map[string]int)
	cycles := make([][]string, 0)
	seenCycles := make(map[string]struct{})

	var visit func(string)
	visit = func(pluginID string) {
		state[pluginID] = 1
		stackIndex[pluginID] = len(stack)
		stack = append(stack, pluginID)
		plugin := byID[pluginID]
		for _, dependency := range plugin.Dependencies {
			if dependency.Optional {
				continue
			}
			target, exists := byID[dependency.ID]
			if !exists || !pluginAvailableForRelationship(*target) || !pluginVersionSatisfies(target.Version, dependency.Version) {
				continue
			}
			switch state[target.ID] {
			case 0:
				visit(target.ID)
			case 1:
				start := stackIndex[target.ID]
				cycle := append([]string(nil), stack[start:]...)
				cycle = append(cycle, target.ID)
				keyMembers := append([]string(nil), cycle[:len(cycle)-1]...)
				sort.Strings(keyMembers)
				key := strings.Join(keyMembers, "\x00")
				if _, duplicate := seenCycles[key]; !duplicate {
					seenCycles[key] = struct{}{}
					cycles = append(cycles, cycle)
				}
			}
		}
		stack = stack[:len(stack)-1]
		delete(stackIndex, pluginID)
		state[pluginID] = 2
	}

	ids := make([]string, 0, len(plugins))
	for _, plugin := range plugins {
		if pluginAvailableForRelationship(plugin) {
			ids = append(ids, plugin.ID)
		}
	}
	sort.Strings(ids)
	for _, pluginID := range ids {
		if state[pluginID] == 0 {
			visit(pluginID)
		}
	}
	return cycles
}

func pluginCatalogExecutionIndexes(catalog PluginCatalog) []int {
	byID := make(map[string]int, len(catalog.Plugins))
	ids := make([]string, 0, len(catalog.Plugins))
	for i, plugin := range catalog.Plugins {
		if !pluginExecutable(plugin) {
			continue
		}
		byID[plugin.ID] = i
		ids = append(ids, plugin.ID)
	}
	sort.Strings(ids)
	state := make(map[string]uint8, len(ids))
	ordered := make([]int, 0, len(ids))
	var visit func(string)
	visit = func(pluginID string) {
		if state[pluginID] != 0 {
			return
		}
		state[pluginID] = 1
		plugin := catalog.Plugins[byID[pluginID]]
		dependencies := append([]PluginDependency(nil), plugin.Dependencies...)
		sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].ID < dependencies[j].ID })
		for _, dependency := range dependencies {
			index, exists := byID[dependency.ID]
			if !exists || state[dependency.ID] == 1 || !pluginVersionSatisfies(catalog.Plugins[index].Version, dependency.Version) {
				continue
			}
			visit(dependency.ID)
		}
		state[pluginID] = 2
		ordered = append(ordered, byID[pluginID])
	}
	for _, pluginID := range ids {
		visit(pluginID)
	}
	return ordered
}

func pluginMapExecutionOrder(plugins map[string]LoadedPlugin, reverse bool) []LoadedPlugin {
	catalog := PluginCatalog{Plugins: make([]LoadedPlugin, 0, len(plugins))}
	for _, plugin := range plugins {
		catalog.Plugins = append(catalog.Plugins, plugin)
	}
	indexes := pluginCatalogExecutionIndexes(catalog)
	ordered := make([]LoadedPlugin, 0, len(indexes))
	for _, index := range indexes {
		ordered = append(ordered, catalog.Plugins[index])
	}
	if reverse {
		for left, right := 0, len(ordered)-1; left < right; left, right = left+1, right-1 {
			ordered[left], ordered[right] = ordered[right], ordered[left]
		}
	}
	return ordered
}

func pluginRequiredDependencyFailure(plugin LoadedPlugin, failures map[string]string) string {
	for _, dependency := range plugin.Dependencies {
		if dependency.Optional {
			continue
		}
		if reason := strings.TrimSpace(failures[dependency.ID]); reason != "" {
			return fmt.Sprintf("required dependency %s failed: %s", dependency.ID, reason)
		}
	}
	return ""
}
