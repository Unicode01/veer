package app

import (
	"fmt"
	"math"
	"runtime"
	"sort"

	"github.com/Unicode01/veer/internal/store"
	"github.com/cilium/ebpf"
)

const (
	pluginDefaultMaxObjectsPerPlugin       = 16
	pluginDefaultMaxCapabilitiesPerPlugin  = 128
	pluginDefaultMaxProgramsPerPlugin      = 128
	pluginDefaultMaxMapsPerPlugin          = 128
	pluginDefaultMaxHooksPerPlugin         = 128
	pluginDefaultMaxResourcesPerPlugin     = 64
	pluginDefaultMaxActionsPerPlugin       = 64
	pluginDefaultMaxServicesPerPlugin      = 64
	pluginDefaultMaxVirtualIfacesPerPlugin = 64
	pluginDefaultMaxInstructionsPerProgram = 262144
	pluginDefaultMaxInstructionsPerPlugin  = 1048576
	pluginDefaultMaxMapMemoryMB            = 64
	pluginDefaultMaxPluginMapMemoryMB      = 256
	pluginDefaultMaxGlobalMapMemoryMB      = 1024
	pluginDefaultMaxPluginDatabaseMB       = 256
	pluginDefaultMaxGlobalDatabaseMB       = 2048
	pluginDefaultMaxBlobObjectsPerPlugin   = 1024
	pluginDefaultMaxBlobObjectMB           = 64
	pluginDefaultMaxPluginBlobMB           = 256
	pluginDefaultMaxGlobalBlobMB           = 2048
	pluginDefaultControlMemoryMB           = 512
	pluginDefaultGlobalControlMemoryMB     = 2048
	pluginDefaultControlProcessMemoryMB    = 224
	pluginDefaultControlPIDs               = 64
	pluginDefaultGlobalControlPIDs         = 512
	pluginDefaultControlCPUPercent         = 200
)

// PluginResourceLimitConfig is expressed in operator-friendly units. The
// normalized byte limits are published in the runtime catalog.
type PluginResourceLimitConfig struct {
	ObjectsPerPlugin       int `json:"objects_per_plugin,omitempty"`
	CapabilitiesPerPlugin  int `json:"capabilities_per_plugin,omitempty"`
	ProgramsPerPlugin      int `json:"programs_per_plugin,omitempty"`
	MapsPerPlugin          int `json:"maps_per_plugin,omitempty"`
	HooksPerPlugin         int `json:"hooks_per_plugin,omitempty"`
	ResourcesPerPlugin     int `json:"resources_per_plugin,omitempty"`
	ActionsPerPlugin       int `json:"actions_per_plugin,omitempty"`
	ServicesPerPlugin      int `json:"services_per_plugin,omitempty"`
	VirtualIfacesPerPlugin int `json:"virtual_interfaces_per_plugin,omitempty"`
	InstructionsPerProgram int `json:"instructions_per_program,omitempty"`
	InstructionsPerPlugin  int `json:"instructions_per_plugin,omitempty"`
	MapMemoryMB            int `json:"map_memory_mb,omitempty"`
	PluginMapMemoryMB      int `json:"plugin_map_memory_mb,omitempty"`
	GlobalMapMemoryMB      int `json:"global_map_memory_mb,omitempty"`
	PluginDatabaseMB       int `json:"plugin_database_mb,omitempty"`
	GlobalDatabaseMB       int `json:"global_database_mb,omitempty"`
	BlobObjectsPerPlugin   int `json:"blob_objects_per_plugin,omitempty"`
	BlobObjectMB           int `json:"blob_object_mb,omitempty"`
	PluginBlobMB           int `json:"plugin_blob_mb,omitempty"`
	GlobalBlobMB           int `json:"global_blob_mb,omitempty"`
	ControlMemoryMB        int `json:"control_memory_mb,omitempty"`
	GlobalControlMemoryMB  int `json:"global_control_memory_mb,omitempty"`
	ControlProcessMemoryMB int `json:"control_process_memory_mb,omitempty"`
	ControlPIDs            int `json:"control_pids,omitempty"`
	GlobalControlPIDs      int `json:"global_control_pids,omitempty"`
	ControlCPUPercent      int `json:"control_cpu_percent,omitempty"`
}

type PluginResourceLimits struct {
	ObjectsPerPlugin          int    `json:"objects_per_plugin"`
	CapabilitiesPerPlugin     int    `json:"capabilities_per_plugin"`
	ProgramsPerPlugin         int    `json:"programs_per_plugin"`
	MapsPerPlugin             int    `json:"maps_per_plugin"`
	HooksPerPlugin            int    `json:"hooks_per_plugin"`
	ResourcesPerPlugin        int    `json:"resources_per_plugin"`
	ActionsPerPlugin          int    `json:"actions_per_plugin"`
	ServicesPerPlugin         int    `json:"services_per_plugin"`
	VirtualIfacesPerPlugin    int    `json:"virtual_interfaces_per_plugin"`
	InstructionsPerProgram    int    `json:"instructions_per_program"`
	InstructionsPerPlugin     int    `json:"instructions_per_plugin"`
	MapMemoryBytes            uint64 `json:"map_memory_bytes"`
	PluginMapMemoryBytes      uint64 `json:"plugin_map_memory_bytes"`
	GlobalMapMemoryBytes      uint64 `json:"global_map_memory_bytes"`
	PluginDatabaseBytes       int64  `json:"plugin_database_bytes"`
	GlobalDatabaseBytes       int64  `json:"global_database_bytes"`
	BlobObjectsPerPlugin      int    `json:"blob_objects_per_plugin"`
	BlobObjectBytes           int64  `json:"blob_object_bytes"`
	PluginBlobBytes           int64  `json:"plugin_blob_bytes"`
	GlobalBlobBytes           int64  `json:"global_blob_bytes"`
	ControlMemoryBytes        int64  `json:"control_memory_bytes"`
	GlobalControlMemoryBytes  int64  `json:"global_control_memory_bytes"`
	ControlProcessMemoryBytes uint64 `json:"control_process_memory_bytes"`
	ControlPIDs               int    `json:"control_pids"`
	GlobalControlPIDs         int    `json:"global_control_pids"`
	ControlCPUPercent         int    `json:"control_cpu_percent"`
}

type PluginResourceUsage struct {
	Objects                 int      `json:"objects"`
	Capabilities            int      `json:"capabilities"`
	Programs                int      `json:"programs"`
	Maps                    int      `json:"maps"`
	Hooks                   int      `json:"hooks"`
	Resources               int      `json:"resources"`
	Actions                 int      `json:"actions"`
	Services                int      `json:"services"`
	VirtualInterfaces       int      `json:"virtual_interfaces"`
	Instructions            uint64   `json:"instructions"`
	EstimatedMapMemoryBytes uint64   `json:"estimated_map_memory_bytes"`
	DatabaseRecords         int      `json:"database_records"`
	DatabaseBytes           int64    `json:"database_bytes"`
	LimitWarnings           []string `json:"limit_warnings,omitempty"`
}

type PluginObjectResourceUsage struct {
	Programs                int    `json:"programs"`
	Maps                    int    `json:"maps"`
	Instructions            uint64 `json:"instructions"`
	EstimatedMapMemoryBytes uint64 `json:"estimated_map_memory_bytes"`
}

func normalizePluginResourceLimitConfig(cfg PluginResourceLimitConfig) (PluginResourceLimitConfig, error) {
	cfg.ObjectsPerPlugin = normalizeBoundedConfigValue(cfg.ObjectsPerPlugin, pluginDefaultMaxObjectsPerPlugin, 1, 128)
	cfg.CapabilitiesPerPlugin = normalizeBoundedConfigValue(cfg.CapabilitiesPerPlugin, pluginDefaultMaxCapabilitiesPerPlugin, 1, 1024)
	cfg.ProgramsPerPlugin = normalizeBoundedConfigValue(cfg.ProgramsPerPlugin, pluginDefaultMaxProgramsPerPlugin, 1, 2048)
	cfg.MapsPerPlugin = normalizeBoundedConfigValue(cfg.MapsPerPlugin, pluginDefaultMaxMapsPerPlugin, 1, 2048)
	cfg.HooksPerPlugin = normalizeBoundedConfigValue(cfg.HooksPerPlugin, pluginDefaultMaxHooksPerPlugin, 1, 1024)
	cfg.ResourcesPerPlugin = normalizeBoundedConfigValue(cfg.ResourcesPerPlugin, pluginDefaultMaxResourcesPerPlugin, 1, 1024)
	cfg.ActionsPerPlugin = normalizeBoundedConfigValue(cfg.ActionsPerPlugin, pluginDefaultMaxActionsPerPlugin, 1, 1024)
	cfg.ServicesPerPlugin = normalizeBoundedConfigValue(cfg.ServicesPerPlugin, pluginDefaultMaxServicesPerPlugin, 1, 1024)
	cfg.VirtualIfacesPerPlugin = normalizeBoundedConfigValue(cfg.VirtualIfacesPerPlugin, pluginDefaultMaxVirtualIfacesPerPlugin, 1, 1024)
	cfg.InstructionsPerProgram = normalizeBoundedConfigValue(cfg.InstructionsPerProgram, pluginDefaultMaxInstructionsPerProgram, 4096, 1_000_000)
	cfg.InstructionsPerPlugin = normalizeBoundedConfigValue(cfg.InstructionsPerPlugin, pluginDefaultMaxInstructionsPerPlugin, 4096, 16_000_000)
	cfg.MapMemoryMB = normalizeBoundedConfigValue(cfg.MapMemoryMB, pluginDefaultMaxMapMemoryMB, 1, 16384)
	cfg.PluginMapMemoryMB = normalizeBoundedConfigValue(cfg.PluginMapMemoryMB, pluginDefaultMaxPluginMapMemoryMB, 1, 32768)
	cfg.GlobalMapMemoryMB = normalizeBoundedConfigValue(cfg.GlobalMapMemoryMB, pluginDefaultMaxGlobalMapMemoryMB, 1, 65536)
	cfg.PluginDatabaseMB = normalizeBoundedConfigValue(cfg.PluginDatabaseMB, pluginDefaultMaxPluginDatabaseMB, 1, 16384)
	cfg.GlobalDatabaseMB = normalizeBoundedConfigValue(cfg.GlobalDatabaseMB, pluginDefaultMaxGlobalDatabaseMB, 1, 65536)
	cfg.BlobObjectsPerPlugin = normalizeBoundedConfigValue(cfg.BlobObjectsPerPlugin, pluginDefaultMaxBlobObjectsPerPlugin, 1, 65536)
	cfg.BlobObjectMB = normalizeBoundedConfigValue(cfg.BlobObjectMB, pluginDefaultMaxBlobObjectMB, 1, 4096)
	cfg.PluginBlobMB = normalizeBoundedConfigValue(cfg.PluginBlobMB, pluginDefaultMaxPluginBlobMB, 1, 65536)
	cfg.GlobalBlobMB = normalizeBoundedConfigValue(cfg.GlobalBlobMB, pluginDefaultMaxGlobalBlobMB, 1, 262144)
	cfg.ControlMemoryMB = normalizeBoundedConfigValue(cfg.ControlMemoryMB, pluginDefaultControlMemoryMB, 32, 16384)
	cfg.GlobalControlMemoryMB = normalizeBoundedConfigValue(cfg.GlobalControlMemoryMB, pluginDefaultGlobalControlMemoryMB, 32, 65536)
	cfg.ControlProcessMemoryMB = normalizeBoundedConfigValue(cfg.ControlProcessMemoryMB, pluginDefaultControlProcessMemoryMB, 16, 16384)
	cfg.ControlPIDs = normalizeBoundedConfigValue(cfg.ControlPIDs, pluginDefaultControlPIDs, 1, 4096)
	cfg.GlobalControlPIDs = normalizeBoundedConfigValue(cfg.GlobalControlPIDs, pluginDefaultGlobalControlPIDs, 1, 65536)
	cfg.ControlCPUPercent = normalizeBoundedConfigValue(cfg.ControlCPUPercent, pluginDefaultControlCPUPercent, 10, 6400)
	if cfg.InstructionsPerProgram > cfg.InstructionsPerPlugin {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.instructions_per_program cannot exceed instructions_per_plugin")
	}
	if cfg.MapMemoryMB > cfg.PluginMapMemoryMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.map_memory_mb cannot exceed plugin_map_memory_mb")
	}
	if cfg.PluginMapMemoryMB > cfg.GlobalMapMemoryMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.plugin_map_memory_mb cannot exceed global_map_memory_mb")
	}
	if cfg.PluginDatabaseMB > cfg.GlobalDatabaseMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.plugin_database_mb cannot exceed global_database_mb")
	}
	if cfg.BlobObjectMB > cfg.PluginBlobMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.blob_object_mb cannot exceed plugin_blob_mb")
	}
	if cfg.PluginBlobMB > cfg.GlobalBlobMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.plugin_blob_mb cannot exceed global_blob_mb")
	}
	if cfg.ControlMemoryMB > cfg.GlobalControlMemoryMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.control_memory_mb cannot exceed global_control_memory_mb")
	}
	if cfg.ControlProcessMemoryMB > cfg.ControlMemoryMB {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.control_process_memory_mb cannot exceed control_memory_mb")
	}
	if cfg.ControlPIDs > cfg.GlobalControlPIDs {
		return PluginResourceLimitConfig{}, fmt.Errorf("plugins_resource_limits.control_pids cannot exceed global_control_pids")
	}
	return cfg, nil
}

func pluginResourceLimitsFromConfig(cfg *Config) PluginResourceLimits {
	values := PluginResourceLimitConfig{}
	if cfg != nil {
		values = cfg.PluginsResourceLimits
	}
	values, err := normalizePluginResourceLimitConfig(values)
	if err != nil {
		values, _ = normalizePluginResourceLimitConfig(PluginResourceLimitConfig{})
	}
	return PluginResourceLimits{
		ObjectsPerPlugin:          values.ObjectsPerPlugin,
		CapabilitiesPerPlugin:     values.CapabilitiesPerPlugin,
		ProgramsPerPlugin:         values.ProgramsPerPlugin,
		MapsPerPlugin:             values.MapsPerPlugin,
		HooksPerPlugin:            values.HooksPerPlugin,
		ResourcesPerPlugin:        values.ResourcesPerPlugin,
		ActionsPerPlugin:          values.ActionsPerPlugin,
		ServicesPerPlugin:         values.ServicesPerPlugin,
		VirtualIfacesPerPlugin:    values.VirtualIfacesPerPlugin,
		InstructionsPerProgram:    values.InstructionsPerProgram,
		InstructionsPerPlugin:     values.InstructionsPerPlugin,
		MapMemoryBytes:            uint64(values.MapMemoryMB) << 20,
		PluginMapMemoryBytes:      uint64(values.PluginMapMemoryMB) << 20,
		GlobalMapMemoryBytes:      uint64(values.GlobalMapMemoryMB) << 20,
		PluginDatabaseBytes:       int64(values.PluginDatabaseMB) << 20,
		GlobalDatabaseBytes:       int64(values.GlobalDatabaseMB) << 20,
		BlobObjectsPerPlugin:      values.BlobObjectsPerPlugin,
		BlobObjectBytes:           int64(values.BlobObjectMB) << 20,
		PluginBlobBytes:           int64(values.PluginBlobMB) << 20,
		GlobalBlobBytes:           int64(values.GlobalBlobMB) << 20,
		ControlMemoryBytes:        int64(values.ControlMemoryMB) << 20,
		GlobalControlMemoryBytes:  int64(values.GlobalControlMemoryMB) << 20,
		ControlProcessMemoryBytes: uint64(values.ControlProcessMemoryMB) << 20,
		ControlPIDs:               values.ControlPIDs,
		GlobalControlPIDs:         values.GlobalControlPIDs,
		ControlCPUPercent:         values.ControlCPUPercent,
	}
}

type pluginHostResourceLimits struct {
	MemoryBytes       int64
	GlobalMemoryBytes int64
	ProcessRSSBytes   uint64
	PIDs              int
	GlobalPIDs        int
	CPUPercent        int
}

func pluginHostResourceLimitsFromConfig(cfg *Config) pluginHostResourceLimits {
	limits := pluginResourceLimitsFromConfig(cfg)
	return pluginHostResourceLimits{
		MemoryBytes:       limits.ControlMemoryBytes,
		GlobalMemoryBytes: limits.GlobalControlMemoryBytes,
		ProcessRSSBytes:   limits.ControlProcessMemoryBytes,
		PIDs:              limits.ControlPIDs,
		GlobalPIDs:        limits.GlobalControlPIDs,
		CPUPercent:        limits.ControlCPUPercent,
	}
}

func validatePluginSurfaceDefinitionLimits(plugin *LoadedPlugin) error {
	if plugin == nil {
		return nil
	}
	limits := plugin.resourceLimits
	checks := []struct {
		name  string
		value int
		limit int
	}{
		{"objects", len(plugin.Objects), limits.ObjectsPerPlugin},
		{"capabilities", len(plugin.Capabilities), limits.CapabilitiesPerPlugin},
		{"hooks", len(plugin.Hooks), limits.HooksPerPlugin},
		{"resources", len(plugin.Resources), limits.ResourcesPerPlugin},
		{"actions", len(plugin.Actions), limits.ActionsPerPlugin},
		{"services", len(plugin.Services), limits.ServicesPerPlugin},
		{"virtual interfaces", len(plugin.VirtualInterfaces), limits.VirtualIfacesPerPlugin},
	}
	for _, check := range checks {
		if check.value > check.limit {
			return fmt.Errorf("plugin resource budget: %s = %d exceeds limit %d", check.name, check.value, check.limit)
		}
	}
	return nil
}

func validatePluginAggregateObjectLimits(plugin *LoadedPlugin) error {
	if plugin == nil {
		return nil
	}
	usage := PluginResourceUsage{
		Objects:           len(plugin.Objects),
		Capabilities:      len(plugin.Capabilities),
		Hooks:             len(plugin.Hooks),
		Resources:         len(plugin.Resources),
		Actions:           len(plugin.Actions),
		Services:          len(plugin.Services),
		VirtualInterfaces: len(plugin.VirtualInterfaces),
	}
	if plugin.ResourceUsage != nil {
		usage.DatabaseRecords = plugin.ResourceUsage.DatabaseRecords
		usage.DatabaseBytes = plugin.ResourceUsage.DatabaseBytes
		usage.LimitWarnings = append([]string(nil), plugin.ResourceUsage.LimitWarnings...)
	}
	for i := range plugin.Objects {
		objectUsage := plugin.Objects[i].ResourceUsage
		if objectUsage == nil {
			continue
		}
		usage.Programs += objectUsage.Programs
		usage.Maps += objectUsage.Maps
		if !safeAddUint64(&usage.Instructions, objectUsage.Instructions) ||
			!safeAddUint64(&usage.EstimatedMapMemoryBytes, objectUsage.EstimatedMapMemoryBytes) {
			return fmt.Errorf("plugin resource budget overflow")
		}
	}
	limits := plugin.resourceLimits
	if usage.Programs > limits.ProgramsPerPlugin {
		return fmt.Errorf("plugin resource budget: programs = %d exceeds limit %d", usage.Programs, limits.ProgramsPerPlugin)
	}
	if usage.Maps > limits.MapsPerPlugin {
		return fmt.Errorf("plugin resource budget: maps = %d exceeds limit %d", usage.Maps, limits.MapsPerPlugin)
	}
	if usage.Instructions > uint64(limits.InstructionsPerPlugin) {
		return fmt.Errorf("plugin resource budget: instructions = %d exceeds limit %d", usage.Instructions, limits.InstructionsPerPlugin)
	}
	if usage.EstimatedMapMemoryBytes > limits.PluginMapMemoryBytes {
		return fmt.Errorf("plugin resource budget: estimated map memory = %d bytes exceeds per-plugin limit %d", usage.EstimatedMapMemoryBytes, limits.PluginMapMemoryBytes)
	}
	plugin.ResourceUsage = &usage
	return nil
}

func enforcePluginCatalogGlobalResourceLimits(catalog *PluginCatalog) {
	if catalog == nil {
		return
	}
	limits := catalog.Runtime.ResourceLimits
	var used uint64
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.ResourceUsage == nil {
			continue
		}
		candidate := plugin.ResourceUsage.EstimatedMapMemoryBytes
		if candidate > limits.GlobalMapMemoryBytes-used {
			plugin.Status = pluginStatusError
			plugin.Runtime = invalidPluginRuntimeState()
			plugin.Error = fmt.Sprintf("global plugin eBPF map budget exceeded: used=%d candidate=%d limit=%d bytes", used, candidate, limits.GlobalMapMemoryBytes)
			plugin.staticDir = ""
			plugin.AssetBasePath = ""
			continue
		}
		used += candidate
	}
	catalog.Runtime.ResourceUsage.EstimatedMapMemoryBytes = used
}

func applyPluginDatabaseResourceUsage(catalog *PluginCatalog, db store.RuleStore) {
	if catalog == nil || db == nil {
		return
	}
	limits := catalog.Runtime.ResourceLimits
	usageByPlugin, global, err := store.GetPluginRecordStorageUsages(db)
	if err != nil {
		return
	}
	catalog.Runtime.ResourceUsage.DatabaseRecords = global.Records
	catalog.Runtime.ResourceUsage.DatabaseBytes = global.Bytes
	for i := range catalog.Plugins {
		plugin := &catalog.Plugins[i]
		if plugin.Builtin || plugin.ID == "" {
			continue
		}
		usage := usageByPlugin[plugin.ID]
		if plugin.ResourceUsage == nil {
			plugin.ResourceUsage = &PluginResourceUsage{}
		}
		plugin.ResourceUsage.DatabaseRecords = usage.Records
		plugin.ResourceUsage.DatabaseBytes = usage.Bytes
		plugin.ResourceUsage.LimitWarnings = nil
		if usage.Bytes > limits.PluginDatabaseBytes {
			plugin.ResourceUsage.LimitWarnings = append(plugin.ResourceUsage.LimitWarnings,
				fmt.Sprintf("plugin database usage %d exceeds limit %d bytes", usage.Bytes, limits.PluginDatabaseBytes))
		}
	}
	if catalog.Runtime.ResourceUsage.DatabaseBytes > limits.GlobalDatabaseBytes {
		catalog.Runtime.ResourceUsage.LimitWarnings = []string{
			fmt.Sprintf("global plugin database usage %d exceeds limit %d bytes", catalog.Runtime.ResourceUsage.DatabaseBytes, limits.GlobalDatabaseBytes),
		}
	} else {
		catalog.Runtime.ResourceUsage.LimitWarnings = nil
	}
}

func pluginObjectResourceUsageFromSpec(spec *ebpf.CollectionSpec, limits PluginResourceLimits) (*PluginObjectResourceUsage, error) {
	if spec == nil {
		return &PluginObjectResourceUsage{}, nil
	}
	usage := &PluginObjectResourceUsage{Programs: len(spec.Programs), Maps: len(spec.Maps)}
	programNames := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		programNames = append(programNames, name)
	}
	sort.Strings(programNames)
	for _, name := range programNames {
		program := spec.Programs[name]
		if program == nil {
			continue
		}
		instructions := len(program.Instructions)
		if instructions > limits.InstructionsPerProgram {
			return nil, fmt.Errorf("program %q instructions = %d exceeds per-program limit %d", name, instructions, limits.InstructionsPerProgram)
		}
		if !safeAddUint64(&usage.Instructions, uint64(instructions)) {
			return nil, fmt.Errorf("program instruction count overflow")
		}
	}
	cpus := runtime.NumCPU()
	if possible, err := ebpf.PossibleCPU(); err == nil && possible > cpus {
		cpus = possible
	}
	if cpus < 1 {
		cpus = 1
	}
	mapNames := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		mapSpec := spec.Maps[name]
		bytes, err := estimatePluginMapMemory(mapSpec, cpus, 0)
		if err != nil {
			return nil, fmt.Errorf("map %q: %w", name, err)
		}
		if bytes > limits.MapMemoryBytes {
			return nil, fmt.Errorf("map %q estimated memory = %d bytes exceeds per-map limit %d", name, bytes, limits.MapMemoryBytes)
		}
		if !safeAddUint64(&usage.EstimatedMapMemoryBytes, bytes) {
			return nil, fmt.Errorf("map memory estimate overflow")
		}
	}
	return usage, nil
}

func estimatePluginMapMemory(spec *ebpf.MapSpec, cpus, depth int) (uint64, error) {
	if spec == nil {
		return 0, fmt.Errorf("map spec is nil")
	}
	if depth > 1 {
		return 0, fmt.Errorf("nested map depth exceeds one")
	}
	if spec.MaxEntries == 0 {
		return 0, fmt.Errorf("max_entries must be positive")
	}
	if spec.Pinning != ebpf.PinNone {
		return 0, fmt.Errorf("map pinning is not managed by the plugin runtime")
	}
	entries := uint64(spec.MaxEntries)
	key := alignPluginMapBytes(uint64(spec.KeySize))
	value := alignPluginMapBytes(uint64(spec.ValueSize))
	var entryBytes uint64
	switch spec.Type {
	case ebpf.RingBuf, ebpf.UserRingbuf:
		return entries, nil
	case ebpf.Arena, ebpf.StructOpsMap:
		return 0, fmt.Errorf("map type %s is not supported for external plugins", spec.Type)
	case ebpf.Array, ebpf.ProgramArray, ebpf.PerfEventArray,
		ebpf.CGroupArray, ebpf.ArrayOfMaps, ebpf.DevMap, ebpf.CPUMap,
		ebpf.XSKMap, ebpf.ReusePortSockArray:
		entryBytes = value
	case ebpf.Hash, ebpf.LRUHash, ebpf.LRUCPUHash, ebpf.LPMTrie,
		ebpf.HashOfMaps, ebpf.DevMapHash, ebpf.SockHash:
		entryBytes = key + value + 32
	case ebpf.PerCPUHash:
		entryBytes = key + value*uint64(cpus) + 32
	case ebpf.PerCPUArray:
		entryBytes = value * uint64(cpus)
	case ebpf.Queue, ebpf.Stack, ebpf.BloomFilter, ebpf.StackTrace,
		ebpf.SockMap, ebpf.CGroupStorage, ebpf.PerCPUCGroupStorage,
		ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage, ebpf.CgroupStorage:
		entryBytes = key + value + 32
	default:
		return 0, fmt.Errorf("map type %s is not supported for external plugins", spec.Type)
	}
	if entryBytes == 0 {
		entryBytes = 8
	}
	bytes, ok := safeMulUint64(entries, entryBytes)
	if !ok {
		return 0, fmt.Errorf("memory estimate overflow")
	}
	if spec.InnerMap != nil {
		innerBytes, err := estimatePluginMapMemory(spec.InnerMap, cpus, depth+1)
		if err != nil {
			return 0, fmt.Errorf("inner map: %w", err)
		}
		instances := uint64(1)
		if len(spec.Contents) > 0 {
			instances = uint64(len(spec.Contents))
		}
		initialBytes, ok := safeMulUint64(innerBytes, instances)
		if !ok || !safeAddUint64(&bytes, initialBytes) {
			return 0, fmt.Errorf("inner map memory estimate overflow")
		}
	}
	// Include map metadata and allocator slack without pretending the estimate
	// is an exact kernel accounting value.
	overhead := uint64(4096)
	if bytes > math.MaxUint64-overhead {
		return 0, fmt.Errorf("memory estimate overflow")
	}
	return bytes + overhead, nil
}

func alignPluginMapBytes(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	return (value + 7) &^ 7
}

func safeMulUint64(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	if a > math.MaxUint64/b {
		return 0, false
	}
	return a * b, true
}

func safeAddUint64(target *uint64, value uint64) bool {
	if target == nil || *target > math.MaxUint64-value {
		return false
	}
	*target += value
	return true
}
