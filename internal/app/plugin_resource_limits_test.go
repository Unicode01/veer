package app

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPluginMapResourceEstimateAccountsForPerCPUValues(t *testing.T) {
	t.Parallel()
	spec := &ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 64, MaxEntries: 1024}
	got, err := estimatePluginMapMemory(spec, 8, 0)
	if err != nil {
		t.Fatal(err)
	}
	wantMinimum := uint64(1024 * 64 * 8)
	if got < wantMinimum {
		t.Fatalf("estimated bytes = %d, want at least %d", got, wantMinimum)
	}
}

func TestPluginObjectResourceUsageRejectsOversizedMap(t *testing.T) {
	t.Parallel()
	limits := pluginResourceLimitsFromConfig(nil)
	limits.MapMemoryBytes = 1 << 20
	_, err := pluginObjectResourceUsageFromSpec(&ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"sessions": {Type: ebpf.Hash, KeySize: 16, ValueSize: 64, MaxEntries: 65536},
	}}, limits)
	if err == nil || !strings.Contains(err.Error(), "per-map limit") {
		t.Fatalf("oversized map error = %v", err)
	}
}

func TestPluginObjectResourceUsageRejectsUnmanagedPinning(t *testing.T) {
	t.Parallel()
	_, err := pluginObjectResourceUsageFromSpec(&ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"pinned": {Type: ebpf.Hash, KeySize: 4, ValueSize: 8, MaxEntries: 1, Pinning: ebpf.PinByName},
	}}, pluginResourceLimitsFromConfig(nil))
	if err == nil || !strings.Contains(err.Error(), "pinning") {
		t.Fatalf("pinned map error = %v", err)
	}
}

func TestPluginSurfaceDefinitionBudgetRejectsExcessResources(t *testing.T) {
	t.Parallel()
	pluginsDir := t.TempDir()
	writeTestPlugin(t, pluginsDir, "resource_budget", `{
  "api_version":"v1",
  "id":"resource_budget",
  "name":"Resource Budget",
  "version":"1.0.0",
  "kind":"control",
  "resources":[
    {"id":"first","methods":["list"]},
    {"id":"second","methods":["list"]}
  ]
}`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: pluginsDir, PluginsResourceLimits: PluginResourceLimitConfig{ResourcesPerPlugin: 1}})
	plugin := pluginByIDForTest(t, loadPluginCatalogWithControlRegistration(cfg), "resource_budget")
	if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, "resources = 2 exceeds limit 1") {
		t.Fatalf("plugin status=%q error=%q", plugin.Status, plugin.Error)
	}
}

func TestPluginCatalogGlobalMapBudgetRejectsOverflowingPlugin(t *testing.T) {
	t.Parallel()
	catalog := PluginCatalog{
		Runtime: PluginRuntimeCapabilities{ResourceLimits: PluginResourceLimits{GlobalMapMemoryBytes: 100}},
		Plugins: []LoadedPlugin{
			{PluginManifest: PluginManifest{ID: "first"}, Status: pluginStatusActive, ResourceUsage: &PluginResourceUsage{EstimatedMapMemoryBytes: 60}},
			{PluginManifest: PluginManifest{ID: "second"}, Status: pluginStatusActive, ResourceUsage: &PluginResourceUsage{EstimatedMapMemoryBytes: 50}},
		},
	}
	enforcePluginCatalogGlobalResourceLimits(&catalog)
	if catalog.Plugins[0].Status != pluginStatusActive {
		t.Fatalf("first plugin status = %q", catalog.Plugins[0].Status)
	}
	if catalog.Plugins[1].Status != pluginStatusError || !strings.Contains(catalog.Plugins[1].Error, "global plugin eBPF map budget exceeded") {
		t.Fatalf("second plugin status=%q error=%q", catalog.Plugins[1].Status, catalog.Plugins[1].Error)
	}
	if got := catalog.Runtime.ResourceUsage.EstimatedMapMemoryBytes; got != 60 {
		t.Fatalf("global admitted map memory = %d, want 60", got)
	}
}

func TestNormalizePluginResourceLimitConfigRejectsInconsistentMemoryLimits(t *testing.T) {
	t.Parallel()
	_, err := normalizePluginResourceLimitConfig(PluginResourceLimitConfig{
		MapMemoryMB:       128,
		PluginMapMemoryMB: 64,
	})
	if err == nil || !strings.Contains(err.Error(), "map_memory_mb") {
		t.Fatalf("inconsistent memory limit error = %v", err)
	}
}

func TestPluginHostResourceLimitsUseNormalizedConfig(t *testing.T) {
	t.Parallel()
	cfg := &Config{PluginsResourceLimits: PluginResourceLimitConfig{
		ControlMemoryMB:        384,
		GlobalControlMemoryMB:  1536,
		ControlProcessMemoryMB: 192,
		ControlPIDs:            32,
		GlobalControlPIDs:      256,
		ControlCPUPercent:      150,
	}}
	limits := pluginHostResourceLimitsFromConfig(cfg)
	if limits.MemoryBytes != 384<<20 || limits.GlobalMemoryBytes != 1536<<20 || limits.ProcessRSSBytes != 192<<20 {
		t.Fatalf("memory limits = %+v", limits)
	}
	if limits.PIDs != 32 || limits.GlobalPIDs != 256 || limits.CPUPercent != 150 {
		t.Fatalf("process limits = %+v", limits)
	}
}

func TestNormalizePluginResourceLimitConfigRejectsProcessLimitAboveCgroup(t *testing.T) {
	t.Parallel()
	_, err := normalizePluginResourceLimitConfig(PluginResourceLimitConfig{
		ControlMemoryMB:        128,
		GlobalControlMemoryMB:  512,
		ControlProcessMemoryMB: 256,
	})
	if err == nil || !strings.Contains(err.Error(), "control_process_memory_mb") {
		t.Fatalf("inconsistent control memory error = %v", err)
	}
}
