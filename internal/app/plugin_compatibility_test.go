package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/kernelcap"
	"github.com/Unicode01/veer/internal/store"
)

func TestNormalizePluginManifestCompatibilityAndRelationships(t *testing.T) {
	var manifest PluginManifest
	err := json.Unmarshal([]byte(`{
  "api_version": "v1",
  "id": "edge_plugin",
  "name": "Edge Plugin",
  "version": "1.2.3-beta.1+build.7",
  "kind": "pipeline",
  "compatibility": {
    "runtime": ">=1.0.0 <2.0.0",
    "tc_pipeline_abi": 2,
    "os": ["linux"],
    "architectures": ["arm64", "amd64"],
    "kernel": ">=5.10.0",
    "features": ["dataplane.tc_pipeline.v2"]
  },
  "dependencies": [
    {"id": "wan_core", "version": ">=1.2.0 <2.0.0"},
    {"id": "optional_helper", "version": "^2.0.0", "optional": true}
  ],
  "conflicts": [
    {"id": "legacy_edge", "version": "<1.0.0"}
  ]
}`), &manifest)
	if err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if err := normalizePluginManifest(&manifest); err != nil {
		t.Fatalf("normalizePluginManifest() error = %v", err)
	}
	if manifest.Version != "1.2.3-beta.1+build.7" {
		t.Fatalf("version = %q", manifest.Version)
	}
	if manifest.Compatibility == nil || manifest.Compatibility.Runtime != ">=1.0.0 <2.0.0" || manifest.Compatibility.TCPipelineABI != 2 {
		t.Fatalf("compatibility = %+v", manifest.Compatibility)
	}
	if got := strings.Join(manifest.Compatibility.Architectures, ","); got != "amd64,arm64" {
		t.Fatalf("architectures = %q", got)
	}
	if len(manifest.Dependencies) != 2 || manifest.Dependencies[0].ID != "optional_helper" || !manifest.Dependencies[0].Optional {
		t.Fatalf("dependencies = %+v", manifest.Dependencies)
	}
	if len(manifest.Conflicts) != 1 || manifest.Conflicts[0].ID != "legacy_edge" {
		t.Fatalf("conflicts = %+v", manifest.Conflicts)
	}
}

func TestNormalizePluginManifestRejectsInvalidStaticContracts(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unknown top level", body: `"typo":true`, want: `unknown manifest field "typo"`},
		{name: "unknown compatibility", body: `"compatibility":{"runtime_api":"1"}`, want: `unknown field "runtime_api"`},
		{name: "invalid version", body: `"version":"latest"`, want: "must be a semantic version"},
		{name: "invalid runtime constraint", body: `"compatibility":{"runtime":"not-a-range"}`, want: "invalid semantic version constraint"},
		{name: "negative ABI", body: `"compatibility":{"tc_pipeline_abi":-1}`, want: "cannot be negative"},
		{name: "self dependency", body: `"dependencies":[{"id":"contract_plugin"}]`, want: "cannot reference the plugin itself"},
		{name: "relationship overlap", body: `"dependencies":[{"id":"helper"}],"conflicts":[{"id":"helper"}]`, want: "both a dependency and a conflict"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := `"version":"1.0.0",`
			if strings.Contains(tt.body, `"version"`) {
				version = ""
			}
			data := []byte(`{"api_version":"v1","id":"contract_plugin","name":"Contract",` + version + `"kind":"control",` + tt.body + `}`)
			var manifest PluginManifest
			err := json.Unmarshal(data, &manifest)
			if err == nil {
				err = normalizePluginManifest(&manifest)
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckPluginCompatibility(t *testing.T) {
	env := pluginHostEnvironment{
		RuntimeVersion: "1.4.0",
		TCPipelineABI:  2,
		OS:             "linux",
		Arch:           "arm64",
		KernelRelease:  "6.8.12",
		Features:       map[string]struct{}{"control.goja.v1": {}, "dataplane.tc_pipeline.v2": {}},
	}
	compatible := relationshipTestPlugin("compatible", "1.0.0")
	compatible.Compatibility = &PluginCompatibility{
		Runtime:       ">=1.2.0 <2.0.0",
		TCPipelineABI: 2,
		OS:            []string{"linux"},
		Architectures: []string{"amd64", "arm64"},
		Kernel:        ">=6.6.0",
		Features:      []string{"control.goja.v1"},
	}
	if err := checkPluginCompatibility(compatible, env); err != nil {
		t.Fatalf("compatible plugin error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*PluginCompatibility)
		want   string
	}{
		{name: "runtime", mutate: func(c *PluginCompatibility) { c.Runtime = ">=2.0.0" }, want: "runtime"},
		{name: "pipeline ABI", mutate: func(c *PluginCompatibility) { c.TCPipelineABI = 3 }, want: "pipeline ABI"},
		{name: "os", mutate: func(c *PluginCompatibility) { c.OS = []string{"freebsd"} }, want: "operating system"},
		{name: "arch", mutate: func(c *PluginCompatibility) { c.Architectures = []string{"riscv64"} }, want: "architecture"},
		{name: "kernel", mutate: func(c *PluginCompatibility) { c.Kernel = ">=7.0.0" }, want: "kernel"},
		{name: "feature", mutate: func(c *PluginCompatibility) { c.Features = []string{"missing.feature"} }, want: "missing required features"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := compatible
			copyCompatibility := *compatible.Compatibility
			copyCompatibility.OS = append([]string(nil), compatible.Compatibility.OS...)
			copyCompatibility.Architectures = append([]string(nil), compatible.Compatibility.Architectures...)
			copyCompatibility.Features = append([]string(nil), compatible.Compatibility.Features...)
			plugin.Compatibility = &copyCompatibility
			tt.mutate(plugin.Compatibility)
			err := checkPluginCompatibility(plugin, env)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestResolvePluginCatalogRelationshipsAndOrder(t *testing.T) {
	base := relationshipTestPlugin("base", "1.3.0")
	middle := relationshipTestPlugin("middle", "2.0.0")
	middle.Dependencies = []PluginDependency{{ID: "base", Version: ">=1.2.0 <2.0.0"}}
	application := relationshipTestPlugin("application", "3.0.0")
	application.Dependencies = []PluginDependency{{ID: "middle", Version: "^2.0.0"}}
	optional := relationshipTestPlugin("optional", "1.0.0")
	optional.Dependencies = []PluginDependency{{ID: "not_installed", Version: "*", Optional: true}}

	catalog := PluginCatalog{Plugins: []LoadedPlugin{application, optional, middle, base}}
	catalog = resolvePluginCatalogRelationships(catalog, relationshipTestEnvironment())
	for _, plugin := range catalog.Plugins {
		if plugin.Status != pluginStatusActive {
			t.Fatalf("plugin %s status=%s error=%s", plugin.ID, plugin.Status, plugin.Error)
		}
	}
	indexes := pluginCatalogExecutionIndexes(catalog)
	ids := make([]string, 0, len(indexes))
	for _, index := range indexes {
		ids = append(ids, catalog.Plugins[index].ID)
	}
	if got := strings.Join(ids, ","); got != "base,middle,application,optional" {
		t.Fatalf("execution order = %q", got)
	}
}

func TestResolvePluginCatalogRejectsDependencyFailures(t *testing.T) {
	tests := []struct {
		name    string
		plugins []LoadedPlugin
		failed  []string
		want    string
	}{
		{
			name: "missing",
			plugins: []LoadedPlugin{withRelationshipDependencies(relationshipTestPlugin("app", "1.0.0"),
				PluginDependency{ID: "missing", Version: ">=1.0.0"})},
			failed: []string{"app"}, want: "not installed",
		},
		{
			name: "version",
			plugins: []LoadedPlugin{
				withRelationshipDependencies(relationshipTestPlugin("app", "1.0.0"), PluginDependency{ID: "base", Version: ">=2.0.0"}),
				relationshipTestPlugin("base", "1.9.0"),
			},
			failed: []string{"app"}, want: "does not satisfy",
		},
		{
			name: "disabled",
			plugins: []LoadedPlugin{
				withRelationshipDependencies(relationshipTestPlugin("app", "1.0.0"), PluginDependency{ID: "base", Version: "*"}),
				disabledRelationshipTestPlugin("base", "1.0.0"),
			},
			failed: []string{"app"}, want: "is disabled",
		},
		{
			name: "conflict",
			plugins: []LoadedPlugin{
				withRelationshipConflicts(relationshipTestPlugin("first", "1.0.0"), PluginConflict{ID: "second", Version: ">=1.0.0"}),
				relationshipTestPlugin("second", "1.0.0"),
			},
			failed: []string{"first", "second"}, want: "conflicts with",
		},
		{
			name: "cycle and dependent",
			plugins: []LoadedPlugin{
				withRelationshipDependencies(relationshipTestPlugin("a", "1.0.0"), PluginDependency{ID: "b", Version: "*"}),
				withRelationshipDependencies(relationshipTestPlugin("b", "1.0.0"), PluginDependency{ID: "a", Version: "*"}),
				withRelationshipDependencies(relationshipTestPlugin("consumer", "1.0.0"), PluginDependency{ID: "a", Version: "*"}),
			},
			failed: []string{"a", "b", "consumer"}, want: "dependency",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog := resolvePluginCatalogRelationships(PluginCatalog{Plugins: tt.plugins}, relationshipTestEnvironment())
			for _, id := range tt.failed {
				plugin := relationshipPluginByID(t, catalog, id)
				if plugin.Status != pluginStatusError || !strings.Contains(plugin.Error, tt.want) {
					t.Fatalf("plugin %s status=%s error=%q, want %q", id, plugin.Status, plugin.Error, tt.want)
				}
			}
		})
	}
}

func TestApplyPluginStatesDisablesRequiredDependentsAndRecovers(t *testing.T) {
	dir := t.TempDir()
	writeRelationshipManifest(t, dir, "base", "1.0.0", nil, "")
	writeRelationshipManifest(t, dir, "dependent", "1.0.0", []PluginDependency{{ID: "base", Version: "^1.0.0"}}, "")
	db := openTestDB(t)
	if err := store.SetPluginEnabled(db, "base", false); err != nil {
		t.Fatalf("SetPluginEnabled(false) error = %v", err)
	}
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	catalog := loadPluginCatalogWithState(cfg, db)
	dependent := relationshipPluginByID(t, catalog, "dependent")
	if dependent.Status != pluginStatusError || !strings.Contains(dependent.Error, "base is disabled") {
		t.Fatalf("dependent while base disabled = %+v", dependent)
	}

	if err := store.SetPluginEnabled(db, "base", true); err != nil {
		t.Fatalf("SetPluginEnabled(true) error = %v", err)
	}
	catalog = loadPluginCatalogWithState(cfg, db)
	dependent = relationshipPluginByID(t, catalog, "dependent")
	if dependent.Status != pluginStatusActive || dependent.Error != "" {
		t.Fatalf("dependent after base recovery = %+v", dependent)
	}
}

func TestPluginControlReconcileStopsAfterRequiredDependencyFailure(t *testing.T) {
	dir := t.TempDir()
	writeRelationshipManifest(t, dir, "base", "1.0.0", nil, `exports.onReconcile = function () { throw new Error('base failed'); };`)
	writeRelationshipManifest(t, dir, "dependent", "1.0.0", []PluginDependency{{ID: "base", Version: "^1.0.0"}}, `exports.onReconcile = function () { throw new Error('dependent should not execute'); };`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	catalog := loadPluginCatalogWithState(cfg, openTestDB(t))
	runtime := newPluginControlRuntime(openTestDB(t), cfg, nil)
	defer runtime.Close()
	snapshot := runtime.Reconcile(catalog)
	base := snapshot.Plugins["base"]
	if base.Mode != pluginRuntimeModeError || !strings.Contains(base.Error, "base failed") {
		t.Fatalf("base state = %+v", base)
	}
	dependent := snapshot.Plugins["dependent"]
	if dependent.Mode != pluginRuntimeModeError || !strings.Contains(dependent.Reason, "required dependency reconcile failed") || strings.Contains(dependent.Error, "should not execute") {
		t.Fatalf("dependent state = %+v", dependent)
	}
}

func TestPluginRuntimeCapabilitiesExposeCompatibilityContract(t *testing.T) {
	caps := pluginRuntimeCapabilities(pluginsEnabledTestConfig(&Config{}))
	if caps.RuntimeVersion != pluginRuntimeVersion || caps.TCPipelineABI != pluginTCPipelineABI {
		t.Fatalf("runtime contract = version %q ABI %d", caps.RuntimeVersion, caps.TCPipelineABI)
	}
	if caps.HostOS == "" || caps.HostArch == "" {
		t.Fatalf("runtime environment = %+v", caps)
	}
	if caps.XDPPipeline.ProgramArrayEntries != pluginXDPPipelineProgramArrayEntries || caps.XDPPipeline.HookLimit != pluginXDPPipelineHookLimit || !caps.XDPPipeline.RequiresInterfaces {
		t.Fatalf("xdp pipeline contract = %+v", caps.XDPPipeline)
	}
	for _, feature := range []string{
		"control.process_isolation.v1",
		"control.resource_schema.v1",
		"control.resource_transactions.v1",
		"dataplane.tc_pipeline.v2",
		"dataplane.xdp_pipeline.v1",
		"ebpf.map_migration.v1",
	} {
		if !containsString(caps.Features, feature) {
			t.Fatalf("runtime features = %+v, missing %s", caps.Features, feature)
		}
	}
}

func TestPluginHostPreflightRejectsUnavailableInferredXDPFeature(t *testing.T) {
	original := detectPluginHostKernelCapabilities
	t.Cleanup(func() { detectPluginHostKernelCapabilities = original })
	available := kernelcap.CapabilityCheck{Available: true}
	caps := kernelcap.KernelCapabilities{
		OS:              "linux",
		BPFXDP:          kernelcap.CapabilityCheck{Reason: "test verifier rejected xdp"},
		BPFMapProgArray: available,
		Netlink:         kernelcap.NetlinkCapabilities{LinkList: available},
	}
	detectPluginHostKernelCapabilities = func() kernelcap.KernelCapabilities { return caps }
	plugin := relationshipTestPlugin("xdp_pipeline", "1.0.0")
	plugin.Hooks = []PluginHook{{
		ID: "pre", Engine: kernelEngineXDP, Attach: "ingress", Stage: pluginPipelineStagePreForward,
		Program: "dataplane:pre", Mode: "observe", Interfaces: []string{"eth0"},
	}}
	if err := checkPluginHostPrerequisites(plugin); err == nil || !strings.Contains(err.Error(), "dataplane.xdp_pipeline.v1") || !strings.Contains(err.Error(), "test verifier rejected xdp") {
		t.Fatalf("XDP preflight error = %v", err)
	}
	caps.BPFXDP = available
	if err := checkPluginHostPrerequisites(plugin); err != nil {
		t.Fatalf("available XDP preflight error = %v", err)
	}
}

func TestPluginHostPreflightRejectsUnavailableInferredTCFeature(t *testing.T) {
	original := detectPluginHostKernelCapabilities
	t.Cleanup(func() { detectPluginHostKernelCapabilities = original })
	available := kernelcap.CapabilityCheck{Available: true}
	caps := kernelcap.KernelCapabilities{
		OS:                "linux",
		BPFMapArray:       available,
		BPFMapHash:        available,
		BPFMapLRUHash:     available,
		BPFMapPerCPUHash:  available,
		BPFMapPerCPUArray: available,
		BPFMapProgArray:   available,
		BPFMapRingBuf:     available,
		BPFSchedCLS:       available,
		TC:                kernelcap.CapabilityCheck{Reason: "test verifier rejected sched_cls"},
		Netlink: kernelcap.NetlinkCapabilities{
			RouteSocket: available,
			LinkList:    available,
			RouteList:   available,
		},
	}
	detectPluginHostKernelCapabilities = func() kernelcap.KernelCapabilities { return caps }
	plugin := relationshipTestPlugin("pipeline", "1.0.0")
	plugin.Hooks = []PluginHook{{
		ID: "forward", Engine: kernelEngineTC, Attach: "ingress", Stage: pluginPipelineDirectionForward,
		Program: "dataplane:forward", Mode: "observe",
	}}
	if err := checkPluginHostPrerequisites(plugin); err == nil || !strings.Contains(err.Error(), "dataplane.tc_pipeline.v2") || !strings.Contains(err.Error(), "test verifier rejected") {
		t.Fatalf("TC preflight error = %v", err)
	}
	capabilities := pluginRuntimeCapabilities(pluginsEnabledTestConfig(&Config{}))
	if capabilities.FeatureStatus["dataplane.tc_pipeline.v2"].Available || containsString(capabilities.AvailableFeatures, "dataplane.tc_pipeline.v2") {
		t.Fatalf("runtime capability availability = %+v", capabilities)
	}

	caps.TC = available
	if err := checkPluginHostPrerequisites(plugin); err != nil {
		t.Fatalf("available TC preflight error = %v", err)
	}
}

func TestPluginHostPreflightInfersPrivateMapRequirements(t *testing.T) {
	original := detectPluginHostKernelCapabilities
	t.Cleanup(func() { detectPluginHostKernelCapabilities = original })
	available := kernelcap.CapabilityCheck{Available: true}
	caps := kernelcap.KernelCapabilities{
		OS:                "linux",
		BPFMapArray:       available,
		BPFMapHash:        kernelcap.CapabilityCheck{Reason: "test hash maps unavailable"},
		BPFMapPerCPUHash:  available,
		BPFMapPerCPUArray: available,
		BPFMapProgArray:   available,
		BPFSchedCLS:       available,
		TC:                available,
	}
	detectPluginHostKernelCapabilities = func() kernelcap.KernelCapabilities { return caps }
	plugin := relationshipTestPlugin("map_plugin", "1.0.0")
	plugin.Control = &PluginControl{Permissions: []string{"ebpf.map_write"}}
	if err := checkPluginHostPrerequisites(plugin); err == nil || !strings.Contains(err.Error(), "ebpf.private_maps") || !strings.Contains(err.Error(), "test hash maps unavailable") {
		t.Fatalf("private map preflight error = %v", err)
	}
	availability := currentPluginHostFeatureAvailability()
	if availability.Status["ebpf.map_transactions.v1"].Available {
		t.Fatalf("map transaction availability = %+v", availability.Status["ebpf.map_transactions.v1"])
	}
	plugin.Objects = []PluginObject{{StateMaps: []PluginObjectStateMap{
		{Name: "sessions_v1", Policy: pluginObjectMapPreserve, SchemaVersion: 1},
		{Name: "sessions_v2", Policy: pluginObjectMapMigrate, SchemaVersion: 2, MigrateFrom: "sessions_v1"},
	}}}
	if err := checkPluginHostPrerequisites(plugin); err == nil || !strings.Contains(err.Error(), "ebpf.map_migration.v1") {
		t.Fatalf("map migration preflight error = %v", err)
	}

	caps.BPFMapHash = available
	if err := checkPluginHostPrerequisites(plugin); err != nil {
		t.Fatalf("available private map preflight error = %v", err)
	}
	availability = currentPluginHostFeatureAvailability()
	if !availability.Status["ebpf.map_transactions.v1"].Available {
		t.Fatalf("map transaction availability = %+v", availability.Status["ebpf.map_transactions.v1"])
	}
}

func TestPluginHostPreflightMarksLinuxNetworkFeaturesUnavailableOffLinux(t *testing.T) {
	original := detectPluginHostKernelCapabilities
	t.Cleanup(func() { detectPluginHostKernelCapabilities = original })
	detectPluginHostKernelCapabilities = func() kernelcap.KernelCapabilities {
		return kernelcap.KernelCapabilities{OS: "windows"}
	}
	availability := currentPluginHostFeatureAvailability()
	for _, feature := range []string{"control.net_offloads.v1", "control.net_policy.v1", "control.net_transactions.v1", "dataplane.xdp_pipeline.v1", "ebpf.map_transactions.v1", "ebpf.map_migration.v1"} {
		if state := availability.Status[feature]; state.Available || !strings.Contains(state.Reason, "requires Linux") {
			t.Fatalf("feature %s availability = %+v", feature, state)
		}
	}
}

func TestPluginGojaHostInfoExposesCompatibilityContract(t *testing.T) {
	dir := t.TempDir()
	writeRelationshipManifest(t, dir, "host_info", "1.0.0", nil, `
plugin.action({id: 'host_info', runtime_update: 'runtime_query'});
exports.onAction = function () { return plugin.host(); };
`)
	cfg := pluginsEnabledTestConfig(&Config{PluginsDir: dir})
	db := openTestDB(t)
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	plugin := relationshipPluginByID(t, catalog, "host_info")
	if len(plugin.Actions) != 1 {
		t.Fatalf("actions = %+v", plugin.Actions)
	}
	runtime := newPluginControlRuntime(db, cfg, nil)
	defer runtime.Close()
	runtime.Reconcile(catalog)
	result, err := runtime.QueryPluginAction(plugin, plugin.Actions[0], json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("QueryPluginAction() error = %v", err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(host info) error = %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`"runtime_version":"` + pluginRuntimeVersion + `"`,
		`"tc_pipeline_abi":` + fmt.Sprint(pluginTCPipelineABI),
		`"dataplane.tc_pipeline.v2"`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("host info = %s, want %s", text, want)
		}
	}
}

func relationshipTestEnvironment() pluginHostEnvironment {
	return pluginHostEnvironment{
		RuntimeVersion: pluginRuntimeVersion,
		TCPipelineABI:  pluginTCPipelineABI,
		OS:             "linux",
		Arch:           "amd64",
		KernelRelease:  "6.8.0",
		Features: func() map[string]struct{} {
			features := make(map[string]struct{}, len(pluginRuntimeFeatures))
			for _, feature := range pluginRuntimeFeatures {
				features[feature] = struct{}{}
			}
			return features
		}(),
	}
}

func relationshipTestPlugin(id, version string) LoadedPlugin {
	return LoadedPlugin{
		PluginManifest: PluginManifest{APIVersion: pluginAPIVersionV1, ID: id, Name: id, Version: version, Kind: "control", Stability: pluginStabilityStable},
		Enabled:        true,
		Status:         pluginStatusActive,
		Runtime:        externalPluginRuntimeState(),
	}
}

func disabledRelationshipTestPlugin(id, version string) LoadedPlugin {
	plugin := relationshipTestPlugin(id, version)
	disableLoadedPlugin(&plugin)
	return plugin
}

func withRelationshipDependencies(plugin LoadedPlugin, dependencies ...PluginDependency) LoadedPlugin {
	plugin.Dependencies = dependencies
	return plugin
}

func withRelationshipConflicts(plugin LoadedPlugin, conflicts ...PluginConflict) LoadedPlugin {
	plugin.Conflicts = conflicts
	return plugin
}

func relationshipPluginByID(t *testing.T, catalog PluginCatalog, id string) LoadedPlugin {
	t.Helper()
	for _, plugin := range catalog.Plugins {
		if plugin.ID == id {
			return plugin
		}
	}
	t.Fatalf("plugin %s not found in %+v", id, catalog.Plugins)
	return LoadedPlugin{}
}

func writeRelationshipManifest(t *testing.T, root, id, version string, dependencies []PluginDependency, control string) {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", id, err)
	}
	manifest := PluginManifest{
		APIVersion:   pluginAPIVersionV1,
		ID:           id,
		Name:         id,
		Version:      version,
		Kind:         "control",
		Stability:    pluginStabilityLab,
		Dependencies: dependencies,
	}
	if control != "" {
		manifest.Control = &PluginControl{Main: "control.js", Permissions: []string{"plugin.register"}}
		if err := os.WriteFile(filepath.Join(dir, "control.js"), []byte(control), 0o600); err != nil {
			t.Fatalf("WriteFile(control.js) error = %v", err)
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent(%s) error = %v", id, err)
	}
	if err := os.WriteFile(filepath.Join(dir, pluginManifestFile), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile(plugin.json) error = %v", err)
	}
}
