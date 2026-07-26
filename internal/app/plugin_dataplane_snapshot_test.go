package app

import (
	"strings"
	"testing"
)

func TestCombinePluginDataplaneSnapshotsMergesTCXDPAndNetfilterAttachments(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "dual_engine", Name: "Dual Engine", Version: "1.0.0", Kind: "pipeline"},
		Status:         pluginStatusActive,
	}}}
	tcAttachment := PluginAttachmentState{HookID: "tc", Engine: kernelEngineTC, Interface: "eth0", Program: "tc:main", Status: "attached"}
	xdpAttachment := PluginAttachmentState{HookID: "xdp", Engine: kernelEngineXDP, Interface: "eth0", Program: "xdp:main", Status: "attached"}
	netfilterAttachment := PluginAttachmentState{
		HookID: "netfilter", Engine: pluginEngineNetfilter, Attach: "forward", Stage: "filter", Interface: "host",
		Family: "ipv4", NetfilterHook: "forward", Phase: "filter", Namespace: "host", Program: "netfilter:main", Status: "attached",
	}

	snapshot := combinePluginDataplaneSnapshots(catalog,
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"dual_engine": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true, Attachments: []PluginAttachmentState{tcAttachment}},
		}},
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"dual_engine": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true, Attachments: []PluginAttachmentState{xdpAttachment}},
		}},
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"dual_engine": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true, Attachments: []PluginAttachmentState{netfilterAttachment}},
		}},
	)
	state := snapshot.Plugins["dual_engine"]
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 3 || len(state.Attachments) != 3 {
		t.Fatalf("combined state = %+v", state)
	}
	if state.Attachments[0].Engine != kernelEngineTC || state.Attachments[1].Engine != kernelEngineXDP || state.Attachments[2].Engine != pluginEngineNetfilter {
		t.Fatalf("combined attachment order = %+v", state.Attachments)
	}
}

func TestPluginCatalogWithHookEnginesDoesNotMutateSource(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "multi_engine", Name: "Multi Engine", Version: "1.0.0", Kind: "pipeline"},
		Hooks: []PluginHook{
			{ID: "tc", Engine: kernelEngineTC, Before: []string{"peer/tc"}},
			{ID: "xdp", Engine: kernelEngineXDP},
			{ID: "netfilter", Engine: pluginEngineNetfilter, Before: []string{"peer/netfilter"}},
		},
	}}}

	filtered := pluginCatalogWithHookEngines(catalog, pluginEngineNetfilter)
	if len(filtered.Plugins) != 1 || len(filtered.Plugins[0].Hooks) != 1 || filtered.Plugins[0].Hooks[0].Engine != pluginEngineNetfilter {
		t.Fatalf("filtered catalog = %+v", filtered.Plugins)
	}
	filtered.Plugins[0].Hooks[0].Before[0] = "changed/netfilter"
	if len(catalog.Plugins[0].Hooks) != 3 || catalog.Plugins[0].Hooks[2].Before[0] != "peer/netfilter" {
		t.Fatalf("source catalog was mutated = %+v", catalog.Plugins[0].Hooks)
	}
}

func TestCombinePluginDataplaneSnapshotsKeepsAttachmentWithPeerError(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "partial", Name: "Partial", Version: "1.0.0", Kind: "pipeline"},
		Status:         pluginStatusActive,
	}}}
	snapshot := combinePluginDataplaneSnapshots(catalog,
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"partial": {Mode: pluginRuntimeModeDataplane, Attached: true, Attachments: []PluginAttachmentState{{HookID: "tc", Engine: kernelEngineTC, Interface: "eth0", Status: "attached"}}},
		}},
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"partial": pluginRuntimeErrorState("xdp conflict"),
		}},
	)
	state := snapshot.Plugins["partial"]
	if state.Mode != pluginRuntimeModeError || !state.Attached || len(state.Attachments) != 1 || state.Error != "xdp conflict" {
		t.Fatalf("combined partial failure state = %+v", state)
	}
}

func TestCombinePluginDataplaneSnapshotsKeepsNetfilterFamiliesDistinct(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "dual_stack", Name: "Dual Stack", Version: "1.0.0", Kind: "pipeline"},
		Status:         pluginStatusActive,
	}}}
	base := PluginAttachmentState{
		HookID: "filter", Engine: pluginEngineNetfilter, Attach: "output", Stage: "filter", Interface: "host",
		NetfilterHook: "output", Phase: "filter", Namespace: "host", Program: "filter:main", Status: "attached",
	}
	ipv4 := base
	ipv4.Family = "ipv4"
	ipv6 := base
	ipv6.Family = "ipv6"

	snapshot := combinePluginDataplaneSnapshots(catalog, pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"dual_stack": {Mode: pluginRuntimeModeDataplane, Attached: true, Attachments: []PluginAttachmentState{ipv6, ipv4}},
	}})
	state := snapshot.Plugins["dual_stack"]
	if state.AttachmentCount != 2 || len(state.Attachments) != 2 {
		t.Fatalf("combined dual-stack state = %+v", state)
	}
	if state.Attachments[0].Family != "ipv4" || state.Attachments[1].Family != "ipv6" {
		t.Fatalf("combined dual-stack attachment order = %+v", state.Attachments)
	}
}

func TestProcessManagerSkipsRuntimeReplayAfterPluginControlFailure(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{
		{PluginManifest: PluginManifest{ID: "broken", Name: "Broken", Version: "1.0.0", Kind: "pipeline"}, Status: pluginStatusActive},
		{PluginManifest: PluginManifest{ID: "healthy", Name: "Healthy", Version: "1.0.0", Kind: "pipeline"}, Status: pluginStatusActive},
	}}
	control := &pluginPostReplayFilterRuntimeTest{controlSnapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
		"broken":  pluginRuntimeErrorState("control failed"),
		"healthy": {Mode: pluginRuntimeModeControl},
	}}}
	pm := &ProcessManager{
		cfg:                  pluginsEnabledTestConfig(&Config{}),
		pluginControlRuntime: control,
		pluginRuntime: pluginDataplaneRuntimeTest{snapshot: pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"broken":  pluginRuntimeErrorState("attach failed"),
			"healthy": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true},
		}}},
	}

	_, err := pm.reconcilePluginCatalogForRuntime(catalog)
	if err == nil || !strings.Contains(err.Error(), "control failed") || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("reconcile error = %v, want retained control and dataplane failures", err)
	}
	if len(control.replayed) != 1 || control.replayed[0] != "healthy" {
		t.Fatalf("runtime replay plugins = %v, want only healthy", control.replayed)
	}
}

type pluginPostReplayFilterRuntimeTest struct {
	emptySnapshotPluginControlRuntimeTest
	controlSnapshot pluginRuntimeSnapshot
	replayed        []string
}

func (rt *pluginPostReplayFilterRuntimeTest) Reconcile(PluginCatalog) pluginRuntimeSnapshot {
	return rt.controlSnapshot
}

func (rt *pluginPostReplayFilterRuntimeTest) Snapshot() pluginRuntimeSnapshot {
	return rt.controlSnapshot
}

func (rt *pluginPostReplayFilterRuntimeTest) ReapplyPluginRuntimeResourcesAfterDataplane(catalog PluginCatalog, _ pluginRuntimeSnapshot) map[string]error {
	for _, plugin := range catalog.Plugins {
		rt.replayed = append(rt.replayed, plugin.ID)
	}
	return nil
}
