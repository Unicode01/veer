package app

import "testing"

func TestCombinePluginDataplaneSnapshotsMergesTCAndXDPAttachments(t *testing.T) {
	catalog := PluginCatalog{Plugins: []LoadedPlugin{{
		PluginManifest: PluginManifest{ID: "dual_engine", Name: "Dual Engine", Version: "1.0.0", Kind: "pipeline"},
		Status:         pluginStatusActive,
	}}}
	tcAttachment := PluginAttachmentState{HookID: "tc", Engine: kernelEngineTC, Interface: "eth0", Program: "tc:main", Status: "attached"}
	xdpAttachment := PluginAttachmentState{HookID: "xdp", Engine: kernelEngineXDP, Interface: "eth0", Program: "xdp:main", Status: "attached"}

	snapshot := combinePluginDataplaneSnapshots(catalog,
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"dual_engine": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true, Attachments: []PluginAttachmentState{tcAttachment}},
		}},
		pluginRuntimeSnapshot{Plugins: map[string]PluginRuntimeState{
			"dual_engine": {Mode: pluginRuntimeModeDataplane, Attachable: true, Attached: true, Attachments: []PluginAttachmentState{xdpAttachment}},
		}},
	)
	state := snapshot.Plugins["dual_engine"]
	if state.Mode != pluginRuntimeModeDataplane || !state.Attached || state.AttachmentCount != 2 || len(state.Attachments) != 2 {
		t.Fatalf("combined state = %+v", state)
	}
	if state.Attachments[0].Engine != kernelEngineTC || state.Attachments[1].Engine != kernelEngineXDP {
		t.Fatalf("combined attachment order = %+v", state.Attachments)
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
