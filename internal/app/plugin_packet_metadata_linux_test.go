//go:build linux

package app

import (
	"strings"
	"testing"
)

func TestApplyKernelPluginPacketMetadataBindingsResolvesNamespaces(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{
		packetMetadataDesiredPlugin("producer", "producer.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "producer/classification", SchemaVersion: 2, MaxBytes: 24, Access: pluginPacketMetadataAccessReadWrite,
		}}),
		packetMetadataDesiredPlugin("consumer", "consumer.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 3, Namespace: "producer/classification", SchemaVersion: 2, MaxBytes: 24, Access: pluginPacketMetadataAccessRead,
		}}),
		packetMetadataDesiredPlugin("other", "other.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "other/flags", SchemaVersion: 1, MaxBytes: 8, Access: pluginPacketMetadataAccessReadWrite,
		}}),
	}
	resolved, states := applyKernelPluginPacketMetadataBindings(desired, map[string]PluginRuntimeState{})
	if len(states) != 0 || len(resolved) != 3 {
		t.Fatalf("resolved=%+v states=%+v", resolved, states)
	}
	slots := make(map[string]uint32)
	for _, item := range resolved {
		binding := item.hooks[0].PacketMetadata[0]
		slots[item.plugin.ID] = binding.NamespaceSlot
	}
	if slots["other"] != 0 || slots["producer"] != 1 || slots["consumer"] != slots["producer"] {
		t.Fatalf("namespace slots = %+v", slots)
	}
}

func TestApplyKernelPluginPacketMetadataBindingsContainsInvalidPlugins(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{
		packetMetadataDesiredPlugin("producer", "producer.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "producer/data", SchemaVersion: 1, MaxBytes: 16, Access: pluginPacketMetadataAccessReadWrite,
		}}),
		packetMetadataDesiredPlugin("consumer", "consumer.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "producer/data", SchemaVersion: 2, MaxBytes: 16, Access: pluginPacketMetadataAccessRead,
		}}),
		packetMetadataDesiredPlugin("healthy", "healthy.o"),
	}
	resolved, states := applyKernelPluginPacketMetadataBindings(desired, map[string]PluginRuntimeState{})
	if len(resolved) != 2 || resolved[0].plugin.ID != "producer" || resolved[1].plugin.ID != "healthy" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if state := states["consumer"]; !strings.Contains(state.Error, "owner provides version 1") {
		t.Fatalf("consumer state = %+v", state)
	}
}

func TestApplyKernelPluginPacketMetadataBindingsRejectsForeignWriterAndDependents(t *testing.T) {
	desired := []kernelPluginPipelineDesiredPlugin{
		packetMetadataDesiredPlugin("intruder", "intruder.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "owner/data", SchemaVersion: 1, MaxBytes: 16, Access: pluginPacketMetadataAccessReadWrite,
		}}),
		packetMetadataDesiredPlugin("reader", "reader.o", kernelPluginPacketMetadataBinding{PluginPacketMetadataBinding: PluginPacketMetadataBinding{
			Slot: 0, Namespace: "owner/data", SchemaVersion: 1, MaxBytes: 16, Access: pluginPacketMetadataAccessRead,
		}}),
		packetMetadataDesiredPlugin("healthy", "healthy.o"),
	}
	resolved, states := applyKernelPluginPacketMetadataBindings(desired, map[string]PluginRuntimeState{})
	if len(resolved) != 1 || resolved[0].plugin.ID != "healthy" {
		t.Fatalf("resolved = %+v", resolved)
	}
	if !strings.Contains(states["intruder"].Error, "owned by plugin owner") {
		t.Fatalf("intruder state = %+v", states["intruder"])
	}
	if !strings.Contains(states["reader"].Error, "no active read_write owner") {
		t.Fatalf("reader state = %+v", states["reader"])
	}
}

func packetMetadataDesiredPlugin(pluginID, objectID string, bindings ...kernelPluginPacketMetadataBinding) kernelPluginPipelineDesiredPlugin {
	return kernelPluginPipelineDesiredPlugin{
		plugin: LoadedPlugin{PluginManifest: PluginManifest{ID: pluginID}},
		hooks: []kernelPluginPipelineHookPlan{{
			PluginID: pluginID, HookID: "hook", ObjectID: objectID, ObjectPath: "/tmp/" + objectID,
			Stage: kernelPluginPipelineStagePreForward, PacketMetadata: bindings,
		}},
	}
}
