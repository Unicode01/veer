package app

import (
	"strings"
	"testing"
)

func TestNormalizePluginPacketMetadataBindings(t *testing.T) {
	hook := PluginHook{
		ID: "producer", Engine: kernelEngineTC, Stage: pluginPipelineStagePreForward, Program: "object:program",
		PacketMetadata: []PluginPacketMetadataBinding{{
			Slot: 3, Namespace: " OWNER / CLASSIFIER ", Access: "READ_WRITE", MaxBytes: 24,
		}},
	}
	if err := normalizePluginHook(&hook); err != nil {
		t.Fatalf("normalizePluginHook() error = %v", err)
	}
	if len(hook.PacketMetadata) != 1 {
		t.Fatalf("packet metadata = %+v", hook.PacketMetadata)
	}
	binding := hook.PacketMetadata[0]
	if binding.Namespace != "owner/classifier" || binding.SchemaVersion != 1 || binding.MaxBytes != 24 || binding.Access != pluginPacketMetadataAccessReadWrite {
		t.Fatalf("normalized binding = %+v", binding)
	}
}

func TestNormalizePluginPacketMetadataBindingsRejectsInvalidContracts(t *testing.T) {
	for name, bindings := range map[string][]PluginPacketMetadataBinding{
		"namespace": {{Slot: 0, Namespace: "missing-separator"}},
		"duplicate_slot": {
			{Slot: 0, Namespace: "owner/first"},
			{Slot: 0, Namespace: "owner/second"},
		},
		"oversized": {{Slot: 0, Namespace: "owner/data", MaxBytes: pluginPacketMetadataPayloadMaxBytes + 1}},
		"access":    {{Slot: 0, Namespace: "owner/data", Access: "write"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := normalizePluginPacketMetadataBindings(bindings)
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatalf("normalize accepted %+v", bindings)
			}
		})
	}
}

func TestNormalizePluginHookRejectsPacketMetadataOutsideTC(t *testing.T) {
	hook := PluginHook{
		ID: "producer", Engine: kernelEngineXDP, Stage: pluginPipelineStagePreForward, Program: "object:program",
		PacketMetadata: []PluginPacketMetadataBinding{{Slot: 0, Namespace: "producer/data"}},
	}
	if err := normalizePluginHook(&hook); err == nil || !strings.Contains(err.Error(), "only available to tc") {
		t.Fatalf("normalizePluginHook() error = %v", err)
	}
}
