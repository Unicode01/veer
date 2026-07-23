//go:build linux

package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	kernelPluginPacketMetadataAccessRead  = uint8(1)
	kernelPluginPacketMetadataAccessWrite = uint8(2)
)

type kernelPluginPacketMetadataBinding struct {
	PluginPacketMetadataBinding
	NamespaceSlot uint32
}

type kernelTCPluginMetadataBindingV1 struct {
	NamespaceSlot uint32
	SchemaVersion uint32
	MaxBytes      uint16
	Access        uint8
	Reserved      uint8
}

type kernelPluginPacketMetadataContract struct {
	SchemaVersion int
	MaxBytes      int
	WriterPlugin  string
}

func kernelPluginPacketMetadataBindings(values []PluginPacketMetadataBinding) []kernelPluginPacketMetadataBinding {
	if len(values) == 0 {
		return nil
	}
	out := make([]kernelPluginPacketMetadataBinding, len(values))
	for i, value := range values {
		out[i].PluginPacketMetadataBinding = value
	}
	return out
}

func cloneKernelPluginPacketMetadataBindings(values []kernelPluginPacketMetadataBinding) []kernelPluginPacketMetadataBinding {
	return append([]kernelPluginPacketMetadataBinding(nil), values...)
}

func pluginPacketMetadataBindingsForState(values []kernelPluginPacketMetadataBinding) []PluginPacketMetadataBinding {
	if len(values) == 0 {
		return nil
	}
	out := make([]PluginPacketMetadataBinding, len(values))
	for i, value := range values {
		out[i] = value.PluginPacketMetadataBinding
	}
	return out
}

func kernelPluginPacketMetadataAccess(value string) uint8 {
	access := kernelPluginPacketMetadataAccessRead
	if value == pluginPacketMetadataAccessReadWrite {
		access |= kernelPluginPacketMetadataAccessWrite
	}
	return access
}

func applyKernelPluginPacketMetadataBindings(desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState) {
	for len(desired) > 0 {
		namespaceSlots, invalid := validateKernelPluginPacketMetadataBindings(desired)
		if len(invalid) == 0 {
			for i := range desired {
				for j := range desired[i].hooks {
					for k := range desired[i].hooks[j].PacketMetadata {
						desired[i].hooks[j].PacketMetadata[k].NamespaceSlot = namespaceSlots[desired[i].hooks[j].PacketMetadata[k].Namespace]
					}
				}
			}
			return desired, states
		}
		filtered := make([]kernelPluginPipelineDesiredPlugin, 0, len(desired))
		for _, item := range desired {
			message, rejected := invalid[item.plugin.ID]
			if !rejected {
				filtered = append(filtered, item)
				continue
			}
			states[item.plugin.ID] = pluginRuntimeErrorState(message)
		}
		if len(filtered) == len(desired) {
			break
		}
		desired = filtered
	}
	return desired, states
}

func validateKernelPluginPacketMetadataBindings(desired []kernelPluginPipelineDesiredPlugin) (map[string]uint32, map[string]string) {
	invalid := make(map[string]string)
	addIssue := func(pluginID, message string) {
		if previous := invalid[pluginID]; previous == "" {
			invalid[pluginID] = message
		} else if !strings.Contains(previous, message) {
			invalid[pluginID] = previous + "; " + message
		}
	}

	type localBinding struct {
		namespace     string
		schemaVersion int
		maxBytes      int
	}
	localSlots := make(map[string]localBinding)
	writers := make(map[string]kernelPluginPacketMetadataContract)
	namespaces := make(map[string]struct{})
	for _, item := range desired {
		for _, hook := range item.hooks {
			for _, binding := range hook.PacketMetadata {
				namespaces[binding.Namespace] = struct{}{}
				localKey := item.plugin.ID + "\x00" + hook.ObjectID + "\x00" + fmt.Sprint(binding.Slot)
				current := localBinding{namespace: binding.Namespace, schemaVersion: binding.SchemaVersion, maxBytes: binding.MaxBytes}
				if previous, exists := localSlots[localKey]; exists && previous != current {
					addIssue(item.plugin.ID, fmt.Sprintf("object %s packet metadata slot %d has conflicting bindings", hook.ObjectID, binding.Slot))
				} else {
					localSlots[localKey] = current
				}
				owner, _, _ := strings.Cut(binding.Namespace, "/")
				if binding.Access != pluginPacketMetadataAccessReadWrite {
					continue
				}
				if owner != item.plugin.ID {
					addIssue(item.plugin.ID, fmt.Sprintf("packet metadata namespace %s is owned by plugin %s and cannot be opened read_write", binding.Namespace, owner))
					continue
				}
				contract := kernelPluginPacketMetadataContract{SchemaVersion: binding.SchemaVersion, MaxBytes: binding.MaxBytes, WriterPlugin: item.plugin.ID}
				if previous, exists := writers[binding.Namespace]; exists && previous != contract {
					addIssue(item.plugin.ID, fmt.Sprintf("packet metadata writer contract for %s conflicts with schema version %d and max bytes %d", binding.Namespace, previous.SchemaVersion, previous.MaxBytes))
					addIssue(previous.WriterPlugin, fmt.Sprintf("packet metadata writer contract for %s is inconsistent", binding.Namespace))
				} else {
					writers[binding.Namespace] = contract
				}
			}
		}
	}

	for _, item := range desired {
		for _, hook := range item.hooks {
			for _, binding := range hook.PacketMetadata {
				writer, exists := writers[binding.Namespace]
				if !exists {
					addIssue(item.plugin.ID, fmt.Sprintf("packet metadata namespace %s has no active read_write owner", binding.Namespace))
					continue
				}
				if binding.SchemaVersion != writer.SchemaVersion || binding.MaxBytes != writer.MaxBytes {
					addIssue(item.plugin.ID, fmt.Sprintf("packet metadata namespace %s requires schema version %d and max bytes %d, owner provides version %d and %d bytes", binding.Namespace, binding.SchemaVersion, binding.MaxBytes, writer.SchemaVersion, writer.MaxBytes))
				}
			}
		}
	}
	if len(namespaces) > pluginPacketMetadataNamespaceLimit {
		message := fmt.Sprintf("packet metadata namespace count %d exceeds limit %d", len(namespaces), pluginPacketMetadataNamespaceLimit)
		for _, item := range desired {
			for _, hook := range item.hooks {
				if len(hook.PacketMetadata) > 0 {
					addIssue(item.plugin.ID, message)
					break
				}
			}
		}
	}
	if len(invalid) > 0 {
		return nil, invalid
	}

	names := make([]string, 0, len(namespaces))
	for namespace := range namespaces {
		names = append(names, namespace)
	}
	sort.Strings(names)
	slots := make(map[string]uint32, len(names))
	for index, namespace := range names {
		slots[namespace] = uint32(index)
	}
	return slots, nil
}

func kernelPluginObjectMetadataBindings(desired []kernelPluginPipelineDesiredPlugin) map[string][]kernelPluginPacketMetadataBinding {
	type objectBindings struct {
		values map[int]kernelPluginPacketMetadataBinding
	}
	objects := make(map[string]*objectBindings)
	for _, item := range desired {
		for _, hook := range item.hooks {
			if len(hook.PacketMetadata) == 0 {
				continue
			}
			key := item.plugin.ID + "\x00" + hook.ObjectID + "\x00" + hook.ObjectPath
			object := objects[key]
			if object == nil {
				object = &objectBindings{values: make(map[int]kernelPluginPacketMetadataBinding)}
				objects[key] = object
			}
			for _, binding := range hook.PacketMetadata {
				previous, exists := object.values[binding.Slot]
				if exists && previous.Access == pluginPacketMetadataAccessReadWrite {
					binding.Access = pluginPacketMetadataAccessReadWrite
				}
				object.values[binding.Slot] = binding
			}
		}
	}
	out := make(map[string][]kernelPluginPacketMetadataBinding, len(objects))
	for key, object := range objects {
		values := make([]kernelPluginPacketMetadataBinding, 0, len(object.values))
		for _, binding := range object.values {
			values = append(values, binding)
		}
		sort.Slice(values, func(i, j int) bool { return values[i].Slot < values[j].Slot })
		out[key] = values
	}
	return out
}

func kernelPluginObjectMetadataKey(pluginID, objectID, objectPath string) string {
	return pluginID + "\x00" + objectID + "\x00" + objectPath
}

func validateKernelPluginPacketMetadataObjectSpec(spec *ebpf.CollectionSpec, objectPath string) error {
	if spec == nil {
		return fmt.Errorf("plugin object %s packet metadata spec is unavailable", objectPath)
	}
	bindingSpec := spec.Maps[kernelTCPacketMetadataBindingsMapName]
	if bindingSpec == nil {
		return fmt.Errorf("plugin object %s must declare host-managed map %q for packet metadata", objectPath, kernelTCPacketMetadataBindingsMapName)
	}
	if bindingSpec.Type != ebpf.Array || bindingSpec.KeySize != 4 || bindingSpec.ValueSize != 12 || bindingSpec.MaxEntries < pluginPacketMetadataBindingLimit {
		return fmt.Errorf("plugin object %s declares incompatible map %q: type=%s key_size=%d value_size=%d max_entries=%d", objectPath, kernelTCPacketMetadataBindingsMapName, bindingSpec.Type, bindingSpec.KeySize, bindingSpec.ValueSize, bindingSpec.MaxEntries)
	}
	for _, name := range []string{kernelTCPacketMetadataGenerationMapNameV4, kernelTCPacketMetadataGenerationMapNameV6} {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("plugin object %s must declare shared map %q for packet metadata", objectPath, name)
		}
		if mapSpec.Type != ebpf.PerCPUArray || mapSpec.KeySize != 4 || mapSpec.ValueSize != 8 || mapSpec.MaxEntries < 1 {
			return fmt.Errorf("plugin object %s declares incompatible map %q: type=%s key_size=%d value_size=%d max_entries=%d", objectPath, name, mapSpec.Type, mapSpec.KeySize, mapSpec.ValueSize, mapSpec.MaxEntries)
		}
	}
	for _, name := range []string{kernelTCPacketMetadataMapNameV4, kernelTCPacketMetadataMapNameV6} {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("plugin object %s must declare shared map %q for packet metadata", objectPath, name)
		}
		if mapSpec.Type != ebpf.PerCPUArray || mapSpec.KeySize != 4 || mapSpec.ValueSize != 80 || mapSpec.MaxEntries < pluginPacketMetadataNamespaceLimit {
			return fmt.Errorf("plugin object %s declares incompatible map %q: type=%s key_size=%d value_size=%d max_entries=%d", objectPath, name, mapSpec.Type, mapSpec.KeySize, mapSpec.ValueSize, mapSpec.MaxEntries)
		}
	}
	return nil
}

func populateKernelPluginPacketMetadataBindings(bindingMap *ebpf.Map, bindings []kernelPluginPacketMetadataBinding) error {
	if bindingMap == nil {
		return fmt.Errorf("packet metadata binding map is unavailable")
	}
	for _, binding := range bindings {
		if binding.Slot < 0 || binding.Slot >= pluginPacketMetadataBindingLimit || binding.NamespaceSlot >= pluginPacketMetadataNamespaceLimit {
			return fmt.Errorf("packet metadata binding %s has invalid slots local=%d namespace=%d", binding.Namespace, binding.Slot, binding.NamespaceSlot)
		}
		value := kernelTCPluginMetadataBindingV1{
			NamespaceSlot: binding.NamespaceSlot,
			SchemaVersion: uint32(binding.SchemaVersion),
			MaxBytes:      uint16(binding.MaxBytes),
			Access:        kernelPluginPacketMetadataAccess(binding.Access),
		}
		if err := bindingMap.Put(uint32(binding.Slot), value); err != nil {
			return fmt.Errorf("put local slot %d namespace %s: %w", binding.Slot, binding.Namespace, err)
		}
	}
	return nil
}
