//go:build linux

package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

const pluginControlMapClearMaxEntries = 16384

func (rt *linuxKernelRuleRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return putPluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key, value)
}

func (rt *linuxKernelRuleRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key)
}

func (rt *linuxKernelRuleRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return deletePluginMapValueInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName, key)
}

func (rt *linuxKernelRuleRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clearPluginMapInRefs(rt.pluginPipelineLoaded, pluginID, objectID, mapName)
}

func (rt *linuxPluginDataplaneRuntime) PutPluginMapValue(pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return putPluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key, value)
}

func (rt *linuxPluginDataplaneRuntime) GetPluginMapValue(pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return getPluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key)
}

func (rt *linuxPluginDataplaneRuntime) DeletePluginMapValue(pluginID string, objectID string, mapName string, key []byte) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return deletePluginMapValueInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName, key)
}

func (rt *linuxPluginDataplaneRuntime) ClearPluginMap(pluginID string, objectID string, mapName string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clearPluginMapInRefs(rt.loadedPluginObjectRefsLocked(pluginID), pluginID, objectID, mapName)
}

func (rt *linuxPluginDataplaneRuntime) loadedPluginObjectRefsLocked(pluginID string) []loadedPluginObjectRef {
	if rt == nil || rt.loaded == nil {
		return nil
	}
	loaded := rt.loaded[pluginID]
	if loaded == nil {
		return nil
	}
	return loaded.objects
}

func putPluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte, value []byte) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	if err := validatePluginMapKeyValue(m, key, value); err != nil {
		return err
	}
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("put map %s: %w", mapName, err)
	}
	return nil
}

func getPluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte) ([]byte, error) {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return nil, err
	}
	if int(m.KeySize()) != len(key) {
		return nil, fmt.Errorf("map %s key size = %d, want %d", mapName, len(key), m.KeySize())
	}
	value := make([]byte, int(m.ValueSize()))
	if err := m.Lookup(key, value); err != nil {
		return nil, fmt.Errorf("get map %s: %w", mapName, err)
	}
	return value, nil
}

func deletePluginMapValueInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string, key []byte) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	if int(m.KeySize()) != len(key) {
		return fmt.Errorf("map %s key size = %d, want %d", mapName, len(key), m.KeySize())
	}
	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete map %s: %w", mapName, err)
	}
	return nil
}

func clearPluginMapInRefs(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string) error {
	m, err := findPluginLoadedMap(refs, pluginID, objectID, mapName)
	if err != nil {
		return err
	}
	keySize := int(m.KeySize())
	valueSize := int(m.ValueSize())
	if keySize <= 0 || valueSize <= 0 {
		return fmt.Errorf("map %s has invalid key/value size %d/%d", mapName, keySize, valueSize)
	}
	maxEntries := m.MaxEntries()
	if maxEntries > pluginControlMapClearMaxEntries {
		return fmt.Errorf("map %s max entries = %d exceeds clear limit %d; delete keys explicitly", mapName, maxEntries, pluginControlMapClearMaxEntries)
	}
	key := make([]byte, keySize)
	value := make([]byte, valueSize)
	keys := make([][]byte, 0, maxEntries)
	iter := m.Iterate()
	for iter.Next(key, value) {
		keys = append(keys, append([]byte(nil), key...))
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate map %s: %w", mapName, err)
	}
	for _, key := range keys {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("clear map %s: %w", mapName, err)
		}
	}
	return nil
}

func findPluginLoadedMap(refs []loadedPluginObjectRef, pluginID string, objectID string, mapName string) (*ebpf.Map, error) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	objectID = strings.TrimSpace(strings.ToLower(objectID))
	mapName = strings.TrimSpace(mapName)
	if pluginID == "" || mapName == "" {
		return nil, errPluginRuntimeTargetNotLoaded
	}
	for _, ref := range refs {
		if ref.PluginID != pluginID || ref.coll == nil {
			continue
		}
		if objectID != "" && ref.ObjectID != objectID {
			continue
		}
		if m := ref.coll.Maps[mapName]; m != nil {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%w: plugin %s object %s map %s", errPluginRuntimeTargetNotLoaded, pluginID, objectID, mapName)
}

func validatePluginMapKeyValue(m *ebpf.Map, key []byte, value []byte) error {
	if m == nil {
		return fmt.Errorf("map is nil")
	}
	if int(m.KeySize()) != len(key) {
		return fmt.Errorf("map key size = %d, want %d", len(key), m.KeySize())
	}
	if int(m.ValueSize()) != len(value) {
		return fmt.Errorf("map value size = %d, want %d", len(value), m.ValueSize())
	}
	return nil
}
