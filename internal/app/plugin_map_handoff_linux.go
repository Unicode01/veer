//go:build linux

package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

// Plugin state maps across a Veer hot restart.
//
// A state map an object declares with policy "preserve" (or "migrate") keeps
// its contents when the object is reloaded within one process: the loaders
// hand the previous collection's maps to the new one. A hot restart starts a
// new process, so without help every plugin map would start empty there,
// while the dispatcher chains left attached by the predecessor keep running
// the old programs until the successor's replace them.
//
// The predecessor pins those maps under the "plugin-maps" hot-restart
// directory and records each object's state map contracts. The successor's
// loaders treat the pinned maps as the previous object when they have none of
// their own, so the usual contract and map spec checks decide what is kept.
// When they reject it the object loads with empty maps, as before. Once the
// startup reconcile has loaded every plugin, the pins are released.

const (
	pluginMapHandoffEngine        = "plugin-maps"
	pluginMapHandoffFormatVersion = 1
)

var pluginMapHandoffNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,96}$`)

type pluginMapHandoffMap struct {
	Name       string                        `json:"name"`
	Pin        string                        `json:"pin"`
	Descriptor kernelHotRestartMapDescriptor `json:"descriptor"`
}

type pluginMapHandoffObject struct {
	PluginID     string                 `json:"plugin_id"`
	ObjectID     string                 `json:"object_id"`
	ObjectSHA256 string                 `json:"object_sha256,omitempty"`
	StateMaps    []PluginObjectStateMap `json:"state_maps"`
	Maps         []pluginMapHandoffMap  `json:"maps"`
}

type pluginMapHandoffMetadata struct {
	FormatVersion   int                      `json:"format_version"`
	OwnerPID        int                      `json:"owner_pid"`
	OwnerStartTicks uint64                   `json:"owner_start_ticks,omitempty"`
	Objects         []pluginMapHandoffObject `json:"objects"`
}

// pluginObjectRefSource is a runtime that loads plugin objects.
type pluginObjectRefSource interface {
	pluginObjectRefs() []loadedPluginObjectRef
}

func pluginMapHandoffKey(pluginID, objectID string) string {
	return pluginID + "\x00" + objectID
}

func pluginMapHandoffPinName(pluginID, objectID, mapName string) (string, error) {
	name := pluginID + "--" + objectID + "--" + mapName
	if !pluginMapHandoffNamePattern.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("plugin %s object %s map %s has no valid pin name", pluginID, objectID, mapName)
	}
	return name, nil
}

func pluginMapKeptAcrossRestart(policy string) bool {
	return policy == pluginObjectMapPreserve || policy == pluginObjectMapMigrate
}

// handOffPluginStateMapsForHotRestart pins the preserved state maps of every
// plugin object the sources hold, when this process is ending in a hot
// restart. It must run before the sources close.
func handOffPluginStateMapsForHotRestart(sources ...any) error {
	if !kernelHotRestartRequested() {
		return nil
	}
	var refs []loadedPluginObjectRef
	for _, source := range sources {
		if s, ok := source.(pluginObjectRefSource); ok && s != nil {
			refs = append(refs, s.pluginObjectRefs()...)
		}
	}
	return handOffPluginStateMaps(refs)
}

func handOffPluginStateMaps(refs []loadedPluginObjectRef) error {
	clearKernelHotRestartState(pluginMapHandoffEngine)
	dir := kernelHotRestartEngineDir(pluginMapHandoffEngine)
	meta := pluginMapHandoffMetadata{FormatVersion: pluginMapHandoffFormatVersion}
	seen := make(map[string]struct{}, len(refs))
	var failures []string
	for _, ref := range refs {
		if ref.coll == nil {
			continue
		}
		key := pluginMapHandoffKey(ref.PluginID, ref.ObjectID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		object := pluginMapHandoffObject{
			PluginID:     ref.PluginID,
			ObjectID:     ref.ObjectID,
			ObjectSHA256: ref.ObjectSHA256,
			StateMaps:    append([]PluginObjectStateMap(nil), ref.StateMaps...),
		}
		for _, contract := range ref.StateMaps {
			if !pluginMapKeptAcrossRestart(contract.Policy) {
				continue
			}
			m := ref.coll.Maps[contract.Name]
			if m == nil {
				continue
			}
			pin, err := pluginMapHandoffPinName(ref.PluginID, ref.ObjectID, contract.Name)
			if err == nil {
				err = os.MkdirAll(dir, 0o755)
			}
			var descriptor kernelHotRestartMapDescriptor
			if err == nil {
				descriptor, err = kernelHotRestartMapDescriptorFromMap(m)
			}
			if err == nil {
				path := filepath.Join(dir, pin)
				_ = os.Remove(path)
				err = m.Pin(path)
			}
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s/%s %s: %v", ref.PluginID, ref.ObjectID, contract.Name, err))
				continue
			}
			object.Maps = append(object.Maps, pluginMapHandoffMap{Name: contract.Name, Pin: pin, Descriptor: descriptor})
		}
		if len(object.Maps) > 0 {
			meta.Objects = append(meta.Objects, object)
		}
	}
	if len(meta.Objects) == 0 {
		clearKernelHotRestartState(pluginMapHandoffEngine)
		if len(failures) > 0 {
			return fmt.Errorf("pin plugin state maps: %s", strings.Join(failures, "; "))
		}
		return nil
	}
	if err := writePluginMapHandoffMetadata(meta); err != nil {
		clearKernelHotRestartState(pluginMapHandoffEngine)
		return err
	}
	names := make([]string, 0, len(meta.Objects))
	for _, object := range meta.Objects {
		names = append(names, fmt.Sprintf("%s/%s(%d)", object.PluginID, object.ObjectID, len(object.Maps)))
	}
	log.Printf("plugin hot restart: preserved state maps of %s for successor", strings.Join(names, ", "))
	if len(failures) > 0 {
		return fmt.Errorf("pin plugin state maps: %s", strings.Join(failures, "; "))
	}
	return nil
}

func writePluginMapHandoffMetadata(meta pluginMapHandoffMetadata) error {
	dir := kernelHotRestartMetadataDir(pluginMapHandoffEngine)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create plugin map handoff metadata dir %q: %w", dir, err)
	}
	owner := populateKernelMetadataOwner(kernelHotRestartMetadata{})
	meta.OwnerPID, meta.OwnerStartTicks = owner.OwnerPID, owner.OwnerStartTicks
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal plugin map handoff metadata: %w", err)
	}
	if err := os.WriteFile(kernelHotRestartMetadataPath(pluginMapHandoffEngine), data, 0o644); err != nil {
		return fmt.Errorf("write plugin map handoff metadata: %w", err)
	}
	return nil
}

func readPluginMapHandoffMetadata() (pluginMapHandoffMetadata, error) {
	data, err := os.ReadFile(kernelHotRestartMetadataPath(pluginMapHandoffEngine))
	if err != nil {
		return pluginMapHandoffMetadata{}, err
	}
	var meta pluginMapHandoffMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return pluginMapHandoffMetadata{}, err
	}
	return meta, nil
}

type pluginMapHandoffEntry struct {
	object  pluginMapHandoffObject
	maps    map[string]*ebpf.Map
	adopted bool
}

type pluginMapHandoffRegistry struct {
	mu       sync.Mutex
	loaded   bool
	released bool
	entries  map[string]*pluginMapHandoffEntry
}

var pluginMapHandoff pluginMapHandoffRegistry

func (r *pluginMapHandoffRegistry) loadLocked() {
	if r.loaded {
		return
	}
	r.loaded = true
	r.entries = make(map[string]*pluginMapHandoffEntry)
	meta, err := readPluginMapHandoffMetadata()
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("plugin hot restart: read preserved state map metadata: %v; plugin maps start empty", err)
		}
		return
	}
	if meta.FormatVersion != pluginMapHandoffFormatVersion {
		log.Printf("plugin hot restart: preserved state map metadata format %d is not %d; plugin maps start empty", meta.FormatVersion, pluginMapHandoffFormatVersion)
		return
	}
	dir := kernelHotRestartEngineDir(pluginMapHandoffEngine)
	for _, object := range meta.Objects {
		entry := &pluginMapHandoffEntry{object: object, maps: make(map[string]*ebpf.Map, len(object.Maps))}
		for _, item := range object.Maps {
			if !pluginMapHandoffNamePattern.MatchString(item.Pin) {
				continue
			}
			m, ok, err := loadPinnedKernelMap(filepath.Join(dir, item.Pin))
			if err != nil || !ok {
				log.Printf("plugin hot restart: %s/%s map %s is not pinned (%v); it starts empty", object.PluginID, object.ObjectID, item.Name, err)
				continue
			}
			descriptor, err := kernelHotRestartMapDescriptorFromMap(m)
			if err != nil || descriptor != item.Descriptor {
				_ = m.Close()
				log.Printf("plugin hot restart: %s/%s map %s does not match its recorded layout; it starts empty", object.PluginID, object.ObjectID, item.Name)
				continue
			}
			entry.maps[item.Name] = m
		}
		if len(entry.maps) > 0 {
			r.entries[pluginMapHandoffKey(object.PluginID, object.ObjectID)] = entry
		}
	}
}

// pluginMapHandoffPrevious stands in for the previous object of a plugin
// object a predecessor handed its state maps to; nil when there is none.
// Only the contracts of maps that came across are kept, so a contract whose
// map did not reaches the loader as absent rather than as a broken promise.
func pluginMapHandoffPrevious(pluginID, objectID string) *loadedPluginObjectRef {
	r := &pluginMapHandoff
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.released {
		return nil
	}
	r.loadLocked()
	entry := r.entries[pluginMapHandoffKey(pluginID, objectID)]
	if entry == nil {
		return nil
	}
	contracts := make([]PluginObjectStateMap, 0, len(entry.object.StateMaps))
	for _, contract := range entry.object.StateMaps {
		if pluginMapKeptAcrossRestart(contract.Policy) && entry.maps[contract.Name] == nil {
			continue
		}
		contracts = append(contracts, contract)
	}
	maps := make(map[string]*ebpf.Map, len(entry.maps))
	for name, m := range entry.maps {
		maps[name] = m
	}
	return &loadedPluginObjectRef{
		PluginID:     pluginID,
		ObjectID:     objectID,
		ObjectSHA256: entry.object.ObjectSHA256,
		StateMaps:    contracts,
		coll:         &ebpf.Collection{Maps: maps},
	}
}

func pluginMapHandoffMarkAdopted(pluginID, objectID string) {
	r := &pluginMapHandoff
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry := r.entries[pluginMapHandoffKey(pluginID, objectID)]; entry != nil && !entry.adopted {
		entry.adopted = true
		names := make([]string, 0, len(entry.maps))
		for name := range entry.maps {
			names = append(names, name)
		}
		sort.Strings(names)
		log.Printf("plugin hot restart: %s/%s kept state maps %s from the previous process", pluginID, objectID, strings.Join(names, ","))
	}
}

// releasePluginMapHandoff drops the predecessor's pins once the startup
// reconcile has loaded every plugin. Objects that adopted the maps hold their
// own references; the rest of the state is gone with the pins.
func releasePluginMapHandoff() {
	r := &pluginMapHandoff
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	r.released = true
	var unclaimed []string
	for _, entry := range r.entries {
		if !entry.adopted {
			unclaimed = append(unclaimed, entry.object.PluginID+"/"+entry.object.ObjectID)
		}
		for _, m := range entry.maps {
			_ = m.Close()
		}
	}
	r.entries = nil
	if len(unclaimed) > 0 {
		sort.Strings(unclaimed)
		log.Printf("plugin hot restart: no plugin object took the preserved state maps of %s; they are released", strings.Join(unclaimed, ", "))
	}
	clearKernelHotRestartState(pluginMapHandoffEngine)
}

// loadPluginObjectWithHandoff loads a plugin object with the previous object
// of this process when there is one; otherwise with the state maps a
// predecessor handed off, and with empty maps when those do not fit.
func loadPluginObjectWithHandoff(pluginID, objectID string, previous *loadedPluginObjectRef, unchanged bool, load func(*loadedPluginObjectRef, bool) (*loadedPluginObject, error)) (*loadedPluginObject, error) {
	if previous != nil {
		return load(previous, unchanged)
	}
	handoff := pluginMapHandoffPrevious(pluginID, objectID)
	if handoff == nil {
		return load(nil, false)
	}
	object, err := load(handoff, false)
	if err == nil {
		pluginMapHandoffMarkAdopted(pluginID, objectID)
		return object, nil
	}
	log.Printf("plugin hot restart: %s/%s cannot keep the previous process's state maps (%v); they start empty", pluginID, objectID, err)
	return load(nil, false)
}

func copyLoadedPluginObjectRefs(refs []loadedPluginObjectRef) []loadedPluginObjectRef {
	return append([]loadedPluginObjectRef(nil), refs...)
}

func (rt *linuxKernelRuleRuntime) pluginObjectRefs() []loadedPluginObjectRef {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return copyLoadedPluginObjectRefs(rt.pluginPipelineLoaded)
}

func (rt *kernelXDPPluginPipelineRuntime) pluginObjectRefs() []loadedPluginObjectRef {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return copyLoadedPluginObjectRefs(rt.loaded)
}

func (rt *kernelNetfilterPluginPipelineRuntime) pluginObjectRefs() []loadedPluginObjectRef {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return copyLoadedPluginObjectRefs(rt.loaded)
}

func (rt *linuxPluginDataplaneRuntime) pluginObjectRefs() []loadedPluginObjectRef {
	if rt == nil || rt.netfilter == nil {
		return nil
	}
	return rt.netfilter.pluginObjectRefs()
}

func (rt *orderedKernelRuleRuntime) pluginObjectRefs() []loadedPluginObjectRef {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	entries := append([]orderedKernelRuntimeEntry(nil), rt.entries...)
	xdpPlugins := rt.xdpPlugins
	rt.mu.Unlock()
	var refs []loadedPluginObjectRef
	for _, entry := range entries {
		if source, ok := entry.rt.(pluginObjectRefSource); ok {
			refs = append(refs, source.pluginObjectRefs()...)
		}
	}
	if xdpPlugins != nil {
		refs = append(refs, xdpPlugins.pluginObjectRefs()...)
	}
	return refs
}
