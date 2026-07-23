//go:build linux

package app

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

const (
	kernelXDPPluginRuntimeEngine          = "xdp-plugin"
	kernelXDPPluginProgramChainMapName    = "xdp_prog_chain"
	kernelXDPPluginConfigMapName          = "xdp_plugin_config"
	kernelXDPPluginInterfacesMapName      = "xdp_plugin_interfaces"
	kernelXDPPluginScratchMapName         = "xdp_plugin_scratch"
	kernelXDPPluginMetricsMapName         = "xdp_plugin_metrics"
	kernelXDPPluginDispatcherProgramName  = "veer_xdp_plugin_dispatch"
	kernelXDPPluginContinueProgramName    = "veer_xdp_plugin_continue"
	kernelXDPPluginContinueSlot           = 7
	kernelXDPPluginBank0Base              = 8
	kernelXDPPluginBank1Base              = 16
	kernelXDPPluginMaxHooks               = pluginXDPPipelineHookLimit
	kernelXDPPluginProgramChainMaxEntries = pluginXDPPipelineProgramArrayEntries
)

//go:embed ebpf/plugin-xdp-dispatcher-bpf.o
var embeddedPluginXDPDispatcherObject []byte

type kernelXDPPluginConfig struct {
	Count      uint32
	ActiveBank uint32
	GlobalMask uint32
	Generation uint32
}

type kernelXDPPluginInterfaceKey struct {
	IfIndex uint32
	Bank    uint32
}

type kernelXDPPluginInterfaceValue struct {
	Mask uint32
}

type kernelXDPPluginMetricValue struct {
	Packets        uint64
	Bytes          uint64
	Continued      uint64
	TailCallMisses uint64
}

type kernelXDPPluginPieces struct {
	dispatcher   *ebpf.Program
	continuation *ebpf.Program
	progChain    *ebpf.Map
	config       *ebpf.Map
	interfaces   *ebpf.Map
	metrics      *ebpf.Map
}

type kernelXDPPluginHookPlan struct {
	PluginID         string                 `json:"plugin_id"`
	HookID           string                 `json:"hook_id"`
	ObjectID         string                 `json:"object_id"`
	ObjectPath       string                 `json:"object_path"`
	ObjectSHA256     string                 `json:"object_sha256,omitempty"`
	ObjectStateMaps  []PluginObjectStateMap `json:"object_state_maps,omitempty"`
	ProgramRef       string                 `json:"program_ref"`
	ProgramSection   string                 `json:"program_section"`
	Stage            string                 `json:"stage"`
	Mode             string                 `json:"mode"`
	Interfaces       []string               `json:"interfaces"`
	InterfaceIndexes []uint32               `json:"interface_indexes"`
	Priority         int                    `json:"priority"`
	Before           []string               `json:"before,omitempty"`
	After            []string               `json:"after,omitempty"`
	Order            int                    `json:"order"`
}

type kernelXDPPluginDesiredPlugin struct {
	plugin   LoadedPlugin
	hooks    []kernelXDPPluginHookPlan
	warnings []string
}

type loadedKernelXDPPluginProgram struct {
	plan kernelXDPPluginHookPlan
	prog *ebpf.Program
}

type kernelXDPPluginPipelineRuntime struct {
	mu            sync.Mutex
	cfg           *Config
	dispatcher    *ebpf.Collection
	attachments   []xdpAttachment
	programID     uint32
	loaded        []loadedPluginObjectRef
	desired       []kernelXDPPluginDesiredPlugin
	fingerprint   string
	activeBank    uint32
	snapshot      pluginRuntimeSnapshot
	orphanChecked bool
}

func newKernelXDPPluginPipelineRuntime(cfg *Config) *kernelXDPPluginPipelineRuntime {
	return &kernelXDPPluginPipelineRuntime{cfg: cfg}
}

func (rt *kernelXDPPluginPipelineRuntime) enabled() bool {
	return rt != nil && rt.cfg != nil && rt.cfg.PluginsEnabled() && rt.cfg.PluginsDataplaneEnabled()
}

func (rt *kernelXDPPluginPipelineRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	if rt == nil {
		return kernelPluginPipelineManifestOnlySnapshot(catalog)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.enabled() {
		if err := rt.cleanupLocked(); err != nil {
			log.Printf("xdp plugin pipeline cleanup while disabled: %v", err)
		}
		rt.snapshot = kernelPluginPipelineManifestOnlySnapshot(catalog)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	desired, states := buildKernelXDPPluginDesired(catalog, rt.cfg)
	if preserved, ok := rt.preserveCatalogFailureLocked(catalog, desired, states); ok {
		rt.snapshot = preserved
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}
	fingerprint := kernelXDPPluginFingerprint(desired, states)
	if fingerprint == rt.fingerprint && rt.dispatcher != nil && rt.attachmentsHealthyLocked(desired) {
		snapshot := clonePluginRuntimeSnapshot(rt.snapshot)
		populateKernelXDPPluginMetrics(snapshot, rt.dispatcher.Maps[kernelXDPPluginMetricsMapName])
		return snapshot
	}

	if len(desired) == 0 {
		if err := rt.cleanupLocked(); err != nil {
			for id, state := range states {
				state.Error = joinPluginRuntimeText(state.Error, err.Error())
				state.Reason = joinPluginRuntimeText(state.Reason, "xdp plugin pipeline cleanup failed")
				states[id] = state
			}
		}
		rt.fingerprint = fingerprint
		rt.snapshot = completeKernelPluginSnapshot(catalog, states)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	if !rt.orphanChecked {
		if err := cleanupOrphanXDPPluginRuntimeState(); err != nil {
			rt.snapshot = rt.failureSnapshot(catalog, desired, states, fmt.Errorf("recover xdp plugin runtime: %w", err))
			return clonePluginRuntimeSnapshot(rt.snapshot)
		}
		rt.orphanChecked = true
	}

	dispatcher := rt.dispatcher
	createdDispatcher := false
	if dispatcher == nil {
		var err error
		dispatcher, err = loadKernelXDPPluginDispatcher()
		if err != nil {
			rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
			return clonePluginRuntimeSnapshot(rt.snapshot)
		}
		createdDispatcher = true
	}
	pieces, err := kernelXDPPluginCollectionPieces(dispatcher)
	if err != nil {
		if createdDispatcher {
			dispatcher.Close()
		}
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	loaded, programs, loadStates, err := rt.loadProgramsLocked(desired, pieces)
	for id, state := range loadStates {
		states[id] = state
	}
	if err != nil {
		cleanupKernelPluginPipelineCollections(loaded)
		if createdDispatcher {
			dispatcher.Close()
		}
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	desiredIfIndexes := collectKernelXDPPluginInterfaces(programs)
	programID := kernelProgramID(pieces.dispatcher)
	newAttachments, addedAttachments, err := rt.reconcileAttachmentsLocked(desiredIfIndexes, pieces.dispatcher, programID)
	if err != nil {
		detachOwnedXDPPluginAttachments(addedAttachments, programID)
		cleanupKernelPluginPipelineCollections(loaded)
		if createdDispatcher {
			dispatcher.Close()
		}
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	bank, err := installKernelXDPPluginPrograms(pieces, programs)
	if err != nil {
		detachOwnedXDPPluginAttachments(addedAttachments, programID)
		cleanupKernelPluginPipelineCollections(loaded)
		if createdDispatcher {
			dispatcher.Close()
		}
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	attachmentsByPlugin := kernelXDPPluginAttachmentStates(programs, bank)
	for _, item := range desired {
		attachments := sortedPluginAttachmentStates(attachmentsByPlugin[item.plugin.ID])
		state := PluginRuntimeState{
			Mode:            pluginRuntimeModeDataplane,
			Attachable:      true,
			Attached:        len(attachments) > 0,
			AttachmentCount: len(attachments),
			Attachments:     attachments,
			Reason:          strings.Join(item.warnings, "; "),
		}
		states[item.plugin.ID] = state
	}

	oldLoaded := rt.loaded
	oldAttachments := append([]xdpAttachment(nil), rt.attachments...)
	oldBank := rt.activeBank
	rt.dispatcher = dispatcher
	rt.loaded = loaded
	rt.desired = cloneKernelXDPPluginDesired(desired)
	rt.attachments = newAttachments
	rt.programID = programID
	rt.activeBank = bank
	rt.fingerprint = fingerprint
	rt.snapshot = completeKernelPluginSnapshot(catalog, states)

	if len(oldLoaded) > 0 || oldBank != bank {
		time.Sleep(kernelPluginPipelineUpdateGrace)
	}
	if oldBank != bank {
		if err := clearKernelXDPPluginBank(pieces, oldBank); err != nil {
			log.Printf("xdp plugin pipeline cleanup inactive bank %d: %v", oldBank, err)
		}
	}
	cleanupKernelPluginPipelineCollections(oldLoaded)
	detachStaleOwnedXDPPluginAttachments(oldAttachments, newAttachments, programID)
	if err := writeXDPPluginRuntimeMetadata(newAttachments, programID); err != nil {
		log.Printf("xdp plugin pipeline metadata: %v", err)
	}

	snapshot := clonePluginRuntimeSnapshot(rt.snapshot)
	populateKernelXDPPluginMetrics(snapshot, pieces.metrics)
	return snapshot
}

func (rt *kernelXDPPluginPipelineRuntime) Snapshot() pluginRuntimeSnapshot {
	if rt == nil {
		return pluginRuntimeSnapshot{}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	snapshot := clonePluginRuntimeSnapshot(rt.snapshot)
	if rt.dispatcher != nil {
		populateKernelXDPPluginMetrics(snapshot, rt.dispatcher.Maps[kernelXDPPluginMetricsMapName])
	}
	return snapshot
}

func (rt *kernelXDPPluginPipelineRuntime) Close() error {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.cleanupLocked()
}

func (rt *kernelXDPPluginPipelineRuntime) Maintain() error {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.dispatcher == nil || len(rt.desired) == 0 {
		return nil
	}
	if !rt.attachmentsHealthyLocked(rt.desired) {
		return fmt.Errorf("xdp plugin dispatcher attachment disappeared; awaiting dataplane reconcile")
	}
	return nil
}

func (rt *kernelXDPPluginPipelineRuntime) failureSnapshot(catalog PluginCatalog, desired []kernelXDPPluginDesiredPlugin, states map[string]PluginRuntimeState, failure error) pluginRuntimeSnapshot {
	message := "xdp plugin pipeline failed"
	if failure != nil {
		message = failure.Error()
	}
	if rt.dispatcher != nil && len(rt.loaded) > 0 && len(rt.snapshot.Plugins) > 0 && kernelXDPPluginCanPreserveDesired(rt.desired, desired) {
		preserved := clonePluginRuntimeSnapshot(rt.snapshot)
		for _, item := range desired {
			state := preserved.Plugins[item.plugin.ID]
			state.Reason = joinPluginRuntimeText(state.Reason, "xdp plugin update failed; previous chain preserved")
			state.Error = joinPluginRuntimeText(state.Error, message)
			preserved.Plugins[item.plugin.ID] = state
		}
		return preserved
	}
	if rt.dispatcher != nil || len(rt.loaded) > 0 || len(rt.attachments) > 0 {
		if err := rt.cleanupLocked(); err != nil {
			message = joinPluginRuntimeText(message, "clear incompatible previous xdp plugin chain: "+err.Error())
		}
	}
	for _, item := range desired {
		state := pluginRuntimeErrorState(message)
		state.Reason = "xdp plugin pipeline failed"
		states[item.plugin.ID] = state
	}
	return completeKernelPluginSnapshot(catalog, states)
}

func (rt *kernelXDPPluginPipelineRuntime) preserveCatalogFailureLocked(catalog PluginCatalog, desired []kernelXDPPluginDesiredPlugin, states map[string]PluginRuntimeState) (pluginRuntimeSnapshot, bool) {
	if len(rt.loaded) == 0 || len(rt.desired) == 0 || len(rt.snapshot.Plugins) == 0 {
		return pluginRuntimeSnapshot{}, false
	}
	desiredIDs := make(map[string]struct{}, len(desired))
	for _, item := range desired {
		desiredIDs[item.plugin.ID] = struct{}{}
	}
	catalogByID := make(map[string]LoadedPlugin, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		catalogByID[plugin.ID] = plugin
	}
	failures := make(map[string]string)
	for _, old := range rt.desired {
		plugin, found := catalogByID[old.plugin.ID]
		if !found || plugin.Status == pluginStatusDisabled {
			return pluginRuntimeSnapshot{}, false
		}
		if _, ok := desiredIDs[old.plugin.ID]; ok {
			continue
		}
		if state, ok := states[old.plugin.ID]; ok && state.Error != "" {
			failures[old.plugin.ID] = state.Error
			continue
		}
		if plugin.Status == pluginStatusError {
			message := strings.TrimSpace(plugin.Error)
			if message == "" {
				message = "plugin catalog reload failed"
			}
			failures[old.plugin.ID] = message
			continue
		}
		return pluginRuntimeSnapshot{}, false
	}
	if len(failures) == 0 {
		return pluginRuntimeSnapshot{}, false
	}
	preserved := clonePluginRuntimeSnapshot(rt.snapshot)
	for pluginID, message := range failures {
		state := preserved.Plugins[pluginID]
		state.Reason = joinPluginRuntimeText(state.Reason, "xdp plugin catalog update failed; previous chain preserved")
		state.Error = joinPluginRuntimeText(state.Error, message)
		preserved.Plugins[pluginID] = state
	}
	return preserved, true
}

func kernelXDPPluginCanPreserveDesired(current, next []kernelXDPPluginDesiredPlugin) bool {
	currentHooks := flattenKernelXDPPluginHooks(current)
	nextHooks := flattenKernelXDPPluginHooks(next)
	if len(currentHooks) == 0 || len(currentHooks) != len(nextHooks) {
		return false
	}
	for i := range currentHooks {
		left, right := currentHooks[i], nextHooks[i]
		if left.PluginID != right.PluginID || left.HookID != right.HookID || left.ObjectID != right.ObjectID ||
			left.Stage != right.Stage || left.Priority != right.Priority || left.Order != right.Order || left.Mode != right.Mode ||
			!equalKernelXDPPluginStringSlices(left.Before, right.Before) || !equalKernelXDPPluginStringSlices(left.After, right.After) ||
			!equalKernelXDPPluginStringSlices(left.Interfaces, right.Interfaces) || !equalUint32Slices(left.InterfaceIndexes, right.InterfaceIndexes) {
			return false
		}
	}
	return true
}

func flattenKernelXDPPluginHooks(values []kernelXDPPluginDesiredPlugin) []kernelXDPPluginHookPlan {
	out := make([]kernelXDPPluginHookPlan, 0)
	for _, item := range values {
		out = append(out, item.hooks...)
	}
	sort.Slice(out, func(i, j int) bool { return kernelXDPPluginHookLess(out[i], out[j]) })
	return out
}

func equalKernelXDPPluginStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalUint32Slices(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func completeKernelPluginSnapshot(catalog PluginCatalog, states map[string]PluginRuntimeState) pluginRuntimeSnapshot {
	result := kernelPluginPipelineManifestOnlySnapshot(catalog)
	if result.Plugins == nil {
		result.Plugins = make(map[string]PluginRuntimeState)
	}
	for id, state := range states {
		result.Plugins[id] = state
	}
	return result
}

func buildKernelXDPPluginDesired(catalog PluginCatalog, cfg *Config) ([]kernelXDPPluginDesiredPlugin, map[string]PluginRuntimeState) {
	states := make(map[string]PluginRuntimeState)
	desired := make([]kernelXDPPluginDesiredPlugin, 0, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || !pluginHasHookEngine(plugin, kernelEngineXDP) {
			continue
		}
		if ok, reason := pluginDataplaneStabilityAllowed(plugin, cfg); !ok {
			state := externalPluginRuntimeState()
			state.Reason = reason
			states[plugin.ID] = state
			continue
		}
		item, state := buildKernelXDPPluginDesiredPlugin(plugin)
		if len(item.hooks) == 0 || state.Error != "" {
			states[plugin.ID] = state
			continue
		}
		desired = append(desired, item)
	}
	desired, states = applyKernelXDPPluginOrdering(desired, states)
	totalHooks := 0
	for _, item := range desired {
		totalHooks += len(item.hooks)
	}
	if totalHooks > kernelXDPPluginMaxHooks {
		state := pluginRuntimeErrorState(fmt.Sprintf("too many xdp plugin hooks: %d > %d", totalHooks, kernelXDPPluginMaxHooks))
		for _, item := range desired {
			states[item.plugin.ID] = state
		}
		return nil, states
	}
	sort.Slice(desired, func(i, j int) bool {
		return kernelXDPPluginHookLess(desired[i].hooks[0], desired[j].hooks[0])
	})
	return desired, states
}

func buildKernelXDPPluginDesiredPlugin(plugin LoadedPlugin) (kernelXDPPluginDesiredPlugin, PluginRuntimeState) {
	item := kernelXDPPluginDesiredPlugin{plugin: plugin}
	objects := make(map[string]PluginObject, len(plugin.Objects)*2)
	for _, object := range plugin.Objects {
		if object.Status != pluginObjectStatusVerified {
			continue
		}
		objects[object.ID] = object
		objects[object.Path] = object
	}
	for _, hook := range plugin.Hooks {
		if hook.Engine != kernelEngineXDP {
			continue
		}
		stage, err := normalizeKernelXDPPluginStage(hook.Stage, hook.Priority)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: %v", hook.ID, err))
		}
		attach := strings.TrimSpace(strings.ToLower(hook.Attach))
		if attach == "" {
			attach = "ingress"
		}
		if attach != "ingress" {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: xdp plugins support ingress attach only", hook.ID))
		}
		if len(hook.Context) > 0 {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: tc context is unavailable before the xdp dispatcher", hook.ID))
		}
		if len(hook.Interfaces) == 0 {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: interfaces is required for xdp plugins", hook.ID))
		}
		objectRef, programRef, ok := parsePluginProgramRef(hook.Program)
		if !ok {
			return item, pluginRuntimeErrorState("program must use object:program for xdp pipeline hooks")
		}
		object, ok := objects[objectRef]
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing object %q", hook.ID, objectRef))
		}
		program, ok := pluginObjectProgramByRef(object, programRef)
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing program %q in object %q", hook.ID, programRef, objectRef))
		}
		if program.Type != kernelEngineXDP {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s program %q type = %q, want xdp", hook.ID, programRef, program.Type))
		}
		realPath, err := resolvePluginObjectRealPath(&plugin, object)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s object path: %v", hook.ID, err))
		}
		ifIndexes := make([]uint32, 0, len(hook.Interfaces))
		interfaces := make([]string, 0, len(hook.Interfaces))
		seen := make(map[uint32]struct{}, len(hook.Interfaces))
		for _, name := range hook.Interfaces {
			link, err := pluginControlNetLinkByName(name)
			if err != nil {
				return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s resolve interface %q: %v", hook.ID, name, err))
			}
			if link == nil || link.Attrs() == nil || link.Attrs().Index <= 0 {
				return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s resolve interface %q: invalid link identity", hook.ID, name))
			}
			ifindex := uint32(link.Attrs().Index)
			if _, exists := seen[ifindex]; exists {
				continue
			}
			seen[ifindex] = struct{}{}
			interfaces = append(interfaces, link.Attrs().Name)
			ifIndexes = append(ifIndexes, ifindex)
		}
		item.hooks = append(item.hooks, kernelXDPPluginHookPlan{
			PluginID:         plugin.ID,
			HookID:           hook.ID,
			ObjectID:         object.ID,
			ObjectPath:       realPath,
			ObjectSHA256:     object.ResolvedSHA256,
			ObjectStateMaps:  append([]PluginObjectStateMap(nil), object.StateMaps...),
			ProgramRef:       programRef,
			ProgramSection:   program.Section,
			Stage:            stage,
			Mode:             hook.Mode,
			Interfaces:       interfaces,
			InterfaceIndexes: ifIndexes,
			Priority:         hook.Priority,
			Before:           append([]string(nil), hook.Before...),
			After:            append([]string(nil), hook.After...),
		})
	}
	if len(item.hooks) == 0 {
		state := externalPluginRuntimeState()
		state.Reason = "no supported xdp pipeline hook is declared"
		return item, state
	}
	sort.Slice(item.hooks, func(i, j int) bool {
		return kernelXDPPluginHookLess(item.hooks[i], item.hooks[j])
	})
	return item, PluginRuntimeState{}
}

func normalizeKernelXDPPluginStage(stage string, priority int) (string, error) {
	stage = strings.TrimSpace(strings.ToLower(stage))
	switch stage {
	case kernelPluginPipelineStagePreForward:
		return kernelPluginPipelineStagePreForward, nil
	case kernelPluginPipelineStageForward:
		if priority >= pluginPipelineCorePriority {
			return "", fmt.Errorf("stage=forward priority=%d is not before Veer Core priority %d", priority, pluginPipelineCorePriority)
		}
		return kernelPluginPipelineStagePreForward, nil
	default:
		return "", fmt.Errorf("xdp plugins support stage=pre_forward or pre-core stage=forward only")
	}
}

func kernelXDPPluginHookLess(left, right kernelXDPPluginHookPlan) bool {
	if left.Order != right.Order {
		return left.Order < right.Order
	}
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	if left.PluginID != right.PluginID {
		return left.PluginID < right.PluginID
	}
	return left.HookID < right.HookID
}

func applyKernelXDPPluginOrdering(desired []kernelXDPPluginDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelXDPPluginDesiredPlugin, map[string]PluginRuntimeState) {
	for len(desired) > 0 {
		nodes := make([]pluginHookOrderNode, 0)
		for _, item := range desired {
			for _, hook := range item.hooks {
				nodes = append(nodes, pluginHookOrderNode{
					PluginID: hook.PluginID, HookID: hook.HookID, Stage: hook.Stage, Priority: hook.Priority,
					Before: hook.Before, After: hook.After,
				})
			}
		}
		order, invalid := resolvePluginHookOrder(nodes)
		if len(invalid) == 0 {
			for i := range desired {
				for j := range desired[i].hooks {
					key := pluginHookOrderKey(desired[i].hooks[j].PluginID, desired[i].hooks[j].HookID)
					desired[i].hooks[j].Order = order[key]
				}
				sort.Slice(desired[i].hooks, func(left, right int) bool {
					return kernelXDPPluginHookLess(desired[i].hooks[left], desired[i].hooks[right])
				})
			}
			return desired, states
		}
		filtered := make([]kernelXDPPluginDesiredPlugin, 0, len(desired))
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

func pluginHasHookEngine(plugin LoadedPlugin, engine string) bool {
	for _, hook := range plugin.Hooks {
		if hook.Engine == engine && hook.Attach != "none" && hook.Mode != "control" {
			return true
		}
	}
	return false
}

func kernelXDPPluginCatalogHasRuntimeHooks(catalog PluginCatalog, cfg *Config) bool {
	if cfg == nil || !cfg.PluginsEnabled() || !cfg.PluginsDataplaneEnabled() {
		return false
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || !pluginHasHookEngine(plugin, kernelEngineXDP) {
			continue
		}
		if ok, _ := pluginDataplaneStabilityAllowed(plugin, cfg); !ok {
			continue
		}
		for _, hook := range plugin.Hooks {
			if hook.Engine != kernelEngineXDP || len(hook.Interfaces) == 0 {
				continue
			}
			if _, err := normalizeKernelXDPPluginStage(hook.Stage, hook.Priority); err == nil {
				attach := strings.TrimSpace(strings.ToLower(hook.Attach))
				if attach == "" || attach == "ingress" {
					return true
				}
			}
		}
	}
	return false
}

func kernelXDPPluginFingerprint(desired []kernelXDPPluginDesiredPlugin, states map[string]PluginRuntimeState) string {
	type pluginEntry struct {
		ID       string                    `json:"id"`
		Hooks    []kernelXDPPluginHookPlan `json:"hooks"`
		Warnings []string                  `json:"warnings,omitempty"`
	}
	type stateEntry struct {
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	payload := struct {
		Plugins []pluginEntry `json:"plugins"`
		States  []stateEntry  `json:"states,omitempty"`
	}{Plugins: make([]pluginEntry, 0, len(desired))}
	for _, item := range desired {
		payload.Plugins = append(payload.Plugins, pluginEntry{ID: item.plugin.ID, Hooks: item.hooks, Warnings: item.warnings})
	}
	for id, state := range states {
		payload.States = append(payload.States, stateEntry{ID: id, Reason: state.Reason, Error: state.Error})
	}
	sort.Slice(payload.States, func(i, j int) bool { return payload.States[i].ID < payload.States[j].ID })
	data, _ := json.Marshal(payload)
	return hashPluginRuntimeSource(data)
}

func cloneKernelXDPPluginDesired(values []kernelXDPPluginDesiredPlugin) []kernelXDPPluginDesiredPlugin {
	if len(values) == 0 {
		return nil
	}
	out := make([]kernelXDPPluginDesiredPlugin, len(values))
	for i, item := range values {
		out[i] = item
		out[i].warnings = append([]string(nil), item.warnings...)
		out[i].hooks = make([]kernelXDPPluginHookPlan, len(item.hooks))
		for j, hook := range item.hooks {
			out[i].hooks[j] = hook
			out[i].hooks[j].Before = append([]string(nil), hook.Before...)
			out[i].hooks[j].After = append([]string(nil), hook.After...)
			out[i].hooks[j].Interfaces = append([]string(nil), hook.Interfaces...)
			out[i].hooks[j].InterfaceIndexes = append([]uint32(nil), hook.InterfaceIndexes...)
			out[i].hooks[j].ObjectStateMaps = append([]PluginObjectStateMap(nil), hook.ObjectStateMaps...)
		}
	}
	return out
}

func hashPluginRuntimeSource(data []byte) string {
	return fmt.Sprintf("%x", pluginRuntimeSHA256(data))
}

func pluginRuntimeSHA256(data []byte) [32]byte {
	return sha256Bytes(data)
}

func sha256Bytes(data []byte) [32]byte {
	// Kept local to avoid exposing hash state to plugin code.
	return sha256.Sum256(data)
}

func loadKernelXDPPluginDispatcher() (*ebpf.Collection, error) {
	if len(embeddedPluginXDPDispatcherObject) == 0 {
		return nil, fmt.Errorf("embedded xdp plugin dispatcher object is empty")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("xdp plugin pipeline: remove memlock limit: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedPluginXDPDispatcherObject))
	if err != nil {
		return nil, fmt.Errorf("load embedded xdp plugin dispatcher: %w", err)
	}
	if err := validateKernelXDPPluginDispatcherSpec(spec); err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	if err != nil {
		logKernelVerifierDetails(err)
		return nil, fmt.Errorf("load xdp plugin dispatcher into kernel: %w", err)
	}
	pieces, err := kernelXDPPluginCollectionPieces(coll)
	if err != nil {
		coll.Close()
		return nil, err
	}
	if err := pieces.progChain.Put(uint32(kernelXDPPluginContinueSlot), uint32(pieces.continuation.FD())); err != nil {
		coll.Close()
		return nil, fmt.Errorf("install xdp plugin continuation: %w", err)
	}
	return coll, nil
}

func validateKernelXDPPluginDispatcherSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return fmt.Errorf("xdp plugin dispatcher collection spec is nil")
	}
	for _, name := range []string{kernelXDPPluginDispatcherProgramName, kernelXDPPluginContinueProgramName} {
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.XDP {
			return fmt.Errorf("xdp plugin dispatcher program %q is missing or has incompatible type", name)
		}
	}
	checks := []struct {
		name       string
		typeName   ebpf.MapType
		keySize    uint32
		valueSize  uint32
		minEntries uint32
	}{
		{kernelXDPPluginProgramChainMapName, ebpf.ProgramArray, 4, 4, kernelXDPPluginProgramChainMaxEntries},
		{kernelXDPPluginConfigMapName, ebpf.Array, 4, 16, 1},
		{kernelXDPPluginInterfacesMapName, ebpf.Hash, 8, 4, 1},
		{kernelXDPPluginScratchMapName, ebpf.PerCPUArray, 4, 16, 1},
		{kernelXDPPluginMetricsMapName, ebpf.PerCPUArray, 4, 32, kernelXDPPluginMaxHooks},
	}
	for _, check := range checks {
		m := spec.Maps[check.name]
		if m == nil || m.Type != check.typeName || m.KeySize != check.keySize || m.ValueSize != check.valueSize || m.MaxEntries < check.minEntries {
			if m == nil {
				return fmt.Errorf("xdp plugin dispatcher map %q is missing", check.name)
			}
			return fmt.Errorf("xdp plugin dispatcher map %q is incompatible: type=%s key=%d value=%d entries=%d", check.name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries)
		}
	}
	return nil
}

func kernelXDPPluginCollectionPieces(coll *ebpf.Collection) (kernelXDPPluginPieces, error) {
	if coll == nil {
		return kernelXDPPluginPieces{}, fmt.Errorf("xdp plugin dispatcher collection is nil")
	}
	pieces := kernelXDPPluginPieces{
		dispatcher:   coll.Programs[kernelXDPPluginDispatcherProgramName],
		continuation: coll.Programs[kernelXDPPluginContinueProgramName],
		progChain:    coll.Maps[kernelXDPPluginProgramChainMapName],
		config:       coll.Maps[kernelXDPPluginConfigMapName],
		interfaces:   coll.Maps[kernelXDPPluginInterfacesMapName],
		metrics:      coll.Maps[kernelXDPPluginMetricsMapName],
	}
	if pieces.dispatcher == nil || pieces.continuation == nil || pieces.progChain == nil || pieces.config == nil || pieces.interfaces == nil || pieces.metrics == nil {
		return kernelXDPPluginPieces{}, fmt.Errorf("xdp plugin dispatcher collection is incomplete")
	}
	return pieces, nil
}

func (rt *kernelXDPPluginPipelineRuntime) loadProgramsLocked(desired []kernelXDPPluginDesiredPlugin, pieces kernelXDPPluginPieces) ([]loadedPluginObjectRef, []loadedKernelXDPPluginProgram, map[string]PluginRuntimeState, error) {
	states := make(map[string]PluginRuntimeState)
	plans := make([]kernelXDPPluginHookPlan, 0, kernelXDPPluginMaxHooks)
	for _, item := range desired {
		plans = append(plans, item.hooks...)
	}
	sort.Slice(plans, func(i, j int) bool { return kernelXDPPluginHookLess(plans[i], plans[j]) })
	if len(plans) > kernelXDPPluginMaxHooks {
		return nil, nil, states, fmt.Errorf("too many xdp plugin hooks: %d > %d", len(plans), kernelXDPPluginMaxHooks)
	}

	cache := make(map[string]*loadedPluginObject)
	refs := make([]loadedPluginObjectRef, 0, len(plans))
	refSeen := make(map[string]struct{}, len(plans))
	programs := make([]loadedKernelXDPPluginProgram, 0, len(plans))
	for _, plan := range plans {
		cacheKey := plan.PluginID + "\x00" + plan.ObjectPath
		object := cache[cacheKey]
		if object == nil {
			previous, unchanged := previousKernelXDPPluginObject(rt.loaded, plan)
			var err error
			object, err = loadKernelXDPPluginObject(plan, pieces, previous, unchanged)
			if err != nil {
				cleanupLoadedPluginObjectCache(cache)
				return nil, nil, states, fmt.Errorf("load plugin %s object %s: %w", plan.PluginID, plan.ObjectID, err)
			}
			cache[cacheKey] = object
		}
		prog, err := pluginProgramForAttach(object, plan.ProgramSection, plan.ProgramRef)
		if err != nil {
			cleanupLoadedPluginObjectCache(cache)
			return nil, nil, states, fmt.Errorf("load plugin %s hook %s: %w", plan.PluginID, plan.HookID, err)
		}
		programs = append(programs, loadedKernelXDPPluginProgram{plan: plan, prog: prog})
		refKey := plan.PluginID + "\x00" + plan.ObjectID + "\x00" + plan.ObjectPath
		if _, ok := refSeen[refKey]; !ok {
			refSeen[refKey] = struct{}{}
			refs = append(refs, loadedPluginObjectRef{
				PluginID:     plan.PluginID,
				ObjectID:     plan.ObjectID,
				ObjectPath:   plan.ObjectPath,
				ObjectSHA256: plan.ObjectSHA256,
				StateMaps:    append([]PluginObjectStateMap(nil), plan.ObjectStateMaps...),
				Migrations:   append([]PluginEBPFStateMigration(nil), object.migrations...),
				spec:         object.spec,
				coll:         object.coll,
			})
		}
	}
	return refs, programs, states, nil
}

func previousKernelXDPPluginObject(refs []loadedPluginObjectRef, plan kernelXDPPluginHookPlan) (*loadedPluginObjectRef, bool) {
	for i := range refs {
		ref := &refs[i]
		if ref.PluginID != plan.PluginID || ref.ObjectID != plan.ObjectID || ref.ObjectPath != plan.ObjectPath {
			continue
		}
		return ref, ref.ObjectSHA256 == plan.ObjectSHA256
	}
	return nil, false
}

func loadKernelXDPPluginObject(plan kernelXDPPluginHookPlan, pieces kernelXDPPluginPieces, previous *loadedPluginObjectRef, unchanged bool) (*loadedPluginObject, error) {
	spec, err := loadVerifiedPluginObjectCollectionSpec(plan.ObjectPath, plan.ObjectSHA256)
	if err != nil {
		return nil, err
	}
	chainSpec := spec.Maps[kernelXDPPluginProgramChainMapName]
	if chainSpec == nil || chainSpec.Type != ebpf.ProgramArray || chainSpec.MaxEntries < kernelXDPPluginProgramChainMaxEntries {
		return nil, fmt.Errorf("object must declare shared map %q as a program array with at least %d entries", kernelXDPPluginProgramChainMapName, kernelXDPPluginProgramChainMaxEntries)
	}
	replacements, err := pluginPipelineMapReplacements(spec, map[string]*ebpf.Map{
		kernelXDPPluginProgramChainMapName: pieces.progChain,
	}, plan.ObjectStateMaps, previous, unchanged)
	if err != nil {
		return nil, err
	}
	migrations, err := planPluginObjectStateMigrations(plan.PluginID, plan.ObjectID, plan.ObjectStateMaps, previous)
	if err != nil {
		return nil, err
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(replacements))
	if err != nil {
		logKernelVerifierDetails(err)
		return nil, err
	}
	return &loadedPluginObject{path: plan.ObjectPath, spec: spec, coll: coll, migrations: migrations}, nil
}

func collectKernelXDPPluginInterfaces(programs []loadedKernelXDPPluginProgram) []int {
	seen := make(map[int]struct{})
	for _, item := range programs {
		for _, ifindex := range item.plan.InterfaceIndexes {
			if ifindex > 0 {
				seen[int(ifindex)] = struct{}{}
			}
		}
	}
	out := make([]int, 0, len(seen))
	for ifindex := range seen {
		out = append(out, ifindex)
	}
	sort.Ints(out)
	return out
}

func (rt *kernelXDPPluginPipelineRuntime) reconcileAttachmentsLocked(desired []int, prog *ebpf.Program, programID uint32) ([]xdpAttachment, []xdpAttachment, error) {
	oldByIndex := make(map[int]xdpAttachment, len(rt.attachments))
	for _, att := range rt.attachments {
		oldByIndex[att.ifindex] = att
	}
	result := make([]xdpAttachment, 0, len(desired))
	added := make([]xdpAttachment, 0, len(desired))
	for _, ifindex := range desired {
		if old, ok := oldByIndex[ifindex]; ok && xdpAttachmentExists(old, rt.programID) {
			result = append(result, old)
			continue
		}
		att, err := attachKernelXDPPluginDispatcher(ifindex, prog, rt.cfg != nil && rt.cfg.ExperimentalFeatureEnabled(experimentalFeatureXDPGeneric))
		if err != nil {
			return result, added, fmt.Errorf("attach xdp plugin dispatcher on %s: %w", xdpInterfaceLabel(ifindex), err)
		}
		result = append(result, att)
		added = append(added, att)
	}
	if len(result) == 0 || programID == 0 {
		return result, added, fmt.Errorf("xdp plugin dispatcher did not establish a verifiable attachment")
	}
	return result, added, nil
}

func attachKernelXDPPluginDispatcher(ifindex int, prog *ebpf.Program, allowGeneric bool) (xdpAttachment, error) {
	if prog == nil {
		return xdpAttachment{}, fmt.Errorf("dispatcher program is nil")
	}
	link, err := pluginControlNetLinkByIndex(ifindex)
	if err != nil {
		return xdpAttachment{}, err
	}
	if attrs := link.Attrs(); attrs != nil && attrs.Xdp != nil && attrs.Xdp.Attached {
		return xdpAttachment{}, fmt.Errorf("interface already has xdp program id %d; Veer will not replace it", attrs.Xdp.ProgId)
	}
	var failures []string
	for _, mode := range xdpAttachOrder(link, nil, allowGeneric) {
		flags := mode | nl.XDP_FLAGS_UPDATE_IF_NOEXIST
		if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err == nil {
			return xdpAttachment{ifindex: ifindex, flags: mode}, nil
		} else {
			failures = append(failures, fmt.Sprintf("%s=%v", xdpAttachFlagsLabel(mode), err))
		}
	}
	if !allowGeneric {
		failures = append(failures, "generic skipped: "+xdpGenericAttachmentExperimentalReason())
	}
	return xdpAttachment{}, errors.New(strings.Join(failures, "; "))
}

func (rt *kernelXDPPluginPipelineRuntime) attachmentsHealthyLocked(desired []kernelXDPPluginDesiredPlugin) bool {
	wanted := make(map[int]struct{})
	for _, plugin := range desired {
		for _, hook := range plugin.hooks {
			for _, ifindex := range hook.InterfaceIndexes {
				wanted[int(ifindex)] = struct{}{}
			}
		}
	}
	if len(wanted) != len(rt.attachments) || rt.programID == 0 {
		return false
	}
	for _, att := range rt.attachments {
		if _, ok := wanted[att.ifindex]; !ok || !xdpAttachmentExists(att, rt.programID) {
			return false
		}
	}
	return true
}

func installKernelXDPPluginPrograms(pieces kernelXDPPluginPieces, programs []loadedKernelXDPPluginProgram) (bank uint32, resultErr error) {
	if len(programs) == 0 || len(programs) > kernelXDPPluginMaxHooks {
		return 0, fmt.Errorf("xdp plugin program count %d is outside 1..%d", len(programs), kernelXDPPluginMaxHooks)
	}
	var current kernelXDPPluginConfig
	if err := pieces.config.Lookup(uint32(0), &current); err != nil {
		return 0, fmt.Errorf("lookup xdp plugin config: %w", err)
	}
	inactive := (current.ActiveBank & 1) ^ 1
	switched := false
	defer func() {
		if resultErr != nil && !switched {
			_ = clearKernelXDPPluginBank(pieces, inactive)
		}
	}()
	if err := clearKernelXDPPluginBank(pieces, inactive); err != nil {
		return 0, err
	}
	base := kernelXDPPluginBankBase(inactive)
	interfaceMasks := make(map[uint32]uint32)
	for i, item := range programs {
		if item.prog == nil {
			return 0, fmt.Errorf("xdp plugin program %d is nil", i)
		}
		slot := uint32(base + i)
		if err := pieces.progChain.Put(slot, uint32(item.prog.FD())); err != nil {
			return 0, fmt.Errorf("install xdp plugin %s/%s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
		}
		bit := uint32(1) << uint32(i)
		for _, ifindex := range item.plan.InterfaceIndexes {
			interfaceMasks[ifindex] |= bit
		}
	}
	for ifindex, mask := range interfaceMasks {
		key := kernelXDPPluginInterfaceKey{IfIndex: ifindex, Bank: inactive}
		if err := pieces.interfaces.Put(key, kernelXDPPluginInterfaceValue{Mask: mask}); err != nil {
			return 0, fmt.Errorf("sync xdp plugin interface %d bank %d: %w", ifindex, inactive, err)
		}
	}
	if err := clearKernelXDPPluginMetrics(pieces.metrics); err != nil {
		return 0, fmt.Errorf("reset xdp plugin metrics: %w", err)
	}
	next := kernelXDPPluginConfig{
		Count:      uint32(len(programs)),
		ActiveBank: inactive,
		Generation: current.Generation + 1,
	}
	if err := pieces.config.Put(uint32(0), next); err != nil {
		return 0, fmt.Errorf("switch xdp plugin chain bank: %w", err)
	}
	switched = true
	return inactive, nil
}

func kernelXDPPluginBankBase(bank uint32) int {
	if bank&1 == 0 {
		return kernelXDPPluginBank0Base
	}
	return kernelXDPPluginBank1Base
}

func clearKernelXDPPluginBank(pieces kernelXDPPluginPieces, bank uint32) error {
	var failures []string
	base := kernelXDPPluginBankBase(bank)
	for i := 0; i < kernelXDPPluginMaxHooks; i++ {
		if err := deleteKernelMapEntry(pieces.progChain, uint32(base+i)); err != nil {
			failures = append(failures, fmt.Sprintf("clear xdp plugin slot %d: %v", base+i, err))
		}
	}
	keys := make([]kernelXDPPluginInterfaceKey, 0)
	iterator := pieces.interfaces.Iterate()
	var key kernelXDPPluginInterfaceKey
	var value kernelXDPPluginInterfaceValue
	for iterator.Next(&key, &value) {
		if key.Bank&1 == bank&1 {
			keys = append(keys, key)
		}
	}
	if err := iterator.Err(); err != nil {
		failures = append(failures, fmt.Sprintf("iterate xdp plugin interfaces: %v", err))
	}
	for _, current := range keys {
		if err := deleteKernelMapEntry(pieces.interfaces, current); err != nil {
			failures = append(failures, fmt.Sprintf("clear xdp plugin interface %d bank %d: %v", current.IfIndex, current.Bank, err))
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func clearKernelXDPPluginMetrics(metrics *ebpf.Map) error {
	if metrics == nil {
		return fmt.Errorf("xdp plugin metrics map is nil")
	}
	possible, err := kernelPossibleCPUCount()
	if err != nil {
		return err
	}
	zero := make([]kernelXDPPluginMetricValue, possible)
	for i := uint32(0); i < kernelXDPPluginMaxHooks; i++ {
		if err := metrics.Put(i, zero); err != nil {
			return err
		}
	}
	return nil
}

func kernelXDPPluginAttachmentStates(programs []loadedKernelXDPPluginProgram, bank uint32) map[string][]PluginAttachmentState {
	result := make(map[string][]PluginAttachmentState)
	base := kernelXDPPluginBankBase(bank)
	for index, item := range programs {
		for i, ifindex := range item.plan.InterfaceIndexes {
			name := ""
			if i < len(item.plan.Interfaces) {
				name = item.plan.Interfaces[i]
			}
			if name == "" {
				name = xdpInterfaceLabel(int(ifindex))
			}
			result[item.plan.PluginID] = append(result[item.plan.PluginID], PluginAttachmentState{
				HookID:    item.plan.HookID,
				Engine:    kernelEngineXDP,
				Attach:    "ingress",
				Stage:     item.plan.Stage,
				Interface: name,
				Program:   item.plan.ObjectID + ":" + item.plan.ProgramRef,
				Mode:      item.plan.Mode,
				Priority:  item.plan.Priority,
				Before:    append([]string(nil), item.plan.Before...),
				After:     append([]string(nil), item.plan.After...),
				Order:     item.plan.Order,
				ChainSlot: base + index,
				Status:    "attached",
			})
		}
	}
	return result
}

func populateKernelXDPPluginMetrics(snapshot pluginRuntimeSnapshot, metrics *ebpf.Map) {
	if metrics == nil || len(snapshot.Plugins) == 0 {
		return
	}
	possible, err := kernelPossibleCPUCount()
	if err != nil {
		return
	}
	cache := make(map[int]kernelXDPPluginMetricValue)
	for pluginID, state := range snapshot.Plugins {
		changed := false
		for i := range state.Attachments {
			attachment := &state.Attachments[i]
			if attachment.Engine != kernelEngineXDP {
				continue
			}
			index, ok := kernelXDPPluginMetricIndex(attachment.ChainSlot)
			if !ok {
				continue
			}
			value, exists := cache[index]
			if !exists {
				perCPU := make([]kernelXDPPluginMetricValue, possible)
				if err := metrics.Lookup(uint32(index), &perCPU); err != nil {
					continue
				}
				for _, current := range perCPU {
					value.Packets += current.Packets
					value.Bytes += current.Bytes
					value.Continued += current.Continued
					value.TailCallMisses += current.TailCallMisses
				}
				cache[index] = value
			}
			total := pluginPacketMetrics(value.Packets, value.Bytes, value.Continued, value.TailCallMisses, attachment.Mode == "drop")
			attachment.Metrics = &PluginAttachmentMetrics{Total: total}
			changed = true
		}
		if changed {
			snapshot.Plugins[pluginID] = state
		}
	}
}

func kernelXDPPluginMetricIndex(slot int) (int, bool) {
	for _, base := range []int{kernelXDPPluginBank0Base, kernelXDPPluginBank1Base} {
		if slot >= base && slot < base+kernelXDPPluginMaxHooks {
			return slot - base, true
		}
	}
	return 0, false
}

func (rt *kernelXDPPluginPipelineRuntime) cleanupLocked() error {
	var failures []string
	if rt.dispatcher != nil {
		if pieces, err := kernelXDPPluginCollectionPieces(rt.dispatcher); err != nil {
			failures = append(failures, err.Error())
		} else {
			var current kernelXDPPluginConfig
			if err := pieces.config.Lookup(uint32(0), &current); err != nil {
				failures = append(failures, fmt.Sprintf("lookup xdp plugin config: %v", err))
			} else {
				empty := kernelXDPPluginConfig{ActiveBank: (current.ActiveBank & 1) ^ 1, Generation: current.Generation + 1}
				if err := pieces.config.Put(uint32(0), empty); err != nil {
					failures = append(failures, fmt.Sprintf("disable xdp plugin chain: %v", err))
				} else if current.Count > 0 {
					time.Sleep(kernelPluginPipelineUpdateGrace)
				}
			}
			for bank := uint32(0); bank < 2; bank++ {
				if err := clearKernelXDPPluginBank(pieces, bank); err != nil {
					failures = append(failures, err.Error())
				}
			}
		}
	}
	detachOwnedXDPPluginAttachments(rt.attachments, rt.programID)
	cleanupKernelPluginPipelineCollections(rt.loaded)
	if rt.dispatcher != nil {
		rt.dispatcher.Close()
	}
	clearKernelRuntimeMetadata(kernelXDPPluginRuntimeEngine)
	rt.dispatcher = nil
	rt.attachments = nil
	rt.programID = 0
	rt.loaded = nil
	rt.desired = nil
	rt.fingerprint = ""
	rt.activeBank = 0
	rt.snapshot = pluginRuntimeSnapshot{}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func detachOwnedXDPPluginAttachments(attachments []xdpAttachment, programID uint32) {
	for i := len(attachments) - 1; i >= 0; i-- {
		att := attachments[i]
		if programID == 0 || !xdpAttachmentExists(att, programID) {
			continue
		}
		if err := detachXDPAttachment(att); err != nil {
			log.Printf("xdp plugin pipeline detach %s: %v", xdpInterfaceLabel(att.ifindex), err)
		}
	}
}

func detachStaleOwnedXDPPluginAttachments(oldAttachments, newAttachments []xdpAttachment, programID uint32) {
	active := make(map[int]struct{}, len(newAttachments))
	for _, att := range newAttachments {
		active[att.ifindex] = struct{}{}
	}
	for _, att := range oldAttachments {
		if _, ok := active[att.ifindex]; ok {
			continue
		}
		detachOwnedXDPPluginAttachments([]xdpAttachment{att}, programID)
	}
}

func writeXDPPluginRuntimeMetadata(attachments []xdpAttachment, programID uint32) error {
	meta := kernelHotRestartMetadata{
		FormatVersion:  kernelHotRestartMetadataFormatVersion,
		Engine:         kernelXDPPluginRuntimeEngine,
		XDPAttachments: make([]kernelHotRestartXDPAttachment, 0, len(attachments)),
	}
	for _, att := range attachments {
		meta.XDPAttachments = append(meta.XDPAttachments, kernelHotRestartXDPAttachment{Ifindex: att.ifindex, Flags: att.flags, ProgramID: programID})
	}
	return writeKernelRuntimeMetadata(kernelXDPPluginRuntimeEngine, meta)
}

func cleanupOrphanXDPPluginRuntimeState() error {
	meta, err := readKernelRuntimeMetadata(kernelXDPPluginRuntimeEngine)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			clearKernelRuntimeMetadata(kernelXDPPluginRuntimeEngine)
			return nil
		}
		return err
	}
	if meta.Engine != kernelXDPPluginRuntimeEngine {
		return fmt.Errorf("xdp plugin runtime metadata has unexpected engine %q", meta.Engine)
	}
	if kernelMetadataOwnerAlive(meta) {
		return fmt.Errorf("another Veer process still owns the xdp plugin dispatcher")
	}
	for _, item := range meta.XDPAttachments {
		att := xdpAttachment{ifindex: item.Ifindex, flags: item.Flags}
		if item.ProgramID == 0 || !xdpAttachmentExists(att, item.ProgramID) {
			continue
		}
		if err := detachXDPAttachment(att); err != nil {
			return fmt.Errorf("detach orphan xdp plugin dispatcher from ifindex %d: %w", item.Ifindex, err)
		}
	}
	clearKernelRuntimeMetadata(kernelXDPPluginRuntimeEngine)
	return nil
}
