//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const (
	kernelPluginPipelineInterface       = builtinPluginPipelineID
	kernelPluginPipelineStageForward    = "forward"
	kernelPluginPipelineStageReply      = "reply"
	kernelPluginPipelineStagePreForward = "pre_forward"
	kernelPluginPipelineStagePostLookup = "post_lookup"
	kernelPluginPipelineStagePreReply   = "pre_reply"
	kernelPluginPipelineStagePostReply  = "post_reply"
	kernelPluginPipelineUpdateGrace     = 25 * time.Millisecond
	kernelPluginPipelineAttachIngress   = uint32(0)
	kernelPluginPipelineAttachEgress    = uint32(1)
)

type kernelTCPluginConfigV4 struct {
	PreForwardCount            uint32
	PostLookupCount            uint32
	PreReplyCount              uint32
	PostReplyCount             uint32
	ForwardCoreEnable          uint32
	ReplyCoreEnable            uint32
	ActiveBank                 uint32
	PreForwardGlobalMask       uint32
	PostLookupGlobalMask       uint32
	PreReplyGlobalMask         uint32
	PostReplyGlobalMask        uint32
	EgressPreForwardGlobalMask uint32
	EgressPostLookupGlobalMask uint32
	EgressPreReplyGlobalMask   uint32
	EgressPostReplyGlobalMask  uint32
}

type kernelTCPluginInterfaceKeyV4 struct {
	IfIndex uint32
	Bank    uint32
	Attach  uint32
}

type kernelTCPluginInterfaceValueV4 struct {
	PreForwardMask uint32
	PostLookupMask uint32
	PreReplyMask   uint32
	PostReplyMask  uint32
}

type kernelPluginPipelineInterfaceMasks struct {
	globalByAttach map[uint32]kernelTCPluginInterfaceValueV4
	byInterface    map[kernelPluginPipelineInterfaceScope]kernelTCPluginInterfaceValueV4
}

type kernelPluginPipelineInterfaceScope struct {
	IfIndex uint32
	Attach  uint32
}

type kernelPluginPipelineCoreConfig struct {
	Forward bool
	Reply   bool
}

type kernelAttachmentRuleSets struct {
	ForwardIngress map[int][]int64
	ReplyIngress   map[int][]int64
	ForwardEgress  map[int][]int64
	ReplyEgress    map[int][]int64
}

func kernelAttachmentRuleSetsForPrepared(forward, reply map[int][]int64) kernelAttachmentRuleSets {
	return kernelAttachmentRuleSets{
		ForwardIngress: forward,
		ReplyIngress:   reply,
		ForwardEgress:  make(map[int][]int64),
		ReplyEgress:    make(map[int][]int64),
	}
}

func (sets kernelAttachmentRuleSets) hasTargets() bool {
	return len(sets.ForwardIngress) > 0 || len(sets.ReplyIngress) > 0 ||
		len(sets.ForwardEgress) > 0 || len(sets.ReplyEgress) > 0
}

func (sets kernelAttachmentRuleSets) rules(reply bool, attach uint32) map[int][]int64 {
	if reply {
		if attach == kernelPluginPipelineAttachEgress {
			return sets.ReplyEgress
		}
		return sets.ReplyIngress
	}
	if attach == kernelPluginPipelineAttachEgress {
		return sets.ForwardEgress
	}
	return sets.ForwardIngress
}

func (sets kernelAttachmentRuleSets) clone() kernelAttachmentRuleSets {
	return kernelAttachmentRuleSets{
		ForwardIngress: cloneKernelPluginPipelineAttachRuleSet(sets.ForwardIngress),
		ReplyIngress:   cloneKernelPluginPipelineAttachRuleSet(sets.ReplyIngress),
		ForwardEgress:  cloneKernelPluginPipelineAttachRuleSet(sets.ForwardEgress),
		ReplyEgress:    cloneKernelPluginPipelineAttachRuleSet(sets.ReplyEgress),
	}
}

func cloneKernelPluginPipelineAttachRuleSet(src map[int][]int64) map[int][]int64 {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[int][]int64, len(src))
	for ifindex, ruleIDs := range src {
		dst[ifindex] = append([]int64(nil), ruleIDs...)
	}
	return dst
}

func mergeKernelPluginPipelineAttachmentRuleSets(dst *kernelAttachmentRuleSets, src kernelAttachmentRuleSets) {
	if dst == nil {
		return
	}
	mergeKernelPluginPipelineAttachRuleSets(dst.ForwardIngress, src.ForwardIngress)
	mergeKernelPluginPipelineAttachRuleSets(dst.ReplyIngress, src.ReplyIngress)
	mergeKernelPluginPipelineAttachRuleSets(dst.ForwardEgress, src.ForwardEgress)
	mergeKernelPluginPipelineAttachRuleSets(dst.ReplyEgress, src.ReplyEgress)
}

func boolToKernelPluginConfigFlag(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}

type kernelPluginPipelineDesiredPlugin struct {
	plugin   LoadedPlugin
	hooks    []kernelPluginPipelineHookPlan
	warnings []string
}

type kernelPluginPipelineHookPlan struct {
	PluginID         string
	HookID           string
	ObjectID         string
	ObjectPath       string
	ObjectSHA256     string
	ProgramRef       string
	ProgramSection   string
	Stage            string
	Attach           string
	Mode             string
	Context          []string
	Interfaces       []string
	InterfaceIndexes []uint32
	Priority         int
}

type loadedKernelPluginPipelineProgram struct {
	plan kernelPluginPipelineHookPlan
	prog *ebpf.Program
}

func (rt *linuxKernelRuleRuntime) PluginSnapshot() pluginRuntimeSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
}

func (rt *linuxKernelRuleRuntime) ReconcilePlugins(catalog PluginCatalog) pluginRuntimeSnapshot {
	ensurePluginCatalogControlRegistration(&catalog, rt.cfg)
	desired, states := buildKernelPluginPipelineDesiredForRuntime(catalog, rt.cfg)
	rt.mu.Lock()
	noPreparedRules := len(rt.preparedRules) == 0
	rt.mu.Unlock()
	if noPreparedRules {
		desired = kernelPluginPipelineFilterNoRulePlugins(desired)
	}
	desired, states, attachmentTargets := kernelPluginPipelineResolveExplicitAttachTargets(desired, states)
	if rt.pluginPipelineEnabled &&
		kernelPluginPipelineDesiredHasHooks(desired) &&
		attachmentTargets.hasTargets() {
		catalogForReconcile := catalog
		_, _ = rt.reconcileWithPluginCatalog(nil, &catalogForReconcile)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.pluginPipelineActive = rt.pluginPipelineEnabled && kernelPluginPipelineDesiredHasHooks(desired)
	if !rt.pluginPipelineActive {
		if err := rt.clearPluginPipelineProgramsFromCollectionLocked(); err != nil {
			log.Printf("kernel plugin pipeline cleanup: clear inactive tc chain failed: %v", err)
		}
		cleanedIdleRuntime := rt.cleanupIdlePluginPipelineRuntimeLocked("inactive plugin catalog")
		if !cleanedIdleRuntime {
			rt.cleanupPluginPipelineLocked()
		}
		rt.pluginRuntimeSnapshot = kernelPluginPipelineInactiveSnapshot(catalog, states)
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	if rt.coll == nil {
		rt.cleanupPluginPipelineLocked()
		rt.pluginRuntimeSnapshot = kernelPluginPipelineUnavailableSnapshot(catalog, "no active tc kernel pipeline is loaded")
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		if clearErr := rt.clearPluginPipelineProgramsFromCollectionLocked(); clearErr != nil {
			log.Printf("kernel plugin pipeline cleanup: clear unavailable tc chain failed: %v", clearErr)
		}
		cleanedIdleRuntime := rt.cleanupIdlePluginPipelineRuntimeLocked("unavailable plugin pipeline")
		if !cleanedIdleRuntime {
			rt.cleanupPluginPipelineLocked()
		}
		rt.pluginRuntimeSnapshot = kernelPluginPipelineUnavailableSnapshot(catalog, err.Error())
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	return rt.reconcilePluginPipelineLocked(catalog, pieces, desired, states, kernelPluginPipelineCoreConfig{Forward: !noPreparedRules, Reply: !noPreparedRules})
}

func (rt *linuxKernelRuleRuntime) reconcilePluginPipelineLocked(catalog PluginCatalog, pieces kernelCollectionPieces, desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState, core kernelPluginPipelineCoreConfig) pluginRuntimeSnapshot {
	if snapshot, preserve := rt.preservePluginPipelineCatalogFailureLocked(catalog, pieces, desired); preserve {
		return snapshot
	}
	rt.pluginPipelineActive = rt.pluginPipelineEnabled && kernelPluginPipelineDesiredHasHooks(desired)
	if !rt.pluginPipelineActive {
		if err := clearKernelPluginPipelinePrograms(pieces); err != nil {
			log.Printf("kernel plugin pipeline cleanup: clear inactive tc chain failed: %v", err)
		}
		if !rt.cleanupIdlePluginPipelineRuntimeLocked("inactive plugin pipeline") {
			rt.cleanupPluginPipelineLocked()
		}
		rt.pluginRuntimeSnapshot = kernelPluginPipelineInactiveSnapshot(catalog, states)
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	if !kernelCollectionPiecesSupportPluginPipelineV4(pieces) {
		rt.cleanupPluginPipelineLocked()
		rt.pluginRuntimeSnapshot = kernelPluginPipelineUnavailableSnapshot(catalog, "tc object does not expose the plugin pipeline")
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	if err := configureTCKernelProgramChain(pieces, true); err != nil {
		rt.cleanupPluginPipelineLocked()
		rt.pluginRuntimeSnapshot = kernelPluginPipelineUnavailableSnapshot(catalog, err.Error())
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}

	fingerprint := kernelPluginPipelineFingerprint(desired, states, core)
	if fingerprint == rt.pluginPipelineFingerprint && rt.pluginPipelineProgChain == pieces.progChainV4 && len(rt.pluginPipelineLoaded) > 0 {
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}

	loaded, programs, loadStates, loadErr := rt.loadKernelPluginPipelinePrograms(desired, pieces)
	for id, state := range loadStates {
		states[id] = state
	}
	if loadErr != nil {
		cleanupKernelPluginPipelineCollections(loaded)
		return rt.preservePluginPipelineUpdateFailureLocked(catalog, pieces, desired, states, fmt.Sprintf("load plugin pipeline: %v", loadErr))
	}
	if len(programs) == 0 {
		cleanupKernelPluginPipelineCollections(loaded)
		if err := clearKernelPluginPipelinePrograms(pieces); err != nil {
			log.Printf("kernel plugin pipeline cleanup: clear empty tc chain failed: %v", err)
		}
		oldLoaded := rt.pluginPipelineLoaded
		rt.pluginPipelineLoaded = nil
		rt.pluginPipelineDesired = nil
		rt.pluginPipelineFingerprint = ""
		rt.pluginPipelineProgChain = pieces.progChainV4
		rt.pluginPipelineBankSwitchedAt = time.Time{}
		rt.pluginPipelineActive = false
		cleanupKernelPluginPipelineCollections(oldLoaded)
		_ = rt.cleanupIdlePluginPipelineRuntimeLocked("empty plugin pipeline")
		rt.pluginRuntimeSnapshot = kernelPluginPipelineInactiveSnapshot(catalog, states)
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	if rt.pluginPipelineProgChain == pieces.progChainV4 && !rt.pluginPipelineBankSwitchedAt.IsZero() {
		if remaining := kernelPluginPipelineUpdateGrace - time.Since(rt.pluginPipelineBankSwitchedAt); remaining > 0 {
			time.Sleep(remaining)
		}
	}
	activeBank, err := installKernelPluginPipelinePrograms(pieces, programs, core)
	if err != nil {
		cleanupKernelPluginPipelineCollections(loaded)
		return rt.preservePluginPipelineUpdateFailureLocked(catalog, pieces, desired, states, fmt.Sprintf("install plugin pipeline: %v", err))
	}

	oldLoaded := rt.pluginPipelineLoaded
	if len(oldLoaded) > 0 {
		time.Sleep(kernelPluginPipelineUpdateGrace)
		if err := clearKernelPluginPipelineBank(pieces, activeBank^1); err != nil {
			log.Printf("kernel plugin pipeline cleanup: clear inactive bank %d failed: %v", activeBank^1, err)
		}
	}
	rt.pluginPipelineLoaded = loaded
	rt.pluginPipelineDesired = cloneKernelPluginPipelineDesired(desired)
	rt.pluginPipelineFingerprint = fingerprint
	rt.pluginPipelineProgChain = pieces.progChainV4
	rt.pluginPipelineBankSwitchedAt = time.Now()
	rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{Plugins: states}
	cleanupKernelPluginPipelineCollections(oldLoaded)
	return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
}

func (rt *linuxKernelRuleRuntime) preservePluginPipelineCatalogFailureLocked(catalog PluginCatalog, pieces kernelCollectionPieces, desired []kernelPluginPipelineDesiredPlugin) (pluginRuntimeSnapshot, bool) {
	if rt.pluginPipelineProgChain != pieces.progChainV4 || len(rt.pluginPipelineLoaded) == 0 {
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
	loadedIDs := make(map[string]struct{}, len(rt.pluginPipelineLoaded))
	for _, ref := range rt.pluginPipelineLoaded {
		loadedIDs[ref.PluginID] = struct{}{}
	}
	failures := make(map[string]string)
	for pluginID := range loadedIDs {
		plugin, found := catalogByID[pluginID]
		if !found || !plugin.Enabled || plugin.Status == pluginStatusDisabled {
			return pluginRuntimeSnapshot{}, false
		}
		if plugin.Status == pluginStatusError {
			message := strings.TrimSpace(plugin.Error)
			if message == "" {
				message = "plugin catalog reload failed"
			}
			failures[pluginID] = message
			continue
		}
		if _, stillDesired := desiredIDs[pluginID]; !stillDesired {
			return pluginRuntimeSnapshot{}, false
		}
	}
	if len(failures) == 0 {
		return pluginRuntimeSnapshot{}, false
	}

	snapshot := clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	if snapshot.Plugins == nil {
		snapshot.Plugins = make(map[string]PluginRuntimeState)
	}
	for pluginID, message := range failures {
		state := snapshot.Plugins[pluginID]
		state.Error = message
		if strings.TrimSpace(state.Reason) != "" {
			state.Reason += "; "
		}
		state.Reason += "plugin catalog update failed; previous chain preserved"
		snapshot.Plugins[pluginID] = state
	}
	rt.pluginPipelineActive = true
	rt.pluginRuntimeSnapshot = snapshot
	return clonePluginRuntimeSnapshot(snapshot), true
}

func (rt *linuxKernelRuleRuntime) preservePluginPipelineUpdateFailureLocked(catalog PluginCatalog, pieces kernelCollectionPieces, desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState, message string) pluginRuntimeSnapshot {
	if rt.pluginPipelineProgChain == pieces.progChainV4 && len(rt.pluginPipelineLoaded) > 0 && kernelPluginPipelineCanPreserveLoadedPlugins(rt.pluginPipelineLoaded, desired) {
		snapshot := clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
		if snapshot.Plugins == nil {
			snapshot.Plugins = make(map[string]PluginRuntimeState)
		}
		for _, item := range desired {
			state := snapshot.Plugins[item.plugin.ID]
			state.Error = message
			if strings.TrimSpace(state.Reason) != "" {
				state.Reason += "; "
			}
			state.Reason += "plugin pipeline update failed; previous chain preserved"
			snapshot.Plugins[item.plugin.ID] = state
		}
		rt.pluginPipelineActive = true
		rt.pluginRuntimeSnapshot = snapshot
		return clonePluginRuntimeSnapshot(snapshot)
	}

	if err := clearKernelPluginPipelinePrograms(pieces); err != nil {
		message += "; clear unusable plugin chain: " + err.Error()
	}
	cleanupKernelPluginPipelineCollections(rt.pluginPipelineLoaded)
	rt.pluginPipelineLoaded = nil
	rt.pluginPipelineDesired = nil
	rt.pluginPipelineFingerprint = ""
	rt.pluginPipelineProgChain = pieces.progChainV4
	rt.pluginPipelineBankSwitchedAt = time.Time{}
	rt.pluginPipelineActive = false
	for _, item := range desired {
		state := pluginRuntimeErrorState(message)
		state.Reason = "plugin pipeline update failed; no previous compatible chain was retained"
		states[item.plugin.ID] = state
	}
	states = kernelPluginPipelineErrorAll(catalog, message, states)
	rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{Plugins: states}
	return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
}

func kernelPluginPipelineCanPreserveLoadedPlugins(loaded []loadedPluginObjectRef, desired []kernelPluginPipelineDesiredPlugin) bool {
	desiredIDs := make(map[string]struct{}, len(desired))
	for _, item := range desired {
		desiredIDs[item.plugin.ID] = struct{}{}
	}
	for _, ref := range loaded {
		if _, ok := desiredIDs[ref.PluginID]; !ok {
			return false
		}
	}
	return len(loaded) > 0
}

func (rt *linuxKernelRuleRuntime) pluginPipelineDesiredForCatalogFailure(catalog PluginCatalog, current []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState, bool) {
	if len(rt.pluginPipelineLoaded) == 0 || len(rt.pluginPipelineDesired) == 0 {
		return nil, states, false
	}
	currentIDs := make(map[string]struct{}, len(current))
	for _, item := range current {
		currentIDs[item.plugin.ID] = struct{}{}
	}
	catalogByID := make(map[string]LoadedPlugin, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		catalogByID[plugin.ID] = plugin
	}
	loadedIDs := make(map[string]struct{}, len(rt.pluginPipelineLoaded))
	for _, ref := range rt.pluginPipelineLoaded {
		loadedIDs[ref.PluginID] = struct{}{}
	}
	failures := make(map[string]string)
	for pluginID := range loadedIDs {
		plugin, found := catalogByID[pluginID]
		if !found || !plugin.Enabled || plugin.Status == pluginStatusDisabled {
			return nil, states, false
		}
		if plugin.Status == pluginStatusError {
			message := strings.TrimSpace(plugin.Error)
			if message == "" {
				message = "plugin catalog reload failed"
			}
			failures[pluginID] = message
			continue
		}
		if _, stillDesired := currentIDs[pluginID]; !stillDesired {
			return nil, states, false
		}
	}
	if len(failures) == 0 {
		return nil, states, false
	}
	if states == nil {
		states = make(map[string]PluginRuntimeState)
	}
	for pluginID, message := range failures {
		state := states[pluginID]
		state.Error = message
		state.Reason = "plugin catalog update failed; previous chain is being retained"
		states[pluginID] = state
	}
	return cloneKernelPluginPipelineDesired(rt.pluginPipelineDesired), states, true
}

func cloneKernelPluginPipelineDesired(values []kernelPluginPipelineDesiredPlugin) []kernelPluginPipelineDesiredPlugin {
	if len(values) == 0 {
		return nil
	}
	out := make([]kernelPluginPipelineDesiredPlugin, len(values))
	for i, item := range values {
		out[i] = item
		out[i].warnings = append([]string(nil), item.warnings...)
		out[i].hooks = make([]kernelPluginPipelineHookPlan, len(item.hooks))
		for j, hook := range item.hooks {
			out[i].hooks[j] = hook
			out[i].hooks[j].Context = append([]string(nil), hook.Context...)
			out[i].hooks[j].Interfaces = append([]string(nil), hook.Interfaces...)
			out[i].hooks[j].InterfaceIndexes = append([]uint32(nil), hook.InterfaceIndexes...)
		}
	}
	return out
}

func kernelPluginPipelineDesiredHasHooks(desired []kernelPluginPipelineDesiredPlugin) bool {
	for _, item := range desired {
		if len(item.hooks) > 0 {
			return true
		}
	}
	return false
}

func kernelPluginPipelineHookHasExplicitInterfaces(plan kernelPluginPipelineHookPlan) bool {
	return len(plan.Interfaces) > 0
}

func kernelPluginPipelineHasAttachmentTargets(forwardIfRules map[int][]int64, replyIfRules map[int][]int64) bool {
	return len(forwardIfRules) > 0 || len(replyIfRules) > 0
}

func kernelPluginPipelineFilterNoRulePlugins(desired []kernelPluginPipelineDesiredPlugin) []kernelPluginPipelineDesiredPlugin {
	if len(desired) == 0 {
		return nil
	}
	filtered := make([]kernelPluginPipelineDesiredPlugin, 0, len(desired))
	for _, item := range desired {
		next := item
		next.hooks = nil
		for _, hook := range item.hooks {
			if kernelPluginPipelineHookRunnableWithoutRules(hook) {
				next.hooks = append(next.hooks, hook)
			}
		}
		if len(next.hooks) > 0 {
			filtered = append(filtered, next)
		}
	}
	return filtered
}

func kernelPluginPipelineHookRunnableWithoutRules(plan kernelPluginPipelineHookPlan) bool {
	if !kernelPluginPipelineHookHasExplicitInterfaces(plan) {
		return false
	}
	switch plan.Stage {
	case kernelPluginPipelineStagePreForward,
		kernelPluginPipelineStagePostLookup,
		kernelPluginPipelineStagePreReply,
		kernelPluginPipelineStagePostReply:
		return true
	default:
		return false
	}
}

func kernelPluginPipelineResolveExplicitAttachTargets(desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState, kernelAttachmentRuleSets) {
	if states == nil {
		states = make(map[string]PluginRuntimeState)
	}
	targets := kernelAttachmentRuleSetsForPrepared(make(map[int][]int64), make(map[int][]int64))
	if len(desired) == 0 {
		return nil, states, targets
	}

	filtered := make([]kernelPluginPipelineDesiredPlugin, 0, len(desired))
	for itemIndex := range desired {
		item := desired[itemIndex]
		itemTargets := kernelAttachmentRuleSetsForPrepared(make(map[int][]int64), make(map[int][]int64))
		itemErr := ""
		for hookIndex := range item.hooks {
			hook := &item.hooks[hookIndex]
			hook.InterfaceIndexes = nil
			if len(hook.Interfaces) == 0 {
				continue
			}
			seenIndexes := make(map[uint32]struct{}, len(hook.Interfaces))
			for _, name := range hook.Interfaces {
				iface, err := net.InterfaceByName(name)
				if err != nil {
					itemErr = fmt.Sprintf("hook %s interface %q: %v", hook.HookID, name, err)
					break
				}
				if _, exists := seenIndexes[uint32(iface.Index)]; !exists {
					hook.InterfaceIndexes = append(hook.InterfaceIndexes, uint32(iface.Index))
					seenIndexes[uint32(iface.Index)] = struct{}{}
				}
				for _, attach := range kernelPluginPipelinePlanAttachDirections(hook.Attach) {
					switch hook.Stage {
					case kernelPluginPipelineStagePreForward, kernelPluginPipelineStagePostLookup:
						if attach == kernelPluginPipelineAttachEgress {
							itemTargets.ForwardEgress[iface.Index] = nil
						} else {
							itemTargets.ForwardIngress[iface.Index] = nil
						}
					case kernelPluginPipelineStagePreReply, kernelPluginPipelineStagePostReply:
						if attach == kernelPluginPipelineAttachEgress {
							itemTargets.ReplyEgress[iface.Index] = nil
						} else {
							itemTargets.ReplyIngress[iface.Index] = nil
						}
					}
				}
			}
			if itemErr != "" {
				break
			}
		}
		if itemErr != "" {
			states[item.plugin.ID] = pluginRuntimeErrorState(itemErr)
			continue
		}
		desired[itemIndex] = item
		mergeKernelPluginPipelineAttachmentRuleSets(&targets, itemTargets)
		filtered = append(filtered, item)
	}
	return filtered, states, targets
}

// kernelPluginPipelineResolveExplicitAttachRuleSets retains the ingress-only
// result shape used by older callers and focused unit tests.
func kernelPluginPipelineResolveExplicitAttachRuleSets(desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState, map[int][]int64, map[int][]int64) {
	desired, states, targets := kernelPluginPipelineResolveExplicitAttachTargets(desired, states)
	return desired, states, targets.ForwardIngress, targets.ReplyIngress
}

func mergeKernelPluginPipelineAttachRuleSets(dst map[int][]int64, src map[int][]int64) {
	if len(src) == 0 {
		return
	}
	for ifindex, ruleIDs := range src {
		if _, ok := dst[ifindex]; ok {
			dst[ifindex] = append(dst[ifindex], ruleIDs...)
			continue
		}
		dst[ifindex] = append([]int64(nil), ruleIDs...)
	}
}

func kernelPluginPipelineNormalizeStage(stage string, priority int) (string, bool, error) {
	switch stage {
	case kernelPluginPipelineStagePreForward:
		return kernelPluginPipelineStagePreForward, true, nil
	case kernelPluginPipelineStagePostLookup:
		return kernelPluginPipelineStagePostLookup, true, nil
	case kernelPluginPipelineStagePreReply:
		return kernelPluginPipelineStagePreReply, true, nil
	case kernelPluginPipelineStagePostReply:
		return kernelPluginPipelineStagePostReply, true, nil
	case kernelPluginPipelineStageForward:
		if priority < pluginPipelineCorePriority {
			return kernelPluginPipelineStagePreForward, true, nil
		}
		if priority > pluginPipelineCorePriority {
			return kernelPluginPipelineStagePostLookup, true, nil
		}
		return "", true, fmt.Errorf("stage=forward priority=%d collides with Veer Core priority %d; use a lower priority for pre-core hooks or a higher priority for next-core hooks", priority, pluginPipelineCorePriority)
	case kernelPluginPipelineStageReply:
		if priority < pluginPipelineCorePriority {
			return kernelPluginPipelineStagePreReply, true, nil
		}
		if priority > pluginPipelineCorePriority {
			return kernelPluginPipelineStagePostReply, true, nil
		}
		return "", true, fmt.Errorf("stage=reply priority=%d collides with Veer Reply Core priority %d; use a lower priority for pre-core hooks or a higher priority for next-core hooks", priority, pluginPipelineCorePriority)
	default:
		return "", false, nil
	}
}

func kernelPluginPipelineStageRank(stage string) int {
	switch stage {
	case kernelPluginPipelineStagePreForward:
		return 0
	case kernelPluginPipelineStagePostLookup:
		return 1
	case kernelPluginPipelineStagePreReply:
		return 2
	case kernelPluginPipelineStagePostReply:
		return 3
	default:
		return 99
	}
}

func effectiveKernelPluginPipelineHookContext(values []string, stage string) ([]string, error) {
	seen := make(map[string]struct{}, len(values)+1)
	out := make([]string, 0, len(values)+1)
	add := func(value string) {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, value := range values {
		if !validPluginHookContext(value) {
			return nil, fmt.Errorf("unsupported context %q", value)
		}
		add(value)
	}
	if stage == kernelPluginPipelineStagePostLookup || stage == kernelPluginPipelineStagePostReply {
		add(pluginHookContextTCPluginCtxV4)
	} else if _, ok := seen[pluginHookContextTCPluginCtxV4]; ok {
		return nil, fmt.Errorf("context %q is only available after Veer Core lookup", pluginHookContextTCPluginCtxV4)
	}
	sort.Strings(out)
	return out, nil
}

func kernelPluginPipelineHookNeedsContext(plan kernelPluginPipelineHookPlan, contextName string) bool {
	for _, item := range plan.Context {
		if item == contextName {
			return true
		}
	}
	return false
}

func kernelPluginPipelineObjectCacheKey(objectPath string, needsPluginCtx bool) string {
	if needsPluginCtx {
		return objectPath + "\x00" + pluginHookContextTCPluginCtxV4
	}
	return objectPath + "\x00"
}

func kernelPluginPipelineLess(a, b kernelPluginPipelineHookPlan) bool {
	if ar, br := kernelPluginPipelineStageRank(a.Stage), kernelPluginPipelineStageRank(b.Stage); ar != br {
		return ar < br
	}
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	if a.PluginID != b.PluginID {
		return a.PluginID < b.PluginID
	}
	return a.HookID < b.HookID
}

func buildKernelPluginPipelineDesired(catalog PluginCatalog) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState) {
	return buildKernelPluginPipelineDesiredWithConfig(catalog, nil, false)
}

func buildKernelPluginPipelineDesiredForRuntime(catalog PluginCatalog, cfg *Config) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState) {
	return buildKernelPluginPipelineDesiredWithConfig(catalog, cfg, true)
}

func buildKernelPluginPipelineDesiredWithConfig(catalog PluginCatalog, cfg *Config, enforceStability bool) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState) {
	states := make(map[string]PluginRuntimeState)
	desired := make([]kernelPluginPipelineDesiredPlugin, 0, len(catalog.Plugins))
	preForwardHooks := 0
	postLookupHooks := 0
	preReplyHooks := 0
	postReplyHooks := 0
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if enforceStability {
			if ok, reason := pluginDataplaneStabilityAllowed(plugin, cfg); !ok {
				state := externalPluginRuntimeState()
				state.Reason = reason
				states[plugin.ID] = state
				continue
			}
		}
		item, state := buildKernelPluginPipelineDesiredPlugin(plugin)
		if len(item.hooks) == 0 || state.Error != "" {
			states[plugin.ID] = state
			continue
		}
		for _, hook := range item.hooks {
			switch hook.Stage {
			case kernelPluginPipelineStagePreForward:
				preForwardHooks++
			case kernelPluginPipelineStagePostLookup:
				postLookupHooks++
			case kernelPluginPipelineStagePreReply:
				preReplyHooks++
			case kernelPluginPipelineStagePostReply:
				postReplyHooks++
			}
		}
		desired = append(desired, item)
	}
	if preForwardHooks > tcProgramChainV4PluginPreForwardMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many pre-core tc plugin hooks: %d > %d", preForwardHooks, tcProgramChainV4PluginPreForwardMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	if postLookupHooks > tcProgramChainV4PluginPostLookupMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many next-core tc plugin hooks: %d > %d", postLookupHooks, tcProgramChainV4PluginPostLookupMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	if preReplyHooks > tcProgramChainV4PluginPreReplyMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many pre-reply tc plugin hooks: %d > %d", preReplyHooks, tcProgramChainV4PluginPreReplyMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	if postReplyHooks > tcProgramChainV4PluginPostReplyMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many post-reply tc plugin hooks: %d > %d", postReplyHooks, tcProgramChainV4PluginPostReplyMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	if preForwardHooks+postLookupHooks > tcProgramChainV4PluginTotalMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many total tc plugin hooks: %d > %d", preForwardHooks+postLookupHooks, tcProgramChainV4PluginTotalMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	if preReplyHooks+postReplyHooks > tcProgramChainV4PluginReplyTotalMax {
		errState := pluginRuntimeErrorState(fmt.Sprintf("too many total reply tc plugin hooks: %d > %d", preReplyHooks+postReplyHooks, tcProgramChainV4PluginReplyTotalMax))
		for _, item := range desired {
			states[item.plugin.ID] = errState
		}
		return nil, states
	}
	sort.Slice(desired, func(i, j int) bool {
		a := desired[i].hooks[0]
		b := desired[j].hooks[0]
		return kernelPluginPipelineLess(a, b)
	})
	return desired, states
}

func kernelPluginPipelineCatalogHasRuntimeHooks(catalog PluginCatalog, cfg *Config) bool {
	if cfg == nil || !cfg.PluginsEnabled() || !cfg.PluginsDataplaneEnabled() {
		return false
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if ok, _ := pluginDataplaneStabilityAllowed(plugin, cfg); !ok {
			continue
		}
		for _, hook := range plugin.Hooks {
			stage, supported, err := kernelPluginPipelineNormalizeStage(hook.Stage, hook.Priority)
			if hook.Engine == kernelEngineTC &&
				supported &&
				err == nil &&
				stage != "" &&
				hook.Attach != "none" &&
				hook.Mode != "control" {
				return true
			}
		}
	}
	return false
}

func buildKernelPluginPipelineDesiredPlugin(plugin LoadedPlugin) (kernelPluginPipelineDesiredPlugin, PluginRuntimeState) {
	item := kernelPluginPipelineDesiredPlugin{plugin: plugin}
	objects := make(map[string]PluginObject, len(plugin.Objects)*2)
	for _, object := range plugin.Objects {
		if object.Status != pluginObjectStatusVerified {
			continue
		}
		objects[object.ID] = object
		objects[object.Path] = object
	}
	for _, hook := range plugin.Hooks {
		if hook.Engine == "control" {
			continue
		}
		if hook.Engine != kernelEngineTC {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: %s hooks are registration-only in the tc pipeline", hook.ID, hook.Engine))
			continue
		}
		stage, supported, err := kernelPluginPipelineNormalizeStage(hook.Stage, hook.Priority)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: %v", hook.ID, err))
		}
		if !supported {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: use stage=forward or stage=reply with priority below or above Veer Core priority %d", hook.ID, pluginPipelineCorePriority))
			continue
		}
		context, err := effectiveKernelPluginPipelineHookContext(hook.Context, stage)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: %v", hook.ID, err))
		}
		if hook.Attach == "none" {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: attach=none is not on the Veer tc pipeline", hook.ID))
			continue
		}
		if hook.Mode == "control" {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: control mode cannot run in the tc pipeline", hook.ID))
			continue
		}
		objectRef, programRef, ok := parsePluginProgramRef(hook.Program)
		if !ok {
			return item, pluginRuntimeErrorState("program must use object:program for tc pipeline hooks")
		}
		object, ok := objects[objectRef]
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing object %q", hook.ID, objectRef))
		}
		program, ok := pluginObjectProgramByRef(object, programRef)
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing program %q in object %q", hook.ID, programRef, objectRef))
		}
		if program.Type != kernelEngineTC {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s program %q type = %q, want tc", hook.ID, programRef, program.Type))
		}
		realPath, err := resolvePluginObjectRealPath(&plugin, object)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s object path: %v", hook.ID, err))
		}
		attach := hook.Attach
		if attach == "" {
			attach = "ingress"
		}
		item.hooks = append(item.hooks, kernelPluginPipelineHookPlan{
			PluginID:       plugin.ID,
			HookID:         hook.ID,
			ObjectID:       object.ID,
			ObjectPath:     realPath,
			ObjectSHA256:   object.ResolvedSHA256,
			ProgramRef:     programRef,
			ProgramSection: program.Section,
			Stage:          stage,
			Attach:         attach,
			Mode:           hook.Mode,
			Context:        context,
			Interfaces:     append([]string(nil), hook.Interfaces...),
			Priority:       hook.Priority,
		})
	}
	if len(item.hooks) == 0 {
		state := externalPluginRuntimeState()
		state.Reason = fmt.Sprintf("no supported tc pipeline hook is declared; use stage=forward or stage=reply with priority below or above Veer Core priority %d", pluginPipelineCorePriority)
		if len(item.warnings) > 0 {
			state.Reason += ": " + strings.Join(item.warnings, "; ")
		}
		return item, state
	}
	sort.Slice(item.hooks, func(i, j int) bool {
		a := item.hooks[i]
		b := item.hooks[j]
		return kernelPluginPipelineLess(a, b)
	})
	return item, PluginRuntimeState{}
}

func (rt *linuxKernelRuleRuntime) loadKernelPluginPipelinePrograms(desired []kernelPluginPipelineDesiredPlugin, pieces kernelCollectionPieces) ([]loadedPluginObjectRef, []loadedKernelPluginPipelineProgram, map[string]PluginRuntimeState, error) {
	states := make(map[string]PluginRuntimeState)
	if len(desired) == 0 {
		return nil, nil, states, nil
	}
	_ = rt.ensureMemlock()

	objectCache := make(map[string]*loadedPluginObject)
	objectNeedsContext := kernelPluginPipelineObjectContextNeeds(desired)
	failedPlugins := make(map[string]string)
	programs := make([]loadedKernelPluginPipelineProgram, 0, len(desired))
	for _, item := range desired {
		for _, plan := range item.hooks {
			needsPluginCtx := objectNeedsContext[plan.ObjectPath]
			previous := reusableKernelPluginPipelineObject(rt.pluginPipelineLoaded, plan)
			object, err := loadPluginObjectForPipeline(objectCache, plan.ObjectPath, plan.ObjectSHA256, pieces, needsPluginCtx, previous)
			if err != nil {
				failedPlugins[plan.PluginID] = err.Error()
				break
			}
			prog, err := pluginProgramForAttach(object, plan.ProgramSection, plan.ProgramRef)
			if err != nil {
				failedPlugins[plan.PluginID] = err.Error()
				break
			}
			programs = append(programs, loadedKernelPluginPipelineProgram{plan: plan, prog: prog})
		}
	}
	sort.SliceStable(programs, func(i, j int) bool {
		return kernelPluginPipelineLess(programs[i].plan, programs[j].plan)
	})

	if len(failedPlugins) > 0 {
		filtered := programs[:0]
		for _, item := range programs {
			if _, failed := failedPlugins[item.plan.PluginID]; failed {
				continue
			}
			filtered = append(filtered, item)
		}
		programs = filtered
		for pluginID, message := range failedPlugins {
			states[pluginID] = pluginRuntimeErrorState(message)
		}
	}

	countByPlugin := make(map[string]int)
	attachmentsByPlugin := make(map[string][]PluginAttachmentState)
	preForwardIndex := 0
	postLookupIndex := 0
	preReplyIndex := 0
	postReplyIndex := 0
	for _, item := range programs {
		slot := 0
		switch item.plan.Stage {
		case kernelPluginPipelineStagePreForward:
			slot = tcProgramChainIndexV4PluginBase + preForwardIndex
			preForwardIndex++
		case kernelPluginPipelineStagePostLookup:
			slot = tcProgramChainIndexV4PluginPostBase + postLookupIndex
			postLookupIndex++
		case kernelPluginPipelineStagePreReply:
			slot = tcProgramChainIndexV4PluginReplyBase + preReplyIndex
			preReplyIndex++
		case kernelPluginPipelineStagePostReply:
			slot = tcProgramChainIndexV4PluginReplyPostBase + postReplyIndex
			postReplyIndex++
		}
		countByPlugin[item.plan.PluginID]++
		attachmentsByPlugin[item.plan.PluginID] = append(attachmentsByPlugin[item.plan.PluginID], PluginAttachmentState{
			HookID:    item.plan.HookID,
			Engine:    kernelEngineTC,
			Attach:    item.plan.Attach,
			Stage:     item.plan.Stage,
			Interface: kernelPluginPipelineInterface,
			Program:   item.plan.ObjectID + ":" + item.plan.ProgramRef,
			Mode:      item.plan.Mode,
			Context:   append([]string(nil), item.plan.Context...),
			Priority:  item.plan.Priority,
			ChainSlot: slot,
			Status:    "chained",
		})
	}
	for _, item := range desired {
		if _, failed := failedPlugins[item.plugin.ID]; failed {
			continue
		}
		count := countByPlugin[item.plugin.ID]
		if count == 0 {
			continue
		}
		reason := strings.Join(item.warnings, "; ")
		states[item.plugin.ID] = PluginRuntimeState{
			Mode:            pluginRuntimeModeDataplane,
			Attachable:      true,
			Attached:        true,
			AttachmentCount: count,
			Attachments:     sortedPluginAttachmentStates(attachmentsByPlugin[item.plugin.ID]),
			Reason:          reason,
		}
	}

	refs := make([]loadedPluginObjectRef, 0, len(objectCache))
	for _, item := range programs {
		object, ok := objectCache[kernelPluginPipelineObjectCacheKey(item.plan.ObjectPath, objectNeedsContext[item.plan.ObjectPath])]
		if !ok || object == nil || object.coll == nil {
			continue
		}
		refs = append(refs, loadedPluginObjectRef{
			PluginID:     item.plan.PluginID,
			ObjectID:     item.plan.ObjectID,
			ObjectPath:   item.plan.ObjectPath,
			ObjectSHA256: item.plan.ObjectSHA256,
			spec:         object.spec,
			coll:         object.coll,
		})
	}
	refs = uniqueLoadedPluginObjectRefs(refs)
	cleanupUnusedPluginObjectCollections(objectCache, refs)
	if len(failedPlugins) > 0 {
		ids := make([]string, 0, len(failedPlugins))
		for id := range failedPlugins {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		failures := make([]string, 0, len(ids))
		for _, id := range ids {
			failures = append(failures, id+": "+failedPlugins[id])
		}
		return refs, programs, states, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return refs, programs, states, nil
}

func kernelPluginPipelineObjectContextNeeds(desired []kernelPluginPipelineDesiredPlugin) map[string]bool {
	out := make(map[string]bool)
	for _, item := range desired {
		for _, hook := range item.hooks {
			if kernelPluginPipelineHookNeedsContext(hook, pluginHookContextTCPluginCtxV4) {
				out[hook.ObjectPath] = true
			} else if _, ok := out[hook.ObjectPath]; !ok {
				out[hook.ObjectPath] = false
			}
		}
	}
	return out
}

func cleanupUnusedPluginObjectCollections(cache map[string]*loadedPluginObject, refs []loadedPluginObjectRef) {
	if len(cache) == 0 {
		return
	}
	used := make(map[*ebpf.Collection]struct{}, len(refs))
	for _, ref := range refs {
		if ref.coll != nil {
			used[ref.coll] = struct{}{}
		}
	}
	for _, object := range cache {
		if object == nil || object.coll == nil {
			continue
		}
		if _, ok := used[object.coll]; ok {
			continue
		}
		object.coll.Close()
		object.coll = nil
	}
}

func reusableKernelPluginPipelineObject(refs []loadedPluginObjectRef, plan kernelPluginPipelineHookPlan) *loadedPluginObjectRef {
	hash := strings.TrimSpace(strings.ToLower(plan.ObjectSHA256))
	if hash == "" {
		return nil
	}
	for i := range refs {
		ref := &refs[i]
		if ref.PluginID != plan.PluginID || ref.ObjectID != plan.ObjectID {
			continue
		}
		if strings.TrimSpace(strings.ToLower(ref.ObjectSHA256)) != hash || ref.coll == nil {
			continue
		}
		return ref
	}
	return nil
}

func pluginPipelineMapReplacements(spec *ebpf.CollectionSpec, shared map[string]*ebpf.Map, previous *loadedPluginObjectRef) (map[string]*ebpf.Map, error) {
	replacements := make(map[string]*ebpf.Map, len(shared))
	for name, m := range shared {
		replacements[name] = m
	}
	if previous == nil || previous.coll == nil {
		return replacements, nil
	}

	names := make([]string, 0, len(previous.coll.Maps))
	for name := range previous.coll.Maps {
		if _, hostOwned := replacements[name]; hostOwned {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		oldMap := previous.coll.Maps[name]
		nextSpec := spec.Maps[name]
		if oldMap == nil || nextSpec == nil {
			return nil, fmt.Errorf("preserve plugin map %q: map is missing from the unchanged object", name)
		}
		if err := nextSpec.Compatible(oldMap); err != nil {
			return nil, fmt.Errorf("preserve plugin map %q: %w", name, err)
		}
		replacements[name] = oldMap
	}
	return replacements, nil
}

func loadPluginObjectForPipeline(cache map[string]*loadedPluginObject, objectPath, expectedSHA256 string, pieces kernelCollectionPieces, needsPluginCtx bool, previous *loadedPluginObjectRef) (*loadedPluginObject, error) {
	if pieces.progChainV4 == nil {
		return nil, fmt.Errorf("tc program chain map is unavailable")
	}
	cacheKey := kernelPluginPipelineObjectCacheKey(objectPath, needsPluginCtx)
	if object, ok := cache[cacheKey]; ok {
		if needsPluginCtx && object.spec.Maps[kernelTCPluginContextMapName] == nil {
			return nil, fmt.Errorf("plugin object %s must declare shared map %q for context-aware pipeline hooks", objectPath, kernelTCPluginContextMapName)
		}
		return object, nil
	}
	spec, err := loadVerifiedPluginObjectCollectionSpec(objectPath, expectedSHA256)
	if err != nil {
		return nil, fmt.Errorf("load plugin object spec %s: %w", objectPath, err)
	}
	if spec.Maps[kernelTCProgramChainMapName] == nil {
		return nil, fmt.Errorf("plugin object %s must declare shared map %q for Veer pipeline chaining", objectPath, kernelTCProgramChainMapName)
	}
	if needsPluginCtx && spec.Maps[kernelTCPluginContextMapName] == nil {
		return nil, fmt.Errorf("plugin object %s must declare shared map %q for context-aware pipeline hooks", objectPath, kernelTCPluginContextMapName)
	}
	sharedMaps := map[string]*ebpf.Map{
		kernelTCProgramChainMapName: pieces.progChainV4,
	}
	if needsPluginCtx {
		if pieces.pluginCtxV4 == nil {
			return nil, fmt.Errorf("tc plugin context map is unavailable")
		}
		sharedMaps[kernelTCPluginContextMapName] = pieces.pluginCtxV4
	}
	replacements, err := pluginPipelineMapReplacements(spec, sharedMaps, previous)
	if err != nil {
		return nil, fmt.Errorf("load plugin object %s: %w", objectPath, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(replacements))
	if err != nil {
		logKernelVerifierDetails(err)
		return nil, fmt.Errorf("load plugin object %s: %w", objectPath, err)
	}
	object := &loadedPluginObject{path: objectPath, spec: spec, coll: coll}
	cache[cacheKey] = object
	return object, nil
}

func installKernelPluginPipelinePrograms(pieces kernelCollectionPieces, programs []loadedKernelPluginPipelineProgram, core kernelPluginPipelineCoreConfig) (uint32, error) {
	preForward := make([]loadedKernelPluginPipelineProgram, 0, len(programs))
	postLookup := make([]loadedKernelPluginPipelineProgram, 0, len(programs))
	preReply := make([]loadedKernelPluginPipelineProgram, 0, len(programs))
	postReply := make([]loadedKernelPluginPipelineProgram, 0, len(programs))
	for _, item := range programs {
		switch item.plan.Stage {
		case kernelPluginPipelineStagePreForward:
			preForward = append(preForward, item)
		case kernelPluginPipelineStagePostLookup:
			postLookup = append(postLookup, item)
		case kernelPluginPipelineStagePreReply:
			preReply = append(preReply, item)
		case kernelPluginPipelineStagePostReply:
			postReply = append(postReply, item)
		default:
			return 0, fmt.Errorf("unsupported plugin stage %q", item.plan.Stage)
		}
	}
	if len(preForward) > tcProgramChainV4PluginPreForwardMax {
		return 0, fmt.Errorf("too many pre_forward plugin programs: %d > %d", len(preForward), tcProgramChainV4PluginPreForwardMax)
	}
	if len(postLookup) > tcProgramChainV4PluginPostLookupMax {
		return 0, fmt.Errorf("too many post_lookup plugin programs: %d > %d", len(postLookup), tcProgramChainV4PluginPostLookupMax)
	}
	if len(preForward)+len(postLookup) > tcProgramChainV4PluginTotalMax {
		return 0, fmt.Errorf("too many total plugin programs: %d > %d", len(preForward)+len(postLookup), tcProgramChainV4PluginTotalMax)
	}
	if len(preReply) > tcProgramChainV4PluginPreReplyMax {
		return 0, fmt.Errorf("too many pre_reply plugin programs: %d > %d", len(preReply), tcProgramChainV4PluginPreReplyMax)
	}
	if len(postReply) > tcProgramChainV4PluginPostReplyMax {
		return 0, fmt.Errorf("too many post_reply plugin programs: %d > %d", len(postReply), tcProgramChainV4PluginPostReplyMax)
	}
	if len(preReply)+len(postReply) > tcProgramChainV4PluginReplyTotalMax {
		return 0, fmt.Errorf("too many total reply plugin programs: %d > %d", len(preReply)+len(postReply), tcProgramChainV4PluginReplyTotalMax)
	}
	if pieces.progChainV4 == nil || pieces.pluginConfigV4 == nil || pieces.pluginInterfacesV4 == nil {
		return 0, fmt.Errorf("tc plugin pipeline maps are incomplete")
	}

	var current kernelTCPluginConfigV4
	if err := pieces.pluginConfigV4.Lookup(uint32(0), &current); err != nil {
		return 0, fmt.Errorf("lookup tc plugin config: %w", err)
	}
	inactiveBank := (current.ActiveBank & 1) ^ 1
	masks, err := buildKernelPluginPipelineInterfaceMasks(programs)
	if err != nil {
		return 0, err
	}
	if err := clearKernelPluginPipelineInterfaceBank(pieces.pluginInterfacesV4, inactiveBank); err != nil {
		return 0, err
	}

	installStage := func(items []loadedKernelPluginPipelineProgram, stage string, max int) error {
		base, err := kernelPluginPipelineBankStageBase(inactiveBank, stage)
		if err != nil {
			return err
		}
		for i, item := range items {
			if item.prog == nil {
				return fmt.Errorf("%s plugin program at index %d is nil", stage, i)
			}
			slot := uint32(base + i)
			if err := pieces.progChainV4.Put(slot, uint32(item.prog.FD())); err != nil {
				return fmt.Errorf("install plugin %s hook %s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
			}
		}
		for i := len(items); i < max; i++ {
			if err := deleteKernelMapEntry(pieces.progChainV4, uint32(base+i)); err != nil {
				return fmt.Errorf("clear stale %s plugin slot %d: %w", stage, base+i, err)
			}
		}
		return nil
	}
	if err := installStage(preForward, kernelPluginPipelineStagePreForward, tcProgramChainV4PluginPreForwardMax); err != nil {
		return 0, err
	}
	if err := installStage(postLookup, kernelPluginPipelineStagePostLookup, tcProgramChainV4PluginPostLookupMax); err != nil {
		return 0, err
	}
	if err := installStage(preReply, kernelPluginPipelineStagePreReply, tcProgramChainV4PluginPreReplyMax); err != nil {
		return 0, err
	}
	if err := installStage(postReply, kernelPluginPipelineStagePostReply, tcProgramChainV4PluginPostReplyMax); err != nil {
		return 0, err
	}
	for scope, value := range masks.byInterface {
		key := kernelTCPluginInterfaceKeyV4{IfIndex: scope.IfIndex, Bank: inactiveBank, Attach: scope.Attach}
		if err := pieces.pluginInterfacesV4.Put(key, value); err != nil {
			return 0, fmt.Errorf("sync tc plugin interface %d attach %d bank %d: %w", scope.IfIndex, scope.Attach, inactiveBank, err)
		}
	}
	ingressGlobal := masks.globalByAttach[kernelPluginPipelineAttachIngress]
	egressGlobal := masks.globalByAttach[kernelPluginPipelineAttachEgress]
	next := kernelTCPluginConfigV4{
		PreForwardCount:            uint32(len(preForward)),
		PostLookupCount:            uint32(len(postLookup)),
		PreReplyCount:              uint32(len(preReply)),
		PostReplyCount:             uint32(len(postReply)),
		ForwardCoreEnable:          boolToKernelPluginConfigFlag(core.Forward),
		ReplyCoreEnable:            boolToKernelPluginConfigFlag(core.Reply),
		ActiveBank:                 inactiveBank,
		PreForwardGlobalMask:       ingressGlobal.PreForwardMask,
		PostLookupGlobalMask:       ingressGlobal.PostLookupMask,
		PreReplyGlobalMask:         ingressGlobal.PreReplyMask,
		PostReplyGlobalMask:        ingressGlobal.PostReplyMask,
		EgressPreForwardGlobalMask: egressGlobal.PreForwardMask,
		EgressPostLookupGlobalMask: egressGlobal.PostLookupMask,
		EgressPreReplyGlobalMask:   egressGlobal.PreReplyMask,
		EgressPostReplyGlobalMask:  egressGlobal.PostReplyMask,
	}
	if err := syncKernelPluginConfigV4(pieces.pluginConfigV4, next); err != nil {
		return 0, err
	}
	return inactiveBank, nil
}

func buildKernelPluginPipelineInterfaceMasks(programs []loadedKernelPluginPipelineProgram) (kernelPluginPipelineInterfaceMasks, error) {
	result := kernelPluginPipelineInterfaceMasks{
		globalByAttach: make(map[uint32]kernelTCPluginInterfaceValueV4, 2),
		byInterface:    make(map[kernelPluginPipelineInterfaceScope]kernelTCPluginInterfaceValueV4),
	}
	stageIndexes := make(map[string]uint32, 4)
	for _, item := range programs {
		index := stageIndexes[item.plan.Stage]
		if index >= 32 {
			return result, fmt.Errorf("plugin stage %s exceeds interface mask width", item.plan.Stage)
		}
		stageIndexes[item.plan.Stage] = index + 1
		bit := uint32(1) << index
		if len(item.plan.Interfaces) > 0 && len(item.plan.InterfaceIndexes) == 0 {
			return result, fmt.Errorf("plugin %s hook %s has unresolved interfaces", item.plan.PluginID, item.plan.HookID)
		}
		for _, attach := range kernelPluginPipelinePlanAttachDirections(item.plan.Attach) {
			if len(item.plan.InterfaceIndexes) == 0 {
				value := result.globalByAttach[attach]
				setKernelPluginPipelineStageMask(&value, item.plan.Stage, bit)
				result.globalByAttach[attach] = value
				continue
			}
			for _, ifindex := range item.plan.InterfaceIndexes {
				if ifindex == 0 {
					return result, fmt.Errorf("plugin %s hook %s resolved invalid ifindex 0", item.plan.PluginID, item.plan.HookID)
				}
				scope := kernelPluginPipelineInterfaceScope{IfIndex: ifindex, Attach: attach}
				value := result.byInterface[scope]
				setKernelPluginPipelineStageMask(&value, item.plan.Stage, bit)
				result.byInterface[scope] = value
			}
		}
	}
	return result, nil
}

func kernelPluginPipelinePlanAttachDirections(attach string) []uint32 {
	switch attach {
	case "egress":
		return []uint32{kernelPluginPipelineAttachEgress}
	case "both":
		return []uint32{kernelPluginPipelineAttachIngress, kernelPluginPipelineAttachEgress}
	default:
		return []uint32{kernelPluginPipelineAttachIngress}
	}
}

func setKernelPluginPipelineStageMask(value *kernelTCPluginInterfaceValueV4, stage string, bit uint32) {
	switch stage {
	case kernelPluginPipelineStagePreForward:
		value.PreForwardMask |= bit
	case kernelPluginPipelineStagePostLookup:
		value.PostLookupMask |= bit
	case kernelPluginPipelineStagePreReply:
		value.PreReplyMask |= bit
	case kernelPluginPipelineStagePostReply:
		value.PostReplyMask |= bit
	}
}

func kernelPluginPipelineBankStageBase(bank uint32, stage string) (int, error) {
	if bank&1 == 0 {
		switch stage {
		case kernelPluginPipelineStagePreForward:
			return tcProgramChainIndexV4PluginBase, nil
		case kernelPluginPipelineStagePostLookup:
			return tcProgramChainIndexV4PluginPostBase, nil
		case kernelPluginPipelineStagePreReply:
			return tcProgramChainIndexV4PluginReplyBase, nil
		case kernelPluginPipelineStagePostReply:
			return tcProgramChainIndexV4PluginReplyPostBase, nil
		}
	} else {
		switch stage {
		case kernelPluginPipelineStagePreForward:
			return tcProgramChainIndexV4PluginBank1Base, nil
		case kernelPluginPipelineStagePostLookup:
			return tcProgramChainIndexV4PluginBank1PostBase, nil
		case kernelPluginPipelineStagePreReply:
			return tcProgramChainIndexV4PluginBank1ReplyBase, nil
		case kernelPluginPipelineStagePostReply:
			return tcProgramChainIndexV4PluginBank1ReplyPostBase, nil
		}
	}
	return 0, fmt.Errorf("unsupported plugin stage %q", stage)
}

func clearKernelPluginPipelineInterfaceBank(m *ebpf.Map, bank uint32) error {
	if m == nil {
		return fmt.Errorf("tc plugin interface map is nil")
	}
	keys := make([]kernelTCPluginInterfaceKeyV4, 0)
	iterator := m.Iterate()
	var key kernelTCPluginInterfaceKeyV4
	var value kernelTCPluginInterfaceValueV4
	for iterator.Next(&key, &value) {
		if key.Bank&1 == bank&1 {
			keys = append(keys, key)
		}
	}
	if err := iterator.Err(); err != nil {
		return fmt.Errorf("iterate tc plugin interfaces: %w", err)
	}
	for _, key := range keys {
		if err := deleteKernelMapEntry(m, key); err != nil {
			return fmt.Errorf("delete tc plugin interface %d bank %d: %w", key.IfIndex, key.Bank, err)
		}
	}
	return nil
}

func clearKernelPluginPipelineBank(pieces kernelCollectionPieces, bank uint32) error {
	errs := make([]string, 0)
	if pieces.progChainV4 == nil {
		errs = append(errs, "tc program chain map is nil")
	} else {
		for _, stage := range []struct {
			name  string
			count int
		}{
			{name: kernelPluginPipelineStagePreForward, count: tcProgramChainV4PluginPreForwardMax},
			{name: kernelPluginPipelineStagePostLookup, count: tcProgramChainV4PluginPostLookupMax},
			{name: kernelPluginPipelineStagePreReply, count: tcProgramChainV4PluginPreReplyMax},
			{name: kernelPluginPipelineStagePostReply, count: tcProgramChainV4PluginPostReplyMax},
		} {
			base, _ := kernelPluginPipelineBankStageBase(bank, stage.name)
			for i := 0; i < stage.count; i++ {
				if err := deleteKernelMapEntry(pieces.progChainV4, uint32(base+i)); err != nil {
					errs = append(errs, fmt.Sprintf("delete tc plugin chain slot %d: %v", base+i, err))
				}
			}
		}
	}
	if pieces.pluginInterfacesV4 != nil {
		if err := clearKernelPluginPipelineInterfaceBank(pieces.pluginInterfacesV4, bank); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func clearKernelPluginPipelinePrograms(pieces kernelCollectionPieces) error {
	errs := make([]string, 0)
	current := kernelTCPluginConfigV4{}
	hadActiveChain := false
	if pieces.pluginConfigV4 != nil {
		if err := pieces.pluginConfigV4.Lookup(uint32(0), &current); err != nil {
			errs = append(errs, fmt.Sprintf("lookup tc plugin config: %v", err))
		} else {
			hadActiveChain = current.PreForwardCount > 0 || current.PostLookupCount > 0 || current.PreReplyCount > 0 || current.PostReplyCount > 0
		}
	}
	empty := kernelTCPluginConfigV4{ActiveBank: (current.ActiveBank & 1) ^ 1}
	if err := syncKernelPluginConfigV4(pieces.pluginConfigV4, empty); err != nil {
		errs = append(errs, err.Error())
	}
	if hadActiveChain {
		time.Sleep(kernelPluginPipelineUpdateGrace)
	}
	for bank := uint32(0); bank < 2; bank++ {
		if err := clearKernelPluginPipelineBank(pieces, bank); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func syncKernelPluginConfigV4(m *ebpf.Map, value kernelTCPluginConfigV4) error {
	if m == nil {
		if value == (kernelTCPluginConfigV4{}) {
			return nil
		}
		return fmt.Errorf("tc plugin config map is nil")
	}
	key := uint32(0)
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("sync tc plugin config: %w", err)
	}
	return nil
}

func (rt *linuxKernelRuleRuntime) clearPluginPipelineProgramsFromCollectionLocked() error {
	if rt == nil || rt.coll == nil {
		return nil
	}
	pieces, err := lookupKernelCollectionPieces(rt.coll)
	if err != nil {
		return err
	}
	return clearKernelPluginPipelinePrograms(pieces)
}

func (rt *linuxKernelRuleRuntime) cleanupIdlePluginPipelineRuntimeLocked(reason string) bool {
	if rt == nil || rt.coll == nil || len(rt.preparedRules) > 0 {
		return false
	}
	refs := kernelRuntimeMapRefsFromCollection(rt.coll)
	flows, err := countKernelRuntimeFlowEntriesExact(refs)
	if err != nil {
		log.Printf("kernel plugin pipeline cleanup: preserve tc runtime after %s because flow count failed: %v", reason, err)
		return false
	}
	nat, err := countKernelRuntimeNATEntriesExact(refs)
	if err != nil {
		log.Printf("kernel plugin pipeline cleanup: preserve tc runtime after %s because nat count failed: %v", reason, err)
		return false
	}
	if flows > 0 || nat > 0 {
		log.Printf("kernel plugin pipeline cleanup: preserve tc runtime after %s with active flow/nat entries=%d/%d", reason, flows, nat)
		return false
	}
	rt.cleanupLocked()
	rt.stateLog.Logf("kernel plugin pipeline cleanup: detached idle tc runtime after %s", reason)
	return true
}

func (rt *linuxKernelRuleRuntime) cleanupPluginPipelineLocked() {
	cleanupKernelPluginPipelineCollections(rt.pluginPipelineLoaded)
	rt.pluginPipelineLoaded = nil
	rt.pluginPipelineDesired = nil
	rt.pluginPipelineFingerprint = ""
	rt.pluginPipelineProgChain = nil
	rt.pluginPipelineBankSwitchedAt = time.Time{}
	rt.pluginPipelineActive = false
	rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{}
}

func cleanupKernelPluginPipelineCollections(refs []loadedPluginObjectRef) {
	seen := make(map[*ebpf.Collection]struct{}, len(refs))
	for i := len(refs) - 1; i >= 0; i-- {
		coll := refs[i].coll
		if coll != nil {
			if _, ok := seen[coll]; ok {
				continue
			}
			seen[coll] = struct{}{}
			coll.Close()
		}
	}
}

func kernelPluginPipelineManifestOnlySnapshot(catalog PluginCatalog) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		states[plugin.ID] = externalPluginRuntimeState()
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func kernelPluginPipelineInactiveSnapshot(catalog PluginCatalog, states map[string]PluginRuntimeState) pluginRuntimeSnapshot {
	if len(states) == 0 {
		return kernelPluginPipelineManifestOnlySnapshot(catalog)
	}
	out := make(map[string]PluginRuntimeState, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if state, ok := states[plugin.ID]; ok {
			out[plugin.ID] = state
			continue
		}
		out[plugin.ID] = externalPluginRuntimeState()
	}
	return pluginRuntimeSnapshot{Plugins: out}
}

func kernelPluginPipelineUnavailableSnapshot(catalog PluginCatalog, reason string) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		state := pluginRuntimeErrorState(reason)
		state.Reason = "tc plugin pipeline is unavailable"
		states[plugin.ID] = state
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func kernelPluginPipelineErrorAll(catalog PluginCatalog, message string, states map[string]PluginRuntimeState) map[string]PluginRuntimeState {
	if states == nil {
		states = make(map[string]PluginRuntimeState)
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if _, exists := states[plugin.ID]; exists {
			continue
		}
		states[plugin.ID] = pluginRuntimeErrorState(message)
	}
	return states
}

func kernelPluginPipelineFingerprint(items []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState, core kernelPluginPipelineCoreConfig) string {
	type fingerprintHook struct {
		PluginID         string   `json:"plugin_id"`
		HookID           string   `json:"hook_id"`
		ObjectID         string   `json:"object_id"`
		ObjectPath       string   `json:"object_path"`
		ObjectSHA256     string   `json:"object_sha256,omitempty"`
		ProgramRef       string   `json:"program_ref"`
		ProgramSection   string   `json:"program_section"`
		Stage            string   `json:"stage"`
		Mode             string   `json:"mode"`
		Context          []string `json:"context,omitempty"`
		Interfaces       []string `json:"interfaces,omitempty"`
		InterfaceIndexes []uint32 `json:"interface_indexes,omitempty"`
		Priority         int      `json:"priority"`
	}
	type fingerprintState struct {
		ID     string `json:"id"`
		Mode   string `json:"mode"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	type fingerprintCore struct {
		Forward bool `json:"forward"`
		Reply   bool `json:"reply"`
	}
	payload := struct {
		Hooks  []fingerprintHook  `json:"hooks"`
		States []fingerprintState `json:"states,omitempty"`
		Core   fingerprintCore    `json:"core"`
	}{
		Core: fingerprintCore(core),
	}
	for _, item := range items {
		for _, hook := range item.hooks {
			interfaces := append([]string(nil), hook.Interfaces...)
			interfaceIndexes := append([]uint32(nil), hook.InterfaceIndexes...)
			sort.Strings(interfaces)
			sort.Slice(interfaceIndexes, func(i, j int) bool { return interfaceIndexes[i] < interfaceIndexes[j] })
			payload.Hooks = append(payload.Hooks, fingerprintHook{
				PluginID:         hook.PluginID,
				HookID:           hook.HookID,
				ObjectID:         hook.ObjectID,
				ObjectPath:       kernelPluginPipelineFingerprintObjectPath(hook),
				ObjectSHA256:     hook.ObjectSHA256,
				ProgramRef:       hook.ProgramRef,
				ProgramSection:   hook.ProgramSection,
				Stage:            hook.Stage,
				Mode:             hook.Mode,
				Context:          hook.Context,
				Interfaces:       interfaces,
				InterfaceIndexes: interfaceIndexes,
				Priority:         hook.Priority,
			})
		}
	}
	for id, state := range states {
		payload.States = append(payload.States, fingerprintState{ID: id, Mode: state.Mode, Reason: state.Reason, Error: state.Error})
	}
	sort.Slice(payload.Hooks, func(i, j int) bool {
		a := payload.Hooks[i]
		b := payload.Hooks[j]
		if ar, br := kernelPluginPipelineStageRank(a.Stage), kernelPluginPipelineStageRank(b.Stage); ar != br {
			return ar < br
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.PluginID != b.PluginID {
			return a.PluginID < b.PluginID
		}
		return a.HookID < b.HookID
	})
	sort.Slice(payload.States, func(i, j int) bool {
		return payload.States[i].ID < payload.States[j].ID
	})
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func kernelPluginPipelineFingerprintObjectPath(hook kernelPluginPipelineHookPlan) string {
	if strings.TrimSpace(hook.ObjectSHA256) != "" {
		return ""
	}
	return hook.ObjectPath
}
