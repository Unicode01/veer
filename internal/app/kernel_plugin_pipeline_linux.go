//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	kernelPluginPipelineInterface       = "fvtap"
	kernelPluginPipelineStageForward    = "forward"
	kernelPluginPipelineStageReply      = "reply"
	kernelPluginPipelineStagePreForward = "pre_forward"
	kernelPluginPipelineStagePostLookup = "post_lookup"
	kernelPluginPipelineStagePreReply   = "pre_reply"
	kernelPluginPipelineStagePostReply  = "post_reply"
)

type kernelTCPluginConfigV4 struct {
	PreForwardCount uint32
	PostLookupCount uint32
	PreReplyCount   uint32
	PostReplyCount  uint32
}

type kernelPluginPipelineDesiredPlugin struct {
	plugin   LoadedPlugin
	hooks    []kernelPluginPipelineHookPlan
	warnings []string
}

type kernelPluginPipelineHookPlan struct {
	PluginID       string
	HookID         string
	ObjectID       string
	ObjectPath     string
	ObjectSHA256   string
	ProgramRef     string
	ProgramSection string
	Stage          string
	Attach         string
	Mode           string
	Context        []string
	Interfaces     []string
	Priority       int
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
	desired, states := buildKernelPluginPipelineDesired(catalog)
	rt.mu.Lock()
	noPreparedRules := len(rt.preparedRules) == 0
	rt.mu.Unlock()
	if noPreparedRules {
		desired = kernelPluginPipelineFilterNoRulePlugins(desired)
	}
	desired, states, forwardIfRules, replyIfRules := kernelPluginPipelineResolveExplicitAttachRuleSets(desired, states)
	if rt.pluginPipelineEnabled &&
		kernelPluginPipelineDesiredHasHooks(desired) &&
		kernelPluginPipelineHasAttachmentTargets(forwardIfRules, replyIfRules) {
		catalogForReconcile := catalog
		_, _ = rt.reconcileWithPluginCatalog(nil, &catalogForReconcile)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	rt.pluginPipelineActive = rt.pluginPipelineEnabled && kernelPluginPipelineDesiredHasHooks(desired)
	if !rt.pluginPipelineActive {
		rt.cleanupPluginPipelineLocked()
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
		rt.cleanupPluginPipelineLocked()
		rt.pluginRuntimeSnapshot = kernelPluginPipelineUnavailableSnapshot(catalog, err.Error())
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	return rt.reconcilePluginPipelineLocked(catalog, pieces, desired, states)
}

func (rt *linuxKernelRuleRuntime) reconcilePluginPipelineFromCatalogLocked(catalog PluginCatalog, pieces kernelCollectionPieces) pluginRuntimeSnapshot {
	desired, states := buildKernelPluginPipelineDesired(catalog)
	return rt.reconcilePluginPipelineLocked(catalog, pieces, desired, states)
}

func (rt *linuxKernelRuleRuntime) reconcilePluginPipelineLocked(catalog PluginCatalog, pieces kernelCollectionPieces, desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) pluginRuntimeSnapshot {
	rt.pluginPipelineActive = rt.pluginPipelineEnabled && kernelPluginPipelineDesiredHasHooks(desired)
	if !rt.pluginPipelineActive {
		_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
		rt.cleanupPluginPipelineLocked()
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

	fingerprint := kernelPluginPipelineFingerprint(desired, states)
	if fingerprint == rt.pluginPipelineFingerprint && rt.pluginPipelineProgChain == pieces.progChainV4 && len(rt.pluginPipelineLoaded) > 0 {
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}

	loaded, programs, loadStates := rt.loadKernelPluginPipelinePrograms(desired, pieces)
	for id, state := range loadStates {
		states[id] = state
	}
	if len(programs) == 0 {
		cleanupKernelPluginPipelineCollections(loaded)
		_ = installKernelPluginPipelinePrograms(pieces, nil)
		oldLoaded := rt.pluginPipelineLoaded
		rt.pluginPipelineLoaded = nil
		rt.pluginPipelineFingerprint = ""
		rt.pluginPipelineProgChain = pieces.progChainV4
		rt.pluginPipelineActive = false
		rt.pluginRuntimeSnapshot = kernelPluginPipelineInactiveSnapshot(catalog, states)
		cleanupKernelPluginPipelineCollections(oldLoaded)
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}
	if err := installKernelPluginPipelinePrograms(pieces, programs); err != nil {
		cleanupKernelPluginPipelineCollections(loaded)
		_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
		rt.cleanupPluginPipelineLocked()
		states = kernelPluginPipelineErrorAll(catalog, fmt.Sprintf("install plugin pipeline: %v", err), states)
		rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{Plugins: states}
		rt.pluginPipelineFingerprint = ""
		rt.pluginPipelineProgChain = pieces.progChainV4
		return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
	}

	oldLoaded := rt.pluginPipelineLoaded
	rt.pluginPipelineLoaded = loaded
	rt.pluginPipelineFingerprint = fingerprint
	rt.pluginPipelineProgChain = pieces.progChainV4
	rt.pluginRuntimeSnapshot = pluginRuntimeSnapshot{Plugins: states}
	cleanupKernelPluginPipelineCollections(oldLoaded)
	return clonePluginRuntimeSnapshot(rt.pluginRuntimeSnapshot)
}

func kernelPluginPipelineCatalogHasDesiredHooks(catalog PluginCatalog) bool {
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		for _, hook := range plugin.Hooks {
			_, supported, err := kernelPluginPipelineNormalizeStage(hook.Stage, hook.Priority)
			if hook.Engine == kernelEngineTC &&
				supported &&
				err == nil &&
				hook.Attach != "egress" &&
				hook.Attach != "none" &&
				hook.Mode != "control" {
				return true
			}
		}
	}
	return false
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
	case kernelPluginPipelineStagePreForward, kernelPluginPipelineStagePreReply:
		return true
	default:
		return false
	}
}

func kernelPluginPipelineResolveExplicitAttachRuleSets(desired []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) ([]kernelPluginPipelineDesiredPlugin, map[string]PluginRuntimeState, map[int][]int64, map[int][]int64) {
	if states == nil {
		states = make(map[string]PluginRuntimeState)
	}
	forwardIfRules := make(map[int][]int64)
	replyIfRules := make(map[int][]int64)
	if len(desired) == 0 {
		return nil, states, forwardIfRules, replyIfRules
	}

	filtered := make([]kernelPluginPipelineDesiredPlugin, 0, len(desired))
	for _, item := range desired {
		itemForwardIfRules := make(map[int][]int64)
		itemReplyIfRules := make(map[int][]int64)
		itemErr := ""
		for _, hook := range item.hooks {
			if len(hook.Interfaces) == 0 {
				continue
			}
			for _, name := range hook.Interfaces {
				iface, err := net.InterfaceByName(name)
				if err != nil {
					itemErr = fmt.Sprintf("hook %s interface %q: %v", hook.HookID, name, err)
					break
				}
				switch hook.Stage {
				case kernelPluginPipelineStagePreForward, kernelPluginPipelineStagePostLookup:
					itemForwardIfRules[iface.Index] = nil
				case kernelPluginPipelineStagePreReply, kernelPluginPipelineStagePostReply:
					itemReplyIfRules[iface.Index] = nil
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
		mergeKernelPluginPipelineAttachRuleSets(forwardIfRules, itemForwardIfRules)
		mergeKernelPluginPipelineAttachRuleSets(replyIfRules, itemReplyIfRules)
		filtered = append(filtered, item)
	}
	return filtered, states, forwardIfRules, replyIfRules
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
		return "", true, fmt.Errorf("stage=forward priority=%d collides with fvtap core priority %d; use a lower priority for pre-core hooks or a higher priority for next-core hooks", priority, pluginPipelineCorePriority)
	case kernelPluginPipelineStageReply:
		if priority < pluginPipelineCorePriority {
			return kernelPluginPipelineStagePreReply, true, nil
		}
		if priority > pluginPipelineCorePriority {
			return kernelPluginPipelineStagePostReply, true, nil
		}
		return "", true, fmt.Errorf("stage=reply priority=%d collides with fvtap reply core priority %d; use a lower priority for pre-core hooks or a higher priority for next-core hooks", priority, pluginPipelineCorePriority)
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
		return nil, fmt.Errorf("context %q is only available after fvtap core lookup", pluginHookContextTCPluginCtxV4)
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
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: %s hooks are manifest-only in the tc pipeline", hook.ID, hook.Engine))
			continue
		}
		stage, supported, err := kernelPluginPipelineNormalizeStage(hook.Stage, hook.Priority)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: %v", hook.ID, err))
		}
		if !supported {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: use stage=forward/reply with priority around fvtap core priority %d, or legacy stage=pre_forward/post_lookup/pre_reply/post_reply", hook.ID, pluginPipelineCorePriority))
			continue
		}
		context, err := effectiveKernelPluginPipelineHookContext(hook.Context, stage)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s: %v", hook.ID, err))
		}
		if hook.Attach == "egress" || hook.Attach == "none" {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: attach=%s is not on the fvtap tc ingress pipeline", hook.ID, hook.Attach))
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
		item.hooks = append(item.hooks, kernelPluginPipelineHookPlan{
			PluginID:       plugin.ID,
			HookID:         hook.ID,
			ObjectID:       object.ID,
			ObjectPath:     realPath,
			ObjectSHA256:   object.ResolvedSHA256,
			ProgramRef:     programRef,
			ProgramSection: program.Section,
			Stage:          stage,
			Attach:         "ingress",
			Mode:           hook.Mode,
			Context:        context,
			Interfaces:     append([]string(nil), hook.Interfaces...),
			Priority:       hook.Priority,
		})
	}
	if len(item.hooks) == 0 {
		state := externalPluginRuntimeState()
		state.Reason = fmt.Sprintf("no supported tc pipeline hook is declared; use stage=forward or stage=reply with priority below or above fvtap core priority %d", pluginPipelineCorePriority)
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

func (rt *linuxKernelRuleRuntime) loadKernelPluginPipelinePrograms(desired []kernelPluginPipelineDesiredPlugin, pieces kernelCollectionPieces) ([]loadedPluginObjectRef, []loadedKernelPluginPipelineProgram, map[string]PluginRuntimeState) {
	states := make(map[string]PluginRuntimeState)
	if len(desired) == 0 {
		return nil, nil, states
	}
	_ = rt.ensureMemlock()

	objectCache := make(map[string]*loadedPluginObject)
	objectNeedsContext := kernelPluginPipelineObjectContextNeeds(desired)
	failedPlugins := make(map[string]string)
	programs := make([]loadedKernelPluginPipelineProgram, 0, len(desired))
	for _, item := range desired {
		for _, plan := range item.hooks {
			needsPluginCtx := objectNeedsContext[plan.ObjectPath]
			object, err := loadPluginObjectForPipeline(objectCache, plan.ObjectPath, pieces, needsPluginCtx)
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
			PluginID:   item.plan.PluginID,
			ObjectID:   item.plan.ObjectID,
			ObjectPath: item.plan.ObjectPath,
			spec:       object.spec,
			coll:       object.coll,
		})
	}
	refs = uniqueLoadedPluginObjectRefs(refs)
	cleanupUnusedPluginObjectCollections(objectCache, refs)
	return refs, programs, states
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

func loadPluginObjectForPipeline(cache map[string]*loadedPluginObject, objectPath string, pieces kernelCollectionPieces, needsPluginCtx bool) (*loadedPluginObject, error) {
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
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load plugin object spec %s: %w", objectPath, err)
	}
	if spec.Maps[kernelTCProgramChainMapName] == nil {
		return nil, fmt.Errorf("plugin object %s must declare shared map %q for fvtap pipeline chaining", objectPath, kernelTCProgramChainMapName)
	}
	if needsPluginCtx && spec.Maps[kernelTCPluginContextMapName] == nil {
		return nil, fmt.Errorf("plugin object %s must declare shared map %q for context-aware pipeline hooks", objectPath, kernelTCPluginContextMapName)
	}
	replacements := map[string]*ebpf.Map{
		kernelTCProgramChainMapName: pieces.progChainV4,
	}
	if needsPluginCtx {
		if pieces.pluginCtxV4 == nil {
			return nil, fmt.Errorf("tc plugin context map is unavailable")
		}
		replacements[kernelTCPluginContextMapName] = pieces.pluginCtxV4
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

func installKernelPluginPipelinePrograms(pieces kernelCollectionPieces, programs []loadedKernelPluginPipelineProgram) error {
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
			return fmt.Errorf("unsupported plugin stage %q", item.plan.Stage)
		}
	}
	if len(preForward) > tcProgramChainV4PluginPreForwardMax {
		return fmt.Errorf("too many pre_forward plugin programs: %d > %d", len(preForward), tcProgramChainV4PluginPreForwardMax)
	}
	if len(postLookup) > tcProgramChainV4PluginPostLookupMax {
		return fmt.Errorf("too many post_lookup plugin programs: %d > %d", len(postLookup), tcProgramChainV4PluginPostLookupMax)
	}
	if len(preForward)+len(postLookup) > tcProgramChainV4PluginTotalMax {
		return fmt.Errorf("too many total plugin programs: %d > %d", len(preForward)+len(postLookup), tcProgramChainV4PluginTotalMax)
	}
	if len(preReply) > tcProgramChainV4PluginPreReplyMax {
		return fmt.Errorf("too many pre_reply plugin programs: %d > %d", len(preReply), tcProgramChainV4PluginPreReplyMax)
	}
	if len(postReply) > tcProgramChainV4PluginPostReplyMax {
		return fmt.Errorf("too many post_reply plugin programs: %d > %d", len(postReply), tcProgramChainV4PluginPostReplyMax)
	}
	if len(preReply)+len(postReply) > tcProgramChainV4PluginReplyTotalMax {
		return fmt.Errorf("too many total reply plugin programs: %d > %d", len(preReply)+len(postReply), tcProgramChainV4PluginReplyTotalMax)
	}
	for i, item := range preForward {
		if item.prog == nil {
			return fmt.Errorf("pre_forward plugin program at index %d is nil", i)
		}
		slot := uint32(tcProgramChainIndexV4PluginBase + i)
		if err := pieces.progChainV4.Put(slot, uint32(item.prog.FD())); err != nil {
			_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
			return fmt.Errorf("install plugin %s hook %s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
		}
	}
	for i, item := range postLookup {
		if item.prog == nil {
			return fmt.Errorf("post_lookup plugin program at index %d is nil", i)
		}
		slot := uint32(tcProgramChainIndexV4PluginPostBase + i)
		if err := pieces.progChainV4.Put(slot, uint32(item.prog.FD())); err != nil {
			_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
			return fmt.Errorf("install plugin %s hook %s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
		}
	}
	for i, item := range preReply {
		if item.prog == nil {
			return fmt.Errorf("pre_reply plugin program at index %d is nil", i)
		}
		slot := uint32(tcProgramChainIndexV4PluginReplyBase + i)
		if err := pieces.progChainV4.Put(slot, uint32(item.prog.FD())); err != nil {
			_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
			return fmt.Errorf("install plugin %s hook %s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
		}
	}
	for i, item := range postReply {
		if item.prog == nil {
			return fmt.Errorf("post_reply plugin program at index %d is nil", i)
		}
		slot := uint32(tcProgramChainIndexV4PluginReplyPostBase + i)
		if err := pieces.progChainV4.Put(slot, uint32(item.prog.FD())); err != nil {
			_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
			return fmt.Errorf("install plugin %s hook %s at slot %d: %w", item.plan.PluginID, item.plan.HookID, slot, err)
		}
	}
	if err := syncKernelPluginConfigV4(pieces.pluginConfigV4, uint32(len(preForward)), uint32(len(postLookup)), uint32(len(preReply)), uint32(len(postReply))); err != nil {
		_ = syncKernelPluginConfigV4(pieces.pluginConfigV4, 0, 0, 0, 0)
		return err
	}
	for i := len(preForward); i < tcProgramChainV4PluginPreForwardMax; i++ {
		_ = deleteKernelMapEntry(pieces.progChainV4, uint32(tcProgramChainIndexV4PluginBase+i))
	}
	for i := len(postLookup); i < tcProgramChainV4PluginPostLookupMax; i++ {
		_ = deleteKernelMapEntry(pieces.progChainV4, uint32(tcProgramChainIndexV4PluginPostBase+i))
	}
	for i := len(preReply); i < tcProgramChainV4PluginPreReplyMax; i++ {
		_ = deleteKernelMapEntry(pieces.progChainV4, uint32(tcProgramChainIndexV4PluginReplyBase+i))
	}
	for i := len(postReply); i < tcProgramChainV4PluginPostReplyMax; i++ {
		_ = deleteKernelMapEntry(pieces.progChainV4, uint32(tcProgramChainIndexV4PluginReplyPostBase+i))
	}
	return nil
}

func syncKernelPluginConfigV4(m *ebpf.Map, preForwardCount uint32, postLookupCount uint32, preReplyCount uint32, postReplyCount uint32) error {
	if m == nil {
		if preForwardCount == 0 && postLookupCount == 0 && preReplyCount == 0 && postReplyCount == 0 {
			return nil
		}
		return fmt.Errorf("tc plugin config map is nil")
	}
	key := uint32(0)
	value := kernelTCPluginConfigV4{
		PreForwardCount: preForwardCount,
		PostLookupCount: postLookupCount,
		PreReplyCount:   preReplyCount,
		PostReplyCount:  postReplyCount,
	}
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("sync tc plugin config: %w", err)
	}
	return nil
}

func (rt *linuxKernelRuleRuntime) cleanupPluginPipelineLocked() {
	cleanupKernelPluginPipelineCollections(rt.pluginPipelineLoaded)
	rt.pluginPipelineLoaded = nil
	rt.pluginPipelineFingerprint = ""
	rt.pluginPipelineProgChain = nil
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

func kernelPluginPipelineErrorAllFromDesired(desired []kernelPluginPipelineDesiredPlugin, message string, states map[string]PluginRuntimeState) map[string]PluginRuntimeState {
	if states == nil {
		states = make(map[string]PluginRuntimeState)
	}
	for _, item := range desired {
		if _, exists := states[item.plugin.ID]; exists {
			continue
		}
		states[item.plugin.ID] = pluginRuntimeErrorState(message)
	}
	return states
}

func kernelPluginPipelineFingerprint(items []kernelPluginPipelineDesiredPlugin, states map[string]PluginRuntimeState) string {
	type fingerprintHook struct {
		PluginID       string   `json:"plugin_id"`
		HookID         string   `json:"hook_id"`
		ObjectID       string   `json:"object_id"`
		ObjectPath     string   `json:"object_path"`
		ObjectSHA256   string   `json:"object_sha256,omitempty"`
		ProgramRef     string   `json:"program_ref"`
		ProgramSection string   `json:"program_section"`
		Stage          string   `json:"stage"`
		Mode           string   `json:"mode"`
		Context        []string `json:"context,omitempty"`
		Priority       int      `json:"priority"`
	}
	type fingerprintState struct {
		ID     string `json:"id"`
		Mode   string `json:"mode"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	payload := struct {
		Hooks  []fingerprintHook  `json:"hooks"`
		States []fingerprintState `json:"states,omitempty"`
	}{}
	for _, item := range items {
		for _, hook := range item.hooks {
			payload.Hooks = append(payload.Hooks, fingerprintHook{
				PluginID:       hook.PluginID,
				HookID:         hook.HookID,
				ObjectID:       hook.ObjectID,
				ObjectPath:     hook.ObjectPath,
				ObjectSHA256:   hook.ObjectSHA256,
				ProgramRef:     hook.ProgramRef,
				ProgramSection: hook.ProgramSection,
				Stage:          hook.Stage,
				Mode:           hook.Mode,
				Context:        hook.Context,
				Priority:       hook.Priority,
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
