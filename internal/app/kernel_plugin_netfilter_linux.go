//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type kernelNetfilterPluginGroupKey struct {
	Namespace string `json:"namespace"`
	Family    string `json:"family"`
	Hook      string `json:"hook"`
	Phase     string `json:"phase"`
}

func (key kernelNetfilterPluginGroupKey) String() string {
	return strings.Join([]string{key.Namespace, key.Family, key.Hook, key.Phase}, "/")
}

type kernelNetfilterPluginHookPlan struct {
	PluginID        string                        `json:"plugin_id"`
	HookID          string                        `json:"hook_id"`
	ObjectID        string                        `json:"object_id"`
	ObjectPath      string                        `json:"object_path"`
	ObjectSHA256    string                        `json:"object_sha256,omitempty"`
	ObjectStateMaps []PluginObjectStateMap        `json:"object_state_maps,omitempty"`
	ProgramRef      string                        `json:"program_ref"`
	ProgramSection  string                        `json:"program_section"`
	Group           kernelNetfilterPluginGroupKey `json:"group"`
	Mode            string                        `json:"mode"`
	Priority        int                           `json:"priority"`
	Before          []string                      `json:"before,omitempty"`
	After           []string                      `json:"after,omitempty"`
	Order           int                           `json:"order"`
}

type kernelNetfilterPluginDesiredPlugin struct {
	plugin LoadedPlugin
	hooks  []kernelNetfilterPluginHookPlan
}

type kernelNetfilterPluginGroupPlan struct {
	Key   kernelNetfilterPluginGroupKey
	Hooks []kernelNetfilterPluginHookPlan
}

type loadedKernelNetfilterPluginProgram struct {
	plan kernelNetfilterPluginHookPlan
	prog *ebpf.Program
}

type loadedKernelNetfilterPluginAttachment struct {
	plan              kernelNetfilterPluginHookPlan
	prog              *ebpf.Program
	link              link.Link
	programID         ebpf.ProgramID
	kernelPriority    int32
	staging           bool
	namespaceIdentity pluginControlNetNamespaceIdentity
}

type kernelNetfilterPluginPipelineRuntime struct {
	mu          sync.Mutex
	cfg         *Config
	attachments []*loadedKernelNetfilterPluginAttachment
	loaded      []loadedPluginObjectRef
	desired     []kernelNetfilterPluginDesiredPlugin
	fingerprint string
	snapshot    pluginRuntimeSnapshot
}

func newKernelNetfilterPluginPipelineRuntime(cfg *Config) *kernelNetfilterPluginPipelineRuntime {
	return &kernelNetfilterPluginPipelineRuntime{cfg: cfg}
}

func (rt *kernelNetfilterPluginPipelineRuntime) enabled() bool {
	return rt != nil && rt.cfg != nil && rt.cfg.PluginsEnabled() && rt.cfg.PluginsDataplaneEnabled()
}

func (rt *kernelNetfilterPluginPipelineRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	if rt == nil {
		return kernelPluginPipelineManifestOnlySnapshot(catalog)
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if !rt.enabled() {
		if err := rt.cleanupLocked(); err != nil {
			log.Printf("netfilter plugin pipeline cleanup while disabled: %v", err)
		}
		rt.snapshot = kernelPluginPipelineManifestOnlySnapshot(catalog)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	desired, groups, states := buildKernelNetfilterPluginDesired(catalog, rt.cfg)
	fingerprint := kernelNetfilterPluginFingerprint(desired, groups, states)
	if fingerprint == rt.fingerprint && rt.attachmentsHealthyLocked(desired) {
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}
	if len(groups) == 0 {
		if err := rt.cleanupLocked(); err != nil {
			for id, state := range states {
				state.Error = joinPluginRuntimeText(state.Error, err.Error())
				states[id] = state
			}
		}
		rt.fingerprint = fingerprint
		rt.snapshot = completeKernelPluginSnapshot(catalog, states)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("netfilter plugin pipeline: remove memlock limit: %v", err)
	}
	loadedObjects, programs, err := rt.loadProgramsLocked(desired)
	if err != nil {
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}
	oldAttachments := rt.attachments
	oldLoaded := rt.loaded
	var attachments []*loadedKernelNetfilterPluginAttachment
	if len(oldAttachments) == 0 {
		attachments, err = attachKernelNetfilterPluginPrograms(programs, 0)
	} else if kernelNetfilterPluginAttachmentsStaged(oldAttachments) {
		attachments, err = attachKernelNetfilterPluginPrograms(programs, 0)
		if err == nil {
			_ = closeKernelNetfilterPluginAttachments(oldAttachments)
		}
	} else {
		var staged []*loadedKernelNetfilterPluginAttachment
		staged, err = attachKernelNetfilterPluginPrograms(programs, pluginNetfilterPipelineHookLimit)
		if err != nil {
			_ = closeKernelNetfilterPluginAttachments(staged)
		}
		if err == nil {
			closeOldErr := closeKernelNetfilterPluginAttachments(oldAttachments)
			attachments, err = attachKernelNetfilterPluginPrograms(programs, 0)
			if err == nil && closeOldErr != nil {
				err = fmt.Errorf("close previous netfilter links: %w", closeOldErr)
			}
			if err == nil {
				_ = closeKernelNetfilterPluginAttachments(staged)
			} else {
				_ = closeKernelNetfilterPluginAttachments(attachments)
				restored, restoreErr := attachKernelNetfilterPluginPrograms(kernelNetfilterProgramsFromAttachments(oldAttachments), 0)
				if restoreErr == nil {
					rt.attachments = restored
					_ = closeKernelNetfilterPluginAttachments(staged)
					cleanupKernelPluginPipelineCollections(loadedObjects)
					rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
					return clonePluginRuntimeSnapshot(rt.snapshot)
				}
				rt.attachments = staged
				rt.loaded = loadedObjects
				rt.desired = cloneKernelNetfilterPluginDesired(desired)
				rt.fingerprint = ""
				stagingFailure := fmt.Errorf("%w; restore previous links: %v; new links retained at staging priorities", err, restoreErr)
				rt.snapshot = kernelNetfilterStagingFailureSnapshot(catalog, desired, states, staged, stagingFailure)
				cleanupKernelPluginPipelineCollections(oldLoaded)
				return clonePluginRuntimeSnapshot(rt.snapshot)
			}
		}
	}
	if err != nil {
		_ = closeKernelNetfilterPluginAttachments(attachments)
		cleanupKernelPluginPipelineCollections(loadedObjects)
		rt.rememberInitialFailureLocked(desired)
		rt.snapshot = rt.failureSnapshot(catalog, desired, states, err)
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	attachmentStates := kernelNetfilterPluginAttachmentStates(attachments)
	for _, item := range desired {
		pluginAttachments := sortedPluginAttachmentStates(attachmentStates[item.plugin.ID])
		states[item.plugin.ID] = PluginRuntimeState{
			Mode:            pluginRuntimeModeDataplane,
			Attachable:      true,
			Attached:        len(pluginAttachments) > 0,
			AttachmentCount: len(pluginAttachments),
			Attachments:     pluginAttachments,
		}
	}

	rt.attachments = attachments
	rt.loaded = loadedObjects
	rt.desired = cloneKernelNetfilterPluginDesired(desired)
	rt.fingerprint = fingerprint
	rt.snapshot = completeKernelPluginSnapshot(catalog, states)

	if len(oldAttachments) > 0 && !kernelNetfilterPluginAttachmentsClosed(oldAttachments) {
		if err := closeKernelNetfilterPluginAttachments(oldAttachments); err != nil {
			log.Printf("netfilter plugin pipeline cleanup previous links: %v", err)
		}
	}
	cleanupKernelPluginPipelineCollections(oldLoaded)
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *kernelNetfilterPluginPipelineRuntime) Snapshot() pluginRuntimeSnapshot {
	if rt == nil {
		return pluginRuntimeSnapshot{}
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *kernelNetfilterPluginPipelineRuntime) Close() error {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.cleanupLocked()
}

func (rt *kernelNetfilterPluginPipelineRuntime) failureSnapshot(catalog PluginCatalog, desired []kernelNetfilterPluginDesiredPlugin, states map[string]PluginRuntimeState, failure error) pluginRuntimeSnapshot {
	message := "netfilter plugin pipeline failed"
	if failure != nil {
		message = failure.Error()
	}
	if len(rt.attachments) > 0 && len(rt.snapshot.Plugins) > 0 {
		preserved := clonePluginRuntimeSnapshot(rt.snapshot)
		for _, item := range desired {
			state := preserved.Plugins[item.plugin.ID]
			state.Reason = joinPluginRuntimeText(state.Reason, "netfilter plugin update failed; previous links preserved")
			state.Error = joinPluginRuntimeText(state.Error, message)
			preserved.Plugins[item.plugin.ID] = state
		}
		return preserved
	}
	for _, item := range desired {
		states[item.plugin.ID] = pluginRuntimeErrorState(message)
	}
	return completeKernelPluginSnapshot(catalog, states)
}

func (rt *kernelNetfilterPluginPipelineRuntime) rememberInitialFailureLocked(desired []kernelNetfilterPluginDesiredPlugin) {
	if len(rt.attachments) != 0 {
		return
	}
	rt.desired = cloneKernelNetfilterPluginDesired(desired)
	rt.fingerprint = ""
}

func kernelNetfilterStagingFailureSnapshot(catalog PluginCatalog, desired []kernelNetfilterPluginDesiredPlugin, states map[string]PluginRuntimeState, attachments []*loadedKernelNetfilterPluginAttachment, failure error) pluginRuntimeSnapshot {
	attachmentStates := kernelNetfilterPluginAttachmentStates(attachments)
	message := "netfilter plugin links are running at staging priorities"
	if failure != nil {
		message = failure.Error()
	}
	for _, item := range desired {
		pluginAttachments := sortedPluginAttachmentStates(attachmentStates[item.plugin.ID])
		states[item.plugin.ID] = PluginRuntimeState{
			Mode:            pluginRuntimeModeError,
			Attachable:      true,
			Attached:        len(pluginAttachments) > 0,
			AttachmentCount: len(pluginAttachments),
			Attachments:     pluginAttachments,
			Reason:          "netfilter update degraded; retry will promote staging links",
			Error:           message,
		}
	}
	return completeKernelPluginSnapshot(catalog, states)
}

func buildKernelNetfilterPluginDesired(catalog PluginCatalog, cfg *Config) ([]kernelNetfilterPluginDesiredPlugin, []kernelNetfilterPluginGroupPlan, map[string]PluginRuntimeState) {
	states := make(map[string]PluginRuntimeState)
	desired := make([]kernelNetfilterPluginDesiredPlugin, 0, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || !pluginHasHookEngine(plugin, pluginEngineNetfilter) {
			continue
		}
		if ok, reason := pluginDataplaneStabilityAllowed(plugin, cfg); !ok {
			state := externalPluginRuntimeState()
			state.Reason = reason
			states[plugin.ID] = state
			continue
		}
		item, state := buildKernelNetfilterPluginDesiredPlugin(plugin)
		if len(item.hooks) == 0 || state.Error != "" {
			states[plugin.ID] = state
			continue
		}
		desired = append(desired, item)
	}

	for len(desired) > 0 {
		groups := groupKernelNetfilterPluginHooks(desired)
		invalid := make(map[string]string)
		for i := range groups {
			group := &groups[i]
			if len(group.Hooks) > pluginNetfilterPipelineHookLimit {
				message := fmt.Sprintf("netfilter placement %s has %d hooks, limit is %d", group.Key.String(), len(group.Hooks), pluginNetfilterPipelineHookLimit)
				for _, hook := range group.Hooks {
					invalid[hook.PluginID] = message
				}
				continue
			}
			nodes := make([]pluginHookOrderNode, 0, len(group.Hooks))
			for _, hook := range group.Hooks {
				nodes = append(nodes, pluginHookOrderNode{
					PluginID: hook.PluginID,
					HookID:   hook.HookID,
					Stage:    group.Key.String(),
					Priority: hook.Priority,
					Before:   hook.Before,
					After:    hook.After,
				})
			}
			order, orderingInvalid := resolvePluginHookOrder(nodes)
			for pluginID, message := range orderingInvalid {
				invalid[pluginID] = message
			}
			if len(orderingInvalid) == 0 {
				for index := range group.Hooks {
					group.Hooks[index].Order = order[pluginHookOrderKey(group.Hooks[index].PluginID, group.Hooks[index].HookID)]
				}
				sort.Slice(group.Hooks, func(left, right int) bool {
					return kernelNetfilterPluginHookLess(group.Hooks[left], group.Hooks[right])
				})
			}
		}
		if len(groups) > pluginNetfilterPipelineGroupLimit {
			message := fmt.Sprintf("netfilter pipeline has %d placements, limit is %d", len(groups), pluginNetfilterPipelineGroupLimit)
			for _, item := range desired {
				invalid[item.plugin.ID] = message
			}
		}
		if len(invalid) == 0 {
			applyKernelNetfilterGroupOrderToDesired(desired, groups)
			sort.Slice(desired, func(i, j int) bool { return desired[i].plugin.ID < desired[j].plugin.ID })
			return desired, groups, states
		}
		filtered := make([]kernelNetfilterPluginDesiredPlugin, 0, len(desired))
		for _, item := range desired {
			if message, rejected := invalid[item.plugin.ID]; rejected {
				states[item.plugin.ID] = pluginRuntimeErrorState(message)
				continue
			}
			filtered = append(filtered, item)
		}
		if len(filtered) == len(desired) {
			break
		}
		desired = filtered
	}
	return nil, nil, states
}

func buildKernelNetfilterPluginDesiredPlugin(plugin LoadedPlugin) (kernelNetfilterPluginDesiredPlugin, PluginRuntimeState) {
	item := kernelNetfilterPluginDesiredPlugin{plugin: plugin}
	objects := make(map[string]PluginObject, len(plugin.Objects)*2)
	for _, object := range plugin.Objects {
		if object.Status != pluginObjectStatusVerified {
			continue
		}
		objects[object.ID] = object
		objects[object.Path] = object
	}
	for _, hook := range plugin.Hooks {
		if hook.Engine != pluginEngineNetfilter {
			continue
		}
		objectRef, programRef, ok := parsePluginProgramRef(hook.Program)
		if !ok {
			return item, pluginRuntimeErrorState("program must use object:program for netfilter hooks")
		}
		object, ok := objects[objectRef]
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing object %q", hook.ID, objectRef))
		}
		program, ok := pluginObjectProgramByRef(object, programRef)
		if !ok {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s references missing program %q in object %q", hook.ID, programRef, objectRef))
		}
		if program.Type != pluginEngineNetfilter {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s program %q type = %q, want netfilter", hook.ID, programRef, program.Type))
		}
		realPath, err := resolvePluginObjectRealPath(&plugin, object)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s object path: %v", hook.ID, err))
		}
		for _, family := range expandKernelNetfilterPluginFamilies(hook.Family) {
			item.hooks = append(item.hooks, kernelNetfilterPluginHookPlan{
				PluginID:        plugin.ID,
				HookID:          hook.ID,
				ObjectID:        object.ID,
				ObjectPath:      realPath,
				ObjectSHA256:    object.ResolvedSHA256,
				ObjectStateMaps: append([]PluginObjectStateMap(nil), object.StateMaps...),
				ProgramRef:      programRef,
				ProgramSection:  program.Section,
				Group:           kernelNetfilterPluginGroupKey{Namespace: hook.Namespace, Family: family, Hook: hook.NetfilterHook, Phase: hook.Phase},
				Mode:            hook.Mode,
				Priority:        hook.Priority,
				Before:          append([]string(nil), hook.Before...),
				After:           append([]string(nil), hook.After...),
			})
		}
	}
	if len(item.hooks) == 0 {
		state := externalPluginRuntimeState()
		state.Reason = "no supported netfilter hook is declared"
		return item, state
	}
	return item, PluginRuntimeState{}
}

func expandKernelNetfilterPluginFamilies(family string) []string {
	if family == "inet" {
		return []string{"ipv4", "ipv6"}
	}
	return []string{family}
}

func groupKernelNetfilterPluginHooks(desired []kernelNetfilterPluginDesiredPlugin) []kernelNetfilterPluginGroupPlan {
	byKey := make(map[string]*kernelNetfilterPluginGroupPlan)
	for _, item := range desired {
		for _, hook := range item.hooks {
			key := hook.Group.String()
			group := byKey[key]
			if group == nil {
				group = &kernelNetfilterPluginGroupPlan{Key: hook.Group}
				byKey[key] = group
			}
			group.Hooks = append(group.Hooks, hook)
		}
	}
	groups := make([]kernelNetfilterPluginGroupPlan, 0, len(byKey))
	for _, group := range byKey {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Key.String() < groups[j].Key.String() })
	return groups
}

func applyKernelNetfilterGroupOrderToDesired(desired []kernelNetfilterPluginDesiredPlugin, groups []kernelNetfilterPluginGroupPlan) {
	orders := make(map[string]int)
	for _, group := range groups {
		for _, hook := range group.Hooks {
			orders[group.Key.String()+"\x00"+pluginHookOrderKey(hook.PluginID, hook.HookID)] = hook.Order
		}
	}
	for i := range desired {
		for j := range desired[i].hooks {
			hook := &desired[i].hooks[j]
			hook.Order = orders[hook.Group.String()+"\x00"+pluginHookOrderKey(hook.PluginID, hook.HookID)]
		}
		sort.Slice(desired[i].hooks, func(left, right int) bool {
			return kernelNetfilterPluginHookLess(desired[i].hooks[left], desired[i].hooks[right])
		})
	}
}

func kernelNetfilterPluginHookLess(left, right kernelNetfilterPluginHookPlan) bool {
	if left.Group.String() != right.Group.String() {
		return left.Group.String() < right.Group.String()
	}
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

func cloneKernelNetfilterPluginDesired(values []kernelNetfilterPluginDesiredPlugin) []kernelNetfilterPluginDesiredPlugin {
	out := make([]kernelNetfilterPluginDesiredPlugin, len(values))
	for i, item := range values {
		out[i] = item
		out[i].hooks = make([]kernelNetfilterPluginHookPlan, len(item.hooks))
		for j, hook := range item.hooks {
			out[i].hooks[j] = hook
			out[i].hooks[j].ObjectStateMaps = append([]PluginObjectStateMap(nil), hook.ObjectStateMaps...)
			out[i].hooks[j].Before = append([]string(nil), hook.Before...)
			out[i].hooks[j].After = append([]string(nil), hook.After...)
		}
	}
	return out
}

func kernelNetfilterPluginFingerprint(desired []kernelNetfilterPluginDesiredPlugin, groups []kernelNetfilterPluginGroupPlan, states map[string]PluginRuntimeState) string {
	type pluginEntry struct {
		ID    string                          `json:"id"`
		Hooks []kernelNetfilterPluginHookPlan `json:"hooks"`
	}
	type stateEntry struct {
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	payload := struct {
		Plugins []pluginEntry                    `json:"plugins"`
		Groups  []kernelNetfilterPluginGroupPlan `json:"groups"`
		States  []stateEntry                     `json:"states,omitempty"`
	}{Groups: groups}
	for _, item := range desired {
		payload.Plugins = append(payload.Plugins, pluginEntry{ID: item.plugin.ID, Hooks: item.hooks})
	}
	for id, state := range states {
		payload.States = append(payload.States, stateEntry{ID: id, Reason: state.Reason, Error: state.Error})
	}
	sort.Slice(payload.States, func(i, j int) bool { return payload.States[i].ID < payload.States[j].ID })
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func (rt *kernelNetfilterPluginPipelineRuntime) loadProgramsLocked(desired []kernelNetfilterPluginDesiredPlugin) ([]loadedPluginObjectRef, []loadedKernelNetfilterPluginProgram, error) {
	plans := make([]kernelNetfilterPluginHookPlan, 0)
	for _, item := range desired {
		plans = append(plans, item.hooks...)
	}
	sort.Slice(plans, func(i, j int) bool { return kernelNetfilterPluginHookLess(plans[i], plans[j]) })

	cache := make(map[string]*loadedPluginObject)
	refs := make([]loadedPluginObjectRef, 0)
	refSeen := make(map[string]struct{})
	programs := make([]loadedKernelNetfilterPluginProgram, 0, len(plans))
	for _, plan := range plans {
		cacheKey := plan.PluginID + "\x00" + plan.ObjectID + "\x00" + plan.ObjectPath
		object := cache[cacheKey]
		if object == nil {
			previous, unchanged := previousKernelNetfilterPluginObject(rt.loaded, plan)
			var err error
			object, err = loadKernelNetfilterPluginObject(plan, previous, unchanged)
			if err != nil {
				cleanupLoadedPluginObjectCache(cache)
				return nil, nil, fmt.Errorf("load plugin %s object %s: %w", plan.PluginID, plan.ObjectID, err)
			}
			cache[cacheKey] = object
		}
		prog, err := pluginProgramForAttach(object, plan.ProgramSection, plan.ProgramRef)
		if err != nil {
			cleanupLoadedPluginObjectCache(cache)
			return nil, nil, fmt.Errorf("load plugin %s hook %s: %w", plan.PluginID, plan.HookID, err)
		}
		programs = append(programs, loadedKernelNetfilterPluginProgram{plan: plan, prog: prog})
		refKey := plan.PluginID + "\x00" + plan.ObjectID + "\x00" + plan.ObjectPath
		if _, exists := refSeen[refKey]; !exists {
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
	return refs, programs, nil
}

func previousKernelNetfilterPluginObject(refs []loadedPluginObjectRef, plan kernelNetfilterPluginHookPlan) (*loadedPluginObjectRef, bool) {
	hash := strings.TrimSpace(strings.ToLower(plan.ObjectSHA256))
	for i := range refs {
		ref := &refs[i]
		if ref.PluginID != plan.PluginID || ref.ObjectID != plan.ObjectID || ref.coll == nil {
			continue
		}
		unchanged := hash != "" && strings.TrimSpace(strings.ToLower(ref.ObjectSHA256)) == hash &&
			pluginObjectStateMapsEqual(ref.StateMaps, plan.ObjectStateMaps)
		return ref, unchanged
	}
	return nil, false
}

func loadKernelNetfilterPluginObject(plan kernelNetfilterPluginHookPlan, previous *loadedPluginObjectRef, unchanged bool) (*loadedPluginObject, error) {
	spec, err := loadVerifiedPluginObjectCollectionSpec(plan.ObjectPath, plan.ObjectSHA256)
	if err != nil {
		return nil, err
	}
	replacements, err := pluginPipelineMapReplacements(spec, nil, plan.ObjectStateMaps, previous, unchanged)
	if err != nil {
		return nil, err
	}
	migrations, err := planPluginObjectStateMigrations(plan.PluginID, plan.ObjectID, plan.ObjectStateMaps, previous)
	if err != nil {
		return nil, err
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(replacements))
	if err != nil {
		logKernelVerifierDetails(err)
		return nil, err
	}
	return &loadedPluginObject{path: plan.ObjectPath, spec: spec, coll: collection, migrations: migrations}, nil
}

func attachKernelNetfilterPluginPrograms(programs []loadedKernelNetfilterPluginProgram, priorityOffset int) ([]*loadedKernelNetfilterPluginAttachment, error) {
	attachments := make([]*loadedKernelNetfilterPluginAttachment, 0, len(programs))
	for _, item := range programs {
		attached, err := attachKernelNetfilterPluginProgram(item, priorityOffset)
		if err != nil {
			return attachments, fmt.Errorf("attach netfilter plugin %s/%s at %s: %w", item.plan.PluginID, item.plan.HookID, item.plan.Group.String(), err)
		}
		attachments = append(attachments, attached)
	}
	return attachments, nil
}

func kernelNetfilterProgramsFromAttachments(attachments []*loadedKernelNetfilterPluginAttachment) []loadedKernelNetfilterPluginProgram {
	programs := make([]loadedKernelNetfilterPluginProgram, 0, len(attachments))
	for _, attached := range attachments {
		if attached == nil || attached.prog == nil {
			continue
		}
		programs = append(programs, loadedKernelNetfilterPluginProgram{plan: attached.plan, prog: attached.prog})
	}
	return programs
}

func kernelNetfilterPluginAttachmentsStaged(attachments []*loadedKernelNetfilterPluginAttachment) bool {
	if len(attachments) == 0 {
		return false
	}
	for _, attached := range attachments {
		if attached == nil || !attached.staging {
			return false
		}
	}
	return true
}

func kernelNetfilterPluginAttachmentsClosed(attachments []*loadedKernelNetfilterPluginAttachment) bool {
	for _, attached := range attachments {
		if attached != nil && attached.link != nil {
			return false
		}
	}
	return true
}

func attachKernelNetfilterPluginProgram(item loadedKernelNetfilterPluginProgram, priorityOffset int) (*loadedKernelNetfilterPluginAttachment, error) {
	if item.prog == nil {
		return nil, fmt.Errorf("program is nil")
	}
	priority := kernelNetfilterPluginPriority(item.plan.Group.Phase, item.plan.Order, priorityOffset)
	var attached link.Link
	var identity pluginControlNetNamespaceIdentity
	attach := func() error {
		var err error
		attached, err = link.AttachNetfilter(link.NetfilterOptions{
			Program:        item.prog,
			ProtocolFamily: kernelNetfilterProtocolFamily(item.plan.Group.Family),
			Hook:           kernelNetfilterHook(item.plan.Group.Hook),
			Priority:       priority,
		})
		return err
	}
	var err error
	if item.plan.Group.Namespace == "host" {
		err = attach()
	} else {
		identity, err = linuxPluginRunInNamespaceWithIdentity(item.plan.Group.Namespace, attach)
	}
	if err != nil {
		if attached != nil {
			_ = attached.Close()
		}
		return nil, err
	}
	result := &loadedKernelNetfilterPluginAttachment{
		plan:              item.plan,
		prog:              item.prog,
		link:              attached,
		programID:         ebpf.ProgramID(kernelProgramID(item.prog)),
		kernelPriority:    priority,
		staging:           priorityOffset != 0,
		namespaceIdentity: identity,
	}
	if !kernelNetfilterPluginAttachmentHealthy(result) {
		_ = attached.Close()
		return nil, fmt.Errorf("attached link could not be verified")
	}
	return result, nil
}

func kernelNetfilterProtocolFamily(family string) link.NetfilterProtocolFamily {
	if family == "ipv6" {
		return link.NetfilterProtoIPv6
	}
	return link.NetfilterProtoIPv4
}

func kernelNetfilterHook(hook string) link.NetfilterInetHook {
	switch hook {
	case "prerouting":
		return link.NetfilterInetPreRouting
	case "input":
		return link.NetfilterInetLocalIn
	case "output":
		return link.NetfilterInetLocalOut
	case "postrouting":
		return link.NetfilterInetPostRouting
	default:
		return link.NetfilterInetForward
	}
}

func kernelNetfilterPhasePriority(phase string) int32 {
	switch phase {
	case "early":
		return -500
	case "raw":
		return -290
	case "mangle":
		return -140
	case "dstnat":
		return -90
	case "security":
		return 60
	case "srcnat":
		return 110
	case "late":
		return 30000
	default:
		return 10
	}
}

func kernelNetfilterPluginPriority(phase string, order, priorityOffset int) int32 {
	return kernelNetfilterPhasePriority(phase) + int32(order+priorityOffset)
}

func kernelNetfilterNamespaceIdentity(namespace string) (pluginControlNetNamespaceIdentity, error) {
	if namespace == "host" {
		return pluginControlNetNamespaceIdentity{}, nil
	}
	info, found, err := linuxPluginNamespaceLookup(namespace)
	if err != nil {
		return pluginControlNetNamespaceIdentity{}, fmt.Errorf("inspect namespace %s: %w", namespace, err)
	}
	if !found {
		return pluginControlNetNamespaceIdentity{}, fmt.Errorf("namespace %s no longer exists", namespace)
	}
	return info.Identity, nil
}

func kernelNetfilterPluginAttachmentStates(attachments []*loadedKernelNetfilterPluginAttachment) map[string][]PluginAttachmentState {
	result := make(map[string][]PluginAttachmentState)
	for _, attached := range attachments {
		if attached == nil {
			continue
		}
		plan := attached.plan
		status := "attached"
		if attached.staging {
			status = "staging"
		}
		result[plan.PluginID] = append(result[plan.PluginID], PluginAttachmentState{
			HookID:        plan.HookID,
			Engine:        pluginEngineNetfilter,
			Attach:        plan.Group.Hook,
			Stage:         plan.Group.Phase,
			Interface:     plan.Group.Namespace,
			Family:        plan.Group.Family,
			NetfilterHook: plan.Group.Hook,
			Phase:         plan.Group.Phase,
			Namespace:     plan.Group.Namespace,
			Program:       plan.ObjectID + ":" + plan.ProgramRef,
			Mode:          plan.Mode,
			Priority:      plan.Priority,
			Before:        append([]string(nil), plan.Before...),
			After:         append([]string(nil), plan.After...),
			Order:         plan.Order,
			FilterHandle:  fmt.Sprintf("bpf_link:priority=%d", attached.kernelPriority),
			Status:        status,
		})
	}
	return result
}

func (rt *kernelNetfilterPluginPipelineRuntime) attachmentsHealthyLocked(desired []kernelNetfilterPluginDesiredPlugin) bool {
	wanted := 0
	for _, item := range desired {
		wanted += len(item.hooks)
	}
	if wanted == 0 || wanted != len(rt.attachments) || len(rt.loaded) == 0 {
		return false
	}
	for _, attached := range rt.attachments {
		if !kernelNetfilterPluginAttachmentHealthy(attached) {
			return false
		}
		identity, err := kernelNetfilterNamespaceIdentity(attached.plan.Group.Namespace)
		if err != nil {
			return false
		}
		if attached.plan.Group.Namespace != "host" && !pluginControlNamespaceIdentityEqual(identity, attached.namespaceIdentity) {
			return false
		}
	}
	return true
}

func kernelNetfilterPluginAttachmentHealthy(attached *loadedKernelNetfilterPluginAttachment) bool {
	if attached == nil || attached.link == nil || attached.programID == 0 {
		return false
	}
	info, err := attached.link.Info()
	if err != nil || info == nil || info.Program != attached.programID {
		return false
	}
	netfilter := info.Netfilter()
	if netfilter == nil {
		return false
	}
	return netfilter.ProtocolFamily == kernelNetfilterProtocolFamily(attached.plan.Group.Family) &&
		netfilter.Hook == kernelNetfilterHook(attached.plan.Group.Hook) &&
		netfilter.Priority == attached.kernelPriority
}

func closeKernelNetfilterPluginAttachments(attachments []*loadedKernelNetfilterPluginAttachment) error {
	failures := make([]string, 0)
	for index := len(attachments) - 1; index >= 0; index-- {
		attached := attachments[index]
		if attached == nil || attached.link == nil {
			continue
		}
		if err := attached.link.Close(); err != nil {
			failures = append(failures, fmt.Sprintf("%s/%s: %v", attached.plan.PluginID, attached.plan.HookID, err))
		}
		attached.link = nil
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (rt *kernelNetfilterPluginPipelineRuntime) cleanupLocked() error {
	if rt == nil {
		return nil
	}
	err := closeKernelNetfilterPluginAttachments(rt.attachments)
	cleanupKernelPluginPipelineCollections(rt.loaded)
	rt.attachments = nil
	rt.loaded = nil
	rt.desired = nil
	rt.fingerprint = ""
	rt.snapshot = pluginRuntimeSnapshot{}
	return err
}
