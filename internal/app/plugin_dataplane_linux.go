//go:build linux

package app

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	pluginTCFilterPriorityBase uint16 = 40000
	pluginTCFilterHandleBase   uint16 = 40000
	pluginTCFilterMaxCount            = 20000
)

func newPluginDataplaneRuntime(cfg *Config) pluginDataplaneRuntime {
	return &linuxPluginDataplaneRuntime{cfg: cfg, loaded: make(map[string]*loadedPluginDataplane)}
}

type linuxPluginDataplaneRuntime struct {
	mu          sync.Mutex
	cfg         *Config
	fingerprint string
	loaded      map[string]*loadedPluginDataplane
	snapshot    pluginRuntimeSnapshot
}

type loadedPluginDataplane struct {
	objects []loadedPluginObjectRef
	filters []*netlink.BpfFilter
}

type pluginDataplaneDesiredPlugin struct {
	plugin      LoadedPlugin
	attachments []pluginTCAttachPlan
	warnings    []string
}

type pluginTCAttachPlan struct {
	PluginID       string `json:"plugin_id"`
	HookID         string `json:"hook_id"`
	ObjectID       string `json:"object_id"`
	ObjectPath     string `json:"object_path"`
	ObjectSHA256   string `json:"object_sha256,omitempty"`
	ProgramRef     string `json:"program_ref"`
	ProgramSection string `json:"program_section"`
	Interface      string `json:"interface"`
	IfIndex        int    `json:"ifindex"`
	Attach         string `json:"attach"`
	Mode           string `json:"mode"`
	RelativePrio   int    `json:"relative_priority"`
	Priority       uint16 `json:"priority"`
	HandleMinor    uint16 `json:"handle_minor"`
}

type loadedPluginObject struct {
	path string
	spec *ebpf.CollectionSpec
	coll *ebpf.Collection
}

type loadedPluginObjectRef struct {
	PluginID     string
	ObjectID     string
	ObjectPath   string
	ObjectSHA256 string
	spec         *ebpf.CollectionSpec
	coll         *ebpf.Collection
}

func (rt *linuxPluginDataplaneRuntime) Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	states := make(map[string]PluginRuntimeState)
	if !rt.dataplaneEnabled() {
		for _, plugin := range catalog.Plugins {
			if plugin.Builtin || plugin.Status != pluginStatusActive {
				continue
			}
			states[plugin.ID] = externalPluginRuntimeState()
		}
		rt.cleanupLocked()
		rt.fingerprint = ""
		rt.snapshot = pluginRuntimeSnapshot{Plugins: states}
		return clonePluginRuntimeSnapshot(rt.snapshot)
	}

	desired, planStates := rt.buildDesiredPlugins(catalog)
	for id, state := range planStates {
		states[id] = state
	}
	fingerprint := pluginDataplaneFingerprint(desired, states)
	if fingerprint == rt.fingerprint {
		if rt.loadedAttachmentsHealthyLocked() {
			return clonePluginRuntimeSnapshot(rt.snapshot)
		}
		log.Printf("plugin runtime: detected missing tc attachment, rebuilding plugin dataplane")
	}

	rt.cleanupLocked()
	rt.loaded = make(map[string]*loadedPluginDataplane)
	for _, item := range desired {
		state := PluginRuntimeState{
			Mode:       pluginRuntimeModeDataplane,
			Attachable: true,
			Attached:   false,
			Reason:     strings.Join(item.warnings, "; "),
		}
		loaded, attachments, err := rt.loadDesiredPlugin(item)
		if err != nil {
			state.Mode = pluginRuntimeModeError
			state.Attachable = false
			state.Error = err.Error()
			if state.Reason == "" {
				state.Reason = "plugin dataplane attach failed"
			}
			cleanupLoadedPluginDataplane(loaded)
			states[item.plugin.ID] = state
			continue
		}
		state.Attached = len(attachments) > 0
		state.AttachmentCount = len(attachments)
		state.Attachments = sortedPluginAttachmentStates(attachments)
		states[item.plugin.ID] = state
		rt.loaded[item.plugin.ID] = loaded
	}

	rt.fingerprint = fingerprint
	rt.snapshot = pluginRuntimeSnapshot{Plugins: states}
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *linuxPluginDataplaneRuntime) Snapshot() pluginRuntimeSnapshot {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return clonePluginRuntimeSnapshot(rt.snapshot)
}

func (rt *linuxPluginDataplaneRuntime) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.cleanupLocked()
	rt.snapshot = pluginRuntimeSnapshot{}
	rt.fingerprint = ""
	return nil
}

func (rt *linuxPluginDataplaneRuntime) dataplaneEnabled() bool {
	return rt.cfg != nil && rt.cfg.PluginsEnabled() && rt.cfg.PluginsDataplaneEnabled()
}

func (rt *linuxPluginDataplaneRuntime) cleanupLocked() {
	for id, loaded := range rt.loaded {
		cleanupLoadedPluginDataplane(loaded)
		delete(rt.loaded, id)
	}
}

func cleanupLoadedPluginDataplane(loaded *loadedPluginDataplane) {
	if loaded == nil {
		return
	}
	for i := len(loaded.filters) - 1; i >= 0; i-- {
		if loaded.filters[i] != nil {
			_ = netlink.FilterDel(loaded.filters[i])
		}
	}
	seen := make(map[*ebpf.Collection]struct{}, len(loaded.objects))
	for i := len(loaded.objects) - 1; i >= 0; i-- {
		coll := loaded.objects[i].coll
		if coll != nil {
			if _, ok := seen[coll]; ok {
				continue
			}
			seen[coll] = struct{}{}
			coll.Close()
		}
	}
}

func (rt *linuxPluginDataplaneRuntime) loadedAttachmentsHealthyLocked() bool {
	for _, loaded := range rt.loaded {
		if loaded == nil {
			continue
		}
		for _, filter := range loaded.filters {
			if !pluginTCFilterExists(filter) {
				return false
			}
		}
	}
	return true
}

func pluginTCFilterExists(filter *netlink.BpfFilter) bool {
	if filter == nil {
		return false
	}
	link, err := netlink.LinkByIndex(filter.LinkIndex)
	if err != nil {
		return false
	}
	filters, err := netlink.FilterList(link, filter.Parent)
	if err != nil {
		return false
	}
	for _, item := range filters {
		bpf, ok := item.(*netlink.BpfFilter)
		if !ok || bpf == nil {
			continue
		}
		if bpf.Priority == filter.Priority && bpf.Handle == filter.Handle && bpf.Name == filter.Name {
			return true
		}
	}
	return false
}

func (rt *linuxPluginDataplaneRuntime) buildDesiredPlugins(catalog PluginCatalog) ([]pluginDataplaneDesiredPlugin, map[string]PluginRuntimeState) {
	states := make(map[string]PluginRuntimeState)
	desired := make([]pluginDataplaneDesiredPlugin, 0, len(catalog.Plugins))
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if ok, reason := pluginDataplaneStabilityAllowed(plugin, rt.cfg); !ok {
			state := externalPluginRuntimeState()
			state.Reason = reason
			states[plugin.ID] = state
			continue
		}
		item, state := buildDesiredPluginDataplane(plugin)
		if len(item.attachments) == 0 || state.Error != "" {
			states[plugin.ID] = state
			continue
		}
		desired = append(desired, item)
	}
	sort.Slice(desired, func(i, j int) bool {
		return desired[i].plugin.ID < desired[j].plugin.ID
	})
	if err := assignPluginTCFilterIDs(desired); err != nil {
		for _, item := range desired {
			states[item.plugin.ID] = pluginRuntimeErrorState(err.Error())
		}
		return nil, states
	}
	return desired, states
}

func buildDesiredPluginDataplane(plugin LoadedPlugin) (pluginDataplaneDesiredPlugin, PluginRuntimeState) {
	item := pluginDataplaneDesiredPlugin{plugin: plugin}
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
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: %s dataplane plugins are not attached yet", hook.ID, hook.Engine))
			continue
		}
		if hook.Mode != "observe" {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: only observe mode can be attached directly", hook.ID))
			continue
		}
		if len(hook.Interfaces) == 0 {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: interfaces is required for direct tc attach", hook.ID))
			continue
		}
		objectRef, programRef, ok := parsePluginProgramRef(hook.Program)
		if !ok {
			return item, pluginRuntimeErrorState("program must use object:program for tc hooks")
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
		attaches := pluginHookAttachDirections(hook.Attach)
		if len(attaches) == 0 {
			item.warnings = append(item.warnings, fmt.Sprintf("hook %s skipped: attach=none", hook.ID))
			continue
		}
		resolvedLinks := make(map[string]netlink.Link, len(hook.Interfaces))
		for _, iface := range hook.Interfaces {
			link, err := netlink.LinkByName(iface)
			if err != nil {
				return item, pluginRuntimeErrorState(fmt.Sprintf("resolve plugin hook interface %q for hook %s: %v", iface, hook.ID, err))
			}
			resolvedLinks[iface] = link
		}
		realPath, err := resolvePluginObjectRealPath(&plugin, object)
		if err != nil {
			return item, pluginRuntimeErrorState(fmt.Sprintf("hook %s object path: %v", hook.ID, err))
		}
		for _, iface := range hook.Interfaces {
			link := resolvedLinks[iface]
			for _, attach := range attaches {
				item.attachments = append(item.attachments, pluginTCAttachPlan{
					PluginID:       plugin.ID,
					HookID:         hook.ID,
					ObjectID:       object.ID,
					ObjectPath:     realPath,
					ObjectSHA256:   object.ResolvedSHA256,
					ProgramRef:     programRef,
					ProgramSection: program.Section,
					Interface:      iface,
					IfIndex:        link.Attrs().Index,
					Attach:         attach,
					Mode:           hook.Mode,
					RelativePrio:   hook.Priority,
				})
			}
		}
	}
	if len(item.attachments) == 0 {
		state := externalPluginRuntimeState()
		if len(item.warnings) > 0 {
			state.Reason = strings.Join(item.warnings, "; ")
		}
		return item, state
	}
	sort.Slice(item.attachments, func(i, j int) bool {
		a := item.attachments[i]
		b := item.attachments[j]
		if a.RelativePrio != b.RelativePrio {
			return a.RelativePrio < b.RelativePrio
		}
		if a.Interface != b.Interface {
			return a.Interface < b.Interface
		}
		if a.Attach != b.Attach {
			return a.Attach < b.Attach
		}
		if a.HookID != b.HookID {
			return a.HookID < b.HookID
		}
		return a.ProgramRef < b.ProgramRef
	})
	return item, PluginRuntimeState{}
}

func pluginHookAttachDirections(attach string) []string {
	switch attach {
	case "egress":
		return []string{"egress"}
	case "both":
		return []string{"ingress", "egress"}
	case "none":
		return nil
	default:
		return []string{"ingress"}
	}
}

func assignPluginTCFilterIDs(items []pluginDataplaneDesiredPlugin) error {
	total := 0
	for i := range items {
		total += len(items[i].attachments)
	}
	if total > pluginTCFilterMaxCount {
		return fmt.Errorf("too many plugin tc attachments: %d > %d", total, pluginTCFilterMaxCount)
	}

	index := 0
	for i := range items {
		for j := range items[i].attachments {
			items[i].attachments[j].Priority = pluginTCFilterPriorityBase + uint16(index)
			items[i].attachments[j].HandleMinor = pluginTCFilterHandleBase + uint16(index)
			index++
		}
	}
	return nil
}

func (rt *linuxPluginDataplaneRuntime) loadDesiredPlugin(item pluginDataplaneDesiredPlugin) (*loadedPluginDataplane, []PluginAttachmentState, error) {
	if len(item.attachments) == 0 {
		return &loadedPluginDataplane{}, nil, nil
	}
	if len(item.attachments) > pluginTCFilterMaxCount {
		return nil, nil, fmt.Errorf("too many plugin tc attachments: %d > %d", len(item.attachments), pluginTCFilterMaxCount)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("plugin runtime: remove memlock limit: %v", err)
	}
	loaded := &loadedPluginDataplane{}
	objects := make(map[string]*loadedPluginObject)
	states := make([]PluginAttachmentState, 0, len(item.attachments))
	for _, plan := range item.attachments {
		object, err := loadPluginObjectForAttach(objects, plan.ObjectPath, plan.ObjectSHA256)
		if err != nil {
			cleanupLoadedPluginObjectCache(objects)
			return loaded, states, err
		}
		prog, err := pluginProgramForAttach(object, plan.ProgramSection, plan.ProgramRef)
		if err != nil {
			cleanupLoadedPluginObjectCache(objects)
			return loaded, states, err
		}
		filter, err := attachPluginTCProgram(plan, prog)
		if err != nil {
			cleanupLoadedPluginObjectCache(objects)
			return loaded, states, fmt.Errorf("attach hook %s on %s %s: %w", plan.HookID, plan.Interface, plan.Attach, err)
		}
		loaded.filters = append(loaded.filters, filter)
		states = append(states, PluginAttachmentState{
			HookID:       plan.HookID,
			Engine:       kernelEngineTC,
			Attach:       plan.Attach,
			Interface:    plan.Interface,
			Program:      plan.ObjectID + ":" + plan.ProgramRef,
			Mode:         plan.Mode,
			Priority:     int(plan.Priority),
			FilterHandle: fmt.Sprintf("0x%x", netlink.MakeHandle(0, plan.HandleMinor)),
			Status:       "attached",
		})
	}
	for _, plan := range item.attachments {
		if object := objects[plan.ObjectPath]; object != nil && object.coll != nil {
			loaded.objects = append(loaded.objects, loadedPluginObjectRef{
				PluginID:     plan.PluginID,
				ObjectID:     plan.ObjectID,
				ObjectPath:   plan.ObjectPath,
				ObjectSHA256: plan.ObjectSHA256,
				spec:         object.spec,
				coll:         object.coll,
			})
		}
	}
	loaded.objects = uniqueLoadedPluginObjectRefs(loaded.objects)
	return loaded, states, nil
}

func uniqueLoadedPluginObjectRefs(refs []loadedPluginObjectRef) []loadedPluginObjectRef {
	if len(refs) < 2 {
		return refs
	}
	seen := make(map[string]struct{}, len(refs))
	out := refs[:0]
	for _, ref := range refs {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%p", ref.PluginID, ref.ObjectID, ref.ObjectPath, ref.coll)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func cleanupLoadedPluginObjectCache(objects map[string]*loadedPluginObject) {
	for _, object := range objects {
		if object != nil && object.coll != nil {
			object.coll.Close()
			object.coll = nil
		}
	}
}

func loadPluginObjectForAttach(cache map[string]*loadedPluginObject, objectPath, expectedSHA256 string) (*loadedPluginObject, error) {
	if object, ok := cache[objectPath]; ok {
		return object, nil
	}
	spec, err := loadVerifiedPluginObjectCollectionSpec(objectPath, expectedSHA256)
	if err != nil {
		return nil, fmt.Errorf("load plugin object spec %s: %w", objectPath, err)
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, kernelCollectionOptions(nil))
	if err != nil {
		logKernelVerifierDetails(err)
		return nil, fmt.Errorf("load plugin object %s: %w", objectPath, err)
	}
	object := &loadedPluginObject{path: objectPath, spec: spec, coll: coll}
	cache[objectPath] = object
	return object, nil
}

func pluginProgramForAttach(object *loadedPluginObject, section, programRef string) (*ebpf.Program, error) {
	if object == nil || object.spec == nil || object.coll == nil {
		return nil, fmt.Errorf("plugin object is not loaded")
	}
	name := ""
	for candidateName, spec := range object.spec.Programs {
		if spec == nil || spec.SectionName != section {
			continue
		}
		if candidateName == programRef {
			name = candidateName
			break
		}
		if name == "" {
			name = candidateName
		}
	}
	if name == "" {
		return nil, fmt.Errorf("program section %q not found in %s", section, object.path)
	}
	prog := object.coll.Programs[name]
	if prog == nil {
		return nil, fmt.Errorf("program %q not loaded from %s", name, object.path)
	}
	return prog, nil
}

func attachPluginTCProgram(plan pluginTCAttachPlan, prog *ebpf.Program) (*netlink.BpfFilter, error) {
	if prog == nil {
		return nil, fmt.Errorf("nil program")
	}
	if err := ensureClsactQdisc(plan.IfIndex); err != nil {
		return nil, err
	}
	name := pluginTCFilterName(plan)
	if err := ensurePluginTCFilterSlotAvailable(plan, name); err != nil {
		return nil, err
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: plan.IfIndex,
			Handle:    netlink.MakeHandle(0, plan.HandleMinor),
			Parent:    pluginTCParent(plan.Attach),
			Priority:  plan.Priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func ensurePluginTCFilterSlotAvailable(plan pluginTCAttachPlan, name string) error {
	link, err := netlink.LinkByIndex(plan.IfIndex)
	if err != nil {
		return err
	}
	filters, err := netlink.FilterList(link, pluginTCParent(plan.Attach))
	if err != nil {
		return err
	}
	handle := netlink.MakeHandle(0, plan.HandleMinor)
	for _, item := range filters {
		bpf, ok := item.(*netlink.BpfFilter)
		if !ok || bpf == nil {
			continue
		}
		if bpf.Priority != plan.Priority || bpf.Handle != handle {
			continue
		}
		if bpf.Name == name {
			return nil
		}
		return fmt.Errorf("tc filter priority/handle slot already used by %q", bpf.Name)
	}
	return nil
}

func pluginTCParent(attach string) uint32 {
	if attach == "egress" {
		return netlink.HANDLE_MIN_EGRESS
	}
	return netlink.HANDLE_MIN_INGRESS
}

func pluginTCFilterName(plan pluginTCAttachPlan) string {
	value := "fwdplug_" + plan.PluginID + "_" + plan.HookID
	value = strings.NewReplacer(".", "_", ":", "_", "/", "_").Replace(value)
	if len(value) > 63 {
		return value[:63]
	}
	return value
}

func pluginDataplaneFingerprint(items []pluginDataplaneDesiredPlugin, states map[string]PluginRuntimeState) string {
	type fingerprintPlugin struct {
		ID          string               `json:"id"`
		Attachments []pluginTCAttachPlan `json:"attachments"`
		Warnings    []string             `json:"warnings,omitempty"`
	}
	type fingerprintState struct {
		ID     string `json:"id"`
		Mode   string `json:"mode"`
		Reason string `json:"reason,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	payload := struct {
		Plugins []fingerprintPlugin `json:"plugins"`
		States  []fingerprintState  `json:"states,omitempty"`
	}{Plugins: make([]fingerprintPlugin, 0, len(items))}
	for _, item := range items {
		payload.Plugins = append(payload.Plugins, fingerprintPlugin{
			ID:          item.plugin.ID,
			Attachments: append([]pluginTCAttachPlan(nil), item.attachments...),
			Warnings:    append([]string(nil), item.warnings...),
		})
	}
	for id, state := range states {
		payload.States = append(payload.States, fingerprintState{ID: id, Mode: state.Mode, Reason: state.Reason, Error: state.Error})
	}
	sort.Slice(payload.States, func(i, j int) bool {
		return payload.States[i].ID < payload.States[j].ID
	})
	data, _ := json.Marshal(payload)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}
