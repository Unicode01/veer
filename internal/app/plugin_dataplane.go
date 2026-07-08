package app

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"forward/internal/store"
)

type pluginDataplaneRuntime interface {
	Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot
	Snapshot() pluginRuntimeSnapshot
	Close() error
}

type pluginPipelineRuntime interface {
	ReconcilePlugins(catalog PluginCatalog) pluginRuntimeSnapshot
	PluginSnapshot() pluginRuntimeSnapshot
}

type pluginRuntimeSnapshot struct {
	Plugins  map[string]PluginRuntimeState
	Surfaces map[string]PluginRuntimeSurface
}

type PluginRuntimeSurface struct {
	Capabilities      []string                 `json:"capabilities,omitempty"`
	VirtualInterfaces []PluginVirtualInterface `json:"virtual_interfaces,omitempty"`
	Objects           []PluginObject           `json:"objects,omitempty"`
	Hooks             []PluginHook             `json:"hooks,omitempty"`
	Resources         []PluginResource         `json:"resources,omitempty"`
	Actions           []PluginAction           `json:"actions,omitempty"`
	UI                *PluginUI                `json:"ui,omitempty"`
}

func (s pluginRuntimeSnapshot) stateFor(id string) (PluginRuntimeState, bool) {
	if len(s.Plugins) == 0 {
		return PluginRuntimeState{}, false
	}
	state, ok := s.Plugins[id]
	return state, ok
}

func applyPluginRuntimeSnapshot(catalog *PluginCatalog, snapshot pluginRuntimeSnapshot) {
	if catalog == nil {
		return
	}
	applyPluginRuntimeSurfaces(catalog, snapshot.Surfaces)
	for i := range catalog.Plugins {
		if state, ok := snapshot.stateFor(catalog.Plugins[i].ID); ok {
			catalog.Plugins[i].Runtime = state
		}
	}
}

func applyPluginRuntimeSurfaces(catalog *PluginCatalog, surfaces map[string]PluginRuntimeSurface) {
	if catalog == nil || len(surfaces) == 0 {
		return
	}
	for i := range catalog.Plugins {
		surface, ok := surfaces[catalog.Plugins[i].ID]
		if !ok {
			continue
		}
		applyPluginRuntimeSurface(&catalog.Plugins[i], surface)
	}
}

func loadPluginCatalogWithControlRegistration(cfg *Config) PluginCatalog {
	catalog := loadPluginCatalog(cfg)
	applyPluginControlRegistrationSurfaces(&catalog, cfg)
	return catalog
}

func applyPluginControlRegistrationSurfaces(catalog *PluginCatalog, cfg *Config) {
	if catalog == nil {
		return
	}
	rt, ok := newPluginControlRuntime(nil, cfg, nil).(*gojaPluginControlRuntime)
	if !ok || rt == nil {
		return
	}
	defer rt.Close()

	surfaces := make(map[string]PluginRuntimeSurface)
	for i := range catalog.Plugins {
		plugin := catalog.Plugins[i]
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
			continue
		}
		if ok, _ := pluginControlRegistrationAllowed(plugin); !ok {
			continue
		}
		surface, err := rt.runPluginControlWithSurface(plugin, pluginControlEvent{Kind: "register"}, true)
		if err != nil {
			catalog.Plugins[i].Status = pluginStatusError
			catalog.Plugins[i].Runtime = invalidPluginRuntimeState()
			catalog.Plugins[i].Error = err.Error()
			catalog.Plugins[i].staticDir = ""
			catalog.Plugins[i].AssetBasePath = ""
			continue
		}
		surfaces[plugin.ID] = surface
	}
	applyPluginRuntimeSurfaces(catalog, surfaces)
}

func pluginCatalogNeedsControlRegistration(catalog PluginCatalog) bool {
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive || plugin.controlMainPath == "" {
			continue
		}
		if len(plugin.Capabilities) == 0 &&
			len(plugin.VirtualInterfaces) == 0 &&
			len(plugin.Objects) == 0 &&
			len(plugin.Hooks) == 0 &&
			len(plugin.Resources) == 0 &&
			len(plugin.Actions) == 0 &&
			plugin.UI == nil {
			return true
		}
	}
	return false
}

func ensurePluginCatalogControlRegistration(catalog *PluginCatalog, cfg *Config) {
	if catalog == nil || !pluginCatalogNeedsControlRegistration(*catalog) {
		return
	}
	applyPluginControlRegistrationSurfaces(catalog, cfg)
}

func applyPluginRuntimeSurface(plugin *LoadedPlugin, surface PluginRuntimeSurface) {
	if plugin == nil || plugin.Builtin || plugin.Status != pluginStatusActive {
		return
	}
	plugin.Capabilities = append([]string(nil), surface.Capabilities...)
	plugin.VirtualInterfaces = append([]PluginVirtualInterface(nil), surface.VirtualInterfaces...)
	plugin.Objects = append([]PluginObject(nil), surface.Objects...)
	plugin.Hooks = append([]PluginHook(nil), surface.Hooks...)
	plugin.Resources = append([]PluginResource(nil), surface.Resources...)
	plugin.Actions = append([]PluginAction(nil), surface.Actions...)
	if surface.UI != nil {
		ui := *surface.UI
		plugin.UI = &ui
	} else {
		plugin.UI = nil
	}
	finalizePluginRuntimeSurface(plugin)
}

func finalizePluginRuntimeSurface(plugin *LoadedPlugin) {
	if plugin == nil || plugin.Builtin || plugin.Status != pluginStatusActive {
		return
	}
	if err := resolvePluginObjects(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
	if err := validatePluginHookProgramRefs(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
	if err := resolvePluginAssets(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
}

func pluginManifestOnlyRuntimeSnapshot(catalog PluginCatalog) pluginRuntimeSnapshot {
	states := make(map[string]PluginRuntimeState)
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		states[plugin.ID] = externalPluginRuntimeState()
	}
	return pluginRuntimeSnapshot{Plugins: states}
}

func completePluginRuntimeSnapshot(catalog PluginCatalog, snapshot pluginRuntimeSnapshot) pluginRuntimeSnapshot {
	if len(snapshot.Plugins) == 0 {
		return pluginManifestOnlyRuntimeSnapshot(catalog)
	}
	out := clonePluginRuntimeSnapshot(snapshot)
	if out.Plugins == nil {
		out.Plugins = make(map[string]PluginRuntimeState)
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Builtin || plugin.Status != pluginStatusActive {
			continue
		}
		if _, ok := out.Plugins[plugin.ID]; ok {
			continue
		}
		out.Plugins[plugin.ID] = externalPluginRuntimeState()
	}
	return out
}

func (pm *ProcessManager) pluginCatalogWithConfig(fallbackCfg *Config) PluginCatalog {
	cfg := fallbackCfg
	if pm != nil {
		if pm.cfg != nil {
			cfg = pm.cfg
		}
	}
	catalog := pm.pluginCatalogWithControlSurface(cfg)
	if pm != nil {
		if runtime, ok := pm.kernelRuntime.(pluginPipelineRuntime); ok {
			mergePluginRuntimeSnapshot(&catalog, runtime.PluginSnapshot())
			return catalog
		}
	}
	if pm == nil || pm.pluginRuntime == nil {
		return catalog
	}
	snapshot := pm.pluginRuntime.Reconcile(catalog)
	mergePluginRuntimeSnapshot(&catalog, snapshot)
	return catalog
}

func (pm *ProcessManager) pluginCatalogWithControlSurface(cfg *Config) PluginCatalog {
	if pm == nil || pm.pluginControlRuntime == nil {
		catalog := loadPluginCatalogWithControlRegistration(cfg)
		if pm == nil {
			return catalog
		}
		return applyPluginHookBindingsFromDB(catalog, pm.db)
	}

	catalog := loadPluginCatalog(cfg)
	snapshot := pm.pluginControlRuntime.Snapshot()
	if len(snapshot.Plugins) == 0 && len(snapshot.Surfaces) == 0 {
		snapshot = pm.pluginControlRuntime.Reconcile(catalog)
	}
	applyPluginRuntimeSnapshot(&catalog, snapshot)
	return applyPluginHookBindingsFromDB(catalog, pm.db)
}

func (pm *ProcessManager) reconcilePluginDataplaneForCatalog(catalog PluginCatalog) (pluginRuntimeSnapshot, bool) {
	if pm == nil {
		return pluginRuntimeSnapshot{}, false
	}
	if runtime, ok := pm.kernelRuntime.(pluginPipelineRuntime); ok {
		if _, ok := pm.kernelRuntime.(kernelRuleRuntimeWithPluginCatalog); ok {
			pm.redistributeWorkers()
			return completePluginRuntimeSnapshot(catalog, runtime.PluginSnapshot()), true
		}
		return completePluginRuntimeSnapshot(catalog, runtime.ReconcilePlugins(catalog)), false
	}
	if pm.pluginRuntime != nil {
		return completePluginRuntimeSnapshot(catalog, pm.pluginRuntime.Reconcile(catalog)), false
	}
	return pluginManifestOnlyRuntimeSnapshot(catalog), false
}

func (pm *ProcessManager) reconcilePluginsForRuntime() pluginRuntimeSnapshot {
	if pm == nil {
		return pluginRuntimeSnapshot{}
	}
	catalog := loadPluginCatalog(pm.cfg)
	if pm.pluginControlRuntime != nil {
		controlSnapshot := pm.pluginControlRuntime.Reconcile(catalog)
		applyPluginRuntimeSnapshot(&catalog, controlSnapshot)
		for _, plugin := range catalog.Plugins {
			state, ok := controlSnapshot.stateFor(plugin.ID)
			if !ok || state.Error == "" {
				continue
			}
			log.Printf("plugin control runtime: %s: %s", plugin.ID, state.Error)
		}
	} else {
		applyPluginControlRegistrationSurfaces(&catalog, pm.cfg)
	}
	refreshCorePlans := pluginCatalogHasActiveEgressNATPlansResource(catalog, pm.cfg) || pluginCatalogHasActiveForwardRulePlansResource(catalog, pm.cfg)
	catalog = applyPluginHookBindingsFromDB(catalog, pm.db)
	snapshot, redistributed := pm.reconcilePluginDataplaneForCatalog(catalog)
	for _, plugin := range catalog.Plugins {
		state, ok := snapshot.stateFor(plugin.ID)
		if !ok || state.Error == "" {
			continue
		}
		log.Printf("plugin runtime: %s: %s", plugin.ID, state.Error)
	}
	pm.markPluginReconcileResourcesAfterRuntime(catalog, snapshot)
	if refreshCorePlans && !redistributed {
		pm.redistributeWorkers()
	}
	return snapshot
}

func (pm *ProcessManager) ApplyPluginResourceReconcileFromControl(plugin LoadedPlugin, resource PluginResource) error {
	if pm == nil || pm.db == nil {
		return fmt.Errorf("plugin process manager is unavailable")
	}
	if resource.RuntimeUpdate != "plugin_reconcile" {
		return applyPluginResourceRuntimeUpdate(pm.db, pm, plugin, resource)
	}
	if ok, reason := pluginControlStabilityAllowed(plugin, pm.cfg); !ok {
		err := fmt.Errorf("%s", reason)
		_ = markPluginRuntimeError(pm.db, plugin.ID, "resource", resource.ID, err)
		return err
	}
	catalog := loadPluginCatalogWithControlRegistration(pm.cfg)
	refreshCorePlans := pluginCatalogHasActiveEgressNATPlansResource(catalog, pm.cfg) || pluginCatalogHasActiveForwardRulePlansResource(catalog, pm.cfg) || pluginResourceAffectsActiveCorePlans(plugin, resource, pm.cfg)
	catalog = applyPluginHookBindingsFromDB(catalog, pm.db)
	snapshot, redistributed := pm.reconcilePluginDataplaneForCatalog(catalog)
	for _, plugin := range catalog.Plugins {
		state, ok := snapshot.stateFor(plugin.ID)
		if !ok || state.Error == "" {
			continue
		}
		log.Printf("plugin runtime: %s: %s", plugin.ID, state.Error)
	}
	pm.markPluginReconcileResourcesAfterRuntime(catalog, snapshot)
	if refreshCorePlans && !redistributed {
		pm.redistributeWorkers()
	}
	return pluginReconcileResourceError(pm.db, plugin.ID, resource.ID)
}

func (pm *ProcessManager) markPluginReconcileResourcesAfterRuntime(catalog PluginCatalog, snapshot pluginRuntimeSnapshot) {
	if pm == nil || pm.db == nil {
		return
	}
	for _, plugin := range catalog.Plugins {
		if plugin.Status != pluginStatusActive {
			continue
		}
		state, hasState := snapshot.stateFor(plugin.ID)
		for _, resource := range plugin.Resources {
			if resource.RuntimeUpdate != "plugin_reconcile" {
				continue
			}
			status, err := store.PluginRuntimeStatusOrNil(pm.db, plugin.ID, "resource", resource.ID)
			if err != nil {
				log.Printf("plugin runtime status lookup failed: %s/%s: %v", plugin.ID, resource.ID, err)
				continue
			}
			if status == nil {
				continue
			}
			if hasState && strings.TrimSpace(state.Error) != "" {
				if err := markPluginRuntimeError(pm.db, plugin.ID, "resource", resource.ID, fmt.Errorf("%s", state.Error)); err != nil {
					log.Printf("plugin runtime status error update failed: %s/%s: %v", plugin.ID, resource.ID, err)
				}
				continue
			}
			if status.Status == "applied" && status.LastError == "" && status.AppliedRevision == status.Revision {
				continue
			}
			if err := markPluginRuntimeAppliedToCurrentRevision(pm.db, plugin.ID, "resource", resource.ID); err != nil {
				log.Printf("plugin runtime status applied update failed: %s/%s: %v", plugin.ID, resource.ID, err)
			}
		}
	}
}

func mergePluginRuntimeSnapshot(catalog *PluginCatalog, snapshot pluginRuntimeSnapshot) {
	if catalog == nil {
		return
	}
	applyPluginRuntimeSurfaces(catalog, snapshot.Surfaces)
	for i := range catalog.Plugins {
		next, ok := snapshot.stateFor(catalog.Plugins[i].ID)
		if !ok {
			continue
		}
		current := catalog.Plugins[i].Runtime
		if current.Mode == "" || current.Mode == pluginRuntimeModeRegistered || current.Mode == pluginRuntimeModeInvalid {
			catalog.Plugins[i].Runtime = next
			continue
		}
		if next.Mode == pluginRuntimeModeDataplane || next.Attached || next.AttachmentCount > 0 || len(next.Attachments) > 0 {
			next.Reason = joinPluginRuntimeText(current.Reason, next.Reason)
			next.Error = joinPluginRuntimeText(current.Error, next.Error)
			catalog.Plugins[i].Runtime = next
			continue
		}
		if next.Error == "" {
			continue
		}
		current.Error = joinPluginRuntimeText(current.Error, next.Error)
		current.Reason = joinPluginRuntimeText(current.Reason, next.Reason)
		catalog.Plugins[i].Runtime = current
	}
}

func joinPluginRuntimeText(values ...string) string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, "; ")
}

func pluginRuntimeErrorState(message string) PluginRuntimeState {
	return PluginRuntimeState{
		Mode:       pluginRuntimeModeError,
		Attachable: false,
		Attached:   false,
		Reason:     "plugin runtime failed",
		Error:      message,
	}
}

func pluginDataplaneStabilityAllowed(plugin LoadedPlugin, cfg *Config) (bool, string) {
	stability := strings.TrimSpace(strings.ToLower(plugin.Stability))
	if stability == "" {
		stability = pluginStabilityLab
	}
	switch stability {
	case pluginStabilityStable, pluginStabilityPreview, pluginStabilityLab:
		return true, ""
	case pluginStabilityDeprecated:
		return false, "plugin stability is deprecated; external dataplane attach is disabled"
	default:
		return false, "plugin stability is unknown; external dataplane attach is disabled"
	}
}

func sortedPluginAttachmentStates(states []PluginAttachmentState) []PluginAttachmentState {
	if len(states) == 0 {
		return nil
	}
	out := append([]PluginAttachmentState(nil), states...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		if out[i].Attach != out[j].Attach {
			return out[i].Attach < out[j].Attach
		}
		if out[i].Stage != out[j].Stage {
			return out[i].Stage < out[j].Stage
		}
		if out[i].ChainSlot != out[j].ChainSlot {
			if out[i].ChainSlot == 0 {
				return false
			}
			if out[j].ChainSlot == 0 {
				return true
			}
			return out[i].ChainSlot < out[j].ChainSlot
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].HookID != out[j].HookID {
			return out[i].HookID < out[j].HookID
		}
		return out[i].Program < out[j].Program
	})
	return out
}

func clonePluginRuntimeSnapshot(snapshot pluginRuntimeSnapshot) pluginRuntimeSnapshot {
	out := pluginRuntimeSnapshot{Plugins: make(map[string]PluginRuntimeState, len(snapshot.Plugins))}
	for id, state := range snapshot.Plugins {
		state.Attachments = sortedPluginAttachmentStates(state.Attachments)
		out.Plugins[id] = state
	}
	if len(snapshot.Surfaces) > 0 {
		out.Surfaces = make(map[string]PluginRuntimeSurface, len(snapshot.Surfaces))
		for id, surface := range snapshot.Surfaces {
			out.Surfaces[id] = clonePluginRuntimeSurface(surface)
		}
	}
	return out
}

func clonePluginRuntimeSurface(surface PluginRuntimeSurface) PluginRuntimeSurface {
	out := PluginRuntimeSurface{
		Capabilities:      append([]string(nil), surface.Capabilities...),
		VirtualInterfaces: append([]PluginVirtualInterface(nil), surface.VirtualInterfaces...),
		Objects:           append([]PluginObject(nil), surface.Objects...),
		Hooks:             append([]PluginHook(nil), surface.Hooks...),
		Resources:         append([]PluginResource(nil), surface.Resources...),
		Actions:           append([]PluginAction(nil), surface.Actions...),
	}
	if surface.UI != nil {
		ui := *surface.UI
		out.UI = &ui
	}
	return out
}
