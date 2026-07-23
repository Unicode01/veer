package app

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

type pluginDataplaneRuntime interface {
	Reconcile(catalog PluginCatalog) pluginRuntimeSnapshot
	Snapshot() pluginRuntimeSnapshot
	Close() error
}

type disabledPluginDataplaneRuntime struct{}

func (disabledPluginDataplaneRuntime) Reconcile(PluginCatalog) pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{}
}

func (disabledPluginDataplaneRuntime) Snapshot() pluginRuntimeSnapshot {
	return pluginRuntimeSnapshot{}
}

func (disabledPluginDataplaneRuntime) Close() error {
	return nil
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
	Capabilities       []string                  `json:"capabilities,omitempty"`
	VirtualInterfaces  []PluginVirtualInterface  `json:"virtual_interfaces,omitempty"`
	Objects            []PluginObject            `json:"objects,omitempty"`
	Hooks              []PluginHook              `json:"hooks,omitempty"`
	Resources          []PluginResource          `json:"resources,omitempty"`
	Actions            []PluginAction            `json:"actions,omitempty"`
	Services           []PluginService           `json:"services,omitempty"`
	EventSubscriptions []PluginEventSubscription `json:"event_subscriptions,omitempty"`
	RingSubscriptions  []PluginRingSubscription  `json:"ring_subscriptions,omitempty"`
	UI                 *PluginUI                 `json:"ui,omitempty"`
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
	enforcePluginCatalogGlobalResourceLimits(catalog)
}

func loadPluginCatalogWithControlRegistration(cfg *Config) PluginCatalog {
	catalog := loadPluginCatalog(cfg)
	applyPluginControlRegistrationSurfaces(&catalog, cfg)
	return catalog
}

func loadPluginCatalogWithControlRegistrationAndState(cfg *Config, db store.RuleStore) PluginCatalog {
	catalog := loadPluginCatalogWithState(cfg, db)
	applyPluginControlRegistrationSurfaces(&catalog, cfg)
	return applyPluginStatesFromDB(catalog, db)
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

	for _, i := range pluginCatalogExecutionIndexes(*catalog) {
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
			*catalog = resolvePluginCatalogRelationships(*catalog, currentPluginHostEnvironment())
			continue
		}
		applyPluginRuntimeSurface(&catalog.Plugins[i], surface)
		if catalog.Plugins[i].Status != pluginStatusActive {
			*catalog = resolvePluginCatalogRelationships(*catalog, currentPluginHostEnvironment())
		}
	}
	enforcePluginCatalogGlobalResourceLimits(catalog)
	*catalog = resolvePluginCatalogRelationships(*catalog, currentPluginHostEnvironment())
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
			len(plugin.Services) == 0 &&
			len(plugin.EventSubscriptions) == 0 &&
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
	plugin.Hooks = clonePluginHooks(surface.Hooks)
	plugin.Resources = append([]PluginResource(nil), surface.Resources...)
	plugin.Actions = append([]PluginAction(nil), surface.Actions...)
	plugin.Services = clonePluginServices(surface.Services)
	plugin.EventSubscriptions = append([]PluginEventSubscription(nil), surface.EventSubscriptions...)
	plugin.RingSubscriptions = append([]PluginRingSubscription(nil), surface.RingSubscriptions...)
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
	if plugin.resourceLimits.ObjectsPerPlugin == 0 {
		plugin.resourceLimits = pluginResourceLimitsFromConfig(nil)
	}
	if err := validatePluginSurfaceDefinitionLimits(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
	if err := validatePluginServices(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
	if err := validatePluginEventSubscriptions(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
		return
	}
	if err := validatePluginRingSubscriptions(plugin); err != nil {
		plugin.Status = pluginStatusError
		plugin.Runtime = invalidPluginRuntimeState()
		plugin.Error = err.Error()
		plugin.staticDir = ""
		plugin.AssetBasePath = ""
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
	if err := validatePluginAggregateObjectLimits(plugin); err != nil {
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
			catalog = applyPluginStatesFromDB(catalog, pm.db)
			catalog.HotReload = pm.snapshotPluginCatalogHotReloadStatus()
			return catalog
		}
	}
	if pm == nil || pm.pluginRuntime == nil {
		if pm != nil {
			catalog.HotReload = pm.snapshotPluginCatalogHotReloadStatus()
		}
		return catalog
	}
	snapshot := pm.pluginRuntime.Reconcile(catalog)
	mergePluginRuntimeSnapshot(&catalog, snapshot)
	catalog = applyPluginStatesFromDB(catalog, pm.db)
	catalog.HotReload = pm.snapshotPluginCatalogHotReloadStatus()
	return catalog
}

func (pm *ProcessManager) pluginCatalogWithControlSurface(cfg *Config) PluginCatalog {
	if pm == nil || pm.pluginControlRuntime == nil {
		var db store.RuleStore
		if pm != nil {
			db = pm.db
		}
		catalogCfg := cfg
		sourceDir := ""
		if pm != nil {
			catalogCfg, sourceDir = pm.appliedPluginCatalogConfig(cfg)
		}
		catalog := loadPluginCatalogWithControlRegistrationAndState(catalogCfg, db)
		if sourceDir != "" {
			catalog.Directory = sourceDir
		}
		if pm == nil {
			return catalog
		}
		return applyPluginHookBindingsFromDB(catalog, pm.db)
	}

	catalogCfg, sourceDir := pm.appliedPluginCatalogConfig(cfg)
	catalog := loadPluginCatalogWithState(catalogCfg, pm.db)
	catalog.Directory = sourceDir
	snapshot := pm.pluginControlRuntime.Snapshot()
	if len(snapshot.Plugins) == 0 && len(snapshot.Surfaces) == 0 {
		// This path is used by the initial dataplane reconcile while redistributeMu
		// is held. Registration is side-effect free; persistent onReconcile handlers
		// may synchronously request another redistribution and must run outside it.
		applyPluginControlRegistrationSurfaces(&catalog, catalogCfg)
		catalog = applyPluginStatesFromDB(catalog, pm.db)
		return applyPluginHookBindingsFromDB(catalog, pm.db)
	}
	applyPluginRuntimeSnapshot(&catalog, snapshot)
	catalog = applyPluginStatesFromDB(catalog, pm.db)
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
	snapshot, _ := pm.reconcilePluginsForRuntimeWithError()
	return snapshot
}

func (pm *ProcessManager) reconcilePluginsForRuntimeWithError() (pluginRuntimeSnapshot, error) {
	if pm == nil {
		return pluginRuntimeSnapshot{}, nil
	}
	catalogCfg, sourceDir := pm.appliedPluginCatalogConfig(pm.cfg)
	catalog := loadPluginCatalogWithState(catalogCfg, pm.db)
	catalog.Directory = sourceDir
	return pm.reconcilePluginCatalogForRuntime(catalog)
}

func (pm *ProcessManager) reconcilePluginCatalogForRuntime(catalog PluginCatalog) (pluginRuntimeSnapshot, error) {
	var migrationRuntime pluginResourceMigrationTransactionRuntime
	migrationOwned := false
	migrationFinished := false
	if runtime, ok := pm.pluginControlRuntime.(pluginResourceMigrationTransactionRuntime); ok {
		migrationRuntime = runtime
		if migrationRuntime.PluginResourceMigrationTransactionID() == "" {
			if err := migrationRuntime.BeginPluginResourceMigrationTransaction(); err != nil {
				return pluginRuntimeSnapshot{}, fmt.Errorf("begin plugin resource migration transaction: %w", err)
			}
			migrationOwned = true
		}
		defer func() {
			if migrationOwned && !migrationFinished {
				_ = migrationRuntime.RollbackPluginResourceMigrationTransaction()
			}
		}()
	}
	issues := make(map[string]string)
	if pm.pluginControlRuntime != nil {
		controlSnapshot := pm.pluginControlRuntime.Reconcile(catalog)
		applyPluginRuntimeSnapshot(&catalog, controlSnapshot)
		catalog = applyPluginStatesFromDB(catalog, pm.db)
		for _, plugin := range catalog.Plugins {
			state, ok := controlSnapshot.stateFor(plugin.ID)
			if !ok || state.Error == "" {
				continue
			}
			issues[plugin.ID] = state.Error
			log.Printf("plugin control runtime: %s: %s", plugin.ID, state.Error)
		}
	} else {
		applyPluginControlRegistrationSurfaces(&catalog, pm.cfg)
		catalog = applyPluginStatesFromDB(catalog, pm.db)
	}
	refreshCorePlans := pluginCatalogMayAffectActiveCorePlans(catalog, pm.cfg)
	catalog = applyPluginHookBindingsFromDB(catalog, pm.db)
	snapshot, redistributed := pm.reconcilePluginDataplaneForCatalog(catalog)
	migrationFailed := false
	migrationRuntimes, pendingMigrations := pendingPluginEBPFStateMigrationsForProcess(pm)
	var completedMigrations []PluginEBPFStateMigration
	if len(pendingMigrations) > 0 {
		migrator, ok := pm.pluginControlRuntime.(pluginControlEBPFStateMigrator)
		if !ok || migrator == nil {
			for _, migration := range pendingMigrations {
				issues[migration.PluginID] = "plugin control runtime does not support eBPF state migration"
			}
			migrationFailed = true
		} else {
			var failures map[string]error
			completedMigrations, failures = migrator.ApplyPluginEBPFStateMigrations(catalog, snapshot, pendingMigrations)
			for pluginID, err := range failures {
				issues[pluginID] = err.Error()
				log.Printf("plugin eBPF state migration: %s: %v", pluginID, err)
				migrationFailed = true
			}
		}
	}
	if reconciler, ok := pm.pluginControlRuntime.(pluginControlPostDataplaneReconciler); ok && !migrationFailed {
		for pluginID, err := range reconciler.ReapplyPluginRuntimeResourcesAfterDataplane(catalog, snapshot) {
			issues[pluginID] = err.Error()
			log.Printf("plugin post-dataplane runtime resource replay: %s: %v", pluginID, err)
		}
	}
	for _, plugin := range catalog.Plugins {
		state, ok := snapshot.stateFor(plugin.ID)
		if !ok || state.Error == "" {
			continue
		}
		issues[plugin.ID] = state.Error
		log.Printf("plugin runtime: %s: %s", plugin.ID, state.Error)
	}
	if len(issues) == 0 {
		if migrationRuntime != nil && migrationOwned {
			if err := migrationRuntime.CommitPluginResourceMigrationTransaction(); err != nil {
				return snapshot, fmt.Errorf("commit plugin resource migration transaction: %w", err)
			}
			migrationFinished = true
		}
		for _, runtime := range migrationRuntimes {
			runtime.CompletePluginEBPFStateMigrations(completedMigrations)
		}
		pm.markPluginReconcileResourcesAfterRuntime(catalog, snapshot)
		if refreshCorePlans && !redistributed {
			pm.redistributeWorkers()
		}
		return snapshot, nil
	}
	if migrationRuntime != nil && migrationOwned {
		if err := migrationRuntime.RollbackPluginResourceMigrationTransaction(); err != nil {
			issues["resource_migration"] = err.Error()
		}
		migrationFinished = true
	}
	pm.markPluginReconcileResourcesAfterRuntime(catalog, snapshot)
	if refreshCorePlans {
		pm.redistributeWorkers()
	}
	ids := make([]string, 0, len(issues))
	for id := range issues {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	messages := make([]string, 0, len(ids))
	for _, id := range ids {
		messages = append(messages, id+": "+issues[id])
	}
	return snapshot, fmt.Errorf("plugin runtime update failed: %s", strings.Join(messages, "; "))
}

func pendingPluginEBPFStateMigrationsForProcess(pm *ProcessManager) ([]pluginEBPFStateMigrationRuntime, []PluginEBPFStateMigration) {
	if pm == nil {
		return nil, nil
	}
	runtimes := make([]pluginEBPFStateMigrationRuntime, 0, 2)
	for _, candidate := range []any{pm.kernelRuntime, pm.pluginRuntime} {
		if runtime, ok := candidate.(pluginEBPFStateMigrationRuntime); ok && runtime != nil {
			runtimes = append(runtimes, runtime)
		}
	}
	seen := make(map[string]struct{})
	pending := make([]PluginEBPFStateMigration, 0)
	for _, runtime := range runtimes {
		for _, migration := range runtime.PendingPluginEBPFStateMigrations() {
			if _, duplicate := seen[migration.key()]; duplicate {
				continue
			}
			seen[migration.key()] = struct{}{}
			pending = append(pending, migration)
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].key() < pending[j].key() })
	return runtimes, pending
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
	catalogCfg := pluginCatalogConfigForProcess(pm, pm.cfg)
	catalog := loadPluginCatalogWithControlRegistrationAndState(catalogCfg, pm.db)
	refreshCorePlans := pluginCatalogMayAffectActiveCorePlans(catalog, catalogCfg) || pluginResourceAffectsActiveCorePlans(plugin, resource, catalogCfg)
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
		if next.WorkerQueue == nil {
			next.WorkerQueue = current.WorkerQueue
		}
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

func combinePluginDataplaneSnapshots(catalog PluginCatalog, snapshots ...pluginRuntimeSnapshot) pluginRuntimeSnapshot {
	result := pluginManifestOnlyRuntimeSnapshot(catalog)
	if result.Plugins == nil {
		result.Plugins = make(map[string]PluginRuntimeState)
	}
	for _, snapshot := range snapshots {
		for id, next := range snapshot.Plugins {
			result.Plugins[id] = combinePluginRuntimeStates(result.Plugins[id], next)
		}
		if len(snapshot.Surfaces) > 0 {
			if result.Surfaces == nil {
				result.Surfaces = make(map[string]PluginRuntimeSurface)
			}
			for id, surface := range snapshot.Surfaces {
				result.Surfaces[id] = surface
			}
		}
	}
	return result
}

func combinePluginRuntimeStates(current, next PluginRuntimeState) PluginRuntimeState {
	if current.Mode == "" || current.Mode == pluginRuntimeModeRegistered || current.Mode == pluginRuntimeModeInvalid {
		current = next
	} else if next.Mode != "" && next.Mode != pluginRuntimeModeRegistered && next.Mode != pluginRuntimeModeInvalid {
		current.Attachments = append(current.Attachments, next.Attachments...)
		current.Attachable = current.Attachable || next.Attachable
		current.Attached = current.Attached || next.Attached
		current.Reason = joinPluginRuntimeText(current.Reason, next.Reason)
		current.Error = joinPluginRuntimeText(current.Error, next.Error)
		if next.WorkerQueue != nil {
			current.WorkerQueue = next.WorkerQueue
		}
		if next.EventBus != nil {
			current.EventBus = next.EventBus
		}
		if next.Operations != nil {
			current.Operations = next.Operations
		}
		if next.RingBuffers != nil {
			current.RingBuffers = next.RingBuffers
		}
		if next.ControlHealth != nil {
			current.ControlHealth = next.ControlHealth
		}
		if next.Isolation != nil {
			current.Isolation = next.Isolation
		}
		if len(next.Metrics) > 0 {
			current.Metrics = append(current.Metrics, next.Metrics...)
		}
		if len(next.Leases) > 0 {
			current.Leases = append(current.Leases, next.Leases...)
		}
		if current.Error != "" {
			current.Mode = pluginRuntimeModeError
		} else if current.Attached || len(current.Attachments) > 0 {
			current.Mode = pluginRuntimeModeDataplane
		} else if next.Mode != "" {
			current.Mode = next.Mode
		}
	}
	current.Attachments = uniquePluginAttachmentStates(current.Attachments)
	current.AttachmentCount = len(current.Attachments)
	current.Attached = current.Attached || current.AttachmentCount > 0
	return current
}

func uniquePluginAttachmentStates(states []PluginAttachmentState) []PluginAttachmentState {
	if len(states) < 2 {
		return sortedPluginAttachmentStates(states)
	}
	seen := make(map[string]struct{}, len(states))
	out := make([]PluginAttachmentState, 0, len(states))
	for _, state := range states {
		key := strings.Join([]string{
			state.Engine,
			state.HookID,
			state.Attach,
			state.Stage,
			state.Interface,
			state.Program,
			strconv.Itoa(state.ChainSlot),
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, state)
	}
	return sortedPluginAttachmentStates(out)
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
		for i := range state.Attachments {
			state.Attachments[i].Before = append([]string(nil), state.Attachments[i].Before...)
			state.Attachments[i].After = append([]string(nil), state.Attachments[i].After...)
			state.Attachments[i].PacketMetadata = append([]PluginPacketMetadataBinding(nil), state.Attachments[i].PacketMetadata...)
			if state.Attachments[i].Metrics != nil {
				metrics := *state.Attachments[i].Metrics
				state.Attachments[i].Metrics = &metrics
			}
		}
		if state.WorkerQueue != nil {
			queue := *state.WorkerQueue
			state.WorkerQueue = &queue
		}
		if state.EventBus != nil {
			events := *state.EventBus
			events.Subscriptions = append([]PluginEventSubscriptionState(nil), state.EventBus.Subscriptions...)
			state.EventBus = &events
		}
		if state.Operations != nil {
			operations := *state.Operations
			operations.ByStatus = make(map[string]int, len(state.Operations.ByStatus))
			for status, count := range state.Operations.ByStatus {
				operations.ByStatus[status] = count
			}
			state.Operations = &operations
		}
		if state.RingBuffers != nil {
			rings := *state.RingBuffers
			rings.Subscriptions = append([]PluginRingSubscriptionState(nil), state.RingBuffers.Subscriptions...)
			state.RingBuffers = &rings
		}
		if state.ControlHealth != nil {
			health := *state.ControlHealth
			health.Circuits = append([]PluginControlCircuitState(nil), state.ControlHealth.Circuits...)
			state.ControlHealth = &health
		}
		if len(state.Metrics) > 0 {
			state.Metrics = append([]PluginMetricState(nil), state.Metrics...)
			for i := range state.Metrics {
				if len(state.Metrics[i].Labels) == 0 {
					continue
				}
				labels := make(map[string]string, len(state.Metrics[i].Labels))
				for key, value := range state.Metrics[i].Labels {
					labels[key] = value
				}
				state.Metrics[i].Labels = labels
			}
		}
		state.Leases = append([]PluginResourceLeaseState(nil), state.Leases...)
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
		Capabilities:       append([]string(nil), surface.Capabilities...),
		VirtualInterfaces:  append([]PluginVirtualInterface(nil), surface.VirtualInterfaces...),
		Objects:            append([]PluginObject(nil), surface.Objects...),
		Hooks:              clonePluginHooks(surface.Hooks),
		Resources:          append([]PluginResource(nil), surface.Resources...),
		Actions:            append([]PluginAction(nil), surface.Actions...),
		Services:           clonePluginServices(surface.Services),
		EventSubscriptions: append([]PluginEventSubscription(nil), surface.EventSubscriptions...),
		RingSubscriptions:  append([]PluginRingSubscription(nil), surface.RingSubscriptions...),
	}
	if surface.UI != nil {
		ui := *surface.UI
		out.UI = &ui
	}
	return out
}

func clonePluginHooks(hooks []PluginHook) []PluginHook {
	if len(hooks) == 0 {
		return nil
	}
	out := make([]PluginHook, len(hooks))
	for i, hook := range hooks {
		out[i] = hook
		out[i].Before = append([]string(nil), hook.Before...)
		out[i].After = append([]string(nil), hook.After...)
		out[i].Context = append([]string(nil), hook.Context...)
		out[i].Interfaces = append([]string(nil), hook.Interfaces...)
		out[i].PacketMetadata = append([]PluginPacketMetadataBinding(nil), hook.PacketMetadata...)
	}
	return out
}
