package app

import (
	"log"
	"sort"
	"strings"
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
	Plugins map[string]PluginRuntimeState
}

func (s pluginRuntimeSnapshot) stateFor(id string) (PluginRuntimeState, bool) {
	if len(s.Plugins) == 0 {
		return PluginRuntimeState{}, false
	}
	state, ok := s.Plugins[id]
	return state, ok
}

func applyPluginRuntimeSnapshot(catalog *PluginCatalog, snapshot pluginRuntimeSnapshot) {
	if catalog == nil || len(snapshot.Plugins) == 0 {
		return
	}
	for i := range catalog.Plugins {
		if state, ok := snapshot.stateFor(catalog.Plugins[i].ID); ok {
			catalog.Plugins[i].Runtime = state
		}
	}
}

func (pm *ProcessManager) pluginCatalogWithConfig(fallbackCfg *Config) PluginCatalog {
	cfg := fallbackCfg
	if pm != nil {
		if pm.cfg != nil {
			cfg = pm.cfg
		}
	}
	catalog := loadPluginCatalog(cfg)
	if pm != nil {
		catalog = applyPluginHookBindingsFromDB(catalog, pm.db)
	}
	if pm != nil && pm.pluginControlRuntime != nil {
		applyPluginRuntimeSnapshot(&catalog, pm.pluginControlRuntime.Snapshot())
	}
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

func (pm *ProcessManager) reconcilePluginsForRuntime() {
	if pm == nil {
		return
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
	}
	catalog = applyPluginHookBindingsFromDB(catalog, pm.db)
	var snapshot pluginRuntimeSnapshot
	if runtime, ok := pm.kernelRuntime.(pluginPipelineRuntime); ok {
		snapshot = runtime.ReconcilePlugins(catalog)
	} else if pm.pluginRuntime != nil {
		snapshot = pm.pluginRuntime.Reconcile(catalog)
	} else {
		return
	}
	for _, plugin := range catalog.Plugins {
		state, ok := snapshot.stateFor(plugin.ID)
		if !ok || state.Error == "" {
			continue
		}
		log.Printf("plugin runtime: %s: %s", plugin.ID, state.Error)
	}
}

func mergePluginRuntimeSnapshot(catalog *PluginCatalog, snapshot pluginRuntimeSnapshot) {
	if catalog == nil || len(snapshot.Plugins) == 0 {
		return
	}
	for i := range catalog.Plugins {
		next, ok := snapshot.stateFor(catalog.Plugins[i].ID)
		if !ok {
			continue
		}
		current := catalog.Plugins[i].Runtime
		if current.Mode == "" || current.Mode == pluginRuntimeModeManifestOnly || current.Mode == pluginRuntimeModeInvalid {
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
	return out
}
