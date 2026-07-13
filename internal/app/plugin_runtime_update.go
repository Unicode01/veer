package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

type PluginResourceRecord struct {
	Key       string          `json:"key"`
	Data      json.RawMessage `json:"data"`
	Enabled   bool            `json:"enabled"`
	Revision  int64           `json:"revision"`
	UpdatedAt string          `json:"updated_at,omitempty"`
}

type pluginRuntimeDataApplier interface {
	ApplyPluginResourceData(plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error
	ApplyPluginAction(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error
}

var errPluginRuntimeTargetNotLoaded = errors.New("plugin runtime target is not loaded")

func pluginResourceMutationStatus(resource PluginResource) string {
	switch resource.RuntimeUpdate {
	case "manual", "plugin_reconcile", "runtime_apply":
		return "pending"
	default:
		return "stored"
	}
}

func markPluginResourceMutation(db store.RuleStore, plugin LoadedPlugin, resource PluginResource) error {
	return store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
		PluginID:   plugin.ID,
		TargetType: "resource",
		TargetID:   resource.ID,
		Status:     pluginResourceMutationStatus(resource),
		LastError:  "",
	})
}

func applyPluginResourceRuntimeUpdate(db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource) error {
	cfg := processConfigForPluginRuntimeUpdate(pm)
	refreshCorePlans := pluginResourceAffectsActiveCorePlans(plugin, resource, cfg)
	switch resource.RuntimeUpdate {
	case "none", "manual", "":
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	case "plugin_reconcile":
		if ok, reason := pluginControlStabilityAllowed(plugin, cfg); !ok {
			err := fmt.Errorf("%s", reason)
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		if pm == nil {
			err := fmt.Errorf("plugin_reconcile runtime update requires process manager")
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		pm.reconcilePluginsForRuntime()
		if err := pluginReconcileResourceError(db, plugin.ID, resource.ID); err != nil {
			redistributePluginCorePlans(pm, refreshCorePlans)
			return err
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "resource", resource.ID); err != nil {
			return err
		}
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	case "runtime_apply":
		if ok, reason := pluginControlStabilityAllowed(plugin, cfg); !ok {
			err := fmt.Errorf("%s", reason)
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		appliers := pluginRuntimeDataAppliersForProcess(pm)
		if len(appliers) == 0 {
			err := fmt.Errorf("plugin runtime data applier is unavailable")
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		records, err := loadPluginResourceRecords(db, plugin, resource)
		if err != nil {
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		if err := applyPluginResourceDataWithAppliers(appliers, plugin, resource, records); err != nil {
			_ = markPluginRuntimeError(db, plugin.ID, "resource", resource.ID, err)
			return err
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "resource", resource.ID); err != nil {
			return err
		}
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	default:
		return fmt.Errorf("unsupported resource runtime_update %q", resource.RuntimeUpdate)
	}
}

func applyPluginActionRuntimeUpdate(db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	cfg := processConfigForPluginRuntimeUpdate(pm)
	refreshCorePlans := pluginMayAffectActiveCorePlans(plugin, cfg)
	switch action.RuntimeUpdate {
	case "none", "":
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	case "plugin_reconcile":
		if ok, reason := pluginControlStabilityAllowed(plugin, cfg); !ok {
			err := fmt.Errorf("%s", reason)
			_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
			return err
		}
		if pm == nil {
			err := fmt.Errorf("plugin_reconcile runtime update requires process manager")
			_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
			return err
		}
		snapshot := pm.reconcilePluginsForRuntime()
		if err := pluginReconcileActionError(snapshot, plugin.ID); err != nil {
			redistributePluginCorePlans(pm, refreshCorePlans)
			return err
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "action", action.ID); err != nil {
			return err
		}
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	case "runtime_apply":
		if ok, reason := pluginControlStabilityAllowed(plugin, cfg); !ok {
			err := fmt.Errorf("%s", reason)
			_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
			return err
		}
		appliers := pluginRuntimeDataAppliersForProcess(pm)
		if len(appliers) == 0 {
			err := fmt.Errorf("plugin runtime data applier is unavailable")
			_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
			return err
		}
		if err := applyPluginActionWithAppliers(appliers, plugin, action, payload); err != nil {
			_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
			return err
		}
		if err := markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "action", action.ID); err != nil {
			return err
		}
		redistributePluginCorePlans(pm, refreshCorePlans)
		return nil
	default:
		return fmt.Errorf("unsupported action runtime_update %q", action.RuntimeUpdate)
	}
}

func queryPluginActionRuntime(pm *ProcessManager, plugin LoadedPlugin, action PluginAction, payload json.RawMessage) (any, error) {
	if action.RuntimeUpdate != "runtime_query" {
		return nil, fmt.Errorf("action %s is not a runtime query", action.ID)
	}
	if ok, reason := pluginControlStabilityAllowed(plugin, processConfigForPluginRuntimeUpdate(pm)); !ok {
		return nil, fmt.Errorf("%s", reason)
	}
	if pm == nil || pm.pluginControlRuntime == nil {
		return nil, fmt.Errorf("plugin runtime query requires process manager")
	}
	return pm.pluginControlRuntime.QueryPluginAction(plugin, action, payload)
}

func pluginResourceAffectsActiveCorePlans(plugin LoadedPlugin, resource PluginResource, cfg *Config) bool {
	return (pluginResourceAffectsCoreEgressNAT(resource) ||
		pluginResourceAffectsCoreForwardRules(resource) ||
		pluginResourceAffectsCoreIPv6Assignments(resource) ||
		pluginResourceAffectsCoreDHCPv4(resource)) && pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func pluginMayAffectActiveCorePlans(plugin LoadedPlugin, cfg *Config) bool {
	return (pluginHasEgressNATPlansResource(plugin) ||
		pluginHasForwardRulePlansResource(plugin) ||
		pluginHasIPv6AssignmentPlansResource(plugin) ||
		pluginHasDHCPv4PlansResource(plugin)) && pluginCoreResourceStabilityAllowed(plugin, cfg)
}

func processConfigForPluginRuntimeUpdate(pm *ProcessManager) *Config {
	if pm == nil {
		return nil
	}
	return pm.cfg
}

func redistributePluginCorePlans(pm *ProcessManager, enabled bool) {
	if !enabled || pm == nil {
		return
	}
	pm.redistributeWorkers()
}

func applyPluginResourceDataWithAppliers(appliers []pluginRuntimeDataApplier, plugin LoadedPlugin, resource PluginResource, records []PluginResourceRecord) error {
	var notLoadedErr error
	for _, applier := range appliers {
		err := applier.ApplyPluginResourceData(plugin, resource, records)
		if err == nil {
			return nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoadedErr = err
			continue
		}
		return err
	}
	if notLoadedErr != nil {
		return notLoadedErr
	}
	return fmt.Errorf("plugin runtime data applier is unavailable")
}

func applyPluginActionWithAppliers(appliers []pluginRuntimeDataApplier, plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	var notLoadedErr error
	for _, applier := range appliers {
		err := applier.ApplyPluginAction(plugin, action, payload)
		if err == nil {
			return nil
		}
		if errors.Is(err, errPluginRuntimeTargetNotLoaded) {
			notLoadedErr = err
			continue
		}
		return err
	}
	if notLoadedErr != nil {
		return notLoadedErr
	}
	return fmt.Errorf("plugin runtime data applier is unavailable")
}

func pluginRuntimeDataAppliersForProcess(pm *ProcessManager) []pluginRuntimeDataApplier {
	if pm == nil {
		return nil
	}
	out := make([]pluginRuntimeDataApplier, 0, 2)
	if applier, ok := pm.pluginControlRuntime.(pluginRuntimeDataApplier); ok {
		out = append(out, applier)
	}
	if applier, ok := pm.kernelRuntime.(pluginRuntimeDataApplier); ok {
		out = append(out, applier)
	}
	if applier, ok := pm.pluginRuntime.(pluginRuntimeDataApplier); ok {
		out = append(out, applier)
	}
	return out
}

func (pm *ProcessManager) PluginRuntimeDataAppliers() []pluginRuntimeDataApplier {
	return pluginRuntimeDataAppliersForProcess(pm)
}

func (pm *ProcessManager) ApplyPluginResourceRuntimeUpdate(plugin LoadedPlugin, resource PluginResource) error {
	if pm == nil || pm.db == nil {
		return fmt.Errorf("plugin process manager is unavailable")
	}
	return applyPluginResourceRuntimeUpdate(pm.db, pm, plugin, resource)
}

func (pm *ProcessManager) ApplyPluginActionRuntimeUpdate(plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	if pm == nil || pm.db == nil {
		return fmt.Errorf("plugin process manager is unavailable")
	}
	return applyPluginActionRuntimeUpdate(pm.db, pm, plugin, action, payload)
}

func loadPluginResourceRecords(db *sql.DB, plugin LoadedPlugin, resource PluginResource) ([]PluginResourceRecord, error) {
	items, err := store.GetPluginRecords(db, plugin.ID, resource.ID)
	if err != nil {
		return nil, err
	}
	out := make([]PluginResourceRecord, 0, len(items))
	for _, item := range items {
		out = append(out, PluginResourceRecord{
			Key:       item.RecordKey,
			Data:      json.RawMessage(item.DataJSON),
			Enabled:   item.Enabled,
			Revision:  item.Revision,
			UpdatedAt: item.UpdatedAt,
		})
	}
	return out, nil
}

func markPluginRuntimeAppliedToCurrentRevision(db *sql.DB, pluginID, targetType, targetID string) error {
	status, err := store.PluginRuntimeStatusOrNil(db, pluginID, targetType, targetID)
	if err != nil {
		return err
	}
	if status == nil {
		return store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
			PluginID:        pluginID,
			TargetType:      targetType,
			TargetID:        targetID,
			Status:          "applied",
			AppliedRevision: 0,
		})
	}
	return store.MarkPluginRuntimeApplied(db, pluginID, targetType, targetID, status.Revision)
}

func markPluginRuntimeError(db *sql.DB, pluginID, targetType, targetID string, applyErr error) error {
	message := ""
	if applyErr != nil {
		message = applyErr.Error()
	}
	return store.MarkPluginRuntimeError(db, pluginID, targetType, targetID, message)
}

func pluginReconcileResourceError(db *sql.DB, pluginID, resourceID string) error {
	if db == nil {
		return nil
	}
	status, err := store.PluginRuntimeStatusOrNil(db, pluginID, "resource", resourceID)
	if err != nil {
		return err
	}
	if status == nil || status.Status != "error" {
		return nil
	}
	message := strings.TrimSpace(status.LastError)
	if message == "" {
		message = "plugin reconcile failed"
	}
	return fmt.Errorf("%s", message)
}

func pluginReconcileActionError(snapshot pluginRuntimeSnapshot, pluginID string) error {
	state, ok := snapshot.stateFor(pluginID)
	if !ok {
		return nil
	}
	message := strings.TrimSpace(state.Error)
	if message == "" {
		return nil
	}
	return fmt.Errorf("%s", message)
}
