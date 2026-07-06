package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"forward/internal/store"
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
	switch resource.RuntimeUpdate {
	case "none", "manual", "":
		return nil
	case "plugin_reconcile":
		if pm != nil {
			pm.reconcilePluginsForRuntime()
		}
		return markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "resource", resource.ID)
	case "runtime_apply":
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
		return markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "resource", resource.ID)
	default:
		return fmt.Errorf("unsupported resource runtime_update %q", resource.RuntimeUpdate)
	}
}

func applyPluginActionRuntimeUpdate(db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, action PluginAction, payload json.RawMessage) error {
	switch action.RuntimeUpdate {
	case "none", "":
		return nil
	case "plugin_reconcile":
		if pm != nil {
			pm.reconcilePluginsForRuntime()
		}
		return markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "action", action.ID)
	case "runtime_apply":
		appliers := pluginRuntimeDataAppliersForProcess(pm)
		if len(appliers) == 0 {
			return fmt.Errorf("plugin runtime data applier is unavailable")
		}
		if err := applyPluginActionWithAppliers(appliers, plugin, action, payload); err != nil {
			return err
		}
		return markPluginRuntimeAppliedToCurrentRevision(db, plugin.ID, "action", action.ID)
	default:
		return fmt.Errorf("unsupported action runtime_update %q", action.RuntimeUpdate)
	}
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
