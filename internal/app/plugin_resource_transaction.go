package app

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const (
	pluginResourceTransactionMaxOperations = 128
	pluginResourceTransactionMaxJSONBytes  = 1 << 20
)

type pluginResourceTransactionOperation struct {
	Operation  string          `json:"op"`
	PluginID   string          `json:"plugin,omitempty"`
	ResourceID string          `json:"resource"`
	Key        string          `json:"key"`
	Data       json.RawMessage `json:"data,omitempty"`
	Enabled    *bool           `json:"enabled,omitempty"`
}

type pluginResourceTransactionOptions struct {
	Apply bool `json:"apply,omitempty"`
}

type preparedPluginResourceTransactionOperation struct {
	operation string
	plugin    LoadedPlugin
	resource  PluginResource
	key       string
	data      json.RawMessage
	enabled   *bool
	before    *store.PluginRecord
	mutated   bool
}

type pluginResourceTransactionTarget struct {
	plugin   LoadedPlugin
	resource PluginResource
}

func (h *pluginControlHost) resourceTransaction(call goja.FunctionCall) goja.Value {
	h.requirePermission("resource")
	return h.executePluginResourceTransaction(call, false)
}

func (h *pluginControlHost) pluginResourceTransaction(call goja.FunctionCall) goja.Value {
	h.requirePermission("plugin.resource")
	return h.executePluginResourceTransaction(call, true)
}

func (h *pluginControlHost) executePluginResourceTransaction(call goja.FunctionCall, crossPlugin bool) goja.Value {
	operations, options := h.parsePluginResourceTransaction(call, crossPlugin)
	prepared := make([]preparedPluginResourceTransactionOperation, 0, len(operations))
	seen := make(map[string]struct{}, len(operations))
	for i, operation := range operations {
		operation.Operation = strings.TrimSpace(strings.ToLower(operation.Operation))
		if operation.Operation != "set" && operation.Operation != "delete" {
			h.throwf("resources.transaction operation %d: op must be set or delete", i)
		}
		resourceID, err := pluginPathToken(operation.ResourceID)
		if err != nil {
			h.throwf("resources.transaction operation %d resource: %v", i, err)
		}
		key, err := pluginPathToken(operation.Key)
		if err != nil {
			h.throwf("resources.transaction operation %d key: %v", i, err)
		}
		plugin := h.plugin
		var resource PluginResource
		if crossPlugin {
			if strings.TrimSpace(operation.PluginID) == "" {
				h.throwf("plugins.resources.transaction operation %d: plugin is required", i)
			}
			plugin, resource = h.requiredTargetPluginResource(operation.PluginID, resourceID)
		} else {
			if strings.TrimSpace(operation.PluginID) != "" && strings.TrimSpace(strings.ToLower(operation.PluginID)) != h.plugin.ID {
				h.throwf("resources.transaction operation %d cannot target another plugin", i)
			}
			found := false
			for _, candidate := range append(append([]PluginResource(nil), h.surface.Resources...), h.plugin.Resources...) {
				if candidate.ID == resourceID {
					resource = candidate
					found = true
					break
				}
			}
			if !found {
				h.throwf("resources.transaction operation %d: resource %s is not declared", i, resourceID)
			}
		}
		targetKey := plugin.ID + "\x00" + resource.ID + "\x00" + key
		if _, duplicate := seen[targetKey]; duplicate {
			h.throwf("resources.transaction operation %d duplicates %s/%s/%s", i, plugin.ID, resource.ID, key)
		}
		seen[targetKey] = struct{}{}
		prepared = append(prepared, preparedPluginResourceTransactionOperation{
			operation: operation.Operation, plugin: plugin, resource: resource, key: key, data: operation.Data, enabled: operation.Enabled,
		})
	}
	preparedTargets := make(map[string]struct{})
	for _, item := range prepared {
		targetKey := item.plugin.ID + "\x00" + item.resource.ID
		if _, exists := preparedTargets[targetKey]; exists {
			continue
		}
		if err := h.preparePluginResourceMutation(item.plugin, item.resource); err != nil {
			h.throwf("resources.transaction: %v", err)
		}
		preparedTargets[targetKey] = struct{}{}
	}

	tx, err := h.db.Begin()
	if err != nil {
		h.throwf("resources.transaction: %v", err)
	}
	defer tx.Rollback()
	mutatedTargets := make(map[string]pluginResourceTransactionTarget)
	targetOrder := make([]string, 0)
	for i := range prepared {
		item := &prepared[i]
		if err := h.ensurePluginResourceMutationAllowed(tx, item.plugin, item.resource); err != nil {
			h.throwf("resources.transaction: %v", err)
		}
		existing, err := store.GetPluginRecord(tx, item.plugin.ID, item.resource.ID, item.key)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			h.throwf("resources.transaction: %v", err)
		}
		if err == nil {
			copyRecord := h.decryptPluginRecord(*existing, item.resource, "resources.transaction")
			item.before = &copyRecord
		}
		if item.operation == "delete" {
			h.requirePluginResourceTransactionMethod(crossPlugin, item.plugin, item.resource, "delete")
			if item.before == nil {
				continue
			}
			if err := store.DeletePluginRecord(tx, item.plugin.ID, item.resource.ID, item.key); err != nil {
				h.throwf("resources.transaction: %v", err)
			}
			item.mutated = true
		} else {
			method := "create"
			if item.before != nil {
				method = "update"
			}
			h.requirePluginResourceTransactionMethod(crossPlugin, item.plugin, item.resource, method)
			if len(item.data) == 0 {
				h.throwf("resources.transaction set %s/%s/%s: data is required", item.plugin.ID, item.resource.ID, item.key)
			}
			var dataJSON string
			if item.before == nil {
				dataJSON, err = pluginRecordDataJSON(item.data, item.resource)
			} else {
				dataJSON, err = pluginRecordDataJSONForUpdate(item.data, item.resource, item.before.DataJSON)
			}
			if err != nil {
				h.throwf("resources.transaction set %s/%s/%s: %v", item.plugin.ID, item.resource.ID, item.key, err)
			}
			enabled := true
			if item.before != nil {
				enabled = item.before.Enabled
			}
			if item.enabled != nil {
				enabled = *item.enabled
			}
			if item.before != nil && item.before.DataJSON == dataJSON && item.before.Enabled == enabled {
				continue
			}
			storedDataJSON := h.encryptPluginRecordData(item.plugin.ID, item.resource, item.key, dataJSON, "resources.transaction")
			if err := upsertPluginControlRecord(tx, item.plugin.ID, item.resource.ID, item.key, storedDataJSON, enabled, pluginResourceMaxRecords(item.resource), h.resourceMutationTransaction, pluginResourceLimitsFromConfig(h.cfg)); err != nil {
				h.throwf("resources.transaction: %v", err)
			}
			item.mutated = true
		}
		if item.mutated {
			targetKey := item.plugin.ID + "\x00" + item.resource.ID
			if _, exists := mutatedTargets[targetKey]; !exists {
				mutatedTargets[targetKey] = pluginResourceTransactionTarget{plugin: item.plugin, resource: item.resource}
				targetOrder = append(targetOrder, targetKey)
			}
		}
	}
	for _, targetKey := range targetOrder {
		target := mutatedTargets[targetKey]
		if err := markPluginResourceMutation(tx, target.plugin, target.resource); err != nil {
			h.throwf("resources.transaction: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		h.throwf("resources.transaction: %v", err)
	}
	for _, item := range prepared {
		if item.mutated {
			h.runtime.publishPluginResourceChanged(h.plugin.ID, item.plugin, item.resource, item.operation, item.key)
		}
	}

	if options.Apply {
		applied := make([]pluginResourceTransactionTarget, 0, len(targetOrder))
		for _, targetKey := range targetOrder {
			target := mutatedTargets[targetKey]
			applied = append(applied, target)
			if err := h.applyPluginResourceTransactionTarget(target); err != nil {
				rollbackErr := h.rollbackPluginResourceTransaction(prepared, applied)
				if rollbackErr != nil {
					h.throwf("resources.transaction apply %s/%s: %v; rollback: %v", target.plugin.ID, target.resource.ID, err, rollbackErr)
				}
				h.throwf("resources.transaction apply %s/%s: %v; changes rolled back", target.plugin.ID, target.resource.ID, err)
			}
		}
	}
	return h.vm.ToValue(map[string]any{
		"status": "completed", "operations": len(prepared), "mutated_resources": len(targetOrder), "applied": options.Apply,
	})
}

func (h *pluginControlHost) parsePluginResourceTransaction(call goja.FunctionCall, crossPlugin bool) ([]pluginResourceTransactionOperation, pluginResourceTransactionOptions) {
	api := "resources.transaction"
	if crossPlugin {
		api = "plugins.resources.transaction"
	}
	if len(call.Arguments) == 0 || goja.IsUndefined(call.Arguments[0]) || goja.IsNull(call.Arguments[0]) {
		h.throwf("%s: operations are required", api)
	}
	raw, err := json.Marshal(call.Arguments[0].Export())
	if err != nil || len(raw) > pluginResourceTransactionMaxJSONBytes {
		h.throwf("%s: operations exceed the JSON limit or are not serializable", api)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var operations []pluginResourceTransactionOperation
	if err := decoder.Decode(&operations); err != nil {
		h.throwf("%s: %v", api, err)
	}
	if len(operations) == 0 || len(operations) > pluginResourceTransactionMaxOperations {
		h.throwf("%s: operation count must be between 1 and %d", api, pluginResourceTransactionMaxOperations)
	}
	var options pluginResourceTransactionOptions
	if len(call.Arguments) > 1 && !goja.IsUndefined(call.Arguments[1]) && !goja.IsNull(call.Arguments[1]) {
		raw, err := json.Marshal(call.Arguments[1].Export())
		if err != nil {
			h.throwf("%s: options are not serializable", api)
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&options); err != nil {
			h.throwf("%s options: %v", api, err)
		}
	}
	return operations, options
}

func (h *pluginControlHost) requirePluginResourceTransactionMethod(crossPlugin bool, plugin LoadedPlugin, resource PluginResource, method string) {
	if crossPlugin {
		h.requirePluginResourceAccess(plugin.ID, resource.ID, method, "plugins.resources.transaction")
		if !pluginResourceAllows(resource, method) {
			h.throwf("plugins.resources.transaction: resource %s/%s does not allow %s", plugin.ID, resource.ID, method)
		}
		return
	}
	if !pluginResourceControlAllows(resource, method) {
		h.throwf("resources.transaction: resource %s does not allow %s", resource.ID, method)
	}
}

func (h *pluginControlHost) applyPluginResourceTransactionTarget(target pluginResourceTransactionTarget) error {
	if target.plugin.ID == h.plugin.ID {
		return h.applyTargetPluginResourceRuntimeUpdate(target.plugin, target.resource)
	}
	release := h.beginSynchronousPluginCall(target.plugin.ID, "resource transaction "+target.resource.ID)
	defer release()
	return h.applyTargetPluginResourceRuntimeUpdate(target.plugin, target.resource)
}

func (h *pluginControlHost) rollbackPluginResourceTransaction(operations []preparedPluginResourceTransactionOperation, applied []pluginResourceTransactionTarget) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	mutatedTargets := make(map[string]pluginResourceTransactionTarget)
	for i := len(operations) - 1; i >= 0; i-- {
		item := operations[i]
		if !item.mutated {
			continue
		}
		if err := h.ensurePluginResourceMutationAllowed(tx, item.plugin, item.resource); err != nil {
			return err
		}
		if item.before == nil {
			err := store.DeletePluginRecord(tx, item.plugin.ID, item.resource.ID, item.key)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		} else {
			storedDataJSON := h.encryptPluginRecordData(item.plugin.ID, item.resource, item.key, item.before.DataJSON, "resources.transaction rollback")
			if err := upsertPluginControlRecord(tx, item.plugin.ID, item.resource.ID, item.key, storedDataJSON, item.before.Enabled, pluginResourceMaxRecords(item.resource), h.resourceMutationTransaction, pluginResourceLimitsForRollback()); err != nil {
				return err
			}
		}
		mutatedTargets[item.plugin.ID+"\x00"+item.resource.ID] = pluginResourceTransactionTarget{plugin: item.plugin, resource: item.resource}
	}
	for _, target := range mutatedTargets {
		if err := markPluginResourceMutation(tx, target.plugin, target.resource); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	for _, item := range operations {
		if item.mutated {
			h.runtime.publishPluginResourceChanged(h.plugin.ID, item.plugin, item.resource, "rollback", item.key)
		}
	}
	rollbackErrors := make([]string, 0)
	for i := len(applied) - 1; i >= 0; i-- {
		if err := h.applyPluginResourceTransactionTarget(applied[i]); err != nil {
			rollbackErrors = append(rollbackErrors, applied[i].plugin.ID+"/"+applied[i].resource.ID+": "+err.Error())
		}
	}
	if len(rollbackErrors) > 0 {
		return fmt.Errorf("runtime rollback failed: %s", strings.Join(rollbackErrors, "; "))
	}
	return nil
}
