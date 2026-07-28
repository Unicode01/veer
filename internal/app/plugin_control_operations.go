package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const (
	pluginOperationMaxRecordsPerPlugin = 1024
	pluginOperationMaxFieldBytes       = 256 << 10
	pluginOperationMaxEnvelopeBytes    = ((pluginOperationMaxFieldBytes + 16 + 2) / 3 * 4) + 1024
	pluginOperationMaxPluginBytes      = 64 << 20
	pluginOperationDefaultListLimit    = 100
	pluginOperationMaxListLimit        = 500
	pluginOperationMaxRetryDelayMS     = int64(7 * 24 * time.Hour / time.Millisecond)
	pluginOperationSecretResourceID    = "$operations"
)

var pluginOperationTerminalStatuses = map[string]struct{}{
	"completed": {},
	"failed":    {},
	"cancelled": {},
}

type pluginOperationBeginRequest struct {
	Key     string          `json:"key"`
	Kind    string          `json:"kind"`
	Input   json.RawMessage `json:"input,omitempty"`
	State   json.RawMessage `json:"state,omitempty"`
	Restart bool            `json:"restart,omitempty"`
}

type pluginOperationListRequest struct {
	Kind      string `json:"kind,omitempty"`
	Status    string `json:"status,omitempty"`
	Resumable bool   `json:"resumable,omitempty"`
	Limit     int    `json:"limit,omitempty"`
}

type pluginOperationCheckpointRequest struct {
	Phase string          `json:"phase,omitempty"`
	State json.RawMessage `json:"state"`
}

type pluginOperationRetryRequest struct {
	Phase   string          `json:"phase,omitempty"`
	State   json.RawMessage `json:"state,omitempty"`
	Error   string          `json:"error"`
	DelayMS int64           `json:"delay_ms,omitempty"`
}

type pluginOperationFailRequest struct {
	Phase string          `json:"phase,omitempty"`
	State json.RawMessage `json:"state,omitempty"`
	Error string          `json:"error"`
}

func (h *pluginControlHost) operationBegin(call goja.FunctionCall) goja.Value {
	const api = "operations.begin"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	var request pluginOperationBeginRequest
	h.requiredOperationRequest(call, 0, &request, api)
	request.Key = h.normalizeOperationToken(request.Key, "key", api)
	request.Kind = h.normalizeOperationToken(request.Kind, "kind", api)
	input := h.normalizeOperationJSON(request.Input, api+" input")
	state := h.normalizeOperationJSON(request.State, api+" state")

	existing, err := store.PluginOperationByKey(h.db, h.plugin.ID, request.Key)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if existing != nil {
		plain := h.decryptPluginOperation(*existing, api)
		if !request.Restart || !pluginOperationTerminal(plain.Status) {
			if plain.Kind != request.Kind || plain.InputJSON != string(input) {
				h.throwf("%s: operation key %s already belongs to a different request", api, request.Key)
			}
			return h.vm.ToValue(h.pluginOperationForScript(plain))
		}
		restarted := *existing
		restarted.Kind = request.Kind
		restarted.InputJSON = h.encryptPluginOperationJSON(restarted.OperationID, "input", input, api)
		restarted.StateJSON = h.encryptPluginOperationJSON(restarted.OperationID, "state", state, api)
		restarted.ResultJSON = h.encryptPluginOperationJSON(restarted.OperationID, "result", json.RawMessage("null"), api)
		restarted.ErrorJSON = h.encryptPluginOperationJSON(restarted.OperationID, "error", json.RawMessage("null"), api)
		h.requirePluginOperationReplacement(*existing, restarted, api)
		if err := store.RestartPluginOperation(h.db, restarted, existing.Revision); err != nil {
			h.throwf("%s: restart: %v", api, err)
		}
		return h.vm.ToValue(h.requiredPluginOperation(restarted.OperationID, api))
	}

	count, err := store.CountPluginOperations(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("%s: count operations: %v", api, err)
	}
	if count >= pluginOperationMaxRecordsPerPlugin {
		h.throwf("%s: operation count exceeds %d", api, pluginOperationMaxRecordsPerPlugin)
	}
	operationID, err := newPluginPackageID()
	if err != nil {
		h.throwf("%s: generate id: %v", api, err)
	}
	item := store.PluginOperation{
		OperationID:  operationID,
		PluginID:     h.plugin.ID,
		OperationKey: request.Key,
		Kind:         request.Kind,
		Status:       "pending",
		InputJSON:    h.encryptPluginOperationJSON(operationID, "input", input, api),
		StateJSON:    h.encryptPluginOperationJSON(operationID, "state", state, api),
		ResultJSON:   h.encryptPluginOperationJSON(operationID, "result", json.RawMessage("null"), api),
		ErrorJSON:    h.encryptPluginOperationJSON(operationID, "error", json.RawMessage("null"), api),
	}
	h.requirePluginOperationStorage(item, api)
	if err := store.AddPluginOperation(h.db, item); err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationGet(call goja.FunctionCall) goja.Value {
	const api = "operations.get"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	item, err := store.PluginOperationByID(h.db, h.plugin.ID, operationID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if item == nil {
		return goja.Null()
	}
	return h.vm.ToValue(h.pluginOperationForScript(h.decryptPluginOperation(*item, api)))
}

func (h *pluginControlHost) operationGetByKey(call goja.FunctionCall) goja.Value {
	const api = "operations.getByKey"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	key := h.normalizeOperationToken(h.requiredOperationString(call, 0, "operation key", api), "key", api)
	item, err := store.PluginOperationByKey(h.db, h.plugin.ID, key)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if item == nil {
		return goja.Null()
	}
	return h.vm.ToValue(h.pluginOperationForScript(h.decryptPluginOperation(*item, api)))
}

func (h *pluginControlHost) operationList(call goja.FunctionCall) goja.Value {
	const api = "operations.list"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	var request pluginOperationListRequest
	if len(call.Arguments) > 0 && !goja.IsUndefined(call.Arguments[0]) && !goja.IsNull(call.Arguments[0]) {
		h.exportJSONValue(call.Arguments[0], &request, api)
	}
	if strings.TrimSpace(request.Kind) != "" {
		request.Kind = h.normalizeOperationToken(request.Kind, "kind", api)
	}
	request.Status = strings.ToLower(strings.TrimSpace(request.Status))
	if request.Status != "" && !pluginOperationStatus(request.Status) {
		h.throwf("%s: invalid status %q", api, request.Status)
	}
	if request.Resumable && request.Status != "" {
		h.throwf("%s: status and resumable cannot be combined", api)
	}
	if request.Limit == 0 {
		request.Limit = pluginOperationDefaultListLimit
	}
	if request.Limit < 1 || request.Limit > pluginOperationMaxListLimit {
		h.throwf("%s: limit must be between 1 and %d", api, pluginOperationMaxListLimit)
	}
	queryLimit := request.Limit
	if request.Resumable {
		queryLimit = pluginOperationMaxRecordsPerPlugin
	}
	items, err := store.GetPluginOperations(h.db, h.plugin.ID, request.Kind, request.Status, queryLimit)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	now := time.Now().UnixMilli()
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		plain := h.decryptPluginOperation(item, api)
		if request.Resumable && !pluginOperationResumable(plain, now) {
			continue
		}
		out = append(out, h.pluginOperationForScript(plain))
		if len(out) >= request.Limit {
			break
		}
	}
	return h.vm.ToValue(out)
}

func (h *pluginControlHost) operationClaim(call goja.FunctionCall) goja.Value {
	const api = "operations.claim"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	errorJSON := h.encryptPluginOperationJSON(operationID, "error", json.RawMessage("null"), api)
	if err := store.ClaimPluginOperation(h.db, h.plugin.ID, operationID, errorJSON, expectedRevision, time.Now().UnixMilli()); err != nil {
		h.throwf("%s: operation is stale, terminal, or not due: %v", api, err)
	}
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationCheckpoint(call goja.FunctionCall) goja.Value {
	const api = "operations.checkpoint"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	var request pluginOperationCheckpointRequest
	h.requiredOperationRequest(call, 2, &request, api)
	state := h.normalizeOperationJSON(request.State, api+" state")
	item := store.PluginOperation{
		PluginID:    h.plugin.ID,
		OperationID: operationID,
		Phase:       h.normalizeOperationPhase(request.Phase, api),
		StateJSON:   h.encryptPluginOperationJSON(operationID, "state", state, api),
	}
	current := h.requiredPluginOperationRecord(operationID, api)
	candidate := current
	candidate.Phase = item.Phase
	candidate.StateJSON = item.StateJSON
	h.requirePluginOperationReplacement(current, candidate, api)
	if err := store.CheckpointPluginOperation(h.db, item, expectedRevision); err != nil {
		h.throwf("%s: operation is stale or not running: %v", api, err)
	}
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationComplete(call goja.FunctionCall) goja.Value {
	const api = "operations.complete"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	result := json.RawMessage("null")
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) {
		result = h.normalizeOperationValue(call.Arguments[2], api+" result")
	}
	current := h.requiredPluginOperationRecord(operationID, api)
	item := store.PluginOperation{
		PluginID:    h.plugin.ID,
		OperationID: operationID,
		Status:      "completed",
		Phase:       current.Phase,
		StateJSON:   current.StateJSON,
		ResultJSON:  h.encryptPluginOperationJSON(operationID, "result", result, api),
		ErrorJSON:   h.encryptPluginOperationJSON(operationID, "error", json.RawMessage("null"), api),
	}
	candidate := current
	candidate.ResultJSON = item.ResultJSON
	candidate.ErrorJSON = item.ErrorJSON
	h.requirePluginOperationReplacement(current, candidate, api)
	if err := store.TransitionPluginOperation(h.db, item, expectedRevision); err != nil {
		h.throwf("%s: operation is stale or not running: %v", api, err)
	}
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationRetry(call goja.FunctionCall) goja.Value {
	const api = "operations.retry"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	var request pluginOperationRetryRequest
	h.requiredOperationRequest(call, 2, &request, api)
	if request.DelayMS < 0 || request.DelayMS > pluginOperationMaxRetryDelayMS {
		h.throwf("%s: delay_ms must be between 0 and %d", api, pluginOperationMaxRetryDelayMS)
	}
	h.transitionPluginOperation(operationID, expectedRevision, "retry_wait", request.Phase, request.State, request.Error, request.DelayMS, api)
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationFail(call goja.FunctionCall) goja.Value {
	const api = "operations.fail"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	var request pluginOperationFailRequest
	h.requiredOperationRequest(call, 2, &request, api)
	h.transitionPluginOperation(operationID, expectedRevision, "failed", request.Phase, request.State, request.Error, 0, api)
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationCancel(call goja.FunctionCall) goja.Value {
	const api = "operations.cancel"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	expectedRevision := h.requiredOperationRevision(call, 1, api)
	var request pluginOperationFailRequest
	if len(call.Arguments) > 2 && !goja.IsUndefined(call.Arguments[2]) && !goja.IsNull(call.Arguments[2]) {
		h.exportJSONValue(call.Arguments[2], &request, api)
	}
	h.transitionPluginOperation(operationID, expectedRevision, "cancelled", request.Phase, request.State, request.Error, 0, api)
	return h.vm.ToValue(h.requiredPluginOperation(operationID, api))
}

func (h *pluginControlHost) operationRemove(call goja.FunctionCall) goja.Value {
	const api = "operations.remove"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	operationID := h.requiredOperationID(call, 0, api)
	if err := store.DeletePluginOperation(h.db, h.plugin.ID, operationID); err != nil {
		h.throwf("%s: operation is missing or nonterminal: %v", api, err)
	}
	return goja.Undefined()
}

func (h *pluginControlHost) operationStats(goja.FunctionCall) goja.Value {
	const api = "operations.stats"
	h.requireOperationAPI(api)
	release := h.lockPluginOperationStore(api)
	defer release()
	items, err := store.GetPluginOperations(h.db, h.plugin.ID, "", "", pluginOperationMaxRecordsPerPlugin)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	counts := map[string]int{}
	for _, item := range items {
		counts[item.Status]++
	}
	bytesUsed, err := store.PluginOperationStorageBytes(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	return h.vm.ToValue(map[string]any{
		"total": len(items), "by_status": counts, "bytes": bytesUsed,
		"record_limit": pluginOperationMaxRecordsPerPlugin, "byte_limit": pluginOperationMaxPluginBytes,
	})
}

func (h *pluginControlHost) transitionPluginOperation(operationID string, expectedRevision int64, status, phase string, state json.RawMessage, message string, delayMS int64, api string) {
	current := h.requiredPluginOperationRecord(operationID, api)
	stateJSON := current.StateJSON
	if len(state) > 0 {
		normalized := h.normalizeOperationJSON(state, api+" state")
		stateJSON = h.encryptPluginOperationJSON(operationID, "state", normalized, api)
	}
	errorJSON := h.normalizeOperationJSONValue(message, api+" error")
	item := store.PluginOperation{
		PluginID:    h.plugin.ID,
		OperationID: operationID,
		Status:      status,
		Phase:       h.normalizeOperationPhase(phase, api),
		StateJSON:   stateJSON,
		ResultJSON:  current.ResultJSON,
		ErrorJSON:   h.encryptPluginOperationJSON(operationID, "error", errorJSON, api),
	}
	if item.Phase == "" {
		item.Phase = current.Phase
	}
	if status == "retry_wait" {
		item.NextAttemptUnixMS = time.Now().UnixMilli() + delayMS
	}
	candidate := current
	candidate.Status = item.Status
	candidate.Phase = item.Phase
	candidate.StateJSON = item.StateJSON
	candidate.ResultJSON = item.ResultJSON
	candidate.ErrorJSON = item.ErrorJSON
	h.requirePluginOperationReplacement(current, candidate, api)
	if err := store.TransitionPluginOperation(h.db, item, expectedRevision); err != nil {
		h.throwf("%s: operation is stale or not running: %v", api, err)
	}
}

func (h *pluginControlHost) requireOperationAPI(api string) {
	h.requirePermission("operation")
	if h.workerVM {
		h.throwf("%s is only available in the plugin main VM", api)
	}
	if h.db == nil {
		h.throwf("%s: plugin operation store is unavailable", api)
	}
}

func (h *pluginControlHost) lockPluginOperationStore(api string) func() {
	secrets := h.pluginSecretStore(api)
	secrets.operationMu.RLock()
	return secrets.operationMu.RUnlock
}

func (h *pluginControlHost) requiredOperationRequest(call goja.FunctionCall, index int, target any, api string) {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s: request is required", api)
	}
	h.exportJSONValue(call.Arguments[index], target, api)
}

func (h *pluginControlHost) requiredOperationID(call goja.FunctionCall, index int, api string) string {
	value := strings.ToLower(strings.TrimSpace(h.requiredOperationString(call, index, "operation id", api)))
	if len(value) != 32 || !isLowerHex(value) {
		h.throwf("%s: operation id is invalid", api)
	}
	return value
}

func (h *pluginControlHost) requiredOperationRevision(call goja.FunctionCall, index int, api string) int64 {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s: expected revision is required", api)
	}
	number := call.Arguments[index].ToFloat()
	if math.IsNaN(number) || math.IsInf(number, 0) || number < 1 || number > 1<<53-1 || math.Trunc(number) != number {
		h.throwf("%s: expected revision must be a positive safe integer", api)
	}
	return int64(number)
}

func (h *pluginControlHost) requiredOperationString(call goja.FunctionCall, index int, label, api string) string {
	if len(call.Arguments) <= index || goja.IsUndefined(call.Arguments[index]) || goja.IsNull(call.Arguments[index]) {
		h.throwf("%s: %s is required", api, label)
	}
	value := strings.TrimSpace(call.Arguments[index].String())
	if value == "" {
		h.throwf("%s: %s is required", api, label)
	}
	return value
}

func (h *pluginControlHost) normalizeOperationToken(value, label, api string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if !pluginTokenPattern.MatchString(value) {
		h.throwf("%s: %s must match %s", api, label, pluginTokenPattern.String())
	}
	return value
}

func (h *pluginControlHost) normalizeOperationPhase(value, api string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	return h.normalizeOperationToken(value, "phase", api)
}

func (h *pluginControlHost) normalizeOperationValue(value goja.Value, label string) json.RawMessage {
	raw, err := json.Marshal(value.Export())
	if err != nil {
		h.throwf("%s is not JSON serializable: %v", label, err)
	}
	return h.normalizeOperationJSON(raw, label)
}

func (h *pluginControlHost) normalizeOperationJSONValue(value any, label string) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		h.throwf("%s is not JSON serializable: %v", label, err)
	}
	return h.normalizeOperationJSON(raw, label)
}

func (h *pluginControlHost) normalizeOperationJSON(raw json.RawMessage, label string) json.RawMessage {
	normalized, err := normalizePluginOperationJSON(raw, label)
	if err != nil {
		h.throwf("%v", err)
	}
	return normalized
}

func normalizePluginOperationJSON(raw json.RawMessage, label string) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("null")
	}
	if len(raw) > pluginOperationMaxFieldBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, pluginOperationMaxFieldBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("%s is invalid JSON: %w", label, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("%s contains trailing JSON values", label)
		}
		return nil, fmt.Errorf("%s contains invalid trailing JSON: %w", label, err)
	}
	if err := validatePluginHostJSONValue(value, 0); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	normalized, err := json.Marshal(value)
	if err != nil || len(normalized) > pluginOperationMaxFieldBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", label, pluginOperationMaxFieldBytes)
	}
	return normalized, nil
}

func (h *pluginControlHost) encryptPluginOperationJSON(operationID, field string, value json.RawMessage, api string) string {
	secrets := h.pluginSecretStore(api)
	encrypted, err := secrets.encryptJSON(h.plugin.ID, pluginOperationSecretResourceID, operationID, field, value)
	if err != nil {
		h.throwf("%s: encrypt operation %s: %v", api, field, err)
	}
	return string(encrypted)
}

func (h *pluginControlHost) decryptPluginOperation(item store.PluginOperation, api string) store.PluginOperation {
	secrets := h.pluginSecretStore(api)
	for field, target := range map[string]*string{
		"input": &item.InputJSON, "state": &item.StateJSON, "result": &item.ResultJSON, "error": &item.ErrorJSON,
	} {
		plain, err := decryptPluginOperationPayload(secrets, item, field, *target)
		if err != nil {
			h.throwf("%s: decrypt operation %s: %v", api, field, err)
		}
		*target = string(plain)
	}
	return item
}

func decryptPluginOperationPayload(secrets *pluginSecretStore, item store.PluginOperation, field, value string) (json.RawMessage, error) {
	if len(value) > pluginOperationMaxEnvelopeBytes {
		return nil, fmt.Errorf("encrypted value exceeds %d bytes", pluginOperationMaxEnvelopeBytes)
	}
	plain, encrypted, err := secrets.decryptJSON(item.PluginID, pluginOperationSecretResourceID, item.OperationID, field, json.RawMessage(value))
	if err != nil {
		return nil, err
	}
	if !encrypted {
		return nil, fmt.Errorf("value is not encrypted")
	}
	return normalizePluginOperationJSON(plain, "decrypted operation "+field)
}

func (h *pluginControlHost) requiredPluginOperationRecord(operationID, api string) store.PluginOperation {
	item, err := store.PluginOperationByID(h.db, h.plugin.ID, operationID)
	if err != nil {
		h.throwf("%s: %v", api, err)
	}
	if item == nil {
		h.throwf("%s: operation %s was not found", api, operationID)
	}
	return *item
}

func (h *pluginControlHost) requiredPluginOperation(operationID, api string) map[string]any {
	return h.pluginOperationForScript(h.decryptPluginOperation(h.requiredPluginOperationRecord(operationID, api), api))
}

func (h *pluginControlHost) pluginOperationForScript(item store.PluginOperation) map[string]any {
	now := time.Now().UnixMilli()
	return map[string]any{
		"id": item.OperationID, "key": item.OperationKey, "kind": item.Kind,
		"status": item.Status, "phase": item.Phase,
		"input":    pluginControlDecodeJSON(json.RawMessage(item.InputJSON)),
		"state":    pluginControlDecodeJSON(json.RawMessage(item.StateJSON)),
		"result":   pluginControlDecodeJSON(json.RawMessage(item.ResultJSON)),
		"error":    pluginControlDecodeJSON(json.RawMessage(item.ErrorJSON)),
		"attempts": item.Attempts, "revision": item.Revision,
		"next_attempt_unix_ms": item.NextAttemptUnixMS,
		"resumable":            pluginOperationResumable(item, now),
		"created_at":           item.CreatedAt, "updated_at": item.UpdatedAt,
	}
}

func (h *pluginControlHost) requirePluginOperationStorage(item store.PluginOperation, api string) {
	used, err := store.PluginOperationStorageBytes(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("%s: inspect operation storage: %v", api, err)
	}
	delta := store.PluginOperationStoredBytes(item)
	if delta > pluginOperationMaxPluginBytes-used {
		h.throwf("%s: operation storage exceeds %d bytes", api, pluginOperationMaxPluginBytes)
	}
	if err := ensurePluginDatabaseStorageQuota(h.db, h.plugin.ID, delta, pluginResourceLimitsFromConfig(h.cfg)); err != nil {
		h.throwf("%s: %v", api, err)
	}
}

func (h *pluginControlHost) requirePluginOperationReplacement(current, candidate store.PluginOperation, api string) {
	used, err := store.PluginOperationStorageBytes(h.db, h.plugin.ID)
	if err != nil {
		h.throwf("%s: inspect operation storage: %v", api, err)
	}
	currentBytes := store.PluginOperationStoredBytes(current)
	candidateBytes := store.PluginOperationStoredBytes(candidate)
	delta := candidateBytes - currentBytes
	if delta <= 0 {
		return
	}
	if delta > pluginOperationMaxPluginBytes-used {
		h.throwf("%s: operation storage exceeds %d bytes", api, pluginOperationMaxPluginBytes)
	}
	if err := ensurePluginDatabaseStorageQuota(h.db, h.plugin.ID, delta, pluginResourceLimitsFromConfig(h.cfg)); err != nil {
		h.throwf("%s: %v", api, err)
	}
}

func pluginOperationTerminal(status string) bool {
	_, ok := pluginOperationTerminalStatuses[status]
	return ok
}

func pluginOperationStatus(status string) bool {
	switch status {
	case "pending", "running", "retry_wait", "completed", "failed", "cancelled":
		return true
	default:
		return false
	}
}

func pluginOperationResumable(item store.PluginOperation, nowUnixMS int64) bool {
	switch item.Status {
	case "pending", "running":
		return true
	case "retry_wait":
		return item.NextAttemptUnixMS <= nowUnixMS
	default:
		return false
	}
}

func pluginOperationRuntimeSnapshots(db store.RuleStore, pluginIDs []string) (map[string]PluginOperationRuntimeState, error) {
	summaries, err := store.PluginOperationSummaries(db, pluginIDs, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	out := make(map[string]PluginOperationRuntimeState, len(summaries))
	for pluginID, summary := range summaries {
		out[pluginID] = PluginOperationRuntimeState{
			Total: summary.Total, Resumable: summary.Resumable, Bytes: summary.Bytes, ByStatus: summary.ByStatus,
		}
	}
	return out, nil
}

func isLowerHex(value string) bool {
	for _, char := range value {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
