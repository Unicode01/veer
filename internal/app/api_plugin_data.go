package app

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"forward/internal/store"
)

type pluginRecordWriteRequest struct {
	Key     string          `json:"key,omitempty"`
	Data    json.RawMessage `json:"data"`
	Enabled *bool           `json:"enabled,omitempty"`
}

type pluginActionRequest struct {
	Payload json.RawMessage `json:"payload,omitempty"`
}

type pluginStateWriteRequest struct {
	Enabled *bool `json:"enabled,omitempty"`
}

type pluginStateResponse struct {
	PluginID string       `json:"plugin_id"`
	Enabled  bool         `json:"enabled"`
	Plugin   LoadedPlugin `json:"plugin"`
}

type pluginRecordResponse struct {
	ID            int64                        `json:"id"`
	Key           string                       `json:"key"`
	Data          json.RawMessage              `json:"data"`
	Enabled       bool                         `json:"enabled"`
	Revision      int64                        `json:"revision"`
	CreatedAt     string                       `json:"created_at,omitempty"`
	UpdatedAt     string                       `json:"updated_at,omitempty"`
	RuntimeStatus *pluginRuntimeStatusResponse `json:"runtime_status,omitempty"`
	RuntimeError  string                       `json:"runtime_error,omitempty"`
	Error         string                       `json:"error,omitempty"`
}

type pluginRuntimeStatusResponse struct {
	TargetType      string `json:"target_type"`
	TargetID        string `json:"target_id"`
	Status          string `json:"status"`
	Revision        int64  `json:"revision"`
	AppliedRevision int64  `json:"applied_revision"`
	LastError       string `json:"last_error,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

type pluginRecordsResponse struct {
	PluginID      string                       `json:"plugin_id"`
	ResourceID    string                       `json:"resource_id"`
	Records       []pluginRecordResponse       `json:"records"`
	Total         int                          `json:"total"`
	Limit         int                          `json:"limit"`
	Offset        int                          `json:"offset"`
	HasMore       bool                         `json:"has_more"`
	RuntimeStatus *pluginRuntimeStatusResponse `json:"runtime_status,omitempty"`
}

type pluginActionResponse struct {
	PluginID      string                       `json:"plugin_id"`
	ActionID      string                       `json:"action_id"`
	Status        string                       `json:"status"`
	RuntimeUpdate string                       `json:"runtime_update"`
	RuntimeStatus *pluginRuntimeStatusResponse `json:"runtime_status,omitempty"`
	RuntimeError  string                       `json:"runtime_error,omitempty"`
	Error         string                       `json:"error,omitempty"`
}

func handlePluginAPIRoute(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) bool {
	const prefix = "/api/plugins/"
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 2 {
		return false
	}
	if parts[1] == "assets" {
		return false
	}
	switch parts[1] {
	case "state":
		handlePluginStateAPI(w, r, cfg, db, pm, parts)
		return true
	case "resources":
		handlePluginResourceAPI(w, r, cfg, db, pm, parts)
		return true
	case "actions":
		handlePluginActionAPI(w, r, cfg, db, pm, parts)
		return true
	default:
		return false
	}
}

func handlePluginStateAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager, parts []string) {
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin data store is unavailable"})
		return
	}
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(parts[0]))
	if !pluginIDPattern.MatchString(pluginID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plugin not found"})
		return
	}
	if pluginID == "fvtap" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "built-in plugin cannot be disabled"})
		return
	}
	if !externalPluginExists(cfg, pluginID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plugin not found"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, pluginStateResponseForID(cfg, db, pm, pluginID))
	case http.MethodPut, http.MethodPost:
		var req pluginStateWriteRequest
		if err := decodeJSONRequestBody(w, r, &req, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if req.Enabled == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled is required"})
			return
		}
		if err := store.SetPluginEnabled(db, pluginID, *req.Enabled); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		if pm != nil {
			pm.reconcilePluginsForRuntime()
			pm.redistributeWorkers()
		}
		writeJSON(w, http.StatusOK, pluginStateResponseForID(cfg, db, pm, pluginID))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func externalPluginExists(cfg *Config, pluginID string) bool {
	catalog := loadPluginCatalog(cfg)
	for _, plugin := range catalog.Plugins {
		if plugin.ID == pluginID && !plugin.Builtin {
			return true
		}
	}
	return false
}

func pluginStateResponseForID(cfg *Config, db *sql.DB, pm *ProcessManager, pluginID string) pluginStateResponse {
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	if pm != nil {
		catalog = pm.pluginCatalogWithConfig(cfg)
	}
	for _, plugin := range catalog.Plugins {
		if plugin.ID == pluginID {
			return pluginStateResponse{PluginID: pluginID, Enabled: plugin.Enabled, Plugin: plugin}
		}
	}
	return pluginStateResponse{PluginID: pluginID, Enabled: true}
}

func handlePluginResourceAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager, parts []string) {
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin data store is unavailable"})
		return
	}
	if len(parts) < 3 || len(parts) > 4 {
		http.NotFound(w, r)
		return
	}
	plugin, resource, ok := pluginResourceForRequest(w, cfg, db, pm, parts[0], parts[2])
	if !ok {
		return
	}
	recordKey := ""
	if len(parts) == 4 {
		var err error
		recordKey, err = pluginPathToken(parts[3])
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		if recordKey == "" {
			if !pluginResourceAllows(resource, "list") {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource does not allow list"})
				return
			}
			handleListPluginRecords(w, r, db, plugin, resource)
			return
		}
		if !pluginResourceAllows(resource, "get") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource does not allow get"})
			return
		}
		handleGetPluginRecord(w, db, plugin, resource, recordKey)
	case http.MethodPost:
		if recordKey != "" {
			http.NotFound(w, r)
			return
		}
		if !pluginResourceAllows(resource, "create") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource does not allow create"})
			return
		}
		handleCreatePluginRecord(w, r, db, pm, plugin, resource)
	case http.MethodPut:
		if recordKey == "" {
			http.NotFound(w, r)
			return
		}
		if !pluginResourceAllows(resource, "update") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource does not allow update"})
			return
		}
		handleUpdatePluginRecord(w, r, db, pm, plugin, resource, recordKey)
	case http.MethodDelete:
		if recordKey == "" {
			http.NotFound(w, r)
			return
		}
		if !pluginResourceAllows(resource, "delete") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "resource does not allow delete"})
			return
		}
		handleDeletePluginRecord(w, db, pm, plugin, resource, recordKey)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}

}

func handlePluginActionAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager, parts []string) {
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin data store is unavailable"})
		return
	}
	if len(parts) != 3 {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	plugin, action, ok := pluginActionForRequest(w, cfg, db, pm, parts[0], parts[2])
	if !ok {
		return
	}

	var req pluginActionRequest
	if err := decodeJSONRequestBody(w, r, &req, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if len(req.Payload) == 0 {
		req.Payload = json.RawMessage(`{}`)
	}
	if len(req.Payload) > pluginActionMaxPayloadBytes(action) || !json.Valid(req.Payload) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid action payload"})
		return
	}

	actionStatus := "pending"
	if action.RuntimeUpdate == "none" || action.RuntimeUpdate == "" {
		actionStatus = "completed"
	}
	if err := store.UpsertPluginRuntimeStatus(db, store.PluginRuntimeStatus{
		PluginID:   plugin.ID,
		TargetType: "action",
		TargetID:   action.ID,
		Status:     actionStatus,
		LastError:  "",
	}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := applyPluginActionRuntimeUpdate(db, pm, plugin, action, req.Payload); err != nil {
		_ = markPluginRuntimeError(db, plugin.ID, "action", action.ID, err)
		status, statusErr := store.PluginRuntimeStatusOrNil(db, plugin.ID, "action", action.ID)
		if statusErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": fmt.Sprintf("%v; load runtime status: %v", err, statusErr)})
			return
		}
		writeJSON(w, http.StatusInternalServerError, pluginActionResponse{
			PluginID:      plugin.ID,
			ActionID:      action.ID,
			Status:        "error",
			RuntimeUpdate: action.RuntimeUpdate,
			RuntimeStatus: pluginRuntimeStatusResponseFromStore(status),
			RuntimeError:  err.Error(),
			Error:         err.Error(),
		})
		return
	}
	status, err := store.PluginRuntimeStatusOrNil(db, plugin.ID, "action", action.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pluginActionResponse{
		PluginID:      plugin.ID,
		ActionID:      action.ID,
		Status:        "completed",
		RuntimeUpdate: action.RuntimeUpdate,
		RuntimeStatus: pluginRuntimeStatusResponseFromStore(status),
	})
}

type pluginRecordListPage struct {
	Limit  int
	Offset int
}

func handleListPluginRecords(w http.ResponseWriter, r *http.Request, db *sql.DB, plugin LoadedPlugin, resource PluginResource) {
	page, err := pluginRecordListPageFromQuery(r.URL.Query())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	total, err := store.CountPluginRecords(db, plugin.ID, resource.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	records, err := store.GetPluginRecordsPage(db, plugin.ID, resource.ID, page.Limit, page.Offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	status, err := store.PluginRuntimeStatusOrNil(db, plugin.ID, "resource", resource.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]pluginRecordResponse, 0, len(records))
	for _, item := range records {
		out = append(out, pluginRecordResponseFromStore(item, resource))
	}
	writeJSON(w, http.StatusOK, pluginRecordsResponse{
		PluginID:      plugin.ID,
		ResourceID:    resource.ID,
		Records:       out,
		Total:         total,
		Limit:         page.Limit,
		Offset:        page.Offset,
		HasMore:       page.Offset+len(out) < total,
		RuntimeStatus: pluginRuntimeStatusResponseFromStore(status),
	})
}

func handleGetPluginRecord(w http.ResponseWriter, db *sql.DB, plugin LoadedPlugin, resource PluginResource, recordKey string) {
	item, err := store.GetPluginRecord(db, plugin.ID, resource.ID, recordKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, pluginRecordResponseFromStore(*item, resource))
}

func handleCreatePluginRecord(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource) {
	req, ok := decodePluginRecordWriteRequest(w, r, resource)
	if !ok {
		return
	}
	recordKey := strings.TrimSpace(req.Key)
	if recordKey == "" {
		recordKey = newPluginRecordKey()
	} else {
		var err error
		recordKey, err = pluginPathToken(recordKey)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	dataJSON, err := pluginRecordDataJSON(req.Data, resource)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	count, err := store.CountPluginRecords(tx, plugin.ID, resource.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if count >= pluginResourceMaxRecords(resource) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "resource record limit reached"})
		return
	}

	item := store.PluginRecord{
		PluginID:   plugin.ID,
		ResourceID: resource.ID,
		RecordKey:  recordKey,
		DataJSON:   dataJSON,
		Enabled:    enabled,
	}
	if _, err := store.AddPluginRecord(tx, &item); err != nil {
		if store.SQLiteUniqueConstraintIndexName(err) == store.ConstraintIndexPluginRecordKey {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "record key already exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := markPluginResourceMutation(tx, plugin, resource); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	created, err := store.GetPluginRecord(tx, plugin.ID, resource.ID, recordKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp := pluginRecordMutationResponse(db, pm, plugin, resource, *created)
	if resp.RuntimeError != "" {
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func handleUpdatePluginRecord(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource, recordKey string) {
	req, ok := decodePluginRecordWriteRequest(w, r, resource)
	if !ok {
		return
	}

	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	existing, err := store.GetPluginRecord(tx, plugin.ID, resource.ID, recordKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	dataJSON, err := pluginRecordDataJSONForUpdate(req.Data, resource, existing.DataJSON)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if existing.DataJSON == dataJSON && existing.Enabled == enabled {
		status, statusErr := store.PluginRuntimeStatusOrNil(tx, plugin.ID, "resource", resource.ID)
		if statusErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": statusErr.Error()})
			return
		}
		if status != nil && status.Status != "error" {
			resp := pluginRecordResponseFromStore(*existing, resource)
			resp.RuntimeStatus = pluginRuntimeStatusResponseFromStore(status)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	item := store.PluginRecord{
		PluginID:   plugin.ID,
		ResourceID: resource.ID,
		RecordKey:  recordKey,
		DataJSON:   dataJSON,
		Enabled:    enabled,
	}
	if err := store.UpdatePluginRecord(tx, &item); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := markPluginResourceMutation(tx, plugin, resource); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	updated, err := store.GetPluginRecord(tx, plugin.ID, resource.ID, recordKey)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resp := pluginRecordMutationResponse(db, pm, plugin, resource, *updated)
	if resp.RuntimeError != "" {
		writeJSON(w, http.StatusInternalServerError, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleDeletePluginRecord(w http.ResponseWriter, db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource, recordKey string) {
	tx, err := db.Begin()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	if err := store.DeletePluginRecord(tx, plugin.ID, resource.ID, recordKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := markPluginResourceMutation(tx, plugin, resource); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	status, runtimeErr := applyPluginResourceRuntimeUpdateStatus(db, pm, plugin, resource)
	if runtimeErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status":         "deleted",
			"error":          runtimeErr.Error(),
			"runtime_error":  runtimeErr.Error(),
			"runtime_status": status,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "deleted",
		"runtime_status": status,
	})
}

func pluginResourceForRequest(w http.ResponseWriter, cfg *Config, db *sql.DB, pm *ProcessManager, pluginID, resourceID string) (LoadedPlugin, PluginResource, bool) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	resourceID = strings.TrimSpace(strings.ToLower(resourceID))
	if !pluginIDPattern.MatchString(pluginID) || !pluginTokenPattern.MatchString(resourceID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return LoadedPlugin{}, PluginResource{}, false
	}
	plugin, ok := loadedPluginForControlAPI(cfg, db, pm, pluginID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plugin not found"})
		return LoadedPlugin{}, PluginResource{}, false
	}
	for _, resource := range plugin.Resources {
		if resource.ID == resourceID {
			return plugin, resource, true
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "resource not found"})
	return LoadedPlugin{}, PluginResource{}, false
}

func pluginActionForRequest(w http.ResponseWriter, cfg *Config, db *sql.DB, pm *ProcessManager, pluginID, actionID string) (LoadedPlugin, PluginAction, bool) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	actionID = strings.TrimSpace(strings.ToLower(actionID))
	if !pluginIDPattern.MatchString(pluginID) || !pluginTokenPattern.MatchString(actionID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return LoadedPlugin{}, PluginAction{}, false
	}
	plugin, ok := loadedPluginForControlAPI(cfg, db, pm, pluginID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plugin not found"})
		return LoadedPlugin{}, PluginAction{}, false
	}
	for _, action := range plugin.Actions {
		if action.ID == actionID {
			return plugin, action, true
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "action not found"})
	return LoadedPlugin{}, PluginAction{}, false
}

func loadedPluginForControlAPI(cfg *Config, db *sql.DB, pm *ProcessManager, pluginID string) (LoadedPlugin, bool) {
	catalog := loadPluginCatalogWithControlRegistrationAndState(cfg, db)
	if pm != nil {
		catalog = pm.pluginCatalogWithConfig(cfg)
	}
	for _, plugin := range catalog.Plugins {
		if plugin.ID == pluginID && plugin.Status == pluginStatusActive {
			return plugin, true
		}
	}
	return LoadedPlugin{}, false
}

func decodePluginRecordWriteRequest(w http.ResponseWriter, r *http.Request, resource PluginResource) (pluginRecordWriteRequest, bool) {
	var req pluginRecordWriteRequest
	if err := decodeJSONRequestBody(w, r, &req, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return req, false
	}
	if len(req.Data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "data is required"})
		return req, false
	}
	return req, true
}

func pluginRecordDataJSON(raw json.RawMessage, resource PluginResource) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("data is required")
	}
	out, err := canonicalPluginRecordJSON(raw)
	if err != nil {
		return "", err
	}
	if len(out) > pluginResourceMaxRecordBytes(resource) {
		return "", fmt.Errorf("data exceeds resource max_record_bytes")
	}
	return out, nil
}

func pluginRecordDataJSONForUpdate(raw json.RawMessage, resource PluginResource, existingDataJSON string) (string, error) {
	dataJSON, err := pluginRecordDataJSON(raw, resource)
	if err != nil {
		return "", err
	}
	if len(resource.SecretFields) == 0 {
		return dataJSON, nil
	}
	merged, changed, err := mergePluginSecretFieldsForUpdate([]byte(dataJSON), []byte(existingDataJSON), resource)
	if err != nil {
		return "", err
	}
	if !changed {
		return dataJSON, nil
	}
	return pluginRecordDataJSON(merged, resource)
}

func canonicalPluginRecordJSON(raw []byte) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("data is required")
	}
	if !json.Valid(raw) {
		return "", fmt.Errorf("data must be valid json")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("data must be valid json")
	}
	out, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal json: %v", err)
	}
	return string(out), nil
}

func mergePluginSecretFieldsForUpdate(nextJSON []byte, existingJSON []byte, resource PluginResource) (json.RawMessage, bool, error) {
	var next map[string]json.RawMessage
	if err := json.Unmarshal(nextJSON, &next); err != nil || next == nil {
		return nil, false, nil
	}
	var existing map[string]json.RawMessage
	if err := json.Unmarshal(existingJSON, &existing); err != nil || existing == nil {
		return nil, false, nil
	}

	nextKeys := make(map[string]string, len(next))
	for key := range next {
		nextKeys[strings.ToLower(key)] = key
	}
	existingKeys := make(map[string]string, len(existing))
	for key := range existing {
		existingKeys[strings.ToLower(key)] = key
	}

	changed := false
	for _, field := range resource.SecretFields {
		lowerField := strings.ToLower(field)
		existingKey, hasExisting := existingKeys[lowerField]
		if !hasExisting {
			continue
		}
		nextKey, hasNext := nextKeys[lowerField]
		if !hasNext {
			next[existingKey] = existing[existingKey]
			changed = true
			continue
		}
		if pluginSecretFieldValueIsRedacted(next[nextKey]) {
			next[nextKey] = existing[existingKey]
			changed = true
		}
	}
	if !changed {
		return nil, false, nil
	}
	out, err := json.Marshal(next)
	if err != nil {
		return nil, false, fmt.Errorf("merge secret fields: %v", err)
	}
	return json.RawMessage(out), true, nil
}

func pluginSecretFieldValueIsRedacted(raw json.RawMessage) bool {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return value == "__redacted__"
}

func pluginRecordResponseFromStore(item store.PluginRecord, resource PluginResource) pluginRecordResponse {
	return pluginRecordResponse{
		ID:        item.ID,
		Key:       item.RecordKey,
		Data:      redactPluginResourceData(item.DataJSON, resource),
		Enabled:   item.Enabled,
		Revision:  item.Revision,
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}
}

func pluginRecordMutationResponse(db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource, item store.PluginRecord) pluginRecordResponse {
	resp := pluginRecordResponseFromStore(item, resource)
	status, err := applyPluginResourceRuntimeUpdateStatus(db, pm, plugin, resource)
	resp.RuntimeStatus = status
	if err != nil {
		resp.RuntimeError = err.Error()
		resp.Error = err.Error()
	}
	return resp
}

func applyPluginResourceRuntimeUpdateStatus(db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource) (*pluginRuntimeStatusResponse, error) {
	runtimeErr := applyPluginResourceRuntimeUpdate(db, pm, plugin, resource)
	status, statusErr := store.PluginRuntimeStatusOrNil(db, plugin.ID, "resource", resource.ID)
	if statusErr != nil {
		if runtimeErr != nil {
			return nil, fmt.Errorf("%v; load runtime status: %w", runtimeErr, statusErr)
		}
		return nil, statusErr
	}
	return pluginRuntimeStatusResponseFromStore(status), runtimeErr
}

func pluginRuntimeStatusResponseFromStore(item *store.PluginRuntimeStatus) *pluginRuntimeStatusResponse {
	if item == nil {
		return nil
	}
	return &pluginRuntimeStatusResponse{
		TargetType:      item.TargetType,
		TargetID:        item.TargetID,
		Status:          item.Status,
		Revision:        item.Revision,
		AppliedRevision: item.AppliedRevision,
		LastError:       item.LastError,
		UpdatedAt:       item.UpdatedAt,
	}
}

func redactPluginResourceData(dataJSON string, resource PluginResource) json.RawMessage {
	if strings.TrimSpace(dataJSON) == "" {
		return json.RawMessage(`null`)
	}
	if len(resource.SecretFields) == 0 {
		return json.RawMessage(dataJSON)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(dataJSON), &obj); err != nil || obj == nil {
		return json.RawMessage(dataJSON)
	}
	secretFields := make(map[string]struct{}, len(resource.SecretFields))
	for _, field := range resource.SecretFields {
		secretFields[strings.ToLower(field)] = struct{}{}
	}
	for key := range obj {
		if _, ok := secretFields[strings.ToLower(key)]; ok {
			obj[key] = json.RawMessage(`"__redacted__"`)
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return json.RawMessage(dataJSON)
	}
	return json.RawMessage(out)
}

func pluginResourceAllows(resource PluginResource, method string) bool {
	method = strings.TrimSpace(strings.ToLower(method))
	for _, value := range resource.Methods {
		if value == method {
			return true
		}
	}
	return false
}

func pluginResourceControlAllows(resource PluginResource, method string) bool {
	if len(resource.ControlMethods) == 0 {
		return pluginResourceAllows(resource, method)
	}
	method = strings.TrimSpace(strings.ToLower(method))
	for _, value := range resource.ControlMethods {
		if value == method {
			return true
		}
	}
	return false
}

func pluginResourceMaxRecords(resource PluginResource) int {
	if resource.MaxRecords <= 0 {
		return pluginResourceDefaultMaxRecords
	}
	return resource.MaxRecords
}

func pluginResourceMaxRecordBytes(resource PluginResource) int {
	if resource.MaxRecordBytes <= 0 {
		return pluginResourceDefaultMaxRecordBytes
	}
	return resource.MaxRecordBytes
}

func pluginActionMaxPayloadBytes(action PluginAction) int {
	if action.MaxPayloadBytes <= 0 {
		return pluginActionDefaultMaxPayloadBytes
	}
	return action.MaxPayloadBytes
}

func pluginRecordListPageFromQuery(values url.Values) (pluginRecordListPage, error) {
	limit, hasLimit, err := pluginRecordListIntParam(values, "limit")
	if err != nil {
		return pluginRecordListPage{}, err
	}
	offset, hasOffset, err := pluginRecordListIntParam(values, "offset")
	if err != nil {
		return pluginRecordListPage{}, err
	}
	return normalizePluginRecordListPage(limit, hasLimit, offset, hasOffset)
}

func pluginRecordListIntParam(values url.Values, name string) (int, bool, error) {
	rawValues, ok := values[name]
	if !ok {
		return 0, false, nil
	}
	raw := ""
	if len(rawValues) > 0 {
		raw = strings.TrimSpace(rawValues[len(rawValues)-1])
	}
	if raw == "" {
		return 0, true, fmt.Errorf("%s must be an integer", name)
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, true, fmt.Errorf("%s must be an integer", name)
	}
	return value, true, nil
}

func normalizePluginRecordListPage(limit int, hasLimit bool, offset int, hasOffset bool) (pluginRecordListPage, error) {
	if !hasLimit {
		limit = pluginResourceListDefaultLimit
	}
	if !hasOffset {
		offset = 0
	}
	if limit <= 0 || limit > pluginResourceListHardLimit {
		return pluginRecordListPage{}, fmt.Errorf("limit must be between 1 and %d", pluginResourceListHardLimit)
	}
	if offset < 0 {
		return pluginRecordListPage{}, fmt.Errorf("offset must be >= 0")
	}
	return pluginRecordListPage{Limit: limit, Offset: offset}, nil
}

func pluginPathToken(value string) (string, error) {
	decoded, err := url.PathUnescape(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("invalid path token")
	}
	decoded = strings.TrimSpace(strings.ToLower(decoded))
	if !pluginTokenPattern.MatchString(decoded) {
		return "", fmt.Errorf("token must match %s", pluginTokenPattern.String())
	}
	return decoded, nil
}

func newPluginRecordKey() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "rec_" + hex.EncodeToString(b[:])
	}
	return "rec_" + strconv.FormatInt(time.Now().UnixNano(), 36)
}
