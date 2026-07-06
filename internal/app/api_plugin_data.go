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

type pluginRecordResponse struct {
	ID        int64           `json:"id"`
	Key       string          `json:"key"`
	Data      json.RawMessage `json:"data"`
	Enabled   bool            `json:"enabled"`
	Revision  int64           `json:"revision"`
	CreatedAt string          `json:"created_at,omitempty"`
	UpdatedAt string          `json:"updated_at,omitempty"`
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
	RuntimeStatus *pluginRuntimeStatusResponse `json:"runtime_status,omitempty"`
}

type pluginActionResponse struct {
	PluginID      string                       `json:"plugin_id"`
	ActionID      string                       `json:"action_id"`
	Status        string                       `json:"status"`
	RuntimeUpdate string                       `json:"runtime_update"`
	RuntimeStatus *pluginRuntimeStatusResponse `json:"runtime_status,omitempty"`
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

func handlePluginResourceAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager, parts []string) {
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin data store is unavailable"})
		return
	}
	if len(parts) < 3 || len(parts) > 4 {
		http.NotFound(w, r)
		return
	}
	plugin, resource, ok := pluginResourceForRequest(w, cfg, parts[0], parts[2])
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
			handleListPluginRecords(w, db, plugin, resource)
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
	plugin, action, ok := pluginActionForRequest(w, cfg, parts[0], parts[2])
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
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
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

func handleListPluginRecords(w http.ResponseWriter, db *sql.DB, plugin LoadedPlugin, resource PluginResource) {
	records, err := store.GetPluginRecords(db, plugin.ID, resource.ID)
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
	_ = applyPluginResourceRuntimeUpdate(db, pm, plugin, resource)
	writeJSON(w, http.StatusCreated, pluginRecordResponseFromStore(*created, resource))
}

func handleUpdatePluginRecord(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager, plugin LoadedPlugin, resource PluginResource, recordKey string) {
	req, ok := decodePluginRecordWriteRequest(w, r, resource)
	if !ok {
		return
	}
	dataJSON, err := pluginRecordDataJSON(req.Data, resource)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
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
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
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
	_ = applyPluginResourceRuntimeUpdate(db, pm, plugin, resource)
	writeJSON(w, http.StatusOK, pluginRecordResponseFromStore(*updated, resource))
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
	_ = applyPluginResourceRuntimeUpdate(db, pm, plugin, resource)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func pluginResourceForRequest(w http.ResponseWriter, cfg *Config, pluginID, resourceID string) (LoadedPlugin, PluginResource, bool) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	resourceID = strings.TrimSpace(strings.ToLower(resourceID))
	if !pluginIDPattern.MatchString(pluginID) || !pluginTokenPattern.MatchString(resourceID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return LoadedPlugin{}, PluginResource{}, false
	}
	plugin, ok := loadedPluginForControlAPI(cfg, pluginID)
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

func pluginActionForRequest(w http.ResponseWriter, cfg *Config, pluginID, actionID string) (LoadedPlugin, PluginAction, bool) {
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	actionID = strings.TrimSpace(strings.ToLower(actionID))
	if !pluginIDPattern.MatchString(pluginID) || !pluginTokenPattern.MatchString(actionID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return LoadedPlugin{}, PluginAction{}, false
	}
	plugin, ok := loadedPluginForControlAPI(cfg, pluginID)
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

func loadedPluginForControlAPI(cfg *Config, pluginID string) (LoadedPlugin, bool) {
	catalog := loadPluginCatalog(cfg)
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
	if len(req.Data) > pluginResourceMaxRecordBytes(resource) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "data exceeds resource max_record_bytes"})
		return req, false
	}
	return req, true
}

func pluginRecordDataJSON(raw json.RawMessage, resource PluginResource) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("data is required")
	}
	if len(raw) > pluginResourceMaxRecordBytes(resource) {
		return "", fmt.Errorf("data exceeds resource max_record_bytes")
	}
	if !json.Valid(raw) {
		return "", fmt.Errorf("data must be valid json")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return "", fmt.Errorf("data must be valid json")
	}
	return buf.String(), nil
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
