package app

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
	"github.com/dop251/goja"
)

const (
	pluginLogMaxEntriesPerPlugin = 500
	pluginLogMaxFieldsBytes      = 8 << 10
	pluginLogRateWindow          = time.Second
	pluginLogRateLimit           = 100
	pluginLogDefaultListLimit    = 100
	pluginLogMaxListLimit        = 500
)

type PluginLogEntry struct {
	Sequence  uint64         `json:"sequence"`
	PluginID  string         `json:"plugin_id"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
	Event     string         `json:"event,omitempty"`
	Worker    string         `json:"worker,omitempty"`
	CreatedAt string         `json:"created_at"`
}

type PluginLogState struct {
	Entries            uint64 `json:"entries"`
	Dropped            uint64 `json:"dropped"`
	PersistenceDropped uint64 `json:"persistence_dropped"`
}

type pluginLogBuffer struct {
	entries      []PluginLogEntry
	dropped      uint64
	totalEntries uint64
	windowStart  time.Time
	windowCount  int
}

type pluginLogsResponse struct {
	PluginID string           `json:"plugin_id"`
	Logs     []PluginLogEntry `json:"logs"`
	State    PluginLogState   `json:"state"`
}

func (h *pluginControlHost) writePluginLog(level string, call goja.FunctionCall) {
	message, fields := h.structuredPluginLogMessage(call)
	entry := PluginLogEntry{
		PluginID: h.plugin.ID,
		Level:    level,
		Message:  message,
		Fields:   fields,
		Worker:   h.workerName,
	}
	if len(h.eventStack) > 0 {
		entry.Event = h.eventStack[len(h.eventStack)-1]
	}
	if h.runtime != nil {
		h.runtime.appendPluginLog(entry)
	}
	if len(fields) == 0 {
		log.Printf("plugin %s %s: %s", h.plugin.ID, level, message)
		return
	}
	raw, _ := json.Marshal(fields)
	log.Printf("plugin %s %s: %s fields=%s", h.plugin.ID, level, message, raw)
}

func (h *pluginControlHost) structuredPluginLogMessage(call goja.FunctionCall) (string, map[string]any) {
	arguments := call.Arguments
	var fields map[string]any
	if len(arguments) > 1 {
		if candidate, ok := arguments[len(arguments)-1].Export().(map[string]any); ok {
			fields = sanitizePluginLogFields(candidate, 0)
			arguments = arguments[:len(arguments)-1]
		}
	}
	parts := make([]string, 0, len(arguments))
	for _, arg := range arguments {
		if goja.IsUndefined(arg) {
			continue
		}
		parts = append(parts, arg.String())
	}
	message := boundedPluginControlHealthError(strings.Join(parts, " "))
	if message == "" {
		message = "plugin log"
	}
	if len(fields) > 0 {
		raw, err := json.Marshal(fields)
		if err != nil || len(raw) > pluginLogMaxFieldsBytes {
			fields = map[string]any{"_truncated": true}
		}
	}
	return message, fields
}

func sanitizePluginLogFields(fields map[string]any, depth int) map[string]any {
	if fields == nil || depth > 8 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for key, value := range fields {
		if pluginLogSensitiveField(key) {
			out[key] = "__redacted__"
			continue
		}
		out[key] = sanitizePluginLogValue(value, depth+1)
	}
	return out
}

func sanitizePluginLogValue(value any, depth int) any {
	if depth > 8 {
		return "__truncated__"
	}
	switch typed := value.(type) {
	case map[string]any:
		return sanitizePluginLogFields(typed, depth)
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = sanitizePluginLogValue(typed[i], depth+1)
		}
		return out
	default:
		return typed
	}
}

func pluginLogSensitiveField(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	key = strings.ReplaceAll(key, "-", "_")
	switch key {
	case "authorization", "cookie", "password", "passwd", "private_key", "secret", "token", "api_key", "web_token", "access_token", "refresh_token":
		return true
	default:
		return strings.HasSuffix(key, "_password") || strings.HasSuffix(key, "_secret") || strings.HasSuffix(key, "_token")
	}
}

func (rt *gojaPluginControlRuntime) appendPluginLog(entry PluginLogEntry) bool {
	if rt == nil || entry.PluginID == "" {
		return false
	}
	now := time.Now().UTC()
	rt.logMu.Lock()
	defer rt.logMu.Unlock()
	if rt.pluginLogs == nil {
		rt.pluginLogs = make(map[string]*pluginLogBuffer)
	}
	buffer := rt.pluginLogs[entry.PluginID]
	if buffer == nil {
		buffer = &pluginLogBuffer{}
		rt.pluginLogs[entry.PluginID] = buffer
	}
	if buffer.windowStart.IsZero() || now.Sub(buffer.windowStart) >= pluginLogRateWindow {
		buffer.windowStart = now
		buffer.windowCount = 0
	}
	if buffer.windowCount >= pluginLogRateLimit {
		buffer.dropped++
		return false
	}
	buffer.windowCount++
	rt.pluginLogSequence++
	entry.Sequence = rt.pluginLogSequence
	entry.CreatedAt = now.Format(time.RFC3339Nano)
	entry.Level = normalizePluginLogLevel(entry.Level)
	entry.Message = boundedPluginControlHealthError(entry.Message)
	entry.Fields = sanitizePluginLogFields(entry.Fields, 0)
	buffer.totalEntries++
	if len(buffer.entries) >= pluginLogMaxEntriesPerPlugin {
		copy(buffer.entries, buffer.entries[1:])
		buffer.entries[len(buffer.entries)-1] = entry
	} else {
		buffer.entries = append(buffer.entries, entry)
	}
	if rt.logPersistence != nil {
		rt.logPersistence.enqueue(entry)
	}
	return true
}

func pluginControlFailureLogEntry(pluginID, worker string, event pluginControlEvent, err error) PluginLogEntry {
	message := "plugin control handler failed"
	if err != nil {
		message = err.Error()
	}
	return PluginLogEntry{
		PluginID: pluginID,
		Level:    "error",
		Message:  message,
		Event:    pluginControlCircuitKey(event),
		Worker:   worker,
		Fields: map[string]any{
			"kind": event.Kind,
		},
	}
}

func normalizePluginLogLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "info", "warn", "error":
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return "info"
	}
}

func (rt *gojaPluginControlRuntime) pluginLogEntries(pluginID, level string, limit int) ([]PluginLogEntry, PluginLogState) {
	if limit <= 0 || limit > pluginLogMaxListLimit {
		limit = pluginLogDefaultListLimit
	}
	level = strings.ToLower(strings.TrimSpace(level))
	rt.logMu.Lock()
	defer rt.logMu.Unlock()
	buffer := rt.pluginLogs[pluginID]
	if buffer == nil {
		return []PluginLogEntry{}, PluginLogState{}
	}
	state := PluginLogState{Entries: buffer.totalEntries, Dropped: buffer.dropped}
	if rt.logPersistence != nil {
		state.PersistenceDropped = rt.logPersistence.droppedEntries(pluginID)
	}
	out := make([]PluginLogEntry, 0, min(limit, len(buffer.entries)))
	for i := len(buffer.entries) - 1; i >= 0 && len(out) < limit; i-- {
		entry := buffer.entries[i]
		if level != "" && entry.Level != level {
			continue
		}
		entry.Fields = clonePluginLogFields(entry.Fields)
		out = append(out, entry)
	}
	return out, state
}

func clonePluginLogFields(fields map[string]any) map[string]any {
	if fields == nil {
		return nil
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return map[string]any{"_invalid": true}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{"_invalid": true}
	}
	return out
}

func (rt *gojaPluginControlRuntime) pluginLogState(pluginID string) PluginLogState {
	if rt == nil {
		return PluginLogState{}
	}
	rt.logMu.Lock()
	defer rt.logMu.Unlock()
	buffer := rt.pluginLogs[pluginID]
	if buffer == nil {
		return PluginLogState{}
	}
	state := PluginLogState{Entries: buffer.totalEntries, Dropped: buffer.dropped}
	if rt.logPersistence != nil {
		state.PersistenceDropped = rt.logPersistence.droppedEntries(pluginID)
	}
	return state
}

func (rt *gojaPluginControlRuntime) clearAllPluginLogs() {
	if rt == nil {
		return
	}
	rt.logMu.Lock()
	rt.pluginLogs = nil
	rt.logMu.Unlock()
}

func handlePluginLogsAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager, parts []string) {
	if len(parts) != 2 || !pluginIDPattern.MatchString(parts[0]) {
		http.NotFound(w, r)
		return
	}
	pluginID := strings.ToLower(strings.TrimSpace(parts[0]))
	if !externalPluginExists(cfg, pm, pluginID) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plugin not found"})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := pluginLogDefaultListLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > pluginLogMaxListLimit {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("limit must be between 1 and %d", pluginLogMaxListLimit)})
			return
		}
		limit = value
	}
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	if level != "" && normalizePluginLogLevel(level) != level {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "level must be debug, info, warn, or error"})
		return
	}
	beforeID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("before_id")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "before_id must be a positive integer"})
			return
		}
		beforeID = value
	}
	logs := []PluginLogEntry{}
	state := PluginLogState{}
	if pm != nil {
		if rt, ok := pm.pluginControlRuntime.(*gojaPluginControlRuntime); ok {
			state = rt.pluginLogState(pluginID)
			if db == nil {
				logs, state = rt.pluginLogEntries(pluginID, level, limit)
			} else if rt.logPersistence != nil {
				rt.logPersistence.flushPending(pluginLogPersistTimeout)
			}
		}
	}
	if db != nil {
		persisted, err := store.GetPluginLogs(db, pluginID, level, limit, beforeID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		logs = make([]PluginLogEntry, 0, len(persisted))
		for _, item := range persisted {
			fields := map[string]any(nil)
			if item.FieldsJSON != "" && item.FieldsJSON != "{}" {
				if err := json.Unmarshal([]byte(item.FieldsJSON), &fields); err != nil {
					fields = map[string]any{"_invalid": true}
				}
			}
			logs = append(logs, PluginLogEntry{
				Sequence: uint64(item.ID), PluginID: item.PluginID, Level: item.Level, Message: item.Message,
				Fields: fields, Event: item.Event, Worker: item.Worker, CreatedAt: item.CreatedAt,
			})
		}
		count, err := store.CountPluginLogs(db, pluginID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		state.Entries = count
	}
	writeJSON(w, http.StatusOK, pluginLogsResponse{PluginID: pluginID, Logs: logs, State: state})
}
