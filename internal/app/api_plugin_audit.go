package app

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Unicode01/veer/internal/store"
)

const (
	pluginAuditDefaultLimit   = 100
	pluginAuditMaxLimit       = 500
	pluginAuditMaxDetailsSize = 16 << 10
)

type pluginAuditLogResponse struct {
	ID        int64           `json:"id"`
	PluginID  string          `json:"plugin_id,omitempty"`
	Operation string          `json:"operation"`
	Actor     string          `json:"actor"`
	Outcome   string          `json:"outcome"`
	Details   json.RawMessage `json:"details"`
	CreatedAt string          `json:"created_at"`
}

func recordPluginAudit(db *sql.DB, pluginID, operation, actor, outcome string, details map[string]any) {
	if db == nil {
		return
	}
	pluginID = strings.TrimSpace(strings.ToLower(pluginID))
	operation = strings.TrimSpace(strings.ToLower(operation))
	actor = strings.TrimSpace(strings.ToLower(actor))
	outcome = strings.TrimSpace(strings.ToLower(outcome))
	if actor == "" {
		actor = "system"
	}
	raw, err := json.Marshal(sanitizePluginLogFields(details, 0))
	if err != nil || len(raw) > pluginAuditMaxDetailsSize {
		raw = []byte(`{"_truncated":true}`)
	}
	if err := store.AddPluginAuditLog(db, store.PluginAuditLog{
		PluginID: pluginID, Operation: operation, Actor: actor, Outcome: outcome, DetailsJSON: string(raw),
	}); err != nil {
		log.Printf("plugin audit write failed: plugin=%s operation=%s outcome=%s error=%s",
			strconv.QuoteToASCII(pluginID), strconv.QuoteToASCII(operation), strconv.QuoteToASCII(outcome), strconv.QuoteToASCII(err.Error()))
	}
}

func handlePluginAuditAPI(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if db == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin audit store is unavailable"})
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	if pluginID != "" && !pluginIDPattern.MatchString(pluginID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid plugin_id"})
		return
	}
	limit := pluginAuditDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > pluginAuditMaxLimit {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit"})
			return
		}
		limit = value
	}
	beforeID := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("before_id")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid before_id"})
			return
		}
		beforeID = value
	}
	items, err := store.GetPluginAuditLogs(db, pluginID, limit, beforeID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]pluginAuditLogResponse, 0, len(items))
	for _, item := range items {
		details := json.RawMessage(item.DetailsJSON)
		if !json.Valid(details) {
			details = json.RawMessage(`{"_invalid":true}`)
		}
		out = append(out, pluginAuditLogResponse{
			ID: item.ID, PluginID: item.PluginID, Operation: item.Operation, Actor: item.Actor, Outcome: item.Outcome,
			Details: details, CreatedAt: item.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": out, "limit": limit})
}
