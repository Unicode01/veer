package app

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Unicode01/veer/internal/store"
)

const pluginEventDeadLetterAPIPageSize = 100

type pluginEventDeadLetterMutationRequest struct {
	PluginID   string `json:"plugin_id"`
	DeliveryID string `json:"delivery_id"`
}

func handlePluginEventDeadLettersAPI(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	if pluginID != "" && (!pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plugin_id is invalid"})
		return
	}
	limit := pluginEventDeadLetterAPIPageSize
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 500 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 500"})
			return
		}
		limit = value
	}
	var beforeID int64
	if raw := strings.TrimSpace(r.URL.Query().Get("before_id")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "before_id is invalid"})
			return
		}
		beforeID = value
	}
	items, err := store.ListDeadPluginEventDeliveries(db, pluginID, beforeID, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		value := pluginEventDeliveryPublicState(item)
		value["id"] = item.ID
		out = append(out, value)
	}
	writeJSON(w, http.StatusOK, out)
}

func handlePluginEventDeadLetterRetryAPI(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := decodePluginEventDeadLetterMutation(w, r)
	if !ok {
		return
	}
	item, err := store.RetryDeadPluginEventDelivery(db, request.PluginID, request.DeliveryID, time.Now().UnixMilli())
	if err != nil {
		recordPluginAudit(db, request.PluginID, "event.dead_letter.retry", "api", "error", map[string]any{"delivery_id": request.DeliveryID, "error": err.Error()})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	if runtime := pluginEventControlRuntime(pm); runtime != nil {
		runtime.noteRetriedDeadPluginEvent(*item)
	}
	recordPluginAudit(db, request.PluginID, "event.dead_letter.retry", "api", "success", map[string]any{"delivery_id": request.DeliveryID})
	writeJSON(w, http.StatusOK, pluginEventDeliveryPublicState(*item))
}

func handlePluginEventDeadLetterDiscardAPI(w http.ResponseWriter, r *http.Request, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	request, ok := decodePluginEventDeadLetterMutation(w, r)
	if !ok {
		return
	}
	item, err := store.GetPluginEventDelivery(db, request.PluginID, request.DeliveryID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "dead-letter delivery was not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if item.Status != store.PluginEventDeliveryDead {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "delivery is not dead-lettered"})
		return
	}
	deleted, err := store.DeleteDeadPluginEventDelivery(db, request.PluginID, request.DeliveryID)
	if err != nil {
		recordPluginAudit(db, request.PluginID, "event.dead_letter.discard", "api", "error", map[string]any{"delivery_id": request.DeliveryID, "error": err.Error()})
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !deleted {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "delivery changed while discarding"})
		return
	}
	if runtime := pluginEventControlRuntime(pm); runtime != nil {
		runtime.noteDiscardedPluginEvent(*item)
	}
	recordPluginAudit(db, request.PluginID, "event.dead_letter.discard", "api", "success", map[string]any{"delivery_id": request.DeliveryID})
	writeJSON(w, http.StatusOK, map[string]any{"discarded": true, "plugin_id": request.PluginID, "delivery_id": request.DeliveryID})
}

func decodePluginEventDeadLetterMutation(w http.ResponseWriter, r *http.Request) (pluginEventDeadLetterMutationRequest, bool) {
	var request pluginEventDeadLetterMutationRequest
	if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return request, false
	}
	request.PluginID = strings.TrimSpace(strings.ToLower(request.PluginID))
	request.DeliveryID = strings.TrimSpace(strings.ToLower(request.DeliveryID))
	if !pluginIDPattern.MatchString(request.PluginID) || reservedBuiltinPluginID(request.PluginID) || validatePluginPackageID(request.DeliveryID) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "plugin_id or delivery_id is invalid"})
		return request, false
	}
	return request, true
}

func pluginEventControlRuntime(pm *ProcessManager) *gojaPluginControlRuntime {
	if pm == nil {
		return nil
	}
	pm.mu.Lock()
	runtime, _ := pm.pluginControlRuntime.(*gojaPluginControlRuntime)
	pm.mu.Unlock()
	return runtime
}
