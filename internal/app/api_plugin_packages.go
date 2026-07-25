package app

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

var pluginPackageFallbackMu sync.Mutex

func handlePluginPackageStageAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > pluginPackageMaxContainerBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": fmt.Sprintf("plugin package exceeds %d bytes", pluginPackageMaxContainerBytes)})
		return
	}
	for _, header := range []string{"X-Veer-Plugin-Signer", "X-Veer-Plugin-Public-Key", "X-Veer-Plugin-Signature"} {
		if strings.TrimSpace(r.Header.Get(header)) != "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "detached plugin signatures are not supported; upload a signed .veerpkg package"})
			return
		}
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, pluginPackageMaxContainerBytes+1)
	deferredRelationships := false
	if raw := strings.TrimSpace(r.URL.Query().Get("defer_relationships")); raw != "" {
		if raw != "true" && raw != "false" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "defer_relationships must be true or false"})
			return
		}
		deferredRelationships = raw == "true"
	}
	stage, err := manager.StageWithDeferredRelationships(r.Body, deferredRelationships)
	if err != nil {
		recordPluginAudit(db, "", "package.stage", "api", "error", map[string]any{"error": err.Error()})
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, stage)
}

func handlePluginPackageApplyAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginPackageApplyRequest
	if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result, err := manager.ApplyStage(request)
	if err != nil {
		recordPluginAudit(db, "", "package.apply", "api", "error", map[string]any{"stage_id": request.StageID, "error": err.Error()})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func handlePluginPackageBatchApplyAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginPackageBatchApplyRequest
	if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result, err := manager.ApplyBatch(request)
	if err != nil {
		stageIDs := make([]string, 0, len(request.Stages))
		for _, stage := range request.Stages {
			stageIDs = append(stageIDs, stage.StageID)
		}
		recordPluginAudit(db, "", "package.batch_apply", "api", "error", map[string]any{"stage_ids": stageIDs, "error": err.Error()})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func handlePluginPackageHistoryAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	history, err := manager.ListHistory(pluginID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, history)
}

func handlePluginPackageProvenanceAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	if pluginID != "" && (!pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid plugin id"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	statuses, err := manager.ListPluginPackageProvenance()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if pluginID != "" {
		filtered := make([]PluginPackageProvenanceStatus, 0, 1)
		for _, status := range statuses {
			if status.PluginID == pluginID {
				filtered = append(filtered, status)
				break
			}
		}
		statuses = filtered
	}
	writeJSON(w, http.StatusOK, statuses)
}

func handlePluginPackageProbationsAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	if pluginID != "" && (!pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid plugin id"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	probations, err := manager.ListProbations()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if pluginID != "" {
		filtered := make([]PluginPackageProbation, 0, 1)
		for _, probation := range probations {
			if probation.PluginID == pluginID {
				filtered = append(filtered, probation)
				break
			}
		}
		probations = filtered
	}
	writeJSON(w, http.StatusOK, probations)
}

func handlePluginPackageProbationGroupsAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	groupID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("group_id")))
	pluginID := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("plugin_id")))
	if groupID != "" && validatePluginPackageID(groupID) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid probation group id"})
		return
	}
	if pluginID != "" && (!pluginIDPattern.MatchString(pluginID) || reservedBuiltinPluginID(pluginID)) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid plugin id"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	groups, err := manager.ListProbationGroups()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	filtered := make([]PluginPackageProbationGroup, 0, len(groups))
	for _, group := range groups {
		if groupID != "" && group.ID != groupID {
			continue
		}
		if pluginID != "" {
			found := false
			for _, member := range group.Members {
				if member.PluginID == pluginID {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		filtered = append(filtered, group)
	}
	writeJSON(w, http.StatusOK, filtered)
}

func handlePluginPackageRollbackAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginPackageRollbackRequest
	if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	stage, err := manager.PrepareRollback(request)
	if err != nil {
		recordPluginAudit(db, request.PluginID, "package.rollback_stage", "api", "error", map[string]any{"history_id": request.HistoryID, "error": err.Error()})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, stage)
}

func handlePluginPackageUninstallAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginPackageUninstallRequest
	if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	result, err := manager.Uninstall(request)
	if err != nil {
		recordPluginAudit(db, request.PluginID, "package.uninstall", "api", "error", map[string]any{"purge_data": request.PurgeData, "error": err.Error()})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func handlePluginTrustAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet && !requirePluginAdminRequest(w, r, cfg) {
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		keys, err := manager.ListTrustKeys()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, keys)
	case http.MethodPost:
		var request PluginTrustKeyRequest
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		key, err := manager.AddTrustKey(request)
		if err != nil {
			recordPluginAudit(db, "", "trust.add", "api", "error", map[string]any{"name": request.Name, "error": err.Error()})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, key)
	case http.MethodDelete:
		var request struct {
			ID string `json:"id"`
		}
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := manager.DeleteTrustKey(request.ID); err != nil {
			recordPluginAudit(db, "", "trust.delete", "api", "error", map[string]any{"key_id": request.ID, "error": err.Error()})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func lockPluginPackageOperations(pm *ProcessManager) func() {
	if pm != nil {
		pm.pluginPackageMu.Lock()
		return pm.pluginPackageMu.Unlock
	}
	pluginPackageFallbackMu.Lock()
	return pluginPackageFallbackMu.Unlock
}
