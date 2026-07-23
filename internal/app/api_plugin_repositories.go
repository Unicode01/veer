package app

import (
	"database/sql"
	"net/http"
	"strings"
)

func handlePluginRepositoriesAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
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
		repositories, err := manager.ListRepositories()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, repositories)
	case http.MethodPost:
		var request PluginRepositoryRequest
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		repository, err := manager.AddRepository(request)
		if err != nil {
			recordPluginAudit(db, "", "repository.add", "api", "error", map[string]any{"repository_id": request.ID, "error": err.Error()})
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, repository)
	case http.MethodDelete:
		var request struct {
			ID string `json:"id"`
		}
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := manager.DeleteRepository(request.ID); err != nil {
			recordPluginAudit(db, "", "repository.delete", "api", "error", map[string]any{"repository_id": request.ID, "error": err.Error()})
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePluginRepositoryCatalogAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("repository_id")))
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	catalog, err := manager.LoadRepositoryCatalog(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, catalog)
}

func handlePluginRepositoryRefreshAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		RepositoryID string `json:"repository_id"`
	}
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
	catalog, err := manager.RefreshRepository(request.RepositoryID)
	if err != nil {
		recordPluginAudit(db, "", "repository.refresh", "api", "error", map[string]any{"repository_id": request.RepositoryID, "error": err.Error()})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, catalog)
}

func handlePluginRepositoryStageAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginRepositoryStageRequest
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
	stage, err := manager.StageFromRepository(request)
	if err != nil {
		recordPluginAudit(db, request.PluginID, "repository.stage", "api", "error", map[string]any{
			"repository_id": request.RepositoryID, "version": request.Version, "error": err.Error(),
		})
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, stage)
}

func handlePluginRepositoryPlanAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request PluginRepositoryInstallPlanRequest
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
	plan, err := manager.PrepareRepositoryInstallPlan(request)
	if err != nil {
		recordPluginAudit(db, request.PluginID, "repository.plan", "api", "error", map[string]any{
			"repository_id": request.RepositoryID, "version": request.Version, "error": err.Error(),
		})
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	recordPluginAudit(db, request.PluginID, "repository.plan", "api", "success", map[string]any{
		"repository_id": request.RepositoryID, "version": request.Version, "stage_count": len(plan.Stages),
	})
	writeJSON(w, http.StatusCreated, plan)
}

func handlePluginRepositoryPoliciesAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
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
		policies, err := manager.ListRepositoryPolicies()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, policies)
	case http.MethodPut:
		var request PluginRepositoryPolicyRequest
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		policy, err := manager.SetRepositoryPolicy(request)
		if err != nil {
			recordPluginAudit(db, request.PluginID, "repository.policy.set", "api", "error", map[string]any{"error": err.Error()})
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, policy)
	case http.MethodDelete:
		var request struct {
			PluginID string `json:"plugin_id"`
		}
		if err := decodeJSONRequestBody(w, r, &request, apiJSONBodyMaxBytes); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		if err := manager.DeleteRepositoryPolicy(request.PluginID); err != nil {
			recordPluginAudit(db, request.PluginID, "repository.policy.delete", "api", "error", map[string]any{"error": err.Error()})
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handlePluginRepositoryUpdatesAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	unlock := lockPluginPackageOperations(pm)
	defer unlock()
	manager, err := newPluginPackageManager(cfg, db, pm)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	updates, err := manager.ListRepositoryUpdates()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, updates)
}
