package app

import (
	"database/sql"
	"net/http"
)

func handlePluginSecretsAPI(w http.ResponseWriter, r *http.Request, cfg *Config, db *sql.DB, pm *ProcessManager) {
	if r.Method != http.MethodGet && !requirePluginAdminRequest(w, r, cfg) {
		return
	}
	if pm == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "plugin secret runtime is unavailable"})
		return
	}
	secrets, err := pluginSecretStoreForRequest(db, pm)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, secrets.status())
	case http.MethodPost:
		unlock := lockPluginPackageOperations(pm)
		defer unlock()
		result, err := secrets.rotate(pm.pluginCatalogWithConfig(cfg))
		if err != nil {
			recordPluginAudit(db, "", "secrets.rotate", "api", "error", map[string]any{"error": err.Error()})
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		recordPluginAudit(db, "", "secrets.rotate", "api", "success", map[string]any{"active_key": result.ActiveKey})
		writeJSON(w, http.StatusOK, result)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
