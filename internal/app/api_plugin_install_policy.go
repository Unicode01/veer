package app

import (
	"net/http"
	"strings"
)

func pluginRemoteInstallAPIRequest(r *http.Request) bool {
	path := r.URL.Path
	if path == "/api/plugins/reload" {
		return true
	}
	for _, prefix := range []string{"/api/plugin-trust", "/api/plugin-repositories", "/api/plugin-repository-policies"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	// Installation history and probation state remain readable for diagnostics.
	return strings.HasPrefix(path, "/api/plugin-packages/") && r.Method != http.MethodGet
}

func pluginInstallationPolicyMiddleware(cfg *Config, next http.Handler) http.Handler {
	deny := authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "remote plugin installation is disabled; configure plugins_remote_install_enabled locally and restart Veer",
		})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.PluginRemoteInstallEnabled() && pluginRemoteInstallAPIRequest(r) {
			deny(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
