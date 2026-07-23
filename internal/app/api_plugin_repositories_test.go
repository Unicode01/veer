package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPluginRepositoryAPIManagesPinnedRepositoryConfiguration(t *testing.T) {
	repositoryServer := newPluginRepositoryTestServer(t)
	repositoryServer.publish(1, nil)
	cfg := pluginsEnabledTestConfig(&Config{
		WebToken: "repository-token", PluginAdminToken: "repository-admin", PluginsDir: t.TempDir(),
	})
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	request := repositoryServer.request("official", "stable")
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	perform := func(method, target string, body []byte, admin bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer repository-token")
		if admin {
			req.Header.Set(pluginAdminTokenHeader, "repository-admin")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	if rec := perform(http.MethodPost, "/api/plugin-repositories", body, false); rec.Code != http.StatusForbidden {
		t.Fatalf("repository add without admin = %d %s", rec.Code, rec.Body.String())
	}
	added := perform(http.MethodPost, "/api/plugin-repositories", body, true)
	if added.Code != http.StatusCreated || !strings.Contains(added.Body.String(), `"root_sha256"`) || strings.Contains(added.Body.String(), `"root":`) {
		t.Fatalf("repository add = %d %s", added.Code, added.Body.String())
	}
	listed := perform(http.MethodGet, "/api/plugin-repositories", nil, false)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"id":"official"`) {
		t.Fatalf("repository list = %d %s", listed.Code, listed.Body.String())
	}
	catalog := perform(http.MethodGet, "/api/plugin-repositories/catalog?repository_id=official", nil, false)
	if catalog.Code != http.StatusNotFound || !strings.Contains(catalog.Body.String(), "has not been refreshed") {
		t.Fatalf("repository empty catalog = %d %s", catalog.Code, catalog.Body.String())
	}
	policyBody := []byte(`{"plugin_id":"demo_plugin","repository_id":"official","channel":"stable","pinned_version":"1.0.0","hold":true}`)
	if rec := perform(http.MethodPut, "/api/plugin-repository-policies", policyBody, false); rec.Code != http.StatusForbidden {
		t.Fatalf("repository policy write without admin = %d %s", rec.Code, rec.Body.String())
	}
	policy := perform(http.MethodPut, "/api/plugin-repository-policies", policyBody, true)
	if policy.Code != http.StatusOK || !strings.Contains(policy.Body.String(), `"pinned_version":"1.0.0"`) || !strings.Contains(policy.Body.String(), `"hold":true`) {
		t.Fatalf("repository policy write = %d %s", policy.Code, policy.Body.String())
	}
	policies := perform(http.MethodGet, "/api/plugin-repository-policies", nil, false)
	if policies.Code != http.StatusOK || !strings.Contains(policies.Body.String(), `"plugin_id":"demo_plugin"`) {
		t.Fatalf("repository policy list = %d %s", policies.Code, policies.Body.String())
	}
	updates := perform(http.MethodGet, "/api/plugin-repositories/updates", nil, false)
	if updates.Code != http.StatusOK || strings.TrimSpace(updates.Body.String()) != "[]" {
		t.Fatalf("repository updates = %d %s", updates.Code, updates.Body.String())
	}
	if rec := perform(http.MethodDelete, "/api/plugin-repositories", []byte(`{"id":"official"}`), true); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "referenced by policy") {
		t.Fatalf("repository delete with policy = %d %s", rec.Code, rec.Body.String())
	}
	removedPolicy := perform(http.MethodDelete, "/api/plugin-repository-policies", []byte(`{"plugin_id":"demo_plugin"}`), true)
	if removedPolicy.Code != http.StatusOK {
		t.Fatalf("repository policy delete = %d %s", removedPolicy.Code, removedPolicy.Body.String())
	}
	deleted := perform(http.MethodDelete, "/api/plugin-repositories", []byte(`{"id":"official"}`), true)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"status":"deleted"`) {
		t.Fatalf("repository delete = %d %s", deleted.Code, deleted.Body.String())
	}
}
