package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPluginPackageAPIsRequireAuthentication(t *testing.T) {
	cfg := &Config{WebToken: "package-token", PluginsDir: t.TempDir()}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	for _, test := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/plugin-packages/stage"},
		{http.MethodPost, "/api/plugin-packages/apply"},
		{http.MethodPost, "/api/plugin-packages/apply-batch"},
		{http.MethodGet, "/api/plugin-packages/history?plugin_id=test_plugin"},
		{http.MethodGet, "/api/plugin-packages/provenance?plugin_id=test_plugin"},
		{http.MethodGet, "/api/plugin-packages/probations?plugin_id=test_plugin"},
		{http.MethodGet, "/api/plugin-packages/probation-groups?plugin_id=test_plugin"},
		{http.MethodPost, "/api/plugin-packages/rollback"},
		{http.MethodPost, "/api/plugin-packages/uninstall"},
		{http.MethodGet, "/api/plugin-trust"},
		{http.MethodPost, "/api/plugin-trust"},
		{http.MethodDelete, "/api/plugin-trust"},
		{http.MethodGet, "/api/plugin-repositories"},
		{http.MethodPost, "/api/plugin-repositories"},
		{http.MethodDelete, "/api/plugin-repositories"},
		{http.MethodGet, "/api/plugin-repositories/catalog?repository_id=official"},
		{http.MethodPost, "/api/plugin-repositories/refresh"},
		{http.MethodPost, "/api/plugin-repositories/stage"},
		{http.MethodPost, "/api/plugin-repositories/plan"},
		{http.MethodGet, "/api/plugin-repository-policies"},
		{http.MethodPut, "/api/plugin-repository-policies"},
		{http.MethodDelete, "/api/plugin-repository-policies"},
		{http.MethodGet, "/api/plugin-repositories/updates"},
		{http.MethodGet, "/api/plugin-event-dead-letters"},
		{http.MethodPost, "/api/plugin-event-dead-letters/retry"},
		{http.MethodPost, "/api/plugin-event-dead-letters/discard"},
	} {
		req := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want %d", test.method, test.path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestPluginPackageMutationsRequireSeparateAdminToken(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "package-token", PluginAdminToken: "package-admin", PluginsDir: t.TempDir()})
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: "admin_gate", Version: "1.0.0"})
	request := func(adminToken string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/plugin-packages/stage", bytes.NewReader(archive))
		req.Header.Set("Authorization", "Bearer package-token")
		if adminToken != "" {
			req.Header.Set(pluginAdminTokenHeader, adminToken)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(""); rec.Code != http.StatusForbidden {
		t.Fatalf("stage without plugin admin status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := request("wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("stage with wrong plugin admin status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := request("package-admin"); rec.Code != http.StatusCreated {
		t.Fatalf("stage with plugin admin status = %d: %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/plugin-admin/status", nil)
	req.Header.Set("Authorization", "Bearer package-token")
	req.Header.Set(pluginAdminTokenHeader, "package-admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"configured":true`) || !strings.Contains(rec.Body.String(), `"authorized":true`) {
		t.Fatalf("plugin admin status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPluginPackageMutationsAreDisabledWithoutAdminToken(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "package-token", PluginAdminToken: "", PluginsDir: t.TempDir()})
	cfg.PluginAdminToken = ""
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/plugin-packages/stage", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Authorization", "Bearer package-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("disabled plugin admin status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPluginPackageBatchAPIEndToEnd(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "package-token", PluginsDir: t.TempDir()})
	handler := buildAPIHandler(cfg, openTestDB(t), nil)
	requests := make([]PluginPackageApplyRequest, 0, 2)
	for _, pluginID := range []string{"api_batch_a", "api_batch_b"} {
		archive := buildPluginPackageForTest(t, pluginPackageTestSpec{ID: pluginID, Version: "1.0.0"})
		rec := performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/stage?defer_relationships=true", archive)
		if rec.Code != http.StatusCreated {
			t.Fatalf("stage %s status = %d: %s", pluginID, rec.Code, rec.Body.String())
		}
		var stage PluginPackageStage
		decodePluginPackageAPIResponse(t, rec, &stage)
		if !stage.DeferredRelationships {
			t.Fatalf("stage %s did not defer relationships", pluginID)
		}
		requests = append(requests, PluginPackageApplyRequest{StageID: stage.ID, AllowUnsigned: true})
	}
	rec := performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/apply-batch", mustPluginPackageJSON(t, PluginPackageBatchApplyRequest{Stages: requests}))
	if rec.Code != http.StatusOK {
		t.Fatalf("batch apply status = %d: %s", rec.Code, rec.Body.String())
	}
	var result PluginPackageBatchOperationResult
	decodePluginPackageAPIResponse(t, rec, &result)
	if result.Operation != "batch_apply" || len(result.Plugins) != 2 {
		t.Fatalf("batch apply result = %+v", result)
	}
	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/probation-groups?group_id="+url.QueryEscape(result.ID), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("probation group status = %d: %s", rec.Code, rec.Body.String())
	}
	var groups []PluginPackageProbationGroup
	decodePluginPackageAPIResponse(t, rec, &groups)
	if len(groups) != 1 || groups[0].ID != result.ID || len(groups[0].Members) != 2 {
		t.Fatalf("probation groups = %+v", groups)
	}
}

func TestPluginPackageProvenanceAPIReportsInstalledTrustState(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "package-token", PluginsDir: t.TempDir()})
	db := openTestDB(t)
	manager, err := newPluginPackageManager(cfg, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.applyPluginPackageProvenance(
		"api_origin",
		pluginPackageProvenanceForTest("api_origin", "1.0.0", "c"),
		time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
	handler := buildAPIHandler(cfg, db, nil)
	rec := performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/provenance?plugin_id=api_origin", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("provenance status = %d: %s", rec.Code, rec.Body.String())
	}
	var statuses []PluginPackageProvenanceStatus
	decodePluginPackageAPIResponse(t, rec, &statuses)
	if len(statuses) != 1 || statuses[0].PluginID != "api_origin" || statuses[0].Status != "repository_unavailable" {
		t.Fatalf("provenance statuses = %+v", statuses)
	}
	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/provenance?plugin_id=../escape", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid provenance filter status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPluginPackageAPIEndToEnd(t *testing.T) {
	cfg := pluginsEnabledTestConfig(&Config{WebToken: "package-token", PluginsDir: t.TempDir()})
	db := openTestDB(t)
	handler := buildAPIHandler(cfg, db, nil)

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trustBody := mustPluginPackageJSON(t, PluginTrustKeyRequest{
		Name: "API Publisher", PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		Scope: &PluginTrustScope{PluginIDs: []string{"api_*"}, ExecutionTiers: []string{pluginPackageExecutionTierControl}},
	})
	rec := performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-trust", trustBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST trust status = %d: %s", rec.Code, rec.Body.String())
	}
	var trustKey PluginTrustKey
	decodePluginPackageAPIResponse(t, rec, &trustKey)
	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-trust", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET trust status = %d: %s", rec.Code, rec.Body.String())
	}
	var trustKeys []PluginTrustKey
	decodePluginPackageAPIResponse(t, rec, &trustKeys)
	if len(trustKeys) != 1 || trustKeys[0].ID != trustKey.ID || !equalPluginTrustScopes(trustKeys[0].Scope, trustKey.Scope) {
		t.Fatalf("trust keys = %+v", trustKeys)
	}

	installVersion := func(version string) PluginPackageOperationResult {
		t.Helper()
		archive := buildPluginPackageForTest(t, pluginPackageTestSpec{
			ID: "api_managed", Version: version, Permissions: []string{"plugin.register"}, Control: `exports.onReconcile = function () {};`,
		})
		rec := performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/stage", archive)
		if rec.Code != http.StatusCreated {
			t.Fatalf("stage %s status = %d: %s", version, rec.Code, rec.Body.String())
		}
		var stage PluginPackageStage
		decodePluginPackageAPIResponse(t, rec, &stage)
		apply := PluginPackageApplyRequest{StageID: stage.ID, ApprovedPrivilegeDigest: stage.PrivilegeDigest, AllowUnsigned: true}
		rec = performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/apply", mustPluginPackageJSON(t, apply))
		if rec.Code != http.StatusOK {
			t.Fatalf("apply %s status = %d: %s", version, rec.Code, rec.Body.String())
		}
		var result PluginPackageOperationResult
		decodePluginPackageAPIResponse(t, rec, &result)
		return result
	}

	if result := installVersion("1.0.0"); result.Operation != "install" || result.Version != "1.0.0" {
		t.Fatalf("install result = %+v", result)
	}
	if result := installVersion("2.0.0"); result.Operation != "update" || result.Version != "2.0.0" || result.HistoryID == "" {
		t.Fatalf("update result = %+v", result)
	}
	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/probations?plugin_id=api_managed", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("probation status = %d: %s", rec.Code, rec.Body.String())
	}
	var probations []PluginPackageProbation
	decodePluginPackageAPIResponse(t, rec, &probations)
	if len(probations) != 1 || probations[0].Version != "2.0.0" || !probations[0].Pending || probations[0].PreviousHistoryID == "" {
		t.Fatalf("probations = %+v", probations)
	}

	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/history?plugin_id="+url.QueryEscape("api_managed"), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status = %d: %s", rec.Code, rec.Body.String())
	}
	var history []PluginPackageHistoryEntry
	decodePluginPackageAPIResponse(t, rec, &history)
	if len(history) != 1 || history[0].Version != "1.0.0" {
		t.Fatalf("history = %+v", history)
	}

	rollbackRequest := PluginPackageRollbackRequest{PluginID: "api_managed", HistoryID: history[0].ID}
	rec = performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/rollback", mustPluginPackageJSON(t, rollbackRequest))
	if rec.Code != http.StatusCreated {
		t.Fatalf("prepare rollback status = %d: %s", rec.Code, rec.Body.String())
	}
	var rollbackStage PluginPackageStage
	decodePluginPackageAPIResponse(t, rec, &rollbackStage)
	rec = performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/apply", mustPluginPackageJSON(t, PluginPackageApplyRequest{
		StageID: rollbackStage.ID, ApprovedPrivilegeDigest: rollbackStage.PrivilegeDigest,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply rollback status = %d: %s", rec.Code, rec.Body.String())
	}
	var rollbackResult PluginPackageOperationResult
	decodePluginPackageAPIResponse(t, rec, &rollbackResult)
	if rollbackResult.Operation != "rollback" || rollbackResult.Version != "1.0.0" {
		t.Fatalf("rollback result = %+v", rollbackResult)
	}

	rec = performPluginPackageAPIRequest(t, handler, http.MethodPost, "/api/plugin-packages/uninstall", mustPluginPackageJSON(t, PluginPackageUninstallRequest{PluginID: "api_managed", PurgeData: true}))
	if rec.Code != http.StatusOK {
		t.Fatalf("uninstall status = %d: %s", rec.Code, rec.Body.String())
	}
	var uninstallResult PluginPackageOperationResult
	decodePluginPackageAPIResponse(t, rec, &uninstallResult)
	if uninstallResult.Operation != "uninstall" {
		t.Fatalf("uninstall result = %+v", uninstallResult)
	}
	rec = performPluginPackageAPIRequest(t, handler, http.MethodGet, "/api/plugin-packages/probations?plugin_id=api_managed", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("probation after uninstall status = %d: %s", rec.Code, rec.Body.String())
	}
	probations = nil
	decodePluginPackageAPIResponse(t, rec, &probations)
	if len(probations) != 0 {
		t.Fatalf("probations after uninstall = %+v", probations)
	}

	rec = performPluginPackageAPIRequest(t, handler, http.MethodDelete, "/api/plugin-trust", mustPluginPackageJSON(t, map[string]string{"id": trustKey.ID}))
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE trust status = %d: %s", rec.Code, rec.Body.String())
	}
}

func performPluginPackageAPIRequest(t *testing.T, handler http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer package-token")
	req.Header.Set(pluginAdminTokenHeader, "test-plugin-admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func mustPluginPackageJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodePluginPackageAPIResponse(t *testing.T, rec *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(target); err != nil {
		t.Fatalf("decode API response: %v; body=%s", err, rec.Body.String())
	}
}
