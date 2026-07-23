package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Unicode01/veer/internal/store"
)

func TestPluginAuditPersistsRedactedOperationsAndAPI(t *testing.T) {
	db := openTestDB(t)
	recordPluginAudit(db, "audit_plugin", "package.install", "api", "success", map[string]any{
		"version": "1.0.0",
		"token":   "plain-token",
		"nested":  map[string]any{"password": "plain-password", "result": "ok"},
	})
	recordPluginAudit(db, "other_plugin", "plugin.state", "api", "success", map[string]any{"enabled": false})

	items, err := store.GetPluginAuditLogs(db, "audit_plugin", 10, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("GetPluginAuditLogs() = %+v, err=%v", items, err)
	}
	if strings.Contains(items[0].DetailsJSON, "plain-token") || strings.Contains(items[0].DetailsJSON, "plain-password") {
		t.Fatalf("audit details leaked sensitive data: %s", items[0].DetailsJSON)
	}
	for _, want := range []string{`"token":"__redacted__"`, `"password":"__redacted__"`, `"result":"ok"`} {
		if !strings.Contains(items[0].DetailsJSON, want) {
			t.Fatalf("audit details = %s, want %s", items[0].DetailsJSON, want)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/plugin-audit?plugin_id=audit_plugin&limit=1", nil)
	rec := httptest.NewRecorder()
	handlePluginAuditAPI(rec, req, db)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit API status = %d: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Logs []pluginAuditLogResponse `json:"logs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Logs) != 1 || response.Logs[0].PluginID != "audit_plugin" || response.Logs[0].Operation != "package.install" {
		t.Fatalf("audit API response = %+v", response)
	}
}

func TestPluginAuditAPIRejectsInvalidPagination(t *testing.T) {
	db := openTestDB(t)
	for _, target := range []string{
		"/api/plugin-audit?limit=0",
		"/api/plugin-audit?before_id=-1",
		"/api/plugin-audit?plugin_id=../escape",
	} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rec := httptest.NewRecorder()
		handlePluginAuditAPI(rec, req, db)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", target, rec.Code)
		}
	}
}
