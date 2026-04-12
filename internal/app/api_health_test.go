package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

func TestBuildAPIHandlerHealthz(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{}
	handler := buildAPIHandler(&Config{
		WebBind:  "127.0.0.1",
		WebPort:  8080,
		WebToken: "test-token",
	}, db, pm)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /healthz response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Fatalf("/healthz status = %q, want ok", resp["status"])
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("/healthz Cache-Control = %q, want no-store", got)
	}
}

func TestBuildAPIHandlerReadyzReflectsProcessManagerState(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{}
	handler := buildAPIHandler(&Config{
		WebBind:  "127.0.0.1",
		WebPort:  8080,
		WebToken: "test-token",
	}, db, pm)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz before ready status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var resp struct {
		Status string `json:"status"`
		Ready  bool   `json:"ready"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /readyz before ready response: %v", err)
	}
	if resp.Status != "starting" || resp.Ready {
		t.Fatalf("/readyz before ready = %+v, want status=starting ready=false", resp)
	}

	pm.setReady(true)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz after ready status = %d, want %d", rec.Code, http.StatusOK)
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /readyz after ready response: %v", err)
	}
	if resp.Status != "ready" || !resp.Ready {
		t.Fatalf("/readyz after ready = %+v, want status=ready ready=true", resp)
	}
}

func TestAPIListenAddrUsesNormalizedBind(t *testing.T) {
	addr := apiListenAddr(&Config{
		WebBind: " [::1] ",
		WebPort: 9090,
	})
	if addr != "[::1]:9090" {
		t.Fatalf("apiListenAddr() = %q, want [::1]:9090", addr)
	}
}

func TestBuildAPIHandlerCanDisableStaticWebUIOnly(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{}
	handler := buildAPIHandler(&Config{
		WebBind:             "127.0.0.1",
		WebPort:             8080,
		WebToken:            "test-token",
		WebUIEnabledSetting: boolPtr(false),
	}, db, pm)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET / with web_ui_enabled=false status = %d, want %d", rec.Code, http.StatusNotFound)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tags with web_ui_enabled=false status = %d, want %d", rec.Code, http.StatusOK)
	}

	var tags []string
	if err := json.NewDecoder(rec.Body).Decode(&tags); err != nil {
		t.Fatalf("decode /api/tags response: %v", err)
	}
	if len(tags) != 0 {
		t.Fatalf("/api/tags = %#v, want empty list", tags)
	}
}
