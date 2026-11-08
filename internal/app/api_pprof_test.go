package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofRequiresAuth(t *testing.T) {
	cfg := &Config{WebToken: "pprof-token"}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)

	for _, path := range []string{
		"/debug/pprof/",
		"/debug/pprof/goroutine?debug=1",
		"/debug/pprof/heap",
		"/debug/pprof/cmdline",
		"/debug/pprof/profile?seconds=1",
		"/debug/pprof/symbol",
		"/debug/pprof/trace?seconds=1",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated %s status = %d, want %d", path, rec.Code, http.StatusUnauthorized)
		}
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-token %s status = %d, want %d", path, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestPprofServesProfilesWithToken(t *testing.T) {
	cfg := &Config{WebToken: "pprof-token"}
	handler := buildAPIHandler(cfg, openTestDB(t), nil)

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+cfg.WebToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d: %s", path, rec.Code, rec.Body.String())
		}
		return rec
	}

	if body := get("/debug/pprof/").Body.String(); !strings.Contains(body, "goroutine") {
		t.Fatalf("pprof index does not list profiles: %s", body)
	}
	rec := get("/debug/pprof/goroutine?debug=1")
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Fatalf("goroutine profile content type = %q, want text/plain", got)
	}
	if !strings.Contains(rec.Body.String(), "TestPprofServesProfilesWithToken") {
		t.Fatalf("goroutine profile does not show this test's stack: %s", rec.Body.String())
	}
	if got := get("/debug/pprof/heap").Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("heap profile content type = %q, want application/octet-stream", got)
	}
}
