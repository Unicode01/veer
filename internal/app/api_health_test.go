package app

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func TestBuildAPIHandlerReadyzRedactsReconcileErrors(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{
		ready:                    true,
		desiredGeneration:        2,
		appliedGeneration:        1,
		pluginReconcileLastError: "secret plugin path",
		ruleWorkers: map[int]*WorkerInfo{
			0: {errored: true, lastError: "secret dataplane path"},
		},
	}
	handler := buildAPIHandler(&Config{WebBind: "127.0.0.1", WebPort: 8080, WebToken: "test-token"}, db, pm)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("secret")) || bytes.Contains(rec.Body.Bytes(), []byte("last_error")) {
		t.Fatalf("/readyz leaked reconcile detail: %s", rec.Body.String())
	}
	var resp struct {
		Status    string `json:"status"`
		Dataplane struct {
			Status string `json:"status"`
		} `json:"dataplane"`
		Plugins struct {
			Status string `json:"status"`
		} `json:"plugins"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /readyz response: %v", err)
	}
	if resp.Status != "error" || resp.Dataplane.Status != "error" || resp.Plugins.Status != "error" {
		t.Fatalf("/readyz response = %+v", resp)
	}
}

func TestBuildAPIHandlerReadyzRejectsUnavailableEgressNAT(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{
		ready: true,
		egressNATPlans: map[int64]ruleDataplanePlan{
			7: {
				KernelEligible:  true,
				EffectiveEngine: ruleEngineUserspace,
				FallbackReason:  "tc map ABI mismatch",
			},
		},
		enabledEgressNATs:      map[int64]bool{7: true},
		kernelEgressNATs:       map[int64]bool{},
		kernelEgressNATEngines: map[int64]string{},
	}
	handler := buildAPIHandler(&Config{
		WebBind:  "127.0.0.1",
		WebPort:  8080,
		WebToken: "test-token",
	}, db, pm)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with unavailable egress NAT status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	pm.mu.Lock()
	pm.egressNATPlans[7] = ruleDataplanePlan{KernelEligible: true, EffectiveEngine: ruleEngineKernel}
	pm.kernelEgressNATs[7] = true
	pm.kernelEgressNATEngines[7] = kernelEngineTC
	pm.mu.Unlock()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz with running egress NAT status = %d, want %d", rec.Code, http.StatusOK)
	}

	pm.mu.Lock()
	delete(pm.enabledEgressNATs, 7)
	pm.egressNATPlans[7] = ruleDataplanePlan{EffectiveEngine: ruleEngineUserspace, FallbackReason: "disabled"}
	delete(pm.kernelEgressNATs, 7)
	delete(pm.kernelEgressNATEngines, 7)
	pm.mu.Unlock()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz with disabled egress NAT status = %d, want %d", rec.Code, http.StatusOK)
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

func TestStartAPIReportsBindFailure(t *testing.T) {
	db := openTestDB(t)
	pm := &ProcessManager{}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	server, err := startAPI(&Config{
		WebBind:  "127.0.0.1",
		WebPort:  port,
		WebToken: "test-token",
	}, db, pm)
	if err == nil {
		if server != nil {
			_ = server.Close()
		}
		t.Fatalf("startAPI() error = nil, want bind failure for port %s", strconv.Itoa(port))
	}
	if server != nil {
		t.Fatalf("startAPI() server = %#v, want nil on bind failure", server)
	}
}
