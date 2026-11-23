package app

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAPIBindExposesRemoteClients(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{name: "nil config", cfg: nil, want: false},
		{name: "default bind", cfg: &Config{}, want: false},
		{name: "ipv4 loopback", cfg: &Config{WebBind: "127.0.0.1"}, want: false},
		{name: "ipv4 loopback alias", cfg: &Config{WebBind: "127.0.0.2"}, want: false},
		{name: "ipv6 loopback", cfg: &Config{WebBind: "::1"}, want: false},
		{name: "localhost", cfg: &Config{WebBind: "localhost"}, want: false},
		{name: "localhost absolute", cfg: &Config{WebBind: "localhost."}, want: false},
		{name: "all ipv4", cfg: &Config{WebBind: "0.0.0.0"}, want: true},
		{name: "all ipv6", cfg: &Config{WebBind: "::"}, want: true},
		{name: "specific remote ip", cfg: &Config{WebBind: "192.0.2.10"}, want: true},
		{name: "hostname", cfg: &Config{WebBind: "example.com"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := apiBindExposesRemoteClients(tt.cfg); got != tt.want {
				t.Fatalf("apiBindExposesRemoteClients() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildAPIHandlerRateLimitsInvalidBearerTokens(t *testing.T) {
	handler := buildAPIHandler(&Config{WebToken: "correct-token"}, openTestDB(t), &ProcessManager{})
	for attempt := 0; attempt < apiAuthFailureLimit; attempt++ {
		req := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
		req.RemoteAddr = "192.0.2.10:12345"
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("invalid attempt %d status = %d, want %d", attempt+1, rec.Code, http.StatusUnauthorized)
		}
	}

	blocked := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	blocked.RemoteAddr = "192.0.2.10:54321"
	blocked.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, blocked)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited invalid token status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if rec.Header().Get("Retry-After") == "" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("rate-limit headers = Retry-After %q, Cache-Control %q", rec.Header().Get("Retry-After"), rec.Header().Get("Cache-Control"))
	}

	recovery := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	recovery.RemoteAddr = "192.0.2.10:12345"
	recovery.Header.Set("Authorization", "Bearer correct-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, recovery)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token recovery status = %d, want %d", rec.Code, http.StatusOK)
	}

	afterRecovery := httptest.NewRequest(http.MethodGet, "/api/tags", nil)
	afterRecovery.RemoteAddr = "192.0.2.10:12345"
	afterRecovery.Header.Set("Authorization", "Bearer wrong-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, afterRecovery)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token after recovery status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAPIAuthFailureLimiterExpiresAndBoundsState(t *testing.T) {
	now := time.Unix(1000, 0)
	limiter := newAPIAuthFailureLimiter()
	limiter.now = func() time.Time { return now }
	for attempt := 0; attempt < apiAuthFailureLimit; attempt++ {
		if allowed, _ := limiter.allowFailure("client"); !allowed {
			t.Fatalf("attempt %d was unexpectedly blocked", attempt+1)
		}
	}
	if allowed, _ := limiter.allowFailure("client"); allowed {
		t.Fatal("attempt after failure limit was allowed")
	}
	now = now.Add(apiAuthFailureWindow)
	if allowed, _ := limiter.allowFailure("client"); !allowed {
		t.Fatal("attempt after failure window was blocked")
	}

	// A full table stays bounded by making room instead of refusing: the
	// client whose window started first is forgotten.
	limiter = newAPIAuthFailureLimiter()
	limiter.now = func() time.Time { return now }
	for index := 0; index < apiAuthFailureMaxClients; index++ {
		client := "client-" + strconv.Itoa(index)
		if allowed, _ := limiter.allowFailure(client); !allowed {
			t.Fatalf("client %d was unexpectedly blocked", index)
		}
		now = now.Add(time.Millisecond)
	}
	if allowed, _ := limiter.allowFailure("overflow-client"); !allowed {
		t.Fatal("a full table refused a new client")
	}
	if len(limiter.entries) != apiAuthFailureMaxClients {
		t.Fatalf("table holds %d clients, want %d", len(limiter.entries), apiAuthFailureMaxClients)
	}
	if _, kept := limiter.entries["client-0"]; kept {
		t.Fatal("the oldest client was not the one evicted")
	}
	if _, kept := limiter.entries["client-1"]; !kept {
		t.Fatal("a newer client was evicted")
	}
	// A client over its own limit stays blocked while the table is full.
	for attempt := 1; attempt < apiAuthFailureLimit; attempt++ {
		limiter.allowFailure("overflow-client")
	}
	if allowed, _ := limiter.allowFailure("overflow-client"); allowed {
		t.Fatal("a client over its limit was allowed in a full table")
	}
}

func TestAPIAuthLimiterKeyGroupsIPv6Prefixes(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                 "192.0.2.7",
		"::ffff:192.0.2.7":          "192.0.2.7",
		"2001:db8:1:2:aaaa::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":           "2001:db8:1:3::/64",
		"::1":                       "::/64",
		"unknown":                   "unknown",
	} {
		if got := apiAuthLimiterKey(in); got != want {
			t.Errorf("apiAuthLimiterKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildAPIHandlerSetsBrowserSecurityHeaders(t *testing.T) {
	handler := buildAPIHandler(&Config{WebToken: "test-token"}, openTestDB(t), &ProcessManager{})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for name, want := range map[string]string{
		"X-Content-Type-Options":            "nosniff",
		"X-Frame-Options":                   "DENY",
		"X-Permitted-Cross-Domain-Policies": "none",
		"Referrer-Policy":                   "no-referrer",
		"Cross-Origin-Resource-Policy":      "same-origin",
		"Cross-Origin-Opener-Policy":        "same-origin",
	} {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if got := rec.Header().Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
		t.Errorf("Permissions-Policy = %q, want disabled browser capabilities", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, want frame-ancestors restriction", got)
	}
}
