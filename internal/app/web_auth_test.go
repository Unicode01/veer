package app

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type webAuthFixture struct {
	t     *testing.T
	cfg   *Config
	db    *sql.DB
	key   []byte
	files systemAccountFiles
	now   time.Time

	mu   sync.Mutex
	logs []string

	auth    *webAuth
	handler http.Handler
}

func newWebAuthFixture(t *testing.T, configure func(cfg *Config)) *webAuthFixture {
	t.Helper()
	cfg := &Config{
		WebToken:             "fixture-web-token-0123456789",
		WebAuthRealmsSetting: []string{webAuthRealmSystem, webAuthRealmToken},
	}
	if configure != nil {
		configure(cfg)
	}
	f := &webAuthFixture{
		t:     t,
		cfg:   cfg,
		db:    openTestDB(t),
		key:   bytes.Repeat([]byte{7}, webSessionKeyBytes),
		files: standardTestAccounts(t, t.TempDir()),
		now:   testAccountsNow,
	}
	f.build()
	return f
}

// build makes a new handler from the same key and database, as a restart
// or hot restart of the daemon would.
func (f *webAuthFixture) build() {
	f.auth = newWebAuth(f.cfg, f.db, nil, webAuthOptions{
		key:      f.key,
		accounts: f.files,
		now:      func() time.Time { return f.now },
		logf: func(format string, args ...any) {
			f.mu.Lock()
			f.logs = append(f.logs, fmt.Sprintf(format, args...))
			f.mu.Unlock()
		},
	})
	f.handler = buildAPIHandlerWithAuth(f.cfg, f.db, &ProcessManager{}, f.auth)
}

func (f *webAuthFixture) logText() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

type webRequestOption func(r *http.Request)

func fromAddr(addr string) webRequestOption {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

func overTLS() webRequestOption {
	return func(r *http.Request) { r.TLS = &tls.ConnectionState{} }
}

func withHeader(name, value string) webRequestOption {
	return func(r *http.Request) { r.Header.Add(name, value) }
}

func withCookie(value string) webRequestOption {
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: webSessionCookieName, Value: value})
	}
}

func (f *webAuthFixture) do(method, path string, body any, opts ...webRequestOption) *httptest.ResponseRecorder {
	f.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "127.0.0.1:40000"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, opt := range opts {
		opt(req)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == webSessionCookieName {
			return cookie
		}
	}
	return nil
}

func decodeSessionView(t *testing.T, rec *httptest.ResponseRecorder) webSessionView {
	t.Helper()
	var view webSessionView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode session view %q: %v", rec.Body.String(), err)
	}
	return view
}

func decodeAuthError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var payload map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &payload)
	return payload["code"]
}

type webLogin struct {
	cookie string
	csrf   string
	view   webSessionView
}

func (f *webAuthFixture) login(t *testing.T, body webLoginRequest, opts ...webRequestOption) webLogin {
	t.Helper()
	rec := f.do(http.MethodPost, webAuthLoginPath, body, opts...)
	if rec.Code != http.StatusOK {
		t.Fatalf("login %+v: status %d %s", body, rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(t, rec)
	if cookie == nil {
		t.Fatal("login set no session cookie")
	}
	view := decodeSessionView(t, rec)
	return webLogin{cookie: cookie.Value, csrf: view.CSRFToken, view: view}
}

func rootLogin() webLoginRequest {
	return webLoginRequest{Realm: webAuthRealmSystem, Username: "root", Password: testPassword}
}

func TestWebLoginSystemAccountIssuesSession(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin())
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	cookie := sessionCookie(t, rec)
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("cookie = %+v, want HttpOnly SameSite=Strict Path=/", cookie)
	}
	if cookie.Secure {
		t.Fatal("cookie over loopback plain HTTP is Secure; the browser would not send it back")
	}
	if cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Fatalf("cookie persists (MaxAge %d, Expires %v), want a browser-session cookie", cookie.MaxAge, cookie.Expires)
	}
	view := decodeSessionView(t, rec)
	if !view.Authenticated || view.Identity == nil || view.Identity.Name != "root@system" || view.CSRFToken == "" {
		t.Fatalf("view = %+v", view)
	}
	if view.Session == nil || view.Session.IdleTimeoutSeconds != 1800 || !view.Session.ExpiresAt.Equal(testAccountsNow.Add(12*time.Hour)) {
		t.Fatalf("session = %+v", view.Session)
	}
	if strings.Contains(rec.Body.String(), testPassword) {
		t.Fatal("response echoes the password")
	}

	// The cookie authorizes API reads and the session endpoint shows who.
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie.Value)); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/tags with session: %d", rec.Code)
	}
	session := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, withCookie(cookie.Value)))
	if !session.Authenticated || session.Identity.Name != "root@system" || session.CSRFToken != view.CSRFToken {
		t.Fatalf("session view = %+v", session)
	}

	// Other administrators log in as themselves.
	alice := f.login(t, webLoginRequest{Realm: webAuthRealmSystem, Username: "alice", Password: testPassword})
	if alice.view.Identity.Name != "alice@system" {
		t.Fatalf("alice identity = %+v", alice.view.Identity)
	}
	logs := f.logText()
	if !strings.Contains(logs, "auth: login accepted client=127.0.0.1 realm=system user=root session=") {
		t.Fatalf("missing success log: %s", logs)
	}
	if strings.Contains(logs, testPassword) {
		t.Fatal("log contains the password")
	}
}

func TestWebLoginSystemAccountRefusalsLookAlike(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	for _, tc := range []struct {
		user, password, reason string
	}{
		{"root", "wrong", "bad_password"},
		{"carol", testPassword, "not_admin"},
		{"nobody", testPassword, "unknown_user"},
		{"locked", testPassword, "locked"},
		{"expired", testPassword, "account_expired"},
		{"root", "", "empty_password"},
	} {
		rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmSystem, Username: tc.user, Password: tc.password})
		if rec.Code != http.StatusUnauthorized || decodeAuthError(t, rec) != "invalid_credentials" || sessionCookie(t, rec) != nil {
			t.Errorf("%s/%s: status %d body %s", tc.user, tc.reason, rec.Code, rec.Body.String())
		}
		if !strings.Contains(f.logText(), "auth: login failed client=127.0.0.1 realm=system user="+tc.user+" reason="+tc.reason) {
			t.Errorf("missing failure log for %s: %s", tc.reason, f.logText())
		}
	}
}

func TestWebLoginRootSwitchAndAdminGroups(t *testing.T) {
	denyRoot := false
	f := newWebAuthFixture(t, func(cfg *Config) {
		cfg.WebRootLoginSetting = &denyRoot
		groups := []string{"admins"}
		cfg.WebAdminGroupsSetting = &groups
	})
	if rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin()); rec.Code != http.StatusUnauthorized {
		t.Fatalf("root with web_root_login=false: %d", rec.Code)
	}
	if !strings.Contains(f.logText(), "reason=root_disabled") {
		t.Fatalf("log: %s", f.logText())
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmSystem, Username: "alice", Password: testPassword}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("alice (sudo) with web_admin_groups=[admins]: %d", rec.Code)
	}
	f.login(t, webLoginRequest{Realm: webAuthRealmSystem, Username: "dave", Password: testPassword})
	view := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil))
	if view.Methods.System.DefaultUser != "" {
		t.Fatalf("default user with root login disabled = %q", view.Methods.System.DefaultUser)
	}
}

func TestWebLoginSystemAccountNeedsSecureTransport(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) {
		cfg.WebTrustedProxies = []string{"10.0.0.5", "fd00::/64"}
	})
	refused := []struct {
		name string
		opts []webRequestOption
	}{
		{"remote plain HTTP", []webRequestOption{fromAddr("198.51.100.7:5000")}},
		{"loopback relayed by an untrusted local proxy", []webRequestOption{withHeader("X-Forwarded-For", "198.51.100.7")}},
		{"loopback relayed with X-Real-IP", []webRequestOption{withHeader("X-Real-IP", "198.51.100.7")}},
		{"untrusted remote proxy claiming HTTPS", []webRequestOption{fromAddr("10.0.0.6:5000"), withHeader("X-Forwarded-Proto", "https")}},
		{"trusted proxy for a plain HTTP client", []webRequestOption{fromAddr("10.0.0.5:5000"), withHeader("X-Forwarded-For", "203.0.113.9"), withHeader("X-Forwarded-Proto", "http")}},
		{"trusted proxy without a protocol", []webRequestOption{fromAddr("10.0.0.5:5000"), withHeader("X-Forwarded-For", "203.0.113.9")}},
		{"same host address, not loopback", []webRequestOption{fromAddr("192.0.2.1:5000")}},
	}
	for _, tc := range refused {
		rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), tc.opts...)
		if rec.Code != http.StatusForbidden || decodeAuthError(t, rec) != webSystemRealmInsecure {
			t.Errorf("%s: status %d %s, want 403 insecure_channel", tc.name, rec.Code, rec.Body.String())
		}
		view := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, tc.opts...))
		if view.Methods.System.Available || view.Methods.System.Reason != webSystemRealmInsecure {
			t.Errorf("%s: methods = %+v", tc.name, view.Methods.System)
		}
	}
	accepted := []struct {
		name       string
		opts       []webRequestOption
		secure     bool
		wantClient string
	}{
		{"loopback plain HTTP", nil, false, "127.0.0.1"},
		{"IPv6 loopback", []webRequestOption{fromAddr("[::1]:5000")}, false, "::1"},
		{"remote TLS", []webRequestOption{fromAddr("198.51.100.7:5000"), overTLS()}, true, "198.51.100.7"},
		{"remote TLS ignores untrusted forwarding headers", []webRequestOption{fromAddr("198.51.100.8:5000"), overTLS(), withHeader("X-Forwarded-For", "1.2.3.4")}, true, "198.51.100.8"},
		{"trusted proxy for an HTTPS client", []webRequestOption{fromAddr("10.0.0.5:5000"), withHeader("X-Forwarded-For", "198.51.100.9, 10.0.0.5"), withHeader("X-Forwarded-Proto", "https")}, true, "198.51.100.9"},
		{"trusted IPv6 proxy", []webRequestOption{fromAddr("[fd00::2]:5000"), withHeader("X-Forwarded-For", "2001:db8::9"), withHeader("X-Forwarded-Proto", "https")}, true, "2001:db8::9"},
	}
	for _, tc := range accepted {
		rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), tc.opts...)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d %s", tc.name, rec.Code, rec.Body.String())
			continue
		}
		if cookie := sessionCookie(t, rec); cookie.Secure != tc.secure {
			t.Errorf("%s: cookie Secure = %v, want %v", tc.name, cookie.Secure, tc.secure)
		}
		if !strings.Contains(f.logText(), "login accepted client="+tc.wantClient+" ") {
			t.Errorf("%s: log does not name client %s: %s", tc.name, tc.wantClient, f.logText())
		}
	}
}

func TestWebLoginTokenRealm(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) { cfg.WebAuthRealmsSetting = nil })
	// A config without web_auth_realms keeps token login only, also over
	// plain HTTP from a remote client.
	view := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, fromAddr("198.51.100.7:5000")))
	if view.Methods.System.Enabled || view.Methods.System.Reason != webSystemRealmDisabled || !view.Methods.Token.Available {
		t.Fatalf("methods = %+v", view.Methods)
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin()); rec.Code != http.StatusForbidden || decodeAuthError(t, rec) != "realm_disabled" {
		t.Fatalf("system login without the realm: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: "wrong"}, fromAddr("198.51.100.7:5000")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	login := f.login(t, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, fromAddr("198.51.100.7:5000"))
	if login.view.Identity.Name != "token" || login.view.Identity.Via != "session" {
		t.Fatalf("identity = %+v", login.view.Identity)
	}
	if !strings.Contains(f.logText(), "token login over plain HTTP client=198.51.100.7") {
		t.Fatalf("missing plain HTTP warning: %s", f.logText())
	}
	if rec := f.do(http.MethodGet, "/api/tags", nil, fromAddr("198.51.100.7:5000"), withCookie(login.cookie)); rec.Code != http.StatusOK {
		t.Fatalf("token session: %d", rec.Code)
	}
	// Bearer requests are unchanged and report themselves as such.
	bearer := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, withHeader("Authorization", "Bearer "+f.cfg.WebToken)))
	if !bearer.Authenticated || bearer.Identity.Via != "bearer" || bearer.CSRFToken != "" {
		t.Fatalf("bearer view = %+v", bearer)
	}
	// Rotating web_token ends token sessions.
	f.cfg.WebToken = "rotated-web-token-0123456789"
	rec := f.do(http.MethodGet, "/api/tags", nil, fromAddr("198.51.100.7:5000"), withCookie(login.cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionCredentialsChanged {
		t.Fatalf("session after token rotation: %d reason %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
}

func TestWebSessionIdleAndAbsoluteExpiry(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	login := f.login(t, rootLogin())
	cookie := login.cookie

	// Activity slides the idle window; the refreshed cookie carries it.
	for i := 0; i < 3; i++ {
		f.now = f.now.Add(20 * time.Minute)
		rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie))
		if rec.Code != http.StatusOK {
			t.Fatalf("step %d: %d", i, rec.Code)
		}
		refreshed := sessionCookie(t, rec)
		if refreshed == nil {
			t.Fatalf("step %d: no refreshed cookie", i)
		}
		cookie = refreshed.Value
	}

	// Background polling does not count as activity.
	for i := 0; i < 2; i++ {
		f.now = f.now.Add(14 * time.Minute)
		rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie), withHeader(webBackgroundHeader, "1"))
		if rec.Code != http.StatusOK || sessionCookie(t, rec) != nil {
			t.Fatalf("background poll %d: %d, cookie %v", i, rec.Code, sessionCookie(t, rec))
		}
	}
	f.now = f.now.Add(2 * time.Minute)
	rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionIdle {
		t.Fatalf("after 30 idle minutes: %d reason %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
	if cleared := sessionCookie(t, rec); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("refused cookie not cleared: %+v", cleared)
	}
	view := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, withCookie(cookie)))
	if view.Authenticated || view.Refused != webSessionIdle {
		t.Fatalf("session view after idle = %+v", view)
	}

	// However active, a session ends 12 hours after login.
	login = f.login(t, rootLogin())
	cookie = login.cookie
	start := f.now
	for f.now.Sub(start) < 12*time.Hour-25*time.Minute {
		f.now = f.now.Add(25 * time.Minute)
		rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie))
		if rec.Code != http.StatusOK {
			t.Fatalf("active session refused after %s: %d %q", f.now.Sub(start), rec.Code, rec.Header().Get(webAuthReasonHeader))
		}
		if refreshed := sessionCookie(t, rec); refreshed != nil {
			cookie = refreshed.Value
		}
	}
	f.now = start.Add(12 * time.Hour)
	rec = f.do(http.MethodGet, "/api/tags", nil, withCookie(cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionExpired {
		t.Fatalf("after 12 hours: %d reason %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
}

func TestWebSessionTimeoutsFollowConfig(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) {
		cfg.WebSessionIdleMinutes = 5
		cfg.WebSessionMaxHours = 1
	})
	login := f.login(t, rootLogin())
	if login.view.Session.IdleTimeoutSeconds != 300 || !login.view.Session.ExpiresAt.Equal(f.now.Add(time.Hour)) {
		t.Fatalf("session = %+v", login.view.Session)
	}
	f.now = f.now.Add(5 * time.Minute)
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login.cookie)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after 5 idle minutes: %d", rec.Code)
	}
}

func TestWebSessionLogoutRevokesAcrossRestarts(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	kept := f.login(t, rootLogin())
	ended := f.login(t, webLoginRequest{Realm: webAuthRealmSystem, Username: "alice", Password: testPassword})

	// Logging out needs the CSRF token like any other change.
	if rec := f.do(http.MethodPost, webAuthLogoutPath, nil, withCookie(ended.cookie)); rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", rec.Code)
	}
	rec := f.do(http.MethodPost, webAuthLogoutPath, nil, withCookie(ended.cookie), withHeader(webCSRFHeader, ended.csrf))
	if rec.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	if cleared := sessionCookie(t, rec); cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("logout did not clear the cookie: %+v", cleared)
	}
	if !strings.Contains(f.logText(), "auth: logout client=127.0.0.1 realm=system user=alice session=") {
		t.Fatalf("missing logout log: %s", f.logText())
	}
	rec = f.do(http.MethodGet, "/api/tags", nil, withCookie(ended.cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionRevoked {
		t.Fatalf("logged-out cookie: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}

	// A hot restart: a new process with the same key file and database.
	f.build()
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(kept.cookie)); rec.Code != http.StatusOK {
		t.Fatalf("session after restart: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(ended.cookie)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session after restart: %d", rec.Code)
	}
	// The CSRF token stays the same too, so an open panel keeps working.
	view := decodeSessionView(t, f.do(http.MethodGet, webAuthSessionPath, nil, withCookie(kept.cookie)))
	if view.CSRFToken != kept.csrf {
		t.Fatal("CSRF token changed across restart")
	}

	// A new key (auth/session.key deleted) ends every session.
	f.key = bytes.Repeat([]byte{8}, webSessionKeyBytes)
	f.build()
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(kept.cookie)); rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionInvalid {
		t.Fatalf("session under another key: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
}

func TestWebSessionEndsWhenTheAccountChanges(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	login := f.login(t, rootLogin())
	alice := f.login(t, webLoginRequest{Realm: webAuthRealmSystem, Username: "alice", Password: testPassword})

	shadow, err := os.ReadFile(f.files.shadow)
	if err != nil {
		t.Fatal(err)
	}
	// passwd root: the same password again gets a new hash.
	updated := strings.Replace(string(shadow), "root:"+testHashSHA512, "root:"+testHashMD5, 1)
	// usermod -L alice
	updated = strings.Replace(updated, "alice:"+testHashYes, "alice:!"+testHashYes, 1)
	if err := os.WriteFile(f.files.shadow, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(systemAccountFileReloadGap)
	rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login.cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionCredentialsChanged {
		t.Fatalf("root after a password change: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
	rec = f.do(http.MethodGet, "/api/tags", nil, withCookie(alice.cookie))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionAccountRefused {
		t.Fatalf("alice after locking: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
	// The same password logs in again with the new hash.
	f.login(t, rootLogin())
}

func TestWebSessionSystemRealmStaysOnSecureTransport(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	login := f.login(t, rootLogin())
	rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login.cookie), fromAddr("198.51.100.7:5000"))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionInsecure {
		t.Fatalf("system session over remote plain HTTP: %d %q", rec.Code, rec.Header().Get(webAuthReasonHeader))
	}
	f.cfg.WebAuthRealmsSetting = []string{webAuthRealmToken}
	login2 := f.login(t, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken})
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login.cookie)); rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionRealmDisabled {
		t.Fatalf("system session after the realm was removed: %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login2.cookie)); rec.Code != http.StatusOK {
		t.Fatalf("token session: %d", rec.Code)
	}
}

func TestWebSessionRejectsForgedCookies(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	login := f.login(t, rootLogin())
	body, sig, _ := strings.Cut(login.cookie, ".")
	ticket, _ := f.auth.decodeTicket(login.cookie)
	forged := *ticket
	forged.User = "alice"
	other := newWebAuth(f.cfg, nil, nil, webAuthOptions{key: bytes.Repeat([]byte{9}, webSessionKeyBytes)})
	for name, value := range map[string]string{
		"garbage":           "not-a-ticket",
		"swapped signature": body + "." + strings.Repeat("A", len(sig)),
		"edited payload":    f.auth.encodeTicket(&forged)[:strings.Index(f.auth.encodeTicket(&forged), ".")] + "." + sig,
		"other key":         other.encodeTicket(ticket),
		"oversized":         strings.Repeat("a", webSessionCookieMaxBytes+1),
	} {
		rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(value))
		if rec.Code != http.StatusUnauthorized || rec.Header().Get(webAuthReasonHeader) != webSessionInvalid {
			t.Errorf("%s: %d %q", name, rec.Code, rec.Header().Get(webAuthReasonHeader))
		}
	}
}

func TestWebSessionCSRFProtection(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	login := f.login(t, rootLogin(), withHeader("Origin", "http://127.0.0.1:8889"), func(r *http.Request) { r.Host = "127.0.0.1:8889" })
	post := func(opts ...webRequestOption) *httptest.ResponseRecorder {
		base := []webRequestOption{withCookie(login.cookie), func(r *http.Request) { r.Host = "panel.example:8889" }}
		return f.do(http.MethodPost, "/api/rules/validate", map[string]any{}, append(base, opts...)...)
	}
	for name, tc := range map[string]struct {
		opts []webRequestOption
		code string
	}{
		"no token":            {nil, "csrf"},
		"wrong token":         {[]webRequestOption{withHeader(webCSRFHeader, "AAAA")}, "csrf"},
		"other origin":        {[]webRequestOption{withHeader(webCSRFHeader, login.csrf), withHeader("Origin", "https://evil.example")}, "cross_origin"},
		"other port":          {[]webRequestOption{withHeader(webCSRFHeader, login.csrf), withHeader("Origin", "https://panel.example:8890")}, "cross_origin"},
		"cross-site fetch":    {[]webRequestOption{withHeader(webCSRFHeader, login.csrf), withHeader("Sec-Fetch-Site", "cross-site")}, "cross_origin"},
		"same-site subdomain": {[]webRequestOption{withHeader(webCSRFHeader, login.csrf), withHeader("Sec-Fetch-Site", "same-site")}, "cross_origin"},
	} {
		rec := post(tc.opts...)
		if rec.Code != http.StatusForbidden || decodeAuthError(t, rec) != tc.code {
			t.Errorf("%s: %d %s, want 403 %s", name, rec.Code, rec.Body.String(), tc.code)
		}
	}
	for name, opts := range map[string][]webRequestOption{
		"token":              {withHeader(webCSRFHeader, login.csrf)},
		"token and origin":   {withHeader(webCSRFHeader, login.csrf), withHeader("Origin", "http://panel.example:8889"), withHeader("Sec-Fetch-Site", "same-origin")},
		"default https port": {withHeader(webCSRFHeader, login.csrf), withHeader("Origin", "https://panel.example:8889")},
	} {
		if rec := post(opts...); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Reads need no token.
	if rec := f.do(http.MethodGet, "/api/tags", nil, withCookie(login.cookie)); rec.Code != http.StatusOK {
		t.Fatalf("GET with session: %d", rec.Code)
	}
	// Bearer requests need neither token nor origin.
	rec := f.do(http.MethodPost, "/api/rules/validate", map[string]any{}, withHeader("Authorization", "Bearer "+f.cfg.WebToken), withHeader("Origin", "https://evil.example"))
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("bearer POST: %d %s", rec.Code, rec.Body.String())
	}
	// A trusted proxy's X-Forwarded-Host is the host the browser used.
	f.cfg.WebTrustedProxies = []string{"127.0.0.1"}
	f.build()
	rec = f.do(http.MethodPost, "/api/rules/validate", map[string]any{}, withCookie(login.cookie), withHeader(webCSRFHeader, login.csrf),
		withHeader("Origin", "https://router.example"), withHeader("X-Forwarded-Host", "router.example"), withHeader("X-Forwarded-Proto", "https"))
	if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("proxied POST: %d %s", rec.Code, rec.Body.String())
	}
	// Login itself rejects foreign origins and non-JSON bodies.
	if rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), withHeader("Origin", "https://evil.example")); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, webAuthLoginPath, strings.NewReader(`{"realm":"system","username":"root","password":"Hello world!"}`))
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Content-Type", "text/plain")
	plain := httptest.NewRecorder()
	f.handler.ServeHTTP(plain, req)
	if plain.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain login: %d", plain.Code)
	}
}

func TestWebLoginRateLimit(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) { cfg.WebTrustedProxies = []string{"10.0.0.5"} })
	viaProxy := func(client string) []webRequestOption {
		return []webRequestOption{fromAddr("10.0.0.5:5000"), withHeader("X-Forwarded-For", client), withHeader("X-Forwarded-Proto", "https")}
	}
	wrong := webLoginRequest{Realm: webAuthRealmSystem, Username: "root", Password: "guess"}
	for i := 0; i < apiAuthFailureLimit; i++ {
		if rec := f.do(http.MethodPost, webAuthLoginPath, wrong, viaProxy("203.0.113.1")...); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, rec.Code)
		}
	}
	rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), viaProxy("203.0.113.1")...)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("correct password after the limit: %d", rec.Code)
	}
	// Token guesses share the budget.
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, viaProxy("203.0.113.1")...); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("token login after the limit: %d", rec.Code)
	}
	// Another client behind the same proxy is not affected.
	f.login(t, rootLogin(), viaProxy("203.0.113.2")...)
	// The limit lifts after the window.
	f.now = f.now.Add(apiAuthFailureWindow)
	f.login(t, rootLogin(), viaProxy("203.0.113.1")...)

	// Wrong Bearer tokens count; stale cookies and missing credentials do
	// not, so an expired panel cannot lock its own address out.
	for i := 0; i < 3*apiAuthFailureLimit; i++ {
		f.do(http.MethodGet, "/api/tags", nil, fromAddr("192.0.2.50:1"), withCookie("stale"))
		f.do(http.MethodGet, "/api/tags", nil, fromAddr("192.0.2.50:1"))
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, fromAddr("192.0.2.50:1")); rec.Code != http.StatusOK {
		t.Fatalf("login after stale-cookie polling: %d", rec.Code)
	}
	for i := 0; i < apiAuthFailureLimit; i++ {
		f.do(http.MethodGet, "/api/tags", nil, fromAddr("192.0.2.51:1"), withHeader("Authorization", "Bearer wrong"))
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, fromAddr("192.0.2.51:1")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("login after wrong bearer tokens: %d", rec.Code)
	}
	if !strings.Contains(f.logText(), "auth: bearer token rejected client=192.0.2.51") {
		t.Fatal("wrong bearer tokens are not logged")
	}
}

// A burst of concurrent guesses from one client must not get more password
// checks than the limit allows: each attempt is counted before it is
// checked, not after.
func TestWebLoginRateLimitHoldsUnderConcurrency(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	const burst = 4 * apiAuthFailureLimit
	for _, realm := range []string{webAuthRealmSystem, webAuthRealmToken} {
		guess := webLoginRequest{Realm: realm, Username: "root", Password: "guess"}
		if realm == webAuthRealmToken {
			guess = webLoginRequest{Realm: realm, Token: "guess"}
		}
		client := fromAddr("127.0.0.1:1")
		if realm == webAuthRealmToken {
			client = fromAddr("198.51.100.30:1")
		}
		codes := make(chan int, burst)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				codes <- f.do(http.MethodPost, webAuthLoginPath, guess, client).Code
			}()
		}
		close(start)
		wg.Wait()
		close(codes)
		counts := map[int]int{}
		for code := range codes {
			counts[code]++
		}
		if counts[http.StatusUnauthorized] != apiAuthFailureLimit || counts[http.StatusTooManyRequests] != burst-apiAuthFailureLimit {
			t.Fatalf("%s burst answers = %v, want %d × 401 and %d × 429", realm, counts, apiAuthFailureLimit, burst-apiAuthFailureLimit)
		}
		reason := "reason=bad_password"
		if realm == webAuthRealmToken {
			reason = "reason=bad_token"
		}
		if checked := strings.Count(f.logText(), reason); checked != apiAuthFailureLimit {
			t.Fatalf("%s burst checked %d credentials, want %d", realm, checked, apiAuthFailureLimit)
		}
		// The right credentials inside the same window are refused too.
		right := rootLogin()
		if realm == webAuthRealmToken {
			right = webLoginRequest{Realm: realm, Token: f.cfg.WebToken}
		}
		if rec := f.do(http.MethodPost, webAuthLoginPath, right, client); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("%s correct credentials after the burst: %d", realm, rec.Code)
		}
	}
	f.now = f.now.Add(apiAuthFailureWindow)
	f.login(t, rootLogin())
}

// Filling the failure table from thousands of addresses must not lock other
// clients out of signing in.
func TestWebLoginWorksWhenTheFailureTableIsFull(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	for i := 0; i < apiAuthFailureMaxClients; i++ {
		// One wrong Bearer token from each of 4096 different /64s.
		f.do(http.MethodGet, "/api/tags", nil, fromAddr(fmt.Sprintf("[2001:db8:%x:%x::1]:1", i>>8, i&0xff)), withHeader("Authorization", "Bearer wrong"))
	}
	if n := len(f.auth.limiter.entries); n != apiAuthFailureMaxClients {
		t.Fatalf("failure table holds %d clients, want it full (%d)", n, apiAuthFailureMaxClients)
	}
	f.login(t, rootLogin())
	f.login(t, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, fromAddr("198.51.100.50:1"))
	if rec := f.do(http.MethodGet, "/api/tags", nil, fromAddr("198.51.100.51:1"), withHeader("Authorization", "Bearer "+f.cfg.WebToken)); rec.Code != http.StatusOK {
		t.Fatalf("bearer request with a full table: %d", rec.Code)
	}
	// A client over its own limit is still refused.
	guesser := fromAddr("198.51.100.52:1")
	for i := 0; i < apiAuthFailureLimit; i++ {
		if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: "guess"}, guesser); rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i+1, rec.Code)
		}
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}, guesser); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("correct token after the client's own limit: %d", rec.Code)
	}
}

// One host usually holds a whole IPv6 /64, so the addresses of a /64 share
// one failure budget, directly and behind a trusted proxy. The log still
// names the exact address.
func TestWebLoginRateLimitCountsAnIPv6PrefixAsOneClient(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) { cfg.WebTrustedProxies = []string{"10.0.0.5"} })
	refused := 0
	for i := 0; i < apiAuthFailureMaxClients; i++ {
		addr := fmt.Sprintf("[2001:db8:1:2:%x:%x::1]:1", i>>8, i&0xff)
		switch rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: "guess"}, fromAddr(addr)); rec.Code {
		case http.StatusUnauthorized:
			if i >= apiAuthFailureLimit {
				t.Fatalf("attempt %d from the same /64 was checked", i+1)
			}
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("attempt %d: %d", i+1, rec.Code)
		}
	}
	if refused != apiAuthFailureMaxClients-apiAuthFailureLimit {
		t.Fatalf("%d attempts refused, want %d", refused, apiAuthFailureMaxClients-apiAuthFailureLimit)
	}
	if !strings.Contains(f.logText(), "login failed client=2001:db8:1:2:0:1:0:1 ") {
		t.Fatalf("log does not name the exact address: %s", f.logText()[:200])
	}
	right := webLoginRequest{Realm: webAuthRealmToken, Token: f.cfg.WebToken}
	if rec := f.do(http.MethodPost, webAuthLoginPath, right, fromAddr("[2001:db8:1:2:ffff::9]:1")); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("another address of the blocked /64: %d", rec.Code)
	}
	f.login(t, right, fromAddr("[2001:db8:1:3::9]:1"))

	viaProxy := func(client string) []webRequestOption {
		return []webRequestOption{fromAddr("10.0.0.5:5000"), withHeader("X-Forwarded-For", client), withHeader("X-Forwarded-Proto", "https")}
	}
	for i := 0; i < apiAuthFailureLimit; i++ {
		f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: "guess"}, viaProxy(fmt.Sprintf("2001:db8:9:9::%x", i+1))...)
	}
	if rec := f.do(http.MethodPost, webAuthLoginPath, right, viaProxy("2001:db8:9:9::ff")...); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("proxied client in a blocked /64: %d", rec.Code)
	}
	f.login(t, right, viaProxy("2001:db8:9:a::1")...)
}

// Requests turned away before any credential is checked do not use up the
// client's attempts.
func TestWebLoginRefusalsBeforeCheckingKeepAttempts(t *testing.T) {
	f := newWebAuthFixture(t, func(cfg *Config) { cfg.WebAuthRealmsSetting = []string{webAuthRealmSystem} })
	remote := fromAddr("198.51.100.40:1")
	for i := 0; i < 2*apiAuthFailureLimit; i++ {
		if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmToken, Token: "x"}, remote); rec.Code != http.StatusForbidden {
			t.Fatalf("disabled realm: %d", rec.Code)
		}
		if rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), remote); rec.Code != http.StatusForbidden {
			t.Fatalf("insecure channel: %d", rec.Code)
		}
		if rec := f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: "pam"}, remote); rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown realm: %d", rec.Code)
		}
		if rec := f.do(http.MethodPost, webAuthLoginPath, map[string]any{"realm": "system", "extra": 1}, remote); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad body: %d", rec.Code)
		}
	}
	// Unreadable account files: the attempt is counted, then given back.
	moved := f.files.shadow + ".moved"
	if err := os.Rename(f.files.shadow, moved); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2*apiAuthFailureLimit; i++ {
		if rec := f.do(http.MethodPost, webAuthLoginPath, rootLogin(), remote, overTLS()); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("unreadable accounts: %d", rec.Code)
		}
	}
	if err := os.Rename(moved, f.files.shadow); err != nil {
		t.Fatal(err)
	}
	f.login(t, rootLogin(), remote, overTLS())
	if strings.Contains(f.logText(), "reason=bad_password") {
		t.Fatalf("a refused request checked a password: %s", f.logText())
	}
}

func TestWebAuthLogLinesResistInjection(t *testing.T) {
	f := newWebAuthFixture(t, nil)
	f.do(http.MethodPost, webAuthLoginPath, webLoginRequest{Realm: webAuthRealmSystem, Username: "x client=1.2.3.4 \"\n", Password: "p"}, fromAddr("198.51.100.20:1"), overTLS())
	logs := f.logText()
	if strings.Contains(logs, "client=1.2.3.4") || strings.Contains(logs, "\n\"") {
		t.Fatalf("user name leaked into the log line: %q", logs)
	}
	if !strings.Contains(logs, "auth: login failed client=198.51.100.20 realm=system user=x?client?1.2.3.4??? reason=invalid_user") {
		t.Fatalf("log = %q", logs)
	}
	if got := sanitizeLogUser(strings.Repeat("a", 100)); len(got) != webLogUserMaxRunes+3 {
		t.Fatalf("long user = %q", got)
	}
}

func TestWebSessionKeyFilePersists(t *testing.T) {
	dir := t.TempDir()
	first, err := loadOrCreateWebSessionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateWebSessionKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(first) != webSessionKeyBytes {
		t.Fatal("session key changed between loads")
	}
	path := filepath.Join(dir, webSessionKeyDir, webSessionKeyFile)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode = %v, %v", info.Mode(), err)
		}
		dirInfo, _ := os.Stat(filepath.Dir(path))
		if dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("key dir mode = %v", dirInfo.Mode())
		}
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateWebSessionKey(dir); err == nil {
		t.Fatal("a damaged key was accepted")
	}
}

func TestWebAuthConfigValidation(t *testing.T) {
	load := func(extra string) (*Config, error) {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(`{"web_token":"test-token"`+extra+`}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadConfig(path)
	}
	cfg, err := load("")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.WebAuthRealms(); len(got) != 1 || got[0] != webAuthRealmToken {
		t.Fatalf("default realms = %v", got)
	}
	if cfg.WebSessionIdleTimeout() != 30*time.Minute || cfg.WebSessionLifetime() != 12*time.Hour || !cfg.WebRootLoginAllowed() {
		t.Fatalf("defaults: idle %s, lifetime %s, root %v", cfg.WebSessionIdleTimeout(), cfg.WebSessionLifetime(), cfg.WebRootLoginAllowed())
	}
	if got := cfg.WebAdminGroups(); strings.Join(got, ",") != "sudo,wheel" {
		t.Fatalf("default admin groups = %v", got)
	}
	cfg, err = load(`,"web_auth_realms":[" System ","token","system"],"web_session_idle_minutes":99999,"web_session_max_hours":2,"web_admin_groups":[],"web_root_login":false,"web_trusted_proxies":["127.0.0.1"," 10.0.0.0/8 ","::1"]`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.WebAuthRealms(), ",") != "system,token" || cfg.WebSessionIdleTimeout() != 24*time.Hour || cfg.WebSessionLifetime() != 2*time.Hour {
		t.Fatalf("realms %v idle %s lifetime %s", cfg.WebAuthRealms(), cfg.WebSessionIdleTimeout(), cfg.WebSessionLifetime())
	}
	if len(cfg.WebAdminGroups()) != 0 || cfg.WebRootLoginAllowed() || strings.Join(cfg.WebTrustedProxies, ",") != "127.0.0.1,10.0.0.0/8,::1" {
		t.Fatalf("groups %v root %v proxies %v", cfg.WebAdminGroups(), cfg.WebRootLoginAllowed(), cfg.WebTrustedProxies)
	}
	for _, bad := range []string{
		`,"web_auth_realms":[]`,
		`,"web_auth_realms":["pam"]`,
		`,"web_session_idle_minutes":-1`,
		`,"web_admin_groups":["bad:group"]`,
		`,"web_trusted_proxies":["not-an-ip"]`,
		`,"web_trusted_proxies":["10.0.0.0/33"]`,
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("config %s was accepted", bad)
		}
	}
}
