package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Panel sessions.
//
// A login (with a system account or web_token) yields a cookie that holds a
// signed ticket: session id, realm, user, issue time, last activity and a
// fingerprint of the credential it was issued for. The signing key lives in
// auth/session.key under the install directory, so sessions survive restarts
// and hot restarts the way PVE tickets survive with its authkey. The server
// still checks every request: a logout revokes the session id (kept in the
// database until the session would have expired), a changed password or
// web_token changes the fingerprint, and a system account that is locked,
// expired or no longer an administrator stops working at once.
//
// Requests that change something with a session cookie must carry the
// session's CSRF token in X-Veer-CSRF (handed out at login, like PVE's
// CSRFPreventionToken) and, when the browser sends one, an Origin naming
// this host. Bearer requests are unchanged and need neither.
const (
	webSessionCookieName      = "veer_session"
	webCSRFHeader             = "X-Veer-CSRF"
	webBackgroundHeader       = "X-Veer-Background"
	webAuthReasonHeader       = "X-Veer-Auth-Reason"
	webSessionKeyDir          = "auth"
	webSessionKeyFile         = "session.key"
	webSessionKeyBytes        = 32
	webSessionRefreshInterval = time.Minute
	webSessionClockSkew       = 5 * time.Minute
	webSessionCookieMaxBytes  = 4096
	webSessionRevocationsTTL  = 15 * time.Second
	webSystemLoginSlots       = 2
	webSystemLoginSlotWait    = 10 * time.Second
	webLogUserMaxRunes        = 64
)

// Reasons a session cookie is refused, sent in X-Veer-Auth-Reason so the
// panel can say why it shows the login page again.
const (
	webSessionInvalid            = "session_invalid"
	webSessionExpired            = "session_expired"
	webSessionIdle               = "session_idle"
	webSessionRevoked            = "session_revoked"
	webSessionCredentialsChanged = "session_credentials_changed"
	webSessionRealmDisabled      = "session_realm_disabled"
	webSessionAccountRefused     = "session_account_refused"
	webSessionInsecure           = "session_insecure_channel"
)

type webSessionTicket struct {
	Version     int    `json:"v"`
	ID          string `json:"sid"`
	Realm       string `json:"realm"`
	User        string `json:"user,omitempty"`
	IssuedAt    int64  `json:"iat"`
	SeenAt      int64  `json:"seen"`
	Fingerprint string `json:"fp"`
}

// webIdentity is who a request acts as.
type webIdentity struct {
	Realm  string
	User   string
	Via    string // "session" or "bearer"
	ticket *webSessionTicket
}

// Name is the identity as the panel shows it: root@system, alice@system,
// token.
func (id *webIdentity) Name() string {
	if id == nil {
		return ""
	}
	if id.Realm == webAuthRealmSystem {
		return id.User + "@system"
	}
	return webAuthRealmToken
}

type webAuthOptions struct {
	key      []byte
	accounts systemAccountFiles
	now      func() time.Time
	logf     func(format string, args ...any)
}

type webAuth struct {
	cfg        *Config
	key        []byte
	accounts   *systemAccountStore
	revoked    *webSessionRevocations
	limiter    *apiAuthFailureLimiter
	proxies    []*net.IPNet
	panelRelay func() string
	now        func() time.Time
	logf       func(format string, args ...any)
	hashSlots  chan struct{}
}

func newWebAuth(cfg *Config, db *sql.DB, pm *ProcessManager, opts webAuthOptions) *webAuth {
	key := opts.key
	if len(key) == 0 {
		key = make([]byte, webSessionKeyBytes)
		if _, err := rand.Read(key); err != nil {
			panic(fmt.Sprintf("web auth: random key: %v", err))
		}
	}
	files := opts.accounts
	if files == (systemAccountFiles{}) {
		files = defaultSystemAccountFiles
	}
	now := opts.now
	if now == nil {
		now = time.Now
	}
	logf := opts.logf
	if logf == nil {
		logf = log.Printf
	}
	a := &webAuth{
		cfg:       cfg,
		key:       key,
		accounts:  newSystemAccountStore(files),
		limiter:   newAPIAuthFailureLimiter(),
		now:       now,
		logf:      logf,
		hashSlots: make(chan struct{}, webSystemLoginSlots),
	}
	a.accounts.now = now
	a.limiter.now = now
	a.revoked = newWebSessionRevocations(db, now)
	if cfg != nil {
		for _, value := range cfg.WebTrustedProxies {
			if network, err := parseTrustedProxy(strings.TrimSpace(value)); err == nil {
				a.proxies = append(a.proxies, network)
			}
		}
	}
	if pm != nil {
		a.panelRelay = pm.panelRelayForward
	}
	return a
}

// loadOrCreateWebSessionKey returns the session signing key kept under
// baseDir, creating it (0600, in a 0700 directory) on first use.
func loadOrCreateWebSessionKey(baseDir string) ([]byte, error) {
	dir := filepath.Join(baseDir, webSessionKeyDir)
	path := filepath.Join(dir, webSessionKeyFile)
	if key, err := readWebSessionKey(path); err == nil {
		return key, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err != nil {
		return nil, err
	} else if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	_ = os.Chmod(dir, 0o700)
	key := make([]byte, webSessionKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp(dir, ".session.key-*")
	if err != nil {
		return nil, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return nil, err
	}
	if _, err := temp.Write(key); err != nil {
		temp.Close()
		return nil, err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	// Link instead of rename: a process that created the key first wins,
	// and everyone then uses its key.
	if err := os.Link(tempPath, path); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return readWebSessionKey(path)
}

func readWebSessionKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("session key %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("secure session key permissions: %w", err)
		}
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != webSessionKeyBytes {
		return nil, fmt.Errorf("session key %s has %d bytes, want %d; delete it to create a new one (this ends every panel session)", path, len(key), webSessionKeyBytes)
	}
	return key, nil
}

func (a *webAuth) mac(parts ...string) []byte {
	mac := hmac.New(sha256.New, a.key)
	for _, part := range parts {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}

func (a *webAuth) encodeTicket(ticket *webSessionTicket) string {
	payload, _ := json.Marshal(ticket)
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + base64.RawURLEncoding.EncodeToString(a.mac("veer-session", body))
}

func (a *webAuth) decodeTicket(value string) (*webSessionTicket, bool) {
	if value == "" || len(value) > webSessionCookieMaxBytes {
		return nil, false
	}
	body, sig, ok := strings.Cut(value, ".")
	if !ok {
		return nil, false
	}
	want := a.mac("veer-session", body)
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, want) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, false
	}
	var ticket webSessionTicket
	if err := json.Unmarshal(payload, &ticket); err != nil || ticket.Version != 1 || ticket.ID == "" {
		return nil, false
	}
	return &ticket, true
}

func (a *webAuth) csrfToken(ticket *webSessionTicket) string {
	return base64.RawURLEncoding.EncodeToString(a.mac("csrf", ticket.ID)[:18])
}

func (a *webAuth) tokenFingerprint() string {
	token := ""
	if a.cfg != nil {
		token = strings.TrimSpace(a.cfg.WebToken)
	}
	return base64.RawURLEncoding.EncodeToString(a.mac("token", token)[:16])
}

func (a *webAuth) systemFingerprint(user, hash string) string {
	return base64.RawURLEncoding.EncodeToString(a.mac("system", user, hash)[:16])
}

func (a *webAuth) loginPolicy() systemLoginPolicy {
	return systemLoginPolicy{adminGroups: a.cfg.WebAdminGroups(), rootLogin: a.cfg.WebRootLoginAllowed()}
}

func (a *webAuth) bearerMatches(token string) bool {
	if a.cfg == nil {
		return false
	}
	expected := strings.TrimSpace(a.cfg.WebToken)
	return expected != "" && token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// newSession issues a session for realm and user and sets its cookie.
func (a *webAuth) newSession(w http.ResponseWriter, r *http.Request, realm, user, fingerprint string) *webSessionTicket {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		panic(fmt.Sprintf("web auth: random session id: %v", err))
	}
	now := a.now().Unix()
	ticket := &webSessionTicket{
		Version:     1,
		ID:          base64.RawURLEncoding.EncodeToString(id),
		Realm:       realm,
		User:        user,
		IssuedAt:    now,
		SeenAt:      now,
		Fingerprint: fingerprint,
	}
	a.setSessionCookie(w, r, ticket)
	return ticket
}

func (a *webAuth) setSessionCookie(w http.ResponseWriter, r *http.Request, ticket *webSessionTicket) {
	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookieName,
		Value:    a.encodeTicket(ticket),
		Path:     "/",
		HttpOnly: true,
		Secure:   a.transport(r).https,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *webAuth) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     webSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.transport(r).https,
		SameSite: http.SameSiteStrictMode,
	})
}

func (a *webAuth) sessionExpiry(ticket *webSessionTicket) time.Time {
	return time.Unix(ticket.IssuedAt, 0).Add(a.cfg.WebSessionLifetime())
}

// checkSession decides whether ticket is still good for r; reason is "" when
// it is.
func (a *webAuth) checkSession(r *http.Request, ticket *webSessionTicket) string {
	now := a.now()
	issued := time.Unix(ticket.IssuedAt, 0)
	switch {
	case issued.After(now.Add(webSessionClockSkew)):
		return webSessionInvalid
	case !now.Before(a.sessionExpiry(ticket)):
		return webSessionExpired
	case !now.Before(time.Unix(ticket.SeenAt, 0).Add(a.cfg.WebSessionIdleTimeout())):
		return webSessionIdle
	case !a.cfg.WebAuthRealmEnabled(ticket.Realm):
		return webSessionRealmDisabled
	case a.revoked.contains(ticket.ID):
		return webSessionRevoked
	}
	switch ticket.Realm {
	case webAuthRealmToken:
		if !hmac.Equal([]byte(ticket.Fingerprint), []byte(a.tokenFingerprint())) {
			return webSessionCredentialsChanged
		}
	case webAuthRealmSystem:
		if allowed, _ := a.systemTransportAllowed(r); !allowed {
			return webSessionInsecure
		}
		account, refusal, err := a.accounts.account(ticket.User, a.loginPolicy())
		if err != nil || refusal != "" {
			return webSessionAccountRefused
		}
		if !hmac.Equal([]byte(ticket.Fingerprint), []byte(a.systemFingerprint(account.name, account.hash))) {
			return webSessionCredentialsChanged
		}
	default:
		return webSessionInvalid
	}
	return ""
}

// webRequestTransport is what the panel knows about the client's connection.
type webRequestTransport struct {
	peer     net.IP // the address that connected to the panel
	client   net.IP // the client, as a trusted proxy reports it
	viaProxy bool   // relayed by a trusted proxy
	https    bool   // the client's own connection uses TLS
	// relayed is set when a peer that is not a trusted proxy sent
	// forwarding headers: someone relays for a client we cannot see.
	relayed bool
}

func (a *webAuth) trustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range a.proxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *webAuth) transport(r *http.Request) webRequestTransport {
	t := webRequestTransport{peer: apiAddrIP(r.RemoteAddr), https: r.TLS != nil}
	t.client = t.peer
	if !a.trustedProxy(t.peer) {
		relayed, _ := apiPlainRequestRelayed(r)
		t.relayed = relayed
		return t
	}
	// The proxy's word counts only when it is configured as trusted. Walk
	// X-Forwarded-For from the right: the first address that is not one of
	// our proxies is the client.
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(value, ",")...)
	}
	if len(hops) > 0 {
		t.viaProxy = true
		for i := len(hops) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(hops[i]))
			if ip == nil {
				break
			}
			if v4 := ip.To4(); v4 != nil {
				ip = v4
			}
			t.client = ip
			if !a.trustedProxy(ip) {
				break
			}
		}
	}
	// The nearest proxy appends or sets the last value.
	protos := r.Header.Values("X-Forwarded-Proto")
	if len(protos) > 0 {
		t.viaProxy = true
		values := strings.Split(protos[len(protos)-1], ",")
		t.https = strings.EqualFold(strings.TrimSpace(values[len(values)-1]), "https")
	}
	return t
}

func (a *webAuth) clientKey(r *http.Request) string {
	if ip := a.transport(r).client; ip != nil {
		return ip.String()
	}
	return apiAuthClientKey(r)
}

// systemTransportAllowed reports whether a system account password may be
// sent over r's connection: TLS, or a connection from this host's loopback
// that nothing relays, or a trusted proxy that says its client used HTTPS.
func (a *webAuth) systemTransportAllowed(r *http.Request) (bool, string) {
	t := a.transport(r)
	if t.viaProxy {
		if t.https {
			return true, ""
		}
		return false, "a trusted proxy relayed it for a client that did not use HTTPS"
	}
	if r.TLS != nil {
		return true, ""
	}
	if t.relayed {
		return false, "plain HTTP with forwarding headers from a proxy that is not in web_trusted_proxies"
	}
	if t.peer == nil || !t.peer.IsLoopback() {
		return false, "plain HTTP from a remote client"
	}
	if a.panelRelay != nil {
		if relay := a.panelRelay(); relay != "" {
			return false, "plain HTTP from this host while its " + relay + " relays clients to the panel port"
		}
	}
	return true, ""
}

// sameOriginRequest checks the Origin a browser sent against the host the
// request was made to.
func (a *webAuth) sameOriginRequest(r *http.Request) bool {
	if site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	host := r.Host
	if a.trustedProxy(apiAddrIP(r.RemoteAddr)) {
		if forwarded := r.Header.Values("X-Forwarded-Host"); len(forwarded) > 0 {
			values := strings.Split(forwarded[len(forwarded)-1], ",")
			host = strings.TrimSpace(values[len(values)-1])
		}
	}
	return normalizeOriginHost(parsed.Host, parsed.Scheme) == normalizeOriginHost(host, parsed.Scheme)
}

func normalizeOriginHost(hostport, scheme string) string {
	hostport = strings.ToLower(strings.TrimSpace(hostport))
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return host
	}
	return net.JoinHostPort(host, port)
}

// sanitizeLogUser makes a user name safe to put in a log line that fail2ban
// parses: no spaces, quotes or control characters, and bounded length.
func sanitizeLogUser(name string) string {
	if name == "" {
		return "-"
	}
	var b strings.Builder
	count := 0
	for _, r := range name {
		if count == webLogUserMaxRunes {
			b.WriteString("...")
			break
		}
		count++
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._-@$", r):
			b.WriteRune(r)
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func shortSessionID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// Request state the middleware attaches for the handlers.

type webAuthContextKey struct{}

type webAuthRequestState struct {
	identity *webIdentity
	refused  string // why a session cookie was refused
}

func webAuthStateFromRequest(r *http.Request) *webAuthRequestState {
	if r == nil {
		return nil
	}
	state, _ := r.Context().Value(webAuthContextKey{}).(*webAuthRequestState)
	return state
}

func requestWebIdentity(r *http.Request) *webIdentity {
	if state := webAuthStateFromRequest(r); state != nil {
		return state.identity
	}
	return nil
}

func webAuthCheckedPath(path string) bool {
	return apiCredentialProtectedPath(path) || path == "/debug/pprof" || strings.HasPrefix(path, "/debug/pprof/")
}

func unsafeHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

func bearerTokenFromRequest(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", false
	}
	fields := strings.Fields(header)
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") {
		return fields[1], true
	}
	return "", true
}

// middleware authenticates each management request once: a Bearer header,
// or else the session cookie. Wrong Bearer tokens count towards the failure
// limit; a stale or forged cookie does not (it cannot guess anything, and a
// panel left open past its idle timeout would otherwise lock its own
// address out of the login form).
func (a *webAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !webAuthCheckedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		state := &webAuthRequestState{}
		r = r.WithContext(context.WithValue(r.Context(), webAuthContextKey{}, state))
		if token, present := bearerTokenFromRequest(r); present {
			client := a.clientKey(r)
			if a.bearerMatches(token) {
				a.limiter.reset(client)
				state.identity = &webIdentity{Realm: webAuthRealmToken, Via: "bearer"}
				next.ServeHTTP(w, r)
				return
			}
			if allowed, retryAfter := a.limiter.allowFailure(client); !allowed {
				writeAPIAuthRateLimit(w, retryAfter)
				return
			}
			a.logf("auth: bearer token rejected client=%s", client)
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(webSessionCookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		ticket, ok := a.decodeTicket(cookie.Value)
		reason := webSessionInvalid
		if ok {
			reason = a.checkSession(r, ticket)
		}
		if reason != "" {
			state.refused = reason
			a.clearSessionCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}
		identity := &webIdentity{Realm: ticket.Realm, User: ticket.User, Via: "session", ticket: ticket}
		if unsafeHTTPMethod(r.Method) && r.URL.Path != webAuthLoginPath {
			if !a.sameOriginRequest(r) {
				writeWebAuthError(w, http.StatusForbidden, "cross_origin", "request origin does not match this panel")
				return
			}
			provided := strings.TrimSpace(r.Header.Get(webCSRFHeader))
			if provided == "" || !hmac.Equal([]byte(provided), []byte(a.csrfToken(ticket))) {
				writeWebAuthError(w, http.StatusForbidden, "csrf", "missing or invalid "+webCSRFHeader+" header")
				return
			}
		}
		if r.Header.Get(webBackgroundHeader) == "" {
			now := a.now()
			if now.Sub(time.Unix(ticket.SeenAt, 0)) >= webSessionRefreshInterval {
				refreshed := *ticket
				refreshed.SeenAt = now.Unix()
				a.setSessionCookie(w, r, &refreshed)
				identity.ticket = &refreshed
			}
		}
		state.identity = identity
		next.ServeHTTP(w, r)
	})
}

func writeWebAuthError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": message, "code": code})
}

// webSessionRevocations remembers logged-out sessions. Each process reads
// the database table again every few seconds, so a logout handled by the
// other side of a hot restart is seen here too.
type webSessionRevocations struct {
	db  *sql.DB
	now func() time.Time

	mu       sync.Mutex
	ids      map[string]int64
	loadedAt time.Time
}

func newWebSessionRevocations(db *sql.DB, now func() time.Time) *webSessionRevocations {
	return &webSessionRevocations{db: db, now: now, ids: make(map[string]int64)}
}

func (s *webSessionRevocations) contains(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.db != nil && (s.loadedAt.IsZero() || now.Sub(s.loadedAt) >= webSessionRevocationsTTL || now.Before(s.loadedAt)) {
		s.reloadLocked(now)
	}
	expires, ok := s.ids[id]
	return ok && now.Unix() < expires
}

func (s *webSessionRevocations) reloadLocked(now time.Time) {
	if _, err := s.db.Exec(`DELETE FROM web_session_revocations WHERE expires_unix <= ?`, now.Unix()); err != nil {
		log.Printf("auth: prune revoked sessions: %v", err)
	}
	rows, err := s.db.Query(`SELECT session_id, expires_unix FROM web_session_revocations`)
	if err != nil {
		log.Printf("auth: read revoked sessions: %v", err)
		return
	}
	defer rows.Close()
	ids := make(map[string]int64)
	for rows.Next() {
		var id string
		var expires int64
		if rows.Scan(&id, &expires) == nil {
			ids[id] = expires
		}
	}
	if rows.Err() != nil {
		return
	}
	// Keep revocations of this process that a failed write left out.
	for id, expires := range s.ids {
		if _, ok := ids[id]; !ok && expires > now.Unix() {
			ids[id] = expires
		}
	}
	s.ids = ids
	s.loadedAt = now
}

func (s *webSessionRevocations) add(id string, expires time.Time) error {
	s.mu.Lock()
	s.ids[id] = expires.Unix()
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO web_session_revocations (session_id, expires_unix) VALUES (?, ?)`, id, expires.Unix())
	return err
}

// logWebAuthStartup says how the panel can be logged into and what keeps a
// realm from working.
func logWebAuthStartup(cfg *Config, a *webAuth) {
	realms := cfg.WebAuthRealms()
	log.Printf("web login: realms %s; sessions end after %s idle or %s", strings.Join(realms, ", "), cfg.WebSessionIdleTimeout(), cfg.WebSessionLifetime())
	if !cfg.WebAuthRealmEnabled(webAuthRealmSystem) {
		return
	}
	if err := a.accounts.readable(); err != nil {
		log.Printf("web login: system accounts are unavailable: %v", err)
	}
	if !cfg.WebTLSEnabled() && apiBindExposesRemoteClients(cfg) && len(a.proxies) == 0 {
		log.Printf("web login: web_tls is off, so system accounts can log in only from this host (or through web_trusted_proxies over HTTPS)")
	}
	groups := cfg.WebAdminGroups()
	if len(groups) == 0 {
		groups = []string{"(none)"}
	}
	log.Printf("web login: system accounts allowed: uid 0 %s, groups %s", map[bool]string{true: "yes", false: "no"}[cfg.WebRootLoginAllowed()], strings.Join(groups, ", "))
}
