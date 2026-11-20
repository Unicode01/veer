package app

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	webAuthSessionPath = "/api/auth/session"
	webAuthLoginPath   = "/api/auth/login"
	webAuthLogoutPath  = "/api/auth/logout"

	webLoginBodyMaxBytes = 16 << 10
)

// Reasons the system realm is unavailable, for the login page.
const (
	webSystemRealmDisabled   = "disabled"
	webSystemRealmInsecure   = "insecure_channel"
	webSystemRealmUnreadable = "accounts_unreadable"
)

type webLoginRequest struct {
	Realm    string `json:"realm"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
}

type webIdentityView struct {
	Realm string `json:"realm"`
	User  string `json:"user,omitempty"`
	Name  string `json:"name"`
	Via   string `json:"via"`
}

type webSessionInfoView struct {
	IssuedAt           time.Time `json:"issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	IdleTimeoutSeconds int64     `json:"idle_timeout_seconds"`
}

type webRealmView struct {
	Enabled     bool   `json:"enabled"`
	Available   bool   `json:"available"`
	Reason      string `json:"reason,omitempty"`
	DefaultUser string `json:"default_user,omitempty"`
}

type webAuthMethodsView struct {
	Realms []string     `json:"realms"`
	System webRealmView `json:"system"`
	Token  webRealmView `json:"token"`
}

type webTransportView struct {
	Secure   bool `json:"secure"`
	Loopback bool `json:"loopback"`
}

type webSessionView struct {
	Authenticated bool                `json:"authenticated"`
	Identity      *webIdentityView    `json:"identity,omitempty"`
	CSRFToken     string              `json:"csrf_token,omitempty"`
	Session       *webSessionInfoView `json:"session,omitempty"`
	Refused       string              `json:"refused,omitempty"`
	Methods       webAuthMethodsView  `json:"methods"`
	Transport     webTransportView    `json:"transport"`
}

func (a *webAuth) register(mux *http.ServeMux) {
	mux.HandleFunc(webAuthSessionPath, a.handleSession)
	mux.HandleFunc(webAuthLoginPath, a.handleLogin)
	mux.HandleFunc(webAuthLogoutPath, a.handleLogout)
}

func (a *webAuth) methodsView(r *http.Request) webAuthMethodsView {
	view := webAuthMethodsView{Realms: a.cfg.WebAuthRealms()}
	view.Token = webRealmView{Enabled: a.cfg.WebAuthRealmEnabled(webAuthRealmToken)}
	view.Token.Available = view.Token.Enabled
	system := webRealmView{Enabled: a.cfg.WebAuthRealmEnabled(webAuthRealmSystem)}
	if a.cfg.WebRootLoginAllowed() {
		system.DefaultUser = "root"
	}
	switch {
	case !system.Enabled:
		system.Reason = webSystemRealmDisabled
	default:
		if allowed, _ := a.systemTransportAllowed(r); !allowed {
			system.Reason = webSystemRealmInsecure
		} else if err := a.accounts.readable(); err != nil {
			system.Reason = webSystemRealmUnreadable
		} else {
			system.Available = true
		}
	}
	view.System = system
	return view
}

func (a *webAuth) sessionView(r *http.Request, identity *webIdentity) webSessionView {
	t := a.transport(r)
	view := webSessionView{
		Methods:   a.methodsView(r),
		Transport: webTransportView{Secure: t.https, Loopback: !t.viaProxy && !t.relayed && t.peer != nil && t.peer.IsLoopback()},
	}
	if state := webAuthStateFromRequest(r); state != nil {
		view.Refused = state.refused
	}
	if identity == nil {
		return view
	}
	view.Authenticated = true
	view.Refused = ""
	view.Identity = &webIdentityView{Realm: identity.Realm, User: identity.User, Name: identity.Name(), Via: identity.Via}
	if identity.ticket != nil {
		view.CSRFToken = a.csrfToken(identity.ticket)
		view.Session = &webSessionInfoView{
			IssuedAt:           time.Unix(identity.ticket.IssuedAt, 0).UTC(),
			ExpiresAt:          a.sessionExpiry(identity.ticket).UTC(),
			IdleTimeoutSeconds: int64(a.cfg.WebSessionIdleTimeout() / time.Second),
		}
	}
	return view
}

// handleSession tells the panel who it is logged in as and how it can log
// in. It answers without credentials, so it shows nothing secret.
func (a *webAuth) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, a.sessionView(r, requestWebIdentity(r)))
}

func (a *webAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// A JSON body cannot come from a cross-site form without a CORS
	// preflight, which the panel never grants.
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeWebAuthError(w, http.StatusUnsupportedMediaType, "bad_request", "login requires a JSON body")
		return
	}
	if !a.sameOriginRequest(r) {
		writeWebAuthError(w, http.StatusForbidden, "cross_origin", "request origin does not match this panel")
		return
	}
	client := a.clientKey(r)
	var req webLoginRequest
	r.Body = http.MaxBytesReader(w, r.Body, webLoginBodyMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeWebAuthError(w, http.StatusBadRequest, "bad_request", "invalid login request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeWebAuthError(w, http.StatusBadRequest, "bad_request", "invalid login request")
		return
	}
	realm := strings.ToLower(strings.TrimSpace(req.Realm))
	if realm != webAuthRealmSystem && realm != webAuthRealmToken {
		writeWebAuthError(w, http.StatusBadRequest, "bad_request", "realm must be system or token")
		return
	}
	if !a.cfg.WebAuthRealmEnabled(realm) {
		a.logf("auth: login refused client=%s realm=%s user=%s reason=realm_disabled", client, realm, sanitizeLogUser(req.Username))
		writeWebAuthError(w, http.StatusForbidden, "realm_disabled", "this login method is not enabled (web_auth_realms)")
		return
	}
	// Every credential check is counted before it runs: checking first and
	// counting after would let a burst of concurrent requests all pass the
	// check and each try a password. A success clears the count below; a
	// request that could not be checked at all gives its attempt back.
	reserveAttempt := func() bool {
		allowed, retryAfter := a.limiter.allowFailure(client)
		if !allowed {
			writeAPIAuthRateLimit(w, retryAfter)
		}
		return allowed
	}
	var user, fingerprint string
	switch realm {
	case webAuthRealmToken:
		if !reserveAttempt() {
			return
		}
		if !a.bearerMatches(strings.TrimSpace(req.Token)) {
			a.loginFailed(w, client, realm, "", "bad_token")
			return
		}
		fingerprint = a.tokenFingerprint()
		if !a.transport(r).https {
			a.logf("auth: token login over plain HTTP client=%s; enable web_tls so the token is not sent in clear text", client)
		}
	case webAuthRealmSystem:
		if allowed, why := a.systemTransportAllowed(r); !allowed {
			a.logf("auth: login refused client=%s realm=system user=%s reason=insecure_channel (%s)", client, sanitizeLogUser(req.Username), why)
			writeWebAuthError(w, http.StatusForbidden, webSystemRealmInsecure, "system account login needs HTTPS (web_tls) or a connection from this host")
			return
		}
		if !reserveAttempt() {
			return
		}
		account, reason, status := a.verifySystemLogin(r, req.Username, req.Password)
		if status != 0 {
			a.limiter.release(client)
			writeWebAuthError(w, status, "unavailable", "system account login is unavailable; see the Veer log")
			return
		}
		if reason != "" {
			a.loginFailed(w, client, realm, req.Username, reason)
			return
		}
		user = account.name
		fingerprint = a.systemFingerprint(account.name, account.hash)
	}
	a.limiter.reset(client)
	if previous := requestWebIdentity(r); previous != nil && previous.ticket != nil {
		_ = a.revoked.add(previous.ticket.ID, a.sessionExpiry(previous.ticket))
	}
	ticket := a.newSession(w, r, realm, user, fingerprint)
	a.logf("auth: login accepted client=%s realm=%s user=%s session=%s", client, realm, sanitizeLogUser(user), shortSessionID(ticket.ID))
	identity := &webIdentity{Realm: realm, User: user, Via: "session", ticket: ticket}
	writeJSON(w, http.StatusOK, a.sessionView(r, identity))
}

// verifySystemLogin checks a system account login. status is non-zero when
// it could not be decided at all.
func (a *webAuth) verifySystemLogin(r *http.Request, username, password string) (*systemAccount, string, int) {
	timer := time.NewTimer(webSystemLoginSlotWait)
	defer timer.Stop()
	select {
	case a.hashSlots <- struct{}{}:
	case <-timer.C:
		a.logf("auth: system login busy client=%s", a.clientKey(r))
		return nil, "", http.StatusServiceUnavailable
	case <-r.Context().Done():
		return nil, "", http.StatusServiceUnavailable
	}
	defer func() { <-a.hashSlots }()
	account, reason, err := a.accounts.account(username, a.loginPolicy())
	if err != nil {
		a.logf("auth: system accounts unreadable: %v", err)
		return nil, "", http.StatusServiceUnavailable
	}
	if reason != "" {
		spendSystemLoginDecoyHash(password)
		return nil, reason, 0
	}
	if reason := verifySystemPassword(account, password); reason != "" {
		return nil, reason, 0
	}
	return account, "", 0
}

// loginFailed answers a checked login that failed; its attempt was counted
// before the check.
func (a *webAuth) loginFailed(w http.ResponseWriter, client, realm, user, reason string) {
	a.logf("auth: login failed client=%s realm=%s user=%s reason=%s", client, realm, sanitizeLogUser(user), reason)
	writeWebAuthError(w, http.StatusUnauthorized, "invalid_credentials", "invalid credentials")
}

// handleLogout ends the session of the cookie. The middleware has checked
// the CSRF token of a valid session already.
func (a *webAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	identity := requestWebIdentity(r)
	if identity != nil && identity.ticket != nil {
		if err := a.revoked.add(identity.ticket.ID, a.sessionExpiry(identity.ticket)); err != nil {
			a.logf("auth: record logout: %v", err)
		}
		a.logf("auth: logout client=%s realm=%s user=%s session=%s", a.clientKey(r), identity.Realm, sanitizeLogUser(identity.User), shortSessionID(identity.ticket.ID))
	}
	a.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
