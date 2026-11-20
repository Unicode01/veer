(function () {
  'use strict';

  // Panel sign-in. The browser keeps no credential: logging in (with a
  // system account or the access token) gets an HttpOnly session cookie, and
  // requests that change something carry the session's CSRF token. A token
  // that an older panel saved in localStorage is exchanged for a session once
  // and then deleted.
  const app = window.VeerApp;
  const $ = app.$;
  const legacyTokenKeys = ['veer_token', 'forward_token'];
  const realmStorageKey = 'veer_login_realm';
  const activityThrottleMS = 1000;

  const el = {
    modal: $('tokenModal'),
    form: $('loginForm'),
    host: $('loginHost'),
    switcher: $('loginRealmSwitch'),
    realmSystem: $('loginRealmSystem'),
    realmToken: $('loginRealmToken'),
    realmNote: $('loginRealmNote'),
    systemFields: $('loginSystemFields'),
    tokenFields: $('loginTokenFields'),
    username: $('loginUsername'),
    password: $('loginPassword'),
    token: $('tokenInput'),
    notice: $('loginNotice'),
    status: $('loginStatus'),
    error: $('loginError'),
    submit: $('tokenSubmit'),
    identity: $('sessionIdentity'),
    identityAvatar: $('sessionAvatar'),
    identityName: $('sessionIdentityName'),
    identityRealm: $('sessionIdentityRealm'),
    logout: $('logoutBtn')
  };

  app.state.session = null;
  app.state.authMethods = null;
  app.state.authTransport = null;
  app.state.loginRealm = '';
  app.state.lastActivityAt = 0;
  app.state.activityReportedAt = 0;

  function storageGet(storage, key) {
    try {
      return storage.getItem(key);
    } catch (_) {
      return null;
    }
  }

  function storageSet(storage, key, value) {
    try {
      if (value === null) storage.removeItem(key);
      else storage.setItem(key, value);
    } catch (_) {}
  }

  app.readLegacyToken = function readLegacyToken() {
    for (const key of legacyTokenKeys) {
      const value = String(storageGet(localStorage, key) || '').trim();
      if (value) return value;
    }
    return '';
  };

  app.clearLegacyToken = function clearLegacyToken() {
    legacyTokenKeys.forEach((key) => storageSet(localStorage, key, null));
  };

  app.isAuthenticated = function isAuthenticated() {
    return !!app.state.session;
  };

  // A request counts as activity for the idle timeout unless it is a
  // background poll and the user has done nothing since the last request.
  app.authHeaders = function authHeaders(method, extra, options) {
    const headers = Object.assign({}, extra || {});
    const upper = String(method || 'GET').toUpperCase();
    const session = app.state.session;
    if (upper !== 'GET' && upper !== 'HEAD' && session && session.csrf) headers['X-Veer-CSRF'] = session.csrf;
    if (options && options.background && app.state.lastActivityAt <= app.state.activityReportedAt) {
      headers['X-Veer-Background'] = '1';
    } else {
      app.state.activityReportedAt = Date.now();
    }
    return headers;
  };

  app.authFetch = async function authFetch(path, init, options) {
    const request = Object.assign({ credentials: 'same-origin' }, init || {});
    request.headers = app.authHeaders(request.method || 'GET', request.headers, options);
    const response = await fetch(path, request);
    if (response.status === 401) {
      app.handleUnauthorized(response);
      throw new Error('unauthorized');
    }
    if (response.status === 403) {
      const payload = await response.clone().json().catch(() => null);
      if (payload && (payload.code === 'csrf' || payload.code === 'cross_origin')) {
        app.handleUnauthorized(response);
        throw new Error('unauthorized');
      }
    }
    return response;
  };

  app.handleUnauthorized = function handleUnauthorized(response) {
    const reason = response && response.headers ? response.headers.get('X-Veer-Auth-Reason') || '' : '';
    const hadSession = !!app.state.session;
    app.state.session = null;
    app.renderSessionIdentity();
    app.showTokenModal({ reason: hadSession ? (reason || 'default') : reason });
  };

  function applySessionView(view) {
    app.state.authMethods = view && view.methods ? view.methods : null;
    app.state.authTransport = view && view.transport ? view.transport : null;
    if (view && view.authenticated && view.identity) {
      app.state.session = {
        identity: view.identity,
        csrf: view.csrf_token || '',
        expiresAt: view.session && view.session.expires_at ? new Date(view.session.expires_at) : null,
        idleTimeoutSeconds: view.session ? Number(view.session.idle_timeout_seconds) || 0 : 0
      };
    } else {
      app.state.session = null;
    }
    app.renderSessionIdentity();
    return app.state.session;
  }

  async function postLogin(body) {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const payload = await response.json().catch(() => ({}));
    return { response, payload };
  }

  // restoreSession runs at page load: it exchanges a token an older panel
  // stored, then asks the server who this browser is. It resolves to true
  // when the dashboard can start.
  app.restoreSession = async function restoreSession() {
    let migrationRejected = false;
    const legacy = app.readLegacyToken();
    if (legacy) {
      try {
        const { response, payload } = await postLogin({ realm: 'token', token: legacy });
        if (response.ok) {
          app.clearLegacyToken();
          applySessionView(payload);
          return true;
        }
        // A definite no: the stored token is wrong, or token sign-in is off.
        if (response.status === 400 || response.status === 401 || response.status === 403) {
          app.clearLegacyToken();
          migrationRejected = true;
        }
      } catch (_) {
        // Keep it and try again on the next load.
      }
    }
    try {
      const response = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error(response.statusText || String(response.status));
      const view = await response.json();
      if (applySessionView(view)) return true;
      app.showTokenModal({ reason: view.refused || '', migrationRejected });
    } catch (err) {
      app.showTokenModal({ error: app.t('auth.error.network', { message: err && err.message ? err.message : String(err) }) });
    }
    return false;
  };

  app.refreshSessionInfo = async function refreshSessionInfo() {
    const response = await fetch('/api/auth/session', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) throw new Error(response.statusText || String(response.status));
    return applySessionView(await response.json());
  };

  // Login form

  function realmInfo(realm) {
    const methods = app.state.authMethods || {};
    if (realm === 'system') return methods.system || { enabled: false, available: false, reason: 'disabled' };
    return methods.token || { enabled: true, available: true };
  }

  function chooseRealm(preferred) {
    const system = realmInfo('system');
    const token = realmInfo('token');
    const candidates = [preferred, storageGet(localStorage, realmStorageKey), 'system', 'token'];
    for (const realm of candidates) {
      if (realm === 'system' && system.available) return 'system';
      if (realm === 'token' && token.available) return 'token';
    }
    return token.enabled ? 'token' : 'system';
  }

  function setText(node, text) {
    if (!node) return;
    node.textContent = text || '';
    node.hidden = !text;
  }

  function renderLoginForm() {
    const system = realmInfo('system');
    const token = realmInfo('token');
    const realm = app.state.loginRealm;
    el.realmToken.hidden = !token.enabled;
    el.realmSystem.disabled = !system.available;
    el.realmSystem.setAttribute('aria-pressed', String(realm === 'system'));
    el.realmToken.setAttribute('aria-pressed', String(realm === 'token'));
    // The switch appears only when both methods are turned on. A method the
    // config leaves off is not offered at all; one that is on but cannot be
    // used from here stays visible, greyed out, with the reason under it.
    el.switcher.hidden = !(token.enabled && system.enabled);
    const unavailable = system.enabled && !system.available ? app.t('auth.systemUnavailable.' + (system.reason || 'insecure_channel')) : '';
    setText(el.realmNote, unavailable);
    if (unavailable) el.realmSystem.title = unavailable;
    else el.realmSystem.removeAttribute('title');
    el.systemFields.hidden = realm !== 'system';
    el.tokenFields.hidden = realm !== 'token';
    [el.username, el.password].forEach((input) => { input.disabled = realm !== 'system'; });
    el.token.disabled = realm !== 'token';
    const transport = app.state.authTransport || {};
    const plaintext = realm === 'token' && transport.secure === false && !transport.loopback;
    setText(el.notice, plaintext ? app.t('auth.plaintextWarning') : '');
    if (el.host) setText(el.host, window.location.host || '');
  }

  app.selectLoginRealm = function selectLoginRealm(realm, options) {
    if (realm === 'system' && !realmInfo('system').available) return;
    if (realm === 'token' && !realmInfo('token').enabled) return;
    app.state.loginRealm = realm;
    setText(el.error, '');
    renderLoginForm();
    if (options && options.focus) focusLoginField();
  };

  function focusLoginField() {
    if (app.state.loginRealm === 'system') {
      if (el.username.value.trim()) el.password.focus();
      else el.username.focus();
    } else {
      el.token.focus();
    }
  }

  function sessionEndedMessage(reason) {
    if (!reason) return '';
    const key = 'auth.sessionEnded.' + reason;
    const text = app.t(key);
    return text === key ? app.t('auth.sessionEnded.default') : text;
  }

  app.showTokenModal = function showTokenModal(options) {
    const opts = options || {};
    const wasActive = el.modal.classList.contains('active');
    if (typeof app.stopPolling === 'function') app.stopPolling();
    if (typeof app.closeDropdowns === 'function') app.closeDropdowns();
    app.el.appRoot.style.display = 'none';
    el.modal.classList.add('active');
    el.modal.setAttribute('aria-hidden', 'false');
    let status = sessionEndedMessage(opts.reason);
    if (opts.migrationRejected) status = app.t('auth.tokenRejected');
    if (opts.loggedOut) status = app.t('toast.loggedOut');
    // Several requests in flight can each come back 401; only the first one
    // opens the form, the rest must not wipe what the user is typing.
    if (wasActive) {
      if (status) setText(el.status, status);
      if (opts.error) setText(el.error, opts.error);
      return;
    }
    const system = realmInfo('system');
    if (!el.username.value) el.username.value = system.default_user || '';
    app.state.loginRealm = chooseRealm(app.state.loginRealm);
    el.password.value = '';
    el.token.value = '';
    setText(el.error, opts.error || '');
    setText(el.status, status);
    setBusy(false);
    renderLoginForm();
    focusLoginField();
    // The methods depend on how this page reached the server; refresh them
    // when the form opens after the dashboard ran. Another tab may have
    // signed in again meanwhile, and then this one carries on.
    if (opts.reason || opts.loggedOut) {
      app.refreshSessionInfo().then((session) => {
        if (session && !opts.loggedOut) {
          app.hideTokenModal();
          app.init();
          return;
        }
        if (app.state.loginRealm === 'system' && !realmInfo('system').available) app.state.loginRealm = chooseRealm('');
        renderLoginForm();
      }).catch(() => {});
    }
  };

  app.hideTokenModal = function hideTokenModal() {
    el.modal.classList.remove('active');
    el.modal.setAttribute('aria-hidden', 'true');
    el.password.value = '';
    el.token.value = '';
    [el.username, el.password, el.token].forEach((input) => { input.disabled = true; });
    setText(el.error, '');
    setText(el.status, '');
    app.el.appRoot.style.display = 'block';
  };

  function setBusy(busy) {
    el.submit.disabled = busy;
    el.submit.classList.toggle('is-busy', busy);
    el.form.setAttribute('aria-busy', String(busy));
  }

  function loginErrorMessage(realm, response, payload) {
    const code = payload && payload.code;
    if (response.status === 429) {
      const seconds = Number(response.headers.get('Retry-After')) || 60;
      return app.t('auth.error.rateLimited', { seconds });
    }
    if (code === 'invalid_credentials') return app.t(realm === 'system' ? 'auth.error.invalid' : 'auth.error.invalidToken');
    if (code === 'insecure_channel') return app.t('auth.systemUnavailable.insecure_channel');
    if (code === 'realm_disabled') return app.t('auth.error.realmDisabled');
    if (code === 'unavailable') return app.t('auth.error.unavailable');
    return app.t('auth.error.network', { message: (payload && payload.error) || response.statusText || String(response.status) });
  }

  async function submitLogin(event) {
    if (event) event.preventDefault();
    if (el.submit.disabled) return;
    const realm = app.state.loginRealm;
    const body = { realm };
    let missing = null;
    if (realm === 'system') {
      body.username = el.username.value.trim();
      body.password = el.password.value;
      if (!body.username) missing = [el.username, 'auth.error.usernameRequired'];
      else if (!body.password) missing = [el.password, 'auth.error.passwordRequired'];
    } else {
      body.token = el.token.value.trim();
      if (!body.token) missing = [el.token, 'auth.error.tokenRequired'];
    }
    if (missing) {
      setText(el.error, app.t(missing[1]));
      missing[0].focus();
      return;
    }
    setText(el.error, '');
    setText(el.status, '');
    setBusy(true);
    try {
      const { response, payload } = await postLogin(body);
      if (!response.ok) {
        setText(el.error, loginErrorMessage(realm, response, payload));
        if (payload && payload.code === 'insecure_channel') {
          await app.refreshSessionInfo().catch(() => {});
          renderLoginForm();
        }
        setBusy(false);
        if (realm === 'system') {
          el.password.value = '';
          el.password.focus();
        } else {
          el.token.select();
          el.token.focus();
        }
        return;
      }
      app.clearLegacyToken();
      storageSet(localStorage, realmStorageKey, realm);
      applySessionView(payload);
      setBusy(false);
      app.hideTokenModal();
      app.init();
    } catch (err) {
      setBusy(false);
      setText(el.error, app.t('auth.error.network', { message: err && err.message ? err.message : String(err) }));
    }
  }

  app.logout = async function logout() {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'same-origin',
        headers: app.authHeaders('POST', { 'Content-Type': 'application/json' })
      });
      if (!response.ok && response.status !== 401) throw new Error(response.statusText || String(response.status));
    } catch (err) {
      app.notify('error', app.t('errors.actionFailed', { action: app.t('auth.logout'), message: err.message }));
      return false;
    }
    app.state.session = null;
    app.clearLegacyToken();
    if (typeof app.clearPluginAdminToken === 'function') app.clearPluginAdminToken();
    app.renderSessionIdentity();
    app.showTokenModal({ loggedOut: true });
    return true;
  };

  // Sidebar identity

  app.renderSessionIdentity = function renderSessionIdentity() {
    if (!el.identity) return;
    const session = app.state.session;
    el.identity.hidden = !session;
    if (!session) {
      el.identityName.textContent = '';
      if (el.identityRealm) el.identityRealm.textContent = '';
      el.identity.removeAttribute('title');
      return;
    }
    const identity = session.identity || {};
    const system = identity.realm === 'system';
    // A system account shows its user name and initial; the token has no
    // user, so it shows the method instead.
    const user = system ? (identity.user || String(identity.name || '').replace(/@system$/, '')) : '';
    el.identityName.textContent = system ? user : app.t('auth.realm.token');
    if (el.identityRealm) el.identityRealm.textContent = system ? app.t('auth.realm.system') : 'web_token';
    if (el.identityAvatar) {
      el.identityAvatar.dataset.realm = system ? 'system' : 'token';
      el.identityAvatar.dataset.initial = system ? (Array.from(user)[0] || '?').toUpperCase() : '';
    }
    const realm = app.t(system ? 'auth.realm.system' : 'auth.realm.token');
    const parts = [app.t('auth.identityLabel') + ' ' + (identity.name || ''), realm];
    if (session.expiresAt && !Number.isNaN(session.expiresAt.getTime())) {
      parts.push(app.t('auth.sessionEnds', { time: session.expiresAt.toLocaleString(app.state.locale, { hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' }) }));
    }
    el.identity.title = parts.join(' · ');
    el.identity.setAttribute('aria-label', el.identity.title);
  };

  // Events

  el.form.addEventListener('submit', submitLogin);
  [el.realmSystem, el.realmToken].forEach((button) => {
    button.addEventListener('click', () => app.selectLoginRealm(button.dataset.realm, { focus: true }));
  });
  el.switcher.addEventListener('keydown', (event) => {
    if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
    const options = [el.realmSystem, el.realmToken].filter((button) => !button.hidden && !button.disabled);
    if (options.length < 2) return;
    event.preventDefault();
    const index = options.indexOf(document.activeElement);
    const next = options[(index + (event.key === 'ArrowRight' ? 1 : options.length - 1)) % options.length];
    next.focus();
    app.selectLoginRealm(next.dataset.realm);
  });
  el.logout.addEventListener('click', async () => {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.logoutTitle'),
      message: app.t('auth.logoutConfirm'),
      confirmText: app.t('auth.logout'),
      cancelText: app.t('common.cancel')
    });
    if (!confirmed) return;
    await app.logout();
  });
  const noteActivity = () => {
    const now = Date.now();
    if (now - app.state.lastActivityAt >= activityThrottleMS) app.state.lastActivityAt = now;
  };
  ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((type) => {
    document.addEventListener(type, noteActivity, { capture: true, passive: true });
  });

  app.refreshLocalizedUI = (function wrapAuthLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original.apply(this, arguments);
      if (el.modal.classList.contains('active')) renderLoginForm();
      app.renderSessionIdentity();
    };
  })(app.refreshLocalizedUI);
})();
