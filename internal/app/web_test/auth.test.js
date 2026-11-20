const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const authSource = fs.readFileSync(path.join(__dirname, '..', 'web', 'js', 'auth.js'), 'utf8');

const elementIds = [
  'tokenModal', 'loginForm', 'loginHost', 'loginRealmSwitch', 'loginRealmSystem', 'loginRealmToken',
  'loginRealmNote', 'loginSystemFields', 'loginTokenFields', 'loginUsername', 'loginPassword', 'tokenInput',
  'loginNotice', 'loginStatus', 'loginError', 'tokenSubmit', 'sessionIdentity', 'sessionIdentityName',
  'logoutBtn', 'app'
];

function createElement(document, id) {
  const listeners = {};
  const attributes = {};
  const classes = new Set();
  return {
    id,
    hidden: false,
    disabled: false,
    value: '',
    textContent: '',
    title: '',
    dataset: {},
    style: {},
    classList: {
      add(name) { classes.add(name); },
      remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
      toggle(name, force) {
        const on = force === undefined ? !classes.has(name) : !!force;
        if (on) classes.add(name); else classes.delete(name);
        return on;
      }
    },
    setAttribute(name, value) { attributes[name] = String(value); },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(attributes, name) ? attributes[name] : null; },
    removeAttribute(name) { delete attributes[name]; },
    addEventListener(type, handler) { (listeners[type] = listeners[type] || []).push(handler); },
    async dispatch(type, event) {
      for (const handler of listeners[type] || []) {
        await handler(Object.assign({ type, preventDefault() {}, key: '' }, event || {}));
      }
    },
    focus() { document.activeElement = this; },
    select() {}
  };
}

function jsonResponse(status, body, headers) {
  const values = Object.assign({}, headers || {});
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: String(status),
    headers: { get(name) { return values[name] || values[String(name).toLowerCase()] || null; } },
    json: async () => body,
    clone() { return jsonResponse(status, body, headers); }
  };
}

const dictionary = {
  'auth.sessionEnded.session_idle': 'idle-ended',
  'auth.sessionEnded.default': 'session-ended',
  'auth.tokenRejected': 'saved-token-rejected',
  'toast.loggedOut': 'signed-out',
  'auth.systemUnavailable.insecure_channel': 'needs-https',
  'auth.systemUnavailable.disabled': 'system-off',
  'auth.plaintextWarning': 'plaintext',
  'auth.error.invalid': 'bad-password',
  'auth.error.invalidToken': 'bad-token',
  'auth.error.rateLimited': 'slow-down {{seconds}}',
  'auth.error.passwordRequired': 'need-password',
  'auth.realm.system': 'System account',
  'auth.realm.token': 'Access token',
  'auth.identityLabel': 'Signed in as',
  'auth.sessionEnds': 'ends {{time}}'
};

function sessionView(overrides) {
  return Object.assign({
    authenticated: false,
    methods: {
      realms: ['system', 'token'],
      system: { enabled: true, available: true, default_user: 'root' },
      token: { enabled: true, available: true }
    },
    transport: { secure: true, loopback: false }
  }, overrides || {});
}

function signedIn(name, realm) {
  return sessionView({
    authenticated: true,
    identity: { realm, user: realm === 'system' ? name.split('@')[0] : '', name, via: 'session' },
    csrf_token: 'csrf-123',
    session: { issued_at: '2026-11-20T10:00:00Z', expires_at: '2026-11-20T22:00:00Z', idle_timeout_seconds: 1800 }
  });
}

function createHarness(options) {
  const opts = options || {};
  const storage = new Map(Object.entries(opts.storage || {}));
  const documentListeners = {};
  const document = {
    activeElement: null,
    addEventListener(type, handler) { (documentListeners[type] = documentListeners[type] || []).push(handler); }
  };
  const elements = {};
  elementIds.forEach((id) => { elements[id] = createElement(document, id); });
  elements.loginRealmSystem.dataset.realm = 'system';
  elements.loginRealmToken.dataset.realm = 'token';
  const requests = [];
  const calls = { init: 0, notify: [] };
  const app = {
    $: (id) => elements[id] || null,
    el: { appRoot: elements.app },
    state: { locale: 'en-US' },
    t(key, params) {
      let text = Object.prototype.hasOwnProperty.call(dictionary, key) ? dictionary[key] : key;
      if (params) text = text.replace(/\{\{(\w+)\}\}/g, (_, name) => String(params[name]));
      return text;
    },
    init() { calls.init += 1; },
    stopPolling() {},
    closeDropdowns() {},
    notify(type, message) { calls.notify.push({ type, message }); },
    confirmAction: async () => true,
    clearPluginAdminToken() { calls.pluginAdminCleared = true; }
  };
  const context = vm.createContext({
    window: { VeerApp: app, location: { host: 'router.example:8889' } },
    document,
    localStorage: {
      getItem(key) { return storage.has(key) ? storage.get(key) : null; },
      setItem(key, value) { storage.set(key, String(value)); },
      removeItem(key) { storage.delete(key); }
    },
    async fetch(url, init) {
      const request = Object.assign({ url, method: 'GET' }, init || {});
      if (request.body) request.json = JSON.parse(request.body);
      requests.push(request);
      return opts.respond(request, requests.length);
    },
    Date,
    Number,
    JSON,
    Promise,
    Error,
    String,
    Object
  });
  vm.runInContext(authSource, context, { filename: 'auth.js' });
  return { app, elements, storage, requests, calls, document, documentListeners };
}

test('a token saved by the old panel is exchanged for a session and deleted', async () => {
  const h = createHarness({
    storage: { veer_token: 'legacy-token', forward_token: 'legacy-token' },
    respond(request) {
      assert.equal(request.url, '/api/auth/login');
      return jsonResponse(200, signedIn('token', 'token'));
    }
  });
  assert.equal(await h.app.restoreSession(), true);
  assert.equal(h.requests.length, 1);
  assert.deepEqual(h.requests[0].json, { realm: 'token', token: 'legacy-token' });
  assert.equal(h.requests[0].credentials, 'same-origin');
  assert.equal(h.storage.has('veer_token'), false);
  assert.equal(h.storage.has('forward_token'), false);
  assert.equal(h.app.isAuthenticated(), true);
  assert.equal(h.app.state.session.csrf, 'csrf-123');
  assert.equal(h.elements.sessionIdentity.hidden, false);
  assert.equal(h.elements.sessionIdentityName.textContent, 'token');
});

test('a rejected saved token is deleted and the sign-in form says why', async () => {
  const h = createHarness({
    storage: { forward_token: 'stale' },
    respond(request) {
      if (request.url === '/api/auth/login') return jsonResponse(401, { code: 'invalid_credentials' });
      return jsonResponse(200, sessionView());
    }
  });
  assert.equal(await h.app.restoreSession(), false);
  assert.equal(h.storage.has('forward_token'), false);
  assert.equal(h.elements.tokenModal.classList.contains('active'), true);
  assert.equal(h.elements.loginStatus.textContent, 'saved-token-rejected');
  assert.equal(h.elements.loginStatus.hidden, false);
  // System accounts are available, so they are offered first, with root.
  assert.equal(h.app.state.loginRealm, 'system');
  assert.equal(h.elements.loginUsername.value, 'root');
  assert.equal(h.document.activeElement, h.elements.loginPassword);
});

test('a saved token survives a failed exchange that proves nothing', async () => {
  const h = createHarness({
    storage: { veer_token: 'keep-me' },
    respond(request) {
      if (request.url === '/api/auth/login') throw new Error('offline');
      return jsonResponse(200, sessionView());
    }
  });
  assert.equal(await h.app.restoreSession(), false);
  assert.equal(h.storage.get('veer_token'), 'keep-me');
});

test('writes carry the CSRF token and background polls do not keep the session alive', async () => {
  const h = createHarness({ respond: () => jsonResponse(200, signedIn('root@system', 'system')) });
  await h.app.restoreSession();
  assert.equal(h.app.authHeaders('GET', {})['X-Veer-CSRF'], undefined);
  assert.equal(h.app.authHeaders('POST', {})['X-Veer-CSRF'], 'csrf-123');
  assert.equal(h.app.authHeaders('DELETE', { A: '1' }).A, '1');
  assert.equal(h.app.authHeaders('GET', {}, { background: true })['X-Veer-Background'], '1');
  // A key press makes the next poll count as activity, once.
  h.app.state.activityReportedAt = Date.now() - 5000;
  for (const handler of h.documentListeners.keydown) handler({});
  assert.equal(h.app.authHeaders('GET', {}, { background: true })['X-Veer-Background'], undefined);
  assert.equal(h.app.authHeaders('GET', {}, { background: true })['X-Veer-Background'], '1');
});

test('an expired session returns to the sign-in form with the reason', async () => {
  let session = true;
  const h = createHarness({
    respond(request) {
      if (request.url === '/api/auth/session') return jsonResponse(200, session ? signedIn('root@system', 'system') : sessionView());
      return jsonResponse(401, {}, { 'X-Veer-Auth-Reason': 'session_idle' });
    }
  });
  await h.app.restoreSession();
  session = false;
  await assert.rejects(h.app.authFetch('/api/rules', { method: 'GET' }), /unauthorized/);
  assert.equal(h.app.isAuthenticated(), false);
  assert.equal(h.elements.tokenModal.classList.contains('active'), true);
  assert.equal(h.elements.loginStatus.textContent, 'idle-ended');
  assert.equal(h.elements.sessionIdentity.hidden, true);
  assert.equal(h.elements.app.style.display, 'none');
});

test('system accounts are greyed out with the reason when the connection is not secure', async () => {
  const h = createHarness({
    respond: () => jsonResponse(200, sessionView({
      methods: {
        realms: ['system', 'token'],
        system: { enabled: true, available: false, reason: 'insecure_channel', default_user: 'root' },
        token: { enabled: true, available: true }
      },
      transport: { secure: false, loopback: false }
    }))
  });
  assert.equal(await h.app.restoreSession(), false);
  assert.equal(h.app.state.loginRealm, 'token');
  assert.equal(h.elements.loginRealmSystem.disabled, true);
  assert.equal(h.elements.loginRealmToken.getAttribute('aria-pressed'), 'true');
  assert.equal(h.elements.loginRealmNote.textContent, 'needs-https');
  assert.equal(h.elements.loginNotice.textContent, 'plaintext');
  assert.equal(h.elements.loginSystemFields.hidden, true);
  assert.equal(h.elements.loginTokenFields.hidden, false);
  // The greyed-out option cannot be selected.
  await h.elements.loginRealmSystem.dispatch('click');
  assert.equal(h.app.state.loginRealm, 'token');
});

test('signing in with a system account starts the dashboard', async () => {
  const h = createHarness({
    respond(request) {
      if (request.url === '/api/auth/session') return jsonResponse(200, sessionView());
      if (request.json.password === 'secret') return jsonResponse(200, signedIn('alice@system', 'system'));
      if (request.json.password === 'slow') return jsonResponse(429, { code: 'rate_limited' }, { 'Retry-After': '42' });
      return jsonResponse(401, { code: 'invalid_credentials' });
    }
  });
  await h.app.restoreSession();
  h.elements.loginUsername.value = 'alice';
  h.elements.loginPassword.value = '';
  await h.elements.loginForm.dispatch('submit');
  assert.equal(h.elements.loginError.textContent, 'need-password');
  assert.equal(h.requests.length, 1);

  h.elements.loginPassword.value = 'wrong';
  await h.elements.loginForm.dispatch('submit');
  assert.equal(h.elements.loginError.textContent, 'bad-password');
  assert.equal(h.elements.loginPassword.value, '');

  h.elements.loginPassword.value = 'slow';
  await h.elements.loginForm.dispatch('submit');
  assert.equal(h.elements.loginError.textContent, 'slow-down 42');

  h.elements.loginPassword.value = 'secret';
  await h.elements.loginForm.dispatch('submit');
  const login = h.requests[h.requests.length - 1];
  assert.deepEqual(login.json, { realm: 'system', username: 'alice', password: 'secret' });
  assert.equal(h.calls.init, 1);
  assert.equal(h.elements.tokenModal.classList.contains('active'), false);
  assert.equal(h.elements.loginPassword.value, '');
  assert.equal(h.storage.get('veer_login_realm'), 'system');
  assert.equal(h.elements.sessionIdentityName.textContent, 'alice@system');
  assert.match(h.elements.sessionIdentity.title, /Signed in as alice@system · System account · ends /);
});

test('signing out ends the session on the server and forgets local credentials', async () => {
  const h = createHarness({
    storage: { veer_token: 'old' },
    respond(request) {
      if (request.url === '/api/auth/login') return jsonResponse(200, signedIn('root@system', 'system'));
      if (request.url === '/api/auth/logout') return jsonResponse(200, { ok: true });
      return jsonResponse(200, sessionView());
    }
  });
  await h.app.restoreSession();
  await h.elements.logoutBtn.dispatch('click');
  const logout = h.requests.find((request) => request.url === '/api/auth/logout');
  assert.equal(logout.method, 'POST');
  assert.equal(logout.headers['X-Veer-CSRF'], 'csrf-123');
  assert.equal(h.app.isAuthenticated(), false);
  assert.equal(h.calls.pluginAdminCleared, true);
  assert.equal(h.elements.tokenModal.classList.contains('active'), true);
  assert.equal(h.elements.loginStatus.textContent, 'signed-out');
  assert.equal(h.storage.has('veer_token'), false);
});
