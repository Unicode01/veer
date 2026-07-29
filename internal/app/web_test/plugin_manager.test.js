const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function makeNode(tagName) {
  const classes = new Set();
  const listeners = {};
  const node = {
    tagName: String(tagName || 'div').toUpperCase(),
    className: '',
    textContent: '',
    title: '',
    hidden: false,
    disabled: false,
    checked: false,
    value: '',
    files: [],
    style: {},
    dataset: {},
    attributes: {},
    childNodes: [],
    parentNode: null,
    scrollTop: 0,
    classList: {
      add(...names) {
        names.filter(Boolean).forEach((name) => classes.add(String(name)));
        node.className = Array.from(classes).join(' ');
      },
      remove(...names) {
        names.forEach((name) => classes.delete(String(name)));
        node.className = Array.from(classes).join(' ');
      },
      contains(name) {
        return classes.has(String(name));
      },
      toggle(name, force) {
        const enabled = force === undefined ? !classes.has(String(name)) : !!force;
        if (enabled) classes.add(String(name));
        else classes.delete(String(name));
        node.className = Array.from(classes).join(' ');
        return enabled;
      }
    },
    appendChild(child) {
      if (!child) return child;
      child.parentNode = node;
      node.childNodes.push(child);
      return child;
    },
    removeChild(child) {
      const index = node.childNodes.indexOf(child);
      if (index >= 0) node.childNodes.splice(index, 1);
      child.parentNode = null;
      return child;
    },
    setAttribute(name, value) {
      node.attributes[String(name)] = value === true ? '' : String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(node.attributes, name) ? node.attributes[name] : null;
    },
    addEventListener(type, handler) {
      if (!listeners[type]) listeners[type] = [];
      listeners[type].push(handler);
    },
    async dispatch(type, event = {}) {
      const handlers = listeners[type] || [];
      for (const handler of handlers) await handler(Object.assign({ target: node, preventDefault() {} }, event));
    },
    querySelector() {
      return null;
    },
    querySelectorAll() {
      return [];
    },
    focus() {},
    contains(target) {
      return target === node || node.childNodes.some((child) => child.contains && child.contains(target));
    }
  };
  Object.defineProperty(node, 'firstChild', {
    get() {
      return node.childNodes[0] || null;
    }
  });
  return node;
}

function createHarness() {
  const calls = [];
  const notifications = [];
  const confirmations = [];
  const elements = {
    confirmModal: makeNode('div'),
    pluginManagerModal: makeNode('div'),
    pluginManagerTitle: makeNode('h2'),
    pluginManagerMeta: makeNode('p'),
    pluginManagerNav: makeNode('div'),
    pluginManagerBody: makeNode('div'),
    closePluginManagerBtn: makeNode('button'),
    addPluginBtn: makeNode('button'),
    managePluginsAdvancedBtn: makeNode('button')
  };
  let apiHandler = async () => ({});
  let rawHandler = async () => ({ ok: true, status: 201, statusText: 'Created', json: async () => ({}) });
  let confirmResult = true;
	let pluginAdminToken = 'test-plugin-admin';
  const documentListeners = {};
  const document = {
    activeElement: null,
    createElement: makeNode,
    createTextNode(text) {
      const node = makeNode('#text');
      node.textContent = String(text || '');
      return node;
    },
    addEventListener(type, handler) {
      if (!documentListeners[type]) documentListeners[type] = [];
      documentListeners[type].push(handler);
    }
  };
  const app = {
    __enablePluginTests: true,
    el: elements,
    state: {
      locale: 'en-US',
      activeRequests: 0,
      plugins: {
        data: [{
          id: 'demo',
          name: 'Demo',
          version: '1.0.0',
          status: 'active',
          stability: 'stable',
          kind: 'control',
          source: 'plugins/demo',
          runtime: {
            mode: 'control',
            attachment_count: 0,
            control_health: { status: 'healthy', calls: 2, failures: 0 },
            worker_queue: { pending_requests: 0, request_limit: 256 },
            event_bus: { delivered: 1, dropped: 0 }
          }
        }],
        manager: {
          open: false,
          view: '',
          pluginID: '',
          tab: '',
          busy: false,
          stage: null,
          trustKeys: [],
          auditLogs: [],
          history: [],
          logs: null,
          secrets: null
        }
      }
    },
    t(key, params) {
      let text = String(key);
      Object.keys(params || {}).forEach((name) => {
        text = text.replaceAll('{{' + name + '}}', String(params[name] == null ? '' : params[name]));
      });
      return text;
    },
    createNode(tagName, options = {}) {
      const node = makeNode(tagName);
      if (options.className) {
        String(options.className).split(/\s+/).filter(Boolean).forEach((name) => node.classList.add(name));
      }
      if (options.text != null) node.textContent = String(options.text);
      if (options.title) node.title = String(options.title);
      Object.entries(options.attrs || {}).forEach(([name, value]) => {
        if (value == null || value === false) return;
        node.setAttribute(name, value === true ? '' : String(value));
      });
      Object.entries(options.dataset || {}).forEach(([name, value]) => {
        if (value != null) node.dataset[name] = String(value);
      });
      if (options.disabled) node.disabled = true;
      this.appendNodeContent(node, options.children);
      return node;
    },
    appendNodeContent(parent, content) {
      if (content == null || content === false) return;
      if (Array.isArray(content)) {
        content.forEach((item) => this.appendNodeContent(parent, item));
        return;
      }
      if (typeof content === 'string' || typeof content === 'number') {
        parent.appendChild(document.createTextNode(content));
        return;
      }
      parent.appendChild(content);
    },
    clearNode(node) {
      while (node && node.firstChild) node.removeChild(node.firstChild);
    },
    createCell(content) {
      const cell = makeNode('td');
      this.appendNodeContent(cell, content);
      return cell;
    },
    formatBytes(value) {
      return String(Number(value || 0)) + ' B';
    },
    getToken() {
      return 'test-token';
    },
	getPluginAdminToken() {
	  return pluginAdminToken;
	},
	setPluginAdminToken(value) {
	  pluginAdminToken = String(value || '').trim();
	},
	clearPluginAdminToken() {
	  pluginAdminToken = '';
	},
    clearToken() {
      this.clearedToken = true;
    },
    showTokenModal() {
      this.showedTokenModal = true;
    },
    renderOverview() {},
    renderPluginsTable() {
      this.renderedPlugins = true;
    },
    async loadPlugins() {
      this.loadedPlugins = true;
    },
    async apiCall(method, requestPath, body) {
      calls.push({ method, path: requestPath, body });
      return apiHandler(method, requestPath, body);
    },
	async pluginAdminAPICall(method, requestPath, body) {
	  calls.push({ method, path: requestPath, body, pluginAdminToken });
	  return apiHandler(method, requestPath, body);
	},
    async confirmAction(options) {
      confirmations.push(options || {});
      return confirmResult;
    },
    notify(type, message) {
      notifications.push({ type, message });
    },
    refreshLocalizedUI() {}
  };

  const context = vm.createContext({
    window: {
      VeerApp: app,
      setTimeout(fn) {
        if (typeof fn === 'function') fn();
      }
    },
    document,
    fetch: (...args) => rawHandler(...args),
    console,
    Intl,
    Date,
    JSON,
    URL,
    encodeURIComponent
  });
  const source = fs.readFileSync(path.join(__dirname, '..', 'web', 'js', 'plugin_manager.js'), 'utf8');
  vm.runInContext(source, context, { filename: 'plugin_manager.js' });
  app.__calls = calls;
  app.__notifications = notifications;
  app.__confirmations = confirmations;
  app.__setAPIHandler = (handler) => { apiHandler = handler; };
  app.__setRawHandler = (handler) => { rawHandler = handler; };
  app.__setConfirmResult = (value) => { confirmResult = value; };
  app.__documentListeners = documentListeners;
  return app;
}

function descendantText(node) {
  if (!node) return '';
  return [node.textContent, node.title].concat((node.childNodes || []).map(descendantText)).filter(Boolean).join(' ');
}

function findDescendant(node, predicate) {
  if (!node) return null;
  if (predicate(node)) return node;
  for (const child of node.childNodes || []) {
    const found = findDescendant(child, predicate);
    if (found) return found;
  }
  return null;
}

function stagedPackage(overrides = {}) {
  return Object.assign({
    id: '0123456789abcdef0123456789abcdef',
    plugin_id: 'demo',
    name: 'Demo',
    version: '2.0.0',
    existing_version: '1.0.0',
    archive_sha256: 'a'.repeat(64),
		trusted: false,
		signed: false,
		publisher_status: 'none',
		stability: 'stable',
    privilege_digest: 'b'.repeat(64),
    privilege_additions: ['permission:net.admin'],
    permissions: ['net.admin'],
    dependencies: [],
    conflicts: [],
    affected_plugins: [],
    expires_at: '2026-07-15T00:00:00Z',
    runtime_surface: { objects: [], hooks: [], resources: [], actions: [] }
  }, overrides);
}

function plain(value) {
  return JSON.parse(JSON.stringify(value));
}

test('package staging sends one self-contained package without detached signature headers', async () => {
  const app = createHarness();
  const stage = stagedPackage({ trusted: true, signed: true, privilege_additions: [] });
	const packageFile = { type: 'application/zip', name: 'demo.veerpkg' };
  let rawRequest;
  app.__setRawHandler(async (requestPath, options) => {
    rawRequest = { path: requestPath, options };
    return { ok: true, status: 201, statusText: 'Created', json: async () => stage };
  });
  app.openPluginManager('install');
	const result = await app.stagePluginPackage(packageFile);

  assert.equal(result.plugin_id, 'demo');
  assert.equal(rawRequest.path, '/api/plugin-packages/stage');
  assert.equal(rawRequest.options.method, 'POST');
	assert.equal(rawRequest.options.body, packageFile);
  assert.equal(rawRequest.options.headers.Authorization, 'Bearer test-token');
	assert.equal(rawRequest.options.headers['X-Veer-Plugin-Admin'], 'test-plugin-admin');
	assert.equal(rawRequest.options.headers['Content-Type'], 'application/zip');
	assert.equal(rawRequest.options.headers['X-Veer-Plugin-Signer'], undefined);
	assert.equal(rawRequest.options.headers['X-Veer-Plugin-Public-Key'], undefined);
	assert.equal(rawRequest.options.headers['X-Veer-Plugin-Signature'], undefined);
  assert.equal(app.state.plugins.manager.busy, false);
  assert.equal(app.state.plugins.manager.stage.id, stage.id);
});

test('plugin admin access status uses the session-scoped admin request path', async () => {
	const app = createHarness();
	app.__setAPIHandler(async (method, requestPath) => {
		assert.equal(method, 'GET');
		assert.equal(requestPath, '/api/plugin-admin/status');
		return { configured: true, authorized: true };
	});
	app.openPluginManager('access');
	await new Promise((resolve) => setImmediate(resolve));
	assert.equal(app.__calls[0].pluginAdminToken, 'test-plugin-admin');
	assert.equal(app.state.plugins.manager.adminStatus.authorized, true);
	const tokenInput = findDescendant(app.el.pluginManagerBody, (node) => node.attributes.type === 'password');
	assert.ok(tokenInput);
	assert.equal(tokenInput.attributes.name, 'veer-plugin-admin-token');
	assert.equal(tokenInput.attributes.autocomplete, 'new-password');
	assert.equal(tokenInput.attributes['data-1p-ignore'], 'true');
	assert.equal(tokenInput.attributes['data-lpignore'], 'true');
	assert.equal(tokenInput.attributes['data-bwignore'], 'true');
});

test('batch staging accepts mixed signed and unsigned package files without sidecar matching', async () => {
  const app = createHarness();
	const packages = [
	{ type: 'application/zip', name: 'dependency.veerpkg' },
	{ type: 'application/gzip', name: 'consumer.tar.gz' }
  ];
  const rawCalls = [];
  app.__setRawHandler(async (requestPath, options) => {
    rawCalls.push({ path: requestPath, options });
	const dependency = options.body.name === 'dependency.veerpkg';
    return {
      ok: true,
      status: 201,
      statusText: 'Created',
      json: async () => stagedPackage({
        id: dependency ? '1'.repeat(32) : '2'.repeat(32),
        plugin_id: dependency ? 'dependency' : 'consumer',
        trusted: true,
        signed: true,
        privilege_additions: []
      })
    };
  });
  app.openPluginManager('install');
	const stages = await app.stagePluginPackages(packages);

  assert.equal(stages.length, 2);
  assert.equal(rawCalls.length, 2);
  assert.ok(rawCalls.every((call) => call.path === '/api/plugin-packages/stage?defer_relationships=true'));
	assert.deepEqual(rawCalls.map((call) => call.options.body.name), ['dependency.veerpkg', 'consumer.tar.gz']);
	assert.ok(rawCalls.every((call) => !call.options.headers['X-Veer-Plugin-Signature']));
  assert.equal(app.state.plugins.manager.stage, null);
  assert.equal(app.state.plugins.manager.stages.length, 2);
});

test('staged package approval only blocks unsigned policy and privilege expansion', () => {
	const app = createHarness();
	const stage = stagedPackage();
	assert.equal(app.__pluginManagerStageApprovedForTest(stage, {}), false);
	assert.equal(app.__pluginManagerStageApprovedForTest(stage, { approvePrivileges: true }), true);
	assert.equal(app.__pluginManagerStageApprovedForTest(stagedPackage({ signed: true, publisher_status: 'unknown', privilege_additions: [] }), {}), true);
	assert.equal(app.__pluginManagerStageApprovedForTest(stagedPackage({ trusted: true, privilege_additions: [] }), {}), true);
});

test('signed-package policy cannot be bypassed by unsigned approval', () => {
  const app = createHarness();
  app.state.plugins.catalog = { runtime: { require_signed_packages: true } };
  const stage = stagedPackage({ privilege_additions: [] });
	assert.equal(app.__pluginManagerStageApprovedForTest(stage, {}), false);
	assert.equal(app.__pluginManagerStageApprovedForTest(stagedPackage({ signed: true, publisher_status: 'unknown', privilege_additions: [] }), {}), true);
  assert.equal(app.__pluginManagerStageApprovedForTest(stagedPackage({ trusted: true, privilege_additions: [] }), {}), true);
});

test('package apply submits stage digest and explicit unsigned approval', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'install';
  state.stage = stagedPackage();
	state.approvePrivileges = true;
  app.__setAPIHandler(async (method, requestPath) => {
    assert.equal(method, 'POST');
    assert.equal(requestPath, '/api/plugin-packages/apply');
    return { plugin_id: 'demo', catalog: { plugins: [{ id: 'demo', version: '2.0.0' }] } };
  });

  await app.applyStagedPluginPackage();
  const call = app.__calls[0];
  assert.deepEqual(plain(call.body), {
    stage_id: state.stage.id,
    approved_privilege_digest: state.stage.privilege_digest,
		approve_unsigned: true,
		approve_publisher: false,
		remember_publisher: false
  });
  assert.equal(app.state.plugins.data[0].version, '2.0.0');
	assert.equal(app.state.plugins.manager.open, false);
});

test('first-seen signed publisher can install once or be remembered from review', async () => {
	const app = createHarness();
	const state = app.state.plugins.manager;
	state.open = true;
	state.view = 'install';
	state.stage = stagedPackage({
		signed: true,
		trusted: false,
		publisher_status: 'unknown',
		signer_id: 'c'.repeat(32),
		signer_public_key: 'publisher-key',
		privilege_additions: []
	});
	state.rememberPublishers = true;
	app.__setAPIHandler(async () => ({ plugin_id: 'demo', catalog: { plugins: [] } }));

	await app.applyStagedPluginPackage();
	assert.deepEqual(plain(app.__calls[0].body), {
		stage_id: state.stage.id,
		approved_privilege_digest: '',
		approve_unsigned: false,
		approve_publisher: true,
		remember_publisher: true
	});
});

test('first-seen publisher review shows inline warning and optional ongoing trust', () => {
	const app = createHarness();
	const state = app.state.plugins.manager;
	state.open = true;
	state.view = 'install';
	state.stage = stagedPackage({
		signed: true,
		trusted: false,
		publisher_status: 'unknown',
		signer_id: 'd'.repeat(32),
		privilege_additions: []
	});
	app.__pluginManagerRenderStageForTest();
	const text = descendantText(app.el.pluginManagerBody);
	assert.match(text, /plugins\.package\.publisherUnknownWarning/);
	assert.match(text, /plugins\.package\.rememberPublisher/);
	assert.doesNotMatch(text, /plugins\.package\.unsignedBlocked/);
});

test('batch apply submits per-stage approvals to the atomic endpoint', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'install';
  state.stage = null;
  state.stages = [
    stagedPackage({ id: '1'.repeat(32), plugin_id: 'dependency' }),
    stagedPackage({ id: '2'.repeat(32), plugin_id: 'consumer', trusted: true, privilege_additions: [] })
  ];
	state.approvePrivileges = true;
  app.__setAPIHandler(async (method, requestPath) => {
    assert.equal(method, 'POST');
    assert.equal(requestPath, '/api/plugin-packages/apply-batch');
    return { operation: 'batch_apply', plugins: [], catalog: { plugins: [] } };
  });

  await app.applyStagedPluginPackages();
  assert.deepEqual(plain(app.__calls[0].body), {
    stages: [
			{ stage_id: '1'.repeat(32), approved_privilege_digest: 'b'.repeat(64), approve_unsigned: true, approve_publisher: false, remember_publisher: false },
			{ stage_id: '2'.repeat(32), approved_privilege_digest: '', approve_unsigned: false, approve_publisher: false, remember_publisher: false }
		]
	});
  assert.equal(app.state.plugins.manager.open, false);
});

test('repository manager loads only the selected catalog and renders provenance warnings', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'repositories';
  const repositories = [
    { id: 'repo_a', name: 'Repository A', channel: 'stable', target_count: 1 },
    { id: 'repo_b', name: 'Repository B', channel: 'preview', target_count: 1 }
  ];
  app.__setAPIHandler(async (method, requestPath) => {
    assert.equal(method, 'GET');
    if (requestPath === '/api/plugin-repositories') return repositories;
    if (requestPath === '/api/plugin-packages/provenance') {
      return [{ plugin_id: 'demo', version: '1.0.0', status: 'revoked', revocation_reason: 'security advisory' }];
    }
	if (requestPath === '/api/plugin-repository-policies') return [];
	if (requestPath === '/api/plugin-repositories/updates') return [];
    if (requestPath === '/api/plugin-repositories/catalog?repository_id=repo_a') {
      return { repository_id: 'repo_a', targets: [{ plugin_id: 'demo', name: 'Demo', version: '2.0.0', channel: 'stable' }] };
    }
    throw new Error('unexpected request ' + requestPath);
  });

  await app.__pluginManagerLoadRepositoriesForTest();
  assert.equal(state.selectedRepositoryID, 'repo_a');
  assert.equal(state.repositoryCatalog.repository_id, 'repo_a');
  assert.equal(app.__calls.filter((call) => call.path.includes('/catalog?')).length, 1);
  assert.ok(!app.__calls.some((call) => call.path.includes('repository_id=repo_b')));
  const text = descendantText(app.el.pluginManagerBody);
  assert.match(text, /plugins\.repository\.provenanceWarning/);
  assert.match(text, /security advisory/);
});

test('repository policy removal requires confirmation before deleting', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'repositories';
  state.repositories = [{ id: 'repo', name: 'Repository', channel: 'stable', target_count: 1 }];
  state.selectedRepositoryID = 'repo';
  state.repositoryPolicies = [{ plugin_id: 'demo', repository_id: 'repo', channel: 'stable', pinned_version: '1.0.0', hold: true }];
  state.repositoryUpdates = [{ plugin_id: 'demo', current_version: '1.0.0', status: 'held' }];
  state.repositoryPolicyPluginID = 'demo';
  state.repositoryCatalog = { repository_id: 'repo', targets: [] };
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (method === 'DELETE' && requestPath === '/api/plugin-repository-policies') {
      assert.deepEqual(plain(body), { plugin_id: 'demo' });
      return { status: 'deleted' };
    }
    if (method === 'GET' && requestPath === '/api/plugin-repositories') return state.repositories;
    if (method === 'GET' && requestPath === '/api/plugin-packages/provenance') return [];
    if (method === 'GET' && requestPath === '/api/plugin-repository-policies') return [];
    if (method === 'GET' && requestPath === '/api/plugin-repositories/updates') return [];
    if (method === 'GET' && requestPath === '/api/plugin-repositories/catalog?repository_id=repo') return { repository_id: 'repo', targets: [] };
    throw new Error('unexpected request ' + method + ' ' + requestPath);
  });

  app.refreshLocalizedUI();
  const remove = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'BUTTON' && node.textContent === 'plugins.repository.policy.remove');
  assert.ok(remove, 'policy remove button should be rendered');

  app.__setConfirmResult(false);
  await remove.dispatch('click');
  assert.equal(app.__calls.length, 0);
  assert.equal(app.__confirmations.length, 1);
  assert.equal(app.__confirmations[0].danger, true);

  app.__setConfirmResult(true);
  await remove.dispatch('click');
  assert.equal(app.__calls[0].method, 'DELETE');
  assert.equal(app.__notifications.at(-1).type, 'success');
});

test('repository dependency plan enters the existing atomic approval flow', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'repositories';
  const target = { plugin_id: 'repo_root', name: 'Repository Root', version: '2.0.0', channel: 'stable', dependencies: [{ id: 'repo_dep' }] };
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (method === 'GET' && requestPath === '/api/plugin-repositories') return [{ id: 'repo', name: 'Repository', channel: 'stable', target_count: 1 }];
    if (method === 'GET' && requestPath === '/api/plugin-packages/provenance') return [];
	if (method === 'GET' && requestPath === '/api/plugin-repository-policies') return [];
	if (method === 'GET' && requestPath === '/api/plugin-repositories/updates') return [];
    if (method === 'GET' && requestPath === '/api/plugin-repositories/catalog?repository_id=repo') return { repository_id: 'repo', targets: [target] };
    if (method === 'POST' && requestPath === '/api/plugin-repositories/plan') {
      assert.deepEqual(plain(body), { repository_id: 'repo', plugin_id: 'repo_root', version: '2.0.0' });
      return {
        repository_id: 'repo',
        requested_plugin_id: 'repo_root',
        reused: [{ plugin_id: 'already_here', version: '1.0.0' }],
        stages: [
          stagedPackage({ id: '1'.repeat(32), plugin_id: 'repo_dep', name: 'Dependency', trusted: true, privilege_additions: [], deferred_relationships: true }),
          stagedPackage({ id: '2'.repeat(32), plugin_id: 'repo_root', name: 'Repository Root', trusted: true, deferred_relationships: true })
        ]
      };
    }
    throw new Error('unexpected request ' + method + ' ' + requestPath);
  });

  await app.__pluginManagerLoadRepositoriesForTest();
  const prepare = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'BUTTON' && node.textContent === 'plugins.repository.prepare');
  assert.ok(prepare, 'prepare button should be rendered');
  await prepare.dispatch('click');
  assert.equal(state.view, 'install');
  assert.equal(state.installReturnView, 'repositories');
  assert.equal(state.stages.length, 2);
  assert.match(descendantText(app.el.pluginManagerBody), /already_here 1\.0\.0/);
});

test('trust key add and delete use the management API and refresh the list', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'trust';
  const key = { id: 'd'.repeat(32), name: 'Publisher', public_key: 'e'.repeat(44), created_at: '2026-07-14T00:00:00Z' };
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (method === 'POST') {
      assert.deepEqual(plain(body), { name: 'Publisher', public_key: key.public_key });
      return key;
    }
    if (method === 'DELETE') {
      assert.deepEqual(plain(body), { id: key.id });
      return { status: 'deleted' };
    }
    if (method === 'GET') return method === 'GET' && app.__calls.some((call) => call.method === 'DELETE') ? [] : [key];
    throw new Error('unexpected request');
  });

  await app.addPluginTrustKey('Publisher', key.public_key);
  assert.equal(state.trustKeys.length, 1);
  await app.deletePluginTrustKey(key);
  assert.equal(state.trustKeys.length, 0);
  assert.deepEqual(app.__calls.map((call) => call.method), ['POST', 'GET', 'DELETE', 'GET']);
});

test('trust key add sends normalized publisher scope', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'trust';
  const key = {
    id: 'a'.repeat(32),
    name: 'Scoped Publisher',
    public_key: 'b'.repeat(44),
    scope: {
      plugin_ids: ['vendor_*'],
      permissions: ['plugin.register', 'ui'],
      execution_tiers: ['control'],
      stabilities: ['preview', 'stable']
    }
  };
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (method === 'POST' && requestPath === '/api/plugin-trust') {
      assert.deepEqual(plain(body), {
        name: key.name,
        public_key: key.public_key,
        scope: key.scope
      });
      return key;
    }
    if (method === 'GET' && requestPath === '/api/plugin-trust') return [key];
    throw new Error('unexpected request ' + method + ' ' + requestPath);
  });

  await app.addPluginTrustKey(key.name, key.public_key, '', key.scope);
  assert.equal(state.trustKeys.length, 1);
  assert.deepEqual(plain(state.trustKeys[0].scope), key.scope);
});

test('publisher management lists remembered keys without a manual add form', async () => {
	const app = createHarness();
	app.__setAPIHandler(async (method, requestPath) => {
		assert.equal(method, 'GET');
		assert.equal(requestPath, '/api/plugin-trust');
		return [];
	});
	app.openPluginManager('trust');
	await new Promise((resolve) => setImmediate(resolve));
	const text = descendantText(app.el.pluginManagerBody);
	assert.match(text, /plugins\.trust\.empty/);
	assert.doesNotMatch(text, /plugins\.trust\.addTitle/);
});

test('publisher management collapses and paginates revoked history', async () => {
	const app = createHarness();
	const state = app.state.plugins.manager;
	const revoked = Array.from({ length: 25 }, (_, index) => {
		const number = index + 1;
		return {
			id: 'revoked-' + String(number).padStart(2, '0'),
			name: 'Revoked ' + String(number).padStart(2, '0'),
			public_key: 'key-' + number,
			status: 'revoked',
			created_at: '2026-06-01T00:00:00Z',
			revoked_at: '2026-07-' + String(number).padStart(2, '0') + 'T00:00:00Z'
		};
	});
	app.__setAPIHandler(async (method, requestPath) => {
		assert.equal(method, 'GET');
		assert.equal(requestPath, '/api/plugin-trust');
		return [{
			id: 'active-key', name: 'Active Publisher', public_key: 'active-public-key',
			status: 'active', created_at: '2026-07-25T00:00:00Z'
		}].concat(revoked);
	});

	app.openPluginManager('trust');
	await new Promise((resolve) => setImmediate(resolve));

	let text = descendantText(app.el.pluginManagerBody);
	let history = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'DETAILS');
	assert.match(text, /Active Publisher/);
	assert.match(text, /Revoked 25/);
	assert.doesNotMatch(text, /Revoked 15/);
	assert.ok(history);
	assert.equal(history.open, false);

	history.open = true;
	await history.dispatch('toggle');
	const next = findDescendant(history, (node) => node.tagName === 'BUTTON' && node.textContent === 'pagination.next');
	assert.ok(next);
	await next.dispatch('click');

	text = descendantText(app.el.pluginManagerBody);
	history = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'DETAILS');
	assert.equal(state.trustRevokedPage, 2);
	assert.match(text, /Revoked 15/);
	assert.doesNotMatch(text, /Revoked 25/);
	assert.equal(history.open, true);
});

test('audit view filters by plugin and paginates with before_id', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'audit';
  state.auditPluginID = 'demo';
  const firstPage = Array.from({ length: 50 }, (_, index) => ({
    id: 100 - index,
    plugin_id: 'demo',
    operation: 'package.stage',
    outcome: 'success',
    details: {},
    created_at: '2026-07-14T00:00:00Z'
  }));
  app.__setAPIHandler(async (_method, requestPath) => {
    if (requestPath.includes('before_id=')) return { logs: [{ id: 49, plugin_id: 'demo', operation: 'older', outcome: 'success', details: {} }] };
    return { logs: firstPage };
  });

  await app.__pluginManagerLoadAuditForTest(false);
  assert.equal(state.auditLogs.length, 50);
  assert.equal(state.auditHasMore, true);
  await app.__pluginManagerLoadAuditForTest(true);
  assert.equal(state.auditLogs.length, 51);
  assert.match(app.__calls[0].path, /plugin_id=demo/);
  assert.match(app.__calls[1].path, /before_id=51/);
});

test('dead-letter manager lists retries and discards durable deliveries', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'dead-letters';
  const first = {
    id: 2,
    delivery_id: '1'.repeat(32),
    target_plugin: 'demo',
    source_plugin: 'source',
    topic: 'plugin.source.changed',
    attempts: 2,
    max_attempts: 2,
    status: 'dead',
    last_error: 'handler failed'
  };
  const second = Object.assign({}, first, { id: 1, delivery_id: '2'.repeat(32) });
  let deadLetters = [first, second];
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (method === 'GET' && requestPath === '/api/plugin-event-dead-letters?limit=100') return deadLetters;
    if (method === 'POST' && requestPath === '/api/plugin-event-dead-letters/retry') {
      assert.deepEqual(plain(body), { plugin_id: 'demo', delivery_id: first.delivery_id });
      deadLetters = [second];
      return Object.assign({}, first, { status: 'pending' });
    }
    if (method === 'POST' && requestPath === '/api/plugin-event-dead-letters/discard') {
      assert.deepEqual(plain(body), { plugin_id: 'demo', delivery_id: second.delivery_id });
      deadLetters = [];
      return { discarded: true };
    }
    throw new Error('unexpected request ' + method + ' ' + requestPath);
  });

  await app.__pluginManagerLoadDeadLettersForTest(false);
  const retry = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'BUTTON' && node.textContent === 'plugins.deadLetters.retry');
  assert.ok(retry, 'retry button should be rendered');
  await retry.dispatch('click');
  const discard = findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'BUTTON' && node.textContent === 'plugins.deadLetters.discard');
  assert.ok(discard, 'discard button should be rendered');
  await discard.dispatch('click');
  assert.equal(state.deadLetters.length, 0);
  assert.ok(app.__calls.some((call) => call.path === '/api/plugin-event-dead-letters/retry'));
  assert.ok(app.__calls.some((call) => call.path === '/api/plugin-event-dead-letters/discard'));
});

test('secret status and rotation preserve only public keyring metadata', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'secrets';
  app.__setAPIHandler(async (method, requestPath) => {
    if (method === 'GET') {
      assert.equal(requestPath, '/api/plugin-secrets');
      return { available: true, persistent: true, active_key: 'a'.repeat(32), key_count: 1 };
    }
    assert.equal(requestPath, '/api/plugin-secrets');
    return { active_key: 'b'.repeat(32), rotated_at: '2026-07-14T01:00:00Z' };
  });

  await app.__pluginManagerLoadSecretsForTest();
  assert.equal(state.secrets.active_key, 'a'.repeat(32));
  await app.rotatePluginSecrets();
  assert.equal(state.secrets.active_key, 'b'.repeat(32));
  assert.deepEqual(app.__calls.map((call) => [call.method, call.path]), [
    ['GET', '/api/plugin-secrets'],
    ['POST', '/api/plugin-secrets']
  ]);
});

test('rollback and uninstall preserve staged approval and destructive flags', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'plugin';
  state.pluginID = 'demo';
  state.tab = 'history';
  const rollbackStage = stagedPackage({ trusted: true, history_id: 'history-id', privilege_additions: [] });
  app.__setAPIHandler(async (method, requestPath, body) => {
    if (requestPath === '/api/plugin-packages/rollback') return rollbackStage;
    if (requestPath === '/api/plugin-packages/uninstall') return { operation: 'uninstall', plugin_id: body.plugin_id };
    throw new Error('unexpected request');
  });

  await app.preparePluginRollback('demo', 'history-id');
  assert.equal(state.view, 'install');
  assert.equal(state.stage.history_id, 'history-id');
  assert.deepEqual(plain(app.__calls[0].body), { plugin_id: 'demo', history_id: 'history-id' });

  state.view = 'plugin';
  state.pluginID = 'demo';
  await app.uninstallPluginPackage('demo', { purgeData: true, force: true });
  assert.deepEqual(plain(app.__calls[1].body), { plugin_id: 'demo', force: true, purge_data: true });
  assert.equal(app.loadedPlugins, true);
  assert.equal(state.open, false);
});

test('history and log loaders use bounded plugin-scoped endpoints', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'plugin';
  state.pluginID = 'demo';
  state.tab = 'history';
  app.__setAPIHandler(async (_method, requestPath) => {
    if (requestPath.includes('/history')) return [{ id: 'history', version: '0.9.0' }];
    return { plugin_id: 'demo', logs: [], state: { entries: 0, dropped: 0 } };
  });
  await app.__pluginManagerLoadHistoryForTest('demo');
  assert.equal(state.history.length, 1);
  state.tab = 'logs';
  state.logLevel = 'error';
  await app.__pluginManagerLoadLogsForTest('demo');
  assert.equal(app.__calls[0].path, '/api/plugin-packages/history?plugin_id=demo');
  assert.equal(app.__calls[1].path, '/api/plugins/demo/logs?limit=200&level=error');
});

test('mutating operations lock modal dismissal and authentication closes it forcibly', () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  app.openPluginManager('install');
  state.busy = true;
  app.openPluginManager('install');
  state.busy = true;
  assert.equal(app.closePluginManager(), false);
  assert.equal(state.open, true);
  app.showTokenModal();
  assert.equal(state.open, false);
  assert.equal(app.showedTokenModal, true);
});

test('plugin manager ignores escape while a confirmation modal is active', () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  app.openPluginManager('secrets');
  app.el.confirmModal.classList.add('active');
  const handler = app.__documentListeners.keydown[0];
  assert.equal(typeof handler, 'function');
  handler({key: 'Escape', preventDefault() {}});
  assert.equal(state.open, true);

  app.el.confirmModal.classList.remove('active');
  handler({key: 'Escape', preventDefault() {}});
  assert.equal(state.open, false);
});

test('plugin manager keeps routine navigation separate from advanced operations', async () => {
  const app = createHarness();
  await app.el.managePluginsAdvancedBtn.dispatch('click');

  assert.equal(app.state.plugins.manager.view, 'advanced');
  const navText = descendantText(app.el.pluginManagerNav);
  assert.match(navText, /plugins\.catalog\.add/);
  assert.match(navText, /plugins\.manager\.advanced/);
  assert.doesNotMatch(navText, /plugins\.trust\.title|plugins\.audit\.title|plugins\.secrets\.title/);

  const bodyText = descendantText(app.el.pluginManagerBody);
  assert.doesNotMatch(bodyText, /plugins\.package\.install|plugins\.repository\.title/);
  assert.match(bodyText, /plugins\.trust\.title/);
  assert.match(bodyText, /plugins\.audit\.title/);
  assert.match(bodyText, /plugins\.deadLetters\.title/);
  assert.match(bodyText, /plugins\.secrets\.title/);
  assert.match(bodyText, /plugins\.admin\.title/);
});

test('add plugin opens local package installation without loading a repository', async () => {
  const app = createHarness();
  await app.el.addPluginBtn.dispatch('click');

  assert.equal(app.state.plugins.manager.view, 'install');
  const text = descendantText(app.el.pluginManagerBody);
	assert.match(text, /plugins\.package\.archive/);
	assert.doesNotMatch(text, /plugins\.package\.signature/);
	const packageInput = findDescendant(app.el.pluginManagerBody, (node) => node.attributes.type === 'file');
	assert.ok(packageInput);
	assert.match(packageInput.attributes.accept, /\.veerpkg/);
	assert.doesNotMatch(packageInput.attributes.accept, /\.sig/);
  assert.doesNotMatch(text, /plugins\.repository\.metadataURL|plugins\.repository\.targetsURL|plugins\.repository\.root/);
  assert.deepEqual(app.__calls, []);
});

test('plugin manager menu reserves persistent focus styling for keyboard focus', () => {
  const css = fs.readFileSync(path.join(__dirname, '..', 'web', 'css', 'tables.css'), 'utf8');
  assert.match(css, /\.plugin-manager-menu-item:hover,\s*\.plugin-manager-menu-item:focus-visible/);
  assert.doesNotMatch(css, /\.plugin-manager-menu-item:hover,\s*\.plugin-manager-menu-item:focus\s*\{/);
});

test('plugin overview exposes isolated host health and package probation', async () => {
  const app = createHarness();
  app.state.plugins.data[0].runtime.isolation = {
    enabled: true,
    platform: 'linux/amd64',
    process_count: 2,
    pids: [101, 202],
    restart_count: 3,
    rss_bytes: 4096,
    resource_limit_mode: 'cgroup_v2+rss',
    resource_limit_degraded: 'cgroup unavailable'
  };
  app.state.plugins.data[0].runtime.leases = [
    { type: 'net.link.state', key: 'host0/mtu' },
    { type: 'net.route', key: '0.0.0.0/0|host0|100|0' }
  ];
  app.state.plugins.data[0].runtime.operations = {
    total: 4,
    resumable: 2,
    bytes: 8192,
    by_status: { running: 2, completed: 2 }
  };
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'plugin';
  state.pluginID = 'demo';
  state.tab = 'overview';
  app.__setAPIHandler(async () => [{
    plugin_id: 'demo', version: '1.0.0', pending: false,
    started_at: '2026-07-14T00:00:00Z', expires_at: '2026-07-14T00:10:00Z',
    previous_history_id: 'history-1', unclean_starts: 0
  }]);
  await app.__pluginManagerLoadOverviewForTest('demo');
  const text = descendantText(app.el.pluginManagerBody);
  assert.ok(findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'SUMMARY' && node.textContent === 'plugins.manager.technicalDetails'));
  assert.ok(findDescendant(app.el.pluginManagerBody, (node) => node.tagName === 'SUMMARY' && node.textContent === 'plugins.manager.maintenance'));
  assert.match(text, /plugins\.manager\.isolation/);
  assert.match(text, /plugins\.manager\.hostProcesses/);
  assert.match(text, /2 \/ plugins\.manager\.restarts 3/);
  assert.match(text, /PID 101, 202/);
  assert.match(text, /cgroup unavailable/);
  assert.match(text, /plugins\.manager\.leases/);
  assert.match(text, /host0\/mtu/);
  assert.match(text, /plugins\.manager\.operations/);
  assert.match(text, /4 \/ plugins\.manager\.resumable 2/);
  assert.match(text, /running: 2/);
  assert.match(text, /plugins\.probation\.title/);
  assert.match(text, /plugins\.probation\.observing/);
  assert.match(text, /history-1/);
});

test('plugin overview exposes atomic probation group members', async () => {
  const app = createHarness();
  const state = app.state.plugins.manager;
  state.open = true;
  state.view = 'plugin';
  state.pluginID = 'demo';
  state.tab = 'overview';
  app.__setAPIHandler(async (method, requestPath) => {
    assert.equal(method, 'GET');
    if (requestPath.startsWith('/api/plugin-packages/probations?')) {
      return [{
        plugin_id: 'demo', version: '2.0.0', pending: false, group_id: 'a'.repeat(32),
        started_at: '2026-07-14T00:00:00Z', expires_at: '2026-07-14T00:10:00Z'
      }];
    }
    assert.equal(requestPath, '/api/plugin-packages/probation-groups?group_id=' + 'a'.repeat(32));
    return [{
      id: 'a'.repeat(32),
      members: [
        { plugin_id: 'demo', version: '2.0.0', operation: 'update' },
        { plugin_id: 'dependency', version: '2.0.0', operation: 'update' }
      ]
    }];
  });
  await app.__pluginManagerLoadOverviewForTest('demo');
  const text = descendantText(app.el.pluginManagerBody);
  assert.match(text, /plugins\.probation\.group/);
  assert.match(text, /plugins\.probation\.groupMeta/);
  assert.match(text, /dependency \/ 2\.0\.0 \/ update/);
});
