const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createClassList() {
  const values = new Set();
  return {
    add(name) { values.add(name); },
    remove(name) { values.delete(name); },
    toggle(name, force) {
      const enabled = force === undefined ? !values.has(name) : !!force;
      if (enabled) values.add(name);
      else values.delete(name);
      return enabled;
    },
    contains(name) { return values.has(name); }
  };
}

function createNode(id, extra) {
  return Object.assign({
    id,
    hidden: false,
    disabled: false,
    textContent: '',
    value: '',
    checked: false,
    style: {},
    dataset: {},
    attributes: {},
    classList: createClassList(),
    childNodes: [],
    tagName: 'DIV',
    isConnected: true,
    appendChild(child) { this.childNodes.push(child); return child; },
    remove() { this.removed = true; },
    focus() { this.focused = true; },
    addEventListener() {},
    removeEventListener() {},
    querySelector() { return null; },
    querySelectorAll() { return []; },
    setAttribute(name, value) { this.attributes[name] = String(value); },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null; },
    removeAttribute(name) { delete this.attributes[name]; },
    getBoundingClientRect() { return { left: 0, right: 0, top: 0, bottom: 0, width: 0, height: 0 }; }
  }, extra || {});
}

function createDiagnosticsHarness(savedTab) {
  const storage = Object.create(null);
  if (savedTab) storage.forward_active_tab = savedTab;
  const nodes = Object.create(null);
  const ensure = (id) => {
    if (!nodes[id]) nodes[id] = createNode(id);
    return nodes[id];
  };
  const tabs = ['rules', 'diagnostics'].map((tab) => createNode('tab-' + tab + '-button', {
    dataset: { tab },
    tagName: 'BUTTON'
  }));
  const panels = ['rules', 'diagnostics'].map((tab) => ensure('tab-' + tab));

  const app = {
    el: {},
    state: {
      rules: { data: [] },
      sites: { data: [] },
      ranges: { data: [] },
      managedNetworks: { data: [] },
      managedNetworkReservationCandidates: { data: [] },
      managedNetworkReservations: { data: [] },
      egressNATs: { data: [] },
      ipv6Assignments: { data: [] },
      workers: { data: [] },
      ruleStats: { data: [] },
      siteStats: { data: [] },
      rangeStats: { data: [] },
      egressNATStats: { data: [] }
    },
    storageKeys: {},
    $(id) { return ensure(id); },
    t(key) { return key; },
    renderRulesTable() {},
    renderSitesTable() {},
    renderRangesTable() {},
    renderManagedNetworksTable() {},
    renderManagedNetworkReservationCandidatesTable() {},
    renderManagedNetworkReservationsTable() {},
    renderEgressNATsTable() {},
    renderIPv6AssignmentsTable() {},
    renderWorkersTable() {},
    renderRuleStatsTable() {},
    renderSiteStatsTable() {},
    renderRangeStatsTable() {},
    renderEgressNATStatsTable() {},
    renderOverview() {},
    hasActiveFilters() { return false; },
    hasTableViewChanges() { return false; },
    closeDropdowns() {},
    getToken() { return 'token'; },
    stopPolling() {},
    formatClock(value) { return String(value); }
  };

  const documentRef = {
    hidden: false,
    activeElement: null,
    documentElement: { clientWidth: 1024, clientHeight: 768 },
    querySelector(selector) {
      const match = /^\.tab\[data-tab="(.+)"\]$/.exec(selector);
      if (!match) return null;
      return tabs.find((tab) => tab.dataset.tab === match[1]) || null;
    },
    querySelectorAll(selector) {
      if (selector === '.tab') return tabs;
      if (selector === '.tab-content') return panels;
      return [];
    },
    createElement(tag) { return createNode('', { tagName: String(tag || '').toUpperCase() }); },
    addEventListener() {},
    removeEventListener() {}
  };

  const context = vm.createContext({
    window: {
      VeerApp: app,
      innerWidth: 1024,
      innerHeight: 768,
      setInterval() { return 1; },
      clearInterval() {},
      setTimeout(fn) { if (typeof fn === 'function') fn(); return 1; },
      addEventListener() {},
      removeEventListener() {}
    },
    document: documentRef,
    localStorage: {
      getItem(key) { return Object.prototype.hasOwnProperty.call(storage, key) ? storage[key] : null; },
      setItem(key, value) { storage[key] = String(value); }
    },
    requestAnimationFrame(fn) { if (typeof fn === 'function') fn(); },
    console
  });

  const uiPath = path.join(__dirname, '..', 'web', 'js', 'ui.js');
  vm.runInContext(fs.readFileSync(uiPath, 'utf8'), context, { filename: uiPath });

  return { app, tabs, panels, storage };
}

test('ui migrates removed worker and stats tabs to diagnostics', () => {
  for (const oldTab of ['workers', 'rule-stats']) {
    const { app } = createDiagnosticsHarness(oldTab);
    assert.equal(app.state.activeTab, 'diagnostics');
  }
});

test('missing plugin resource records do not count as dashboard sync failures', () => {
  const { app } = createDiagnosticsHarness('rules');
  const recordPath = '/api/plugins/router_wizard/resources/config/default';
  app.state.requestFailures['GET ' + recordPath] = {
    key: 'GET ' + recordPath,
    path: recordPath,
    message: 'record not found',
    at: Date.now()
  };
  const error = new Error('record not found');
  error.status = 404;
  error.payload = { error: 'record not found' };

  app.recordRequestFailure('GET', recordPath, error);

  assert.deepEqual(Object.keys(app.state.requestFailures), []);
});

test('plugin collection and endpoint failures still count as dashboard sync failures', () => {
  const { app } = createDiagnosticsHarness('rules');
  const missingRecord = new Error('record not found');
  missingRecord.status = 404;
  missingRecord.payload = { error: 'record not found' };
  const missingPlugin = new Error('plugin not found');
  missingPlugin.status = 404;
  missingPlugin.payload = { error: 'plugin not found' };

  app.recordRequestFailure('GET', '/api/plugins/router_wizard/resources/config', missingRecord);
  app.recordRequestFailure('GET', '/api/plugins/router_wizard/resources/config/default', missingPlugin);

  assert.deepEqual(
    Object.keys(app.state.requestFailures).sort(),
    [
      'GET /api/plugins/router_wizard/resources/config',
      'GET /api/plugins/router_wizard/resources/config/default'
    ]
  );
});

test('activateTab loads diagnostics workers and stats', () => {
  const { app, storage } = createDiagnosticsHarness('rules');
  let workerLoads = 0;
  let statsLoads = 0;
  app.loadWorkers = function loadWorkers() { workerLoads += 1; };
  app.loadAllStats = function loadAllStats() { statsLoads += 1; };

  app.activateTab('diagnostics');

  assert.equal(app.state.activeTab, 'diagnostics');
  assert.equal(storage.forward_active_tab, 'diagnostics');
  assert.equal(workerLoads, 1);
  assert.equal(statsLoads, 1);
});

test('refreshDashboard only loads the active fixed tab', async () => {
  const { app } = createDiagnosticsHarness('rules');
  const calls = [];
  app.loadRules = () => { calls.push('rules'); };
  app.loadSites = () => { calls.push('sites'); };
  app.loadWorkers = () => { calls.push('workers'); };
  app.loadAllStats = () => { calls.push('stats'); };

  await app.refreshDashboard({ activeTabOnly: true, activeTab: 'rules' });

  assert.deepEqual(calls, ['rules']);
});

test('managed network tab refresh includes related data and switch context', async () => {
  const { app } = createDiagnosticsHarness('rules');
  const calls = [];
  app.loadManagedNetworks = () => { calls.push('networks'); };
  app.loadManagedNetworkReservations = () => { calls.push('reservations'); };
  app.loadHostNetwork = () => { calls.push('host-network'); };

  await app.refreshDashboard({
    activeTabOnly: true,
    activeTab: 'managed-networks',
    includeContext: true
  });

  assert.deepEqual(calls, ['networks', 'reservations', 'host-network']);
});

test('dynamic plugin tab refreshes plugin runtime state without reloading all pages', async () => {
  const { app } = createDiagnosticsHarness('rules');
  const calls = [];
  app.loadPlugins = () => { calls.push('plugins'); };
  app.loadRules = () => { calls.push('rules'); };

  await app.refreshDashboard({ activeTabOnly: true, activeTab: 'plugin-observe' });

  assert.deepEqual(calls, ['plugins']);
});

test('activateTab hides overview outside main data pages', () => {
  const { app } = createDiagnosticsHarness('rules');

  app.activateTab('rules');
  assert.equal(app.el.overviewPanel.hidden, false);

  app.activateTab('diagnostics');
  assert.equal(app.el.overviewPanel.hidden, true);
});
