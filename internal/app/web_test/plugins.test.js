const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function makeNode(tagName, opts = {}) {
  const classes = new Set(String(opts.className || '').split(/\s+/).filter(Boolean));
  const node = {
    tagName: String(tagName || 'div').toUpperCase(),
    className: opts.className || '',
    textContent: opts.text || '',
    title: opts.title || '',
    attributes: {},
    dataset: Object.assign({}, opts.dataset || {}),
    hidden: false,
    style: {},
    childNodes: [],
    parentNode: null,
    contentWindow: opts.contentWindow || null,
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
      if (child.__isFragment) {
        child.childNodes.slice().forEach((grandchild) => node.appendChild(grandchild));
        child.childNodes = [];
        return child;
      }
      child.parentNode = node;
      node.childNodes.push(child);
      return child;
    },
    setAttribute(name, value) {
      node.attributes[String(name)] = value === true ? '' : String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(node.attributes, String(name)) ? node.attributes[String(name)] : null;
    },
    addEventListener() {},
    closest() {
      return makeNode('div');
    }
  };
  if (Array.isArray(opts.children)) opts.children.forEach((child) => node.appendChild(child));
  return node;
}

function appendNodeContent(parent, content) {
  if (content == null || content === false) return;
  if (Array.isArray(content)) {
    content.forEach((item) => appendNodeContent(parent, item));
    return;
  }
  if (typeof content === 'string' || typeof content === 'number') {
    parent.appendChild(makeNode('#text', { text: String(content) }));
    return;
  }
  parent.appendChild(content);
}

function collectText(node) {
  if (!node) return '';
  const parts = [];
  if (node.textContent) parts.push(String(node.textContent));
  (node.childNodes || []).forEach((child) => {
    const text = collectText(child);
    if (text) parts.push(text);
  });
  return parts.join(' ').trim();
}

function collectAttribute(node, name) {
  if (!node) return '';
  const parts = [];
  const value = node.attributes && node.attributes[name];
  if (value) parts.push(String(value));
  (node.childNodes || []).forEach((child) => {
    const text = collectAttribute(child, name);
    if (text) parts.push(text);
  });
  return parts.join('\n').trim();
}

function findNodes(node, predicate, out = []) {
  if (!node) return out;
  if (predicate(node)) out.push(node);
  (node.childNodes || []).forEach((child) => findNodes(child, predicate, out));
  return out;
}

function createHarness() {
  const notifications = [];
  const openedWindows = [];
  const windowListeners = {};
  const elements = {
    pluginsBody: makeNode('tbody'),
    noPlugins: makeNode('p'),
    pluginsCatalogMeta: makeNode('div'),
    pluginsChainMeta: makeNode('div'),
    pluginUIPanel: makeNode('section'),
    pluginUITitle: makeNode('h3'),
    pluginUIMeta: makeNode('p'),
    pluginUIFrame: makeNode('iframe'),
    pluginUpdateSelectionBar: makeNode('div'),
    pluginUpdateSelectionMeta: makeNode('span'),
    applyPluginUpdateBtn: makeNode('button'),
    pluginsPagination: makeNode('div')
  };
  const translations = {
    'common.actions': 'Actions',
    'common.dash': '-',
    'common.disable': 'Disable',
    'common.enable': 'Enable',
    'common.no': 'No',
    'common.noMatches': 'No matches.',
    'common.processing': 'Processing...',
    'common.status': 'Status',
    'common.yes': 'Yes',
    'errors.operationFailed': 'Operation failed: {{message}}',
    'noun.plugin': 'Plugin',
    'plugins.catalog.meta': 'External plugin directory: {{dir}}; external plugin scan: {{enabled}}; external dataplane attach: {{attach}}',
    'plugins.chain.empty': 'TC path: legacy fvtap fast path; no external plugins are chained around fvtap core.',
    'plugins.chain.meta': 'TC pipeline: {{chain}}',
    'plugins.chain.slot': 'slot {{slot}}',
    'plugins.chain.forwardPath': 'forward: {{chain}}',
    'plugins.chain.replyPath': 'reply: {{chain}}',
    'plugins.chain.preForward': 'pre_forward[{{chain}}]',
    'plugins.chain.core': 'fvtap core(priority={{priority}})',
    'plugins.chain.postLookup': 'post_lookup[{{chain}}]',
    'plugins.chain.apply': 'fvtap apply/redirect',
    'plugins.chain.preReply': 'pre_reply[{{chain}}]',
    'plugins.chain.replyCore': 'fvtap reply core(priority={{priority}})',
    'plugins.chain.postReply': 'post_reply[{{chain}}]',
    'plugins.chain.replyApply': 'fvtap reply rewrite',
    'plugins.empty': 'No plugins matched.',
    'plugins.error': 'Error',
    'plugins.details': 'Details',
    'plugins.open': 'Open',
    'plugins.openFailed': 'Open plugin UI failed: {{message}}',
    'plugins.opening': 'Loading plugin UI...',
    'plugins.popupBlocked': 'The browser blocked the plugin UI popup.',
    'plugins.catalog.title': 'Plugin Catalog',
    'plugins.catalog.dir': 'Dir',
    'plugins.catalog.scan': 'Scan',
    'plugins.catalog.dataplane': 'Dataplane',
    'plugins.catalog.registrationOnly': 'Register only',
    'plugins.catalog.registrationOnlyDetail': '{{engines}} is currently validated and displayed, but not attached as an external plugin hot-path engine.',
    'plugins.catalog.scanOn': 'Enabled',
    'plugins.catalog.scanOff': 'Off',
    'plugins.catalog.hotReload': 'Update monitor',
    'plugins.catalog.hotReloadDetail': 'Plugin update: {{status}}',
    'plugins.catalog.hotReloadIdle': 'Idle',
    'plugins.catalog.hotReloadWatching': 'Watching',
    'plugins.catalog.hotReloadReloaded': 'Applied',
    'plugins.catalog.hotReloadPartial': 'Partial',
    'plugins.catalog.hotReloadError': 'Error',
    'plugins.catalog.hotReloadOff': 'Off',
    'plugins.catalog.updateAvailable': 'Update available',
    'plugins.catalog.lastCheck': 'Checked',
    'plugins.catalog.lastReload': 'Applied',
    'plugins.catalog.fingerprint': 'Fingerprint',
    'plugins.catalog.appliedFingerprint': 'Applied',
    'plugins.catalog.detectedFingerprint': 'Pending',
    'plugins.update.apply': 'Apply Update',
    'plugins.update.applySelected': 'Apply Updates ({{count}})',
    'plugins.update.applying': 'Applying',
    'plugins.update.applied': 'Plugin update applied',
    'plugins.update.appliedSelected': 'Applied {{count}} plugin updates',
    'plugins.update.failed': 'Plugin update failed: {{message}}',
    'plugins.update.detail': 'Applied {{applied}}; pending {{detected}}',
    'plugins.update.selected': '{{count}} selected',
    'plugins.update.selectModified': 'Update',
    'plugins.update.selectAdded': 'Add',
    'plugins.update.selectRemoved': 'Remove',
    'plugins.update.rowDetail': 'Current {{applied}}; pending {{detected}}',
    'plugins.runtime.attachable': 'Attachable',
    'plugins.runtime.attached': 'Attached',
    'plugins.runtime.attachments': 'Attachments',
    'plugins.runtime.builtin': 'Built-in dataplane',
    'plugins.runtime.dataplane': 'Dataplane enabled',
    'plugins.runtime.disabled': 'Disabled',
    'plugins.runtime.error': 'Runtime error',
    'plugins.runtime.invalid': 'Validation failed',
    'plugins.runtime.registered': 'Registered',
    'plugins.source': 'Source',
    'plugins.status.active': 'Loaded',
    'plugins.status.builtin': 'Built-in',
    'plugins.status.disabled': 'Disabled',
    'plugins.status.error': 'Error',
    'plugins.status.pending': 'Pending add',
    'plugins.chain.title': 'TC Pipeline',
    'plugins.chain.legacy': 'legacy fvtap',
    'plugins.chain.none': 'No chain',
    'plugins.chain.chained': '{{count}} chained',
    'plugins.chain.preCompact': 'pre x{{count}}',
    'plugins.chain.coreCompact': 'core p{{priority}}',
    'plugins.chain.postCompact': 'post x{{count}}',
    'plugins.chain.applyCompact': 'apply',
    'plugins.chain.preReplyCompact': 'r-pre x{{count}}',
    'plugins.chain.replyCoreCompact': 'r-core p{{priority}}',
    'plugins.chain.postReplyCompact': 'r-post x{{count}}',
    'plugins.chain.replyApplyCompact': 'r-apply',
    'plugins.link.title': 'Plugin Dataplane Chains',
    'plugins.link.desc': 'Shows how this plugin is attached to the fvtap pipeline; the current plugin is highlighted.',
    'plugins.link.count': '{{count}} items',
    'plugins.link.interfaceChain': 'Interface Chain',
    'plugins.link.declaredChain': 'Declared Chain',
    'plugins.link.unbound': 'unbound',
    'plugins.link.current': 'Current plugin',
    'plugins.link.core': 'fvtap core',
    'plugins.link.apply': 'apply/rewrite',
    'plugins.link.coreCompact': 'core',
    'plugins.link.replyCoreCompact': 'r-core',
    'plugins.link.role': 'Role',
    'plugins.link.direction': 'Direction',
    'plugins.link.type': 'Type',
    'plugins.link.scope': 'Scope',
    'plugins.link.steps': 'Steps',
    'plugins.link.step': '#{{index}}',
    'plugins.link.stepIndex': 'Step',
    'plugins.link.flags': 'Flags',
    'plugins.link.node': 'Node',
    'plugins.ui.assets': 'Static Assets',
    'plugins.ui.emptyTitle': 'No Plugin Selected',
    'plugins.ui.loadedMeta': '{{id}} / {{entry}}',
    'toast.disabled': '{{item}} disabled.',
    'toast.enabled': '{{item}} enabled.'
  };

  const app = {
    el: elements,
    __enablePluginTests: true,
    state: {
      locale: 'zh-CN',
      activeRequests: 0,
      plugins: {
        data: [],
        catalog: null,
        sortKey: '',
        sortAsc: true,
        searchQuery: '',
        page: 1,
        pageSize: 10
      }
    },
    t(key, params) {
      let text = Object.prototype.hasOwnProperty.call(translations, key) ? translations[key] : key;
      if (!params) return text;
      return text.replace(/\{\{(\w+)\}\}/g, (_, name) => {
        if (!Object.prototype.hasOwnProperty.call(params, name)) return '';
        return params[name] == null ? '' : String(params[name]);
      });
    },
    createNode(tagName, opts = {}) {
      const node = makeNode(tagName, opts);
      if (opts.attrs) {
        Object.keys(opts.attrs).forEach((key) => {
          const value = opts.attrs[key];
          if (value == null || value === false) return;
          node.setAttribute(key, value === true ? '' : String(value));
        });
      }
      if (opts.dataset) node.dataset = Object.assign({}, opts.dataset);
      return node;
    },
    appendNodeContent,
    createBadgeNode(className, text, title) {
      return makeNode('span', { className: 'badge ' + String(className || ''), text: String(text || ''), title: title || '' });
    },
    createStatusBadgeNode(info, title) {
      return this.createBadgeNode('badge-' + info.badge, info.text, title || '');
    },
    createCell(content, className) {
      const node = makeNode('td', { className: className || '' });
      appendNodeContent(node, content);
      return node;
    },
    emptyCellNode(className) {
      return makeNode('span', { className: className || '', text: '-' });
    },
    clearNode(node) {
      if (node) node.childNodes = [];
    },
    matchesSearch(query, values) {
      const q = String(query || '').toLowerCase();
      return values.some((value) => String(value || '').toLowerCase().includes(q));
    },
    sortByState(list) {
      return list.slice();
    },
    paginateList(st, list) {
      return { items: list.slice(0, st.pageSize || 10) };
    },
    hasActiveFilters(st) {
      return !!(st && st.searchQuery);
    },
    updateSortIndicators() {},
    renderFilterMeta() {},
    renderPagination() {},
    updateEmptyState(node, state) {
      node.textContent = state.message || '';
      node.hidden = false;
    },
    hideEmptyState(node) {
      node.hidden = true;
    },
    toggleTableVisibility(tableId, visible) {
      this.lastTableVisibility = { tableId, visible };
    },
    getToken() {
      return 'test-token';
    },
    clearToken() {
      this.tokenCleared = true;
    },
    showTokenModal() {
      this.tokenModalShown = true;
    },
    notify(type, message) {
      notifications.push({ type, message });
    }
  };

  const context = vm.createContext({
    window: {
      ForwardApp: app,
      addEventListener(type, handler) {
        if (!windowListeners[type]) windowListeners[type] = [];
        windowListeners[type].push(handler);
      },
      setTimeout(fn) {
        if (typeof fn === 'function') fn();
      },
      open() {
        const child = {
          document: { title: '', body: { textContent: '' } },
          location: {
            href: '',
            replace(url) {
              this.href = url;
            }
          },
          closed: false,
          close() {
            this.closed = true;
          }
        };
        openedWindows.push(child);
        return child;
      }
    },
    document: {
      createElement(tagName) {
        return makeNode(tagName);
      },
      createDocumentFragment() {
        return {
          __isFragment: true,
          childNodes: [],
          appendChild(child) {
            this.childNodes.push(child);
            return child;
          }
        };
      },
      querySelectorAll(selector) {
        if (selector === 'iframe[data-plugin-frame="1"]') {
          return [elements.pluginUIFrame].filter((frame) => frame.dataset && frame.dataset.pluginFrame === '1');
        }
        return [];
      }
    },
    fetch: async () => ({ ok: false, status: 404, statusText: 'not found', headers: { get() { return ''; } }, text: async () => '' }),
    Blob: class TestBlob {
      constructor(parts, opts) {
        this.parts = parts;
        this.type = opts && opts.type || '';
        app.lastBlob = this;
      }
    },
    URL: {
      createObjectURL() {
        return 'blob:plugin-ui';
      },
      revokeObjectURL(url) {
        app.revokedBlobURL = url;
      }
    },
    console
  });

  const filePath = path.join(__dirname, '..', 'web', 'js', 'plugins.js');
  vm.runInContext(fs.readFileSync(filePath, 'utf8'), context, { filename: filePath });
  app.__context = context;
  app.__openedWindows = openedWindows;
  app.__notifications = notifications;
  app.__windowListeners = windowListeners;
  return app;
}

function extractForwardPluginHostScript(srcdoc) {
  const match = String(srcdoc || '').match(/<script data-forward-plugin-host>([\s\S]*?)<\/script>/);
  assert.ok(match, 'decorated plugin HTML should include ForwardPluginHost script');
  return match[1];
}

function attachPluginHostChildFrame(app) {
  const childListeners = {};
  let timerID = 0;
  const timers = new Map();
  let childWindow;
  const parentWindow = {
    postMessage(message) {
      const handlers = app.__windowListeners.message || [];
      handlers.forEach((handler) => handler({ source: childWindow, data: message }));
    }
  };
  childWindow = {
    parent: parentWindow,
    addEventListener(type, handler) {
      if (!childListeners[type]) childListeners[type] = [];
      childListeners[type].push(handler);
    },
    postMessage(message) {
      const handlers = childListeners.message || [];
      handlers.forEach((handler) => handler({ source: parentWindow, data: message }));
    },
    setTimeout(fn) {
      timerID += 1;
      timers.set(timerID, fn);
      return timerID;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    requestAnimationFrame(fn) {
      if (typeof fn === 'function') fn();
      return 1;
    },
    cancelAnimationFrame() {}
  };
  app.el.pluginUIFrame.contentWindow = childWindow;

  const childContext = vm.createContext({
    window: childWindow,
    document: {
      body: {
        classList: { add() {} },
        appendChild() {},
        scrollHeight: 0,
        offsetHeight: 0
      },
      documentElement: {
        scrollHeight: 0,
        offsetHeight: 0
      },
      addEventListener() {},
      createElement(tagName) {
        return makeNode(tagName);
      },
      createTextNode(text) {
        return makeNode('#text', { text: String(text || '') });
      },
      querySelector() {
        return null;
      }
    },
    Node: function TestNode() {},
    console
  });
  vm.runInContext(extractForwardPluginHostScript(app.el.pluginUIFrame.srcdoc), childContext, { filename: 'forward-plugin-host.js' });
  return childContext.window.ForwardPluginHost;
}

test('renderPluginsTable renders builtin and external plugin details', () => {
  const app = createHarness();
  app.state.plugins.catalog = {
    external_plugins_enabled: true,
    directory: 'plugins',
    runtime: { external_dataplane_attach: false, external_dataplane_engines: ['tc'], registration_only_engines: ['xdp'], core_priority: 1000 },
    hot_reload: {
      enabled: true,
      check_interval_ms: 2000,
      last_check_at: '2026-07-09T01:02:03Z',
      last_check_result: 'unchanged',
      last_reload_at: '2026-07-09T01:03:04Z',
      last_reload_source: 'manual',
      last_reload_result: 'success',
      catalog_fingerprint: 'abcdef1234567890',
      fingerprint_short_hash: 'abcdef123456',
      applied_fingerprint: 'abcdef1234567890',
      applied_fingerprint_short_hash: 'abcdef123456',
      detected_fingerprint: 'abcdef1234567890',
      detected_fingerprint_short_hash: 'abcdef123456'
    }
  };
  app.state.plugins.data = [
    {
      id: 'fvtap',
      status: 'builtin',
      runtime: { mode: 'builtin', attachable: true, attached: true },
      name: 'Forward Virtual Tap',
      kind: 'pipeline',
      version: 'builtin',
      capabilities: ['kernel_tc'],
      objects: [{ id: 'forward-tc', path: 'builtin:forward-tc' }],
      hooks: [{ id: 'tc-ingress', engine: 'tc', attach: 'ingress', stage: 'forward', priority: 1000, program: 'builtin:forward-tc', mode: 'rewrite' }]
    },
    {
      id: 'packet_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 1,
        attachments: [{ hook_id: 'observe-ingress', engine: 'tc', attach: 'ingress', stage: 'pre_forward', interface: 'fvtap', program: 'observer:tc_ingress', priority: 10, chain_slot: 10, status: 'chained' }]
      },
      name: 'Packet Observer',
      kind: 'pipeline',
      version: '0.1.0',
      capabilities: ['observe'],
      virtual_interfaces: [{ id: 'vtap0', type: 'logical' }],
      objects: [{ id: 'observer', path: 'observer.o', programs: [{ id: 'tc_ingress', section: 'tc/ingress', type: 'tc' }] }],
      hooks: [{ id: 'observe-ingress', engine: 'tc', attach: 'ingress', stage: 'forward', priority: 10, program: 'observer.o:tc_ingress', mode: 'observe', interfaces: ['fvtap'] }],
      ui: { entry: 'index.html' },
      asset_base_path: '/api/plugins/packet_observer/assets/'
    }
  ];

  app.renderPluginsTable();

  const text = collectText(app.el.pluginsBody);
  assert.match(text, /fvtap/);
  assert.match(text, /packet_observer/);
  assert.match(text, /Loaded/);
  assert.match(text, /Details/);
  assert.match(text, /Open/);
  assert.doesNotMatch(text, /objects=1/);
  const detailLabels = collectAttribute(app.el.pluginsBody, 'aria-label');
  assert.match(detailLabels, /Objects/i);
  assert.match(detailLabels, /Hooks/i);
  assert.match(detailLabels, /chain_slot=10/);
  const detailButtons = app.el.pluginsBody.childNodes
    .flatMap((row) => row.childNodes || [])
    .flatMap((cell) => cell.childNodes || [])
    .flatMap((node) => node.childNodes || [])
    .filter((node) => String(node.className || '').includes('plugin-detail-trigger'));
  assert.equal(detailButtons.length, 2);
  assert.deepEqual(detailButtons.map((node) => node.dataset.pluginId), ['fvtap', 'packet_observer']);
  const toggleButtons = findNodes(app.el.pluginsBody, (node) => String(node.className || '').includes('btn-toggle-plugin'));
  assert.equal(toggleButtons.length, 1);
  assert.equal(toggleButtons[0].dataset.pluginId, 'packet_observer');
  assert.equal(toggleButtons[0].dataset.enabled, '0');
  assert.equal(collectText(toggleButtons[0]), 'Disable');
  assert.match(collectText(app.el.pluginsCatalogMeta), /Plugin Catalog/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Dir plugins/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Dataplane No/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Register only XDP/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Update monitor Applied/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Applied abcdef123456/);
  assert.match(app.el.pluginsCatalogMeta.title, /Plugin update: Applied/);
  assert.match(collectText(app.el.pluginsChainMeta), /TC Pipeline/);
  assert.match(collectText(app.el.pluginsChainMeta), /1 chained/);
  assert.match(collectText(app.el.pluginsChainMeta), /pre x1/);
  assert.match(collectText(app.el.pluginsChainMeta), /core p1000/);
  assert.match(collectText(app.el.pluginsChainMeta), /apply/);
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: pre_forward[slot 10 packet_observer.observe-ingress (priority=10)] -> fvtap core(priority=1000) -> fvtap apply/redirect');
  assert.deepEqual(app.lastTableVisibility, { tableId: 'pluginsTable', visible: true });
});

test('plugin catalog exposes a pending update without applying it', () => {
  const app = createHarness();
  app.state.plugins.catalog = {
    external_plugins_enabled: true,
    directory: 'plugins',
    runtime: {},
    hot_reload: {
      enabled: true,
      update_available: true,
      last_check_result: 'update_available',
      applied_fingerprint: 'aaaaaaaaaaaaaaaa',
      applied_fingerprint_short_hash: 'aaaaaaaaaaaa',
      detected_fingerprint: 'bbbbbbbbbbbbbbbb',
      detected_fingerprint_short_hash: 'bbbbbbbbbbbb',
      updates: [{
        plugin_id: 'packet_observer',
        name: 'Packet Observer',
        kind: 'pipeline',
        change: 'modified',
        applied_version: '1.0.0',
        detected_version: '1.1.0'
      }]
    }
  };
  app.state.plugins.data = [{ id: 'packet_observer', name: 'Packet Observer', kind: 'pipeline', version: '1.0.0', status: 'active' }];

  app.renderPluginsTable();

  assert.equal(app.el.pluginUpdateSelectionBar.hidden, true);
  assert.equal(app.el.applyPluginUpdateBtn.hidden, true);
  const checkboxes = findNodes(app.el.pluginsBody, (node) => String(node.className || '').includes('plugin-update-checkbox'));
  assert.equal(checkboxes.length, 1);
  assert.equal(checkboxes[0].dataset.pluginId, 'packet_observer');
  const updateChoices = findNodes(app.el.pluginsBody, (node) => String(node.className || '').split(/\s+/).includes('plugin-update-choice'));
  assert.equal(updateChoices.length, 1);
  assert.equal(String(updateChoices[0].className).includes('is-selected'), false);
  assert.equal(findNodes(updateChoices[0], (node) => String(node.className || '').split(/\s+/).includes('plugin-update-check')).length, 1);
  assert.equal(findNodes(updateChoices[0], (node) => String(node.className || '').split(/\s+/).includes('plugin-update-choice-label')).length, 1);
  app.togglePluginUpdateSelection('packet_observer', true);
  const selectedChoices = findNodes(app.el.pluginsBody, (node) => String(node.className || '').split(/\s+/).includes('plugin-update-choice'));
  assert.equal(selectedChoices.length, 1);
  assert.equal(String(selectedChoices[0].className).includes('is-selected'), true);
  assert.equal(app.el.pluginUpdateSelectionBar.hidden, false);
  assert.equal(app.el.applyPluginUpdateBtn.hidden, false);
  assert.equal(app.el.applyPluginUpdateBtn.disabled, false);
  assert.equal(app.el.applyPluginUpdateBtn.textContent, 'Apply Updates (1)');
  assert.equal(app.el.applyPluginUpdateBtn.title, 'packet_observer');
  assert.equal(app.el.pluginUpdateSelectionMeta.textContent, '1 selected');
  assert.match(collectText(app.el.pluginsCatalogMeta), /Update monitor Update available/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Applied aaaaaaaaaaaa/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Pending bbbbbbbbbbbb/);
});

test('plugin catalog renders a pending addition as a selectable table row', () => {
  const app = createHarness();
  app.state.plugins.catalog = {
    external_plugins_enabled: true,
    directory: 'plugins',
    runtime: {},
    hot_reload: {
      enabled: true,
      update_available: true,
      updates: [{
        plugin_id: 'new_plugin',
        source: 'new_plugin',
        name: 'New Plugin',
        kind: 'control',
        change: 'added',
        detected_version: '1.0.0'
      }]
    }
  };

  app.renderPluginsTable();

  assert.match(collectText(app.el.pluginsBody), /new_plugin/);
  assert.match(collectText(app.el.pluginsBody), /Pending add/);
  assert.match(collectText(app.el.pluginsBody), /Add/);
  const checkboxes = findNodes(app.el.pluginsBody, (node) => String(node.className || '').includes('plugin-update-checkbox'));
  assert.equal(checkboxes.length, 1);
  assert.equal(checkboxes[0].dataset.pluginId, 'new_plugin');
  assert.equal(app.el.pluginUpdateSelectionBar.hidden, true);
});

test('plugin page panel creates its refresh control without row state dependencies', () => {
  const app = createHarness();
  const panel = app.__createPluginTabPanelForTest({
    tabID: 'plugin-observe',
    pluginID: 'packet_observer',
    title: 'Observe',
    entry: 'index.html'
  });
  const refresh = findNodes(panel, (node) => String(node.className || '').includes('btn-reload-plugin-page'));
  assert.equal(refresh.length, 1);
  assert.equal(refresh[0].dataset.pluginTab, 'plugin-observe');
});

test('applyPluginUpdate posts the pending catalog and reports completion', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.catalog = {
    external_plugins_enabled: true,
    directory: 'plugins',
    runtime: {},
    hot_reload: {
      enabled: true,
      update_available: true,
      updates: [{ plugin_id: 'packet_observer', change: 'modified', applied_version: '1.0.0', detected_version: '1.1.0' }]
    }
  };
  app.state.plugins.data = [{ id: 'packet_observer', name: 'Packet Observer', version: '1.0.0', status: 'active' }];
  app.apiCall = async (method, path, body) => {
    calls.push({ method, path, body });
    return {
      external_plugins_enabled: true,
      directory: 'plugins',
      runtime: {},
      hot_reload: { enabled: true, update_available: false, last_reload_result: 'success' },
      plugins: []
    };
  };

  app.renderPluginsTable();
  app.togglePluginUpdateSelection('packet_observer', true);
  await app.applyPluginUpdate();

  assert.deepEqual(JSON.parse(JSON.stringify(calls)), [{ method: 'POST', path: '/api/plugins/reload', body: { plugin_ids: ['packet_observer'] } }]);
  assert.equal(app.state.plugins.applyingUpdate, false);
  assert.equal(app.state.plugins.catalog.hot_reload.update_available, false);
  assert.equal(app.el.applyPluginUpdateBtn.hidden, true);
  assert.deepEqual(app.__notifications, [{ type: 'success', message: 'Applied 1 plugin updates' }]);
});

test('togglePluginEnabled updates persisted plugin state and refreshes catalog', async () => {
  const app = createHarness();
  const calls = [];
  let renderCount = 0;
  app.state.pendingRows = {};
  app.isRowPending = function isRowPending(type, id) {
    return !!app.state.pendingRows[type + ':' + id];
  };
  app.setRowPending = function setRowPending(type, id, pending) {
    const key = type + ':' + id;
    if (pending) app.state.pendingRows[key] = true;
    else delete app.state.pendingRows[key];
  };
  app.renderPluginsTable = function renderPluginsTableForToggleTest() {
    renderCount += 1;
  };
  app.apiCall = async function apiCall(method, reqPath, body) {
    calls.push({
      method,
      reqPath,
      body,
      pending: app.isRowPending('plugin', 'packet_observer')
    });
    return { plugin_id: 'packet_observer', enabled: body.enabled };
  };
  app.loadPlugins = async function loadPluginsForToggleTest() {
    calls.push({ method: 'LOAD_PLUGINS' });
  };

  await app.togglePluginEnabled('packet_observer', false);

  assert.deepEqual(JSON.parse(JSON.stringify(calls[0])), {
    method: 'PUT',
    reqPath: '/api/plugins/packet_observer/state',
    body: { enabled: false },
    pending: true
  });
  assert.deepEqual(calls[1], { method: 'LOAD_PLUGINS' });
  assert.equal(app.isRowPending('plugin', 'packet_observer'), false);
  assert.equal(renderCount, 2);
  assert.deepEqual(app.__notifications, [{ type: 'success', message: 'Plugin disabled.' }]);
});

test('renderPluginsTable applies plugin search filter', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: false, directory: 'plugins' };
  app.state.plugins.searchQuery = 'missing';
  app.state.plugins.data = [{ id: 'fvtap', status: 'builtin', name: 'Forward Virtual Tap' }];

  app.renderPluginsTable();

  assert.equal(app.el.pluginsBody.childNodes.length, 0);
  assert.equal(app.el.noPlugins.textContent, 'No matches.');
  assert.deepEqual(app.lastTableVisibility, { tableId: 'pluginsTable', visible: false });
});

test('renderPluginsTable places next-core chain entries after fvtap core', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  app.state.plugins.data = [
    { id: 'fvtap', status: 'builtin', name: 'Forward Virtual Tap', runtime: { mode: 'builtin', attachable: true, attached: true } },
    {
      id: 'rule_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 1,
        attachments: [{ hook_id: 'after-core', engine: 'tc', attach: 'ingress', stage: 'post_lookup', interface: 'fvtap', program: 'observer:tc_post_lookup', priority: 1010, chain_slot: 18, status: 'chained', context: ['tc_plugin_ctx_v4'] }]
      },
      name: 'Rule Observer'
    }
  ];

  app.renderPluginsTable();

  assert.match(collectText(app.el.pluginsChainMeta), /TC Pipeline/);
  assert.match(collectText(app.el.pluginsChainMeta), /1 chained/);
  assert.match(collectText(app.el.pluginsChainMeta), /post x1/);
  assert.match(collectText(app.el.pluginsChainMeta), /core p1000/);
  assert.match(collectAttribute(app.el.pluginsBody, 'aria-label'), /tc_plugin_ctx_v4/);
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: fvtap core(priority=1000) -> post_lookup[slot 18 rule_observer.after-core (priority=1010)] -> fvtap apply/redirect');
});

test('renderPluginsTable renders reply chain separately from forward chain', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  app.state.plugins.data = [
    { id: 'fvtap', status: 'builtin', name: 'Forward Virtual Tap', runtime: { mode: 'builtin', attachable: true, attached: true } },
    {
      id: 'reply_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 2,
        attachments: [
          { hook_id: 'before-reply', engine: 'tc', attach: 'ingress', stage: 'pre_reply', interface: 'fvtap', program: 'observer:tc_pre_reply', priority: 990, chain_slot: 29, status: 'chained' },
          { hook_id: 'after-reply', engine: 'tc', attach: 'ingress', stage: 'post_reply', interface: 'fvtap', program: 'observer:tc_post_reply', priority: 1010, chain_slot: 37, status: 'chained', context: ['tc_plugin_ctx_v4'] }
        ]
      },
      name: 'Reply Observer'
    }
  ];

  app.renderPluginsTable();

  const text = collectText(app.el.pluginsChainMeta);
  assert.match(text, /2 chained/);
  assert.match(text, /r-pre x1/);
  assert.match(text, /r-core p1000/);
  assert.match(text, /r-post x1/);
  assert.match(text, /r-apply/);
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: fvtap core(priority=1000) -> fvtap apply/redirect | reply: pre_reply[slot 29 reply_observer.before-reply (priority=990)] -> fvtap reply core(priority=1000) -> post_reply[slot 37 reply_observer.after-reply (priority=1010)] -> fvtap reply rewrite');
});

test('plugin dataplane link rows hide virtual-interface-only control plugins', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const controlOnly = {
    id: 'wan_core',
    name: 'WAN Core',
    kind: 'control',
    virtual_interfaces: [{ id: 'fwdwan0', type: 'veth', description: 'local WAN handoff' }]
  };
  const pppoe = {
    id: 'pppoe_client',
    name: 'PPPoE Client',
    kind: 'pipeline',
    hooks: [{ id: 'pppoe-forward', engine: 'tc', attach: 'ingress', stage: 'pre_forward', priority: 20, program: 'pppoe.o:tc_ingress', mode: 'rewrite', interfaces: ['eth1'] }]
  };
  app.state.plugins.data = [controlOnly, pppoe];

  assert.equal(app.__pluginLinkRowsForTest(controlOnly).length, 0);

  const rows = app.__pluginLinkRowsForTest(pppoe);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, 'Declared Chain');
  assert.equal(rows[0].label, 'TC ingress forward');
  assert.equal(rows[0].segments[0].text, 'eth1');
  const current = rows[0].segments.find((segment) => segment.current);
  assert.equal(current.text, 'pppoe_client');
  assert.equal(current.detailTitle, 'pppoe_client.pppoe-forward');
  assert.ok(current.detailRows.some((row) => row.label === 'Priority' && row.value === '20'));
  assert.ok(current.detailRows.some((row) => row.label === 'Interfaces' && row.value === 'eth1'));
  const core = rows[0].segments.find((segment) => segment.core);
  assert.equal(core.text, 'core');
  assert.ok(core.detailRows.some((row) => row.label === 'Priority' && row.value === '1000'));
  assert.ok(rows[0].segments.some((segment) => segment.apply && segment.text === 'apply'));

  const card = app.__createPluginLinkCardForTest({ plugin: pppoe });
  assert.doesNotMatch(collectText(card), /\bDetails\b/);
  const buttons = [];
  const walk = (node) => {
    if (!node) return;
    if (node.tagName === 'BUTTON') buttons.push(node);
    (node.childNodes || []).forEach(walk);
  };
  walk(card);
  assert.deepEqual(buttons.map((button) => button.textContent), ['eth1', 'pppoe_client', 'core', 'apply']);
});

test('plugin dataplane runtime link rows preserve bound hook interfaces', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const pppoe = {
    id: 'pppoe_client',
    name: 'PPPoE Client',
    kind: 'pipeline',
    hooks: [
      { id: 'pppoe-ingress', engine: 'tc', attach: 'ingress', stage: 'forward', priority: 20, interfaces: ['eth1'] },
      { id: 'pppoe-egress', engine: 'tc', attach: 'egress', stage: 'forward', priority: 20, interfaces: ['fwdlocal0'] }
    ],
    runtime: {
      mode: 'dataplane',
      attachments: [
        { hook_id: 'pppoe-ingress', engine: 'tc', attach: 'ingress', stage: 'pre_forward', interface: 'fvtap', priority: 20, chain_slot: 11, status: 'chained' },
        { hook_id: 'pppoe-egress', engine: 'tc', attach: 'egress', stage: 'pre_forward', interface: 'fvtap', priority: 20, chain_slot: 10, status: 'chained' }
      ]
    }
  };
  app.state.plugins.data = [pppoe];

  const rows = app.__pluginLinkRowsForTest(pppoe);
  assert.equal(rows.length, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(rows.map((row) => row.label).sort())), ['TC egress forward', 'TC ingress forward']);
  assert.deepEqual(JSON.parse(JSON.stringify(rows.map((row) => row.segments[0].text).sort())), ['eth1', 'fwdlocal0']);
  assert.ok(rows.every((row) => row.segments.some((segment) => segment.current && segment.text === 'pppoe_client')));
});

test('plugin dataplane link rows ignore registration-only xdp hooks', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const xdpOnly = {
    id: 'xdp_probe',
    name: 'XDP Probe',
    kind: 'pipeline',
    hooks: [{ id: 'xdp-ingress', engine: 'xdp', attach: 'ingress', stage: 'forward', priority: 20, program: 'probe:xdp_ingress', mode: 'observe', interfaces: ['eth0'] }],
    runtime: { mode: 'registered', attachable: false, attached: false, reason: 'xdp hooks are registration-only in the tc pipeline' }
  };
  app.state.plugins.data = [xdpOnly];

  assert.equal(app.__pluginLinkRowsForTest(xdpOnly).length, 0);
});

test('openPluginUI fetches protected asset and renders inline iframe', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch(url, opts) {
    calls.push({ url, authorization: opts.headers.Authorization });
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };

  await app.openPluginUI('packet_observer');

  assert.deepEqual(calls, [{
    url: '/api/plugins/packet_observer/assets/index.html',
    authorization: 'Bearer test-token'
  }]);
  assert.equal(app.__openedWindows.length, 0);
  assert.equal(app.el.pluginUIPanel.hidden, false);
  assert.equal(app.el.pluginUITitle.textContent, 'Packet Observer');
  assert.equal(app.el.pluginUIMeta.textContent, 'packet_observer / index.html');
  assert.equal(app.el.pluginUIFrame.src, 'about:blank');
  assert.equal(app.el.pluginUIFrame.getAttribute('sandbox'), 'allow-scripts allow-forms allow-popups');
  assert.match(String(app.el.pluginUIFrame.srcdoc), /data-forward-plugin-host/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /ForwardPluginHost/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.data/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /list: function \(resource, options\)/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /upsert: function \(resource, key, data, options\)/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /error\.status !== 404/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /limit: options\.limit/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /offset: options\.offset/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.action/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.errorText/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.toastError/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.t = function/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.onLocaleChange/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.recordPicker = function/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.collectionEditor = function/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.plugins = Object\.freeze/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /error_payload/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /runtime_status/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /runtime_error/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /clearTimeout\(pending\.timeout\)/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /event\.source !== window\.parent/);

  app.closePluginUI();

  assert.equal(app.el.pluginUIPanel.hidden, true);
});

test('plugin RPC data.list forwards pagination query params', () => {
  const filePath = path.join(__dirname, '..', 'web', 'js', 'plugins.js');
  const source = fs.readFileSync(filePath, 'utf8');
  assert.match(source, /payload\.limit/);
  assert.match(source, /payload\.offset/);
  assert.match(source, /limit=/);
  assert.match(source, /offset=/);
});

test('plugin host cross-plugin resource reads enforce manifest grants', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'lan_core',
    name: 'LAN Core',
    asset_base_path: '/api/plugins/lan_core/assets/',
    ui: { entry: 'index.html' },
    control: {
      resource_access: [{ plugin: 'wan_core', resource: 'status', methods: ['get', 'list'] }]
    }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>LAN Core</title>'
    };
  };
  app.apiCall = async function apiCall(method, reqPath) {
    calls.push({ method, reqPath });
    return { records: [{ key: 'wan-a', data: { phase: 'applied' } }] };
  };

  await app.openPluginUI('lan_core');
  const host = attachPluginHostChildFrame(app);
  const result = await host.plugins.resources.list('wan_core', 'status', { limit: 32, offset: 0 });
  assert.equal(result.records[0].key, 'wan-a');
  assert.deepEqual(calls, [{ method: 'GET', reqPath: '/api/plugins/wan_core/resources/status?limit=32&offset=0' }]);

  await assert.rejects(
    host.plugins.resources.list('pppoe_client', 'sessions', { limit: 32 }),
    /plugin resource access denied/
  );
  assert.equal(calls.length, 1);
});

test('core plugin pages use record pickers and structured route editors', () => {
  const pluginRoot = path.join(__dirname, '..', '..', '..', 'plugins');
  const wan = fs.readFileSync(path.join(pluginRoot, 'wan_core', 'ui', 'index.html'), 'utf8');
  const lan = fs.readFileSync(path.join(pluginRoot, 'lan_core', 'ui', 'index.html'), 'utf8');
  const local = fs.readFileSync(path.join(pluginRoot, 'vtolocal', 'ui', 'index.html'), 'utf8');
  const pppoe = fs.readFileSync(path.join(pluginRoot, 'pppoe_client', 'ui', 'index.html'), 'utf8');
  const router = fs.readFileSync(path.join(pluginRoot, 'router_wizard', 'ui', 'index.html'), 'utf8');

  assert.match(wan, /F\.recordPicker/);
  assert.match(wan, /F\.collectionEditor/);
  assert.match(wan, /wanProfileField\.hidden = profilePicker\.keys\(\)\.length <= 1/);
  assert.match(lan, /F\.recordPicker/);
  assert.match(lan, /lanProfileField\.hidden = lanPicker\.keys\(\)\.length <= 1/);
  assert.match(lan, /wanReferenceField\.hidden = wanPicker\.keys\(\)\.length <= 1/);
  assert.match(local, /F\.recordPicker/);
  assert.match(local, /F\.collectionEditor/);
  assert.match(pppoe, /const action = active \? 'disconnect' : 'dial'/);
  assert.match(pppoe, /setConfigurationLocked\(active \|\| redialing \|\| pending\)/);
  assert.match(pppoe, /stats\.push\(\.\.\.trafficStats\(data\)\)/);
  assert.doesNotMatch(pppoe, /'traffic\.title'/);
  assert.doesNotMatch(pppoe, /const trafficBody/);
  [wan, lan, local, router].forEach((source) => {
    assert.match(source, /F\.setButtonState/);
    assert.match(source, /'action\.update'/);
    assert.match(source, /tone: 'danger'/);
  });
  assert.doesNotMatch(wan, /Routes JSON/);
  assert.doesNotMatch(local, /Routes JSON/);
});

test('plugin table combines UI controls into a visible actions column', () => {
  const cssPath = path.join(__dirname, '..', 'web', 'css', 'tables.css');
  const source = fs.readFileSync(cssPath, 'utf8');
  const widths = new Map();
  const pattern = /#pluginsTable th:nth-child\((\d+)\),\s*#pluginsTable td:nth-child\(\1\)\s*\{\s*width:\s*(\d+)%/g;
  for (const match of source.matchAll(pattern)) {
    const column = Number(match[1]);
    if (!widths.has(column)) widths.set(column, Number(match[2]));
  }

  assert.equal(widths.size, 6);
  assert.equal(widths.get(6), 19);
  assert.equal(Array.from(widths.values()).reduce((sum, width) => sum + width, 0), 100);
  assert.match(source, /@media \(max-width: 720px\)[\s\S]*?#pluginsTable\s*\{\s*min-width:\s*880px/);
  assert.match(source, /@media \(max-width: 720px\)[\s\S]*?#pluginsTable th:nth-child\(6\),\s*#pluginsTable td:nth-child\(6\)\s*\{\s*width:\s*22%/);
});

test('router wizard apply keeps the previous saved config available for rollback', () => {
  const filePath = path.join(__dirname, '..', '..', '..', 'plugins', 'router_wizard', 'ui', 'index.html');
  const source = fs.readFileSync(filePath, 'utf8');
  const body = source.match(/async function applyRouter\(button\) \{([\s\S]*?)\n      \}/);
  assert.ok(body, 'applyRouter function should exist');
  assert.doesNotMatch(body[1], /saveConfig\s*\(/);
  assert.match(body[1], /F\.action\('apply_router'/);
});

test('router wizard renders recovery steps without a raw status dump', () => {
  const filePath = path.join(__dirname, '..', '..', '..', 'plugins', 'router_wizard', 'ui', 'index.html');
  const source = fs.readFileSync(filePath, 'utf8');

  assert.match(source, /lastStatus\.steps/);
  assert.match(source, /lastStatus\.rollback_steps/);
  assert.match(source, /lastStatus\.restore_steps/);
  assert.match(source, /lastStatus\.restore_rollback_steps/);
  assert.match(source, /appendStepGroup/);
  assert.doesNotMatch(source, /JSON\.stringify\(value \|\| \{\}, null, 2\)/);
  assert.doesNotMatch(source, /json\.raw/);
});

test('plugin host data.upsert only falls back to create on missing records', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);

  app.apiCall = async function apiCall(method, reqPath, body) {
    calls.push({ method, reqPath, body });
    if (method === 'PUT') {
      const error = new Error('record not found');
      error.status = 404;
      error.payload = { error: 'record not found' };
      throw error;
    }
    assert.equal(method, 'POST');
    return { key: 'alpha', data: body.data, enabled: body.enabled !== false };
  };

  const created = await host.data.upsert('bindings', 'alpha', { name: 'alpha' }, { enabled: true });
  assert.equal(created.key, 'alpha');
  assert.deepEqual(calls.map((call) => call.method), ['PUT', 'POST']);
  assert.equal(calls[0].reqPath, '/api/plugins/packet_observer/resources/bindings/alpha');
  assert.equal(calls[1].reqPath, '/api/plugins/packet_observer/resources/bindings');
  assert.deepEqual(JSON.parse(JSON.stringify(calls[1].body)), { data: { name: 'alpha' }, key: 'alpha', enabled: true });

  calls.length = 0;
  app.apiCall = async function apiCall(method, reqPath, body) {
    calls.push({ method, reqPath, body });
    const error = new Error('runtime apply failed');
    error.status = 500;
    error.payload = {
      error: 'runtime apply failed',
      runtime_error: 'runtime apply failed',
      runtime_status: { status: 'error', last_error: 'runtime apply failed' }
    };
    throw error;
  };

  await assert.rejects(
    host.data.upsert('bindings', 'alpha', { name: 'alpha' }, { enabled: true }),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.runtime_error, 'runtime apply failed');
      assert.equal(error.runtime_status.status, 'error');
      return true;
    }
  );
  assert.deepEqual(calls.map((call) => call.method), ['PUT']);
});

test('plugin host exposes locale helper and receives locale broadcasts', async () => {
  const app = createHarness();
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);
  const messages = {
    'zh-CN': { greeting: '你好 {{name}}' },
    'en-US': { greeting: 'Hello {{name}}' }
  };

  assert.equal(host.locale, 'zh-CN');
  assert.equal(host.t(messages, 'greeting', { name: 'Forward' }), '你好 Forward');

  let changedLocale = '';
  host.onLocaleChange((locale) => {
    changedLocale = locale;
  });
  app.state.locale = 'en-US';
  app.refreshLocalizedUI();

  assert.equal(changedLocale, 'en-US');
  assert.equal(host.locale, 'en-US');
  assert.equal(host.t(messages, 'greeting', { name: 'Forward' }), 'Hello Forward');
});

test('plugin host button state distinguishes busy disabled and danger actions', async () => {
  const app = createHarness();
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);
  const button = host.button('Dial', null, true);
  button.getBoundingClientRect = () => ({ width: 84 });

  host.setButtonState(button, { label: 'Disconnecting', busy: true, tone: 'danger', state: 'disconnect' });
  assert.equal(button.textContent, 'Disconnecting');
  assert.equal(button.disabled, true);
  assert.equal(button.dataset.state, 'disconnect');
  assert.equal(button.style.minWidth, '84px');
  assert.match(button.className, /is-busy/);
  assert.match(button.className, /is-danger/);
  assert.equal(button.getAttribute('aria-busy'), 'true');

  host.setButtonState(button, { label: 'Dial', disabled: true, title: 'Unavailable' });
  assert.equal(button.disabled, true);
  assert.equal(button.title, 'Unavailable');
  assert.equal(button.style.minWidth, '');
  assert.doesNotMatch(button.className, /is-busy/);
  assert.doesNotMatch(button.className, /is-danger/);
  assert.equal(button.getAttribute('aria-busy'), 'false');

  host.setButtonState(button, { label: 'Dial' });
  assert.equal(button.disabled, false);
  assert.equal(button.dataset.state, 'ready');
});

test('plugin iframe RPC returns runtime error payload and rejects plugin id mismatch', async () => {
  const app = createHarness();
  const frameWindow = {
    messages: [],
    postMessage(message, targetOrigin) {
      this.messages.push({ message, targetOrigin });
    }
  };
  app.el.pluginUIFrame.dataset.pluginFrame = '1';
  app.el.pluginUIFrame.dataset.pluginId = 'packet_observer';
  app.el.pluginUIFrame.contentWindow = frameWindow;
  app.apiCall = async function apiCall(method, reqPath, body) {
    assert.equal(method, 'PUT');
    assert.equal(reqPath, '/api/plugins/packet_observer/resources/bindings/alpha');
    assert.equal(JSON.stringify(body), JSON.stringify({ data: { name: 'alpha' } }));
    const error = new Error('attach failed');
    error.status = 500;
    error.payload = {
      error: 'attach failed',
      runtime_error: 'attach failed',
      runtime_status: {
        target_type: 'resource',
        target_id: 'bindings',
        status: 'error',
        last_error: 'attach failed'
      }
    };
    throw error;
  };

  const handlers = app.__windowListeners.message || [];
  assert.equal(handlers.length, 1);
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'rpc-1',
      op: 'data.update',
      payload: {
        resource: 'bindings',
        key: 'alpha',
        data: { name: 'alpha' }
      }
    }
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(frameWindow.messages.length, 1);
  const response = frameWindow.messages[0].message;
  assert.equal(frameWindow.messages[0].targetOrigin, '*');
  assert.equal(response.type, 'forward-plugin-rpc-result');
  assert.equal(response.pluginId, 'packet_observer');
  assert.equal(response.id, 'rpc-1');
  assert.equal(response.ok, false);
  assert.equal(response.error, 'attach failed');
  assert.equal(response.status, 500);
  assert.equal(response.error_payload.runtime_error, 'attach failed');
  assert.equal(response.error_payload.runtime_status.status, 'error');

  handlers[0]({
    source: frameWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'other_plugin',
      id: 'rpc-2',
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(frameWindow.messages.length, 1);
});

test('plugin iframe RPC ignores foreign or malformed messages before API calls', async () => {
  const app = createHarness();
  const frameWindow = { messages: [], postMessage(message) { this.messages.push(message); } };
  const foreignWindow = { messages: [], postMessage(message) { this.messages.push(message); } };
  let apiCalls = 0;
  app.el.pluginUIFrame.dataset.pluginFrame = '1';
  app.el.pluginUIFrame.dataset.pluginId = 'packet_observer';
  app.el.pluginUIFrame.contentWindow = frameWindow;
  app.apiCall = async function apiCall() {
    apiCalls += 1;
    return {};
  };

  const handlers = app.__windowListeners.message || [];
  assert.equal(handlers.length, 1);
  handlers[0]({
    source: foreignWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'rpc-foreign',
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'packet_observer',
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'x'.repeat(129),
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'forward-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'rpc-no-op',
      payload: { resource: 'bindings' }
    }
  });
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(apiCalls, 0);
  assert.equal(frameWindow.messages.length, 0);
  assert.equal(foreignWindow.messages.length, 0);
});

test('openPluginUI handles unauthorized asset response', async () => {
  const app = createHarness();
  app.state.plugins.data = [{
    id: 'packet_observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: false,
      status: 401,
      headers: { get() { return ''; } },
      text: async () => ''
    };
  };

  await app.openPluginUI('packet_observer');

  assert.equal(app.tokenCleared, true);
  assert.equal(app.tokenModalShown, true);
  assert.equal(app.el.pluginUIPanel.hidden, true);
});
