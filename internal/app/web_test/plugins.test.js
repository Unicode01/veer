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
    'plugins.chain.empty': 'TC path: legacy Veer fast path; no external plugins are chained around Veer Core.',
    'plugins.chain.meta': 'TC pipeline: {{chain}}',
    'plugins.chain.slot': 'slot {{slot}}',
    'plugins.chain.forwardPath': 'forward: {{chain}}',
    'plugins.chain.replyPath': 'reply: {{chain}}',
    'plugins.chain.preForward': 'pre_forward[{{chain}}]',
    'plugins.chain.core': 'Veer Core(priority={{priority}})',
    'plugins.chain.postLookup': 'post_lookup[{{chain}}]',
    'plugins.chain.apply': 'Veer apply/redirect',
    'plugins.chain.preReply': 'pre_reply[{{chain}}]',
    'plugins.chain.replyCore': 'Veer Reply Core(priority={{priority}})',
    'plugins.chain.postReply': 'post_reply[{{chain}}]',
    'plugins.chain.replyApply': 'Veer reply rewrite',
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
    'plugins.chain.legacy': 'legacy Veer',
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
    'plugins.link.desc': 'Shows how this plugin is attached to the Veer pipeline; the current plugin is highlighted.',
    'plugins.link.count': '{{count}} items',
    'plugins.link.interfaceChain': 'Interface Chain',
    'plugins.link.declaredChain': 'Declared Chain',
    'plugins.link.netfilterPlacement': 'Netfilter Placement',
    'plugins.link.unbound': 'unbound',
    'plugins.link.current': 'Current plugin',
    'plugins.link.core': 'Veer Core',
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
      VeerApp: app,
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
    btoa(value) {
      return Buffer.from(String(value), 'binary').toString('base64');
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

function extractVeerPluginHostScript(srcdoc) {
  const match = String(srcdoc || '').match(/<script data-veer-plugin-host>([\s\S]*?)<\/script>/);
  assert.ok(match, 'decorated plugin HTML should include VeerPluginHost script');
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

  const childHead = makeNode('head');
  const childBody = makeNode('body');
  childBody.scrollHeight = 0;
  childBody.offsetHeight = 0;
  const childDocumentElement = makeNode('html');
  childDocumentElement.scrollHeight = 0;
  childDocumentElement.offsetHeight = 0;

  const childContext = vm.createContext({
    window: childWindow,
    document: {
      head: childHead,
      body: childBody,
      documentElement: childDocumentElement,
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
    btoa(value) {
      return Buffer.from(String(value), 'binary').toString('base64');
    },
    console
  });
  vm.runInContext(extractVeerPluginHostScript(app.el.pluginUIFrame.srcdoc), childContext, { filename: 'veer-plugin-host.js' });
  return childContext.window.VeerPluginHost;
}

test('renderPluginsTable renders builtin and external plugin details', () => {
  const app = createHarness();
  app.state.plugins.catalog = {
    external_plugins_enabled: true,
    directory: 'plugins',
    runtime: { external_dataplane_attach: false, external_dataplane_engines: ['tc', 'xdp'], registration_only_engines: [], core_priority: 1000 },
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
      id: 'veer_core',
      status: 'builtin',
      runtime: { mode: 'builtin', attachable: true, attached: true },
      name: 'Veer Core',
      kind: 'pipeline',
      version: 'builtin',
      capabilities: ['kernel_tc'],
      objects: [{ id: 'veer-tc', path: 'builtin:veer-tc' }],
      hooks: [{ id: 'tc-ingress', engine: 'tc', attach: 'ingress', stage: 'forward', priority: 1000, program: 'builtin:veer-tc', mode: 'rewrite' }]
    },
    {
      id: 'packet_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 1,
        attachments: [{
          hook_id: 'observe-ingress', engine: 'tc', attach: 'ingress', stage: 'pre_forward', interface: 'veer',
          program: 'observer:tc_ingress', priority: 10, before: ['firewall/filter'], after: ['pppoe_client/decap'],
          packet_metadata: [{slot: 0, namespace: 'packet_observer/classification', schema_version: 1, max_bytes: 16, access: 'read_write'}],
          order: 2, chain_slot: 10, status: 'chained'
        }]
      },
      name: 'Packet Observer',
      kind: 'pipeline',
      version: '0.1.0',
      capabilities: ['observe'],
      virtual_interfaces: [{ id: 'vtap0', type: 'logical' }],
      objects: [{ id: 'observer', path: 'observer.o', programs: [{ id: 'tc_ingress', section: 'tc/ingress', type: 'tc' }] }],
      hooks: [{
        id: 'observe-ingress', engine: 'tc', attach: 'ingress', stage: 'forward', priority: 10,
        before: ['firewall/filter'], after: ['pppoe_client/decap'],
        packet_metadata: [{slot: 0, namespace: 'packet_observer/classification', schema_version: 1, max_bytes: 16, access: 'read_write'}],
        program: 'observer.o:tc_ingress', mode: 'observe', interfaces: ['veer']
      }],
      ui: { entry: 'index.html' },
      asset_base_path: '/api/plugins/packet_observer/assets/'
    }
  ];

  app.renderPluginsTable();

  assert.ok(app.el.pluginsBody.childNodes.every((row) => row.childNodes.length === 4));
  const text = collectText(app.el.pluginsBody);
  assert.match(text, /veer/);
  assert.match(text, /packet_observer/);
  assert.match(text, /Loaded/);
  assert.match(text, /Details/);
  assert.match(text, /Open/);
  assert.doesNotMatch(text, /objects=1/);
  const detailLabels = collectAttribute(app.el.pluginsBody, 'aria-label');
  assert.match(detailLabels, /Objects/i);
  assert.match(detailLabels, /Hooks/i);
  assert.match(detailLabels, /before=firewall\/filter/);
  assert.match(detailLabels, /after=pppoe_client\/decap/);
  assert.match(detailLabels, /order=2/);
  assert.match(detailLabels, /metadata=s0:packet_observer\/classification:v1:16B:read_write/);
  assert.match(detailLabels, /chain_slot=10/);
  const detailButtons = app.el.pluginsBody.childNodes
    .flatMap((row) => row.childNodes || [])
    .flatMap((cell) => cell.childNodes || [])
    .flatMap((node) => node.childNodes || [])
    .filter((node) => String(node.className || '').includes('plugin-detail-trigger'));
  assert.equal(detailButtons.length, 2);
  assert.deepEqual(detailButtons.map((node) => node.dataset.pluginId), ['veer_core', 'packet_observer']);
  const toggleButtons = findNodes(app.el.pluginsBody, (node) => String(node.className || '').includes('btn-toggle-plugin'));
  assert.equal(toggleButtons.length, 1);
  assert.equal(toggleButtons[0].dataset.pluginId, 'packet_observer');
  assert.equal(toggleButtons[0].dataset.enabled, '0');
  assert.equal(collectText(toggleButtons[0]), 'Disable');
  assert.match(collectText(app.el.pluginsCatalogMeta), /Plugin Catalog/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Dir plugins/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Dataplane No/);
  assert.doesNotMatch(collectText(app.el.pluginsCatalogMeta), /Register only/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Update monitor Applied/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Applied abcdef123456/);
  assert.match(app.el.pluginsCatalogMeta.title, /Plugin update: Applied/);
  assert.match(collectText(app.el.pluginsChainMeta), /TC Pipeline/);
  assert.match(collectText(app.el.pluginsChainMeta), /1 chained/);
  assert.match(collectText(app.el.pluginsChainMeta), /pre x1/);
  assert.match(collectText(app.el.pluginsChainMeta), /core p1000/);
  assert.match(collectText(app.el.pluginsChainMeta), /apply/);
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: pre_forward[slot 10 packet_observer.observe-ingress (priority=10)] -> Veer Core(priority=1000) -> Veer apply/redirect');
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

test('plugin page ignores a duplicate load while its first request is pending', async () => {
  const app = createHarness();
  const plugin = {
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html', page: 'observe', page_title: 'Observe' }
  };
  app.state.plugins.data = [plugin];
  const panel = app.__createPluginTabPanelForTest({
    tabID: 'plugin-observe',
    pluginID: plugin.id,
    title: 'Observe',
    entry: plugin.ui.entry,
    plugin
  });
  const iframe = findNodes(panel, (node) => String(node.className || '').includes('plugin-page-frame'))[0];
  const refresh = findNodes(panel, (node) => String(node.className || '').includes('btn-reload-plugin-page'))[0];
  panel.querySelector = (selector) => selector.includes('plugin-page-frame') ? iframe : refresh;
  app.__context.document.getElementById = (id) => id === 'tab-plugin-observe' ? panel : null;

  let completeFetch;
  let fetchCalls = 0;
  app.__context.fetch = () => {
    fetchCalls += 1;
    return new Promise((resolve) => {
      completeFetch = () => resolve({
        ok: true,
        status: 200,
        headers: { get(name) { return name === 'Content-Type' ? 'text/html; charset=utf-8' : ''; } },
        text: async () => '<!doctype html><title>Observe</title>'
      });
    });
  };

  const first = app.loadPluginPageForTab('plugin-observe');
  const duplicate = app.loadPluginPageForTab('plugin-observe');

  assert.equal(fetchCalls, 1);
  await duplicate;
  completeFetch();
  await first;
  assert.equal(panel.dataset.loaded, '1');
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
  app.state.plugins.data = [{ id: 'veer_core', status: 'builtin', name: 'Veer Core' }];

  app.renderPluginsTable();

  assert.equal(app.el.pluginsBody.childNodes.length, 0);
  assert.equal(app.el.noPlugins.textContent, 'No matches.');
  assert.deepEqual(app.lastTableVisibility, { tableId: 'pluginsTable', visible: false });
});

test('plugin details include compact host and custom metrics', () => {
  const app = createHarness();
  const text = app.__pluginDetailsPlainTextForTest({
    id: 'metric_plugin',
    status: 'active',
    runtime: {
      mode: 'dataplane', attachable: true, attached: true, attachment_count: 1,
      attachments: [{
        hook_id: 'observe', engine: 'tc', attach: 'ingress', stage: 'post_apply', status: 'chained',
        metrics: {total: {packets: 10, bytes: 640, continued_packets: 10, terminal_packets: 0, tail_call_misses: 0}}
      }],
      metrics: [{name: 'sessions', type: 'gauge', value: 2, labels: {wan: 'wan0'}}]
    }
  });

  assert.match(text, /packets=10/);
  assert.match(text, /bytes=640/);
  assert.match(text, /sessions\{wan=wan0\}/);
  assert.match(text, /gauge \| 2/);
});

test('renderPluginsTable places next-core chain entries after Veer Core', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  app.state.plugins.data = [
    { id: 'veer_core', status: 'builtin', name: 'Veer Core', runtime: { mode: 'builtin', attachable: true, attached: true } },
    {
      id: 'rule_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 1,
        attachments: [{ hook_id: 'after-core', engine: 'tc', attach: 'ingress', stage: 'post_lookup', interface: 'veer', program: 'observer:tc_post_lookup', priority: 1010, chain_slot: 18, status: 'chained', context: ['tc_plugin_ctx_v4'] }]
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
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: Veer Core(priority=1000) -> post_lookup[slot 18 rule_observer.after-core (priority=1010)] -> Veer apply/redirect');
});

test('renderPluginsTable renders reply chain separately from forward chain', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  app.state.plugins.data = [
    { id: 'veer_core', status: 'builtin', name: 'Veer Core', runtime: { mode: 'builtin', attachable: true, attached: true } },
    {
      id: 'reply_observer',
      status: 'active',
      runtime: {
        mode: 'dataplane',
        attachable: true,
        attached: true,
        attachment_count: 2,
        attachments: [
          { hook_id: 'before-reply', engine: 'tc', attach: 'ingress', stage: 'pre_reply', interface: 'veer', program: 'observer:tc_pre_reply', priority: 990, chain_slot: 29, status: 'chained' },
          { hook_id: 'after-reply', engine: 'tc', attach: 'ingress', stage: 'post_reply', interface: 'veer', program: 'observer:tc_post_reply', priority: 1010, chain_slot: 37, status: 'chained', context: ['tc_plugin_ctx_v4'] }
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
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: Veer Core(priority=1000) -> Veer apply/redirect | reply: pre_reply[slot 29 reply_observer.before-reply (priority=990)] -> Veer Reply Core(priority=1000) -> post_reply[slot 37 reply_observer.after-reply (priority=1010)] -> Veer reply rewrite');
});

test('plugin dataplane link rows hide virtual-interface-only control plugins', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const controlOnly = {
    id: 'wan_core',
    name: 'WAN Core',
    kind: 'control',
    virtual_interfaces: [{ id: 'veerwan0', type: 'veth', description: 'local WAN handoff' }]
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
      { id: 'pppoe-egress', engine: 'tc', attach: 'egress', stage: 'forward', priority: 20, interfaces: ['veerlocal0'] }
    ],
    runtime: {
      mode: 'dataplane',
      attachments: [
        { hook_id: 'pppoe-ingress', engine: 'tc', attach: 'ingress', stage: 'pre_forward', interface: 'veer', priority: 20, chain_slot: 11, status: 'chained' },
        { hook_id: 'pppoe-egress', engine: 'tc', attach: 'egress', stage: 'pre_forward', interface: 'veer', priority: 20, chain_slot: 10, status: 'chained' }
      ]
    }
  };
  app.state.plugins.data = [pppoe];

  const rows = app.__pluginLinkRowsForTest(pppoe);
  assert.equal(rows.length, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(rows.map((row) => row.label).sort())), ['TC egress forward', 'TC ingress forward']);
  assert.deepEqual(JSON.parse(JSON.stringify(rows.map((row) => row.segments[0].text).sort())), ['eth1', 'veerlocal0']);
  assert.ok(rows.every((row) => row.segments.some((segment) => segment.current && segment.text === 'pppoe_client')));
});

test('plugin dataplane link rows render attached xdp hooks', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const xdpOnly = {
    id: 'xdp_probe',
    name: 'XDP Probe',
    kind: 'pipeline',
    hooks: [{ id: 'xdp-ingress', engine: 'xdp', attach: 'ingress', stage: 'forward', priority: 20, program: 'probe:xdp_ingress', mode: 'observe', interfaces: ['eth0'] }],
    runtime: {
      mode: 'dataplane',
      attachable: true,
      attached: true,
      attachments: [
        { hook_id: 'xdp-ingress', engine: 'xdp', attach: 'ingress', stage: 'pre_forward', interface: 'eth0', priority: 20, chain_slot: 8, status: 'chained' }
      ]
    }
  };
  app.state.plugins.data = [xdpOnly];

  const rows = app.__pluginLinkRowsForTest(xdpOnly);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].label, 'XDP ingress forward');
  assert.ok(rows[0].segments.some((segment) => segment.current && segment.text === 'xdp_probe'));
});

test('plugin dataplane link rows render native netfilter placements without Veer core', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
  const counter = {
    id: 'nf_counter',
    name: 'Netfilter Counter',
    kind: 'pipeline',
    hooks: [{ id: 'count', engine: 'netfilter', family: 'inet', hook: 'forward', phase: 'filter', namespace: 'host', priority: 20, program: 'counter:nf_count' }],
    runtime: {
      mode: 'dataplane',
      attachable: true,
      attached: true,
      attachment_count: 1,
      attachments: [{
        hook_id: 'count', engine: 'netfilter', family: 'ipv4', netfilter_hook: 'forward', phase: 'filter', namespace: 'host',
        attach: 'forward', stage: 'filter', interface: 'host', priority: 20, order: 1, program: 'counter:nf_count',
        filter_handle: 'bpf_link:priority=5', status: 'attached'
      }]
    }
  };
  const dropper = {
    id: 'nf_dropper',
    name: 'Netfilter Dropper',
    kind: 'pipeline',
    runtime: {
      mode: 'dataplane',
      attachable: true,
      attached: true,
      attachment_count: 1,
      attachments: [{
        hook_id: 'drop', engine: 'netfilter', family: 'ipv4', netfilter_hook: 'forward', phase: 'filter', namespace: 'host',
        attach: 'forward', stage: 'filter', interface: 'host', priority: 10, order: 0, program: 'dropper:nf_drop',
        filter_handle: 'bpf_link:priority=4', status: 'attached'
      }]
    }
  };
  app.state.plugins.data = [counter, dropper];

  const rows = app.__pluginLinkRowsForTest(counter);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, 'Netfilter Placement');
  assert.equal(rows[0].label, 'host / ipv4 / forward / filter');
  assert.deepEqual(JSON.parse(JSON.stringify(rows[0].segments.map((segment) => segment.text))), ['nf_dropper', 'nf_counter']);
  assert.equal(rows[0].segments.some((segment) => segment.core || segment.apply), false);
  const current = rows[0].segments.find((segment) => segment.current);
  assert.ok(current.detailRows.some((row) => row.label === 'Family' && row.value === 'ipv4'));
  assert.ok(current.detailRows.some((row) => row.label === 'Netfilter Hook' && row.value === 'forward'));
  assert.ok(current.detailRows.some((row) => row.label === 'Phase' && row.value === 'filter'));
  assert.ok(current.detailRows.some((row) => row.label === 'Namespace' && row.value === 'host'));
  assert.ok(current.detailRows.some((row) => row.label === 'Kernel attachment' && row.value === 'bpf_link:priority=5'));

  app.renderPluginsTable();
  const details = collectAttribute(app.el.pluginsBody, 'aria-label');
  assert.match(details, /family=inet/);
  assert.match(details, /hook=forward/);
  assert.match(details, /phase=filter/);
  assert.match(details, /namespace=host/);
  assert.match(details, /kernel=bpf_link:priority=5/);
  assert.doesNotMatch(details, /tc_prio=20/);
});

test('openPluginUI fetches protected asset and renders inline iframe', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'nested/page #1.html' }
  }];
  app.__context.fetch = async function fetch(url, opts) {
    calls.push({ url, authorization: opts.headers.Authorization });
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/plain' : ''; } },
      text: async () => '<!doctype html><script data-plugin-prehead>window.pluginRan = true;</script><head><title>Plugin</title></head>'
    };
  };

  await app.openPluginUI('packet_observer');

  assert.deepEqual(calls, [{
    url: '/api/plugins/packet_observer/assets/nested/page%20%231.html',
    authorization: 'Bearer test-token'
  }]);
  assert.equal(app.__openedWindows.length, 0);
  assert.equal(app.el.pluginUIPanel.hidden, false);
  assert.equal(app.el.pluginUITitle.textContent, 'Packet Observer');
  assert.equal(app.el.pluginUIMeta.textContent, 'packet_observer / nested/page #1.html');
  assert.equal(app.el.pluginUIFrame.src, 'about:blank');
  assert.equal(app.el.pluginUIFrame.getAttribute('sandbox'), 'allow-scripts');
  assert.equal(app.el.pluginUIFrame.getAttribute('referrerpolicy'), 'no-referrer');
  assert.match(app.el.pluginUIFrame.getAttribute('csp'), /connect-src 'none'/);
  assert.match(app.el.pluginUIFrame.getAttribute('csp'), /form-action 'none'/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /http-equiv="Content-Security-Policy"/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /base-uri 'none'/);
  assert.ok(
    String(app.el.pluginUIFrame.srcdoc).indexOf('http-equiv="Content-Security-Policy"') <
      String(app.el.pluginUIFrame.srcdoc).indexOf('data-plugin-prehead'),
    'the host CSP must precede plugin-controlled executable content'
  );
  assert.match(String(app.el.pluginUIFrame.srcdoc), /data-veer-plugin-host/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /VeerPluginHost/);
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
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.assets = Object\.freeze/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /max_inflight/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /pendingRPCBytes/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /error_payload/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /runtime_status/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /runtime_error/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /clearTimeout\(pending\.timeout\)/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /event\.source !== window\.parent/);

  app.closePluginUI();

  assert.equal(app.el.pluginUIPanel.hidden, true);
});

test('plugin host loads bounded same-plugin text json style script and image assets', async () => {
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
    if (url.endsWith('index.html')) {
      return response('text/html; charset=utf-8', '<!doctype html><title>Plugin</title>');
    }
    if (url.endsWith('assets/info.txt')) return response('text/plain; charset=utf-8', 'hello');
    if (url.endsWith('assets/config.json')) return response('application/json', '{"enabled":true}');
    if (url.endsWith('assets/plugin.css')) return response('text/css', '.plugin { color: red; }');
    if (url.endsWith('assets/plugin.js')) return response('text/javascript', 'window.pluginAssetLoaded = true;');
    if (url.endsWith('assets/icon.png')) {
      const bytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47]);
      return response('image/png', '', bytes.buffer);
    }
    return { ok: false, status: 404, statusText: 'not found', headers: { get() { return ''; } }, text: async () => '' };
  };

  function response(contentType, body, buffer) {
    const length = buffer ? buffer.byteLength : Buffer.byteLength(body);
    return {
      ok: true,
      status: 200,
      headers: {
        get(name) {
          if (String(name).toLowerCase() === 'content-type') return contentType;
          if (String(name).toLowerCase() === 'content-length') return String(length);
          return '';
        }
      },
      text: async () => body,
      arrayBuffer: async () => buffer
    };
  }

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);

  assert.equal(await host.assets.text('assets/info.txt'), 'hello');
  assert.deepEqual(JSON.parse(JSON.stringify(await host.assets.json('assets/config.json'))), { enabled: true });
  const style = await host.assets.style('assets/plugin.css', { media: 'screen' });
  assert.equal(style.tagName, 'STYLE');
  assert.equal(style.getAttribute('media'), 'screen');
  assert.equal(style.textContent, '.plugin { color: red; }');
  assert.equal(style.parentNode.tagName, 'HEAD');
  const script = await host.assets.script('assets/plugin.js');
  assert.equal(script.tagName, 'SCRIPT');
  assert.match(script.textContent, /window\.pluginAssetLoaded = true/);
  assert.match(script.textContent, /sourceURL=veer-plugin:\/\/packet_observer\/assets\/plugin\.js/);
  assert.equal(script.parentNode.tagName, 'HEAD');
  assert.equal(await host.assets.dataURL('assets/icon.png'), 'data:image/png;base64,iVBORw==');
  assert.ok(calls.every((call) => call.authorization === 'Bearer test-token'));
});

test('plugin asset bridge rejects traversal mismatched types invalid JSON and oversized files', async () => {
  const app = createHarness();
  let fetchCalls = 0;
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    ui: { entry: 'index.html' }
  }];
  app.__context.fetch = async function fetch(url) {
    fetchCalls += 1;
    if (url.endsWith('index.html')) {
      return {
        ok: true,
        status: 200,
        headers: { get(name) { return String(name).toLowerCase() === 'content-type' ? 'text/html' : ''; } },
        text: async () => '<!doctype html><title>Plugin</title>'
      };
    }
    const isLarge = url.endsWith('large.txt');
    const contentType = url.endsWith('.json') ? 'application/json' : 'text/css';
    return {
      ok: true,
      status: 200,
      headers: {
        get(name) {
          if (String(name).toLowerCase() === 'content-type') return contentType;
          if (String(name).toLowerCase() === 'content-length') return isLarge ? String(1024 * 1024 + 1) : '';
          return '';
        }
      },
      text: async () => isLarge ? '' : '{broken'
    };
  };

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);
  const afterEntry = fetchCalls;
  await assert.rejects(host.assets.text('../secret.txt'), (error) => error.status === 400);
  assert.equal(fetchCalls, afterEntry);
  await assert.rejects(host.assets.script('assets/not-script.css'), (error) => error.status === 415);
  await assert.rejects(host.assets.json('assets/broken.json'), (error) => error.status === 422);
  await assert.rejects(host.assets.text('assets/large.txt'), (error) => error.status === 413);
});

test('plugin host and parent both enforce RPC queue payload and rate limits', async () => {
  const app = createHarness();
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    actions: [{ id: 'hold' }, { id: 'overflow' }, { id: 'test' }],
    ui: { entry: 'index.html', actions: ['hold', 'overflow', 'test'] }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return String(name).toLowerCase() === 'content-type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };
  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);

  app.apiCall = () => new Promise(() => {});
  const pending = Array.from({ length: host.rpcLimits.max_inflight }, (_, index) => host.action('hold', { index }));
  assert.equal(pending.length, 32);
  await assert.rejects(host.action('overflow'), (error) => error.status === 429);

  const frameWindow = {
    messages: [],
    postMessage(message) {
      this.messages.push(message);
    }
  };
  app.closePluginUI();
  app.el.pluginUIFrame.dataset.pluginFrame = '1';
  app.el.pluginUIFrame.dataset.pluginId = 'packet_observer';
  app.el.pluginUIFrame.contentWindow = frameWindow;
  const handler = app.__windowListeners.message[0];
  let apiCalls = 0;
  app.apiCall = async function apiCall() {
    apiCalls += 1;
    return {};
  };

  handler({
    source: frameWindow,
    data: {
      type: 'veer-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'oversized',
      op: 'action',
      payload: { action: 'test', payload: { value: 'x'.repeat(2 * 1024 * 1024 + 1) } }
    }
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(frameWindow.messages.at(-1).status, 413);
  assert.equal(frameWindow.messages.at(-1).error_payload.code, 'plugin_ui_rpc_payload_limit');
  assert.equal(apiCalls, 0);

  for (let index = 0; index <= 120; index++) {
    handler({
      source: frameWindow,
      data: {
        type: 'veer-plugin-rpc',
        pluginId: 'packet_observer',
        id: 'rate-' + index,
        op: 'action',
        payload: { action: 'test', payload: { index } }
      }
    });
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.equal(apiCalls, 120);
  assert.equal(frameWindow.messages.at(-1).status, 429);
  assert.equal(frameWindow.messages.at(-1).error_payload.code, 'plugin_ui_rpc_rate_limit');
});

test('plugin RPC data.list forwards pagination query params', () => {
  const filePath = path.join(__dirname, '..', 'web', 'js', 'plugins.js');
  const source = fs.readFileSync(filePath, 'utf8');
  assert.match(source, /payload\.limit/);
  assert.match(source, /payload\.offset/);
  assert.match(source, /limit=/);
  assert.match(source, /offset=/);
});

test('plugin host exposes and executes only explicitly granted UI capabilities', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'packet_observer',
    name: 'Packet Observer',
    asset_base_path: '/api/plugins/packet_observer/assets/',
    resources: [
      { id: 'bindings', methods: ['list', 'get', 'create', 'update', 'delete'] },
      { id: 'internal_status', methods: ['list', 'get'] }
    ],
    actions: [{ id: 'apply' }, { id: 'clear_state' }],
    ui: {
      entry: 'index.html',
      resources: [{ resource: 'bindings', methods: ['list'] }],
      actions: ['apply']
    }
  }];
  app.__context.fetch = async function fetch() {
    return {
      ok: true,
      status: 200,
      headers: { get(name) { return name === 'Content-Type' ? 'text/html' : ''; } },
      text: async () => '<!doctype html><title>Plugin</title>'
    };
  };
  app.apiCall = async function apiCall(method, reqPath) {
    calls.push({ method, reqPath });
    return { ok: true, records: [] };
  };

  await app.openPluginUI('packet_observer');
  const host = attachPluginHostChildFrame(app);
  assert.deepEqual(JSON.parse(JSON.stringify(host.resources)), [{
    id: 'bindings',
    description: '',
    methods: ['list'],
    runtime_update: '',
    max_records: 0,
    max_record_bytes: 0,
    schema_version: 1,
    schema: null,
    schema_digest: ''
  }]);
  assert.deepEqual(JSON.parse(JSON.stringify(host.actions)).map((action) => action.id), ['apply']);

  await host.data.list('bindings');
  await host.action('apply');
  await assert.rejects(host.data.get('bindings', 'default'), (error) => error.status === 403 && error.payload.code === 'plugin_ui_capability_denied');
  await assert.rejects(host.data.list('internal_status'), (error) => error.status === 403 && error.payload.code === 'plugin_ui_capability_denied');
  await assert.rejects(host.action('clear_state'), (error) => error.status === 403 && error.payload.code === 'plugin_ui_capability_denied');
  assert.deepEqual(calls, [
    { method: 'GET', reqPath: '/api/plugins/packet_observer/resources/bindings' },
    { method: 'POST', reqPath: '/api/plugins/packet_observer/actions/apply' }
  ]);
});

test('plugin host cross-plugin resource reads enforce manifest grants', async () => {
  const app = createHarness();
  const calls = [];
  app.state.plugins.data = [{
    id: 'lan_core',
    name: 'LAN Core',
    asset_base_path: '/api/plugins/lan_core/assets/',
    ui: {
      entry: 'index.html',
      resource_access: [{ plugin: 'wan_core', resource: 'status', methods: ['list'] }]
    },
    control: {
      resource_access: [{ plugin: 'wan_core', resource: 'status', methods: ['get', 'list'] }]
    }
  }, {
    id: 'wan_core',
    resources: [{ id: 'status', methods: ['list', 'get'] }]
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

  app.state.plugins.data[0].control.resource_access[0].methods = ['get'];
  await assert.rejects(
    host.plugins.resources.list('wan_core', 'status', { limit: 32 }),
    /plugin UI cross-plugin resource capability denied/
  );

  await assert.rejects(
    host.plugins.resources.list('pppoe_client', 'sessions', { limit: 32 }),
    /plugin UI cross-plugin resource capability denied/
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

test('plugin table keeps routine plugin information in four stable columns', () => {
  const cssPath = path.join(__dirname, '..', 'web', 'css', 'tables.css');
  const source = fs.readFileSync(cssPath, 'utf8');
  const widths = new Map();
  const pattern = /#pluginsTable th:nth-child\((\d+)\),\s*#pluginsTable td:nth-child\(\1\)\s*\{\s*width:\s*(\d+)%/g;
  for (const match of source.matchAll(pattern)) {
    const column = Number(match[1]);
    if (!widths.has(column)) widths.set(column, Number(match[2]));
  }

  assert.equal(widths.size, 4);
  assert.equal(widths.get(1), 30);
  assert.equal(widths.get(4), 32);
  assert.equal(Array.from(widths.values()).reduce((sum, width) => sum + width, 0), 100);
  assert.match(source, /@media \(max-width: 720px\)[\s\S]*?#pluginsTable\s*\{\s*min-width:\s*760px/);
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
    resources: [{ id: 'bindings', methods: ['create', 'update'] }],
    ui: {
      entry: 'index.html',
      resources: [{ resource: 'bindings', methods: ['create', 'update'] }]
    }
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
  assert.equal(host.t(messages, 'greeting', { name: 'Veer' }), '你好 Veer');

  let changedLocale = '';
  host.onLocaleChange((locale) => {
    changedLocale = locale;
  });
  app.state.locale = 'en-US';
  app.refreshLocalizedUI();

  assert.equal(changedLocale, 'en-US');
  assert.equal(host.locale, 'en-US');
  assert.equal(host.t(messages, 'greeting', { name: 'Veer' }), 'Hello Veer');
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
  app.state.plugins.data = [{
    id: 'packet_observer',
    resources: [{ id: 'bindings', methods: ['update'] }],
    ui: { resources: [{ resource: 'bindings', methods: ['update'] }] }
  }];
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
      type: 'veer-plugin-rpc',
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
  assert.equal(response.type, 'veer-plugin-rpc-result');
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
      type: 'veer-plugin-rpc',
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
      type: 'veer-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'rpc-foreign',
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'veer-plugin-rpc',
      pluginId: 'packet_observer',
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'veer-plugin-rpc',
      pluginId: 'packet_observer',
      id: 'x'.repeat(129),
      op: 'data.list',
      payload: { resource: 'bindings' }
    }
  });
  handlers[0]({
    source: frameWindow,
    data: {
      type: 'veer-plugin-rpc',
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
