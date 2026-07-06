const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function makeNode(tagName, opts = {}) {
  const node = {
    tagName: String(tagName || 'div').toUpperCase(),
    className: opts.className || '',
    textContent: opts.text || '',
    title: opts.title || '',
    attributes: {},
    hidden: false,
    style: {},
    childNodes: [],
    parentNode: null,
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

function createHarness() {
  const notifications = [];
  const openedWindows = [];
  const elements = {
    pluginsBody: makeNode('tbody'),
    noPlugins: makeNode('p'),
    pluginsCatalogMeta: makeNode('div'),
    pluginsChainMeta: makeNode('div'),
    pluginUIPanel: makeNode('section'),
    pluginUITitle: makeNode('h3'),
    pluginUIMeta: makeNode('p'),
    pluginUIFrame: makeNode('iframe'),
    pluginsPagination: makeNode('div')
  };
  const translations = {
    'common.dash': '-',
    'common.no': 'No',
    'common.noMatches': 'No matches.',
    'common.status': 'Status',
    'common.yes': 'Yes',
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
    'plugins.catalog.scanOn': 'Enabled',
    'plugins.catalog.scanOff': 'Off',
    'plugins.runtime.attachable': 'Attachable',
    'plugins.runtime.attached': 'Attached',
    'plugins.runtime.attachments': 'Attachments',
    'plugins.runtime.builtin': 'Built-in dataplane',
    'plugins.runtime.dataplane': 'Dataplane enabled',
    'plugins.runtime.error': 'Runtime error',
    'plugins.runtime.invalid': 'Validation failed',
    'plugins.runtime.manifestOnly': 'Manifest only',
    'plugins.source': 'Source',
    'plugins.status.active': 'Loaded',
    'plugins.status.builtin': 'Built-in',
    'plugins.status.error': 'Error',
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
    'plugins.ui.assets': 'Static Assets',
    'plugins.ui.emptyTitle': 'No Plugin Selected',
    'plugins.ui.loadedMeta': '{{id}} / {{entry}}'
  };

  const app = {
    el: elements,
    state: {
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
  return app;
}

test('renderPluginsTable renders builtin and external plugin details', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins/runtime', runtime: { external_dataplane_attach: false, core_priority: 1000 } };
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
      hooks: [{ id: 'observe-ingress', engine: 'tc', attach: 'ingress', stage: 'pre_forward', program: 'observer.o:tc_ingress', mode: 'observe', interfaces: ['fvtap'] }],
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
    .filter((node) => node.dataset && node.dataset.pluginId);
  assert.equal(detailButtons.length, 2);
  assert.deepEqual(detailButtons.map((node) => node.dataset.pluginId), ['fvtap', 'packet_observer']);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Plugin Catalog/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /plugins\/runtime/);
  assert.match(collectText(app.el.pluginsCatalogMeta), /Dataplane No/);
  assert.match(collectText(app.el.pluginsChainMeta), /TC Pipeline/);
  assert.match(collectText(app.el.pluginsChainMeta), /1 chained/);
  assert.match(collectText(app.el.pluginsChainMeta), /pre x1/);
  assert.match(collectText(app.el.pluginsChainMeta), /core p1000/);
  assert.match(collectText(app.el.pluginsChainMeta), /apply/);
  assert.equal(app.el.pluginsChainMeta.title, 'TC pipeline: forward: pre_forward[slot 10 packet_observer.observe-ingress (priority=10)] -> fvtap core(priority=1000) -> fvtap apply/redirect');
  assert.deepEqual(app.lastTableVisibility, { tableId: 'pluginsTable', visible: true });
});

test('renderPluginsTable applies plugin search filter', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: false, directory: 'plugins/runtime' };
  app.state.plugins.searchQuery = 'missing';
  app.state.plugins.data = [{ id: 'fvtap', status: 'builtin', name: 'Forward Virtual Tap' }];

  app.renderPluginsTable();

  assert.equal(app.el.pluginsBody.childNodes.length, 0);
  assert.equal(app.el.noPlugins.textContent, 'No matches.');
  assert.deepEqual(app.lastTableVisibility, { tableId: 'pluginsTable', visible: false });
});

test('renderPluginsTable places next-core chain entries after fvtap core', () => {
  const app = createHarness();
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins/runtime', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
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
  app.state.plugins.catalog = { external_plugins_enabled: true, directory: 'plugins/runtime', runtime: { external_dataplane_attach: true, core_priority: 1000 } };
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
  assert.match(String(app.el.pluginUIFrame.srcdoc), /data-forward-plugin-host/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /ForwardPluginHost/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.data/);
  assert.match(String(app.el.pluginUIFrame.srcdoc), /host\.action/);

  app.closePluginUI();

  assert.equal(app.el.pluginUIPanel.hidden, true);
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
