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
    hidden: !!opts.hidden,
    disabled: false,
    style: {},
    dataset: {},
    attributes: Object.assign({}, opts.attrs || {}),
    childNodes: [],
    parentNode: null,
    classList: {
      add(...names) {
        const set = new Set(String(node.className || '').split(/\s+/).filter(Boolean));
        names.forEach((name) => set.add(String(name)));
        node.className = Array.from(set).join(' ');
      },
      remove(...names) {
        const remove = new Set(names.map((name) => String(name)));
        node.className = String(node.className || '').split(/\s+/).filter((name) => name && !remove.has(name)).join(' ');
      },
      toggle(name, force) {
        const has = this.contains(name);
        if (force === true || (!has && force !== false)) this.add(name);
        else if (has && force !== true) this.remove(name);
      },
      contains(name) {
        return String(node.className || '').split(/\s+/).includes(String(name));
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
    removeChild(child) {
      const index = node.childNodes.indexOf(child);
      if (index >= 0) node.childNodes.splice(index, 1);
      child.parentNode = null;
      return child;
    },
    setAttribute(name, value) {
      node.attributes[name] = value == null ? '' : String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(node.attributes, name) ? node.attributes[name] : null;
    },
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(node.attributes, name);
    },
    addEventListener() {},
    removeEventListener() {},
    contains(target) {
      if (target === node) return true;
      return node.childNodes.some((child) => typeof child.contains === 'function' && child.contains(target));
    },
    getBoundingClientRect() {
      return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
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

function createHarness() {
  const translations = {
    'common.close': 'Close',
    'common.unavailable': 'Unavailable',
    'common.dash': '-',
    'rule.engine.preference.auto': 'Auto',
    'rule.engine.preference.kernel': 'Kernel',
    'rule.engine.preference.userspace': 'Userspace',
    'kernel.summary.status': 'Kernel Status',
    'kernel.summary.activeKernel': 'Kernel Assignments',
    'kernel.summary.activeKernelValue': 'Rules {{rules}} / Ranges {{ranges}}',
    'kernel.summary.pressure': 'Current Pressure',
    'kernel.summary.retry': 'Recovery Attempts',
    'kernel.summary.retryValue': 'Full {{full}} / Incremental {{incremental}}',
    'kernel.summary.fallbacksValue': 'Rules {{rules}} / Ranges {{ranges}}',
    'kernel.summary.transientFallbacksValue': 'Transient: rules {{rules}} / ranges {{ranges}}',
    'kernel.summary.incrementalMatchedValue': 'Matched rules {{rules}} / ranges {{ranges}}',
    'kernel.summary.incrementalAttemptedValue': 'Attempted rules {{rules}} / ranges {{ranges}}',
    'kernel.summary.incrementalRecoveredValue': 'Recovered rules {{rules}} / ranges {{ranges}}',
    'kernel.summary.incrementalRetainedValue': 'Retained rules {{rules}} / ranges {{ranges}}',
    'kernel.summary.retryFallbackValue': 'Incremental -> full fallback {{count}} time(s)',
    'kernel.summary.configuredOrder': 'Kernel Engine Order',
    'kernel.summary.mapProfile': 'Startup map profile',
    'kernel.summary.mapProfileMemoryUnknown': 'RAM unknown',
    'kernel.summary.mapProfileDetail': 'RAM {{memory}} flows {{flows}} nat {{nat}} egress {{egress}}',
    'kernel.summary.degraded': 'Kernel Engine Degraded',
    'kernel.summary.degradedValue': '{{engine}} is running in degraded-until-restart mode',
    'kernel.pressure.noneHint': 'No active table pressure',
    'kernel.pressure.none': 'Normal',
    'kernel.available.yes': 'Available',
    'kernel.available.no': 'Unavailable',
    'kernel.traffic.enabled': 'Enabled',
    'kernel.traffic.disabled': 'Disabled',
    'kernel.retry.idle': 'Idle',
    'kernel.retry.pending': 'Pending',
    'kernel.loaded.yes': 'Loaded',
    'kernel.loaded.no': 'Not loaded',
    'kernel.attachments.healthy': 'Healthy',
    'kernel.attachments.degraded': 'Degraded',
    'kernel.mode.rebuild': 'Rebuild',
    'kernel.mode.unknown': 'Unknown',
    'kernel.engine.details': 'Details',
    'kernel.maps.rules': 'rules',
    'kernel.maps.flows': 'flows',
    'kernel.maps.nat': 'nat',
    'kernel.maps.ipv4': 'IPv4',
    'kernel.maps.ipv6': 'IPv6',
    'kernel.maps.ipv4Short': 'v4',
    'kernel.maps.ipv6Short': 'v6',
    'kernel.maps.tooltip.profile': 'Profile',
    'kernel.maps.tooltip.mode': 'Mode',
    'kernel.maps.tooltip.base': 'Base',
    'kernel.maps.tooltip.decision': 'Decision',
    'kernel.maps.tooltip.peak': 'Peak',
    'kernel.maps.tooltip.scope': 'Aggregation',
    'kernel.maps.tooltip.total': 'Total',
    'kernel.maps.tooltip.oldBank': 'Old bank',
    'kernel.maps.tooltip.mode.adaptive': 'Adaptive',
    'kernel.maps.tooltip.mode.fixed': 'Fixed',
    'kernel.maps.tooltip.decision.current': 'Current capacity {{current}}',
    'kernel.maps.tooltip.scope.families': 'Active capacity summed across v4/v6 families',
    'kernel.traffic.enabled': 'Enabled',
    'kernel.traffic.disabled': 'Disabled'
  };

  const documentRef = {
    body: makeNode('body'),
    hidden: false,
    activeElement: null,
    getElementById() {
      return null;
    },
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
    addEventListener() {},
    querySelectorAll() {
      return [];
    }
  };

  const tabRulesButton = makeNode('button', { className: 'tab' });
  tabRulesButton.dataset.tab = 'rules';
  const tabEgressNATButton = makeNode('button', { className: 'tab' });
  tabEgressNATButton.dataset.tab = 'egress-nats';
  const tabRulesPanel = makeNode('div', { className: 'tab-content' });
  const tabEgressNATPanel = makeNode('div', { className: 'tab-content' });
  const egressNATStatsSection = makeNode('section');
  const managedNetworkAutoEgressNATGroup = makeNode('div');
  const managedNetworksAutoEgressNATHeader = makeNode('th');
  const elements = {
    'tab-rules-button': tabRulesButton,
    'tab-egress-nats-button': tabEgressNATButton,
    'tab-rules': tabRulesPanel,
    'tab-egress-nats': tabEgressNATPanel,
    egressNATStatsSection,
    managedNetworkAutoEgressNATGroup,
    managedNetworksAutoEgressNATHeader
  };

  documentRef.getElementById = function getElementById(id) {
    return Object.prototype.hasOwnProperty.call(elements, id) ? elements[id] : null;
  };
  documentRef.querySelectorAll = function querySelectorAll(selector) {
    if (selector === '.tab') return [tabRulesButton, tabEgressNATButton];
    if (selector === '.tab-content') return [tabRulesPanel, tabEgressNATPanel];
    return [];
  };

  const app = {
    state: {
      kernelRuntime: { data: null },
      kernelRuntimeDismissedNotes: {},
      kernelFeatureVisibility: { loaded: false, egressNAT: true, managedNetworkAutoEgressNAT: true },
      activeTab: 'rules'
    },
    el: {
      kernelRuntimeSummary: makeNode('div'),
      kernelRuntimeBody: makeNode('tbody'),
      noKernelRuntime: makeNode('div')
    },
    $(id) {
      return Object.prototype.hasOwnProperty.call(elements, id) ? elements[id] : null;
    },
    t(key, params) {
      let text = Object.prototype.hasOwnProperty.call(translations, key) ? translations[key] : key;
      if (!params) return text;
      return text.replace(/\{\{(\w+)\}\}/g, (_, name) => {
        if (!Object.prototype.hasOwnProperty.call(params, name)) return '';
        return params[name] == null ? '' : String(params[name]);
      });
    },
    translateRuntimeReason(value) {
      return String(value || '').trim();
    },
    createNode(tagName, opts = {}) {
      const node = makeNode(tagName, opts);
      if (opts.text != null) node.textContent = String(opts.text);
      if (opts.title != null) node.title = String(opts.title);
      if (opts.attrs) {
        Object.keys(opts.attrs).forEach((key) => node.setAttribute(key, opts.attrs[key]));
      }
      if (opts.children) {
        opts.children.forEach((child) => appendNodeContent(node, child));
      }
      return node;
    },
    appendNodeContent,
    createBadgeNode(className, text, title) {
      return makeNode('span', {
        className: 'badge ' + String(className || ''),
        text: String(text || ''),
        title: String(title || '')
      });
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
      if (!node) return;
      node.childNodes = [];
    },
    toggleTableVisibility() {},
    activateTab(tabId) {
      this.state.activeTab = tabId;
    },
    firstVisibleTabId() {
      return !tabRulesButton.hidden ? 'rules' : '';
    },
    syncManagedNetworkKernelFeatureVisibility() {
      const visible = typeof this.kernelFeatureVisible === 'function'
        ? this.kernelFeatureVisible('managedNetworkAutoEgressNAT')
        : true;
      managedNetworkAutoEgressNATGroup.hidden = !visible;
      managedNetworksAutoEgressNATHeader.hidden = !visible;
    },
    formatClock(value) {
      return String(value || '');
    },
    formatBytes(value) {
      return String(value || 0);
    },
    notify() {}
  };

  const windowRef = {
    ForwardApp: app,
    addEventListener() {},
    removeEventListener() {},
    innerWidth: 1280,
    innerHeight: 720,
    scrollX: 0,
    scrollY: 0
  };

  const context = vm.createContext({
    window: windowRef,
    document: documentRef,
    console,
    URLSearchParams
  });

  const baseDir = path.join(__dirname, '..', 'web', 'js');
  const code = fs.readFileSync(path.join(baseDir, 'stats.js'), 'utf8');
  vm.runInContext(code, context, { filename: path.join(baseDir, 'stats.js') });

  return { app, elements };
}

function collectKernelRuntimeNotes(node, out = []) {
  if (!node) return out;
  if (String(node.className || '').split(/\s+/).includes('kernel-runtime-note')) out.push(node);
  (node.childNodes || []).forEach((child) => collectKernelRuntimeNotes(child, out));
  return out;
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

function baseRuntimeData() {
  return {
    available: true,
    default_engine: 'auto',
    configured_order: ['tc', 'xdp'],
    traffic_stats: true,
    active_rule_count: 1,
    active_range_count: 3,
    kernel_fallback_rule_count: 0,
    kernel_fallback_range_count: 0,
    transient_fallback_rule_count: 0,
    transient_fallback_range_count: 0,
    retry_pending: false,
    kernel_retry_count: 0,
    kernel_incremental_retry_count: 0,
    kernel_incremental_retry_fallback_count: 0,
    kernel_flows_map_base_limit: 262144,
    kernel_nat_map_base_limit: 262144,
    kernel_egress_nat_auto_floor: 262144
  };
}

function runtimeEngine(overrides) {
  return Object.assign({
    name: 'tc',
    available: true,
    loaded: true,
    attachments_healthy: true,
    attachments: 8,
    active_entries: 60005,
    traffic_stats: true,
    degraded: false,
    pressure_active: false,
    rules_map_entries: 60005,
    rules_map_capacity: 65536,
    rules_map_entries_v4: 60005,
    rules_map_capacity_v4: 65536,
    rules_map_capacity_v6: 65536,
    flows_map_entries: 194,
    flows_map_capacity: 262144,
    flows_map_entries_v4: 192,
    flows_map_capacity_v4: 262144,
    flows_map_capacity_v6: 262144,
    nat_map_entries: 96,
    nat_map_capacity: 262144,
    nat_map_entries_v4: 95,
    nat_map_capacity_v4: 262144,
    nat_map_capacity_v6: 262144,
    last_reconcile_mode: 'rebuild',
    last_reconcile_ms: 569,
    last_reconcile_request_entries: 60005,
    last_reconcile_prepared_entries: 60005,
    last_reconcile_applied_entries: 60005,
    last_reconcile_upserts: 60005,
    last_reconcile_attaches: 8,
    last_reconcile_prepare_ms: 145,
    last_maintain_ms: 13,
    last_prune_budget: 65536,
    last_prune_scanned: 184
  }, overrides || {});
}

test('renderKernelRuntime omits degraded note when no engine is degraded', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    engines: [runtimeEngine()]
  });

  app.renderKernelRuntime();

  const notes = collectKernelRuntimeNotes(app.el.kernelRuntimeSummary);
  const degradedNotes = notes.filter((note) => collectText(note).includes('Kernel Engine Degraded'));
  assert.equal(degradedNotes.length, 0);
});

test('applyKernelFeatureVisibility hides egress nat surfaces when kernel dataplane is unavailable', () => {
  const { app, elements } = createHarness();
  app.state.activeTab = 'egress-nats';

  app.applyKernelFeatureVisibility({
    available: false,
    engines: [
      { name: 'tc', available: false },
      { name: 'xdp', available: false }
    ]
  });

  assert.equal(elements['tab-egress-nats-button'].hidden, true);
  assert.equal(elements['tab-egress-nats'].hidden, true);
  assert.equal(elements.egressNATStatsSection.hidden, true);
  assert.equal(elements.managedNetworkAutoEgressNATGroup.hidden, true);
  assert.equal(elements.managedNetworksAutoEgressNATHeader.hidden, true);
  assert.equal(app.state.activeTab, 'rules');
});

test('applyKernelFeatureVisibility keeps egress nat surfaces visible when kernel dataplane is available', () => {
  const { app, elements } = createHarness();

  app.applyKernelFeatureVisibility({
    available: true,
    engines: [
      { name: 'tc', available: true }
    ]
  });

  assert.equal(elements['tab-egress-nats-button'].hidden, false);
  assert.equal(elements['tab-egress-nats'].hidden, false);
  assert.equal(elements.egressNATStatsSection.hidden, false);
  assert.equal(elements.managedNetworkAutoEgressNATGroup.hidden, false);
  assert.equal(elements.managedNetworksAutoEgressNATHeader.hidden, false);
});

test('renderKernelRuntime renders degraded note when an engine is degraded', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    engines: [runtimeEngine({
      degraded: true,
      degraded_reason: 'degraded reason'
    })]
  });

  app.renderKernelRuntime();

  const notes = collectKernelRuntimeNotes(app.el.kernelRuntimeSummary);
  const noteTexts = notes.map((note) => collectText(note));
  assert.ok(noteTexts.some((text) => text.includes('Kernel Engine Degraded: TC:')));
});
