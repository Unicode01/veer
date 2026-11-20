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
    'kernel.flowCache.enabled': 'Flow cache on',
    'kernel.flowCache.disabled': 'Flow cache off',
    'kernel.flowCache.inactive': 'Flow cache inactive: {{option}} is on',
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
    'kernel.traffic.disabled': 'Disabled',
    'kernel.note.helperModuleMissing': 'No helper module for {{release}}',
    'kernel.note.helperModuleOtherReleases': 'installed for {{releases}}',
    'kernel.note.helperModuleRebuild': 'run {{command}}',
    'kernel.note.helperModuleUnavailable': 'Helper module unavailable'
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
    VeerApp: app,
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

test('renderKernelRuntime shows whether the configured flow cache is in effect', () => {
  for (const state of [
    { configured: false, engine: {}, want: 'Flow cache off' },
    { configured: true, engine: { flow_cache: true }, want: 'Flow cache on' },
    {
      configured: true,
      engine: { flow_cache_disabled_by: 'kernel_tc_reply_l2_cache' },
      want: 'Flow cache inactive: kernel_tc_reply_l2_cache is on'
    }
  ]) {
    const { app } = createHarness();
    app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
      kernel_tc_flow_cache: state.configured,
      engines: [runtimeEngine(state.engine)]
    });

    app.renderKernelRuntime();

    assert.ok(collectText(app.el.kernelRuntimeSummary).includes(state.want), state.want);
  }
});

// The status details as "label: value" lines (hints appended), the way the popover reads.
function statusDetailLines(app, groupID) {
  return app.kernelRuntimeStatusGroups(app.state.kernelRuntime.data)
    .filter((group) => !groupID || group.id === groupID)
    .flatMap((group) => (group.rows || []).map((row) => {
      const value = row.devices ? row.devices.join(', ') : row.value;
      return row.label + ': ' + value + (row.hint ? ' · ' + row.hint : '');
    }));
}

test('kernel status details distinguish helper build support, loading and usable capabilities', () => {
  for (const state of [
    {compiled:false,loaded:false,available:false,want:'kernel.helper.notCompiled',tone:'unknown'},
    {compiled:false,loaded:true,available:false,want:'kernel.helper.notCompiled',tone:'unknown'},
    {compiled:true,loaded:true,available:false,want:'kernel.helper.unavailable',reason:'ABI mismatch',tone:'bad'},
    {compiled:true,loaded:true,available:true,want:'kernel.helper.available',tone:'ok'}
  ]) {
    const {app}=createHarness();
    app.state.kernelRuntime.data=Object.assign(baseRuntimeData(), {
      kernel_helper_module:{name:'veer_kfuncs',...state}, engines:[runtimeEngine()]
    });
    app.renderKernelRuntime();
    const group=app.kernelRuntimeStatusGroups(app.state.kernelRuntime.data).find((item)=>item.id==='platform');
    const row=group && group.rows.find((item)=>item.value.includes('veer_kfuncs'));
    assert.ok(row,'helper status must be in the platform group');
    assert.ok(row.value.includes(state.loaded?'Loaded':'Not loaded'));
    assert.ok(row.value.includes(state.want));
    assert.equal(row.state,state.tone);
    if(state.reason)assert.equal(row.hint,state.reason);
  }
});

test('kernel runtime notes flag a helper module missing after a kernel upgrade', () => {
  function helperNotes(helper) {
    const {app}=createHarness();
    app.state.kernelRuntime.data=Object.assign(baseRuntimeData(), {
      kernel_helper_module:Object.assign({name:'veer_kfuncs'}, helper), engines:[runtimeEngine()]
    });
    app.renderKernelRuntime();
    return collectKernelRuntimeNotes(app.el.kernelRuntimeSummary).map(collectText).filter((text)=>text.includes('elper module'));
  }
  const missing=helperNotes({compiled:true,loaded:false,available:false,module_installed:false,
    kernel_release:'6.12.74',other_module_releases:['6.12.73'],rebuild_command:'/opt/veer/veer kfuncs build'});
  assert.equal(missing.length,1);
  for(const part of ['No helper module for 6.12.74','installed for 6.12.73','run /opt/veer/veer kfuncs build'])assert.ok(missing[0].includes(part),missing[0]);

  const failed=helperNotes({compiled:true,loaded:true,available:false,module_installed:true,kernel_release:'6.12.74',reason:'ABI mismatch'});
  assert.equal(failed.length,1);
  assert.ok(failed[0].includes('Helper module unavailable') && failed[0].includes('ABI mismatch'));

  assert.equal(helperNotes({compiled:true,loaded:true,available:true,module_installed:true,kernel_release:'6.12.74'}).length,0);
  assert.equal(helperNotes({compiled:false,loaded:false,available:false,module_installed:false,kernel_release:'6.12.74'}).length,0);
  // Release binaries carry helper support; a host that never installed a module is not nagged.
  assert.equal(helperNotes({compiled:true,loaded:false,available:false,module_installed:false,kernel_release:'6.12.74',
    other_module_releases:[],reason:'not installed'}).length,0);
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
  assert.ok(noteTexts.some((text) => text.includes('Kernel Engine Degraded') && text.includes('TC: ')), noteTexts.join('\n'));
});

function kernelRuntimeAriaLabels(node) {
  const labels = [];
  (function visit(current) {
    if (current.attributes?.['aria-label']) labels.push(current.attributes['aria-label']);
    (current.childNodes || []).forEach(visit);
  })(node);
  return labels;
}

// The harness appends `children` twice (makeNode and createNode), so nodes are deduplicated.
function collectNodes(node, predicate, out = []) {
  if (!node) return out;
  if (predicate(node) && !out.includes(node)) out.push(node);
  (node.childNodes || []).forEach((child) => collectNodes(child, predicate, out));
  return out;
}

test('kernel status details show TCX support and each device\'s native XDP support', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    kernel_capabilities: {
      tc: { available: true },
      tcx_attach: { available: true },
      xdp_generic: { available: true }
    },
    kernel_xdp_native: {
      available: true,
      devices: [
        { name: 'enp6s0f0', type: 'device', native: true, redirect_target: false },
        { name: 'tap100i0', type: 'tuntap', native: true, redirect_target: true },
        { name: 'vmbr0', type: 'bridge', native: false, redirect_target: false }
      ]
    },
    engines: [runtimeEngine({ attachment_api: 'tcx' })]
  });
  app.renderKernelRuntime();

  const dataplane = statusDetailLines(app, 'dataplane');
  assert.ok(dataplane.includes('kernel.status.attachInUse: kernel.status.attachTCX'), dataplane.join('\n'));
  assert.ok(dataplane.includes('kernel.capability.tcx: Available'), dataplane.join('\n'));
  const native = statusDetailLines(app, 'xdpNative');
  assert.ok(native.includes('kernel.capability.xdpNative: enp6s0f0, tap100i0'), native.join('\n'));
  assert.ok(native.includes('kernel.capability.xdpRedirectTarget: tap100i0 · kernel.capability.xdpRedirectTargetHint'), native.join('\n'));
  assert.ok(native.includes('kernel.capability.xdpGenericOnly: vmbr0'), native.join('\n'));
  // The details trigger is a short button that opens the panel, not a dump of every row.
  const trigger = collectNodes(app.el.kernelRuntimeSummary, (node) => String(node.className || '').includes('kernel-runtime-status-trigger'))[0];
  assert.ok(trigger, 'status card must offer the details panel');
  assert.equal(trigger.attributes['aria-haspopup'], 'dialog');
  assert.equal(trigger.attributes['aria-label'], undefined);
});

test('kernel status details call native XDP unknown on a kernel without per-device features', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    kernel_capabilities: { tc: { available: true }, tcx_attach: { available: false, reason: 'TCX attach unavailable' } },
    kernel_xdp_native: { available: false, reason: 'needs Linux 6.3 or later' },
    engines: [runtimeEngine()]
  });
  app.renderKernelRuntime();

  const native = statusDetailLines(app, 'xdpNative');
  assert.deepEqual([...native], ['kernel.capability.xdpNative: common.unknown · needs Linux 6.3 or later']);
  const dataplane = app.kernelRuntimeStatusGroups(app.state.kernelRuntime.data).find((group) => group.id === 'dataplane');
  const tcx = dataplane.rows.find((row) => row.label === 'kernel.capability.tcx');
  assert.equal(tcx.state, 'bad');
  assert.equal(tcx.hint, 'TCX attach unavailable');
  assert.equal(dataplane.open, true);
});

test('kernel status details list every native device instead of cutting the list short', () => {
  const { app } = createHarness();
  const devices = Array.from({ length: 11 }, (_, index) => ({ name: 'tap' + String(100 + index) + 'i0', native: true, redirect_target: true }));
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    kernel_capabilities: { tc: { available: true } },
    kernel_xdp_native: { available: true, devices: devices },
    engines: [runtimeEngine()]
  });
  app.renderKernelRuntime();

  const group = app.kernelRuntimeStatusGroups(app.state.kernelRuntime.data).find((item) => item.id === 'xdpNative');
  assert.equal(group.rows[0].devices.length, 11);
  assert.ok(group.rows[0].devices.includes('tap110i0'));
});

test('kernel status details put warnings first and group the checks', () => {
  const { app } = createHarness();
  const ok = { available: true };
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    available: false,
    available_reason: 'no kernel engine',
    kernel_capabilities: {
      os: 'linux', arch: 'amd64', kernel_release: '7.0.14-29-pve',
      tc: ok, bpf_map_array: ok, bpf_map_hash: { available: false, reason: 'EPERM' },
      netlink: { route_socket: ok, link_list: ok },
      ip_route: { command: ok, path: '/usr/sbin/ip' },
      warnings: ['netlink subscriptions are incomplete', 'ip route command support is incomplete']
    },
    engines: [runtimeEngine()]
  });
  app.renderKernelRuntime();

  const groups = app.kernelRuntimeStatusGroups(app.state.kernelRuntime.data);
  assert.deepEqual([...groups.map((group) => group.id)], ['warnings', 'platform', 'dataplane', 'maps', 'netlink', 'ipRoute']);
  assert.deepEqual([...groups[0].alerts.map((alert) => alert.tone)], ['bad', 'warn', 'warn']);
  const maps = groups.find((group) => group.id === 'maps');
  assert.equal(maps.open, true, 'a group with a failed check opens by itself');
  assert.equal(maps.summary.tone, 'bad');
  const netlink = groups.find((group) => group.id === 'netlink');
  assert.equal(netlink.open, false, 'a group whose checks all pass stays folded');
  assert.equal(netlink.summary.tone, 'ok');
  const trigger = collectNodes(app.el.kernelRuntimeSummary, (node) => String(node.className || '').includes('kernel-runtime-status-trigger'))[0];
  assert.ok(String(trigger.className).includes('is-warning'));
});

test('engine details name the TC attach API and the XDP attach mode', () => {
  const { app } = createHarness();
  const tc = runtimeEngine({ attachment_api: 'tcx', attachment_mode: 'dispatch_v4' });
  const xdp = runtimeEngine({ name: 'xdp', attachment_mode: 'driver' });
  const tcRows = app.kernelRuntimeEngineDetailRows(tc).map((row) => row.label + ': ' + row.value);
  assert.ok(tcRows.includes('kernel.engineDetail.attach: kernel.status.attachTCX'), tcRows.join('\n'));
  assert.ok(tcRows.includes('kernel.engineDetail.program: dispatch_v4'), tcRows.join('\n'));
  const xdpRows = app.kernelRuntimeEngineDetailRows(xdp).map((row) => row.label + ': ' + row.value);
  assert.ok(xdpRows.includes('kernel.engineDetail.xdpMode: runtimeReason.xdpDriverMode'), xdpRows.join('\n'));
});

test('a TC engine attached through tcx is shown as TCX everywhere', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    configured_order: ['tc', 'xdp'],
    kernel_capabilities: { tc: { available: true }, tcx_attach: { available: true }, xdp_generic: { available: true } },
    engines: [runtimeEngine({ attachment_api: 'tcx', pressure_active: true, pressure_level: 'hold' }), runtimeEngine({ name: 'xdp' })]
  });
  app.renderKernelRuntime();

  const summary = collectText(app.el.kernelRuntimeSummary);
  assert.ok(summary.includes('TCX Available'), summary);
  assert.ok(!/\bTC Available\b/.test(summary), summary);
  assert.ok(summary.includes('TCX kernel.pressure.hold'), summary);
  const badges = collectNodes(app.el.kernelRuntimeSummary, (node) => /\bbadge-(tc|xdp)\b/.test(String(node.className || ''))).map((node) => node.textContent);
  assert.deepEqual(badges, ['TCX', 'XDP']);
  const rowBadges = collectNodes(app.el.kernelRuntimeBody, (node) => /\bbadge-(tc|xdp)\b/.test(String(node.className || ''))).map((node) => node.textContent);
  assert.deepEqual(rowBadges, ['TCX', 'XDP']);
  assert.equal(app.kernelEngineLabel('tc'), 'TCX');

  app.state.kernelRuntime.data.engines[0].attachment_api = 'cls_bpf';
  assert.equal(app.kernelEngineLabel('tc'), 'TC');
  app.state.kernelRuntime.data.engines[0].attachment_api = '';
  assert.equal(app.kernelEngineLabel('tc'), 'TC');
});

test('runtime notes render as one list with a title, a time and their own dismiss button', () => {
  const { app } = createHarness();
  app.state.kernelRuntime.data = Object.assign(baseRuntimeData(), {
    last_kernel_retry_at: '15:29:02',
    last_kernel_retry_reason: 'tc attach vmbr2 port tap108i0: interface not found',
    last_kernel_incremental_retry_at: '15:31:12',
    last_kernel_incremental_retry_result: 'recovered 1 rule owner',
    engines: [runtimeEngine()]
  });
  app.renderKernelRuntime();

  const lists = collectNodes(app.el.kernelRuntimeSummary, (node) => String(node.className || '').split(/\s+/).includes('kernel-runtime-notes'));
  assert.equal(lists.length, 1);
  const notes = collectKernelRuntimeNotes(lists[0]);
  assert.equal(notes.length, 2);
  notes.forEach((note) => {
    assert.equal(note.tagName, 'LI');
    const close = collectNodes(note, (node) => String(node.className || '').includes('kernel-runtime-note-close'))[0];
    assert.ok(close && /kernel\.note\.dismiss/.test(close.attributes['aria-label']));
  });
  assert.ok(collectText(notes[0]).includes('15:29:02'));
  assert.ok(collectText(notes[0]).includes('interface not found'));
  // The dismissal key is unchanged, so notes dismissed before this layout stay dismissed.
  app.state.kernelRuntimeDismissedNotes = { 'kernel.note.lastRetry|kernel.note.lastRetry · 15:29:02 · tc attach vmbr2 port tap108i0: interface not found': true };
  app.renderKernelRuntime();
  assert.equal(collectKernelRuntimeNotes(app.el.kernelRuntimeSummary).length, 1);
});
