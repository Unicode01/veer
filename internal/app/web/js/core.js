(function () {
  const $ = (id) => document.getElementById(id);

  const app = {
    $, 
    el: {
      tokenModal: $('tokenModal'),
      tokenInput: $('tokenInput'),
      tokenSubmit: $('tokenSubmit'),
      appRoot: $('app'),
      logoutBtn: $('logoutBtn'),

      ruleForm: $('ruleForm'),
      ruleFormTitle: $('ruleFormTitle'),
      ruleSubmitBtn: $('ruleSubmitBtn'),
      ruleCancelBtn: $('ruleCancelBtn'),
      editRuleId: $('editRuleId'),
      rulesBody: $('rulesBody'),
      noRules: $('noRules'),
      inInterface: $('inInterface'),
      inInterfacePicker: $('inInterfacePicker'),
      inInterfaceOptions: $('inInterfaceOptions'),
      inIP: $('inIP'),
      outInterface: $('outInterface'),
      outInterfacePicker: $('outInterfacePicker'),
      outInterfaceOptions: $('outInterfaceOptions'),
      ruleOutSourceIP: $('ruleOutSourceIP'),
      ruleOutSourceIPOptions: $('ruleOutSourceIPOptions'),
      ruleTransparent: $('ruleTransparent'),
      ruleOutIP: $('outIP'),
      ruleTransparentWarning: $('ruleTransparentWarning'),

      siteForm: $('siteForm'),
      siteFormTitle: $('siteFormTitle'),
      siteSubmitBtn: $('siteSubmitBtn'),
      siteCancelBtn: $('siteCancelBtn'),
      editSiteId: $('editSiteId'),
      sitesBody: $('sitesBody'),
      noSites: $('noSites'),
      siteListenIface: $('siteListenIface'),
      siteListenIfacePicker: $('siteListenIfacePicker'),
      siteListenIfaceOptions: $('siteListenIfaceOptions'),
      siteListenIP: $('siteListenIP'),
      siteBackendSourceIP: $('siteBackendSourceIP'),
      siteBackendSourceIPOptions: $('siteBackendSourceIPOptions'),
      siteTransparent: $('siteTransparent'),
      siteBackendIP: $('siteBackendIP'),
      siteTransparentWarning: $('siteTransparentWarning'),

      rangeForm: $('rangeForm'),
      rangeFormTitle: $('rangeFormTitle'),
      rangeSubmitBtn: $('rangeSubmitBtn'),
      rangeCancelBtn: $('rangeCancelBtn'),
      editRangeId: $('editRangeId'),
      rangesBody: $('rangesBody'),
      noRanges: $('noRanges'),
      rangeInInterface: $('rangeInInterface'),
      rangeInInterfacePicker: $('rangeInInterfacePicker'),
      rangeInInterfaceOptions: $('rangeInInterfaceOptions'),
      rangeInIP: $('rangeInIP'),
      rangeOutInterface: $('rangeOutInterface'),
      rangeOutInterfacePicker: $('rangeOutInterfacePicker'),
      rangeOutInterfaceOptions: $('rangeOutInterfaceOptions'),
      rangeOutSourceIP: $('rangeOutSourceIP'),
      rangeOutSourceIPOptions: $('rangeOutSourceIPOptions'),
      rangeTransparent: $('rangeTransparent'),
      rangeOutIP: $('rangeOutIP'),
      rangeTransparentWarning: $('rangeTransparentWarning'),

      egressNATForm: $('egressNATForm'),
      egressNATFormTitle: $('egressNATFormTitle'),
      egressNATSubmitBtn: $('egressNATSubmitBtn'),
      egressNATCancelBtn: $('egressNATCancelBtn'),
      editEgressNATId: $('editEgressNATId'),
      egressNATsBody: $('egressNATsBody'),
      noEgressNATs: $('noEgressNATs'),
      egressNATParentInterface: $('egressNATParentInterface'),
      egressNATParentPicker: $('egressNATParentPicker'),
      egressNATParentOptions: $('egressNATParentOptions'),
      egressNATChildInterface: $('egressNATChildInterface'),
      egressNATChildPicker: $('egressNATChildPicker'),
      egressNATChildOptions: $('egressNATChildOptions'),
      egressNATOutInterface: $('egressNATOutInterface'),
      egressNATOutPicker: $('egressNATOutPicker'),
      egressNATOutOptions: $('egressNATOutOptions'),
      egressNATOutInterfaceHint: $('egressNATOutInterfaceHint'),
      egressNATOutSourceIP: $('egressNATOutSourceIP'),
      egressNATProtocol: $('egressNATProtocol'),
      egressNATNatType: $('egressNATNatType'),
      egressNATProtocolDropdown: $('egressNATProtocolDropdown'),
      egressNATProtocolTrigger: $('egressNATProtocolTrigger'),
      egressNATProtocolMenu: $('egressNATProtocolMenu'),
      egressNATProtocolTCP: $('egressNATProtocolTCP'),
      egressNATProtocolUDP: $('egressNATProtocolUDP'),
      egressNATProtocolICMP: $('egressNATProtocolICMP'),
      egressNATOutSourceIPOptions: $('egressNATOutSourceIPOptions'),

      workersBody: $('workersBody'),
      noWorkers: $('noWorkers'),

      kernelRuntimeSummary: $('kernelRuntimeSummary'),
      kernelRuntimeBody: $('kernelRuntimeBody'),
      noKernelRuntime: $('noKernelRuntime'),
      ruleStatsBody: $('ruleStatsBody'),
      noRuleStats: $('noRuleStats'),
      siteStatsBody: $('siteStatsBody'),
      noSiteStats: $('noSiteStats'),
      rangeStatsBody: $('rangeStatsBody'),
      noRangeStats: $('noRangeStats'),
      egressNATStatsBody: $('egressNATStatsBody'),
      noEgressNATStats: $('noEgressNATStats'),
      refreshCurrentConnsBtns: Array.from(document.querySelectorAll('.refresh-current-conns-btn')),

      masterVersion: $('masterVersion')
    },
    interfaces: [],
    tags: [],
    state: {
      rules: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10, selectedIds: new Set(), batchDeleting: false },
      sites: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10 },
      ranges: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10 },
      egressNATs: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 },
      workers: { data: [], sortKey: '', sortAsc: true, masterHash: '', page: 1, pageSize: 10 },
      kernelRuntime: { data: null },
      ruleStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20, total: 0 },
      siteStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20 },
      rangeStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20, total: 0 },
      egressNATStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20, total: 0 },
      currentConnsSnapshot: {
        loaded: false,
        rules: {},
        sites: {},
        ranges: {},
        egressNATs: {}
      }
    }
  };

  app.esc = function esc(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  };

  app.escAttr = function escAttr(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\r?\n/g, '&#10;');
  };

  app.encData = function encData(obj) {
    return encodeURIComponent(JSON.stringify(obj));
  };

  app.decData = function decData(text) {
    return JSON.parse(decodeURIComponent(text || ''));
  };

  app.parseIPv4 = function parseIPv4(ip) {
    const text = (ip || '').trim();
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(text)) return null;
    const parts = text.split('.').map((p) => parseInt(p, 10));
    if (parts.length !== 4) return null;
    for (const v of parts) {
      if (Number.isNaN(v) || v < 0 || v > 255) return null;
    }
    return parts;
  };

  app.isValidIPv6 = function isValidIPv6(ip) {
    const text = (ip || '').trim();
    if (!text || text.indexOf(':') < 0 || text.indexOf('%') >= 0) return false;
    try {
      new URL('http://[' + text + ']/');
      return true;
    } catch (err) {
      return false;
    }
  };

  app.isValidIP = function isValidIP(ip) {
    const text = (ip || '').trim();
    return !!app.parseIPv4(text) || app.isValidIPv6(text);
  };

  app.ipFamily = function ipFamily(ip) {
    const text = (ip || '').trim();
    if (app.parseIPv4(text)) return 'ipv4';
    if (app.isValidIPv6(text)) return 'ipv6';
    return '';
  };

  app.isPublicIPv4 = function isPublicIPv4(ip) {
    const p = app.parseIPv4(ip);
    if (!p) return false;
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return false;
    if (p[0] === 169 && p[1] === 254) return false;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
    if (p[0] === 192 && p[1] === 168) return false;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false;
    if (p[0] >= 224) return false;
    return true;
  };

  app.isBridgeInterface = function isBridgeInterface(name) {
    return /^(vmbr|virbr|br|ovs)/i.test((name || '').trim());
  };

  app.transparentAvailability = function transparentAvailability(backendIP) {
    const family = typeof app.ipFamily === 'function' ? app.ipFamily((backendIP || '').trim()) : '';
    if (family === 'ipv6') {
      return {
        supported: false,
        level: 'info',
        text: '透明传输当前仅支持 IPv4 目标；IPv6 目标请关闭透传。',
        needsConfirm: false
      };
    }
    return {
      supported: true,
      level: '',
      text: '',
      needsConfirm: false
    };
  };

  app.buildTransparentWarning = function buildTransparentWarning(transparent, backendIP, outIface, targetLabel) {
    if (!transparent) return { level: '', text: '', needsConfirm: false };

    const ip = (backendIP || '').trim();
    if (!app.parseIPv4(ip)) {
      return {
        level: 'info',
        text: '透传依赖后端使用明确的 IPv4 地址，并且回包必须重新经过本机。',
        needsConfirm: false
      };
    }

    if (app.isPublicIPv4(ip)) {
      const prefix = app.isBridgeInterface(outIface)
        ? '检测到目标是公网 IP，且出接口像桥接接口。'
        : '检测到目标是公网 IP。';
      return {
        level: 'warning',
        text: prefix + ' 如果 ' + targetLabel + ' 默认网关不经过本机（例如上级直路由到 VM、本机只做网桥），透传通常会失败。',
        needsConfirm: true
      };
    }

    return {
      level: 'info',
      text: '透传已开启。请确认 ' + targetLabel + ' 的默认网关或策略路由指向本机，否则回包不会回到本机。',
      needsConfirm: false
    };
  };

  app.applyTransparentWarning = function applyTransparentWarning(node, warning) {
    if (!warning || !warning.text) {
      node.className = 'transparent-warning';
      node.textContent = '';
      return warning;
    }
    node.className = 'transparent-warning is-visible ' + (warning.level === 'warning' ? 'is-warning' : 'is-info');
    node.textContent = warning.text;
    return warning;
  };

  app.confirmTransparentWarning = function confirmTransparentWarning(warning) {
    return !warning || !warning.needsConfirm;
  };

  app.syncTransparentToggleState = function syncTransparentToggleState(input, backendIP) {
    const availability = typeof app.transparentAvailability === 'function'
      ? app.transparentAvailability(backendIP)
      : { supported: true, level: '', text: '', needsConfirm: false };

    if (!input) return availability;

    if (!availability.supported) {
      input.checked = false;
      input.disabled = true;
      input.setAttribute('aria-disabled', 'true');
      if (availability.text) input.setAttribute('title', availability.text);
      else input.removeAttribute('title');
      return availability;
    }

    input.disabled = false;
    input.removeAttribute('aria-disabled');
    input.removeAttribute('title');
    return availability;
  };

  app.syncTransparentSourceIPState = function syncTransparentSourceIPState(input, transparent) {
    if (!input) return;
    if (transparent) {
      input.value = '';
      input.disabled = true;
      input.setAttribute('aria-disabled', 'true');
    } else {
      input.disabled = false;
      input.removeAttribute('aria-disabled');
    }
  };

  app.updateRuleTransparentWarning = function updateRuleTransparentWarning() {
    const el = app.el;
    const availability = app.syncTransparentToggleState(el.ruleTransparent, el.ruleOutIP.value);
    app.syncTransparentSourceIPState(el.ruleOutSourceIP, el.ruleTransparent.checked);
    return app.applyTransparentWarning(
      el.ruleTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(el.ruleTransparent.checked, el.ruleOutIP.value, el.outInterface.value, '后端主机')
        : availability
    );
  };

  app.updateSiteTransparentWarning = function updateSiteTransparentWarning() {
    const el = app.el;
    const availability = app.syncTransparentToggleState(el.siteTransparent, el.siteBackendIP.value);
    app.syncTransparentSourceIPState(el.siteBackendSourceIP, el.siteTransparent.checked);
    return app.applyTransparentWarning(
      el.siteTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(el.siteTransparent.checked, el.siteBackendIP.value, '', '后端主机')
        : availability
    );
  };

  app.updateRangeTransparentWarning = function updateRangeTransparentWarning() {
    const el = app.el;
    const availability = app.syncTransparentToggleState(el.rangeTransparent, el.rangeOutIP.value);
    app.syncTransparentSourceIPState(el.rangeOutSourceIP, el.rangeTransparent.checked);
    return app.applyTransparentWarning(
      el.rangeTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(el.rangeTransparent.checked, el.rangeOutIP.value, el.rangeOutInterface.value, '目标主机')
        : availability
    );
  };

  app.getToken = function getToken() { return localStorage.getItem('forward_token') || ''; };
  app.setToken = function setToken(token) { localStorage.setItem('forward_token', token); };
  app.clearToken = function clearToken() { localStorage.removeItem('forward_token'); };

  app.showTokenModal = function showTokenModal() {
    app.el.appRoot.style.display = 'none';
    app.el.tokenModal.classList.add('active');
    app.el.tokenInput.value = '';
    app.el.tokenInput.focus();
  };

  app.hideTokenModal = function hideTokenModal() {
    app.el.tokenModal.classList.remove('active');
    app.el.appRoot.style.display = 'block';
  };

  app.apiCall = async function apiCall(method, path, body) {
    const opts = {
      method,
      headers: {
        Authorization: 'Bearer ' + app.getToken(),
        'Content-Type': 'application/json'
      }
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(path, opts);
    if (resp.status === 401) {
      app.clearToken();
      app.showTokenModal();
      throw new Error('unauthorized');
    }
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: resp.statusText }));
      const error = new Error(err.error || resp.statusText);
      error.payload = err;
      error.status = resp.status;
      throw error;
    }
    return resp.json();
  };

  app.compareValues = function compareValues(a, b) {
    const va = a == null ? '' : a;
    const vb = b == null ? '' : b;
    if (typeof va === 'number' && typeof vb === 'number') return va - vb;
    return String(va).localeCompare(String(vb), 'zh-CN', { numeric: true, sensitivity: 'base' });
  };

  app.sortByState = function sortByState(arr, st, getter) {
    const out = arr.slice();
    if (!st.sortKey) return out;
    out.sort((a, b) => {
      const r = app.compareValues(getter(a, st.sortKey), getter(b, st.sortKey));
      return st.sortAsc ? r : -r;
    });
    return out;
  };

  app.toggleSort = function toggleSort(st, key) {
    if (st.sortKey === key) {
      if (st.sortAsc) st.sortAsc = false;
      else {
        st.sortKey = '';
        st.sortAsc = true;
      }
    } else {
      st.sortKey = key;
      st.sortAsc = true;
    }
  };

  app.updateSortIndicators = function updateSortIndicators(tableId, st) {
    document.querySelectorAll('#' + tableId + ' thead th.sortable').forEach((th) => {
      th.classList.remove('sort-asc', 'sort-desc', 'tag-filtered');
      if (th.dataset.sort === st.sortKey) th.classList.add(st.sortAsc ? 'sort-asc' : 'sort-desc');
      if (th.dataset.sort === 'tag' && st.filterTag) th.classList.add('tag-filtered');
    });
  };

  app.toggleTableVisibility = function toggleTableVisibility(tableId, visible) {
    const table = app.$(tableId);
    if (!table) return;
    table.style.display = visible ? 'table' : 'none';
    const wrap = table.closest('.table-scroll');
    if (wrap) wrap.style.display = visible ? 'block' : 'none';
  };

  app.statusInfo = function statusInfo(status, enabled) {
    if (enabled === false) return { badge: 'disabled', text: '已禁用' };
    if (status === 'error') return { badge: 'error', text: '异常' };
    if (status === 'draining') return { badge: 'draining', text: '更新中' };
    if (status === 'running') return { badge: 'running', text: '运行中' };
    return { badge: 'stopped', text: '已停止' };
  };

  app.formatBytes = function formatBytes(n) {
    if (!n || n <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = n;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i++;
    }
    const text = v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1);
    return text + ' ' + units[i];
  };

  app.formatSpeed = function formatSpeed(bps) {
    return app.formatBytes(bps) + '/s';
  };

  function interfaceAddressSummary(addrs) {
    if (!Array.isArray(addrs)) return '';
    const items = addrs.filter(Boolean);
    if (!items.length) return '';
    const preview = items.slice(0, 2);
    const suffix = items.length > preview.length ? ', +' + (items.length - preview.length) : '';
    return preview.join(', ') + suffix;
  }

  app.interfaceOptionLabel = function interfaceOptionLabel(iface) {
    if (!iface) return '';
    const name = String(iface.name || '').trim();
    const kind = String(iface.kind || '').trim().toLowerCase();
    const parent = String(iface.parent || '').trim();
    const meta = [];
    if (kind) meta.push(kind);
    if (parent) meta.push('via ' + parent);

    let label = name;
    if (meta.length) label += ' [' + meta.join(' ') + ']';

    const addressText = interfaceAddressSummary(iface.addrs);
    if (addressText) label += ' (' + addressText + ')';
    return label;
  };

  app.interfaceAddresses = function interfaceAddresses(iface) {
    return Array.isArray(iface && iface.addrs) ? iface.addrs.filter(Boolean) : [];
  };

  app.interfaceSearchText = function interfaceSearchText(iface) {
    if (!iface) return '';
    return [
      iface.name,
      iface.kind,
      iface.parent,
      app.interfaceOptionLabel(iface),
      ...app.interfaceAddresses(iface)
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
  };

  app.filterInterfaceItems = function filterInterfaceItems(items, query) {
    const list = Array.isArray(items) ? items.slice() : [];
    const tokens = String(query || '')
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    if (!tokens.length) return list;
    return list.filter((iface) => {
      const haystack = app.interfaceSearchText(iface);
      return tokens.every((token) => haystack.indexOf(token) >= 0);
    });
  };

  app.findInterfaceByName = function findInterfaceByName(name, items) {
    const target = String(name || '').trim();
    const list = Array.isArray(items) ? items : app.interfaces;
    if (!target || !Array.isArray(list)) return null;
    return list.find((iface) => iface && iface.name === target) || null;
  };

  app.findInterfaceByDisplayText = function findInterfaceByDisplayText(text, items) {
    const target = String(text || '').trim();
    const list = Array.isArray(items) ? items : app.interfaces;
    if (!target || !Array.isArray(list)) return null;
    return list.find((iface) => iface && (iface.name === target || app.interfaceOptionLabel(iface) === target)) || null;
  };

  app.getInterfacePickerItems = function getInterfacePickerItems(hiddenEl, options) {
    const opts = options || {};
    const baseItems = Array.isArray(opts.items)
      ? opts.items.slice()
      : (typeof opts.getItems === 'function' ? opts.getItems() : (app.interfaces || [])).slice();
    const seen = Object.create(null);
    const items = [];
    baseItems.forEach((iface) => {
      if (!iface || !iface.name || seen[iface.name]) return;
      seen[iface.name] = true;
      items.push(iface);
    });
    const selectedName = hiddenEl ? String(hiddenEl.value || '').trim() : '';
    if (opts.preserveSelected && selectedName && !seen[selectedName]) {
      const selectedInfo = app.findInterfaceByName(selectedName);
      if (selectedInfo) {
        seen[selectedName] = true;
        items.push(selectedInfo);
      }
    }
    return items;
  };

  app.setInterfacePickerValue = function setInterfacePickerValue(hiddenEl, pickerEl, value, options) {
    const opts = options || {};
    const normalized = String(value || '').trim();
    if (hiddenEl) hiddenEl.value = normalized;
    if (!pickerEl) return null;
    if (!normalized) {
      pickerEl.value = '';
      return null;
    }
    const items = app.getInterfacePickerItems(hiddenEl, opts);
    const iface = app.findInterfaceByName(normalized, items) || app.findInterfaceByName(normalized);
    pickerEl.value = iface ? app.interfaceOptionLabel(iface) : normalized;
    return iface || null;
  };

  app.syncInterfacePickerSelection = function syncInterfacePickerSelection(hiddenEl, pickerEl, options) {
    const opts = options || {};
    const items = app.getInterfacePickerItems(hiddenEl, opts);
    const text = String(pickerEl && pickerEl.value || '').trim();
    if (!hiddenEl) return { value: '', item: null, items: items, text: text };
    if (!text) {
      hiddenEl.value = '';
      return { value: '', item: null, items: items, text: '' };
    }

    const exact = app.findInterfaceByDisplayText(text, items) || app.findInterfaceByDisplayText(text);
    if (exact) {
      hiddenEl.value = exact.name;
      if (pickerEl && opts.commitLabel !== false) pickerEl.value = app.interfaceOptionLabel(exact);
      return { value: exact.name, item: exact, items: items, text: text };
    }

    const matches = app.filterInterfaceItems(items, text);
    if (matches.length === 1) {
      hiddenEl.value = matches[0].name;
      if (pickerEl && opts.commitLabel) pickerEl.value = app.interfaceOptionLabel(matches[0]);
      return { value: matches[0].name, item: matches[0], items: items, text: text, matches: matches };
    }

    hiddenEl.value = '';
    return { value: '', item: null, items: items, text: text, matches: matches };
  };

  app.getInterfaceSubmissionValue = function getInterfaceSubmissionValue(hiddenEl, pickerEl, options) {
    const currentValue = hiddenEl ? String(hiddenEl.value || '').trim() : '';
    const currentText = String(pickerEl && pickerEl.value || '').trim();
    if (!currentText) return currentValue;
    const result = app.syncInterfacePickerSelection(hiddenEl, pickerEl, Object.assign({}, options || {}, { commitLabel: true }));
    if (result && result.value) return result.value;
    return currentText;
  };

  app.populateInterfacePicker = function populateInterfacePicker(hiddenEl, pickerEl, listEl, options) {
    const opts = options || {};
    const items = app.getInterfacePickerItems(hiddenEl, opts);
    if (listEl) {
      app.clearNode(listEl);
      items.forEach((iface) => {
        const opt = document.createElement('option');
        opt.value = app.interfaceOptionLabel(iface);
        opt.label = iface.name;
        listEl.appendChild(opt);
      });
    }
    if (pickerEl) {
      pickerEl.disabled = !!opts.disabled;
      if (opts.disabled) pickerEl.setAttribute('aria-disabled', 'true');
      else pickerEl.removeAttribute('aria-disabled');
      if (Object.prototype.hasOwnProperty.call(opts, 'placeholder')) {
        const placeholder = opts.placeholder == null ? '' : String(opts.placeholder);
        pickerEl.placeholder = placeholder;
      }
    }
    const currentValue = hiddenEl ? String(hiddenEl.value || '').trim() : '';
    const currentInItems = currentValue ? app.findInterfaceByName(currentValue, items) : null;
    if (currentValue && (opts.preserveSelected || currentInItems)) {
      app.setInterfacePickerValue(hiddenEl, pickerEl, currentValue, opts);
    } else {
      if (hiddenEl && currentValue && !opts.preserveSelected) hiddenEl.value = '';
      if (pickerEl && !opts.preserveText) pickerEl.value = '';
    }
    return items;
  };

  app.addSelectPlaceholderOption = function addSelectPlaceholderOption(sel, label, options) {
    if (!sel) return null;
    const opts = options || {};
    const opt = document.createElement('option');
    opt.value = opts.value == null ? '__placeholder__' : String(opts.value);
    opt.textContent = label == null ? '' : String(label);
    if (opts.disabled !== false) opt.disabled = true;
    if (opts.hidden) opt.hidden = true;
    sel.appendChild(opt);
    return opt;
  };

  app.populateInterfaceSelectFiltered = function populateInterfaceSelectFiltered(sel, selected, options) {
    if (!sel) return;
    const opts = options || {};
    const current = selected == null ? sel.value : selected;
    const baseItems = Array.isArray(opts.items) ? opts.items.slice() : (app.interfaces || []).slice();
    const filteredItems = app.filterInterfaceItems(baseItems, opts.query);
    const unspecifiedText = typeof app.t === 'function' ? app.t('common.unspecified') : 'Unspecified';

    while (sel.firstChild) sel.removeChild(sel.firstChild);
    {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = unspecifiedText;
      sel.appendChild(opt);
    }
    filteredItems.forEach((iface) => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      opt.textContent = app.interfaceOptionLabel(iface);
      sel.appendChild(opt);
    });
    if (opts.preserveSelected && current) {
      const hasCurrent = Array.from(sel.options || []).some((option) => option.value === current);
      if (!hasCurrent) {
        const currentInfo = baseItems.find((iface) => iface && iface.name === current) ||
          (app.interfaces || []).find((iface) => iface && iface.name === current);
        const opt = document.createElement('option');
        opt.value = current;
        opt.textContent = currentInfo ? app.interfaceOptionLabel(currentInfo) : current;
        sel.appendChild(opt);
      }
    }
    const hasSelectableOption = Array.from(sel.options || []).some((option) => option && option.value);
    if (!hasSelectableOption && String(opts.query || '').trim()) {
      app.addSelectPlaceholderOption(
        sel,
        typeof app.t === 'function' ? app.t('interface.search.noResults') : 'No matching interfaces',
        { value: '__no_matching_interfaces__' }
      );
    }
    const resolved = current && Array.from(sel.options || []).some((option) => option.value === current) ? current : '';
    sel.value = resolved;
  };

  app.populateInterfaceSelect = function populateInterfaceSelect(sel, selected) {
    app.populateInterfaceSelectFiltered(sel, selected, { preserveSelected: true });
  };

  app.populateIPSelect = function populateIPSelect(ifaceSel, ipSel, selected) {
    const ifaceName = ifaceSel.value;
    while (ipSel.firstChild) ipSel.removeChild(ipSel.firstChild);
    {
      const opt = document.createElement('option');
      opt.value = '0.0.0.0';
      opt.textContent = '0.0.0.0 (All)';
      ipSel.appendChild(opt);
    }
    if (!ifaceName) {
      app.interfaces.forEach((iface) => {
        app.interfaceAddresses(iface).forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr + ' (' + iface.name + ')';
          ipSel.appendChild(o);
        });
      });
    } else {
      const iface = app.interfaces.find((i) => i.name === ifaceName);
      if (iface) {
        app.interfaceAddresses(iface).forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr;
          ipSel.appendChild(o);
        });
      }
    }
    if (selected) ipSel.value = selected;
  };

  app.populateSiteListenIP = function populateSiteListenIP(ifaceSel, ipSel, selected) {
    const ifaceName = ifaceSel.value;
    while (ipSel.firstChild) ipSel.removeChild(ipSel.firstChild);
    {
      const opt = document.createElement('option');
      opt.value = '0.0.0.0';
      opt.textContent = '0.0.0.0 (All)';
      ipSel.appendChild(opt);
    }
    if (!ifaceName) {
      app.interfaces.forEach((iface) => {
        app.interfaceAddresses(iface).forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr + ' (' + iface.name + ')';
          ipSel.appendChild(o);
        });
      });
    } else {
      const iface = app.interfaces.find((i) => i.name === ifaceName);
      if (iface) {
        app.interfaceAddresses(iface).forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr;
          ipSel.appendChild(o);
        });
      }
    }
    if (selected) ipSel.value = selected;
  };

  app.populateTagSelect = function populateTagSelect(sel, selected) {
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'Unspecified';
      sel.appendChild(opt);
    }
    app.tags.forEach((tag) => {
      const opt = document.createElement('option');
      opt.value = tag;
      opt.textContent = tag;
      sel.appendChild(opt);
    });
    sel.value = selected || '';
  };

  app.loadTags = async function loadTags() {
    try {
      app.tags = await app.apiCall('GET', '/api/tags');
      app.populateTagSelect(app.$('ruleTag'), app.$('ruleTag').value);
      app.populateTagSelect(app.$('siteTag'), app.$('siteTag').value);
      app.populateTagSelect(app.$('rangeTag'), app.$('rangeTag').value);
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load tags:', e);
    }
  };

  app.loadInterfaces = async function loadInterfaces() {
    try {
      const el = app.el;
      app.interfaces = await app.apiCall('GET', '/api/interfaces');
      if (typeof app.refreshRuleInterfaceSelectors === 'function') app.refreshRuleInterfaceSelectors();
      else {
        app.populateInterfaceSelect(el.inInterface);
        app.populateInterfaceSelect(el.outInterface);
        app.populateIPSelect(el.inInterface, el.inIP, el.inIP.value);
      }
      if (typeof app.refreshSiteInterfaceSelectors === 'function') app.refreshSiteInterfaceSelectors();
      else {
        app.populateInterfaceSelect(el.siteListenIface);
        app.populateSiteListenIP(el.siteListenIface, el.siteListenIP, el.siteListenIP.value);
      }
      if (typeof app.refreshRangeInterfaceSelectors === 'function') app.refreshRangeInterfaceSelectors();
      else {
        app.populateInterfaceSelect(el.rangeInInterface);
        app.populateInterfaceSelect(el.rangeOutInterface);
        app.populateIPSelect(el.rangeInInterface, el.rangeInIP, el.rangeInIP.value);
      }
      if (typeof app.refreshRuleSourceIPOptions === 'function') {
        app.refreshRuleSourceIPOptions(el.ruleOutSourceIP.value);
      } else if (typeof app.populateSourceIPSelect === 'function') {
        app.populateSourceIPSelect(el.outInterface, el.ruleOutSourceIP, el.ruleOutSourceIP.value);
      }
      if (typeof app.refreshSiteBackendSourceIPOptions === 'function') {
        app.refreshSiteBackendSourceIPOptions(el.siteBackendSourceIP.value);
      } else if (typeof app.populateSourceIPSelect === 'function') {
        app.populateSourceIPSelect(null, el.siteBackendSourceIP, el.siteBackendSourceIP.value);
      }
      if (typeof app.refreshRangeSourceIPOptions === 'function') {
        app.refreshRangeSourceIPOptions(el.rangeOutSourceIP.value);
      } else if (typeof app.populateSourceIPSelect === 'function') {
        app.populateSourceIPSelect(el.rangeOutInterface, el.rangeOutSourceIP, el.rangeOutSourceIP.value);
      }
      if (typeof app.populateSourceIPSelect === 'function') {
        app.populateSourceIPSelect(el.egressNATOutInterface, el.egressNATOutSourceIP, el.egressNATOutSourceIP.value);
      }
      if (typeof app.populateEgressNATInterfaceSelectors === 'function') {
        app.populateEgressNATInterfaceSelectors();
      }
      app.updateRuleTransparentWarning();
      app.updateSiteTransparentWarning();
      app.updateRangeTransparentWarning();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load interfaces:', e);
    }
  };

  window.ForwardApp = app;
})();
