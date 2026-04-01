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
      inIP: $('inIP'),
      outInterface: $('outInterface'),
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
      rangeInIP: $('rangeInIP'),
      rangeOutInterface: $('rangeOutInterface'),
      rangeOutSourceIP: $('rangeOutSourceIP'),
      rangeOutSourceIPOptions: $('rangeOutSourceIPOptions'),
      rangeTransparent: $('rangeTransparent'),
      rangeOutIP: $('rangeOutIP'),
      rangeTransparentWarning: $('rangeTransparentWarning'),

      workersBody: $('workersBody'),
      noWorkers: $('noWorkers'),

      ruleStatsBody: $('ruleStatsBody'),
      noRuleStats: $('noRuleStats'),
      siteStatsBody: $('siteStatsBody'),
      noSiteStats: $('noSiteStats'),
      rangeStatsBody: $('rangeStatsBody'),
      noRangeStats: $('noRangeStats'),
      refreshCurrentConnsBtns: Array.from(document.querySelectorAll('.refresh-current-conns-btn')),

      masterVersion: $('masterVersion')
    },
    interfaces: [],
    tags: [],
    state: {
      rules: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10, selectedIds: new Set(), batchDeleting: false },
      sites: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10 },
      ranges: { data: [], sortKey: '', sortAsc: true, filterTag: '', page: 1, pageSize: 10 },
      workers: { data: [], sortKey: '', sortAsc: true, masterHash: '', page: 1, pageSize: 10 },
      ruleStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20, total: 0 },
      siteStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20 },
      rangeStats: { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 20, total: 0 },
      currentConnsSnapshot: {
        loaded: false,
        rules: {},
        sites: {},
        ranges: {}
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
    app.syncTransparentSourceIPState(el.ruleOutSourceIP, el.ruleTransparent.checked);
    return app.applyTransparentWarning(
      el.ruleTransparentWarning,
      app.buildTransparentWarning(el.ruleTransparent.checked, el.ruleOutIP.value, el.outInterface.value, '后端主机')
    );
  };

  app.updateSiteTransparentWarning = function updateSiteTransparentWarning() {
    const el = app.el;
    app.syncTransparentSourceIPState(el.siteBackendSourceIP, el.siteTransparent.checked);
    return app.applyTransparentWarning(
      el.siteTransparentWarning,
      app.buildTransparentWarning(el.siteTransparent.checked, el.siteBackendIP.value, '', '后端主机')
    );
  };

  app.updateRangeTransparentWarning = function updateRangeTransparentWarning() {
    const el = app.el;
    app.syncTransparentSourceIPState(el.rangeOutSourceIP, el.rangeTransparent.checked);
    return app.applyTransparentWarning(
      el.rangeTransparentWarning,
      app.buildTransparentWarning(el.rangeTransparent.checked, el.rangeOutIP.value, el.rangeOutInterface.value, '目标主机')
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

  app.populateInterfaceSelect = function populateInterfaceSelect(sel, selected) {
    const current = sel.value;
    while (sel.firstChild) sel.removeChild(sel.firstChild);
    {
      const opt = document.createElement('option');
      opt.value = '';
      opt.textContent = 'Unspecified';
      sel.appendChild(opt);
    }
    app.interfaces.forEach((iface) => {
      const opt = document.createElement('option');
      opt.value = iface.name;
      opt.textContent = iface.name + ' (' + iface.addrs.join(', ') + ')';
      sel.appendChild(opt);
    });
    sel.value = selected || current || '';
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
        iface.addrs.forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr + ' (' + iface.name + ')';
          ipSel.appendChild(o);
        });
      });
    } else {
      const iface = app.interfaces.find((i) => i.name === ifaceName);
      if (iface) {
        iface.addrs.forEach((addr) => {
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
        iface.addrs.forEach((addr) => {
          const o = document.createElement('option');
          o.value = addr;
          o.textContent = addr + ' (' + iface.name + ')';
          ipSel.appendChild(o);
        });
      });
    } else {
      const iface = app.interfaces.find((i) => i.name === ifaceName);
      if (iface) {
        iface.addrs.forEach((addr) => {
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
      app.populateInterfaceSelect(el.inInterface);
      app.populateInterfaceSelect(el.outInterface);
      app.populateInterfaceSelect(el.siteListenIface);
      app.populateInterfaceSelect(el.rangeInInterface);
      app.populateInterfaceSelect(el.rangeOutInterface);
      app.populateIPSelect(el.inInterface, el.inIP, el.inIP.value);
      app.populateIPSelect(el.rangeInInterface, el.rangeInIP, el.rangeInIP.value);
      app.populateSiteListenIP(el.siteListenIface, el.siteListenIP, el.siteListenIP.value);
      if (typeof app.populateSourceIPSelect === 'function') {
        app.populateSourceIPSelect(el.outInterface, el.ruleOutSourceIP, el.ruleOutSourceIP.value);
        app.populateSourceIPSelect(null, el.siteBackendSourceIP, el.siteBackendSourceIP.value);
        app.populateSourceIPSelect(el.rangeOutInterface, el.rangeOutSourceIP, el.rangeOutSourceIP.value);
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
