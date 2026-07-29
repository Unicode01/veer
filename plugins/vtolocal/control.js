plugin.capabilities(['vtap', 'local_route', 'net_admin', 'control']);
pipeline.handoff({
  id: 'vtolocal0',
  description: 'Single Linux L3 boundary used by host routes and the bidirectional Veer pipeline.'
});
plugin.resource({
  id: 'links',
  description: 'Local dummy interface and its route/address bindings.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'runtime_apply',
  max_records: 16,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'status',
  description: 'Last applied local handoff status.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 16,
  max_record_bytes: 16384
});
plugin.action({
  id: 'apply',
  description: 'Apply a vtolocal binding from payload or stored profile.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 16384
});
plugin.action({
  id: 'teardown',
  description: 'Remove plugin-owned state and delete the dummy only when this plugin created it.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 4096
});
plugin.service({
  id: 'local.handoff',
  version: '1.0.0',
  description: 'Linux-local L3 handoff and route service.',
  actions: ['apply', 'teardown'],
  resources: ['links', 'status']
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: 'f99d932f2258f162d26159868ee2cf6259da5e608d1fdd86c1b795302d001ba5',
  page: 'vtolocal',
  page_title: 'VToLocal',
  resources: [
    {resource: 'links', methods: ['list', 'create', 'update']},
    {resource: 'status', methods: ['list']}
  ],
  actions: ['teardown']
});

exports.onReconcile = function () {
  applyStoredLinks();
  armRepairTimer();
};

exports.onDeactivate = function () {
  timer.clear('vtolocal_repair');
  var records = resources.list('links') || [];
  var failures = [];
  for (var i = 0; i < records.length; i++) {
    if (!records[i]) continue;
    try {
      teardownLink(loadProfile({profile_key: records[i].key}));
    } catch (e) {
      failures.push(token(records[i].key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (failures.length) throw new Error('VToLocal deactivate cleanup failed: ' + failures.join('; '));
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'links') return;
  var records = ctx.records || [];
  try {
    applyRecords(records, true);
  } finally {
    armRepairTimer(mergedLinkRecords(records));
  }
};

exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== 'vtolocal_repair') return;
  applyStoredLinks();
  armRepairTimer();
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply') {
    var profile = loadProfile(ctx.payload || {});
    setRecordIfChanged('links', profile.profile_key, profile, true);
    applyProfile(profile);
    armRepairTimer();
    return;
  }
  if (action === 'teardown') {
    teardownLink(loadProfile(ctx.payload || {}));
    armRepairTimer();
    return;
  }
  throw new Error('unsupported action ' + action);
};

function teardownLink(teardown) {
  var previous = previousStatus(teardown.profile_key);
  resources.set('links', teardown.profile_key, teardown, false);
  var previousTeardown = teardownPreviousState(previous);
  var cleanupErrors = cleanupManagedState(previousTeardown, teardownProfile(teardown));
  var deleteError = '';
  var deleteTarget = managedLinkProven(previousTeardown) ? safeIfaceName(previousTeardown.local_interface || '') : '';
  var deleteSkipped = !deleteTarget;
  if (deleteTarget) {
    try {
      net.link.delete(deleteTarget);
    } catch (e) {
      deleteError = errorMessage(e);
    }
  }
  var status = {
    phase: 'deleted',
    profile_key: teardown.profile_key,
    local_interface: deleteTarget || teardown.local_interface,
    cleanup_errors: cleanupErrors,
    managed_link: previousTeardown.managed_link === true || !!deleteTarget,
    link_delete_skipped: deleteSkipped
  };
  if (deleteError) {
    status.phase = 'delete_failed';
    status.last_error = deleteError;
  } else if (deleteSkipped) {
    status.link_delete_skip_reason = linkDeleteSkipReason(previousTeardown);
  } else if (cleanupErrors.length) {
    status.phase = 'delete_partial';
    status.last_error = cleanupErrors.join('; ');
  }
  setRecordIfChanged('status', teardown.profile_key, status, false);
}

function applyStoredLinks() {
  applyRecords(resources.list('links') || [], false);
}

function armRepairTimer(records) {
  var links = records || resources.list('links') || [];
  for (var i = 0; i < links.length; i++) {
    if (links[i] && links[i].enabled !== false) {
      timer.setInterval('vtolocal_repair', 2000, {});
      return;
    }
  }
  timer.clear('vtolocal_repair');
}

function mergedLinkRecords(records) {
  var out = [];
  var positions = {};
  var stored = resources.list('links') || [];
  for (var i = 0; i < stored.length; i++) {
    if (!stored[i]) continue;
    positions[token(stored[i].key || 'default')] = out.length;
    out.push(stored[i]);
  }
  for (var j = 0; j < (records || []).length; j++) {
    if (!records[j]) continue;
    var key = token(records[j].key || 'default');
    if (Object.prototype.hasOwnProperty.call(positions, key)) {
      out[positions[key]] = records[j];
    } else {
      positions[key] = out.length;
      out.push(records[j]);
    }
  }
  return out;
}

function applyRecords(records, reportErrors) {
  var failures = [];
  for (var i = 0; i < records.length; i++) {
    if (!records[i]) continue;
    if (records[i].enabled === false) {
      disableLinkRuntime(records[i]);
      continue;
    }
    try {
      applyProfile(normalizeProfile(records[i].key, records[i].data || {}));
    } catch (e) {
      markApplyError(records[i].key, e);
      failures.push(token(records[i].key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (reportErrors && failures.length) {
    throw new Error('failed to apply ' + failures.length + ' VToLocal link record(s): ' + failures.join('; '));
  }
}

function disableLinkRuntime(record) {
  var key = token(record && record.key || 'default');
  var raw = record && record.data ? record.data : {};
  teardownLink(normalizeProfile(key, raw));
}

function markApplyError(key, error) {
  key = token(key || 'default');
  var previous = previousStatus(key);
  previous.phase = 'error';
  previous.profile_key = key;
  previous.last_error = errorMessage(error);
  setRecordIfChanged('status', key, previous, false);
}

function loadProfile(payload) {
  var key = token(payload.profile_key || payload.profile || payload.key || 'default');
  var record = resources.get('links', key);
  var data = record && record.data ? record.data : {};
  return normalizeProfile(key, merge(data, payload || {}));
}

function applyProfile(profile) {
  var previous = previousStatus(profile.profile_key);
  var result = net.link.ensureDummy({
    name: profile.local_interface,
    mtu: profile.mtu,
    up: true
  });
  var sameManagedLink = managedLinkProven(previous) && safeIfaceName(previous.local_interface || '') === profile.local_interface;
  var cleanupErrors = cleanupManagedState(previous, profile);
  cleanupErrors = cleanupErrors.concat(cleanupManagedLinkReplacement(previous, profile));
  replaceAddrs(profile.local_interface, profile.addresses);
  replaceRoutes(profile.local_interface, profile.routes);
  setRecordIfChanged('status', profile.profile_key, {
    phase: 'applied',
    profile_key: profile.profile_key,
    local_interface: result.link.name,
    local_ifindex: result.link.ifindex,
    mtu: profile.mtu,
    addresses: profile.addresses,
    routes: profile.routes,
    cleanup_errors: cleanupErrors,
    managed_link: result.created === true || sameManagedLink,
    route_count: profile.routes.length,
    pipeline_ingress_interface: profile.local_interface,
    pipeline_egress_interface: profile.local_interface
  });
}

function previousStatus(key) {
  var record = resources.get('status', key);
  return record && record.data ? record.data : {};
}

function cleanupManagedState(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (previous.phase !== 'applied' && previous.phase !== 'error') return errors;
  cleanupRemovedAddrs(previous.local_interface, previous.addresses, profile.local_interface, profile.addresses, errors);
  cleanupRemovedRoutes(previous.local_interface, previous.routes, profile.local_interface, profile.routes, errors);
  return errors;
}

function cleanupManagedLinkReplacement(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (!managedLinkProven(previous) || !managedLinkChanged(previous, profile)) return errors;
  var local = safeIfaceName(previous.local_interface || '');
  if (!local) return errors;
  try {
    net.link.delete(local);
  } catch (e) {
    errors.push('old dummy ' + local + ': ' + errorMessage(e));
  }
  return errors;
}

function managedLinkChanged(previous, profile) {
  previous = previous || {};
  profile = profile || {};
  var previousLocal = safeIfaceName(previous.local_interface || '');
  if (!previousLocal) return false;
  return previousLocal !== safeIfaceName(profile.local_interface || '');
}

function managedLinkProven(previous) {
  previous = previous || {};
  if (previous.phase === 'deleted') return false;
  return previous.managed_link === true;
}

function linkDeleteSkipReason(previous) {
  previous = previous || {};
  if (previous.managed_link === true && previous.phase === 'deleted') {
    return 'previous vtolocal status already deleted this plugin-managed dummy';
  }
  return 'no previous vtolocal status proves this dummy was plugin-managed';
}

function teardownProfile(profile) {
  return {
    local_interface: profile.local_interface,
    addresses: [],
    routes: []
  };
}

function teardownPreviousState(previous) {
  previous = previous || {};
  return {
    phase: previous.phase || '',
    managed_link: previous.managed_link === true,
    local_interface: previous.local_interface || '',
    addresses: Array.isArray(previous.addresses) ? previous.addresses : [],
    routes: Array.isArray(previous.routes) ? previous.routes : []
  };
}

function cleanupRemovedAddrs(iface, previousAddrs, nextIface, nextAddrs, errors) {
  iface = safeIfaceName(iface);
  if (!iface) return;
  var previous = cidrList(previousAddrs);
  if (!previous.length) return;
  nextIface = safeIfaceName(nextIface);
  var next = iface === nextIface ? cidrSet(cidrList(nextAddrs)) : {};
  for (var i = 0; i < previous.length; i++) {
    var cidr = previous[i];
    if (next[cidr]) continue;
    try {
      net.addr.delete({interface: iface, cidr: cidr});
    } catch (e) {
      errors.push('addr ' + iface + ' ' + cidr + ': ' + errorMessage(e));
    }
  }
}

function cleanupRemovedRoutes(previousDefaultDev, previousRoutes, nextDefaultDev, nextRoutes, errors) {
  if (!Array.isArray(previousRoutes) || !previousRoutes.length) return;
  var next = routeSet(nextDefaultDev, nextRoutes);
  for (var i = 0; i < previousRoutes.length; i++) {
    var req = routeRequest(previousDefaultDev, previousRoutes[i]);
    if (!req || next[routeKey(req)]) continue;
    try {
      net.route.delete(req);
    } catch (e) {
      errors.push('route ' + req.dst + ' dev ' + req.dev + ': ' + errorMessage(e));
    }
  }
}

function replaceAddrs(iface, addrs) {
  for (var i = 0; i < addrs.length; i++) {
    net.addr.replace({interface: iface, cidr: addrs[i]});
  }
}

function replaceRoutes(defaultDev, routes) {
  for (var i = 0; i < routes.length; i++) {
    var req = routeRequest(defaultDev, routes[i]);
    if (req) net.route.replace(req);
  }
}

function routeSet(defaultDev, routes) {
  var out = {};
  if (!Array.isArray(routes)) return out;
  for (var i = 0; i < routes.length; i++) {
    var req = routeRequest(defaultDev, routes[i]);
    if (req) out[routeKey(req)] = true;
  }
  return out;
}

function routeRequest(defaultDev, route) {
  route = route || {};
  var dst = route.dst || route.destination || route.cidr;
  if (!dst) return null;
  var dev = safeIfaceName(route.dev || route.interface || defaultDev);
  if (!dev) return null;
  return {
    dst: text(dst),
    dev: dev,
    gateway: route.gateway || route.gw || '',
    src: route.src || route.source || '',
    table: intValue(route.table, 0, 2147483647, 0),
    metric: intValue(route.metric, 0, 2147483647, 0),
    scope: routeScope(route, dst)
  };
}

function routeKey(req) {
  return [req.dst, req.dev, req.gateway || '', req.src || '', req.table || 0, req.metric || 0, req.scope || 0].join('|');
}

function cidrSet(values) {
  var out = {};
  for (var i = 0; i < values.length; i++) out[values[i]] = true;
  return out;
}

function setRecordIfChanged(resource, key, data, enabled) {
  var current = resources.get(resource, key);
  var currentData = current && current.data ? current.data : null;
  var currentEnabled = current ? current.enabled !== false : null;
  var nextEnabled = enabled !== false;
  if (current && currentEnabled === nextEnabled && stableJSON(currentData) === stableJSON(data)) return;
  resources.set(resource, key, data, nextEnabled);
}

function stableJSON(value) {
  if (value && typeof value === 'object') value = JSON.parse(JSON.stringify(value));
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (e) {
      // Keep non-JSON strings comparable as plain values.
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) delete value.updated_at;
  return JSON.stringify(sortObject(value));
}

function sortObject(value) {
  if (Array.isArray(value)) {
    var out = [];
    for (var i = 0; i < value.length; i++) out.push(sortObject(value[i]));
    return out;
  }
  if (!value || typeof value !== 'object') return value;
  var keys = [];
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) keys.push(k);
  }
  keys.sort();
  var obj = {};
  for (var j = 0; j < keys.length; j++) {
    if (keys[j] === 'updated_at') continue;
    obj[keys[j]] = sortObject(value[keys[j]]);
  }
  return obj;
}

function routeScope(route, dst) {
  if (route.scope != null && route.scope !== '') return intValue(route.scope, 0, 255, 0);
  if (route.gateway || route.gw || isDefaultRoute(dst)) return 0;
  return 253;
}

function isDefaultRoute(dst) {
  dst = lower(dst);
  return dst === '' || dst === 'default' || dst === '0.0.0.0/0' || dst === '::/0';
}

function normalizeProfile(key, raw) {
  raw = raw || {};
  var localInterface = text(raw.local_interface || 'veerlocal0');
  return {
    profile_key: key,
    local_interface: ifaceName(localInterface, 'local_interface'),
    mtu: intValue(raw.mtu, 576, 65535, 1492),
    addresses: cidrList(raw.addresses || raw.local_addresses || []),
    routes: Array.isArray(raw.routes) ? raw.routes : []
  };
}

function cidrList(value) {
  if (value == null || value === '') return [];
  if (Array.isArray(value)) {
    var out = [];
    for (var i = 0; i < value.length; i++) {
      var item = text(value[i]);
      if (item) out.push(item);
    }
    return out;
  }
  return [text(value)].filter(Boolean);
}

function ifaceName(value, label) {
  value = text(value);
  if (!value || utf8ByteLength(value) > 15 || /[\/\\\s\u0000]/.test(value)) {
    throw new Error(label + ' contains invalid characters or exceeds 15 bytes');
  }
  return value;
}

function safeIfaceName(value) {
  try {
    value = text(value);
    if (!value) return '';
    return ifaceName(value, 'interface');
  } catch (e) {
    return '';
  }
}

function utf8ByteLength(value) {
  var n = 0;
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code <= 0x7f) n += 1;
    else if (code <= 0x7ff) n += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

function intValue(value, min, max, fallback) {
  var n = parseInt(value, 10);
  if (!isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function token(value) {
  return lower(value || 'default').replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'default';
}

function text(value) {
  return String(value == null ? '' : value).trim();
}

function lower(value) {
  return text(value).toLowerCase();
}

function merge(a, b) {
  var out = {};
  var k;
  for (k in a) if (Object.prototype.hasOwnProperty.call(a, k)) out[k] = a[k];
  for (k in b) if (Object.prototype.hasOwnProperty.call(b, k)) out[k] = b[k];
  return out;
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}
