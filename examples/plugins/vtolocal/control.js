plugin.capabilities(['vtap', 'local_route', 'net_admin', 'control']);
plugin.virtualInterface({
  id: 'vtolocal0',
  type: 'logical',
  description: 'Logical local-to-fvtap handoff. The real ingress side is the configured vtap peer interface.'
});
plugin.resource({
  id: 'links',
  description: 'Local veth pair and optional route/address bindings.',
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
  description: 'Delete the configured host-side veth link. Deleting one side removes the pair.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 4096
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: 'cc0a4f4cb9b2462865efa055b5364a09d700fe75a1740e870eb78e48958b6222',
  page: 'vtolocal',
  page_title: 'VToLocal'
});

exports.onReconcile = function () {
  applyStoredLinks();
  armRepairTimer();
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
    var teardown = loadProfile(ctx.payload || {});
    var previous = previousStatus(teardown.profile_key);
    resources.set('links', teardown.profile_key, teardown, false);
    var previousTeardown = teardownPreviousState(previous, teardown);
    var cleanupErrors = cleanupManagedState(previousTeardown, teardownProfile(teardown));
    var deleteError = '';
    var deleteTarget = managedLinkProven(previousTeardown) ? safeIfaceName(previousTeardown.host_interface || '') : '';
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
      host_interface: deleteTarget || teardown.host_interface,
      vtap_interface: previousTeardown.vtap_interface || teardown.vtap_interface,
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
    armRepairTimer();
    return;
  }
  throw new Error('unsupported action ' + action);
};

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
  setRecordIfChanged('status', key, {
    phase: 'disabled',
    profile_key: key,
    host_interface: safeIfaceName(raw.host_interface || raw.host || raw.local_interface || ''),
    vtap_interface: safeIfaceName(raw.vtap_interface || raw.vtap || raw.peer || '')
  }, false);
}

function markApplyError(key, error) {
  key = token(key || 'default');
  setRecordIfChanged('status', key, {
    phase: 'error',
    profile_key: key,
    last_error: errorMessage(error)
  }, false);
}

function loadProfile(payload) {
  var key = token(payload.profile_key || payload.profile || payload.key || 'default');
  var record = resources.get('links', key);
  var data = record && record.data ? record.data : {};
  return normalizeProfile(key, merge(data, payload || {}));
}

function applyProfile(profile) {
  var previous = previousStatus(profile.profile_key);
  var cleanupErrors = cleanupManagedLinkReplacement(previous, profile);
  var pair = net.link.ensureVeth({
    host: profile.host_interface,
    peer: profile.vtap_interface,
    mtu: profile.mtu,
    up: true
  });
  cleanupErrors = cleanupErrors.concat(cleanupManagedState(previous, profile));
  replaceAddrs(profile.host_interface, profile.host_addresses);
  replaceAddrs(profile.vtap_interface, profile.vtap_addresses);
  replaceRoutes(profile.host_interface, profile.routes);
  setRecordIfChanged('status', profile.profile_key, {
    phase: 'applied',
    profile_key: profile.profile_key,
    host_interface: pair.host.name,
    host_ifindex: pair.host.ifindex,
    vtap_interface: pair.peer.name,
    vtap_ifindex: pair.peer.ifindex,
    mtu: profile.mtu,
    host_addresses: profile.host_addresses,
    vtap_addresses: profile.vtap_addresses,
    routes: profile.routes,
    cleanup_errors: cleanupErrors,
    managed_link: true,
    route_count: profile.routes.length,
    egress_nat_parent_interface: profile.vtap_interface
  });
}

function previousStatus(key) {
  var record = resources.get('status', key);
  return record && record.data ? record.data : {};
}

function cleanupManagedState(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (!managedLinkProven(previous)) return errors;
  if (managedLinkChanged(previous, profile)) return errors;
  cleanupRemovedAddrs(previous.host_interface, previous.host_addresses, profile.host_interface, profile.host_addresses, errors);
  cleanupRemovedAddrs(previous.vtap_interface, previous.vtap_addresses, profile.vtap_interface, profile.vtap_addresses, errors);
  cleanupRemovedRoutes(previous.host_interface, previous.routes, profile.host_interface, profile.routes, errors);
  return errors;
}

function cleanupManagedLinkReplacement(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (!managedLinkProven(previous) || !managedLinkChanged(previous, profile)) return errors;
  var host = safeIfaceName(previous.host_interface || '');
  if (!host) return errors;
  try {
    net.link.delete(host);
  } catch (e) {
    errors.push('old veth ' + host + ': ' + errorMessage(e));
  }
  return errors;
}

function managedLinkChanged(previous, profile) {
  previous = previous || {};
  profile = profile || {};
  var previousHost = safeIfaceName(previous.host_interface || '');
  var previousVTap = safeIfaceName(previous.vtap_interface || '');
  if (!previousHost || !previousVTap) return false;
  return previousHost !== safeIfaceName(profile.host_interface || '') ||
    previousVTap !== safeIfaceName(profile.vtap_interface || '');
}

function managedLinkProven(previous) {
  previous = previous || {};
  if (previous.phase === 'deleted') return false;
  return previous.managed_link === true || previous.phase === 'applied';
}

function linkDeleteSkipReason(previous) {
  previous = previous || {};
  if (previous.managed_link === true && previous.phase === 'deleted') {
    return 'previous vtolocal status already deleted this plugin-managed veth pair';
  }
  return 'no previous vtolocal status proves this veth pair was plugin-managed';
}

function teardownProfile(profile) {
  return {
    host_interface: profile.host_interface,
    vtap_interface: profile.vtap_interface,
    host_addresses: [],
    vtap_addresses: [],
    routes: []
  };
}

function teardownPreviousState(previous, profile) {
  previous = previous || {};
  return {
    phase: previous.phase || '',
    managed_link: previous.managed_link === true,
    host_interface: previous.host_interface || '',
    vtap_interface: previous.vtap_interface || '',
    host_addresses: Array.isArray(previous.host_addresses) ? previous.host_addresses : [],
    vtap_addresses: Array.isArray(previous.vtap_addresses) ? previous.vtap_addresses : [],
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
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (e) {
      // Keep non-JSON strings comparable as plain values.
    }
  } else if (value && typeof value === 'object') {
    value = JSON.parse(JSON.stringify(value));
  }
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
  var hostInterface = text(raw.host_interface || raw.host || raw.local_interface || 'fwdlocal0');
  var vtapInterface = text(raw.vtap_interface || raw.vtap || raw.peer || 'fwdvtap0');
  if (hostInterface === vtapInterface) throw new Error('host_interface and vtap_interface must be different');
  return {
    profile_key: key,
    host_interface: ifaceName(hostInterface, 'host_interface'),
    vtap_interface: ifaceName(vtapInterface, 'vtap_interface'),
    mtu: intValue(raw.mtu, 576, 65535, 1492),
    host_addresses: cidrList(raw.host_addresses || raw.host_addrs || raw.host_cidr || raw.host_ipv4_cidr || '169.254.253.1/30'),
    vtap_addresses: cidrList(raw.vtap_addresses || raw.vtap_addrs || raw.vtap_cidr || raw.vtap_ipv4_cidr || '169.254.253.2/30'),
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
