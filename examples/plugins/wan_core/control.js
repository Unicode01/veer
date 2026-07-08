plugin.capabilities(['wan', 'vtap', 'local_route', 'forward_core_adapter', 'net_admin', 'control']);
plugin.virtualInterface({
  id: 'wan0',
  type: 'logical',
  description: 'Logical WAN endpoint backed by a protocol driver and a vtap handoff.'
});
plugin.resource({
  id: 'profiles',
  description: 'WAN adapter defaults such as local/vtap interface names, MTU, addresses, and route policy.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'sessions',
  description: 'Normalized WAN driver session state. Any protocol driver can publish this shape.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'runtime_apply',
  max_records: 32,
  max_record_bytes: 32768
});
plugin.resource({
  id: 'status',
  description: 'Last applied WAN adapter state and forward_core handoff details.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 32768
});
plugin.action({
  id: 'apply_session',
  description: 'Apply a normalized WAN session from payload or the sessions resource.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'teardown',
  description: 'Delete the configured local handoff veth pair and mark the WAN adapter down.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: 'd2ff5941a782f8c0f3a87483dd3d19b4b5546ced1bafc2ca1c60023fa7d82160',
  page: 'wan',
  page_title: 'WAN'
});

exports.onReconcile = function () {
  applyStoredSessions();
  armRepairTimer();
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'sessions') return;
  var records = ctx.records || [];
  try {
    applyRecords(records, true);
  } finally {
    armRepairTimer(mergedSessionRecords(records));
  }
};

exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== 'wan_repair') return;
  applyStoredSessions();
  armRepairTimer();
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply_session') {
    var plan = loadPlan(ctx.payload || {});
    setRecordIfChanged('profiles', plan.key, plan.profile, true);
    setRecordIfChanged('sessions', plan.key, plan.session, true);
    applySession(plan);
    armRepairTimer();
    return;
  }
  if (action === 'teardown') {
    var plan = loadPlan(ctx.payload || {});
    var previous = previousStatus(plan.key);
    resources.set('sessions', plan.key, plan.session, false);
    var previousTeardown = teardownPreviousState(previous, plan.profile);
    var cleanupErrors = cleanupManagedState(previousTeardown, teardownProfile(plan.profile));
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
      wan_id: plan.key,
      host_interface: deleteTarget || plan.profile.host_interface,
      vtap_interface: previousTeardown.vtap_interface || plan.profile.vtap_interface,
      cleanup_errors: cleanupErrors,
      managed_link: previousTeardown.managed_link === true || !!deleteTarget,
      link_delete_skipped: deleteSkipped,
      forward_core: forwardCoreHandoff(plan.profile)
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
    setRecordIfChanged('status', plan.key, status, false);
    armRepairTimer();
    return;
  }
  throw new Error('unsupported action ' + action);
};

function applyStoredSessions() {
  applyRecords(resources.list('sessions') || [], false);
}

function armRepairTimer(records) {
  var sessions = records || resources.list('sessions') || [];
  for (var i = 0; i < sessions.length; i++) {
    if (sessions[i] && sessions[i].enabled !== false) {
      timer.setInterval('wan_repair', 2000, {});
      return;
    }
  }
  timer.clear('wan_repair');
}

function mergedSessionRecords(records) {
  var out = [];
  var positions = {};
  var stored = resources.list('sessions') || [];
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
    var record = records[i];
    if (!record) continue;
    if (record.enabled === false) {
      disableSessionRuntime(record);
      continue;
    }
    try {
      applySession(loadPlan({key: record.key, session: record.data || {}}));
    } catch (e) {
      markApplyError(record.key, e);
      failures.push(token(record.key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (reportErrors && failures.length) {
    throw new Error('failed to apply ' + failures.length + ' WAN session record(s): ' + failures.join('; '));
  }
}

function disableSessionRuntime(record) {
  var key = token(record && record.key || 'default');
  var raw = record && record.data ? record.data : {};
  var hostInterface = safeIfaceName(raw.host_interface || raw.host || raw.local_interface || '');
  var vtapInterface = safeIfaceName(raw.vtap_interface || raw.vtap || raw.peer || '');
  var status = {
    phase: 'disabled',
    wan_id: key,
    profile_key: token(raw.profile_key || key),
    state: text(raw.state || raw.phase || ''),
    usable: false,
    driver: text(raw.driver || ''),
    driver_plugin: text(raw.driver_plugin || ''),
    real_interface: text(raw.real_interface || raw.interface || ''),
    wan_interface: text(raw.wan_interface || raw.real_interface || raw.interface || ''),
    host_interface: hostInterface,
    vtap_interface: vtapInterface
  };
  if (hostInterface && vtapInterface) {
    status.forward_core = forwardCoreHandoff({
      host_interface: hostInterface,
      vtap_interface: vtapInterface
    });
  }
  setRecordIfChanged('status', key, status, false);
}

function markApplyError(key, error) {
  key = token(key || 'default');
  setRecordIfChanged('status', key, {
    phase: 'error',
    wan_id: key,
    last_error: errorMessage(error)
  }, false);
}

function loadPlan(payload) {
  payload = payload || {};
  var inlineSession = payload.session || payload.link || null;
  var key = token(payload.wan_id || payload.profile_key || payload.profile || payload.key ||
    (inlineSession && (inlineSession.wan_id || inlineSession.profile_key)) || 'default');
  var sessionRecord = resources.get('sessions', key);
  var sessionBase = sessionRecord && sessionRecord.data ? sessionRecord.data : {};
  var rawSession = merge(sessionBase, inlineSession || payload || {});
  var session = normalizeSession(key, rawSession);
  var profile = normalizeProfile(key, session, merge(merge(rawSession, loadProfile(key)), payload || {}));
  return {key: key, session: session, profile: profile};
}

function loadProfile(key) {
  var record = resources.get('profiles', key);
  return record && record.data ? record.data : {};
}

function applySession(plan) {
  if (!sessionUsable(plan.session)) {
    setRecordIfChanged('status', plan.key, {
      phase: 'skipped',
      reason: 'wan session is not usable',
      wan_id: plan.key,
      state: plan.session.state,
      usable: plan.session.usable,
      driver: plan.session.driver,
      driver_plugin: plan.session.driver_plugin,
      real_interface: plan.session.real_interface,
      wan_interface: plan.session.wan_interface,
      forward_core: forwardCoreHandoff(plan.profile)
    }, false);
    return;
  }

  var previous = previousStatus(plan.key);
  var cleanupErrors = cleanupManagedLinkReplacement(previous, plan.profile);
  var pair = net.link.ensureVeth({
    host: plan.profile.host_interface,
    peer: plan.profile.vtap_interface,
    mtu: plan.profile.mtu,
    up: true
  });
  cleanupErrors = cleanupErrors.concat(cleanupManagedState(previous, plan.profile));
  replaceAddrs(plan.profile.host_interface, plan.profile.host_addresses);
  replaceAddrs(plan.profile.vtap_interface, plan.profile.vtap_addresses);
  replaceRoutes(plan.profile.host_interface, plan.profile.routes);
  var handoff = forwardCoreHandoff(plan.profile);

  setRecordIfChanged('status', plan.key, {
    phase: 'applied',
    wan_id: plan.key,
    profile_key: plan.session.profile_key,
    driver: plan.session.driver,
    driver_plugin: plan.session.driver_plugin,
    state: plan.session.state,
    usable: plan.session.usable,
    real_interface: plan.session.real_interface,
    wan_interface: plan.session.wan_interface,
    host_interface: pair.host.name,
    host_ifindex: pair.host.ifindex,
    host_mac: pair.host.mac,
    vtap_interface: pair.peer.name,
    vtap_ifindex: pair.peer.ifindex,
    vtap_mac: pair.peer.mac,
    mtu: plan.profile.mtu,
    ipv4: plan.session.ipv4,
    ipv4_peer: plan.session.ipv4_peer,
    ipv6_link_local: plan.session.ipv6_link_local,
    ipv6_peer_link_local: plan.session.ipv6_peer_link_local,
    pd_prefix: plan.session.pd_prefix,
    pd_prefixes: plan.session.pd_prefixes,
    dns_servers: plan.session.dns_servers,
    route_count: plan.profile.routes.length,
    host_addresses: plan.profile.host_addresses,
    vtap_addresses: plan.profile.vtap_addresses,
    routes: plan.profile.routes,
    cleanup_errors: cleanupErrors,
    managed_link: true,
    forward_core: handoff,
    forward_parent_interface: handoff.parent_interface,
    egress_nat_parent_interface: handoff.egress_nat_interface,
    egress_nat_redirect_mode: handoff.egress_nat_redirect_mode,
    egress_nat_virtual_source_ip: true
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
    return 'previous wan_core status already deleted this plugin-managed veth pair';
  }
  return 'no previous wan_core status proves this veth pair was plugin-managed';
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

function sessionUsable(session) {
  if (session.usable === false) return false;
  var state = lower(session.state);
  return state === '' || state === 'up' || state === 'ready' || state === 'active';
}

function forwardCoreHandoff(profile) {
  return {
    mode: 'vtap',
    parent_interface: profile.host_interface,
    ingress_interface: profile.host_interface,
    route_interface: profile.host_interface,
    tunnel_interface: profile.vtap_interface,
    egress_nat_interface: profile.host_interface,
    egress_nat_redirect_mode: profile.egress_nat_redirect_mode,
    note: 'Attach Forward/Egress NAT rules to host_interface; the protocol driver owns vtap_interface.'
  };
}

function normalizeSession(key, raw) {
  raw = raw || {};
  var pdPrefixes = Array.isArray(raw.pd_prefixes) ? raw.pd_prefixes : [];
  var dnsServers = Array.isArray(raw.dns_servers) ? raw.dns_servers : [];
  return {
    wan_id: token(raw.wan_id || key),
    profile_key: token(raw.profile_key || key),
    driver: text(raw.driver || ''),
    driver_plugin: text(raw.driver_plugin || ''),
    state: text(raw.state || raw.phase || ''),
    usable: bool(raw.usable, true),
    real_interface: text(raw.real_interface || raw.interface || ''),
    wan_interface: text(raw.wan_interface || raw.real_interface || raw.interface || ''),
    ipv4: text(raw.ipv4 || raw.ipv4_address || ''),
    ipv4_peer: text(raw.ipv4_peer || raw.peer_ipv4 || raw.gateway || ''),
    ipv6_link_local: text(raw.ipv6_link_local || ''),
    ipv6_peer_link_local: text(raw.ipv6_peer_link_local || raw.peer_ipv6_link_local || ''),
    pd_prefix: text(raw.pd_prefix || (pdPrefixes[0] && pdPrefixes[0].prefix) || ''),
    pd_prefixes: pdPrefixes,
    dns_servers: dnsServers,
    mtu: intValue(raw.mtu || raw.mru, 576, 65535, 1492),
    session_id: intValue(raw.session_id, 0, 65535, 0),
    updated_at: text(raw.updated_at || '')
  };
}

function normalizeProfile(key, session, raw) {
  raw = raw || {};
  var hostInterface = text(raw.host_interface || raw.host || raw.local_interface || 'fwdlocal0');
  var vtapInterface = text(raw.vtap_interface || raw.vtap || raw.peer || 'fwdvtap0');
  if (hostInterface === vtapInterface) throw new Error('host_interface and vtap_interface must be different');
  var hostAddresses = cidrList(raw.host_addresses || raw.host_addrs || raw.host_cidr || '169.254.253.1/30');
  hostAddresses = appendCIDRUnique(hostAddresses, ipv4HostCIDR(session.ipv4));
  return {
    profile_key: key,
    host_interface: ifaceName(hostInterface, 'host_interface'),
    vtap_interface: ifaceName(vtapInterface, 'vtap_interface'),
    mtu: intValue(raw.mtu || session.mtu, 576, 65535, 1492),
    host_addresses: hostAddresses,
    vtap_addresses: cidrList(raw.vtap_addresses || raw.vtap_addrs || raw.vtap_cidr || '169.254.253.2/30'),
    routes: Array.isArray(raw.routes) ? raw.routes : [],
    egress_nat_redirect_mode: normalizeRedirectMode(raw.egress_nat_redirect_mode || raw.redirect_mode || 'prepared_l2')
  };
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

function appendCIDRUnique(values, cidr) {
  cidr = text(cidr);
  if (!cidr) return values;
  var out = Array.isArray(values) ? values.slice() : [];
  for (var i = 0; i < out.length; i++) {
    if (out[i] === cidr) return out;
  }
  out.push(cidr);
  return out;
}

function ipv4HostCIDR(value) {
  value = text(value);
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return '';
  var parts = value.split('.');
  for (var i = 0; i < parts.length; i++) {
    var n = parseInt(parts[i], 10);
    if (!isFinite(n) || n < 0 || n > 255) return '';
  }
  return value + '/32';
}

function normalizeRedirectMode(value) {
  value = lower(value);
  if (value === 'prepared_l2' || value === 'raw_l2' || value === 'vtap') return 'prepared_l2';
  return '';
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

function bool(value, fallback) {
  if (value === true || value === false) return value;
  if (value == null || value === '') return fallback;
  var normalized = lower(value);
  if (normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no' || normalized === 'off') return false;
  return fallback;
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
  for (k in a || {}) if (Object.prototype.hasOwnProperty.call(a, k)) out[k] = a[k];
  for (k in b || {}) if (Object.prototype.hasOwnProperty.call(b, k)) out[k] = b[k];
  return out;
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}
