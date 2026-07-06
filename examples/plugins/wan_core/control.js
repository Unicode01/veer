exports.onReconcile = function () {
  applyStoredSessions();
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'sessions') return;
  applyRecords(ctx.records || []);
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply_session') {
    applySession(loadPlan(ctx.payload || {}));
    return;
  }
  if (action === 'teardown') {
    var plan = loadPlan(ctx.payload || {});
    net.link.delete(plan.profile.host_interface);
    resources.set('status', plan.key, {
      phase: 'deleted',
      wan_id: plan.key,
      host_interface: plan.profile.host_interface,
      vtap_interface: plan.profile.vtap_interface,
      forward_core: forwardCoreHandoff(plan.profile),
      updated_at: now()
    });
    return;
  }
  throw new Error('unsupported action ' + action);
};

function applyStoredSessions() {
  applyRecords(resources.list('sessions') || []);
}

function applyRecords(records) {
  for (var i = 0; i < records.length; i++) {
    var record = records[i];
    if (!record || record.enabled === false) continue;
    applySession(loadPlan({key: record.key, session: record.data || {}}));
  }
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
    resources.set('status', plan.key, {
      phase: 'skipped',
      reason: 'wan session is not usable',
      wan_id: plan.key,
      state: plan.session.state,
      usable: plan.session.usable,
      driver: plan.session.driver,
      driver_plugin: plan.session.driver_plugin,
      real_interface: plan.session.real_interface,
      wan_interface: plan.session.wan_interface,
      forward_core: forwardCoreHandoff(plan.profile),
      updated_at: now()
    });
    return;
  }

  var pair = net.link.ensureVeth({
    host: plan.profile.host_interface,
    peer: plan.profile.vtap_interface,
    mtu: plan.profile.mtu,
    up: true
  });
  replaceAddrs(plan.profile.host_interface, plan.profile.host_addresses);
  replaceAddrs(plan.profile.vtap_interface, plan.profile.vtap_addresses);
  replaceRoutes(plan.profile.host_interface, plan.profile.routes);

  resources.set('status', plan.key, {
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
    forward_core: forwardCoreHandoff(plan.profile),
    forward_parent_interface: plan.profile.vtap_interface,
    egress_nat_parent_interface: plan.profile.vtap_interface,
    updated_at: now()
  });
}

function sessionUsable(session) {
  if (session.usable === false) return false;
  var state = lower(session.state);
  return state === '' || state === 'up' || state === 'ready' || state === 'active';
}

function forwardCoreHandoff(profile) {
  return {
    mode: 'vtap',
    parent_interface: profile.vtap_interface,
    ingress_interface: profile.vtap_interface,
    route_interface: profile.host_interface,
    note: 'Attach Forward/Egress NAT rules to parent_interface; route host/local traffic through route_interface.'
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
  return {
    profile_key: key,
    host_interface: ifaceName(hostInterface, 'host_interface'),
    vtap_interface: ifaceName(vtapInterface, 'vtap_interface'),
    mtu: intValue(raw.mtu || session.mtu, 576, 65535, 1492),
    host_addresses: cidrList(raw.host_addresses || raw.host_addrs || raw.host_cidr || '169.254.253.1/30'),
    vtap_addresses: cidrList(raw.vtap_addresses || raw.vtap_addrs || raw.vtap_cidr || '169.254.253.2/30'),
    routes: Array.isArray(raw.routes) ? raw.routes : []
  };
}

function replaceAddrs(iface, addrs) {
  for (var i = 0; i < addrs.length; i++) {
    net.addr.replace({interface: iface, cidr: addrs[i]});
  }
}

function replaceRoutes(defaultDev, routes) {
  for (var i = 0; i < routes.length; i++) {
    var route = routes[i] || {};
    var dst = route.dst || route.destination || route.cidr;
    if (!dst) continue;
    net.route.replace({
      dst: dst,
      dev: route.dev || route.interface || defaultDev,
      gateway: route.gateway || route.gw || '',
      src: route.src || route.source || '',
      table: intValue(route.table, 0, 2147483647, 0),
      metric: intValue(route.metric, 0, 2147483647, 0),
      scope: routeScope(route, dst)
    });
  }
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

function ifaceName(value, label) {
  value = text(value);
  if (!value || value.length > 15 || value.indexOf('\u0000') >= 0) throw new Error(label + ' is invalid or exceeds 15 bytes');
  return value;
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

function now() {
  return new Date().toISOString();
}
