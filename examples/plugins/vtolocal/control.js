exports.onReconcile = function () {
  applyStoredLinks();
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'links') return;
  applyRecords(ctx.records || []);
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply') {
    var profile = loadProfile(ctx.payload || {});
    applyProfile(profile);
    return;
  }
  if (action === 'teardown') {
    var teardown = loadProfile(ctx.payload || {});
    net.link.delete(teardown.host_interface);
    resources.set('status', teardown.profile_key, {
      phase: 'deleted',
      host_interface: teardown.host_interface,
      vtap_interface: teardown.vtap_interface,
      updated_at: now()
    });
    return;
  }
  throw new Error('unsupported action ' + action);
};

function applyStoredLinks() {
  applyRecords(resources.list('links') || []);
}

function applyRecords(records) {
  for (var i = 0; i < records.length; i++) {
    if (!records[i] || records[i].enabled === false) continue;
    applyProfile(normalizeProfile(records[i].key, records[i].data || {}));
  }
}

function loadProfile(payload) {
  var key = token(payload.profile_key || payload.profile || payload.key || 'default');
  var record = resources.get('links', key);
  var data = record && record.data ? record.data : {};
  return normalizeProfile(key, merge(data, payload || {}));
}

function applyProfile(profile) {
  var pair = net.link.ensureVeth({
    host: profile.host_interface,
    peer: profile.vtap_interface,
    mtu: profile.mtu,
    up: true
  });
  replaceAddrs(profile.host_interface, profile.host_addresses);
  replaceAddrs(profile.vtap_interface, profile.vtap_addresses);
  replaceRoutes(profile.host_interface, profile.routes);
  resources.set('status', profile.profile_key, {
    phase: 'applied',
    profile_key: profile.profile_key,
    host_interface: pair.host.name,
    host_ifindex: pair.host.ifindex,
    vtap_interface: pair.peer.name,
    vtap_ifindex: pair.peer.ifindex,
    mtu: profile.mtu,
    host_addresses: profile.host_addresses,
    vtap_addresses: profile.vtap_addresses,
    route_count: profile.routes.length,
    egress_nat_parent_interface: profile.vtap_interface,
    updated_at: now()
  });
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

function now() {
  return new Date().toISOString();
}
