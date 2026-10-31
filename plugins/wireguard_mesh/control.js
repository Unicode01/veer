var KFUNCS = false, TUNNEL_OBJECT_PATH = 'wg_adapter.o';
if (typeof plugin.host === 'function') {
  var host = plugin.host();
  if ((host.available_features || []).indexOf('dataplane.kfuncs.handoff.v1') >= 0) {
    try { crypto.sha256File('wg_adapter-kfuncs.o'); KFUNCS = true; TUNNEL_OBJECT_PATH = 'wg_adapter-kfuncs.o'; }
    catch (e) { /* Packages built before this capability retain the base path. */ }
  }
}
// Stable plugin ID and WG names preserve existing profiles during upgrades.
var coreDrivers = require('./core-drivers');
var coreManager = require('./core-manager');
var IP = '/usr/sbin/ip', WG = '/usr/bin/wg', NFT = '/usr/sbin/nft';
var PROTOCOL = '242'; // Used only when cleaning up leases from the old routing example.
var OBJECT = 'wg_adapter', MAP = 'wg_links';
var changing = false;
plugin.capabilities(['vpn', 'wireguard', 'mihomo', 'sing_box', 'wan', 'tc_adapter', 'control']);
pipeline.node({id: 'wireguard', description: 'VPN core attached to a WAN Core veth boundary.'});
ebpf.loadObject({id: OBJECT, path: TUNNEL_OBJECT_PATH, sha256: crypto.sha256File(TUNNEL_OBJECT_PATH),
  programs: [{id: 'tc_adapter', section: 'tc/veer/pre_forward', type: 'tc'}]});
pipeline.attach({id: 'wg-links', direction: 'forward', attach: 'ingress', priority: 20,
  program: 'wg_adapter:tc_adapter', mode: 'rewrite'});
plugin.resource({id: 'hook_bindings', methods: ['list', 'get'], control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'plugin_reconcile', max_records: 1, max_record_bytes: 4096});
plugin.resource({id: 'profiles', schema_version: 2, methods: ['list', 'get', 'create', 'update'], runtime_update: 'manual', max_records: 8, max_record_bytes: 16384,
  schema: {type: 'object', additionalProperties: false, properties: {
    driver: {type: 'string', enum: ['wireguard', 'mihomo', 'sing_box', 'tun']},
    core_path: {type: 'string'}, config_secret: {type: 'string'}, upstream_interface: {type: 'string'},
    tun_interface: {type: 'string'}, tun_alias: {type: 'string'}, max_restarts: {type: 'integer'}, startup_timeout_seconds: {type: 'integer'},
    slot: {type: 'integer'}, mtu: {type: 'integer'}, listen_port: {type: 'integer'},
    addresses: {type: 'array', items: {type: 'string'}}, remote_routes: {type: 'array', items: {type: 'string'}},
    peers: {type: 'array', items: {type: 'object', additionalProperties: false, properties: {
      public_key: {type: 'string'}, endpoint: {type: 'string'}, allowed_ips: {type: 'array', items: {type: 'string'}},
      keepalive: {type: 'integer'}, preshared_key_secret: {type: 'string'}
    }}}
  }}});
plugin.resource({id: 'status', methods: ['list', 'get'], control_methods: ['list', 'get', 'create', 'update', 'delete'], runtime_update: 'manual', max_records: 8, max_record_bytes: 32768});
plugin.action({id: 'set_key', description: 'Store a private or preshared key in the encrypted Secret store.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'set_core_config', description: 'Store JSON core configuration encrypted.', runtime_update: 'runtime_apply', max_payload_bytes: 1048576});
plugin.action({id: 'apply', description: 'Create or update a VPN WAN; select it in LAN or Egress NAT settings.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'teardown', description: 'Remove the owned VPN WAN and its TC adapter.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'inspect', description: 'Read public interface, peer, handshake and traffic state.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_logs', description: 'Explicitly read managed core logs; output may contain credentials.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_status', description: 'List persistent core versions and installation progress.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_install', description: 'Download and verify an official core release in the background.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_select', description: 'Choose an installed core for subsequently applied WANs.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_rollback', description: 'Restore the previous default core version.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_remove', description: 'Remove an unused installed core version.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
ui.register({static_dir: 'ui', entry: 'index.html', sha256: '22d33356f0bb622cbca23ce76e1faea6ceb573c67c3551b77acf0b2e84e8edd1', page: 'wireguard', page_title: 'VPN',
  resources: [{resource: 'profiles', methods: ['list', 'get', 'create', 'update']}, {resource: 'status', methods: ['list']}],
  actions: ['set_key', 'set_core_config', 'apply', 'teardown', 'inspect', 'core_logs', 'core_status', 'core_install', 'core_select', 'core_rollback', 'core_remove']});

exports.onAction = function (ctx) {
  var payload = ctx.payload || {}, key = profileKey(payload.key);
  if (['core_status', 'core_install', 'core_select', 'core_rollback', 'core_remove'].indexOf(ctx.action.id) >= 0) {
    var driver = coreManager.driver(payload.driver);
    if (ctx.action.id === 'core_status') return process.binaryStatus(driver);
    if (ctx.action.id === 'core_install') return process.binaryInstall(coreManager.install(payload, plugin.host()));
    if (ctx.action.id === 'core_remove') return process.binaryRemove({id:driver, version:String(payload.version || '')});
    var version = ctx.action.id === 'core_rollback' ? process.binaryStatus(driver).previous : String(payload.version || '');
    if (!version) throw new Error('No previous installed core version');
    return process.binarySelect({id:driver, version:version});
  }
  if (ctx.action.id === 'set_key') {
    var value = wgKey(payload.value), name = payload.name ? token(payload.name) : 'private_' + key;
    var publicKey = name === 'private_' + key ? command(WG, ['pubkey'], value + '\n').trim() : '';
    secret.set(name, value);
    return {stored: true, name: name, public_key: publicKey};
  }
  if (ctx.action.id === 'set_core_config') {
    var config = String(payload.value || '');
    try { var parsed = JSON.parse(config); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(); }
    catch (e) { throw new Error('Core configuration must be a JSON object'); }
    if (utf8Size(config) > 768 * 1024) throw new Error('Core configuration exceeds 768 KiB');
    secret.set('core_' + key, config); return {stored: true};
  }
  if (ctx.action.id === 'inspect') return inspect(key);
  if (ctx.action.id === 'core_logs') {
    var active = allLeases()[key];
    if (!active || ['mihomo', 'sing_box'].indexOf(active.plan.driver) < 0) throw new Error('No managed proxy core for this profile');
    var logs = process.logs('vpn_' + key);
    // runtime_query has a 64 KiB JSON response bound, including escaping.
    return {stdout: logs.stdout.slice(-4000), stderr: logs.stderr.slice(-4000),
      truncated: logs.truncated || logs.stdout.length > 4000 || logs.stderr.length > 4000};
  }
  if (ctx.action.id === 'teardown') { teardown(key); return {phase: 'down'}; }
  if (ctx.action.id === 'apply') {
    var record = resources.get('profiles', key);
    if (!record || record.enabled === false) throw new Error('Save and enable the profile first');
    return apply(key, record.data, true);
  }
  throw new Error('Unsupported action');
};
exports.onReconcile = function () {
  if (changing) return;
  var errors = [];
  Object.keys(allLeases()).sort().forEach(function (key) {
    var lease = allLeases()[key], record = resources.get('profiles', key);
    if (!lease.active) return;
    if (!record || record.enabled === false) { teardown(key); return; }
    try { apply(key, lease.settings); }
    catch (e) { errors.push(key + ': ' + String(e.message || e)); resources.set('status', key, {phase: 'error', error: String(e.message || e), cleanup_required: true}, true); }
  });
  armRepair();
  if (errors.length) throw new Error(errors.join('; '));
};
exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== 'wg_repair') return;
  Object.keys(allLeases()).sort().forEach(function (key) {
    var lease = allLeases()[key];
    if (!lease.active || isLegacy(lease)) return;
    if (lease.plan.driver && lease.plan.driver !== 'wireguard') { repairTUN(key, lease); return; }
    try {
      var p = lease.plan, wg = ownedLink(p), boundary = boundaryLinks(p);
      if (lease.pending || !wg || !boundary || (wg.flags || []).indexOf('UP') < 0 || wg.mtu !== p.mtu || wg.ifindex !== lease.wg_ifindex || boundary.local.ifindex !== lease.local_ifindex || boundary.peer.ifindex !== lease.pipeline_ifindex) {
        clearMaps(lease);
        apply(key, lease.settings);
      }
    } catch (e) {
      try { clearMaps(lease); } catch (cleanup) { log.error('WG map cleanup failed: ' + String(cleanup.message || cleanup)); }
      resources.set('status', key, {phase: 'error', error: String(e.message || e), cleanup_required: true}, true);
    }
  });
};
exports.onDeactivate = function () {
  timer.clear('wg_repair');
  var failures = [];
  Object.keys(allLeases()).forEach(function (key) {
    try { teardown(key); } catch (e) { failures.push(key + ': ' + String(e.message || e)); }
  });
  if (failures.length) throw new Error('WireGuard cleanup incomplete: ' + failures.join('; '));
};
function allLeases() {
  var out = {};
  kv.list({limit: 32}).forEach(function (r) { if (r.key.indexOf('lease_') === 0) out[r.key.slice(6)] = r.data; });
  return out;
}
function armRepair() {
  if (Object.keys(allLeases()).some(function (k) { return allLeases()[k].active; })) timer.setInterval('wg_repair', Object.keys(allLeases()).some(function (k) { return allLeases()[k].plan.driver && allLeases()[k].plan.driver !== 'wireguard'; }) ? 1000 : 5000, {});
  else timer.clear('wg_repair');
}
function normalize(key, raw) {
  raw = raw || {};
  if (raw.driver && raw.driver !== 'wireguard') return normalizeTUN(key, raw);
  if (raw.bindings || raw.masquerade != null || raw.bypass_cidrs) throw new Error('Legacy routing profile: teardown the old profile, then configure a WAN and select it in Egress NAT');
  var p = {driver: 'wireguard', key: key, slot: integer(raw.slot, 1, 8, 1), interface: 'vwg' + key,
    mtu: integer(raw.mtu, 1280, 9000, 1420), listen_port: integer(raw.listen_port, 0, 65535, 0)};
  p.owner = 'veer:wireguard_mesh:' + key;
  p.wan_id = 'wg_' + key; p.local = 'veerwg' + p.slot; p.pipeline = 'veerwgp' + p.slot;
  p.addresses = list(raw.addresses, 1, 8).map(function (v) { return prefix(v, true).text; });
  if (!p.addresses.some(function (v) { return prefix(v).family === '4'; })) throw new Error('A local IPv4 tunnel address is required for Veer Egress NAT');
  p.peers = list(raw.peers, 1, 8).map(function (peer) {
    var endpoint = String(peer.endpoint || '');
    if (endpoint) {
      var match = /^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)$/.exec(endpoint);
      if (!match) throw new Error('Endpoint must be a numeric IP:port (bracket IPv6)');
      address(match[1].replace(/[\[\]]/g, '')); integer(match[2], 1, 65535);
    }
    return {public_key: wgKey(peer.public_key), endpoint: endpoint,
      allowed_ips: list(peer.allowed_ips, 1, 32).map(function (v) { return prefix(v).text; }),
      keepalive: integer(peer.keepalive, 0, 65535, 25), preshared_key_secret: peer.preshared_key_secret ? token(peer.preshared_key_secret) : ''};
  });
  var seenPeers = {}, seenPrefixes = {};
  p.peers.forEach(function (peer) {
    if (seenPeers[peer.public_key]) throw new Error('Duplicate peer public key');
    seenPeers[peer.public_key] = true;
    peer.allowed_ips.forEach(function (v) { if (seenPrefixes[v]) throw new Error('AllowedIPs must not be duplicated across peers'); seenPrefixes[v] = true; });
    if (peer.endpoint) {
      var endpointIP = peer.endpoint[0] === '[' ? peer.endpoint.slice(1, peer.endpoint.indexOf(']')) : peer.endpoint.split(':')[0];
      if (p.addresses.some(function (v) { return covers(prefix(v), prefix(endpointIP)); })) throw new Error('Tunnel address route would capture a WireGuard endpoint');
    }
  });
  p.remote_routes = list(raw.remote_routes || [], 0, 32).map(function (v) {
    var cidr = prefix(v);
    if (cidr.bits === 0) throw new Error('remote_routes cannot replace the host default route; select the WAN in Egress NAT instead');
    if (!p.peers.some(function (peer) { return peer.allowed_ips.some(function (a) { return covers(prefix(a), cidr); }); })) throw new Error('Route is not covered by peer AllowedIPs');
    p.peers.forEach(function (peer) {
      if (!peer.endpoint) return;
      var host = peer.endpoint[0] === '[' ? peer.endpoint.slice(1, peer.endpoint.indexOf(']')) : peer.endpoint.split(':')[0];
      if (covers(cidr, prefix(host))) throw new Error('Remote route would capture a WireGuard endpoint');
    });
    return cidr.text;
  });
  return p;
}
function settings(p) { if (p.driver && p.driver !== 'wireguard') return p.settings; return {slot: p.slot, mtu: p.mtu, listen_port: p.listen_port, addresses: p.addresses, peers: p.peers, remote_routes: p.remote_routes}; }
function link(name) {
  // Query only this device; dumping a PVE host's whole interface inventory on
  // every health check can exceed the exec output bound and waste CPU.
  var result = execute(IP, ['-j', '-d', 'link', 'show', 'dev', name]);
  if (result.exit_code !== 0) {
    if (/does not exist|Cannot find device/.test(result.stderr || '')) return null;
    throw new Error('Cannot inspect VPN interface');
  }
  return JSON.parse(result.stdout || '[]').filter(function (l) { return l.ifname === name; })[0] || null;
}
function ownedLink(p) {
  var current = link(p.interface);
  var lease = allLeases()[p.key];
  var created = lease && lease.pending && lease.created_ifindex === (current && current.ifindex) && !current.ifalias;
  if (current && ((current.ifalias !== p.owner && !created) || !current.linkinfo || current.linkinfo.info_kind !== (p.driver && p.driver !== 'wireguard' ? 'tun' : 'wireguard'))) throw new Error('Refusing to modify an existing unowned VPN interface');
  return current;
}
function wanRecord(resource, p) { return plugins.resources.get('wan_core', resource, p.wan_id); }
function assertWANOwner(p) {
  var session = wanRecord('sessions', p);
  ['sessions', 'status'].forEach(function (resource) {
    var r = wanRecord(resource, p);
    if (resource === 'status' && r && r.data && r.data.phase === 'deleted' && session && session.enabled === false &&
        session.data.driver_plugin === 'wireguard_mesh' && r.data.local_interface === p.local && r.data.pipeline_interface === p.pipeline) return;
    if (r && r.data && r.data.driver_plugin !== 'wireguard_mesh') throw new Error('WAN key is already owned by another driver');
  });
}
function wanCall(action, payload) { return plugins.services.call({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core', action: action, payload: payload}); }
function boundaryLinks(p) {
  var r = wanRecord('status', p), data = r && r.data;
  if (!data || data.driver_plugin !== 'wireguard_mesh') return null;
  var local = link(p.local), peer = link(p.pipeline);
  if (!local || !peer || !local.linkinfo || !peer.linkinfo || local.linkinfo.info_kind !== 'veth' || peer.linkinfo.info_kind !== 'veth') return null;
  function linked(a, b) { return a.link_index === b.ifindex || a.link === b.ifname; }
  if (!linked(local, peer) || !linked(peer, local) || data.local_ifindex !== local.ifindex || data.pipeline_ifindex !== peer.ifindex) return null;
  return {local: local, peer: peer};
}
function wanPayload(p, usable) {
  // Userspace TUN providers do not all negotiate GSO/vnet headers. Keep their
  // boundary segmented even when the kernel WireGuard extension is available.
  var gso = KFUNCS && (!p.driver || p.driver === 'wireguard');
  return {wan_id: p.wan_id, key: p.wan_id, profile_key: p.key, driver: p.driver || 'wireguard', driver_plugin: 'wireguard_mesh',
    state: usable ? 'up' : 'prepared', usable: usable, real_interface: p.interface, wan_interface: p.local,
    local_interface: p.local, pipeline_interface: p.pipeline, handoff_mode: 'segmented_veth', mtu: p.mtu,
    ipv4: p.addresses.filter(function (v) { return prefix(v).family === '4'; })[0].split('/')[0],
    addresses: p.addresses, routes: p.remote_routes.map(function (dst) { return {dst: dst, dev: p.local}; }),
    install_default_route: false, install_default_route_v6: false, egress_nat_redirect_mode: 'prepared_l2',
    interface_preparation: {local_gso: {max_size: gso ? 65536 : p.mtu, max_segs: gso ? 65535 : 1}, local_offloads: {sg: gso, tso: gso, gso: gso}, pipeline_offloads: {gro: gso, lro: false}}};
}
function bindings(exclude) {
  var names = [];
  Object.keys(allLeases()).sort().forEach(function (key) {
    var lease = allLeases()[key];
    if (key !== exclude && lease.active && !isLegacy(lease)) names = names.concat([lease.plan.interface, lease.plan.pipeline]);
  });
  resources.set('hook_bindings', 'wg-links', {hook_id: 'wg-links', interfaces: names}, names.length > 0, true);
}
function u32(n) { var s = ''; for (var i = 0; i < 4; i++) s += ('0' + ((n >>> (i * 8)) & 255).toString(16)).slice(-2); return s; }
function macHex(s) { if (!/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/.test(s || '')) throw new Error('Invalid WAN boundary MAC'); return s.replace(/:/g, '').toLowerCase(); }
function clearMaps(lease) {
  [lease && lease.wg_ifindex, lease && lease.pipeline_ifindex].forEach(function (index) {
    if (!index) return;
    try { ebpf.mapDelete(OBJECT, MAP, u32(index)); }
    catch (e) { if (String(e.message || e).indexOf('plugin runtime target is not loaded') < 0) throw e; }
  });
}
function installMaps(p, wg, boundary, old) {
  var ops = [], next = [wg.ifindex, boundary.peer.ifindex];
  [old && old.wg_ifindex, old && old.pipeline_ifindex].forEach(function (n) { if (n && next.indexOf(n) < 0) ops.push({op: 'delete', object: OBJECT, map: MAP, key: u32(n)}); });
  ops.push({op: 'put', object: OBJECT, map: MAP, key: u32(boundary.peer.ifindex), value: u32(1) + u32(wg.ifindex) + '000000000000000000000000' + u32(p.mtu)});
  ops.push({op: 'put', object: OBJECT, map: MAP, key: u32(wg.ifindex), value: u32(2) + u32(boundary.peer.ifindex) + macHex(boundary.peer.address) + macHex(boundary.local.address) + u32(p.mtu)});
  ebpf.mapTransaction({operations: ops});
}
function isLegacy(lease) { return !!(lease && lease.plan && lease.plan.bindings); }
function apply(key, raw, explicit) {
  var before = changing; changing = true;
  try { return raw && raw.driver && raw.driver !== 'wireguard' ? applyTUNProfile(key, raw, explicit === true) : applyProfile(key, raw); } finally { changing = before; }
}
function applyProfile(key, raw) {
  var p = normalize(key, raw), old = allLeases()[key];
  if (isLegacy(old)) throw new Error('Teardown the legacy routing profile before creating a WireGuard WAN');
  if (old && (old.plan.driver && old.plan.driver !== 'wireguard')) throw new Error('Teardown before changing the driver');
  if (old && old.plan.slot !== p.slot) throw new Error('Teardown before changing the slot');
  Object.keys(allLeases()).forEach(function (k) { if (k !== key && allLeases()[k].plan.slot === p.slot) throw new Error('Slot is already reserved by another profile'); });
  plugins.services.resolve({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'});
  assertWANOwner(p);
  var wg = ownedLink(p), config = configuration(p);
  var previousWAN = wanRecord('status', p), previousSession = wanRecord('sessions', p);
  var cleanWAN = previousWAN && previousWAN.data.phase === 'deleted' && previousSession && previousSession.enabled === false;
  if (!old && (wg || link(p.local) || link(p.pipeline) || ((previousWAN || previousSession) && !cleanWAN))) throw new Error('Recorded ownership is missing; inspect leftover WAN resources before retrying');
  kv.set('lease_' + key, {active: true, pending: true, settings: settings(p), plan: p,
    created_ifindex: old && old.created_ifindex, wg_ifindex: old && old.wg_ifindex, local_ifindex: old && old.local_ifindex, pipeline_ifindex: old && old.pipeline_ifindex});
  try {
    if ((link(p.local) || link(p.pipeline)) && !boundaryLinks(p)) throw new Error('WAN boundary is not ready or no longer owned; inspect replaced interfaces');
    wanCall('prepare_handoff', wanPayload(p, false));
    if (!wg) {
      ip(['link', 'add', 'name', p.interface, 'alias', p.owner, 'type', 'wireguard']);
      // Some iproute/kernel combinations ignore alias during RTM_NEWLINK.
      var created = link(p.interface), pending = allLeases()[key];
      if (!created || !created.linkinfo || created.linkinfo.info_kind !== 'wireguard') throw new Error('WireGuard creation did not return the expected link');
      pending.created_ifindex = created.ifindex; kv.set('lease_' + key, pending);
    }
    ip(['link', 'set', 'dev', p.interface, 'alias', p.owner]);
    command(WG, ['syncconf', p.interface, '/dev/stdin'], config);
    ip(['link', 'set', 'dev', p.interface, 'mtu', String(p.mtu), 'up']);
    plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, true), true, true);
    wg = ownedLink(p);
    var boundary = boundaryLinks(p);
    if (!wg || !boundary) throw new Error('WAN boundary is not ready');
    bindings();
    installMaps(p, wg, boundary, old);
    kv.set('lease_' + key, {active: true, settings: settings(p), plan: p, wg_ifindex: wg.ifindex,
      local_ifindex: boundary.local.ifindex, pipeline_ifindex: boundary.peer.ifindex});
    var result = {phase: 'applied', interface: p.interface, wan_id: p.wan_id, local_interface: p.local,
      pipeline_interface: p.pipeline, egress_nat_interface: p.local, egress_nat_source_ip: wanPayload(p, true).ipv4,
      egress_nat_redirect_mode: 'prepared_l2', tc_ready: true, mtu: p.mtu, dataplane: KFUNCS ? 'kfuncs' : 'bpf'};
    resources.set('status', key, result, true); armRepair(); return result;
  } catch (e) {
    try {
      clearMaps(old);
      wg = ownedLink(p); if (wg) clearMaps({wg_ifindex: wg.ifindex});
      var partial = boundaryLinks(p); if (partial) clearMaps({pipeline_ifindex: partial.peer.ifindex});
    } catch (cleanup) { log.error('WG map cleanup failed: ' + String(cleanup.message || cleanup)); }
    resources.set('status', key, {phase: 'error', interface: p.interface, local_interface: p.local,
      error: String(e.message || e), cleanup_required: true}, true);
    throw e;
  }
}
function teardown(key) {
  var before = changing; changing = true;
  try { return teardownProfile(key); } finally { changing = before; }
}
function teardownProfile(key) {
  var lease = allLeases()[key]; if (!lease) return;
  var p = lease.plan;
  if (p.driver && p.driver !== 'wireguard') return teardownTUN(key, lease);
  ownedLink(p);
  if (isLegacy(lease)) {
    var nft = table(p);
    if (lease.previous) removePlan(lease.previous);
    removePlan(p);
    if (ownedLink(p)) ip(['link', 'del', 'dev', p.interface]);
    if (nft) command(NFT, ['delete', 'table', 'inet', p.nft]);
  } else {
    assertWANOwner(p);
    clearMaps(lease);
    bindings(key);
    if (ownedLink(p)) ip(['link', 'del', 'dev', p.interface]);
    if (wanRecord('status', p)) {
      wanCall('teardown', wanPayload(p, false));
      if (wanRecord('status', p).data.phase !== 'deleted') throw new Error('WAN cleanup incomplete; retry teardown');
    }
  }
  kv.delete('lease_' + key);
  resources.set('status', key, {phase: 'down'}, false); armRepair();
}
function inspect(key) {
  var lease = allLeases()[key]; if (!lease) return {phase: 'down'};
  var p = lease.plan;
  if (p.driver && p.driver !== 'wireguard') {
    var status = resources.get('status', key);
    return {phase: status && status.data ? status.data.phase : 'missing', driver: p.driver,
      process: p.driver === 'tun' ? null : process.status('vpn_' + key), interface: p.interface, wan_id: p.wan_id};
  }
  if (!ownedLink(p)) return {phase: 'missing', interface: p.interface};
  return {phase: 'configured', interface: p.interface, wan_id: p.wan_id, local_interface: p.local,
    public_key: command(WG, ['show', p.interface, 'public-key']).trim(), endpoints: command(WG, ['show', p.interface, 'endpoints']).trim(),
    latest_handshakes: command(WG, ['show', p.interface, 'latest-handshakes']).trim(), transfer: command(WG, ['show', p.interface, 'transfer']).trim()};
}

function execute(program, args, stdin) {
  var result = process.exec({command: program, args: args, stdin: stdin || '', timeout_ms: 2000});
  if (result.timed_out || result.cancelled || result.truncated) throw new Error('Command did not complete: ' + program);
  return result;
}
function command(program, args, stdin) {
  var result = execute(program, args, stdin);
  // wg/nft diagnostics can quote their input, including keys. Never expose stderr.
  if (result.exit_code !== 0) throw new Error('Command failed: ' + program + ' ' + args[0] + ' (exit ' + result.exit_code + ')');
  return result.stdout || '';
}
function ip(args) { return command(IP, args); }
function jsonIP(args) { return JSON.parse(ip(['-j'].concat(args)) || '[]'); }
function token(value) {
  var text = String(value || '');
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(text)) throw new Error('Invalid identifier');
  return text;
}
function profileKey(value) {
  var key = token(value || 'default');
  if (key.length > 11) throw new Error('Profile key must be at most 11 characters');
  return key;
}
function integer(value, min, max, fallback) {
  var n = value == null ? fallback : Number(value);
  if (!isFinite(n) || Math.floor(n) !== n || n < min || n > max) throw new Error('Integer outside allowed range');
  return n;
}
function iface(value) {
  var name = String(value || '');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(name)) throw new Error('Invalid LAN interface');
  return name;
}
function wgKey(value) {
  var key = String(value || '').trim();
  if (!/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(key) || key === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') throw new Error('Invalid WireGuard key');
  return key;
}
function list(value, min, max) {
  if (!Array.isArray(value) || value.length < min || value.length > max) throw new Error('List outside allowed size');
  return value;
}
function address(value) {
  var text = String(value);
  var bytes = [], parts, i;
  if (text.indexOf(':') < 0) {
    parts = text.split('.');
    if (parts.length !== 4) throw new Error('Invalid IPv4 address');
    for (i = 0; i < 4; i++) {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i]) || Number(parts[i]) > 255) throw new Error('Invalid IPv4 address');
      bytes.push(Number(parts[i]));
    }
    return bytes;
  }
  if (!/^[0-9a-fA-F:]+$/.test(text) || text.indexOf(':::') >= 0) throw new Error('Invalid IPv6 address');
  parts = text.split('::');
  if (parts.length > 2) throw new Error('Invalid IPv6 address');
  var left = parts[0] ? parts[0].split(':') : [];
  var right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  var count = left.length + right.length;
  if ((parts.length === 1 && count !== 8) || (parts.length === 2 && count >= 8)) throw new Error('Invalid IPv6 address');
  var groups = left.slice();
  if (parts.length === 2) for (i = count; i < 8; i++) groups.push('0');
  groups = groups.concat(right);
  groups.forEach(function (group) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) throw new Error('Invalid IPv6 address');
    var n = parseInt(group, 16); bytes.push(n >> 8, n & 255);
  });
  return bytes;
}
function addressText(bytes) {
  if (bytes.length === 4) return bytes.join('.');
  var groups = [];
  for (var i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  return groups.join(':');
}
function prefix(value, preserveHost) {
  var parts = String(value || '').split('/');
  if (parts.length > 2) throw new Error('Invalid CIDR');
  var bytes = address(parts[0]);
  if (parts.length === 2 && !/^(0|[1-9][0-9]{0,2})$/.test(parts[1])) throw new Error('Invalid CIDR length');
  var bits = integer(parts.length === 2 ? parts[1] : bytes.length * 8, 0, bytes.length * 8);
  var network = bytes.map(function (b, i) { var remain = bits - i * 8; return remain >= 8 ? b : remain <= 0 ? 0 : b & (255 << (8 - remain)); });
  return {text: addressText(preserveHost ? bytes : network) + '/' + bits, bytes: network, bits: bits, family: bytes.length === 4 ? '4' : '6'};
}
function covers(a, b) {
  if (a.family !== b.family || a.bits > b.bits) return false;
  for (var i = 0; i < a.bytes.length; i++) {
    var remain = a.bits - i * 8, mask = remain >= 8 ? 255 : remain <= 0 ? 0 : (255 << (8 - remain)) & 255;
    if ((a.bytes[i] & mask) !== (b.bytes[i] & mask)) return false;
  }
  return true;
}

function configuration(p) {
  var lines = ['[Interface]', 'PrivateKey = ' + wgKey(secret.get('private_' + p.key)), 'ListenPort = ' + p.listen_port];
  p.peers.forEach(function (peer) {
    lines.push('[Peer]', 'PublicKey = ' + peer.public_key, 'AllowedIPs = ' + peer.allowed_ips.join(', '), 'PersistentKeepalive = ' + peer.keepalive);
    if (peer.endpoint) lines.push('Endpoint = ' + peer.endpoint);
    if (peer.preshared_key_secret) lines.push('PresharedKey = ' + wgKey(secret.get(peer.preshared_key_secret)));
  });
  return lines.join('\n') + '\n';
}

// Exact cleanup for previously applied 0.1.x routing leases.
function table(p) {
  var result = execute(NFT, ['-j', 'list', 'table', 'inet', p.nft]);
  if (result.exit_code !== 0) {
    if (/No such file or directory/.test(result.stderr || '')) return null;
    throw new Error('Cannot inspect nftables ownership');
  }
  var items = JSON.parse(result.stdout).nftables || [];
  var existing = items.filter(function (v) { return v.table && v.table.name === p.nft; })[0];
  var owner = existing && existing.table.comment;
  if (existing && owner == null) {
    // Older nft releases omit table comments from JSON. Require the exact
    // top-level comment, before any chain, from their canonical text output.
    var lines = command(NFT, ['list', 'table', 'inet', p.nft]).split('\n').map(function (line) { return line.trim(); }).filter(Boolean);
    if (lines[0] === 'table inet ' + p.nft + ' {' && lines[1] === 'comment "' + p.owner + '"') owner = p.owner;
  }
  if (!existing || owner !== p.owner) throw new Error('Reserved nftables table is owned by another configuration');
  return existing.table;
}
function routes(p, family) {
  var result = execute(IP, ['-j', '-' + family, 'route', 'show', 'table', String(p.table)]);
  if (result.exit_code !== 0) {
    if (/FIB table does not exist/.test(result.stderr || '')) return [];
    throw new Error('Cannot inspect routing table');
  }
  return JSON.parse(result.stdout || '[]');
}
function ruleArgs(p, b) {
  return ['priority', String(b.priority), 'from', b.source, 'to', b.destination, 'iif', b.lan_interface, 'table', String(p.table), 'protocol', PROTOCOL];
}
function ruleMatches(r, p, b) {
  function normalized(value, length) {
    if (!value || value === 'all') return b.family === '4' ? '0.0.0.0/0' : prefix('::/0').text;
    return prefix(value.indexOf('/') < 0 && length != null ? value + '/' + length : value).text;
  }
  return Number(r.priority) === b.priority && String(r.protocol) === PROTOCOL && Number(r.table) === p.table &&
    r.iif === b.lan_interface && normalized(r.src, r.srclen) === b.source && normalized(r.dst, r.dstlen) === b.destination;
}
function routeMatches(actual, planned) {
  var dst = actual.dst === 'default' ? (planned.family === '4' ? '0.0.0.0/0' : '::/0') : actual.dst;
  return dst && prefix(dst).text === prefix(planned.dst).text && String(actual.protocol) === PROTOCOL &&
    String(actual.metric || 0) === planned.metric && (actual.type || 'unicast') === (planned.type || 'unicast') &&
    (actual.dev || '') === (planned.dev || (planned.type && planned.family === '6' && actual.dev === 'lo' ? 'lo' : '')) && !actual.gateway && !actual.nexthops;
}
function routePlan(p) {
  var out = [];
  ['4', '6'].forEach(function (family) {
    if (!p.bindings.some(function (b) { return b.family === family; })) return;
    out.push({family: family, type: 'unreachable', dst: family === '4' ? '0.0.0.0/0' : '::/0', metric: '32760'});
    var seen = {};
    p.peers.forEach(function (peer) { peer.allowed_ips.forEach(function (cidr) {
      if (prefix(cidr).family !== family || seen[cidr]) return;
      seen[cidr] = true; out.push({family: family, dst: cidr, dev: p.interface, metric: '10'});
    }); });
    p.bypass.forEach(function (cidr) {
      if (prefix(cidr).family === family) out.push({family: family, type: 'throw', dst: cidr, metric: '1'});
    });
  });
  return out;
}
function routeArgs(p, r) {
  var args = r.type ? [r.type, r.dst] : [r.dst, 'dev', r.dev];
  return args.concat(['table', String(p.table), 'metric', r.metric, 'proto', PROTOCOL]);
}
function removePlan(p) {
  p.bindings.forEach(function (b) {
    var rules = jsonIP(['-' + b.family, 'rule', 'show']);
    if (rules.some(function (r) { return ruleMatches(r, p, b); })) ip(['-' + b.family, 'rule', 'del'].concat(ruleArgs(p, b)));
  });
  routePlan(p).forEach(function (r) {
    if (routes(p, r.family).some(function (v) { return routeMatches(v, r); })) ip(['-' + r.family, 'route', 'del'].concat(routeArgs(p, r)));
  });
}

// TUN drivers share the same WAN and TC adapter as kernel WireGuard.
function normalizeTUN(key, raw) {
  var driver = String(raw.driver);
  if (['mihomo', 'sing_box', 'tun'].indexOf(driver) < 0) throw new Error('Unsupported VPN driver');
  var p = {key: key, driver: driver, slot: integer(raw.slot, 1, 8, 1), mtu: integer(raw.mtu, 1280, 9000, 1420)};
  p.interface = driver === 'tun' ? iface(raw.tun_interface) : 'vtun' + key;
  if (driver === 'tun' && !raw.tun_interface) throw new Error('An external TUN interface is required');
  p.owner = driver === 'tun' ? String(raw.tun_alias || '') : 'veer:wireguard_mesh:' + key;
  if (!p.owner || p.owner.length > 128 || /[\r\n\0]/.test(p.owner)) throw new Error('An external TUN requires an explicit tun_alias ownership marker');
  p.wan_id = 'vpn_' + key; p.local = 'veervpn' + p.slot; p.pipeline = 'veervpnp' + p.slot;
  if ([p.local, p.pipeline].indexOf(p.interface) >= 0) throw new Error('TUN and WAN boundaries must differ');
  p.addresses = list(raw.addresses, 1, 8).map(function (v) {
    var c = prefix(v, true);
    if (c.bits !== (c.family === '4' ? 32 : 128)) throw new Error('Proxy WAN addresses must be /32 or /128 to avoid changing host routes');
    return c.text;
  });
  if (!p.addresses.some(function (v) { return prefix(v).family === '4'; })) throw new Error('A local IPv4 WAN address is required');
  if (raw.remote_routes && raw.remote_routes.length) throw new Error('Select this WAN in Veer instead of installing host routes');
  p.remote_routes = [];
  p.upstream_interface = driver === 'tun' ? '' : iface(raw.upstream_interface);
  if (driver !== 'tun' && (!raw.upstream_interface || [p.interface, p.local, p.pipeline].indexOf(p.upstream_interface) >= 0)) throw new Error('Select a separate physical or PPPoE upstream_interface');
  var managed = driver !== 'tun' && !raw.core_path ? process.binaryStatus(driver) : null;
  p.core_path = driver === 'tun' ? '' : coreDrivers.command(driver, raw.core_path || (managed && managed.path));
  p.config_secret = raw.config_secret ? token(raw.config_secret) : 'core_' + key;
  p.max_restarts = integer(raw.max_restarts, 0, 10, 3);
  p.startup_timeout_seconds = integer(raw.startup_timeout_seconds, 1, 300, 30);
  p.settings = {driver: driver, slot: p.slot, mtu: p.mtu, addresses: p.addresses, upstream_interface: p.upstream_interface,
    core_path: p.core_path, config_secret: p.config_secret, max_restarts: p.max_restarts, startup_timeout_seconds: p.startup_timeout_seconds};
  if (driver === 'tun') { p.settings.tun_interface = p.interface; p.settings.tun_alias = p.owner; }
  return p;
}
function suspendTUN(p, lease) {
  clearMaps(lease);
  // Keep the selected WAN boundary, but withdraw availability. Never fall back
  // to the host's direct default route when a core is absent or restarting.
  if (wanRecord('status', p)) plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, false), false, true);
}
function applyTUNProfile(key, raw, explicit) {
  var p = normalizeTUN(key, raw), old = allLeases()[key], managed = p.driver !== 'tun';
  if (old && ((old.plan.driver || 'wireguard') !== p.driver || old.plan.slot !== p.slot || old.plan.interface !== p.interface))
    throw new Error('Teardown before changing the driver, slot or TUN interface');
  Object.keys(allLeases()).forEach(function (k) {
    var other = allLeases()[k].plan;
    if (k !== key && (other.slot === p.slot || other.interface === p.interface)) throw new Error('Slot or TUN is already reserved by another profile');
    if (managed && k !== key && [other.interface, other.local, other.pipeline].indexOf(p.upstream_interface) >= 0)
      throw new Error('Another VPN boundary cannot be the upstream interface');
  });
  plugins.services.resolve({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'});
  assertWANOwner(p);
  var current = link(p.interface), previousWAN = wanRecord('status', p);
  var cleanWAN = previousWAN && previousWAN.data.phase === 'deleted';
  if (!old && (link(p.local) || link(p.pipeline) || (previousWAN && !cleanWAN) || (managed && current)))
    throw new Error('Recorded ownership is missing; inspect leftover VPN resources');
  if (!managed) ownedLink(p);
  // Build and validate before changing any network state. Active core configs
  // are encrypted separately so subsequent draft edits do not change recovery.
  var spec = null;
  if (managed) {
    var text = !explicit && old ? secret.get('active_' + key) : '';
    if (text && typeof text !== 'string') throw new Error('Invalid active core configuration');
    spec = text ? {command: p.core_path, args: p.driver === 'mihomo' ? ['-d', '.', '-f', '{config}'] : ['run', '-c', '{config}'], config: text}
      : coreDrivers.build(p, secret.get(p.config_secret));
  }
  // Reconciliation of a healthy WAN must not withdraw it or reprepare the
  // boundary: that would disturb unrelated live flows on every inventory event.
  var stableBoundary = boundaryLinks(p), stableProcess = managed ? process.status('vpn_' + key) : null;
  if (!explicit && old && !old.pending && current && current.linkinfo && current.linkinfo.info_kind === 'tun' && current.ifalias === p.owner && current.ifindex === old.wg_ifindex &&
      current.mtu === p.mtu && (current.flags || []).indexOf('UP') >= 0 && stableBoundary &&
      stableBoundary.local.ifindex === old.local_ifindex && stableBoundary.peer.ifindex === old.pipeline_ifindex &&
      (!managed || (stableProcess.state === 'running' && stableProcess.started_at === old.process_started_at))) {
    if (managed) process.start({id: 'vpn_' + key, command: spec.command, args: spec.args, config: spec.config,
      restart: 'on-failure', max_restarts: p.max_restarts, stop_timeout_ms: 1000});
    bindings(); installMaps(p, current, stableBoundary, old);
    return resources.get('status', key).data;
  }
  var lease = {active: true, pending: true, settings: p.settings, plan: p,
    wg_ifindex: old && old.wg_ifindex, pipeline_ifindex: old && old.pipeline_ifindex,
    local_ifindex: old && old.local_ifindex, process_started_at: old && old.process_started_at};
  kv.set('lease_' + key, lease);
  try {
    suspendTUN(p, old);
    wanCall('prepare_handoff', wanPayload(p, false));
    var proc = null;
    if (managed) {
      if (explicit) {
        process.stop('vpn_' + key);
        if (link(p.interface)) throw new Error('TUN remains after core stop; refusing to take over an external interface');
        secret.set('active_' + key, spec.config);
      }
      // A stopped owner generation can be restored; exited/failed entries retain their budget.
      if (!explicit && process.status('vpn_' + key).state === 'stopped') process.stop('vpn_' + key);
      // An exhausted restart budget remains exhausted until an explicit apply.
      proc = process.start({id: 'vpn_' + key, command: spec.command, args: spec.args, config: spec.config,
        restart: 'on-failure', max_restarts: p.max_restarts, stop_timeout_ms: 1000});
      current = link(p.interface);
      // Some cores keep running after their TUN is deleted. Restart only a
      // previously published generation, with the supervisor's existing budget.
      if (!explicit && !current && proc.state === 'running' &&
          ((old && old.wg_ifindex && proc.started_at === old.process_started_at) || Date.now() - proc.started_at >= p.startup_timeout_seconds * 1000))
        proc = process.restart('vpn_' + key);
      if (proc.state !== 'running' || !current) {
        resources.set('status', key, {phase: proc.state === 'exited' || proc.state === 'failed' ? 'failed' : 'starting',
          driver: p.driver, interface: p.interface, wan_id: p.wan_id, process: proc}, true);
        armRepair(); return {phase: 'starting', driver: p.driver, wan_id: p.wan_id, process: proc};
      }
      if (!current.linkinfo || current.linkinfo.info_kind !== 'tun') throw new Error('Core did not create a TUN interface');
      if (!current.ifalias && (!old || proc.started_at !== old.process_started_at)) ip(['link', 'set', 'dev', p.interface, 'alias', p.owner]);
    }
    current = ownedLink(p);
    if (managed && current && ((current.flags || []).indexOf('UP') < 0 || current.mtu !== p.mtu)) {
      ip(['link', 'set', 'dev', p.interface, 'mtu', String(p.mtu), 'up']);
      current = ownedLink(p);
    }
    if (!current || (current.flags || []).indexOf('UP') < 0) throw new Error('TUN interface is not ready');
    if (current.mtu !== p.mtu) throw new Error('TUN MTU does not match the WAN profile');
    var boundary = boundaryLinks(p);
    if (!boundary) throw new Error('WAN boundary is not ready');
    lease.wg_ifindex = current.ifindex; lease.local_ifindex = boundary.local.ifindex;
    lease.pipeline_ifindex = boundary.peer.ifindex;
    kv.set('lease_' + key, lease);
    bindings(); installMaps(p, current, boundary, old);
    if (managed && (process.status('vpn_' + key).state !== 'running' || process.status('vpn_' + key).started_at !== proc.started_at)) throw new Error('Core restarted while publishing the WAN');
    plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, true), true, true);
    lease.pending = false; lease.wg_ifindex = current.ifindex; lease.local_ifindex = boundary.local.ifindex;
    lease.pipeline_ifindex = boundary.peer.ifindex; lease.process_started_at = proc && proc.started_at;
    kv.set('lease_' + key, lease);
    var result = {phase: 'applied', driver: p.driver, interface: p.interface, wan_id: p.wan_id,
      local_interface: p.local, pipeline_interface: p.pipeline, egress_nat_interface: p.local,
      egress_nat_source_ip: wanPayload(p, true).ipv4, egress_nat_redirect_mode: 'prepared_l2', tc_ready: true,
      process: proc, dataplane: KFUNCS ? 'kfuncs' : 'bpf'};
    resources.set('status', key, result, true); armRepair(); return result;
  } catch (e) {
    try { suspendTUN(p, lease); } catch (cleanup) { log.error('VPN suspension failed'); }
    // Core diagnostics may include credentials; never publish their output.
    resources.set('status', key, {phase: 'error', driver: p.driver, error: String(e.message || e), cleanup_required: true}, true);
    armRepair(); throw e;
  }
}
function repairTUN(key, lease) {
  try {
    var p = lease.plan, current = link(p.interface), boundary = boundaryLinks(p);
    var proc = p.driver === 'tun' ? null : process.status('vpn_' + key);
    if (lease.pending || !current || !boundary || current.ifalias !== p.owner || current.ifindex !== lease.wg_ifindex ||
        current.mtu !== p.mtu || (current.flags || []).indexOf('UP') < 0 || boundary.local.ifindex !== lease.local_ifindex ||
        boundary.peer.ifindex !== lease.pipeline_ifindex || (proc && (proc.state !== 'running' || proc.started_at !== lease.process_started_at))) {
      suspendTUN(p, lease);
      apply(key, lease.settings);
    }
  } catch (e) {
    try { suspendTUN(lease.plan, lease); } catch (_) { log.error('VPN suspension failed'); }
    resources.set('status', key, {phase: 'error', driver: lease.plan.driver, error: String(e.message || e), cleanup_required: true}, true);
  }
}
function teardownTUN(key, lease) {
  var p = lease.plan;
  assertWANOwner(p); suspendTUN(p, lease);
  bindings(key);
  // External TUN mode never deletes or reconfigures its provider's device.
  if (p.driver !== 'tun') process.stop('vpn_' + key);
  if (wanRecord('status', p)) {
    wanCall('teardown', wanPayload(p, false));
    if (wanRecord('status', p).data.phase !== 'deleted') throw new Error('WAN cleanup incomplete; retry teardown');
  }
  kv.delete('lease_' + key); secret.delete('active_' + key);
  resources.set('status', key, {phase: 'down', driver: p.driver}, false); armRepair();
}

function utf8Size(text) { return unescape(encodeURIComponent(text)).length; }
