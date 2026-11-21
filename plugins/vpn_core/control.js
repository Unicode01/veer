var KFUNCS = false, DIRECT = false, TUNNEL_OBJECT_PATH = 'tunnel_adapter.o';
if (typeof plugin.host === 'function') {
  var host = plugin.host();
  if ((host.available_features || []).indexOf('dataplane.kfuncs.handoff.v1') >= 0) {
    try { crypto.sha256File('tunnel_adapter-kfuncs.o'); KFUNCS = true; TUNNEL_OBJECT_PATH = 'tunnel_adapter-kfuncs.o'; }
    catch (e) { /* Packages built before this capability retain the base path. */ }
  }
  if (KFUNCS && (host.available_features || []).indexOf('dataplane.kfuncs.handoff_ingress.v1') >= 0) {
    try { crypto.sha256File('tunnel_adapter-direct.o'); DIRECT = true; TUNNEL_OBJECT_PATH = 'tunnel_adapter-direct.o'; }
    catch (e) { /* Keep the veth boundary when the optional object is absent. */ }
  }
}
// Every driver shares the tunnel adapter. WireGuard keeps its own WAN keys and
// netdev names (wg_<key>, vwg<key>, veerwg<slot>) because Egress NAT selects them.
var coreDrivers = require('./core-drivers');
var shares = require('./ui/share');
var coreManager = require('./core-manager');
var health = require('./health-check').create({path: healthPath, leases: allLeases});
var IP = '/usr/sbin/ip', WG = '/usr/bin/wg', NFT = '/usr/sbin/nft', SYSCTL = '/usr/sbin/sysctl';
// A proxy exit may use another exit as its upstream; at most two exits in front.
var MAX_CHAIN = 2;
var PROTOCOL = '242'; // Used only when cleaning up leases from the old routing example.
var OBJECT = 'tunnel_adapter', MAP = 'tunnel_links', REPAIR_TIMER = 'tunnel_repair';
var EVENT_TIMER = 'tunnel_event', RETRY_TIMER = 'tunnel_retry', MAP_TIMER = 'tunnel_maps';
var HOOK_IN = 'tunnel-links', HOOK_DIRECT_OUT = 'tunnel-direct-out';
var changing = false;
// Exits are checked when something changes, not on a polling tick: a link
// event (the tunnel, the WAN boundary or a chained front going away, down or
// being replaced) or a core process changing state arms EVENT_TIMER, which
// checks the core, the tunnel, the boundary and the TC map entries of every
// exit and repairs what differs. An exit that is still negotiating its TUN
// offloads is checked again every PENDING_RETRY_MS, a failed repair with
// backoff from RETRY_MIN_MS to RETRY_MAX_MS, and REPAIR_TIMER checks
// everything every SAFETY_REPAIR_MS in case an event was lost. The TC map
// entries have no event: MAP_TIMER reads them every MAP_CHECK_MS and puts
// back what the last check or install wrote (two map reads per exit, no link
// or record reads).
var SAFETY_REPAIR_MS = 300000, EVENT_REPAIR_DELAY_MS = 250, PENDING_RETRY_MS = 1000, MAP_CHECK_MS = 5000;
// Per exit key: the adapter entries last written and the ifindexes they
// belong to. Dropped whenever the entries are withdrawn on purpose.
var expectedMaps = {};
// Retry delay per exit key whose last repair failed.
var RETRY_MIN_MS = 2000, RETRY_MAX_MS = 60000, retryDelays = {};
plugin.capabilities(['vpn', 'wireguard', 'mihomo', 'sing_box', 'wan', 'tc_adapter', 'control']);
events.subscribe({id: 'vpn_links', topic: 'net.link', worker: 'events', handler: 'onNetEvent', queue_size: 64});
// Hosts before process.state learn of a core restart from its TUN going away.
if (hostFeature('control.process_events.v1')) {
  events.subscribe({id: 'vpn_processes', topic: 'process.state', worker: 'events', handler: 'onProcessEvent', queue_size: 16});
}
pipeline.node({id: 'vpn', description: 'VPN core attached to a WAN Core boundary.'});
ebpf.loadObject({id: OBJECT, path: TUNNEL_OBJECT_PATH, sha256: crypto.sha256File(TUNNEL_OBJECT_PATH),
  programs: [{id: 'tc_adapter', section: 'tc/veer/pre_forward', type: 'tc'}]});
pipeline.attach({id: HOOK_IN, direction: 'forward', attach: 'ingress', priority: 20,
  program: OBJECT + ':tc_adapter', mode: 'rewrite', binding_required: true});
pipeline.attach({id: HOOK_DIRECT_OUT, direction: 'forward', attach: 'egress', priority: 20,
  program: OBJECT + ':tc_adapter', mode: 'rewrite', binding_required: true});
plugin.resource({id: 'hook_bindings', methods: ['list', 'get'], control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'plugin_reconcile', max_records: 2, max_record_bytes: 4096});
plugin.resource({id: 'profiles', schema_version: 3, methods: ['list', 'get', 'create', 'update'], control_methods: ['list', 'get', 'create', 'update', 'delete'], runtime_update: 'manual', max_records: 8, max_record_bytes: 16384,
  schema: {type: 'object', additionalProperties: false, properties: {
    driver: {type: 'string', enum: ['wireguard', 'mihomo', 'sing_box', 'tun']},
    core_path: {type: 'string'}, config_secret: {type: 'string'}, upstream_interface: {type: 'string'}, upstream_ip: {type: 'string'},
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
plugin.action({id: 'core_form', description: 'Read node names and advanced settings without credentials.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'health_status', description: 'Read actual VPN path probe results and settings.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'health_settings', description: 'Configure manual or periodic VPN path probes independently of the running tunnel.', runtime_update: 'runtime_apply', max_payload_bytes: 4096});
plugin.action({id: 'health_check', description: 'Queue a bounded asynchronous request through the applied VPN WAN.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'apply', description: 'Create or update a VPN WAN; select it in LAN or Egress NAT settings.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'teardown', description: 'Remove the owned VPN WAN and its TC adapter.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'delete_profile', description: 'Teardown the owned VPN WAN, then delete its draft and unshared credentials.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'inspect', description: 'Read public interface, peer, handshake and traffic state.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'upstream_interfaces', description: 'List interfaces a proxy core can use as its uplink.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_logs', description: 'Explicitly read managed core logs; output may contain credentials.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_status', description: 'List persistent core versions and installation progress.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
plugin.action({id: 'core_install', description: 'Download and verify an official core release in the background.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_select', description: 'Choose an installed core for subsequently applied WANs.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_rollback', description: 'Restore the previous default core version.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'core_remove', description: 'Remove an unused installed core version.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
ui.register({static_dir: 'ui', entry: 'index.html', sha256: '30039017dbb70e05163e484256e5a986e3a0049258c6cf617813b3c0d23831c9', page: 'vpn', page_title: 'VPN',
  resources: [{resource: 'profiles', methods: ['list', 'get', 'create', 'update']}, {resource: 'status', methods: ['list']}],
  actions: ['set_key', 'set_core_config', 'core_form', 'health_status', 'health_settings', 'health_check', 'apply', 'teardown', 'delete_profile', 'inspect', 'upstream_interfaces', 'core_logs', 'core_status', 'core_install', 'core_select', 'core_rollback', 'core_remove']});

exports.onAction = function (ctx) {
  var payload = ctx.payload || {}, key = profileKey(payload.key);
  if (ctx.action.id === 'health_status') return health.all();
  if (ctx.action.id === 'health_settings' || ctx.action.id === 'health_check') {
    if (!resources.get('profiles', key)) throw fail('profile_not_saved', '请先保存出口配置');
    return ctx.action.id === 'health_settings' ? health.configure(key, payload.settings) : health.start(key);
  }
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
    var name = payload.name ? token(payload.name) : 'core_' + key;
    if (payload.format === 'links') {
      var source = String(payload.value || '').trim();
      if (!source) {
        var previous;
        try { previous = JSON.parse(secret.get(name)); } catch (e) { throw fail('links_required', '请先导入分享链接'); }
        if (!previous || previous.veer_proxy !== 1 || previous.driver !== payload.driver) throw fail('links_required', '请为当前核心重新导入分享链接');
        source = previous.links;
      }
      var imported = shares.create(payload.driver, source, payload.selected, payload.options, payload.via);
      // Validate both parsing and generation before replacing any saved Secret.
      shares.generate(imported);
      secret.set(name, JSON.stringify(imported));
      return {stored: true, form: shares.metadata(imported)};
    }
    if (payload.format && payload.format !== 'native') throw fail('core_config_invalid', 'Unsupported core configuration format');
    var config = String(payload.value || '');
    try { var parsed = JSON.parse(config); if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error(); }
    catch (e) { throw fail('core_config_invalid', 'Core configuration must be a JSON object'); }
    if (parsed.veer_proxy != null) throw fail('core_config_invalid', 'Use the sharing-link import format for managed node configurations');
    if (utf8Size(config) > 768 * 1024) throw fail('core_config_invalid', 'Core configuration exceeds 768 KiB');
    secret.set(name, config); return {stored: true};
  }
  if (ctx.action.id === 'core_form') {
    var record = resources.get('profiles', key);
    if (!record || ['mihomo', 'sing_box'].indexOf(record.data.driver) < 0) return {mode: 'empty'};
    var saved = secret.get(record.data.config_secret || 'core_' + key);
    if (!saved) return {mode: 'empty'};
    var form = shares.metadata(JSON.parse(saved));
    if (form.driver && form.driver !== record.data.driver) throw fail('core_config_invalid', 'Saved node configuration belongs to another core');
    return form;
  }
  if (ctx.action.id === 'inspect') return inspect(key);
  if (ctx.action.id === 'upstream_interfaces') return {items: upstreamInterfaces()};
  if (ctx.action.id === 'core_logs') {
    var active = allLeases()[key];
    if (!active || ['mihomo', 'sing_box'].indexOf(active.plan.driver) < 0) throw new Error('No managed proxy core for this profile');
    var logs = process.logs('vpn_' + key);
    // runtime_query has a 64 KiB JSON response bound, including escaping.
    return {stdout: logs.stdout.slice(-4000), stderr: logs.stderr.slice(-4000),
      truncated: logs.truncated || logs.stdout.length > 4000 || logs.stderr.length > 4000};
  }
  if (ctx.action.id === 'teardown') { assertNoDependents(key); teardown(key); return {phase: 'down'}; }
  if (ctx.action.id === 'delete_profile') { assertNoDependents(key); return deleteProfile(key); }
  if (ctx.action.id === 'apply') {
    var record = resources.get('profiles', key);
    if (!record || record.enabled === false) throw fail('profile_not_saved', 'Save and enable the profile first');
    return apply(key, record.data, true, record.revision);
  }
  throw new Error('Unsupported action');
};
exports.onReconcile = function () {
  if (changing) return;
  var errors = [];
  var leases = allLeases();
  chainOrder(leases).forEach(function (key) {
    var lease = leases[key], record = resources.get('profiles', key);
    if (!lease.active) return;
    if (!record || record.enabled === false) { teardown(key); return; }
    try { apply(key, lease.settings); }
    catch (e) { errors.push(key + ': ' + String(e.message || e)); resources.set('status', key, errorStatus(key, lease.plan, e), true); }
  });
  armRepair();
  if (errors.length) {
    armRetry(errors.map(function (line) { return line.slice(0, line.indexOf(':')); }));
    throw new Error(errors.join('; '));
  }
};
exports.onTimer = function (ctx) {
  var name = ctx.timer && ctx.timer.name;
  if (name === 'vpn_health') { health.tick(); return; }
  if (name === MAP_TIMER) { checkMaps(); return; }
  // Stop timers this version no longer arms, such as wg_repair from 0.9.0.
  if (name !== REPAIR_TIMER && name !== EVENT_TIMER && name !== RETRY_TIMER) { if (name) timer.clear(name); return; }
  var failed = [];
  var leases = allLeases();
  chainOrder(leases).forEach(function (key) {
    var lease = leases[key];
    if (!lease.active || isLegacy(lease)) return;
    if (lease.plan.driver && lease.plan.driver !== 'wireguard') { if (!repairTUN(key, lease)) failed.push(key); return; }
    try {
      var p = lease.plan, wg = ownedLink(p, lease);
      var tunnelOK = !lease.pending && wg && (wg.flags || []).indexOf('UP') >= 0 && wg.mtu === p.mtu && wg.ifindex === lease.tunnel_ifindex;
      var boundary = tunnelOK ? boundaryLinks(p) : null;
      if (!tunnelOK || !boundary || boundary.local.ifindex !== lease.local_ifindex || boundary.peer.ifindex !== lease.pipeline_ifindex) {
        clearMaps(lease);
        apply(key, lease.settings);
      } else repairMaps(p, wg, boundary);
    } catch (e) {
      failed.push(key);
      delete expectedMaps[key];
      try { clearMaps(lease); } catch (cleanup) { log.error('Tunnel map cleanup failed: ' + String(cleanup.message || cleanup)); }
      resources.set('status', key, errorStatus(key, lease.plan, e), true);
    }
  });
  armRetry(failed);
};
// Runs in the events worker. The check that follows reads a few links per
// exit, so any link change (or a resync after lost events) may arm it. It is
// armed once: later events of a burst, or a flapping interface elsewhere,
// cannot keep postponing it.
exports.onNetEvent = function () {
  armEventCheck();
};
exports.onProcessEvent = function (ctx) {
  var payload = (ctx.event && ctx.event.payload) || {};
  if (String(payload.id || '').indexOf('vpn_') === 0) armEventCheck();
};
function armEventCheck() {
  var timers = timer.list() || [];
  for (var i = 0; i < timers.length; i++) {
    if (timers[i] && timers[i].name === EVENT_TIMER) return;
  }
  timer.setTimeout(EVENT_TIMER, EVENT_REPAIR_DELAY_MS, {});
}
// Puts back an exit's adapter entries when they differ from what was last
// written, as long as its lease still holds the same tunnel and boundary.
function checkMaps() {
  Object.keys(expectedMaps).forEach(function (key) {
    var want = expectedMaps[key];
    var intact = want.entries.every(function (entry) {
      // Hash-map reads may throw for absent keys.
      try { return ebpf.mapGet(OBJECT, MAP, entry.key) === entry.value; }
      catch (_) { return false; }
    });
    if (intact) return;
    var record = kv.get('lease_' + key), lease = record && record.data;
    if (!lease || !lease.active || lease.pending || lease.tunnel_ifindex !== want.tunnel || lease.pipeline_ifindex !== want.pipeline) {
      delete expectedMaps[key];
      return;
    }
    try { ebpf.mapTransaction({operations: want.entries}); }
    catch (e) { log.error('Tunnel map repair failed: ' + String(e.message || e)); }
  });
}
function hostFeature(name) {
  if (typeof plugin.host !== 'function') return false;
  return (plugin.host().available_features || []).indexOf(name) >= 0;
}
// An exit still negotiating its TUN offloads is checked again soon; a failed
// repair waits longer each time, since no event may follow it. Each exit
// backs off on its own, so one that keeps failing does not delay the first
// retry of another.
function armRetry(failedKeys) {
  var leases = allLeases();
  var pending = Object.keys(leases).some(function (k) { return leases[k].active && leases[k].pending; });
  var next = {}, delay = pending ? PENDING_RETRY_MS : 0;
  (failedKeys || []).forEach(function (key) {
    next[key] = retryDelays[key] ? Math.min(retryDelays[key] * 2, RETRY_MAX_MS) : RETRY_MIN_MS;
    delay = delay ? Math.min(delay, next[key]) : next[key];
  });
  retryDelays = next;
  if (delay) timer.setTimeout(RETRY_TIMER, delay, {});
  else timer.clear(RETRY_TIMER);
}
exports.onDeactivate = function () {
  health.stop();
  [REPAIR_TIMER, EVENT_TIMER, RETRY_TIMER, MAP_TIMER].forEach(function (name) { timer.clear(name); });
  expectedMaps = {};
  var failures = [];
  // Chained exits first, so no core keeps dialing through a removed front.
  chainOrder(allLeases()).reverse().forEach(function (key) {
    try { teardown(key); } catch (e) { failures.push(key + ': ' + String(e.message || e)); }
  });
  if (failures.length) throw new Error('VPN cleanup incomplete: ' + failures.join('; '));
};
function allLeases() {
  var out = {};
  for (var offset = 0; offset < 1024; offset += 32) {
    var page = kv.list({limit: 32, offset: offset});
    page.forEach(function (r) {
      if (r.key.indexOf('lease_') !== 0) return;
      var lease = r.data;
      // Leases written before 0.9.1 call the tunnel ifindex wg_ifindex; the next write drops it.
      if (lease && lease.wg_ifindex != null) {
        if (lease.tunnel_ifindex == null) lease.tunnel_ifindex = lease.wg_ifindex;
        delete lease.wg_ifindex;
      }
      out[r.key.slice(6)] = lease;
    });
    if (page.length < 32) break;
  }
  return out;
}
function armRepair() {
  health.arm();
  var leases = allLeases(), keys = Object.keys(leases);
  Object.keys(expectedMaps).forEach(function (k) { if (!leases[k] || !leases[k].active) delete expectedMaps[k]; });
  if (keys.some(function (k) { return leases[k].active; })) {
    timer.setInterval(REPAIR_TIMER, SAFETY_REPAIR_MS, {});
    timer.setInterval(MAP_TIMER, MAP_CHECK_MS, {});
    // Whatever was just applied gets one check soon: a TUN that is still
    // negotiating or an apply that failed is then retried from there.
    if (keys.some(function (k) { return leases[k].active && leases[k].pending; })) timer.setTimeout(RETRY_TIMER, PENDING_RETRY_MS, {});
  } else {
    [REPAIR_TIMER, EVENT_TIMER, RETRY_TIMER, MAP_TIMER].forEach(function (name) { timer.clear(name); });
  }
}
// Chained exits: a proxy exit's upstream_interface may be another applied
// exit's WAN boundary. Its core binds every socket there (sing-box
// default_interface, Mihomo interface-name), and the front's TC adapter carries
// that traffic into the front tunnel like any other packet leaving the boundary.
function exitByBoundary(name, leases) {
  var keys = Object.keys(leases);
  for (var i = 0; i < keys.length; i++) {
    var lease = leases[keys[i]];
    if (name && lease.active && !isLegacy(lease) && lease.plan.local === name) return {key: keys[i], lease: lease};
  }
  return null;
}
function chainDepth(key, leases) {
  var depth = 0, seen = {}, cur = leases[key];
  seen[key] = true;
  while (cur && cur.plan && cur.plan.upstream_interface) {
    var front = exitByBoundary(cur.plan.upstream_interface, leases);
    if (!front || seen[front.key]) break;
    seen[front.key] = true; depth++; cur = front.lease;
  }
  return depth;
}
// Fronts before the exits chained behind them, then by key.
function chainOrder(leases) {
  var depth = {};
  Object.keys(leases).forEach(function (k) { depth[k] = chainDepth(k, leases); });
  return Object.keys(leases).sort(function (a, b) { return depth[a] - depth[b] || (a < b ? -1 : a > b ? 1 : 0); });
}
function dependents(key, leases) {
  leases = leases || allLeases();
  var lease = leases[key];
  if (!lease || !lease.plan || !lease.plan.local) return [];
  return Object.keys(leases).filter(function (k) {
    return k !== key && leases[k].active && leases[k].plan && leases[k].plan.upstream_interface === lease.plan.local;
  }).sort();
}
function assertNoDependents(key) {
  var users = dependents(key);
  if (users.length) throw fail('upstream_in_use', 'Exit ' + key + ' is the upstream of ' + users.join(', ') + '; teardown those exits or change their upstream first');
}
// Structural checks of an upstream that is another exit: never a tunnel or
// pipeline, no loop, at most MAX_CHAIN exits in front. Returns the front exit.
function upstreamChain(p) {
  var leases = allLeases();
  Object.keys(leases).forEach(function (k) {
    var other = leases[k].plan;
    if (k !== p.key && other && [other.interface, other.pipeline].indexOf(p.upstream_interface) >= 0)
      throw fail('upstream_invalid', 'A VPN tunnel or pipeline cannot be the upstream; select the WAN boundary ' + other.local + ' of exit ' + k);
  });
  var front = exitByBoundary(p.upstream_interface, leases);
  if (!front) {
    if (/^veer(wg|vpn)[0-9]+$/.test(p.upstream_interface)) throw fail('upstream_exit_down', 'Upstream VPN exit boundary ' + p.upstream_interface + ' is not applied; apply that exit first');
    return null;
  }
  for (var cur = front, depth = 1; cur; depth++) {
    if (cur.key === p.key) throw fail('upstream_cycle', 'Upstream exits would form a loop through ' + p.key);
    if (depth > MAX_CHAIN) throw fail('upstream_chain_too_long', 'At most ' + MAX_CHAIN + ' VPN exits can be chained in front of a proxy exit');
    cur = cur.lease.plan.upstream_interface ? exitByBoundary(cur.lease.plan.upstream_interface, leases) : null;
  }
  return front;
}
// Before (re)starting a chained core: the front must be published, and its
// boundary must accept replies addressed to the core's own sockets.
function upstreamReady(front, p) {
  var status = resources.get('status', front.key), boundary = link(p.upstream_interface);
  if (front.lease.pending || !status || !status.data || status.data.phase !== 'applied' || !boundary)
    throw fail('upstream_exit_down', 'Upstream VPN exit ' + front.key + ' is not ready');
  loosenReversePath(p.upstream_interface);
  return boundary;
}
// Replies to a chained core arrive on the front boundary, while the host's
// best route back to the node uses the physical uplink. Strict reverse-path
// filtering (rp_filter 1) drops them. The kernel uses max(all, interface), so
// loose mode on this plugin-owned boundary alone is enough.
function loosenReversePath(name) {
  function value(key) { return Number(command(SYSCTL, ['-n', key]).trim()); }
  try {
    var own = 'net.ipv4.conf.' + name + '.rp_filter';
    if (Math.max(value('net.ipv4.conf.all.rp_filter'), value(own)) !== 1) return;
    command(SYSCTL, ['-q', '-w', own + '=2']);
  } catch (e) {
    throw fail('upstream_rp_filter', 'Strict reverse-path filtering on ' + name + ' drops replies to the chained core and could not be relaxed: ' + String(e.message || e));
  }
}
function normalize(key, raw) {
  raw = raw || {};
  if (raw.upstream_ip && raw.driver !== 'sing_box') throw fail('upstream_ip_singbox_only', '出站 IP 仅支持 sing-box');
  if (raw.driver && raw.driver !== 'wireguard') return normalizeTUN(key, raw);
  if (raw.bindings || raw.masquerade != null || raw.bypass_cidrs) throw new Error('Legacy routing profile: teardown the old profile, then configure a WAN and select it in Egress NAT');
  var p = {driver: 'wireguard', key: key, slot: integer(raw.slot, 1, 8, 1), interface: 'vwg' + key,
    mtu: integer(raw.mtu, 1280, 9000, 1420), listen_port: integer(raw.listen_port, 0, 65535, 0)};
  p.owner = 'veer:vpn_core:' + key;
  p.wan_id = 'wg_' + key; p.local = 'veerwg' + p.slot; p.pipeline = 'veerwgp' + p.slot;
  p.handoff_mode = DIRECT ? 'direct' : 'segmented_veth';
  p.addresses = list(raw.addresses, 1, 8).map(function (v) { return prefix(v, true).text; });
  if (!p.addresses.some(function (v) { return prefix(v).family === '4'; })) throw fail('wg_address_required', 'A local IPv4 tunnel address is required for Veer Egress NAT');
  p.peers = list(raw.peers, 1, 8).map(function (peer) {
    var endpoint = String(peer.endpoint || '');
    if (endpoint) {
      var match = /^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)$/.exec(endpoint);
      if (!match) throw fail('endpoint_invalid', 'Endpoint must be a numeric IP:port (bracket IPv6)');
      address(match[1].replace(/[\[\]]/g, '')); integer(match[2], 1, 65535);
    }
    return {public_key: wgKey(peer.public_key), endpoint: endpoint,
      allowed_ips: list(peer.allowed_ips, 1, 32).map(function (v) { return prefix(v).text; }),
      keepalive: integer(peer.keepalive, 0, 65535, 25), preshared_key_secret: peer.preshared_key_secret ? token(peer.preshared_key_secret) : ''};
  });
  var seenPeers = {}, seenPrefixes = {};
  p.peers.forEach(function (peer) {
    if (seenPeers[peer.public_key]) throw fail('peer_invalid', 'Duplicate peer public key');
    seenPeers[peer.public_key] = true;
    peer.allowed_ips.forEach(function (v) { if (seenPrefixes[v]) throw fail('peer_invalid', 'AllowedIPs must not be duplicated across peers'); seenPrefixes[v] = true; });
    if (peer.endpoint) {
      var endpointIP = peer.endpoint[0] === '[' ? peer.endpoint.slice(1, peer.endpoint.indexOf(']')) : peer.endpoint.split(':')[0];
      if (p.addresses.some(function (v) { return covers(prefix(v), prefix(endpointIP)); })) throw fail('route_invalid', 'Tunnel address route would capture a WireGuard endpoint');
    }
  });
  p.remote_routes = list(raw.remote_routes || [], 0, 32).map(function (v) {
    var cidr = prefix(v);
    if (cidr.bits === 0) throw fail('route_invalid', 'remote_routes cannot replace the host default route; select the WAN in Egress NAT instead');
    if (!p.peers.some(function (peer) { return peer.allowed_ips.some(function (a) { return covers(prefix(a), cidr); }); })) throw fail('route_invalid', 'Route is not covered by peer AllowedIPs');
    p.peers.forEach(function (peer) {
      if (!peer.endpoint) return;
      var host = peer.endpoint[0] === '[' ? peer.endpoint.slice(1, peer.endpoint.indexOf(']')) : peer.endpoint.split(':')[0];
      if (covers(cidr, prefix(host))) throw fail('route_invalid', 'Remote route would capture a WireGuard endpoint');
    });
    return cidr.text;
  });
  return p;
}
function settings(p) { if (p.driver && p.driver !== 'wireguard') return p.settings; return {slot: p.slot, mtu: p.mtu, listen_port: p.listen_port, addresses: p.addresses, peers: p.peers, remote_routes: p.remote_routes}; }
function link(name) {
  // Prefer a bounded native lookup. Older hosts lack alias/TUN details, so
  // retain their exec path rather than weakening the ownership checks.
  try {
    var info = net.link.get(name);
    if (typeof info.alias === 'string' && (info.kind !== 'tuntap' || info.tun_mode)) {
      return {ifname: info.name, ifindex: info.ifindex, ifalias: info.alias,
        linkinfo: {info_kind: info.tun_mode || info.kind}, mtu: info.mtu,
        address: info.mac, flags: info.up ? ['UP'] : [], link_index: info.peer_ifindex,
        link: info.peer_name, tun_vnet_hdr: info.tun_vnet_hdr === true};
    }
  } catch (e) {
    if (String(e.message || e).indexOf('link not found:') >= 0) return null;
    throw e;
  }
  // Query only this device; dumping a PVE host's whole interface inventory on
  // every health check can exceed the exec output bound and waste CPU.
  var result = execute(IP, ['-j', '-d', 'link', 'show', 'dev', name]);
  if (result.exit_code !== 0) {
    if (/does not exist|Cannot find device/.test(result.stderr || '')) return null;
    throw new Error('Cannot inspect VPN interface');
  }
  return JSON.parse(result.stdout || '[]').filter(function (l) { return l.ifname === name; })[0] || null;
}
function ownedLink(p, lease) {
  var current = link(p.interface);
  // Callers that already hold the lease save a KV listing per check.
  if (lease === undefined) lease = allLeases()[p.key];
  var created = current && lease && lease.pending && lease.created_ifindex === current.ifindex && !current.ifalias;
  if (current && ((current.ifalias !== p.owner && !created) || !current.linkinfo || current.linkinfo.info_kind !== (p.driver && p.driver !== 'wireguard' ? 'tun' : 'wireguard'))) throw fail('unowned_interface', 'Refusing to modify an existing unowned VPN interface');
  return current;
}
function wanRecord(resource, p) { return plugins.resources.get('wan_core', resource, p.wan_id); }
function cleanWANState(p) {
  var status = wanRecord('status', p), session = wanRecord('sessions', p);
  if (!status || status.enabled !== false || !session || session.enabled !== false) return false;
  var data = status.data || {}, owner = session.data || {};
  if (owner.driver_plugin !== 'vpn_core' || owner.profile_key !== p.key || owner.wan_id !== p.wan_id ||
      owner.real_interface !== p.interface || data.local_interface !== p.local || !knownWANPipeline(p, data.pipeline_interface) ||
      (data.cleanup_errors || []).length) return false;
  if (data.phase === 'deleted') return true;
  // Older WAN Core versions replaced the teardown journal with "disabled"
  // during restart. Accept only its fully withdrawn, matching owner state;
  // the caller separately requires every managed interface to be absent.
  return data.phase === 'disabled' && data.driver_plugin === 'vpn_core' && data.profile_key === p.key &&
    data.managed_link === false && data.arp_disabled_by_plugin !== true && data.noarp_ready !== true;
}
function assertWANOwner(p) {
  var session = wanRecord('sessions', p);
  ['sessions', 'status'].forEach(function (resource) {
    var r = wanRecord(resource, p);
    if (resource === 'status' && r && r.data && r.data.phase === 'deleted' && session && session.enabled === false &&
        session.data.driver_plugin === 'vpn_core' && session.data.profile_key === p.key && session.data.real_interface === p.interface &&
        r.data.local_interface === p.local && knownWANPipeline(p, r.data.pipeline_interface)) return;
    if (r && r.data && r.data.driver_plugin !== 'vpn_core') throw fail('wan_owned_by_other', 'WAN key is already owned by another driver');
  });
}
function wanCall(action, payload) { return plugins.services.call({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core', action: action, payload: payload}); }
function wanPipeline(p) { return p.handoff_mode === 'direct' ? '' : p.pipeline; }
function knownWANPipeline(p, name) { return !name || name === p.pipeline; }
function boundaryLinks(p, previousMode) {
  var r = wanRecord('status', p), data = r && r.data;
  if (!data || data.driver_plugin !== 'vpn_core' || data.local_interface !== p.local) return null;
  var name = data.pipeline_interface || '';
  if (previousMode ? (name && name !== p.pipeline) : name !== wanPipeline(p)) return null;
  var local = link(p.local), peer = name ? link(name) : local;
  if (!name) {
    if (!local || !local.linkinfo || local.linkinfo.info_kind !== 'dummy' || data.local_ifindex !== local.ifindex) return null;
    return {local: local, peer: local, direct: true};
  }
  if (!local || !peer || !local.linkinfo || !peer.linkinfo || local.linkinfo.info_kind !== 'veth' || peer.linkinfo.info_kind !== 'veth') return null;
  function linked(a, b) { return a.link_index === b.ifindex || a.link === b.ifname; }
  if (!linked(local, peer) || !linked(peer, local) || data.local_ifindex !== local.ifindex || data.pipeline_ifindex !== peer.ifindex) return null;
  return {local: local, peer: peer};
}
function wanPayload(p, usable) {
  // Kernel WireGuard segments GSO skbs itself, so its boundary keeps GSO on
  // both the helper and the plain BPF path; segmenting at the WAN boundary
  // would push every MTU-sized packet through the veth and TC separately.
  // A managed TUN must positively negotiate vnet headers and offloads before
  // accepting large skbs. Never carry a previous core generation's capability
  // into its prepared/restarting boundary.
  var gso = (!p.driver || p.driver === 'wireguard') || (usable && p.tun_gso === true);
  return {wan_id: p.wan_id, key: p.wan_id, profile_key: p.key, driver: p.driver || 'wireguard', driver_plugin: 'vpn_core',
    state: usable ? 'up' : 'prepared', usable: usable, real_interface: p.interface, wan_interface: p.local,
    local_interface: p.local, pipeline_interface: wanPipeline(p), handoff_mode: p.handoff_mode || 'segmented_veth', mtu: p.mtu,
    ipv4: p.addresses.filter(function (v) { return prefix(v).family === '4'; })[0].split('/')[0],
    addresses: p.addresses, routes: p.remote_routes.map(function (dst) { return {dst: dst, dev: p.local}; }),
    install_default_route: false, install_default_route_v6: false, egress_nat_redirect_mode: 'prepared_l2',
    interface_preparation: {local_gso: {max_size: gso ? 65536 : p.mtu, max_segs: gso ? 65535 : 1}, local_offloads: {sg: gso, tso: gso, gso: gso}, pipeline_offloads: {gro: gso, lro: false}}};
}
function bindings(exclude) {
  var names = [], outgoing = [], leases = allLeases();
  Object.keys(leases).sort().forEach(function (key) {
    var lease = leases[key];
    if (key !== exclude && lease.active && !isLegacy(lease)) {
      names.push(lease.plan.interface);
      if (lease.plan.handoff_mode === 'direct') outgoing.push(lease.plan.local);
      else names.push(lease.plan.pipeline);
    }
  });
  // Records for hooks this version no longer declares, such as the wg-* hooks
  // before 0.9.1, would otherwise fill the two-record resource.
  resources.list('hook_bindings', {limit: 8}).forEach(function (r) {
    if (r.key !== HOOK_IN && r.key !== HOOK_DIRECT_OUT) resources.delete('hook_bindings', r.key);
  });
  resources.set('hook_bindings', HOOK_IN, {hook_id: HOOK_IN, interfaces: names}, names.length > 0, true);
  resources.set('hook_bindings', HOOK_DIRECT_OUT, {hook_id: HOOK_DIRECT_OUT, interfaces: outgoing}, outgoing.length > 0, true);
}
function u32(n) { var s = ''; for (var i = 0; i < 4; i++) s += ('0' + ((n >>> (i * 8)) & 255).toString(16)).slice(-2); return s; }
function macHex(s) { if (!/^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/.test(s || '')) throw new Error('Invalid WAN boundary MAC'); return s.replace(/:/g, '').toLowerCase(); }
function clearMaps(lease) {
  if (lease && lease.plan && lease.plan.key) delete expectedMaps[lease.plan.key];
  [lease && lease.tunnel_ifindex, lease && lease.pipeline_ifindex].forEach(function (index) {
    if (!index) return;
    try { ebpf.mapDelete(OBJECT, MAP, u32(index)); }
    catch (e) { if (String(e.message || e).indexOf('plugin runtime target is not loaded') < 0) throw e; }
  });
}
function mapEntries(p, tunnel, boundary) {
  var entries = [
    {op: 'put', object: OBJECT, map: MAP, key: u32(boundary.peer.ifindex), value: u32(1) + u32(tunnel.ifindex) + '000000000000000000000000' + u32(p.mtu)},
    {op: 'put', object: OBJECT, map: MAP, key: u32(tunnel.ifindex), value: u32(boundary.direct ? 3 : 2) + u32(boundary.peer.ifindex) + macHex(boundary.peer.address) + macHex(boundary.local.address) + u32(p.mtu)}
  ];
  // Every caller writes these or checks them against the map.
  if (p.key) expectedMaps[p.key] = {tunnel: tunnel.ifindex, pipeline: boundary.peer.ifindex, entries: entries};
  return entries;
}
function repairMaps(p, tunnel, boundary) {
  // A dataplane replacement can lose private maps without replacing netdevs
  // or the core. Restore only this WAN's two entries; leave live flows alone.
  var entries = mapEntries(p, tunnel, boundary);
  if (entries.some(function (entry) {
    // Hash-map reads may throw for absent keys.
    try { return ebpf.mapGet(OBJECT, MAP, entry.key) !== entry.value; }
    catch (_) { return true; }
  }))
    ebpf.mapTransaction({operations: entries});
}
function installMaps(p, tunnel, boundary, old) {
  var ops = [], next = [tunnel.ifindex, boundary.peer.ifindex];
  [old && old.tunnel_ifindex, old && old.pipeline_ifindex].forEach(function (n) { if (n && next.indexOf(n) < 0) ops.push({op: 'delete', object: OBJECT, map: MAP, key: u32(n)}); });
  ebpf.mapTransaction({operations: ops.concat(mapEntries(p, tunnel, boundary))});
}
function isLegacy(lease) { return !!(lease && lease.plan && lease.plan.bindings); }
function apply(key, raw, explicit, revision) {
  if (explicit) health.invalidate(key);
  var before = changing; changing = true;
  try {
    var result = raw && raw.driver && raw.driver !== 'wireguard' ? applyTUNProfile(key, raw, explicit === true) : applyProfile(key, raw, explicit === true);
    if (explicit) recordApplied(key, raw, revision);
    annotateStatus(key);
    return result;
  } finally { changing = before; }
}
// What the page compares with the draft: the profile revision and, for
// generated proxy configs, the node of the last explicit apply. Kept outside
// the lease, which the drivers rewrite as a whole.
function recordApplied(key, raw, revision) {
  var applied = {profile_revision: typeof revision === 'number' ? revision : 0, node: null};
  if (raw && (raw.driver === 'mihomo' || raw.driver === 'sing_box')) {
    try {
      var saved = JSON.parse(secret.get(raw.config_secret || 'core_' + key) || 'null');
      if (saved && saved.veer_proxy === 1) {
        var form = shares.metadata(saved), nodes = form.nodes || [], node = nodes[form.selected || 0];
        var summary = function (n) { return {name: String(n.name || ''), type: String(n.type || '')}; };
        if (node) applied.node = summary(node);
        // Front hops in dialing order, so the card can show the chain that was applied.
        if (node && form.via && form.via.length) applied.node.via = form.via.map(function (i) { return summary(nodes[i]); });
      }
    } catch (_) { /* A native or unreadable config has no node summary. */ }
  }
  kv.set('applied_' + key, applied);
}
function annotateStatus(key) {
  var status = resources.get('status', key), applied = kv.get('applied_' + key);
  applied = applied && applied.data;
  if (!status || !status.data || !applied) return;
  var data = status.data;
  if (data.profile_revision === applied.profile_revision && JSON.stringify(data.node || null) === JSON.stringify(applied.node || null)) return;
  data.profile_revision = applied.profile_revision; data.node = applied.node || null;
  resources.set('status', key, data, status.enabled !== false);
}
function applyProfile(key, raw, explicit) {
  var p = normalize(key, raw), old = allLeases()[key];
  if (isLegacy(old)) throw fail('teardown_required', 'Teardown the legacy routing profile before creating a WireGuard WAN');
  if (old && (old.plan.driver && old.plan.driver !== 'wireguard')) throw fail('teardown_required', 'Teardown before changing the driver');
  if (old && old.plan.slot !== p.slot) throw fail('teardown_required', 'Teardown before changing the slot');
  Object.keys(allLeases()).forEach(function (k) { if (k !== key && allLeases()[k].plan.slot === p.slot) throw fail('slot_reserved', 'Slot is already reserved by another profile'); });
  plugins.services.resolve({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'});
  assertWANOwner(p);
  var wg = ownedLink(p), config = configuration(p);
  var previousWAN = wanRecord('status', p), previousSession = wanRecord('sessions', p);
  var cleanWAN = cleanWANState(p);
  if (!old) assertNoLeftovers(p, [wg && p.interface, link(p.local) && p.local, link(p.pipeline) && p.pipeline], (previousWAN || previousSession) && !cleanWAN);
  var stable = boundaryLinks(p);
  if (!explicit && old && !old.pending && wg && stable && wg.ifindex === old.tunnel_ifindex &&
      wg.mtu === p.mtu && (wg.flags || []).indexOf('UP') >= 0 && stable.local.ifindex === old.local_ifindex &&
      stable.peer.ifindex === old.pipeline_ifindex) {
    bindings(); repairMaps(p, wg, stable);
    return resources.get('status', key).data;
  }
  kv.set('lease_' + key, {active: true, pending: true, settings: settings(p), plan: p,
    created_ifindex: old && old.created_ifindex, tunnel_ifindex: old && old.tunnel_ifindex, local_ifindex: old && old.local_ifindex, pipeline_ifindex: old && old.pipeline_ifindex});
  try {
    if ((link(p.local) || link(p.pipeline)) && !boundaryLinks(p, true)) throw fail('boundary_not_ready', 'WAN boundary is not ready or no longer owned; inspect replaced interfaces');
    suspendTUN(p, old);
    wanCall('prepare_handoff', wanPayload(p, false));
    if (!wg) {
      ip(['link', 'add', 'name', p.interface, 'alias', p.owner, 'type', 'wireguard']);
      // Some iproute/kernel combinations ignore alias during RTM_NEWLINK.
      var created = link(p.interface), pending = allLeases()[key];
      if (!created || !created.linkinfo || created.linkinfo.info_kind !== 'wireguard') throw fail('wireguard_unavailable', 'WireGuard creation did not return the expected link');
      pending.created_ifindex = created.ifindex; kv.set('lease_' + key, pending);
    }
    ip(['link', 'set', 'dev', p.interface, 'alias', p.owner]);
    command(WG, ['syncconf', p.interface, '/dev/stdin'], config);
    ip(['link', 'set', 'dev', p.interface, 'mtu', String(p.mtu), 'up']);
    wg = ownedLink(p);
    var boundary = boundaryLinks(p);
    if (!wg || !boundary) throw fail('boundary_not_ready', 'WAN boundary is not ready');
    bindings();
    installMaps(p, wg, boundary, old);
    plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, true), true, true);
    kv.set('lease_' + key, {active: true, settings: settings(p), plan: p, tunnel_ifindex: wg.ifindex,
      local_ifindex: boundary.local.ifindex, pipeline_ifindex: boundary.peer.ifindex});
    var result = {phase: 'applied', interface: p.interface, wan_id: p.wan_id, local_interface: p.local,
      pipeline_interface: wanPipeline(p), handoff_mode: p.handoff_mode, egress_nat_interface: p.local, egress_nat_source_ip: wanPayload(p, true).ipv4,
      egress_nat_redirect_mode: 'prepared_l2', tc_ready: true, mtu: p.mtu, dataplane: KFUNCS ? 'kfuncs' : 'bpf', boundary_gso: true};
    resources.set('status', key, result, true); armRepair(); return result;
  } catch (e) {
    try {
      clearMaps(old);
      wg = ownedLink(p); if (wg) clearMaps({tunnel_ifindex: wg.ifindex});
      var partial = boundaryLinks(p); if (partial) clearMaps({pipeline_ifindex: partial.peer.ifindex});
    } catch (cleanup) { log.error('Tunnel map cleanup failed: ' + String(cleanup.message || cleanup)); }
    resources.set('status', key, errorStatus(key, p, e), true);
    throw e;
  }
}
function teardown(key) {
  health.invalidate(key);
  var before = changing; changing = true;
  try { return teardownProfile(key); } finally { changing = before; }
}
function profileSecrets(key, data) {
  var names = ['private_' + key, 'active_' + key, 'core_' + key, 'core_mihomo_' + key, 'core_sing_box_' + key];
  if (data) {
    if (data.config_secret) names.push(data.config_secret);
    (data.peers || []).forEach(function (peer) { if (peer.preshared_key_secret) names.push(peer.preshared_key_secret); });
  }
  for (var i = 0; i < 8; i++) names.push('psk_' + key + '_' + i);
  return names.filter(function (name) { return /^[a-z][a-z0-9_]{0,31}$/.test(name); });
}
function deleteProfile(key) {
  var record = resources.get('profiles', key), leases = allLeases(), lease = leases[key];
  var names = profileSecrets(key, record && record.data).concat(profileSecrets(key, lease && lease.settings));
  var retained = [];
  resources.list('profiles', {limit: 8}).forEach(function (r) { if (r.key !== key) retained = retained.concat(profileSecrets(r.key, r.data)); });
  Object.keys(leases).forEach(function (k) { if (k !== key) retained = retained.concat(profileSecrets(k, leases[k].settings)); });
  // Keep the retryable draft and credentials until network cleanup succeeds.
  teardown(key);
  ['wg_' + key, 'vpn_' + key].forEach(function (id) {
    var session = plugins.resources.get('wan_core', 'sessions', id);
    if (!session || session.data.driver_plugin !== 'vpn_core' || session.data.profile_key !== key) return;
    if (session.enabled !== false) throw fail('wan_cleanup_incomplete', 'WAN session is still active; retry teardown');
    wanCall('teardown', {key: id, session: session.data, forget: true});
    if (plugins.resources.get('wan_core', 'sessions', id)) throw fail('wan_cleanup_incomplete', 'WAN records remain; retry deletion');
  });
  health.remove(key);
  names.forEach(function (name) { if (retained.indexOf(name) < 0) secret.delete(name); });
  resources.transaction([{op: 'delete', resource: 'status', key: key}, {op: 'delete', resource: 'profiles', key: key}]);
  armRepair(); return {phase: 'deleted'};
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
      if (wanRecord('status', p).data.phase !== 'deleted') throw fail('wan_cleanup_incomplete', 'WAN cleanup incomplete; retry teardown');
    }
  }
  kv.delete('lease_' + key); kv.delete('applied_' + key);
  resources.set('status', key, {phase: 'down'}, false); armRepair();
}
function inspect(key) {
  var lease = allLeases()[key]; if (!lease) return {phase: 'down'};
  var p = lease.plan, applied = kv.get('applied_' + key);
  var base = {driver: p.driver || 'wireguard', interface: p.interface, wan_id: p.wan_id, local_interface: p.local,
    handoff_mode: p.handoff_mode || 'segmented_veth', dataplane: KFUNCS ? 'kfuncs' : 'bpf', traffic: traffic(p.interface)};
  if (p.driver && p.driver !== 'wireguard') {
    var status = resources.get('status', key);
    base.phase = status && status.data ? status.data.phase : 'missing';
    base.process = p.driver === 'tun' ? null : processSummary(process.status('vpn_' + key));
    base.tun_gso = p.tun_gso === true; base.boundary_gso = p.tun_gso === true;
    base.node = applied && applied.data ? applied.data.node || null : null;
    return base;
  }
  if (!ownedLink(p)) { base.phase = 'missing'; return base; }
  base.phase = 'configured'; base.boundary_gso = true;
  base.public_key = command(WG, ['show', p.interface, 'public-key']).trim();
  base.peers = wgPeers(p);
  return base;
}
function upstreamInterfaces() {
  // Suggestions only: the profile still accepts any name and apply validates it.
  // Leave out loopback, every VPN tunnel and boundary, and hypervisor plumbing.
  var own = /^(veerwgp?|veervpnp?|vwg|vtun)[a-z0-9_]*$/, plumbing = /^(tap|fwbr|fwpr|fwln|veth)/;
  function addresses(l) { return (l.addresses || []).filter(function (a) { return !/^fe80:/i.test(a); }); }
  function boundary(name) { try { return net.link.get(name); } catch (_) { return null; } }
  var physical = net.link.list().filter(function (l) {
    return l.name && l.name !== 'lo' && !own.test(l.name) && !plumbing.test(l.name) && l.kind !== 'tuntap' && l.kind !== 'dummy';
  }).map(function (l) {
    return {name: l.name, kind: l.kind || '', up: l.up === true, addresses: addresses(l)};
  }).sort(function (a, b) {
    return (b.up - a.up) || (b.addresses.length > 0) - (a.addresses.length > 0) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  });
  // Applied exits come last: choosing one chains this exit behind it.
  var leases = allLeases(), exits = [];
  chainOrder(leases).forEach(function (k) {
    var lease = leases[k], status = resources.get('status', k), l = lease.plan && lease.plan.local ? boundary(lease.plan.local) : null;
    if (!lease.active || isLegacy(lease) || !l || !status || !status.data || status.data.phase !== 'applied') return;
    exits.push({name: lease.plan.local, kind: 'vpn', up: l.up === true, addresses: addresses(l), exit: k, driver: lease.plan.driver || 'wireguard'});
  });
  return physical.concat(exits);
}
function traffic(name) {
  // Tunnel counters: the boundary's own may skip redirected packets.
  try {
    var stats = net.link.get(name).statistics;
    return stats ? {rx_bytes: stats.rx_bytes, tx_bytes: stats.tx_bytes, rx_packets: stats.rx_packets, tx_packets: stats.tx_packets} : null;
  } catch (_) { return null; }
}
function wgPeers(p) {
  // Never `wg show dump`: its first line carries the private key.
  var peers = {};
  function rows(field) {
    return command(WG, ['show', p.interface, field]).split('\n').map(function (line) { return line.split('\t'); }).filter(function (cols) { return cols[0]; });
  }
  function peer(publicKey) { return peers[publicKey] || (peers[publicKey] = {public_key: publicKey, endpoint: '', latest_handshake: 0, rx_bytes: 0, tx_bytes: 0}); }
  rows('endpoints').forEach(function (c) { peer(c[0]).endpoint = c[1] && c[1] !== '(none)' ? c[1] : ''; });
  rows('latest-handshakes').forEach(function (c) { peer(c[0]).latest_handshake = Number(c[1]) || 0; });
  rows('transfer').forEach(function (c) { var v = peer(c[0]); v.rx_bytes = Number(c[1]) || 0; v.tx_bytes = Number(c[2]) || 0; });
  // Configured order first; a peer only the kernel knows still shows.
  var ordered = p.peers.map(function (configured) { var v = peer(configured.public_key); delete peers[configured.public_key]; return v; });
  return ordered.concat(Object.keys(peers).map(function (k) { return peers[k]; }));
}
exports.onHealthProbe = function (ctx) { health.run(ctx.payload || {}); };
function healthPath(key, workerRead) {
  var lease = allLeases()[key], status = resources.get('status', key);
  if (!lease || !lease.active || lease.pending || isLegacy(lease) || !status || status.data.phase !== 'applied') return null;
  var p = lease.plan, tunnel = ownedLink(p), boundary = boundaryLinks(p);
  if (!tunnel || (tunnel.flags || []).indexOf('UP') < 0 || tunnel.ifindex !== lease.tunnel_ifindex || !boundary ||
      boundary.local.ifindex !== lease.local_ifindex || boundary.peer.ifindex !== lease.pipeline_ifindex) return null;
  var managed = p.driver && p.driver !== 'wireguard' && p.driver !== 'tun';
  var proc = managed && !workerRead ? process.status('vpn_' + key) : null;
  if (proc && (proc.state !== 'running' || proc.started_at !== lease.process_started_at)) return null;
  var generation = kv.get('health_generation_' + key);
  return {interface: p.local, source_ip: wanPayload(p, true).ipv4,
    // Use ordered primitives: host-decoded objects do not promise JS property
    // order. Explicit applies/settings already advance the health generation.
    fingerprint: JSON.stringify([generation && generation.data, tunnel.ifindex, boundary.local.ifindex, boundary.peer.ifindex, managed ? lease.process_started_at : null])};
}

function execute(program, args, stdin) {
  var result;
  try { result = process.exec({command: program, args: args, stdin: stdin || '', timeout_ms: 2000}); }
  catch (e) {
    if (/no such file|not found/i.test(String(e.message || e))) throw fail('tool_missing', 'Required tool is not installed: ' + program);
    throw e;
  }
  if (result.timed_out || result.cancelled || result.truncated) throw fail('command_failed', 'Command did not complete: ' + program);
  return result;
}
function command(program, args, stdin) {
  var result = execute(program, args, stdin);
  if (result.exit_code === 0) return result.stdout || '';
  var text = 'Command failed: ' + program + ' ' + args[0] + ' (exit ' + result.exit_code + ')';
  // wg/nft diagnostics can quote their input, including keys: never expose
  // their stderr. ip never receives a key; keep its first line, minus anything
  // shaped like one.
  var reason = program === IP ? String(result.stderr || '').split('\n')[0].replace(/[A-Za-z0-9+/]{42,}=*/g, '[redacted]').slice(0, 160).trim() : '';
  if (program === IP && args.indexOf('wireguard') >= 0 && /Unknown device type|not supported|Not supported/i.test(reason))
    throw fail('wireguard_unavailable', text + ': ' + reason);
  throw fail('command_failed', reason ? text + ': ' + reason : text);
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
  if (!/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(key) || key === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') throw fail('wg_key_invalid', 'Invalid WireGuard key');
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
  var privateKey = secret.get('private_' + p.key);
  if (!privateKey) throw fail('private_key_missing', 'Save the local WireGuard private key before applying');
  var lines = ['[Interface]', 'PrivateKey = ' + wgKey(privateKey), 'ListenPort = ' + p.listen_port];
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
  if (raw.upstream_ip && driver !== 'sing_box') throw fail('upstream_ip_singbox_only', '出站 IP 仅支持 sing-box');
  var p = {key: key, driver: driver, slot: integer(raw.slot, 1, 8, 1), mtu: integer(raw.mtu, 1280, 9000, 1420)};
  p.interface = driver === 'tun' ? iface(raw.tun_interface) : 'vtun' + key;
  if (driver === 'tun' && !raw.tun_interface) throw fail('tun_config_invalid', 'An external TUN interface is required');
  p.owner = driver === 'tun' ? String(raw.tun_alias || '') : 'veer:vpn_core:' + key;
  if (!p.owner || p.owner.length > 128 || /[\r\n\0]/.test(p.owner)) throw fail('tun_config_invalid', 'An external TUN requires an explicit tun_alias ownership marker');
  p.wan_id = 'vpn_' + key; p.local = 'veervpn' + p.slot; p.pipeline = 'veervpnp' + p.slot;
  p.handoff_mode = DIRECT ? 'direct' : 'segmented_veth';
  if ([p.local, p.pipeline].indexOf(p.interface) >= 0) throw fail('tun_config_invalid', 'TUN and WAN boundaries must differ');
  p.addresses = list(raw.addresses || [], 0, 8).map(function (v) {
    var c = prefix(v, true);
    if (c.bits !== (c.family === '4' ? 32 : 128)) throw fail('wan_address_invalid', 'Proxy WAN addresses must be /32 or /128 to avoid changing host routes');
    return c.text;
  });
  if (p.addresses.length && !p.addresses.some(function (v) { return prefix(v).family === '4'; })) throw fail('wan_address_invalid', 'A local IPv4 WAN address is required');
  if (raw.remote_routes && raw.remote_routes.length) throw fail('route_invalid', 'Select this WAN in Veer instead of installing host routes');
  p.remote_routes = [];
  p.upstream_interface = driver === 'tun' ? '' : iface(raw.upstream_interface);
  if (driver !== 'tun' && (!raw.upstream_interface || [p.interface, p.local, p.pipeline].indexOf(p.upstream_interface) >= 0)) throw fail('upstream_invalid', 'Select a separate physical or PPPoE upstream_interface');
  p.upstream_ip = String(raw.upstream_ip || '').trim();
  if (p.upstream_ip) {
    // Bind an address already owned by the selected uplink; never create an
    // address, route or NAT rule to make a source binding appear to work.
    p.upstream_ip = addressText(address(p.upstream_ip));
    var upstream = net.link.get(p.upstream_interface);
    if (!(upstream.addresses || []).some(function (value) { return addressText(address(value.split('/')[0])) === p.upstream_ip; }))
      throw fail('upstream_ip_not_owned', '出站 IP 不属于所选出站接口');
  }
  var managed = driver !== 'tun' && !raw.core_path ? process.binaryStatus(driver) : null;
  p.core_path = driver === 'tun' ? '' : coreDrivers.command(driver, raw.core_path || (managed && managed.path));
  p.config_secret = raw.config_secret ? token(raw.config_secret) : 'core_' + key;
  p.max_restarts = integer(raw.max_restarts, 0, 10, 3);
  p.startup_timeout_seconds = integer(raw.startup_timeout_seconds, 1, 300, 30);
  p.settings = {driver: driver, slot: p.slot, mtu: p.mtu, addresses: p.addresses, upstream_interface: p.upstream_interface,
    core_path: p.core_path, config_secret: p.config_secret, max_restarts: p.max_restarts, startup_timeout_seconds: p.startup_timeout_seconds};
  if (p.upstream_ip) p.settings.upstream_ip = p.upstream_ip;
  if (driver === 'tun') { p.settings.tun_interface = p.interface; p.settings.tun_alias = p.owner; }
  return p;
}
function resolveWANAddresses(p, old) {
  // An explicit address keeps the existing API contract. Automatic addresses
  // are pinned in the applied lease, never recalculated on healthy polling or
  // recovery, so an existing NAT selection retains its source address.
  if (!p.addresses.length && old && old.plan.addresses && old.plan.addresses.length)
    p.addresses = old.plan.addresses.slice();
  if (!p.addresses.length) {
    var occupied = [];
    function reserve(values) { (values || []).forEach(function (v) { occupied.push(prefix(v)); }); }
    net.link.list().forEach(function (l) { reserve(l.addresses); });
    var routes = JSON.parse(command(IP, ['-j', '-4', 'route', 'show', 'table', 'all']));
    routes.forEach(function (r) { if (r.dst && r.dst !== 'default' && prefix(r.dst).bits > 0) reserve([r.dst]); });
    resources.list('profiles', {limit: 8}).forEach(function (r) { if (r.key !== p.key) reserve(r.data.addresses); });
    var leases = allLeases();
    Object.keys(leases).forEach(function (key) { if (key !== p.key) reserve(leases[key].plan.addresses); });
    var pools = ['10.78.', '172.31.', '192.168.', '198.19.'];
    for (var i = 0; i < pools.length && !p.addresses.length; i++) {
      for (var n = 0; n < 8; n++) {
        var candidate = prefix(pools[i] + (p.slot + n * 8) + '.1/32', true);
        if (!occupied.some(function (v) { return covers(v, candidate); })) { p.addresses = [candidate.text]; break; }
      }
    }
    if (!p.addresses.length) throw fail('no_free_address', 'No free internal WAN address; choose an unused /32 address in advanced settings');
  }
  p.settings.addresses = p.addresses;
}
function suspendTUN(p, lease) {
  if (p && p.key) delete expectedMaps[p.key];
  clearMaps(lease);
  // Keep the selected WAN boundary, but withdraw availability. Never fall back
  // to the host's direct default route when a core is absent or restarting.
  if (wanRecord('status', p)) plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, false), false, true);
}
function tunGSO(p, current) {
  // sing-box's Linux gVisor driver negotiates this itself and Mihomo does when
  // its generated config sets gso. External TUN providers have their own
  // contracts and retain the segmented boundary.
  if ((p.driver !== 'sing_box' && p.driver !== 'mihomo') || current.tun_vnet_hdr !== true) return {enabled: false};
  try {
    var features = net.link.getOffloads(p.interface);
    var enabled = features.tx === true && features.sg === true && features.tso === true && features.gso === true;
    return {enabled: enabled, retry: !enabled};
  } catch (_) {
    // Offload introspection is an optimization; missing ethtool must not stop a
    // working core. Keep diagnostics bounded and free of core configuration.
    log.warn('TUN offload capability unavailable; using a segmented VPN boundary');
    return {enabled: false};
  }
}
function applyTUNProfile(key, raw, explicit) {
  var p = normalizeTUN(key, raw), old = allLeases()[key], managed = p.driver !== 'tun';
  if (old && ((old.plan.driver || 'wireguard') !== p.driver || old.plan.slot !== p.slot || old.plan.interface !== p.interface))
    throw fail('teardown_required', 'Teardown before changing the driver, slot or TUN interface');
  Object.keys(allLeases()).forEach(function (k) {
    var other = allLeases()[k].plan;
    if (k !== key && (other.slot === p.slot || other.interface === p.interface)) throw fail('slot_reserved', 'Slot or TUN is already reserved by another profile');
  });
  var front = managed ? upstreamChain(p) : null, frontLink = front ? link(p.upstream_interface) : null;
  plugins.services.resolve({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'});
  assertWANOwner(p);
  resolveWANAddresses(p, old);
  var current = link(p.interface), previousWAN = wanRecord('status', p), previousSession = wanRecord('sessions', p);
  var cleanWAN = cleanWANState(p);
  if (!old) assertNoLeftovers(p, [managed && current && p.interface, link(p.local) && p.local, link(p.pipeline) && p.pipeline], (previousWAN || previousSession) && !cleanWAN);
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
  if (!explicit && old && !old.pending && current && current.linkinfo && current.linkinfo.info_kind === 'tun' && current.ifalias === p.owner && current.ifindex === old.tunnel_ifindex &&
      current.mtu === p.mtu && (current.flags || []).indexOf('UP') >= 0 && stableBoundary &&
      stableBoundary.local.ifindex === old.local_ifindex && stableBoundary.peer.ifindex === old.pipeline_ifindex &&
      (!managed || (stableProcess.state === 'running' && stableProcess.started_at === old.process_started_at)) &&
      (!front || (frontLink && frontLink.ifindex === old.upstream_ifindex))) {
    if (managed) process.start({id: 'vpn_' + key, command: spec.command, args: spec.args, config: spec.config,
      restart: 'on-failure', max_restarts: p.max_restarts, stop_timeout_ms: 1000});
    bindings(); installMaps(p, current, stableBoundary, old);
    return resources.get('status', key).data;
  }
  // A chained core waits for its front; nothing changes until it is ready.
  if (front) frontLink = upstreamReady(front, p);
  var lease = {active: true, pending: true, settings: p.settings, plan: p,
    tunnel_ifindex: old && old.tunnel_ifindex, pipeline_ifindex: old && old.pipeline_ifindex,
    local_ifindex: old && old.local_ifindex, process_started_at: old && old.process_started_at,
    upstream_ifindex: front ? frontLink.ifindex : null};
  kv.set('lease_' + key, lease);
  try {
    suspendTUN(p, old);
    wanCall('prepare_handoff', wanPayload(p, false));
    var proc = null;
    if (managed) {
      if (explicit) {
        process.stop('vpn_' + key);
        if (link(p.interface)) throw fail('tun_external_remains', 'TUN remains after core stop; refusing to take over an external interface');
        secret.set('active_' + key, spec.config);
      }
      // A rebuilt front boundary has a new ifindex: restart the chained core so
      // no socket stays bound to the old one. Stopping costs no restart budget.
      if (!explicit && front && old && old.upstream_ifindex !== frontLink.ifindex) process.stop('vpn_' + key);
      // A stopped owner generation can be restored; exited/failed entries retain their budget.
      if (!explicit && process.status('vpn_' + key).state === 'stopped') process.stop('vpn_' + key);
      // An exhausted restart budget remains exhausted until an explicit apply.
      proc = process.start({id: 'vpn_' + key, command: spec.command, args: spec.args, config: spec.config,
        restart: 'on-failure', max_restarts: p.max_restarts, stop_timeout_ms: 1000});
      current = link(p.interface);
      // Some cores keep running after their TUN is deleted. Restart only a
      // previously published generation, with the supervisor's existing budget.
      if (!explicit && !current && proc.state === 'running' &&
          ((old && old.tunnel_ifindex && proc.started_at === old.process_started_at) || Date.now() - proc.started_at >= p.startup_timeout_seconds * 1000))
        proc = process.restart('vpn_' + key);
      if (proc.state !== 'running' || !current) {
        var stopped = proc.state === 'exited' || proc.state === 'failed';
        var waiting = {phase: stopped ? 'failed' : 'starting', driver: p.driver, interface: p.interface, wan_id: p.wan_id, wan_addresses: p.addresses,
          process: processSummary(proc), startup_timeout_seconds: p.startup_timeout_seconds, max_restarts: p.max_restarts};
        // An exhausted budget stays failed until an explicit apply; say so.
        if (stopped) { waiting.error_code = 'core_exited'; waiting.error = 'Core exited with code ' + proc.exit_code + ' after ' + proc.starts + ' start(s)'; }
        resources.set('status', key, waiting, true);
        armRepair(); return {phase: 'starting', driver: p.driver, wan_id: p.wan_id, wan_addresses: p.addresses, process: proc};
      }
      if (!current.linkinfo || current.linkinfo.info_kind !== 'tun') throw fail('tun_not_created', 'Core did not create a TUN interface');
      if (!current.ifalias && (!old || proc.started_at !== old.process_started_at)) ip(['link', 'set', 'dev', p.interface, 'alias', p.owner]);
    }
    current = ownedLink(p);
    if (managed && current && ((current.flags || []).indexOf('UP') < 0 || current.mtu !== p.mtu)) {
      ip(['link', 'set', 'dev', p.interface, 'mtu', String(p.mtu), 'up']);
      current = ownedLink(p);
    }
    if (!current || (current.flags || []).indexOf('UP') < 0) throw fail('tun_not_ready', 'TUN interface is not ready');
    if (current.mtu !== p.mtu) throw fail('tun_mtu_mismatch', 'TUN MTU does not match the WAN profile');
    // The TUN becomes visible before a core finishes TUNSETOFFLOAD. A negative
    // result at that instant is not its final capability. Retry at most twice,
    // one second apart, while keeping the WAN unpublished and the maps empty.
    var generation = proc ? proc.started_at : current.ifindex;
    var sameProbe = old && old.tun_probe_generation === generation;
    var waiting = sameProbe && old.tun_probe_retry_at > Date.now();
    var probe = waiting ? {enabled: false, retry: true} : tunGSO(p, current);
    lease.tun_probe_generation = generation;
    lease.tun_probe_attempts = (sameProbe ? old.tun_probe_attempts || 0 : 0) + (waiting ? 0 : 1);
    if (waiting || (probe.retry && lease.tun_probe_attempts < 3)) {
      lease.tun_probe_retry_at = waiting ? old.tun_probe_retry_at : Date.now() + 1000;
      kv.set('lease_' + key, lease);
      var starting = {phase: 'starting', driver: p.driver, interface: p.interface, wan_id: p.wan_id, wan_addresses: p.addresses, process: proc};
      resources.set('status', key, starting, true); armRepair(); return starting;
    }
    p.tun_gso = probe.enabled;
    // Probe only while publishing this generation, never on healthy polling.
    var verified = ownedLink(p);
    if (!verified || verified.ifindex !== current.ifindex || verified.mtu !== p.mtu || (verified.flags || []).indexOf('UP') < 0)
      throw fail('core_restarted', 'TUN changed while inspecting its capabilities');
    if (p.tun_gso) {
      // WAN Core persists the preparation in its profile, which takes priority
      // over later session fields. Update that profile before publishing;
      // otherwise its original segmented settings silently override the probe.
      var prepared = wanPayload(p, false);
      prepared.interface_preparation = wanPayload(p, true).interface_preparation;
      wanCall('prepare_handoff', prepared);
    }
    var boundary = boundaryLinks(p);
    if (!boundary) throw fail('boundary_not_ready', 'WAN boundary is not ready');
    lease.tunnel_ifindex = current.ifindex; lease.local_ifindex = boundary.local.ifindex;
    lease.pipeline_ifindex = boundary.peer.ifindex;
    kv.set('lease_' + key, lease);
    bindings(); installMaps(p, current, boundary, old);
    if (managed && (process.status('vpn_' + key).state !== 'running' || process.status('vpn_' + key).started_at !== proc.started_at)) throw fail('core_restarted', 'Core restarted while publishing the WAN');
    plugins.resources.set('wan_core', 'sessions', p.wan_id, wanPayload(p, true), true, true);
    lease.pending = false; lease.tunnel_ifindex = current.ifindex; lease.local_ifindex = boundary.local.ifindex;
    lease.pipeline_ifindex = boundary.peer.ifindex; lease.process_started_at = proc && proc.started_at;
    kv.set('lease_' + key, lease);
    var result = {phase: 'applied', driver: p.driver, interface: p.interface, wan_id: p.wan_id,
      local_interface: p.local, pipeline_interface: wanPipeline(p), handoff_mode: p.handoff_mode, egress_nat_interface: p.local, wan_addresses: p.addresses,
      egress_nat_source_ip: wanPayload(p, true).ipv4, egress_nat_redirect_mode: 'prepared_l2', tc_ready: true,
      process: proc && processSummary(proc), dataplane: KFUNCS ? 'kfuncs' : 'bpf', tun_gso: p.tun_gso, boundary_gso: p.tun_gso === true};
    resources.set('status', key, result, true); armRepair(); return result;
  } catch (e) {
    try { suspendTUN(p, lease); } catch (cleanup) { log.error('VPN suspension failed'); }
    // Core diagnostics may include credentials; never publish their output.
    resources.set('status', key, errorStatus(key, p, e, {process: managed ? processSummary(process.status('vpn_' + key)) : null}), true);
    armRepair(); throw e;
  }
}
// Returns false when the exit could not be repaired.
function repairTUN(key, lease) {
  try {
    var p = lease.plan, current = link(p.interface);
    var proc = p.driver === 'tun' ? null : process.status('vpn_' + key);
    var tunnelOK = !lease.pending && current && current.linkinfo && current.linkinfo.info_kind === 'tun' && current.ifalias === p.owner &&
      current.ifindex === lease.tunnel_ifindex && current.mtu === p.mtu && (current.flags || []).indexOf('UP') >= 0 &&
      !(proc && (proc.state !== 'running' || proc.started_at !== lease.process_started_at));
    // A chained exit also needs the same front boundary it bound to.
    if (tunnelOK && lease.upstream_ifindex != null) {
      var frontLink = link(p.upstream_interface);
      tunnelOK = !!frontLink && frontLink.ifindex === lease.upstream_ifindex;
    }
    var boundary = tunnelOK ? boundaryLinks(p) : null;
    if (!tunnelOK || !boundary || boundary.local.ifindex !== lease.local_ifindex || boundary.peer.ifindex !== lease.pipeline_ifindex) {
      suspendTUN(p, lease);
      apply(key, lease.settings);
    } else repairMaps(p, current, boundary);
    return true;
  } catch (e) {
    try { suspendTUN(lease.plan, lease); } catch (_) { log.error('VPN suspension failed'); }
    resources.set('status', key, errorStatus(key, lease.plan, e), true);
    return false;
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
    if (wanRecord('status', p).data.phase !== 'deleted') throw fail('wan_cleanup_incomplete', 'WAN cleanup incomplete; retry teardown');
  }
  kv.delete('lease_' + key); kv.delete('applied_' + key); secret.delete('active_' + key);
  resources.set('status', key, {phase: 'down', driver: p.driver}, false); armRepair();
}

function utf8Size(text) { return unescape(encodeURIComponent(text)).length; }
// Errors the page can explain start with a stable [code]; the WebUI localizes
// the code and shows the English rest as the diagnostic. Unknown errors keep
// their text and the page shows it unchanged.
function fail(code, message) { return new Error('[' + code + '] ' + message); }
function errorFields(e) {
  var text = String((e && e.message) || e), match = /^\[([a-z_]+)\] /.exec(text);
  return match ? {error: text.slice(match[0].length), error_code: match[1]} : {error: text, error_code: 'unknown'};
}
function errorStatus(key, p, e, extra) {
  var out = {phase: 'error', driver: p.driver || 'wireguard', interface: p.interface, local_interface: p.local, wan_id: p.wan_id,
    failed_at: Date.now(), cleanup_required: true};
  var fields = errorFields(e); out.error = fields.error; out.error_code = fields.error_code;
  // Repair retries every few seconds: keep the time the failure first appeared.
  var previous = resources.get('status', key);
  if (previous && previous.data && previous.data.phase === 'error' && previous.data.error === out.error && previous.data.failed_at)
    out.failed_at = previous.data.failed_at;
  Object.keys(extra || {}).forEach(function (k) { if (extra[k] != null) out[k] = extra[k]; });
  return out;
}
function processSummary(proc) {
  // Only supervisor facts: core output can carry credentials and stays in core_logs.
  return proc ? {state: proc.state, pid: proc.pid, starts: proc.starts, exit_code: proc.exit_code, started_at: proc.started_at} : null;
}
function assertNoLeftovers(p, links, wanRecords) {
  // Without a lease these belong to an interrupted cleanup or to someone else.
  // Name them so the administrator can inspect or remove exactly these.
  var names = links.filter(Boolean);
  if (wanRecords) names.push('WAN ' + p.wan_id);
  if (names.length) throw fail('ownership_missing', 'Recorded ownership is missing; leftover: ' + names.join(', '));
}
