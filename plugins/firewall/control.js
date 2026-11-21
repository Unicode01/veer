'use strict';
/*
 * Firewall: a source filter for the interfaces it is bound to, attached
 * through the Veer XDP dispatcher ahead of the TC dataplane. Policies match
 * TCP/UDP ports, ICMP types, IP protocols or everything else (catch-all);
 * global settings add blocklist sets, a security baseline and connection
 * tracking, whose tc_egress program records the connections this side opens
 * so their replies pass.
 *
 * Policies, sets and settings are drafts until "apply": it compiles them into
 * the generation of the maps the packets do not read, switches fw_cfg to it,
 * and starts a confirmation deadline. The page confirms once it can still
 * reach the API under the new rules; if it cannot, the deadline restores the
 * last confirmed rule set.
 *
 * Every map is declared preserve, so a Veer hot restart hands them to the
 * successor and filtering goes on without a gap. Snapshots of the applied
 * and confirmed rule sets rebuild the maps when they start empty: a cold
 * start, an older host, or a map layout that changed.
 *
 * Policies with a syn_limit also limit new TCP connections per source prefix
 * and ban sources over it (fw_rate, fw_ban; the bans/unban actions list and
 * lift them). Sets take elements at runtime too (set_add, or a policy's
 * add_to_set), which outlive applies. Drops are sampled into the fw_events
 * ring; the drop_log worker keeps the latest ones in memory for the events
 * action.
 */
var compile = require('./lib/compile');

var OBJECT = 'firewall';
var OBJECT_PATH = 'firewall.o';
var HOOK = 'wan-filter';
var CONFIRM_TIMER = 'confirm_deadline';
var SYNC_TIMER = 'sync_retry';
var PRUNE_TIMER = 'set_prune';
var STATE_KEY = 'state';
var GEN_ARRAYS_KEY = 'gen_arrays';
var IFACES_KEY = 'ifaces';
var DYN_KEY = 'dyn_sets';
var DEFAULT_CONFIRM_SECONDS = 120;
var SYNC_RETRY_MS = 3000;
var SYNC_RETRY_LIMIT = 20;
var PRUNE_MS = 60000;
var TX_LIMIT = 256;
var LPM_MAPS = ['fw_ports', 'fw_dst4', 'fw_dst6', 'fw_src4', 'fw_src6'];
var ARRAY_ZERO = {fw_port_bits: '0000000000000000', fw_class: '00000000', fw_policy: '00000000', fw_limit: compile.LIMIT_VALUE_ZERO,
  fw_pext: compile.PEXT_VALUE_ZERO, fw_gcfg: compile.GCFG_VALUE_ZERO};
var ARRAY_SIZES = {fw_port_bits: 2 * compile.PORT_WORDS_PER_GEN, fw_class: 2 * compile.CLASSES_PER_GEN, fw_policy: 2 * compile.POLICIES_PER_GEN,
  fw_limit: 2 * compile.POLICIES_PER_GEN, fw_pext: 2 * compile.POLICIES_PER_GEN, fw_gcfg: 2};
var CFG_HAS_L3 = 1;
var CFG_ACTIVE = 2;
var CFG_LOADED = 4; // written by this script only, tells fresh maps apart
var IFACE_L3 = 1;
var COUNTER_NAMES = ['pass', 'drop', 'trusted'];
var EVASIVE_COUNTER = 3;
var IFACE_NAME = /^[A-Za-z0-9_.:@-]{1,15}$/;
var LIMIT_KEY_HEX = /^[0-9a-f]{40}$/;
var DEFAULT_LOG_PER_SECOND = 10;
var LOG_WORKER = 'drop_log';
var LOG_KEEP = 500;
var MAX_API_ELEMENTS = 1024;      // set_add elements kept in KV across cold starts
var MAX_SET_TIMEOUT = 30 * 86400;
var BOGON_MODES = ['off', 'reserved', 'all'];
var URPF_MODES = ['off', 'loose', 'strict'];
var TC_EGRESS_FEATURE = 'dataplane.xdp_tc_egress.v1';

var STATE_MAPS = ['fw_cfg', 'fw_ifaces', 'fw_port_bits', 'fw_ports', 'fw_class', 'fw_dst4', 'fw_dst6', 'fw_policy', 'fw_src4', 'fw_src6', 'fw_stats',
  'fw_limit', 'fw_rate', 'fw_ban', 'fw_lstats', 'fw_log_cfg', 'fw_log_tat', 'fw_gcfg', 'fw_pext', 'fw_sets', 'fw_ct', 'fw_gstats'];

// Connection tracking needs the host to run the egress program; older hosts
// still run everything else.
var TC_EGRESS = false;
if (typeof plugin.host === 'function') {
  var hostInfo = plugin.host();
  TC_EGRESS = (hostInfo.available_features || []).indexOf(TC_EGRESS_FEATURE) >= 0;
}

plugin.capabilities(['firewall', 'xdp']);
pipeline.node({id: 'firewall', description: 'Source filter for ports, ICMP and IP protocols with sets and connection tracking, run ahead of the Veer core: by the XDP dispatcher, or at TC ingress on interfaces without native XDP.'});
ebpf.loadObject({
  id: OBJECT,
  path: OBJECT_PATH,
  sha256: crypto.sha256File(OBJECT_PATH),
  description: 'XDP program, with a TC twin for interfaces without native XDP, that drops packets policies do not allow, and a TC egress program that records the connections this side opens.',
  programs: [
    {id: 'filter', section: 'xdp/veer/firewall', type: 'xdp'},
    {id: 'filter_tc', section: 'tc/veer/firewall', type: 'tc'},
    {id: 'track', section: 'tc/veer/firewall_egress', type: 'tc'}
  ],
  state_maps: STATE_MAPS.map(function (name) { return {name: name, policy: 'preserve', schema_version: 1}; })
});
ebpf.ringSubscribe({
  id: 'drop_log',
  object: OBJECT,
  map: 'fw_events',
  worker: LOG_WORKER,
  handler: 'onDropEvents',
  queue_size: 16,
  max_records: 128,
  max_bytes: 16384, // 128 events of 56 bytes
  poll_timeout_ms: 500
});
var HOOK_SPEC = {
  id: HOOK,
  engine: 'xdp',
  stage: 'pre_forward',
  priority: 10,
  program: OBJECT + ':filter',
  // Where native XDP is missing the host attaches this at TC ingress ahead of
  // the Veer core, instead of the dispatcher in generic mode, which would copy
  // every GRO aggregate.
  tc_fallback: OBJECT + ':filter_tc',
  mode: 'drop',
  binding_required: true
};
// At TC egress of the same interfaces; the binding turns it on only while
// connection tracking is.
if (TC_EGRESS) HOOK_SPEC.tc_egress = OBJECT + ':track';
hooks.attach(HOOK_SPEC);

var CIDR_LIST = {type: 'array', maxItems: 256, items: {type: 'string', maxLength: 64}};
var SET_NAME_SCHEMA = {type: 'string', maxLength: 48, pattern: '^[a-z0-9][a-z0-9_-]{0,47}$'};
plugin.resource({
  id: 'policies',
  description: 'Draft policies. Nothing reaches the dataplane before the apply action.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: compile.MAX_POLICY_SLOT,
  max_record_bytes: 131072,
  schema_version: 2,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      name: {type: 'string', maxLength: 64},
      remark: {type: 'string', maxLength: 256},
      protocol: {type: 'string', enum: ['tcp', 'udp', 'tcp+udp', 'icmp', 'icmpv6', 'ip', 'any']},
      ports: {type: 'array', maxItems: 64, items: {type: ['string', 'integer']}},
      icmp_types: {type: 'array', maxItems: 64, items: {type: ['string', 'integer']}},
      ip_protocols: {type: 'array', maxItems: 64, items: {type: ['string', 'integer']}},
      destinations: {type: 'array', maxItems: 64, items: {type: 'string', maxLength: 64}},
      default_action: {type: 'string', enum: ['allow', 'drop']},
      tcp_new_only: {type: 'boolean'},
      syn_limit: {
        type: 'object',
        additionalProperties: false,
        required: ['max_new', 'window_seconds'],
        properties: {
          max_new: {type: 'integer', minimum: 1, maximum: 1000000},
          window_seconds: {type: 'integer', minimum: 1, maximum: 3600},
          ban_seconds: {type: 'integer', minimum: 0, maximum: 604800},
          ipv6_prefix: {type: 'integer', minimum: 32, maximum: 128}
        }
      },
      add_to_set: {
        type: 'object',
        additionalProperties: false,
        required: ['set'],
        properties: {
          set: SET_NAME_SCHEMA,
          timeout_seconds: {type: 'integer', minimum: 0, maximum: MAX_SET_TIMEOUT},
          ipv6_prefix: {type: 'integer', minimum: 32, maximum: 128}
        }
      },
      sources: {
        type: 'array',
        maxItems: 1024,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['action'],
          properties: {
            cidr: {type: 'string', maxLength: 64},
            set: SET_NAME_SCHEMA,
            action: {type: 'string', enum: ['allow', 'drop']},
            remark: {type: 'string', maxLength: 128}
          }
        }
      }
    }
  }
});
plugin.resource({
  id: 'sets',
  description: 'Draft address sets: their static elements reach the dataplane with apply; set_add adds elements at once.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: compile.MAX_SETS,
  max_record_bytes: 262144,
  schema_version: 1,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      name: {type: 'string', maxLength: 64},
      remark: {type: 'string', maxLength: 256},
      elements: {type: 'array', maxItems: 4096, items: {type: 'string', maxLength: 64}}
    }
  }
});
plugin.resource({
  id: 'settings',
  description: 'Draft settings: bound interfaces, trusted sources, blocklists, baseline checks, connection tracking and the confirmation timeout.',
  methods: ['list', 'get', 'create', 'update'],
  runtime_update: 'manual',
  max_records: 1,
  max_record_bytes: 32768,
  schema_version: 2,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      interfaces: {type: 'array', maxItems: 16, items: {type: 'string', maxLength: 15}},
      trusted_sources: CIDR_LIST,
      confirm_timeout_seconds: {type: 'integer', minimum: 30, maximum: 600},
      log_per_second: {type: 'integer', minimum: 0, maximum: 1000},
      connection_tracking: {type: 'boolean'},
      blocklists: {type: 'array', maxItems: 4, items: SET_NAME_SCHEMA},
      baseline: {
        type: 'object',
        additionalProperties: false,
        properties: {
          bogon_sources: {type: 'string', enum: BOGON_MODES},
          invalid_tcp_flags: {type: 'boolean'},
          drop_fragments: {type: 'boolean'},
          urpf: {type: 'string', enum: URPF_MODES}
        }
      }
    }
  }
});
plugin.resource({
  id: 'snapshots',
  description: 'The applied and the last confirmed rule set, kept to rebuild the maps after a restart.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 2,
  max_record_bytes: 1048576
});
plugin.resource({
  id: 'hook_bindings',
  description: 'Interfaces the XDP hook runs on, written by apply and rollback.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'plugin_reconcile',
  max_records: 1,
  max_record_bytes: 4096
});
plugin.action({id: 'check', description: 'Validate the draft: errors that block an apply, and warnings an apply must accept by passing their token as accept_warnings.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'apply', description: 'Apply the draft policies, sets and settings; they stay until confirmed or the deadline restores the previous rule set.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'confirm', description: 'Keep the rule set applied last.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'rollback', description: 'Restore the last confirmed rule set now.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'status', description: 'Read the applied rule set, the confirmation deadline, per-policy and global counters.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'interfaces', description: 'List interfaces the hook can bind to.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'bans', description: 'List sources banned for going over a SYN limit, a page at a time.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'unban', description: 'Lift one ban (key), the bans of one policy, or all of them.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'events', description: 'The latest sampled drops, newest first.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'set_add', description: 'Add elements to an applied set at once, with an optional timeout: {set, elements, timeout_seconds}.', runtime_update: 'runtime_apply', max_payload_bytes: 65536});
plugin.action({id: 'set_del', description: 'Remove elements added at runtime from a set: {set, elements}.', runtime_update: 'runtime_apply', max_payload_bytes: 65536});
plugin.action({id: 'set_flush', description: 'Remove every element added at runtime from a set: {set}.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'set_list', description: 'List the elements of an applied set, a page at a time: {set, cursor, limit}.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: crypto.sha256File('ui/index.html'),
  page: 'firewall',
  page_title: 'Firewall',
  resources: [
    {resource: 'policies', methods: ['list', 'get', 'create', 'update', 'delete']},
    {resource: 'sets', methods: ['list', 'get', 'create', 'update', 'delete']},
    {resource: 'settings', methods: ['list', 'get', 'create', 'update']},
    {resource: 'snapshots', methods: ['list', 'get']}
  ],
  actions: ['check', 'apply', 'confirm', 'rollback', 'status', 'interfaces', 'bans', 'unban', 'events', 'set_add', 'set_del', 'set_flush', 'set_list']
});

// ------------------------------------------------------------------ helpers

function now() { return Date.now(); }

function loadState() {
  var record = kv.get(STATE_KEY);
  var st = record && record.data && typeof record.data === 'object' ? record.data : {};
  if (st.generation !== 0 && st.generation !== 1) st.generation = 0;
  if (!st.slots || typeof st.slots !== 'object') st.slots = {};
  if (!st.set_ids || typeof st.set_ids !== 'object') st.set_ids = {};
  if (!st.baselines || typeof st.baselines !== 'object') st.baselines = {};
  return st;
}

function saveState(st) { kv.set(STATE_KEY, st); }

function kvData(key, fallback) {
  var record = kv.get(key);
  return record && record.data !== undefined && record.data !== null ? record.data : fallback;
}

function listAll(resource) {
  var out = [];
  for (var offset = 0; ; offset += 256) {
    var page = resources.list(resource, {limit: 256, offset: offset}) || [];
    out = out.concat(page);
    if (page.length < 256) return out;
  }
}

function settingsDraft() {
  var record = resources.get('settings', 'default');
  return record && record.data ? record.data : {};
}

function normalizeBaseline(data) {
  data = data || {};
  var bogon = data.bogon_sources === undefined ? 'off' : data.bogon_sources;
  var urpf = data.urpf === undefined ? 'off' : data.urpf;
  if (BOGON_MODES.indexOf(bogon) < 0) throw new Error('bogon_sources 必须是 off、reserved 或 all');
  if (URPF_MODES.indexOf(urpf) < 0) throw new Error('urpf 必须是 off、loose 或 strict');
  return {bogonSources: bogon, invalidTcpFlags: data.invalid_tcp_flags === true, dropFragments: data.drop_fragments === true, urpf: urpf};
}

function normalizeSettings(data) {
  data = data || {};
  var interfaces = [];
  (data.interfaces || []).forEach(function (name) {
    name = String(name).trim();
    if (!IFACE_NAME.test(name)) throw new Error('接口名无效: ' + name);
    if (interfaces.indexOf(name) < 0) interfaces.push(name);
  });
  var trusted = (data.trusted_sources || []).map(compile.parseCIDR);
  var seconds = data.confirm_timeout_seconds === undefined ? DEFAULT_CONFIRM_SECONDS : Number(data.confirm_timeout_seconds);
  if (!(seconds >= 30 && seconds <= 600)) throw new Error('确认超时必须在 30 到 600 秒之间');
  var logRate = data.log_per_second === undefined ? DEFAULT_LOG_PER_SECOND : Number(data.log_per_second);
  if (!(logRate >= 0 && logRate <= 1000) || Math.floor(logRate) !== logRate) throw new Error('丢包日志速率必须是 0 到 1000 之间的整数');
  var blocklists = [];
  (data.blocklists || []).forEach(function (name) {
    name = String(name);
    if (!compile.SET_NAME.test(name)) throw new Error('黑名单集合名无效: ' + name);
    if (blocklists.indexOf(name) < 0) blocklists.push(name);
  });
  if (blocklists.length > compile.BLOCK_SETS) throw new Error('黑名单集合最多 ' + compile.BLOCK_SETS + ' 个');
  return {
    interfaces: interfaces,
    trusted: trusted,
    confirmSeconds: Math.floor(seconds),
    logPerSecond: logRate,
    connectionTracking: data.connection_tracking === true,
    blocklists: blocklists,
    baseline: normalizeBaseline(data.baseline)
  };
}

/* fw_log_cfg: a GCRA allowing logPerSecond events per CPU, in bursts of as many. */
function logConfigHex(logPerSecond) {
  if (!logPerSecond) return compile.u32le(0) + compile.u32le(0) + compile.u32le(0) + compile.u32le(0);
  var interval = Math.floor(1e9 / logPerSecond);
  var tolerance = interval * (logPerSecond - 1);
  return compile.u32le(interval) + compile.u32le(0) + compile.u32le(tolerance) + compile.u32le(0);
}

function byKey(a, b) { return a.key < b.key ? -1 : a.key > b.key ? 1 : 0; }

/*
 * Snapshot form of a rule set: the policy and set records as stored, so
 * compiling a snapshot again gives the same maps.
 */
function snapshotOf(records, settingsData, setRecords) {
  return {
    policies: records.map(function (r) { return {key: r.key, enabled: r.enabled !== false, data: r.data}; }).sort(byKey),
    settings: settingsData || {},
    sets: (setRecords || []).map(function (r) { return {key: r.key, enabled: r.enabled !== false, data: r.data}; }).sort(byKey)
  };
}

function draftSnapshot() {
  return snapshotOf(listAll('policies'), settingsDraft(), listAll('sets'));
}

function readSnapshot(name) {
  var record = resources.get('snapshots', name);
  if (!record || !record.data || !Array.isArray(record.data.policies)) return null;
  // Snapshots of 1.0 have no sets.
  if (!Array.isArray(record.data.sets)) record.data.sets = [];
  return record.data;
}

function writeSnapshot(name, snapshot) {
  resources.set('snapshots', name, snapshot, true, false);
}

/* Validates a snapshot and compiles it; throws with every problem found. */
function buildRuleset(snapshot, slots, setIds) {
  var errors = [];
  var sets = [];
  (snapshot.sets || []).forEach(function (s) {
    if (!s.enabled) return;
    try { sets.push(compile.normalizeSet(s.key, s.data)); } catch (e) { errors.push(e.message); }
  });
  var setKeys = sets.map(function (s) { return s.key; });
  var policies = [];
  snapshot.policies.forEach(function (p) {
    if (!p.enabled) return;
    try { policies.push(compile.normalizePolicy(p.key, p.data, setKeys)); } catch (e) { errors.push(e.message); }
  });
  var settings;
  try { settings = normalizeSettings(snapshot.settings); } catch (e) { errors.push(e.message); }
  if (settings) {
    settings.blocklists.forEach(function (name) {
      if (setKeys.indexOf(name) < 0) errors.push('黑名单引用的集合不存在: ' + name);
    });
    if (settings.connectionTracking && !TC_EGRESS) {
      errors.push('这个 Veer 不支持连接跟踪（缺少 ' + TC_EGRESS_FEATURE + '），请升级 Veer 或关闭连接跟踪');
    }
  }
  errors = errors.concat(compile.findConflicts(policies));
  if (errors.length) {
    var err = new Error(errors.join('；'));
    err.errors = errors;
    throw err;
  }
  var assigned = compile.assignSlots(policies.map(function (p) { return p.key; }), slots);
  policies.forEach(function (p) { p.slot = assigned.slots[p.key]; });
  var ids = compile.assignSetIds(setKeys, setIds);
  sets.forEach(function (s) { s.id = ids.ids[s.key]; });
  return {policies: policies, settings: settings, sets: sets, slots: assigned.slots, fresh: assigned.fresh, setIds: ids.ids};
}

function transact(ops) {
  for (var i = 0; i < ops.length; i += TX_LIMIT) ebpf.mapTransaction({operations: ops.slice(i, i + TX_LIMIT)});
}

function scanKeys(map) {
  var keys = [];
  scanAll(map, function (e) { keys.push(e.key); });
  return keys;
}

/* Writes a compiled rule set into one generation, which packets do not read. */
function writeGeneration(generation, compiled) {
  var ops = [];
  LPM_MAPS.forEach(function (map) {
    scanKeys(map).forEach(function (key) {
      if (compile.keyGeneration(key) === generation) ops.push({op: 'delete', object: OBJECT, map: map, key: key});
    });
  });
  transact(ops);

  ops = [];
  LPM_MAPS.forEach(function (map) {
    compiled.lpm[map].forEach(function (e) { ops.push({op: 'put', object: OBJECT, map: map, key: e.key, value: e.value}); });
  });
  var tracked = kvData(GEN_ARRAYS_KEY, {});
  var previous = tracked[String(generation)];
  var written = {};
  Object.keys(ARRAY_ZERO).forEach(function (map) {
    var desired = compiled.arrays[map];
    var stale = [];
    if (previous && Array.isArray(previous[map])) {
      stale = previous[map];
    } else {
      // Unknown earlier content: clear the whole generation.
      var per = ARRAY_SIZES[map] / 2;
      for (var i = generation * per; i < (generation + 1) * per; i++) stale.push(i);
    }
    stale.forEach(function (index) {
      if (desired[index] === undefined) ops.push({op: 'put', object: OBJECT, map: map, key: compile.u32le(index), value: ARRAY_ZERO[map]});
    });
    written[map] = Object.keys(desired).map(Number);
    written[map].forEach(function (index) {
      ops.push({op: 'put', object: OBJECT, map: map, key: compile.u32le(index), value: desired[index]});
    });
  });
  transact(ops);
  tracked[String(generation)] = written;
  kv.set(GEN_ARRAYS_KEY, tracked);
}

/* Marks the bound interfaces that carry no Ethernet header; true if any. */
function syncInterfaces(names) {
  var l3 = [];
  names.forEach(function (name) {
    var link;
    try { link = net.link.get(name); } catch (e) { return; }
    if (!link || !link.ifindex) return;
    var mac = String(link.mac || '');
    if (!mac || /^(00:){5}00$/.test(mac)) l3.push(link.ifindex);
  });
  var previous = kvData(IFACES_KEY, []);
  var ops = [];
  previous.forEach(function (ifindex) {
    if (l3.indexOf(ifindex) < 0) ops.push({op: 'delete', object: OBJECT, map: 'fw_ifaces', key: compile.u32le(ifindex)});
  });
  l3.forEach(function (ifindex) {
    ops.push({op: 'put', object: OBJECT, map: 'fw_ifaces', key: compile.u32le(ifindex), value: compile.u32le(IFACE_L3)});
  });
  if (ops.length) transact(ops);
  kv.set(IFACES_KEY, l3);
  return l3.length > 0;
}

/*
 * Points the XDP hook at the interfaces; only a change touches the record.
 * tc_egress turns the egress program on with connection tracking.
 */
function bindInterfaces(names, tracking) {
  var current = resources.get('hook_bindings', HOOK);
  var data = {hook_id: HOOK, interfaces: names, tc_egress: !!(tracking && TC_EGRESS)};
  var enabled = names.length > 0;
  if (current && current.enabled === enabled && sameJSON(current.data, data)) return false;
  resources.set('hook_bindings', HOOK, data, enabled, true);
  return true;
}

function readConfig() {
  var hex = ebpf.mapGet(OBJECT, 'fw_cfg', compile.u32le(0));
  if (!hex || hex.length < 16) return {generation: 0, flags: 0};
  var word = function (offset) { return parseInt(hex.substr(offset + 6, 2) + hex.substr(offset + 4, 2) + hex.substr(offset + 2, 2) + hex.substr(offset, 2), 16); };
  return {generation: word(0), flags: word(8)};
}

/*
 * fw_sets holds both what apply writes (static elements, the bogon
 * prefixes) and what arrives at runtime (set_add, add_to_set); it is not
 * per generation. Before the flip, the static elements of the new rule set
 * go in, and set_add elements that a cold start lost come back from KV.
 * Returns the keys to remove after the flip: static elements the rule set no
 * longer has, and anything of a set that is gone.
 */
function syncSetsBefore(ruleset) {
  var desired = compile.compileSets(ruleset.sets, ruleset.settings.baseline);
  var known = {};
  known[compile.SET_BOGON] = true;
  ruleset.sets.forEach(function (s) { known[s.id] = true; });
  var present = {};
  var stale = [];
  scanAll('fw_sets', function (e) {
    present[e.key] = true;
    var key = compile.decodeSetKey(e.key);
    var value = compile.decodeSetValue(e.value);
    if (!key || !known[key.id]) stale.push(e.key);
    else if (value && value.kind === 'static' && desired[e.key] === undefined) stale.push(e.key);
  });
  var ops = [];
  Object.keys(desired).forEach(function (key) {
    ops.push({op: 'put', object: OBJECT, map: 'fw_sets', key: key, value: desired[key]});
  });
  restoreDynamic(ruleset, desired, present).forEach(function (op) { ops.push(op); });
  transact(ops);
  return stale;
}

function removeStale(map, keys) {
  transact(keys.map(function (key) { return {op: 'delete', object: OBJECT, map: map, key: key}; }));
}

/* Writes a rule set into generation and makes packets read it. */
function activate(ruleset, generation) {
  var compiled = compile.compileGeneration(ruleset.policies, ruleset.settings.trusted, generation,
    {setIds: ruleset.setIds, settings: ruleset.settings});
  writeGeneration(generation, compiled);
  var staleSets = syncSetsBefore(ruleset);
  var flags = CFG_LOADED | (compiled.active ? CFG_ACTIVE : 0) | (syncInterfaces(ruleset.settings.interfaces) ? CFG_HAS_L3 : 0);
  ebpf.mapPut(OBJECT, 'fw_log_cfg', compile.u32le(0), logConfigHex(ruleset.settings.logPerSecond));
  ebpf.mapPut(OBJECT, 'fw_cfg', compile.u32le(0), compile.u32le(generation) + compile.u32le(flags));
  removeStale('fw_sets', staleSets);
  if (ruleset.policies.some(function (p) { return p.addToSet; }) || Object.keys(dynamicElements()).length) armPrune();
  compiled.summary.sets = ruleset.sets.length;
  compiled.summary.connection_tracking = ruleset.settings.connectionTracking;
  return compiled.summary;
}

/* [pass, drop, trusted, evasive, ban, rate]: drop counts every drop, ban and
 * rate break out the SYN limit's share; evasive is meaningful for slot 0. */
function counters(slot) {
  var values = [0, 1, 2, 3].map(function (c) {
    return compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_stats', compile.statsKey(slot, c)));
  });
  return values.concat([compile.LCNT_BAN, compile.LCNT_RATE].map(function (c) {
    return compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_lstats', compile.lstatsKey(slot, c)));
  }));
}

function globalCounters() {
  var out = {};
  compile.GCOUNTERS.forEach(function (name, i) {
    out[name] = compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_gstats', compile.gstatsKey(i)));
  });
  return out;
}

/* New slots start their counters from what the slot shows now. */
function resetBaselines(st, fresh) {
  fresh.forEach(function (slot) {
    var values = [0, 0, 0, 0, 0, 0];
    try { values = counters(slot); } catch (e) { /* maps not loaded: nothing counted yet */ }
    st.baselines[String(slot)] = values;
  });
}

/* Every entry of a map; scans are best-effort snapshots. */
function scanAll(map, visit) {
  var cursor = '';
  for (var guard = 0; guard < 4096; guard++) {
    var options = {limit: 256};
    if (cursor) options.cursor = cursor;
    var page = ebpf.mapScan(OBJECT, map, options);
    (page.entries || []).forEach(visit);
    if (page.done || !page.entries || !page.entries.length) return;
    cursor = page.cursor;
  }
}

/*
 * Forgets bans and SYN counts of slots that now belong to another policy, so
 * a new policy does not inherit them. The maps may not be loaded yet (the
 * first apply binds the interface first): nothing to forget then.
 */
function clearLimitState(slots) {
  if (!slots.length) return;
  var wanted = {};
  slots.forEach(function (slot) { wanted[slot] = true; });
  ['fw_ban', 'fw_rate'].forEach(function (map) {
    var stale = [];
    try {
      scanAll(map, function (e) {
        var key = compile.decodeLimitKey(e.key);
        if (key && wanted[key.slot]) stale.push(e.key);
      });
    } catch (e) {
      return;
    }
    stale.forEach(function (key) { try { ebpf.mapDelete(OBJECT, map, key); } catch (e) { /* gone already */ } });
  });
}

function scheduleSync(st, error) {
  st.dirty = true;
  st.sync_attempts = (st.sync_attempts || 0) + 1;
  st.last_error = error ? String(error.message || error) : st.last_error;
  if (st.sync_attempts <= SYNC_RETRY_LIMIT) timer.setTimeout(SYNC_TIMER, SYNC_RETRY_MS, {});
}

/*
 * Writes the rule set into st.generation and switches packets to it. A
 * failure (the object is not loaded until the hook has an interface) leaves
 * the state dirty and retries.
 */
function commit(st, ruleset) {
  try {
    st.summary = activate(ruleset, st.generation);
    st.dirty = false;
    st.sync_attempts = 0;
    st.last_error = '';
    timer.clear(SYNC_TIMER);
  } catch (e) {
    if (!ruleset.settings.interfaces.length) {
      // No interface: the hook is detached and nothing filters anyway.
      st.dirty = true;
      st.last_error = '';
      return;
    }
    scheduleSync(st, e);
  }
}

/*
 * Installs a snapshot: validates it, binds its interfaces, then lets change
 * update the state and writes the maps. Binding comes before any state is
 * read for writing: the binding's dataplane reconcile loads the object (and
 * a host may run onReconcile from it), so the state is loaded afterwards.
 */
function install(snapshot, change) {
  var check = buildRuleset(snapshot, loadState().slots, loadState().set_ids);
  bindInterfaces(check.settings.interfaces, check.settings.connectionTracking);
  var st = loadState();
  change(st);
  var ruleset = buildRuleset(snapshot, st.slots, st.set_ids);
  st.slots = ruleset.slots;
  st.set_ids = ruleset.setIds;
  resetBaselines(st, ruleset.fresh);
  clearLimitState(ruleset.fresh);
  forgetGoneSets(ruleset.setIds);
  commit(st, ruleset);
  saveState(st);
}

function flipped(generation) { return generation === 0 ? 1 : 0; }

function restoreConfirmed(reason) {
  var confirmed = readSnapshot('confirmed') || snapshotOf([], {}, []);
  try {
    buildRuleset(confirmed, {}, {});
  } catch (e) {
    // Never fails a rollback over a stored snapshot: keep its interfaces and
    // settings, no policies, sets or blocklists.
    var kept = {};
    Object.keys(confirmed.settings || {}).forEach(function (k) { kept[k] = confirmed.settings[k]; });
    delete kept.blocklists;
    if (!TC_EGRESS) delete kept.connection_tracking;
    try { normalizeSettings(kept); } catch (err) { kept = {interfaces: (confirmed.settings || {}).interfaces || []}; }
    confirmed = snapshotOf([], kept, []);
  }
  install(confirmed, function (st) {
    st.generation = flipped(st.generation);
    st.pending = null;
    st.rolled_back_at = now();
    st.rollback_reason = reason;
    writeSnapshot('applied', confirmed);
    timer.clear(CONFIRM_TIMER);
  });
}

// ----------------------------------------------------------------- actions

/*
 * Validates the draft without touching anything: errors block an apply,
 * warnings need their token passed back to apply as accept_warnings.
 */
function check() {
  var snapshot = draftSnapshot();
  var st = loadState();
  var ruleset;
  try {
    ruleset = buildRuleset(snapshot, st.slots, st.set_ids);
  } catch (e) {
    return {snapshot: snapshot, errors: e.errors || [String(e.message || e)], warnings: [], token: ''};
  }
  var warnings = compile.findWarnings(ruleset.policies, ruleset.settings.trusted, {ct: ruleset.settings.connectionTracking});
  if (ruleset.settings.baseline.urpf === 'strict') {
    warnings.push({id: 'urpf_strict', policy: null,
      message: '严格反向路径检查要求回到来源的路由从收包的接口出去：多出口、非对称路由，以及 VLAN、PPPoE 帧（路由在子接口上）会被误丢，这些情况请用宽松模式。'});
  }
  return {snapshot: snapshot, errors: [], warnings: warnings, token: compile.warningsToken(warnings)};
}

function apply(payload) {
  if (loadState().pending) throw new Error('上一次应用还在等待确认：请先确认或回滚');
  var result = check();
  if (result.errors.length) throw new Error(result.errors.join('；'));
  if (result.token && (payload || {}).accept_warnings !== result.token) {
    throw new Error('应用前需要确认以下提示（把 check 返回的 token 作为 accept_warnings 传给 apply）：' +
      result.warnings.map(function (w) { return w.message; }).join('；'));
  }
  var snapshot = result.snapshot;
  var settings = normalizeSettings(snapshot.settings);
  install(snapshot, function (st) {
    st.generation = flipped(st.generation);
    st.pending = {deadline_ms: now() + settings.confirmSeconds * 1000};
    st.applied_at = now();
    writeSnapshot('applied', snapshot);
    timer.setTimeout(CONFIRM_TIMER, settings.confirmSeconds * 1000, {});
  });
  // The binding's dataplane reconcile has run by now. A hook the host could
  // not attach filters nothing, and the page would confirm it: undo instead.
  // With connection tracking the egress program must be there too, or
  // replies to this side's connections would be dropped.
  var attach = settings.interfaces.length ? attachmentStatus(settings.interfaces) : null;
  var missing = attach && !attach.error && settings.connectionTracking ?
    attach.interfaces.filter(function (i) { return i.attached && !i.egress; }).map(function (i) { return i.interface; }) : [];
  if (attach && (attach.error || missing.length)) {
    restoreConfirmed('attach_failed');
    throw new Error('防火墙没能挂载到接口，已回到上一次确认的规则：' +
      (attach.error || '连接跟踪的出向程序没挂上 ' + missing.join('、')));
  }
}

function confirm() {
  var st = loadState();
  if (!st.pending) return;
  writeSnapshot('confirmed', readSnapshot('applied') || snapshotOf([], {}, []));
  st.pending = null;
  st.confirmed_at = now();
  timer.clear(CONFIRM_TIMER);
  saveState(st);
}

function rollback(reason) {
  if (!loadState().pending) return;
  restoreConfirmed(reason);
}

/*
 * Brings the maps in line with the state: after a Veer restart (empty maps),
 * after a write that failed, or when a deadline passed while Veer was down.
 * Writes go to st.generation, which packets do not read unless the maps are
 * empty anyway: activate switches fw_cfg to it last.
 */
function sync() {
  var st = loadState();
  var applied = readSnapshot('applied');
  if (!applied) return;
  if (st.pending && now() >= st.pending.deadline_ms) {
    restoreConfirmed('deadline');
    return;
  }
  if (st.pending) {
    // Timers do not outlive the Veer process; a new one arms the deadline
    // again for the time that is left.
    timer.setTimeout(CONFIRM_TIMER, Math.max(1000, st.pending.deadline_ms - now()), {});
  }
  var cfg;
  try { cfg = readConfig(); } catch (e) { cfg = null; }
  var fresh = !cfg || !(cfg.flags & CFG_LOADED);
  if (fresh && st.pending && !st.dirty) {
    // Maps written once and now empty: a new Veer process that could not
    // keep them (an older host, or a map layout that changed). The
    // unconfirmed rule set is not restored, the confirmed one is. Maps the
    // host kept keep the pending rule set and its re-armed deadline. (Dirty
    // maps were never written, as right after the first apply binds an
    // interface.)
    restoreConfirmed('restart');
    return;
  }
  if (!fresh && !st.dirty && cfg.generation === st.generation) {
    // A binding written by 1.0 has no tc_egress, which the host takes as on:
    // add the field. Only then: install binds before it commits, and the
    // reconcile its binding write may run must not bind from the snapshot
    // being replaced.
    var binding = resources.get('hook_bindings', HOOK);
    if (binding && binding.data && binding.data.tc_egress === undefined) {
      var settings = normalizeSettingsSafe(applied.settings);
      var data = {hook_id: HOOK, interfaces: binding.data.interfaces || [], tc_egress: !!(settings && settings.connectionTracking && TC_EGRESS)};
      resources.set('hook_bindings', HOOK, data, binding.enabled, true);
    }
    // Timers do not outlive the process either; one still pending is left
    // alone, or frequent reconciles would keep pushing it back.
    if (Object.keys(dynamicElements()).length || applied.policies.some(function (p) { return p.enabled && p.data && p.data.add_to_set; })) {
      armPruneUnlessPending();
    }
    return;
  }
  install(applied, function () {});
}

/* JSON with sorted keys: the host stores records canonically, not in the order written. */
function canonicalJSON(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().filter(function (k) { return value[k] !== undefined; })
      .map(function (k) { return JSON.stringify(k) + ':' + canonicalJSON(value[k]); }).join(',') + '}';
  }
  return JSON.stringify(value);
}

function sameJSON(a, b) { return canonicalJSON(a) === canonicalJSON(b); }

function status() {
  var st = loadState();
  var applied = readSnapshot('applied');
  var draft = draftSnapshot();
  var loaded = true;
  var names = {};
  var limits = {};
  (applied ? applied.policies : []).forEach(function (p) {
    names[p.key] = p.data && p.data.name ? p.data.name : p.key;
    if (p.enabled && p.data && p.data.syn_limit) limits[p.key] = p.data.syn_limit;
  });
  var policies = Object.keys(st.slots).sort().map(function (key) {
    var slot = st.slots[key];
    var item = {key: key, name: names[key] || key, slot: slot, syn_limit: limits[key] || null, counters: null};
    if (!loaded) return item;
    try {
      var values = counters(slot);
      var base = st.baselines[String(slot)] || [];
      var since = function (i) { return Math.max(0, values[i] - (base[i] || 0)); };
      item.counters = {};
      COUNTER_NAMES.forEach(function (name, i) { item.counters[name] = since(i); });
      item.counters.banned = since(4);
      item.counters.rate_limited = since(5);
    } catch (e) {
      loaded = false;
    }
    return item;
  });
  var evasive = null;
  var log = null;
  var global = null;
  if (loaded) {
    try {
      evasive = counters(0)[EVASIVE_COUNTER];
      log = {
        logged: compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_lstats', compile.lstatsKey(0, compile.LCNT_LOGGED))),
        lost: compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_lstats', compile.lstatsKey(0, compile.LCNT_LOST)))
      };
      global = globalCounters();
    } catch (e) {
      loaded = false;
    }
  }
  var settings = applied ? normalizeSettingsSafe(applied.settings) : null;
  return {
    generation: st.generation,
    loaded: loaded,
    pending: st.pending ? {deadline_ms: st.pending.deadline_ms, remaining_seconds: Math.max(0, Math.round((st.pending.deadline_ms - now()) / 1000))} : null,
    applied_at: st.applied_at || null,
    confirmed_at: st.confirmed_at || null,
    rolled_back_at: st.rolled_back_at || null,
    rollback_reason: st.rollback_reason || null,
    last_error: st.last_error || '',
    dirty: !!st.dirty,
    interfaces: settings ? settings.interfaces : [],
    draft_changed: !applied || !sameJSON(draft, applied),
    summary: st.summary || null,
    policies: policies,
    sets: (applied ? applied.sets : []).filter(function (s) { return s.enabled; }).map(function (s) {
      return {key: s.key, name: (s.data && s.data.name) || s.key, id: st.set_ids[s.key] || null, static_elements: ((s.data && s.data.elements) || []).length};
    }),
    evasive_drops: evasive,
    drop_log: log,
    global: global,
    connection_tracking: {available: TC_EGRESS, enabled: !!(settings && settings.connectionTracking)},
    attachments: attachmentStatus(settings ? settings.interfaces : []),
    core: coreEngine()
  };
}

function normalizeSettingsSafe(data) {
  try { return normalizeSettings(data); } catch (e) { return null; }
}

/*
 * How the hook sits on each bound interface: attached (mode 'driver' or
 * 'generic' XDP, or 'tc' where the tc_fallback runs), not attached, or the
 * host's error; egress says whether the tc_egress program runs there. null
 * on hosts without control.attachment_status.v1.
 */
function attachmentStatus(names) {
  if (typeof plugin.attachments !== 'function') return null;
  var runtime;
  try { runtime = plugin.attachments(); } catch (e) { return null; }
  var ingress = {};
  var egress = {};
  ((runtime && runtime.attachments) || []).forEach(function (a) {
    if (a.hook_id !== HOOK || a.engine !== 'xdp') return;
    if (a.attach === 'egress') egress[a.interface] = a;
    else ingress[a.interface] = a;
  });
  return {
    error: (runtime && runtime.error) || '',
    reason: (runtime && runtime.reason) || '',
    interfaces: names.map(function (name) {
      var a = ingress[name];
      var e = egress[name];
      var out = {interface: name, attached: false, mode: '', error: '', egress: !!(e && e.status === 'attached')};
      if (!a) return out;
      out.attached = a.status === 'attached';
      out.mode = a.xdp_mode || '';
      out.error = a.error || '';
      return out;
    })
  };
}

/*
 * An active XDP plugin hook keeps the Veer core on its TC engine; worth a
 * notice only where the configuration prefers the XDP engine.
 */
function coreEngine() {
  var host;
  try { host = plugin.host(); } catch (e) { return null; }
  if (!host || !Array.isArray(host.kernel_engine_order)) return null;
  var prefersXDP = host.kernel_engine_order[0] === 'xdp';
  return {
    engine_order: host.kernel_engine_order,
    prefers_xdp: prefersXDP,
    pinned_to_tc: prefersXDP && host.core_engine_pinned_to_tc === true
  };
}

/* CLOCK_MONOTONIC in ms (the clock BPF ban times use), or null on hosts
 * that cannot tell it: bans then show no remaining time. */
function monotonicMs() {
  try {
    if (typeof ebpf.monotonicMs === 'function') return Number(ebpf.monotonicMs());
  } catch (e) { /* older host */ }
  return null;
}

function slotPolicies() {
  var st = loadState();
  var applied = readSnapshot('applied');
  var names = {};
  (applied ? applied.policies : []).forEach(function (p) { names[p.key] = p.data && p.data.name ? p.data.name : p.key; });
  var bySlot = {};
  Object.keys(st.slots).forEach(function (key) { bySlot[st.slots[key]] = {key: key, name: names[key] || key}; });
  return bySlot;
}

function pageLimit(value, fallback, max) {
  var n = Number(value);
  return n >= 1 && n <= max && Math.floor(n) === n ? n : fallback;
}

/* One page of active bans: {items, cursor, done}; expired ones are skipped. */
function bans(payload) {
  payload = payload || {};
  var options = {limit: pageLimit(payload.limit, 100, 256)};
  if (payload.cursor) options.cursor = String(payload.cursor);
  var page = ebpf.mapScan(OBJECT, 'fw_ban', options);
  var nowMs = monotonicMs();
  var bySlot = slotPolicies();
  var items = [];
  (page.entries || []).forEach(function (e) {
    var key = compile.decodeLimitKey(e.key);
    if (!key) return;
    var remaining = null;
    if (nowMs !== null) {
      remaining = Math.ceil((compile.decodeBanUntilMs(e.value) - nowMs) / 1000);
      if (remaining <= 0) return;
    }
    var policy = bySlot[key.slot] || null;
    items.push({key: e.key, source: key.source, policy: policy ? policy.key : null, policy_name: policy ? policy.name : null,
      remaining_seconds: remaining});
  });
  return {items: items, cursor: page.cursor || '', done: !!page.done, clock: nowMs !== null};
}

/* Lifts bans: {key} one ban, {policy} every ban of a policy, {all: true} all. */
function unban(payload) {
  payload = payload || {};
  var keys = [];
  if (payload.key !== undefined) {
    var key = String(payload.key).toLowerCase();
    if (!LIMIT_KEY_HEX.test(key)) throw new Error('封禁记录无效');
    keys.push(key);
  } else if (payload.all === true || payload.policy !== undefined) {
    var slot = null;
    if (payload.policy !== undefined) {
      slot = loadState().slots[String(payload.policy)];
      if (!slot) throw new Error('没有这条已应用的策略: ' + payload.policy);
    }
    scanAll('fw_ban', function (e) {
      var k = compile.decodeLimitKey(e.key);
      if (k && (slot === null || k.slot === slot)) keys.push(e.key);
    });
  } else {
    throw new Error('需要 key、policy 或 all');
  }
  keys.forEach(function (key) {
    // The SYN count goes too, or the next SYN would ban the source again.
    try { ebpf.mapDelete(OBJECT, 'fw_ban', key); } catch (e) { /* expired and reclaimed */ }
    try { ebpf.mapDelete(OBJECT, 'fw_rate', key); } catch (e) { /* none */ }
  });
  return {removed: keys.length};
}

// -------------------------------------------------------------------- sets

/* set_add elements kept for cold starts: {set: {cidr text: expires wall ms, 0 = until removed}}. */
function dynamicElements() {
  var data = kvData(DYN_KEY, {});
  return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
}

/*
 * The value of the longest fw_sets prefix covering key (an LPM lookup from
 * userspace matches like the dataplane does), or null. The host throws for
 * a key nothing covers.
 */
function setLookup(key) {
  try { return ebpf.mapGet(OBJECT, 'fw_sets', key) || null; } catch (e) { return null; }
}

/* The id of an applied set, or an error naming what is wrong. */
function appliedSetId(name) {
  name = String(name || '');
  var id = loadState().set_ids[name];
  var applied = readSnapshot('applied');
  var exists = applied && applied.sets.some(function (s) { return s.key === name && s.enabled; });
  if (!id || !exists) throw new Error('没有这个已应用的集合: ' + name + '（新建或改名的集合要先应用）');
  return id;
}

function elementList(payload) {
  var list = payload.elements;
  if (typeof list === 'string') list = [list];
  if (!Array.isArray(list) || !list.length) throw new Error('需要 elements');
  if (list.length > 256) throw new Error('一次最多 256 个元素');
  return list.map(function (raw) { return compile.parseCIDR(String(raw)); });
}

/*
 * set_add: the elements go into the dataplane at once, until timeout_seconds
 * pass (0 or none: until removed). Static elements of the set stay as they
 * are. They survive applies and hot restarts; a cold start restores them
 * from KV.
 */
function setAdd(payload) {
  payload = payload || {};
  var name = String(payload.set || '');
  var id = appliedSetId(name);
  var elements = elementList(payload);
  var seconds = payload.timeout_seconds === undefined ? 0 : Number(payload.timeout_seconds);
  if (!(seconds >= 0 && seconds <= MAX_SET_TIMEOUT) || Math.floor(seconds) !== seconds) {
    throw new Error('timeout_seconds 必须是 0 到 ' + MAX_SET_TIMEOUT + ' 之间的整数');
  }
  var mono = monotonicMs();
  if (seconds && mono === null) throw new Error('这个 Veer 读不到单调时钟，不能设置超时');
  var dyn = dynamicElements();
  var own = dyn[name] || {};
  var total = Object.keys(dyn).reduce(function (n, k) { return n + Object.keys(dyn[k]).length; }, 0);
  var ops = [];
  var added = 0;
  elements.forEach(function (cidr) {
    var key = compile.setKey(id, cidr);
    var current = setLookup(key);
    var decoded = current ? compile.decodeSetValue(current) : null;
    if (decoded && decoded.kind === 'static') return;
    if (own[cidr.text] === undefined) total++;
    if (total > MAX_API_ELEMENTS) throw new Error('set_add 的元素合计最多 ' + MAX_API_ELEMENTS + ' 个');
    own[cidr.text] = seconds ? now() + seconds * 1000 : 0;
    ops.push({op: 'put', object: OBJECT, map: 'fw_sets', key: key, value: compile.setValue(seconds ? mono + seconds * 1000 : 0, compile.SET_KIND_API)});
    added++;
  });
  transact(ops);
  dyn[name] = own;
  kv.set(DYN_KEY, dyn);
  if (seconds) armPrune();
  return {added: added};
}

/* set_del: removes runtime elements (set_add or add_to_set); static ones stay. */
function setDel(payload) {
  payload = payload || {};
  var name = String(payload.set || '');
  var id = appliedSetId(name);
  var dyn = dynamicElements();
  var own = dyn[name] || {};
  var removed = 0;
  elementList(payload).forEach(function (cidr) {
    var key = compile.setKey(id, cidr);
    var current = setLookup(key);
    var decoded = current ? compile.decodeSetValue(current) : null;
    delete own[cidr.text];
    if (!decoded || decoded.kind === 'static') return;
    try { ebpf.mapDelete(OBJECT, 'fw_sets', key); removed++; } catch (e) { /* gone */ }
  });
  dyn[name] = own;
  kv.set(DYN_KEY, dyn);
  return {removed: removed};
}

function setFlush(payload) {
  var name = String((payload || {}).set || '');
  var id = appliedSetId(name);
  var keys = [];
  scanAll('fw_sets', function (e) {
    var key = compile.decodeSetKey(e.key);
    var value = compile.decodeSetValue(e.value);
    if (key && key.id === id && value && value.kind !== 'static') keys.push(e.key);
  });
  keys.forEach(function (key) { try { ebpf.mapDelete(OBJECT, 'fw_sets', key); } catch (e) { /* gone */ } });
  var dyn = dynamicElements();
  delete dyn[name];
  kv.set(DYN_KEY, dyn);
  return {removed: keys.length};
}

/* One page of a set's elements: {items: [{cidr, kind, remaining_seconds}], cursor, done}. */
function setList(payload) {
  payload = payload || {};
  var id = appliedSetId(payload.set);
  var options = {limit: pageLimit(payload.limit, 256, 256)};
  if (payload.cursor) options.cursor = String(payload.cursor);
  var page = ebpf.mapScan(OBJECT, 'fw_sets', options);
  var mono = monotonicMs();
  var items = [];
  (page.entries || []).forEach(function (e) {
    var key = compile.decodeSetKey(e.key);
    var value = compile.decodeSetValue(e.value);
    if (!key || key.id !== id || !value) return;
    var remaining = null;
    if (value.expiresMs) {
      if (mono !== null) {
        remaining = Math.ceil((value.expiresMs - mono) / 1000);
        if (remaining <= 0) return;
      }
    }
    items.push({cidr: key.cidr, kind: value.kind, remaining_seconds: remaining});
  });
  return {items: items, cursor: page.cursor || '', done: !!page.done};
}

/*
 * set_add elements a cold start lost: ops putting back the unexpired ones
 * that present (the keys fw_sets holds) lacks, timed from now.
 */
function restoreDynamic(ruleset, desired, present) {
  var dyn = dynamicElements();
  var mono = monotonicMs();
  var wall = now();
  var ops = [];
  ruleset.sets.forEach(function (set) {
    var own = dyn[set.key] || {};
    Object.keys(own).forEach(function (text) {
      var expires = own[text];
      if (expires && (expires <= wall || mono === null)) return;
      var key;
      try { key = compile.setKey(set.id, compile.parseCIDR(text)); } catch (e) { return; }
      if (present[key] || desired[key] !== undefined) return;
      ops.push({op: 'put', object: OBJECT, map: 'fw_sets', key: key,
        value: compile.setValue(expires ? mono + (expires - wall) : 0, compile.SET_KIND_API)});
    });
  });
  return ops;
}

/* Drops the KV elements of sets that no longer exist. */
function forgetGoneSets(setIds) {
  var dyn = dynamicElements();
  var changed = false;
  Object.keys(dyn).forEach(function (name) {
    if (!setIds[name]) { delete dyn[name]; changed = true; }
  });
  if (changed) kv.set(DYN_KEY, dyn);
}

function armPrune() { timer.setTimeout(PRUNE_TIMER, PRUNE_MS, {}); }

function armPruneUnlessPending() {
  var pending = false;
  try {
    pending = (timer.list() || []).some(function (t) { return t && t.name === PRUNE_TIMER; });
  } catch (e) { /* hosts without timer.list: arm */ }
  if (!pending) armPrune();
}

/*
 * Removes expired runtime elements from fw_sets (the dataplane already
 * ignores them) and from KV, then re-arms itself while any may expire.
 */
function prune() {
  var mono = monotonicMs();
  if (mono === null) return;
  var expired = [];
  var timed = false;
  scanAll('fw_sets', function (e) {
    var value = compile.decodeSetValue(e.value);
    if (!value || !value.expiresMs) return;
    if (value.expiresMs <= mono) expired.push(e.key);
    else timed = true;
  });
  expired.forEach(function (key) { try { ebpf.mapDelete(OBJECT, 'fw_sets', key); } catch (e) { /* gone */ } });
  var dyn = dynamicElements();
  var wall = now();
  var changed = false;
  Object.keys(dyn).forEach(function (name) {
    Object.keys(dyn[name]).forEach(function (text) {
      if (dyn[name][text] && dyn[name][text] <= wall) { delete dyn[name][text]; changed = true; }
    });
  });
  if (changed) kv.set(DYN_KEY, dyn);
  var applied = readSnapshot('applied');
  var adding = applied && applied.policies.some(function (p) { return p.enabled && p.data && p.data.add_to_set; });
  if (timed || adding) armPrune();
  return {removed: expired.length};
}

/* The latest sampled drops, newest first, with policy, set and interface names. */
function events(payload) {
  var limit = pageLimit((payload || {}).limit, 100, LOG_KEEP);
  var items = worker.call(LOG_WORKER, 'recentDrops', {limit: limit}) || [];
  var bySlot = slotPolicies();
  var setNames = {};
  var ids = loadState().set_ids;
  Object.keys(ids).forEach(function (name) { setNames[ids[name]] = name; });
  var ifaces = {};
  try {
    (net.link.list() || []).forEach(function (l) { ifaces[l.ifindex] = l.name; });
  } catch (e) { /* names are a convenience */ }
  var nowMono = monotonicMs();
  var wall = now();
  return items.map(function (event) {
    event.at_ms = nowMono === null ? null : Math.round(wall - (nowMono - event.time_ms));
    if (event.reason === 'blocklist') {
      event.set = setNames[event.slot] || null;
      event.policy = null;
      event.policy_name = null;
    } else {
      var policy = bySlot[event.slot];
      event.policy = policy ? policy.key : null;
      event.policy_name = policy ? policy.name : null;
    }
    event.interface = ifaces[event.ifindex] || String(event.ifindex);
    return event;
  });
}

// ------------------------------------------------------- drop_log worker

// Only the drop_log worker VM fills this; the main VM asks it via worker.call.
var dropLog = [];

exports.onDropEvents = function (ctx) {
  var records = (ctx.payload && ctx.payload.records) || [];
  records.forEach(function (record) {
    var event = compile.decodeEvent(record.data);
    if (event) dropLog.push(event);
  });
  if (dropLog.length > LOG_KEEP) dropLog = dropLog.slice(dropLog.length - LOG_KEEP);
};

exports.recentDrops = function (ctx) {
  var limit = pageLimit(ctx.payload && ctx.payload.limit, 100, LOG_KEEP);
  return dropLog.slice(Math.max(0, dropLog.length - limit)).reverse();
};

function interfaces() {
  return (net.link.list() || []).filter(function (l) { return l.name && l.name !== 'lo'; }).map(function (l) {
    var mac = String(l.mac || '');
    return {
      name: l.name,
      kind: l.kind || '',
      up: !!l.up,
      master: l.master_name || '',
      l3: !mac || /^(00:){5}00$/.test(mac)
    };
  });
}

exports.onAction = function (ctx) {
  var id = ctx.action && ctx.action.id;
  if (id === 'apply') return apply(ctx.payload);
  if (id === 'check') {
    var result = check();
    return {errors: result.errors, warnings: result.warnings, token: result.token};
  }
  if (id === 'confirm') return confirm();
  if (id === 'rollback') return rollback('manual');
  if (id === 'status') return status();
  if (id === 'interfaces') return interfaces();
  if (id === 'bans') return bans(ctx.payload);
  if (id === 'unban') return unban(ctx.payload);
  if (id === 'events') return events(ctx.payload);
  if (id === 'set_add') return setAdd(ctx.payload);
  if (id === 'set_del') return setDel(ctx.payload);
  if (id === 'set_flush') return setFlush(ctx.payload);
  if (id === 'set_list') return setList(ctx.payload);
  throw new Error('unknown action: ' + id);
};

exports.onTimer = function (ctx) {
  var name = ctx.timer && ctx.timer.name;
  if (name === CONFIRM_TIMER) return rollback('deadline');
  if (name === SYNC_TIMER) return sync();
  if (name === PRUNE_TIMER) return prune();
};

exports.onReconcile = function () {
  sync();
};
