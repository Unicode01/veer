'use strict';
/*
 * Firewall: a stateless source filter for TCP and UDP destination ports,
 * attached through the Veer XDP dispatcher ahead of the TC dataplane.
 *
 * Policies are drafts until "apply": it compiles them into the generation of
 * the maps the packets do not read, switches fw_cfg to it, and starts a
 * confirmation deadline. The page confirms once it can still reach the API
 * under the new rules; if it cannot, the deadline restores the last confirmed
 * rule set.
 *
 * Every map is declared preserve, so a Veer hot restart hands them to the
 * successor and filtering goes on without a gap. Snapshots of the applied
 * and confirmed rule sets rebuild the maps when they start empty: a cold
 * start, an older host, or a map layout that changed.
 *
 * Policies with a syn_limit also limit new TCP connections per source prefix
 * and ban sources over it (fw_rate, fw_ban; the bans/unban actions list and
 * lift them). Drops are sampled into the fw_events ring; the drop_log worker
 * keeps the latest ones in memory for the events action.
 */
var compile = require('./lib/compile');

var OBJECT = 'firewall';
var OBJECT_PATH = 'firewall.o';
var HOOK = 'wan-filter';
var CONFIRM_TIMER = 'confirm_deadline';
var SYNC_TIMER = 'sync_retry';
var STATE_KEY = 'state';
var GEN_ARRAYS_KEY = 'gen_arrays';
var IFACES_KEY = 'ifaces';
var DEFAULT_CONFIRM_SECONDS = 120;
var SYNC_RETRY_MS = 3000;
var SYNC_RETRY_LIMIT = 20;
var TX_LIMIT = 256;
var LPM_MAPS = ['fw_ports', 'fw_dst4', 'fw_dst6', 'fw_src4', 'fw_src6'];
var ARRAY_ZERO = {fw_port_bits: '0000000000000000', fw_class: '00000000', fw_policy: '00000000', fw_limit: compile.LIMIT_VALUE_ZERO};
var ARRAY_SIZES = {fw_port_bits: 2 * compile.PORT_WORDS_PER_GEN, fw_class: 2 * compile.CLASSES_PER_GEN, fw_policy: 2 * compile.POLICIES_PER_GEN,
  fw_limit: 2 * compile.POLICIES_PER_GEN};
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

var STATE_MAPS = ['fw_cfg', 'fw_ifaces', 'fw_port_bits', 'fw_ports', 'fw_class', 'fw_dst4', 'fw_dst6', 'fw_policy', 'fw_src4', 'fw_src6', 'fw_stats',
  'fw_limit', 'fw_rate', 'fw_ban', 'fw_lstats', 'fw_log_cfg', 'fw_log_tat'];

plugin.capabilities(['firewall', 'xdp']);
pipeline.node({id: 'firewall', description: 'Stateless source filter for TCP and UDP ports, run ahead of the Veer core: by the XDP dispatcher, or at TC ingress on interfaces without native XDP.'});
ebpf.loadObject({
  id: OBJECT,
  path: OBJECT_PATH,
  sha256: crypto.sha256File(OBJECT_PATH),
  description: 'XDP program, with a TC twin for interfaces without native XDP, that drops packets to protected ports from sources a policy does not allow.',
  programs: [
    {id: 'filter', section: 'xdp/veer/firewall', type: 'xdp'},
    {id: 'filter_tc', section: 'tc/veer/firewall', type: 'tc'}
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
hooks.attach({
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
});

var CIDR_LIST = {type: 'array', maxItems: 256, items: {type: 'string', maxLength: 64}};
plugin.resource({
  id: 'policies',
  description: 'Draft policies. Nothing reaches the dataplane before the apply action.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: compile.MAX_POLICY_SLOT,
  max_record_bytes: 131072,
  schema_version: 1,
  schema: {
    type: 'object',
    additionalProperties: false,
    required: ['ports'],
    properties: {
      name: {type: 'string', maxLength: 64},
      remark: {type: 'string', maxLength: 256},
      protocol: {type: 'string', enum: ['tcp', 'udp', 'tcp+udp']},
      ports: {type: 'array', minItems: 1, maxItems: 64, items: {type: ['string', 'integer']}},
      destinations: {type: 'array', maxItems: 64, items: {type: 'string', maxLength: 64}},
      default_action: {type: 'string', enum: ['allow', 'drop']},
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
      sources: {
        type: 'array',
        maxItems: 1024,
        items: {
          type: 'object',
          additionalProperties: false,
          required: ['cidr', 'action'],
          properties: {
            cidr: {type: 'string', maxLength: 64},
            action: {type: 'string', enum: ['allow', 'drop']},
            remark: {type: 'string', maxLength: 128}
          }
        }
      }
    }
  }
});
plugin.resource({
  id: 'settings',
  description: 'Draft settings: bound interfaces, trusted sources and the confirmation timeout.',
  methods: ['list', 'get', 'create', 'update'],
  runtime_update: 'manual',
  max_records: 1,
  max_record_bytes: 32768,
  schema_version: 1,
  schema: {
    type: 'object',
    additionalProperties: false,
    properties: {
      interfaces: {type: 'array', maxItems: 16, items: {type: 'string', maxLength: 15}},
      trusted_sources: CIDR_LIST,
      confirm_timeout_seconds: {type: 'integer', minimum: 30, maximum: 600},
      log_per_second: {type: 'integer', minimum: 0, maximum: 1000}
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
plugin.action({id: 'apply', description: 'Apply the draft policies and settings; they stay until confirmed or the deadline restores the previous rule set.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'confirm', description: 'Keep the rule set applied last.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'rollback', description: 'Restore the last confirmed rule set now.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'status', description: 'Read the applied rule set, the confirmation deadline and per-policy counters.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'interfaces', description: 'List interfaces the hook can bind to.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'bans', description: 'List sources banned for going over a SYN limit, a page at a time.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'unban', description: 'Lift one ban (key), the bans of one policy, or all of them.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'events', description: 'The latest sampled drops, newest first.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: crypto.sha256File('ui/index.html'),
  page: 'firewall',
  page_title: 'Firewall',
  resources: [
    {resource: 'policies', methods: ['list', 'get', 'create', 'update', 'delete']},
    {resource: 'settings', methods: ['list', 'get', 'create', 'update']},
    {resource: 'snapshots', methods: ['list', 'get']}
  ],
  actions: ['check', 'apply', 'confirm', 'rollback', 'status', 'interfaces', 'bans', 'unban', 'events']
});

// ------------------------------------------------------------------ helpers

function now() { return Date.now(); }

function loadState() {
  var record = kv.get(STATE_KEY);
  var st = record && record.data && typeof record.data === 'object' ? record.data : {};
  if (st.generation !== 0 && st.generation !== 1) st.generation = 0;
  if (!st.slots || typeof st.slots !== 'object') st.slots = {};
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
  return {interfaces: interfaces, trusted: trusted, confirmSeconds: Math.floor(seconds), logPerSecond: logRate};
}

/* fw_log_cfg: a GCRA allowing logPerSecond events per CPU, in bursts of as many. */
function logConfigHex(logPerSecond) {
  if (!logPerSecond) return compile.u32le(0) + compile.u32le(0) + compile.u32le(0) + compile.u32le(0);
  var interval = Math.floor(1e9 / logPerSecond);
  var tolerance = interval * (logPerSecond - 1);
  return compile.u32le(interval) + compile.u32le(0) + compile.u32le(tolerance) + compile.u32le(0);
}

/*
 * Snapshot form of a rule set: the policy records as stored, so compiling a
 * snapshot again gives the same maps.
 */
function snapshotOf(records, settingsData) {
  return {
    policies: records.map(function (r) { return {key: r.key, enabled: r.enabled !== false, data: r.data}; })
      .sort(function (a, b) { return a.key < b.key ? -1 : a.key > b.key ? 1 : 0; }),
    settings: settingsData || {}
  };
}

function readSnapshot(name) {
  var record = resources.get('snapshots', name);
  return record && record.data && Array.isArray(record.data.policies) ? record.data : null;
}

function writeSnapshot(name, snapshot) {
  resources.set('snapshots', name, snapshot, true, false);
}

/* Validates a snapshot and compiles it; throws with every problem found. */
function buildRuleset(snapshot, slots) {
  var errors = [];
  var policies = [];
  snapshot.policies.forEach(function (p) {
    if (!p.enabled) return;
    try { policies.push(compile.normalizePolicy(p.key, p.data)); } catch (e) { errors.push(e.message); }
  });
  var settings;
  try { settings = normalizeSettings(snapshot.settings); } catch (e) { errors.push(e.message); }
  errors = errors.concat(compile.findConflicts(policies));
  if (errors.length) {
    var err = new Error(errors.join('；'));
    err.errors = errors;
    throw err;
  }
  var assigned = compile.assignSlots(policies.map(function (p) { return p.key; }), slots);
  policies.forEach(function (p) { p.slot = assigned.slots[p.key]; });
  return {policies: policies, settings: settings, slots: assigned.slots, fresh: assigned.fresh};
}

function transact(ops) {
  for (var i = 0; i < ops.length; i += TX_LIMIT) ebpf.mapTransaction({operations: ops.slice(i, i + TX_LIMIT)});
}

function scanKeys(map) {
  var keys = [];
  var cursor = '';
  for (var guard = 0; guard < 4096; guard++) {
    var options = {limit: 256};
    if (cursor) options.cursor = cursor;
    var page = ebpf.mapScan(OBJECT, map, options);
    (page.entries || []).forEach(function (e) { keys.push(e.key); });
    if (page.done || !page.entries || !page.entries.length) return keys;
    cursor = page.cursor;
  }
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

/* Points the XDP hook at the interfaces; only a change touches the record. */
function bindInterfaces(names) {
  var current = resources.get('hook_bindings', HOOK);
  var data = {hook_id: HOOK, interfaces: names};
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

/* Writes a rule set into generation and makes packets read it. */
function activate(ruleset, generation) {
  var compiled = compile.compileGeneration(ruleset.policies, ruleset.settings.trusted, generation);
  writeGeneration(generation, compiled);
  var flags = CFG_LOADED | (compiled.active ? CFG_ACTIVE : 0) | (syncInterfaces(ruleset.settings.interfaces) ? CFG_HAS_L3 : 0);
  ebpf.mapPut(OBJECT, 'fw_log_cfg', compile.u32le(0), logConfigHex(ruleset.settings.logPerSecond));
  ebpf.mapPut(OBJECT, 'fw_cfg', compile.u32le(0), compile.u32le(generation) + compile.u32le(flags));
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

/* New slots start their counters from what the slot shows now. */
function resetBaselines(st, fresh) {
  fresh.forEach(function (slot) {
    var values = [0, 0, 0, 0, 0, 0];
    try { values = counters(slot); } catch (e) { /* maps not loaded: nothing counted yet */ }
    st.baselines[String(slot)] = values;
  });
}

/* Every key of an LRU map; scans are best-effort snapshots. */
function scanAll(map, visit) {
  var cursor = '';
  for (var guard = 0; guard < 1024; guard++) {
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
  var check = buildRuleset(snapshot, loadState().slots);
  bindInterfaces(check.settings.interfaces);
  var st = loadState();
  change(st);
  var ruleset = buildRuleset(snapshot, st.slots);
  st.slots = ruleset.slots;
  resetBaselines(st, ruleset.fresh);
  clearLimitState(ruleset.fresh);
  commit(st, ruleset);
  saveState(st);
}

function flipped(generation) { return generation === 0 ? 1 : 0; }

function restoreConfirmed(reason) {
  var confirmed = readSnapshot('confirmed') || snapshotOf([], {});
  try {
    buildRuleset(confirmed, {});
  } catch (e) {
    // Never fails a rollback over a stored snapshot: keep its interfaces, no policies.
    confirmed = snapshotOf([], confirmed.settings);
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
  var snapshot = snapshotOf(listAll('policies'), settingsDraft());
  var ruleset;
  try {
    ruleset = buildRuleset(snapshot, loadState().slots);
  } catch (e) {
    return {snapshot: snapshot, errors: e.errors || [String(e.message || e)], warnings: [], token: ''};
  }
  var warnings = compile.findWarnings(ruleset.policies, ruleset.settings.trusted);
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
  var attach = settings.interfaces.length ? attachmentStatus(settings.interfaces) : null;
  if (attach && attach.error) {
    restoreConfirmed('attach_failed');
    throw new Error('防火墙没能挂载到接口，已回到上一次确认的规则：' + attach.error);
  }
}

function confirm() {
  var st = loadState();
  if (!st.pending) return;
  writeSnapshot('confirmed', readSnapshot('applied') || snapshotOf([], {}));
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
  if (!fresh && !st.dirty && cfg.generation === st.generation) return;
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
  var draft = snapshotOf(listAll('policies'), settingsDraft());
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
  if (loaded) {
    try {
      evasive = counters(0)[EVASIVE_COUNTER];
      log = {
        logged: compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_lstats', compile.lstatsKey(0, compile.LCNT_LOGGED))),
        lost: compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_lstats', compile.lstatsKey(0, compile.LCNT_LOST)))
      };
    } catch (e) {
      loaded = false;
    }
  }
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
    interfaces: applied ? normalizeInterfacesSafe(applied.settings) : [],
    draft_changed: !applied || !sameJSON(draft, applied),
    summary: st.summary || null,
    policies: policies,
    evasive_drops: evasive,
    drop_log: log,
    attachments: attachmentStatus(applied ? normalizeInterfacesSafe(applied.settings) : []),
    core: coreEngine()
  };
}

/*
 * How the hook sits on each bound interface: attached (mode 'driver' or
 * 'generic' XDP, or 'tc' where the tc_fallback runs), not attached, or the
 * host's error. null on hosts without control.attachment_status.v1.
 */
function attachmentStatus(names) {
  if (typeof plugin.attachments !== 'function') return null;
  var runtime;
  try { runtime = plugin.attachments(); } catch (e) { return null; }
  var byInterface = {};
  ((runtime && runtime.attachments) || []).forEach(function (a) {
    if (a.hook_id === HOOK && a.engine === 'xdp') byInterface[a.interface] = a;
  });
  return {
    error: (runtime && runtime.error) || '',
    reason: (runtime && runtime.reason) || '',
    interfaces: names.map(function (name) {
      var a = byInterface[name];
      if (!a) return {interface: name, attached: false, mode: '', error: ''};
      return {interface: name, attached: a.status === 'attached', mode: a.xdp_mode || '', error: a.error || ''};
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

/* The latest sampled drops, newest first, with policy and interface names. */
function events(payload) {
  var limit = pageLimit((payload || {}).limit, 100, LOG_KEEP);
  var items = worker.call(LOG_WORKER, 'recentDrops', {limit: limit}) || [];
  var bySlot = slotPolicies();
  var ifaces = {};
  try {
    (net.link.list() || []).forEach(function (l) { ifaces[l.ifindex] = l.name; });
  } catch (e) { /* names are a convenience */ }
  var nowMono = monotonicMs();
  var wall = now();
  return items.map(function (event) {
    var policy = bySlot[event.slot];
    event.at_ms = nowMono === null ? null : Math.round(wall - (nowMono - event.time_ms));
    event.policy = policy ? policy.key : null;
    event.policy_name = policy ? policy.name : null;
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

function normalizeInterfacesSafe(settings) {
  try { return normalizeSettings(settings).interfaces; } catch (e) { return []; }
}

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
  throw new Error('unknown action: ' + id);
};

exports.onTimer = function (ctx) {
  var name = ctx.timer && ctx.timer.name;
  if (name === CONFIRM_TIMER) return rollback('deadline');
  if (name === SYNC_TIMER) return sync();
};

exports.onReconcile = function () {
  sync();
};
