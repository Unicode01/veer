'use strict';
/*
 * Firewall: a stateless source filter for TCP and UDP destination ports,
 * attached through the Veer XDP dispatcher ahead of the TC dataplane.
 *
 * Policies are drafts until "apply": it compiles them into the generation of
 * the maps the packets do not read, switches fw_cfg to it, and starts a
 * confirmation deadline. The page confirms once it can still reach the API
 * under the new rules; if it cannot, the deadline restores the last confirmed
 * rule set. Snapshots of the applied and confirmed rule sets let the plugin
 * rebuild its maps after Veer restarts, since a new Veer process starts the
 * plugin with empty maps.
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
var ARRAY_ZERO = {fw_port_bits: '0000000000000000', fw_class: '00000000', fw_policy: '00000000'};
var ARRAY_SIZES = {fw_port_bits: 2 * compile.PORT_WORDS_PER_GEN, fw_class: 2 * compile.CLASSES_PER_GEN, fw_policy: 2 * compile.POLICIES_PER_GEN};
var CFG_HAS_L3 = 1;
var CFG_ACTIVE = 2;
var CFG_LOADED = 4; // written by this script only, tells fresh maps apart
var IFACE_L3 = 1;
var COUNTER_NAMES = ['pass', 'drop', 'trusted'];
var EVASIVE_COUNTER = 3;
var IFACE_NAME = /^[A-Za-z0-9_.:@-]{1,15}$/;

var STATE_MAPS = ['fw_cfg', 'fw_ifaces', 'fw_port_bits', 'fw_ports', 'fw_class', 'fw_dst4', 'fw_dst6', 'fw_policy', 'fw_src4', 'fw_src6', 'fw_stats'];

plugin.capabilities(['firewall', 'xdp']);
pipeline.node({id: 'firewall', description: 'Stateless source filter for TCP and UDP ports, run by the XDP dispatcher ahead of the Veer core.'});
ebpf.loadObject({
  id: OBJECT,
  path: OBJECT_PATH,
  sha256: crypto.sha256File(OBJECT_PATH),
  description: 'XDP program that drops packets to protected ports from sources a policy does not allow.',
  programs: [{id: 'filter', section: 'xdp/veer/firewall', type: 'xdp'}],
  state_maps: STATE_MAPS.map(function (name) { return {name: name, policy: 'preserve', schema_version: 1}; })
});
hooks.attach({
  id: HOOK,
  engine: 'xdp',
  stage: 'pre_forward',
  priority: 10,
  program: OBJECT + ':filter',
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
      confirm_timeout_seconds: {type: 'integer', minimum: 30, maximum: 600}
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
plugin.action({id: 'apply', description: 'Apply the draft policies and settings; they stay until confirmed or the deadline restores the previous rule set.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'confirm', description: 'Keep the rule set applied last.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'rollback', description: 'Restore the last confirmed rule set now.', runtime_update: 'runtime_apply', max_payload_bytes: 1024});
plugin.action({id: 'status', description: 'Read the applied rule set, the confirmation deadline and per-policy counters.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
plugin.action({id: 'interfaces', description: 'List interfaces the hook can bind to.', runtime_update: 'runtime_query', max_payload_bytes: 1024});
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
  actions: ['apply', 'confirm', 'rollback', 'status', 'interfaces']
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
  return {interfaces: interfaces, trusted: trusted, confirmSeconds: Math.floor(seconds)};
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
  if (errors.length) throw new Error(errors.join('；'));
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
  if (current && current.enabled === enabled && JSON.stringify(current.data) === JSON.stringify(data)) return false;
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
  ebpf.mapPut(OBJECT, 'fw_cfg', compile.u32le(0), compile.u32le(generation) + compile.u32le(flags));
  return compiled.summary;
}

function counters(slot) {
  return [0, 1, 2, 3].map(function (c) {
    return compile.sumPerCPU(ebpf.mapGetPerCPU(OBJECT, 'fw_stats', compile.statsKey(slot, c)));
  });
}

/* New slots start their counters from what the slot shows now. */
function resetBaselines(st, fresh) {
  fresh.forEach(function (slot) {
    var values = [0, 0, 0, 0];
    try { values = counters(slot); } catch (e) { /* maps not loaded: nothing counted yet */ }
    st.baselines[String(slot)] = values;
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

function apply() {
  if (loadState().pending) throw new Error('上一次应用还在等待确认：请先确认或回滚');
  var snapshot = snapshotOf(listAll('policies'), settingsDraft());
  var seconds = normalizeSettings(snapshot.settings).confirmSeconds;
  install(snapshot, function (st) {
    st.generation = flipped(st.generation);
    st.pending = {deadline_ms: now() + seconds * 1000};
    st.applied_at = now();
    writeSnapshot('applied', snapshot);
    timer.setTimeout(CONFIRM_TIMER, seconds * 1000, {});
  });
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
  var cfg;
  try { cfg = readConfig(); } catch (e) { cfg = null; }
  var fresh = !cfg || !(cfg.flags & CFG_LOADED);
  if (fresh && st.pending && !st.dirty) {
    // Maps written once and now empty: a new Veer process. The unconfirmed
    // rule set is not restored, the confirmed one is. (Dirty maps were never
    // written, as right after the first apply binds an interface.)
    restoreConfirmed('restart');
    return;
  }
  if (!fresh && !st.dirty && cfg.generation === st.generation) return;
  install(applied, function () {});
}

function sameJSON(a, b) { return JSON.stringify(a) === JSON.stringify(b); }

function status() {
  var st = loadState();
  var applied = readSnapshot('applied');
  var draft = snapshotOf(listAll('policies'), settingsDraft());
  var loaded = true;
  var names = {};
  (applied ? applied.policies : []).forEach(function (p) { names[p.key] = p.data && p.data.name ? p.data.name : p.key; });
  var policies = Object.keys(st.slots).sort().map(function (key) {
    var slot = st.slots[key];
    var item = {key: key, name: names[key] || key, slot: slot, counters: null};
    if (!loaded) return item;
    try {
      var values = counters(slot);
      var base = st.baselines[String(slot)] || [0, 0, 0, 0];
      item.counters = {};
      COUNTER_NAMES.forEach(function (name, i) { item.counters[name] = Math.max(0, values[i] - (base[i] || 0)); });
    } catch (e) {
      loaded = false;
    }
    return item;
  });
  var evasive = null;
  if (loaded) {
    try { evasive = counters(0)[EVASIVE_COUNTER]; } catch (e) { loaded = false; }
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
    evasive_drops: evasive
  };
}

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
  if (id === 'apply') return apply();
  if (id === 'confirm') return confirm();
  if (id === 'rollback') return rollback('manual');
  if (id === 'status') return status();
  if (id === 'interfaces') return interfaces();
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
