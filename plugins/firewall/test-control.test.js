'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const {createTestHost} = require('../../sdk/plugin/test-host.cjs');
const c = require('./lib/compile.js');

const LINKS = {
  eth0: {name: 'eth0', ifindex: 2, kind: 'device', mac: '02:00:00:00:00:02', up: true},
  eth1: {name: 'eth1', ifindex: 3, kind: 'device', mac: '02:00:00:00:00:03', up: true},
  vmbr0: {name: 'vmbr0', ifindex: 4, kind: 'bridge', mac: '02:00:00:00:00:04', up: true},
  wg0: {name: 'wg0', ifindex: 5, kind: 'wireguard', mac: '', up: true},
};

function policy(data) {
  return {data: {protocol: 'tcp', default_action: 'drop', ...data}, enabled: true};
}

function makeHost(resources, options = {}) {
  const host = createTestHost({
    pluginDir: path.join(__dirname),
    fixtures: {resources},
    hostInfo: options.hostInfo,
    availableFeatures: options.availableFeatures,
    adapters: {
      'net.link.get': (name) => LINKS[name],
      'net.link.list': () => Object.values(LINKS),
      'ebpf.mapGetPerCPU': (object, map, key) => (options.counters ? options.counters(key) : ['0000000000000000']),
      ...(options.adapters || {}),
    },
  });
  host.load();
  return host;
}

function map(host, name) {
  return host.state.maps.get('firewall\0' + name) || new Map();
}

function cfg(host) {
  const hex = map(host, 'fw_cfg').get('00000000');
  if (!hex) return null;
  const word = (o) => parseInt(hex.substr(o + 6, 2) + hex.substr(o + 4, 2) + hex.substr(o + 2, 2) + hex.substr(o, 2), 16);
  return {generation: word(0), flags: word(8)};
}

function keysOf(host, name, generation) {
  return [...map(host, name).keys()].filter((k) => c.keyGeneration(k) === generation).sort();
}

function state(host) {
  return host.snapshot().kv.state;
}

function setPolicy(host, key, data, enabled = true) {
  host.state.resources.get('policies').set(key, {key, data: {protocol: 'tcp', default_action: 'drop', ...data}, enabled, revision: 1});
}

const SSH = policy({name: 'SSH', ports: ['22'], sources: [{cidr: '198.51.100.0/24', action: 'allow'}]});
const SETTINGS = {data: {interfaces: ['eth0'], trusted_sources: ['192.0.2.10'], confirm_timeout_seconds: 60}};

test('apply writes the inactive generation, binds the hook and waits for confirmation', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  assert.deepEqual(cfg(host), {generation: 1, flags: 2 | 4});
  const bindings = host.snapshot().resources.hook_bindings['wan-filter'];
  assert.deepEqual(bindings.data, {hook_id: 'wan-filter', interfaces: ['eth0'], tc_egress: false});
  assert.equal(bindings.enabled, true);
  assert.equal(keysOf(host, 'fw_ports', 1).length, 1);
  assert.deepEqual(keysOf(host, 'fw_src4', 1), ['3800000001000001c6336400', '4000000001000000c000020a']);
  assert.ok(state(host).pending);
  assert.ok(host.snapshot().timers.some((t) => t.name === 'confirm_deadline' && t.delay_ms === 60000));

  host.action('confirm', {});
  assert.equal(state(host).pending, null);
  assert.ok(!host.snapshot().timers.some((t) => t.name === 'confirm_deadline'));
  assert.deepEqual(host.snapshot().resources.snapshots.confirmed.data, host.snapshot().resources.snapshots.applied.data);
});

test('apply refuses while an earlier apply waits and on invalid drafts', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  assert.throws(() => host.action('apply', {}), /等待确认/);
  host.action('confirm', {});
  setPolicy(host, 'dup', {name: 'dup', ports: ['22']});
  const before = state(host);
  assert.throws(() => host.action('apply', {}), /作用于相同的目标地址/);
  assert.deepEqual(state(host), before);
  setPolicy(host, 'dup', {name: 'dup', ports: ['22'], sources: [{cidr: 'nonsense', action: 'allow'}]});
  assert.throws(() => host.action('apply', {}), /地址无效/);
  assert.equal(cfg(host).generation, 1);
});

test('the deadline restores the confirmed rule set and its interfaces', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  // A new draft: another port and another interface, never confirmed.
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  host.state.resources.get('settings').set('default', {key: 'default', data: {...SETTINGS.data, interfaces: ['eth0', 'eth1']}, enabled: true, revision: 2});
  host.action('apply', {});
  assert.equal(cfg(host).generation, 0);
  assert.deepEqual(host.snapshot().resources.hook_bindings['wan-filter'].data.interfaces, ['eth0', 'eth1']);
  assert.equal(keysOf(host, 'fw_ports', 0).length, 2);

  host.fireTimer('confirm_deadline');
  const st = state(host);
  assert.equal(st.pending, null);
  assert.equal(st.rollback_reason, 'deadline');
  assert.equal(cfg(host).generation, 1);
  assert.deepEqual(host.snapshot().resources.hook_bindings['wan-filter'].data.interfaces, ['eth0']);
  assert.deepEqual(host.snapshot().resources.snapshots.applied.data, host.snapshot().resources.snapshots.confirmed.data);
  // Generation 1 holds only the confirmed policy again.
  assert.equal(keysOf(host, 'fw_ports', 1).length, 1);
});

test('rewriting a generation removes what the older rule set left there', () => {
  const host = makeHost({policies: {ssh: SSH, web: policy({name: 'web', ports: ['8443'], sources: [{cidr: '10.0.0.0/8', action: 'allow'}]})}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  const word8443 = c.u32le(1 * c.PORT_WORDS_PER_GEN + (8443 >> 6));
  assert.notEqual(map(host, 'fw_port_bits').get(word8443), '0000000000000000');
  host.state.resources.get('policies').delete('web');
  host.action('apply', {}); // generation 0
  host.action('confirm', {});
  host.action('apply', {}); // generation 1 again, without web
  host.action('confirm', {});
  assert.equal(cfg(host).generation, 1);
  assert.equal(map(host, 'fw_port_bits').get(word8443), '0000000000000000');
  assert.equal(keysOf(host, 'fw_ports', 1).length, 1);
  assert.ok(!keysOf(host, 'fw_src4', 1).some((k) => k.endsWith('0a000000')));
});

/* Applies the draft the way the page does once the user accepts its warnings. */
function applyAccepting(host) {
  const check = host.action('check', {});
  assert.deepEqual(check.errors, []);
  return host.action('apply', check.token ? {accept_warnings: check.token} : {});
}

test('apply needs the warnings the check reported accepted, and only those', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: {data: {interfaces: ['eth0']}}}});
  const check = host.action('check', {});
  assert.deepEqual(check.errors, []);
  assert.deepEqual(check.warnings.map((w) => w.id), ['lockout:ssh']);
  assert.throws(() => host.action('apply', {}), /应用前需要确认/);
  assert.equal(cfg(host), null);
  // The draft changed after the check: the old token does not cover it.
  setPolicy(host, 'high', {name: 'high', protocol: 'udp', ports: ['40000-40100']});
  assert.throws(() => host.action('apply', {accept_warnings: check.token}), /应用前需要确认/);
  const again = host.action('check', {});
  assert.deepEqual(again.warnings.map((w) => w.id), ['reply_ports:high', 'lockout:ssh']);
  host.action('apply', {accept_warnings: again.token});
  assert.ok(state(host).pending);
  assert.equal(cfg(host).flags & 2, 2);
});

test('check reports draft errors and writes nothing', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  setPolicy(host, 'dup', {name: 'dup', ports: ['22']});
  setPolicy(host, 'bad', {name: 'bad', ports: ['70000']});
  const check = host.action('check', {});
  assert.equal(check.errors.length, 2, JSON.stringify(check.errors));
  assert.ok(check.errors.some((e) => /端口无效/.test(e)));
  assert.ok(check.errors.some((e) => /作用于相同的目标地址/.test(e)));
  assert.deepEqual(check.warnings, []);
  assert.equal(check.token, '');
  assert.equal(cfg(host), null);
  assert.equal(host.snapshot().resources.hook_bindings, undefined);
});

test('an L3 interface is marked so the program skips Ethernet parsing', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: {data: {interfaces: ['eth0', 'wg0']}}}});
  applyAccepting(host);
  assert.equal(cfg(host).flags & 1, 1);
  assert.deepEqual([...map(host, 'fw_ifaces').entries()], [['05000000', '01000000']]);
});

test('after a restart the applied rule set returns, an unconfirmed one does not', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  host.state.maps.clear(); // a new Veer process starts the plugin with empty maps
  host.reconcile();
  assert.equal(cfg(host).flags & 4, 4);
  assert.equal(keysOf(host, 'fw_ports', cfg(host).generation).length, 1);

  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  host.action('apply', {});
  assert.ok(state(host).pending);
  host.state.maps.clear();
  host.reconcile();
  const st = state(host);
  assert.equal(st.pending, null);
  assert.equal(st.rollback_reason, 'restart');
  assert.equal(keysOf(host, 'fw_ports', cfg(host).generation).length, 1);
});

test('a hot restart that kept the maps keeps a pending apply and arms its deadline again', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  host.action('apply', {});
  const before = JSON.stringify([...host.state.maps.entries()].map(([k, v]) => [k, [...v.entries()]]));
  // The new process has the maps (the host handed them over) but no timers.
  host.state.timers.clear();
  host.reconcile();
  const st = state(host);
  assert.ok(st.pending, 'the pending apply is still pending');
  const deadline = host.snapshot().timers.find((t) => t.name === 'confirm_deadline');
  assert.ok(deadline && deadline.delay_ms > 0 && deadline.delay_ms <= 60000, JSON.stringify(deadline));
  assert.equal(JSON.stringify([...host.state.maps.entries()].map(([k, v]) => [k, [...v.entries()]])), before, 'kept maps are not rewritten');
  host.fireTimer('confirm_deadline');
  assert.equal(state(host).rollback_reason, 'deadline');
  assert.equal(keysOf(host, 'fw_ports', cfg(host).generation).length, 1);
});

test('status reports counters from where a policy started', () => {
  let packets = 5;
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}}, {
    counters: () => [c.u32le(packets) + '00000000'],
  });
  host.action('apply', {});
  packets = 12;
  const status = host.action('status', {});
  assert.equal(status.loaded, true);
  assert.equal(status.generation, 1);
  assert.ok(status.pending.remaining_seconds > 0);
  assert.deepEqual(status.policies, [{key: 'ssh', name: 'SSH', slot: 1, syn_limit: null,
    counters: {pass: 7, drop: 7, trusted: 7, banned: 7, rate_limited: 7}}]);
  assert.equal(status.draft_changed, false);
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  assert.equal(host.action('status', {}).draft_changed, true);
});

function sortedKeys(value) {
  if (Array.isArray(value)) return value.map(sortedKeys);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortedKeys(value[k])]));
  }
  return value;
}

test('an applied draft counts as unchanged after the host stores it canonically', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  // The real host keeps records as canonical JSON: keys come back sorted.
  for (const name of ['snapshots', 'policies', 'settings', 'hook_bindings']) {
    for (const record of host.state.resources.get(name).values()) record.data = sortedKeys(record.data);
  }
  assert.equal(host.action('status', {}).draft_changed, false);
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  assert.equal(host.action('status', {}).draft_changed, true);
});

test('interfaces lists bindable links and flags L3 ones', () => {
  const host = makeHost({});
  const list = host.action('interfaces', {});
  assert.deepEqual(list.map((l) => [l.name, l.l3]), [['eth0', false], ['eth1', false], ['vmbr0', false], ['wg0', true]]);
});

const LIMITED = policy({name: 'SSH', ports: ['22'], default_action: 'allow', syn_limit: {max_new: 20, window_seconds: 10, ban_seconds: 300}});

function limitKey(slot, addr) {
  return c.u8(4) + c.u8(32) + c.u16le(slot) + (addr + '0'.repeat(32)).slice(0, 32);
}

function seed(host, name, entries) {
  const m = host.state.maps.get('firewall\0' + name) || new Map();
  for (const [k, v] of entries) m.set(k, v);
  host.state.maps.set('firewall\0' + name, m);
}

test('apply writes SYN limits and the drop log rate', () => {
  const host = makeHost({policies: {ssh: LIMITED}, settings: {default: SETTINGS}});
  host.action('apply', {});
  const g = cfg(host).generation;
  const index = g * c.POLICIES_PER_GEN + 1;
  assert.equal(map(host, 'fw_policy').get(c.u32le(index)), '03000000');
  assert.equal(map(host, 'fw_limit').get(c.u32le(index)).slice(0, 24), c.u32le(20) + c.u32le(10) + c.u32le(300));
  // 10 events/s per CPU in bursts of 10: interval 0.1 s, tolerance 0.9 s.
  assert.equal(map(host, 'fw_log_cfg').get('00000000'), c.u32le(100000000) + '00000000' + c.u32le(900000000) + '00000000');
  assert.deepEqual(host.action('status', {}).policies[0].syn_limit, {max_new: 20, window_seconds: 10, ban_seconds: 300});

  host.action('confirm', {});
  host.state.resources.get('settings').set('default', {key: 'default', data: {...SETTINGS.data, log_per_second: 0}, enabled: true, revision: 2});
  host.state.resources.get('policies').set('ssh', {key: 'ssh', data: {...LIMITED.data, syn_limit: undefined}, enabled: true, revision: 2});
  host.action('apply', {});
  const g2 = cfg(host).generation;
  assert.equal(map(host, 'fw_log_cfg').get('00000000'), '00'.repeat(16));
  assert.equal(map(host, 'fw_policy').get(c.u32le(g2 * c.POLICIES_PER_GEN + 1)), '01000000');
  assert.equal(map(host, 'fw_limit').get(c.u32le(g2 * c.POLICIES_PER_GEN + 1)), c.LIMIT_VALUE_ZERO);
});

test('bans list with their policy and unban lifts one, a policy or all', () => {
  let clock = () => 1000; // ms on the clock BPF ban ends use
  const host = makeHost({policies: {ssh: LIMITED, web: policy({name: 'web', ports: ['443'], syn_limit: {max_new: 5, window_seconds: 1}})}, settings: {default: SETTINGS}},
    {adapters: {'ebpf.monotonicMs': () => clock()}});
  host.action('apply', {});
  host.action('confirm', {});
  const slots = host.action('status', {}).policies.reduce((acc, p) => ({...acc, [p.key]: p.slot}), {});
  const a = limitKey(slots.ssh, 'cb007105');
  const b = limitKey(slots.ssh, 'cb007106');
  const w = limitKey(slots.web, 'cb007107');
  const expired = limitKey(slots.ssh, 'cb007108');
  // Bans end at 5000 ms; the expired one at 500 ms.
  seed(host, 'fw_ban', [[a, '00f2052a01000000'], [b, '00f2052a01000000'], [w, '00f2052a01000000'], [expired, '0065cd1d00000000']]);
  seed(host, 'fw_rate', [[a, '00'.repeat(16)]]);

  const page = host.action('bans', {});
  assert.equal(page.done, true);
  assert.equal(page.clock, true);
  assert.deepEqual(page.items.map((i) => [i.source, i.policy, i.policy_name, i.remaining_seconds]).sort(), [
    ['203.0.113.5/32', 'ssh', 'SSH', 4], ['203.0.113.6/32', 'ssh', 'SSH', 4], ['203.0.113.7/32', 'web', 'web', 4]]);
  // A host that cannot tell the time: every ban, no remaining time.
  clock = () => { throw new Error('not supported'); };
  const blind = host.action('bans', {});
  assert.equal(blind.clock, false);
  assert.equal(blind.items.length, 4);
  assert.ok(blind.items.every((i) => i.remaining_seconds === null));
  clock = () => 1000;
  host.state.maps.get('firewall fw_ban').delete(expired);

  assert.deepEqual(host.action('unban', {key: a}), {removed: 1});
  assert.equal(map(host, 'fw_ban').has(a), false);
  assert.equal(map(host, 'fw_rate').has(a), false, 'the SYN count goes with the ban');
  assert.deepEqual(host.action('unban', {policy: 'ssh'}), {removed: 1});
  assert.deepEqual([...map(host, 'fw_ban').keys()], [w]);
  assert.deepEqual(host.action('unban', {all: true}), {removed: 1});
  assert.equal(map(host, 'fw_ban').size, 0);
  assert.throws(() => host.action('unban', {key: 'zz'}), /封禁记录无效/);
  assert.throws(() => host.action('unban', {policy: 'nope'}), /没有这条已应用的策略/);
  assert.throws(() => host.action('unban', {}), /需要 key、policy 或 all/);
});

test('a policy that takes over a slot starts without its bans', () => {
  const host = makeHost({policies: {ssh: LIMITED}, settings: {default: SETTINGS}});
  host.action('apply', {});
  host.action('confirm', {});
  const old = limitKey(1, 'cb007105');
  const other = limitKey(2, 'cb007106');
  seed(host, 'fw_ban', [[old, '00f2052a01000000'], [other, '00f2052a01000000']]);
  seed(host, 'fw_rate', [[other, '00'.repeat(16)]]);
  host.state.resources.get('policies').delete('ssh');
  setPolicy(host, 'web', {name: 'web', ports: ['443'], syn_limit: {max_new: 5, window_seconds: 1}});
  host.action('apply', {});
  assert.equal(host.action('status', {}).policies[0].slot, 2, 'the new policy avoids the slot just freed');
  assert.deepEqual([...map(host, 'fw_ban').keys()], [old]);
  assert.equal(map(host, 'fw_rate').size, 0);
});

function eventHex(slot, reason, ifindex, src) {
  return c.u32le(5000000) + c.u32le(0) + c.u32le(ifindex) + c.u16le(slot) + c.u8(reason) + c.u8(4) + c.u8(0) + '00' +
    '9c40' + '0016' + '0000' + (src + '0'.repeat(32)).slice(0, 32) + ('0a000001' + '0'.repeat(32)).slice(0, 32);
}

test('sampled drops reach the worker and come back newest first', () => {
  const host = makeHost({policies: {ssh: LIMITED}, settings: {default: SETTINGS}}, {adapters: {'ebpf.monotonicMs': () => 10000}});
  host.action('apply', {});
  host.ring('drop_log', [eventHex(1, 1, 2, 'cb007105'), eventHex(1, 3, 2, 'cb007106')]);
  host.ring('drop_log', [eventHex(0, 4, 3, 'cb007107')]);
  const items = host.action('events', {limit: 2});
  assert.deepEqual(items.map((e) => [e.reason, e.source, e.policy, e.interface]), [
    ['evasive', '203.0.113.7', null, 'eth1'], ['rate', '203.0.113.6', 'ssh', 'eth0']]);
  assert.equal(items[1].policy_name, 'SSH');
  // Logged at 5 ms on a clock now at 10000 ms: 9995 ms ago.
  assert.ok(Math.abs(items[1].at_ms - (Date.now() - 9995)) < 5000, String(items[1].at_ms));
  assert.equal(host.action('events', {}).length, 3);
  // The worker keeps the latest 500.
  const batch = Array.from({length: 128}, () => eventHex(1, 1, 2, 'cb007105'));
  for (let i = 0; i < 5; i++) host.ring('drop_log', batch);
  assert.equal(host.action('events', {limit: 500}).length, 500);
});

test('status reports how the hook sits on each interface and whether the core left XDP', () => {
  const attachments = [
    {hook_id: 'wan-filter', engine: 'xdp', interface: 'eth0', status: 'attached', xdp_mode: 'driver'},
    {hook_id: 'wan-filter', engine: 'xdp', interface: 'wg0', status: 'attached', xdp_mode: 'generic'},
    {hook_id: 'wan-filter', engine: 'xdp', interface: 'vmbr0', status: 'attached', xdp_mode: 'tc'},
    {hook_id: 'other', engine: 'xdp', interface: 'eth1', status: 'attached', xdp_mode: 'driver'},
  ];
  const host = makeHost({policies: {ssh: SSH}, settings: {default: {data: {...SETTINGS.data, interfaces: ['eth0', 'eth1', 'vmbr0', 'wg0']}}}}, {
    adapters: {'plugin.attachments': () => ({attachments})},
    hostInfo: {kernel_engine_order: ['xdp', 'tc'], core_engine_pinned_to_tc: true},
  });
  host.action('apply', {});
  const st = host.action('status', {});
  assert.deepEqual(st.attachments, {error: '', reason: '', interfaces: [
    {interface: 'eth0', attached: true, mode: 'driver', error: '', egress: false},
    {interface: 'eth1', attached: false, mode: '', error: '', egress: false},
    {interface: 'vmbr0', attached: true, mode: 'tc', error: '', egress: false},
    {interface: 'wg0', attached: true, mode: 'generic', error: '', egress: false},
  ]});
  assert.deepEqual(st.core, {engine_order: ['xdp', 'tc'], prefers_xdp: true, pinned_to_tc: true});
});

test('the hook carries a TC fallback and, where the host has them, a TC egress program from the same object', () => {
  const host = makeHost({});
  const hook = host.surface.hooks.find((item) => item.id === 'wan-filter');
  assert.equal(hook.engine, 'xdp');
  assert.equal(hook.program, 'firewall:filter');
  assert.equal(hook.tc_fallback, 'firewall:filter_tc');
  assert.equal(hook.tc_egress, 'firewall:track');
  const object = host.surface.objects.find((item) => item.id === 'firewall');
  assert.deepEqual(object.programs.map((p) => [p.id, p.section, p.type]), [
    ['filter', 'xdp/veer/firewall', 'xdp'],
    ['filter_tc', 'tc/veer/firewall', 'tc'],
    ['track', 'tc/veer/firewall_egress', 'tc'],
  ]);
  // An older host: no egress program on the hook, and connection tracking is refused.
  const old = makeHost({settings: {default: {data: {interfaces: ['eth0'], connection_tracking: true}}}},
    {availableFeatures: ['dataplane.xdp_pipeline.v1', 'dataplane.xdp_tc_fallback.v1']});
  assert.equal(old.surface.hooks.find((item) => item.id === 'wan-filter').tc_egress, undefined);
  assert.match(old.action('check', {}).errors.join(), /不支持连接跟踪/);
});

test('an apply the host cannot attach is undone; status passes the error on', () => {
  let failure = '';
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}}, {
    adapters: {'plugin.attachments': () => ({error: failure})},
    hostInfo: {kernel_engine_order: ['tc', 'xdp'], core_engine_pinned_to_tc: true},
  });
  host.action('apply', {});
  host.action('confirm', {});
  const confirmedGeneration = cfg(host).generation;
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  failure = 'eth0 already runs another XDP program';
  assert.throws(() => host.action('apply', {}), /没能挂载到接口.*another XDP program/);
  assert.equal(state(host).pending, null);
  assert.equal(state(host).rollback_reason, 'attach_failed');
  assert.equal(cfg(host).generation, confirmedGeneration, 'back on the confirmed rules');
  assert.equal(keysOf(host, 'fw_ports', cfg(host).generation).length, 1);
  const st = host.action('status', {});
  assert.equal(st.attachments.error, 'eth0 already runs another XDP program');
  assert.deepEqual(st.attachments.interfaces, [{interface: 'eth0', attached: false, mode: '', error: '', egress: false}]);
  assert.deepEqual(st.core, {engine_order: ['tc', 'xdp'], prefers_xdp: false, pinned_to_tc: false});
});

function setRecord(elements, extra = {}) {
  return {data: {elements, ...extra}, enabled: true};
}

function setEntries(host) {
  return [...map(host, 'fw_sets').entries()].map(([key, value]) => ({...c.decodeSetKey(key), kind: c.decodeSetValue(value).kind}))
    .sort((a, b) => (a.id - b.id) || a.cidr.localeCompare(b.cidr));
}

test('sets reach fw_sets with apply; removed elements and sets leave after the flip', () => {
  const host = makeHost({
    policies: {ssh: policy({name: 'SSH', ports: ['22'], sources: [{set: 'office', action: 'allow'}]})},
    sets: {office: setRecord(['203.0.113.0/24', '2001:db8::/32']), deny: setRecord(['198.51.100.7'])},
    settings: {default: {data: {...SETTINGS.data, blocklists: ['deny']}}},
  });
  host.action('apply', {});
  const ids = state(host).set_ids;
  assert.deepEqual(Object.keys(ids).sort(), ['deny', 'office']);
  assert.deepEqual(setEntries(host).map((e) => [e.id, e.cidr, e.kind]), [
    [ids.deny, '198.51.100.7/32', 'static'],
    [ids.office, '2001:db8::/32', 'static'],
    [ids.office, '203.0.113.0/24', 'static'],
  ].sort((a, b) => (a[0] - b[0]) || a[1].localeCompare(b[1])));
  // The blocklist and the policy's source set are in the generation.
  const gcfg = map(host, 'fw_gcfg').get(c.u32le(cfg(host).generation));
  assert.equal(gcfg.substr(12, 2), '01');
  assert.equal(gcfg.substr(16, 4), c.u16le(ids.deny));
  const pext = map(host, 'fw_pext').get(c.u32le(cfg(host).generation * 256 + state(host).slots.ssh));
  assert.equal(pext.substr(2, 2), '01');
  host.action('confirm', {});

  // Drop the IPv6 element and the deny set.
  host.state.resources.get('sets').set('office', {key: 'office', data: {elements: ['203.0.113.0/24']}, enabled: true, revision: 2});
  host.state.resources.get('sets').delete('deny');
  host.state.resources.get('settings').set('default', {key: 'default', data: SETTINGS.data, enabled: true, revision: 2});
  host.action('apply', {});
  assert.deepEqual(setEntries(host).map((e) => [e.id, e.cidr]), [[ids.office, '203.0.113.0/24']]);
  assert.equal(state(host).set_ids.office, ids.office, 'the set keeps its id');
});

test('a policy may not name a set the draft lacks, nor a blocklist', () => {
  const host = makeHost({
    policies: {ssh: policy({name: 'SSH', ports: ['22'], sources: [{set: 'office', action: 'allow'}]})},
    settings: {default: {data: {...SETTINGS.data, blocklists: ['deny']}}},
  });
  const errors = host.action('check', {}).errors.join('；');
  assert.match(errors, /引用的集合不存在: office/);
  assert.match(errors, /黑名单引用的集合不存在: deny/);
});

test('set_add, set_list, set_del and set_flush change an applied set at once', () => {
  let mono = 1000000;
  const host = makeHost({policies: {ssh: SSH}, sets: {scanners: setRecord(['192.0.2.0/24'])}, settings: {default: SETTINGS}}, {
    adapters: {'ebpf.monotonicMs': () => mono},
  });
  assert.throws(() => host.action('set_add', {set: 'scanners', elements: ['198.51.100.1']}), /已应用的集合/);
  host.action('apply', {});
  host.action('confirm', {});
  assert.deepEqual(host.action('set_add', {set: 'scanners', elements: ['198.51.100.1', '192.0.2.0/24'], timeout_seconds: 60}), {added: 1});
  assert.deepEqual(host.action('set_add', {set: 'scanners', elements: '2001:db8::5'}), {added: 1});
  const list = host.action('set_list', {set: 'scanners'});
  assert.deepEqual(list.items.map((i) => [i.cidr, i.kind, i.remaining_seconds]).sort(), [
    ['192.0.2.0/24', 'static', null],
    ['198.51.100.1/32', 'api', 60],
    ['2001:db8::5/128', 'api', null],
  ]);
  // A cold start loses fw_sets; the next reconcile restores the set_add elements from KV.
  host.state.maps.clear();
  host.reconcile();
  assert.deepEqual(setEntries(host).map((e) => [e.cidr, e.kind]).sort(), [
    ['192.0.2.0/24', 'static'], ['198.51.100.1/32', 'api'], ['2001:db8::5/128', 'api'],
  ]);
  assert.deepEqual(host.action('set_del', {set: 'scanners', elements: ['2001:db8::5', '192.0.2.0/24']}), {removed: 1});
  // Expired elements leave with the prune timer.
  assert.ok(host.snapshot().timers.some((t) => t.name === 'set_prune'));
  mono += 61000;
  host.fireTimer('set_prune');
  assert.deepEqual(setEntries(host).map((e) => e.cidr), ['192.0.2.0/24']);
  host.action('set_add', {set: 'scanners', elements: ['198.51.100.2']});
  assert.deepEqual(host.action('set_flush', {set: 'scanners'}), {removed: 1});
  assert.deepEqual(setEntries(host).map((e) => e.cidr), ['192.0.2.0/24']);
  assert.throws(() => host.action('set_add', {set: 'scanners', elements: ['1.2.3.4'], timeout_seconds: -1}), /timeout_seconds/);
});

test('connection tracking turns on the egress program and the generation flag, and needs it attached', () => {
  let attachments = [
    {hook_id: 'wan-filter', engine: 'xdp', attach: 'ingress', interface: 'eth0', status: 'attached', xdp_mode: 'driver'},
  ];
  const host = makeHost({
    policies: {all: policy({name: 'all', protocol: 'any'})},
    settings: {default: {data: {...SETTINGS.data, connection_tracking: true}}},
  }, {adapters: {'plugin.attachments': () => ({attachments})}});
  // Catch-all drop with tracking: only the lockout warning is left, and trusted sources clear it.
  assert.deepEqual(host.action('check', {}).warnings, []);
  assert.throws(() => host.action('apply', {}), /出向程序没挂上 eth0/);
  assert.equal(state(host).rollback_reason, 'attach_failed');
  // Nothing was confirmed yet: the rollback unbinds.
  assert.deepEqual(host.state.resources.get('hook_bindings').get('wan-filter').data, {hook_id: 'wan-filter', interfaces: [], tc_egress: false});
  attachments = attachments.concat([{hook_id: 'wan-filter', engine: 'xdp', attach: 'egress', interface: 'eth0', status: 'attached', xdp_mode: 'tc'}]);
  host.action('apply', {});
  assert.deepEqual(host.state.resources.get('hook_bindings').get('wan-filter').data, {hook_id: 'wan-filter', interfaces: ['eth0'], tc_egress: true});
  const gcfg = map(host, 'fw_gcfg').get(c.u32le(cfg(host).generation));
  assert.equal(parseInt(gcfg.substr(0, 2), 16) & 1, 1);
  assert.notEqual(gcfg.substr(8, 4), '0000', 'the catch-all class');
  const st = host.action('status', {});
  assert.deepEqual(st.connection_tracking, {available: true, enabled: true});
  assert.deepEqual(st.attachments.interfaces, [{interface: 'eth0', attached: true, mode: 'driver', error: '', egress: true}]);
});

test('a reconcile over kept maps fixes a 1.0 binding and leaves a pending prune alone', () => {
  const host = makeHost({
    policies: {ssh: policy({name: 'SSH', ports: ['22'], add_to_set: {set: 'scanners'}})},
    sets: {scanners: setRecord([])},
    settings: {default: SETTINGS},
  });
  host.action('apply', {});
  host.action('confirm', {});
  // 1.0 wrote no tc_egress, which the host takes as on.
  host.state.resources.get('hook_bindings').set('wan-filter', {key: 'wan-filter', data: {hook_id: 'wan-filter', interfaces: ['eth0']}, enabled: true, revision: 1});
  const prune = host.state.timers.get('set_prune');
  assert.ok(prune, 'apply arms the prune timer');
  prune.delay_ms = 1234; // tells a re-armed timer apart
  host.reconcile();
  assert.deepEqual(host.state.resources.get('hook_bindings').get('wan-filter').data, {hook_id: 'wan-filter', interfaces: ['eth0'], tc_egress: false});
  assert.equal(host.state.timers.get('set_prune').delay_ms, 1234, 'a pending prune is not pushed back');
  // A new process has no timers: the reconcile arms it again.
  host.state.timers.clear();
  host.reconcile();
  assert.equal(host.state.timers.get('set_prune').delay_ms, 60000);
});

test('baseline settings set generation flags and write the bogon prefixes', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: {data: {...SETTINGS.data,
    baseline: {bogon_sources: 'all', invalid_tcp_flags: true, drop_fragments: true, urpf: 'strict'}}}}});
  const checked = host.action('check', {});
  assert.deepEqual(checked.warnings.map((w) => w.id), ['urpf_strict']);
  host.action('apply', {accept_warnings: checked.token});
  const gcfg = map(host, 'fw_gcfg').get(c.u32le(cfg(host).generation));
  assert.equal(parseInt(gcfg.substr(0, 2), 16), 2 | 4 | 8 | 32);
  const bogons = setEntries(host).filter((e) => e.id === c.SET_BOGON);
  assert.equal(bogons.length, c.BOGONS_RESERVED.length + c.BOGONS_PRIVATE.length);
  assert.ok(bogons.some((e) => e.cidr === '10.0.0.0/8'));
  host.action('confirm', {});
  // Back to reserved only: the private prefixes leave.
  host.state.resources.get('settings').set('default', {key: 'default', data: {...SETTINGS.data, baseline: {bogon_sources: 'reserved'}}, enabled: true, revision: 2});
  host.action('apply', {});
  assert.equal(setEntries(host).filter((e) => e.id === c.SET_BOGON).length, c.BOGONS_RESERVED.length);
});

test('status reports the global counters', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: SETTINGS}}, {
    counters: (key) => [c.u32le(parseInt(key.substr(0, 2), 16) + 1) + '00000000'],
  });
  host.action('apply', {});
  const st = host.action('status', {});
  assert.equal(st.global.established, 1);
  assert.equal(st.global.blocklist, 4);
  assert.deepEqual(Object.keys(st.global), c.GCOUNTERS);
});

test('blocklist drops name their set', () => {
  const host = makeHost({sets: {deny: setRecord(['198.51.100.7'])}, settings: {default: {data: {...SETTINGS.data, blocklists: ['deny']}}}});
  host.action('apply', {});
  const id = state(host).set_ids.deny;
  host.ring('drop_log', [eventHex(id, 5, 2, 'c6336407')]);
  const [event] = host.action('events', {});
  assert.equal(event.reason, 'blocklist');
  assert.equal(event.set, 'deny');
  assert.equal(event.policy, null);
});
