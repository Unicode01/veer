'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const {createTestHost} = require('../../sdk/plugin/test-host.cjs');
const c = require('./lib/compile.js');

const LINKS = {
  eth0: {name: 'eth0', ifindex: 2, kind: 'device', mac: '02:00:00:00:00:02', up: true},
  eth1: {name: 'eth1', ifindex: 3, kind: 'device', mac: '02:00:00:00:00:03', up: true},
  wg0: {name: 'wg0', ifindex: 5, kind: 'wireguard', mac: '', up: true},
};

function policy(data) {
  return {data: {protocol: 'tcp', default_action: 'drop', ...data}, enabled: true};
}

function makeHost(resources, options = {}) {
  const host = createTestHost({
    pluginDir: path.join(__dirname),
    fixtures: {resources},
    adapters: {
      'net.link.get': (name) => LINKS[name],
      'net.link.list': () => Object.values(LINKS),
      'ebpf.mapGetPerCPU': (object, map, key) => (options.counters ? options.counters(key) : ['0000000000000000']),
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
  assert.deepEqual(bindings.data, {hook_id: 'wan-filter', interfaces: ['eth0']});
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

test('an L3 interface is marked so the program skips Ethernet parsing', () => {
  const host = makeHost({policies: {ssh: SSH}, settings: {default: {data: {interfaces: ['eth0', 'wg0']}}}});
  host.action('apply', {});
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
  assert.deepEqual(status.policies, [{key: 'ssh', name: 'SSH', slot: 1, counters: {pass: 7, drop: 7, trusted: 7}}]);
  assert.equal(status.draft_changed, false);
  setPolicy(host, 'web', {name: 'web', ports: ['8443']});
  assert.equal(host.action('status', {}).draft_changed, true);
});

test('interfaces lists bindable links and flags L3 ones', () => {
  const host = makeHost({});
  const list = host.action('interfaces', {});
  assert.deepEqual(list.map((l) => [l.name, l.l3]), [['eth0', false], ['eth1', false], ['wg0', true]]);
});
