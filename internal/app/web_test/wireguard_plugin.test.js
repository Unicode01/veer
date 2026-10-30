'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const test = require('node:test');
const {createTestHost} = require('../../../sdk/plugin/test-host.cjs');
const pluginDir = path.resolve(__dirname, '../../../plugins/wireguard_mesh');
const PRIVATE = Buffer.alloc(32, 1).toString('base64');
const PUBLIC = Buffer.alloc(32, 2).toString('base64');
const clone = v => JSON.parse(JSON.stringify(v));
function profile(extra = {}) {
  return {slot: 1, addresses: ['10.77.0.1/32'], peers: [{public_key: PUBLIC, endpoint: '192.0.2.2:51820', allowed_ips: ['0.0.0.0/0']}],
    bindings: [{lan_interface: 'br-lan', source: '192.168.10.20/32', destination: '0.0.0.0/0'}], masquerade: true, ...extra};
}
// Persisted kernel state, rather than only assertions about command strings.
function fixture(config = profile(), options = {}) {
  const state = {links: [{ifname: 'br-lan', ifindex: 2, addr_info: [{local: '192.168.10.1', prefixlen: 24, scope: 'global'}]}],
    routes: [], rules: [], tables: {}, calls: [], config: '', fail: null, filters: {}, sysctls: {}, ...options.state};
  const ok = (stdout = '') => ({stdout, stderr: '', exit_code: 0, timed_out: false, cancelled: false, truncated: false});
  const error = stderr => ({...ok(), stderr, exit_code: 2});
  const exec = request => {
    state.calls.push(clone(request));
    if (state.fail && state.fail(request)) return error('input was ' + PRIVATE);
    const a = request.args;
    if (request.command.endsWith('/sysctl')) return ok(a[0] === '-n' ? (state.sysctls[a[1]] ?? (a[1].endsWith('rp_filter') ? '2' : '1')) : '');
    if (request.command.endsWith('/tc')) return ok(JSON.stringify(state.filters[a[a.indexOf('dev') + 1]] || []));
    if (request.command.endsWith('/wg')) {
      if (a[0] === 'pubkey') return ok(PUBLIC + '\n');
      if (a[0] === 'syncconf') { state.config = request.stdin; return ok(); }
      assert.notEqual(a[2], 'dump'); assert.notEqual(a[2], 'private-key');
      return ok(a[2] === 'public-key' ? PUBLIC : 'peer\t123');
    }
    if (request.command.endsWith('/nft')) {
      if (a[0] === '-j') {
        const table = state.tables[a[4]];
        return table ? ok(JSON.stringify({nftables: [{table:state.legacyNftJSON ? {name:table.name} : table}]})) : error('No such file or directory');
      }
      if (a[0] === 'list') {
        const table = state.tables[a[3]];
        return ok(table.text || 'table inet '+table.name+' {\n\tcomment "'+table.comment+'"\n\tchain forward {\n\t}\n}\n');
      }
      if (a[0] === 'delete') { delete state.tables[a[3]]; return ok(); }
      const match = /add table inet (\w+) \{ comment "([^"]+)"/.exec(request.stdin);
      assert.ok(match, request.stdin);
      state.tables[match[1]] = {name: match[1], comment: match[2], rules: request.stdin};
      return ok();
    }
    assert.match(request.command, /\/ip$/);
    const family = a.includes('-6') ? '6' : '4';
    const args = a.filter(v => !['-j', '-4', '-6', '-d'].includes(v));
    const field = key => args[args.indexOf(key) + 1];
    if (args[0] === 'link') {
      if (args[1] === 'show') return ok(JSON.stringify(state.links));
      if (args[1] === 'add') {
        assert.equal(state.links.some(v => v.ifname === field('name')), false);
        state.links.push({ifname: field('name'), ifindex: 3, addr_info: []});
      }
      if (args[1] === 'set' && args.includes('alias')) state.links.find(v => v.ifname === field('dev')).ifalias = field('alias');
      if (args[1] === 'del') { state.links = state.links.filter(v => v.ifname !== field('dev')); state.routes = state.routes.filter(v => v.dev !== field('dev')); }
      return ok();
    }
    if (args[0] === 'address') {
      const link = state.links.find(v => v.ifname === field('dev'));
      if (args[1] === 'show') return ok(JSON.stringify(link ? [link] : []));
      const [local, prefixlen] = args[2].split('/');
      link.addr_info = link.addr_info.filter(v => v.local !== local);
      if (args[1] === 'replace') link.addr_info.push({local, prefixlen: Number(prefixlen), scope: 'global'});
      return ok();
    }
    if (args[0] === 'route') {
      if (args[1] === 'show') return ok(JSON.stringify(state.routes.filter(v => v.family === family && v.table === Number(field('table')))));
      const special = ['throw', 'unreachable'].includes(args[2]);
      const r = {family, type: special ? args[2] : 'unicast', dst: args[special ? 3 : 2], table: Number(field('table')),
        metric: Number(field('metric')), protocol: field('proto'), ...(special ? (family === '6' ? {dev:'lo'} : {}) : {dev: field('dev')})};
      state.routes = state.routes.filter(v => !(v.family === r.family && v.table === r.table && v.dst === r.dst && v.metric === r.metric));
      if (args[1] === 'replace') state.routes.push(r);
      return ok();
    }
    if (args[0] === 'rule') {
      if (args[1] === 'show') return ok(JSON.stringify(state.rules.filter(v => v.family === family)));
      const [src, srclen] = field('from').split('/'), [dst, dstlen] = field('to').split('/');
      const r = {family, priority: Number(field('priority')), src, srclen:Number(srclen), dst, dstlen:Number(dstlen), iif: field('iif'), table: Number(field('table')), protocol: field('protocol')};
      const same = v => JSON.stringify(v) === JSON.stringify(r);
      if (args[1] === 'add') { assert.equal(state.rules.some(same), false, 'duplicate rule'); state.rules.push(r); }
      if (args[1] === 'del') state.rules = state.rules.filter(v => !same(v));
      return ok();
    }
    assert.fail('unmodelled command: ' + a.join(' '));
  };
  const host = createTestHost({pluginDir, remoteInstallEnabled: options.remoteInstallEnabled,
    fixtures: {kv: options.kv || {}, resources: {profiles: {default: {data: config, enabled: true}}}, secrets: options.missingKey ? {} : {private_default: PRIVATE}},
    adapters: {'process.exec': exec}}).load();
  return {host, state, apply: () => host.action('apply', {key: 'default'})};
}
test('WireGuard example is lab-only; a saved draft and registration do not execute commands', () => {
  const {host, state} = fixture(); host.reconcile();
  assert.equal(state.calls.length, 0);
  assert.equal(host.snapshot().manifest.stability, 'lab');
  assert.deepEqual(host.snapshot().manifest.compatibility.os, ['linux']);
  assert.equal(host.snapshot().surface.ui.page, 'wireguard');
  assert.throws(() => fixture(profile(), {remoteInstallEnabled: true}).apply(), /disabled while remote/);
});
test('WG applies scoped routing, NAT, guards, secret stdin, public status and exact teardown', () => {
  const {host, state, apply} = fixture();
  host.action('set_key', {key: 'default', value: PRIVATE});
  assert.equal(apply().phase, 'applied');
  assert.equal(state.rules.length, 1);
  assert.equal(state.rules[0].iif, 'br-lan');
  assert.equal(state.rules[0].src, '192.168.10.20');
  assert.equal(state.rules[0].srclen, 32);
  assert.ok(state.routes.some(v => v.type === 'unreachable'));
  assert.ok(state.routes.some(v => v.type === 'throw' && v.dst === '192.168.10.0/24'));
  assert.match(state.tables.veer_wg_1.rules, /oifname != "vwgdefault" reject/);
  assert.match(state.tables.veer_wg_1.rules, /masquerade/);
  assert.match(state.config, new RegExp('PrivateKey = ' + PRIVATE));
  assert.equal(state.calls.some(v => v.args.some(a => a.includes(PRIVATE))), false);
  assert.equal(host.snapshot().secrets.private_default, '[REDACTED]');
  assert.equal(host.action('inspect', {key: 'default'}).public_key, PUBLIC);
  apply(); assert.equal(state.rules.length, 1, 'reapplying does not duplicate rules');
  state.routes.push({family: '4', table: 999, dst: '198.51.100.0/24', protocol: 'static'});
  host.action('teardown', {key: 'default'});
  assert.equal(state.rules.length, 0); assert.equal(state.routes.length, 1);
  assert.equal(state.links.some(v => v.ifname === 'vwgdefault'), false);
  assert.deepEqual(state.tables, {});
  assert.equal(host.snapshot().kv.lease_default, undefined);
});
test('WG mesh preserves source addresses and accepts explicit IPv6 device selectors', () => {
  const {state, apply} = fixture(profile({addresses: ['fd77::1/128'], masquerade: false,
    peers: [{public_key: PUBLIC, endpoint: '[2001:db8::2]:51820', allowed_ips: ['fd88::/64']}],
    bindings: [{lan_interface: 'br-lan', source: 'fd10::20/128', destination: 'fd88::/64'}]}));
  apply(); assert.equal(state.rules[0].family, '6');
  assert.equal(state.tables.veer_wg_1.rules.includes('masquerade'), false);
  assert.match(state.tables.veer_wg_1.rules, /ip6 saddr/);
  assert.ok(state.routes.some(v => v.family === '6' && v.type === 'unreachable'));
});
test('WG refuses invalid addresses, endpoint/config injection, uncovered destinations and low IPv6 MTU before exec', () => {
  for (const source of ['192.168.1.999/32', '192.168.1.1/33', '192.168.01.1/24', '192.168.1.1\nPostUp=evil', 'fd00:::1/64', 'fd00::1/129', ':1:2:3:4:5:6:7/64']) {
    const h = fixture(profile({bindings: [{lan_interface: 'br-lan', source, destination: '0.0.0.0/0'}]}));
    assert.throws(h.apply); assert.equal(h.state.calls.length, 0);
  }
  for (const change of [
    {peers: [{public_key: PUBLIC, endpoint: 'host.invalid:51820', allowed_ips: ['0.0.0.0/0']}]},
    {peers: [{public_key: PUBLIC, endpoint: '1.2.3.4:51820\nPostUp=evil', allowed_ips: ['0.0.0.0/0']}]},
    {peers: [{public_key: PUBLIC, allowed_ips: ['10.0.0.0/8']}]},
    {mtu: 1000, peers: [{public_key: PUBLIC, allowed_ips: ['::/0']}], bindings: [{lan_interface: 'br-lan', source: 'fd00::/64', destination: '::/0'}]}
  ]) { const h = fixture(profile(change)); assert.throws(h.apply); assert.equal(h.state.calls.length, 0); }
});
test('WG refuses foreign interfaces, nft tables, route tables and policy-rule collisions without mutations', () => {
  for (const change of [
    {links: [{ifname: 'vwgdefault', ifalias: 'someone-else'}]},
    {tables: {veer_wg_1: {name: 'veer_wg_1', comment: 'someone-else'}}},
    {routes: [{family: '4', table: 52001, dst: '0.0.0.0/0', protocol: 'static'}]},
    {rules: [{family: '4', priority: 22032, table: 254, protocol: 'static'}]}
  ]) {
    const h = fixture(profile(), {state: change}); assert.throws(h.apply);
    assert.equal(h.state.calls.some(v => ['add', 'replace', 'del', 'syncconf', '-f', '-w'].some(w => v.args.includes(w))), false);
  }
});
test('WG detects fast-path forwarding on the LAN, bridge members, XDP and host forwarding prerequisites', () => {
  for (const state of [
    {filters: {'br-lan': [{kind: 'bpf'}]}},
    {links: [{ifname: 'br-lan', ifindex: 2, addr_info: []}, {ifname: 'tap100i0', ifindex: 5, master: 'br-lan'}], filters: {tap100i0: [{kind: 'bpf'}]}},
    {links: [{ifname: 'br-lan', ifindex: 2, addr_info: [], xdp: {attached: 'generic'}}]},
    {sysctls: {'net.ipv4.ip_forward': '0'}}, {sysctls: {'net.ipv4.conf.all.rp_filter': '1'}}
  ]) { const h = fixture(profile(), {state}); assert.throws(h.apply, /conflict|forward|rp_filter/); assert.equal(h.state.tables.veer_wg_1, undefined); }
});
test('WG validates missing secrets before host mutations and never propagates key-containing command stderr', () => {
  const missing = fixture(profile(), {missingKey: true}); assert.throws(missing.apply, /key/);
  assert.equal(missing.state.tables.veer_wg_1, undefined);
  const h = fixture(); h.state.fail = r => r.args[0] === 'syncconf';
  assert.throws(h.apply, e => !e.message.includes(PRIVATE) && /failed/.test(e.message));
  assert.match(h.state.tables.veer_wg_1.rules, /daddr 0.0.0.0\/0 reject/);
  assert.equal(h.state.rules.length, 0);
  h.state.fail = null; h.apply(); assert.equal(h.state.rules.length, 1);
});
test('WG recovers a partially applied policy, and rejects editing an unrecovered pending configuration', () => {
  const h = fixture();
  h.state.fail = r => r.command.endsWith('/nft') && r.args[0] === '-f' && r.stdin.includes('masquerade');
  assert.throws(h.apply); assert.equal(h.state.rules.length, 1);
  const edited = fixture(profile({slot: 2}), {state: h.state, kv: h.host.snapshot().kv});
  assert.throws(edited.apply, /Retry.*teardown/);
  h.host.run('onAction', {action: {id: 'inspect'}, payload: {key: 'default'}});
  h.state.fail = null; h.apply(); assert.equal(h.state.rules.length, 1);
  h.state.links = h.state.links.filter(v => v.ifname !== 'vwgdefault');
  assert.equal(h.host.action('inspect', {key: 'default'}).phase, 'missing');
  assert.ok(h.state.routes.some(v => v.type === 'unreachable'));
  assert.match(h.state.tables.veer_wg_1.rules, /oifname != "vwgdefault" reject/);
});
test('WG reconnect restores the applied settings, not edited drafts, and deactivation cleans all owned state', () => {
  const h = fixture(); h.apply();
  const snapshot = h.host.snapshot();
  assert.equal(snapshot.kv.lease_default.settings.slot, 1);
  // Updating drafts does not change the active slot across restart/reconcile.
  const restarted = fixture(profile({slot: 2}), {state: h.state, kv: snapshot.kv});
  restarted.host.reconcile(); assert.equal(restarted.state.rules.length, 1);
  assert.equal(restarted.state.rules[0].table, 52001);
  restarted.host.run('onDeactivate'); assert.equal(restarted.state.rules.length, 0); assert.deepEqual(restarted.state.tables, {});
});

test('WG reserves slots and rejects overlapping selectors across profiles while allowing separate devices', () => {
  const original = fixture(); original.apply();
  const lease = clone(original.host.snapshot().kv.lease_default);
  lease.plan.key = 'other'; lease.plan.interface = 'vwgother';
  const reserved = fixture(profile(), {kv:{lease_other:lease}});
  assert.throws(reserved.apply, /Slot is already reserved/);
  const overlapping = fixture(profile({slot:2}), {kv:{lease_other:lease}});
  assert.throws(overlapping.apply, /selectors overlap/);
  assert.equal(overlapping.state.tables.veer_wg_2, undefined);
  const separate = fixture(profile({slot:2, bindings:[{lan_interface:'br-lan', source:'192.168.10.30/32', destination:'0.0.0.0/0'}]}), {kv:{lease_other:lease}});
  assert.equal(separate.apply().table, 52002);
});

test('WG refuses same-protocol foreign routes and preserves them during teardown', () => {
  const h = fixture(); h.apply();
  const foreign = {family:'4', table:52001, dst:'198.51.100.0/24', protocol:'242', metric:10, dev:'wan'};
  h.state.routes.push(foreign);
  const calls = h.state.calls.length;
  assert.throws(h.apply, /foreign routes/);
  assert.equal(h.state.calls.slice(calls).some(v => v.args.includes('del') || v.args.includes('-f')), false);
  h.host.action('teardown', {key:'default'});
  assert.deepEqual(h.state.routes, [foreign]);
});

test('WG handles old nft JSON without table comments and refuses nested or foreign ownership markers', () => {
  const h = fixture(profile(), {state:{legacyNftJSON:true}});
  h.apply(); h.apply(); assert.equal(h.state.rules.length,1);
  h.host.action('teardown',{key:'default'}); assert.deepEqual(h.state.tables,{});
  for (const text of [
    'table inet veer_wg_1 {\n\tchain forward {\n\t\tcomment "veer:wireguard_mesh:default"\n\t}\n}\n',
    'table inet veer_wg_1 {\n\tcomment "someone-else"\n}\n',
    'table inet wrong_table {\n\tcomment "veer:wireguard_mesh:default"\n}\n'
  ]) {
    const foreign=fixture(profile(),{state:{legacyNftJSON:true,tables:{veer_wg_1:{name:'veer_wg_1',text}}}});
    assert.throws(foreign.apply,/owned by another/);
    assert.equal(foreign.state.calls.some(v => v.args.includes('-f')),false);
  }
});
