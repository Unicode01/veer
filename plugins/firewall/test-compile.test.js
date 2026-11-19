'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const c = require('./lib/compile.js');

test('parseCIDR normalizes IPv4, IPv6 and IPv4-mapped prefixes', () => {
  const cases = [
    ['10.1.2.3/8', 4, 8, '10.0.0.0/8', '0a000000'],
    ['192.0.2.10', 4, 32, '192.0.2.10/32', 'c000020a'],
    ['2001:db8::1/64', 6, 64, '2001:db8::/64', '20010db8000000000000000000000000'],
    ['::1', 6, 128, '::1/128', '00000000000000000000000000000001'],
    ['::ffff:1.2.3.0/120', 4, 24, '1.2.3.0/24', '01020300'],
    ['64:ff9b::1.2.3.4', 6, 128, '64:ff9b::102:304/128', '0064ff9b000000000000000001020304'],
    ['1:2:3:4:5:6:1.2.3.4', 6, 128, '1:2:3:4:5:6:102:304/128', '00010002000300040005000601020304'],
    ['::/0', 6, 0, '::/0', '00000000000000000000000000000000'],
  ];
  for (const [input, family, prefix, text, hex] of cases) {
    const got = c.parseCIDR(input);
    assert.equal(got.family, family, input);
    assert.equal(got.prefix, prefix, input);
    assert.equal(got.text, text, input);
    assert.equal(c.bytesHex(got.bytes), hex, input);
  }
  for (const bad of ['1.2.3', '1.2.3.4/33', '01.2.3.4', '::1::2', '1:2:3:4:5:6:7:8:9', 'g::1', '', '1.2.3.4/x']) {
    assert.throws(() => c.parseCIDR(bad), undefined, bad);
  }
});

test('cidrOverlap compares the shorter prefix only', () => {
  const p = c.parseCIDR;
  assert.equal(c.cidrOverlap(p('10.0.0.0/8'), p('10.1.0.0/16')), true);
  assert.equal(c.cidrOverlap(p('10.0.0.0/16'), p('10.1.0.0/16')), false);
  assert.equal(c.cidrOverlap(p('10.0.0.0/8'), p('::/0')), false);
  assert.equal(c.cidrOverlap(p('2001:db8::/32'), p('2001:db8:1::/48')), true);
});

test('port ranges merge and decompose into aligned prefixes', () => {
  assert.deepEqual(c.parsePortRanges(['22', '20-25', 80, '81'], 'p'), [[20, 25], [80, 81]]);
  assert.throws(() => c.parsePortRanges(['0'], 'p'));
  assert.throws(() => c.parsePortRanges(['10-5'], 'p'));
  assert.throws(() => c.parsePortRanges(['65536'], 'p'));
  assert.deepEqual(c.portPrefixes(22, 22), [{port: 22, prefix: 16}]);
  assert.deepEqual(c.portPrefixes(11100, 11200), [
    {port: 11100, prefix: 14}, {port: 11104, prefix: 11}, {port: 11136, prefix: 10}, {port: 11200, prefix: 16},
  ]);
  // Every port of 1-65535 is covered exactly once.
  let covered = 0;
  for (const pfx of c.portPrefixes(1, 65535)) covered += 1 << (16 - pfx.prefix);
  assert.equal(covered, 65535);
});

test('conflicting policies are reported, disjoint ones are not', () => {
  const pol = (key, data) => c.normalizePolicy(key, {ports: ['22'], ...data});
  assert.equal(c.findConflicts([pol('a', {}), pol('b', {protocol: 'udp'})]).length, 0);
  assert.equal(c.findConflicts([pol('a', {}), pol('b', {})]).length, 1);
  assert.equal(c.findConflicts([pol('a', {destinations: ['10.0.0.1']}), pol('b', {destinations: ['10.0.0.2']})]).length, 0);
  assert.equal(c.findConflicts([pol('a', {destinations: ['10.0.0.0/8']}), pol('b', {destinations: ['10.1.0.1']})]).length, 1);
  assert.equal(c.findConflicts([pol('a', {destinations: ['10.0.0.1']}), pol('b', {})]).length, 1);
  assert.equal(c.findConflicts([pol('a', {ports: ['1-100']}), pol('b', {ports: ['100-200']})]).length, 1);
  assert.throws(() => c.normalizePolicy('x', {ports: ['22'], protocol: 'icmp'}));
  assert.throws(() => c.normalizePolicy('x', {ports: ['22'], sources: [{cidr: '1.2.3.4', action: 'allow'}, {cidr: '1.2.3.4/32', action: 'drop'}]}));
});

test('slots stay with their policy and new policies avoid freed slots', () => {
  const first = c.assignSlots(['a', 'b', 'c'], {});
  assert.deepEqual(first.slots, {a: 1, b: 2, c: 3});
  assert.deepEqual(first.fresh, [1, 2, 3]);
  const second = c.assignSlots(['c', 'd'], first.slots);
  assert.equal(second.slots.c, 3);
  assert.equal(second.slots.d, 4); // 1 and 2 were held by deleted policies
  assert.deepEqual(second.fresh, [4]);
});

test('compileGeneration lays out the maps firewall.bpf.c reads', () => {
  const rdp = c.normalizePolicy('rdp', {protocol: 'tcp', ports: ['23390'], default_action: 'drop',
    sources: [{cidr: '203.0.113.0/24', action: 'allow'}]});
  rdp.slot = 1;
  const ssh = c.normalizePolicy('ssh', {protocol: 'tcp+udp', ports: ['22', '10022-10024'], destinations: ['198.51.100.7'],
    sources: [{cidr: '2001:db8::/32', action: 'allow'}]});
  ssh.slot = 2;
  const out = c.compileGeneration([rdp, ssh], [c.parseCIDR('192.0.2.10')], 1);
  assert.equal(out.active, true);
  // Port 22: word 0, bit 22, in generation 1 (index 2048) for TCP and 3072 for UDP.
  assert.equal(out.arrays.fw_port_bits[2048], '0000400000000000');
  assert.equal(out.arrays.fw_port_bits[3072], '0000400000000000');
  // 10022-10024: word 156, bits 38-40 (high half 0x1c0).
  assert.equal(out.arrays.fw_port_bits[2048 + 156], '00000000c0010000');
  // 23390 is TCP only.
  assert.equal(out.arrays.fw_port_bits[2048 + 365], '0000004000000000');
  assert.equal(out.arrays.fw_port_bits[3072 + 365], undefined);
  // Class 1: ports of ssh, scoped by destination; class 2: rdp for any destination.
  assert.equal(out.arrays.fw_class[1024 + 1], '00000100');
  assert.equal(out.arrays.fw_class[1024 + 2], '01000000');
  assert.equal(out.arrays.fw_policy[256 + 1], '01010000');
  assert.equal(out.arrays.fw_policy[256 + 2], '01010000');
  const ports = Object.fromEntries(out.lpm.fw_ports.map((e) => [e.key, e.value]));
  assert.equal(ports['2000000001000016'], '01000000');   // tcp 22/16 -> class 1
  assert.equal(ports['1f00000001002726'], '01000000');   // tcp 10022/15
  assert.equal(ports['2000000001005b5e'], '02000000');   // tcp 23390 -> class 2
  assert.equal(ports['2000000001010016'], '01000000');   // udp 22
  assert.deepEqual(out.lpm.fw_dst4, [{key: '4000000001000001c6336407', value: '02000000'}]);
  assert.deepEqual(out.lpm.fw_src4.sort((a, b) => a.key.localeCompare(b.key)), [
    {key: '3800000001000001cb007100', value: '00000000'},  // rdp: 203.0.113.0/24 allow
    {key: '4000000001000000c000020a', value: '00000000'},  // trusted 192.0.2.10
  ]);
  assert.deepEqual(out.lpm.fw_src6, [{key: '400000000100000220010db8000000000000000000000000', value: '00000000'}]);
  for (const map of Object.keys(out.lpm)) {
    for (const e of out.lpm[map]) assert.equal(c.keyGeneration(e.key), 1, map);
  }
});

test('an empty rule set is inactive and writes nothing', () => {
  const out = c.compileGeneration([], [], 0);
  assert.equal(out.active, false);
  assert.deepEqual(out.arrays, {fw_port_bits: {}, fw_class: {}, fw_policy: {}, fw_limit: {}});
  for (const map of Object.keys(out.lpm)) assert.equal(out.lpm[map].length, 0);
});

function dropPolicy(key, data) {
  return c.normalizePolicy(key, {protocol: 'tcp', default_action: 'drop', ...data});
}

test('warnings name drop policies that can lock out an administrator or drop replies', () => {
  const trusted = [c.parseCIDR('192.0.2.10')];
  const ids = (policies, t) => c.findWarnings(policies, t).map((w) => w.id);
  // Management ports, unless a trusted source still gets through.
  assert.deepEqual(ids([dropPolicy('ssh', {ports: ['22']})], []), ['lockout:ssh']);
  assert.deepEqual(ids([dropPolicy('ssh', {ports: ['22']})], trusted), []);
  assert.deepEqual(ids([dropPolicy('web', {ports: ['8000-8100']})], []), ['lockout:web']);
  assert.match(c.findWarnings([dropPolicy('web', {ports: ['8000-8100']})], [])[0].message, /8006.*8080/);
  assert.deepEqual(ids([dropPolicy('dns', {protocol: 'udp', ports: ['22']})], []), []);
  assert.deepEqual(ids([dropPolicy('open', {ports: ['22'], default_action: 'allow'})], []), []);
  // Reply ports: any port in the NAT pool, ranges in the ephemeral ports.
  assert.deepEqual(ids([dropPolicy('game', {ports: ['25565']})], trusted), ['reply_ports:game']);
  assert.deepEqual(ids([dropPolicy('wg', {protocol: 'udp', ports: ['51820']})], []), []);
  assert.deepEqual(ids([dropPolicy('high', {protocol: 'udp', ports: ['40000-40010']})], []), ['reply_ports:high']);
  assert.deepEqual(ids([dropPolicy('low', {ports: ['1000-19999']})], trusted), []);
  const all = c.findWarnings([dropPolicy('all', {ports: ['1-65535']})], []);
  assert.deepEqual(all.map((w) => w.id), ['lockout:all', 'reply_ports:all']);
  assert.match(all[1].message, /20000-32767 在 Veer 出向 NAT.*32768-60999 在宿主/);
});

test('the warnings token follows the warnings, not their order', () => {
  const one = c.findWarnings([dropPolicy('ssh', {ports: ['22']})], []);
  const two = c.findWarnings([dropPolicy('ssh', {ports: ['22']}), dropPolicy('game', {ports: ['25565']})], []);
  assert.equal(c.warningsToken([]), '');
  assert.match(c.warningsToken(one), /^[0-9a-f]{8}$/);
  assert.notEqual(c.warningsToken(one), c.warningsToken(two));
  assert.equal(c.warningsToken(two), c.warningsToken(two.slice().reverse()));
});

test('sumPerCPU adds little-endian u64 counters', () => {
  assert.equal(c.sumPerCPU(['0100000000000000', 'ff00000000000000', '0001000000000000']), 512);
  assert.equal(c.sumPerCPU(null), 0);
});

test('syn_limit is validated, defaulted and only allowed with tcp', () => {
  const pol = (limit, protocol = 'tcp') => c.normalizePolicy('p', {protocol, ports: ['22'], default_action: 'allow', syn_limit: limit});
  assert.deepEqual(pol({max_new: 20, window_seconds: 10}).synLimit, {maxNew: 20, windowSeconds: 10, banSeconds: 0, ipv6Prefix: 64});
  assert.deepEqual(pol({max_new: 5, window_seconds: 1, ban_seconds: 600, ipv6_prefix: 56}, 'tcp+udp').synLimit,
    {maxNew: 5, windowSeconds: 1, banSeconds: 600, ipv6Prefix: 56});
  assert.equal(pol(undefined).synLimit, null);
  assert.throws(() => pol({max_new: 5, window_seconds: 1}, 'udp'), /只限制 TCP/);
  assert.throws(() => pol({max_new: 0, window_seconds: 1}), /max_new/);
  assert.throws(() => pol({max_new: 5}), /window_seconds/);
  assert.throws(() => pol({max_new: 5, window_seconds: 1, ipv6_prefix: 16}), /ipv6_prefix/);
  assert.throws(() => pol({max_new: 1.5, window_seconds: 1}), /max_new/);
});

test('prefix masks cover whole and partial bytes', () => {
  assert.equal(c.prefixMaskHex(64), 'ff'.repeat(8) + '00'.repeat(8));
  assert.equal(c.prefixMaskHex(60), 'ff'.repeat(7) + 'f0' + '00'.repeat(8));
  assert.equal(c.prefixMaskHex(128), 'ff'.repeat(16));
  assert.equal(c.prefixMaskHex(32), 'ff'.repeat(4) + '00'.repeat(12));
});

test('a limited policy sets its flag and writes fw_limit', () => {
  const ssh = c.normalizePolicy('ssh', {protocol: 'tcp', ports: ['22'], default_action: 'allow', syn_limit: {max_new: 20, window_seconds: 10, ban_seconds: 300, ipv6_prefix: 60}});
  const web = c.normalizePolicy('web', {protocol: 'tcp', ports: ['443'], default_action: 'allow'});
  ssh.slot = 3;
  web.slot = 4;
  const out = c.compileGeneration([ssh, web], [], 1);
  assert.equal(out.arrays.fw_policy[256 + 3], '03000000');
  assert.equal(out.arrays.fw_policy[256 + 4], '01000000');
  assert.equal(out.arrays.fw_limit[256 + 3], c.u32le(20) + c.u32le(10) + c.u32le(300) + '3c000000' + c.prefixMaskHex(60));
  assert.equal(out.arrays.fw_limit[256 + 3].length, c.LIMIT_VALUE_ZERO.length);
  assert.equal(out.arrays.fw_limit[256 + 4], undefined);
  assert.equal(out.summary.syn_limited, 1);
});

function limitKeyHex(family, prefix, slot, addrHex) {
  return c.u8(family) + c.u8(prefix) + c.u16le(slot) + (addrHex + '0'.repeat(32)).slice(0, 32);
}

test('ban keys, ban ends and drop events decode', () => {
  assert.deepEqual(c.decodeLimitKey(limitKeyHex(4, 32, 3, 'cb007105')), {family: 4, prefix: 32, slot: 3, source: '203.0.113.5/32'});
  assert.deepEqual(c.decodeLimitKey(limitKeyHex(6, 64, 1, '20010db8000000010000000000000000')), {family: 6, prefix: 64, slot: 1, source: '2001:db8:0:1::/64'});
  assert.equal(c.decodeLimitKey('00'.repeat(20)), null);
  assert.equal(c.decodeBanUntilMs('00f2052a01000000'), 5000);

  const ev = c.u32le(2000000) + c.u32le(0) + c.u32le(7) + c.u16le(3) + c.u8(3) + c.u8(4) + c.u8(0) + '00' +
    '9c40' + '0016' + '0000' + ('cb007105' + '0'.repeat(32)).slice(0, 32) + ('0a000001' + '0'.repeat(32)).slice(0, 32);
  assert.equal(ev.length, c.EVENT_BYTES * 2);
  assert.deepEqual(c.decodeEvent(ev), {time_ms: 2, ifindex: 7, slot: 3, reason: 'rate', protocol: 'tcp', source_port: 40000, port: 22,
    source: '203.0.113.5', destination: '10.0.0.1'});
  assert.equal(c.decodeEvent('00'), null);
});
