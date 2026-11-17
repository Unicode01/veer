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
  assert.deepEqual(out.arrays, {fw_port_bits: {}, fw_class: {}, fw_policy: {}});
  for (const map of Object.keys(out.lpm)) assert.equal(out.lpm[map].length, 0);
});

test('sumPerCPU adds little-endian u64 counters', () => {
  assert.equal(c.sumPerCPU(['0100000000000000', 'ff00000000000000', '0001000000000000']), 512);
  assert.equal(c.sumPerCPU(null), 0);
});
