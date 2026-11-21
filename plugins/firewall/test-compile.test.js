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
  assert.deepEqual(out.arrays, {fw_port_bits: {}, fw_class: {}, fw_policy: {}, fw_limit: {}, fw_pext: {}, fw_gcfg: {}});
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

test('ICMP types, IP protocols and catch-all policies normalize to fw_ports ranges', () => {
  assert.deepEqual(c.parseIcmpTypes(undefined, false, 'p'), [[0, 65535]]);
  assert.deepEqual(c.parseIcmpTypes(['echo-request', '3/4', '0'], false, 'p'), [[0, 255], [772, 772], [2048, 2303]]);
  assert.deepEqual(c.parseIcmpTypes(['echo-request'], true, 'p'), [[128 * 256, 128 * 256 + 255]]);
  assert.throws(() => c.parseIcmpTypes(['nope'], false, 'p'), /ICMP 类型无效/);
  assert.throws(() => c.parseIcmpTypes(['3/300'], false, 'p'), /代码无效/);
  assert.deepEqual(c.parseIpProtocols(['gre', 50], 'p'), [[47 * 256, 47 * 256 + 255], [50 * 256, 50 * 256 + 255]]);
  assert.throws(() => c.parseIpProtocols([6], 'p'), /tcp/);
  assert.throws(() => c.parseIpProtocols([], 'p'), /至少/);

  const icmp = c.normalizePolicy('ping', {protocol: 'icmp', icmp_types: ['echo-request']});
  assert.deepEqual(Object.keys(icmp.match), ['2']);
  assert.deepEqual(icmp.ranges, []);
  const any = c.normalizePolicy('all', {protocol: 'any', default_action: 'drop'});
  assert.equal(any.any, true);
  assert.deepEqual(any.match, {});
  assert.throws(() => c.normalizePolicy('x', {protocol: 'any', ports: ['22']}), /不能带端口/);
  assert.throws(() => c.normalizePolicy('x', {protocol: 'icmp', ip_protocols: [47]}), /按类型匹配/);
  assert.throws(() => c.normalizePolicy('x', {protocol: 'sctp'}), /协议必须是/);
  // syn_limit and tcp_new_only need TCP, which a catch-all policy covers.
  assert.equal(c.normalizePolicy('x', {protocol: 'any', tcp_new_only: true}).newOnly, true);
  assert.ok(c.normalizePolicy('x', {protocol: 'any', syn_limit: {max_new: 5, window_seconds: 1}}).synLimit);
  assert.throws(() => c.normalizePolicy('x', {protocol: 'udp', ports: ['53'], tcp_new_only: true}), /只作用于 TCP/);
  assert.throws(() => c.normalizePolicy('x', {protocol: 'icmp', syn_limit: {max_new: 5, window_seconds: 1}}), /只限制 TCP/);
});

test('conflicts cover ICMP types, IP protocols and catch-all policies', () => {
  const pol = (key, data) => c.normalizePolicy(key, data);
  assert.equal(c.findConflicts([pol('a', {protocol: 'icmp', icmp_types: ['8']}), pol('b', {protocol: 'icmp', icmp_types: ['0']})]).length, 0);
  assert.ok(c.findConflicts([pol('a', {protocol: 'icmp'}), pol('b', {protocol: 'icmp', icmp_types: ['3/4']})])[0].includes('icmp 类型 3/4'));
  assert.equal(c.findConflicts([pol('a', {protocol: 'icmp'}), pol('b', {protocol: 'icmpv6'})]).length, 0);
  assert.ok(c.findConflicts([pol('a', {protocol: 'ip', ip_protocols: ['gre']}), pol('b', {protocol: 'ip', ip_protocols: [47, 50]})])[0].includes('IP 协议 47'));
  // A catch-all policy never conflicts with a specific one, only with another catch-all.
  assert.equal(c.findConflicts([pol('a', {protocol: 'any'}), pol('b', {ports: ['22']})]).length, 0);
  assert.equal(c.findConflicts([pol('a', {protocol: 'any'}), pol('b', {protocol: 'any'})]).length, 1);
  assert.equal(c.findConflicts([pol('a', {protocol: 'any', destinations: ['10.0.0.1']}), pol('b', {protocol: 'any', destinations: ['10.0.0.2']})]).length, 0);
});

test('sources may name sets; add_to_set names one and defaults its timeout', () => {
  const p = c.normalizePolicy('p', {ports: ['22'], sources: [{set: 'office', action: 'allow'}, {cidr: '10.0.0.0/8', action: 'drop'}],
    add_to_set: {set: 'scanners'}}, ['office', 'scanners']);
  assert.deepEqual(p.sourceSets, [{set: 'office', action: c.ACTION_PASS}]);
  assert.equal(p.sources.length, 1);
  assert.deepEqual(p.addToSet, {set: 'scanners', seconds: 3600, ipv6Prefix: 64});
  assert.throws(() => c.normalizePolicy('p', {ports: ['22'], sources: [{set: 'gone', action: 'allow'}]}, ['office']), /不存在/);
  assert.throws(() => c.normalizePolicy('p', {ports: ['22'], sources: [{set: 'office', cidr: '1.2.3.4', action: 'allow'}]}, ['office']), /之一/);
  assert.throws(() => c.normalizePolicy('p', {ports: ['22'], sources: [{set: 'office', action: 'allow'}, {set: 'office', action: 'drop'}]}, ['office']), /重复/);
  const five = ['a', 'b', 'c', 'd', 'e'];
  assert.throws(() => c.normalizePolicy('p', {ports: ['22'], sources: five.map((s) => ({set: s, action: 'allow'}))}, five), /最多 4/);
  assert.throws(() => c.normalizePolicy('p', {ports: ['22'], add_to_set: {set: 'scanners', timeout_seconds: 99999999}}, ['scanners']), /timeout_seconds/);
});

test('warnings follow connection tracking, tcp_new_only and catch-all policies', () => {
  const ids = (policies, options) => c.findWarnings(policies, [], options).map((w) => w.id);
  const game = dropPolicy('game', {ports: ['25565']});
  assert.deepEqual(ids([game]), ['reply_ports:game']);
  assert.deepEqual(ids([game], {ct: true}), []);
  // Tracking never records UDP flows from covered ports: the warning stays.
  const udpHigh = dropPolicy('udphigh', {protocol: 'udp', ports: ['1024-65535']});
  assert.deepEqual(ids([udpHigh], {ct: true}), ['reply_ports:udphigh']);
  assert.ok(c.findWarnings([udpHigh], [], {ct: true})[0].message.includes('连接跟踪不记录'));
  assert.deepEqual(ids([dropPolicy('both', {protocol: 'tcp+udp', ports: ['25565']})], {ct: true}), ['reply_ports:both']);
  assert.deepEqual(ids([dropPolicy('game', {ports: ['25565'], tcp_new_only: true})]), []);
  assert.deepEqual(ids([dropPolicy('both', {protocol: 'tcp+udp', ports: ['25565'], tcp_new_only: true})]), ['reply_ports:both']);
  const all = c.normalizePolicy('all', {protocol: 'any', default_action: 'drop'});
  assert.deepEqual(ids([all]), ['lockout:all', 'reply_all:all']);
  assert.deepEqual(ids([all], {ct: true}), ['lockout:all']);
  // A port policy that allows the management ports decides them instead.
  const mgmt = c.normalizePolicy('mgmt', {ports: ['22', '8006', '8080'], default_action: 'allow'});
  assert.deepEqual(ids([all, mgmt], {ct: true}), []);
  assert.ok(c.findWarnings([dropPolicy('ssh', {ports: ['22'], tcp_new_only: true})], [])[0].message.includes('只判新连接'));
});

test('fw_pext and fw_gcfg carry the new policy and global settings', () => {
  const ssh = c.normalizePolicy('ssh', {ports: ['22'], tcp_new_only: true, sources: [{set: 'office', action: 'allow'}, {set: 'bad', action: 'drop'}],
    add_to_set: {set: 'scanners', timeout_seconds: 600, ipv6_prefix: 56}}, ['office', 'bad', 'scanners']);
  ssh.slot = 2;
  const ping = c.normalizePolicy('ping', {protocol: 'icmp', icmp_types: ['echo-request'], default_action: 'allow'});
  ping.slot = 3;
  const all = c.normalizePolicy('all', {protocol: 'any', default_action: 'drop'});
  all.slot = 4;
  const out = c.compileGeneration([ssh, ping, all], [], 0, {
    setIds: {office: 1, bad: 2, scanners: 3, deny: 4},
    settings: {connectionTracking: true, blocklists: ['deny'], baseline: {bogonSources: 'all', invalidTcpFlags: true, dropFragments: false, urpf: 'strict'}},
  });
  // flags 3 (new only + add to set), 2 sets, add set 3 for 600 s, sets 1 and 2 (allow, drop), /56.
  assert.equal(out.arrays.fw_pext[2], '0302' + '0300' + c.u32le(600) + '0100' + '0200' + '0000' + '0000' + '00010000' + '38000000' + c.prefixMaskHex(56));
  assert.equal(out.arrays.fw_pext[2].length, c.PEXT_VALUE_ZERO.length);
  assert.equal(out.arrays.fw_pext[3], undefined);
  // ICMP echo request: proto 2, type 8 /8 -> the ICMP policy's class.
  const ports = Object.fromEntries(out.lpm.fw_ports.map((e) => [e.key, e.value]));
  assert.equal(ports['1800000000020800'], c.u32le(2));
  // gcfg: CT | BOGON | BAD_FLAGS | URPF_STRICT | PROTO = 1+2+4+32+64, catch-all class 3, one blocklist (set 4).
  assert.equal(out.arrays.fw_gcfg[0], c.u32le(103) + c.u16le(3) + '01' + '00' + '0400' + '0000' + '0000' + '0000');
  assert.equal(out.arrays.fw_class[3], '04000000');
  assert.equal(out.summary.catch_all, 1);
  assert.throws(() => c.compileGeneration([], [], 0, {settings: {blocklists: ['gone']}}), /集合不存在/);
});

test('sets compile to fw_sets entries; ids stay stable; keys decode', () => {
  const office = c.normalizeSet('office', {elements: ['203.0.113.0/24', '2001:db8::/32']});
  office.id = 5;
  const entries = c.compileSets([office], {bogonSources: 'off'});
  assert.deepEqual(entries, {
    ['38000000' + '04' + '00' + '0005' + 'cb007100' + '0'.repeat(24)]: c.setValue(0, c.SET_KIND_STATIC),
    ['40000000' + '06' + '00' + '0005' + '20010db8' + '0'.repeat(24)]: c.setValue(0, c.SET_KIND_STATIC),
  });
  assert.equal(c.setValue(0, 1), '0000000000000000' + '01000000' + '00000000');
  assert.equal(c.u64leNsFromMs(5000), '00f2052a01000000');
  assert.deepEqual(c.decodeSetKey(c.setKey(5, c.parseCIDR('203.0.113.0/24'))), {id: 5, family: 4, prefix: 24, cidr: '203.0.113.0/24'});
  assert.deepEqual(c.decodeSetValue(c.setValue(5000, c.SET_KIND_API)), {expiresMs: 5000, kind: 'api'});
  const reserved = Object.keys(c.compileSets([], {bogonSources: 'reserved'})).length;
  assert.equal(reserved, c.BOGONS_RESERVED.length);
  assert.equal(Object.keys(c.compileSets([], {bogonSources: 'all'})).length, reserved + c.BOGONS_PRIVATE.length);
  for (const key of Object.keys(c.compileSets([], {bogonSources: 'all'}))) assert.equal(c.decodeSetKey(key).id, c.SET_BOGON);
  assert.throws(() => c.normalizeSet('Bad Name', {}), /集合名无效/);
  assert.throws(() => c.normalizeSet('dup', {elements: ['1.2.3.4', '1.2.3.4/32']}), /重复/);

  const first = c.assignSetIds(['a', 'b'], {});
  assert.deepEqual(first.ids, {a: 1, b: 2});
  const second = c.assignSetIds(['b', 'c'], first.ids);
  assert.deepEqual(second.ids, {b: 2, c: 3});
  assert.deepEqual(second.fresh, [3]);
});

test('drop events decode ICMP and other protocols and the new reasons', () => {
  const ev = (reason, proto, sport, dport) => c.u32le(0) + c.u32le(0) + c.u32le(2) + c.u16le(0) + c.u8(reason) + c.u8(4) + c.u8(proto) + '00' +
    sport + dport + '0000' + ('cb007105' + '0'.repeat(32)).slice(0, 32) + ('0a000001' + '0'.repeat(32)).slice(0, 32);
  const icmp = c.decodeEvent(ev(5, 2, '1234', '0800'));
  assert.equal(icmp.reason, 'blocklist');
  assert.equal(icmp.protocol, 'icmp');
  assert.equal(icmp.icmp_type, 8);
  assert.equal(icmp.icmp_code, 0);
  assert.equal(icmp.port, 0);
  const gre = c.decodeEvent(ev(6, 4, '0000', '2f00'));
  assert.equal(gre.reason, 'bogon');
  assert.equal(gre.protocol, 'ip');
  assert.equal(gre.ip_protocol, 47);
  assert.equal(c.decodeEvent(ev(9, 0, '0001', '0016')).reason, 'fragment');
});
