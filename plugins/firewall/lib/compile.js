'use strict';
/*
 * Turns firewall policies into the map entries firewall.bpf.c reads. Pure
 * functions, no host API: control.js writes the result, the unit tests check
 * it. Layouts must match the structs in firewall.bpf.c (little-endian hosts).
 */

var MAX_POLICY_SLOT = 255;   // slots 1..255; slot 0 holds the trusted sources
var MAX_CLASSES = 1023;      // class ids 1..1023 (fw_class holds 1024 per generation)
var MAX_PORT_RANGES = 64;
var MAX_DESTINATIONS = 64;
var MAX_SOURCES = 1024;
var MAX_TRUSTED = 256;
// Per generation; each LPM map holds both generations.
var PORT_PREFIX_CAPACITY = 8192;
var DST_CAPACITY = 4096;
var SRC_CAPACITY = 16384;

var PORT_WORDS = 1024;
var PORT_WORDS_PER_GEN = 2 * PORT_WORDS;
var CLASSES_PER_GEN = 1024;
var POLICIES_PER_GEN = 256;
var COUNTERS = 4;

// fw_ports proto byte; fw_port_bits covers TCP and UDP only.
var PROTO_TCP = 0;
var PROTO_UDP = 1;
var PROTO_ICMP = 2;   // port: type << 8 | code
var PROTO_ICMPV6 = 3; // port: type << 8 | code
var PROTO_IP = 4;     // port: protocol << 8
var PROTO_NAMES = ['tcp', 'udp', 'icmp', 'icmpv6', 'ip'];
var ACTION_PASS = 0;
var ACTION_DROP = 1;

var POLICY_VALID = 1;
var POLICY_LIMIT = 2;

// fw_pext
var PX_NEW_ONLY = 1;
var PX_ADD_SET = 2;
var PX_SETS = 4;
var PEXT_VALUE_ZERO = '00'.repeat(40);
var MAX_ADD_SECONDS = 30 * 86400;

// fw_gcfg
var G_CT = 1;
var G_BOGON = 2;
var G_BAD_FLAGS = 4;
var G_DROP_FRAGS = 8;
var G_URPF_LOOSE = 16;
var G_URPF_STRICT = 32;
var G_PROTO = 64;
var BLOCK_SETS = 4;
var GCFG_VALUE_ZERO = '00'.repeat(16);

// fw_sets
var MAX_SETS = 255;            // ids 1..255; 0xfff0 holds the bogon prefixes
var SET_BOGON = 0xfff0;
var MAX_SET_ELEMENTS = 4096;   // static elements of one set
var SET_STATIC_CAPACITY = 32768;
var SET_KIND_STATIC = 1;       // from the sets resource
var SET_KIND_API = 2;          // added with the set_add action
var SET_KIND_POLICY = 3;       // added by a policy's add_to_set
var SET_KINDS = {1: 'static', 2: 'api', 3: 'policy'};
var SET_NAME = /^[a-z0-9][a-z0-9_-]{0,47}$/;

// Sources no packet arriving from outside can have: unspecified, loopback,
// multicast and reserved space, documentation ranges. "all" adds private,
// shared (CGNAT) and link-local space, which a WAN can legitimately see
// behind a modem or a carrier NAT.
var BOGONS_RESERVED = ['0.0.0.0/8', '127.0.0.0/8', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/3', '::/128', '::1/128', '100::/64', '2001:db8::/32', 'ff00::/8'];
var BOGONS_PRIVATE = ['10.0.0.0/8', '100.64.0.0/10', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'];
var MAX_SYN_PER_WINDOW = 1000000;
var MAX_LIMIT_WINDOW_SECONDS = 3600;
var MAX_BAN_SECONDS = 7 * 86400;
var DEFAULT_LIMIT_IPV6_PREFIX = 64;
var LIMIT_VALUE_ZERO = '0000000000000000000000000000000000000000000000000000000000000000'; // 32 bytes

// fw_lstats: per policy slot; slot 0 counts the drop log.
var LCOUNTERS = 4;
var LCNT_BAN = 0;
var LCNT_RATE = 1;
var LCNT_LOGGED = 2;
var LCNT_LOST = 3;

// fw_gstats
var GCOUNTERS = ['established', 'related', 'essential', 'blocklist', 'bogon', 'urpf', 'tcp_flags', 'fragment',
  'ct_new', 'ct_full', 'ct_short', 'set_add', 'set_full'];

var EVENT_BYTES = 56;
var REASONS = {1: 'acl', 2: 'ban', 3: 'rate', 4: 'evasive', 5: 'blocklist', 6: 'bogon', 7: 'urpf', 8: 'tcp_flags', 9: 'fragment'};

// ICMP type names accepted in icmp_types.
var ICMP_TYPES = {'echo-reply': 0, 'destination-unreachable': 3, 'redirect': 5, 'echo-request': 8, 'router-advertisement': 9,
  'router-solicitation': 10, 'time-exceeded': 11, 'parameter-problem': 12, 'timestamp-request': 13, 'timestamp-reply': 14};
var ICMPV6_TYPES = {'destination-unreachable': 1, 'packet-too-big': 2, 'time-exceeded': 3, 'parameter-problem': 4,
  'echo-request': 128, 'echo-reply': 129, 'router-solicitation': 133, 'router-advertisement': 134,
  'neighbor-solicitation': 135, 'neighbor-advertisement': 136};

function fail(message) {
  throw new Error(message);
}

// ---------------------------------------------------------------- hex helpers

function hexByte(value) {
  var s = (value & 0xff).toString(16);
  return s.length < 2 ? '0' + s : s;
}

function u8(value) { return hexByte(value); }
function u16le(value) { return hexByte(value) + hexByte(value >>> 8); }
function u16be(value) { return hexByte(value >>> 8) + hexByte(value); }
function u32le(value) { return hexByte(value) + hexByte(value >>> 8) + hexByte(value >>> 16) + hexByte(value >>> 24); }
function bytesHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) out += hexByte(bytes[i]);
  return out;
}

// --------------------------------------------------------------- addresses

function parseIPv4(text) {
  var parts = text.split('.');
  if (parts.length !== 4) return null;
  var out = [];
  for (var i = 0; i < 4; i++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i])) return null;
    var n = Number(parts[i]);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

function parseHexGroups(part) {
  if (part === '') return [];
  var groups = part.split(':');
  var out = [];
  for (var i = 0; i < groups.length; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    out.push(parseInt(groups[i], 16));
  }
  return out;
}

function parseIPv6(text) {
  if (text.indexOf(':') < 0) return null;
  var tail = [];
  var lastColon = text.lastIndexOf(':');
  if (text.slice(lastColon + 1).indexOf('.') >= 0) {
    // An embedded IPv4 address supplies the last two groups.
    var v4 = parseIPv4(text.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    var before = text.slice(0, lastColon + 1);
    text = before.slice(-2) === '::' ? before : text.slice(0, lastColon);
  }
  var halves = text.split('::');
  if (halves.length > 2) return null;
  var head = parseHexGroups(halves[0]);
  var rest = halves.length === 2 ? parseHexGroups(halves[1]) : [];
  if (!head || !rest) return null;
  var total = head.length + rest.length + tail.length;
  var groups = head.slice();
  if (halves.length === 2) {
    if (total > 7) return null;
    for (var z = total; z < 8; z++) groups.push(0);
  } else if (total !== 8) {
    return null;
  }
  groups = groups.concat(rest, tail);
  var bytes = [];
  for (var g = 0; g < 8; g++) bytes.push(groups[g] >>> 8, groups[g] & 0xff);
  return bytes;
}

function formatAddress(family, bytes) {
  if (family === 4) return bytes.join('.');
  var groups = [];
  for (var i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  // Compress the longest run of zero groups (RFC 5952).
  var best = -1, bestLen = 0;
  for (var start = 0; start < 8;) {
    if (groups[start] !== '0') { start++; continue; }
    var end = start;
    while (end < 8 && groups[end] === '0') end++;
    if (end - start > bestLen && end - start > 1) { best = start; bestLen = end - start; }
    start = end;
  }
  if (best < 0) return groups.join(':');
  return groups.slice(0, best).join(':') + '::' + groups.slice(best + bestLen).join(':');
}

/*
 * Parses "addr" or "addr/len" into {family, bytes, prefix, text}. Host bits
 * are cleared and text is the normalized form. IPv4-mapped IPv6 prefixes
 * (::ffff:a.b.c.d/96 and longer) become IPv4: the filter sees IPv4 packets.
 */
function parseCIDR(raw) {
  if (typeof raw !== 'string') fail('地址必须是字符串');
  var text = raw.trim();
  if (!text || text.length > 64) fail('地址无效: ' + raw);
  var slash = text.indexOf('/');
  var addr = slash < 0 ? text : text.slice(0, slash);
  var prefixText = slash < 0 ? '' : text.slice(slash + 1);
  var family = 4;
  var bytes = parseIPv4(addr);
  if (!bytes) {
    bytes = parseIPv6(addr);
    family = 6;
  }
  if (!bytes) fail('地址无效: ' + raw);
  var max = family === 4 ? 32 : 128;
  var prefix = max;
  if (slash >= 0) {
    if (!/^[0-9]{1,3}$/.test(prefixText)) fail('前缀长度无效: ' + raw);
    prefix = Number(prefixText);
    if (prefix > max) fail('前缀长度无效: ' + raw);
  }
  if (family === 6 && prefix >= 96) {
    var mapped = true;
    for (var i = 0; i < 10; i++) if (bytes[i] !== 0) mapped = false;
    if (bytes[10] !== 0xff || bytes[11] !== 0xff) mapped = false;
    if (mapped) {
      family = 4;
      bytes = bytes.slice(12);
      prefix -= 96;
      max = 32;
    }
  }
  for (var b = 0; b < bytes.length; b++) {
    var keep = Math.max(0, Math.min(8, prefix - b * 8));
    bytes[b] &= keep === 0 ? 0 : (0xff << (8 - keep)) & 0xff;
  }
  return {family: family, bytes: bytes, prefix: prefix, text: formatAddress(family, bytes) + '/' + prefix};
}

function cidrOverlap(a, b) {
  if (a.family !== b.family) return false;
  var bits = Math.min(a.prefix, b.prefix);
  for (var i = 0; i < a.bytes.length && bits > 0; i++, bits -= 8) {
    var mask = bits >= 8 ? 0xff : (0xff << (8 - bits)) & 0xff;
    if ((a.bytes[i] & mask) !== (b.bytes[i] & mask)) return false;
  }
  return true;
}

// ------------------------------------------------------------------ policies

function parsePortRanges(list, label) {
  if (!Array.isArray(list) || list.length === 0) fail(label + ': 至少需要一个端口');
  if (list.length > MAX_PORT_RANGES) fail(label + ': 端口区间最多 ' + MAX_PORT_RANGES + ' 个');
  var ranges = [];
  list.forEach(function (item) {
    var text = String(item).trim();
    var m = /^([0-9]{1,5})(?:\s*-\s*([0-9]{1,5}))?$/.exec(text);
    if (!m) fail(label + ': 端口无效: ' + item);
    var a = Number(m[1]);
    var b = m[2] === undefined ? a : Number(m[2]);
    if (a < 1 || b > 65535 || a > b) fail(label + ': 端口无效: ' + item);
    ranges.push([a, b]);
  });
  ranges.sort(function (x, y) { return x[0] - y[0]; });
  var merged = [];
  ranges.forEach(function (r) {
    var last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  });
  return merged;
}

function parseAction(value, label) {
  if (value === 'allow') return ACTION_PASS;
  if (value === 'drop') return ACTION_DROP;
  fail(label + ': 动作必须是 allow 或 drop');
}

function intIn(value, min, max, label) {
  var n = Number(value);
  if (value === null || value === '' || !isFinite(n) || Math.floor(n) !== n || n < min || n > max) {
    fail(label + ' 必须是 ' + min + ' 到 ' + max + ' 之间的整数');
  }
  return n;
}

/*
 * {max_new, window_seconds, ban_seconds, ipv6_prefix}: at most max_new new
 * TCP connections (SYNs) per window from one source prefix; over that, SYNs
 * are dropped and, with ban_seconds, the prefix is banned from the policy.
 */
function parseSynLimit(value, protocols, label) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) fail(label + ': syn_limit 必须是对象');
  if (protocols.indexOf(PROTO_TCP) < 0) fail(label + ': syn_limit 只限制 TCP 新连接，协议需要包含 tcp');
  return {
    maxNew: intIn(value.max_new, 1, MAX_SYN_PER_WINDOW, label + ': syn_limit.max_new'),
    windowSeconds: intIn(value.window_seconds, 1, MAX_LIMIT_WINDOW_SECONDS, label + ': syn_limit.window_seconds'),
    banSeconds: value.ban_seconds === undefined ? 0 : intIn(value.ban_seconds, 0, MAX_BAN_SECONDS, label + ': syn_limit.ban_seconds'),
    ipv6Prefix: value.ipv6_prefix === undefined ? DEFAULT_LIMIT_IPV6_PREFIX : intIn(value.ipv6_prefix, 32, 128, label + ': syn_limit.ipv6_prefix')
  };
}

/* The first prefix bits of 16 bytes set, as hex. */
function prefixMaskHex(prefix) {
  var out = '';
  for (var i = 0; i < 16; i++) {
    var bits = Math.max(0, Math.min(8, prefix - i * 8));
    out += hexByte((0xff << (8 - bits)) & 0xff);
  }
  return out;
}

function mergeRanges(ranges) {
  ranges.sort(function (x, y) { return x[0] - y[0]; });
  var merged = [];
  ranges.forEach(function (r) {
    var last = merged[merged.length - 1];
    if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
    else merged.push([r[0], r[1]]);
  });
  return merged;
}

/*
 * ICMP types as ranges over type << 8 | code: "8" or a name is every code
 * of the type, "3/4" one code. No list is every type.
 */
function parseIcmpTypes(list, v6, label) {
  if (list === undefined || list === null || (Array.isArray(list) && list.length === 0)) return [[0, 65535]];
  if (!Array.isArray(list)) fail(label + ': icmp_types 必须是数组');
  if (list.length > MAX_PORT_RANGES) fail(label + ': ICMP 类型最多 ' + MAX_PORT_RANGES + ' 个');
  var names = v6 ? ICMPV6_TYPES : ICMP_TYPES;
  var ranges = [];
  list.forEach(function (item) {
    var text = String(item).trim().toLowerCase();
    var m = /^([a-z0-9-]+)(?:\/([0-9]{1,3}))?$/.exec(text);
    if (!m) fail(label + ': ICMP 类型无效: ' + item);
    var type = /^[0-9]{1,3}$/.test(m[1]) ? Number(m[1]) : names[m[1]];
    if (type === undefined || type > 255) fail(label + ': ICMP 类型无效: ' + item);
    if (m[2] === undefined) {
      ranges.push([type * 256, type * 256 + 255]);
    } else {
      var code = Number(m[2]);
      if (code > 255) fail(label + ': ICMP 代码无效: ' + item);
      ranges.push([type * 256 + code, type * 256 + code]);
    }
  });
  return mergeRanges(ranges);
}

var IP_PROTOCOL_NAMES = {igmp: 2, ipip: 4, ipv6: 41, gre: 47, esp: 50, ah: 51, ospf: 89, pim: 103, vrrp: 112, l2tp: 115, sctp: 132};

/* IP protocol numbers as ranges over protocol << 8. */
function parseIpProtocols(list, label) {
  if (!Array.isArray(list) || list.length === 0) fail(label + ': ip 策略至少需要一个协议号（ip_protocols）');
  if (list.length > MAX_PORT_RANGES) fail(label + ': 协议号最多 ' + MAX_PORT_RANGES + ' 个');
  var ranges = [];
  list.forEach(function (item) {
    var text = String(item).trim().toLowerCase();
    var n = /^[0-9]{1,3}$/.test(text) ? Number(text) : IP_PROTOCOL_NAMES[text];
    if (n === undefined || n > 255) fail(label + ': 协议号无效: ' + item);
    if (n === 1 || n === 6 || n === 17 || n === 58) fail(label + ': 协议 ' + n + ' 请用 icmp、tcp、udp 或 icmpv6 策略');
    ranges.push([n * 256, n * 256 + 255]);
  });
  return mergeRanges(ranges);
}

function intOr(value, fallback, min, max, label) {
  return value === undefined || value === null ? fallback : intIn(value, min, max, label);
}

/*
 * Validates one policy record and returns its normalized form:
 * {key, name, protocols, ranges, match, any, destinations, defaultAction,
 *  sources, sourceSets, synLimit, newOnly, addToSet}.
 * ranges are the TCP/UDP ports; match maps every fw_ports proto the policy
 * covers to its ranges; any marks a catch-all policy. sets, when given,
 * lists the set keys sources and add_to_set may name.
 */
function normalizePolicy(key, data, sets) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('策略 ' + key + ': 内容必须是对象');
  var label = '策略 ' + (data.name || key);
  var protocol = data.protocol || 'tcp';
  var protocols = [];
  var match = {};
  var any = false;
  var hasPorts = Array.isArray(data.ports) && data.ports.length > 0;
  var ranges = [];
  if (protocol === 'tcp' || protocol === 'udp' || protocol === 'tcp+udp') {
    protocols = protocol === 'tcp' ? [PROTO_TCP] : protocol === 'udp' ? [PROTO_UDP] : [PROTO_TCP, PROTO_UDP];
    ranges = parsePortRanges(data.ports, label);
    protocols.forEach(function (p) { match[p] = ranges; });
    if (data.icmp_types || data.ip_protocols) fail(label + ': tcp/udp 策略不能带 icmp_types 或 ip_protocols');
  } else if (protocol === 'icmp' || protocol === 'icmpv6') {
    if (hasPorts || data.ip_protocols) fail(label + ': ICMP 策略按类型匹配，不能带端口或 ip_protocols');
    protocols = [protocol === 'icmp' ? PROTO_ICMP : PROTO_ICMPV6];
    match[protocols[0]] = parseIcmpTypes(data.icmp_types, protocol === 'icmpv6', label);
  } else if (protocol === 'ip') {
    if (hasPorts || data.icmp_types) fail(label + ': ip 策略按协议号匹配，不能带端口或 icmp_types');
    protocols = [PROTO_IP];
    match[PROTO_IP] = parseIpProtocols(data.ip_protocols, label);
  } else if (protocol === 'any') {
    if (hasPorts || data.icmp_types || data.ip_protocols) fail(label + ': 全部流量策略不能带端口、icmp_types 或 ip_protocols');
    any = true;
  } else {
    fail(label + ': 协议必须是 tcp、udp、tcp+udp、icmp、icmpv6、ip 或 any');
  }
  var tcp = any || protocols.indexOf(PROTO_TCP) >= 0;
  var destinations = (data.destinations || []).map(parseCIDR);
  if (destinations.length > MAX_DESTINATIONS) fail(label + ': 目标地址最多 ' + MAX_DESTINATIONS + ' 个');
  var knownSet = function (name, what) {
    if (typeof name !== 'string' || !SET_NAME.test(name)) fail(label + ': ' + what + '的集合名无效: ' + name);
    if (sets && sets.indexOf(name) < 0) fail(label + ': ' + what + '引用的集合不存在: ' + name);
    return name;
  };
  var sources = [];
  var sourceSets = [];
  (data.sources || []).forEach(function (entry) {
    if (!entry || typeof entry !== 'object') fail(label + ': 来源条目必须是 {cidr, action} 或 {set, action}');
    if (entry.set !== undefined) {
      if (entry.cidr !== undefined) fail(label + ': 来源条目只能写 cidr 或 set 之一');
      sourceSets.push({set: knownSet(entry.set, '来源'), action: parseAction(entry.action, label)});
    } else {
      sources.push({cidr: parseCIDR(entry.cidr), action: parseAction(entry.action, label)});
    }
  });
  if (sources.length > MAX_SOURCES) fail(label + ': 来源最多 ' + MAX_SOURCES + ' 个');
  if (sourceSets.length > PX_SETS) fail(label + ': 来源集合最多 ' + PX_SETS + ' 个');
  var seen = {};
  sources.forEach(function (s) {
    if (seen[s.cidr.text]) fail(label + ': 来源重复: ' + s.cidr.text);
    seen[s.cidr.text] = true;
  });
  sourceSets.forEach(function (s) {
    if (seen['set:' + s.set]) fail(label + ': 来源集合重复: ' + s.set);
    seen['set:' + s.set] = true;
  });
  if (data.tcp_new_only !== undefined && typeof data.tcp_new_only !== 'boolean') fail(label + ': tcp_new_only 必须是布尔值');
  var newOnly = data.tcp_new_only === true;
  if (newOnly && !tcp) fail(label + ': tcp_new_only 只作用于 TCP，协议需要包含 tcp');
  var addToSet = null;
  if (data.add_to_set !== undefined && data.add_to_set !== null) {
    var add = data.add_to_set;
    if (typeof add !== 'object' || Array.isArray(add)) fail(label + ': add_to_set 必须是对象');
    addToSet = {
      set: knownSet(add.set, '写入'),
      seconds: intOr(add.timeout_seconds, 3600, 0, MAX_ADD_SECONDS, label + ': add_to_set.timeout_seconds'),
      ipv6Prefix: intOr(add.ipv6_prefix, DEFAULT_LIMIT_IPV6_PREFIX, 32, 128, label + ': add_to_set.ipv6_prefix')
    };
  }
  return {
    key: key,
    name: String(data.name || key),
    protocols: protocols,
    ranges: ranges,
    match: match,
    any: any,
    destinations: destinations,
    defaultAction: parseAction(data.default_action || 'drop', label),
    sources: sources,
    sourceSets: sourceSets,
    synLimit: parseSynLimit(data.syn_limit, tcp ? [PROTO_TCP] : protocols, label),
    newOnly: newOnly,
    addToSet: addToSet
  };
}

function rangesIntersect(a, b) {
  for (var i = 0; i < a.length; i++)
    for (var j = 0; j < b.length; j++)
      if (a[i][0] <= b[j][1] && b[j][0] <= a[i][1]) return [Math.max(a[i][0], b[j][0])];
  return null;
}

function matchText(proto, value) {
  if (proto === PROTO_TCP || proto === PROTO_UDP) return PROTO_NAMES[proto] + ' 端口 ' + value;
  if (proto === PROTO_IP) return 'IP 协议 ' + (value >> 8);
  return PROTO_NAMES[proto] + ' 类型 ' + (value >> 8) + '/' + (value & 255);
}

function destinationsOverlap(a, b) {
  if (!a.destinations.length || !b.destinations.length) return true;
  for (var x = 0; x < a.destinations.length; x++)
    for (var y = 0; y < b.destinations.length; y++)
      if (cidrOverlap(a.destinations[x], b.destinations[y])) return true;
  return false;
}

/*
 * Two policies conflict when they match the same protocol and port (ICMP
 * type, IP protocol) and either names no destinations or their destinations
 * overlap: the filter could not tell which one a packet belongs to. Two
 * catch-all policies conflict the same way.
 */
function findConflicts(policies) {
  var errors = [];
  for (var i = 0; i < policies.length; i++) {
    for (var j = i + 1; j < policies.length; j++) {
      var a = policies[i], b = policies[j];
      if (a.any || b.any) {
        if (a.any && b.any && destinationsOverlap(a, b)) errors.push('策略 ' + a.name + ' 和 ' + b.name + ' 都是全部流量策略，作用于相同的目标地址');
        continue;
      }
      for (var proto = 0; proto < PROTO_NAMES.length; proto++) {
        if (!a.match[proto] || !b.match[proto]) continue;
        var hit = rangesIntersect(a.match[proto], b.match[proto]);
        if (!hit || !destinationsOverlap(a, b)) continue;
        errors.push('策略 ' + a.name + ' 和 ' + b.name + ' 在 ' + matchText(proto, hit[0]) + ' 上作用于相同的目标地址');
        break;
      }
    }
  }
  return errors;
}

// ----------------------------------------------------------------- warnings

// Ports whose loss locks an administrator out. Veer's own port is whatever
// web_port says, which a plugin cannot read; 8080 is its default.
var MANAGEMENT_PORTS = [
  {port: 22, name: 'SSH'},
  {port: 8006, name: 'Proxmox VE'},
  {port: 8080, name: 'Veer 默认管理端口'}
];
// Replies to outbound connections arrive on these ports: Veer's egress NAT
// pool once the host's ephemeral ports are taken out of it, and Linux's
// default ip_local_port_range. The plugin cannot read the actual values.
var NAT_REPLY_PORTS = [20000, 32767];
var EPHEMERAL_REPLY_PORTS = [32768, 60999];

function portText(range) { return range[0] === range[1] ? String(range[0]) : range[0] + '-' + range[1]; }

/* The first part of ranges inside window; single ports skipped when rangesOnly. */
function overlapWith(ranges, window, rangesOnly) {
  for (var i = 0; i < ranges.length; i++) {
    if (rangesOnly && ranges[i][0] === ranges[i][1]) continue;
    var lo = Math.max(ranges[i][0], window[0]);
    var hi = Math.min(ranges[i][1], window[1]);
    if (lo <= hi) return [lo, hi];
  }
  return null;
}

/*
 * Rule sets that are valid but likely to cut off more than intended. Only
 * policies that drop unlisted sources can: one deciding a management port
 * with no trusted source (a port policy covering it, else a catch-all
 * policy), or one covering ports that replies to outbound connections use.
 * Without connection tracking a reply is just another packet from an
 * unlisted source; with it, TCP replies and those of UDP flows from
 * unprotected ports pass, and tcp_new_only lets every TCP reply through even
 * without it. A single port in the ephemeral range is
 * left alone: a local listener keeps the kernel from picking it.
 * options.ct says whether connection tracking is on.
 * Returns [{id, policy, message}].
 */
function findWarnings(policies, trusted, options) {
  var ct = !!(options && options.ct);
  var warnings = [];
  var tcpPort = function (pol, port) {
    return !!pol.match[PROTO_TCP] && pol.match[PROTO_TCP].some(function (r) { return r[0] <= port && port <= r[1]; });
  };
  policies.forEach(function (p) {
    if (p.defaultAction !== ACTION_DROP) return;
    var label = '策略 ' + p.name;
    if (!trusted.length && (p.any || p.match[PROTO_TCP])) {
      var hit = MANAGEMENT_PORTS.filter(function (m) {
        if (!p.any) return tcpPort(p, m.port);
        return !policies.some(function (other) { return !other.any && tcpPort(other, m.port); });
      });
      if (hit.length) {
        warnings.push({
          id: 'lockout:' + p.key,
          policy: p.key,
          message: label + ' 默认丢弃 tcp ' + hit.map(function (m) { return m.port + '（' + m.name + '）'; }).join('、') +
            '，且没有信任来源：只有放行的来源还能连上。' +
            (p.newOnly ? '它只判新连接，已经连着的会话不受影响，所以确认能成功，断开后才连不上。' : '')
        });
      }
    }
    if (p.any) {
      if (ct) return;
      warnings.push({
        id: 'reply_all:' + p.key,
        policy: p.key,
        message: label + ' 是默认丢弃的全部流量策略，但没开连接跟踪：本机和经 Veer 出站的连接，回包都按来源判断，' +
          '对端不在放行列表里时被丢弃。开启连接跟踪后回包自动放行。'
      });
      return;
    }
    // Connection tracking only records UDP flows from ports no UDP policy
    // covers (a reply leaving a protected port must not open it), so it
    // never rescues a UDP policy over reply ports.
    var replyRanges = [];
    if (p.match[PROTO_TCP] && !p.newOnly && !ct) replyRanges = replyRanges.concat(p.match[PROTO_TCP]);
    if (p.match[PROTO_UDP]) replyRanges = replyRanges.concat(p.match[PROTO_UDP]);
    var nat = overlapWith(replyRanges, NAT_REPLY_PORTS, false);
    var ephemeral = overlapWith(replyRanges, EPHEMERAL_REPLY_PORTS, true);
    if (nat || ephemeral) {
      var parts = [];
      if (nat) parts.push(portText(nat) + ' 在 Veer 出向 NAT 的端口池（默认 20000-32767）内');
      if (ephemeral) parts.push(portText(ephemeral) + ' 在宿主出站连接的临时端口（默认 32768-60999）内');
      warnings.push({
        id: 'reply_ports:' + p.key,
        policy: p.key,
        message: label + ' 的端口 ' + parts.join('，') + (ct ?
          '：连接跟踪不记录从受 UDP 策略保护的端口发出的 UDP 流，这些端口上出站 UDP 的回包仍按来源判断，对端不在放行列表里时被丢弃。' +
          '把 UDP 策略限定在服务端口上可以避免。' :
          '：没开连接跟踪，出站连接的回包也会按来源判断，对端不在放行列表里时回包被丢弃，连接失败。' +
          '开启连接跟踪，或者 TCP 策略打开“只判新连接”，可以避免。')
      });
    }
  });
  return warnings;
}

/* Fingerprint of a warning list (FNV-1a); '' when there is none. */
function warningsToken(warnings) {
  if (!warnings.length) return '';
  var text = warnings.map(function (w) { return w.id + '\n' + w.message; }).sort().join('\n\n');
  var h = 0x811c9dc5;
  for (var i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = (h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return ('0000000' + h.toString(16)).slice(-8);
}

/*
 * Keeps slot numbers stable across applies so counters follow their policy.
 * slots maps policy keys to slots; returns the updated map and the slots
 * assigned now (their counters start from a fresh baseline).
 */
function assignSlots(keys, slots) {
  var next = {};
  var used = {};
  var fresh = [];
  keys.forEach(function (key) {
    var slot = slots && slots[key];
    if (slot >= 1 && slot <= MAX_POLICY_SLOT && !used[slot]) {
      next[key] = slot;
      used[slot] = true;
    }
  });
  // Prefer slots no policy held before, so a new policy does not inherit
  // the counters of a deleted one.
  var held = {};
  Object.keys(slots || {}).forEach(function (key) { held[slots[key]] = true; });
  keys.forEach(function (key) {
    if (next[key]) return;
    var slot = 0;
    for (var s = 1; s <= MAX_POLICY_SLOT && !slot; s++) if (!used[s] && !held[s]) slot = s;
    for (var t = 1; t <= MAX_POLICY_SLOT && !slot; t++) if (!used[t]) slot = t;
    if (!slot) fail('策略最多 ' + MAX_POLICY_SLOT + ' 条');
    next[key] = slot;
    used[slot] = true;
    fresh.push(slot);
  });
  return {slots: next, fresh: fresh};
}

// ---------------------------------------------------------------- compiling

// [a, b] as aligned power-of-two blocks over the 16-bit port space.
function portPrefixes(a, b) {
  var out = [];
  while (a <= b) {
    var size = 1;
    while (size < 65536 && a % (size * 2) === 0 && a + size * 2 - 1 <= b) size *= 2;
    var bits = 0;
    while ((1 << bits) < size) bits++;
    out.push({port: a, prefix: 16 - bits});
    a += size;
  }
  return out;
}

function portKey(generation, proto, port, prefix) {
  return u32le(16 + prefix) + u8(generation) + u8(proto) + u16be(port);
}

function addrKey(generation, id, cidr) {
  return u32le(32 + cidr.prefix) + u8(generation) + '00' + u16be(id) + bytesHex(cidr.bytes);
}

/*
 * Compiles normalized policies (each with .slot) and trusted source CIDRs
 * into the entries of one generation:
 *   arrays: {fw_port_bits, fw_class, fw_policy, fw_limit, fw_pext, fw_gcfg}:
 *           index -> value hex, only non-zero entries (the caller zeroes what
 *           an older rule set left);
 *   lpm:    {fw_ports, fw_dst4, fw_dst6, fw_src4, fw_src6}: [{key, value}];
 *   active: whether any policy exists.
 * options: {setIds: set key -> id, settings: {connectionTracking,
 * blocklists, baseline}} as normalizeSettings in control.js returns them.
 */
function compileGeneration(policies, trusted, generation, options) {
  if (generation !== 0 && generation !== 1) fail('generation must be 0 or 1');
  if (trusted.length > MAX_TRUSTED) fail('信任来源最多 ' + MAX_TRUSTED + ' 个');
  options = options || {};
  var setIds = options.setIds || {};
  var settings = options.settings || {};
  var setId = function (name) {
    if (!setIds[name]) fail('集合不存在: ' + name);
    return setIds[name];
  };
  var words = [[], []];
  for (var p = 0; p < 2; p++) for (var w = 0; w < PORT_WORDS; w++) words[p].push([0, 0]);
  var classes = {};
  var classList = [];
  var lpm = {fw_ports: [], fw_dst4: [], fw_dst6: [], fw_src4: [], fw_src6: []};
  var classFor = function (id, covering) {
    var cls = classes[id];
    if (cls) return cls;
    if (classList.length >= MAX_CLASSES) fail('端口划分过细：端口类超过 ' + MAX_CLASSES + ' 个');
    cls = {id: classList.length + 1, anyPolicy: 0, scoped: []};
    covering.forEach(function (pol) {
      if (pol.destinations.length) cls.scoped.push(pol);
      else cls.anyPolicy = pol.slot;
    });
    classes[id] = cls;
    classList.push(cls);
    return cls;
  };

  for (var proto = 0; proto < PROTO_NAMES.length; proto++) {
    var members = policies.filter(function (pol) { return !!pol.match[proto]; });
    var cuts = {};
    members.forEach(function (pol) {
      pol.match[proto].forEach(function (r) { cuts[r[0]] = true; cuts[r[1] + 1] = true; });
    });
    var bounds = Object.keys(cuts).map(Number).sort(function (x, y) { return x - y; });
    for (var i = 0; i + 1 < bounds.length; i++) {
      var lo = bounds[i], hi = bounds[i + 1] - 1;
      var covering = members.filter(function (pol) {
        return pol.match[proto].some(function (r) { return r[0] <= lo && lo <= r[1]; });
      });
      if (!covering.length) continue;
      var cls = classFor(covering.map(function (pol) { return pol.slot; }).sort(function (x, y) { return x - y; }).join(','), covering);
      portPrefixes(lo, hi).forEach(function (pfx) {
        lpm.fw_ports.push({key: portKey(generation, proto, pfx.port, pfx.prefix), value: u32le(cls.id)});
      });
      if (proto > PROTO_UDP) continue;
      for (var port = lo; port <= hi; port++) {
        var word = words[proto][port >> 6];
        var bit = port & 63;
        if (bit < 32) word[0] = (word[0] | (1 << bit)) >>> 0;
        else word[1] = (word[1] | (1 << (bit - 32))) >>> 0;
      }
    }
  }
  if (lpm.fw_ports.length > PORT_PREFIX_CAPACITY) fail('端口前缀超过容量 ' + PORT_PREFIX_CAPACITY);
  // The catch-all policies share one class: packets no other class takes.
  var catchAll = policies.filter(function (pol) { return pol.any; });
  var anyClass = catchAll.length ? classFor('any:' + catchAll.map(function (pol) { return pol.slot; }).sort().join(','), catchAll).id : 0;

  var arrays = {fw_port_bits: {}, fw_class: {}, fw_policy: {}, fw_limit: {}, fw_pext: {}, fw_gcfg: {}};
  for (var bp = 0; bp < 2; bp++) {
    for (var wi = 0; wi < PORT_WORDS; wi++) {
      var pair = words[bp][wi];
      if (pair[0] || pair[1])
        arrays.fw_port_bits[generation * PORT_WORDS_PER_GEN + bp * PORT_WORDS + wi] = u32le(pair[0]) + u32le(pair[1]);
    }
  }
  classList.forEach(function (cls) {
    arrays.fw_class[generation * CLASSES_PER_GEN + cls.id] = u16le(cls.anyPolicy) + u8(cls.scoped.length ? 1 : 0) + '00';
    cls.scoped.forEach(function (pol) {
      pol.destinations.forEach(function (cidr) {
        lpm[cidr.family === 4 ? 'fw_dst4' : 'fw_dst6'].push({key: addrKey(generation, cls.id, cidr), value: u32le(pol.slot)});
      });
    });
  });
  var proto2 = false;
  policies.forEach(function (pol) {
    var index = generation * POLICIES_PER_GEN + pol.slot;
    var limit = pol.synLimit;
    if (pol.match[PROTO_ICMP] || pol.match[PROTO_ICMPV6] || pol.match[PROTO_IP]) proto2 = true;
    arrays.fw_policy[index] = u8(POLICY_VALID | (limit ? POLICY_LIMIT : 0)) + u8(pol.defaultAction) + '0000';
    if (limit) {
      arrays.fw_limit[index] = u32le(limit.maxNew) + u32le(limit.windowSeconds) + u32le(limit.banSeconds) +
        u8(limit.ipv6Prefix) + '000000' + prefixMaskHex(limit.ipv6Prefix);
    }
    var ext = pextHex(pol, setId);
    if (ext !== PEXT_VALUE_ZERO) arrays.fw_pext[index] = ext;
    pol.sources.forEach(function (src) {
      lpm[src.cidr.family === 4 ? 'fw_src4' : 'fw_src6'].push({key: addrKey(generation, pol.slot, src.cidr), value: u8(src.action) + '000000'});
    });
  });
  trusted.forEach(function (cidr) {
    lpm[cidr.family === 4 ? 'fw_src4' : 'fw_src6'].push({key: addrKey(generation, 0, cidr), value: u8(ACTION_PASS) + '000000'});
  });
  ['fw_dst4', 'fw_dst6'].forEach(function (name) {
    if (lpm[name].length > DST_CAPACITY) fail('目标地址条目超过容量 ' + DST_CAPACITY);
  });
  ['fw_src4', 'fw_src6'].forEach(function (name) {
    if (lpm[name].length > SRC_CAPACITY) fail('来源条目超过容量 ' + SRC_CAPACITY);
  });

  var baseline = settings.baseline || {};
  var gflags = (settings.connectionTracking ? G_CT : 0) |
    (baseline.bogonSources && baseline.bogonSources !== 'off' ? G_BOGON : 0) |
    (baseline.invalidTcpFlags ? G_BAD_FLAGS : 0) |
    (baseline.dropFragments ? G_DROP_FRAGS : 0) |
    (baseline.urpf === 'loose' ? G_URPF_LOOSE : 0) |
    (baseline.urpf === 'strict' ? G_URPF_STRICT : 0) |
    (proto2 ? G_PROTO : 0);
  var blocks = (settings.blocklists || []).map(setId);
  if (blocks.length > BLOCK_SETS) fail('黑名单集合最多 ' + BLOCK_SETS + ' 个');
  var gcfg = u32le(gflags) + u16le(anyClass) + u8(blocks.length) + '00';
  for (var b = 0; b < BLOCK_SETS; b++) gcfg += u16le(blocks[b] || 0);
  if (gcfg !== GCFG_VALUE_ZERO) arrays.fw_gcfg[generation] = gcfg;
  return {
    arrays: arrays,
    lpm: lpm,
    active: policies.length > 0,
    summary: {
      policies: policies.length,
      classes: classList.length,
      port_prefixes: lpm.fw_ports.length,
      destinations: lpm.fw_dst4.length + lpm.fw_dst6.length,
      sources: lpm.fw_src4.length + lpm.fw_src6.length,
      syn_limited: policies.filter(function (pol) { return pol.synLimit; }).length,
      catch_all: catchAll.length,
      blocklists: blocks.length
    }
  };
}

/* fw_pext of a policy: struct fw_pext in firewall.bpf.c (40 bytes). */
function pextHex(pol, setId) {
  var flags = (pol.newOnly ? PX_NEW_ONLY : 0) | (pol.addToSet ? PX_ADD_SET : 0);
  var add = pol.addToSet;
  var hex = u8(flags) + u8(pol.sourceSets.length) + u16le(add ? setId(add.set) : 0) + u32le(add ? add.seconds : 0);
  for (var i = 0; i < PX_SETS; i++) hex += u16le(pol.sourceSets[i] ? setId(pol.sourceSets[i].set) : 0);
  for (var j = 0; j < PX_SETS; j++) hex += u8(pol.sourceSets[j] ? pol.sourceSets[j].action : 0);
  hex += u8(add ? add.ipv6Prefix : 0) + '000000' + (add ? prefixMaskHex(add.ipv6Prefix) : '00'.repeat(16));
  return hex;
}

// -------------------------------------------------------------------- sets

/* A sets record: {key, name, elements (parsed CIDRs), remark}. */
function normalizeSet(key, data) {
  if (!SET_NAME.test(String(key))) fail('集合名无效: ' + key + '（小写字母、数字、- 和 _，最长 48）');
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('集合 ' + key + ': 内容必须是对象');
  var label = '集合 ' + key;
  var elements = (data.elements || []).map(function (raw) { return parseCIDR(raw); });
  if (elements.length > MAX_SET_ELEMENTS) fail(label + ': 静态元素最多 ' + MAX_SET_ELEMENTS + ' 个');
  var seen = {};
  elements.forEach(function (cidr) {
    if (seen[cidr.text]) fail(label + ': 元素重复: ' + cidr.text);
    seen[cidr.text] = true;
  });
  return {key: String(key), name: String(data.name || key), elements: elements};
}

/* Stable set ids, like policy slots. */
function assignSetIds(keys, ids) {
  var next = {};
  var used = {};
  keys.forEach(function (key) {
    var id = ids && ids[key];
    if (id >= 1 && id <= MAX_SETS && !used[id]) {
      next[key] = id;
      used[id] = true;
    }
  });
  var held = {};
  Object.keys(ids || {}).forEach(function (key) { held[ids[key]] = true; });
  var fresh = [];
  keys.forEach(function (key) {
    if (next[key]) return;
    var id = 0;
    for (var s = 1; s <= MAX_SETS && !id; s++) if (!used[s] && !held[s]) id = s;
    for (var t = 1; t <= MAX_SETS && !id; t++) if (!used[t]) id = t;
    if (!id) fail('集合最多 ' + MAX_SETS + ' 个');
    next[key] = id;
    used[id] = true;
    fresh.push(id);
  });
  return {ids: next, fresh: fresh};
}

/* fw_sets key: {prefixlen, family, pad, id (network order), addr[16]}. */
function setKey(id, cidr) {
  var addr = bytesHex(cidr.bytes);
  return u32le(32 + cidr.prefix) + u8(cidr.family) + '00' + u16be(id) + (addr + '0'.repeat(32)).slice(0, 32);
}

/* A little-endian u64 of nanoseconds from milliseconds, exact below 2^53/15625 ms. */
function u64leNsFromMs(ms) {
  var q = Math.round(ms) * 15625; // ns = q * 64
  var hi = Math.floor(q / 67108864);
  var lo = (q % 67108864) * 64;
  return u32le(lo >>> 0) + u32le(hi >>> 0);
}

/* fw_sets value: {expires_ns, kind}; expiresMs 0 = until removed. */
function setValue(expiresMs, kind) {
  return (expiresMs ? u64leNsFromMs(expiresMs) : '0000000000000000') + u32le(kind) + '00000000';
}

function decodeSetKey(keyHex) {
  if (!keyHex || keyHex.length < 48) return null;
  var prefixlen = hexU32le(keyHex, 0) - 32;
  var family = parseInt(keyHex.substr(8, 2), 16);
  if ((family !== 4 && family !== 6) || prefixlen < 0 || prefixlen > (family === 4 ? 32 : 128)) return null;
  return {id: hexU16be(keyHex, 12), family: family, prefix: prefixlen, cidr: addressFromHex(family, keyHex.substr(16)) + '/' + prefixlen};
}

function decodeSetValue(valueHex) {
  if (!valueHex || valueHex.length < 32) return null;
  return {expiresMs: hexU64leMs(valueHex, 0), kind: SET_KINDS[hexU32le(valueHex, 16)] || 'unknown'};
}

/*
 * The static fw_sets entries of the normalized sets (each with .id) and of
 * the bogon prefixes baseline.bogonSources asks for: {key: value}.
 */
function compileSets(sets, baseline) {
  var out = {};
  var total = 0;
  sets.forEach(function (set) {
    set.elements.forEach(function (cidr) {
      out[setKey(set.id, cidr)] = setValue(0, SET_KIND_STATIC);
      total++;
    });
  });
  if (total > SET_STATIC_CAPACITY) fail('集合静态元素合计超过容量 ' + SET_STATIC_CAPACITY);
  var bogons = baseline && baseline.bogonSources;
  if (bogons === 'reserved' || bogons === 'all') {
    var list = bogons === 'all' ? BOGONS_RESERVED.concat(BOGONS_PRIVATE) : BOGONS_RESERVED;
    list.forEach(function (text) { out[setKey(SET_BOGON, parseCIDR(text))] = setValue(0, SET_KIND_STATIC); });
  }
  return out;
}

// ------------------------------------------------------------ bans and log

function hexU16le(hex, offset) { return parseInt(hex.substr(offset + 2, 2) + hex.substr(offset, 2), 16); }
function hexU16be(hex, offset) { return parseInt(hex.substr(offset, 4), 16); }
function hexU32le(hex, offset) { return hexU16le(hex, offset) + hexU16le(hex, offset + 4) * 65536; }
/* A little-endian u64 of nanoseconds, as milliseconds (exact enough). */
function hexU64leMs(hex, offset) { return (hexU32le(hex, offset) + hexU32le(hex, offset + 8) * 4294967296) / 1e6; }

function addressFromHex(family, hex) {
  var bytes = [];
  for (var i = 0; i < (family === 4 ? 4 : 16); i++) bytes.push(parseInt(hex.substr(i * 2, 2), 16));
  return formatAddress(family, bytes);
}

/* fw_ban / fw_rate key: {family u8, prefix u8, slot u16le, addr[16]}. */
function decodeLimitKey(keyHex) {
  var family = parseInt(keyHex.substr(0, 2), 16);
  var prefix = parseInt(keyHex.substr(2, 2), 16);
  if ((family !== 4 && family !== 6) || keyHex.length < 40) return null;
  return {family: family, prefix: prefix, slot: hexU16le(keyHex, 4), source: addressFromHex(family, keyHex.substr(8)) + '/' + prefix};
}

/* fw_ban value: the ban's end, ktime ns as milliseconds. */
function decodeBanUntilMs(valueHex) { return hexU64leMs(valueHex, 0); }

/* struct fw_event in firewall.bpf.c (56 bytes). */
function decodeEvent(hex) {
  if (!hex || hex.length < EVENT_BYTES * 2) return null;
  var family = parseInt(hex.substr(30, 2), 16);
  var proto = parseInt(hex.substr(32, 2), 16);
  var event = {
    time_ms: hexU64leMs(hex, 0),
    ifindex: hexU32le(hex, 16),
    slot: hexU16le(hex, 24),
    reason: REASONS[parseInt(hex.substr(28, 2), 16)] || 'unknown',
    protocol: PROTO_NAMES[proto] || '',
    source_port: hexU16be(hex, 36),
    port: hexU16be(hex, 40),
    source: '',
    destination: ''
  };
  // ICMP keeps type and code in the port field, other protocols their number.
  if (proto === PROTO_ICMP || proto === PROTO_ICMPV6) {
    event.icmp_type = event.port >> 8;
    event.icmp_code = event.port & 255;
    event.port = 0;
    event.source_port = 0;
  } else if (proto === PROTO_IP) {
    event.ip_protocol = event.port >> 8;
    event.port = 0;
    event.source_port = 0;
  }
  if (family === 4 || family === 6) {
    event.source = addressFromHex(family, hex.substr(48, 32));
    event.destination = addressFromHex(family, hex.substr(80, 32));
  }
  return event;
}

function lstatsKey(slot, counter) { return u32le(slot * LCOUNTERS + counter); }

// The generation byte of any key the LPM maps hold: right after prefixlen.
function keyGeneration(keyHex) {
  return parseInt(keyHex.substr(8, 2), 16);
}

function arrayIndexGeneration(map, index) {
  if (map === 'fw_port_bits') return Math.floor(index / PORT_WORDS_PER_GEN);
  if (map === 'fw_class') return Math.floor(index / CLASSES_PER_GEN);
  if (map === 'fw_gcfg') return index;
  return Math.floor(index / POLICIES_PER_GEN);
}

function gstatsKey(counter) { return u32le(counter); }

function statsKey(slot, counter) {
  return u32le(slot * COUNTERS + counter);
}

// Sums a per-CPU u64 value (array of little-endian hex strings).
function sumPerCPU(values) {
  var total = 0;
  (values || []).forEach(function (hex) {
    var v = 0;
    for (var i = Math.min(hex.length, 16) - 2; i >= 0; i -= 2) v = v * 256 + parseInt(hex.substr(i, 2), 16);
    total += v;
  });
  return total;
}

module.exports = {
  MAX_POLICY_SLOT: MAX_POLICY_SLOT,
  PORT_WORDS_PER_GEN: PORT_WORDS_PER_GEN,
  CLASSES_PER_GEN: CLASSES_PER_GEN,
  POLICIES_PER_GEN: POLICIES_PER_GEN,
  COUNTERS: COUNTERS,
  ACTION_PASS: ACTION_PASS,
  ACTION_DROP: ACTION_DROP,
  u8: u8, u16le: u16le, u16be: u16be, u32le: u32le, bytesHex: bytesHex,
  parseCIDR: parseCIDR,
  cidrOverlap: cidrOverlap,
  parsePortRanges: parsePortRanges,
  normalizePolicy: normalizePolicy,
  findConflicts: findConflicts,
  findWarnings: findWarnings,
  warningsToken: warningsToken,
  prefixMaskHex: prefixMaskHex,
  decodeLimitKey: decodeLimitKey,
  decodeBanUntilMs: decodeBanUntilMs,
  decodeEvent: decodeEvent,
  lstatsKey: lstatsKey,
  LCNT_BAN: LCNT_BAN,
  LCNT_RATE: LCNT_RATE,
  LCNT_LOGGED: LCNT_LOGGED,
  LCNT_LOST: LCNT_LOST,
  LIMIT_VALUE_ZERO: LIMIT_VALUE_ZERO,
  EVENT_BYTES: EVENT_BYTES,
  assignSlots: assignSlots,
  portPrefixes: portPrefixes,
  compileGeneration: compileGeneration,
  keyGeneration: keyGeneration,
  arrayIndexGeneration: arrayIndexGeneration,
  statsKey: statsKey,
  sumPerCPU: sumPerCPU,
  PROTO_NAMES: PROTO_NAMES,
  PEXT_VALUE_ZERO: PEXT_VALUE_ZERO,
  GCFG_VALUE_ZERO: GCFG_VALUE_ZERO,
  GCOUNTERS: GCOUNTERS,
  gstatsKey: gstatsKey,
  MAX_SETS: MAX_SETS,
  SET_BOGON: SET_BOGON,
  SET_KIND_STATIC: SET_KIND_STATIC,
  SET_KIND_API: SET_KIND_API,
  SET_KIND_POLICY: SET_KIND_POLICY,
  SET_NAME: SET_NAME,
  BLOCK_SETS: BLOCK_SETS,
  BOGONS_RESERVED: BOGONS_RESERVED,
  BOGONS_PRIVATE: BOGONS_PRIVATE,
  parseIcmpTypes: parseIcmpTypes,
  parseIpProtocols: parseIpProtocols,
  normalizeSet: normalizeSet,
  assignSetIds: assignSetIds,
  setKey: setKey,
  setValue: setValue,
  decodeSetKey: decodeSetKey,
  decodeSetValue: decodeSetValue,
  compileSets: compileSets,
  u64leNsFromMs: u64leNsFromMs,
  pextHex: pextHex
};
