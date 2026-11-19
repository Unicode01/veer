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

var PROTO_TCP = 0;
var PROTO_UDP = 1;
var ACTION_PASS = 0;
var ACTION_DROP = 1;

var POLICY_VALID = 1;
var POLICY_LIMIT = 2;
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

var EVENT_BYTES = 56;
var REASONS = {1: 'acl', 2: 'ban', 3: 'rate', 4: 'evasive'};

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

/*
 * Validates one policy record and returns its normalized form:
 * {key, name, protocols, ranges, destinations, defaultAction, sources}.
 */
function normalizePolicy(key, data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('策略 ' + key + ': 内容必须是对象');
  var label = '策略 ' + (data.name || key);
  var protocol = data.protocol || 'tcp';
  var protocols;
  if (protocol === 'tcp') protocols = [PROTO_TCP];
  else if (protocol === 'udp') protocols = [PROTO_UDP];
  else if (protocol === 'tcp+udp') protocols = [PROTO_TCP, PROTO_UDP];
  else fail(label + ': 协议必须是 tcp、udp 或 tcp+udp');
  var destinations = (data.destinations || []).map(parseCIDR);
  if (destinations.length > MAX_DESTINATIONS) fail(label + ': 目标地址最多 ' + MAX_DESTINATIONS + ' 个');
  var sources = (data.sources || []).map(function (entry) {
    if (!entry || typeof entry !== 'object') fail(label + ': 来源条目必须是 {cidr, action}');
    return {cidr: parseCIDR(entry.cidr), action: parseAction(entry.action, label)};
  });
  if (sources.length > MAX_SOURCES) fail(label + ': 来源最多 ' + MAX_SOURCES + ' 个');
  var seen = {};
  sources.forEach(function (s) {
    if (seen[s.cidr.text]) fail(label + ': 来源重复: ' + s.cidr.text);
    seen[s.cidr.text] = true;
  });
  return {
    key: key,
    name: String(data.name || key),
    protocols: protocols,
    ranges: parsePortRanges(data.ports, label),
    destinations: destinations,
    defaultAction: parseAction(data.default_action || 'drop', label),
    sources: sources,
    synLimit: parseSynLimit(data.syn_limit, protocols, label)
  };
}

function rangesIntersect(a, b) {
  for (var i = 0; i < a.length; i++)
    for (var j = 0; j < b.length; j++)
      if (a[i][0] <= b[j][1] && b[j][0] <= a[i][1]) return [Math.max(a[i][0], b[j][0])];
  return null;
}

/*
 * Two policies conflict when they share a protocol and a port and either
 * names no destinations or their destinations overlap: the filter could not
 * tell which one a packet belongs to.
 */
function findConflicts(policies) {
  var errors = [];
  for (var i = 0; i < policies.length; i++) {
    for (var j = i + 1; j < policies.length; j++) {
      var a = policies[i], b = policies[j];
      var shared = a.protocols.filter(function (p) { return b.protocols.indexOf(p) >= 0; });
      if (!shared.length) continue;
      var port = rangesIntersect(a.ranges, b.ranges);
      if (!port) continue;
      var overlap = !a.destinations.length || !b.destinations.length;
      for (var x = 0; !overlap && x < a.destinations.length; x++)
        for (var y = 0; !overlap && y < b.destinations.length; y++)
          if (cidrOverlap(a.destinations[x], b.destinations[y])) overlap = true;
      if (overlap) {
        errors.push('策略 ' + a.name + ' 和 ' + b.name + ' 在 ' + (shared[0] === PROTO_TCP ? 'tcp' : 'udp') +
          ' 端口 ' + port[0] + ' 上作用于相同的目标地址');
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
 * policies that drop unlisted sources can: one covering a management port
 * with no trusted source, or one covering ports that replies to outbound
 * connections use (the filter keeps no connection state, so a reply is just
 * another packet from an unlisted source). A single port in the ephemeral
 * range is left alone: a local listener keeps the kernel from picking it.
 * Returns [{id, policy, message}].
 */
function findWarnings(policies, trusted) {
  var warnings = [];
  policies.forEach(function (p) {
    if (p.defaultAction !== ACTION_DROP) return;
    var label = '策略 ' + p.name;
    if (!trusted.length && p.protocols.indexOf(PROTO_TCP) >= 0) {
      var hit = MANAGEMENT_PORTS.filter(function (m) {
        return p.ranges.some(function (r) { return r[0] <= m.port && m.port <= r[1]; });
      });
      if (hit.length) {
        warnings.push({
          id: 'lockout:' + p.key,
          policy: p.key,
          message: label + ' 默认丢弃 tcp ' + hit.map(function (m) { return m.port + '（' + m.name + '）'; }).join('、') +
            '，且没有信任来源：只有放行的来源还能连上。'
        });
      }
    }
    var nat = overlapWith(p.ranges, NAT_REPLY_PORTS, false);
    var ephemeral = overlapWith(p.ranges, EPHEMERAL_REPLY_PORTS, true);
    if (nat || ephemeral) {
      var parts = [];
      if (nat) parts.push(portText(nat) + ' 在 Veer 出向 NAT 的端口池（默认 20000-32767）内');
      if (ephemeral) parts.push(portText(ephemeral) + ' 在宿主出站连接的临时端口（默认 32768-60999）内');
      warnings.push({
        id: 'reply_ports:' + p.key,
        policy: p.key,
        message: label + ' 的端口 ' + parts.join('，') +
          '：过滤不跟踪连接，出站连接的回包也会按来源判断，对端不在放行列表里时回包被丢弃，连接失败。'
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
 *   arrays: {fw_port_bits, fw_class, fw_policy}: index -> value hex, only
 *           non-zero entries (the caller zeroes what an older rule set left);
 *   lpm:    {fw_ports, fw_dst4, fw_dst6, fw_src4, fw_src6}: [{key, value}];
 *   active: whether any policy exists.
 */
function compileGeneration(policies, trusted, generation) {
  if (generation !== 0 && generation !== 1) fail('generation must be 0 or 1');
  if (trusted.length > MAX_TRUSTED) fail('信任来源最多 ' + MAX_TRUSTED + ' 个');
  var words = [[], []];
  for (var p = 0; p < 2; p++) for (var w = 0; w < PORT_WORDS; w++) words[p].push([0, 0]);
  var classes = {};
  var classList = [];
  var lpm = {fw_ports: [], fw_dst4: [], fw_dst6: [], fw_src4: [], fw_src6: []};

  [PROTO_TCP, PROTO_UDP].forEach(function (proto) {
    var members = policies.filter(function (pol) { return pol.protocols.indexOf(proto) >= 0; });
    var cuts = {};
    members.forEach(function (pol) {
      pol.ranges.forEach(function (r) { cuts[r[0]] = true; cuts[r[1] + 1] = true; });
    });
    var bounds = Object.keys(cuts).map(Number).sort(function (x, y) { return x - y; });
    for (var i = 0; i + 1 < bounds.length; i++) {
      var lo = bounds[i], hi = bounds[i + 1] - 1;
      var covering = members.filter(function (pol) {
        return pol.ranges.some(function (r) { return r[0] <= lo && lo <= r[1]; });
      });
      if (!covering.length) continue;
      var id = covering.map(function (pol) { return pol.slot; }).sort(function (x, y) { return x - y; }).join(',');
      var cls = classes[id];
      if (!cls) {
        if (classList.length >= MAX_CLASSES) fail('端口划分过细：端口类超过 ' + MAX_CLASSES + ' 个');
        cls = {id: classList.length + 1, anyPolicy: 0, scoped: []};
        covering.forEach(function (pol) {
          if (pol.destinations.length) cls.scoped.push(pol);
          else cls.anyPolicy = pol.slot;
        });
        classes[id] = cls;
        classList.push(cls);
      }
      portPrefixes(lo, hi).forEach(function (pfx) {
        lpm.fw_ports.push({key: portKey(generation, proto, pfx.port, pfx.prefix), value: u32le(cls.id)});
      });
      for (var port = lo; port <= hi; port++) {
        var word = words[proto][port >> 6];
        var bit = port & 63;
        if (bit < 32) word[0] = (word[0] | (1 << bit)) >>> 0;
        else word[1] = (word[1] | (1 << (bit - 32))) >>> 0;
      }
    }
  });
  if (lpm.fw_ports.length > PORT_PREFIX_CAPACITY) fail('端口前缀超过容量 ' + PORT_PREFIX_CAPACITY);

  var arrays = {fw_port_bits: {}, fw_class: {}, fw_policy: {}, fw_limit: {}};
  for (var proto = 0; proto < 2; proto++) {
    for (var wi = 0; wi < PORT_WORDS; wi++) {
      var pair = words[proto][wi];
      if (pair[0] || pair[1])
        arrays.fw_port_bits[generation * PORT_WORDS_PER_GEN + proto * PORT_WORDS + wi] = u32le(pair[0]) + u32le(pair[1]);
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
  policies.forEach(function (pol) {
    var index = generation * POLICIES_PER_GEN + pol.slot;
    var limit = pol.synLimit;
    arrays.fw_policy[index] = u8(POLICY_VALID | (limit ? POLICY_LIMIT : 0)) + u8(pol.defaultAction) + '0000';
    if (limit) {
      arrays.fw_limit[index] = u32le(limit.maxNew) + u32le(limit.windowSeconds) + u32le(limit.banSeconds) +
        u8(limit.ipv6Prefix) + '000000' + prefixMaskHex(limit.ipv6Prefix);
    }
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
      syn_limited: policies.filter(function (pol) { return pol.synLimit; }).length
    }
  };
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
    protocol: proto === PROTO_TCP ? 'tcp' : proto === PROTO_UDP ? 'udp' : '',
    source_port: hexU16be(hex, 36),
    port: hexU16be(hex, 40),
    source: '',
    destination: ''
  };
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
  return Math.floor(index / POLICIES_PER_GEN);
}

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
  sumPerCPU: sumPerCPU
};
