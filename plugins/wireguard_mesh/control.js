// Local, opt-in example. Only fixed executables and structured argv reach exec.
var IP = '/usr/sbin/ip';
var WG = '/usr/bin/wg';
var NFT = '/usr/sbin/nft';
var TC = '/usr/sbin/tc';
var SYSCTL = '/usr/sbin/sysctl';
var PROTOCOL = '242';
plugin.capabilities(['wireguard', 'policy_routing', 'control']);
plugin.resource({id: 'profiles', methods: ['list', 'get', 'create', 'update'], runtime_update: 'manual', max_records: 8, max_record_bytes: 16384,
  schema: {type: 'object', additionalProperties: false, properties: {
    slot: {type: 'integer'}, mtu: {type: 'integer'}, listen_port: {type: 'integer'}, masquerade: {type: 'boolean'},
    addresses: {type: 'array', items: {type: 'string'}}, bypass_cidrs: {type: 'array', items: {type: 'string'}},
    peers: {type: 'array', items: {type: 'object', additionalProperties: false, properties: {
      public_key: {type: 'string'}, endpoint: {type: 'string'}, allowed_ips: {type: 'array', items: {type: 'string'}},
      keepalive: {type: 'integer'}, preshared_key_secret: {type: 'string'}
    }}}, bindings: {type: 'array', items: {type: 'object', additionalProperties: false, properties: {
      lan_interface: {type: 'string'}, source: {type: 'string'}, destination: {type: 'string'}
    }}}
  }}});
plugin.resource({id: 'status', methods: ['list', 'get'], control_methods: ['list', 'get', 'create', 'update', 'delete'], runtime_update: 'manual', max_records: 8, max_record_bytes: 32768});
plugin.action({id: 'set_key', description: 'Store a private or preshared key in the encrypted Secret store.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'apply', description: 'Apply a stored WireGuard profile; key/slot identity is immutable until teardown.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'teardown', description: 'Remove this profile\'s routes, rules, firewall table and owned WireGuard interface.', runtime_update: 'runtime_apply', max_payload_bytes: 2048});
plugin.action({id: 'inspect', description: 'Read public keys, endpoints, handshake ages and transfer counters without reading private keys.', runtime_update: 'runtime_query', max_payload_bytes: 2048});
ui.register({static_dir: 'ui', entry: 'index.html', page: 'wireguard', page_title: 'WireGuard',
  resources: [{resource: 'profiles', methods: ['list', 'get', 'create', 'update']}, {resource: 'status', methods: ['list']}],
  actions: ['set_key', 'apply', 'teardown', 'inspect']});

exports.onAction = function (ctx) {
  var payload = ctx.payload || {};
  var key = profileKey(payload.key);
  if (ctx.action.id === 'set_key') {
    var value = wgKey(payload.value);
    var name = payload.name ? token(payload.name) : 'private_' + key;
    var publicKey = '';
    if (name === 'private_' + key) publicKey = command(WG, ['pubkey'], value + '\n').trim();
    secret.set(name, value);
    return {stored: true, name: name, public_key: publicKey};
  }
  if (ctx.action.id === 'inspect') return inspect(key);
  if (ctx.action.id === 'teardown') { teardown(key); return {phase: 'down'}; }
  if (ctx.action.id === 'apply') {
    var record = resources.get('profiles', key);
    if (!record || record.enabled === false) throw new Error('Save and enable the profile first');
    return apply(key, record.data);
  }
  throw new Error('Unsupported action');
};

// Restart restores only explicitly applied profiles, never a newly saved draft.
exports.onReconcile = function () {
  var leases = allLeases();
  Object.keys(leases).sort().forEach(function (key) {
    if (!leases[key].active) return;
    var record = resources.get('profiles', key);
    if (!record || record.enabled === false) { teardown(key); return; }
    try { apply(key, leases[key].settings); }
    catch (e) { resources.set('status', key, {phase: 'error', error: String(e.message || e)}, true); }
  });
};
exports.onDeactivate = function () {
  var failures = [];
  Object.keys(allLeases()).forEach(function (key) {
    try { teardown(key); } catch (e) { failures.push(key + ': ' + String(e.message || e)); }
  });
  if (failures.length) throw new Error('WireGuard cleanup incomplete: ' + failures.join('; '));
};

function allLeases() {
  var out = {};
  kv.list({limit: 32}).forEach(function (record) {
    if (record.key.indexOf('lease_') === 0) out[record.key.slice(6)] = record.data;
  });
  return out;
}

function execute(program, args, stdin) {
  var result = process.exec({command: program, args: args, stdin: stdin || '', timeout_ms: 2000});
  if (result.timed_out || result.cancelled || result.truncated) throw new Error('Command did not complete: ' + program);
  return result;
}
function command(program, args, stdin) {
  var result = execute(program, args, stdin);
  // wg/nft diagnostics can quote their input, including keys. Never expose stderr.
  if (result.exit_code !== 0) throw new Error('Command failed: ' + program + ' ' + args[0] + ' (exit ' + result.exit_code + ')');
  return result.stdout || '';
}
function ip(args) { return command(IP, args); }
function jsonIP(args) { return JSON.parse(ip(['-j'].concat(args)) || '[]'); }
function token(value) {
  var text = String(value || '');
  if (!/^[a-z][a-z0-9_]{0,31}$/.test(text)) throw new Error('Invalid identifier');
  return text;
}
function profileKey(value) {
  var key = token(value || 'default');
  if (key.length > 11) throw new Error('Profile key must be at most 11 characters');
  return key;
}
function integer(value, min, max, fallback) {
  var n = value == null ? fallback : Number(value);
  if (!isFinite(n) || Math.floor(n) !== n || n < min || n > max) throw new Error('Integer outside allowed range');
  return n;
}
function iface(value) {
  var name = String(value || '');
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$/.test(name)) throw new Error('Invalid LAN interface');
  return name;
}
function wgKey(value) {
  var key = String(value || '').trim();
  if (!/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(key) || key === 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=') throw new Error('Invalid WireGuard key');
  return key;
}
function list(value, min, max) {
  if (!Array.isArray(value) || value.length < min || value.length > max) throw new Error('List outside allowed size');
  return value;
}
function address(value) {
  var text = String(value);
  var bytes = [], parts, i;
  if (text.indexOf(':') < 0) {
    parts = text.split('.');
    if (parts.length !== 4) throw new Error('Invalid IPv4 address');
    for (i = 0; i < 4; i++) {
      if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i]) || Number(parts[i]) > 255) throw new Error('Invalid IPv4 address');
      bytes.push(Number(parts[i]));
    }
    return bytes;
  }
  if (!/^[0-9a-fA-F:]+$/.test(text) || text.indexOf(':::') >= 0) throw new Error('Invalid IPv6 address');
  parts = text.split('::');
  if (parts.length > 2) throw new Error('Invalid IPv6 address');
  var left = parts[0] ? parts[0].split(':') : [];
  var right = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  var count = left.length + right.length;
  if ((parts.length === 1 && count !== 8) || (parts.length === 2 && count >= 8)) throw new Error('Invalid IPv6 address');
  var groups = left.slice();
  if (parts.length === 2) for (i = count; i < 8; i++) groups.push('0');
  groups = groups.concat(right);
  groups.forEach(function (group) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) throw new Error('Invalid IPv6 address');
    var n = parseInt(group, 16); bytes.push(n >> 8, n & 255);
  });
  return bytes;
}
function addressText(bytes) {
  if (bytes.length === 4) return bytes.join('.');
  var groups = [];
  for (var i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  return groups.join(':');
}
function prefix(value, preserveHost) {
  var parts = String(value || '').split('/');
  if (parts.length > 2) throw new Error('Invalid CIDR');
  var bytes = address(parts[0]);
  if (parts.length === 2 && !/^(0|[1-9][0-9]{0,2})$/.test(parts[1])) throw new Error('Invalid CIDR length');
  var bits = integer(parts.length === 2 ? parts[1] : bytes.length * 8, 0, bytes.length * 8);
  var network = bytes.map(function (b, i) { var remain = bits - i * 8; return remain >= 8 ? b : remain <= 0 ? 0 : b & (255 << (8 - remain)); });
  return {text: addressText(preserveHost ? bytes : network) + '/' + bits, bytes: network, bits: bits, family: bytes.length === 4 ? '4' : '6'};
}
function covers(a, b) {
  if (a.family !== b.family || a.bits > b.bits) return false;
  for (var i = 0; i < a.bytes.length; i++) {
    var remain = a.bits - i * 8, mask = remain >= 8 ? 255 : remain <= 0 ? 0 : (255 << (8 - remain)) & 255;
    if ((a.bytes[i] & mask) !== (b.bytes[i] & mask)) return false;
  }
  return true;
}
function normalize(key, raw) {
  raw = raw || {};
  var p = {key: key, slot: integer(raw.slot, 1, 8, 1), interface: 'vwg' + key,
    mtu: integer(raw.mtu, 576, 9000, 1420), listen_port: integer(raw.listen_port, 0, 65535, 0), masquerade: raw.masquerade === true};
  p.table = 52000 + p.slot; p.priority = 22000 + p.slot * 32;
  p.owner = 'veer:wireguard_mesh:' + key; p.nft = 'veer_wg_' + p.slot;
  p.addresses = list(raw.addresses, 1, 8).map(function (v) { return prefix(v, true).text; });
  p.bypass = list(raw.bypass_cidrs || [], 0, 32).map(function (v) { return prefix(v).text; });
  p.peers = list(raw.peers, 1, 8).map(function (peer) {
    var endpoint = String(peer.endpoint || '');
    if (endpoint) {
      var match = /^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)$/.exec(endpoint);
      if (!match) throw new Error('Endpoint must be a numeric IP:port (bracket IPv6)');
      address(match[1].replace(/[\[\]]/g, '')); integer(match[2], 1, 65535);
    }
    return {public_key: wgKey(peer.public_key), endpoint: endpoint,
      allowed_ips: list(peer.allowed_ips, 1, 32).map(function (v) { return prefix(v).text; }),
      keepalive: integer(peer.keepalive, 0, 65535, 25),
      preshared_key_secret: peer.preshared_key_secret ? token(peer.preshared_key_secret) : ''};
  });
  var seenPeers = {}, seenPrefixes = {};
  p.peers.forEach(function (peer) {
    if (seenPeers[peer.public_key]) throw new Error('Duplicate peer public key');
    seenPeers[peer.public_key] = true;
    peer.allowed_ips.forEach(function (cidr) {
      if (seenPrefixes[cidr]) throw new Error('AllowedIPs must not be duplicated across peers');
      seenPrefixes[cidr] = true;
    });
  });
  p.bindings = list(raw.bindings, 1, 16).map(function (b, index) {
    var src = prefix(b.source), dst = prefix(b.destination);
    if (src.family !== dst.family) throw new Error('Source and destination families differ');
    if (!p.peers.some(function (peer) { return peer.allowed_ips.some(function (v) { return covers(prefix(v), dst); }); })) throw new Error('Destination is not covered by peer AllowedIPs');
    return {lan_interface: iface(b.lan_interface), source: src.text, destination: dst.text, family: src.family, priority: p.priority + index};
  });
  if (p.mtu < 1280 && p.bindings.some(function (b) { return b.family === '6'; })) throw new Error('IPv6 requires MTU >= 1280');
  return p;
}
function settings(p) {
  return {slot: p.slot, mtu: p.mtu, listen_port: p.listen_port, masquerade: p.masquerade,
    addresses: p.addresses.slice(), bypass_cidrs: p.bypass.slice(), peers: p.peers,
    bindings: p.bindings.map(function (b) { return {lan_interface: b.lan_interface, source: b.source, destination: b.destination}; })};
}
function link(name) { return jsonIP(['link', 'show']).filter(function (l) { return l.ifname === name; })[0] || null; }
function ownedLink(p) {
  var current = link(p.interface);
  if (current && current.ifalias !== p.owner) throw new Error('Refusing to modify an existing unowned WireGuard interface');
  return current;
}
function table(p) {
  var result = execute(NFT, ['-j', 'list', 'table', 'inet', p.nft]);
  if (result.exit_code !== 0) {
    if (/No such file or directory/.test(result.stderr || '')) return null;
    throw new Error('Cannot inspect nftables ownership');
  }
  var items = JSON.parse(result.stdout).nftables || [];
  var existing = items.filter(function (v) { return v.table && v.table.name === p.nft; })[0];
  if (!existing || existing.table.comment !== p.owner) throw new Error('Reserved nftables table is owned by another configuration');
  return existing.table;
}
function routes(p, family) {
  var result = execute(IP, ['-j', '-' + family, 'route', 'show', 'table', String(p.table)]);
  if (result.exit_code !== 0) {
    if (/FIB table does not exist/.test(result.stderr || '')) return [];
    throw new Error('Cannot inspect routing table');
  }
  return JSON.parse(result.stdout || '[]');
}
function ruleArgs(p, b) {
  return ['priority', String(b.priority), 'from', b.source, 'to', b.destination, 'iif', b.lan_interface, 'table', String(p.table), 'protocol', PROTOCOL];
}
function ruleMatches(r, p, b) {
  function normalized(value, length) {
    if (!value || value === 'all') return b.family === '4' ? '0.0.0.0/0' : prefix('::/0').text;
    return prefix(value.indexOf('/') < 0 && length != null ? value + '/' + length : value).text;
  }
  return Number(r.priority) === b.priority && String(r.protocol) === PROTOCOL && Number(r.table) === p.table &&
    r.iif === b.lan_interface && normalized(r.src, r.srclen) === b.source && normalized(r.dst, r.dstlen) === b.destination;
}
function routeMatches(actual, planned) {
  var dst = actual.dst === 'default' ? (planned.family === '4' ? '0.0.0.0/0' : '::/0') : actual.dst;
  return dst && prefix(dst).text === prefix(planned.dst).text && String(actual.protocol) === PROTOCOL &&
    String(actual.metric || 0) === planned.metric && (actual.type || 'unicast') === (planned.type || 'unicast') &&
    (actual.dev || '') === (planned.dev || (planned.type && planned.family === '6' && actual.dev === 'lo' ? 'lo' : '')) && !actual.gateway && !actual.nexthops;
}
function preflight(p, old) {
  var owned = ownedLink(p), nft = table(p);
  if (!old && (owned || nft)) throw new Error('Recorded ownership is missing; inspect leftover resources before retrying');
  var leases = allLeases();
  Object.keys(leases).forEach(function (key) {
    if (key === p.key) return;
    var other = leases[key].plan;
    if (other.slot === p.slot) throw new Error('Slot is already reserved by another profile');
    p.bindings.forEach(function (a) { other.bindings.forEach(function (b) {
      if (a.lan_interface === b.lan_interface && coversEither(a.source, b.source) && coversEither(a.destination, b.destination)) throw new Error('Traffic selectors overlap another active profile');
    }); });
  });
  ['4', '6'].forEach(function (family) {
    var existing = routes(p, family);
    if (existing.some(function (r) {
      return !old || ![old.plan, old.previous].filter(Boolean).some(function (plan) {
        return routePlan(plan).some(function (planned) { return planned.family === family && routeMatches(r, planned); });
      });
    })) throw new Error('Routing table contains foreign routes');
    var rules = jsonIP(['-' + family, 'rule', 'show']);
    rules.forEach(function (r) {
      if (r.priority < p.priority || r.priority >= p.priority + 32) return;
      var owned = old && [old.plan, old.previous].filter(Boolean).some(function (plan) { return plan.bindings.some(function (b) { return ruleMatches(r, plan, b); }); });
      if (!owned) throw new Error('Policy rule priority is already in use');
    });
  });
  var inputs = {};
  p.bindings.forEach(function (b) { inputs[b.lan_interface] = true; });
  var links = jsonIP(['-d', 'link', 'show']);
  Object.keys(inputs).forEach(function (name) {
    var current = links.filter(function (l) { return l.ifname === name; })[0];
    if (!current || name === p.interface) throw new Error('LAN interface does not exist');
    // Linux policy routing cannot steer traffic already redirected by Veer TC/XDP.
    var attached = jsonIP(['address', 'show', 'dev', name]);
    (attached[0] && attached[0].addr_info || []).forEach(function (a) {
      if (a.scope !== 'global') return;
      var cidr = prefix(a.local + '/' + a.prefixlen).text;
      if (p.bypass.indexOf(cidr) < 0) p.bypass.push(cidr);
    });
  });
  // Check bridge members too: Veer can attach before packets reach the bridge.
  var changed = true;
  while (changed) {
    changed = false;
    links.forEach(function (l) {
      var master = links.filter(function (m) { return m.ifindex === l.master || m.ifname === l.master; })[0];
      if (master && inputs[master.ifname] && !inputs[l.ifname]) { inputs[l.ifname] = true; changed = true; }
    });
  }
  Object.keys(inputs).forEach(function (name) {
    var current = links.filter(function (l) { return l.ifname === name; })[0];
    if (current && current.xdp && current.xdp.attached && current.xdp.attached !== 'off') throw new Error('LAN fast-path conflict: remove XDP from ' + name);
    var filters = JSON.parse(command(TC, ['-j', 'filter', 'show', 'dev', name, 'ingress']) || '[]');
    if (filters.some(function (f) { return f.kind === 'bpf'; })) throw new Error('LAN fast-path conflict: disable Veer fast NAT/BPF on ' + name);
  });
  if (p.bindings.some(function (b) { return b.family === '4'; })) {
    if (command(SYSCTL, ['-n', 'net.ipv4.ip_forward']).trim() !== '1') throw new Error('Enable net.ipv4.ip_forward on the host first');
    if (command(SYSCTL, ['-n', 'net.ipv4.conf.all.rp_filter']).trim() === '1') throw new Error('Use loose/disabled global rp_filter for policy routing');
  }
  if (p.bindings.some(function (b) { return b.family === '6'; }) && command(SYSCTL, ['-n', 'net.ipv6.conf.all.forwarding']).trim() !== '1') throw new Error('Enable IPv6 forwarding on the host first');
}
function coversEither(a, b) { return covers(prefix(a), prefix(b)) || covers(prefix(b), prefix(a)); }
function configuration(p) {
  var lines = ['[Interface]', 'PrivateKey = ' + wgKey(secret.get('private_' + p.key)), 'ListenPort = ' + p.listen_port];
  p.peers.forEach(function (peer) {
    lines.push('[Peer]', 'PublicKey = ' + peer.public_key, 'AllowedIPs = ' + peer.allowed_ips.join(', '), 'PersistentKeepalive = ' + peer.keepalive);
    if (peer.endpoint) lines.push('Endpoint = ' + peer.endpoint);
    if (peer.preshared_key_secret) lines.push('PresharedKey = ' + wgKey(secret.get(peer.preshared_key_secret)));
  });
  return lines.join('\n') + '\n';
}
function firewall(p, existing, blocked) {
  var lines = [];
  if (existing) lines.push('delete table inet ' + p.nft);
  lines.push('add table inet ' + p.nft + ' { comment "' + p.owner + '"; }');
  lines.push('add chain inet ' + p.nft + ' forward { type filter hook forward priority -10; policy accept; }');
  lines.push('add chain inet ' + p.nft + ' nat { type nat hook postrouting priority 100; policy accept; }');
  p.bindings.forEach(function (b) {
    var family = b.family === '4' ? 'ip' : 'ip6';
    var select = 'iifname "' + b.lan_interface + '" ' + family + ' saddr ' + b.source;
    p.bypass.forEach(function (cidr) {
      if (prefix(cidr).family === b.family) lines.push('add rule inet ' + p.nft + ' forward ' + select + ' ' + family + ' daddr ' + cidr + ' return');
    });
    lines.push('add rule inet ' + p.nft + ' forward ' + select + ' ' + family + ' daddr ' + b.destination + (blocked ? '' : ' oifname != "' + p.interface + '"') + ' reject');
    if (!blocked && p.masquerade) lines.push('add rule inet ' + p.nft + ' nat ' + select + ' oifname "' + p.interface + '" ' + family + ' daddr ' + b.destination + ' masquerade');
  });
  command(NFT, ['-f', '/dev/stdin'], lines.join('\n') + '\n');
}
function routePlan(p) {
  var out = [];
  ['4', '6'].forEach(function (family) {
    if (!p.bindings.some(function (b) { return b.family === family; })) return;
    out.push({family: family, type: 'unreachable', dst: family === '4' ? '0.0.0.0/0' : '::/0', metric: '32760'});
    var seen = {};
    p.peers.forEach(function (peer) { peer.allowed_ips.forEach(function (cidr) {
      if (prefix(cidr).family !== family || seen[cidr]) return;
      seen[cidr] = true; out.push({family: family, dst: cidr, dev: p.interface, metric: '10'});
    }); });
    p.bypass.forEach(function (cidr) {
      if (prefix(cidr).family === family) out.push({family: family, type: 'throw', dst: cidr, metric: '1'});
    });
  });
  return out;
}
function routeArgs(p, r) {
  var args = r.type ? [r.type, r.dst] : [r.dst, 'dev', r.dev];
  return args.concat(['table', String(p.table), 'metric', r.metric, 'proto', PROTOCOL]);
}
function removePlan(p) {
  p.bindings.forEach(function (b) {
    var rules = jsonIP(['-' + b.family, 'rule', 'show']);
    if (rules.some(function (r) { return ruleMatches(r, p, b); })) ip(['-' + b.family, 'rule', 'del'].concat(ruleArgs(p, b)));
  });
  routePlan(p).forEach(function (r) {
    if (routes(p, r.family).some(function (v) { return routeMatches(v, r); })) ip(['-' + r.family, 'route', 'del'].concat(routeArgs(p, r)));
  });
}
function apply(key, raw) {
  var p = normalize(key, raw), old = allLeases()[key];
  var requested = settings(p);
  if (old && old.pending && JSON.stringify(old.settings) !== JSON.stringify(requested)) throw new Error('Retry the failed configuration or teardown before editing it');
  if (old && old.plan.slot !== p.slot) throw new Error('Teardown before changing the slot');
  preflight(p, old);
  var config = configuration(p); // Validate every secret before changing the host.
  var previous = old && (old.previous || old.plan);
  kv.set('lease_' + key, {active: true, pending: true, settings: requested, plan: p, previous: previous || null});
  try {
    firewall(p, !!table(p), true);
    // Remove only exact, protocol-tagged resources recorded by this plugin.
    if (previous) removePlan(previous);
    removePlan(p); // A prior attempt may have failed after installing some rules.
    if (!ownedLink(p)) {
      ip(['link', 'add', 'name', p.interface, 'type', 'wireguard']);
      ip(['link', 'set', 'dev', p.interface, 'alias', p.owner]);
    }
    command(WG, ['syncconf', p.interface, '/dev/stdin'], config);
    ip(['link', 'set', 'dev', p.interface, 'mtu', String(p.mtu), 'up']);
    if (p.bindings.some(function (b) { return b.family === '4'; })) command(SYSCTL, ['-w', 'net.ipv4.conf.' + p.interface + '.rp_filter=2']);
    var current = jsonIP(['address', 'show', 'dev', p.interface])[0];
    (current && current.addr_info || []).forEach(function (a) {
      var cidr = prefix(a.local + '/' + a.prefixlen, true).text;
      if (a.scope === 'global' && p.addresses.indexOf(cidr) < 0) ip(['address', 'del', cidr, 'dev', p.interface]);
    });
    p.addresses.forEach(function (cidr) { ip(['address', 'replace', cidr, 'dev', p.interface]); });
    routePlan(p).forEach(function (r) { ip(['-' + r.family, 'route', 'replace'].concat(routeArgs(p, r))); });
    p.bindings.forEach(function (b) { ip(['-' + b.family, 'rule', 'add'].concat(ruleArgs(p, b))); });
    firewall(p, true, false);
    kv.set('lease_' + key, {active: true, settings: requested, plan: p});
    resources.set('status', key, {phase: 'applied', interface: p.interface, table: p.table, bindings: p.bindings, masquerade: p.masquerade}, true);
    return {phase: 'applied', interface: p.interface, table: p.table};
  } catch (e) {
    // Keep the guard and lease on failure. A retry/teardown can recover exact state.
    resources.set('status', key, {phase: 'error', interface: p.interface, error: String(e.message || e), cleanup_required: true}, true);
    throw e;
  }
}
function teardown(key) {
  var lease = allLeases()[key];
  if (!lease) return;
  var p = lease.plan;
  ownedLink(p); var nft = table(p);
  if (lease.previous) removePlan(lease.previous);
  removePlan(p);
  if (ownedLink(p)) ip(['link', 'del', 'dev', p.interface]);
  // Teardown explicitly returns traffic to the system's normal routing policy.
  if (nft) command(NFT, ['delete', 'table', 'inet', p.nft]);
  kv.delete('lease_' + key);
  resources.set('status', key, {phase: 'down'}, false);
}
function inspect(key) {
  var lease = allLeases()[key];
  if (!lease) return {phase: 'down'};
  var p = lease.plan;
  if (!ownedLink(p)) return {phase: 'missing', interface: p.interface};
  return {phase: 'configured', interface: p.interface, public_key: command(WG, ['show', p.interface, 'public-key']).trim(),
    endpoints: command(WG, ['show', p.interface, 'endpoints']).trim(),
    latest_handshakes: command(WG, ['show', p.interface, 'latest-handshakes']).trim(),
    transfer: command(WG, ['show', p.interface, 'transfer']).trim()};
}
