'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {createTestHost} = require('../../sdk/plugin/test-host.cjs');

const LOCAL = 'veerlocal0';
const PIPE = 'veerpipe0';
const FULL_REPAIR_TICKS = 15;
const WRITES = ['net.link.ensureVeth', 'net.link.ensureDummy', 'net.link.setARP', 'net.link.setGSO', 'net.link.setOffloads',
  'net.addr.replace', 'net.route.replace', 'net.rule.replace', 'net.neigh.replace'];

// A small kernel model: links with addresses, GSO limits and offloads, plus
// route, rule and neighbor sets keyed the way wan_core replaces them.
function kernel() {
  const k = {links: new Map(), routes: new Map(), rules: new Map(), neigh: new Map(), next: 10, failEnsure: false, failures: 0};
  const info = l => ({name: l.name, ifindex: l.ifindex, kind: l.kind, mtu: l.mtu, up: l.up, arp: l.arp, addresses: l.addresses.slice(),
    peer_ifindex: l.peer ? k.links.get(l.peer).ifindex : 0, peer_name: l.peer || '', mac: '02:00:00:00:00:' + l.ifindex.toString(16),
    gso_max_size: l.gso_max_size, gso_max_segs: l.gso_max_segs});
  const add = (name, kind, mtu, up, peer) => {
    const l = {name, kind, ifindex: k.next++, mtu, up, arp: true, addresses: [], peer, gso_max_size: 65536, gso_max_segs: 65535,
      offloads: {sg: true, tso: true, gso: true, gro: true, lro: false}};
    k.links.set(name, l);
    return l;
  };
  const need = name => {
    const l = k.links.get(name);
    if (!l) throw new Error('link not found: ' + name);
    return l;
  };
  const ensure = (l, mtu, up) => {
    if (mtu) l.mtu = mtu;
    if (up) l.up = true;
  };
  k.adapters = {
    'net.link.get': name => info(need(name)),
    'net.link.ensureVeth': req => {
      if (k.failEnsure) {
        k.failures++;
        throw new Error('temporary veth failure');
      }
      let host = k.links.get(req.host), peer = k.links.get(req.peer), created = false;
      if (!host && !peer) {
        host = add(req.host, 'veth', req.mtu, req.up, req.peer);
        peer = add(req.peer, 'veth', req.mtu, req.up, req.host);
        created = true;
      }
      ensure(host, req.mtu, req.up);
      ensure(peer, req.mtu, req.up);
      return {host: info(host), peer: info(peer), created};
    },
    'net.link.ensureDummy': req => {
      let l = k.links.get(req.name), created = false;
      if (!l) {
        l = add(req.name, 'dummy', req.mtu, req.up);
        created = true;
      }
      ensure(l, req.mtu, req.up);
      return {link: info(l), created};
    },
    'net.link.setARP': (name, enabled) => {
      const l = need(name);
      l.arp = enabled;
      return info(l);
    },
    'net.link.setGSO': (name, limits) => {
      const l = need(name);
      l.gso_max_size = limits.max_size;
      l.gso_max_segs = limits.max_segs;
      return info(l);
    },
    'net.link.setOffloads': (name, features) => { Object.assign(need(name).offloads, features); },
    'net.link.delete': name => {
      const l = need(name);
      k.links.delete(name);
      if (l.peer) k.links.delete(l.peer);
      for (const [key, route] of k.routes) if (route.dev === name) k.routes.delete(key);
    },
    'net.addr.replace': req => {
      const l = need(req.interface);
      if (!l.addresses.includes(req.cidr)) l.addresses.push(req.cidr);
    },
    'net.addr.delete': req => {
      const l = need(req.interface);
      l.addresses = l.addresses.filter(a => a !== req.cidr);
    },
    'net.route.replace': req => { k.routes.set([req.dst, req.table].join('|'), req); },
    'net.route.delete': req => { k.routes.delete([req.dst, req.table].join('|')); },
    'net.rule.replace': req => { k.rules.set([req.family, req.priority].join('|'), req); },
    'net.rule.delete': req => { k.rules.delete([req.family, req.priority].join('|')); },
    'net.neigh.replace': req => { k.neigh.set([req.interface, req.ip].join('|'), req); },
    'net.neigh.delete': req => { k.neigh.delete([req.interface, req.ip].join('|')); },
  };
  return k;
}

const session = {
  key: 'default', driver: 'pppoe', state: 'up', usable: true, local_interface: LOCAL, pipeline_interface: PIPE,
  ipv4: '192.0.2.2', ipv4_peer: '192.0.2.1', ipv6: '2001:db8::2', ipv6_link_local: 'fe80::2', ipv6_gateway: 'fe80::1',
  peer_mac: '02:00:00:00:00:01', pd_prefix: '2001:db8:100::/56', install_default_route_v6: true,
  interface_preparation: {local_gso: {max_size: 1492, max_segs: 1}, local_offloads: {sg: false, tso: false, gso: false},
    pipeline_offloads: {gro: false, lro: false}},
};

function fixture(payload = session) {
  const k = kernel();
  const host = createTestHost({pluginDir: __dirname, adapters: k.adapters}).load();
  host.action('apply_session', payload);
  host.state.calls.length = 0;
  const calls = () => host.state.calls.map(c => c.api);
  const writes = () => calls().filter(api => WRITES.includes(api)).length;
  const tick = () => host.fireTimer('wan_repair');
  const reset = () => { host.state.calls.length = 0; };
  const status = () => host.state.resources.get('status').get('default').data;
  return {k, host, calls, writes, tick, reset, status};
}

test('stable repair ticks only read the boundary and stagger the full apply', () => {
  const h = fixture();
  h.tick(); // the first tick after start learns the record revisions with a full apply
  h.reset();
  let fullTicks = 0;
  for (let i = 0; i < FULL_REPAIR_TICKS; i++) {
    h.reset();
    h.tick();
    const calls = h.calls();
    if (calls.includes('net.link.ensureVeth')) {
      fullTicks++;
      continue;
    }
    assert.equal(h.writes(), 0, 'light tick wrote: ' + calls.join(','));
    assert.deepEqual(calls.filter(api => api.startsWith('net.')), ['net.link.get', 'net.link.get']);
  }
  assert.equal(fullTicks, 1, 'one full apply per session every FULL_REPAIR_TICKS ticks');
  assert.equal(h.status().phase, 'applied');
});

test('a reconcile counts as the full apply for the ticks that follow', () => {
  const h = fixture();
  h.host.reconcile();
  h.reset();
  h.tick(); // not the staggered full tick of key "default"
  assert.equal(h.calls().includes('net.link.ensureVeth'), false);
  assert.equal(h.writes(), 0);
});

test('the light check repairs boundary drift on the next tick', () => {
  const drifts = {
    deleted: k => k.adapters['net.link.delete'](LOCAL),
    local_down: k => { k.links.get(LOCAL).up = false; },
    pipeline_down: k => { k.links.get(PIPE).up = false; },
    mtu: k => { k.links.get(LOCAL).mtu = 1400; },
    arp: k => { k.links.get(LOCAL).arp = true; },
    address: k => { k.links.get(LOCAL).addresses = k.links.get(LOCAL).addresses.filter(a => a !== '192.0.2.2/32'); },
    gso: k => { k.links.get(LOCAL).gso_max_size = 65536; },
    replaced: k => {
      k.adapters['net.link.delete'](LOCAL);
      k.adapters['net.link.ensureVeth']({host: LOCAL, peer: PIPE, mtu: 1492, up: true});
    },
  };
  for (const [name, drift] of Object.entries(drifts)) {
    const h = fixture();
    h.tick();
    h.tick();
    drift(h.k);
    h.reset();
    h.tick();
    assert.ok(h.calls().includes('net.link.ensureVeth'), name + ': no full apply');
    const local = h.k.links.get(LOCAL), pipe = h.k.links.get(PIPE);
    assert.ok(local && pipe, name);
    assert.equal(local.up && pipe.up, true, name);
    assert.equal(local.mtu, 1492, name);
    assert.equal(local.arp, false, name);
    assert.equal(local.gso_max_size, 1492, name);
    assert.ok(local.addresses.includes('192.0.2.2/32'), name);
    assert.equal(h.status().local_ifindex, local.ifindex, name);
    assert.equal(h.status().pipeline_ifindex, pipe.ifindex, name);
    h.reset();
    h.tick();
    assert.equal(h.writes(), 0, name + ': the tick after the repair is light again');
  }
});

test('route, rule, neighbor and offload drift is repaired by the next full apply', () => {
  const h = fixture();
  h.tick();
  const routes = h.k.routes.size, rules = h.k.rules.size, neigh = h.k.neigh.size;
  assert.ok(routes && rules && neigh);
  h.k.routes.clear();
  h.k.rules.clear();
  h.k.neigh.clear();
  h.k.links.get(PIPE).offloads.gro = true;
  let ticks = 0;
  while (h.k.routes.size === 0 && ticks < FULL_REPAIR_TICKS) {
    h.tick();
    ticks++;
  }
  assert.ok(ticks <= FULL_REPAIR_TICKS, 'repaired within ' + ticks + ' ticks');
  assert.equal(h.k.routes.size, routes);
  assert.equal(h.k.rules.size, rules);
  assert.equal(h.k.neigh.size, neigh);
  assert.equal(h.k.links.get(PIPE).offloads.gro, false);
});

test('a changed profile or session record is applied on the next tick', () => {
  const h = fixture();
  h.tick();
  h.tick();
  const profile = h.host.state.resources.get('profiles').get('default');
  profile.data = {...profile.data, mtu: 1480};
  profile.revision++;
  h.reset();
  h.tick();
  assert.equal(h.k.links.get(LOCAL).mtu, 1480);
  assert.equal(h.status().mtu, 1480);
  const record = h.host.state.resources.get('sessions').get('default');
  record.data = {...record.data, ipv4: '192.0.2.3'};
  record.revision++;
  h.tick();
  assert.ok(h.k.links.get(LOCAL).addresses.includes('192.0.2.3/32'));
});

test('a failed apply is retried on every tick until it succeeds', () => {
  const h = fixture();
  h.tick();
  h.k.failEnsure = true;
  h.k.adapters['net.link.delete'](LOCAL);
  h.tick();
  h.tick();
  assert.equal(h.k.failures, 2);
  assert.equal(h.status().phase, 'error');
  h.k.failEnsure = false;
  h.tick();
  assert.equal(h.status().phase, 'applied');
  assert.ok(h.k.links.get(LOCAL));
});

test('direct boundaries check the single dummy', () => {
  const h = fixture({key: 'default', driver: 'wireguard', driver_plugin: 'vpn_core', state: 'up', usable: true,
    local_interface: LOCAL, handoff_mode: 'direct', ipv4: '10.77.0.1', addresses: ['10.77.0.1/32'], mtu: 1420});
  h.tick();
  h.reset();
  h.tick();
  assert.deepEqual(h.calls().filter(api => api.startsWith('net.')), ['net.link.get']);
  h.k.links.get(LOCAL).up = false;
  h.tick();
  assert.equal(h.k.links.get(LOCAL).up, true);
});
