'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const {createTestHost} = require('../../sdk/plugin/test-host.cjs');

const LOCAL = 'veerlocal0';
const PIPE = 'veerpipe0';

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
      if (k.failEnsure === true || (typeof k.failEnsure === 'function' && k.failEnsure(req))) {
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
      if (k.failDelete) throw new Error('net.link.delete: link is owned by another plugin');
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
  const timers = () => new Map([...host.state.timers.values()].map(t => [t.name, t]));
  // Deliver an event the way the host does, then run the repair it armed.
  const EVENT_TIMERS = ['wan_event', 'wan_event_full'];
  const event = (topic, eventPayload = {interface: LOCAL}) => {
    for (const name of EVENT_TIMERS) host.state.timers.delete(name);
    host.emit(topic, eventPayload);
    const armed = EVENT_TIMERS.filter(name => host.state.timers.has(name));
    for (const name of armed) host.fireTimer(name);
    return armed;
  };
  const safety = () => host.fireTimer('wan_repair');
  const reset = () => { host.state.calls.length = 0; };
  const status = () => host.state.resources.get('status').get('default').data;
  safety(); // learn the record revisions, as the first repair after start does
  reset();
  return {k, host, calls, writes, timers, event, safety, reset, status};
}

test('nothing polls: the only interval is the five-minute safety repair', () => {
  const h = fixture();
  const intervals = [...h.timers().values()].filter(t => t.kind === 'interval');
  assert.deepEqual(intervals.map(t => [t.name, t.delay_ms]), [['wan_repair', 300000]]);
  // The safety repair replays every write; the host turns those that change
  // nothing into no-ops, so it arms no retry either.
  h.safety();
  assert.equal(h.status().phase, 'applied');
  assert.equal(h.timers().has('wan_retry'), false);
});

test('every network event but a dynamic neighbor runs a full apply', () => {
  for (const topic of ['net.link', 'net.addr', 'net.route', 'net.rule', 'net.offload']) {
    const h = fixture();
    assert.deepEqual(h.event(topic), ['wan_event_full'], topic);
    assert.ok(h.calls().includes('net.route.replace'), topic + ': routes were not replayed');
    assert.equal(h.status().phase, 'applied', topic);
  }
  const h = fixture();
  assert.deepEqual(h.event('net.link', {operation: 'resync', reason: 'netlink_resubscribe'}), ['wan_event_full'], 'resync');
});

test('a link that went down and up gets its flushed routes back', () => {
  const h = fixture();
  const routes = h.k.routes.size;
  // The kernel flushes a link's IPv4 routes on down without a route event;
  // the link is healthy again by the time the repair runs.
  h.k.routes.clear();
  h.event('net.link', {interface: LOCAL, operation: 'update', admin_up: true});
  assert.equal(h.k.routes.size, routes);
});

test('a burst of events arms the repair once and does not postpone it', () => {
  const h = fixture();
  h.host.emit('net.link', {interface: LOCAL});
  const first = h.timers().get('wan_event_full');
  assert.ok(first, 'the first event arms the repair');
  for (let i = 0; i < 5; i++) h.host.emit('net.addr', {interface: LOCAL});
  assert.equal(h.timers().get('wan_event_full').next_fire, first.next_fire, 'later events must not move it');
});

test('the full apply after a link event repairs boundary drift', () => {
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
    drift(h.k);
    h.event('net.link');
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
    h.event('net.link');
    assert.equal(h.status().phase, 'applied', name + ': the repair after the repair keeps it applied');
    assert.equal(h.status().local_ifindex, local.ifindex, name + ': and changes nothing');
  }
});

test('route, rule, static neighbor and offload events run a full apply', () => {
  const drifts = {
    'net.route': [k => k.routes.clear(), k => k.routes.size > 0],
    'net.rule': [k => k.rules.clear(), k => k.rules.size > 0],
    'net.neigh': [k => k.neigh.clear(), k => k.neigh.size > 0],
    'net.offload': [k => { k.links.get(PIPE).offloads.gro = true; }, k => k.links.get(PIPE).offloads.gro === false],
  };
  for (const [topic, [drift, repaired]] of Object.entries(drifts)) {
    const h = fixture();
    drift(h.k);
    const payload = topic === 'net.neigh' ? {interface: LOCAL, operation: 'delete', state: 0x80} : {interface: LOCAL};
    assert.deepEqual(h.event(topic, payload), ['wan_event_full'], topic);
    assert.ok(repaired(h.k), topic + ' not repaired');
  }
});

test('a dynamic neighbor changing state arms nothing', () => {
  const h = fixture();
  assert.deepEqual(h.event('net.neigh', {interface: LOCAL, operation: 'update', state: 0x02}), []);
  assert.deepEqual(h.event('net.neigh', {interface: LOCAL, operation: 'update', state: 0x04}), []);
});

test('the safety repair replays routes, rules, neighbors and offloads', () => {
  const h = fixture();
  const routes = h.k.routes.size, rules = h.k.rules.size, neigh = h.k.neigh.size;
  assert.ok(routes && rules && neigh);
  h.k.routes.clear();
  h.k.rules.clear();
  h.k.neigh.clear();
  h.k.links.get(PIPE).offloads.gro = true;
  h.safety();
  assert.equal(h.k.routes.size, routes);
  assert.equal(h.k.rules.size, rules);
  assert.equal(h.k.neigh.size, neigh);
  assert.equal(h.k.links.get(PIPE).offloads.gro, false);
});

test('a changed profile is applied after its record event', () => {
  const h = fixture();
  const profile = h.host.state.resources.get('profiles').get('default');
  profile.data = {...profile.data, mtu: 1480};
  profile.revision++;
  assert.deepEqual(h.event('resource.changed', {plugin_id: 'wan_core', resource_id: 'status', operation: 'update', key: 'default'}), [],
    'its own status records arm nothing');
  assert.deepEqual(h.event('resource.changed', {plugin_id: 'wan_core', resource_id: 'profiles', operation: 'update', key: 'default'}),
    ['wan_event']);
  assert.equal(h.k.links.get(LOCAL).mtu, 1480);
  assert.equal(h.status().mtu, 1480);
});

test('a failed apply is retried with backoff until it succeeds', () => {
  const h = fixture();
  h.k.failEnsure = true;
  h.k.adapters['net.link.delete'](LOCAL);
  h.event('net.link');
  assert.equal(h.k.failures, 1);
  assert.equal(h.status().phase, 'error');
  assert.equal(h.timers().get('wan_retry').delay_ms, 2000);
  h.host.fireTimer('wan_retry');
  assert.equal(h.k.failures, 2);
  assert.equal(h.timers().get('wan_retry').delay_ms, 4000, 'the retry backs off');
  h.k.failEnsure = false;
  h.host.fireTimer('wan_retry');
  assert.equal(h.status().phase, 'applied');
  assert.ok(h.k.links.get(LOCAL));
  assert.equal(h.timers().has('wan_retry'), false, 'no retry once applied');
});

test('direct boundaries check the single dummy', () => {
  const h = fixture({key: 'default', driver: 'wireguard', driver_plugin: 'vpn_core', state: 'up', usable: true,
    local_interface: LOCAL, handoff_mode: 'direct', ipv4: '10.77.0.1', addresses: ['10.77.0.1/32'], mtu: 1420});
  // A profile edit runs the light check: a direct boundary reads one link.
  assert.deepEqual(h.event('resource.changed', {resource_id: 'profiles'}), ['wan_event']);
  assert.deepEqual(h.calls().filter(api => api.startsWith('net.')), ['net.link.get']);
  h.k.links.get(LOCAL).up = false;
  h.event('net.link');
  assert.equal(h.k.links.get(LOCAL).up, true);
});

test('each session backs off on its own', () => {
  const h = fixture();
  h.host.action('apply_session', {...session, key: 'second', local_interface: 'veerlocal1', pipeline_interface: 'veerpipe1'});
  // The default session keeps failing: its retries back off.
  h.k.failEnsure = req => req.host === LOCAL;
  h.k.adapters['net.link.delete'](LOCAL);
  h.event('net.link');
  assert.equal(h.timers().get('wan_retry').delay_ms, 2000);
  h.host.fireTimer('wan_retry');
  h.host.fireTimer('wan_retry');
  assert.equal(h.timers().get('wan_retry').delay_ms, 8000);
  // A second session that starts failing is retried after 2 s, not 16 s.
  h.k.failEnsure = () => true;
  h.k.adapters['net.link.delete']('veerlocal1');
  h.event('net.link');
  assert.equal(h.timers().get('wan_retry').delay_ms, 2000);
});

test('an unfinished teardown keeps naming its driver, so the driver can retry it', () => {
  const driven = {...session, driver: 'wireguard', driver_plugin: 'vpn_core', profile_key: 'default'};
  const h = fixture(driven);
  h.k.failDelete = true;
  h.host.action('teardown', {key: 'default', session: {...driven, state: 'down', usable: false}});
  assert.equal(h.status().phase, 'delete_failed');
  assert.equal(h.status().driver_plugin, 'vpn_core');
  assert.equal(h.status().driver, 'wireguard');
  assert.equal(h.status().profile_key, 'default');
  assert.equal(h.timers().has('wan_event') || h.timers().has('wan_retry'), false, 'nothing retries a failed delete on its own');
  h.k.failDelete = false;
  h.host.action('teardown', {key: 'default', session: {...driven, state: 'down', usable: false}});
  assert.equal(h.status().phase, 'deleted');
  assert.equal(h.k.links.has(LOCAL), false);
});
