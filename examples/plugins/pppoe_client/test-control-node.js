#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const nodeCrypto = require('crypto');
const path = require('path');
const vm = require('vm');

const pluginDir = __dirname;
const controlPath = path.join(pluginDir, 'control.js');

const ETH_P_PPP_DISC = '0x8863';
const ETH_P_PPP_SESS = '0x8864';
const CODE_PADI = 0x09;
const CODE_PADO = 0x07;
const CODE_PADR = 0x19;
const CODE_PADS = 0x65;
const CODE_PADT = 0xa7;
const TAG_SERVICE_NAME = 0x0101;
const TAG_AC_NAME = 0x0102;
const TAG_HOST_UNIQ = 0x0103;
const PPP_IP = 0x0021;
const PPP_IPV6 = 0x0057;
const PPP_LCP = 0xc021;
const PPP_PAP = 0xc023;
const PPP_CHAP = 0xc223;
const PPP_IPCP = 0x8021;
const PPP_IPV6CP = 0x8057;
const SESSION_ID = 0x0010;
const LOCAL_MAC = '02:00:00:00:00:01';
const AC_MAC = '02:00:00:00:00:02';
const LAN_MAC = '02:00:00:00:10:02';
const LAN_PEER_MAC = '02:00:00:00:10:01';

function main() {
  testRegistration();
  testPapIPv6PDTunnel();
  testExplicitLanPeerMACDoesNotRequirePeerLink();
  testChapDialKeepaliveAndSecretBoundary();
  testAutoRedialAfterKeepaliveTimeout();
  testAutoRedialDoesNotMaskAuthFailure();
  testDisconnectClearsTunnelAndWANState();
  testTunnelConfigRuntimeApplyReplaysAndClearsMap();
  testTrafficProbeTimeoutFailsClosed();
  testDebugStatsDeclaresCounterBuildMode();
  console.log('pppoe_client control-plane self-test passed');
}

function testRegistration() {
  const h = createHarness({auth: 'none'});
  assert(h.state.capabilities.includes('pppoe'), 'pppoe capability should be registered');
  assert(h.state.objects.some((item) => item.id === 'pppoe_tunnel'), 'pppoe_tunnel object should be registered');
  assert(h.state.hooks.some((item) => item.id === 'pppoe-forward' && item.mode === 'rewrite'), 'forward hook should be registered');
  assert(h.state.hooks.some((item) => item.id === 'pppoe-reply' && item.stage === 'reply'), 'reply hook should be registered');
  assert(h.state.actions.map((item) => item.id).includes('traffic_probe'), 'traffic_probe action should be registered');
  assert.strictEqual(h.state.ui.page, 'pppoe', 'ui page should be registered');
}

function testPapIPv6PDTunnel() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'pap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: true,
    negotiate_ipv6: true,
    request_pd: true,
    dhcpv6_settle_ms: 0,
    send_padt: false,
    post_session_control_ms: 0,
    lan_interface: 'fwdvtap0',
    lan_peer_interface: 'fwdlocal0',
    wan_interface: 'eth0',
    prepare_interfaces: true,
    prepare_lan_mtu: true,
    prepare_lan_peer: true,
    prepare_wan_mtu: false,
    prepare_offloads: true,
    wan_core_sync: true,
    wan_core_apply: true
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.phase, 'session_probe');
  assert.strictEqual(session.session_id, SESSION_ID);
  assert.strictEqual(session.lcp_ack, true);
  assert.strictEqual(session.auth_sent, true);
  assert.strictEqual(session.auth_method, 'pap');
  assert.strictEqual(session.auth_ok, true);
  assert.strictEqual(session.ipcp.phase, 'configure_ack');
  assert.strictEqual(session.ipv6cp.phase, 'configure_ack');
  assert.strictEqual(session.ipv6cp.up, true);
  assert.strictEqual(session.dhcpv6_pd.phase, 'reply');
  assert.strictEqual(session.dhcpv6_pd.prefix, '2001:db8:1234::/56');
  assert.strictEqual(session.tunnel_installed, true);
  assert.strictEqual(session.tunnel.mode, 'direct_vtap');

  const tunnelPut = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config' && item.value !== '00'.repeat(40));
  assert(tunnelPut, 'traffic_probe should install a non-zero tunnel config');
  assert.strictEqual(tunnelPut.value.length, 80, 'tunnel config map value must stay ABI-sized');
  const tunnelRecord = h.resource('tunnel_configs', 'active');
  assert.strictEqual(tunnelRecord.enabled, true, 'traffic_probe should persist active tunnel config');
  assert.strictEqual(tunnelRecord.data.value_hex, tunnelPut.value, 'persisted tunnel config should match applied map value');
  assert(h.state.timers.has('tunnel_repair'), 'active tunnel config should arm repair timer');
  assert(h.state.netCalls.includes('setMTU:fwdvtap0:1492'), 'LAN vtap MTU should be prepared');
  assert(h.state.netCalls.includes('setOffloads:fwdlocal0:gro=false,gso=false,sg=false,tso=false,tx=false'), 'LAN peer offloads should be disabled');

  const forwardBinding = h.resource('hook_bindings', 'pppoe-forward').data;
  assert.deepStrictEqual(forwardBinding.interfaces, ['fwdvtap0', 'fwdlocal0', 'eth0']);
  const wanSync = h.pluginResource('wan_core', 'sessions', 'default');
  assert(wanSync, 'wan_core session handoff should be written through plugin.resource');
  assert.strictEqual(wanSync.data.driver, 'pppoe');
  assert.strictEqual(wanSync.data.usable, true);
}

function testExplicitLanPeerMACDoesNotRequirePeerLink() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'pap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: true,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    post_session_control_ms: 0,
    lan_interface: 'fwdvtap0',
    lan_peer_interface: 'hidden0',
    lan_dst_mac: LAN_PEER_MAC,
    wan_interface: 'eth0',
    prepare_interfaces: true,
    prepare_lan_mtu: true,
    prepare_offloads: true,
    wan_core_sync: false
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.tunnel_installed, true);
  assert.strictEqual(session.tunnel.lan_dst_mac, LAN_PEER_MAC);
  assert(!h.state.netCalls.some((item) => item.includes('hidden0')), 'hidden lan peer should not be prepared by default when lan_dst_mac is explicit');
}

function testChapDialKeepaliveAndSecretBoundary() {
  const h = createHarness({auth: 'chap', echoReplies: true});
  runAction(h, 'dial', {
    interface: 'eth0',
    username: 'chap-user',
    password: 'chap-pass',
    auth: 'chap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    keepalive_interval_ms: 1000,
    wan_core_sync: false
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.auth_sent, true);
  assert.strictEqual(session.auth_method, 'chap');
  assert.strictEqual(session.auth_ok, true);
  assert.strictEqual(h.state.secrets.get('pppoe-password-default'), 'chap-pass');
  assert(h.state.timers.has('lcp_echo'), 'dial should arm lcp_echo keepalive');
  assert(!JSON.stringify(h.state.timers.get('lcp_echo').payload).includes('chap-pass'), 'keepalive timer payload must not contain the password');

  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: h.state.timers.get('lcp_echo').payload}});
  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_ok');
  assert.strictEqual(keepalive.session_id, SESSION_ID);
}

function testAutoRedialAfterKeepaliveTimeout() {
  const h = createHarness({auth: 'none', echoReplies: false});
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default',
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: 'up',
    usable: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC
  }, true);

  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: {
    profile_key: 'default',
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 20,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    auto_redial: true,
    redial_clear_tunnel: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.redial_attempted, true);
  assert.strictEqual(keepalive.phase, 'redial_ok');
  assert.strictEqual(keepalive.redial_session_id, SESSION_ID);
  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.phase, 'session_probe');
  assert.strictEqual(last.padt_sent, false);
}

function testAutoRedialDoesNotMaskAuthFailure() {
  const h = createHarness({auth: 'pap-reject', echoReplies: false});
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default',
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: 'up',
    usable: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC
  }, true);

  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: {
    profile_key: 'default',
    interface: 'eth0',
    username: 'user',
    password: 'wrong-password',
    auth: 'pap',
    timeout_ms: 20,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    auto_redial: true,
    redial_clear_tunnel: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.redial_attempted, true);
  assert.strictEqual(keepalive.phase, 'redial_failed');
  assert.strictEqual(keepalive.redial_phase, 'session_probe');
  assert.strictEqual(keepalive.redial_tunnel_installed, false);
  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.lcp_ready, false);
  assert.strictEqual(last.auth_method, 'pap');
  assert.strictEqual(last.auth_ok, false);
}

function testDisconnectClearsTunnelAndWANState() {
  const h = createHarness({auth: 'none'});
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    wan_id: 'default',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default',
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: 'up',
    usable: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC
  }, true);

  runAction(h, 'disconnect', {
    interface: 'eth0',
    wan_core_sync: true,
    wan_core_apply: true
  });

  const padt = h.state.l2Sends.find((req) => req.ethertype === ETH_P_PPP_DISC && discoveryCode(req.payload) === CODE_PADT);
  assert(padt, 'disconnect should send PADT');
  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.phase, 'disconnected');
  assert.strictEqual(last.padt_sent, true);
  const wan = h.resource('wan_links', 'default');
  assert.strictEqual(wan.enabled, false);
  assert.strictEqual(wan.data.usable, false);
  assert.strictEqual(wan.data.phase, 'disconnected');
  const clear = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config' && item.value === '00'.repeat(40));
  assert(clear, 'disconnect should clear tunnel config');
  assert(!h.state.timers.has('tunnel_repair'), 'disconnect should clear tunnel repair timer');
}

function testTunnelConfigRuntimeApplyReplaysAndClearsMap() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'pap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: true,
    negotiate_ipv6: false,
    send_padt: false,
    post_session_control_ms: 0,
    lan_interface: 'fwdvtap0',
    lan_peer_interface: 'fwdlocal0',
    wan_interface: 'eth0',
    wan_core_sync: false
  });

  const record = h.resource('tunnel_configs', 'active');
  h.state.mapPuts.length = 0;
  h.context.exports.onResourceApply({
    resource: {id: 'tunnel_configs', runtime_update: 'runtime_apply'},
    records: [{key: 'active', data: record.data, enabled: true}]
  });
  const replay = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config');
  assert(replay, 'runtime_apply should replay tunnel config into eBPF map');
  assert.strictEqual(replay.value, record.data.value_hex, 'runtime_apply replay should preserve ABI value');

  h.state.mapPuts.length = 0;
  h.context.exports.onResourceApply({
    resource: {id: 'tunnel_configs', runtime_update: 'runtime_apply'},
    records: []
  });
  const clear = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config');
  assert(clear, 'empty tunnel config apply should clear eBPF map');
  assert.strictEqual(clear.value, '00'.repeat(40), 'empty tunnel config apply should write zero ABI value');
}

function testTrafficProbeTimeoutFailsClosed() {
  const h = createHarness({auth: 'pap', padsTimeout: true});
  assert.throws(() => runAction(h, 'traffic_probe', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'pap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: true,
    negotiate_ipv6: false,
    send_padt: false,
    post_session_control_ms: 0,
    lan_interface: 'fwdvtap0',
    lan_peer_interface: 'fwdlocal0',
    wan_interface: 'eth0',
    wan_core_sync: false
  }), /did not install tunnel/);
  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.phase, 'timeout');
  assert.strictEqual(session.message, 'PADS timeout');
  assert(!h.state.records.has('tunnel_configs/active'), 'failed traffic_probe must not persist tunnel config');
}

function testDebugStatsDeclaresCounterBuildMode() {
  const h = createHarness({auth: 'none'});
  runAction(h, 'debug_stats', {});
  const stats = h.resource('sessions', 'debug_stats').data.stats;
  assert.strictEqual(stats.counter_build, 'disabled_by_default');
  assert(stats.note.includes('PPPOE_TUNNEL_DIAG=1'), 'debug stats should explain how to enable per-packet counters');
  assert.strictEqual(stats.lan_encap_path, 0);
  assert.strictEqual(stats.pppoe_seen, 0);
}

function createHarness(options) {
  const state = {
    capabilities: [],
    virtualInterfaces: [],
    objects: [],
    hooks: [],
    resources: [],
    actions: [],
    ui: null,
    records: new Map(),
    pluginRecords: new Map(),
    secrets: new Map(),
    timers: new Map(),
    mapPuts: [],
    mapValues: new Map(),
    l2Sends: [],
    l2Exchanges: [],
    l2Recvs: [],
    netCalls: [],
    randomByte: 1,
    lastEchoIdentifier: null
  };
  const context = {
    console,
    Date,
    Math,
    JSON,
    setTimeout,
    clearTimeout,
    exports: {},
    plugin: {
      capabilities(items) { state.capabilities.push(...items); },
      virtualInterface(item) { state.virtualInterfaces.push(clone(item)); },
      resource(item) { state.resources.push(clone(item)); },
      action(item) { state.actions.push(clone(item)); }
    },
    ebpf: {
      loadObject(item) { state.objects.push(clone(item)); },
      mapPut(object, map, key, value) {
        state.mapPuts.push({object, map, key, value});
        state.mapValues.set(`${object}/${map}/${key}`, value);
      },
      mapGet(object, map, key) {
        return state.mapValues.get(`${object}/${map}/${key}`) || '00'.repeat(8);
      }
    },
    hooks: {
      attach(item) { state.hooks.push(clone(item)); }
    },
    ui: {
      register(item) { state.ui = clone(item); }
    },
    resources: {
      get(resource, key) {
        const record = state.records.get(`${resource}/${key}`);
        return record ? clone(record) : null;
      },
      set(resource, key, data, enabled, apply) {
        state.records.set(`${resource}/${key}`, {data: clone(data), enabled: enabled !== false});
        if (apply === true && typeof context.exports.onResourceApply === 'function') {
          context.exports.onResourceApply({
            resource: {id: resource, runtime_update: 'runtime_apply'},
            records: resourceRecords(state, resource)
          });
        }
      },
      delete(resource, key, apply) {
        state.records.delete(`${resource}/${key}`);
        if (apply === true && typeof context.exports.onResourceApply === 'function') {
          context.exports.onResourceApply({
            resource: {id: resource, runtime_update: 'runtime_apply'},
            records: resourceRecords(state, resource)
          });
        }
      }
    },
    plugins: {
      resources: {
        set(plugin, resource, key, data, enabled, apply) {
          state.pluginRecords.set(`${plugin}/${resource}/${key}`, {
            data: clone(data),
            enabled: enabled !== false,
            apply: apply === true
          });
        }
      }
    },
    secret: {
      set(key, value) { state.secrets.set(key, value); },
      get(key) { return state.secrets.has(key) ? state.secrets.get(key) : null; }
    },
    timer: {
      setInterval(name, intervalMs, payload) {
        state.timers.set(name, {kind: 'interval', intervalMs, payload: clone(payload)});
      },
      setTimeout(name, delayMs, payload) {
        state.timers.set(name, {kind: 'timeout', delayMs, payload: clone(payload)});
      },
      clear(name) {
        state.timers.delete(name);
      }
    },
    net: {
      link: {
        get(name) {
          return linkInfo(name);
        },
        setMTU(name, mtu) {
          state.netCalls.push(`setMTU:${name}:${mtu}`);
        },
        setOffloads(name, features) {
          const parts = Object.keys(features).sort().map((key) => `${key}=${features[key]}`);
          state.netCalls.push(`setOffloads:${name}:${parts.join(',')}`);
        }
      },
      l2: {
        send(req) {
          state.l2Sends.push(clone(req));
          rememberEchoRequest(state, context, req);
        },
        exchange(req) {
          const frames = context.net.l2.exchangeMany(req);
          return frames.length ? frames[0] : null;
        },
        exchangeMany(req) {
          state.l2Exchanges.push(clone(req));
          return handleExchangeMany(context, state, options || {}, req);
        },
        recv(req) {
          const frames = context.net.l2.recvMany(req);
          return frames.length ? frames[0] : null;
        },
        recvMany(req) {
          state.l2Recvs.push(clone(req));
          return handleRecvMany(context, state, options || {}, req);
        }
      }
    },
    crypto: {
      sha256File(rel) {
        const file = path.join(pluginDir, rel);
        if (!fs.existsSync(file)) return '00'.repeat(32);
        return nodeCrypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
      },
      randomBytes(length) {
        let out = '';
        for (let i = 0; i < length; i++) {
          out += hexByte(state.randomByte++);
        }
        return out;
      },
      md5() {
        const h = nodeCrypto.createHash('md5');
        for (const part of arguments) {
          if (Array.isArray(part)) h.update(Buffer.from(part));
          else if (part && typeof part === 'object' && part.hex != null) h.update(Buffer.from(String(part.hex), 'hex'));
          else h.update(Buffer.from(String(part == null ? '' : part)));
        }
        return h.digest('hex');
      }
    },
    log: {
      info() {}
    }
  };
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(controlPath, 'utf8'), context, {filename: controlPath});
  return {
    context,
    state,
    resource(resource, key) {
      const record = state.records.get(`${resource}/${key}`);
      assert(record, `missing resource ${resource}/${key}`);
      return clone(record);
    },
    setResource(resource, key, data, enabled) {
      state.records.set(`${resource}/${key}`, {data: clone(data), enabled: enabled !== false});
    },
    pluginResource(plugin, resource, key) {
      const record = state.pluginRecords.get(`${plugin}/${resource}/${key}`);
      return record ? clone(record) : null;
    }
  };
}

function runAction(h, id, payload) {
  h.context.exports.onAction({action: {id}, payload: payload || {}});
}

function resourceRecords(state, resource) {
  const out = [];
  for (const [id, record] of state.records.entries()) {
    const slash = id.indexOf('/');
    if (slash < 0 || id.slice(0, slash) !== resource) continue;
    out.push({key: id.slice(slash + 1), data: clone(record.data), enabled: record.enabled !== false});
  }
  return out;
}

function handleExchangeMany(ctx, state, options, req) {
  if (req.ethertype === ETH_P_PPP_DISC) {
    const code = discoveryCode(req.payload);
    const discovery = ctx.parseDiscoveryFrame({payload_hex: req.payload});
    const hostUniq = ctx.firstTagHex(discovery, TAG_HOST_UNIQ);
    if (code === CODE_PADI) {
      return [discoveryFrame(ctx, CODE_PADO, 0, [
        ctx.tagString(TAG_SERVICE_NAME, ''),
        ctx.tagString(TAG_AC_NAME, 'test-ac'),
        ctx.tagHex(TAG_HOST_UNIQ, hostUniq)
      ])];
    }
    if (options.padsTimeout) return [];
    if (code === CODE_PADR) {
      return [discoveryFrame(ctx, CODE_PADS, SESSION_ID, [
        ctx.tagString(TAG_SERVICE_NAME, ''),
        ctx.tagString(TAG_AC_NAME, 'test-ac'),
        ctx.tagHex(TAG_HOST_UNIQ, hostUniq)
      ])];
    }
    return [];
  }

  if (req.ethertype !== ETH_P_PPP_SESS || !req.payload) return [];
  const parsed = ctx.parseSessionFrame({payload_hex: req.payload});
  const cp = parsed.protocol === PPP_IPV6 ? null : ctx.parseCP(parsed.payload);
  if (parsed.protocol === PPP_LCP && cp.code === 1) {
    const frames = [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(2, cp.identifier, cp.data_hex))];
    if (options.auth === 'chap') {
      frames.push(sessionFrame(ctx, PPP_CHAP, ctx.cpPacket(1, 0x42, '04aabbccdd' + ctx.stringHex('test-ac'))));
    }
    return frames;
  }
  if (parsed.protocol === PPP_PAP && cp.code === 1) {
    assert(cp.data_hex.includes(ctx.stringHex('user')) || cp.data_hex.includes(ctx.stringHex('chap-user')), 'PAP Authenticate-Request should include username');
    if (options.auth === 'pap-reject') return [sessionFrame(ctx, PPP_PAP, ctx.cpPacket(3, cp.identifier, ctx.stringHex('denied')))];
    return [sessionFrame(ctx, PPP_PAP, ctx.cpPacket(2, cp.identifier, ctx.stringHex('ok')))];
  }
  if (parsed.protocol === PPP_CHAP && cp.code === 2) {
    const bytes = Buffer.from(cp.data_hex, 'hex');
    assert.strictEqual(bytes[0], 16, 'CHAP Response value-size should be 16');
    const digest = bytes.slice(1, 17).toString('hex');
    const expected = nodeCrypto.createHash('md5').update(Buffer.from([cp.identifier])).update('chap-pass').update(Buffer.from('aabbccdd', 'hex')).digest('hex');
    assert.strictEqual(digest, expected, 'CHAP response digest should match MD5(ID + password + challenge)');
    return [sessionFrame(ctx, PPP_CHAP, ctx.cpPacket(3, cp.identifier, ctx.stringHex('ok')))];
  }
  if (parsed.protocol === PPP_IPCP && cp.code === 1) {
    return [sessionFrame(ctx, PPP_IPCP, ctx.cpPacket(2, cp.identifier, cp.data_hex))];
  }
  if (parsed.protocol === PPP_IPV6CP && cp.code === 1) {
    return [sessionFrame(ctx, PPP_IPV6CP, ctx.cpPacket(2, cp.identifier, cp.data_hex))];
  }
  if (parsed.protocol === PPP_IPV6) {
    const packet = ctx.parseIPv6UDP(parsed.payload);
    assert(packet, 'DHCPv6 test path should send IPv6/UDP');
    const dhcp = ctx.parseDHCPv6(packet.payload_hex);
    if (dhcp.message_type === 1) return [dhcpv6Frame(ctx, 2, dhcp.transaction_id)];
    if (dhcp.message_type === 3) return [dhcpv6Frame(ctx, 7, dhcp.transaction_id)];
  }
  return [];
}

function handleRecvMany(ctx, state, options, req) {
  if (req.ethertype !== ETH_P_PPP_SESS) return [];
  if (options.echoReplies && state.lastEchoIdentifier != null) {
    const id = state.lastEchoIdentifier;
    state.lastEchoIdentifier = null;
    return [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(10, id, '00000000'))];
  }
  return [];
}

function rememberEchoRequest(state, ctx, req) {
  if (req.ethertype !== ETH_P_PPP_SESS || !req.payload) return;
  let parsed;
  try {
    parsed = ctx.parseSessionFrame({payload_hex: req.payload});
  } catch (_) {
    return;
  }
  if (parsed.protocol !== PPP_LCP) return;
  const cp = ctx.parseCP(parsed.payload);
  if (cp.code === 9) state.lastEchoIdentifier = cp.identifier;
}

function discoveryFrame(ctx, code, sessionID, tags) {
  return {
    interface: 'eth0',
    ifindex: 7,
    ethertype: ETH_P_PPP_DISC,
    src_mac: AC_MAC,
    dst_mac: LOCAL_MAC,
    payload_hex: ctx.pppoeDiscovery(code, sessionID, tags)
  };
}

function sessionFrame(ctx, protocol, payloadHex) {
  return {
    interface: 'eth0',
    ifindex: 7,
    ethertype: ETH_P_PPP_SESS,
    src_mac: AC_MAC,
    dst_mac: LOCAL_MAC,
    payload_hex: ctx.pppoeSession(SESSION_ID, ctx.u16hex(protocol) + payloadHex)
  };
}

function dhcpv6Frame(ctx, messageType, xid) {
  const serverID = '00030001020000000002';
  const prefix = '20010db8123400000000000000000000';
  const iaPrefix = ctx.u32hex(3600) + ctx.u32hex(7200) + '38' + prefix;
  const iaPD = ctx.u32hex(1) + ctx.u32hex(0) + ctx.u32hex(0) + ctx.dhcpv6Option(26, iaPrefix);
  const payload = ctx.hexByte(messageType) + xid + ctx.dhcpv6Option(2, serverID) + ctx.dhcpv6Option(25, iaPD);
  return sessionFrame(ctx, PPP_IPV6, ctx.ipv6UDP('fe80::2', 'fe80::1', 547, 546, payload));
}

function discoveryCode(payloadHex) {
  return parseInt(String(payloadHex || '').slice(2, 4), 16);
}

function linkInfo(name) {
  if (name === 'eth0') return {name, ifindex: 7, kind: 'device', mtu: 1500, mac: LOCAL_MAC, up: true};
  if (name === 'fwdlocal0') return {name, ifindex: 101, kind: 'veth', mtu: 1492, mac: LAN_PEER_MAC, up: true};
  if (name === 'fwdvtap0') return {name, ifindex: 102, kind: 'veth', mtu: 1492, mac: LAN_MAC, up: true};
  if (name === 'hidden0') throw new Error('Link not found');
  return {name, ifindex: 200, kind: 'device', mtu: 1500, mac: '02:00:00:00:20:00', up: true};
}

function clone(value) {
  if (value == null) return value;
  return JSON.parse(JSON.stringify(value));
}

function hexByte(value) {
  value = Number(value) & 0xff;
  return (value < 16 ? '0' : '') + value.toString(16);
}

main();
