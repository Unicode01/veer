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
const LOCAL_BOUNDARY_MAC = '02:00:00:00:10:01';
const PIPELINE_INTERFACE = 'veerpipe0';
const PIPELINE_BOUNDARY_MAC = '02:00:00:00:10:02';

function main() {
  testRegistration();
  testUpgradeLifecycleSchema();
  testReconcileRestoresOnlyActiveControlState();
  testProfilePersistenceFailsBeforeDialing();
  testRawL2RandomIdentityAndCleanup();
  testPapIPv6PDTunnel();
  testDHCPv6RenewRebindAndRecovery();
  testDHCPv6PartialIANAStatusKeepsPDLease();
  testDHCPv6ReconcileRestoresLeaseTimerWithoutKeepalive();
  testDHCPv6InvalidLeaseTimersFailClosed();
  testAutoAuthNegotiatesPAP();
  testAutoAuthNegotiatesCHAP();
  testExplicitAuthMismatchFailsClosed();
  testAutoAuthRejectsUnsupportedCHAPAlgorithm();
  testIPCPDNSRejectFallsBack();
  testRADrivenIPv6WithoutIANA();
  testKeepaliveRedialPreservesTunnelPreparation();
  testRequiredWANCoreSyncFailsClosed();
  testManualMACUsesRawL2WithoutNetdev();
  testChapDialKeepaliveAndSecretBoundary();
  testKeepaliveFailureThresholdRecoversWithoutRedial();
  testKeepaliveGracePreventsPrematureRedial();
  testDisabledAutoRedialHonorsFailureGrace();
  testKeepaliveFinalConfirmationRecoversWithoutPADT();
  testKeepaliveTransportErrorKeepsRetryState();
  testAutoRedialAfterKeepaliveTimeout();
  testRedialDiscoveryFailureRetriesWithoutOldKeepalive();
  testAutoRedialDoesNotMaskAuthFailure();
  testDialIsIdempotentWhileSessionIsActive();
  testQueuedSessionTimersCannotReviveDisconnectedSession();
  testQueuedRedialCannotRunAfterDisconnect();
  testDisconnectClearsTunnelAndWANState();
  testTunnelConfigRuntimeApplyReplaysAndClearsMap();
  testTrafficProbeTimeoutFailsClosed();
  testDebugStatsDeclaresCounterBuildMode();
  testTrafficStatsAggregatePerCPUValues();
  console.log('pppoe_client control-plane self-test passed');
}

function testUpgradeLifecycleSchema() {
  const h = createHarness({auth: 'none'});
  const snapshot = h.context.exports.onUpgradeSnapshot();
  assert.strictEqual(snapshot.schema_version, 1);
  assert.strictEqual(typeof snapshot.schema_version, 'number');
  assert.doesNotThrow(() => h.context.exports.onUpgradeRestore({upgrade: {state: {schema_version: 1}}}));
  assert.throws(
    () => h.context.exports.onUpgradeRestore({upgrade: {state: {schema_version: '1'}}}),
    /unsupported PPPoE upgrade state schema/
  );
}

function testRawL2RandomIdentityAndCleanup() {
  const h = createHarness({auth: 'chap', echoReplies: true});
  const payload = {
    profile_key: 'secondary',
    interface: 'eth0',
    mac_mode: 'random',
    wan_src_mac: '02:00:00:00:00:fe',
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
    install_tunnel: true,
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    prepare_interfaces: true,
    prepare_offloads: true,
    wan_core_sync: false
  };

  runAction(h, 'dial', payload);
  const managed = h.resource('l2_identities', 'secondary').data;
  assert.strictEqual(managed.interface, 'eth0');
  assert.strictEqual(managed.custom_mac, true);
  assert.strictEqual(managed.promisc_enabled_by_plugin, true);
  assert(/^02:/.test(managed.mac_address), 'random raw-L2 MAC should be locally administered unicast');
  assert(h.state.netCalls.includes('setPromiscuous:eth0:true'), 'custom MAC should enable promiscuous mode without creating a netdev');
  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.tunnel_installed, true);
  assert.strictEqual(session.tunnel.wan_interface, 'eth0');
  assert.strictEqual(session.tunnel.local_interface, 'veerlocal0');
  assert.strictEqual(session.tunnel.wan_src_mac, managed.mac_address, 'TC encapsulation should replace a stale WAN source MAC with the raw-L2 identity');
  assert.deepStrictEqual(h.resource('hook_bindings', 'pppoe-ingress').data.interfaces, ['eth0']);
  assert.deepStrictEqual(h.resource('hook_bindings', 'pppoe-egress').data.interfaces, [PIPELINE_INTERFACE]);
  assert(h.state.l2Exchanges.some((item) => item.src_mac === managed.mac_address && item.recv_dst_mac === managed.mac_address), 'raw-L2 requests must send and receive with the selected MAC');
  assert(!h.state.netCalls.some((item) => item.startsWith('ensure') || item.startsWith('delete:')), 'PPPoE identity must not create or delete a Linux netdev');

  const timerPayload = h.state.timers.get('lcp_echo').payload;
  assert.strictEqual(timerPayload.interface, 'eth0');
  assert.strictEqual(timerPayload.wan_interface, 'eth0');
  assert.strictEqual(timerPayload.prepare_wan_offloads, false);
  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: timerPayload}});
  assert.strictEqual(h.resource('l2_identities', 'secondary').data.mac_address, managed.mac_address, 'keepalive must reuse the random MAC');

  runAction(h, 'disconnect', payload);
  assert(h.state.netCalls.includes('setPromiscuous:eth0:false'), 'disconnect should restore plugin-owned promiscuous mode');
  assert(!h.state.records.has('l2_identities/secondary'), 'disconnect should release the raw-L2 identity');
}

function testRegistration() {
  const h = createHarness({auth: 'none'});
  assert(h.state.capabilities.includes('pppoe'), 'pppoe capability should be registered');
  assert(h.state.virtualInterfaces.some((item) => item.id === 'pppoe0' && item.type === 'pipeline'), 'pppoe0 should be a logical pipeline node');
  assert(h.state.objects.some((item) => item.id === 'pppoe_tunnel'), 'pppoe_tunnel object should be registered');
  const tunnelObject = h.state.objects.find((item) => item.id === 'pppoe_tunnel');
  assert(tunnelObject.programs.some((item) => item.id === 'tc_tunnel' && item.type === 'tc'), 'TC tunnel program should be registered');
  assert.strictEqual(tunnelObject.programs.length, 1, 'PPPoE should register only the TC tunnel program');
  assert(h.state.hooks.some((item) => item.id === 'pppoe-ingress' && item.attach === 'ingress'), 'physical ingress hook should be registered');
  assert(h.state.hooks.some((item) => item.id === 'pppoe-egress' && item.attach === 'ingress'), 'segmented pipeline ingress hook should be registered');
  assert(!h.state.capabilities.includes('xdp'), 'PPPoE should not advertise the removed XDP receive path');
  assert(!h.state.hooks.some((item) => item.engine === 'xdp'), 'PPPoE should not register an XDP hook');
  assert(h.state.actions.map((item) => item.id).includes('traffic_probe'), 'traffic_probe action should be registered');
  assert(h.state.actions.some((item) => item.id === 'traffic_stats' && item.runtime_update === 'runtime_query'), 'traffic_stats query action should be registered');
  assert.strictEqual(h.state.ui.page, 'pppoe', 'ui page should be registered');
}

function testReconcileRestoresOnlyActiveControlState() {
  const h = createHarness({auth: 'none', echoReplies: true});
  h.setResource('profiles', 'default', {
    interface: 'eth0',
    auth: 'none',
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 3,
    auto_redial: true,
    install_tunnel: true,
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    wan_core_sync: false
  }, true);
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    profile_key: 'default',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true,
    padt_sent: false
  }, true);

  h.context.exports.onReconcile();
  let resumed = h.state.timers.get('lcp_echo');
  assert(resumed && resumed.kind === 'timeout', 'reconcile should promptly validate the active persisted session');
  assert.strictEqual(resumed.payload.session_id, SESSION_ID);

  h.state.timers.clear();
  h.setResource('sessions', 'last', {
    phase: 'disconnected',
    profile_key: 'default',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: false,
    padt_sent: true
  }, true);
  h.context.exports.onReconcile();
  assert(!h.state.timers.has('lcp_echo') && !h.state.timers.has('redial_retry'), 'manual disconnect must remain down after reconcile');

  h.setResource('sessions', 'last', {
    phase: 'redial_wait',
    profile_key: 'default',
    lcp_ready: false,
    redial_next_attempt: 2
  }, true);
  h.context.exports.onReconcile();
  const retry = h.state.timers.get('redial_retry');
  assert(retry && retry.payload.redial_attempt === 2, 'reconcile should resume an interrupted redial sequence');
}

function testProfilePersistenceFailsBeforeDialing() {
  const h = createHarness({auth: 'none', resourceSetError: 'profiles'});
  assert.throws(() => runAction(h, 'dial', {
    interface: 'eth0',
    auth: 'none',
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    keepalive_interval_ms: 1000,
    auto_redial: true,
    wan_core_sync: false
  }), /resource set failed/);
  assert.strictEqual(h.state.l2Exchanges.length, 0, 'profile persistence failure must happen before PADI');
}

function testKeepaliveRedialPreservesTunnelPreparation() {
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
    keepalive_interval_ms: 1000,
    auto_redial: true,
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    prepare_interfaces: true,
    prepare_local_mtu: true,
    prepare_wan_mtu: false,
    prepare_offloads: false,
    allow_unsafe_offloads: true,
    sync_hook_bindings: true,
    apply_hook_bindings: true,
    decap_mode: 'manual',
    wan_core_sync: false
  });

  const payload = h.state.timers.get('lcp_echo').payload;
  assert.strictEqual(payload.prepare_interfaces, true);
  assert.strictEqual(payload.prepare_local_mtu, true);
  assert.strictEqual(payload.prepare_wan_mtu, false);
  assert.strictEqual(payload.prepare_offloads, false);
  assert.strictEqual(payload.allow_unsafe_offloads, true);
  assert.strictEqual(payload.sync_hook_bindings, true);
  assert.strictEqual(payload.apply_hook_bindings, true);
  assert.strictEqual(payload.decap_mode, 'manual');
}

function testRequiredWANCoreSyncFailsClosed() {
  const h = createHarness({auth: 'none', pluginResourceError: 'wan core apply failed'});
  assert.throws(() => runAction(h, 'traffic_probe', {
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    post_session_control_ms: 0,
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    wan_core_sync: true,
    wan_core_required: true
  }), /required WAN core handoff failed: wan core apply failed/);

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.phase, 'handoff_error');
  assert.strictEqual(session.tunnel_installed, false);
  const link = h.resource('wan_links', 'default').data;
  assert.strictEqual(link.state, 'down');
  assert.strictEqual(link.usable, false);
  const clear = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config' && item.value === '00'.repeat(52));
  assert(clear, 'required WAN core failure should clear the tunnel map');
}

function testPapIPv6PDTunnel() {
  const h = createHarness({auth: 'pap', echoReplies: true, ipcpDNS: true});
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
    ipv6_iid: '0011223344556677',
    request_pd: true,
    dhcpv6_timeout_ms: 8000,
    ipv6_ra_timeout_ms: 8000,
    dhcpv6_settle_ms: 0,
    keepalive_interval_ms: 1000,
    auto_redial: true,
    send_padt: false,
    post_session_control_ms: 0,
    local_interface: 'veerlocal0',
    prepare_interfaces: true,
    prepare_local_mtu: true,
    prepare_wan_mtu: false,
    prepare_offloads: true,
    wan_core_sync: true,
    wan_core_apply: true
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.phase, 'session_probe');
  assert.strictEqual(session.session_id, SESSION_ID);
  assert.match(session.lcp_magic, /^[0-9a-f]{8}$/);
  assert.strictEqual(session.lcp_ack, true);
  assert.strictEqual(session.auth_sent, true);
  assert.strictEqual(session.auth_method, 'pap');
  assert.strictEqual(session.auth_ok, true);
  assert.strictEqual(session.ipcp.phase, 'configure_ack');
  assert.strictEqual(session.ipcp.address, '198.51.100.10');
  assert.deepStrictEqual(session.ipcp.dns_servers, ['223.5.5.5', '1.1.1.1']);
  assert.strictEqual(session.ipv6cp.phase, 'configure_ack');
  assert.strictEqual(session.ipv6cp.up, true);
  assert.strictEqual(session.ipv6_ra.phase, 'router_advertisement');
  assert.strictEqual(session.ipv6_ra.address, '2001:db8:cafe:1:11:2233:4455:6677');
  assert.strictEqual(session.ipv6_ra.router, 'fe80::2');
  assert.strictEqual(session.dhcpv6_pd.phase, 'reply');
  assert.strictEqual(session.dhcpv6_pd.address, '2001:db8:abcd::10');
  assert.strictEqual(session.dhcpv6_pd.prefix, '2001:db8:1234::/56');
  assert.deepStrictEqual(session.dhcpv6_pd.dns_servers, ['2001:4860:4860::8888', '2400:3200::1']);
  assert.deepStrictEqual(h.resource('wan_links', 'default').data.dns_servers, ['223.5.5.5', '1.1.1.1', '2001:4860:4860::8888', '2400:3200::1']);
  assert.strictEqual(session.tunnel_installed, true);
  assert.strictEqual(session.tunnel.mode, 'segmented_veth');
  assert.strictEqual(session.tunnel.pipeline_interface, PIPELINE_INTERFACE);
  assert.strictEqual(session.tunnel.decap_mode, 'auto');

  const tunnelPut = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config' && item.value !== '00'.repeat(52));
  assert(tunnelPut, 'traffic_probe should install a non-zero tunnel config');
  assert.strictEqual(tunnelPut.value.length, 104, 'tunnel config map value must stay ABI-sized');
  assert.strictEqual(tunnelPut.value.slice(16, 24), '66000000', 'pipeline ifindex should be encoded after local ifindex');
  assert.strictEqual(tunnelPut.value.slice(36, 40), '0000', 'default tunnel config should prefer automatic decapsulation');
  assert.strictEqual(tunnelPut.value.slice(40, 44), 'ac05', 'IPv4 TCP MSS clamp should default to 1452 for PPPoE MRU 1492');
  const tunnelRecord = h.resource('tunnel_configs', 'active');
  assert.strictEqual(tunnelRecord.enabled, true, 'traffic_probe should persist active tunnel config');
  assert.strictEqual(tunnelRecord.data.value_hex, tunnelPut.value, 'persisted tunnel config should match applied map value');
  assert.match(tunnelRecord.data.lcp_magic, /^[0-9a-f]{8}$/, 'active tunnel config should retain the negotiated LCP magic');
  assert.strictEqual(tunnelPut.value.slice(-8), tunnelRecord.data.lcp_magic, 'eBPF tunnel config should include the local LCP magic');
  assert(h.state.timers.has('tunnel_repair'), 'active tunnel config should arm repair timer');
  assert(h.state.timers.has('lcp_echo'), 'traffic_probe should arm keepalive when requested');
  assert(!h.state.netCalls.some((item) => item.startsWith('setMTU:veerlocal0:') || item.startsWith('setGSO:veerlocal0:') ||
    item.startsWith('setOffloads:veerlocal0:') || item.startsWith(`setOffloads:${PIPELINE_INTERFACE}:`)),
  'PPPoE must not modify WAN Core-owned handoff interfaces directly');
  assert(h.state.l2Exchanges.every((item) => !item.timeout_ms || item.timeout_ms <= 5000), 'long IPv6 deadlines must use bounded L2 receive windows');

  const ingressBinding = h.resource('hook_bindings', 'pppoe-ingress').data;
  const egressBinding = h.resource('hook_bindings', 'pppoe-egress').data;
  assert.deepStrictEqual(ingressBinding.interfaces, ['eth0']);
  assert.deepStrictEqual(egressBinding.interfaces, [PIPELINE_INTERFACE]);
  const prepareCall = h.state.pluginActionCalls.find((item) => item.plugin === 'wan_core' && item.action === 'prepare_handoff');
  assert(prepareCall, 'WAN Core handoff should be prepared before dialing');
  assert.deepStrictEqual(prepareCall.payload.interface_preparation.local_gso, {max_size: 1492, max_segs: 1});
  assert.deepStrictEqual(prepareCall.payload.interface_preparation.local_offloads, {sg: false, tso: false, gso: false});
  assert.deepStrictEqual(prepareCall.payload.interface_preparation.pipeline_offloads, {gro: false, lro: false});
  const wanSync = h.pluginResource('wan_core', 'sessions', 'default');
  assert(wanSync, 'wan_core session handoff should be written through plugin.resource');
  assert.strictEqual(wanSync.data.driver, 'pppoe');
  assert.strictEqual(wanSync.data.usable, true);
  assert.strictEqual(wanSync.data.ipv6, '2001:db8:abcd::10');
}

function testDHCPv6RenewRebindAndRecovery() {
  const options = {auth: 'pap', echoReplies: true, ipcpDNS: true, dhcpv6TimeoutTypes: []};
  const h = createHarness(options);
  runAction(h, 'traffic_probe', dhcpv6TestPayload());

  let session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.renew_seconds, 1800);
  assert.strictEqual(session.dhcpv6_pd.rebind_seconds, 2880);
  assert.strictEqual(session.dhcpv6_pd.valid_seconds, 7200);
  assert(h.state.timers.has('dhcpv6_lease'), 'active DHCPv6 binding should arm a lease timer');
  assert(h.state.dhcpv6Messages.every((message) => !message.options.some((option) => option.code === 20)),
    'client must not advertise Reconfigure Accept without implementing Reconfigure');

  session.dhcpv6_pd.renew_at_ms = Date.now() - 1;
  session.dhcpv6_pd.rebind_at_ms = Date.now() + 60000;
  session.dhcpv6_pd.expires_at_ms = Date.now() + 120000;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  assert.strictEqual(h.state.dhcpv6Messages[h.state.dhcpv6Messages.length - 1].message_type, 5);
  assert.strictEqual(session.dhcpv6_pd.phase, 'renew_reply');
  assert.strictEqual(session.dhcpv6_pd.renew_attempts, 0);
  assert(h.state.timers.has('dhcpv6_lease'));

  session.dhcpv6_pd.renew_at_ms = Date.now() - 2000;
  session.dhcpv6_pd.rebind_at_ms = Date.now() - 1;
  session.dhcpv6_pd.expires_at_ms = Date.now() + 120000;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  const rebind = h.state.dhcpv6Messages[h.state.dhcpv6Messages.length - 1];
  assert.strictEqual(rebind.message_type, 6);
  assert(!rebind.options.some((option) => option.code === 2), 'Rebind must omit Server Identifier');
  assert.strictEqual(session.dhcpv6_pd.phase, 'rebind_reply');

  options.dhcpv6TimeoutTypes = [5];
  session.dhcpv6_pd.renew_at_ms = Date.now() - 1;
  session.dhcpv6_pd.rebind_at_ms = Date.now() + 60000;
  session.dhcpv6_pd.expires_at_ms = Date.now() + 120000;
  const retainedPrefix = session.dhcpv6_pd.prefix;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'renew_retry');
  assert.strictEqual(session.dhcpv6_pd.prefix, retainedPrefix, 'Renew timeout must retain a still-valid binding');
  assert(session.dhcpv6_pd.next_retry_at_ms > Date.now());
  assert(h.state.timers.has('dhcpv6_lease'));

  options.dhcpv6TimeoutTypes = [1];
  session.dhcpv6_pd.expires_at_ms = Date.now() - 1;
  session.dhcpv6_pd.next_retry_at_ms = 0;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'reacquire_retry');
  assert.strictEqual(session.dhcpv6_pd.prefix, '', 'expired delegated prefix must fail closed');
  assert.strictEqual(h.resource('wan_links', 'default').data.pd_prefix, '');

  options.dhcpv6TimeoutTypes = [];
  session.dhcpv6_pd.next_retry_at_ms = Date.now() - 1;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'reply');
  assert.strictEqual(session.dhcpv6_pd.prefix, '2001:db8:1234::/56');
  assert.strictEqual(session.dhcpv6_pd.reacquire_attempts, 0);
}

function testDHCPv6PartialIANAStatusKeepsPDLease() {
  const h = createHarness({auth: 'pap', echoReplies: true, dhcpv6NoAddress: true});
  runAction(h, 'traffic_probe', dhcpv6TestPayload());

  let session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'reply');
  assert.strictEqual(session.dhcpv6_pd.address, '');
  assert.strictEqual(session.dhcpv6_pd.prefix, '2001:db8:1234::/56');
  assert.strictEqual(session.dhcpv6_pd.partial_binding, true);
  assert.deepStrictEqual(session.dhcpv6_pd.partial_ias, ['ia_na']);
  assert.match(session.dhcpv6_pd.partial_reason, /NOADDRS-AVAIL/);
  assert.strictEqual(session.dhcpv6_pd.ia_na_hex, '', 'failed IA_NA must not enter Renew');
  assert.strictEqual(session.dhcpv6_pd.renew_seconds, 1800);
  assert(h.state.timers.has('dhcpv6_lease'), 'a valid IA_PD must retain lease maintenance');
  const request = h.state.dhcpv6Messages.find((message) => message.message_type === 3);
  assert(request, 'partial Advertise must proceed to Request');
  assert(!request.options.some((option) => option.code === 3), 'Request must not echo a failed IA_NA status');

  session.dhcpv6_pd.renew_at_ms = Date.now() - 1;
  session.dhcpv6_pd.rebind_at_ms = Date.now() + 60000;
  session.dhcpv6_pd.expires_at_ms = Date.now() + 120000;
  h.setResource('sessions', 'last', session, true);
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: clone(h.state.timers.get('dhcpv6_lease').payload)}});
  session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'renew_reply');
  assert.strictEqual(session.dhcpv6_pd.prefix, '2001:db8:1234::/56');
  assert(h.state.timers.has('dhcpv6_lease'));
}

function testDHCPv6ReconcileRestoresLeaseTimerWithoutKeepalive() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  runAction(h, 'traffic_probe', dhcpv6TestPayload({keepalive_interval_ms: 0}));
  assert(!h.state.timers.has('lcp_echo'));
  assert(h.state.timers.has('dhcpv6_lease'));

  h.state.timers.clear();
  h.context.exports.onReconcile();
  assert(!h.state.timers.has('lcp_echo'));
  assert(h.state.timers.has('dhcpv6_lease'), 'reconcile must restore DHCPv6 independently of LCP keepalive');

  const staleLeaseTimer = clone(h.state.timers.get('dhcpv6_lease').payload);
  const exchanges = h.state.dhcpv6Messages.length;
  runAction(h, 'disconnect', {profile_key: 'default'});
  assert(!h.state.timers.has('dhcpv6_lease'), 'disconnect must cancel DHCPv6 lease maintenance');
  h.context.exports.onTimer({timer: {name: 'dhcpv6_lease', payload: staleLeaseTimer}});
  assert.strictEqual(h.state.dhcpv6Messages.length, exchanges, 'queued lease timer must not revive a disconnected session');
}

function testDHCPv6InvalidLeaseTimersFailClosed() {
  const h = createHarness({auth: 'pap', echoReplies: true, dhcpv6T1: 3000, dhcpv6T2: 2000});
  runAction(h, 'traffic_probe', dhcpv6TestPayload());
  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.phase, 'request_invalid_lease_timers');
  assert.strictEqual(session.dhcpv6_pd.prefix, undefined);
  assert.strictEqual(h.resource('wan_links', 'default').data.pd_prefix, '');
  assert(h.state.timers.has('dhcpv6_lease'), 'invalid DHCPv6 reply should retry without redialing the PPPoE session');
}

function dhcpv6TestPayload(overrides) {
  return Object.assign({
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
    ipv6_iid: '0011223344556677',
    request_ipv6_address: true,
    request_pd: true,
    dhcpv6_timeout_ms: 8000,
    ipv6_ra_timeout_ms: 8000,
    dhcpv6_settle_ms: 0,
    keepalive_interval_ms: 0,
    auto_redial: true,
    send_padt: false,
    post_session_control_ms: 0,
    local_interface: 'veerlocal0',
    prepare_interfaces: true,
    prepare_local_mtu: true,
    prepare_wan_mtu: false,
    prepare_offloads: true,
    wan_core_sync: true,
    wan_core_apply: true
  }, overrides || {});
}

function testAutoAuthNegotiatesPAP() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  runAction(h, 'dial', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    keepalive_interval_ms: 0,
    wan_core_sync: false
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.auth, 'auto');
  assert.strictEqual(session.peer_lcp_ack_sent, true);
  assert.strictEqual(session.peer_auth_method, 'pap');
  assert.strictEqual(session.auth_method, 'pap');
  assert.strictEqual(session.auth_ok, true);
  assert.strictEqual(session.lcp_ready, true);
  assert.strictEqual(h.resource('profiles', 'default').data.auth, 'auto');
}

function testAutoAuthNegotiatesCHAP() {
  const h = createHarness({auth: 'chap', echoReplies: true});
  runAction(h, 'dial', {
    interface: 'eth0',
    username: 'chap-user',
    password: 'chap-pass',
    auth: 'auto',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    keepalive_interval_ms: 0,
    wan_core_sync: false
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.peer_auth_method, 'chap');
  assert.strictEqual(session.auth_method, 'chap');
  assert.strictEqual(session.auth_ok, true);
  assert.strictEqual(session.lcp_ready, true);
}

function testExplicitAuthMismatchFailsClosed() {
  const h = createHarness({auth: 'chap'});
  assert.throws(() => runAction(h, 'dial', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'pap',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    wan_core_sync: false
  }), /peer requires chap authentication but profile auth is pap/);
}

function testAutoAuthRejectsUnsupportedCHAPAlgorithm() {
  const h = createHarness({auth: 'chap-unsupported'});
  assert.throws(() => runAction(h, 'dial', {
    interface: 'eth0',
    username: 'user',
    password: 'pass',
    auth: 'auto',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    send_padt: false,
    wan_core_sync: false
  }), /unsupported CHAP algorithm/);
}

function testIPCPDNSRejectFallsBack() {
  const h = createHarness({auth: 'none', ipcpRejectDNS: true});
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: true,
    negotiate_ipv6: false,
    send_padt: false,
    keepalive_interval_ms: 0,
    auto_redial: false,
    install_tunnel: false,
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    wan_core_sync: false
  });
  const ipcp = h.resource('sessions', 'last').data.ipcp;
  assert.strictEqual(ipcp.phase, 'configure_ack', 'IPCP must continue when only DNS options are rejected');
  assert.deepStrictEqual(ipcp.dns_servers, []);
}

function testRADrivenIPv6WithoutIANA() {
  const h = createHarness({auth: 'none', echoReplies: true, omitIANA: true});
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: true,
    ipv6_iid: '0011223344556677',
    request_pd: true,
    dhcpv6_settle_ms: 0,
    send_padt: false,
    post_session_control_ms: 0,
    local_interface: 'veerlocal0',
    wan_core_sync: true,
    wan_core_apply: true
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.dhcpv6_pd.address, '');
  assert.strictEqual(session.ipv6_ra.address, '2001:db8:cafe:1:11:2233:4455:6677');
  const wanSync = h.pluginResource('wan_core', 'sessions', 'default');
  assert.strictEqual(wanSync.data.ipv6, '2001:db8:cafe:1:11:2233:4455:6677');
  assert.strictEqual(wanSync.data.ipv6_gateway, 'fe80::2');
}

function testManualMACUsesRawL2WithoutNetdev() {
  const h = createHarness({auth: 'pap', echoReplies: true});
  const manualMAC = '02:00:00:00:00:99';
  runAction(h, 'traffic_probe', {
    interface: 'eth0',
    mac_mode: 'manual',
    mac_address: manualMAC,
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
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
    prepare_interfaces: true,
    prepare_local_mtu: true,
    prepare_offloads: true,
    wan_core_sync: false
  });

  const session = h.resource('sessions', 'last').data;
  assert.strictEqual(session.tunnel_installed, true);
  assert.strictEqual(session.tunnel.wan_src_mac, manualMAC);
  assert(h.state.l2Exchanges.every((item) => item.src_mac === manualMAC && item.recv_dst_mac === manualMAC), 'all PPPoE exchanges should use the manual MAC');
  assert(!h.state.netCalls.some((item) => item.startsWith('ensure') || item.startsWith('delete:')), 'manual MAC must not create a Linux netdev');
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
  const persisted = h.resource('profiles', 'default').data;
  assert.strictEqual(persisted.username, 'chap-user');
  assert.strictEqual(persisted.keepalive_failure_threshold, 5);
  assert.strictEqual(persisted.keepalive_failure_grace_ms, 60000);
  assert.strictEqual(persisted.keepalive_confirm_timeout_ms, 5000);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(persisted, 'password'), false, 'runtime profile must not persist plaintext credentials');
  assert(h.state.timers.has('lcp_echo'), 'dial should arm lcp_echo keepalive');
  assert(!JSON.stringify(h.state.timers.get('lcp_echo').payload).includes('chap-pass'), 'keepalive timer payload must not contain the password');

  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: h.state.timers.get('lcp_echo').payload}});
  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_ok');
  assert.strictEqual(keepalive.session_id, SESSION_ID);
}

function testKeepaliveFailureThresholdRecoversWithoutRedial() {
  const options = {auth: 'none', echoReplies: false};
  const h = createHarness(options);
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

  const payload = {
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 3,
    auto_redial: true,
    redial_clear_tunnel: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  };

  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload}});
  let keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_timeout');
  assert.strictEqual(keepalive.keepalive_failures, 1);
  assert(h.state.timers.has('lcp_echo'), 'a single missed echo should keep the current session armed');
  assert(!h.state.timers.has('redial_retry'), 'a single missed echo must not trigger redial');
  assert.strictEqual(h.resource('wan_links', 'default').data.state, 'up');

  options.echoReplies = true;
  const retryPayload = h.state.timers.get('lcp_echo').payload;
  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: retryPayload}});
  keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_ok');
  assert.strictEqual(keepalive.keepalive_failures, 0);
  assert.strictEqual(h.state.timers.get('lcp_echo').payload.keepalive_failures, 0);
  assert(!h.state.l2Sends.some((item) => discoveryCode(item.payload) === CODE_PADT), 'recovered keepalive must not close the session');
}

function testKeepaliveGracePreventsPrematureRedial() {
  const h = createHarness({auth: 'none', echoReplies: false});
  h.setResource('sessions', 'last', {
    phase: 'session_probe', session_id: SESSION_ID, ac_mac: AC_MAC, lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default', state: 'up', usable: true, session_id: SESSION_ID, ac_mac: AC_MAC
  }, true);
  const started = Date.now();

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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 60000,
    keepalive_confirm_timeout_ms: 100,
    keepalive_failure_started_ms: started,
    auto_redial: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_timeout');
  assert(keepalive.keepalive_grace_remaining_ms > 0, 'failure grace should remain active');
  assert(!h.state.timers.has('redial_retry'), 'grace period must suppress redial');
  assert.strictEqual(h.state.timers.get('lcp_echo').payload.keepalive_failure_started_ms, started);
  assert.strictEqual(h.resource('wan_links', 'default').data.state, 'up');
  assert(!h.state.l2Sends.some((item) => discoveryCode(item.payload) === CODE_PADT));
}

function testKeepaliveFinalConfirmationRecoversWithoutPADT() {
  const h = createHarness({auth: 'none', echoReplySequence: [false, true]});
  h.setResource('sessions', 'last', {
    phase: 'session_probe', session_id: SESSION_ID, ac_mac: AC_MAC, lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default', state: 'up', usable: true, session_id: SESSION_ID, ac_mac: AC_MAC
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 100,
    auto_redial: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'keepalive_ok');
  assert.strictEqual(keepalive.keepalive_confirmation, 'recovered');
  assert.strictEqual(keepalive.keepalive_recovered_after_failures, 1);
  assert.strictEqual(h.state.timers.get('lcp_echo').payload.keepalive_failures, 0);
  assert(!h.state.timers.has('redial_retry'));
  assert(!h.state.records.has('sessions/redial_last'));
  assert(!h.state.l2Sends.some((item) => discoveryCode(item.payload) === CODE_PADT));
}

function testDisabledAutoRedialHonorsFailureGrace() {
  const h = createHarness({auth: 'none', echoReplies: false});
  h.setResource('sessions', 'last', {
    phase: 'session_probe', session_id: SESSION_ID, ac_mac: AC_MAC, lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default', state: 'up', usable: true, session_id: SESSION_ID, ac_mac: AC_MAC
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 60000,
    auto_redial: false,
    redial_clear_tunnel: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  assert(h.state.timers.has('lcp_echo'), 'disabled redial must keep probing during grace');
  assert.strictEqual(h.resource('wan_links', 'default').data.state, 'up');
  assert(!h.state.mapPuts.some((item) => item.map === 'pppoe_tunnel_config' && item.value === '00'.repeat(52)),
    'one timeout must not clear the tunnel when auto redial is disabled');
}

function testKeepaliveTransportErrorKeepsRetryState() {
  const h = createHarness({auth: 'none', linkGetError: 'link temporarily unavailable'});
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default',
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 100,
    auto_redial: true,
    redial_retry_initial_ms: 250,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  let keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'redial_wait');
  assert.strictEqual(keepalive.redial_trigger, 'keepalive_confirm_error');
  assert(h.state.timers.has('redial_retry'));
  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: h.state.timers.get('redial_retry').payload}});
  keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'redial_wait');
  assert.match(keepalive.redial_error, /link temporarily unavailable/);
  assert.strictEqual(keepalive.redial_next_attempt, 2);
  assert(h.state.timers.has('redial_retry'), 'a retry-time link error must schedule the next attempt');
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 100,
    redial_clear_tunnel: true,
    redial_retry_initial_ms: 250,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  let keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.redial_attempted, true);
  assert.strictEqual(keepalive.phase, 'redial_wait');
  assert.strictEqual(keepalive.redial_next_attempt, 1);
  assert(!h.state.timers.has('lcp_echo'), 'failed session keepalive must stop before redial');
  assert(h.state.timers.has('redial_retry'), 'redial should use an independent retry timer');
  assert(h.state.l2Sends.some((item) => discoveryCode(item.payload) === CODE_PADT), 'redial should close the stale session first');
  assert.strictEqual(h.resource('sessions', 'redial_last').data.trigger, 'keepalive_confirm_timeout');

  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: h.state.timers.get('redial_retry').payload}});
  keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'redial_ok');
  assert.strictEqual(keepalive.redial_session_id, SESSION_ID);
  assert(!h.state.timers.has('redial_retry'), 'successful redial should clear retry state');
  assert(h.state.timers.has('lcp_echo'), 'successful redial should arm keepalive for the new session');
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 100,
    redial_clear_tunnel: true,
    redial_retry_initial_ms: 250,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});

  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: h.state.timers.get('redial_retry').payload}});
  const keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.redial_attempted, true);
  assert.strictEqual(keepalive.phase, 'redial_wait');
  assert.strictEqual(keepalive.redial_phase, 'session_probe');
  assert.match(keepalive.redial_error, /authentication failed/);
  assert.strictEqual(keepalive.redial_next_attempt, 2);
  assert(h.state.timers.has('redial_retry'), 'authentication failure should stay visible and retry with backoff');
  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.lcp_ready, false);
  assert.strictEqual(last.phase, 'redial_wait');
}

function testRedialDiscoveryFailureRetriesWithoutOldKeepalive() {
  const options = {auth: 'none', echoReplies: false, padsTimeout: true};
  const h = createHarness(options);
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
    ac_mac: AC_MAC,
    local_interface: 'veerlocal0'
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 100,
    auto_redial: true,
    redial_clear_tunnel: true,
    redial_retry_initial_ms: 250,
    redial_retry_max_ms: 1000,
    local_interface: 'veerlocal0',
    wan_core_sync: true,
    wan_core_required: true,
    wan_core_apply: true,
    session_id: SESSION_ID,
    ac_mac: AC_MAC
  }}});

  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: h.state.timers.get('redial_retry').payload}});
  let keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'redial_wait');
  assert.strictEqual(keepalive.redial_next_attempt, 2);
  assert.match(keepalive.redial_error, /PADS timeout/);
  assert(!h.state.timers.has('lcp_echo'), 'failed discovery must not resume the stale session keepalive');
  let wan = h.pluginResource('wan_core', 'sessions', 'default');
  assert(wan && wan.enabled === false, 'failed discovery should keep WAN Core fail-closed');

  options.padsTimeout = false;
  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: h.state.timers.get('redial_retry').payload}});
  keepalive = h.resource('sessions', 'keepalive').data;
  assert.strictEqual(keepalive.phase, 'redial_ok');
  assert.strictEqual(keepalive.redial_attempt, 2);
  assert(h.state.timers.has('lcp_echo'), 'recovered discovery should arm only the new session keepalive');
  assert(!h.state.timers.has('redial_retry'));
  wan = h.pluginResource('wan_core', 'sessions', 'default');
  assert(wan && wan.enabled === true && wan.apply === true, 'successful retry should republish WAN Core');
}

function testDisconnectClearsTunnelAndWANState() {
  const h = createHarness({auth: 'none', terminateOnPADT: true});
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

  const padt = h.state.l2Sends.concat(h.state.l2Exchanges).find((req) => req.ethertype === ETH_P_PPP_DISC && discoveryCode(req.payload) === CODE_PADT);
  assert(padt, 'disconnect should send PADT');
  const terminateAck = h.state.l2Sends.find((req) => {
    if (req.ethertype !== ETH_P_PPP_SESS || !req.payload) return false;
    const parsed = h.context.parseSessionFrame({payload_hex: req.payload});
    if (parsed.protocol !== PPP_LCP) return false;
    const cp = h.context.parseCP(parsed.payload);
    return cp.code === 6;
  });
  assert(terminateAck, 'disconnect should acknowledge the peer LCP Terminate-Request');
  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.phase, 'disconnected');
  assert.strictEqual(last.padt_sent, true);
  assert.strictEqual(last.lcp_terminate_ack_sent, true);
  assert.strictEqual(last.disconnect_control.phase, 'terminated');
  assert.strictEqual(last.disconnect_control.terminate_acks_sent, 1);
  const wan = h.resource('wan_links', 'default');
  assert.strictEqual(wan.enabled, false);
  assert.strictEqual(wan.data.usable, false);
  assert.strictEqual(wan.data.phase, 'disconnected');
  const clear = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config' && item.value === '00'.repeat(52));
  assert(clear, 'disconnect should clear tunnel config');
  assert(!h.state.timers.has('tunnel_repair'), 'disconnect should clear tunnel repair timer');
}

function testDialIsIdempotentWhileSessionIsActive() {
  const h = createHarness({auth: 'none', echoReplies: true});
  const payload = {
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    keepalive_interval_ms: 1000,
    post_session_control_ms: 0,
    wan_core_sync: false
  };
  runAction(h, 'dial', payload);
  const first = h.resource('sessions', 'last').data;
  const exchanges = h.state.l2Exchanges.length;

  runAction(h, 'dial', {profile_key: 'default'});

  const second = h.resource('sessions', 'last').data;
  assert.strictEqual(h.state.l2Exchanges.length, exchanges, 'dial on an active profile must not start another discovery');
  assert.strictEqual(second.session_id, first.session_id);
  assert.strictEqual(second.session_generation, first.session_generation);
  assert.match(first.session_generation, /^[0-9a-f]{16}$/);
}

function testQueuedSessionTimersCannotReviveDisconnectedSession() {
  const h = createHarness({auth: 'none', echoReplies: true, terminateOnPADT: true});
  runAction(h, 'dial', {
    interface: 'eth0',
    auth: 'none',
    timeout_ms: 50,
    control_ack_timeout_ms: 10,
    control_idle_timeout_ms: 1,
    max_frames: 4,
    negotiate_ipv4: false,
    negotiate_ipv6: false,
    request_pd: false,
    send_padt: false,
    keepalive_interval_ms: 1000,
    post_session_control_ms: 1000,
    wan_core_sync: false
  });
  const staleKeepalive = clone(h.state.timers.get('lcp_echo').payload);
  const staleControl = clone(h.state.timers.get('session_control').payload);
  assert(staleKeepalive.session_generation, 'keepalive must carry the active session generation');
  assert.strictEqual(staleControl.session_generation, staleKeepalive.session_generation);

  runAction(h, 'disconnect', {profile_key: 'default'});
  const callsAfterDisconnect = h.state.l2Sends.length + h.state.l2Exchanges.length + h.state.l2Recvs.length;
  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: staleKeepalive}});
  h.context.exports.onTimer({timer: {name: 'session_control', payload: staleControl}});

  const last = h.resource('sessions', 'last').data;
  assert.strictEqual(last.phase, 'disconnected');
  assert.strictEqual(last.desired_state, 'down');
  assert.strictEqual(h.state.l2Sends.length + h.state.l2Exchanges.length + h.state.l2Recvs.length,
    callsAfterDisconnect, 'queued session timers must exit before any L2 operation');
  assert(!h.state.timers.has('lcp_echo'));
  assert(!h.state.timers.has('session_control'));
  assert(!h.state.timers.has('redial_retry'));

  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    profile_key: 'default',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    session_generation: 'ff'.repeat(8),
    desired_state: 'up',
    lcp_ready: true,
    padt_sent: false
  }, true);
  h.context.exports.onTimer({timer: {name: 'lcp_echo', payload: staleKeepalive}});
  assert.strictEqual(h.state.l2Sends.length + h.state.l2Exchanges.length + h.state.l2Recvs.length,
    callsAfterDisconnect, 'a reused session id and AC MAC must still reject an older generation');
}

function testQueuedRedialCannotRunAfterDisconnect() {
  const h = createHarness({auth: 'none', echoReplies: false});
  h.setResource('sessions', 'last', {
    phase: 'session_probe',
    profile_key: 'default',
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    lcp_ready: true
  }, true);
  h.setResource('wan_links', 'default', {
    wan_id: 'default', state: 'up', usable: true, session_id: SESSION_ID, ac_mac: AC_MAC
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
    keepalive_interval_ms: 1000,
    keepalive_failure_threshold: 1,
    keepalive_failure_grace_ms: 0,
    keepalive_confirm_timeout_ms: 20,
    auto_redial: true,
    redial_clear_tunnel: true,
    redial_retry_initial_ms: 250,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  }}});
  const staleRedial = clone(h.state.timers.get('redial_retry').payload);
  assert(staleRedial.redial_generation, 'redial retry must carry a cancellation generation');

  runAction(h, 'disconnect', {
    profile_key: 'default',
    interface: 'eth0',
    auth: 'none',
    disconnect_drain_ms: 0,
    session_id: SESSION_ID,
    ac_mac: AC_MAC,
    wan_core_sync: false
  });
  const exchanges = h.state.l2Exchanges.length;
  h.context.exports.onTimer({timer: {name: 'redial_retry', payload: staleRedial}});

  assert.strictEqual(h.state.l2Exchanges.length, exchanges, 'queued redial must not send PADI after disconnect');
  assert.strictEqual(h.resource('sessions', 'last').data.phase, 'disconnected');
  assert(!h.state.timers.has('redial_retry'));
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
    local_interface: 'veerlocal0',
    pipeline_interface: PIPELINE_INTERFACE,
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
    records: [{key: 'active', data: {value_hex: '11'.repeat(48)}, enabled: true}]
  });
  const migrated = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config');
  assert.strictEqual(migrated.value, '11'.repeat(48) + '00'.repeat(4), 'legacy tunnel config should gain a zero LCP magic');

  h.state.mapPuts.length = 0;
  h.context.exports.onResourceApply({
    resource: {id: 'tunnel_configs', runtime_update: 'runtime_apply'},
    records: []
  });
  const clear = h.state.mapPuts.find((item) => item.object === 'pppoe_tunnel' && item.map === 'pppoe_tunnel_config');
  assert(clear, 'empty tunnel config apply should clear eBPF map');
  assert.strictEqual(clear.value, '00'.repeat(52), 'empty tunnel config apply should write zero ABI value');
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
    local_interface: 'veerlocal0',
    wan_core_sync: false
  }), /PADS timeout/);
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
  assert.strictEqual(stats.local_encap_path, 0);
  assert.strictEqual(stats.pppoe_seen, 0);
}

function testTrafficStatsAggregatePerCPUValues() {
  const h = createHarness({
    auth: 'none',
    perCPUValues: [
      u64leHex(1) + u64leHex(100) + u64leHex(2) + u64leHex(200),
      u64leHex(3) + u64leHex(300) + u64leHex(4) + u64leHex(400)
    ]
  });
  h.setResource('sessions', 'last', {profile_key: 'default', session_id: SESSION_ID}, true);
  h.setResource('tunnel_configs', 'active', {session_id: SESSION_ID}, true);
  const stats = runAction(h, 'traffic_stats', {profile_key: 'default'});
  assert.strictEqual(stats.available, true);
  assert.strictEqual(stats.rx_packets, 4);
  assert.strictEqual(stats.rx_bytes, 400);
  assert.strictEqual(stats.tx_packets, 6);
  assert.strictEqual(stats.tx_bytes, 600);
  assert.strictEqual(stats.byte_scope, 'inner_ip');
}

function createHarness(options) {
  const state = {
    capabilities: [],
    virtualInterfaces: [],
    objects: [],
    hooks: [],
    resources: [],
    actions: [],
    services: [],
    ui: null,
    records: new Map(),
    links: new Map(),
    pluginRecords: new Map(),
    pluginActionCalls: [],
    secrets: new Map(),
    timers: new Map(),
    mapPuts: [],
    mapClears: [],
    mapValues: new Map(),
    l2Sends: [],
    l2Exchanges: [],
    l2Recvs: [],
    dhcpv6Messages: [],
    netCalls: [],
    randomByte: 1,
    lastEchoIdentifier: null,
    ipcpNAKSent: false
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
      pipelineNode(item) { state.virtualInterfaces.push(Object.assign({type: 'pipeline'}, clone(item))); },
      handoff(item) { state.virtualInterfaces.push(Object.assign({type: 'handoff'}, clone(item))); },
      resource(item) { state.resources.push(clone(item)); },
      action(item) { state.actions.push(clone(item)); },
      service(item) { state.services.push(clone(item)); }
    },
    pipeline: {
      node(item) { state.virtualInterfaces.push(Object.assign({type: 'pipeline'}, clone(item))); },
      handoff(item) { state.virtualInterfaces.push(Object.assign({type: 'handoff'}, clone(item))); },
      attach(item) {
        const hook = clone(item);
        hook.stage = hook.direction || hook.stage;
        delete hook.direction;
        if (!hook.engine) hook.engine = 'tc';
        if (!hook.attach) hook.attach = 'ingress';
        state.hooks.push(hook);
      }
    },
    ebpf: {
      loadObject(item) { state.objects.push(clone(item)); },
      mapPut(object, map, key, value) {
        state.mapPuts.push({object, map, key, value});
        state.mapValues.set(`${object}/${map}/${key}`, value);
      },
      mapGet(object, map, key) {
        return state.mapValues.get(`${object}/${map}/${key}`) || '00'.repeat(8);
      },
      mapGetPerCPU() {
        return options && Array.isArray(options.perCPUValues) ? options.perCPUValues.slice() : ['00'.repeat(32)];
      },
      mapClear(object, map) {
        state.mapClears.push({object, map});
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
      list(resource) {
        return resourceRecords(state, resource);
      },
      set(resource, key, data, enabled, apply) {
        if (options && options.resourceSetError === resource) throw new Error('resource set failed: ' + resource);
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
        get(plugin, resource, key) {
          const record = state.pluginRecords.get(`${plugin}/${resource}/${key}`);
          return record ? clone(record) : null;
        },
        set(plugin, resource, key, data, enabled, apply) {
          if (options && options.pluginResourceError) throw new Error(options.pluginResourceError);
          state.pluginRecords.set(`${plugin}/${resource}/${key}`, {
            data: clone(data),
            enabled: enabled !== false,
            apply: apply === true
          });
        }
      },
      actions: {
        call(plugin, action, payload) {
          state.pluginActionCalls.push({plugin, action, payload: clone(payload || {})});
          if (options && options.pluginActionError) throw new Error(options.pluginActionError);
          if (plugin !== 'wan_core' || action !== 'prepare_handoff') {
            throw new Error(`unexpected plugin action ${plugin}/${action}`);
          }
          const key = String(payload.wan_id || payload.profile_key || payload.key || 'default');
          const localInterface = String(payload.local_interface || 'veerlocal0');
          const pipelineInterface = String(payload.pipeline_interface || PIPELINE_INTERFACE);
          state.links.set(localInterface, linkInfo(localInterface));
          state.links.set(pipelineInterface, linkInfo(pipelineInterface));
          const status = {
            phase: 'prepared',
            wan_id: key,
            usable: false,
            local_interface: localInterface,
            local_ifindex: linkInfo(localInterface).ifindex,
            pipeline_interface: pipelineInterface,
            pipeline_ifindex: linkInfo(pipelineInterface).ifindex,
            handoff_mode: 'segmented_veth',
            segmentation_ready: true,
            interface_preparation: payload.interface_preparation ? {
              applied: true,
              local_gso: payload.interface_preparation.local_gso,
              local_offloads: payload.interface_preparation.local_offloads,
              pipeline_offloads: payload.interface_preparation.pipeline_offloads,
              warnings: []
            } : {applied: false, warnings: []},
            veer_core: {
              mode: 'segmented_veth',
              parent_interface: localInterface,
              tunnel_interface: pipelineInterface,
              segmentation_ready: true
            }
          };
          state.pluginRecords.set(`wan_core/status/${key}`, {data: clone(status), enabled: false});
          return clone(status);
        }
      },
      services: {
        resolve(request) {
          if (!request || request.service !== 'wan.adapter' || request.provider !== 'wan_core') {
            throw new Error('unexpected service resolution');
          }
          return {
            plugin_id: 'wan_core',
            service: {
              id: 'wan.adapter', version: '1.0.0',
              actions: ['apply_session', 'prepare_handoff', 'teardown'],
              resources: ['profiles', 'sessions', 'status']
            }
          };
        },
        call(request) {
          this.resolve(request);
          const result = context.plugins.actions.call(request.provider, request.action, request.payload || {});
          return {status: 'completed', plugin: request.provider, action: request.action, result};
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
          if (options && options.linkGetError) throw new Error(options.linkGetError);
          if (state.links.has(name)) return clone(state.links.get(name));
          return linkInfo(name);
        },
        setPromiscuous(name, enabled) {
          const link = state.links.has(name) ? clone(state.links.get(name)) : linkInfo(name);
          link.promiscuous = !!enabled;
          state.links.set(name, clone(link));
          state.netCalls.push(`setPromiscuous:${name}:${!!enabled}`);
          return clone(link);
        },
        setMTU(name, mtu) {
          state.netCalls.push(`setMTU:${name}:${mtu}`);
        },
        setOffloads(name, features) {
          const parts = Object.keys(features).sort().map((key) => `${key}=${features[key]}`);
          state.netCalls.push(`setOffloads:${name}:${parts.join(',')}`);
        },
        setGSO(name, limits) {
          state.netCalls.push(`setGSO:${name}:${limits.max_size}:${limits.max_segs}`);
          return {name, gso_max_size: limits.max_size, gso_max_segs: limits.max_segs};
        }
      },
      l2: {
        send(req) {
          state.l2Sends.push(clone(req));
          rememberEchoRequest(state, context, req);
          rememberPADT(state, context, options || {}, req);
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
  return h.context.exports.onAction({action: {id}, payload: payload || {}});
}

function u64leHex(value) {
  let n = BigInt(value);
  let out = '';
  for (let i = 0; i < 8; i++) {
    out += Number(n & 0xffn).toString(16).padStart(2, '0');
    n >>= 8n;
  }
  return out;
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
    if (code === CODE_PADT && options.terminateOnPADT) {
      return [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(5, 0x7e, ctx.stringHex('Received PADT')))];
    }
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
  if (parsed.protocol === PPP_LCP && cp.code === 9) {
    let reply = !!options.echoReplies;
    if (Array.isArray(options.echoReplySequence) && options.echoReplySequence.length) {
      reply = !!options.echoReplySequence.shift();
    }
    if (reply) return [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(10, cp.identifier, '00000000'))];
    return [];
  }
  if (parsed.protocol === PPP_LCP && cp.code === 1) {
    let authOption = '';
    if (options.auth === 'pap' || options.auth === 'pap-reject') {
      authOption = ctx.cpOptionHex(3, ctx.u16hex(PPP_PAP));
    } else if (options.auth === 'chap') {
      authOption = ctx.cpOptionHex(3, ctx.u16hex(PPP_CHAP) + '05');
    } else if (options.auth === 'chap-unsupported') {
      authOption = ctx.cpOptionHex(3, ctx.u16hex(PPP_CHAP) + '80');
    }
    const peerRequest = ctx.cpPacket(1, 0x31, ctx.cpOptionU16(1, 1492) + authOption);
    const frames = [
      sessionFrame(ctx, PPP_LCP, peerRequest),
      sessionFrame(ctx, PPP_LCP, ctx.cpPacket(2, cp.identifier, cp.data_hex))
    ];
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
    if (options.ipcpDNS && !state.ipcpNAKSent) {
      state.ipcpNAKSent = true;
      const requested = ctx.parseCPOptions(cp.data_hex);
      assert(requested.some((item) => item.type === 129), 'IPCP should request primary DNS');
      assert(requested.some((item) => item.type === 131), 'IPCP should request secondary DNS');
      const nak = ctx.cpOptionIPv4(3, '198.51.100.10') + ctx.cpOptionIPv4(129, '223.5.5.5') + ctx.cpOptionIPv4(131, '1.1.1.1');
      return [sessionFrame(ctx, PPP_IPCP, ctx.cpPacket(3, cp.identifier, nak))];
    }
    if (options.ipcpRejectDNS && !state.ipcpNAKSent) {
      state.ipcpNAKSent = true;
      const requested = ctx.parseCPOptions(cp.data_hex);
      const rejected = requested.filter((item) => item.type === 129 || item.type === 131).map((item) => ctx.cpOptionHex(item.type, item.value_hex)).join('');
      return [sessionFrame(ctx, PPP_IPCP, ctx.cpPacket(4, cp.identifier, rejected))];
    }
    return [sessionFrame(ctx, PPP_IPCP, ctx.cpPacket(2, cp.identifier, cp.data_hex))];
  }
  if (parsed.protocol === PPP_IPV6CP && cp.code === 1) {
    return [sessionFrame(ctx, PPP_IPV6CP, ctx.cpPacket(2, cp.identifier, cp.data_hex))];
  }
  if (parsed.protocol === PPP_IPV6) {
    const icmp = ctx.parseIPv6ICMP(parsed.payload);
    if (icmp && icmp.type === 133) return [routerAdvertisementFrame(ctx)];
    const packet = ctx.parseIPv6UDP(parsed.payload);
    assert(packet, 'DHCPv6 test path should send IPv6/UDP');
    const dhcp = ctx.parseDHCPv6(packet.payload_hex);
    state.dhcpv6Messages.push(clone(dhcp));
    assert(!dhcp.options.some((option) => option.code === 20), 'unsupported Reconfigure Accept must not be sent');
    if (dhcp.message_type === 1 || (!options.omitIANA && !options.dhcpv6NoAddress)) {
      assert(dhcp.options.some((option) => option.code === 3), 'DHCPv6 should request IA_NA');
    } else if (options.dhcpv6NoAddress) {
      assert(!dhcp.options.some((option) => option.code === 3), 'failed IA_NA must be omitted after Solicit');
    }
    assert(dhcp.options.some((option) => option.code === 25), 'DHCPv6 should request IA_PD');
    if (Array.isArray(options.dhcpv6TimeoutTypes) && options.dhcpv6TimeoutTypes.includes(dhcp.message_type)) return [];
    if (dhcp.message_type === 1) return [dhcpv6Frame(ctx, 2, dhcp.transaction_id, options)];
    if (dhcp.message_type === 3) return [dhcpv6Frame(ctx, 7, dhcp.transaction_id, options)];
    if (dhcp.message_type === 5) {
      assert(dhcp.options.some((option) => option.code === 2), 'Renew must include Server Identifier');
      return [dhcpv6Frame(ctx, 7, dhcp.transaction_id, options)];
    }
    if (dhcp.message_type === 6) {
      assert(!dhcp.options.some((option) => option.code === 2), 'Rebind must omit Server Identifier');
      return [dhcpv6Frame(ctx, 7, dhcp.transaction_id, options)];
    }
  }
  return [];
}

function handleRecvMany(ctx, state, options, req) {
  if (req.ethertype !== ETH_P_PPP_SESS) return [];
  if (state.pendingTerminateIdentifier != null) {
    const id = state.pendingTerminateIdentifier;
    state.pendingTerminateIdentifier = null;
    return [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(5, id, ctx.stringHex('Received PADT')))];
  }
  if (options.echoReplies && state.lastEchoIdentifier != null) {
    const id = state.lastEchoIdentifier;
    state.lastEchoIdentifier = null;
    return [sessionFrame(ctx, PPP_LCP, ctx.cpPacket(10, id, '00000000'))];
  }
  return [];
}

function rememberPADT(state, ctx, options, req) {
  if (!options.terminateOnPADT || req.ethertype !== ETH_P_PPP_DISC || !req.payload) return;
  if (discoveryCode(req.payload) === CODE_PADT) state.pendingTerminateIdentifier = 0x7e;
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

function dhcpv6Frame(ctx, messageType, xid, options) {
  const serverID = '00030001020000000002';
  const address = '20010db8abcd00000000000000000010';
  const preferred = options && options.dhcpv6PreferredLifetime || 3600;
  const valid = options && options.dhcpv6ValidLifetime || 7200;
  const t1 = options && options.dhcpv6T1 != null ? options.dhcpv6T1 : 1800;
  const t2 = options && options.dhcpv6T2 != null ? options.dhcpv6T2 : 2880;
  const iaAddress = address + ctx.u32hex(preferred) + ctx.u32hex(valid);
  const iaNAData = options && options.dhcpv6NoAddress
    ? ctx.dhcpv6Option(13, ctx.u16hex(2) + ctx.stringHex('NOADDRS-AVAIL'))
    : ctx.dhcpv6Option(5, iaAddress);
  const iaNA = ctx.u32hex(1) + ctx.u32hex(t1) + ctx.u32hex(t2) + iaNAData;
  const prefix = '20010db8123400000000000000000000';
  const iaPrefix = ctx.u32hex(preferred) + ctx.u32hex(valid) + '38' + prefix;
  const iaPD = ctx.u32hex(1) + ctx.u32hex(t1) + ctx.u32hex(t2) + ctx.dhcpv6Option(26, iaPrefix);
  const dns = '20014860486000000000000000008888' + '24003200000000000000000000000001';
  const iana = options && options.omitIANA ? '' : ctx.dhcpv6Option(3, iaNA);
  const payload = ctx.hexByte(messageType) + xid + ctx.dhcpv6Option(2, serverID) + iana + ctx.dhcpv6Option(25, iaPD) + ctx.dhcpv6Option(23, dns);
  return sessionFrame(ctx, PPP_IPV6, ctx.ipv6UDP('fe80::2', 'fe80::1', 547, 546, payload));
}

function routerAdvertisementFrame(ctx) {
  const prefix = '20010db8cafe00010000000000000000';
  const prefixInfo = '030440c0' + ctx.u32hex(7200) + ctx.u32hex(3600) + ctx.u32hex(0) + prefix;
  const dns = '20014860486000000000000000008888';
  const rdnss = '19030000' + ctx.u32hex(600) + dns;
  const body = '40000708' + ctx.u32hex(0) + ctx.u32hex(0) + prefixInfo + rdnss;
  return sessionFrame(ctx, PPP_IPV6, ctx.ipv6ICMP('fe80::2', 'fe80::11:2233:4455:6677', 134, 0, body, 255));
}

function discoveryCode(payloadHex) {
  return parseInt(String(payloadHex || '').slice(2, 4), 16);
}

function linkInfo(name) {
  if (name === 'eth0') return {name, ifindex: 7, kind: 'device', mtu: 1500, mac: LOCAL_MAC, up: true, promiscuous: false};
  if (name === 'veerlocal0') return {name, ifindex: 101, kind: 'veth', mtu: 1492, mac: LOCAL_BOUNDARY_MAC, up: true, promiscuous: false, peer_name: PIPELINE_INTERFACE, peer_ifindex: 102};
  if (name === PIPELINE_INTERFACE) return {name, ifindex: 102, kind: 'veth', mtu: 1492, mac: PIPELINE_BOUNDARY_MAC, up: true, promiscuous: false, peer_name: 'veerlocal0', peer_ifindex: 101};
  return {name, ifindex: 200, kind: 'device', mtu: 1500, mac: '02:00:00:00:20:00', up: true, promiscuous: false};
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
