var ETH_P_PPP_DISC = '0x8863';
var ETH_P_PPP_SESS = '0x8864';
var CODE_PADI = 0x09;
var CODE_PADO = 0x07;
var CODE_PADR = 0x19;
var CODE_PADS = 0x65;
var CODE_PADT = 0xa7;
var TAG_SERVICE_NAME = 0x0101;
var TAG_AC_NAME = 0x0102;
var TAG_HOST_UNIQ = 0x0103;
var TAG_AC_COOKIE = 0x0104;
var TAG_RELAY_SESSION_ID = 0x0110;
var PPP_IP = 0x0021;
var PPP_IPV6 = 0x0057;
var PPP_LCP = 0xc021;
var PPP_PAP = 0xc023;
var PPP_CHAP = 0xc223;
var PPP_IPCP = 0x8021;
var PPP_IPV6CP = 0x8057;
var TUNNEL_CONFIG_RESOURCE = 'tunnel_configs';
var TUNNEL_CONFIG_KEY = 'active';
var TUNNEL_REPAIR_TIMER = 'tunnel_repair';
var REDIAL_RETRY_TIMER = 'redial_retry';
var TUNNEL_CONFIG_HEX_BYTES = 48;
var MAX_L2_RECV_TIMEOUT_MS = 5000;
var L2_IDENTITY_RESOURCE = 'l2_identities';
var DEFAULT_KEEPALIVE_FAILURE_THRESHOLD = 5;
var DEFAULT_KEEPALIVE_FAILURE_GRACE_MS = 60000;
var DEFAULT_KEEPALIVE_CONFIRM_TIMEOUT_MS = 5000;
var IPCP_OPTION_IP_ADDRESS = 3;
var IPCP_OPTION_PRIMARY_DNS = 129;
var IPCP_OPTION_SECONDARY_DNS = 131;
var IPV6CP_OPTION_INTERFACE_ID = 1;
var DHCPV6_SOLICIT = 1;
var DHCPV6_ADVERTISE = 2;
var DHCPV6_REQUEST = 3;
var DHCPV6_REPLY = 7;
var DHCPV6_OPT_CLIENTID = 1;
var DHCPV6_OPT_SERVERID = 2;
var DHCPV6_OPT_IA_NA = 3;
var DHCPV6_OPT_IAADDR = 5;
var DHCPV6_OPT_ORO = 6;
var DHCPV6_OPT_ELAPSED_TIME = 8;
var DHCPV6_OPT_DNS_SERVERS = 23;
var DHCPV6_OPT_RECONF_ACCEPT = 20;
var DHCPV6_OPT_IA_PD = 25;
var DHCPV6_OPT_IAPREFIX = 26;
var DHCPV6_OPT_CLIENT_FQDN = 39;
var ICMPV6_ROUTER_SOLICIT = 133;
var ICMPV6_ROUTER_ADVERT = 134;
var ND_OPT_PREFIX_INFORMATION = 3;
var ND_OPT_RDNSS = 25;
var TUNNEL_STATS_BUILD_NOTE = 'Per-packet tunnel counters are compiled out in the default object. Rebuild with PPPOE_TUNNEL_DIAG=1 to enable non-zero diagnostic counters.';

plugin.capabilities(['pppoe', 'raw_l2', 'control']);
pipeline.node({
  id: 'pppoe0',
  description: 'Logical PPPoE session node in the fvtap pipeline. This does not create a Linux netdev.'
});
ebpf.loadObject({
  id: 'pppoe_tunnel',
  path: 'pppoe_tunnel.o',
  sha256: crypto.sha256File('pppoe_tunnel.o'),
  description: 'Bidirectional TC stage between a physical PPPoE interface and one local Linux L3 boundary.',
  programs: [
    {id: 'tc_tunnel', section: 'tc/fvtap/pre_forward', type: 'tc'}
  ]
});
pipeline.attach({
  id: 'pppoe-ingress',
  direction: 'forward',
  attach: 'ingress',
  priority: 20,
  program: 'pppoe_tunnel:tc_tunnel',
  mode: 'rewrite'
});
pipeline.attach({
  id: 'pppoe-egress',
  direction: 'forward',
  attach: 'ingress',
  priority: 20,
  program: 'pppoe_tunnel:tc_tunnel',
  mode: 'rewrite'
});
plugin.resource({
  id: 'hook_bindings',
  description: 'Runtime TC hook interface bindings. Records map a declared hook_id to one or more real Linux interfaces.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'plugin_reconcile',
  max_records: 16,
  max_record_bytes: 4096
});
plugin.resource({
  id: 'profiles',
  description: 'PPPoE account, interface, negotiation and handoff profile used by client actions.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 16,
  max_record_bytes: 8192,
  secret_fields: ['password']
});
plugin.resource({
  id: L2_IDENTITY_RESOURCE,
  description: 'Raw-L2 source MAC and physical-interface promiscuous-mode ownership for each profile.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 16,
  max_record_bytes: 4096
});
plugin.resource({
  id: 'sessions',
  description: 'Current IPv4/IPv6 session, keepalive, redial and probe results exposed to the plugin UI.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384,
  secret_fields: ['password']
});
plugin.resource({
  id: 'wan_links',
  description: 'Normalized WAN session state exported for wan_core and forward_core handoff.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 32768,
  secret_fields: ['password']
});
plugin.resource({
  id: TUNNEL_CONFIG_RESOURCE,
  description: 'Last installed TC tunnel map configuration. Replayed after plugin dataplane reloads.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'runtime_apply',
  max_records: 1,
  max_record_bytes: 4096
});
plugin.action({
  id: 'discover',
  description: 'Send PADI and record the first PADO response.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.action({
  id: 'probe_session',
  description: 'Run discovery, open a PPPoE session, send one LCP request and optional PAP/CHAP response, then send PADT by default.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.action({
  id: 'traffic_probe',
  description: 'Run discovery/session setup and install the TC IPv4/IPv6-over-PPPoE tunnel without sending PADT.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.action({
  id: 'dial',
  description: 'Run discovery/session setup, negotiate IPCP/IPv6CP/optional DHCPv6-PD, keep the PPPoE session open, and optionally arm LCP keepalive.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.action({
  id: 'disconnect',
  description: 'Send PADT for the stored or provided session and clear keepalive.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 4096
});
plugin.action({
  id: 'clear_state',
  description: 'Delete the stored last probe result.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 1024
});
plugin.action({
  id: 'debug_stats',
  description: 'Read PPPoE tunnel dataplane counters and build-mode diagnostics.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 1024
});
plugin.action({
  id: 'traffic_stats',
  description: 'Read the current PPPoE session inner-IP traffic counters without persisting a snapshot.',
  runtime_update: 'runtime_query',
  max_payload_bytes: 1024
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: crypto.sha256File('ui/index.html'),
  page: 'pppoe',
  page_title: 'PPPoE'
});

exports.onUpgradeSnapshot = function () {
  // Negotiated session state is persisted in resources and tunnel maps. Opting
  // into handoff keeps host-owned timers and sockets attached to the new VM.
  return {schema_version: 1};
};

exports.onUpgradeRestore = function (ctx) {
  var state = ctx && ctx.upgrade ? ctx.upgrade.state : null;
  if (state && state.schema_version !== 1) {
    throw new Error('unsupported PPPoE upgrade state schema: ' + state.schema_version);
  }
};

exports.onReconcile = function () {
  try {
    applyStoredTunnelConfig(false);
  } catch (e) {
    log.info('pppoe tunnel config replay deferred: ' + errorMessage(e));
  }
  armTunnelRepair();
  resumeSessionTimers();
};

exports.onDeactivate = function () {
  timer.clear('lcp_echo');
  timer.clear('session_control');
  timer.clear(REDIAL_RETRY_TIMER);
  timer.clear(TUNNEL_REPAIR_TIMER);
  var failures = [];
  try {
    clearTunnelConfig();
  } catch (e) {
    failures.push('clear tunnel: ' + errorMessage(e));
    try {
      clearTunnelMap();
    } catch (mapError) {
      failures.push('clear tunnel map: ' + errorMessage(mapError));
    }
  }

  var last = resources.get('sessions', 'last');
  var session = last && last.data ? last.data : null;
  if (session && session.session_id && session.ac_mac) {
    var profileKey = token(session.profile_key || session.wan_id || 'default');
    try {
      var profile = loadProfile(merge(session, {profile_key: profileKey, send_padt: true}));
      resolveL2Identity(profile);
      disconnectSession(profile, session);
    } catch (e) {
      failures.push('disconnect ' + profileKey + ': ' + errorMessage(e));
      try {
        failCloseWANCoreFromStored(profileKey, session, 'deactivated');
      } catch (syncError) {
        failures.push('fail-close ' + profileKey + ': ' + errorMessage(syncError));
      }
    }
  }

  var links = resources.list('wan_links') || [];
  for (var i = 0; i < links.length; i++) {
    if (!links[i]) continue;
    var linkKey = token(links[i].key || 'default');
    try {
      failCloseWANCoreFromStored(linkKey, links[i].data || {}, 'deactivated');
      resources.set('wan_links', linkKey, merge(links[i].data || {}, {
        state: 'down',
        usable: false,
        phase: 'deactivated',
        updated_at: new Date().toISOString()
      }), false);
    } catch (e) {
      failures.push('WAN link ' + linkKey + ': ' + errorMessage(e));
    }
  }

  var identities = resources.list(L2_IDENTITY_RESOURCE) || [];
  for (var j = 0; j < identities.length; j++) {
    if (!identities[j]) continue;
    var identityKey = token(identities[j].key || 'default');
    try {
      cleanupL2Identity(identityKey, true);
    } catch (e) {
      failures.push('L2 identity ' + identityKey + ': ' + errorMessage(e));
    }
  }
  if (failures.length) throw new Error('PPPoE deactivate cleanup failed: ' + failures.join('; '));
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== TUNNEL_CONFIG_RESOURCE) return;
  applyTunnelConfigRecords(ctx.records || [], true);
  armTunnelRepair();
};

exports.onTimer = function (ctx) {
  if (!ctx.timer) return;
  if (ctx.timer.name === TUNNEL_REPAIR_TIMER) {
    applyStoredTunnelConfig(false);
    armTunnelRepair();
    return;
  }
  if (ctx.timer.name === 'session_control') {
    serviceSessionControlTimer(ctx.timer.payload || {});
    return;
  }
  if (ctx.timer.name === REDIAL_RETRY_TIMER) {
    serviceRedialRetryTimer(ctx.timer.payload || {});
    return;
  }
  if (ctx.timer.name !== 'lcp_echo') return;
  var payload = ctx.timer.payload || {};
  var profile = loadProfile(payload);
  var sessionID = clampInt(payload.session_id, 1, 65535, 0);
  var peerMAC = macText(payload.ac_mac || payload.peer_mac || '');
  if (!sessionID || !peerMAC) throw new Error('lcp_echo timer requires session_id and ac_mac');
  var result;
  try {
    prepareL2Identity(profile);
    result = sendLCPEcho(profile, peerMAC, sessionID);
  } catch (e) {
    result = baseResult(profile, 'keepalive_error', {
      session_id: sessionID,
      ac_mac: peerMAC,
      message: errorMessage(e)
    });
  }
  var failures = clampInt(payload.keepalive_failures, 0, 1000000, 0);
  if (result.phase === 'keepalive_ok') {
    result.keepalive_failures = 0;
    result.keepalive_failure_threshold = profile.keepalive_failure_threshold;
    result.keepalive_failure_grace_ms = profile.keepalive_failure_grace_ms;
    armKeepalive(profile, payload, 0, 0);
  } else {
    var now = Date.now();
    var failureStartedMs = keepaliveFailureStartedMs(payload, now);
    failures++;
    result.keepalive_failures = failures;
    result.keepalive_failure_threshold = profile.keepalive_failure_threshold;
    result.keepalive_failure_started_at = new Date(failureStartedMs).toISOString();
    result.keepalive_failure_elapsed_ms = Math.max(0, now - failureStartedMs);
    result.keepalive_failure_grace_ms = profile.keepalive_failure_grace_ms;
    result.keepalive_grace_remaining_ms = Math.max(0,
      profile.keepalive_failure_grace_ms - result.keepalive_failure_elapsed_ms);
    var thresholdReached = failures >= profile.keepalive_failure_threshold;
    var graceReached = result.keepalive_failure_elapsed_ms >= profile.keepalive_failure_grace_ms;
    if (thresholdReached && graceReached) {
      var confirmation = confirmLCPEcho(profile, peerMAC, sessionID);
      if (confirmation.phase === 'keepalive_ok') {
        result = merge(confirmation, {
          keepalive_failures: 0,
          keepalive_failure_threshold: profile.keepalive_failure_threshold,
          keepalive_failure_grace_ms: profile.keepalive_failure_grace_ms,
          keepalive_confirmation: 'recovered',
          keepalive_recovered_after_failures: failures
        });
        armKeepalive(profile, payload, 0, 0);
      } else {
        result = merge(result, {
          phase: confirmation.phase,
          keepalive_confirmation: confirmation,
          keepalive_confirm_timeout_ms: profile.keepalive_confirm_timeout_ms
        });
        if (profile.auto_redial) {
          result = redialAfterKeepaliveFailure(profile, result, payload);
        } else if (profile.redial_clear_tunnel) {
          timer.clear('lcp_echo');
          clearTunnelConfig();
          markWANLinkDown(profile, payload, result.phase);
        } else {
          armKeepalive(profile, payload, failures, failureStartedMs);
        }
      }
    } else {
      armKeepalive(profile, payload, failures, failureStartedMs);
    }
  }
  resources.set('sessions', 'keepalive', result);
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'clear_state') {
    var clearPayload = ctx.payload || {};
    var clearKey = token(clearPayload.profile_key || clearPayload.profile || 'default');
    failCloseWANCoreFromStored(clearKey, clearPayload, 'cleared');
    resources.delete('sessions', 'last');
    resources.delete('sessions', 'keepalive');
    resources.delete('sessions', 'control');
    resources.delete('sessions', 'redial_last');
    resources.delete('wan_links', clearKey);
    timer.clear('lcp_echo');
    timer.clear('session_control');
    timer.clear(REDIAL_RETRY_TIMER);
    timer.clear(TUNNEL_REPAIR_TIMER);
    clearTunnelConfig();
    cleanupL2Identity(clearKey, true);
    return;
  }
  if (action === 'debug_stats') {
    resources.set('sessions', 'debug_stats', {
      phase: 'debug_stats',
      stats: readTunnelStats()
    });
    return;
  }
	if (action === 'traffic_stats') {
		return readTrafficStats(ctx.payload || {});
	}

  var profile = loadProfile(ctx.payload || {});
  if (action === 'disconnect') {
    resolveL2Identity(profile);
  } else {
    prepareL2Identity(profile);
  }
  if (action === 'discover') {
    var discovery = discover(profile);
    resources.set('sessions', 'last', discovery);
    return;
  }
  if (action === 'probe_session') {
    var session = probeSession(profile);
    recordSession(profile, session);
    return;
  }
  if (action === 'traffic_probe') {
    timer.clear(REDIAL_RETRY_TIMER);
    profile.install_tunnel = true;
    if (!hasOwn(ctx.payload || {}, 'send_padt')) profile.send_padt = false;
    persistRuntimeProfile(profile);
    var tunnelSession = probeSession(profile);
    recordSession(profile, tunnelSession);
    requireInstalledTunnel(tunnelSession);
    armSessionControl(profile, tunnelSession);
    armKeepalive(profile, tunnelSession);
    return;
  }
  if (action === 'dial') {
    timer.clear(REDIAL_RETRY_TIMER);
    if (!hasOwn(ctx.payload || {}, 'send_padt')) profile.send_padt = false;
    persistRuntimeProfile(profile);
    var dialSession = probeSession(profile);
    recordSession(profile, dialSession);
    armSessionControl(profile, dialSession);
    armKeepalive(profile, dialSession);
    return;
  }
  if (action === 'disconnect') {
    disconnectSession(profile, ctx.payload || {});
    return;
  }
  throw new Error('unsupported action ' + action);
};

function loadProfile(payload) {
  var key = token(payload.profile_key || payload.profile || 'default');
  var record = resources.get('profiles', key);
  var data = record && record.data ? record.data : {};
  var profile = merge(data, payload || {});
  profile.profile_key = key;
  profile.wan_id = token(profile.wan_id || key);
	profile.interface = ifaceName(profile.interface || profile.iface || profile.physical_interface || '', 'interface');
  profile.mac_mode = lower(firstDefined(profile.mac_mode, profile.mac_address ? 'manual' : 'interface'));
  if (profile.mac_mode !== 'interface' && profile.mac_mode !== 'random' && profile.mac_mode !== 'manual') {
    throw new Error('mac_mode must be interface, random or manual');
  }
  profile.mac_address = macText(profile.mac_address || profile.mac || '');
  if (profile.mac_mode === 'manual' && !profile.mac_address) {
    throw new Error('mac_address is required when mac_mode is manual');
  }
  profile.username = text(profile.username || '');
  profile.password = text(profile.password || '');
  profile.password = resolveProfilePassword(profile);
  profile.service = text(profile.service || '');
  profile.ac_name = text(profile.ac_name || '');
  profile.auth = lower(profile.auth || 'pap');
  profile.timeout_ms = clampInt(profile.timeout_ms, 50, 5000, 700);
  profile.control_ack_timeout_ms = clampInt(
    firstDefined(profile.control_ack_timeout_ms, profile.ack_exchange_timeout_ms),
    10,
    250,
    Math.min(profile.timeout_ms, 80)
  );
  profile.control_idle_timeout_ms = clampInt(
    firstDefined(profile.control_idle_timeout_ms, profile.l2_idle_timeout_ms),
    1,
    250,
    10
  );
  profile.disconnect_drain_ms = clampInt(
    firstDefined(profile.disconnect_drain_ms, profile.disconnect_control_ms),
    0,
    2000,
    350
  );
  profile.max_frames = clampInt(profile.max_frames, 1, 8, 4);
  profile.mru = clampInt(profile.mru, 576, 1492, 1492);
  profile.negotiate_ipv4 = bool(firstDefined(profile.negotiate_ipv4, profile.ipcp, profile.ipv4), true);
  profile.negotiate_ipv6 = bool(firstDefined(profile.negotiate_ipv6, profile.ipv6cp, profile.ipv6), false);
  profile.request_pd = bool(firstDefined(profile.request_pd, profile.ipv6_pd, profile.pd), false);
  profile.request_ipv6_address = bool(firstDefined(profile.request_ipv6_address, profile.request_ia_na, profile.ia_na), profile.negotiate_ipv6);
  profile.request_ipv6_router = bool(firstDefined(profile.request_ipv6_router, profile.request_ra, profile.ipv6_ra), profile.negotiate_ipv6);
  if (profile.request_pd || profile.request_ipv6_address) profile.negotiate_ipv6 = true;
  profile.ipv6_iid = iidHex(profile.ipv6_iid || profile.interface_id || '');
  profile.dhcpv6_iaid = clampInt(profile.dhcpv6_iaid || profile.iaid, 0, 0xffffffff, 1);
  profile.dhcpv6_request = bool(firstDefined(profile.dhcpv6_request, profile.request_dhcpv6_reply), true);
  profile.dhcpv6_timeout_ms = clampInt(firstDefined(profile.dhcpv6_timeout_ms, profile.dhcpv6_exchange_timeout_ms), 500, 30000, Math.max(profile.timeout_ms, 5000));
  profile.dhcpv6_settle_ms = clampInt(firstDefined(profile.dhcpv6_settle_ms, profile.dhcpv6_delay_ms), 0, 10000, 2000);
  profile.ipv6_ra_timeout_ms = clampInt(firstDefined(profile.ipv6_ra_timeout_ms, profile.router_solicitation_timeout_ms), 500, 30000, 5000);
  profile.keepalive_interval_ms = clampInt(profile.keepalive_interval_ms, 0, 86400000, 0);
  profile.keepalive_failure_threshold = clampInt(
    firstDefined(profile.keepalive_failure_threshold, profile.keepalive_failures_before_redial),
    1,
    10,
    DEFAULT_KEEPALIVE_FAILURE_THRESHOLD
  );
  profile.keepalive_failure_grace_ms = clampInt(
    firstDefined(profile.keepalive_failure_grace_ms, profile.keepalive_grace_ms),
    0,
    3600000,
    DEFAULT_KEEPALIVE_FAILURE_GRACE_MS
  );
  profile.keepalive_confirm_timeout_ms = clampInt(
    firstDefined(profile.keepalive_confirm_timeout_ms, profile.keepalive_final_timeout_ms),
    100,
    30000,
    Math.max(profile.timeout_ms, DEFAULT_KEEPALIVE_CONFIRM_TIMEOUT_MS)
  );
  profile.auto_redial = bool(firstDefined(profile.auto_redial, profile.redial, profile.reconnect, profile.reconnect_on_timeout), false);
  profile.redial_clear_tunnel = bool(firstDefined(profile.redial_clear_tunnel, profile.clear_tunnel_on_redial), true);
  profile.redial_send_padt = bool(firstDefined(profile.redial_send_padt, profile.close_session_before_redial), true);
  profile.redial_retry_initial_ms = clampInt(
    firstDefined(profile.redial_retry_initial_ms, profile.redial_retry_ms),
    250,
    300000,
    2000
  );
  profile.redial_retry_max_ms = clampInt(
    firstDefined(profile.redial_retry_max_ms, profile.redial_max_retry_ms),
    profile.redial_retry_initial_ms,
    3600000,
    Math.max(profile.redial_retry_initial_ms, 30000)
  );
  profile.install_tunnel = bool(profile.install_tunnel, false);
  profile.prepare_interfaces = bool(firstDefined(profile.prepare_interfaces, profile.prepare_tunnel_interfaces), true);
  profile.prepare_local_mtu = bool(firstDefined(profile.prepare_local_mtu, profile.set_local_mtu), true);
  profile.prepare_wan_mtu = bool(firstDefined(profile.prepare_wan_mtu, profile.set_wan_mtu), false);
  profile.prepare_offloads = bool(firstDefined(profile.prepare_offloads, profile.disable_offloads), true);
  profile.prepare_gso = bool(firstDefined(profile.prepare_gso, profile.limit_gso), true);
  profile.prepare_wan_offloads = bool(firstDefined(profile.prepare_wan_offloads, profile.disable_wan_offloads), false);
  profile.allow_unsafe_offloads = bool(firstDefined(profile.allow_unsafe_offloads, profile.allow_offload_prepare_failure), false);
  profile.sync_hook_bindings = bool(firstDefined(profile.sync_hook_bindings, profile.hook_bindings), true);
  profile.apply_hook_bindings = bool(firstDefined(profile.apply_hook_bindings, profile.hook_bindings_apply), true);
  profile.post_session_control_ms = clampInt(
    firstDefined(profile.post_session_control_ms, profile.post_dial_control_ms, profile.control_drain_ms),
    0,
    10000,
    profile.install_tunnel ? 3000 : 0
  );
  profile.decap_mode = lower(firstDefined(profile.decap_mode, profile.pppoe_decap_mode, 'auto'));
  if (profile.decap_mode !== 'manual' && profile.decap_mode !== 'auto') {
    throw new Error('decap_mode must be manual or auto');
  }
  profile.manual_decap = profile.decap_mode === 'manual';
  profile.mss_clamp_v4 = clampInt(firstDefined(profile.mss_clamp_v4, profile.tcp_mss_v4, profile.mss_clamp), 0, 65535, Math.max(profile.mru - 52, 536));
  profile.mss_clamp_v6 = clampInt(firstDefined(profile.mss_clamp_v6, profile.tcp_mss_v6), 0, 65535, Math.max(profile.mru - 60, 1220));
  profile.send_padt = bool(profile.send_padt, true);
  profile.local_interface = optionalIfaceName(profile.local_interface || '', 'local_interface');
  profile.pipeline_interface = optionalIfaceName(profile.pipeline_interface || profile.tunnel_interface || '', 'pipeline_interface');
  profile.wan_interface = optionalIfaceName(profile.wan_interface || '', 'wan_interface') || profile.interface;
  profile.local_ifindex = clampInt(profile.local_ifindex, 0, 2147483647, 0);
  profile.pipeline_ifindex = clampInt(profile.pipeline_ifindex, 0, 2147483647, 0);
  profile.wan_ifindex = clampInt(profile.wan_ifindex, 0, 2147483647, 0);
  profile.local_src_mac = macText(profile.local_src_mac || '');
  profile.local_dst_mac = macText(profile.local_dst_mac || '');
  profile.wan_src_mac = macText(profile.wan_src_mac || '');
  profile.wan_dst_mac = macText(profile.wan_dst_mac || profile.ac_mac || '');
  profile.wan_core_sync = bool(firstDefined(profile.wan_core_sync, profile.sync_wan_core), !!profile.local_interface);
  profile.wan_core_required = bool(firstDefined(profile.wan_core_required, profile.require_wan_core), profile.wan_core_sync);
  if (profile.wan_core_required && !profile.wan_core_sync) {
    throw new Error('wan_core_required requires wan_core_sync');
  }
  profile.wan_core_apply = bool(firstDefined(profile.wan_core_apply, profile.apply_wan_core), true);
  profile.wan_core_plugin = token(profile.wan_core_plugin || profile.wan_core_plugin_id || 'wan_core');
  return profile;
}

function prepareL2Identity(profile) {
  var key = token(profile.profile_key || 'default');
  var iface = ifaceName(profile.interface, 'interface');
  var link = net.link.get(iface);
  var interfaceMAC = unicastMacText(link.mac || '');
  var previous = resources.get(L2_IDENTITY_RESOURCE, key);
  var previousData = previous && previous.data ? previous.data : null;
  var mac = interfaceMAC;
  if (profile.mac_mode === 'random') {
    mac = previousData && previousData.interface === iface && previousData.mac_address
      ? unicastMacText(previousData.mac_address)
      : randomLocalUnicastMAC();
  } else if (profile.mac_mode === 'manual') {
    mac = unicastMacText(profile.mac_address);
  }
  var custom = lower(mac) !== lower(interfaceMAC);
  if (previousData && (previousData.interface !== iface || lower(previousData.mac_address) !== lower(mac))) {
    cleanupL2Identity(key, true);
    previousData = null;
    link = net.link.get(iface);
  }
  var promiscOwner = !!(previousData && previousData.promisc_enabled_by_plugin);
  var originalPromiscuous = previousData ? previousData.original_promiscuous === true : link.promiscuous === true;
  if (custom && link.promiscuous !== true) {
    link = net.link.setPromiscuous(iface, true);
    promiscOwner = true;
  }
  var record = {
    profile_key: key,
    interface: iface,
    interface_mac: interfaceMAC,
    mac_mode: profile.mac_mode,
    mac_address: mac,
    custom_mac: custom,
    original_promiscuous: originalPromiscuous,
    promisc_enabled_by_plugin: promiscOwner,
    state: 'up'
  };
  if (!sameL2IdentityRecord(previousData, record)) {
    record.updated_at = new Date().toISOString();
    resources.set(L2_IDENTITY_RESOURCE, key, record);
  }
  applyEffectiveL2Identity(profile, record);
  return record;
}

function resolveL2Identity(profile) {
  var key = token(profile.profile_key || 'default');
  var record = resources.get(L2_IDENTITY_RESOURCE, key);
  var data = record && record.data ? record.data : null;
  if (!data) return prepareL2Identity(profile);
  if (data.interface !== profile.interface) throw new Error('stored L2 identity belongs to ' + data.interface + ', want ' + profile.interface);
  var link = net.link.get(data.interface);
  if (data.custom_mac && link.promiscuous !== true) {
    link = net.link.setPromiscuous(data.interface, true);
    data.promisc_enabled_by_plugin = true;
    resources.set(L2_IDENTITY_RESOURCE, key, data);
  }
  applyEffectiveL2Identity(profile, data);
  return data;
}

function applyEffectiveL2Identity(profile, data) {
  profile.interface = data.interface;
  profile.mac_address = data.mac_address;
  // Discovery, control, and tunneled data must use one PPPoE client identity.
  // A persisted wan_src_mac from an older interface/MAC mode would otherwise
  // create a valid session whose data packets are silently rejected by the AC.
  profile.wan_src_mac = data.mac_address;
  profile.wan_interface = data.interface;
}

function cleanupL2Identity(profileKey, force) {
  var key = token(profileKey || 'default');
  var record = resources.get(L2_IDENTITY_RESOURCE, key);
  if (!record || !record.data) return {status: 'not_configured'};
  var data = record.data;
  var transferred = false;
  if (data.promisc_enabled_by_plugin) {
    var records = resources.list(L2_IDENTITY_RESOURCE) || [];
    for (var i = 0; i < records.length; i++) {
      if (!records[i] || token(records[i].key || 'default') === key || records[i].enabled === false) continue;
      var other = records[i].data || {};
      if (other.interface !== data.interface || other.custom_mac !== true) continue;
      other.promisc_enabled_by_plugin = true;
      other.original_promiscuous = data.original_promiscuous === true;
      resources.set(L2_IDENTITY_RESOURCE, token(records[i].key), other, true);
      transferred = true;
      break;
    }
    if (!transferred && data.original_promiscuous !== true) {
      net.link.setPromiscuous(data.interface, false);
    }
  }
  resources.delete(L2_IDENTITY_RESOURCE, key);
  return {status: transferred ? 'ownership_transferred' : 'released', interface: data.interface, mac_address: data.mac_address};
}

function sameL2IdentityRecord(previous, next) {
  if (!previous) return false;
  return previous.profile_key === next.profile_key && previous.interface === next.interface &&
    lower(previous.interface_mac) === lower(next.interface_mac) && previous.mac_mode === next.mac_mode &&
    lower(previous.mac_address) === lower(next.mac_address) && previous.custom_mac === next.custom_mac &&
    previous.original_promiscuous === next.original_promiscuous &&
    previous.promisc_enabled_by_plugin === next.promisc_enabled_by_plugin && previous.state === next.state;
}

function randomLocalUnicastMAC() {
  var bytes = hexToBytes(crypto.randomBytes(6));
  bytes[0] = ((bytes[0] || 0) | 2) & 0xfe;
  return macBytesToText(bytes);
}

function unicastMacText(value) {
  var normalized = macText(value);
  if (!normalized) throw new Error('mac address is required');
  var first = parseInt(normalized.slice(0, 2), 16);
  if ((first & 1) !== 0 || normalized === '00:00:00:00:00:00') {
    throw new Error('mac address must be non-zero unicast');
  }
  return normalized;
}

function discover(profile) {
	var hostUniq = crypto.randomBytes(4);
	var padoFrame = sendPADI(profile, hostUniq);
	if (padoFrame === null) {
		return baseResult(profile, 'timeout', {message: 'PADO timeout', host_uniq: hostUniq});
	}
  var pado = parseDiscoveryFrame(padoFrame);
  if (pado.code !== CODE_PADO) {
    throw new Error('expected PADO, got code 0x' + hexByte(pado.code));
  }
  return baseResult(profile, 'pado', {
    host_uniq: hostUniq,
    ac_mac: padoFrame.src_mac,
    ac_name: firstTagText(pado, TAG_AC_NAME),
    service_name: firstTagText(pado, TAG_SERVICE_NAME),
    tags: tagSummary(pado.tags)
  });
}

function probeSession(profile) {
	prepareWANCoreTunnelBoundary(profile);
	var hostUniq = crypto.randomBytes(4);
	var padoFrame = sendPADI(profile, hostUniq);
	if (padoFrame === null) return baseResult(profile, 'timeout', {message: 'PADO timeout', host_uniq: hostUniq});
	var pado = parseDiscoveryFrame(padoFrame);
	if (pado.code !== CODE_PADO) {
		throw new Error('expected PADO, got code 0x' + hexByte(pado.code));
	}
	var padrTags = [
		tagString(TAG_SERVICE_NAME, profile.service || firstTagText(pado, TAG_SERVICE_NAME)),
		tagHex(TAG_HOST_UNIQ, hostUniq)
	];
  appendForwardedTag(padrTags, pado, TAG_AC_COOKIE);
  appendForwardedTag(padrTags, pado, TAG_RELAY_SESSION_ID);

  var padsFrame = sendPADR(profile, padoFrame.src_mac, hostUniq, padrTags);
  if (padsFrame === null) {
    return baseResult(profile, 'timeout', {message: 'PADS timeout', ac_mac: padoFrame.src_mac});
  }
  var pads = parseDiscoveryFrame(padsFrame);
  if (pads.code !== CODE_PADS) {
    throw new Error('expected PADS, got code 0x' + hexByte(pads.code));
  }
  if (!pads.session_id) throw new Error('PADS did not allocate a session id');

  var frames = runSessionProbe(profile, padsFrame.src_mac, pads.session_id, padsFrame.dst_mac);
  var tunnel = null;
  if (profile.install_tunnel) {
    try {
      if (!lcpReadyForNetworkCP(profile, frames)) throw new Error('cannot install tunnel before LCP/auth is ready');
      tunnel = installTunnel(profile, padsFrame, pads.session_id);
    } catch (e) {
      sendPADT(profile, padsFrame.src_mac, pads.session_id);
      clearTunnelConfig();
      throw e;
    }
  }
  if (profile.send_padt) {
    sendPADT(profile, padsFrame.src_mac, pads.session_id);
    if (tunnel !== null) clearTunnelConfig();
  }
	return baseResult(profile, 'session_probe', {
		host_uniq: hostUniq,
		ac_mac: padsFrame.src_mac,
    local_mac: padsFrame.dst_mac,
		ac_name: firstTagText(pado, TAG_AC_NAME),
    service_name: firstTagText(pado, TAG_SERVICE_NAME),
    session_id: pads.session_id,
    session_id_hex: u16hex(pads.session_id),
    lcp_ack: frames.lcp_ack,
    lcp_ready: lcpReadyForNetworkCP(profile, frames),
    auth_sent: frames.auth_sent,
    auth_method: frames.auth_method,
    auth_ok: frames.auth_ok,
    ipcp: frames.ipcp,
    ipv6cp: frames.ipv6cp,
    ipv6_ra: frames.ipv6_ra,
    dhcpv6_pd: frames.dhcpv6_pd,
    frames: frames.items,
    post_session_control_armed: !profile.send_padt && profile.post_session_control_ms > 0,
    padt_sent: profile.send_padt,
    tunnel_installed: tunnel !== null,
    tunnel: tunnel
  });
}

function prepareWANCoreTunnelBoundary(profile) {
  if (!profile.install_tunnel || !profile.wan_core_sync) return null;
  if (typeof plugins === 'undefined' || !plugins.actions || typeof plugins.actions.call !== 'function') {
    if (profile.wan_core_required) {
      throw new Error('prepare WAN core handoff: plugins.actions.call is unavailable');
    }
    return null;
  }
  var payload = {
    key: profile.wan_id,
    wan_id: profile.wan_id,
    profile_key: profile.profile_key,
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: 'prepared',
    usable: false,
    real_interface: profile.interface,
    wan_interface: profile.local_interface,
    local_interface: profile.local_interface,
    pipeline_interface: profile.pipeline_interface,
    handoff_mode: 'segmented_veth',
    mtu: profile.mru
  };
  try {
    var status = plugins.actions.call(profile.wan_core_plugin, 'prepare_handoff', payload) || {};
    if (status.pipeline_interface) {
      profile.pipeline_interface = optionalIfaceName(status.pipeline_interface, 'wan_core pipeline_interface');
    }
    return status;
  } catch (e) {
    if (profile.wan_core_required || !profile.pipeline_interface) {
      throw new Error('prepare WAN core handoff: ' + errorMessage(e));
    }
    log.info('WAN core handoff preparation deferred: ' + errorMessage(e));
    return null;
  }
}

function installTunnel(profile, padsFrame, sessionID) {
  if (!profile.local_interface) throw new Error('local_interface is required to install the TC tunnel');
  var boundary = resolveTunnelBoundary(profile);
  var localLink = boundary.local;
  var pipelineLink = boundary.pipeline;
  var wanLink = profile.wan_interface ? net.link.get(profile.wan_interface) : null;
  var localIfIndex = profile.local_ifindex || (localLink && localLink.ifindex) || 0;
  var pipelineIfIndex = profile.pipeline_ifindex || (pipelineLink && pipelineLink.ifindex) || 0;
  var wanIfIndex = profile.wan_ifindex || (wanLink && wanLink.ifindex) || padsFrame.ifindex || 0;
  var localSrcMAC = profile.local_src_mac || padsFrame.src_mac || '';
  var localDstMAC = profile.local_dst_mac || (localLink && localLink.mac) || '';
  var wanSrcMAC = profile.wan_src_mac || (wanLink && wanLink.mac) || padsFrame.dst_mac || '';
  var wanDstMAC = profile.wan_dst_mac || padsFrame.src_mac || '';
  if (!localIfIndex) throw new Error('local_ifindex or local_interface is required to install the TC tunnel');
  if (!pipelineIfIndex) throw new Error('pipeline_ifindex or pipeline_interface is required to install the TC tunnel');
  if (!wanIfIndex) throw new Error('wan_ifindex is required to install the TC tunnel');
  if (!localSrcMAC) throw new Error('local_src_mac or AC MAC is required to install the TC tunnel');
  if (!localDstMAC) throw new Error('local_dst_mac or local_interface MAC is required to install the TC tunnel');
  if (!wanSrcMAC) throw new Error('wan_src_mac is required to install the TC tunnel');
  if (!wanDstMAC) throw new Error('wan_dst_mac/ac_mac is required to install the TC tunnel');
  var interfacePreparation = prepareTunnelInterfaces(profile, boundary);
  var hookBindings = syncTunnelHookBindings(profile, boundary);
  clearTunnelStats();

  var flags = 0;
  if (profile.manual_decap) flags |= 2;
  var value = tunnelConfigValueHex({
    enabled: 1,
    local_ifindex: localIfIndex,
    pipeline_ifindex: pipelineIfIndex,
    wan_ifindex: wanIfIndex,
    session_id: sessionID,
    flags: flags,
    mss_clamp_v4: profile.mss_clamp_v4,
    mss_clamp_v6: profile.mss_clamp_v6,
    local_src_mac: localSrcMAC,
    local_dst_mac: localDstMAC,
    wan_src_mac: wanSrcMAC,
    wan_dst_mac: wanDstMAC
  });
  var tunnelRecord = {
    object: 'pppoe_tunnel',
    map: 'pppoe_tunnel_config',
    value_hex: value,
    mode: 'segmented_veth',
    local_interface: profile.local_interface,
    pipeline_interface: pipelineLink.name,
    wan_interface: profile.wan_interface,
    local_ifindex: localIfIndex,
    pipeline_ifindex: pipelineIfIndex,
    wan_ifindex: wanIfIndex,
    local_src_mac: localSrcMAC,
    local_dst_mac: localDstMAC,
    wan_src_mac: wanSrcMAC,
    wan_dst_mac: wanDstMAC,
    session_id: sessionID,
    flags: flags,
    mss_clamp_v4: profile.mss_clamp_v4,
    mss_clamp_v6: profile.mss_clamp_v6,
    decap_mode: profile.decap_mode,
    tunnel_repair_interval_ms: clampInt(profile.tunnel_repair_interval_ms, 500, 86400000, 2000),
    updated_at: new Date().toISOString()
  };
  try {
    resources.set(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, tunnelRecord, true, true);
  } catch (e) {
    clearTunnelConfig();
    throw e;
  }
  armTunnelRepair();
  return {
    object: 'pppoe_tunnel',
    map: 'pppoe_tunnel_config',
    mode: 'segmented_veth',
    requires_kernel_tc_prepared_l2: false,
    local_interface: profile.local_interface,
    pipeline_interface: pipelineLink.name,
    wan_interface: profile.wan_interface,
    local_ifindex: localIfIndex,
    pipeline_ifindex: pipelineIfIndex,
    wan_ifindex: wanIfIndex,
    local_src_mac: localSrcMAC,
    local_dst_mac: localDstMAC,
    wan_src_mac: wanSrcMAC,
    wan_dst_mac: wanDstMAC,
    mss_clamp_v4: profile.mss_clamp_v4,
    mss_clamp_v6: profile.mss_clamp_v6,
    interface_preparation: interfacePreparation,
    hook_bindings: hookBindings,
    decap_mode: profile.decap_mode
  };
}

function resolveTunnelBoundary(profile) {
  var localName = ifaceName(profile.local_interface, 'local_interface');
  var pipelineName = optionalIfaceName(profile.pipeline_interface || '', 'pipeline_interface');
  if (!pipelineName && profile.wan_core_sync && typeof plugins !== 'undefined' && plugins.resources &&
      typeof plugins.resources.get === 'function') {
    var record = plugins.resources.get(profile.wan_core_plugin, 'status', token(profile.wan_id || profile.profile_key));
    // A prepared WAN boundary is intentionally disabled until PPPoE succeeds.
    var status = record && record.data ? record.data : {};
    var statusLocal = optionalIfaceName(status.local_interface || '', 'wan_core local_interface');
    if (statusLocal && statusLocal !== localName) {
      throw new Error('wan_core local interface ' + statusLocal + ' does not match PPPoE local interface ' + localName);
    }
    var forwardCore = status.forward_core || {};
    pipelineName = optionalIfaceName(status.pipeline_interface || forwardCore.tunnel_interface || '', 'wan_core pipeline_interface');
    if (pipelineName && status.segmentation_ready !== true && forwardCore.segmentation_ready !== true) {
      throw new Error('wan_core pipeline boundary is not ready for segmentation');
    }
  }
  if (!pipelineName || pipelineName === localName) {
    throw new Error('PPPoE tunnel requires a segmented WAN handoff with a distinct pipeline interface');
  }
  var local = net.link.get(localName);
  var pipelineLink = net.link.get(pipelineName);
  if (lower(local.kind) !== 'veth' || lower(pipelineLink.kind) !== 'veth') {
    throw new Error('PPPoE segmented handoff must use a veth pair');
  }
  return {
    mode: 'segmented_veth',
    local: local,
    pipeline: pipelineLink
  };
}

function requireInstalledTunnel(session) {
  if (!session || session.tunnel_installed !== true || !session.tunnel) {
    throw new Error('PPPoE traffic_probe did not install tunnel: phase=' + text(session && session.phase || 'unknown') +
      (session && session.message ? ' message=' + session.message : ''));
  }
}

function syncTunnelHookBindings(profile, boundary) {
  if (!profile.sync_hook_bindings) {
    return {status: 'disabled'};
  }
  var wan = profile.wan_interface || profile.interface || '';
  var pipelineInterface = boundary && boundary.pipeline ? boundary.pipeline.name : '';
  if (!wan || !pipelineInterface) {
    return {status: 'skipped', reason: 'no hook interfaces'};
  }
  resources.set('hook_bindings', 'pppoe-ingress', {
    hook_id: 'pppoe-ingress',
    interfaces: [wan]
  }, true, profile.apply_hook_bindings);
  resources.set('hook_bindings', 'pppoe-egress', {
    hook_id: 'pppoe-egress',
    interfaces: [pipelineInterface]
  }, true, profile.apply_hook_bindings);
  return {
    status: profile.apply_hook_bindings ? 'applied' : 'stored',
    ingress: [wan],
    egress: [pipelineInterface],
    applied: profile.apply_hook_bindings
  };
}

function prepareTunnelInterfaces(profile, boundary) {
  var result = {enabled: false, mtu: [], gso: [], offloads: [], warnings: []};
  if (!profile.prepare_interfaces) return result;
  result.enabled = true;

  var local = boundary && boundary.local ? boundary.local.name : (profile.local_interface || '');
  var pipelineInterface = boundary && boundary.pipeline ? boundary.pipeline.name : '';
  var wan = profile.wan_interface || profile.interface || '';
  var tunnelMTU = clampInt(firstDefined(profile.tunnel_mtu, profile.local_mtu, profile.mru), 576, 1492, 1492);
  var preparedMTU = {};
  var preparedOffloads = {};

  if (profile.prepare_local_mtu) {
    prepareTunnelMTU(result, preparedMTU, local, 'local', tunnelMTU);
    prepareTunnelMTU(result, preparedMTU, pipelineInterface, 'pipeline', tunnelMTU);
  }
  if (profile.prepare_gso && local) {
    var gso = net.link.setGSO(local, {max_size: tunnelMTU, max_segs: 1});
    result.gso.push({
      interface: local,
      role: 'local',
      max_size: gso.gso_max_size || tunnelMTU,
      max_segs: gso.gso_max_segs || 1
    });
  }
  if (profile.prepare_wan_mtu && wan) {
    prepareTunnelMTU(result, preparedMTU, wan, 'wan', tunnelMTU);
  }
  if (profile.prepare_offloads) {
    prepareTunnelOffloads(profile, result, preparedOffloads, local, 'local', {sg: false, tso: false, gso: false});
    prepareTunnelOffloads(profile, result, preparedOffloads, pipelineInterface, 'pipeline', {gro: false, lro: false});
    if (profile.prepare_wan_offloads) {
      prepareTunnelOffloads(profile, result, preparedOffloads, wan, 'wan', {tx: false, sg: false, tso: false, gso: false, gro: false});
    }
  }
  return result;
}

function prepareTunnelMTU(result, prepared, iface, role, mtu) {
  if (!iface || prepared[iface]) return;
  prepared[iface] = true;
  net.link.setMTU(iface, mtu);
  result.mtu.push({interface: iface, mtu: mtu, role: role});
}

function prepareTunnelOffloads(profile, result, prepared, iface, role, features) {
  if (!iface) return;
  if (prepared[iface]) return;
  prepared[iface] = true;
  features = features || {tx: false, tso: false, gso: false, gro: false, sg: false};
  try {
    net.link.setOffloads(iface, features);
    result.offloads.push({interface: iface, role: role, features: features});
  } catch (e) {
    var message = e && e.message ? e.message : String(e);
    if (!profile.allow_unsafe_offloads) {
      throw new Error('prepare PPPoE tunnel offloads on ' + iface + ': ' + message);
    }
    result.warnings.push({interface: iface, role: role, warning: message});
  }
}

function clearTunnelConfig() {
  var deleted = false;
  try {
    resources.delete(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, true);
    deleted = true;
  } catch (e) {
    log.info('pppoe tunnel config record clear skipped: ' + errorMessage(e));
  }
  if (!deleted) clearTunnelMap();
  armTunnelRepair();
}

function clearTunnelMap() {
  try {
    ebpf.mapPut('pppoe_tunnel', 'pppoe_tunnel_config', u32lehex(0), zeroTunnelConfigHex());
  } catch (e) {
    log.info('pppoe tunnel config clear skipped: ' + errorMessage(e));
  }
}

function applyStoredTunnelConfig(reportErrors) {
  var records = resources.list(TUNNEL_CONFIG_RESOURCE) || [];
  if (!selectTunnelConfigRecord(records)) return;
  applyTunnelConfigRecords(records, reportErrors);
}

function applyTunnelConfigRecords(records, reportErrors) {
  var selected = selectTunnelConfigRecord(records);
  var failures = [];
  if (!selected) {
    clearTunnelMap();
    return;
  }
  try {
    applyTunnelConfigRecord(selected);
  } catch (e) {
    failures.push(errorMessage(e));
  }
  if (reportErrors && failures.length) {
    throw new Error('failed to apply PPPoE tunnel config: ' + failures.join('; '));
  }
}

function selectTunnelConfigRecord(records) {
  for (var i = 0; i < (records || []).length; i++) {
    var record = records[i];
    if (!record || record.enabled === false) continue;
    if (token(record.key || TUNNEL_CONFIG_KEY) !== TUNNEL_CONFIG_KEY) continue;
    return record;
  }
  return null;
}

function applyTunnelConfigRecord(record) {
  var data = record && record.data ? record.data : {};
  var value = normalizeTunnelConfigValueHex(data.value_hex || tunnelConfigValueHex(data));
  ebpf.mapPut('pppoe_tunnel', 'pppoe_tunnel_config', u32lehex(0), value);
}

function armTunnelRepair() {
  var record = resources.get(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY);
  if (!record || record.enabled === false) {
    timer.clear(TUNNEL_REPAIR_TIMER);
    return;
  }
  var data = record.data || {};
  var interval = clampInt(data.tunnel_repair_interval_ms, 500, 86400000, 2000);
  timer.setInterval(TUNNEL_REPAIR_TIMER, interval, {});
}

function zeroTunnelConfigHex() {
  return repeatHex('00', TUNNEL_CONFIG_HEX_BYTES);
}

function tunnelConfigValueHex(data) {
  data = data || {};
  return ''
    + u32lehex(clampInt(data.enabled, 0, 1, 1))
    + u32lehex(clampInt(data.local_ifindex, 0, 2147483647, 0))
    + u32lehex(clampInt(data.pipeline_ifindex, 0, 2147483647, 0))
    + u32lehex(clampInt(data.wan_ifindex, 0, 2147483647, 0))
    + u16lehex(clampInt(data.session_id, 0, 65535, 0))
    + u16lehex(clampInt(data.flags, 0, 65535, 0))
    + u16lehex(clampInt(data.mss_clamp_v4, 0, 65535, 0))
    + u16lehex(clampInt(data.mss_clamp_v6, 0, 65535, 0))
    + macHex(data.local_src_mac || '00:00:00:00:00:00')
    + macHex(data.local_dst_mac || '00:00:00:00:00:00')
    + macHex(data.wan_src_mac || '00:00:00:00:00:00')
    + macHex(data.wan_dst_mac || '00:00:00:00:00:00');
}

function normalizeTunnelConfigValueHex(value) {
  value = lower(value).replace(/^0x/i, '').replace(/[^0-9a-f]/g, '');
  if (value.length !== TUNNEL_CONFIG_HEX_BYTES * 2) {
    throw new Error('tunnel config value_hex must be ' + TUNNEL_CONFIG_HEX_BYTES + ' bytes');
  }
  return value;
}

function clearTunnelStats() {
	try {
		ebpf.mapClear('pppoe_tunnel', 'pppoe_traffic_stats');
	} catch (e) {
		log.info('pppoe traffic stats clear skipped: ' + (e && e.message ? e.message : String(e)));
	}
  for (var i = 0; i < 24; i++) {
    try {
      ebpf.mapPut('pppoe_tunnel', 'pppoe_tunnel_stats', u32lehex(i), repeatHex('00', 8));
    } catch (e) {
      log.info('pppoe tunnel stats clear skipped: ' + (e && e.message ? e.message : String(e)));
      return;
    }
  }
}

function readTrafficStats(payload) {
	payload = payload || {};
	var sampledAt = Date.now();
	var lastRecord = resources.get('sessions', 'last');
	var session = lastRecord && lastRecord.data ? lastRecord.data : {};
	var configRecord = resources.get(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY);
	var requestedProfile = text(payload.profile_key || payload.profile || '');
	var activeProfile = text(session.profile_key || session.wan_id || '');
	var out = {
		available: false,
		profile_key: activeProfile,
		session_id: clampInt(session.session_id, 0, 65535, 0),
		sampled_at_ms: sampledAt,
		counter_scope: 'current_tunnel',
		byte_scope: 'inner_ip',
		rx_packets: 0,
		rx_bytes: 0,
		tx_packets: 0,
		tx_bytes: 0
	};
	if (requestedProfile && activeProfile && token(requestedProfile) !== token(activeProfile)) {
		out.reason = 'selected profile is not the active PPPoE session';
		return out;
	}
	if (!configRecord || configRecord.enabled === false) {
		out.reason = 'PPPoE tunnel is not installed';
		return out;
	}
	try {
		var values = ebpf.mapGetPerCPU('pppoe_tunnel', 'pppoe_traffic_stats', u32lehex(0));
		for (var i = 0; i < values.length; i++) {
			var value = lower(values[i] || '').replace(/[^0-9a-f]/g, '');
			if (value.length < 64) continue;
			out.rx_packets += u64leNumber(value.substr(0, 16));
			out.rx_bytes += u64leNumber(value.substr(16, 16));
			out.tx_packets += u64leNumber(value.substr(32, 16));
			out.tx_bytes += u64leNumber(value.substr(48, 16));
		}
		out.available = true;
		out.cpu_values = values.length;
	} catch (e) {
		out.reason = errorMessage(e);
	}
	return out;
}

function readTunnelStats() {
  var names = [
    'unused',
    'local_encap_path',
    'decap_path',
    'pppoe_seen',
    'session_match',
    'adjust_room_fail',
    'store_local_eth_fail',
    'redirect_local_ok',
    'redirect_local_fail',
    'last_adjust_room_errno',
    'manual_decap_ok',
    'manual_decap_fail',
    'manual_decap_pull_fail',
    'manual_decap_bounds_fail',
    'manual_decap_copy_short',
    'manual_decap_trim_fail',
    'encap_parse_fail',
    'encap_adjust_room_fail',
    'encap_store_header_fail',
    'encap_store_eth_fail',
    'redirect_wan_ok',
    'redirect_wan_fail',
    'encap_l3_too_large',
    'reserved'
  ];
  var out = {
    counter_build: 'disabled_by_default',
    note: TUNNEL_STATS_BUILD_NOTE
  };
  for (var i = 0; i < names.length; i++) {
    try {
      out[names[i]] = u64leNumber(ebpf.mapGet('pppoe_tunnel', 'pppoe_tunnel_stats', u32lehex(i)));
    } catch (e) {
      out.error = e && e.message ? e.message : String(e);
      break;
    }
  }
  try {
    var configHex = ebpf.mapGet('pppoe_tunnel', 'pppoe_tunnel_config', u32lehex(0));
    out.config = decodeTunnelConfigHex(configHex);
  } catch (e) {
    out.config_error = errorMessage(e);
  }
  return out;
}

function decodeTunnelConfigHex(hex) {
  hex = normalizeTunnelConfigValueHex(hex);
  var bytes = hexToBytes(hex);
  return {
    enabled: u32le(bytes, 0),
    local_ifindex: u32le(bytes, 4),
    pipeline_ifindex: u32le(bytes, 8),
    wan_ifindex: u32le(bytes, 12),
    session_id: u16le(bytes, 16),
    flags: u16le(bytes, 18),
    mss_clamp_v4: u16le(bytes, 20),
    mss_clamp_v6: u16le(bytes, 22),
    local_src_mac: macBytesToText(bytes.slice(24, 30)),
    local_dst_mac: macBytesToText(bytes.slice(30, 36)),
    wan_src_mac: macBytesToText(bytes.slice(36, 42)),
    wan_dst_mac: macBytesToText(bytes.slice(42, 48)),
    value_hex: hex
  };
}

function sendPADI(profile, hostUniq) {
	var padi = pppoeDiscovery(CODE_PADI, 0, [
		tagString(TAG_SERVICE_NAME, profile.service),
		tagHex(TAG_HOST_UNIQ, hostUniq)
	]);
	return exchangeDiscovery(profile, 'ff:ff:ff:ff:ff:ff', padi, CODE_PADO, hostUniq, '');
}

function sendPADR(profile, peerMAC, hostUniq, tags) {
  return exchangeDiscovery(profile, peerMAC, pppoeDiscovery(CODE_PADR, 0, tags), CODE_PADS, hostUniq, peerMAC);
}

function exchangeDiscovery(profile, dstMAC, payload, wantCode, hostUniq, peerMAC) {
  var deadline = Date.now() + profile.timeout_ms;
  var frameLimit = Math.min(Math.max(profile.max_frames * 4, 8), 32);
  var firstFrames = [];

  if (net.l2.exchangeMany) {
    firstFrames = net.l2.exchangeMany(pppoeDiscoveryRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_DISC,
      dst_mac: dstMAC,
      payload: payload,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500,
      max_frames: frameLimit,
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, wantCode, peerMAC, profile)) || [];
  } else {
    var firstFrame = net.l2.exchange(pppoeDiscoveryRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_DISC,
      dst_mac: dstMAC,
      payload: payload,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500
    }, wantCode, peerMAC, profile));
    if (firstFrame !== null) firstFrames = [firstFrame];
  }
  var matched = findDiscoveryFrame(firstFrames, wantCode, hostUniq, peerMAC, wantCode === CODE_PADO ? profile.ac_name : '');
  if (matched !== null) return matched;

  while (Date.now() < deadline) {
    var timeout = Math.max(1, Math.min(profile.timeout_ms, deadline - Date.now()));
    var frames = recvDiscoveryFrames(profile, timeout, frameLimit, wantCode, peerMAC);
    if (!frames.length) break;
    matched = findDiscoveryFrame(frames, wantCode, hostUniq, peerMAC, wantCode === CODE_PADO ? profile.ac_name : '');
    if (matched !== null) return matched;
  }
  return null;
}

function recvDiscoveryFrames(profile, timeoutMs, maxFrames, wantCode, peerMAC) {
  if (net.l2.recvMany) {
    return net.l2.recvMany(pppoeDiscoveryRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_DISC,
      timeout_ms: timeoutMs,
      max_bytes: 1500,
      max_frames: maxFrames,
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, wantCode, peerMAC, profile)) || [];
  }
  var frame = net.l2.recv(pppoeDiscoveryRecvFilter({
    interface: profile.interface,
    ethertype: ETH_P_PPP_DISC,
    timeout_ms: timeoutMs,
    max_bytes: 1500
  }, wantCode, peerMAC, profile));
  return frame === null ? [] : [frame];
}

function pppoeDiscoveryRecvFilter(req, wantCode, peerMAC, profile) {
  applyL2IdentityToRequest(profile, req);
  if (wantCode != null) req.pppoe_code = wantCode;
  if (peerMAC) req.recv_src_mac = peerMAC;
  return req;
}

function pppoeSessionRecvFilter(req, peerMAC, sessionID, profile) {
  applyL2IdentityToRequest(profile, req);
  if (peerMAC) req.recv_src_mac = peerMAC;
  if (sessionID) req.pppoe_session_id = sessionID;
  req.pppoe_code = 0;
  return req;
}

function applyL2IdentityToRequest(profile, req) {
  var mac = profile && profile.mac_address ? macText(profile.mac_address) : '';
  if (!mac) return req;
  req.src_mac = mac;
  req.recv_dst_mac = mac;
  return req;
}

function findDiscoveryFrame(frames, wantCode, hostUniq, peerMAC, acName) {
  var wantHostUniq = lower(hostUniq || '');
  var wantPeer = macText(peerMAC || '');
  var wantACName = text(acName || '');
  for (var i = 0; i < frames.length; i++) {
    if (wantPeer && macText(frames[i].src_mac || '') !== wantPeer) continue;
    var parsed;
    try {
      parsed = parseDiscoveryFrame(frames[i]);
    } catch (e) {
      continue;
    }
    if (parsed.code !== wantCode) continue;
    var gotHostUniq = lower(firstTagHex(parsed, TAG_HOST_UNIQ));
    if (wantHostUniq && gotHostUniq && gotHostUniq !== wantHostUniq) continue;
    if (wantACName && firstTagText(parsed, TAG_AC_NAME) !== wantACName) continue;
    return frames[i];
  }
  return null;
}

function runSessionProbe(profile, peerMAC, sessionID, localMAC) {
	var identifier = randomByte();
	var lcpRequest = cpPacket(1, identifier, cpOptionU16(1, profile.mru) + cpOptionHex(5, crypto.randomBytes(4)));
  var out = {items: [], lcp_ack: false, auth_sent: false, auth_method: '', auth_ok: false, ipcp: null, ipv6cp: null, dhcpv6_pd: null};
	var firstFrames = exchangePPPControlFrames(profile, peerMAC, sessionID, PPP_LCP, lcpRequest, profile.timeout_ms, profile.max_frames);
	if (!firstFrames.length) {
		out.items.push({protocol: 'lcp', event: 'timeout'});
		return out;
	}
	processSessionFrames(profile, peerMAC, sessionID, firstFrames, identifier, out);

  for (var i = 1; i < profile.max_frames; i++) {
    if (lcpReadyForNetworkCP(profile, out)) break;
    var frames = recvPPPSessionFrames(profile, profile.timeout_ms, 1, peerMAC, sessionID);
    var frame = frames.length ? frames[0] : null;
    if (frame === null) {
      out.items.push({event: 'timeout'});
      break;
    }
    processSessionFrame(profile, peerMAC, sessionID, frame, identifier, out);
  }
  if (lcpReadyForNetworkCP(profile, out) && profile.negotiate_ipv4) {
    drainPeerControlAfterAuth(profile, peerMAC, sessionID, out);
    out.ipcp = runIPCP(profile, peerMAC, sessionID);
    if (out.peer_ipcp && out.ipcp) out.ipcp.peer_address = out.peer_ipcp.address || '';
    out.items.push({protocol: 'ipcp', event: out.ipcp.phase || 'complete'});
  }
  if (lcpReadyForNetworkCP(profile, out) && profile.negotiate_ipv6) {
    drainPeerControlAfterAuth(profile, peerMAC, sessionID, out);
    out.ipv6cp = runIPv6CP(profile, peerMAC, sessionID);
    if (out.peer_ipv6cp && out.ipv6cp) {
      out.ipv6cp.peer_interface_id = out.peer_ipv6cp.interface_id || '';
      out.ipv6cp.peer_link_local = out.peer_ipv6cp.link_local || '';
    }
    out.items.push({protocol: 'ipv6cp', event: out.ipv6cp.phase || 'complete'});
  }
  if (lcpReadyForNetworkCP(profile, out) && profile.request_ipv6_router && out.ipv6cp && out.ipv6cp.up) {
    out.ipv6_ra = requestIPv6Router(profile, peerMAC, sessionID);
    out.items.push({protocol: 'icmpv6', event: out.ipv6_ra.phase || 'complete'});
  }
  if (lcpReadyForNetworkCP(profile, out) && (profile.request_ipv6_address || profile.request_pd) && out.ipv6cp && out.ipv6cp.up) {
    out.dhcpv6_pd = requestDHCPv6PD(profile, peerMAC, sessionID, localMAC);
    out.items.push({protocol: 'dhcpv6', event: out.dhcpv6_pd.phase || 'complete'});
  }
  return out;
}

function lcpReadyForNetworkCP(profile, out) {
  if (out.auth_ok) return true;
  if (!out.lcp_ack) return false;
  if (!profile.username) return true;
  if (profile.auth !== 'pap' && profile.auth !== 'chap') return true;
  return false;
}

function processSessionFrame(profile, peerMAC, sessionID, frame, ourLCPID, out) {
  var parsed = parseSessionFrame(frame);
  if (parsed.session_id !== sessionID) {
    out.items.push({event: 'skip_session', session_id: parsed.session_id});
    return;
  }
  handlePPPFrame(profile, peerMAC, sessionID, parsed, ourLCPID, out);
}

function processSessionFrames(profile, peerMAC, sessionID, frames, ourLCPID, out) {
  for (var i = 0; i < frames.length && i < Math.min(profile.max_frames * 2, 16); i++) {
    processSessionFrame(profile, peerMAC, sessionID, frames[i], ourLCPID, out);
  }
}

function handlePPPFrame(profile, peerMAC, sessionID, parsed, ourLCPID, out) {
  if (parsed.protocol === PPP_LCP) {
    var lcp = parseCP(parsed.payload);
    out.items.push({protocol: 'lcp', code: lcp.code, identifier: lcp.identifier, length: lcp.length});
    if (lcp.code === 1) {
      var nextLCPFrames = exchangePPPControlFrames(profile, peerMAC, sessionID, PPP_LCP, cpPacket(2, lcp.identifier, lcp.data_hex), profile.timeout_ms, profile.max_frames);
      out.items.push({protocol: 'lcp', event: 'configure_ack_sent', identifier: lcp.identifier});
      if (nextLCPFrames.length) {
        processSessionFrames(profile, peerMAC, sessionID, nextLCPFrames, ourLCPID, out);
      }
    } else if (lcp.code === 2 && lcp.identifier === ourLCPID) {
      out.lcp_ack = true;
      out.items.push({protocol: 'lcp', event: 'local_configure_ack'});
      if (profile.auth === 'pap' && profile.username && !out.auth_sent) {
        var papFrames = sendPAPFrames(profile, peerMAC, sessionID);
        out.auth_sent = true;
        out.auth_method = 'pap';
        if (!papFrames.length) {
          out.items.push({protocol: 'pap', event: 'timeout'});
        } else {
          processSessionFrames(profile, peerMAC, sessionID, papFrames, ourLCPID, out);
        }
      }
    }
    return;
  }
  if (parsed.protocol === PPP_CHAP) {
    var chap = parseCP(parsed.payload);
    out.items.push({protocol: 'chap', code: chap.code, identifier: chap.identifier, length: chap.length});
    if (chap.code === 1 && profile.auth === 'chap' && profile.username && profile.password && !out.auth_sent) {
      var chapFrames = sendCHAPResponseFrames(profile, peerMAC, sessionID, chap);
      out.auth_sent = true;
      out.auth_method = 'chap';
      if (!chapFrames.length) {
        out.items.push({protocol: 'chap', event: 'timeout'});
      } else {
        processSessionFrames(profile, peerMAC, sessionID, chapFrames, ourLCPID, out);
      }
    } else if (chap.code === 3) {
      out.auth_ok = true;
      out.auth_method = 'chap';
    }
    return;
  }
  if (parsed.protocol === PPP_PAP) {
    var pap = parseCP(parsed.payload);
    out.items.push({protocol: 'pap', code: pap.code, identifier: pap.identifier, length: pap.length});
    if (pap.code === 2) {
      out.auth_ok = true;
      out.auth_method = 'pap';
    }
    return;
  }
  if (parsed.protocol === PPP_IPCP || parsed.protocol === PPP_IPV6CP) {
    handlePeerNetworkControl(profile, peerMAC, sessionID, parsed, out);
    return;
  }
  out.items.push({protocol: '0x' + u16hex(parsed.protocol), length: parsed.payload.length / 2});
}

function drainPeerControlAfterAuth(profile, peerMAC, sessionID, out) {
  if (out.peer_control_drained) return;
  out.peer_control_drained = true;
  var result = servicePPPControlWindow(profile, peerMAC, sessionID, profile.control_ack_timeout_ms, null);
  if (result.frames || result.configure_acks_sent || result.skipped || result.parse_errors) {
    out.items.push({
      event: 'peer_control_drained',
      frames: result.frames,
      configure_acks_sent: result.configure_acks_sent,
      skipped: result.skipped,
      parse_errors: result.parse_errors
    });
  }
}

function handlePeerNetworkControl(profile, peerMAC, sessionID, parsed, out) {
  var cp = parseCP(parsed.payload);
  var protocol = pppControlProtocolName(parsed.protocol);
  var event = {protocol: protocol, code: cp.code, identifier: cp.identifier, length: cp.length};
  annotatePeerNetworkControl(parsed.protocol, cp, event, out);
  out.items.push(event);
  if (cp.code === 1) {
    sendPPPControl(profile, peerMAC, sessionID, parsed.protocol, cpPacket(2, cp.identifier, cp.data_hex));
    out.items.push({protocol: protocol, event: 'configure_ack_sent', identifier: cp.identifier});
    return;
  }
  out.items.push({protocol: protocol, event: cpCodeName(cp.code), identifier: cp.identifier});
}

function annotatePeerNetworkControl(protocol, cp, event, out) {
  if (cp.code !== 1) return;
  var options = parseCPOptions(cp.data_hex);
  if (protocol === PPP_IPCP) {
    var ip = firstCPIPv4Option(options, IPCP_OPTION_IP_ADDRESS);
    if (!ip) return;
    event.address = ip;
    if (out) out.peer_ipcp = {address: ip};
    return;
  }
  if (protocol === PPP_IPV6CP) {
    var iid = firstCPHexOption(options, IPV6CP_OPTION_INTERFACE_ID);
    if (!iid) return;
    event.interface_id = iid;
    event.link_local = linkLocalFromIID(iid);
    if (out) out.peer_ipv6cp = {interface_id: iid, link_local: event.link_local};
  }
}

function sendPAPFrames(profile, peerMAC, sessionID) {
  var userHex = stringHex(profile.username);
  var passHex = stringHex(profile.password);
  var data = hexByte(userHex.length / 2) + userHex + hexByte(passHex.length / 2) + passHex;
  return exchangePPPControlFrames(profile, peerMAC, sessionID, PPP_PAP, cpPacket(1, randomByte(), data), profile.timeout_ms, profile.max_frames);
}

function sendCHAPResponseFrames(profile, peerMAC, sessionID, challenge) {
  var bytes = hexToBytes(challenge.data_hex);
  if (!bytes.length) throw new Error('empty CHAP challenge');
  var valueSize = bytes[0];
  var challengeHex = bytesToHex(bytes.slice(1, 1 + valueSize));
  var digest = crypto.md5([challenge.identifier], profile.password, {hex: challengeHex});
  var nameHex = stringHex(profile.username);
  var data = hexByte(16) + digest + nameHex;
  return exchangePPPControlFrames(profile, peerMAC, sessionID, PPP_CHAP, cpPacket(2, challenge.identifier, data), profile.timeout_ms, profile.max_frames);
}

function persistRuntimeProfile(profile) {
  var data = keepaliveTimerPayload(profile, {}, 0);
  data.wan_id = profile.wan_id;
  data.disconnect_drain_ms = profile.disconnect_drain_ms;
  data.dhcpv6_timeout_ms = profile.dhcpv6_timeout_ms;
  data.dhcpv6_settle_ms = profile.dhcpv6_settle_ms;
  data.ipv6_ra_timeout_ms = profile.ipv6_ra_timeout_ms;
  delete data.session_id;
  delete data.ac_mac;
  delete data.keepalive_failures;
  resources.set('profiles', profile.profile_key, data, true);
}

function resumeSessionTimers() {
  timer.clear('lcp_echo');
  timer.clear('session_control');
  timer.clear(REDIAL_RETRY_TIMER);
  var lastRecord = resources.get('sessions', 'last');
  var last = lastRecord && lastRecord.data ? lastRecord.data : null;
  if (!last) return;
  var key = token(last.profile_key || last.wan_id || 'default');
  var profileRecord = resources.get('profiles', key);
  if (!profileRecord || profileRecord.enabled === false || !profileRecord.data) return;
  var active = last.lcp_ready === true && last.padt_sent !== true && last.session_id && last.ac_mac;
  var resumeRedial = redialResumePhase(last.phase);
  if (!active && !resumeRedial) return;

  var profile;
  try {
    profile = loadProfile({profile_key: key});
    if (!active && !profile.auto_redial) return;
    prepareL2Identity(profile);
  } catch (e) {
    log.info('pppoe session timer resume deferred for ' + key + ': ' + errorMessage(e));
    return;
  }

  if (active) {
    if (!profile.keepalive_interval_ms) return;
    timer.setTimeout('lcp_echo', Math.min(250, profile.keepalive_interval_ms),
      keepaliveTimerPayload(profile, last, 0));
    return;
  }
  if (!resumeRedial) return;
  var waiting = scheduleRedialRetry(profile, {
    phase: 'redial_wait',
    profile_key: key,
    interface: profile.interface,
    redial_attempted: true,
    redial_trigger: 'runtime_reconcile',
    redial_started_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }, Math.max(1, clampInt(last.redial_next_attempt, 1, 1000000, 1)));
  recordRedialStatus(waiting, null);
}

function redialResumePhase(phase) {
  phase = lower(phase);
  return phase === 'redial_wait' || phase === 'redial_retry' || phase === 'redialing' || phase === 'handoff_error';
}

function armKeepalive(profile, session, failures, failureStartedMs) {
  failures = clampInt(failures, 0, 1000000, 0);
  failureStartedMs = normalizeTimestampMs(failureStartedMs, 0);
  if (!profile.keepalive_interval_ms || !session || !session.session_id || !session.ac_mac) {
    timer.clear('lcp_echo');
    return;
  }
  timer.clear(REDIAL_RETRY_TIMER);
  timer.setInterval('lcp_echo', profile.keepalive_interval_ms,
    keepaliveTimerPayload(profile, session, failures, failureStartedMs));
}

function armSessionControl(profile, session) {
  timer.clear('session_control');
  if (profile.send_padt || !profile.post_session_control_ms || !session || !session.session_id || !session.ac_mac) return;
  var payload = sessionControlTimerPayload(profile, session, profile.post_session_control_ms);
  payload.deadline_ms = Date.now() + profile.post_session_control_ms;
  payload.started_at = new Date().toISOString();
  timer.setTimeout('session_control', 10, payload);
}

function disconnectSession(profile, payload) {
  var record = resources.get('sessions', 'last');
  var data = record && record.data ? record.data : {};
  var sessionID = clampInt(payload.session_id || data.session_id, 1, 65535, 0);
  var peerMAC = macText(payload.ac_mac || data.ac_mac || '');
  if (!sessionID || !peerMAC) throw new Error('no stored or provided PPPoE session to disconnect');
  timer.clear('lcp_echo');
  timer.clear('session_control');
  timer.clear(REDIAL_RETRY_TIMER);
  var started = Date.now();
  var frames = sendPADT(profile, peerMAC, sessionID, profile.disconnect_drain_ms);
  var control = newPPPControlWindowResult(profile.disconnect_drain_ms);
  consumePPPControlFrames(profile, peerMAC, sessionID, frames, {terminate_request: true}, control);
  if (profile.disconnect_drain_ms > 0 && control.terminate_acks_sent === 0) {
    try {
      var remaining = Math.max(0, profile.disconnect_drain_ms - (Date.now() - started));
      if (remaining > 0) {
        control = mergeControlWindowResult(control, servicePPPControlWindow(profile, peerMAC, sessionID, remaining, {
          terminate_request: true
        }));
      } else {
        finishPPPControlWindowResult(control, {terminate_request: true});
      }
    } catch (e) {
      control.phase = 'error';
      control.error = errorMessage(e);
    }
  }
  clearTunnelConfig();
  var cleanup = cleanupL2Identity(profile.profile_key, false);
  var disconnected = merge(data, {
    phase: 'disconnected',
    padt_sent: true,
    lcp_terminate_ack_sent: control.terminate_acks_sent > 0,
    disconnect_control: control,
    l2_identity_cleanup: cleanup,
    updated_at: new Date().toISOString()
  });
  resources.set('sessions', 'last', disconnected);
  markWANLinkDown(profile, disconnected, 'disconnected');
}

function recordSession(profile, session) {
  session = session || {};
  resources.set('sessions', 'last', session);
  if (!session.session_id) {
    try {
      markWANLinkDown(profile, session, session.phase || 'session_failed');
    } catch (e) {
      log.info('PPPoE failed-session WAN cleanup deferred: ' + errorMessage(e));
    }
    throw new Error(redialSessionFailure(session));
  }
  var link = publishWANLink(profile, session);
  if (!profile.wan_core_required || wanCoreSyncSucceeded(link && link.wan_core_sync)) return link;

  clearTunnelConfig();
  var sync = link && link.wan_core_sync ? link.wan_core_sync : {status: 'missing'};
  var message = 'required WAN core handoff failed: ' + (sync.error || sync.reason || sync.status || 'unknown error');
  var failedSession = merge(session, {
    phase: 'handoff_error',
    tunnel_installed: false,
    handoff_error: message,
    updated_at: new Date().toISOString()
  });
  resources.set('sessions', 'last', failedSession);
  failCloseWANCoreSync(profile, link, message);
  throw new Error(message);
}

function publishWANLink(profile, session) {
  if (!session || !session.session_id) return null;
  var link = normalizedWANLink(profile, session);
  var sync = syncWANCore(profile, link);
  if (sync) link.wan_core_sync = sync;
  resources.set('wan_links', link.wan_id, link);
  return link;
}

function wanCoreSyncSucceeded(sync) {
  return sync && sync.status === 'synced' && sync.applied === true;
}

function failCloseWANCoreSync(profile, link, message) {
  link = merge(link || normalizedWANLink(profile, {}), {
    state: 'down',
    usable: false,
    phase: 'handoff_error',
    handoff_error: message,
    updated_at: new Date().toISOString()
  });
  var sync = syncWANCore(profile, link);
  if (sync) link.wan_core_sync = sync;
  resources.set('wan_links', link.wan_id, link, false);
}

function markWANLinkDown(profile, previous, phase) {
  var key = token((previous && previous.wan_id) || profile.wan_id || profile.profile_key);
  var record = resources.get('wan_links', key);
  var data = record && record.data ? record.data : normalizedWANLink(profile, previous || {});
  var link = merge(data, {
    state: 'down',
    usable: false,
    phase: phase || 'down',
    updated_at: new Date().toISOString()
  });
  var sync = syncWANCore(profile, link);
  if (sync) link.wan_core_sync = sync;
  resources.set('wan_links', key, link, false);
}

function failCloseWANCoreFromStored(key, payload, phase) {
  var record = resources.get('wan_links', key);
  if (!record || !record.data) return null;
  var profile = {
    profile_key: key,
    wan_id: key,
    wan_core_sync: bool(firstDefined(payload.wan_core_sync, payload.sync_wan_core), true),
    wan_core_apply: bool(firstDefined(payload.wan_core_apply, payload.apply_wan_core), true),
    wan_core_plugin: token(payload.wan_core_plugin || payload.wan_core_plugin_id || 'wan_core')
  };
  var link = merge(record.data, {
    state: 'down',
    usable: false,
    phase: phase || 'down',
    updated_at: new Date().toISOString()
  });
  return syncWANCore(profile, link);
}

function normalizedWANLink(profile, session) {
  session = session || {};
  var ipcp = session.ipcp || {};
  var ipv6cp = session.ipv6cp || {};
  var ipv6RA = session.ipv6_ra || {};
  var dhcpv6PD = session.dhcpv6_pd || {};
  var ipv6Addresses = Array.isArray(dhcpv6PD.addresses) ? dhcpv6PD.addresses : [];
  var pdPrefixes = Array.isArray(dhcpv6PD.prefixes) ? dhcpv6PD.prefixes : [];
  var open = session.padt_sent !== true && session.lcp_ready === true;
  var state = open ? 'up' : (session.padt_sent ? 'closed' : (session.phase || 'unknown'));
  var pipelineInterface = session.tunnel && session.tunnel.pipeline_interface || profile.pipeline_interface || '';
  return {
    wan_id: token(session.wan_id || profile.wan_id || profile.profile_key),
    profile_key: profile.profile_key,
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: state,
    usable: open,
    real_interface: profile.interface,
    physical_interface: profile.interface,
    wan_interface: profile.local_interface || '',
    local_interface: profile.local_interface || '',
    pipeline_interface: pipelineInterface,
    handoff_mode: 'segmented_veth',
    mac_address: profile.mac_address || session.local_mac || '',
    local_mac: session.local_mac || '',
    peer_mac: session.ac_mac || '',
    ac_mac: session.ac_mac || '',
    session_id: clampInt(session.session_id, 0, 65535, 0),
    session_id_hex: session.session_id_hex || '',
    auth: profile.auth,
    auth_method: session.auth_method || '',
    mtu: profile.mru,
    ipv4: ipcp.address || '',
    ipv4_peer: ipcp.peer_address || '',
    ipv6: dhcpv6PD.address || (ipv6Addresses[0] && ipv6Addresses[0].address) || ipv6RA.address || '',
    ipv6_address: dhcpv6PD.address || (ipv6Addresses[0] && ipv6Addresses[0].address) || ipv6RA.address || '',
    ipv6_addresses: ipv6Addresses,
    ipv6_link_local: ipv6cp.link_local || '',
    ipv6_peer_link_local: ipv6cp.peer_link_local || '',
    ipv6_gateway: ipv6RA.router || '',
    ipv6_prefix: ipv6RA.prefix || '',
    pd_prefix: dhcpv6PD.prefix || (pdPrefixes[0] && pdPrefixes[0].prefix) || '',
    pd_prefixes: pdPrefixes,
    dns_servers: uniqueTextValues((ipcp.dns_servers || []).concat(dhcpv6PD.dns_servers || []).concat(ipv6RA.dns_servers || [])),
    tunnel: session.tunnel || null,
    handoff: {
      preferred_mode: 'segmented_veth',
      local_interface: profile.local_interface || '',
      pipeline_interface: pipelineInterface,
      forward_core_parent_interface: profile.local_interface || '',
      segmentation_ready: !!pipelineInterface,
      requires_kernel_tc_prepared_l2: false
    },
    updated_at: session.updated_at || new Date().toISOString()
  };
}

function syncWANCore(profile, link) {
  if (!profile.wan_core_sync) return null;
  if (typeof plugins === 'undefined' || !plugins.resources || typeof plugins.resources.set !== 'function') {
    return {status: 'skipped', reason: 'plugin.resource API is unavailable'};
  }
  try {
    plugins.resources.set(profile.wan_core_plugin, 'sessions', link.wan_id, link, link.usable === true, profile.wan_core_apply);
    return {
      status: 'synced',
      plugin: profile.wan_core_plugin,
      resource: 'sessions',
      key: link.wan_id,
      enabled: link.usable === true,
      applied: profile.wan_core_apply === true
    };
  } catch (e) {
    return {
      status: 'error',
      plugin: profile.wan_core_plugin,
      resource: 'sessions',
      key: link.wan_id,
      error: e && e.message ? e.message : String(e)
    };
  }
}

function redialAfterKeepaliveFailure(profile, keepaliveResult, previousSession) {
  timer.clear('lcp_echo');
  timer.clear('session_control');
  timer.clear(REDIAL_RETRY_TIMER);
  var base = merge(keepaliveResult, {
    redial_attempted: true,
    redial_started_at: new Date().toISOString(),
    redial_trigger: keepaliveResult.phase || 'keepalive_timeout'
  });
  if (profile.redial_send_padt) {
    var previousPeer = macText(previousSession && previousSession.ac_mac || '');
    var previousID = clampInt(previousSession && previousSession.session_id, 1, 65535, 0);
    try {
      if (previousPeer && previousID) {
        sendPADT(profile, previousPeer, previousID);
        base.previous_session_padt_sent = true;
      }
    } catch (e) {
      base.previous_session_close_error = errorMessage(e);
    }
  }
  if (profile.redial_clear_tunnel) clearTunnelConfig();
  markWANLinkDown(profile, previousSession || {}, 'redial_wait');
  var waiting = scheduleRedialRetry(profile, base, 1);
  recordRedialStatus(waiting, null);
  recordRedialDiagnostic(waiting);
  return waiting;
}

function serviceRedialRetryTimer(payload) {
  var profile = loadProfile(payload);
  var attempt = clampInt(payload.redial_attempt, 1, 1000000, 1);
  var base = {
    phase: 'redialing',
    profile_key: profile.profile_key,
    interface: profile.interface,
    mac_mode: profile.mac_mode,
    mac_address: profile.mac_address || '',
    service: profile.service,
    auth: profile.auth,
    redial_attempted: true,
    redial_attempt: attempt,
    redial_trigger: text(payload.redial_trigger || 'retry'),
    redial_started_at: text(payload.redial_started_at || new Date().toISOString()),
    updated_at: new Date().toISOString()
  };
  var result = attemptRedial(profile, base, attempt);
  resources.set('sessions', 'keepalive', result);
  recordRedialDiagnostic(result);
}

function attemptRedial(profile, base, attempt) {
  var session = null;
  try {
    prepareL2Identity(profile);
    profile.send_padt = false;
    session = probeSession(profile);
    if (!session || !session.session_id || session.lcp_ready !== true) {
      throw new Error(redialSessionFailure(session));
    }
    recordSession(profile, session);
    armSessionControl(profile, session);
    armKeepalive(profile, session, 0);
    timer.clear(REDIAL_RETRY_TIMER);
    return merge(base, {
      phase: 'redial_ok',
      redial_phase: session && session.phase ? session.phase : 'unknown',
      redial_session_id: session.session_id || 0,
      redial_tunnel_installed: session && session.tunnel_installed === true,
      redial_updated_at: new Date().toISOString()
    });
  } catch (e) {
    var cleanupError = cleanupFailedRedialSession(profile, session);
    try {
      clearTunnelConfig();
    } catch (clearError) {
      cleanupError = appendError(cleanupError, 'clear tunnel: ' + errorMessage(clearError));
    }
    markWANLinkDown(profile, session || {}, 'redial_retry');
    var failed = merge(base, {
      phase: 'redial_retry',
      redial_attempt: attempt,
      redial_phase: session && session.phase ? session.phase : 'error',
      redial_error: errorMessage(e),
      redial_cleanup_error: cleanupError,
      redial_updated_at: new Date().toISOString()
    });
    var waiting = scheduleRedialRetry(profile, failed, attempt + 1);
    recordRedialStatus(waiting, session);
    return waiting;
  }
}

function cleanupFailedRedialSession(profile, session) {
  if (!session || !session.session_id || !session.ac_mac) return '';
  try {
    sendPADT(profile, session.ac_mac, session.session_id);
    return '';
  } catch (e) {
    return 'close failed session: ' + errorMessage(e);
  }
}

function redialSessionFailure(session) {
  if (!session) return 'PPPoE redial returned no session';
  if (session.message) return text(session.message);
  if (!session.session_id) return 'PPPoE redial did not allocate a session';
  if (session.auth_sent && session.auth_ok !== true) return 'PPPoE redial authentication failed';
  if (session.lcp_ready !== true) return 'PPPoE redial did not reach LCP ready';
  return 'PPPoE redial failed';
}

function scheduleRedialRetry(profile, result, attempt) {
  var delay = redialRetryDelay(profile, attempt);
  var payload = redialRetryTimerPayload(profile, attempt, result);
  timer.setTimeout(REDIAL_RETRY_TIMER, delay, payload);
  return merge(result, {
    phase: 'redial_wait',
    redial_attempt: Math.max(0, attempt - 1),
    redial_next_attempt: attempt,
    redial_retry_in_ms: delay,
    updated_at: new Date().toISOString()
  });
}

function redialRetryDelay(profile, attempt) {
  var exponent = Math.min(Math.max(attempt - 1, 0), 16);
  return Math.min(profile.redial_retry_max_ms,
    profile.redial_retry_initial_ms * Math.pow(2, exponent));
}

function recordRedialStatus(result, session) {
  var current = resources.get('sessions', 'last');
  var previous = current && current.data ? current.data : {};
  var status = merge(previous, {
    phase: result.phase,
    lcp_ready: false,
    tunnel_installed: false,
    redial_attempted: true,
    redial_attempt: result.redial_attempt || 0,
    redial_next_attempt: result.redial_next_attempt || 0,
    redial_retry_in_ms: result.redial_retry_in_ms || 0,
    redial_error: result.redial_error || '',
    redial_phase: result.redial_phase || '',
    updated_at: new Date().toISOString()
  });
  if (session && session.message) status.message = session.message;
  resources.set('sessions', 'last', status);
}

function recordRedialDiagnostic(result) {
  var previousRecord = resources.get('sessions', 'redial_last');
  var previous = previousRecord && previousRecord.data ? previousRecord.data : {};
  var starting = clampInt(result.redial_attempt, 0, 1000000, 0) === 0 &&
    clampInt(result.redial_next_attempt, 0, 1000000, 0) === 1;
  resources.set('sessions', 'redial_last', {
    count: clampInt(previous.count, 0, 1000000, 0) + (starting ? 1 : 0),
    phase: text(result.phase || 'unknown'),
    trigger: text(result.redial_trigger || previous.trigger || ''),
    attempt: clampInt(result.redial_attempt, 0, 1000000, 0),
    next_attempt: clampInt(result.redial_next_attempt, 0, 1000000, 0),
    retry_in_ms: clampInt(result.redial_retry_in_ms, 0, 3600000, 0),
    session_id: clampInt(result.redial_session_id || result.session_id, 0, 65535, 0),
    error: text(result.redial_error || ''),
    started_at: text(result.redial_started_at || previous.started_at || ''),
    updated_at: text(result.redial_updated_at || result.updated_at || new Date().toISOString())
  });
}

function appendError(current, next) {
  if (!next) return current || '';
  return current ? current + '; ' + next : next;
}

function sendLCPEcho(profile, peerMAC, sessionID) {
  var identifier = randomByte();
  var expected = {
    lcp_echo_identifier: identifier
  };
  var started = Date.now();
  var frames = exchangePPPControlFrames(profile, peerMAC, sessionID, PPP_LCP, cpPacket(9, identifier, '00000000'), profile.timeout_ms, profile.max_frames);
  var serviced = newPPPControlWindowResult(profile.timeout_ms);
  consumePPPControlFrames(profile, peerMAC, sessionID, frames, expected, serviced);
  if (!serviced.lcp_echo_reply) {
    var remaining = Math.max(0, profile.timeout_ms - (Date.now() - started));
    if (remaining > 0) {
      serviced = mergeControlWindowResult(serviced, servicePPPControlWindow(profile, peerMAC, sessionID, remaining, expected));
    } else {
      finishPPPControlWindowResult(serviced, expected);
    }
  }
  var phase = serviced.lcp_echo_reply ? 'keepalive_ok' : 'keepalive_timeout';
  return baseResult(profile, phase, {
    session_id: sessionID,
    ac_mac: peerMAC,
    code: serviced.lcp_echo_code || 0,
    identifier: identifier,
    control: serviced
  });
}

function confirmLCPEcho(profile, peerMAC, sessionID) {
  var confirmProfile = merge(profile, {
    timeout_ms: profile.keepalive_confirm_timeout_ms
  });
  try {
    prepareL2Identity(confirmProfile);
    var result = sendLCPEcho(confirmProfile, peerMAC, sessionID);
    if (result.phase !== 'keepalive_ok') result.phase = 'keepalive_confirm_timeout';
    return result;
  } catch (e) {
    return baseResult(profile, 'keepalive_confirm_error', {
      session_id: sessionID,
      ac_mac: peerMAC,
      message: errorMessage(e)
    });
  }
}

function keepaliveFailureStartedMs(payload, now) {
  var started = normalizeTimestampMs(payload.keepalive_failure_started_ms, 0);
  if (!started || started > now) return now;
  return started;
}

function normalizeTimestampMs(value, fallback) {
  var n = Number(value);
  if (!isFinite(n) || n <= 0 || n > 9007199254740991) return fallback;
  return Math.floor(n);
}

function keepaliveTimerPayload(profile, session, failures, failureStartedMs) {
  session = session || {};
  return {
    profile_key: profile.profile_key,
    interface: profile.interface,
    mac_mode: profile.mac_mode,
    mac_address: profile.mac_address,
    username: profile.username,
    service: profile.service,
    ac_name: profile.ac_name,
    auth: profile.auth,
    timeout_ms: profile.timeout_ms,
    control_ack_timeout_ms: profile.control_ack_timeout_ms,
    control_idle_timeout_ms: profile.control_idle_timeout_ms,
    max_frames: profile.max_frames,
    mru: profile.mru,
    negotiate_ipv4: profile.negotiate_ipv4,
    negotiate_ipv6: profile.negotiate_ipv6,
    request_ipv6_address: profile.request_ipv6_address,
    request_ipv6_router: profile.request_ipv6_router,
    request_pd: profile.request_pd,
    dhcpv6_request: profile.dhcpv6_request,
    dhcpv6_timeout_ms: profile.dhcpv6_timeout_ms,
    ipv6_ra_timeout_ms: profile.ipv6_ra_timeout_ms,
    ipv6_iid: profile.ipv6_iid,
    dhcpv6_iaid: profile.dhcpv6_iaid,
    keepalive_interval_ms: profile.keepalive_interval_ms,
    keepalive_failure_threshold: profile.keepalive_failure_threshold,
    keepalive_failure_grace_ms: profile.keepalive_failure_grace_ms,
    keepalive_confirm_timeout_ms: profile.keepalive_confirm_timeout_ms,
    keepalive_failures: clampInt(failures, 0, 1000000, 0),
    keepalive_failure_started_ms: normalizeTimestampMs(failureStartedMs, 0),
    auto_redial: profile.auto_redial,
    redial_clear_tunnel: profile.redial_clear_tunnel,
    redial_send_padt: profile.redial_send_padt,
    redial_retry_initial_ms: profile.redial_retry_initial_ms,
    redial_retry_max_ms: profile.redial_retry_max_ms,
    install_tunnel: profile.install_tunnel,
    prepare_interfaces: profile.prepare_interfaces,
    prepare_local_mtu: profile.prepare_local_mtu,
    prepare_wan_mtu: profile.prepare_wan_mtu,
    mss_clamp_v4: profile.mss_clamp_v4,
    mss_clamp_v6: profile.mss_clamp_v6,
    prepare_offloads: profile.prepare_offloads,
    prepare_gso: profile.prepare_gso,
    prepare_wan_offloads: profile.prepare_wan_offloads,
    allow_unsafe_offloads: profile.allow_unsafe_offloads,
    sync_hook_bindings: profile.sync_hook_bindings,
    apply_hook_bindings: profile.apply_hook_bindings,
    post_session_control_ms: profile.post_session_control_ms,
    decap_mode: profile.decap_mode,
    send_padt: false,
    local_interface: profile.local_interface,
    pipeline_interface: profile.pipeline_interface,
    wan_interface: profile.wan_interface,
    local_ifindex: profile.local_ifindex,
    pipeline_ifindex: profile.pipeline_ifindex,
    wan_ifindex: profile.wan_ifindex,
    local_src_mac: profile.local_src_mac,
    local_dst_mac: profile.local_dst_mac,
    wan_src_mac: profile.wan_src_mac,
    wan_dst_mac: profile.wan_dst_mac,
    wan_core_sync: profile.wan_core_sync,
    wan_core_required: profile.wan_core_required,
    wan_core_apply: profile.wan_core_apply,
    wan_core_plugin: profile.wan_core_plugin,
    session_id: session.session_id,
    ac_mac: session.ac_mac
  };
}

function redialRetryTimerPayload(profile, attempt, result) {
  var payload = keepaliveTimerPayload(profile, {}, 0);
  payload.redial_attempt = attempt;
  payload.redial_trigger = text(result && result.redial_trigger || 'retry');
  payload.redial_started_at = text(result && result.redial_started_at || new Date().toISOString());
  return payload;
}

function resolveProfilePassword(profile) {
  var key = profilePasswordSecretKey(profile.profile_key);
  if (profile.password) {
    try {
      secret.set(key, profile.password);
    } catch (e) {
      // A transient secret-store failure must not break the current dial.
    }
    return profile.password;
  }
  try {
    var stored = secret.get(key);
    if (stored == null) return '';
    if (typeof stored === 'string') return text(stored);
    if (stored && stored.password != null) return text(stored.password);
    return text(stored);
  } catch (e) {
    return '';
  }
}

function profilePasswordSecretKey(profileKey) {
  return 'pppoe-password-' + token(profileKey || 'default');
}

function sessionControlTimerPayload(profile, session, remainingMs) {
  return {
    profile_key: profile.profile_key,
    interface: profile.interface,
    mac_mode: profile.mac_mode,
    mac_address: profile.mac_address,
    timeout_ms: Math.min(profile.timeout_ms, 500),
    control_ack_timeout_ms: profile.control_ack_timeout_ms,
    control_idle_timeout_ms: profile.control_idle_timeout_ms,
    max_frames: profile.max_frames,
    session_id: session.session_id,
    ac_mac: session.ac_mac,
    remaining_ms: remainingMs,
    slice_ms: Math.min(500, Math.max(50, profile.timeout_ms))
  };
}

function runIPCP(profile, peerMAC, sessionID) {
  var requestedIP = '0.0.0.0';
  var requestedDNS = {};
  requestedDNS[IPCP_OPTION_PRIMARY_DNS] = '0.0.0.0';
  requestedDNS[IPCP_OPTION_SECONDARY_DNS] = '0.0.0.0';
  var enabledDNS = {};
  enabledDNS[IPCP_OPTION_PRIMARY_DNS] = true;
  enabledDNS[IPCP_OPTION_SECONDARY_DNS] = true;
  var last = null;
  for (var attempt = 0; attempt < profile.max_frames; attempt++) {
    var identifier = randomByte();
    var requestOptions = cpOptionIPv4(IPCP_OPTION_IP_ADDRESS, requestedIP);
    if (enabledDNS[IPCP_OPTION_PRIMARY_DNS]) requestOptions += cpOptionIPv4(IPCP_OPTION_PRIMARY_DNS, requestedDNS[IPCP_OPTION_PRIMARY_DNS]);
    if (enabledDNS[IPCP_OPTION_SECONDARY_DNS]) requestOptions += cpOptionIPv4(IPCP_OPTION_SECONDARY_DNS, requestedDNS[IPCP_OPTION_SECONDARY_DNS]);
    var req = cpPacket(1, identifier, requestOptions);
    var frame = exchangePPPControl(profile, peerMAC, sessionID, PPP_IPCP, req);
    var result = completeCPNegotiation(profile, peerMAC, sessionID, PPP_IPCP, identifier, frame);
    if (result.timeout) return {phase: 'timeout', requested_address: requestedIP};
    if (result.protocol !== PPP_IPCP) return {phase: 'unexpected_protocol', protocol: '0x' + u16hex(result.protocol), requested_address: requestedIP};
    var cp = result.cp;
    var options = parseCPOptions(cp.data_hex);
    var ip = firstCPIPv4Option(options, IPCP_OPTION_IP_ADDRESS);
    var primaryDNS = firstCPIPv4Option(options, IPCP_OPTION_PRIMARY_DNS) || requestedDNS[IPCP_OPTION_PRIMARY_DNS];
    var secondaryDNS = firstCPIPv4Option(options, IPCP_OPTION_SECONDARY_DNS) || requestedDNS[IPCP_OPTION_SECONDARY_DNS];
    last = {
      phase: cpCodeName(cp.code),
      up: cp.code === 2,
      code: cp.code,
      identifier: cp.identifier,
      address: ip || requestedIP,
      requested_address: requestedIP,
      attempts: attempt + 1,
      dns_servers: usableIPCPDNSServers(enabledDNS, primaryDNS, secondaryDNS)
    };
    if (cp.code === 2) {
      last.peer = ackPeerConfigureRequests(profile, peerMAC, sessionID, PPP_IPCP);
      return last;
    }
    if (cp.code === 3) {
      if (ip) requestedIP = ip;
      if (firstCPIPv4Option(options, IPCP_OPTION_PRIMARY_DNS)) requestedDNS[IPCP_OPTION_PRIMARY_DNS] = primaryDNS;
      if (firstCPIPv4Option(options, IPCP_OPTION_SECONDARY_DNS)) requestedDNS[IPCP_OPTION_SECONDARY_DNS] = secondaryDNS;
      continue;
    }
    if (cp.code === 4) {
      var removedDNS = false;
      var rejectedAddress = false;
      for (var optionIndex = 0; optionIndex < options.length; optionIndex++) {
        var rejectedType = options[optionIndex].type;
        if (rejectedType === IPCP_OPTION_IP_ADDRESS) rejectedAddress = true;
        if (rejectedType === IPCP_OPTION_PRIMARY_DNS || rejectedType === IPCP_OPTION_SECONDARY_DNS) {
          enabledDNS[rejectedType] = false;
          removedDNS = true;
        }
      }
      if (removedDNS && !rejectedAddress) continue;
    }
    return last;
  }
  return last || {phase: 'timeout', requested_address: requestedIP};
}

function usableIPCPDNSServers(enabledDNS, primary, secondary) {
  var out = [];
  if (enabledDNS[IPCP_OPTION_PRIMARY_DNS] && primary && primary !== '0.0.0.0') out.push(primary);
  if (enabledDNS[IPCP_OPTION_SECONDARY_DNS] && secondary && secondary !== '0.0.0.0') out.push(secondary);
  return uniqueTextValues(out);
}

function runIPv6CP(profile, peerMAC, sessionID) {
  var iid = profile.ipv6_iid || crypto.randomBytes(8);
  profile.ipv6_iid = iid;
  var last = null;
  for (var attempt = 0; attempt < profile.max_frames; attempt++) {
    var identifier = randomByte();
    var req = cpPacket(1, identifier, cpOptionHex(IPV6CP_OPTION_INTERFACE_ID, iid));
    var frame = exchangePPPControl(profile, peerMAC, sessionID, PPP_IPV6CP, req);
    var result = completeCPNegotiation(profile, peerMAC, sessionID, PPP_IPV6CP, identifier, frame);
    if (result.timeout) return {phase: 'timeout', interface_id: iid};
    if (result.protocol !== PPP_IPV6CP) return {phase: 'unexpected_protocol', protocol: '0x' + u16hex(result.protocol), interface_id: iid};
    var cp = result.cp;
    var options = parseCPOptions(cp.data_hex);
    var suggested = firstCPHexOption(options, IPV6CP_OPTION_INTERFACE_ID);
    var effectiveIID = suggested || iid;
    last = {
      phase: cpCodeName(cp.code),
      up: cp.code === 2,
      code: cp.code,
      identifier: cp.identifier,
      interface_id: effectiveIID,
      link_local: linkLocalFromIID(effectiveIID),
      requested_interface_id: iid,
      attempts: attempt + 1
    };
    if (cp.code === 2 || cp.code === 4) {
      last.peer = ackPeerConfigureRequests(profile, peerMAC, sessionID, PPP_IPV6CP);
      return last;
    }
    if (cp.code === 3 && suggested) {
      iid = suggested;
      profile.ipv6_iid = iid;
      continue;
    }
    return last;
  }
  return last || {phase: 'timeout', interface_id: iid};
}

function requestIPv6Router(profile, peerMAC, sessionID) {
  var iid = profile.ipv6_iid || crypto.randomBytes(8);
  var src = linkLocalFromIID(iid);
  var dst = 'ff02::2';
  var packet = ipv6ICMP(src, dst, ICMPV6_ROUTER_SOLICIT, 0, '00000000', 255);
  var payload = pppoeSession(sessionID, u16hex(PPP_IPV6) + packet);
  var timeoutMs = clampInt(profile.ipv6_ra_timeout_ms, 500, 30000, 5000);
  var exchangeTimeoutMs = Math.min(timeoutMs, MAX_L2_RECV_TIMEOUT_MS);
  var deadline = Date.now() + timeoutMs;
  var frames = [];
  if (net.l2.exchangeMany) {
    frames = net.l2.exchangeMany(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: exchangeTimeoutMs,
      max_bytes: 1500,
      max_frames: Math.min(Math.max(profile.max_frames * 4, 8), 32),
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, peerMAC, sessionID, profile)) || [];
  } else {
    var first = net.l2.exchange(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: exchangeTimeoutMs,
      max_bytes: 1500
    }, peerMAC, sessionID, profile));
    if (first !== null) frames = [first];
  }
  var result = findIPv6RouterAdvertisement(frames, sessionID, iid);
  if (result) return result;

  while (Date.now() < deadline) {
    var remaining = Math.max(1, Math.min(timeoutMs, deadline - Date.now()));
    frames = recvPPPSessionFrames(profile, remaining, Math.min(Math.max(profile.max_frames * 4, 8), 32), peerMAC, sessionID);
    if (!frames.length) break;
    result = findIPv6RouterAdvertisement(frames, sessionID, iid);
    if (result) return result;
  }
  return {phase: 'timeout', source: src};
}

function findIPv6RouterAdvertisement(frames, sessionID, iid) {
  for (var i = 0; i < frames.length; i++) {
    var parsed;
    try {
      parsed = parseSessionFrame(frames[i]);
    } catch (e) {
      continue;
    }
    if (parsed.session_id !== sessionID || parsed.protocol !== PPP_IPV6) continue;
    var packet = parseIPv6ICMP(parsed.payload);
    if (!packet || packet.type !== ICMPV6_ROUTER_ADVERT) continue;
    return parseIPv6RouterAdvertisement(packet, iid);
  }
  return null;
}

function parseIPv6RouterAdvertisement(packet, iid) {
  var bytes = hexToBytes(packet.body_hex);
  if (bytes.length < 12) return {phase: 'invalid', message: 'router advertisement is truncated'};
  var routerLifetime = u16(bytes, 2);
  var prefixes = [];
  var dnsServers = [];
  var pos = 12;
  while (pos + 2 <= bytes.length) {
    var type = bytes[pos];
    var length = bytes[pos + 1] * 8;
    if (length < 8 || pos + length > bytes.length) break;
    if (type === ND_OPT_PREFIX_INFORMATION && length >= 32) {
      var prefixLength = bytes[pos + 2];
      var flags = bytes[pos + 3];
      var prefix = ipv6BytesToText(bytes.slice(pos + 16, pos + 32));
      prefixes.push({
        prefix: prefix + '/' + prefixLength,
        prefix_length: prefixLength,
        on_link: (flags & 0x80) !== 0,
        autonomous: (flags & 0x40) !== 0,
        valid_lifetime: u32(bytes, pos + 4),
        preferred_lifetime: u32(bytes, pos + 8),
        prefix_hex: bytesToHex(bytes.slice(pos + 16, pos + 32))
      });
    } else if (type === ND_OPT_RDNSS && length >= 24) {
      for (var dnsPos = pos + 8; dnsPos + 16 <= pos + length; dnsPos += 16) {
        dnsServers.push(ipv6BytesToText(bytes.slice(dnsPos, dnsPos + 16)));
      }
    }
    pos += length;
  }
  var selected = null;
  for (var i = 0; i < prefixes.length; i++) {
    if (prefixes[i].autonomous && prefixes[i].prefix_length === 64) {
      selected = prefixes[i];
      break;
    }
  }
  return {
    phase: selected ? 'router_advertisement' : 'router_advertisement_no_slaac',
    router: packet.src,
    router_lifetime: routerLifetime,
    managed: (bytes[1] & 0x80) !== 0,
    other_config: (bytes[1] & 0x40) !== 0,
    prefix: selected ? selected.prefix : '',
    prefixes: prefixes,
    address: selected ? slaacAddress(selected.prefix_hex, selected.prefix_length, iid) : '',
    dns_servers: uniqueTextValues(dnsServers)
  };
}

function requestDHCPv6PD(profile, peerMAC, sessionID, localMAC) {
  if (profile.dhcpv6_settle_ms > 0) {
    servicePPPControlWindow(profile, peerMAC, sessionID, profile.dhcpv6_settle_ms, null);
  }
  var xid = crypto.randomBytes(3);
  var iid = profile.ipv6_iid || crypto.randomBytes(8);
  var src = linkLocalFromIID(iid);
  var dst = 'ff02::1:2';
  var clientID = dhcpv6ClientIDValue(localMAC || '02:00:00:00:00:01');
  var dhcp = dhcpv6Solicit(xid, clientID, profile.dhcpv6_iaid, profile.request_ipv6_address, profile.request_pd);
  var frame = exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, dhcp, xid);
  if (frame === null) return {phase: 'timeout', transaction_id: xid};
  var parsedReply = parseDHCPv6ReplyFrame(frame, xid);
  if (parsedReply.error) return parsedReply.error;
  var reply = parsedReply.reply;
  var offered = dhcpv6LeaseData(reply.options);
  var result = merge({
    phase: dhcpv6MessagePhase(reply.message_type),
    transaction_id: reply.transaction_id,
    server_id: firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_SERVERID)
  }, offered);
  if (reply.message_type !== DHCPV6_ADVERTISE || !profile.dhcpv6_request) return result;

  var serverID = firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_SERVERID);
  var iaNA = firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_IA_NA);
  var iaPD = firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_IA_PD);
  if (!serverID || (!iaNA && !iaPD)) return merge(result, {phase: 'advertise_incomplete'});
  var requestXID = crypto.randomBytes(3);
  var request = dhcpv6Request(requestXID, clientID, serverID, iaNA, iaPD);
  var requestFrame = exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, request, requestXID);
  if (requestFrame === null) return merge(result, {phase: 'request_timeout', request_transaction_id: requestXID});
  var parsedRequestReply = parseDHCPv6ReplyFrame(requestFrame, requestXID);
  if (parsedRequestReply.error) return merge(result, parsedRequestReply.error);
  var finalReply = parsedRequestReply.reply;
  var leased = dhcpv6LeaseData(finalReply.options);
  return {
    phase: dhcpv6MessagePhase(finalReply.message_type),
    transaction_id: finalReply.transaction_id,
    advertise_transaction_id: reply.transaction_id,
    server_id: firstDHCPv6OptionHex(finalReply.options, DHCPV6_OPT_SERVERID) || serverID,
    address: leased.address || offered.address || '',
    addresses: leased.addresses.length ? leased.addresses : offered.addresses,
    advertise_addresses: offered.addresses,
    prefix: leased.prefix || offered.prefix || '',
    prefixes: leased.prefixes.length ? leased.prefixes : offered.prefixes,
    advertise_prefixes: offered.prefixes,
    dns_servers: leased.dns_servers.length ? leased.dns_servers : offered.dns_servers
  };
}

function ackPeerConfigureRequests(profile, peerMAC, sessionID, protocol) {
  var acked = 0;
  var targetAcked = 0;
  var skipped = 0;
  var drainTimeout = clampInt(profile.peer_ack_timeout_ms, 10, 250, profile.control_ack_timeout_ms);
  var frames = recvPPPSessionFrames(profile, drainTimeout, Math.min(profile.max_frames, 6), peerMAC, sessionID);
  if (!frames.length) return {phase: 'timeout', acked: acked, target_acked: targetAcked, skipped: skipped};
  for (var i = 0; i < frames.length && i < Math.min(profile.max_frames * 2, 16); i++) {
    var event = servicePPPControlFrame(profile, peerMAC, sessionID, frames[i], {});
    appendControlEventFrames(frames, event);
    if (event.event === 'configure_ack_sent') {
      acked++;
      if (event.protocol === pppControlProtocolName(protocol)) targetAcked++;
      continue;
    }
    if (event.protocol !== pppControlProtocolName(protocol)) {
      skipped++;
      continue;
    }
    if (event.code !== 1) return {phase: 'complete', acked: acked, target_acked: targetAcked, code: event.code, identifier: event.identifier, skipped: skipped};
  }
  return {phase: acked ? 'acked' : 'drained', acked: acked, target_acked: targetAcked, skipped: skipped};
}

function serviceSessionControlTimer(payload) {
  var profile = loadProfile(payload);
  resolveL2Identity(profile);
  var sessionID = clampInt(payload.session_id, 1, 65535, 0);
  var peerMAC = macText(payload.ac_mac || payload.peer_mac || '');
  if (!sessionID || !peerMAC) throw new Error('session_control timer requires session_id and ac_mac');
  var deadline = timestampMs(payload.deadline_ms);
  var remaining = deadline > 0 ? Math.max(0, deadline - Date.now()) : clampInt(payload.remaining_ms, 0, 10000, 0);
  if (remaining <= 0) return;
  var slice = clampInt(payload.slice_ms, 10, 1500, Math.min(remaining, Math.max(50, profile.timeout_ms)));
  if (slice > remaining) slice = remaining;

  var started = Date.now();
  var result = servicePPPControlWindow(profile, peerMAC, sessionID, slice, null);
  var elapsed = Math.max(slice, Date.now() - started);
  var nextRemaining = Math.max(0, remaining - elapsed);
  result.remaining_ms = nextRemaining;
  result.session_id = sessionID;
  result.ac_mac = peerMAC;
  result.updated_at = new Date().toISOString();

  var current = resources.get('sessions', 'control');
  var currentData = current && current.data ? current.data : null;
  var merged = mergeControlWindowResult(currentData, result);
  resources.set('sessions', 'control', merged);

  var last = resources.get('sessions', 'last');
  if (last && last.data && clampInt(last.data.session_id, 1, 65535, 0) === sessionID) {
    resources.set('sessions', 'last', merge(last.data, {
      post_session_control: merged,
      post_session_control_armed: nextRemaining > 0
    }));
  }
  if (nextRemaining > 0) {
    var next = merge(payload, {remaining_ms: nextRemaining});
    timer.setTimeout('session_control', Math.min(50, nextRemaining), next);
  } else {
    timer.clear('session_control');
  }
}

function mergeControlWindowResult(previous, next) {
  if (!previous || previous.session_id !== next.session_id) {
    return next;
  }
  var out = merge(previous, {
    phase: next.remaining_ms > 0 ? 'active' : next.phase,
    remaining_ms: next.remaining_ms,
    session_id: next.session_id,
    ac_mac: next.ac_mac,
    updated_at: next.updated_at
  });
  out.duration_ms = clampInt(previous.duration_ms, 0, 600000, 0) + clampInt(next.duration_ms, 0, 600000, 0);
  out.polls = clampInt(previous.polls, 0, 1000000, 0) + clampInt(next.polls, 0, 1000000, 0);
  out.frames = clampInt(previous.frames, 0, 1000000, 0) + clampInt(next.frames, 0, 1000000, 0);
  out.skipped = clampInt(previous.skipped, 0, 1000000, 0) + clampInt(next.skipped, 0, 1000000, 0);
  out.timeouts = clampInt(previous.timeouts, 0, 1000000, 0) + clampInt(next.timeouts, 0, 1000000, 0);
  out.parse_errors = clampInt(previous.parse_errors, 0, 1000000, 0) + clampInt(next.parse_errors, 0, 1000000, 0);
  out.configure_acks_sent = clampInt(previous.configure_acks_sent, 0, 1000000, 0) + clampInt(next.configure_acks_sent, 0, 1000000, 0);
  out.echo_replies_sent = clampInt(previous.echo_replies_sent, 0, 1000000, 0) + clampInt(next.echo_replies_sent, 0, 1000000, 0);
  out.terminate_acks_sent = clampInt(previous.terminate_acks_sent, 0, 1000000, 0) + clampInt(next.terminate_acks_sent, 0, 1000000, 0);
  out.lcp_echo_reply = !!previous.lcp_echo_reply || !!next.lcp_echo_reply;
  out.lcp_echo_code = next.lcp_echo_code || previous.lcp_echo_code || 0;
  out.events = (previous.events || []).concat(next.events || []);
  if (out.events.length > 24) out.events = out.events.slice(out.events.length - 24);
  return out;
}

function servicePPPControlWindow(profile, peerMAC, sessionID, durationMs, expected) {
  durationMs = clampInt(durationMs, 0, 10000, 0);
  expected = expected || {};
  var deadline = Date.now() + durationMs;
  var maxPolls = clampInt(profile.control_max_polls, 1, 128, Math.max(4, profile.max_frames * 8));
  var out = newPPPControlWindowResult(durationMs);
  if (durationMs <= 0) return out;

  for (var i = 0; i < maxPolls && Date.now() < deadline; i++) {
    var timeout = Math.min(profile.timeout_ms, Math.max(1, deadline - Date.now()));
    out.polls++;
    var frames = recvPPPSessionFrames(profile, timeout, Math.min(8, Math.max(1, maxPolls - i)), peerMAC, sessionID);
    if (!frames.length) {
      out.timeouts++;
      continue;
    }
    if (consumePPPControlFrames(profile, peerMAC, sessionID, frames, expected, out)) return out;
  }

  finishPPPControlWindowResult(out, expected);
  return out;
}

function newPPPControlWindowResult(durationMs) {
  return {
    phase: 'drained',
    duration_ms: durationMs,
    polls: 0,
    frames: 0,
    skipped: 0,
    timeouts: 0,
    parse_errors: 0,
    configure_acks_sent: 0,
    echo_replies_sent: 0,
    terminate_acks_sent: 0,
    lcp_echo_reply: false,
    lcp_echo_code: 0,
    events: []
  };
}

function consumePPPControlFrames(profile, peerMAC, sessionID, frames, expected, out) {
  for (var j = 0; j < frames.length && j < 64; j++) {
    out.frames++;
    var event = servicePPPControlFrame(profile, peerMAC, sessionID, frames[j], expected);
    appendControlEventFrames(frames, event);
    if (out.events.length < 16) out.events.push(event);
    if (event.event === 'configure_ack_sent') out.configure_acks_sent++;
    if (event.event === 'echo_reply_sent') out.echo_replies_sent++;
    if (event.event === 'terminate_ack_sent') {
      out.terminate_acks_sent++;
      out.phase = 'terminated';
      return true;
    }
    if (event.event === 'lcp_echo_reply') {
      out.lcp_echo_reply = true;
      out.lcp_echo_code = event.code;
      out.phase = 'echo_reply';
      return true;
    }
    if (event.event === 'skip' || event.event === 'skip_session' || event.event === 'skip_peer') out.skipped++;
    if (event.event === 'parse_error') out.parse_errors++;
  }
  return false;
}

function finishPPPControlWindowResult(out, expected) {
  if (expected.terminate_request && out.terminate_acks_sent === 0) {
    out.phase = 'terminate_timeout';
  } else if (expected.lcp_echo_identifier != null && !out.lcp_echo_reply) {
    out.phase = 'echo_timeout';
  } else if (out.frames === 0 && out.timeouts > 0) {
    out.phase = 'timeout';
  }
}

function recvPPPSessionFrames(profile, timeoutMs, maxFrames, peerMAC, sessionID) {
  timeoutMs = clampInt(timeoutMs, 1, MAX_L2_RECV_TIMEOUT_MS, profile.timeout_ms);
  maxFrames = clampInt(maxFrames, 1, 64, 1);
  if (net.l2.recvMany) {
    return net.l2.recvMany(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      timeout_ms: timeoutMs,
      max_bytes: 1500,
      max_frames: maxFrames,
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, peerMAC, sessionID, profile)) || [];
  }
  var frame = net.l2.recv(pppoeSessionRecvFilter({
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    timeout_ms: timeoutMs,
    max_bytes: 1500
  }, peerMAC, sessionID, profile));
  return frame === null ? [] : [frame];
}

function servicePPPControlFrame(profile, peerMAC, sessionID, frame, expected) {
  if (peerMAC && macText(frame.src_mac || '') !== peerMAC) {
    return {event: 'skip_peer', src_mac: frame.src_mac || ''};
  }
  var parsed;
  try {
    parsed = parseSessionFrame(frame);
  } catch (e) {
    return {event: 'parse_error', message: e && e.message ? e.message : String(e)};
  }
  if (parsed.session_id !== sessionID) {
    return {event: 'skip_session', session_id: parsed.session_id};
  }
  if (parsed.protocol !== PPP_LCP && parsed.protocol !== PPP_IPCP && parsed.protocol !== PPP_IPV6CP) {
    return {event: 'skip', protocol: '0x' + u16hex(parsed.protocol), length: parsed.payload.length / 2};
  }

  var cp = parseCP(parsed.payload);
  if (cp.code === 1) {
    var nextFrames = exchangePPPControlFrames(profile, peerMAC, sessionID, parsed.protocol, cpPacket(2, cp.identifier, cp.data_hex), profile.control_ack_timeout_ms, profile.max_frames);
    var ackEvent = {
      event: 'configure_ack_sent',
      protocol: pppControlProtocolName(parsed.protocol),
      code: cp.code,
      identifier: cp.identifier
    };
    annotatePeerNetworkControl(parsed.protocol, cp, ackEvent, null);
    if (nextFrames.length === 1) ackEvent.next_frame = nextFrames[0];
    if (nextFrames.length > 1) ackEvent.next_frames = nextFrames;
    return ackEvent;
  }
  if (parsed.protocol === PPP_LCP && cp.code === 9) {
    sendPPPControl(profile, peerMAC, sessionID, PPP_LCP, cpPacket(10, cp.identifier, cp.data_hex));
    return {event: 'echo_reply_sent', protocol: 'lcp', code: cp.code, identifier: cp.identifier};
  }
  if (parsed.protocol === PPP_LCP && cp.code === 5) {
    sendPPPControl(profile, peerMAC, sessionID, PPP_LCP, cpPacket(6, cp.identifier, ''));
    return {event: 'terminate_ack_sent', protocol: 'lcp', code: cp.code, identifier: cp.identifier};
  }
  if (parsed.protocol === PPP_LCP && cp.code === 10 && expected.lcp_echo_identifier === cp.identifier) {
    return {event: 'lcp_echo_reply', protocol: 'lcp', code: cp.code, identifier: cp.identifier};
  }
  return {
    event: cpCodeName(cp.code),
    protocol: pppControlProtocolName(parsed.protocol),
    code: cp.code,
    identifier: cp.identifier
  };
}

function appendControlEventFrames(frames, event) {
  if (event.next_frame) {
    frames.push(event.next_frame);
    delete event.next_frame;
  }
  if (event.next_frames) {
    for (var i = 0; i < event.next_frames.length; i++) frames.push(event.next_frames[i]);
    delete event.next_frames;
  }
}

function sendPPPControl(profile, peerMAC, sessionID, protocol, cpPayload) {
  net.l2.send(applyL2IdentityToRequest(profile, {
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    dst_mac: peerMAC,
    payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload)
  }));
}

function pppControlProtocolName(protocol) {
  if (protocol === PPP_LCP) return 'lcp';
  if (protocol === PPP_IPCP) return 'ipcp';
  if (protocol === PPP_IPV6CP) return 'ipv6cp';
  return '0x' + u16hex(protocol);
}

function exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, dhcpPayload, transactionID) {
  var payload = pppoeSession(sessionID, u16hex(PPP_IPV6) + ipv6UDP(src, dst, 546, 547, dhcpPayload));
  var timeoutMs = clampInt(profile.dhcpv6_timeout_ms, 500, 30000, Math.max(profile.timeout_ms, 5000));
  var exchangeTimeoutMs = Math.min(timeoutMs, MAX_L2_RECV_TIMEOUT_MS);
  var deadline = Date.now() + timeoutMs;
  var firstFrames = [];
  if (net.l2.exchangeMany) {
    firstFrames = net.l2.exchangeMany(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: exchangeTimeoutMs,
      max_bytes: 1500,
      max_frames: Math.min(Math.max(profile.max_frames * 4, 8), 32),
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, peerMAC, sessionID, profile)) || [];
  } else {
    var firstFrame = net.l2.exchange(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: exchangeTimeoutMs,
      max_bytes: 1500
    }, peerMAC, sessionID, profile));
    if (firstFrame !== null) firstFrames = [firstFrame];
  }
  var matched = findDHCPv6ReplyFrame(firstFrames, sessionID, transactionID);
  if (matched !== null) return matched;

  while (Date.now() < deadline) {
    var remaining = Math.max(1, Math.min(timeoutMs, deadline - Date.now()));
    var frames = recvPPPSessionFrames(profile, remaining, Math.min(Math.max(profile.max_frames * 4, 8), 32), peerMAC, sessionID);
    if (!frames.length) break;
    matched = findDHCPv6ReplyFrame(frames, sessionID, transactionID);
    if (matched !== null) return matched;
  }
  return null;
}

function parseDHCPv6ReplyFrame(frame, transactionID) {
  var parsed = parseSessionFrame(frame);
  if (parsed.protocol !== PPP_IPV6) return {error: {phase: 'unexpected_protocol', protocol: '0x' + u16hex(parsed.protocol), transaction_id: transactionID}};
  var packet = parseIPv6UDP(parsed.payload);
  if (!packet || packet.dst_port !== 546) return {error: {phase: 'unexpected_packet', transaction_id: transactionID}};
  var reply = parseDHCPv6(packet.payload_hex);
  if (reply.transaction_id !== transactionID) {
    return {error: {phase: 'transaction_mismatch', transaction_id: transactionID, reply_transaction_id: reply.transaction_id}};
  }
  return {reply: reply};
}

function findDHCPv6ReplyFrame(frames, sessionID, transactionID) {
  for (var i = 0; i < frames.length; i++) {
    var parsed;
    try {
      parsed = parseSessionFrame(frames[i]);
    } catch (e) {
      continue;
    }
    if (parsed.session_id !== sessionID || parsed.protocol !== PPP_IPV6) continue;
    var packet = parseIPv6UDP(parsed.payload);
    if (!packet || packet.src_port !== 547 || packet.dst_port !== 546) continue;
    var reply = parseDHCPv6(packet.payload_hex);
    if (reply.transaction_id === transactionID) return frames[i];
  }
  return null;
}

function exchangePPPControl(profile, peerMAC, sessionID, protocol, cpPayload, timeoutMs) {
  var timeout = clampInt(timeoutMs, 1, MAX_L2_RECV_TIMEOUT_MS, profile.timeout_ms);
  return net.l2.exchange(pppoeSessionRecvFilter({
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    dst_mac: peerMAC,
    payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload),
    timeout_ms: timeout,
    max_bytes: 1500
  }, peerMAC, sessionID, profile));
}

function exchangePPPControlFrames(profile, peerMAC, sessionID, protocol, cpPayload, timeoutMs, maxFrames) {
  var timeout = clampInt(timeoutMs, 1, 5000, profile.timeout_ms);
  var frameLimit = clampInt(maxFrames, 1, 64, profile.max_frames);
  var deadline = Date.now() + timeout;
  var out = [];
  if (net.l2.exchangeMany) {
    appendMatchingSessionFrames(out, net.l2.exchangeMany(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload),
      timeout_ms: timeout,
      max_bytes: 1500,
      max_frames: Math.min(64, Math.max(frameLimit * 4, frameLimit)),
      idle_timeout_ms: profile.control_idle_timeout_ms
    }, peerMAC, sessionID, profile)) || [], peerMAC, sessionID, frameLimit);
    if (out.length >= frameLimit) return out;
    if (out.length > 0) return out;
    collectMatchingSessionFrames(profile, peerMAC, sessionID, deadline, frameLimit, out);
    return out;
  }
  var frame = exchangePPPControl(profile, peerMAC, sessionID, protocol, cpPayload, timeout);
  appendMatchingSessionFrames(out, frame === null ? [] : [frame], peerMAC, sessionID, frameLimit);
  if (out.length >= frameLimit) return out;
  if (out.length > 0) return out;
  collectMatchingSessionFrames(profile, peerMAC, sessionID, deadline, frameLimit, out);
  return out;
}

function collectMatchingSessionFrames(profile, peerMAC, sessionID, deadline, frameLimit, out) {
  while (Date.now() < deadline && out.length < frameLimit) {
    var timeout = Math.max(1, Math.min(profile.timeout_ms, deadline - Date.now()));
    var frames = recvPPPSessionFrames(profile, timeout, Math.min(64, Math.max((frameLimit - out.length) * 4, 4)), peerMAC, sessionID);
    if (!frames.length) break;
    appendMatchingSessionFrames(out, frames, peerMAC, sessionID, frameLimit);
  }
}

function appendMatchingSessionFrames(out, frames, peerMAC, sessionID, frameLimit) {
  var wantPeer = macText(peerMAC || '');
  for (var i = 0; i < frames.length && out.length < frameLimit; i++) {
    if (wantPeer && macText(frames[i].src_mac || '') !== wantPeer) continue;
    try {
      var parsed = parseSessionFrame(frames[i]);
      if (parsed.session_id !== sessionID) continue;
    } catch (e) {
      continue;
    }
    out.push(frames[i]);
  }
}

function completeCPNegotiation(profile, peerMAC, sessionID, protocol, identifier, firstFrame) {
  var frame = firstFrame;
  for (var i = 0; i < profile.max_frames; i++) {
    if (frame === null) return {timeout: true};
    var parsed = parseSessionFrame(frame);
    if (parsed.protocol !== protocol) return {protocol: parsed.protocol, cp: {code: 0, identifier: 0, data_hex: ''}};
    var cp = parseCP(parsed.payload);
    if (cp.code === 1) {
      frame = net.l2.exchange(pppoeSessionRecvFilter({
        interface: profile.interface,
        ethertype: ETH_P_PPP_SESS,
        dst_mac: peerMAC,
        payload: pppoeSession(sessionID, u16hex(protocol) + cpPacket(2, cp.identifier, cp.data_hex)),
        timeout_ms: profile.timeout_ms,
        max_bytes: 1500
      }, peerMAC, sessionID, profile));
      continue;
    }
    if (cp.identifier === identifier || cp.code === 3 || cp.code === 4) {
      return {protocol: protocol, cp: cp};
    }
    frame = net.l2.recv(pppoeSessionRecvFilter({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500
    }, peerMAC, sessionID, profile));
  }
  return {timeout: true};
}

function sendPADT(profile, peerMAC, sessionID, receiveMs) {
  var req = applyL2IdentityToRequest(profile, {
    interface: profile.interface,
    ethertype: ETH_P_PPP_DISC,
    dst_mac: peerMAC,
    payload: pppoeDiscovery(CODE_PADT, sessionID, [])
  });
  receiveMs = clampInt(receiveMs, 0, 2000, 0);
  if (receiveMs > 0 && net.l2.exchangeMany) {
    req.recv_ethertype = ETH_P_PPP_SESS;
    req.recv_src_mac = peerMAC;
    req.pppoe_code = 0;
    req.pppoe_session_id = sessionID;
    req.timeout_ms = receiveMs;
    req.max_bytes = 1500;
    req.max_frames = profile.max_frames;
    req.idle_timeout_ms = profile.control_idle_timeout_ms;
    return net.l2.exchangeMany(req) || [];
  }
  net.l2.send(req);
  return [];
}

function parseDiscoveryFrame(frame) {
  var bytes = hexToBytes(frame.payload_hex);
  if (bytes.length < 6 || bytes[0] !== 0x11) throw new Error('invalid PPPoE discovery frame');
  var length = u16(bytes, 4);
  var tags = [];
  var pos = 6;
  var end = Math.min(bytes.length, 6 + length);
  while (pos + 4 <= end) {
    var type = u16(bytes, pos);
    var size = u16(bytes, pos + 2);
    pos += 4;
    if (pos + size > end) break;
    tags.push({type: type, value_hex: bytesToHex(bytes.slice(pos, pos + size))});
    pos += size;
  }
  return {code: bytes[1], session_id: u16(bytes, 2), length: length, tags: tags};
}

function parseSessionFrame(frame) {
  var bytes = hexToBytes(frame.payload_hex);
  if (bytes.length < 8 || bytes[0] !== 0x11) throw new Error('invalid PPPoE session frame');
  var length = u16(bytes, 4);
  var payload = bytes.slice(6, Math.min(bytes.length, 6 + length));
  if (payload.length < 2) throw new Error('empty PPP session payload');
  return {
    session_id: u16(bytes, 2),
    protocol: u16(payload, 0),
    payload: bytesToHex(payload.slice(2))
  };
}

function parseCP(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  if (bytes.length < 4) return {code: 0, identifier: 0, length: 0, data_hex: ''};
  var length = Math.min(u16(bytes, 2), bytes.length);
  return {
    code: bytes[0],
    identifier: bytes[1],
    length: length,
    data_hex: bytesToHex(bytes.slice(4, length))
  };
}

function parseCPOptions(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  var out = [];
  var pos = 0;
  while (pos + 2 <= bytes.length) {
    var type = bytes[pos];
    var len = bytes[pos + 1];
    if (len < 2 || pos + len > bytes.length) break;
    out.push({type: type, length: len, value_hex: bytesToHex(bytes.slice(pos + 2, pos + len))});
    pos += len;
  }
  return out;
}

function firstCPHexOption(options, type) {
  for (var i = 0; i < options.length; i++) {
    if (options[i].type === type) return options[i].value_hex;
  }
  return '';
}

function firstCPIPv4Option(options, type) {
  var value = firstCPHexOption(options, type);
  var bytes = hexToBytes(value);
  if (bytes.length < 4) return '';
  return [bytes[0], bytes[1], bytes[2], bytes[3]].join('.');
}

function cpCodeName(code) {
  if (code === 1) return 'configure_request';
  if (code === 2) return 'configure_ack';
  if (code === 3) return 'configure_nak';
  if (code === 4) return 'configure_reject';
  if (code === 5) return 'terminate_request';
  if (code === 6) return 'terminate_ack';
  if (code === 9) return 'echo_request';
  if (code === 10) return 'echo_reply';
  return 'code_' + code;
}

function pppoeDiscovery(code, sessionID, tags) {
  var body = (tags || []).join('');
  return '11' + hexByte(code) + u16hex(sessionID) + u16hex(body.length / 2) + body;
}

function pppoeSession(sessionID, payloadHex) {
  return '1100' + u16hex(sessionID) + u16hex(payloadHex.length / 2) + payloadHex;
}

function cpPacket(code, identifier, dataHex) {
  dataHex = dataHex || '';
  return hexByte(code) + hexByte(identifier) + u16hex(4 + dataHex.length / 2) + dataHex;
}

function tagString(type, value) {
  return tagHex(type, stringHex(value || ''));
}

function tagHex(type, valueHex) {
	valueHex = valueHex || '';
	return u16hex(type) + u16hex(valueHex.length / 2) + valueHex;
}

function cpOptionU16(type, value) {
	return cpOptionHex(type, u16hex(value));
}

function cpOptionIPv4(type, value) {
  var parts = String(value || '0.0.0.0').split('.');
  var hex = '';
  for (var i = 0; i < 4; i++) hex += hexByte(parseInt(parts[i] || '0', 10));
  return cpOptionHex(type, hex);
}

function cpOptionHex(type, valueHex) {
	valueHex = valueHex || '';
	return hexByte(type) + hexByte(2 + valueHex.length / 2) + valueHex;
}

function appendForwardedTag(out, discovery, type) {
  for (var i = 0; i < discovery.tags.length; i++) {
    if (discovery.tags[i].type === type) out.push(tagHex(type, discovery.tags[i].value_hex));
  }
}

function firstTagText(discovery, type) {
  for (var i = 0; i < discovery.tags.length; i++) {
    if (discovery.tags[i].type === type) return hexToString(discovery.tags[i].value_hex);
  }
  return '';
}

function firstTagHex(discovery, type) {
  for (var i = 0; i < discovery.tags.length; i++) {
    if (discovery.tags[i].type === type) return discovery.tags[i].value_hex || '';
  }
  return '';
}

function tagSummary(tags) {
  var out = [];
  for (var i = 0; i < tags.length; i++) {
    out.push({
      type: '0x' + u16hex(tags[i].type),
      bytes: tags[i].value_hex.length / 2,
      text: hexToPrintable(tags[i].value_hex)
    });
  }
  return out;
}

function dhcpv6ClientIDValue(mac) {
  return '00030001' + macHex(mac || '02:00:00:00:00:01');
}

function dhcpv6Solicit(xid, clientIDValue, iaid, requestAddress, requestPD) {
  var clientID = dhcpv6Option(DHCPV6_OPT_CLIENTID, clientIDValue);
  var elapsed = dhcpv6Option(DHCPV6_OPT_ELAPSED_TIME, '0000');
  var oro = dhcpv6ORO();
  var reconfigure = dhcpv6Option(DHCPV6_OPT_RECONF_ACCEPT, '');
  var fqdn = dhcpv6ClientFQDN('OpenWrt');
  var identities = '';
  if (requestAddress) identities += dhcpv6Option(DHCPV6_OPT_IA_NA, u32hex(iaid) + u32hex(0) + u32hex(0));
  if (requestPD) identities += dhcpv6Option(DHCPV6_OPT_IA_PD, u32hex(iaid) + u32hex(0) + u32hex(0));
  return hexByte(DHCPV6_SOLICIT) + xid + elapsed + oro + clientID + reconfigure + fqdn + identities;
}

function dhcpv6Request(xid, clientIDValue, serverIDValue, iaNAValue, iaPDValue) {
  var clientID = dhcpv6Option(DHCPV6_OPT_CLIENTID, clientIDValue);
  var serverID = dhcpv6Option(DHCPV6_OPT_SERVERID, serverIDValue);
  var elapsed = dhcpv6Option(DHCPV6_OPT_ELAPSED_TIME, '0000');
  var oro = dhcpv6ORO();
  var reconfigure = dhcpv6Option(DHCPV6_OPT_RECONF_ACCEPT, '');
  var fqdn = dhcpv6ClientFQDN('OpenWrt');
  var identities = '';
  if (iaNAValue) identities += dhcpv6Option(DHCPV6_OPT_IA_NA, iaNAValue);
  if (iaPDValue) identities += dhcpv6Option(DHCPV6_OPT_IA_PD, iaPDValue);
  return hexByte(DHCPV6_REQUEST) + xid + elapsed + oro + clientID + serverID + reconfigure + fqdn + identities;
}

function dhcpv6Option(code, valueHex) {
  valueHex = valueHex || '';
  return u16hex(code) + u16hex(valueHex.length / 2) + valueHex;
}

function dhcpv6ORO() {
  var codes = [21, 22, 23, 24, 31, 56, 64, 67, 94, 95, 96, 82];
  var out = '';
  for (var i = 0; i < codes.length; i++) out += u16hex(codes[i]);
  return dhcpv6Option(DHCPV6_OPT_ORO, out);
}

function dhcpv6ClientFQDN(name) {
  var labels = text(name || 'OpenWrt').split('.');
  var encoded = '00';
  for (var i = 0; i < labels.length; i++) {
    var label = stringHex(labels[i]);
    encoded += hexByte(label.length / 2) + label;
  }
  return dhcpv6Option(DHCPV6_OPT_CLIENT_FQDN, encoded + '00');
}

function dhcpv6MessagePhase(messageType) {
  if (messageType === DHCPV6_ADVERTISE) return 'advertise';
  if (messageType === DHCPV6_REPLY) return 'reply';
  return 'message_' + messageType;
}

function parseDHCPv6(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  if (bytes.length < 4) return {message_type: 0, transaction_id: '', options: []};
  return {
    message_type: bytes[0],
    transaction_id: bytesToHex(bytes.slice(1, 4)),
    options: parseDHCPv6Options(bytesToHex(bytes.slice(4)))
  };
}

function parseDHCPv6Options(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  var out = [];
  var pos = 0;
  while (pos + 4 <= bytes.length) {
    var code = u16(bytes, pos);
    var len = u16(bytes, pos + 2);
    pos += 4;
    if (pos + len > bytes.length) break;
    out.push({code: code, value_hex: bytesToHex(bytes.slice(pos, pos + len)), options: parseNestedDHCPv6Options(code, bytes.slice(pos, pos + len))});
    pos += len;
  }
  return out;
}

function parseNestedDHCPv6Options(code, valueBytes) {
  if ((code !== DHCPV6_OPT_IA_NA && code !== DHCPV6_OPT_IA_PD) || valueBytes.length < 12) return [];
  return parseDHCPv6Options(bytesToHex(valueBytes.slice(12)));
}

function firstDHCPv6OptionHex(options, code) {
  for (var i = 0; i < options.length; i++) {
    if (options[i].code === code) return options[i].value_hex;
  }
  return '';
}

function dhcpv6LeaseData(options) {
  var addresses = dhcpv6Addresses(options);
  var prefixes = dhcpv6Prefixes(options);
  return {
    address: addresses.length ? addresses[0].address : '',
    addresses: addresses,
    prefix: prefixes.length ? prefixes[0].prefix : '',
    prefixes: prefixes,
    dns_servers: dhcpv6DNSServers(options)
  };
}

function dhcpv6Addresses(options) {
  var out = [];
  for (var i = 0; i < options.length; i++) {
    var option = options[i];
    if (option.code !== DHCPV6_OPT_IA_NA) continue;
    var nested = option.options || [];
    for (var j = 0; j < nested.length; j++) {
      if (nested[j].code !== DHCPV6_OPT_IAADDR) continue;
      var bytes = hexToBytes(nested[j].value_hex);
      if (bytes.length < 24) continue;
      out.push({
        address: ipv6BytesToText(bytes.slice(0, 16)),
        preferred_lifetime: u32(bytes, 16),
        valid_lifetime: u32(bytes, 20)
      });
    }
  }
  return out;
}

function dhcpv6DNSServers(options) {
  var out = [];
  for (var i = 0; i < options.length; i++) {
    if (options[i].code !== DHCPV6_OPT_DNS_SERVERS) continue;
    var bytes = hexToBytes(options[i].value_hex);
    for (var pos = 0; pos + 16 <= bytes.length; pos += 16) {
      out.push(ipv6BytesToText(bytes.slice(pos, pos + 16)));
    }
  }
  return out;
}

function dhcpv6Prefixes(options) {
  var out = [];
  for (var i = 0; i < options.length; i++) {
    var option = options[i];
    if (option.code !== DHCPV6_OPT_IA_PD) continue;
    var nested = option.options || [];
    for (var j = 0; j < nested.length; j++) {
      if (nested[j].code !== DHCPV6_OPT_IAPREFIX) continue;
      var bytes = hexToBytes(nested[j].value_hex);
      if (bytes.length < 25) continue;
      var preferred = u32(bytes, 0);
      var valid = u32(bytes, 4);
      var prefixLen = bytes[8];
      var prefix = ipv6BytesToText(bytes.slice(9, 25));
      out.push({prefix: prefix + '/' + prefixLen, preferred_lifetime: preferred, valid_lifetime: valid});
    }
  }
  return out;
}

function ipv6UDP(src, dst, srcPort, dstPort, payloadHex) {
  var srcHex = ipv6TextToHex(src);
  var dstHex = ipv6TextToHex(dst);
  var payloadLen = payloadHex.length / 2;
  var udpLen = 8 + payloadLen;
  var udpNoChecksum = u16hex(srcPort) + u16hex(dstPort) + u16hex(udpLen) + '0000' + payloadHex;
  var checksum = ipv6UDPChecksum(srcHex, dstHex, udpNoChecksum, udpLen);
  var udp = u16hex(srcPort) + u16hex(dstPort) + u16hex(udpLen) + u16hex(checksum) + payloadHex;
  return '60000000' + u16hex(udpLen) + '11' + '01' + srcHex + dstHex + udp;
}

function ipv6ICMP(src, dst, type, code, bodyHex, hopLimit) {
  var srcHex = ipv6TextToHex(src);
  var dstHex = ipv6TextToHex(dst);
  bodyHex = bodyHex || '';
  var payload = hexByte(type) + hexByte(code) + '0000' + bodyHex;
  var payloadLen = payload.length / 2;
  var checksum = ipv6TransportChecksum(srcHex, dstHex, 58, payload, payloadLen);
  payload = hexByte(type) + hexByte(code) + u16hex(checksum) + bodyHex;
  return '60000000' + u16hex(payloadLen) + '3a' + hexByte(clampInt(hopLimit, 1, 255, 255)) + srcHex + dstHex + payload;
}

function parseIPv6UDP(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  if (bytes.length < 48 || (bytes[0] >> 4) !== 6 || bytes[6] !== 17) return null;
  var payloadLen = u16(bytes, 4);
  var srcPort = u16(bytes, 40);
  var dstPort = u16(bytes, 42);
  var udpLen = u16(bytes, 44);
  var end = Math.min(bytes.length, 40 + Math.min(payloadLen, udpLen));
  if (end < 48) return null;
  return {
    src: ipv6BytesToText(bytes.slice(8, 24)),
    dst: ipv6BytesToText(bytes.slice(24, 40)),
    src_port: srcPort,
    dst_port: dstPort,
    payload_hex: bytesToHex(bytes.slice(48, end))
  };
}

function parseIPv6ICMP(payloadHex) {
  var bytes = hexToBytes(payloadHex);
  if (bytes.length < 44 || (bytes[0] >> 4) !== 6 || bytes[6] !== 58) return null;
  var payloadLen = u16(bytes, 4);
  var end = Math.min(bytes.length, 40 + payloadLen);
  if (end < 44) return null;
  return {
    src: ipv6BytesToText(bytes.slice(8, 24)),
    dst: ipv6BytesToText(bytes.slice(24, 40)),
    type: bytes[40],
    code: bytes[41],
    body_hex: bytesToHex(bytes.slice(44, end))
  };
}

function ipv6UDPChecksum(srcHex, dstHex, udpHex, udpLen) {
  var pseudo = srcHex + dstHex + u32hex(udpLen) + '00000011' + udpHex;
  return onesComplementChecksum(hexToBytes(pseudo));
}

function ipv6TransportChecksum(srcHex, dstHex, nextHeader, payloadHex, payloadLen) {
  var pseudo = srcHex + dstHex + u32hex(payloadLen) + '000000' + hexByte(nextHeader) + payloadHex;
  return onesComplementChecksum(hexToBytes(pseudo));
}

function onesComplementChecksum(bytes) {
  var sum = 0;
  for (var i = 0; i < bytes.length; i += 2) {
    var word = (bytes[i] << 8) + (bytes[i + 1] || 0);
    sum += word;
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >> 16);
  }
  return (~sum) & 0xffff;
}

function linkLocalFromIID(iid) {
  iid = iidHex(iid || crypto.randomBytes(8));
  return ipv6BytesToText(hexToBytes('fe80000000000000' + iid));
}

function slaacAddress(prefixHex, prefixLength, iid) {
  prefixHex = lower(prefixHex);
  iid = iidHex(iid || '');
  if (prefixLength !== 64 || prefixHex.length !== 32 || !iid) return '';
  return ipv6BytesToText(hexToBytes(prefixHex.slice(0, 16) + iid));
}

function ipv6TextToHex(value) {
  value = lower(value);
  if (value === 'ff02::1:2') return 'ff020000000000000000000000010002';
  if (value === 'ff02::2') return 'ff020000000000000000000000000002';
  if (value.indexOf('fe80::') === 0) {
    var suffix = value.slice('fe80::'.length).replace(/:/g, '');
    while (suffix.length < 16) suffix = '0' + suffix;
    return 'fe80000000000000' + suffix.slice(-16);
  }
  throw new Error('unsupported IPv6 literal in PPPoE helper: ' + value);
}

function ipv6BytesToText(bytes) {
  var parts = [];
  for (var i = 0; i < 16; i += 2) parts.push(((bytes[i] || 0) << 8 | (bytes[i + 1] || 0)).toString(16));
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

function baseResult(profile, phase, extra) {
  var out = {
    phase: phase,
    profile_key: profile.profile_key,
    interface: profile.interface,
    mac_mode: profile.mac_mode,
    mac_address: profile.mac_address || '',
    service: profile.service,
    auth: profile.auth,
    updated_at: new Date().toISOString()
  };
  return merge(out, extra || {});
}

function merge(a, b) {
  var out = {};
  var k;
  for (k in a) if (Object.prototype.hasOwnProperty.call(a, k)) out[k] = a[k];
  for (k in b) if (Object.prototype.hasOwnProperty.call(b, k)) out[k] = b[k];
  return out;
}

function token(value) {
  return lower(value || 'default').replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'default';
}

function lower(value) {
  return String(value == null ? '' : value).trim().toLowerCase();
}

function text(value) {
  return String(value == null ? '' : value).trim();
}

function uniqueTextValues(values) {
  var out = [];
  var seen = {};
  for (var i = 0; i < values.length; i++) {
    var value = text(values[i]);
    if (!value || seen[value]) continue;
    seen[value] = true;
    out.push(value);
  }
  return out;
}

function optionalIfaceName(value, label) {
  value = text(value);
  if (!value) return '';
  return ifaceName(value, label);
}

function uniqueInterfaces(values) {
  var out = [];
  var seen = {};
  for (var i = 0; i < values.length; i++) {
    var value = optionalIfaceName(values[i], 'interface');
    if (!value || seen[value]) continue;
    seen[value] = true;
    out.push(value);
  }
  return out;
}

function ifaceName(value, label) {
  value = text(value);
  if (!value || utf8ByteLength(value) > 15 || /[\/\\\s\u0000]/.test(value)) {
    throw new Error(label + ' contains invalid characters or exceeds 15 bytes');
  }
  return value;
}

function utf8ByteLength(value) {
  var n = 0;
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code <= 0x7f) n += 1;
    else if (code <= 0x7ff) n += 2;
    else if (code >= 0xd800 && code <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

function clampInt(value, min, max, fallback) {
  var n = parseInt(value, 10);
  if (!isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

function timestampMs(value) {
  var n = parseInt(value, 10);
  if (!isFinite(n) || n <= 0) return 0;
  return n;
}

function bool(value, fallback) {
  if (value === true || value === false) return value;
  if (value == null || value === '') return fallback;
  var normalized = lower(value);
  if (normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no' || normalized === 'off') return false;
  return fallback;
}

function hasOwn(obj, key) {
  return obj != null && Object.prototype.hasOwnProperty.call(obj, key);
}

function firstDefined() {
  for (var i = 0; i < arguments.length; i++) {
    if (arguments[i] !== undefined && arguments[i] !== null && arguments[i] !== '') return arguments[i];
  }
  return undefined;
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}

function repeatHex(value, count) {
  var out = '';
  for (var i = 0; i < count; i++) out += value;
  return out;
}

function macText(value) {
  value = text(value).toLowerCase();
  if (!value) return '';
  var hex = value.replace(/[^0-9a-f]/g, '');
  if (hex.length !== 12) throw new Error('invalid mac address ' + value);
  var out = [];
  for (var i = 0; i < 12; i += 2) out.push(hex.substr(i, 2));
  return out.join(':');
}

function macHex(value) {
  return macText(value).replace(/:/g, '');
}

function macBytesToText(bytes) {
  var out = [];
  for (var i = 0; i < 6; i++) out.push(hexByte(bytes[i] || 0));
  return out.join(':');
}

function randomByte() {
  return parseInt(crypto.randomBytes(1), 16);
}

function stringHex(value) {
  value = String(value == null ? '' : value);
  var out = '';
  for (var i = 0; i < value.length; i++) {
    var code = value.charCodeAt(i);
    if (code > 255) code = 63;
    out += hexByte(code);
  }
  return out;
}

function hexToString(hex) {
  var bytes = hexToBytes(hex);
  var out = '';
  for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return out;
}

function hexToPrintable(hex) {
  return hexToString(hex).replace(/[^\x20-\x7e]+/g, '.');
}

function hexToBytes(hex) {
  hex = String(hex || '').replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '');
  var out = [];
  for (var i = 0; i + 1 < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
  return out;
}

function bytesToHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) out += hexByte(bytes[i]);
  return out;
}

function u16(bytes, offset) {
  return ((bytes[offset] || 0) << 8) | (bytes[offset + 1] || 0);
}

function u32(bytes, offset) {
  return (((bytes[offset] || 0) << 24) >>> 0)
    + ((bytes[offset + 1] || 0) << 16)
    + ((bytes[offset + 2] || 0) << 8)
    + (bytes[offset + 3] || 0);
}

function u16le(bytes, offset) {
  return (bytes[offset] || 0) | ((bytes[offset + 1] || 0) << 8);
}

function u32le(bytes, offset) {
  return ((bytes[offset] || 0) >>> 0)
    + ((bytes[offset + 1] || 0) << 8)
    + ((bytes[offset + 2] || 0) << 16)
    + (((bytes[offset + 3] || 0) << 24) >>> 0);
}

function u16hex(value) {
  value = Number(value) & 0xffff;
  return hexByte(value >> 8) + hexByte(value);
}

function u32hex(value) {
  value = Number(value) >>> 0;
  return hexByte(value >> 24) + hexByte(value >> 16) + hexByte(value >> 8) + hexByte(value);
}

function u16lehex(value) {
  value = Number(value) & 0xffff;
  return hexByte(value) + hexByte(value >> 8);
}

function u32lehex(value) {
  value = Number(value) >>> 0;
  return hexByte(value) + hexByte(value >> 8) + hexByte(value >> 16) + hexByte(value >> 24);
}

function u64leNumber(hex) {
  var bytes = hexToBytes(hex);
  var out = 0;
  var mul = 1;
  for (var i = 0; i < bytes.length && i < 8; i++) {
    out += bytes[i] * mul;
    mul *= 256;
  }
  return out;
}

function hexByte(value) {
  value = Number(value) & 0xff;
  return (value < 16 ? '0' : '') + value.toString(16);
}

function iidHex(value) {
  value = String(value || '').replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (!value) return '';
  if (value.length !== 16) throw new Error('ipv6_iid must be 8 bytes');
  return value;
}
