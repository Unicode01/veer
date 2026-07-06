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
var IPCP_OPTION_IP_ADDRESS = 3;
var IPV6CP_OPTION_INTERFACE_ID = 1;
var DHCPV6_SOLICIT = 1;
var DHCPV6_ADVERTISE = 2;
var DHCPV6_REQUEST = 3;
var DHCPV6_REPLY = 7;
var DHCPV6_OPT_CLIENTID = 1;
var DHCPV6_OPT_SERVERID = 2;
var DHCPV6_OPT_ORO = 6;
var DHCPV6_OPT_ELAPSED_TIME = 8;
var DHCPV6_OPT_RECONF_ACCEPT = 20;
var DHCPV6_OPT_IA_PD = 25;
var DHCPV6_OPT_IAPREFIX = 26;
var DHCPV6_OPT_CLIENT_FQDN = 39;

exports.onReconcile = function () {
  // The lab plugin has no background state to reconcile; keep the hook explicit
  // so the runtime reports a clean control-plane status at startup.
};

exports.onTimer = function (ctx) {
  if (!ctx.timer) return;
  if (ctx.timer.name === 'session_control') {
    serviceSessionControlTimer(ctx.timer.payload || {});
    return;
  }
  if (ctx.timer.name !== 'lcp_echo') return;
  var payload = ctx.timer.payload || {};
  var profile = loadProfile(payload);
  var sessionID = clampInt(payload.session_id, 1, 65535, 0);
  var peerMAC = macText(payload.ac_mac || payload.peer_mac || '');
  if (!sessionID || !peerMAC) throw new Error('lcp_echo timer requires session_id and ac_mac');
  var result = sendLCPEcho(profile, peerMAC, sessionID);
  if (result.phase !== 'keepalive_ok' && profile.auto_redial) {
    result = redialAfterKeepaliveFailure(profile, result);
  }
  resources.set('sessions', 'keepalive', result);
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'clear_state') {
    var clearKey = token((ctx.payload || {}).profile_key || (ctx.payload || {}).profile || 'default');
    resources.delete('sessions', 'last');
    resources.delete('sessions', 'keepalive');
    resources.delete('sessions', 'control');
    resources.delete('wan_links', clearKey);
    timer.clear('lcp_echo');
    timer.clear('session_control');
    clearTunnelConfig();
    return;
  }

  var profile = loadProfile(ctx.payload || {});
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
    profile.install_tunnel = true;
    if (!hasOwn(ctx.payload || {}, 'send_padt')) profile.send_padt = false;
    var tunnelSession = probeSession(profile);
    recordSession(profile, tunnelSession);
    armSessionControl(profile, tunnelSession);
    return;
  }
  if (action === 'dial') {
    if (!hasOwn(ctx.payload || {}, 'send_padt')) profile.send_padt = false;
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
  profile.interface = text(profile.interface || profile.iface || '');
  if (!profile.interface) throw new Error('interface is required');
  profile.username = text(profile.username || '');
  profile.password = text(profile.password || '');
  profile.service = text(profile.service || '');
  profile.ac_name = text(profile.ac_name || '');
  profile.auth = lower(profile.auth || 'pap');
  profile.timeout_ms = clampInt(profile.timeout_ms, 50, 1500, 700);
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
  profile.max_frames = clampInt(profile.max_frames, 1, 8, 4);
  profile.mru = clampInt(profile.mru, 576, 1492, 1492);
  profile.negotiate_ipv4 = bool(firstDefined(profile.negotiate_ipv4, profile.ipcp, profile.ipv4), true);
  profile.negotiate_ipv6 = bool(firstDefined(profile.negotiate_ipv6, profile.ipv6cp, profile.ipv6), false);
  profile.request_pd = bool(firstDefined(profile.request_pd, profile.ipv6_pd, profile.pd), false);
  if (profile.request_pd) profile.negotiate_ipv6 = true;
  profile.ipv6_iid = iidHex(profile.ipv6_iid || profile.interface_id || '');
  profile.dhcpv6_iaid = clampInt(profile.dhcpv6_iaid || profile.iaid, 0, 0xffffffff, 1);
  profile.dhcpv6_request = bool(firstDefined(profile.dhcpv6_request, profile.request_dhcpv6_reply), true);
  profile.dhcpv6_settle_ms = clampInt(firstDefined(profile.dhcpv6_settle_ms, profile.dhcpv6_delay_ms), 0, 5000, 600);
  profile.keepalive_interval_ms = clampInt(profile.keepalive_interval_ms, 0, 86400000, 0);
  profile.auto_redial = bool(firstDefined(profile.auto_redial, profile.redial, profile.reconnect, profile.reconnect_on_timeout), false);
  profile.redial_clear_tunnel = bool(firstDefined(profile.redial_clear_tunnel, profile.clear_tunnel_on_redial), true);
  profile.install_tunnel = bool(profile.install_tunnel, false);
  profile.post_session_control_ms = clampInt(
    firstDefined(profile.post_session_control_ms, profile.post_dial_control_ms, profile.control_drain_ms),
    0,
    10000,
    profile.install_tunnel ? 3000 : 0
  );
  profile.coupled = bool(profile.coupled || profile.forward_coupled, false);
  profile.send_padt = bool(profile.send_padt, true);
  profile.lan_interface = text(profile.lan_interface || profile.lan_if || profile.lan || profile.vtap_interface || profile.vtap || '');
  profile.lan_peer_interface = text(profile.lan_peer_interface || profile.local_interface || profile.host_interface || profile.host || '');
  profile.wan_interface = text(profile.wan_interface || profile.wan_if || profile.wan || profile.interface || '');
  profile.lan_ifindex = clampInt(profile.lan_ifindex, 0, 2147483647, 0);
  profile.wan_ifindex = clampInt(profile.wan_ifindex, 0, 2147483647, 0);
  profile.lan_src_mac = macText(profile.lan_src_mac || profile.lan_mac || '');
  profile.lan_dst_mac = macText(profile.lan_dst_mac || profile.client_mac || '');
  profile.wan_src_mac = macText(profile.wan_src_mac || '');
  profile.wan_dst_mac = macText(profile.wan_dst_mac || profile.ac_mac || '');
  profile.wan_core_sync = bool(firstDefined(profile.wan_core_sync, profile.sync_wan_core), true);
  profile.wan_core_apply = bool(firstDefined(profile.wan_core_apply, profile.apply_wan_core), true);
  profile.wan_core_plugin = token(profile.wan_core_plugin || profile.wan_core_plugin_id || 'wan_core');
  return profile;
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

  var padsFrame = net.l2.exchange({
    interface: profile.interface,
    ethertype: ETH_P_PPP_DISC,
    dst_mac: padoFrame.src_mac,
    payload: pppoeDiscovery(CODE_PADR, 0, padrTags),
    timeout_ms: profile.timeout_ms,
    max_bytes: 1500
  });
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
    if (!lcpReadyForNetworkCP(profile, frames)) throw new Error('cannot install tunnel before LCP/auth is ready');
    tunnel = installTunnel(profile, padsFrame, pads.session_id);
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
    dhcpv6_pd: frames.dhcpv6_pd,
    frames: frames.items,
    post_session_control_armed: !profile.send_padt && profile.post_session_control_ms > 0,
    padt_sent: profile.send_padt,
    tunnel_installed: tunnel !== null,
    tunnel: tunnel
  });
}

function installTunnel(profile, padsFrame, sessionID) {
  var lanLink = profile.lan_interface ? net.link.get(profile.lan_interface) : null;
  var lanPeerLink = profile.lan_peer_interface ? net.link.get(profile.lan_peer_interface) : null;
  var wanLink = profile.wan_interface ? net.link.get(profile.wan_interface) : null;
  var lanIfIndex = profile.lan_ifindex || (lanLink && lanLink.ifindex) || 0;
  var wanIfIndex = profile.wan_ifindex || (wanLink && wanLink.ifindex) || padsFrame.ifindex || 0;
  var lanSrcMAC = profile.lan_src_mac || (lanLink && lanLink.mac) || '';
  var lanDstMAC = profile.lan_dst_mac || (lanPeerLink && lanPeerLink.mac) || '';
  var wanSrcMAC = profile.wan_src_mac || (wanLink && wanLink.mac) || padsFrame.dst_mac || '';
  var wanDstMAC = profile.wan_dst_mac || padsFrame.src_mac || '';
  if (!lanIfIndex) throw new Error('lan_ifindex or lan_interface is required to install the TC tunnel');
  if (!wanIfIndex) throw new Error('wan_ifindex is required to install the TC tunnel');
  if (!lanSrcMAC) throw new Error('lan_src_mac or lan_interface mac is required to install the TC tunnel');
  if (!lanDstMAC) throw new Error('lan_dst_mac/client_mac or lan_peer_interface mac is required to install the TC tunnel');
  if (!wanSrcMAC) throw new Error('wan_src_mac is required to install the TC tunnel');
  if (!wanDstMAC) throw new Error('wan_dst_mac/ac_mac is required to install the TC tunnel');

  var flags = profile.coupled ? 1 : 0;
  var value = ''
    + u32lehex(1)
    + u32lehex(lanIfIndex)
    + u32lehex(wanIfIndex)
    + u16lehex(sessionID)
    + u16lehex(flags)
    + macHex(lanSrcMAC)
    + macHex(lanDstMAC)
    + macHex(wanSrcMAC)
    + macHex(wanDstMAC);
  ebpf.mapPut('pppoe_tunnel', 'pppoe_tunnel_config', u32lehex(0), value);
  return {
    object: 'pppoe_tunnel',
    map: 'pppoe_tunnel_config',
    mode: profile.coupled ? 'coupled_fvtap' : 'direct_vtap',
    requires_kernel_tc_prepared_l2: false,
    prepared_l2_note: profile.coupled ? 'coupled fvtap mode works without kernel_tc_prepared_l2; enabling prepared_l2 only changes fvtap core egress to static ifindex/MAC redirect and should be used when neighbor MACs are stable' : 'direct vtap mode bypasses fvtap core redirect and does not use kernel_tc_prepared_l2',
    lan_interface: profile.lan_interface,
    lan_peer_interface: profile.lan_peer_interface,
    wan_interface: profile.wan_interface,
    lan_ifindex: lanIfIndex,
    wan_ifindex: wanIfIndex,
    lan_src_mac: lanSrcMAC,
    lan_dst_mac: lanDstMAC,
    wan_src_mac: wanSrcMAC,
    wan_dst_mac: wanDstMAC,
    coupled: profile.coupled
  };
}

function clearTunnelConfig() {
  try {
    ebpf.mapPut('pppoe_tunnel', 'pppoe_tunnel_config', u32lehex(0), repeatHex('00', 40));
  } catch (e) {
    log.info('pppoe tunnel config clear skipped: ' + (e && e.message ? e.message : String(e)));
  }
}

function sendPADI(profile, hostUniq) {
	var padi = pppoeDiscovery(CODE_PADI, 0, [
		tagString(TAG_SERVICE_NAME, profile.service),
		tagHex(TAG_HOST_UNIQ, hostUniq)
	]);
	return net.l2.exchange({
		interface: profile.interface,
		ethertype: ETH_P_PPP_DISC,
		dst_mac: 'ff:ff:ff:ff:ff:ff',
		payload: padi,
		timeout_ms: profile.timeout_ms,
		max_bytes: 1500
	});
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
    var frame = net.l2.recv({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500
    });
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
  if (lcpReadyForNetworkCP(profile, out) && profile.request_pd && out.ipv6cp && out.ipv6cp.up) {
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
  return out.auth_sent === true;
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

function armKeepalive(profile, session) {
  timer.clear('lcp_echo');
  if (!profile.keepalive_interval_ms || !session || !session.session_id || !session.ac_mac) return;
  timer.setInterval('lcp_echo', profile.keepalive_interval_ms, keepaliveTimerPayload(profile, session));
}

function armSessionControl(profile, session) {
  timer.clear('session_control');
  if (profile.send_padt || !profile.post_session_control_ms || !session || !session.session_id || !session.ac_mac) return;
  var payload = sessionControlTimerPayload(profile, session, profile.post_session_control_ms);
  payload.deadline_ms = Date.now() + profile.post_session_control_ms;
  payload.started_at = new Date().toISOString();
  timer.setInterval('session_control', 10, payload);
}

function disconnectSession(profile, payload) {
  var record = resources.get('sessions', 'last');
  var data = record && record.data ? record.data : {};
  var sessionID = clampInt(payload.session_id || data.session_id, 1, 65535, 0);
  var peerMAC = macText(payload.ac_mac || data.ac_mac || '');
  if (!sessionID || !peerMAC) throw new Error('no stored or provided PPPoE session to disconnect');
  sendPADT(profile, peerMAC, sessionID);
  timer.clear('lcp_echo');
  timer.clear('session_control');
  clearTunnelConfig();
  resources.set('sessions', 'last', merge(data, {
    phase: 'disconnected',
    padt_sent: true,
    updated_at: new Date().toISOString()
  }));
  markWANLinkDown(profile, data, 'disconnected');
}

function recordSession(profile, session) {
  resources.set('sessions', 'last', session);
  publishWANLink(profile, session);
}

function publishWANLink(profile, session) {
  if (!session || !session.session_id) return;
  var link = normalizedWANLink(profile, session);
  var sync = syncWANCore(profile, link);
  if (sync) link.wan_core_sync = sync;
  resources.set('wan_links', link.wan_id, link);
}

function markWANLinkDown(profile, previous, phase) {
  var key = token((previous && previous.wan_id) || profile.wan_id || profile.profile_key);
  var record = resources.get('wan_links', key);
  var data = record && record.data ? record.data : normalizedWANLink(profile, previous || {});
  resources.set('wan_links', key, merge(data, {
    state: 'down',
    usable: false,
    phase: phase || 'down',
    updated_at: new Date().toISOString()
  }));
}

function normalizedWANLink(profile, session) {
  session = session || {};
  var ipcp = session.ipcp || {};
  var ipv6cp = session.ipv6cp || {};
  var dhcpv6PD = session.dhcpv6_pd || {};
  var pdPrefixes = Array.isArray(dhcpv6PD.prefixes) ? dhcpv6PD.prefixes : [];
  var open = session.padt_sent !== true && session.lcp_ready === true;
  var state = open ? 'up' : (session.padt_sent ? 'closed' : (session.phase || 'unknown'));
  return {
    wan_id: token(session.wan_id || profile.wan_id || profile.profile_key),
    profile_key: profile.profile_key,
    driver: 'pppoe',
    driver_plugin: 'pppoe_client',
    state: state,
    usable: open,
    real_interface: profile.interface,
    wan_interface: profile.wan_interface || profile.interface,
    host_interface: profile.lan_peer_interface || 'fwdlocal0',
    vtap_interface: profile.lan_interface || 'fwdvtap0',
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
    ipv6_link_local: ipv6cp.link_local || '',
    ipv6_peer_link_local: ipv6cp.peer_link_local || '',
    pd_prefix: dhcpv6PD.prefix || (pdPrefixes[0] && pdPrefixes[0].prefix) || '',
    pd_prefixes: pdPrefixes,
    dns_servers: Array.isArray(dhcpv6PD.dns_servers) ? dhcpv6PD.dns_servers : [],
    tunnel: session.tunnel || null,
    handoff: {
      preferred_mode: session.tunnel && session.tunnel.mode ? session.tunnel.mode : 'direct_vtap',
      host_interface: profile.lan_peer_interface || 'fwdlocal0',
      vtap_interface: profile.lan_interface || 'fwdvtap0',
      forward_core_parent_interface: profile.lan_interface || 'fwdvtap0',
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
    plugins.resources.set(profile.wan_core_plugin, 'sessions', link.wan_id, link, true, profile.wan_core_apply);
    return {
      status: 'synced',
      plugin: profile.wan_core_plugin,
      resource: 'sessions',
      key: link.wan_id,
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

function redialAfterKeepaliveFailure(profile, keepaliveResult) {
  var base = merge(keepaliveResult, {
    redial_attempted: true,
    redial_started_at: new Date().toISOString()
  });
  try {
    if (profile.redial_clear_tunnel) clearTunnelConfig();
    profile.send_padt = false;
    var session = probeSession(profile);
    recordSession(profile, session);
    if (session && session.lcp_ack) {
      armKeepalive(profile, session);
      return merge(base, {
        phase: 'redial_ok',
        redial_phase: session.phase,
        redial_session_id: session.session_id || 0,
        redial_tunnel_installed: session.tunnel_installed === true,
        redial_updated_at: new Date().toISOString()
      });
    }
    return merge(base, {
      phase: 'redial_failed',
      redial_phase: session && session.phase ? session.phase : 'unknown',
      redial_tunnel_installed: session && session.tunnel_installed === true,
      redial_updated_at: new Date().toISOString()
    });
  } catch (e) {
    return merge(base, {
      phase: 'redial_error',
      redial_error: e && e.message ? e.message : String(e),
      redial_updated_at: new Date().toISOString()
    });
  }
}

function sendLCPEcho(profile, peerMAC, sessionID) {
  var identifier = randomByte();
  sendPPPControl(profile, peerMAC, sessionID, PPP_LCP, cpPacket(9, identifier, '00000000'));
  var serviced = servicePPPControlWindow(profile, peerMAC, sessionID, profile.timeout_ms, {
    lcp_echo_identifier: identifier
  });
  var phase = serviced.lcp_echo_reply ? 'keepalive_ok' : 'keepalive_timeout';
  return baseResult(profile, phase, {
    session_id: sessionID,
    ac_mac: peerMAC,
    code: serviced.lcp_echo_code || 0,
    identifier: identifier,
    control: serviced
  });
}

function keepaliveTimerPayload(profile, session) {
  return {
    profile_key: profile.profile_key,
    interface: profile.interface,
    username: profile.username,
    password: profile.password,
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
    request_pd: profile.request_pd,
    dhcpv6_request: profile.dhcpv6_request,
    ipv6_iid: profile.ipv6_iid,
    dhcpv6_iaid: profile.dhcpv6_iaid,
    keepalive_interval_ms: profile.keepalive_interval_ms,
    auto_redial: profile.auto_redial,
    redial_clear_tunnel: profile.redial_clear_tunnel,
    install_tunnel: profile.install_tunnel,
    post_session_control_ms: profile.post_session_control_ms,
    coupled: profile.coupled,
    send_padt: false,
    lan_interface: profile.lan_interface,
    lan_peer_interface: profile.lan_peer_interface,
    wan_interface: profile.wan_interface,
    lan_ifindex: profile.lan_ifindex,
    wan_ifindex: profile.wan_ifindex,
    lan_src_mac: profile.lan_src_mac,
    lan_dst_mac: profile.lan_dst_mac,
    wan_src_mac: profile.wan_src_mac,
    wan_dst_mac: profile.wan_dst_mac,
    wan_core_sync: profile.wan_core_sync,
    wan_core_apply: profile.wan_core_apply,
    wan_core_plugin: profile.wan_core_plugin,
    session_id: session.session_id,
    ac_mac: session.ac_mac
  };
}

function sessionControlTimerPayload(profile, session, remainingMs) {
  return {
    profile_key: profile.profile_key,
    interface: profile.interface,
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
  var last = null;
  for (var attempt = 0; attempt < profile.max_frames; attempt++) {
    var identifier = randomByte();
    var req = cpPacket(1, identifier, cpOptionIPv4(IPCP_OPTION_IP_ADDRESS, requestedIP));
    var frame = exchangePPPControl(profile, peerMAC, sessionID, PPP_IPCP, req);
    var result = completeCPNegotiation(profile, peerMAC, sessionID, PPP_IPCP, identifier, frame);
    if (result.timeout) return {phase: 'timeout', requested_address: requestedIP};
    if (result.protocol !== PPP_IPCP) return {phase: 'unexpected_protocol', protocol: '0x' + u16hex(result.protocol), requested_address: requestedIP};
    var cp = result.cp;
    var options = parseCPOptions(cp.data_hex);
    var ip = firstCPIPv4Option(options, IPCP_OPTION_IP_ADDRESS);
    last = {
      phase: cpCodeName(cp.code),
      up: cp.code === 2,
      code: cp.code,
      identifier: cp.identifier,
      address: ip || requestedIP,
      requested_address: requestedIP,
      attempts: attempt + 1
    };
    if (cp.code === 2 || cp.code === 4) {
      last.peer = ackPeerConfigureRequests(profile, peerMAC, sessionID, PPP_IPCP);
      return last;
    }
    if (cp.code === 3 && ip) {
      requestedIP = ip;
      continue;
    }
    return last;
  }
  return last || {phase: 'timeout', requested_address: requestedIP};
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

function requestDHCPv6PD(profile, peerMAC, sessionID, localMAC) {
  if (profile.dhcpv6_settle_ms > 0) {
    servicePPPControlWindow(profile, peerMAC, sessionID, profile.dhcpv6_settle_ms, null);
  }
  var xid = crypto.randomBytes(3);
  var iid = profile.ipv6_iid || crypto.randomBytes(8);
  var src = linkLocalFromIID(iid);
  var dst = 'ff02::1:2';
  var clientID = dhcpv6ClientIDValue(localMAC || '02:00:00:00:00:01');
  var dhcp = dhcpv6Solicit(xid, clientID, profile.dhcpv6_iaid);
  var frame = exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, dhcp, xid);
  if (frame === null) return {phase: 'timeout', transaction_id: xid};
  var parsedReply = parseDHCPv6ReplyFrame(frame, xid);
  if (parsedReply.error) return parsedReply.error;
  var reply = parsedReply.reply;
  var prefixes = dhcpv6Prefixes(reply.options);
  var result = {
    phase: dhcpv6MessagePhase(reply.message_type),
    transaction_id: reply.transaction_id,
    server_id: firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_SERVERID),
    prefix: prefixes.length ? prefixes[0].prefix : '',
    prefixes: prefixes
  };
  if (reply.message_type !== DHCPV6_ADVERTISE || !profile.dhcpv6_request) return result;

  var serverID = firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_SERVERID);
  var iaPD = firstDHCPv6OptionHex(reply.options, DHCPV6_OPT_IA_PD);
  if (!serverID || !iaPD) return merge(result, {phase: 'advertise_incomplete'});
  var requestXID = crypto.randomBytes(3);
  var request = dhcpv6Request(requestXID, clientID, serverID, iaPD);
  var requestFrame = exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, request, requestXID);
  if (requestFrame === null) return merge(result, {phase: 'request_timeout', request_transaction_id: requestXID});
  var parsedRequestReply = parseDHCPv6ReplyFrame(requestFrame, requestXID);
  if (parsedRequestReply.error) return merge(result, parsedRequestReply.error);
  var finalReply = parsedRequestReply.reply;
  var finalPrefixes = dhcpv6Prefixes(finalReply.options);
  return {
    phase: dhcpv6MessagePhase(finalReply.message_type),
    transaction_id: finalReply.transaction_id,
    advertise_transaction_id: reply.transaction_id,
    server_id: firstDHCPv6OptionHex(finalReply.options, DHCPV6_OPT_SERVERID) || serverID,
    prefix: finalPrefixes.length ? finalPrefixes[0].prefix : (prefixes.length ? prefixes[0].prefix : ''),
    prefixes: finalPrefixes.length ? finalPrefixes : prefixes,
    advertise_prefixes: prefixes
  };
}

function ackPeerConfigureRequests(profile, peerMAC, sessionID, protocol) {
  var acked = 0;
  var targetAcked = 0;
  var skipped = 0;
  var drainTimeout = clampInt(profile.peer_ack_timeout_ms, 10, 250, profile.control_ack_timeout_ms);
  var frames = recvPPPSessionFrames(profile, drainTimeout, Math.min(profile.max_frames, 6));
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
  if (deadline > 0) {
    if (nextRemaining <= 0) timer.clear('session_control');
  } else if (nextRemaining > 0) {
    var next = merge(payload, {remaining_ms: nextRemaining});
    timer.setTimeout('session_control', 10, next);
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
  var out = {
    phase: 'drained',
    duration_ms: durationMs,
    polls: 0,
    frames: 0,
    skipped: 0,
    timeouts: 0,
    parse_errors: 0,
    configure_acks_sent: 0,
    echo_replies_sent: 0,
    lcp_echo_reply: false,
    lcp_echo_code: 0,
    events: []
  };
  if (durationMs <= 0) return out;

  for (var i = 0; i < maxPolls && Date.now() < deadline; i++) {
    var timeout = Math.min(profile.timeout_ms, Math.max(1, deadline - Date.now()));
    out.polls++;
    var frames = recvPPPSessionFrames(profile, timeout, Math.min(8, Math.max(1, maxPolls - i)));
    if (!frames.length) {
      out.timeouts++;
      continue;
    }
    for (var j = 0; j < frames.length && j < 64; j++) {
      out.frames++;
      var event = servicePPPControlFrame(profile, peerMAC, sessionID, frames[j], expected);
      appendControlEventFrames(frames, event);
      if (out.events.length < 16) out.events.push(event);
      if (event.event === 'configure_ack_sent') out.configure_acks_sent++;
      if (event.event === 'echo_reply_sent') out.echo_replies_sent++;
      if (event.event === 'lcp_echo_reply') {
        out.lcp_echo_reply = true;
        out.lcp_echo_code = event.code;
        out.phase = 'echo_reply';
        return out;
      }
      if (event.event === 'skip' || event.event === 'skip_session' || event.event === 'skip_peer') out.skipped++;
      if (event.event === 'parse_error') out.parse_errors++;
    }
  }

  if (expected.lcp_echo_identifier != null && !out.lcp_echo_reply) {
    out.phase = 'echo_timeout';
  } else if (out.frames === 0 && out.timeouts > 0) {
    out.phase = 'timeout';
  }
  return out;
}

function recvPPPSessionFrames(profile, timeoutMs, maxFrames) {
  timeoutMs = clampInt(timeoutMs, 1, 1500, profile.timeout_ms);
  maxFrames = clampInt(maxFrames, 1, 64, 1);
  if (net.l2.recvMany) {
    return net.l2.recvMany({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      timeout_ms: timeoutMs,
      max_bytes: 1500,
      max_frames: maxFrames,
      idle_timeout_ms: profile.control_idle_timeout_ms
    }) || [];
  }
  var frame = net.l2.recv({
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    timeout_ms: timeoutMs,
    max_bytes: 1500
  });
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
  net.l2.send({
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    dst_mac: peerMAC,
    payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload)
  });
}

function pppControlProtocolName(protocol) {
  if (protocol === PPP_LCP) return 'lcp';
  if (protocol === PPP_IPCP) return 'ipcp';
  if (protocol === PPP_IPV6CP) return 'ipv6cp';
  return '0x' + u16hex(protocol);
}

function exchangeDHCPv6(profile, peerMAC, sessionID, src, dst, dhcpPayload, transactionID) {
  var payload = pppoeSession(sessionID, u16hex(PPP_IPV6) + ipv6UDP(src, dst, 546, 547, dhcpPayload));
  var deadline = Date.now() + profile.timeout_ms;
  var firstFrames = [];
  if (net.l2.exchangeMany) {
    firstFrames = net.l2.exchangeMany({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500,
      max_frames: Math.min(Math.max(profile.max_frames * 4, 8), 32),
      idle_timeout_ms: profile.control_idle_timeout_ms
    }) || [];
  } else {
    var firstFrame = net.l2.exchange({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: payload,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500
    });
    if (firstFrame !== null) firstFrames = [firstFrame];
  }
  var matched = findDHCPv6ReplyFrame(firstFrames, sessionID, transactionID);
  if (matched !== null) return matched;

  while (Date.now() < deadline) {
    var remaining = Math.max(1, Math.min(profile.timeout_ms, deadline - Date.now()));
    var frames = recvPPPSessionFrames(profile, remaining, Math.min(Math.max(profile.max_frames * 4, 8), 32));
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
  var timeout = clampInt(timeoutMs, 1, 1500, profile.timeout_ms);
  return net.l2.exchange({
    interface: profile.interface,
    ethertype: ETH_P_PPP_SESS,
    dst_mac: peerMAC,
    payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload),
    timeout_ms: timeout,
    max_bytes: 1500
  });
}

function exchangePPPControlFrames(profile, peerMAC, sessionID, protocol, cpPayload, timeoutMs, maxFrames) {
  var timeout = clampInt(timeoutMs, 1, 1500, profile.timeout_ms);
  var frameLimit = clampInt(maxFrames, 1, 64, profile.max_frames);
  if (net.l2.exchangeMany) {
    return net.l2.exchangeMany({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      dst_mac: peerMAC,
      payload: pppoeSession(sessionID, u16hex(protocol) + cpPayload),
      timeout_ms: timeout,
      max_bytes: 1500,
      max_frames: frameLimit,
      idle_timeout_ms: profile.control_idle_timeout_ms
    }) || [];
  }
  var frame = exchangePPPControl(profile, peerMAC, sessionID, protocol, cpPayload, timeout);
  return frame === null ? [] : [frame];
}

function completeCPNegotiation(profile, peerMAC, sessionID, protocol, identifier, firstFrame) {
  var frame = firstFrame;
  for (var i = 0; i < profile.max_frames; i++) {
    if (frame === null) return {timeout: true};
    var parsed = parseSessionFrame(frame);
    if (parsed.protocol !== protocol) return {protocol: parsed.protocol, cp: {code: 0, identifier: 0, data_hex: ''}};
    var cp = parseCP(parsed.payload);
    if (cp.code === 1) {
      frame = net.l2.exchange({
        interface: profile.interface,
        ethertype: ETH_P_PPP_SESS,
        dst_mac: peerMAC,
        payload: pppoeSession(sessionID, u16hex(protocol) + cpPacket(2, cp.identifier, cp.data_hex)),
        timeout_ms: profile.timeout_ms,
        max_bytes: 1500
      });
      continue;
    }
    if (cp.identifier === identifier || cp.code === 3 || cp.code === 4) {
      return {protocol: protocol, cp: cp};
    }
    frame = net.l2.recv({
      interface: profile.interface,
      ethertype: ETH_P_PPP_SESS,
      timeout_ms: profile.timeout_ms,
      max_bytes: 1500
    });
  }
  return {timeout: true};
}

function sendPADT(profile, peerMAC, sessionID) {
  net.l2.send({
    interface: profile.interface,
    ethertype: ETH_P_PPP_DISC,
    dst_mac: peerMAC,
    payload: pppoeDiscovery(CODE_PADT, sessionID, [])
  });
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

function dhcpv6Solicit(xid, clientIDValue, iaid) {
  var clientID = dhcpv6Option(DHCPV6_OPT_CLIENTID, clientIDValue);
  var elapsed = dhcpv6Option(DHCPV6_OPT_ELAPSED_TIME, '0000');
  var oro = dhcpv6ORO();
  var reconfigure = dhcpv6Option(DHCPV6_OPT_RECONF_ACCEPT, '');
  var fqdn = dhcpv6ClientFQDN('OpenWrt');
  var iapd = dhcpv6Option(DHCPV6_OPT_IA_PD, u32hex(iaid) + u32hex(0) + u32hex(0));
  return hexByte(DHCPV6_SOLICIT) + xid + elapsed + oro + clientID + reconfigure + fqdn + iapd;
}

function dhcpv6Request(xid, clientIDValue, serverIDValue, iaPDValue) {
  var clientID = dhcpv6Option(DHCPV6_OPT_CLIENTID, clientIDValue);
  var serverID = dhcpv6Option(DHCPV6_OPT_SERVERID, serverIDValue);
  var elapsed = dhcpv6Option(DHCPV6_OPT_ELAPSED_TIME, '0000');
  var oro = dhcpv6ORO();
  var reconfigure = dhcpv6Option(DHCPV6_OPT_RECONF_ACCEPT, '');
  var fqdn = dhcpv6ClientFQDN('OpenWrt');
  var iapd = dhcpv6Option(DHCPV6_OPT_IA_PD, iaPDValue);
  return hexByte(DHCPV6_REQUEST) + xid + elapsed + oro + clientID + serverID + reconfigure + fqdn + iapd;
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
  return dhcpv6Option(DHCPV6_OPT_CLIENT_FQDN, '00' + stringHex(name || 'OpenWrt') + '00');
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
  if (code !== DHCPV6_OPT_IA_PD || valueBytes.length < 12) return [];
  return parseDHCPv6Options(bytesToHex(valueBytes.slice(12)));
}

function firstDHCPv6OptionHex(options, code) {
  for (var i = 0; i < options.length; i++) {
    if (options[i].code === code) return options[i].value_hex;
  }
  return '';
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

function ipv6UDPChecksum(srcHex, dstHex, udpHex, udpLen) {
  var pseudo = srcHex + dstHex + u32hex(udpLen) + '00000011' + udpHex;
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

function ipv6TextToHex(value) {
  value = lower(value);
  if (value === 'ff02::1:2') return 'ff020000000000000000000000010002';
  if (value.indexOf('fe80::') === 0) {
    var suffix = value.slice('fe80::'.length).replace(/:/g, '');
    while (suffix.length < 16) suffix = '0' + suffix;
    return 'fe80000000000000' + suffix.slice(-16);
  }
  throw new Error('unsupported IPv6 literal in PPPoE lab helper: ' + value);
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
