plugin.capabilities(['lan', 'bridge', 'lan_ports', 'egress_nat_adapter', 'net_admin', 'control']);
pipeline.handoff({
  id: 'lan0',
  type: 'bridge',
  description: 'Logical LAN endpoint backed by a Linux bridge such as br-lan.'
});
plugin.resource({
  id: 'profiles',
  description: 'LAN bridge defaults such as bridge name, member ports, gateway addresses, selected WAN egress, and whether to preserve the bridge on teardown.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'status',
  description: 'Last applied LAN bridge state and member port details.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 32768
});
plugin.resource({
  id: 'egress_nat_plans',
  description: 'Core outbound NAT config generated from LAN bridge and WAN egress metadata.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'ipv6_assignment_plans',
  description: 'IPv6 delegated-prefix assignments generated from WAN Core PD metadata for the selected LAN bridge.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'dhcpv4_plans',
  description: 'DHCPv4 listener config generated for the LAN bridge without taking ownership of the bridge gateway address.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.action({
  id: 'apply_network',
  description: 'Create or update the configured LAN bridge and publish the generated outbound NAT config.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'teardown',
  description: 'Detach plugin-managed member ports, delete an unprotected configured bridge, preserve protected vmbr* bridges and pre-existing bridge members, and mark the LAN adapter down.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.action({
  id: 'traffic_stats',
  description: 'Read bridge and actual bridge-member link counters without persisting a snapshot.',
  runtime_update: 'runtime_query',
  max_payload_bytes: 2048
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: 'a4d7bc4dbfa34fa8b04a1a8d658fb5c82c56cbfea14dd32586522e0c82b47991',
  page: 'lan',
  page_title: 'LAN'
});

exports.onReconcile = function () {
  applyStoredProfiles();
  armRepairTimer();
};

exports.onDeactivate = function () {
  timer.clear('lan_repair');
  var records = resources.list('profiles') || [];
  var failures = [];
  for (var i = 0; i < records.length; i++) {
    if (!records[i]) continue;
    try {
      teardownNetwork(loadPlan({key: records[i].key, profile: records[i].data || {}}));
    } catch (e) {
      failures.push(token(records[i].key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (failures.length) throw new Error('LAN deactivate cleanup failed: ' + failures.join('; '));
};

exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== 'lan_repair') return;
  applyStoredProfiles();
  armRepairTimer();
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'profiles') return;
  var records = ctx.records || [];
  try {
    applyRecords(records, true);
  } finally {
    armRepairTimer(mergedProfileRecords(records));
  }
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
	if (action === 'traffic_stats') {
		return readTrafficStats(ctx.payload || {});
	}
  if (action === 'apply_network') {
    var plan = loadPlan(ctx.payload || {});
    setRecordIfChanged('profiles', plan.key, plan.profile, true);
    applyNetwork(plan);
    armRepairTimer();
    return;
  }
  if (action === 'teardown') {
    teardownNetwork(loadPlan(ctx.payload || {}));
    armRepairTimer();
    return;
  }
  throw new Error('unsupported action ' + action);
};

function readTrafficStats(payload) {
	payload = payload || {};
	var key = token(payload.profile_key || payload.lan_id || payload.key || 'default');
	var profileRecord = resources.get('profiles', key);
	var statusRecord = resources.get('status', key);
	var profile = profileRecord && profileRecord.data ? profileRecord.data : {};
	var status = statusRecord && statusRecord.data ? statusRecord.data : {};
	var bridge = safeIfaceName(payload.bridge || status.bridge || profile.bridge || profile.bridge_interface || '');
	var ports = [];
	try {
		var portSource = statusRecord && Array.isArray(status.bridge_members)
			? status.bridge_members
			: (statusRecord && Array.isArray(status.ports) ? status.ports : (profile.ports || []));
		ports = trafficIfaceList(portSource);
	} catch (e) {
		ports = [];
	}
	var out = {
		available: false,
		profile_key: key,
		sampled_at_ms: Date.now(),
		counter_scope: 'linux_link',
		bridge: null,
		ports: []
	};
	if (!bridge) {
		out.reason = 'LAN bridge is not configured';
		return out;
	}
	out.bridge = readLinkTrafficStats(bridge);
	for (var i = 0; i < ports.length; i++) {
		out.ports.push(readLinkTrafficStats(ports[i]));
	}
	out.available = !!(out.bridge && !out.bridge.error && out.bridge.statistics);
	if (!out.available) out.reason = out.bridge && out.bridge.error ? out.bridge.error : 'link statistics are unavailable';
	return out;
}

function readLinkTrafficStats(name) {
	try {
		var link = net.link.get(name);
		var stats = link && link.statistics ? link.statistics : null;
		return {
			name: name,
			ifindex: intValue(link && link.ifindex, 0, 2147483647, 0),
			up: !!(link && link.up),
			oper_state: text(link && link.oper_state || ''),
			statistics: stats ? {
				rx_packets: trafficCounter(stats.rx_packets),
				tx_packets: trafficCounter(stats.tx_packets),
				rx_bytes: trafficCounter(stats.rx_bytes),
				tx_bytes: trafficCounter(stats.tx_bytes),
				rx_errors: trafficCounter(stats.rx_errors),
				tx_errors: trafficCounter(stats.tx_errors),
				rx_dropped: trafficCounter(stats.rx_dropped),
				tx_dropped: trafficCounter(stats.tx_dropped)
			} : null
		};
	} catch (e) {
		return {name: name, error: errorMessage(e), statistics: null};
	}
}

function trafficCounter(value) {
	var n = Number(value);
	if (!isFinite(n) || n < 0) return 0;
	return Math.floor(n);
}

function trafficIfaceList(value) {
	if (!Array.isArray(value)) return ifaceList(value);
	var names = [];
	for (var i = 0; i < value.length; i++) {
		var item = value[i];
		if (item && typeof item === 'object') item = item.name || item.interface || item.link || '';
		if (text(item)) names.push(item);
	}
	return ifaceList(names);
}

function applyStoredProfiles() {
  applyRecords(resources.list('profiles') || [], false);
}

function armRepairTimer(records) {
  var profiles = records || resources.list('profiles') || [];
  for (var i = 0; i < profiles.length; i++) {
    if (profiles[i] && profiles[i].enabled !== false) {
      timer.setInterval('lan_repair', 2000, {});
      return;
    }
  }
  timer.clear('lan_repair');
}

function mergedProfileRecords(records) {
  var out = [];
  var positions = {};
  var stored = resources.list('profiles') || [];
  for (var i = 0; i < stored.length; i++) {
    if (!stored[i]) continue;
    positions[token(stored[i].key || 'default')] = out.length;
    out.push(stored[i]);
  }
  for (var j = 0; j < (records || []).length; j++) {
    if (!records[j]) continue;
    var key = token(records[j].key || 'default');
    if (Object.prototype.hasOwnProperty.call(positions, key)) {
      out[positions[key]] = records[j];
    } else {
      positions[key] = out.length;
      out.push(records[j]);
    }
  }
  return out;
}

function applyRecords(records, reportErrors) {
  var failures = [];
  for (var i = 0; i < records.length; i++) {
    var record = records[i];
    if (!record) continue;
    if (record.enabled === false) {
      disableProfileRuntime(record);
      continue;
    }
    try {
      applyNetwork(loadPlan({key: record.key, profile: record.data || {}}));
    } catch (e) {
      markApplyError(record.key, e);
      failures.push(token(record.key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (reportErrors && failures.length) {
    throw new Error('failed to apply ' + failures.length + ' LAN profile record(s): ' + failures.join('; '));
  }
}

function disableProfileRuntime(record) {
  var key = token(record && record.key || 'default');
  var raw = record && record.data ? record.data : {};
  var previous = previousStatus(key);
  var groRestore = restorePreviousMemberGRO(previous);
  var plan = {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    parent_interface: safeIfaceName(raw.bridge || raw.bridge_interface || ''),
    child_interface: '',
    out_interface: safeIfaceName(raw.wan_egress_interface || raw.out_interface || raw.wan_interface || ''),
    out_source_ip: text(raw.wan_egress_source_ip || raw.out_source_ip || raw.source_ip || ''),
    protocol: normalizeProtocol(raw.protocol || 'tcp+udp'),
    nat_type: text(raw.nat_type || 'symmetric'),
    redirect_mode: normalizeRedirectMode(raw.redirect_mode || raw.egress_nat_redirect_mode || ''),
    enabled: false,
    note: 'disabled because lan_core profile is disabled'
  };
  setEgressNATPlanIfChanged(key, plan, false);
  setDHCPv4PlanIfChanged(key, disabledDHCPv4Plan(key, plan.parent_interface, 'disabled because lan_core profile is disabled'), false);
  setIPv6AssignmentPlanIfChanged(key, disabledIPv6AssignmentPlan(key, plan.parent_interface, 'disabled because lan_core profile is disabled'), false);
  if (previous.phase === 'deleted' && safeIfaceName(previous.bridge || '') === plan.parent_interface) {
    previous.member_gro = disabledMemberGROState(raw.mtu || previous.bridge_mtu, groRestore);
    previous.cleanup_errors = (Array.isArray(previous.cleanup_errors) ? previous.cleanup_errors : []).concat(groRestore.errors);
    setRecordIfChanged('status', key, previous, false);
    return;
  }
  setRecordIfChanged('status', key, {
    phase: 'disabled',
    lan_id: key,
    bridge: plan.parent_interface,
    wan_ref: token(raw.wan_ref || raw.wan || 'default'),
    cleanup_errors: groRestore.errors,
    member_gro: disabledMemberGROState(raw.mtu, groRestore),
    egress_nat_plan: plan
  }, false);
}

function markApplyError(key, error) {
  key = token(key || 'default');
  var message = errorMessage(error);
  var previous = previousStatus(key);
  var groRestore = restorePreviousMemberGRO(previous);
  if (groRestore.errors.length) message += '; ' + groRestore.errors.join('; ');
  setEgressNATPlanIfChanged(key, {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    enabled: false,
    note: 'disabled because lan_core failed to apply this profile',
    last_error: message
  }, false);
  setDHCPv4PlanIfChanged(key, disabledDHCPv4Plan(key, '', 'disabled because lan_core failed to apply this profile'), false);
  setIPv6AssignmentPlanIfChanged(key, disabledIPv6AssignmentPlan(key, '', 'disabled because lan_core failed to apply this profile'), false);
  setRecordIfChanged('status', key, {
    phase: 'error',
    lan_id: key,
    cleanup_errors: groRestore.errors,
    member_gro: disabledMemberGROState(previous.bridge_mtu, groRestore),
    last_error: message
  }, false);
}

function loadPlan(payload) {
  payload = payload || {};
  var inlineProfile = payload.profile || null;
  var key = token(payload.lan_id || payload.network_id || payload.profile_key || payload.key ||
    (inlineProfile && (inlineProfile.lan_id || inlineProfile.network_id || inlineProfile.profile_key || inlineProfile.key)) || 'default');
  var stored = resources.get('profiles', key);
  var storedProfile = stored && stored.data ? stored.data : {};
  var raw = merge(storedProfile, inlineProfile || payload || {});
  return {key: key, profile: normalizeProfile(key, raw)};
}

function applyNetwork(plan) {
  var profile = plan.profile;
  var previous = previousStatus(plan.key);
  var bridgeExisted = linkExists(profile.bridge);
  var bridge = net.link.ensureBridge({
    name: profile.bridge,
    mtu: profile.mtu,
    up: true
  });
  var cleanupErrors = cleanupManagedBridgeState(previous, profile);
  cleanupManagedPorts(previous, profile, cleanupErrors);
  replaceAddrs(profile.bridge, profile.addresses);

  var members = [];
  var missingPorts = [];
  var failedPorts = [];
  var managedPortSet = retainedManagedPortSet(previous, profile);
  for (var i = 0; i < profile.ports.length; i++) {
    var port = profile.ports[i];
    var current = null;
    try {
      current = net.link.get(port);
    } catch (e) {
      missingPorts.push(port);
      continue;
    }
    var info = current;
    var wasMember = current.master_name === profile.bridge;
    try {
      if (current.master_name !== profile.bridge || current.up !== true) {
        info = net.link.setMaster({link: port, master: profile.bridge, up: true});
      }
    } catch (e) {
      failedPorts.push({name: port, error: e && e.message ? e.message : String(e)});
      continue;
    }
    if (!wasMember) managedPortSet[port] = true;
    members.push({
      name: info.name || port,
      ifindex: info.ifindex || 0,
      kind: info.kind || '',
      mac: info.mac || '',
      master_name: info.master_name || profile.bridge,
      master_ifindex: info.master_ifindex || bridge.ifindex || 0,
      managed: !!managedPortSet[port]
    });
  }
  var managedPorts = sortedSetKeys(managedPortSet);
  var bridgeState = readBridgeMembers(
    profile.bridge,
    bridge.ifindex || 0,
    ifaceSet(profile.ports),
    managedPortSet,
    members
  );
  var wanEgress = resolveWanEgress(profile);
  var memberGRO = reconcileMemberGRO(previous, profile, bridgeState.members, wanEgress);
  var dnsState = resolveDNSState(profile, wanEgress);
  var egressPlan = buildEgressNATPlan(plan.key, profile, wanEgress);
  var dhcpv4Plan = buildDHCPv4Plan(plan.key, profile, wanEgress, dnsState);
  var ipv6Plan = buildIPv6AssignmentPlan(plan.key, profile, wanEgress, dnsState);
  setEgressNATPlanIfChanged(plan.key, egressPlan, egressPlan.enabled === true);
  setDHCPv4PlanIfChanged(plan.key, dhcpv4Plan, dhcpv4Plan.enabled === true);
  setIPv6AssignmentPlanIfChanged(plan.key, ipv6Plan, ipv6Plan.enabled === true);
  var phase = (missingPorts.length || failedPorts.length || memberGRO.errors.length) ? 'partial' : 'applied';
  var bridgeCreatedByThisPlugin = bridgeCreatedByPlugin(previous, profile, bridgeExisted);
  setRecordIfChanged('status', plan.key, {
    phase: phase,
    lan_id: plan.key,
    bridge: bridge.name || profile.bridge,
    bridge_ifindex: bridge.ifindex || 0,
    bridge_mac: bridge.mac || '',
    bridge_mtu: bridge.mtu || profile.mtu,
    bridge_created: bridgeCreatedByThisPlugin,
    bridge_existing: bridgeExisted,
    bridge_addresses: profile.addresses,
    cleanup_errors: cleanupErrors,
    preserve_bridge: profile.preserve_bridge,
    configured_ports: profile.ports,
    ports: members,
    bridge_members: bridgeState.members,
    bridge_members_error: bridgeState.error,
    member_gro: memberGRO,
    managed_ports: managedPorts,
    missing_ports: missingPorts,
    failed_ports: failedPorts,
    wan_ref: profile.wan_ref,
    wan_plugin: profile.wan_plugin,
    wan_egress: wanEgress,
    dns: dnsState,
    egress_nat_plan: egressPlan,
    dhcpv4_plan: dhcpv4Plan,
    ipv6_assignment_plan: ipv6Plan,
    repair_timer: 'lan_repair'
  }, true);
}

function previousStatus(key) {
  var record = resources.get('status', key);
  return record && record.data ? record.data : {};
}

function bridgeCreatedByPlugin(previous, profile, bridgeExisted) {
  previous = previous || {};
  if (!bridgeExisted) return true;
  if (!previous.bridge_created) return false;
  return safeIfaceName(previous.bridge || '') === safeIfaceName(profile.bridge);
}

function cleanupManagedBridgeState(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (previous.phase === 'deleted') return errors;
  cleanupRemovedAddrs(previous.bridge, previous.bridge_addresses, profile.bridge, profile.addresses, errors);
  return errors;
}

function cleanupManagedPorts(previous, profile, errors) {
  var previousBridge = safeIfaceName(previous && previous.bridge || '');
  if (!previousBridge) return;
  var nextBridge = safeIfaceName(profile.bridge);
  var nextPorts = ifaceSet(profile.ports);
  var previousManaged = managedPortsFromPrevious(previous, profile, false);
  for (var i = 0; i < previousManaged.length; i++) {
    var port = previousManaged[i];
    if (previousBridge === nextBridge && nextPorts[port]) continue;
    try {
      net.link.clearMaster(port);
    } catch (e) {
      errors.push('port ' + port + ': ' + errorMessage(e));
    }
  }
}

function retainedManagedPortSet(previous, profile) {
  var out = {};
  var previousBridge = safeIfaceName(previous && previous.bridge || '');
  if (previousBridge !== safeIfaceName(profile.bridge)) return out;
  var nextPorts = ifaceSet(profile.ports);
  var previousManaged = managedPortsFromPrevious(previous, profile, false);
  for (var i = 0; i < previousManaged.length; i++) {
    var port = previousManaged[i];
    if (nextPorts[port]) out[port] = true;
  }
  return out;
}

function managedPortsFromPrevious(previous, profile, teardown) {
  previous = previous || {};
  if (previous.phase === 'deleted') return [];
  if (Array.isArray(previous.managed_ports)) return ifaceList(previous.managed_ports);
  return [];
}

function cleanupRemovedAddrs(iface, previousAddrs, nextIface, nextAddrs, errors) {
  iface = safeIfaceName(iface);
  if (!iface) return;
  var previous = cidrList(previousAddrs);
  if (!previous.length) return;
  nextIface = safeIfaceName(nextIface);
  var next = iface === nextIface ? cidrSet(cidrList(nextAddrs)) : {};
  for (var i = 0; i < previous.length; i++) {
    var cidr = previous[i];
    if (next[cidr]) continue;
    try {
      net.addr.delete({interface: iface, cidr: cidr});
    } catch (e) {
      errors.push('addr ' + iface + ' ' + cidr + ': ' + errorMessage(e));
    }
  }
}

function teardownNetwork(plan) {
  var profile = plan.profile;
  var egressPlan = buildEgressNATPlan(plan.key, profile, resolveWanEgress(profile));
  egressPlan.enabled = false;
  egressPlan.note = 'disabled by lan_core teardown';
  resources.set('profiles', plan.key, profile, false);
  setEgressNATPlanIfChanged(plan.key, egressPlan, false);
  setDHCPv4PlanIfChanged(plan.key, disabledDHCPv4Plan(plan.key, profile.bridge, 'disabled by lan_core teardown'), false);
  setIPv6AssignmentPlanIfChanged(plan.key, disabledIPv6AssignmentPlan(plan.key, profile.bridge, 'disabled by lan_core teardown'), false);

  var previous = previousStatus(plan.key);
  var cleanupErrors = cleanupManagedBridgeState(teardownBridgePreviousState(previous, profile), teardownBridgeProfile(profile));
  var managedPorts = managedPortsFromPrevious(previous, profile, true);
  var bridgeDeleteAllowed = shouldDeleteBridge(previous, profile);
  var bridgeWasPluginCreated = previous.bridge_created === true;
  var failedPorts = [];
  for (var i = 0; i < managedPorts.length; i++) {
    try {
      net.link.clearMaster(managedPorts[i]);
    } catch (e) {
      failedPorts.push({name: managedPorts[i], error: errorMessage(e)});
    }
  }
  var groRestore = restorePreviousMemberGRO(previous);
  cleanupErrors = cleanupErrors.concat(groRestore.errors);
  var bridgeError = '';
  var bridgeDeleteSkipped = !profile.preserve_bridge && !bridgeDeleteAllowed;
  if (bridgeDeleteAllowed) {
    try {
      net.link.delete(profile.bridge);
    } catch (e) {
      bridgeError = errorMessage(e);
    }
  }
  var phase = (failedPorts.length || bridgeError) ? 'delete_partial' : 'deleted';
  var bridgeState = readBridgeMembers(
    profile.bridge,
    intValue(previous.bridge_ifindex, 0, 2147483647, 0),
    ifaceSet(profile.ports),
    {},
    []
  );
  var status = {
    phase: phase,
    lan_id: plan.key,
    bridge: profile.bridge,
    bridge_created: bridgeWasPluginCreated,
    bridge_preserved: profile.preserve_bridge,
    bridge_delete_skipped: bridgeDeleteSkipped,
    cleanup_errors: cleanupErrors,
    configured_ports: profile.ports,
    ports: profile.ports,
    bridge_members: bridgeState.members,
    bridge_members_error: bridgeState.error,
    member_gro: disabledMemberGROState(profile.mtu, groRestore),
    managed_ports: managedPorts,
    failed_ports: failedPorts,
    wan_ref: profile.wan_ref
  };
  if (bridgeError) {
    status.bridge_error = bridgeError;
    status.last_error = bridgeError;
  } else if (bridgeDeleteSkipped) {
    status.bridge_delete_skip_reason = bridgeDeleteSkipReason(previous);
  } else if (failedPorts.length) {
    status.last_error = 'failed to detach ' + failedPorts.length + ' LAN port(s)';
  } else if (cleanupErrors.length) {
    status.last_error = cleanupErrors.join('; ');
  }
  setRecordIfChanged('status', plan.key, status, false);
}

function teardownBridgeProfile(profile) {
  return {
    bridge: profile.bridge,
    addresses: []
  };
}

function teardownBridgePreviousState(previous, profile) {
  previous = previous || {};
  return {
    bridge: previous.bridge || '',
    bridge_addresses: Array.isArray(previous.bridge_addresses) ? previous.bridge_addresses : []
  };
}

function shouldDeleteBridge(previous, profile) {
  previous = previous || {};
  if (previous.phase === 'deleted') return false;
  if (!profile || profile.preserve_bridge) return false;
  if (safeIfaceName(previous.bridge || '') !== safeIfaceName(profile.bridge)) return false;
  return previous.bridge_created === true;
}

function bridgeDeleteSkipReason(previous) {
  previous = previous || {};
  if (previous.bridge_created === true && previous.phase === 'deleted') {
    return 'previous lan_core status already deleted this plugin-created bridge';
  }
  return 'no previous lan_core status proves this bridge was plugin-created';
}

function ifaceSet(values) {
  var out = {};
  values = ifaceList(values || []);
  for (var i = 0; i < values.length; i++) out[values[i]] = true;
  return out;
}

function sortedSetKeys(set) {
  var out = [];
  for (var key in set) {
    if (Object.prototype.hasOwnProperty.call(set, key) && set[key]) out.push(key);
  }
  out.sort();
  return out;
}

function readBridgeMembers(bridgeName, bridgeIfindex, configuredPortSet, managedPortSet, fallback) {
  bridgeName = safeIfaceName(bridgeName);
  bridgeIfindex = intValue(bridgeIfindex, 0, 2147483647, 0);
  configuredPortSet = configuredPortSet || {};
  managedPortSet = managedPortSet || {};
  var members = [];
  try {
    var links = net.link.list() || [];
    for (var i = 0; i < links.length; i++) {
      var info = links[i] || {};
      var name = safeIfaceName(info.name || '');
      if (!name) continue;
      var masterName = safeIfaceName(info.master_name || '');
      var masterIfindex = intValue(info.master_ifindex, 0, 2147483647, 0);
      if (masterName !== bridgeName && (!bridgeIfindex || masterIfindex !== bridgeIfindex)) continue;
      members.push(bridgeMemberView(info, name, bridgeName, bridgeIfindex, configuredPortSet, managedPortSet));
    }
    sortBridgeMembers(members);
    return {members: members, error: ''};
  } catch (e) {
    fallback = Array.isArray(fallback) ? fallback : [];
    for (var j = 0; j < fallback.length; j++) {
      var fallbackInfo = fallback[j] || {};
      var fallbackName = safeIfaceName(fallbackInfo.name || fallbackInfo.interface || fallbackInfo);
      if (!fallbackName) continue;
      members.push(bridgeMemberView(fallbackInfo, fallbackName, bridgeName, bridgeIfindex, configuredPortSet, managedPortSet));
    }
    sortBridgeMembers(members);
    return {members: members, error: errorMessage(e)};
  }
}

function bridgeMemberView(info, name, bridgeName, bridgeIfindex, configuredPortSet, managedPortSet) {
  return {
    name: name,
    ifindex: intValue(info.ifindex, 0, 2147483647, 0),
    kind: text(info.kind || ''),
    mac: text(info.mac || ''),
    up: info.up === true,
    oper_state: text(info.oper_state || ''),
    master_name: safeIfaceName(info.master_name || '') || bridgeName,
    master_ifindex: intValue(info.master_ifindex, 0, 2147483647, bridgeIfindex),
    configured: !!configuredPortSet[name],
    managed: !!managedPortSet[name]
  };
}

function sortBridgeMembers(members) {
  members.sort(function (a, b) {
    var ai = intValue(a && a.ifindex, 0, 2147483647, 0);
    var bi = intValue(b && b.ifindex, 0, 2147483647, 0);
    if (ai && bi && ai !== bi) return ai - bi;
    if (ai && !bi) return -1;
    if (!ai && bi) return 1;
    return text(a && a.name).localeCompare(text(b && b.name));
  });
}

function reconcileMemberGRO(previous, profile, members, wanEgress) {
  previous = previous || {};
  members = Array.isArray(members) ? members : [];
  wanEgress = wanEgress || {};
  var bridgeMTU = intValue(profile.mtu, 576, 65535, 1500);
  var wanMTU = intValue(wanEgress.mtu, 0, 65535, 0);
  var required = profile.auto_egress_nat && profile.protocol.indexOf('tcp') >= 0 && !!wanEgress.interface &&
    wanMTU > 0 && bridgeMTU > wanMTU && wanEgress.segmentation_ready !== true;
  var previousEntries = previous.member_gro && Array.isArray(previous.member_gro.members)
    ? previous.member_gro.members
    : [];
  var previousByName = {};
  var currentNames = {};
  var active = [];
  var pendingRestore = [];
  var errors = [];
  for (var i = 0; i < previousEntries.length; i++) {
    var previousName = safeIfaceName(previousEntries[i] && previousEntries[i].name || '');
    if (previousName) previousByName[previousName] = previousEntries[i];
  }
  for (var j = 0; j < members.length; j++) {
    var memberName = safeIfaceName(members[j] && members[j].name || '');
    if (memberName) currentNames[memberName] = true;
  }
  for (var k = 0; k < previousEntries.length; k++) {
    var stale = previousEntries[k] || {};
    var staleName = safeIfaceName(stale.name || '');
    if (!staleName || (required && currentNames[staleName])) continue;
    if (!restoreMemberGRO(stale, errors)) pendingRestore.push(stale);
  }
  if (required) {
    for (var n = 0; n < members.length; n++) {
      var member = members[n] || {};
      var name = safeIfaceName(member.name || '');
      if (!name) continue;
      var old = previousByName[name] || {};
      var entry = {
        name: name,
        original_gro: typeof old.original_gro === 'boolean' ? old.original_gro : false,
        restore_gro: old.restore_gro === true,
        applied: false
      };
      try {
        var features = net.link.getOffloads(name) || {};
        if (typeof features.gro !== 'boolean') throw new Error('GRO state is unavailable');
        if (typeof old.original_gro !== 'boolean') entry.original_gro = features.gro;
        if (features.gro) {
          net.link.setOffloads(name, {gro: false});
          entry.restore_gro = entry.original_gro === true;
        }
        entry.applied = true;
        member.gro = false;
      } catch (e) {
        errors.push('GRO ' + name + ': ' + errorMessage(e));
      }
      active.push(entry);
    }
  }
  return {
    required: required,
    applied: required && errors.length === 0 && active.length === members.length,
    bridge_mtu: bridgeMTU,
    wan_mtu: wanMTU,
    members: pendingRestore.concat(active),
    errors: errors,
    note: required
      ? 'Compatibility fallback disables GRO because the lower-MTU WAN does not publish a segmentation boundary.'
      : (wanEgress.segmentation_ready === true
        ? 'The WAN pipeline provides a kernel segmentation boundary; LAN GRO remains enabled.'
        : 'No lower-MTU WAN GRO adaptation is required.')
  };
}

function restoreMemberGRO(entry, errors) {
  if (!entry || entry.restore_gro !== true) return true;
  var name = safeIfaceName(entry.name || '');
  if (!name) return true;
  try {
    var features = net.link.getOffloads(name) || {};
    if (features.gro === false) net.link.setOffloads(name, {gro: true});
    return true;
  } catch (e) {
    errors.push('restore GRO ' + name + ': ' + errorMessage(e));
    return false;
  }
}

function restorePreviousMemberGRO(previous) {
  previous = previous || {};
  var entries = previous.member_gro && Array.isArray(previous.member_gro.members)
    ? previous.member_gro.members
    : [];
  var errors = [];
  var pending = [];
  for (var i = 0; i < entries.length; i++) {
    if (!restoreMemberGRO(entries[i], errors)) pending.push(entries[i]);
  }
  return {errors: errors, members: pending};
}

function disabledMemberGROState(bridgeMTU, restore) {
  restore = restore || {errors: [], members: []};
  return {
    required: false,
    applied: false,
    bridge_mtu: intValue(bridgeMTU, 0, 65535, 0),
    wan_mtu: 0,
    members: restore.members || [],
    errors: restore.errors || [],
    note: 'LAN GRO adaptation is disabled and plugin-owned changes were restored.'
  };
}

function normalizeProfile(key, raw) {
  raw = raw || {};
  var bridge = ifaceName(raw.bridge || raw.bridge_interface || 'br-lan', 'bridge');
  var ports = ifaceList(raw.ports || raw.member_ports || raw.interfaces || []);
  for (var i = 0; i < ports.length; i++) {
    if (ports[i] === bridge) throw new Error('LAN port must be different from bridge');
  }
  var addresses = cidrList(raw.addresses || raw.bridge_addresses || raw.ipv4_cidr || '192.168.100.1/24');
  var dnsMode = normalizeDNSMode(raw.dns_mode || raw.dns || 'auto');
  var manualDNSServers = dnsServerList(raw.dns_servers || raw.manual_dns_servers || []);
  if (dnsMode === 'manual' && !manualDNSServers.length) throw new Error('manual DNS mode requires at least one DNS server');
  return {
    profile_key: key,
    bridge: bridge,
    ports: ports,
    mtu: intValue(raw.mtu || raw.bridge_mtu, 576, 65535, 1500),
    addresses: addresses,
    dhcpv4_enabled: bool(raw.dhcpv4_enabled, false),
    dhcpv4_cidr: text(raw.dhcpv4_cidr || firstIPv4CIDR(addresses) || ''),
    dhcpv4_gateway: text(raw.dhcpv4_gateway || ''),
    dhcpv4_pool_start: text(raw.dhcpv4_pool_start || ''),
    dhcpv4_pool_end: text(raw.dhcpv4_pool_end || ''),
    dns_mode: dnsMode,
    dns_servers: manualDNSServers,
    wan_ref: token(raw.wan_ref || raw.wan || 'default'),
    wan_plugin: token(raw.wan_plugin || 'wan_core'),
    wan_egress_interface: optionalIfaceName(raw.wan_egress_interface || raw.out_interface || raw.wan_interface || ''),
    wan_egress_source_ip: text(raw.wan_egress_source_ip || raw.out_source_ip || raw.source_ip || ''),
    auto_egress_nat: bool(raw.auto_egress_nat, true),
    auto_ipv6_pd: bool(raw.auto_ipv6_pd, true),
    ipv6_subnet_id: intValue(raw.ipv6_subnet_id || raw.pd_subnet_id, 0, 65535, 0),
    nat_type: text(raw.nat_type || 'symmetric'),
    protocol: normalizeProtocol(raw.protocol || 'tcp+udp'),
    redirect_mode: normalizeRedirectMode(raw.redirect_mode || raw.egress_nat_redirect_mode || ''),
    preserve_bridge: bool(raw.preserve_bridge, isProtectedBridgeName(bridge))
  };
}

function resolveWanEgress(profile) {
  var result = {
    plugin: profile.wan_plugin,
    ref: profile.wan_ref,
    interface: profile.wan_egress_interface,
    source_ip: profile.wan_egress_source_ip,
    mtu: interfaceMTU(profile.wan_egress_interface),
    segmentation_ready: false,
    redirect_mode: '',
    pd_prefix: '',
    pd_prefixes: [],
    source: profile.wan_egress_interface ? 'profile' : 'wan_core',
    resolved: !!profile.wan_egress_interface
  };
  if (typeof plugins === 'undefined' || !plugins.resources || typeof plugins.resources.get !== 'function') {
    if (result.interface) return result;
    result.source = 'unavailable';
    result.last_error = 'plugins.resources.get is unavailable';
    return result;
  }
  try {
    var record = plugins.resources.get(profile.wan_plugin, 'status', profile.wan_ref);
    if (record && record.enabled !== false && record.data) {
      var data = record.data || {};
      var veerCore = data.veer_core || {};
      result.segmentation_ready = data.segmentation_ready === true || veerCore.segmentation_ready === true;
      result.handoff_mode = text(data.handoff_mode || veerCore.mode || '');
      result.redirect_mode = normalizeRedirectMode(data.egress_nat_redirect_mode || veerCore.egress_nat_redirect_mode || '');
      result.mtu = intValue(data.mtu || veerCore.mtu, 0, 65535, result.mtu);
      result.pd_prefixes = Array.isArray(data.pd_prefixes) ? data.pd_prefixes : [];
      result.pd_prefix = text(data.pd_prefix || firstPrefixValue(result.pd_prefixes) || '');
      result.dns_servers = dnsServerList(data.dns_servers || veerCore.dns_servers || []);
      result.source_ip = result.source_ip || ipAddress(data.ipv4 || firstArrayValue(data.host_addresses) || '');
      if (!result.interface) {
        result.phase = text(data.phase || '');
        result.interface = optionalIfaceName(data.egress_nat_parent_interface || veerCore.egress_nat_interface || data.veer_parent_interface || veerCore.parent_interface || data.host_interface || '');
        result.source = 'wan_core';
      }
      if (!result.mtu) result.mtu = interfaceMTU(result.interface);
      result.resolved = !!result.interface;
      if (!result.resolved) result.last_error = 'WAN status does not publish an egress interface';
      return result;
    }
    if (result.interface) return result;
    if (!record || record.enabled === false || !record.data) {
      result.last_error = 'WAN status record is unavailable or disabled';
      return result;
    }
  } catch (e) {
    if (result.interface) return result;
    result.source = 'error';
    result.last_error = errorMessage(e);
    return result;
  }
}

function interfaceMTU(name) {
  name = safeIfaceName(name);
  if (!name) return 0;
  try {
    var link = net.link.get(name);
    return intValue(link && link.mtu, 0, 65535, 0);
  } catch (e) {
    return 0;
  }
}

function resolveDNSState(profile, wanEgress) {
  var source = profile.dns_mode;
  var servers = [];
  if (source === 'manual') servers = dnsServerList(profile.dns_servers || []);
  if (source === 'auto') servers = dnsServerList(wanEgress && wanEgress.dns_servers || []);
  return {
    mode: source,
    source: source === 'auto' ? (wanEgress && wanEgress.source || 'wan_core') : source,
    servers: servers,
    ipv4_servers: dnsServersByFamily(servers, 4),
    ipv6_servers: dnsServersByFamily(servers, 6),
    resolved: source === 'disabled' || servers.length > 0,
    note: source === 'auto' && !servers.length ? 'WAN Core has not published usable DNS servers yet.' : ''
  };
}

function buildDHCPv4Plan(key, profile, wanEgress, dnsState) {
  dnsState = dnsState || resolveDNSState(profile, wanEgress || resolveWanEgress(profile));
  var plan = {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    bridge: profile.bridge,
    ipv4_cidr: profile.dhcpv4_cidr,
    gateway: profile.dhcpv4_gateway,
    pool_start: profile.dhcpv4_pool_start,
    pool_end: profile.dhcpv4_pool_end,
    dns_mode: dnsState.mode,
    dns_servers: dnsState.ipv4_servers,
    enabled: false,
    note: ''
  };
  if (!profile.dhcpv4_enabled) {
    plan.note = 'DHCPv4 is disabled for this LAN profile.';
    return plan;
  }
  if (!plan.ipv4_cidr) {
    plan.note = 'DHCPv4 requires an IPv4 gateway CIDR on the LAN bridge.';
    return plan;
  }
  plan.enabled = true;
  plan.note = dnsState.note || 'Serve DHCPv4 on the existing LAN bridge and distribute the effective IPv4 DNS servers.';
  return plan;
}

function buildEgressNATPlan(key, profile, wanEgress) {
  wanEgress = wanEgress || resolveWanEgress(profile);
  return {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    parent_interface: profile.bridge,
    child_interface: '',
    out_interface: wanEgress.interface,
    out_source_ip: wanEgress.source_ip,
    protocol: profile.protocol,
    nat_type: profile.nat_type,
    redirect_mode: profile.redirect_mode || normalizeRedirectMode(wanEgress.redirect_mode || ''),
    enabled: profile.auto_egress_nat && !!wanEgress.interface,
    note: wanEgress.interface
      ? 'Apply generated outbound NAT to core: parent_interface=LAN bridge, out_interface=WAN egress.'
      : 'WAN egress interface is not set yet; keep generated outbound NAT disabled until wan_core publishes one.' + (wanEgress.last_error ? ' ' + wanEgress.last_error : '')
  };
}

function buildIPv6AssignmentPlan(key, profile, wanEgress, dnsState) {
  wanEgress = wanEgress || resolveWanEgress(profile);
  dnsState = dnsState || resolveDNSState(profile, wanEgress);
  var plan = {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    parent_interface: wanEgress.interface,
    target_interface: profile.bridge,
    parent_prefix: wanEgress.pd_prefix,
    assigned_prefix: '',
    subnet_index: profile.ipv6_subnet_id,
    upstream_routed: true,
    configure_gateway: true,
    reject_unassigned: true,
    dns_mode: dnsState.mode,
    dns_servers: dnsState.ipv6_servers,
    enabled: false,
    note: ''
  };
  if (!profile.auto_ipv6_pd) {
    plan.note = 'Automatic IPv6 PD assignment is disabled for this LAN profile.';
    return plan;
  }
  if (!plan.parent_interface || !plan.parent_prefix) {
    plan.note = 'WAN Core has not published both an egress interface and delegated IPv6 prefix yet.';
    if (wanEgress.last_error) plan.note += ' ' + wanEgress.last_error;
    return plan;
  }
  if (typeof net === 'undefined' || !net.prefix || typeof net.prefix.subnet !== 'function') {
    plan.note = 'net.prefix.subnet is unavailable.';
    return plan;
  }
  try {
    plan.assigned_prefix = net.prefix.subnet({
      prefix: plan.parent_prefix,
      new_length: 64,
      index: plan.subnet_index
    });
    plan.enabled = true;
    plan.note = 'Route and advertise the selected /64 on the LAN bridge; the upstream already routes the delegated parent prefix.';
  } catch (e) {
    plan.last_error = errorMessage(e);
    plan.note = 'Delegated prefix cannot provide the selected /64.';
  }
  return plan;
}

function disabledDHCPv4Plan(key, bridge, note) {
  return {
    lan_id: token(key || 'default'),
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: token(key || 'default'),
    bridge: safeIfaceName(bridge || ''),
    ipv4_cidr: '',
    gateway: '',
    pool_start: '',
    pool_end: '',
    dns_mode: 'disabled',
    dns_servers: [],
    enabled: false,
    note: text(note || 'disabled')
  };
}

function disabledIPv6AssignmentPlan(key, bridge, note) {
  return {
    lan_id: token(key || 'default'),
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: token(key || 'default'),
    parent_interface: '',
    target_interface: safeIfaceName(bridge || ''),
    parent_prefix: '',
    assigned_prefix: '',
    upstream_routed: true,
    configure_gateway: true,
    reject_unassigned: true,
    enabled: false,
    note: text(note || 'disabled')
  };
}

function normalizeRedirectMode(value) {
  value = lower(text(value));
  if (value === 'prepared_l2' || value === 'raw_l2' || value === 'vtap') return 'prepared_l2';
  return '';
}

function replaceAddrs(iface, addrs) {
  for (var i = 0; i < addrs.length; i++) {
    net.addr.replace({interface: iface, cidr: addrs[i]});
  }
}

function setRecordIfChanged(resource, key, data, enabled) {
  setRecordIfChangedApply(resource, key, data, enabled, false);
}

function setEgressNATPlanIfChanged(key, data, enabled) {
  setRecordIfChangedApply('egress_nat_plans', key, data, enabled, true);
}

function setDHCPv4PlanIfChanged(key, data, enabled) {
  setRecordIfChangedApply('dhcpv4_plans', key, data, enabled, true);
}

function setIPv6AssignmentPlanIfChanged(key, data, enabled) {
  setRecordIfChangedApply('ipv6_assignment_plans', key, data, enabled, true);
}

function normalizeDNSMode(value) {
  value = lower(value || 'auto');
  if (value === 'auto' || value === 'manual' || value === 'disabled') return value;
  throw new Error('dns_mode must be auto, manual or disabled');
}

function dnsServerList(value) {
  var raw = Array.isArray(value) ? value : text(value).split(/[\s,;]+/);
  var out = [];
  var seen = {};
  for (var i = 0; i < raw.length; i++) {
    var item = text(raw[i]);
    if (!item || seen[item]) continue;
    seen[item] = true;
    out.push(item);
    if (out.length >= 8) break;
  }
  return out;
}

function dnsServersByFamily(values, family) {
  values = dnsServerList(values || []);
  var out = [];
  for (var i = 0; i < values.length; i++) {
    var isV6 = values[i].indexOf(':') >= 0;
    if ((family === 6 && isV6) || (family === 4 && !isV6)) out.push(values[i]);
  }
  return out;
}

function firstIPv4CIDR(values) {
  values = cidrList(values || []);
  for (var i = 0; i < values.length; i++) {
    if (values[i].indexOf(':') < 0) return values[i];
  }
  return '';
}

function setRecordIfChangedApply(resource, key, data, enabled, apply) {
  var current = resources.get(resource, key);
  var currentData = current && current.data ? current.data : null;
  var currentEnabled = current ? current.enabled !== false : null;
  var nextEnabled = enabled !== false;
  if (current && currentEnabled === nextEnabled && stableJSON(currentData) === stableJSON(data)) return;
  resources.set(resource, key, data, nextEnabled, apply === true);
}

function stableJSON(value) {
  if (value && typeof value === 'object') value = JSON.parse(JSON.stringify(value));
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (e) {
      // Keep non-JSON strings comparable as plain values.
    }
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) delete value.updated_at;
  return JSON.stringify(sortObject(value));
}

function sortObject(value) {
  if (Array.isArray(value)) {
    var out = [];
    for (var i = 0; i < value.length; i++) out.push(sortObject(value[i]));
    return out;
  }
  if (!value || typeof value !== 'object') return value;
  var keys = [];
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) keys.push(k);
  }
  keys.sort();
  var obj = {};
  for (var j = 0; j < keys.length; j++) {
    if (keys[j] === 'updated_at') continue;
    obj[keys[j]] = sortObject(value[keys[j]]);
  }
  return obj;
}

function ifaceList(value) {
  var raw = [];
  if (Array.isArray(value)) raw = value;
  else raw = text(value).split(',');
  var out = [];
  var seen = {};
  for (var i = 0; i < raw.length; i++) {
    var item = ifaceName(raw[i], 'port');
    if (seen[item]) continue;
    seen[item] = true;
    out.push(item);
  }
  return out;
}

function cidrList(value) {
  if (value == null || value === '') return [];
  if (Array.isArray(value)) {
    var out = [];
    for (var i = 0; i < value.length; i++) {
      var item = text(value[i]);
      if (item) out.push(item);
    }
    return out;
  }
  return [text(value)].filter(Boolean);
}

function cidrSet(values) {
  var out = {};
  for (var i = 0; i < values.length; i++) out[values[i]] = true;
  return out;
}

function firstArrayValue(value) {
  return Array.isArray(value) && value.length ? value[0] : '';
}

function firstPrefixValue(value) {
  if (!Array.isArray(value) || !value.length) return '';
  var first = value[0];
  if (first && typeof first === 'object') return text(first.prefix || first.cidr || '');
  return text(first || '');
}

function ipAddress(value) {
  value = text(value);
  var slash = value.indexOf('/');
  if (slash >= 0) value = value.slice(0, slash);
  return value;
}

function optionalIfaceName(value) {
  value = text(value);
  if (!value) return '';
  return ifaceName(value, 'interface');
}

function linkExists(name) {
  name = safeIfaceName(name);
  if (!name) return false;
  try {
    var info = net.link.get(name);
    return !!(info && info.name);
  } catch (e) {
    return false;
  }
}

function safeIfaceName(value) {
  try {
    return optionalIfaceName(value);
  } catch (e) {
    return '';
  }
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

function normalizeProtocol(value) {
  value = lower(value || 'tcp+udp');
  if (!value) return 'tcp+udp';
  var seen = {};
  var parts = value.split(/[^a-z0-9]+/);
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (!part) continue;
    if (part !== 'tcp' && part !== 'udp' && part !== 'icmp') {
      throw new Error('protocol must include one or more of tcp, udp, icmp');
    }
    seen[part] = true;
  }
  var out = [];
  if (seen.tcp) out.push('tcp');
  if (seen.udp) out.push('udp');
  if (seen.icmp) out.push('icmp');
  if (!out.length) throw new Error('protocol must include one or more of tcp, udp, icmp');
  return out.join('+');
}

function isProtectedBridgeName(value) {
  value = lower(value);
  return value.indexOf('vmbr') === 0;
}

function intValue(value, min, max, fallback) {
  var n = parseInt(value, 10);
  if (!isFinite(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
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

function token(value) {
  return lower(value || 'default').replace(/[^a-z0-9_.-]+/g, '-').replace(/^-+|-+$/g, '') || 'default';
}

function text(value) {
  return String(value == null ? '' : value).trim();
}

function lower(value) {
  return text(value).toLowerCase();
}

function merge(a, b) {
  var out = {};
  var k;
  for (k in a || {}) if (Object.prototype.hasOwnProperty.call(a, k)) out[k] = a[k];
  for (k in b || {}) if (Object.prototype.hasOwnProperty.call(b, k)) out[k] = b[k];
  return out;
}

function errorMessage(error) {
  return error && error.message ? error.message : String(error);
}
