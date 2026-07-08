plugin.capabilities(['lan', 'bridge', 'lan_ports', 'egress_nat_adapter', 'net_admin', 'control']);
plugin.virtualInterface({
  id: 'lan0',
  type: 'logical',
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
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: 'ac30d7e2604eede6c7752a7063ff10da6052c63dec687d6e9531d74e76688e4d',
  page: 'lan',
  page_title: 'LAN'
});

exports.onReconcile = function () {
  applyStoredProfiles();
  armRepairTimer();
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
  if (previous.phase === 'deleted' && safeIfaceName(previous.bridge || '') === plan.parent_interface) {
    setRecordIfChanged('status', key, previous, false);
    return;
  }
  setRecordIfChanged('status', key, {
    phase: 'disabled',
    lan_id: key,
    bridge: plan.parent_interface,
    wan_ref: token(raw.wan_ref || raw.wan || 'default'),
    egress_nat_plan: plan
  }, false);
}

function markApplyError(key, error) {
  key = token(key || 'default');
  var message = errorMessage(error);
  setEgressNATPlanIfChanged(key, {
    lan_id: key,
    source: 'lan_core',
    owner_plugin: 'lan_core',
    owner_key: key,
    enabled: false,
    note: 'disabled because lan_core failed to apply this profile',
    last_error: message
  }, false);
  setRecordIfChanged('status', key, {
    phase: 'error',
    lan_id: key,
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

  var wanEgress = resolveWanEgress(profile);
  var egressPlan = buildEgressNATPlan(plan.key, profile, wanEgress);
  setEgressNATPlanIfChanged(plan.key, egressPlan, egressPlan.enabled === true);
  var phase = (missingPorts.length || failedPorts.length) ? 'partial' : 'applied';
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
    ports: members,
    managed_ports: managedPorts,
    missing_ports: missingPorts,
    failed_ports: failedPorts,
    wan_ref: profile.wan_ref,
    wan_plugin: profile.wan_plugin,
    wan_egress: wanEgress,
    egress_nat_plan: egressPlan,
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
  var status = {
    phase: phase,
    lan_id: plan.key,
    bridge: profile.bridge,
    bridge_created: bridgeWasPluginCreated,
    bridge_preserved: profile.preserve_bridge,
    bridge_delete_skipped: bridgeDeleteSkipped,
    cleanup_errors: cleanupErrors,
    ports: profile.ports,
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

function normalizeProfile(key, raw) {
  raw = raw || {};
  var bridge = ifaceName(raw.bridge || raw.bridge_interface || 'br-lan', 'bridge');
  var ports = ifaceList(raw.ports || raw.member_ports || raw.interfaces || []);
  for (var i = 0; i < ports.length; i++) {
    if (ports[i] === bridge) throw new Error('LAN port must be different from bridge');
  }
  var addresses = cidrList(raw.addresses || raw.bridge_addresses || raw.ipv4_cidr || '192.168.100.1/24');
  return {
    profile_key: key,
    bridge: bridge,
    ports: ports,
    mtu: intValue(raw.mtu || raw.bridge_mtu, 576, 65535, 1500),
    addresses: addresses,
    wan_ref: token(raw.wan_ref || raw.wan || 'default'),
    wan_plugin: token(raw.wan_plugin || 'wan_core'),
    wan_egress_interface: optionalIfaceName(raw.wan_egress_interface || raw.out_interface || raw.wan_interface || ''),
    wan_egress_source_ip: text(raw.wan_egress_source_ip || raw.out_source_ip || raw.source_ip || ''),
    auto_egress_nat: bool(raw.auto_egress_nat, true),
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
    redirect_mode: '',
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
      var forwardCore = data.forward_core || {};
      result.redirect_mode = normalizeRedirectMode(data.egress_nat_redirect_mode || forwardCore.egress_nat_redirect_mode || '');
      result.source_ip = result.source_ip || ipAddress(data.ipv4 || firstArrayValue(data.host_addresses) || '');
      if (!result.interface) {
        result.phase = text(data.phase || '');
        result.interface = optionalIfaceName(data.egress_nat_parent_interface || forwardCore.egress_nat_interface || data.forward_parent_interface || forwardCore.parent_interface || data.host_interface || '');
        result.source = 'wan_core';
      }
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

function setRecordIfChangedApply(resource, key, data, enabled, apply) {
  var current = resources.get(resource, key);
  var currentData = current && current.data ? current.data : null;
  var currentEnabled = current ? current.enabled !== false : null;
  var nextEnabled = enabled !== false;
  if (current && currentEnabled === nextEnabled && stableJSON(currentData) === stableJSON(data)) return;
  resources.set(resource, key, data, nextEnabled, apply === true);
}

function stableJSON(value) {
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (e) {
      // Keep non-JSON strings comparable as plain values.
    }
  } else if (value && typeof value === 'object') {
    value = JSON.parse(JSON.stringify(value));
  }
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
