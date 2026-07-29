plugin.capabilities(['wan', 'local_route', 'veer_core_adapter', 'net_admin', 'control']);
var MAIN_ROUTE_TABLE = 254;
var AUTO_ROUTE_TABLE_BASE = 12000;
var AUTO_ROUTE_SLOT_COUNT = 8000;
var AUTO_RULE_PRIORITY_BASE = 10000;
pipeline.handoff({
  id: 'wan0',
  description: 'Linux L3 boundary shared by the system stack, Veer Core and an optional segmented protocol pipeline.'
});
plugin.resource({
  id: 'profiles',
  description: 'WAN handoff defaults such as the local interface, MTU, addresses, and route policy.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 16384
});
plugin.resource({
  id: 'sessions',
  description: 'Normalized WAN driver session state. Any protocol driver can publish this shape.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'runtime_apply',
  max_records: 32,
  max_record_bytes: 32768
});
plugin.resource({
  id: 'status',
  description: 'Last applied WAN adapter state and veer_core handoff details.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 32,
  max_record_bytes: 32768
});
plugin.action({
  id: 'apply_session',
  description: 'Apply a normalized WAN session from payload or the sessions resource.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'prepare_handoff',
  description: 'Create the plugin-managed local WAN boundary without publishing a usable WAN session.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'teardown',
  description: 'Delete the local WAN boundary when it is plugin-managed and mark the WAN adapter down.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.service({
  id: 'wan.adapter',
  version: '1.0.0',
  description: 'Protocol-neutral WAN session and Linux handoff service.',
  actions: ['apply_session', 'prepare_handoff', 'teardown'],
  resources: ['profiles', 'sessions', 'status']
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  sha256: '4d190cbe36e1571afc0db561fe6cc1f3f715a8aa4c953f882dbb145fb4639098',
  page: 'wan',
  page_title: 'WAN',
  resources: [
    {resource: 'profiles', methods: ['list', 'create', 'update']},
    {resource: 'sessions', methods: ['list']},
    {resource: 'status', methods: ['list']}
  ],
  actions: ['apply_session', 'prepare_handoff', 'teardown']
});

exports.onReconcile = function () {
  applyStoredSessions();
  armRepairTimer();
};

exports.onDeactivate = function () {
  timer.clear('wan_repair');
  var records = resources.list('sessions') || [];
  var failures = [];
  for (var i = 0; i < records.length; i++) {
    if (!records[i]) continue;
    try {
      teardownSession(loadPlan({key: records[i].key, session: records[i].data || {}}));
    } catch (e) {
      failures.push(token(records[i].key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (failures.length) throw new Error('WAN deactivate cleanup failed: ' + failures.join('; '));
};

exports.onResourceApply = function (ctx) {
  if (!ctx.resource || ctx.resource.id !== 'sessions') return;
  var records = ctx.records || [];
  try {
    applyRecords(records, true);
  } finally {
    armRepairTimer(mergedSessionRecords(records));
  }
};

exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== 'wan_repair') return;
  applyStoredSessions();
  armRepairTimer();
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply_session') {
    var plan = loadPlan(ctx.payload || {});
    setRecordIfChanged('profiles', plan.key, storedProfile(plan, ctx.payload || {}), true);
    setRecordIfChanged('sessions', plan.key, plan.session, true);
    applySession(plan);
    armRepairTimer();
    return;
  }
  if (action === 'prepare_handoff') {
    var preparePlan = loadPlan(ctx.payload || {});
    setRecordIfChanged('profiles', preparePlan.key, storedProfile(preparePlan, ctx.payload || {}), true);
    return prepareHandoff(preparePlan);
  }
  if (action === 'teardown') {
    teardownSession(loadPlan(ctx.payload || {}));
    armRepairTimer();
    return;
  }
  throw new Error('unsupported action ' + action);
};

function teardownSession(plan) {
  var previous = previousStatus(plan.key);
  resources.set('sessions', plan.key, plan.session, false);
  var previousTeardown = teardownPreviousState(previous, plan.profile);
  var cleanupErrors = cleanupManagedState(previousTeardown, teardownProfile(plan.profile));
  var deleteError = '';
  var deleteTarget = managedLinkProven(previousTeardown) ? safeIfaceName(previousTeardown.local_interface || '') : '';
  var deleteSkipped = !deleteTarget;
  var arpRestored = false;
  if (deleteTarget) {
    try {
      net.link.delete(deleteTarget);
    } catch (e) {
      deleteError = errorMessage(e);
    }
  } else {
    arpRestored = restorePreviousARP(previousTeardown, cleanupErrors);
  }
  var linkDeleted = !!deleteTarget && !deleteError;
  var arpStillManaged = linkDeleted ? false : (deleteError ? previousTeardown.arp_disabled_by_plugin === true :
    (!arpRestored && previousTeardown.arp_disabled_by_plugin === true));
  var status = {
    phase: 'deleted',
    wan_id: plan.key,
    local_interface: deleteTarget || plan.profile.local_interface,
    pipeline_interface: plan.profile.pipeline_interface,
    handoff_mode: plan.profile.handoff_mode,
    cleanup_errors: cleanupErrors,
    managed_link: previousTeardown.managed_link === true || !!deleteTarget,
    original_arp: previousTeardown.original_arp,
    arp_disabled_by_plugin: arpStillManaged,
    noarp_ready: arpStillManaged && previousTeardown.noarp_ready === true,
    arp_restored: arpRestored && previousTeardown.arp_disabled_by_plugin === true,
    link_delete_skipped: deleteSkipped,
    veer_core: veerCoreHandoff(plan.profile, false)
  };
  if (deleteError) {
    status.phase = 'delete_failed';
    status.last_error = deleteError;
  } else if (deleteSkipped) {
    status.link_delete_skip_reason = linkDeleteSkipReason(previousTeardown);
  } else if (cleanupErrors.length) {
    status.phase = 'delete_partial';
    status.last_error = cleanupErrors.join('; ');
  }
  setRecordIfChanged('status', plan.key, status, false);
}

function applyStoredSessions() {
  applyRecords(resources.list('sessions') || [], false);
}

function armRepairTimer(records) {
  var sessions = records || resources.list('sessions') || [];
  for (var i = 0; i < sessions.length; i++) {
    if (sessions[i] && sessions[i].enabled !== false) {
      timer.setInterval('wan_repair', 2000, {});
      return;
    }
  }
  timer.clear('wan_repair');
}

function mergedSessionRecords(records) {
  var out = [];
  var positions = {};
  var stored = resources.list('sessions') || [];
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
      disableSessionRuntime(record);
      continue;
    }
    try {
      applySession(loadPlan({key: record.key, session: record.data || {}}));
    } catch (e) {
      markApplyError(record.key, e);
      failures.push(token(record.key || 'default') + ': ' + errorMessage(e));
    }
  }
  if (reportErrors && failures.length) {
    throw new Error('failed to apply ' + failures.length + ' WAN session record(s): ' + failures.join('; '));
  }
}

function disableSessionRuntime(record) {
  var key = token(record && record.key || 'default');
  var raw = merge(record && record.data ? record.data : {}, {state: 'down', usable: false});
  var plan = loadPlan({key: key, session: raw});
  var previous = previousStatus(key);
  var localInterface = safeIfaceName(plan.profile.local_interface || raw.local_interface || '');
  var previousManaged = managedLinkProven(previous) && previousMatchesInterface(previous, localInterface);
  var previousSegmentationReady = previous.noarp_ready === true && !managedLinkChanged(previous, plan.profile);
  var cleanupErrors = previousManaged ? cleanupManagedState(previous, plan.profile) : [];
  var status = {
    phase: 'disabled',
    wan_id: key,
    profile_key: token(raw.profile_key || key),
    state: text(raw.state || raw.phase || ''),
    usable: false,
    driver: text(raw.driver || ''),
    driver_plugin: text(raw.driver_plugin || ''),
    real_interface: text(raw.real_interface || raw.interface || ''),
    wan_interface: text(raw.wan_interface || raw.real_interface || raw.interface || ''),
    local_interface: localInterface,
    pipeline_interface: plan.profile.pipeline_interface,
    handoff_mode: plan.profile.handoff_mode,
    addresses: plan.profile.addresses,
    routes: plan.profile.routes,
    cleanup_errors: cleanupErrors,
    managed_link: previousManaged,
    original_arp: previous.original_arp,
    arp_disabled_by_plugin: previous.arp_disabled_by_plugin === true && previousMatchesInterface(previous, localInterface),
    noarp_ready: previousSegmentationReady
  };
  if (localInterface) {
    status.veer_core = veerCoreHandoff({
      local_interface: localInterface,
      pipeline_interface: plan.profile.pipeline_interface,
      handoff_mode: plan.profile.handoff_mode,
      egress_nat_redirect_mode: ''
    }, previousSegmentationReady);
  }
  setRecordIfChanged('status', key, status, false);
}

function markApplyError(key, error) {
  key = token(key || 'default');
  var previous = previousStatus(key);
  previous.phase = 'error';
  previous.wan_id = key;
  previous.last_error = errorMessage(error);
  setRecordIfChanged('status', key, previous, false);
}

function loadPlan(payload) {
  payload = payload || {};
  var inlineSession = payload.session || payload.link || null;
  var key = token(payload.wan_id || payload.profile_key || payload.profile || payload.key ||
    (inlineSession && (inlineSession.wan_id || inlineSession.profile_key)) || 'default');
  var sessionRecord = resources.get('sessions', key);
  var sessionBase = sessionRecord && sessionRecord.data ? sessionRecord.data : {};
  var rawSession = merge(sessionBase, inlineSession || payload || {});
  var session = normalizeSession(key, rawSession);
  var profile = normalizeProfile(key, session, merge(merge(rawSession, loadProfile(key)), payload || {}));
  return {key: key, session: session, profile: profile};
}

function loadProfile(key) {
  var record = resources.get('profiles', key);
  return record && record.data ? record.data : {};
}

function storedProfile(plan, payload) {
  payload = payload || {};
  var inline = payload.session || payload.link || {};
  var previous = loadProfile(plan.key);
  var raw = merge(merge(previous, inline), payload);
  var profile = {
    profile_key: plan.key,
    local_interface: plan.profile.local_interface,
    pipeline_interface: plan.profile.pipeline_interface,
    handoff_mode: plan.profile.handoff_mode,
    mtu: plan.profile.mtu,
    interface_preparation: plan.profile.interface_preparation,
    addresses: cidrList(raw.addresses || raw.local_addresses || []),
    routes: Array.isArray(raw.routes) ? raw.routes.slice() : [],
    rules: Array.isArray(raw.rules) ? raw.rules.slice() : [],
    neighbors: Array.isArray(raw.neighbors) ? raw.neighbors.slice() : [],
    ipv6_route_table: plan.profile.ipv6_route_table,
    ipv6_rule_priority: plan.profile.ipv6_rule_priority,
    route_metric: plan.profile.route_metric,
    route_metric_v6: plan.profile.route_metric_v6,
    egress_nat_redirect_mode: plan.profile.egress_nat_redirect_mode
  };
  if (profileFieldSupplied(previous, inline, payload, 'install_default_route')) {
    profile.install_default_route = plan.profile.install_default_route;
  }
  if (profileFieldSupplied(previous, inline, payload, 'install_default_route_v6')) {
    profile.install_default_route_v6 = plan.profile.install_default_route_v6;
  }
  return profile;
}

function profileFieldSupplied(previous, inline, payload, name) {
  return Object.prototype.hasOwnProperty.call(previous || {}, name) ||
    Object.prototype.hasOwnProperty.call(inline || {}, name) ||
    Object.prototype.hasOwnProperty.call(payload || {}, name);
}

function applySession(plan) {
  var previous = previousStatus(plan.key);
  if (!sessionUsable(plan.session)) {
    var previousSegmentationReady = previous.noarp_ready === true && !managedLinkChanged(previous, plan.profile);
    setRecordIfChanged('status', plan.key, {
      phase: 'skipped',
      reason: 'wan session is not usable',
      wan_id: plan.key,
      state: plan.session.state,
      usable: plan.session.usable,
      driver: plan.session.driver,
      driver_plugin: plan.session.driver_plugin,
      real_interface: plan.session.real_interface,
      wan_interface: plan.session.wan_interface,
      local_interface: previous.local_interface || plan.profile.local_interface,
      pipeline_interface: previous.pipeline_interface || plan.profile.pipeline_interface,
      handoff_mode: previousHandoffMode(previous),
      managed_link: managedLinkProven(previous) && !managedLinkChanged(previous, plan.profile),
      original_arp: previous.original_arp,
      arp_disabled_by_plugin: previous.arp_disabled_by_plugin === true,
      segmentation_ready: previousSegmentationReady,
      noarp_ready: previousSegmentationReady,
      veer_core: veerCoreHandoff(plan.profile, previousSegmentationReady)
    }, false);
    return;
  }

  var replacement = replaceHandoffLink(previous, plan.profile);
  var cleanupErrors = replacement.cleanup_errors;
  var link = replacement.link;
  var sameManagedLink = managedLinkProven(previous) && !managedLinkChanged(previous, plan.profile);
  cleanupErrors = cleanupErrors.concat(cleanupManagedState(previous, plan.profile));
  replaceAddrs(plan.profile.local_interface, plan.profile.addresses);
  replaceNeighbors(plan.profile.local_interface, plan.profile.neighbors);
  replaceRoutes(plan.profile.local_interface, plan.profile.routes);
  replaceRules(plan.profile.rules);
  var handoff = veerCoreHandoff(plan.profile, link.noarp_ready === true);

  setRecordIfChanged('status', plan.key, {
    phase: 'applied',
    wan_id: plan.key,
    profile_key: plan.session.profile_key,
    driver: plan.session.driver,
    driver_plugin: plan.session.driver_plugin,
    state: plan.session.state,
    usable: plan.session.usable,
    real_interface: plan.session.real_interface,
    wan_interface: plan.session.wan_interface,
    local_interface: link.local.name,
    local_ifindex: link.local.ifindex,
    local_mac: link.local.mac,
    pipeline_interface: link.pipeline ? link.pipeline.name : '',
    pipeline_ifindex: link.pipeline ? link.pipeline.ifindex : 0,
    pipeline_mac: link.pipeline ? link.pipeline.mac : '',
    handoff_mode: link.mode,
    segmentation_ready: link.mode === 'segmented_veth' && !!link.pipeline && link.noarp_ready === true,
    noarp_ready: link.noarp_ready === true,
    original_arp: link.original_arp,
    arp_disabled_by_plugin: link.arp_disabled_by_plugin === true,
    mtu: plan.profile.mtu,
    interface_preparation_request: plan.profile.interface_preparation,
    interface_preparation: link.interface_preparation,
    ipv4: plan.session.ipv4,
    ipv4_peer: plan.session.ipv4_peer,
    ipv6: plan.session.ipv6,
    ipv6_addresses: plan.session.ipv6_addresses,
    ipv6_link_local: plan.session.ipv6_link_local,
    ipv6_peer_link_local: plan.session.ipv6_peer_link_local,
    ipv6_gateway: plan.session.ipv6_gateway,
    ipv6_prefix: plan.session.ipv6_prefix,
    pd_prefix: plan.session.pd_prefix,
    pd_prefixes: plan.session.pd_prefixes,
    dns_servers: plan.session.dns_servers,
    route_count: plan.profile.routes.length,
    rule_count: plan.profile.rules.length,
    neighbor_count: plan.profile.neighbors.length,
    addresses: plan.profile.addresses,
    routes: plan.profile.routes,
    rules: plan.profile.rules,
    neighbors: plan.profile.neighbors,
    ipv6_route_table: plan.profile.ipv6_route_table,
    ipv6_rule_priority: plan.profile.ipv6_rule_priority,
    cleanup_errors: cleanupErrors,
    managed_link: link.created === true || sameManagedLink,
    veer_core: handoff,
    veer_parent_interface: handoff.parent_interface,
    egress_nat_parent_interface: handoff.egress_nat_interface,
    egress_nat_redirect_mode: handoff.egress_nat_redirect_mode,
    egress_nat_virtual_source_ip: false
  });
}

function previousStatus(key) {
  var record = resources.get('status', key);
  return record && record.data ? record.data : {};
}

function cleanupManagedState(previous, profile) {
  previous = previous || {};
  var errors = [];
  if (!managedLinkProven(previous)) return errors;
  if (managedLinkChanged(previous, profile)) return errors;
  cleanupRemovedRules(previous.rules, profile.rules, errors);
  cleanupRemovedAddrs(previous.local_interface, previous.addresses, profile.local_interface, profile.addresses, errors);
  cleanupRemovedRoutes(previous.local_interface, previous.routes, profile.local_interface, profile.routes, errors);
  cleanupRemovedNeighbors(previous.local_interface, previous.neighbors, profile.local_interface, profile.neighbors, errors);
  return errors;
}

function cleanupManagedLinkReplacement(previous, profile) {
  previous = previous || {};
  var result = {errors: [], deleted: false};
  if (!managedLinkChanged(previous, profile)) return result;
  var local = safeIfaceName(previous.local_interface || '');
  if (!local) return result;
  cleanupRemovedRules(previous.rules, profile.rules, result.errors);
  if (!managedLinkProven(previous)) {
    restorePreviousARP(previous, result.errors);
    return result;
  }
  try {
    net.link.delete(local);
    result.deleted = true;
  } catch (e) {
    result.errors.push('old WAN handoff ' + local + ': ' + errorMessage(e));
  }
  return result;
}

function replaceHandoffLink(previous, profile) {
  var cleanup = cleanupManagedLinkReplacement(previous, profile);
  try {
    return {
      cleanup_errors: cleanup.errors,
      link: ensureHandoffLink(profile, previous)
    };
  } catch (e) {
    if (!cleanup.deleted) throw e;
    var rollbackError = rollbackPreviousHandoff(previous, profile);
    if (rollbackError) {
      throw new Error(errorMessage(e) + '; previous WAN handoff rollback failed: ' + rollbackError);
    }
    throw new Error(errorMessage(e) + '; previous WAN handoff restored');
  }
}

function rollbackPreviousHandoff(previous, nextProfile) {
  previous = previous || {};
  var local = safeIfaceName(previous.local_interface || '');
  if (!local) return 'previous local interface is unavailable';
  var mode = previousHandoffMode(previous);
  var pipeline = mode === 'segmented_veth' ? safeIfaceName(previous.pipeline_interface || '') : '';
  if (mode === 'segmented_veth' && !pipeline) return 'previous pipeline interface is unavailable';
  var profile = {
    local_interface: local,
    pipeline_interface: pipeline,
    handoff_mode: mode,
    mtu: intValue(previous.mtu, 576, 65535, intValue(nextProfile && nextProfile.mtu, 576, 65535, 1492)),
    addresses: cidrList(previous.addresses || []),
    routes: Array.isArray(previous.routes) ? previous.routes : [],
    rules: Array.isArray(previous.rules) ? previous.rules : [],
    neighbors: Array.isArray(previous.neighbors) ? previous.neighbors : [],
    interface_preparation: normalizeInterfacePreparation(previous.interface_preparation_request, previous.mtu)
  };
  try {
    ensureHandoffLink(profile, previous);
    replaceAddrs(profile.local_interface, profile.addresses);
    replaceNeighbors(profile.local_interface, profile.neighbors);
    replaceRoutes(profile.local_interface, profile.routes);
    replaceRules(profile.rules);
    return '';
  } catch (e) {
    return errorMessage(e);
  }
}

function managedLinkChanged(previous, profile) {
  previous = previous || {};
  profile = profile || {};
  var previousLocal = safeIfaceName(previous.local_interface || '');
  if (!previousLocal) return false;
  if (previousLocal !== safeIfaceName(profile.local_interface || '')) return true;
  var previousMode = previousHandoffMode(previous);
  var nextMode = normalizeHandoffMode(profile.handoff_mode || 'direct');
  if (previousMode !== nextMode) return true;
  if (nextMode === 'segmented_veth') {
    return safeIfaceName(previous.pipeline_interface || '') !== safeIfaceName(profile.pipeline_interface || '');
  }
  return false;
}

function previousHandoffMode(previous) {
  previous = previous || {};
  var veerCore = previous.veer_core || {};
  var mode = lower(previous.handoff_mode || veerCore.mode || '');
  return mode === 'segmented_veth' || mode === 'vtap' ? 'segmented_veth' : 'direct';
}

function managedLinkProven(previous) {
  previous = previous || {};
  if (previous.phase === 'deleted') return false;
  return previous.managed_link === true;
}

function previousMatchesInterface(previous, localInterface) {
  previous = previous || {};
  localInterface = safeIfaceName(localInterface || '');
  if (!localInterface) return false;
  return safeIfaceName(previous.local_interface || '') === localInterface;
}

function linkDeleteSkipReason(previous) {
  previous = previous || {};
  if (previous.managed_link === true && previous.phase === 'deleted') {
    return 'previous wan_core status already deleted this plugin-managed handoff';
  }
  return 'no previous wan_core status proves this handoff was plugin-managed';
}

function teardownProfile(profile) {
  return {
    local_interface: profile.local_interface,
    pipeline_interface: profile.pipeline_interface,
    handoff_mode: profile.handoff_mode,
    addresses: [],
    routes: [],
    rules: [],
    neighbors: []
  };
}

function teardownPreviousState(previous, profile) {
  previous = previous || {};
  return {
    phase: previous.phase || '',
    managed_link: previous.managed_link === true,
    local_interface: previous.local_interface || '',
    pipeline_interface: previous.pipeline_interface || '',
    handoff_mode: previousHandoffMode(previous),
    original_arp: previous.original_arp,
    arp_disabled_by_plugin: previous.arp_disabled_by_plugin === true,
    noarp_ready: previous.noarp_ready === true,
    interface_preparation_request: previous.interface_preparation_request || null,
    addresses: Array.isArray(previous.addresses) ? previous.addresses : [],
    routes: Array.isArray(previous.routes) ? previous.routes : [],
    rules: Array.isArray(previous.rules) ? previous.rules : [],
    neighbors: Array.isArray(previous.neighbors) ? previous.neighbors : []
  };
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

function cleanupRemovedRoutes(previousDefaultDev, previousRoutes, nextDefaultDev, nextRoutes, errors) {
  if (!Array.isArray(previousRoutes) || !previousRoutes.length) return;
  var next = routeSet(nextDefaultDev, nextRoutes);
  for (var i = 0; i < previousRoutes.length; i++) {
    var req = routeRequest(previousDefaultDev, previousRoutes[i]);
    if (!req || next[routeKey(req)]) continue;
    try {
      net.route.delete(req);
    } catch (e) {
      errors.push('route ' + req.dst + ' dev ' + req.dev + ': ' + errorMessage(e));
    }
  }
}

function cleanupRemovedRules(previousRules, nextRules, errors) {
  if (!Array.isArray(previousRules) || !previousRules.length) return;
  var next = ruleSet(nextRules);
  for (var i = 0; i < previousRules.length; i++) {
    var req = ruleRequest(previousRules[i]);
    if (!req || next[ruleKey(req)]) continue;
    try {
      net.rule.delete(req);
    } catch (e) {
      errors.push('rule priority ' + req.priority + ': ' + errorMessage(e));
    }
  }
}

function cleanupRemovedNeighbors(previousDefaultDev, previousNeighbors, nextDefaultDev, nextNeighbors, errors) {
  if (!Array.isArray(previousNeighbors) || !previousNeighbors.length) return;
  var next = neighborSet(nextDefaultDev, nextNeighbors);
  for (var i = 0; i < previousNeighbors.length; i++) {
    var req = neighborRequest(previousDefaultDev, previousNeighbors[i]);
    if (!req || next[neighborKey(req)]) continue;
    try {
      net.neigh.delete(req);
    } catch (e) {
      errors.push('neighbor ' + req.ip + ' dev ' + req.interface + ': ' + errorMessage(e));
    }
  }
}

function sessionUsable(session) {
  if (session.usable === false) return false;
  var state = lower(session.state);
  return state === '' || state === 'up' || state === 'ready' || state === 'active';
}

function prepareHandoff(plan) {
  var previous = previousStatus(plan.key);
  var replacement = replaceHandoffLink(previous, plan.profile);
  var cleanupErrors = replacement.cleanup_errors;
  var link = replacement.link;
  var sameManagedLink = managedLinkProven(previous) && !managedLinkChanged(previous, plan.profile);
  var handoff = veerCoreHandoff(plan.profile, link.noarp_ready === true);
  var status = {
    phase: cleanupErrors.length ? 'prepared_partial' : 'prepared',
    wan_id: plan.key,
    profile_key: plan.session.profile_key,
    driver: plan.session.driver,
    driver_plugin: plan.session.driver_plugin,
    state: plan.session.state || 'prepared',
    usable: false,
    real_interface: plan.session.real_interface,
    wan_interface: plan.session.wan_interface,
    local_interface: link.local.name,
    local_ifindex: link.local.ifindex,
    local_mac: link.local.mac,
    pipeline_interface: link.pipeline ? link.pipeline.name : '',
    pipeline_ifindex: link.pipeline ? link.pipeline.ifindex : 0,
    pipeline_mac: link.pipeline ? link.pipeline.mac : '',
    handoff_mode: link.mode,
    segmentation_ready: link.mode === 'segmented_veth' && !!link.pipeline && link.noarp_ready === true,
    noarp_ready: link.noarp_ready === true,
    original_arp: link.original_arp,
    arp_disabled_by_plugin: link.arp_disabled_by_plugin === true,
    mtu: plan.profile.mtu,
    interface_preparation_request: plan.profile.interface_preparation,
    interface_preparation: link.interface_preparation,
    addresses: plan.profile.addresses,
    cleanup_errors: cleanupErrors,
    managed_link: link.created === true || sameManagedLink,
    veer_core: handoff,
    note: 'The local boundary is prepared; WAN egress remains disabled until a usable session is applied.'
  };
  if (cleanupErrors.length) status.last_error = cleanupErrors.join('; ');
  setRecordIfChanged('status', plan.key, status, false);
  return status;
}

function ensureHandoffLink(profile, previous) {
  if (profile.handoff_mode === 'segmented_veth') {
    var pair = net.link.ensureVeth({
      host: profile.local_interface,
      peer: profile.pipeline_interface,
      mtu: profile.mtu,
      up: true
    });
    var arpState;
    var interfacePreparation;
    try {
      arpState = ensureSegmentedLocalARP(pair, previous, profile);
      interfacePreparation = prepareManagedHandoffInterfaces(profile, arpState.local, pair.peer);
    } catch (e) {
      if (pair.created === true) {
        try {
          net.link.delete(profile.local_interface);
        } catch (cleanupError) {
          throw new Error(errorMessage(e) + '; cleanup created veth: ' + errorMessage(cleanupError));
        }
      }
      throw e;
    }
    return {
      mode: 'segmented_veth',
      local: arpState.local,
      pipeline: pair.peer,
      created: pair.created === true,
      noarp_ready: arpState.noarp_ready,
      original_arp: arpState.original_arp,
      arp_disabled_by_plugin: arpState.arp_disabled_by_plugin,
      interface_preparation: interfacePreparation
    };
  }
  var dummy = net.link.ensureDummy({
    name: profile.local_interface,
    mtu: profile.mtu,
    up: true
  });
  try {
    return {
      mode: 'direct',
      local: dummy.link,
      pipeline: null,
      created: dummy.created === true,
      noarp_ready: false,
      original_arp: dummy.link.arp,
      arp_disabled_by_plugin: false,
      interface_preparation: prepareManagedHandoffInterfaces(profile, dummy.link, null)
    };
  } catch (e) {
    if (dummy.created === true) {
      try { net.link.delete(profile.local_interface); } catch (_) {}
    }
    throw e;
  }
}

function prepareManagedHandoffInterfaces(profile, local, pipeline) {
  var request = profile && profile.interface_preparation;
  var result = {applied: false, local_gso: null, local_offloads: null, pipeline_offloads: null, warnings: []};
  if (!request) return result;
  if (request.local_gso && local && local.name) {
    var gso = net.link.setGSO(local.name, request.local_gso);
    result.local_gso = {
      interface: local.name,
      max_size: gso.gso_max_size || request.local_gso.max_size,
      max_segs: gso.gso_max_segs || request.local_gso.max_segs
    };
  }
  result.local_offloads = prepareManagedHandoffOffloads(request, local, request.local_offloads, 'local', result.warnings);
  result.pipeline_offloads = prepareManagedHandoffOffloads(request, pipeline, request.pipeline_offloads, 'pipeline', result.warnings);
  result.applied = true;
  return result;
}

function prepareManagedHandoffOffloads(request, link, features, role, warnings) {
  if (!features || !link || !link.name) return null;
  try {
    net.link.setOffloads(link.name, features);
    return {interface: link.name, features: features};
  } catch (e) {
    if (!request.allow_unsafe_offloads) {
      throw new Error('prepare WAN handoff ' + role + ' offloads on ' + link.name + ': ' + errorMessage(e));
    }
    warnings.push({interface: link.name, role: role, warning: errorMessage(e)});
    return null;
  }
}

function ensureSegmentedLocalARP(pair, previous, profile) {
  pair = pair || {};
  previous = previous || {};
  var local = pair.host || {};
  var continued = !managedLinkChanged(previous, profile) &&
    safeIfaceName(previous.local_interface || '') === safeIfaceName(profile.local_interface || '') &&
    previousHandoffMode(previous) === 'segmented_veth';
  var originalARP = local.arp !== false;
  var disabledByPlugin = false;
  if (continued && previous.arp_disabled_by_plugin === true) {
    originalARP = previous.original_arp !== false;
    disabledByPlugin = true;
  }
  if (local.arp !== false) {
    local = net.link.setARP(profile.local_interface, false);
    disabledByPlugin = originalARP === true;
  }
  if (!local || local.arp !== false) {
    throw new Error('segmented WAN local interface did not enter NOARP state');
  }
  return {
    local: local,
    noarp_ready: true,
    original_arp: originalARP,
    arp_disabled_by_plugin: disabledByPlugin
  };
}

function restorePreviousARP(previous, errors) {
  previous = previous || {};
  errors = errors || [];
  if (previous.arp_disabled_by_plugin !== true || previous.original_arp !== true) return true;
  var local = safeIfaceName(previous.local_interface || '');
  if (!local) return true;
  try {
    net.link.setARP(local, true);
    return true;
  } catch (e) {
    errors.push('restore ARP ' + local + ': ' + errorMessage(e));
    return false;
  }
}

function veerCoreHandoff(profile, segmentationReady) {
  var segmented = profile.handoff_mode === 'segmented_veth';
  return {
    mode: segmented ? 'segmented_veth' : 'single_local_boundary',
    parent_interface: profile.local_interface,
    ingress_interface: profile.local_interface,
    route_interface: profile.local_interface,
    tunnel_interface: segmented ? profile.pipeline_interface : '',
    egress_nat_interface: profile.local_interface,
    egress_nat_redirect_mode: profile.egress_nat_redirect_mode,
    segmentation_ready: segmented && segmentationReady === true,
    note: segmented
      ? 'Veer/Egress NAT targets the local veth; the kernel segments GSO before the protocol plugin runs on the pipeline peer.'
      : 'Veer/Egress NAT redirects L3 traffic to the local boundary; the protocol plugin handles its TC hooks.'
  };
}

function normalizeSession(key, raw) {
  raw = raw || {};
  var ipv6Addresses = Array.isArray(raw.ipv6_addresses) ? raw.ipv6_addresses : [];
  var pdPrefixes = Array.isArray(raw.pd_prefixes) ? raw.pd_prefixes : [];
  var dnsServers = Array.isArray(raw.dns_servers) ? raw.dns_servers : [];
  return {
    wan_id: token(raw.wan_id || key),
    profile_key: token(raw.profile_key || key),
    driver: text(raw.driver || ''),
    driver_plugin: text(raw.driver_plugin || ''),
    state: text(raw.state || raw.phase || ''),
    usable: bool(raw.usable, true),
    real_interface: text(raw.real_interface || raw.interface || ''),
    wan_interface: text(raw.wan_interface || raw.real_interface || raw.interface || ''),
    peer_mac: text(raw.peer_mac || raw.ac_mac || raw.wan_dst_mac || ''),
    ipv4: text(raw.ipv4 || raw.ipv4_address || ''),
    ipv4_peer: text(raw.ipv4_peer || raw.peer_ipv4 || raw.gateway || ''),
    ipv6: text(raw.ipv6 || raw.ipv6_address || (ipv6Addresses[0] && ipv6Addresses[0].address) || ''),
    ipv6_addresses: ipv6Addresses,
    ipv6_link_local: text(raw.ipv6_link_local || ''),
    ipv6_peer_link_local: text(raw.ipv6_peer_link_local || raw.peer_ipv6_link_local || ''),
    ipv6_gateway: text(raw.ipv6_gateway || raw.ipv6_router || ''),
    ipv6_prefix: text(raw.ipv6_prefix || ''),
    pd_prefix: text(raw.pd_prefix || (pdPrefixes[0] && pdPrefixes[0].prefix) || ''),
    pd_prefixes: pdPrefixes,
    dns_servers: dnsServers,
    install_default_route_v6: bool(raw.install_default_route_v6, false),
    mtu: intValue(raw.mtu || raw.mru, 576, 65535, 1492),
    session_id: intValue(raw.session_id, 0, 65535, 0),
    updated_at: text(raw.updated_at || '')
  };
}

function normalizeProfile(key, session, raw) {
  raw = raw || {};
  var localInterface = text(raw.local_interface || 'veerlocal0');
  var handoffMode = normalizeHandoffMode(raw.handoff_mode || raw.pipeline_mode ||
    (lower(session.driver || raw.driver || raw.driver_plugin) === 'pppoe' || lower(raw.driver_plugin) === 'pppoe_client'
      ? 'segmented_veth'
      : 'direct'));
  var pipelineInterface = text(raw.pipeline_interface || raw.tunnel_interface || raw.vtap_interface ||
    (handoffMode === 'segmented_veth' ? derivedPipelineInterface(localInterface, key) : ''));
  if (handoffMode === 'segmented_veth' && localInterface === pipelineInterface) {
    throw new Error('local_interface and pipeline_interface must be different');
  }
  var addresses = cidrList(raw.addresses || raw.local_addresses || []);
  var routes = Array.isArray(raw.routes) ? raw.routes.slice() : [];
  var rules = Array.isArray(raw.rules) ? raw.rules.slice() : [];
  var neighbors = Array.isArray(raw.neighbors) ? raw.neighbors.slice() : [];
  var installDefaultRouteV6 = bool(raw.install_default_route_v6, session.install_default_route_v6);
  var routingIdentity = allocateIPv6RoutingIdentity(key, raw);
  if (sessionUsable(session)) {
    addresses = appendCIDRUnique(addresses, ipv4HostCIDR(session.ipv4));
    addresses = appendCIDRUnique(addresses, ipv6HostCIDR(session.ipv6));
    addresses = appendCIDRUnique(addresses, ipv6LinkLocalCIDR(session.ipv6_link_local));
    var ipv4PeerCIDR = ipv4HostCIDR(session.ipv4_peer);
    if (handoffMode === 'segmented_veth' && session.ipv4 && ipv4PeerCIDR) {
      routes = appendRouteUnique(routes, {dst: ipv4PeerCIDR, dev: localInterface, src: session.ipv4});
    }
    if (bool(raw.install_default_route, false) && session.ipv4) {
      routes = appendRouteUnique(routes, {dst: '0.0.0.0/0', dev: localInterface, src: session.ipv4, metric: intValue(raw.route_metric, 0, 2147483647, 0)});
    }
    if (installDefaultRouteV6) {
      if (handoffMode === 'segmented_veth') {
        var sourcePrefix = ipv6RouteSourcePrefix(session);
        var gateway = text(session.ipv6_gateway || session.ipv6_peer_link_local || '');
        if (!sourcePrefix || !gateway || !session.peer_mac) {
          throw new Error('segmented IPv6 default route requires delegated/source prefix, IPv6 peer gateway and peer MAC');
        }
        routes = appendRouteUnique(routes, {
          dst: '::/0', dev: localInterface, gateway: gateway, table: routingIdentity.table,
          metric: intValue(raw.route_metric_v6, 0, 2147483647, 0)
        });
        rules = appendRuleUnique(rules, {
          family: 'ipv6', priority: routingIdentity.priority, table: MAIN_ROUTE_TABLE, dst: sourcePrefix
        });
        rules = appendRuleUnique(rules, {
          family: 'ipv6', priority: routingIdentity.priority + 1, table: routingIdentity.table, src: sourcePrefix
        });
        neighbors = appendNeighborUnique(neighbors, {
          interface: localInterface, ip: gateway, mac: session.peer_mac, state: 'permanent'
        });
      } else if (session.ipv6) {
        routes = appendRouteUnique(routes, {
          dst: '::/0', dev: localInterface, src: session.ipv6,
          metric: intValue(raw.route_metric_v6, 0, 2147483647, 0)
        });
      }
    }
  }
  var mtu = intValue(raw.mtu || session.mtu, 576, 65535, 1492);
  return {
    profile_key: key,
    local_interface: ifaceName(localInterface, 'local_interface'),
    pipeline_interface: handoffMode === 'segmented_veth' ? ifaceName(pipelineInterface, 'pipeline_interface') : '',
    handoff_mode: handoffMode,
    mtu: mtu,
    interface_preparation: normalizeInterfacePreparation(raw.interface_preparation, mtu),
    addresses: addresses,
    routes: routes,
    rules: rules,
    neighbors: neighbors,
    ipv6_route_table: routingIdentity.table,
    ipv6_rule_priority: routingIdentity.priority,
    install_default_route: bool(raw.install_default_route, false),
    install_default_route_v6: installDefaultRouteV6,
    route_metric: intValue(raw.route_metric, 0, 2147483647, 0),
    route_metric_v6: intValue(raw.route_metric_v6, 0, 2147483647, 0),
    egress_nat_redirect_mode: normalizeRedirectMode(raw.egress_nat_redirect_mode || raw.redirect_mode || '')
  };
}

function allocateIPv6RoutingIdentity(key, raw) {
  var explicitTable = intValue(raw.ipv6_route_table || raw.route_table_v6, 1, 2147483647, 0);
  var explicitPriority = intValue(raw.ipv6_rule_priority || raw.rule_priority_v6, 1, 32764, 0);
  var usedTables = {};
  var usedPriorities = {};
  var records = (resources.list('profiles') || []).concat(resources.list('status') || []);
  for (var i = 0; i < records.length; i++) {
    var record = records[i];
    if (!record || token(record.key || 'default') === token(key || 'default')) continue;
    var data = record.data || {};
    var table = intValue(data.ipv6_route_table || data.route_table_v6, 1, 2147483647, 0);
    var priority = intValue(data.ipv6_rule_priority || data.rule_priority_v6, 1, 32764, 0);
    if (table) usedTables[table] = true;
    if (priority) {
      usedPriorities[priority] = true;
      usedPriorities[priority + 1] = true;
    }
  }
  if (explicitTable && usedTables[explicitTable]) throw new Error('ipv6_route_table is already assigned to another WAN profile');
  if (explicitPriority && (usedPriorities[explicitPriority] || usedPriorities[explicitPriority + 1])) {
    throw new Error('ipv6_rule_priority overlaps another WAN profile');
  }
  if (explicitTable && explicitPriority) return {table: explicitTable, priority: explicitPriority};

  var start = stableTokenHash(key) % AUTO_ROUTE_SLOT_COUNT;
  for (var offset = 0; offset < AUTO_ROUTE_SLOT_COUNT; offset++) {
    var slot = (start + offset) % AUTO_ROUTE_SLOT_COUNT;
    var candidateTable = explicitTable || (AUTO_ROUTE_TABLE_BASE + slot);
    var candidatePriority = explicitPriority || (AUTO_RULE_PRIORITY_BASE + slot * 2);
    if (usedTables[candidateTable] || usedPriorities[candidatePriority] || usedPriorities[candidatePriority + 1]) continue;
    return {table: candidateTable, priority: candidatePriority};
  }
  throw new Error('no free IPv6 WAN routing identity is available');
}

function stableTokenHash(value) {
  value = token(value || 'default');
  var hash = 2166136261;
  for (var i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0;
}

function ipv6RouteSourcePrefix(session) {
  var value = text(session.pd_prefix || session.ipv6_prefix || '');
  if (value) return value;
  value = text(session.ipv6 || '');
  return value ? value + '/128' : '';
}

function normalizeInterfacePreparation(value, mtu) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  var localGSO = null;
  if (value.local_gso && typeof value.local_gso === 'object' && !Array.isArray(value.local_gso)) {
    localGSO = {
      max_size: intValue(value.local_gso.max_size, 576, 65536, intValue(mtu, 576, 65536, 1492)),
      max_segs: intValue(value.local_gso.max_segs, 1, 65535, 1)
    };
  }
  var localOffloads = normalizeOffloadSettings(value.local_offloads);
  var pipelineOffloads = normalizeOffloadSettings(value.pipeline_offloads);
  if (!localGSO && !localOffloads && !pipelineOffloads) return null;
  return {
    local_gso: localGSO,
    local_offloads: localOffloads,
    pipeline_offloads: pipelineOffloads,
    allow_unsafe_offloads: bool(value.allow_unsafe_offloads, false)
  };
}

function normalizeOffloadSettings(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  var names = ['rx', 'tx', 'sg', 'tso', 'ufo', 'gso', 'gro', 'lro'];
  var out = {};
  var count = 0;
  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    if (!Object.prototype.hasOwnProperty.call(value, name)) continue;
    out[name] = value[name] === true;
    count++;
  }
  return count ? out : null;
}

function normalizeHandoffMode(value) {
  value = lower(value);
  if (value === 'segmented' || value === 'segmented_veth' || value === 'veth' || value === 'vtap') {
    return 'segmented_veth';
  }
  return 'direct';
}

function derivedPipelineInterface(localInterface, key) {
  var seed = text(localInterface) + '|' + token(key || 'default');
  var hash = 2166136261;
  for (var i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  var suffix = ('00000000' + hash.toString(16)).slice(-8);
  return 'veerp' + suffix;
}

function replaceAddrs(iface, addrs) {
  for (var i = 0; i < addrs.length; i++) {
    net.addr.replace({interface: iface, cidr: addrs[i]});
  }
}

function replaceRoutes(defaultDev, routes) {
  for (var i = 0; i < routes.length; i++) {
    var req = routeRequest(defaultDev, routes[i]);
    if (req) net.route.replace(req);
  }
}

function replaceRules(rules) {
  for (var i = 0; i < rules.length; i++) {
    var req = ruleRequest(rules[i]);
    if (req) net.rule.replace(req);
  }
}

function replaceNeighbors(defaultDev, neighbors) {
  for (var i = 0; i < neighbors.length; i++) {
    var req = neighborRequest(defaultDev, neighbors[i]);
    if (req) net.neigh.replace(req);
  }
}

function routeSet(defaultDev, routes) {
  var out = {};
  if (!Array.isArray(routes)) return out;
  for (var i = 0; i < routes.length; i++) {
    var req = routeRequest(defaultDev, routes[i]);
    if (req) out[routeKey(req)] = true;
  }
  return out;
}

function routeRequest(defaultDev, route) {
  route = route || {};
  var dst = route.dst || route.destination || route.cidr;
  if (!dst) return null;
  var dev = safeIfaceName(route.dev || route.interface || defaultDev);
  if (!dev) return null;
  return {
    dst: text(dst),
    dev: dev,
    gateway: route.gateway || route.gw || '',
    src: route.src || route.source || '',
    table: intValue(route.table, 0, 2147483647, 0),
    metric: intValue(route.metric, 0, 2147483647, 0),
    scope: routeScope(route, dst)
  };
}

function routeKey(req) {
  return [req.dst, req.dev, req.gateway || '', req.src || '', req.table || 0, req.metric || 0, req.scope || 0].join('|');
}

function ruleSet(rules) {
  var out = {};
  if (!Array.isArray(rules)) return out;
  for (var i = 0; i < rules.length; i++) {
    var req = ruleRequest(rules[i]);
    if (req) out[ruleKey(req)] = true;
  }
  return out;
}

function ruleRequest(rule) {
  rule = rule || {};
  var priority = intValue(rule.priority || rule.pref, 1, 32765, 0);
  var table = intValue(rule.table || rule.table_id, 1, 2147483647, 0);
  if (!priority || !table) return null;
  var req = {
    family: lower(rule.family || ''),
    priority: priority,
    table: table,
    src: text(rule.src || rule.source || rule.from || ''),
    dst: text(rule.dst || rule.destination || rule.to || ''),
    invert: rule.invert === true
  };
  var iif = safeIfaceName(rule.iif || rule.in_interface || '');
  var oif = safeIfaceName(rule.oif || rule.out_interface || '');
  if (iif) req.iif = iif;
  if (oif) req.oif = oif;
  if (rule.mark != null || rule.fwmark != null) req.mark = Number(rule.mark != null ? rule.mark : rule.fwmark) >>> 0;
  if (rule.mask != null || rule.fwmask != null) req.mask = Number(rule.mask != null ? rule.mask : rule.fwmask) >>> 0;
  return req;
}

function ruleKey(req) {
  return [req.family || '', req.priority, req.table, req.src || '', req.dst || '', req.iif || '', req.oif || '',
    req.mark == null ? '' : req.mark, req.mask == null ? '' : req.mask, req.invert === true ? 1 : 0].join('|');
}

function neighborSet(defaultDev, neighbors) {
  var out = {};
  if (!Array.isArray(neighbors)) return out;
  for (var i = 0; i < neighbors.length; i++) {
    var req = neighborRequest(defaultDev, neighbors[i]);
    if (req) out[neighborKey(req)] = true;
  }
  return out;
}

function neighborRequest(defaultDev, neighbor) {
  neighbor = neighbor || {};
  var iface = safeIfaceName(neighbor.interface || neighbor.dev || defaultDev);
  var ip = text(neighbor.ip || neighbor.address || '');
  if (!iface || !ip) return null;
  return {
    interface: iface,
    ip: ip,
    mac: text(neighbor.mac || neighbor.lladdr || ''),
    state: lower(neighbor.state || 'permanent'),
    vlan: intValue(neighbor.vlan, 0, 4095, 0)
  };
}

function neighborKey(req) {
  return [req.interface, req.ip, req.mac || '', req.state || '', req.vlan || 0].join('|');
}

function cidrSet(values) {
  var out = {};
  for (var i = 0; i < values.length; i++) out[values[i]] = true;
  return out;
}

function setRecordIfChanged(resource, key, data, enabled) {
  var current = resources.get(resource, key);
  var currentData = current && current.data ? current.data : null;
  var currentEnabled = current ? current.enabled !== false : null;
  var nextEnabled = enabled !== false;
  if (current && currentEnabled === nextEnabled && stableJSON(currentData) === stableJSON(data)) return;
  resources.set(resource, key, data, nextEnabled);
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

function routeScope(route, dst) {
  if (route.scope != null && route.scope !== '') return intValue(route.scope, 0, 255, 0);
  if (route.gateway || route.gw || isDefaultRoute(dst)) return 0;
  return 253;
}

function isDefaultRoute(dst) {
  dst = lower(dst);
  return dst === '' || dst === 'default' || dst === '0.0.0.0/0' || dst === '::/0';
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

function appendCIDRUnique(values, cidr) {
  cidr = text(cidr);
  if (!cidr) return values;
  var out = Array.isArray(values) ? values.slice() : [];
  for (var i = 0; i < out.length; i++) {
    if (out[i] === cidr) return out;
  }
  out.push(cidr);
  return out;
}

function ipv4HostCIDR(value) {
  value = text(value);
  if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return '';
  var parts = value.split('.');
  for (var i = 0; i < parts.length; i++) {
    var n = parseInt(parts[i], 10);
    if (!isFinite(n) || n < 0 || n > 255) return '';
  }
  return value + '/32';
}

function ipv6HostCIDR(value) {
  value = text(value);
  if (!value || value.indexOf(':') < 0 || /[\s/]/.test(value)) return '';
  return value + '/128';
}

function ipv6LinkLocalCIDR(value) {
  value = text(value);
  if (!value || value.indexOf(':') < 0 || /[\s/]/.test(value)) return '';
  return value + '/64';
}

function appendRouteUnique(routes, route) {
  var out = Array.isArray(routes) ? routes.slice() : [];
  var wanted = routeKey(routeRequest(route.dev || '', route));
  for (var i = 0; i < out.length; i++) {
    var existing = routeRequest(route.dev || '', out[i]);
    if (existing && routeKey(existing) === wanted) return out;
  }
  out.push(route);
  return out;
}

function appendRuleUnique(rules, rule) {
  var out = Array.isArray(rules) ? rules.slice() : [];
  var wanted = ruleRequest(rule);
  if (!wanted) return out;
  var wantedKey = ruleKey(wanted);
  for (var i = 0; i < out.length; i++) {
    var existing = ruleRequest(out[i]);
    if (existing && ruleKey(existing) === wantedKey) return out;
  }
  out.push(rule);
  return out;
}

function appendNeighborUnique(neighbors, neighbor) {
  var out = Array.isArray(neighbors) ? neighbors.slice() : [];
  var wanted = neighborRequest(neighbor.interface || neighbor.dev || '', neighbor);
  if (!wanted) return out;
  var wantedKey = neighborKey(wanted);
  for (var i = 0; i < out.length; i++) {
    var existing = neighborRequest(neighbor.interface || neighbor.dev || '', out[i]);
    if (existing && neighborKey(existing) === wantedKey) return out;
  }
  out.push(neighbor);
  return out;
}

function normalizeRedirectMode(value) {
  value = lower(value);
  if (value === 'prepared_l2' || value === 'raw_l2' || value === 'vtap') return 'prepared_l2';
  return '';
}

function ifaceName(value, label) {
  value = text(value);
  if (!value || utf8ByteLength(value) > 15 || /[\/\\\s\u0000]/.test(value)) {
    throw new Error(label + ' contains invalid characters or exceeds 15 bytes');
  }
  return value;
}

function safeIfaceName(value) {
  try {
    value = text(value);
    if (!value) return '';
    return ifaceName(value, 'interface');
  } catch (e) {
    return '';
  }
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
