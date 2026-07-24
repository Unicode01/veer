var CONFIG_RESOURCE = 'config';
var CONFIG_KEY = 'default';
var ROUTER_OPERATION_KEY = 'router_default';
var ROUTER_APPLY_OPERATION = 'router.apply';
var ROUTER_TEARDOWN_OPERATION = 'router.teardown';
var ROUTER_RECOVERY_TIMER = 'router_operation_recovery';
var SERVICE_BY_PLUGIN = {
  wan_core: 'wan.adapter',
  lan_core: 'lan.adapter',
  pppoe_client: 'pppoe.client',
  vtolocal: 'local.handoff'
};

plugin.capabilities(['router_wizard', 'orchestration', 'wan_lan', 'control']);
plugin.resource({
  id: CONFIG_RESOURCE,
  description: 'Single router configuration. It contains only WAN and LAN intent; runtime changes are delegated to existing plugins.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 1,
  max_record_bytes: 32768,
  secret_fields: ['password', 'pppoe_password']
});
plugin.resource({
  id: 'status',
  description: 'Last orchestration result and compact downstream plugin status snapshot.',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 1,
  max_record_bytes: 32768
});
plugin.action({
  id: 'apply_router',
  description: 'Save the WAN/LAN config and apply the selected orchestration steps.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'teardown_router',
  description: 'Disable LAN and optional PPPoE/WAN handoff in safe order.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 32768
});
plugin.action({
  id: 'refresh_status',
  description: 'Refresh the wizard status snapshot without applying network changes.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 8192
});
plugin.service({
  id: 'router.orchestrator',
  version: '1.0.0',
  description: 'Transactional WAN and LAN router orchestration service.',
  actions: ['apply_router', 'teardown_router', 'refresh_status'],
  resources: ['config', 'status']
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  page: 'router',
  page_title: 'Router',
  resources: [
    {resource: 'config', methods: ['get', 'create', 'update']},
    {resource: 'status', methods: ['get']}
  ],
  actions: ['apply_router', 'teardown_router', 'refresh_status']
});

exports.onReconcile = function () {
  resumeRouterOperations();
  var cfg = storedConfig();
  if (!cfg) {
    setRecordIfChanged('status', CONFIG_KEY, refreshStatus(defaultConfig(), 'not_configured', []), false);
    return;
  }
  var previous = previousStatus();
  setRecordIfChanged('status', CONFIG_KEY, refreshStatus(cfg, previous.phase || 'stored', previous.steps || []), true);
};

exports.onDeactivate = function () {
  cancelActiveRouterOperation('router wizard deactivated');
  var cfg = storedConfig();
  if (cfg) teardownRouterAttempt(cfg);
};

exports.onTimer = function (ctx) {
  if (!ctx.timer || ctx.timer.name !== ROUTER_RECOVERY_TIMER) return;
  resumeRouterOperations();
};

exports.onAction = function (ctx) {
  var action = ctx.action && ctx.action.id;
  if (action === 'apply_router') return applyRouter(ctx.payload || {});
  if (action === 'teardown_router') return teardownRouter(ctx.payload || {});
  if (action === 'refresh_status') {
    var cfg = loadConfigFromPayload(ctx.payload || {});
    var status = refreshStatus(cfg, 'refreshed', []);
    setRecordIfChanged('status', CONFIG_KEY, status, true);
    return status;
  }
  throw new Error('unsupported action ' + action);
};

function applyRouter(payload) {
  var cfg = loadConfigFromPayload(payload);
  var previous = storedConfigRecord();
  var operation = operations.begin({
    key: ROUTER_OPERATION_KEY,
    kind: ROUTER_APPLY_OPERATION,
    input: {config: cfg, previous: previous},
    state: {phase: 'pending'},
    restart: true
  });
  armRouterOperationRecovery();
  return runRouterOperation(operation);
}

function applyRouterAttempt(cfg, previous) {
  var steps = [];
  var compensations = [];
  try {
    applyRouterConfig(cfg, steps, compensations);
    var status = refreshStatus(cfg, 'applied', steps);
    setRecordIfChanged('status', CONFIG_KEY, status, true);
    setRecordIfChanged(CONFIG_RESOURCE, CONFIG_KEY, cfg, true);
    return status;
  } catch (applyError) {
    var rollbackSteps = runCompensations(compensations);
    var restoreSteps = [];
    var restoreRollbackSteps = [];
    var previousConfig = enabledConfigFromRecord(previous);
    if (previousConfig) {
      var restoreCompensations = [];
      try {
        applyRouterConfig(previousConfig, restoreSteps, restoreCompensations);
      } catch (restoreError) {
        restoreRollbackSteps = runCompensations(restoreCompensations);
        restoreSteps.push(failedStep('restore.previous', restoreError));
      }
    }
    var rollbackFailed = hasFailedStep(rollbackSteps) || hasFailedStep(restoreSteps) || hasFailedStep(restoreRollbackSteps);
    var failureStatus = refreshStatus(cfg, rollbackFailed ? 'rollback_partial' : 'rolled_back', steps);
    failureStatus.last_error = errorMessage(applyError);
    failureStatus.rollback_steps = rollbackSteps;
    failureStatus.restore_steps = restoreSteps;
    failureStatus.restore_rollback_steps = restoreRollbackSteps;
    setRecordIfChanged('status', CONFIG_KEY, failureStatus, false);
    throw new Error(routerApplyFailureMessage(applyError, rollbackSteps, restoreSteps, restoreRollbackSteps));
  }
}

function applyRouterConfig(cfg, steps, compensations) {
  if (cfg.wan.mode === 'pppoe') {
    addCompensation(compensations, 'wan_core.teardown', function () {
      return callAction('wan_core', 'teardown', wanCorePayload(cfg));
    });
    runRequiredStep(steps, 'wan_core.prepare_handoff', function () {
      return callAction('wan_core', 'prepare_handoff', wanCorePreparePayload(cfg));
    });
    addCompensation(compensations, 'pppoe_client.disconnect', function () {
      return callAction('pppoe_client', 'disconnect', pppoePayload(cfg));
    });
    runRequiredStep(steps, 'pppoe_client.dial', function () {
      return callAction('pppoe_client', 'dial', pppoePayload(cfg));
    });
  } else {
    runRequiredStep(steps, 'wan.existing', function () {
      if (!cfg.wan.egress_interface) throw new Error('WAN egress interface is required');
      return {phase: 'ok'};
    });
  }

  addCompensation(compensations, 'lan_core.teardown', function () {
    return callAction('lan_core', 'teardown', lanPayload(cfg));
  });
  runRequiredStep(steps, 'lan_core.apply_network', function () {
    return callAction('lan_core', 'apply_network', lanPayload(cfg));
  });
}

function teardownRouter(payload) {
  var cfg = loadConfigFromPayload(payload);
  var operation = operations.begin({
    key: ROUTER_OPERATION_KEY,
    kind: ROUTER_TEARDOWN_OPERATION,
    input: {config: cfg},
    state: {phase: 'pending'},
    restart: true
  });
  armRouterOperationRecovery();
  return runRouterOperation(operation);
}

function teardownRouterAttempt(cfg) {
  var steps = [];
  setRecordIfChanged(CONFIG_RESOURCE, CONFIG_KEY, cfg, false);

  runStep(steps, 'lan_core.teardown', function () {
    return callAction('lan_core', 'teardown', lanPayload(cfg));
  });
  if (cfg.wan.mode === 'pppoe') {
    runStep(steps, 'pppoe_client.disconnect', function () {
      return callAction('pppoe_client', 'disconnect', pppoePayload(cfg));
    });
    runStep(steps, 'wan_core.teardown', function () {
      return callAction('wan_core', 'teardown', wanCorePayload(cfg));
    });
  }

  var failed = steps.some(function (step) { return step.ok === false; });
  var status = refreshStatus(cfg, failed ? 'teardown_partial' : 'deleted', steps);
  setRecordIfChanged('status', CONFIG_KEY, status, false);
  if (failed) throw new Error(firstFailedStepMessage(steps));
  return status;
}

function runRouterOperation(operation) {
  if (!operation || !operation.id) throw new Error('router operation is unavailable');
  if (!operation.resumable) return operation.result || refreshStatus(defaultConfig(), operation.status || 'idle', []);
  var claimed = operations.claim(operation.id, operation.revision);
  try {
    var input = claimed.input || {};
    var result;
    if (claimed.kind === ROUTER_APPLY_OPERATION) {
      result = applyRouterAttempt(normalizeConfig(input.config || {}), input.previous || null);
    } else if (claimed.kind === ROUTER_TEARDOWN_OPERATION) {
      result = teardownRouterAttempt(normalizeConfig(input.config || {}));
    } else {
      throw new Error('unsupported router operation kind ' + claimed.kind);
    }
    var completed = operations.complete(claimed.id, claimed.revision, result || {});
    settleRouterOperationRecovery();
    return completed.result || result;
  } catch (error) {
    var current = operations.get(claimed.id);
    if (current && current.status === 'running') {
      try {
        operations.fail(current.id, current.revision, {
          phase: 'failed',
          state: {failed_at: now(), error: errorMessage(error)},
          error: errorMessage(error)
        });
      } catch (journalError) {
        throw new Error(errorMessage(error) + '; persist router operation failure: ' + errorMessage(journalError));
      }
    }
    settleRouterOperationRecovery();
    throw error;
  }
}

function resumeRouterOperations() {
  var pending = operations.list({resumable: true, limit: 8});
  if (!pending.length) {
    settleRouterOperationRecovery();
    return;
  }
  armRouterOperationRecovery();
  for (var i = 0; i < pending.length; i++) {
    if (pending[i].key !== ROUTER_OPERATION_KEY) continue;
    try {
      runRouterOperation(pending[i]);
    } catch (error) {
      log.warn('router operation recovery failed: ' + errorMessage(error));
    }
  }
  settleRouterOperationRecovery();
}

function armRouterOperationRecovery() {
  timer.setInterval(ROUTER_RECOVERY_TIMER, 2000, {});
}

function settleRouterOperationRecovery() {
  var active = operations.list({limit: 8}).some(function (operation) {
    return operation.key === ROUTER_OPERATION_KEY &&
      (operation.status === 'pending' || operation.status === 'running' || operation.status === 'retry_wait');
  });
  if (!active) timer.clear(ROUTER_RECOVERY_TIMER);
}

function cancelActiveRouterOperation(reason) {
  var operation = operations.getByKey(ROUTER_OPERATION_KEY);
  if (!operation || (operation.status !== 'pending' && operation.status !== 'running')) return;
  try {
    var claimed = operations.claim(operation.id, operation.revision);
    operations.cancel(claimed.id, claimed.revision, {
      phase: 'cancelled',
      state: {cancelled_at: now()},
      error: reason || 'cancelled'
    });
  } catch (error) {
    log.warn('cancel router operation failed: ' + errorMessage(error));
  }
  settleRouterOperationRecovery();
}

function runStep(steps, name, fn) {
  try {
    var result = fn();
    steps.push({
      name: name,
      ok: true,
      detail: result && result.phase ? result.phase : 'ok',
      updated_at: now()
    });
  } catch (e) {
    steps.push({
      name: name,
      ok: false,
      error: errorMessage(e),
      updated_at: now()
    });
  }
}

function runRequiredStep(steps, name, fn) {
  try {
    var result = fn();
    steps.push(successStep(name, result));
    return result;
  } catch (e) {
    steps.push(failedStep(name, e));
    throw e;
  }
}

function addCompensation(compensations, name, fn) {
  compensations.push({name: name, run: fn});
}

function runCompensations(compensations) {
  var steps = [];
  for (var i = compensations.length - 1; i >= 0; i--) {
    var item = compensations[i];
    try {
      steps.push(successStep(item.name, item.run()));
    } catch (e) {
      steps.push(failedStep(item.name, e));
    }
  }
  return steps;
}

function successStep(name, result) {
  return {
    name: name,
    ok: true,
    detail: result && result.phase ? result.phase : 'ok',
    updated_at: now()
  };
}

function failedStep(name, error) {
  return {
    name: name,
    ok: false,
    error: errorMessage(error),
    updated_at: now()
  };
}

function hasFailedStep(steps) {
  return (steps || []).some(function (step) { return step && step.ok === false; });
}

function routerApplyFailureMessage(error, rollbackSteps, restoreSteps, restoreRollbackSteps) {
  var failures = [];
  [rollbackSteps, restoreSteps, restoreRollbackSteps].forEach(function (steps) {
    for (var i = 0; i < (steps || []).length; i++) {
      if (steps[i] && steps[i].ok === false) failures.push(steps[i].name + ': ' + steps[i].error);
    }
  });
  var message = errorMessage(error);
  if (failures.length) message += '; rollback: ' + failures.join('; ');
  return message;
}

function firstFailedStepMessage(steps) {
  for (var i = 0; i < steps.length; i++) {
    if (steps[i] && steps[i].ok === false) return steps[i].name + ': ' + steps[i].error;
  }
  return 'router wizard failed';
}

function refreshStatus(cfg, phase, steps) {
  var wanStatus = readPluginRecord('wan_core', 'status', cfg.wan.ref);
  var lanStatus = readPluginRecord('lan_core', 'status', cfg.lan.id);
  var egressPlan = readPluginRecord('lan_core', 'egress_nat_plans', cfg.lan.id);
  var pppoeLink = cfg.wan.mode === 'pppoe' ? readPluginRecord('pppoe_client', 'wan_links', cfg.wan.ref) : notUsedRecord('pppoe disabled');
  var pppoeLast = cfg.wan.mode === 'pppoe' ? readPluginRecord('pppoe_client', 'sessions', 'last') : notUsedRecord('pppoe disabled');
  return {
    phase: phase,
    wan_mode: cfg.wan.mode,
    wan_ref: cfg.wan.ref,
    lan_id: cfg.lan.id,
    lan_bridge: cfg.lan.bridge,
    lan_ports: cfg.lan.ports,
    wan_egress_interface: effectiveWANInterface(cfg, wanStatus, pppoeLink),
    auto_egress_nat: cfg.lan.auto_egress_nat,
    steps: steps || [],
    downstream: {
      wan_core: compactRecord(wanStatus),
      lan_core: compactRecord(lanStatus),
      egress_nat: compactRecord(egressPlan),
      pppoe_link: compactRecord(pppoeLink),
      pppoe_last: compactRecord(pppoeLast)
    },
    updated_at: now()
  };
}

function readPluginRecord(pluginID, resourceID, key) {
  if (!key) return notConfiguredRecord('empty record key');
  if (typeof plugins === 'undefined' || !plugins.resources || typeof plugins.resources.list !== 'function') {
    return unavailableRecord('plugins.resources is unavailable');
  }
  try {
    requireServiceEndpoint(pluginID, 'resources', resourceID);
    var records = plugins.resources.list(pluginID, resourceID, {limit: 128, offset: 0}) || [];
    for (var i = 0; i < records.length; i++) {
      if (records[i] && records[i].key === key) return records[i];
    }
    return {
      enabled: false,
      data: {
        phase: 'not_configured',
        configured: false,
        record_key: key,
        record_count_hint: records.length,
        note: 'downstream plugin/resource is reachable, but this record does not exist yet'
      }
    };
  } catch (listError) {
    return unavailableRecord(errorMessage(listError));
  }
}

function isMissingRecordError(error) {
  var message = lower(errorMessage(error));
  return message.indexOf('no rows') >= 0 || message.indexOf('record not found') >= 0 || message.indexOf('not found') >= 0;
}

function unavailableRecord(message) {
  return {
    enabled: false,
    data: {
      phase: 'unavailable',
      available: false,
      last_error: message
    }
  };
}

function notConfiguredRecord(note) {
  return {
    enabled: false,
    data: {
      phase: 'not_configured',
      configured: false,
      note: note || ''
    }
  };
}

function notUsedRecord(note) {
  return {
    enabled: false,
    data: {
      phase: 'not_used',
      configured: false,
      note: note || ''
    }
  };
}

function compactRecord(record) {
  if (!record) return {available: false, configured: false, phase: 'unavailable'};
  var data = record.data || {};
  var phase = text(data.phase || data.state || '');
  return {
    available: data.available === false ? false : true,
    configured: phase !== 'not_configured' && phase !== 'not_used' && phase !== 'unavailable',
    enabled: record.enabled !== false,
    phase: phase || 'available',
    interface: text(data.interface || data.local_interface || data.wan_interface || data.bridge || data.out_interface || ''),
    parent_interface: text(data.veer_parent_interface || data.egress_nat_parent_interface || data.parent_interface || ''),
    out_interface: text(data.out_interface || (data.egress_nat_plan && data.egress_nat_plan.out_interface) || ''),
    source_ip: text(data.out_source_ip || data.ipv4 || data.wan_egress_source_ip || ''),
    last_error: text(data.last_error || data.error || ''),
    note: text(data.note || ''),
    updated_at: text(data.updated_at || ''),
    data: data
  };
}

function callAction(pluginID, actionID, payload) {
  if (typeof plugins === 'undefined' || !plugins.services || typeof plugins.services.call !== 'function') {
    throw new Error('plugins.services.call is unavailable');
  }
  var service = requireServiceEndpoint(pluginID, 'actions', actionID);
  return plugins.services.call({
    service: service.id,
    version: '^1.0.0',
    provider: pluginID,
    action: actionID,
    payload: payload || {}
  });
}

function requireServiceEndpoint(pluginID, endpointKind, endpointID) {
  var serviceID = SERVICE_BY_PLUGIN[pluginID];
  if (!serviceID) throw new Error('no typed service is declared for plugin ' + pluginID);
  if (typeof plugins === 'undefined' || !plugins.services || typeof plugins.services.resolve !== 'function') {
    throw new Error('plugins.services.resolve is unavailable');
  }
  var provider = plugins.services.resolve({service: serviceID, version: '^1.0.0', provider: pluginID});
  var endpoints = provider && provider.service && provider.service[endpointKind];
  if (!Array.isArray(endpoints) || endpoints.indexOf(endpointID) < 0) {
    throw new Error('service ' + serviceID + ' from ' + pluginID + ' does not expose ' + endpointKind + ' endpoint ' + endpointID);
  }
  return provider.service;
}

function loadConfigFromPayload(payload) {
  payload = payload || {};
  return normalizeConfig(merge(storedConfig() || {}, payload));
}

function storedConfig() {
  var record = storedConfigRecord();
  return record && record.data ? normalizeConfig(record.data) : null;
}

function storedConfigRecord() {
  try {
    return resources.get(CONFIG_RESOURCE, CONFIG_KEY);
  } catch (e) {
    return null;
  }
}

function enabledConfigFromRecord(record) {
  if (!record || record.enabled === false || !record.data) return null;
  try {
    return normalizeConfig(record.data);
  } catch (e) {
    return null;
  }
}

function previousStatus() {
  try {
    var record = resources.get('status', CONFIG_KEY);
    return record && record.data ? record.data : {};
  } catch (e) {
    return {};
  }
}

function defaultConfig() {
  return normalizeConfig({lan: {dhcpv4_enabled: true, dns_mode: 'auto'}});
}

function normalizeConfig(raw) {
  raw = raw || {};
  var wan = raw.wan && typeof raw.wan === 'object' ? raw.wan : raw;
  var pppoe = wan.pppoe && typeof wan.pppoe === 'object' ? wan.pppoe : {};
  var lan = raw.lan && typeof raw.lan === 'object' ? raw.lan : raw;
  var mode = lower(wan.mode || raw.wan_mode || 'existing');
  if (mode !== 'existing' && mode !== 'pppoe') throw new Error('WAN mode must be existing or pppoe');
  var bridge = ifaceName(lan.bridge || raw.lan_bridge || raw.bridge || 'br-lan', 'LAN bridge');
  return {
    wan: {
      mode: mode,
      ref: token(wan.ref || raw.wan_ref || 'default'),
      egress_interface: optionalIfaceName(wan.egress_interface || raw.wan_egress_interface || raw.out_interface || ''),
      source_ip: text(wan.source_ip || raw.wan_egress_source_ip || raw.out_source_ip || ''),
      local_interface: ifaceName(wan.local_interface || raw.wan_local_interface || 'veerlocal0', 'WAN local interface'),
      mtu: intValue(wan.mtu || raw.wan_mtu || raw.mru, 576, 65535, 1492),
      pppoe: {
        interface: optionalIfaceName(firstDefined(pppoe.interface, wan.pppoe_interface, raw.pppoe_interface, raw.interface, '')),
        mac_mode: normalizeMACMode(firstDefined(pppoe.mac_mode, wan.mac_mode, raw.pppoe_mac_mode, pppoe.mac_address || wan.mac_address || raw.pppoe_mac_address ? 'manual' : 'random')),
        mac_address: text(firstDefined(pppoe.mac_address, wan.mac_address, raw.pppoe_mac_address, '')),
        username: text(firstDefined(pppoe.username, wan.username, raw.pppoe_username, raw.username, '')),
        password: text(firstDefined(pppoe.password, wan.password, raw.pppoe_password, raw.password, '')),
        service: text(firstDefined(pppoe.service, wan.service, raw.pppoe_service, raw.service, '')),
        auth: normalizeAuth(firstDefined(pppoe.auth, wan.auth, raw.pppoe_auth, raw.auth, 'pap')),
        negotiate_ipv6: bool(firstDefined(pppoe.negotiate_ipv6, wan.negotiate_ipv6, raw.pppoe_negotiate_ipv6), false),
        request_ipv6_address: bool(firstDefined(pppoe.request_ipv6_address, wan.request_ipv6_address, raw.pppoe_request_ipv6_address), true),
        request_ipv6_router: bool(firstDefined(pppoe.request_ipv6_router, wan.request_ipv6_router, raw.pppoe_request_ipv6_router), true),
        request_pd: bool(firstDefined(pppoe.request_pd, wan.request_pd, raw.pppoe_request_pd), false),
        dhcpv6_timeout_ms: intValue(firstDefined(pppoe.dhcpv6_timeout_ms, wan.dhcpv6_timeout_ms, raw.pppoe_dhcpv6_timeout_ms), 500, 30000, 5000),
        dhcpv6_settle_ms: intValue(firstDefined(pppoe.dhcpv6_settle_ms, wan.dhcpv6_settle_ms, raw.pppoe_dhcpv6_settle_ms), 0, 10000, 2000),
        ipv6_ra_timeout_ms: intValue(firstDefined(pppoe.ipv6_ra_timeout_ms, wan.ipv6_ra_timeout_ms, raw.pppoe_ipv6_ra_timeout_ms), 500, 30000, 5000),
        install_tunnel: bool(firstDefined(pppoe.install_tunnel, wan.install_tunnel, raw.pppoe_install_tunnel), true),
        auto_redial: bool(firstDefined(pppoe.auto_redial, wan.auto_redial, raw.pppoe_auto_redial), true),
        keepalive_interval_ms: intValue(firstDefined(pppoe.keepalive_interval_ms, wan.keepalive_interval_ms, raw.pppoe_keepalive_interval_ms), 0, 86400000, 15000),
        keepalive_failure_threshold: intValue(firstDefined(pppoe.keepalive_failure_threshold, wan.keepalive_failure_threshold, raw.pppoe_keepalive_failure_threshold), 1, 10, 5),
        keepalive_failure_grace_ms: intValue(firstDefined(pppoe.keepalive_failure_grace_ms, wan.keepalive_failure_grace_ms, raw.pppoe_keepalive_failure_grace_ms), 0, 3600000, 60000),
        keepalive_confirm_timeout_ms: intValue(firstDefined(pppoe.keepalive_confirm_timeout_ms, wan.keepalive_confirm_timeout_ms, raw.pppoe_keepalive_confirm_timeout_ms), 100, 30000, 5000)
      }
    },
    lan: {
      id: token(lan.id || raw.lan_id || 'default'),
      bridge: bridge,
      ports: ifaceList(lan.ports || raw.lan_ports || raw.ports || []),
      addresses: cidrList(lan.addresses || raw.lan_addresses || raw.addresses || '192.168.100.1/24'),
      mtu: intValue(lan.mtu || raw.lan_mtu || raw.mtu, 576, 65535, 1500),
      preserve_bridge: bool(firstDefined(lan.preserve_bridge, raw.preserve_bridge), isProtectedBridgeName(bridge)),
      dhcpv4_enabled: bool(firstDefined(lan.dhcpv4_enabled, raw.dhcpv4_enabled), false),
      dns_mode: normalizeDNSMode(firstDefined(lan.dns_mode, raw.dns_mode, 'auto')),
      dns_servers: dnsServerList(firstDefined(lan.dns_servers, raw.dns_servers, [])),
      auto_egress_nat: bool(firstDefined(lan.auto_egress_nat, raw.auto_egress_nat), true),
      protocol: normalizeProtocol(lan.protocol || raw.egress_nat_protocol || raw.protocol || 'tcp+udp+icmp'),
      nat_type: text(lan.nat_type || raw.egress_nat_type || raw.nat_type || 'symmetric'),
      redirect_mode: normalizeRedirectMode(lan.redirect_mode || raw.redirect_mode || raw.egress_nat_redirect_mode || '')
    }
  };
}

function pppoePayload(cfg) {
  var pppoe = cfg.wan.pppoe;
  if (!pppoe.interface) throw new Error('PPPoE interface is required');
  if (!pppoe.username) throw new Error('PPPoE username is required');
  return {
    profile_key: cfg.wan.ref,
    wan_id: cfg.wan.ref,
    interface: pppoe.interface,
    mac_mode: pppoe.mac_mode,
    mac_address: pppoe.mac_address,
    username: pppoe.username,
    password: pppoe.password,
    service: pppoe.service,
    auth: pppoe.auth,
    negotiate_ipv4: true,
    negotiate_ipv6: pppoe.negotiate_ipv6,
    request_ipv6_address: pppoe.negotiate_ipv6 && pppoe.request_ipv6_address,
    request_ipv6_router: pppoe.negotiate_ipv6 && pppoe.request_ipv6_router,
    request_pd: pppoe.request_pd,
    dhcpv6_timeout_ms: pppoe.dhcpv6_timeout_ms,
    dhcpv6_settle_ms: pppoe.dhcpv6_settle_ms,
    ipv6_ra_timeout_ms: pppoe.ipv6_ra_timeout_ms,
    auto_redial: pppoe.auto_redial,
    keepalive_interval_ms: pppoe.keepalive_interval_ms,
    keepalive_failure_threshold: pppoe.keepalive_failure_threshold,
    keepalive_failure_grace_ms: pppoe.keepalive_failure_grace_ms,
    keepalive_confirm_timeout_ms: pppoe.keepalive_confirm_timeout_ms,
    install_tunnel: pppoe.install_tunnel,
    local_interface: cfg.wan.local_interface,
    wan_core_sync: true,
    wan_core_apply: true,
    wan_core_plugin: 'wan_core',
    send_padt: false
  };
}

function wanCorePayload(cfg) {
  return {
    key: cfg.wan.ref,
    wan_id: cfg.wan.ref,
    profile_key: cfg.wan.ref,
    driver: cfg.wan.mode === 'pppoe' ? 'pppoe_client' : 'existing',
    driver_plugin: cfg.wan.mode === 'pppoe' ? 'pppoe_client' : 'router_wizard',
    state: 'up',
    usable: true,
    real_interface: cfg.wan.egress_interface || cfg.wan.pppoe.interface,
    wan_interface: cfg.wan.local_interface,
    mtu: cfg.wan.mtu,
    local_interface: cfg.wan.local_interface,
    handoff_mode: cfg.wan.mode === 'pppoe' ? 'segmented_veth' : 'direct',
    install_default_route: true,
    install_default_route_v6: cfg.wan.pppoe.negotiate_ipv6,
    egress_nat_redirect_mode: ''
  };
}

function wanCorePreparePayload(cfg) {
  var payload = wanCorePayload(cfg);
  payload.state = 'prepared';
  payload.usable = false;
  return payload;
}

function lanPayload(cfg) {
  if (cfg.wan.mode === 'existing' && !cfg.wan.egress_interface) {
    throw new Error('WAN egress interface is required');
  }
  return {
    key: cfg.lan.id,
    lan_id: cfg.lan.id,
    bridge: cfg.lan.bridge,
    ports: cfg.lan.ports,
    addresses: cfg.lan.addresses,
    mtu: cfg.lan.mtu,
    preserve_bridge: cfg.lan.preserve_bridge,
    dhcpv4_enabled: cfg.lan.dhcpv4_enabled,
    dns_mode: cfg.lan.dns_mode,
    dns_servers: cfg.lan.dns_servers,
    wan_ref: cfg.wan.ref,
    wan_plugin: 'wan_core',
    wan_egress_interface: cfg.wan.mode === 'existing' ? cfg.wan.egress_interface : '',
    wan_egress_source_ip: cfg.wan.source_ip,
    auto_egress_nat: cfg.lan.auto_egress_nat,
    protocol: cfg.lan.protocol,
    nat_type: cfg.lan.nat_type,
    redirect_mode: cfg.wan.mode === 'pppoe' ? '' : cfg.lan.redirect_mode
  };
}

function effectiveWANInterface(cfg, wanStatus, pppoeLink) {
  if (cfg.wan.egress_interface) return cfg.wan.egress_interface;
  var wanData = wanStatus && wanStatus.data ? wanStatus.data : {};
  var linkData = pppoeLink && pppoeLink.data ? pppoeLink.data : {};
  var veerCore = wanData.veer_core || {};
  return text(wanData.egress_nat_parent_interface || veerCore.egress_nat_interface ||
    wanData.veer_parent_interface || veerCore.parent_interface ||
    wanData.local_interface || linkData.local_interface || linkData.wan_interface || '');
}

function setRecordIfChanged(resource, key, data, enabled) {
  var current = null;
  try {
    current = resources.get(resource, key);
  } catch (e) {
    current = null;
  }
  var currentData = current && current.data ? current.data : null;
  var currentEnabled = current ? current.enabled !== false : null;
  var nextEnabled = enabled !== false;
  if (current && currentEnabled === nextEnabled && stableJSON(currentData) === stableJSON(data)) return;
  resources.set(resource, key, data, nextEnabled);
}

function stableJSON(value) {
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch (e) {
      // Compare non-JSON strings as plain values.
    }
  } else if (value && typeof value === 'object') {
    value = JSON.parse(JSON.stringify(value));
  }
  return JSON.stringify(sortObject(value));
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== 'object') return value;
  var keys = [];
  for (var k in value) {
    if (Object.prototype.hasOwnProperty.call(value, k)) keys.push(k);
  }
  keys.sort();
  var out = {};
  for (var i = 0; i < keys.length; i++) {
    if (keys[i] === 'updated_at') continue;
    out[keys[i]] = sortObject(value[keys[i]]);
  }
  return out;
}

function ifaceList(value) {
  var raw = Array.isArray(value) ? value : text(value).split(',');
  var out = [];
  var seen = {};
  for (var i = 0; i < raw.length; i++) {
    var item = optionalIfaceName(raw[i]);
    if (!item || seen[item]) continue;
    seen[item] = true;
    out.push(item);
  }
  return out;
}

function cidrList(value) {
  if (value == null || value === '') return [];
  var raw = Array.isArray(value) ? value : String(value).split(',');
  var out = [];
  for (var i = 0; i < raw.length; i++) {
    var item = text(raw[i]);
    if (item) out.push(item);
  }
  return out;
}

function normalizeProtocol(value) {
  value = lower(value || 'tcp+udp');
  var seen = {};
  var parts = value.split(/[^a-z0-9]+/);
  for (var i = 0; i < parts.length; i++) {
    var part = parts[i];
    if (!part) continue;
    if (part !== 'tcp' && part !== 'udp' && part !== 'icmp') throw new Error('protocol must include tcp, udp or icmp');
    seen[part] = true;
  }
  var out = [];
  if (seen.tcp) out.push('tcp');
  if (seen.udp) out.push('udp');
  if (seen.icmp) out.push('icmp');
  if (!out.length) throw new Error('protocol must include tcp, udp or icmp');
  return out.join('+');
}

function normalizeRedirectMode(value) {
  value = lower(value);
  if (value === 'prepared_l2' || value === 'raw_l2' || value === 'vtap') return 'prepared_l2';
  return '';
}

function normalizeDNSMode(value) {
  value = lower(value || 'auto');
  if (value === 'auto' || value === 'manual' || value === 'disabled') return value;
  throw new Error('DNS mode must be auto, manual or disabled');
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
  }
  return out;
}

function normalizeAuth(value) {
  value = lower(value || 'pap');
  if (value === 'pap' || value === 'chap') return value;
  throw new Error('PPPoE auth must be pap or chap');
}

function normalizeMACMode(value) {
  value = lower(value || 'random');
  if (value === 'random' || value === 'manual') return value;
  throw new Error('PPPoE MAC mode must be random or manual');
}

function optionalIfaceName(value) {
  value = text(value);
  if (!value) return '';
  return ifaceName(value, 'interface');
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

function isProtectedBridgeName(value) {
  return lower(value).indexOf('vmbr') === 0;
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

function firstDefined() {
  for (var i = 0; i < arguments.length; i++) {
    if (arguments[i] !== undefined && arguments[i] !== null && arguments[i] !== '') return arguments[i];
  }
  return undefined;
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

function now() {
  return new Date().toISOString();
}
