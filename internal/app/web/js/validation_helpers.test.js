const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createInput(name) {
  return {
    name,
    focused: false,
    ariaInvalid: false,
    errorMessage: '',
    value: '',
    checked: false,
    disabled: false,
    hidden: false,
    style: {},
    dataset: {},
    classList: {
      add() {},
      remove() {},
      toggle() {}
    },
    focus() {
      this.focused = true;
    },
    addEventListener() {},
    querySelectorAll() {
      return [];
    },
    querySelector() {
      return null;
    },
    closest() {
      return null;
    },
    reset() {},
    scrollIntoView() {},
    hasAttribute(attr) {
      return attr === 'aria-invalid' ? this.ariaInvalid : false;
    },
    setAttribute(attr) {
      if (attr === 'aria-invalid') this.ariaInvalid = true;
    },
    removeAttribute(attr) {
      if (attr === 'aria-invalid') this.ariaInvalid = false;
    }
  };
}

function translate(dict, key, params) {
  let text = Object.prototype.hasOwnProperty.call(dict, key) ? dict[key] : key;
  if (!params) return text;
  return text.replace(/\{\{(\w+)\}\}/g, (_, name) => {
    if (!Object.prototype.hasOwnProperty.call(params, name)) return '';
    return params[name] == null ? '' : String(params[name]);
  });
}

function loadScript(context, filename) {
  const code = fs.readFileSync(filename, 'utf8');
  vm.runInContext(code, context, { filename });
}

function createHarness() {
  const translations = {
    'common.delete': 'Delete',
    'common.cancel': 'Cancel',
    'errors.operationFailed': 'Operation failed: {{message}}',
    'errors.deleteFailed': 'Delete failed: {{message}}',
    'validation.ruleNotFound': 'The rule no longer exists.',
    'validation.siteNotFound': 'The site no longer exists.',
    'validation.rangeNotFound': 'The range mapping no longer exists.',
    'validation.required': 'This field is required.',
    'validation.invalidID': 'The ID is invalid.',
    'validation.positiveId': 'The ID must be greater than 0.',
    'validation.portRange': 'Ports must be between 1 and 65535.',
    'validation.protocol': 'Protocol must be tcp, udp, or tcp+udp.',
    'validation.transparentIPv4Only': 'Transparent mode currently supports IPv4 only in this phase.',
    'validation.ruleBatchRequired': 'At least one batch operation is required.',
    'validation.sourceIPBackendFamily': 'Backend source IP must match the backend IP family.',
    'validation.rangeOrder': 'The start port must not exceed the end port.',
    'validation.issueJoiner': '; ',
    'validation.issueSummaryMore': '{{messages}} (and {{count}} more)',
    'validation.reviewErrors': 'Review the highlighted fields.'
  };

  const elements = {
    editRuleId: createInput('editRuleId'),
    inInterface: createInput('inInterface'),
    inIP: createInput('inIP'),
    inPort: createInput('inPort'),
    outInterface: createInput('outInterface'),
    outIP: createInput('outIP'),
    outPort: createInput('outPort'),
    protocol: createInput('protocol'),
    ruleOutSourceIP: createInput('ruleOutSourceIP'),
    ruleTransparent: createInput('ruleTransparent'),
    editSiteId: createInput('editSiteId'),
    siteDomain: createInput('siteDomain'),
    siteTag: createInput('siteTag'),
    siteListenIface: createInput('siteListenIface'),
    siteListenIP: createInput('siteListenIP'),
    siteBackendIP: createInput('siteBackendIP'),
    siteBackendSourceIP: createInput('siteBackendSourceIP'),
    siteBackendHTTP: createInput('siteBackendHTTP'),
    siteBackendHTTPS: createInput('siteBackendHTTPS'),
    siteTransparent: createInput('siteTransparent'),
    editRangeId: createInput('editRangeId'),
    rangeInInterface: createInput('rangeInInterface'),
    rangeInIP: createInput('rangeInIP'),
    rangeStartPort: createInput('rangeStartPort'),
    rangeEndPort: createInput('rangeEndPort'),
    rangeOutInterface: createInput('rangeOutInterface'),
    rangeOutIP: createInput('rangeOutIP'),
    rangeOutSourceIP: createInput('rangeOutSourceIP'),
    rangeOutStartPort: createInput('rangeOutStartPort'),
    rangeProtocol: createInput('rangeProtocol'),
    rangeTransparent: createInput('rangeTransparent'),
    rangeTag: createInput('rangeTag'),
    tokenSubmit: createInput('tokenSubmit'),
    tokenInput: createInput('tokenInput'),
    logoutBtn: createInput('logoutBtn'),
    ruleForm: createInput('ruleForm'),
    siteForm: createInput('siteForm'),
    rangeForm: createInput('rangeForm'),
    ruleCancelBtn: createInput('ruleCancelBtn'),
    siteCancelBtn: createInput('siteCancelBtn'),
    rangeCancelBtn: createInput('rangeCancelBtn'),
    batchDeleteRulesBtn: createInput('batchDeleteRulesBtn'),
    rulesSelectAll: createInput('rulesSelectAll'),
    inPort: createInput('inPort'),
    outPort: createInput('outPort'),
    ruleRemark: createInput('ruleRemark'),
    ruleTag: createInput('ruleTag'),
    siteBackendSourceIPOptions: createInput('siteBackendSourceIPOptions'),
    rangeOutSourceIPOptions: createInput('rangeOutSourceIPOptions'),
    ruleOutSourceIPOptions: createInput('ruleOutSourceIPOptions'),
    rangeRemark: createInput('rangeRemark')
  };

  const notifications = [];
  const pendingRows = {};
  const app = {
    state: {
      rules: { data: [], selectedIds: new Set(), batchDeleting: false },
      sites: { data: [] },
      ranges: { data: [] }
    },
    el: {
      editRuleId: elements.editRuleId,
      inInterface: elements.inInterface,
      inIP: elements.inIP,
      outInterface: elements.outInterface,
      ruleOutSourceIP: elements.ruleOutSourceIP,
      ruleTransparent: elements.ruleTransparent,
      ruleOutIP: elements.outIP,
      ruleForm: elements.ruleForm,
      ruleCancelBtn: elements.ruleCancelBtn,
      tokenSubmit: elements.tokenSubmit,
      tokenInput: elements.tokenInput,
      logoutBtn: elements.logoutBtn,
      editSiteId: elements.editSiteId,
      siteListenIface: elements.siteListenIface,
      siteListenIP: elements.siteListenIP,
      siteBackendSourceIP: elements.siteBackendSourceIP,
      siteTransparent: elements.siteTransparent,
      siteBackendIP: elements.siteBackendIP,
      siteForm: elements.siteForm,
      siteCancelBtn: elements.siteCancelBtn,
      editRangeId: elements.editRangeId,
      rangeInInterface: elements.rangeInInterface,
      rangeInIP: elements.rangeInIP,
      rangeOutInterface: elements.rangeOutInterface,
      rangeOutSourceIP: elements.rangeOutSourceIP,
      rangeTransparent: elements.rangeTransparent,
      rangeOutIP: elements.rangeOutIP,
      rangeForm: elements.rangeForm,
      rangeCancelBtn: elements.rangeCancelBtn,
      batchDeleteRulesBtn: elements.batchDeleteRulesBtn,
      rulesSelectAll: elements.rulesSelectAll
    },
    $(id) {
      return elements[id] || null;
    },
    t(key, params) {
      return translate(translations, key, params);
    },
    notify(type, message) {
      notifications.push({ type, message });
    },
    setFieldError(input, message) {
      if (!input) return;
      input.ariaInvalid = true;
      input.errorMessage = message;
    },
    clearFieldError(input) {
      if (!input) return;
      input.ariaInvalid = false;
      input.errorMessage = '';
    },
    clearFormErrors() {},
    focusFirstError() {},
    confirmAction() {
      return Promise.resolve(true);
    },
    renderRulesTable() {},
    renderSitesTable() {},
    renderRangesTable() {},
    loadRules() {
      return Promise.resolve();
    },
    loadSites() {
      return Promise.resolve();
    },
    loadRanges() {
      return Promise.resolve();
    },
    exitRuleEditMode() {},
    exitSiteEditMode() {},
    exitRangeEditMode() {},
    isRowPending(type, id) {
      return !!pendingRows[type + ':' + id];
    },
    setRowPending(type, id, pending) {
      pendingRows[type + ':' + id] = !!pending;
      if (!pending) delete pendingRows[type + ':' + id];
    },
    getToken() {
      return '';
    },
    showTokenModal() {},
    refreshLocalizedUI() {},
    stopPolling() {},
    closeDropdowns() {},
    refreshDashboard() {},
    markDataFresh() {},
    updateSortIndicators() {},
    renderFilterMeta() {},
    renderRulesToolbar() {},
    renderPagination() {},
    updateEmptyState() {},
    toggleTableVisibility() {},
    hideEmptyState() {},
    renderOverview() {},
    createCell() {},
    createTagBadgeNode() {},
    emptyCellNode() {},
    createEndpointNode() {},
    createBadgeNode() {},
    createStatusBadgeNode() {},
    createActionDropdown() {},
    encData() {
      return '';
    },
    sortByState(items) {
      return items;
    },
    paginateList(state, items) {
      return { items: items || [] };
    },
    statusInfo() {
      return { text: '', badge: 'stopped' };
    },
    matchesSearch() {
      return true;
    },
    hasActiveFilters() {
      return false;
    },
    getRuleSelection() {
      return this.state.rules.selectedIds;
    }
  };

  const context = vm.createContext({
    window: {
      ForwardApp: app,
      setInterval() {
        return 1;
      },
      clearInterval() {},
      addEventListener() {}
    },
    document: {
      hidden: false,
      querySelectorAll() {
        return [];
      },
      addEventListener() {}
    },
    console
  });

  const baseDir = __dirname;
  loadScript(context, path.join(baseDir, 'rules.js'));
  loadScript(context, path.join(baseDir, 'sites.js'));
  loadScript(context, path.join(baseDir, 'ranges.js'));
  loadScript(context, path.join(baseDir, 'init.js'));

  app.renderRulesTable = function renderRulesTable() {};
  app.renderSitesTable = function renderSitesTable() {};
  app.renderRangesTable = function renderRangesTable() {};
  app.loadRules = function loadRules() {
    return Promise.resolve();
  };
  app.loadSites = function loadSites() {
    return Promise.resolve();
  };
  app.loadRanges = function loadRanges() {
    return Promise.resolve();
  };

  return { app, elements, notifications };
}

test('translateValidationMessage covers batch-required message', () => {
  const { app } = createHarness();
  assert.equal(
    app.translateValidationMessage('at least one batch operation is required'),
    'At least one batch operation is required.'
  );
});

test('getValidationIssueSummary falls back to all issues when scope filter is empty', () => {
  const { app } = createHarness();
  const summary = app.getValidationIssueSummary({
    issues: [{ scope: 'request', message: 'at least one batch operation is required' }]
  }, ['delete'], 3);

  assert.equal(summary, 'At least one batch operation is required.');
});

test('applyRuleValidationIssues aggregates toast messages and focuses the first field', () => {
  const { app, elements, notifications } = createHarness();

  app.applyRuleValidationIssues([
    { scope: 'create', field: 'in_ip', message: 'is required' },
    { scope: 'create', field: 'in_port', message: 'must be between 1 and 65535' },
    { scope: 'create', field: 'protocol', message: 'must be tcp, udp, or tcp+udp' },
    { scope: 'create', field: 'transparent', message: 'transparent mode currently supports only IPv4 rules' }
  ]);

  assert.equal(
    notifications.at(-1).message,
    'This field is required.; Ports must be between 1 and 65535.; Protocol must be tcp, udp, or tcp+udp. (and 1 more)'
  );
  assert.equal(elements.inIP.focused, true);
  assert.equal(elements.inIP.errorMessage, 'This field is required.');
  assert.equal(elements.inPort.errorMessage, 'Ports must be between 1 and 65535.');
});

test('applySiteValidationIssues reuses aggregated toast summary', () => {
  const { app, elements, notifications } = createHarness();

  app.applySiteValidationIssues([
    { scope: 'create', field: 'domain', message: 'is required' },
    { scope: 'create', field: 'backend_ip', message: 'is required' },
    { scope: 'create', field: 'backend_source_ip', message: 'must match backend_ip address family' },
    { scope: 'create', field: 'transparent', message: 'transparent mode currently supports only IPv4 rules' }
  ]);

  assert.equal(
    notifications.at(-1).message,
    'This field is required.; Backend source IP must match the backend IP family.; Transparent mode currently supports IPv4 only in this phase.'
  );
  assert.equal(elements.siteDomain.focused, true);
  assert.equal(elements.siteDomain.errorMessage, 'This field is required.');
  assert.equal(elements.siteBackendIP.errorMessage, 'This field is required.');
});

test('applyRangeValidationIssues reuses aggregated toast summary', () => {
  const { app, elements, notifications } = createHarness();

  app.applyRangeValidationIssues([
    { scope: 'create', field: 'in_ip', message: 'is required' },
    { scope: 'create', field: 'start_port', message: 'must be between 1 and 65535' },
    { scope: 'create', field: 'protocol', message: 'must be tcp, udp, or tcp+udp' },
    { scope: 'create', field: 'end_port', message: 'start_port must be <= end_port' }
  ]);

  assert.equal(
    notifications.at(-1).message,
    'This field is required.; Ports must be between 1 and 65535.; Protocol must be tcp, udp, or tcp+udp. (and 1 more)'
  );
  assert.equal(elements.rangeInIP.focused, true);
  assert.equal(elements.rangeInIP.errorMessage, 'This field is required.');
  assert.equal(elements.rangeStartPort.errorMessage, 'Ports must be between 1 and 65535.');
});

test('toggleItem shows translated not-found issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.state.rules.data = [{ id: 9, enabled: true }];
  app.apiCall = async () => {
    const err = new Error('toggle failed');
    err.payload = { issues: [{ scope: 'toggle', field: 'id', message: 'rule not found' }] };
    throw err;
  };

  await app.toggleItem('rule', 9);

  assert.equal(notifications.at(-1).message, 'Operation failed: The rule no longer exists.');
});

test('toggleItem shows translated invalid-id issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.apiCall = async () => {
    const err = new Error('invalid id');
    err.payload = { issues: [{ scope: 'toggle', field: 'id', message: 'invalid id' }] };
    throw err;
  };

  await app.toggleItem('rule', 'bad');

  assert.equal(notifications.at(-1).message, 'Operation failed: The ID is invalid.');
});

test('deleteRule shows translated not-found issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.apiCall = async () => {
    const err = new Error('delete failed');
    err.payload = { issues: [{ scope: 'delete', field: 'id', message: 'rule not found' }] };
    throw err;
  };

  await app.deleteRule(12);

  assert.equal(notifications.at(-1).message, 'Delete failed: The rule no longer exists.');
});

test('deleteSite shows translated invalid-id issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.apiCall = async () => {
    const err = new Error('delete failed');
    err.payload = { issues: [{ scope: 'delete', field: 'id', message: 'invalid id' }] };
    throw err;
  };

  await app.deleteSite('bad');

  assert.equal(notifications.at(-1).message, 'Delete failed: The ID is invalid.');
});

test('deleteRange shows translated not-found issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.apiCall = async () => {
    const err = new Error('delete failed');
    err.payload = { issues: [{ scope: 'delete', field: 'id', message: 'range not found' }] };
    throw err;
  };

  await app.deleteRange(33);

  assert.equal(notifications.at(-1).message, 'Delete failed: The range mapping no longer exists.');
});

test('deleteSelectedRules shows aggregated multi-issue toast summary', async () => {
  const { app, notifications } = createHarness();
  app.state.rules.selectedIds = new Set([11, 22, 33]);
  app.apiCall = async () => {
    const err = new Error('batch delete failed');
    err.payload = {
      issues: [
        { scope: 'delete', field: 'id', message: 'rule not found' },
        { scope: 'delete_ids', field: 'id', message: 'invalid id' },
        { scope: 'delete', field: 'id', message: 'must be greater than 0' },
        { scope: 'delete', field: 'transparent', message: 'transparent mode currently supports only IPv4 rules' }
      ]
    };
    throw err;
  };

  await app.deleteSelectedRules();

  assert.equal(
    notifications.at(-1).message,
    'Delete failed: The rule no longer exists.; The ID is invalid.; The ID must be greater than 0. (and 1 more)'
  );
});

test('deleteSelectedRules falls back to request-scope issue summary', async () => {
  const { app, notifications } = createHarness();
  app.apiCall = async () => {
    const err = new Error('batch delete failed');
    err.payload = {
      issues: [
        { scope: 'request', message: 'at least one batch operation is required' }
      ]
    };
    throw err;
  };

  await app.deleteSelectedRules([44]);

  assert.equal(
    notifications.at(-1).message,
    'Delete failed: At least one batch operation is required.'
  );
});
