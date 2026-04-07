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
    attributes: {},
    childNodes: [],
    dataset: {},
    classList: {
      add() {},
      remove() {},
      toggle() {},
      contains() {
        return false;
      }
    },
    tagName: 'INPUT',
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
    appendChild(child) {
      this.childNodes.push(child);
      return child;
    },
    removeChild(child) {
      const index = this.childNodes.indexOf(child);
      if (index >= 0) this.childNodes.splice(index, 1);
      return child;
    },
    reset() {},
    scrollIntoView() {},
    get firstChild() {
      return this.childNodes.length ? this.childNodes[0] : null;
    },
    get options() {
      return this.childNodes;
    },
    getAttribute(attr) {
      return Object.prototype.hasOwnProperty.call(this.attributes, attr) ? this.attributes[attr] : null;
    },
    hasAttribute(attr) {
      if (attr === 'aria-invalid') return this.ariaInvalid;
      return Object.prototype.hasOwnProperty.call(this.attributes, attr);
    },
    setAttribute(attr, value) {
      if (attr === 'aria-invalid') this.ariaInvalid = true;
      this.attributes[attr] = value == null ? '' : value;
    },
    removeAttribute(attr) {
      if (attr === 'aria-invalid') this.ariaInvalid = false;
      delete this.attributes[attr];
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
    'common.unspecified': 'Unspecified',
    'common.selectInterfaceFirst': 'Select interface first',
    'common.familyLabel': 'Address Family',
    'common.family.ipv4': 'IPv4',
    'common.family.ipv6': 'IPv6',
    'common.family.mixed': 'Mixed',
    'interface.picker.placeholder': 'Search or select interface...',
    'interface.search.placeholder': 'Filter interfaces...',
    'interface.search.noResults': 'No matching interfaces',
    'errors.operationFailed': 'Operation failed: {{message}}',
    'errors.deleteFailed': 'Delete failed: {{message}}',
    'validation.ruleNotFound': 'The rule no longer exists.',
    'validation.siteNotFound': 'The site no longer exists.',
    'validation.rangeNotFound': 'The range mapping no longer exists.',
    'validation.egressNATNotFound': 'The egress NAT takeover no longer exists.',
    'validation.egressNATRequired': 'Select the parent interface and outbound interface.',
    'validation.egressNATCreateIDOmit': 'Do not send an ID when creating an egress NAT takeover.',
    'validation.egressNATChildConflict': 'The selected egress NAT scope is already claimed by egress NAT takeover #{{id}}.',
    'validation.egressNATNoChildren': 'The selected parent interface currently has no eligible child interfaces to take over.',
    'validation.egressNATSingleTargetOutConflict': 'The parent interface must be different from the outbound interface in single-target mode.',
    'validation.childInterfaceDifferent': 'The child interface must be different from the outbound interface.',
    'validation.childParentMismatch': 'The child interface is not attached to the selected parent interface.',
    'egressNAT.scope.allChildren': 'All Eligible Child Interfaces',
    'egressNAT.scope.self': 'Selected Interface',
    'egressNAT.form.childInterfaceAll': 'All Eligible Child Interfaces',
    'egressNAT.form.interfaceSearchPlaceholder': 'Filter interfaces...',
    'egressNAT.form.outInterfaceHintAuto': 'Auto-selected a likely uplink interface: {{name}}. You can still change it manually.',
    'validation.required': 'This field is required.',
    'validation.invalidID': 'The ID is invalid.',
    'validation.ipv4': 'Enter a valid IPv4 address.',
    'validation.positiveId': 'The ID must be greater than 0.',
    'validation.portRange': 'Ports must be between 1 and 65535.',
    'validation.protocol': 'Protocol must be tcp, udp, or tcp+udp.',
    'validation.egressNATProtocol': 'Select at least one protocol (tcp, udp, icmp).',
    'validation.egressNATNatType': 'NAT type must be symmetric or full_cone.',
    'validation.transparentIPv4Only': 'Transparent mode currently supports IPv4 only in this phase.',
    'validation.ruleBatchRequired': 'At least one batch operation is required.',
    'validation.sourceIPBackendFamily': 'Backend source IP must match the backend IP family.',
    'validation.rangeOrder': 'The start port must not exceed the end port.',
    'runtimeReason.kernelMixedFamily': 'The kernel dataplane does not support mixed IPv4/IPv6 forwarding yet.',
    'runtimeReason.kernelTransparentIPv6': 'The kernel dataplane does not support transparent IPv6 rules yet.',
    'transparent.info.ipv6Unavailable': 'Transparent mode currently supports IPv4 targets only. Disable it for IPv6 targets.',
    'validation.issueJoiner': '; ',
    'validation.issueSummaryMore': '{{messages}} (and {{count}} more)',
    'validation.reviewErrors': 'Review the highlighted fields.',
    'egressNAT.natType.symmetric': 'Symmetric',
    'egressNAT.natType.fullCone': 'Full Cone'
  };

  const elements = {
    editRuleId: createInput('editRuleId'),
    inInterface: createInput('inInterface'),
    inInterfacePicker: createInput('inInterfacePicker'),
    inInterfaceOptions: createInput('inInterfaceOptions'),
    inIP: createInput('inIP'),
    inPort: createInput('inPort'),
    outInterface: createInput('outInterface'),
    outInterfacePicker: createInput('outInterfacePicker'),
    outInterfaceOptions: createInput('outInterfaceOptions'),
    outIP: createInput('outIP'),
    outPort: createInput('outPort'),
    protocol: createInput('protocol'),
    ruleOutSourceIP: createInput('ruleOutSourceIP'),
    ruleTransparent: createInput('ruleTransparent'),
    ruleTransparentWarning: createInput('ruleTransparentWarning'),
    editSiteId: createInput('editSiteId'),
    siteDomain: createInput('siteDomain'),
    siteTag: createInput('siteTag'),
    siteListenIface: createInput('siteListenIface'),
    siteListenIfacePicker: createInput('siteListenIfacePicker'),
    siteListenIfaceOptions: createInput('siteListenIfaceOptions'),
    siteListenIP: createInput('siteListenIP'),
    siteBackendIP: createInput('siteBackendIP'),
    siteBackendSourceIP: createInput('siteBackendSourceIP'),
    siteBackendHTTP: createInput('siteBackendHTTP'),
    siteBackendHTTPS: createInput('siteBackendHTTPS'),
    siteTransparent: createInput('siteTransparent'),
    siteTransparentWarning: createInput('siteTransparentWarning'),
    editRangeId: createInput('editRangeId'),
    rangeInInterface: createInput('rangeInInterface'),
    rangeInInterfacePicker: createInput('rangeInInterfacePicker'),
    rangeInInterfaceOptions: createInput('rangeInInterfaceOptions'),
    rangeInIP: createInput('rangeInIP'),
    rangeStartPort: createInput('rangeStartPort'),
    rangeEndPort: createInput('rangeEndPort'),
    rangeOutInterface: createInput('rangeOutInterface'),
    rangeOutInterfacePicker: createInput('rangeOutInterfacePicker'),
    rangeOutInterfaceOptions: createInput('rangeOutInterfaceOptions'),
    rangeOutIP: createInput('rangeOutIP'),
    rangeOutSourceIP: createInput('rangeOutSourceIP'),
    rangeOutStartPort: createInput('rangeOutStartPort'),
    rangeProtocol: createInput('rangeProtocol'),
    rangeTransparent: createInput('rangeTransparent'),
    rangeTransparentWarning: createInput('rangeTransparentWarning'),
    rangeTag: createInput('rangeTag'),
    editEgressNATId: createInput('editEgressNATId'),
    egressNATForm: createInput('egressNATForm'),
    egressNATFormTitle: createInput('egressNATFormTitle'),
    egressNATSubmitBtn: createInput('egressNATSubmitBtn'),
    egressNATCancelBtn: createInput('egressNATCancelBtn'),
    egressNATParentInterface: createInput('egressNATParentInterface'),
    egressNATParentPicker: createInput('egressNATParentPicker'),
    egressNATParentOptions: createInput('egressNATParentOptions'),
    egressNATChildInterface: createInput('egressNATChildInterface'),
    egressNATChildPicker: createInput('egressNATChildPicker'),
    egressNATChildOptions: createInput('egressNATChildOptions'),
    egressNATOutInterface: createInput('egressNATOutInterface'),
    egressNATOutPicker: createInput('egressNATOutPicker'),
    egressNATOutOptions: createInput('egressNATOutOptions'),
    egressNATOutInterfaceHint: createInput('egressNATOutInterfaceHint'),
    egressNATOutSourceIP: createInput('egressNATOutSourceIP'),
    egressNATNatType: createInput('egressNATNatType'),
    egressNATProtocol: createInput('egressNATProtocol'),
    egressNATProtocolDropdown: createInput('egressNATProtocolDropdown'),
    egressNATProtocolTrigger: createInput('egressNATProtocolTrigger'),
    egressNATProtocolMenu: createInput('egressNATProtocolMenu'),
    egressNATProtocolTCP: createInput('egressNATProtocolTCP'),
    egressNATProtocolUDP: createInput('egressNATProtocolUDP'),
    egressNATProtocolICMP: createInput('egressNATProtocolICMP'),
    egressNATOutSourceIPOptions: createInput('egressNATOutSourceIPOptions'),
    egressNATsSearchInput: createInput('egressNATsSearchInput'),
    emptyAddEgressNATBtn: createInput('emptyAddEgressNATBtn'),
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

  elements.egressNATProtocolTCP.value = 'tcp';
  elements.egressNATProtocolUDP.value = 'udp';
  elements.egressNATProtocolICMP.value = 'icmp';
  elements.egressNATProtocolMenu.hidden = true;
  elements.ruleOutSourceIP.attributes.list = 'ruleOutSourceIPOptions';
  elements.siteBackendSourceIP.attributes.list = 'siteBackendSourceIPOptions';
  elements.rangeOutSourceIP.attributes.list = 'rangeOutSourceIPOptions';
  elements.egressNATOutSourceIP.attributes.list = 'egressNATOutSourceIPOptions';

  const notifications = [];
  const pendingRows = {};
  const app = {
    state: {
      rules: { data: [], selectedIds: new Set(), batchDeleting: false },
      sites: { data: [] },
      ranges: { data: [] },
      egressNATs: { data: [] }
    },
    el: {
      editRuleId: elements.editRuleId,
      inInterface: elements.inInterface,
      inInterfacePicker: elements.inInterfacePicker,
      inInterfaceOptions: elements.inInterfaceOptions,
      inIP: elements.inIP,
      outInterface: elements.outInterface,
      outInterfacePicker: elements.outInterfacePicker,
      outInterfaceOptions: elements.outInterfaceOptions,
      ruleOutSourceIP: elements.ruleOutSourceIP,
      ruleTransparent: elements.ruleTransparent,
      ruleOutIP: elements.outIP,
      ruleTransparentWarning: elements.ruleTransparentWarning,
      ruleForm: elements.ruleForm,
      ruleCancelBtn: elements.ruleCancelBtn,
      tokenSubmit: elements.tokenSubmit,
      tokenInput: elements.tokenInput,
      logoutBtn: elements.logoutBtn,
      editSiteId: elements.editSiteId,
      siteListenIface: elements.siteListenIface,
      siteListenIfacePicker: elements.siteListenIfacePicker,
      siteListenIfaceOptions: elements.siteListenIfaceOptions,
      siteListenIP: elements.siteListenIP,
      siteBackendSourceIP: elements.siteBackendSourceIP,
      siteTransparent: elements.siteTransparent,
      siteBackendIP: elements.siteBackendIP,
      siteTransparentWarning: elements.siteTransparentWarning,
      siteForm: elements.siteForm,
      siteCancelBtn: elements.siteCancelBtn,
      editRangeId: elements.editRangeId,
      rangeInInterface: elements.rangeInInterface,
      rangeInInterfacePicker: elements.rangeInInterfacePicker,
      rangeInInterfaceOptions: elements.rangeInInterfaceOptions,
      rangeInIP: elements.rangeInIP,
      rangeOutInterface: elements.rangeOutInterface,
      rangeOutInterfacePicker: elements.rangeOutInterfacePicker,
      rangeOutInterfaceOptions: elements.rangeOutInterfaceOptions,
      rangeOutSourceIP: elements.rangeOutSourceIP,
      rangeTransparent: elements.rangeTransparent,
      rangeOutIP: elements.rangeOutIP,
      rangeTransparentWarning: elements.rangeTransparentWarning,
      rangeForm: elements.rangeForm,
      rangeCancelBtn: elements.rangeCancelBtn,
      editEgressNATId: elements.editEgressNATId,
      egressNATForm: elements.egressNATForm,
      egressNATFormTitle: elements.egressNATFormTitle,
      egressNATSubmitBtn: elements.egressNATSubmitBtn,
      egressNATCancelBtn: elements.egressNATCancelBtn,
      egressNATParentInterface: elements.egressNATParentInterface,
      egressNATParentPicker: elements.egressNATParentPicker,
      egressNATParentOptions: elements.egressNATParentOptions,
      egressNATChildInterface: elements.egressNATChildInterface,
      egressNATChildPicker: elements.egressNATChildPicker,
      egressNATChildOptions: elements.egressNATChildOptions,
      egressNATOutInterface: elements.egressNATOutInterface,
      egressNATOutPicker: elements.egressNATOutPicker,
      egressNATOutOptions: elements.egressNATOutOptions,
      egressNATOutInterfaceHint: elements.egressNATOutInterfaceHint,
      egressNATOutSourceIP: elements.egressNATOutSourceIP,
      egressNATNatType: elements.egressNATNatType,
      egressNATProtocol: elements.egressNATProtocol,
      egressNATProtocolDropdown: elements.egressNATProtocolDropdown,
      egressNATProtocolTrigger: elements.egressNATProtocolTrigger,
      egressNATProtocolMenu: elements.egressNATProtocolMenu,
      egressNATProtocolTCP: elements.egressNATProtocolTCP,
      egressNATProtocolUDP: elements.egressNATProtocolUDP,
      egressNATProtocolICMP: elements.egressNATProtocolICMP,
      egressNATsSearchInput: elements.egressNATsSearchInput,
      emptyAddEgressNATBtn: elements.emptyAddEgressNATBtn,
      batchDeleteRulesBtn: elements.batchDeleteRulesBtn,
      rulesSelectAll: elements.rulesSelectAll
    },
    $(id) {
      return elements[id] || null;
    },
    t(key, params) {
      return translate(translations, key, params);
    },
    compareValues(a, b) {
      const va = a == null ? '' : a;
      const vb = b == null ? '' : b;
      if (typeof va === 'number' && typeof vb === 'number') return va - vb;
      return String(va).localeCompare(String(vb), 'en-US', { numeric: true, sensitivity: 'base' });
    },
    parseIPv4(ip) {
      const text = String(ip || '').trim();
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(text)) return null;
      const parts = text.split('.').map((part) => parseInt(part, 10));
      if (parts.length !== 4 || parts.some((part) => Number.isNaN(part) || part < 0 || part > 255)) return null;
      return parts;
    },
    isValidIPv6(ip) {
      const text = String(ip || '').trim();
      if (!text || text.indexOf(':') < 0 || text.indexOf('%') >= 0) return false;
      try {
        new URL('http://[' + text + ']/');
        return true;
      } catch (err) {
        return false;
      }
    },
    isValidIP(ip) {
      const text = String(ip || '').trim();
      return !!this.parseIPv4(text) || this.isValidIPv6(text);
    },
    ipFamily(ip) {
      const text = String(ip || '').trim();
      if (this.parseIPv4(text)) return 'ipv4';
      if (this.isValidIPv6(text)) return 'ipv6';
      return '';
    },
    isPublicIPv4(ip) {
      const p = this.parseIPv4(ip);
      if (!p) return false;
      if (p[0] === 10 || p[0] === 127 || p[0] === 0) return false;
      if (p[0] === 169 && p[1] === 254) return false;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return false;
      if (p[0] === 192 && p[1] === 168) return false;
      if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return false;
      if (p[0] >= 224) return false;
      return true;
    },
    isBridgeInterface(name) {
      return /^(vmbr|virbr|br|ovs)/i.test(String(name || '').trim());
    },
    transparentAvailability(backendIP) {
      const family = typeof this.ipFamily === 'function' ? this.ipFamily(String(backendIP || '').trim()) : '';
      if (family === 'ipv6') {
        return {
          supported: false,
          level: 'info',
          text: this.t('transparent.info.ipv6Unavailable'),
          needsConfirm: false
        };
      }
      return {
        supported: true,
        level: '',
        text: '',
        needsConfirm: false
      };
    },
    buildTransparentWarning(transparent, backendIP, outIface, targetLabel) {
      if (!transparent) return { level: '', text: '', needsConfirm: false };

      const ip = String(backendIP || '').trim();
      if (!this.parseIPv4(ip)) {
        return {
          level: 'info',
          text: 'Transparent mode requires a concrete IPv4 backend address, and reply traffic must pass back through this host.',
          needsConfirm: false
        };
      }

      if (this.isPublicIPv4(ip)) {
        const prefix = this.isBridgeInterface(outIface)
          ? 'A public target IP and a bridge-like outbound interface were detected.'
          : 'A public target IP was detected.';
        return {
          level: 'warning',
          text: prefix + ' Transparent mode usually fails if the default gateway of ' + targetLabel + ' does not route back through this host.',
          needsConfirm: true
        };
      }

      return {
        level: 'info',
        text: 'Transparent mode is enabled. Confirm that the default gateway or policy route of ' + targetLabel + ' points back to this host, otherwise reply traffic will bypass it.',
        needsConfirm: false
      };
    },
    applyTransparentWarning(node, warning) {
      if (!warning || !warning.text) {
        if (node) {
          node.className = 'transparent-warning';
          node.textContent = '';
        }
        return warning;
      }
      if (node) {
        node.className = 'transparent-warning is-visible ' + (warning.level === 'warning' ? 'is-warning' : 'is-info');
        node.textContent = warning.text;
      }
      return warning;
    },
    confirmTransparentWarning(warning) {
      return !warning || !warning.needsConfirm;
    },
    syncTransparentToggleState(input, backendIP) {
      const availability = typeof this.transparentAvailability === 'function'
        ? this.transparentAvailability(backendIP)
        : { supported: true, level: '', text: '', needsConfirm: false };
      if (!input) return availability;
      if (!availability.supported) {
        input.checked = false;
        input.disabled = true;
        input.setAttribute('aria-disabled', 'true');
        if (availability.text) input.setAttribute('title', availability.text);
        else input.removeAttribute('title');
        return availability;
      }
      input.disabled = false;
      input.removeAttribute('aria-disabled');
      input.removeAttribute('title');
      return availability;
    },
    syncTransparentSourceIPState(input, transparent) {
      if (!input) return;
      if (transparent) {
        input.value = '';
        input.disabled = true;
        input.setAttribute('aria-disabled', 'true');
      } else {
        input.disabled = false;
        input.removeAttribute('aria-disabled');
      }
    },
    updateRuleTransparentWarning() {
      const availability = this.syncTransparentToggleState(this.el.ruleTransparent, this.el.ruleOutIP.value);
      this.syncTransparentSourceIPState(this.el.ruleOutSourceIP, this.el.ruleTransparent.checked);
      return this.applyTransparentWarning(
        this.el.ruleTransparentWarning,
        availability && availability.supported
          ? this.buildTransparentWarning(this.el.ruleTransparent.checked, this.el.ruleOutIP.value, this.el.outInterface.value, 'backend host')
          : availability
      );
    },
    updateSiteTransparentWarning() {
      const availability = this.syncTransparentToggleState(this.el.siteTransparent, this.el.siteBackendIP.value);
      this.syncTransparentSourceIPState(this.el.siteBackendSourceIP, this.el.siteTransparent.checked);
      return this.applyTransparentWarning(
        this.el.siteTransparentWarning,
        availability && availability.supported
          ? this.buildTransparentWarning(this.el.siteTransparent.checked, this.el.siteBackendIP.value, '', 'backend host')
          : availability
      );
    },
    updateRangeTransparentWarning() {
      const availability = this.syncTransparentToggleState(this.el.rangeTransparent, this.el.rangeOutIP.value);
      this.syncTransparentSourceIPState(this.el.rangeOutSourceIP, this.el.rangeTransparent.checked);
      return this.applyTransparentWarning(
        this.el.rangeTransparentWarning,
        availability && availability.supported
          ? this.buildTransparentWarning(this.el.rangeTransparent.checked, this.el.rangeOutIP.value, this.el.rangeOutInterface.value, 'target host')
          : availability
      );
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
    renderEgressNATsTable() {},
    loadRules() {
      return Promise.resolve();
    },
    loadSites() {
      return Promise.resolve();
    },
    loadRanges() {
      return Promise.resolve();
    },
    loadEgressNATs() {
      return Promise.resolve();
    },
    exitRuleEditMode() {},
    exitSiteEditMode() {},
    exitRangeEditMode() {},
    exitEgressNATEditMode() {},
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
    clearNode(node) {
      if (!node) return;
      node.childNodes = [];
    },
    addOption(sel, value, label) {
      if (!sel) return;
      sel.appendChild({ value, textContent: label });
    },
    addSelectPlaceholderOption(sel, label, options) {
      if (!sel) return null;
      const opts = options || {};
      const option = {
        value: opts.value == null ? '__placeholder__' : String(opts.value),
        textContent: label == null ? '' : String(label),
        disabled: opts.disabled !== false
      };
      sel.appendChild(option);
      return option;
    },
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
    interfaceOptionLabel(iface) {
      if (!iface) return '';
      const name = String(iface.name || '').trim();
      const kind = String(iface.kind || '').trim().toLowerCase();
      const parent = String(iface.parent || '').trim();
      const addrs = Array.isArray(iface.addrs) ? iface.addrs.filter(Boolean) : [];
      const meta = [];
      if (kind) meta.push(kind);
      if (parent) meta.push('via ' + parent);
      let label = name;
      if (meta.length) label += ' [' + meta.join(' ') + ']';
      if (addrs.length) {
        const preview = addrs.slice(0, 2);
        const suffix = addrs.length > preview.length ? ', +' + (addrs.length - preview.length) : '';
        label += ' (' + preview.join(', ') + suffix + ')';
      }
      return label;
    },
    interfaceSearchText(iface) {
      if (!iface) return '';
      return [
        iface.name,
        iface.kind,
        iface.parent,
        this.interfaceOptionLabel(iface),
        ...(Array.isArray(iface.addrs) ? iface.addrs.filter(Boolean) : [])
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
    },
    interfaceAddresses(iface) {
      return Array.isArray(iface && iface.addrs) ? iface.addrs.filter(Boolean) : [];
    },
    filterInterfaceItems(items, query) {
      const list = Array.isArray(items) ? items.slice() : [];
      const tokens = String(query || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
      if (!tokens.length) return list;
      return list.filter((iface) => {
        const haystack = this.interfaceSearchText(iface);
        return tokens.every((token) => haystack.indexOf(token) >= 0);
      });
    },
    findInterfaceByName(name, items) {
      const target = String(name || '').trim();
      const list = Array.isArray(items) ? items : (this.interfaces || []);
      if (!target) return null;
      return list.find((iface) => iface && iface.name === target) || null;
    },
    findInterfaceByDisplayText(text, items) {
      const target = String(text || '').trim();
      const list = Array.isArray(items) ? items : (this.interfaces || []);
      if (!target) return null;
      return list.find((iface) => iface && (iface.name === target || this.interfaceOptionLabel(iface) === target)) || null;
    },
    getInterfacePickerItems(hiddenEl, options) {
      const opts = options || {};
      const baseItems = Array.isArray(opts.items)
        ? opts.items.slice()
        : (typeof opts.getItems === 'function' ? opts.getItems() : (this.interfaces || [])).slice();
      const seen = Object.create(null);
      const items = [];
      baseItems.forEach((iface) => {
        if (!iface || !iface.name || seen[iface.name]) return;
        seen[iface.name] = true;
        items.push(iface);
      });
      const selectedName = hiddenEl ? String(hiddenEl.value || '').trim() : '';
      if (opts.preserveSelected && selectedName && !seen[selectedName]) {
        const selectedInfo = this.findInterfaceByName(selectedName);
        if (selectedInfo) items.push(selectedInfo);
      }
      return items;
    },
    setInterfacePickerValue(hiddenEl, pickerEl, value, options) {
      const normalized = String(value || '').trim();
      if (hiddenEl) hiddenEl.value = normalized;
      if (!pickerEl) return null;
      if (!normalized) {
        pickerEl.value = '';
        return null;
      }
      const items = this.getInterfacePickerItems(hiddenEl, options);
      const iface = this.findInterfaceByName(normalized, items) || this.findInterfaceByName(normalized);
      pickerEl.value = iface ? this.interfaceOptionLabel(iface) : normalized;
      return iface || null;
    },
    syncInterfacePickerSelection(hiddenEl, pickerEl, options) {
      const opts = options || {};
      const items = this.getInterfacePickerItems(hiddenEl, opts);
      const text = String(pickerEl && pickerEl.value || '').trim();
      if (!hiddenEl) return { value: '', item: null, items, text };
      if (!text) {
        hiddenEl.value = '';
        return { value: '', item: null, items, text: '' };
      }
      const exact = this.findInterfaceByDisplayText(text, items) || this.findInterfaceByDisplayText(text);
      if (exact) {
        hiddenEl.value = exact.name;
        if (pickerEl && opts.commitLabel !== false) pickerEl.value = this.interfaceOptionLabel(exact);
        return { value: exact.name, item: exact, items, text };
      }
      const matches = this.filterInterfaceItems(items, text);
      if (matches.length === 1) {
        hiddenEl.value = matches[0].name;
        if (pickerEl && opts.commitLabel) pickerEl.value = this.interfaceOptionLabel(matches[0]);
        return { value: matches[0].name, item: matches[0], items, text, matches };
      }
      hiddenEl.value = '';
      return { value: '', item: null, items, text, matches };
    },
    getInterfaceSubmissionValue(hiddenEl, pickerEl, options) {
      const currentValue = hiddenEl ? String(hiddenEl.value || '').trim() : '';
      const currentText = String(pickerEl && pickerEl.value || '').trim();
      if (!currentText) return currentValue;
      const result = this.syncInterfacePickerSelection(hiddenEl, pickerEl, Object.assign({}, options || {}, { commitLabel: true }));
      if (result && result.value) return result.value;
      return currentText;
    },
    populateInterfacePicker(hiddenEl, pickerEl, listEl, options) {
      const opts = options || {};
      const items = this.getInterfacePickerItems(hiddenEl, opts);
      if (listEl) {
        this.clearNode(listEl);
        items.forEach((iface) => {
          listEl.appendChild({ value: this.interfaceOptionLabel(iface), label: iface.name, textContent: this.interfaceOptionLabel(iface) });
        });
      }
      if (pickerEl) {
        pickerEl.disabled = !!opts.disabled;
        if (Object.prototype.hasOwnProperty.call(opts, 'placeholder')) pickerEl.placeholder = opts.placeholder;
      }
      const currentValue = hiddenEl ? String(hiddenEl.value || '').trim() : '';
      const currentInItems = currentValue ? this.findInterfaceByName(currentValue, items) : null;
      if (currentValue && (opts.preserveSelected || currentInItems)) this.setInterfacePickerValue(hiddenEl, pickerEl, currentValue, opts);
      else {
        if (hiddenEl && currentValue && !opts.preserveSelected) hiddenEl.value = '';
        if (pickerEl && !opts.preserveText) pickerEl.value = '';
      }
      return items;
    },
    populateInterfaceSelect(sel, selected) {
      if (!sel) return;
      const current = selected == null ? sel.value : selected;
      this.clearNode(sel);
      this.addOption(sel, '', this.t('common.unspecified'));
      (this.interfaces || []).forEach((iface) => {
        this.addOption(sel, iface.name, this.interfaceOptionLabel(iface));
      });
      sel.value = current || '';
    },
    populateInterfaceSelectFiltered(sel, selected, options) {
      if (!sel) return;
      const opts = options || {};
      const current = selected == null ? sel.value : selected;
      const baseItems = Array.isArray(opts.items) ? opts.items.slice() : (this.interfaces || []).slice();
      const filtered = this.filterInterfaceItems(baseItems, opts.query);
      this.clearNode(sel);
      this.addOption(sel, '', this.t('common.unspecified'));
      filtered.forEach((iface) => {
        this.addOption(sel, iface.name, this.interfaceOptionLabel(iface));
      });
      if (opts.preserveSelected && current) {
        const hasCurrent = sel.options.some((option) => option.value === current);
        if (!hasCurrent) {
          const currentInfo = baseItems.find((iface) => iface && iface.name === current) ||
            (this.interfaces || []).find((iface) => iface && iface.name === current);
          this.addOption(sel, current, currentInfo ? this.interfaceOptionLabel(currentInfo) : current);
        }
      }
      const hasSelectableOption = sel.options.some((option) => option && option.value);
      if (!hasSelectableOption && String(opts.query || '').trim()) {
        this.addSelectPlaceholderOption(sel, this.t('interface.search.noResults'), { value: '__no_matching_interfaces__' });
      }
      const resolved = current && sel.options.some((option) => option.value === current) ? current : '';
      sel.value = resolved;
    },
    populateIPSelect(ifaceSel, ipSel, selected) {
      if (!ipSel) return;
      ipSel.value = selected == null ? ipSel.value : selected;
    },
    populateSiteListenIP(ifaceSel, ipSel, selected) {
      if (!ipSel) return;
      ipSel.value = selected == null ? ipSel.value : selected;
    },
    populateSourceIPSelect(ifaceSel, inputEl, selected, legacy, options) {
      if (!inputEl) return;
      const opts = (options && typeof options === 'object')
        ? options
        : ((legacy && typeof legacy === 'object') ? legacy : {});
      const current = selected == null ? inputEl.value : selected;
      const family = String(opts.family || '').trim().toLowerCase();
      const ifaceName = ifaceSel ? ifaceSel.value : '';
      const listId = inputEl.getAttribute('list');
      const listEl = listId ? elements[listId] : null;
      const seen = Object.create(null);

      if (listEl) this.clearNode(listEl);

      const appendOption = (value, label) => {
        if (!listEl || !value || seen[value]) return;
        if (!this.isValidIP(value)) return;
        if (family && this.ipFamily(value) !== family) return;
        const normalized = String(value).trim().toLowerCase();
        if (normalized === '0.0.0.0' || normalized === '::' || /^127\./.test(value) || normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return;
        seen[value] = true;
        listEl.appendChild({ value, label, textContent: value });
      };

      if (listEl) {
        if (!ifaceName) {
          (this.interfaces || []).forEach((iface) => {
            this.interfaceAddresses(iface).forEach((addr) => appendOption(addr, addr + ' (' + iface.name + ')'));
          });
        } else {
          const iface = (this.interfaces || []).find((item) => item.name === ifaceName);
          if (iface) this.interfaceAddresses(iface).forEach((addr) => appendOption(addr, addr));
        }
      }

      if (family && current && this.isValidIP(current) && this.ipFamily(current) !== family) inputEl.value = '';
      else inputEl.value = current == null ? inputEl.value : current;
    },
    getRuleSelection() {
      return this.state.rules.selectedIds;
    }
  };

  const documentRef = {
    hidden: false,
    activeElement: null,
    querySelectorAll() {
      return [];
    },
    addEventListener() {}
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
    document: documentRef,
    console
  });

  const baseDir = __dirname;
  loadScript(context, path.join(baseDir, 'rules.js'));
  loadScript(context, path.join(baseDir, 'sites.js'));
  loadScript(context, path.join(baseDir, 'ranges.js'));
  loadScript(context, path.join(baseDir, 'egress_nats.js'));
  loadScript(context, path.join(baseDir, 'init.js'));

  app.renderRulesTable = function renderRulesTable() {};
  app.renderSitesTable = function renderSitesTable() {};
  app.renderRangesTable = function renderRangesTable() {};
  app.renderEgressNATsTable = function renderEgressNATsTable() {};
  app.loadRules = function loadRules() {
    return Promise.resolve();
  };
  app.loadSites = function loadSites() {
    return Promise.resolve();
  };
  app.loadRanges = function loadRanges() {
    return Promise.resolve();
  };
  app.loadEgressNATs = function loadEgressNATs() {
    return Promise.resolve();
  };
  app.populateEgressNATSourceIPSelect = function populateEgressNATSourceIPSelect() {};

  return { app, elements, notifications, documentRef };
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

test('applyEgressNATValidationIssues reuses aggregated toast summary', () => {
  const { app, elements, notifications } = createHarness();

  app.applyEgressNATValidationIssues([
    { scope: 'create', field: 'egress_nat', message: 'parent_interface and out_interface are required' },
    { scope: 'create', field: 'child_interface', message: 'egress nat scope conflicts with egress nat #12' },
    { scope: 'create', field: 'out_source_ip', message: 'out_source_ip must be a valid IPv4 address' }
  ]);

  assert.equal(
    notifications.at(-1).message,
    'Select the parent interface and outbound interface.; The selected egress NAT scope is already claimed by egress NAT takeover #12.; Enter a valid IPv4 address.'
  );
  assert.equal(elements.egressNATParentPicker.focused, true);
  assert.equal(elements.egressNATParentPicker.errorMessage, 'Select the parent interface and outbound interface.');
  assert.equal(elements.egressNATChildPicker.errorMessage, 'The selected egress NAT scope is already claimed by egress NAT takeover #12.');
  assert.equal(elements.egressNATOutSourceIP.errorMessage, 'Enter a valid IPv4 address.');
});

test('applyEgressNATValidationIssues highlights protocol field', () => {
  const { app, elements, notifications } = createHarness();

  app.applyEgressNATValidationIssues([
    { scope: 'create', field: 'protocol', message: 'must include one or more of tcp, udp, icmp' }
  ]);

  assert.equal(notifications.at(-1).message, 'Select at least one protocol (tcp, udp, icmp).');
  assert.equal(elements.egressNATProtocolTrigger.focused, true);
  assert.equal(elements.egressNATProtocolTrigger.errorMessage, 'Select at least one protocol (tcp, udp, icmp).');
});

test('translateValidationMessage covers single-target outbound conflict', () => {
  const { app } = createHarness();

  assert.equal(
    app.translateValidationMessage('parent_interface must be different from out_interface when selecting a single target interface'),
    'The parent interface must be different from the outbound interface in single-target mode.'
  );
});

test('translateRuntimeReason covers IPv6 kernel fallback reasons', () => {
  const { app } = createHarness();

  assert.equal(
    app.translateRuntimeReason('kernel dataplane does not support mixed IPv4/IPv6 forwarding'),
    'The kernel dataplane does not support mixed IPv4/IPv6 forwarding yet.'
  );
  assert.equal(
    app.translateRuntimeReason('kernel dataplane currently does not support transparent IPv6 rules'),
    'The kernel dataplane does not support transparent IPv6 rules yet.'
  );
  assert.equal(
    app.translateRuntimeReason('some other runtime reason'),
    'some other runtime reason'
  );
});

test('getRuleEngineInfo uses translated runtime reason in badge title', () => {
  const { app } = createHarness();

  const info = app.getRuleEngineInfo({
    effective_engine: 'userspace',
    fallback_reason: 'kernel dataplane does not support mixed IPv4/IPv6 forwarding',
    kernel_reason: ''
  });

  assert.match(info.title, /mixed IPv4\/IPv6 forwarding yet/);
});

test('getAddressFamilyInfo identifies ipv6 and mixed routes', () => {
  const { app } = createHarness();

  const ipv6Info = app.getAddressFamilyInfo('::', '2001:db8::2');
  assert.equal(ipv6Info.family, 'ipv6');
  assert.equal(ipv6Info.badgeClass, 'badge-family-ipv6');
  assert.equal(ipv6Info.badgeText, 'IPv6');

  const mixedInfo = app.getAddressFamilyInfo('0.0.0.0', '2001:db8::2');
  assert.equal(mixedInfo.family, 'mixed');
  assert.equal(mixedInfo.badgeClass, 'badge-family-mixed');
  assert.match(mixedInfo.searchText, /mixed/i);
});

test('buildEgressNATFromForm normalizes single-target parent into parent-child scope', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge' },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'vmbr0', kind: 'bridge' }
  ];
  elements.egressNATParentInterface.value = 'tap100i0';
  elements.egressNATChildInterface.value = 'stale-child';
  elements.egressNATOutInterface.value = 'vmbr0';
  elements.egressNATOutSourceIP.value = '198.51.100.10';
  elements.egressNATProtocol.value = 'tcp+udp';
  elements.egressNATNatType.value = 'full_cone';

  const item = app.buildEgressNATFromForm();

  assert.equal(item.parent_interface, 'vmbr1');
  assert.equal(item.child_interface, 'tap100i0');
  assert.equal(item.out_interface, 'vmbr0');
  assert.equal(item.nat_type, 'full_cone');
});

test('buildEgressNATFromForm keeps standalone physical single-target as parent scope', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'enp1s0', kind: 'device' },
    { name: 'eno1', kind: 'device' }
  ];
  elements.egressNATParentInterface.value = 'enp1s0';
  elements.egressNATChildInterface.value = 'stale-child';
  elements.egressNATOutInterface.value = 'eno1';
  elements.egressNATProtocol.value = 'tcp+udp';

  const item = app.buildEgressNATFromForm();

  assert.equal(item.parent_interface, 'enp1s0');
  assert.equal(item.child_interface, '');
  assert.equal(item.out_interface, 'eno1');
});

test('formatEgressNATChildScope shows selected-interface label for single-target parent', () => {
  const { app } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge' },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'enp1s0', kind: 'device' }
  ];

  assert.equal(app.formatEgressNATChildScope('', 'tap100i0'), 'Selected Interface');
  assert.equal(app.formatEgressNATChildScope('', 'enp1s0'), 'Selected Interface');
  assert.equal(app.formatEgressNATChildScope('', 'vmbr1'), 'All Eligible Child Interfaces');
});

test('formatEgressNATStatsChildScope shows ALL for wildcard parent takeover', () => {
  const { app } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge' },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'enp1s0', kind: 'device' }
  ];

  assert.equal(app.formatEgressNATTableChildScope('', 'vmbr1'), 'ALL');
  assert.equal(app.formatEgressNATTableChildScope('', 'tap100i0'), 'Selected Interface');
  assert.equal(app.formatEgressNATTableChildScope('', 'enp1s0'), 'Selected Interface');
  assert.equal(app.formatEgressNATStatsChildScope('', 'vmbr1'), 'ALL');
  assert.equal(app.formatEgressNATStatsChildScope('', 'tap100i0'), 'Selected Interface');
  assert.equal(app.formatEgressNATStatsChildScope('', 'enp1s0'), 'Selected Interface');
});

test('populateEgressNATInterfaceSelectors filters standalone physical target from outbound list', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'enp1s0', kind: 'device', addrs: ['10.0.0.2'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] },
    { name: 'vmbr0', kind: 'bridge', addrs: ['198.51.100.1', '2001:db8::1', '203.0.113.20'] }
  ];
  elements.egressNATParentInterface.value = 'enp1s0';
  elements.egressNATOutInterface.value = 'eno1';

  app.populateEgressNATInterfaceSelectors();

  assert.deepEqual(
    elements.egressNATOutOptions.options.map((option) => option.label),
    ['eno1', 'vmbr0']
  );
  assert.equal(elements.egressNATParentPicker.value, 'enp1s0 [device] (10.0.0.2)');
  assert.equal(elements.egressNATOutPicker.value, 'eno1 [device] (198.51.100.10)');
});

test('populateEgressNATInterfaceSelectors filters selected child target from outbound list', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge' },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'tap101i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'vmbr0', kind: 'bridge' }
  ];
  elements.egressNATParentInterface.value = 'vmbr1';
  elements.egressNATChildInterface.value = 'tap100i0';
  elements.egressNATOutInterface.value = 'tap100i0';

  app.populateEgressNATInterfaceSelectors();

  assert.deepEqual(
    elements.egressNATOutOptions.options.map((option) => option.label),
    ['tap101i0', 'vmbr0', 'vmbr1']
  );
  assert.equal(elements.egressNATOutInterface.value, 'vmbr0');
  assert.equal(elements.egressNATOutPicker.value, 'vmbr0 [bridge]');
  assert.equal(
    elements.egressNATOutInterfaceHint.textContent,
    'Auto-selected a likely uplink interface: vmbr0. You can still change it manually.'
  );
});

test('populateEgressNATInterfaceSelectors auto-selects a likely uplink for empty outbound interface', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'eno1', kind: 'device' },
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86', '2402:1f00:8001:1856::1'] }
  ];
  elements.egressNATParentInterface.value = 'vmbr1';
  elements.egressNATChildInterface.value = 'tap100i0';

  app.populateEgressNATInterfaceSelectors();

  assert.equal(elements.egressNATOutInterface.value, 'vmbr0');
  assert.equal(elements.egressNATOutPicker.value, 'vmbr0 [bridge] (15.235.165.86, 2402:1f00:8001:1856::1)');
  assert.equal(
    elements.egressNATOutInterfaceHint.textContent,
    'Auto-selected a likely uplink interface: vmbr0. You can still change it manually.'
  );
  assert.equal(elements.egressNATOutInterfaceHint.hidden, false);
});

test('populateEgressNATInterfaceSelectors keeps manual outbound interface selection without auto hint', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap' },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] },
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86'] }
  ];
  elements.egressNATParentInterface.value = 'vmbr1';
  elements.egressNATChildInterface.value = 'tap100i0';
  elements.egressNATOutInterface.value = 'eno1';

  app.populateEgressNATInterfaceSelectors();

  assert.equal(elements.egressNATOutInterface.value, 'eno1');
  assert.equal(elements.egressNATOutPicker.value, 'eno1 [device] (198.51.100.10)');
  assert.equal(elements.egressNATOutInterfaceHint.textContent, '');
  assert.equal(elements.egressNATOutInterfaceHint.hidden, true);
});

test('populateEgressNATInterfaceSelectors populates picker option lists for parent child and outbound interfaces', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'tap100i0', parent: 'vmbr1', kind: 'tuntap', addrs: ['10.0.0.1'] },
    { name: 'tap200i0', parent: 'vmbr1', kind: 'tuntap', addrs: ['10.0.0.2'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] },
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86'] }
  ];
  elements.egressNATParentInterface.value = 'vmbr1';
  elements.egressNATChildInterface.value = 'tap200i0';

  app.populateEgressNATInterfaceSelectors({ preserveOutSelection: true, autoSelectOut: false });

  assert.deepEqual(
    elements.egressNATParentOptions.options.map((option) => option.label),
    ['eno1', 'tap100i0', 'tap200i0', 'vmbr0', 'vmbr1']
  );
  assert.deepEqual(
    elements.egressNATChildOptions.options.map((option) => option.label),
    ['tap100i0', 'tap200i0']
  );
  assert.deepEqual(
    elements.egressNATOutOptions.options.map((option) => option.label),
    ['eno1', 'tap100i0', 'vmbr0', 'vmbr1']
  );
});

test('syncInterfacePickerSelection resolves unique matches from typed interface text', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] }
  ];

  app.populateInterfacePicker(elements.inInterface, elements.inInterfacePicker, elements.inInterfaceOptions, {
    preserveSelected: true
  });
  elements.inInterfacePicker.value = '10.0.0.254';

  const result = app.syncInterfacePickerSelection(elements.inInterface, elements.inInterfacePicker, { commitLabel: true });

  assert.equal(result.value, 'vmbr1');
  assert.equal(elements.inInterface.value, 'vmbr1');
  assert.equal(elements.inInterfacePicker.value, 'vmbr1 [bridge] (10.0.0.254)');
});

test('populateEgressNATInterfaceSelectors disables child picker for single-target parent', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'enp1s0', kind: 'device', addrs: ['10.0.0.2'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] }
  ];
  elements.egressNATParentInterface.value = 'enp1s0';

  app.populateEgressNATInterfaceSelectors();

  assert.equal(elements.egressNATChildPicker.disabled, true);
  assert.equal(elements.egressNATChildPicker.placeholder, 'Selected Interface');
});

test('refreshRuleInterfaceSelectors syncs picker labels from hidden interface values', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86', '2402:db8::1'] },
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10', '2001:db8::10'] }
  ];
  elements.inInterface.value = 'vmbr1';
  elements.outInterface.value = 'eno1';
  elements.outIP.value = '2001:db8::20';
  elements.ruleOutSourceIP.value = '198.51.100.10';

  app.refreshRuleInterfaceSelectors();

  assert.deepEqual(elements.inInterfaceOptions.options.map((option) => option.label), ['vmbr0', 'vmbr1', 'eno1']);
  assert.deepEqual(elements.outInterfaceOptions.options.map((option) => option.label), ['vmbr0', 'vmbr1', 'eno1']);
  assert.equal(elements.inInterface.value, 'vmbr1');
  assert.equal(elements.outInterface.value, 'eno1');
  assert.equal(elements.inInterfacePicker.value, 'vmbr1 [bridge] (10.0.0.254)');
  assert.equal(elements.outInterfacePicker.value, 'eno1 [device] (198.51.100.10, 2001:db8::10)');
  assert.equal(elements.ruleOutSourceIP.value, '');
  assert.deepEqual(
    elements.ruleOutSourceIPOptions.options.map((option) => option.value),
    ['2001:db8::10']
  );
});

test('refreshSiteInterfaceSelectors syncs picker label from hidden interface value', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] },
    { name: 'lo', kind: 'device', addrs: ['127.0.0.1', '::1'] }
  ];
  elements.siteListenIface.value = 'vmbr0';

  app.refreshSiteInterfaceSelectors();

  assert.deepEqual(elements.siteListenIfaceOptions.options.map((option) => option.label), ['vmbr0', 'eno1', 'lo']);
  assert.equal(elements.siteListenIface.value, 'vmbr0');
  assert.equal(elements.siteListenIfacePicker.value, 'vmbr0 [bridge] (15.235.165.86)');
});

test('refreshSiteBackendSourceIPOptions filters candidates to backend family', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86', '2402:db8::1'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10', '2001:db8::10'] }
  ];
  elements.siteBackendIP.value = '2001:db8::99';
  elements.siteBackendSourceIP.value = '198.51.100.10';

  app.refreshSiteBackendSourceIPOptions();

  assert.equal(elements.siteBackendSourceIP.value, '');
  assert.deepEqual(
    elements.siteBackendSourceIPOptions.options.map((option) => option.value),
    ['2402:db8::1', '2001:db8::10']
  );
});

test('refreshRangeInterfaceSelectors syncs picker labels from hidden interface values', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86'] },
    { name: 'vmbr1', kind: 'bridge', addrs: ['10.0.0.254'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10', '2001:db8::10'] }
  ];
  elements.rangeInInterface.value = 'vmbr1';
  elements.rangeOutInterface.value = 'eno1';
  elements.rangeOutIP.value = '2001:db8::20';
  elements.rangeOutSourceIP.value = '198.51.100.10';

  app.refreshRangeInterfaceSelectors();

  assert.deepEqual(elements.rangeInInterfaceOptions.options.map((option) => option.label), ['vmbr0', 'vmbr1', 'eno1']);
  assert.deepEqual(elements.rangeOutInterfaceOptions.options.map((option) => option.label), ['vmbr0', 'vmbr1', 'eno1']);
  assert.equal(elements.rangeInInterface.value, 'vmbr1');
  assert.equal(elements.rangeOutInterface.value, 'eno1');
  assert.equal(elements.rangeInInterfacePicker.value, 'vmbr1 [bridge] (10.0.0.254)');
  assert.equal(elements.rangeOutInterfacePicker.value, 'eno1 [device] (198.51.100.10, 2001:db8::10)');
  assert.equal(elements.rangeOutSourceIP.value, '');
  assert.deepEqual(
    elements.rangeOutSourceIPOptions.options.map((option) => option.value),
    ['2001:db8::10']
  );
});

test('updateRuleTransparentWarning disables transparent mode for IPv6 targets', () => {
  const { app, elements } = createHarness();
  elements.ruleTransparent.checked = true;
  elements.outIP.value = '2001:db8::20';
  elements.ruleOutSourceIP.value = '2001:db8::10';

  const warning = app.updateRuleTransparentWarning();

  assert.equal(elements.ruleTransparent.disabled, true);
  assert.equal(elements.ruleTransparent.checked, false);
  assert.equal(elements.ruleOutSourceIP.disabled, false);
  assert.equal(warning.text, 'Transparent mode currently supports IPv4 targets only. Disable it for IPv6 targets.');
  assert.equal(elements.ruleTransparentWarning.textContent, warning.text);
});

test('updateSiteTransparentWarning disables transparent mode for IPv6 backends', () => {
  const { app, elements } = createHarness();
  elements.siteTransparent.checked = true;
  elements.siteBackendIP.value = '2001:db8::99';
  elements.siteBackendSourceIP.value = '2001:db8::10';

  const warning = app.updateSiteTransparentWarning();

  assert.equal(elements.siteTransparent.disabled, true);
  assert.equal(elements.siteTransparent.checked, false);
  assert.equal(elements.siteBackendSourceIP.disabled, false);
  assert.equal(warning.text, 'Transparent mode currently supports IPv4 targets only. Disable it for IPv6 targets.');
  assert.equal(elements.siteTransparentWarning.textContent, warning.text);
});

test('updateRangeTransparentWarning disables transparent mode for IPv6 targets', () => {
  const { app, elements } = createHarness();
  elements.rangeTransparent.checked = true;
  elements.rangeOutIP.value = '2001:db8::42';
  elements.rangeOutSourceIP.value = '2001:db8::10';

  const warning = app.updateRangeTransparentWarning();

  assert.equal(elements.rangeTransparent.disabled, true);
  assert.equal(elements.rangeTransparent.checked, false);
  assert.equal(elements.rangeOutSourceIP.disabled, false);
  assert.equal(warning.text, 'Transparent mode currently supports IPv4 targets only. Disable it for IPv6 targets.');
  assert.equal(elements.rangeTransparentWarning.textContent, warning.text);
});

test('buildRuleFromForm uses typed picker text when no exact interface match exists', () => {
  const { app, elements } = createHarness();
  app.interfaces = [
    { name: 'vmbr0', kind: 'bridge', addrs: ['15.235.165.86'] },
    { name: 'eno1', kind: 'device', addrs: ['198.51.100.10'] }
  ];
  elements.inInterfacePicker.value = 'missing-interface';
  elements.outInterface.value = 'eno1';
  elements.inIP.value = '0.0.0.0';
  elements.outIP.value = '198.51.100.2';
  elements.inPort.value = '1000';
  elements.outPort.value = '2000';
  elements.protocol.value = 'tcp';

  const rule = app.buildRuleFromForm();

  assert.equal(rule.in_interface, 'missing-interface');
  assert.equal(rule.out_interface, 'eno1');
});

test('shouldPauseAutoRefresh returns true while picker input is focused', () => {
  const { app, elements, documentRef } = createHarness();
  documentRef.activeElement = elements.inInterfacePicker;

  assert.equal(app.shouldPauseAutoRefresh(), true);
});

test('shouldPauseAutoRefresh returns false when no transient interaction is active', () => {
  const { app, documentRef } = createHarness();
  documentRef.activeElement = null;

  assert.equal(app.shouldPauseAutoRefresh(), false);
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

test('toggleEgressNAT shows translated not-found issue in toast', async () => {
  const { app, notifications } = createHarness();
  app.state.egressNATs.data = [{ id: 17, enabled: true }];
  app.apiCall = async () => {
    const err = new Error('toggle failed');
    err.payload = { issues: [{ scope: 'toggle', field: 'id', message: 'egress nat not found' }] };
    throw err;
  };

  await app.toggleEgressNAT(17);

  assert.equal(notifications.at(-1).message, 'Operation failed: The egress NAT takeover no longer exists.');
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
