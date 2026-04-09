(function () {
  const app = window.ForwardApp;
  if (!app) return;

  Object.assign(app.el, {
    editManagedNetworkId: app.$('editManagedNetworkId'),
    managedNetworkForm: app.$('managedNetworkForm'),
    managedNetworkFormTitle: app.$('managedNetworkFormTitle'),
    managedNetworkSubmitBtn: app.$('managedNetworkSubmitBtn'),
    managedNetworkCancelBtn: app.$('managedNetworkCancelBtn'),
    managedNetworkPVEQuickFillBtn: app.$('managedNetworkPVEQuickFillBtn'),
    managedNetworkName: app.$('managedNetworkName'),
    managedNetworkRemark: app.$('managedNetworkRemark'),
    managedNetworkBridgeLabel: app.$('managedNetworkBridgeLabel'),
    managedNetworkBridgeMode: app.$('managedNetworkBridgeMode'),
    managedNetworkBridgeInterface: app.$('managedNetworkBridgeInterface'),
    managedNetworkBridgePicker: app.$('managedNetworkBridgePicker'),
    managedNetworkBridgeOptions: app.$('managedNetworkBridgeOptions'),
    managedNetworkBridgeAdvancedRow: app.$('managedNetworkBridgeAdvancedRow'),
    managedNetworkBridgeAdvancedDetails: app.$('managedNetworkBridgeAdvancedDetails'),
    managedNetworkBridgeMTU: app.$('managedNetworkBridgeMTU'),
    managedNetworkBridgeVLANAware: app.$('managedNetworkBridgeVLANAware'),
    managedNetworkUplinkInterface: app.$('managedNetworkUplinkInterface'),
    managedNetworkUplinkPicker: app.$('managedNetworkUplinkPicker'),
    managedNetworkUplinkOptions: app.$('managedNetworkUplinkOptions'),
    managedNetworkIPv4Enabled: app.$('managedNetworkIPv4Enabled'),
    managedNetworkIPv4CIDR: app.$('managedNetworkIPv4CIDR'),
    managedNetworkIPv4Gateway: app.$('managedNetworkIPv4Gateway'),
    managedNetworkIPv4PoolStart: app.$('managedNetworkIPv4PoolStart'),
    managedNetworkIPv4PoolEnd: app.$('managedNetworkIPv4PoolEnd'),
    managedNetworkIPv4DNSServers: app.$('managedNetworkIPv4DNSServers'),
    managedNetworkIPv6Enabled: app.$('managedNetworkIPv6Enabled'),
    managedNetworkIPv6ParentInterface: app.$('managedNetworkIPv6ParentInterface'),
    managedNetworkIPv6ParentPicker: app.$('managedNetworkIPv6ParentPicker'),
    managedNetworkIPv6ParentOptions: app.$('managedNetworkIPv6ParentOptions'),
    managedNetworkIPv6ParentPrefix: app.$('managedNetworkIPv6ParentPrefix'),
    managedNetworkIPv6AssignmentMode: app.$('managedNetworkIPv6AssignmentMode'),
    managedNetworkAutoEgressNAT: app.$('managedNetworkAutoEgressNAT'),
    managedNetworksBody: app.$('managedNetworksBody'),
    noManagedNetworks: app.$('noManagedNetworks'),
    managedNetworksSearchInput: app.$('managedNetworksSearchInput'),
    managedNetworkRuntimeStatusBtn: app.$('managedNetworkRuntimeStatusBtn'),
    repairManagedNetworkRuntimeBtn: app.$('repairManagedNetworkRuntimeBtn'),
    reloadManagedNetworkRuntimeBtn: app.$('reloadManagedNetworkRuntimeBtn'),
    emptyAddManagedNetworkBtn: app.$('emptyAddManagedNetworkBtn'),
    editManagedNetworkReservationId: app.$('editManagedNetworkReservationId'),
    managedNetworkReservationForm: app.$('managedNetworkReservationForm'),
    managedNetworkReservationFormTitle: app.$('managedNetworkReservationFormTitle'),
    managedNetworkReservationSubmitBtn: app.$('managedNetworkReservationSubmitBtn'),
    managedNetworkReservationCancelBtn: app.$('managedNetworkReservationCancelBtn'),
    managedNetworkReservationManagedNetworkId: app.$('managedNetworkReservationManagedNetworkId'),
    managedNetworkReservationMACAddress: app.$('managedNetworkReservationMACAddress'),
    managedNetworkReservationIPv4Address: app.$('managedNetworkReservationIPv4Address'),
    managedNetworkReservationRemark: app.$('managedNetworkReservationRemark'),
    managedNetworkReservationCandidatesFilterMeta: app.$('managedNetworkReservationCandidatesFilterMeta'),
    managedNetworkReservationCandidatesSearchInput: app.$('managedNetworkReservationCandidatesSearchInput'),
    managedNetworkReservationCandidatesBody: app.$('managedNetworkReservationCandidatesBody'),
    noManagedNetworkReservationCandidates: app.$('noManagedNetworkReservationCandidates'),
    managedNetworkReservationsBody: app.$('managedNetworkReservationsBody'),
    noManagedNetworkReservations: app.$('noManagedNetworkReservations'),
    managedNetworkReservationsSearchInput: app.$('managedNetworkReservationsSearchInput'),
    emptyAddManagedNetworkReservationBtn: app.$('emptyAddManagedNetworkReservationBtn')
  });

  app.state.managedNetworks = app.state.managedNetworks || { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.managedNetworkRuntimeReloadStatus = app.state.managedNetworkRuntimeReloadStatus || null;
  app.state.managedNetworkReservationCandidates = app.state.managedNetworkReservationCandidates || { data: [], page: 1, pageSize: 10, searchQuery: '', selectedIPv4ByKey: {} };
  app.state.managedNetworkReservations = app.state.managedNetworkReservations || { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.forms = app.state.forms || {};
  app.state.forms.managedNetwork = app.state.forms.managedNetwork || { mode: 'add', sourceId: 0 };
  app.state.forms.managedNetworkReservation = app.state.forms.managedNetworkReservation || { mode: 'add', sourceId: 0 };
  app.state.pendingForms = app.state.pendingForms || {};
  if (!Object.prototype.hasOwnProperty.call(app.state.pendingForms, 'managedNetwork')) app.state.pendingForms.managedNetwork = false;
  if (!Object.prototype.hasOwnProperty.call(app.state.pendingForms, 'managedNetworkReservation')) app.state.pendingForms.managedNetworkReservation = false;

  function hostInterfaces() {
    return Array.isArray(app.hostNetworkInterfaces) ? app.hostNetworkInterfaces : [];
  }

  function hostInterfaceToPickerItem(iface) {
    const addresses = Array.isArray(iface && iface.addresses) ? iface.addresses : [];
    return {
      name: String((iface && iface.name) || '').trim(),
      kind: String((iface && iface.kind) || '').trim(),
      parent: String((iface && iface.parent) || '').trim(),
      addrs: addresses
        .map((address) => String((address && address.ip) || '').trim())
        .filter(Boolean)
    };
  }

  function isLoopbackPickerItem(iface) {
    return String((iface && iface.name) || '').trim().toLowerCase() === 'lo';
  }

  function hasIPv6Prefix(iface) {
    return (Array.isArray(iface && iface.addresses) ? iface.addresses : []).some((address) =>
      address && address.family === 'ipv6' && String(address.cidr || '').trim()
    );
  }

  function hostPickerItems(filterFn) {
    return hostInterfaces()
      .filter((iface) => iface && iface.name && !isLoopbackPickerItem(iface) && (!filterFn || filterFn(iface)))
      .map((iface) => hostInterfaceToPickerItem(iface))
      .sort((a, b) => {
        const aBridge = /bridge/i.test(a.kind) ? 0 : 1;
        const bBridge = /bridge/i.test(b.kind) ? 0 : 1;
        if (aBridge !== bBridge) return aBridge - bBridge;
        return app.compareValues(a.name, b.name);
      });
  }

  function normalizeManagedNetworkIPv6AssignmentMode(value) {
    return String(value || '').trim().toLowerCase() === 'prefix_64' ? 'prefix_64' : 'single_128';
  }

  function normalizeManagedNetworkBridgeMode(value) {
    return String(value || '').trim().toLowerCase() === 'existing' ? 'existing' : 'create';
  }

  function managedNetworkUsesExistingBridge() {
    return normalizeManagedNetworkBridgeMode(app.el.managedNetworkBridgeMode && app.el.managedNetworkBridgeMode.value) === 'existing';
  }

  function managedNetworkBridgePlaceholder() {
    return app.t(
      managedNetworkUsesExistingBridge()
        ? 'managedNetwork.form.bridge.placeholder.existing'
        : 'managedNetwork.form.bridge.placeholder.create'
    );
  }

  function managedNetworkBridgeLabelKey() {
    return managedNetworkUsesExistingBridge()
      ? 'managedNetwork.form.bridge.existingLabel'
      : 'managedNetwork.form.bridge.createLabel';
  }

  function syncManagedNetworkBridgeFieldPresentation() {
    const el = app.el;
    const placeholder = managedNetworkBridgePlaceholder();
    if (el.managedNetworkBridgeLabel) {
      el.managedNetworkBridgeLabel.textContent = app.t(managedNetworkBridgeLabelKey());
    }
    if (el.managedNetworkBridgePicker) {
      el.managedNetworkBridgePicker.placeholder = placeholder;
    }
  }

  function setManagedNetworkBridgeAdvancedExpanded(expanded) {
    if (app.el.managedNetworkBridgeAdvancedDetails) {
      app.el.managedNetworkBridgeAdvancedDetails.open = !!expanded;
    }
  }

  function hasManagedNetworkBridgeAdvancedConfig(item) {
    if (!item || normalizeManagedNetworkBridgeMode(item.bridge_mode) === 'existing') return false;
    return (Number(item.bridge_mtu) > 0) || !!item.bridge_vlan_aware;
  }

  function suggestManagedNetworkBridgeName() {
    const used = new Set(
      hostInterfaces()
        .map((iface) => String((iface && iface.name) || '').trim().toLowerCase())
        .filter(Boolean)
    );
    for (let index = 0; index < 4096; index++) {
      const name = 'vmbr' + index;
      if (!used.has(name.toLowerCase())) return name;
    }
    return 'vmbr4096';
  }

  function isManagedNetworkBridgeAutofilled() {
    return !!(app.el.managedNetworkBridgePicker && app.el.managedNetworkBridgePicker.dataset && app.el.managedNetworkBridgePicker.dataset.autofilled === 'true');
  }

  function setManagedNetworkBridgeAutofilled(enabled) {
    if (!app.el.managedNetworkBridgePicker || !app.el.managedNetworkBridgePicker.dataset) return;
    if (enabled) app.el.managedNetworkBridgePicker.dataset.autofilled = 'true';
    else delete app.el.managedNetworkBridgePicker.dataset.autofilled;
  }

  function maybeAutofillManagedNetworkBridgeName() {
    const el = app.el;
    if (managedNetworkUsesExistingBridge()) {
      setManagedNetworkBridgeAutofilled(false);
      return;
    }
    const formState = app.state.forms.managedNetwork || { mode: 'add', sourceId: 0 };
    const currentValue = String(el.managedNetworkBridgeInterface && el.managedNetworkBridgeInterface.value || '').trim();
    const currentText = String(el.managedNetworkBridgePicker && el.managedNetworkBridgePicker.value || '').trim();
    if (formState.mode !== 'add') return;
    if (currentText && currentText !== currentValue) return;
    const suggested = suggestManagedNetworkBridgeName();
    if (!suggested) return;
    if ((currentValue || currentText) && !isManagedNetworkBridgeAutofilled()) return;
    if (currentValue === suggested && currentText === suggested) return;
    if (el.managedNetworkBridgeInterface) el.managedNetworkBridgeInterface.value = suggested;
    if (el.managedNetworkBridgePicker) el.managedNetworkBridgePicker.value = suggested;
    setManagedNetworkBridgeAutofilled(true);
  }

  function compareIPv4Text(a, b) {
    const left = app.parseIPv4(a);
    const right = app.parseIPv4(b);
    if (!left || !right) return 0;
    for (let i = 0; i < 4; i++) {
      if (left[i] !== right[i]) return left[i] - right[i];
    }
    return 0;
  }

  function hostInterfaceAddressesByFamily(iface, family) {
    return (Array.isArray(iface && iface.addresses) ? iface.addresses : []).filter((address) =>
      address && (!family || address.family === family)
    );
  }

  function isBridgeHostInterface(iface) {
    return /bridge/i.test(String((iface && iface.kind) || '').trim());
  }

  function isLikelyGuestHostInterface(iface) {
    const name = String((iface && iface.name) || '').trim().toLowerCase();
    if (!name) return false;
    return /^(tap|fwpr|fwln|fwbr|veth|virbr|docker|cali|cni|lxc|vnet)/.test(name);
  }

  function hostInterfaceHasPublicIPv4(iface) {
    return hostInterfaceAddressesByFamily(iface, 'ipv4').some((address) => app.isPublicIPv4(address && address.ip));
  }

  function hostInterfaceHasIPv4(iface) {
    return hostInterfaceAddressesByFamily(iface, 'ipv4').length > 0;
  }

  function hostInterfaceIPv6Prefixes(iface) {
    return hostInterfaceAddressesByFamily(iface, 'ipv6')
      .map((address) => String((address && address.cidr) || '').trim())
      .filter(Boolean);
  }

  function hasManagedNetworkPVENonGuestSlave(items, bridgeName) {
    const currentBridge = String(bridgeName || '').trim();
    if (!currentBridge) return false;
    return (Array.isArray(items) ? items : []).some((iface) => {
      if (!iface || !iface.name || isLikelyGuestHostInterface(iface)) return false;
      return String(iface.parent || '').trim() === currentBridge;
    });
  }

  function scoreManagedNetworkPVEUplink(iface) {
    if (!iface || !iface.name || isLikelyGuestHostInterface(iface)) return -1;

    const name = String(iface.name).trim().toLowerCase();
    let score = 0;
    if (hostInterfaceHasIPv4(iface)) score += 200;
    if (hostInterfaceHasPublicIPv4(iface)) score += 120;
    if (name === 'vmbr0') score += 100;
    if (isBridgeHostInterface(iface)) score += 60;
    if (/^vmbr\d+$/.test(name)) score += 20;
    if (hostInterfaceIPv6Prefixes(iface).length > 0) score += 10;
    if (String(iface.parent || '').trim()) score -= 10;
    return score;
  }

  function pickManagedNetworkPVEUplink() {
    const items = hostInterfaces()
      .filter((iface) => iface && iface.name && !isLoopbackPickerItem(iface))
      .slice();

    const sortByScore = (list) => list.slice().sort((a, b) => {
      const scoreDiff = scoreManagedNetworkPVEUplink(b) - scoreManagedNetworkPVEUplink(a);
      if (scoreDiff !== 0) return scoreDiff;
      return app.compareValues(String(a.name || ''), String(b.name || ''));
    });

    const establishedBridgeUplinks = sortByScore(items.filter((iface) => {
      if (!isBridgeHostInterface(iface) || !hostInterfaceHasIPv4(iface)) return false;
      return hasManagedNetworkPVENonGuestSlave(items, iface.name);
    }));
    if (establishedBridgeUplinks.length) {
      return establishedBridgeUplinks[0];
    }

    const directPhysicalUplinks = sortByScore(items.filter((iface) => {
      if (isBridgeHostInterface(iface)) return false;
      if (String(iface.parent || '').trim()) return false;
      return hostInterfaceHasIPv4(iface);
    }));
    if (directPhysicalUplinks.length) {
      return directPhysicalUplinks[0];
    }

    const ranked = sortByScore(items);
    return ranked.length ? ranked[0] : null;
  }

  function parseIPv4CIDRRange(value) {
    const text = String(value || '').trim();
    const slash = text.lastIndexOf('/');
    if (slash <= 0 || slash === text.length - 1) return null;
    const ip = text.slice(0, slash).trim();
    const prefixLen = parseInt(text.slice(slash + 1).trim(), 10);
    const parts = app.parseIPv4(ip);
    if (!parts || Number.isNaN(prefixLen) || prefixLen < 0 || prefixLen > 32) return null;

    const ipValue = (((parts[0] << 24) >>> 0) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
    const network = (ipValue & mask) >>> 0;
    const broadcast = (network | (~mask >>> 0)) >>> 0;
    return { network, broadcast, prefixLen };
  }

  function ipv4RangeOverlaps(a, b) {
    return !!(a && b) && a.network <= b.broadcast && b.network <= a.broadcast;
  }

  function uint32ToIPv4Text(value) {
    const current = value >>> 0;
    return [
      (current >>> 24) & 0xff,
      (current >>> 16) & 0xff,
      (current >>> 8) & 0xff,
      current & 0xff
    ].join('.');
  }

  function collectManagedNetworkPVEUsedIPv4Ranges() {
    const ranges = [];

    hostInterfaces().forEach((iface) => {
      hostInterfaceAddressesByFamily(iface, 'ipv4').forEach((address) => {
        const current = parseIPv4CIDRRange(address && address.cidr);
        if (current) ranges.push(current);
      });
    });

    const managedNetworks = app.state && app.state.managedNetworks && Array.isArray(app.state.managedNetworks.data)
      ? app.state.managedNetworks.data
      : [];
    managedNetworks.forEach((item) => {
      const current = parseIPv4CIDRRange(item && item.ipv4_cidr);
      if (current) ranges.push(current);
    });

    return ranges;
  }

  function pickManagedNetworkPVEIPv4CIDR() {
    const used = collectManagedNetworkPVEUsedIPv4Ranges();
    const groups = [
      { first: 192, second: 168, start: 100, end: 250 },
      { first: 10, second: 10, start: 10, end: 250 }
    ];

    for (let groupIndex = 0; groupIndex < groups.length; groupIndex++) {
      const group = groups[groupIndex];
      for (let octet = group.start; octet <= group.end; octet++) {
        const cidr = group.first + '.' + group.second + '.' + octet + '.1/24';
        const candidate = parseIPv4CIDRRange(cidr);
        if (!candidate) continue;
        if (used.some((current) => ipv4RangeOverlaps(candidate, current))) continue;
        return cidr;
      }
    }

    return '192.168.100.1/24';
  }

  function deriveManagedNetworkPVEPool(cidr) {
    const range = parseIPv4CIDRRange(cidr);
    if (!range || range.prefixLen !== 24) {
      return { start: '', end: '' };
    }
    return {
      start: uint32ToIPv4Text(range.network + 10),
      end: uint32ToIPv4Text(Math.max(range.network + 10, range.broadcast - 5))
    };
  }

  function pickManagedNetworkPVEIPv6Parent(uplinkName) {
    const selectedUplink = String(uplinkName || '').trim();
    const items = hostInterfaces().filter((iface) => hostInterfaceIPv6Prefixes(iface).length > 0);
    if (!items.length) return null;

    const preferred = items.find((iface) => String(iface && iface.name || '').trim() === selectedUplink);
    const current = preferred || items[0];
    const prefixes = hostInterfaceIPv6Prefixes(current);
    if (!current || !prefixes.length) return null;

    return {
      name: String(current.name || '').trim(),
      prefix: prefixes[0]
    };
  }

  function parseManagedNetworkBridgeMTUValue() {
    const text = String(app.el.managedNetworkBridgeMTU && app.el.managedNetworkBridgeMTU.value || '').trim();
    if (!text) return 0;
    if (!/^\d+$/.test(text)) return 0;
    const value = parseInt(text, 10);
    return Number.isFinite(value) ? value : 0;
  }

  function isValidManagedNetworkBridgeMTUText(value) {
    const text = String(value || '').trim();
    if (!text) return true;
    if (!/^\d+$/.test(text)) return false;
    const parsed = parseInt(text, 10);
    return Number.isFinite(parsed) && parsed >= 0 && parsed <= 65535;
  }

  function isValidIPv4CIDR(value) {
    const text = String(value || '').trim();
    const slash = text.lastIndexOf('/');
    if (slash <= 0 || slash === text.length - 1) return false;
    const ip = text.slice(0, slash).trim();
    const prefixLen = parseInt(text.slice(slash + 1).trim(), 10);
    return !!app.parseIPv4(ip) && !Number.isNaN(prefixLen) && prefixLen >= 0 && prefixLen <= 32;
  }

  function splitIPv4List(value) {
    return String(value || '')
      .split(/[\s,;]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function normalizeMACAddress(value) {
    const text = String(value || '').trim().toLowerCase().replace(/-/g, ':');
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(text)) return '';
    return text;
  }

  function isValidMACAddress(value) {
    return !!normalizeMACAddress(value);
  }

  function setInputDisabled(input, disabled) {
    if (!input) return;
    input.disabled = !!disabled;
    if (disabled) input.setAttribute('aria-disabled', 'true');
    else input.removeAttribute('aria-disabled');
  }

  function managedNetworkIPv6ParentPrefixOptions(parentName) {
    if (typeof app.getIPv6ParentPrefixOptions === 'function') {
      return app.getIPv6ParentPrefixOptions(parentName);
    }
    return [];
  }

  function formatManagedNetworkIPv6ParentPrefixOption(option) {
    if (typeof app.formatIPv6ParentPrefixOption === 'function') {
      return app.formatIPv6ParentPrefixOption(option);
    }
    return option && option.value ? option.value : '';
  }

  function ensureSelectOption(selectEl, value, label) {
    if (!selectEl || !value) return;
    const exists = Array.from(selectEl.options || []).some((option) => option.value === value);
    if (exists) return;
    app.addOption(selectEl, value, label || value);
  }

  function populateManagedNetworkIPv6ParentPrefixSelect(selected) {
    const el = app.el;
    const selectEl = el.managedNetworkIPv6ParentPrefix;
    if (!selectEl) return;

    const enabled = !!(el.managedNetworkIPv6Enabled && el.managedNetworkIPv6Enabled.checked);
    const parentName = String(el.managedNetworkIPv6ParentInterface && el.managedNetworkIPv6ParentInterface.value || '').trim();
    const current = selected == null ? String(selectEl.value || '').trim() : String(selected || '').trim();

    app.clearNode(selectEl);
    if (!enabled) {
      app.addSelectPlaceholderOption(selectEl, app.t('common.selectInterfaceFirst'), { value: '' });
      selectEl.value = '';
      setInputDisabled(selectEl, true);
      return;
    }

    if (!parentName) {
      app.addSelectPlaceholderOption(selectEl, app.t('common.selectInterfaceFirst'), { value: '' });
      selectEl.value = '';
      setInputDisabled(selectEl, false);
      return;
    }

    const options = managedNetworkIPv6ParentPrefixOptions(parentName);
    if (!options.length) {
      app.addSelectPlaceholderOption(selectEl, app.t('ipv6.form.parentPrefix.empty'), { value: '' });
      selectEl.value = '';
      setInputDisabled(selectEl, false);
      return;
    }

    app.addSelectPlaceholderOption(selectEl, app.t('common.unspecified'), { value: '', hidden: true });
    options.forEach((option) => {
      app.addOption(selectEl, option.value, formatManagedNetworkIPv6ParentPrefixOption(option));
    });
    if (current) ensureSelectOption(selectEl, current, current);

    let resolved = current;
    if (!resolved || !Array.from(selectEl.options || []).some((option) => option.value === resolved)) {
      resolved = options[0].value;
    }
    selectEl.value = resolved || '';
    setInputDisabled(selectEl, false);
  }

  function syncManagedNetworkOptionStates() {
    const el = app.el;
    const ipv4Enabled = !!(el.managedNetworkIPv4Enabled && el.managedNetworkIPv4Enabled.checked);
    const ipv6Enabled = !!(el.managedNetworkIPv6Enabled && el.managedNetworkIPv6Enabled.checked);
    const createMode = !managedNetworkUsesExistingBridge();

    if (el.managedNetworkBridgeAdvancedRow) {
      el.managedNetworkBridgeAdvancedRow.hidden = !createMode;
    }
    if (!createMode) {
      setManagedNetworkBridgeAdvancedExpanded(false);
    }

    [
      el.managedNetworkBridgeMTU,
      el.managedNetworkBridgeVLANAware
    ].forEach((input) => setInputDisabled(input, !createMode));

    [
      el.managedNetworkIPv4CIDR,
      el.managedNetworkIPv4Gateway,
      el.managedNetworkIPv4PoolStart,
      el.managedNetworkIPv4PoolEnd,
      el.managedNetworkIPv4DNSServers
    ].forEach((input) => setInputDisabled(input, !ipv4Enabled));

    [
      el.managedNetworkIPv6ParentPicker,
      el.managedNetworkIPv6ParentInterface,
      el.managedNetworkIPv6ParentPrefix,
      el.managedNetworkIPv6AssignmentMode
    ].forEach((input) => setInputDisabled(input, !ipv6Enabled));
  }

  function assignmentModeLabel(value) {
    return app.t(
      normalizeManagedNetworkIPv6AssignmentMode(value) === 'prefix_64'
        ? 'managedNetwork.form.ipv6Mode.prefix64'
        : 'managedNetwork.form.ipv6Mode.single128'
    );
  }

  function enabledBadge(enabled) {
    return app.createBadgeNode(
      enabled ? 'badge-running' : 'badge-disabled',
      app.t(enabled ? 'status.enabled' : 'status.disabled')
    );
  }

  function runtimeStatusInfo(status, enabled) {
    return app.statusInfo(String(status || '').trim().toLowerCase(), enabled);
  }

  function managedNetworkRuntimeReloadSourceLabel(source) {
    const normalized = String(source || '').trim().toLowerCase();
    if (normalized === 'link_change') return app.t('managedNetwork.runtimeReload.source.linkChange');
    if (normalized === 'manual') return app.t('managedNetwork.runtimeReload.source.manual');
    return normalized || app.t('managedNetwork.runtimeReload.result.unknown');
  }

  function formatManagedNetworkRuntimeReloadTimestamp(value) {
    const text = String(value || '').trim();
    if (!text) return '';
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return text;
    return new Intl.DateTimeFormat(app.state.locale, {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).format(date);
  }

  function managedNetworkRuntimeReloadBadgeInfo(status) {
    const item = status && typeof status === 'object' ? status : {};
    const source = String(item.last_request_source || '').trim().toLowerCase();
    const result = String(item.last_result || '').trim().toLowerCase();
    if (item.pending) {
      return {
        text: app.t('managedNetwork.runtimeReload.badge.pending'),
        tone: 'pending',
        detail: app.t('managedNetwork.runtimeReload.result.pending')
      };
    }
    if (result === 'fallback') {
      return {
        text: app.t('managedNetwork.runtimeReload.badge.fallback'),
        tone: 'warning',
        detail: app.t('managedNetwork.runtimeReload.result.fallback')
      };
    }
    if (result === 'partial') {
      return {
        text: app.t('managedNetwork.runtimeReload.badge.partial'),
        tone: 'warning',
        detail: app.t('managedNetwork.runtimeReload.result.partial')
      };
    }
    if (result === 'success') {
      if (source === 'link_change') {
        return {
          text: app.t('managedNetwork.runtimeReload.badge.autoRecovered'),
          tone: 'success',
          detail: app.t('managedNetwork.runtimeReload.result.autoRecovered')
        };
      }
      return {
        text: app.t('managedNetwork.runtimeReload.badge.reloaded'),
        tone: 'success',
        detail: app.t('managedNetwork.runtimeReload.result.success')
      };
    }
    if (String(item.last_error || '').trim()) {
      return {
        text: app.t('managedNetwork.runtimeReload.badge.partial'),
        tone: 'warning',
        detail: String(item.last_error || '').trim()
      };
    }
    return {
      text: app.t('managedNetwork.runtimeReload.badge.idle'),
      tone: 'idle',
      detail: app.t('managedNetwork.runtimeReload.result.idle')
    };
  }

  function managedNetworkRuntimeReloadTooltipLines(status) {
    const item = status && typeof status === 'object' ? status : {};
    const badge = managedNetworkRuntimeReloadBadgeInfo(item);
    const lines = [
      app.t('managedNetwork.runtimeReload.tooltip.status') + ': ' + badge.detail
    ];
    if (item.pending && item.due_at) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.dueAt') + ': ' + formatManagedNetworkRuntimeReloadTimestamp(item.due_at));
    }
    if (item.last_request_source) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.source') + ': ' + managedNetworkRuntimeReloadSourceLabel(item.last_request_source));
    }
    if (item.last_requested_at) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.requestedAt') + ': ' + formatManagedNetworkRuntimeReloadTimestamp(item.last_requested_at));
    }
    if (item.last_started_at) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.startedAt') + ': ' + formatManagedNetworkRuntimeReloadTimestamp(item.last_started_at));
    }
    if (item.last_completed_at) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.completedAt') + ': ' + formatManagedNetworkRuntimeReloadTimestamp(item.last_completed_at));
    }
    if (item.last_request_summary) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.requestSummary') + ': ' + String(item.last_request_summary).trim());
    }
    if (item.last_applied_summary) {
      const appliedSummaryLabel = app.t('managedNetwork.runtimeReload.tooltip.appliedSummary');
      const appliedSummaryTokens = String(item.last_applied_summary)
        .trim()
        .split(/\s+/)
        .map((value) => String(value || '').trim())
        .filter(Boolean);
      if (appliedSummaryTokens.length > 1) {
        appliedSummaryTokens.forEach((token) => {
          lines.push(appliedSummaryLabel + ': ' + token);
        });
      } else if (appliedSummaryTokens.length === 1) {
        lines.push(appliedSummaryLabel + ': ' + appliedSummaryTokens[0]);
      }
    }
    if (item.last_error) {
      lines.push(app.t('managedNetwork.runtimeReload.tooltip.error') + ': ' + String(item.last_error).trim());
    }
    return lines.filter(Boolean);
  }

  function createManagedNetworkRuntimeReloadTooltipRow(label, value) {
    return app.createNode('div', {
      className: 'kernel-runtime-tooltip-breakdown-row',
      children: [
        app.createNode('span', {
          className: 'kernel-runtime-tooltip-breakdown-label',
          text: label
        }),
        app.createNode('span', {
          className: 'kernel-runtime-tooltip-breakdown-value',
          text: value
        })
      ]
    });
  }

  function createManagedNetworkRuntimeReloadTooltipContent(status) {
    if (typeof app.createNode !== 'function') {
      return managedNetworkRuntimeReloadTooltipLines(status).join('\n');
    }
    const item = status && typeof status === 'object' ? status : {};
    const badge = managedNetworkRuntimeReloadBadgeInfo(item);
    const rows = managedNetworkRuntimeReloadTooltipLines(item).slice(1).map((line) => {
      const colon = line.indexOf(': ');
      if (colon <= 0) {
        return createManagedNetworkRuntimeReloadTooltipRow(app.t('managedNetwork.runtimeReload.tooltip.note'), line);
      }
      return createManagedNetworkRuntimeReloadTooltipRow(line.slice(0, colon), line.slice(colon + 2));
    });
    return [
      app.createNode('div', {
        className: 'kernel-runtime-tooltip-header',
        children: [
          app.createNode('div', {
            className: 'kernel-runtime-tooltip-title',
            text: app.t('managedNetwork.runtimeReload.tooltip.title')
          }),
          app.createNode('div', {
            className: 'kernel-runtime-tooltip-primary',
            text: badge.detail
          })
        ]
      }),
      rows.length ? app.createNode('div', {
        className: 'kernel-runtime-tooltip-breakdown',
        children: rows
      }) : null
    ];
  }

  app.renderManagedNetworkRuntimeStatusButton = function renderManagedNetworkRuntimeStatusButton() {
    const button = app.el.managedNetworkRuntimeStatusBtn;
    if (!button) return;

    const status = app.state.managedNetworkRuntimeReloadStatus || {};
    const badge = managedNetworkRuntimeReloadBadgeInfo(status);
    const detailText = managedNetworkRuntimeReloadTooltipLines(status).join('\n');

    button.hidden = false;
    button.textContent = badge.text;
    button.className = 'kernel-runtime-detail-trigger managed-network-runtime-status' +
      (badge.tone === 'success' ? ' is-success' : '') +
      (badge.tone === 'pending' ? ' is-pending' : '') +
      (badge.tone === 'warning' ? ' is-warning' : '');
    button.title = detailText;
    button.setAttribute('aria-label', detailText || badge.text);

    if (typeof app.bindFloatingDetailTooltip === 'function' && button.dataset.tooltipBound !== 'true') {
      button.setAttribute('aria-describedby', 'kernelRuntimeFloatingTooltip');
      button.setAttribute('aria-expanded', 'false');
      app.bindFloatingDetailTooltip(button, () => createManagedNetworkRuntimeReloadTooltipContent(app.state.managedNetworkRuntimeReloadStatus || {}));
      button.dataset.tooltipBound = 'true';
    }
  };

  app.loadManagedNetworkRuntimeStatus = async function loadManagedNetworkRuntimeStatus(options) {
    const opts = options || {};
    try {
      app.state.managedNetworkRuntimeReloadStatus = await app.apiCall('GET', '/api/managed-networks/runtime-status');
      app.renderManagedNetworkRuntimeStatusButton();
    } catch (e) {
      if (!opts.silent && e.message !== 'unauthorized') console.error('load managed network runtime status:', e);
    }
  };

  function managedNetworkChildInterfaces(item) {
    return Array.isArray(item && item.child_interfaces)
      ? item.child_interfaces.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
  }

  function managedNetworkChildCount(item) {
    const value = Number(item && item.child_interface_count);
    return Number.isFinite(value) && value > 0 ? value : 0;
  }

  function managedNetworkGeneratedIPv6Count(item) {
    const value = Number(item && item.generated_ipv6_assignment_count);
    return Number.isFinite(value) && value > 0 ? value : 0;
  }

  function managedNetworkPreviewWarnings(item) {
    return Array.isArray(item && item.preview_warnings)
      ? item.preview_warnings.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
  }

  function managedNetworkRepairIssues(item) {
    return Array.isArray(item && item.repair_issues)
      ? item.repair_issues.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
  }

  function managedNetworkNeedsRepair(item) {
    return !!(item && item.repair_recommended) || managedNetworkRepairIssues(item).length > 0;
  }

  function buildManagedNetworkRepairSummary(result) {
    const payload = result && typeof result === 'object' ? result : {};
    const bridges = Array.isArray(payload.bridges)
      ? payload.bridges.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
    const guestLinks = Array.isArray(payload.guest_links)
      ? payload.guest_links.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
    const parts = [];
    if (bridges.length) {
      parts.push(app.t('managedNetwork.repair.summary.bridges', {
        count: bridges.length,
        items: bridges.join(', ')
      }));
    }
    if (guestLinks.length) {
      parts.push(app.t('managedNetwork.repair.summary.guestLinks', {
        count: guestLinks.length,
        items: guestLinks.join(', ')
      }));
    }
    if (!parts.length) return app.t('managedNetwork.repair.summary.none');
    return parts.join('; ');
  }

  function managedNetworkReservationCount(item) {
    const value = Number(item && item.reservation_count);
    return Number.isFinite(value) && value > 0 ? value : 0;
  }

  function managedNetworkReservationNetworkLabel(item) {
    const name = String((item && item.name) || '').trim();
    const bridge = String((item && item.bridge) || '').trim();
    if (name && bridge) return name + ' (' + bridge + ')';
    return name || bridge || '';
  }

  function managedNetworkReservationCandidateKey(item) {
    return String((item && item.managed_network_id) || '') + '|' + String((item && item.mac_address) || '').trim().toLowerCase();
  }

  function managedNetworkReservationCandidateIPv4Choices(item) {
    const choices = [];
    const seen = Object.create(null);
    const appendChoice = function appendChoice(value) {
      const current = String(value || '').trim();
      if (!current || seen[current]) return;
      seen[current] = true;
      choices.push(current);
    };

    (Array.isArray(item && item.ipv4_candidates) ? item.ipv4_candidates : []).forEach(appendChoice);
    appendChoice(item && item.suggested_ipv4);
    appendChoice(item && item.existing_reservation_ipv4);
    return choices;
  }

  function normalizeManagedNetworkReservationCandidateSelections(items) {
    const st = app.state.managedNetworkReservationCandidates || {};
    const currentSelections = st.selectedIPv4ByKey && typeof st.selectedIPv4ByKey === 'object' ? st.selectedIPv4ByKey : {};
    const nextSelections = {};

    (Array.isArray(items) ? items : []).forEach((item) => {
      const key = managedNetworkReservationCandidateKey(item);
      if (!key) return;
      const choices = managedNetworkReservationCandidateIPv4Choices(item);
      if (!choices.length) return;
      const current = String(currentSelections[key] || '').trim();
      nextSelections[key] = choices.indexOf(current) >= 0 ? current : choices[0];
    });

    st.selectedIPv4ByKey = nextSelections;
  }

  function selectedManagedNetworkReservationCandidateIPv4(item) {
    const choices = managedNetworkReservationCandidateIPv4Choices(item);
    if (!choices.length) return '';
    const st = app.state.managedNetworkReservationCandidates || {};
    const key = managedNetworkReservationCandidateKey(item);
    const current = String(st.selectedIPv4ByKey && st.selectedIPv4ByKey[key] || '').trim();
    return choices.indexOf(current) >= 0 ? current : choices[0];
  }

  function setManagedNetworkReservationCandidateIPv4Selection(item, value) {
    if (!item) return;
    const key = managedNetworkReservationCandidateKey(item);
    if (!key) return;
    const choices = managedNetworkReservationCandidateIPv4Choices(item);
    const current = String(value || '').trim();
    const st = app.state.managedNetworkReservationCandidates = app.state.managedNetworkReservationCandidates || { data: [], page: 1, pageSize: 10, searchQuery: '', selectedIPv4ByKey: {} };
    if (!st.selectedIPv4ByKey || typeof st.selectedIPv4ByKey !== 'object') st.selectedIPv4ByKey = {};
    if (choices.indexOf(current) >= 0) st.selectedIPv4ByKey[key] = current;
    else delete st.selectedIPv4ByKey[key];
  }

  function formatManagedNetworkReservationCandidateGuest(item) {
    const guestName = String((item && item.pve_guest_name) || '').trim();
    const vmid = String((item && item.pve_vmid) || '').trim();
    const guestNIC = String((item && item.pve_guest_nic) || '').trim();
    const meta = [];
    if (vmid) meta.push('#' + vmid);
    if (guestNIC) meta.push(guestNIC);
    if (!guestName && !meta.length) return '';
    if (!guestName) return 'VM ' + meta.join(' / ');
    if (!meta.length) return guestName;
    return guestName + ' (' + meta.join(' / ') + ')';
  }

  function createManagedNetworkReservationCandidateStatusNode(item) {
    const status = String((item && item.status) || '').trim().toLowerCase();
    const title = String((item && item.status_message) || '').trim();
    switch (status) {
      case 'reserved':
        return app.createBadgeNode('badge-running', app.t('managedNetworkCandidate.status.reserved'), title);
      case 'available':
        return app.createBadgeNode('badge-running', app.t('managedNetworkCandidate.status.available'), title);
      default:
        return app.createBadgeNode('badge-disabled', app.t('managedNetworkCandidate.status.unavailable'), title);
    }
  }

  function createManagedNetworkReservationCandidateIPv4Node(item) {
    const choices = managedNetworkReservationCandidateIPv4Choices(item);
    const selected = selectedManagedNetworkReservationCandidateIPv4(item);
    if (!choices.length) return app.emptyCellNode();
    if (choices.length === 1) return choices[0];

    const select = app.createNode('select', {
      className: 'table-inline-select',
      title: choices.join(', ')
    });
    choices.forEach((choice) => {
      const option = document.createElement('option');
      option.value = choice;
      option.textContent = choice;
      option.selected = choice === selected;
      select.appendChild(option);
    });
    select.addEventListener('change', () => {
      setManagedNetworkReservationCandidateIPv4Selection(item, select.value);
    });

    return select;
  }

  function managedNetworkReservationCandidateSearchValues(item) {
    return [
      item && item.managed_network_name,
      item && item.managed_network_bridge,
      formatManagedNetworkReservationCandidateGuest(item),
      item && item.child_interface,
      item && item.mac_address,
      item && item.suggested_ipv4,
      item && item.existing_reservation_ipv4,
      item && item.suggested_remark,
      item && item.existing_reservation_remark,
      item && item.status,
      item && item.status_message
    ].concat(managedNetworkReservationCandidateIPv4Choices(item));
  }

  app.prefillManagedNetworkReservationFromCandidate = function prefillManagedNetworkReservationFromCandidate(item) {
    const el = app.el;
    if (!item) return;
    const selectedIPv4 = selectedManagedNetworkReservationCandidateIPv4(item) || item.suggested_ipv4 || item.existing_reservation_ipv4 || '';
    app.setManagedNetworkReservationFormAdd();
    el.managedNetworkReservationManagedNetworkId.value = String(item.managed_network_id || '');
    el.managedNetworkReservationMACAddress.value = item.mac_address || '';
    el.managedNetworkReservationIPv4Address.value = selectedIPv4;
    el.managedNetworkReservationRemark.value = item.suggested_remark || item.child_interface || '';
    app.syncManagedNetworkReservationFormState();
    if (el.managedNetworkReservationFormTitle && typeof el.managedNetworkReservationFormTitle.scrollIntoView === 'function') {
      el.managedNetworkReservationFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  app.editManagedNetworkReservationFromCandidate = function editManagedNetworkReservationFromCandidate(item) {
    if (!item || !item.existing_reservation_id) return;
    app.enterManagedNetworkReservationEditMode({
      id: item.existing_reservation_id,
      managed_network_id: item.managed_network_id,
      mac_address: item.mac_address,
      ipv4_address: item.existing_reservation_ipv4,
      remark: item.existing_reservation_remark || item.suggested_remark || item.child_interface || ''
    });
  };

  app.renderManagedNetworkReservationCandidatesTable = function renderManagedNetworkReservationCandidatesTable() {
    const el = app.el;
    const st = app.state.managedNetworkReservationCandidates;
    if (!st || !el.managedNetworkReservationCandidatesBody) return;

    const items = Array.isArray(st.data) ? st.data : [];
    normalizeManagedNetworkReservationCandidateSelections(items);
    let filteredList = items.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, managedNetworkReservationCandidateSearchValues(item)));
    }
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.managedNetworkReservationCandidatesBody);
    app.renderFilterMeta('managedNetworkReservationCandidates', filteredList.length, items.length);
    app.renderPagination('managedNetworkReservationCandidates', filteredList.length);
    if (!filteredList.length) {
      app.updateEmptyState(el.noManagedNetworkReservationCandidates, {
        message: items.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('managedNetworkCandidate.list.empty'),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('managedNetworkReservationCandidatesTable', false);
      return;
    }

    app.hideEmptyState(el.noManagedNetworkReservationCandidates);
    app.toggleTableVisibility('managedNetworkReservationCandidatesTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const rowKey = managedNetworkReservationCandidateKey(item);
      const pending = app.isRowPending('managed-network-reservation-candidate', rowKey);
      const tr = document.createElement('tr');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      const actions = [];
      if (String(item.status || '').trim().toLowerCase() === 'reserved' && item.existing_reservation_id) {
        actions.push({
          className: 'btn-edit-managed-network-reservation-candidate',
          text: app.t('managedNetworkCandidate.action.edit'),
          dataset: { managedNetworkReservationCandidate: app.encData(item) },
          disabled: pending
        });
      } else if (String(item.status || '').trim().toLowerCase() === 'available' && item.suggested_ipv4) {
        actions.push({
          className: 'btn-create-managed-network-reservation-candidate',
          text: app.t('managedNetworkCandidate.action.create'),
          dataset: { managedNetworkReservationCandidate: app.encData(item) },
          disabled: pending
        });
      } else {
        actions.push({
          className: 'btn-fill-managed-network-reservation-candidate',
          text: app.t('managedNetworkCandidate.action.fill'),
          dataset: { managedNetworkReservationCandidate: app.encData(item) },
          disabled: pending
        });
      }

      tr.appendChild(app.createCell(item.managed_network_name || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.managed_network_bridge || app.emptyCellNode()));
      tr.appendChild(app.createCell(formatManagedNetworkReservationCandidateGuest(item) || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.child_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.mac_address || app.emptyCellNode()));
      tr.appendChild(app.createCell(createManagedNetworkReservationCandidateIPv4Node(item)));
      tr.appendChild(app.createCell(createManagedNetworkReservationCandidateStatusNode(item)));
      tr.appendChild(app.createCell(app.createActionDropdown(actions, pending), 'cell-actions'));
      fragment.appendChild(tr);
    });

    el.managedNetworkReservationCandidatesBody.appendChild(fragment);
  };

  app.loadManagedNetworkReservationCandidates = async function loadManagedNetworkReservationCandidates() {
    try {
      app.state.managedNetworkReservationCandidates.data = await app.apiCall('GET', '/api/managed-network-reservation-candidates');
      normalizeManagedNetworkReservationCandidateSelections(app.state.managedNetworkReservationCandidates.data);
      app.renderManagedNetworkReservationCandidatesTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load managed network reservation candidates:', e);
    }
  };

  app.createManagedNetworkReservationFromCandidate = async function createManagedNetworkReservationFromCandidate(item) {
    const selectedIPv4 = selectedManagedNetworkReservationCandidateIPv4(item);
    if (!item || !item.managed_network_id || !item.mac_address || !selectedIPv4) return;
    const rowKey = managedNetworkReservationCandidateKey(item);
    if (app.isRowPending('managed-network-reservation-candidate', rowKey)) return;

    app.setRowPending('managed-network-reservation-candidate', rowKey, true);
    app.renderManagedNetworkReservationCandidatesTable();
    try {
      await app.apiCall('POST', '/api/managed-network-reservations', {
        managed_network_id: item.managed_network_id,
        mac_address: item.mac_address,
        ipv4_address: selectedIPv4,
        remark: item.suggested_remark || item.child_interface || ''
      });
      app.notify('success', app.t('toast.saved', { item: app.t('noun.managedNetworkReservation') }));
      await Promise.all([
        typeof app.loadManagedNetworks === 'function' ? app.loadManagedNetworks() : Promise.resolve(),
        typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['create']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.saveFailed', { message: message }));
      }
    } finally {
      app.setRowPending('managed-network-reservation-candidate', rowKey, false);
      app.renderManagedNetworkReservationCandidatesTable();
    }
  };

  function formatManagedNetworkIPv4Summary(item) {
    if (!item || item.ipv4_enabled === false) return app.t('status.disabled');
    const parts = [];
    if (item.ipv4_cidr) parts.push(item.ipv4_cidr);
    if (item.ipv4_pool_start || item.ipv4_pool_end) {
      parts.push((item.ipv4_pool_start || app.t('common.auto')) + ' - ' + (item.ipv4_pool_end || app.t('common.auto')));
    }
    if (item.ipv4_dns_servers) parts.push(item.ipv4_dns_servers);
    return parts.length ? parts.join(' | ') : app.t('common.auto');
  }

  function buildManagedNetworkIPv4Title(item) {
    if (!item || item.ipv4_enabled === false) return app.t('status.disabled');
    const lines = [];
    if (item.ipv4_cidr) lines.push(app.t('managedNetwork.form.ipv4CIDR') + ': ' + item.ipv4_cidr);
    if (item.ipv4_gateway) lines.push(app.t('managedNetwork.form.ipv4Gateway') + ': ' + item.ipv4_gateway);
    if (item.ipv4_pool_start || item.ipv4_pool_end) {
      lines.push(
        app.t('managedNetwork.form.ipv4PoolStart') + ': ' + (item.ipv4_pool_start || app.t('common.auto')) +
        '\n' +
        app.t('managedNetwork.form.ipv4PoolEnd') + ': ' + (item.ipv4_pool_end || app.t('common.auto'))
      );
    }
    if (item.ipv4_dns_servers) lines.push(app.t('managedNetwork.form.ipv4DNSServers') + ': ' + item.ipv4_dns_servers);
    const reservationCount = managedNetworkReservationCount(item);
    if (reservationCount > 0) {
      lines.push(app.t('managedNetwork.list.reservations', { count: reservationCount }));
    }
    const runtime = runtimeStatusInfo(item.ipv4_runtime_status, item.enabled !== false);
    lines.push('DHCPv4: ' + runtime.text);
    if (item.ipv4_runtime_detail) lines.push(String(item.ipv4_runtime_detail).trim());
    if (item.ipv4_dhcpv4_reply_count) lines.push('DHCPv4 replies: ' + String(item.ipv4_dhcpv4_reply_count));
    return lines.length ? lines.join('\n') : app.t('common.auto');
  }

  function formatManagedNetworkIPv6Summary(item) {
    if (!item || item.ipv6_enabled === false) return app.t('status.disabled');
    const parts = [];
    if (item.ipv6_parent_interface) parts.push(item.ipv6_parent_interface);
    if (item.ipv6_parent_prefix) parts.push(item.ipv6_parent_prefix);
    parts.push(assignmentModeLabel(item.ipv6_assignment_mode));
    return parts.join(' | ');
  }

  function buildManagedNetworkIPv6Title(item) {
    if (!item || item.ipv6_enabled === false) return app.t('status.disabled');
    const lines = [];
    if (item.ipv6_parent_interface) lines.push(app.t('managedNetwork.form.ipv6ParentInterface') + ': ' + item.ipv6_parent_interface);
    if (item.ipv6_parent_prefix) lines.push(app.t('managedNetwork.form.ipv6ParentPrefix') + ': ' + item.ipv6_parent_prefix);
    lines.push(app.t('managedNetwork.form.ipv6AssignmentMode') + ': ' + assignmentModeLabel(item.ipv6_assignment_mode));
    const generatedCount = managedNetworkGeneratedIPv6Count(item);
    lines.push(app.t('ipv6.list.assignmentCount') + ': ' + String(generatedCount));
    const runtime = runtimeStatusInfo(item.ipv6_runtime_status, item.enabled !== false);
    lines.push('IPv6: ' + runtime.text);
    if (item.ipv6_runtime_detail) lines.push(String(item.ipv6_runtime_detail).trim());
    const counts = [];
    if (item.ipv6_ra_advertisement_count) {
      counts.push(app.t('ipv6.list.assignmentCount.ra', { count: item.ipv6_ra_advertisement_count }));
    }
    if (item.ipv6_dhcpv6_reply_count) {
      counts.push(app.t('ipv6.list.assignmentCount.dhcpv6', { count: item.ipv6_dhcpv6_reply_count }));
    }
    if (counts.length) lines.push(counts.join(' / '));
    const warnings = managedNetworkPreviewWarnings(item);
    if (warnings.length) lines.push(warnings.join('\n'));
    return lines.join('\n');
  }

  function createManagedNetworkTextNode(value, options) {
    const text = String(value || '').trim();
    if (!text) return app.emptyCellNode();
    return app.createNode('span', {
      className: 'managed-network-text' + ((options && options.mono) ? ' managed-network-text-mono' : ''),
      text: text,
      title: (options && options.title) || text
    });
  }

  function createManagedNetworkSummaryNode(mainText, title, badges, options) {
    return app.createNode('span', {
      className: 'managed-network-summary' + ((options && options.mainMono) ? ' managed-network-summary-mono' : ''),
      title: title || '',
      children: [
        app.createNode('span', {
          className: 'managed-network-summary-main',
          text: mainText || app.t('common.auto'),
          title: title || ''
        }),
        Array.isArray(badges) && badges.length
          ? app.createNode('span', {
            className: 'managed-network-summary-badges',
            children: badges
          })
          : null
      ]
    });
  }

  function createManagedNetworkIPv4Node(item) {
    if (!item || item.ipv4_enabled === false) return enabledBadge(false);
    const title = buildManagedNetworkIPv4Title(item);
    const reservationCount = managedNetworkReservationCount(item);
    const badges = [];
    const runtime = runtimeStatusInfo(item.ipv4_runtime_status, item.enabled !== false);
    if (item.ipv4_pool_start || item.ipv4_pool_end) {
      badges.push(app.createBadgeNode('badge-' + runtime.badge, 'DHCP', title));
    }
    if (reservationCount > 0) {
      badges.push(app.createBadgeNode(
        'badge-running',
        String(reservationCount),
        app.t('managedNetwork.list.reservations', { count: reservationCount })
      ));
    }
    return createManagedNetworkSummaryNode(item.ipv4_cidr || app.t('common.auto'), title, badges, {
      mainMono: true
    });
  }

  function buildManagedNetworkBridgeTitle(item) {
    if (!item) return '';
    const mode = normalizeManagedNetworkBridgeMode(item.bridge_mode);
    const lines = [
      app.t('managedNetwork.form.bridgeMode') + ': ' + app.t(
        mode === 'existing'
          ? 'managedNetwork.form.bridgeMode.existing'
          : 'managedNetwork.form.bridgeMode.create'
      )
    ];
    if (mode === 'create') {
      lines.push(app.t('managedNetwork.form.bridgeMTU') + ': ' + (item.bridge_mtu ? String(item.bridge_mtu) : app.t('common.auto')));
      lines.push(app.t('managedNetwork.form.bridgeVLANAware') + ': ' + app.t(item.bridge_vlan_aware ? 'status.enabled' : 'status.disabled'));
    } else {
      lines.push(app.t('managedNetwork.form.bridgeAdvancedHint'));
    }
    return lines.join('\n');
  }

  function createManagedNetworkTargetsNode(item) {
    const names = managedNetworkChildInterfaces(item);
    const count = managedNetworkChildCount(item);
    const issues = managedNetworkRepairIssues(item);
    const titleLines = [
      names.length ? names.join(', ') : app.t('managedNetwork.list.targets.none')
    ];
    if (issues.length) {
      titleLines.push(app.t('managedNetwork.list.repairNeeded'));
      titleLines.push(...issues);
    }
    const badges = [
      app.createBadgeNode(
        issues.length ? 'badge-error' : (count > 0 ? 'badge-running' : 'badge-disabled'),
        String(count),
        titleLines.join('\n')
      )
    ];
    if (issues.length) {
      badges.push(app.createBadgeNode(
        'badge-error',
        app.t('managedNetwork.list.repairBadge'),
        [app.t('managedNetwork.list.repairNeeded'), ...issues].join('\n')
      ));
    }
    return app.createNode('span', {
      className: 'managed-network-summary-badges',
      children: badges
    });
  }

  function createManagedNetworkIPv6Node(item) {
    if (!item || item.ipv6_enabled === false) return enabledBadge(false);
    const generatedCount = managedNetworkGeneratedIPv6Count(item);
    const warnings = managedNetworkPreviewWarnings(item);
    const title = buildManagedNetworkIPv6Title(item);
    const summary = String(item.ipv6_parent_interface || '').trim() || app.t('status.enabled');
    const badges = [];
    const runtime = runtimeStatusInfo(
      item.ipv6_runtime_status || (warnings.length > 0 && generatedCount === 0 ? 'error' : ''),
      item.enabled !== false
    );
    badges.push(app.createBadgeNode('badge-kernel', normalizeManagedNetworkIPv6AssignmentMode(item.ipv6_assignment_mode) === 'prefix_64' ? '/64' : '/128', title));
    badges.push(app.createBadgeNode(
      'badge-' + runtime.badge,
      String(generatedCount),
      title
    ));
    return createManagedNetworkSummaryNode(summary, title, badges);
  }

  function createManagedNetworkAutoEgressNATNode(item) {
    const warnings = managedNetworkPreviewWarnings(item);
    const title = warnings.join('\n');
    if (!item || item.auto_egress_nat === false || item.enabled === false) {
      return app.createBadgeNode('badge-disabled', app.t('status.disabled'), title);
    }
    if (item.generated_egress_nat) {
      return app.createBadgeNode('badge-running', app.t('status.enabled'), title);
    }
    return app.createBadgeNode('badge-error', app.t('common.skipped'), title);
  }

  app.getManagedNetworkBridgeItems = function getManagedNetworkBridgeItems() {
    if (!managedNetworkUsesExistingBridge()) return [];
    return hostPickerItems();
  };

  app.getManagedNetworkUplinkItems = function getManagedNetworkUplinkItems(bridgeName) {
    const selectedBridge = String(bridgeName || '').trim();
    return hostPickerItems((iface) => String(iface && iface.name || '').trim() !== selectedBridge);
  };

  app.getManagedNetworkIPv6ParentItems = function getManagedNetworkIPv6ParentItems() {
    return hostPickerItems((iface) => hasIPv6Prefix(iface));
  };

  app.refreshManagedNetworkInterfaceSelectors = function refreshManagedNetworkInterfaceSelectors(options) {
    const opts = options || {};
    const el = app.el;
    if (!el.managedNetworkBridgeInterface) return;

    syncManagedNetworkBridgeFieldPresentation();

    app.populateInterfacePicker(el.managedNetworkBridgeInterface, el.managedNetworkBridgePicker, el.managedNetworkBridgeOptions, {
      items: app.getManagedNetworkBridgeItems(),
      preserveSelected: true,
      preserveText: !managedNetworkUsesExistingBridge(),
      placeholder: managedNetworkBridgePlaceholder()
    });
    maybeAutofillManagedNetworkBridgeName();

    app.populateInterfacePicker(el.managedNetworkUplinkInterface, el.managedNetworkUplinkPicker, el.managedNetworkUplinkOptions, {
      items: app.getManagedNetworkUplinkItems(el.managedNetworkBridgeInterface.value),
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });

    app.populateInterfacePicker(el.managedNetworkIPv6ParentInterface, el.managedNetworkIPv6ParentPicker, el.managedNetworkIPv6ParentOptions, {
      items: app.getManagedNetworkIPv6ParentItems(),
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });

    populateManagedNetworkIPv6ParentPrefixSelect(opts.preservePrefix ? el.managedNetworkIPv6ParentPrefix.value : '');
    syncManagedNetworkOptionStates();
  };

  app.syncManagedNetworkFormState = function syncManagedNetworkFormState() {
    const el = app.el;
    if (!el.managedNetworkSubmitBtn || !el.managedNetworkCancelBtn || !el.managedNetworkFormTitle) return;

    syncManagedNetworkOptionStates();

    const formState = app.state.forms.managedNetwork || { mode: 'add', sourceId: 0 };
    const pending = !!app.state.pendingForms.managedNetwork;
    if (formState.mode === 'edit' && el.editManagedNetworkId && el.editManagedNetworkId.value) {
      el.managedNetworkFormTitle.textContent = app.t('managedNetwork.form.title.edit', { id: el.editManagedNetworkId.value });
      el.managedNetworkSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('managedNetwork.form.submit.edit');
      el.managedNetworkCancelBtn.style.display = '';
    } else {
      el.managedNetworkFormTitle.textContent = app.t('managedNetwork.form.title.add');
      el.managedNetworkSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('managedNetwork.form.submit.add');
      el.managedNetworkCancelBtn.style.display = 'none';
    }

    el.managedNetworkCancelBtn.textContent = app.t('common.cancelEdit');
    el.managedNetworkSubmitBtn.disabled = pending;
    el.managedNetworkSubmitBtn.classList.toggle('is-busy', pending);
    el.managedNetworkCancelBtn.disabled = pending;
  };

  app.setManagedNetworkFormAdd = function setManagedNetworkFormAdd() {
    const el = app.el;
    app.state.forms.managedNetwork = { mode: 'add', sourceId: 0 };
    if (el.managedNetworkForm) el.managedNetworkForm.reset();
    if (el.editManagedNetworkId) el.editManagedNetworkId.value = '';
    setManagedNetworkBridgeAutofilled(false);
    if (el.managedNetworkBridgeMode) el.managedNetworkBridgeMode.value = 'create';
    if (el.managedNetworkBridgeInterface) el.managedNetworkBridgeInterface.value = '';
    if (el.managedNetworkUplinkInterface) el.managedNetworkUplinkInterface.value = '';
    if (el.managedNetworkIPv6ParentInterface) el.managedNetworkIPv6ParentInterface.value = '';
    if (el.managedNetworkIPv4Enabled) el.managedNetworkIPv4Enabled.checked = true;
    if (el.managedNetworkIPv6Enabled) el.managedNetworkIPv6Enabled.checked = false;
    if (el.managedNetworkAutoEgressNAT) el.managedNetworkAutoEgressNAT.checked = true;
    if (el.managedNetworkBridgeMTU) el.managedNetworkBridgeMTU.value = '';
    if (el.managedNetworkBridgeVLANAware) el.managedNetworkBridgeVLANAware.checked = false;
    setManagedNetworkBridgeAdvancedExpanded(false);
    if (el.managedNetworkIPv6AssignmentMode) el.managedNetworkIPv6AssignmentMode.value = 'single_128';
    app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: false });
    app.syncManagedNetworkFormState();
  };

  app.applyManagedNetworkPVEQuickFill = async function applyManagedNetworkPVEQuickFill() {
    const el = app.el;
    if (!el.managedNetworkForm) return;
    try {
      if ((!Array.isArray(app.hostNetworkInterfaces) || app.hostNetworkInterfaces.length === 0) && typeof app.loadHostNetwork === 'function') {
        await app.loadHostNetwork();
      }

      if (typeof app.clearFormErrors === 'function') app.clearFormErrors(el.managedNetworkForm);
      app.setManagedNetworkFormAdd();

      const bridgeName = String(el.managedNetworkBridgeInterface && el.managedNetworkBridgeInterface.value || '').trim() || suggestManagedNetworkBridgeName();
      const uplink = pickManagedNetworkPVEUplink();
      const ipv4CIDR = pickManagedNetworkPVEIPv4CIDR();
      const pool = deriveManagedNetworkPVEPool(ipv4CIDR);
      const ipv6Parent = pickManagedNetworkPVEIPv6Parent(uplink ? uplink.name : '');

      if (el.managedNetworkBridgeMode) el.managedNetworkBridgeMode.value = 'create';
      if (el.managedNetworkBridgeInterface) el.managedNetworkBridgeInterface.value = bridgeName;
      if (el.managedNetworkBridgePicker) el.managedNetworkBridgePicker.value = bridgeName;
      setManagedNetworkBridgeAutofilled(true);

      if (el.managedNetworkName) el.managedNetworkName.value = bridgeName + '-lan';
      if (el.managedNetworkUplinkInterface) el.managedNetworkUplinkInterface.value = uplink ? String(uplink.name || '') : '';
      if (el.managedNetworkIPv4Enabled) el.managedNetworkIPv4Enabled.checked = true;
      if (el.managedNetworkIPv4CIDR) el.managedNetworkIPv4CIDR.value = ipv4CIDR;
      if (el.managedNetworkIPv4Gateway) el.managedNetworkIPv4Gateway.value = '';
      if (el.managedNetworkIPv4PoolStart) el.managedNetworkIPv4PoolStart.value = pool.start;
      if (el.managedNetworkIPv4PoolEnd) el.managedNetworkIPv4PoolEnd.value = pool.end;
      if (el.managedNetworkIPv4DNSServers) el.managedNetworkIPv4DNSServers.value = '1.1.1.1, 8.8.8.8';
      if (el.managedNetworkAutoEgressNAT) el.managedNetworkAutoEgressNAT.checked = !!uplink;
      if (el.managedNetworkIPv6Enabled) el.managedNetworkIPv6Enabled.checked = !!ipv6Parent;
      if (el.managedNetworkIPv6ParentInterface) el.managedNetworkIPv6ParentInterface.value = ipv6Parent ? ipv6Parent.name : '';
      if (el.managedNetworkIPv6AssignmentMode) el.managedNetworkIPv6AssignmentMode.value = 'single_128';
      setManagedNetworkBridgeAdvancedExpanded(false);

      app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: false });

      if (el.managedNetworkIPv6ParentPrefix) {
        el.managedNetworkIPv6ParentPrefix.value = ipv6Parent ? ipv6Parent.prefix : '';
        if (ipv6Parent) populateManagedNetworkIPv6ParentPrefixSelect(ipv6Parent.prefix);
      }

      app.syncManagedNetworkFormState();
    } catch (e) {
      if (e && e.message !== 'unauthorized') {
        app.notify('error', app.t('errors.actionFailed', {
          action: app.t('managedNetwork.form.quickFill'),
          message: app.translateValidationMessage(e.message)
        }));
      }
    }
  };

  app.enterManagedNetworkEditMode = function enterManagedNetworkEditMode(item) {
    const el = app.el;
    app.state.forms.managedNetwork = { mode: 'edit', sourceId: item.id };
    el.editManagedNetworkId.value = item.id;
    el.managedNetworkName.value = item.name || '';
    el.managedNetworkRemark.value = item.remark || '';
    setManagedNetworkBridgeAutofilled(false);
    if (el.managedNetworkBridgeMode) el.managedNetworkBridgeMode.value = normalizeManagedNetworkBridgeMode(item.bridge_mode);
    el.managedNetworkBridgeInterface.value = item.bridge || '';
    if (el.managedNetworkBridgeMTU) el.managedNetworkBridgeMTU.value = item.bridge_mtu ? String(item.bridge_mtu) : '';
    if (el.managedNetworkBridgeVLANAware) el.managedNetworkBridgeVLANAware.checked = !!item.bridge_vlan_aware;
    setManagedNetworkBridgeAdvancedExpanded(hasManagedNetworkBridgeAdvancedConfig(item));
    el.managedNetworkUplinkInterface.value = item.uplink_interface || '';
    el.managedNetworkIPv4Enabled.checked = item.ipv4_enabled !== false;
    el.managedNetworkIPv4CIDR.value = item.ipv4_cidr || '';
    el.managedNetworkIPv4Gateway.value = item.ipv4_gateway || '';
    el.managedNetworkIPv4PoolStart.value = item.ipv4_pool_start || '';
    el.managedNetworkIPv4PoolEnd.value = item.ipv4_pool_end || '';
    el.managedNetworkIPv4DNSServers.value = item.ipv4_dns_servers || '';
    el.managedNetworkIPv6Enabled.checked = !!item.ipv6_enabled;
    el.managedNetworkIPv6ParentInterface.value = item.ipv6_parent_interface || '';
    el.managedNetworkIPv6AssignmentMode.value = normalizeManagedNetworkIPv6AssignmentMode(item.ipv6_assignment_mode);
    el.managedNetworkAutoEgressNAT.checked = !!item.auto_egress_nat;
    app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: false });
    el.managedNetworkIPv6ParentPrefix.value = item.ipv6_parent_prefix || '';
    populateManagedNetworkIPv6ParentPrefixSelect(item.ipv6_parent_prefix || '');
    app.syncManagedNetworkFormState();
    if (el.managedNetworkFormTitle && typeof el.managedNetworkFormTitle.scrollIntoView === 'function') {
      el.managedNetworkFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  app.exitManagedNetworkEditMode = function exitManagedNetworkEditMode() {
    if (app.el.managedNetworkForm) app.clearFormErrors(app.el.managedNetworkForm);
    app.setManagedNetworkFormAdd();
  };

  app.buildManagedNetworkFromForm = function buildManagedNetworkFromForm() {
    const el = app.el;
    const bridgeMode = normalizeManagedNetworkBridgeMode(el.managedNetworkBridgeMode && el.managedNetworkBridgeMode.value);
    const createMode = bridgeMode !== 'existing';
    return {
      name: String(el.managedNetworkName && el.managedNetworkName.value || '').trim(),
      bridge_mode: bridgeMode,
      bridge: app.getInterfaceSubmissionValue(el.managedNetworkBridgeInterface, el.managedNetworkBridgePicker, {
        items: app.getManagedNetworkBridgeItems(),
        preserveSelected: true
      }),
      bridge_mtu: createMode ? parseManagedNetworkBridgeMTUValue() : 0,
      bridge_vlan_aware: createMode && !!(el.managedNetworkBridgeVLANAware && el.managedNetworkBridgeVLANAware.checked),
      uplink_interface: app.getInterfaceSubmissionValue(el.managedNetworkUplinkInterface, el.managedNetworkUplinkPicker, {
        items: app.getManagedNetworkUplinkItems(el.managedNetworkBridgeInterface.value),
        preserveSelected: true
      }),
      ipv4_enabled: !!(el.managedNetworkIPv4Enabled && el.managedNetworkIPv4Enabled.checked),
      ipv4_cidr: String(el.managedNetworkIPv4CIDR && el.managedNetworkIPv4CIDR.value || '').trim(),
      ipv4_gateway: String(el.managedNetworkIPv4Gateway && el.managedNetworkIPv4Gateway.value || '').trim(),
      ipv4_pool_start: String(el.managedNetworkIPv4PoolStart && el.managedNetworkIPv4PoolStart.value || '').trim(),
      ipv4_pool_end: String(el.managedNetworkIPv4PoolEnd && el.managedNetworkIPv4PoolEnd.value || '').trim(),
      ipv4_dns_servers: String(el.managedNetworkIPv4DNSServers && el.managedNetworkIPv4DNSServers.value || '').trim(),
      ipv6_enabled: !!(el.managedNetworkIPv6Enabled && el.managedNetworkIPv6Enabled.checked),
      ipv6_parent_interface: app.getInterfaceSubmissionValue(el.managedNetworkIPv6ParentInterface, el.managedNetworkIPv6ParentPicker, {
        items: app.getManagedNetworkIPv6ParentItems(),
        preserveSelected: true
      }),
      ipv6_parent_prefix: String(el.managedNetworkIPv6ParentPrefix && el.managedNetworkIPv6ParentPrefix.value || '').trim(),
      ipv6_assignment_mode: normalizeManagedNetworkIPv6AssignmentMode(el.managedNetworkIPv6AssignmentMode && el.managedNetworkIPv6AssignmentMode.value),
      auto_egress_nat: !!(el.managedNetworkAutoEgressNAT && el.managedNetworkAutoEgressNAT.checked),
      remark: String(el.managedNetworkRemark && el.managedNetworkRemark.value || '').trim()
    };
  };

  app.getManagedNetworkFieldInputs = function getManagedNetworkFieldInputs(issue) {
    const field = String((issue && issue.field) || '').trim();
    if (field === 'bridge_mtu' || field === 'bridge_vlan_aware') {
      setManagedNetworkBridgeAdvancedExpanded(true);
    }
    const map = {
      id: app.el.editManagedNetworkId,
      name: app.el.managedNetworkName,
      bridge_mode: app.el.managedNetworkBridgeMode,
      bridge: app.el.managedNetworkBridgePicker || app.el.managedNetworkBridgeInterface,
      bridge_mtu: app.el.managedNetworkBridgeMTU,
      bridge_vlan_aware: app.el.managedNetworkBridgeVLANAware,
      uplink_interface: app.el.managedNetworkUplinkPicker || app.el.managedNetworkUplinkInterface,
      ipv4_cidr: app.el.managedNetworkIPv4CIDR,
      ipv4_gateway: app.el.managedNetworkIPv4Gateway,
      ipv4_pool_start: app.el.managedNetworkIPv4PoolStart,
      ipv4_pool_end: app.el.managedNetworkIPv4PoolEnd,
      ipv4_dns_servers: app.el.managedNetworkIPv4DNSServers,
      ipv6_parent_interface: app.el.managedNetworkIPv6ParentPicker || app.el.managedNetworkIPv6ParentInterface,
      ipv6_parent_prefix: app.el.managedNetworkIPv6ParentPrefix,
      ipv6_assignment_mode: app.el.managedNetworkIPv6AssignmentMode,
      remark: app.el.managedNetworkRemark
    };
    return map[field] ? [map[field]] : [];
  };

  app.applyManagedNetworkValidationIssues = function applyManagedNetworkValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getManagedNetworkFieldInputs(issue);
      if (!inputs.length) return;
      const translated = app.translateValidationMessage(issue.message);
      inputs.forEach((input) => {
        if (!input) return;
        if (!firstInvalid) firstInvalid = input;
        if (!input.hasAttribute('aria-invalid')) app.setFieldError(input, translated);
      });
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.getValidationIssueSummary({ issues: relevant }, null, 3) || app.translateValidationMessage(relevant[0].message));
  };

  app.getManagedNetworkSortValue = function getManagedNetworkSortValue(item, key) {
    if (key === 'enabled' || key === 'auto_egress_nat' || key === 'ipv4_enabled' || key === 'ipv6_enabled') {
      return item && item[key] ? 1 : 0;
    }
    return item ? item[key] : '';
  };

  app.renderManagedNetworksTable = function renderManagedNetworksTable() {
    const el = app.el;
    const st = app.state.managedNetworks;
    if (!st || !el.managedNetworksBody) return;
    app.closeDropdowns();
    app.renderManagedNetworkRuntimeStatusButton();

    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, [
        item.id,
        item.name,
        normalizeManagedNetworkBridgeMode(item.bridge_mode) === 'existing'
          ? app.t('managedNetwork.form.bridgeMode.existing')
          : app.t('managedNetwork.form.bridgeMode.create'),
        item.bridge,
        item.bridge_mtu,
        item.bridge_vlan_aware ? app.t('status.enabled') : app.t('status.disabled'),
        item.uplink_interface,
        item.child_interface_count,
        ...(managedNetworkChildInterfaces(item)),
        item.ipv4_cidr,
        item.ipv4_gateway,
        item.ipv4_pool_start,
        item.ipv4_pool_end,
        item.ipv4_dns_servers,
        formatManagedNetworkIPv4Summary(item),
        item.ipv4_runtime_status,
        item.ipv4_runtime_detail,
        item.ipv4_dhcpv4_reply_count,
        runtimeStatusInfo(item.ipv4_runtime_status, item.enabled !== false).text,
        item.ipv6_parent_interface,
        item.ipv6_parent_prefix,
        assignmentModeLabel(item.ipv6_assignment_mode),
        formatManagedNetworkIPv6Summary(item),
        item.generated_ipv6_assignment_count,
        item.ipv6_runtime_status,
        item.ipv6_runtime_detail,
        item.ipv6_ra_advertisement_count,
        item.ipv6_dhcpv6_reply_count,
        runtimeStatusInfo(item.ipv6_runtime_status, item.enabled !== false).text,
        item.remark,
        item.auto_egress_nat ? app.t('status.enabled') : app.t('status.disabled'),
        item.generated_egress_nat ? app.t('status.enabled') : app.t('common.skipped'),
        ...(managedNetworkPreviewWarnings(item)),
        ...(managedNetworkRepairIssues(item)),
        managedNetworkNeedsRepair(item) ? app.t('managedNetwork.list.repairNeeded') : '',
        item.enabled === false ? app.t('status.disabled') : app.t('status.enabled')
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getManagedNetworkSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.managedNetworksBody);
    app.updateSortIndicators('managedNetworksTable', st);
    app.renderFilterMeta('managedNetworks', filteredList.length, st.data.length);
    app.renderPagination('managedNetworks', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noManagedNetworks, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('managedNetwork.list.empty'),
        actionButton: app.el.emptyAddManagedNetworkBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('managedNetworksTable', false);
      return;
    }

    app.hideEmptyState(el.noManagedNetworks);
    app.toggleTableVisibility('managedNetworksTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('managed-network', item.id);
      const toggleText = pending ? app.t('common.processing') : app.t(item.enabled === false ? 'common.enable' : 'common.disable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.appendChild(app.createCell(String(item.id)));
      tr.appendChild(app.createCell(createManagedNetworkTextNode(item.name), 'managed-network-cell-text'));
      tr.appendChild(app.createCell(createManagedNetworkTextNode(item.bridge, {
        mono: true,
        title: buildManagedNetworkBridgeTitle(item)
      }), 'managed-network-cell-text'));
      tr.appendChild(app.createCell(createManagedNetworkTextNode(item.uplink_interface, { mono: true }), 'managed-network-cell-text'));
      tr.appendChild(app.createCell(createManagedNetworkTargetsNode(item), 'managed-network-cell-tight'));
      tr.appendChild(app.createCell(createManagedNetworkIPv4Node(item), 'managed-network-cell-compact'));
      tr.appendChild(app.createCell(createManagedNetworkIPv6Node(item), 'managed-network-cell-compact'));
      tr.appendChild(app.createCell(createManagedNetworkAutoEgressNATNode(item), 'managed-network-cell-tight'));
      tr.appendChild(app.createCell(createManagedNetworkTextNode(item.remark), 'managed-network-cell-text'));
      tr.appendChild(app.createCell(enabledBadge(item.enabled !== false)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: item.enabled === false ? 'btn-enable-managed-network' : 'btn-disable-managed-network',
          text: toggleText,
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-edit-managed-network',
          text: app.t('common.edit'),
          dataset: { managedNetwork: app.encData(item) },
          disabled: pending
        },
        {
          className: 'btn-delete-managed-network',
          text: app.t('common.delete'),
          dataset: { id: item.id },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.managedNetworksBody.appendChild(fragment);
  };

  app.loadManagedNetworks = async function loadManagedNetworks() {
    const runtimeStatusPromise = typeof app.loadManagedNetworkRuntimeStatus === 'function'
      ? app.loadManagedNetworkRuntimeStatus({ silent: true })
      : Promise.resolve();
    try {
      app.state.managedNetworks.data = await app.apiCall('GET', '/api/managed-networks');
      app.markDataFresh();
      if (typeof app.refreshManagedNetworkReservationNetworkOptions === 'function') {
        app.refreshManagedNetworkReservationNetworkOptions();
      }
      app.renderManagedNetworksTable();
      if (typeof app.renderManagedNetworkReservationsTable === 'function') {
        app.renderManagedNetworkReservationsTable();
      }
      if (typeof app.loadManagedNetworkReservationCandidates === 'function') {
        await app.loadManagedNetworkReservationCandidates();
      }
      await runtimeStatusPromise;
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load managed networks:', e);
    }
  };

  app.reloadManagedNetworkRuntime = async function reloadManagedNetworkRuntime() {
    try {
      const result = await app.apiCall('POST', '/api/managed-networks/reload-runtime');
      const status = String(result && result.status || '').trim().toLowerCase();
      const errorText = String(result && result.error || '').trim();
      if (status === 'partial') {
        app.notify('warning', app.t('managedNetwork.runtimeReload.result.partial') + (errorText ? ' ' + errorText : ''));
      } else if (status === 'fallback') {
        app.notify('warning', app.t('managedNetwork.runtimeReload.result.fallback') + (errorText ? ' ' + errorText : ''));
      } else if (status === 'success') {
        app.notify('success', app.t('managedNetwork.runtimeReload.completed'));
      } else {
        app.notify('success', app.t('managedNetwork.runtimeReload.queued'));
      }
      await Promise.all([
        typeof app.loadHostNetwork === 'function' ? app.loadHostNetwork() : Promise.resolve(),
        typeof app.loadInterfaces === 'function' ? app.loadInterfaces() : Promise.resolve(),
        typeof app.loadManagedNetworks === 'function' ? app.loadManagedNetworks() : Promise.resolve(),
        typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve(),
        typeof app.loadIPv6Assignments === 'function' ? app.loadIPv6Assignments() : Promise.resolve()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        app.notify('error', app.t('errors.actionFailed', {
          action: app.t('managedNetwork.runtimeReload.action'),
          message: app.translateValidationMessage(e.message)
        }));
      }
    }
  };

  app.repairManagedNetworkRuntime = async function repairManagedNetworkRuntime() {
    try {
      const result = await app.apiCall('POST', '/api/managed-networks/repair');
      const status = String(result && result.status || '').trim().toLowerCase();
      const summary = buildManagedNetworkRepairSummary(result);
      if (status === 'partial') {
        const errorText = String(result && result.error || '').trim();
        app.notify('warning', app.t('managedNetwork.repair.partial') + ' ' + summary + (errorText ? ' ' + errorText : ''));
      } else {
        app.notify('success', app.t('managedNetwork.repair.queued') + ' ' + summary);
      }
      await Promise.all([
        typeof app.loadHostNetwork === 'function' ? app.loadHostNetwork() : Promise.resolve(),
        typeof app.loadInterfaces === 'function' ? app.loadInterfaces() : Promise.resolve(),
        typeof app.loadManagedNetworks === 'function' ? app.loadManagedNetworks() : Promise.resolve(),
        typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve(),
        typeof app.loadIPv6Assignments === 'function' ? app.loadIPv6Assignments() : Promise.resolve()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        app.notify('error', app.t('errors.actionFailed', {
          action: app.t('managedNetwork.repair.action'),
          message: app.translateValidationMessage(e.message)
        }));
      }
    }
  };

  app.toggleManagedNetwork = async function toggleManagedNetwork(id) {
    if (app.isRowPending('managed-network', id)) return;

    app.setRowPending('managed-network', id, true);
    app.renderManagedNetworksTable();
    try {
      const result = await app.apiCall('POST', '/api/managed-networks/toggle?id=' + encodeURIComponent(String(id)));
      app.notify('success', app.t(result && result.enabled ? 'toast.enabled' : 'toast.disabled', { item: app.t('noun.managedNetwork') }));
      await app.loadManagedNetworks();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['toggle']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.operationFailed', { message: message }));
      }
    } finally {
      app.setRowPending('managed-network', id, false);
      app.renderManagedNetworksTable();
    }
  };

  app.deleteManagedNetwork = async function deleteManagedNetwork(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('managedNetwork.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('managed-network', id, true);
    app.renderManagedNetworksTable();
    try {
      await app.apiCall('DELETE', '/api/managed-networks?id=' + id);
      if (parseInt(app.el.editManagedNetworkId.value || '0', 10) === id) app.exitManagedNetworkEditMode();
      if (parseInt(app.el.managedNetworkReservationManagedNetworkId.value || '0', 10) === id && typeof app.exitManagedNetworkReservationEditMode === 'function') {
        app.exitManagedNetworkReservationEditMode();
      }
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.managedNetwork') }));
      if (typeof app.loadHostNetwork === 'function') await app.loadHostNetwork();
      await Promise.all([
        app.loadManagedNetworks(),
        typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('managed-network', id, false);
      app.renderManagedNetworksTable();
    }
  };

  app.refreshManagedNetworkReservationNetworkOptions = function refreshManagedNetworkReservationNetworkOptions() {
    const selectEl = app.el.managedNetworkReservationManagedNetworkId;
    if (!selectEl) return;

    const current = String(selectEl.value || '').trim();
    const items = (app.state.managedNetworks && Array.isArray(app.state.managedNetworks.data))
      ? app.state.managedNetworks.data.slice().sort((a, b) => app.compareValues(managedNetworkReservationNetworkLabel(a), managedNetworkReservationNetworkLabel(b)))
      : [];

    app.clearNode(selectEl);
    if (!items.length) {
      app.addSelectPlaceholderOption(selectEl, app.t('managedNetworkReservation.form.managedNetwork.empty'), { value: '' });
      selectEl.value = '';
      selectEl.disabled = false;
      return;
    }

    app.addSelectPlaceholderOption(selectEl, app.t('common.unspecified'), { value: '', hidden: true });
    items.forEach((item) => {
      app.addOption(selectEl, String(item.id), managedNetworkReservationNetworkLabel(item) || ('#' + String(item.id)));
    });

    const hasCurrent = Array.from(selectEl.options || []).some((option) => option.value === current);
    if (current && hasCurrent) selectEl.value = current;
    else if (!app.state.forms.managedNetworkReservation || app.state.forms.managedNetworkReservation.mode !== 'edit') selectEl.value = items[0] ? String(items[0].id) : '';
  };

  app.syncManagedNetworkReservationFormState = function syncManagedNetworkReservationFormState() {
    const el = app.el;
    if (!el.managedNetworkReservationSubmitBtn || !el.managedNetworkReservationCancelBtn || !el.managedNetworkReservationFormTitle) return;

    const formState = app.state.forms.managedNetworkReservation || { mode: 'add', sourceId: 0 };
    const pending = !!app.state.pendingForms.managedNetworkReservation;
    if (formState.mode === 'edit' && el.editManagedNetworkReservationId && el.editManagedNetworkReservationId.value) {
      el.managedNetworkReservationFormTitle.textContent = app.t('managedNetworkReservation.form.title.edit', { id: el.editManagedNetworkReservationId.value });
      el.managedNetworkReservationSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('managedNetworkReservation.form.submit.edit');
      el.managedNetworkReservationCancelBtn.style.display = '';
    } else {
      el.managedNetworkReservationFormTitle.textContent = app.t('managedNetworkReservation.form.title.add');
      el.managedNetworkReservationSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('managedNetworkReservation.form.submit.add');
      el.managedNetworkReservationCancelBtn.style.display = 'none';
    }

    el.managedNetworkReservationSubmitBtn.disabled = pending;
    el.managedNetworkReservationSubmitBtn.classList.toggle('is-busy', pending);
    el.managedNetworkReservationCancelBtn.disabled = pending;
  };

  app.setManagedNetworkReservationFormAdd = function setManagedNetworkReservationFormAdd() {
    const el = app.el;
    app.state.forms.managedNetworkReservation = { mode: 'add', sourceId: 0 };
    if (el.managedNetworkReservationForm) el.managedNetworkReservationForm.reset();
    if (el.editManagedNetworkReservationId) el.editManagedNetworkReservationId.value = '';
    app.refreshManagedNetworkReservationNetworkOptions();
    app.syncManagedNetworkReservationFormState();
  };

  app.enterManagedNetworkReservationEditMode = function enterManagedNetworkReservationEditMode(item) {
    const el = app.el;
    app.state.forms.managedNetworkReservation = { mode: 'edit', sourceId: item.id };
    el.editManagedNetworkReservationId.value = item.id;
    app.refreshManagedNetworkReservationNetworkOptions();
    el.managedNetworkReservationManagedNetworkId.value = String(item.managed_network_id || '');
    el.managedNetworkReservationMACAddress.value = item.mac_address || '';
    el.managedNetworkReservationIPv4Address.value = item.ipv4_address || '';
    el.managedNetworkReservationRemark.value = item.remark || '';
    app.syncManagedNetworkReservationFormState();
    if (el.managedNetworkReservationFormTitle && typeof el.managedNetworkReservationFormTitle.scrollIntoView === 'function') {
      el.managedNetworkReservationFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  app.exitManagedNetworkReservationEditMode = function exitManagedNetworkReservationEditMode() {
    if (app.el.managedNetworkReservationForm) app.clearFormErrors(app.el.managedNetworkReservationForm);
    app.setManagedNetworkReservationFormAdd();
  };

  app.buildManagedNetworkReservationFromForm = function buildManagedNetworkReservationFromForm() {
    const el = app.el;
    const normalizedMAC = normalizeMACAddress(el.managedNetworkReservationMACAddress && el.managedNetworkReservationMACAddress.value);
    return {
      managed_network_id: parseInt(String(el.managedNetworkReservationManagedNetworkId && el.managedNetworkReservationManagedNetworkId.value || '').trim(), 10) || 0,
      mac_address: normalizedMAC || String(el.managedNetworkReservationMACAddress && el.managedNetworkReservationMACAddress.value || '').trim(),
      ipv4_address: String(el.managedNetworkReservationIPv4Address && el.managedNetworkReservationIPv4Address.value || '').trim(),
      remark: String(el.managedNetworkReservationRemark && el.managedNetworkReservationRemark.value || '').trim()
    };
  };

  app.getManagedNetworkReservationFieldInputs = function getManagedNetworkReservationFieldInputs(issue) {
    const field = String((issue && issue.field) || '').trim();
    const map = {
      id: app.el.editManagedNetworkReservationId,
      managed_network_id: app.el.managedNetworkReservationManagedNetworkId,
      mac_address: app.el.managedNetworkReservationMACAddress,
      ipv4_address: app.el.managedNetworkReservationIPv4Address,
      remark: app.el.managedNetworkReservationRemark
    };
    return map[field] ? [map[field]] : [];
  };

  app.applyManagedNetworkReservationValidationIssues = function applyManagedNetworkReservationValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getManagedNetworkReservationFieldInputs(issue);
      if (!inputs.length) return;
      const translated = app.translateValidationMessage(issue.message);
      inputs.forEach((input) => {
        if (!input) return;
        if (!firstInvalid) firstInvalid = input;
        if (!input.hasAttribute('aria-invalid')) app.setFieldError(input, translated);
      });
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.getValidationIssueSummary({ issues: relevant }, null, 3) || app.translateValidationMessage(relevant[0].message));
  };

  app.getManagedNetworkReservationSortValue = function getManagedNetworkReservationSortValue(item, key) {
    if (key === 'managed_network_name') return item && item.managed_network_name ? item.managed_network_name : '';
    if (key === 'managed_network_bridge') return item && item.managed_network_bridge ? item.managed_network_bridge : '';
    return item ? item[key] : '';
  };

  app.renderManagedNetworkReservationsTable = function renderManagedNetworkReservationsTable() {
    const el = app.el;
    const st = app.state.managedNetworkReservations;
    if (!st || !el.managedNetworkReservationsBody) return;
    app.closeDropdowns();

    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, [
        item.id,
        item.managed_network_name,
        item.managed_network_bridge,
        item.mac_address,
        item.ipv4_address,
        item.remark
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getManagedNetworkReservationSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.managedNetworkReservationsBody);
    app.updateSortIndicators('managedNetworkReservationsTable', st);
    app.renderFilterMeta('managedNetworkReservations', filteredList.length, st.data.length);
    app.renderPagination('managedNetworkReservations', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noManagedNetworkReservations, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('managedNetworkReservation.list.empty'),
        actionButton: app.el.emptyAddManagedNetworkReservationBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('managedNetworkReservationsTable', false);
      return;
    }

    app.hideEmptyState(el.noManagedNetworkReservations);
    app.toggleTableVisibility('managedNetworkReservationsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('managed-network-reservation', item.id);
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.appendChild(app.createCell(String(item.id)));
      tr.appendChild(app.createCell(item.managed_network_name || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.managed_network_bridge || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.mac_address || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.ipv4_address || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.remark || app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: 'btn-edit-managed-network-reservation',
          text: app.t('common.edit'),
          dataset: { managedNetworkReservation: app.encData(item) },
          disabled: pending
        },
        {
          className: 'btn-delete-managed-network-reservation',
          text: app.t('common.delete'),
          dataset: { id: item.id },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.managedNetworkReservationsBody.appendChild(fragment);
  };

  app.loadManagedNetworkReservations = async function loadManagedNetworkReservations() {
    try {
      app.state.managedNetworkReservations.data = await app.apiCall('GET', '/api/managed-network-reservations');
      app.renderManagedNetworkReservationsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load managed network reservations:', e);
    }
  };

  app.deleteManagedNetworkReservation = async function deleteManagedNetworkReservation(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('managedNetworkReservation.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('managed-network-reservation', id, true);
    app.renderManagedNetworkReservationsTable();
    try {
      await app.apiCall('DELETE', '/api/managed-network-reservations?id=' + id);
      if (parseInt(app.el.editManagedNetworkReservationId.value || '0', 10) === id) app.exitManagedNetworkReservationEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.managedNetworkReservation') }));
      await Promise.all([
        typeof app.loadManagedNetworks === 'function' ? app.loadManagedNetworks() : Promise.resolve(),
        typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('managed-network-reservation', id, false);
      app.renderManagedNetworkReservationsTable();
    }
  };

  app.validateManagedNetworkReservationFormFields = function validateManagedNetworkReservationFormFields(item) {
    const el = app.el;
    let valid = true;

    if (!app.validateRequiredField(el.managedNetworkReservationManagedNetworkId)) valid = false;
    if (!app.validateRequiredField(el.managedNetworkReservationMACAddress)) valid = false;
    if (!app.validateRequiredField(el.managedNetworkReservationIPv4Address)) valid = false;

    if (item.managed_network_id) {
      const selectedNetwork = (app.state.managedNetworks.data || []).find((entry) => entry.id === item.managed_network_id);
      if (selectedNetwork && selectedNetwork.ipv4_enabled === false) {
        app.setFieldError(el.managedNetworkReservationManagedNetworkId, app.t('validation.managedNetworkReservationIPv4Disabled'));
        valid = false;
      } else {
        app.clearFieldError(el.managedNetworkReservationManagedNetworkId);
      }
    }

    if (item.mac_address) {
      if (!isValidMACAddress(item.mac_address)) {
        app.setFieldError(el.managedNetworkReservationMACAddress, app.t('validation.macAddress'));
        valid = false;
      } else {
        el.managedNetworkReservationMACAddress.value = normalizeMACAddress(item.mac_address);
        app.clearFieldError(el.managedNetworkReservationMACAddress);
      }
    }

    if (item.ipv4_address) {
      if (!app.parseIPv4(item.ipv4_address)) {
        app.setFieldError(el.managedNetworkReservationIPv4Address, app.t('validation.ipv4'));
        valid = false;
      } else {
        app.clearFieldError(el.managedNetworkReservationIPv4Address);
      }
    }

    return valid;
  };

  app.validateManagedNetworkFormFields = function validateManagedNetworkFormFields(item) {
    const el = app.el;
    let valid = true;

    if (!app.validateRequiredField(el.managedNetworkName)) valid = false;
    if (!app.validateRequiredField(el.managedNetworkBridgeMode)) valid = false;
    if (!app.validateRequiredField(el.managedNetworkBridgePicker || el.managedNetworkBridgeInterface)) valid = false;

    if (item.bridge && item.uplink_interface && item.bridge === item.uplink_interface) {
      app.setFieldError(el.managedNetworkBridgePicker || el.managedNetworkBridgeInterface, app.t('validation.managedNetworkBridgeUplinkConflict'));
      app.setFieldError(el.managedNetworkUplinkPicker || el.managedNetworkUplinkInterface, app.t('validation.managedNetworkBridgeUplinkConflict'));
      valid = false;
    }

    if (item.auto_egress_nat && !item.uplink_interface) {
      app.setFieldError(el.managedNetworkUplinkPicker || el.managedNetworkUplinkInterface, app.t('validation.managedNetworkUplinkRequired'));
      valid = false;
    }

    if (!managedNetworkUsesExistingBridge()) {
      const bridgeMTUText = String(el.managedNetworkBridgeMTU && el.managedNetworkBridgeMTU.value || '').trim();
      if (!isValidManagedNetworkBridgeMTUText(bridgeMTUText)) {
        setManagedNetworkBridgeAdvancedExpanded(true);
        app.setFieldError(el.managedNetworkBridgeMTU, app.t('validation.managedNetworkBridgeMTU'));
        valid = false;
      } else {
        app.clearFieldError(el.managedNetworkBridgeMTU);
      }
    } else {
      app.clearFieldError(el.managedNetworkBridgeMTU);
    }

    if (item.ipv4_enabled) {
      if (!item.ipv4_cidr) {
        app.setFieldError(el.managedNetworkIPv4CIDR, app.t('validation.managedNetworkIPv4Required'));
        valid = false;
      } else if (!isValidIPv4CIDR(item.ipv4_cidr)) {
        app.setFieldError(el.managedNetworkIPv4CIDR, app.t('validation.ipv4CIDR'));
        valid = false;
      } else {
        app.clearFieldError(el.managedNetworkIPv4CIDR);
      }

      [
        el.managedNetworkIPv4Gateway,
        el.managedNetworkIPv4PoolStart,
        el.managedNetworkIPv4PoolEnd
      ].forEach((input) => {
        const value = String(input && input.value || '').trim();
        if (!value) {
          app.clearFieldError(input);
          return;
        }
        if (!app.parseIPv4(value)) {
          app.setFieldError(input, app.t('validation.ipv4'));
          valid = false;
          return;
        }
        app.clearFieldError(input);
      });

      const dnsItems = splitIPv4List(item.ipv4_dns_servers);
      if (dnsItems.some((entry) => !app.parseIPv4(entry))) {
        app.setFieldError(el.managedNetworkIPv4DNSServers, app.t('validation.ipv4'));
        valid = false;
      } else {
        app.clearFieldError(el.managedNetworkIPv4DNSServers);
      }

      if (item.ipv4_pool_start && item.ipv4_pool_end && compareIPv4Text(item.ipv4_pool_start, item.ipv4_pool_end) > 0) {
        app.setFieldError(el.managedNetworkIPv4PoolStart, app.t('validation.managedNetworkIPv4PoolOrder'));
        app.setFieldError(el.managedNetworkIPv4PoolEnd, app.t('validation.managedNetworkIPv4PoolOrder'));
        valid = false;
      }
    } else {
      [
        el.managedNetworkIPv4CIDR,
        el.managedNetworkIPv4Gateway,
        el.managedNetworkIPv4PoolStart,
        el.managedNetworkIPv4PoolEnd,
        el.managedNetworkIPv4DNSServers
      ].forEach((input) => app.clearFieldError(input));
    }

    if (item.ipv6_enabled) {
      if (!app.validateRequiredField(el.managedNetworkIPv6ParentPicker || el.managedNetworkIPv6ParentInterface)) valid = false;
      if (!app.validateRequiredField(el.managedNetworkIPv6ParentPrefix)) valid = false;
      if (item.ipv6_parent_prefix && !app.isValidIPv6Prefix(item.ipv6_parent_prefix)) {
        app.setFieldError(el.managedNetworkIPv6ParentPrefix, app.t('validation.ipv6Prefix'));
        valid = false;
      } else if (item.ipv6_parent_prefix) {
        app.clearFieldError(el.managedNetworkIPv6ParentPrefix);
      }
    } else {
      [
        el.managedNetworkIPv6ParentPicker,
        el.managedNetworkIPv6ParentInterface,
        el.managedNetworkIPv6ParentPrefix,
        el.managedNetworkIPv6AssignmentMode
      ].forEach((input) => app.clearFieldError(input));
    }

    return valid;
  };

  app.refreshLocalizedUI = (function wrapRefreshLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original();
      if (typeof app.syncManagedNetworkFormState === 'function') app.syncManagedNetworkFormState();
      if (typeof app.renderManagedNetworkRuntimeStatusButton === 'function') app.renderManagedNetworkRuntimeStatusButton();
      if (typeof app.refreshManagedNetworkInterfaceSelectors === 'function') {
        app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: true });
      }
      if (typeof app.refreshManagedNetworkReservationNetworkOptions === 'function') {
        app.refreshManagedNetworkReservationNetworkOptions();
      }
      if (typeof app.renderManagedNetworkReservationCandidatesTable === 'function') {
        app.renderManagedNetworkReservationCandidatesTable();
      }
      if (typeof app.syncManagedNetworkReservationFormState === 'function') {
        app.syncManagedNetworkReservationFormState();
      }
    };
  })(app.refreshLocalizedUI);
})();
