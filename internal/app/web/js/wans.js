(function () {
  const app = window.ForwardApp;
  if (!app) return;

  Object.assign(app.el, {
    wanProfileForm: app.$('wanProfileForm'),
    wanProfileFormTitle: app.$('wanProfileFormTitle'),
    wanProfileSubmitBtn: app.$('wanProfileSubmitBtn'),
    wanProfileCancelBtn: app.$('wanProfileCancelBtn'),
    editWANProfileId: app.$('editWANProfileId'),
    wanProfileName: app.$('wanProfileName'),
    wanProfileType: app.$('wanProfileType'),
    wanProfileParentInterface: app.$('wanProfileParentInterface'),
    wanProfileParentPicker: app.$('wanProfileParentPicker'),
    wanProfileParentOptions: app.$('wanProfileParentOptions'),
    wanProfileRuntimeInterface: app.$('wanProfileRuntimeInterface'),
    wanProfileRuntimePicker: app.$('wanProfileRuntimePicker'),
    wanProfileRuntimeOptions: app.$('wanProfileRuntimeOptions'),
    wanProfileIPv4CIDR: app.$('wanProfileIPv4CIDR'),
    wanProfileIPv4Gateway: app.$('wanProfileIPv4Gateway'),
    wanProfileUsername: app.$('wanProfileUsername'),
    wanProfilePassword: app.$('wanProfilePassword'),
    wanProfileMTU: app.$('wanProfileMTU'),
    wanProfileMRU: app.$('wanProfileMRU'),
    wanProfileDefaultRoute: app.$('wanProfileDefaultRoute'),
    wanProfileMetric: app.$('wanProfileMetric'),
    wanProfileDNSMode: app.$('wanProfileDNSMode'),
    wanProfileDNSServers: app.$('wanProfileDNSServers'),
    wanProfileRemark: app.$('wanProfileRemark'),
    wanProfilesBody: app.$('wanProfilesBody'),
    noWANProfiles: app.$('noWANProfiles'),
    wanProfilesSearchInput: app.$('wanProfilesSearchInput'),
    wanProfilesFilterMeta: app.$('wanProfilesFilterMeta'),
    clearWANProfilesFilter: app.$('clearWANProfilesFilter'),
    wanProfilesPagination: app.$('wanProfilesPagination'),
    emptyAddWANProfileBtn: app.$('emptyAddWANProfileBtn'),
    managedNetworkWANProfile: app.$('managedNetworkWANProfile'),
    egressNATWANProfile: app.$('egressNATWANProfile')
  });

  app.state.wanProfiles = app.state.wanProfiles || { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.forms = app.state.forms || {};
  app.state.forms.wanProfile = app.state.forms.wanProfile || { mode: 'add', sourceId: 0 };
  app.state.pendingForms = app.state.pendingForms || {};
  if (!Object.prototype.hasOwnProperty.call(app.state.pendingForms, 'wanProfile')) app.state.pendingForms.wanProfile = false;

  function normalizeWANType(value) {
    const text = String(value || '').trim().toLowerCase();
    if (text === 'static' || text === 'dhcp' || text === 'pppoe') return text;
    return 'existing';
  }

  function normalizeDNSMode(value) {
    const text = String(value || '').trim().toLowerCase();
    if (text === 'manual' || text === 'ignore') return text;
    return 'auto';
  }

  function wanProfileItemsForSelect() {
    return (app.state.wanProfiles && Array.isArray(app.state.wanProfiles.data))
      ? app.state.wanProfiles.data.slice().sort((a, b) => app.compareValues(wanProfileLabel(a), wanProfileLabel(b)))
      : [];
  }

  function wanProfileLabel(item) {
    if (!item) return '';
    const name = String(item.name || '').trim() || ('#' + item.id);
    const type = app.t('wan.type.' + normalizeWANType(item.type));
    const iface = String(item.effective_interface || item.runtime_interface || item.parent_interface || '').trim();
    return name + ' [' + type + ']' + (iface ? ' -> ' + iface : '');
  }

  function selectedWANProfileID(selectEl) {
    return parseInt(String(selectEl && selectEl.value || '').trim(), 10) || 0;
  }

  function setGroupVisible(input, visible) {
    if (!input) return;
    const group = input.closest('.form-group');
    if (group) group.hidden = !visible;
  }

  function setGroupDisabled(input, disabled) {
    if (!input) return;
    input.disabled = !!disabled;
    if (disabled) input.setAttribute('aria-disabled', 'true');
    else input.removeAttribute('aria-disabled');
  }

  function wanStatusInfo(item) {
    if (!item || item.enabled === false) return { badge: 'disabled', text: app.t('status.disabled') };
    const status = String(item.status || '').trim().toLowerCase();
    if (status === 'running') return { badge: 'running', text: app.t('wan.status.running') };
    if (status === 'up') return { badge: 'running', text: app.t('wan.status.up') };
    if (status === 'error') return { badge: 'error', text: app.t('wan.status.error') };
    if (status === 'unsupported') return { badge: 'error', text: app.t('wan.status.unsupported') };
    if (status === 'disabled') return { badge: 'disabled', text: app.t('status.disabled') };
    return { badge: 'stopped', text: app.t('wan.status.unknown') };
  }

  function wanAddressSummary(item) {
    const parts = [];
    const v4 = Array.isArray(item && item.ipv4_addresses) ? item.ipv4_addresses.filter(Boolean) : [];
    const v6 = Array.isArray(item && item.ipv6_addresses) ? item.ipv6_addresses.filter(Boolean) : [];
    if (v4.length) parts.push('IPv4 ' + v4.slice(0, 2).join(', ') + (v4.length > 2 ? ', +' + (v4.length - 2) : ''));
    if (v6.length) parts.push('IPv6 ' + v6.slice(0, 1).join(', ') + (v6.length > 1 ? ', +' + (v6.length - 1) : ''));
    return parts.join('\n');
  }

  function wanRuntimeTitle(item) {
    return [
      app.t('wan.form.platform') + ': ' + (item.platform || app.t('common.dash')),
      item.supported === false && item.supported_reason ? item.supported_reason : '',
      item.last_error || '',
      item.default_ipv4_route ? app.t('wan.list.defaultIPv4') : '',
      item.default_ipv6_route ? app.t('wan.list.defaultIPv6') : ''
    ].filter(Boolean).join('\n');
  }

  app.findWANProfileByID = function findWANProfileByID(id) {
    const target = parseInt(id, 10) || 0;
    if (target <= 0) return null;
    return (app.state.wanProfiles.data || []).find((item) => parseInt(item.id, 10) === target) || null;
  };

  app.formatWANProfileRef = function formatWANProfileRef(id, fallback) {
    const item = app.findWANProfileByID(id);
    if (!item) return fallback || '';
    return wanProfileLabel(item);
  };

  app.populateWANProfileSelect = function populateWANProfileSelect(selectEl, selected, options) {
    if (!selectEl) return;
    const opts = options || {};
    const current = selected == null ? String(selectEl.value || '') : String(selected || '');
    app.clearNode(selectEl);
    app.addOption(selectEl, '', opts.emptyLabel || app.t('wan.select.none'));
    wanProfileItemsForSelect().forEach((item) => {
      app.addOption(selectEl, String(item.id), wanProfileLabel(item));
    });
    if (current && !Array.from(selectEl.options || []).some((option) => option.value === current)) {
      app.addOption(selectEl, current, opts.missingLabel || app.t('wan.select.missing', { id: current }));
    }
    selectEl.value = current;
  };

  app.refreshWANProfileSelects = function refreshWANProfileSelects() {
    app.populateWANProfileSelect(app.el.managedNetworkWANProfile, app.el.managedNetworkWANProfile && app.el.managedNetworkWANProfile.value, {
      emptyLabel: app.t('wan.select.noneManagedNetwork')
    });
    app.populateWANProfileSelect(app.el.egressNATWANProfile, app.el.egressNATWANProfile && app.el.egressNATWANProfile.value, {
      emptyLabel: app.t('wan.select.noneEgressNAT')
    });
  };

  app.getWANParentItems = function getWANParentItems() {
    return (app.hostNetworkInterfaces || []).filter((iface) => iface && iface.name && String(iface.name).trim().toLowerCase() !== 'lo').map((iface) => ({
      name: String(iface.name || '').trim(),
      kind: String(iface.kind || '').trim(),
      parent: String(iface.parent || '').trim(),
      addrs: (Array.isArray(iface.addresses) ? iface.addresses : []).map((address) => String((address && address.ip) || '').trim()).filter(Boolean)
    }));
  };

  app.getWANRuntimeItems = function getWANRuntimeItems() {
    return app.getWANParentItems();
  };

  app.refreshWANInterfaceSelectors = function refreshWANInterfaceSelectors() {
    const el = app.el;
    if (!el.wanProfileParentInterface) return;
    app.populateInterfacePicker(el.wanProfileParentInterface, el.wanProfileParentPicker, el.wanProfileParentOptions, {
      items: app.getWANParentItems(),
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });
    app.populateInterfacePicker(el.wanProfileRuntimeInterface, el.wanProfileRuntimePicker, el.wanProfileRuntimeOptions, {
      items: app.getWANRuntimeItems(),
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });
  };

  app.syncWANProfileFormState = function syncWANProfileFormState() {
    const el = app.el;
    if (!el.wanProfileForm || !el.wanProfileSubmitBtn || !el.wanProfileCancelBtn) return;

    const type = normalizeWANType(el.wanProfileType && el.wanProfileType.value);
    const dnsMode = normalizeDNSMode(el.wanProfileDNSMode && el.wanProfileDNSMode.value);
    const pending = !!app.state.pendingForms.wanProfile;
    const formState = app.state.forms.wanProfile || { mode: 'add', sourceId: 0 };

    setGroupVisible(el.wanProfileParentPicker || el.wanProfileParentInterface, type !== 'existing');
    setGroupVisible(el.wanProfileRuntimePicker || el.wanProfileRuntimeInterface, type === 'existing');
    setGroupVisible(el.wanProfileIPv4CIDR, type === 'static');
    setGroupVisible(el.wanProfileIPv4Gateway, type === 'static');
    setGroupVisible(el.wanProfileUsername, type === 'pppoe');
    setGroupVisible(el.wanProfilePassword, type === 'pppoe');
    setGroupVisible(el.wanProfileMRU, type === 'pppoe');
    setGroupVisible(el.wanProfileDNSServers, dnsMode === 'manual');

    if (formState.mode === 'edit' && el.editWANProfileId && el.editWANProfileId.value) {
      el.wanProfileFormTitle.textContent = app.t('wan.form.title.edit', { id: el.editWANProfileId.value });
      el.wanProfileSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('wan.form.submit.edit');
      el.wanProfileCancelBtn.style.display = '';
    } else {
      el.wanProfileFormTitle.textContent = app.t('wan.form.title.add');
      el.wanProfileSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('wan.form.submit.add');
      el.wanProfileCancelBtn.style.display = 'none';
    }

    el.wanProfileSubmitBtn.disabled = pending;
    el.wanProfileSubmitBtn.classList.toggle('is-busy', pending);
    el.wanProfileCancelBtn.disabled = pending;
  };

  app.setWANProfileFormAdd = function setWANProfileFormAdd() {
    const el = app.el;
    app.state.forms.wanProfile = { mode: 'add', sourceId: 0 };
    if (el.wanProfileForm) el.wanProfileForm.reset();
    if (el.editWANProfileId) el.editWANProfileId.value = '';
    if (el.wanProfileType) el.wanProfileType.value = 'existing';
    if (el.wanProfileParentInterface) el.wanProfileParentInterface.value = '';
    if (el.wanProfileRuntimeInterface) el.wanProfileRuntimeInterface.value = '';
    if (el.wanProfileDefaultRoute) el.wanProfileDefaultRoute.checked = true;
    if (el.wanProfileDNSMode) el.wanProfileDNSMode.value = 'auto';
    app.refreshWANInterfaceSelectors();
    app.syncWANProfileFormState();
  };

  app.enterWANProfileEditMode = function enterWANProfileEditMode(item) {
    const el = app.el;
    app.state.forms.wanProfile = { mode: 'edit', sourceId: item.id };
    el.editWANProfileId.value = item.id;
    el.wanProfileName.value = item.name || '';
    el.wanProfileType.value = normalizeWANType(item.type);
    el.wanProfileParentInterface.value = item.parent_interface || '';
    el.wanProfileRuntimeInterface.value = item.runtime_interface || '';
    el.wanProfileIPv4CIDR.value = item.ipv4_cidr || '';
    el.wanProfileIPv4Gateway.value = item.ipv4_gateway || '';
    el.wanProfileUsername.value = item.username || '';
    el.wanProfilePassword.value = '';
    el.wanProfilePassword.placeholder = item.password_set ? app.t('wan.form.password.keep') : app.t('wan.form.password.placeholder');
    el.wanProfileMTU.value = item.mtu ? String(item.mtu) : '';
    el.wanProfileMRU.value = item.mru ? String(item.mru) : '';
    el.wanProfileDefaultRoute.checked = item.default_route !== false;
    el.wanProfileMetric.value = item.metric ? String(item.metric) : '';
    el.wanProfileDNSMode.value = normalizeDNSMode(item.dns_mode);
    el.wanProfileDNSServers.value = item.dns_servers || '';
    el.wanProfileRemark.value = item.remark || '';
    app.refreshWANInterfaceSelectors();
    app.syncWANProfileFormState();
    if (el.wanProfileFormTitle && typeof el.wanProfileFormTitle.scrollIntoView === 'function') {
      el.wanProfileFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  app.exitWANProfileEditMode = function exitWANProfileEditMode() {
    if (app.el.wanProfileForm) app.clearFormErrors(app.el.wanProfileForm);
    app.setWANProfileFormAdd();
  };

  app.buildWANProfileFromForm = function buildWANProfileFromForm() {
    const el = app.el;
    const type = normalizeWANType(el.wanProfileType && el.wanProfileType.value);
    return {
      name: String(el.wanProfileName && el.wanProfileName.value || '').trim(),
      type: type,
      parent_interface: app.getInterfaceSubmissionValue(el.wanProfileParentInterface, el.wanProfileParentPicker, {
        items: app.getWANParentItems(),
        preserveSelected: true
      }),
      runtime_interface: app.getInterfaceSubmissionValue(el.wanProfileRuntimeInterface, el.wanProfileRuntimePicker, {
        items: app.getWANRuntimeItems(),
        preserveSelected: true
      }),
      ipv4_cidr: String(el.wanProfileIPv4CIDR && el.wanProfileIPv4CIDR.value || '').trim(),
      ipv4_gateway: String(el.wanProfileIPv4Gateway && el.wanProfileIPv4Gateway.value || '').trim(),
      username: String(el.wanProfileUsername && el.wanProfileUsername.value || '').trim(),
      password: String(el.wanProfilePassword && el.wanProfilePassword.value || ''),
      mtu: parseInt(String(el.wanProfileMTU && el.wanProfileMTU.value || '').trim(), 10) || 0,
      mru: parseInt(String(el.wanProfileMRU && el.wanProfileMRU.value || '').trim(), 10) || 0,
      default_route: !!(el.wanProfileDefaultRoute && el.wanProfileDefaultRoute.checked),
      metric: parseInt(String(el.wanProfileMetric && el.wanProfileMetric.value || '').trim(), 10) || 0,
      dns_mode: normalizeDNSMode(el.wanProfileDNSMode && el.wanProfileDNSMode.value),
      dns_servers: String(el.wanProfileDNSServers && el.wanProfileDNSServers.value || '').trim(),
      remark: String(el.wanProfileRemark && el.wanProfileRemark.value || '').trim()
    };
  };

  app.getWANProfileFieldInputs = function getWANProfileFieldInputs(issue) {
    const field = String((issue && issue.field) || '').trim();
    const map = {
      id: app.el.editWANProfileId,
      name: app.el.wanProfileName,
      type: app.el.wanProfileType,
      parent_interface: app.el.wanProfileParentPicker || app.el.wanProfileParentInterface,
      runtime_interface: app.el.wanProfileRuntimePicker || app.el.wanProfileRuntimeInterface,
      ipv4_cidr: app.el.wanProfileIPv4CIDR,
      ipv4_gateway: app.el.wanProfileIPv4Gateway,
      username: app.el.wanProfileUsername,
      password: app.el.wanProfilePassword,
      mtu: app.el.wanProfileMTU,
      mru: app.el.wanProfileMRU,
      metric: app.el.wanProfileMetric,
      dns_mode: app.el.wanProfileDNSMode,
      dns_servers: app.el.wanProfileDNSServers,
      remark: app.el.wanProfileRemark
    };
    return map[field] ? [map[field]] : [];
  };

  app.applyWANProfileValidationIssues = function applyWANProfileValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getWANProfileFieldInputs(issue);
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

  app.validateWANProfileFormFields = function validateWANProfileFormFields(item) {
    const el = app.el;
    const type = normalizeWANType(item.type);
    let valid = true;

    if (!app.validateRequiredField(el.wanProfileName)) valid = false;
    if (!app.validateRequiredField(el.wanProfileType)) valid = false;
    if (type === 'existing') {
      if (!app.validateRequiredField(el.wanProfileRuntimePicker || el.wanProfileRuntimeInterface)) valid = false;
    } else if (!app.validateRequiredField(el.wanProfileParentPicker || el.wanProfileParentInterface)) {
      valid = false;
    }
    if (type === 'static') {
      if (!app.validateRequiredField(el.wanProfileIPv4CIDR)) valid = false;
      if (item.ipv4_cidr && !isValidIPv4CIDRText(item.ipv4_cidr)) {
        app.setFieldError(el.wanProfileIPv4CIDR, app.t('validation.ipv4CIDR'));
        valid = false;
      }
      if (item.ipv4_gateway && !app.parseIPv4(item.ipv4_gateway)) {
        app.setFieldError(el.wanProfileIPv4Gateway, app.t('validation.ipv4'));
        valid = false;
      }
    }
    if (type === 'pppoe' && !app.validateRequiredField(el.wanProfileUsername)) valid = false;
    if (item.dns_mode === 'manual') {
      if (!app.validateRequiredField(el.wanProfileDNSServers)) valid = false;
      splitCSV(item.dns_servers).forEach((entry) => {
        if (!app.isValidIP(entry)) {
          app.setFieldError(el.wanProfileDNSServers, app.t('validation.ip'));
          valid = false;
        }
      });
    }
    [
      { input: el.wanProfileMTU, min: 0, max: 65535 },
      { input: el.wanProfileMRU, min: 0, max: 65535 },
      { input: el.wanProfileMetric, min: 0, max: 2147483647 }
    ].forEach((entry) => {
      const raw = String(entry.input && entry.input.value || '').trim();
      if (!raw) {
        app.clearFieldError(entry.input);
        return;
      }
      const value = parseInt(raw, 10);
      if (Number.isNaN(value) || value < entry.min || value > entry.max) {
        app.setFieldError(entry.input, app.t('validation.numberRange', { min: entry.min, max: entry.max }));
        valid = false;
      } else {
        app.clearFieldError(entry.input);
      }
    });
    return valid;
  };

  function isValidIPv4CIDRText(value) {
    const text = String(value || '').trim();
    const slash = text.lastIndexOf('/');
    if (slash <= 0 || slash === text.length - 1) return false;
    const ip = text.slice(0, slash);
    const prefix = parseInt(text.slice(slash + 1), 10);
    return !!app.parseIPv4(ip) && !Number.isNaN(prefix) && prefix >= 0 && prefix <= 32;
  }

  function splitCSV(value) {
    return String(value || '').split(/[,\s;]+/).map((item) => item.trim()).filter(Boolean);
  }

  app.getWANProfileSortValue = function getWANProfileSortValue(item, key) {
    if (key === 'status') return wanStatusInfo(item).text;
    if (key === 'effective_interface') return item.effective_interface || item.runtime_interface || item.parent_interface || '';
    if (key === 'enabled') return item.enabled === false ? 0 : 1;
    return item ? item[key] : '';
  };

  app.renderWANProfilesTable = function renderWANProfilesTable() {
    const el = app.el;
    const st = app.state.wanProfiles;
    if (!st || !el.wanProfilesBody) return;
    app.closeDropdowns();

    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, [
        item.id,
        item.name,
        item.type,
        app.t('wan.type.' + normalizeWANType(item.type)),
        item.parent_interface,
        item.runtime_interface,
        item.effective_interface,
        item.ipv4_cidr,
        item.ipv4_gateway,
        item.username,
        item.dns_mode,
        item.dns_servers,
        item.remark,
        item.status,
        item.last_error,
        wanAddressSummary(item)
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getWANProfileSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.wanProfilesBody);
    app.updateSortIndicators('wanProfilesTable', st);
    app.renderFilterMeta('wanProfiles', filteredList.length, st.data.length);
    app.renderPagination('wanProfiles', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noWANProfiles, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('wan.list.empty'),
        actionButton: el.emptyAddWANProfileBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('wanProfilesTable', false);
      return;
    }

    app.hideEmptyState(el.noWANProfiles);
    app.toggleTableVisibility('wanProfilesTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('wan-profile', item.id);
      const info = wanStatusInfo(item);
      const ifaceText = item.effective_interface || item.runtime_interface || item.parent_interface || '';
      const actions = [
        {
          className: item.enabled === false ? 'btn-enable-wan-profile' : 'btn-disable-wan-profile',
          text: pending ? app.t('common.processing') : app.t(item.enabled === false ? 'common.enable' : 'common.disable'),
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-edit-wan-profile',
          text: app.t('common.edit'),
          dataset: { wanProfile: app.encData(item) },
          disabled: pending
        },
        {
          className: 'btn-apply-wan-profile',
          text: app.t('wan.action.apply'),
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-reconnect-wan-profile',
          text: app.t('wan.action.reconnect'),
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-delete-wan-profile',
          text: app.t('common.delete'),
          dataset: { id: item.id },
          disabled: pending
        }
      ];
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');
      tr.appendChild(app.createCell(String(item.id)));
      tr.appendChild(app.createCell(item.name || app.emptyCellNode()));
      tr.appendChild(app.createCell(app.t('wan.type.' + normalizeWANType(item.type))));
      tr.appendChild(app.createCell(item.parent_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(ifaceText || app.emptyCellNode()));
      tr.appendChild(app.createCell(wanAddressSummary(item) || app.emptyCellNode(), 'managed-network-cell-text'));
      tr.appendChild(app.createCell(app.createBadgeNode('badge-' + info.badge, info.text, wanRuntimeTitle(item))));
      tr.appendChild(app.createCell(item.dns_mode === 'manual' ? (item.dns_servers || app.emptyCellNode()) : app.t('wan.dnsMode.' + normalizeDNSMode(item.dns_mode))));
      tr.appendChild(app.createCell(item.remark || app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createActionDropdown(actions, pending), 'cell-actions'));
      fragment.appendChild(tr);
    });
    el.wanProfilesBody.appendChild(fragment);
  };

  app.loadWANProfiles = async function loadWANProfiles() {
    try {
      app.state.wanProfiles.data = await app.apiCall('GET', '/api/wans');
      app.markDataFresh();
      app.refreshWANProfileSelects();
      app.renderWANProfilesTable();
      if (typeof app.renderManagedNetworksTable === 'function') app.renderManagedNetworksTable();
      if (typeof app.renderEgressNATsTable === 'function') app.renderEgressNATsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load wan profiles:', e);
    }
  };

  app.toggleWANProfile = async function toggleWANProfile(id) {
    if (app.isRowPending('wan-profile', id)) return;
    const source = (app.state.wanProfiles.data || []).find((item) => item.id === id);
    const willEnable = source ? source.enabled === false : false;
    app.setRowPending('wan-profile', id, true);
    app.renderWANProfilesTable();
    try {
      await app.apiCall('POST', '/api/wans/toggle?id=' + id);
      app.notify('success', app.t(willEnable ? 'toast.enabled' : 'toast.disabled', { item: app.t('noun.wanProfile') }));
      await app.loadWANProfiles();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['toggle']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.operationFailed', { message: message }));
      }
    } finally {
      app.setRowPending('wan-profile', id, false);
      app.renderWANProfilesTable();
    }
  };

  app.applyWANProfile = async function applyWANProfile(id) {
    if (app.isRowPending('wan-profile', id)) return;
    app.setRowPending('wan-profile', id, true);
    app.renderWANProfilesTable();
    try {
      const result = await app.apiCall('POST', '/api/wans/apply?id=' + id);
      app.notify('success', result && result.output ? result.output : app.t('wan.action.apply.success'), 4200);
      await Promise.all([
        typeof app.loadHostNetwork === 'function' ? app.loadHostNetwork() : Promise.resolve(),
        app.loadWANProfiles()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = String((e.payload && (e.payload.error || e.payload.output)) || e.message || '').trim();
        app.notify('error', app.t('errors.operationFailed', { message: app.translateValidationMessage(message) }));
      }
    } finally {
      app.setRowPending('wan-profile', id, false);
      app.renderWANProfilesTable();
    }
  };

  app.reconnectWANProfile = async function reconnectWANProfile(id) {
    if (app.isRowPending('wan-profile', id)) return;
    app.setRowPending('wan-profile', id, true);
    app.renderWANProfilesTable();
    try {
      const result = await app.apiCall('POST', '/api/wans/reconnect?id=' + id);
      app.notify('success', result && result.output ? result.output : app.t('wan.action.reconnect.success'), 4200);
      await Promise.all([
        typeof app.loadHostNetwork === 'function' ? app.loadHostNetwork() : Promise.resolve(),
        app.loadWANProfiles()
      ]);
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = String((e.payload && (e.payload.error || e.payload.output)) || e.message || '').trim();
        app.notify('error', app.t('errors.operationFailed', { message: app.translateValidationMessage(message) }));
      }
    } finally {
      app.setRowPending('wan-profile', id, false);
      app.renderWANProfilesTable();
    }
  };

  app.deleteWANProfile = async function deleteWANProfile(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('wan.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;
    app.setRowPending('wan-profile', id, true);
    app.renderWANProfilesTable();
    try {
      await app.apiCall('DELETE', '/api/wans?id=' + id);
      if (parseInt(app.el.editWANProfileId.value || '0', 10) === id) app.exitWANProfileEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.wanProfile') }));
      await app.loadWANProfiles();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('wan-profile', id, false);
      app.renderWANProfilesTable();
    }
  };

  app.refreshLocalizedUI = (function wrapRefreshLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original();
      if (typeof app.syncWANProfileFormState === 'function') app.syncWANProfileFormState();
      if (typeof app.refreshWANProfileSelects === 'function') app.refreshWANProfileSelects();
      if (typeof app.renderWANProfilesTable === 'function') app.renderWANProfilesTable();
    };
  })(app.refreshLocalizedUI);
})();
