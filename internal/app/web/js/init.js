(function () {
  const app = window.ForwardApp;
  if (!app) return;

  function rerenderByType(type) {
    if (type === 'rule') app.renderRulesTable();
    else if (type === 'site') app.renderSitesTable();
    else if (type === 'range') app.renderRangesTable();
  }

  function nounKeyByType(type) {
    if (type === 'rule') return 'noun.rule';
    if (type === 'site') return 'noun.site';
    return 'noun.range';
  }

  function bindSearchInput(input, table, render) {
    if (!input || !app.state[table]) return;
    input.value = app.state[table].searchQuery || '';

    input.addEventListener('input', () => {
      app.state[table].searchQuery = input.value || '';
      app.state[table].page = 1;
      render();
    });

    input.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' || !input.value) return;
      e.preventDefault();
      input.value = '';
      app.state[table].searchQuery = '';
      app.state[table].page = 1;
      render();
    });
  }

  function bindInterfacePicker(hiddenInput, pickerInput, options) {
    if (!hiddenInput || !pickerInput) return;
    const opts = options || {};
    const sync = function sync(commitLabel) {
      const previousValue = String(hiddenInput.value || '').trim();
      const result = app.syncInterfacePickerSelection(
        hiddenInput,
        pickerInput,
        Object.assign({}, opts, { commitLabel: !!commitLabel })
      );
      if (typeof opts.onSync === 'function') opts.onSync(result, previousValue);
    };

    pickerInput.addEventListener('input', () => sync(false));
    pickerInput.addEventListener('change', () => sync(true));
    pickerInput.addEventListener('blur', () => sync(true));
    pickerInput.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' || !pickerInput.value) return;
      e.preventDefault();
      pickerInput.value = '';
      hiddenInput.value = '';
      if (typeof opts.onSync === 'function') opts.onSync({ value: '', item: null, items: [], text: '' });
    });
  }

  app.shouldPauseAutoRefresh = function shouldPauseAutoRefresh() {
    if (app.state.activeDropdown) return true;
    if (app.el.egressNATProtocolMenu && !app.el.egressNATProtocolMenu.hidden) return true;
    if (app.el.confirmModal && app.el.confirmModal.classList && typeof app.el.confirmModal.classList.contains === 'function' &&
      app.el.confirmModal.classList.contains('active')) {
      return true;
    }

    const active = document.activeElement;
    if (!active) return false;
    const tag = String(active.tagName || '').toUpperCase();
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    if (active === app.el.egressNATProtocolTrigger) return true;
    return false;
  };

  app.startPolling = function startPolling() {
    app.stopPolling();
    if (!app.getToken() || document.hidden) return;

    app.state.pollerId = setInterval(() => {
      if (document.hidden || app.shouldPauseAutoRefresh()) return;
      app.refreshDashboard({
        includeWorkers: true,
        includeStats: app.state.activeTab === 'rule-stats'
      });
    }, 5000);
  };

  app.toggleItem = async function toggleItem(type, id) {
    if (app.isRowPending(type, id)) return;
    const source = app.state[type + 's'] && app.state[type + 's'].data
      ? app.state[type + 's'].data.find((item) => item.id === id)
      : null;
    const willEnable = source ? source.enabled === false : false;

    app.setRowPending(type, id, true);
    rerenderByType(type);

    try {
      await app.apiCall('POST', '/api/' + type + 's/toggle?id=' + id);
      app.notify('success', app.t(willEnable ? 'toast.enabled' : 'toast.disabled', { item: app.t(nounKeyByType(type)) }));
      if (type === 'rule') app.loadRules();
      else if (type === 'site') app.loadSites();
      else if (type === 'range') app.loadRanges();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['toggle', 'set_enabled']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.operationFailed', { message: message }));
      }
    } finally {
      app.setRowPending(type, id, false);
      rerenderByType(type);
    }
  };

  document.querySelectorAll('.tab').forEach((tab) => {
    tab.addEventListener('click', () => app.activateTab(tab.dataset.tab));

    tab.addEventListener('keydown', (e) => {
      const tabs = Array.from(document.querySelectorAll('.tab'));
      const index = tabs.indexOf(tab);
      if (index < 0) return;

      let nextIndex = index;
      if (e.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') nextIndex = 0;
      else if (e.key === 'End') nextIndex = tabs.length - 1;
      else return;

      e.preventDefault();
      app.activateTab(tabs[nextIndex].dataset.tab, { focus: true });
    });
  });

  if (app.el.localeSelect) {
    app.el.localeSelect.addEventListener('change', () => app.setLocale(app.el.localeSelect.value));
  }

  if (app.el.themeSelect) {
    app.el.themeSelect.addEventListener('change', () => app.setTheme(app.el.themeSelect.value));
  }

  bindSearchInput(app.el.rulesSearchInput, 'rules', () => app.renderRulesTable());
  bindSearchInput(app.el.sitesSearchInput, 'sites', () => app.renderSitesTable());
  bindSearchInput(app.el.rangesSearchInput, 'ranges', () => app.renderRangesTable());
  bindSearchInput(app.el.managedNetworksSearchInput, 'managedNetworks', () => app.renderManagedNetworksTable());
  bindSearchInput(app.el.managedNetworkReservationCandidatesSearchInput, 'managedNetworkReservationCandidates', () => app.renderManagedNetworkReservationCandidatesTable());
  bindSearchInput(app.el.managedNetworkReservationsSearchInput, 'managedNetworkReservations', () => app.renderManagedNetworkReservationsTable());
  bindSearchInput(app.el.egressNATsSearchInput, 'egressNATs', () => app.renderEgressNATsTable());
  bindSearchInput(app.el.ipv6AssignmentsSearchInput, 'ipv6Assignments', () => app.renderIPv6AssignmentsTable());
  bindSearchInput(app.el.workersSearchInput, 'workers', () => app.renderWorkersTable());

  if (app.el.batchDeleteRulesBtn) {
    app.el.batchDeleteRulesBtn.addEventListener('click', () => app.deleteSelectedRules());
  }

  if (app.el.rulesSelectAll) {
    app.el.rulesSelectAll.addEventListener('change', () => {
      const pageItems = app.paginateList(app.state.rules, app.getFilteredRules()).items;
      pageItems.forEach((rule) => {
        if (app.isRowPending('rule', rule.id)) return;
        app.setRuleSelected(rule.id, app.el.rulesSelectAll.checked);
      });
      app.renderRulesTable();
    });
  }

  if (app.el.refreshNowBtn) {
    app.el.refreshNowBtn.addEventListener('click', () => {
      app.refreshDashboard({
        includeMeta: true,
        includeWorkers: true,
        includeStats: app.state.activeTab === 'rule-stats'
      });
    });
  }

  if (app.el.refreshWorkersBtn) {
    app.el.refreshWorkersBtn.addEventListener('click', () => app.loadWorkers());
  }

  (app.el.refreshCurrentConnsBtns || []).forEach((button) => {
    button.addEventListener('click', () => app.loadCurrentConns());
  });

  if (app.el.emptyRefreshWorkersBtn) {
    app.el.emptyRefreshWorkersBtn.addEventListener('click', () => app.loadWorkers());
  }

  if (app.el.emptyAddRuleBtn) {
    app.el.emptyAddRuleBtn.addEventListener('click', () => app.focusSection('rules', app.el.ruleFormTitle, app.$('ruleRemark')));
  }

  if (app.el.emptyAddSiteBtn) {
    app.el.emptyAddSiteBtn.addEventListener('click', () => app.focusSection('sites', app.el.siteFormTitle, app.$('siteDomain')));
  }

  if (app.el.emptyAddRangeBtn) {
    app.el.emptyAddRangeBtn.addEventListener('click', () => app.focusSection('ranges', app.el.rangeFormTitle, app.$('rangeRemark')));
  }

  if (app.el.emptyAddManagedNetworkBtn) {
    app.el.emptyAddManagedNetworkBtn.addEventListener('click', () => app.focusSection('managed-networks', app.el.managedNetworkFormTitle, app.el.managedNetworkName));
  }

  if (app.el.emptyAddManagedNetworkReservationBtn) {
    app.el.emptyAddManagedNetworkReservationBtn.addEventListener('click', () => {
      const hasManagedNetworks = !!(app.state.managedNetworks && Array.isArray(app.state.managedNetworks.data) && app.state.managedNetworks.data.length);
      if (!hasManagedNetworks) {
        app.focusSection('managed-networks', app.el.managedNetworkFormTitle, app.el.managedNetworkName);
        return;
      }
      app.focusSection('managed-networks', app.el.managedNetworkReservationFormTitle, app.el.managedNetworkReservationManagedNetworkId);
    });
  }

  if (app.el.emptyAddEgressNATBtn) {
    app.el.emptyAddEgressNATBtn.addEventListener('click', () => app.focusSection('egress-nats', app.el.egressNATFormTitle, app.el.egressNATParentPicker || app.el.egressNATParentInterface));
  }

  if (app.el.emptyAddIPv6AssignmentBtn) {
    app.el.emptyAddIPv6AssignmentBtn.addEventListener('click', () => app.focusSection('ipv6-assignments', app.el.ipv6AssignmentFormTitle, app.el.ipv6ParentPicker || app.el.ipv6ParentInterface));
  }

  app.el.tokenSubmit.addEventListener('click', () => {
    const token = app.el.tokenInput.value.trim();
    if (!token) return;
    app.setToken(token);
    app.hideTokenModal();
    app.init();
  });

  app.el.tokenInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') app.el.tokenSubmit.click();
  });

  app.el.logoutBtn.addEventListener('click', async () => {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.logoutTitle'),
      message: app.t('auth.logoutConfirm'),
      confirmText: app.t('auth.logout'),
      cancelText: app.t('common.cancel')
    });
    if (!confirmed) return;

    app.clearToken();
    app.notify('success', app.t('toast.loggedOut'));
    app.showTokenModal();
  });

  bindInterfacePicker(app.el.inInterface, app.el.inInterfacePicker, {
    onSync() {
      app.populateIPSelect(app.el.inInterface, app.el.inIP, app.el.inIP.value);
    }
  });
  bindInterfacePicker(app.el.outInterface, app.el.outInterfacePicker, {
    onSync() {
      if (typeof app.refreshRuleSourceIPOptions === 'function') app.refreshRuleSourceIPOptions(app.el.ruleOutSourceIP.value);
      else app.populateSourceIPSelect(app.el.outInterface, app.el.ruleOutSourceIP, app.el.ruleOutSourceIP.value, false);
      app.updateRuleTransparentWarning();
    }
  });
  bindInterfacePicker(app.el.siteListenIface, app.el.siteListenIfacePicker, {
    onSync() {
      app.populateSiteListenIP(app.el.siteListenIface, app.el.siteListenIP, app.el.siteListenIP.value);
      app.updateSiteTransparentWarning();
    }
  });
  bindInterfacePicker(app.el.rangeInInterface, app.el.rangeInInterfacePicker, {
    onSync() {
      app.populateIPSelect(app.el.rangeInInterface, app.el.rangeInIP, app.el.rangeInIP.value);
    }
  });
  bindInterfacePicker(app.el.rangeOutInterface, app.el.rangeOutInterfacePicker, {
    onSync() {
      if (typeof app.refreshRangeSourceIPOptions === 'function') app.refreshRangeSourceIPOptions(app.el.rangeOutSourceIP.value);
      else app.populateSourceIPSelect(app.el.rangeOutInterface, app.el.rangeOutSourceIP, app.el.rangeOutSourceIP.value, false);
      app.updateRangeTransparentWarning();
    }
  });
  bindInterfacePicker(app.el.managedNetworkBridgeInterface, app.el.managedNetworkBridgePicker, {
    getItems() {
      return typeof app.getManagedNetworkBridgeItems === 'function' ? app.getManagedNetworkBridgeItems() : [];
    },
    preserveSelected: true,
    onSync(result, previousValue) {
      const existingMode = String(app.el.managedNetworkBridgeMode && app.el.managedNetworkBridgeMode.value || '').trim().toLowerCase() === 'existing';
      if (!existingMode) return;
      if (previousValue === String((result && result.value) || '').trim()) return;
      if (typeof app.refreshManagedNetworkInterfaceSelectors === 'function') {
        app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: true });
      }
    }
  });
  bindInterfacePicker(app.el.managedNetworkUplinkInterface, app.el.managedNetworkUplinkPicker, {
    getItems() {
      return typeof app.getManagedNetworkUplinkItems === 'function'
        ? app.getManagedNetworkUplinkItems(app.el.managedNetworkBridgeInterface.value)
        : [];
    },
    preserveSelected: true
  });
  bindInterfacePicker(app.el.managedNetworkIPv6ParentInterface, app.el.managedNetworkIPv6ParentPicker, {
    getItems() {
      return typeof app.getManagedNetworkIPv6ParentItems === 'function' ? app.getManagedNetworkIPv6ParentItems() : [];
    },
    preserveSelected: true,
    onSync() {
      if (typeof app.refreshManagedNetworkInterfaceSelectors === 'function') {
        app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: false });
      }
    }
  });
  bindInterfacePicker(app.el.egressNATParentInterface, app.el.egressNATParentPicker, {
    getItems() {
      return typeof app.getEgressNATParentInterfaces === 'function' ? app.getEgressNATParentInterfaces() : (app.interfaces || []);
    },
    preserveSelected: true,
    onSync(result, previousValue) {
      if (previousValue === String((result && result.value) || '').trim()) return;
      app.el.egressNATChildInterface.value = '';
      if (app.el.egressNATChildPicker) app.el.egressNATChildPicker.value = '';
      app.populateEgressNATInterfaceSelectors();
    }
  });
  bindInterfacePicker(app.el.egressNATChildInterface, app.el.egressNATChildPicker, {
    getItems() {
      return typeof app.getEgressNATChildInterfaces === 'function'
        ? app.getEgressNATChildInterfaces(app.el.egressNATParentInterface.value)
        : [];
    },
    preserveSelected: true,
    onSync() {
      app.populateEgressNATInterfaceSelectors({ preserveOutSelection: true, autoSelectOut: false });
    }
  });
  bindInterfacePicker(app.el.egressNATOutInterface, app.el.egressNATOutPicker, {
    getItems() {
      return typeof app.getEgressNATOutInterfaceCandidates === 'function'
        ? app.getEgressNATOutInterfaceCandidates(app.el.egressNATParentInterface.value, app.el.egressNATChildInterface.value)
        : (app.interfaces || []);
    },
    preserveSelected: true,
    onSync() {
      if (typeof app.updateEgressNATOutInterfaceHint === 'function') {
        app.updateEgressNATOutInterfaceHint('', false);
      }
      app.populateEgressNATSourceIPSelect(app.el.egressNATOutSourceIP.value);
    }
  });
  bindInterfacePicker(app.el.ipv6ParentInterface, app.el.ipv6ParentPicker, {
    getItems() {
      return typeof app.refreshIPv6AssignmentInterfaceSelectors === 'function' && typeof app.getParentInterfaceItems === 'function'
        ? app.getParentInterfaceItems()
        : [];
    },
    preserveSelected: true,
    onSync() {
      if (typeof app.refreshIPv6AssignmentInterfaceSelectors === 'function') {
        app.refreshIPv6AssignmentInterfaceSelectors({ preservePrefix: false });
      }
    }
  });
  bindInterfacePicker(app.el.ipv6TargetInterface, app.el.ipv6TargetPicker, {
    getItems() {
      return typeof app.getTargetInterfaceItems === 'function'
        ? app.getTargetInterfaceItems(app.el.ipv6ParentInterface.value)
        : [];
    },
    preserveSelected: true
  });
  if (app.el.ipv6ParentPrefix) {
    app.el.ipv6ParentPrefix.addEventListener('change', () => {
      if (typeof app.syncIPv6AssignedPrefixFromParentPrefix === 'function') {
        app.syncIPv6AssignedPrefixFromParentPrefix();
      }
    });
  }
  if (app.el.ipv6AssignedPrefix) {
    app.el.ipv6AssignedPrefix.addEventListener('input', () => {
      if (typeof app.updateIPv6AssignmentModeHint === 'function') app.updateIPv6AssignmentModeHint();
    });
    app.el.ipv6AssignedPrefix.addEventListener('change', () => {
      if (typeof app.updateIPv6AssignmentModeHint === 'function') app.updateIPv6AssignmentModeHint();
    });
  }
  if (app.el.managedNetworkIPv4Enabled) {
    app.el.managedNetworkIPv4Enabled.addEventListener('change', () => {
      if (typeof app.syncManagedNetworkFormState === 'function') app.syncManagedNetworkFormState();
    });
  }
  if (app.el.managedNetworkBridgeMode) {
    app.el.managedNetworkBridgeMode.addEventListener('change', () => {
      if (typeof app.refreshManagedNetworkInterfaceSelectors === 'function') {
        app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: true });
      }
      if (typeof app.syncManagedNetworkFormState === 'function') app.syncManagedNetworkFormState();
    });
  }
  if (app.el.managedNetworkBridgePicker) {
    app.el.managedNetworkBridgePicker.addEventListener('input', () => {
      if (app.el.managedNetworkBridgePicker.dataset) delete app.el.managedNetworkBridgePicker.dataset.autofilled;
    });
  }
  if (app.el.managedNetworkPVEQuickFillBtn) {
    app.el.managedNetworkPVEQuickFillBtn.addEventListener('click', () => {
      if (typeof app.applyManagedNetworkPVEQuickFill === 'function') app.applyManagedNetworkPVEQuickFill();
    });
  }
  if (app.el.reloadManagedNetworkRuntimeBtn) {
    app.el.reloadManagedNetworkRuntimeBtn.addEventListener('click', () => {
      if (typeof app.reloadManagedNetworkRuntime === 'function') app.reloadManagedNetworkRuntime();
    });
  }
  if (app.el.repairManagedNetworkRuntimeBtn) {
    app.el.repairManagedNetworkRuntimeBtn.addEventListener('click', () => {
      if (typeof app.repairManagedNetworkRuntime === 'function') app.repairManagedNetworkRuntime();
    });
  }
  if (app.el.managedNetworkIPv6Enabled) {
    app.el.managedNetworkIPv6Enabled.addEventListener('change', () => {
      if (typeof app.refreshManagedNetworkInterfaceSelectors === 'function') {
        app.refreshManagedNetworkInterfaceSelectors({ preservePrefix: true });
      }
      if (typeof app.syncManagedNetworkFormState === 'function') app.syncManagedNetworkFormState();
    });
  }
  if (app.el.managedNetworkIPv6ParentPrefix) {
    app.el.managedNetworkIPv6ParentPrefix.addEventListener('change', () => {
      if (typeof app.syncManagedNetworkFormState === 'function') app.syncManagedNetworkFormState();
    });
  }
  if (app.el.egressNATProtocolTCP) app.el.egressNATProtocolTCP.addEventListener('change', app.syncEgressNATProtocolSelectionFromInputs);
  if (app.el.egressNATProtocolUDP) app.el.egressNATProtocolUDP.addEventListener('change', app.syncEgressNATProtocolSelectionFromInputs);
  if (app.el.egressNATProtocolICMP) app.el.egressNATProtocolICMP.addEventListener('change', app.syncEgressNATProtocolSelectionFromInputs);
  app.el.ruleTransparent.addEventListener('change', app.updateRuleTransparentWarning);
  app.el.siteTransparent.addEventListener('change', app.updateSiteTransparentWarning);
  app.el.rangeTransparent.addEventListener('change', app.updateRangeTransparentWarning);
  app.el.ruleOutIP.addEventListener('input', () => {
    if (typeof app.refreshRuleSourceIPOptions === 'function') app.refreshRuleSourceIPOptions();
    app.updateRuleTransparentWarning();
  });
  app.el.siteBackendIP.addEventListener('input', () => {
    if (typeof app.refreshSiteBackendSourceIPOptions === 'function') app.refreshSiteBackendSourceIPOptions();
    app.updateSiteTransparentWarning();
  });
  app.el.rangeOutIP.addEventListener('input', () => {
    if (typeof app.refreshRangeSourceIPOptions === 'function') app.refreshRangeSourceIPOptions();
    app.updateRangeTransparentWarning();
  });

  app.el.ruleCancelBtn.addEventListener('click', app.exitRuleEditMode);
  app.el.siteCancelBtn.addEventListener('click', app.exitSiteEditMode);
  app.el.rangeCancelBtn.addEventListener('click', app.exitRangeEditMode);
  if (app.el.managedNetworkCancelBtn) app.el.managedNetworkCancelBtn.addEventListener('click', app.exitManagedNetworkEditMode);
  if (app.el.managedNetworkReservationCancelBtn) app.el.managedNetworkReservationCancelBtn.addEventListener('click', app.exitManagedNetworkReservationEditMode);
  if (app.el.egressNATCancelBtn) app.el.egressNATCancelBtn.addEventListener('click', app.exitEgressNATEditMode);
  if (app.el.ipv6AssignmentCancelBtn) app.el.ipv6AssignmentCancelBtn.addEventListener('click', app.exitIPv6AssignmentEditMode);

  document.addEventListener('visibilitychange', () => {
    app.state.pageVisible = !document.hidden;
    if (document.hidden) {
      app.stopPolling();
      app.closeDropdowns();
      return;
    }

    if (!app.getToken()) return;
    app.refreshDashboard({
      includeWorkers: true,
      includeStats: app.state.activeTab === 'rule-stats'
    });
    app.startPolling();
  });

  document.addEventListener('change', (e) => {
    if (e.target === app.el.egressNATProtocolTCP || e.target === app.el.egressNATProtocolUDP || e.target === app.el.egressNATProtocolICMP) {
      app.syncEgressNATProtocolSelectionFromInputs();
      return;
    }

    const ruleSelect = e.target.closest('.rule-select-checkbox[data-id]');
    if (!ruleSelect) return;
    app.setRuleSelected(parseInt(ruleSelect.dataset.id, 10), ruleSelect.checked);
    app.renderRulesTable();
  });

  document.addEventListener('click', (e) => {
    if (e.target === app.el.egressNATProtocolTrigger) {
      e.stopPropagation();
      const isOpen = !!(app.el.egressNATProtocolMenu && !app.el.egressNATProtocolMenu.hidden);
      app.closeDropdowns();
      if (!isOpen) app.openEgressNATProtocolMenu();
      return;
    }

    if (e.target.closest('#egressNATProtocolMenu')) {
      return;
    }

    if (typeof app.closeEgressNATProtocolMenu === 'function') app.closeEgressNATProtocolMenu();

    const trigger = e.target.closest('.action-dropdown-trigger');
    if (trigger) {
      e.stopPropagation();
      const dropdown = trigger.closest('.action-dropdown');
      const wasOpen = dropdown.classList.contains('open');
      if (wasOpen) app.closeDropdowns();
      else app.openDropdown(dropdown);
      return;
    }

    const menuItem = e.target.closest('.action-dropdown-menu button');
    app.closeDropdowns();

    const th = e.target.closest('th.sortable');
    if (th) {
      const table = th.dataset.table;
      const key = th.dataset.sort;
      if (table && key && app.state[table]) {
        app.toggleSort(app.state[table], key);
        if (table === 'rules') app.renderRulesTable();
        else if (table === 'sites') app.renderSitesTable();
        else if (table === 'ranges') app.renderRangesTable();
        else if (table === 'managedNetworks') app.renderManagedNetworksTable();
        else if (table === 'egressNATs') app.renderEgressNATsTable();
        else if (table === 'ipv6Assignments') app.renderIPv6AssignmentsTable();
        else if (table === 'workers') app.renderWorkersTable();
        else if (table === 'ruleStats') app.loadRuleStats();
        else if (table === 'siteStats') app.renderSiteStatsTable();
        else if (table === 'rangeStats') app.loadRangeStats();
        else if (table === 'egressNATStats') app.loadEgressNATStats();
      }
      return;
    }

    const tagBadge = e.target.closest('.tag-badge[data-table][data-tag]');
    if (tagBadge) {
      const table = tagBadge.dataset.table;
      const tag = tagBadge.dataset.tag;
      if (app.state[table] && Object.prototype.hasOwnProperty.call(app.state[table], 'filterTag')) {
        app.state[table].filterTag = app.state[table].filterTag === tag ? '' : tag;
        app.state[table].page = 1;
        if (table === 'rules') app.renderRulesTable();
        else if (table === 'sites') app.renderSitesTable();
        else if (table === 'ranges') app.renderRangesTable();
      }
      return;
    }

    const toggle = e.target.closest('.btn-enable, .btn-disable');
    if (toggle) {
      app.toggleItem(toggle.dataset.type, parseInt(toggle.dataset.id, 10));
      return;
    }

    const toggleEgressNAT = e.target.closest('.btn-egress-enable, .btn-egress-disable');
    if (toggleEgressNAT) {
      app.toggleEgressNAT(parseInt(toggleEgressNAT.dataset.id, 10));
      return;
    }

    const toggleManagedNetwork = e.target.closest('.btn-enable-managed-network, .btn-disable-managed-network');
    if (toggleManagedNetwork) {
      app.toggleManagedNetwork(parseInt(toggleManagedNetwork.dataset.id, 10));
      return;
    }

    const persistManagedNetworkBridge = e.target.closest('.btn-persist-managed-network-bridge');
    if (persistManagedNetworkBridge) {
      app.persistManagedNetworkBridge(parseInt(persistManagedNetworkBridge.dataset.id, 10));
      return;
    }

    const editRule = e.target.closest('.btn-edit');
    if (editRule) {
      app.enterRuleEditMode(app.decData(editRule.dataset.rule));
      return;
    }

    const cloneRule = e.target.closest('.btn-clone');
    if (cloneRule) {
      app.enterRuleCloneMode(app.decData(cloneRule.dataset.rule));
      return;
    }

    const editSite = e.target.closest('.btn-edit-site');
    if (editSite) {
      app.enterSiteEditMode(app.decData(editSite.dataset.site));
      return;
    }

    const cloneSite = e.target.closest('.btn-clone-site');
    if (cloneSite) {
      app.enterSiteCloneMode(app.decData(cloneSite.dataset.site));
      return;
    }

    const editRange = e.target.closest('.btn-edit-range');
    if (editRange) {
      app.enterRangeEditMode(app.decData(editRange.dataset.range));
      return;
    }

    const editEgressNAT = e.target.closest('.btn-edit-egress-nat');
    if (editEgressNAT) {
      app.enterEgressNATEditMode(app.decData(editEgressNAT.dataset.egressNat));
      return;
    }

    const editManagedNetwork = e.target.closest('.btn-edit-managed-network');
    if (editManagedNetwork) {
      app.enterManagedNetworkEditMode(app.decData(editManagedNetwork.dataset.managedNetwork));
      return;
    }

    const editManagedNetworkReservation = e.target.closest('.btn-edit-managed-network-reservation');
    if (editManagedNetworkReservation) {
      app.enterManagedNetworkReservationEditMode(app.decData(editManagedNetworkReservation.dataset.managedNetworkReservation));
      return;
    }

    const editManagedNetworkReservationCandidate = e.target.closest('.btn-edit-managed-network-reservation-candidate');
    if (editManagedNetworkReservationCandidate) {
      app.editManagedNetworkReservationFromCandidate(app.decData(editManagedNetworkReservationCandidate.dataset.managedNetworkReservationCandidate));
      return;
    }

    const fillManagedNetworkReservationCandidate = e.target.closest('.btn-fill-managed-network-reservation-candidate');
    if (fillManagedNetworkReservationCandidate) {
      app.prefillManagedNetworkReservationFromCandidate(app.decData(fillManagedNetworkReservationCandidate.dataset.managedNetworkReservationCandidate));
      return;
    }

    const createManagedNetworkReservationCandidate = e.target.closest('.btn-create-managed-network-reservation-candidate');
    if (createManagedNetworkReservationCandidate) {
      app.createManagedNetworkReservationFromCandidate(app.decData(createManagedNetworkReservationCandidate.dataset.managedNetworkReservationCandidate));
      return;
    }

    const cloneRange = e.target.closest('.btn-clone-range');
    if (cloneRange) {
      app.enterRangeCloneMode(app.decData(cloneRange.dataset.range));
      return;
    }

    const del = e.target.closest('.btn-delete');
    if (del) {
      const id = parseInt(del.dataset.id, 10);
      if (del.dataset.type === 'site') app.deleteSite(id);
      else if (del.dataset.type === 'range') app.deleteRange(id);
      else app.deleteRule(id);
      return;
    }

    const deleteEgressNAT = e.target.closest('.btn-delete-egress-nat');
    if (deleteEgressNAT) {
      app.deleteEgressNAT(parseInt(deleteEgressNAT.dataset.id, 10));
      return;
    }

    const deleteManagedNetwork = e.target.closest('.btn-delete-managed-network');
    if (deleteManagedNetwork) {
      app.deleteManagedNetwork(parseInt(deleteManagedNetwork.dataset.id, 10));
      return;
    }

    const deleteManagedNetworkReservation = e.target.closest('.btn-delete-managed-network-reservation');
    if (deleteManagedNetworkReservation) {
      app.deleteManagedNetworkReservation(parseInt(deleteManagedNetworkReservation.dataset.id, 10));
      return;
    }

    const toggleIPv6Assignment = e.target.closest('.btn-enable-ipv6-assignment, .btn-disable-ipv6-assignment');
    if (toggleIPv6Assignment) {
      app.toggleIPv6Assignment(parseInt(toggleIPv6Assignment.dataset.id, 10));
      return;
    }

    const editIPv6Assignment = e.target.closest('.btn-edit-ipv6-assignment');
    if (editIPv6Assignment) {
      app.enterIPv6AssignmentEditMode(app.decData(editIPv6Assignment.dataset.ipv6Assignment));
      return;
    }

    const deleteIPv6Assignment = e.target.closest('.btn-delete-ipv6-assignment');
    if (deleteIPv6Assignment) {
      app.deleteIPv6Assignment(parseInt(deleteIPv6Assignment.dataset.id, 10));
    }
  });

  app.el.ruleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    app.clearFormErrors(app.el.ruleForm);
    const rule = app.buildRuleFromForm();
    let valid = true;
    if (!app.validateRequiredField(app.el.inIP)) valid = false;
    if (!app.validatePortField(app.$('inPort'))) valid = false;
    if (!app.validateIPField(app.$('outIP'))) valid = false;
    if (!app.validatePortField(app.$('outPort'))) valid = false;
    if (!valid || !rule.in_ip || !rule.in_port || !rule.out_ip || !rule.out_port) {
      app.notify('error', app.t('validation.reviewErrors'));
      app.focusFirstError(app.el.ruleForm);
      return;
    }

    const editing = parseInt(app.el.editRuleId.value || '0', 10);
    await app.withFormBusy(
      'rule',
      app.el.ruleSubmitBtn,
      app.el.ruleCancelBtn,
      app.t('common.saving'),
      async () => {
        try {
          const payload = Object.assign({}, rule);
          if (editing > 0) payload.id = editing;

          const validatedRule = await app.validateRuleDraft(payload, editing > 0);
          if (!validatedRule) return;

          if (editing > 0) {
            const warning = app.updateRuleTransparentWarning();
            if (!(await app.confirmTransparentWarning(warning))) return;

            await app.apiCall('PUT', '/api/rules', {
              id: editing,
              in_interface: validatedRule.in_interface,
              in_ip: validatedRule.in_ip,
              in_port: validatedRule.in_port,
              out_interface: validatedRule.out_interface,
              out_ip: validatedRule.out_ip,
              out_source_ip: validatedRule.out_source_ip || '',
              out_port: validatedRule.out_port,
              protocol: validatedRule.protocol,
              remark: validatedRule.remark || '',
              tag: validatedRule.tag || '',
              transparent: !!validatedRule.transparent
            });
            app.notify('success', app.t('toast.saved', { item: app.t('noun.rule') }));
          } else {
            const warning = app.updateRuleTransparentWarning();
            if (!(await app.confirmTransparentWarning(warning))) return;

            await app.apiCall('POST', '/api/rules', {
              in_interface: validatedRule.in_interface,
              in_ip: validatedRule.in_ip,
              in_port: validatedRule.in_port,
              out_interface: validatedRule.out_interface,
              out_ip: validatedRule.out_ip,
              out_source_ip: validatedRule.out_source_ip || '',
              out_port: validatedRule.out_port,
              protocol: validatedRule.protocol,
              remark: validatedRule.remark || '',
              tag: validatedRule.tag || '',
              transparent: !!validatedRule.transparent
            });
            app.notify('success', app.t('toast.created', { item: app.t('noun.rule') }));
          }
          app.exitRuleEditMode();
          await app.loadRules();
        } catch (err) {
          if (err.message !== 'unauthorized') {
            if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
              app.applyRuleValidationIssues(err.payload.issues);
              return;
            }
            app.notify('error', app.t('errors.actionFailed', {
              action: app.t(editing > 0 ? 'action.update' : 'action.add'),
              message: err.message
            }));
          }
        }
      },
      app.syncRuleFormState
    );
  });

  app.el.siteForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    app.clearFormErrors(app.el.siteForm);
    const httpPort = parseInt(app.$('siteBackendHTTP').value, 10) || 0;
    const httpsPort = parseInt(app.$('siteBackendHTTPS').value, 10) || 0;
    if (httpPort === 0 && httpsPort === 0) {
      app.setFieldError(app.$('siteBackendHTTP'), app.t('validation.required'));
      app.setFieldError(app.$('siteBackendHTTPS'), app.t('validation.required'));
      app.notify('error', app.t('validation.sitePortsRequired'));
      app.focusFirstError(app.el.siteForm);
      return;
    }

    const site = {
      domain: app.$('siteDomain').value.trim(),
      listen_ip: app.el.siteListenIP.value || '0.0.0.0',
      listen_interface: app.getInterfaceSubmissionValue(app.el.siteListenIface, app.el.siteListenIfacePicker),
      backend_ip: app.$('siteBackendIP').value.trim(),
      backend_source_ip: app.$('siteTransparent').checked ? '' : app.el.siteBackendSourceIP.value,
      backend_http_port: httpPort,
      backend_https_port: httpsPort,
      tag: app.$('siteTag').value,
      transparent: app.$('siteTransparent').checked
    };

    let valid = true;
    if (!app.validateRequiredField(app.$('siteDomain'))) valid = false;
    if (!app.validateIPField(app.$('siteBackendIP'))) valid = false;
    if (!app.validateOptionalPortField(app.$('siteBackendHTTP'), true)) valid = false;
    if (!app.validateOptionalPortField(app.$('siteBackendHTTPS'), true)) valid = false;
    if (!valid || !site.domain || !site.backend_ip) {
      app.notify('error', app.t('validation.reviewErrors'));
      app.focusFirstError(app.el.siteForm);
      return;
    }

    const warning = app.updateSiteTransparentWarning();
    if (!(await app.confirmTransparentWarning(warning))) return;

    const editing = parseInt(app.el.editSiteId.value || '0', 10);
    await app.withFormBusy(
      'site',
      app.el.siteSubmitBtn,
      app.el.siteCancelBtn,
      app.t('common.saving'),
      async () => {
        try {
          if (editing > 0) {
            site.id = editing;
            await app.apiCall('PUT', '/api/sites', site);
            app.notify('success', app.t('toast.saved', { item: app.t('noun.site') }));
          } else {
            await app.apiCall('POST', '/api/sites', site);
            app.notify('success', app.t('toast.created', { item: app.t('noun.site') }));
          }
          app.exitSiteEditMode();
          app.loadSites();
        } catch (err) {
          if (err.message !== 'unauthorized') {
            if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
              app.applySiteValidationIssues(err.payload.issues);
              return;
            }
            app.notify('error', app.t('errors.actionFailed', {
              action: app.t(editing > 0 ? 'action.update' : 'action.add'),
              message: err.message
            }));
          }
        }
      },
      app.syncSiteFormState
    );
  });

  app.el.rangeForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    app.clearFormErrors(app.el.rangeForm);
    const startPort = parseInt(app.$('rangeStartPort').value, 10);
    const endPort = parseInt(app.$('rangeEndPort').value, 10);
    const outIP = app.$('rangeOutIP').value.trim();
    const inIPVal = app.el.rangeInIP.value;

    let valid = true;
    if (!app.validateRequiredField(app.el.rangeInIP)) valid = false;
    if (!app.validatePortField(app.$('rangeStartPort'))) valid = false;
    if (!app.validatePortField(app.$('rangeEndPort'))) valid = false;
    if (!app.validateIPField(app.$('rangeOutIP'))) valid = false;
    if (!app.validateOptionalPortField(app.$('rangeOutStartPort'))) valid = false;
    if (!valid || !inIPVal || !startPort || !endPort || !outIP) {
      app.notify('error', app.t('validation.reviewErrors'));
      app.focusFirstError(app.el.rangeForm);
      return;
    }
    if (startPort > endPort) {
      app.notify('error', app.t('validation.rangeOrder'));
      app.setFieldError(app.$('rangeEndPort'), app.t('validation.rangeOrder'));
      app.focusFirstError(app.el.rangeForm);
      return;
    }

    const range = {
      in_interface: app.getInterfaceSubmissionValue(app.el.rangeInInterface, app.el.rangeInInterfacePicker),
      in_ip: inIPVal,
      start_port: startPort,
      end_port: endPort,
      out_interface: app.getInterfaceSubmissionValue(app.el.rangeOutInterface, app.el.rangeOutInterfacePicker),
      out_ip: outIP,
      out_source_ip: app.$('rangeTransparent').checked ? '' : app.el.rangeOutSourceIP.value,
      out_start_port: parseInt(app.$('rangeOutStartPort').value, 10) || 0,
      protocol: app.$('rangeProtocol').value,
      remark: app.$('rangeRemark').value.trim(),
      tag: app.$('rangeTag').value,
      transparent: app.$('rangeTransparent').checked
    };

    const warning = app.updateRangeTransparentWarning();
    if (!(await app.confirmTransparentWarning(warning))) return;

    const editing = parseInt(app.el.editRangeId.value || '0', 10);
    await app.withFormBusy(
      'range',
      app.el.rangeSubmitBtn,
      app.el.rangeCancelBtn,
      app.t('common.saving'),
      async () => {
        try {
          if (editing > 0) {
            range.id = editing;
            await app.apiCall('PUT', '/api/ranges', range);
            app.notify('success', app.t('toast.saved', { item: app.t('noun.range') }));
          } else {
            await app.apiCall('POST', '/api/ranges', range);
            app.notify('success', app.t('toast.created', { item: app.t('noun.range') }));
          }
          app.exitRangeEditMode();
          app.loadRanges();
        } catch (err) {
          if (err.message !== 'unauthorized') {
            if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
              app.applyRangeValidationIssues(err.payload.issues);
              return;
            }
            app.notify('error', app.t('errors.actionFailed', {
              action: app.t(editing > 0 ? 'action.update' : 'action.add'),
              message: err.message
            }));
          }
        }
      },
      app.syncRangeFormState
    );
  });

  if (app.el.managedNetworkForm) {
    app.el.managedNetworkForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      app.clearFormErrors(app.el.managedNetworkForm);

      const item = app.buildManagedNetworkFromForm();
      const valid = typeof app.validateManagedNetworkFormFields === 'function'
        ? app.validateManagedNetworkFormFields(item)
        : true;

      if (!valid || !item.name || !item.bridge) {
        app.notify('error', app.t('validation.reviewErrors'));
        app.focusFirstError(app.el.managedNetworkForm);
        return;
      }

      const editing = parseInt(app.el.editManagedNetworkId.value || '0', 10);
      await app.withFormBusy(
        'managedNetwork',
        app.el.managedNetworkSubmitBtn,
        app.el.managedNetworkCancelBtn,
        app.t('common.saving'),
        async () => {
          try {
            const current = editing > 0
              ? (app.state.managedNetworks.data || []).find((entry) => entry.id === editing)
              : null;
            const payload = Object.assign({}, item, {
              enabled: current ? current.enabled !== false : true
            });

            if (editing > 0) {
              payload.id = editing;
              await app.apiCall('PUT', '/api/managed-networks', payload);
              app.notify('success', app.t('toast.saved', { item: app.t('noun.managedNetwork') }));
            } else {
              await app.apiCall('POST', '/api/managed-networks', payload);
              app.notify('success', app.t('toast.created', { item: app.t('noun.managedNetwork') }));
            }
            app.exitManagedNetworkEditMode();
            if (typeof app.loadHostNetwork === 'function') await app.loadHostNetwork();
            await app.loadManagedNetworks();
          } catch (err) {
            if (err.message !== 'unauthorized') {
              if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
                app.applyManagedNetworkValidationIssues(err.payload.issues);
                return;
              }
              app.notify('error', app.t('errors.actionFailed', {
                action: app.t(editing > 0 ? 'action.update' : 'action.add'),
                message: app.translateValidationMessage(err.message)
              }));
            }
          }
        },
        app.syncManagedNetworkFormState
      );
    });
  }

  if (app.el.managedNetworkReservationForm) {
    app.el.managedNetworkReservationForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      app.clearFormErrors(app.el.managedNetworkReservationForm);

      const item = app.buildManagedNetworkReservationFromForm();
      const valid = typeof app.validateManagedNetworkReservationFormFields === 'function'
        ? app.validateManagedNetworkReservationFormFields(item)
        : true;

      if (!valid || !item.managed_network_id || !item.mac_address || !item.ipv4_address) {
        app.notify('error', app.t('validation.reviewErrors'));
        app.focusFirstError(app.el.managedNetworkReservationForm);
        return;
      }

      const editing = parseInt(app.el.editManagedNetworkReservationId.value || '0', 10);
      await app.withFormBusy(
        'managedNetworkReservation',
        app.el.managedNetworkReservationSubmitBtn,
        app.el.managedNetworkReservationCancelBtn,
        app.t('common.saving'),
        async () => {
          try {
            if (editing > 0) {
              await app.apiCall('PUT', '/api/managed-network-reservations', Object.assign({ id: editing }, item));
              app.notify('success', app.t('toast.saved', { item: app.t('noun.managedNetworkReservation') }));
            } else {
              await app.apiCall('POST', '/api/managed-network-reservations', item);
              app.notify('success', app.t('toast.created', { item: app.t('noun.managedNetworkReservation') }));
            }
            app.exitManagedNetworkReservationEditMode();
            await Promise.all([
              typeof app.loadManagedNetworks === 'function' ? app.loadManagedNetworks() : Promise.resolve(),
              typeof app.loadManagedNetworkReservations === 'function' ? app.loadManagedNetworkReservations() : Promise.resolve()
            ]);
          } catch (err) {
            if (err.message !== 'unauthorized') {
              if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
                app.applyManagedNetworkReservationValidationIssues(err.payload.issues);
                return;
              }
              app.notify('error', app.t('errors.actionFailed', {
                action: app.t(editing > 0 ? 'action.update' : 'action.add'),
                message: app.translateValidationMessage(err.message)
              }));
            }
          }
        },
        app.syncManagedNetworkReservationFormState
      );
    });
  }

  if (app.el.egressNATForm) {
    app.el.egressNATForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      app.clearFormErrors(app.el.egressNATForm);

      const item = app.buildEgressNATFromForm();
      let valid = true;
      if (!app.validateRequiredField(app.el.egressNATParentPicker || app.el.egressNATParentInterface)) valid = false;
      if (!app.validateRequiredField(app.el.egressNATOutPicker || app.el.egressNATOutInterface)) valid = false;
      if (!item.protocol) {
        app.setFieldError(app.el.egressNATProtocolTrigger || app.el.egressNATProtocol, app.t('validation.egressNATProtocol'));
        valid = false;
      } else if (app.el.egressNATProtocolTrigger || app.el.egressNATProtocol) {
        app.clearFieldError(app.el.egressNATProtocolTrigger || app.el.egressNATProtocol);
      }

      if (item.out_source_ip) {
        if (!app.parseIPv4(item.out_source_ip)) {
          app.setFieldError(app.el.egressNATOutSourceIP, app.t('validation.ipv4'));
          valid = false;
        } else {
          app.clearFieldError(app.el.egressNATOutSourceIP);
        }
      }

      if (!valid || !item.parent_interface || !item.out_interface) {
        app.notify('error', app.t('validation.reviewErrors'));
        app.focusFirstError(app.el.egressNATForm);
        return;
      }

      if (item.child_interface && item.child_interface === item.out_interface) {
        app.setFieldError(app.el.egressNATChildPicker || app.el.egressNATChildInterface, app.t('validation.childInterfaceDifferent'));
        app.setFieldError(app.el.egressNATOutPicker || app.el.egressNATOutInterface, app.t('validation.childInterfaceDifferent'));
        app.notify('error', app.t('validation.childInterfaceDifferent'));
        app.focusFirstError(app.el.egressNATForm);
        return;
      }
      if (typeof app.isEgressNATSingleTargetInterfaceName === 'function' &&
        app.isEgressNATSingleTargetInterfaceName(item.parent_interface) &&
        item.parent_interface === item.out_interface) {
        app.setFieldError(app.el.egressNATParentPicker || app.el.egressNATParentInterface, app.t('validation.egressNATSingleTargetOutConflict'));
        app.setFieldError(app.el.egressNATOutPicker || app.el.egressNATOutInterface, app.t('validation.egressNATSingleTargetOutConflict'));
        app.notify('error', app.t('validation.egressNATSingleTargetOutConflict'));
        app.focusFirstError(app.el.egressNATForm);
        return;
      }

      const editing = parseInt(app.el.editEgressNATId.value || '0', 10);
      await app.withFormBusy(
        'egressNAT',
        app.el.egressNATSubmitBtn,
        app.el.egressNATCancelBtn,
        app.t('common.saving'),
        async () => {
          try {
            if (editing > 0) {
              await app.apiCall('PUT', '/api/egress-nats', Object.assign({ id: editing }, item));
              app.notify('success', app.t('toast.saved', { item: app.t('noun.egressNAT') }));
            } else {
              await app.apiCall('POST', '/api/egress-nats', item);
              app.notify('success', app.t('toast.created', { item: app.t('noun.egressNAT') }));
            }
            app.exitEgressNATEditMode();
            await app.loadEgressNATs();
          } catch (err) {
            if (err.message !== 'unauthorized') {
              if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
                app.applyEgressNATValidationIssues(err.payload.issues);
                return;
              }
              app.notify('error', app.t('errors.actionFailed', {
                action: app.t(editing > 0 ? 'action.update' : 'action.add'),
                message: app.translateValidationMessage(err.message)
              }));
            }
          }
        },
        app.syncEgressNATFormState
      );
    });
  }

  if (app.el.ipv6AssignmentForm) {
    app.el.ipv6AssignmentForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      app.clearFormErrors(app.el.ipv6AssignmentForm);

      const item = app.buildIPv6AssignmentFromForm();
      let valid = true;
      if (!app.validateRequiredField(app.el.ipv6ParentPicker || app.el.ipv6ParentInterface)) valid = false;
      if (!app.validateRequiredField(app.el.ipv6ParentPrefix)) valid = false;
      if (!app.validateRequiredField(app.el.ipv6TargetPicker || app.el.ipv6TargetInterface)) valid = false;
      if (!app.validateRequiredField(app.el.ipv6AssignedPrefix)) valid = false;
      if (valid && typeof app.validateIPv6PrefixField === 'function' && !app.validateIPv6PrefixField(app.el.ipv6AssignedPrefix)) valid = false;

      if (!valid || !item.parent_interface || !item.parent_prefix || !item.target_interface || !item.assigned_prefix) {
        app.notify('error', app.t('validation.reviewErrors'));
        app.focusFirstError(app.el.ipv6AssignmentForm);
        return;
      }

      const editing = parseInt(app.el.editIPv6AssignmentId.value || '0', 10);
      await app.withFormBusy(
        'ipv6Assignment',
        app.el.ipv6AssignmentSubmitBtn,
        app.el.ipv6AssignmentCancelBtn,
        app.t('common.saving'),
        async () => {
          try {
            const current = editing > 0
              ? (app.state.ipv6Assignments.data || []).find((entry) => entry.id === editing)
              : null;
            const payload = {
              parent_interface: item.parent_interface,
              target_interface: item.target_interface,
              parent_prefix: item.parent_prefix,
              assigned_prefix: item.assigned_prefix,
              remark: item.remark || '',
              enabled: current ? current.enabled !== false : true
            };

            if (editing > 0) {
              payload.id = editing;
              await app.apiCall('PUT', '/api/ipv6-assignments', payload);
              app.notify('success', app.t('toast.saved', { item: app.t('noun.ipv6Assignment') }));
            } else {
              await app.apiCall('POST', '/api/ipv6-assignments', payload);
              app.notify('success', app.t('toast.created', { item: app.t('noun.ipv6Assignment') }));
            }
            app.exitIPv6AssignmentEditMode();
            await app.loadIPv6Assignments();
          } catch (err) {
            if (err.message !== 'unauthorized') {
              if (err.payload && Array.isArray(err.payload.issues) && err.payload.issues.length > 0) {
                app.applyIPv6AssignmentValidationIssues(err.payload.issues);
                return;
              }
              app.notify('error', app.t('errors.actionFailed', {
                action: app.t(editing > 0 ? 'action.update' : 'action.add'),
                message: app.translateValidationMessage(err.message)
              }));
            }
          }
        },
        app.syncIPv6AssignmentFormState
      );
    });
  }

  app.init = function init() {
    if (!app.getToken()) {
      app.showTokenModal();
      return;
    }

    app.hideTokenModal();
    app.setRuleFormAdd();
    app.setSiteFormAdd();
    app.setRangeFormAdd();
    if (typeof app.setManagedNetworkFormAdd === 'function') app.setManagedNetworkFormAdd();
    if (typeof app.setManagedNetworkReservationFormAdd === 'function') app.setManagedNetworkReservationFormAdd();
    if (typeof app.setEgressNATFormAdd === 'function') app.setEgressNATFormAdd();
    if (typeof app.setIPv6AssignmentFormAdd === 'function') app.setIPv6AssignmentFormAdd();
    app.activateTab(app.state.activeTab, { persist: false, skipLoad: true });

    app.refreshDashboard({
      includeMeta: true,
      includeWorkers: true,
      includeStats: app.state.activeTab === 'rule-stats'
    });

    app.startPolling();
  };

  app.refreshLocalizedUI();
  app.init();
})();
