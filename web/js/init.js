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

  app.startPolling = function startPolling() {
    app.stopPolling();
    if (!app.getToken() || document.hidden) return;

    app.state.pollerId = setInterval(() => {
      if (document.hidden) return;
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
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.operationFailed', { message: e.message }));
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

  app.el.inInterface.addEventListener('change', () => app.populateIPSelect(app.el.inInterface, app.el.inIP));
  app.el.rangeInInterface.addEventListener('change', () => app.populateIPSelect(app.el.rangeInInterface, app.el.rangeInIP));
  app.el.siteListenIface.addEventListener('change', () => {
    app.populateSiteListenIP(app.el.siteListenIface, app.el.siteListenIP);
    app.updateSiteTransparentWarning();
  });

  app.el.outInterface.addEventListener('change', app.updateRuleTransparentWarning);
  app.el.rangeOutInterface.addEventListener('change', app.updateRangeTransparentWarning);
  app.el.ruleTransparent.addEventListener('change', app.updateRuleTransparentWarning);
  app.el.siteTransparent.addEventListener('change', app.updateSiteTransparentWarning);
  app.el.rangeTransparent.addEventListener('change', app.updateRangeTransparentWarning);
  app.el.ruleOutIP.addEventListener('input', app.updateRuleTransparentWarning);
  app.el.siteBackendIP.addEventListener('input', app.updateSiteTransparentWarning);
  app.el.rangeOutIP.addEventListener('input', app.updateRangeTransparentWarning);

  app.el.ruleCancelBtn.addEventListener('click', app.exitRuleEditMode);
  app.el.siteCancelBtn.addEventListener('click', app.exitSiteEditMode);
  app.el.rangeCancelBtn.addEventListener('click', app.exitRangeEditMode);

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
    const ruleSelect = e.target.closest('.rule-select-checkbox[data-id]');
    if (!ruleSelect) return;
    app.setRuleSelected(parseInt(ruleSelect.dataset.id, 10), ruleSelect.checked);
    app.renderRulesTable();
  });

  document.addEventListener('click', (e) => {
    const trigger = e.target.closest('.action-dropdown-trigger');
    if (trigger) {
      e.stopPropagation();
      const dropdown = trigger.closest('.action-dropdown');
      const wasOpen = dropdown.classList.contains('open');
      app.closeDropdowns();
      if (!wasOpen) {
        dropdown.classList.add('open');
        trigger.setAttribute('aria-expanded', 'true');
      }
      return;
    }

    const menuItem = e.target.closest('.action-dropdown-menu button');
    if (menuItem) {
      const dropdown = menuItem.closest('.action-dropdown');
      if (dropdown) {
        dropdown.classList.remove('open');
        const triggerButton = dropdown.querySelector('.action-dropdown-trigger');
        if (triggerButton) triggerButton.setAttribute('aria-expanded', 'false');
      }
    } else {
      app.closeDropdowns();
    }

    const th = e.target.closest('th.sortable');
    if (th) {
      const table = th.dataset.table;
      const key = th.dataset.sort;
      if (table && key && app.state[table]) {
        app.toggleSort(app.state[table], key);
        if (table === 'rules') app.renderRulesTable();
        else if (table === 'sites') app.renderSitesTable();
        else if (table === 'ranges') app.renderRangesTable();
        else if (table === 'workers') app.renderWorkersTable();
        else if (table === 'ruleStats') app.renderRuleStatsTable();
        else if (table === 'siteStats') app.renderSiteStatsTable();
        else if (table === 'rangeStats') app.renderRangeStatsTable();
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
    }
  });

  app.el.ruleForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    app.clearFormErrors(app.el.ruleForm);
    const rule = app.buildRuleFromForm();
    let valid = true;
    if (!app.validateRequiredField(app.el.inIP)) valid = false;
    if (!app.validatePortField(app.$('inPort'))) valid = false;
    if (!app.validateIPv4Field(app.$('outIP'))) valid = false;
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
      listen_interface: app.el.siteListenIface.value,
      backend_ip: app.$('siteBackendIP').value.trim(),
      backend_http_port: httpPort,
      backend_https_port: httpsPort,
      tag: app.$('siteTag').value,
      transparent: app.$('siteTransparent').checked
    };

    let valid = true;
    if (!app.validateRequiredField(app.$('siteDomain'))) valid = false;
    if (!app.validateIPv4Field(app.$('siteBackendIP'))) valid = false;
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
    if (!app.validateIPv4Field(app.$('rangeOutIP'))) valid = false;
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
      in_interface: app.el.rangeInInterface.value,
      in_ip: inIPVal,
      start_port: startPort,
      end_port: endPort,
      out_interface: app.el.rangeOutInterface.value,
      out_ip: outIP,
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

  app.init = function init() {
    if (!app.getToken()) {
      app.showTokenModal();
      return;
    }

    app.hideTokenModal();
    app.setRuleFormAdd();
    app.setSiteFormAdd();
    app.setRangeFormAdd();
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
