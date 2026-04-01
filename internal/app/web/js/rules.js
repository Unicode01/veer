(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.syncRuleFormState = function syncRuleFormState() {
    const el = app.el;
    const formState = app.state.forms.rule;
    const pending = !!app.state.pendingForms.rule;

    if (formState.mode === 'edit' && el.editRuleId.value) {
      el.ruleFormTitle.textContent = app.t('rule.form.title.edit', { id: el.editRuleId.value });
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.edit');
      el.ruleCancelBtn.style.display = '';
    } else if (formState.mode === 'clone' && formState.sourceId) {
      el.ruleFormTitle.textContent = app.t('rule.form.title.clone', { id: formState.sourceId });
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.clone');
      el.ruleCancelBtn.style.display = '';
    } else {
      el.ruleFormTitle.textContent = app.t('rule.form.title.add');
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.add');
      el.ruleCancelBtn.style.display = 'none';
    }

    el.ruleCancelBtn.textContent = app.t('common.cancelEdit');
    el.ruleSubmitBtn.disabled = pending;
    el.ruleSubmitBtn.classList.toggle('is-busy', pending);
    el.ruleCancelBtn.disabled = pending;
  };

  app.setRuleFormAdd = function setRuleFormAdd() {
    app.state.forms.rule = { mode: 'add', sourceId: 0 };
    app.el.editRuleId.value = '';
    app.syncRuleFormState();
  };

  app.enterRuleEditMode = function enterRuleEditMode(rule) {
    const el = app.el;
    app.state.forms.rule = { mode: 'edit', sourceId: rule.id };
    el.editRuleId.value = rule.id;
    app.syncRuleFormState();

    app.$('ruleRemark').value = rule.remark || '';
    app.populateTagSelect(app.$('ruleTag'), rule.tag);
    app.populateInterfaceSelect(el.inInterface, rule.in_interface);
    app.populateIPSelect(el.inInterface, el.inIP, rule.in_ip);
    app.$('inPort').value = rule.in_port;
    app.populateInterfaceSelect(el.outInterface, rule.out_interface);
    app.populateSourceIPSelect(el.outInterface, el.ruleOutSourceIP, rule.out_source_ip, true);
    app.$('outIP').value = rule.out_ip;
    app.$('outPort').value = rule.out_port;
    app.$('protocol').value = rule.protocol;
    app.$('ruleTransparent').checked = !!rule.transparent;
    app.updateRuleTransparentWarning();
    el.ruleFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.enterRuleCloneMode = function enterRuleCloneMode(rule) {
    const el = app.el;
    app.state.forms.rule = { mode: 'clone', sourceId: rule.id };
    el.editRuleId.value = '';
    app.syncRuleFormState();

    app.$('ruleRemark').value = rule.remark || '';
    app.populateTagSelect(app.$('ruleTag'), rule.tag);
    app.populateInterfaceSelect(el.inInterface, rule.in_interface);
    app.populateIPSelect(el.inInterface, el.inIP, rule.in_ip);
    app.$('inPort').value = rule.in_port;
    app.populateInterfaceSelect(el.outInterface, rule.out_interface);
    app.populateSourceIPSelect(el.outInterface, el.ruleOutSourceIP, rule.out_source_ip, true);
    app.$('outIP').value = rule.out_ip;
    app.$('outPort').value = rule.out_port;
    app.$('protocol').value = rule.protocol;
    app.$('ruleTransparent').checked = !!rule.transparent;
    app.updateRuleTransparentWarning();
    el.ruleFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitRuleEditMode = function exitRuleEditMode() {
    app.setRuleFormAdd();
    app.el.ruleForm.reset();
    app.populateSourceIPSelect(app.el.outInterface, app.el.ruleOutSourceIP, '', false);
    app.updateRuleTransparentWarning();
  };

  app.getRuleSelection = function getRuleSelection() {
    if (!(app.state.rules.selectedIds instanceof Set)) {
      app.state.rules.selectedIds = new Set(app.state.rules.selectedIds || []);
    }
    return app.state.rules.selectedIds;
  };

  app.clearRuleSelection = function clearRuleSelection() {
    app.getRuleSelection().clear();
  };

  app.setRuleSelected = function setRuleSelected(id, selected) {
    const selection = app.getRuleSelection();
    if (selected) selection.add(id);
    else selection.delete(id);
  };

  app.pruneRuleSelection = function pruneRuleSelection() {
    const knownIds = new Set((app.state.rules.data || []).map((rule) => rule.id));
    app.getRuleSelection().forEach((id) => {
      if (!knownIds.has(id)) app.state.rules.selectedIds.delete(id);
    });
  };

  app.getRuleSortValue = function getRuleSortValue(rule, key) {
    if (key === 'status') {
      if (!rule.enabled) return 3;
      if (rule.status === 'running') return 0;
      if (rule.status === 'error') return 1;
      return 2;
    }
    if (key === 'transparent') return rule.transparent ? 1 : 0;
    if (key === 'effective_engine') return rule.effective_engine || 'userspace';
    return rule[key];
  };

  app.getRuleEngineInfo = function getRuleEngineInfo(rule) {
    const effective = (rule.effective_engine || 'userspace').toLowerCase();
    const kernelEngine = String(rule.effective_kernel_engine || '').toLowerCase();
    let badgeClass = 'badge-userspace';
    let badgeText = app.t('rule.engine.effective.' + effective);
    if (effective === 'kernel') {
      if (kernelEngine === 'xdp') {
        badgeClass = 'badge-xdp';
        badgeText = 'XDP';
      } else if (kernelEngine === 'tc') {
        badgeClass = 'badge-tc';
        badgeText = 'TC';
      } else if (kernelEngine === 'mixed') {
        badgeClass = 'badge-kernel';
        badgeText = 'MIXED';
      } else {
        badgeClass = 'badge-kernel';
      }
    }
    let hintKey = '';
    if (rule.fallback_reason) hintKey = 'rule.engine.hint.fallback';
    else if (effective === 'kernel') hintKey = 'rule.engine.hint.kernelActive';
    else if (!rule.kernel_eligible) hintKey = 'rule.engine.hint.userspaceOnly';

    const titleParts = [
      app.t('rule.engine.effectiveLabel') + ': ' + app.t('rule.engine.effective.' + effective)
    ];
    if (effective === 'kernel' && kernelEngine) titleParts.push('Kernel Engine: ' + kernelEngine.toUpperCase());
    if (rule.fallback_reason) titleParts.push(rule.fallback_reason);
    else if (rule.kernel_reason) titleParts.push(rule.kernel_reason);

    return {
      badgeClass: badgeClass,
      badgeText: badgeText,
      hintText: hintKey ? app.t(hintKey) : '',
      title: titleParts.join('\n')
    };
  };

  app.getFilteredRules = function getFilteredRules() {
    const st = app.state.rules;
    let filteredList = st.data.slice();
    if (st.filterTag) filteredList = filteredList.filter((rule) => rule.tag === st.filterTag);
    if (st.searchQuery) {
      filteredList = filteredList.filter((rule) => app.matchesSearch(st.searchQuery, [
        rule.id,
        rule.remark,
        rule.tag,
        rule.in_interface,
        rule.in_ip,
        rule.in_port,
        rule.out_interface,
        rule.out_ip,
        rule.out_source_ip,
        rule.out_port,
        rule.protocol,
        app.statusInfo(rule.status, rule.enabled).text
      ]));
    }
    return app.sortByState(filteredList, st, app.getRuleSortValue);
  };

  app.syncRulesSelectionState = function syncRulesSelectionState(pageItems) {
    const selectAll = app.el.rulesSelectAll;
    if (!selectAll) return;

    const st = app.state.rules;
    const selection = app.getRuleSelection();
    const selectableIds = (pageItems || [])
      .filter((rule) => !app.isRowPending('rule', rule.id))
      .map((rule) => rule.id);
    const selectedOnPage = selectableIds.filter((id) => selection.has(id)).length;

    selectAll.disabled = selectableIds.length === 0 || st.batchDeleting;
    selectAll.checked = selectableIds.length > 0 && selectedOnPage === selectableIds.length;
    selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < selectableIds.length;
  };

  app.renderRulesToolbar = function renderRulesToolbar(filteredList, pageItems) {
    const st = app.state.rules;
    const selection = app.getRuleSelection();
    const selectedCount = selection.size;

    if (app.el.rulesSelectAll) {
      app.el.rulesSelectAll.setAttribute('aria-label', app.t('rule.selection.selectAll'));
    }

    if (app.el.rulesSelectionMeta) {
      app.el.rulesSelectionMeta.hidden = selectedCount === 0;
      app.el.rulesSelectionMeta.textContent = selectedCount > 0
        ? app.t('rule.selection.summary', { count: selectedCount })
        : '';
    }

    if (app.el.batchDeleteRulesBtn) {
      app.el.batchDeleteRulesBtn.disabled = selectedCount === 0 || st.batchDeleting;
      app.el.batchDeleteRulesBtn.classList.toggle('is-busy', st.batchDeleting);
      app.el.batchDeleteRulesBtn.textContent = st.batchDeleting
        ? app.t('common.processing')
        : app.t('rule.batch.delete');
    }

    app.syncRulesSelectionState(pageItems);
  };

  app.getRuleFieldInput = function getRuleFieldInput(field) {
    const map = {
      id: app.el.editRuleId,
      in_interface: app.el.inInterface,
      in_ip: app.el.inIP,
      in_port: app.$('inPort'),
      out_interface: app.el.outInterface,
      out_ip: app.$('outIP'),
      out_source_ip: app.el.ruleOutSourceIP,
      out_port: app.$('outPort'),
      protocol: app.$('protocol')
    };
    return map[field] || null;
  };

  app.translateRuleValidationMessage = function translateRuleValidationMessage(message) {
    const text = String(message || '').trim();
    if (!text) return app.t('validation.reviewErrors');

    const known = {
      'is required': app.t('validation.required'),
      'must be greater than 0': app.t('validation.positiveId'),
      'must be a valid IPv4 address': app.t('validation.ipv4'),
      'must be a specific non-loopback IPv4 address': app.t('validation.sourceIPSpecific'),
      'must be omitted when transparent mode is enabled': app.t('validation.sourceIPTransparent'),
      'must be between 1 and 65535': app.t('validation.portRange'),
      'must be tcp, udp, or tcp+udp': app.t('validation.protocol'),
      'must be auto, userspace, or kernel': app.t('validation.enginePreference'),
      'interface does not exist on this host': app.t('validation.interfaceMissing'),
      'must be assigned to the selected outbound interface': app.t('validation.sourceIPOutboundInterface'),
      'must be assigned to a local interface': app.t('validation.sourceIPLocal'),
      'rule not found': app.t('validation.ruleNotFound')
    };
    if (known[text]) return known[text];
    if (text.indexOf('listener conflicts with ') === 0) {
      return app.t('validation.listenerConflict', { detail: text.slice('listener conflicts with '.length) });
    }
    return text;
  };

  app.applyRuleValidationIssues = function applyRuleValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const input = app.getRuleFieldInput(issue.field);
      if (!input) return;
      if (!firstInvalid) firstInvalid = input;
      if (!input.hasAttribute('aria-invalid')) {
        app.setFieldError(input, app.translateRuleValidationMessage(issue.message));
      }
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.translateRuleValidationMessage(relevant[0].message));
  };

  app.validateRuleDraft = async function validateRuleDraft(rule, editing) {
    const payload = {
      create: editing ? [] : [rule],
      update: editing ? [rule] : [],
      delete_ids: [],
      set_enabled: []
    };
    const resp = await app.apiCall('POST', '/api/rules/validate', payload);
    if (!resp || !resp.valid) {
      app.applyRuleValidationIssues(resp && resp.issues);
      return null;
    }
    return editing
      ? ((resp.update && resp.update[0]) || rule)
      : ((resp.create && resp.create[0]) || rule);
  };

  app.renderRulesTable = function renderRulesTable() {
    const el = app.el;
    const st = app.state.rules;
    app.closeDropdowns();
    if (st.sortKey === 'effective_engine') {
      st.sortKey = '';
      st.sortAsc = true;
    }
    const filteredList = app.getFilteredRules();
    const pageInfo = app.paginateList(st, filteredList);
    const list = pageInfo.items;
    const selection = app.getRuleSelection();

    app.clearNode(el.rulesBody);
    app.updateSortIndicators('rulesTable', st);
    app.renderFilterMeta('rules', filteredList.length, st.data.length);
    app.renderRulesToolbar(filteredList, list);
    app.renderPagination('rules', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noRules, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('rule.list.empty'),
        actionButton: app.el.emptyAddRuleBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('rulesTable', false);
      app.renderOverview();
      return;
    }

    app.hideEmptyState(el.noRules);
    app.toggleTableVisibility('rulesTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((rule) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('rule', rule.id);
      const info = app.statusInfo(rule.status, rule.enabled);
      const toggleClass = rule.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(rule.enabled ? 'common.disable' : 'common.enable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      const checkbox = app.createNode('input', {
        className: 'rule-select-checkbox',
        attrs: {
          type: 'checkbox',
          'aria-label': app.t('rule.selection.toggle', { id: rule.id })
        },
        dataset: {
          id: rule.id
        }
      });
      checkbox.checked = selection.has(rule.id);
      if (pending || st.batchDeleting) {
        checkbox.disabled = true;
        checkbox.setAttribute('aria-disabled', 'true');
      }

      tr.appendChild(app.createCell(checkbox, 'cell-select'));
      tr.appendChild(app.createCell(String(rule.id)));
      tr.appendChild(app.createCell(rule.remark
        ? app.createNode('span', { text: rule.remark, title: rule.remark })
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createTagBadgeNode('rules', rule.tag, st.filterTag === rule.tag)));
      tr.appendChild(app.createCell(rule.in_interface ? rule.in_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(rule.in_ip));
      tr.appendChild(app.createCell(String(rule.in_port)));
      tr.appendChild(app.createCell(rule.out_interface ? rule.out_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createEndpointNode(rule.out_ip, rule.out_source_ip)));
      tr.appendChild(app.createCell(String(rule.out_port)));
      tr.appendChild(app.createCell(String(rule.protocol || '').toUpperCase()));
      tr.appendChild(app.createCell(rule.transparent
        ? app.createBadgeNode('badge-running', app.t('common.yes'))
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createStatusBadgeNode(info)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: toggleClass,
          text: toggleText,
          dataset: { id: rule.id, type: 'rule' },
          disabled: pending
        },
        {
          className: 'btn-edit',
          text: app.t('common.edit'),
          dataset: { rule: app.encData(rule) },
          disabled: pending
        },
        {
          className: 'btn-clone',
          text: app.t('common.clone'),
          dataset: { rule: app.encData(rule) },
          disabled: pending
        },
        {
          className: 'btn-delete',
          text: app.t('common.delete'),
          dataset: { id: rule.id, type: 'rule' },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.rulesBody.appendChild(fragment);

    app.renderOverview();
  };

  app.loadRules = async function loadRules() {
    try {
      app.state.rules.data = await app.apiCall('GET', '/api/rules');
      app.pruneRuleSelection();
      app.markDataFresh();
      app.renderRulesTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load rules:', e);
    }
  };

  app.deleteRule = async function deleteRule(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('rule.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('rule', id, true);
    app.renderRulesTable();
    try {
      await app.apiCall('DELETE', '/api/rules?id=' + id);
      app.getRuleSelection().delete(id);
      if (app.el.editRuleId.value === String(id)) app.exitRuleEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.rule') }));
      await app.loadRules();
    } catch (e) {
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.deleteFailed', { message: e.message }));
    } finally {
      app.setRowPending('rule', id, false);
      app.renderRulesTable();
    }
  };

  app.deleteSelectedRules = async function deleteSelectedRules(ids) {
    const st = app.state.rules;
    if (st.batchDeleting) return;

    const targetIds = Array.from(new Set((ids || Array.from(app.getRuleSelection()))
      .map((value) => parseInt(value, 10))
      .filter((value) => !Number.isNaN(value) && value > 0)));
    if (!targetIds.length) return;

    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('rule.batch.delete.confirm', { count: targetIds.length }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    st.batchDeleting = true;
    targetIds.forEach((id) => app.setRowPending('rule', id, true));
    app.renderRulesTable();

    try {
      await app.apiCall('POST', '/api/rules/batch', {
        create: [],
        update: [],
        delete_ids: targetIds,
        set_enabled: []
      });
      targetIds.forEach((id) => app.getRuleSelection().delete(id));
      if (targetIds.indexOf(parseInt(app.el.editRuleId.value || '0', 10)) >= 0) app.exitRuleEditMode();
      app.notify('success', app.t('rule.batch.delete.success', { count: targetIds.length }));
      await app.loadRules();
    } catch (e) {
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.deleteFailed', { message: e.message }));
    } finally {
      st.batchDeleting = false;
      targetIds.forEach((id) => app.setRowPending('rule', id, false));
      app.renderRulesTable();
    }
  };

  app.buildRuleFromForm = function buildRuleFromForm() {
    const el = app.el;
    return {
      in_interface: el.inInterface.value,
      in_ip: el.inIP.value,
      in_port: parseInt(app.$('inPort').value, 10),
      out_interface: el.outInterface.value,
      out_ip: app.$('outIP').value.trim(),
      out_source_ip: app.$('ruleTransparent').checked ? '' : el.ruleOutSourceIP.value,
      out_port: parseInt(app.$('outPort').value, 10),
      protocol: app.$('protocol').value,
      remark: app.$('ruleRemark').value.trim(),
      tag: app.$('ruleTag').value,
      transparent: app.$('ruleTransparent').checked
    };
  };
})();
