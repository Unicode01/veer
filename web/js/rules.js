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
    app.updateRuleTransparentWarning();
  };

  app.getRuleSortValue = function getRuleSortValue(rule, key) {
    if (key === 'status') {
      if (!rule.enabled) return 3;
      if (rule.status === 'running') return 0;
      if (rule.status === 'error') return 1;
      return 2;
    }
    if (key === 'transparent') return rule.transparent ? 1 : 0;
    return rule[key];
  };

  app.renderRulesTable = function renderRulesTable() {
    const el = app.el;
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
        rule.out_port,
        rule.protocol,
        app.statusInfo(rule.status, rule.enabled).text
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getRuleSortValue);
    const list = app.paginateList(st, filteredList).items;

    el.rulesBody.innerHTML = '';
    app.updateSortIndicators('rulesTable', st);
    app.renderFilterMeta('rules', filteredList.length, st.data.length);
    app.renderPagination('rules', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noRules, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('rule.list.empty'),
        actionButton: app.el.emptyAddRuleBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('rulesTable', false);
      return;
    }

    app.hideEmptyState(el.noRules);
    app.toggleTableVisibility('rulesTable', true);

    list.forEach((rule) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('rule', rule.id);
      const info = app.statusInfo(rule.status, rule.enabled);
      const remark = rule.remark
        ? '<span title="' + app.esc(rule.remark) + '">' + app.esc(rule.remark) + '</span>'
        : app.emptyCellHTML();
      const tag = rule.tag
        ? '<span class="tag-badge' + (st.filterTag === rule.tag ? ' tag-active' : '') + '" data-table="rules" data-tag="' + app.esc(rule.tag) + '">' + app.esc(rule.tag) + '</span>'
        : app.emptyCellHTML();
      const toggleClass = rule.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(rule.enabled ? 'common.disable' : 'common.enable');
      const disabledAttr = pending ? ' disabled aria-disabled="true"' : '';
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.innerHTML =
        '<td>' + rule.id + '</td>' +
        '<td>' + remark + '</td>' +
        '<td>' + tag + '</td>' +
        '<td>' + (rule.in_interface ? app.esc(rule.in_interface) : app.emptyCellHTML()) + '</td>' +
        '<td>' + app.esc(rule.in_ip) + '</td>' +
        '<td>' + rule.in_port + '</td>' +
        '<td>' + (rule.out_interface ? app.esc(rule.out_interface) : app.emptyCellHTML()) + '</td>' +
        '<td>' + app.esc(rule.out_ip) + '</td>' +
        '<td>' + rule.out_port + '</td>' +
        '<td>' + app.esc(String(rule.protocol || '').toUpperCase()) + '</td>' +
        '<td>' + (rule.transparent ? '<span class="badge badge-running">' + app.t('common.yes') + '</span>' : app.emptyCellHTML()) + '</td>' +
        '<td><span class="badge badge-' + info.badge + '">' + info.text + '</span></td>' +
        '<td class="cell-actions"><div class="action-dropdown">' +
        '<button class="action-dropdown-trigger" aria-expanded="false"' + disabledAttr + '>' + app.t('common.actions') + ' &#9662;</button>' +
        '<div class="action-dropdown-menu">' +
        '<button class="' + toggleClass + '" data-id="' + rule.id + '" data-type="rule"' + disabledAttr + '>' + toggleText + '</button>' +
        '<button class="btn-edit" data-rule="' + app.encData(rule) + '"' + disabledAttr + '>' + app.t('common.edit') + '</button>' +
        '<button class="btn-clone" data-rule="' + app.encData(rule) + '"' + disabledAttr + '>' + app.t('common.clone') + '</button>' +
        '<button class="btn-delete" data-id="' + rule.id + '" data-type="rule"' + disabledAttr + '>' + app.t('common.delete') + '</button>' +
        '</div></div></td>';

      el.rulesBody.appendChild(tr);
    });

    app.renderOverview();
  };

  app.loadRules = async function loadRules() {
    try {
      app.state.rules.data = await app.apiCall('GET', '/api/rules');
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
      if (app.el.editRuleId.value === String(id)) app.exitRuleEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.rule') }));
      app.loadRules();
    } catch (e) {
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.deleteFailed', { message: e.message }));
    } finally {
      app.setRowPending('rule', id, false);
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
      out_port: parseInt(app.$('outPort').value, 10),
      protocol: app.$('protocol').value,
      remark: app.$('ruleRemark').value.trim(),
      tag: app.$('ruleTag').value,
      transparent: app.$('ruleTransparent').checked
    };
  };
})();
