(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.syncRangeFormState = function syncRangeFormState() {
    const el = app.el;
    const formState = app.state.forms.range;
    const pending = !!app.state.pendingForms.range;

    if (formState.mode === 'edit' && el.editRangeId.value) {
      el.rangeFormTitle.textContent = app.t('range.form.title.edit', { id: el.editRangeId.value });
      el.rangeSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('range.form.submit.edit');
      el.rangeCancelBtn.style.display = '';
    } else if (formState.mode === 'clone' && formState.sourceId) {
      el.rangeFormTitle.textContent = app.t('range.form.title.clone', { id: formState.sourceId });
      el.rangeSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('range.form.submit.clone');
      el.rangeCancelBtn.style.display = '';
    } else {
      el.rangeFormTitle.textContent = app.t('range.form.title.add');
      el.rangeSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('range.form.submit.add');
      el.rangeCancelBtn.style.display = 'none';
    }

    el.rangeCancelBtn.textContent = app.t('common.cancelEdit');
    el.rangeSubmitBtn.disabled = pending;
    el.rangeSubmitBtn.classList.toggle('is-busy', pending);
    el.rangeCancelBtn.disabled = pending;
  };

  app.setRangeFormAdd = function setRangeFormAdd() {
    app.state.forms.range = { mode: 'add', sourceId: 0 };
    app.el.editRangeId.value = '';
    app.syncRangeFormState();
  };

  app.enterRangeEditMode = function enterRangeEditMode(range) {
    const el = app.el;
    app.state.forms.range = { mode: 'edit', sourceId: range.id };
    el.editRangeId.value = range.id;
    app.syncRangeFormState();

    app.$('rangeRemark').value = range.remark || '';
    app.populateTagSelect(app.$('rangeTag'), range.tag);
    app.populateInterfaceSelect(el.rangeInInterface, range.in_interface);
    app.populateIPSelect(el.rangeInInterface, el.rangeInIP, range.in_ip);
    app.$('rangeStartPort').value = range.start_port;
    app.$('rangeEndPort').value = range.end_port;
    app.populateInterfaceSelect(el.rangeOutInterface, range.out_interface);
    app.$('rangeOutIP').value = range.out_ip;
    app.$('rangeOutStartPort').value = range.out_start_port || '';
    app.$('rangeProtocol').value = range.protocol;
    app.$('rangeTransparent').checked = !!range.transparent;
    app.updateRangeTransparentWarning();
    el.rangeFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.enterRangeCloneMode = function enterRangeCloneMode(range) {
    const el = app.el;
    app.state.forms.range = { mode: 'clone', sourceId: range.id };
    el.editRangeId.value = '';
    app.syncRangeFormState();

    app.$('rangeRemark').value = range.remark || '';
    app.populateTagSelect(app.$('rangeTag'), range.tag);
    app.populateInterfaceSelect(el.rangeInInterface, range.in_interface);
    app.populateIPSelect(el.rangeInInterface, el.rangeInIP, range.in_ip);
    app.$('rangeStartPort').value = range.start_port;
    app.$('rangeEndPort').value = range.end_port;
    app.populateInterfaceSelect(el.rangeOutInterface, range.out_interface);
    app.$('rangeOutIP').value = range.out_ip;
    app.$('rangeOutStartPort').value = range.out_start_port || '';
    app.$('rangeProtocol').value = range.protocol;
    app.$('rangeTransparent').checked = !!range.transparent;
    app.updateRangeTransparentWarning();
    el.rangeFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitRangeEditMode = function exitRangeEditMode() {
    app.setRangeFormAdd();
    app.el.rangeForm.reset();
    app.updateRangeTransparentWarning();
  };

  app.getRangeSortValue = function getRangeSortValue(range, key) {
    if (key === 'status') {
      if (!range.enabled) return 3;
      if (range.status === 'running') return 0;
      if (range.status === 'error') return 1;
      return 2;
    }
    if (key === 'transparent') return range.transparent ? 1 : 0;
    return range[key];
  };

  app.renderRangesTable = function renderRangesTable() {
    const el = app.el;
    const st = app.state.ranges;
    app.closeDropdowns();
    let filteredList = st.data.slice();
    if (st.filterTag) filteredList = filteredList.filter((range) => range.tag === st.filterTag);
    if (st.searchQuery) {
      filteredList = filteredList.filter((range) => app.matchesSearch(st.searchQuery, [
        range.id,
        range.remark,
        range.tag,
        range.in_interface,
        range.in_ip,
        range.start_port,
        range.end_port,
        range.out_interface,
        range.out_ip,
        range.out_start_port,
        range.protocol,
        app.statusInfo(range.status, range.enabled).text
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getRangeSortValue);
    const list = app.paginateList(st, filteredList).items;

    el.rangesBody.innerHTML = '';
    app.updateSortIndicators('rangesTable', st);
    app.renderFilterMeta('ranges', filteredList.length, st.data.length);
    app.renderPagination('ranges', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noRanges, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('range.list.empty'),
        actionButton: app.el.emptyAddRangeBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('rangesTable', false);
      return;
    }

    app.hideEmptyState(el.noRanges);
    app.toggleTableVisibility('rangesTable', true);

    list.forEach((range) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('range', range.id);
      const info = app.statusInfo(range.status, range.enabled);
      const remark = range.remark
        ? '<span title="' + app.esc(range.remark) + '">' + app.esc(range.remark) + '</span>'
        : app.emptyCellHTML();
      const tag = range.tag
        ? '<span class="tag-badge' + (st.filterTag === range.tag ? ' tag-active' : '') + '" data-table="ranges" data-tag="' + app.esc(range.tag) + '">' + app.esc(range.tag) + '</span>'
        : app.emptyCellHTML();
      const outEndPort = range.out_start_port + (range.end_port - range.start_port);
      const toggleClass = range.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(range.enabled ? 'common.disable' : 'common.enable');
      const disabledAttr = pending ? ' disabled aria-disabled="true"' : '';
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.innerHTML =
        '<td>' + range.id + '</td>' +
        '<td>' + remark + '</td>' +
        '<td>' + tag + '</td>' +
        '<td>' + (range.in_interface ? app.esc(range.in_interface) : app.emptyCellHTML()) + '</td>' +
        '<td>' + app.esc(range.in_ip) + '</td>' +
        '<td><span class="mono-cell">' + range.start_port + '-' + range.end_port + '</span></td>' +
        '<td>' + (range.out_interface ? app.esc(range.out_interface) : app.emptyCellHTML()) + '</td>' +
        '<td>' + app.esc(range.out_ip) + '</td>' +
        '<td><span class="mono-cell">' + range.out_start_port + '-' + outEndPort + '</span></td>' +
        '<td>' + app.esc(String(range.protocol || '').toUpperCase()) + '</td>' +
        '<td>' + (range.transparent ? '<span class="badge badge-running">' + app.t('common.yes') + '</span>' : app.emptyCellHTML()) + '</td>' +
        '<td><span class="badge badge-' + info.badge + '">' + info.text + '</span></td>' +
        '<td class="cell-actions"><div class="action-dropdown">' +
        '<button class="action-dropdown-trigger" aria-expanded="false"' + disabledAttr + '>' + app.t('common.actions') + ' &#9662;</button>' +
        '<div class="action-dropdown-menu">' +
        '<button class="' + toggleClass + '" data-id="' + range.id + '" data-type="range"' + disabledAttr + '>' + toggleText + '</button>' +
        '<button class="btn-edit-range" data-range="' + app.encData(range) + '"' + disabledAttr + '>' + app.t('common.edit') + '</button>' +
        '<button class="btn-clone-range" data-range="' + app.encData(range) + '"' + disabledAttr + '>' + app.t('common.clone') + '</button>' +
        '<button class="btn-delete" data-id="' + range.id + '" data-type="range"' + disabledAttr + '>' + app.t('common.delete') + '</button>' +
        '</div></div></td>';

      el.rangesBody.appendChild(tr);
    });

    app.renderOverview();
  };

  app.loadRanges = async function loadRanges() {
    try {
      app.state.ranges.data = await app.apiCall('GET', '/api/ranges');
      app.markDataFresh();
      app.renderRangesTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load ranges:', e);
    }
  };

  app.deleteRange = async function deleteRange(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('range.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('range', id, true);
    app.renderRangesTable();
    try {
      await app.apiCall('DELETE', '/api/ranges?id=' + id);
      if (app.el.editRangeId.value === String(id)) app.exitRangeEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.range') }));
      app.loadRanges();
    } catch (e) {
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.deleteFailed', { message: e.message }));
    } finally {
      app.setRowPending('range', id, false);
      app.renderRangesTable();
    }
  };
})();
