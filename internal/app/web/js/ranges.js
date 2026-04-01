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
    app.populateSourceIPSelect(el.rangeOutInterface, el.rangeOutSourceIP, range.out_source_ip, true);
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
    app.populateSourceIPSelect(el.rangeOutInterface, el.rangeOutSourceIP, range.out_source_ip, true);
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
    app.populateSourceIPSelect(app.el.rangeOutInterface, app.el.rangeOutSourceIP, '', false);
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
        range.out_source_ip,
        range.out_start_port,
        range.protocol,
        app.statusInfo(range.status, range.enabled).text
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getRangeSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.rangesBody);
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

    const fragment = document.createDocumentFragment();
    list.forEach((range) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('range', range.id);
      const info = app.statusInfo(range.status, range.enabled);
      const outEndPort = range.out_start_port + (range.end_port - range.start_port);
      const toggleClass = range.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(range.enabled ? 'common.disable' : 'common.enable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      const rangePortNode = app.createNode('span', {
        className: 'mono-cell',
        text: range.start_port + '-' + range.end_port
      });
      const outPortNode = app.createNode('span', {
        className: 'mono-cell',
        text: range.out_start_port + '-' + outEndPort
      });

      tr.appendChild(app.createCell(String(range.id)));
      tr.appendChild(app.createCell(range.remark
        ? app.createNode('span', { text: range.remark, title: range.remark })
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createTagBadgeNode('ranges', range.tag, st.filterTag === range.tag)));
      tr.appendChild(app.createCell(range.in_interface ? range.in_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(range.in_ip));
      tr.appendChild(app.createCell(rangePortNode));
      tr.appendChild(app.createCell(range.out_interface ? range.out_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createEndpointNode(range.out_ip, range.out_source_ip)));
      tr.appendChild(app.createCell(outPortNode));
      tr.appendChild(app.createCell(String(range.protocol || '').toUpperCase()));
      tr.appendChild(app.createCell(range.transparent
        ? app.createBadgeNode('badge-running', app.t('common.yes'))
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createStatusBadgeNode(info)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: toggleClass,
          text: toggleText,
          dataset: { id: range.id, type: 'range' },
          disabled: pending
        },
        {
          className: 'btn-edit-range',
          text: app.t('common.edit'),
          dataset: { range: app.encData(range) },
          disabled: pending
        },
        {
          className: 'btn-clone-range',
          text: app.t('common.clone'),
          dataset: { range: app.encData(range) },
          disabled: pending
        },
        {
          className: 'btn-delete',
          text: app.t('common.delete'),
          dataset: { id: range.id, type: 'range' },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.rangesBody.appendChild(fragment);

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
