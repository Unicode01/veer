(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.syncSiteFormState = function syncSiteFormState() {
    const el = app.el;
    const formState = app.state.forms.site;
    const pending = !!app.state.pendingForms.site;

    if (formState.mode === 'edit' && el.editSiteId.value) {
      el.siteFormTitle.textContent = app.t('site.form.title.edit', { id: el.editSiteId.value });
      el.siteSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('site.form.submit.edit');
      el.siteCancelBtn.style.display = '';
    } else if (formState.mode === 'clone' && formState.sourceId) {
      el.siteFormTitle.textContent = app.t('site.form.title.clone', { id: formState.sourceId });
      el.siteSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('site.form.submit.clone');
      el.siteCancelBtn.style.display = '';
    } else {
      el.siteFormTitle.textContent = app.t('site.form.title.add');
      el.siteSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('site.form.submit.add');
      el.siteCancelBtn.style.display = 'none';
    }

    el.siteCancelBtn.textContent = app.t('common.cancelEdit');
    el.siteSubmitBtn.disabled = pending;
    el.siteSubmitBtn.classList.toggle('is-busy', pending);
    el.siteCancelBtn.disabled = pending;
  };

  app.setSiteFormAdd = function setSiteFormAdd() {
    app.state.forms.site = { mode: 'add', sourceId: 0 };
    app.el.editSiteId.value = '';
    app.syncSiteFormState();
  };

  app.enterSiteEditMode = function enterSiteEditMode(site) {
    const el = app.el;
    app.state.forms.site = { mode: 'edit', sourceId: site.id };
    el.editSiteId.value = site.id;
    app.syncSiteFormState();

    app.$('siteDomain').value = site.domain;
    app.populateTagSelect(app.$('siteTag'), site.tag);
    app.populateInterfaceSelect(el.siteListenIface, site.listen_interface);
    app.populateSiteListenIP(el.siteListenIface, el.siteListenIP, site.listen_ip);
    app.$('siteBackendIP').value = site.backend_ip;
    app.$('siteBackendHTTP').value = site.backend_http_port || '';
    app.$('siteBackendHTTPS').value = site.backend_https_port || '';
    app.$('siteTransparent').checked = !!site.transparent;
    app.updateSiteTransparentWarning();
    el.siteFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.enterSiteCloneMode = function enterSiteCloneMode(site) {
    const el = app.el;
    app.state.forms.site = { mode: 'clone', sourceId: site.id };
    el.editSiteId.value = '';
    app.syncSiteFormState();

    app.$('siteDomain').value = site.domain;
    app.populateTagSelect(app.$('siteTag'), site.tag);
    app.populateInterfaceSelect(el.siteListenIface, site.listen_interface);
    app.populateSiteListenIP(el.siteListenIface, el.siteListenIP, site.listen_ip);
    app.$('siteBackendIP').value = site.backend_ip;
    app.$('siteBackendHTTP').value = site.backend_http_port || '';
    app.$('siteBackendHTTPS').value = site.backend_https_port || '';
    app.$('siteTransparent').checked = !!site.transparent;
    app.updateSiteTransparentWarning();
    el.siteFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitSiteEditMode = function exitSiteEditMode() {
    app.setSiteFormAdd();
    app.el.siteForm.reset();
    app.updateSiteTransparentWarning();
  };

  app.getSiteSortValue = function getSiteSortValue(site, key) {
    if (key === 'status') {
      if (!site.enabled) return 3;
      if (site.status === 'running') return 0;
      if (site.status === 'error') return 1;
      return 2;
    }
    if (key === 'transparent') return site.transparent ? 1 : 0;
    return site[key];
  };

  app.renderSitesTable = function renderSitesTable() {
    const el = app.el;
    const st = app.state.sites;
    app.closeDropdowns();
    let filteredList = st.data.slice();
    if (st.filterTag) filteredList = filteredList.filter((site) => site.tag === st.filterTag);
    if (st.searchQuery) {
      filteredList = filteredList.filter((site) => app.matchesSearch(st.searchQuery, [
        site.id,
        site.domain,
        site.tag,
        site.listen_interface,
        site.listen_ip,
        site.backend_ip,
        site.backend_http_port,
        site.backend_https_port,
        app.statusInfo(site.status, site.enabled).text
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getSiteSortValue);
    const list = app.paginateList(st, filteredList).items;

    el.sitesBody.innerHTML = '';
    app.updateSortIndicators('sitesTable', st);
    app.renderFilterMeta('sites', filteredList.length, st.data.length);
    app.renderPagination('sites', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noSites, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('site.list.empty'),
        actionButton: app.el.emptyAddSiteBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('sitesTable', false);
      return;
    }

    app.hideEmptyState(el.noSites);
    app.toggleTableVisibility('sitesTable', true);

    list.forEach((site) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('site', site.id);
      const info = app.statusInfo(site.status, site.enabled);
      const tag = site.tag
        ? '<span class="tag-badge' + (st.filterTag === site.tag ? ' tag-active' : '') + '" data-table="sites" data-tag="' + app.esc(site.tag) + '">' + app.esc(site.tag) + '</span>'
        : app.emptyCellHTML();
      const toggleClass = site.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(site.enabled ? 'common.disable' : 'common.enable');
      const disabledAttr = pending ? ' disabled aria-disabled="true"' : '';
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.innerHTML =
        '<td>' + site.id + '</td>' +
        '<td>' + app.esc(site.domain) + '</td>' +
        '<td>' + tag + '</td>' +
        '<td>' + app.esc(site.listen_ip) + '</td>' +
        '<td>' + app.esc(site.backend_ip) + '</td>' +
        '<td>' + (site.backend_http_port || app.emptyCellHTML('inline')) + '</td>' +
        '<td>' + (site.backend_https_port || app.emptyCellHTML('inline')) + '</td>' +
        '<td>' + (site.transparent ? '<span class="badge badge-running">' + app.t('common.yes') + '</span>' : app.emptyCellHTML()) + '</td>' +
        '<td><span class="badge badge-' + info.badge + '">' + info.text + '</span></td>' +
        '<td class="cell-actions"><div class="action-dropdown">' +
        '<button class="action-dropdown-trigger" aria-expanded="false"' + disabledAttr + '>' + app.t('common.actions') + ' &#9662;</button>' +
        '<div class="action-dropdown-menu">' +
        '<button class="' + toggleClass + '" data-id="' + site.id + '" data-type="site"' + disabledAttr + '>' + toggleText + '</button>' +
        '<button class="btn-edit-site" data-site="' + app.encData(site) + '"' + disabledAttr + '>' + app.t('common.edit') + '</button>' +
        '<button class="btn-clone-site" data-site="' + app.encData(site) + '"' + disabledAttr + '>' + app.t('common.clone') + '</button>' +
        '<button class="btn-delete" data-id="' + site.id + '" data-type="site"' + disabledAttr + '>' + app.t('common.delete') + '</button>' +
        '</div></div></td>';

      el.sitesBody.appendChild(tr);
    });

    app.renderOverview();
  };

  app.loadSites = async function loadSites() {
    try {
      app.state.sites.data = await app.apiCall('GET', '/api/sites');
      app.markDataFresh();
      app.renderSitesTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load sites:', e);
    }
  };

  app.deleteSite = async function deleteSite(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('site.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('site', id, true);
    app.renderSitesTable();
    try {
      await app.apiCall('DELETE', '/api/sites?id=' + id);
      if (app.el.editSiteId.value === String(id)) app.exitSiteEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.site') }));
      app.loadSites();
    } catch (e) {
      if (e.message !== 'unauthorized') app.notify('error', app.t('errors.deleteFailed', { message: e.message }));
    } finally {
      app.setRowPending('site', id, false);
      app.renderSitesTable();
    }
  };
})();
