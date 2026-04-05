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
    app.populateSourceIPSelect(null, el.siteBackendSourceIP, site.backend_source_ip, true);
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
    app.populateSourceIPSelect(null, el.siteBackendSourceIP, site.backend_source_ip, true);
    app.$('siteBackendHTTP').value = site.backend_http_port || '';
    app.$('siteBackendHTTPS').value = site.backend_https_port || '';
    app.$('siteTransparent').checked = !!site.transparent;
    app.updateSiteTransparentWarning();
    el.siteFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitSiteEditMode = function exitSiteEditMode() {
    app.setSiteFormAdd();
    app.el.siteForm.reset();
    app.populateSourceIPSelect(null, app.el.siteBackendSourceIP, '', false);
    app.updateSiteTransparentWarning();
  };

  app.getSiteFieldInputs = function getSiteFieldInputs(issue) {
    const msg = String((issue && issue.message) || '').trim();
    const field = String((issue && issue.field) || '').trim();
    const map = {
      id: app.el.editSiteId,
      domain: app.$('siteDomain'),
      listen_interface: app.el.siteListenIface,
      listen_ip: app.el.siteListenIP,
      backend_ip: app.$('siteBackendIP'),
      backend_source_ip: app.el.siteBackendSourceIP,
      backend_http_port: app.$('siteBackendHTTP'),
      backend_https_port: app.$('siteBackendHTTPS'),
      transparent: app.$('siteTransparent'),
      tag: app.$('siteTag')
    };
    if (map[field]) return [map[field]];
    if (msg === 'domain and backend_ip are required') return [app.$('siteDomain'), app.$('siteBackendIP')];
    if (msg === 'at least one of backend_http_port or backend_https_port is required') return [app.$('siteBackendHTTP'), app.$('siteBackendHTTPS')];
    if (msg === 'transparent mode currently supports only IPv4 rules') return [app.$('siteTransparent')];
    if (msg.indexOf('listen_interface ') === 0) return [app.el.siteListenIface];
    if (msg.indexOf('listen_ip ') === 0) return [app.el.siteListenIP];
    if (msg.indexOf('backend_ip ') === 0) return [app.$('siteBackendIP')];
    if (msg.indexOf('backend_source_ip ') === 0) return [app.el.siteBackendSourceIP];
    if (msg.indexOf('HTTP route conflicts with ') === 0 || msg.indexOf('HTTPS route conflicts with ') === 0) return [app.$('siteDomain')];
    return [];
  };

  app.applySiteValidationIssues = function applySiteValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getSiteFieldInputs(issue);
      if (!inputs.length) return;
      const translated = app.translateValidationMessage(issue.message);
      inputs.forEach((input) => {
        if (!input) return;
        if (!firstInvalid) firstInvalid = input;
        if (!input.hasAttribute('aria-invalid')) {
          app.setFieldError(input, translated);
        }
      });
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.getValidationIssueSummary({ issues: relevant }, null, 3) || app.translateValidationMessage(relevant[0].message));
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
        site.backend_source_ip,
        site.backend_http_port,
        site.backend_https_port,
        app.statusInfo(site.status, site.enabled).text
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getSiteSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.sitesBody);
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

    const fragment = document.createDocumentFragment();
    list.forEach((site) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('site', site.id);
      const info = app.statusInfo(site.status, site.enabled);
      const toggleClass = site.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(site.enabled ? 'common.disable' : 'common.enable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.appendChild(app.createCell(String(site.id)));
      tr.appendChild(app.createCell(site.domain));
      tr.appendChild(app.createCell(app.createTagBadgeNode('sites', site.tag, st.filterTag === site.tag)));
      tr.appendChild(app.createCell(site.listen_ip));
      tr.appendChild(app.createCell(app.createEndpointNode(site.backend_ip, site.backend_source_ip)));
      tr.appendChild(app.createCell(site.backend_http_port || app.emptyCellNode('inline')));
      tr.appendChild(app.createCell(site.backend_https_port || app.emptyCellNode('inline')));
      tr.appendChild(app.createCell(site.transparent
        ? app.createBadgeNode('badge-running', app.t('common.yes'))
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createStatusBadgeNode(info)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: toggleClass,
          text: toggleText,
          dataset: { id: site.id, type: 'site' },
          disabled: pending
        },
        {
          className: 'btn-edit-site',
          text: app.t('common.edit'),
          dataset: { site: app.encData(site) },
          disabled: pending
        },
        {
          className: 'btn-clone-site',
          text: app.t('common.clone'),
          dataset: { site: app.encData(site) },
          disabled: pending
        },
        {
          className: 'btn-delete',
          text: app.t('common.delete'),
          dataset: { id: site.id, type: 'site' },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.sitesBody.appendChild(fragment);

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
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('site', id, false);
      app.renderSitesTable();
    }
  };
})();
