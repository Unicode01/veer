(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.storageKeys = Object.assign({
    activeTab: 'forward_active_tab'
  }, app.storageKeys || {});

  Object.assign(app.el, {
    toastStack: app.$('toastStack'),
    confirmModal: app.$('confirmModal'),
    confirmTitle: app.$('confirmTitle'),
    confirmMessage: app.$('confirmMessage'),
    confirmCancelBtn: app.$('confirmCancelBtn'),
    confirmSubmitBtn: app.$('confirmSubmitBtn'),
    lastSyncLabel: app.$('lastSyncLabel'),
    overviewRulesValue: app.$('overviewRulesValue'),
    overviewSitesValue: app.$('overviewSitesValue'),
    overviewRangesValue: app.$('overviewRangesValue'),
    overviewWorkersValue: app.$('overviewWorkersValue'),
    overviewRunningValue: app.$('overviewRunningValue'),
    refreshNowBtn: app.$('refreshNowBtn'),
    rulesFilterMeta: app.$('rulesFilterMeta'),
    rulesSelectionMeta: app.$('rulesSelectionMeta'),
    rulesSearchInput: app.$('rulesSearchInput'),
    rulesSelectAll: app.$('rulesSelectAll'),
    batchDeleteRulesBtn: app.$('batchDeleteRulesBtn'),
    clearRulesFilter: app.$('clearRulesFilter'),
    sitesFilterMeta: app.$('sitesFilterMeta'),
    sitesSearchInput: app.$('sitesSearchInput'),
    clearSitesFilter: app.$('clearSitesFilter'),
    rangesFilterMeta: app.$('rangesFilterMeta'),
    rangesSearchInput: app.$('rangesSearchInput'),
    clearRangesFilter: app.$('clearRangesFilter'),
    workersFilterMeta: app.$('workersFilterMeta'),
    workersSearchInput: app.$('workersSearchInput'),
    refreshWorkersBtn: app.$('refreshWorkersBtn'),
    emptyAddRuleBtn: app.$('emptyAddRuleBtn'),
    emptyAddSiteBtn: app.$('emptyAddSiteBtn'),
    emptyAddRangeBtn: app.$('emptyAddRangeBtn'),
    emptyRefreshWorkersBtn: app.$('emptyRefreshWorkersBtn'),
    rulesPagination: app.$('rulesPagination'),
    sitesPagination: app.$('sitesPagination'),
    rangesPagination: app.$('rangesPagination'),
    workersPagination: app.$('workersPagination'),
    ruleStatsPagination: app.$('ruleStatsPagination'),
    siteStatsPagination: app.$('siteStatsPagination'),
    rangeStatsPagination: app.$('rangeStatsPagination')
  });

  app.state.activeTab = app.state.activeTab || localStorage.getItem(app.storageKeys.activeTab) || 'rules';
  app.state.pendingRows = app.state.pendingRows || {};
  app.state.pendingForms = app.state.pendingForms || { rule: false, site: false, range: false };
  app.state.lastSyncAt = app.state.lastSyncAt || 0;
  app.state.confirmResolver = null;
  app.state.confirmFocusReturn = null;
  app.state.activeRequests = app.state.activeRequests || 0;
  app.state.pageVisible = typeof app.state.pageVisible === 'boolean' ? app.state.pageVisible : !document.hidden;

  app.paginationConfig = {
    rules: { container: app.el.rulesPagination, pageSizes: [10, 20, 50], render: () => app.renderRulesTable() },
    sites: { container: app.el.sitesPagination, pageSizes: [10, 20, 50], render: () => app.renderSitesTable() },
    ranges: { container: app.el.rangesPagination, pageSizes: [10, 20, 50], render: () => app.renderRangesTable() },
    workers: { container: app.el.workersPagination, pageSizes: [10, 20, 50], render: () => app.renderWorkersTable() },
    ruleStats: { container: app.el.ruleStatsPagination, pageSizes: [20, 50, 100], render: () => app.renderRuleStatsTable() },
    siteStats: { container: app.el.siteStatsPagination, pageSizes: [20, 50, 100], render: () => app.renderSiteStatsTable() },
    rangeStats: { container: app.el.rangeStatsPagination, pageSizes: [20, 50, 100], render: () => app.renderRangeStatsTable() }
  };

  ['rules', 'sites', 'ranges', 'workers', 'ruleStats', 'siteStats', 'rangeStats'].forEach((table) => {
    if (!app.state[table]) return;
    app.state[table].searchQuery = app.state[table].searchQuery || '';
    app.state[table].page = Math.max(1, parseInt(app.state[table].page, 10) || 1);
    app.state[table].pageSize = Math.max(1, parseInt(app.state[table].pageSize, 10) || ((table.indexOf('Stats') >= 0) ? 20 : 10));
    if (table === 'rules' && !(app.state.rules.selectedIds instanceof Set)) {
      app.state.rules.selectedIds = new Set(app.state.rules.selectedIds || []);
    }
  });

  app.notify = function notify(type, message, timeout) {
    if (!app.el.toastStack || !message) return;

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + (type || 'info');
    toast.setAttribute('role', 'status');
    toast.textContent = message;
    app.el.toastStack.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('is-visible'));

    const lifespan = timeout || 2800;
    window.setTimeout(() => {
      toast.classList.remove('is-visible');
      window.setTimeout(() => toast.remove(), 180);
    }, lifespan);
  };

  app.closeDropdowns = function closeDropdowns() {
    document.querySelectorAll('.action-dropdown.open').forEach((dropdown) => {
      dropdown.classList.remove('open');
      const trigger = dropdown.querySelector('.action-dropdown-trigger');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
  };

  app.openConfirmModal = function openConfirmModal(options) {
    if (!app.el.confirmModal) return Promise.resolve(true);

    if (app.state.confirmResolver) {
      app.state.confirmResolver(false);
      app.state.confirmResolver = null;
    }

    app.state.confirmFocusReturn = document.activeElement;
    app.el.confirmTitle.textContent = options.title || app.t('common.confirm');
    app.el.confirmMessage.textContent = options.message || '';
    app.el.confirmCancelBtn.textContent = options.cancelText || app.t('common.cancel');
    app.el.confirmSubmitBtn.textContent = options.confirmText || app.t('common.confirm');
    app.el.confirmSubmitBtn.classList.toggle('is-danger', !!options.danger);
    app.el.confirmModal.classList.add('active');
    app.el.confirmModal.setAttribute('aria-hidden', 'false');

    return new Promise((resolve) => {
      app.state.confirmResolver = resolve;
      app.el.confirmSubmitBtn.focus();
    });
  };

  app.closeConfirmModal = function closeConfirmModal(result) {
    if (!app.el.confirmModal) return;
    app.el.confirmModal.classList.remove('active');
    app.el.confirmModal.setAttribute('aria-hidden', 'true');
    app.el.confirmSubmitBtn.classList.remove('is-danger');

    if (app.state.confirmResolver) {
      const resolve = app.state.confirmResolver;
      app.state.confirmResolver = null;
      resolve(!!result);
    }

    if (app.state.confirmFocusReturn && typeof app.state.confirmFocusReturn.focus === 'function') {
      app.state.confirmFocusReturn.focus();
    }
    app.state.confirmFocusReturn = null;
  };

  app.confirmAction = function confirmAction(options) {
    return app.openConfirmModal(options || {});
  };

  app.isRowPending = function isRowPending(type, id) {
    return !!app.state.pendingRows[type + ':' + id];
  };

  app.setRowPending = function setRowPending(type, id, pending) {
    const key = type + ':' + id;
    if (pending) app.state.pendingRows[key] = true;
    else delete app.state.pendingRows[key];
  };

  app.withFormBusy = async function withFormBusy(key, submitBtn, cancelBtn, busyText, task, onDone) {
    if (app.state.pendingForms[key]) return false;
    app.state.pendingForms[key] = true;
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.classList.add('is-busy');
      submitBtn.textContent = busyText || app.t('common.saving');
    }
    if (cancelBtn) cancelBtn.disabled = true;

    try {
      await task();
      return true;
    } finally {
      app.state.pendingForms[key] = false;
      if (submitBtn) submitBtn.classList.remove('is-busy');
      if (cancelBtn) cancelBtn.disabled = false;
      if (typeof onDone === 'function') onDone();
    }
  };

  app.formatClock = function formatClock(timestamp) {
    if (!timestamp) return app.t('overview.awaitingSync');
    return new Intl.DateTimeFormat(app.state.locale, {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    }).format(new Date(timestamp));
  };

  app.normalizeSearchValue = function normalizeSearchValue(value) {
    return String(value == null ? '' : value).trim().toLocaleLowerCase(app.state.locale || undefined);
  };

  app.matchesSearch = function matchesSearch(query, values) {
    const normalizedQuery = app.normalizeSearchValue(query);
    if (!normalizedQuery) return true;

    const haystack = values
      .filter((value) => value != null && value !== '')
      .map((value) => app.normalizeSearchValue(value))
      .join(' ');

    return normalizedQuery.split(/\s+/).every((token) => haystack.indexOf(token) >= 0);
  };

  app.hasActiveFilters = function hasActiveFilters(state) {
    if (!state) return false;
    return !!((state.filterTag || '').trim() || (state.searchQuery || '').trim());
  };

  app.getDefaultPageSize = function getDefaultPageSize(table) {
    const config = app.paginationConfig[table];
    if (config && Array.isArray(config.pageSizes) && config.pageSizes.length > 0) return config.pageSizes[0];
    const state = app.state[table];
    return state && state.pageSize ? state.pageSize : 10;
  };

  app.hasTableViewChanges = function hasTableViewChanges(table) {
    const state = app.state[table];
    if (!state) return false;
    const hasSelection = state.selectedIds instanceof Set && state.selectedIds.size > 0;
    return app.hasActiveFilters(state) ||
      !!state.sortKey ||
      state.page !== 1 ||
      state.pageSize !== app.getDefaultPageSize(table) ||
      hasSelection;
  };

  app.resetTableView = function resetTableView(table) {
    const state = app.state[table];
    if (!state) return;

    if (Object.prototype.hasOwnProperty.call(state, 'filterTag')) state.filterTag = '';
    state.searchQuery = '';
    state.sortKey = '';
    state.sortAsc = true;
    state.page = 1;
    state.pageSize = app.getDefaultPageSize(table);

    if (state.selectedIds instanceof Set) state.selectedIds.clear();

    const input = app.el[table + 'SearchInput'];
    if (input) input.value = '';
  };

  app.updateEmptyState = function updateEmptyState(container, options) {
    if (!container) return;

    const opts = options || {};
    const title = container.querySelector('.empty-title');
    if (title) title.textContent = opts.message || '';
    if (opts.actionButton) opts.actionButton.hidden = !opts.showAction;

    container.classList.toggle('is-filtered-empty', !!opts.filtered);
    container.style.display = 'block';
  };

  app.hideEmptyState = function hideEmptyState(container) {
    if (!container) return;
    container.classList.remove('is-filtered-empty');
    container.style.display = 'none';
  };

  app.focusSection = function focusSection(tabId, heading, field) {
    app.activateTab(tabId);
    requestAnimationFrame(() => {
      if (heading && typeof heading.scrollIntoView === 'function') {
        heading.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }

      window.setTimeout(() => {
        if (field && typeof field.focus === 'function') field.focus();
        if (field && typeof field.select === 'function' && field.tagName === 'INPUT' && field.type !== 'checkbox') {
          field.select();
        }
      }, 180);
    });
  };

  app.refreshDashboard = function refreshDashboard(options) {
    const opts = Object.assign({
      includeMeta: false,
      includeWorkers: app.state.activeTab === 'workers',
      includeStats: app.state.activeTab === 'rule-stats'
    }, options || {});

    const tasks = [];
    if (opts.includeMeta) {
      if (typeof app.loadInterfaces === 'function') tasks.push(app.loadInterfaces());
      if (typeof app.loadTags === 'function') tasks.push(app.loadTags());
    }
    if (typeof app.loadRules === 'function') tasks.push(app.loadRules());
    if (typeof app.loadSites === 'function') tasks.push(app.loadSites());
    if (typeof app.loadRanges === 'function') tasks.push(app.loadRanges());
    if (opts.includeWorkers && typeof app.loadWorkers === 'function') tasks.push(app.loadWorkers());
    if (opts.includeStats && typeof app.loadAllStats === 'function') tasks.push(app.loadAllStats());
    return Promise.all(tasks);
  };

  app.getPaginationInfo = function getPaginationInfo(state, totalItems) {
    const pageSize = Math.max(1, parseInt(state.pageSize, 10) || 10);
    const total = Math.max(0, parseInt(totalItems, 10) || 0);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(Math.max(1, parseInt(state.page, 10) || 1), totalPages);
    const offset = (page - 1) * pageSize;
    const start = total > 0 ? offset + 1 : 0;
    const end = total > 0 ? Math.min(offset + pageSize, total) : 0;

    state.page = page;
    state.pageSize = pageSize;

    return {
      page: page,
      pageSize: pageSize,
      totalItems: total,
      totalPages: totalPages,
      offset: offset,
      start: start,
      end: end
    };
  };

  app.paginateList = function paginateList(state, list) {
    const items = Array.isArray(list) ? list : [];
    const info = app.getPaginationInfo(state, items.length);
    return Object.assign({}, info, {
      items: items.slice(info.offset, info.offset + info.pageSize)
    });
  };

  app.renderPagination = function renderPagination(table, totalItems) {
    const config = app.paginationConfig[table];
    const state = app.state[table];
    if (!config || !state || !config.container) return;

    if (!totalItems) {
      config.container.hidden = true;
      config.container.innerHTML = '';
      return;
    }

    const info = app.getPaginationInfo(state, totalItems);
    const options = (config.pageSizes || [10, 20, 50]).map((size) => {
      const selected = info.pageSize === size ? ' selected' : '';
      return '<option value="' + size + '"' + selected + '>' + size + '</option>';
    }).join('');

    config.container.hidden = false;
    config.container.innerHTML =
      '<div class="table-pagination-summary">' + app.t('pagination.summary', {
        start: info.start,
        end: info.end,
        total: info.totalItems
      }) + '</div>' +
      '<div class="table-pagination-actions">' +
      '<label class="pagination-size-label">' +
      '<span>' + app.t('pagination.pageSize') + '</span>' +
      '<select class="pagination-size-select" data-table="' + table + '">' + options + '</select>' +
      '</label>' +
      '<button type="button" class="pagination-btn" data-table="' + table + '" data-page="' + (info.page - 1) + '"' + (info.page <= 1 ? ' disabled aria-disabled="true"' : '') + '>' + app.t('pagination.previous') + '</button>' +
      '<span class="pagination-page-label">' + app.t('pagination.page', { page: info.page, totalPages: info.totalPages }) + '</span>' +
      '<button type="button" class="pagination-btn" data-table="' + table + '" data-page="' + (info.page + 1) + '"' + (info.page >= info.totalPages ? ' disabled aria-disabled="true"' : '') + '>' + app.t('pagination.next') + '</button>' +
      '</div>';
  };

  app.goToPage = function goToPage(table, page) {
    const config = app.paginationConfig[table];
    const state = app.state[table];
    if (!config || !state || typeof config.render !== 'function') return;
    state.page = Math.max(1, parseInt(page, 10) || 1);
    config.render();
  };

  app.setPageSize = function setPageSize(table, pageSize) {
    const config = app.paginationConfig[table];
    const state = app.state[table];
    if (!config || !state || typeof config.render !== 'function') return;
    state.pageSize = Math.max(1, parseInt(pageSize, 10) || state.pageSize || 10);
    state.page = 1;
    config.render();
  };

  app.renderOverview = function renderOverview() {
    if (app.el.overviewRulesValue) app.el.overviewRulesValue.textContent = String((app.state.rules.data || []).length);
    if (app.el.overviewSitesValue) app.el.overviewSitesValue.textContent = String((app.state.sites.data || []).length);
    if (app.el.overviewRangesValue) app.el.overviewRangesValue.textContent = String((app.state.ranges.data || []).length);
    if (app.el.overviewWorkersValue) app.el.overviewWorkersValue.textContent = String((app.state.workers.data || []).length);

    const runningTotal =
      (app.state.rules.data || []).filter((item) => item.enabled !== false && item.status === 'running').length +
      (app.state.sites.data || []).filter((item) => item.enabled !== false && item.status === 'running').length +
      (app.state.ranges.data || []).filter((item) => item.enabled !== false && item.status === 'running').length;

    if (app.el.overviewRunningValue) app.el.overviewRunningValue.textContent = String(runningTotal);
    const busy = app.state.activeRequests > 0;
    [app.el.refreshNowBtn, app.el.refreshWorkersBtn, app.el.emptyRefreshWorkersBtn].forEach((button) => {
      if (!button) return;
      button.disabled = busy;
      button.classList.toggle('is-busy', busy);
      button.setAttribute('aria-busy', busy ? 'true' : 'false');
    });
    if (app.el.lastSyncLabel) {
      if (busy) {
        app.el.lastSyncLabel.textContent = app.t('overview.syncing');
      } else {
        app.el.lastSyncLabel.textContent = app.state.lastSyncAt
          ? app.t('overview.lastSync', { time: app.formatClock(app.state.lastSyncAt) })
          : app.t('overview.awaitingSync');
      }
    }
  };

  app.markDataFresh = function markDataFresh() {
    app.state.lastSyncAt = Date.now();
    app.renderOverview();
  };

  app.renderFilterMeta = function renderFilterMeta(table, visibleCount, totalCount) {
    const map = {
      rules: { meta: app.el.rulesFilterMeta, clear: app.el.clearRulesFilter },
      sites: { meta: app.el.sitesFilterMeta, clear: app.el.clearSitesFilter },
      ranges: { meta: app.el.rangesFilterMeta, clear: app.el.clearRangesFilter },
      workers: { meta: app.el.workersFilterMeta, clear: null }
    };

    const target = map[table];
    const state = app.state[table];
    if (!target || !state) return;

    const filtered = app.hasActiveFilters(state);
    const total = typeof totalCount === 'number' ? totalCount : (state.data || []).length;
    const shown = typeof visibleCount === 'number' ? visibleCount : total;
    if (target.meta) {
      target.meta.hidden = false;
      target.meta.textContent = filtered
        ? app.t('filter.summary.filtered', { visible: shown, total: total })
        : app.t('filter.summary.all', { count: total });
    }
    if (target.clear) {
      target.clear.hidden = !app.hasTableViewChanges(table);
      target.clear.textContent = app.t('filter.reset');
    }
  };

  app.handleTabLoad = function handleTabLoad(target) {
    if (target === 'workers') app.loadWorkers();
    if (target === 'rule-stats') app.loadAllStats();
  };

  app.activateTab = function activateTab(target, options) {
    const opts = options || {};
    const tabId = target || 'rules';
    const nextTab = document.querySelector('.tab[data-tab="' + tabId + '"]');
    const nextPanel = app.$('tab-' + tabId);
    if (!nextTab || !nextPanel) return;

    document.querySelectorAll('.tab').forEach((tab) => {
      const active = tab === nextTab;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
      tab.setAttribute('tabindex', active ? '0' : '-1');
    });

    document.querySelectorAll('.tab-content').forEach((panel) => {
      const active = panel === nextPanel;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });

    app.state.activeTab = tabId;
    if (opts.persist !== false) localStorage.setItem(app.storageKeys.activeTab, tabId);
    if (opts.focus) nextTab.focus();
    app.closeDropdowns();
    if (!opts.skipLoad) app.handleTabLoad(tabId);
  };

  app.confirmTransparentWarning = function confirmTransparentWarning(warning) {
    if (!warning || !warning.needsConfirm) return Promise.resolve(true);
    return app.confirmAction({
      title: app.t('confirm.warningTitle'),
      message: warning.text,
      confirmText: app.t('common.confirm'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
  };

  app.refreshLocalizedUI = (function wrapRefreshLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original();
      app.renderOverview();
      app.renderFilterMeta('rules');
      app.renderFilterMeta('sites');
      app.renderFilterMeta('ranges');
      app.renderFilterMeta('workers');
      if (app.el.confirmModal && !app.el.confirmModal.classList.contains('active')) {
        app.el.confirmCancelBtn.textContent = app.t('common.cancel');
        app.el.confirmSubmitBtn.textContent = app.t('common.confirm');
      }
    };
  })(app.refreshLocalizedUI);

  app.showTokenModal = (function wrapShowTokenModal(original) {
    return function showTokenModal() {
      app.closeDropdowns();
      if (app.el.confirmModal && app.el.confirmModal.classList.contains('active')) {
        app.closeConfirmModal(false);
      }
      original();
    };
  })(app.showTokenModal);

  app.clearFieldError = function clearFieldError(input) {
    if (!input) return;
    input.removeAttribute('aria-invalid');
    const group = input.closest('.form-group');
    if (!group) return;
    group.classList.remove('has-error');
    const msg = group.querySelector('.field-error');
    if (msg) msg.remove();
  };

  app.setFieldError = function setFieldError(input, message) {
    if (!input) return;
    const group = input.closest('.form-group');
    if (!group) return;
    app.clearFieldError(input);
    input.setAttribute('aria-invalid', 'true');
    group.classList.add('has-error');
    const msg = document.createElement('div');
    msg.className = 'field-error';
    msg.textContent = message;
    group.appendChild(msg);
  };

  app.clearFormErrors = function clearFormErrors(form) {
    if (!form) return;
    form.querySelectorAll('input, select').forEach((field) => app.clearFieldError(field));
  };

  app.focusFirstError = function focusFirstError(form) {
    if (!form) return;
    const first = form.querySelector('[aria-invalid="true"]');
    if (first && typeof first.focus === 'function') first.focus();
  };

  app.validateRequiredField = function validateRequiredField(input) {
    if (!input) return true;
    const value = input.value == null ? '' : String(input.value).trim();
    if (value) {
      app.clearFieldError(input);
      return true;
    }
    app.setFieldError(input, app.t('validation.required'));
    return false;
  };

  app.validateIPv4Field = function validateIPv4Field(input) {
    if (!input) return true;
    const value = input.value == null ? '' : String(input.value).trim();
    if (app.parseIPv4(value)) {
      app.clearFieldError(input);
      return true;
    }
    app.setFieldError(input, app.t('validation.ipv4'));
    return false;
  };

  app.validatePortField = function validatePortField(input, allowZero) {
    if (!input) return true;
    const raw = input.value == null ? '' : String(input.value).trim();
    const value = parseInt(raw, 10);
    const min = allowZero ? 0 : 1;
    if (raw && !Number.isNaN(value) && value >= min && value <= 65535) {
      app.clearFieldError(input);
      return true;
    }
    app.setFieldError(input, app.t('validation.required'));
    return false;
  };

  app.validateOptionalPortField = function validateOptionalPortField(input, allowZero) {
    if (!input) return true;
    const raw = input.value == null ? '' : String(input.value).trim();
    if (!raw) {
      app.clearFieldError(input);
      return true;
    }
    return app.validatePortField(input, !!allowZero);
  };

  [
    { button: app.el.clearRulesFilter, table: 'rules', render: () => app.renderRulesTable() },
    { button: app.el.clearSitesFilter, table: 'sites', render: () => app.renderSitesTable() },
    { button: app.el.clearRangesFilter, table: 'ranges', render: () => app.renderRangesTable() }
  ].forEach((entry) => {
    if (!entry.button) return;
    entry.button.addEventListener('click', () => {
      app.resetTableView(entry.table);
      entry.render();
    });
  });

  if (app.el.confirmCancelBtn) app.el.confirmCancelBtn.addEventListener('click', () => app.closeConfirmModal(false));
  if (app.el.confirmSubmitBtn) app.el.confirmSubmitBtn.addEventListener('click', () => app.closeConfirmModal(true));
  if (app.el.confirmModal) {
    app.el.confirmModal.addEventListener('click', (e) => {
      if (e.target === app.el.confirmModal) app.closeConfirmModal(false);
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (app.el.confirmModal && app.el.confirmModal.classList.contains('active')) {
        app.closeConfirmModal(false);
        return;
      }
      app.closeDropdowns();
    }

    if (app.el.confirmModal && app.el.confirmModal.classList.contains('active')) {
      if (e.key === 'Enter') {
        e.preventDefault();
        app.closeConfirmModal(true);
        return;
      }

      if (e.key === 'Tab') {
        const focusable = [app.el.confirmCancelBtn, app.el.confirmSubmitBtn].filter(Boolean);
        if (!focusable.length) return;
        const currentIndex = focusable.indexOf(document.activeElement);
        const nextIndex = e.shiftKey
          ? (currentIndex <= 0 ? focusable.length - 1 : currentIndex - 1)
          : (currentIndex === focusable.length - 1 ? 0 : currentIndex + 1);
        e.preventDefault();
        focusable[nextIndex].focus();
      }
    }
  });

  document.addEventListener('input', (e) => {
    const field = e.target.closest('input, select');
    if (field) app.clearFieldError(field);
  });

  document.addEventListener('change', (e) => {
    const pageSizeSelect = e.target.closest('.pagination-size-select[data-table]');
    if (pageSizeSelect) {
      app.setPageSize(pageSizeSelect.dataset.table, pageSizeSelect.value);
      return;
    }

    const field = e.target.closest('input, select');
    if (field) app.clearFieldError(field);
  });

  document.addEventListener('click', (e) => {
    const pageButton = e.target.closest('.pagination-btn[data-table][data-page]');
    if (!pageButton || pageButton.disabled) return;
    app.goToPage(pageButton.dataset.table, pageButton.dataset.page);
  });

  app.apiCall = (function wrapApiCall(original) {
    return async function apiCall(method, path, body) {
      app.state.activeRequests++;
      app.renderOverview();
      try {
        return await original(method, path, body);
      } finally {
        app.state.activeRequests = Math.max(0, app.state.activeRequests - 1);
        app.renderOverview();
      }
    };
  })(app.apiCall);

  app.renderOverview();
})();
