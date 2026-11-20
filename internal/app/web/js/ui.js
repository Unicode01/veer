(function () {
  const app = window.VeerApp;
  if (!app) return;

  app.storageKeys = Object.assign({
    activeTab: 'veer_active_tab'
  }, app.storageKeys || {});
  app.legacyStorageKeys = Object.assign({
    activeTab: 'forward_active_tab'
  }, app.legacyStorageKeys || {});

  Object.assign(app.el, {
    toastStack: app.$('toastStack'),
    confirmModal: app.$('confirmModal'),
    confirmTitle: app.$('confirmTitle'),
    confirmMessage: app.$('confirmMessage'),
    confirmCancelBtn: app.$('confirmCancelBtn'),
    confirmSubmitBtn: app.$('confirmSubmitBtn'),
    overviewPanel: app.el.overviewPanel || app.$('overviewPanel'),
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
    managedNetworksFilterMeta: app.$('managedNetworksFilterMeta'),
    managedNetworksSearchInput: app.$('managedNetworksSearchInput'),
    clearManagedNetworksFilter: app.$('clearManagedNetworksFilter'),
    repairManagedNetworkRuntimeBtn: app.$('repairManagedNetworkRuntimeBtn'),
    reloadManagedNetworkRuntimeBtn: app.$('reloadManagedNetworkRuntimeBtn'),
    managedNetworkReservationCandidatesFilterMeta: app.$('managedNetworkReservationCandidatesFilterMeta'),
    managedNetworkReservationCandidatesSearchInput: app.$('managedNetworkReservationCandidatesSearchInput'),
    clearManagedNetworkReservationCandidatesFilter: app.$('clearManagedNetworkReservationCandidatesFilter'),
    managedNetworkReservationsFilterMeta: app.$('managedNetworkReservationsFilterMeta'),
    managedNetworkReservationsSearchInput: app.$('managedNetworkReservationsSearchInput'),
    clearManagedNetworkReservationsFilter: app.$('clearManagedNetworkReservationsFilter'),
    egressNATsFilterMeta: app.$('egressNATsFilterMeta'),
    egressNATsSearchInput: app.$('egressNATsSearchInput'),
    clearEgressNATsFilter: app.$('clearEgressNATsFilter'),
    ipv6AssignmentsFilterMeta: app.$('ipv6AssignmentsFilterMeta'),
    ipv6AssignmentsSearchInput: app.$('ipv6AssignmentsSearchInput'),
    clearIPv6AssignmentsFilter: app.$('clearIPv6AssignmentsFilter'),
    workersFilterMeta: app.$('workersFilterMeta'),
    workersSearchInput: app.$('workersSearchInput'),
    refreshWorkersBtn: app.$('refreshWorkersBtn'),
    emptyAddRuleBtn: app.$('emptyAddRuleBtn'),
    emptyAddSiteBtn: app.$('emptyAddSiteBtn'),
    emptyAddRangeBtn: app.$('emptyAddRangeBtn'),
    emptyAddManagedNetworkBtn: app.$('emptyAddManagedNetworkBtn'),
    emptyAddManagedNetworkReservationBtn: app.$('emptyAddManagedNetworkReservationBtn'),
    emptyAddEgressNATBtn: app.$('emptyAddEgressNATBtn'),
    emptyAddIPv6AssignmentBtn: app.$('emptyAddIPv6AssignmentBtn'),
    emptyRefreshWorkersBtn: app.$('emptyRefreshWorkersBtn'),
    rulesPagination: app.$('rulesPagination'),
    sitesPagination: app.$('sitesPagination'),
    rangesPagination: app.$('rangesPagination'),
    managedNetworksPagination: app.$('managedNetworksPagination'),
    managedNetworkReservationCandidatesPagination: app.$('managedNetworkReservationCandidatesPagination'),
    managedNetworkReservationsPagination: app.$('managedNetworkReservationsPagination'),
    egressNATsPagination: app.$('egressNATsPagination'),
    ipv6AssignmentsPagination: app.$('ipv6AssignmentsPagination'),
    workersPagination: app.$('workersPagination'),
    pluginsBody: app.$('pluginsBody'),
    noPlugins: app.$('noPlugins'),
    pluginsSearchInput: app.$('pluginsSearchInput'),
    pluginsFilterMeta: app.$('pluginsFilterMeta'),
    pluginsCatalogMeta: app.$('pluginsCatalogMeta'),
    pluginsChainMeta: app.$('pluginsChainMeta'),
    pluginUIPanel: app.$('pluginUIPanel'),
    pluginUITitle: app.$('pluginUITitle'),
    pluginUIMeta: app.$('pluginUIMeta'),
    pluginUIFrame: app.$('pluginUIFrame'),
    closePluginUIBtn: app.$('closePluginUIBtn'),
    pluginUpdateSelectionBar: app.$('pluginUpdateSelectionBar'),
    pluginUpdateSelectionMeta: app.$('pluginUpdateSelectionMeta'),
    applyPluginUpdateBtn: app.$('applyPluginUpdateBtn'),
    pluginManagerModal: app.$('pluginManagerModal'),
    pluginManagerTitle: app.$('pluginManagerTitle'),
    pluginManagerMeta: app.$('pluginManagerMeta'),
    pluginManagerNav: app.$('pluginManagerNav'),
    pluginManagerBody: app.$('pluginManagerBody'),
    closePluginManagerBtn: app.$('closePluginManagerBtn'),
    addPluginBtn: app.$('addPluginBtn'),
    managePluginsAdvancedBtn: app.$('managePluginsAdvancedBtn'),
    refreshPluginsBtn: app.$('refreshPluginsBtn'),
    pluginsPagination: app.$('pluginsPagination'),
    ruleStatsPagination: app.$('ruleStatsPagination'),
    siteStatsPagination: app.$('siteStatsPagination'),
    rangeStatsPagination: app.$('rangeStatsPagination'),
    egressNATStatsPagination: app.$('egressNATStatsPagination')
  });

  let storedActiveTab = localStorage.getItem(app.storageKeys.activeTab);
  if (storedActiveTab === null) {
    storedActiveTab = localStorage.getItem(app.legacyStorageKeys.activeTab);
    if (storedActiveTab !== null) localStorage.setItem(app.storageKeys.activeTab, storedActiveTab);
  }
  app.state.activeTab = app.state.activeTab || storedActiveTab || 'rules';
  if (app.state.activeTab === 'workers' || app.state.activeTab === 'rule-stats') {
    app.state.activeTab = 'diagnostics';
  }
  app.state.managedNetworks = app.state.managedNetworks || { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.managedNetworkReservationCandidates = app.state.managedNetworkReservationCandidates || { data: [], page: 1, pageSize: 10, searchQuery: '', selectedIPv4ByKey: {} };
  app.state.managedNetworkReservations = app.state.managedNetworkReservations || { data: [], sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.plugins = app.state.plugins || { data: [], catalog: null, sortKey: '', sortAsc: true, page: 1, pageSize: 10 };
  app.state.plugins.selectedUpdateIDs = app.state.plugins.selectedUpdateIDs || {};
  app.state.plugins.applyingUpdate = app.state.plugins.applyingUpdate === true;
  app.state.plugins.manager = app.state.plugins.manager || {
    open: false,
    view: '',
    pluginID: '',
    tab: '',
    busy: false,
    stage: null,
    trustKeys: [],
    auditLogs: [],
    auditPluginID: '',
    auditHasMore: false,
    history: [],
    logs: null,
    logLevel: '',
    secrets: null
  };
  app.state.pendingRows = app.state.pendingRows || {};
  app.state.pendingForms = app.state.pendingForms || { rule: false, site: false, range: false, managedNetwork: false, managedNetworkReservation: false, egressNAT: false, ipv6Assignment: false };
  if (!Object.prototype.hasOwnProperty.call(app.state.pendingForms, 'managedNetwork')) app.state.pendingForms.managedNetwork = false;
  if (!Object.prototype.hasOwnProperty.call(app.state.pendingForms, 'managedNetworkReservation')) app.state.pendingForms.managedNetworkReservation = false;
  app.state.forms = app.state.forms || {};
  app.state.forms.managedNetwork = app.state.forms.managedNetwork || { mode: 'add', sourceId: 0 };
  app.state.forms.managedNetworkReservation = app.state.forms.managedNetworkReservation || { mode: 'add', sourceId: 0 };
  app.state.lastSyncAt = app.state.lastSyncAt || 0;
  app.state.requestFailures = app.state.requestFailures || {};
  app.state.confirmResolver = null;
  app.state.confirmFocusReturn = null;
  app.state.activeRequests = app.state.activeRequests || 0;
  app.state.syncFailureRetrying = app.state.syncFailureRetrying === true;
  app.state.pageVisible = typeof app.state.pageVisible === 'boolean' ? app.state.pageVisible : !document.hidden;
  app.state.activeDropdown = app.state.activeDropdown || null;
  app.state.dropdownPositionScheduled = false;
  app.state.pollRefreshInFlight = app.state.pollRefreshInFlight || null;

  app.paginationConfig = {
    rules: { container: app.el.rulesPagination, pageSizes: [10, 20, 50], render: () => app.renderRulesTable() },
    sites: { container: app.el.sitesPagination, pageSizes: [10, 20, 50], render: () => app.renderSitesTable() },
    ranges: { container: app.el.rangesPagination, pageSizes: [10, 20, 50], render: () => app.renderRangesTable() },
    managedNetworks: { container: app.el.managedNetworksPagination, pageSizes: [10, 20, 50], render: () => app.renderManagedNetworksTable() },
    managedNetworkReservationCandidates: { container: app.el.managedNetworkReservationCandidatesPagination, pageSizes: [10, 20, 50], render: () => app.renderManagedNetworkReservationCandidatesTable() },
    managedNetworkReservations: { container: app.el.managedNetworkReservationsPagination, pageSizes: [10, 20, 50], render: () => app.renderManagedNetworkReservationsTable() },
    egressNATs: { container: app.el.egressNATsPagination, pageSizes: [10, 20, 50], render: () => app.renderEgressNATsTable() },
    ipv6Assignments: { container: app.el.ipv6AssignmentsPagination, pageSizes: [10, 20, 50], render: () => app.renderIPv6AssignmentsTable() },
    workers: { container: app.el.workersPagination, pageSizes: [10, 20, 50], render: () => app.renderWorkersTable() },
    plugins: { container: app.el.pluginsPagination, pageSizes: [10, 20, 50], render: () => app.renderPluginsTable() },
    ruleStats: {
      container: app.el.ruleStatsPagination,
      pageSizes: [20, 50, 100],
      render: () => app.renderRuleStatsTable(),
      reload: () => app.loadRuleStats()
    },
    siteStats: { container: app.el.siteStatsPagination, pageSizes: [20, 50, 100], render: () => app.renderSiteStatsTable() },
    rangeStats: {
      container: app.el.rangeStatsPagination,
      pageSizes: [20, 50, 100],
      render: () => app.renderRangeStatsTable(),
      reload: () => app.loadRangeStats()
    },
    egressNATStats: {
      container: app.el.egressNATStatsPagination,
      pageSizes: [20, 50, 100],
      render: () => app.renderEgressNATStatsTable(),
      reload: () => app.loadEgressNATStats()
    }
  };

  ['rules', 'sites', 'ranges', 'managedNetworks', 'managedNetworkReservationCandidates', 'managedNetworkReservations', 'egressNATs', 'ipv6Assignments', 'workers', 'plugins', 'ruleStats', 'siteStats', 'rangeStats', 'egressNATStats'].forEach((table) => {
    if (!app.state[table]) return;
    app.state[table].searchQuery = app.state[table].searchQuery || '';
    app.state[table].page = Math.max(1, parseInt(app.state[table].page, 10) || 1);
    app.state[table].pageSize = Math.max(1, parseInt(app.state[table].pageSize, 10) || ((table.indexOf('Stats') >= 0) ? 20 : 10));
    if (table === 'rules' && !(app.state.rules.selectedIds instanceof Set)) {
      app.state.rules.selectedIds = new Set(app.state.rules.selectedIds || []);
    }
    if (table === 'managedNetworkReservationCandidates' && (!app.state[table].selectedIPv4ByKey || typeof app.state[table].selectedIPv4ByKey !== 'object')) {
      app.state[table].selectedIPv4ByKey = {};
    }
  });

  app.notify = function notify(type, message, timeout) {
    if (!app.el.toastStack || !message) return;

    const tone = type || 'info';
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + tone;
    // Errors interrupt (role=alert); everything else is announced politely by the stack.
    toast.setAttribute('role', tone === 'error' ? 'alert' : 'status');
    toast.textContent = message;
    app.el.toastStack.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('is-visible'));

    // DESIGN §5.9: toasts stay five seconds; errors and warnings stay longer so they can be read.
    const lifespan = timeout || (tone === 'error' || tone === 'warning' ? 8000 : 5000);
    window.setTimeout(() => {
      toast.classList.remove('is-visible');
      window.setTimeout(() => toast.remove(), 180);
    }, lifespan);
  };

  // Every floating layer (detail popovers, sync failures, row menus) is placed the same way: below
  // its trigger when the content fits there, otherwise on the roomier side, clamped to the viewport,
  // and capped in height so a long layer scrolls inside itself instead of running off screen.
  app.placeFloating = function placeFloating(panel, anchor, options) {
    if (!panel || !anchor || typeof anchor.getBoundingClientRect !== 'function') return;
    const opts = Object.assign({ align: 'start', offset: 8, margin: 12, maxHeight: 0 }, options || {});
    const root = document.documentElement || {};
    const viewportWidth = root.clientWidth || window.innerWidth || 0;
    const viewportHeight = window.innerHeight || root.clientHeight || 0;
    const rect = anchor.getBoundingClientRect();

    panel.style.maxHeight = '';
    panel.style.left = '0px';
    panel.style.top = '0px';
    const natural = panel.getBoundingClientRect().height;
    const cap = Math.max(120, Math.min(opts.maxHeight > 0 ? opts.maxHeight : Infinity, viewportHeight - opts.margin * 2));
    const below = viewportHeight - rect.bottom - opts.offset - opts.margin;
    const above = rect.top - opts.offset - opts.margin;
    const wanted = Math.min(natural, cap);
    const placeBelow = below >= wanted || below >= above;
    const room = Math.max(placeBelow ? below : above, Math.min(cap, 160));
    const height = Math.min(wanted, room);
    panel.style.maxHeight = Math.floor(Math.min(cap, room)) + 'px';

    const width = panel.getBoundingClientRect().width;
    let left = rect.left;
    if (opts.align === 'end') left = rect.right - width;
    else if (opts.align === 'center') left = rect.left + (rect.width - width) / 2;
    left = Math.min(Math.max(left, opts.margin), Math.max(opts.margin, viewportWidth - width - opts.margin));
    let top = placeBelow ? rect.bottom + opts.offset : rect.top - height - opts.offset;
    top = Math.min(Math.max(top, opts.margin), Math.max(opts.margin, viewportHeight - height - opts.margin));

    panel.style.left = Math.round(left) + 'px';
    panel.style.top = Math.round(top) + 'px';
  };

  // Floating layers close the same way: Escape (focus returns to the trigger), a press outside, or
  // focus moving elsewhere. They follow their trigger on scroll and resize and close once it is gone.
  const floatingLayers = [];
  let floatingListenersBound = false;

  function openFloatingLayers() {
    return floatingLayers.filter((layer) => layer.isOpen());
  }

  function floatingLayerHolds(layer, target) {
    if (!target) return false;
    if (layer.el && typeof layer.el.contains === 'function' && layer.el.contains(target)) return true;
    return !!(layer.trigger && typeof layer.trigger.contains === 'function' && layer.trigger.contains(target));
  }

  function bindFloatingListeners() {
    if (floatingListenersBound || typeof document.addEventListener !== 'function') return;
    floatingListenersBound = true;
    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape') return;
      const open = openFloatingLayers();
      if (!open.length) return;
      event.stopPropagation();
      open.forEach((layer) => layer.hide({
        restoreFocus: layer.pinned || floatingLayerHolds(layer, document.activeElement)
      }));
    }, true);
    document.addEventListener('pointerdown', (event) => {
      openFloatingLayers().forEach((layer) => {
        if (!floatingLayerHolds(layer, event.target)) layer.hide();
      });
    }, true);
    document.addEventListener('focusin', (event) => {
      openFloatingLayers().forEach((layer) => {
        if (!floatingLayerHolds(layer, event.target)) layer.hide();
      });
    });
    document.addEventListener('scroll', (event) => {
      openFloatingLayers().forEach((layer) => {
        if (layer.el.contains(event.target)) return;
        layer.position();
      });
    }, true);
    window.addEventListener('resize', () => openFloatingLayers().forEach((layer) => layer.position()));
  }

  // True while a layer the user opened on purpose (a click) is showing; hover previews wait.
  app.floatingLayerPinned = function floatingLayerPinned() {
    return openFloatingLayers().some((layer) => layer.pinned);
  };

  app.createFloatingLayer = function createFloatingLayer(options) {
    const opts = Object.assign({ id: '', className: '', role: 'dialog', label: '', placement: null }, options || {});
    const layer = {
      el: null,
      trigger: null,
      pinned: false,
      ensure() {
        if (layer.el) return layer.el;
        layer.el = app.createNode('div', {
          className: ['popover', opts.className].filter(Boolean).join(' '),
          attrs: Object.assign({ role: opts.role, hidden: true }, opts.id ? { id: opts.id } : null)
        });
        if (opts.label) layer.el.setAttribute('aria-label', opts.label);
        document.body.appendChild(layer.el);
        bindFloatingListeners();
        return layer.el;
      },
      isOpen() {
        return !!layer.el && !layer.el.hidden;
      },
      isOpenFor(trigger) {
        return layer.isOpen() && layer.trigger === trigger;
      },
      show(trigger, content, showOptions) {
        const showOpts = showOptions || {};
        const el = layer.ensure();
        floatingLayers.forEach((other) => {
          if (other !== layer && other.isOpen()) other.hide();
        });
        if (layer.trigger && layer.trigger !== trigger) layer.trigger.setAttribute('aria-expanded', 'false');
        layer.trigger = trigger || null;
        layer.pinned = !!showOpts.pinned;
        el.classList.toggle('is-pinned', layer.pinned);
        if (showOpts.label) el.setAttribute('aria-label', showOpts.label);
        app.clearNode(el);
        app.appendNodeContent(el, content);
        el.hidden = false;
        el.classList.add('is-visible');
        if (trigger) trigger.setAttribute('aria-expanded', 'true');
        layer.position();
      },
      hide(hideOptions) {
        const hideOpts = hideOptions || {};
        const trigger = layer.trigger;
        if (trigger) trigger.setAttribute('aria-expanded', 'false');
        layer.trigger = null;
        layer.pinned = false;
        if (layer.el) {
          layer.el.classList.remove('is-visible', 'is-pinned');
          layer.el.hidden = true;
          app.clearNode(layer.el);
        }
        if (hideOpts.restoreFocus && trigger && trigger.isConnected !== false && !trigger.disabled && typeof trigger.focus === 'function') {
          trigger.focus();
        }
        if (typeof opts.onHide === 'function') opts.onHide();
      },
      position() {
        if (!layer.isOpen()) return;
        const trigger = layer.trigger;
        if (!trigger) return;
        if (trigger.isConnected === false) {
          layer.hide();
          return;
        }
        const rect = trigger.getBoundingClientRect();
        const viewportHeight = window.innerHeight || (document.documentElement || {}).clientHeight || 0;
        if (rect.width === 0 && rect.height === 0) {
          layer.hide();
          return;
        }
        // A layer never hangs on without its anchor: once the trigger leaves the viewport it closes.
        if (rect.bottom < 0 || rect.top > viewportHeight) {
          layer.hide();
          return;
        }
        app.placeFloating(layer.el, trigger, opts.placement);
      }
    };
    floatingLayers.push(layer);
    return layer;
  };

  // Popover content blocks shared by every detail layer: a header (title, mono meta, close), titled
  // sections and label | value rows whose labels wrap instead of being cut off.
  app.popoverHeader = function popoverHeader(options) {
    const opts = options || {};
    const close = typeof opts.onClose === 'function'
      ? app.createNode('button', {
          className: ['popover-close'].concat(opts.closeClassName || []).join(' '),
          text: '×',
          attrs: { type: 'button', 'aria-label': app.t('common.close'), title: app.t('common.close') }
        })
      : null;
    if (close) {
      close.addEventListener('click', (event) => {
        event.stopPropagation();
        opts.onClose(event);
      });
    }
    return app.createNode('div', {
      className: ['popover-header'].concat(opts.className || []).join(' '),
      children: [
        app.createNode('div', {
          className: 'popover-heading',
          children: [
            app.createNode('span', { className: 'popover-title', text: opts.title || '' }),
            opts.meta ? app.createNode('span', { className: 'popover-meta' + (opts.metaMono === false ? '' : ' mono'), text: opts.meta }) : null
          ].filter(Boolean)
        }),
        opts.aside || opts.actions || close
          ? app.createNode('div', {
              className: 'popover-header-actions',
              children: [].concat(opts.aside || [], opts.actions || [], close || []).filter(Boolean)
            })
          : null
      ].filter(Boolean)
    });
  };

  app.popoverState = function popoverState(state, text) {
    const tone = state === 'ok' || state === 'bad' || state === 'warn' ? state : 'unknown';
    return app.createNode('span', { className: 'popover-state is-' + tone, text: text });
  };

  app.popoverRows = function popoverRows(rows, options) {
    const opts = options || {};
    const list = app.createNode('dl', { className: ['popover-rows'].concat(opts.className || []).join(' ') });
    (rows || []).filter(Boolean).forEach((row) => {
      const value = row.state
        ? app.popoverState(row.state, row.value)
        : row.node || app.createNode('span', { text: row.value == null || row.value === '' ? app.t('common.dash') : String(row.value) });
      list.appendChild(app.createNode('dt', { className: row.wide ? 'is-wide' : '', text: row.label }));
      list.appendChild(app.createNode('dd', {
        className: [row.mono ? 'mono' : '', row.wide ? 'is-wide' : '', row.tone ? 'is-' + row.tone : ''].filter(Boolean).join(' '),
        children: [value, row.hint ? app.createNode('span', { className: 'popover-hint', text: row.hint }) : null].filter(Boolean)
      }));
    });
    return list;
  };

  // A titled block; collapsible sections use <details> and show a short summary beside the title.
  app.popoverSection = function popoverSection(options) {
    const opts = options || {};
    const titleChildren = [
      app.createNode('span', { className: 'popover-section-label', text: opts.title || '' }),
      opts.summary ? app.createNode('span', { className: 'popover-section-summary' + (opts.tone ? ' is-' + opts.tone : ''), text: opts.summary }) : null
    ].filter(Boolean);
    const body = app.createNode('div', { className: 'popover-section-body', children: [].concat(opts.children || []).filter(Boolean) });
    if (opts.collapsible === false) {
      return app.createNode('div', {
        className: ['popover-section'].concat(opts.className || []).join(' '),
        children: [app.createNode('div', { className: 'popover-section-title', children: titleChildren }), body]
      });
    }
    return app.createNode('details', {
      className: ['popover-section'].concat(opts.className || []).join(' '),
      attrs: opts.open ? { open: true } : null,
      children: [app.createNode('summary', { className: 'popover-section-title', children: titleChildren }), body]
    });
  };

  app.positionDropdown = function positionDropdown(dropdown) {
    if (!dropdown) return;

    const trigger = dropdown.querySelector('.action-dropdown-trigger');
    const menu = dropdown.querySelector('.action-dropdown-menu');
    if (!trigger || !menu) return;

    menu.style.minWidth = Math.max(160, Math.ceil(trigger.getBoundingClientRect().width)) + 'px';
    app.placeFloating(menu, trigger, { align: 'end', offset: 6, margin: 8 });
  };

  app.scheduleDropdownPosition = function scheduleDropdownPosition() {
    if (!app.state.activeDropdown || app.state.dropdownPositionScheduled) return;
    app.state.dropdownPositionScheduled = true;
    requestAnimationFrame(() => {
      app.state.dropdownPositionScheduled = false;
      if (!app.state.activeDropdown) return;
      const dropdown = app.state.activeDropdown.dropdown;
      if (!dropdown || !dropdown.isConnected) {
        app.closeDropdowns();
        return;
      }
      app.positionDropdown(dropdown);
    });
  };

  app.openDropdown = function openDropdown(dropdown) {
    if (!dropdown) return;

    const trigger = dropdown.querySelector('.action-dropdown-trigger');
    if (!trigger || trigger.disabled) return;

    app.closeDropdowns();
    dropdown.classList.add('open');
    trigger.setAttribute('aria-expanded', 'true');
    app.state.activeDropdown = { dropdown: dropdown, trigger: trigger };
    app.positionDropdown(dropdown);
  };

  app.closeDropdowns = function closeDropdowns() {
    document.querySelectorAll('.action-dropdown.open').forEach((dropdown) => {
      dropdown.classList.remove('open');
      const trigger = dropdown.querySelector('.action-dropdown-trigger');
      const menu = dropdown.querySelector('.action-dropdown-menu');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
      if (menu) {
        menu.style.left = '';
        menu.style.top = '';
        menu.style.minWidth = '';
        menu.style.maxHeight = '';
      }
    });
    app.state.activeDropdown = null;
    app.state.dropdownPositionScheduled = false;
    if (typeof app.closeEgressNATProtocolMenu === 'function') app.closeEgressNATProtocolMenu();
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

  function appendDashboardLoader(tasks, name) {
    if (typeof app[name] === 'function') tasks.push(app[name]());
  }

  app.refreshActiveTab = function refreshActiveTab(tabId, options) {
    const target = String(tabId || app.state.activeTab || 'rules');
    const opts = options || {};
    const tasks = [];

    if (target === 'rules') appendDashboardLoader(tasks, 'loadRules');
    else if (target === 'sites') appendDashboardLoader(tasks, 'loadSites');
    else if (target === 'ranges') appendDashboardLoader(tasks, 'loadRanges');
    else if (target === 'managed-networks') {
      appendDashboardLoader(tasks, 'loadManagedNetworks');
      appendDashboardLoader(tasks, 'loadManagedNetworkReservations');
      if (opts.includeContext) appendDashboardLoader(tasks, 'loadHostNetwork');
    } else if (target === 'egress-nats') appendDashboardLoader(tasks, 'loadEgressNATs');
    else if (target === 'ipv6-assignments') {
      appendDashboardLoader(tasks, 'loadIPv6Assignments');
      if (opts.includeContext) appendDashboardLoader(tasks, 'loadHostNetwork');
    } else if (target === 'plugins' || target.indexOf('plugin-') === 0) {
      appendDashboardLoader(tasks, 'loadPlugins');
    } else if (target === 'diagnostics') {
      appendDashboardLoader(tasks, 'loadWorkers');
      appendDashboardLoader(tasks, 'loadAllStats');
    }

    return Promise.all(tasks);
  };

  app.refreshDashboard = function refreshDashboard(options) {
    const opts = Object.assign({
      activeTabOnly: false,
      activeTab: '',
      includeContext: false,
      includeMeta: false,
      includePlugins: false,
      includeWorkers: app.state.activeTab === 'diagnostics',
      includeStats: app.state.activeTab === 'diagnostics'
    }, options || {});

    if (opts.activeTabOnly) {
      return app.refreshActiveTab(opts.activeTab || app.state.activeTab, {
        includeContext: opts.includeContext
      });
    }

    const tasks = [];
    if (opts.includeMeta) {
      appendDashboardLoader(tasks, 'loadInterfaces');
      appendDashboardLoader(tasks, 'loadHostNetwork');
      appendDashboardLoader(tasks, 'loadTags');
    }
    appendDashboardLoader(tasks, 'loadRules');
    appendDashboardLoader(tasks, 'loadSites');
    appendDashboardLoader(tasks, 'loadRanges');
    appendDashboardLoader(tasks, 'loadManagedNetworks');
    appendDashboardLoader(tasks, 'loadManagedNetworkReservations');
    appendDashboardLoader(tasks, 'loadEgressNATs');
    appendDashboardLoader(tasks, 'loadIPv6Assignments');
    if (opts.includePlugins) appendDashboardLoader(tasks, 'loadPlugins');
    if (opts.includeWorkers) appendDashboardLoader(tasks, 'loadWorkers');
    if (opts.includeStats) appendDashboardLoader(tasks, 'loadAllStats');
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
      app.clearNode(config.container);
      return;
    }

    const info = app.getPaginationInfo(state, totalItems);
    config.container.hidden = false;
    app.clearNode(config.container);

    const summary = app.createNode('div', {
      className: 'table-pagination-summary',
      text: app.t('pagination.summary', {
        start: info.start,
        end: info.end,
        total: info.totalItems
      })
    });
    const actions = app.createNode('div', { className: 'table-pagination-actions' });
    const sizeLabel = app.createNode('label', { className: 'pagination-size-label' });
    const sizeText = app.createNode('span', { text: app.t('pagination.pageSize') });
    const sizeSelect = app.createNode('select', {
      className: 'pagination-size-select',
      dataset: { table: table }
    });
    (config.pageSizes || [10, 20, 50]).forEach((size) => {
      const option = document.createElement('option');
      option.value = String(size);
      option.textContent = String(size);
      option.selected = info.pageSize === size;
      sizeSelect.appendChild(option);
    });
    sizeLabel.appendChild(sizeText);
    sizeLabel.appendChild(sizeSelect);

    const prevBtn = app.createActionButton({
      className: 'pagination-btn',
      text: app.t('pagination.previous'),
      dataset: {
        table: table,
        page: info.page - 1
      },
      disabled: info.page <= 1
    });
    const pageLabel = app.createNode('span', {
      className: 'pagination-page-label',
      text: app.t('pagination.page', { page: info.page, totalPages: info.totalPages })
    });
    const nextBtn = app.createActionButton({
      className: 'pagination-btn',
      text: app.t('pagination.next'),
      dataset: {
        table: table,
        page: info.page + 1
      },
      disabled: info.page >= info.totalPages
    });

    actions.appendChild(sizeLabel);
    actions.appendChild(prevBtn);
    actions.appendChild(pageLabel);
    actions.appendChild(nextBtn);
    config.container.appendChild(summary);
    config.container.appendChild(actions);
  };

  app.goToPage = function goToPage(table, page) {
    const config = app.paginationConfig[table];
    const state = app.state[table];
    if (!config || !state || typeof config.render !== 'function') return;
    state.page = Math.max(1, parseInt(page, 10) || 1);
    if (typeof config.reload === 'function') {
      config.reload();
      return;
    }
    config.render();
  };

  app.setPageSize = function setPageSize(table, pageSize) {
    const config = app.paginationConfig[table];
    const state = app.state[table];
    if (!config || !state || typeof config.render !== 'function') return;
    state.pageSize = Math.max(1, parseInt(pageSize, 10) || state.pageSize || 10);
    state.page = 1;
    if (typeof config.reload === 'function') {
      config.reload();
      return;
    }
    config.render();
  };

  function requestFailureKey(method, path) {
    if (String(method || '').toUpperCase() !== 'GET') return '';
    const requestPath = String(path || '').trim();
    if (!requestPath) return '';
    return 'GET ' + requestPath.split(/[?#]/, 1)[0];
  }

  function requestFailureEntries() {
    return Object.values(app.state.requestFailures || {})
      .sort((left, right) => Number(right.at || 0) - Number(left.at || 0));
  }

  function retryableRequestFailures(failures) {
    const loaders = app.requestFailureLoaders || {};
    return (failures || []).filter((failure) => {
      const loaderName = loaders[String(failure && failure.path || '')];
      return !!loaderName && typeof app[loaderName] === 'function';
    });
  }

  let syncFailureLayer = null;

  function syncFailurePopoverLayer() {
    if (!syncFailureLayer) {
      syncFailureLayer = app.createFloatingLayer({
        id: 'overviewSyncPopover',
        className: 'overview-sync-popover',
        role: 'dialog',
        placement: { align: 'end', maxHeight: 360 }
      });
    }
    return syncFailureLayer;
  }

  function hideSyncFailurePopover(options) {
    if (app.el.lastSyncLabel) app.el.lastSyncLabel.setAttribute('aria-expanded', 'false');
    if (syncFailureLayer) syncFailureLayer.hide(options);
  }

  function renderSyncFailurePopover() {
    const failures = requestFailureEntries();
    if (!failures.length) {
      hideSyncFailurePopover();
      return;
    }

    const retrying = app.state.syncFailureRetrying === true;
    const retryableFailures = retryableRequestFailures(failures);

    const retryButton = retryableFailures.length
      ? app.createNode('button', {
        className: 'mini-btn' + (retrying ? ' is-busy' : ''),
        text: app.t(retrying ? 'overview.syncRetrying' : 'common.retry'),
        attrs: { type: 'button', 'aria-busy': retrying ? 'true' : 'false' },
        disabled: retrying
      })
      : null;
    if (retryButton) {
      retryButton.addEventListener('click', (event) => {
        event.stopPropagation();
        app.retryRequestFailures();
      });
    }

    const layer = syncFailurePopoverLayer();
    layer.show(app.el.lastSyncLabel, [
      app.popoverHeader({
        className: 'overview-sync-popover-header',
        title: app.t('overview.syncFailed', { count: failures.length }),
        meta: app.t(retryableFailures.length ? 'overview.syncFailuresHint' : 'overview.syncFailuresManualHint'),
        metaMono: false,
        onClose: () => hideSyncFailurePopover({ restoreFocus: true })
      }),
      app.createNode('ul', {
        className: 'popover-list overview-sync-failure-list',
        children: failures.map((failure) => app.createNode('li', {
          className: 'popover-list-item is-warn overview-sync-failure',
          children: [
            app.createNode('span', {
              className: 'popover-list-title mono overview-sync-failure-path',
              text: failure.path || app.t('common.unknown')
            }),
            app.createNode('span', {
              className: 'popover-list-text overview-sync-failure-message',
              text: failure.message || app.t('common.unknown')
            })
          ]
        }))
      }),
      retryableFailures.length ? app.createNode('div', {
        className: 'popover-actions overview-sync-popover-actions',
        children: [retryButton]
      }) : null
    ].filter(Boolean), { pinned: true, label: app.t('overview.syncFailuresTitle') });
  }

  app.toggleSyncFailurePopover = function toggleSyncFailurePopover() {
    if (!app.el.lastSyncLabel || app.el.lastSyncLabel.disabled) return;
    if (syncFailureLayer && syncFailureLayer.isOpen()) {
      hideSyncFailurePopover();
      return;
    }
    renderSyncFailurePopover();
  };

  app.retryRequestFailures = async function retryRequestFailures() {
    const failures = requestFailureEntries();
    if (app.state.syncFailureRetrying || !retryableRequestFailures(failures).length) return;
    app.state.syncFailureRetrying = true;
    renderSyncFailurePopover();

    try {
      if (typeof app.retryFailedDataLoads === 'function') {
        await app.retryFailedDataLoads({ force: true, limit: 16 });
      } else {
        await app.refreshDashboard({ includeMeta: true, includePlugins: true, includeWorkers: true, includeStats: true });
      }
    } finally {
      app.state.syncFailureRetrying = false;
      const remaining = requestFailureEntries().length;
      app.renderOverview();
      if (remaining) {
        renderSyncFailurePopover();
        app.notify('warning', app.t('overview.syncRetryRemaining', { count: remaining }));
      } else {
        hideSyncFailurePopover();
        app.notify('success', app.t('overview.syncRestored'));
      }
    }
  };

  if (app.el.lastSyncLabel) {
    app.el.lastSyncLabel.addEventListener('click', (event) => {
      event.stopPropagation();
      app.toggleSyncFailurePopover();
    });
    app.el.lastSyncLabel.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        app.toggleSyncFailurePopover();
      } else if (event.key === 'Escape') {
        hideSyncFailurePopover();
      }
    });
  }

  function isMissingPluginResourceRecord(method, path, error) {
    if (String(method || '').toUpperCase() !== 'GET' || Number(error && error.status) !== 404) return false;
    const segments = String(path || '').trim().split(/[?#]/, 1)[0].split('/').filter(Boolean);
    if (segments.length !== 6 || segments[0] !== 'api' || segments[1] !== 'plugins' || segments[3] !== 'resources') {
      return false;
    }
    const payload = error && error.payload && typeof error.payload === 'object' ? error.payload : {};
    const code = String(payload.code || '').trim().toLowerCase();
    const message = String(payload.error || (error && error.message) || '').trim().toLowerCase();
    return code === 'plugin_resource_record_not_found' || message === 'record not found';
  }

  app.recordRequestFailure = function recordRequestFailure(method, path, error) {
    const key = requestFailureKey(method, path);
    if (!key || (error && error.message === 'unauthorized')) return;
    if (isMissingPluginResourceRecord(method, path, error)) {
      app.clearRequestFailure(method, path);
      return;
    }

    const failures = app.state.requestFailures || {};
    const firstFailure = Object.keys(failures).length === 0;
    const message = String(error && error.message || error || app.t('common.unknown')).trim().slice(0, 240);
    failures[key] = {
      key: key,
      path: key.slice(4),
      message: message || app.t('common.unknown'),
      at: Date.now()
    };
    const keys = Object.keys(failures);
    if (keys.length > 16) {
      keys.sort((left, right) => Number(failures[left].at || 0) - Number(failures[right].at || 0));
      keys.slice(0, keys.length - 16).forEach((oldKey) => delete failures[oldKey]);
    }
    app.state.requestFailures = failures;
    if (firstFailure && typeof app.notify === 'function') {
      const retryable = retryableRequestFailures([failures[key]]).length > 0;
      app.notify('warning', app.t(retryable ? 'overview.syncFailedToast' : 'overview.syncFailedManualToast', {
        message: failures[key].message
      }));
    }
    app.renderOverview();
  };

  app.clearRequestFailure = function clearRequestFailure(method, path) {
    const key = requestFailureKey(method, path);
    if (!key || !app.state.requestFailures || !Object.prototype.hasOwnProperty.call(app.state.requestFailures, key)) return;
    delete app.state.requestFailures[key];
    app.renderOverview();
  };

  app.renderOverview = function renderOverview() {
    if (app.el.overviewRulesValue) app.el.overviewRulesValue.textContent = String((app.state.rules.data || []).length);
    if (app.el.overviewSitesValue) app.el.overviewSitesValue.textContent = String((app.state.sites.data || []).length);
    if (app.el.overviewRangesValue) app.el.overviewRangesValue.textContent = String((app.state.ranges.data || []).length);
    if (app.el.overviewWorkersValue) app.el.overviewWorkersValue.textContent = String((app.state.workers.data || []).length);

    const runningTotal =
      (app.state.rules.data || []).filter((item) => item.enabled !== false && item.status === 'running').length +
      (app.state.sites.data || []).filter((item) => item.enabled !== false && item.status === 'running').length +
      (app.state.ranges.data || []).filter((item) => item.enabled !== false && item.status === 'running').length +
      (app.state.egressNATs.data || []).filter((item) => item.enabled !== false && item.status === 'running').length;

    if (app.el.overviewRunningValue) app.el.overviewRunningValue.textContent = String(runningTotal);
    const busy = app.state.activeRequests > 0;
    [app.el.refreshNowBtn, app.el.refreshWorkersBtn, app.el.emptyRefreshWorkersBtn, app.el.applyPluginUpdateBtn, app.el.refreshPluginsBtn, app.el.repairManagedNetworkRuntimeBtn, app.el.reloadManagedNetworkRuntimeBtn].forEach((button) => {
      if (!button) return;
      button.disabled = busy;
      button.classList.toggle('is-busy', busy);
      button.setAttribute('aria-busy', busy ? 'true' : 'false');
    });
    (app.el.refreshCurrentConnsBtns || []).forEach((button) => {
      if (!button) return;
      button.disabled = busy;
      button.classList.toggle('is-busy', busy);
      button.setAttribute('aria-busy', busy ? 'true' : 'false');
    });
    if (app.el.lastSyncLabel) {
      const failures = requestFailureEntries();
      const showFailure = !busy && failures.length > 0;
      app.el.lastSyncLabel.classList.toggle('is-error', showFailure);
      app.el.lastSyncLabel.disabled = !showFailure;
      if (busy) {
        app.el.lastSyncLabel.textContent = app.t('overview.syncing');
        app.el.lastSyncLabel.title = '';
      } else if (showFailure) {
        app.el.lastSyncLabel.textContent = app.t('overview.syncFailed', { count: failures.length });
        app.el.lastSyncLabel.title = '';
        app.el.lastSyncLabel.setAttribute('aria-controls', 'overviewSyncPopover');
        app.el.lastSyncLabel.setAttribute('aria-haspopup', 'dialog');
        app.el.lastSyncLabel.setAttribute('aria-label', app.t('overview.syncFailed', { count: failures.length }) + '. ' + app.t('overview.syncFailuresTitle'));
      } else {
        app.el.lastSyncLabel.textContent = app.state.lastSyncAt
          ? app.t('overview.lastSync', { time: new Intl.RelativeTimeFormat(app.state.locale, { numeric: 'auto' }).format(-Math.max(0, Math.floor((Date.now() - app.state.lastSyncAt) / 1000)), 'second') })
          : app.t('overview.awaitingSync');
        app.el.lastSyncLabel.title = app.state.lastSyncAt ? new Date(app.state.lastSyncAt).toLocaleString(app.state.locale) : '';
        app.el.lastSyncLabel.removeAttribute('aria-controls');
        app.el.lastSyncLabel.removeAttribute('aria-haspopup');
        app.el.lastSyncLabel.removeAttribute('aria-label');
        hideSyncFailurePopover();
      }
      if (!busy && failures.length && syncFailureLayer && syncFailureLayer.isOpen() && !app.state.syncFailureRetrying) {
        renderSyncFailurePopover();
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
      managedNetworks: { meta: app.el.managedNetworksFilterMeta, clear: app.el.clearManagedNetworksFilter },
      managedNetworkReservationCandidates: { meta: app.el.managedNetworkReservationCandidatesFilterMeta, clear: app.el.clearManagedNetworkReservationCandidatesFilter },
      managedNetworkReservations: { meta: app.el.managedNetworkReservationsFilterMeta, clear: app.el.clearManagedNetworkReservationsFilter },
      egressNATs: { meta: app.el.egressNATsFilterMeta, clear: app.el.clearEgressNATsFilter },
      ipv6Assignments: { meta: app.el.ipv6AssignmentsFilterMeta, clear: app.el.clearIPv6AssignmentsFilter },
      workers: { meta: app.el.workersFilterMeta, clear: null },
      plugins: { meta: app.el.pluginsFilterMeta, clear: null }
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
    return app.refreshDashboard({
      activeTabOnly: true,
      activeTab: target,
      includeContext: true
    });
  };

  app.updateOverviewVisibility = function updateOverviewVisibility(tabId) {
    if (!app.el.overviewPanel) return;
    const visibleTabs = new Set(['rules', 'sites', 'ranges', 'managed-networks', 'egress-nats', 'ipv6-assignments']);
    app.el.overviewPanel.hidden = !visibleTabs.has(String(tabId || ''));
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
    app.updateOverviewVisibility(tabId);
    if (opts.persist !== false) {
      localStorage.setItem(app.storageKeys.activeTab, tabId);
      localStorage.setItem(app.legacyStorageKeys.activeTab, tabId);
    }
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
      app.renderFilterMeta('managedNetworks');
      app.renderFilterMeta('managedNetworkReservationCandidates');
      app.renderFilterMeta('managedNetworkReservations');
      app.renderFilterMeta('egressNATs');
      app.renderFilterMeta('ipv6Assignments');
      app.renderFilterMeta('workers');
      app.renderFilterMeta('plugins');
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
      return original.apply(app, arguments);
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

  app.validateIPField = function validateIPField(input) {
    if (!input) return true;
    const value = input.value == null ? '' : String(input.value).trim();
    if (app.isValidIP(value)) {
      app.clearFieldError(input);
      return true;
    }
    app.setFieldError(input, app.t('validation.ip'));
    return false;
  };

  app.validateIPv4Field = app.validateIPField;

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
    { button: app.el.clearRangesFilter, table: 'ranges', render: () => app.renderRangesTable() },
    { button: app.el.clearManagedNetworksFilter, table: 'managedNetworks', render: () => app.renderManagedNetworksTable() },
    { button: app.el.clearManagedNetworkReservationCandidatesFilter, table: 'managedNetworkReservationCandidates', render: () => app.renderManagedNetworkReservationCandidatesTable() },
    { button: app.el.clearManagedNetworkReservationsFilter, table: 'managedNetworkReservations', render: () => app.renderManagedNetworkReservationsTable() },
    { button: app.el.clearEgressNATsFilter, table: 'egressNATs', render: () => app.renderEgressNATsTable() },
    { button: app.el.clearIPv6AssignmentsFilter, table: 'ipv6Assignments', render: () => app.renderIPv6AssignmentsTable() }
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

  window.addEventListener('resize', app.scheduleDropdownPosition);
  document.addEventListener('scroll', app.scheduleDropdownPosition, true);

  app.apiCall = (function wrapApiCall(original) {
    return async function apiCall(method, path, body) {
      app.state.activeRequests++;
      app.renderOverview();
      try {
        const result = await original(method, path, body);
        app.clearRequestFailure(method, path);
        return result;
      } catch (error) {
        app.recordRequestFailure(method, path, error);
        throw error;
      } finally {
        app.state.activeRequests = Math.max(0, app.state.activeRequests - 1);
        app.renderOverview();
      }
    };
  })(app.apiCall);

  app.renderOverview();
})();
