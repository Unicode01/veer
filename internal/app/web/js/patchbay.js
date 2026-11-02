(function () {
  'use strict';
  const app = window.VeerApp;
  if (!app || !app.el.appRoot) return;
  const node = (tag, options) => app.createNode(tag, options || {});
  const text = (key, params) => app.t(key, params);
  const configs = [
    { tab: 'rules', state: 'rules', stem: 'Rule', form: 'rule', title: 'tab.rules', color: 'blue', render: 'renderRulesTable', idColumn: 1 },
    { tab: 'sites', state: 'sites', stem: 'Site', form: 'site', title: 'tab.sites', color: 'violet', render: 'renderSitesTable', idColumn: 0 },
    { tab: 'ranges', state: 'ranges', stem: 'Range', form: 'range', title: 'tab.ranges', color: 'green', render: 'renderRangesTable', idColumn: 0 },
    { tab: 'managed-networks', state: 'managedNetworks', stem: 'ManagedNetwork', form: 'managedNetwork', title: 'tab.managedNetworks', color: 'brown', render: 'renderManagedNetworksTable', idColumn: 0 },
    { tab: 'egress-nats', state: 'egressNATs', stem: 'EgressNAT', form: 'egressNAT', title: 'tab.egressNATs', color: 'slate', render: 'renderEgressNATsTable', idColumn: 0 },
    { tab: 'ipv6-assignments', state: 'ipv6Assignments', stem: 'IPv6Assignment', form: 'ipv6Assignment', title: 'tab.ipv6Assignments', color: 'rose', render: 'renderIPv6AssignmentsTable', idColumn: 0 }
  ];
  const reservation = { tab: 'managed-networks', state: 'managedNetworkReservations', stem: 'ManagedNetworkReservation', form: 'managedNetworkReservation', title: 'managedNetworkReservation.list.title', color: 'brown' };
  const allForms = configs.concat(reservation);
  let activeDrawer = null;
  let drawerSnapshot = '';
  let drawerReturn = null;
  let commandReturn = null;
  let closingDrawer = false;
  let sidebarOpen = false;
  let commandIndex = 0;
  let commands = [];
  let pendingHash = '';
  let selectedNetworkID = 0;
  let networkSubview = 'overview';
  const shell = {};

  function wrap(name, after) {
    const original = app[name];
    if (typeof original !== 'function') return;
    app[name] = function () {
      const result = original.apply(app, arguments);
      after.apply(app, arguments);
      return result;
    };
  }

  function tone(item) {
    if (item.enabled === false) return 'off';
    const values = [item.status, item.runtime_status, item.ipv4_runtime_status, item.ipv6_runtime_status].filter(Boolean).map(String);
    if (item.runtime_error || values.some((value) => /error|failed|degraded|conflict/.test(value))) return 'attention';
    if (values.some((value) => /^(running|active|ready|applied|up|ok)$/.test(value))) return 'live';
    return 'pending';
  }

  function routeParts(cfg, item) {
    switch (cfg.state) {
      case 'rules': return [[item.in_interface, item.in_ip, item.in_port], [item.out_interface, item.out_ip, item.out_port]];
      case 'sites': return [[item.listen_interface, item.listen_ip, [Number(item.backend_http_port) > 0 ? 80 : null, Number(item.backend_https_port) > 0 ? 443 : null].filter(Boolean).join(' / ')], ['', item.backend_ip, [item.backend_http_port, item.backend_https_port].filter((port) => Number(port) > 0).join(' / ')]];
      case 'ranges': {
        const start = Number(item.out_start_port) || Number(item.start_port);
        return [[item.in_interface, item.in_ip, item.start_port && item.start_port + '–' + item.end_port], [item.out_interface, item.out_ip, start && start + '–' + (start + Number(item.end_port) - Number(item.start_port))]];
      }
      case 'egressNATs': return [[item.parent_interface, item.child_interface || text('patchbay.allDevices'), ''], [item.out_interface, item.out_source_ip || text('common.auto'), '']];
      case 'ipv6Assignments': return [[item.parent_interface, item.parent_prefix, ''], [item.target_interface, item.assigned_prefix || item.address, '']];
      case 'managedNetworks': return [[item.bridge, item.ipv4_cidr || item.name, ''], [item.uplink_interface || item.ipv6_parent_interface, item.ipv6_parent_prefix || text('patchbay.upstream'), '']];
      default: return [[], []];
    }
  }

  function portLabel(parts) {
    const label = node('span', { className: 'port-label' });
    if (parts[0]) label.appendChild(node('span', { className: 'port-interface', text: parts[0] }));
    label.appendChild(node('span', { className: 'port-address', text: parts[1] || '—' }));
    if (parts[2]) label.appendChild(node('strong', { className: 'port-number', text: ':' + parts[2] }));
    label.title = parts.filter(Boolean).join(' · ');
    return label;
  }

  function routeNode(cfg, item) {
    const parts = routeParts(cfg, item);
    return node('div', {
      className: 'patch-route route-' + cfg.color + (item.enabled === false ? ' route-off' : ''),
      children: [portLabel(parts[0]), node('span', { className: 'patch-cable', attrs: { 'aria-hidden': 'true' } }), portLabel(parts[1])]
    });
  }

  function configForTab(tab) { return configs.find((cfg) => cfg.tab === tab); }
  function pageTitle() {
    const cfg = configForTab(app.state.activeTab);
    if (cfg) return text(cfg.title);
    const button = document.getElementById('tab-' + app.state.activeTab + '-button');
    return button ? (button.dataset.pageTitle || button.textContent) : text('tab.rules');
  }
  function groupKey(tab) {
    if (['rules', 'sites', 'ranges'].includes(tab)) return 'patchbay.nav.entry';
    if (['managed-networks', 'egress-nats', 'ipv6-assignments'].includes(tab)) return 'patchbay.nav.network';
    return tab === 'diagnostics' ? 'patchbay.nav.runtime' : 'patchbay.nav.extensions';
  }

  function icon(path, size) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', size || '16');
    svg.setAttribute('height', size || '16');
    svg.setAttribute('aria-hidden', 'true');
    const line = document.createElementNS(svg.namespaceURI, 'path');
    Object.entries({ d: path, fill: 'none', stroke: 'currentColor', 'stroke-width': '1.7', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }).forEach(([key, value]) => line.setAttribute(key, value));
    svg.appendChild(line);
    return svg;
  }

  function closeThemeMenu(restoreFocus) {
    if (!shell.themeMenu || shell.themeMenu.hidden) return;
    shell.themeMenu.hidden = true;
    shell.themeButton.setAttribute('aria-expanded', 'false');
    if (restoreFocus) shell.themeButton.focus();
  }

  function renderSettings() {
    if (!shell.themeButton) return;
    shell.themeButton.title = text('toolbar.theme') + ': ' + text('theme.' + app.state.theme);
    shell.themeButton.setAttribute('aria-label', shell.themeButton.title);
    shell.themeLabel.textContent = text('toolbar.theme');
    shell.themeMenu.setAttribute('aria-label', text('toolbar.theme'));
    shell.themeMenu.querySelectorAll('button').forEach((button) => {
      button.textContent = text('theme.' + button.dataset.theme);
      button.setAttribute('aria-checked', String(button.dataset.theme === app.state.theme));
    });
    shell.localeButton.textContent = app.state.locale === 'en-US' ? '中文' : 'EN';
    shell.localeButton.title = app.state.locale === 'en-US' ? '切换为简体中文' : 'Switch to English';
    shell.localeButton.setAttribute('aria-label', shell.localeButton.title);
  }

  function buildSettings(actions) {
    actions.className = 'sidebar-settings';
    actions.querySelectorAll('.toolbar-field').forEach((label) => { label.hidden = true; });
    shell.themeLabel = node('span');
    shell.themeButton = node('button', { className: 'sidebar-tool', attrs: { type: 'button', id: 'themeMenuButton', 'aria-haspopup': 'menu', 'aria-controls': 'themeMenu', 'aria-expanded': 'false' }, children: [icon('M12 3a9 9 0 1 0 0 18V3Z M12 3a9 9 0 0 1 0 18'), shell.themeLabel] });
    shell.themeMenu = node('div', { className: 'theme-menu', attrs: { id: 'themeMenu', role: 'menu', hidden: '' } });
    ['system', 'light', 'dark'].forEach((theme) => {
      const button = node('button', { attrs: { type: 'button', role: 'menuitemradio', tabindex: '-1' }, dataset: { theme } });
      button.addEventListener('click', () => { app.setTheme(theme); closeThemeMenu(true); });
      shell.themeMenu.appendChild(button);
    });
    const openThemeMenu = () => {
      shell.themeMenu.hidden = false;
      shell.themeButton.setAttribute('aria-expanded', 'true');
      shell.themeMenu.querySelector('[aria-checked="true"]').focus();
    };
    shell.themeButton.addEventListener('click', () => { if (shell.themeMenu.hidden) openThemeMenu(); else closeThemeMenu(true); });
    shell.themeButton.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); openThemeMenu(); }
    });
    shell.themeMenu.addEventListener('keydown', (event) => {
      const buttons = Array.from(shell.themeMenu.children);
      const index = buttons.indexOf(document.activeElement);
      if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault();
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (index + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length;
        buttons[next].focus();
      }
      if (event.key === 'Escape' || event.key === 'Tab') {
        event.preventDefault();
        event.stopPropagation();
        closeThemeMenu(true);
        if (event.key === 'Tab' && !event.shiftKey) shell.localeButton.focus();
      }
    });
    shell.localeButton = node('button', { className: 'sidebar-tool locale-tool', attrs: { type: 'button', id: 'localeToggle' } });
    shell.localeButton.addEventListener('click', () => { closeThemeMenu(false); app.setLocale(app.state.locale === 'en-US' ? 'zh-CN' : 'en-US'); });
    const logout = actions.querySelector('#logoutBtn');
    logout.className = 'sidebar-tool';
    logout.addEventListener('click', () => closeThemeMenu(false));
    actions.append(shell.themeMenu, shell.themeButton, shell.localeButton, logout);
    document.addEventListener('pointerdown', (event) => { if (!actions.contains(event.target)) closeThemeMenu(false); });
    document.addEventListener('focusin', (event) => { if (!actions.contains(event.target)) closeThemeMenu(false); });
    renderSettings();
  }

  function buildShell() {
    const root = app.el.appRoot;
    root.classList.add('patchbay');
    const oldHeader = root.querySelector('header');
    const tabs = root.querySelector('.tabs');
    const actions = oldHeader.querySelector('.header-actions');
    const brand = oldHeader.querySelector('.header-title');
    brand.className = 'sidebar-brand';
    brand.insertBefore(icon('M3 6h7l4 12h7 M19 18a2 2 0 1 0 4 0 2 2 0 1 0-4 0', '24'), brand.firstChild);
    brand.appendChild(app.$('masterVersion'));
    shell.host = node('div', { className: 'host-card', children: [
      node('strong', { className: 'mono', text: window.location.hostname || 'Veer', attrs: { id: 'hostName' } }),
      node('dl', { children: [
        node('dt', { text: text('patchbay.hostSystem'), dataset: { i18n: 'patchbay.hostSystem' } }), node('dd', { attrs: { id: 'hostPlatform' } }),
        node('dt', { text: text('patchbay.hostKernel'), dataset: { i18n: 'patchbay.hostKernel' } }), node('dd', { attrs: { id: 'hostKernel' } })
      ] }),
      node('span', { className: 'host-uptime', attrs: { id: 'hostUptime' } })
    ] });
    shell.sidebar = node('aside', { className: 'sidebar', attrs: { id: 'mainSidebar' }, children: [brand, shell.host] });
    const nav = node('nav', { attrs: { 'aria-label': text('patchbay.navigation') }, children: [tabs] });
    tabs.setAttribute('aria-orientation', 'vertical');
    shell.sidebar.appendChild(nav);
    buildSettings(actions);
    shell.sidebar.appendChild(actions);
    root.prepend(shell.sidebar);
    shell.main = node('main', { className: 'workspace', attrs: { id: 'mainContent' } });
    const mobile = node('button', { className: 'icon-button mobile-menu', text: '☰', attrs: { type: 'button', id: 'sidebarToggle', 'aria-controls': 'mainSidebar', 'aria-expanded': 'false', 'aria-label': text('patchbay.navigation') } });
    mobile.addEventListener('click', () => setSidebar(!sidebarOpen));
    shell.breadcrumb = node('div', { className: 'breadcrumb' });
    shell.commandButton = node('button', { className: 'command-trigger', attrs: { id: 'openCommandPalette', type: 'button' }, children: [node('span', { text: text('patchbay.search'), dataset: { i18n: 'patchbay.search' } }), node('kbd', { text: 'Ctrl K' })] });
    shell.commandButton.addEventListener('click', openCommand);
    const topbar = node('div', { className: 'topbar', children: [mobile, shell.breadcrumb, node('div', { className: 'topbar-actions', children: [shell.commandButton, app.el.lastSyncLabel, app.el.refreshNowBtn] })] });
    shell.main.appendChild(topbar);
    shell.content = node('div', { className: 'page-content' });
    shell.heading = node('div', { className: 'page-heading', children: [node('div', { children: [
      node('p', { className: 'page-eyebrow', attrs: { id: 'pageEyebrow' } }),
      node('h1', { attrs: { id: 'pageTitle' } }),
      node('p', { className: 'page-description', attrs: { id: 'pageDescription' } })
    ] })] });
    shell.create = node('button', { className: 'primary-button', attrs: { id: 'createResourceBtn', type: 'button' } });
    shell.create.addEventListener('click', () => startCreate(configForTab(app.state.activeTab)));
    shell.heading.appendChild(shell.create);
    shell.content.appendChild(shell.heading);
    Array.from(root.children).forEach((child) => {
      if (child === shell.sidebar || child === oldHeader) return;
      shell.content.appendChild(child);
    });
    oldHeader.remove();
    shell.main.appendChild(shell.content);
    root.appendChild(shell.main);
    shell.navBackdrop = node('button', { className: 'sidebar-backdrop', attrs: { type: 'button', hidden: '', 'aria-label': text('common.close') } });
    shell.navBackdrop.addEventListener('click', () => setSidebar(false));
    root.appendChild(shell.navBackdrop);
    const overview = app.el.overviewPanel;
    Array.from(overview.children).forEach((child) => { child.hidden = true; });
    shell.kpis = node('div', { className: 'kpi-strip' });
    overview.appendChild(shell.kpis);
    [['rules', 'entry'], ['managed-networks', 'network'], ['plugins', 'extensions'], ['diagnostics', 'runtime']].forEach(([tab, group]) => {
      const label = node('p', { className: 'nav-group nav-group-' + group, text: text('patchbay.nav.' + group), dataset: { i18n: 'patchbay.nav.' + group } });
      tabs.insertBefore(label, app.$('tab-' + tab + '-button'));
    });
  }

  function setSidebar(open) {
    if (!open) closeThemeMenu(false);
    sidebarOpen = !!open;
    shell.sidebar.classList.toggle('is-open', sidebarOpen);
    shell.navBackdrop.hidden = !sidebarOpen;
    app.$('sidebarToggle').setAttribute('aria-expanded', String(sidebarOpen));
    syncInert();
    if (sidebarOpen) (shell.sidebar.querySelector('.tab.active') || shell.sidebar.querySelector('button')).focus();
    else if (document.activeElement && shell.sidebar.contains(document.activeElement) && window.innerWidth < 860) app.$('sidebarToggle').focus();
  }

  function syncInert() {
    const modal = !!activeDrawer || !!(shell.command && !shell.command.hidden);
    shell.main.inert = modal || sidebarOpen;
    shell.sidebar.inert = modal || (window.innerWidth < 860 && !sidebarOpen);
    document.body.classList.toggle('overlay-open', modal || sidebarOpen);
  }

  function renderShell() {
    if (!shell.heading) return;
    const tab = app.state.activeTab || 'rules';
    const cfg = configForTab(tab);
    const title = pageTitle();
    shell.breadcrumb.replaceChildren(node('span', { text: text(groupKey(tab)) }), node('span', { className: 'breadcrumb-separator', text: '/' }), node('strong', { text: title }));
    app.$('pageTitle').textContent = title;
    app.$('pageEyebrow').textContent = text(groupKey(tab));
    app.$('pageDescription').textContent = text('patchbay.desc.' + (cfg ? cfg.state : tab === 'diagnostics' ? 'diagnostics' : 'plugins'));
    shell.heading.className = 'page-heading' + (cfg ? ' resource-' + cfg.color : '');
    shell.heading.hidden = tab.startsWith('plugin-');
    shell.create.hidden = !cfg || (tab === 'managed-networks' && selectedNetworkID > 0);
    if (cfg) shell.create.textContent = text('patchbay.create.' + cfg.state);
    document.querySelectorAll('.tabs .tab').forEach((button) => {
      const id = button.dataset.tab;
      const resource = configForTab(id);
      button.setAttribute('aria-current', id === tab ? 'page' : 'false');
      if (!button.dataset.pageTitle || resource || !id.startsWith('plugin-')) {
        button.dataset.pageTitle = resource ? text(resource.title) : id === 'plugins' ? text('tab.plugins') : id === 'diagnostics' ? text('tab.diagnostics') : button.textContent;
      }
      if (resource) button.dataset.resourceColor = resource.color;
      if (id.startsWith('plugin-')) {
        const plugin = (app.state.plugins.data || []).find((item) => item.id === button.title);
        button.dataset.pluginStatus = plugin ? plugin.status : '';
      }
      const count = resource ? (app.state[resource.state].data || []).length : id === 'plugins' ? (app.state.plugins.data || []).length : null;
      button.replaceChildren(node('span', { className: 'nav-label', text: button.dataset.pageTitle }));
      if (count !== null) button.appendChild(node('span', { className: 'nav-count', text: Number(count).toLocaleString() }));
    });
    if (cfg) {
      const rows = app.state[cfg.state].data || [];
      const values = [rows.length, rows.filter((item) => tone(item) === 'live').length, rows.filter((item) => tone(item) === 'attention').length, rows.filter((item) => tone(item) === 'off').length];
      shell.kpis.replaceChildren(...['total', 'live', 'attention', 'off'].map((key, index) => node('div', { className: 'kpi', children: [node('span', { text: text('patchbay.status.' + key) }), node('strong', { text: values[index].toLocaleString() })] })));
    }
    const caps = app.state.kernelRuntime && app.state.kernelRuntime.data && app.state.kernelRuntime.data.kernel_capabilities;
    const host = app.hostSummary || caps || {};
    const platform = [host.os, host.arch].filter(Boolean).join(' / ');
    app.$('hostName').textContent = host.name || window.location.hostname || 'Veer';
    app.$('hostName').title = app.$('hostName').textContent;
    app.$('hostPlatform').textContent = platform || '—';
    app.$('hostKernel').textContent = host.kernel_release || '—';
    app.$('hostKernel').title = host.kernel_release || '';
    app.$('hostUptime').textContent = Number.isFinite(host.uptime_seconds) ? text('patchbay.uptime', { days: Math.floor(host.uptime_seconds / 86400), hours: Math.floor(host.uptime_seconds % 86400 / 3600) }) : '';
    if (activeDrawer) updatePreview(activeDrawer);
  }

  function serializeForm(cfg) {
    return JSON.stringify(Array.from(cfg.element.elements).filter((el) => el.id && !/^(submit|button)$/.test(el.type)).map((el) => [el.id, el.type === 'checkbox' ? el.checked : el.value]));
  }

  function buildDrawers() {
    shell.drawerTitle = node('h2', { attrs: { id: 'resourceDrawerTitle' } });
    const close = node('button', { className: 'icon-button', text: '×', attrs: { type: 'button', 'aria-label': text('common.close'), id: 'closeResourceDrawer' } });
    close.addEventListener('click', requestCloseDrawer);
    shell.drawerPanel = node('div', { className: 'resource-drawer-panel', attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'resourceDrawerTitle', tabindex: '-1' }, children: [node('div', { className: 'drawer-heading', children: [shell.drawerTitle, close] })] });
    shell.drawerBody = node('div', { className: 'drawer-body' });
    shell.drawerPanel.appendChild(shell.drawerBody);
    shell.drawer = node('div', { className: 'resource-drawer', attrs: { id: 'resourceDrawer', hidden: '' }, children: [shell.drawerPanel] });
    document.body.appendChild(shell.drawer);
    shell.drawer.addEventListener('click', (event) => { if (event.target === shell.drawer) requestCloseDrawer(); });
    allForms.forEach((cfg) => {
      cfg.element = app.$(cfg.form + 'Form');
      if (!cfg.element) return;
      cfg.section = cfg.element.closest('section');
      cfg.section.hidden = true;
      cfg.section.classList.add('drawer-form');
      cfg.preview = node('div', { className: 'drawer-preview', attrs: { 'aria-label': text('patchbay.preview') } });
      cfg.section.insertBefore(cfg.preview, cfg.element);
      shell.drawerBody.appendChild(cfg.section);
      cfg.footer = node('div', { className: 'drawer-footer', attrs: { hidden: '' } });
      const submit = app.$(cfg.form + 'SubmitBtn');
      const cancel = app.$(cfg.form + 'CancelBtn');
      submit.classList.add('primary-button');
      submit.setAttribute('form', cfg.element.id);
      cancel.classList.add('drawer-cancel');
      cancel.addEventListener('click', (event) => { event.preventDefault(); event.stopImmediatePropagation(); requestCloseDrawer(); }, true);
      cfg.footer.append(cancel, submit);
      shell.drawerPanel.appendChild(cfg.footer);
      cfg.element.querySelectorAll('.form-actions').forEach((el) => el.closest('.form-row').remove());
      organizeEditor(cfg);
      cfg.element.querySelectorAll('.form-group').forEach((group) => {
        const label = group.querySelector('label');
        const field = group.querySelector('input:not([type="hidden"]),select,textarea');
        if (label && field && field.id && !label.contains(field)) label.htmlFor = field.id;
        if (field && /(?:IP|Port|Interface|Prefix|Address|Picker|MAC)/i.test(field.id)) field.classList.add('mono');
      });
      cfg.element.addEventListener('input', () => updatePreview(cfg));
      cfg.element.addEventListener('change', () => updatePreview(cfg));
      cfg.element.addEventListener('invalid', (event) => {
        const details = event.target.closest('details');
        if (details) details.open = true;
      }, true);
      cfg.element.addEventListener('focusout', (event) => {
        const field = event.target;
        if (field.validity && !field.validity.valid && field.value) app.setFieldError(field, field.validationMessage);
      });
      ['Edit', 'Clone'].forEach((mode) => wrap('enter' + cfg.stem + mode + 'Mode', () => openDrawer(cfg)));
      wrap('exit' + cfg.stem + 'EditMode', () => { if (activeDrawer === cfg) closeDrawer(); });
      wrap('sync' + cfg.stem + 'FormState', () => {
        if (activeDrawer === cfg) shell.drawerTitle.textContent = app.$(cfg.form + 'FormTitle').textContent;
      });
    });
  }

  function organizeEditor(cfg) {
    const fields = {
      rule: [['inInterfacePicker', 'inIP', 'inPort'], ['outInterfacePicker', 'outIP', 'outPort'], ['ruleOutSourceIP', 'ruleTransparent']],
      site: [['siteListenIfacePicker', 'siteListenIP', 'siteQUIC'], ['siteBackendIP', 'siteBackendHTTP', 'siteBackendHTTPS'], ['siteBackendSourceIP', 'siteTransparent']],
      range: [['rangeInInterfacePicker', 'rangeInIP', 'rangeStartPort', 'rangeEndPort'], ['rangeOutInterfacePicker', 'rangeOutIP', 'rangeOutStartPort'], ['rangeOutSourceIP', 'rangeTransparent']]
    }[cfg.form];
    if (fields) fields.forEach((ids, index) => {
      const container = node(index === 2 ? 'details' : 'fieldset', { className: index === 2 ? 'advanced-options editor-group' : 'editor-group' });
      container.appendChild(node(index === 2 ? 'summary' : 'legend', { text: text('patchbay.editor.' + ['entry', 'target', 'advanced'][index]), dataset: { i18n: 'patchbay.editor.' + ['entry', 'target', 'advanced'][index] } }));
      const grid = node('div', { className: 'form-row' });
      ids.forEach((id) => { const input = app.$(id); const group = input && input.closest('.form-group'); if (group && cfg.element.contains(group)) grid.appendChild(group); });
      container.appendChild(grid);
      if (grid.children.length) cfg.element.appendChild(container);
      if (index === 2) {
        const warning = app.$(cfg.form + 'TransparentWarning');
        if (warning) container.appendChild(warning);
      }
    });
    cfg.element.querySelectorAll('.form-row').forEach((row) => { if (!row.children.length) row.remove(); });
    const select = app.$(cfg.form === 'rule' ? 'protocol' : cfg.form === 'range' ? 'rangeProtocol' : '');
    if (select) {
      select.hidden = true;
      const segmented = node('div', { className: 'segmented-control', attrs: { role: 'group', 'aria-label': text('form.protocol') } });
      Array.from(select.options).forEach((option) => {
        const button = node('button', { text: option.textContent, attrs: { type: 'button', 'aria-pressed': String(select.value === option.value) }, dataset: { value: option.value } });
        button.addEventListener('click', () => { select.value = option.value; select.dispatchEvent(new Event('change', { bubbles: true })); updatePreview(cfg); });
        segmented.appendChild(button);
      });
      select.after(segmented);
      cfg.protocolControl = { select, segmented };
    }
  }

  function openDrawer(cfg, field) {
    if (!cfg || !cfg.element) return;
    if (activeDrawer && activeDrawer !== cfg) return;
    if (!activeDrawer) drawerReturn = document.activeElement;
    activeDrawer = cfg;
    setSidebar(false);
    cfg.section.hidden = false;
    cfg.footer.hidden = false;
    shell.drawer.hidden = false;
    shell.drawerTitle.textContent = app.$(cfg.form + 'FormTitle').textContent;
    shell.drawerPanel.dataset.color = cfg.color;
    updatePreview(cfg);
    drawerSnapshot = serializeForm(cfg);
    shell.drawerBody.scrollTop = 0;
    syncInert();
    requestAnimationFrame(() => {
      if (activeDrawer !== cfg) return;
      const target = field || cfg.element.querySelector('input:not([type="hidden"]):not(:disabled),select:not(:disabled),textarea:not(:disabled)');
      (target || shell.drawerPanel).focus();
    });
  }

  function closeDrawer() {
    if (!activeDrawer) return;
    activeDrawer.section.hidden = true;
    activeDrawer.footer.hidden = true;
    activeDrawer = null;
    shell.drawer.hidden = true;
    app.closeDropdowns();
    syncInert();
    const target = drawerReturn && drawerReturn.isConnected && !drawerReturn.closest('[hidden]') ? drawerReturn : shell.create;
    if (target && !target.hidden) target.focus();
    drawerReturn = null;
  }

  async function requestCloseDrawer() {
    if (!activeDrawer) return true;
    if (closingDrawer || app.state.pendingForms[activeDrawer.form]) return false;
    closingDrawer = true;
    const cfg = activeDrawer;
    try {
      if (serializeForm(cfg) !== drawerSnapshot && !await app.confirmAction({ title: text('patchbay.discard.title'), message: text('patchbay.discard.message'), confirmText: text('patchbay.discard.action'), cancelText: text('patchbay.keepEditing') })) return false;
      app['exit' + cfg.stem + 'EditMode']();
      return true;
    } finally { closingDrawer = false; }
  }

  function startCreate(cfg) {
    if (!cfg || activeDrawer) return;
    app['exit' + cfg.stem + 'EditMode']();
    if (cfg === reservation && selectedNetworkID) app.el.managedNetworkReservationManagedNetworkId.value = String(selectedNetworkID);
    openDrawer(cfg);
  }

  function updatePreview(cfg) {
    if (!cfg.preview) return;
    if (cfg.protocolControl) cfg.protocolControl.segmented.querySelectorAll('button').forEach((button) => button.setAttribute('aria-pressed', String(button.dataset.value === cfg.protocolControl.select.value)));
    const build = app['build' + cfg.stem + 'FromForm'];
    let draft = {};
    if (typeof build === 'function') {
      try { draft = build(); } catch (_) { /* An incomplete draft has no endpoint yet. */ }
    }
    if (cfg.state === 'managedNetworkReservations') {
      cfg.preview.replaceChildren(node('p', { className: 'mono', text: [draft.mac_address || '—', '→', draft.ipv4_address || '—'].join(' ') }));
      return;
    }
    cfg.preview.replaceChildren(routeNode(cfg, draft), node('p', { className: 'field-hint', text: text('patchbay.previewHint') }));
  }

  function decorateTable(cfg) {
    const table = app.$(cfg.state + 'Table');
    const body = app.$(cfg.state + 'Body');
    if (!table || !body) return;
    table.classList.add('resource-table');
    table.dataset.resource = cfg.state;
    const oldHeader = table.querySelector('thead tr');
    const select = cfg.state === 'rules' ? app.$('rulesSelectAll') : null;
    const headers = [];
    if (select) headers.push(node('th', { className: 'cell-select', children: [select] }));
    const sortKeys = { status: 'status', name: cfg.state === 'sites' ? 'domain' : cfg.state === 'managedNetworks' ? 'name' : cfg.state === 'egressNATs' ? 'parent_interface' : 'remark', route: cfg.state === 'sites' ? 'listen_ip' : ['managedNetworks', 'egressNATs', 'ipv6Assignments'].includes(cfg.state) ? 'id' : 'in_ip', protocol: 'protocol' };
    ['status', 'name', 'route', 'protocol', 'actions'].forEach((key) => {
      const th = node('th', { className: 'resource-' + key, attrs: { scope: 'col' } });
      const sort = sortKeys[key];
      if (sort) {
        const state = app.state[cfg.state];
        const button = node('button', { className: 'column-sort', text: text('patchbay.column.' + key) + (state.sortKey === sort ? (state.sortAsc ? ' ↑' : ' ↓') : ''), attrs: { type: 'button' }, dataset: { column: key } });
        th.setAttribute('aria-sort', state.sortKey === sort ? (state.sortAsc ? 'ascending' : 'descending') : 'none');
        button.addEventListener('click', () => { app.toggleSort(state, sort); app[cfg.render](); table.querySelector('[data-column="' + key + '"]').focus(); });
        th.appendChild(button);
      } else th.textContent = text('patchbay.column.' + key);
      headers.push(th);
    });
    oldHeader.replaceChildren(...headers);
    const byID = new Map((app.state[cfg.state].data || []).map((item) => [Number(item.id), item]));
    Array.from(body.children).forEach((row) => {
      const cells = Array.from(row.children);
      const item = byID.get(Number(cells[cfg.idColumn] && cells[cfg.idColumn].textContent));
      if (!item) return;
      const state = tone(item);
      row.classList.add('resource-row');
      row.classList.toggle('is-paused', item.enabled === false);
      row.dataset.tone = state;
      row.dataset.resourceId = String(item.id);
      const status = cells[cells.length - 2];
      status.className = 'resource-status';
      status.dataset.label = text('patchbay.column.status');
      const name = node('div', { className: 'resource-name-content', children: [node('strong', { className: 'mono', text: item.remark || item.name || item.domain || '#' + item.id }), node('span', { className: 'resource-id mono', text: '#' + item.id })] });
      if (cfg.state === 'managedNetworks') {
        const link = node('button', { className: 'network-detail-link mono', text: item.name || item.bridge || '#' + item.id, attrs: { type: 'button' } });
        link.addEventListener('click', () => openNetworkDetail(item.id));
        name.firstChild.replaceWith(link);
      }
      if (item.domain && item.remark) name.appendChild(node('span', { className: 'mono', text: item.domain }));
      if (item.tag && typeof app.createTagBadgeNode === 'function') name.appendChild(app.createTagBadgeNode(cfg.state, item.tag, app.state[cfg.state].filterTag === item.tag));
      const reason = item.runtime_error || item.runtime_detail || item.ipv4_runtime_detail || item.ipv6_runtime_detail || item.fallback_reason || item.kernel_reason;
      if (reason) name.appendChild(node('span', { className: 'resource-reason' + (item.runtime_error ? ' is-error' : state === 'attention' ? ' is-warning' : ''), text: reason }));
      const details = node('details', { className: 'resource-details', children: [node('summary', { text: text('patchbay.details') })] });
      if (cfg.state === 'managedNetworks') cells.slice(4, cells.length - 2).forEach((cell) => details.appendChild(node('div', { children: Array.from(cell.childNodes) })));
      const meta = [item.out_source_ip || item.backend_source_ip ? text('form.outSourceIP') + ': ' + (item.out_source_ip || item.backend_source_ip) : '', item.transparent ? text('form.transparent') : '', item.nat_type || '', item.quic ? 'HTTP/3 (UDP 443)' : ''].filter(Boolean);
      meta.forEach((value) => details.appendChild(node('p', { className: 'mono', text: value })));
      if (details.children.length > 1) name.appendChild(details);
      const actions = cells[cells.length - 1];
      actions.classList.add('resource-actions');
      actions.dataset.label = text('common.actions');
      const edit = actions.querySelector('button[class*="btn-edit"]');
      if (edit) { edit.classList.add('mini-btn', 'quick-edit'); actions.prepend(edit); }
      const output = [];
      if (cfg.state === 'rules') output.push(cells[0]);
      output.push(status, app.createCell(name, 'resource-name'), app.createCell(routeNode(cfg, item), 'resource-route'), app.createCell(String(item.protocol || (cfg.state === 'sites' ? (item.quic ? 'HTTP · H3' : 'HTTP · TLS') : cfg.state === 'ipv6Assignments' ? 'IPv6' : 'IPv4 / IPv6')).toUpperCase(), 'resource-protocol'), actions);
      row.replaceChildren(...output);
    });
    renderChips(cfg);
    if (cfg.state === 'managedNetworks' && selectedNetworkID) renderNetworkDetail();
    renderShell();
  }

  function buildNetworkDetail() {
    const panel = app.$('tab-managed-networks');
    shell.networkList = app.$('managedNetworksTable').closest('section');
    shell.leaseList = app.$('managedNetworkReservationsTable').closest('section');
    shell.deviceList = app.$('managedNetworkReservationCandidatesTable').closest('section');
    const back = node('button', { className: 'mini-btn', text: text('patchbay.network.back'), dataset: { i18n: 'patchbay.network.back' }, attrs: { type: 'button' } });
    back.addEventListener('click', () => { selectedNetworkID = 0; shell.networkDetail.hidden = true; shell.networkList.hidden = false; shell.create.hidden = false; shell.networkList.querySelector('.network-detail-link')?.focus(); });
    shell.networkTitle = node('h2', { className: 'mono' });
    shell.networkTabs = node('div', { className: 'network-subtabs', attrs: { role: 'tablist', 'aria-label': text('patchbay.networkDetails') } });
    shell.networkOverview = node('div', { className: 'network-overview', attrs: { role: 'tabpanel', id: 'networkDetail-overview' } });
    shell.leaseList.id = 'networkDetail-leases';
    shell.deviceList.id = 'networkDetail-devices';
    shell.leaseList.setAttribute('role', 'tabpanel');
    shell.deviceList.setAttribute('role', 'tabpanel');
    const add = node('button', { className: 'mini-btn', text: text('managedNetworkReservation.form.title.add'), dataset: { i18n: 'managedNetworkReservation.form.title.add' }, attrs: { type: 'button', id: 'addNetworkReservationBtn' } });
    add.addEventListener('click', () => startCreate(reservation));
    shell.leaseList.prepend(add);
    shell.networkDetail = node('div', { className: 'network-detail', attrs: { hidden: '' }, children: [back, shell.networkTitle, shell.networkTabs, shell.networkOverview, shell.leaseList, shell.deviceList] });
    panel.appendChild(shell.networkDetail);
  }
  function openNetworkDetail(id) {
    selectedNetworkID = Number(id);
    networkSubview = 'overview';
    app.state.managedNetworkReservations.page = 1;
    app.state.managedNetworkReservationCandidates.page = 1;
    shell.networkList.hidden = true;
    shell.networkDetail.hidden = false;
    shell.create.hidden = true;
    renderNetworkDetail();
    app.renderManagedNetworkReservationsTable();
    app.renderManagedNetworkReservationCandidatesTable();
    shell.networkTabs.querySelector('button').focus();
  }
  function renderNetworkDetail() {
    const item = (app.state.managedNetworks.data || []).find((entry) => Number(entry.id) === selectedNetworkID);
    if (!item) { selectedNetworkID = 0; shell.networkDetail.hidden = true; shell.networkList.hidden = false; return; }
    shell.networkTitle.textContent = item.name || item.bridge || '#' + item.id;
    shell.networkTabs.replaceChildren(...['overview', 'leases', 'devices'].map((key, index) => {
      const button = node('button', { text: text('patchbay.network.' + key), attrs: { type: 'button', role: 'tab', id: 'networkDetail-tab-' + key, 'aria-controls': 'networkDetail-' + key, 'aria-selected': String(networkSubview === key), tabindex: networkSubview === key ? '0' : '-1' } });
      button.addEventListener('click', () => { networkSubview = key; renderNetworkDetail(); app.$('networkDetail-tab-' + key).focus(); });
      button.addEventListener('keydown', (event) => {
        if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
        event.preventDefault(); networkSubview = ['overview', 'leases', 'devices'][(index + (event.key === 'ArrowRight' ? 1 : 2)) % 3]; renderNetworkDetail(); app.$('networkDetail-tab-' + networkSubview).focus();
      });
      return button;
    }));
    [shell.networkOverview, shell.leaseList, shell.deviceList].forEach((panel, index) => { const key = ['overview', 'leases', 'devices'][index]; panel.hidden = networkSubview !== key; panel.setAttribute('aria-labelledby', 'networkDetail-tab-' + key); });
    shell.networkOverview.replaceChildren(routeNode(configs[3], item));
    const fields = [['form.remark', item.remark], ['managedNetwork.form.bridge', item.bridge], ['patchbay.network.ipv4', item.ipv4_cidr], ['patchbay.network.ipv6', item.ipv6_parent_prefix], ['patchbay.network.devices', (item.child_interfaces || []).join(', ')]];
    const list = node('dl', { className: 'network-facts' });
    fields.forEach(([key, value]) => { if (value) list.append(node('dt', { text: text(key) }), node('dd', { className: 'mono', text: value })); });
    shell.networkOverview.appendChild(list);
  }

  function renderChips(cfg) {
    const panel = app.$('tab-' + cfg.tab);
    const toolbar = panel && panel.querySelector('.table-toolbar');
    if (!toolbar) return;
    let chips = toolbar.querySelector('.status-chips');
    if (!chips) { chips = node('div', { className: 'status-chips', attrs: { 'aria-label': text('patchbay.filterStatus') } }); toolbar.appendChild(chips); }
    const state = app.state[cfg.state];
    const rows = state.data || [];
    chips.replaceChildren(...['all', 'live', 'attention', 'off'].map((key) => {
      const count = key === 'all' ? rows.length : rows.filter((item) => tone(item) === key).length;
      const button = node('button', { className: 'status-chip', attrs: { type: 'button', 'aria-pressed': String((state.statusFilter || 'all') === key) }, children: [node('span', { text: text('patchbay.status.' + key) }), node('span', { className: 'mono', text: String(count) })] });
      button.addEventListener('click', () => { state.statusFilter = key; state.page = 1; app[cfg.render](); });
      return button;
    }));
  }

  function tabFromHash() {
    const value = window.location.hash.slice(1);
    if (!/^[a-z0-9_-]*$/.test(value)) return '';
    return value === 'diag' ? 'diagnostics' : value;
  }
  function writeHash(tab, replace) {
    const hash = '#' + (tab === 'diagnostics' ? 'diag' : tab);
    if (window.location.hash !== hash) window.history[replace ? 'replaceState' : 'pushState'](null, '', hash);
  }

  function buildCommands() {
    shell.commandInput = node('input', { attrs: { type: 'search', id: 'commandSearch', autocomplete: 'off', role: 'combobox', 'aria-controls': 'commandResults', 'aria-expanded': 'true', 'aria-autocomplete': 'list', placeholder: text('patchbay.commandPlaceholder'), 'aria-label': text('patchbay.search') } });
    shell.commandList = node('div', { className: 'command-results', attrs: { id: 'commandResults', role: 'listbox' } });
    const panel = node('div', { className: 'command-panel', attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-label': text('patchbay.search') }, children: [shell.commandInput, shell.commandList, node('p', { className: 'command-help', text: text('patchbay.commandHelp') })] });
    shell.command = node('div', { className: 'command-overlay', attrs: { id: 'commandPalette', hidden: '' }, children: [panel] });
    document.body.appendChild(shell.command);
    shell.command.addEventListener('click', (event) => { if (event.target === shell.command) closeCommand(); });
    shell.commandInput.addEventListener('input', () => renderCommands());
    shell.commandInput.addEventListener('keydown', (event) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault();
        commandIndex = Math.max(0, Math.min(commands.length - 1, commandIndex + (event.key === 'ArrowDown' ? 1 : -1)));
        updateCommandSelection();
      } else if (event.key === 'Enter' && commands[commandIndex]) { event.preventDefault(); executeCommand(commands[commandIndex]); }
    });
  }
  function renderCommands() {
    const query = shell.commandInput.value.trim().toLowerCase();
    commands = [];
    document.querySelectorAll('.tabs .tab:not([hidden])').forEach((button) => {
      const title = button.dataset.pageTitle || button.textContent;
      commands.push({ title, detail: text('patchbay.goToPage'), run: () => app.activateTab(button.dataset.tab) });
    });
    configs.forEach((cfg) => {
      commands.push({ title: text('patchbay.create.' + cfg.state), detail: text(cfg.title), run: () => { app.activateTab(cfg.tab); startCreate(cfg); } });
      (app.state[cfg.state].data || []).forEach((item) => {
        const title = item.remark || item.name || item.domain || '#' + item.id;
        const detail = [text(cfg.title), ...routeParts(cfg, item).flat().filter(Boolean)].join(' · ');
        commands.push({ title, detail, run: () => { app.activateTab(cfg.tab); app['enter' + cfg.stem + 'EditMode'](item); } });
      });
    });
    commands.push({ title: text('patchbay.toggleTheme'), detail: '', run: () => app.applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark') });
    commands = commands.filter((command) => !query || (command.title + ' ' + command.detail).toLowerCase().includes(query)).slice(0, 40);
    commandIndex = 0;
    shell.commandList.replaceChildren(...commands.map((command, index) => {
      const button = node('button', { className: 'command-result', attrs: { type: 'button', role: 'option', id: 'command-result-' + index, tabindex: '-1' }, children: [node('strong', { text: command.title }), node('span', { className: 'mono', text: command.detail })] });
      button.addEventListener('click', () => executeCommand(command));
      return button;
    }));
    if (!commands.length) shell.commandList.appendChild(node('p', { className: 'command-empty', text: text('common.noMatches') }));
    updateCommandSelection();
  }
  function updateCommandSelection() {
    Array.from(shell.commandList.querySelectorAll('[role="option"]')).forEach((option, index) => {
      option.setAttribute('aria-selected', String(index === commandIndex));
      if (index === commandIndex) { shell.commandInput.setAttribute('aria-activedescendant', option.id); option.scrollIntoView({ block: 'nearest' }); }
    });
    if (!commands.length) shell.commandInput.removeAttribute('aria-activedescendant');
  }
  function executeCommand(command) { closeCommand(); command.run(); }
  function openCommand() {
    if (activeDrawer || document.querySelector('.modal.active')) return;
    commandReturn = document.activeElement;
    setSidebar(false);
    shell.command.hidden = false;
    shell.commandInput.value = '';
    renderCommands();
    syncInert();
    shell.commandInput.focus();
  }
  function closeCommand() {
    shell.command.hidden = true;
    syncInert();
    if (commandReturn && commandReturn.isConnected) commandReturn.focus();
  }

  function trapFocus(event, container) {
    const focusable = Array.from(container.querySelectorAll('button:not(:disabled), input:not(:disabled):not([type="hidden"]), select:not(:disabled), textarea:not(:disabled), a[href], summary, [tabindex="0"]')).filter((el) => el.getClientRects().length && !el.closest('[inert]'));
    if (!focusable.length) { event.preventDefault(); return; }
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || !container.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && (document.activeElement === last || !container.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
  }

  buildShell();
  buildDrawers();
  buildNetworkDetail();
  buildCommands();
  app.filterManagedNetworkDetailRows = (rows) => selectedNetworkID ? rows.filter((item) => Number(item.managed_network_id) === selectedNetworkID) : rows;
  const originalSort = app.sortByState;
  app.sortByState = function (list, state, getValue) {
    const filtered = configs.some((cfg) => app.state[cfg.state] === state) && state.statusFilter && state.statusFilter !== 'all'
      ? list.filter((item) => tone(item) === state.statusFilter) : list;
    return originalSort(filtered, state, getValue);
  };
  const originalHasFilters = app.hasActiveFilters;
  app.hasActiveFilters = (state) => originalHasFilters(state) || !!(state && state.statusFilter && state.statusFilter !== 'all');
  wrap('resetTableView', (key) => { if (app.state[key]) app.state[key].statusFilter = 'all'; });
  configs.forEach((cfg) => wrap(cfg.render, () => decorateTable(cfg)));
  wrap('renderOverview', renderShell);
  wrap('renderRulesToolbar', () => {
    const selected = app.getRuleSelection().size;
    app.el.batchDeleteRulesBtn.hidden = selected === 0;
    app.el.rulesSearchInput.hidden = selected > 0;
    const toolbar = app.el.rulesSearchInput.closest('.table-toolbar');
    toolbar.classList.toggle('has-selection', selected > 0);
    let cancel = toolbar.querySelector('.cancel-selection');
    if (!cancel) {
      cancel = node('button', { className: 'mini-btn cancel-selection', attrs: { type: 'button' } });
      cancel.addEventListener('click', () => { app.clearRuleSelection(); app.renderRulesTable(); });
      toolbar.appendChild(cancel);
    }
    cancel.textContent = text('patchbay.clearSelection');
    cancel.hidden = selected === 0;
  });
  wrap('refreshLocalizedUI', () => {
    renderSettings();
    document.querySelectorAll('.tabs .tab').forEach((button) => { delete button.dataset.pageTitle; });
    renderShell();
    if (selectedNetworkID) renderNetworkDetail();
  });
  wrap('applyTheme', renderSettings);
  const originalActivate = app.activateTab;
  app.activateTab = function (target, options) {
    if (!/^[a-z0-9_-]+$/.test(target || '')) return;
    if (activeDrawer && target !== app.state.activeTab) {
      requestCloseDrawer().then((closed) => { if (closed) app.activateTab(target, options); else writeHash(app.state.activeTab, true); });
      return;
    }
    originalActivate(target, options);
    if (app.state.activeTab !== target || !app.$('tab-' + target)) return;
    setSidebar(false);
    if (!pendingHash || pendingHash === target) { pendingHash = ''; writeHash(target, options && options.persist === false); }
    renderShell();
  };
  const originalFocus = app.focusSection;
  app.focusSection = function (tab, heading, field) {
    const cfg = allForms.find((entry) => heading === app.$(entry.form + 'FormTitle'));
    if (!cfg) return originalFocus(tab, heading, field);
    app.activateTab(tab);
    openDrawer(cfg, field);
  };
  wrap('renderPluginsTable', () => {
    const group = document.querySelector('.nav-group-runtime');
    document.querySelectorAll('.plugin-page-tab').forEach((button) => {
      button.dataset.pageTitle = button.textContent;
      if (group && group.parentNode === button.parentNode) group.parentNode.insertBefore(button, group);
    });
    if (pendingHash && app.$('tab-' + pendingHash)) app.activateTab(pendingHash, { persist: false });
    else if (pendingHash && app.state.plugins.catalog) { pendingHash = ''; app.activateTab('plugins', { persist: false }); }
    renderShell();
  });
  wrap('showTokenModal', () => { closeDrawer(); if (shell.command) closeCommand(); setSidebar(false); });
  window.addEventListener('hashchange', () => {
    const tab = tabFromHash();
    if (tab && app.$('tab-' + tab)) app.activateTab(tab, { persist: false });
    else { pendingHash = ''; app.activateTab('rules', { persist: false }); }
  });
  window.addEventListener('resize', () => {
    if (window.innerWidth >= 860 && sidebarOpen) setSidebar(false);
    else syncInert();
  });
  window.addEventListener('beforeunload', (event) => {
    if (activeDrawer && serializeForm(activeDrawer) !== drawerSnapshot) { event.preventDefault(); event.returnValue = ''; }
  });
  document.addEventListener('keydown', (event) => {
    if (event.isComposing || event.defaultPrevented) return;
    const modal = document.querySelector('.modal.active');
    if (modal) return;
    if (event.key === 'Escape') {
      if (!shell.command.hidden) { event.preventDefault(); closeCommand(); }
      else if (activeDrawer) { event.preventDefault(); requestCloseDrawer(); }
      else if (sidebarOpen) { event.preventDefault(); setSidebar(false); }
      return;
    }
    if (event.key === 'Tab') {
      if (!shell.command.hidden) trapFocus(event, shell.command);
      else if (activeDrawer) trapFocus(event, shell.drawerPanel);
      else if (sidebarOpen) trapFocus(event, shell.sidebar);
      return;
    }
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); if (shell.command.hidden) openCommand(); else closeCommand(); return; }
    if (event.ctrlKey || event.metaKey || event.altKey || activeDrawer || !shell.command.hidden || /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable) return;
    const cfg = configForTab(app.state.activeTab);
    if (cfg && event.key.toLowerCase() === 'n') { event.preventDefault(); startCreate(cfg); }
    if (event.key === '/') {
      const input = app.$('tab-' + app.state.activeTab).querySelector('input[type="search"]');
      if (input) { event.preventDefault(); input.focus(); }
    }
  });
  const requested = tabFromHash();
  if (requested && (configForTab(requested) || ['diagnostics', 'plugins'].includes(requested))) app.state.activeTab = requested;
  else if (requested.startsWith('plugin-')) { pendingHash = requested; app.state.activeTab = 'plugins'; }
  else if (!app.$('tab-' + app.state.activeTab)) app.state.activeTab = 'rules';
  app.patchbay = { configs, tone, routeParts, openDrawer, requestCloseDrawer, activeDrawer: () => activeDrawer };
})();
