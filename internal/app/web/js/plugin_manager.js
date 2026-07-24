(function () {
  const app = window.VeerApp;
  if (!app) return;

  const packageArchivePath = '/api/plugin-packages/stage';
  const auditPageSize = 50;
	const deadLetterPageSize = 100;
  const managerAdvancedViews = new Set(['advanced', 'repositories', 'trust', 'audit', 'dead-letters', 'secrets', 'access']);
  let managerFocusReturn = null;

  function managerState() {
    app.state.plugins = app.state.plugins || {};
    app.state.plugins.manager = app.state.plugins.manager || {};
    const state = app.state.plugins.manager;
    if (!Array.isArray(state.trustKeys)) state.trustKeys = [];
    if (!Array.isArray(state.auditLogs)) state.auditLogs = [];
	if (!Array.isArray(state.deadLetters)) state.deadLetters = [];
    if (!Array.isArray(state.history)) state.history = [];
	if (!Array.isArray(state.repositories)) state.repositories = [];
	if (!Array.isArray(state.provenance)) state.provenance = [];
	if (!Array.isArray(state.repositoryPolicies)) state.repositoryPolicies = [];
	if (!Array.isArray(state.repositoryUpdates)) state.repositoryUpdates = [];
	if (!Array.isArray(state.stages)) state.stages = state.stage ? [state.stage] : [];
    if (!Object.prototype.hasOwnProperty.call(state, 'probation')) state.probation = null;
	if (!Object.prototype.hasOwnProperty.call(state, 'probationGroup')) state.probationGroup = null;
    if (typeof state.requestID !== 'number') state.requestID = 0;
    return state;
  }

	function managerActiveStages() {
		const state = managerState();
		if (Array.isArray(state.stages) && state.stages.length) return state.stages.filter(Boolean);
		return state.stage ? [state.stage] : [];
	}

  function managerPlugin(pluginID) {
    const id = String(pluginID || '').trim();
    return (app.state.plugins.data || []).find((plugin) => plugin && plugin.id === id) || null;
  }

  function managerRequiresSignedPackages() {
    const catalog = app.state.plugins.catalog || {};
    return !!(catalog.runtime && catalog.runtime.require_signed_packages);
  }

  function managerErrorText(error) {
    if (!error) return app.t('plugins.manager.unknownError');
    if (error.payload && error.payload.error) return String(error.payload.error);
    return String(error.message || error);
  }

  function managerFormatDate(value) {
    const text = String(value || '').trim();
    if (!text) return app.t('common.dash');
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return text;
    try {
      return new Intl.DateTimeFormat(app.state.locale || undefined, {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      }).format(date);
    } catch (_) {
      return text;
    }
  }

  function managerShortText(value, limit) {
    const text = String(value == null ? '' : value);
    const max = Math.max(16, Number(limit) || 96);
    return text.length > max ? text.slice(0, max - 3) + '...' : text;
  }

  function managerButton(text, className, handler, options) {
    const opts = options || {};
    const button = app.createNode('button', {
      className: className || 'mini-btn',
      text,
      title: opts.title || '',
      attrs: {
        type: 'button',
        disabled: opts.disabled ? 'disabled' : null,
        'aria-busy': opts.busy ? 'true' : 'false'
      }
    });
    button.disabled = !!opts.disabled;
    if (opts.busy) button.classList.add('is-busy');
    if (typeof handler === 'function') button.addEventListener('click', handler);
    return button;
  }

  function managerSetButtonBusy(button, busy, busyText, idleText) {
    if (!button) return;
    button.disabled = !!busy;
    button.classList.toggle('is-busy', !!busy);
    button.setAttribute('aria-busy', busy ? 'true' : 'false');
    if (busyText || idleText) button.textContent = busy ? busyText : idleText;
  }

  function managerNotice(text, tone) {
    return app.createNode('div', {
      className: 'plugin-manager-notice' + (tone ? ' is-' + tone : ''),
      text
    });
  }

  function managerEmpty(text) {
    return app.createNode('div', { className: 'plugin-manager-empty', text });
  }

  function managerLoading() {
    return app.createNode('div', {
      className: 'plugin-manager-loading',
      text: app.t('plugins.manager.loading')
    });
  }

  function managerSection(title, children, actions) {
    const heading = app.createNode('div', {
      className: 'plugin-manager-section-heading',
      children: [
        app.createNode('h3', { text: title }),
        actions || null
      ].filter(Boolean)
    });
    return app.createNode('section', {
      className: 'plugin-manager-section',
      children: [heading].concat((children || []).filter(Boolean))
    });
  }

  function managerMenu(items) {
    return app.createNode('div', {
      className: 'plugin-manager-menu',
      children: (items || []).map((item) => {
        const button = app.createNode('button', {
          className: 'plugin-manager-menu-item',
          attrs: { type: 'button' },
          children: [
            app.createNode('span', { text: item.label }),
            app.createNode('span', { className: 'plugin-manager-menu-open', text: app.t('plugins.manager.open'), attrs: { 'aria-hidden': 'true' } })
          ]
        });
        button.addEventListener('click', item.open);
        return button;
      })
    });
  }

  function managerDisclosure(title, children, tone) {
    return app.createNode('details', {
      className: 'plugin-manager-disclosure' + (tone ? ' is-' + tone : ''),
      children: [
        app.createNode('summary', { text: title }),
        app.createNode('div', {
          className: 'plugin-manager-disclosure-body',
          children: (children || []).filter(Boolean)
        })
      ]
    });
  }

  function managerFacts(rows) {
    const facts = app.createNode('dl', { className: 'plugin-manager-facts' });
    (rows || []).filter((row) => row && row.value !== '' && row.value != null).forEach((row) => {
      const item = app.createNode('div', { className: 'plugin-manager-fact' });
      item.appendChild(app.createNode('dt', { text: row.label }));
      item.appendChild(app.createNode('dd', {
        className: row.mono ? 'plugin-manager-mono' : '',
        text: row.value,
        title: row.title || ''
      }));
      facts.appendChild(item);
    });
    return facts;
  }

  function managerList(values) {
    const list = app.createNode('ul', { className: 'plugin-manager-list' });
    (values || []).filter(Boolean).forEach((value) => {
      list.appendChild(app.createNode('li', {
        className: 'plugin-manager-list-item',
        text: value,
        title: value
      }));
    });
    return list;
  }

  function managerField(label, control, hint, wide) {
    return app.createNode('div', {
      className: 'plugin-manager-field' + (wide ? ' is-wide' : ''),
      children: [
        app.createNode('label', { text: label }),
        control,
        hint ? app.createNode('span', { className: 'plugin-manager-hint', text: hint }) : null
      ].filter(Boolean)
    });
  }

  function managerTable(headers, rows) {
    const table = app.createNode('table', { className: 'plugin-manager-table' });
    const thead = app.createNode('thead');
    const headerRow = app.createNode('tr');
    (headers || []).forEach((header) => headerRow.appendChild(app.createNode('th', { text: header })));
    thead.appendChild(headerRow);
    const tbody = app.createNode('tbody');
    (rows || []).forEach((cells) => {
      const row = app.createNode('tr');
      cells.forEach((cell) => row.appendChild(app.createCell(cell)));
      tbody.appendChild(row);
    });
    table.appendChild(thead);
    table.appendChild(tbody);
    return app.createNode('div', { className: 'plugin-manager-table-wrap', children: [table] });
  }

  function managerRender(content) {
    if (!app.el.pluginManagerBody) return;
    app.clearNode(app.el.pluginManagerBody);
    app.appendNodeContent(app.el.pluginManagerBody, content);
    app.el.pluginManagerBody.scrollTop = 0;
  }

  function managerSetHeader(title, meta) {
    if (app.el.pluginManagerTitle) app.el.pluginManagerTitle.textContent = title || app.t('plugins.manager.title');
    if (app.el.pluginManagerMeta) app.el.pluginManagerMeta.textContent = meta || '';
  }

  function managerNextRequest() {
    const state = managerState();
    state.requestID += 1;
    return state.requestID;
  }

  function managerRequestCurrent(requestID, view, pluginID, tab) {
    const state = managerState();
    if (!state.open || state.requestID !== requestID || state.view !== view) return false;
    if (pluginID != null && state.pluginID !== pluginID) return false;
    if (tab != null && state.tab !== tab) return false;
    return true;
  }

  function managerGlobalNav() {
    return [
	  { id: 'install', label: app.t('plugins.catalog.add') },
	  { id: 'advanced', label: app.t('plugins.manager.advanced') }
    ];
  }

  function managerPluginNav() {
    return [
      { id: 'overview', label: app.t('plugins.manager.overview') },
      { id: 'history', label: app.t('plugins.history.title') },
      { id: 'logs', label: app.t('plugins.logs.title') }
    ];
  }

  function managerRenderNav() {
    const state = managerState();
    const nav = app.el.pluginManagerNav;
    if (app.el.closePluginManagerBtn) {
      app.el.closePluginManagerBtn.disabled = !!state.busy;
      app.el.closePluginManagerBtn.setAttribute('aria-disabled', state.busy ? 'true' : 'false');
    }
    if (!nav) return;
    app.clearNode(nav);
    const items = state.view === 'plugin' ? managerPluginNav() : managerGlobalNav();
    const active = state.view === 'plugin'
      ? state.tab
      : (managerAdvancedViews.has(state.view) ? 'advanced' : state.view);
    items.forEach((item) => {
      nav.appendChild(managerButton(item.label, 'plugin-manager-nav-btn' + (item.id === active ? ' is-active' : ''), () => {
        if (state.view === 'plugin') app.openPluginManager('plugin', { pluginID: state.pluginID, tab: item.id });
        else app.openPluginManager(item.id);
      }, { disabled: !!state.busy }));
    });
    nav.hidden = false;
  }

  function managerRenderAdvanced() {
    managerSetHeader(app.t('plugins.manager.advanced'), '');
    managerRender(app.createNode('div', {
      className: 'plugin-manager-stack',
      children: [
        managerSection(app.t('plugins.manager.security'), [managerMenu([
          { label: app.t('plugins.trust.title'), open: () => app.openPluginManager('trust') },
          { label: app.t('plugins.secrets.title'), open: () => app.openPluginManager('secrets') },
          { label: app.t('plugins.admin.title'), open: () => app.openPluginManager('access') }
        ])]),
        managerSection(app.t('plugins.manager.operationsAndAudit'), [managerMenu([
          { label: app.t('plugins.audit.title'), open: () => app.openPluginManager('audit') },
          { label: app.t('plugins.deadLetters.title'), open: () => app.openPluginManager('dead-letters') }
        ])])
      ]
    }));
    managerFocusInitial();
  }

  function managerOpenShell() {
    const state = managerState();
    if (!state.open) managerFocusReturn = document.activeElement;
    state.open = true;
    if (app.el.pluginManagerModal) {
      app.el.pluginManagerModal.classList.add('active');
      app.el.pluginManagerModal.setAttribute('aria-hidden', 'false');
    }
  }

  function managerFocusInitial() {
    window.setTimeout(() => {
      const body = app.el.pluginManagerBody;
      const target = body && body.querySelector
        ? body.querySelector('input:not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled])')
        : null;
      if (target && typeof target.focus === 'function') target.focus();
      else if (app.el.closePluginManagerBtn && typeof app.el.closePluginManagerBtn.focus === 'function') app.el.closePluginManagerBtn.focus();
    }, 0);
  }

  function managerShowError(error, retry) {
    const controls = [];
    if (typeof retry === 'function') {
      controls.push(managerButton(app.t('common.retry'), 'mini-btn', retry));
    }
    managerRender(app.createNode('div', {
      className: 'plugin-manager-stack',
      children: [
        managerNotice(managerErrorText(error), 'danger'),
        controls.length ? app.createNode('div', { className: 'plugin-manager-actions', children: controls }) : null
      ].filter(Boolean)
    }));
  }

  function managerRenderPackageInput() {
    const state = managerState();
    managerSetHeader(app.t('plugins.package.installTitle'), app.t('plugins.package.installMeta'));
    const archive = app.createNode('input', {
      className: 'plugin-manager-file',
	  attrs: { type: 'file', accept: '.tar.gz,.tgz,application/gzip', required: true, multiple: 'multiple' }
    });
    const signature = app.createNode('input', {
      className: 'plugin-manager-file',
	  attrs: { type: 'file', accept: '.sig,.json,application/json', multiple: 'multiple' }
    });
    const stageButton = managerButton(app.t('plugins.package.stage'), '', async () => {
	  const archiveFiles = Array.from(archive.files || []);
	  const signatureFiles = Array.from(signature.files || []);
	  if (!archiveFiles.length) {
        app.notify('error', app.t('plugins.package.archiveRequired'));
        archive.focus();
        return;
      }
	  if (archiveFiles.length > 16) {
		app.notify('error', app.t('plugins.package.batchLimit'));
		return;
	  }
	  await app.stagePluginPackages(archiveFiles, signatureFiles, stageButton);
    }, { disabled: !!state.busy });
    const form = app.createNode('div', {
      className: 'plugin-manager-form',
      children: [
        app.createNode('div', {
          className: 'plugin-manager-form-grid',
          children: [
            managerField(app.t('plugins.package.archive'), archive, app.t('plugins.package.archiveHint'), true),
            managerField(app.t('plugins.package.signature'), signature, app.t('plugins.package.signatureHint'), true)
          ]
        }),
        managerNotice(app.t('plugins.package.stageHint')),
        app.createNode('div', { className: 'plugin-manager-actions', children: [stageButton] })
      ]
    });
    managerRender(form);
    managerFocusInitial();
  }

  async function managerReadSignatureSidecar(file) {
    if (!file) return {};
    const raw = typeof file.text === 'function' ? await file.text() : String(file);
    let value;
    try {
      value = JSON.parse(raw);
    } catch (_) {
      throw new Error(app.t('plugins.package.signatureInvalid'));
    }
    const signerID = String(value && value.signer_id || '').trim().toLowerCase();
    const signature = String(value && value.signature || '').trim();
    if (Number(value && value.version) !== 1 || !/^[a-f0-9]{32}$/.test(signerID) || !signature) {
      throw new Error(app.t('plugins.package.signatureInvalid'));
    }
    return { signerID, signature };
  }

	function managerMatchSignatureFiles(archives, signatures) {
		const selected = Array.isArray(signatures) ? signatures.filter(Boolean) : [];
		if (!selected.length) return archives.map(() => null);
		if (archives.length === 1 && selected.length === 1) return [selected[0]];
		const byName = new Map();
		selected.forEach((file) => byName.set(String(file.name || '').toLowerCase(), file));
		const matched = archives.map((archive) => byName.get((String(archive.name || '') + '.sig').toLowerCase()) || null);
		const matchedFiles = new Set(matched.filter(Boolean));
		if (matchedFiles.size !== selected.length) throw new Error(app.t('plugins.package.signatureUnmatched'));
		return matched;
	}

  async function managerRawRequest(method, path, body, headers) {
    const requestHeaders = Object.assign({ Authorization: 'Bearer ' + app.getToken() }, headers || {});
	const adminToken = typeof app.getPluginAdminToken === 'function' ? app.getPluginAdminToken() : '';
	if (adminToken) requestHeaders['X-Veer-Plugin-Admin'] = adminToken;
    app.state.activeRequests = Number(app.state.activeRequests || 0) + 1;
    if (typeof app.renderOverview === 'function') app.renderOverview();
    try {
      const response = await fetch(path, { method, headers: requestHeaders, body });
      if (response.status === 401) {
        app.clearToken();
        app.showTokenModal();
        throw new Error('unauthorized');
      }
      let payload = {};
      try {
        payload = await response.json();
      } catch (_) {
        payload = { error: response.statusText || app.t('plugins.manager.unknownError') };
      }
      if (!response.ok) {
        const error = new Error(payload.error || response.statusText || app.t('plugins.manager.unknownError'));
        error.payload = payload;
        error.status = response.status;
        throw error;
      }
      return payload;
    } finally {
      app.state.activeRequests = Math.max(0, Number(app.state.activeRequests || 0) - 1);
      if (typeof app.renderOverview === 'function') app.renderOverview();
    }
  }

	function managerAPIRequest(method, path, body) {
		if (typeof app.pluginAdminAPICall === 'function') return app.pluginAdminAPICall(method, path, body);
		return app.apiCall(method, path, body);
	}

	function managerRenderAccess() {
		const state = managerState();
		const status = state.adminStatus || {};
		managerSetHeader(app.t('plugins.admin.title'), app.t('plugins.admin.meta'));
		const tokenInput = app.createNode('input', {
			attrs: { type: 'password', autocomplete: 'off', spellcheck: 'false', placeholder: app.t('plugins.admin.placeholder') }
		});
		const unlockButton = managerButton(app.t('plugins.admin.unlock'), '', async () => {
			const token = String(tokenInput.value || '').trim();
			if (!token) {
				app.notify('error', app.t('plugins.admin.required'));
				return;
			}
			if (typeof app.setPluginAdminToken === 'function') app.setPluginAdminToken(token);
			managerSetButtonBusy(unlockButton, true, app.t('plugins.admin.checking'), app.t('plugins.admin.unlock'));
			try {
				const checked = await managerAPIRequest('GET', '/api/plugin-admin/status');
				if (!checked.authorized) throw new Error(app.t('plugins.admin.invalid'));
				state.adminStatus = checked;
				tokenInput.value = '';
				app.notify('success', app.t('plugins.admin.unlocked'));
			} catch (error) {
				if (typeof app.clearPluginAdminToken === 'function') app.clearPluginAdminToken();
				state.adminStatus = { configured: status.configured, authorized: false };
				app.notify('error', app.t('plugins.admin.unlockFailed', { message: managerErrorText(error) }));
			} finally {
				managerSetButtonBusy(unlockButton, false, app.t('plugins.admin.checking'), app.t('plugins.admin.unlock'));
				if (state.open && state.view === 'access') managerRenderAccess();
			}
		});
		const clearButton = managerButton(app.t('plugins.admin.lock'), 'mini-btn', () => {
			if (typeof app.clearPluginAdminToken === 'function') app.clearPluginAdminToken();
			state.adminStatus = { configured: !!status.configured, authorized: false };
			app.notify('success', app.t('plugins.admin.locked'));
			managerRenderAccess();
		}, { disabled: !status.authorized });
		const tone = !status.configured ? 'danger' : (status.authorized ? '' : 'warning');
		const statusText = !status.configured
			? app.t('plugins.admin.disabled')
			: (status.authorized ? app.t('plugins.admin.active') : app.t('plugins.admin.lockedStatus'));
		managerRender(app.createNode('div', {
			className: 'plugin-manager-stack',
			children: [
				managerNotice(statusText, tone),
				managerSection(app.t('plugins.admin.sessionTitle'), [
					app.createNode('div', { className: 'plugin-manager-form-grid', children: [managerField(app.t('plugins.admin.token'), tokenInput, app.t('plugins.admin.sessionHint'), true)] }),
					app.createNode('div', { className: 'plugin-manager-inline-actions', children: [unlockButton, clearButton] })
				])
			]
		}));
		managerFocusInitial();
	}

	async function managerLoadAccess() {
		const requestID = managerNextRequest();
		managerSetHeader(app.t('plugins.admin.title'), app.t('plugins.admin.meta'));
		managerRender(managerLoading());
		try {
			const status = await managerAPIRequest('GET', '/api/plugin-admin/status');
			if (!managerRequestCurrent(requestID, 'access')) return;
			managerState().adminStatus = status || {};
			managerRenderAccess();
		} catch (error) {
			if (managerRequestCurrent(requestID, 'access')) managerShowError(error, managerLoadAccess);
		}
	}

  function managerStageOperation(stage) {
    if (stage && stage.history_id) return app.t('plugins.package.operation.rollback');
    if (stage && stage.existing_version) return app.t('plugins.package.operation.update');
    return app.t('plugins.package.operation.install');
  }

  function managerDependencyText(item) {
    return [item && item.id, item && item.version, item && item.optional ? app.t('plugins.package.optional') : ''].filter(Boolean).join(' ');
  }

  function managerConflictText(item) {
    return [item && item.id, item && item.version].filter(Boolean).join(' ');
  }

  function managerCompatibilityText(value) {
    if (!value || typeof value !== 'object') return '';
    return [
      value.runtime ? 'runtime ' + value.runtime : '',
      value.tc_pipeline_abi ? 'TC ABI ' + value.tc_pipeline_abi : '',
      Array.isArray(value.os) && value.os.length ? 'OS ' + value.os.join('/') : '',
      Array.isArray(value.architectures) && value.architectures.length ? 'arch ' + value.architectures.join('/') : '',
      value.kernel ? 'kernel ' + value.kernel : '',
      Array.isArray(value.features) && value.features.length ? 'features ' + value.features.join('/') : ''
    ].filter(Boolean).join(' | ');
  }

  function managerRuntimeSurfaceText(surface) {
    const value = surface && typeof surface === 'object' ? surface : {};
    return [
      app.t('plugins.objects') + ' ' + (Array.isArray(value.objects) ? value.objects.length : 0),
      app.t('plugins.hooks') + ' ' + (Array.isArray(value.hooks) ? value.hooks.length : 0),
      app.t('plugins.manager.resources') + ' ' + (Array.isArray(value.resources) ? value.resources.length : 0),
      app.t('common.actions') + ' ' + (Array.isArray(value.actions) ? value.actions.length : 0)
    ].join(' / ');
  }

  function managerRenderStageReview() {
    const state = managerState();
	const activeStages = managerActiveStages();
	if (activeStages.length > 1) {
	  managerRenderBatchStageReview(activeStages);
	  return;
	}
	const stage = activeStages[0];
    if (!stage) {
      managerRenderPackageInput();
      return;
    }
    managerSetHeader(app.t('plugins.package.reviewTitle'), app.t('plugins.package.reviewMeta', { id: stage.plugin_id, version: stage.version }));
    const privilegeAdditions = Array.isArray(stage.privilege_additions) ? stage.privilege_additions : [];
    const dependencies = Array.isArray(stage.dependencies) ? stage.dependencies.map(managerDependencyText).filter(Boolean) : [];
    const conflicts = Array.isArray(stage.conflicts) ? stage.conflicts.map(managerConflictText).filter(Boolean) : [];
    const permissions = Array.isArray(stage.permissions) ? stage.permissions : [];
    const affected = Array.isArray(stage.affected_plugins) ? stage.affected_plugins : [];
    const needsUnsigned = !stage.trusted;
    const needsPrivileges = privilegeAdditions.length > 0;
    const facts = managerFacts([
      { label: app.t('plugins.manager.plugin'), value: [stage.name, stage.plugin_id].filter(Boolean).join(' / ') },
      { label: app.t('plugins.package.operation'), value: managerStageOperation(stage) },
      { label: app.t('plugins.version'), value: stage.version || app.t('common.dash') },
      { label: app.t('plugins.package.currentVersion'), value: stage.existing_version || app.t('plugins.package.notInstalled') },
      { label: app.t('plugins.package.signatureState'), value: stage.history_id ? app.t('plugins.package.trustedHistory') : (stage.trusted ? app.t('plugins.package.trusted') : app.t('plugins.package.unsigned')) },
	  { label: app.t('plugins.package.executionTier'), value: app.t('plugins.package.executionTier.' + String(stage.execution_tier || 'control')) },
      { label: app.t('plugins.package.trustedPublisherRequired'), value: stage.requires_trusted_publisher ? app.t('common.yes') : app.t('common.no') },
      { label: app.t('plugins.package.signer'), value: stage.signer_name ? stage.signer_name + ' / ' + stage.signer_id : app.t('common.dash'), mono: !!stage.signer_id },
	  stage.signer_id ? { label: app.t('plugins.trust.scope'), value: managerTrustScopeSummary(stage.signer_scope), title: managerTrustScopeDetail(stage.signer_scope) } : null,
      { label: app.t('plugins.package.expires'), value: managerFormatDate(stage.expires_at) },
      { label: 'SHA256', value: managerShortText(stage.archive_sha256, 28), title: stage.archive_sha256, mono: true },
      { label: app.t('plugins.package.compatibility'), value: managerCompatibilityText(stage.compatibility) || app.t('common.dash') },
      { label: app.t('plugins.package.surface'), value: managerRuntimeSurfaceText(stage.runtime_surface) }
    ]);
    const sections = [managerSection(app.t('plugins.package.summary'), [facts])];
	const repositoryPlan = state.repositoryPlan || null;
	if (repositoryPlan && Array.isArray(repositoryPlan.reused) && repositoryPlan.reused.length) {
	  sections.push(managerSection(app.t('plugins.repository.reused'), [managerList(repositoryPlan.reused.map((item) => item.plugin_id + ' ' + item.version))]));
	}
    if (permissions.length) sections.push(managerSection(app.t('plugins.package.permissions'), [managerList(permissions)]));
    if (dependencies.length) sections.push(managerSection(app.t('plugins.package.dependencies'), [managerList(dependencies)]));
    if (conflicts.length) sections.push(managerSection(app.t('plugins.package.conflicts'), [managerList(conflicts)]));
    if (affected.length) sections.push(managerSection(app.t('plugins.package.affected'), [managerList(affected)]));
    if (needsUnsigned) sections.push(managerNotice(app.t(managerRequiresSignedPackages() ? 'plugins.package.unsignedBlocked' : 'plugins.package.unsignedWarning'), 'warning'));
    if (needsPrivileges) {
      sections.push(managerSection(app.t('plugins.package.privilegeAdditions'), [
        managerList(privilegeAdditions),
        managerNotice(app.t('plugins.package.privilegeWarning'), 'warning')
      ]));
    }

    const approvals = [];
    if (needsUnsigned && !managerRequiresSignedPackages()) {
      const input = app.createNode('input', { attrs: { type: 'checkbox' } });
      input.checked = !!state.approveUnsigned;
      input.addEventListener('change', () => {
        state.approveUnsigned = !!input.checked;
        applyButton.disabled = !managerStageApproved(stage, state) || state.busy;
      });
      approvals.push(app.createNode('label', {
        className: 'plugin-manager-approval',
        children: [input, app.createNode('span', { text: app.t('plugins.package.approveUnsigned') })]
      }));
    }
    if (needsPrivileges) {
      const input = app.createNode('input', { attrs: { type: 'checkbox' } });
      input.checked = !!state.approvePrivileges;
      input.addEventListener('change', () => {
        state.approvePrivileges = !!input.checked;
        applyButton.disabled = !managerStageApproved(stage, state) || state.busy;
      });
      approvals.push(app.createNode('label', {
        className: 'plugin-manager-approval',
        children: [input, app.createNode('span', { text: app.t('plugins.package.approvePrivileges') })]
      }));
    }
    const applyButton = managerButton(app.t('plugins.package.apply'), '', () => app.applyStagedPluginPackage(applyButton), {
      disabled: !managerStageApproved(stage, state) || state.busy
    });
    const resetButton = managerButton(app.t('plugins.package.chooseAnother'), 'btn-cancel', () => {
	  managerResetInstallSelection();
    }, { disabled: !!state.busy });
    sections.push(app.createNode('div', {
      className: 'plugin-manager-stack',
      children: approvals.concat([
        app.createNode('div', { className: 'plugin-manager-actions', children: [resetButton, applyButton] })
      ])
    }));
    managerRender(app.createNode('div', { className: 'plugin-manager-stack', children: sections }));
  }

	function managerRenderBatchStageReview(stages) {
		const state = managerState();
		managerSetHeader(app.t('plugins.package.batchReviewTitle'), app.t('plugins.package.batchReviewMeta', { count: stages.length }));
		const needsUnsigned = stages.some((stage) => !stage.trusted);
		const needsPrivileges = stages.some((stage) => Array.isArray(stage.privilege_additions) && stage.privilege_additions.length);
		const rows = stages.map((stage) => [
			app.createNode('code', { className: 'plugin-manager-mono', text: stage.plugin_id || '' }),
			app.createNode('span', { text: managerStageOperation(stage) }),
			app.createNode('span', { text: stage.version || app.t('common.dash') }),
			app.createNode('span', { text: stage.trusted ? app.t('plugins.package.trusted') : app.t('plugins.package.unsigned') }),
			app.createNode('span', { text: String(Array.isArray(stage.privilege_additions) ? stage.privilege_additions.length : 0) }),
			app.createNode('span', { text: String(Array.isArray(stage.dependencies) ? stage.dependencies.length : 0) })
		]);
		const sections = [managerSection(app.t('plugins.package.summary'), [managerTable([
			app.t('plugins.manager.plugin'), app.t('plugins.package.operation'), app.t('plugins.version'),
			app.t('plugins.package.signatureState'), app.t('plugins.package.privilegeAdditions'), app.t('plugins.package.dependencies')
		], rows)])];
		const repositoryPlan = state.repositoryPlan || null;
		if (repositoryPlan && Array.isArray(repositoryPlan.reused) && repositoryPlan.reused.length) {
			sections.push(managerSection(app.t('plugins.repository.reused'), [managerList(repositoryPlan.reused.map((item) => item.plugin_id + ' ' + item.version))]));
		}
		if (needsUnsigned) sections.push(managerNotice(app.t(managerRequiresSignedPackages() ? 'plugins.package.batchUnsignedBlocked' : 'plugins.package.batchUnsignedWarning'), 'warning'));
		if (needsPrivileges) sections.push(managerNotice(app.t('plugins.package.batchPrivilegeWarning'), 'warning'));

		const approvals = [];
		let applyButton;
		if (needsUnsigned && !managerRequiresSignedPackages()) {
			const input = app.createNode('input', { attrs: { type: 'checkbox' } });
			input.checked = !!state.approveUnsigned;
			input.addEventListener('change', () => {
				state.approveUnsigned = !!input.checked;
				applyButton.disabled = !managerStagesApproved(stages, state) || state.busy;
			});
			approvals.push(app.createNode('label', {
				className: 'plugin-manager-approval',
				children: [input, app.createNode('span', { text: app.t('plugins.package.approveUnsignedBatch') })]
			}));
		}
		if (needsPrivileges) {
			const input = app.createNode('input', { attrs: { type: 'checkbox' } });
			input.checked = !!state.approvePrivileges;
			input.addEventListener('change', () => {
				state.approvePrivileges = !!input.checked;
				applyButton.disabled = !managerStagesApproved(stages, state) || state.busy;
			});
			approvals.push(app.createNode('label', {
				className: 'plugin-manager-approval',
				children: [input, app.createNode('span', { text: app.t('plugins.package.approvePrivilegesBatch') })]
			}));
		}
		applyButton = managerButton(app.t('plugins.package.applyBatch'), '', () => app.applyStagedPluginPackages(applyButton), {
			disabled: !managerStagesApproved(stages, state) || state.busy
		});
		const resetButton = managerButton(app.t('plugins.package.chooseAnother'), 'btn-cancel', () => {
			managerResetInstallSelection();
		}, { disabled: !!state.busy });
		sections.push(app.createNode('div', {
			className: 'plugin-manager-stack',
			children: approvals.concat([app.createNode('div', { className: 'plugin-manager-actions', children: [resetButton, applyButton] })])
		}));
		managerRender(app.createNode('div', { className: 'plugin-manager-stack', children: sections }));
	}

  function managerStageApproved(stage, state) {
    const additions = Array.isArray(stage && stage.privilege_additions) ? stage.privilege_additions : [];
    if (stage && !stage.trusted && managerRequiresSignedPackages()) return false;
    if (stage && !stage.trusted && !state.approveUnsigned) return false;
    if (additions.length && !state.approvePrivileges) return false;
    return true;
  }

	function managerStagesApproved(stages, state) {
		return Array.isArray(stages) && stages.length > 0 && stages.every((stage) => managerStageApproved(stage, state));
	}

	function managerResetInstallSelection() {
		const state = managerState();
		const returnToRepositories = state.installReturnView === 'repositories';
		state.stage = null;
		state.stages = [];
		state.repositoryPlan = null;
		state.installReturnView = '';
		state.approveUnsigned = false;
		state.approvePrivileges = false;
		if (returnToRepositories) {
			state.view = 'repositories';
			managerRenderNav();
			managerLoadRepositories();
			return;
		}
		managerRenderPackageInput();
	}

  app.stagePluginPackage = async function stagePluginPackage(archiveFile, signatureFile, button) {
    const state = managerState();
    if (state.busy || !archiveFile) return null;
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.package.staging'), app.t('plugins.package.stage'));
    try {
      const sidecar = await managerReadSignatureSidecar(signatureFile);
      const headers = { 'Content-Type': archiveFile.type || 'application/gzip' };
      if (sidecar.signerID) headers['X-Veer-Plugin-Signer'] = sidecar.signerID;
      if (sidecar.signature) headers['X-Veer-Plugin-Signature'] = sidecar.signature;
      const stage = await managerRawRequest('POST', packageArchivePath, archiveFile, headers);
      state.stage = stage;
	  state.stages = [stage];
	  state.repositoryPlan = null;
	  state.installReturnView = '';
      state.approveUnsigned = false;
      state.approvePrivileges = false;
      managerRenderStageReview();
      return stage;
    } catch (error) {
      if (managerState().open) app.notify('error', app.t('plugins.package.stageFailed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.package.staging'), app.t('plugins.package.stage'));
	  if (state.open && state.view === 'install' && managerActiveStages().length) managerRenderStageReview();
    }
  };

	app.stagePluginPackages = async function stagePluginPackages(archiveFiles, signatureFiles, button) {
		const state = managerState();
		const archives = Array.isArray(archiveFiles) ? archiveFiles.filter(Boolean) : [];
		if (state.busy || !archives.length || archives.length > 16) return null;
		state.busy = true;
		managerRenderNav();
		managerSetButtonBusy(button, true, app.t('plugins.package.stagingBatch', { count: archives.length }), app.t('plugins.package.stage'));
		try {
			const matchedSignatures = managerMatchSignatureFiles(archives, signatureFiles);
			const stages = [];
			for (let index = 0; index < archives.length; index += 1) {
				const archiveFile = archives[index];
				const sidecar = await managerReadSignatureSidecar(matchedSignatures[index]);
				const headers = { 'Content-Type': archiveFile.type || 'application/gzip' };
				if (sidecar.signerID) headers['X-Veer-Plugin-Signer'] = sidecar.signerID;
				if (sidecar.signature) headers['X-Veer-Plugin-Signature'] = sidecar.signature;
				const path = packageArchivePath + (archives.length > 1 ? '?defer_relationships=true' : '');
				stages.push(await managerRawRequest('POST', path, archiveFile, headers));
			}
			state.stages = stages;
			state.stage = stages.length === 1 ? stages[0] : null;
			state.repositoryPlan = null;
			state.installReturnView = '';
			state.approveUnsigned = false;
			state.approvePrivileges = false;
			managerRenderStageReview();
			return stages;
		} catch (error) {
			if (managerState().open) app.notify('error', app.t('plugins.package.stageFailed', { message: managerErrorText(error) }));
			return null;
		} finally {
			state.busy = false;
			managerRenderNav();
			managerSetButtonBusy(button, false, app.t('plugins.package.stagingBatch', { count: archives.length }), app.t('plugins.package.stage'));
			if (state.open && state.view === 'install' && managerActiveStages().length) managerRenderStageReview();
		}
	};

  app.applyStagedPluginPackage = async function applyStagedPluginPackage(button) {
    const state = managerState();
    const stage = state.stage;
    if (state.busy || !stage || !managerStageApproved(stage, state)) return null;
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.package.applying'), app.t('plugins.package.apply'));
    try {
      const result = await managerAPIRequest('POST', '/api/plugin-packages/apply', {
        stage_id: stage.id,
        approved_privilege_digest: Array.isArray(stage.privilege_additions) && stage.privilege_additions.length ? stage.privilege_digest : '',
        allow_unsigned: !stage.trusted && !!state.approveUnsigned
      });
      if (result && result.catalog) {
        app.state.plugins.catalog = result.catalog;
        app.state.plugins.data = Array.isArray(result.catalog.plugins) ? result.catalog.plugins : [];
        if (typeof app.renderPluginsTable === 'function') app.renderPluginsTable();
      } else if (typeof app.loadPlugins === 'function') {
        await app.loadPlugins();
      }
      app.notify('success', app.t('plugins.package.applied', { id: stage.plugin_id, version: stage.version }));
      app.closePluginManager(true);
      return result;
    } catch (error) {
      app.notify('error', app.t('plugins.package.applyFailed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.package.applying'), app.t('plugins.package.apply'));
    }
  };

	app.applyStagedPluginPackages = async function applyStagedPluginPackages(button) {
		const state = managerState();
		const stages = managerActiveStages();
		if (state.busy || stages.length < 2 || !managerStagesApproved(stages, state)) return null;
		state.busy = true;
		managerRenderNav();
		managerSetButtonBusy(button, true, app.t('plugins.package.applyingBatch'), app.t('plugins.package.applyBatch'));
		try {
			const result = await managerAPIRequest('POST', '/api/plugin-packages/apply-batch', {
				stages: stages.map((stage) => ({
					stage_id: stage.id,
					approved_privilege_digest: Array.isArray(stage.privilege_additions) && stage.privilege_additions.length ? stage.privilege_digest : '',
					allow_unsigned: !stage.trusted && !!state.approveUnsigned
				}))
			});
			if (result && result.catalog) {
				app.state.plugins.catalog = result.catalog;
				app.state.plugins.data = Array.isArray(result.catalog.plugins) ? result.catalog.plugins : [];
				if (typeof app.renderPluginsTable === 'function') app.renderPluginsTable();
			} else if (typeof app.loadPlugins === 'function') {
				await app.loadPlugins();
			}
			app.notify('success', app.t('plugins.package.batchApplied', { count: stages.length }));
			app.closePluginManager(true);
			return result;
		} catch (error) {
			app.notify('error', app.t('plugins.package.applyFailed', { message: managerErrorText(error) }));
			return null;
		} finally {
			state.busy = false;
			managerRenderNav();
			managerSetButtonBusy(button, false, app.t('plugins.package.applyingBatch'), app.t('plugins.package.applyBatch'));
		}
	};

	function managerRepositoryByID(repositoryID) {
		const id = String(repositoryID || '').trim();
		return managerState().repositories.find((repository) => repository && repository.id === id) || null;
	}

	function managerRepositoryProvenanceStatus(pluginID) {
		return managerState().provenance.find((item) => item && item.plugin_id === pluginID) || null;
	}

	function managerRepositoryPolicy(pluginID) {
		return managerState().repositoryPolicies.find((item) => item && item.plugin_id === pluginID) || null;
	}

	function managerRepositoryUpdateStatusText(status) {
		const key = 'plugins.repository.updateStatus.' + String(status || 'unavailable');
		return app.t(key);
	}

	function managerRenderRepositoryPolicyForm(update) {
		const state = managerState();
		const pluginID = String(update && update.plugin_id || state.repositoryPolicyPluginID || '').trim();
		const existing = managerRepositoryPolicy(pluginID);
		const repositorySelect = app.createNode('select');
		state.repositories.forEach((repository) => repositorySelect.appendChild(app.createNode('option', {
			text: repository.name || repository.id,
			attrs: { value: repository.id }
		})));
		repositorySelect.value = existing && existing.repository_id || update && update.repository_id || state.selectedRepositoryID || '';
		const channelSelect = app.createNode('select', { children: [
			app.createNode('option', { text: app.t('plugins.repository.channel.stable'), attrs: { value: 'stable' } }),
			app.createNode('option', { text: app.t('plugins.repository.channel.preview'), attrs: { value: 'preview' } })
		] });
		channelSelect.value = existing && existing.channel || update && update.channel || 'stable';
		const pinInput = app.createNode('input', { attrs: {
			type: 'text', autocomplete: 'off', spellcheck: 'false', maxlength: '64', placeholder: app.t('plugins.repository.policy.pinPlaceholder')
		} });
		pinInput.value = existing && existing.pinned_version || '';
		const holdInput = app.createNode('input', { attrs: { type: 'checkbox' } });
		holdInput.checked = !!(existing && existing.hold);
		const holdControl = app.createNode('label', {
			className: 'plugin-manager-approval',
			children: [holdInput, app.createNode('span', { text: app.t('plugins.repository.policy.holdHint') })]
		});
		let saveButton;
		saveButton = managerButton(app.t('common.save'), '', async () => {
			if (state.busy || !pluginID || !repositorySelect.value) return;
			state.busy = true;
			managerRenderNav();
			managerSetButtonBusy(saveButton, true, app.t('plugins.repository.policy.saving'), app.t('common.save'));
			try {
				await managerAPIRequest('PUT', '/api/plugin-repository-policies', {
					plugin_id: pluginID,
					repository_id: repositorySelect.value,
					channel: channelSelect.value,
					pinned_version: String(pinInput.value || '').trim(),
					hold: !!holdInput.checked
				});
				state.repositoryPolicyPluginID = '';
				app.notify('success', app.t('plugins.repository.policy.saved', { id: pluginID }));
				await managerLoadRepositories();
			} catch (error) {
				app.notify('error', app.t('plugins.repository.policy.saveFailed', { message: managerErrorText(error) }));
			} finally {
				state.busy = false;
				managerRenderNav();
				managerSetButtonBusy(saveButton, false, app.t('plugins.repository.policy.saving'), app.t('common.save'));
			}
		}, { disabled: !!state.busy || !state.repositories.length });
		const cancelButton = managerButton(app.t('common.cancel'), 'btn-cancel', () => {
			state.repositoryPolicyPluginID = '';
			managerRenderRepositories();
		}, { disabled: !!state.busy });
		const actions = [cancelButton, saveButton];
		if (existing) {
			actions.unshift(managerButton(app.t('plugins.repository.policy.remove'), 'plugin-manager-danger-btn', async () => {
				if (state.busy) return;
				state.busy = true;
				managerRenderNav();
				try {
					await managerAPIRequest('DELETE', '/api/plugin-repository-policies', { plugin_id: pluginID });
					state.repositoryPolicyPluginID = '';
					app.notify('success', app.t('plugins.repository.policy.removed', { id: pluginID }));
					await managerLoadRepositories();
				} catch (error) {
					app.notify('error', app.t('plugins.repository.policy.removeFailed', { message: managerErrorText(error) }));
				} finally {
					state.busy = false;
					managerRenderNav();
				}
			}, { disabled: !!state.busy }));
		}
		return managerSection(app.t('plugins.repository.policy.editTitle', { id: pluginID }), [
			app.createNode('div', { className: 'plugin-manager-form-grid', children: [
				managerField(app.t('plugins.repository.selected'), repositorySelect),
				managerField(app.t('plugins.repository.channel'), channelSelect),
				managerField(app.t('plugins.repository.policy.pin'), pinInput, app.t('plugins.repository.policy.pinHint')),
				managerField(app.t('plugins.repository.policy.hold'), holdControl)
			] }),
			app.createNode('div', { className: 'plugin-manager-inline-actions', children: actions })
		]);
	}

	function managerRepositoryStatusText(target) {
		if (target && target.revoked) return app.t('plugins.repository.status.revoked');
		const provenance = managerRepositoryProvenanceStatus(target && target.plugin_id);
		if (provenance && provenance.version === target.version) {
			const key = 'plugins.repository.status.' + String(provenance.status || 'trusted');
			return app.t(key);
		}
		const installed = managerPlugin(target && target.plugin_id);
		if (installed && installed.version === target.version) return app.t('plugins.repository.status.installed');
		if (installed && installed.version) return app.t('plugins.repository.status.installedVersion', { version: installed.version });
		return app.t('plugins.repository.status.available');
	}

	function managerRenderRepositoryForm() {
		const state = managerState();
		const idInput = app.createNode('input', { attrs: { type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false' } });
		const nameInput = app.createNode('input', { attrs: { type: 'text', maxlength: '128', autocomplete: 'off' } });
		const metadataInput = app.createNode('input', { attrs: { type: 'url', autocomplete: 'off', spellcheck: 'false', placeholder: 'https://example.com/metadata/' } });
		const targetsInput = app.createNode('input', { attrs: { type: 'url', autocomplete: 'off', spellcheck: 'false', placeholder: 'https://example.com/targets/' } });
		const channelSelect = app.createNode('select', { children: [
			app.createNode('option', { text: app.t('plugins.repository.channel.stable'), attrs: { value: 'stable' } }),
			app.createNode('option', { text: app.t('plugins.repository.channel.preview'), attrs: { value: 'preview' } })
		] });
		const rootInput = app.createNode('textarea', { attrs: { rows: '5', autocomplete: 'off', spellcheck: 'false', placeholder: app.t('plugins.repository.rootPlaceholder') } });
		const addButton = managerButton(app.t('plugins.repository.add'), '', async () => {
			let root;
			try {
				root = JSON.parse(String(rootInput.value || '').trim());
			} catch (_) {
				app.notify('error', app.t('plugins.repository.rootInvalid'));
				rootInput.focus();
				return;
			}
			const request = {
				id: String(idInput.value || '').trim(),
				name: String(nameInput.value || '').trim(),
				metadata_url: String(metadataInput.value || '').trim(),
				targets_url: String(targetsInput.value || '').trim(),
				channel: String(channelSelect.value || 'stable'),
				root
			};
			if (!request.id || !request.name || !request.metadata_url || !request.targets_url) {
				app.notify('error', app.t('plugins.repository.required'));
				return;
			}
			state.busy = true;
			managerRenderNav();
			managerSetButtonBusy(addButton, true, app.t('plugins.repository.adding'), app.t('plugins.repository.add'));
			try {
				const repository = await managerAPIRequest('POST', '/api/plugin-repositories', request);
				state.selectedRepositoryID = repository.id;
				state.repositoryFormOpen = false;
				app.notify('success', app.t('plugins.repository.added', { name: repository.name || repository.id }));
				await managerLoadRepositories();
			} catch (error) {
				app.notify('error', app.t('plugins.repository.addFailed', { message: managerErrorText(error) }));
			} finally {
				state.busy = false;
				managerRenderNav();
				managerSetButtonBusy(addButton, false, app.t('plugins.repository.adding'), app.t('plugins.repository.add'));
			}
		});
		return managerSection(app.t('plugins.repository.addTitle'), [
			app.createNode('div', { className: 'plugin-manager-form-grid', children: [
				managerField(app.t('plugins.repository.id'), idInput),
				managerField(app.t('plugins.repository.name'), nameInput),
				managerField(app.t('plugins.repository.metadataURL'), metadataInput, '', true),
				managerField(app.t('plugins.repository.targetsURL'), targetsInput, '', true),
				managerField(app.t('plugins.repository.channel'), channelSelect),
				managerField(app.t('plugins.repository.root'), rootInput, app.t('plugins.repository.rootHint'), true)
			] }),
			app.createNode('div', { className: 'plugin-manager-inline-actions', children: [addButton] })
		]);
	}

	function managerRenderRepositories() {
		const state = managerState();
		managerSetHeader(app.t('plugins.repository.title'), app.t('plugins.repository.meta'));
		const sections = [];
		const unhealthy = state.provenance.filter((item) => item && item.status && item.status !== 'trusted');
		if (unhealthy.length) {
			sections.push(managerNotice(app.t('plugins.repository.provenanceWarning', { count: unhealthy.length }), 'warning'));
			sections.push(managerSection(app.t('plugins.repository.installedTrust'), [managerList(unhealthy.map((item) => {
				const reason = item.revocation_reason ? ': ' + item.revocation_reason : '';
				return item.plugin_id + ' ' + item.version + ' / ' + app.t('plugins.repository.status.' + item.status) + reason;
			}))]));
		}
		const addToggle = managerButton(
			state.repositoryFormOpen ? app.t('common.cancel') : app.t('plugins.repository.add'),
			'mini-btn',
			() => {
				state.repositoryFormOpen = !state.repositoryFormOpen;
				managerRenderRepositories();
			},
			{ disabled: !!state.busy }
		);
		if (!state.repositories.length) {
			sections.push(managerSection(app.t('plugins.repository.configured'), [managerEmpty(app.t('plugins.repository.empty'))], addToggle));
			if (state.repositoryFormOpen) sections.push(managerRenderRepositoryForm());
			managerRender(app.createNode('div', { className: 'plugin-manager-stack', children: sections }));
			return;
		}
		const selector = app.createNode('select');
		state.repositories.forEach((repository) => selector.appendChild(app.createNode('option', {
			text: (repository.name || repository.id) + ' / ' + repository.channel,
			attrs: { value: repository.id }
		})));
		selector.value = state.selectedRepositoryID || state.repositories[0].id;
		selector.addEventListener('change', () => {
			state.selectedRepositoryID = selector.value;
			managerLoadRepositories();
		});
		const repository = managerRepositoryByID(selector.value);
		let refreshButton;
		refreshButton = managerButton(app.t('plugins.repository.refresh'), 'mini-btn', () => managerRefreshRepository(refreshButton), { disabled: !!state.busy });
		const deleteButton = managerButton(app.t('plugins.repository.delete'), 'mini-btn plugin-manager-danger-btn', () => managerDeleteRepository(repository), { disabled: !!state.busy });
		sections.push(managerSection(app.t('plugins.repository.configured'), [
			app.createNode('div', { className: 'plugin-manager-form-grid', children: [managerField(app.t('plugins.repository.selected'), selector, '', true)] }),
			repository ? managerFacts([
				{ label: app.t('plugins.repository.channel'), value: repository.channel },
				{ label: app.t('plugins.repository.targets'), value: String(repository.target_count || 0) },
				{ label: app.t('plugins.repository.lastRefresh'), value: managerFormatDate(repository.last_refresh_at) },
				{ label: app.t('plugins.repository.metadataVersion'), value: String(repository.targets_version || 0) },
				{ label: app.t('plugins.repository.metadataURL'), value: repository.metadata_url, title: repository.metadata_url },
				{ label: app.t('plugins.repository.targetsURL'), value: repository.targets_url, title: repository.targets_url }
			]) : null,
			app.createNode('div', { className: 'plugin-manager-inline-actions', children: [refreshButton, deleteButton] })
		], addToggle));
		if (state.repositoryFormOpen) sections.push(managerRenderRepositoryForm());
		if (state.repositoryUpdates.length) {
			const updateRows = state.repositoryUpdates.map((update) => {
				const policy = managerRepositoryPolicy(update.plugin_id);
				const editButton = managerButton(app.t('plugins.repository.policy.edit'), 'mini-btn', () => {
					state.repositoryPolicyPluginID = update.plugin_id;
					managerRenderRepositories();
				}, { disabled: !!state.busy });
				let updateButton = null;
				if (update.status === 'update_available' && update.target) {
					updateButton = managerButton(app.t('plugins.repository.prepare'), 'mini-btn', () => managerPrepareRepositoryTarget(update.target, updateButton), { disabled: !!state.busy });
				}
				return [
					app.createNode('code', { className: 'plugin-manager-mono', text: update.plugin_id || '' }),
					app.createNode('span', { text: update.current_version || app.t('common.dash') }),
					app.createNode('span', { text: update.available_version || app.t('common.dash') }),
					app.createNode('span', { text: managerRepositoryUpdateStatusText(update.status), title: update.reason || '' }),
					app.createNode('span', { text: policy && policy.pinned_version || app.t('common.dash') }),
					app.createNode('span', { text: policy && policy.hold ? app.t('common.yes') : app.t('common.no') }),
					app.createNode('div', { className: 'plugin-manager-inline-actions', children: [updateButton, editButton].filter(Boolean) })
				];
			});
			sections.push(managerSection(app.t('plugins.repository.updates'), [managerTable([
				app.t('plugins.manager.plugin'), app.t('plugins.package.currentVersion'), app.t('plugins.repository.availableVersion'),
				app.t('common.status'), app.t('plugins.repository.policy.pin'), app.t('plugins.repository.policy.hold'), app.t('common.actions')
			], updateRows)]));
		}
		if (state.repositoryPolicyPluginID) {
			const update = state.repositoryUpdates.find((item) => item && item.plugin_id === state.repositoryPolicyPluginID) || { plugin_id: state.repositoryPolicyPluginID };
			sections.push(managerRenderRepositoryPolicyForm(update));
		}
		if (state.repositoryCatalogError) sections.push(managerNotice(state.repositoryCatalogError, 'warning'));
		const targets = state.repositoryCatalog && Array.isArray(state.repositoryCatalog.targets)
			? state.repositoryCatalog.targets.filter((target) => !repository || target.channel === repository.channel)
			: [];
		if (!targets.length) {
			sections.push(managerSection(app.t('plugins.repository.catalog'), [managerEmpty(app.t('plugins.repository.catalogEmpty'))]));
		} else {
			const rows = targets.map((target) => {
				let installButton;
				installButton = managerButton(
					target.revoked ? app.t('plugins.repository.revoked') : app.t('plugins.repository.prepare'),
					'mini-btn',
					() => managerPrepareRepositoryTarget(target, installButton),
					{ disabled: !!state.busy || !!target.revoked, title: target.revocation_reason || '' }
				);
				return [
					app.createNode('span', { text: target.name || target.plugin_id, title: target.description || target.plugin_id }),
					app.createNode('code', { className: 'plugin-manager-mono', text: target.version || '' }),
					app.createNode('span', { text: target.stability || target.channel || '' }),
					app.createNode('span', { text: String(Array.isArray(target.dependencies) ? target.dependencies.filter((item) => !item.optional).length : 0) }),
					app.createNode('span', { text: managerRepositoryStatusText(target), title: target.revocation_reason || '' }),
					installButton
				];
			});
			sections.push(managerSection(app.t('plugins.repository.catalog'), [managerTable([
				app.t('plugins.manager.plugin'), app.t('plugins.version'), app.t('plugins.stability'),
				app.t('plugins.package.dependencies'), app.t('common.status'), app.t('common.actions')
			], rows)]));
		}
		managerRender(app.createNode('div', { className: 'plugin-manager-stack', children: sections }));
	}

	async function managerLoadRepositories() {
		const state = managerState();
		const requestID = managerNextRequest();
		managerSetHeader(app.t('plugins.repository.title'), app.t('plugins.repository.meta'));
		managerRender(managerLoading());
		try {
			const values = await Promise.all([
				managerAPIRequest('GET', '/api/plugin-repositories'),
				managerAPIRequest('GET', '/api/plugin-packages/provenance'),
				managerAPIRequest('GET', '/api/plugin-repository-policies'),
				managerAPIRequest('GET', '/api/plugin-repositories/updates')
			]);
			if (!managerRequestCurrent(requestID, 'repositories')) return;
			state.repositories = Array.isArray(values[0]) ? values[0] : [];
			state.provenance = Array.isArray(values[1]) ? values[1] : [];
			state.repositoryPolicies = Array.isArray(values[2]) ? values[2] : [];
			state.repositoryUpdates = Array.isArray(values[3]) ? values[3] : [];
			if (!managerRepositoryByID(state.selectedRepositoryID)) {
				state.selectedRepositoryID = state.repositories.length ? state.repositories[0].id : '';
			}
			state.repositoryCatalog = null;
			state.repositoryCatalogError = '';
			if (state.selectedRepositoryID) {
				try {
					state.repositoryCatalog = await managerAPIRequest('GET', '/api/plugin-repositories/catalog?repository_id=' + encodeURIComponent(state.selectedRepositoryID));
				} catch (error) {
					state.repositoryCatalogError = managerErrorText(error);
				}
			}
			if (managerRequestCurrent(requestID, 'repositories')) managerRenderRepositories();
		} catch (error) {
			if (managerRequestCurrent(requestID, 'repositories')) managerShowError(error, managerLoadRepositories);
		}
	}

	async function managerRefreshRepository(button) {
		const state = managerState();
		if (state.busy || !state.selectedRepositoryID) return;
		state.busy = true;
		managerRenderNav();
		managerSetButtonBusy(button, true, app.t('plugins.repository.refreshing'), app.t('plugins.repository.refresh'));
		try {
			await managerAPIRequest('POST', '/api/plugin-repositories/refresh', { repository_id: state.selectedRepositoryID });
			app.notify('success', app.t('plugins.repository.refreshed'));
			await managerLoadRepositories();
		} catch (error) {
			app.notify('error', app.t('plugins.repository.refreshFailed', { message: managerErrorText(error) }));
		} finally {
			state.busy = false;
			managerRenderNav();
			managerSetButtonBusy(button, false, app.t('plugins.repository.refreshing'), app.t('plugins.repository.refresh'));
		}
	}

	async function managerDeleteRepository(repository) {
		if (!repository) return;
		const confirmed = await app.confirmAction({
			title: app.t('plugins.repository.deleteTitle'),
			message: app.t('plugins.repository.deleteConfirm', { name: repository.name || repository.id }),
			confirmText: app.t('plugins.repository.delete'),
			danger: true
		});
		if (!confirmed) return;
		const state = managerState();
		state.busy = true;
		managerRenderNav();
		try {
			await managerAPIRequest('DELETE', '/api/plugin-repositories', { id: repository.id });
			state.selectedRepositoryID = '';
			app.notify('success', app.t('plugins.repository.deleted', { name: repository.name || repository.id }));
			await managerLoadRepositories();
		} catch (error) {
			app.notify('error', app.t('plugins.repository.deleteFailed', { message: managerErrorText(error) }));
		} finally {
			state.busy = false;
			managerRenderNav();
		}
	}

	async function managerPrepareRepositoryTarget(target, button) {
		const state = managerState();
		if (state.busy || !state.selectedRepositoryID || !target || target.revoked) return;
		state.busy = true;
		managerRenderNav();
		managerSetButtonBusy(button, true, app.t('plugins.repository.preparing'), app.t('plugins.repository.prepare'));
		try {
			const plan = await managerAPIRequest('POST', '/api/plugin-repositories/plan', {
				repository_id: state.selectedRepositoryID,
				plugin_id: target.plugin_id,
				version: target.version
			});
			const stages = plan && Array.isArray(plan.stages) ? plan.stages : [];
			if (!stages.length) {
				app.notify('success', app.t('plugins.repository.noChanges'));
				return;
			}
			state.repositoryPlan = plan;
			state.stages = stages;
			state.stage = stages.length === 1 ? stages[0] : null;
			state.installReturnView = 'repositories';
			state.approveUnsigned = false;
			state.approvePrivileges = false;
			state.view = 'install';
		} catch (error) {
			app.notify('error', app.t('plugins.repository.prepareFailed', { message: managerErrorText(error) }));
		} finally {
			state.busy = false;
			managerRenderNav();
			managerSetButtonBusy(button, false, app.t('plugins.repository.preparing'), app.t('plugins.repository.prepare'));
			if (state.open && state.view === 'install' && managerActiveStages().length) managerRenderStageReview();
			else if (state.open && state.view === 'repositories') managerRenderRepositories();
		}
	}

  function managerRenderTrust() {
    const state = managerState();
    managerSetHeader(app.t('plugins.trust.title'), app.t('plugins.trust.meta'));
    const nameInput = app.createNode('input', {
      attrs: { type: 'text', maxlength: '128', autocomplete: 'off', spellcheck: 'false' }
    });
    const keyInput = app.createNode('textarea', {
      attrs: { rows: '3', autocomplete: 'off', spellcheck: 'false' }
    });
	const pluginIDsInput = app.createNode('input', {
	  attrs: { type: 'text', maxlength: '2048', autocomplete: 'off', spellcheck: 'false', placeholder: 'vendor_*, exact_plugin' }
	});
	const permissionsInput = app.createNode('input', {
	  attrs: { type: 'text', maxlength: '4096', autocomplete: 'off', spellcheck: 'false', placeholder: 'plugin.register, resource, ui' }
	});
	const executionTierSelect = app.createNode('select');
	[
	  ['', app.t('plugins.trust.scopeAny')],
	  ['control', app.t('plugins.trust.scopeControl')],
	  ['dataplane', app.t('plugins.trust.scopeDataplane')]
	].forEach((item) => executionTierSelect.appendChild(app.createNode('option', { text: item[1], attrs: { value: item[0] } })));
	const stabilitiesInput = app.createNode('input', {
	  attrs: { type: 'text', maxlength: '256', autocomplete: 'off', spellcheck: 'false', placeholder: 'stable, preview' }
	});
	const replaceSelect = app.createNode('select');
	replaceSelect.appendChild(app.createNode('option', { text: app.t('plugins.trust.noReplacement'), attrs: { value: '' } }));
	state.trustKeys.filter((key) => key && key.status === 'active').forEach((key) => {
	  replaceSelect.appendChild(app.createNode('option', { text: (key.name || key.id) + ' · ' + managerShortText(key.id, 18), attrs: { value: key.id } }));
	});
    const addButton = managerButton(app.t('plugins.trust.add'), '', () => {
	  const scope = managerTrustScopeFromValues(pluginIDsInput.value, permissionsInput.value, executionTierSelect.value, stabilitiesInput.value);
	  app.addPluginTrustKey(nameInput.value, keyInput.value, replaceSelect.value, scope, addButton);
    }, { disabled: !!state.busy });
    const form = managerSection(app.t('plugins.trust.addTitle'), [
      app.createNode('div', {
        className: 'plugin-manager-form-grid',
        children: [
          managerField(app.t('plugins.trust.name'), nameInput, '', false),
		  managerField(app.t('plugins.trust.replaces'), replaceSelect, app.t('plugins.trust.replacesHint'), false),
          managerField(app.t('plugins.trust.publicKey'), keyInput, app.t('plugins.trust.publicKeyHint'), true),
		  managerField(app.t('plugins.trust.scopePlugins'), pluginIDsInput, app.t('plugins.trust.scopePluginsHint'), true),
		  managerField(app.t('plugins.trust.scopePermissions'), permissionsInput, app.t('plugins.trust.scopePermissionsHint'), true),
		  managerField(app.t('plugins.trust.scopeTier'), executionTierSelect, app.t('plugins.trust.scopeTierHint'), false),
		  managerField(app.t('plugins.trust.scopeStabilities'), stabilitiesInput, app.t('plugins.trust.scopeStabilitiesHint'), false)
        ]
      }),
      app.createNode('div', { className: 'plugin-manager-inline-actions', children: [addButton] })
    ]);
    let list;
    if (!state.trustKeys.length) {
      list = managerEmpty(app.t('plugins.trust.empty'));
    } else {
      const rows = state.trustKeys.map((key) => {
		const revoked = key.status === 'revoked';
		const remove = managerButton(app.t('plugins.trust.revoke'), 'mini-btn plugin-manager-danger-btn', () => app.deletePluginTrustKey(key), { disabled: !!state.busy || revoked });
        return [
          app.createNode('span', { text: key.name || app.t('common.dash') }),
          app.createNode('code', { className: 'plugin-manager-mono', text: key.id || '', title: key.id || '' }),
          app.createNode('code', { className: 'plugin-manager-mono', text: managerShortText(key.public_key, 30), title: key.public_key || '' }),
		  app.createNode('span', { text: managerTrustScopeSummary(key.scope), title: managerTrustScopeDetail(key.scope) }),
		  app.createNode('span', { text: revoked ? app.t('plugins.trust.revoked') : app.t('plugins.trust.active'), title: key.replaced_by ? app.t('plugins.trust.replacedBy', { id: key.replaced_by }) : '' }),
          app.createNode('span', { text: managerFormatDate(key.created_at) }),
          remove
        ];
      });
      list = managerTable([
        app.t('plugins.trust.name'),
        app.t('plugins.trust.keyID'),
        app.t('plugins.trust.publicKey'),
		app.t('plugins.trust.scope'),
		app.t('common.status'),
        app.t('plugins.manager.createdAt'),
        app.t('common.actions')
      ], rows);
    }
    managerRender(app.createNode('div', {
      className: 'plugin-manager-stack',
      children: [form, managerSection(app.t('plugins.trust.list'), [list])]
    }));
    managerFocusInitial();
  }

  function managerTrustScopeTokens(value) {
	return Array.from(new Set(String(value || '').split(/[\s,]+/).map((item) => item.trim().toLowerCase()).filter(Boolean))).sort();
  }

  function managerTrustScopeFromValues(pluginIDs, permissions, executionTier, stabilities) {
	const scope = {
	  plugin_ids: managerTrustScopeTokens(pluginIDs),
	  permissions: managerTrustScopeTokens(permissions),
	  execution_tiers: managerTrustScopeTokens(executionTier),
	  stabilities: managerTrustScopeTokens(stabilities)
	};
	return Object.values(scope).some((values) => values.length) ? scope : null;
  }

  function managerTrustScopeDetail(scope) {
	if (!scope || typeof scope !== 'object') return app.t('plugins.trust.scopeGlobalDetail');
	return [
	  Array.isArray(scope.plugin_ids) && scope.plugin_ids.length ? app.t('plugins.trust.scopePlugins') + ': ' + scope.plugin_ids.join(', ') : '',
	  Array.isArray(scope.permissions) && scope.permissions.length ? app.t('plugins.trust.scopePermissions') + ': ' + scope.permissions.join(', ') : '',
	  Array.isArray(scope.execution_tiers) && scope.execution_tiers.length ? app.t('plugins.trust.scopeTier') + ': ' + scope.execution_tiers.join(', ') : '',
	  Array.isArray(scope.stabilities) && scope.stabilities.length ? app.t('plugins.trust.scopeStabilities') + ': ' + scope.stabilities.join(', ') : ''
	].filter(Boolean).join('\n') || app.t('plugins.trust.scopeGlobalDetail');
  }

  function managerTrustScopeSummary(scope) {
	if (!scope || typeof scope !== 'object') return app.t('plugins.trust.scopeGlobal');
	const count = ['plugin_ids', 'permissions', 'execution_tiers', 'stabilities'].reduce((total, key) => {
	  return total + (Array.isArray(scope[key]) ? scope[key].length : 0);
	}, 0);
	return count ? app.t('plugins.trust.scopeRestricted', { count }) : app.t('plugins.trust.scopeGlobal');
  }

  async function managerLoadTrust() {
    const requestID = managerNextRequest();
    managerSetHeader(app.t('plugins.trust.title'), app.t('plugins.trust.meta'));
    managerRender(managerLoading());
    try {
      const keys = await managerAPIRequest('GET', '/api/plugin-trust');
      if (!managerRequestCurrent(requestID, 'trust')) return;
      managerState().trustKeys = Array.isArray(keys) ? keys : [];
      managerRenderTrust();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'trust')) managerShowError(error, managerLoadTrust);
    }
  }

  app.addPluginTrustKey = async function addPluginTrustKey(name, publicKey, replaces, scope, button) {
	if (button === undefined && scope && typeof scope === 'object' && (scope.tagName || scope.classList)) {
	  button = scope;
	  scope = null;
	}
	if (button === undefined && replaces && typeof replaces === 'object') {
	  button = replaces;
	  replaces = '';
	  scope = null;
	}
    const state = managerState();
    const normalizedName = String(name || '').trim();
    const normalizedKey = String(publicKey || '').trim();
    if (state.busy) return null;
    if (!normalizedName || !normalizedKey) {
      app.notify('error', app.t('plugins.trust.required'));
      return null;
    }
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.trust.adding'), app.t('plugins.trust.add'));
    try {
	  const body = { name: normalizedName, public_key: normalizedKey };
	  if (String(replaces || '').trim()) body.replaces = String(replaces).trim();
	  if (scope && typeof scope === 'object') body.scope = scope;
	  const key = await managerAPIRequest('POST', '/api/plugin-trust', body);
      app.notify('success', app.t('plugins.trust.added', { name: key.name || normalizedName }));
      await managerLoadTrust();
      return key;
    } catch (error) {
      app.notify('error', app.t('plugins.trust.addFailed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.trust.adding'), app.t('plugins.trust.add'));
      if (state.open && state.view === 'trust') managerRenderTrust();
    }
  };

  app.deletePluginTrustKey = async function deletePluginTrustKey(key) {
    const state = managerState();
    if (state.busy || !key || !key.id) return false;
    const confirmed = await app.confirmAction({
      title: app.t('plugins.trust.deleteTitle'),
      message: app.t('plugins.trust.deleteConfirm', { name: key.name || key.id }),
	  confirmText: app.t('plugins.trust.revoke'),
      danger: true
    });
    if (!confirmed) return false;
    state.busy = true;
    managerRenderNav();
    try {
      await managerAPIRequest('DELETE', '/api/plugin-trust', { id: key.id });
      app.notify('success', app.t('plugins.trust.deleted', { name: key.name || key.id }));
      await managerLoadTrust();
      return true;
    } catch (error) {
      app.notify('error', app.t('plugins.trust.deleteFailed', { message: managerErrorText(error) }));
      return false;
    } finally {
      state.busy = false;
      managerRenderNav();
      if (state.open && state.view === 'trust') managerRenderTrust();
    }
  };

  function managerAuditDetails(value) {
    try {
      return JSON.stringify(value == null ? {} : value);
    } catch (_) {
      return '{}';
    }
  }

  function managerRenderAudit() {
    const state = managerState();
    managerSetHeader(app.t('plugins.audit.title'), app.t('plugins.audit.meta'));
    const select = app.createNode('select', { className: 'plugin-manager-filter' });
    const all = app.createNode('option', { text: app.t('plugins.audit.allPlugins'), attrs: { value: '' } });
    select.appendChild(all);
    (app.state.plugins.data || []).filter((plugin) => plugin && !plugin.builtin && plugin.id).forEach((plugin) => {
      select.appendChild(app.createNode('option', { text: plugin.name ? plugin.name + ' / ' + plugin.id : plugin.id, attrs: { value: plugin.id } }));
    });
    select.value = state.auditPluginID || '';
    select.addEventListener('change', () => {
      state.auditPluginID = select.value || '';
      managerLoadAudit(false);
    });
    const refresh = managerButton(app.t('common.refresh'), 'mini-btn', () => managerLoadAudit(false));
    const filter = app.createNode('div', { className: 'plugin-manager-filter-row', children: [select, refresh] });
    let list;
    if (!state.auditLogs.length) {
      list = managerEmpty(app.t('plugins.audit.empty'));
    } else {
      list = managerTable([
        app.t('plugins.manager.createdAt'),
        app.t('plugins.manager.plugin'),
        app.t('plugins.audit.operation'),
        app.t('plugins.audit.actor'),
        app.t('plugins.audit.outcome'),
        app.t('plugins.audit.details')
      ], state.auditLogs.map((entry) => {
        const details = managerAuditDetails(entry.details);
        return [
          app.createNode('span', { text: managerFormatDate(entry.created_at) }),
          app.createNode('code', { className: 'plugin-manager-mono', text: entry.plugin_id || app.t('plugins.audit.host') }),
          app.createNode('code', { className: 'plugin-manager-mono', text: entry.operation || '' }),
          app.createNode('span', { text: entry.actor || app.t('common.dash') }),
          app.createNode('span', {
            className: 'plugin-manager-outcome is-' + String(entry.outcome || '').toLowerCase(),
            text: entry.outcome || app.t('common.dash')
          }),
          app.createNode('code', { className: 'plugin-manager-mono', text: managerShortText(details, 150), title: details })
        ];
      }));
    }
    const loadOlder = state.auditHasMore
      ? managerButton(app.t('plugins.audit.loadOlder'), 'mini-btn', () => managerLoadAudit(true))
      : null;
    managerRender(app.createNode('div', {
      className: 'plugin-manager-stack',
      children: [filter, list, loadOlder ? app.createNode('div', { className: 'plugin-manager-actions', children: [loadOlder] }) : null].filter(Boolean)
    }));
  }

  async function managerLoadAudit(append) {
    const state = managerState();
    const requestID = managerNextRequest();
    const pluginID = state.auditPluginID || '';
    let path = '/api/plugin-audit?limit=' + auditPageSize;
    if (pluginID) path += '&plugin_id=' + encodeURIComponent(pluginID);
    if (append && state.auditLogs.length) path += '&before_id=' + encodeURIComponent(String(state.auditLogs[state.auditLogs.length - 1].id));
    managerSetHeader(app.t('plugins.audit.title'), app.t('plugins.audit.meta'));
    if (!append) managerRender(managerLoading());
    try {
      const response = await managerAPIRequest('GET', path);
      if (!managerRequestCurrent(requestID, 'audit')) return;
      const logs = Array.isArray(response && response.logs) ? response.logs : [];
      state.auditLogs = append ? state.auditLogs.concat(logs) : logs;
      state.auditHasMore = logs.length === auditPageSize;
      managerRenderAudit();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'audit')) managerShowError(error, () => managerLoadAudit(!!append));
    }
  }

	function managerDeadLetterDetail(item) {
		return managerAuditDetails({
			delivery_id: item.delivery_id,
			subscription: item.subscription,
			topic: item.topic,
			source_plugin: item.source_plugin,
			target_plugin: item.target_plugin,
			resource: item.resource,
			schema_version: item.schema_version,
			payload: item.payload
		});
	}

	function managerRenderDeadLetters() {
		const state = managerState();
		managerSetHeader(app.t('plugins.deadLetters.title'), app.t('plugins.deadLetters.meta'));
		const select = app.createNode('select', { className: 'plugin-manager-filter' });
		select.appendChild(app.createNode('option', { text: app.t('plugins.deadLetters.allPlugins'), attrs: { value: '' } }));
		(app.state.plugins.data || []).filter((plugin) => plugin && !plugin.builtin && plugin.id).forEach((plugin) => {
			select.appendChild(app.createNode('option', { text: plugin.name ? plugin.name + ' / ' + plugin.id : plugin.id, attrs: { value: plugin.id } }));
		});
		select.value = state.deadLetterPluginID || '';
		select.addEventListener('change', () => {
			state.deadLetterPluginID = select.value || '';
			managerLoadDeadLetters(false);
		});
		const refresh = managerButton(app.t('common.refresh'), 'mini-btn', () => managerLoadDeadLetters(false), { disabled: !!state.busy });
		const filter = app.createNode('div', { className: 'plugin-manager-filter-row', children: [select, refresh] });
		let list;
		if (!state.deadLetters.length) {
			list = managerEmpty(app.t('plugins.deadLetters.empty'));
		} else {
			list = managerTable([
				app.t('plugins.manager.updatedAt'), app.t('plugins.manager.plugin'), app.t('plugins.deadLetters.topic'),
				app.t('plugins.deadLetters.source'), app.t('plugins.deadLetters.attempts'), app.t('plugins.error'), app.t('common.actions')
			], state.deadLetters.map((item) => {
				const detail = managerDeadLetterDetail(item);
				let retryButton;
				retryButton = managerButton(app.t('plugins.deadLetters.retry'), 'mini-btn', () => managerRetryDeadLetter(item, retryButton), {
					disabled: !!state.busy, title: detail
				});
				const discardButton = managerButton(app.t('plugins.deadLetters.discard'), 'mini-btn plugin-manager-danger-btn', () => managerDiscardDeadLetter(item), {
					disabled: !!state.busy, title: detail
				});
				return [
					app.createNode('span', { text: managerFormatDate(item.updated_at) }),
					app.createNode('code', { className: 'plugin-manager-mono', text: item.target_plugin || item.plugin_id || '' }),
					app.createNode('code', { className: 'plugin-manager-mono', text: item.topic || '', title: detail }),
					app.createNode('code', { className: 'plugin-manager-mono', text: item.source_plugin || app.t('plugins.audit.host') }),
					app.createNode('span', { text: String(Number(item.attempts || 0)) + ' / ' + String(Number(item.max_attempts || 0)) }),
					app.createNode('span', { text: managerShortText(item.last_error || '', 96), title: item.last_error || '' }),
					app.createNode('div', { className: 'plugin-manager-inline-actions', children: [retryButton, discardButton] })
				];
			}));
		}
		const loadOlder = state.deadLetterHasMore
			? managerButton(app.t('plugins.deadLetters.loadOlder'), 'mini-btn', () => managerLoadDeadLetters(true), { disabled: !!state.busy })
			: null;
		managerRender(app.createNode('div', {
			className: 'plugin-manager-stack',
			children: [filter, list, loadOlder ? app.createNode('div', { className: 'plugin-manager-actions', children: [loadOlder] }) : null].filter(Boolean)
		}));
	}

	async function managerLoadDeadLetters(append) {
		const state = managerState();
		const requestID = managerNextRequest();
		let path = '/api/plugin-event-dead-letters?limit=' + deadLetterPageSize;
		if (state.deadLetterPluginID) path += '&plugin_id=' + encodeURIComponent(state.deadLetterPluginID);
		if (append && state.deadLetters.length) path += '&before_id=' + encodeURIComponent(String(state.deadLetters[state.deadLetters.length - 1].id));
		managerSetHeader(app.t('plugins.deadLetters.title'), app.t('plugins.deadLetters.meta'));
		if (!append) managerRender(managerLoading());
		try {
			const response = await managerAPIRequest('GET', path);
			if (!managerRequestCurrent(requestID, 'dead-letters')) return;
			const items = Array.isArray(response) ? response : [];
			state.deadLetters = append ? state.deadLetters.concat(items) : items;
			state.deadLetterHasMore = items.length === deadLetterPageSize;
			managerRenderDeadLetters();
		} catch (error) {
			if (managerRequestCurrent(requestID, 'dead-letters')) managerShowError(error, () => managerLoadDeadLetters(!!append));
		}
	}

	async function managerRetryDeadLetter(item, button) {
		const state = managerState();
		if (state.busy || !item) return;
		state.busy = true;
		managerRenderNav();
		managerSetButtonBusy(button, true, app.t('plugins.deadLetters.retrying'), app.t('plugins.deadLetters.retry'));
		try {
			await managerAPIRequest('POST', '/api/plugin-event-dead-letters/retry', { plugin_id: item.target_plugin || item.plugin_id, delivery_id: item.delivery_id });
			app.notify('success', app.t('plugins.deadLetters.retried'));
			await managerLoadDeadLetters(false);
		} catch (error) {
			app.notify('error', app.t('plugins.deadLetters.retryFailed', { message: managerErrorText(error) }));
		} finally {
			state.busy = false;
			managerRenderNav();
		}
	}

	async function managerDiscardDeadLetter(item) {
		if (!item) return;
		const confirmed = await app.confirmAction({
			title: app.t('plugins.deadLetters.discardTitle'),
			message: app.t('plugins.deadLetters.discardConfirm'),
			confirmText: app.t('plugins.deadLetters.discard'),
			danger: true
		});
		if (!confirmed) return;
		const state = managerState();
		state.busy = true;
		managerRenderNav();
		try {
			await managerAPIRequest('POST', '/api/plugin-event-dead-letters/discard', { plugin_id: item.target_plugin || item.plugin_id, delivery_id: item.delivery_id });
			app.notify('success', app.t('plugins.deadLetters.discarded'));
			await managerLoadDeadLetters(false);
		} catch (error) {
			app.notify('error', app.t('plugins.deadLetters.discardFailed', { message: managerErrorText(error) }));
		} finally {
			state.busy = false;
			managerRenderNav();
		}
	}

  function managerRenderSecrets() {
    const state = managerState();
    const secrets = state.secrets || {};
    managerSetHeader(app.t('plugins.secrets.title'), app.t('plugins.secrets.meta'));
    const facts = managerFacts([
      { label: app.t('plugins.secrets.available'), value: secrets.available ? app.t('common.yes') : app.t('common.no') },
      { label: app.t('plugins.secrets.persistent'), value: secrets.persistent ? app.t('common.yes') : app.t('common.no') },
      { label: app.t('plugins.secrets.activeKey'), value: secrets.active_key || app.t('common.dash'), mono: true },
      { label: app.t('plugins.secrets.keyCount'), value: String(Number(secrets.key_count || 0)) }
    ]);
    const children = [facts];
    if (!secrets.available) children.push(managerNotice(app.t('plugins.secrets.unavailable'), 'danger'));
    else if (!secrets.persistent) children.push(managerNotice(app.t('plugins.secrets.ephemeral'), 'warning'));
    else children.push(managerNotice(app.t('plugins.secrets.rotateHint')));
    const rotate = managerButton(app.t('plugins.secrets.rotate'), '', () => app.rotatePluginSecrets(rotate), {
      disabled: !secrets.available || !secrets.persistent || !!state.busy
    });
    children.push(app.createNode('div', { className: 'plugin-manager-actions', children: [rotate] }));
    managerRender(app.createNode('div', { className: 'plugin-manager-stack', children }));
  }

  async function managerLoadSecrets() {
    const requestID = managerNextRequest();
    managerSetHeader(app.t('plugins.secrets.title'), app.t('plugins.secrets.meta'));
    managerRender(managerLoading());
    try {
      const secrets = await managerAPIRequest('GET', '/api/plugin-secrets');
      if (!managerRequestCurrent(requestID, 'secrets')) return;
      managerState().secrets = secrets || {};
      managerRenderSecrets();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'secrets')) managerShowError(error, managerLoadSecrets);
    }
  }

  app.rotatePluginSecrets = async function rotatePluginSecrets(button) {
    const state = managerState();
    if (state.busy) return null;
    const confirmed = await app.confirmAction({
      title: app.t('plugins.secrets.rotateTitle'),
      message: app.t('plugins.secrets.rotateConfirm'),
      confirmText: app.t('plugins.secrets.rotate'),
      danger: false
    });
    if (!confirmed) return null;
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.secrets.rotating'), app.t('plugins.secrets.rotate'));
    try {
      const result = await managerAPIRequest('POST', '/api/plugin-secrets', {});
      state.secrets = Object.assign({}, state.secrets || {}, result || {}, { available: true, persistent: true });
      managerRenderSecrets();
      app.notify('success', app.t('plugins.secrets.rotated'));
      return result;
    } catch (error) {
      app.notify('error', app.t('plugins.secrets.rotateFailed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.secrets.rotating'), app.t('plugins.secrets.rotate'));
      if (state.open && state.view === 'secrets') managerRenderSecrets();
    }
  };

  function managerRuntimeStatus(plugin) {
    const runtime = plugin && plugin.runtime || {};
    return [plugin && plugin.status, runtime.mode].filter(Boolean).join(' / ') || app.t('common.dash');
  }

	function managerRenderProbation(probation, group) {
    if (!probation) return null;
    const pending = !!probation.pending;
    const status = pending ? app.t('plugins.probation.pending') : app.t('plugins.probation.observing');
    const notice = pending
      ? app.t('plugins.probation.pendingMeta')
      : app.t('plugins.probation.observingMeta', { expires: managerFormatDate(probation.expires_at) });
    const facts = managerFacts([
      { label: app.t('common.status'), value: status },
      { label: app.t('plugins.version'), value: probation.version || app.t('common.dash') },
      { label: app.t('plugins.probation.startedAt'), value: managerFormatDate(probation.started_at) },
      { label: app.t('plugins.probation.expiresAt'), value: managerFormatDate(probation.expires_at) },
      { label: app.t('plugins.probation.fallback'), value: probation.previous_history_id || app.t('plugins.probation.disableFallback'), mono: !!probation.previous_history_id },
	  { label: app.t('plugins.probation.group'), value: probation.group_id || '', mono: !!probation.group_id },
      { label: app.t('plugins.probation.restarts'), value: String(Number(probation.unclean_starts || 0)) },
      { label: app.t('plugins.probation.recoveryAttempts'), value: String(Number(probation.recovery_attempts || 0)) },
      { label: app.t('plugins.probation.nextRecovery'), value: managerFormatDate(probation.next_recovery_at) },
      { label: app.t('plugins.probation.lastFailure'), value: probation.last_failure || '', title: probation.last_failure || '' }
    ]);
	const children = [managerNotice(notice, pending ? 'warning' : ''), facts];
	if (group && Array.isArray(group.members) && group.members.length) {
	  children.push(managerNotice(app.t('plugins.probation.groupMeta', { count: group.members.length }), 'warning'));
	  children.push(managerList(group.members.map((member) => [member.plugin_id, member.version, member.operation].filter(Boolean).join(' / '))));
	}
	return managerSection(app.t('plugins.probation.title'), children);
  }

  function managerRenderPluginOverview() {
    const state = managerState();
    const plugin = managerPlugin(state.pluginID);
    if (!plugin) {
      managerShowError(new Error(app.t('plugins.manager.pluginMissing')));
      return;
    }
    const runtime = plugin.runtime || {};
    const health = runtime.control_health || {};
    const worker = runtime.worker_queue || {};
    const eventBus = runtime.event_bus || {};
	const operationState = runtime.operations || null;
	const operationDetail = operationState ? Object.keys(operationState.by_status || {}).sort().map((status) => {
	  return status + ': ' + String(Number(operationState.by_status[status] || 0));
	}).concat([
	  app.t('plugins.manager.resumable') + ': ' + String(Number(operationState.resumable || 0)),
	  app.formatBytes(Number(operationState.bytes || 0))
	]).join(' | ') : '';
    const leases = Array.isArray(runtime.leases) ? runtime.leases : [];
    const leaseDetail = leases.map((item) => [item.type, item.key].filter(Boolean).join(': ')).join(' | ');
    const isolation = runtime.isolation || null;
    const isolationDetail = isolation ? [
      isolation.platform,
      Array.isArray(isolation.pids) && isolation.pids.length ? 'PID ' + isolation.pids.join(', ') : '',
      isolation.resource_limit_mode,
	  isolation.sandbox_level ? app.t('plugins.manager.sandboxLevel') + ': ' + app.t('plugins.manager.sandbox.' + isolation.sandbox_level) : '',
	  isolation.sandbox_mode,
      isolation.restart_backoff_until ? app.t('plugins.manager.backoffUntil') + ': ' + isolation.restart_backoff_until : '',
      isolation.resource_limit_degraded,
	  isolation.sandbox_degraded,
      isolation.last_error
    ].filter(Boolean).join(' | ') : '';
    managerSetHeader(plugin.name || plugin.id, [plugin.id, plugin.version].filter(Boolean).join(' / '));
    const summaryFacts = managerFacts([
      { label: app.t('common.status'), value: managerRuntimeStatus(plugin) },
      { label: app.t('plugins.version'), value: plugin.version || app.t('common.dash') },
      { label: app.t('plugins.stability'), value: plugin.stability || app.t('common.dash') },
      { label: app.t('plugins.manager.health'), value: health.status || app.t('common.dash') },
      { label: app.t('plugins.error'), value: plugin.error || runtime.error || '' },
      { label: app.t('plugins.detail.reason'), value: runtime.reason || '' }
    ]);
    const technicalFacts = managerFacts([
      { label: 'ID', value: plugin.id, mono: true },
      { label: app.t('plugins.kind'), value: plugin.kind || app.t('common.dash') },
      { label: app.t('plugins.source'), value: plugin.source || app.t('common.dash'), mono: true },
      { label: app.t('plugins.runtime.attachments'), value: String(Number(runtime.attachment_count || 0)) },
      { label: app.t('plugins.manager.calls'), value: String(Number(health.calls || 0)) },
      { label: app.t('plugins.manager.failures'), value: String(Number(health.failures || 0)) },
      { label: app.t('plugins.manager.openCircuits'), value: String(Number(health.open_circuits || 0)) },
      { label: app.t('plugins.manager.logs'), value: String(Number(health.log_entries || 0)) + ' / ' + app.t('plugins.manager.dropped') + ' ' + String(Number(health.dropped_logs || 0)) },
      { label: app.t('plugins.manager.workerQueue'), value: String(Number(worker.pending_requests || 0)) + ' / ' + String(Number(worker.request_limit || 0)) },
      { label: app.t('plugins.manager.events'), value: String(Number(eventBus.delivered || 0)) + ' / ' + app.t('plugins.manager.dropped') + ' ' + String(Number(eventBus.dropped || 0)) },
	  operationState ? { label: app.t('plugins.manager.operations'), value: String(Number(operationState.total || 0)) + ' / ' + app.t('plugins.manager.resumable') + ' ' + String(Number(operationState.resumable || 0)), title: operationDetail } : null,
      { label: app.t('plugins.manager.leases'), value: String(leases.length), title: leaseDetail },
      isolation ? { label: app.t('plugins.manager.isolation'), value: isolation.enabled ? (app.t('common.yes') + (isolation.sandbox_level ? ' · ' + app.t('plugins.manager.sandbox.' + isolation.sandbox_level) : '')) : app.t('common.no'), title: isolationDetail } : null,
      isolation ? { label: app.t('plugins.manager.hostProcesses'), value: String(Number(isolation.process_count || 0)) + ' / ' + app.t('plugins.manager.restarts') + ' ' + String(Number(isolation.restart_count || 0)), title: isolationDetail } : null,
      isolation ? { label: app.t('plugins.manager.hostMemory'), value: app.formatBytes(Number(isolation.rss_bytes || 0)), title: isolationDetail } : null
    ]);
    const purge = app.createNode('input', { attrs: { type: 'checkbox' } });
    const force = app.createNode('input', { attrs: { type: 'checkbox' } });
    const uninstall = managerButton(app.t('plugins.uninstall.action'), 'plugin-manager-danger-btn', () => {
      app.uninstallPluginPackage(plugin.id, { purgeData: !!purge.checked, force: !!force.checked }, uninstall);
    }, { disabled: !!state.busy });
    const danger = app.createNode('div', {
      className: 'plugin-manager-danger-zone',
      children: [
        app.createNode('div', {
          children: [
            app.createNode('h3', { text: app.t('plugins.uninstall.title') }),
            app.createNode('p', { text: app.t('plugins.uninstall.meta') })
          ]
        }),
        app.createNode('div', {
          className: 'plugin-manager-danger-controls',
          children: [
            app.createNode('label', { className: 'plugin-manager-approval', children: [purge, app.createNode('span', { text: app.t('plugins.uninstall.purgeData') })] }),
            app.createNode('label', { className: 'plugin-manager-approval', children: [force, app.createNode('span', { text: app.t('plugins.uninstall.force') })] }),
            uninstall
          ]
        })
      ]
    });
    managerRender(app.createNode('div', {
      className: 'plugin-manager-stack',
	  children: [
        managerSection(app.t('plugins.manager.overview'), [summaryFacts]),
        managerRenderProbation(state.probation, state.probationGroup),
        managerDisclosure(app.t('plugins.manager.technicalDetails'), [technicalFacts]),
        managerDisclosure(app.t('plugins.manager.maintenance'), [danger], 'danger')
      ].filter(Boolean)
    }));
  }

  async function managerLoadPluginOverview(pluginID) {
    const state = managerState();
    const requestID = managerNextRequest();
    managerRender(managerLoading());
    try {
      const probations = await managerAPIRequest('GET', '/api/plugin-packages/probations?plugin_id=' + encodeURIComponent(pluginID));
      if (!managerRequestCurrent(requestID, 'plugin', pluginID, 'overview')) return;
      state.probation = Array.isArray(probations) && probations.length ? probations[0] : null;
	  state.probationGroup = null;
	  if (state.probation && state.probation.group_id) {
		const groups = await managerAPIRequest('GET', '/api/plugin-packages/probation-groups?group_id=' + encodeURIComponent(state.probation.group_id));
		if (!managerRequestCurrent(requestID, 'plugin', pluginID, 'overview')) return;
		state.probationGroup = Array.isArray(groups) && groups.length ? groups[0] : null;
	  }
      managerRenderPluginOverview();
      managerFocusInitial();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'plugin', pluginID, 'overview')) managerShowError(error, () => managerLoadPluginOverview(pluginID));
    }
  }

  function managerRenderPluginHistory() {
    const state = managerState();
    const plugin = managerPlugin(state.pluginID);
    managerSetHeader(plugin && (plugin.name || plugin.id) || state.pluginID, app.t('plugins.history.meta'));
    if (!state.history.length) {
      managerRender(managerEmpty(app.t('plugins.history.empty')));
      return;
    }
    const rows = state.history.map((entry) => {
      const rollback = managerButton(app.t('plugins.history.rollback'), 'mini-btn', () => app.preparePluginRollback(state.pluginID, entry.id, rollback), { disabled: !!state.busy });
      return [
        app.createNode('span', { text: entry.version || app.t('common.dash') }),
        app.createNode('span', { text: entry.reason || app.t('common.dash') }),
        app.createNode('span', { text: managerFormatDate(entry.created_at) }),
        app.createNode('code', { className: 'plugin-manager-mono', text: managerShortText(entry.archive_sha256 || entry.source_fingerprint, 24), title: entry.archive_sha256 || entry.source_fingerprint || '' }),
        rollback
      ];
    });
    managerRender(managerTable([
      app.t('plugins.version'),
      app.t('plugins.history.reason'),
      app.t('plugins.manager.createdAt'),
      app.t('plugins.history.fingerprint'),
      app.t('common.actions')
    ], rows));
  }

  async function managerLoadPluginHistory(pluginID) {
    const state = managerState();
    const requestID = managerNextRequest();
    managerRender(managerLoading());
    try {
      const history = await managerAPIRequest('GET', '/api/plugin-packages/history?plugin_id=' + encodeURIComponent(pluginID));
      if (!managerRequestCurrent(requestID, 'plugin', pluginID, 'history')) return;
      state.history = Array.isArray(history) ? history : [];
      managerRenderPluginHistory();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'plugin', pluginID, 'history')) managerShowError(error, () => managerLoadPluginHistory(pluginID));
    }
  }

  function managerRenderPluginLogs() {
    const state = managerState();
    const plugin = managerPlugin(state.pluginID);
    const response = state.logs || { logs: [], state: {} };
    const logs = Array.isArray(response.logs) ? response.logs : [];
    managerSetHeader(plugin && (plugin.name || plugin.id) || state.pluginID, app.t('plugins.logs.meta', {
      entries: Number(response.state && response.state.entries || 0),
      dropped: Number(response.state && response.state.dropped || 0)
    }));
    const select = app.createNode('select', { className: 'plugin-manager-filter' });
    [
      ['', app.t('plugins.logs.allLevels')],
      ['debug', 'DEBUG'],
      ['info', 'INFO'],
      ['warn', 'WARN'],
      ['error', 'ERROR']
    ].forEach((item) => select.appendChild(app.createNode('option', { text: item[1], attrs: { value: item[0] } })));
    select.value = state.logLevel || '';
    select.addEventListener('change', () => {
      state.logLevel = select.value || '';
      managerLoadPluginLogs(state.pluginID);
    });
    const refresh = managerButton(app.t('common.refresh'), 'mini-btn', () => managerLoadPluginLogs(state.pluginID));
    const filter = app.createNode('div', { className: 'plugin-manager-filter-row', children: [select, refresh] });
    let content = managerEmpty(app.t('plugins.logs.empty'));
    if (logs.length) {
      content = managerTable([
        app.t('plugins.manager.createdAt'),
        app.t('plugins.logs.level'),
        app.t('plugins.logs.event'),
        app.t('plugins.logs.worker'),
        app.t('plugins.logs.message'),
        app.t('plugins.logs.fields')
      ], logs.map((entry) => {
        const fields = managerAuditDetails(entry.fields || {});
        return [
          app.createNode('span', { text: managerFormatDate(entry.created_at) }),
          app.createNode('span', { className: 'plugin-manager-log-level is-' + String(entry.level || 'info'), text: String(entry.level || 'info').toUpperCase() }),
          app.createNode('code', { className: 'plugin-manager-mono', text: entry.event || app.t('common.dash') }),
          app.createNode('code', { className: 'plugin-manager-mono', text: entry.worker || app.t('common.dash') }),
          app.createNode('span', { text: entry.message || '' }),
          app.createNode('code', { className: 'plugin-manager-mono', text: managerShortText(fields, 120), title: fields })
        ];
      }));
    }
    managerRender(app.createNode('div', { className: 'plugin-manager-stack', children: [filter, content] }));
  }

  async function managerLoadPluginLogs(pluginID) {
    const state = managerState();
    const requestID = managerNextRequest();
    let path = '/api/plugins/' + encodeURIComponent(pluginID) + '/logs?limit=200';
    if (state.logLevel) path += '&level=' + encodeURIComponent(state.logLevel);
    managerRender(managerLoading());
    try {
      const logs = await managerAPIRequest('GET', path);
      if (!managerRequestCurrent(requestID, 'plugin', pluginID, 'logs')) return;
      state.logs = logs || { logs: [], state: {} };
      managerRenderPluginLogs();
    } catch (error) {
      if (managerRequestCurrent(requestID, 'plugin', pluginID, 'logs')) managerShowError(error, () => managerLoadPluginLogs(pluginID));
    }
  }

  app.preparePluginRollback = async function preparePluginRollback(pluginID, historyID, button) {
    const state = managerState();
    if (state.busy) return null;
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.history.preparing'), app.t('plugins.history.rollback'));
    try {
      const stage = await managerAPIRequest('POST', '/api/plugin-packages/rollback', {
        plugin_id: pluginID,
        history_id: historyID
      });
      state.view = 'install';
      state.pluginID = '';
      state.tab = '';
      state.stage = stage;
	  state.stages = [stage];
      state.approveUnsigned = false;
      state.approvePrivileges = false;
      managerRenderNav();
      managerRenderStageReview();
      return stage;
    } catch (error) {
      app.notify('error', app.t('plugins.history.prepareFailed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.history.preparing'), app.t('plugins.history.rollback'));
	  if (state.open && state.view === 'install' && managerActiveStages().length) managerRenderStageReview();
    }
  };

  app.uninstallPluginPackage = async function uninstallPluginPackage(pluginID, options, button) {
    const state = managerState();
    if (state.busy) return null;
    const opts = options || {};
    const details = [
      app.t('plugins.uninstall.confirm', { id: pluginID }),
      opts.purgeData ? app.t('plugins.uninstall.confirmPurge') : '',
      opts.force ? app.t('plugins.uninstall.confirmForce') : ''
    ].filter(Boolean).join(' ');
    const confirmed = await app.confirmAction({
      title: app.t('plugins.uninstall.title'),
      message: details,
      confirmText: app.t('plugins.uninstall.action'),
      danger: true
    });
    if (!confirmed) return null;
    state.busy = true;
    managerRenderNav();
    managerSetButtonBusy(button, true, app.t('plugins.uninstall.removing'), app.t('plugins.uninstall.action'));
    try {
      const result = await managerAPIRequest('POST', '/api/plugin-packages/uninstall', {
        plugin_id: pluginID,
        force: !!opts.force,
        purge_data: !!opts.purgeData
      });
      if (typeof app.loadPlugins === 'function') await app.loadPlugins();
      app.notify('success', app.t('plugins.uninstall.removed', { id: pluginID }));
      app.closePluginManager(true);
      return result;
    } catch (error) {
      app.notify('error', app.t('plugins.uninstall.failed', { message: managerErrorText(error) }));
      return null;
    } finally {
      state.busy = false;
      managerRenderNav();
      managerSetButtonBusy(button, false, app.t('plugins.uninstall.removing'), app.t('plugins.uninstall.action'));
    }
  };

  app.openPluginManager = function openPluginManager(view, options) {
    const state = managerState();
    const opts = options || {};
    managerNextRequest();
    managerOpenShell();
    state.view = String(view || 'install');
    state.pluginID = state.view === 'plugin' ? String(opts.pluginID || state.pluginID || '').trim() : '';
    state.tab = state.view === 'plugin' ? String(opts.tab || 'overview') : '';
    state.busy = false;
    if (state.view !== 'install') {
      state.stage = null;
	  state.stages = [];
	  state.repositoryPlan = null;
	  state.installReturnView = '';
      state.approveUnsigned = false;
      state.approvePrivileges = false;
    }
    managerRenderNav();
	if (state.view === 'repositories') {
	  managerLoadRepositories();
	  return;
	}
    if (state.view === 'advanced') {
      managerRenderAdvanced();
      return;
    }
    if (state.view === 'install') {
	  if (managerActiveStages().length) managerRenderStageReview();
      else managerRenderPackageInput();
      return;
    }
    if (state.view === 'trust') {
      managerLoadTrust();
      return;
    }
    if (state.view === 'audit') {
      state.auditLogs = [];
      state.auditHasMore = false;
      managerLoadAudit(false);
      return;
    }
	if (state.view === 'dead-letters') {
		state.deadLetters = [];
		state.deadLetterHasMore = false;
		managerLoadDeadLetters(false);
		return;
	}
    if (state.view === 'secrets') {
      managerLoadSecrets();
      return;
    }
	if (state.view === 'access') {
	  managerLoadAccess();
	  return;
	}
    if (state.view === 'plugin') {
      if (!state.pluginID) {
        managerShowError(new Error(app.t('plugins.manager.pluginMissing')));
        return;
      }
      if (state.tab === 'history') {
        managerLoadPluginHistory(state.pluginID);
        return;
      }
      if (state.tab === 'logs') {
        managerLoadPluginLogs(state.pluginID);
        return;
      }
      managerLoadPluginOverview(state.pluginID);
      return;
    }
    state.view = 'install';
    managerRenderNav();
    managerRenderPackageInput();
  };

  app.closePluginManager = function closePluginManager(force) {
    const state = managerState();
    if (state.busy && !force) return false;
    state.open = false;
    state.requestID += 1;
    if (app.el.pluginManagerModal) {
      app.el.pluginManagerModal.classList.remove('active');
      app.el.pluginManagerModal.setAttribute('aria-hidden', 'true');
    }
    if (managerFocusReturn && typeof managerFocusReturn.focus === 'function') managerFocusReturn.focus();
    managerFocusReturn = null;
    return true;
  };

  function managerFocusableElements() {
    const modal = app.el.pluginManagerModal;
    if (!modal || !modal.querySelectorAll) return [];
    return Array.from(modal.querySelectorAll('button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'))
      .filter((node) => !node.hidden);
  }

  function managerHandleKeydown(event) {
    const state = managerState();
    if (!state.open) return;
    if (app.el.confirmModal && app.el.confirmModal.classList.contains('active')) return;
    if (event.key === 'Escape') {
      event.preventDefault();
      app.closePluginManager();
      return;
    }
    if (event.key !== 'Tab') return;
    const focusable = managerFocusableElements();
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  if (app.el.addPluginBtn) app.el.addPluginBtn.addEventListener('click', () => app.openPluginManager('install'));
  if (app.el.managePluginsAdvancedBtn) app.el.managePluginsAdvancedBtn.addEventListener('click', () => app.openPluginManager('advanced'));
  if (app.el.closePluginManagerBtn) app.el.closePluginManagerBtn.addEventListener('click', () => app.closePluginManager());
  if (app.el.pluginManagerModal) {
    app.el.pluginManagerModal.addEventListener('click', (event) => {
      if (event.target === app.el.pluginManagerModal) app.closePluginManager();
    });
  }
  document.addEventListener('keydown', managerHandleKeydown);

  app.showTokenModal = (function wrapPluginManagerTokenModal(original) {
    return function showTokenModalWithoutPluginOverlay() {
      if (managerState().open) app.closePluginManager(true);
      if (typeof original === 'function') return original.apply(app, arguments);
    };
  })(app.showTokenModal);

  app.refreshLocalizedUI = (function wrapPluginManagerLocalizedUI(original) {
    return function refreshLocalizedUIWithPluginManager() {
      if (typeof original === 'function') original();
      const state = managerState();
      if (!state.open) return;
      managerRenderNav();
	  if (state.view === 'repositories') managerRenderRepositories();
	  else if (state.view === 'advanced') managerRenderAdvanced();
	  else if (state.view === 'install') managerActiveStages().length ? managerRenderStageReview() : managerRenderPackageInput();
      else if (state.view === 'trust') managerRenderTrust();
      else if (state.view === 'audit') managerRenderAudit();
	  else if (state.view === 'dead-letters') managerRenderDeadLetters();
      else if (state.view === 'secrets') managerRenderSecrets();
	  else if (state.view === 'access') managerRenderAccess();
      else if (state.view === 'plugin' && state.tab === 'history') managerRenderPluginHistory();
      else if (state.view === 'plugin' && state.tab === 'logs') managerRenderPluginLogs();
      else if (state.view === 'plugin') managerRenderPluginOverview();
    };
  })(app.refreshLocalizedUI);

  if (app.__enablePluginTests) {
    app.__pluginManagerReadSignatureForTest = managerReadSignatureSidecar;
    app.__pluginManagerStageApprovedForTest = managerStageApproved;
	app.__pluginManagerStagesApprovedForTest = managerStagesApproved;
	app.__pluginManagerMatchSignaturesForTest = managerMatchSignatureFiles;
    app.__pluginManagerRenderStageForTest = managerRenderStageReview;
    app.__pluginManagerLoadAuditForTest = managerLoadAudit;
	app.__pluginManagerLoadDeadLettersForTest = managerLoadDeadLetters;
    app.__pluginManagerLoadTrustForTest = managerLoadTrust;
    app.__pluginManagerLoadSecretsForTest = managerLoadSecrets;
	app.__pluginManagerLoadRepositoriesForTest = managerLoadRepositories;
    app.__pluginManagerLoadHistoryForTest = managerLoadPluginHistory;
    app.__pluginManagerLoadLogsForTest = managerLoadPluginLogs;
    app.__pluginManagerLoadOverviewForTest = managerLoadPluginOverview;
	app.__pluginManagerLoadAccessForTest = managerLoadAccess;
  }
})();
