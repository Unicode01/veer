(function () {
  const app = window.ForwardApp;
  if (!app) return;

  function listText(values) {
    if (!Array.isArray(values) || values.length === 0) return '';
    return values.filter(Boolean).join(', ');
  }

  function pluginStatusInfo(plugin) {
    const status = String(plugin && plugin.status || '').toLowerCase();
    if (status === 'builtin') return { badge: 'kernel', text: app.t('plugins.status.builtin') };
    if (status === 'active') return { badge: 'running', text: app.t('plugins.status.active') };
    if (status === 'error') return { badge: 'error', text: app.t('plugins.status.error') };
    return { badge: 'disabled', text: status || app.t('common.dash') };
  }

  function pluginRuntimeModeText(mode) {
    const value = String(mode || '').toLowerCase();
    if (value === 'builtin') return app.t('plugins.runtime.builtin');
    if (value === 'dataplane') return app.t('plugins.runtime.dataplane');
    if (value === 'control') return app.t('plugins.runtime.control');
    if (value === 'error') return app.t('plugins.runtime.error');
    if (value === 'manifest_only') return app.t('plugins.runtime.manifestOnly');
    if (value === 'invalid') return app.t('plugins.runtime.invalid');
    return value || app.t('common.dash');
  }

  function pluginRuntimeSummary(plugin) {
    const runtime = plugin && plugin.runtime ? plugin.runtime : null;
    if (!runtime) return '';
    const parts = [
      pluginRuntimeModeText(runtime.mode),
      app.t('plugins.runtime.attachable') + ': ' + (runtime.attachable ? app.t('common.yes') : app.t('common.no')),
      app.t('plugins.runtime.attached') + ': ' + (runtime.attached ? app.t('common.yes') : app.t('common.no'))
    ];
    if (typeof runtime.attachment_count === 'number') parts.push(app.t('plugins.runtime.attachments') + ': ' + runtime.attachment_count);
    if (runtime.error) parts.push(app.t('plugins.error') + ': ' + runtime.error);
    if (runtime.reason) parts.push(runtime.reason);
    return parts.filter(Boolean).join(' | ');
  }

  let pluginDetailPopover = null;
  let pluginDetailPopoverTrigger = null;
  let pluginDetailPopoverPinned = false;

  function textOrDash(value) {
    const text = String(value == null ? '' : value).trim();
    return text || app.t('common.dash');
  }

  function detailRow(label, value) {
    const text = String(value == null ? '' : value).trim();
    if (!text) return null;
    return { label, value: text };
  }

  function pluginObjectDetail(object) {
    const programs = Array.isArray(object && object.programs) ? object.programs : [];
    const parts = [
      object && object.path,
      object && object.status ? 'status=' + object.status : '',
      object && typeof object.program_count === 'number' ? 'programs=' + object.program_count : (programs.length ? 'programs=' + programs.length : ''),
      object && typeof object.map_count === 'number' ? 'maps=' + object.map_count : '',
      object && object.error ? app.t('plugins.error') + ': ' + object.error : '',
      object && object.description
    ].filter(Boolean);
    const programText = programs.map((program) => [
      program.id,
      program.section,
      program.type
    ].filter(Boolean).join(' / ')).filter(Boolean).join(', ');
    if (programText) parts.push(programText);
    return parts.join(' | ');
  }

  function pluginHookDetail(hook) {
    return [
      hook && hook.engine ? String(hook.engine).toUpperCase() : '',
      hook && hook.attach,
      hook && hook.stage,
      hook && typeof hook.priority === 'number' ? 'priority=' + hook.priority : '',
      hook && hook.program,
      hook && hook.mode,
      hook && Array.isArray(hook.context) && hook.context.length ? 'ctx=' + hook.context.join(',') : '',
      hook && Array.isArray(hook.interfaces) && hook.interfaces.length ? 'if=' + hook.interfaces.join(',') : ''
    ].filter(Boolean).join(' | ');
  }

  function pluginAttachmentDetail(attachment) {
    return [
      attachment && attachment.engine ? String(attachment.engine).toUpperCase() : '',
      attachment && attachment.attach,
      attachment && attachment.stage,
      attachment && attachment.interface,
      attachment && attachment.status,
      attachment && attachment.program,
      attachmentPriorityParts(attachment).join(' | '),
      attachment && Array.isArray(attachment.context) && attachment.context.length ? 'ctx=' + attachment.context.join(',') : '',
      attachment && attachment.filter_handle,
      attachment && attachment.error ? app.t('plugins.error') + ': ' + attachment.error : ''
    ].filter(Boolean).join(' | ');
  }

  function pluginDetailsSections(plugin) {
    const item = plugin || {};
    const runtime = item.runtime && typeof item.runtime === 'object' ? item.runtime : null;
    const info = pluginStatusInfo(item);
    const capabilities = Array.isArray(item.capabilities) ? item.capabilities.filter(Boolean) : [];
    const vifs = Array.isArray(item.virtual_interfaces) ? item.virtual_interfaces : [];
    const objects = Array.isArray(item.objects) ? item.objects : [];
    const hooks = Array.isArray(item.hooks) ? item.hooks : [];
    const attachments = runtime && Array.isArray(runtime.attachments) ? runtime.attachments : [];
    const sections = [];

    sections.push({
      title: app.t('plugins.detail.runtime'),
      rows: [
        detailRow('ID', item.id),
        detailRow(app.t('common.status'), info.text),
        detailRow(app.t('plugins.detail.mode'), runtime ? pluginRuntimeModeText(runtime.mode) : ''),
        detailRow(app.t('plugins.runtime.attachable'), runtime ? (runtime.attachable ? app.t('common.yes') : app.t('common.no')) : ''),
        detailRow(app.t('plugins.runtime.attached'), runtime ? (runtime.attached ? app.t('common.yes') : app.t('common.no')) : ''),
        detailRow(app.t('plugins.runtime.attachments'), runtime && typeof runtime.attachment_count === 'number' ? String(runtime.attachment_count) : ''),
        detailRow(app.t('plugins.kind'), item.kind),
        detailRow(app.t('plugins.version'), item.version),
        detailRow(app.t('plugins.source'), item.source),
        detailRow(app.t('plugins.error'), item.error || (runtime && runtime.error)),
        detailRow(app.t('plugins.detail.reason'), runtime && runtime.reason),
        detailRow(app.t('plugins.detail.description'), item.description)
      ].filter(Boolean)
    });

    const capabilityRows = [];
    if (capabilities.length) capabilityRows.push(detailRow(app.t('plugins.capabilities'), capabilities.join(', ')));
    vifs.forEach((vif) => {
      capabilityRows.push(detailRow(vif.id || app.t('plugins.virtualInterfaces'), [
        vif.type ? 'type=' + vif.type : '',
        vif.description || ''
      ].filter(Boolean).join(' | ')));
    });
    if (capabilityRows.length) {
      sections.push({
        title: app.t('plugins.detail.capabilitySurface'),
        rows: capabilityRows.filter(Boolean)
      });
    }

    if (objects.length) {
      sections.push({
        title: app.t('plugins.objects'),
        rows: objects.map((object) => detailRow(object.id || app.t('plugins.objects'), pluginObjectDetail(object))).filter(Boolean)
      });
    }

    if (hooks.length) {
      sections.push({
        title: app.t('plugins.hooks'),
        rows: hooks.map((hook) => detailRow(hook.id || app.t('plugins.hooks'), pluginHookDetail(hook))).filter(Boolean)
      });
    }

    if (attachments.length) {
      sections.push({
        title: app.t('plugins.runtime.attachments'),
        rows: attachments.map((attachment) => detailRow(attachment.hook_id || app.t('plugins.runtime.attachments'), pluginAttachmentDetail(attachment))).filter(Boolean)
      });
    }

    return sections.filter((section) => section.rows && section.rows.length);
  }

  function pluginDetailsPlainText(plugin) {
    return pluginDetailsSections(plugin).map((section) => {
      const rows = section.rows.map((row) => row.label + ': ' + row.value);
      return [section.title].concat(rows).join('\n');
    }).join('\n\n');
  }

  function pluginDetailRowNode(row) {
    return app.createNode('div', {
      className: 'kernel-runtime-tooltip-breakdown-row plugin-detail-row',
      children: [
        app.createNode('span', {
          className: 'kernel-runtime-tooltip-breakdown-label',
          text: row.label
        }),
        app.createNode('span', {
          className: 'kernel-runtime-tooltip-breakdown-value plugin-detail-value',
          text: row.value
        })
      ]
    });
  }

  function pluginDetailSectionNode(section, index) {
    return app.createNode('details', {
      className: 'plugin-detail-section',
      attrs: index === 0 ? { open: true } : null,
      children: [
        app.createNode('summary', {
          className: 'plugin-detail-section-title',
          children: [
            app.createNode('span', { text: section.title }),
            app.createNode('span', {
              className: 'plugin-detail-section-count',
              text: String(section.rows.length)
            })
          ]
        }),
        app.createNode('div', {
          className: 'kernel-runtime-tooltip-breakdown plugin-detail-breakdown',
          children: section.rows.map(pluginDetailRowNode)
        })
      ]
    });
  }

  function pluginDetailContent(plugin) {
    const item = plugin || {};
    const info = pluginStatusInfo(item);
    const closeButton = app.createNode('button', {
      className: 'plugin-detail-close',
      text: app.t('plugins.detail.close'),
      attrs: { type: 'button' }
    });
    if (closeButton && typeof closeButton.addEventListener === 'function') {
      closeButton.addEventListener('click', hidePluginPopover);
    }

    const meta = [
      item.id,
      item.kind,
      item.version
    ].filter(Boolean).join(' / ');
    const sections = pluginDetailsSections(item);
    return [
      app.createNode('div', {
        className: 'kernel-runtime-tooltip-header plugin-detail-header',
        children: [
          app.createNode('div', {
            children: [
              app.createNode('span', {
                className: 'kernel-runtime-tooltip-title',
                text: item.name || item.id || app.t('plugins.details')
              }),
              app.createNode('span', {
                className: 'kernel-runtime-tooltip-meta',
                text: meta || app.t('common.dash')
              })
            ]
          }),
          app.createNode('div', {
            className: 'plugin-detail-header-actions',
            children: [
              app.createStatusBadgeNode(info, ''),
              closeButton
            ]
          })
        ]
      }),
      sections.length
        ? app.createNode('div', {
            className: 'plugin-detail-sections',
            children: sections.map(pluginDetailSectionNode)
          })
        : app.createNode('div', {
            className: 'kernel-runtime-tooltip-meta',
            text: app.t('plugins.detail.empty')
          })
    ];
  }

  function ensurePluginPopover() {
    if (pluginDetailPopover) return pluginDetailPopover;
    pluginDetailPopover = app.createNode('div', {
      className: 'kernel-runtime-floating-tooltip plugin-detail-popover',
      attrs: {
        id: 'pluginRuntimeTooltip',
        role: 'dialog',
        hidden: true
      }
    });
    document.body.appendChild(pluginDetailPopover);
    return pluginDetailPopover;
  }

  function positionPluginPopover() {
    if (!pluginDetailPopover || !pluginDetailPopoverTrigger || pluginDetailPopover.hidden) return;
    if (!pluginDetailPopoverTrigger.isConnected && typeof pluginDetailPopoverTrigger.isConnected === 'boolean') {
      hidePluginPopover();
      return;
    }

    const margin = 12;
    const offset = 8;
    const viewportWidth = document.documentElement.clientWidth || window.innerWidth || 0;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
    const triggerRect = pluginDetailPopoverTrigger.getBoundingClientRect();
    const spaceBelow = Math.max(0, viewportHeight - triggerRect.bottom - offset - margin);
    const spaceAbove = Math.max(0, triggerRect.top - offset - margin);
    const preferBelow = spaceBelow >= 220 || spaceBelow >= spaceAbove;
    const maxHeight = Math.max(180, Math.min(360, viewportHeight - margin * 2, preferBelow ? spaceBelow : spaceAbove));

    pluginDetailPopover.style.maxHeight = Math.round(maxHeight) + 'px';
    pluginDetailPopover.style.left = '0px';
    pluginDetailPopover.style.top = '0px';

    const tipRect = pluginDetailPopover.getBoundingClientRect();
    let left = triggerRect.left;
    if (left + tipRect.width > viewportWidth - margin) left = viewportWidth - tipRect.width - margin;
    left = Math.max(margin, left);

    let top = preferBelow ? triggerRect.bottom + offset : triggerRect.top - tipRect.height - offset;
    if (top < margin) top = margin;
    if (top + tipRect.height > viewportHeight - margin) top = Math.max(margin, viewportHeight - tipRect.height - margin);

    pluginDetailPopover.style.left = Math.round(left) + 'px';
    pluginDetailPopover.style.top = Math.round(top) + 'px';
  }

  function hidePluginPopover() {
    if (pluginDetailPopoverTrigger) {
      pluginDetailPopoverTrigger.setAttribute('aria-expanded', 'false');
    }
    pluginDetailPopoverTrigger = null;
    pluginDetailPopoverPinned = false;

    if (!pluginDetailPopover) return;
    pluginDetailPopover.classList.remove('is-visible');
    pluginDetailPopover.hidden = true;
    app.clearNode(pluginDetailPopover);
  }

  function showPluginPopover(trigger, pinned) {
    if (!trigger) return;
    const pluginID = trigger.dataset ? String(trigger.dataset.pluginId || '') : '';
    const plugin = (app.state.plugins.data || []).find((item) => item && item.id === pluginID);
    if (!plugin) return;
    const popover = ensurePluginPopover();
    if (pluginDetailPopoverTrigger && pluginDetailPopoverTrigger !== trigger) {
      pluginDetailPopoverTrigger.setAttribute('aria-expanded', 'false');
    }

    pluginDetailPopoverTrigger = trigger;
    pluginDetailPopoverPinned = !!pinned;
    app.clearNode(popover);
    app.appendNodeContent(popover, pluginDetailContent(plugin));
    popover.hidden = false;
    popover.classList.add('is-visible');
    trigger.setAttribute('aria-expanded', 'true');
    positionPluginPopover();
  }

  function togglePluginPopover(trigger) {
    if (pluginDetailPopoverTrigger === trigger && pluginDetailPopoverPinned) {
      hidePluginPopover();
      return;
    }
    showPluginPopover(trigger, true);
  }

  function attachmentChainSlot(attachment) {
    if (!attachment || typeof attachment.chain_slot !== 'number' || !Number.isFinite(attachment.chain_slot)) return 0;
    return attachment.chain_slot;
  }

  function pluginPipelineCorePriority() {
    const catalog = app.state.plugins.catalog || {};
    const runtime = catalog.runtime || {};
    if (typeof runtime.core_priority === 'number' && Number.isFinite(runtime.core_priority)) return runtime.core_priority;
    const plugins = Array.isArray(app.state.plugins.data) ? app.state.plugins.data : [];
    const fvtap = plugins.find((plugin) => plugin && plugin.id === 'fvtap');
    const hooks = fvtap && Array.isArray(fvtap.hooks) ? fvtap.hooks : [];
    const coreHook = hooks.find((hook) => hook && hook.engine === 'tc' && hook.attach === 'ingress' && hook.stage === 'forward');
    if (coreHook && typeof coreHook.priority === 'number' && Number.isFinite(coreHook.priority)) return coreHook.priority;
    return 1000;
  }

  function attachmentPriorityParts(attachment) {
    const parts = [];
    if (typeof attachment.priority === 'number') {
      parts.push((attachment.filter_handle ? 'tc_prio=' : 'priority=') + attachment.priority);
    }
    const slot = attachmentChainSlot(attachment);
    if (slot > 0) parts.push('chain_slot=' + slot);
    return parts;
  }

  function pluginSortValue(plugin, key) {
    if (key === 'status') return plugin.status || '';
    if (key === 'kind') return plugin.kind || '';
    if (key === 'version') return plugin.version || '';
    if (key === 'name') return plugin.name || '';
    return plugin.id || '';
  }

  function pluginSearchValues(plugin) {
    const hooks = Array.isArray(plugin.hooks) ? plugin.hooks : [];
    const attachments = plugin && plugin.runtime && Array.isArray(plugin.runtime.attachments) ? plugin.runtime.attachments : [];
    const virtualInterfaces = Array.isArray(plugin.virtual_interfaces) ? plugin.virtual_interfaces : [];
    const objects = Array.isArray(plugin.objects) ? plugin.objects : [];
    return [
      plugin.id,
      plugin.name,
      plugin.version,
      plugin.kind,
      plugin.status,
      plugin.source,
      plugin.error,
      plugin.description,
      plugin.asset_base_path,
      pluginRuntimeSummary(plugin),
      listText(plugin.capabilities),
      objects.map((object) => [
        object.id,
        object.path,
        object.status,
        object.error,
        object.sha256,
        object.resolved_sha256,
        object.description,
        Array.isArray(object.programs) ? object.programs.map((program) => [program.id, program.section, program.type].filter(Boolean).join(' ')).join(' ') : ''
      ].filter(Boolean).join(' ')).join(' '),
      hooks.map((hook) => [hook.id, hook.engine, hook.attach, hook.stage, hook.program, hook.mode, Array.isArray(hook.context) ? hook.context.join(' ') : ''].filter(Boolean).join(' ')).join(' '),
      attachments.map((attachment) => [attachment.hook_id, attachment.engine, attachment.attach, attachment.stage, attachment.interface, attachment.program, attachment.status, Array.isArray(attachment.context) ? attachment.context.join(' ') : '', String(attachment.chain_slot || ''), String(attachment.priority || '')].filter(Boolean).join(' ')).join(' '),
      virtualInterfaces.map((vif) => [vif.id, vif.type, vif.description].filter(Boolean).join(' ')).join(' ')
    ];
  }

  function pluginMetadata(plugin, keys) {
    const metadata = plugin && plugin.metadata && typeof plugin.metadata === 'object' ? plugin.metadata : {};
    for (let i = 0; i < keys.length; i++) {
      const value = String(metadata[keys[i]] || '').trim();
      if (value) return value;
    }
    return '';
  }

  function normalizePluginPageID(value) {
    const page = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
    return page && page !== 'plugins' && page !== 'diagnostics' ? page : '';
  }

  function pluginPageInfo(plugin) {
    if (!plugin || !plugin.asset_base_path || !(plugin.ui && plugin.ui.entry)) return null;
    const rawPage = pluginMetadata(plugin, [
      'ui.page',
      'ui_page',
      'forward.page',
      'forward_page',
      'forward.ui.page',
      'forward_ui_page',
      'page',
      'tab'
    ]);
    const page = normalizePluginPageID(rawPage);
    if (!page) return null;
    const title = pluginMetadata(plugin, [
      'ui.page_title',
      'ui_page_title',
      'forward.page_title',
      'forward_page_title',
      'forward.ui.title',
      'forward_ui_title',
      'page_title',
      'tab_title',
      'title'
    ]) || plugin.name || page;
    return {
      tabID: 'plugin-' + page,
      page,
      title,
      pluginID: plugin.id || '',
      entry: plugin.ui.entry,
      plugin
    };
  }

  function pluginPages() {
    const data = Array.isArray(app.state.plugins.data) ? app.state.plugins.data : [];
    const pages = [];
    const seen = new Set();
    data.forEach((plugin) => {
      const page = pluginPageInfo(plugin);
      if (!page || seen.has(page.tabID)) return;
      seen.add(page.tabID);
      pages.push(page);
    });
    pages.sort((a, b) => a.page < b.page ? -1 : a.page > b.page ? 1 : 0);
    return pages;
  }

  function bindPluginTabButton(button) {
    if (!button || button.dataset.boundPluginTab === '1') return;
    button.dataset.boundPluginTab = '1';
    button.addEventListener('click', () => app.activateTab(button.dataset.tab));
    button.addEventListener('keydown', (e) => {
      const tabs = Array.from(document.querySelectorAll('.tab')).filter((item) => item && !item.hidden);
      const index = tabs.indexOf(button);
      if (index < 0) return;
      let nextIndex = index;
      if (e.key === 'ArrowRight') nextIndex = (index + 1) % tabs.length;
      else if (e.key === 'ArrowLeft') nextIndex = (index - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') nextIndex = 0;
      else if (e.key === 'End') nextIndex = tabs.length - 1;
      else return;
      e.preventDefault();
      app.activateTab(tabs[nextIndex].dataset.tab, { focus: true });
    });
  }

  function pluginUINode(plugin) {
    if (!plugin.asset_base_path && (!plugin.ui || !plugin.ui.entry)) return app.emptyCellNode('stat-muted');
    const text = plugin.ui && plugin.ui.entry ? plugin.ui.entry : app.t('plugins.ui.assets');
    if (!plugin.asset_base_path || !(plugin.ui && plugin.ui.entry)) {
      return app.createNode('span', {
        className: 'worker-route',
        text: text,
        title: plugin.asset_base_path || ''
      });
    }
    return app.createNode('button', {
      className: 'mini-btn btn-open-plugin-ui',
      text: app.t('plugins.open'),
      title: plugin.asset_base_path + plugin.ui.entry,
      dataset: { pluginId: plugin.id || '' }
    });
  }

  function pluginHostComponentCSS() {
    return `
:root {
  color-scheme: light dark;
  --fwd-bg: #f7f4ed;
  --fwd-surface: #fffdf8;
  --fwd-surface-soft: #f1eee7;
  --fwd-text: #24211d;
  --fwd-muted: #6d655a;
  --fwd-border: #ded7ca;
  --fwd-primary: #1f6f5b;
  --fwd-primary-soft: #e4f2ed;
  --fwd-radius: 14px;
  --fwd-shadow: 0 18px 44px rgba(42, 33, 22, 0.11);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
body.fwd-plugin-body,
body {
  margin: 0;
  background: radial-gradient(circle at top left, rgba(31, 111, 91, 0.12), transparent 34%), var(--fwd-bg);
  color: var(--fwd-text);
}
.fwd-page { padding: 18px; }
.fwd-stack { display: grid; gap: 14px; }
.fwd-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
.fwd-card {
  padding: 16px;
  border: 1px solid var(--fwd-border);
  border-radius: var(--fwd-radius);
  background: var(--fwd-surface);
  box-shadow: var(--fwd-shadow);
}
.fwd-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.fwd-title { margin: 0; font-size: 20px; line-height: 1.25; }
.fwd-desc { margin: 6px 0 0; color: var(--fwd-muted); line-height: 1.6; }
.fwd-muted { color: var(--fwd-muted); }
.fwd-stat {
  display: grid; gap: 5px; min-width: 0; padding: 13px;
  border: 1px solid var(--fwd-border); border-radius: 12px; background: var(--fwd-surface-soft);
}
.fwd-stat-label { color: var(--fwd-muted); font-size: 12px; font-weight: 650; }
.fwd-stat-value {
  color: var(--fwd-text); font-size: 18px; font-weight: 760; line-height: 1.2;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.fwd-button {
  display: inline-flex; align-items: center; justify-content: center;
  min-height: 34px; padding: 0 13px; border: 1px solid var(--fwd-border);
  border-radius: 999px; background: var(--fwd-primary); color: #fff;
  font-weight: 650; cursor: pointer;
  transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease, border-color 0.16s ease;
}
.fwd-button.secondary { background: var(--fwd-primary-soft); color: var(--fwd-primary); }
.fwd-button:hover, .fwd-button:focus {
  transform: translateY(-1px);
  box-shadow: 0 8px 18px rgba(31, 111, 91, 0.2);
}
.fwd-button:active { transform: translateY(0); box-shadow: none; }
.fwd-button:disabled { opacity: 0.58; cursor: not-allowed; transform: none; box-shadow: none; }
.fwd-badge {
  display: inline-flex; align-items: center; min-height: 24px; padding: 0 9px;
  border-radius: 999px; border: 1px solid var(--fwd-border);
  background: var(--fwd-surface-soft); color: var(--fwd-muted); font-size: 12px; font-weight: 650;
}
.fwd-status {
  min-height: 22px;
  color: var(--fwd-muted);
  font-size: 12px;
  font-weight: 650;
}
.fwd-toast-stack {
  position: fixed; right: 14px; bottom: 14px; z-index: 20;
  display: grid; gap: 8px; max-width: min(320px, calc(100vw - 28px));
}
.fwd-toast {
  padding: 9px 11px; border: 1px solid var(--fwd-border); border-radius: 12px;
  background: var(--fwd-surface); color: var(--fwd-text); box-shadow: var(--fwd-shadow);
  font-size: 12px; line-height: 1.45; opacity: 0; transform: translateY(6px);
  transition: opacity 0.16s ease, transform 0.16s ease;
}
.fwd-toast.is-visible { opacity: 1; transform: translateY(0); }
.fwd-table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 10px; }
.fwd-table th, .fwd-table td { padding: 10px 12px; border-bottom: 1px solid var(--fwd-border); text-align: left; font-size: 13px; }
.fwd-table th { color: var(--fwd-muted); background: var(--fwd-surface-soft); }
.fwd-table td { overflow-wrap: anywhere; }
.fwd-field { display: grid; gap: 6px; }
.fwd-field label { color: var(--fwd-muted); font-size: 12px; font-weight: 650; }
.fwd-input {
  min-height: 38px; padding: 0 12px; border: 1px solid var(--fwd-border);
  border-radius: 10px; background: var(--fwd-surface); color: var(--fwd-text);
}
@media (max-width: 720px) {
  .fwd-page { padding: 12px; }
  .fwd-grid { grid-template-columns: 1fr; }
  .fwd-toolbar { align-items: flex-start; }
}
@media (prefers-color-scheme: dark) {
  :root {
    --fwd-bg: #12161a;
    --fwd-surface: #1b2026;
    --fwd-surface-soft: #242a31;
    --fwd-text: #f2efe8;
    --fwd-muted: #a8a096;
    --fwd-border: #323943;
    --fwd-primary: #5bc0a4;
    --fwd-primary-soft: #18352e;
    --fwd-shadow: 0 18px 44px rgba(0, 0, 0, 0.26);
  }
}`;
  }

  function pluginHostComponentJS(plugin) {
    const host = {
      version: 'v1',
      pluginId: plugin && plugin.id || '',
      pluginName: plugin && plugin.name || '',
      resources: Array.isArray(plugin && plugin.resources) ? plugin.resources.map(function (resource) {
        return {
          id: resource && resource.id || '',
          description: resource && resource.description || '',
          methods: Array.isArray(resource && resource.methods) ? resource.methods.slice() : [],
          runtime_update: resource && resource.runtime_update || '',
          max_records: resource && resource.max_records || 0,
          max_record_bytes: resource && resource.max_record_bytes || 0
        };
      }) : [],
      actions: Array.isArray(plugin && plugin.actions) ? plugin.actions.map(function (action) {
        return {
          id: action && action.id || '',
          description: action && action.description || '',
          runtime_update: action && action.runtime_update || '',
          max_payload_bytes: action && action.max_payload_bytes || 0
        };
      }) : [],
      classes: {
        page: 'fwd-page',
        stack: 'fwd-stack',
        grid: 'fwd-grid',
        card: 'fwd-card',
        toolbar: 'fwd-toolbar',
        title: 'fwd-title',
        description: 'fwd-desc',
        muted: 'fwd-muted',
        stat: 'fwd-stat',
        statLabel: 'fwd-stat-label',
      statValue: 'fwd-stat-value',
        status: 'fwd-status',
        toastStack: 'fwd-toast-stack',
        toast: 'fwd-toast',
        button: 'fwd-button',
        secondaryButton: 'fwd-button secondary',
        badge: 'fwd-badge',
        table: 'fwd-table',
        field: 'fwd-field',
        input: 'fwd-input'
      }
    };
    return `
(function () {
  var host = ${JSON.stringify(host).replace(/</g, '\\u003c')};
  var resizeTimer = 0;
  function append(parent, children) {
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child == null || child === false) return;
      parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    });
  }
  function tableCell(tag, text) {
    return host.h(tag, { text: text == null || text === '' ? '-' : String(text) });
  }
  function measureHeight() {
    var body = document.body;
    var root = document.documentElement;
    return Math.max(
      body ? body.scrollHeight : 0,
      body ? body.offsetHeight : 0,
      root ? root.scrollHeight : 0,
      root ? root.offsetHeight : 0,
      160
    );
  }
  function postHeight() {
    if (!window.parent || window.parent === window) return;
    window.parent.postMessage({
      type: 'forward-plugin-ui-height',
      pluginId: host.pluginId,
      height: measureHeight()
    }, '*');
  }
  function scheduleHeight() {
    if (resizeTimer) window.cancelAnimationFrame(resizeTimer);
    resizeTimer = window.requestAnimationFrame(function () {
      resizeTimer = 0;
      postHeight();
    });
  }
  var rpcSeq = 0;
  var pendingRPC = {};
  function rpc(op, payload) {
    if (!window.parent || window.parent === window) {
      return Promise.reject(new Error('plugin host bridge is unavailable'));
    }
    var id = host.pluginId + ':' + (++rpcSeq);
    return new Promise(function (resolve, reject) {
      pendingRPC[id] = { resolve: resolve, reject: reject };
      window.parent.postMessage({
        type: 'forward-plugin-rpc',
        pluginId: host.pluginId,
        id: id,
        op: op,
        payload: payload || {}
      }, '*');
      window.setTimeout(function () {
        if (!pendingRPC[id]) return;
        delete pendingRPC[id];
        reject(new Error('plugin host request timed out'));
      }, 30000);
    });
  }
  window.addEventListener('message', function (event) {
    var data = event && event.data && typeof event.data === 'object' ? event.data : null;
    if (!data || data.type !== 'forward-plugin-rpc-result' || data.pluginId !== host.pluginId || !data.id) return;
    var pending = pendingRPC[data.id];
    if (!pending) return;
    delete pendingRPC[data.id];
    if (data.ok) pending.resolve(data.result);
    else pending.reject(new Error(data.error || 'plugin host request failed'));
  });
  host.h = function (tag, opts, children) {
    var el = document.createElement(tag);
    opts = opts || {};
    if (opts.className) el.className = opts.className;
    if (opts.text != null) el.textContent = String(opts.text);
    if (opts.title) el.title = String(opts.title);
    if (opts.attrs) Object.keys(opts.attrs).forEach(function (key) {
      if (opts.attrs[key] == null || opts.attrs[key] === false) return;
      el.setAttribute(key, opts.attrs[key] === true ? '' : String(opts.attrs[key]));
    });
    if (children != null) append(el, children);
    return el;
  };
  host.stack = function (children, opts) {
    opts = opts || {};
    opts.className = [host.classes.stack, opts.className || ''].filter(Boolean).join(' ');
    return host.h('div', opts, children);
  };
  host.card = function (children, opts) {
    opts = opts || {};
    opts.className = [host.classes.card, opts.className || ''].filter(Boolean).join(' ');
    return host.h('section', opts, children);
  };
  host.button = function (text, onClick, secondary) {
    var btn = host.h('button', { className: secondary ? host.classes.secondaryButton : host.classes.button, text: text, attrs: { type: 'button' } });
    if (typeof onClick === 'function') btn.addEventListener('click', onClick);
    return btn;
  };
  host.badge = function (text, title) {
    return host.h('span', { className: host.classes.badge, text: text, title: title || '' });
  };
  host.status = function (text) {
    return host.h('span', { className: host.classes.status, text: text || '' });
  };
  host.toast = function (message, timeout) {
    var stack = document.querySelector('.' + host.classes.toastStack);
    if (!stack) {
      stack = host.h('div', { className: host.classes.toastStack, attrs: { role: 'status', 'aria-live': 'polite' } });
      document.body.appendChild(stack);
    }
    var toast = host.h('div', { className: host.classes.toast, text: message || '' });
    stack.appendChild(toast);
    window.requestAnimationFrame(function () { toast.classList.add('is-visible'); });
    window.setTimeout(function () {
      toast.classList.remove('is-visible');
      window.setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
        scheduleHeight();
      }, 180);
    }, timeout || 2200);
    scheduleHeight();
    return toast;
  };
  host.stat = function (label, value, detail) {
    return host.h('div', { className: host.classes.stat, title: detail || '' }, [
      host.h('span', { className: host.classes.statLabel, text: label }),
      host.h('span', { className: host.classes.statValue, text: value == null || value === '' ? '-' : String(value) })
    ]);
  };
  host.table = function (headers, rows) {
    return host.h('table', { className: host.classes.table }, [
      host.h('thead', null, host.h('tr', null, (headers || []).map(function (header) { return tableCell('th', header); }))),
      host.h('tbody', null, (rows || []).map(function (row) {
        return host.h('tr', null, (row || []).map(function (cell) { return tableCell('td', cell); }));
      }))
    ]);
  };
  host.data = Object.freeze({
    list: function (resource) {
      return rpc('data.list', { resource: resource });
    },
    get: function (resource, key) {
      return rpc('data.get', { resource: resource, key: key });
    },
    create: function (resource, data, options) {
      options = options || {};
      return rpc('data.create', { resource: resource, key: options.key || '', data: data, enabled: options.enabled });
    },
    update: function (resource, key, data, options) {
      options = options || {};
      return rpc('data.update', { resource: resource, key: key, data: data, enabled: options.enabled });
    },
    delete: function (resource, key) {
      return rpc('data.delete', { resource: resource, key: key });
    }
  });
  host.action = function (name, payload) {
    return rpc('action', { action: name, payload: payload || {} });
  };
  host.requestResize = scheduleHeight;
  window.ForwardPluginHost = Object.freeze(host);
  document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.add('fwd-plugin-body');
    scheduleHeight();
    window.setTimeout(scheduleHeight, 80);
    window.setTimeout(scheduleHeight, 300);
    if (window.ResizeObserver) {
      new ResizeObserver(scheduleHeight).observe(document.body);
    }
    if (window.MutationObserver) {
      new MutationObserver(scheduleHeight).observe(document.documentElement, {
        attributes: true,
        childList: true,
        subtree: true,
        characterData: true
      });
    }
  });
  window.addEventListener('load', scheduleHeight);
  window.addEventListener('resize', scheduleHeight);
})();`;
  }

  function decoratePluginHTML(html, plugin) {
    const injection = [
      '<style data-forward-plugin-host>',
      pluginHostComponentCSS(),
      '</style>',
      '<script data-forward-plugin-host>',
      pluginHostComponentJS(plugin).replace(/<\/script/gi, '<\\/script'),
      '</script>'
    ].join('');
    if (/<head(\s[^>]*)?>/i.test(html)) {
      return html.replace(/<head(\s[^>]*)?>/i, (match) => match + injection);
    }
    return injection + html;
  }

  function setPluginUIPanelLoading(plugin, entry) {
    const panel = app.el.pluginUIPanel;
    if (!panel) return false;
    panel.hidden = false;
    if (app.el.pluginUITitle) app.el.pluginUITitle.textContent = plugin.name || plugin.id || app.t('plugins.ui.emptyTitle');
    if (app.el.pluginUIMeta) app.el.pluginUIMeta.textContent = app.t('plugins.opening');
    if (app.el.pluginUIFrame) {
      app.el.pluginUIFrame.title = plugin.name || plugin.id || 'Plugin UI';
      preparePluginFrame(app.el.pluginUIFrame, plugin, entry);
      app.el.pluginUIFrame.src = 'about:blank';
      app.el.pluginUIFrame.setAttribute('sandbox', 'allow-scripts allow-forms allow-popups');
    }
    if (typeof panel.scrollIntoView === 'function') panel.scrollIntoView({ block: 'nearest' });
    return true;
  }

  function setPluginUIPanelLoaded(plugin, entry, html) {
    if (!app.el.pluginUIPanel || !app.el.pluginUIFrame) return false;
    app.state.plugins.activePluginId = plugin.id || '';
    app.el.pluginUIPanel.hidden = false;
    if (app.el.pluginUITitle) app.el.pluginUITitle.textContent = plugin.name || plugin.id || app.t('plugins.ui.emptyTitle');
    if (app.el.pluginUIMeta) {
      app.el.pluginUIMeta.textContent = app.t('plugins.ui.loadedMeta', {
        id: plugin.id || '',
        entry
      });
    }
    preparePluginFrame(app.el.pluginUIFrame, plugin, entry);
    app.el.pluginUIFrame.src = 'about:blank';
    app.el.pluginUIFrame.srcdoc = html;
    return true;
  }

  async function fetchDecoratedPluginHTML(plugin, entry) {
    const basePath = String(plugin && plugin.asset_base_path || '').trim();
    const url = basePath + entry;
    const resp = await fetch(url, {
      headers: { Authorization: 'Bearer ' + app.getToken() }
    });
    if (resp.status === 401) {
      app.clearToken();
      app.showTokenModal();
      throw new Error('unauthorized');
    }
    if (!resp.ok) throw new Error(resp.statusText || String(resp.status));
    const contentType = resp.headers.get('Content-Type') || 'text/html; charset=utf-8';
    const raw = await resp.text();
    return contentType.toLowerCase().includes('text/html') ? decoratePluginHTML(raw, plugin) : raw;
  }

  function preparePluginFrame(iframe, plugin, entry) {
    if (!iframe) return;
    iframe.style.height = '';
    if (iframe.dataset) {
      iframe.dataset.pluginFrame = '1';
      iframe.dataset.pluginId = plugin && plugin.id || '';
      iframe.dataset.pluginEntry = entry || '';
    }
  }

  function setPluginFrameHeight(iframe, height) {
    const value = Math.ceil(Number(height) || 0);
    if (!iframe || value <= 0) return;
    iframe.style.height = Math.min(Math.max(value + 2, 180), 6000) + 'px';
  }

  function findPluginFrameBySource(source) {
    if (!source || typeof document.querySelectorAll !== 'function') return null;
    const frames = Array.from(document.querySelectorAll('iframe[data-plugin-frame="1"]'));
    for (let i = 0; i < frames.length; i++) {
      try {
        if (frames[i].contentWindow === source) return frames[i];
      } catch (e) {
        // Cross-origin access can throw for plugin popups; ignore and keep scanning.
      }
    }
    return null;
  }

  function postPluginRPCResult(source, pluginId, id, ok, result, error) {
    if (!source || !id) return;
    try {
      source.postMessage({
        type: 'forward-plugin-rpc-result',
        pluginId: pluginId || '',
        id,
        ok: !!ok,
        result: ok ? result : undefined,
        error: ok ? undefined : (error || 'plugin request failed')
      }, '*');
    } catch (e) {
      console.error('plugin rpc response:', e);
    }
  }

  function pluginRPCString(value, label) {
    const text = String(value == null ? '' : value).trim();
    if (!text) throw new Error(label + ' is required');
    return text;
  }

  async function callPluginRPCAPI(pluginId, op, payload) {
    payload = payload && typeof payload === 'object' ? payload : {};
    const id = encodeURIComponent(pluginRPCString(pluginId, 'plugin id'));
    const resource = payload.resource != null ? encodeURIComponent(pluginRPCString(payload.resource, 'resource')) : '';
    const key = payload.key != null && payload.key !== '' ? encodeURIComponent(pluginRPCString(payload.key, 'key')) : '';
    if (op === 'data.list') return app.apiCall('GET', '/api/plugins/' + id + '/resources/' + resource);
    if (op === 'data.get') {
      if (!key) throw new Error('key is required');
      return app.apiCall('GET', '/api/plugins/' + id + '/resources/' + resource + '/' + key);
    }
    if (op === 'data.create') {
      const body = { data: payload.data };
      if (payload.key != null && payload.key !== '') body.key = payload.key;
      if (payload.enabled != null) body.enabled = !!payload.enabled;
      return app.apiCall('POST', '/api/plugins/' + id + '/resources/' + resource, body);
    }
    if (op === 'data.update') {
      if (!key) throw new Error('key is required');
      const body = { data: payload.data };
      if (payload.enabled != null) body.enabled = !!payload.enabled;
      return app.apiCall('PUT', '/api/plugins/' + id + '/resources/' + resource + '/' + key, body);
    }
    if (op === 'data.delete') {
      if (!key) throw new Error('key is required');
      return app.apiCall('DELETE', '/api/plugins/' + id + '/resources/' + resource + '/' + key);
    }
    if (op === 'action') {
      const action = encodeURIComponent(pluginRPCString(payload.action, 'action'));
      return app.apiCall('POST', '/api/plugins/' + id + '/actions/' + action, { payload: payload.payload || {} });
    }
    throw new Error('unsupported plugin operation');
  }

  async function handlePluginFrameRPC(event, frame, data) {
    const pluginId = frame && frame.dataset ? frame.dataset.pluginId : '';
    if (!pluginId || data.pluginId !== pluginId) return;
    try {
      const result = await callPluginRPCAPI(pluginId, String(data.op || ''), data.payload);
      postPluginRPCResult(event.source, pluginId, data.id, true, result, '');
    } catch (e) {
      postPluginRPCResult(event.source, pluginId, data.id, false, null, e.message || String(e));
    }
  }

  function handlePluginFrameMessage(event) {
    const data = event && event.data && typeof event.data === 'object' ? event.data : null;
    if (!data) return;
    const frame = findPluginFrameBySource(event.source);
    if (!frame) return;
    if (frame.dataset && data.pluginId && frame.dataset.pluginId && data.pluginId !== frame.dataset.pluginId) return;
    if (data.type === 'forward-plugin-ui-height') {
      setPluginFrameHeight(frame, data.height);
      return;
    }
    if (data.type === 'forward-plugin-rpc') {
      handlePluginFrameRPC(event, frame, data);
    }
  }

  function pluginPageByTabID(tabID) {
    return pluginPages().find((page) => page.tabID === tabID) || null;
  }

  function createPluginTabPanel(page) {
    const panel = document.createElement('div');
    panel.id = 'tab-' + page.tabID;
    panel.className = 'tab-content plugin-page-tab-content';
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', 'tab-' + page.tabID + '-button');
    panel.hidden = true;

    const section = app.createNode('section', {
      className: 'plugin-page-section',
      children: [
        app.createNode('div', {
          className: 'plugin-page-toolbar',
          children: [
            app.createNode('div', {
              className: 'plugin-page-title-block',
              children: [
                app.createNode('h2', { text: page.title }),
                app.createNode('p', {
                  className: 'section-desc',
                  text: app.t('plugins.ui.loadedMeta', { id: page.pluginID, entry: page.entry })
                })
              ]
            }),
            app.createNode('button', {
              className: 'mini-btn btn-reload-plugin-page',
              text: app.t('plugins.refresh'),
              dataset: { pluginTab: page.tabID }
            })
          ]
        }),
        app.createNode('iframe', {
          className: 'plugin-page-frame',
          title: page.title,
          dataset: {
            pluginFrame: '1',
            pluginId: page.pluginID,
            pluginEntry: page.entry
          },
          attrs: { sandbox: 'allow-scripts allow-forms allow-popups' }
        })
      ]
    });
    panel.appendChild(section);
    return panel;
  }

  function setPluginPageLoadingState(tabID, loading) {
    const selector = '.btn-reload-plugin-page[data-plugin-tab="' + String(tabID || '').replace(/"/g, '\\"') + '"]';
    let button = null;
    const panel = typeof document.getElementById === 'function' ? document.getElementById('tab-' + tabID) : null;
    if (panel && typeof panel.querySelector === 'function') button = panel.querySelector(selector);
    if (!button && typeof document.querySelector === 'function') button = document.querySelector(selector);
    if (!button) return;
    button.disabled = !!loading;
    if (button.classList && typeof button.classList.toggle === 'function') button.classList.toggle('is-busy', !!loading);
    button.setAttribute('aria-busy', loading ? 'true' : 'false');
  }

  function renderPluginPageTabs() {
    if (typeof document.querySelector !== 'function') return;
    const tabs = document.querySelector('.tabs');
    const pluginsPanel = document.getElementById('tab-plugins');
    const main = pluginsPanel && pluginsPanel.parentNode ? pluginsPanel.parentNode : (document.querySelector('.app-shell') || document.querySelector('main') || document.body);
    if (!tabs || !main) return;
    const pages = pluginPages();
    const pageIDs = new Set(pages.map((page) => page.tabID));

    Array.from(document.querySelectorAll('.plugin-page-tab')).forEach((tab) => {
      if (!pageIDs.has(tab.dataset.tab)) tab.remove();
    });
    Array.from(document.querySelectorAll('.plugin-page-tab-content')).forEach((panel) => {
      const tabID = String(panel.id || '').replace(/^tab-/, '');
      if (!pageIDs.has(tabID)) panel.remove();
    });

    const tabAnchor = document.querySelector('.tab[data-tab="diagnostics"]');
    const diagnosticsPanel = document.getElementById('tab-diagnostics');
    pages.forEach((page) => {
      let button = document.querySelector('.tab[data-tab="' + page.tabID + '"]');
      if (!button) {
        button = document.createElement('button');
        button.id = 'tab-' + page.tabID + '-button';
        button.className = 'tab plugin-page-tab';
        button.type = 'button';
        button.dataset.tab = page.tabID;
        button.setAttribute('role', 'tab');
        button.setAttribute('aria-selected', 'false');
        button.setAttribute('aria-controls', 'tab-' + page.tabID);
        button.setAttribute('tabindex', '-1');
        if (tabAnchor && tabAnchor.parentNode === tabs) tabs.insertBefore(button, tabAnchor);
        else tabs.appendChild(button);
      }
      button.textContent = page.title;
      button.title = page.pluginID;
      bindPluginTabButton(button);

      if (!document.getElementById('tab-' + page.tabID)) {
        const panel = createPluginTabPanel(page);
        if (diagnosticsPanel && diagnosticsPanel.parentNode === main) main.insertBefore(panel, diagnosticsPanel);
        else if (pluginsPanel && pluginsPanel.parentNode === main && pluginsPanel.nextSibling) main.insertBefore(panel, pluginsPanel.nextSibling);
        else main.appendChild(panel);
      }
    });

    if (pageIDs.has(app.state.activeTab)) {
      app.activateTab(app.state.activeTab, { persist: false, skipLoad: true });
      app.loadPluginPageForTab(app.state.activeTab);
    }
  }

  function renderPluginCatalogMeta() {
    const el = app.el.pluginsCatalogMeta;
    if (!el) return;
    const catalog = app.state.plugins.catalog || {};
    const runtime = catalog.runtime || {};
    const enabled = catalog.external_plugins_enabled !== false;
    const attach = !!runtime.external_dataplane_attach;
    app.clearNode(el);
    el.title = app.t('plugins.catalog.meta', {
      dir: catalog.directory || '',
      enabled: enabled ? app.t('common.yes') : app.t('common.no'),
      attach: attach ? app.t('common.yes') : app.t('common.no')
    });
    el.appendChild(app.createNode('div', {
      className: 'plugin-meta-heading',
      children: [
        app.createNode('span', { className: 'plugin-meta-title', text: app.t('plugins.catalog.title') }),
        app.createNode('span', {
          className: 'plugin-meta-badge ' + (enabled ? 'is-ok' : 'is-muted'),
          text: enabled ? app.t('plugins.catalog.scanOn') : app.t('plugins.catalog.scanOff')
        })
      ]
    }));
    el.appendChild(app.createNode('div', {
      className: 'plugin-meta-items',
      children: [
        pluginMetaItem(app.t('plugins.catalog.dir'), catalog.directory || app.t('common.dash'), 'mono'),
        pluginMetaItem(app.t('plugins.catalog.scan'), enabled ? app.t('common.yes') : app.t('common.no'), enabled ? 'ok' : 'muted'),
        pluginMetaItem(app.t('plugins.catalog.dataplane'), attach ? app.t('common.yes') : app.t('common.no'), attach ? 'ok' : 'muted')
      ]
    }));
  }

  function pluginMetaItem(label, value, tone) {
    return app.createNode('span', {
      className: 'plugin-meta-item' + (tone ? ' is-' + tone : ''),
      children: [
        app.createNode('span', { className: 'plugin-meta-item-label', text: label }),
        app.createNode('span', { className: 'plugin-meta-item-value', text: value })
      ]
    });
  }

  function pluginPipelineChip(text, tone, title) {
    return app.createNode('span', {
      className: 'plugin-pipeline-chip' + (tone ? ' is-' + tone : ''),
      text,
      title: title || text
    });
  }

  function pluginPipelineArrow() {
    return app.createNode('span', {
      className: 'plugin-pipeline-arrow',
      text: '>'
    });
  }

  function appendPipelineNode(nodes, node) {
    if (nodes.length) nodes.push(pluginPipelineArrow());
    nodes.push(node);
  }

  function pluginChainItemText(item) {
    const name = [item.pluginID, item.hookID].filter(Boolean).join('.');
    const slot = item.slot > 0 ? 's' + item.slot : '';
    return [slot, name, 'p' + item.priority].filter(Boolean).join(' ');
  }

  function renderPluginChainMeta() {
    const el = app.el.pluginsChainMeta;
    if (!el) return;
    const data = Array.isArray(app.state.plugins.data) ? app.state.plugins.data : [];
    const corePriority = pluginPipelineCorePriority();
    const chain = [];
    data.forEach((plugin) => {
      const attachments = plugin && plugin.runtime && Array.isArray(plugin.runtime.attachments) ? plugin.runtime.attachments : [];
      attachments.forEach((attachment) => {
        const slot = attachmentChainSlot(attachment);
        const status = String(attachment.status || '').toLowerCase();
        if (slot <= 0 && status !== 'chained') return;
        chain.push({
          slot,
          priority: typeof attachment.priority === 'number' ? attachment.priority : 0,
          pluginID: plugin.id || '',
          hookID: attachment.hook_id || '',
          program: attachment.program || '',
          stage: attachment.stage || ''
        });
      });
    });
    chain.sort((a, b) => {
      if (a.slot !== b.slot) {
        if (a.slot === 0) return 1;
        if (b.slot === 0) return -1;
        return a.slot - b.slot;
      }
      if (a.priority !== b.priority) return a.priority - b.priority;
      if (a.pluginID !== b.pluginID) return a.pluginID < b.pluginID ? -1 : 1;
      return a.hookID < b.hookID ? -1 : a.hookID > b.hookID ? 1 : 0;
    });
    const formatItems = (items) => items.map((item) => {
      const name = [item.pluginID, item.hookID].filter(Boolean).join('.');
      const slot = item.slot > 0 ? app.t('plugins.chain.slot', { slot: item.slot }) + ' ' : '';
      const priority = 'priority=' + item.priority;
      return slot + name + ' (' + priority + ')';
    });
    const isReplyStage = (item) => item.stage === 'pre_reply' || item.stage === 'post_reply' || item.stage === 'reply' || item.slot >= 29;
    const isForwardPostCore = (item) => item.stage === 'post_lookup' || item.stage === 'next_forward' || (item.stage === 'forward' && item.priority > corePriority) || (item.slot >= 18 && item.slot < 26);
    const isReplyPostCore = (item) => item.stage === 'post_reply' || (item.stage === 'reply' && item.priority > corePriority) || item.slot >= 37;
    const forwardChain = chain.filter((item) => !isReplyStage(item));
    const replyChain = chain.filter((item) => isReplyStage(item));
    const preForward = forwardChain.filter((item) => !isForwardPostCore(item));
    const postLookup = forwardChain.filter((item) => isForwardPostCore(item));
    const preReply = replyChain.filter((item) => !isReplyPostCore(item));
    const postReply = replyChain.filter((item) => isReplyPostCore(item));
    const parts = [];
    const forwardParts = [];
    if (preForward.length) forwardParts.push(app.t('plugins.chain.preForward', { chain: formatItems(preForward).join(' -> ') }));
    forwardParts.push(app.t('plugins.chain.core', { priority: corePriority }));
    if (postLookup.length) forwardParts.push(app.t('plugins.chain.postLookup', { chain: formatItems(postLookup).join(' -> ') }));
    forwardParts.push(app.t('plugins.chain.apply'));
    parts.push(app.t('plugins.chain.forwardPath', { chain: forwardParts.join(' -> ') }));
    if (replyChain.length) {
      const replyParts = [];
      if (preReply.length) replyParts.push(app.t('plugins.chain.preReply', { chain: formatItems(preReply).join(' -> ') }));
      replyParts.push(app.t('plugins.chain.replyCore', { priority: corePriority }));
      if (postReply.length) replyParts.push(app.t('plugins.chain.postReply', { chain: formatItems(postReply).join(' -> ') }));
      replyParts.push(app.t('plugins.chain.replyApply'));
      parts.push(app.t('plugins.chain.replyPath', { chain: replyParts.join(' -> ') }));
    }
    const detail = chain.length ? app.t('plugins.chain.meta', { chain: parts.join(' | ') }) : app.t('plugins.chain.empty');
    const nodes = [];
    if (!chain.length) appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.legacy'), 'muted', detail));
    if (preForward.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.preCompact', { count: preForward.length }), 'pre', preForward.map(pluginChainItemText).join('\n')));
    }
    appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.coreCompact', { priority: corePriority }), 'core', app.t('plugins.chain.core', { priority: corePriority })));
    if (postLookup.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.postCompact', { count: postLookup.length }), 'post', postLookup.map(pluginChainItemText).join('\n')));
    }
    appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.applyCompact'), 'apply', app.t('plugins.chain.apply')));
    if (preReply.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.preReplyCompact', { count: preReply.length }), 'pre', preReply.map(pluginChainItemText).join('\n')));
    }
    if (replyChain.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.replyCoreCompact', { priority: corePriority }), 'core', app.t('plugins.chain.replyCore', { priority: corePriority })));
    }
    if (postReply.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.postReplyCompact', { count: postReply.length }), 'post', postReply.map(pluginChainItemText).join('\n')));
    }
    if (replyChain.length) {
      appendPipelineNode(nodes, pluginPipelineChip(app.t('plugins.chain.replyApplyCompact'), 'apply', app.t('plugins.chain.replyApply')));
    }

    app.clearNode(el);
    el.title = detail;
    el.appendChild(app.createNode('div', {
      className: 'plugin-meta-heading',
      children: [
        app.createNode('span', { className: 'plugin-meta-title', text: app.t('plugins.chain.title') }),
        app.createNode('span', {
          className: 'plugin-meta-badge ' + (chain.length ? 'is-ok' : 'is-muted'),
          text: chain.length ? app.t('plugins.chain.chained', { count: chain.length }) : app.t('plugins.chain.none')
        })
      ]
    }));
    el.appendChild(app.createNode('div', {
      className: 'plugin-pipeline',
      children: nodes
    }));
  }

  app.renderPluginsTable = function renderPluginsTable() {
    const el = app.el;
    const st = app.state.plugins;
    const data = Array.isArray(st.data) ? st.data : [];
    let filteredList = data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((plugin) => app.matchesSearch(st.searchQuery, pluginSearchValues(plugin)));
    }
    filteredList = app.sortByState(filteredList, st, pluginSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.pluginsBody);
    app.updateSortIndicators('pluginsTable', st);
    app.renderFilterMeta('plugins', filteredList.length, data.length);
    app.renderPagination('plugins', filteredList.length);
    renderPluginCatalogMeta();
    renderPluginChainMeta();

    if (!filteredList.length) {
      app.updateEmptyState(el.noPlugins, {
        message: data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('plugins.empty'),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('pluginsTable', false);
      return;
    }

    app.hideEmptyState(el.noPlugins);
    app.toggleTableVisibility('pluginsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((plugin) => {
      const tr = document.createElement('tr');
      const info = pluginStatusInfo(plugin);
      const detailText = pluginDetailsPlainText(plugin);
      const nameTitle = [
        plugin.source ? app.t('plugins.source') + ': ' + plugin.source : '',
        plugin.description || ''
      ].filter(Boolean).join('\n');

      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'stat-mono plugin-text-truncate',
        text: plugin.id || app.t('common.dash'),
        title: plugin.id || ''
      }), 'plugin-cell-id'));
      tr.appendChild(app.createCell(app.createNode('div', {
        className: 'plugin-status-compact',
        children: [
          app.createStatusBadgeNode(info, ''),
          app.createNode('button', {
            className: 'kernel-runtime-detail-trigger plugin-detail-trigger',
            text: app.t('plugins.details'),
            attrs: {
              type: 'button',
              'aria-haspopup': 'dialog',
              'aria-expanded': 'false',
              'aria-controls': 'pluginRuntimeTooltip',
              'aria-label': detailText || (app.t('plugins.details') + ': ' + textOrDash(plugin.name || plugin.id))
            },
            dataset: { pluginId: plugin.id || '' }
          })
        ].filter(Boolean)
      }), 'plugin-cell-status'));
      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'plugin-text-truncate',
        text: plugin.name || app.t('common.dash'),
        title: nameTitle
      }), 'plugin-cell-name'));
      tr.appendChild(app.createCell(plugin.kind ? app.createNode('span', { className: 'plugin-text-truncate', text: plugin.kind, title: plugin.kind }) : app.emptyCellNode('stat-muted'), 'plugin-cell-tight'));
      tr.appendChild(app.createCell(plugin.version ? app.createNode('span', { className: 'plugin-text-truncate', text: plugin.version, title: plugin.version }) : app.emptyCellNode('stat-muted'), 'plugin-cell-tight'));
      tr.appendChild(app.createCell(pluginUINode(plugin), 'plugin-cell-tight'));
      fragment.appendChild(tr);
    });

    el.pluginsBody.appendChild(fragment);
  };

  app.loadPlugins = async function loadPlugins() {
    try {
      const resp = await app.apiCall('GET', '/api/plugins');
      app.state.plugins.catalog = resp || {};
      app.state.plugins.data = Array.isArray(resp && resp.plugins) ? resp.plugins : [];
      renderPluginPageTabs();
      app.renderPluginsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load plugins:', e);
    }
  };

  app.openPluginUI = async function openPluginUI(pluginId) {
    const plugin = (app.state.plugins.data || []).find((item) => item && item.id === pluginId);
    const entry = String(plugin && plugin.ui && plugin.ui.entry || '').trim();
    const basePath = String(plugin && plugin.asset_base_path || '').trim();
    if (!plugin || !entry || !basePath) return;
    const page = pluginPageInfo(plugin);
    if (page && typeof document.getElementById === 'function' && document.getElementById('tab-' + page.tabID)) {
      app.activateTab(page.tabID);
      return;
    }
    setPluginUIPanelLoading(plugin, entry);

    try {
      const html = await fetchDecoratedPluginHTML(plugin, entry);
      if (!setPluginUIPanelLoaded(plugin, entry, html)) {
        const blobURL = URL.createObjectURL(new Blob([html], { type: 'text/html; charset=utf-8' }));
        const fallback = window.open(blobURL, '_blank', 'noopener');
        if (!fallback) throw new Error('popup blocked');
        window.setTimeout(() => URL.revokeObjectURL(blobURL), 5 * 60 * 1000);
      }
    } catch (e) {
      if (e.message === 'unauthorized') app.closePluginUI();
      if (e.message !== 'unauthorized') {
        const message = e.message === 'popup blocked'
          ? app.t('plugins.popupBlocked')
          : app.t('plugins.openFailed', { message: e.message || String(e) });
        app.notify('error', message);
      }
    }
  };

  app.loadPluginPageForTab = async function loadPluginPageForTab(tabID, options) {
    const page = pluginPageByTabID(tabID);
    if (!page) return;
    const panel = typeof document.getElementById === 'function' ? document.getElementById('tab-' + page.tabID) : null;
    if (!panel) return;
    const iframe = panel.querySelector ? panel.querySelector('.plugin-page-frame') : null;
    if (!iframe) return;
    const opts = options || {};
    if (!opts.force && panel.dataset.loaded === '1') return;
    panel.dataset.loaded = 'loading';
    setPluginPageLoadingState(page.tabID, true);
    try {
      const html = await fetchDecoratedPluginHTML(page.plugin, page.entry);
      panel.dataset.loaded = '1';
      preparePluginFrame(iframe, page.plugin, page.entry);
      iframe.src = 'about:blank';
      iframe.srcdoc = html;
    } catch (e) {
      panel.dataset.loaded = '';
      if (e.message !== 'unauthorized') {
        app.notify('error', app.t('plugins.openFailed', { message: e.message || String(e) }));
      }
    } finally {
      setPluginPageLoadingState(page.tabID, false);
    }
  };

  app.reloadPluginPageForTab = function reloadPluginPageForTab(tabID) {
    const panel = typeof document.getElementById === 'function' ? document.getElementById('tab-' + tabID) : null;
    if (panel) panel.dataset.loaded = '';
    return app.loadPluginPageForTab(tabID, { force: true });
  };

  app.closePluginUI = function closePluginUI() {
    if (app.el.pluginUIFrame) {
      app.el.pluginUIFrame.srcdoc = '';
      app.el.pluginUIFrame.src = 'about:blank';
      app.el.pluginUIFrame.style.height = '';
      if (app.el.pluginUIFrame.dataset) {
        delete app.el.pluginUIFrame.dataset.pluginFrame;
        delete app.el.pluginUIFrame.dataset.pluginId;
        delete app.el.pluginUIFrame.dataset.pluginEntry;
      }
    }
    if (app.el.pluginUIPanel) app.el.pluginUIPanel.hidden = true;
    if (app.el.pluginUIMeta) app.el.pluginUIMeta.textContent = '';
    if (app.el.pluginUITitle) app.el.pluginUITitle.textContent = app.t('plugins.ui.emptyTitle');
    if (app.state.plugins) app.state.plugins.activePluginId = '';
  };

  app.handleTabLoad = (function wrapPluginPageTabLoad(original) {
    return function handleTabLoadWithPluginPages(target) {
      if (String(target || '').indexOf('plugin-') === 0) {
        app.loadPluginPageForTab(target);
        return;
      }
      if (typeof original === 'function') original(target);
    };
  })(app.handleTabLoad);

  if (document && typeof document.addEventListener === 'function') {
    document.addEventListener('click', (e) => {
      const trigger = e.target.closest && e.target.closest('.plugin-detail-trigger[data-plugin-id]');
      if (trigger) {
        e.preventDefault();
        e.stopPropagation();
        togglePluginPopover(trigger);
        return;
      }
      if (pluginDetailPopover && pluginDetailPopover.contains(e.target)) return;
      hidePluginPopover();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') hidePluginPopover();
    });
    document.addEventListener('scroll', () => {
      if (pluginDetailPopoverTrigger) positionPluginPopover();
    }, true);
  }
  if (window && typeof window.addEventListener === 'function') {
    window.addEventListener('resize', () => {
      if (pluginDetailPopoverTrigger) positionPluginPopover();
    });
    window.addEventListener('message', handlePluginFrameMessage);
  }
})();
