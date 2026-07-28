(function () {
  const app = window.VeerApp;
  if (!app) return;

  const pluginUIRPCMaxInflight = 32;
  const pluginUIRPCMaxPayloadBytes = 2 * 1024 * 1024;
  const pluginUIRPCMaxPendingBytes = 4 * 1024 * 1024;
  const pluginUIRPCRateWindowMs = 10 * 1000;
  const pluginUIRPCRateLimit = 120;
  const pluginUIAssetTextMaxBytes = 1024 * 1024;
  const pluginUIAssetDataMaxBytes = 4 * 1024 * 1024;
  const pluginFrameRPCStates = new WeakMap();

  function listText(values) {
    if (!Array.isArray(values) || values.length === 0) return '';
    return values.filter(Boolean).join(', ');
  }

  function pluginStatusInfo(plugin) {
    const status = String(plugin && plugin.status || '').toLowerCase();
    if (status === 'builtin') return { badge: 'kernel', text: app.t('plugins.status.builtin') };
    if (status === 'active') return { badge: 'running', text: app.t('plugins.status.active') };
    if (status === 'disabled') return { badge: 'disabled', text: app.t('plugins.status.disabled') };
    if (status === 'error') return { badge: 'error', text: app.t('plugins.status.error') };
    if (status === 'pending') return { badge: 'warning', text: app.t('plugins.status.pending') };
    return { badge: 'disabled', text: status || app.t('common.dash') };
  }

  function pluginStabilityInfo(plugin) {
    const stability = String(plugin && plugin.stability || 'lab').toLowerCase();
    if (stability === 'stable') return { className: 'is-stable', text: app.t('plugins.stability.stable') };
    if (stability === 'preview') return { className: 'is-preview', text: app.t('plugins.stability.preview') };
    if (stability === 'deprecated') return { className: 'is-deprecated', text: app.t('plugins.stability.deprecated') };
    return { className: 'is-lab', text: app.t('plugins.stability.lab') };
  }

  function pluginStabilityBadgeNode(plugin) {
    const info = pluginStabilityInfo(plugin);
    return app.createNode('span', {
      className: 'plugin-stability-badge ' + info.className,
      text: info.text,
      title: app.t('plugins.stability') + ': ' + info.text
    });
  }

  function pluginRuntimeModeText(mode) {
    const value = String(mode || '').toLowerCase();
    if (value === 'builtin') return app.t('plugins.runtime.builtin');
    if (value === 'dataplane') return app.t('plugins.runtime.dataplane');
    if (value === 'control') return app.t('plugins.runtime.control');
    if (value === 'disabled') return app.t('plugins.runtime.disabled');
    if (value === 'error') return app.t('plugins.runtime.error');
    if (value === 'registered') return app.t('plugins.runtime.registered');
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
    const engine = String(hook && hook.engine || '').toLowerCase();
    const netfilter = engine === 'netfilter';
    return [
      engine ? engine.toUpperCase() : '',
      netfilter && hook && hook.family ? 'family=' + hook.family : '',
      netfilter && hook && hook.hook ? 'hook=' + hook.hook : '',
      netfilter && hook && hook.phase ? 'phase=' + hook.phase : '',
      netfilter && hook && hook.namespace ? 'namespace=' + hook.namespace : '',
      !netfilter && hook && hook.attach,
      !netfilter && hook && hook.stage,
      hook && typeof hook.priority === 'number' ? 'priority=' + hook.priority : '',
      hook && hook.program,
      hook && hook.mode,
      hook && Array.isArray(hook.before) && hook.before.length ? 'before=' + hook.before.join(',') : '',
      hook && Array.isArray(hook.after) && hook.after.length ? 'after=' + hook.after.join(',') : '',
      pluginPacketMetadataDetail(hook && hook.packet_metadata),
      hook && Array.isArray(hook.context) && hook.context.length ? 'ctx=' + hook.context.join(',') : '',
      hook && Array.isArray(hook.interfaces) && hook.interfaces.length ? 'if=' + hook.interfaces.join(',') : ''
    ].filter(Boolean).join(' | ');
  }

  function pluginPacketMetadataDetail(bindings) {
    if (!Array.isArray(bindings) || !bindings.length) return '';
    return 'metadata=' + bindings.map((binding) => [
      's' + String(binding && binding.slot != null ? binding.slot : 0),
      binding && binding.namespace,
      binding && binding.schema_version ? 'v' + binding.schema_version : '',
      binding && binding.max_bytes ? String(binding.max_bytes) + 'B' : '',
      binding && binding.access
    ].filter(Boolean).join(':')).join(',');
  }

  function pluginMetricNumber(value) {
    const number = Number(value || 0);
    if (!Number.isFinite(number)) return app.t('common.dash');
    try {
      return new Intl.NumberFormat(app.state.locale || undefined, { maximumFractionDigits: 3 }).format(number);
    } catch (_) {
      return String(number);
    }
  }

  function pluginMetricIdentity(metric) {
    const name = String(metric && metric.name || '').trim() || app.t('plugins.metrics.title');
    const labels = metric && metric.labels && typeof metric.labels === 'object' ? metric.labels : {};
    const entries = Object.keys(labels).sort().map((key) => key + '=' + String(labels[key]));
    return entries.length ? name + '{' + entries.join(', ') + '}' : name;
  }

  function pluginMetricDetail(metric) {
    return [
      metric && metric.type,
      pluginMetricNumber(metric && metric.value),
      metric && metric.updated_at
    ].filter(Boolean).join(' | ');
  }

  function pluginAttachmentMetricDetail(attachment) {
    const total = attachment && attachment.metrics && attachment.metrics.total;
    if (!total || typeof total !== 'object') return '';
    return [
      app.t('plugins.metrics.packets') + '=' + pluginMetricNumber(total.packets),
      app.t('plugins.metrics.bytes') + '=' + pluginMetricNumber(total.bytes),
      app.t('plugins.metrics.continued') + '=' + pluginMetricNumber(total.continued_packets),
      app.t('plugins.metrics.terminal') + '=' + pluginMetricNumber(total.terminal_packets),
      Number(total.tail_call_misses || 0) ? app.t('plugins.metrics.misses') + '=' + pluginMetricNumber(total.tail_call_misses) : ''
    ].filter(Boolean).join(' / ');
  }

  function pluginAttachmentDetail(attachment) {
    const engine = String(attachment && attachment.engine || '').toLowerCase();
    const netfilter = engine === 'netfilter';
    return [
      engine ? engine.toUpperCase() : '',
      netfilter && attachment && attachment.family ? 'family=' + attachment.family : '',
      netfilter && attachment && attachment.netfilter_hook ? 'hook=' + attachment.netfilter_hook : '',
      netfilter && attachment && attachment.phase ? 'phase=' + attachment.phase : '',
      netfilter && attachment && attachment.namespace ? 'namespace=' + attachment.namespace : '',
      !netfilter && attachment && attachment.attach,
      !netfilter && attachment && attachment.stage,
      !netfilter && attachment && attachment.interface,
      attachment && attachment.status,
      attachment && attachment.program,
      attachmentPriorityParts(attachment).join(' | '),
      attachment && Array.isArray(attachment.context) && attachment.context.length ? 'ctx=' + attachment.context.join(',') : '',
      pluginPacketMetadataDetail(attachment && attachment.packet_metadata),
      attachment && attachment.filter_handle ? (netfilter ? 'kernel=' : '') + attachment.filter_handle : '',
      pluginAttachmentMetricDetail(attachment),
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
    const metrics = runtime && Array.isArray(runtime.metrics) ? runtime.metrics : [];
    const sections = [];

    sections.push({
      title: app.t('plugins.detail.runtime'),
      rows: [
        detailRow('ID', item.id),
        detailRow(app.t('common.status'), info.text),
        detailRow(app.t('plugins.stability'), pluginStabilityInfo(item).text),
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

    if (metrics.length) {
      sections.push({
        title: app.t('plugins.metrics.title'),
        rows: metrics.map((metric) => detailRow(pluginMetricIdentity(metric), pluginMetricDetail(metric))).filter(Boolean)
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
    const manageButton = !item.builtin && item.id && item.id !== 'veer_core'
      ? app.createNode('button', {
          className: 'plugin-detail-close plugin-detail-manage',
          text: app.t('plugins.manager.action'),
          attrs: { type: 'button' }
        })
      : null;
    if (manageButton && typeof manageButton.addEventListener === 'function') {
      manageButton.addEventListener('click', () => {
        hidePluginPopover();
        if (typeof app.openPluginManager === 'function') {
          app.openPluginManager('plugin', { pluginID: item.id, tab: 'overview' });
        }
      });
    }
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
              pluginStabilityBadgeNode(item),
              app.createStatusBadgeNode(info, ''),
              manageButton,
              closeButton
            ].filter(Boolean)
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
    const core = plugins.find((plugin) => plugin && plugin.id === 'veer_core');
    const hooks = core && Array.isArray(core.hooks) ? core.hooks : [];
    const coreHook = hooks.find((hook) => hook && hook.engine === 'tc' && hook.attach === 'ingress' && hook.stage === 'forward');
    if (coreHook && typeof coreHook.priority === 'number' && Number.isFinite(coreHook.priority)) return coreHook.priority;
    return 1000;
  }

  function attachmentPriorityParts(attachment) {
    const parts = [];
    if (typeof attachment.priority === 'number') {
      const engine = String(attachment.engine || '').toLowerCase();
      parts.push((engine === 'tc' && attachment.filter_handle ? 'tc_prio=' : 'priority=') + attachment.priority);
    }
    const slot = attachmentChainSlot(attachment);
    if (typeof attachment.order === 'number' && Number.isFinite(attachment.order)) {
      parts.push('order=' + attachment.order);
    }
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
      plugin.stability,
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
      hooks.map((hook) => [hook.id, hook.engine, hook.attach, hook.stage, hook.family, hook.hook, hook.phase, hook.namespace, hook.program, hook.mode, Array.isArray(hook.before) ? hook.before.join(' ') : '', Array.isArray(hook.after) ? hook.after.join(' ') : '', pluginPacketMetadataDetail(hook.packet_metadata), Array.isArray(hook.context) ? hook.context.join(' ') : ''].filter(Boolean).join(' ')).join(' '),
      attachments.map((attachment) => [attachment.hook_id, attachment.engine, attachment.attach, attachment.stage, attachment.interface, attachment.family, attachment.netfilter_hook, attachment.phase, attachment.namespace, attachment.program, attachment.status, attachment.filter_handle, Array.isArray(attachment.before) ? attachment.before.join(' ') : '', Array.isArray(attachment.after) ? attachment.after.join(' ') : '', pluginPacketMetadataDetail(attachment.packet_metadata), Array.isArray(attachment.context) ? attachment.context.join(' ') : '', String(attachment.order ?? ''), String(attachment.chain_slot || ''), String(attachment.priority || '')].filter(Boolean).join(' ')).join(' '),
      virtualInterfaces.map((vif) => [vif.id, vif.type, vif.description].filter(Boolean).join(' ')).join(' ')
    ];
  }

  function normalizePluginPageID(value) {
    const page = String(value || '').trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
    return page && page !== 'plugins' && page !== 'diagnostics' ? page : '';
  }

  function pluginPageInfo(plugin) {
    if (!plugin || !plugin.asset_base_path || !(plugin.ui && plugin.ui.entry)) return null;
    const ui = plugin.ui || {};
    const page = normalizePluginPageID(ui.page);
    if (!page) return null;
    const title = String(ui.page_title || '').trim() || plugin.name || page;
    return {
      tabID: 'plugin-' + page,
      page,
      title,
      pluginID: plugin.id || '',
      entry: plugin.ui.entry,
      plugin
    };
  }

  function attachmentDirection(attachment) {
    const stage = String(attachment && attachment.stage || '').toLowerCase();
    const slot = attachmentChainSlot(attachment);
    if (stage.indexOf('reply') >= 0 || slot >= 29) return 'reply';
    return 'forward';
  }

  function attachmentIsPostCore(attachment, corePriority) {
    const stage = String(attachment && attachment.stage || '').toLowerCase();
    const priority = typeof (attachment && attachment.priority) === 'number' ? attachment.priority : 0;
    const slot = attachmentChainSlot(attachment);
    const direction = attachmentDirection(attachment);
    if (direction === 'reply') {
      return stage === 'post_reply' || priority > corePriority || slot >= 37;
    }
    return stage === 'post_lookup' || stage === 'next_forward' || priority > corePriority || (slot >= 18 && slot < 26);
  }

  function pluginAttachmentSortValue(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    const slot = attachmentChainSlot(attachment);
    const priority = typeof attachment.priority === 'number' ? attachment.priority : 0;
    return {
      slot: slot > 0 ? slot : 9999,
      priority,
      pluginID: item && item.pluginID || '',
      hookID: attachment.hook_id || ''
    };
  }

  function comparePluginAttachmentItems(a, b) {
    const av = pluginAttachmentSortValue(a);
    const bv = pluginAttachmentSortValue(b);
    if (av.slot !== bv.slot) return av.slot - bv.slot;
    if (av.priority !== bv.priority) return av.priority - bv.priority;
    if (av.pluginID !== bv.pluginID) return av.pluginID < bv.pluginID ? -1 : 1;
    return av.hookID < bv.hookID ? -1 : av.hookID > bv.hookID ? 1 : 0;
  }

  function pluginRuntimeAttachmentItems() {
    const data = Array.isArray(app.state.plugins.data) ? app.state.plugins.data : [];
    const out = [];
    data.forEach((plugin) => {
      const runtime = plugin && plugin.runtime && typeof plugin.runtime === 'object' ? plugin.runtime : null;
      const attachments = runtime && Array.isArray(runtime.attachments) ? runtime.attachments : [];
      const hooks = Array.isArray(plugin && plugin.hooks) ? plugin.hooks : [];
      attachments.forEach((attachment) => {
        out.push({
          pluginID: plugin && plugin.id || '',
          pluginName: plugin && plugin.name || '',
          hook: hooks.find((hook) => hook && hook.id === attachment.hook_id) || null,
          attachment
        });
      });
    });
    return out;
  }

  function attachmentGroupKey(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    const interfaces = pluginAttachmentInterfaces(item);
    return [
      String(attachment.engine || '').toLowerCase(),
      String(attachment.attach || '').toLowerCase(),
      attachmentDirection(attachment),
      interfaces.length ? interfaces.slice().sort().join(',').toLowerCase() : String(attachment.interface || '').toLowerCase()
    ].join('\x1f');
  }

  function attachmentGroupLabel(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    const engine = attachment.engine ? String(attachment.engine).toUpperCase() : 'TC';
    return [
      engine,
      attachment.attach || '',
      attachmentDirection(attachment)
    ].filter(Boolean).join(' ');
  }

  function pluginAttachmentInterfaces(item) {
    const hook = item && item.hook ? item.hook : null;
    return hook && Array.isArray(hook.interfaces)
      ? hook.interfaces.map((value) => String(value || '').trim()).filter(Boolean)
      : [];
  }

  function pluginInterfaceSegment(interfaces, pipelineInterface, attach, direction) {
    const values = Array.isArray(interfaces) ? interfaces.filter(Boolean) : [];
    const text = values.length ? values.join(',') : (pipelineInterface || app.t('plugins.link.unbound'));
    return {
      text,
      title: values.length ? values.join(', ') : app.t('plugins.link.unbound'),
      detailTitle: text,
      detailRows: [
        detailRow('Interfaces', values.length ? values.join(', ') : app.t('plugins.link.unbound')),
        detailRow('Pipeline', pipelineInterface),
        detailRow('Attach', attach),
        detailRow(app.t('plugins.link.direction'), direction)
      ].filter(Boolean)
    };
  }

  function pluginAttachmentSegment(item, currentPluginID) {
    const attachment = item && item.attachment ? item.attachment : {};
    const interfaces = pluginAttachmentInterfaces(item);
    const slot = attachmentChainSlot(attachment);
    const label = item.pluginID || attachment.hook_id || app.t('common.dash');
    const netfilter = String(attachment.engine || '').toLowerCase() === 'netfilter';
    return {
      text: label,
      title: [
        item.pluginName || item.pluginID,
        attachment.hook_id,
        netfilter && attachment.family ? 'family=' + attachment.family : '',
        netfilter && attachment.netfilter_hook ? 'hook=' + attachment.netfilter_hook : '',
        netfilter && attachment.phase ? 'phase=' + attachment.phase : '',
        netfilter && attachment.namespace ? 'namespace=' + attachment.namespace : '',
        attachment.stage,
        attachment.mode,
        attachment.program,
        interfaces.length ? 'if=' + interfaces.join(',') : '',
        attachment.status,
        attachment.error ? app.t('plugins.error') + ': ' + attachment.error : ''
      ].filter(Boolean).join(' | '),
      current: item.pluginID === currentPluginID,
      error: !!attachment.error,
      detailTitle: [item.pluginID, attachment.hook_id].filter(Boolean).join('.') || label,
      detailRows: [
        detailRow('Plugin', item.pluginName || item.pluginID),
        detailRow('Hook', attachment.hook_id),
        detailRow('Engine', attachment.engine ? String(attachment.engine).toUpperCase() : ''),
        detailRow('Family', netfilter ? attachment.family : ''),
        detailRow('Netfilter Hook', netfilter ? attachment.netfilter_hook : ''),
        detailRow('Phase', netfilter ? attachment.phase : ''),
        detailRow('Namespace', netfilter ? attachment.namespace : ''),
        detailRow('Attach', netfilter ? '' : attachment.attach),
        detailRow('Stage', netfilter ? '' : attachment.stage),
        detailRow('Mode', attachment.mode),
        detailRow('Interfaces', !netfilter && interfaces.length ? interfaces.join(', ') : ''),
        detailRow('Pipeline', netfilter ? '' : attachment.interface),
        detailRow('Program', attachment.program),
        detailRow('Status', attachment.status),
        detailRow('Priority', typeof attachment.priority === 'number' ? String(attachment.priority) : ''),
        detailRow('Kernel attachment', netfilter ? attachment.filter_handle : ''),
        detailRow('Before', Array.isArray(attachment.before) && attachment.before.length ? attachment.before.join(', ') : ''),
        detailRow('After', Array.isArray(attachment.after) && attachment.after.length ? attachment.after.join(', ') : ''),
        detailRow('Resolved order', typeof attachment.order === 'number' ? String(attachment.order) : ''),
        detailRow('Packet metadata', pluginPacketMetadataDetail(attachment.packet_metadata)),
        detailRow('Slot', slot > 0 ? String(slot) : ''),
        detailRow('Context', Array.isArray(attachment.context) && attachment.context.length ? attachment.context.join(', ') : ''),
        detailRow(app.t('plugins.error'), attachment.error)
      ].filter(Boolean)
    };
  }

  function pluginCoreSegment(direction, corePriority) {
    return {
      text: direction === 'reply'
        ? app.t('plugins.link.replyCoreCompact')
        : app.t('plugins.link.coreCompact'),
      title: direction === 'reply'
        ? app.t('plugins.chain.replyCore', { priority: corePriority })
        : app.t('plugins.chain.core', { priority: corePriority }),
      core: true,
      detailTitle: direction === 'reply' ? app.t('plugins.chain.replyCore', { priority: corePriority }) : app.t('plugins.chain.core', { priority: corePriority }),
      detailRows: [
        detailRow(app.t('plugins.link.role'), direction === 'reply' ? app.t('plugins.link.replyCoreCompact') : app.t('plugins.link.coreCompact')),
        detailRow(app.t('plugins.link.direction'), direction),
        detailRow('Priority', String(corePriority))
      ].filter(Boolean)
    };
  }

  function pluginApplySegment(direction) {
    return {
      text: direction === 'reply' ? app.t('plugins.chain.replyApplyCompact') : app.t('plugins.chain.applyCompact'),
      title: direction === 'reply' ? app.t('plugins.chain.replyApply') : app.t('plugins.chain.apply'),
      apply: true,
      detailTitle: direction === 'reply' ? app.t('plugins.chain.replyApply') : app.t('plugins.chain.apply'),
      detailRows: [
        detailRow(app.t('plugins.link.role'), direction === 'reply' ? app.t('plugins.chain.replyApplyCompact') : app.t('plugins.chain.applyCompact')),
        detailRow(app.t('plugins.link.direction'), direction)
      ].filter(Boolean)
    };
  }

  function pluginAttachmentChainRows(plugin) {
    const currentID = plugin && plugin.id || '';
    if (!currentID) return [];
    const all = pluginRuntimeAttachmentItems().filter((item) => String(item && item.attachment && item.attachment.engine || '').toLowerCase() !== 'netfilter');
    const current = all.filter((item) => item.pluginID === currentID);
    if (!current.length) return [];
    const relevantKeys = new Set(current.map(attachmentGroupKey));
    const corePriority = pluginPipelineCorePriority();
    const groups = [];
    const groupMap = new Map();
    all.forEach((item) => {
      const key = attachmentGroupKey(item);
      if (!relevantKeys.has(key)) return;
      let group = groupMap.get(key);
      if (!group) {
        group = { key, sample: item, items: [] };
        groupMap.set(key, group);
        groups.push(group);
      }
      group.items.push(item);
    });
    groups.sort((a, b) => {
      const al = attachmentGroupLabel(a.sample);
      const bl = attachmentGroupLabel(b.sample);
      return al < bl ? -1 : al > bl ? 1 : 0;
    });
    return groups.map((group) => {
      const direction = attachmentDirection(group.sample.attachment);
      const pre = group.items.filter((item) => !attachmentIsPostCore(item.attachment, corePriority)).sort(comparePluginAttachmentItems);
      const post = group.items.filter((item) => attachmentIsPostCore(item.attachment, corePriority)).sort(comparePluginAttachmentItems);
      return {
        kind: app.t('plugins.link.interfaceChain'),
        label: attachmentGroupLabel(group.sample),
        segments: [pluginInterfaceSegment(
          pluginAttachmentInterfaces(group.sample),
          group.sample.attachment && group.sample.attachment.interface,
          group.sample.attachment && group.sample.attachment.attach,
          direction
        )].concat(pre.map((item) => pluginAttachmentSegment(item, currentID)))
          .concat([pluginCoreSegment(direction, corePriority)])
          .concat(post.map((item) => pluginAttachmentSegment(item, currentID)))
          .concat([pluginApplySegment(direction)])
      };
    });
  }

  function netfilterPlacementKey(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    return [
      String(attachment.namespace || attachment.interface || 'host').toLowerCase(),
      String(attachment.family || 'inet').toLowerCase(),
      String(attachment.netfilter_hook || attachment.attach || '').toLowerCase(),
      String(attachment.phase || attachment.stage || '').toLowerCase()
    ].join('\x1f');
  }

  function netfilterPlacementLabel(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    return [
      attachment.namespace || attachment.interface || 'host',
      attachment.family || 'inet',
      attachment.netfilter_hook || attachment.attach,
      attachment.phase || attachment.stage
    ].filter(Boolean).join(' / ');
  }

  function compareNetfilterAttachmentItems(a, b) {
    const aa = a && a.attachment ? a.attachment : {};
    const ba = b && b.attachment ? b.attachment : {};
    const ao = typeof aa.order === 'number' ? aa.order : 9999;
    const bo = typeof ba.order === 'number' ? ba.order : 9999;
    if (ao !== bo) return ao - bo;
    return comparePluginAttachmentItems(a, b);
  }

  function pluginNetfilterPlacementRows(plugin) {
    const currentID = plugin && plugin.id || '';
    if (!currentID) return [];
    const all = pluginRuntimeAttachmentItems().filter((item) => String(item && item.attachment && item.attachment.engine || '').toLowerCase() === 'netfilter');
    const current = all.filter((item) => item.pluginID === currentID);
    if (!current.length) return [];
    const relevantKeys = new Set(current.map(netfilterPlacementKey));
    const groups = [];
    const groupMap = new Map();
    all.forEach((item) => {
      const key = netfilterPlacementKey(item);
      if (!relevantKeys.has(key)) return;
      let group = groupMap.get(key);
      if (!group) {
        group = { key, sample: item, items: [] };
        groupMap.set(key, group);
        groups.push(group);
      }
      group.items.push(item);
    });
    groups.sort((a, b) => {
      const al = netfilterPlacementLabel(a.sample);
      const bl = netfilterPlacementLabel(b.sample);
      return al < bl ? -1 : al > bl ? 1 : 0;
    });
    return groups.map((group) => ({
      kind: app.t('plugins.link.netfilterPlacement'),
      label: netfilterPlacementLabel(group.sample),
      segments: group.items.sort(compareNetfilterAttachmentItems).map((item) => pluginAttachmentSegment(item, currentID))
    }));
  }

  function hookDirection(hook) {
    const stage = String(hook && hook.stage || '').toLowerCase();
    if (stage.indexOf('reply') >= 0) return 'reply';
    return 'forward';
  }

  function hookIsPostCore(hook, corePriority) {
    const stage = String(hook && hook.stage || '').toLowerCase();
    const priority = typeof (hook && hook.priority) === 'number' ? hook.priority : 0;
    const direction = hookDirection(hook);
    if (direction === 'reply') return stage === 'post_reply' || priority > corePriority;
    return stage === 'post_lookup' || stage === 'next_forward' || priority > corePriority;
  }

  function declaredHookPipelineStage(hook, corePriority) {
    const stage = String(hook && hook.stage || '').toLowerCase();
    const priority = typeof (hook && hook.priority) === 'number' ? hook.priority : 0;
    if (stage === 'pre_forward' || stage === 'post_lookup' || stage === 'pre_reply' || stage === 'post_reply') return stage;
    if (stage === 'forward') {
      if (priority < corePriority) return 'pre_forward';
      if (priority > corePriority) return 'post_lookup';
      return '';
    }
    if (stage === 'reply') {
      if (priority < corePriority) return 'pre_reply';
      if (priority > corePriority) return 'post_reply';
      return '';
    }
    return '';
  }

  function isDeclaredVeerPipelineHook(hook, corePriority) {
    const engine = String(hook && hook.engine || 'tc').toLowerCase();
    const attach = String(hook && hook.attach || 'ingress').toLowerCase();
    const mode = String(hook && hook.mode || '').toLowerCase();
    if (engine !== 'tc' || attach === 'egress' || attach === 'none' || mode === 'control') return false;
    return !!declaredHookPipelineStage(hook, corePriority);
  }

  function pluginHookSegment(plugin, hook, currentPluginID) {
    const label = plugin && plugin.id || hook && hook.id || app.t('common.dash');
    return {
      text: label,
      title: [
        plugin && (plugin.name || plugin.id),
        hook && hook.id,
        hook && hook.stage,
        hook && hook.mode,
        hook && hook.program,
        hook && Array.isArray(hook.interfaces) && hook.interfaces.length ? 'if=' + hook.interfaces.join(',') : app.t('plugins.link.unbound')
      ].filter(Boolean).join(' | '),
      current: plugin && plugin.id === currentPluginID,
      detailTitle: [plugin && plugin.id, hook && hook.id].filter(Boolean).join('.') || label,
      detailRows: [
        detailRow('Plugin', plugin && (plugin.name || plugin.id)),
        detailRow('Hook', hook && hook.id),
        detailRow('Engine', hook && hook.engine ? String(hook.engine).toUpperCase() : ''),
        detailRow('Attach', hook && hook.attach),
        detailRow('Stage', hook && hook.stage),
        detailRow('Mode', hook && hook.mode),
        detailRow('Interfaces', hook && Array.isArray(hook.interfaces) && hook.interfaces.length ? hook.interfaces.join(', ') : app.t('plugins.link.unbound')),
        detailRow('Program', hook && hook.program),
        detailRow('Priority', typeof (hook && hook.priority) === 'number' ? String(hook.priority) : ''),
        detailRow('Before', hook && Array.isArray(hook.before) && hook.before.length ? hook.before.join(', ') : ''),
        detailRow('After', hook && Array.isArray(hook.after) && hook.after.length ? hook.after.join(', ') : ''),
        detailRow('Packet metadata', pluginPacketMetadataDetail(hook && hook.packet_metadata)),
        detailRow('Context', hook && Array.isArray(hook.context) && hook.context.length ? hook.context.join(', ') : '')
      ].filter(Boolean)
    };
  }

  function comparePluginHookItems(a, b) {
    const ah = a && a.hook ? a.hook : {};
    const bh = b && b.hook ? b.hook : {};
    const ap = typeof ah.priority === 'number' ? ah.priority : 0;
    const bp = typeof bh.priority === 'number' ? bh.priority : 0;
    if (ap !== bp) return ap - bp;
    const aid = a && a.plugin && a.plugin.id || '';
    const bid = b && b.plugin && b.plugin.id || '';
    if (aid !== bid) return aid < bid ? -1 : 1;
    const ahid = ah.id || '';
    const bhid = bh.id || '';
    return ahid < bhid ? -1 : ahid > bhid ? 1 : 0;
  }

  function hookGroupKey(item) {
    const hook = item && item.hook ? item.hook : {};
    const interfaces = Array.isArray(hook.interfaces) && hook.interfaces.length ? hook.interfaces.slice().sort().join(',') : '*';
    return [
      String(hook.engine || 'tc').toLowerCase(),
      String(hook.attach || 'ingress').toLowerCase(),
      hookDirection(hook),
      interfaces
    ].join('\x1f');
  }

  function hookGroupLabel(item) {
    const hook = item && item.hook ? item.hook : {};
    const engine = hook.engine ? String(hook.engine).toUpperCase() : 'TC';
    return [engine, hook.attach || 'ingress', hookDirection(hook)].filter(Boolean).join(' ');
  }

  function pluginDeclaredHookChainRows(plugin) {
    const currentID = plugin && plugin.id || '';
    if (!currentID) return [];
    const data = Array.isArray(app.state.plugins.data) ? app.state.plugins.data : [];
    const corePriority = pluginPipelineCorePriority();
    const all = [];
    data.forEach((candidate) => {
      const hooks = Array.isArray(candidate && candidate.hooks) ? candidate.hooks : [];
      hooks.forEach((hook) => {
        if (!isDeclaredVeerPipelineHook(hook, corePriority)) return;
        all.push({ plugin: candidate, hook });
      });
    });
    const current = all.filter((item) => item.plugin && item.plugin.id === currentID);
    if (!current.length) return [];
    const relevantKeys = new Set(current.map(hookGroupKey));
    const groups = [];
    const groupMap = new Map();
    all.forEach((item) => {
      const key = hookGroupKey(item);
      if (!relevantKeys.has(key)) return;
      let group = groupMap.get(key);
      if (!group) {
        group = { key, sample: item, items: [] };
        groupMap.set(key, group);
        groups.push(group);
      }
      group.items.push(item);
    });
    groups.sort((a, b) => {
      const al = hookGroupLabel(a.sample);
      const bl = hookGroupLabel(b.sample);
      return al < bl ? -1 : al > bl ? 1 : 0;
    });
    return groups.map((group) => {
      const direction = hookDirection(group.sample.hook);
      const pre = group.items.filter((item) => !hookIsPostCore(item.hook, corePriority)).sort(comparePluginHookItems);
      const post = group.items.filter((item) => hookIsPostCore(item.hook, corePriority)).sort(comparePluginHookItems);
      return {
        kind: app.t('plugins.link.declaredChain'),
        label: hookGroupLabel(group.sample),
        segments: [pluginInterfaceSegment(
          Array.isArray(group.sample.hook && group.sample.hook.interfaces) ? group.sample.hook.interfaces : [],
          '',
          group.sample.hook && group.sample.hook.attach,
          direction
        )].concat(pre.map((item) => pluginHookSegment(item.plugin, item.hook, currentID)))
          .concat([pluginCoreSegment(direction, corePriority)])
          .concat(post.map((item) => pluginHookSegment(item.plugin, item.hook, currentID)))
          .concat([pluginApplySegment(direction)])
      };
    });
  }

  function pluginVirtualLinkItems(plugin) {
    const item = plugin || {};

    const chains = pluginAttachmentChainRows(item);
    const netfilterPlacements = pluginNetfilterPlacementRows(item);
    if (chains.length || netfilterPlacements.length) return chains.concat(netfilterPlacements);
    const declaredChains = pluginDeclaredHookChainRows(item);
    if (declaredChains.length) return declaredChains;

    return [];
  }

  function pluginHasVirtualLinkCard(plugin) {
    return pluginVirtualLinkItems(plugin).length > 0;
  }

  function pluginLinkSegmentFlags(segment) {
    const item = segment && typeof segment === 'object' ? segment : { text: String(segment || '') };
    return [
      item.current ? app.t('plugins.link.current') : '',
      item.core ? app.t('plugins.link.core') : '',
      item.apply ? app.t('plugins.link.apply') : '',
      item.error ? app.t('plugins.error') : ''
    ].filter(Boolean);
  }

  function pluginLinkSegmentDetailSections(row, segment, index) {
    const item = segment && typeof segment === 'object' ? segment : { text: String(segment || '') };
    const flags = pluginLinkSegmentFlags(item);
    const rows = Array.isArray(item.detailRows) ? item.detailRows : [];
    return [
      {
        title: app.t('plugins.detail.runtime'),
        rows: [
          detailRow(app.t('plugins.link.type'), row && row.kind),
          detailRow(app.t('plugins.link.scope'), row && row.label),
          detailRow(app.t('plugins.link.stepIndex'), String((index || 0) + 1)),
          detailRow(app.t('plugins.link.flags'), flags.join(', '))
        ].filter(Boolean)
      },
      {
        title: item.detailTitle || item.text || app.t('plugins.details'),
        rows: rows.length ? rows : [
          detailRow(app.t('plugins.link.node'), item.text),
          detailRow(app.t('plugins.detail.description'), item.title)
        ].filter(Boolean)
      }
    ].filter((section) => section.rows && section.rows.length);
  }

  function pluginLinkSegmentDetailContent(row, segment, index) {
    const item = segment && typeof segment === 'object' ? segment : { text: String(segment || '') };
    const closeButton = app.createNode('button', {
      className: 'plugin-detail-close',
      text: app.t('plugins.detail.close'),
      attrs: { type: 'button' }
    });
    if (closeButton && typeof closeButton.addEventListener === 'function') {
      closeButton.addEventListener('click', hidePluginPopover);
    }
    const sections = pluginLinkSegmentDetailSections(row, item, index);
    return [
      app.createNode('div', {
        className: 'kernel-runtime-tooltip-header plugin-detail-header',
        children: [
          app.createNode('div', {
            children: [
              app.createNode('span', {
                className: 'kernel-runtime-tooltip-title',
                text: item.detailTitle || item.text || app.t('plugins.link.node')
              }),
              app.createNode('span', {
                className: 'kernel-runtime-tooltip-meta',
                text: [row && row.kind, row && row.label].filter(Boolean).join(' / ') || app.t('common.dash')
              })
            ]
          }),
          app.createNode('div', {
            className: 'plugin-detail-header-actions',
            children: [
              app.createNode('span', {
                className: 'plugin-meta-badge is-ok',
                text: app.t('plugins.link.step', { index: (index || 0) + 1 })
              }),
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

  function showPluginLinkPopover(trigger, row, segment, index, pinned) {
    if (!trigger || !row) return;
    const popover = ensurePluginPopover();
    if (pluginDetailPopoverTrigger && pluginDetailPopoverTrigger !== trigger) {
      pluginDetailPopoverTrigger.setAttribute('aria-expanded', 'false');
    }

    pluginDetailPopoverTrigger = trigger;
    pluginDetailPopoverPinned = !!pinned;
    app.clearNode(popover);
    app.appendNodeContent(popover, pluginLinkSegmentDetailContent(row, segment, index));
    popover.hidden = false;
    popover.classList.add('is-visible');
    trigger.setAttribute('aria-expanded', 'true');
    positionPluginPopover();
  }

  function togglePluginLinkPopover(trigger, row, segment, index) {
    if (pluginDetailPopoverTrigger === trigger && pluginDetailPopoverPinned) {
      hidePluginPopover();
      return;
    }
    showPluginLinkPopover(trigger, row, segment, index, true);
  }

  function createPluginVirtualLinkCard(page) {
    const rows = pluginVirtualLinkItems(page && page.plugin);
    if (!rows.length) return null;
    const rowTitle = (row) => {
      const parts = row.segments && row.segments.length
        ? row.segments.map((segment) => segment.text || '').filter(Boolean)
        : (row.steps || []);
      return [row.kind, row.label].filter(Boolean).join(': ') + (parts.length ? ' -> ' + parts.join(' -> ') : '');
    };
    const stepNode = (step, row, index) => {
      const segment = step && typeof step === 'object' ? step : { text: String(step || '') };
      const classes = [
        'plugin-link-step',
        segment.current ? 'is-current' : '',
        segment.core ? 'is-core' : '',
        segment.apply ? 'is-apply' : '',
        segment.error ? 'is-error' : ''
      ].filter(Boolean).join(' ');
      const button = app.createNode('button', {
        className: classes,
        text: segment.text || app.t('common.dash'),
        title: segment.detailTitle || segment.title || segment.text || '',
        attrs: { type: 'button', 'aria-expanded': 'false' }
      });
      if (button && typeof button.addEventListener === 'function') {
        button.addEventListener('click', (e) => {
          if (e && typeof e.preventDefault === 'function') e.preventDefault();
          if (e && typeof e.stopPropagation === 'function') e.stopPropagation();
          togglePluginLinkPopover(button, row, segment, index);
        });
      }
      return button;
    };
    const rowNode = (row) => {
      return app.createNode('div', {
        className: 'plugin-link-row',
        title: rowTitle(row),
        children: [
          app.createNode('span', { className: 'plugin-link-kind', text: row.kind || app.t('common.dash') }),
          app.createNode('span', { className: 'plugin-link-name', text: row.label || app.t('common.dash') }),
          app.createNode('div', {
            className: 'plugin-link-path',
            children: (row.segments && row.segments.length ? row.segments : (row.steps && row.steps.length ? row.steps : [app.t('common.dash')])).reduce((nodes, step, index) => {
              if (nodes.length) nodes.push(app.createNode('span', { className: 'plugin-link-inline-arrow', text: '>' }));
              nodes.push(stepNode(step, row, index));
              return nodes;
            }, [])
          })
        ]
      });
    };
    return app.createNode('section', {
      className: 'plugin-link-card',
      children: [
        app.createNode('div', {
          className: 'plugin-link-card-head',
          children: [
            app.createNode('div', {
            children: [
              app.createNode('h3', { text: app.t('plugins.link.title') }),
              app.createNode('p', {
                  className: 'plugin-link-desc',
                  text: app.t('plugins.link.desc')
                })
            ]
          }),
            app.createNode('span', {
              className: 'plugin-meta-badge is-ok',
              text: app.t('plugins.link.count', { count: rows.length })
            })
          ]
        }),
        app.createNode('div', {
          className: 'plugin-link-list',
          children: rows.map(rowNode)
        })
      ]
    });
  }

  function updatePluginPageLinkCard(panel, page) {
    if (!panel || !page) return;
    const current = panel.querySelector ? panel.querySelector('.plugin-link-card') : null;
    const next = createPluginVirtualLinkCard(page);
    if (!next) {
      if (current) {
        if (typeof current.remove === 'function') current.remove();
        else if (current.parentNode && typeof current.parentNode.removeChild === 'function') current.parentNode.removeChild(current);
      }
      return;
    }
    if (current) {
      if (current.parentNode && typeof current.parentNode.replaceChild === 'function') current.parentNode.replaceChild(next, current);
      else if (typeof current.replaceWith === 'function') current.replaceWith(next);
      return;
    }
    const pageSection = panel.querySelector ? panel.querySelector('.plugin-page-section') : null;
    if (pageSection && pageSection.parentNode) {
      if (pageSection.nextSibling) pageSection.parentNode.insertBefore(next, pageSection.nextSibling);
      else pageSection.parentNode.appendChild(next);
    } else {
      panel.appendChild(next);
    }
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
    if (!plugin.asset_base_path && (!plugin.ui || !plugin.ui.entry)) return null;
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

  function pendingPluginUpdates(status) {
    const item = status && typeof status === 'object' ? status : {};
    return Array.isArray(item.updates) ? item.updates.filter((update) => update && update.plugin_id) : [];
  }

  function pluginUpdateMap(status) {
    const updates = new Map();
    pendingPluginUpdates(status).forEach((update) => updates.set(String(update.plugin_id), update));
    return updates;
  }

  function pluginRowsWithPendingUpdates(data, status) {
    const updates = pluginUpdateMap(status);
    const seen = new Set();
    const rows = data.map((plugin) => {
      const id = String(plugin && plugin.id || '');
      seen.add(id);
      const update = updates.get(id);
      return update ? Object.assign({}, plugin, { _pendingUpdate: update }) : plugin;
    });
    updates.forEach((update, id) => {
      if (seen.has(id)) return;
      rows.push({
        id: id,
        name: update.name || id,
        kind: update.kind || '',
        version: update.detected_version || '',
        source: update.source || '',
        status: 'pending',
        enabled: false,
        runtime: { mode: 'pending', attachable: false, attached: false },
        _pendingOnly: true,
        _pendingUpdate: update
      });
    });
    return rows;
  }

  function selectedPluginUpdateIDs() {
    const selected = app.state.plugins.selectedUpdateIDs || {};
    return Object.keys(selected).filter((id) => selected[id]).sort();
  }

  function pluginUpdateChoiceText(update) {
    const change = String(update && update.change || '').toLowerCase();
    if (change === 'added') return app.t('plugins.update.selectAdded');
    if (change === 'removed') return app.t('plugins.update.selectRemoved');
    return app.t('plugins.update.selectModified');
  }

  function pluginUpdateChoiceTitle(update) {
    const applied = update && update.applied_version || app.t('common.dash');
    const detected = update && update.detected_version || app.t('common.dash');
    return app.t('plugins.update.rowDetail', { applied, detected });
  }

  function pluginUpdateSelectorNode(update) {
    if (!update || !update.plugin_id) return null;
    const id = String(update.plugin_id);
    const applying = app.state.plugins.applyingUpdate === true;
    const selected = !!(app.state.plugins.selectedUpdateIDs && app.state.plugins.selectedUpdateIDs[id]);
    const input = app.createNode('input', {
      className: 'plugin-update-checkbox',
      attrs: {
        type: 'checkbox',
        checked: selected ? 'checked' : null,
        disabled: applying ? 'disabled' : null,
        'aria-label': pluginUpdateChoiceText(update)
      },
      dataset: { pluginId: id }
    });
    input.checked = selected;
    return app.createNode('label', {
      className: 'plugin-update-choice' + (selected ? ' is-selected' : '') + (applying ? ' is-disabled' : ''),
      title: pluginUpdateChoiceTitle(update),
      children: [
        input,
        app.createNode('span', {
          className: 'plugin-update-check',
          attrs: { 'aria-hidden': 'true' }
        }),
        app.createNode('span', {
          className: 'plugin-update-choice-label',
          text: pluginUpdateChoiceText(update)
        })
      ]
    });
  }

  function pluginActionsNode(plugin) {
    if (!plugin || plugin.builtin || plugin.id === 'veer_core' || plugin._pendingOnly) return null;
    const id = String(plugin.id || '').trim();
    if (!id) return null;
    const pending = app.isRowPending && app.isRowPending('plugin', id);
    const enabled = plugin.enabled !== false && String(plugin.status || '').toLowerCase() !== 'disabled';
    const willEnable = !enabled;
    return app.createNode('button', {
      className: 'mini-btn btn-toggle-plugin ' + (enabled ? 'btn-disable' : 'btn-enable') + (pending ? ' is-busy' : ''),
      text: pending ? app.t('common.processing') : app.t(enabled ? 'common.disable' : 'common.enable'),
      attrs: {
        type: 'button',
        disabled: pending ? 'disabled' : null,
        'aria-busy': pending ? 'true' : 'false'
      },
      dataset: {
        pluginId: id,
        enabled: willEnable ? '1' : '0'
      }
    });
  }

  function pluginControlsNode(plugin) {
    const controls = [pluginUpdateSelectorNode(plugin && plugin._pendingUpdate), pluginUINode(plugin), pluginActionsNode(plugin)].filter(Boolean);
    if (!controls.length) return app.emptyCellNode('stat-muted');
    if (controls.length === 1) return controls[0];
    return app.createNode('div', {
      className: 'plugin-table-actions',
      children: controls
    });
  }

  function pluginHostComponentCSS() {
    return `
:root {
  --veer-bg: #f5f6f8;
  --veer-surface: #ffffff;
  --veer-surface-soft: #f8f9fb;
  --veer-surface-tint: #eef4ff;
  --veer-text: #1f2937;
  --veer-muted: #4b5563;
  --veer-soft: #6b7280;
  --veer-border: #d9dde3;
  --veer-border-strong: #c7ced8;
  --veer-primary: #2563eb;
  --veer-primary-hover: #1d4ed8;
  --veer-primary-soft: rgba(37, 99, 235, 0.08);
  --veer-focus: rgba(37, 99, 235, 0.14);
  --veer-success-bg: #f0fdf4;
  --veer-success-border: #86efac;
  --veer-success-text: #15803d;
  --veer-danger: #dc2626;
  --veer-danger-hover: #b91c1c;
  --veer-danger-soft: rgba(220, 38, 38, 0.08);
  --veer-radius: 10px;
  --veer-shadow: 0 2px 8px rgba(15, 23, 42, 0.04);
  color-scheme: light;
  font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}
* {
  box-sizing: border-box;
}
body.veer-plugin-body,
body {
  margin: 0;
  background: var(--veer-bg);
  color: var(--veer-text);
  font-size: 13px;
}
.veer-page { padding: 8px; }
.veer-stack { display: grid; gap: 8px; }
.veer-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; }
.veer-card {
  min-width: 0;
  padding: 10px;
  border: 1px solid var(--veer-border);
  border-radius: 9px;
  background: rgba(255, 255, 255, 0.94);
  box-shadow: var(--veer-shadow);
}
.veer-card + .veer-card { margin-top: 0; }
.veer-card > * + * { margin-top: 8px; }
.veer-card > .veer-toolbar + * { margin-top: 10px; }
.veer-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 7px; flex-wrap: wrap; }
.veer-title { margin: 0; font-size: 16px; line-height: 1.28; font-weight: 680; letter-spacing: -0.01em; }
.veer-desc { margin: 3px 0 0; color: var(--veer-muted); line-height: 1.42; font-size: 12px; }
.veer-muted { color: var(--veer-muted); }
.veer-stat {
  display: grid;
  gap: 3px;
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid var(--veer-border);
  border-radius: 8px;
  background: var(--veer-surface-soft);
}
.veer-stat-label { color: var(--veer-soft); font-size: 10.5px; font-weight: 650; text-transform: uppercase; letter-spacing: 0.04em; }
.veer-stat-value {
  color: var(--veer-text); font-size: 14px; font-weight: 720; line-height: 1.22;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.veer-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 30px;
  padding: 0 11px;
  border: 1px solid var(--veer-primary);
  border-radius: 8px;
  background: var(--veer-primary);
  color: #fff;
  font-size: 12px;
  font-weight: 650;
  line-height: 1.2;
  white-space: nowrap;
  cursor: pointer;
  transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease, border-color 0.16s ease, color 0.16s ease;
}
.veer-button.secondary {
  border-color: var(--veer-border);
  background: var(--veer-surface);
  color: var(--veer-primary);
}
.veer-button.is-danger {
  border-color: var(--veer-danger);
  background: var(--veer-danger);
  color: #fff;
}
.veer-button.secondary.is-danger {
  border-color: color-mix(in srgb, var(--veer-danger) 42%, var(--veer-border));
  background: var(--veer-surface);
  color: var(--veer-danger);
}
.veer-button:hover, .veer-button:focus {
  transform: translateY(-1px);
  border-color: var(--veer-primary-hover);
  background: var(--veer-primary-hover);
  box-shadow: 0 6px 14px rgba(37, 99, 235, 0.18);
}
.veer-button.secondary:hover, .veer-button.secondary:focus {
  background: var(--veer-primary-soft);
  color: var(--veer-primary-hover);
}
.veer-button.is-danger:hover, .veer-button.is-danger:focus {
  border-color: var(--veer-danger-hover);
  background: var(--veer-danger-hover);
  box-shadow: 0 6px 14px rgba(220, 38, 38, 0.16);
}
.veer-button.secondary.is-danger:hover, .veer-button.secondary.is-danger:focus {
  border-color: var(--veer-danger);
  background: var(--veer-danger-soft);
  color: var(--veer-danger-hover);
}
.veer-button:active { transform: translateY(0); box-shadow: none; }
.veer-button:disabled { opacity: 0.52; cursor: not-allowed; transform: none; box-shadow: none; }
.veer-button.is-busy:disabled { opacity: 0.76; cursor: wait; }
.veer-button.is-busy::after {
  width: 11px;
  height: 11px;
  margin-left: 7px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  content: "";
  animation: veer-button-spin 0.7s linear infinite;
}
@keyframes veer-button-spin { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
  .veer-button.is-busy::after { animation-duration: 1.4s; }
}
.veer-badge {
  display: inline-flex; align-items: center; min-height: 21px; padding: 0 8px;
  border-radius: 999px; border: 1px solid var(--veer-border);
  background: var(--veer-surface-soft); color: var(--veer-muted); font-size: 11px; font-weight: 650;
  white-space: nowrap;
}
.veer-status {
  display: inline-flex;
  align-items: center;
  min-height: 21px;
  padding: 0 8px;
  border: 1px solid var(--veer-success-border);
  border-radius: 999px;
  background: var(--veer-success-bg);
  color: var(--veer-success-text);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}
.veer-toast-stack {
  position: fixed; right: 12px; bottom: 12px; z-index: 20;
  display: grid; gap: 7px; max-width: min(340px, calc(100vw - 24px));
}
.veer-toast {
  padding: 9px 11px; border: 1px solid var(--veer-border); border-radius: 10px;
  background: rgba(255, 255, 255, 0.98); color: var(--veer-text); box-shadow: 0 16px 34px rgba(15, 23, 42, 0.12);
  font-size: 12px; line-height: 1.45; opacity: 0; transform: translateY(6px) scale(0.98);
  transition: opacity 0.16s ease, transform 0.16s ease;
}
.veer-toast.is-visible { opacity: 1; transform: translateY(0) scale(1); }
.veer-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  overflow: hidden;
  border: 1px solid var(--veer-border);
  border-radius: 9px;
  background: var(--veer-surface);
}
.veer-table th, .veer-table td { padding: 8px 10px; border-bottom: 1px solid var(--veer-border); text-align: left; font-size: 12px; }
.veer-table tr:last-child td { border-bottom: 0; }
.veer-table th { color: var(--veer-soft); background: var(--veer-surface-soft); font-weight: 700; }
.veer-table td { overflow-wrap: anywhere; }
.veer-field { display: grid; gap: 6px; min-width: 0; }
.veer-field label,
.veer-field > span:first-child { color: var(--veer-muted); font-size: 11px; font-weight: 650; }
.veer-record-picker { display: grid; gap: 6px; min-width: 0; }
.veer-record-picker > [hidden] { display: none; }
.veer-collection-editor { display: grid; gap: 8px; min-width: 0; }
.veer-collection-rows { display: grid; gap: 7px; min-width: 0; }
.veer-collection-row {
  position: relative;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(112px, 1fr));
  gap: 7px;
  min-width: 0;
  padding: 8px 42px 8px 8px;
  border: 1px solid var(--veer-border);
  border-radius: 8px;
  background: var(--veer-surface-soft);
}
.veer-collection-field { display: grid; gap: 4px; min-width: 0; }
.veer-collection-field > span {
  overflow: hidden;
  color: var(--veer-muted);
  font-size: 10px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.veer-collection-field.wide { grid-column: span 2; }
.veer-collection-remove {
  position: absolute;
  top: 8px;
  right: 8px;
  width: 28px;
  min-width: 28px;
  min-height: 28px;
  padding: 0;
  font-size: 16px;
  line-height: 1;
}
.veer-collection-empty {
  margin: 0;
  padding: 9px 10px;
  border: 1px dashed var(--veer-border);
  border-radius: 8px;
  color: var(--veer-soft);
  font-size: 11px;
}
.veer-collection-actions { display: flex; justify-content: flex-start; }
.veer-input {
  width: 100%;
  min-height: 31px;
  padding: 5px 9px;
  border: 1px solid var(--veer-border);
  border-radius: 7px;
  background: var(--veer-surface);
  color: var(--veer-text);
  font: inherit;
  font-size: 12px;
  outline: none;
  transition: border-color 0.16s ease, box-shadow 0.16s ease, background 0.16s ease;
}
textarea.veer-input {
  min-height: 70px;
  padding-top: 7px;
  line-height: 1.45;
  resize: vertical;
}
.veer-input:hover {
  border-color: var(--veer-border-strong);
}
.veer-input:focus {
  border-color: var(--veer-primary);
  box-shadow: 0 0 0 3px var(--veer-focus);
  background: #fff;
}
select.veer-input {
  appearance: none;
  padding-right: 30px;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--veer-soft) 50%),
    linear-gradient(135deg, var(--veer-soft) 50%, transparent 50%);
  background-position:
    calc(100% - 16px) 14px,
    calc(100% - 11px) 14px;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
.veer-input[type="checkbox"] {
  appearance: none;
  width: 34px;
  min-width: 34px;
  height: 20px;
  min-height: 20px;
  padding: 0;
  border-radius: 999px;
  background: var(--veer-surface-soft);
  cursor: pointer;
  position: relative;
  vertical-align: middle;
}
.veer-input[type="checkbox"]::before {
  content: "";
  position: absolute;
  width: 14px;
  height: 14px;
  left: 2px;
  top: 2px;
  border-radius: 50%;
  background: var(--veer-soft);
  transition: transform 0.16s ease, background 0.16s ease;
}
.veer-input[type="checkbox"]:checked {
  border-color: var(--veer-primary);
  background: var(--veer-primary);
}
.veer-input[type="checkbox"]:checked::before {
  transform: translateX(14px);
  background: #fff;
}
.veer-input[type="checkbox"]:focus {
  background: var(--veer-primary-soft);
}
.veer-input[type="checkbox"]:checked:focus {
  background: var(--veer-primary);
}
@media (max-width: 720px) {
  .veer-page { padding: 8px; }
  .veer-grid { grid-template-columns: 1fr; }
  .veer-toolbar { align-items: flex-start; }
  .veer-collection-field.wide { grid-column: span 1; }
}
@media (prefers-color-scheme: dark) {
  :root {
    --veer-bg: #12161a;
    --veer-surface: #171b21;
    --veer-surface-soft: #1d232b;
    --veer-surface-tint: #172036;
    --veer-text: #e5e7eb;
    --veer-muted: #b3bcc8;
    --veer-soft: #8d98a8;
    --veer-border: #323943;
    --veer-border-strong: #3a4452;
    --veer-primary: #60a5fa;
    --veer-primary-hover: #93c5fd;
    --veer-primary-soft: rgba(96, 165, 250, 0.12);
    --veer-focus: rgba(96, 165, 250, 0.16);
    --veer-success-bg: rgba(34, 197, 94, 0.16);
    --veer-success-border: rgba(74, 222, 128, 0.44);
    --veer-success-text: #86efac;
    --veer-shadow: 0 2px 8px rgba(0, 0, 0, 0.18);
    color-scheme: dark;
  }
  .veer-card { background: rgba(23, 27, 33, 0.94); }
  .veer-input:focus { background: var(--veer-surface); }
  .veer-toast { background: rgba(23, 27, 33, 0.98); box-shadow: 0 18px 36px rgba(0, 0, 0, 0.32); }
}`;
  }

  function pluginHostComponentJS(plugin) {
    const grantedActions = new Set(Array.isArray(plugin && plugin.ui && plugin.ui.actions) ? plugin.ui.actions : []);
    const host = {
      version: 'v1',
      pluginId: plugin && plugin.id || '',
      pluginName: plugin && plugin.name || '',
      locale: app.state.locale || 'zh-CN',
      rpcLimits: {
        max_inflight: pluginUIRPCMaxInflight,
        max_payload_bytes: pluginUIRPCMaxPayloadBytes,
        max_pending_bytes: pluginUIRPCMaxPendingBytes
      },
      resources: Array.isArray(plugin && plugin.resources) ? plugin.resources.map(function (resource) {
        const methods = pluginUIOwnResourceMethods(plugin, resource && resource.id);
        return {
          id: resource && resource.id || '',
          description: resource && resource.description || '',
          methods: methods,
          runtime_update: resource && resource.runtime_update || '',
          max_records: resource && resource.max_records || 0,
          max_record_bytes: resource && resource.max_record_bytes || 0,
          schema_version: resource && resource.schema_version || 1,
          schema: resource && resource.schema || null,
          schema_digest: resource && resource.schema_digest || ''
        };
      }).filter(function (resource) { return resource.id && resource.methods.length > 0; }) : [],
      actions: Array.isArray(plugin && plugin.actions) ? plugin.actions.filter(function (action) {
        return action && grantedActions.has(action.id);
      }).map(function (action) {
        return {
          id: action && action.id || '',
          description: action && action.description || '',
          runtime_update: action && action.runtime_update || '',
          max_payload_bytes: action && action.max_payload_bytes || 0,
          request_schema_version: action && action.request_schema_version || 1,
          request_schema: action && action.request_schema || null,
          request_schema_digest: action && action.request_schema_digest || '',
          response_schema_version: action && action.response_schema_version || 1,
          response_schema: action && action.response_schema || null,
          response_schema_digest: action && action.response_schema_digest || ''
        };
      }) : [],
      classes: {
        page: 'veer-page',
        stack: 'veer-stack',
        grid: 'veer-grid',
        card: 'veer-card',
        toolbar: 'veer-toolbar',
        title: 'veer-title',
        description: 'veer-desc',
        muted: 'veer-muted',
        stat: 'veer-stat',
        statLabel: 'veer-stat-label',
        statValue: 'veer-stat-value',
        status: 'veer-status',
        toastStack: 'veer-toast-stack',
        toast: 'veer-toast',
        button: 'veer-button',
        secondaryButton: 'veer-button secondary',
        badge: 'veer-badge',
        table: 'veer-table',
        field: 'veer-field',
        input: 'veer-input'
      }
    };
    return `
(function () {
  var host = ${JSON.stringify(host).replace(/</g, '\\u003c')};
  var resizeTimer = 0;
  var currentLocale = normalizeLocale(host.locale);
  var localeListeners = [];
  function append(parent, children) {
    (Array.isArray(children) ? children : [children]).forEach(function (child) {
      if (child == null || child === false) return;
      parent.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    });
  }
  function tableCell(tag, text) {
    return host.h(tag, { text: text == null || text === '' ? '-' : String(text) });
  }
  function normalizeLocale(locale) {
    return locale === 'en-US' ? 'en-US' : 'zh-CN';
  }
  function formatText(text, params) {
    text = text == null ? '' : String(text);
    if (!params) return text;
    return text.replace(/\\{\\{(\\w+)\\}\\}/g, function (_, name) {
      if (!Object.prototype.hasOwnProperty.call(params, name)) return '';
      return params[name] == null ? '' : String(params[name]);
    });
  }
  function updateLocale(locale) {
    var next = normalizeLocale(locale);
    if (next === currentLocale) return;
    currentLocale = next;
    if (document && document.documentElement) document.documentElement.lang = currentLocale;
    localeListeners.slice().forEach(function (listener) {
      try {
        listener(currentLocale);
      } catch (e) {
        console.error('plugin locale listener failed:', e);
      }
    });
    scheduleHeight();
  }
  function measureHeight() {
    var body = document.body;
    if (!body) return 160;
    var bodyRect = body.getBoundingClientRect ? body.getBoundingClientRect() : { top: 0, height: 0 };
    var bottom = 0;
    var children = body.children || [];
    for (var i = 0; i < children.length; i++) {
      var child = children[i];
      if (!child || !child.getBoundingClientRect) continue;
      var rect = child.getBoundingClientRect();
      bottom = Math.max(bottom, rect.bottom - bodyRect.top);
    }
    var paddingBottom = 0;
    if (window.getComputedStyle) {
      var style = window.getComputedStyle(body);
      paddingBottom = parseFloat(style && style.paddingBottom || '0') || 0;
    }
    return Math.max(Math.ceil(bottom + paddingBottom), 160);
  }
  function postHeight() {
    if (!window.parent || window.parent === window) return;
    window.parent.postMessage({
      type: 'veer-plugin-ui-height',
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
  var rpcEpoch = Date.now().toString(36) + ':' + Math.random().toString(36).slice(2);
  var pendingRPC = Object.create(null);
  var pendingRPCCount = 0;
  var pendingRPCBytes = 0;
  function utf8ByteLength(value) {
    value = String(value == null ? '' : value);
    var bytes = 0;
    for (var i = 0; i < value.length; i++) {
      var code = value.charCodeAt(i);
      if (code < 0x80) bytes += 1;
      else if (code < 0x800) bytes += 2;
      else if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    }
    return bytes;
  }
  function rpcError(message, status) {
    var error = new Error(message);
    error.status = status || 0;
    return error;
  }
  function releasePendingRPC(id) {
    var pending = pendingRPC[id];
    if (!pending) return null;
    delete pendingRPC[id];
    pendingRPCCount = Math.max(0, pendingRPCCount - 1);
    pendingRPCBytes = Math.max(0, pendingRPCBytes - pending.bytes);
    if (pending.timeout) window.clearTimeout(pending.timeout);
    return pending;
  }
  function rpc(op, payload) {
    if (!window.parent || window.parent === window) {
      return Promise.reject(new Error('plugin host bridge is unavailable'));
    }
    payload = payload || {};
    var encoded;
    try {
      encoded = JSON.stringify({ op: op, payload: payload });
    } catch (error) {
      return Promise.reject(rpcError('plugin host request must be JSON serializable', 400));
    }
    var bytes = utf8ByteLength(encoded);
    if (bytes > host.rpcLimits.max_payload_bytes) {
      return Promise.reject(rpcError('plugin host request exceeds the payload limit', 413));
    }
    if (pendingRPCCount >= host.rpcLimits.max_inflight || pendingRPCBytes + bytes > host.rpcLimits.max_pending_bytes) {
      return Promise.reject(rpcError('plugin host request queue is full', 429));
    }
    var id = host.pluginId + ':' + rpcEpoch + ':' + (++rpcSeq);
    return new Promise(function (resolve, reject) {
      var timeout = window.setTimeout(function () {
        var pending = releasePendingRPC(id);
        if (!pending) return;
        pending.reject(rpcError('plugin host request timed out', 504));
      }, 30000);
      pendingRPC[id] = { resolve: resolve, reject: reject, timeout: timeout, bytes: bytes };
      pendingRPCCount++;
      pendingRPCBytes += bytes;
      try {
        window.parent.postMessage({
          type: 'veer-plugin-rpc',
          pluginId: host.pluginId,
          id: id,
          op: op,
          payload: payload
        }, '*');
      } catch (error) {
        releasePendingRPC(id);
        reject(error);
      }
    });
  }
  window.addEventListener('message', function (event) {
    if (!window.parent || event.source !== window.parent) return;
    var data = event && event.data && typeof event.data === 'object' ? event.data : null;
    if (data && data.type === 'veer-plugin-locale' && data.pluginId === host.pluginId) {
      updateLocale(data.locale);
      return;
    }
    if (!data || data.type !== 'veer-plugin-rpc-result' || data.pluginId !== host.pluginId || !data.id) return;
    var pending = releasePendingRPC(data.id);
    if (!pending) return;
    if (data.ok) {
      pending.resolve(data.result);
    } else {
      var error = new Error(data.error || 'plugin host request failed');
      error.payload = data.error_payload || null;
      error.status = data.status || 0;
      if (error.payload && typeof error.payload === 'object') {
        error.runtime_status = error.payload.runtime_status || null;
        error.runtime_error = error.payload.runtime_error || '';
      }
      pending.reject(error);
    }
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
  host.setButtonState = function (button, state) {
    if (!button) return button;
    state = state || {};
    var busy = state.busy === true;
    var disabled = busy || state.disabled === true;
    var busyWidth = 0;
    if (busy && button.dataset && !button.dataset.veerBusyWidth && typeof button.getBoundingClientRect === 'function') {
      busyWidth = Math.ceil(Number(button.getBoundingClientRect().width) || 0);
    }
    if (state.label != null) button.textContent = String(state.label);
    if (button.dataset) {
      if (busy && !button.dataset.veerBusyWidth && busyWidth > 0) {
        button.dataset.veerBusyWidth = String(busyWidth);
        if (button.style) button.style.minWidth = busyWidth + 'px';
      } else if (!busy && button.dataset.veerBusyWidth) {
        delete button.dataset.veerBusyWidth;
        if (button.style) button.style.minWidth = '';
      }
      button.dataset.state = String(state.state || (busy ? 'busy' : (disabled ? 'disabled' : 'ready')));
    }
    button.disabled = disabled;
    button.hidden = state.hidden === true;
    button.title = state.title == null ? '' : String(state.title);
    if (typeof button.setAttribute === 'function') {
      button.setAttribute('aria-busy', busy ? 'true' : 'false');
      button.setAttribute('aria-disabled', disabled ? 'true' : 'false');
    }
    function toggleClass(name, enabled) {
      if (button.classList && typeof button.classList.toggle === 'function') {
        button.classList.toggle(name, enabled);
        return;
      }
      var classes = String(button.className || '').split(/\\s+/).filter(Boolean).filter(function (item) { return item !== name; });
      if (enabled) classes.push(name);
      button.className = classes.join(' ');
    }
    toggleClass('is-busy', busy);
    toggleClass('is-danger', state.tone === 'danger');
    return button;
  };
  host.badge = function (text, title) {
    return host.h('span', { className: host.classes.badge, text: text, title: title || '' });
  };
  host.status = function (text) {
    return host.h('span', { className: host.classes.status, text: text || '' });
  };
  Object.defineProperty(host, 'locale', {
    enumerable: true,
    get: function () {
      return currentLocale;
    }
  });
  host.t = function (messages, key, params) {
    key = String(key == null ? '' : key);
    if (!messages || typeof messages !== 'object') return formatText(key, params);
    var dict = messages[currentLocale] && typeof messages[currentLocale] === 'object' ? messages[currentLocale] : null;
    var fallback = messages['en-US'] && typeof messages['en-US'] === 'object'
      ? messages['en-US']
      : (messages['zh-CN'] && typeof messages['zh-CN'] === 'object' ? messages['zh-CN'] : {});
    var text = dict && Object.prototype.hasOwnProperty.call(dict, key) ? dict[key]
      : (fallback && Object.prototype.hasOwnProperty.call(fallback, key) ? fallback[key] : key);
    return formatText(text, params);
  };
  host.onLocaleChange = function (callback) {
    if (typeof callback !== 'function') return function () {};
    localeListeners.push(callback);
    return function unsubscribe() {
      localeListeners = localeListeners.filter(function (item) { return item !== callback; });
    };
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
  host.errorText = function (error, fallback) {
    if (!error) return fallback || 'Unknown error';
    if (typeof error === 'string') return error;
    var payload = error.payload && typeof error.payload === 'object' ? error.payload : null;
    var runtimeStatus = error.runtime_status || (payload && payload.runtime_status) || null;
    var message = error.runtime_error || (payload && payload.runtime_error) || '';
    if (!message && runtimeStatus && typeof runtimeStatus === 'object') {
      message = runtimeStatus.last_error || runtimeStatus.error || '';
    }
    if (!message && payload) message = payload.error || payload.message || '';
    if (!message && error.message) message = error.message;
    if (!message) message = String(error);
    return String(message || fallback || 'Unknown error');
  };
  host.toastError = function (error, timeout) {
    return host.toast(host.errorText(error), timeout || 4200);
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
  host.recordPicker = function (options) {
    options = options || {};
    var newValue = options.newValue || '__veer_new_record__';
    var keys = [];
    var listeners = [];
    var select = host.h('select', { className: host.classes.input });
    var input = host.h('input', {
      className: host.classes.input,
      attrs: { type: 'text', placeholder: labelValue(options.newPlaceholder) }
    });
    var root = host.h('div', { className: 'veer-record-picker' }, [select, input]);

    function labelValue(value) {
      return typeof value === 'function' ? String(value() || '') : String(value || '');
    }
    function uniqueKeys(values) {
      var seen = {};
      return (Array.isArray(values) ? values : []).map(function (value) {
        return String(value == null ? '' : value).trim();
      }).filter(function (value) {
        if (!value || value === newValue || seen[value]) return false;
        seen[value] = true;
        return true;
      }).sort();
    }
    function render(selected, forceNew) {
      selected = String(selected == null ? '' : selected).trim();
      select.replaceChildren();
      keys.forEach(function (key) {
        select.appendChild(host.h('option', { text: key, attrs: { value: key } }));
      });
      select.appendChild(host.h('option', {
        text: labelValue(options.newLabel) || 'New...',
        attrs: { value: newValue }
      }));
      if (!forceNew && selected && keys.indexOf(selected) >= 0) {
        select.value = selected;
        input.value = selected;
        input.hidden = true;
      } else {
        select.value = newValue;
        input.value = selected || labelValue(options.defaultKey);
        input.hidden = false;
      }
      scheduleHeight();
    }
    function notifyChange() {
      var detail = { key: api.value(), isNew: api.isNew() };
      listeners.slice().forEach(function (listener) { listener(detail); });
      scheduleHeight();
    }
    select.addEventListener('change', function () {
      if (select.value === newValue) {
        input.value = '';
        input.hidden = false;
        input.focus();
      } else {
        input.value = select.value;
        input.hidden = true;
      }
      notifyChange();
    });
    input.addEventListener('input', scheduleHeight);

    var api = {
      element: root,
      select: select,
      input: input,
      value: function () {
        return select.value === newValue ? input.value.trim() : String(select.value || '').trim();
      },
      isNew: function () { return select.value === newValue; },
      keys: function () { return keys.slice(); },
      setKeys: function (values, selected, forceNew) {
        keys = uniqueKeys(values);
        render(selected, forceNew === true);
      },
      selectKey: function (key) {
        key = String(key == null ? '' : key).trim();
        render(key, keys.indexOf(key) < 0);
      },
      resetNew: function (suggestedKey) {
        render(String(suggestedKey || ''), true);
      },
      refreshLabels: function () {
        input.placeholder = labelValue(options.newPlaceholder);
        render(api.value(), api.isNew());
      },
      onChange: function (listener) {
        if (typeof listener === 'function') listeners.push(listener);
        return api;
      }
    };
    render(labelValue(options.defaultKey), true);
    return api;
  };
  host.collectionEditor = function (options) {
    options = options || {};
    var columns = Array.isArray(options.columns) ? options.columns : [];
    var entries = [];
    var rows = host.h('div', { className: 'veer-collection-rows' });
    var empty = host.h('p', { className: 'veer-collection-empty' });
    var addButton = host.button('', function () { add({}); }, true);
    var root = host.h('div', { className: 'veer-collection-editor' }, [
      rows,
      empty,
      host.h('div', { className: 'veer-collection-actions' }, [addButton])
    ]);

    function labelValue(value) {
      return typeof value === 'function' ? String(value() || '') : String(value || '');
    }
    function updateEmpty() {
      empty.hidden = entries.length > 0;
      empty.textContent = labelValue(options.emptyLabel) || 'No entries.';
      addButton.textContent = labelValue(options.addLabel) || 'Add';
      scheduleHeight();
    }
    function add(value) {
      value = value && typeof value === 'object' ? value : {};
      var inputs = {};
      var fields = columns.map(function (column) {
        var attrs = {
          type: column.type || 'text',
          value: value[column.key] == null ? '' : value[column.key],
          placeholder: labelValue(column.placeholder),
          'aria-label': labelValue(column.label) || column.key
        };
        ['min', 'max', 'step', 'inputmode'].forEach(function (name) {
          if (column[name] != null) attrs[name] = column[name];
        });
        var input = host.h('input', { className: host.classes.input, attrs: attrs });
        inputs[column.key] = input;
        return host.h('label', {
          className: 'veer-collection-field' + (column.wide ? ' wide' : '')
        }, [
          host.h('span', { text: labelValue(column.label) || column.key, title: labelValue(column.label) || column.key }),
          input
        ]);
      });
      var remove = host.button(labelValue(options.removeText) || 'x', null, true);
      remove.className += ' veer-collection-remove';
      remove.title = labelValue(options.removeLabel) || 'Remove';
      remove.setAttribute('aria-label', remove.title);
      var row = host.h('div', { className: 'veer-collection-row' }, fields.concat([remove]));
      var entry = { row: row, inputs: inputs, original: Object.assign({}, value), labels: fields, remove: remove };
      remove.addEventListener('click', function () {
        entries = entries.filter(function (item) { return item !== entry; });
        if (row.parentNode) row.parentNode.removeChild(row);
        updateEmpty();
      });
      entries.push(entry);
      rows.appendChild(row);
      updateEmpty();
      return entry;
    }
    function values() {
      return entries.map(function (entry) {
        var out = Object.assign({}, entry.original);
        var populated = false;
        columns.forEach(function (column) {
          var raw = String(entry.inputs[column.key].value == null ? '' : entry.inputs[column.key].value).trim();
          if (!raw) {
            delete out[column.key];
            return;
          }
          populated = true;
          out[column.key] = column.type === 'number' ? Number(raw) : raw;
        });
        return populated ? out : null;
      }).filter(Boolean);
    }
    function setValues(next) {
      entries = [];
      rows.replaceChildren();
      (Array.isArray(next) ? next : []).forEach(add);
      updateEmpty();
    }
    function refreshLabels() {
      entries.forEach(function (entry) {
        columns.forEach(function (column, index) {
          var label = labelValue(column.label) || column.key;
          var span = entry.labels[index] && entry.labels[index].querySelector('span');
          if (span) {
            span.textContent = label;
            span.title = label;
          }
          entry.inputs[column.key].placeholder = labelValue(column.placeholder);
          entry.inputs[column.key].setAttribute('aria-label', label);
        });
        entry.remove.textContent = labelValue(options.removeText) || 'x';
        entry.remove.title = labelValue(options.removeLabel) || 'Remove';
        entry.remove.setAttribute('aria-label', entry.remove.title);
      });
      updateEmpty();
    }
    var api = {
      element: root,
      add: add,
      setValues: setValues,
      values: values,
      refreshLabels: refreshLabels,
      count: function () { return entries.length; }
    };
    updateEmpty();
    return api;
  };
  host.data = Object.freeze({
    list: function (resource, options) {
      options = options || {};
      return rpc('data.list', { resource: resource, limit: options.limit, offset: options.offset });
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
    upsert: function (resource, key, data, options) {
      options = options || {};
      return host.data.update(resource, key, data, options).catch(function (error) {
        if (!error || error.status !== 404) throw error;
        return host.data.create(resource, data, Object.assign({}, options, { key: key }));
      });
    },
    delete: function (resource, key) {
      return rpc('data.delete', { resource: resource, key: key });
    }
  });
  host.plugins = Object.freeze({
    resources: Object.freeze({
      list: function (plugin, resource, options) {
        options = options || {};
        return rpc('plugins.resources.list', {
          plugin: plugin,
          resource: resource,
          limit: options.limit,
          offset: options.offset
        });
      },
      get: function (plugin, resource, key) {
        return rpc('plugins.resources.get', { plugin: plugin, resource: resource, key: key });
      }
    })
  });
  function appendAssetElement(element) {
    var parent = document.head || document.body || document.documentElement;
    if (!parent || !parent.appendChild) throw new Error('plugin document cannot attach an asset');
    parent.appendChild(element);
    scheduleHeight();
    return element;
  }
  host.assets = Object.freeze({
    text: function (path) {
      return rpc('asset.text', { path: path });
    },
    json: function (path) {
      return rpc('asset.json', { path: path });
    },
    style: function (path, options) {
      options = options || {};
      return rpc('asset.style', { path: path }).then(function (source) {
        var element = document.createElement('style');
        element.setAttribute('data-veer-plugin-asset', String(path));
        if (options.media) element.setAttribute('media', String(options.media));
        element.textContent = String(source || '');
        return appendAssetElement(element);
      });
    },
    script: function (path) {
      return rpc('asset.script', { path: path }).then(function (source) {
        var element = document.createElement('script');
        element.setAttribute('data-veer-plugin-asset', String(path));
        element.textContent = String(source || '') + '\\n//# sourceURL=veer-plugin://' + host.pluginId + '/' + String(path);
        return appendAssetElement(element);
      });
    },
    dataURL: function (path) {
      return rpc('asset.data_url', { path: path });
    }
  });
  host.action = function (name, payload) {
    return rpc('action', { action: name, payload: payload || {} });
  };
  host.requestResize = scheduleHeight;
  window.VeerPluginHost = Object.freeze(host);
  if (document && document.documentElement) document.documentElement.lang = currentLocale;
  document.addEventListener('DOMContentLoaded', function () {
    document.body.classList.add('veer-plugin-body');
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

  const pluginFrameSandbox = 'allow-scripts';
  const pluginFrameCSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data: blob:; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; manifest-src 'none'; form-action 'none'; base-uri 'none'";
  const pluginFrameCSPAttribute = pluginFrameCSP.replace(/&/g, '&amp;').replace(/"/g, '&quot;');

  function decoratePluginHTML(html, plugin) {
    const securityPrefix = [
      '<meta http-equiv="Content-Security-Policy" content="' + pluginFrameCSPAttribute + '">',
      '<meta name="referrer" content="no-referrer">'
    ].join('');
    const injection = [
      '<style data-veer-plugin-host>',
      pluginHostComponentCSS(),
      '</style>',
      '<script data-veer-plugin-host>',
      pluginHostComponentJS(plugin).replace(/<\/script/gi, '<\\/script'),
      '</script>'
    ].join('');
    let decorated;
    if (/<head(\s[^>]*)?>/i.test(html)) {
      decorated = html.replace(/<head(\s[^>]*)?>/i, (match) => match + injection);
    } else if (/<html(\s[^>]*)?>/i.test(html)) {
      decorated = html.replace(/<html(\s[^>]*)?>/i, (match) => match + '<head>' + injection + '</head>');
    } else {
      decorated = '<head>' + injection + '</head>' + html;
    }
    const doctype = decorated.match(/^(\uFEFF?\s*<!doctype[^>]*>)/i);
    if (doctype) {
      return doctype[1] + securityPrefix + decorated.slice(doctype[1].length);
    }
    return securityPrefix + decorated;
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
    const entryPath = normalizePluginUIAssetPath(entry);
    const url = basePath + entryPath.encoded;
    const resp = await fetch(url, {
      headers: { Authorization: 'Bearer ' + app.getToken() }
    });
    if (resp.status === 401) {
      app.clearToken();
      app.showTokenModal();
      throw new Error('unauthorized');
    }
    if (!resp.ok) throw new Error(resp.statusText || String(resp.status));
    const raw = await resp.text();
    return decoratePluginHTML(raw, plugin);
  }

  function preparePluginFrame(iframe, plugin, entry) {
    if (!iframe) return;
    pluginFrameRPCStates.delete(iframe);
    securePluginFrame(iframe);
    iframe.style.height = '';
    if (iframe.dataset) {
      iframe.dataset.pluginFrame = '1';
      iframe.dataset.pluginId = plugin && plugin.id || '';
      iframe.dataset.pluginEntry = entry || '';
    }
    iframe.onload = function () {
      postPluginFrameLocale(iframe);
    };
  }

  function securePluginFrame(iframe) {
    if (!iframe || typeof iframe.setAttribute !== 'function') return;
    iframe.setAttribute('sandbox', pluginFrameSandbox);
    iframe.setAttribute('referrerpolicy', 'no-referrer');
    iframe.setAttribute('csp', pluginFrameCSP);
    iframe.setAttribute('allow', "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'; usb 'none'; serial 'none'; bluetooth 'none'; clipboard-read 'none'; clipboard-write 'none'");
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

  function currentPluginLocale() {
    const locale = app.state && app.state.locale ? app.state.locale : 'zh-CN';
    return typeof app.normalizeLocale === 'function' ? app.normalizeLocale(locale) : (locale === 'en-US' ? 'en-US' : 'zh-CN');
  }

  function postPluginFrameLocale(iframe) {
    if (!iframe || !iframe.contentWindow || !iframe.dataset) return;
    const pluginId = iframe.dataset.pluginId || '';
    if (!pluginId) return;
    try {
      iframe.contentWindow.postMessage({
        type: 'veer-plugin-locale',
        pluginId,
        locale: currentPluginLocale()
      }, '*');
    } catch (e) {
      console.error('plugin locale message:', e);
    }
  }

  function postAllPluginFrameLocales() {
    if (typeof document.querySelectorAll !== 'function') return;
    Array.from(document.querySelectorAll('iframe[data-plugin-frame="1"]')).forEach(postPluginFrameLocale);
  }

  function postPluginRPCResult(source, pluginId, id, ok, result, error, errorPayload, status) {
    if (!source || !id) return;
    try {
      source.postMessage({
        type: 'veer-plugin-rpc-result',
        pluginId: pluginId || '',
        id,
        ok: !!ok,
        result: ok ? result : undefined,
        error: ok ? undefined : (error || 'plugin request failed'),
        error_payload: ok ? undefined : (errorPayload || null),
        status: ok ? undefined : (status || 0)
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

  function pluginUTF8ByteLength(value) {
    value = String(value == null ? '' : value);
    let bytes = 0;
    for (let i = 0; i < value.length; i++) {
      const code = value.charCodeAt(i);
      if (code < 0x80) bytes += 1;
      else if (code < 0x800) bytes += 2;
      else if (code >= 0xd800 && code <= 0xdbff && i + 1 < value.length && value.charCodeAt(i + 1) >= 0xdc00 && value.charCodeAt(i + 1) <= 0xdfff) {
        bytes += 4;
        i++;
      } else bytes += 3;
    }
    return bytes;
  }

  function pluginRPCFailure(message, status, code) {
    const error = new Error(message);
    error.status = status || 0;
    error.payload = { error: message, code: code || 'plugin_ui_rpc_error' };
    return error;
  }

  function pluginFrameRPCState(frame) {
    let state = pluginFrameRPCStates.get(frame);
    if (!state) {
      state = { inflight: 0, pendingBytes: 0, ids: new Set(), calls: [] };
      pluginFrameRPCStates.set(frame, state);
    }
    return state;
  }

  function admitPluginFrameRPC(frame, data) {
    let encoded;
    try {
      encoded = JSON.stringify({ op: data.op, payload: data.payload || {} });
    } catch (error) {
      throw pluginRPCFailure('plugin UI request must be JSON serializable', 400, 'plugin_ui_rpc_invalid');
    }
    const bytes = pluginUTF8ByteLength(encoded);
    if (bytes > pluginUIRPCMaxPayloadBytes) {
      throw pluginRPCFailure('plugin UI request exceeds the payload limit', 413, 'plugin_ui_rpc_payload_limit');
    }
    const state = pluginFrameRPCState(frame);
    if (state.ids.has(data.id)) {
      throw pluginRPCFailure('duplicate plugin UI request id', 409, 'plugin_ui_rpc_duplicate');
    }
    const now = Date.now();
    state.calls = state.calls.filter((at) => now - at < pluginUIRPCRateWindowMs);
    if (state.calls.length >= pluginUIRPCRateLimit) {
      throw pluginRPCFailure('plugin UI request rate limit reached', 429, 'plugin_ui_rpc_rate_limit');
    }
    if (state.inflight >= pluginUIRPCMaxInflight || state.pendingBytes + bytes > pluginUIRPCMaxPendingBytes) {
      throw pluginRPCFailure('plugin UI request queue is full', 429, 'plugin_ui_rpc_queue_full');
    }
    state.calls.push(now);
    state.inflight++;
    state.pendingBytes += bytes;
    state.ids.add(data.id);
    let released = false;
    return function release() {
      if (released) return;
      released = true;
      state.inflight = Math.max(0, state.inflight - 1);
      state.pendingBytes = Math.max(0, state.pendingBytes - bytes);
      state.ids.delete(data.id);
    };
  }

  function normalizePluginUIAssetPath(value) {
    const assetPath = pluginRPCString(value, 'asset path');
    if (assetPath.length > 1024 || assetPath.includes('\\') || assetPath.startsWith('/') || /[\u0000-\u001f\u007f]/.test(assetPath)) {
      throw pluginRPCFailure('asset path must be a bounded plugin-relative path', 400, 'plugin_ui_asset_path');
    }
    const segments = assetPath.split('/');
    if (segments.some((segment) => !segment || segment === '.' || segment === '..')) {
      throw pluginRPCFailure('asset path must not contain empty or traversal segments', 400, 'plugin_ui_asset_path');
    }
    return {
      value: assetPath,
      encoded: segments.map((segment) => encodeURIComponent(segment)).join('/'),
      extension: segments[segments.length - 1].toLowerCase().split('.').pop()
    };
  }

  function pluginUIAssetMIME(response) {
    return String(response.headers && response.headers.get ? response.headers.get('Content-Type') || '' : '')
      .split(';')[0].trim().toLowerCase();
  }

  function pluginUIAssetTypeAllowed(op, mime, extension) {
    if (op === 'asset.text') {
      return mime.startsWith('text/') || ['json', 'js', 'mjs', 'css', 'svg', 'xml'].includes(extension) ||
        ['application/json', 'application/javascript', 'application/xml', 'image/svg+xml'].includes(mime);
    }
    if (op === 'asset.json') return extension === 'json' && (!mime || mime === 'application/json' || mime === 'text/json' || mime === 'text/plain');
    if (op === 'asset.style') return extension === 'css' && (!mime || mime === 'text/css' || mime === 'text/plain');
    if (op === 'asset.script') {
      return ['js', 'mjs'].includes(extension) && (!mime || ['text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript', 'text/plain'].includes(mime));
    }
    if (op === 'asset.data_url') return mime.startsWith('image/');
    return false;
  }

  function pluginUIAssetContentLength(response) {
    const raw = String(response.headers && response.headers.get ? response.headers.get('Content-Length') || '' : '').trim();
    if (!/^\d+$/.test(raw)) return 0;
    return Number(raw);
  }

  function pluginArrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      const chunk = bytes.subarray(offset, Math.min(offset + 32768, bytes.length));
      for (let i = 0; i < chunk.length; i++) binary += String.fromCharCode(chunk[i]);
    }
    return btoa(binary);
  }

  async function fetchPluginUIAsset(pluginId, op, rawPath) {
    const plugin = (app.state.plugins.data || []).find((item) => item && item.id === pluginId);
    const expectedBase = '/api/plugins/' + encodeURIComponent(pluginId) + '/assets/';
    const basePath = String(plugin && plugin.asset_base_path || '').trim();
    if (!plugin || basePath !== expectedBase) {
      throw pluginRPCFailure('plugin UI assets are unavailable', 404, 'plugin_ui_asset_unavailable');
    }
    const assetPath = normalizePluginUIAssetPath(rawPath);
    const response = await fetch(basePath + assetPath.encoded, {
      headers: { Authorization: 'Bearer ' + app.getToken() }
    });
    if (response.status === 401) {
      app.clearToken();
      app.showTokenModal();
      throw pluginRPCFailure('unauthorized', 401, 'unauthorized');
    }
    if (!response.ok) {
      throw pluginRPCFailure(response.statusText || 'plugin UI asset request failed', response.status || 500, 'plugin_ui_asset_fetch');
    }
    const mime = pluginUIAssetMIME(response);
    if (!pluginUIAssetTypeAllowed(op, mime, assetPath.extension)) {
      throw pluginRPCFailure('plugin UI asset type is not allowed for ' + op, 415, 'plugin_ui_asset_type');
    }
    const maxBytes = op === 'asset.data_url' ? pluginUIAssetDataMaxBytes : pluginUIAssetTextMaxBytes;
    const contentLength = pluginUIAssetContentLength(response);
    if (contentLength > maxBytes) {
      throw pluginRPCFailure('plugin UI asset exceeds the size limit', 413, 'plugin_ui_asset_size');
    }
    if (op === 'asset.data_url') {
      if (typeof response.arrayBuffer !== 'function') {
        throw pluginRPCFailure('plugin UI asset response is not readable', 500, 'plugin_ui_asset_response');
      }
      const buffer = await response.arrayBuffer();
      if (buffer.byteLength > maxBytes) {
        throw pluginRPCFailure('plugin UI asset exceeds the size limit', 413, 'plugin_ui_asset_size');
      }
      return 'data:' + mime + ';base64,' + pluginArrayBufferToBase64(buffer);
    }
    const source = await response.text();
    if (pluginUTF8ByteLength(source) > maxBytes) {
      throw pluginRPCFailure('plugin UI asset exceeds the size limit', 413, 'plugin_ui_asset_size');
    }
    if (op === 'asset.json') {
      try {
        return JSON.parse(source);
      } catch (error) {
        throw pluginRPCFailure('plugin UI JSON asset is invalid', 422, 'plugin_ui_asset_json');
      }
    }
    return source;
  }

  function pluginUIByID(pluginID) {
    return (app.state.plugins.data || []).find((plugin) => plugin && plugin.id === pluginID) || null;
  }

  function pluginUIOwnResourceMethods(plugin, resourceID) {
    const ui = plugin && plugin.ui && typeof plugin.ui === 'object' ? plugin.ui : null;
    const grants = ui && Array.isArray(ui.resources) ? ui.resources : [];
    const grant = grants.find((item) => item && item.resource === resourceID);
    const resources = Array.isArray(plugin && plugin.resources) ? plugin.resources : [];
    const resource = resources.find((item) => item && item.id === resourceID);
    const exposed = resource && Array.isArray(resource.methods) ? resource.methods : [];
    return grant && Array.isArray(grant.methods) ? grant.methods.filter((method) => exposed.includes(method)) : [];
  }

  function pluginUIOwnResourceAccessAllowed(pluginID, resourceID, method) {
    return pluginUIOwnResourceMethods(pluginUIByID(pluginID), resourceID).includes(method);
  }

  function pluginUIActionAccessAllowed(pluginID, actionID) {
    const plugin = pluginUIByID(pluginID);
    const ui = plugin && plugin.ui && typeof plugin.ui === 'object' ? plugin.ui : null;
    const registered = Array.isArray(plugin && plugin.actions) ? plugin.actions : [];
    return !!(ui && Array.isArray(ui.actions) && ui.actions.includes(actionID) &&
      registered.some((action) => action && action.id === actionID));
  }

  function pluginUICrossResourceAccessAllowed(sourcePluginID, targetPluginID, resourceID, method) {
    const source = pluginUIByID(sourcePluginID);
    const ui = source && source.ui && typeof source.ui === 'object' ? source.ui : null;
    const uiGrants = ui && Array.isArray(ui.resource_access) ? ui.resource_access : [];
    const uiAllowed = uiGrants.some((grant) => {
      if (!grant || grant.plugin !== targetPluginID || grant.resource !== resourceID) return false;
      return Array.isArray(grant.methods) && grant.methods.includes(method);
    });
    if (!uiAllowed) return false;
    const target = pluginUIByID(targetPluginID);
    const targetResources = Array.isArray(target && target.resources) ? target.resources : [];
    const targetResource = targetResources.find((resource) => resource && resource.id === resourceID);
    if (!targetResource || !Array.isArray(targetResource.methods) || !targetResource.methods.includes(method)) return false;
    const control = source && source.control && typeof source.control === 'object' ? source.control : null;
    const grants = control && Array.isArray(control.resource_access) ? control.resource_access : [];
    return grants.some((grant) => {
      if (!grant || grant.plugin !== targetPluginID || grant.resource !== resourceID) return false;
      return Array.isArray(grant.methods) && grant.methods.includes(method);
    });
  }

  async function callPluginRPCAPI(pluginId, op, payload) {
    payload = payload && typeof payload === 'object' ? payload : {};
    const id = encodeURIComponent(pluginRPCString(pluginId, 'plugin id'));
    if (op === 'asset.text' || op === 'asset.json' || op === 'asset.style' || op === 'asset.script' || op === 'asset.data_url') {
      return fetchPluginUIAsset(pluginId, op, payload.path);
    }
    const resourceText = payload.resource != null ? pluginRPCString(payload.resource, 'resource') : '';
    const resource = resourceText ? encodeURIComponent(resourceText) : '';
    const key = payload.key != null && payload.key !== '' ? encodeURIComponent(pluginRPCString(payload.key, 'key')) : '';
    if (op === 'data.list') {
      if (!pluginUIOwnResourceAccessAllowed(pluginId, resourceText, 'list')) {
        throw pluginRPCFailure('plugin UI resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      const query = [];
      if (payload.limit != null && payload.limit !== '') query.push('limit=' + encodeURIComponent(String(payload.limit)));
      if (payload.offset != null && payload.offset !== '') query.push('offset=' + encodeURIComponent(String(payload.offset)));
      return app.apiCall('GET', '/api/plugins/' + id + '/resources/' + resource + (query.length ? '?' + query.join('&') : ''));
    }
    if (op === 'data.get') {
      if (!pluginUIOwnResourceAccessAllowed(pluginId, resourceText, 'get')) {
        throw pluginRPCFailure('plugin UI resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      if (!key) throw new Error('key is required');
      return app.apiCall('GET', '/api/plugins/' + id + '/resources/' + resource + '/' + key);
    }
    if (op === 'data.create') {
      if (!pluginUIOwnResourceAccessAllowed(pluginId, resourceText, 'create')) {
        throw pluginRPCFailure('plugin UI resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      const body = { data: payload.data };
      if (payload.key != null && payload.key !== '') body.key = payload.key;
      if (payload.enabled != null) body.enabled = !!payload.enabled;
      return app.apiCall('POST', '/api/plugins/' + id + '/resources/' + resource, body);
    }
    if (op === 'data.update') {
      if (!pluginUIOwnResourceAccessAllowed(pluginId, resourceText, 'update')) {
        throw pluginRPCFailure('plugin UI resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      if (!key) throw new Error('key is required');
      const body = { data: payload.data };
      if (payload.enabled != null) body.enabled = !!payload.enabled;
      return app.apiCall('PUT', '/api/plugins/' + id + '/resources/' + resource + '/' + key, body);
    }
    if (op === 'data.delete') {
      if (!pluginUIOwnResourceAccessAllowed(pluginId, resourceText, 'delete')) {
        throw pluginRPCFailure('plugin UI resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      if (!key) throw new Error('key is required');
      return app.apiCall('DELETE', '/api/plugins/' + id + '/resources/' + resource + '/' + key);
    }
    if (op === 'plugins.resources.list' || op === 'plugins.resources.get') {
      const targetPluginText = pluginRPCString(payload.plugin, 'target plugin id');
      const targetResourceText = pluginRPCString(payload.resource, 'target resource id');
      const method = op === 'plugins.resources.list' ? 'list' : 'get';
      if (!pluginUICrossResourceAccessAllowed(pluginId, targetPluginText, targetResourceText, method)) {
        throw pluginRPCFailure('plugin UI cross-plugin resource capability denied', 403, 'plugin_ui_capability_denied');
      }
      const targetPlugin = encodeURIComponent(targetPluginText);
      const targetResource = encodeURIComponent(targetResourceText);
      if (method === 'list') {
        const query = [];
        if (payload.limit != null && payload.limit !== '') query.push('limit=' + encodeURIComponent(String(payload.limit)));
        if (payload.offset != null && payload.offset !== '') query.push('offset=' + encodeURIComponent(String(payload.offset)));
        return app.apiCall('GET', '/api/plugins/' + targetPlugin + '/resources/' + targetResource + (query.length ? '?' + query.join('&') : ''));
      }
      const targetKey = encodeURIComponent(pluginRPCString(payload.key, 'target resource key'));
      return app.apiCall('GET', '/api/plugins/' + targetPlugin + '/resources/' + targetResource + '/' + targetKey);
    }
    if (op === 'action') {
      const actionText = pluginRPCString(payload.action, 'action');
      if (!pluginUIActionAccessAllowed(pluginId, actionText)) {
        throw pluginRPCFailure('plugin UI action capability denied', 403, 'plugin_ui_capability_denied');
      }
      const action = encodeURIComponent(actionText);
      return app.apiCall('POST', '/api/plugins/' + id + '/actions/' + action, { payload: payload.payload || {} });
    }
    throw new Error('unsupported plugin operation');
  }

  async function handlePluginFrameRPC(event, frame, data) {
    const pluginId = frame && frame.dataset ? frame.dataset.pluginId : '';
    if (!pluginId || data.pluginId !== pluginId) return;
    if (typeof data.id !== 'string' || data.id.length < 1 || data.id.length > 128) return;
    if (typeof data.op !== 'string' || data.op.length < 1 || data.op.length > 64) return;
    let release;
    try {
      release = admitPluginFrameRPC(frame, data);
      const result = await callPluginRPCAPI(pluginId, data.op, data.payload);
      postPluginRPCResult(event.source, pluginId, data.id, true, result, '');
    } catch (e) {
      postPluginRPCResult(event.source, pluginId, data.id, false, null, e.message || String(e), e.payload || null, e.status || 0);
    } finally {
      if (release) release();
    }
  }

  function handlePluginFrameMessage(event) {
    const data = event && event.data && typeof event.data === 'object' ? event.data : null;
    if (!data) return;
    const frame = findPluginFrameBySource(event.source);
    if (!frame) return;
    if (frame.dataset && data.pluginId && frame.dataset.pluginId && data.pluginId !== frame.dataset.pluginId) return;
    if (data.type === 'veer-plugin-ui-height') {
      setPluginFrameHeight(frame, data.height);
      return;
    }
    if (data.type === 'veer-plugin-rpc') {
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

    const children = [
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
      })
    ];
    children.push(app.createNode('iframe', {
      className: 'plugin-page-frame',
      title: page.title,
      dataset: {
        pluginFrame: '1',
        pluginId: page.pluginID,
        pluginEntry: page.entry
      },
      attrs: { sandbox: pluginFrameSandbox, referrerpolicy: 'no-referrer', csp: pluginFrameCSP }
    }));

    const section = app.createNode('section', {
      className: 'plugin-page-section',
      children
    });
    panel.appendChild(section);
    const linkCard = pluginHasVirtualLinkCard(page.plugin) ? createPluginVirtualLinkCard(page) : null;
    if (linkCard) panel.appendChild(linkCard);
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
      } else {
        updatePluginPageLinkCard(document.getElementById('tab-' + page.tabID), page);
      }
    });

    if (pageIDs.has(app.state.activeTab)) {
      app.activateTab(app.state.activeTab, { persist: false, skipLoad: true });
      app.loadPluginPageForTab(app.state.activeTab);
    }
  }

  function renderPluginCatalogMeta() {
    const el = app.el.pluginsCatalogMeta;
    const catalog = app.state.plugins.catalog || {};
    const runtime = catalog.runtime || {};
    const hotReload = catalog.hot_reload || null;
    syncPluginUpdateButton(hotReload);
    if (!el) return;
    const hotReloadInfo = pluginHotReloadInfo(hotReload);
    const enabled = catalog.external_plugins_enabled !== false;
    const attach = !!runtime.external_dataplane_attach;
    const attachEngines = pluginRuntimeEngineList(runtime.external_dataplane_engines);
    const registrationOnlyEngines = pluginRuntimeEngineList(runtime.registration_only_engines);
    app.clearNode(el);
    const titleParts = [app.t('plugins.catalog.meta', {
      dir: catalog.directory || '',
      enabled: enabled ? app.t('common.yes') : app.t('common.no'),
      attach: attach ? app.t('common.yes') : app.t('common.no')
    })];
    if (hotReload) titleParts.push(app.t('plugins.catalog.hotReloadDetail', { status: hotReloadInfo.detail }));
    el.title = titleParts.join('; ');
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
    const items = [
      pluginMetaItem(app.t('plugins.catalog.dir'), catalog.directory || app.t('common.dash'), 'mono'),
      pluginMetaItem(app.t('plugins.catalog.scan'), enabled ? app.t('common.yes') : app.t('common.no'), enabled ? 'ok' : 'muted'),
      pluginMetaItem(app.t('plugins.catalog.dataplane'), attach ? (attachEngines || app.t('common.yes')) : app.t('common.no'), attach ? 'ok' : 'muted')
    ];
    if (registrationOnlyEngines) {
      items.push(pluginMetaItem(app.t('plugins.catalog.registrationOnly'), registrationOnlyEngines, 'muted', app.t('plugins.catalog.registrationOnlyDetail', { engines: registrationOnlyEngines })));
    }
    if (hotReload) {
      items.push(pluginMetaItem(app.t('plugins.catalog.hotReload'), hotReloadInfo.text, hotReloadInfo.tone, hotReloadInfo.detail));
      items.push(pluginMetaItem(app.t('plugins.catalog.lastCheck'), formatPluginHotReloadTimestamp(hotReload.last_check_at), hotReload.last_check_error ? 'warning' : 'muted'));
      if (hotReload.last_reload_at) {
        items.push(pluginMetaItem(app.t('plugins.catalog.lastReload'), formatPluginHotReloadTimestamp(hotReload.last_reload_at), hotReload.last_reload_error ? 'warning' : 'muted'));
      }
      const appliedHash = hotReload.applied_fingerprint_short_hash || hotReload.fingerprint_short_hash || '';
      if (appliedHash) {
        items.push(pluginMetaItem(app.t('plugins.catalog.appliedFingerprint'), appliedHash, 'mono', hotReload.applied_fingerprint || hotReload.catalog_fingerprint || appliedHash));
      }
      if (hotReload.update_available && hotReload.detected_fingerprint_short_hash) {
        items.push(pluginMetaItem(app.t('plugins.catalog.detectedFingerprint'), hotReload.detected_fingerprint_short_hash, 'warning', hotReload.detected_fingerprint || hotReload.detected_fingerprint_short_hash));
      }
    }
    el.appendChild(app.createNode('div', { className: 'plugin-meta-items', children: items }));
  }

  function pluginMetaItem(label, value, tone, title) {
    return app.createNode('span', {
      className: 'plugin-meta-item' + (tone ? ' is-' + tone : ''),
      title: title || '',
      children: [
        app.createNode('span', { className: 'plugin-meta-item-label', text: label }),
        app.createNode('span', { className: 'plugin-meta-item-value', text: value })
      ]
    });
  }

  function pluginHotReloadInfo(status) {
    const item = status && typeof status === 'object' ? status : null;
    if (!item || item.enabled === false) {
      return {
        text: app.t('plugins.catalog.hotReloadOff'),
        tone: 'muted',
        detail: app.t('plugins.catalog.hotReloadOff')
      };
    }
    const checkError = String(item.last_check_error || '').trim();
    const reloadError = String(item.last_reload_error || '').trim();
    const reloadResult = String(item.last_reload_result || '').trim().toLowerCase();
    const checkResult = String(item.last_check_result || '').trim().toLowerCase();
    if (checkError || reloadError || checkResult === 'error') {
      const detail = reloadError || checkError || app.t('plugins.catalog.hotReloadError');
      return {
        text: app.t('plugins.catalog.hotReloadError'),
        tone: 'warning',
        detail
      };
    }
    if (reloadResult === 'partial') {
      return {
        text: app.t('plugins.catalog.hotReloadPartial'),
        tone: 'warning',
        detail: app.t('plugins.catalog.hotReloadPartial')
      };
    }
    if (item.update_available === true || checkResult === 'update_available') {
      return {
        text: app.t('plugins.catalog.updateAvailable'),
        tone: 'warning',
        detail: app.t('plugins.catalog.updateAvailable')
      };
    }
    if (reloadResult === 'success') {
      return {
        text: app.t('plugins.catalog.hotReloadReloaded'),
        tone: 'ok',
        detail: app.t('plugins.catalog.hotReloadReloaded')
      };
    }
    if (checkResult === 'unchanged' || checkResult === 'success') {
      return {
        text: app.t('plugins.catalog.hotReloadWatching'),
        tone: 'ok',
        detail: app.t('plugins.catalog.hotReloadWatching')
      };
    }
    return {
      text: app.t('plugins.catalog.hotReloadIdle'),
      tone: 'muted',
      detail: app.t('plugins.catalog.hotReloadIdle')
    };
  }

  function syncPluginUpdateButton(status) {
    const button = app.el.applyPluginUpdateBtn;
    const item = status && typeof status === 'object' ? status : {};
    const updates = pendingPluginUpdates(item);
    const available = new Set(updates.map((update) => String(update.plugin_id)));
    const selected = app.state.plugins.selectedUpdateIDs || {};
    Object.keys(selected).forEach((id) => {
      if (!available.has(id)) delete selected[id];
    });
    app.state.plugins.selectedUpdateIDs = selected;
    const selectedIDs = selectedPluginUpdateIDs();
    const applying = app.state.plugins.applyingUpdate === true;
    const visible = selectedIDs.length > 0 || applying;
    if (app.el.pluginUpdateSelectionBar) app.el.pluginUpdateSelectionBar.hidden = !visible;
    if (app.el.pluginUpdateSelectionMeta) {
      app.el.pluginUpdateSelectionMeta.textContent = app.t('plugins.update.selected', { count: selectedIDs.length });
    }
    if (!button) return;
    button.hidden = !visible;
    button.disabled = applying || selectedIDs.length === 0 || app.state.activeRequests > 0;
    button.classList.toggle('is-busy', applying);
    button.setAttribute('aria-busy', applying ? 'true' : 'false');
    button.textContent = app.t(applying ? 'plugins.update.applying' : 'plugins.update.applySelected', { count: selectedIDs.length });
    button.title = selectedIDs.join(', ');
  }

  function formatPluginHotReloadTimestamp(value) {
    const text = String(value || '').trim();
    if (!text) return app.t('common.dash');
    const date = new Date(text);
    if (Number.isNaN(date.getTime())) return text;
    try {
      return new Intl.DateTimeFormat(app.state.locale || undefined, {
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

  function pluginRuntimeEngineList(value) {
    if (!Array.isArray(value)) return '';
    return value
      .map((item) => String(item || '').trim().toUpperCase())
      .filter(Boolean)
      .join('/');
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
    const appliedData = Array.isArray(st.data) ? st.data : [];
    const hotReload = st.catalog && st.catalog.hot_reload;
    const data = pluginRowsWithPendingUpdates(appliedData, hotReload);
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
      const pluginID = String(plugin && plugin.id || '').trim();
      const pending = pluginID && app.isRowPending && app.isRowPending('plugin', pluginID);
      const info = pluginStatusInfo(plugin);
      const detailText = pluginDetailsPlainText(plugin);
      const nameTitle = [
        plugin.source ? app.t('plugins.source') + ': ' + plugin.source : '',
        plugin.description || ''
      ].filter(Boolean).join('\n');
      if (pending) {
        tr.className = 'row-pending';
        tr.setAttribute('aria-busy', 'true');
      }

      tr.appendChild(app.createCell(app.createNode('div', {
        className: 'plugin-identity',
        title: nameTitle,
        children: [
          app.createNode('span', {
            className: 'plugin-identity-name plugin-text-truncate',
            text: plugin.name || plugin.id || app.t('common.dash')
          }),
          plugin.name && plugin.id ? app.createNode('span', {
            className: 'plugin-identity-id stat-mono plugin-text-truncate',
            text: plugin.id
          }) : null
        ].filter(Boolean)
      }), 'plugin-cell-name'));
      tr.appendChild(app.createCell(app.createNode('div', {
        className: 'plugin-status-compact',
        children: [
          app.createStatusBadgeNode(info, ''),
          pluginStabilityBadgeNode(plugin),
          plugin._pendingOnly ? null : app.createNode('button', {
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
      const update = plugin._pendingUpdate;
      const appliedVersion = update && update.applied_version || plugin.version || '';
      const detectedVersion = update && update.detected_version || '';
      const versionText = appliedVersion && detectedVersion && appliedVersion !== detectedVersion
        ? appliedVersion + ' -> ' + detectedVersion
        : (detectedVersion || appliedVersion);
      tr.appendChild(app.createCell(versionText ? app.createNode('span', {
        className: 'plugin-text-truncate',
        text: versionText,
        title: update ? pluginUpdateChoiceTitle(update) : versionText
      }) : app.emptyCellNode('stat-muted'), 'plugin-cell-tight'));
      tr.appendChild(app.createCell(pluginControlsNode(plugin), 'plugin-cell-tight'));
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

  app.togglePluginUpdateSelection = function togglePluginUpdateSelection(pluginId, selected) {
    const id = String(pluginId || '').trim();
    if (!id || app.state.plugins.applyingUpdate) return;
    const updates = pluginUpdateMap(app.state.plugins.catalog && app.state.plugins.catalog.hot_reload);
    if (!updates.has(id)) return;
    app.state.plugins.selectedUpdateIDs = app.state.plugins.selectedUpdateIDs || {};
    if (selected) app.state.plugins.selectedUpdateIDs[id] = true;
    else delete app.state.plugins.selectedUpdateIDs[id];
    app.renderPluginsTable();
  };

  app.applyPluginUpdate = async function applyPluginUpdate() {
    const hotReload = app.state.plugins.catalog && app.state.plugins.catalog.hot_reload;
    const pluginIDs = selectedPluginUpdateIDs();
    if (app.state.plugins.applyingUpdate || !hotReload || pluginIDs.length === 0) return;
    app.state.plugins.applyingUpdate = true;
    app.renderPluginsTable();
    try {
      const resp = await (typeof app.pluginAdminAPICall === 'function' ? app.pluginAdminAPICall : app.apiCall)('POST', '/api/plugins/reload', { plugin_ids: pluginIDs });
      app.state.plugins.catalog = resp || {};
      app.state.plugins.data = Array.isArray(resp && resp.plugins) ? resp.plugins : [];
      app.state.plugins.selectedUpdateIDs = {};
      renderPluginPageTabs();
      app.renderPluginsTable();
      app.notify('success', app.t('plugins.update.appliedSelected', { count: pluginIDs.length }));
    } catch (e) {
      await app.loadPlugins();
      const message = e && e.message ? e.message : String(e);
      app.notify('error', app.t('plugins.update.failed', { message }));
    } finally {
      app.state.plugins.applyingUpdate = false;
      app.renderPluginsTable();
    }
  };

  app.togglePluginEnabled = async function togglePluginEnabled(pluginId, enabled) {
    const id = String(pluginId || '').trim();
    if (!id || id === 'veer_core') return;
    if (app.isRowPending && app.isRowPending('plugin', id)) return;
    const willEnable = !!enabled;
    if (app.setRowPending) app.setRowPending('plugin', id, true);
    app.renderPluginsTable();
    try {
      await (typeof app.pluginAdminAPICall === 'function' ? app.pluginAdminAPICall : app.apiCall)('PUT', '/api/plugins/' + encodeURIComponent(id) + '/state', { enabled: willEnable });
      await app.loadPlugins();
      app.notify('success', app.t(willEnable ? 'toast.enabled' : 'toast.disabled', { item: app.t('noun.plugin') }));
    } catch (e) {
      const message = e && e.message ? e.message : String(e);
      app.notify('error', app.t('errors.operationFailed', { message: message }));
    } finally {
      if (app.setRowPending) app.setRowPending('plugin', id, false);
      app.renderPluginsTable();
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
    if (!opts.force && (panel.dataset.loaded === '1' || panel.dataset.loaded === 'loading')) return;
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
      pluginFrameRPCStates.delete(app.el.pluginUIFrame);
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

  if (app.__enablePluginTests) {
    app.__pluginLinkRowsForTest = pluginVirtualLinkItems;
    app.__createPluginLinkCardForTest = createPluginVirtualLinkCard;
    app.__createPluginTabPanelForTest = createPluginTabPanel;
    app.__decoratePluginHTMLForTest = decoratePluginHTML;
    app.__pluginDetailsPlainTextForTest = pluginDetailsPlainText;
  }

  app.refreshLocalizedUI = (function wrapPluginLocalizedUI(original) {
    return function refreshLocalizedUIWithPlugins() {
      if (typeof original === 'function') original();
      if (typeof app.renderPluginsTable === 'function') app.renderPluginsTable();
      renderPluginPageTabs();
      postAllPluginFrameLocales();
    };
  })(app.refreshLocalizedUI);

  app.handleTabLoad = (function wrapPluginPageTabLoad(original) {
    return function handleTabLoadWithPluginPages(target) {
      if (String(target || '').indexOf('plugin-') === 0) {
        const refresh = typeof original === 'function' ? original(target) : Promise.resolve();
        return Promise.resolve(refresh).then(() => app.loadPluginPageForTab(target));
      }
      if (typeof original === 'function') return original(target);
      return Promise.resolve();
    };
  })(app.handleTabLoad);

  if (document && typeof document.addEventListener === 'function') {
    document.addEventListener('click', (e) => {
      const togglePlugin = e.target.closest && e.target.closest('.btn-toggle-plugin[data-plugin-id]');
      if (togglePlugin) {
        e.preventDefault();
        e.stopPropagation();
        app.togglePluginEnabled(togglePlugin.dataset.pluginId, togglePlugin.dataset.enabled === '1');
        return;
      }
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
    document.addEventListener('change', (e) => {
      const checkbox = e.target.closest && e.target.closest('.plugin-update-checkbox[data-plugin-id]');
      if (!checkbox) return;
      app.togglePluginUpdateSelection(checkbox.dataset.pluginId, checkbox.checked);
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
