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
    if (status === 'disabled') return { badge: 'disabled', text: app.t('plugins.status.disabled') };
    if (status === 'error') return { badge: 'error', text: app.t('plugins.status.error') };
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
              pluginStabilityBadgeNode(item),
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
      hooks.map((hook) => [hook.id, hook.engine, hook.attach, hook.stage, hook.program, hook.mode, Array.isArray(hook.context) ? hook.context.join(' ') : ''].filter(Boolean).join(' ')).join(' '),
      attachments.map((attachment) => [attachment.hook_id, attachment.engine, attachment.attach, attachment.stage, attachment.interface, attachment.program, attachment.status, Array.isArray(attachment.context) ? attachment.context.join(' ') : '', String(attachment.chain_slot || ''), String(attachment.priority || '')].filter(Boolean).join(' ')).join(' '),
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
      attachments.forEach((attachment) => {
        out.push({
          pluginID: plugin && plugin.id || '',
          pluginName: plugin && plugin.name || '',
          attachment
        });
      });
    });
    return out;
  }

  function attachmentGroupKey(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    return [
      String(attachment.engine || '').toLowerCase(),
      String(attachment.attach || '').toLowerCase(),
      attachmentDirection(attachment),
      String(attachment.interface || '').toLowerCase()
    ].join('\x1f');
  }

  function attachmentGroupLabel(item) {
    const attachment = item && item.attachment ? item.attachment : {};
    const engine = attachment.engine ? String(attachment.engine).toUpperCase() : 'TC';
    return [
      engine,
      attachment.attach || '',
      attachmentDirection(attachment),
      attachment.interface || ''
    ].filter(Boolean).join(' ');
  }

  function pluginAttachmentSegment(item, currentPluginID) {
    const attachment = item && item.attachment ? item.attachment : {};
    const slot = attachmentChainSlot(attachment);
    const label = item.pluginID || attachment.hook_id || app.t('common.dash');
    return {
      text: label,
      title: [
        item.pluginName || item.pluginID,
        attachment.hook_id,
        attachment.stage,
        attachment.mode,
        attachment.program,
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
        detailRow('Attach', attachment.attach),
        detailRow('Stage', attachment.stage),
        detailRow('Mode', attachment.mode),
        detailRow('Interface', attachment.interface),
        detailRow('Program', attachment.program),
        detailRow('Status', attachment.status),
        detailRow('Priority', typeof attachment.priority === 'number' ? String(attachment.priority) : ''),
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
    const all = pluginRuntimeAttachmentItems();
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
        segments: pre.map((item) => pluginAttachmentSegment(item, currentID))
          .concat([pluginCoreSegment(direction, corePriority)])
          .concat(post.map((item) => pluginAttachmentSegment(item, currentID)))
          .concat([pluginApplySegment(direction)])
      };
    });
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

  function isDeclaredFVTapPipelineHook(hook, corePriority) {
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
    const interfaces = Array.isArray(hook.interfaces) && hook.interfaces.length ? hook.interfaces.join(',') : app.t('plugins.link.unbound');
    return [engine, hook.attach || 'ingress', hookDirection(hook), interfaces].filter(Boolean).join(' ');
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
        if (!isDeclaredFVTapPipelineHook(hook, corePriority)) return;
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
        segments: pre.map((item) => pluginHookSegment(item.plugin, item.hook, currentID))
          .concat([pluginCoreSegment(direction, corePriority)])
          .concat(post.map((item) => pluginHookSegment(item.plugin, item.hook, currentID)))
          .concat([pluginApplySegment(direction)])
      };
    });
  }

  function pluginVirtualLinkItems(plugin) {
    const item = plugin || {};

    const chains = pluginAttachmentChainRows(item);
    if (chains.length) return chains;
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

  function pluginActionsNode(plugin) {
    if (!plugin || plugin.builtin || plugin.id === 'fvtap') return app.emptyCellNode('stat-muted');
    const id = String(plugin.id || '').trim();
    if (!id) return app.emptyCellNode('stat-muted');
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

  function pluginHostComponentCSS() {
    return `
:root {
  --fwd-bg: #f5f6f8;
  --fwd-surface: #ffffff;
  --fwd-surface-soft: #f8f9fb;
  --fwd-surface-tint: #eef4ff;
  --fwd-text: #1f2937;
  --fwd-muted: #4b5563;
  --fwd-soft: #6b7280;
  --fwd-border: #d9dde3;
  --fwd-border-strong: #c7ced8;
  --fwd-primary: #2563eb;
  --fwd-primary-hover: #1d4ed8;
  --fwd-primary-soft: rgba(37, 99, 235, 0.08);
  --fwd-focus: rgba(37, 99, 235, 0.14);
  --fwd-success-bg: #f0fdf4;
  --fwd-success-border: #86efac;
  --fwd-success-text: #15803d;
  --fwd-page-wash-start: rgba(255, 255, 255, 0.92);
  --fwd-page-wash-end: rgba(245, 246, 248, 0.92);
  --fwd-radius: 10px;
  --fwd-shadow: 0 2px 8px rgba(15, 23, 42, 0.04);
  color-scheme: light;
  font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
}
* {
  box-sizing: border-box;
}
body.fwd-plugin-body,
body {
  margin: 0;
  background:
    linear-gradient(180deg, var(--fwd-page-wash-start), var(--fwd-page-wash-end)),
    radial-gradient(circle at 12% 0%, rgba(37, 99, 235, 0.08), transparent 32%),
    var(--fwd-bg);
  color: var(--fwd-text);
  font-size: 13px;
}
.fwd-page { padding: 8px; }
.fwd-stack { display: grid; gap: 8px; }
.fwd-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 8px; }
.fwd-card {
  min-width: 0;
  padding: 10px;
  border: 1px solid var(--fwd-border);
  border-radius: 9px;
  background: rgba(255, 255, 255, 0.94);
  box-shadow: var(--fwd-shadow);
}
.fwd-card + .fwd-card { margin-top: 0; }
.fwd-card > * + * { margin-top: 8px; }
.fwd-card > .fwd-toolbar + * { margin-top: 10px; }
.fwd-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 7px; flex-wrap: wrap; }
.fwd-title { margin: 0; font-size: 16px; line-height: 1.28; font-weight: 680; letter-spacing: -0.01em; }
.fwd-desc { margin: 3px 0 0; color: var(--fwd-muted); line-height: 1.42; font-size: 12px; }
.fwd-muted { color: var(--fwd-muted); }
.fwd-stat {
  display: grid;
  gap: 3px;
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid var(--fwd-border);
  border-radius: 8px;
  background: linear-gradient(180deg, var(--fwd-surface), var(--fwd-surface-soft));
}
.fwd-stat-label { color: var(--fwd-soft); font-size: 10.5px; font-weight: 650; text-transform: uppercase; letter-spacing: 0.04em; }
.fwd-stat-value {
  color: var(--fwd-text); font-size: 14px; font-weight: 720; line-height: 1.22;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.fwd-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 30px;
  padding: 0 11px;
  border: 1px solid var(--fwd-primary);
  border-radius: 8px;
  background: var(--fwd-primary);
  color: #fff;
  font-size: 12px;
  font-weight: 650;
  line-height: 1.2;
  white-space: nowrap;
  cursor: pointer;
  transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease, border-color 0.16s ease, color 0.16s ease;
}
.fwd-button.secondary {
  border-color: var(--fwd-border);
  background: var(--fwd-surface);
  color: var(--fwd-primary);
}
.fwd-button:hover, .fwd-button:focus {
  transform: translateY(-1px);
  border-color: var(--fwd-primary-hover);
  background: var(--fwd-primary-hover);
  box-shadow: 0 6px 14px rgba(37, 99, 235, 0.18);
}
.fwd-button.secondary:hover, .fwd-button.secondary:focus {
  background: var(--fwd-primary-soft);
  color: var(--fwd-primary-hover);
}
.fwd-button:active { transform: translateY(0); box-shadow: none; }
.fwd-button:disabled { opacity: 0.58; cursor: wait; transform: none; box-shadow: none; }
.fwd-badge {
  display: inline-flex; align-items: center; min-height: 21px; padding: 0 8px;
  border-radius: 999px; border: 1px solid var(--fwd-border);
  background: var(--fwd-surface-soft); color: var(--fwd-muted); font-size: 11px; font-weight: 650;
  white-space: nowrap;
}
.fwd-status {
  display: inline-flex;
  align-items: center;
  min-height: 21px;
  padding: 0 8px;
  border: 1px solid var(--fwd-success-border);
  border-radius: 999px;
  background: var(--fwd-success-bg);
  color: var(--fwd-success-text);
  font-size: 11px;
  font-weight: 700;
  white-space: nowrap;
}
.fwd-toast-stack {
  position: fixed; right: 12px; bottom: 12px; z-index: 20;
  display: grid; gap: 7px; max-width: min(340px, calc(100vw - 24px));
}
.fwd-toast {
  padding: 9px 11px; border: 1px solid var(--fwd-border); border-radius: 10px;
  background: rgba(255, 255, 255, 0.98); color: var(--fwd-text); box-shadow: 0 16px 34px rgba(15, 23, 42, 0.12);
  font-size: 12px; line-height: 1.45; opacity: 0; transform: translateY(6px) scale(0.98);
  transition: opacity 0.16s ease, transform 0.16s ease;
}
.fwd-toast.is-visible { opacity: 1; transform: translateY(0) scale(1); }
.fwd-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  overflow: hidden;
  border: 1px solid var(--fwd-border);
  border-radius: 9px;
  background: var(--fwd-surface);
}
.fwd-table th, .fwd-table td { padding: 8px 10px; border-bottom: 1px solid var(--fwd-border); text-align: left; font-size: 12px; }
.fwd-table tr:last-child td { border-bottom: 0; }
.fwd-table th { color: var(--fwd-soft); background: var(--fwd-surface-soft); font-weight: 700; }
.fwd-table td { overflow-wrap: anywhere; }
.fwd-field { display: grid; gap: 6px; min-width: 0; }
.fwd-field label,
.fwd-field > span:first-child { color: var(--fwd-muted); font-size: 11px; font-weight: 650; }
.fwd-input {
  width: 100%;
  min-height: 31px;
  padding: 5px 9px;
  border: 1px solid var(--fwd-border);
  border-radius: 7px;
  background: var(--fwd-surface);
  color: var(--fwd-text);
  font: inherit;
  font-size: 12px;
  outline: none;
  transition: border-color 0.16s ease, box-shadow 0.16s ease, background 0.16s ease;
}
textarea.fwd-input {
  min-height: 70px;
  padding-top: 7px;
  line-height: 1.45;
  resize: vertical;
}
.fwd-input:hover {
  border-color: var(--fwd-border-strong);
}
.fwd-input:focus {
  border-color: var(--fwd-primary);
  box-shadow: 0 0 0 3px var(--fwd-focus);
  background: #fff;
}
select.fwd-input {
  appearance: none;
  padding-right: 30px;
  background-image:
    linear-gradient(45deg, transparent 50%, var(--fwd-soft) 50%),
    linear-gradient(135deg, var(--fwd-soft) 50%, transparent 50%);
  background-position:
    calc(100% - 16px) 14px,
    calc(100% - 11px) 14px;
  background-size: 5px 5px, 5px 5px;
  background-repeat: no-repeat;
}
.fwd-input[type="checkbox"] {
  appearance: none;
  width: 34px;
  min-width: 34px;
  height: 20px;
  min-height: 20px;
  padding: 0;
  border-radius: 999px;
  background: var(--fwd-surface-soft);
  cursor: pointer;
  position: relative;
  vertical-align: middle;
}
.fwd-input[type="checkbox"]::before {
  content: "";
  position: absolute;
  width: 14px;
  height: 14px;
  left: 2px;
  top: 2px;
  border-radius: 50%;
  background: var(--fwd-soft);
  transition: transform 0.16s ease, background 0.16s ease;
}
.fwd-input[type="checkbox"]:checked {
  border-color: var(--fwd-primary);
  background: var(--fwd-primary);
}
.fwd-input[type="checkbox"]:checked::before {
  transform: translateX(14px);
  background: #fff;
}
.fwd-input[type="checkbox"]:focus {
  background: var(--fwd-primary-soft);
}
.fwd-input[type="checkbox"]:checked:focus {
  background: var(--fwd-primary);
}
@media (max-width: 720px) {
  .fwd-page { padding: 8px; }
  .fwd-grid { grid-template-columns: 1fr; }
  .fwd-toolbar { align-items: flex-start; }
}
@media (prefers-color-scheme: dark) {
  :root {
    --fwd-bg: #12161a;
    --fwd-surface: #171b21;
    --fwd-surface-soft: #1d232b;
    --fwd-surface-tint: #172036;
    --fwd-text: #e5e7eb;
    --fwd-muted: #b3bcc8;
    --fwd-soft: #8d98a8;
    --fwd-border: #323943;
    --fwd-border-strong: #3a4452;
    --fwd-primary: #60a5fa;
    --fwd-primary-hover: #93c5fd;
    --fwd-primary-soft: rgba(96, 165, 250, 0.12);
    --fwd-focus: rgba(96, 165, 250, 0.16);
    --fwd-success-bg: rgba(34, 197, 94, 0.16);
    --fwd-success-border: rgba(74, 222, 128, 0.44);
    --fwd-success-text: #86efac;
    --fwd-page-wash-start: rgba(17, 20, 24, 0.92);
    --fwd-page-wash-end: rgba(17, 20, 24, 0.92);
    --fwd-shadow: 0 2px 8px rgba(0, 0, 0, 0.18);
    color-scheme: dark;
  }
  .fwd-card { background: rgba(23, 27, 33, 0.94); }
  .fwd-input:focus { background: var(--fwd-surface); }
  .fwd-toast { background: rgba(23, 27, 33, 0.98); box-shadow: 0 18px 36px rgba(0, 0, 0, 0.32); }
}`;
  }

  function pluginHostComponentJS(plugin) {
    const host = {
      version: 'v1',
      pluginId: plugin && plugin.id || '',
      pluginName: plugin && plugin.name || '',
      locale: app.state.locale || 'zh-CN',
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
      var timeout = window.setTimeout(function () {
        if (!pendingRPC[id]) return;
        delete pendingRPC[id];
        reject(new Error('plugin host request timed out'));
      }, 30000);
      pendingRPC[id] = { resolve: resolve, reject: reject, timeout: timeout };
      window.parent.postMessage({
        type: 'forward-plugin-rpc',
        pluginId: host.pluginId,
        id: id,
        op: op,
        payload: payload || {}
      }, '*');
    });
  }
  window.addEventListener('message', function (event) {
    if (!window.parent || event.source !== window.parent) return;
    var data = event && event.data && typeof event.data === 'object' ? event.data : null;
    if (data && data.type === 'forward-plugin-locale' && data.pluginId === host.pluginId) {
      updateLocale(data.locale);
      return;
    }
    if (!data || data.type !== 'forward-plugin-rpc-result' || data.pluginId !== host.pluginId || !data.id) return;
    var pending = pendingRPC[data.id];
    if (!pending) return;
    delete pendingRPC[data.id];
    if (pending.timeout) window.clearTimeout(pending.timeout);
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
  host.action = function (name, payload) {
    return rpc('action', { action: name, payload: payload || {} });
  };
  host.requestResize = scheduleHeight;
  window.ForwardPluginHost = Object.freeze(host);
  if (document && document.documentElement) document.documentElement.lang = currentLocale;
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
    iframe.onload = function () {
      postPluginFrameLocale(iframe);
    };
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
        type: 'forward-plugin-locale',
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
        type: 'forward-plugin-rpc-result',
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

  async function callPluginRPCAPI(pluginId, op, payload) {
    payload = payload && typeof payload === 'object' ? payload : {};
    const id = encodeURIComponent(pluginRPCString(pluginId, 'plugin id'));
    const resource = payload.resource != null ? encodeURIComponent(pluginRPCString(payload.resource, 'resource')) : '';
    const key = payload.key != null && payload.key !== '' ? encodeURIComponent(pluginRPCString(payload.key, 'key')) : '';
    if (op === 'data.list') {
      const query = [];
      if (payload.limit != null && payload.limit !== '') query.push('limit=' + encodeURIComponent(String(payload.limit)));
      if (payload.offset != null && payload.offset !== '') query.push('offset=' + encodeURIComponent(String(payload.offset)));
      return app.apiCall('GET', '/api/plugins/' + id + '/resources/' + resource + (query.length ? '?' + query.join('&') : ''));
    }
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
    if (typeof data.id !== 'string' || data.id.length < 1 || data.id.length > 128) return;
    if (typeof data.op !== 'string' || data.op.length < 1 || data.op.length > 64) return;
    try {
      const result = await callPluginRPCAPI(pluginId, data.op, data.payload);
      postPluginRPCResult(event.source, pluginId, data.id, true, result, '');
    } catch (e) {
      postPluginRPCResult(event.source, pluginId, data.id, false, null, e.message || String(e), e.payload || null, e.status || 0);
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
      attrs: { sandbox: 'allow-scripts allow-forms allow-popups' }
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

      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'stat-mono plugin-text-truncate',
        text: plugin.id || app.t('common.dash'),
        title: plugin.id || ''
      }), 'plugin-cell-id'));
      tr.appendChild(app.createCell(app.createNode('div', {
        className: 'plugin-status-compact',
        children: [
          app.createStatusBadgeNode(info, ''),
          pluginStabilityBadgeNode(plugin),
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
      tr.appendChild(app.createCell(pluginActionsNode(plugin), 'plugin-cell-tight'));
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

  app.togglePluginEnabled = async function togglePluginEnabled(pluginId, enabled) {
    const id = String(pluginId || '').trim();
    if (!id || id === 'fvtap') return;
    if (app.isRowPending && app.isRowPending('plugin', id)) return;
    const willEnable = !!enabled;
    if (app.setRowPending) app.setRowPending('plugin', id, true);
    app.renderPluginsTable();
    try {
      await app.apiCall('PUT', '/api/plugins/' + encodeURIComponent(id) + '/state', { enabled: willEnable });
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

  if (app.__enablePluginTests) {
    app.__pluginLinkRowsForTest = pluginVirtualLinkItems;
    app.__createPluginLinkCardForTest = createPluginVirtualLinkCard;
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
        app.loadPluginPageForTab(target);
        return;
      }
      if (typeof original === 'function') original(target);
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
