(function () {
  const app = window.VeerApp;
  if (!app) return;

  function ensureCurrentConnsSnapshot() {
    if (!app.state.currentConnsSnapshot) {
      app.state.currentConnsSnapshot = {
        loaded: false,
        rules: {},
        sites: {},
        ranges: {},
        egressNATs: {}
      };
    }
    return app.state.currentConnsSnapshot;
  }

  function getCurrentConnValue(kind, id) {
    const snapshot = ensureCurrentConnsSnapshot();
    if (!snapshot.loaded) return null;
    const table = snapshot[kind] || {};
    return Object.prototype.hasOwnProperty.call(table, id) ? table[id] : 0;
  }

  function statSortValue(item, key) {
    if (key === 'current_conns') {
      return item.current_conns == null ? -1 : item.current_conns;
    }
    return item[key];
  }

  function currentConnsCellNode(value) {
    if (value == null) return app.emptyCellNode('stat-muted');
    return app.createNode('span', {
      className: value > 0 ? 'stat-pill active' : 'stat-pill',
      text: String(value)
    });
  }

  function egressNATStatsIDCellContent(id) {
    const numericID = Number(id);
    if (!Number.isFinite(numericID) || numericID >= 0) {
      return String(id);
    }
    return app.createNode('span', {
      className: 'stat-muted',
      text: app.t('stats.egressNATs.id.auto'),
      title: app.t('stats.egressNATs.id.auto.title', { id: numericID })
    });
  }

  function buildStatsQuery(state) {
    const params = new URLSearchParams();
    params.set('page', String(state.page || 1));
    params.set('page_size', String(state.pageSize || 20));
    if (state.sortKey) {
      params.set('sort_key', state.sortKey);
      params.set('sort_asc', state.sortAsc === false ? 'false' : 'true');
    }
    return params.toString();
  }

  function findRuleConfig(ruleID) {
    const list = app.state && app.state.rules && Array.isArray(app.state.rules.data)
      ? app.state.rules.data
      : [];
    return list.find((rule) => rule && rule.id === ruleID) || null;
  }

  function findRangeConfig(rangeID) {
    const list = app.state && app.state.ranges && Array.isArray(app.state.ranges.data)
      ? app.state.ranges.data
      : [];
    return list.find((range) => range && range.id === rangeID) || null;
  }

  function findSiteConfig(siteID) {
    const list = app.state && app.state.sites && Array.isArray(app.state.sites.data)
      ? app.state.sites.data
      : [];
    return list.find((site) => site && site.id === siteID) || null;
  }

  function statsTargetCellNode(primary, sourceIP, detailText, metaText) {
    if (!primary) return app.emptyCellNode('stat-muted');
    const subParts = [
      sourceIP ? app.t('common.sourceShort') + ' ' + sourceIP : '',
      detailText,
      metaText
    ].filter(Boolean);
    const title = [
      app.t('stats.target') + ': ' + primary,
      sourceIP ? app.t('common.sourceShort') + ': ' + sourceIP : '',
      detailText,
      metaText
    ].filter(Boolean).join('\n');
    return app.createNode('div', {
      className: 'stats-target-cell',
      title: title,
      children: [
        app.createNode('span', {
          className: 'stats-target-main',
          text: primary
        }),
        subParts.length
          ? app.createNode('span', {
              className: 'stats-target-sub',
              text: subParts.join(' · ')
            })
          : null
      ].filter(Boolean)
    });
  }

  function ruleStatsTargetCellNode(rule) {
    if (!rule) return app.emptyCellNode('stat-muted');
    const detail = [
      String(rule.protocol || '').toUpperCase(),
      rule.out_port ? String(rule.out_port) : ''
    ].filter(Boolean).join(' · ');
    const meta = [
      rule.in_interface ? app.t('stats.route.in') + ' ' + rule.in_interface : '',
      rule.out_interface ? app.t('stats.route.out') + ' ' + rule.out_interface : ''
    ].filter(Boolean).join(' · ');
    return statsTargetCellNode(rule.out_ip, rule.out_source_ip, detail, meta);
  }

  function rangeStatsTargetCellNode(range) {
    if (!range) return app.emptyCellNode('stat-muted');
    let portText = '';
    if (range.out_start_port) {
      const outEnd = range.out_start_port + ((range.end_port || 0) - (range.start_port || 0));
      portText = String(range.out_start_port) + '-' + String(outEnd);
    }
    const routeText = [range.in_interface, range.out_interface].filter(Boolean).join(' -> ');
    const mainText = [
      range.out_ip,
      portText
    ].filter(Boolean).join(' · ');
    const subText = [
      range.out_source_ip ? app.t('common.sourceShort') + ' ' + range.out_source_ip : '',
      String(range.protocol || '').toUpperCase(),
      routeText
    ].filter(Boolean).join(' · ');
    const title = [
      app.t('stats.target') + ': ' + String(range.out_ip || ''),
      portText ? app.t('range.list.outboundRange') + ': ' + portText : '',
      range.out_source_ip ? app.t('common.sourceShort') + ': ' + range.out_source_ip : '',
      range.protocol ? app.t('form.protocol') + ': ' + String(range.protocol || '').toUpperCase() : '',
      range.in_interface ? app.t('stats.route.in') + ': ' + range.in_interface : '',
      range.out_interface ? app.t('stats.route.out') + ': ' + range.out_interface : ''
    ].filter(Boolean).join('\n');
    return app.createNode('div', {
      className: 'stats-target-cell',
      title: title,
      children: [
        app.createNode('span', {
          className: 'stats-target-main',
          text: mainText
        }),
        subText
          ? app.createNode('span', {
              className: 'stats-target-sub',
              text: subText
            })
          : null
      ].filter(Boolean)
    });
  }

  function siteStatsTargetCellNode(site) {
    if (!site) return app.emptyCellNode('stat-muted');
    const detail = [];
    if (site.backend_http_port) detail.push('HTTP ' + String(site.backend_http_port));
    if (site.backend_https_port) detail.push('HTTPS ' + String(site.backend_https_port));
    const meta = [
      site.listen_interface ? app.t('stats.route.listen') + ' ' + site.listen_interface : '',
      site.transparent ? app.t('form.transparentShort') : ''
    ].filter(Boolean).join(' · ');
    return statsTargetCellNode(site.backend_ip, site.backend_source_ip, detail.join(' · '), meta);
  }

  function egressNATStatsProtocolNode(protocol) {
    const normalized = typeof app.normalizeEgressNATProtocolValue === 'function'
      ? app.normalizeEgressNATProtocolValue(protocol)
      : String(protocol || '').trim().toLowerCase();
    const fullText = typeof app.formatEgressNATProtocol === 'function'
      ? app.formatEgressNATProtocol(protocol || '')
      : String(protocol || '').toUpperCase();
    const compactText = normalized
      ? normalized.split('+').map((item) => item.toUpperCase()).join('/')
      : fullText;
    return app.createNode('span', {
      className: 'stats-inline-compact',
      text: compactText,
      title: fullText
    });
  }

  function rebuildCurrentConns(kind, rows, idKey) {
    return (rows || []).map((row) => Object.assign({}, row, {
      current_conns: getCurrentConnValue(kind, row[idKey])
    }));
  }

  function kernelStatePill(flag, trueKey, falseKey) {
    return app.createNode('span', {
      className: flag ? 'stat-pill active' : 'stat-pill',
      text: app.t(flag ? trueKey : falseKey)
    });
  }

  // The configured flow cache, and the option that keeps it from taking effect on the TC engine.
  function kernelFlowCachePill(data) {
    if (!data.kernel_tc_flow_cache) {
      return kernelStatePill(false, 'kernel.flowCache.enabled', 'kernel.flowCache.disabled');
    }
    const tc = (Array.isArray(data.engines) ? data.engines : []).find((engine) => engine && engine.name === 'tc');
    if (tc && tc.flow_cache_disabled_by) {
      return app.createNode('span', {
        className: 'stat-pill',
        text: app.t('kernel.flowCache.inactive', { option: tc.flow_cache_disabled_by })
      });
    }
    return kernelStatePill(true, 'kernel.flowCache.enabled', 'kernel.flowCache.disabled');
  }

  // The configured engine is "tc" whichever way its programs hang on a device; what the panel shows
  // follows the runtime: "TCX" once the TC engine is attached through tcx links, "TC" for cls_bpf
  // filters or before anything is attached. Config and API values keep the name "tc".
  function kernelTCAttachmentAPI(runtime) {
    const data = runtime || (app.state.kernelRuntime && app.state.kernelRuntime.data);
    const engines = data && Array.isArray(data.engines) ? data.engines : [];
    const tc = engines.find((engine) => engine && String(engine.name || '').trim().toLowerCase() === 'tc');
    return tc ? String(tc.attachment_api || '').trim().toLowerCase() : '';
  }

  function kernelEngineLabel(name, runtime) {
    const normalized = String(name || '').trim().toLowerCase();
    if (!normalized) return '';
    if (normalized === 'tc') return kernelTCAttachmentAPI(runtime) === 'tcx' ? 'TCX' : 'TC';
    return normalized.toUpperCase();
  }

  function kernelEngineTitle(name, runtime) {
    const normalized = String(name || '').trim().toLowerCase();
    if (normalized !== 'tc') return '';
    const api = kernelTCAttachmentAPI(runtime);
    if (api === 'tcx') return app.t('kernel.engine.tcxTitle');
    if (api === 'cls_bpf') return app.t('kernel.engine.clsBPFTitle');
    return '';
  }

  app.kernelEngineLabel = function (name) { return kernelEngineLabel(name); };
  app.kernelEngineTitle = function (name) { return kernelEngineTitle(name); };

  function kernelEngineBadge(name, runtime) {
    const normalized = String(name || '').toLowerCase();
    const badgeClass = normalized === 'xdp' ? 'badge-xdp' : normalized === 'tc' ? 'badge-tc' : 'badge-kernel';
    return app.createBadgeNode(badgeClass, kernelEngineLabel(normalized, runtime) || app.t('common.dash'), kernelEngineTitle(normalized, runtime));
  }

  function kernelDefaultEngineBadge(name) {
    const normalized = String(name || '').toLowerCase();
    switch (normalized) {
      case 'kernel':
        return app.createBadgeNode('badge-kernel', app.t('rule.engine.preference.kernel'));
      case 'userspace':
        return app.createBadgeNode('badge-userspace', app.t('rule.engine.preference.userspace'));
      default:
        return app.createBadgeNode('badge-disabled', app.t('rule.engine.preference.auto'));
    }
  }

  function kernelRuntimeModeLabel(value) {
    switch (value) {
      case 'steady':
      case 'in_place':
      case 'rebuild':
      case 'cleared':
        return app.t('kernel.mode.' + value);
      default:
        return app.t('kernel.mode.unknown');
    }
  }

  function kernelRuntimePressureLevel(engine) {
    const level = String(engine && engine.pressure_level || '').toLowerCase().trim();
    if (level) return level;
    return engine && engine.pressure_active ? 'hold' : 'none';
  }

  function kernelRuntimePressureRank(level) {
    switch (level) {
      case 'hold':
        return 1;
      case 'shed':
        return 2;
      case 'full':
        return 3;
      default:
        return 0;
    }
  }

  function kernelRuntimePressureBadge(level, reason) {
    const title = typeof app.translateRuntimeReason === 'function'
      ? app.translateRuntimeReason(reason)
      : String(reason || '').trim();
    let badgeClass = 'badge-disabled';
    switch (level) {
      case 'hold':
        badgeClass = 'badge-kernel';
        break;
      case 'shed':
        badgeClass = 'badge-error';
        break;
      case 'full':
        badgeClass = 'badge-stopped';
        break;
      default:
        badgeClass = 'badge-disabled';
        break;
    }
    return app.createBadgeNode(badgeClass, app.t('kernel.pressure.' + level), title || '');
  }

  function kernelRuntimePressureSummary(engines) {
    const active = (engines || []).filter((engine) => !!engine && !!engine.pressure_active);
    if (!active.length) {
      return {
        level: 'none',
        subtext: app.t('kernel.pressure.noneHint')
      };
    }

    let highestLevel = 'none';
    active.forEach((engine) => {
      const level = kernelRuntimePressureLevel(engine);
      if (kernelRuntimePressureRank(level) > kernelRuntimePressureRank(highestLevel)) {
        highestLevel = level;
      }
    });

    const subtext = active.map((engine) => {
      const label = kernelEngineLabel(engine.name) || app.t('common.dash');
      return label + ' ' + app.t('kernel.pressure.' + kernelRuntimePressureLevel(engine));
    }).join('; ');

    return {
      level: highestLevel,
      subtext
    };
  }

  function kernelRuntimeMapPercent(entries, capacity) {
    if (!(capacity > 0)) return 0;
    return (entries / capacity) * 100;
  }

  function formatKernelRuntimePercent(percent) {
    if (percent >= 99.95) return '100%';
    const rounded = Math.round(percent * 10) / 10;
    if (Math.abs(rounded - Math.round(rounded)) < 0.05) {
      return String(Math.round(rounded)) + '%';
    }
    return rounded.toFixed(1) + '%';
  }

  function kernelRuntimeMapLevel(percent, capacity) {
    if (!(capacity > 0)) return 'empty';
    if (percent >= 80) return 'high';
    if (percent >= 50) return 'medium';
    return 'low';
  }

  function kernelRuntimeMapTooltipDetailText(detail) {
    const entries = Number(detail && detail.entries || 0);
    const capacity = Number(detail && detail.capacity || 0);
    const percent = kernelRuntimeMapPercent(entries, capacity);
    return formatKernelRuntimePercent(percent) + ' · ' + String(entries) + ' / ' + String(capacity);
  }

  function kernelRuntimeMapCounterText(entries, capacity) {
    return String(entries) + ' / ' + String(capacity);
  }

  function kernelRuntimeMapDisplay(item) {
    const details = Array.isArray(item && item.details) ? item.details : [];
    let aggregateEntries = 0;
    let aggregateCapacity = 0;
    let aggregateOldCapacity = 0;
    let aggregateUsed = false;

    details.forEach((detail) => {
      const entries = Number(detail && detail.entries || 0);
      const capacity = Number(detail && detail.capacity || 0);
      const oldCapacity = Number(detail && detail.oldCapacity || 0);
      if (entries > 0 || capacity > 0 || oldCapacity > 0) {
        aggregateEntries += entries;
        aggregateCapacity += capacity;
        aggregateOldCapacity += oldCapacity;
        aggregateUsed = true;
      }
    });

    const rawEntries = Number(item && item.entries || 0);
    const rawCapacity = Number(item && item.capacity || 0);
    return {
      rawEntries: rawEntries,
      rawCapacity: rawCapacity,
      entries: aggregateUsed ? aggregateEntries : rawEntries,
      capacity: aggregateUsed ? aggregateCapacity : rawCapacity,
      oldCapacity: aggregateOldCapacity,
      aggregated: aggregateUsed,
      hasOldBank: aggregateOldCapacity > 0
    };
  }

  function kernelRuntimeMapBadgeMetrics(item, display) {
    const details = Array.isArray(item && item.details) ? item.details : [];
    let peak = null;

    details.forEach((detail) => {
      const entries = Number(detail && detail.entries || 0);
      const capacity = Number(detail && detail.capacity || 0);
      if (!(capacity > 0)) return;
      const percent = kernelRuntimeMapPercent(entries, capacity);
      if (!peak ||
        percent > peak.percent ||
        (percent === peak.percent && entries > peak.entries) ||
        (percent === peak.percent && entries === peak.entries && capacity > peak.capacity)) {
        peak = {
          label: String(detail && (detail.shortLabel || detail.label) || '').trim(),
          entries: entries,
          capacity: capacity,
          percent: percent
        };
      }
    });

    if (peak) {
      return peak;
    }
    return {
      label: '',
      entries: display.entries,
      capacity: display.capacity,
      percent: kernelRuntimeMapPercent(display.entries, display.capacity)
    };
  }

  function kernelRuntimeMapBadgeAriaLabel(item, metrics) {
    const parts = [item.label, formatKernelRuntimePercent(metrics.percent)];
    if (metrics.capacity > 0) {
      const scope = metrics.label ? metrics.label + ' ' : '';
      parts.push('(' + scope + kernelRuntimeMapCounterText(metrics.entries, metrics.capacity) + ')');
    }
    return parts.join(' ');
  }

  function kernelRuntimeMapTooltipMetaText(display, badgeMetrics) {
    if (badgeMetrics && badgeMetrics.label && badgeMetrics.capacity > 0 &&
      (badgeMetrics.entries !== display.entries || badgeMetrics.capacity !== display.capacity)) {
      return app.t('kernel.maps.tooltip.peak') + ' ' + badgeMetrics.label + ' ' +
        kernelRuntimeMapCounterText(badgeMetrics.entries, badgeMetrics.capacity) + ' · ' +
        app.t('kernel.maps.tooltip.total') + ' ' +
        kernelRuntimeMapCounterText(display.entries, display.capacity);
    }
    return kernelRuntimeMapCounterText(display.entries, display.capacity);
  }

  function kernelRuntimeMapBaseLimit(kind, runtimeData) {
    if (!runtimeData) return 0;
    if (kind === 'rules') return Number(runtimeData.kernel_rules_map_base_limit || 0);
    if (kind === 'flows') return Number(runtimeData.kernel_flows_map_base_limit || 0);
    if (kind === 'nat') return Number(runtimeData.kernel_nat_map_base_limit || 0);
    return 0;
  }

  function kernelRuntimeMapConfiguredLimit(kind, runtimeData) {
    if (!runtimeData) return 0;
    if (kind === 'rules') return Number(runtimeData.kernel_rules_map_configured_limit || 0);
    if (kind === 'flows') return Number(runtimeData.kernel_flows_map_configured_limit || 0);
    if (kind === 'nat') return Number(runtimeData.kernel_nat_map_configured_limit || 0);
    return 0;
  }

  function kernelRuntimeMapCapacityMode(kind, runtimeData) {
    if (!runtimeData) return '';
    if (kind === 'rules') return String(runtimeData.kernel_rules_map_capacity_mode || '').trim();
    if (kind === 'flows') return String(runtimeData.kernel_flows_map_capacity_mode || '').trim();
    if (kind === 'nat') return String(runtimeData.kernel_nat_map_capacity_mode || '').trim();
    return '';
  }

  function kernelRuntimeMapDecisionText(item, runtimeData) {
    const mode = kernelRuntimeMapCapacityMode(item.kind, runtimeData);
    const configuredLimit = kernelRuntimeMapConfiguredLimit(item.kind, runtimeData);
    const baseLimit = kernelRuntimeMapBaseLimit(item.kind, runtimeData);
    const currentCapacity = kernelRuntimeMapDisplay(item).capacity;

    if (mode === 'fixed') {
      return app.t('kernel.maps.tooltip.decision.fixed', {
        limit: configuredLimit || currentCapacity || baseLimit || 0
      });
    }
    if (baseLimit > 0 && currentCapacity > 0 && currentCapacity < baseLimit) {
      return app.t('kernel.maps.tooltip.decision.retained', {
        current: currentCapacity,
        base: baseLimit
      });
    }
    if (baseLimit > 0 && currentCapacity > baseLimit) {
      return app.t('kernel.maps.tooltip.decision.expanded', {
        base: baseLimit,
        current: currentCapacity
      });
    }
    if (baseLimit > 0) {
      return app.t('kernel.maps.tooltip.decision.base', {
        base: baseLimit
      });
    }
    return app.t('kernel.maps.tooltip.decision.current', {
      current: currentCapacity
    });
  }

  function kernelRuntimeMapOldBankSummary(details) {
    const activeDetails = Array.isArray(details) ? details : [];
    const parts = activeDetails.reduce((items, detail) => {
      const oldCapacity = Number(detail && detail.oldCapacity || 0);
      if (!(oldCapacity > 0)) return items;
      const label = String(detail && (detail.shortLabel || detail.label) || '').trim();
      items.push((label || app.t('common.dash')) + ' ' + String(oldCapacity));
      return items;
    }, []);
    return parts.join(' · ');
  }

  function kernelRuntimeMapInfoRows(item, runtimeData) {
    if (!runtimeData) return [];

    const rows = [];
    const display = kernelRuntimeMapDisplay(item);
    if (runtimeData.kernel_map_profile) {
      rows.push({
        label: app.t('kernel.maps.tooltip.profile'),
        value: kernelRuntimeMapProfileLabel(runtimeData.kernel_map_profile) + ' · ' + kernelRuntimeMapProfileMemoryLabel(runtimeData.kernel_map_total_memory_bytes)
      });
    }

    const mode = kernelRuntimeMapCapacityMode(item.kind, runtimeData);
    if (mode) {
      rows.push({
        label: app.t('kernel.maps.tooltip.mode'),
        value: app.t('kernel.maps.tooltip.mode.' + mode)
      });
    }

    const baseLimit = kernelRuntimeMapBaseLimit(item.kind, runtimeData);
    if (baseLimit > 0) {
      rows.push({
        label: app.t('kernel.maps.tooltip.base'),
        value: String(baseLimit)
      });
    }

    rows.push({
      label: app.t('kernel.maps.tooltip.decision'),
      value: kernelRuntimeMapDecisionText(item, runtimeData)
    });

    if (display.aggregated && (display.rawCapacity !== display.capacity || display.rawEntries !== display.entries)) {
      rows.push({
        label: app.t('kernel.maps.tooltip.scope'),
        value: app.t('kernel.maps.tooltip.scope.families')
      });
    }
    if (display.hasOldBank) {
      rows.push({
        label: app.t('kernel.maps.tooltip.oldBank'),
        value: kernelRuntimeMapOldBankSummary(item.details)
      });
    }

    return rows;
  }

  function kernelRuntimeMapTooltipContent(item, percentText, runtimeData, badgeMetrics) {
    const details = (Array.isArray(item.details) ? item.details : []).filter((detail) => (detail.capacity || 0) > 0 || (detail.entries || 0) > 0);
    const infoRows = kernelRuntimeMapInfoRows(item, runtimeData);
    const display = kernelRuntimeMapDisplay(item);
    return [
      app.popoverHeader({
        title: item.label,
        meta: kernelRuntimeMapTooltipMetaText(display, badgeMetrics),
        aside: app.createNode('span', { className: 'popover-figure mono', text: percentText })
      }),
      details.length
        ? app.popoverRows(details.map((detail) => ({ label: detail.label, value: kernelRuntimeMapTooltipDetailText(detail), mono: true })))
        : null,
      infoRows.length ? app.popoverRows(infoRows) : null
    ].filter(Boolean);
  }

  // Small read-only details open on hover or focus and stay open after a click; the status panel
  // (bindKernelRuntimePanel) opens on click only because it holds collapsible sections.
  let kernelRuntimeTooltipLayer = null;
  let kernelRuntimePanelLayer = null;

  function kernelTooltipLayer() {
    if (!kernelRuntimeTooltipLayer && typeof app.createFloatingLayer === 'function') {
      kernelRuntimeTooltipLayer = app.createFloatingLayer({
        id: 'kernelRuntimeFloatingTooltip',
        className: 'kernel-runtime-floating-tooltip',
        role: 'tooltip',
        placement: { align: 'center', maxHeight: 420 }
      });
    }
    return kernelRuntimeTooltipLayer;
  }

  function kernelPanelLayer() {
    if (!kernelRuntimePanelLayer && typeof app.createFloatingLayer === 'function') {
      kernelRuntimePanelLayer = app.createFloatingLayer({
        id: 'kernelRuntimeStatusDetails',
        className: 'is-wide kernel-runtime-status-popover',
        role: 'dialog',
        placement: { align: 'start', maxHeight: 560 }
      });
    }
    return kernelRuntimePanelLayer;
  }

  function hideKernelRuntimeTooltip() {
    if (kernelRuntimeTooltipLayer) kernelRuntimeTooltipLayer.hide();
    if (kernelRuntimePanelLayer) kernelRuntimePanelLayer.hide();
  }

  function bindKernelRuntimeTooltip(trigger, contentFactory) {
    const show = (pinned) => {
      const layer = kernelTooltipLayer();
      if (layer) layer.show(trigger, contentFactory(), { pinned: pinned });
    };
    const hideIfPreview = () => {
      const layer = kernelRuntimeTooltipLayer;
      if (layer && layer.isOpenFor(trigger) && !layer.pinned) layer.hide();
    };
    const pinnedElsewhere = () => typeof app.floatingLayerPinned === 'function' && app.floatingLayerPinned();
    trigger.addEventListener('mouseenter', () => {
      if (pinnedElsewhere()) return;
      show(false);
    });
    trigger.addEventListener('mouseleave', hideIfPreview);
    trigger.addEventListener('focus', () => {
      const layer = kernelRuntimeTooltipLayer;
      if ((layer && layer.isOpenFor(trigger)) || pinnedElsewhere()) return;
      show(false);
    });
    trigger.addEventListener('blur', hideIfPreview);
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const layer = kernelRuntimeTooltipLayer;
      if (layer && layer.isOpenFor(trigger) && layer.pinned) {
        layer.hide();
        return;
      }
      show(true);
    });
  }

  function bindKernelRuntimePanel(trigger, contentFactory, label) {
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const layer = kernelPanelLayer();
      if (!layer) return;
      if (layer.isOpenFor(trigger)) {
        layer.hide();
        return;
      }
      layer.show(trigger, contentFactory(() => layer.hide({ restoreFocus: true })), { pinned: true, label: label });
    });
  }

  app.bindFloatingDetailTooltip = function bindFloatingDetailTooltip(trigger, contentFactory) {
    if (!trigger || typeof contentFactory !== 'function') return;
    bindKernelRuntimeTooltip(trigger, contentFactory);
  };

  function kernelRuntimeMapsNode(engine, runtimeData) {
    const items = [
      {
        kind: 'rules',
        label: app.t('kernel.maps.rules'),
        entries: engine.rules_map_entries || 0,
        capacity: engine.rules_map_capacity || 0,
        details: [
          {
            label: app.t('kernel.maps.ipv4'),
            shortLabel: app.t('kernel.maps.ipv4Short'),
            entries: engine.rules_map_entries_v4 || 0,
            capacity: engine.rules_map_capacity_v4 || 0
          },
          {
            label: app.t('kernel.maps.ipv6'),
            shortLabel: app.t('kernel.maps.ipv6Short'),
            entries: engine.rules_map_entries_v6 || 0,
            capacity: engine.rules_map_capacity_v6 || 0
          }
        ]
      },
      {
        kind: 'flows',
        label: app.t('kernel.maps.flows'),
        entries: engine.flows_map_entries || 0,
        capacity: engine.flows_map_capacity || 0,
        details: [
          {
            label: app.t('kernel.maps.ipv4'),
            shortLabel: app.t('kernel.maps.ipv4Short'),
            entries: engine.flows_map_entries_v4 || 0,
            capacity: engine.flows_map_capacity_v4 || 0,
            oldCapacity: engine.flows_map_old_capacity_v4 || 0
          },
          {
            label: app.t('kernel.maps.ipv6'),
            shortLabel: app.t('kernel.maps.ipv6Short'),
            entries: engine.flows_map_entries_v6 || 0,
            capacity: engine.flows_map_capacity_v6 || 0,
            oldCapacity: engine.flows_map_old_capacity_v6 || 0
          }
        ]
      }
    ];

    if ((engine.nat_map_entries || 0) > 0 || (engine.nat_map_capacity || 0) > 0) {
      items.push({
        kind: 'nat',
        label: app.t('kernel.maps.nat'),
        entries: engine.nat_map_entries || 0,
        capacity: engine.nat_map_capacity || 0,
        details: [
          {
            label: app.t('kernel.maps.ipv4'),
            shortLabel: app.t('kernel.maps.ipv4Short'),
            entries: engine.nat_map_entries_v4 || 0,
            capacity: engine.nat_map_capacity_v4 || 0,
            oldCapacity: engine.nat_map_old_capacity_v4 || 0
          },
          {
            label: app.t('kernel.maps.ipv6'),
            shortLabel: app.t('kernel.maps.ipv6Short'),
            entries: engine.nat_map_entries_v6 || 0,
            capacity: engine.nat_map_capacity_v6 || 0,
            oldCapacity: engine.nat_map_old_capacity_v6 || 0
          }
        ]
      });
    }

    const list = app.createNode('div', { className: 'kernel-runtime-map-list' });
    items.forEach((item) => {
      const display = kernelRuntimeMapDisplay(item);
      const badgeMetrics = kernelRuntimeMapBadgeMetrics(item, display);
      const percent = badgeMetrics.percent;
      const percentText = formatKernelRuntimePercent(percent);
      const badge = app.createNode('button', {
        className: 'kernel-runtime-map-badge is-' + kernelRuntimeMapLevel(percent, badgeMetrics.capacity),
        attrs: {
          type: 'button',
          'aria-describedby': 'kernelRuntimeFloatingTooltip',
          'aria-expanded': 'false',
          'aria-label': kernelRuntimeMapBadgeAriaLabel(item, badgeMetrics)
        },
        children: [
          app.createNode('span', {
            className: 'kernel-runtime-map-badge-label',
            text: item.label
          }),
          app.createNode('span', {
            className: 'kernel-runtime-map-badge-value',
            text: percentText
          })
        ]
      });
      bindKernelRuntimeTooltip(badge, () => kernelRuntimeMapTooltipContent(item, percentText, runtimeData, badgeMetrics));
      list.appendChild(badge);
    });
    return list;
  }

  function kernelRuntimeSummaryCard(labelKey, value, subtext) {
    const card = app.createNode('article', { className: 'kernel-runtime-card' });
    card.appendChild(app.createNode('div', {
      className: 'kernel-runtime-label',
      text: app.t(labelKey)
    }));

    const valueNode = app.createNode('div', { className: 'kernel-runtime-value' });
    app.appendNodeContent(valueNode, value);
    card.appendChild(valueNode);

    if (subtext) {
      const subNode = app.createNode('div', { className: 'kernel-runtime-sub' });
      app.appendNodeContent(subNode, subtext);
      card.appendChild(subNode);
    }
    return card;
  }

  function kernelRuntimeSummaryInline(content) {
    return app.createNode('div', {
      className: 'kernel-runtime-inline',
      children: content
    });
  }

  function kernelRuntimeTimestampLabel(timestamp) {
    if (!timestamp) return '';
    return app.formatClock(timestamp);
  }

  function kernelRuntimeDurationLabel(milliseconds) {
    const value = Number(milliseconds || 0);
    if (!(value > 0)) return '';
    if (value < 1000) return String(Math.round(value)) + 'ms';
    const seconds = value / 1000;
    if (Math.abs(seconds - Math.round(seconds)) < 0.05) {
      return String(Math.round(seconds)) + 's';
    }
    return (Math.round(seconds * 10) / 10).toFixed(1) + 's';
  }

  function kernelRuntimeMapProfileLabel(profileName) {
    const name = String(profileName || '').trim();
    if (!name) return app.t('common.dash');
    return app.t('kernel.summary.mapProfileValue.' + name);
  }

  function kernelRuntimeMapProfileMemoryLabel(totalMemoryBytes) {
    const value = Number(totalMemoryBytes || 0);
    if (!(value > 0)) return app.t('kernel.summary.mapProfileMemoryUnknown');
    return app.formatBytes(value);
  }

  function kernelRuntimeMapProfileDetail(data) {
    if (!data) return '';
    const flows = Number(data.kernel_flows_map_base_limit || 0);
    const nat = Number(data.kernel_nat_map_base_limit || 0);
    const egress = Number(data.kernel_egress_nat_auto_floor || 0);
    if (!(flows > 0) && !(nat > 0) && !(egress > 0)) return '';
    return app.t('kernel.summary.mapProfileDetail', {
      memory: kernelRuntimeMapProfileMemoryLabel(data.kernel_map_total_memory_bytes),
      flows: flows || 0,
      nat: nat || 0,
      egress: egress || 0
    });
  }

  function kernelRuntimeReconcileDetail(engine) {
    if (!engine) return '';
    const parts = [];
    const duration = kernelRuntimeDurationLabel(engine.last_reconcile_ms);
    if (duration) parts.push(duration);
    if (engine.last_reconcile_at) parts.push('@' + app.formatClock(engine.last_reconcile_at));
    if (
      engine.last_reconcile_request_entries ||
      engine.last_reconcile_prepared_entries ||
      engine.last_reconcile_applied_entries ||
      engine.last_reconcile_upserts ||
      engine.last_reconcile_deletes ||
      engine.last_reconcile_attaches ||
      engine.last_reconcile_detaches ||
      engine.last_reconcile_preserved ||
      engine.last_reconcile_flow_purge_deleted
    ) {
      parts.push(
        'req=' + String(engine.last_reconcile_request_entries || 0),
        'prep=' + String(engine.last_reconcile_prepared_entries || 0),
        'applied=' + String(engine.last_reconcile_applied_entries || 0),
        'upsert=' + String(engine.last_reconcile_upserts || 0),
        'delete=' + String(engine.last_reconcile_deletes || 0),
        'attach=' + String(engine.last_reconcile_attaches || 0),
        'detach=' + String(engine.last_reconcile_detaches || 0),
        'preserve=' + String(engine.last_reconcile_preserved || 0),
        'purge=' + String(engine.last_reconcile_flow_purge_deleted || 0)
      );
    }
    const phaseParts = [];
    if (engine.last_reconcile_prepare_ms) phaseParts.push('prepare=' + kernelRuntimeDurationLabel(engine.last_reconcile_prepare_ms));
    if (engine.last_reconcile_attach_ms) phaseParts.push('attach=' + kernelRuntimeDurationLabel(engine.last_reconcile_attach_ms));
    if (engine.last_reconcile_flow_purge_ms) phaseParts.push('purge=' + kernelRuntimeDurationLabel(engine.last_reconcile_flow_purge_ms));
    if (phaseParts.length) {
      parts.push(phaseParts.join(' '));
    }
    if (engine.last_reconcile_error) {
      parts.push('err=' + String(engine.last_reconcile_error));
    }
    return parts.join(' ');
  }

  function kernelRuntimeCooldownWindowLabel(nextExpiry, clearAt) {
    const next = kernelRuntimeTimestampLabel(nextExpiry);
    const clear = kernelRuntimeTimestampLabel(clearAt);
    if (!next && !clear) return '';
    if (!clear || next === clear) {
      return app.t('kernel.summary.activeCooldownClearValue', {
        clear: clear || next
      });
    }
    return app.t('kernel.summary.activeCooldownWindowValue', {
      next: next,
      clear: clear
    });
  }

  function ensureKernelRuntimeDismissedNotes() {
    if (!app.state.kernelRuntimeDismissedNotes || typeof app.state.kernelRuntimeDismissedNotes !== 'object') {
      app.state.kernelRuntimeDismissedNotes = {};
    }
    return app.state.kernelRuntimeDismissedNotes;
  }

  function syncKernelRuntimeDismissedNotes(data) {
    const dismissed = {};
    const keys = Array.isArray(data && data.dismissed_note_keys) ? data.dismissed_note_keys : [];
    keys.forEach((key) => {
      key = String(key || '').trim();
      if (!key) return;
      dismissed[key] = true;
    });
    app.state.kernelRuntimeDismissedNotes = dismissed;
    return dismissed;
  }

  function pruneKernelRuntimeDismissedNotes(activeKeys) {
    const dismissed = ensureKernelRuntimeDismissedNotes();
    const keep = activeKeys && typeof activeKeys === 'object' ? activeKeys : {};
    Object.keys(dismissed).forEach((key) => {
      if (!keep[key]) delete dismissed[key];
    });
  }

  async function dismissKernelRuntimeNote(key) {
    key = String(key || '').trim();
    if (!key) return false;

    const response = await app.apiCall('POST', '/api/kernel/runtime/dismiss-note', { key: key });
    const data = app.state && app.state.kernelRuntime ? app.state.kernelRuntime.data : null;
    if (data && response && Array.isArray(response.dismissed_note_keys)) {
      data.dismissed_note_keys = response.dismissed_note_keys.slice();
    }
    syncKernelRuntimeDismissedNotes(data || response || null);
    return true;
  }

  // A runtime note keeps its dismissal key (scope + full text, as the API stores it) and carries its
  // parts separately, so the list can show a title, a time and the message on their own lines.
  function kernelRuntimeNoteSpec(kind, text, parts) {
    const message = String(text || '').trim();
    if (!message) return null;
    const scope = String(kind || 'note').trim() || 'note';
    const display = parts && typeof parts === 'object' ? parts : {};
    const title = String(display.title || '').trim();
    return {
      key: scope + '|' + message,
      text: message,
      title: title,
      time: String(display.time || '').trim(),
      detail: title ? String(display.detail || '').trim() : message,
      tone: display.tone === 'info' ? 'info' : 'warn'
    };
  }

  function createKernelRuntimeNoteNode(spec) {
    if (!spec || !spec.key || !spec.text) return null;
    const dismissed = ensureKernelRuntimeDismissedNotes();
    if (dismissed[spec.key]) return null;

    const head = spec.title || spec.time
      ? app.createNode('div', {
          className: 'kernel-runtime-note-head',
          children: [
            spec.title ? app.createNode('strong', { className: 'kernel-runtime-note-title', text: spec.title }) : null,
            spec.time ? app.createNode('span', { className: 'kernel-runtime-note-time mono', text: spec.time }) : null
          ].filter(Boolean)
        })
      : null;
    const node = app.createNode('li', {
      className: 'kernel-runtime-note is-' + spec.tone,
      children: [
        app.createNode('span', { className: 'kernel-runtime-note-mark', attrs: { 'aria-hidden': 'true' } }),
        app.createNode('div', {
          className: 'kernel-runtime-note-body',
          children: [
            head,
            spec.detail ? app.createNode('p', { className: 'kernel-runtime-note-text', text: spec.detail }) : null
          ].filter(Boolean)
        })
      ]
    });

    const closeButton = app.createNode('button', {
      className: 'popover-close kernel-runtime-note-close',
      text: '×',
      attrs: {
        type: 'button',
        title: app.t('kernel.note.dismissTitle'),
        'aria-label': app.t('kernel.note.dismiss', { title: spec.title || spec.detail })
      }
    });
    closeButton.addEventListener('click', async () => {
      if (closeButton.disabled) return;
      closeButton.disabled = true;
      try {
        await dismissKernelRuntimeNote(spec.key);
        hideKernelRuntimeTooltip();
        if (typeof app.renderKernelRuntime === 'function') {
          app.renderKernelRuntime();
        }
      } catch (e) {
        closeButton.disabled = false;
        if (e.message !== 'unauthorized') {
          app.notify('error', app.t('errors.actionFailed', {
            action: app.t('kernel.note.dismissTitle'),
            message: app.translateValidationMessage(e.message)
          }));
        }
      }
    });
    node.appendChild(closeButton);

    return node;
  }

  function appendKernelRuntimeNote(container, spec, activeKeys) {
    if (!container || !spec || !spec.key) return;
    if (activeKeys) activeKeys[spec.key] = true;
    const node = createKernelRuntimeNoteNode(spec);
    if (node) container.appendChild(node);
  }

  function kernelRuntimeSummaryNote(labelKey, timestamp, detail, tone) {
    const text = typeof app.translateRuntimeReason === 'function'
      ? app.translateRuntimeReason(detail)
      : String(detail || '').trim();
    if (!text) return null;

    const parts = [app.t(labelKey)];
    const clock = kernelRuntimeTimestampLabel(timestamp);
    if (clock) parts.push(clock);
    parts.push(text);

    return kernelRuntimeNoteSpec(labelKey, parts.join(' · '), {
      title: app.t(labelKey),
      time: clock,
      detail: text,
      tone: tone
    });
  }

  function kernelRuntimeNetlinkRecoveryDetail(data) {
    if (!data || !data.kernel_netlink_recover_pending) return '';
    const parts = [];
    const source = String(data.kernel_netlink_recover_source || '').trim();
    const summary = String(data.kernel_netlink_recover_summary || '').trim();
    const triggerSummary = String(data.kernel_netlink_recover_trigger_summary || '').trim();
    if (source) parts.push('source=' + source);
    if (triggerSummary) parts.push('scope=' + triggerSummary);
    if (summary) parts.push(summary);
    return parts.join(' | ');
  }

  function kernelRuntimeDetailText(engine) {
    if (!engine) return '';
    const parts = [];
    const reconcileDetail = kernelRuntimeReconcileDetail(engine);
    if (reconcileDetail) {
      parts.push('reconcile ' + reconcileDetail);
    }
    const attachmentMode = String(engine.attachment_mode || '').trim().toLowerCase();
    const engineName = String(engine.name || '').trim().toLowerCase();
    if (engineName === 'xdp') {
      if (attachmentMode === 'driver') {
        parts.push(app.t('runtimeReason.xdpDriverMode'));
      } else if (attachmentMode === 'generic') {
        parts.push(app.t('runtimeReason.xdpGenericMode'));
      } else if (attachmentMode === 'mixed') {
        parts.push(app.t('runtimeReason.xdpMixedMode'));
      }
    } else if (engineName === 'tc') {
      // attachment_api is how the programs hang on the device (tcx or
      // cls_bpf); attachment_mode is the core program layout.
      const attachmentAPI = String(engine.attachment_api || '').trim().toLowerCase();
      if (attachmentAPI) parts.push('attach=' + attachmentAPI);
      if (attachmentMode) parts.push('program=' + attachmentMode);
    }
    [
      engine.pressure_reason,
      engine.degraded_reason,
      engine.available_reason,
      engine.attachment_summary
    ].forEach((item) => {
      const text = typeof app.translateRuntimeReason === 'function'
        ? app.translateRuntimeReason(item)
        : String(item || '').trim();
      if (!text) return;
      if (parts.indexOf(text) >= 0) return;
      parts.push(text);
    });
    if (engine.last_maintain_ms || engine.last_maintain_error) {
      const maintainParts = [];
      if (engine.last_maintain_ms) maintainParts.push(String(engine.last_maintain_ms) + 'ms');
      if (engine.last_maintain_at) maintainParts.push('@' + app.formatClock(engine.last_maintain_at));
      if (engine.last_prune_budget || engine.last_prune_scanned || engine.last_prune_deleted) {
        maintainParts.push('prune=' + String(engine.last_prune_scanned || 0) + '/' + String(engine.last_prune_deleted || 0) + '/' + String(engine.last_prune_budget || 0));
      }
      if (engine.last_maintain_error) maintainParts.push('err=' + String(engine.last_maintain_error));
      parts.push('maintain ' + maintainParts.join(' '));
    }
    if (engine.pressure_since) {
      parts.push('pressure_since=' + app.formatClock(engine.pressure_since));
    }
    if (engine.degraded_since) {
      parts.push('degraded_since=' + app.formatClock(engine.degraded_since));
    }
    if (engine.attachments_unhealthy_count) {
      let text = 'attachments_unhealthy=' + String(engine.attachments_unhealthy_count);
      if (engine.last_attachments_unhealthy_at) {
        text += ' last=' + app.formatClock(engine.last_attachments_unhealthy_at);
      }
      parts.push(text);
    }
    if (engine.diagnostics || engine.diagnostics_verbose) {
      parts.push('diag=' + (engine.diagnostics_verbose ? 'verbose' : 'on'));
    }
    const diagParts = [];
    [
      ['fib', engine.diag_fib_non_success],
      ['drop', engine.diag_redirect_drop],
      ['nat_fail', engine.diag_nat_reserve_fail],
      ['recreate', engine.diag_reply_flow_recreated],
      ['oversize', engine.diag_oversize_drop]
    ].forEach(([label, value]) => {
      if (!value) return;
      diagParts.push(label + '=' + String(value));
    });
    if (engine.diagnostics_verbose) {
      [
        ['neigh', engine.diag_redirect_neigh_used],
        ['self_heal', engine.diag_nat_self_heal_insert],
        ['flow_fail', engine.diag_flow_update_fail],
        ['nat_update_fail', engine.diag_nat_update_fail],
        ['rewrite_fail', engine.diag_rewrite_fail],
        ['probe2', engine.diag_nat_probe_round2_used],
        ['probe3', engine.diag_nat_probe_round3_used],
        ['tcp_close_del', engine.diag_tcp_close_delete],
        ['pmtu', engine.diag_pmtu_to_stack],
        ['frag', engine.diag_fragment_forwarded],
        ['flow_cache', engine.diag_flow_cache_hit]
      ].forEach(([label, value]) => {
        if (!value) return;
        diagParts.push(label + '=' + String(value));
      });
    }
    if (diagParts.length) {
      parts.push('diag_counts ' + diagParts.join(' '));
    }
    if (engine.diag_snapshot_error) {
      parts.push('diag_err=' + String(engine.diag_snapshot_error));
    }
    return parts.join(' | ');
  }

  function kernelRuntimeXDPAttachmentModeNote(engines) {
    const xdpEngine = (engines || []).find((engine) => String(engine.name || '').trim().toLowerCase() === 'xdp');
    if (!xdpEngine) return null;

    const mode = String(xdpEngine.attachment_mode || '').trim().toLowerCase();
    let detail = '';
    if (mode === 'generic') detail = app.t('runtimeReason.xdpGenericMode');
    else if (mode === 'mixed') detail = app.t('runtimeReason.xdpMixedMode');
    if (!detail) return null;

    return kernelRuntimeNoteSpec('xdp_attachment_mode', app.t('kernel.note.xdpAttachmentMode') + ' · ' + detail, {
      title: app.t('kernel.note.xdpAttachmentMode'),
      detail: detail
    });
  }

  // A kernel upgrade leaves no module for the new release and the host quietly
  // falls back to the base dataplane; say so and give the rebuild command.
  // Release binaries carry helper support on every host, so one that never
  // installed a module for any kernel runs the base dataplane as intended.
  function kernelRuntimeHelperModuleNote(helper) {
    if (!helper || typeof helper !== 'object' || !helper.compiled || helper.available) return null;
    if (!helper.loaded && helper.module_installed === false && helper.kernel_release) {
      const others = Array.isArray(helper.other_module_releases)
        ? helper.other_module_releases.map((value) => String(value || '').trim()).filter(Boolean)
        : [];
      if (!others.length) return null;
      const parts = [app.t('kernel.note.helperModuleMissing', { release: helper.kernel_release })];
      parts.push(app.t('kernel.note.helperModuleOtherReleases', { releases: others.join(', ') }));
      if (helper.rebuild_command) parts.push(app.t('kernel.note.helperModuleRebuild', { command: helper.rebuild_command }));
      return kernelRuntimeNoteSpec('kernel_helper_module', parts.join(' · '), {
        title: app.t('kernel.helper.title'),
        detail: parts.join(' · ')
      });
    }
    const reason = String(helper.reason || '').trim();
    if (!reason) return null;
    const text = app.t('kernel.note.helperModuleUnavailable') + ' · ' + reason;
    return kernelRuntimeNoteSpec('kernel_helper_module', text, { title: app.t('kernel.helper.title'), detail: text });
  }

  // Native XDP is up to each device's driver, so the kernel reports it per
  // device (Linux 6.3+); older kernels leave it unknown until an attach.
  function kernelXDPNativeDevices(report) {
    return report && typeof report === 'object' && report.available && Array.isArray(report.devices)
      ? report.devices.filter((device) => device && typeof device === 'object')
      : [];
  }

  function kernelXDPNativeSummary(report) {
    if (!report || typeof report !== 'object') return '';
    if (!report.available) return app.t('common.unknown');
    const count = kernelXDPNativeDevices(report).filter((device) => device.native).length;
    return app.t('kernel.capability.xdpNativeCount', { count: count });
  }

  function kernelDeviceNames(devices) {
    return devices.map((device) => String(device.name || '').trim()).filter(Boolean);
  }

  // One line for the summary card: the TC dataplane under the name the engine is shown with,
  // generic and native XDP, and how many netlink checks passed.
  function kernelRuntimeCapabilitySummary(capabilities, xdpNative, runtime) {
    if (!capabilities || typeof capabilities !== 'object') return '';
    const parts = [];
    const stateText = (check) => (check.available ? app.t('kernel.available.yes') : app.t('kernel.available.no'));
    [
      [kernelEngineLabel('tc', runtime), capabilities.tc],
      ['XDP generic', capabilities.xdp_generic]
    ].forEach(([label, check]) => {
      if (!check || typeof check !== 'object') return;
      parts.push(label + ' ' + stateText(check));
    });
    const nativeSummary = kernelXDPNativeSummary(xdpNative);
    if (nativeSummary) parts.push('XDP native ' + nativeSummary);
    const netlink = capabilities.netlink || {};
    const netlinkChecks = [
      netlink.route_socket,
      netlink.link_list,
      netlink.route_list,
      netlink.link_subscribe,
      netlink.address_subscribe,
      netlink.neighbor_subscribe,
      netlink.route_subscribe
    ].filter((check) => check && typeof check === 'object');
    if (netlinkChecks.length) {
      const okCount = netlinkChecks.filter((check) => !!check.available).length;
      parts.push('netlink ' + String(okCount) + '/' + String(netlinkChecks.length));
    }
    return parts.join(' · ');
  }

  function kernelCheckRow(labelKey, check) {
    if (!check || typeof check !== 'object') return null;
    const ok = !!check.available;
    const reason = String(check.reason || '').trim();
    return {
      label: app.t(labelKey),
      value: ok ? app.t('kernel.available.yes') : app.t('kernel.available.no'),
      state: ok ? 'ok' : 'bad',
      hint: ok ? '' : reason
    };
  }

  function kernelChecksSummary(rows) {
    const checks = rows.filter((row) => row && (row.state === 'ok' || row.state === 'bad'));
    if (!checks.length) return null;
    const ok = checks.filter((row) => row.state === 'ok').length;
    return {
      text: app.t('kernel.status.checksAvailable', { ok: ok, total: checks.length }),
      tone: ok === checks.length ? 'ok' : 'bad'
    };
  }

  function kernelStatusGroup(id, titleKey, rows, options) {
    const list = (rows || []).filter(Boolean);
    if (!list.length) return null;
    const opts = options || {};
    const summary = Object.prototype.hasOwnProperty.call(opts, 'summary') ? opts.summary : kernelChecksSummary(list);
    const failing = list.some((row) => row.state === 'bad');
    return {
      id: id,
      title: app.t(titleKey),
      rows: list,
      summary: summary,
      open: !!opts.open || failing
    };
  }

  // Everything the status details show, grouped the way an operator reads it: what is wrong first,
  // then the platform, the dataplane, per-device XDP, BPF features, netlink and the ip tool.
  function kernelRuntimeStatusGroups(data) {
    const runtime = data && typeof data === 'object' ? data : {};
    const caps = runtime.kernel_capabilities && typeof runtime.kernel_capabilities === 'object' ? runtime.kernel_capabilities : {};
    const helper = runtime.kernel_helper_module;
    const groups = [];

    const alerts = [];
    const unavailableReason = String(runtime.available_reason || '').trim();
    if (runtime.available === false && unavailableReason) {
      alerts.push({ tone: 'bad', text: app.t('common.unavailable') + ': ' + unavailableReason });
    }
    (Array.isArray(caps.warnings) ? caps.warnings : []).forEach((warning) => {
      const text = String(warning || '').trim();
      if (text) alerts.push({ tone: 'warn', text: text });
    });
    if (alerts.length) {
      groups.push({
        id: 'warnings',
        title: app.t('kernel.status.group.warnings'),
        alerts: alerts,
        summary: { text: String(alerts.length), tone: 'warn' },
        open: true
      });
    }

    const platformRows = [];
    const osArch = [caps.os, caps.arch].filter(Boolean).join('/');
    if (osArch) platformRows.push({ label: app.t('kernel.capability.platform'), value: osArch, mono: true });
    if (caps.kernel_release) platformRows.push({ label: app.t('kernel.status.kernelRelease'), value: String(caps.kernel_release), mono: true });
    if (helper && typeof helper === 'object' && helper.name) {
      const state = [
        helper.name,
        app.t(helper.loaded ? 'kernel.loaded.yes' : 'kernel.loaded.no'),
        app.t(helper.compiled ? (helper.available ? 'kernel.helper.available' : 'kernel.helper.unavailable') : 'kernel.helper.notCompiled')
      ];
      let tone = 'unknown';
      if (helper.compiled && helper.available) tone = 'ok';
      else if (helper.compiled && (helper.loaded || helper.module_installed)) tone = 'bad';
      platformRows.push({
        label: app.t('kernel.helper.title'),
        value: state.join(' · '),
        state: tone,
        hint: helper.compiled && helper.reason ? String(helper.reason) : ''
      });
    }
    groups.push(kernelStatusGroup('platform', 'kernel.status.group.platform', platformRows, { open: true, summary: null }));

    const attachAPI = kernelTCAttachmentAPI(runtime);
    groups.push(kernelStatusGroup('dataplane', 'kernel.status.group.dataplane', [
      attachAPI ? {
        label: app.t('kernel.status.attachInUse'),
        value: attachAPI === 'tcx' ? app.t('kernel.status.attachTCX') : attachAPI === 'cls_bpf' ? app.t('kernel.status.attachClsBPF') : attachAPI
      } : null,
      kernelCheckRow('kernel.capability.tc', caps.tc),
      kernelCheckRow('kernel.capability.tcx', caps.tcx_attach),
      kernelCheckRow('kernel.capability.tcAttach', caps.tc_attach),
      kernelCheckRow('kernel.capability.xdpGeneric', caps.xdp_generic),
      kernelCheckRow('kernel.capability.xdpGenericAttach', caps.xdp_generic_attach),
      kernelCheckRow('kernel.capability.netfilter', caps.netfilter)
    ], { open: true }));

    const native = runtime.kernel_xdp_native;
    if (native && typeof native === 'object') {
      if (!native.available) {
        const reason = String(native.reason || '').trim();
        groups.push(kernelStatusGroup('xdpNative', 'kernel.status.group.xdpNative', [{
          label: app.t('kernel.capability.xdpNative'),
          value: app.t('common.unknown'),
          state: 'unknown',
          hint: reason
        }], { open: true, summary: { text: app.t('common.unknown'), tone: '' } }));
      } else {
        const devices = kernelXDPNativeDevices(native);
        const nativeDevices = devices.filter((device) => device.native);
        groups.push(kernelStatusGroup('xdpNative', 'kernel.status.group.xdpNative', [
          { label: app.t('kernel.capability.xdpNative'), devices: kernelDeviceNames(nativeDevices) },
          {
            label: app.t('kernel.capability.xdpRedirectTarget'),
            devices: kernelDeviceNames(devices.filter((device) => device.redirect_target)),
            hint: nativeDevices.some((device) => !device.redirect_target) ? app.t('kernel.capability.xdpRedirectTargetHint') : ''
          },
          { label: app.t('kernel.capability.xdpGenericOnly'), devices: kernelDeviceNames(devices.filter((device) => !device.native)) }
        ], {
          open: true,
          summary: { text: app.t('kernel.status.nativeCount', { native: nativeDevices.length, total: devices.length }), tone: '' }
        }));
      }
    }

    const mapRows = [];
    if (runtime.kernel_map_profile) {
      mapRows.push({
        label: app.t('kernel.summary.mapProfile'),
        value: kernelRuntimeMapProfileLabel(runtime.kernel_map_profile),
        hint: kernelRuntimeMapProfileDetail(runtime)
      });
    }
    [
      ['kernel.capability.bpfArray', caps.bpf_map_array],
      ['kernel.capability.bpfHash', caps.bpf_map_hash],
      ['kernel.capability.bpfLRUHash', caps.bpf_map_lru_hash],
      ['kernel.capability.bpfPerCPUHash', caps.bpf_map_percpu_hash],
      ['kernel.capability.bpfPerCPUArray', caps.bpf_map_percpu_array],
      ['kernel.capability.bpfProgArray', caps.bpf_map_prog_array],
      ['kernel.capability.bpfDevMapHash', caps.bpf_map_devmap_hash],
      ['kernel.capability.bpfRingBuf', caps.bpf_map_ringbuf],
      ['kernel.capability.bpfSchedCLS', caps.bpf_sched_cls],
      ['kernel.capability.bpfXDP', caps.bpf_xdp],
      ['kernel.capability.bpfNetfilter', caps.bpf_netfilter]
    ].forEach(([labelKey, check]) => mapRows.push(kernelCheckRow(labelKey, check)));
    groups.push(kernelStatusGroup('maps', 'kernel.status.group.maps', mapRows));

    const netlink = caps.netlink || {};
    groups.push(kernelStatusGroup('netlink', 'kernel.status.group.netlink', [
      ['kernel.capability.netlinkRouteSocket', netlink.route_socket],
      ['kernel.capability.netlinkLinkList', netlink.link_list],
      ['kernel.capability.netlinkRouteList', netlink.route_list],
      ['kernel.capability.netlinkLinkSubscribe', netlink.link_subscribe],
      ['kernel.capability.netlinkAddressSubscribe', netlink.address_subscribe],
      ['kernel.capability.netlinkNeighborSubscribe', netlink.neighbor_subscribe],
      ['kernel.capability.netlinkRouteSubscribe', netlink.route_subscribe]
    ].map(([labelKey, check]) => kernelCheckRow(labelKey, check))));

    const ipRoute = caps.ip_route || {};
    groups.push(kernelStatusGroup('ipRoute', 'kernel.status.group.ipRoute', [
      kernelCheckRow('kernel.capability.ipCommand', ipRoute.command),
      kernelCheckRow('kernel.capability.ipRuleShow', ipRoute.rule_show),
      kernelCheckRow('kernel.capability.ipRouteShow', ipRoute.route_show),
      ipRoute.path ? { label: app.t('kernel.capability.ipPath'), value: String(ipRoute.path), mono: true } : null
    ]));

    return groups.filter(Boolean);
  }

  app.kernelRuntimeStatusGroups = kernelRuntimeStatusGroups;

  function kernelDeviceChips(names) {
    if (!names.length) return app.createNode('span', { className: 'popover-muted', text: app.t('common.dash') });
    return app.createNode('span', {
      className: 'popover-chips',
      children: names.map((name) => app.createNode('span', { className: 'popover-chip mono', text: name }))
    });
  }

  function kernelStatusGroupNode(group) {
    const children = [];
    if (group.alerts) {
      children.push(app.createNode('ul', {
        className: 'popover-list',
        children: group.alerts.map((alert) => app.createNode('li', {
          className: 'popover-list-item is-' + alert.tone,
          children: [app.createNode('span', { className: 'popover-list-text', text: alert.text })]
        }))
      }));
    }
    if (group.rows) {
      children.push(app.popoverRows(group.rows.map((row) => (
        row.devices ? Object.assign({}, row, { node: kernelDeviceChips(row.devices) }) : row
      ))));
    }
    return app.popoverSection({
      className: 'kernel-status-group is-' + group.id,
      title: group.title,
      summary: group.summary ? group.summary.text : '',
      tone: group.summary ? group.summary.tone : '',
      open: group.open,
      collapsible: group.id !== 'warnings',
      children: children
    });
  }

  function kernelRuntimeStatusDetailsNode(data) {
    const groups = kernelRuntimeStatusGroups(data);
    if (!groups.length) return null;
    const warnings = groups.find((group) => group.id === 'warnings');
    const warningCount = warnings ? warnings.alerts.length : 0;
    const button = app.createNode('button', {
      className: 'kernel-runtime-detail-trigger kernel-runtime-status-trigger' + (warningCount ? ' is-warning' : ''),
      text: warningCount ? app.t('kernel.status.detailsWithWarnings', { count: warningCount }) : app.t('kernel.engine.details'),
      attrs: {
        type: 'button',
        'aria-haspopup': 'dialog',
        'aria-controls': 'kernelRuntimeStatusDetails',
        'aria-expanded': 'false'
      }
    });
    bindKernelRuntimePanel(button, (close) => [
      app.popoverHeader({ title: app.t('kernel.summary.status'), onClose: close }),
      app.createNode('div', {
        className: 'popover-sections',
        children: kernelRuntimeStatusGroups(app.state.kernelRuntime && app.state.kernelRuntime.data || data).map(kernelStatusGroupNode)
      })
    ], app.t('kernel.summary.status'));
    return button;
  }

  // Engine details as label | value rows; the reconcile badge shows the reconcile rows only.
  function kernelRuntimeEngineDetailRows(engine) {
    if (!engine) return [];
    const rows = [];
    const lower = (value) => String(value || '').trim().toLowerCase();
    const name = lower(engine.name);
    const mode = lower(engine.attachment_mode);
    if (name === 'tc') {
      const api = lower(engine.attachment_api);
      if (api) {
        rows.push({
          label: app.t('kernel.engineDetail.attach'),
          value: api === 'tcx' ? app.t('kernel.status.attachTCX') : api === 'cls_bpf' ? app.t('kernel.status.attachClsBPF') : api
        });
      }
      if (mode) rows.push({ label: app.t('kernel.engineDetail.program'), value: mode, mono: true });
    } else if (name === 'xdp') {
      const xdpMode = mode === 'driver' ? 'runtimeReason.xdpDriverMode' : mode === 'generic' ? 'runtimeReason.xdpGenericMode' : mode === 'mixed' ? 'runtimeReason.xdpMixedMode' : '';
      if (xdpMode) rows.push({ label: app.t('kernel.engineDetail.xdpMode'), value: app.t(xdpMode) });
    }

    const seen = [];
    [engine.pressure_reason, engine.degraded_reason, engine.available_reason, engine.attachment_summary].forEach((item) => {
      const text = typeof app.translateRuntimeReason === 'function'
        ? app.translateRuntimeReason(item)
        : String(item || '').trim();
      if (!text || seen.indexOf(text) >= 0) return;
      seen.push(text);
      rows.push({ label: app.t('kernel.engineDetail.reason'), value: text, tone: engine.degraded ? 'warn' : '' });
    });

    const reconcile = [];
    const duration = kernelRuntimeDurationLabel(engine.last_reconcile_ms);
    if (duration) reconcile.push(duration);
    if (engine.last_reconcile_at) reconcile.push(app.formatClock(engine.last_reconcile_at));
    if (engine.last_reconcile_mode) reconcile.push(kernelRuntimeModeLabel(engine.last_reconcile_mode));
    if (reconcile.length) rows.push({ label: app.t('kernel.engineDetail.reconcile'), value: reconcile.join(' · '), group: 'reconcile' });
    if (
      engine.last_reconcile_request_entries || engine.last_reconcile_prepared_entries || engine.last_reconcile_applied_entries ||
      engine.last_reconcile_upserts || engine.last_reconcile_deletes || engine.last_reconcile_attaches ||
      engine.last_reconcile_detaches || engine.last_reconcile_preserved || engine.last_reconcile_flow_purge_deleted
    ) {
      rows.push({
        label: app.t('kernel.engineDetail.reconcileCounts'),
        value: [
          'req=' + String(engine.last_reconcile_request_entries || 0),
          'prep=' + String(engine.last_reconcile_prepared_entries || 0),
          'applied=' + String(engine.last_reconcile_applied_entries || 0),
          'upsert=' + String(engine.last_reconcile_upserts || 0),
          'delete=' + String(engine.last_reconcile_deletes || 0),
          'attach=' + String(engine.last_reconcile_attaches || 0),
          'detach=' + String(engine.last_reconcile_detaches || 0),
          'preserve=' + String(engine.last_reconcile_preserved || 0),
          'purge=' + String(engine.last_reconcile_flow_purge_deleted || 0)
        ].join(' '),
        mono: true,
        group: 'reconcile'
      });
    }
    const phases = [];
    if (engine.last_reconcile_prepare_ms) phases.push('prepare=' + kernelRuntimeDurationLabel(engine.last_reconcile_prepare_ms));
    if (engine.last_reconcile_attach_ms) phases.push('attach=' + kernelRuntimeDurationLabel(engine.last_reconcile_attach_ms));
    if (engine.last_reconcile_flow_purge_ms) phases.push('purge=' + kernelRuntimeDurationLabel(engine.last_reconcile_flow_purge_ms));
    if (phases.length) rows.push({ label: app.t('kernel.engineDetail.reconcilePhases'), value: phases.join(' '), mono: true, group: 'reconcile' });
    if (engine.last_reconcile_error) {
      rows.push({ label: app.t('kernel.engineDetail.reconcileError'), value: String(engine.last_reconcile_error), tone: 'bad', group: 'reconcile' });
    }

    if (engine.last_maintain_ms || engine.last_maintain_at) {
      const maintain = [];
      if (engine.last_maintain_ms) maintain.push(String(engine.last_maintain_ms) + 'ms');
      if (engine.last_maintain_at) maintain.push(app.formatClock(engine.last_maintain_at));
      if (engine.last_prune_budget || engine.last_prune_scanned || engine.last_prune_deleted) {
        maintain.push('prune ' + String(engine.last_prune_scanned || 0) + '/' + String(engine.last_prune_deleted || 0) + '/' + String(engine.last_prune_budget || 0));
      }
      rows.push({ label: app.t('kernel.engineDetail.maintain'), value: maintain.join(' · '), mono: true });
    }
    if (engine.last_maintain_error) {
      rows.push({ label: app.t('kernel.engineDetail.maintainError'), value: String(engine.last_maintain_error), tone: 'bad' });
    }
    if (engine.pressure_since) rows.push({ label: app.t('kernel.engineDetail.pressureSince'), value: app.formatClock(engine.pressure_since) });
    if (engine.degraded_since) rows.push({ label: app.t('kernel.engineDetail.degradedSince'), value: app.formatClock(engine.degraded_since), tone: 'warn' });
    if (engine.attachments_unhealthy_count) {
      rows.push({
        label: app.t('kernel.engineDetail.unhealthy'),
        value: String(engine.attachments_unhealthy_count) + (engine.last_attachments_unhealthy_at ? ' · ' + app.formatClock(engine.last_attachments_unhealthy_at) : ''),
        tone: 'warn'
      });
    }
    if (engine.diagnostics || engine.diagnostics_verbose) {
      rows.push({ label: app.t('kernel.engineDetail.diagnostics'), value: engine.diagnostics_verbose ? 'verbose' : 'on', mono: true });
    }
    const counters = [];
    [
      ['fib', engine.diag_fib_non_success],
      ['drop', engine.diag_redirect_drop],
      ['nat_fail', engine.diag_nat_reserve_fail],
      ['recreate', engine.diag_reply_flow_recreated],
      ['oversize', engine.diag_oversize_drop]
    ].concat(engine.diagnostics_verbose ? [
      ['neigh', engine.diag_redirect_neigh_used],
      ['self_heal', engine.diag_nat_self_heal_insert],
      ['flow_fail', engine.diag_flow_update_fail],
      ['nat_update_fail', engine.diag_nat_update_fail],
      ['rewrite_fail', engine.diag_rewrite_fail],
      ['probe2', engine.diag_nat_probe_round2_used],
      ['probe3', engine.diag_nat_probe_round3_used],
      ['tcp_close_del', engine.diag_tcp_close_delete],
      ['pmtu', engine.diag_pmtu_to_stack],
      ['frag', engine.diag_fragment_forwarded],
      ['flow_cache', engine.diag_flow_cache_hit]
    ] : []).forEach(([label, value]) => {
      if (value) counters.push(label + '=' + String(value));
    });
    if (counters.length) rows.push({ label: app.t('kernel.engineDetail.diagCounts'), value: counters.join(' '), mono: true });
    if (engine.diag_snapshot_error) {
      rows.push({ label: app.t('kernel.engineDetail.diagError'), value: String(engine.diag_snapshot_error), tone: 'bad' });
    }
    return rows;
  }

  app.kernelRuntimeEngineDetailRows = kernelRuntimeEngineDetailRows;

  function kernelRuntimeReconcileNode(engine) {
    if (!engine) return app.emptyCellNode('stat-muted');

    const modeText = kernelRuntimeModeLabel(engine.last_reconcile_mode);
    const rows = kernelRuntimeEngineDetailRows(engine).filter((row) => row.group === 'reconcile');
    const badge = app.createNode('span', {
      className: 'badge ' + (engine.last_reconcile_error ? 'badge-error' : 'badge-disabled') + (rows.length ? ' kernel-runtime-reconcile-badge' : ''),
      text: modeText || app.t('common.dash'),
      attrs: rows.length ? {
        tabindex: '0',
        role: 'button',
        'aria-describedby': 'kernelRuntimeFloatingTooltip',
        'aria-expanded': 'false'
      } : null
    });

    if (rows.length) {
      bindKernelRuntimeTooltip(badge, () => [
        app.popoverHeader({ title: app.t('kernel.engine.reconcile'), meta: kernelEngineLabel(engine.name) }),
        app.popoverRows(rows)
      ]);
    }

    return badge;
  }

  function kernelRuntimeDegradedSummaryText(engines) {
    const degraded = (engines || []).filter((engine) => !!engine.degraded);
    if (!degraded.length) return '';
    return degraded.map((engine) => {
      const label = kernelEngineLabel(engine.name) || app.t('common.dash');
      const detail = kernelRuntimeDetailText(engine) || app.t('kernel.summary.degradedValue', { engine: label });
      return label + ': ' + detail;
    }).join('; ');
  }

  function kernelRuntimeDetailNode(engine) {
    const rows = kernelRuntimeEngineDetailRows(engine);
    if (!rows.length) return app.emptyCellNode('stat-muted');
    const warn = !!engine.degraded || !!engine.pressure_active;
    const title = app.t('kernel.engineDetail.title', { engine: kernelEngineLabel(engine.name) || app.t('common.dash') });

    const button = app.createNode('button', {
      className: 'kernel-runtime-detail-trigger' + (warn ? ' is-warning' : ''),
      text: app.t(warn ? 'kernel.degraded.yes' : 'kernel.engine.details'),
      attrs: {
        type: 'button',
        'aria-label': title,
        'aria-describedby': 'kernelRuntimeFloatingTooltip',
        'aria-expanded': 'false'
      }
    });

    bindKernelRuntimeTooltip(button, () => [
      app.popoverHeader({ title: title, meta: kernelEngineTitle(engine.name), metaMono: false }),
      app.popoverRows(rows)
    ]);

    return button;
  }

  function applyCurrentConnsSnapshot(payload) {
    const next = {
      loaded: true,
      rules: {},
      sites: {},
      ranges: {},
      egressNATs: {}
    };

    (payload && payload.rules ? payload.rules : []).forEach((item) => {
      next.rules[item.rule_id] = item.current_conns || 0;
    });
    (payload && payload.sites ? payload.sites : []).forEach((item) => {
      next.sites[item.site_id] = item.current_conns || 0;
    });
    (payload && payload.ranges ? payload.ranges : []).forEach((item) => {
      next.ranges[item.range_id] = item.current_conns || 0;
    });
    (payload && payload.egress_nats ? payload.egress_nats : []).forEach((item) => {
      next.egressNATs[item.egress_nat_id] = item.current_conns || 0;
    });

    app.state.currentConnsSnapshot = next;
    app.state.ruleStats.data = rebuildCurrentConns('rules', app.state.ruleStats.data, 'rule_id');
    app.state.siteStats.data = rebuildCurrentConns('sites', app.state.siteStats.data, 'site_id');
    app.state.rangeStats.data = rebuildCurrentConns('ranges', app.state.rangeStats.data, 'range_id');
    app.state.egressNATStats.data = rebuildCurrentConns('egressNATs', app.state.egressNATStats.data, 'egress_nat_id');
  }

  app.renderKernelRuntime = function renderKernelRuntime() {
    const el = app.el;
    const data = app.state.kernelRuntime.data;
    hideKernelRuntimeTooltip();
    app.clearNode(el.kernelRuntimeSummary);
    app.clearNode(el.kernelRuntimeBody);

    if (!data) {
      pruneKernelRuntimeDismissedNotes({});
      el.noKernelRuntime.style.display = 'block';
      app.toggleTableVisibility('kernelRuntimeTable', false);
      return;
    }

    const configuredOrder = Array.isArray(data.configured_order) ? data.configured_order : [];
    const engines = Array.isArray(data.engines) ? data.engines : [];
    const pressureSummary = kernelRuntimePressureSummary(engines);
    const configuredOrderNodes = configuredOrder.length
      ? configuredOrder.map((name) => kernelEngineBadge(name, data))
      : [app.emptyCellNode('stat-muted')];
    const capabilitySummary = kernelRuntimeCapabilitySummary(data.kernel_capabilities, data.kernel_xdp_native, data);
    const statusDetails = kernelRuntimeStatusDetailsNode(data);

    const summaryFragment = document.createDocumentFragment();
    summaryFragment.appendChild(kernelRuntimeSummaryCard(
      'kernel.summary.status',
      kernelRuntimeSummaryInline([
        kernelStatePill(!!data.available, 'kernel.available.yes', 'kernel.available.no'),
        kernelDefaultEngineBadge(data.default_engine)
      ]),
      [
        kernelRuntimeSummaryInline([
          app.createNode('span', {
            className: 'kernel-runtime-sub-label',
            text: app.t('kernel.summary.configuredOrder')
          }),
          app.createNode('span', { className: 'kernel-runtime-engine-order', children: configuredOrderNodes })
        ]),
        data.kernel_map_profile
          ? kernelRuntimeSummaryInline([
              app.createNode('span', { className: 'kernel-runtime-sub-label', text: app.t('kernel.summary.mapProfile') }),
              app.createNode('span', { text: kernelRuntimeMapProfileLabel(data.kernel_map_profile) })
            ])
          : null,
        capabilitySummary
          ? kernelRuntimeSummaryInline([
              app.createNode('span', { className: 'kernel-runtime-sub-label', text: app.t('kernel.summary.capabilities') }),
              app.createNode('span', { className: 'kernel-runtime-capabilities', text: capabilitySummary })
            ])
          : null,
        statusDetails ? kernelRuntimeSummaryInline([statusDetails]) : null
      ].filter(Boolean)
    ));
    summaryFragment.appendChild(kernelRuntimeSummaryCard(
      'kernel.summary.activeKernel',
      app.t('kernel.summary.activeKernelValue', {
        rules: data.active_rule_count || 0,
        ranges: data.active_range_count || 0
      }),
      kernelRuntimeSummaryInline([
        kernelStatePill(!!data.traffic_stats, 'kernel.traffic.enabled', 'kernel.traffic.disabled'),
        kernelFlowCachePill(data),
        app.createNode('span', {
          text: app.t(data.retry_pending ? 'kernel.retry.pending' : 'kernel.retry.idle')
        })
      ])
    ));
    summaryFragment.appendChild(kernelRuntimeSummaryCard(
      'kernel.summary.pressure',
      kernelRuntimePressureBadge(pressureSummary.level),
      [
        app.createNode('div', {
          text: pressureSummary.subtext
        }),
        app.createNode('div', {
          text: app.t('kernel.summary.fallbacksValue', {
            rules: data.kernel_fallback_rule_count || 0,
            ranges: data.kernel_fallback_range_count || 0
          })
        }),
        app.createNode('div', {
          text: app.t('kernel.summary.transientFallbacksValue', {
            rules: data.transient_fallback_rule_count || 0,
            ranges: data.transient_fallback_range_count || 0
          })
        })
      ]
    ));
    const retryDetails = [
      app.createNode('div', {
        text: app.t('kernel.summary.incrementalMatchedValue', {
          rules: data.last_kernel_incremental_retry_matched_rule_owners || 0,
          ranges: data.last_kernel_incremental_retry_matched_range_owners || 0
        })
      }),
      app.createNode('div', {
        text: app.t('kernel.summary.incrementalAttemptedValue', {
          rules: data.last_kernel_incremental_retry_attempted_rule_owners || 0,
          ranges: data.last_kernel_incremental_retry_attempted_range_owners || 0
        })
      }),
      app.createNode('div', {
        text: app.t('kernel.summary.incrementalRecoveredValue', {
          rules: data.last_kernel_incremental_retry_recovered_rule_owners || 0,
          ranges: data.last_kernel_incremental_retry_recovered_range_owners || 0
        })
      }),
      app.createNode('div', {
        text: app.t('kernel.summary.incrementalRetainedValue', {
          rules: data.last_kernel_incremental_retry_retained_rule_owners || 0,
          ranges: data.last_kernel_incremental_retry_retained_range_owners || 0
        })
      }),
      app.createNode('div', {
        text: app.t('kernel.summary.retryFallbackValue', {
          count: data.kernel_incremental_retry_fallback_count || 0
        }) + (kernelRuntimeTimestampLabel(data.last_kernel_incremental_retry_at) ? (' @ ' + kernelRuntimeTimestampLabel(data.last_kernel_incremental_retry_at)) : '')
      })
    ];
    if ((data.last_kernel_incremental_retry_cooldown_rule_owners || 0) > 0 || (data.last_kernel_incremental_retry_cooldown_range_owners || 0) > 0) {
      retryDetails.push(app.createNode('div', {
        text: app.t('kernel.summary.incrementalCooldownValue', {
          rules: data.last_kernel_incremental_retry_cooldown_rule_owners || 0,
          ranges: data.last_kernel_incremental_retry_cooldown_range_owners || 0
        }) +
          (data.last_kernel_incremental_retry_cooldown_summary ? (' | ' + data.last_kernel_incremental_retry_cooldown_summary) : '') +
          (data.last_kernel_incremental_retry_cooldown_scope ? (' | ' + data.last_kernel_incremental_retry_cooldown_scope) : '')
      }));
    }
    if ((data.last_kernel_incremental_retry_backoff_rule_owners || 0) > 0 || (data.last_kernel_incremental_retry_backoff_range_owners || 0) > 0) {
      const backoffDuration = kernelRuntimeDurationLabel(data.last_kernel_incremental_retry_backoff_max_delay_ms);
      let text = app.t('kernel.summary.incrementalBackoffValue', {
        rules: data.last_kernel_incremental_retry_backoff_rule_owners || 0,
        ranges: data.last_kernel_incremental_retry_backoff_range_owners || 0
      });
      if (data.last_kernel_incremental_retry_backoff_summary) {
        text += ' | ' + data.last_kernel_incremental_retry_backoff_summary;
      }
      if (data.last_kernel_incremental_retry_backoff_scope) {
        text += ' | ' + data.last_kernel_incremental_retry_backoff_scope;
      }
      if (data.last_kernel_incremental_retry_backoff_max_failures) {
        text += ' | max_failures=' + String(data.last_kernel_incremental_retry_backoff_max_failures);
      }
      if (backoffDuration) {
        text += ' | max_delay=' + backoffDuration;
      }
      retryDetails.push(app.createNode('div', { text: text }));
    }
    if ((data.cooldown_rule_owner_count || 0) > 0 || (data.cooldown_range_owner_count || 0) > 0) {
      const cooldownWindow = kernelRuntimeCooldownWindowLabel(data.cooldown_next_expiry_at, data.cooldown_clear_at);
      retryDetails.push(app.createNode('div', {
        text: app.t('kernel.summary.activeCooldownValue', {
          rules: data.cooldown_rule_owner_count || 0,
          ranges: data.cooldown_range_owner_count || 0
        }) +
          (data.cooldown_summary ? (' | ' + data.cooldown_summary) : '') +
          (cooldownWindow ? (' | ' + cooldownWindow) : '')
      }));
    }
    summaryFragment.appendChild(kernelRuntimeSummaryCard(
      'kernel.summary.retry',
      app.t('kernel.summary.retryValue', {
        full: data.kernel_retry_count || 0,
        incremental: data.kernel_incremental_retry_count || 0
      }),
      retryDetails
    ));
    el.kernelRuntimeSummary.appendChild(summaryFragment);

    // Notes form one list under the cards: each has a tone mark, a title and time, the message and
    // its own dismiss button, so several of them stay aligned instead of stacking as boxes.
    const activeKernelRuntimeNotes = {};
    const notes = app.createNode('ul', {
      className: 'kernel-runtime-notes',
      attrs: { 'aria-label': app.t('kernel.note.listLabel') }
    });
    [
      kernelRuntimeNoteSpec('transient_fallback_summary', data.transient_fallback_summary, {
        title: app.t('kernel.note.transientFallback'),
        detail: data.transient_fallback_summary
      }),
      kernelRuntimeSummaryNote('kernel.note.lastRetry', data.last_kernel_retry_at, data.last_kernel_retry_reason),
      kernelRuntimeSummaryNote('kernel.note.lastIncrementalRetry', data.last_kernel_incremental_retry_at, data.last_kernel_incremental_retry_result),
      kernelRuntimeSummaryNote(
        'kernel.note.pendingNetlinkRecovery',
        data.kernel_netlink_recover_requested_at,
        kernelRuntimeNetlinkRecoveryDetail(data)
      ),
      kernelRuntimeSummaryNote('kernel.note.attachmentIssue', '', data.last_kernel_attachment_issue),
      kernelRuntimeSummaryNote(
        'kernel.note.lastAttachmentHealError',
        data.last_kernel_attachment_heal_at,
        data.last_kernel_attachment_heal_error
      ),
      kernelRuntimeSummaryNote(
        'kernel.note.lastAttachmentHeal',
        data.last_kernel_attachment_heal_at,
        data.last_kernel_attachment_heal_summary,
        'info'
      ),
      (() => {
        const degradedSummary = kernelRuntimeDegradedSummaryText(engines);
        return degradedSummary
          ? kernelRuntimeNoteSpec('degraded_summary', app.t('kernel.summary.degraded') + ': ' + degradedSummary, {
              title: app.t('kernel.summary.degraded'),
              detail: degradedSummary
            })
          : null;
      })(),
      kernelRuntimeXDPAttachmentModeNote(engines),
      kernelRuntimeHelperModuleNote(data.kernel_helper_module)
    ].forEach((spec) => appendKernelRuntimeNote(notes, spec, activeKernelRuntimeNotes));
    if (notes.childNodes.length) el.kernelRuntimeSummary.appendChild(notes);
    pruneKernelRuntimeDismissedNotes(activeKernelRuntimeNotes);

    if (!engines.length) {
      el.noKernelRuntime.style.display = 'block';
      app.toggleTableVisibility('kernelRuntimeTable', false);
      return;
    }

    el.noKernelRuntime.style.display = 'none';
    app.toggleTableVisibility('kernelRuntimeTable', true);

    const fragment = document.createDocumentFragment();
    engines.forEach((engine) => {
      const tr = document.createElement('tr');
      const pressureLevel = kernelRuntimePressureLevel(engine);
      tr.appendChild(app.createCell(kernelEngineBadge(engine.name, data), 'stat-mono'));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.available, 'kernel.available.yes', 'kernel.available.no')));
      tr.appendChild(app.createCell(kernelRuntimePressureBadge(pressureLevel, engine.pressure_reason || '')));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.loaded, 'kernel.loaded.yes', 'kernel.loaded.no')));
      tr.appendChild(app.createCell(String(engine.active_entries || 0), 'stat-mono'));
      tr.appendChild(app.createCell(String(engine.attachments || 0), 'stat-mono'));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.attachments_healthy, 'kernel.attachments.healthy', 'kernel.attachments.degraded')));
      tr.appendChild(app.createCell(kernelRuntimeMapsNode(engine, data), 'kernel-runtime-maps'));
      tr.appendChild(app.createCell(kernelRuntimeReconcileNode(engine)));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.traffic_stats, 'kernel.traffic.enabled', 'kernel.traffic.disabled')));
      tr.appendChild(app.createCell(
        kernelRuntimeDetailNode(engine),
        'kernel-runtime-detail-cell'
      ));
      fragment.appendChild(tr);
    });
    el.kernelRuntimeBody.appendChild(fragment);
  };

  app.renderRuleStatsTable = function renderRuleStatsTable() {
    const el = app.el;
    const st = app.state.ruleStats;
    const list = Array.isArray(st.data) ? st.data : [];
    const total = typeof st.total === 'number' ? st.total : list.length;
    app.clearNode(el.ruleStatsBody);
    app.updateSortIndicators('ruleStatsTable', st);
    app.renderPagination('ruleStats', total);

    if (!list.length) {
      el.noRuleStats.style.display = 'block';
      app.toggleTableVisibility('ruleStatsTable', false);
      return;
    }
    el.noRuleStats.style.display = 'none';
    app.toggleTableVisibility('ruleStatsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((s) => {
      const rule = findRuleConfig(s.rule_id);
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.rule_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.remark ? s.remark : app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(ruleStatsTargetCellNode(rule)));
      tr.appendChild(app.createCell(currentConnsCellNode(s.current_conns)));
      tr.appendChild(app.createCell(String(s.total_conns)));
      tr.appendChild(app.createCell(String(s.rejected_conns)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_in)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_out)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_in)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_out)));
      fragment.appendChild(tr);
    });
    el.ruleStatsBody.appendChild(fragment);
  };

  app.renderSiteStatsTable = function renderSiteStatsTable() {
    const el = app.el;
    const st = app.state.siteStats;
    const sortedList = app.sortByState(st.data, st, statSortValue);
    const list = app.paginateList(st, sortedList).items;
    app.clearNode(el.siteStatsBody);
    app.updateSortIndicators('siteStatsTable', st);
    app.renderPagination('siteStats', sortedList.length);

    if (!sortedList.length) {
      el.noSiteStats.style.display = 'block';
      app.toggleTableVisibility('siteStatsTable', false);
      return;
    }
    el.noSiteStats.style.display = 'none';
    app.toggleTableVisibility('siteStatsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((s) => {
      const site = findSiteConfig(s.site_id);
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.site_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.domain ? s.domain : app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(siteStatsTargetCellNode(site)));
      tr.appendChild(app.createCell(currentConnsCellNode(s.current_conns)));
      tr.appendChild(app.createCell(String(s.total_conns)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_in)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_out)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_in)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_out)));
      fragment.appendChild(tr);
    });
    el.siteStatsBody.appendChild(fragment);
  };

  app.renderRangeStatsTable = function renderRangeStatsTable() {
    const el = app.el;
    const st = app.state.rangeStats;
    const list = Array.isArray(st.data) ? st.data : [];
    const total = typeof st.total === 'number' ? st.total : list.length;
    app.clearNode(el.rangeStatsBody);
    app.updateSortIndicators('rangeStatsTable', st);
    app.renderPagination('rangeStats', total);

    if (!list.length) {
      el.noRangeStats.style.display = 'block';
      app.toggleTableVisibility('rangeStatsTable', false);
      return;
    }
    el.noRangeStats.style.display = 'none';
    app.toggleTableVisibility('rangeStatsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((s) => {
      const range = findRangeConfig(s.range_id);
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.range_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.remark ? s.remark : app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(rangeStatsTargetCellNode(range)));
      tr.appendChild(app.createCell(currentConnsCellNode(s.current_conns)));
      tr.appendChild(app.createCell(String(s.total_conns)));
      tr.appendChild(app.createCell(String(s.rejected_conns)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_in)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_out)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_in)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_out)));
      fragment.appendChild(tr);
    });
    el.rangeStatsBody.appendChild(fragment);
  };

  app.renderEgressNATStatsTable = function renderEgressNATStatsTable() {
    const el = app.el;
    const st = app.state.egressNATStats;
    const list = Array.isArray(st.data) ? st.data : [];
    const total = typeof st.total === 'number' ? st.total : list.length;
    app.clearNode(el.egressNATStatsBody);
    app.updateSortIndicators('egressNATStatsTable', st);
    app.renderPagination('egressNATStats', total);

    if (!list.length) {
      el.noEgressNATStats.style.display = 'block';
      app.toggleTableVisibility('egressNATStatsTable', false);
      return;
    }
    el.noEgressNATStats.style.display = 'none';
    app.toggleTableVisibility('egressNATStatsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((s) => {
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(
        egressNATStatsIDCellContent(s.egress_nat_id),
        Number(s.egress_nat_id) < 0 ? '' : 'stat-mono'
      ));
      tr.appendChild(app.createCell(s.parent_interface || app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(
        typeof app.formatEgressNATStatsChildScope === 'function'
          ? app.formatEgressNATStatsChildScope(s.child_interface, s.parent_interface)
          : (s.child_interface || app.emptyCellNode('stat-muted'))
      ));
      tr.appendChild(app.createCell(s.out_interface || app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(s.out_source_ip || app.emptyCellNode('stat-muted')));
      tr.appendChild(app.createCell(
        egressNATStatsProtocolNode(s.protocol || '')
      ));
      tr.appendChild(app.createCell(
        typeof app.formatEgressNATNatType === 'function'
          ? app.formatEgressNATNatType(s.nat_type || '')
          : String(s.nat_type || '')
      ));
      tr.appendChild(app.createCell(currentConnsCellNode(s.current_conns)));
      tr.appendChild(app.createCell(String(s.total_conns)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_in)));
      tr.appendChild(app.createCell(app.formatSpeed(s.speed_out)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_in)));
      tr.appendChild(app.createCell(app.formatBytes(s.bytes_out)));
      fragment.appendChild(tr);
    });
    el.egressNATStatsBody.appendChild(fragment);
  };

  function kernelDataplaneVisibleFromRuntime(runtime) {
    if (!runtime || typeof runtime !== 'object') return true;
    const engines = Array.isArray(runtime.engines) ? runtime.engines : [];
    const anyAvailableEngine = engines.some((engine) => engine && engine.available);
    return !!runtime.available || anyAvailableEngine;
  }

  function setHiddenByID(id, hidden) {
    const node = typeof app.$ === 'function' ? app.$(id) : document.getElementById(id);
    if (!node) return;
    node.hidden = !!hidden;
  }

  app.kernelFeatureVisible = function kernelFeatureVisible(name) {
    const state = app.state.kernelFeatureVisibility || {};
    if (!state.loaded) return true;
    return state[name] !== false;
  };

  app.computeKernelFeatureVisibility = function computeKernelFeatureVisibility(runtime) {
    const loaded = !!runtime && typeof runtime === 'object';
    const kernelVisible = loaded ? kernelDataplaneVisibleFromRuntime(runtime) : true;
    return {
      loaded: loaded,
      egressNAT: kernelVisible,
      managedNetworkAutoEgressNAT: kernelVisible
    };
  };

  app.applyKernelFeatureVisibility = function applyKernelFeatureVisibility(runtime) {
    if (runtime && typeof runtime === 'object') {
      app.state.kernelFeatureVisibility = app.computeKernelFeatureVisibility(runtime);
    } else if (!app.state.kernelFeatureVisibility) {
      app.state.kernelFeatureVisibility = app.computeKernelFeatureVisibility(null);
    }

    const showEgressNAT = app.kernelFeatureVisible('egressNAT');
    setHiddenByID('tab-egress-nats-button', !showEgressNAT);
    setHiddenByID('tab-egress-nats', !showEgressNAT);
    setHiddenByID('egressNATStatsSection', !showEgressNAT);

    if (!showEgressNAT && app.state.activeTab === 'egress-nats' && typeof app.activateTab === 'function') {
      const fallback = typeof app.firstVisibleTabId === 'function' ? app.firstVisibleTabId() : 'rules';
      if (fallback && fallback !== 'egress-nats') {
        app.activateTab(fallback, { persist: true, skipLoad: true });
      }
    }

    if (typeof app.syncManagedNetworkKernelFeatureVisibility === 'function') {
      app.syncManagedNetworkKernelFeatureVisibility();
    }
  };

  app.loadKernelRuntime = async function loadKernelRuntime() {
    try {
      app.state.kernelRuntime.data = await app.apiCall('GET', '/api/kernel/runtime');
      app.applyKernelFeatureVisibility(app.state.kernelRuntime.data);
      syncKernelRuntimeDismissedNotes(app.state.kernelRuntime.data);
      app.renderKernelRuntime();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load kernel runtime:', e);
    }
  };

  app.loadRuleStats = async function loadRuleStats() {
    try {
      const st = app.state.ruleStats;
      const payload = await app.apiCall('GET', '/api/rules/stats?' + buildStatsQuery(st));

      st.page = payload && payload.page ? payload.page : st.page;
      st.pageSize = payload && payload.page_size ? payload.page_size : st.pageSize;
      st.total = payload && typeof payload.total === 'number' ? payload.total : 0;
      st.data = ((payload && payload.items) || []).map((s) => {
        return {
          rule_id: s.rule_id,
          remark: s.remark || '',
          current_conns: getCurrentConnValue('rules', s.rule_id),
          total_conns: s.total_conns || 0,
          rejected_conns: s.rejected_conns || 0,
          speed_in: s.speed_in || 0,
          speed_out: s.speed_out || 0,
          bytes_in: s.bytes_in || 0,
          bytes_out: s.bytes_out || 0
        };
      });

      app.renderRuleStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load rule stats:', e);
    }
  };

  app.loadSiteStats = async function loadSiteStats() {
    try {
      const stats = await app.apiCall('GET', '/api/sites/stats');
      app.state.siteStats.data = (stats || []).map((s) => ({
        site_id: s.site_id,
        domain: s.domain || '',
        current_conns: getCurrentConnValue('sites', s.site_id),
        total_conns: s.total_conns || 0,
        speed_in: s.speed_in || 0,
        speed_out: s.speed_out || 0,
        bytes_in: s.bytes_in || 0,
        bytes_out: s.bytes_out || 0
      }));
      app.renderSiteStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load site stats:', e);
    }
  };

  app.loadRangeStats = async function loadRangeStats() {
    try {
      const st = app.state.rangeStats;
      const payload = await app.apiCall('GET', '/api/ranges/stats?' + buildStatsQuery(st));

      st.page = payload && payload.page ? payload.page : st.page;
      st.pageSize = payload && payload.page_size ? payload.page_size : st.pageSize;
      st.total = payload && typeof payload.total === 'number' ? payload.total : 0;
      st.data = ((payload && payload.items) || []).map((s) => {
        return {
          range_id: s.range_id,
          remark: s.remark || '',
          current_conns: getCurrentConnValue('ranges', s.range_id),
          total_conns: s.total_conns || 0,
          rejected_conns: s.rejected_conns || 0,
          speed_in: s.speed_in || 0,
          speed_out: s.speed_out || 0,
          bytes_in: s.bytes_in || 0,
          bytes_out: s.bytes_out || 0
        };
      });

      app.renderRangeStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load range stats:', e);
    }
  };

  app.loadEgressNATStats = async function loadEgressNATStats() {
    try {
      const st = app.state.egressNATStats;
      const payload = await app.apiCall('GET', '/api/egress-nats/stats?' + buildStatsQuery(st));

      st.page = payload && payload.page ? payload.page : st.page;
      st.pageSize = payload && payload.page_size ? payload.page_size : st.pageSize;
      st.total = payload && typeof payload.total === 'number' ? payload.total : 0;
      st.data = ((payload && payload.items) || []).map((s) => {
        return {
          egress_nat_id: s.egress_nat_id,
          parent_interface: s.parent_interface || '',
          child_interface: s.child_interface || '',
          out_interface: s.out_interface || '',
          out_source_ip: s.out_source_ip || '',
          protocol: s.protocol || '',
          nat_type: s.nat_type || '',
          current_conns: getCurrentConnValue('egressNATs', s.egress_nat_id),
          total_conns: s.total_conns || 0,
          speed_in: s.speed_in || 0,
          speed_out: s.speed_out || 0,
          bytes_in: s.bytes_in || 0,
          bytes_out: s.bytes_out || 0
        };
      });

      app.renderEgressNATStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load egress nat stats:', e);
    }
  };

  app.loadCurrentConns = async function loadCurrentConns(options) {
    const opts = options || {};
    try {
      const snapshot = await app.apiCall('GET', '/api/stats/current-conns');
      applyCurrentConnsSnapshot(snapshot || {});
      app.renderRuleStatsTable();
      app.renderSiteStatsTable();
      app.renderRangeStatsTable();
      app.renderEgressNATStatsTable();
      if (opts.notify) app.notify('success', app.t('toast.refreshed', { item: app.t('stats.currentConns') }));
      return true;
    } catch (e) {
      if (e.message !== 'unauthorized') {
        console.error('load current conns:', e);
        if (opts.notify) app.notify('error', app.t('errors.actionFailed', {
          action: app.t('stats.refreshCurrentConns'),
          message: app.translateValidationMessage(e.message)
        }));
      }
      return false;
    }
  };

  app.loadAllStats = async function loadAllStats() {
    await Promise.all([app.loadKernelRuntime(), app.loadRuleStats(), app.loadSiteStats(), app.loadRangeStats(), app.loadEgressNATStats()]);
  };
})();
