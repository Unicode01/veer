(function () {
  const app = window.ForwardApp;
  if (!app) return;

  function ensureCurrentConnsSnapshot() {
    if (!app.state.currentConnsSnapshot) {
      app.state.currentConnsSnapshot = {
        loaded: false,
        rules: {},
        sites: {},
        ranges: {}
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

  function kernelEngineBadge(name) {
    const normalized = String(name || '').toLowerCase();
    const badgeClass = normalized === 'xdp' ? 'badge-xdp' : normalized === 'tc' ? 'badge-tc' : 'badge-kernel';
    return app.createBadgeNode(badgeClass, normalized || app.t('common.dash'));
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
    return app.createBadgeNode(badgeClass, app.t('kernel.pressure.' + level), reason || '');
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
      const label = String(engine.name || app.t('common.dash')).toUpperCase();
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

  function kernelRuntimeMapTooltipContent(item, percentText) {
    return [
      app.createNode('span', {
        className: 'kernel-runtime-tooltip-title',
        text: item.label
      }),
      app.createNode('span', {
        className: 'kernel-runtime-tooltip-primary',
        text: percentText
      }),
      app.createNode('span', {
        className: 'kernel-runtime-tooltip-meta',
        text: String(item.entries) + ' / ' + String(item.capacity)
      })
    ];
  }

  function bindKernelRuntimeTooltip(trigger, contentFactory) {
    trigger.addEventListener('mouseenter', () => showKernelRuntimeTooltip(trigger, contentFactory(), false));
    trigger.addEventListener('mouseleave', () => {
      if (kernelRuntimeTooltipTrigger === trigger && !kernelRuntimeTooltipPinned) {
        hideKernelRuntimeTooltip();
      }
    });
    trigger.addEventListener('focus', () => showKernelRuntimeTooltip(trigger, contentFactory(), false));
    trigger.addEventListener('blur', () => {
      if (kernelRuntimeTooltipTrigger === trigger && !kernelRuntimeTooltipPinned) {
        hideKernelRuntimeTooltip();
      }
    });
    trigger.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (kernelRuntimeTooltipTrigger === trigger && kernelRuntimeTooltipPinned) {
        hideKernelRuntimeTooltip();
        return;
      }
      showKernelRuntimeTooltip(trigger, contentFactory(), true);
    });
  }

  function kernelRuntimeMapsNode(engine) {
    ensureKernelRuntimeTooltip();

    const items = [
      {
        label: app.t('kernel.maps.rules'),
        entries: engine.rules_map_entries || 0,
        capacity: engine.rules_map_capacity || 0
      },
      {
        label: app.t('kernel.maps.flows'),
        entries: engine.flows_map_entries || 0,
        capacity: engine.flows_map_capacity || 0
      }
    ];

    if ((engine.nat_map_entries || 0) > 0 || (engine.nat_map_capacity || 0) > 0) {
      items.push({
        label: app.t('kernel.maps.nat'),
        entries: engine.nat_map_entries || 0,
        capacity: engine.nat_map_capacity || 0
      });
    }

    const list = app.createNode('div', { className: 'kernel-runtime-map-list' });
    items.forEach((item) => {
      const percent = kernelRuntimeMapPercent(item.entries, item.capacity);
      const percentText = formatKernelRuntimePercent(percent);
      const badge = app.createNode('button', {
        className: 'kernel-runtime-map-badge is-' + kernelRuntimeMapLevel(percent, item.capacity),
        attrs: {
          type: 'button',
          'aria-describedby': 'kernelRuntimeFloatingTooltip',
          'aria-expanded': 'false',
          'aria-label': item.label + ' ' + percentText + ' (' + String(item.entries) + '/' + String(item.capacity) + ')'
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
      bindKernelRuntimeTooltip(badge, () => kernelRuntimeMapTooltipContent(item, percentText));
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

  function kernelRuntimeSummaryNote(labelKey, timestamp, detail) {
    const text = String(detail || '').trim();
    if (!text) return null;

    const parts = [app.t(labelKey)];
    const clock = kernelRuntimeTimestampLabel(timestamp);
    if (clock) parts.push(clock);
    parts.push(text);

    return app.createNode('div', {
      className: 'kernel-runtime-note',
      text: parts.join(' · ')
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
    [
      engine.pressure_reason,
      engine.degraded_reason,
      engine.available_reason,
      engine.attachment_summary
    ].forEach((item) => {
      const text = String(item || '').trim();
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
      ['recreate', engine.diag_reply_flow_recreated]
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
        ['tcp_close_del', engine.diag_tcp_close_delete]
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

  function kernelRuntimeDegradedSummaryText(engines) {
    const degraded = (engines || []).filter((engine) => !!engine.degraded);
    if (!degraded.length) return '';
    return degraded.map((engine) => {
      const label = String(engine.name || app.t('common.dash')).toUpperCase();
      const detail = kernelRuntimeDetailText(engine) || app.t('kernel.summary.degradedValue', { engine: label });
      return label + ': ' + detail;
    }).join('; ');
  }

  let kernelRuntimeTooltip = null;
  let kernelRuntimeTooltipTrigger = null;
  let kernelRuntimeTooltipPinned = false;

  function ensureKernelRuntimeTooltip() {
    if (kernelRuntimeTooltip) return kernelRuntimeTooltip;

    kernelRuntimeTooltip = app.createNode('div', {
      className: 'kernel-runtime-floating-tooltip',
      attrs: {
        id: 'kernelRuntimeFloatingTooltip',
        role: 'tooltip',
        hidden: true
      }
    });
    document.body.appendChild(kernelRuntimeTooltip);

    window.addEventListener('resize', hideKernelRuntimeTooltip);
    document.addEventListener('scroll', hideKernelRuntimeTooltip, true);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') hideKernelRuntimeTooltip();
    });
    document.addEventListener('click', (e) => {
      if (!kernelRuntimeTooltipTrigger) return;
      if (kernelRuntimeTooltipTrigger.contains(e.target)) return;
      hideKernelRuntimeTooltip();
    });
    document.addEventListener('focusin', (e) => {
      if (!kernelRuntimeTooltipTrigger) return;
      if (kernelRuntimeTooltipTrigger.contains(e.target)) return;
      hideKernelRuntimeTooltip();
    });

    return kernelRuntimeTooltip;
  }

  function positionKernelRuntimeTooltip() {
    if (!kernelRuntimeTooltip || !kernelRuntimeTooltipTrigger || kernelRuntimeTooltip.hidden) return;

    const margin = 12;
    const offset = 8;
    const triggerRect = kernelRuntimeTooltipTrigger.getBoundingClientRect();

    kernelRuntimeTooltip.style.left = '0px';
    kernelRuntimeTooltip.style.top = '0px';

    const tipRect = kernelRuntimeTooltip.getBoundingClientRect();
    let left = triggerRect.left + ((triggerRect.width - tipRect.width) / 2);
    left = Math.min(Math.max(left, margin), Math.max(margin, window.innerWidth - tipRect.width - margin));

    let top = triggerRect.bottom + offset;
    if (top + tipRect.height > window.innerHeight - margin) {
      const aboveTop = triggerRect.top - tipRect.height - offset;
      top = aboveTop >= margin ? aboveTop : Math.max(margin, window.innerHeight - tipRect.height - margin);
    }

    kernelRuntimeTooltip.style.left = Math.round(left) + 'px';
    kernelRuntimeTooltip.style.top = Math.round(top) + 'px';
  }

  function hideKernelRuntimeTooltip() {
    if (kernelRuntimeTooltipTrigger) {
      kernelRuntimeTooltipTrigger.setAttribute('aria-expanded', 'false');
    }
    kernelRuntimeTooltipTrigger = null;
    kernelRuntimeTooltipPinned = false;

    if (!kernelRuntimeTooltip) return;
    kernelRuntimeTooltip.classList.remove('is-visible');
    kernelRuntimeTooltip.hidden = true;
    app.clearNode(kernelRuntimeTooltip);
  }

  function showKernelRuntimeTooltip(trigger, content, pinned) {
    const tooltip = ensureKernelRuntimeTooltip();
    if (kernelRuntimeTooltipTrigger && kernelRuntimeTooltipTrigger !== trigger) {
      kernelRuntimeTooltipTrigger.setAttribute('aria-expanded', 'false');
    }

    kernelRuntimeTooltipTrigger = trigger;
    kernelRuntimeTooltipPinned = !!pinned;
    app.clearNode(tooltip);
    app.appendNodeContent(tooltip, content);
    tooltip.hidden = false;
    tooltip.classList.add('is-visible');
    trigger.setAttribute('aria-expanded', 'true');
    positionKernelRuntimeTooltip();
  }

  function kernelRuntimeDetailNode(detail, degraded) {
    const text = String(detail || '').trim();
    if (!text) return app.emptyCellNode('stat-muted');
    ensureKernelRuntimeTooltip();

    const button = app.createNode('button', {
      className: 'kernel-runtime-detail-trigger' + (degraded ? ' is-warning' : ''),
      text: app.t(degraded ? 'kernel.degraded.yes' : 'kernel.engine.details'),
      attrs: {
        type: 'button',
        'aria-label': text,
        'aria-describedby': 'kernelRuntimeFloatingTooltip',
        'aria-expanded': 'false'
      }
    });

    bindKernelRuntimeTooltip(button, () => text);

    return button;
  }

  function applyCurrentConnsSnapshot(payload) {
    const next = {
      loaded: true,
      rules: {},
      sites: {},
      ranges: {}
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

    app.state.currentConnsSnapshot = next;
    app.state.ruleStats.data = rebuildCurrentConns('rules', app.state.ruleStats.data, 'rule_id');
    app.state.siteStats.data = rebuildCurrentConns('sites', app.state.siteStats.data, 'site_id');
    app.state.rangeStats.data = rebuildCurrentConns('ranges', app.state.rangeStats.data, 'range_id');
  }

  app.renderKernelRuntime = function renderKernelRuntime() {
    const el = app.el;
    const data = app.state.kernelRuntime.data;
    hideKernelRuntimeTooltip();
    app.clearNode(el.kernelRuntimeSummary);
    app.clearNode(el.kernelRuntimeBody);

    if (!data) {
      el.noKernelRuntime.style.display = 'block';
      app.toggleTableVisibility('kernelRuntimeTable', false);
      return;
    }

    const configuredOrder = Array.isArray(data.configured_order) ? data.configured_order : [];
    const engines = Array.isArray(data.engines) ? data.engines : [];
    const pressureSummary = kernelRuntimePressureSummary(engines);
    const configuredOrderNodes = configuredOrder.length
      ? configuredOrder.map((name) => kernelEngineBadge(name))
      : [app.emptyCellNode('stat-muted')];

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
            text: app.t('kernel.summary.configuredOrder') + ':'
          }),
          configuredOrderNodes
        ]),
        !data.available && (data.available_reason || app.t('common.unavailable'))
          ? app.createNode('div', {
              text: data.available_reason || app.t('common.unavailable')
            })
          : null
      ]
    ));
    summaryFragment.appendChild(kernelRuntimeSummaryCard(
      'kernel.summary.activeKernel',
      app.t('kernel.summary.activeKernelValue', {
        rules: data.active_rule_count || 0,
        ranges: data.active_range_count || 0
      }),
      kernelRuntimeSummaryInline([
        kernelStatePill(!!data.traffic_stats, 'kernel.traffic.enabled', 'kernel.traffic.disabled'),
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

    if (data.transient_fallback_summary) {
      el.kernelRuntimeSummary.appendChild(app.createNode('div', {
        className: 'kernel-runtime-note',
        text: data.transient_fallback_summary
      }));
    }
    const lastRetryNote = kernelRuntimeSummaryNote('kernel.note.lastRetry', data.last_kernel_retry_at, data.last_kernel_retry_reason);
    if (lastRetryNote) {
      el.kernelRuntimeSummary.appendChild(lastRetryNote);
    }
    const lastIncrementalRetryNote = kernelRuntimeSummaryNote('kernel.note.lastIncrementalRetry', data.last_kernel_incremental_retry_at, data.last_kernel_incremental_retry_result);
    if (lastIncrementalRetryNote) {
      el.kernelRuntimeSummary.appendChild(lastIncrementalRetryNote);
    }
    const pendingNetlinkRecoveryNote = kernelRuntimeSummaryNote(
      'kernel.note.pendingNetlinkRecovery',
      data.kernel_netlink_recover_requested_at,
      kernelRuntimeNetlinkRecoveryDetail(data)
    );
    if (pendingNetlinkRecoveryNote) {
      el.kernelRuntimeSummary.appendChild(pendingNetlinkRecoveryNote);
    }
    const attachmentIssueNote = kernelRuntimeSummaryNote('kernel.note.attachmentIssue', '', data.last_kernel_attachment_issue);
    if (attachmentIssueNote) {
      el.kernelRuntimeSummary.appendChild(attachmentIssueNote);
    }
    const attachmentHealErrorNote = kernelRuntimeSummaryNote(
      'kernel.note.lastAttachmentHealError',
      data.last_kernel_attachment_heal_at,
      data.last_kernel_attachment_heal_error
    );
    if (attachmentHealErrorNote) {
      el.kernelRuntimeSummary.appendChild(attachmentHealErrorNote);
    }
    const attachmentHealNote = kernelRuntimeSummaryNote(
      'kernel.note.lastAttachmentHeal',
      data.last_kernel_attachment_heal_at,
      data.last_kernel_attachment_heal_summary
    );
    if (attachmentHealNote) {
      el.kernelRuntimeSummary.appendChild(attachmentHealNote);
    }
    const degradedSummary = kernelRuntimeDegradedSummaryText(engines);
    if (degradedSummary) {
      el.kernelRuntimeSummary.appendChild(app.createNode('div', {
        className: 'kernel-runtime-note',
        text: app.t('kernel.summary.degraded') + ': ' + degradedSummary
      }));
    }

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
      tr.appendChild(app.createCell(kernelEngineBadge(engine.name), 'stat-mono'));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.available, 'kernel.available.yes', 'kernel.available.no')));
      tr.appendChild(app.createCell(kernelRuntimePressureBadge(pressureLevel, engine.pressure_reason || '')));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.loaded, 'kernel.loaded.yes', 'kernel.loaded.no')));
      tr.appendChild(app.createCell(String(engine.active_entries || 0), 'stat-mono'));
      tr.appendChild(app.createCell(String(engine.attachments || 0), 'stat-mono'));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.attachments_healthy, 'kernel.attachments.healthy', 'kernel.attachments.degraded')));
      tr.appendChild(app.createCell(kernelRuntimeMapsNode(engine), 'kernel-runtime-maps'));
      tr.appendChild(app.createCell(kernelRuntimeModeLabel(engine.last_reconcile_mode)));
      tr.appendChild(app.createCell(kernelStatePill(!!engine.traffic_stats, 'kernel.traffic.enabled', 'kernel.traffic.disabled')));
      tr.appendChild(app.createCell(
        kernelRuntimeDetailNode(kernelRuntimeDetailText(engine), !!engine.degraded || !!engine.pressure_active),
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
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.rule_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.remark ? s.remark : app.emptyCellNode('stat-muted')));
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
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.site_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.domain ? s.domain : app.emptyCellNode('stat-muted')));
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
      const tr = document.createElement('tr');
      tr.appendChild(app.createCell(String(s.range_id), 'stat-mono'));
      tr.appendChild(app.createCell(s.remark ? s.remark : app.emptyCellNode('stat-muted')));
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

  app.loadKernelRuntime = async function loadKernelRuntime() {
    try {
      app.state.kernelRuntime.data = await app.apiCall('GET', '/api/kernel/runtime');
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

  app.loadCurrentConns = async function loadCurrentConns() {
    try {
      const snapshot = await app.apiCall('GET', '/api/stats/current-conns');
      applyCurrentConnsSnapshot(snapshot || {});
      app.renderRuleStatsTable();
      app.renderSiteStatsTable();
      app.renderRangeStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load current conns:', e);
    }
  };

  app.loadAllStats = async function loadAllStats() {
    await Promise.all([app.loadKernelRuntime(), app.loadRuleStats(), app.loadSiteStats(), app.loadRangeStats()]);
  };
})();
