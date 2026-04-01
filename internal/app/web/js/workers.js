(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.workerTypeLabel = function workerTypeLabel(kind) {
    if (kind === 'kernel') return app.t('workers.kind.kernel');
    if (kind === 'rule') return app.t('workers.kind.rule');
    if (kind === 'range') return app.t('workers.kind.range');
    return app.t('workers.kind.shared');
  };

  app.workerCount = function workerCount(worker) {
    if (worker.kind === 'kernel') return worker.rule_count || worker.range_count || 0;
    if (worker.kind === 'rule') return worker.rule_count || 0;
    if (worker.kind === 'range') return worker.range_count || 0;
    return worker.site_count || 0;
  };

  app.workerSearchValues = function workerSearchValues(worker) {
    const values = [
      app.workerTypeLabel(worker.kind),
      worker.kind,
      worker.index,
      worker.status,
      app.statusInfo(worker.status).text,
      worker.binary_hash,
      app.workerCount(worker)
    ];

    if ((worker.kind === 'kernel' || worker.kind === 'rule') && (worker.rules || []).length > 0) {
      (worker.rules || []).forEach((rule) => {
        values.push(rule.id, rule.remark, rule.in_ip, rule.in_port, rule.out_ip, rule.out_port, rule.protocol, rule.tag, rule.effective_engine, rule.effective_kernel_engine, rule.kernel_reason, rule.fallback_reason);
      });
    }
    if ((worker.kind === 'kernel' || worker.kind === 'range') && (worker.ranges || []).length > 0) {
      (worker.ranges || []).forEach((range) => {
        values.push(range.id, range.remark, range.in_ip, range.start_port, range.end_port, range.out_ip, range.out_start_port, range.protocol, range.tag, range.effective_engine, range.effective_kernel_engine, range.kernel_reason, range.fallback_reason);
      });
    }
    if (worker.kind === 'shared') {
      values.push(worker.site_count, app.t('workers.sharedSites', { count: app.workerCount(worker) }));
    }

    return values;
  };

  app.workerSortValue = function workerSortValue(worker, key) {
    if (key === 'kind') return worker.kind === 'kernel' ? 0 : (worker.kind === 'rule' ? 1 : (worker.kind === 'range' ? 2 : 3));
    if (key === 'index') return worker.kind === 'shared' || worker.kind === 'kernel' ? -1 : worker.index;
    if (key === 'status') return worker.status === 'running' ? 0 : (worker.status === 'draining' ? 1 : (worker.status === 'error' ? 2 : 3));
    if (key === 'binary_hash') return worker.binary_hash || '';
    if (key === 'count') return app.workerCount(worker);
    return worker[key];
  };

  app.renderRuleDetails = function renderRuleDetails(rules) {
    if (!rules || rules.length === 0) {
      return app.createNode('span', {
        className: 'worker-empty',
        text: app.t('workers.emptyRules')
      });
    }
    const list = app.createNode('div', { className: 'worker-detail-list' });
    rules.forEach((rule) => {
      const info = app.statusInfo(rule.status, rule.enabled);
      const engine = typeof app.getRuleEngineInfo === 'function'
        ? app.getRuleEngineInfo(rule)
        : {
            badgeClass: (rule.effective_engine || 'userspace') === 'kernel' ? 'badge-kernel' : 'badge-userspace',
            badgeText: (rule.effective_engine || 'userspace'),
            title: rule.fallback_reason || rule.kernel_reason || ''
          };
      const row = app.createNode('div', { className: 'worker-detail-row' });
      row.appendChild(app.createStatusBadgeNode(info));
      row.appendChild(app.createNode('span', {
        className: 'worker-route',
        text: '#' + rule.id + ' ' + rule.in_ip + ':' + rule.in_port + ' -> ' + rule.out_ip + ':' + rule.out_port
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-proto',
        text: String(rule.protocol || '').toUpperCase()
      }));
      row.appendChild(app.createBadgeNode(engine.badgeClass, engine.badgeText, engine.title || ''));
      if (rule.remark) {
        row.appendChild(app.createNode('span', {
          className: 'worker-meta',
          text: '(' + rule.remark + ')'
        }));
      }
      list.appendChild(row);
    });
    return list;
  };

  app.renderRangeDetails = function renderRangeDetails(ranges) {
    if (!ranges || ranges.length === 0) {
      return app.createNode('span', {
        className: 'worker-empty',
        text: app.t('workers.emptyRanges')
      });
    }
    const list = app.createNode('div', { className: 'worker-detail-list' });
    ranges.forEach((range) => {
      const info = app.statusInfo(range.status, range.enabled);
      const engine = typeof app.getRuleEngineInfo === 'function'
        ? app.getRuleEngineInfo(range)
        : {
            badgeClass: (range.effective_engine || 'userspace') === 'kernel' ? 'badge-kernel' : 'badge-userspace',
            badgeText: (range.effective_engine || 'userspace'),
            title: range.fallback_reason || range.kernel_reason || ''
          };
      const outEnd = range.out_start_port + (range.end_port - range.start_port);
      const row = app.createNode('div', { className: 'worker-detail-row' });
      row.appendChild(app.createStatusBadgeNode(info));
      row.appendChild(app.createNode('span', {
        className: 'worker-route',
        text: '#' + range.id + ' ' + range.in_ip + ':' + range.start_port + '-' + range.end_port + ' -> ' + range.out_ip + ':' + range.out_start_port + '-' + outEnd
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-proto',
        text: String(range.protocol || '').toUpperCase()
      }));
      row.appendChild(app.createBadgeNode(engine.badgeClass, engine.badgeText, engine.title || ''));
      if (range.remark) {
        row.appendChild(app.createNode('span', {
          className: 'worker-meta',
          text: '(' + range.remark + ')'
        }));
      }
      list.appendChild(row);
    });
    return list;
  };

  app.renderWorkersTable = function renderWorkersTable() {
    const el = app.el;
    const st = app.state.workers;
    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((worker) => app.matchesSearch(st.searchQuery, app.workerSearchValues(worker)));
    }
    filteredList = app.sortByState(filteredList, st, app.workerSortValue);
    const list = app.paginateList(st, filteredList).items;
    app.clearNode(el.workersBody);
    app.updateSortIndicators('workersTable', st);
    app.renderFilterMeta('workers', filteredList.length, st.data.length);
    app.renderPagination('workers', filteredList.length);

    if (!filteredList.length) {
      app.updateEmptyState(el.noWorkers, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('workers.empty'),
        actionButton: app.el.emptyRefreshWorkersBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('workersTable', false);
      return;
    }

    app.hideEmptyState(el.noWorkers);
    app.toggleTableVisibility('workersTable', true);

    const masterHash = st.masterHash || '';
    const fragment = document.createDocumentFragment();
    list.forEach((worker) => {
      const tr = document.createElement('tr');
      const info = app.statusInfo(worker.status);
      const count = app.workerCount(worker);
      const countText = worker.kind === 'shared'
        ? app.t('workers.count.sites', { count: count })
        : app.t('workers.count.entries', { count: count });
      const detail = worker.kind === 'shared'
        ? app.createNode('div', {
            className: 'worker-detail-list',
            children: app.createNode('div', {
              className: 'worker-detail-row',
              children: app.createNode('span', {
                className: 'worker-meta',
                text: app.t('workers.sharedSites', { count: count })
              })
            })
          })
        : ((worker.rules || []).length > 0
          ? app.renderRuleDetails(worker.rules)
          : app.renderRangeDetails(worker.ranges));
      const typeClass = worker.kind === 'kernel'
        ? 'worker-type-kernel'
        : (worker.kind === 'rule' ? 'worker-type-rule' : (worker.kind === 'range' ? 'worker-type-range' : 'worker-type-shared'));
      const workerHash = worker.binary_hash || '';
      const hashClass = !workerHash ? '' : (workerHash === masterHash ? 'hash-match' : 'hash-outdated');
      const hashShort = workerHash ? workerHash.substring(0, 8) : app.t('common.dash');

      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'worker-type ' + typeClass,
        text: app.workerTypeLabel(worker.kind)
      })));
      tr.appendChild(app.createCell(worker.kind === 'shared' || worker.kind === 'kernel' ? app.emptyCellNode() : String(worker.index)));
      tr.appendChild(app.createCell(app.createStatusBadgeNode(info)));
      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'worker-hash ' + hashClass,
        text: hashShort,
        title: workerHash
      })));
      tr.appendChild(app.createCell(countText));
      tr.appendChild(app.createCell(detail));

      fragment.appendChild(tr);
    });

    el.workersBody.appendChild(fragment);

    app.renderOverview();
  };

  app.loadWorkers = async function loadWorkers() {
    try {
      const resp = await app.apiCall('GET', '/api/workers');
      app.state.workers.masterHash = resp.binary_hash || '';
      app.state.workers.data = resp.workers || [];
      app.markDataFresh();

      if (app.el.masterVersion) {
        app.el.masterVersion.textContent = app.state.workers.masterHash ? app.state.workers.masterHash.substring(0, 8) : '';
        app.el.masterVersion.title = app.state.workers.masterHash || '';
      }

      app.renderWorkersTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load workers:', e);
    }
  };
})();
