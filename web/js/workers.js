(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.workerTypeLabel = function workerTypeLabel(kind) {
    if (kind === 'rule') return app.t('workers.kind.rule');
    if (kind === 'range') return app.t('workers.kind.range');
    return app.t('workers.kind.shared');
  };

  app.workerCount = function workerCount(worker) {
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

    if (worker.kind === 'rule') {
      (worker.rules || []).forEach((rule) => {
        values.push(rule.id, rule.remark, rule.in_ip, rule.in_port, rule.out_ip, rule.out_port, rule.protocol, rule.tag);
      });
    } else if (worker.kind === 'range') {
      (worker.ranges || []).forEach((range) => {
        values.push(range.id, range.remark, range.in_ip, range.start_port, range.end_port, range.out_ip, range.out_start_port, range.protocol, range.tag);
      });
    } else {
      values.push(worker.site_count, app.t('workers.sharedSites', { count: app.workerCount(worker) }));
    }

    return values;
  };

  app.workerSortValue = function workerSortValue(worker, key) {
    if (key === 'kind') return worker.kind === 'rule' ? 0 : (worker.kind === 'range' ? 1 : 2);
    if (key === 'index') return worker.kind === 'shared' ? -1 : worker.index;
    if (key === 'status') return worker.status === 'running' ? 0 : (worker.status === 'draining' ? 1 : (worker.status === 'error' ? 2 : 3));
    if (key === 'binary_hash') return worker.binary_hash || '';
    if (key === 'count') return app.workerCount(worker);
    return worker[key];
  };

  app.renderRuleDetails = function renderRuleDetails(rules) {
    if (!rules || rules.length === 0) return '<span class="worker-empty">' + app.t('workers.emptyRules') + '</span>';
    let html = '<div class="worker-detail-list">';
    rules.forEach((rule) => {
      const info = app.statusInfo(rule.status, rule.enabled);
      const remark = rule.remark ? '<span class="worker-meta">(' + app.esc(rule.remark) + ')</span>' : '';
      html += '<div class="worker-detail-row">' +
        '<span class="badge badge-' + info.badge + '">' + info.text + '</span>' +
        '<span class="worker-route">#' + rule.id + ' ' + app.esc(rule.in_ip) + ':' + rule.in_port + ' -> ' + app.esc(rule.out_ip) + ':' + rule.out_port + '</span>' +
        '<span class="worker-proto">' + app.esc(String(rule.protocol || '').toUpperCase()) + '</span>' +
        remark +
        '</div>';
    });
    html += '</div>';
    return html;
  };

  app.renderRangeDetails = function renderRangeDetails(ranges) {
    if (!ranges || ranges.length === 0) return '<span class="worker-empty">' + app.t('workers.emptyRanges') + '</span>';
    let html = '<div class="worker-detail-list">';
    ranges.forEach((range) => {
      const info = app.statusInfo(range.status, range.enabled);
      const outEnd = range.out_start_port + (range.end_port - range.start_port);
      const remark = range.remark ? '<span class="worker-meta">(' + app.esc(range.remark) + ')</span>' : '';
      html += '<div class="worker-detail-row">' +
        '<span class="badge badge-' + info.badge + '">' + info.text + '</span>' +
        '<span class="worker-route">#' + range.id + ' ' + app.esc(range.in_ip) + ':' + range.start_port + '-' + range.end_port + ' -> ' + app.esc(range.out_ip) + ':' + range.out_start_port + '-' + outEnd + '</span>' +
        '<span class="worker-proto">' + app.esc(String(range.protocol || '').toUpperCase()) + '</span>' +
        remark +
        '</div>';
    });
    html += '</div>';
    return html;
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
    el.workersBody.innerHTML = '';
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
    list.forEach((worker) => {
      const tr = document.createElement('tr');
      const info = app.statusInfo(worker.status);
      const count = app.workerCount(worker);
      const countText = worker.kind === 'shared'
        ? app.t('workers.count.sites', { count: count })
        : app.t('workers.count.entries', { count: count });
      const detail = worker.kind === 'rule'
        ? app.renderRuleDetails(worker.rules)
        : (worker.kind === 'range'
          ? app.renderRangeDetails(worker.ranges)
          : ('<div class="worker-detail-list"><div class="worker-detail-row"><span class="worker-meta">' + app.t('workers.sharedSites', { count: count }) + '</span></div></div>'));
      const typeClass = worker.kind === 'rule' ? 'worker-type-rule' : (worker.kind === 'range' ? 'worker-type-range' : 'worker-type-shared');
      const workerHash = worker.binary_hash || '';
      const hashClass = !workerHash ? '' : (workerHash === masterHash ? 'hash-match' : 'hash-outdated');
      const hashShort = workerHash ? workerHash.substring(0, 8) : app.t('common.dash');

      tr.innerHTML =
        '<td><span class="worker-type ' + typeClass + '">' + app.workerTypeLabel(worker.kind) + '</span></td>' +
        '<td>' + (worker.kind === 'shared' ? app.emptyCellHTML() : worker.index) + '</td>' +
        '<td><span class="badge badge-' + info.badge + '">' + info.text + '</span></td>' +
        '<td><span class="worker-hash ' + hashClass + '" title="' + app.esc(workerHash) + '">' + app.esc(hashShort) + '</span></td>' +
        '<td>' + countText + '</td>' +
        '<td>' + detail + '</td>';

      el.workersBody.appendChild(tr);
    });

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
