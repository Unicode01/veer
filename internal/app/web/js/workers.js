(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.workerTypeLabel = function workerTypeLabel(kind) {
    if (kind === 'kernel') return app.t('workers.kind.kernel');
    if (kind === 'rule') return app.t('workers.kind.rule');
    if (kind === 'range') return app.t('workers.kind.range');
    if (kind === 'egress_nat') return app.t('workers.kind.egress_nat');
    return app.t('workers.kind.shared');
  };

  app.workerCount = function workerCount(worker) {
    if (worker.kind === 'kernel') return worker.rule_count || worker.range_count || 0;
    if (worker.kind === 'rule') return worker.rule_count || 0;
    if (worker.kind === 'range') return worker.range_count || 0;
    if (worker.kind === 'egress_nat') return worker.egress_nat_count || 0;
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
        const familyInfo = typeof app.getAddressFamilyInfo === 'function'
          ? app.getAddressFamilyInfo(rule.in_ip, rule.out_ip)
          : null;
        if (familyInfo && familyInfo.searchText) values.push(familyInfo.searchText);
      });
    }
    if ((worker.kind === 'kernel' || worker.kind === 'range') && (worker.ranges || []).length > 0) {
      (worker.ranges || []).forEach((range) => {
        values.push(range.id, range.remark, range.in_ip, range.start_port, range.end_port, range.out_ip, range.out_start_port, range.protocol, range.tag, range.effective_engine, range.effective_kernel_engine, range.kernel_reason, range.fallback_reason);
        const familyInfo = typeof app.getAddressFamilyInfo === 'function'
          ? app.getAddressFamilyInfo(range.in_ip, range.out_ip)
          : null;
        if (familyInfo && familyInfo.searchText) values.push(familyInfo.searchText);
      });
    }
    if (worker.kind === 'egress_nat' && (worker.egress_nats || []).length > 0) {
      (worker.egress_nats || []).forEach((item) => {
        const childScope = typeof app.formatEgressNATTableChildScope === 'function'
          ? app.formatEgressNATTableChildScope(item.child_interface, item.parent_interface)
          : (typeof app.formatEgressNATChildScope === 'function'
            ? app.formatEgressNATChildScope(item.child_interface, item.parent_interface)
            : (item.child_interface || '*'));
        const protocol = typeof app.formatEgressNATProtocol === 'function'
          ? app.formatEgressNATProtocol(item.protocol || '')
          : String(item.protocol || '').toUpperCase();
        const natType = typeof app.formatEgressNATNatType === 'function'
          ? app.formatEgressNATNatType(item.nat_type || '')
          : String(item.nat_type || '');
        values.push(
          item.id,
          item.parent_interface,
          item.child_interface,
          childScope,
          item.out_interface,
          item.out_source_ip,
          item.protocol,
          protocol,
          item.nat_type,
          natType,
          item.status,
          item.effective_engine,
          item.effective_kernel_engine,
          item.kernel_reason,
          item.fallback_reason
        );
      });
    }
    if (worker.kind === 'shared') {
      values.push(worker.site_count, app.t('workers.sharedSites', { count: app.workerCount(worker) }));
    }

    return values;
  };

  app.workerSortValue = function workerSortValue(worker, key) {
    if (key === 'kind') return worker.kind === 'kernel' ? 0 : (worker.kind === 'rule' ? 1 : (worker.kind === 'range' ? 2 : (worker.kind === 'egress_nat' ? 3 : 4)));
    if (key === 'index') return worker.kind === 'shared' || worker.kind === 'kernel' || worker.kind === 'egress_nat' ? -1 : worker.index;
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
      const statusTitle = [
        app.t('common.status') + ': ' + info.text,
        engine.title || ''
      ].filter(Boolean).join('\n');
      const row = app.createNode('div', { className: 'worker-detail-row' });
      row.appendChild(app.createBadgeNode('badge-' + info.badge, info.text, statusTitle));
      row.appendChild(app.createNode('span', {
        className: 'worker-route',
        text: '#' + rule.id + ' ' + rule.in_ip + ':' + rule.in_port + ' -> ' + rule.out_ip + ':' + rule.out_port
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-proto',
        text: String(rule.protocol || '').toUpperCase()
      }));
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
      const statusTitle = [
        app.t('common.status') + ': ' + info.text,
        engine.title || ''
      ].filter(Boolean).join('\n');
      const outEnd = range.out_start_port + (range.end_port - range.start_port);
      const row = app.createNode('div', { className: 'worker-detail-row' });
      row.appendChild(app.createBadgeNode('badge-' + info.badge, info.text, statusTitle));
      row.appendChild(app.createNode('span', {
        className: 'worker-route',
        text: '#' + range.id + ' ' + range.in_ip + ':' + range.start_port + '-' + range.end_port + ' -> ' + range.out_ip + ':' + range.out_start_port + '-' + outEnd
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-proto',
        text: String(range.protocol || '').toUpperCase()
      }));
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

  app.renderEgressNATDetails = function renderEgressNATDetails(items) {
    if (!items || items.length === 0) {
      return app.createNode('span', {
        className: 'worker-empty',
        text: app.t('workers.emptyEgressNATs')
      });
    }
    const list = app.createNode('div', { className: 'worker-detail-list' });
    items.forEach((item) => {
      const info = app.statusInfo(item.status, item.enabled);
      const engine = typeof app.getRuleEngineInfo === 'function'
        ? app.getRuleEngineInfo(item)
        : {
            badgeClass: 'badge-kernel',
            badgeText: String(item.effective_kernel_engine || item.effective_engine || 'kernel').toUpperCase(),
            title: item.fallback_reason || item.kernel_reason || ''
          };
      const statusTitle = [
        app.t('common.status') + ': ' + info.text,
        engine.title || ''
      ].filter(Boolean).join('\n');
      const singleTarget = typeof app.isEgressNATSingleTargetInterfaceName === 'function'
        ? app.isEgressNATSingleTargetInterfaceName(item.parent_interface) && !item.child_interface
        : false;
      const childScope = typeof app.formatEgressNATTableChildScope === 'function'
        ? app.formatEgressNATTableChildScope(item.child_interface, item.parent_interface)
        : (typeof app.formatEgressNATChildScope === 'function'
          ? app.formatEgressNATChildScope(item.child_interface, item.parent_interface)
          : (item.child_interface || '*'));
      const protocol = typeof app.formatEgressNATProtocol === 'function'
        ? app.formatEgressNATProtocol(item.protocol || '')
        : String(item.protocol || '').toUpperCase();
      const natType = typeof app.formatEgressNATNatType === 'function'
        ? app.formatEgressNATNatType(item.nat_type || '')
        : String(item.nat_type || '');
      const row = app.createNode('div', { className: 'worker-detail-row' });
      row.appendChild(app.createBadgeNode('badge-' + info.badge, info.text, statusTitle));
      row.appendChild(app.createNode('span', {
        className: 'worker-route',
        text: '#' + item.id + ' ' + (singleTarget ? item.parent_interface : (item.parent_interface + '/' + childScope)) + ' -> ' + item.out_interface
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-proto',
        text: protocol
      }));
      row.appendChild(app.createNode('span', {
        className: 'worker-meta',
        text: '[' + natType + ']'
      }));
      if (item.out_source_ip) {
        row.appendChild(app.createNode('span', {
          className: 'worker-meta',
          text: '(' + item.out_source_ip + ')'
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
        : (worker.kind === 'egress_nat'
          ? app.renderEgressNATDetails(worker.egress_nats || [])
        : ((worker.rules || []).length > 0
          ? app.renderRuleDetails(worker.rules)
          : app.renderRangeDetails(worker.ranges)));
      const typeClass = worker.kind === 'kernel'
        ? 'worker-type-kernel'
        : (worker.kind === 'rule' ? 'worker-type-rule' : (worker.kind === 'range' ? 'worker-type-range' : (worker.kind === 'egress_nat' ? 'worker-type-egress-nat' : 'worker-type-shared')));
      const workerHash = worker.binary_hash || '';
      const hashClass = !workerHash ? '' : (workerHash === masterHash ? 'hash-match' : 'hash-outdated');
      const hashShort = workerHash ? workerHash.substring(0, 8) : app.t('common.dash');

      tr.appendChild(app.createCell(app.createNode('span', {
        className: 'worker-type ' + typeClass,
        text: app.workerTypeLabel(worker.kind)
      })));
      tr.appendChild(app.createCell(worker.kind === 'shared' || worker.kind === 'kernel' || worker.kind === 'egress_nat' ? app.emptyCellNode() : String(worker.index)));
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
