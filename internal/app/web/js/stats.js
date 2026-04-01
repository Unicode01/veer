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

  function ruleMetaSource() {
    if (app.state.rules && Array.isArray(app.state.rules.data) && app.state.rules.data.length > 0) {
      return Promise.resolve(app.state.rules.data);
    }
    return app.apiCall('GET', '/api/rules');
  }

  function rangeMetaSource() {
    if (app.state.ranges && Array.isArray(app.state.ranges.data) && app.state.ranges.data.length > 0) {
      return Promise.resolve(app.state.ranges.data);
    }
    return app.apiCall('GET', '/api/ranges');
  }

  function rebuildCurrentConns(kind, rows, idKey) {
    return (rows || []).map((row) => Object.assign({}, row, {
      current_conns: getCurrentConnValue(kind, row[idKey])
    }));
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

  app.renderRuleStatsTable = function renderRuleStatsTable() {
    const el = app.el;
    const st = app.state.ruleStats;
    const sortedList = app.sortByState(st.data, st, statSortValue);
    const list = app.paginateList(st, sortedList).items;
    app.clearNode(el.ruleStatsBody);
    app.updateSortIndicators('ruleStatsTable', st);
    app.renderPagination('ruleStats', sortedList.length);

    if (!sortedList.length) {
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
    const sortedList = app.sortByState(st.data, st, statSortValue);
    const list = app.paginateList(st, sortedList).items;
    app.clearNode(el.rangeStatsBody);
    app.updateSortIndicators('rangeStatsTable', st);
    app.renderPagination('rangeStats', sortedList.length);

    if (!sortedList.length) {
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

  app.loadRuleStats = async function loadRuleStats() {
    try {
      const [stats, rules] = await Promise.all([
        app.apiCall('GET', '/api/rules/stats'),
        ruleMetaSource()
      ]);
      const ruleMap = {};
      (rules || []).forEach((rule) => {
        ruleMap[rule.id] = rule;
      });

      app.state.ruleStats.data = (stats || []).map((s) => {
        const rule = ruleMap[s.rule_id];
        return {
          rule_id: s.rule_id,
          remark: rule && rule.remark ? rule.remark : '',
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
      const [stats, ranges] = await Promise.all([
        app.apiCall('GET', '/api/ranges/stats'),
        rangeMetaSource()
      ]);
      const rangeMap = {};
      (ranges || []).forEach((range) => {
        rangeMap[range.id] = range;
      });

      app.state.rangeStats.data = (stats || []).map((s) => {
        const range = rangeMap[s.range_id];
        return {
          range_id: s.range_id,
          remark: range && range.remark ? range.remark : '',
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
    await Promise.all([app.loadRuleStats(), app.loadSiteStats(), app.loadRangeStats()]);
  };
})();
