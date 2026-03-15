(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.renderRuleStatsTable = function renderRuleStatsTable() {
    const el = app.el;
    const st = app.state.ruleStats;
    const sortedList = app.sortByState(st.data, st, (x, k) => x[k]);
    const list = app.paginateList(st, sortedList).items;
    el.ruleStatsBody.innerHTML = '';
    app.updateSortIndicators('ruleStatsTable', st);
    app.renderPagination('ruleStats', sortedList.length);

    if (!sortedList.length) {
      el.noRuleStats.style.display = 'block';
      app.toggleTableVisibility('ruleStatsTable', false);
      return;
    }
    el.noRuleStats.style.display = 'none';
    app.toggleTableVisibility('ruleStatsTable', true);

    list.forEach((s) => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="stat-mono">' + s.rule_id + '</td>' +
        '<td>' + (s.remark ? app.esc(s.remark) : app.emptyCellHTML('stat-muted')) + '</td>' +
        '<td><span class="' + (s.current_conns > 0 ? 'stat-pill active' : 'stat-pill') + '">' + s.current_conns + '</span></td>' +
        '<td>' + s.total_conns + '</td>' +
        '<td>' + s.rejected_conns + '</td>' +
        '<td>' + app.formatSpeed(s.speed_in) + '</td>' +
        '<td>' + app.formatSpeed(s.speed_out) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_in) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_out) + '</td>';
      el.ruleStatsBody.appendChild(tr);
    });
  };

  app.renderSiteStatsTable = function renderSiteStatsTable() {
    const el = app.el;
    const st = app.state.siteStats;
    const sortedList = app.sortByState(st.data, st, (x, k) => x[k]);
    const list = app.paginateList(st, sortedList).items;
    el.siteStatsBody.innerHTML = '';
    app.updateSortIndicators('siteStatsTable', st);
    app.renderPagination('siteStats', sortedList.length);

    if (!sortedList.length) {
      el.noSiteStats.style.display = 'block';
      app.toggleTableVisibility('siteStatsTable', false);
      return;
    }
    el.noSiteStats.style.display = 'none';
    app.toggleTableVisibility('siteStatsTable', true);

    list.forEach((s) => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="stat-mono">' + s.site_id + '</td>' +
        '<td>' + (s.domain ? app.esc(s.domain) : app.emptyCellHTML('stat-muted')) + '</td>' +
        '<td><span class="' + (s.active_conns > 0 ? 'stat-pill active' : 'stat-pill') + '">' + s.active_conns + '</span></td>' +
        '<td>' + s.total_conns + '</td>' +
        '<td>' + app.formatSpeed(s.speed_in) + '</td>' +
        '<td>' + app.formatSpeed(s.speed_out) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_in) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_out) + '</td>';
      el.siteStatsBody.appendChild(tr);
    });
  };

  app.renderRangeStatsTable = function renderRangeStatsTable() {
    const el = app.el;
    const st = app.state.rangeStats;
    const sortedList = app.sortByState(st.data, st, (x, k) => x[k]);
    const list = app.paginateList(st, sortedList).items;
    el.rangeStatsBody.innerHTML = '';
    app.updateSortIndicators('rangeStatsTable', st);
    app.renderPagination('rangeStats', sortedList.length);

    if (!sortedList.length) {
      el.noRangeStats.style.display = 'block';
      app.toggleTableVisibility('rangeStatsTable', false);
      return;
    }
    el.noRangeStats.style.display = 'none';
    app.toggleTableVisibility('rangeStatsTable', true);

    list.forEach((s) => {
      const tr = document.createElement('tr');
      tr.innerHTML =
        '<td class="stat-mono">' + s.range_id + '</td>' +
        '<td>' + (s.remark ? app.esc(s.remark) : app.emptyCellHTML('stat-muted')) + '</td>' +
        '<td><span class="' + (s.current_conns > 0 ? 'stat-pill active' : 'stat-pill') + '">' + s.current_conns + '</span></td>' +
        '<td>' + s.total_conns + '</td>' +
        '<td>' + s.rejected_conns + '</td>' +
        '<td>' + app.formatSpeed(s.speed_in) + '</td>' +
        '<td>' + app.formatSpeed(s.speed_out) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_in) + '</td>' +
        '<td>' + app.formatBytes(s.bytes_out) + '</td>';
      el.rangeStatsBody.appendChild(tr);
    });
  };

  app.loadRuleStats = async function loadRuleStats() {
    try {
      const [stats, rules] = await Promise.all([
        app.apiCall('GET', '/api/rules/stats'),
        app.apiCall('GET', '/api/rules')
      ]);
      const ruleMap = {};
      (rules || []).forEach((r) => { ruleMap[r.id] = r; });

      app.state.ruleStats.data = (stats || []).map((s) => {
        const rule = ruleMap[s.rule_id];
        const proto = (rule && rule.protocol) ? String(rule.protocol).toLowerCase() : '';
        const hasUDP = proto.indexOf('udp') >= 0;
        const hasTCP = proto.indexOf('tcp') >= 0;
        let currentConns = 0;
        if (hasUDP && hasTCP) currentConns = (s.nat_table_size || 0) + (s.active_conns || 0);
        else if (hasUDP) currentConns = s.nat_table_size || 0;
        else currentConns = s.active_conns || 0;

        return {
          rule_id: s.rule_id,
          remark: rule && rule.remark ? rule.remark : '',
          current_conns: currentConns,
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
        active_conns: s.active_conns || 0,
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
        app.apiCall('GET', '/api/ranges')
      ]);
      const rangeMap = {};
      (ranges || []).forEach((r) => { rangeMap[r.id] = r; });

      app.state.rangeStats.data = (stats || []).map((s) => {
        const range = rangeMap[s.range_id];
        const proto = (range && range.protocol) ? String(range.protocol).toLowerCase() : '';
        const hasUDP = proto.indexOf('udp') >= 0;
        const hasTCP = proto.indexOf('tcp') >= 0;
        let currentConns = 0;
        if (hasUDP && hasTCP) currentConns = (s.nat_table_size || 0) + (s.active_conns || 0);
        else if (hasUDP) currentConns = s.nat_table_size || 0;
        else currentConns = s.active_conns || 0;

        return {
          range_id: s.range_id,
          remark: range && range.remark ? range.remark : '',
          current_conns: currentConns,
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

  app.loadAllStats = async function loadAllStats() {
    await Promise.all([app.loadRuleStats(), app.loadSiteStats(), app.loadRangeStats()]);
  };
})();
