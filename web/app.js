(function() {
    const tokenModal = document.getElementById('tokenModal');
    const tokenInput = document.getElementById('tokenInput');
    const tokenSubmit = document.getElementById('tokenSubmit');
    const app = document.getElementById('app');
    const logoutBtn = document.getElementById('logoutBtn');
    const ruleForm = document.getElementById('ruleForm');
    const ruleFormTitle = document.getElementById('ruleFormTitle');
    const ruleSubmitBtn = document.getElementById('ruleSubmitBtn');
    const ruleCancelBtn = document.getElementById('ruleCancelBtn');
    const editRuleId = document.getElementById('editRuleId');
    const rulesBody = document.getElementById('rulesBody');
    const noRules = document.getElementById('noRules');
    const inInterface = document.getElementById('inInterface');
    const inIP = document.getElementById('inIP');
    const outInterface = document.getElementById('outInterface');

    const siteForm = document.getElementById('siteForm');
    const siteFormTitle = document.getElementById('siteFormTitle');
    const siteSubmitBtn = document.getElementById('siteSubmitBtn');
    const siteCancelBtn = document.getElementById('siteCancelBtn');
    const editSiteId = document.getElementById('editSiteId');
    const sitesBody = document.getElementById('sitesBody');
    const noSites = document.getElementById('noSites');
    const siteListenIface = document.getElementById('siteListenIface');
    const siteListenIP = document.getElementById('siteListenIP');

    const rangeForm = document.getElementById('rangeForm');
    const rangeFormTitle = document.getElementById('rangeFormTitle');
    const rangeSubmitBtn = document.getElementById('rangeSubmitBtn');
    const rangeCancelBtn = document.getElementById('rangeCancelBtn');
    const editRangeId = document.getElementById('editRangeId');
    const rangesBody = document.getElementById('rangesBody');
    const noRanges = document.getElementById('noRanges');
    const rangeInInterface = document.getElementById('rangeInInterface');
    const rangeInIP = document.getElementById('rangeInIP');
    const rangeOutInterface = document.getElementById('rangeOutInterface');

    const workersBody = document.getElementById('workersBody');
    const noWorkers = document.getElementById('noWorkers');
    const ruleStatsBody = document.getElementById('ruleStatsBody');
    const noRuleStats = document.getElementById('noRuleStats');
    const siteStatsBody = document.getElementById('siteStatsBody');
    const noSiteStats = document.getElementById('noSiteStats');
    const rangeStatsBody = document.getElementById('rangeStatsBody');
    const noRangeStats = document.getElementById('noRangeStats');

    let interfaces = [];
    let tags = [];
    let rulesSortKey = '';
    let rulesSortAsc = true;
    let rulesFilterTag = '';
    let lastRulesData = [];

    // ---- Token ----
    function getToken() { return localStorage.getItem('forward_token') || ''; }
    function setToken(t) { localStorage.setItem('forward_token', t); }
    function clearToken() { localStorage.removeItem('forward_token'); }
    function showTokenModal() {
        app.style.display = 'none';
        tokenModal.classList.add('active');
        tokenInput.value = '';
        tokenInput.focus();
    }
    function hideTokenModal() {
        tokenModal.classList.remove('active');
        app.style.display = 'block';
    }

    // ---- API ----
    async function apiCall(method, path, body) {
        var opts = {
            method: method,
            headers: { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' }
        };
        if (body) opts.body = JSON.stringify(body);
        var resp = await fetch(path, opts);
        if (resp.status === 401) { clearToken(); showTokenModal(); throw new Error('unauthorized'); }
        if (!resp.ok) {
            var err = await resp.json().catch(function() { return { error: resp.statusText }; });
            throw new Error(err.error || resp.statusText);
        }
        return resp.json();
    }

    // ---- Tabs ----
    document.querySelectorAll('.tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
            tab.classList.add('active');
            var target = tab.dataset.tab;
            document.getElementById('tab-' + target).classList.add('active');
            if (target === 'workers') loadWorkers();
            if (target === 'rule-stats') { loadRuleStats(); loadSiteStats(); loadRangeStats(); }
        });
    });

    // ---- Interface helpers ----
    function populateInterfaceSelect(sel, selectedValue) {
        var current = sel.value;
        sel.innerHTML = '<option value="">不指定</option>';
        interfaces.forEach(function(iface) {
            var opt = document.createElement('option');
            opt.value = iface.name;
            opt.textContent = iface.name + ' (' + iface.addrs.join(', ') + ')';
            sel.appendChild(opt);
        });
        sel.value = selectedValue || current || '';
    }

    function populateIPSelect(ifaceSel, ipSel, selectedValue) {
        var ifaceName = ifaceSel.value;
        ipSel.innerHTML = '<option value="0.0.0.0">0.0.0.0 (所有)</option>';
        if (!ifaceName) {
            interfaces.forEach(function(iface) {
                iface.addrs.forEach(function(addr) {
                    var o = document.createElement('option');
                    o.value = addr; o.textContent = addr + ' (' + iface.name + ')';
                    ipSel.appendChild(o);
                });
            });
        } else {
            var iface = interfaces.find(function(i) { return i.name === ifaceName; });
            if (iface) {
                iface.addrs.forEach(function(addr) {
                    var opt = document.createElement('option');
                    opt.value = addr; opt.textContent = addr;
                    ipSel.appendChild(opt);
                });
            }
        }
        if (selectedValue) ipSel.value = selectedValue;
    }

    function populateSiteListenIP(ifaceSel, ipSel) {
        var ifaceName = ifaceSel.value;
        ipSel.innerHTML = '<option value="0.0.0.0">0.0.0.0 (所有)</option>';
        var list = ifaceName
            ? (interfaces.find(function(i) { return i.name === ifaceName; }) || {}).addrs || []
            : [].concat.apply([], interfaces.map(function(i) { return i.addrs.map(function(a) { return {addr:a, name:i.name}; }); }));
        if (!ifaceName) {
            interfaces.forEach(function(iface) {
                iface.addrs.forEach(function(addr) {
                    var o = document.createElement('option');
                    o.value = addr; o.textContent = addr + ' (' + iface.name + ')';
                    ipSel.appendChild(o);
                });
            });
        } else {
            list.forEach(function(addr) {
                var opt = document.createElement('option');
                opt.value = addr; opt.textContent = addr;
                ipSel.appendChild(opt);
            });
        }
    }

    function populateTagSelect(sel, selectedValue) {
        sel.innerHTML = '<option value="">不指定</option>';
        tags.forEach(function(tag) {
            var opt = document.createElement('option');
            opt.value = tag;
            opt.textContent = tag;
            sel.appendChild(opt);
        });
        sel.value = selectedValue || '';
    }

    async function loadTags() {
        try {
            tags = await apiCall('GET', '/api/tags');
            populateTagSelect(document.getElementById('ruleTag'));
            populateTagSelect(document.getElementById('siteTag'));
            populateTagSelect(document.getElementById('rangeTag'));
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load tags:', e);
        }
    }

    // ---- Edit mode ----
    function enterEditMode(r) {
        editRuleId.value = r.id;
        ruleFormTitle.textContent = '编辑规则 #' + r.id;
        ruleSubmitBtn.textContent = '保存修改';
        ruleCancelBtn.style.display = '';

        document.getElementById('ruleRemark').value = r.remark || '';
        populateTagSelect(document.getElementById('ruleTag'), r.tag);
        populateInterfaceSelect(inInterface, r.in_interface);
        populateIPSelect(inInterface, inIP, r.in_ip);
        document.getElementById('inPort').value = r.in_port;
        populateInterfaceSelect(outInterface, r.out_interface);
        document.getElementById('outIP').value = r.out_ip;
        document.getElementById('outPort').value = r.out_port;
        document.getElementById('protocol').value = r.protocol;
        document.getElementById('ruleTransparent').checked = !!r.transparent;

        ruleFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function exitEditMode() {
        editRuleId.value = '';
        ruleFormTitle.textContent = '添加规则';
        ruleSubmitBtn.textContent = '添加规则';
        ruleCancelBtn.style.display = 'none';
        ruleForm.reset();
    }

    // ---- Load data ----
    async function loadInterfaces() {
        try {
            interfaces = await apiCall('GET', '/api/interfaces');
            populateInterfaceSelect(inInterface);
            populateInterfaceSelect(outInterface);
            populateInterfaceSelect(siteListenIface);
            populateInterfaceSelect(rangeInInterface);
            populateInterfaceSelect(rangeOutInterface);
            populateIPSelect(inInterface, inIP);
            populateIPSelect(rangeInInterface, rangeInIP);
            populateSiteListenIP(siteListenIface, siteListenIP);
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load interfaces:', e);
        }
    }

    async function loadRules() {
        try {
            var rules = await apiCall('GET', '/api/rules');
            lastRulesData = rules;
            renderRulesTable(rules);
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load rules:', e);
        }
    }

    function getRuleStatusText(r) {
        if (!r.enabled) return '已禁用';
        if (r.status === 'error') return '\u5f02\u5e38';
        if (r.status === 'running') return '运行中';
        return '已停止';
    }

    function getRuleStatusBadge(r) {
        if (!r.enabled) return 'disabled';
        if (r.status === 'error') return 'error';
        if (r.status === 'running') return 'running';
        return 'stopped';
    }

    function getRuleSortValue(r, key) {
        if (key === 'status') {
            if (!r.enabled) return 3;
            if (r.status === 'running') return 0;
            if (r.status === 'error') return 1;
            return 2;
        }
        var val = r[key];
        if (val === undefined || val === null) return '';
        return val;
    }

    function renderRulesTable(rules) {
        rulesBody.innerHTML = '';
        if (rules.length === 0) {
            noRules.style.display = 'block';
            document.getElementById('rulesTable').style.display = 'none';
            return;
        }
        noRules.style.display = 'none';
        document.getElementById('rulesTable').style.display = 'table';

        var filtered = rules;
        if (rulesFilterTag) {
            filtered = rules.filter(function(r) { return r.tag === rulesFilterTag; });
        }

        if (rulesSortKey) {
            filtered = filtered.slice().sort(function(a, b) {
                var va = getRuleSortValue(a, rulesSortKey);
                var vb = getRuleSortValue(b, rulesSortKey);
                if (typeof va === 'number' && typeof vb === 'number') {
                    return rulesSortAsc ? va - vb : vb - va;
                }
                va = String(va).toLowerCase();
                vb = String(vb).toLowerCase();
                if (va < vb) return rulesSortAsc ? -1 : 1;
                if (va > vb) return rulesSortAsc ? 1 : -1;
                return 0;
            });
        }

        updateSortIndicators();

        filtered.forEach(function(r) {
            var tr = document.createElement('tr');
            var remarkHtml = r.remark ? '<span title="' + escHtml(r.remark) + '">' + escHtml(r.remark) + '</span>' : '<span style="color:#ccc">-</span>';
            var tagHtml = r.tag ? '<span class="tag-badge' + (rulesFilterTag === r.tag ? ' tag-active' : '') + '" data-tag="' + escHtml(r.tag) + '">' + escHtml(r.tag) + '</span>' : '<span style="color:#ccc">-</span>';
            var statusBadge = getRuleStatusBadge(r);
            var statusText = getRuleStatusText(r);
            var toggleClass = r.enabled ? 'btn-disable' : 'btn-enable';
            var toggleText = r.enabled ? '禁用' : '启用';
            tr.innerHTML =
                '<td>' + r.id + '</td>' +
                '<td>' + remarkHtml + '</td>' +
                '<td>' + tagHtml + '</td>' +
                '<td>' + (r.in_interface || '-') + '</td>' +
                '<td>' + r.in_ip + '</td>' +
                '<td>' + r.in_port + '</td>' +
                '<td>' + (r.out_interface || '-') + '</td>' +
                '<td>' + r.out_ip + '</td>' +
                '<td>' + r.out_port + '</td>' +
                '<td>' + r.protocol.toUpperCase() + '</td>' +
                '<td>' + (r.transparent ? '<span class="badge badge-running">是</span>' : '<span style="color:#ccc">-</span>') + '</td>' +
                '<td><span class="badge badge-' + statusBadge + '">' + statusText + '</span></td>' +
                '<td>' +
                '<button class="' + toggleClass + '" data-id="' + r.id + '" data-type="rule">' + toggleText + '</button>' +
                '<button class="btn-edit" data-rule=\'' + JSON.stringify(r) + '\'>编辑</button>' +
                '<button class="btn-delete" data-id="' + r.id + '" data-type="rule">删除</button>' +
                '</td>';
            rulesBody.appendChild(tr);
        });
    }

    function updateSortIndicators() {
        var ths = document.querySelectorAll('#rulesTable thead th.sortable');
        ths.forEach(function(th) {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.sort === rulesSortKey) {
                th.classList.add(rulesSortAsc ? 'sort-asc' : 'sort-desc');
            }
            if (th.dataset.sort === 'tag' && rulesFilterTag) {
                th.classList.add('tag-filtered');
            } else {
                th.classList.remove('tag-filtered');
            }
        });
    }

    function escHtml(s) {
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function formatBytes(n) {
        if (!n || n <= 0) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var v = n;
        var i = 0;
        while (v >= 1024 && i < units.length - 1) {
            v = v / 1024;
            i++;
        }
        var text = (v >= 10 || i === 0) ? Math.round(v) : v.toFixed(1);
        return text + ' ' + units[i];
    }

    function formatSpeed(bps) {
        return formatBytes(bps) + '/s';
    }

    function statusInfo(status, enabled) {
        if (enabled === false) return { badge: 'disabled', text: '\u5df2\u7981\u7528' };
        if (status === 'error') return { badge: 'error', text: '\u5f02\u5e38' };
        if (status === 'draining') return { badge: 'draining', text: '\u66f4\u65b0\u4e2d' };
        if (status === 'running') return { badge: 'running', text: '\u8fd0\u884c\u4e2d' };
        return { badge: 'stopped', text: '\u5df2\u505c\u6b62' };
    }

    async function loadSites() {
        try {
            var sites = await apiCall('GET', '/api/sites');
            sitesBody.innerHTML = '';
            if (sites.length === 0) {
                noSites.style.display = 'block';
                document.getElementById('sitesTable').style.display = 'none';
                return;
            }
            noSites.style.display = 'none';
            document.getElementById('sitesTable').style.display = 'table';
            sites.forEach(function(s) {
                var tr = document.createElement('tr');
                var statusBadge, statusText;
                if (!s.enabled) {
                    statusBadge = 'disabled'; statusText = '已禁用';
                } else if (s.status === 'error') {
                    statusBadge = 'error'; statusText = '\u5f02\u5e38';
                } else if (s.status === 'running') {
                    statusBadge = 'running'; statusText = '运行中';
                } else {
                    statusBadge = 'stopped'; statusText = '已停止';
                }
                var toggleClass = s.enabled ? 'btn-disable' : 'btn-enable';
                var toggleText = s.enabled ? '禁用' : '启用';
                var tagHtml = s.tag ? '<span class="tag-badge">' + escHtml(s.tag) + '</span>' : '<span style="color:#ccc">-</span>';
                tr.innerHTML =
                    '<td>' + s.id + '</td>' +
                    '<td>' + s.domain + '</td>' +
                    '<td>' + tagHtml + '</td>' +
                    '<td>' + s.listen_ip + '</td>' +
                    '<td>' + s.backend_ip + '</td>' +
                    '<td>' + (s.backend_http_port || '-') + '</td>' +
                    '<td>' + (s.backend_https_port || '-') + '</td>' +
                    '<td>' + (s.transparent ? '<span class="badge badge-running">是</span>' : '<span style="color:#ccc">-</span>') + '</td>' +
                    '<td><span class="badge badge-' + statusBadge + '">' + statusText + '</span></td>' +
                    '<td>' +
                    '<button class="' + toggleClass + '" data-id="' + s.id + '" data-type="site">' + toggleText + '</button>' +
                    '<button class="btn-edit-site" data-site=\'' + JSON.stringify(s) + '\'>编辑</button>' +
                    '<button class="btn-delete" data-id="' + s.id + '" data-type="site">删除</button>' +
                    '</td>';
                sitesBody.appendChild(tr);
            });
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load sites:', e);
        }
    }

    async function loadRanges() {
        try {
            var ranges = await apiCall('GET', '/api/ranges');
            rangesBody.innerHTML = '';
            if (ranges.length === 0) {
                noRanges.style.display = 'block';
                document.getElementById('rangesTable').style.display = 'none';
                return;
            }
            noRanges.style.display = 'none';
            document.getElementById('rangesTable').style.display = 'table';
            ranges.forEach(function(r) {
                var tr = document.createElement('tr');
                var remarkHtml = r.remark ? '<span title="' + escHtml(r.remark) + '">' + escHtml(r.remark) + '</span>' : '<span style="color:#ccc">-</span>';
                var tagHtml = r.tag ? '<span class="tag-badge">' + escHtml(r.tag) + '</span>' : '<span style="color:#ccc">-</span>';
                var outEndPort = r.out_start_port + (r.end_port - r.start_port);
                var statusBadge, statusText;
                if (!r.enabled) {
                    statusBadge = 'disabled'; statusText = '已禁用';
                } else if (r.status === 'error') {
                    statusBadge = 'error'; statusText = '\u5f02\u5e38';
                } else if (r.status === 'running') {
                    statusBadge = 'running'; statusText = '运行中';
                } else {
                    statusBadge = 'stopped'; statusText = '已停止';
                }
                var toggleClass = r.enabled ? 'btn-disable' : 'btn-enable';
                var toggleText = r.enabled ? '禁用' : '启用';
                tr.innerHTML =
                    '<td>' + r.id + '</td>' +
                    '<td>' + remarkHtml + '</td>' +
                    '<td>' + tagHtml + '</td>' +
                    '<td>' + (r.in_interface || '-') + '</td>' +
                    '<td>' + r.in_ip + '</td>' +
                    '<td>' + r.start_port + ' - ' + r.end_port + '</td>' +
                    '<td>' + (r.out_interface || '-') + '</td>' +
                    '<td>' + r.out_ip + '</td>' +
                    '<td>' + r.out_start_port + ' - ' + outEndPort + '</td>' +
                    '<td>' + r.protocol.toUpperCase() + '</td>' +
                    '<td>' + (r.transparent ? '<span class="badge badge-running">是</span>' : '<span style="color:#ccc">-</span>') + '</td>' +
                    '<td><span class="badge badge-' + statusBadge + '">' + statusText + '</span></td>' +
                    '<td>' +
                    '<button class="' + toggleClass + '" data-id="' + r.id + '" data-type="range">' + toggleText + '</button>' +
                    '<button class="btn-edit-range" data-range=\'' + JSON.stringify(r) + '\'>编辑</button>' +
                    '<button class="btn-delete" data-id="' + r.id + '" data-type="range">删除</button>' +
                    '</td>';
                rangesBody.appendChild(tr);
            });
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load ranges:', e);
        }
    }

    function workerTypeLabel(kind) {
        if (kind === 'rule') return '\u666e\u901a\u6620\u5c04';
        if (kind === 'range') return '\u8303\u56f4\u6620\u5c04';
        return '\u5171\u4eab\u5efa\u7ad9';
    }

    function renderRuleDetails(rules) {
        if (!rules || rules.length === 0) return '<span class="worker-empty">\u65e0\u89c4\u5219</span>';
        var html = '<div class="worker-detail-list">';
        rules.forEach(function(r) {
            var info = statusInfo(r.status, r.enabled);
            var remark = r.remark ? '<span class="worker-meta">(' + escHtml(r.remark) + ')</span>' : '';
            var protocol = (r.protocol || '').toUpperCase();
            html += '<div class="worker-detail-row">' +
                '<span class="badge badge-' + info.badge + '">' + info.text + '</span>' +
                '<span class="worker-route">#' + r.id + ' ' + r.in_ip + ':' + r.in_port + ' \u2192 ' + r.out_ip + ':' + r.out_port + '</span>' +
                '<span class="worker-proto">' + protocol + '</span>' +
                remark +
                '</div>';
        });
        html += '</div>';
        return html;
    }

    function renderRangeDetails(ranges) {
        if (!ranges || ranges.length === 0) return '<span class="worker-empty">\u65e0\u8303\u56f4</span>';
        var html = '<div class="worker-detail-list">';
        ranges.forEach(function(r) {
            var info = statusInfo(r.status, r.enabled);
            var outEnd = r.out_start_port + (r.end_port - r.start_port);
            var protocol = (r.protocol || '').toUpperCase();
            var remark = r.remark ? '<span class="worker-meta">(' + escHtml(r.remark) + ')</span>' : '';
            html += '<div class="worker-detail-row">' +
                '<span class="badge badge-' + info.badge + '">' + info.text + '</span>' +
                '<span class="worker-route">#' + r.id + ' ' + r.in_ip + ':' + r.start_port + '-' + r.end_port +
                ' \u2192 ' + r.out_ip + ':' + r.out_start_port + '-' + outEnd + '</span>' +
                '<span class="worker-proto">' + protocol + '</span>' +
                remark +
                '</div>';
        });
        html += '</div>';
        return html;
    }

    async function loadWorkers() {
        try {
            var resp = await apiCall('GET', '/api/workers');
            var masterHash = resp.binary_hash || '';
            var versionEl = document.getElementById('masterVersion');
            if (versionEl && masterHash) {
                versionEl.textContent = masterHash.substring(0, 8);
                versionEl.title = masterHash;
            }
            workersBody.innerHTML = '';
            if (!resp.workers || resp.workers.length === 0) {
                noWorkers.style.display = 'block';
                document.getElementById('workersTable').style.display = 'none';
            } else {
                noWorkers.style.display = 'none';
                document.getElementById('workersTable').style.display = 'table';
                resp.workers.forEach(function(w) {
                    var tr = document.createElement('tr');
                    var info = statusInfo(w.status);
                    var countText = '-';
                    var detailHtml = '';
                    if (w.kind === 'rule') {
                        countText = (w.rule_count || 0) + '\u6761';
                        detailHtml = renderRuleDetails(w.rules);
                    } else if (w.kind === 'range') {
                        countText = (w.range_count || 0) + '\u6761';
                        detailHtml = renderRangeDetails(w.ranges);
                    } else {
                        countText = (w.site_count || 0) + '\u4e2a\u7ad9\u70b9';
                        detailHtml = '<div class="worker-detail-list">' +
                            '<div class="worker-detail-row">' +
                            '<span class="worker-meta">\u5171\u4eab\u7ad9\u70b9\uff1a' + (w.site_count || 0) + '</span>' +
                            '</div></div>';
                    }
                    var typeClass = w.kind === 'rule' ? 'worker-type-rule' : (w.kind === 'range' ? 'worker-type-range' : 'worker-type-shared');
                    var wHash = w.binary_hash || '';
                    var hashShort = wHash ? wHash.substring(0, 8) : '-';
                    var hashMatch = wHash && masterHash && wHash === masterHash;
                    var hashClass = !wHash ? '' : (hashMatch ? 'hash-match' : 'hash-outdated');
                    var hashTitle = wHash ? wHash : '';
                    tr.innerHTML =
                        '<td><span class="worker-type ' + typeClass + '">' + workerTypeLabel(w.kind) + '</span></td>' +
                        '<td>' + (w.kind === 'shared' ? '-' : w.index) + '</td>' +
                        '<td><span class="badge badge-' + info.badge + '">' + info.text + '</span></td>' +
                        '<td><span class="worker-hash ' + hashClass + '" title="' + hashTitle + '">' + hashShort + '</span></td>' +
                        '<td>' + countText + '</td>' +
                        '<td>' + detailHtml + '</td>';
                    workersBody.appendChild(tr);
                });
            }
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load workers:', e);
        }
    }

    async function loadRuleStats() {
        try {
            var results = await Promise.all([
                apiCall('GET', '/api/rules/stats'),
                apiCall('GET', '/api/rules')
            ]);
            var stats = results[0] || [];
            var rules = results[1] || [];
            var ruleMap = {};
            rules.forEach(function(r) { ruleMap[r.id] = r; });

            ruleStatsBody.innerHTML = '';
            var table = document.getElementById('ruleStatsTable');
            if (!stats || stats.length === 0) {
                noRuleStats.style.display = 'block';
                if (table) table.style.display = 'none';
                return;
            }
            noRuleStats.style.display = 'none';
            if (table) table.style.display = 'table';
            stats.forEach(function(s) {
                var tr = document.createElement('tr');
                var rule = ruleMap[s.rule_id];
                var remark = rule && rule.remark ? escHtml(rule.remark) : '<span class="stat-muted">-</span>';
                var proto = (rule && rule.protocol) ? String(rule.protocol).toLowerCase() : '';
                var hasUDP = proto.indexOf('udp') >= 0;
                var hasTCP = proto.indexOf('tcp') >= 0;
                var currentConns = 0;
                if (hasUDP && hasTCP) {
                    currentConns = (s.nat_table_size || 0) + (s.active_conns || 0);
                } else if (hasUDP) {
                    currentConns = s.nat_table_size || 0;
                } else {
                    currentConns = s.active_conns || 0;
                }
                var totalConns = s.total_conns || 0;
                var totalClass = currentConns > 0 ? 'stat-pill active' : 'stat-pill';
                tr.innerHTML =
                    '<td class="stat-mono">' + s.rule_id + '</td>' +
                    '<td>' + remark + '</td>' +
                    '<td><span class="' + totalClass + '">' + currentConns + '</span></td>' +
                    '<td>' + totalConns + '</td>' +
                    '<td>' + (s.rejected_conns || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_in || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_out || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_in || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_out || 0) + '</td>';
                ruleStatsBody.appendChild(tr);
            });
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load rule stats:', e);
        }
    }

    async function loadSiteStats() {
        try {
            var stats = await apiCall('GET', '/api/sites/stats');
            siteStatsBody.innerHTML = '';
            var table = document.getElementById('siteStatsTable');
            if (!stats || stats.length === 0) {
                noSiteStats.style.display = 'block';
                if (table) table.style.display = 'none';
                return;
            }
            noSiteStats.style.display = 'none';
            if (table) table.style.display = 'table';
            stats.forEach(function(s) {
                var tr = document.createElement('tr');
                var currentConns = s.active_conns || 0;
                var totalClass = currentConns > 0 ? 'stat-pill active' : 'stat-pill';
                tr.innerHTML =
                    '<td class="stat-mono">' + s.site_id + '</td>' +
                    '<td>' + escHtml(s.domain || '') + '</td>' +
                    '<td><span class="' + totalClass + '">' + currentConns + '</span></td>' +
                    '<td>' + (s.total_conns || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_in || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_out || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_in || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_out || 0) + '</td>';
                siteStatsBody.appendChild(tr);
            });
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load site stats:', e);
        }
    }

    async function loadRangeStats() {
        try {
            var results = await Promise.all([
                apiCall('GET', '/api/ranges/stats'),
                apiCall('GET', '/api/ranges')
            ]);
            var stats = results[0] || [];
            var ranges = results[1] || [];
            var rangeMap = {};
            ranges.forEach(function(r) { rangeMap[r.id] = r; });

            rangeStatsBody.innerHTML = '';
            var table = document.getElementById('rangeStatsTable');
            if (!stats || stats.length === 0) {
                noRangeStats.style.display = 'block';
                if (table) table.style.display = 'none';
                return;
            }
            noRangeStats.style.display = 'none';
            if (table) table.style.display = 'table';
            stats.forEach(function(s) {
                var tr = document.createElement('tr');
                var range = rangeMap[s.range_id];
                var remark = range && range.remark ? escHtml(range.remark) : '<span class="stat-muted">-</span>';
                var proto = (range && range.protocol) ? String(range.protocol).toLowerCase() : '';
                var hasUDP = proto.indexOf('udp') >= 0;
                var hasTCP = proto.indexOf('tcp') >= 0;
                var currentConns = 0;
                if (hasUDP && hasTCP) {
                    currentConns = (s.nat_table_size || 0) + (s.active_conns || 0);
                } else if (hasUDP) {
                    currentConns = s.nat_table_size || 0;
                } else {
                    currentConns = s.active_conns || 0;
                }
                var totalConns = s.total_conns || 0;
                var totalClass = currentConns > 0 ? 'stat-pill active' : 'stat-pill';
                tr.innerHTML =
                    '<td class="stat-mono">' + s.range_id + '</td>' +
                    '<td>' + remark + '</td>' +
                    '<td><span class="' + totalClass + '">' + currentConns + '</span></td>' +
                    '<td>' + totalConns + '</td>' +
                    '<td>' + (s.rejected_conns || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_in || 0) + '</td>' +
                    '<td>' + formatSpeed(s.speed_out || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_in || 0) + '</td>' +
                    '<td>' + formatBytes(s.bytes_out || 0) + '</td>';
                rangeStatsBody.appendChild(tr);
            });
        } catch (e) {
            if (e.message !== 'unauthorized') console.error('load range stats:', e);
        }
    }

    // ---- Site edit mode ----
    function enterSiteEditMode(s) {
        editSiteId.value = s.id;
        siteFormTitle.textContent = '编辑建站配置 #' + s.id;
        siteSubmitBtn.textContent = '保存修改';
        siteCancelBtn.style.display = '';

        document.getElementById('siteDomain').value = s.domain;
        populateTagSelect(document.getElementById('siteTag'), s.tag);
        populateInterfaceSelect(siteListenIface, s.listen_interface);
        populateSiteListenIP(siteListenIface, siteListenIP);
        siteListenIP.value = s.listen_ip;
        document.getElementById('siteBackendIP').value = s.backend_ip;
        document.getElementById('siteBackendHTTP').value = s.backend_http_port || '';
        document.getElementById('siteBackendHTTPS').value = s.backend_https_port || '';
        document.getElementById('siteTransparent').checked = !!s.transparent;

        siteFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function exitSiteEditMode() {
        editSiteId.value = '';
        siteFormTitle.textContent = '添加建站配置';
        siteSubmitBtn.textContent = '添加配置';
        siteCancelBtn.style.display = 'none';
        siteForm.reset();
    }

    // ---- Range edit mode ----
    function enterRangeEditMode(r) {
        editRangeId.value = r.id;
        rangeFormTitle.textContent = '编辑范围映射 #' + r.id;
        rangeSubmitBtn.textContent = '保存修改';
        rangeCancelBtn.style.display = '';

        document.getElementById('rangeRemark').value = r.remark || '';
        populateTagSelect(document.getElementById('rangeTag'), r.tag);
        populateInterfaceSelect(rangeInInterface, r.in_interface);
        populateIPSelect(rangeInInterface, rangeInIP, r.in_ip);
        document.getElementById('rangeStartPort').value = r.start_port;
        document.getElementById('rangeEndPort').value = r.end_port;
        populateInterfaceSelect(rangeOutInterface, r.out_interface);
        document.getElementById('rangeOutIP').value = r.out_ip;
        document.getElementById('rangeOutStartPort').value = r.out_start_port || '';
        document.getElementById('rangeProtocol').value = r.protocol;
        document.getElementById('rangeTransparent').checked = !!r.transparent;

        rangeFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function exitRangeEditMode() {
        editRangeId.value = '';
        rangeFormTitle.textContent = '添加范围映射';
        rangeSubmitBtn.textContent = '添加映射';
        rangeCancelBtn.style.display = 'none';
        rangeForm.reset();
    }

    // ---- Actions ----
    async function deleteRule(id) {
        if (!confirm('确认删除规则 #' + id + '？')) return;
        try {
            await apiCall('DELETE', '/api/rules?id=' + id);
            if (editRuleId.value === String(id)) exitEditMode();
            loadRules();
        } catch (e) {
            if (e.message !== 'unauthorized') alert('删除失败: ' + e.message);
        }
    }

    async function deleteSite(id) {
        if (!confirm('确认删除建站配置 #' + id + '？')) return;
        try {
            await apiCall('DELETE', '/api/sites?id=' + id);
            if (editSiteId.value === String(id)) exitSiteEditMode();
            loadSites();
        } catch (e) {
            if (e.message !== 'unauthorized') alert('删除失败: ' + e.message);
        }
    }

    async function deleteRange(id) {
        if (!confirm('确认删除范围映射 #' + id + '？')) return;
        try {
            await apiCall('DELETE', '/api/ranges?id=' + id);
            if (editRangeId.value === String(id)) exitRangeEditMode();
            loadRanges();
        } catch (e) {
            if (e.message !== 'unauthorized') alert('删除失败: ' + e.message);
        }
    }

    async function toggleItem(type, id) {
        try {
            await apiCall('POST', '/api/' + type + 's/toggle?id=' + id);
            if (type === 'rule') loadRules();
            else if (type === 'site') loadSites();
            else if (type === 'range') loadRanges();
        } catch (e) {
            if (e.message !== 'unauthorized') alert('操作失败: ' + e.message);
        }
    }

    function buildRuleFromForm() {
        return {
            in_interface: inInterface.value,
            in_ip: inIP.value,
            in_port: parseInt(document.getElementById('inPort').value),
            out_interface: outInterface.value,
            out_ip: document.getElementById('outIP').value.trim(),
            out_port: parseInt(document.getElementById('outPort').value),
            protocol: document.getElementById('protocol').value,
            remark: document.getElementById('ruleRemark').value.trim(),
            tag: document.getElementById('ruleTag').value,
            transparent: document.getElementById('ruleTransparent').checked
        };
    }

    // ---- Events ----
    tokenSubmit.addEventListener('click', function() {
        var token = tokenInput.value.trim();
        if (!token) return;
        setToken(token);
        hideTokenModal();
        init();
    });
    tokenInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') tokenSubmit.click(); });
    logoutBtn.addEventListener('click', function() { clearToken(); showTokenModal(); });

    inInterface.addEventListener('change', function() { populateIPSelect(inInterface, inIP); });
    rangeInInterface.addEventListener('change', function() { populateIPSelect(rangeInInterface, rangeInIP); });
    siteListenIface.addEventListener('change', function() { populateSiteListenIP(siteListenIface, siteListenIP); });

    ruleCancelBtn.addEventListener('click', exitEditMode);
    siteCancelBtn.addEventListener('click', exitSiteEditMode);
    rangeCancelBtn.addEventListener('click', exitRangeEditMode);

    // Delegate clicks
    document.addEventListener('click', function(e) {
        // Sortable header click
        if (e.target.classList.contains('sortable')) {
            var key = e.target.dataset.sort;
            if (key === 'tag') {
                // Tag header: no sort, just toggle tag filter if active
                return;
            }
            if (rulesSortKey === key) {
                if (rulesSortAsc) {
                    rulesSortAsc = false;
                } else {
                    rulesSortKey = '';
                    rulesSortAsc = true;
                }
            } else {
                rulesSortKey = key;
                rulesSortAsc = true;
            }
            renderRulesTable(lastRulesData);
            return;
        }
        // Tag badge click in rules table - filter by tag
        if (e.target.classList.contains('tag-badge') && e.target.closest('#rulesBody')) {
            var clickedTag = e.target.dataset.tag;
            if (rulesFilterTag === clickedTag) {
                rulesFilterTag = '';
            } else {
                rulesFilterTag = clickedTag;
            }
            renderRulesTable(lastRulesData);
            return;
        }
        if (e.target.classList.contains('btn-enable') || e.target.classList.contains('btn-disable')) {
            var id = parseInt(e.target.dataset.id);
            var type = e.target.dataset.type;
            toggleItem(type, id);
            return;
        }
        if (e.target.classList.contains('btn-edit')) {
            var r = JSON.parse(e.target.dataset.rule);
            enterEditMode(r);
            return;
        }
        if (e.target.classList.contains('btn-edit-site')) {
            var s = JSON.parse(e.target.dataset.site);
            enterSiteEditMode(s);
            return;
        }
        if (e.target.classList.contains('btn-edit-range')) {
            var r = JSON.parse(e.target.dataset.range);
            enterRangeEditMode(r);
            return;
        }
        if (e.target.classList.contains('btn-delete')) {
            var id = parseInt(e.target.dataset.id);
            if (e.target.dataset.type === 'site') deleteSite(id);
            else if (e.target.dataset.type === 'range') deleteRange(id);
            else deleteRule(id);
        }
    });

    ruleForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        var rule = buildRuleFromForm();
        if (!rule.in_ip || !rule.in_port || !rule.out_ip || !rule.out_port) {
            alert('请填写完整的 IP 和端口');
            return;
        }
        var editing = editRuleId.value;
        try {
            if (editing) {
                rule.id = parseInt(editing);
                await apiCall('PUT', '/api/rules', rule);
                exitEditMode();
            } else {
                await apiCall('POST', '/api/rules', rule);
                ruleForm.reset();
            }
            loadRules();
        } catch (e) {
            if (e.message !== 'unauthorized') alert((editing ? '修改' : '添加') + '失败: ' + e.message);
        }
    });

    siteForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        var httpPort = parseInt(document.getElementById('siteBackendHTTP').value) || 0;
        var httpsPort = parseInt(document.getElementById('siteBackendHTTPS').value) || 0;
        if (httpPort === 0 && httpsPort === 0) { alert('HTTP 端口和 HTTPS 端口至少填写一个'); return; }
        var site = {
            domain: document.getElementById('siteDomain').value.trim(),
            listen_ip: siteListenIP.value || '0.0.0.0',
            listen_interface: siteListenIface.value,
            backend_ip: document.getElementById('siteBackendIP').value.trim(),
            backend_http_port: httpPort,
            backend_https_port: httpsPort,
            tag: document.getElementById('siteTag').value,
            transparent: document.getElementById('siteTransparent').checked
        };
        if (!site.domain || !site.backend_ip) { alert('请填写域名和后端IP'); return; }
        var editing = editSiteId.value;
        try {
            if (editing) {
                site.id = parseInt(editing);
                await apiCall('PUT', '/api/sites', site);
                exitSiteEditMode();
            } else {
                await apiCall('POST', '/api/sites', site);
                siteForm.reset();
            }
            loadSites();
        } catch (e) {
            if (e.message !== 'unauthorized') alert((editing ? '修改' : '添加') + '失败: ' + e.message);
        }
    });

    rangeForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        var startPort = parseInt(document.getElementById('rangeStartPort').value);
        var endPort = parseInt(document.getElementById('rangeEndPort').value);
        var outIP = document.getElementById('rangeOutIP').value.trim();
        var inIP = rangeInIP.value;
        if (!inIP || !startPort || !endPort || !outIP) {
            alert('请填写完整的 IP 和端口范围');
            return;
        }
        if (startPort > endPort) {
            alert('起始端口不能大于结束端口');
            return;
        }
        var outStartPort = parseInt(document.getElementById('rangeOutStartPort').value) || 0;
        var range = {
            in_interface: rangeInInterface.value,
            in_ip: inIP,
            start_port: startPort,
            end_port: endPort,
            out_interface: rangeOutInterface.value,
            out_ip: outIP,
            out_start_port: outStartPort,
            protocol: document.getElementById('rangeProtocol').value,
            remark: document.getElementById('rangeRemark').value.trim(),
            tag: document.getElementById('rangeTag').value,
            transparent: document.getElementById('rangeTransparent').checked
        };
        var editing = editRangeId.value;
        try {
            if (editing) {
                range.id = parseInt(editing);
                await apiCall('PUT', '/api/ranges', range);
                exitRangeEditMode();
            } else {
                await apiCall('POST', '/api/ranges', range);
                rangeForm.reset();
            }
            loadRanges();
        } catch (e) {
            if (e.message !== 'unauthorized') alert((editing ? '修改' : '添加') + '失败: ' + e.message);
        }
    });

    // ---- Init ----
    function init() {
        if (!getToken()) { showTokenModal(); return; }
        hideTokenModal();
        loadInterfaces();
        loadTags();
        loadRules();
        loadSites();
        loadRanges();
        loadWorkers();
        setInterval(function() {
            loadRules();
            loadSites();
            loadRanges();
            if (document.getElementById('tab-workers').classList.contains('active')) loadWorkers();
            if (document.getElementById('tab-rule-stats').classList.contains('active')) { loadRuleStats(); loadSiteStats(); loadRangeStats(); }
        }, 5000);
    }

    init();
})();
