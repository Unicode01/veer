(function () {
  const app = window.ForwardApp;
  if (!app) return;

  const colorSchemeQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  app.translations = {
    'zh-CN': {
      'app.title': 'NAT Forward Manager',
      'app.subtitle': '在一个面板里统一管理转发规则、建站配置和 Worker 状态。',
      'auth.title': '认证配置',
      'auth.description': '请输入 API Token 继续。',
      'auth.tokenPlaceholder': '请输入 Token',
      'auth.confirm': '确认',
      'auth.logout': '退出',
      'toolbar.language': '语言',
      'toolbar.theme': '主题',
      'locale.zh-CN': '简体中文',
      'locale.en-US': 'English',
      'theme.system': '跟随系统',
      'theme.light': '浅色',
      'theme.dark': '深色',
      'tab.rules': '端口转发',
      'tab.sites': '建站配置 (80/443)',
      'tab.ranges': '范围映射',
      'tab.workers': 'Worker 状态',
      'tab.stats': '流量统计',
      'form.remark': '备注',
      'form.tag': '标签',
      'form.protocol': '协议',
      'form.transparent': '透传源 IP',
      'form.transparentShort': '透传',
      'form.inInterface': '入接口',
      'form.inIP': '入 IP',
      'form.inPort': '入端口',
      'form.outInterface': '出接口',
      'form.outIP': '出 IP',
      'form.outPort': '出端口',
      'common.unspecified': '不指定',
      'common.selectInterfaceFirst': '请先选择接口',
      'common.allAddresses': '0.0.0.0 (所有)',
      'common.status': '状态',
      'common.actions': '操作',
      'common.cancel': '取消',
      'common.cancelEdit': '取消编辑',
      'common.confirm': '确认',
      'common.clear': '清除',
      'common.enable': '启用',
      'common.disable': '禁用',
      'common.edit': '编辑',
      'common.clone': '克隆',
      'common.delete': '删除',
      'common.yes': '是',
      'common.dash': '-',
      'common.processing': '处理中...',
      'common.saving': '保存中...',
      'common.refresh': '刷新',
      'common.noMatches': '当前筛选下没有匹配项。',
      'common.signingOut': '退出中...',
      'rule.form.remark.placeholder': '可选，如：Web 服务器转发',
      'rule.form.title.add': '添加规则',
      'rule.form.title.edit': '编辑规则 #{{id}}',
      'rule.form.title.clone': '克隆新规则 (来源 #{{id}})',
      'rule.form.submit.add': '添加规则',
      'rule.form.submit.edit': '保存修改',
      'rule.form.submit.clone': '创建规则',
      'rule.list.title': '转发规则',
      'rule.list.empty': '暂无转发规则',
      'rule.delete.confirm': '确认删除规则 #{{id}} 吗？',
      'site.form.title.add': '添加建站配置',
      'site.form.title.edit': '编辑建站配置 #{{id}}',
      'site.form.title.clone': '克隆新建站配置 (来源 #{{id}})',
      'site.form.submit.add': '添加配置',
      'site.form.submit.edit': '保存修改',
      'site.form.submit.clone': '创建配置',
      'site.form.desc': '多个域名共享 80/443 端口，通过 HTTP Host / TLS SNI 路由到不同后端。',
      'site.form.domain': '域名',
      'site.form.listenInterface': '监听接口',
      'site.form.listenIP': '监听 IP',
      'site.form.backendIP': '后端 IP',
      'site.form.backendHTTP': '后端 HTTP 端口',
      'site.form.backendHTTP.placeholder': '80 (0=不启用)',
      'site.form.backendHTTPS': '后端 HTTPS 端口',
      'site.form.backendHTTPS.placeholder': '443 (0=不启用)',
      'site.list.title': '建站列表',
      'site.list.httpPort': 'HTTP 端口',
      'site.list.httpsPort': 'HTTPS 端口',
      'site.list.empty': '暂无建站配置',
      'site.delete.confirm': '确认删除建站配置 #{{id}} 吗？',
      'range.form.remark.placeholder': '可选，如：游戏服务器端口段',
      'range.form.title.add': '添加范围映射',
      'range.form.title.edit': '编辑范围映射 #{{id}}',
      'range.form.title.clone': '克隆新范围映射 (来源 #{{id}})',
      'range.form.submit.add': '添加映射',
      'range.form.submit.edit': '保存修改',
      'range.form.submit.clone': '创建映射',
      'range.form.desc': '将本机端口范围 (如 10000-20000) 一一映射到目标主机的对应端口。',
      'range.form.startPort': '起始端口',
      'range.form.endPort': '结束端口',
      'range.form.targetIP': '目标 IP',
      'range.form.targetStartPort': '目标起始端口',
      'range.form.targetStartPort.placeholder': '留空 = 同入端口',
      'range.list.title': '范围映射列表',
      'range.list.inboundRange': '入端口范围',
      'range.list.outboundRange': '出端口范围',
      'range.list.empty': '暂无范围映射',
      'range.delete.confirm': '确认删除范围映射 #{{id}} 吗？',
      'workers.title': 'Worker 状态',
      'workers.kind': '类型',
      'workers.version': '版本',
      'workers.count': '数量',
      'workers.details': '详情',
      'workers.empty': '暂无 Worker',
      'workers.kind.rule': '普通映射',
      'workers.kind.range': '范围映射',
      'workers.kind.shared': '共享建站',
      'workers.emptyRules': '无规则',
      'workers.emptyRanges': '无范围',
      'workers.count.sites': '{{count}} 个站点',
      'workers.count.entries': '{{count}} 条',
      'workers.sharedSites': '共享站点：{{count}}',
      'workers.refresh': '刷新 Workers',
      'overview.kicker': '实时概览',
      'overview.title': '概览',
      'overview.desc': '快速查看总数、运行中项目和最近一次刷新时间。',
      'overview.rules': '规则',
      'overview.sites': '站点',
      'overview.ranges': '范围',
      'overview.workers': 'Worker',
      'overview.running': '运行中',
      'overview.autoRefresh': '每 5 秒自动刷新一次',
      'overview.awaitingSync': '等待首次同步',
      'overview.syncing': '正在同步…',
      'overview.lastSync': '最近更新于 {{time}}',
      'filter.activeTag': '当前按标签筛选：{{tag}}',
      'filter.summary.all': '显示 {{count}} 项',
      'filter.summary.filtered': '显示 {{visible}} / {{total}} 项',
      'filter.clear': '清除筛选',
      'pagination.previous': '上一页',
      'pagination.next': '下一页',
      'pagination.page': '第 {{page}} / {{totalPages}} 页',
      'pagination.summary': '显示 {{start}}-{{end}} / {{total}}',
      'pagination.pageSize': '每页',
      'search.rules.placeholder': '搜索规则、IP、端口、标签...',
      'search.sites.placeholder': '搜索域名、IP、标签...',
      'search.ranges.placeholder': '搜索备注、IP、端口、标签...',
      'search.workers.placeholder': '搜索类型、哈希、路由...',
      'empty.action.rule': '创建第一条规则',
      'empty.action.site': '创建第一个站点',
      'empty.action.range': '创建第一条映射',
      'confirm.warningTitle': '确认操作',
      'confirm.deleteTitle': '确认删除',
      'confirm.logoutTitle': '退出登录',
      'auth.logoutConfirm': '这会清除当前保存的 Token。继续吗？',
      'stats.rules.title': '规则流量统计',
      'stats.sites.title': '建站流量统计',
      'stats.ranges.title': '范围映射流量统计',
      'stats.currentConns': '连接数',
      'stats.totalConns': '总连接数',
      'stats.rejectedConns': '拒绝连接数',
      'stats.speedIn': '上行速度',
      'stats.speedOut': '下行速度',
      'stats.bytesIn': '总上行',
      'stats.bytesOut': '总下行',
      'stats.rules.empty': '暂无统计数据（规则未运行）',
      'stats.sites.empty': '暂无建站统计数据',
      'stats.ranges.empty': '暂无范围映射统计数据',
      'transparent.info.invalid': '透传依赖后端使用明确的 IPv4 地址，并且回包必须重新经过本机。',
      'transparent.warning.public': '检测到目标是公网 IP。如果 {{target}} 的默认网关不经过本机（例如上级直接路由到 VM），透传通常会失败。',
      'transparent.warning.publicBridge': '检测到目标是公网 IP，且出接口像桥接接口。如果 {{target}} 的默认网关不经过本机（例如本机只做网桥），透传通常会失败。',
      'transparent.info.enabled': '透传已开启。请确认 {{target}} 的默认网关或策略路由指向本机，否则回包不会回到本机。',
      'transparent.confirmContinue': '继续保存吗？',
      'transparent.target.backend': '后端主机',
      'transparent.target.destination': '目标主机',
      'status.disabled': '已禁用',
      'status.error': '异常',
      'status.draining': '更新中',
      'status.running': '运行中',
      'status.stopped': '已停止',
      'errors.operationFailed': '操作失败: {{message}}',
      'errors.deleteFailed': '删除失败: {{message}}',
      'errors.actionFailed': '{{action}}失败: {{message}}',
      'action.add': '添加',
      'action.update': '修改',
      'noun.rule': '规则',
      'noun.site': '站点',
      'noun.range': '范围映射',
      'toast.created': '{{item}}已创建。',
      'toast.saved': '{{item}}已保存。',
      'toast.deleted': '{{item}}已删除。',
      'toast.enabled': '{{item}}已启用。',
      'toast.disabled': '{{item}}已禁用。',
      'toast.loggedOut': '已退出登录。',
      'validation.required': '此字段必填。',
      'validation.ipv4': '请输入有效的 IPv4 地址。',
      'validation.reviewErrors': '请检查已标记的字段。',
      'validation.ruleRequired': '请填写完整的 IP 和端口。',
      'validation.sitePortsRequired': 'HTTP 端口和 HTTPS 端口至少填写一个。',
      'validation.siteRequired': '请填写域名和后端 IP。',
      'validation.rangeRequired': '请填写完整的 IP 和端口范围。',
      'validation.rangeOrder': '起始端口不能大于结束端口。'
    },
    'en-US': {
      'app.title': 'NAT Forward Manager',
      'app.subtitle': 'Manage forwarding rules, sites, and worker state from one panel.',
      'auth.title': 'Authentication',
      'auth.description': 'Enter your API token to continue.',
      'auth.tokenPlaceholder': 'Enter token',
      'auth.confirm': 'Continue',
      'auth.logout': 'Logout',
      'toolbar.language': 'Language',
      'toolbar.theme': 'Theme',
      'locale.zh-CN': '简体中文',
      'locale.en-US': 'English',
      'theme.system': 'System',
      'theme.light': 'Light',
      'theme.dark': 'Dark',
      'tab.rules': 'Port Forwarding',
      'tab.sites': 'Sites (80/443)',
      'tab.ranges': 'Range Mapping',
      'tab.workers': 'Worker Status',
      'tab.stats': 'Traffic Stats',
      'form.remark': 'Remark',
      'form.tag': 'Tag',
      'form.protocol': 'Protocol',
      'form.transparent': 'Transparent Source IP',
      'form.transparentShort': 'Transparent',
      'form.inInterface': 'Inbound Interface',
      'form.inIP': 'Inbound IP',
      'form.inPort': 'Inbound Port',
      'form.outInterface': 'Outbound Interface',
      'form.outIP': 'Outbound IP',
      'form.outPort': 'Outbound Port',
      'common.unspecified': 'Unspecified',
      'common.selectInterfaceFirst': 'Select interface first',
      'common.allAddresses': '0.0.0.0 (All)',
      'common.status': 'Status',
      'common.actions': 'Actions',
      'common.cancel': 'Cancel',
      'common.cancelEdit': 'Cancel',
      'common.confirm': 'Confirm',
      'common.clear': 'Clear',
      'common.enable': 'Enable',
      'common.disable': 'Disable',
      'common.edit': 'Edit',
      'common.clone': 'Clone',
      'common.delete': 'Delete',
      'common.yes': 'Yes',
      'common.dash': '-',
      'common.processing': 'Working...',
      'common.saving': 'Saving...',
      'common.refresh': 'Refresh',
      'common.noMatches': 'No matches for the current filters.',
      'common.signingOut': 'Signing out...',
      'rule.form.remark.placeholder': 'Optional, e.g. Web server forwarding',
      'rule.form.title.add': 'Add Rule',
      'rule.form.title.edit': 'Edit Rule #{{id}}',
      'rule.form.title.clone': 'Clone Rule (from #{{id}})',
      'rule.form.submit.add': 'Add Rule',
      'rule.form.submit.edit': 'Save Changes',
      'rule.form.submit.clone': 'Create Rule',
      'rule.list.title': 'Forwarding Rules',
      'rule.list.empty': 'No forwarding rules yet.',
      'rule.delete.confirm': 'Delete rule #{{id}}?',
      'site.form.title.add': 'Add Site',
      'site.form.title.edit': 'Edit Site #{{id}}',
      'site.form.title.clone': 'Clone Site (from #{{id}})',
      'site.form.submit.add': 'Add Site',
      'site.form.submit.edit': 'Save Changes',
      'site.form.submit.clone': 'Create Site',
      'site.form.desc': 'Share ports 80/443 across multiple domains and route by HTTP Host or TLS SNI.',
      'site.form.domain': 'Domain',
      'site.form.listenInterface': 'Listen Interface',
      'site.form.listenIP': 'Listen IP',
      'site.form.backendIP': 'Backend IP',
      'site.form.backendHTTP': 'Backend HTTP Port',
      'site.form.backendHTTP.placeholder': '80 (0 disables)',
      'site.form.backendHTTPS': 'Backend HTTPS Port',
      'site.form.backendHTTPS.placeholder': '443 (0 disables)',
      'site.list.title': 'Sites',
      'site.list.httpPort': 'HTTP Port',
      'site.list.httpsPort': 'HTTPS Port',
      'site.list.empty': 'No sites yet.',
      'site.delete.confirm': 'Delete site #{{id}}?',
      'range.form.remark.placeholder': 'Optional, e.g. game server ports',
      'range.form.title.add': 'Add Range Mapping',
      'range.form.title.edit': 'Edit Range Mapping #{{id}}',
      'range.form.title.clone': 'Clone Range Mapping (from #{{id}})',
      'range.form.submit.add': 'Add Mapping',
      'range.form.submit.edit': 'Save Changes',
      'range.form.submit.clone': 'Create Mapping',
      'range.form.desc': 'Map a local port range such as 10000-20000 one-to-one to the target host.',
      'range.form.startPort': 'Start Port',
      'range.form.endPort': 'End Port',
      'range.form.targetIP': 'Target IP',
      'range.form.targetStartPort': 'Target Start Port',
      'range.form.targetStartPort.placeholder': 'Blank = same as inbound',
      'range.list.title': 'Range Mappings',
      'range.list.inboundRange': 'Inbound Port Range',
      'range.list.outboundRange': 'Outbound Port Range',
      'range.list.empty': 'No range mappings yet.',
      'range.delete.confirm': 'Delete range mapping #{{id}}?',
      'workers.title': 'Worker Status',
      'workers.kind': 'Type',
      'workers.version': 'Version',
      'workers.count': 'Count',
      'workers.details': 'Details',
      'workers.empty': 'No workers yet.',
      'workers.kind.rule': 'Direct Mapping',
      'workers.kind.range': 'Range Mapping',
      'workers.kind.shared': 'Shared Sites',
      'workers.emptyRules': 'No rules',
      'workers.emptyRanges': 'No ranges',
      'workers.count.sites': '{{count}} sites',
      'workers.count.entries': '{{count}} entries',
      'workers.sharedSites': 'Shared sites: {{count}}',
      'workers.refresh': 'Refresh Workers',
      'overview.kicker': 'Live Overview',
      'overview.title': 'Overview',
      'overview.desc': 'Quickly scan totals, running items, and the latest refresh time.',
      'overview.rules': 'Rules',
      'overview.sites': 'Sites',
      'overview.ranges': 'Ranges',
      'overview.workers': 'Workers',
      'overview.running': 'Running',
      'overview.autoRefresh': 'Auto refresh every 5 seconds',
      'overview.awaitingSync': 'Waiting for first sync',
      'overview.syncing': 'Syncing…',
      'overview.lastSync': 'Updated {{time}}',
      'filter.activeTag': 'Filtering by tag: {{tag}}',
      'filter.summary.all': 'Showing {{count}} items',
      'filter.summary.filtered': 'Showing {{visible}} / {{total}} items',
      'filter.clear': 'Clear Filter',
      'pagination.previous': 'Previous',
      'pagination.next': 'Next',
      'pagination.page': 'Page {{page}} / {{totalPages}}',
      'pagination.summary': 'Showing {{start}}-{{end}} / {{total}}',
      'pagination.pageSize': 'Per page',
      'search.rules.placeholder': 'Search rules, IPs, ports, tags...',
      'search.sites.placeholder': 'Search domains, IPs, tags...',
      'search.ranges.placeholder': 'Search remarks, IPs, ports, tags...',
      'search.workers.placeholder': 'Search type, hash, route...',
      'empty.action.rule': 'Create First Rule',
      'empty.action.site': 'Create First Site',
      'empty.action.range': 'Create First Mapping',
      'confirm.warningTitle': 'Confirm Action',
      'confirm.deleteTitle': 'Confirm Deletion',
      'confirm.logoutTitle': 'Sign Out',
      'auth.logoutConfirm': 'This clears the saved token for this browser. Continue?',
      'stats.rules.title': 'Rule Traffic Stats',
      'stats.sites.title': 'Site Traffic Stats',
      'stats.ranges.title': 'Range Traffic Stats',
      'stats.currentConns': 'Connections',
      'stats.totalConns': 'Total Connections',
      'stats.rejectedConns': 'Rejected Connections',
      'stats.speedIn': 'Ingress Speed',
      'stats.speedOut': 'Egress Speed',
      'stats.bytesIn': 'Ingress Total',
      'stats.bytesOut': 'Egress Total',
      'stats.rules.empty': 'No rule statistics yet.',
      'stats.sites.empty': 'No site statistics yet.',
      'stats.ranges.empty': 'No range statistics yet.',
      'transparent.info.invalid': 'Transparent mode requires a concrete IPv4 backend address, and reply traffic must pass back through this host.',
      'transparent.warning.public': 'A public target IP was detected. Transparent mode usually fails if the default gateway of {{target}} does not route back through this host.',
      'transparent.warning.publicBridge': 'A public target IP and a bridge-like outbound interface were detected. Transparent mode usually fails if the default gateway of {{target}} does not route back through this host.',
      'transparent.info.enabled': 'Transparent mode is enabled. Confirm that the default gateway or policy route of {{target}} points back to this host, otherwise reply traffic will bypass it.',
      'transparent.confirmContinue': 'Continue saving?',
      'transparent.target.backend': 'the backend host',
      'transparent.target.destination': 'the target host',
      'status.disabled': 'Disabled',
      'status.error': 'Error',
      'status.draining': 'Updating',
      'status.running': 'Running',
      'status.stopped': 'Stopped',
      'errors.operationFailed': 'Operation failed: {{message}}',
      'errors.deleteFailed': 'Delete failed: {{message}}',
      'errors.actionFailed': '{{action}} failed: {{message}}',
      'action.add': 'Add',
      'action.update': 'Update',
      'noun.rule': 'Rule',
      'noun.site': 'Site',
      'noun.range': 'Range Mapping',
      'toast.created': '{{item}} created.',
      'toast.saved': '{{item}} saved.',
      'toast.deleted': '{{item}} deleted.',
      'toast.enabled': '{{item}} enabled.',
      'toast.disabled': '{{item}} disabled.',
      'toast.loggedOut': 'Signed out.',
      'validation.required': 'This field is required.',
      'validation.ipv4': 'Enter a valid IPv4 address.',
      'validation.reviewErrors': 'Review the highlighted fields.',
      'validation.ruleRequired': 'Please fill in complete IP and port values.',
      'validation.sitePortsRequired': 'Fill in either the HTTP port or the HTTPS port.',
      'validation.siteRequired': 'Please fill in the domain and backend IP.',
      'validation.rangeRequired': 'Please fill in complete IP and port range values.',
      'validation.rangeOrder': 'The start port must not exceed the end port.'
    }
  };

  app.storageKeys = Object.assign({
    locale: 'forward_locale',
    theme: 'forward_theme'
  }, app.storageKeys || {});

  app.el.localeSelect = app.$('localeSelect');
  app.el.themeSelect = app.$('themeSelect');

  app.state.locale = app.state.locale || 'zh-CN';
  app.state.theme = app.state.theme || 'system';
  app.state.resolvedTheme = app.state.resolvedTheme || 'light';
  app.state.pollerId = app.state.pollerId || 0;
  app.state.forms = app.state.forms || {
    rule: { mode: 'add', sourceId: 0 },
    site: { mode: 'add', sourceId: 0 },
    range: { mode: 'add', sourceId: 0 }
  };

  app.normalizeLocale = function normalizeLocale(locale) {
    return locale === 'en-US' ? 'en-US' : 'zh-CN';
  };

  app.normalizeTheme = function normalizeTheme(theme) {
    return theme === 'light' || theme === 'dark' ? theme : 'system';
  };

  app.detectLocale = function detectLocale() {
    const candidate = (navigator.languages && navigator.languages[0]) || navigator.language || '';
    return /^en/i.test(candidate) ? 'en-US' : 'zh-CN';
  };

  app.t = function t(key, params) {
    const locale = app.state.locale || 'zh-CN';
    const dict = app.translations[locale] || app.translations['en-US'];
    const fallback = app.translations['en-US'] || {};
    let text = dict[key] || fallback[key] || key;
    if (!params) return text;
    return text.replace(/\{\{(\w+)\}\}/g, (_, name) => {
      if (!Object.prototype.hasOwnProperty.call(params, name)) return '';
      return params[name] == null ? '' : String(params[name]);
    });
  };

  app.getLocale = function getLocale() {
    return app.normalizeLocale(localStorage.getItem(app.storageKeys.locale) || app.detectLocale());
  };

  app.setLocale = function setLocale(locale) {
    app.state.locale = app.normalizeLocale(locale);
    localStorage.setItem(app.storageKeys.locale, app.state.locale);
    document.documentElement.lang = app.state.locale;
    if (app.el.localeSelect) app.el.localeSelect.value = app.state.locale;
    app.refreshLocalizedUI();
  };

  app.resolveTheme = function resolveTheme(theme) {
    if (theme === 'light' || theme === 'dark') return theme;
    return colorSchemeQuery && colorSchemeQuery.matches ? 'dark' : 'light';
  };

  app.getTheme = function getTheme() {
    return app.normalizeTheme(localStorage.getItem(app.storageKeys.theme) || 'system');
  };

  app.applyTheme = function applyTheme(theme, persist) {
    app.state.theme = app.normalizeTheme(theme);
    app.state.resolvedTheme = app.resolveTheme(app.state.theme);

    if (persist !== false) {
      localStorage.setItem(app.storageKeys.theme, app.state.theme);
    }

    document.documentElement.dataset.theme = app.state.resolvedTheme;
    document.documentElement.style.colorScheme = app.state.resolvedTheme;
    if (app.el.themeSelect) app.el.themeSelect.value = app.state.theme;
  };

  app.setTheme = function setTheme(theme) {
    app.applyTheme(theme, true);
  };

  app.localizeDocument = function localizeDocument() {
    document.querySelectorAll('[data-i18n]').forEach((node) => {
      node.textContent = app.t(node.dataset.i18n);
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
      node.setAttribute('placeholder', app.t(node.dataset.i18nPlaceholder));
    });

    document.querySelectorAll('[data-i18n-title]').forEach((node) => {
      node.setAttribute('title', app.t(node.dataset.i18nTitle));
    });

    document.title = app.t('app.title');
  };

  app.emptyCellHTML = function emptyCellHTML(extraClass) {
    return '<span class="cell-empty' + (extraClass ? ' ' + extraClass : '') + '">' + app.t('common.dash') + '</span>';
  };

  app.addOption = function addOption(sel, value, label) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label;
    sel.appendChild(opt);
  };

  app.stopPolling = function stopPolling() {
    if (app.state.pollerId) {
      clearInterval(app.state.pollerId);
      app.state.pollerId = 0;
    }
  };

  app.showTokenModal = function showTokenModal() {
    app.stopPolling();
    app.el.appRoot.style.display = 'none';
    app.el.tokenModal.classList.add('active');
    app.el.tokenInput.value = '';
    app.el.tokenInput.focus();
  };

  app.compareValues = function compareValues(a, b) {
    const va = a == null ? '' : a;
    const vb = b == null ? '' : b;
    if (typeof va === 'number' && typeof vb === 'number') return va - vb;
    return String(va).localeCompare(String(vb), app.state.locale, { numeric: true, sensitivity: 'base' });
  };

  app.statusInfo = function statusInfo(status, enabled) {
    if (enabled === false) return { badge: 'disabled', text: app.t('status.disabled') };
    if (status === 'error') return { badge: 'error', text: app.t('status.error') };
    if (status === 'draining') return { badge: 'draining', text: app.t('status.draining') };
    if (status === 'running') return { badge: 'running', text: app.t('status.running') };
    return { badge: 'stopped', text: app.t('status.stopped') };
  };

  app.buildTransparentWarning = function buildTransparentWarning(transparent, backendIP, outIface, targetKey) {
    if (!transparent) return { level: '', text: '', needsConfirm: false };

    const ip = (backendIP || '').trim();
    if (!app.parseIPv4(ip)) {
      return {
        level: 'info',
        text: app.t('transparent.info.invalid'),
        needsConfirm: false
      };
    }

    if (app.isPublicIPv4(ip)) {
      return {
        level: 'warning',
        text: app.t(app.isBridgeInterface(outIface) ? 'transparent.warning.publicBridge' : 'transparent.warning.public', {
          target: app.t(targetKey)
        }),
        needsConfirm: true
      };
    }

    return {
      level: 'info',
      text: app.t('transparent.info.enabled', { target: app.t(targetKey) }),
      needsConfirm: false
    };
  };

  app.confirmTransparentWarning = function confirmTransparentWarning(warning) {
    return !warning || !warning.needsConfirm;
  };

  app.updateRuleTransparentWarning = function updateRuleTransparentWarning() {
    return app.applyTransparentWarning(
      app.el.ruleTransparentWarning,
      app.buildTransparentWarning(app.el.ruleTransparent.checked, app.el.ruleOutIP.value, app.el.outInterface.value, 'transparent.target.backend')
    );
  };

  app.updateSiteTransparentWarning = function updateSiteTransparentWarning() {
    return app.applyTransparentWarning(
      app.el.siteTransparentWarning,
      app.buildTransparentWarning(app.el.siteTransparent.checked, app.el.siteBackendIP.value, '', 'transparent.target.backend')
    );
  };

  app.updateRangeTransparentWarning = function updateRangeTransparentWarning() {
    return app.applyTransparentWarning(
      app.el.rangeTransparentWarning,
      app.buildTransparentWarning(app.el.rangeTransparent.checked, app.el.rangeOutIP.value, app.el.rangeOutInterface.value, 'transparent.target.destination')
    );
  };

  app.populateInterfaceSelect = function populateInterfaceSelect(sel, selected) {
    if (!sel) return;
    const current = selected == null ? sel.value : selected;
    sel.innerHTML = '';
    app.addOption(sel, '', app.t('common.unspecified'));
    app.interfaces.forEach((iface) => {
      app.addOption(sel, iface.name, iface.name + ' (' + iface.addrs.join(', ') + ')');
    });
    sel.value = current || '';
  };

  app.populateIPSelect = function populateIPSelect(ifaceSel, ipSel, selected) {
    if (!ipSel) return;
    const current = selected == null ? ipSel.value : selected;
    const ifaceName = ifaceSel ? ifaceSel.value : '';
    ipSel.innerHTML = '';
    app.addOption(ipSel, '0.0.0.0', app.t('common.allAddresses'));

    if (!ifaceName) {
      app.interfaces.forEach((iface) => {
        iface.addrs.forEach((addr) => {
          app.addOption(ipSel, addr, addr + ' (' + iface.name + ')');
        });
      });
    } else {
      const iface = app.interfaces.find((item) => item.name === ifaceName);
      if (iface) {
        iface.addrs.forEach((addr) => app.addOption(ipSel, addr, addr));
      }
    }

    ipSel.value = current || '0.0.0.0';
  };

  app.populateSiteListenIP = function populateSiteListenIP(ifaceSel, ipSel, selected) {
    app.populateIPSelect(ifaceSel, ipSel, selected);
  };

  app.populateTagSelect = function populateTagSelect(sel, selected) {
    if (!sel) return;
    const current = selected == null ? sel.value : selected;
    sel.innerHTML = '';
    app.addOption(sel, '', app.t('common.unspecified'));
    app.tags.forEach((tag) => app.addOption(sel, tag, tag));
    sel.value = current || '';
  };

  app.rebuildSelects = function rebuildSelects() {
    if (app.el.localeSelect) app.el.localeSelect.value = app.state.locale;
    if (app.el.themeSelect) app.el.themeSelect.value = app.state.theme;

    app.populateInterfaceSelect(app.el.inInterface, app.el.inInterface.value);
    app.populateInterfaceSelect(app.el.outInterface, app.el.outInterface.value);
    app.populateInterfaceSelect(app.el.siteListenIface, app.el.siteListenIface.value);
    app.populateInterfaceSelect(app.el.rangeInInterface, app.el.rangeInInterface.value);
    app.populateInterfaceSelect(app.el.rangeOutInterface, app.el.rangeOutInterface.value);

    app.populateIPSelect(app.el.inInterface, app.el.inIP, app.el.inIP.value);
    app.populateIPSelect(app.el.rangeInInterface, app.el.rangeInIP, app.el.rangeInIP.value);
    app.populateSiteListenIP(app.el.siteListenIface, app.el.siteListenIP, app.el.siteListenIP.value);

    app.populateTagSelect(app.$('ruleTag'), app.$('ruleTag').value);
    app.populateTagSelect(app.$('siteTag'), app.$('siteTag').value);
    app.populateTagSelect(app.$('rangeTag'), app.$('rangeTag').value);
  };

  app.refreshLocalizedUI = function refreshLocalizedUI() {
    app.localizeDocument();
    app.rebuildSelects();

    if (typeof app.syncRuleFormState === 'function') app.syncRuleFormState();
    if (typeof app.syncSiteFormState === 'function') app.syncSiteFormState();
    if (typeof app.syncRangeFormState === 'function') app.syncRangeFormState();

    app.updateRuleTransparentWarning();
    app.updateSiteTransparentWarning();
    app.updateRangeTransparentWarning();

    if (typeof app.renderRulesTable === 'function') app.renderRulesTable();
    if (typeof app.renderSitesTable === 'function') app.renderSitesTable();
    if (typeof app.renderRangesTable === 'function') app.renderRangesTable();
    if (typeof app.renderWorkersTable === 'function') app.renderWorkersTable();
    if (typeof app.renderRuleStatsTable === 'function') app.renderRuleStatsTable();
    if (typeof app.renderSiteStatsTable === 'function') app.renderSiteStatsTable();
    if (typeof app.renderRangeStatsTable === 'function') app.renderRangeStatsTable();
  };

  app.state.locale = app.getLocale();
  app.state.theme = app.getTheme();
  app.applyTheme(app.state.theme, false);
  document.documentElement.lang = app.state.locale;

  if (colorSchemeQuery) {
    const syncSystemTheme = function syncSystemTheme() {
      if (app.state.theme === 'system') app.applyTheme('system', false);
    };

    if (typeof colorSchemeQuery.addEventListener === 'function') {
      colorSchemeQuery.addEventListener('change', syncSystemTheme);
    } else if (typeof colorSchemeQuery.addListener === 'function') {
      colorSchemeQuery.addListener(syncSystemTheme);
    }
  }

  app.localizeDocument();
})();
