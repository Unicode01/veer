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
      'tab.managedNetworks': '托管网络',
      'tab.egressNATs': '出向 NAT',
      'tab.ipv6Assignments': 'IPv6 分配',
      'tab.workers': 'Worker 状态',
      'tab.stats': '流量统计',
      'form.remark': '备注',
      'form.tag': '标签',
      'form.protocol': '协议',
      'form.engine': '转发引擎',
      'form.transparent': '透传源 IP',
      'form.transparentShort': '透传',
      'form.inInterface': '入接口',
      'form.inIP': '入 IP',
      'form.inPort': '入端口',
      'form.outInterface': '出接口',
      'form.outIP': '出 IP',
      'form.outSourceIP': '固定出站源 IP',
      'form.outPort': '出端口',
      'interface.picker.placeholder': '搜索或选择接口...',
      'interface.search.placeholder': '筛选接口...',
      'interface.search.noResults': '没有匹配的接口',
      'common.unspecified': '不指定',
      'common.selectInterfaceFirst': '请先选择接口',
      'common.allAddresses': '0.0.0.0 (所有)',
      'common.allIPv4Addresses': '0.0.0.0 (所有 IPv4)',
      'common.allIPv6Addresses': ':: (所有 IPv6)',
      'common.familyLabel': '地址族',
      'common.family.ipv4': 'IPv4',
      'common.family.ipv6': 'IPv6',
      'common.family.mixed': '混合',
      'common.status': '状态',
      'common.actions': '操作',
      'common.cancel': '取消',
      'common.cancelEdit': '取消编辑',
      'common.confirm': '确认',
      'common.auto': '自动选择',
      'common.clear': '清除',
      'common.enable': '启用',
      'common.disable': '禁用',
      'common.edit': '编辑',
      'common.clone': '克隆',
      'common.delete': '删除',
      'common.yes': '是',
      'common.skipped': '已跳过',
      'common.dash': '-',
      'common.unavailable': '当前不可用',
      'common.sourceShort': '源',
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
      'rule.list.engine': '引擎',
      'rule.list.empty': '暂无转发规则',
      'rule.engine.preferenceLabel': '偏好',
      'rule.engine.effectiveLabel': '实际',
      'rule.engine.preference.auto': '自动',
      'rule.engine.preference.userspace': '用户态',
      'rule.engine.preference.kernel': '内核',
      'rule.engine.effective.userspace': '用户态',
      'rule.engine.effective.kernel': '内核态',
      'rule.engine.hint.kernelActive': '内核生效',
      'rule.engine.hint.kernelReady': '可切内核',
      'rule.engine.hint.userspaceOnly': '仅用户态',
      'rule.engine.hint.fallback': '已回退',
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
      'site.form.backendSourceIP': '后端源 IP',
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
      'managedNetwork.form.title.add': '添加托管网络',
      'managedNetwork.form.title.edit': '编辑托管网络 #{{id}}',
      'managedNetwork.form.desc': '用一条托管网络配置统一定义下游桥、IPv4 网关与 DHCPv4 地址池、可选 IPv6 下发来源，以及是否自动接管出向流量做 Egress NAT。',
      'managedNetwork.form.name': '名称',
      'managedNetwork.form.name.placeholder': '例如：vm100-lan',
      'managedNetwork.form.bridgeMode': '桥模式',
      'managedNetwork.form.bridgeMode.create': '创建新桥',
      'managedNetwork.form.bridgeMode.existing': '使用现有接口',
      'managedNetwork.form.bridge': '桥 / 下游接口',
      'managedNetwork.form.bridge.createLabel': '新桥名称',
      'managedNetwork.form.bridge.existingLabel': '现有桥 / 下游接口',
      'managedNetwork.form.bridge.placeholder.create': '输入新 bridge 名称，例如 vmbr1',
      'managedNetwork.form.bridge.placeholder.existing': '搜索或选择现有接口...',
      'managedNetwork.form.advancedOptions': '高级选项',
      'managedNetwork.form.bridgeMTU': '桥 MTU',
      'managedNetwork.form.bridgeVLANAware': 'VLAN 感知桥',
      'managedNetwork.form.bridgeAdvancedHint': '仅在创建新托管桥时生效。使用现有接口模式会保留当前桥配置。',
      'managedNetwork.form.uplinkInterface': '上行接口',
      'managedNetwork.form.autoEgressNAT': '自动出向 NAT',
      'managedNetwork.form.ipv4Enabled': '启用 IPv4 网关 + DHCPv4',
      'managedNetwork.form.ipv4CIDR': 'IPv4 网关 CIDR',
      'managedNetwork.form.ipv4CIDR.placeholder': '例如 192.0.2.1/24',
      'managedNetwork.form.ipv4Gateway': 'IPv4 网关覆盖值',
      'managedNetwork.form.ipv4PoolStart': 'DHCPv4 起始地址',
      'managedNetwork.form.ipv4PoolEnd': 'DHCPv4 结束地址',
      'managedNetwork.form.ipv4DNSServers': 'DHCPv4 DNS 服务器',
      'managedNetwork.form.ipv4DNSServers.placeholder': '例如 1.1.1.1, 8.8.8.8',
      'managedNetwork.form.ipv6Enabled': '启用 IPv6 下发',
      'managedNetwork.form.ipv6ParentInterface': 'IPv6 父接口',
      'managedNetwork.form.ipv6ParentPrefix': 'IPv6 父前缀',
      'managedNetwork.form.ipv6AssignmentMode': 'IPv6 分配模式',
      'managedNetwork.form.ipv6Mode.single128': '单 IP (/128)',
      'managedNetwork.form.ipv6Mode.prefix64': '委派前缀 (/64)',
      'managedNetwork.form.quickFill': 'PVE 快速填充',
      'managedNetwork.form.remark.placeholder': '可选，如：VM 100 私有网段',
      'managedNetwork.form.submit.add': '添加托管网络',
      'managedNetwork.form.submit.edit': '保存修改',
      'managedNetwork.list.title': '托管网络列表',
      'managedNetwork.list.targets': '下游接口',
      'managedNetwork.list.targets.none': '未匹配到下游接口',
      'managedNetwork.list.repairBadge': '修',
      'managedNetwork.list.repairNeeded': '异常但可修复',
      'managedNetwork.list.reservations': '固定租约 {{count}} 条',
      'managedNetwork.repair.action': '修复网络',
      'managedNetwork.repair.queued': '托管网络修复已开始，并已触发运行时重载。',
      'managedNetwork.repair.partial': '托管网络部分修复已应用，并已触发运行时重载。',
      'managedNetwork.repair.summary.none': '未发现需要修复的桥或来宾链路。',
      'managedNetwork.repair.summary.bridges': '桥 {{count}} 个：{{items}}',
      'managedNetwork.repair.summary.guestLinks': '链路 {{count}} 条：{{items}}',
      'managedNetwork.persist.action': '写入宿主机配置',
      'managedNetwork.persist.confirm.title': '写入宿主机网络配置',
      'managedNetwork.persist.confirm.message': '把桥 {{bridge}} 写入 {{path}}，保留当前运行中的桥，并把这条托管网络切换为“使用现有接口”模式？',
      'managedNetwork.persist.success': '桥 {{bridge}} 已写入宿主机网络配置，并已切换为使用现有接口模式。',
      'managedNetwork.runtimeReload.action': '重载运行时',
      'managedNetwork.runtimeReload.queued': '托管网络运行时重载已排队。',
      'managedNetwork.runtimeReload.completed': '托管网络运行时重载已完成。',
      'managedNetwork.runtimeReload.badge.idle': '状态',
      'managedNetwork.runtimeReload.badge.pending': '待应用',
      'managedNetwork.runtimeReload.badge.reloaded': '已重载',
      'managedNetwork.runtimeReload.badge.autoRecovered': '已自愈',
      'managedNetwork.runtimeReload.badge.partial': '部分完成',
      'managedNetwork.runtimeReload.badge.fallback': '已回退',
      'managedNetwork.runtimeReload.source.manual': '手动重载',
      'managedNetwork.runtimeReload.source.linkChange': '链路变更自动恢复',
      'managedNetwork.runtimeReload.result.idle': '尚无重载记录',
      'managedNetwork.runtimeReload.result.pending': '等待执行',
      'managedNetwork.runtimeReload.result.success': '重载成功',
      'managedNetwork.runtimeReload.result.autoRecovered': '自动恢复成功',
      'managedNetwork.runtimeReload.result.partial': '定向重载部分完成，运行时应用有错误',
      'managedNetwork.runtimeReload.result.fallback': '已回退到全量重分发',
      'managedNetwork.runtimeReload.result.unknown': '未知',
      'managedNetwork.runtimeReload.tooltip.title': '托管网络运行时',
      'managedNetwork.runtimeReload.tooltip.status': '状态',
      'managedNetwork.runtimeReload.tooltip.source': '来源',
      'managedNetwork.runtimeReload.tooltip.requestedAt': '请求时间',
      'managedNetwork.runtimeReload.tooltip.startedAt': '开始时间',
      'managedNetwork.runtimeReload.tooltip.completedAt': '完成时间',
      'managedNetwork.runtimeReload.tooltip.dueAt': '计划执行',
      'managedNetwork.runtimeReload.tooltip.requestSummary': '触发接口',
      'managedNetwork.runtimeReload.tooltip.appliedSummary': '应用摘要',
      'managedNetwork.runtimeReload.tooltip.error': '错误',
      'managedNetwork.runtimeReload.tooltip.note': '说明',
      'managedNetwork.list.empty': '暂无托管网络',
      'managedNetwork.delete.confirm': '确认删除托管网络 #{{id}} 吗？',
      'managedNetworkReservation.form.title.add': '添加固定 DHCPv4 租约',
      'managedNetworkReservation.form.title.edit': '编辑固定 DHCPv4 租约 #{{id}}',
      'managedNetworkReservation.form.desc': '把虚拟机网卡 MAC 绑定到托管网络内的固定 IPv4。DHCPv4 会优先下发这个地址，动态地址池也会自动避让它。',
      'managedNetworkReservation.form.managedNetwork': '托管网络',
      'managedNetworkReservation.form.managedNetwork.empty': '请先创建托管网络',
      'managedNetworkReservation.form.macAddress': 'MAC 地址',
      'managedNetworkReservation.form.macAddress.placeholder': '例如 bc:24:11:31:53:db',
      'managedNetworkReservation.form.ipv4Address': '固定 IPv4',
      'managedNetworkReservation.form.ipv4Address.placeholder': '例如 10.0.0.10',
      'managedNetworkReservation.form.remark.placeholder': '可选，如：VM 100 LAN',
      'managedNetworkReservation.form.submit.add': '添加固定租约',
      'managedNetworkReservation.form.submit.edit': '保存修改',
      'managedNetworkCandidate.list.title': '已发现 MAC 候选',
      'managedNetworkCandidate.list.desc': '从托管桥的转发表里学习来宾 MAC，并提供一键创建固定 DHCPv4 租约。',
      'managedNetworkCandidate.list.guest': '来宾',
      'managedNetworkCandidate.list.childInterface': '子接口',
      'managedNetworkCandidate.list.suggestedIPv4': '建议 IPv4',
      'managedNetworkCandidate.list.ipv4Candidates': 'IPv4 候选',
      'managedNetworkCandidate.list.ipv4CandidateCount': '{{count}} 个候选',
      'managedNetworkCandidate.list.status': '状态',
      'managedNetworkCandidate.list.empty': '暂未发现可导入的来宾 MAC。',
      'managedNetworkCandidate.status.available': '可创建',
      'managedNetworkCandidate.status.reserved': '已保留',
      'managedNetworkCandidate.status.unavailable': '不可用',
      'managedNetworkCandidate.action.create': '创建固定租约',
      'managedNetworkCandidate.action.edit': '编辑固定租约',
      'managedNetworkCandidate.action.fill': '带入表单',
      'managedNetworkReservation.list.title': '固定 DHCPv4 租约',
      'managedNetworkReservation.list.empty': '暂无固定 DHCPv4 租约',
      'managedNetworkReservation.delete.confirm': '确认删除固定 DHCPv4 租约 #{{id}} 吗？',
      'egressNAT.form.title.add': '添加出向 NAT 接管',
      'egressNAT.form.title.edit': '编辑出向 NAT 接管 #{{id}}',
      'egressNAT.form.desc': '接管指定父接口下全部可接管子接口，或直接接管单个子接口的 IPv4 TCP/UDP/ICMP 出向流量，并在 TC 中使用指定出口接口、源 IP 和 NAT 类型做出向改写。',
      'egressNAT.form.parentInterface': '父接口',
      'egressNAT.form.childInterface': '子接口',
      'egressNAT.form.childInterfaceAll': '全部可接管子接口',
      'egressNAT.form.interfaceSearchPlaceholder': '筛选接口...',
      'egressNAT.form.protocolPlaceholder': '选择协议',
      'egressNAT.form.natType': 'NAT 类型',
      'egressNAT.form.outInterfaceHintAuto': '已自动推荐更像上行出口的接口：{{name}}。你仍然可以手动改成其他出口。',
      'egressNAT.natType.symmetric': 'Symmetric',
      'egressNAT.natType.fullCone': 'Full Cone',
      'egressNAT.scope.allChildren': '全部可接管子接口',
      'egressNAT.scope.self': '当前接口',
      'egressNAT.form.submit.add': '添加接管',
      'egressNAT.form.submit.edit': '保存修改',
      'egressNAT.list.title': '出向 NAT 接管列表',
      'egressNAT.list.empty': '暂无出向 NAT 接管',
      'egressNAT.delete.confirm': '确认删除出向 NAT 接管 #{{id}} 吗？',
      'ipv6.form.title.add': '添加 IPv6 分配',
      'ipv6.form.title.edit': '编辑 IPv6 分配 #{{id}}',
      'ipv6.form.desc': '记录父前缀里哪段 IPv6 地址或前缀交给目标侧使用；语义上不会把地址直接加到宿主机的目标接口上。',
      'ipv6.form.parentInterface': '父接口',
      'ipv6.form.parentPrefix': '父前缀',
      'ipv6.form.parentPrefix.placeholder': '请先选择父接口',
      'ipv6.form.parentPrefix.empty': '所选接口没有可用的 IPv6 前缀',
      'ipv6.form.targetInterface': '目标接口',
      'ipv6.form.assignedPrefix': '分配前缀',
      'ipv6.form.assignedPrefix.placeholder': '例如 2001:db8:100:1::/64 或 2001:db8:100:1::10/128',
      'ipv6.form.remark.placeholder': '可选，如：VM 100 IPv6 委派',
      'ipv6.form.modeHint.generic': '/128 表示把单个 IPv6 交给目标侧使用，并可通过托管 RA + DHCPv6 IA_NA 自动获取；/64 适合作为虚拟机子网，并会通过 RA 广播该前缀以支持 SLAAC 自动获取；其他前缀长度更适合作为下游委派前缀。不会把地址直接绑到宿主目标接口。',
      'ipv6.form.modeHint.singleAddress': '/128 单地址语义：目标侧使用这个 IPv6；不会把它加到宿主目标接口。运行时会在目标接口发送托管 RA，并通过 DHCPv6 IA_NA 下发该地址。',
      'ipv6.form.modeHint.slaacPrefix': '/64 子网语义：把整段前缀交给目标侧使用，适合虚拟机子网；运行时会在目标接口发送 RA，便于客体侧通过 SLAAC 自动获取地址。',
      'ipv6.form.modeHint.delegatedPrefix': '/{{prefix_len}} 委派前缀语义：把这个前缀路由给目标侧，适合下游继续规划子网或手动地址配置。',
      'ipv6.form.submit.add': '添加分配',
      'ipv6.form.submit.edit': '保存修改',
      'ipv6.list.title': 'IPv6 分配列表',
      'ipv6.list.assignmentCount': '分配次数',
      'ipv6.list.assignmentCount.ra': 'RA {{count}}',
      'ipv6.list.assignmentCount.dhcpv6': 'DHCPv6 {{count}}',
      'ipv6.list.empty': '暂无 IPv6 分配',
      'ipv6.delete.confirm': '确认删除 IPv6 分配 #{{id}} 吗？',
      'workers.title': 'Worker 状态',
      'workers.kind': '类型',
      'workers.version': '版本',
      'workers.count': '数量',
      'workers.details': '详情',
      'workers.empty': '暂无 Worker',
      'workers.kind.rule': '普通映射',
      'workers.kind.kernel': '内核转发',
      'workers.kind.range': '范围映射',
      'workers.kind.egress_nat': '出向 NAT',
      'workers.kind.shared': '共享建站',
      'workers.emptyRules': '无规则',
      'workers.emptyRanges': '无范围',
      'workers.emptyEgressNATs': '无出向 NAT',
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
      'filter.reset': '重置视图',
      'pagination.previous': '上一页',
      'pagination.next': '下一页',
      'pagination.page': '第 {{page}} / {{totalPages}} 页',
      'pagination.summary': '显示 {{start}}-{{end}} / {{total}}',
      'pagination.pageSize': '每页',
      'rule.batch.delete': '批量删除',
      'rule.batch.delete.confirm': '确认删除选中的 {{count}} 条规则吗？',
      'rule.batch.delete.success': '已删除 {{count}} 条规则。',
      'rule.selection.summary': '已选 {{count}} 条',
      'rule.selection.toggle': '选择规则 #{{id}}',
      'rule.selection.selectAll': '选择当前页全部规则',
      'search.rules.placeholder': '搜索规则、IP、端口、标签...',
      'search.sites.placeholder': '搜索域名、IP、标签...',
      'search.ranges.placeholder': '搜索备注、IP、端口、标签...',
      'search.managedNetworks.placeholder': '搜索名称、桥、上行、前缀...',
      'search.managedNetworkReservationCandidates.placeholder': '搜索托管网络、来宾、接口、MAC、IPv4...',
      'search.managedNetworkReservations.placeholder': '搜索托管网络、桥、MAC、IPv4...',
      'search.egressNATs.placeholder': '搜索父接口、子接口、出口、源 IP...',
      'search.ipv6Assignments.placeholder': '搜索接口、前缀、备注...',
      'search.workers.placeholder': '搜索类型、哈希、路由...',
      'empty.action.rule': '创建第一条规则',
      'empty.action.site': '创建第一个站点',
      'empty.action.range': '创建第一条映射',
      'empty.action.managedNetwork': '创建第一条托管网络',
      'empty.action.managedNetworkReservation': '创建第一条固定租约',
      'empty.action.egressNAT': '创建第一条接管',
      'empty.action.ipv6Assignment': '创建第一条分配',
      'confirm.warningTitle': '确认操作',
      'confirm.deleteTitle': '确认删除',
      'confirm.logoutTitle': '退出登录',
      'auth.logoutConfirm': '这会清除当前保存的 Token。继续吗？',
      'kernel.runtime.title': '内核态运行时',
      'kernel.runtime.desc': '用于调试当前 TC/XDP 链路是否可用、是否已附加，以及是否存在表压力或临时回退。',
      'kernel.runtime.empty': '当前没有可展示的内核引擎运行时详情。',
      'kernel.summary.status': '内核态总状态',
      'kernel.summary.defaultEngine': '默认转发策略',
      'kernel.summary.configuredOrder': '内核引擎顺序',
      'kernel.summary.activeKernel': '当前内核承载',
      'kernel.summary.activeKernelValue': '规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.pressure': '当前表压力',
      'kernel.summary.fallbacks': '当前回退',
      'kernel.summary.fallbacksValue': '规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.transientFallbacksValue': '临时回退：规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.retry': '恢复尝试',
      'kernel.summary.retryValue': '全量 {{full}} / 增量 {{incremental}}',
      'kernel.summary.retryFallbackValue': '增量回退全量 {{count}} 次',
      'kernel.summary.incremental': '最近增量结果',
      'kernel.summary.incrementalMatchedValue': '命中规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.incrementalAttemptedValue': '尝试规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.incrementalRecoveredValue': '恢复规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.incrementalRetainedValue': '保留规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.incrementalCooldownValue': '最近 cooldown 命中：规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.incrementalBackoffValue': '最近 backoff：规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.activeCooldownValue': '当前 cooldown：规则 {{rules}} / 范围 {{ranges}}',
      'kernel.summary.activeCooldownWindowValue': '下一次释放 {{next}} / 全部释放 {{clear}}',
      'kernel.summary.activeCooldownClearValue': '全部释放 {{clear}}',
      'kernel.summary.mapProfile': '启动 Map 档位',
      'kernel.summary.mapProfileValue.default': '默认',
      'kernel.summary.mapProfileValue.small': '小内存',
      'kernel.summary.mapProfileValue.medium': '中内存',
      'kernel.summary.mapProfileValue.large': '大内存',
      'kernel.summary.mapProfileValue.custom': '自定义',
      'kernel.summary.mapProfileMemoryUnknown': 'RAM 未知',
      'kernel.summary.mapProfileDetail': 'RAM {{memory}} · flows 基线 {{flows}} · nat 基线 {{nat}} · egress NAT floor {{egress}}',
      'kernel.summary.degraded': '内核引擎降级',
      'kernel.summary.degradedValue': '{{engine}} 处于需重启恢复的降级状态',
      'kernel.summary.trafficStats': '内核流量统计',
      'kernel.available.yes': '可用',
      'kernel.available.no': '不可用',
      'kernel.degraded.yes': '已降级',
      'kernel.degraded.no': '正常',
      'kernel.loaded.yes': '已加载',
      'kernel.loaded.no': '未加载',
      'kernel.attachments.healthy': '正常',
      'kernel.attachments.degraded': '异常',
      'kernel.traffic.enabled': '已开启',
      'kernel.traffic.disabled': '已关闭',
      'kernel.retry.pending': '存在待重试回退',
      'kernel.retry.idle': '无待重试回退',
      'kernel.note.lastRetry': '最近全量重试',
      'kernel.note.lastIncrementalRetry': '最近增量恢复',
      'kernel.note.pendingNetlinkRecovery': '待处理 netlink 恢复',
      'kernel.note.attachmentIssue': '当前附加异常',
      'kernel.note.lastAttachmentHeal': '最近附加自愈',
      'kernel.note.lastAttachmentHealError': '最近附加自愈失败',
      'kernel.note.xdpAttachmentMode': 'XDP 附加模式',
      'kernel.mode.steady': '稳定',
      'kernel.mode.in_place': '原地更新',
      'kernel.mode.rebuild': '重建',
      'kernel.mode.cleared': '已清空',
      'kernel.mode.unknown': '未知',
      'kernel.pressure.none': '正常',
      'kernel.pressure.hold': '限新增',
      'kernel.pressure.shed': '局部回退',
      'kernel.pressure.full': '全量回退',
      'kernel.pressure.noneHint': '无活动表压力',
      'kernel.engine.name': '引擎',
      'kernel.engine.available': '可用性',
      'kernel.engine.pressure': '压力状态',
      'kernel.engine.loaded': '程序状态',
      'kernel.engine.entries': '当前条目',
      'kernel.engine.attachments': '附加点',
      'kernel.engine.attachHealthy': '附加健康',
      'kernel.engine.families': '协议族',
      'kernel.engine.maps': 'Map 占用',
      'kernel.engine.reconcile': '最近同步',
      'kernel.engine.traffic': '流量统计',
      'kernel.engine.details': '详情',
      'kernel.maps.rules': 'rules',
      'kernel.maps.flows': 'flows',
      'kernel.maps.nat': 'nat',
      'kernel.maps.ipv4': 'IPv4',
      'kernel.maps.ipv6': 'IPv6',
      'kernel.maps.ipv4Short': 'v4',
      'kernel.maps.ipv6Short': 'v6',
      'kernel.maps.tooltip.profile': '档位',
      'kernel.maps.tooltip.mode': '模式',
      'kernel.maps.tooltip.base': '基线',
      'kernel.maps.tooltip.decision': '决策',
      'kernel.maps.tooltip.scope': '统计口径',
      'kernel.maps.tooltip.oldBank': '旧表',
      'kernel.maps.tooltip.mode.adaptive': '自适应',
      'kernel.maps.tooltip.mode.fixed': '固定',
      'kernel.maps.tooltip.decision.base': '使用启动基线 {{base}}',
      'kernel.maps.tooltip.decision.expanded': '从基线 {{base}} 扩到 {{current}}',
      'kernel.maps.tooltip.decision.retained': '保留较小 live map {{current}}（目标基线 {{base}}）',
      'kernel.maps.tooltip.decision.fixed': '使用显式配置 {{limit}}',
      'kernel.maps.tooltip.decision.current': '当前容量 {{current}}',
      'kernel.maps.tooltip.scope.families': '主容量按 v4/v6 活跃表合计',
      'kernel.maps.tooltip.scope.familiesWithOldBank': '按 v4/v6 合计，含旧表容量',
      'runtimeReason.kernelMixedFamily': '内核态暂不支持 IPv4/IPv6 混合转发。',
      'runtimeReason.kernelTransparentIPv6': '内核态当前不支持 IPv6 透传规则。',
      'runtimeReason.xdpGenericExperimental': 'XDP 的 generic/mixed 附加默认关闭；需要显式开启实验特性 `xdp_generic` 才允许使用。',
      'runtimeReason.xdpVethNatRedirectLegacyKernel': '当前内核上的 veth 场景不启用 XDP NAT redirect；已建议回退到 TC，或升级到更新内核。',
      'runtimeReason.xdpGenericMode': 'XDP 当前以 generic (SKB) 模式附加；这仍走 skb 路径，不应视为 driver fast-path。',
      'runtimeReason.xdpMixedMode': 'XDP 当前混合使用 driver / generic 附加；generic 接口仍走 skb 路径，不应视为完整 driver fast-path。',
      'stats.rules.title': '规则流量统计',
      'stats.sites.title': '建站流量统计',
      'stats.ranges.title': '范围映射流量统计',
      'stats.egressNATs.title': '出向 NAT 流量统计',
      'stats.egressNATs.empty': '暂无出向 NAT 统计数据',
      'stats.egressNATs.id.auto': '自动',
      'stats.egressNATs.id.auto.title': '托管网络自动生成的出向 NAT 规则（ID {{id}}）',
      'stats.currentConns': '连接数',
      'stats.target': '目标',
      'stats.route.in': '入',
      'stats.route.out': '出',
      'stats.route.listen': '监听',
      'stats.refreshCurrentConns': '获取当前连接数',
      'stats.currentConnsManual': '当前连接数按需获取',
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
      'transparent.info.ipv6Unavailable': '透明传输当前仅支持 IPv4 目标；IPv6 目标请关闭透传。',
      'transparent.warning.public': '检测到目标是公网 IP。如果 {{target}} 的默认网关不经过本机（例如上级直接路由到 VM），透传通常会失败。',
      'transparent.warning.publicBridge': '检测到目标是公网 IP，且出接口像桥接接口。如果 {{target}} 的默认网关不经过本机（例如本机只做网桥），透传通常会失败。',
      'transparent.info.enabled': '透传已开启。请确认 {{target}} 的默认网关或策略路由指向本机，否则回包不会回到本机。',
      'transparent.confirmContinue': '继续保存吗？',
      'transparent.target.backend': '后端主机',
      'transparent.target.destination': '目标主机',
      'status.enabled': '已启用',
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
      'noun.managedNetwork': '托管网络',
      'noun.managedNetworkReservation': '固定租约',
      'noun.egressNAT': '出向 NAT 接管',
      'noun.ipv6Assignment': 'IPv6 分配',
      'toast.created': '{{item}}已创建。',
      'toast.saved': '{{item}}已保存。',
      'toast.deleted': '{{item}}已删除。',
      'toast.enabled': '{{item}}已启用。',
      'toast.disabled': '{{item}}已禁用。',
      'toast.loggedOut': '已退出登录。',
      'validation.required': '此字段必填。',
      'validation.invalidID': 'ID 无效。',
      'validation.ip': '请输入有效的 IP 地址。',
      'validation.ipv4': '请输入有效的 IPv4 地址。',
      'validation.macAddress': '请输入有效的 MAC 地址。',
      'validation.ipv4CIDR': '请输入有效的 IPv4 CIDR。',
      'validation.ipv6': '请输入有效的 IPv6 地址。',
      'validation.ipv6Prefix': '请输入有效的 IPv6 CIDR 前缀。',
      'validation.prefixLength': '前缀长度必须在 1 到 128 之间。',
      'validation.sourceIPSpecific': '请使用明确且非回环的本机 IP 地址。',
      'validation.positiveId': 'ID 必须大于 0。',
      'validation.ruleCreateIDOmit': '新增规则时不能携带 ID。',
      'validation.portRange': '端口必须在 1 到 65535 之间。',
      'validation.protocol': '协议只能是 tcp、udp 或 tcp+udp。',
      'validation.egressNATProtocol': '请至少选择一个协议（tcp、udp、icmp）。',
      'validation.enginePreference': '引擎只能是 auto、userspace 或 kernel。',
      'validation.interfaceMissing': '接口在当前主机上不存在。',
      'validation.sourceIPTransparent': '透传开启时不能固定源 IP。',
      'validation.sourceIPOutboundInterface': '固定源 IP 不属于所选出接口。',
      'validation.sourceIPLocal': '固定源 IP 不属于当前主机。',
      'validation.transparentIPv4Only': '当前阶段的透传仅支持 IPv4。',
      'validation.sourceIPIPv4Only': '固定源 IP 当前仅支持纯 IPv4 的用户态转发。',
      'validation.sourceIPOutboundFamily': '固定源 IP 必须与出站目标 IP 的地址族一致。',
      'validation.sourceIPBackendFamily': '后端源 IP 必须与后端 IP 的地址族一致。',
      'validation.sourceIPTargetFamily': '固定源 IP 必须与目标 IP 的地址族一致。',
      'validation.ruleDuplicateUpdate': '更新列表里存在重复的规则 ID。',
      'validation.ruleDeletePendingUpdate': '该规则已被加入删除列表，不能再更新。',
      'validation.ruleDuplicateToggle': '启停列表里存在重复的规则 ID。',
      'validation.ruleDeletePendingToggle': '该规则已被加入删除列表，不能再切换启停状态。',
      'validation.ruleBatchRequired': '批量操作至少要包含一项变更。',
      'validation.listenerConflict': '监听冲突：{{detail}}',
      'validation.routeConflict': '路由冲突：{{detail}}',
      'validation.ruleNotFound': '规则不存在或已被删除。',
      'validation.siteNotFound': '站点不存在或已被删除。',
      'validation.rangeNotFound': '范围映射不存在或已被删除。',
      'validation.managedNetworkNotFound': '托管网络不存在或已被删除。',
      'validation.managedNetworkCreateIDOmit': '创建托管网络时不能携带 ID。',
      'validation.managedNetworkReservationNotFound': '固定租约不存在或已被删除。',
      'validation.managedNetworkReservationCreateIDOmit': '创建固定租约时不能携带 ID。',
      'validation.managedNetworkReservationIPv4Disabled': '所选托管网络没有启用 IPv4 网关和 DHCPv4。',
      'validation.managedNetworkReservationIPv4Invalid': '所选托管网络的 IPv4 配置无效，请先修正托管网络。',
      'validation.managedNetworkReservationIPv4InsideCIDR': '固定 IPv4 必须位于托管网络的 IPv4 CIDR 内。',
      'validation.managedNetworkReservationGatewayConflict': '固定 IPv4 不能与托管网络网关地址相同。',
      'validation.managedNetworkReservationHostRequired': '固定 IPv4 必须使用可分配的主机地址。',
      'validation.managedNetworkReservationMACConflict': '该 MAC 已被固定租约 #{{id}} 占用。',
      'validation.managedNetworkReservationIPConflict': '该 IPv4 已被固定租约 #{{id}} 占用。',
      'validation.managedNetworkBridgeMode': '请选择创建新桥或使用现有接口。',
      'validation.managedNetworkBridgeMissing': '所选桥接口在当前主机上不存在。',
      'validation.managedNetworkBridgeNameConflict': '这个桥名称已被一个非 bridge 接口占用，请换个名字或改用“使用现有接口”。',
      'validation.ipv6AssignmentNotFound': 'IPv6 分配不存在或已被删除。',
      'validation.ipv6AssignmentCreateIDOmit': '创建 IPv6 分配时不能携带 ID。',
      'validation.targetInterfaceDifferent': '目标接口不能与父接口相同。',
      'validation.parentPrefixMissing': '所选父接口上不存在该父前缀。',
      'validation.assignedPrefixInsideParent': '分配前缀必须位于父前缀范围内。',
      'validation.ipv6AssignedOnHost': '该 IPv6 已经存在于宿主机接口上，不能再把它当作目标侧单地址使用。',
      'validation.ipv6AssignmentOverlap': '该分配前缀与 IPv6 分配 #{{id}} 重叠。',
      'validation.issueJoiner': '；',
      'validation.issueSummaryMore': '{{messages}}（另 {{count}} 项）',
      'validation.reviewErrors': '请检查已标记的字段。',
      'validation.ruleRequired': '请填写完整的 IP 和端口。',
      'validation.sitePortsRequired': 'HTTP 端口和 HTTPS 端口至少填写一个。',
      'validation.siteRequired': '请填写域名和后端 IP。',
      'validation.rangeRequired': '请填写完整的 IP 和端口范围。',
      'validation.rangeOrder': '起始端口不能大于结束端口。',
      'validation.managedNetworkIPv4Required': '启用 IPv4 时请填写 IPv4 网关 CIDR。',
      'validation.managedNetworkIPv6Required': '启用 IPv6 时请选择父接口和父前缀。',
      'validation.managedNetworkBridgeUplinkConflict': '桥接口不能与上行接口相同。',
      'validation.managedNetworkBridgeMTU': '桥 MTU 必须在 0 到 65535 之间。',
      'validation.managedNetworkPersistRequiresCreate': '只有创建新桥模式的托管网络才能执行写入宿主机配置。',
      'validation.managedNetworkUplinkRequired': '启用自动出向 NAT 时请选择上行接口。',
      'validation.managedNetworkIPv4PoolOrder': 'DHCPv4 起始地址不能大于结束地址。',
      'validation.egressNATRequired': '请选择父接口和出口接口。',
      'validation.egressNATNotFound': '出向 NAT 接管不存在或已被删除。',
      'validation.egressNATCreateIDOmit': '创建出向 NAT 接管时不能携带 ID。',
      'validation.egressNATChildConflict': '所选接管范围已被出向 NAT 接管 #{{id}} 占用。',
      'validation.egressNATNoChildren': '所选父接口下当前没有可接管的子接口。',
      'validation.egressNATNatType': 'NAT 类型必须是 symmetric 或 full_cone。',
      'validation.egressNATSingleTargetOutConflict': '单接口接管模式下，父接口不能与出口接口相同。',
      'validation.childInterfaceDifferent': '子接口不能与出口接口相同。',
      'validation.childParentMismatch': '子接口不属于所选父接口。',
      'validation.sourceIPEgressIPv4Only': '出向 NAT 的固定源 IP 当前仅支持 IPv4。'
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
      'tab.managedNetworks': 'Managed Networks',
      'tab.egressNATs': 'Egress NAT',
      'tab.ipv6Assignments': 'IPv6 Assignments',
      'tab.workers': 'Worker Status',
      'tab.stats': 'Traffic Stats',
      'form.remark': 'Remark',
      'form.tag': 'Tag',
      'form.protocol': 'Protocol',
      'form.engine': 'Forward Engine',
      'form.transparent': 'Transparent Source IP',
      'form.transparentShort': 'Transparent',
      'form.inInterface': 'Inbound Interface',
      'form.inIP': 'Inbound IP',
      'form.inPort': 'Inbound Port',
      'form.outInterface': 'Outbound Interface',
      'form.outIP': 'Outbound IP',
      'form.outSourceIP': 'Fixed Source IP',
      'form.outPort': 'Outbound Port',
      'interface.picker.placeholder': 'Search or select interface...',
      'interface.search.placeholder': 'Filter interfaces...',
      'interface.search.noResults': 'No matching interfaces',
      'common.unspecified': 'Unspecified',
      'common.selectInterfaceFirst': 'Select interface first',
      'common.allAddresses': '0.0.0.0 (All)',
      'common.allIPv4Addresses': '0.0.0.0 (All IPv4)',
      'common.allIPv6Addresses': ':: (All IPv6)',
      'common.familyLabel': 'Address Family',
      'common.family.ipv4': 'IPv4',
      'common.family.ipv6': 'IPv6',
      'common.family.mixed': 'Mixed',
      'common.status': 'Status',
      'common.actions': 'Actions',
      'common.cancel': 'Cancel',
      'common.cancelEdit': 'Cancel',
      'common.confirm': 'Confirm',
      'common.auto': 'Auto',
      'common.clear': 'Clear',
      'common.enable': 'Enable',
      'common.disable': 'Disable',
      'common.edit': 'Edit',
      'common.clone': 'Clone',
      'common.delete': 'Delete',
      'common.yes': 'Yes',
      'common.skipped': 'Skipped',
      'common.dash': '-',
      'common.unavailable': 'Unavailable',
      'common.sourceShort': 'src',
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
      'rule.list.engine': 'Engine',
      'rule.list.empty': 'No forwarding rules yet.',
      'rule.engine.preferenceLabel': 'Preference',
      'rule.engine.effectiveLabel': 'Effective',
      'rule.engine.preference.auto': 'Auto',
      'rule.engine.preference.userspace': 'Userspace',
      'rule.engine.preference.kernel': 'Kernel',
      'rule.engine.effective.userspace': 'Userspace',
      'rule.engine.effective.kernel': 'Kernel',
      'rule.engine.hint.kernelActive': 'Kernel active',
      'rule.engine.hint.kernelReady': 'Kernel-ready',
      'rule.engine.hint.userspaceOnly': 'Userspace only',
      'rule.engine.hint.fallback': 'Fallback active',
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
      'site.form.backendSourceIP': 'Backend Source IP',
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
      'managedNetwork.form.title.add': 'Add Managed Network',
      'managedNetwork.form.title.edit': 'Edit Managed Network #{{id}}',
      'managedNetwork.form.desc': 'Use one managed network entry to define the downstream bridge, IPv4 gateway + DHCP pool, optional IPv6 handout source, and whether outbound traffic should be auto-taken over with egress NAT.',
      'managedNetwork.form.name': 'Name',
      'managedNetwork.form.name.placeholder': 'For example: vm100-lan',
      'managedNetwork.form.bridgeMode': 'Bridge Mode',
      'managedNetwork.form.bridgeMode.create': 'Create New Bridge',
      'managedNetwork.form.bridgeMode.existing': 'Use Existing Interface',
      'managedNetwork.form.bridge': 'Bridge / Downstream Interface',
      'managedNetwork.form.bridge.createLabel': 'New Bridge Name',
      'managedNetwork.form.bridge.existingLabel': 'Existing Bridge / Downstream Interface',
      'managedNetwork.form.bridge.placeholder.create': 'Type a new bridge name, for example vmbr1',
      'managedNetwork.form.bridge.placeholder.existing': 'Search or select interface...',
      'managedNetwork.form.advancedOptions': 'Advanced Options',
      'managedNetwork.form.bridgeMTU': 'Bridge MTU',
      'managedNetwork.form.bridgeVLANAware': 'VLAN Aware Bridge',
      'managedNetwork.form.bridgeAdvancedHint': 'Only applies when creating a new managed bridge. Existing-interface mode keeps the current bridge settings.',
      'managedNetwork.form.uplinkInterface': 'Uplink Interface',
      'managedNetwork.form.autoEgressNAT': 'Auto Egress NAT',
      'managedNetwork.form.ipv4Enabled': 'Enable IPv4 Gateway + DHCPv4',
      'managedNetwork.form.ipv4CIDR': 'IPv4 Gateway CIDR',
      'managedNetwork.form.ipv4CIDR.placeholder': 'For example 192.0.2.1/24',
      'managedNetwork.form.ipv4Gateway': 'IPv4 Gateway Override',
      'managedNetwork.form.ipv4PoolStart': 'DHCPv4 Pool Start',
      'managedNetwork.form.ipv4PoolEnd': 'DHCPv4 Pool End',
      'managedNetwork.form.ipv4DNSServers': 'DHCPv4 DNS Servers',
      'managedNetwork.form.ipv4DNSServers.placeholder': 'For example 1.1.1.1, 8.8.8.8',
      'managedNetwork.form.ipv6Enabled': 'Enable IPv6 Handout',
      'managedNetwork.form.ipv6ParentInterface': 'IPv6 Parent Interface',
      'managedNetwork.form.ipv6ParentPrefix': 'IPv6 Parent Prefix',
      'managedNetwork.form.ipv6AssignmentMode': 'IPv6 Assignment Mode',
      'managedNetwork.form.ipv6Mode.single128': 'Single IP (/128)',
      'managedNetwork.form.ipv6Mode.prefix64': 'Delegated Prefix (/64)',
      'managedNetwork.form.quickFill': 'PVE Quick Fill',
      'managedNetwork.form.remark.placeholder': 'Optional, for example: VM 100 private LAN',
      'managedNetwork.form.submit.add': 'Add Managed Network',
      'managedNetwork.form.submit.edit': 'Save Changes',
      'managedNetwork.list.title': 'Managed Networks',
      'managedNetwork.list.targets': 'Targets',
      'managedNetwork.list.targets.none': 'No matched downstream interfaces',
      'managedNetwork.list.repairBadge': 'Fix',
      'managedNetwork.list.repairNeeded': 'Repair recommended',
      'managedNetwork.list.reservations': '{{count}} fixed lease(s)',
      'managedNetwork.repair.action': 'Repair Network',
      'managedNetwork.repair.queued': 'Managed network repair started and runtime reload was triggered.',
      'managedNetwork.repair.partial': 'Managed network repair partially applied and runtime reload was triggered.',
      'managedNetwork.repair.summary.none': 'No bridge or guest-link repairs were needed.',
      'managedNetwork.repair.summary.bridges': 'Bridges {{count}}: {{items}}',
      'managedNetwork.repair.summary.guestLinks': 'Guest links {{count}}: {{items}}',
      'managedNetwork.persist.action': 'Persist Bridge',
      'managedNetwork.persist.confirm.title': 'Persist Host Network Bridge',
      'managedNetwork.persist.confirm.message': 'Write bridge {{bridge}} into {{path}}, keep the live bridge as-is, and switch this managed network to existing-interface mode?',
      'managedNetwork.persist.success': 'Bridge {{bridge}} was written to host network config and this managed network now uses existing-interface mode.',
      'managedNetwork.runtimeReload.action': 'Reload Runtime',
      'managedNetwork.runtimeReload.queued': 'Managed network runtime reload queued.',
      'managedNetwork.runtimeReload.completed': 'Managed network runtime reload completed.',
      'managedNetwork.runtimeReload.badge.idle': 'Status',
      'managedNetwork.runtimeReload.badge.pending': 'Pending',
      'managedNetwork.runtimeReload.badge.reloaded': 'Reloaded',
      'managedNetwork.runtimeReload.badge.autoRecovered': 'Recovered',
      'managedNetwork.runtimeReload.badge.partial': 'Partial',
      'managedNetwork.runtimeReload.badge.fallback': 'Fallback',
      'managedNetwork.runtimeReload.source.manual': 'Manual reload',
      'managedNetwork.runtimeReload.source.linkChange': 'Auto recovery from link change',
      'managedNetwork.runtimeReload.result.idle': 'No reload has been recorded yet',
      'managedNetwork.runtimeReload.result.pending': 'Waiting to run',
      'managedNetwork.runtimeReload.result.success': 'Reload completed successfully',
      'managedNetwork.runtimeReload.result.autoRecovered': 'Auto recovery completed successfully',
      'managedNetwork.runtimeReload.result.partial': 'Targeted reload completed with runtime apply errors',
      'managedNetwork.runtimeReload.result.fallback': 'Fell back to full redistribute',
      'managedNetwork.runtimeReload.result.unknown': 'Unknown',
      'managedNetwork.runtimeReload.tooltip.title': 'Managed Network Runtime',
      'managedNetwork.runtimeReload.tooltip.status': 'Status',
      'managedNetwork.runtimeReload.tooltip.source': 'Source',
      'managedNetwork.runtimeReload.tooltip.requestedAt': 'Requested At',
      'managedNetwork.runtimeReload.tooltip.startedAt': 'Started At',
      'managedNetwork.runtimeReload.tooltip.completedAt': 'Completed At',
      'managedNetwork.runtimeReload.tooltip.dueAt': 'Scheduled For',
      'managedNetwork.runtimeReload.tooltip.requestSummary': 'Triggered Interfaces',
      'managedNetwork.runtimeReload.tooltip.appliedSummary': 'Applied Summary',
      'managedNetwork.runtimeReload.tooltip.error': 'Error',
      'managedNetwork.runtimeReload.tooltip.note': 'Note',
      'managedNetwork.list.empty': 'No managed networks yet.',
      'managedNetwork.delete.confirm': 'Delete managed network #{{id}}?',
      'managedNetworkReservation.form.title.add': 'Add Fixed DHCPv4 Lease',
      'managedNetworkReservation.form.title.edit': 'Edit Fixed DHCPv4 Lease #{{id}}',
      'managedNetworkReservation.form.desc': 'Bind a VM NIC MAC address to a fixed IPv4 inside a managed network. DHCPv4 will always prefer this address and the dynamic pool will automatically avoid it.',
      'managedNetworkReservation.form.managedNetwork': 'Managed Network',
      'managedNetworkReservation.form.managedNetwork.empty': 'Create a managed network first',
      'managedNetworkReservation.form.macAddress': 'MAC Address',
      'managedNetworkReservation.form.macAddress.placeholder': 'For example bc:24:11:31:53:db',
      'managedNetworkReservation.form.ipv4Address': 'Fixed IPv4',
      'managedNetworkReservation.form.ipv4Address.placeholder': 'For example 10.0.0.10',
      'managedNetworkReservation.form.remark.placeholder': 'Optional, e.g. VM 100 LAN',
      'managedNetworkReservation.form.submit.add': 'Add Fixed Lease',
      'managedNetworkReservation.form.submit.edit': 'Save Changes',
      'managedNetworkCandidate.list.title': 'Discovered MAC Candidates',
      'managedNetworkCandidate.list.desc': 'Learn guest MAC addresses from the managed bridge forwarding database and offer one-click fixed DHCPv4 lease creation.',
      'managedNetworkCandidate.list.guest': 'Guest',
      'managedNetworkCandidate.list.childInterface': 'Child Interface',
      'managedNetworkCandidate.list.suggestedIPv4': 'Suggested IPv4',
      'managedNetworkCandidate.list.ipv4Candidates': 'IPv4 Candidates',
      'managedNetworkCandidate.list.ipv4CandidateCount': '{{count}} candidates',
      'managedNetworkCandidate.list.status': 'Status',
      'managedNetworkCandidate.list.empty': 'No guest MAC candidates discovered yet.',
      'managedNetworkCandidate.status.available': 'Ready',
      'managedNetworkCandidate.status.reserved': 'Reserved',
      'managedNetworkCandidate.status.unavailable': 'Unavailable',
      'managedNetworkCandidate.action.create': 'Create Fixed Lease',
      'managedNetworkCandidate.action.edit': 'Edit Fixed Lease',
      'managedNetworkCandidate.action.fill': 'Fill Form',
      'managedNetworkReservation.list.title': 'Fixed DHCPv4 Leases',
      'managedNetworkReservation.list.empty': 'No fixed DHCPv4 leases yet.',
      'managedNetworkReservation.delete.confirm': 'Delete fixed DHCPv4 lease #{{id}}?',
      'egressNAT.form.title.add': 'Add Egress NAT Takeover',
      'egressNAT.form.title.edit': 'Edit Egress NAT Takeover #{{id}}',
      'egressNAT.form.desc': 'Take over IPv4 TCP/UDP/ICMP egress traffic from all eligible child interfaces under a parent scope, or from one selected child interface directly, and apply TC egress rewriting with the selected uplink, source IP, and NAT type.',
      'egressNAT.form.parentInterface': 'Parent Interface',
      'egressNAT.form.childInterface': 'Child Interface',
      'egressNAT.form.childInterfaceAll': 'All Eligible Child Interfaces',
      'egressNAT.form.interfaceSearchPlaceholder': 'Filter interfaces...',
      'egressNAT.form.protocolPlaceholder': 'Select protocols',
      'egressNAT.form.natType': 'NAT Type',
      'egressNAT.form.outInterfaceHintAuto': 'Auto-selected a likely uplink interface: {{name}}. You can still change it manually.',
      'egressNAT.natType.symmetric': 'Symmetric',
      'egressNAT.natType.fullCone': 'Full Cone',
      'egressNAT.scope.allChildren': 'All Eligible Child Interfaces',
      'egressNAT.scope.self': 'Selected Interface',
      'egressNAT.form.submit.add': 'Add Takeover',
      'egressNAT.form.submit.edit': 'Save Changes',
      'egressNAT.list.title': 'Egress NAT Takeover',
      'egressNAT.list.empty': 'No egress NAT takeovers yet.',
      'egressNAT.delete.confirm': 'Delete egress NAT takeover #{{id}}?',
      'ipv6.form.title.add': 'Add IPv6 Assignment',
      'ipv6.form.title.edit': 'Edit IPv6 Assignment #{{id}}',
      'ipv6.form.desc': 'Record which IPv6 address or prefix from a parent prefix the target side may use. This does not mean binding that address onto the host-side target interface.',
      'ipv6.form.parentInterface': 'Parent Interface',
      'ipv6.form.parentPrefix': 'Parent Prefix',
      'ipv6.form.parentPrefix.placeholder': 'Select a parent interface first',
      'ipv6.form.parentPrefix.empty': 'The selected interface has no usable IPv6 prefixes',
      'ipv6.form.targetInterface': 'Target Interface',
      'ipv6.form.assignedPrefix': 'Assigned Prefix',
      'ipv6.form.assignedPrefix.placeholder': 'For example 2001:db8:100:1::/64 or 2001:db8:100:1::10/128',
      'ipv6.form.remark.placeholder': 'Optional, e.g. VM 100 delegated IPv6',
      'ipv6.form.modeHint.generic': '/128 means a single IPv6 for the target to use and can be announced with managed RA + DHCPv6 IA_NA; /64 suits a guest subnet and will advertise that prefix with RA for SLAAC; other prefix lengths are better treated as delegated downstream prefixes. The address is not bound to the host-side target interface.',
      'ipv6.form.modeHint.singleAddress': '/128 single-address semantics: the target side uses this IPv6 itself instead of adding it onto the host-side target interface. The runtime will send managed RA on the target interface and hand out this address via DHCPv6 IA_NA.',
      'ipv6.form.modeHint.slaacPrefix': '/64 subnet semantics: hand the whole prefix to the target side, which suits a guest subnet; the runtime will send RA on the target interface so the guest can pick it up via SLAAC.',
      'ipv6.form.modeHint.delegatedPrefix': '/{{prefix_len}} delegated-prefix semantics: route this prefix toward the target side for downstream subnet planning or manual addressing.',
      'ipv6.form.submit.add': 'Add Assignment',
      'ipv6.form.submit.edit': 'Save Changes',
      'ipv6.list.title': 'IPv6 Assignments',
      'ipv6.list.assignmentCount': 'Handout Count',
      'ipv6.list.assignmentCount.ra': 'RA {{count}}',
      'ipv6.list.assignmentCount.dhcpv6': 'DHCPv6 {{count}}',
      'ipv6.list.empty': 'No IPv6 assignments yet.',
      'ipv6.delete.confirm': 'Delete IPv6 assignment #{{id}}?',
      'workers.title': 'Worker Status',
      'workers.kind': 'Type',
      'workers.version': 'Version',
      'workers.count': 'Count',
      'workers.details': 'Details',
      'workers.empty': 'No workers yet.',
      'workers.kind.rule': 'Direct Mapping',
      'workers.kind.kernel': 'Kernel Dataplane',
      'workers.kind.range': 'Range Mapping',
      'workers.kind.egress_nat': 'Egress NAT',
      'workers.kind.shared': 'Shared Sites',
      'workers.emptyRules': 'No rules',
      'workers.emptyRanges': 'No ranges',
      'workers.emptyEgressNATs': 'No egress NAT entries',
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
      'filter.reset': 'Reset View',
      'pagination.previous': 'Previous',
      'pagination.next': 'Next',
      'pagination.page': 'Page {{page}} / {{totalPages}}',
      'pagination.summary': 'Showing {{start}}-{{end}} / {{total}}',
      'pagination.pageSize': 'Per page',
      'rule.batch.delete': 'Delete Selected',
      'rule.batch.delete.confirm': 'Delete the selected {{count}} rules?',
      'rule.batch.delete.success': 'Deleted {{count}} rules.',
      'rule.selection.summary': '{{count}} selected',
      'rule.selection.toggle': 'Select rule #{{id}}',
      'rule.selection.selectAll': 'Select all rules on the current page',
      'search.rules.placeholder': 'Search rules, IPs, ports, tags...',
      'search.sites.placeholder': 'Search domains, IPs, tags...',
      'search.ranges.placeholder': 'Search remarks, IPs, ports, tags...',
      'search.managedNetworks.placeholder': 'Search names, bridges, uplinks, prefixes...',
      'search.managedNetworkReservationCandidates.placeholder': 'Search managed network, guest, interface, MAC, IPv4...',
      'search.managedNetworkReservations.placeholder': 'Search managed network, bridge, MAC, IPv4...',
      'search.egressNATs.placeholder': 'Search parent, child, uplink, source IP...',
      'search.ipv6Assignments.placeholder': 'Search interfaces, prefixes, remarks...',
      'search.workers.placeholder': 'Search type, hash, route...',
      'empty.action.rule': 'Create First Rule',
      'empty.action.site': 'Create First Site',
      'empty.action.range': 'Create First Mapping',
      'empty.action.managedNetwork': 'Create First Managed Network',
      'empty.action.managedNetworkReservation': 'Create First Fixed Lease',
      'empty.action.egressNAT': 'Create First Takeover',
      'empty.action.ipv6Assignment': 'Create First Assignment',
      'confirm.warningTitle': 'Confirm Action',
      'confirm.deleteTitle': 'Confirm Deletion',
      'confirm.logoutTitle': 'Sign Out',
      'auth.logoutConfirm': 'This clears the saved token for this browser. Continue?',
      'kernel.runtime.title': 'Kernel Runtime',
      'kernel.runtime.desc': 'Debug the current TC/XDP dataplane state, attachment health, and active pressure or transient fallbacks.',
      'kernel.runtime.empty': 'No kernel engine runtime details are available right now.',
      'kernel.summary.status': 'Kernel Status',
      'kernel.summary.defaultEngine': 'Default Forwarding',
      'kernel.summary.configuredOrder': 'Kernel Engine Order',
      'kernel.summary.activeKernel': 'Kernel Assignments',
      'kernel.summary.activeKernelValue': 'Rules {{rules}} / Ranges {{ranges}}',
      'kernel.summary.pressure': 'Current Pressure',
      'kernel.summary.fallbacks': 'Current Fallbacks',
      'kernel.summary.fallbacksValue': 'Rules {{rules}} / Ranges {{ranges}}',
      'kernel.summary.transientFallbacksValue': 'Transient: rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.retry': 'Recovery Attempts',
      'kernel.summary.retryValue': 'Full {{full}} / Incremental {{incremental}}',
      'kernel.summary.retryFallbackValue': 'Incremental -> full fallback {{count}} time(s)',
      'kernel.summary.incremental': 'Last Incremental Result',
      'kernel.summary.incrementalMatchedValue': 'Matched rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.incrementalAttemptedValue': 'Attempted rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.incrementalRecoveredValue': 'Recovered rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.incrementalRetainedValue': 'Retained rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.incrementalCooldownValue': 'Last cooldown hits: rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.incrementalBackoffValue': 'Last backoff hits: rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.activeCooldownValue': 'Active cooldown: rules {{rules}} / ranges {{ranges}}',
      'kernel.summary.activeCooldownWindowValue': 'Next release {{next}} / clear {{clear}}',
      'kernel.summary.activeCooldownClearValue': 'Clear {{clear}}',
      'kernel.summary.mapProfile': 'Startup map profile',
      'kernel.summary.mapProfileValue.default': 'Default',
      'kernel.summary.mapProfileValue.small': 'Small memory',
      'kernel.summary.mapProfileValue.medium': 'Medium memory',
      'kernel.summary.mapProfileValue.large': 'Large memory',
      'kernel.summary.mapProfileValue.custom': 'Custom',
      'kernel.summary.mapProfileMemoryUnknown': 'RAM unknown',
      'kernel.summary.mapProfileDetail': 'RAM {{memory}} · flows base {{flows}} · nat base {{nat}} · egress NAT floor {{egress}}',
      'kernel.summary.degraded': 'Kernel Engine Degraded',
      'kernel.summary.degradedValue': '{{engine}} is running in degraded-until-restart mode',
      'kernel.summary.trafficStats': 'Kernel Traffic Stats',
      'kernel.available.yes': 'Available',
      'kernel.available.no': 'Unavailable',
      'kernel.degraded.yes': 'Degraded',
      'kernel.degraded.no': 'Normal',
      'kernel.loaded.yes': 'Loaded',
      'kernel.loaded.no': 'Not Loaded',
      'kernel.attachments.healthy': 'Healthy',
      'kernel.attachments.degraded': 'Degraded',
      'kernel.traffic.enabled': 'Enabled',
      'kernel.traffic.disabled': 'Disabled',
      'kernel.retry.pending': 'Transient retries pending',
      'kernel.retry.idle': 'No transient retries',
      'kernel.note.lastRetry': 'Last full retry',
      'kernel.note.lastIncrementalRetry': 'Last incremental retry',
      'kernel.note.pendingNetlinkRecovery': 'Pending netlink recovery',
      'kernel.note.attachmentIssue': 'Active attachment issue',
      'kernel.note.lastAttachmentHeal': 'Last attachment self-heal',
      'kernel.note.lastAttachmentHealError': 'Last attachment self-heal failure',
      'kernel.note.xdpAttachmentMode': 'XDP attachment mode',
      'kernel.mode.steady': 'Steady',
      'kernel.mode.in_place': 'In-place',
      'kernel.mode.rebuild': 'Rebuild',
      'kernel.mode.cleared': 'Cleared',
      'kernel.mode.unknown': 'Unknown',
      'kernel.pressure.none': 'Normal',
      'kernel.pressure.hold': 'Hold',
      'kernel.pressure.shed': 'Shed',
      'kernel.pressure.full': 'Full',
      'kernel.pressure.noneHint': 'No active table pressure',
      'kernel.engine.name': 'Engine',
      'kernel.engine.available': 'Availability',
      'kernel.engine.pressure': 'Pressure',
      'kernel.engine.loaded': 'Program',
      'kernel.engine.entries': 'Entries',
      'kernel.engine.attachments': 'Attachments',
      'kernel.engine.attachHealthy': 'Attachment Health',
      'kernel.engine.families': 'Families',
      'kernel.engine.maps': 'Map Usage',
      'kernel.engine.reconcile': 'Last Reconcile',
      'kernel.engine.traffic': 'Traffic Stats',
      'kernel.engine.details': 'Details',
      'kernel.maps.rules': 'rules',
      'kernel.maps.flows': 'flows',
      'kernel.maps.nat': 'nat',
      'kernel.maps.ipv4': 'IPv4',
      'kernel.maps.ipv6': 'IPv6',
      'kernel.maps.ipv4Short': 'v4',
      'kernel.maps.ipv6Short': 'v6',
      'kernel.maps.tooltip.profile': 'Profile',
      'kernel.maps.tooltip.mode': 'Mode',
      'kernel.maps.tooltip.base': 'Base',
      'kernel.maps.tooltip.decision': 'Decision',
      'kernel.maps.tooltip.scope': 'Aggregation',
      'kernel.maps.tooltip.oldBank': 'Old bank',
      'kernel.maps.tooltip.mode.adaptive': 'Adaptive',
      'kernel.maps.tooltip.mode.fixed': 'Fixed',
      'kernel.maps.tooltip.decision.base': 'Using startup base {{base}}',
      'kernel.maps.tooltip.decision.expanded': 'Expanded from base {{base}} to {{current}}',
      'kernel.maps.tooltip.decision.retained': 'Retained smaller live map {{current}} (target base {{base}})',
      'kernel.maps.tooltip.decision.fixed': 'Using explicit limit {{limit}}',
      'kernel.maps.tooltip.decision.current': 'Current capacity {{current}}',
      'kernel.maps.tooltip.scope.families': 'Active capacity summed across v4/v6 families',
      'kernel.maps.tooltip.scope.familiesWithOldBank': 'Summed across v4/v6 families, including old-bank capacity',
      'runtimeReason.kernelMixedFamily': 'The kernel dataplane does not support mixed IPv4/IPv6 forwarding yet.',
      'runtimeReason.kernelTransparentIPv6': 'The kernel dataplane does not support transparent IPv6 rules yet.',
      'runtimeReason.xdpGenericExperimental': 'XDP generic/mixed attachment is disabled by default; enable the experimental `xdp_generic` feature to allow it.',
      'runtimeReason.xdpVethNatRedirectLegacyKernel': 'XDP NAT redirect on veth is disabled on this kernel; fall back to TC or upgrade to a newer kernel.',
      'runtimeReason.xdpGenericMode': 'XDP is attached in generic (SKB) mode; packets still traverse the skb path and this should not be treated as driver fast-path.',
      'runtimeReason.xdpMixedMode': 'XDP is using mixed driver / generic attachment modes; interfaces in generic mode still traverse the skb path and are not full driver fast-path.',
      'stats.rules.title': 'Rule Traffic Stats',
      'stats.sites.title': 'Site Traffic Stats',
      'stats.ranges.title': 'Range Traffic Stats',
      'stats.egressNATs.title': 'Egress NAT Traffic Stats',
      'stats.egressNATs.empty': 'No egress NAT statistics yet.',
      'stats.egressNATs.id.auto': 'AUTO',
      'stats.egressNATs.id.auto.title': 'Managed-network auto-generated egress NAT rule (ID {{id}})',
      'stats.currentConns': 'Connections',
      'stats.target': 'Target',
      'stats.route.in': 'IN',
      'stats.route.out': 'OUT',
      'stats.route.listen': 'LISTEN',
      'stats.refreshCurrentConns': 'Fetch Current Connections',
      'stats.currentConnsManual': 'Current connections are fetched on demand',
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
      'transparent.info.ipv6Unavailable': 'Transparent mode currently supports IPv4 targets only. Disable it for IPv6 targets.',
      'transparent.warning.public': 'A public target IP was detected. Transparent mode usually fails if the default gateway of {{target}} does not route back through this host.',
      'transparent.warning.publicBridge': 'A public target IP and a bridge-like outbound interface were detected. Transparent mode usually fails if the default gateway of {{target}} does not route back through this host.',
      'transparent.info.enabled': 'Transparent mode is enabled. Confirm that the default gateway or policy route of {{target}} points back to this host, otherwise reply traffic will bypass it.',
      'transparent.confirmContinue': 'Continue saving?',
      'transparent.target.backend': 'the backend host',
      'transparent.target.destination': 'the target host',
      'status.enabled': 'Enabled',
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
      'noun.managedNetwork': 'Managed Network',
      'noun.managedNetworkReservation': 'Fixed Lease',
      'noun.egressNAT': 'Egress NAT Takeover',
      'noun.ipv6Assignment': 'IPv6 Assignment',
      'toast.created': '{{item}} created.',
      'toast.saved': '{{item}} saved.',
      'toast.deleted': '{{item}} deleted.',
      'toast.enabled': '{{item}} enabled.',
      'toast.disabled': '{{item}} disabled.',
      'toast.loggedOut': 'Signed out.',
      'validation.required': 'This field is required.',
      'validation.invalidID': 'The ID is invalid.',
      'validation.ip': 'Enter a valid IP address.',
      'validation.ipv4': 'Enter a valid IPv4 address.',
      'validation.macAddress': 'Enter a valid MAC address.',
      'validation.ipv4CIDR': 'Enter a valid IPv4 CIDR.',
      'validation.ipv6': 'Enter a valid IPv6 address.',
      'validation.ipv6Prefix': 'Enter a valid IPv6 CIDR prefix.',
      'validation.prefixLength': 'Prefix length must be between 1 and 128.',
      'validation.sourceIPSpecific': 'Use a specific non-loopback local IP address.',
      'validation.positiveId': 'The ID must be greater than 0.',
      'validation.ruleCreateIDOmit': 'A new rule must not include an ID.',
      'validation.portRange': 'Ports must be between 1 and 65535.',
      'validation.protocol': 'Protocol must be tcp, udp, or tcp+udp.',
      'validation.egressNATProtocol': 'Select at least one protocol (tcp, udp, icmp).',
      'validation.enginePreference': 'Engine must be auto, userspace, or kernel.',
      'validation.interfaceMissing': 'The interface does not exist on this host.',
      'validation.sourceIPTransparent': 'Fixed source IP is not allowed in transparent mode.',
      'validation.sourceIPOutboundInterface': 'Fixed source IP is not assigned to the selected outbound interface.',
      'validation.sourceIPLocal': 'Fixed source IP is not assigned to this host.',
      'validation.transparentIPv4Only': 'Transparent mode currently supports IPv4 only in this phase.',
      'validation.sourceIPIPv4Only': 'Fixed source IP currently supports pure IPv4 userspace forwarding only.',
      'validation.sourceIPOutboundFamily': 'Fixed source IP must match the outbound target IP family.',
      'validation.sourceIPBackendFamily': 'Backend source IP must match the backend IP family.',
      'validation.sourceIPTargetFamily': 'Fixed source IP must match the target IP family.',
      'validation.ruleDuplicateUpdate': 'The update list contains duplicate rule IDs.',
      'validation.ruleDeletePendingUpdate': 'This rule is already scheduled for deletion and cannot be updated.',
      'validation.ruleDuplicateToggle': 'The enable/disable list contains duplicate rule IDs.',
      'validation.ruleDeletePendingToggle': 'This rule is already scheduled for deletion and cannot change enabled state.',
      'validation.ruleBatchRequired': 'At least one batch operation is required.',
      'validation.listenerConflict': 'Listener conflict: {{detail}}',
      'validation.routeConflict': 'Route conflict: {{detail}}',
      'validation.ruleNotFound': 'The rule no longer exists.',
      'validation.siteNotFound': 'The site no longer exists.',
      'validation.rangeNotFound': 'The range mapping no longer exists.',
      'validation.managedNetworkNotFound': 'The managed network no longer exists.',
      'validation.managedNetworkCreateIDOmit': 'Do not send an ID when creating a managed network.',
      'validation.managedNetworkReservationNotFound': 'The fixed lease no longer exists.',
      'validation.managedNetworkReservationCreateIDOmit': 'Do not send an ID when creating a fixed lease.',
      'validation.managedNetworkReservationIPv4Disabled': 'The selected managed network does not have IPv4 gateway + DHCPv4 enabled.',
      'validation.managedNetworkReservationIPv4Invalid': 'The selected managed network has an invalid IPv4 configuration. Fix the managed network first.',
      'validation.managedNetworkReservationIPv4InsideCIDR': 'The fixed IPv4 must stay inside the managed network IPv4 CIDR.',
      'validation.managedNetworkReservationGatewayConflict': 'The fixed IPv4 must not be the managed network gateway address.',
      'validation.managedNetworkReservationHostRequired': 'The fixed IPv4 must use a usable host address.',
      'validation.managedNetworkReservationMACConflict': 'That MAC is already claimed by fixed lease #{{id}}.',
      'validation.managedNetworkReservationIPConflict': 'That IPv4 is already claimed by fixed lease #{{id}}.',
      'validation.managedNetworkBridgeMode': 'Choose whether to create a new bridge or use an existing interface.',
      'validation.managedNetworkBridgeMissing': 'The selected bridge interface does not exist on this host.',
      'validation.managedNetworkBridgeNameConflict': 'That bridge name is already used by a non-bridge interface. Pick another name or switch to using an existing interface.',
      'validation.ipv6AssignmentNotFound': 'The IPv6 assignment no longer exists.',
      'validation.ipv6AssignmentCreateIDOmit': 'Do not send an ID when creating an IPv6 assignment.',
      'validation.targetInterfaceDifferent': 'The target interface must be different from the parent interface.',
      'validation.parentPrefixMissing': 'The parent prefix must exist on the selected parent interface.',
      'validation.assignedPrefixInsideParent': 'The assigned prefix must be contained within the parent prefix.',
      'validation.ipv6AssignedOnHost': 'That IPv6 already exists on a host interface and cannot be reused as the target-side single address.',
      'validation.ipv6AssignmentOverlap': 'The assigned prefix overlaps IPv6 assignment #{{id}}.',
      'validation.issueJoiner': '; ',
      'validation.issueSummaryMore': '{{messages}} (and {{count}} more)',
      'validation.reviewErrors': 'Review the highlighted fields.',
      'validation.ruleRequired': 'Please fill in complete IP and port values.',
      'validation.sitePortsRequired': 'Fill in either the HTTP port or the HTTPS port.',
      'validation.siteRequired': 'Please fill in the domain and backend IP.',
      'validation.rangeRequired': 'Please fill in complete IP and port range values.',
      'validation.rangeOrder': 'The start port must not exceed the end port.',
      'validation.managedNetworkIPv4Required': 'Fill in the IPv4 gateway CIDR when IPv4 is enabled.',
      'validation.managedNetworkIPv6Required': 'Select the IPv6 parent interface and parent prefix when IPv6 is enabled.',
      'validation.managedNetworkBridgeUplinkConflict': 'The bridge interface must be different from the uplink interface.',
      'validation.managedNetworkBridgeMTU': 'Bridge MTU must be between 0 and 65535.',
      'validation.managedNetworkPersistRequiresCreate': 'Only managed networks in create-bridge mode can be written into host config.',
      'validation.managedNetworkUplinkRequired': 'Select an uplink interface when auto egress NAT is enabled.',
      'validation.managedNetworkIPv4PoolOrder': 'The DHCPv4 pool start must not exceed the pool end.',
      'validation.egressNATRequired': 'Select the parent interface and outbound interface.',
      'validation.egressNATNotFound': 'The egress NAT takeover no longer exists.',
      'validation.egressNATCreateIDOmit': 'Do not send an ID when creating an egress NAT takeover.',
      'validation.egressNATChildConflict': 'The selected egress NAT scope is already claimed by egress NAT takeover #{{id}}.',
      'validation.egressNATNoChildren': 'The selected parent interface currently has no eligible child interfaces to take over.',
      'validation.egressNATNatType': 'NAT type must be symmetric or full_cone.',
      'validation.egressNATSingleTargetOutConflict': 'The parent interface must be different from the outbound interface in single-target mode.',
      'validation.childInterfaceDifferent': 'The child interface must be different from the outbound interface.',
      'validation.childParentMismatch': 'The child interface is not attached to the selected parent interface.',
      'validation.sourceIPEgressIPv4Only': 'The fixed egress NAT source IP currently supports IPv4 only.'
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
    range: { mode: 'add', sourceId: 0 },
    egressNAT: { mode: 'add', sourceId: 0 },
    ipv6Assignment: { mode: 'add', sourceId: 0 }
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

  app.clearNode = function clearNode(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  };

  app.appendNodeContent = function appendNodeContent(parent, content) {
    if (!parent || content == null) return;
    if (Array.isArray(content)) {
      content.forEach((item) => app.appendNodeContent(parent, item));
      return;
    }
    if (content instanceof Node) {
      parent.appendChild(content);
      return;
    }
    parent.appendChild(document.createTextNode(String(content)));
  };

  app.createNode = function createNode(tag, options) {
    const el = document.createElement(tag);
    const opts = options || {};
    if (opts.className) el.className = opts.className;
    if (opts.text != null) el.textContent = String(opts.text);
    if (opts.title) el.title = String(opts.title);
    if (opts.attrs) {
      Object.keys(opts.attrs).forEach((key) => {
        const value = opts.attrs[key];
        if (value == null || value === false) return;
        el.setAttribute(key, value === true ? '' : String(value));
      });
    }
    if (opts.dataset) {
      Object.keys(opts.dataset).forEach((key) => {
        const value = opts.dataset[key];
        if (value == null) return;
        el.dataset[key] = String(value);
      });
    }
    if (opts.disabled) {
      el.disabled = true;
      el.setAttribute('aria-disabled', 'true');
    }
    if (opts.children) app.appendNodeContent(el, opts.children);
    return el;
  };

  app.createCell = function createCell(content, className) {
    const td = app.createNode('td', { className: className || '' });
    app.appendNodeContent(td, content);
    return td;
  };

  app.emptyCellNode = function emptyCellNode(extraClass) {
    return app.createNode('span', {
      className: 'cell-empty' + (extraClass ? ' ' + extraClass : ''),
      text: app.t('common.dash')
    });
  };

  app.createBadgeNode = function createBadgeNode(className, text, title) {
    return app.createNode('span', {
      className: 'badge' + (className ? ' ' + className : ''),
      text: text == null ? '' : text,
      title: title || ''
    });
  };

  app.createStatusBadgeNode = function createStatusBadgeNode(status, enabled) {
    const info = typeof status === 'object' && status && Object.prototype.hasOwnProperty.call(status, 'badge')
      ? status
      : app.statusInfo(status, enabled);
    return app.createBadgeNode('badge-' + info.badge, info.text);
  };

  app.createTagBadgeNode = function createTagBadgeNode(table, tag, active) {
    if (!tag) return app.emptyCellNode();
    return app.createNode('span', {
      className: 'tag-badge' + (active ? ' tag-active' : ''),
      text: tag,
      dataset: {
        table: table,
        tag: tag
      }
    });
  };

  app.createEndpointNode = function createEndpointNode(primary, sourceIP) {
    if (!primary) return app.emptyCellNode();
    const primaryNode = app.createNode('span', {
      className: 'endpoint-primary',
      text: primary
    });
    if (!sourceIP) return primaryNode;
    return app.createNode('div', {
      className: 'endpoint-cell',
      children: [
        primaryNode,
        app.createNode('span', {
          className: 'endpoint-secondary',
          text: app.t('common.sourceShort') + ' ' + sourceIP
        })
      ]
    });
  };

  app.createActionButton = function createActionButton(options) {
    const opts = options || {};
    const button = app.createNode('button', {
      className: opts.className || '',
      text: opts.text == null ? '' : opts.text,
      dataset: opts.dataset || {},
      disabled: !!opts.disabled,
      attrs: Object.assign({ type: 'button' }, opts.attrs || {})
    });
    return button;
  };

  app.createActionDropdown = function createActionDropdown(items, disabled) {
    const wrapper = app.createNode('div', { className: 'action-dropdown' });
    const trigger = app.createActionButton({
      className: 'action-dropdown-trigger',
      text: app.t('common.actions') + ' ▼',
      disabled: !!disabled,
      attrs: { 'aria-expanded': 'false' }
    });
    const menu = app.createNode('div', { className: 'action-dropdown-menu' });
    (items || []).forEach((item) => {
      menu.appendChild(app.createActionButton(item));
    });
    wrapper.appendChild(trigger);
    wrapper.appendChild(menu);
    return wrapper;
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

  app.transparentAvailability = function transparentAvailability(backendIP) {
    const family = typeof app.ipFamily === 'function' ? app.ipFamily((backendIP || '').trim()) : '';
    if (family === 'ipv6') {
      return {
        supported: false,
        level: 'info',
        text: app.t('transparent.info.ipv6Unavailable'),
        needsConfirm: false
      };
    }
    return {
      supported: true,
      level: '',
      text: '',
      needsConfirm: false
    };
  };

  app.syncTransparentToggleState = function syncTransparentToggleState(input, backendIP) {
    const availability = typeof app.transparentAvailability === 'function'
      ? app.transparentAvailability(backendIP)
      : { supported: true, level: '', text: '', needsConfirm: false };

    if (!input) return availability;

    if (!availability.supported) {
      input.checked = false;
      input.disabled = true;
      input.setAttribute('aria-disabled', 'true');
      if (availability.text) input.setAttribute('title', availability.text);
      else input.removeAttribute('title');
      return availability;
    }

    input.disabled = false;
    input.removeAttribute('aria-disabled');
    input.removeAttribute('title');
    return availability;
  };

  app.updateRuleTransparentWarning = function updateRuleTransparentWarning() {
    const availability = app.syncTransparentToggleState(app.el.ruleTransparent, app.el.ruleOutIP.value);
    app.syncTransparentSourceIPState(app.el.ruleOutSourceIP, app.el.ruleTransparent.checked);
    return app.applyTransparentWarning(
      app.el.ruleTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(app.el.ruleTransparent.checked, app.el.ruleOutIP.value, app.el.outInterface.value, 'transparent.target.backend')
        : availability
    );
  };

  app.updateSiteTransparentWarning = function updateSiteTransparentWarning() {
    const availability = app.syncTransparentToggleState(app.el.siteTransparent, app.el.siteBackendIP.value);
    app.syncTransparentSourceIPState(app.el.siteBackendSourceIP, app.el.siteTransparent.checked);
    return app.applyTransparentWarning(
      app.el.siteTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(app.el.siteTransparent.checked, app.el.siteBackendIP.value, '', 'transparent.target.backend')
        : availability
    );
  };

  app.updateRangeTransparentWarning = function updateRangeTransparentWarning() {
    const availability = app.syncTransparentToggleState(app.el.rangeTransparent, app.el.rangeOutIP.value);
    app.syncTransparentSourceIPState(app.el.rangeOutSourceIP, app.el.rangeTransparent.checked);
    return app.applyTransparentWarning(
      app.el.rangeTransparentWarning,
      availability && availability.supported
        ? app.buildTransparentWarning(app.el.rangeTransparent.checked, app.el.rangeOutIP.value, app.el.rangeOutInterface.value, 'transparent.target.destination')
        : availability
    );
  };

  app.populateInterfaceSelect = function populateInterfaceSelect(sel, selected) {
    if (typeof app.populateInterfaceSelectFiltered === 'function') {
      app.populateInterfaceSelectFiltered(sel, selected, { preserveSelected: true });
      return;
    }
    if (!sel) return;
    const current = selected == null ? sel.value : selected;
    app.clearNode(sel);
    app.addOption(sel, '', app.t('common.unspecified'));
    app.interfaces.forEach((iface) => {
      app.addOption(sel, iface.name, app.interfaceOptionLabel(iface));
    });
    sel.value = current || '';
  };

  app.populateIPSelect = function populateIPSelect(ifaceSel, ipSel, selected) {
    if (!ipSel) return;
    const current = selected == null ? ipSel.value : selected;
    const ifaceName = ifaceSel ? ifaceSel.value : '';
    app.clearNode(ipSel);
    app.addOption(ipSel, '0.0.0.0', app.t('common.allIPv4Addresses'));
    app.addOption(ipSel, '::', app.t('common.allIPv6Addresses'));

    if (!ifaceName) {
      app.interfaces.forEach((iface) => {
        app.interfaceAddresses(iface).forEach((addr) => {
          app.addOption(ipSel, addr, addr + ' (' + iface.name + ')');
        });
      });
    } else {
      const iface = app.interfaces.find((item) => item.name === ifaceName);
      if (iface) {
        app.interfaceAddresses(iface).forEach((addr) => app.addOption(ipSel, addr, addr));
      }
    }

    ipSel.value = current || '0.0.0.0';
  };

  app.populateSiteListenIP = function populateSiteListenIP(ifaceSel, ipSel, selected) {
    app.populateIPSelect(ifaceSel, ipSel, selected);
  };

  app.populateSourceIPSelect = function populateSourceIPSelect(ifaceSel, inputEl, selected, legacy, options) {
    if (!inputEl) return;

    const opts = (options && typeof options === 'object')
      ? options
      : ((legacy && typeof legacy === 'object') ? legacy : {});
    const current = selected == null ? inputEl.value : selected;
    const ifaceName = ifaceSel ? ifaceSel.value : '';
    const family = String(opts.family || '').trim().toLowerCase();
    const listId = inputEl.getAttribute('list');
    const listEl = listId ? app.$(listId) : null;
    const seen = Object.create(null);
    if (!listEl) {
      if (family && current && app.isValidIP(current) && app.ipFamily(current) !== family) inputEl.value = '';
      else inputEl.value = current || '';
      return;
    }

    app.clearNode(listEl);

    const appendOption = function appendOption(value, label) {
      if (!value || seen[value]) return;
      if (!app.isValidIP(value)) return;
      if (family && app.ipFamily(value) !== family) return;
      const normalized = String(value).trim().toLowerCase();
      if (normalized === '0.0.0.0' || normalized === '::' || /^127\./.test(value) || normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return;
      seen[value] = true;
      const opt = document.createElement('option');
      opt.value = value;
      opt.label = label;
      listEl.appendChild(opt);
    };

    if (!ifaceName) {
      app.interfaces.forEach((iface) => {
        app.interfaceAddresses(iface).forEach((addr) => appendOption(addr, addr + ' (' + iface.name + ')'));
      });
    } else {
      const iface = app.interfaces.find((item) => item.name === ifaceName);
      if (iface) app.interfaceAddresses(iface).forEach((addr) => appendOption(addr, addr));
    }

    if (family && current && app.isValidIP(current) && app.ipFamily(current) !== family) inputEl.value = '';
    else inputEl.value = current || '';
  };

  app.populateTagSelect = function populateTagSelect(sel, selected) {
    if (!sel) return;
    const current = selected == null ? sel.value : selected;
    app.clearNode(sel);
    app.addOption(sel, '', app.t('common.unspecified'));
    app.tags.forEach((tag) => app.addOption(sel, tag, tag));
    sel.value = current || '';
  };

  app.rebuildSelects = function rebuildSelects() {
    if (app.el.localeSelect) app.el.localeSelect.value = app.state.locale;
    if (app.el.themeSelect) app.el.themeSelect.value = app.state.theme;

    if (typeof app.refreshRuleInterfaceSelectors === 'function') app.refreshRuleInterfaceSelectors();
    else {
      app.populateInterfaceSelect(app.el.inInterface, app.el.inInterface.value);
      app.populateInterfaceSelect(app.el.outInterface, app.el.outInterface.value);
      app.populateIPSelect(app.el.inInterface, app.el.inIP, app.el.inIP.value);
    }
    if (typeof app.refreshSiteInterfaceSelectors === 'function') app.refreshSiteInterfaceSelectors();
    else {
      app.populateInterfaceSelect(app.el.siteListenIface, app.el.siteListenIface.value);
      app.populateSiteListenIP(app.el.siteListenIface, app.el.siteListenIP, app.el.siteListenIP.value);
    }
    if (typeof app.refreshRangeInterfaceSelectors === 'function') app.refreshRangeInterfaceSelectors();
    else {
      app.populateInterfaceSelect(app.el.rangeInInterface, app.el.rangeInInterface.value);
      app.populateInterfaceSelect(app.el.rangeOutInterface, app.el.rangeOutInterface.value);
      app.populateIPSelect(app.el.rangeInInterface, app.el.rangeInIP, app.el.rangeInIP.value);
    }

    if (typeof app.refreshRuleSourceIPOptions === 'function') {
      app.refreshRuleSourceIPOptions(app.el.ruleOutSourceIP.value);
    } else {
      app.populateSourceIPSelect(app.el.outInterface, app.el.ruleOutSourceIP, app.el.ruleOutSourceIP.value, true);
    }
    if (typeof app.refreshSiteBackendSourceIPOptions === 'function') {
      app.refreshSiteBackendSourceIPOptions(app.el.siteBackendSourceIP.value);
    } else {
      app.populateSourceIPSelect(null, app.el.siteBackendSourceIP, app.el.siteBackendSourceIP.value, true);
    }
    if (typeof app.refreshRangeSourceIPOptions === 'function') {
      app.refreshRangeSourceIPOptions(app.el.rangeOutSourceIP.value);
    } else {
      app.populateSourceIPSelect(app.el.rangeOutInterface, app.el.rangeOutSourceIP, app.el.rangeOutSourceIP.value, true);
    }
    app.populateSourceIPSelect(app.el.egressNATOutInterface, app.el.egressNATOutSourceIP, app.el.egressNATOutSourceIP.value, true);
    if (typeof app.populateEgressNATInterfaceSelectors === 'function') app.populateEgressNATInterfaceSelectors();
    if (typeof app.refreshEgressNATProtocolUI === 'function') app.refreshEgressNATProtocolUI();

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
    if (typeof app.syncEgressNATFormState === 'function') app.syncEgressNATFormState();

    app.updateRuleTransparentWarning();
    app.updateSiteTransparentWarning();
    app.updateRangeTransparentWarning();

    if (typeof app.renderRulesTable === 'function') app.renderRulesTable();
    if (typeof app.renderSitesTable === 'function') app.renderSitesTable();
    if (typeof app.renderRangesTable === 'function') app.renderRangesTable();
    if (typeof app.renderEgressNATsTable === 'function') app.renderEgressNATsTable();
    if (typeof app.renderWorkersTable === 'function') app.renderWorkersTable();
    if (typeof app.renderKernelRuntime === 'function') app.renderKernelRuntime();
    if (typeof app.renderRuleStatsTable === 'function') app.renderRuleStatsTable();
    if (typeof app.renderSiteStatsTable === 'function') app.renderSiteStatsTable();
    if (typeof app.renderRangeStatsTable === 'function') app.renderRangeStatsTable();
    if (typeof app.renderEgressNATStatsTable === 'function') app.renderEgressNATStatsTable();
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
