const { expect, test } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const vpnShares = require('../../../plugins/vpn_core/ui/share');

const pluginPageHTML = `<!doctype html>
<html>
<head><meta charset="utf-8"><title>Firewall fixture</title></head>
<body>
  <main class="veer-page">
    <section class="veer-card">
      <h1 class="veer-title">Firewall fixture</h1>
      <div class="veer-actions">
        <button id="shrink" type="button">Shrink</button>
        <button id="grow" type="button">Grow</button>
        <button id="confirm" type="button">Confirm</button>
      </div>
      <div id="resizable" style="height: 480px"></div>
    </section>
  </main>
  <script>
    document.getElementById('shrink').addEventListener('click', function () {
      document.getElementById('resizable').style.height = '20px';
      if (window.VeerPluginHost) window.VeerPluginHost.requestResize();
    });
    document.getElementById('grow').addEventListener('click', function () {
      document.getElementById('resizable').style.height = '480px';
      if (window.VeerPluginHost) window.VeerPluginHost.requestResize();
    });
    document.getElementById('confirm').addEventListener('click', function () {
      window.fixtureConfirmResult = 'pending';
      window.VeerPluginHost.confirm({
        title: 'Plugin confirmation',
        message: 'Confirm from sandbox',
        confirmText: 'Proceed',
        cancelText: 'Cancel',
        danger: true
      }).then(function (confirmed) {
        window.fixtureConfirmResult = confirmed;
      });
    });
  </script>
</body>
</html>`;

const netfilterDropper = {
  id: 'nf_dropper',
  name: 'Netfilter Dropper',
  kind: 'pipeline',
  stability: 'stable',
  version: '1.0.0',
  status: 'active',
  enabled: true,
  runtime: {
    mode: 'dataplane',
    attachable: true,
    attached: true,
    attachment_count: 1,
    attachments: [{
      hook_id: 'drop',
      engine: 'netfilter',
      family: 'ipv4',
      netfilter_hook: 'forward',
      phase: 'filter',
      namespace: 'host',
      attach: 'forward',
      stage: 'filter',
      interface: 'host',
      priority: 10,
      order: 0,
      program: 'dropper:nf_drop',
      filter_handle: 'bpf_link:priority=4',
      status: 'attached'
    }]
  }
};

const netfilterCounter = {
  id: 'nf_counter',
  name: 'Netfilter Counter',
  description: 'Counts packets at the native Netfilter forward hook.',
  kind: 'pipeline',
  stability: 'stable',
  version: '1.0.0',
  status: 'active',
  enabled: true,
  capabilities: ['netfilter', 'observe'],
  hooks: [{
    id: 'count',
    engine: 'netfilter',
    family: 'inet',
    hook: 'forward',
    phase: 'filter',
    namespace: 'host',
    priority: 20,
    program: 'counter:nf_count'
  }],
  ui: { entry: 'index.html', page: 'firewall', page_title: 'Firewall' },
  asset_base_path: '/api/plugins/nf_counter/assets/',
  runtime: {
    mode: 'dataplane',
    attachable: true,
    attached: true,
    attachment_count: 1,
    attachments: [{
      hook_id: 'count',
      engine: 'netfilter',
      family: 'ipv4',
      netfilter_hook: 'forward',
      phase: 'filter',
      namespace: 'host',
      attach: 'forward',
      stage: 'filter',
      interface: 'host',
      priority: 20,
      order: 1,
      program: 'counter:nf_count',
      filter_handle: 'bpf_link:priority=5',
      status: 'attached'
    }]
  }
};

const pluginCatalog = {
  external_plugins_enabled: true,
  directory: 'plugins',
  runtime: {
    control_enabled: true,
    external_dataplane_attach: true,
    core_priority: 1000
  },
  hot_reload: {
    enabled: true,
    update_available: false,
    last_check_result: 'unchanged',
    updates: []
  },
  plugins: [
    {
      id: 'veer_core',
      name: 'Veer Core',
      kind: 'builtin',
      stability: 'stable',
      version: '1.0.0',
      status: 'builtin',
      builtin: true,
      enabled: true,
      runtime: { mode: 'builtin', attachable: true, attached: true, attachment_count: 0, attachments: [] }
    },
    netfilterDropper,
    netfilterCounter
  ]
};

const apiFixtures = new Map([
  ['/api/tags', []],
  ['/api/interfaces', []],
  ['/api/host-network', { interfaces: [] }],
  ['/api/rules', []],
  ['/api/sites', []],
  ['/api/ranges', []],
  ['/api/managed-networks', []],
  ['/api/managed-networks/runtime-status', {}],
  ['/api/managed-network-reservation-candidates', []],
  ['/api/managed-network-reservations', []],
  ['/api/egress-nats', []],
  ['/api/ipv6-assignments', []],
  ['/api/plugins', pluginCatalog],
  ['/api/workers', { binary_hash: '0123456789abcdef', workers: [] }]
]);

const browserErrors = new WeakMap();

test('VPN WAN saves drafts and encrypted core configurations through the real UI bridge', async ({ page }, testInfo) => {
  test.setTimeout(60000);
  await openDashboard(page, testInfo);
  const profile = {slot:2, addresses:['10.77.0.1/32'], peers:[{public_key:Buffer.alloc(32,2).toString('base64'), allowed_ips:['0.0.0.0/0']}],
    remote_routes:[]};
  const records = {saved:{key:'saved', data:profile, enabled:true}};
  const actions = [];
  const coreConfigs = {};
  const methods = ['list','get','create','update'];
  const coreActions = ['core_status','core_install','core_select','core_rollback','core_remove'];
  const healthActions=['health_status','health_settings','health_check'], healthRequests=[], healthValues={};
  const healthDefaults=require('../../../plugins/vpn_core/health-check').settings();
  let healthFailure=false, healthPolls=0;
  const cores = {id:'mihomo', directory:'/opt/veer/plugins.veer-state/cores/vpn_core/mihomo/linux-amd64', versions:[]};
  let installationPolls=0;
  const plugin = {id:'vpn_core', name:'VPN WAN', kind:'pipeline', stability:'lab', version:'0.6.1', status:'active', enabled:true,
    resources:[{id:'profiles', methods}, {id:'status', methods:['list','get']}],
    actions:['set_key','set_core_config','core_form','apply','teardown','inspect','core_logs',...coreActions,...healthActions].map(id => ({id})),
    ui:{entry:'index.html', page:'vpn', page_title:'VPN', resources:[{resource:'profiles', methods}, {resource:'status', methods:['list']}],
      actions:['set_key','set_core_config','core_form','apply','teardown','inspect','core_logs',...coreActions,...healthActions]}, asset_base_path:'/api/plugins/vpn_core/assets/', runtime:{mode:'control'}};
  await page.route('**/api/plugins', route => route.fulfill({json:{...pluginCatalog, plugins:[...pluginCatalog.plugins, plugin]}}));
  await page.route('**/api/plugins/vpn_core/**', async route => {
    const url = new URL(route.request().url());
    const endpoint = url.pathname.split('/vpn_core/')[1];
    if (endpoint.startsWith('assets/')) {
      const asset=endpoint.slice('assets/'.length);
      if (!['index.html','app.js','model.js','share.js','style.css'].includes(asset)) return route.fulfill({status:404});
      return route.fulfill({contentType:asset.endsWith('.css')?'text/css':asset.endsWith('.js')?'application/javascript':'text/html; charset=utf-8', body:fs.readFileSync(path.resolve(__dirname, '../../../plugins/vpn_core/ui',asset), 'utf8')});
    }
    if (endpoint === 'resources/status') return route.fulfill({json:{records:[]}});
    if (endpoint === 'resources/profiles' && route.request().method() === 'GET') return route.fulfill({json:{records:Object.values(records)}});
    if (endpoint.startsWith('resources/profiles/')) {
      const key = endpoint.split('/').pop();
      if (route.request().method() === 'PUT') records[key] = {key, ...route.request().postDataJSON()};
      return route.fulfill({json:records[key]});
    }
    if (endpoint.startsWith('actions/')) {
      const id=endpoint.split('/').pop();
      const payload=route.request().postDataJSON().payload;
      if(healthActions.includes(id)) {
        Object.keys(records).forEach(key=>{healthValues[key] ||= {key,settings:{...healthDefaults},state:'unknown',result:null};});
        if(id==='health_status') {
          if(healthValues.saved?.state==='checking' && ++healthPolls>=3)healthValues.saved={...healthValues.saved,state:healthFailure?'unhealthy':'healthy',result:{latency_ms:37,checked_at:Date.now(),message:healthFailure?'检测超时':'VPN 链路可用',consecutive_failures:healthFailure?1:0}};
          return route.fulfill({json:{result:{items:Object.values(healthValues)}}});
        }
        healthRequests.push({id,payload});
        if(id==='health_settings')healthValues[payload.key]={...healthValues[payload.key],settings:payload.settings,state:'stale'};
        if(id==='health_check'){healthValues[payload.key].state='checking';healthPolls=0;}
        return route.fulfill({json:{result:healthValues[payload.key]}});
      }
      if(id==='core_form') {
        const name=records[payload.key]?.data.config_secret || 'core_'+payload.key;
        return route.fulfill({json:{result:coreConfigs[name]?vpnShares.metadata(coreConfigs[name]):{mode:'empty'}}});
      }
      if(id==='set_core_config') {
        actions.push({id,...route.request().postDataJSON()});
        const name=payload.name || 'core_'+payload.key;
        if(payload.format==='links') {
          coreConfigs[name]=vpnShares.create(payload.driver,payload.value||coreConfigs[name]?.links,payload.selected,payload.options);
          return route.fulfill({json:{result:{stored:true,form:vpnShares.metadata(coreConfigs[name])}}});
        }
        coreConfigs[name]=JSON.parse(payload.value);
        return route.fulfill({json:{result:{stored:true}}});
      }
      if(id==='core_status') {
        if(cores.install && cores.install.state==='downloading' && ++installationPolls>=2) {
          cores.version='v1.19.33';cores.versions=[{version:cores.version}];cores.install={state:'ready',downloaded_bytes:1048576};
        }
        return route.fulfill({json:{status:'completed',result:cores}});
      }
      if(id==='core_install') {
        actions.push({id,...route.request().postDataJSON()});
        cores.install={state:'downloading',downloaded_bytes:0};installationPolls=0;
        return route.fulfill({json:{status:'completed',result:cores}});
      }
      if(id==='core_rollback') {
        actions.push({id,...route.request().postDataJSON()});
        [cores.version,cores.previous]=[cores.previous,cores.version];
        return route.fulfill({json:{status:'completed',result:cores}});
      }
      actions.push({id:endpoint.split('/').pop(), ...route.request().postDataJSON()});
      return route.fulfill({json:{plugin_id:'vpn_core', action_id:endpoint.split('/').pop(), status:'completed'}});
    }
    return route.fulfill({status:404, json:{error:'unknown fixture'}});
  });
  await page.evaluate(() => window.VeerApp.loadPlugins());
  await page.locator('[data-tab="plugin-vpn"]').click();
  const frame = page.frameLocator('#tab-plugin-vpn .plugin-page-frame');
  await expect(frame.locator('h1')).toHaveText('VPN 出口');
  await expect(frame.locator('.vpn-outlet')).toHaveCount(1);
  await frame.getByRole('button',{name:'健康检测',exact:true}).click();
  await expect(frame.locator('.vpn-health')).toContainText('未检测');
  await expect(frame.getByLabel('检测地址',{exact:true})).toBeHidden();
  await frame.getByText('检测设置',{exact:true}).click();
  await expect(frame.getByLabel('自动检测',{exact:true})).toHaveValue('off');
  await frame.getByLabel('检测地址',{exact:true}).fill('http://192.168.20.1/health');
  await frame.getByRole('button',{name:'保存检测设置',exact:true}).click();
  await expect.poll(()=>healthRequests.length).toBe(1);
  expect(healthRequests[0].payload.settings.url).toBe('http://192.168.20.1/health');
  expect(actions).toHaveLength(0);
  await frame.getByRole('button',{name:'立即检测',exact:true}).click();
  await expect(frame.locator('.vpn-health')).toContainText('检测中');
  await expect(frame.locator('.vpn-health')).toContainText('链路可用');
  await expect(frame.locator('.vpn-health')).toContainText('37 ms');
  healthFailure=true;
  await frame.getByRole('button',{name:'立即检测',exact:true}).click();
  await expect(frame.locator('.vpn-health')).toContainText('链路异常');
  await expect(frame.locator('.vpn-health')).toContainText('检测超时');
  await expectNoPageOverflow(page);
  await page.screenshot({path:testInfo.outputPath('vpn-health.png'),fullPage:true});
  await frame.getByRole('button',{name:'收起检测',exact:true}).click();
  await expect(frame.getByLabel('代理核心 JSON 配置')).toHaveCount(0);
  await frame.getByRole('button', {name:'编辑', exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址', {exact:true})).toHaveValue('10.77.0.1/32');
  await expect(frame.getByLabel('实际出站接口', {exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('内部 WAN 地址', {exact:true})).toBeHidden();
  await expect(frame.getByLabel('出口标识', {exact:true})).toHaveValue('saved');
  await frame.getByLabel('WireGuard 私钥', {exact:true}).fill(Buffer.alloc(32,1).toString('base64'));
  await frame.getByRole('button', {name:'保存草稿', exact:true}).click();
  await expect(frame.getByLabel('WireGuard 私钥', {exact:true})).toHaveValue('');
  expect(actions).toEqual([{id:'set_key',payload:{key:'saved',value:Buffer.alloc(32,1).toString('base64')}}]);
  await frame.getByRole('button', {name:'保存并应用', exact:true}).click();
  await expect.poll(() => actions.map(a => a.id)).toEqual(['set_key','apply']);
  await frame.getByRole('button', {name:'Mihomo', exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址', {exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('WireGuard 私钥', {exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('内部 WAN 地址', {exact:true})).toBeHidden();
  await expect(frame.getByLabel('节点分享链接或 Base64')).toBeVisible();
  await expect(frame.getByLabel('Mihomo 配置（JSON）', {exact:true})).toBeHidden();
  await frame.getByLabel('实际出站接口', {exact:true}).fill('vmbr0');
  await frame.getByText('分流与高级配置',{exact:true}).click();
  await frame.getByLabel('核心配置方式').selectOption('native');
  await expect(frame.getByLabel('节点分享链接或 Base64')).toBeHidden();
  const coreJSON=JSON.stringify({proxies:[{password:'core-secret'}],rules:['MATCH,DIRECT']});
  await frame.getByLabel('Mihomo 配置（JSON）', {exact:true}).fill(coreJSON);
  await frame.getByRole('button', {name:'保存草稿', exact:true}).click();
  await expect(frame.getByLabel('Mihomo 配置（JSON）', {exact:true})).toHaveValue('');
  expect(actions.at(-1)).toEqual({id:'set_core_config',payload:{key:'saved',name:'core_mihomo_saved',value:coreJSON}});
  await expect.poll(()=>records.saved.data.driver).toBe('mihomo');
  expect(records.saved.data.upstream_interface).toBe('vmbr0');
  expect(records.saved.data.config_secret).toBe('core_mihomo_saved');
  for(const field of ['addresses','peers','listen_port','remote_routes']) expect(records.saved.data[field]).toBeUndefined();
  await expect(frame.locator('body')).not.toContainText('core-secret');
  await frame.getByRole('button', {name:'保存并应用', exact:true}).click();
  await expect.poll(() => actions.map(a => a.id)).toEqual(['set_key','apply','set_core_config','apply']);
  await frame.getByRole('tab',{name:'核心管理',exact:true}).click();
  await expect(frame.locator('.vpn-core-version')).toHaveText('尚未安装');
  await frame.getByRole('button',{name:'安装 / 更新',exact:true}).click();
  await expect(frame.getByRole('combobox',{name:'已安装核心版本'})).toHaveValue('v1.19.33');
  expect(actions.at(-1)).toEqual({id:'core_install',payload:{driver:'mihomo',version:'',sha256:''}});
  await expect(frame.locator('body')).toContainText('安装成功');
  cores.previous='v1.19.32';cores.versions.push({version:cores.previous});
  await frame.getByRole('button',{name:'回滚上一版本',exact:true}).click();
  await expect(frame.locator('.vpn-core-version')).toHaveText('v1.19.32');
  expect(actions.at(-1).id).toBe('core_rollback');
  await expectNoPageOverflow(page);
  expect(await frame.locator('body').evaluate(el => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(1);
  await page.screenshot({path:testInfo.outputPath('vpn-cores.png'), fullPage:true});
  await frame.getByRole('tab',{name:/^出口/}).click();
  await frame.getByRole('button',{name:'收起编辑',exact:true}).click();
  await expect.poll(() => page.locator('#tab-plugin-vpn iframe').evaluate(el => el.getBoundingClientRect().height)).toBeLessThan(850);
  await page.screenshot({path:testInfo.outputPath('vpn-outlets.png'), fullPage:true});
  await frame.getByRole('button',{name:'新建出口',exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址',{exact:true})).toHaveValue('');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect(frame.locator('.vpn-notice')).toContainText('WireGuard 地址');
  await frame.getByText('导入 WireGuard 配置',{exact:true}).click();
  const beforeImport=actions.length;
  await frame.getByLabel('WireGuard 配置文件').fill('[Interface]\nPostUp = touch /tmp/untrusted');
  await frame.getByRole('button',{name:'导入到表单',exact:true}).click();
  await expect(frame.locator('.vpn-notice')).toContainText('脚本钩子');
  expect(actions.length).toBe(beforeImport);
  const privateKey=Buffer.alloc(32,1).toString('base64'),psk=Buffer.alloc(32,3).toString('base64');
  await frame.getByLabel('WireGuard 配置文件').fill('[Interface]\nPrivateKey = '+privateKey+'\nAddress = 10.77.1.1/32\n[Peer]\nPublicKey = '+Buffer.alloc(32,2).toString('base64')+'\nPresharedKey = '+psk+'\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n');
  await frame.getByRole('button',{name:'导入到表单',exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址',{exact:true})).toHaveValue('10.77.1.1/32');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect(frame.getByLabel('WireGuard 私钥')).toHaveValue('');
  await expect(frame.getByLabel('Peer 预共享密钥')).toHaveValue('');
  expect(actions.slice(beforeImport).map(a=>a.id)).toEqual(['set_key','set_key']);
  expect(actions.at(-1).payload).toEqual({key:'vpn1',name:'psk_vpn1_0',value:psk});
  expect(records.vpn1.data.peers[0].preshared_key_secret).toBe('psk_vpn1_0');
  expect(JSON.stringify(records.vpn1.data)).not.toContain(psk);
  expect(JSON.stringify(records.vpn1.data)).not.toContain(privateKey);
  await page.screenshot({path:testInfo.outputPath('vpn-wireguard-form.png'),fullPage:true});
  await frame.getByRole('button',{name:'sing-box',exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址',{exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('内部 WAN 地址',{exact:true})).toBeHidden();
  await expect(frame.getByLabel('Mihomo 配置（JSON）',{exact:true})).toHaveCount(0);
  await frame.getByLabel('实际出站接口',{exact:true}).fill('ppp0');
  await expect(frame.getByLabel('sing-box 配置（JSON）',{exact:true})).toBeHidden();
  await expect(frame.getByLabel('直连网段')).toBeHidden();
  await frame.getByLabel('节点分享链接或 Base64').fill('trojan://test-secret@host.example:0');
  const beforeInvalid=actions.length;
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect(frame.locator('.vpn-notice')).toContainText('端口');expect(actions.length).toBe(beforeInvalid);
  const shareList='ss://'+Buffer.from('aes-128-gcm:share-secret').toString('base64url')+'@192.0.2.2:8388#first\n'+
    'anytls://second-secret@node.example?security=tls&sni=example.com&insecure=0&allowInsecure=0&type=tcp&headerType=none#second';
  await frame.getByLabel('节点分享链接或 Base64').fill(Buffer.from(shareList).toString('base64'));
  await frame.getByRole('button',{name:'识别节点',exact:true}).click();
  await expect(frame.getByLabel('使用节点').locator('option')).toHaveCount(2);
  await frame.getByLabel('使用节点').selectOption('1');
  await frame.getByText('分流与高级配置',{exact:true}).click();
  await frame.getByLabel('直连网段').fill('10.0.0.0/8');
  await frame.getByLabel('直连域名').fill('example.com');
  await frame.getByLabel('下游 DNS').selectOption('on');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect.poll(()=>records.vpn1.data.driver).toBe('sing_box');
  expect(records.vpn1.data.upstream_interface).toBe('ppp0');
  expect(records.vpn1.data.config_secret).toBe('core_sing_box_vpn1');
  expect(actions.at(-1).payload.format).toBe('links');expect(actions.at(-1).payload.selected).toBe(1);
  expect(actions.at(-1).payload.options.direct_cidrs).toEqual(['10.0.0.0/8']);
  expect(actions.at(-1).payload.options.dns_hijack).toBe(true);
  await expect(frame.getByLabel('节点分享链接或 Base64')).toHaveValue('');
  await expect(frame.locator('body')).not.toContainText('share-secret');
  await expect(frame.locator('body')).not.toContainText('second-secret');
  expect(JSON.stringify(records.vpn1)).not.toContain('secret@');
  for(const field of ['addresses','peers','listen_port','remote_routes']) expect(records.vpn1.data[field]).toBeUndefined();
  await page.screenshot({path:testInfo.outputPath('vpn-sing-box-form.png'),fullPage:true});
  await frame.getByRole('button',{name:'收起编辑',exact:true}).click();
  await frame.locator('.vpn-outlet').filter({has:frame.getByRole('heading',{name:'vpn1',exact:true})}).getByRole('button',{name:'编辑',exact:true}).click();
  await expect(frame.getByLabel('使用节点')).toHaveValue('1');
  await expect(frame.getByLabel('直连网段')).toBeHidden();
  await frame.getByText('分流与高级配置',{exact:true}).click();
  await expect(frame.getByLabel('直连网段')).toHaveValue('10.0.0.0/8');
  await frame.getByLabel('使用节点').selectOption('0');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect.poll(()=>coreConfigs.core_sing_box_vpn1.selected).toBe(0);
  expect(actions.at(-1).payload.value).toBe('');
  await frame.getByText('高级设置与 JSON',{exact:true}).click();
  await frame.getByRole('button',{name:'读取当前表单 JSON',exact:true}).click();
  const rawProfile=JSON.parse(await frame.getByLabel('VPN 出口 JSON').inputValue());rawProfile.mtu=1400;
  await frame.getByLabel('VPN 出口 JSON').fill(JSON.stringify(rawProfile));
  await frame.getByRole('button',{name:'将 JSON 更新到表单',exact:true}).click();
  await expect(frame.getByLabel('使用节点')).toHaveValue('0');
  await expect(frame.getByLabel('内部 WAN 地址',{exact:true})).toBeVisible();
  await frame.getByLabel('内部 WAN 地址',{exact:true}).fill('10.90.0.1/24');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect(frame.locator('.vpn-notice')).toContainText('/32 或 /128');
  await frame.getByLabel('内部 WAN 地址',{exact:true}).fill('10.90.0.1/32');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect.poll(()=>records.vpn1.data.addresses).toEqual(['10.90.0.1/32']);
  await frame.getByRole('button',{name:'外部 TUN',exact:true}).click();
  await expect(frame.getByLabel('实际出站接口',{exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('sing-box 配置（JSON）',{exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('WireGuard 私钥',{exact:true})).toHaveCount(0);
  await frame.getByLabel('TUN 接口',{exact:true}).fill('tun0');
  await frame.getByLabel('TUN 归属标记',{exact:true}).fill('external-provider');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect.poll(()=>records.vpn1.data.driver).toBe('tun');
  expect(records.vpn1.data.tun_interface).toBe('tun0');
  expect(records.vpn1.data.tun_alias).toBe('external-provider');
  for(const field of ['addresses','upstream_interface','config_secret','peers']) expect(records.vpn1.data[field]).toBeUndefined();
  await expectNoPageOverflow(page);
  await page.screenshot({path:testInfo.outputPath('vpn-external-tun-form.png'),fullPage:true});
});


test('plugin installation controls follow the host policy while plugin pages remain accessible', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugins"]').click();
  await expect(page.locator('#addPluginBtn')).toBeHidden();
  await expect(page.locator('#managePluginsAdvancedBtn')).toBeVisible();
  await page.locator('#managePluginsAdvancedBtn').click();
  await expect(page.locator('#pluginManagerNav')).not.toContainText(/Add Plugin|添加插件/);
  await expect(page.locator('#pluginManagerBody')).not.toContainText(/Publishers|发布者/);
  await page.locator('#closePluginManagerBtn').click();
  await page.locator('[data-tab="plugin-firewall"]').click();
  await expect(page.frameLocator('#tab-plugin-firewall .plugin-page-frame').locator('h1')).toHaveText('Firewall fixture');

  await page.route('**/api/plugins', async (route) => {
    const catalog = JSON.parse(JSON.stringify(pluginCatalog));
    catalog.runtime.remote_install_enabled = true;
    catalog.runtime.exec_enabled = false;
    await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(catalog)});
  });
  await page.evaluate(() => window.VeerApp.loadPlugins());
  await page.locator('[data-tab="plugins"]').click();
  await expect(page.locator('#addPluginBtn')).toBeVisible();
  await page.locator('#addPluginBtn').click();
  await expect(page.locator('#pluginManagerModal')).toBeVisible();
  await expect(page.locator('#pluginManagerBody input[type="file"]')).toBeVisible();

  await page.route('**/api/plugins', async (route) => {
    await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(pluginCatalog)});
  });
  await page.evaluate(() => window.VeerApp.loadPlugins());
  await expect(page.locator('#pluginManagerModal')).toBeHidden();
  await expect(page.locator('#addPluginBtn')).toBeHidden();
});

async function installDashboardFixtures(page, locale) {
  const errors = [];
  browserErrors.set(page, errors);
  page.on('pageerror', (error) => errors.push('pageerror: ' + error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push('console: ' + message.text());
  });

  await page.addInitScript((selectedLocale) => {
    if (window !== window.top) return;
    localStorage.setItem('veer_token', 'e2e-token');
    localStorage.setItem('veer_locale', selectedLocale);
    localStorage.setItem('veer_theme', 'light');
  }, locale);

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === '/api/plugins/nf_counter/assets/index.html') {
      await route.fulfill({ status: 200, contentType: 'text/html; charset=utf-8', body: pluginPageHTML });
      return;
    }
    if (route.request().method() === 'GET' && apiFixtures.has(url.pathname)) {
      await route.fulfill({ status: 200, contentType: 'application/json; charset=utf-8', body: JSON.stringify(apiFixtures.get(url.pathname)) });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'missing E2E fixture: ' + route.request().method() + ' ' + url.pathname })
    });
  });
}

async function openDashboard(page, testInfo) {
  const locale = testInfo.project.name.startsWith('mobile') ? 'en-US' : 'zh-CN';
  await installDashboardFixtures(page, locale);
  await page.goto('/');
  await expect(page.locator('#app')).toBeVisible();
  await expect(page.locator('#masterVersion')).toHaveText('01234567');
}

async function expectNoPageOverflow(page) {
  await expect.poll(() => page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  )), { message: 'page-level horizontal overflow' }).toBeLessThanOrEqual(1);
}

test.afterEach(async ({ page }) => {
  expect(browserErrors.get(page) || [], 'browser console and page errors').toEqual([]);
});

test('dashboard shell localizes cleanly and plugin details stay usable', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugins"]').click();
  await expect(page.locator('#pluginsBody tr')).toHaveCount(3);

  const unresolved = await page.evaluate(() => {
    const values = [];
    document.querySelectorAll('[data-i18n]').forEach((node) => {
      const key = node.getAttribute('data-i18n') || '';
      if (node.textContent.trim() === key) values.push(key);
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
      const key = node.getAttribute('data-i18n-placeholder') || '';
      if (node.getAttribute('placeholder') === key) values.push(key);
    });
    return values;
  });
  expect(unresolved).toEqual([]);
  const renderedTranslationKeys = await page.evaluate(() => {
    const locale = window.VeerApp.state.locale;
    const dictionary = window.VeerApp.translations[locale] || {};
    const text = document.body.innerText || '';
    return Object.keys(dictionary).filter((key) => text.includes(key));
  });
  expect(renderedTranslationKeys).toEqual([]);
  await expectNoPageOverflow(page);

  const trigger = page.locator('.plugin-detail-trigger[data-plugin-id="nf_counter"]');
  await trigger.scrollIntoViewIfNeeded();
  await trigger.click();
  const popover = page.locator('#pluginRuntimeTooltip');
  await expect(popover).toBeVisible();
  const overlap = await page.evaluate(() => {
    const triggerBox = document.querySelector('.plugin-detail-trigger[data-plugin-id="nf_counter"]').getBoundingClientRect();
    const popoverBox = document.getElementById('pluginRuntimeTooltip').getBoundingClientRect();
    return {
      overlaps: triggerBox.left < popoverBox.right && triggerBox.right > popoverBox.left && triggerBox.top < popoverBox.bottom && triggerBox.bottom > popoverBox.top,
      popover: { left: popoverBox.left, top: popoverBox.top, right: popoverBox.right, bottom: popoverBox.bottom },
      viewport: { width: window.innerWidth, height: window.innerHeight }
    };
  });
  expect(overlap.overlaps).toBe(false);
  expect(overlap.popover.left).toBeGreaterThanOrEqual(0);
  expect(overlap.popover.top).toBeGreaterThanOrEqual(0);
  expect(overlap.popover.right).toBeLessThanOrEqual(overlap.viewport.width);
  expect(overlap.popover.bottom).toBeLessThanOrEqual(overlap.viewport.height);

  const paused = await page.evaluate(() => window.VeerApp.runAutoRefresh() === null);
  expect(paused).toBe(true);
  await expect(popover).toBeVisible();

  await popover.locator('.plugin-detail-close').last().click();
  const resumed = await page.evaluate(async () => {
    const refresh = window.VeerApp.runAutoRefresh();
    if (!refresh) return false;
    await refresh;
    return true;
  });
  expect(resumed).toBe(true);
});

test('manual dashboard refresh reports successful completion', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  const refreshButton = page.locator('#refreshNowBtn');
  await expect(refreshButton).toBeEnabled();
  await refreshButton.click();

  const message = await page.evaluate(() => window.VeerApp.t('toast.refreshed', {
    item: window.VeerApp.t('overview.title')
  }));
  await expect(page.locator('#toastStack')).toContainText(message);
  await expect(refreshButton).toBeEnabled();
});

test('background load failures stay visible and recover outside the active tab', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.route('**/api/rules', async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'fixture sync failure' })
    });
  });

  await page.evaluate(() => window.VeerApp.loadRules());
  const syncLabel = page.locator('#lastSyncLabel');
  await expect(syncLabel).toHaveClass(/is-error/);
  await expect(syncLabel).toBeEnabled();
  await expect(syncLabel).toHaveAttribute('title', '');
  await expect(page.locator('#toastStack')).toContainText('fixture sync failure');

  await syncLabel.click();
  const syncPopover = page.locator('#overviewSyncPopover');
  await expect(syncPopover).toBeVisible();
  await expect(syncPopover).toContainText('/api/rules');
  await expect(syncPopover).toContainText('fixture sync failure');
  const placement = await page.evaluate(() => {
    const trigger = document.getElementById('lastSyncLabel').getBoundingClientRect();
    const popover = document.getElementById('overviewSyncPopover').getBoundingClientRect();
    return {
      overlaps: trigger.left < popover.right && trigger.right > popover.left && trigger.top < popover.bottom && trigger.bottom > popover.top,
      left: popover.left,
      top: popover.top,
      right: popover.right,
      bottom: popover.bottom,
      width: window.innerWidth,
      height: window.innerHeight
    };
  });
  expect(placement.overlaps).toBe(false);
  expect(placement.left).toBeGreaterThanOrEqual(0);
  expect(placement.top).toBeGreaterThanOrEqual(0);
  expect(placement.right).toBeLessThanOrEqual(placement.width);
  expect(placement.bottom).toBeLessThanOrEqual(placement.height);
  await syncPopover.locator('.overview-sync-popover-header button').click();
  await expect(syncPopover).toBeHidden();

  await page.locator('[data-tab="sites"]').click();
  await page.unroute('**/api/rules');
  await page.evaluate(async () => {
    const app = window.VeerApp;
    Object.values(app.state.requestFailures).forEach((failure) => {
      failure.at = Date.now() - 5000;
    });
    await app.runAutoRefresh();
  });
  await expect(syncLabel).not.toHaveClass(/is-error/);
  await expect(syncLabel).toHaveAttribute('title', '');

  browserErrors.set(page, []);
});

test('sync failure details support an immediate retry', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.evaluate(() => window.VeerApp.stopPolling());
  let requestCount = 0;
  let markRetryStarted;
  let releaseRetry;
  const retryStarted = new Promise((resolve) => { markRetryStarted = resolve; });
  await page.route('**/api/rules', async (route) => {
    requestCount += 1;
    if (requestCount > 1) {
      markRetryStarted();
      await new Promise((resolve) => { releaseRetry = resolve; });
      await route.fulfill({
        status: 200,
        contentType: 'application/json; charset=utf-8',
        body: JSON.stringify([])
      });
      return;
    }
    await route.fulfill({
      status: 503,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'retry fixture failure' })
    });
  });

  await page.evaluate(() => window.VeerApp.loadRules());
  const syncLabel = page.locator('#lastSyncLabel');
  await syncLabel.click();
  const syncPopover = page.locator('#overviewSyncPopover');
  await expect(syncPopover).toBeVisible();

  await syncPopover.locator('.overview-sync-popover-actions button').click();
  await retryStarted;
  const retryButton = syncPopover.locator('.overview-sync-popover-actions button');
  await expect(syncPopover).toBeVisible();
  await expect(retryButton).toBeDisabled();
  await expect(retryButton).toHaveClass(/is-busy/);
  releaseRetry();
  await expect(syncPopover).toBeHidden();
  await expect(syncLabel).not.toHaveClass(/is-error/);
  const recoveredText = await page.evaluate(() => window.VeerApp.t('overview.syncRestored'));
  await expect(page.locator('#toastStack')).toContainText(recoveredText);
  await expectNoPageOverflow(page);
  await page.unroute('**/api/rules');

  browserErrors.set(page, []);
});

test('non-replayable plugin failures show guidance without a retry action', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  const resourcePath = '/api/plugins/example/resources/config/default';
  await page.route('**' + resourcePath, async (route) => {
    await route.fulfill({
      status: 503,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({ error: 'plugin resource unavailable' })
    });
  });

  await page.evaluate(async (path) => {
    try {
      await window.VeerApp.apiCall('GET', path);
    } catch (_) {}
  }, resourcePath);

  await page.locator('#lastSyncLabel').click();
  const syncPopover = page.locator('#overviewSyncPopover');
  await expect(syncPopover).toBeVisible();
  await expect(syncPopover).toContainText('plugin resource unavailable');
  await expect(syncPopover.locator('.overview-sync-popover-actions')).toHaveCount(0);
  const manualHint = await page.evaluate(() => window.VeerApp.t('overview.syncFailuresManualHint'));
  await expect(syncPopover).toContainText(manualHint);
  await syncPopover.locator('.overview-sync-popover-header button').click();
  await page.unroute('**' + resourcePath);

  browserErrors.set(page, []);
});

test('in-flight polling waits for an opened floating layer before applying data', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugins"]').click();
  await page.evaluate(() => window.VeerApp.stopPolling());
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight === null)).toBe(true);

  let releaseResponse;
  let markRequestStarted;
  const requestStarted = new Promise((resolve) => { markRequestStarted = resolve; });
  await page.route('**/api/plugins', async (route) => {
    markRequestStarted();
    await new Promise((resolve) => { releaseResponse = resolve; });
    await route.fulfill({
      status: 200,
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify(pluginCatalog)
    });
  });

  await page.evaluate(() => {
    window.__inflightPoll = window.VeerApp.runAutoRefresh();
  });
  await requestStarted;

  const trigger = page.locator('.plugin-detail-trigger[data-plugin-id="nf_counter"]');
  await trigger.click();
  const popover = page.locator('#pluginRuntimeTooltip');
  await expect(popover).toBeVisible();

  releaseResponse();
  await page.waitForTimeout(250);
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight !== null)).toBe(true);
  await page.evaluate(() => window.dispatchEvent(new Event('resize')));
  await expect(popover).toBeVisible();
  await expect(trigger).toHaveAttribute('aria-expanded', 'true');

  await popover.locator('.plugin-detail-close').last().click();
  await expect(popover).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.VeerApp.state.pollRefreshInFlight === null)).toBe(true);
  await page.unroute('**/api/plugins');
});

test('plugin page renders Netfilter placement and resizes in both directions', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugin-firewall"]').click();

  const panel = page.locator('#tab-plugin-firewall');
  await expect(panel).toBeVisible();
  await expect(panel.locator('.plugin-link-card')).toBeVisible();
  await expect(panel.locator('.plugin-link-row')).toContainText('host / ipv4 / forward / filter');
  await expect(panel.locator('.plugin-link-step')).toHaveCount(2);
  await expect(panel.locator('.plugin-link-path')).toContainText('nf_dropper');
  await expect(panel.locator('.plugin-link-path')).toContainText('nf_counter');
  await expectNoPageOverflow(page);

  const frame = panel.locator('.plugin-page-frame');
  const frameBody = page.frameLocator('#tab-plugin-firewall .plugin-page-frame');
  await expect(frameBody.locator('#shrink')).toBeVisible();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeGreaterThan(450);
  const expandedHeight = (await frame.boundingBox()).height;

  await frameBody.locator('#shrink').click();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeLessThan(300);
  const compactHeight = (await frame.boundingBox()).height;
  expect(compactHeight).toBeLessThan(expandedHeight);

  await frameBody.locator('#grow').click();
  await expect.poll(async () => (await frame.boundingBox()).height).toBeGreaterThan(450);
});

test('plugin page confirmation uses the parent overlay and returns the result', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.locator('[data-tab="plugin-firewall"]').click();

  const frame = page.frameLocator('#tab-plugin-firewall .plugin-page-frame');
  await frame.locator('#confirm').click();
  const confirm = page.locator('#confirmModal');
  await expect(confirm).toBeVisible();
  await expect(page.locator('#confirmTitle')).toHaveText('Plugin confirmation');
  await expect(page.locator('#confirmMessage')).toHaveText('Confirm from sandbox');
  await expect(page.locator('#confirmSubmitBtn')).toHaveClass(/is-danger/);

  await page.locator('#confirmCancelBtn').click();
  await expect(confirm).toBeHidden();
  await expect.poll(() => frame.locator('body').evaluate(() => window.fixtureConfirmResult)).toBe(false);
});

test('confirmation dialog stays above plugin management', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.evaluate(() => {
    const manager = document.getElementById('pluginManagerModal');
    manager.classList.add('active');
    manager.setAttribute('aria-hidden', 'false');
    window.VeerApp.confirmAction({ title: 'Confirm fixture', message: 'Layer check', confirmText: 'Confirm', cancelText: 'Cancel' });
  });

  const manager = page.locator('#pluginManagerModal');
  const confirm = page.locator('#confirmModal');
  await expect(manager).toBeVisible();
  await expect(confirm).toBeVisible();
  const layers = await page.evaluate(() => ({
    manager: Number.parseInt(getComputedStyle(document.getElementById('pluginManagerModal')).zIndex, 10),
    confirm: Number.parseInt(getComputedStyle(document.getElementById('confirmModal')).zIndex, 10)
  }));
  expect(layers.confirm).toBeGreaterThan(layers.manager);
  await page.locator('#confirmCancelBtn').click();
  await expect(confirm).toBeHidden();
});
