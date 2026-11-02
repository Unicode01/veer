const { expect, test } = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const vpnShares = require('../../../plugins/vpn_core/ui/share');
const { contrastIssues, brightDarkSurfaces } = require('./contrast.cjs');

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
    var hostAction = window.VeerPluginHost.button('Fixture action', function () {
      window.fixtureHeaderClicks = (window.fixtureHeaderClicks || 0) + 1;
      window.VeerPluginHost.notify('Header action completed');
    });
    hostAction.id = 'fixtureHeaderAction';
    document.body.appendChild(hostAction);
    window.VeerPluginHost.headerActions([hostAction]);
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
  ['/api/host-network', { interfaces: [], host: { name: 'pve-node-03', os: 'linux', arch: 'amd64', kernel_release: '6.8.12-pve', uptime_seconds: 3564000 } }],
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
    actions:['set_key','set_core_config','core_form','apply','teardown','delete_profile','inspect','core_logs',...coreActions,...healthActions].map(id => ({id})),
    ui:{entry:'index.html', page:'vpn', page_title:'VPN', resources:[{resource:'profiles', methods}, {resource:'status', methods:['list']}],
      actions:['set_key','set_core_config','core_form','apply','teardown','delete_profile','inspect','core_logs',...coreActions,...healthActions]}, asset_base_path:'/api/plugins/vpn_core/assets/', runtime:{mode:'control'}};
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
      if(id==='delete_profile') {actions.push({id,payload});delete records[payload.key];delete healthValues[payload.key];return route.fulfill({json:{result:{phase:'deleted'}}});}
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
  await navigatePage(page, 'plugin-vpn');
  const frame = page.frameLocator('#tab-plugin-vpn .plugin-page-frame');
  await expect(page.locator('#tab-plugin-vpn h1')).toHaveText('VPN');
  await expect(frame.locator('h1')).toHaveCount(0);
  await expect(frame.locator('.vpn-outlet')).toHaveCount(1);
  await page.evaluate(() => window.VeerApp.setTheme('dark'));
  await expect(frame.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(frame.locator('.vpn-health')).toHaveCount(0);
  await expect(frame.getByLabel('检测地址',{exact:true})).toHaveCount(0);
  await frame.getByRole('button',{name:'健康检测',exact:true}).click();
  await expect.poll(()=>healthRequests.length).toBe(1);
  expect(healthRequests[0]).toEqual({id:'health_check',payload:{key:'saved'}});
  expect(actions).toHaveLength(0);
  await expect(frame.locator('.vpn-outlet')).toContainText('检测中');
  await expect(frame.locator('.vpn-outlet')).toContainText('链路可用');
  await expect(frame.locator('.vpn-outlet')).toContainText('37 ms');
  healthFailure=true;
  await frame.getByRole('button',{name:'健康检测',exact:true}).click();
  await expect(frame.locator('.vpn-outlet')).toContainText('链路异常');
  await expect(frame.locator('.vpn-outlet')).toContainText('检测超时');
  await expectNoPageOverflow(page);
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-health.png'),fullPage:true});
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
  await expect(frame.getByLabel('出站 IP',{exact:true})).toHaveCount(0);
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
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-cores.png'), fullPage:true});
  await frame.getByRole('tab',{name:/^出口/}).click();
  await frame.getByRole('button',{name:'收起编辑',exact:true}).click();
  await expect.poll(() => page.locator('#tab-plugin-vpn iframe').evaluate(el => el.getBoundingClientRect().height)).toBeLessThan(850);
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-outlets.png'), fullPage:true});
  await page.locator('#tab-plugin-vpn .plugin-header-actions').getByRole('button',{name:'新建出口',exact:true}).click();
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
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-wireguard-form.png'),fullPage:true});
  await frame.getByRole('button',{name:'sing-box',exact:true}).click();
  await expect(frame.getByLabel('本机 WireGuard 地址',{exact:true})).toHaveCount(0);
  await expect(frame.getByLabel('内部 WAN 地址',{exact:true})).toBeHidden();
  await expect(frame.getByLabel('Mihomo 配置（JSON）',{exact:true})).toHaveCount(0);
  await frame.getByLabel('实际出站接口',{exact:true}).fill('ppp0');
  await expect(frame.getByLabel('出站 IP',{exact:true})).toHaveValue('');
  const interfaceBox=await frame.getByLabel('实际出站接口',{exact:true}).boundingBox(), ipBox=await frame.getByLabel('出站 IP',{exact:true}).boundingBox();
  if(testInfo.project.name.startsWith('desktop')) expect(Math.abs(interfaceBox.y-ipBox.y)).toBeLessThan(2);
  await frame.getByLabel('出站 IP',{exact:true}).fill('192.0.2.9/24');
  await frame.getByRole('button',{name:'保存草稿',exact:true}).click();
  await expect(frame.locator('.vpn-notice')).toContainText('出站 IP');
  await frame.getByLabel('出站 IP',{exact:true}).fill('192.0.2.9');
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
  expect(records.vpn1.data.upstream_ip).toBe('192.0.2.9');
  expect(records.vpn1.data.config_secret).toBe('core_sing_box_vpn1');
  expect(actions.at(-1).payload.format).toBe('links');expect(actions.at(-1).payload.selected).toBe(1);
  expect(actions.at(-1).payload.options.direct_cidrs).toEqual(['10.0.0.0/8']);
  expect(actions.at(-1).payload.options.dns_hijack).toBe(true);
  await expect(frame.getByLabel('节点分享链接或 Base64')).toHaveValue('');
  await expect(frame.locator('body')).not.toContainText('share-secret');
  await expect(frame.locator('body')).not.toContainText('second-secret');
  expect(JSON.stringify(records.vpn1)).not.toContain('secret@');
  for(const field of ['addresses','peers','listen_port','remote_routes']) expect(records.vpn1.data[field]).toBeUndefined();
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-sing-box-form.png'),fullPage:true});
  await frame.getByRole('button',{name:'收起编辑',exact:true}).click();
  await frame.locator('.vpn-outlet').filter({has:frame.getByRole('heading',{name:'vpn1',exact:true})}).getByRole('button',{name:'编辑',exact:true}).click();
  await expect(frame.getByLabel('使用节点')).toHaveValue('1');
  await expect(frame.getByLabel('出站 IP',{exact:true})).toHaveValue('192.0.2.9');
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
  for(const field of ['addresses','upstream_interface','upstream_ip','config_secret','peers']) expect(records.vpn1.data[field]).toBeUndefined();
  await expect(frame.getByLabel('出站 IP',{exact:true})).toHaveCount(0);
  await expectNoPageOverflow(page);
  await expectReadableThemes(page, frame.locator('body'));
  await page.screenshot({path:testInfo.outputPath('vpn-external-tun-form.png'),fullPage:true});
  const card=frame.locator('.vpn-outlet').filter({has:frame.getByRole('heading',{name:'vpn1',exact:true})});
  await card.getByRole('button',{name:'删除',exact:true}).click();
  await expect(page.locator('#confirmMessage')).toContainText('共用的核心程序会保留');
  await page.locator('#confirmCancelBtn').click();
  expect(records.vpn1).toBeDefined();
  await card.getByRole('button',{name:'删除',exact:true}).click();
  await page.locator('#confirmSubmitBtn').click();
  await expect.poll(()=>records.vpn1).toBeUndefined();
  await expect(card).toHaveCount(0);await expect(frame.locator('.vpn-editor')).toBeHidden();
  expect(actions.at(-1)).toEqual({id:'delete_profile',payload:{key:'vpn1'}});
});


test('plugin installation controls follow the host policy while plugin pages remain accessible', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await navigatePage(page, 'plugins');
  await expect(page.locator('#addPluginBtn')).toBeHidden();
  await expect(page.locator('#managePluginsAdvancedBtn')).toBeVisible();
  await page.locator('#managePluginsAdvancedBtn').click();
  await expect(page.locator('#pluginManagerNav')).not.toContainText(/Add Plugin|添加插件/);
  await expect(page.locator('#pluginManagerBody')).not.toContainText(/Publishers|发布者/);
  await page.locator('#closePluginManagerBtn').click();
  await navigatePage(page, 'plugin-firewall');
  await expect(page.frameLocator('#tab-plugin-firewall .plugin-page-frame').locator('h1')).toHaveText('Firewall fixture');

  await page.route('**/api/plugins', async (route) => {
    const catalog = JSON.parse(JSON.stringify(pluginCatalog));
    catalog.runtime.remote_install_enabled = true;
    catalog.runtime.exec_enabled = false;
    await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(catalog)});
  });
  await page.evaluate(() => window.VeerApp.loadPlugins());
  await navigatePage(page, 'plugins');
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
  await page.emulateMedia({ reducedMotion: 'reduce' });
  const locale = testInfo.project.name.startsWith('mobile') ? 'en-US' : 'zh-CN';
  await installDashboardFixtures(page, locale);
  await page.goto('/');
  await expect(page.locator('#app')).toBeVisible();
  await expect(page.locator('#masterVersion')).toHaveText('01234567');
  await page.evaluate(() => document.fonts.ready);
}

async function expectReadableThemes(page, scope) {
  for (const theme of ['light', 'dark']) {
    await page.evaluate((theme) => window.VeerApp.setTheme(theme), theme);
    await expect.poll(() => scope.evaluate(() => document.documentElement.dataset.theme)).toBe(theme);
    expect(await contrastIssues(scope), theme).toEqual([]);
    if (theme === 'dark') expect(await brightDarkSurfaces(scope)).toEqual([]);
  }
}

async function expectNoPageOverflow(page) {
  const overflow = await page.evaluate(() => Array.from(document.querySelectorAll('body *')).filter((el) => {
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.left >= 0 && box.right > window.innerWidth + 1;
  }).slice(0, 15).map((el) => ({ element: el.tagName + '#' + el.id + '.' + el.className, width: el.getBoundingClientRect().width, right: el.getBoundingClientRect().right, minWidth: getComputedStyle(el).minWidth, display: getComputedStyle(el).display })));
  if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1)) console.log('Overflow elements:', overflow);
  await expect.poll(() => page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  )), { message: 'page-level horizontal overflow' }).toBeLessThanOrEqual(1);
}

async function navigatePage(page, tab) {
  if (page.viewportSize().width < 860) await page.locator('#sidebarToggle').click();
  await page.locator('[data-tab="' + tab + '"]').click();
}

test('Patchbay resource lists, drawers, filtering and hash navigation work without losing edits', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  const rules = [
    { id: 1, remark: 'web-production', in_interface: 'eth0', in_ip: '203.0.113.10', in_port: 443, out_interface: 'br0', out_ip: '10.0.0.12', out_port: 8443, protocol: 'tcp', enabled: true, status: 'running' },
    { id: 2, remark: 'ipv6-monitoring', in_interface: 'eth0', in_ip: '2001:db8:1234:abcd:1111:2222:3333:4444', in_port: 19999, out_interface: 'br0', out_ip: '2001:db8:ffff:abcd:aaaa:bbbb:cccc:dddd', out_port: 19999, protocol: 'tcp', enabled: false, status: 'stopped' },
    { id: 3, remark: 'mail-service', in_interface: 'eth0', in_ip: '203.0.113.10', in_port: 587, out_interface: 'br0', out_ip: '10.0.0.25', out_port: 587, protocol: 'tcp', enabled: true, status: 'error', runtime_error: 'Port 587 is already in use' }
  ];
  const writes = [];
  await page.route('**/api/interfaces', (route) => route.fulfill({ json: [{ name: 'eth0', addrs: ['203.0.113.10'] }, { name: 'br0', addrs: ['10.0.0.1'] }] }));
  await page.route('**/api/rules/validate', (route) => route.fulfill({ json: { valid: true, ...route.request().postDataJSON() } }));
  await page.route('**/api/rules', (route) => {
    if (route.request().method() === 'PUT') {
      const payload = route.request().postDataJSON();
      writes.push(payload);
      Object.assign(rules.find((rule) => rule.id === payload.id), payload);
      return route.fulfill({ json: payload });
    }
    return route.fulfill({ json: rules });
  });
  await page.evaluate(async () => { await window.VeerApp.loadInterfaces(); await window.VeerApp.loadRules(); window.VeerApp.stopPolling(); });
  await expect(page.locator('#rulesBody tr')).toHaveCount(3);
  await expect(page.locator('#ruleForm')).toBeHidden();
  await expect(page.locator('#rulesBody .patch-route')).toHaveCount(3);
  await expect(page.locator('#rulesBody')).toContainText('Port 587 is already in use');
  await expectNoPageOverflow(page);
  await page.screenshot({ path: testInfo.outputPath('patchbay-list-light.png'), fullPage: true });
  await page.evaluate(() => window.VeerApp.setTheme('dark'));
  expect(await contrastIssues(page.locator('body'))).toEqual([]);
  await page.screenshot({ path: testInfo.outputPath('patchbay-list-dark.png'), fullPage: true });
  await page.locator('#rulesBody .action-dropdown-trigger').first().click();
  expect(await contrastIssues(page.locator('body'))).toEqual([]);
  await page.keyboard.press('Escape');
  await page.locator('#tab-rules .status-chip').last().click();
  await expect(page.locator('#rulesBody tr')).toHaveCount(1);
  await expect(page.locator('#rulesBody')).toContainText('ipv6-monitoring');
  await page.locator('#tab-rules .status-chip').first().click();
  await page.locator('#rulesBody tr').first().locator('.quick-edit').click();
  await expect(page.locator('#resourceDrawer')).toBeVisible();
  await expect(page.locator('#ruleRemark')).toHaveValue('web-production');
  await expect(page.locator('#mainContent')).toHaveAttribute('inert', '');
  await page.locator('#ruleRemark').fill('web-updated');
  await page.keyboard.press('Escape');
  await expect(page.locator('#confirmModal')).toBeVisible();
  await page.locator('#confirmCancelBtn').click();
  await expect(page.locator('#ruleRemark')).toHaveValue('web-updated');
  await page.screenshot({ path: testInfo.outputPath('patchbay-edit-drawer.png'), fullPage: true });
  await page.locator('#ruleSubmitBtn').click();
  await expect(page.locator('#resourceDrawer')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({ id: 1, remark: 'web-updated', in_port: 443, out_port: 8443 });
  await expect(page.locator('#rulesBody')).toContainText('web-updated');
  await navigatePage(page, 'sites');
  await expect(page).toHaveURL(/#sites$/);
  await page.goBack();
  await expect(page.locator('#tab-rules')).toBeVisible();
  await page.keyboard.press('Control+k');
  await page.locator('#commandSearch').fill('web-updated');
  await expect(page.locator('#commandResults [role="option"]')).toHaveCount(1);
  await page.keyboard.press('Enter');
  await expect(page.locator('#ruleRemark')).toHaveValue('web-updated');
  await page.locator('#closeResourceDrawer').click();
  await expect(page.locator('#resourceDrawer')).toBeHidden();
  expect(writes).toHaveLength(1);
  await expectNoPageOverflow(page);
});

test.afterEach(async ({ page }) => {
  expect(browserErrors.get(page) || [], 'browser console and page errors').toEqual([]);
});

test('Patchbay preserves every resource editor and isolates network leases and devices', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.evaluate(() => {
    const app = window.VeerApp;
    app.stopPolling();
    app.hostSummary = { name: 'router-lab', os: 'linux', arch: 'amd64', kernel_release: '6.8-test', uptime_seconds: 90000 };
    app.state.sites.data = [{ id: 11, domain: 'example.test', listen_ip: '203.0.113.10', backend_ip: '10.0.0.2', backend_http_port: 0, backend_https_port: 8443, enabled: true }];
    app.state.ranges.data = [{ id: 12, in_ip: '203.0.113.10', start_port: 8000, end_port: 8010, out_ip: '10.0.0.2', out_start_port: 9000, protocol: 'udp', enabled: true }];
    app.state.managedNetworks.data = [{ id: 13, name: 'lan-one', bridge: 'br0', bridge_mode: 'existing', ipv4_cidr: '10.0.0.1/24', enabled: true }, { id: 14, name: 'lan-two', bridge: 'br1', bridge_mode: 'existing', ipv4_cidr: '10.1.0.1/24', enabled: true }];
    app.state.egressNATs.data = [{ id: 15, parent_interface: 'br0', child_interface: 'tap100', out_interface: 'eth0', out_source_ip: '203.0.113.10', enabled: true }];
    app.state.ipv6Assignments.data = [{ id: 16, parent_interface: 'eth0', target_interface: 'br0', parent_prefix: '2001:db8::/48', assigned_prefix: '2001:db8:0:1::/64', enabled: true }];
    app.state.managedNetworkReservations.data = [{ id: 21, managed_network_id: 13, mac_address: '02:00:00:00:00:01', ipv4_address: '10.0.0.11', remark: 'only-first-network' }, { id: 22, managed_network_id: 14, mac_address: '02:00:00:00:00:02', ipv4_address: '10.1.0.12', remark: 'only-second-network' }];
    app.state.managedNetworkReservationCandidates.data = [{ managed_network_id: 13, child_interface: 'tap100', mac_address: '02:00:00:00:00:03', suggested_ipv4: '10.0.0.13', status: 'ready' }, { managed_network_id: 14, child_interface: 'tap200', mac_address: '02:00:00:00:00:04', suggested_ipv4: '10.1.0.14', status: 'ready' }];
    app.patchbay.configs.forEach((cfg) => app[cfg.render]());
    app.refreshManagedNetworkReservationNetworkOptions();
  });
  const snapshots = await page.evaluate(() => {
    const app = window.VeerApp;
    return Object.fromEntries([['sites','sites'], ['ranges','ranges'], ['managed-networks','managedNetworks'], ['egress-nats','egressNATs'], ['ipv6-assignments','ipv6Assignments'], ['managed-network-reservations','managedNetworkReservations'], ['managed-network-reservation-candidates','managedNetworkReservationCandidates']].map(([endpoint, state]) => [endpoint, app.state[state].data]));
  });
  for (const [endpoint, data] of Object.entries(snapshots)) await page.route('**/api/' + endpoint, (route) => route.fulfill({ json: data }));
  for (const [tab, form] of [['sites','site'], ['ranges','range'], ['managed-networks','managedNetwork'], ['egress-nats','egressNAT'], ['ipv6-assignments','ipv6Assignment']]) {
    await navigatePage(page, tab);
    await page.locator('#tab-' + tab + ' .quick-edit').first().click();
    await expect(page.locator('#' + form + 'Form')).toBeVisible();
    await expect(page.locator('#' + form + 'SubmitBtn')).toBeVisible();
    for (const theme of ['light', 'dark']) {
      await page.evaluate((theme) => window.VeerApp.setTheme(theme), theme);
      expect(await contrastIssues(page.locator('#resourceDrawer')), form + ' ' + theme).toEqual([]);
      if (theme === 'dark') expect(await brightDarkSurfaces(page.locator('#resourceDrawer'))).toEqual([]);
    }
    if (tab === 'sites') {
      await expect(page.locator('#siteBackendHTTP')).toHaveValue('0');
      await expect(page.locator('#siteBackendHTTP').locator('xpath=ancestor::fieldset')).toBeVisible();
      await expect(page.locator('#resourceDrawer .drawer-preview:visible')).toContainText('8443');
      await expect(page.locator('#resourceDrawer .drawer-preview:visible')).not.toContainText('80 / 8443');
    }
    await expectNoPageOverflow(page);
    await page.locator('#closeResourceDrawer').click();
    await expect(page.locator('#resourceDrawer')).toBeHidden();
  }
  await navigatePage(page, 'managed-networks');
  await page.getByRole('button', { name: 'lan-one', exact: true }).click();
  await page.locator('#networkDetail-tab-leases').click();
  await expect(page.locator('#managedNetworkReservationsBody')).toContainText('only-first-network');
  await expect(page.locator('#managedNetworkReservationsBody')).not.toContainText('only-second-network');
  await page.locator('#addNetworkReservationBtn').click();
  await expect(page.locator('#managedNetworkReservationManagedNetworkId')).toHaveValue('13');
  await page.locator('#closeResourceDrawer').click();
  await page.locator('#networkDetail-tab-devices').click();
  await expect(page.locator('#managedNetworkReservationCandidatesBody')).toContainText('tap100');
  await expect(page.locator('#managedNetworkReservationCandidatesBody')).not.toContainText('tap200');
  await page.screenshot({ path: testInfo.outputPath('network-detail.png'), fullPage: true });
  await expectNoPageOverflow(page);
});

test('bundled plugin pages share host actions and themes at desktop and 375px', async ({ page }, testInfo) => {
  const vm = require('node:vm');
  const plugins = ['router_wizard', 'wan_core', 'lan_core', 'pppoe_client', 'vtolocal', 'packet_observer'].map((id) => {
    const root = path.resolve(__dirname, '../../../plugins', id);
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'plugin.json'), 'utf8'));
    const source = fs.readFileSync(path.join(root, 'control.js'), 'utf8');
    const ui = vm.runInNewContext('(' + source.match(/ui\.register\((\{[\s\S]*?\})\);/)[1] + ')', { crypto: { sha256File: () => '' } });
    return { ...manifest, status: 'active', enabled: true, ui, resources: ui.resources.map((entry) => ({ id: entry.resource, methods: entry.methods })), actions: ui.actions.map((id) => ({ id })), control: { ...manifest.control, resource_access: ui.resource_access }, asset_base_path: '/api/plugins/' + id + '/assets/', runtime: { mode: 'control' } };
  });
  await openDashboard(page, testInfo);
  await page.route('**/api/plugins', (route) => route.fulfill({ json: { ...pluginCatalog, plugins } }));
  await page.route('**/api/plugins/*/**', (route) => {
    const url = new URL(route.request().url());
    const parts = url.pathname.split('/');
    if (parts[4] === 'assets') {
      const file = path.resolve(__dirname, '../../../plugins', parts[3], 'ui', ...parts.slice(5));
      return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html; charset=utf-8', body: fs.readFileSync(file, 'utf8') });
    }
    return route.fulfill({ json: parts.length > 6 ? { key: parts[6], data: {}, enabled: true } : { records: [], result: {}, status: 'completed' } });
  });
  await page.evaluate(async () => { await window.VeerApp.loadPlugins(); window.VeerApp.stopPolling(); });
  for (const plugin of plugins) {
    const tab = 'plugin-' + plugin.ui.page;
    await navigatePage(page, tab);
    const panel = page.locator('#tab-' + tab);
    const iframe = page.frameLocator('#tab-' + tab + ' iframe');
    await expect(iframe.locator('main')).toBeVisible();
    await expect(iframe.locator('h1')).toHaveCount(0);
    await expect(panel.locator('.plugin-header-actions .primary-button')).toHaveCount(1);
    await expect.poll(() => iframe.locator('body').evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1);
    await expectNoPageOverflow(page);
    for (const theme of ['dark', 'light']) {
      await page.evaluate((theme) => window.VeerApp.setTheme(theme), theme);
      await expect(iframe.locator('html')).toHaveAttribute('data-theme', theme);
      expect(await contrastIssues(iframe.locator('body')), plugin.id + ' ' + theme).toEqual([]);
      if (theme === 'dark') expect(await brightDarkSurfaces(iframe.locator('body')), plugin.id).toEqual([]);
      await page.screenshot({ path: testInfo.outputPath(plugin.id + '-' + theme + '.png'), fullPage: true });
    }
  }
  await page.setViewportSize({ width: page.viewportSize().width, height: 430 });
  if (page.viewportSize().width < 860) await page.locator('#sidebarToggle').click();
  await expect(page.locator('#themeMenuButton')).toBeInViewport();
  await expect(page.locator('#logoutBtn')).toBeInViewport();
  await expect(page.locator('.sidebar-brand')).toBeInViewport();
  expect(await page.locator('.sidebar nav').evaluate((nav) => nav.scrollHeight > nav.clientHeight)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('sidebar-short.png'), fullPage: true });
});

test('sidebar tools preserve theme, language and logout behavior with keyboard and system changes', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await page.emulateMedia({ reducedMotion: 'no-preference', colorScheme: 'light' });
  if (page.viewportSize().width < 860) {
    await expect(page.locator('#mainSidebar')).toHaveAttribute('inert', '');
    await page.locator('#sidebarToggle').click();
    await expect(page.locator('#mainSidebar')).not.toHaveAttribute('inert', '');
  }
  const theme = page.locator('#themeMenuButton');
  await theme.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('#themeMenu')).toBeVisible();
  await page.keyboard.press('End');
  await page.keyboard.press('Enter');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await expect(theme).toBeFocused();
  expect(await page.evaluate(() => localStorage.getItem('veer_theme'))).toBe('dark');
  expect(await contrastIssues(page.locator('body'))).toEqual([]);
  expect(await brightDarkSurfaces(page.locator('body'))).toEqual([]);
  await theme.click();
  await page.screenshot({ path: testInfo.outputPath('sidebar-theme-dark.png'), fullPage: true });
  await page.keyboard.press('Escape');
  await expect(page.locator('#themeMenu')).toBeHidden();
  await expect(theme).toBeFocused();
  await theme.click();
  await page.locator('#hostName').click();
  await expect(page.locator('#themeMenu')).toBeHidden();
  const originalLocale = await page.locator('html').getAttribute('lang');
  await page.locator('#localeToggle').click();
  await expect(page.locator('html')).toHaveAttribute('lang', originalLocale === 'en-US' ? 'zh-CN' : 'en-US');
  await theme.click();
  await page.keyboard.press('Home');
  await page.keyboard.press('Enter');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.emulateMedia({ colorScheme: 'dark' });
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('veer_theme'))).toBe('system');
  await page.locator('#logoutBtn').click();
  await expect(page.locator('#confirmModal')).toBeVisible();
  expect(await contrastIssues(page.locator('#confirmModal'))).toEqual([]);
  await page.locator('#confirmCancelBtn').click();
  await expect(page.locator('#app')).toBeVisible();
  await expect(page.locator('#tokenModal')).toBeHidden();
});

test('dashboard shell localizes cleanly and plugin details stay usable', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await navigatePage(page, 'plugins');
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
  await expectReadableThemes(page, page.locator('body'));
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

  await navigatePage(page, 'sites');
  await page.unroute('**/api/rules');
  await page.evaluate(async () => {
    const app = window.VeerApp;
    Object.values(app.state.requestFailures).forEach((failure) => {
      failure.at = Date.now() - 5000;
    });
    await app.runAutoRefresh();
  });
  await expect(syncLabel).not.toHaveClass(/is-error/);
  await expect(syncLabel).toHaveAttribute('title', /.+/);

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
  await navigatePage(page, 'plugins');
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
  await navigatePage(page, 'plugin-firewall');

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
  await navigatePage(page, 'plugin-firewall');

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

test('plugin header mirrors button state and notifications cannot escape the active page', async ({ page }, testInfo) => {
  await openDashboard(page, testInfo);
  await navigatePage(page, 'plugin-firewall');
  const frame = page.frameLocator('#tab-plugin-firewall iframe');
  const action = page.locator('#tab-plugin-firewall .plugin-header-actions button');
  await expect(action).toHaveText('Fixture action');
  await expect(frame.locator('#fixtureHeaderAction')).toBeHidden();
  await action.click();
  await expect(page.locator('#toastStack')).toContainText('Netfilter Counter: Header action completed');
  await frame.locator('#fixtureHeaderAction').evaluate((button) => { button.disabled = true; button.textContent = 'Busy'; });
  await expect(action).toHaveText('Busy');
  await expect(action).toBeDisabled();
  await frame.locator('#fixtureHeaderAction').evaluate((button) => { button.disabled = false; button.textContent = 'Ready'; });
  await expect(action).toBeEnabled();
  await expect(action).toHaveText('Ready');
  await navigatePage(page, 'rules');
  const accepted = await frame.locator('body').evaluate(() => window.VeerPluginHost.notify('must stay hidden'));
  expect(accepted).toBe(false);
  await expect(page.locator('#toastStack')).not.toContainText('must stay hidden');
  await navigatePage(page, 'plugin-firewall');
  await expect(action).toHaveText('Ready');
  await page.evaluate(() => window.VeerApp.reloadPluginPageForTab('plugin-firewall'));
  await expect(action).toHaveText('Fixture action');
  await action.click();
  expect(await frame.locator('body').evaluate(() => window.fixtureHeaderClicks)).toBe(1);
  await navigatePage(page, 'plugins');
  await page.evaluate(() => {
    const app = window.VeerApp;
    const plugin = app.state.plugins.data.find((item) => item.id === 'nf_counter');
    delete plugin.ui.page;
    return app.openPluginUI('nf_counter');
  });
  const inline = page.frameLocator('#pluginUIFrame');
  await expect(inline.locator('h1')).toHaveText('Firewall fixture');
  expect(await inline.locator('body').evaluate(() => window.VeerPluginHost.notify('inline visible'))).toBe(true);
  await navigatePage(page, 'rules');
  expect(await inline.locator('body').evaluate(() => window.VeerPluginHost.notify('inline hidden'))).toBe(false);
  await expect(page.locator('#toastStack')).not.toContainText('inline hidden');
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
