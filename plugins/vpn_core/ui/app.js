(function () {
  'use strict';
  const F=window.VeerPluginHost, M=window.VPNConfig, S=window.VPNShare, h=F.h;
  let records=[], statuses={}, busy=false, original={}, currentDriver='wireguard', savedDriver='', editing=false;
  let peers=[], dirty=false, rawDirty=false, coreDriver='mihomo', coreSequence=0, corePoll=null, statusPoll=null;
  let storedMode='empty', nodeNames=[];
  const controlNodes=() => document.querySelectorAll('.vpn-page button,.vpn-page input,.vpn-page select,.vpn-page textarea');
  function node(tag, className, text) { return h(tag,{className,text}); }
  function input(label,value,type) {
    const el=h('input',{className:F.classes.input,attrs:{'aria-label':label,value:value == null ? '' : value,type:type || 'text',autocomplete:type==='password'?'new-password':'off'}});
    return el;
  }
  function area(label) { const el=h('textarea',{className:F.classes.input+' vpn-json',attrs:{'aria-label':label,spellcheck:'false'}});return el; }
  function field(label,el,help,wide) { return h('label',{className:F.classes.field+(wide?' vpn-wide':'')},[node('span','',label),el,help?node('span','vpn-field-help',help):null]); }
  function message(text,error) { notice.hidden=!text;notice.textContent=text || '';notice.dataset.tone=error?'error':'';F.requestResize(); }
  async function run(task) {
    if (busy) return;
    busy=true; controlNodes().forEach(el => {el.disabled=true;});
    try { await task(); }
    catch (error) { message(F.errorText(error),true);F.toastError(error); }
    finally { busy=false;controlNodes().forEach(el => {el.disabled=false;});keyInput.readOnly=editing;renderProxyMode();F.requestResize(); }
  }
  function button(text,task,secondary) { const el=F.button(text,() => run(task),secondary);return el; }
  function actions(children) { return h('div',{className:'vpn-actions'},children); }
  const count=node('span','vpn-count','0'), list=h('div',{className:'vpn-list'});
  const notice=h('div',{className:'vpn-notice',attrs:{role:'status','aria-live':'polite',hidden:true}});
  const outletPanel=h('section',{},[list]);
  const corePanel=h('section',{attrs:{hidden:true}});
  const editor=h('section',{className:'vpn-panel vpn-editor',attrs:{hidden:true}});
  const editorTitle=node('h2','','新建出口');
  const keyInput=input('出口标识',''), addressInput=input('本机 WireGuard 地址',''), wanAddressInput=input('内部 WAN 地址',''), slotInput=input('出口位置',1,'number');
  addressInput.placeholder='使用 WireGuard 配置中的 Address';wanAddressInput.placeholder='自动分配，无需填写';
  const mtuInput=input('MTU',1420,'number'), upstream=input('实际出站接口','','text');
  const listenPort=input('监听端口',0,'number'), privateKey=input('WireGuard 私钥','','password');
  const routes=input('远端内网路由',''), tunName=input('TUN 接口',''), tunAlias=input('TUN 归属标记','');
  const coreConfig=area('代理核心 JSON 配置'), rawConfig=area('VPN 出口 JSON'), importConfig=area('WireGuard 配置文件');
  const shareLinks=area('节点分享链接或 Base64'), nodeSelect=h('select',{className:F.classes.input,attrs:{'aria-label':'使用节点'}});
  shareLinks.classList.add('vpn-links');shareLinks.placeholder='ss://…\nvless://…\n或粘贴 Base64 编码的分享内容';
  const configMode=h('select',{className:F.classes.input,attrs:{'aria-label':'核心配置方式'}},[
    h('option',{attrs:{value:'links'},text:'分享链接 · 自动生成配置'}),h('option',{attrs:{value:'native'},text:'原生 JSON · 自行配置'})
  ]);
  const directCIDRs=area('直连网段'), directDomains=area('直连域名'), bootstrapDNS=input('节点解析 DNS','223.5.5.5'), proxyDNS=input('代理 DNS','1.1.1.1');
  directCIDRs.classList.add('vpn-rule-input');directDomains.classList.add('vpn-rule-input');
  directCIDRs.placeholder='192.168.0.0/16\n10.0.0.0/8';directDomains.placeholder='example.com';
  const hijackDNS=h('select',{className:F.classes.input,attrs:{'aria-label':'下游 DNS'}},[
    h('option',{attrs:{value:'off'},text:'沿用下游 DNS'}),h('option',{attrs:{value:'on'},text:'接管 53 端口并通过节点解析'})
  ]);
  const linksPanel=h('div',{}), nativePanel=h('div',{}), routingPanel=h('div',{});
  function nodeOptions(nodes,selected) {
    nodeNames=nodes.map(n=>({name:n.name,type:n.type}));
    nodeSelect.replaceChildren(...nodeNames.map((n,i)=>h('option',{attrs:{value:String(i)},text:(i+1)+'. '+n.name+' · '+n.type})));
    if(!nodeNames.length)nodeSelect.appendChild(h('option',{attrs:{value:'0'},text:'粘贴后自动识别节点'}));
    nodeSelect.value=String(selected||0);
  }
  function proxyOptions() {return S.options({direct_cidrs:directCIDRs.value,direct_domains:directDomains.value,dns_hijack:hijackDNS.value==='on',bootstrap_dns:bootstrapDNS.value.trim(),proxy_dns:proxyDNS.value.trim()});}
  function proxyForm(form) {
    storedMode=form.mode||'empty';configMode.value=storedMode==='native'?'native':'links';
    nodeOptions(form.nodes||[],form.selected);
    const o=S.options(form.options);
    directCIDRs.value=o.direct_cidrs.join('\n');directDomains.value=o.direct_domains.join('\n');
    bootstrapDNS.value=o.bootstrap_dns;proxyDNS.value=o.proxy_dns;hijackDNS.value=o.dns_hijack?'on':'off';
    renderProxyMode();
  }
  function renderProxyMode() {
    const native=configMode.value==='native';linksPanel.hidden=native;nativePanel.hidden=!native;routingPanel.hidden=native;
    proxyDNS.disabled=hijackDNS.value!=='on';F.requestResize();
  }
  configMode.addEventListener('change',()=>{dirty=true;renderProxyMode();});
  hijackDNS.addEventListener('change',renderProxyMode);
  shareLinks.addEventListener('input',()=>nodeOptions([],0));
  const peerList=h('div',{}), driverButtons={}, driverSpecific=h('div',{});
  const wgAdvanced=h('div',{className:'vpn-subsection vpn-fields',attrs:{hidden:true}},[
    field('WireGuard 监听端口',listenPort,'0 表示由系统分配；对应 [Interface] ListenPort。'),
    field('宿主访问远端内网的路由（可选）',routes,'仅供 Veer 所在主机访问远端内网；下游设备分流在 LAN 或出向 NAT 中设置。')
  ]);
  const proxyAdvanced=h('div',{className:'vpn-subsection vpn-fields',attrs:{hidden:true}},[
    field('内部 WAN 地址（可选）',wanAddressInput,'留空自动分配，重新应用时保留已分配地址。仅用于 Veer 出口，不是节点地址或核心 TUN 地址；手动指定须使用 /32 或 /128。',true)
  ]);
  const wgImport=h('details',{className:'vpn-advanced'},[
    h('summary',{text:'导入 WireGuard 配置'}),node('p','vpn-subtle','粘贴 wg.conf，导入后检查表单再保存。配置中的脚本钩子不会被接受。'),importConfig,
    button('导入到表单',async () => {
      const imported=M.importWG(importConfig.value);
      fill({...imported.profile,slot:Number(slotInput.value)},false);
      privateKey.value=imported.privateKey;
      peers.forEach((p,i) => {p.psk.value=imported.psks[i] || '';});
      importConfig.value='';wgImport.open=false;dirty=true;
      message(imported.warnings.join(' ') || '已导入到表单，尚未保存或应用。');
    },true)
  ]);
  function addPeer(value,psk) {
    value=value || {allowed_ips:['0.0.0.0/0'],keepalive:25};
    const peer={original:M.copy(value),public_key:input('Peer 公钥',value.public_key),endpoint:input('Peer Endpoint',value.endpoint),
      allowed_ips:input('Peer AllowedIPs',(value.allowed_ips || []).join(', ')),keepalive:input('Peer 保活间隔',value.keepalive == null?25:value.keepalive,'number'),psk:input('Peer 预共享密钥',psk || '','password')};
    const row=h('section',{className:'vpn-peer'},[
      h('div',{className:'vpn-heading'},[node('h3','','Peer '+(peers.length+1)),button('移除 Peer',async () => {peers=peers.filter(p=>p!==peer);row.remove();dirty=true;},true)]),
      h('div',{className:'vpn-fields'},[
        field('公钥',peer.public_key,null,true),field('Endpoint',peer.endpoint,'数值 IP:端口，IPv6 使用 [地址]:端口。'),field('AllowedIPs',peer.allowed_ips,'多个网段用逗号分隔。'),
        field('保活间隔（秒）',peer.keepalive,'0 表示关闭。'),field('预共享密钥（可选）',peer.psk,value.preshared_key_secret?'留空沿用已保存的密钥。':'保存后加密存储，不会回填。')
      ])
    ]);
    peer.row=row;peers.push(peer);peerList.appendChild(row);
    return peer;
  }
  function values() {
    return {driver:currentDriver,slot:slotInput.value,mtu:mtuInput.value,addresses:currentDriver==='wireguard'?addressInput.value:wanAddressInput.value,upstream_interface:upstream.value,
      listen_port:listenPort.value,remote_routes:routes.value,tun_interface:tunName.value,tun_alias:tunAlias.value,
      peers:peers.map(p => ({original:p.original,public_key:p.public_key.value,endpoint:p.endpoint.value,allowed_ips:p.allowed_ips.value,keepalive:p.keepalive.value,psk:p.psk.value}))};
  }
  function selected() { return M.identifier(keyInput.value.trim()); }
  function fill(value,replaceOriginal) {
    const driver=value.driver || 'wireguard';
    if (!M.drivers[driver]) throw new Error('此出口类型不受当前页面支持');
    for(const name of ['addresses','peers','remote_routes']) if(value[name]!=null && !Array.isArray(value[name]))throw new Error(name+' 必须是数组');
    if (replaceOriginal!==false) original=M.copy(value);
    currentDriver=driver;proxyForm({mode:'empty'});shareLinks.value='';
    addressInput.value=driver==='wireguard'?(value.addresses || []).join(', '):'';
    wanAddressInput.value=driver==='wireguard'?'':(value.addresses || []).join(', ');slotInput.value=value.slot || 1;mtuInput.value=value.mtu || 1420;
    upstream.value=value.upstream_interface || '';listenPort.value=value.listen_port || 0;routes.value=(value.remote_routes || []).join(', ');
    tunName.value=value.tun_interface || '';tunAlias.value=value.tun_alias || '';
    peers=[];peerList.replaceChildren();(value.peers || (currentDriver==='wireguard'?[{}]:[])).forEach(p=>addPeer(p));
    privateKey.value='';coreConfig.value='';rawDirty=false;rawConfig.value=JSON.stringify(value,null,2);
    renderDriver();F.requestResize();
  }
  function renderDriver() {
    Object.keys(driverButtons).forEach(id => driverButtons[id].setAttribute('aria-pressed',String(id===currentDriver)));
    wgImport.hidden=currentDriver!=='wireguard';
    wgAdvanced.hidden=currentDriver!=='wireguard';proxyAdvanced.hidden=currentDriver==='wireguard';
    driverSpecific.replaceChildren();
    if (currentDriver==='wireguard') driverSpecific.appendChild(h('div',{className:'vpn-subsection'},[
      node('h3','vpn-section-title','WireGuard 连接'),
      node('p','vpn-subtle','导入 wg.conf，或按服务端提供的配置填写。本机地址须与对端配置匹配；连接对端时使用宿主路由。'),wgImport,
      h('div',{className:'vpn-fields'},[
        field('本机 WireGuard 地址',addressInput,'对应 [Interface] Address，包含前缀；多个地址用逗号分隔。'),
        field('本机私钥',privateKey,'对应 [Interface] PrivateKey。留空沿用已保存的私钥，保存后不会回填。')]),
      h('div',{className:'vpn-subsection'},[node('h3','vpn-section-title','远端 Peer'),peerList,button('添加 Peer',async () => {if(peers.length>=8)throw new Error('最多支持 8 个 Peer');addPeer();dirty=true;},true)])
    ]));
    else if (currentDriver==='tun') driverSpecific.appendChild(h('div',{className:'vpn-subsection'},[
      node('h3','vpn-section-title','接入已有 TUN'),
      node('p','vpn-subtle','外部程序负责连接、上联和 TUN 地址。本页只接入它已创建并启用的接口，不安装或启动该程序。'),
      h('div',{className:'vpn-fields'},[field('TUN 接口',tunName,'填写现有 Linux TUN 名称，例如 tun0。'),field('接口归属标记',tunAlias,'必须与该接口的 alias 完全一致，用于确认接口归属。')])
    ]));
    else {
      const name=M.drivers[currentDriver].name;
      coreConfig.setAttribute('aria-label',name+' 配置（JSON）');
      driverSpecific.appendChild(h('div',{className:'vpn-subsection'},[
        node('h3','vpn-section-title',name+' 代理出口'),
        node('p','vpn-subtle','粘贴分享链接，选择节点后即可保存并应用。核心配置、TUN 和内部出口地址自动生成。'),
        h('div',{className:'vpn-fields'},[field('实际出站接口',upstream,'填写可访问节点服务器的物理、网桥或 PPPoE 接口，例如 eth0、vmbr0、ppp0；不能选择 VPN 自身。',true)]),
        linksPanel,
        h('details',{className:'vpn-advanced vpn-proxy-advanced'},[
          h('summary',{text:'分流与高级配置'}),field('核心配置方式',configMode),routingPanel,nativePanel
        ]),
        node('p','vpn-field-help','分享链接与配置加密保存，凭据不会回填。核心在“核心管理”中安装。')
      ]));
      linksPanel.replaceChildren(
        field('节点分享链接或 Base64',shareLinks,'支持 SS、VMess、VLESS、Trojan、Hysteria2、AnyTLS；多条链接每行一条。留空保留已导入节点。'),
        actions([button('识别节点',async()=>{
          nodeOptions(S.parse(shareLinks.value,currentDriver),0);dirty=true;
          message('已识别 '+nodeNames.length+' 个节点，请选择要使用的节点并保存。');
        },true)]),field('使用节点',nodeSelect,'默认选择第一个节点；未点击“识别节点”时，保存也会自动识别。')
      );
      routingPanel.replaceChildren(node('p','vpn-subtle','默认全部通过所选节点。以下例外通过实际出站接口直连；域名规则依赖 HTTP / TLS / QUIC 嗅探，无法识别时仍通过节点。'),
        h('div',{className:'vpn-fields'},[field('直连网段',directCIDRs,'每行一个 CIDR；留空不添加网段例外。'),field('直连域名及子域名',directDomains,'每行一个域名；留空不添加域名例外。'),
          field('节点解析 DNS',bootstrapDNS,'填写可通过上联接口访问的 IPv4 DNS，用于解析节点域名。'),field('下游 DNS',hijackDNS,'仅接管经过此 VPN 出口的 TCP / UDP 53 流量。'),field('代理 DNS',proxyDNS,'通过所选节点访问的 IPv4 DNS。')])
      );
      nativePanel.replaceChildren(field(name+' 配置（JSON）',coreConfig,'填写完整原生 JSON；保存后加密存储。留空保留已保存的原生配置。'));
      renderProxyMode();
    }
  }
  async function openEditor(record) {
    if (dirty && !await F.confirm({title:'离开当前编辑',message:'尚未保存的修改将丢失。',confirmText:'继续',cancelText:'留在此页'})) return;
    editing=!!record;savedDriver=record?(record.data.driver || 'wireguard'):'';keyInput.readOnly=editing;
    const next=record ? {key:record.key,...record.data} : M.allocation(records);
    keyInput.value=next.key;
    fill(record ? record.data : {driver:'wireguard',slot:next.slot,mtu:1420,addresses:[],listen_port:0,peers:[{allowed_ips:['0.0.0.0/0'],keepalive:25}],remote_routes:[]});
    if(record && ['mihomo','sing_box'].includes(currentDriver)) {
      const response=await F.action('core_form',{key:record.key});proxyForm(response.result||{mode:'empty'});
      if(storedMode==='native')driverSpecific.querySelector('details').open=true;
    }
    editorTitle.textContent=editing?'编辑出口 · '+record.key:'新建出口';
    editor.hidden=false;list.hidden=!records.length;dirty=false;message('');editor.scrollIntoView({block:'start',behavior:'smooth'});
  }
  const types=h('div',{className:'vpn-types'},Object.keys(M.drivers).map(id => {
    const driver=M.drivers[id];
    const el=button('',async () => {
      if (id===currentDriver) return;
      const status=statuses[selected()];
      if (editing && status && !['down','deleted'].includes(status.phase)) throw new Error('请先拆除现有出口，再切换类型');
      if (dirty && !await F.confirm({title:'切换出口类型',message:'当前未保存的连接配置将被替换。',confirmText:'切换',cancelText:'取消'})) return;
      const slot=Number(slotInput.value)||1;
      fill({driver:id,slot,mtu:1420,peers:id==='wireguard'?[{allowed_ips:['0.0.0.0/0'],keepalive:25}]:undefined});
      dirty=true;
    },true);
    el.className='vpn-type';el.setAttribute('aria-label',driver.name);el.append(node('strong','',driver.name),node('span','',driver.description));driverButtons[id]=el;return el;
  }));
  const advanced=h('details',{className:'vpn-advanced'},[
    h('summary',{text:'高级设置与 JSON'}),h('div',{className:'vpn-fields'},[field('出口位置',slotInput,'范围 1–8，每个出口使用不同位置。'),field('MTU',mtuInput)]),wgAdvanced,proxyAdvanced,
    button('读取当前表单 JSON',async () => {rawConfig.value=JSON.stringify(M.profile(values(),original,records,selected()),null,2);rawDirty=false;},true),rawConfig,
    button('将 JSON 更新到表单',async () => {
      const value=JSON.parse(rawConfig.value);if(!value || typeof value!=='object' || Array.isArray(value))throw new Error('出口配置必须是 JSON 对象');
      const keep=['mihomo','sing_box'].includes(currentDriver) && value.driver===currentDriver && value.config_secret===original.config_secret;
      const draft=keep?{storedMode,mode:configMode.value,nodes:nodeNames,selected:Number(nodeSelect.value),options:proxyOptions(),links:shareLinks.value,native:coreConfig.value}:null;
      fill(value);
      if(draft) {proxyForm({mode:draft.storedMode,nodes:draft.nodes,selected:draft.selected,options:draft.options});configMode.value=draft.mode;shareLinks.value=draft.links;coreConfig.value=draft.native;renderProxyMode();}
      dirty=true;F.toast('已更新表单，尚未保存');
    },true)
  ]);
  rawConfig.addEventListener('input',()=>{rawDirty=true;});
  async function save(apply) {
    if (rawDirty) throw new Error('请先点击“将 JSON 更新到表单”，或重新读取表单 JSON');
    const key=selected(), profile=M.profile(values(),original,records,key), text=coreConfig.value.trim();
    if (['mihomo','sing_box'].includes(currentDriver) && !profile.config_secret && (!editing || savedDriver!==currentDriver))
      profile.config_secret='core_'+currentDriver+'_'+key;
    const managed=['mihomo','sing_box'].includes(currentDriver), links=shareLinks.value.trim();
    let imported=null;
    if(managed && configMode.value==='links') {
      if(links)imported=S.create(currentDriver,links,nodeSelect.value,proxyOptions());
      else {if(storedMode!=='links')throw new Error('请粘贴节点分享链接或 Base64 分享内容');proxyOptions();}
    } else if(managed) {
      if(text) {try {const parsed=JSON.parse(text);if(!parsed || typeof parsed!=='object' || Array.isArray(parsed))throw new Error();}catch(error){throw new Error('核心配置必须是有效 JSON 对象');}}
      else if(storedMode!=='native')throw new Error('请填写原生 JSON 配置，或切换为分享链接导入');
    }
    // Validate every local field before writing any credential or draft.
    if (privateKey.value.trim() && !/^[A-Za-z0-9+/]{43}=$/.test(privateKey.value.trim())) throw new Error('WireGuard 私钥格式不正确');
    peers.forEach(p=>{if(p.psk.value.trim() && !/^[A-Za-z0-9+/]{43}=$/.test(p.psk.value.trim()))throw new Error('预共享密钥格式不正确');});
    try {
      if (currentDriver==='wireguard') {
        if (privateKey.value.trim()) await F.action('set_key',{key,value:privateKey.value.trim()});
        for (let i=0;i<peers.length;i++) if (peers[i].psk.value.trim()) await F.action('set_key',{key,name:profile.peers[i].preshared_key_secret,value:peers[i].psk.value.trim()});
      } else if(managed && configMode.value==='links') {
        const result=await F.action('set_core_config',{key,...(profile.config_secret?{name:profile.config_secret}:{}),format:'links',driver:currentDriver,value:links,selected:Number(nodeSelect.value),options:proxyOptions()});
        if(result.result && result.result.form)proxyForm(result.result.form);
        else {storedMode='links';if(imported)nodeOptions(S.metadata(imported).nodes,imported.selected);}
      } else if(managed && text) {await F.action('set_core_config',{key,...(profile.config_secret?{name:profile.config_secret}:{}),value:text});storedMode='native';}
    } finally {privateKey.value='';peers.forEach(p=>{p.psk.value='';});coreConfig.value='';shareLinks.value='';}
    await F.data.upsert('profiles',key,profile,{enabled:true});
    original=M.copy(profile);editing=true;savedDriver=currentDriver;keyInput.readOnly=true;dirty=false;
    if (apply) {
      message('草稿已保存，正在应用…');
      try {
        const response=await F.action('apply',{key});
        const result=response && response.result || {};
        message(result.phase==='starting'?'出口正在启动，稍后查看出口卡片状态。':'已应用。请在 LAN 或出向 NAT 中选择此出口；就绪状态仅表示本机接入完成。');
      } catch (error) { await reload();throw error; }
    } else message('草稿已保存，正在运行的出口未改变。');
    await reload();F.toast(apply?'已提交应用':'草稿已保存');
  }
  editor.append(
    h('div',{className:'vpn-heading'},[editorTitle,button('收起编辑',async () => {
      if(dirty && !await F.confirm({title:'放弃未保存修改',message:'草稿尚未保存。',confirmText:'收起',cancelText:'继续编辑'}))return;
      privateKey.value='';coreConfig.value='';shareLinks.value='';importConfig.value='';peers.forEach(p=>{p.psk.value='';});dirty=false;editor.hidden=true;list.hidden=false;
    },true)]),types,
    h('div',{className:'vpn-fields'},[field('出口标识',keyInput,'用于区分出口，保存后保持不变。')]),
    driverSpecific,advanced,
    h('div',{className:'vpn-savebar'},[node('span','vpn-field-help','应用会重建此出口的连接。仅保存草稿不会影响流量。'),actions([button('保存草稿',()=>save(false),true),button('保存并应用',()=>save(true))])])
  );
  editor.addEventListener('input',()=>{dirty=true;});
  const detailPanel=h('section',{className:'vpn-panel vpn-details',attrs:{hidden:true}}), detailOutput=h('pre',{className:'vpn-raw'});
  const detailTitle=node('h2','','运行详情');
  detailPanel.append(h('div',{className:'vpn-heading'},[detailTitle,button('收起详情',async()=>{detailPanel.hidden=true;detailOutput.textContent='';},true)]),detailOutput);
  const phases={applied:['就绪','ready'],configured:['就绪','ready'],starting:['启动中',''],failed:['启动失败','error'],error:['需要处理','error'],down:['已停止',''],deleted:['已停止','']};
  async function showDetails(key,logs) {
    const value=await F.action(logs?'core_logs':'inspect',{key});
    detailTitle.textContent=(logs?'核心日志 · ':'运行详情 · ')+key;
    detailOutput.textContent=JSON.stringify(value.result || value,null,2);detailPanel.hidden=false;
    detailPanel.scrollIntoView({block:'nearest',behavior:'smooth'});
  }
  function renderList() {
    count.textContent=String(records.length);list.replaceChildren();list.className=records.length?'vpn-list':'';list.hidden=!records.length && !editor.hidden;
    if (!records.length) {list.appendChild(h('div',{className:'vpn-empty'},[
      node('div','vpn-icon','↗'),node('h2','','创建你的第一个 VPN 出口'),node('p','','选择 WireGuard、Mihomo 或 sing-box，再把需要的 LAN 或设备分配到这个出口。'),button('创建出口',()=>openEditor(),false)
    ]));return;}
    records.forEach(record=>{
      const profile=record.data, driver=M.drivers[profile.driver || 'wireguard'] || {name:profile.driver,short:'?'}, status=statuses[record.key] || {};
      const phase=phases[status.phase] || ['未应用',''], name=status.local_interface || (profile.driver && profile.driver!=='wireguard'?'veervpn':'veerwg')+profile.slot;
      const metadata=h('dl',{className:'vpn-metadata'});
      const wg=!profile.driver || profile.driver==='wireguard';
      const addresses=profile.addresses && profile.addresses.length?profile.addresses:status.wan_addresses || [];
      [['出口接口',name],[wg?'本机 WireGuard 地址':'内部 WAN 地址',addresses.join(', ') || (wg?'未配置':'应用时自动分配')],
        [wg?'对端选路':profile.driver==='tun'?'外部 TUN 接口':'实际出站接口',wg?'按宿主路由':profile.driver==='tun'?profile.tun_interface:profile.upstream_interface],
        ['接入方式','LAN / 出向 NAT']].forEach(pair=>metadata.append(h('div',{},[node('dt','',pair[0]),node('dd','',pair[1])])));
      const card=h('article',{className:'vpn-outlet'},[
        h('div',{className:'vpn-card-top'},[h('div',{className:'vpn-card-heading'},[node('div','vpn-icon',driver.short),h('div',{},[node('h3','',record.key),node('p','vpn-caption',driver.name)])]),h('span',{className:'vpn-badge',attrs:{'data-tone':phase[1]},text:phase[0]})]),metadata,
        status.error?node('p','vpn-card-error',status.error):null,
        h('div',{className:'vpn-card-footer'},[
          button('编辑',()=>openEditor(record),true),button('查看状态',()=>showDetails(record.key,false),true),
          button('拆除',async()=>{
            if (!await F.confirm({title:'拆除 '+record.key,message:'请先把引用此出口的 LAN 或出向 NAT 切换到其他出口。配置草稿与密钥会保留。',confirmText:'拆除',cancelText:'取消',danger:true}))return;
            await F.action('teardown',{key:record.key});await reload();
          },true),
          ['mihomo','sing_box'].includes(profile.driver)?button('核心日志',async()=>{
            if(await F.confirm({title:'查看核心日志',message:'日志可能包含节点凭据，请在分享前脱敏。',confirmText:'查看',cancelText:'取消'}))await showDetails(record.key,true);
          },true):null
        ])
      ]);list.appendChild(card);
    });
  }
  async function reload() {
    const results=await Promise.all([F.data.list('profiles'),F.data.list('status')]);
    records=Array.isArray(results[0])?results[0]:results[0].records || [];
    const state=Array.isArray(results[1])?results[1]:results[1].records || [];
    statuses={};state.forEach(r=>{statuses[r.key]=r.data || {};});renderList();
    clearTimeout(statusPoll);
    if(state.some(r=>r.data && r.data.phase==='starting'))statusPoll=setTimeout(()=>reload().catch(F.toastError),2500);
    F.requestResize();
  }
  const coreVersion=node('div','vpn-core-version','尚未安装'),coreInfo=node('p','vpn-status-line',''),coreProgress=h('progress',{className:'vpn-progress',attrs:{hidden:true,max:100}});
  const installVersion=input('安装版本',''),installDigest=input('SHA256','');
  installVersion.placeholder='留空使用最新稳定版';
  const installed=h('select',{className:F.classes.input,attrs:{'aria-label':'已安装核心版本'}});
  const coreName=node('h2','','Mihomo'),coreOptions={},coreDetails=h('div',{className:'vpn-panel'});
  function setCoreStatus(status) {
    coreVersion.textContent=status.version || '尚未安装';
    installed.replaceChildren(h('option',{attrs:{value:''},text:'选择已安装版本'}));
    (status.versions || []).forEach(v=>installed.appendChild(h('option',{attrs:{value:v.version},text:v.version+(v.version===status.version?' · 默认':'')})));
    installed.value=status.version || '';
    const job=status.install, phases={resolving:'查询版本中',downloading:'下载中',verifying:'校验中',ready:'安装成功',failed:'安装失败'};
    coreInfo.textContent=job?(phases[job.state] || job.state)+(job.downloaded_bytes?' · '+(job.downloaded_bytes/1048576).toFixed(1)+' MiB':'')+(job.error?' · '+job.error:''):(status.previous?'上一版本：'+status.previous:'从官方发布安装核心，或使用本机已有核心。');
    const active=job && ['resolving','downloading','verifying'].includes(job.state);
    coreProgress.hidden=!active;
    if(active && job.total_bytes)coreProgress.value=100*job.downloaded_bytes/job.total_bytes;else coreProgress.removeAttribute('value');
    F.requestResize();return active;
  }
  async function refreshCore() {
    clearTimeout(corePoll);const sequence=++coreSequence,driver=coreDriver;
    const response=await F.action('core_status',{driver});
    if(sequence!==coreSequence || driver!==coreDriver)return;
    if(!response || !response.result)throw new Error('无法读取核心状态');
    if(setCoreStatus(response.result))corePoll=setTimeout(()=>refreshCore().catch(F.toastError),1500);
  }
  coreDetails.append(coreName,coreVersion,coreInfo,coreProgress,h('div',{className:'vpn-fields'},[field('安装版本',installVersion),field('已安装版本',installed)]),
    h('details',{className:'vpn-advanced'},[h('summary',{text:'指定校验值'}),field('SHA256',installDigest,'官方资产没有摘要时，填写已核实的 SHA256。')]),
    h('div',{className:'vpn-savebar'},[actions([
      button('安装 / 更新',async()=>{++coreSequence;clearTimeout(corePoll);await F.action('core_install',{driver:coreDriver,version:installVersion.value.trim(),sha256:installDigest.value.trim()});await refreshCore();}),
      button('刷新',refreshCore,true),button('设为默认',async()=>{if(!installed.value)throw new Error('请选择版本');await F.action('core_select',{driver:coreDriver,version:installed.value});await refreshCore();},true),
      button('回滚上一版本',async()=>{await F.action('core_rollback',{driver:coreDriver});await refreshCore();},true),
      button('删除版本',async()=>{if(!installed.value)throw new Error('请选择版本');if(!await F.confirm({title:'删除核心版本',message:'删除 '+installed.value+'。默认版本和正在使用的版本不可删除。',confirmText:'删除',cancelText:'取消',danger:true}))return;await F.action('core_remove',{driver:coreDriver,version:installed.value});await refreshCore();},true)
    ])]),node('p','vpn-subtle','切换默认版本不会重启出口。重新应用对应出口后生效。'));
  corePanel.appendChild(h('div',{className:'vpn-core-layout'},[
    h('div',{className:'vpn-core-options'},['mihomo','sing_box'].map(id=>{
      const el=button('',async()=>{coreDriver=id;coreName.textContent=M.drivers[id].name;Object.keys(coreOptions).forEach(k=>coreOptions[k].setAttribute('aria-pressed',String(k===id)));installVersion.value='';installDigest.value='';await refreshCore();},true);
      el.className='vpn-type';el.setAttribute('aria-pressed',String(id===coreDriver));el.append(node('strong','',M.drivers[id].name),node('span','',M.drivers[id].description));coreOptions[id]=el;return el;
    })),coreDetails
  ]));
  const outletTab=h('button',{className:'vpn-tab',attrs:{type:'button',role:'tab','aria-selected':'true'},text:'出口'},count);
  const coreTab=h('button',{className:'vpn-tab',attrs:{type:'button',role:'tab','aria-selected':'false'},text:'核心管理'});
  function switchTab(core) {
    outletPanel.hidden=core;corePanel.hidden=!core;
    outletTab.setAttribute('aria-selected',String(!core));coreTab.setAttribute('aria-selected',String(core));
    if(core)refreshCore().catch(F.toastError);else{++coreSequence;clearTimeout(corePoll);}
    F.requestResize();
  }
  outletTab.addEventListener('click',()=>switchTab(false));coreTab.addEventListener('click',()=>switchTab(true));
  outletPanel.append(editor,detailPanel);
  const page=h('main',{className:F.classes.page+' vpn-page'},[
    h('header',{className:'vpn-header'},[h('div',{},[node('h1','','VPN 出口'),node('p','','管理 VPN 连接，按需分配给 LAN 或下游设备。')]),actions([button('刷新出口',reload,true),button('新建出口',async()=>{switchTab(false);await openEditor();})])]),
    h('nav',{className:'vpn-nav',attrs:{role:'tablist','aria-label':'VPN 页面'}},[outletTab,coreTab]),notice,outletPanel,corePanel
  ]);
  window.addEventListener('pagehide',()=>{++coreSequence;clearTimeout(corePoll);clearTimeout(statusPoll);privateKey.value='';coreConfig.value='';shareLinks.value='';importConfig.value='';});
  document.body.replaceChildren(page);reload().catch(error=>message(F.errorText(error),true));
})();
