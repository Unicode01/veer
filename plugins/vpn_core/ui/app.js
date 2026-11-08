(function () {
  'use strict';
  const F=window.VeerPluginHost, M=window.VPNConfig, S=window.VPNShare, I=window.VPNI18n, h=F.h;
      const notify = F.notify || F.toast;
      const notifyError = F.notifyError || F.toastError;
  let records=[], statuses={}, busy=false, original={}, currentDriver='wireguard', savedDriver='', editing=false;
  let peers=[], dirty=false, rawDirty=false, coreDriver='mihomo', coreSequence=0, corePoll=null, statusPoll=null;
  let storedMode='empty', nodeNames=[];
  let healthStates={}, healthPoll=null, coreStatus=null;
  // Locale: text built once is bound to its message (L) and refreshed when the host locale
  // changes; render functions pass translated strings (T) and are simply rerun.
  const T=(key,params) => I.t(key,params), L=(key,params) => () => T(key,params);
  const bound=[], dynamic=new Map();
  let scope=bound;
  function put(binding) { const text=binding.value();if(binding.prop==='text')binding.el.textContent=text;else binding.el.setAttribute(binding.prop,text); }
  function bind(el,prop,value) {
    if (typeof value==='function') {const binding={el,prop,value};scope.push(binding);put(binding);}
    else if (value!=null) {if(prop==='text')el.textContent=value;else el.setAttribute(prop,value);}
    return el;
  }
  function setMessage(el,key,params) { dynamic.set(el,{key,params});el.textContent=T(key,params);return el; }
  function setRaw(el,text) { dynamic.delete(el);el.textContent=text;return el; }
  const controlNodes=() => document.querySelectorAll('.vpn-page button,.vpn-page input,.vpn-page select,.vpn-page textarea');
  function node(tag, className, text) { return bind(h(tag,{className}),'text',text); }
  function input(label,value,type) {
    const el=h('input',{className:F.classes.input,attrs:{value:value == null ? '' : value,type:type || 'text',autocomplete:type==='password'?'new-password':'off'}});
    return bind(el,'aria-label',label);
  }
  function area(label) { return bind(h('textarea',{className:F.classes.input+' vpn-json',attrs:{spellcheck:'false'}}),'aria-label',label); }
  function option(value,label) { return bind(h('option',{attrs:{value}}),'text',label); }
  function field(label,el,help,wide) { return h('label',{className:F.classes.field+(wide?' vpn-wide':'')},[node('span','',label),el,help?node('span','vpn-field-help',help):null]); }
  function showNotice(error) { notice.hidden=!notice.textContent;notice.dataset.tone=error?'error':'';F.requestResize(); }
  function message(text,error) { setRaw(notice,text || '');showNotice(error); }
  function say(key,params) { setMessage(notice,key,params);showNotice(false); }
  async function run(task) {
    if (busy) return;
    busy=true; controlNodes().forEach(el => {el.disabled=true;});
    try { await task(); }
    catch (error) { message(F.errorText(error),true);notifyError(error); }
    finally { busy=false;controlNodes().forEach(el => {el.disabled=false;});keyInput.readOnly=editing;renderProxyMode();F.requestResize(); }
  }
  function button(text,task,secondary) { return bind(F.button('',() => run(task),secondary),'text',text); }
  function actions(children) { return h('div',{className:'vpn-actions'},children); }
  const count=node('span','vpn-count','0'), list=h('div',{className:'vpn-list'});
  const notice=h('div',{className:'vpn-notice',attrs:{role:'status','aria-live':'polite',hidden:true}});
  const outletPanel=h('section',{},[list]);
  const corePanel=h('section',{attrs:{hidden:true}});
  const editor=h('section',{className:'vpn-panel vpn-editor',attrs:{hidden:true}});
  const editorTitle=setMessage(h('h2'),'editor.new');
  const keyInput=input(L('field.key'),''), addressInput=input(L('field.wgAddress'),''), wanAddressInput=input(L('field.wanAddress'),''), slotInput=input(L('field.slot'),1,'number');
  bind(addressInput,'placeholder',L('field.wgAddress.placeholder'));bind(wanAddressInput,'placeholder',L('field.wanAddress.placeholder'));
  const mtuInput=input(L('field.mtu'),1420,'number'), upstream=input(L('field.upstream'),'','text');
  const upstreamIP=bind(input(L('field.upstreamIP'),'','text'),'placeholder',L('field.upstreamIP.placeholder'));
  const listenPort=input(L('field.listenPort'),0,'number'), privateKey=input(L('field.privateKey'),'','password');
  const routes=input(L('field.routes'),''), tunName=input(L('field.tunName'),''), tunAlias=input(L('field.tunAlias'),'');
  const coreConfig=area(L('field.coreConfig')), rawConfig=area(L('field.rawConfig')), importConfig=area(L('field.importConfig'));
  const shareLinks=area(L('field.shareLinks')), nodeSelect=bind(h('select',{className:F.classes.input}),'aria-label',L('field.node'));
  shareLinks.classList.add('vpn-links');bind(shareLinks,'placeholder',L('field.shareLinks.placeholder'));
  const configMode=bind(h('select',{className:F.classes.input},[
    option('links',L('field.configMode.links')),option('native',L('field.configMode.native'))
  ]),'aria-label',L('field.configMode'));
  const directCIDRs=area(L('field.directCIDRs')), directDomains=area(L('field.directDomains')), bootstrapDNS=input(L('field.bootstrapDNS'),'223.5.5.5'), proxyDNS=input(L('field.proxyDNS'),'1.1.1.1');
  directCIDRs.classList.add('vpn-rule-input');directDomains.classList.add('vpn-rule-input');
  directCIDRs.placeholder='192.168.0.0/16\n10.0.0.0/8';directDomains.placeholder='example.com';
  const hijackDNS=bind(h('select',{className:F.classes.input},[
    option('off',L('field.hijackDNS.off')),option('on',L('field.hijackDNS.on'))
  ]),'aria-label',L('field.hijackDNS'));
  const linksPanel=h('div',{}), nativePanel=h('div',{}), routingPanel=h('div',{});
  function nodeOptions(nodes,selected) {
    nodeNames=nodes.map(n=>({name:n.name,type:n.type}));
    nodeSelect.replaceChildren(...nodeNames.map((n,i)=>h('option',{attrs:{value:String(i)},text:(i+1)+'. '+n.name+' · '+n.type})));
    if(!nodeNames.length)nodeSelect.appendChild(h('option',{attrs:{value:'0'},text:T('field.node.placeholder')}));
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
    field(L('field.wgListenPort'),listenPort,L('field.wgListenPort.help')),
    field(L('field.hostRoutes'),routes,L('field.hostRoutes.help'))
  ]);
  const proxyAdvanced=h('div',{className:'vpn-subsection vpn-fields',attrs:{hidden:true}},[
    field(L('field.wanAddress.optional'),wanAddressInput,L('field.wanAddress.help'),true)
  ]);
  const wgImport=h('details',{className:'vpn-advanced'},[
    node('summary',null,L('wg.import')),node('p','vpn-subtle',L('wg.import.intro')),importConfig,
    button(L('wg.import.action'),async () => {
      const imported=M.importWG(importConfig.value);
      fill({...imported.profile,slot:Number(slotInput.value)},false);
      privateKey.value=imported.privateKey;
      peers.forEach((p,i) => {p.psk.value=imported.psks[i] || '';});
      importConfig.value='';wgImport.open=false;dirty=true;
      if (imported.warnings.length) message(imported.warnings.join(' '));else say('wg.import.done');
    },true)
  ]);
  function addPeer(value,psk) {
    value=value || {allowed_ips:['0.0.0.0/0'],keepalive:25};
    const outer=scope, own=[];
    scope=own;
    try {
      const peer={bound:own,original:M.copy(value),public_key:input(L('peer.publicKey.label'),value.public_key),endpoint:input(L('peer.endpoint.label'),value.endpoint),
        allowed_ips:input(L('peer.allowedIPs.label'),(value.allowed_ips || []).join(', ')),keepalive:input(L('peer.keepalive.label'),value.keepalive == null?25:value.keepalive,'number'),psk:input(L('peer.psk.label'),psk || '','password')};
      const row=h('section',{className:'vpn-peer'},[
        h('div',{className:'vpn-heading'},[node('h3','',L('peer.title',{index:peers.length+1})),button(L('peer.remove'),async () => {peers=peers.filter(p=>p!==peer);row.remove();dirty=true;},true)]),
        h('div',{className:'vpn-fields'},[
          field(L('peer.publicKey'),peer.public_key,null,true),field(L('peer.endpoint'),peer.endpoint,L('peer.endpoint.help')),field(L('peer.allowedIPs'),peer.allowed_ips,L('peer.allowedIPs.help')),
          field(L('peer.keepalive'),peer.keepalive,L('peer.keepalive.help')),field(L('peer.psk'),peer.psk,L(value.preshared_key_secret?'peer.psk.keep':'peer.psk.new'))
        ])
      ]);
      peer.row=row;peers.push(peer);peerList.appendChild(row);
      return peer;
    } finally {scope=outer;}
  }
  function values() {
    return {driver:currentDriver,slot:slotInput.value,mtu:mtuInput.value,addresses:currentDriver==='wireguard'?addressInput.value:wanAddressInput.value,upstream_interface:upstream.value,upstream_ip:upstreamIP.value,
      listen_port:listenPort.value,remote_routes:routes.value,tun_interface:tunName.value,tun_alias:tunAlias.value,
      peers:peers.map(p => ({original:p.original,public_key:p.public_key.value,endpoint:p.endpoint.value,allowed_ips:p.allowed_ips.value,keepalive:p.keepalive.value,psk:p.psk.value}))};
  }
  function selected() { return M.identifier(keyInput.value.trim()); }
  function fill(value,replaceOriginal) {
    const driver=value.driver || 'wireguard';
    if (!M.drivers[driver]) throw new Error(T('error.unsupportedDriver'));
    for(const name of ['addresses','peers','remote_routes']) if(value[name]!=null && !Array.isArray(value[name]))throw new Error(T('error.mustBeArray',{name}));
    if (replaceOriginal!==false) original=M.copy(value);
    currentDriver=driver;proxyForm({mode:'empty'});shareLinks.value='';
    addressInput.value=driver==='wireguard'?(value.addresses || []).join(', '):'';
    wanAddressInput.value=driver==='wireguard'?'':(value.addresses || []).join(', ');slotInput.value=value.slot || 1;mtuInput.value=value.mtu || 1420;
    upstream.value=value.upstream_interface || '';listenPort.value=value.listen_port || 0;routes.value=(value.remote_routes || []).join(', ');
    upstreamIP.value=value.upstream_ip || '';
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
      node('h3','vpn-section-title',T('wg.title')),
      node('p','vpn-subtle',T('wg.intro')),wgImport,
      h('div',{className:'vpn-fields'},[
        field(T('field.wgAddress'),addressInput,T('field.wgAddress.help')),
        field(T('field.localPrivateKey'),privateKey,T('field.localPrivateKey.help'))]),
      h('div',{className:'vpn-subsection'},[node('h3','vpn-section-title',T('wg.peers')),peerList,button(T('peer.add'),async () => {if(peers.length>=8)throw new Error(T('error.maxPeers'));addPeer();dirty=true;},true)])
    ]));
    else if (currentDriver==='tun') driverSpecific.appendChild(h('div',{className:'vpn-subsection'},[
      node('h3','vpn-section-title',T('tun.title')),
      node('p','vpn-subtle',T('tun.intro')),
      h('div',{className:'vpn-fields'},[field(T('field.tunName'),tunName,T('field.tunName.help')),field(T('field.tunAliasShort'),tunAlias,T('field.tunAlias.help'))])
    ]));
    else {
      const name=M.drivers[currentDriver].name;
      coreConfig.setAttribute('aria-label',T('field.nativeConfig',{name}));
      driverSpecific.appendChild(h('div',{className:'vpn-subsection'},[
        node('h3','vpn-section-title',T('proxy.title',{name})),
        node('p','vpn-subtle',T('proxy.intro')),
        h('div',{className:'vpn-fields'},[
          field(T('field.upstream'),upstream,T('field.upstream.help'),currentDriver!=='sing_box'),
          currentDriver==='sing_box'?field(T('field.upstreamIP.optional'),upstreamIP,T('field.upstreamIP.help')):null
        ]),
        linksPanel,
        h('details',{className:'vpn-advanced vpn-proxy-advanced'},[
          node('summary',null,T('proxy.advanced')),field(T('field.configMode'),configMode),routingPanel,nativePanel
        ]),
        node('p','vpn-field-help',T('proxy.storageHint'))
      ]));
      linksPanel.replaceChildren(
        field(T('field.shareLinks'),shareLinks,T('field.shareLinks.help')),
        actions([button(T('proxy.detect'),async()=>{
          nodeOptions(S.parse(shareLinks.value,currentDriver),0);dirty=true;
          say('proxy.detected',{count:nodeNames.length});
        },true)]),field(T('field.node'),nodeSelect,T('field.node.help'))
      );
      routingPanel.replaceChildren(node('p','vpn-subtle',T('proxy.routingIntro')),
        h('div',{className:'vpn-fields'},[field(T('field.directCIDRs'),directCIDRs,T('field.directCIDRs.help')),field(T('field.directDomainsLong'),directDomains,T('field.directDomains.help')),
          field(T('field.bootstrapDNS'),bootstrapDNS,T('field.bootstrapDNS.help')),field(T('field.hijackDNS'),hijackDNS,T('field.hijackDNS.help')),field(T('field.proxyDNS'),proxyDNS,T('field.proxyDNS.help'))])
      );
      nativePanel.replaceChildren(field(T('field.nativeConfig',{name}),coreConfig,T('field.nativeConfig.help')));
      renderProxyMode();
    }
  }
  async function openEditor(record) {
    if (dirty && !await F.confirm({title:T('confirm.leave.title'),message:T('confirm.leave.message'),confirmText:T('confirm.leave.confirm'),cancelText:T('confirm.leave.cancel')})) return;
    editing=!!record;savedDriver=record?(record.data.driver || 'wireguard'):'';keyInput.readOnly=editing;
    const next=record ? {key:record.key,...record.data} : M.allocation(records);
    keyInput.value=next.key;
    fill(record ? record.data : {driver:'wireguard',slot:next.slot,mtu:1420,addresses:[],listen_port:0,peers:[{allowed_ips:['0.0.0.0/0'],keepalive:25}],remote_routes:[]});
    if(record && ['mihomo','sing_box'].includes(currentDriver)) {
      const response=await F.action('core_form',{key:record.key});proxyForm(response.result||{mode:'empty'});
      if(storedMode==='native')driverSpecific.querySelector('details').open=true;
    }
    if (editing) setMessage(editorTitle,'editor.edit',{key:record.key});else setMessage(editorTitle,'editor.new');
    editor.hidden=false;createOutletButton.classList.add('secondary');list.hidden=!records.length;dirty=false;message('');editor.scrollIntoView({block:'start',behavior:'smooth'});
  }
  const types=h('div',{className:'vpn-types'},Object.keys(M.drivers).map(id => {
    const driver=M.drivers[id];
    const el=button('',async () => {
      if (id===currentDriver) return;
      const status=statuses[selected()];
      if (editing && status && !['down','deleted'].includes(status.phase)) throw new Error(T('error.teardownFirst'));
      if (dirty && !await F.confirm({title:T('confirm.switch.title'),message:T('confirm.switch.message'),confirmText:T('confirm.switch.confirm'),cancelText:T('action.cancel')})) return;
      const slot=Number(slotInput.value)||1;
      fill({driver:id,slot,mtu:1420,peers:id==='wireguard'?[{allowed_ips:['0.0.0.0/0'],keepalive:25}]:undefined});
      dirty=true;
    },true);
    el.className='vpn-type';bind(el,'aria-label',()=>driver.name);el.append(node('strong','',()=>driver.name),node('span','',()=>driver.description));driverButtons[id]=el;return el;
  }));
  const advanced=h('details',{className:'vpn-advanced'},[
    node('summary',null,L('editor.advanced')),h('div',{className:'vpn-fields'},[field(L('field.slot'),slotInput,L('field.slot.help')),field(L('field.mtu'),mtuInput)]),wgAdvanced,proxyAdvanced,
    button(L('editor.readJSON'),async () => {rawConfig.value=JSON.stringify(M.profile(values(),original,records,selected()),null,2);rawDirty=false;},true),rawConfig,
    button(L('editor.applyJSON'),async () => {
      const value=JSON.parse(rawConfig.value);if(!value || typeof value!=='object' || Array.isArray(value))throw new Error(T('error.profileObject'));
      const keep=['mihomo','sing_box'].includes(currentDriver) && value.driver===currentDriver && value.config_secret===original.config_secret;
      const draft=keep?{storedMode,mode:configMode.value,nodes:nodeNames,selected:Number(nodeSelect.value),options:proxyOptions(),links:shareLinks.value,native:coreConfig.value}:null;
      fill(value);
      if(draft) {proxyForm({mode:draft.storedMode,nodes:draft.nodes,selected:draft.selected,options:draft.options});configMode.value=draft.mode;shareLinks.value=draft.links;coreConfig.value=draft.native;renderProxyMode();}
      dirty=true;notify(T('editor.jsonApplied'));
    },true)
  ]);
  rawConfig.addEventListener('input',()=>{rawDirty=true;});
  async function save(apply) {
    if (rawDirty) throw new Error(T('error.rawDirty'));
    const key=selected(), profile=M.profile(values(),original,records,key), text=coreConfig.value.trim();
    if (['mihomo','sing_box'].includes(currentDriver) && !profile.config_secret && (!editing || savedDriver!==currentDriver))
      profile.config_secret='core_'+currentDriver+'_'+key;
    const managed=['mihomo','sing_box'].includes(currentDriver), links=shareLinks.value.trim();
    let imported=null;
    if(managed && configMode.value==='links') {
      if(links)imported=S.create(currentDriver,links,nodeSelect.value,proxyOptions());
      else {if(storedMode!=='links')throw new Error(T('error.linksRequired'));proxyOptions();}
    } else if(managed) {
      if(text) {try {const parsed=JSON.parse(text);if(!parsed || typeof parsed!=='object' || Array.isArray(parsed))throw new Error();}catch(error){throw new Error(T('error.coreJSON'));}}
      else if(storedMode!=='native')throw new Error(T('error.nativeRequired'));
    }
    // Validate every local field before writing any credential or draft.
    if (privateKey.value.trim() && !/^[A-Za-z0-9+/]{43}=$/.test(privateKey.value.trim())) throw new Error(T('error.privateKey'));
    peers.forEach(p=>{if(p.psk.value.trim() && !/^[A-Za-z0-9+/]{43}=$/.test(p.psk.value.trim()))throw new Error(T('error.psk'));});
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
      say('save.applying');
      try {
        const response=await F.action('apply',{key});
        const result=response && response.result || {};
        say(result.phase==='starting'?'save.starting':'save.applied');
      } catch (error) { await reload();throw error; }
    } else say('save.draftOnly');
    await reload();notify(T(apply?'save.applySubmitted':'save.draftSaved'));
  }
  editor.append(
    h('div',{className:'vpn-heading'},[editorTitle,button(L('editor.close'),async () => {
      if(dirty && !await F.confirm({title:T('confirm.discard.title'),message:T('confirm.discard.message'),confirmText:T('confirm.discard.confirm'),cancelText:T('confirm.discard.cancel')}))return;
      privateKey.value='';coreConfig.value='';shareLinks.value='';importConfig.value='';peers.forEach(p=>{p.psk.value='';});dirty=false;editor.hidden=true;list.hidden=false;createOutletButton.classList.remove('secondary');
    },true)]),types,
    h('div',{className:'vpn-fields'},[field(L('field.key'),keyInput,L('field.key.help'))]),
    driverSpecific,advanced,
    h('div',{className:'vpn-savebar'},[node('span','vpn-field-help',L('editor.saveHint')),actions([button(L('editor.saveDraft'),()=>save(false),true),button(L('editor.saveApply'),()=>save(true))])])
  );
  editor.addEventListener('input',()=>{dirty=true;});
  const detailPanel=h('section',{className:'vpn-panel vpn-details',attrs:{hidden:true}}), detailOutput=h('pre',{className:'vpn-raw'});
  const detailTitle=setMessage(h('h2'),'details.title');
  detailPanel.append(h('div',{className:'vpn-heading'},[detailTitle,button(L('details.close'),async()=>{detailPanel.hidden=true;detailOutput.textContent='';},true)]),detailOutput);
  const healthPhases={unknown:['health.unknown',''],checking:['health.checking',''],healthy:['health.healthy','ready'],unhealthy:['health.unhealthy','error'],stale:['health.stale',''],unavailable:['health.unavailable','']};
  // Results carry a reason code; the runtime's own text is the fallback for unknown reasons.
  function healthMessage(result) {
    const key='health.reason.'+result.reason;
    return result.reason && Object.prototype.hasOwnProperty.call(I.messages['zh-CN'],key)?T(key,{code:result.status_code}):result.message;
  }
  function healthSummary(key) {
    const value=healthStates[key] || {}, phase=healthPhases[value.state] || healthPhases.unknown, result=value.result;
    const row=h('div',{className:'vpn-health-result',attrs:{role:'status','aria-live':'polite'}},[
      h('span',{className:'vpn-badge',attrs:{'data-tone':phase[1]},text:T(phase[0])}),
      result && ['healthy','unhealthy'].includes(value.state)?node('span','vpn-health-time',result.latency_ms+' ms · '+new Date(result.checked_at).toLocaleTimeString(I.locale())):null
    ]);
    if(result && value.state==='unhealthy')row.appendChild(node('span','vpn-health-message',healthMessage(result)+(result.consecutive_failures>1?' · '+T('health.failures',{count:result.consecutive_failures}):'')));
    return row;
  }
  async function refreshHealth() {
    clearTimeout(healthPoll);
    const response=await F.action('health_status',{});
    healthStates={};((response.result || {}).items || []).forEach(value=>{healthStates[value.key]=value;});
    renderList();
    const values=Object.values(healthStates), checking=values.some(v=>v.state==='checking');
    if(checking || values.some(v=>v.settings.enabled))healthPoll=setTimeout(()=>refreshHealth().catch(notifyError),checking?1000:5000);
    F.requestResize();
  }
  const phases={applied:['phase.ready','ready'],configured:['phase.ready','ready'],starting:['phase.starting',''],failed:['phase.failed','error'],error:['phase.error','error'],down:['phase.stopped',''],deleted:['phase.stopped','']};
  async function showDetails(key,logs) {
    const value=await F.action(logs?'core_logs':'inspect',{key});
    setMessage(detailTitle,logs?'details.logs':'details.runtime',{key});
    detailOutput.textContent=JSON.stringify(value.result || value,null,2);detailPanel.hidden=false;
    detailPanel.scrollIntoView({block:'nearest',behavior:'smooth'});
  }
  function renderList() {
    count.textContent=String(records.length);list.replaceChildren();list.className=records.length?'vpn-list':'';list.hidden=!records.length && !editor.hidden;
    if (!records.length) {list.appendChild(h('div',{className:'vpn-empty'},[
      node('div','vpn-icon','↗'),node('h2','',T('list.emptyTitle')),node('p','',T('list.emptyBody')),button(T('list.create'),()=>openEditor(),true)
    ]));return;}
    records.forEach(record=>{
      const profile=record.data, driver=M.drivers[profile.driver || 'wireguard'] || {name:profile.driver,short:'?'}, status=statuses[record.key] || {};
      const phase=phases[status.phase] || ['phase.notApplied',''], name=status.local_interface || (profile.driver && profile.driver!=='wireguard'?'veervpn':'veerwg')+profile.slot;
      const metadata=h('dl',{className:'vpn-metadata'});
      const wg=!profile.driver || profile.driver==='wireguard';
      const addresses=profile.addresses && profile.addresses.length?profile.addresses:status.wan_addresses || [];
      [[T('list.interface'),name],[T(wg?'field.wgAddress':'field.wanAddress'),addresses.join(', ') || T(wg?'list.notConfigured':'list.assignedOnApply')],
        [T(wg?'list.peerRouting':profile.driver==='tun'?'list.tunInterface':'field.upstream'),wg?T('list.hostRoutes'):profile.driver==='tun'?profile.tun_interface:profile.upstream_interface],
        [T('list.attach'),T('list.attachValue')]].forEach(pair=>metadata.append(h('div',{},[node('dt','',pair[0]),node('dd','',pair[1])])));
      const card=h('article',{className:'vpn-outlet'},[
        h('div',{className:'vpn-card-top'},[h('div',{className:'vpn-card-heading'},[node('div','vpn-icon',driver.short),h('div',{},[node('h3','',record.key),node('p','vpn-caption',driver.name)])]),h('span',{className:'vpn-badge',attrs:{'data-tone':phase[1]},text:T(phase[0])})]),metadata,
        status.error?node('p','vpn-card-error',status.error):null,
        healthStates[record.key] && !['unknown','unavailable'].includes(healthStates[record.key].state)?h('div',{className:'vpn-health-line'},[healthSummary(record.key)]):null,
        h('div',{className:'vpn-card-footer'},[
          button(T('list.edit'),()=>openEditor(record),true),button(T('list.status'),()=>showDetails(record.key,false),true),
          button(T('list.healthCheck'),async()=>{await F.action('health_check',{key:record.key});await refreshHealth();},true),
          button(T('list.teardown'),async()=>{
            if (!await F.confirm({title:T('confirm.teardown.title',{key:record.key}),message:T('confirm.teardown.message'),confirmText:T('list.teardown'),cancelText:T('action.cancel'),danger:true}))return;
            await F.action('teardown',{key:record.key});await reload();
          },true),
          button(T('list.delete'),async()=>{
            if (!await F.confirm({title:T('confirm.delete.title',{key:record.key}),message:T('confirm.delete.message'),confirmText:T('list.delete'),cancelText:T('action.cancel'),danger:true}))return;
            await F.action('delete_profile',{key:record.key});
            if(editing && keyInput.value===record.key) {editor.hidden=true;editing=false;dirty=false;original={};}
            detailPanel.hidden=true;await reload();say('list.deleted',{key:record.key});
          },true),
          ['mihomo','sing_box'].includes(profile.driver)?button(T('list.coreLogs'),async()=>{
            if(await F.confirm({title:T('confirm.logs.title'),message:T('confirm.logs.message'),confirmText:T('confirm.logs.confirm'),cancelText:T('action.cancel')}))await showDetails(record.key,true);
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
    if(state.some(r=>r.data && r.data.phase==='starting'))statusPoll=setTimeout(()=>reload().catch(notifyError),2500);
    await refreshHealth();
    F.requestResize();
  }
  const coreVersion=setMessage(h('div',{className:'vpn-core-version'}),'core.notInstalled'),coreInfo=node('p','vpn-status-line',''),coreProgress=h('progress',{className:'vpn-progress',attrs:{hidden:true,max:100}});
  const installVersion=bind(input(L('core.installVersion'),''),'placeholder',L('core.installVersion.placeholder')),installDigest=input('SHA256','');
  const installed=bind(h('select',{className:F.classes.input}),'aria-label',L('core.installedVersions.label'));
  const coreName=node('h2','','Mihomo'),coreOptions={},coreDetails=h('div',{className:'vpn-panel'});
  const jobPhases=['resolving','downloading','verifying','ready','failed'];
  function setCoreStatus(status) {
    coreStatus=status;
    if (status.version) setRaw(coreVersion,status.version);else setMessage(coreVersion,'core.notInstalled');
    installed.replaceChildren(h('option',{attrs:{value:''},text:T('core.chooseInstalled')}));
    (status.versions || []).forEach(v=>installed.appendChild(h('option',{attrs:{value:v.version},text:v.version+(v.version===status.version?' · '+T('core.default'):'')})));
    installed.value=status.version || '';
    const job=status.install;
    coreInfo.textContent=job?(jobPhases.includes(job.state)?T('core.job.'+job.state):job.state)+(job.downloaded_bytes?' · '+(job.downloaded_bytes/1048576).toFixed(1)+' MiB':'')+(job.error?' · '+job.error:''):(status.previous?T('core.previous',{version:status.previous}):T('core.intro'));
    const active=job && ['resolving','downloading','verifying'].includes(job.state);
    coreProgress.hidden=!active;
    if(active && job.total_bytes)coreProgress.value=100*job.downloaded_bytes/job.total_bytes;else coreProgress.removeAttribute('value');
    F.requestResize();return active;
  }
  async function refreshCore() {
    clearTimeout(corePoll);const sequence=++coreSequence,driver=coreDriver;
    const response=await F.action('core_status',{driver});
    if(sequence!==coreSequence || driver!==coreDriver)return;
    if(!response || !response.result)throw new Error(T('error.coreStatus'));
    if(setCoreStatus(response.result))corePoll=setTimeout(()=>refreshCore().catch(notifyError),1500);
  }
  coreDetails.append(coreName,coreVersion,coreInfo,coreProgress,h('div',{className:'vpn-fields'},[field(L('core.installVersion'),installVersion),field(L('core.installedVersions'),installed)]),
    h('details',{className:'vpn-advanced'},[node('summary',null,L('core.digest')),field('SHA256',installDigest,L('core.digest.help'))]),
    h('div',{className:'vpn-savebar'},[actions([
      button(L('core.install'),async()=>{++coreSequence;clearTimeout(corePoll);await F.action('core_install',{driver:coreDriver,version:installVersion.value.trim(),sha256:installDigest.value.trim()});await refreshCore();}),
      button(L('core.refresh'),refreshCore,true),button(L('core.select'),async()=>{if(!installed.value)throw new Error(T('error.chooseVersion'));await F.action('core_select',{driver:coreDriver,version:installed.value});await refreshCore();},true),
      button(L('core.rollback'),async()=>{await F.action('core_rollback',{driver:coreDriver});await refreshCore();},true),
      button(L('core.remove'),async()=>{if(!installed.value)throw new Error(T('error.chooseVersion'));if(!await F.confirm({title:T('core.remove.title'),message:T('core.remove.message',{version:installed.value}),confirmText:T('list.delete'),cancelText:T('action.cancel'),danger:true}))return;await F.action('core_remove',{driver:coreDriver,version:installed.value});await refreshCore();},true)
    ])]),node('p','vpn-subtle',L('core.selectHint')));
  corePanel.appendChild(h('div',{className:'vpn-core-layout'},[
    h('div',{className:'vpn-core-options'},['mihomo','sing_box'].map(id=>{
      const el=button('',async()=>{coreDriver=id;coreName.textContent=M.drivers[id].name;Object.keys(coreOptions).forEach(k=>coreOptions[k].setAttribute('aria-pressed',String(k===id)));installVersion.value='';installDigest.value='';await refreshCore();},true);
      el.className='vpn-type';el.setAttribute('aria-pressed',String(id===coreDriver));el.append(node('strong','',M.drivers[id].name),node('span','',()=>M.drivers[id].description));coreOptions[id]=el;return el;
    })),coreDetails
  ]));
  const outletTab=h('button',{className:'vpn-tab',attrs:{type:'button',role:'tab','aria-selected':'true'}},[bind(document.createTextNode(''),'text',L('tab.outlets')),count]);
  const coreTab=bind(h('button',{className:'vpn-tab',attrs:{type:'button',role:'tab','aria-selected':'false'}}),'text',L('tab.cores'));
  function switchTab(core) {
    outletPanel.hidden=core;corePanel.hidden=!core;createOutletButton.classList.toggle('secondary',core || !editor.hidden);
    outletTab.setAttribute('aria-selected',String(!core));coreTab.setAttribute('aria-selected',String(core));
    if(core)refreshCore().catch(notifyError);else{++coreSequence;clearTimeout(corePoll);}
    F.requestResize();
  }
  outletTab.addEventListener('click',()=>switchTab(false));coreTab.addEventListener('click',()=>switchTab(true));
  outletPanel.append(editor,detailPanel);
  const refreshOutletButton=button(L('action.refreshOutlets'),reload,true);
  const createOutletButton=button(L('action.newOutlet'),async()=>{switchTab(false);await openEditor();});
  const page=h('main',{className:F.classes.page+' vpn-page'},[
    actions([refreshOutletButton, createOutletButton]),
    bind(h('nav',{className:'vpn-nav',attrs:{role:'tablist'}},[outletTab,coreTab]),'aria-label',L('page.nav')),notice,outletPanel,corePanel
  ]);
  // Rerendering keeps every input value; only the open state of the rebuilt proxy section needs restoring.
  function relocalize() {
    bound.forEach(put);peers.forEach(p=>p.bound.forEach(put));
    dynamic.forEach((value,el)=>{el.textContent=T(value.key,value.params);});
    const advancedOpen=!!driverSpecific.querySelector('.vpn-proxy-advanced[open]');
    renderDriver();
    if(advancedOpen)driverSpecific.querySelector('.vpn-proxy-advanced').open=true;
    if(!nodeNames.length)nodeOptions([],0);
    renderList();
    if(coreStatus) {const chosen=installed.value;setCoreStatus(coreStatus);installed.value=chosen;}
    F.requestResize();
  }
  if (F.onLocaleChange) F.onLocaleChange(relocalize);
  window.addEventListener('pagehide',()=>{++coreSequence;clearTimeout(corePoll);clearTimeout(statusPoll);clearTimeout(healthPoll);privateKey.value='';coreConfig.value='';shareLinks.value='';importConfig.value='';});
  document.body.replaceChildren(page);
      if (F.headerActions) F.headerActions([refreshOutletButton, createOutletButton]);reload().catch(error=>message(F.errorText(error),true));
})();
