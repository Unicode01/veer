'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const {createTestHost} = require('../../../sdk/plugin/test-host.cjs');
const pluginDir = path.resolve(__dirname, '../../../plugins/vpn_core');
const PRIVATE = Buffer.alloc(32, 1).toString('base64');
const PUBLIC = Buffer.alloc(32, 2).toString('base64');
const clone = v => JSON.parse(JSON.stringify(v));
const profile = (extra = {}) => ({slot:1, addresses:['10.77.0.1/32'], peers:[{public_key:PUBLIC, endpoint:'192.0.2.2:51820', allowed_ips:['0.0.0.0/0']}], ...extra});
function fixture(config = profile(), options = {}) {
  const state = options.state || {links:[], records:{sessions:{},status:{}}, calls:[], services:[], next:10, config:'', fail:null};
  const ok = (stdout = '') => ({stdout, stderr:'', exit_code:0});
  const adapters = {
    'net.link.list': () => options.inventory || [],
    'net.link.get': name => {
      const l=state.links.find(l=>l.ifname===name);
      if(!l) throw new Error('net.link.get: link not found: '+name);
      if(options.legacyNetInfo) return {name,kind:l.linkinfo?.info_kind};
      return {name,ifindex:l.ifindex,alias:l.ifalias||'',kind:l.linkinfo?.info_kind,
        mtu:l.mtu,mac:l.address,up:(l.flags||[]).includes('UP'),peer_ifindex:l.link_index,
        peer_name:l.link,tun_vnet_hdr:options.vnetHeader===true};
    },
    'net.link.getOffloads': () => options.offloads || {},
    'process.binaryStatus': id => ({id, versions:[]}),
    'plugins.services.resolve': () => ({provider:'wan_core',service:'wan.adapter',version:'1.0.0'}),
    'plugins.resources.get': (plugin, resource, key) => state.records[resource][key] || null,
    'plugins.resources.set': (plugin, resource, key, data, enabled) => {
      state.records[resource][key] = {data,enabled};
      if (resource === 'sessions') state.records.status[key].data = {...state.records.status[key].data,...data,phase:'applied'};
      return state.records[resource][key];
    },
    'plugins.services.call': request => {
      state.services.push(clone(request));
      const p=request.payload, k=p.wan_id;
      if(request.action === 'teardown') {
        state.links=state.links.filter(l => ![p.local_interface,p.pipeline_interface].includes(l.ifname));
        state.records.sessions[k]={data:p,enabled:false};
        state.records.status[k]={enabled:false,data:{phase:'deleted',local_interface:p.local_interface,pipeline_interface:p.pipeline_interface}};
        return {};
      }
      assert.equal(request.action,'prepare_handoff');
      let local=state.links.find(l=>l.ifname===p.local_interface), peer=state.links.find(l=>l.ifname===p.pipeline_interface);
      if(!local && !peer) {
        local={ifname:p.local_interface,ifindex:state.next++,address:'02:00:00:00:00:01',linkinfo:{info_kind:'veth'}};
        peer={ifname:p.pipeline_interface,ifindex:state.next++,address:'02:00:00:00:00:02',linkinfo:{info_kind:'veth'}};
        local.link_index=peer.ifindex;peer.link_index=local.ifindex;state.links.push(local,peer);
      }
      state.records.status[k]={enabled:false,data:{...p,phase:'prepared',local_ifindex:local.ifindex,pipeline_ifindex:peer.ifindex}};
      return state.records.status[k].data;
    },
    'process.exec': request => {
      state.calls.push(clone(request));
      if(state.fail && state.fail(request)) return {...ok(),exit_code:2,stderr:PRIVATE};
      const a=request.args;
      if(request.command.endsWith('/wg')) {
        if(a[0]==='syncconf') state.config=request.stdin;
        assert.ok(!['dump','private-key'].includes(a[2]));
        return ok(a[0]==='pubkey'||a[2]==='public-key'?PUBLIC:'peer\t123');
      }
      assert.match(request.command,/\/ip$/);
      if(a.includes('route')) {assert.deepEqual(a,['-j','-4','route','show','table','all']);return ok(JSON.stringify(options.routes || []));}
      const args=a.filter(v=>!['-j','-d'].includes(v)), field=k=>args[args.indexOf(k)+1];
      assert.equal(args[0],'link');
      if(args[1]==='show') return ok(JSON.stringify(state.links));
      if(args[1]==='add') state.links.push({ifname:field('name'),ifindex:state.next++,ifalias:state.ignoreCreateAlias?'':field('alias'),linkinfo:{info_kind:'wireguard'},flags:[],mtu:1420});
      if(args[1]==='set') {const l=state.links.find(l=>l.ifname===field('dev'));if(args.includes('alias'))l.ifalias=field('alias');else {l.mtu=Number(field('mtu'));l.flags=['UP'];}}
      if(args[1]==='del') state.links=state.links.filter(l=>l.ifname!==field('dev'));
      return ok();
    }
  };
  const host=createTestHost({pluginDir:options.pluginDir||pluginDir,hostInfo:options.hostInfo,availableFeatures:options.availableFeatures,remoteInstallEnabled:options.remoteInstallEnabled,fixtures:{kv:options.kv||{},resources:{profiles:{default:{data:config,enabled:options.enabled!==false}}},secrets:options.missingKey?{}:{private_default:PRIVATE,...options.secrets}},adapters:{...adapters,...options.adapters}}).load();
  return {host,state,apply:()=>host.action('apply',{key:'default'}),maps:()=>host.state.maps};
}
test('WG is opt-in and registration/drafts do not change networking',()=>{
  const h=fixture();h.host.reconcile();assert.equal(h.state.calls.length,0);assert.equal(h.state.services.length,0);
  const snapshot=h.host.snapshot();
  assert.equal(snapshot.surface.hooks.find(h=>h.id==='wg-links').binding_required,true);
  assert.equal(snapshot.resources.hook_bindings?.['wg-links'],undefined);
  assert.ok(snapshot.manifest.compatibility.features.includes('dataplane.hook_bindings.v1'));
  assert.equal(h.host.snapshot().manifest.kind,'pipeline');assert.equal(h.host.snapshot().manifest.stability,'lab');
  assert.throws(()=>fixture(profile(),{remoteInstallEnabled:true}).apply(),/disabled while remote/);
});

test('VPN UI integrity matches the LF bytes stored in release packages',()=>{
  const fs=require('node:fs'), crypto=require('node:crypto');
  const ui=fixture().host.snapshot().surface.ui;
  const bytes=fs.readFileSync(path.join(pluginDir,ui.static_dir,ui.entry));
  assert.equal(bytes.includes('\r\n'),false,'hash-bearing UI files must use repository LF line endings');
  assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),ui.sha256);
});
test('WG publishes a segmented WAN, installs both TC directions and cleans/reapplies exactly',()=>{
  const h=fixture();h.host.action('set_key',{value:PRIVATE});const result=h.apply();
  assert.equal(result.egress_nat_interface,'veerwg1');assert.equal(result.tc_ready,true);
  const p=h.state.records.sessions.wg_default.data;
  assert.equal(p.egress_nat_redirect_mode,'prepared_l2');assert.equal(p.install_default_route,false);assert.equal(p.usable,true);
  assert.equal(p.interface_preparation.local_offloads.gso,false);
  assert.equal([...h.maps().values()][0].size,2);
  assert.equal(h.state.calls.some(r=>r.args.some(a=>a.includes(PRIVATE))),false);assert.match(h.state.config,/PrivateKey = /);
  assert.equal(h.host.snapshot().secrets.private_default,'[REDACTED]');assert.equal(h.host.action('inspect',{}).public_key,PUBLIC);
  h.apply();assert.equal(h.state.links.length,3);
  h.host.action('teardown',{});assert.equal(h.state.links.length,0);assert.equal(h.host.snapshot().kv.lease_default,undefined);
  h.apply();assert.equal(h.state.links.length,3);
});
test('WG rejects malformed configuration, legacy selectors and recursive host routes before mutation',()=>{
  const changes=[{bindings:[]},{masquerade:false},{mtu:1000},{slot:9},{addresses:['fd77::1/128']},{addresses:['192.168.01.1/24']},{addresses:['1.2.3.4\nPostUp=evil']},
    {peers:[{public_key:PUBLIC,endpoint:'host.invalid:123',allowed_ips:['0.0.0.0/0']}]},
    {peers:[{public_key:PUBLIC,endpoint:'1.2.3.4:123\nPostUp=evil',allowed_ips:['0.0.0.0/0']}]},
    {addresses:['192.0.2.1/24']},{remote_routes:['0.0.0.0/0']},{remote_routes:['192.0.2.0/24']},
    {peers:[{public_key:PUBLIC,allowed_ips:['10.0.0.0/8']}],remote_routes:['192.168.20.0/24']}];
  for(const c of changes){const h=fixture(profile(c));assert.throws(h.apply);assert.equal(h.state.calls.length,0);assert.equal(h.state.services.length,0);}
});
test('WG rejects foreign links/WAN records and validates secrets before host changes',()=>{
  for(const kind of ['link','wan','missing']){
    const h=fixture(profile(),{missingKey:kind==='missing'});
    if(kind==='link')h.state.links.push({ifname:'vwgdefault',ifalias:'foreign',linkinfo:{info_kind:'wireguard'}});
    if(kind==='wan')h.state.records.sessions.wg_default={data:{driver_plugin:'other'},enabled:true};
    assert.throws(h.apply);assert.equal(h.state.services.length,0);assert.equal(h.state.calls.some(r=>r.args.includes('add')),false);
  }
});
test('WG failure does not expose secrets and retry recovers the journaled WAN',()=>{
  const h=fixture();h.state.fail=r=>r.args[0]==='syncconf';
  assert.throws(h.apply,e=>!e.message.includes(PRIVATE)&&/failed/.test(e.message));assert.equal(h.host.snapshot().kv.lease_default.pending,true);
  h.state.fail=null;h.apply();assert.equal(h.host.snapshot().kv.lease_default.pending,undefined);
  h.host.action('teardown',{});assert.equal(h.state.links.length,0);
});
test('WG repairs ifindex changes and restores applied settings across restart, ignoring draft edits',()=>{
  const h=fixture();h.apply();const old=h.host.snapshot();
  h.state.links=h.state.links.filter(l=>l.ifname!=='vwgdefault');
  h.host.run('onTimer',{timer:{name:'wg_repair'}});assert.equal(h.state.links.length,3);
  const next=fixture(profile({slot:2}),{state:h.state,kv:old.kv});next.host.reconcile();
  assert.equal(next.host.snapshot().kv.lease_default.plan.slot,1);
  next.host.run('onDeactivate');assert.equal(next.state.links.length,0);
});
test('WG reserves slots and refuses teardown of an externally replaced link',()=>{
  const h=fixture();h.apply();const lease=clone(h.host.snapshot().kv.lease_default);lease.plan.key='other';
  assert.throws(fixture(profile(),{kv:{lease_other:lease}}).apply,/reserved/);
  assert.throws(fixture(profile({slot:2}),{state:h.state,kv:h.host.snapshot().kv}).apply,/changing the slot/);
  h.state.links.find(l=>l.ifname==='vwgdefault').ifalias='foreign';assert.throws(()=>h.host.action('teardown',{}),/unowned/);
  assert.equal(h.state.links.length,3);
});

test('WG recovers an alias failure using the journaled creation ifindex',()=>{
  const h=fixture();h.state.ignoreCreateAlias=true;h.state.fail=r=>r.args.includes('alias')&&r.args[1]==='set';
  assert.throws(h.apply,/failed/);const lease=h.host.snapshot().kv.lease_default;
  assert.ok(lease.created_ifindex>0);assert.equal(h.state.links.find(l=>l.ifname==='vwgdefault').ifalias,'');
  h.state.fail=null;h.apply();assert.equal(h.state.links.find(l=>l.ifname==='vwgdefault').ifalias,'veer:vpn_core:default');
});
test('WG multiple WANs keep their own maps and bindings during independent teardown',()=>{
  const h=fixture();h.apply();
  h.host.state.resources.get('profiles').set('second',{data:profile({slot:2}),enabled:true});
  h.host.action('set_key',{key:'second',value:PRIVATE});h.host.action('apply',{key:'second'});
  assert.equal(h.state.links.length,6);assert.equal([...h.maps().values()][0].size,4);
  h.host.action('teardown',{key:'default'});assert.equal(h.state.links.length,3);
  assert.equal([...h.maps().values()][0].size,2);
  assert.deepEqual(h.host.snapshot().resources.hook_bindings['wg-links'].data.interfaces,['vwgsecond','veerwgp2']);
  h.host.action('teardown',{key:'second'});assert.equal(h.state.links.length,0);
  assert.equal(h.host.snapshot().resources.hook_bindings['wg-links'].enabled,false);
  assert.deepEqual(h.host.snapshot().resources.hook_bindings['wg-links'].data.interfaces,[]);
});
test('WG rejects a mismatched WAN veth peer without enabling TC forwarding',()=>{
  const h=fixture();h.apply();h.state.links.find(l=>l.ifname==='veerwgp1').link_index=999;
  assert.throws(h.apply,/not ready/);assert.equal([...h.maps().values()][0].size,0);
});
test('WG disabled profiles are torn down on reconciliation',()=>{
  const h=fixture();h.apply();h.host.state.resources.get('profiles').get('default').enabled=false;
  h.host.reconcile();assert.equal(h.state.links.length,0);assert.equal(h.host.snapshot().kv.lease_default,undefined);
});

test('WG legacy cleanup accepts only the owned top-level nft marker and never flushes global state',()=>{
  const plan={key:'default',interface:'vwgdefault',owner:'veer:vpn_core:default',nft:'veer_wg_1',table:52001,
    bindings:[{family:'4',priority:22032,lan_interface:'br-lan',source:'192.168.10.0/24',destination:'0.0.0.0/0'}],peers:[{allowed_ips:['0.0.0.0/0']}],bypass:['192.168.10.0/24']};
  for(const owned of [true,false]) {
    const mutations=[];
    const host=createTestHost({pluginDir,fixtures:{kv:{lease_default:{active:true,plan}}},adapters:{'net.link.get':()=>({}),'process.exec':r=>{
      const a=r.args,ok=stdout=>({stdout,exit_code:0});
      assert.ok(!a.includes('flush'));
      if(r.command.endsWith('/nft')) {
        if(a[0]==='-j')return ok(JSON.stringify({nftables:[{table:{name:'veer_wg_1'}}]}));
        if(a[0]==='list')return ok(owned?'table inet veer_wg_1 {\n comment "veer:vpn_core:default"\n chain forward {\n }\n}\n':'table inet veer_wg_1 {\n chain forward {\n comment "veer:vpn_core:default"\n }\n}\n');
        mutations.push('nft');return ok('');
      }
      if(a.includes('link')&&a.includes('show'))return ok(JSON.stringify([{ifname:'vwgdefault',ifindex:10,ifalias:plan.owner,linkinfo:{info_kind:'wireguard'}}]));
      if(a.includes('show'))return ok('[]');
      mutations.push('ip');return ok('');
    }}}).load();
    assert.throws(()=>host.action('apply',{}),/Save and enable|legacy/i);
    if(owned) {host.action('teardown',{});assert.deepEqual(mutations,['ip','nft']);assert.equal(host.snapshot().kv.lease_default,undefined);}
    else {assert.throws(()=>host.action('teardown',{}),/owned by another/);assert.deepEqual(mutations,[]);assert.ok(host.snapshot().kv.lease_default);}
  }
});


test('WG selects a probed optional object and coordinates GSO, with missing-artifact fallback',t=>{
  const fs=require('node:fs'), os=require('node:os');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'veer-wg-capability-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  fs.cpSync(pluginDir,dir,{recursive:true});
  fs.writeFileSync(path.join(dir,'wg_adapter.o'),'base-test-object');
  fs.writeFileSync(path.join(dir,'wg_adapter-kfuncs.o'),'enhanced-test-object');
  const options={pluginDir:dir,availableFeatures:['dataplane.kfuncs.handoff.v1']};
  const enhanced=fixture(profile(),options);enhanced.apply();
  assert.equal(enhanced.host.snapshot().surface.objects[0].path,'wg_adapter-kfuncs.o');
  const request=enhanced.state.records.sessions.wg_default.data.interface_preparation;
  assert.equal(request.local_gso.max_segs,65535);assert.equal(request.local_offloads.gso,true);assert.equal(request.pipeline_offloads.gro,true);
  assert.equal(enhanced.host.state.resources.get('status').get('default').data.dataplane,'kfuncs');
  fs.unlinkSync(path.join(dir,'wg_adapter-kfuncs.o'));
  const fallback=fixture(profile(),options);fallback.apply();
  assert.equal(fallback.host.snapshot().surface.objects[0].path,'wg_adapter.o');
  assert.equal(fallback.state.records.sessions.wg_default.data.interface_preparation.local_offloads.gso,false);
});


function vpnFixture(driver = 'mihomo', extra = {}, options = {}) {
  const state = options.state || {links:[], records:{sessions:{},status:{}}, calls:[], services:[], next:10};
  const procs = options.procs || {};
  const specs = [];
  const adapters = {
    'process.status': id => procs[id] || {id,state:'stopped',started_at:0},
    'process.stop': id => {
      if (procs[id]) { delete procs[id]; state.links = state.links.filter(l => l.ifname !== 'vtun' + id.slice(4)); }
      return {id,state:'stopped'};
    },
    'process.start': spec => {
      specs.push(clone(spec));
      if (!procs[spec.id]) {
        procs[spec.id] = {id:spec.id,state:'running',pid:100,starts:1,started_at:1000*specs.length};
        if (!options.delayed) state.links.push({ifname:'vtun'+spec.id.slice(4),ifindex:state.next++,ifalias:'',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
      }
      return procs[spec.id];
    },
    'process.restart': id => {
      const p=procs[id];
      if (p.starts >= 4) throw new Error('restart budget exhausted');
      p.starts++;p.started_at+=1000;
      state.links=state.links.filter(l=>l.ifname!=='vtun'+id.slice(4));
      state.links.push({ifname:'vtun'+id.slice(4),ifindex:state.next++,ifalias:'',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
      return {...p,state:'restarting'};
    }
  };
  const h = fixture({driver,slot:1,mtu:1420,addresses:['10.78.0.1/32'],upstream_interface:'eth0',...extra},
    {...options,state,secrets:{core_default:JSON.stringify(driver === 'mihomo' ? {proxies:[{password:'sensitive-core-password'}],tun:{'auto-route':true}} : {outbounds:[{type:'direct',tag:'direct'}]}),...options.secrets},adapters:{...adapters,...options.adapters}});
  return {...h,procs,specs};
}

const healthTick = h => h.host.run('onTimer',{timer:{name:'vpn_health'}});
const healthStatus = h => h.host.action('health_status',{}).items.find(v=>v.key==='default');
test('VPN health settings are bounded and reject credentials, malformed URLs and invalid status codes',()=>{
  const settings=require('../../../plugins/vpn_core/health-check').settings;
  assert.equal(settings().enabled,false);
  for(const value of [{enabled:'yes'},{url:'http://user:secret@example.com/'},{url:'http://a..b/'},{url:'https://a/#secret'},
    {url:'https://a/\nheader'},{url:'ftp://example.com'},{url:'http://example.com:65536'},
    {resolver_ip:'127.00.0.1'},{resolver_ip:'300.1.1.1'},{interval_seconds:14},{timeout_ms:10001},{expected_status:99},{extra:true}])assert.throws(()=>settings(value));
  assert.equal(settings({expected_status:0,url:'http://192.168.20.1:8080/health'}).expected_status,0);
});
for(const driver of ['wireguard','mihomo','sing_box'])test('VPN health '+driver+' uses the applied WAN and does not mutate forwarding or restart the core',()=>{
  const requests=[], options={adapters:{'net.http.request':r=>{requests.push(clone(r));return {status_code:204};}}};
  const h=driver==='wireguard'?fixture(profile(),options):vpnFixture(driver,{},options);
  assert.throws(()=>h.host.action('health_check',{}),/尚未就绪/);
  h.apply();const before=clone(h.state),specs=h.specs?.length;
  assert.equal(healthStatus(h).state,'unknown');assert.equal(h.host.state.timers.has('vpn_health'),false);
  h.host.action('health_check',{});healthTick(h);
  const value=healthStatus(h);assert.equal(value.state,'healthy');assert.equal(value.result.status_code,204);
  assert.equal(value.result.consecutive_failures,0);assert.ok(value.result.last_success_at>0);
  assert.equal(requests.length,1);assert.equal(requests[0].interface,driver==='wireguard'?'veerwg1':'veervpn1');
  assert.equal(requests[0].source_ip,driver==='wireguard'?'10.77.0.1':'10.78.0.1');
  assert.equal(requests[0].follow_redirects,false);assert.equal(requests[0].resolver_ip,'1.1.1.1');
  assert.deepEqual(h.state,before);assert.equal(h.specs?.length,specs);assert.equal(h.host.state.timers.has('vpn_health'),false);
});
test('VPN health counts failures, sanitizes errors, checks HTTP status and recovers without restarting',()=>{
  let response=()=>{throw new Error('password=sensitive-core-password TLS certificate failed');};
  const h=vpnFixture('mihomo',{}, {adapters:{'net.http.request':()=>response()}});h.apply();
  const check=()=>{h.host.action('health_check',{});healthTick(h);return healthStatus(h);};
  assert.equal(check().result.reason,'tls');assert.equal(check().result.consecutive_failures,2);
  assert.ok(!JSON.stringify(healthStatus(h)).includes('sensitive-core-password'));
  response=()=>({status_code:302});assert.equal(check().result.reason,'http_status');
  response=()=>{throw new Error('deadline exceeded');};assert.equal(check().result.reason,'timeout');
  response=()=>({status_code:201});h.host.action('health_settings',{settings:{expected_status:0}});
  assert.equal(check().state,'healthy');assert.equal(healthStatus(h).result.consecutive_failures,0);assert.equal(h.specs.length,1);
});
test('VPN health deduplicates queued work, rejects old generations and expires abandoned jobs',()=>{
  let requests=0;const h=fixture(profile(),{adapters:{'net.http.request':()=>{requests++;return {status_code:204};}}});h.apply();
  const queued=[];h.host.context.worker={dispatch:(name,handler,payload)=>queued.push(clone(payload))};
  h.host.action('health_check',{});h.host.action('health_check',{});assert.equal(queued.length,1);
  h.host.action('health_settings',{settings:{url:'http://192.168.20.1/'}});
  h.host.run('onHealthProbe',{payload:queued[0]});healthTick(h);assert.equal(requests,0);
  h.host.action('health_check',{});const op=h.host.state.operations.get('health_default');op.input.started_at-=20000;
  healthTick(h);assert.equal(healthStatus(h).result.reason,'timeout');
  h.host.action('health_check',{});const newest=queued.at(-1);
  h.host.run('onHealthProbe',{payload:queued[1]});healthTick(h);assert.equal(healthStatus(h).state,'checking');
  h.host.run('onHealthProbe',{payload:newest});healthTick(h);assert.equal(healthStatus(h).state,'healthy');
  assert.equal(h.host.state.operations.size,1,'repeated probes reuse one durable record');
});
test('VPN health cannot publish success after a link or core generation changes',()=>{
  for(const change of ['link','core','teardown']) {
    let h;h=vpnFixture('mihomo',{}, {adapters:{'net.http.request':()=>{
      if(change==='link')h.state.links.find(l=>l.ifname==='vtundefault').ifindex++;
      if(change==='core')h.procs.vpn_default.started_at++;
      if(change==='teardown')h.host.action('teardown',{});
      return {status_code:204};
    }}});h.apply();h.host.action('health_check',{});healthTick(h);
    assert.ok(['stale','unavailable'].includes(healthStatus(h).state));assert.notEqual(healthStatus(h).result?.state,'healthy');
  }
});
test('VPN health automatic probes are opt-in, respect cadence and keep lease enumeration complete',()=>{
  let requests=0;const h=fixture(profile(),{adapters:{'net.http.request':()=>{requests++;return {status_code:204};}}});h.apply();
  // Additional health records must not push applied leases beyond the first KV page.
  for(let i=0;i<45;i++)h.host.context.kv.set('health_padding_'+i,{});
  healthTick(h);assert.equal(requests,0);
  h.host.action('health_check',{});healthTick(h);assert.equal(requests,1);
  h.host.action('health_settings',{settings:{enabled:true,interval_seconds:15}});healthTick(h);healthTick(h);healthTick(h);
  assert.equal(requests,2,'enabling auto probes must immediately check the new settings');
  h.host.state.operations.get('health_default').input.started_at-=16000;healthTick(h);healthTick(h);assert.equal(requests,3);
  h.host.action('health_settings',{settings:{enabled:false}});healthTick(h);assert.equal(requests,3);
  h.host.reconcile();assert.equal(h.host.snapshot().kv.lease_default.active,true);
  h.host.run('onDeactivate');assert.equal(h.host.state.timers.has('vpn_health'),false);assert.equal(h.state.links.length,0);
});

for(const driver of ['mihomo','sing_box']) {
  test('VPN '+driver+' allocates its internal WAN address, publishes it, and pins it across reapply and recovery',()=>{
    const h=vpnFixture(driver,{addresses:undefined});
    const applied=h.apply(), address=applied.egress_nat_source_ip;
    assert.ok(address);assert.deepEqual(applied.wan_addresses,[address+'/32']);
    assert.deepEqual(h.host.snapshot().kv.lease_default.settings.addresses,applied.wan_addresses);
    assert.equal(h.host.snapshot().resources.profiles.default.data.addresses,undefined,'applying must not rewrite the draft');
    const routeReads=h.state.calls.filter(r=>r.args.includes('route')).length;
    h.apply();h.host.reconcile();
    assert.equal(h.state.records.sessions.vpn_default.data.ipv4,address);
    assert.equal(h.state.calls.filter(r=>r.args.includes('route')).length,routeReads);
    h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
    h.host.run('onTimer',{timer:{name:'wg_repair'}});
    h.host.run('onTimer',{timer:{name:'wg_repair'}});
    assert.equal(h.state.records.sessions.vpn_default.data.ipv4,address);
  });
}

test('VPN automatic WAN allocation avoids host networks, non-default routes, drafts and active leases',()=>{
  const h=vpnFixture('mihomo',{addresses:undefined},{inventory:[{name:'br-lan',addresses:['10.78.1.254/24']}],routes:[{dst:'default'},{dst:'10.78.9.1/32'}]});
  h.host.state.resources.get('profiles').set('draft',{data:{driver:'wireguard',slot:2,addresses:['10.78.17.1/32']},enabled:false});
  h.host.context.kv.set('lease_running',{active:true,plan:{slot:3,driver:'mihomo',interface:'vtunrunning',local:'veervpn3',pipeline:'veervpnp3',addresses:['10.78.25.1/32']}});
  const result=h.apply();
  assert.ok(!['10.78.1.1','10.78.9.1','10.78.17.1','10.78.25.1'].includes(result.egress_nat_source_ip));
  assert.equal(h.state.records.sessions.vpn_default.data.ipv4,result.egress_nat_source_ip);
});

test('VPN allocation fails before WAN or process mutation if inventory fails or all pools conflict',()=>{
  const cases=[{inventory:[{addresses:['10.0.0.1/8','172.16.0.1/12','192.168.0.1/16','198.18.0.1/15']}]},
    {adapters:{'net.link.list':()=>{throw new Error('inventory unavailable');}}}];
  for(const options of cases){
    const h=vpnFixture('mihomo',{addresses:undefined},options);
    assert.throws(h.apply,/No free internal WAN address|inventory unavailable/);
    assert.equal(h.specs.length,0);assert.equal(h.state.services.length,0);assert.equal(h.host.snapshot().kv.lease_default,undefined);
  }
});

test('VPN installs official cores through a background host task without changing active WANs',()=>{
  const requests=[];
  const h=vpnFixture('mihomo',{}, {hostInfo:{os:'linux',arch:'amd64'},adapters:{'process.binaryInstall':request=>{requests.push(clone(request));return {id:request.id,versions:[],install:{state:'resolving'}};}}});
  const result=h.host.action('core_install',{driver:'mihomo',version:'1.19.33'});
  assert.equal(result.install.state,'resolving');assert.equal(h.state.services.length,0);assert.equal(h.specs.length,0);
  assert.equal(requests[0].release_url,'https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33');
  assert.match(requests[0].asset,/amd64-compatible/);assert.deepEqual(requests[0].check_args,['-v']);
  h.host.action('core_install',{driver:'sing_box'});
  assert.equal(requests[1].release_url,'https://api.github.com/repos/SagerNet/sing-box/releases/latest');
  assert.equal(requests[1].archive_path,'sing-box-{version}-linux-amd64/sing-box');
  for(const payload of [{driver:'wireguard'},{driver:'mihomo',version:'../../tmp'},{driver:'mihomo',sha256:'bad'}]) assert.throws(()=>h.host.action('core_install',payload));
});

test('VPN managed default updates only explicitly reapplied WANs and keeps recovery pinned',()=>{
  const selected={id:'mihomo',path:'/opt/veer/plugins.veer-state/cores/vpn_core/mihomo/linux-amd64/v1/mihomo',versions:[]};
  const h=vpnFixture('mihomo',{}, {adapters:{'process.binaryStatus':()=>clone(selected)}});
  h.apply();const old=h.specs[0].command;
  assert.equal(old,selected.path);
  selected.path=selected.path.replace('/v1/','/v2/');
  h.host.reconcile();assert.equal(h.specs.at(-1).command,old);
  h.apply();assert.equal(h.specs.at(-1).command,selected.path);
});

test('VPN core rollback chooses the previous version and never restarts processes implicitly',()=>{
  const selected={id:'mihomo',version:'v2',previous:'v1',versions:[]};const calls=[];
  const h=vpnFixture('mihomo',{}, {adapters:{'process.binaryStatus':()=>clone(selected),
    'process.binarySelect':req=>{calls.push(clone(req));return selected;},'process.binaryRemove':req=>{calls.push(clone(req));return selected;}}});
  h.host.action('core_rollback',{driver:'mihomo'});assert.deepEqual(calls[0],{id:'mihomo',version:'v1'});
  h.host.action('core_select',{driver:'mihomo',version:'v3'});assert.deepEqual(calls[1],{id:'mihomo',version:'v3'});
  h.host.action('core_remove',{driver:'mihomo',version:'v0'});assert.deepEqual(calls[2],{id:'mihomo',version:'v0'});
  assert.equal(h.state.services.length,0);assert.equal(h.specs.length,0);
  delete selected.previous;assert.throws(()=>h.host.action('core_rollback',{driver:'mihomo'}),/No previous/);
});

test('VPN saves the core configuration to the selected Secret reference and preserves the legacy default',()=>{
  const h=vpnFixture('sing_box',{config_secret:'core_sing_box_default'});
  const config=JSON.stringify({outbounds:[{type:'direct',tag:'selected-core'}]});
  h.host.action('set_core_config',{name:'core_sing_box_default',value:config});
  h.apply();assert.equal(JSON.parse(h.specs[0].config).outbounds[0].tag,'selected-core');
  h.host.action('set_core_config',{value:'{"outbounds":[]}'});
  assert.equal(h.host.snapshot().secrets.core_default,'[REDACTED]');
  assert.throws(()=>h.host.action('set_core_config',{name:'../../config',value:config}),/identifier/);
});
for(const driver of ['mihomo','sing_box']) {
  test('VPN '+driver+' stores imported links encrypted, edits names/options without credentials and recovers the applied snapshot',()=>{
    const h=vpnFixture(driver), source='ss://'+Buffer.from('aes-128-gcm:import-secret').toString('base64url')+'@192.0.2.2:8388#first\n'+
      'trojan://another-secret@node.example:443?sni=example.com#second';
    const saved=h.host.action('set_core_config',{format:'links',driver,value:Buffer.from(source).toString('base64'),selected:1,options:{direct_cidrs:['10.0.0.0/8']}});
    assert.equal(saved.stored,true);assert.equal(saved.form.selected,1);
    assert.deepEqual(saved.form.nodes.map(n=>n.name),['first','second']);
    assert.equal(h.specs.length,0);assert.equal(h.state.services.length,0);
    const form=h.host.action('core_form',{});assert.deepEqual(form,saved.form);
    for(const secret of ['import-secret','another-secret','192.0.2.2','node.example'])assert.ok(!JSON.stringify(form).includes(secret));
    h.apply();const applied=h.specs[0].config;
    assert.equal(JSON.parse(applied)[driver==='mihomo'?'proxies':'outbounds'][0].password,'another-secret');
    h.host.action('set_core_config',{format:'links',driver,value:'',selected:0,options:{dns_hijack:true}});
    assert.equal(h.host.action('core_form',{}).selected,0);
    delete h.procs.vpn_default;h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
    h.host.reconcile();assert.equal(h.specs.at(-1).config,applied);
    h.apply();assert.equal(JSON.parse(h.specs.at(-1).config)[driver==='mihomo'?'proxies':'outbounds'][0].password,'import-secret');
    assert.equal(h.host.snapshot().secrets.core_default,'[REDACTED]');
    for(const resource of ['profiles','status'])assert.ok(!JSON.stringify(h.host.snapshot().resources[resource]).includes('import-secret'));
  });
  test('VPN '+driver+' validates the entire import before changing a saved config or touching networking',()=>{
    const h=vpnFixture(driver), source='ss://'+Buffer.from('aes-128-gcm:private-password').toString('base64url')+'@192.0.2.2:8388';
    h.host.action('set_core_config',{format:'links',driver,value:source});
    for(const payload of [{value:source+'\ntrojan://private-password@host:0'}, {selected:100},{driver:driver==='mihomo'?'sing_box':'mihomo'}, {options:{direct_cidrs:['10.0.0.0/99']}}]) {
      assert.throws(()=>h.host.action('set_core_config',{format:'links',driver,value:'',...payload}),e=>!e.message.includes('private-password'));
      assert.equal(h.host.action('core_form',{}).selected,0);
    }
    assert.equal(h.specs.length,0);assert.equal(h.state.services.length,0);
    assert.throws(()=>h.host.action('set_core_config',{value:'{"veer_proxy":1}'}),/sharing-link/);
    h.apply();assert.equal(JSON.parse(h.specs.at(-1).config)[driver==='mihomo'?'proxies':'outbounds'][0].password,'private-password');
    const native=vpnFixture(driver);assert.equal(native.host.action('core_form',{}).mode,'native');
    assert.throws(()=>native.host.action('set_core_config',{format:'links',driver,value:''}),/重新导入/);
  });
}
for (const driver of ['mihomo','sing_box']) {
  test('VPN '+driver+' uses a managed TUN WAN and leaves host routing to the selected upstream',()=>{
    const h=vpnFixture(driver); const result=h.apply();
    assert.equal(result.phase,'applied');assert.equal(result.egress_nat_interface,'veervpn1');assert.equal(result.egress_nat_redirect_mode,'prepared_l2');
    assert.equal(h.host.action('inspect',{}).phase,'applied');
    assert.equal([...h.maps().values()][0].size,2);const config=JSON.parse(h.specs[0].config);
    if(driver==='mihomo') {assert.equal(config.tun.stack,'gvisor');assert.equal(config.tun['auto-route'],false);assert.equal(config.tun['auto-redirect'],false);assert.equal(config['interface-name'],'eth0');}
    else {assert.equal(config.inbounds[0].stack,'gvisor');assert.equal(config.inbounds[0].auto_route,false);assert.equal(config.route.default_interface,'eth0');}
    assert.ok(!JSON.stringify(h.host.snapshot().resources.status).includes('sensitive-core-password'));
    h.host.action('teardown',{});assert.equal(h.state.links.length,0);assert.deepEqual(h.procs,{});
  });
}
test('VPN delayed TUN is withheld until ready, then claimed and published by repair',()=>{
  const h=vpnFixture('mihomo',{}, {delayed:true});assert.equal(h.apply().phase,'starting');
  assert.equal(h.state.records.status.vpn_default.enabled,false);
  h.state.links.push({ifname:'vtundefault',ifindex:h.state.next++,ifalias:'',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
  h.host.run('onTimer',{timer:{name:'wg_repair'}});assert.equal(h.host.snapshot().resources.status.default.data.phase,'applied');
  assert.equal(h.state.links.find(l=>l.ifname==='vtundefault').ifalias,'veer:vpn_core:default');
});

test('VPN startup without a TUN times out through the existing restart budget',()=>{
  const h=vpnFixture('mihomo',{}, {delayed:true});h.apply();
  h.procs.vpn_default.started_at=Date.now();
  h.host.run('onTimer',{timer:{name:'wg_repair'}});assert.equal(h.procs.vpn_default.starts,1);
  h.procs.vpn_default.started_at=Date.now()-31000;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});assert.equal(h.procs.vpn_default.starts,2);
  assert.equal(h.state.records.sessions.vpn_default.enabled,false);
});
test('VPN core death withdraws both packet directions and never resets an exhausted restart budget',()=>{
  const h=vpnFixture();h.apply();h.procs.vpn_default.state='exited';h.procs.vpn_default.exit_code=2;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal([...h.maps().values()][0].size,0);assert.equal(h.state.records.sessions.vpn_default.enabled,false);
  assert.equal(h.host.snapshot().resources.status.default.data.phase,'failed');
  assert.equal(h.procs.vpn_default.starts,1);
});

test('VPN deleted TUN uses bounded health recovery, and down/MTU drift repairs the owned link',()=>{
  const h=vpnFixture();h.apply();
  h.state.links.find(l=>l.ifname==='vtundefault').flags=[];
  h.state.links.find(l=>l.ifname==='vtundefault').mtu=1300;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.links.find(l=>l.ifname==='vtundefault').mtu,1420);
  assert.equal(h.procs.vpn_default.starts,1);
  h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.procs.vpn_default.starts,2);
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.host.snapshot().resources.status.default.data.phase,'applied');
  h.procs.vpn_default.starts=4;
  h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.match(h.host.snapshot().resources.status.default.data.error,/budget exhausted/);
  assert.equal([...h.maps().values()][0].size,0);
});
test('VPN recovery restores the applied encrypted configuration and ignores newer drafts',()=>{
  const h=vpnFixture();h.apply();const applied=h.specs[0].config;
  h.host.action('set_core_config',{value:JSON.stringify({proxies:[{password:'new-draft'}]})});
  h.procs.vpn_default.started_at=2000;h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
  h.state.links.push({ifname:'vtundefault',ifindex:h.state.next++,ifalias:'',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.specs.at(-1).config,applied);assert.equal(h.host.snapshot().resources.status.default.data.phase,'applied');
});

test('VPN healthy reconciliation preserves the WAN boundary and running core',()=>{
  const h=vpnFixture();h.apply();const preparations=h.state.services.length;
  h.host.reconcile();
  assert.equal(h.state.services.length,preparations);
  assert.equal(h.procs.vpn_default.starts,1);
  assert.equal(h.state.records.sessions.vpn_default.data.usable,true);
  assert.equal(h.host.snapshot().resources.status.default.data.phase,'applied');
});

for(const driver of ['wireguard','mihomo','sing_box','tun']) {
  test(driver+' repairs lost or corrupt adapter entries without touching networking or restarting cores',()=>{
    const h=driver==='wireguard'?fixture():vpnFixture(driver,driver==='tun'?{tun_interface:'vtundefault',tun_alias:'veer:vpn_core:default'}:{});
    if(driver==='tun') h.state.links.push({ifname:'vtundefault',ifindex:h.state.next++,ifalias:'veer:vpn_core:default',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
    h.apply();
    const map=[...h.maps().values()][0], expected=[...map], before=clone(h.state), lease=clone(h.host.snapshot().kv.lease_default);
    const procs=clone(h.procs||{}), specs=h.specs?.length;
    let writes=0;const put=map.set.bind(map);map.set=(...args)=>{writes++;return put(...args);};
    const tick=()=>h.host.run('onTimer',{timer:{name:'wg_repair'}});
    tick();assert.equal(writes,0,'healthy polls must not rewrite maps');
    for(const damage of ['empty','missing-forward','missing-reply','corrupt-forward','corrupt-reply']) {
      if(damage==='empty')map.clear();
      else {const key=expected[damage.endsWith('forward')?0:1][0];if(damage.startsWith('missing'))map.delete(key);else put(key,'00'.repeat(24));}
      tick();assert.deepEqual([...map].sort(),[...expected].sort(),damage);
      const count=writes;tick();assert.equal(writes,count,'repair must stop writing after recovery');
      assert.deepEqual(h.state,before);assert.deepEqual(h.host.snapshot().kv.lease_default,lease);
      assert.deepEqual(h.procs||{},procs);assert.equal(h.specs?.length,specs);
    }
  });
}

test('VPN enables GSO only for a managed sing-box TUN with negotiated capabilities',()=>{
  const full={tx:true,sg:true,tso:true,gso:true};
  const cases=[
    {driver:'sing_box',vnetHeader:true,offloads:full,want:true},
    {driver:'sing_box',vnetHeader:false,offloads:full,want:false},
    ...Object.keys(full).map(k=>({driver:'sing_box',vnetHeader:true,offloads:{...full,[k]:false},want:false})),
    {driver:'sing_box',vnetHeader:true,offloads:{},want:false},
    {driver:'mihomo',vnetHeader:true,offloads:full,want:false},
    {driver:'sing_box',vnetHeader:true,offloads:full,legacyNetInfo:true,want:false}
  ];
  for(const c of cases){
    let probes=0, now=Date.now();
    const h=vpnFixture(c.driver,{}, {...c,adapters:{'net.link.getOffloads':()=>{probes++;return c.offloads;}}});
    h.host.context.vpnTestNow=()=>now;require('node:vm').runInContext('Date.now = vpnTestNow',h.host.context);
    let status=h.apply();
    for(let i=0;status.phase==='starting'&&i<3;i++){
      now+=1001;h.host.run('onTimer',{timer:{name:'wg_repair'}});status=h.host.action('inspect',{});
    }
    assert.equal(status.phase,'applied');
    const data=h.state.records.sessions.vpn_default.data;
    assert.equal(status.tun_gso,c.want);
    assert.equal(data.interface_preparation.local_offloads.gso,c.want);
    assert.equal(data.interface_preparation.pipeline_offloads.gro,c.want);
    assert.equal(data.interface_preparation.local_gso.max_segs,c.want?65535:1);
    // WAN Core saves prepare_handoff settings as profile defaults. Session
    // updates alone cannot replace those defaults, so inspect the service call.
    const prepared=h.state.services.filter(r=>r.action==='prepare_handoff').at(-1).payload;
    assert.equal(prepared.usable,false);
    assert.equal(prepared.interface_preparation.local_offloads.gso,c.want);
    const before=probes;
    h.host.run('onTimer',{timer:{name:'wg_repair'}});h.host.reconcile();
    assert.equal(probes,before,'healthy polling/reconciliation must not execute ethtool');
    assert.equal(h.state.records.sessions.vpn_default.data.interface_preparation.local_offloads.gso,c.want);
  }
});

test('VPN waits for bounded TUN offload negotiation without publishing or repeated early probes',()=>{
  let probes=0, now=Date.now(), ready=false;
  const h=vpnFixture('sing_box',{}, {vnetHeader:true,adapters:{'net.link.getOffloads':()=>{
    probes++;return {tx:ready,sg:ready,tso:ready,gso:ready};
  }}});
  h.host.context.vpnTestNow=()=>now;require('node:vm').runInContext('Date.now = vpnTestNow',h.host.context);
  assert.equal(h.apply().phase,'starting');
  assert.equal([...h.maps().values()].reduce((n,m)=>n+m.size,0),0);
  assert.notEqual(h.state.records.sessions.vpn_default?.enabled,true);
  h.host.reconcile();h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(probes,1);
  ready=true;now+=1001;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.host.action('inspect',{}).tun_gso,true);
  assert.equal(h.state.records.sessions.vpn_default.enabled,true);
  assert.equal(probes,2);
  for(let i=0;i<10;i++)h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(probes,2);
});

test('VPN offload query failure falls back and a new core generation reprobes safely',()=>{
  let supported=true, probes=0;
  const h=vpnFixture('sing_box',{}, {vnetHeader:true,adapters:{'net.link.getOffloads':()=>{
    probes++;if(!supported)throw new Error('ethtool unavailable');return {tx:true,sg:true,tso:true,gso:true};
  }}});
  assert.equal(h.apply().tun_gso,true);
  supported=false;
  h.state.links=h.state.links.filter(l=>l.ifname!=='vtundefault');
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.records.sessions.vpn_default.enabled,false);
  assert.equal(h.state.records.sessions.vpn_default.data.interface_preparation.local_offloads.gso,false);
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.host.snapshot().resources.status.default.data.phase,'applied');
  assert.equal(h.state.records.sessions.vpn_default.data.interface_preparation.local_offloads.gso,false);
  assert.equal(probes,2);
});

test('VPN refuses a TUN replaced during capability probing before enabling either direction',()=>{
  const h=vpnFixture('sing_box',{}, {vnetHeader:true,adapters:{'net.link.getOffloads':()=>{
    const link=h.state.links.find(l=>l.ifname==='vtundefault');link.ifindex++;
    return {tx:true,sg:true,tso:true,gso:true};
  }}});
  assert.throws(h.apply,/TUN changed/);
  assert.notEqual(h.state.records.sessions.vpn_default?.enabled,true);
  assert.equal([...h.maps().values()].reduce((n,m)=>n+m.size,0),0);
});

test('VPN healthy polling uses native reads without subprocesses or dataplane mutations',()=>{
  const h=vpnFixture();h.apply();
  const before=h.host.snapshot(), calls=h.state.calls.length, preparations=h.state.services.length;
  const maps=clone([...h.maps()].map(([name,entries])=>[name,[...entries]]));
  for(let i=0;i<10;i++)h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.calls.length,calls);
  assert.equal(h.state.services.length,preparations);
  assert.equal(h.specs.length,1);
  assert.deepEqual(h.host.snapshot().kv,before.kv);
  assert.deepEqual([...h.maps()].map(([name,entries])=>[name,[...entries]]),maps);
});

test('VPN older native metadata falls back to bounded ip queries and preserves ownership',()=>{
  const h=vpnFixture('mihomo',{}, {legacyNetInfo:true});h.apply();
  const before=h.state.calls.length;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  const reads=h.state.calls.slice(before);
  assert.equal(reads.length,3);
  for(const r of reads)assert.deepEqual(r.args.slice(0,6),['-j','-d','link','show','dev',r.args[5]]);
  h.state.links.find(l=>l.ifname==='vtundefault').ifalias='foreign';
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.records.sessions.vpn_default.enabled,false);
  assert.match(h.host.snapshot().resources.status.default.data.error,/unowned/);
});

test('VPN native lookup errors suspend forwarding and never bypass ownership through exec',()=>{
  let broken=false;
  const h=vpnFixture('mihomo',{}, {adapters:{'net.link.get':name=>{
    if(broken)throw new Error('netlink permanent failure');
    const l=h.state.links.find(l=>l.ifname===name);
    if(!l)throw new Error('link not found: '+name);
    return {name,ifindex:l.ifindex,alias:l.ifalias||'',kind:l.linkinfo.info_kind,mtu:l.mtu,
      mac:l.address,up:(l.flags||[]).includes('UP'),peer_ifindex:l.link_index};
  }}});
  h.apply();const calls=h.state.calls.length;broken=true;
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.calls.length,calls);
  assert.equal(h.state.records.sessions.vpn_default.enabled,false);
  assert.equal([...h.maps().values()][0].size,0);
  assert.match(h.host.snapshot().resources.status.default.data.error,/netlink permanent failure/);
});

test('VPN native tuntap metadata distinguishes TUN from a foreign TAP',()=>{
  for(const mode of ['tun','tap']){
    const h=vpnFixture('tun',{tun_interface:'tun0',tun_alias:'external-owner'}, {adapters:{'net.link.get':name=>{
      const l=h.state.links.find(l=>l.ifname===name);
      if(!l)throw new Error('link not found: '+name);
      return {name,ifindex:l.ifindex,alias:l.ifalias||'',kind:name==='tun0'?'tuntap':l.linkinfo.info_kind,
        tun_mode:name==='tun0'?mode:'',mtu:l.mtu,mac:l.address,up:(l.flags||[]).includes('UP'),peer_ifindex:l.link_index};
    }}});
    h.state.links.push({ifname:'tun0',ifindex:30,ifalias:'external-owner',flags:['UP'],mtu:1420});
    if(mode==='tap') {assert.throws(h.apply,/unowned/);assert.equal(h.state.services.length,0);}
    else assert.equal(h.apply().phase,'applied');
  }
});

test('VPN polling withdraws a TAP even if its owner and reused ifindex match the lease',()=>{
  const h=vpnFixture();h.apply();
  h.state.links.find(l=>l.ifname==='vtundefault').linkinfo.info_kind='tap';
  h.host.run('onTimer',{timer:{name:'wg_repair'}});
  assert.equal(h.state.records.sessions.vpn_default.enabled,false);
  assert.equal([...h.maps().values()][0].size,0);
});

test('VPN logs are explicit and fit the bounded runtime query response',()=>{
  const h=vpnFixture('mihomo',{}, {adapters:{'process.logs':()=>({stdout:'x'.repeat(64000),stderr:'y'.repeat(64000),truncated:false})}});
  h.apply();const logs=h.host.action('core_logs',{});
  assert.equal(logs.stdout.length,4000);assert.equal(logs.stderr.length,4000);assert.equal(logs.truncated,true);
});
test('VPN rejects recursive upstreams, executable injection and foreign TUNs',()=>{
  for (const extra of [{upstream_interface:'veervpn1'},{core_path:'/bin/sh'},{addresses:['10.0.0.1/8']},{remote_routes:['0.0.0.0/0']}]) {
    const h=vpnFixture('mihomo',extra);assert.throws(h.apply);assert.equal(h.state.services.length,0);assert.equal(h.specs.length,0);
  }
  const h=vpnFixture();h.state.links.push({ifname:'vtundefault',ifindex:19,ifalias:'foreign',linkinfo:{info_kind:'tun'}});
  assert.throws(h.apply,/ownership/);assert.equal(h.specs.length,0);
});
test('VPN external TUN mode checks explicit ownership and leaves the provider device intact',()=>{
  const h=vpnFixture('tun',{tun_interface:'tun0',tun_alias:'external-owner'});
  h.state.links.push({ifname:'tun0',ifindex:30,ifalias:'external-owner',linkinfo:{info_kind:'tun'},flags:['UP'],mtu:1420});
  h.apply();assert.equal(h.specs.length,0);h.host.action('teardown',{});
  assert.deepEqual(h.state.links.map(l=>l.ifname),['tun0']);
});
