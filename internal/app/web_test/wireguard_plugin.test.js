'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');
const {createTestHost} = require('../../../sdk/plugin/test-host.cjs');
const pluginDir = path.resolve(__dirname, '../../../plugins/wireguard_mesh');
const PRIVATE = Buffer.alloc(32, 1).toString('base64');
const PUBLIC = Buffer.alloc(32, 2).toString('base64');
const clone = v => JSON.parse(JSON.stringify(v));
const profile = (extra = {}) => ({slot:1, addresses:['10.77.0.1/32'], peers:[{public_key:PUBLIC, endpoint:'192.0.2.2:51820', allowed_ips:['0.0.0.0/0']}], ...extra});
function fixture(config = profile(), options = {}) {
  const state = options.state || {links:[], records:{sessions:{},status:{}}, calls:[], services:[], next:10, config:'', fail:null};
  const ok = (stdout = '') => ({stdout, stderr:'', exit_code:0});
  const adapters = {
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
      const args=a.filter(v=>!['-j','-d'].includes(v)), field=k=>args[args.indexOf(k)+1];
      assert.equal(args[0],'link');
      if(args[1]==='show') return ok(JSON.stringify(state.links));
      if(args[1]==='add') state.links.push({ifname:field('name'),ifindex:state.next++,ifalias:state.ignoreCreateAlias?'':field('alias'),linkinfo:{info_kind:'wireguard'},flags:[],mtu:1420});
      if(args[1]==='set') {const l=state.links.find(l=>l.ifname===field('dev'));if(args.includes('alias'))l.ifalias=field('alias');else {l.mtu=Number(field('mtu'));l.flags=['UP'];}}
      if(args[1]==='del') state.links=state.links.filter(l=>l.ifname!==field('dev'));
      return ok();
    }
  };
  const host=createTestHost({pluginDir,remoteInstallEnabled:options.remoteInstallEnabled,fixtures:{kv:options.kv||{},resources:{profiles:{default:{data:config,enabled:options.enabled!==false}}},secrets:options.missingKey?{}:{private_default:PRIVATE}},adapters}).load();
  return {host,state,apply:()=>host.action('apply',{key:'default'}),maps:()=>host.state.maps};
}
test('WG is opt-in and registration/drafts do not change networking',()=>{
  const h=fixture();h.host.reconcile();assert.equal(h.state.calls.length,0);assert.equal(h.state.services.length,0);
  assert.equal(h.host.snapshot().manifest.kind,'pipeline');assert.equal(h.host.snapshot().manifest.stability,'lab');
  assert.throws(()=>fixture(profile(),{remoteInstallEnabled:true}).apply(),/disabled while remote/);
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
  h.state.fail=null;h.apply();assert.equal(h.state.links.find(l=>l.ifname==='vwgdefault').ifalias,'veer:wireguard_mesh:default');
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
  const plan={key:'default',interface:'vwgdefault',owner:'veer:wireguard_mesh:default',nft:'veer_wg_1',table:52001,
    bindings:[{family:'4',priority:22032,lan_interface:'br-lan',source:'192.168.10.0/24',destination:'0.0.0.0/0'}],peers:[{allowed_ips:['0.0.0.0/0']}],bypass:['192.168.10.0/24']};
  for(const owned of [true,false]) {
    const mutations=[];
    const host=createTestHost({pluginDir,fixtures:{kv:{lease_default:{active:true,plan}}},adapters:{'process.exec':r=>{
      const a=r.args,ok=stdout=>({stdout,exit_code:0});
      assert.ok(!a.includes('flush'));
      if(r.command.endsWith('/nft')) {
        if(a[0]==='-j')return ok(JSON.stringify({nftables:[{table:{name:'veer_wg_1'}}]}));
        if(a[0]==='list')return ok(owned?'table inet veer_wg_1 {\n comment "veer:wireguard_mesh:default"\n chain forward {\n }\n}\n':'table inet veer_wg_1 {\n chain forward {\n comment "veer:wireguard_mesh:default"\n }\n}\n');
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
