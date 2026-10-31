'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const M=require('../../../plugins/vpn_core/ui/model.js');
const key=Buffer.alloc(32,1).toString('base64');
test('VPN forms allocate distinct slots and preserve existing advanced settings',()=>{
  assert.deepEqual(M.allocation([{key:'vpn1',data:{slot:1}}]),{key:'vpn2',slot:2});
  const fields={driver:'sing_box',slot:'2',mtu:'1420',addresses:'10.78.0.1/32',upstream_interface:'vmbr0'};
  const p=M.profile(fields,{max_restarts:5,config_secret:'custom'},[],'home');
  assert.equal(p.max_restarts,5);assert.equal(p.config_secret,'custom');assert.equal(p.upstream_interface,'vmbr0');
  assert.throws(()=>M.profile(fields,{},[{key:'other',data:{slot:2}}],'home'),/已被/);
  assert.throws(()=>M.profile({...fields,slot:'2oops'},{},[],'home'),/范围/);
  assert.throws(()=>M.profile({...fields,addresses:'999.1.1.1/32'},{},[],'home'),/有效/);
});
test('WG import separates credentials from profile data and reports unsupported DNS',()=>{
  const result=M.importWG('[Interface]\nPrivateKey = '+key+'\nAddress = 10.77.1.1/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = '+key+'\nPresharedKey = '+key+'\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n');
  assert.equal(result.privateKey,key);assert.equal(result.psks[0],key);assert.equal(result.warnings.length,1);
  assert.equal(result.profile.private_key,undefined);assert.equal(result.profile.peers[0].preshared_key,undefined);
  const p=M.profile({driver:'wireguard',slot:1,mtu:1420,addresses:'10.77.1.1/32',peers:[{...result.profile.peers[0],allowed_ips:'0.0.0.0/0, ::/0',psk:key}]},{},[],'home');
  assert.equal(p.peers[0].preshared_key_secret,'psk_home_0');assert.equal(p.peers[0].psk,undefined);
});
test('WG import rejects executable hooks, malformed sections and oversize input',()=>{
  for(const text of ['[Interface]\nPostUp = ip route add default dev wg0','[Interface]\nTable = 123','[Interface]\n[Interface]','Endpoint = 1.2.3.4:5','x'.repeat(131073)]) assert.throws(()=>M.importWG(text));
});
