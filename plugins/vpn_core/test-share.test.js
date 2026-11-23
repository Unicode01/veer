'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
// The page's copy of the share-link import (ui/share.js). The control side is
// src/share.rs and src/drivers.rs; their tests, including the real-core check,
// are in src/tests.rs.
const S=require('./ui/share');
const id='bf000d23-0752-40b4-affe-68f7707a9661';
const b64=s=>Buffer.from(s).toString('base64');
const ss='ss://'+b64('aes-128-gcm:p@ss:word')+'@192.0.2.2:8388#'+encodeURIComponent('测试节点');
const samples=[ss,
  'vmess://'+b64(JSON.stringify({v:'2',ps:'VMess',add:'node.example',port:'443',id,aid:'0',scy:'auto',net:'ws',path:'/proxy',host:'cdn.example',tls:'tls',sni:'cdn.example',alpn:'h2,http/1.1',fp:'chrome'})),
  'vless://'+id+'@node.example:443?security=reality&sni=example.com&fp=chrome&pbk='+Buffer.alloc(32,1).toString('base64url')+'&sid=ab12&flow=xtls-rprx-vision#Reality',
  'trojan://p%40ss%3Aword@[2001:db8::1]:443?sni=example.com&type=grpc&serviceName=proxy',
  'hy2://user%3Apass@node.example/?sni=example.com&obfs=salamander&obfs-password=obfs-secret',
  'anytls://p%40ss%3Aword%2B%E5%AF%86%E7%A0%81@node.example/?sni=example.com&alpn=h2,http%2F1.1&fp=chrome#AnyTLS'
];

for(const driver of ['mihomo','sing_box']) {
  test(driver+' parses plain, URL-safe Base64 and wrapped lists without losing UTF-8 or credentials',()=>{
    const nodes=S.parse(samples.join('\r\n'),driver);
    assert.equal(nodes.length,6);assert.equal(nodes[0].name,'测试节点');assert.equal(nodes[0].password,'p@ss:word');
    assert.deepEqual(S.parse(Buffer.from(samples.join('\n')).toString('base64url'),driver),nodes);
    assert.deepEqual(S.parse(b64(samples.join('\n')).match(/.{1,60}/g).join('\n'),driver),nodes);
    assert.equal(S.parse('ss://'+b64('aes-128-gcm:secret@[2001:db8::2]:1234')+'#legacy',driver)[0].server,'2001:db8::2');
    assert.equal(S.parse('ss://2022-blake3-aes-128-gcm:p%2Bss%3D@host.example:443',driver)[0].password,'p+ss=');
    assert.equal(nodes[3].password,'p@ss:word');assert.equal(nodes[4].password,'user:pass');assert.equal(nodes[4].port,443);
  });
  test(driver+' preserves AnyTLS passwords, TLS verification and explicit/default IPv4/IPv6 endpoints',()=>{
    const node=S.parse(samples[5],driver)[0];
    assert.equal(node.type,'anytls');assert.equal(node.password,'p@ss:word+密码');assert.equal(node.port,443);
    assert.deepEqual(node.tls,{server_name:'example.com',insecure:false,alpn:['h2','http/1.1'],fingerprint:'chrome'});
    const config=S.generate(S.create(driver,samples[5]));
    const p=config[driver==='mihomo'?'proxies':'outbounds'][0];
    assert.equal(p.type,'anytls');assert.equal(p.password,node.password);
    if(driver==='mihomo') {assert.equal(p.sni,'example.com');assert.equal(p['skip-cert-verify'],false);assert.equal(p['client-fingerprint'],'chrome');assert.equal(p.udp,true);}
    else {assert.equal(p.tls.enabled,true);assert.equal(p.tls.insecure,false);assert.equal(p.tls.utls.fingerprint,'chrome');}
    for(const flag of ['insecure','allowInsecure']) {
      const n=S.parse('anytls://private-password@[2001:db8::1]:8443?'+flag+'=1',driver)[0];
      assert.equal(n.server,'2001:db8::1');assert.equal(n.port,8443);assert.equal(n.tls.insecure,true);
    }
    assert.equal(S.parse('anytls://secret@192.0.2.2?insecure=0',driver)[0].tls.insecure,false);
    assert.equal(S.parse('anytls://YWJjZA==@node.example',driver)[0].password,'YWJjZA==');
  });
  test(driver+' accepts explicit AnyTLS TLS/TCP defaults from sharing clients without changing generated settings',()=>{
    const plain='anytls://private-password@node.example?sni=example.com&insecure=0&allowInsecure=0',
      suffix='&security=tls&type=tcp&headerType=none';
    for(const link of [plain+suffix,plain+suffix.replace('type=tcp','type=raw')]) {
      assert.deepEqual(S.parse(link,driver),S.parse(plain,driver));
      assert.deepEqual(S.generate(S.create(driver,link)),S.generate(S.create(driver,plain)));
      assert.deepEqual(S.parse(b64(link),driver),S.parse(plain,driver));
    }
  });
  test(driver+' generates complete configs for each protocol',()=>{
    for(const link of samples) {
      const v=S.create(driver,link,0,{}), config=S.generate(v);
      assert.equal(S.metadata(v).nodes.length,1);
      if(driver==='mihomo') assert.equal(config.rules.at(-1),'MATCH,veer-node');
      else {assert.equal(config.route.final,'veer-node');assert.equal(config.route.default_domain_resolver,'bootstrap');}
    }
  });
  test(driver+' selects imported nodes and creates explicit direct exceptions and optional tunneled DNS',()=>{
    const v=S.create(driver,samples.join('\n'),3,{direct_cidrs:['10.0.0.0/8','fd00::/8'],direct_domains:'*.example.com\ninternal.example',dns_hijack:true});
    const config=S.generate(v), meta=S.metadata(v);
    assert.equal(meta.selected,3);assert.deepEqual(meta.options.direct_domains,['example.com','internal.example']);
    assert.equal(config[driver==='mihomo'?'proxies':'outbounds'][0].password,'p@ss:word');
    const publicJSON=JSON.stringify(meta);
    for(const secret of ['p@ss:word','obfs-secret','node.example','2001:db8::1',id])assert.ok(!publicJSON.includes(secret));
    if(driver==='mihomo') {
      assert.deepEqual(config.tun['dns-hijack'],['any:53','tcp://any:53']);assert.deepEqual(config.dns.nameserver,['1.1.1.1#veer-node']);
      assert.ok(config.rules.includes('IP-CIDR6,fd00::/8,DIRECT,no-resolve'));assert.equal(config.sniffer.enable,true);
    } else {assert.equal(config.dns.final,'remote');assert.equal(config.dns.servers[1].detour,'veer-node');assert.ok(config.route.rules.some(r=>r.action==='hijack-dns'));}
  });
  test(driver+' chains the selected node through front nodes and binds only the first hop to the uplink',()=>{
    const source=samples.join('\n'), m=driver==='mihomo', key=m?'dialer-proxy':'detour';
    // Selected AnyTLS, reached through SS (dialed first) and then VLESS REALITY.
    const v=S.create(driver,source,5,{dns_hijack:true},[0,2]), config=S.generate(v), list=config[m?'proxies':'outbounds'];
    assert.deepEqual(v.via,[0,2]);assert.deepEqual(S.metadata(v).via,[0,2]);
    const byTag=Object.fromEntries(list.map(p=>[p[m?'name':'tag'],p]));
    assert.equal(list[0][m?'name':'tag'],'veer-node');assert.equal(list[0].type,'anytls');assert.equal(list[0][key],'veer-hop-2');
    assert.equal(byTag['veer-hop-1'].type,m?'ss':'shadowsocks');assert.equal(byTag['veer-hop-1'][key],undefined);
    assert.equal(byTag['veer-hop-2'].type,'vless');assert.equal(byTag['veer-hop-2'][key],'veer-hop-1');
    if(m) {assert.equal(config.rules.at(-1),'MATCH,veer-node');assert.deepEqual(config.dns.nameserver,['1.1.1.1#veer-node']);}
    else {
      assert.equal(config.route.final,'veer-node');assert.equal(config.dns.servers[1].detour,'veer-node');
    }
    const publicJSON=JSON.stringify(S.metadata(v));
    for(const secret of ['p@ss:word','node.example',id])assert.ok(!publicJSON.includes(secret));
    // One front node; an empty chain keeps the stored form of earlier versions.
    const one=S.generate(S.create(driver,source,1,{},['3']));
    assert.equal(one[m?'proxies':'outbounds'][0][key],'veer-hop-1');
    assert.equal(S.create(driver,source,1,{},[]).via,undefined);assert.deepEqual(S.metadata(S.create(driver,source,1)).via,[]);
    assert.deepEqual(S.generate(S.create(driver,source,1,{},[])),S.generate(S.create(driver,source,1)));
  });
  test(driver+' rejects front nodes that are missing, repeated, the selected node or too many',()=>{
    const source=samples.join('\n');
    for(const bad of [[6],[-1],[1.5],['x'],[null]])assert.throws(()=>S.create(driver,source,0,{},bad),/前置节点/);
    assert.throws(()=>S.create(driver,source,2,{},[2]),/不能是所选节点/);
    assert.throws(()=>S.create(driver,source,0,{},[1,1]),/不能重复/);
    assert.throws(()=>S.create(driver,source,0,{},[1,2,3]),/最多可设置 2 个/);
    for(const bad of [[2],[1,1],[1,2,3]])assert.throws(()=>S.create(driver,source,2,{},bad),e=>!e.message.includes('p@ss:word') && !e.message.includes(id));
    // A stored chain is checked again against its links.
    assert.throws(()=>S.metadata({veer_proxy:1,driver,links:samples[0],selected:0,via:[1],options:{}}),/前置节点/);
  });
  test(driver+' rejects incomplete or unsupported links without putting credentials in errors',()=>{
    const invalid=['', '!!!!', 'Zg===', '/w==', 'Zh==', 'abc', 'x'.repeat(256*1024+1), Array(129).fill(ss).join('\n'),
      'https://subscription.example/secret','vless://'+id+'@node.example:443?type=kcp',
      'vless://'+id+'@node.example:443?security=tls&security=none','vless://'+id+'@node.example:0',
      'vless://'+id+'@node.example:70000','vless://'+id+'@bad..domain:443','vless://'+id+'@[:::]:443',
      'vless://'+id+'@host:443?security=reality&pbk=bad','vless://'+id+'@host:443?flow=xtls-rprx-vision',
      'trojan://private-password@host:443?security=none','trojan://private-password@host:443?security=tls&sni=%ZZ',
      'ss://'+b64('aes-128-gcm:private-password')+'@host:443?plugin=unavailable',
      'vmess://'+b64(JSON.stringify({add:'host',port:443,id,aid:'10'})),
      'hy2://private-password@host:443?pinSHA256=unknown',
      'anytls://@host','anytls://private-password@host:0','anytls://private-password@host?insecure=perhaps',
      'anytls://private-password@host?security=none','anytls://private-password@host?security=reality',
      'anytls://private-password@host?pbk=unknown','anytls://private-password@host?type=ws',
      'anytls://private-password@host?headerType=http',
      'anytls://private-password@host?sni=bad/host'];
    for(const value of invalid)assert.throws(()=>S.parse(value,driver),e=>!e.message.includes('private-password')&&!e.message.includes(id));
    for(const o of [{direct_cidrs:['10.0.0.0/999']},{direct_cidrs:['1.2.3.999/32']},{direct_domains:'example.com\ninvalid/host'},{proxy_dns:'host.example'},{dns_hijack:'perhaps'},{__unknown:true}])assert.throws(()=>S.options(o));
    for(const selected of [-1,10,1.5,'oops'])assert.throws(()=>S.create(driver,ss,selected));
    assert.throws(()=>S.create(driver,Array(128).fill(ss.split('#')[0]+'#'+'<'.repeat(128)).join('\n')),/摘要过大/);
  });
}
