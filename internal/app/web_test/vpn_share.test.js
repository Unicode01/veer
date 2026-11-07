'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const S=require('../../../plugins/vpn_core/ui/share');
const D=require('../../../plugins/vpn_core/core-drivers');
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
  test(driver+' generates complete configs for each protocol and keeps WAN topology under plugin control',()=>{
    for(const link of samples) {
      const v=S.create(driver,link,0,{}), config=S.generate(v);
      const spec=D.build({driver,slot:2,interface:'vtunhome',mtu:1420,upstream_interface:'eth0'},JSON.stringify(v));
      const built=JSON.parse(spec.config);
      assert.ok(!spec.config.includes('veer_proxy'));assert.equal(S.metadata(v).nodes.length,1);
      if(driver==='mihomo') {assert.equal(config.rules.at(-1),'MATCH,veer-node');assert.equal(built['interface-name'],'eth0');assert.equal(built.tun['auto-route'],false);assert.equal(built['mixed-port'],0);}
      else {assert.equal(config.route.final,'veer-node');assert.equal(config.route.default_domain_resolver,'bootstrap');assert.equal(built.inbounds.length,1);assert.equal(built.route.default_interface,'eth0');assert.equal(built.inbounds[0].auto_route,false);}
    }
    assert.throws(()=>D.build({driver:driver==='mihomo'?'sing_box':'mihomo'},JSON.stringify(S.create(driver,ss))),/another core/);
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

// The privileged VPN gate supplies pinned core executables, validating the
// generated fields with their native parser in addition to exercising traffic.
for(const [driver,env] of [['mihomo','VEER_TEST_MIHOMO'],['sing_box','VEER_TEST_SING_BOX']]) {
  if(!process.env[env])continue;
  test(driver+' accepts generated protocol, transport, DNS and routing configurations in the real core',()=>{
    const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process');
    const dir=fs.mkdtempSync(path.join(os.tmpdir(),'veer-import-config-'));
    try {
      const links=[...samples,...['tcp','ws','grpc','h2'].flatMap(type=>['vless','vmess'].map(protocol=>protocol+'://'+id+'@node.example:443?security=tls&type='+type+(type==='grpc'?'&serviceName=proxy':'')+'&sni=example.com'))];
      for(const link of links)for(const opts of [{},{dns_hijack:true,direct_domains:['example.com'],direct_cidrs:['10.0.0.0/8','fd00::/8']}]) {
        const config=D.build({driver,slot:1,interface:'vtuncheck',mtu:1420,upstream_interface:'lo'},JSON.stringify(S.create(driver,link,0,opts))).config;
        const file=path.join(dir,'config.json');fs.writeFileSync(file,config);
        const args=driver==='mihomo'?['-t','-d',dir,'-f',file]:['check','-c',file];
        const result=cp.spawnSync(process.env[env],args,{encoding:'utf8',timeout:20000,cwd:dir});
        assert.equal(result.status,0,(result.stdout||'')+(result.stderr||''));
      }
    } finally {fs.rmSync(dir,{recursive:true,force:true});}
  });
}
