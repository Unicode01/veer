(function (root) {
  'use strict';
  // Shared by the sandboxed UI and the plugin runtime; no browser/Node APIs.
  const LIMIT=256*1024, MAX_NODES=128;
  const fail=text=>{throw new Error(text);};
  const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
  const object=v=>v && typeof v==='object' && !Array.isArray(v);
  function byteSize(s) {return encodeURIComponent(s).replace(/%[a-f0-9]{2}|[^%]/gi,'x').length;}
  function decode(value) {
    try {return decodeURIComponent(value);} catch(e) {fail('分享链接的 URL 编码无效');}
  }
  function base64(value) {
    const s=String(value).replace(/\s/g,'').replace(/-/g,'+').replace(/_/g,'/');
    if(!s || s.length>LIMIT || !/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.replace(/=+$/,'').length%4===1 || (s.includes('=') && s.length%4)) fail('Base64 编码无效');
    const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', data=s.replace(/=+$/,'');
    let bits=0, count=0, escaped='';
    for(let i=0;i<data.length;i++) {
      bits=(bits<<6)|alphabet.indexOf(data[i]);count+=6;
      if(count>=8) {count-=8;escaped+='%'+((bits>>count)&255).toString(16).padStart(2,'0');bits&=(1<<count)-1;}
    }
    if(bits) fail('Base64 编码无效');
    try {return decodeURIComponent(escaped);}catch(e){fail('Base64 内容不是有效 UTF-8 文本');}
  }
  function port(value) {
    if(!/^\d+$/.test(String(value)) || Number(value)<1 || Number(value)>65535) fail('节点端口必须为 1–65535');
    return Number(value);
  }
  function ipv4(s) {return /^\d+\.\d+\.\d+\.\d+$/.test(s) && s.split('.').every(v=>Number(v)<=255 && String(Number(v))===v);}
  function ipv6(s) {
    if(!s.includes(':') || /[^0-9a-fA-F:]/.test(s) || s.includes(':::'))return false;
    const groups=s.split('::');if(groups.length>2)return false;
    const parts=groups.flatMap(g=>g?g.split(':'):[]);
    return parts.every(v=>/^[0-9a-fA-F]{1,4}$/.test(v)) && (groups.length===2?parts.length<8:parts.length===8);
  }
  function ip(s) {return ipv4(s)||ipv6(s);}
  function hostname(s) {
    if(ip(s))return s;
    if(s.length>253 || !s || !s.replace(/\.$/,'').split('.').every(v=>/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(v)))fail('节点地址必须是有效 IP 或 ASCII 域名');
    if(/^[0-9.]+$/.test(s))fail('节点 IP 地址无效');
    return s;
  }
  function bool(value) {
    if(value==null || value==='')return false;
    if(value===true || value===1 || value==='1' || value==='true')return true;
    if(value===false || value===0 || value==='0' || value==='false')return false;
    fail('链接中的布尔参数无效');
  }
  function uuid(s) {if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s))fail('节点 UUID 格式无效');return s;}
  function text(s,label) {if(typeof s!=='string' || !s || s.length>4096 || /[\x00-\x1f\x7f]/.test(s))fail(label+'无效');return s;}
  function allowed(o, keys) {if(Object.keys(o).some(k=>!keys.includes(k)))fail('链接含暂不支持的参数，请使用高级栏中的原生 JSON');}
  function query(s) {
    const out=Object.create(null);
    if(s) s.split('&').forEach(pair=>{
      const i=pair.indexOf('='), k=decode(i<0?pair:pair.slice(0,i)), v=decode(i<0?'':pair.slice(i+1));
      if(!k || own(out,k))fail('分享链接含重复或空参数');out[k]=v;
    });
    return out;
  }
  function uri(line) {
    const m=/^([a-z0-9]+):\/\/([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/i.exec(line);
    if(!m)fail('分享链接格式无效');
    let body=m[2];if(body.endsWith('/'))body=body.slice(0,-1);
    const at=body.lastIndexOf('@');if(at<0)fail('分享链接缺少节点凭据');
    const a=/^(?:\[([0-9a-fA-F:]+)\]|([^:/\s]+))(?::(\d+))?$/.exec(body.slice(at+1));
    if(!a)fail('节点地址或端口格式无效');
    return {scheme:m[1].toLowerCase(),auth:decode(body.slice(0,at)),server:hostname(a[1]||a[2]),port:a[3]?port(a[3]):null,q:query(m[3]),name:decode(m[4]||'')};
  }
  const common=['type','security','sni','peer','alpn','fp','pbk','sid','spx','flow','encryption','path','host','serviceName','mode','authority','headerType','allowInsecure','insecure'];
  function transport(n,q,driver) {
    const type=q.type==='raw'?'tcp':q.type || 'tcp';
    if(!['tcp','ws','grpc','http','h2'].includes(type))fail('此传输方式暂不支持链接导入，请使用原生 JSON');
    if(q.headerType && q.headerType!=='none')fail('暂不支持 TCP 伪装头，请使用原生 JSON');
    if(q.mode && q.mode!=='gun')fail('暂不支持此 gRPC 模式');
    if(q.authority)fail('暂不支持 gRPC authority，请使用原生 JSON');
    if(q.spx && q.spx!=='/')fail('暂不支持此 REALITY spiderX 参数，请使用原生 JSON');
    n.transport={type:type==='http'?'h2':type,path:q.path||'/',host:q.host||'',service:q.serviceName||''};
    if(n.transport.path.length>2048 || /[\x00-\x1f\x7f]/.test(n.transport.path))fail('传输路径无效');
    if(n.transport.host)hostname(n.transport.host);
    if(n.transport.service && !/^[a-zA-Z0-9_.\/-]{1,256}$/.test(n.transport.service))fail('gRPC 服务名无效');
    if(n.transport.type==='grpc' && !n.transport.service)fail('gRPC 链接缺少 serviceName');
    // The driver's protocol mapping is deliberately explicit, never silently TCP.
    if(driver==='mihomo' && n.type==='trojan' && n.transport.type==='h2')fail('Mihomo Trojan 不支持此传输方式');
  }
  function tls(n,q,defaultSecurity) {
    const security=q.security || defaultSecurity || 'none';
    if(!['none','tls','reality'].includes(security))fail('此 TLS 类型暂不支持');
    if(security==='none') {
      if(q.pbk || q.sid || q.sni || q.peer || q.alpn || q.fp || bool(q.allowInsecure)||bool(q.insecure))fail('TLS 参数与 security=none 冲突');
      return;
    }
    const t={server_name:q.sni||q.peer||n.server,insecure:bool(q.allowInsecure)||bool(q.insecure)};
    hostname(t.server_name);
    if(q.alpn) {t.alpn=q.alpn.split(',');if(t.alpn.some(v=>!v || v.length>64 || /[^\x21-\x7e]/.test(v)))fail('ALPN 参数无效');}
    if(q.fp) {if(!['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'].includes(q.fp))fail('TLS 指纹暂不支持');t.fingerprint=q.fp;}
    if(security==='reality') {
      if(n.type!=='vless' || !/^[A-Za-z0-9_-]{43}$/.test(q.pbk||'') || !/^(?:[0-9a-fA-F]{2}){0,8}$/.test(q.sid||''))fail('REALITY 公钥或 short ID 无效');
      if(t.insecure)fail('REALITY 不接受跳过证书验证');
      t.reality={public_key:q.pbk,short_id:q.sid||''};t.fingerprint=t.fingerprint||'chrome';
    } else if(q.pbk || q.sid)fail('REALITY 参数与 TLS 类型冲突');
    n.tls=t;
  }
  function parseOne(line,driver) {
    let n;
    if(/^vmess:\/\//i.test(line) && !line.includes('@')) {
      let v;try {v=JSON.parse(base64(line.slice(8)));}catch(e){fail('VMess Base64 JSON 无效');}
      if(!object(v))fail('VMess 配置必须是对象');
      allowed(v,['v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp','allowInsecure','insecure','vcn','pcs']);
      if(v.vcn || v.pcs)fail('暂不支持此证书名称或指纹参数，请使用原生 JSON');
      if(v.aid!=null && String(v.aid)!=='0')fail('仅支持 VMess AEAD（alterId=0）');
      n={type:'vmess',name:String(v.ps||''),server:hostname(String(v.add||'')),port:port(v.port),uuid:uuid(String(v.id||'')),cipher:v.scy||'auto'};
      const q={type:v.net||'tcp',path:v.path,host:v.host,security:v.tls||'none',sni:v.sni,alpn:v.alpn,fp:v.fp,allowInsecure:v.allowInsecure,insecure:v.insecure};
      if(v.type && v.type!=='none')fail('暂不支持 VMess 伪装头');
      if(q.type==='grpc') {q.serviceName=q.path;q.path='';}
      transport(n,q,driver);tls(n,q);
    } else {
      // Legacy SS encodes the entire method:password@host:port authority.
      if(/^ss:\/\/[^@?#]+(?:#.*)?$/i.test(line)) {
        const hash=line.indexOf('#'), body=line.slice(5,hash<0?undefined:hash);
        line='ss://'+base64(body)+(hash<0?'':line.slice(hash));
      }
      const u=uri(line), q=u.q;
      n={type:u.scheme==='hy2'?'hysteria2':u.scheme,name:u.name,server:u.server,port:u.port};
      if(n.type==='ss') {
        allowed(q,[]);
        let auth=u.auth;if(!auth.includes(':'))auth=base64(auth);
        const i=auth.indexOf(':');if(i<1)fail('Shadowsocks 凭据无效');
        n.method=auth.slice(0,i);n.password=text(auth.slice(i+1),'Shadowsocks 密码');
        if(!['aes-128-gcm','aes-192-gcm','aes-256-gcm','chacha20-ietf-poly1305','xchacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305'].includes(n.method))fail('此 Shadowsocks 加密方式暂不支持链接导入');
        if(driver==='sing_box' && n.method==='aes-192-gcm')fail('sing-box 不支持此 Shadowsocks 加密方式');
      } else if(['vless','vmess','trojan'].includes(n.type)) {
        allowed(q,common);
        if(n.type==='trojan')n.password=text(u.auth,'Trojan 密码');else n.uuid=uuid(u.auth);
        if(n.type==='vless') {
          if(q.encryption && q.encryption!=='none')fail('VLESS encryption 暂不支持');
          if(q.flow && q.flow!=='xtls-rprx-vision')fail('此 VLESS flow 暂不支持');
          if(q.flow)n.flow=q.flow;
        } else if(n.type==='vmess') {if(q.flow)fail('VMess 不接受 VLESS flow');n.cipher=q.encryption||'auto';}
        else if(q.flow || q.encryption)fail('Trojan 链接包含其他协议参数');
        transport(n,q,driver);tls(n,q,n.type==='trojan'?'tls':'none');
        if(n.type==='trojan' && !n.tls)fail('Trojan 必须启用 TLS');
        if(n.flow && (!n.tls || n.transport.type!=='tcp'))fail('Vision 需要 TCP + TLS/REALITY');
      } else if(n.type==='anytls') {
        allowed(q,['sni','insecure','allowInsecure','alpn','fp','security','type','headerType']);
        if(q.security && q.security!=='tls')fail('AnyTLS 仅支持 TLS，不支持此 security 参数');
        if(q.type && !['tcp','raw'].includes(q.type))fail('AnyTLS 仅支持 TCP，不支持此传输方式');
        if(q.headerType && q.headerType!=='none')fail('AnyTLS 不支持 TCP 伪装头');
        n.port=n.port||443;n.password=text(u.auth,'AnyTLS 密码');
        tls(n,q,'tls');
      } else if(n.type==='hysteria2') {
        allowed(q,['sni','insecure','obfs','obfs-password']);n.port=n.port||443;n.password=text(u.auth,'Hysteria2 密码');
        tls(n,{sni:q.sni,insecure:q.insecure},'tls');
        if(q.obfs) {if(q.obfs!=='salamander')fail('暂只支持 salamander 混淆');n.obfs={type:q.obfs,password:text(q['obfs-password'],'混淆密码')};}
        else if(q['obfs-password'])fail('混淆密码缺少 obfs 类型');
      } else fail('支持 ss、vmess、vless、trojan、hysteria2 / hy2、anytls 分享链接；其他协议请使用原生 JSON');
      if(!n.port)fail('分享链接缺少节点端口');
    }
    if(n.type==='vmess' && !['auto','none','zero','aes-128-gcm','chacha20-poly1305'].includes(n.cipher))fail('VMess 加密方式无效');
    n.name=n.name.replace(/[\x00-\x1f\x7f]/g,'').slice(0,128);
    return n;
  }
  function parse(value,driver) {
    if(!['mihomo','sing_box'].includes(driver))fail('请选择 Mihomo 或 sing-box');
    let source=String(value||'').trim();
    if(!source || source.length>LIMIT || byteSize(source)>LIMIT)fail('分享内容不能为空，且不能超过 256 KiB');
    if(!/^[a-z][a-z0-9+.-]*:\/\//i.test(source))source=base64(source).trim();
    const lines=source.split(/\r?\n/).map(v=>v.trim()).filter(Boolean);
    if(!lines.length || lines.length>MAX_NODES)fail('一次可导入 1–128 个节点');
    return lines.map((line,i)=>{
      try {const n=parseOne(line,driver);n.name=n.name||n.type.toUpperCase()+' '+(i+1);return n;}
      catch(e) {throw new Error('第 '+(i+1)+' 个节点：'+e.message);}
    });
  }
  function list(value) {return Array.isArray(value)?value:String(value||'').split(/[,\n]/).map(v=>v.trim()).filter(Boolean);}
  function options(raw) {
    raw=raw||{};if(!object(raw))fail('高级设置必须是对象');
    allowed(raw,['direct_cidrs','direct_domains','dns_hijack','bootstrap_dns','proxy_dns']);
    const o={direct_cidrs:list(raw.direct_cidrs),direct_domains:list(raw.direct_domains),dns_hijack:bool(raw.dns_hijack),bootstrap_dns:raw.bootstrap_dns||'223.5.5.5',proxy_dns:raw.proxy_dns||'1.1.1.1'};
    if(o.direct_cidrs.length>128 || o.direct_domains.length>128)fail('每类分流规则最多 128 条');
    o.direct_cidrs.forEach(v=>{const a=String(v).split('/');if(a.length!==2 || !ip(a[0]) || !/^\d+$/.test(a[1]) || Number(a[1])>(a[0].includes(':')?128:32))fail('直连网段必须是有效 CIDR');});
    o.direct_domains=o.direct_domains.map(v=>hostname(String(v).replace(/^\.?\*?\.?/,''))).map(v=>v.toLowerCase());
    if(!ipv4(o.bootstrap_dns) || !ipv4(o.proxy_dns))fail('DNS 服务器请填写 IPv4 地址');
    return o;
  }
  function create(driver,source,selected,rawOptions) {
    const nodes=parse(source,driver), index=selected==null?0:Number(selected);
    if(!Number.isInteger(index) || index<0 || index>=nodes.length)fail('请选择有效节点');
    const value={veer_proxy:1,driver,links:source,selected:index,options:options(rawOptions)};
    // runtime_query has a 64 KiB response bound, including JSON escaping.
    const summary=JSON.stringify({nodes:nodes.map(n=>({name:n.name,type:n.type})),options:value.options});
    // Go's JSON encoder additionally escapes HTML and line separators.
    if(byteSize(summary.replace(/[<>&\u2028\u2029]/g,'______'))>48*1024)fail('节点名称或高级规则摘要过大，请减少节点或规则');
    return value;
  }
  function metadata(value) {
    if(!value || value.veer_proxy!==1)return {mode:'native'};
    const nodes=parse(value.links,value.driver);
    return {mode:'links',driver:value.driver,nodes:nodes.map(n=>({name:n.name,type:n.type})),selected:value.selected,options:options(value.options)};
  }
  function proxy(n,driver) {
    const m=driver==='mihomo';
    const p=m?{name:'veer-node',type:n.type,server:n.server,port:n.port,udp:true}:{tag:'veer-node',type:n.type==='ss'?'shadowsocks':n.type,server:n.server,server_port:n.port};
    if(n.type==='ss') {p[m?'cipher':'method']=n.method;p.password=n.password;}
    else if(n.type==='vmess') {p.uuid=n.uuid;p[m?'cipher':'security']=n.cipher;p[m?'alterId':'alter_id']=0;}
    else if(n.type==='vless') {p.uuid=n.uuid;if(n.flow)p.flow=n.flow;}
    else p.password=n.password;
    if(n.tls) {
      const t=n.tls;
      if(m) {
        if(n.type==='vmess'||n.type==='vless')p.tls=true;
        p[n.type==='vmess'?'servername':'sni']=t.server_name;p['skip-cert-verify']=t.insecure;
        if(t.alpn)p.alpn=t.alpn;if(t.fingerprint)p['client-fingerprint']=t.fingerprint;
        if(t.reality)p['reality-opts']={'public-key':t.reality.public_key,'short-id':t.reality.short_id};
      } else {
        p.tls={enabled:true,server_name:t.server_name,insecure:t.insecure};
        if(t.alpn)p.tls.alpn=t.alpn;
        if(t.fingerprint)p.tls.utls={enabled:true,fingerprint:t.fingerprint};
        if(t.reality)p.tls.reality={enabled:true,public_key:t.reality.public_key,short_id:t.reality.short_id};
      }
    }
    if(n.transport && n.transport.type!=='tcp') {
      const t=n.transport;
      if(m) {
        p.network=t.type;
        if(t.type==='ws')p['ws-opts']={path:t.path,headers:t.host?{Host:t.host}:{}};
        if(t.type==='grpc')p['grpc-opts']={'grpc-service-name':t.service};
        if(t.type==='h2')p['h2-opts']={path:t.path,host:t.host?[t.host]:[]};
      } else {
        p.transport={type:t.type==='h2'?'http':t.type};
        if(t.type==='ws') {p.transport.path=t.path;if(t.host)p.transport.headers={Host:t.host};}
        if(t.type==='grpc')p.transport.service_name=t.service;
        if(t.type==='h2') {p.transport.path=t.path;if(t.host)p.transport.host=[t.host];}
      }
    }
    if(n.obfs) {if(m) {p.obfs=n.obfs.type;p['obfs-password']=n.obfs.password;}else p.obfs=n.obfs;}
    return p;
  }
  function generate(value) {
    const v=create(value.driver,value.links,value.selected,value.options), n=parse(v.links,v.driver)[v.selected], o=v.options;
    if(v.driver==='mihomo') {
      const c={mode:'rule','log-level':'warning',ipv6:true,proxies:[proxy(n,v.driver)],rules:[],dns:{enable:true,'enhanced-mode':'redir-host','default-nameserver':[o.bootstrap_dns],'proxy-server-nameserver':[o.bootstrap_dns],nameserver:[o.dns_hijack?o.proxy_dns+'#veer-node':o.bootstrap_dns]}};
      if(o.direct_domains.length) {c.sniffer={enable:true,'parse-pure-ip':true,'override-destination':false,sniff:{HTTP:{ports:[80,8080]},TLS:{ports:[443]},QUIC:{ports:[443]}}};}
      o.direct_cidrs.forEach(v=>c.rules.push((v.includes(':')?'IP-CIDR6':'IP-CIDR')+','+v+',DIRECT,no-resolve'));
      o.direct_domains.forEach(v=>c.rules.push('DOMAIN-SUFFIX,'+v+',DIRECT'));
      c.rules.push('MATCH,veer-node');if(o.dns_hijack)c.tun={'dns-hijack':['any:53','tcp://any:53']};
      return c;
    }
    const c={log:{level:'warn'},outbounds:[proxy(n,v.driver),{type:'direct',tag:'direct'}],dns:{servers:[{type:'udp',tag:'bootstrap',server:o.bootstrap_dns}],final:'bootstrap',strategy:'ipv4_only'},route:{default_domain_resolver:'bootstrap',final:'veer-node',rules:[]}};
    if(o.direct_domains.length)c.route.rules.push({action:'sniff',sniffer:['http','tls','quic'],timeout:'300ms'});
    if(o.dns_hijack) {
      c.dns.servers.push({type:'udp',tag:'remote',server:o.proxy_dns,detour:'veer-node'});c.dns.final='remote';
      c.route.rules.push({port:53,action:'hijack-dns'});
    }
    if(o.direct_cidrs.length)c.route.rules.push({ip_cidr:o.direct_cidrs,action:'route',outbound:'direct'});
    if(o.direct_domains.length)c.route.rules.push({domain_suffix:o.direct_domains,action:'route',outbound:'direct'});
    return c;
  }
  const api={parse,create,metadata,generate,options};
  if(typeof module==='object' && module.exports)module.exports=api;else root.VPNShare=api;
})(typeof window==='object'?window:globalThis);
