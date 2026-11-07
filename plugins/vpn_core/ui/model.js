(function (root) {
  'use strict';
  const drivers = {
    wireguard: {name:'WireGuard', short:'WG', description:'连接远端网络，或使用远端主机上网。'},
    mihomo: {name:'Mihomo', short:'M', description:'使用 Mihomo 的节点、规则与 DNS 配置。'},
    sing_box: {name:'sing-box', short:'S', description:'使用 sing-box 的出站与路由配置。'},
    tun: {name:'外部 TUN', short:'T', description:'接入已由其他程序创建的 TUN 接口。'}
  };
  const copy = value => JSON.parse(JSON.stringify(value));
  const list = value => String(value || '').split(/[,\n]+/).map(s => s.trim()).filter(Boolean);
  function prefix(value) {
    const parts=String(value).split('/'), ip=parts[0];
    if(parts.length!==2 || !/^\d+$/.test(parts[1]))return false;
    if(ip.includes(':')) {
      try {new URL('http://['+ip+']/');}catch(error){return false;}
      return !ip.includes('%') && Number(parts[1])<=128;
    }
    const octets=ip.split('.');
    return octets.length===4 && octets.every(v=>/^\d+$/.test(v) && Number(v)<=255 && String(Number(v))===v) && Number(parts[1])<=32;
  }
  function integer(value, min, max, label) {
    if (!/^\d+$/.test(String(value)) || Number(value) < min || Number(value) > max) throw new Error(label + '范围为 ' + min + '–' + max);
    return Number(value);
  }
  function identifier(key) {
    if (!/^[a-z][a-z0-9_]{0,10}$/.test(key)) throw new Error('出口标识使用 1–11 位小写字母、数字或下划线，以字母开头');
    return key;
  }
  function allocation(records) {
    const used = new Set(records.map(r => Number(r.data.slot))), keys = new Set(records.map(r => r.key));
    for (let slot=1; slot<=8; slot++) if (!used.has(slot)) {
      let key='vpn'+slot, index=1;
      while (keys.has(key)) key='vpn'+slot+'_'+index++;
      return {key, slot};
    }
    throw new Error('最多支持 8 个出口，请先调整已有出口');
  }
  function profile(fields, original, records, key) {
    identifier(key);
    const value=copy(original || {}), driver=fields.driver;
    if (!drivers[driver]) throw new Error('请选择出口类型');
    value.driver=driver;
    value.slot=integer(fields.slot,1,8,'出口位置');
    if (records.some(r => r.key !== key && Number(r.data.slot) === value.slot)) throw new Error('这个出口位置已被其他配置使用');
    value.mtu=integer(fields.mtu,1280,9000,'MTU');
    const addresses=list(fields.addresses);
    const addressLabel=driver==='wireguard'?'本机 WireGuard 地址':'内部 WAN 地址';
    if (addresses.some(v => !prefix(v))) throw new Error('请填写有效的'+addressLabel+'与前缀');
    if ((driver==='wireguard' || addresses.length) && !addresses.some(v => /^\d+\.\d+\.\d+\.\d+\//.test(v))) throw new Error(addressLabel+'至少需要一个 IPv4 地址');
    if (driver!=='wireguard' && addresses.some(v => Number(v.split('/')[1])!==(v.includes(':')?128:32))) throw new Error('内部 WAN 地址只接受 /32 或 /128');
    if (addresses.length) value.addresses=addresses;
    else delete value.addresses;
    const unrelated=driver==='wireguard'?['core_path','config_secret','upstream_interface','tun_interface','tun_alias','max_restarts','startup_timeout_seconds']:
      driver==='tun'?['peers','listen_port','remote_routes','core_path','config_secret','upstream_interface','max_restarts','startup_timeout_seconds']:['peers','listen_port','remote_routes','tun_interface','tun_alias'];
    unrelated.forEach(name=>{delete value[name];});
    delete value.upstream_ip;
    if (driver === 'sing_box') {
      const ip=String(fields.upstream_ip || '').trim();
      if (ip) {
        if (ip.includes('/') || !prefix(ip+(ip.includes(':')?'/128':'/32'))) throw new Error('出站 IP 请填写不带前缀的 IPv4 或 IPv6 地址');
        value.upstream_ip=ip;
      }
    }
    if (driver === 'wireguard') {
      value.listen_port=integer(fields.listen_port || '0',0,65535,'监听端口');
      value.remote_routes=list(fields.remote_routes);
      value.peers=fields.peers.map((peer,index) => {
        const p=copy(peer.original || {});
        p.public_key=String(peer.public_key || '').trim(); p.endpoint=String(peer.endpoint || '').trim();
        p.allowed_ips=list(peer.allowed_ips); p.keepalive=integer(peer.keepalive || '0',0,65535,'保活间隔');
        if (!/^[A-Za-z0-9+/]{43}=$/.test(p.public_key)) throw new Error('Peer '+(index+1)+' 的公钥格式不正确');
        if (!p.allowed_ips.length) throw new Error('请填写 Peer '+(index+1)+' 的 AllowedIPs');
        if (p.allowed_ips.some(v=>!prefix(v))) throw new Error('Peer '+(index+1)+' 的 AllowedIPs 格式不正确');
        if (p.endpoint) {
          const match=/^(\[[0-9a-fA-F:]+\]|[0-9.]+):(\d+)$/.exec(p.endpoint);
          const ip=match && match[1].replace(/[\[\]]/g,'');
          if(!match || !prefix(ip+(ip.includes(':')?'/128':'/32')) || Number(match[2])<1 || Number(match[2])>65535)throw new Error('Endpoint 需要数值 IP 和有效端口');
        }
        if (peer.psk) p.preshared_key_secret='psk_'+key+'_'+index;
        return p;
      });
      if (!value.peers.length || value.peers.length>8) throw new Error('需要 1–8 个 Peer');
    } else if (driver === 'tun') {
      value.tun_interface=String(fields.tun_interface || '').trim(); value.tun_alias=String(fields.tun_alias || '').trim();
      if (!value.tun_interface || !value.tun_alias) throw new Error('请填写外部 TUN 接口与归属标记');
    } else {
      value.upstream_interface=String(fields.upstream_interface || '').trim();
      if (!value.upstream_interface) throw new Error('请填写实际上联接口');
    }
    return value;
  }
  function importWG(text) {
    if (String(text).length>131072) throw new Error('WireGuard 配置不能超过 128 KiB');
    const result={profile:{driver:'wireguard',addresses:[],mtu:1420,listen_port:0,peers:[],remote_routes:[]}, privateKey:'', psks:[], warnings:[]};
    let section='', peer=null;
    for (const raw of String(text).split(/\r?\n/)) {
      const line=raw.replace(/\s*[#;].*$/,'').trim(); if (!line) continue;
      if (/^\[(Interface|Peer)\]$/i.test(line)) {
        section=line.slice(1,-1).toLowerCase();
        if (section==='interface' && result._interface) throw new Error('配置只能包含一个 Interface');
        if (section==='interface') result._interface=true;
        if (section==='peer') {peer={allowed_ips:[],keepalive:25};result.profile.peers.push(peer);result.psks.push('');}
        continue;
      }
      const match=/^([A-Za-z]+)\s*=\s*(.*)$/.exec(line);
      if (!match || !section) throw new Error('无法识别 WireGuard 配置行');
      const name=match[1].toLowerCase(), value=match[2].trim();
      if (['postup','postdown','preup','predown'].includes(name)) throw new Error('不接受包含脚本钩子的 WireGuard 配置');
      if (section==='interface') {
        if (name==='privatekey') result.privateKey=value;
        else if (name==='address') result.profile.addresses.push(...list(value));
        else if (name==='mtu') result.profile.mtu=integer(value,1280,9000,'MTU');
        else if (name==='listenport') result.profile.listen_port=integer(value,0,65535,'监听端口');
        else if (name==='dns') result.warnings.push('DNS 沿用 LAN 设置；导入文件中的 DNS 未应用。');
        else throw new Error('暂不支持 Interface 字段：'+match[1]);
      } else if (name==='publickey') peer.public_key=value;
      else if (name==='endpoint') peer.endpoint=value;
      else if (name==='allowedips') peer.allowed_ips.push(...list(value));
      else if (name==='persistentkeepalive') peer.keepalive=integer(value,0,65535,'保活间隔');
      else if (name==='presharedkey') result.psks[result.psks.length-1]=value;
      else throw new Error('暂不支持 Peer 字段：'+match[1]);
    }
    if (!result._interface || !result.profile.addresses.length || !result.profile.peers.length || result.profile.peers.length>8) throw new Error('配置需要 Interface、隧道地址及 1–8 个 Peer');
    delete result._interface;
    return result;
  }
  const api={drivers,copy,list,identifier,allocation,profile,importWG};
  if (typeof module==='object' && module.exports) module.exports=api;
  else root.VPNConfig=api;
})(typeof window==='object' ? window : globalThis);
