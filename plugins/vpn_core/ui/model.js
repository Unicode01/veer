(function (root) {
  'use strict';
  // Messages come from i18n.js: window.VPNI18n in the page, require() under Node.
  function t(key, params) {
    const i18n = root.VPNI18n || (typeof module === 'object' && module.exports ? require('./i18n.js') : null);
    return i18n ? i18n.t(key, params) : key;
  }
  // Names and descriptions are read when rendered, so they follow the current locale.
  const driver = (name, short, id) => ({short, get name() { return name || t('driver.' + id + '.name'); }, get description() { return t('driver.' + id + '.description'); }});
  const drivers = {
    wireguard: driver('WireGuard', 'WG', 'wireguard'),
    mihomo: driver('Mihomo', 'M', 'mihomo'),
    sing_box: driver('sing-box', 'S', 'sing_box'),
    tun: driver('', 'T', 'tun')
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
    if (!/^\d+$/.test(String(value)) || Number(value) < min || Number(value) > max) throw new Error(t('model.range', {label, min, max}));
    return Number(value);
  }
  function identifier(key) {
    if (!/^[a-z][a-z0-9_]{0,10}$/.test(key)) throw new Error(t('model.identifier'));
    return key;
  }
  function allocation(records) {
    const used = new Set(records.map(r => Number(r.data.slot))), keys = new Set(records.map(r => r.key));
    for (let slot=1; slot<=8; slot++) if (!used.has(slot)) {
      let key='vpn'+slot, index=1;
      while (keys.has(key)) key='vpn'+slot+'_'+index++;
      return {key, slot};
    }
    throw new Error(t('model.maxOutlets'));
  }
  function profile(fields, original, records, key) {
    identifier(key);
    const value=copy(original || {}), driver=fields.driver;
    if (!drivers[driver]) throw new Error(t('model.chooseDriver'));
    value.driver=driver;
    value.slot=integer(fields.slot,1,8,t('field.slot'));
    if (records.some(r => r.key !== key && Number(r.data.slot) === value.slot)) throw new Error(t('model.slotTaken'));
    value.mtu=integer(fields.mtu,1280,9000,t('field.mtu'));
    const addresses=list(fields.addresses);
    const wg=driver==='wireguard';
    if (addresses.some(v => !prefix(v))) throw new Error(t(wg?'model.wgAddressInvalid':'model.wanAddressInvalid'));
    if ((driver==='wireguard' || addresses.length) && !addresses.some(v => /^\d+\.\d+\.\d+\.\d+\//.test(v))) throw new Error(t(wg?'model.wgAddressIPv4':'model.wanAddressIPv4'));
    if (driver!=='wireguard' && addresses.some(v => Number(v.split('/')[1])!==(v.includes(':')?128:32))) throw new Error(t('model.wanAddressHost'));
    if (addresses.length) value.addresses=addresses;
    else delete value.addresses;
    const unrelated=driver==='wireguard'?['core_path','config_secret','upstream_interface','tun_interface','tun_alias','max_restarts','startup_timeout_seconds']:
      driver==='tun'?['peers','listen_port','remote_routes','core_path','config_secret','upstream_interface','max_restarts','startup_timeout_seconds']:['peers','listen_port','remote_routes','tun_interface','tun_alias'];
    unrelated.forEach(name=>{delete value[name];});
    delete value.upstream_ip;
    if (driver === 'sing_box') {
      const ip=String(fields.upstream_ip || '').trim();
      if (ip) {
        if (ip.includes('/') || !prefix(ip+(ip.includes(':')?'/128':'/32'))) throw new Error(t('model.upstreamIP'));
        value.upstream_ip=ip;
      }
    }
    if (driver === 'wireguard') {
      value.listen_port=integer(fields.listen_port || '0',0,65535,t('field.listenPort'));
      value.remote_routes=list(fields.remote_routes);
      value.peers=fields.peers.map((peer,index) => {
        const p=copy(peer.original || {});
        p.public_key=String(peer.public_key || '').trim(); p.endpoint=String(peer.endpoint || '').trim();
        p.allowed_ips=list(peer.allowed_ips); p.keepalive=integer(peer.keepalive || '0',0,65535,t('model.keepalive'));
        if (!/^[A-Za-z0-9+/]{43}=$/.test(p.public_key)) throw new Error(t('model.peerKey',{index:index+1}));
        if (!p.allowed_ips.length) throw new Error(t('model.peerAllowedRequired',{index:index+1}));
        if (p.allowed_ips.some(v=>!prefix(v))) throw new Error(t('model.peerAllowedInvalid',{index:index+1}));
        if (p.endpoint) {
          const match=/^(\[[0-9a-fA-F:]+\]|[0-9.]+):(\d+)$/.exec(p.endpoint);
          const ip=match && match[1].replace(/[\[\]]/g,'');
          if(!match || !prefix(ip+(ip.includes(':')?'/128':'/32')) || Number(match[2])<1 || Number(match[2])>65535)throw new Error(t('model.endpoint'));
        }
        if (peer.psk) p.preshared_key_secret='psk_'+key+'_'+index;
        return p;
      });
      if (!value.peers.length || value.peers.length>8) throw new Error(t('model.peerCount'));
    } else if (driver === 'tun') {
      value.tun_interface=String(fields.tun_interface || '').trim(); value.tun_alias=String(fields.tun_alias || '').trim();
      if (!value.tun_interface || !value.tun_alias) throw new Error(t('model.tunRequired'));
    } else {
      value.upstream_interface=String(fields.upstream_interface || '').trim();
      if (!value.upstream_interface) throw new Error(t('model.upstreamRequired'));
    }
    return value;
  }
  function importWG(text) {
    if (String(text).length>131072) throw new Error(t('model.wgTooLarge'));
    const result={profile:{driver:'wireguard',addresses:[],mtu:1420,listen_port:0,peers:[],remote_routes:[]}, privateKey:'', psks:[], warnings:[]};
    let section='', peer=null;
    for (const raw of String(text).split(/\r?\n/)) {
      const line=raw.replace(/\s*[#;].*$/,'').trim(); if (!line) continue;
      if (/^\[(Interface|Peer)\]$/i.test(line)) {
        section=line.slice(1,-1).toLowerCase();
        if (section==='interface' && result._interface) throw new Error(t('model.wgOneInterface'));
        if (section==='interface') result._interface=true;
        if (section==='peer') {peer={allowed_ips:[],keepalive:25};result.profile.peers.push(peer);result.psks.push('');}
        continue;
      }
      const match=/^([A-Za-z]+)\s*=\s*(.*)$/.exec(line);
      if (!match || !section) throw new Error(t('model.wgLine'));
      const name=match[1].toLowerCase(), value=match[2].trim();
      if (['postup','postdown','preup','predown'].includes(name)) throw new Error(t('model.wgHooks'));
      if (section==='interface') {
        if (name==='privatekey') result.privateKey=value;
        else if (name==='address') result.profile.addresses.push(...list(value));
        else if (name==='mtu') result.profile.mtu=integer(value,1280,9000,t('field.mtu'));
        else if (name==='listenport') result.profile.listen_port=integer(value,0,65535,t('field.listenPort'));
        else if (name==='dns') result.warnings.push(t('model.wgDNS'));
        else throw new Error(t('model.wgInterfaceField',{name:match[1]}));
      } else if (name==='publickey') peer.public_key=value;
      else if (name==='endpoint') peer.endpoint=value;
      else if (name==='allowedips') peer.allowed_ips.push(...list(value));
      else if (name==='persistentkeepalive') peer.keepalive=integer(value,0,65535,t('model.keepalive'));
      else if (name==='presharedkey') result.psks[result.psks.length-1]=value;
      else throw new Error(t('model.wgPeerField',{name:match[1]}));
    }
    if (!result._interface || !result.profile.addresses.length || !result.profile.peers.length || result.profile.peers.length>8) throw new Error(t('model.wgIncomplete'));
    delete result._interface;
    return result;
  }
  const api={drivers,copy,list,identifier,allocation,profile,importWG};
  if (typeof module==='object' && module.exports) module.exports=api;
  else root.VPNConfig=api;
})(typeof window==='object' ? window : globalThis);
