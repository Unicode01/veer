// Core-specific configuration ends here. The WAN and packet handoff are shared.
var shares = require('./ui/share');
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(label + ' must be a JSON object');
  return value;
}
function bindSource(config, p) {
  if (!p.upstream_ip) return;
  var key = p.upstream_ip.indexOf(':') >= 0 ? 'inet6_bind_address' : 'inet4_bind_address';
  function bind(value) {
    if (value.detour) return; // The last outbound in the chain owns the socket.
    // A source address disables sing-box's default_interface inheritance.
    // Bind both explicitly to retain the selected physical uplink.
    value.bind_interface = p.upstream_interface;
    value[key] = p.upstream_ip;
  }
  (config.outbounds || []).forEach(function (value) {
    object(value, 'Outbound');
    if (['selector', 'urltest', 'block', 'dns'].indexOf(value.type) < 0) bind(value);
  });
  // Bootstrap DNS also creates physical sockets; DNS sent through a proxy
  // inherits that proxy's binding instead of binding the inner connection.
  ((config.dns && config.dns.servers) || []).forEach(function (value) {
    if (['local', 'udp', 'tcp', 'tls', 'quic', 'https', 'h3', 'dhcp', 'mdns'].indexOf(value.type) >= 0) bind(value);
  });
}
exports.command = function (driver, path) {
  var name = driver === 'mihomo' ? 'mihomo' : 'sing-box';
  path = String(path || '/usr/local/bin/' + name);
  if (path.slice(-name.length - 1) !== '/' + name || !/^\/[a-zA-Z0-9_./-]+$/.test(path) || /\/(\.\.?)(\/|$)/.test(path))
    throw new Error('Core executable must be a locally installed ' + name + ' binary');
  return path;
};
exports.build = function (p, text) {
  var config;
  try { config = object(JSON.parse(text), 'Core configuration'); }
  catch (e) { throw new Error('Core configuration must be valid JSON'); }
  if (config.veer_proxy === 1) {
    if (config.driver !== p.driver) throw new Error('Saved node configuration belongs to another core');
    config = shares.generate(config);
  }
  var tunAddress = '198.18.' + p.slot + '.1/30';
  if (p.driver === 'mihomo') {
    config.tun = {enable: true, device: p.interface, stack: 'gvisor', mtu: p.mtu,
      'inet4-address': [tunAddress], 'auto-route': false, 'auto-redirect': false,
      'auto-detect-interface': false, 'dns-mode': 'disabled',
      'dns-hijack': config.tun && config.tun['dns-hijack'] || []};
    config['interface-name'] = p.upstream_interface;
    config['find-process-mode'] = 'off';
    // This plugin exposes a WAN, not additional network-facing proxy/API ports.
    ['port', 'socks-port', 'mixed-port', 'redir-port', 'tproxy-port'].forEach(function (key) { config[key] = 0; });
    ['listeners', 'tunnels', 'external-controller', 'external-controller-tls', 'external-controller-unix', 'external-ui', 'external-doh-server'].forEach(function (key) { delete config[key]; });
    if (config.dns) delete object(config.dns, 'DNS configuration').listen;
    return {command: exports.command(p.driver, p.core_path), args: ['-d', '.', '-f', '{config}'], config: JSON.stringify(config)};
  }
  config.inbounds = [{type: 'tun', tag: 'veer-vpn', interface_name: p.interface, address: [tunAddress],
    mtu: p.mtu, stack: 'gvisor', auto_route: false, auto_redirect: false}];
  config.route = config.route ? object(config.route, 'Route configuration') : {};
  config.route.auto_detect_interface = false;
  config.route.default_interface = p.upstream_interface;
  bindSource(config, p);
  // A core must not create a second privileged network topology behind this WAN.
  if (config.endpoints && config.endpoints.length) throw new Error('Use outbound proxies; managed VPN cores do not accept additional endpoints');
  delete config.experimental;
  return {command: exports.command(p.driver, p.core_path), args: ['run', '-c', '{config}'], config: JSON.stringify(config)};
};
