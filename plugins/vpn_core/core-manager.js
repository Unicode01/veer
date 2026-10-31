function driverName(driver) {
  if (driver !== 'mihomo' && driver !== 'sing_box') throw new Error('Core management supports Mihomo and sing-box');
  return driver;
}
exports.driver = driverName;
exports.install = function (payload, host) {
  var driver = driverName(payload.driver);
  if (host.os !== 'linux') throw new Error('VPN core installation requires Linux');
  // Baseline amd64 and conservative ARM/MIPS builds avoid assuming CPU extensions.
  var arch = driver === 'mihomo'
    ? {amd64:'amd64-compatible', arm64:'arm64', arm:'armv5', '386':'386', mips:'mips-softfloat', mipsle:'mipsle-softfloat', mips64:'mips64', mips64le:'mips64le', riscv64:'riscv64', loong64:'loong64-abi2'}[host.arch]
    : {amd64:'amd64', arm64:'arm64', arm:'armv5', '386':'386', mips:'mips-softfloat', mipsle:'mipsle-softfloat', mips64:'mips64-softfloat', mips64le:'mips64le-softfloat', riscv64:'riscv64', loong64:'loong64'}[host.arch];
  if (!arch) throw new Error('No official core build for host architecture ' + host.arch);
  var version = String(payload.version || '').trim();
  if (version && !/^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][a-zA-Z0-9]+)*$/.test(version)) throw new Error('Use a release version such as v1.19.33, or leave blank for latest stable');
  if (version && version[0] !== 'v') version = 'v' + version;
  var repo = driver === 'mihomo' ? 'MetaCubeX/mihomo' : 'SagerNet/sing-box';
  var request = {id:driver, executable:driver === 'mihomo' ? 'mihomo' : 'sing-box',
    format:driver === 'mihomo' ? 'gzip' : 'tar.gz',
    release_url:'https://api.github.com/repos/' + repo + '/releases/' + (version ? 'tags/' + version : 'latest'),
    asset:driver === 'mihomo' ? 'mihomo-linux-' + arch + '-{tag}.gz' : 'sing-box-{version}-linux-' + arch + '.tar.gz',
    check_args:driver === 'mihomo' ? ['-v'] : ['version']};
  if (driver === 'sing_box') request.archive_path = 'sing-box-{version}-linux-' + arch + '/sing-box';
  if (payload.sha256) {
    if (!/^[0-9a-fA-F]{64}$/.test(payload.sha256)) throw new Error('SHA256 must contain 64 hexadecimal characters');
    request.sha256 = payload.sha256.toLowerCase();
  }
  return request;
};
