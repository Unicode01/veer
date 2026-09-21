const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function harness() {
  const dir = path.resolve(__dirname, '../../../plugins/router_wizard');
  const noop = () => {};
  const registration = new Proxy({}, {get: () => noop});
  let stored = null;
  const ctx = vm.createContext({exports: {}, plugin: registration, ui: registration,
    resources: {get: () => stored}, log: registration});
  vm.runInContext(fs.readFileSync(path.join(dir, 'control.js'), 'utf8'), ctx);
  for (const name of ['wanMode', 'wanEgress', 'wanSource', 'pppoeInterface', 'pppoeRandomMac', 'pppoeMacAddress',
    'pppoeUsername', 'pppoePassword', 'pppoeService', 'pppoeAuth', 'pppoeIPv6', 'pppoePD', 'pppoeTunnel',
    'pppoeRedial', 'lanBridge', 'lanPorts', 'lanAddresses', 'lanMtu', 'autoNAT', 'lanDHCPv4', 'lanDNSMode',
    'lanDNSServers', 'natType', 'redirectMode']) ctx[name] = {value: '', checked: false};
  ctx.csv = value => value.split(',').map(item => item.trim()).filter(Boolean);
  ctx.protocolValue = () => 'tcp+udp+icmp';
  for (const name of ['setProtocolValue', 'updateModeVisibility', 'updateLANAddressingVisibility']) ctx[name] = noop;
  const ui = fs.readFileSync(path.join(dir, 'ui/index.html'), 'utf8');
  const extract = (start, end) => {
    const begin = ui.indexOf(start), finish = ui.indexOf(end, begin);
    assert(begin >= 0 && finish > begin);
    return ui.slice(begin, finish);
  };
  vm.runInContext(extract('      let pppoePasswordStored', '      function setBusy'), ctx);
  vm.runInContext(extract('      function fillForm', '      function updateLANAddressingVisibility'), ctx);
  return {ctx, store: cfg => { stored = {data: cfg, enabled: true}; }};
}

test('router wizard round trips canonical and legacy PPPoE form settings', () => {
  const {ctx} = harness();
  const input = {wan: {mode: 'pppoe', pppoe_interface: 'eth0', username: 'alice', password: 'saved',
    mac_mode: 'manual', mac_address: '02:00:00:00:00:01', negotiate_ipv6: true, request_pd: true,
    install_tunnel: false, auto_redial: false}};
  for (const config of [input, ctx.normalizeConfig(input)]) {
    ctx.fillForm(config);
    const actual = ctx.normalizeConfig(ctx.payload()).wan.pppoe;
    assert.equal(actual.interface, 'eth0');
    assert.equal(actual.username, 'alice');
    assert.equal(actual.password, 'saved');
    assert.equal(actual.negotiate_ipv6, true);
    assert.equal(actual.request_pd, true);
    assert.equal(actual.install_tunnel, false);
    assert.equal(actual.auto_redial, false);
  }
});

test('router wizard keeps saved password out of the form and preserves it during apply', () => {
  const {ctx, store} = harness();
  const config = ctx.normalizeConfig({wan: {mode: 'pppoe', pppoe_interface: 'eth0', username: 'alice', password: 'saved'}});
  store(config);
  const visible = JSON.parse(JSON.stringify(config));
  visible.wan.pppoe.password = '__redacted__';
  ctx.fillForm(visible);
  assert.equal(ctx.pppoePassword.value, '');
  const payload = ctx.payload();
  assert.equal(payload.wan.pppoe.password, '__redacted__');
  assert.equal(ctx.loadConfigFromPayload(payload).wan.pppoe.password, 'saved');
  ctx.pppoePassword.value = 'replacement';
  assert.equal(ctx.loadConfigFromPayload(ctx.payload()).wan.pppoe.password, 'replacement');
  store(null);
  assert.throws(() => ctx.loadConfigFromPayload(payload), /No saved PPPoE password/);
});
