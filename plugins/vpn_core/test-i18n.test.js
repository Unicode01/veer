'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const uiDir = path.join(__dirname, 'ui');
const I = require(path.join(uiDir, 'i18n.js'));
const M = require(path.join(uiDir, 'model.js'));
const S = require(path.join(uiDir, 'share.js'));
const cjk = /[㐀-鿿＀-￯]/;
const source = (name) => fs.readFileSync(path.join(uiDir, name), 'utf8');
const placeholders = (text) => [...text.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort().join(',');

function shareMessages() {
  const text = source('share.js');
  const start = text.indexOf('const messages={');
  const end = text.indexOf('\n  };\n', start);
  return { table: Function('return ' + text.slice(start + 'const messages='.length, end + 4))(), code: text.slice(0, start) + text.slice(end) };
}

function inLocale(locale, run) {
  globalThis.VeerPluginHost = { locale };
  try { return run(); } finally { delete globalThis.VeerPluginHost; }
}

test('VPN page and share messages define the same keys and placeholders in both locales', () => {
  for (const [name, table] of [['i18n.js', I.messages], ['share.js', shareMessages().table]]) {
    assert.deepEqual(Object.keys(table).sort(), ['en-US', 'zh-CN'], name);
    assert.deepEqual(Object.keys(table['en-US']).sort(), Object.keys(table['zh-CN']).sort(), name);
    for (const [key, zh] of Object.entries(table['zh-CN'])) {
      assert.equal(placeholders(table['en-US'][key]), placeholders(zh), name + ' ' + key);
      assert.equal(cjk.test(table['en-US'][key]), false, name + ' en-US ' + key);
    }
  }
});

test('VPN UI keeps user-facing text in its message tables', () => {
  for (const name of ['app.js', 'model.js']) {
    const lines = source(name).split('\n').filter((line) => cjk.test(line));
    assert.deepEqual(lines, [], name);
  }
  assert.deepEqual(shareMessages().code.split('\n').filter((line) => cjk.test(line)), [], 'share.js outside its table');
});

test('VPN UI only references message keys that exist', () => {
  const pageKeys = new Set(Object.keys(I.messages['zh-CN']));
  const namespaces = new Set([...pageKeys].map((key) => key.split('.')[0]));
  const missing = [];
  for (const name of ['app.js', 'model.js']) {
    for (const match of source(name).matchAll(/'([a-z][A-Za-z_]*\.[\w.]+)'/g)) {
      if (namespaces.has(match[1].split('.')[0]) && !match[1].endsWith('.') && !pageKeys.has(match[1])) missing.push(name + ': ' + match[1]);
    }
  }
  // Keys built from runtime values.
  const app = source('app.js');
  const jobs = JSON.parse(app.match(/const jobPhases=(\[[^\]]*\])/)[1].replace(/'/g, '"'));
  jobs.forEach((state) => { if (!pageKeys.has('core.job.' + state)) missing.push('core.job.' + state); });
  Object.keys(M.drivers).forEach((id) => { if (!pageKeys.has('driver.' + id + '.description')) missing.push('driver.' + id + '.description'); });
  const reasons = new Set([...fs.readFileSync(path.join(uiDir, '..', 'health-check.js'), 'utf8').matchAll(/reason: '([a-z_]+)'/g)].map((m) => m[1]));
  assert.ok(reasons.size >= 5);
  reasons.forEach((reason) => { if (!pageKeys.has('health.reason.' + reason)) missing.push('health.reason.' + reason); });

  const shareKeys = new Set(Object.keys(shareMessages().table['zh-CN']));
  for (const match of shareMessages().code.matchAll(/msg\('([^']+)'/g)) if (!shareKeys.has(match[1])) missing.push('share.js: ' + match[1]);
  assert.deepEqual(missing, []);
});

test('VPN form and share errors follow the page locale and default to Chinese', () => {
  const sing = { driver: 'sing_box', slot: 1, mtu: 1420, upstream_interface: 'eth0', upstream_ip: '192.0.2.9/24' };
  assert.throws(() => M.profile(sing, {}, [], 'home'), /出站 IP/);
  inLocale('en-US', () => {
    assert.throws(() => M.profile(sing, {}, [], 'home'), /^Error: Enter the outbound IP as an IPv4 or IPv6 address without a prefix$/);
    assert.throws(() => M.profile({ ...sing, upstream_ip: '', slot: 9 }, {}, [], 'home'), /^Error: Outlet slot must be 1–8$/);
    assert.throws(() => M.importWG('[Interface]\nPostUp = touch /tmp/x'), /script hooks/);
    assert.equal(M.drivers.tun.name, 'External TUN');
    assert.throws(() => S.parse('trojan://secret@host.example:0', 'mihomo'), /^Error: Node 1: The node port must be 1–65535$/);
    assert.throws(() => S.parse('hy2://@192.0.2.1:443', 'sing_box'), /^Error: Node 1: Invalid Hysteria2 password$/);
  });
  inLocale('zh-CN', () => assert.throws(() => S.parse('hy2://@192.0.2.1:443', 'sing_box'), /^Error: 第 1 个节点：Hysteria2 密码无效$/));
  assert.equal(M.drivers.tun.name, '外部 TUN');
});
