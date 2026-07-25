const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const webRoot = path.join(__dirname, '..', 'web');

test('modal and overlay layers keep confirmations above plugin management', () => {
  const layout = fs.readFileSync(path.join(webRoot, 'css', 'layout.css'), 'utf8');
  const tables = fs.readFileSync(path.join(webRoot, 'css', 'tables.css'), 'utf8');
  const controls = fs.readFileSync(path.join(webRoot, 'css', 'controls.css'), 'utf8');
  const index = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
  const layer = (name) => {
    const match = layout.match(new RegExp('--' + name + ':\\s*(\\d+)'));
    assert.ok(match, `missing --${name}`);
    return Number(match[1]);
  };

  const values = [
    layer('z-modal'),
    layer('z-plugin-manager'),
    layer('z-popover'),
    layer('z-confirm-modal'),
    layer('z-auth-modal'),
    layer('z-toast')
  ];
  assert.deepEqual(values.slice().sort((left, right) => left - right), values);
  assert.equal(new Set(values).size, values.length);
  assert.match(layout, /\.confirm-modal\s*\{[^}]*z-index:\s*var\(--z-confirm-modal\)/s);
  assert.match(layout, /\.auth-modal\s*\{[^}]*z-index:\s*var\(--z-auth-modal\)/s);
  assert.match(tables, /\.plugin-manager-modal\s*\{[^}]*z-index:\s*var\(--z-plugin-manager\)/s);
  assert.match(tables, /\.kernel-runtime-floating-tooltip\s*\{[^}]*z-index:\s*var\(--z-popover\)/s);
  assert.match(controls, /\.action-dropdown-menu\s*\{[^}]*z-index:\s*var\(--z-popover\)/s);
  assert.match(index, /id="tokenModal" class="modal auth-modal"/);
});

test('token fields cannot claim the plugin search input as a username field', () => {
  const index = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');
  const tokenInput = index.match(/<input[^>]+id="tokenInput"[^>]*>/);
  const pluginSearch = index.match(/<input[^>]+id="pluginsSearchInput"[^>]*>/);

  assert.ok(tokenInput, 'missing web token input');
  assert.ok(pluginSearch, 'missing plugin search input');
  assert.match(tokenInput[0], /autocomplete="new-password"/);
  assert.match(tokenInput[0], /data-1p-ignore="true"/);
  assert.match(tokenInput[0], /data-lpignore="true"/);
  assert.match(tokenInput[0], /data-bwignore="true"/);
  assert.match(tokenInput[0], /\sdisabled(?:\s|>)/);
  assert.match(pluginSearch[0], /name="veer-plugin-filter"/);
  assert.match(pluginSearch[0], /autocomplete="off"/);
  assert.match(pluginSearch[0], /data-1p-ignore="true"/);
  assert.match(pluginSearch[0], /data-lpignore="true"/);
  assert.match(pluginSearch[0], /data-bwignore="true"/);
});

test('plugin manager keeps its header and navigation outside long body scrolling', () => {
  const tables = fs.readFileSync(path.join(webRoot, 'css', 'tables.css'), 'utf8');

  assert.match(tables, /\.plugin-manager-header\s*\{[^}]*flex:\s*0 0 auto/s);
  assert.match(tables, /\.plugin-manager-nav\s*\{[^}]*flex:\s*0 0 auto/s);
  assert.match(tables, /\.plugin-manager-body\s*\{[^}]*flex:\s*1 1 auto[^}]*min-height:\s*0[^}]*overflow-y:\s*auto/s);
});
