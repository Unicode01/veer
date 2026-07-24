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
