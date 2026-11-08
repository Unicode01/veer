const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'ui', 'index.html'), 'utf8');

test('LAN page hides single-choice profile and WAN pickers', () => {
  assert.match(source, /F\.recordPicker/);
  assert.match(source, /lanProfileField\.hidden = lanPicker\.keys\(\)\.length <= 1/);
  assert.match(source, /wanReferenceField\.hidden = wanPicker\.keys\(\)\.length <= 1/);
});

test('LAN page uses host button states for update and danger actions', () => {
  assert.match(source, /F\.setButtonState/);
  assert.match(source, /'action\.update'/);
  assert.match(source, /tone: 'danger'/);
});
