const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'ui', 'index.html'), 'utf8');

test('local link page uses a record picker and a structured route editor', () => {
  assert.match(source, /F\.recordPicker/);
  assert.match(source, /F\.collectionEditor/);
  assert.doesNotMatch(source, /Routes JSON/);
});

test('local link page uses host button states for update and danger actions', () => {
  assert.match(source, /F\.setButtonState/);
  assert.match(source, /'action\.update'/);
  assert.match(source, /tone: 'danger'/);
});
