const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'ui', 'index.html'), 'utf8');

test('router wizard page uses host button states for update and danger actions', () => {
  assert.match(source, /F\.setButtonState/);
  assert.match(source, /'action\.update'/);
  assert.match(source, /tone: 'danger'/);
});

test('router wizard apply keeps the previous saved config available for rollback', () => {
  const body = source.match(/async function applyRouter\(button\) \{([\s\S]*?)\n      \}/);
  assert.ok(body, 'applyRouter function should exist');
  assert.doesNotMatch(body[1], /saveConfig\s*\(/);
  assert.match(body[1], /F\.action\('apply_router'/);
});

test('router wizard renders recovery steps without a raw status dump', () => {
  assert.match(source, /lastStatus\.steps/);
  assert.match(source, /lastStatus\.rollback_steps/);
  assert.match(source, /lastStatus\.restore_steps/);
  assert.match(source, /lastStatus\.restore_rollback_steps/);
  assert.match(source, /appendStepGroup/);
  assert.doesNotMatch(source, /JSON\.stringify\(value \|\| \{\}, null, 2\)/);
  assert.doesNotMatch(source, /json\.raw/);
});
