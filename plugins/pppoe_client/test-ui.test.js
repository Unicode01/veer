const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, 'ui', 'index.html'), 'utf8');

test('PPPoE page locks configuration while a session is active and shows traffic as stats', () => {
  assert.match(source, /const action = active \? 'disconnect' : 'dial'/);
  assert.match(source, /setConfigurationLocked\(active \|\| redialing \|\| pending\)/);
  assert.match(source, /stats\.push\(\.\.\.trafficStats\(data\)\)/);
  assert.doesNotMatch(source, /'traffic\.title'/);
  assert.doesNotMatch(source, /const trafficBody/);
});
