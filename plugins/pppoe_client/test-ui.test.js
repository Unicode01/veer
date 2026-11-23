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

test('PPPoE page defaults keepalive to a 10 s echo, 3 misses, no grace, adaptive', () => {
  assert.match(source, /const keepalive = input\('10000'/);
  assert.match(source, /const keepaliveFailures = input\('3'/);
  assert.match(source, /let keepaliveFailureGraceMs = 0;/);
  assert.match(source, /keepalive_adaptive: keepaliveAdaptive/);
  // Profiles stored by earlier pages all carry the hidden 60000 grace.
  assert.match(source, /data\.keepalive_failure_grace_ms === 60000 \? 0/);
  assert.match(source, /'peer_terminated'\]\.includes\(sessionPhase\)/);
});
