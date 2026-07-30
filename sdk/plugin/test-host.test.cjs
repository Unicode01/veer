'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createTestHost } = require('./test-host.cjs');

const apiContract = JSON.parse(fs.readFileSync(path.join(__dirname, 'api-contract.json'), 'utf8'));

function writePlugin(t, manifest, control, files = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'veer-plugin-sdk-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.writeFileSync(path.join(root, 'plugin.json'), JSON.stringify(manifest, null, 2));
  fs.writeFileSync(path.join(root, 'control.js'), control);
	for (const [name, value] of Object.entries(files)) {
		const target = path.join(root, name);
		fs.mkdirSync(path.dirname(target), { recursive: true });
		fs.writeFileSync(target, value);
	}
  return root;
}

function testManifest(id = 'sdk_test') {
  return {
    api_version: 'v1',
    id,
    name: 'SDK Test',
    version: '1.0.0',
    kind: 'control',
    stability: 'lab',
    control: {
      main: 'control.js',
      permissions: ['plugin.register', 'resource', 'kv', 'secret', 'timer', 'worker', 'event', 'net.admin'],
      net_access: [{ interfaces: ['test*'], operations: ['link.read'] }],
    },
  };
}

const lifecycleControl = `
let mainCount = 0;
let workerCount = 0;
let eventCount = 0;

plugin.capabilities(['sdk-test']);
plugin.resource({
  id: 'status',
  methods: ['list', 'get'],
  control_methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual'
});
plugin.action({id: 'net_probe', runtime_update: 'runtime_query'});
plugin.action({id: 'publish', runtime_update: 'runtime_query'});
plugin.action({id: 'tx_fail', runtime_update: 'runtime_query'});
events.subscribe({id: 'self-events', topic: 'plugin.sdk_test.changed', worker: 'events', handler: 'onEvent'});

exports.onReconcile = function () {
  mainCount++;
  resources.set('status', 'default', {main_count: mainCount});
  kv.set('last_reconcile', mainCount);
  secret.set('token', 'not-visible');
  timer.setTimeout('tick', 10, {main_count: mainCount});
  return {main_count: mainCount, worker_count: worker.call('jobs', 'onWork', {main_count: mainCount}).worker_count};
};

exports.onWork = function (ctx) {
  workerCount++;
  return {worker_count: workerCount, payload: ctx.payload};
};

exports.onEvent = function (ctx) {
  eventCount++;
  const current = resources.get('status', 'default');
  resources.set('status', 'default', Object.assign({}, current.data, {event_count: eventCount, event_topic: ctx.event.topic}));
  return {event_count: eventCount};
};

exports.onTimer = function (ctx) {
  return {timer: ctx.timer.name, payload: ctx.timer.payload};
};

exports.onAction = function (ctx) {
  if (ctx.action.id === 'net_probe') return net.link.get('test0');
  if (ctx.action.id === 'publish') return events.publish('plugin.sdk_test.changed', ctx.payload || {});
  if (ctx.action.id === 'tx_fail') {
    resources.transaction([
      {op: 'set', resource: 'status', key: 'default', data: {should_rollback: true}},
      {op: 'invalid', resource: 'status', key: 'default'}
    ]);
  }
  return null;
};
`;

test('test host loads cached relative modules independently in main and worker VMs', (t) => {
	const manifest = testManifest('sdk_modules');
	manifest.control.permissions.push('worker');
	const pluginDir = writePlugin(t, manifest, `
const first = require('./lib/counter');
const second = require('./lib/counter.js');
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () {
  return {same: first === second, main: first.next(), worker: worker.call('jobs', 'onWork', {}).value};
};
exports.onWork = function () { return {value: first.next()}; };
`, {
		'lib/counter.js': `let value = 0; module.exports.next = function () { value++; return value; };`,
	});
	const host = createTestHost({pluginDir});
	assert.deepEqual(host.action('apply'), {same: true, main: 1, worker: 1});
	assert.deepEqual(host.action('apply'), {same: true, main: 2, worker: 2});
});

test('test host preserves VM and worker state while isolating worker globals', (t) => {
	const pluginDir = writePlugin(t, testManifest(), lifecycleControl);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.link.get': (name) => ({ name, kind: 'dummy', up: true }),
    },
  });

  assert.deepEqual(host.reconcile(), { main_count: 1, worker_count: 1 });
  assert.deepEqual(host.reconcile(), { main_count: 2, worker_count: 2 });
  assert.deepEqual(host.action('net_probe'), { name: 'test0', kind: 'dummy', up: true });
  assert.deepEqual(host.fireTimer('tick'), { timer: 'tick', payload: { main_count: 2 } });

  const publication = host.action('publish', { value: 7 });
  assert.deepEqual(publication, { matched: 1, enqueued: 1, dropped: 0, rejected: 0 });
  let snapshot = host.snapshot();
  assert.equal(snapshot.surface.capabilities[0], 'sdk-test');
  assert.equal(snapshot.resources.status.default.data.main_count, 2);
  assert.equal(snapshot.resources.status.default.data.event_count, 1);
  assert.equal(snapshot.kv.last_reconcile, 2);
  assert.equal(snapshot.secrets.token, '[REDACTED]');
  assert.deepEqual(snapshot.workers.map((item) => item.name).sort(), ['events', 'jobs']);
  assert.equal(snapshot.calls.filter((item) => item.api === 'net.link.get').length, 1);

  assert.throws(() => host.action('tx_fail'), /unsupported resource transaction operation invalid/);
  snapshot = host.snapshot();
  assert.equal(snapshot.resources.status.default.data.should_rollback, undefined);
  assert.equal(snapshot.resources.status.default.data.event_count, 1);
});

test('test host exposes bounded network transactions through explicit adapters', (t) => {
  const manifest = testManifest('sdk_net_batch');
  manifest.control.net_access = [{
    interfaces: ['test*'],
    operations: ['route.write', 'rule.write', 'neigh.write'],
  }];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onReconcile = function () {};
exports.onAction = function () {
  return net.route.transaction([
    {op: 'replace', request: {dst: '0.0.0.0/0', dev: 'test0', table: 100}}
  ]);
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.route.transaction': (operations) => ({status: 'completed', operations: operations.length}),
    },
  });

  assert.deepEqual(host.action('apply'), {status: 'completed', operations: 1});
});

test('test host scopes read-only neighbor and bridge FDB inventory', (t) => {
  const manifest = testManifest('sdk_net_inventory');
  manifest.control.net_access = [{
    interfaces: ['test*'],
    operations: ['neigh.read', 'bridge.fdb.read'],
  }];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onReconcile = function () {};
exports.onAction = function () {
  return {
    neigh: net.neigh.list({interface: 'test0', family: 'ipv4', limit: 10}),
    fdb: net.bridge.fdb.list({interface: 'testbr0', limit: 20})
  };
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.neigh.list': () => ({items: [{interface: 'test0', ip: '192.0.2.2'}], truncated: false}),
      'net.bridge.fdb.list': () => ({items: [{interface: 'test1', mac: '02:00:00:00:00:01'}], truncated: false}),
    },
  });

  assert.deepEqual(host.action('apply'), {
    neigh: {items: [{interface: 'test0', ip: '192.0.2.2'}], truncated: false},
    fdb: {items: [{interface: 'test1', mac: '02:00:00:00:00:01'}], truncated: false},
  });

  manifest.control.net_access = [{interfaces: ['test*'], operations: ['neigh.read']}];
  const deniedDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onReconcile = function () {};
exports.onAction = function () { return net.bridge.fdb.list({interface: 'testbr0'}); };
`);
  const denied = createTestHost({pluginDir: deniedDir, adapters: {'net.bridge.fdb.list': () => ({items: [], truncated: false})}});
  assert.throws(() => denied.action('apply'), /net_access bridge\.fdb\.read for interface testbr0 is not declared/);
});

test('test host brokers HTTP and DNS through explicit scoped adapters', (t) => {
  const manifest = testManifest('sdk_clients');
  manifest.control.permissions.push('net.http', 'net.dns');
  manifest.control.net_access = [{interfaces: ['wan0'], operations: ['http', 'dns']}];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'request', runtime_update: 'runtime_query'});
exports.onAction = function () {
  return {
    http: net.http.request({interface: 'wan0', url: 'https://api.example.test/status'}),
    dns: net.dns.lookup({interface: 'wan0', name: 'example.test', type: 'a'})
  };
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.http.request': (request) => ({status_code: 200, final_url: request.url, body_hex: '6f6b', body_text: 'ok', bytes: 2, headers: {}}),
      'net.dns.lookup': (request) => ({name: request.name, type: request.type, records: ['192.0.2.20']}),
    },
  });
  assert.deepEqual(host.action('request'), {
    http: {status_code: 200, final_url: 'https://api.example.test/status', body_hex: '6f6b', body_text: 'ok', bytes: 2, headers: {}},
    dns: {name: 'example.test', type: 'a', records: ['192.0.2.20']},
  });
  assert.deepEqual(host.snapshot().calls.map((item) => item.api), ['net.http.request', 'net.dns.lookup']);

  const deniedManifest = testManifest('sdk_clients_denied');
  deniedManifest.control.permissions.push('net.http');
  deniedManifest.control.net_access = [{
    interfaces: ['wan0'], operations: ['http'], remote_hosts: ['*.allowed.test'], remote_ports: [443],
  }];
  const deniedDir = writePlugin(t, deniedManifest, `
plugin.action({id: 'request', runtime_update: 'runtime_query'});
exports.onAction = function () { return net.http.request({interface: 'wan0', url: 'https://example.test'}); };
`);
  const denied = createTestHost({pluginDir: deniedDir, adapters: {'net.http.request': () => ({})}});
  assert.throws(() => denied.action('request'), /net_access http endpoint example\.test:443 for interface wan0 is not declared/);
  assert.equal(denied.snapshot().calls.length, 0);
});

test('test host validates every multipath route interface', (t) => {
  const manifest = testManifest('sdk_multipath');
  manifest.control.net_access = [{interfaces: ['test*'], operations: ['route.write']}];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () {
  return net.route.transaction([{op: 'replace', request: {
    dst: '0.0.0.0/0', nexthops: [
      {dev: 'test0', gateway: '192.0.2.1'},
      {dev: 'test1', gateway: '192.0.3.1', weight: 2}
    ]
  }}]);
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {'net.route.transaction': (operations) => ({status: 'completed', operations: operations.length})},
  });
  assert.deepEqual(host.action('apply'), {status: 'completed', operations: 1});

  const deniedManifest = testManifest('sdk_multipath_denied');
  deniedManifest.control.net_access = [{interfaces: ['test0'], operations: ['route.write']}];
  const deniedDir = writePlugin(t, deniedManifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () {
  return net.route.replace({dst: '0.0.0.0/0', nexthops: [{dev: 'test0'}, {dev: 'test1'}]});
};
`);
  const denied = createTestHost({pluginDir: deniedDir, adapters: {'net.route.replace': () => null}});
  assert.throws(() => denied.action('apply'), /net_access route\.write for interface test1 is not declared/);
});

test('test host enforces namespace and TUN/TAP scopes', (t) => {
  const manifest = testManifest('sdk_tuntap');
  manifest.control.permissions.push('net.namespace', 'net.tuntap');
  manifest.control.namespace_access = ['veer-*'];
  manifest.control.net_access = [{interfaces: ['tun*'], operations: ['tuntap']}];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () {
  const namespace = net.namespace.ensure({name: 'veer-test'});
  const device = net.tuntap.ensure({name: 'tun0', namespace: 'veer-test', mode: 'tun'});
  const write = net.tuntap.write({name: 'tun0', namespace: 'veer-test', data: '45000014'});
  return {namespace, device, write};
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.namespace.ensure': (request) => ({name: request.name, identity: '1:2', created: true, owned: true}),
      'net.tuntap.ensure': (request) => ({device: {name: request.name, namespace: request.namespace, mode: request.mode, ifindex: 7}, created: true}),
      'net.tuntap.write': (request) => ({bytes: request.data.length / 2}),
    },
  });
  assert.deepEqual(host.action('apply'), {
    namespace: {name: 'veer-test', identity: '1:2', created: true, owned: true},
    device: {device: {name: 'tun0', namespace: 'veer-test', mode: 'tun', ifindex: 7}, created: true},
    write: {bytes: 4},
  });

  const deniedManifest = testManifest('sdk_tuntap_denied');
  deniedManifest.control.permissions.push('net.tuntap');
  deniedManifest.control.namespace_access = ['veer-ok'];
  deniedManifest.control.net_access = [{interfaces: ['tun*'], operations: ['tuntap']}];
  const deniedDir = writePlugin(t, deniedManifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () { return net.tuntap.ensure({name: 'tun0', namespace: 'veer-no'}); };
`);
  const denied = createTestHost({pluginDir: deniedDir, adapters: {'net.tuntap.ensure': () => null}});
  assert.throws(() => denied.action('apply'), /namespace_access for veer-no is not declared/);
  assert.equal(denied.snapshot().calls.length, 0);
});

test('test host enforces namespace scopes for netlink and transport APIs', (t) => {
  const manifest = testManifest('sdk_netns_scoped');
  manifest.control.permissions.push('net.namespace', 'net.udp', 'net.l2');
  manifest.control.namespace_access = ['veer-test'];
  manifest.control.net_access = [{interfaces: ['eth0'], operations: ['route.write', 'udp', 'l2']}];
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () {
  net.route.replace({namespace: 'veer-test', dst: '192.0.2.0/24', dev: 'eth0'});
  net.udp.send({namespace: 'veer-test', interface: 'eth0', remote_ip: '192.0.2.1', remote_port: 9, payload: '00'});
  return net.l2.send({namespace: 'veer-test', interface: 'eth0', ethertype: '0x88b5', dst_mac: '02:00:00:00:00:01'});
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'net.route.replace': () => null,
      'net.udp.send': () => ({bytes: 1}),
      'net.l2.send': () => ({sent: true}),
    },
  });
  assert.deepEqual(host.action('apply'), {sent: true});

  const deniedManifest = testManifest('sdk_netns_scoped_denied');
  deniedManifest.control.net_access = [{interfaces: ['eth0'], operations: ['route.write']}];
  const deniedDir = writePlugin(t, deniedManifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onAction = function () { return net.route.replace({namespace: 'veer-test', dst: '192.0.2.0/24', dev: 'eth0'}); };
`);
  const denied = createTestHost({pluginDir: deniedDir, adapters: {'net.route.replace': () => null}});
  assert.throws(() => denied.action('apply'), /permission net\.namespace is required/);
  assert.equal(denied.snapshot().calls.length, 0);
});

test('test host applies map transactions and commits the generation selector last', (t) => {
  const manifest = testManifest('sdk_map_transaction');
  manifest.control.permissions.push('ebpf.map_read', 'ebpf.map_write');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'apply', runtime_update: 'runtime_query'});
exports.onReconcile = function () {};
exports.onAction = function () {
  const result = ebpf.mapTransaction({
    operations: [
      {op: 'put', object: 'dataplane', map: 'config', key: '01000000', value: '1400000000000000'},
      {op: 'put', object: 'dataplane', map: 'config', key: '02000000', value: '1e00000000000000'}
    ],
    commit: {object: 'dataplane', map: 'selector', key: '00000000', value: '01000000'}
  });
  return {
    result,
    data: ebpf.mapGet('dataplane', 'config', '01000000'),
    generation: ebpf.mapGet('dataplane', 'selector', '00000000')
  };
};
`);
  const host = createTestHost({pluginDir});

  assert.deepEqual(host.action('apply'), {
    result: {status: 'completed', operations: 2, committed: true},
    data: '1400000000000000',
    generation: '01000000',
  });
});

test('test host provides atomic and chunked plugin blob storage', (t) => {
  const manifest = testManifest('sdk_blobs');
  manifest.control.permissions.push('blob');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'blob', runtime_update: 'runtime_query'});
exports.onAction = function () {
  blob.put({key: 'small', payload_hex: '010203'});
  var upload = blob.begin({key: 'chunked', expected_bytes: 3});
  blob.write({upload_id: upload.upload_id, offset: 0, payload_hex: 'aabb'});
  blob.write({upload_id: upload.upload_id, offset: 2, payload_hex: 'cc'});
  var committed = blob.commit({upload_id: upload.upload_id});
  return {committed: committed, read: blob.read({key: 'chunked', offset: 1, max_bytes: 2}), listed: blob.list()};
};
`);
  const host = createTestHost({pluginDir});
  const result = host.action('blob');
  assert.equal(result.committed.bytes, 3);
  assert.equal(result.read.payload_hex, 'bbcc');
  assert.equal(result.read.eof, true);
  assert.deepEqual(result.listed.map((item) => item.key), ['chunked', 'small']);
  const snapshot = host.snapshot();
  assert.equal(snapshot.blobs.small.bytes, 3);
  assert.equal(snapshot.blobs.chunked.sha256, crypto.createHash('sha256').update(Buffer.from('aabbcc', 'hex')).digest('hex'));
});

test('privileged operations fail unless an adapter is explicitly configured', (t) => {
	const pluginDir = writePlugin(t, testManifest(), lifecycleControl);
  const host = createTestHost({ pluginDir });
  assert.throws(() => host.action('net_probe'), /net\.link\.get requires an explicit test adapter/);
  const snapshot = host.snapshot();
  assert.equal(snapshot.calls[0].api, 'net.link.get');
});

test('registration phase rejects side effects', (t) => {
	const manifest = testManifest('registration_side_effect');
	const pluginDir = writePlugin(t, manifest, `
plugin.resource({id: 'settings', methods: ['get']});
kv.set('forbidden', true);
`);
  assert.throws(() => createTestHost({ pluginDir }), /permission kv is unavailable during plugin registration/);
});

test('cross-plugin events require an explicit source and topic prefix', (t) => {
  const manifest = testManifest('event_sink');
  manifest.control.permissions.push('plugin.event');
  manifest.control.event_access = [{
    plugin: 'event_source',
    topic_prefixes: ['plugin.event_source.session'],
  }];
  const pluginDir = writePlugin(t, manifest, `
events.subscribe({id: 'sessions', topic: 'plugin.event_source.session', match: 'prefix', worker: 'events'});
exports.onEvent = function (ctx) { kv.set('last_source', ctx.event.source_plugin); };
`);
  const host = createTestHost({ pluginDir });
  assert.equal(host.emit('plugin.event_source.session.changed', { value: 1 }), 1);
  assert.equal(host.emit('plugin.event_source.private.changed', { value: 2 }), 0);
  assert.equal(host.snapshot().kv.last_source, 'event_source');
});

test('test host normalizes action schemas and rejects incompatible event versions', (t) => {
  const manifest = testManifest('schema_contracts');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({
  id: 'inspect',
  runtime_update: 'runtime_query',
  request_schema_version: 2,
  request_schema: {type: 'object', properties: {value: {type: 'integer'}}},
  response_schema_version: 3,
  response_schema: {type: 'object', properties: {ok: {type: 'boolean'}}}
});
events.subscribe({
  id: 'updates',
  topic: 'plugin.schema_contracts.updated',
  worker: 'events',
  schema_version: 2,
  schema: {type: 'object', properties: {value: {type: 'integer'}}}
});
exports.onAction = function (ctx) { return ctx.action; };
exports.onEvent = function (ctx) { kv.set('event_version', ctx.event.schema_version); };
`);
  const host = createTestHost({ pluginDir });
  const action = host.action('inspect', {value: 7});
  assert.equal(action.request_schema_version, 2);
  assert.equal(action.response_schema_version, 3);
  assert.equal(host.emit('plugin.schema_contracts.updated', {value: 7}), 0);
  assert.equal(host.emit('plugin.schema_contracts.updated', {value: 7}, {schema_version: 2}), 1);
  const snapshot = host.snapshot();
  assert.equal(snapshot.kv.event_version, 2);
  assert.match(snapshot.surface.actions[0].request_schema_digest, /^[a-f0-9]{64}$/);
  assert.match(snapshot.surface.actions[0].response_schema_digest, /^[a-f0-9]{64}$/);
  assert.match(snapshot.surface.event_subscriptions[0].schema_digest, /^[a-f0-9]{64}$/);
});

test('cross-plugin event subscription cannot exceed its declared prefix', (t) => {
  const manifest = testManifest('event_sink_denied');
  manifest.control.permissions.push('plugin.event');
  manifest.control.event_access = [{
    plugin: 'event_source',
    topic_prefixes: ['plugin.event_source.session'],
  }];
  const pluginDir = writePlugin(t, manifest, `events.subscribe({id: 'private', topic: 'plugin.event_source.private'});`);
  assert.throws(() => createTestHost({ pluginDir }), /not declared in control\.event_access/);
});

test('system lifecycle topic cannot be claimed as a plugin event prefix', (t) => {
  const manifest = testManifest('lifecycle_event_sink');
  manifest.control.permissions.push('plugin.event');
  manifest.control.event_access = [{ plugin: 'lifecycle', topic_prefixes: ['plugin.lifecycle'] }];
  const pluginDir = writePlugin(t, manifest, `exports.onReconcile = function () {};`);
  assert.throws(() => createTestHost({ pluginDir }), /reserved for the Veer lifecycle event/);
});

test('handler execution is interrupted at the configured timeout', (t) => {
	const manifest = testManifest('timeout_plugin');
	const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'loop', runtime_update: 'runtime_query'});
exports.onAction = function () { while (true) {} };
`);
  const host = createTestHost({ pluginDir, timeoutMs: 25 });
  assert.throws(() => host.action('loop'), /Script execution timed out/);
});

test('test host loads bundled control-plane plugins without compatibility shims', () => {
  const pluginsRoot = path.resolve(__dirname, '..', '..', 'plugins');
  for (const id of ['wan_core', 'lan_core', 'vtolocal', 'router_wizard']) {
    const snapshot = createTestHost({ pluginDir: path.join(pluginsRoot, id) }).snapshot();
    assert.equal(snapshot.manifest.id, id);
    assert.ok(snapshot.surface.resources.length > 0, `${id} should register resources`);
    assert.ok(snapshot.surface.actions.length > 0, `${id} should register actions`);
  }
});

test('test host exposes every versioned control API method', (t) => {
  const pluginDir = writePlugin(t, testManifest('api_contract'), `exports.onReconcile = function () {};`);
  const host = createTestHost({ pluginDir });
  assert.equal(apiContract.version, 8);
  assert.equal(apiContract.runtime.api_version, 'v1');
  assert.equal(apiContract.runtime.tc_pipeline_abi, 2);
  assert.equal(apiContract.runtime.core_priority, 1000);
  assert.equal(apiContract.tc_pipeline.program_array_entries, 111);
  assert.equal(apiContract.tc_pipeline.stage_hook_limit, 8);
  assert.equal(apiContract.tc_pipeline.direction_hook_limit, 14);
  assert.deepEqual(apiContract.tc_pipeline.directions, ['forward', 'reply']);
  assert.deepEqual(apiContract.tc_pipeline.phases, ['around_core', 'after_apply']);
  assert.ok(apiContract.tc_pipeline.hook_stages.includes('post_apply'));
  assert.ok(apiContract.tc_pipeline.hook_stages.includes('post_reply_apply'));
  assert.equal(apiContract.netfilter_pipeline.hook_limit, 8);
  assert.equal(apiContract.netfilter_pipeline.group_limit, 64);
  assert.deepEqual(apiContract.netfilter_pipeline.families, ['inet', 'ipv4', 'ipv6']);
  assert.ok(apiContract.netfilter_pipeline.hooks.includes('forward'));
  assert.ok(apiContract.netfilter_pipeline.phases.includes('filter'));
  assert.equal(apiContract.packet_metadata.abi, 1);
  assert.equal(apiContract.packet_metadata.binding_limit, 16);
  assert.equal(apiContract.packet_metadata.namespace_limit, 32);
  assert.equal(apiContract.packet_metadata.payload_max_bytes, 64);
  assert.ok(apiContract.runtime.features.includes('control.net_multipath.v1'));
  assert.ok(apiContract.runtime.features.includes('control.action_schema.v1'));
  assert.ok(apiContract.runtime.features.includes('control.event_schema.v1'));
  assert.ok(apiContract.runtime.features.includes('control.durable_events.v1'));
	assert.ok(apiContract.runtime.features.includes('control.durable_operations.v1'));
	assert.equal(apiContract.operations.max_records_per_plugin, 1024);
  assert.equal(apiContract.schemas.draft, '2020-12');
  assert.equal(apiContract.control.host_protocol_abi, 1);
  assert.equal(apiContract.control.capabilities.length, apiContract.control_methods.length);
  const workerCall = apiContract.control.capabilities.find((item) => item.method === 'worker.call');
  assert.deepEqual(workerCall.permissions, ['worker']);
  assert.deepEqual(workerCall.phases, ['runtime']);
  assert.deepEqual(workerCall.contexts, ['main']);
  const httpRequest = apiContract.control.capabilities.find((item) => item.method === 'net.http.request');
  assert.deepEqual(httpRequest.permissions, ['net.http']);
  assert.deepEqual(httpRequest.conditional_permissions, ['net.dns', 'net.namespace']);
  for (const method of apiContract.control_methods) {
    const value = method.split('.').reduce((current, part) => current && current[part], host.context);
    assert.equal(typeof value, 'function', `${method} must be exposed by the test host`);
  }
});

test('test host models durable operation replay and CAS transitions', (t) => {
  const manifest = testManifest('operation_sdk');
  manifest.control.permissions.push('operation');
  const pluginDir = writePlugin(t, manifest, `
exports.onReconcile = function () {
  var op = operations.begin({key:'router_default', kind:'router.apply', input:{password:'secret'}, state:{step:0}});
  if (op.resumable) {
    op = operations.claim(op.id, op.revision);
    op = operations.checkpoint(op.id, op.revision, {phase:'wan_ready', state:{step:1}});
    operations.complete(op.id, op.revision, {ok:true});
  }
};
plugin.action({id:'worker_probe', runtime_update:'runtime_query'});
exports.onAction = function () { return worker.call('jobs', 'onWorkerProbe', {}); };
exports.onWorkerProbe = function () { return operations.list(); };
`);
  const host = createTestHost({pluginDir});
  host.reconcile();
  const operation = host.context.operations.getByKey('router_default');
  assert.equal(operation.status, 'completed');
  assert.equal(operation.phase, 'wan_ready');
  assert.equal(operation.input.password, 'secret');
  assert.equal(operation.attempts, 1);
  assert.throws(() => host.context.operations.claim(operation.id, 1), /stale/);
  assert.equal(host.snapshot().operations.length, 1);
  assert.throws(() => host.action('worker_probe'), /main VM/);
});

test('router wizard resumes a persisted in-flight orchestration operation', () => {
  const pluginDir = path.resolve(__dirname, '..', '..', 'plugins', 'router_wizard');
  const calls = [];
  const providers = {
    wan_core: {
      plugin_id: 'wan_core',
      service: {id: 'wan.adapter', version: '1.0.0', actions: ['apply_session', 'prepare_handoff', 'teardown'], resources: ['status']},
    },
    lan_core: {
      plugin_id: 'lan_core',
      service: {id: 'lan.adapter', version: '1.0.0', actions: ['apply_network', 'teardown'], resources: ['status', 'egress_nat_plans']},
    },
  };
  const host = createTestHost({
    pluginDir,
    adapters: {
      'plugins.services.resolve': (query) => {
        const provider = providers[query.provider];
        if (!provider || provider.service.id !== query.service) throw new Error(`provider ${query.provider} unavailable`);
        return provider;
      },
      'plugins.services.call': (request) => {
        calls.push(JSON.parse(JSON.stringify(request)));
        return {phase: 'applied'};
      },
      'plugins.resources.list': () => [],
    },
  });
  const config = {
    wan: {mode: 'existing', ref: 'default', egress_interface: 'eth0'},
    lan: {id: 'default', bridge: 'br-lan', ports: ['eth1'], addresses: ['192.168.100.1/24'], auto_egress_nat: true},
  };
  let operation = host.context.operations.begin({
    key: 'router_default', kind: 'router.apply', input: {config, previous: null}, state: {phase: 'pending'},
  });
  operation = host.context.operations.claim(operation.id, operation.revision);
  assert.equal(operation.status, 'running');

  host.reconcile();
  operation = host.context.operations.get(operation.id);
  assert.equal(operation.status, 'completed');
  assert.equal(operation.attempts, 2);
  assert.equal(calls.filter((item) => item.provider === 'lan_core' && item.action === 'apply_network').length, 1);
  assert.equal(host.snapshot().resources.config.default.data.wan.egress_interface, 'eth0');
});

test('test host registers typed services and validates referenced endpoints after registration', (t) => {
  const manifest = testManifest('service_provider');
  const pluginDir = writePlugin(t, manifest, `
plugin.service({
  id: 'wan.adapter',
  version: '1.2.0',
  description: 'Normalized WAN provider',
  actions: ['apply', 'apply'],
  resources: ['status']
});
plugin.action({id: 'apply', runtime_update: 'runtime_apply'});
plugin.resource({id: 'status', methods: ['list', 'get'], runtime_update: 'manual'});
exports.onReconcile = function () {};
`);
  const snapshot = createTestHost({pluginDir}).snapshot();
  assert.deepEqual(snapshot.surface.services, [{
    id: 'wan.adapter', version: '1.2.0', description: 'Normalized WAN provider',
    actions: ['apply'], resources: ['status'],
  }]);

  const invalidDir = writePlugin(t, testManifest('bad_service_provider'), `
plugin.service({id: 'wan.adapter', version: '1.0.0', actions: ['missing']});
exports.onReconcile = function () {};
`);
  assert.throws(() => createTestHost({pluginDir: invalidDir}), /references undeclared action missing/);
});

test('test host normalizes and validates least-privilege UI capabilities', (t) => {
  const manifest = testManifest('ui_capabilities');
  manifest.control.permissions.push('ui', 'plugin.resource');
  manifest.control.resource_access = [{plugin: 'wan_core', resource: 'status', methods: ['get', 'list']}];
  const pluginDir = writePlugin(t, manifest, `
plugin.resource({id: 'profiles', methods: ['list', 'get', 'create', 'update'], runtime_update: 'manual'});
plugin.action({id: 'apply', runtime_update: 'runtime_apply'});
ui.register({
  static_dir: 'ui', entry: 'index.html', page: 'test', page_title: 'Test',
  resources: [{resource: 'profiles', methods: ['update', 'list']}],
  actions: ['apply'],
  resource_access: [{plugin: 'wan_core', resource: 'status', methods: ['list']}]
});
exports.onReconcile = function () {};
`, {'ui/index.html': '<!doctype html>'});
  const ui = createTestHost({pluginDir}).snapshot().surface.ui;
  assert.deepEqual(ui.resources, [{resource: 'profiles', methods: ['list', 'update']}]);
  assert.deepEqual(ui.actions, ['apply']);
  assert.deepEqual(ui.resource_access, [{plugin: 'wan_core', resource: 'status', methods: ['list']}]);

  const undeclaredDir = writePlugin(t, manifest, `
ui.register({static_dir: 'ui', entry: 'index.html', resources: [{resource: 'missing', methods: ['list']}]});
exports.onReconcile = function () {};
`, {'ui/index.html': '<!doctype html>'});
  assert.throws(() => createTestHost({pluginDir: undeclaredDir}), /ui\.resources references undeclared resource missing/);

  const escalationDir = writePlugin(t, manifest, `
ui.register({
  static_dir: 'ui', entry: 'index.html',
  resource_access: [{plugin: 'wan_core', resource: 'status', methods: ['delete']}]
});
exports.onReconcile = function () {};
`, {'ui/index.html': '<!doctype html>'});
  assert.throws(() => createTestHost({pluginDir: escalationDir}), /resource_access\[0\]\.methods are invalid/);
});

test('test host exposes adapter-backed typed service discovery and calls', (t) => {
  const manifest = testManifest('service_consumer');
  manifest.control.permissions.push('plugin.action', 'plugin.resource');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'run', runtime_update: 'runtime_query'});
exports.onAction = function () {
  return {
    providers: plugins.services.list({service: 'wan.adapter', version: '^1.0.0'}),
    selected: plugins.services.resolve({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'}),
    result: plugins.services.call({service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core', action: 'apply', payload: {key: 'default'}})
  };
};
`);
  const provider = {
    plugin_id: 'wan_core', plugin_name: 'WAN Core', plugin_version: '1.0.0', stability: 'stable',
    service: {id: 'wan.adapter', version: '1.0.0', actions: ['apply'], resources: ['status']},
  };
  const host = createTestHost({
    pluginDir,
    adapters: {
      'plugins.services.list': (query) => {
        assert.deepEqual(query, {service: 'wan.adapter', version: '^1.0.0'});
        return [provider];
      },
      'plugins.services.resolve': (query) => {
        assert.deepEqual(query, {service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core'});
        return provider;
      },
      'plugins.services.call': (request) => {
        assert.deepEqual(request, {
          service: 'wan.adapter', version: '^1.0.0', provider: 'wan_core', action: 'apply', payload: {key: 'default'},
        });
        return {status: 'completed', plugin: 'wan_core', action: 'apply'};
      },
    },
  });
  const result = host.action('run');
  assert.deepEqual(result.providers, [provider]);
  assert.deepEqual(result.selected, provider);
  assert.equal(result.result.status, 'completed');
});

test('test host validates and normalizes eBPF state map contracts', (t) => {
  const manifest = testManifest('state_maps');
  manifest.control.permissions.push('ebpf.load');
  const pluginDir = writePlugin(t, manifest, `
ebpf.loadObject({
  id: 'dataplane',
  path: 'dataplane.o',
  state_maps: [
    {name: 'sessions', policy: ' PRESERVE ', schema_version: 1},
    {name: 'sessions_v2', policy: 'MIGRATE', schema_version: 2, migrate_from: 'sessions'},
    {name: 'old_state', policy: 'RESET'}
  ]
});
exports.onReconcile = function () {};
`);
  const snapshot = createTestHost({ pluginDir }).snapshot();
  assert.deepEqual(snapshot.surface.objects[0].state_maps, [
    {name: 'old_state', policy: 'reset'},
    {name: 'sessions', policy: 'preserve', schema_version: 1},
    {name: 'sessions_v2', policy: 'migrate', schema_version: 2, migrate_from: 'sessions'},
  ]);

  const invalidDir = writePlugin(t, Object.assign(testManifest('bad_state_maps'), {
    control: {main: 'control.js', permissions: ['ebpf.load']},
  }), `
ebpf.loadObject({id: 'dataplane', path: 'dataplane.o', state_maps: [
  {name: 'tc_plugin_ctx_v4', policy: 'preserve', schema_version: 1}
]});
`);
  assert.throws(() => createTestHost({ pluginDir: invalidDir }), /reserved/);
});

test('test host executes bounded resumable eBPF state map migrations', (t) => {
  const manifest = testManifest('state_map_migration');
  manifest.control.permissions.push('ebpf.load', 'ebpf.map_read', 'ebpf.map_write');
  const pluginDir = writePlugin(t, manifest, `
ebpf.loadObject({
  id: 'dataplane', path: 'dataplane.o',
  state_maps: [
    {name: 'sessions_v1', policy: 'preserve', schema_version: 1},
    {name: 'sessions_v2', policy: 'migrate', schema_version: 2, migrate_from: 'sessions_v1'}
  ]
});
plugin.action({id: 'read', runtime_update: 'runtime_query'});
exports.onEBPFStateMigrate = function (ctx) {
  var migration = ctx.ebpf_migration;
  var page = ebpf.mapScan(migration.object_id, migration.source_map, {
    cursor: migration.cursor, limit: 1, max_bytes: migration.max_bytes
  });
  if (page.entries.length) {
    ebpf.mapTransaction({operations: page.entries.map(function (entry) {
      return {op: 'put', object: migration.object_id, map: migration.target_map, key: entry.key, value: entry.value + '00'};
    })});
  }
  return {done: page.done, cursor: page.cursor, processed: page.entries.length};
};
exports.onAction = function (ctx) {
  return ebpf.mapGet('dataplane', 'sessions_v2', ctx.payload.key);
};
`);
  const host = createTestHost({pluginDir, fixtures: {maps: {dataplane: {sessions_v1: {
    '01': '0a', '02': '0b', '03': '0c'
  }, sessions_v2: {}}}}});
  assert.deepEqual(host.migrateEBPFState({
    object_id: 'dataplane', source_map: 'sessions_v1', target_map: 'sessions_v2'
  }), {status: 'completed', batches: 3, processed: 3});
  assert.equal(host.action('read', {key: '01'}), '0a00');
  assert.equal(host.action('read', {key: '03'}), '0c00');
});

test('test host rejects stalled or incomplete eBPF state map migrations', (t) => {
  const manifest = testManifest('stalled_state_map_migration');
  manifest.control.permissions.push('ebpf.load', 'ebpf.map_read', 'ebpf.map_write');
  const pluginDir = writePlugin(t, manifest, `
ebpf.loadObject({id:'dataplane', path:'dataplane.o', state_maps:[
  {name:'sessions_v1', policy:'preserve', schema_version:1},
  {name:'sessions_v2', policy:'migrate', schema_version:2, migrate_from:'sessions_v1'}
]});
exports.onEBPFStateMigrate = function () { return {done:false, cursor:'01', processed:0}; };
`);
  const host = createTestHost({pluginDir});
  assert.throws(() => host.migrateEBPFState({
    object_id: 'dataplane', source_map: 'sessions_v1', target_map: 'sessions_v2'
  }), /made no progress/);
});

test('test host normalizes hook ordering references and rejects contradictory edges', (t) => {
  const manifest = testManifest('ordered_hooks');
  manifest.control.permissions.push('hook.attach');
  const pluginDir = writePlugin(t, manifest, `
hooks.attach({
  id: 'ordered', engine: 'tc', stage: 'pre_forward', program: 'object:program',
  before: [' FIREWALL / CHECK ', 'firewall/check'], after: ['pppoe/decap']
});
exports.onReconcile = function () {};
`);
  const hook = createTestHost({pluginDir}).snapshot().surface.hooks[0];
  assert.deepEqual(hook.before, ['firewall/check']);
  assert.deepEqual(hook.after, ['pppoe/decap']);

  const invalidDir = writePlugin(t, Object.assign(testManifest('bad_ordered_hooks'), {
    control: {main: 'control.js', permissions: ['hook.attach']},
  }), `
hooks.attach({id:'bad', engine:'tc', stage:'pre_forward', program:'object:program', before:['a/h'], after:['a/h']});
`);
  assert.throws(() => createTestHost({pluginDir: invalidDir}), /both before and after/);
});

test('test host normalizes packet metadata bindings and rejects unsafe contracts', (t) => {
  const manifest = testManifest('packet_metadata');
  manifest.control.permissions.push('hook.attach');
  const pluginDir = writePlugin(t, manifest, `
hooks.attach({
  id: 'producer', engine: 'tc', stage: 'pre_forward', program: 'object:program',
  packet_metadata: [{slot: 3, namespace: ' PACKET_METADATA / CLASSIFIER ', access: 'READ_WRITE', max_bytes: 24}]
});
`);
  const binding = createTestHost({pluginDir}).snapshot().surface.hooks[0].packet_metadata[0];
  assert.deepEqual(binding, {
    slot: 3, namespace: 'packet_metadata/classifier', schema_version: 1, max_bytes: 24, access: 'read_write'
  });

  const invalidDir = writePlugin(t, Object.assign(testManifest('bad_packet_metadata'), {
    control: {main: 'control.js', permissions: ['hook.attach']},
  }), `
hooks.attach({id:'bad', engine:'tc', stage:'pre_forward', program:'object:program', packet_metadata:[
  {slot:0, namespace:'bad', access:'read_write'}
]});
`);
  assert.throws(() => createTestHost({pluginDir: invalidDir}), /plugin_id\/name/);
});

test('test host supports bounded map scans and explicit ring adapters', (t) => {
  const manifest = testManifest('ebpf_reads');
  manifest.control.permissions.push('ebpf.map_read', 'ebpf.map_write');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'read', runtime_update: 'runtime_query'});
exports.onAction = function () {
  ebpf.mapPut('stats', 'values', '00000001', '0102');
  ebpf.mapPut('stats', 'values', '00000002', '0304');
  return {
    scan: ebpf.mapScan('stats', 'values', {limit: 1, max_bytes: 16}),
    ring: ebpf.ringRead('stats', 'events', {max_records: 1, max_bytes: 16, timeout_ms: 1})
  };
};
`);
  const host = createTestHost({
    pluginDir,
    adapters: {
      'ebpf.ringRead': () => ({
        records: [{data: 'aabb', size: 2, remaining: 0}], bytes: 2,
        dropped_records: 0, remaining: 0, timed_out: false, limit_reached: false,
      }),
    },
  });
  const result = host.action('read');
  assert.deepEqual(result.scan, {
    entries: [{key: '00000001', value: '0102'}], cursor: '00000001', done: false,
  });
  assert.equal(result.ring.records[0].data, 'aabb');
});

test('test host delivers subscribed ring records to a persistent worker', (t) => {
  const manifest = testManifest('ring_push');
  manifest.control.permissions.push('ebpf.load', 'ebpf.map_read');
  const pluginDir = writePlugin(t, manifest, `
ebpf.loadObject({id: 'observer', path: 'observer.o'});
ebpf.ringSubscribe({
  id: 'events', object: 'observer', map: 'events', worker: 'reader', handler: 'onRing',
  max_records: 4, max_bytes: 64
});
let ringBatches = 0;
exports.onRing = function (ctx) {
  ringBatches++;
  kv.set('ring_batches', ringBatches);
  kv.set('last_ring', ctx.payload);
  return {count: ringBatches, first: ctx.payload.records[0].data};
};
`);
  const host = createTestHost({pluginDir});

  assert.deepEqual(host.ring('events', ['aabb', {data: 'cc', remaining: 3}]), {count: 1, first: 'aabb'});
  assert.deepEqual(host.ring('events', ['dd']), {count: 2, first: 'dd'});

  const snapshot = host.snapshot();
  assert.equal(snapshot.kv.ring_batches, 2);
  assert.equal(snapshot.kv.last_ring.subscription, 'events');
  assert.equal(snapshot.ring_deliveries.length, 2);
  const stats = host.context.ebpf.ringStats();
  assert.equal(stats.subscription_count, 1);
  assert.equal(stats.delivered_batches, 2);
  assert.equal(stats.read_records, 3);
  assert.equal(stats.read_bytes, 4);
});

test('test host aggregates bounded counter and gauge metrics', (t) => {
  const manifest = testManifest('metrics_plugin');
  manifest.control.permissions.push('metrics');
  const pluginDir = writePlugin(t, manifest, `
plugin.action({id: 'read_metrics', runtime_update: 'runtime_query'});
exports.onReconcile = function () {
  metrics.counter('reconciles_total', {source: 'test'});
  metrics.counter('reconciles_total', 2, {source: 'test'});
  metrics.gauge('ready', 1);
};
exports.onAction = function () { return metrics.list(); };
`);
  const host = createTestHost({pluginDir});
  host.reconcile();
  const metrics = host.action('read_metrics');
  assert.deepEqual(metrics.map((metric) => [metric.name, metric.value]), [['ready', 1], ['reconciles_total', 3]]);
  assert.equal(host.snapshot().metrics.length, 2);
});
