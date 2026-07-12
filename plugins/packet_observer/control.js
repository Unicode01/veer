plugin.capabilities(['observe', 'tc']);
pipeline.node({
  id: 'vtap0',
  description: 'Example logical pipeline node.'
});
ebpf.loadObject({
  id: 'packet_observer',
  path: 'packet_observer.o',
  description: 'Minimal TC pre_forward chain program used for plugin object validation.',
  programs: [
    {id: 'tc_pre_forward', section: 'tc/fvtap/pre_forward', type: 'tc'}
  ]
});
pipeline.attach({
  id: 'observe-ingress',
  direction: 'forward',
  priority: 10,
  program: 'packet_observer:tc_pre_forward',
  mode: 'observe',
  interfaces: []
});
plugin.resource({
  id: 'bindings',
  description: 'Plugin-owned JSON records persisted by the host for control-plane code.',
  methods: ['list', 'get', 'create', 'update', 'delete'],
  runtime_update: 'manual',
  max_records: 64,
  max_record_bytes: 4096
});
plugin.action({
  id: 'apply',
  description: 'Example explicit Goja control-plane action. It persists the latest apply payload into the plugin KV namespace.',
  runtime_update: 'runtime_apply',
  max_payload_bytes: 4096
});
ui.register({
  static_dir: 'ui',
  entry: 'index.html',
  page: 'observe',
  page_title: 'Observe'
});

exports.onReconcile = function () {
  log.info('control script loaded');
};

exports.onAction = function (ctx) {
  kv.set('last_apply', {
    action: ctx.action && ctx.action.id,
    payload: ctx.payload || {},
    updated_at: new Date().toISOString()
  });
};
