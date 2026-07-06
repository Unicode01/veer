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
