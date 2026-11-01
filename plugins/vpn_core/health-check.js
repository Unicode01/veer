// Network I/O runs only in a dedicated worker. Probe results never repair,
// restart, withdraw or republish a WAN, and contain no core configuration.
function integer(value, min, max, fallback) {
  var n = value == null ? fallback : Number(value);
  if (!isFinite(n) || Math.floor(n) !== n || n < min || n > max) throw new Error('健康检测数值超出范围');
  return n;
}
exports.settings = function (raw) {
  raw = raw || {};
  if (typeof raw !== 'object' || Array.isArray(raw)) throw new Error('健康检测设置必须是对象');
  Object.keys(raw).forEach(function (k) {
    if (['enabled', 'url', 'resolver_ip', 'interval_seconds', 'timeout_ms', 'expected_status'].indexOf(k) < 0) throw new Error('不支持的健康检测设置');
  });
  if (raw.enabled != null && typeof raw.enabled !== 'boolean') throw new Error('自动检测开关必须为布尔值');
  var url = raw.url == null ? 'https://www.gstatic.com/generate_204' : String(raw.url).trim();
  // Keep credentials, fragments and control characters out of public results.
  var match = /^https?:\/\/(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::([0-9]+))?(?:[/?][^\s#\\]*)?$/.exec(url);
  if (!match || url.length > 2048 || /[\x00-\x20\x7f\\]/.test(url)) throw new Error('检测地址须为不含凭据的 HTTP / HTTPS URL');
  if (match[1][0] !== '[' && (match[1].length > 253 || !match[1].replace(/\.$/, '').split('.').every(function (v) { return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(v); }))) throw new Error('检测地址的主机名无效');
  if (match[2]) integer(match[2], 1, 65535);
  var dns = raw.resolver_ip == null ? '1.1.1.1' : String(raw.resolver_ip).trim();
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(dns) || !dns.split('.').every(function (v) { return String(Number(v)) === v && Number(v) <= 255; })) throw new Error('检测 DNS 须为 IPv4 地址');
  var expected = integer(raw.expected_status, 0, 599, 204);
  if (expected > 0 && expected < 100) throw new Error('预期状态码须为 100–599，或 0 表示任意 2xx');
  return {enabled: raw.enabled === true, url: url, resolver_ip: dns,
    interval_seconds: integer(raw.interval_seconds, 15, 3600, 60), timeout_ms: integer(raw.timeout_ms, 500, 10000, 5000),
    expected_status: expected};
};
function active(op) { return op && (op.status === 'pending' || op.status === 'running'); }
function failure(error) {
  var text = String(error && error.message || error).toLowerCase();
  if (/timeout|timed out|deadline/.test(text)) return {reason: 'timeout', message: '检测超时'};
  if (/lookup|dns|resolver|no such host/.test(text)) return {reason: 'dns', message: '经 VPN 解析检测域名失败'};
  if (/tls|certificate|x509/.test(text)) return {reason: 'tls', message: '检测目标的 TLS 握手或证书校验失败'};
  if (/body exceeds|response body/.test(text)) return {reason: 'response_size', message: '检测响应过大，请使用小响应的检测地址'};
  return {reason: 'network', message: 'VPN 请求失败，检查节点连接、认证及目标可达性'};
}
exports.create = function (env) {
  function value(key) { var r = kv.get(key); return r && r.data; }
  function config(key) { return exports.settings(value('health_config_' + key)); }
  function operation(key) { return operations.getByKey('health_' + key); }
  function path(key, workerRead) { try { return env.path(key, workerRead); } catch (_) { return null; } }
  function cancel(op) {
    // Only the serialized main VM owns operation transitions.
    if (!active(op)) return;
    if (op.status === 'pending') op = operations.claim(op.id, op.revision);
    operations.cancel(op.id, op.revision, {error: 'Probe invalidated'});
  }
  function invalidate(key) {
    kv.set('health_generation_' + key, Number(value('health_generation_' + key) || 0) + 1);
    cancel(operation(key));
  }
  function status(key) {
    var c = config(key), p = path(key), op = operation(key), result = op && op.result;
    var state = !p ? 'unavailable' : !op ? 'unknown' : active(op) ? 'checking' : result ? result.state : 'unknown';
    if (p && op && op.input && op.input.path.fingerprint !== p.fingerprint) state = 'stale';
    if (p && active(op) && Date.now() - op.input.started_at >= op.input.config.timeout_ms + 3000) state = 'stale';
    if (p && state !== 'checking' && result && Date.now() - result.checked_at > Math.max(120000, c.interval_seconds * 2000)) state = 'stale';
    return {key: key, settings: c, state: state, result: result || null};
  }
  function start(key) {
    var c = config(key), p = path(key);
    if (!p) throw new Error('出口尚未就绪，请先应用并等待本机接口就绪');
    var old = operation(key), now = Date.now();
    if (active(old) && now - old.input.started_at < old.input.config.timeout_ms + 3000) return status(key);
    cancel(old);
    var previous = old && old.input.path.fingerprint === p.fingerprint && old.result || {};
    var op = operations.begin({key: 'health_' + key, kind: 'vpn_health', restart: true,
      input: {key: key, config: c, path: p, started_at: now, failures: previous.consecutive_failures || 0, last_success_at: previous.last_success_at || 0}});
    op = operations.claim(op.id, op.revision);
    kv.delete('health_result_' + key);
    try { worker.dispatch('health_' + key, 'onHealthProbe', {id: op.id, revision: op.revision, input: op.input}); }
    catch (_) { cancel(operations.get(op.id)); throw new Error('健康检测任务暂不可用，请重试'); }
    arm();
    return status(key);
  }
  function run(payload) {
    // Durable operations and process management belong to the main VM. Workers
    // only read the applied link generation, perform I/O and write one mailbox.
    var input = payload.input, before = path(input.key, true), result, started = Date.now();
    if (!before || before.fingerprint !== input.path.fingerprint) result = {state: 'stale', reason: 'changed', message: '出口已变化，请重新检测'};
    else {
      try {
        var response = net.http.request({interface: before.interface, source_ip: before.source_ip, url: input.config.url,
          method: 'GET', resolver_ip: input.config.resolver_ip, timeout_ms: input.config.timeout_ms,
          max_response_bytes: 4096, follow_redirects: false});
        var code = response.status_code, good = input.config.expected_status ? code === input.config.expected_status : code >= 200 && code < 300;
        result = {state: good ? 'healthy' : 'unhealthy', status_code: code, reason: good ? '' : 'http_status', message: good ? 'VPN 链路可用' : '检测目标返回 HTTP ' + code};
      } catch (e) { result = failure(e); result.state = 'unhealthy'; }
      var after = path(input.key, true);
      if (!after || after.fingerprint !== before.fingerprint) result = {state: 'stale', reason: 'changed', message: '检测期间出口发生变化，请重新检测'};
    }
    result.latency_ms = Math.max(0, Date.now() - started); result.checked_at = Date.now();
    result.consecutive_failures = result.state === 'unhealthy' ? input.failures + 1 : 0;
    result.last_success_at = result.state === 'healthy' ? result.checked_at : input.last_success_at;
    if (resources.get('profiles', input.key)) kv.set('health_result_' + input.key, {id: payload.id, revision: payload.revision, result: result});
  }
  function collect(key) {
    var op = operation(key), reply = value('health_result_' + key);
    if (!active(op)) return;
    if (reply && reply.id === op.id && reply.revision === op.revision) {
      var current = path(key), result = reply.result;
      if (!current || current.fingerprint !== op.input.path.fingerprint) result = {state: 'stale', reason: 'changed', message: '检测期间出口发生变化，请重新检测', checked_at: Date.now()};
      operations.complete(op.id, op.revision, result);
      kv.delete('health_result_' + key);
    } else if (Date.now() - op.input.started_at >= op.input.config.timeout_ms + 3000) {
      operations.complete(op.id, op.revision, {state: 'unhealthy', reason: 'timeout', message: '检测任务超时', checked_at: Date.now(), latency_ms: Date.now() - op.input.started_at, consecutive_failures: op.input.failures + 1, last_success_at: op.input.last_success_at});
    }
  }
  function arm() {
    var leases = env.leases(), keys = Object.keys(leases);
    var running = keys.some(function (key) { return active(operation(key)); });
    if (running || keys.some(function (key) { return leases[key].active && config(key).enabled; })) timer.setInterval('vpn_health', running ? 1000 : 5000, {});
    else timer.clear('vpn_health');
  }
  return {status: status, start: start, run: run, invalidate: invalidate, arm: arm,
    remove: function (key) {
      invalidate(key);
      var op = operation(key); if (op) operations.remove(op.id);
      ['health_config_', 'health_generation_', 'health_result_'].forEach(function (prefix) { kv.delete(prefix + key); });
    },
    configure: function (key, raw) { var c = exports.settings(raw); invalidate(key); kv.set('health_config_' + key, c); arm(); return status(key); },
    tick: function () {
      var leases = env.leases();
      Object.keys(leases).forEach(function (key) {
        try {
          collect(key);
          var c = config(key), op = operation(key);
          if (!leases[key].active || !c.enabled) return;
          var p = path(key);
          if (!p || (op && op.input.path.fingerprint === p.fingerprint && Date.now() - op.input.started_at < c.interval_seconds * 1000)) return;
          start(key);
        } catch (_) { log.warn('VPN health probe could not be queued: ' + key); }
      });
      arm();
    },
    all: function () { return {items: resources.list('profiles', {limit: 8}).map(function (r) { return status(r.key); })}; },
    stop: function () { timer.clear('vpn_health'); Object.keys(env.leases()).forEach(function (key) { cancel(operation(key)); }); }
  };
};
