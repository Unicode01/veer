//! VPN path probes, health-check.js. Network I/O runs only on the dispatched
//! health worker's own instance. Probe results never repair, restart,
//! withdraw or republish a WAN, and contain no core configuration.

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, json, Result, Value};

use crate::Ctx;

const HEALTH_TIMER: &str = "vpn_health";

fn integer(value: &Value, min: f64, max: f64, fallback: f64) -> Result<f64> {
    let n = if value.is_null() { fallback } else { js::number(value) };
    if !n.is_finite() || n.floor() != n || n < min || n > max {
        bail!("健康检测数值超出范围");
    }
    Ok(n)
}

fn label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// ^https?:\/\/(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::([0-9]+))?(?:[/?][^\s#\\]*)?$
/// Returns (host, port) of a URL without credentials or fragment.
fn parse_url(url: &str) -> Option<(String, Option<String>)> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (host, after) = if let Some(inner) = rest.strip_prefix('[') {
        let close = inner.find(']')?;
        let host = &inner[..close];
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return None;
        }
        (format!("[{host}]"), &inner[close + 1..])
    } else {
        let end = rest.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        (rest[..end].to_string(), &rest[end..])
    };
    let (port, path) = match after.strip_prefix(':') {
        Some(tail) => {
            let end = tail.find(|c: char| !c.is_ascii_digit()).unwrap_or(tail.len());
            if end == 0 {
                return None;
            }
            (Some(tail[..end].to_string()), &tail[end..])
        }
        None => (None, after),
    };
    if !path.is_empty() {
        if !path.starts_with(['/', '?']) || path[1..].chars().any(|c| c.is_whitespace() || c == '#' || c == '\\') {
            return None;
        }
    }
    Some((host, port))
}

/// Validated probe settings with their defaults.
pub fn settings(raw: &Value) -> Result<Value> {
    let raw = if truthy(raw) { raw.clone() } else { json!({}) };
    let Value::Object(map) = &raw else {
        bail!("健康检测设置必须是对象");
    };
    if map.keys().any(|k| !["enabled", "url", "resolver_ip", "interval_seconds", "timeout_ms", "expected_status"].contains(&k.as_str())) {
        bail!("不支持的健康检测设置");
    }
    let enabled = g(&raw, "enabled");
    if !enabled.is_null() && !enabled.is_boolean() {
        bail!("自动检测开关必须为布尔值");
    }
    let url = match g(&raw, "url") {
        Value::Null => "https://www.gstatic.com/generate_204".to_string(),
        value => js::string(value).trim().to_string(),
    };
    // Keep credentials, fragments and control characters out of public results.
    let parsed = parse_url(&url);
    if parsed.is_none() || crate::share::utf16_len(&url) > 2048 || url.chars().any(|c| (c as u32) <= 0x20 || c as u32 == 0x7f || c == '\\') {
        bail!("检测地址须为不含凭据的 HTTP / HTTPS URL");
    }
    let (host, port) = parsed.unwrap();
    if !host.starts_with('[') {
        let trimmed = host.strip_suffix('.').unwrap_or(&host);
        if host.len() > 253 || !trimmed.split('.').all(label_ok) {
            bail!("检测地址的主机名无效");
        }
    }
    if let Some(port) = port {
        integer(&json!(port.parse::<f64>().unwrap_or(f64::NAN)), 1.0, 65535.0, f64::NAN)?;
    }
    let dns = match g(&raw, "resolver_ip") {
        Value::Null => "1.1.1.1".to_string(),
        value => js::string(value).trim().to_string(),
    };
    if !crate::share::ipv4(&dns) {
        bail!("检测 DNS 须为 IPv4 地址");
    }
    let expected = integer(g(&raw, "expected_status"), 0.0, 599.0, 204.0)?;
    if expected > 0.0 && expected < 100.0 {
        bail!("预期状态码须为 100–599，或 0 表示任意 2xx");
    }
    Ok(json!({
        "enabled": js::is_true(enabled), "url": url, "resolver_ip": dns,
        "interval_seconds": integer(g(&raw, "interval_seconds"), 15.0, 3600.0, 60.0)? as i64,
        "timeout_ms": integer(g(&raw, "timeout_ms"), 500.0, 10000.0, 5000.0)? as i64,
        "expected_status": expected as i64,
    }))
}

fn active(op: &Value) -> bool {
    truthy(op) && (js::string(g(op, "status")) == "pending" || js::string(g(op, "status")) == "running")
}

fn failure(error: &str) -> Value {
    let text = error.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    let (reason, message) = if has(&["timeout", "timed out", "deadline"]) {
        ("timeout", "检测超时")
    } else if has(&["lookup", "dns", "resolver", "no such host"]) {
        ("dns", "经 VPN 解析检测域名失败")
    } else if has(&["tls", "certificate", "x509"]) {
        ("tls", "检测目标的 TLS 握手或证书校验失败")
    } else if has(&["body exceeds", "response body"]) {
        ("response_size", "检测响应过大，请使用小响应的检测地址")
    } else {
        ("network", "VPN 请求失败，检查节点连接、认证及目标可达性")
    };
    json!({"reason": reason, "message": message})
}

use crate::now;

impl<'a> Ctx<'a> {
    fn kv_value(&self, key: &str) -> Value {
        self.host.kv_get(key).ok().flatten().map(|record| record.get("data").cloned().unwrap_or(Value::Null)).unwrap_or(Value::Null)
    }

    fn health_config(&self, key: &str) -> Result<Value> {
        settings(&self.kv_value(&format!("health_config_{key}")))
    }

    fn health_operation(&self, key: &str) -> Value {
        self.host.call("operations.getByKey", json!([format!("health_{key}")])).unwrap_or(Value::Null)
    }

    fn probe_path(&mut self, key: &str, worker_read: bool) -> Value {
        self.health_path(key, worker_read).unwrap_or(Value::Null)
    }

    fn health_cancel(&self, op: &Value) -> Result<()> {
        // Only the plugin's own instance owns operation transitions.
        if !active(op) {
            return Ok(());
        }
        let mut op = op.clone();
        if js::string(g(&op, "status")) == "pending" {
            op = self.host.call("operations.claim", json!([op["id"], op["revision"]]))?;
        }
        self.host.call("operations.cancel", json!([op["id"], op["revision"], {"error": "Probe invalidated"}]))?;
        Ok(())
    }

    pub fn health_invalidate(&self, key: &str) -> Result<()> {
        let generation = js::number(js::or(&self.kv_value(&format!("health_generation_{key}")), &json!(0)));
        self.host.kv_set(&format!("health_generation_{key}"), &js::num(if generation.is_finite() { generation + 1.0 } else { f64::NAN }))?;
        self.health_cancel(&self.health_operation(key))
    }

    pub fn health_status(&mut self, key: &str) -> Result<Value> {
        let c = self.health_config(key)?;
        let p = self.probe_path(key, false);
        let op = self.health_operation(key);
        let result = g(&op, "result").clone();
        let mut state = if !truthy(&p) {
            "unavailable".to_string()
        } else if !truthy(&op) {
            "unknown".to_string()
        } else if active(&op) {
            "checking".to_string()
        } else if truthy(&result) {
            js::string(g(&result, "state"))
        } else {
            "unknown".to_string()
        };
        let input = g(&op, "input");
        if truthy(&p) && truthy(&op) && truthy(input) && !js::strict_eq(g(g(input, "path"), "fingerprint"), g(&p, "fingerprint")) {
            state = "stale".to_string();
        }
        if truthy(&p) && active(&op) && now() - js::number(g(input, "started_at")) >= js::number(g(g(input, "config"), "timeout_ms")) + 3000.0 {
            state = "stale".to_string();
        }
        if truthy(&p) && state != "checking" && truthy(&result) && now() - js::number(g(&result, "checked_at")) > (120000f64).max(js::number(&c["interval_seconds"]) * 2000.0) {
            state = "stale".to_string();
        }
        Ok(json!({"key": key, "settings": c, "state": state, "result": if truthy(&result) { result } else { Value::Null }}))
    }

    pub fn health_start(&mut self, key: &str) -> Result<Value> {
        let c = self.health_config(key)?;
        let p = self.probe_path(key, false);
        if !truthy(&p) {
            bail!("出口尚未就绪，请先应用并等待本机接口就绪");
        }
        let old = self.health_operation(key);
        let started = now();
        if active(&old) && started - js::number(&old["input"]["started_at"]) < js::number(&old["input"]["config"]["timeout_ms"]) + 3000.0 {
            return self.health_status(key);
        }
        self.health_cancel(&old)?;
        let same_path = truthy(&old) && js::strict_eq(g(g(g(&old, "input"), "path"), "fingerprint"), g(&p, "fingerprint"));
        let previous = if same_path && truthy(g(&old, "result")) { old["result"].clone() } else { json!({}) };
        let input = json!({"key": key, "config": c, "path": p, "started_at": js::num(started),
            "failures": js::or(g(&previous, "consecutive_failures"), &json!(0)),
            "last_success_at": js::or(g(&previous, "last_success_at"), &json!(0))});
        let op = self.host.call("operations.begin", json!([{"key": format!("health_{key}"), "kind": "vpn_health", "restart": true, "input": input}]))?;
        let op = self.host.call("operations.claim", json!([op["id"], op["revision"]]))?;
        self.host.kv_delete(&format!("health_result_{key}"))?;
        let dispatched = self.host.call("worker.dispatch", json!([format!("health_{key}"), "onHealthProbe", {"id": op["id"], "revision": op["revision"], "input": op["input"]}]));
        if dispatched.is_err() {
            let current = self.host.call("operations.get", json!([op["id"]])).unwrap_or(Value::Null);
            let _ = self.health_cancel(&current);
            bail!("健康检测任务暂不可用，请重试");
        }
        self.health_arm()?;
        self.health_status(key)
    }

    /// Runs on the health worker's instance: reads the applied link
    /// generation, performs the request and writes one mailbox record.
    pub fn health_run(&mut self, payload: &Value) -> Result<()> {
        let input = g(payload, "input");
        let key = js::string(g(input, "key"));
        let before = self.probe_path(&key, true);
        let started = now();
        let mut result;
        if !truthy(&before) || !js::strict_eq(g(&before, "fingerprint"), g(g(input, "path"), "fingerprint")) {
            result = json!({"state": "stale", "reason": "changed", "message": "出口已变化，请重新检测"});
        } else {
            let config = g(input, "config");
            let request = json!({"interface": before["interface"], "source_ip": before["source_ip"], "url": config["url"],
                "method": "GET", "resolver_ip": config["resolver_ip"], "timeout_ms": config["timeout_ms"],
                "max_response_bytes": 4096, "follow_redirects": false});
            result = match self.host.call("net.http.request", json!([request])) {
                Ok(response) => {
                    let code = js::number(g(&response, "status_code"));
                    let expected = js::number(g(config, "expected_status"));
                    let good = if expected != 0.0 { code == expected } else { (200.0..300.0).contains(&code) };
                    json!({"state": if good { "healthy" } else { "unhealthy" }, "status_code": response["status_code"],
                        "reason": if good { "" } else { "http_status" },
                        "message": if good { "VPN 链路可用".to_string() } else { format!("检测目标返回 HTTP {}", js::string(&response["status_code"])) }})
                }
                Err(err) => {
                    let mut out = failure(&err.to_string());
                    out["state"] = json!("unhealthy");
                    out
                }
            };
            let after = self.probe_path(&key, true);
            if !truthy(&after) || !js::strict_eq(g(&after, "fingerprint"), g(&before, "fingerprint")) {
                result = json!({"state": "stale", "reason": "changed", "message": "检测期间出口发生变化，请重新检测"});
            }
        }
        let checked = now();
        result["latency_ms"] = js::num((checked - started).max(0.0));
        result["checked_at"] = js::num(checked);
        let unhealthy = js::string(&result["state"]) == "unhealthy";
        result["consecutive_failures"] = if unhealthy { js::num(js::number(g(input, "failures")) + 1.0) } else { json!(0) };
        result["last_success_at"] = if js::string(&result["state"]) == "healthy" { js::num(checked) } else { g(input, "last_success_at").clone() };
        if self.host.resources_get("profiles", &key)?.is_some() {
            self.host.kv_set(&format!("health_result_{key}"), &json!({"id": payload["id"], "revision": payload["revision"], "result": result}))?;
        }
        Ok(())
    }

    fn health_collect(&mut self, key: &str) -> Result<()> {
        let op = self.health_operation(key);
        let reply = self.kv_value(&format!("health_result_{key}"));
        if !active(&op) {
            return Ok(());
        }
        if truthy(&reply) && js::strict_eq(g(&reply, "id"), g(&op, "id")) && js::strict_eq(g(&reply, "revision"), g(&op, "revision")) {
            let current = self.probe_path(key, false);
            let mut result = reply["result"].clone();
            if !truthy(&current) || !js::strict_eq(g(&current, "fingerprint"), &op["input"]["path"]["fingerprint"]) {
                result = json!({"state": "stale", "reason": "changed", "message": "检测期间出口发生变化，请重新检测", "checked_at": js::num(now())});
            }
            self.host.call("operations.complete", json!([op["id"], op["revision"], result]))?;
            self.host.kv_delete(&format!("health_result_{key}"))?;
        } else if now() - js::number(&op["input"]["started_at"]) >= js::number(&op["input"]["config"]["timeout_ms"]) + 3000.0 {
            let input = &op["input"];
            let result = json!({"state": "unhealthy", "reason": "timeout", "message": "检测任务超时", "checked_at": js::num(now()),
                "latency_ms": js::num(now() - js::number(&input["started_at"])), "consecutive_failures": js::num(js::number(&input["failures"]) + 1.0),
                "last_success_at": input["last_success_at"]});
            self.host.call("operations.complete", json!([op["id"], op["revision"], result]))?;
        }
        Ok(())
    }

    pub fn health_arm(&mut self) -> Result<()> {
        let leases = self.all_leases()?;
        let running = leases.keys().any(|key| active(&self.health_operation(key)));
        let mut enabled = false;
        for (key, lease) in &leases {
            if js::is_true(g(lease, "active")) && js::is_true(&self.health_config(key)?["enabled"]) {
                enabled = true;
                break;
            }
        }
        if running || enabled {
            self.host.timer_set_interval(HEALTH_TIMER, if running { 1000 } else { 5000 }, &json!({}))
        } else {
            self.host.timer_clear(HEALTH_TIMER)
        }
    }

    pub fn health_remove(&mut self, key: &str) -> Result<()> {
        self.health_invalidate(key)?;
        let op = self.health_operation(key);
        if truthy(&op) {
            self.host.call("operations.remove", json!([op["id"]]))?;
        }
        for prefix in ["health_config_", "health_generation_", "health_result_"] {
            self.host.kv_delete(&format!("{prefix}{key}"))?;
        }
        Ok(())
    }

    pub fn health_configure(&mut self, key: &str, raw: &Value) -> Result<Value> {
        let c = settings(raw)?;
        self.health_invalidate(key)?;
        self.host.kv_set(&format!("health_config_{key}"), &c)?;
        self.health_arm()?;
        self.health_status(key)
    }

    pub fn health_tick(&mut self) -> Result<()> {
        let leases = self.all_leases()?;
        for (key, lease) in &leases {
            let outcome = (|| -> Result<()> {
                self.health_collect(key)?;
                let c = self.health_config(key)?;
                let op = self.health_operation(key);
                if !js::is_true(g(lease, "active")) || !js::is_true(&c["enabled"]) {
                    return Ok(());
                }
                let p = self.probe_path(key, false);
                let recent = truthy(&op)
                    && js::strict_eq(&op["input"]["path"]["fingerprint"], g(&p, "fingerprint"))
                    && now() - js::number(&op["input"]["started_at"]) < js::number(&c["interval_seconds"]) * 1000.0;
                if !truthy(&p) || recent {
                    return Ok(());
                }
                self.health_start(key)?;
                Ok(())
            })();
            if outcome.is_err() {
                self.host.warn(&format!("VPN health probe could not be queued: {key}"));
            }
        }
        self.health_arm()
    }

    pub fn health_all(&mut self) -> Result<Value> {
        let records = js::array(&self.host.call("resources.list", json!(["profiles", {"limit": 8}]))?);
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            items.push(self.health_status(&js::string(&record["key"]))?);
        }
        Ok(json!({"items": items}))
    }

    pub fn health_stop(&mut self) -> Result<()> {
        self.host.timer_clear(HEALTH_TIMER)?;
        for key in self.all_leases()?.keys() {
            self.health_cancel(&self.health_operation(key))?;
        }
        Ok(())
    }
}
