//! A minimal native plugin. The host's conformance tests use it to check
//! loading, message delivery, host calls, errors, panics, crashes, timeouts
//! and wake messages.

use veer_plugin::{bail, export_plugin, json, Host, Message, MsgKind, Outcome, Plugin, Result, Value, ValueExt};

pub struct Echo {
    reconciles: u64,
    counted: u64,
}

impl Plugin for Echo {
    fn create(host: &Host, config: &Value) -> Result<Self> {
        host.debug(&format!("echo created for {}", config.path("plugin.id").as_str().unwrap_or("?")));
        Ok(Echo { reconciles: 0, counted: 0 })
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        match msg.kind {
            MsgKind::Reconcile => {
                self.reconciles += 1;
                host.call("kv.set", json!(["reconciles", self.reconciles]))?;
                Ok(Outcome::Done)
            }
            MsgKind::Action => self.action(host, msg),
            MsgKind::Wake => {
                host.call("kv.set", json!(["woke", msg.ctx.field("payload").clone()]))?;
                Ok(Outcome::Done)
            }
            MsgKind::Timer => {
                host.call("kv.set", json!(["timer", msg.ctx.path("timer.name").clone()]))?;
                Ok(Outcome::Done)
            }
            MsgKind::Event if msg.handler == "onSlow" => {
                // Runs on the "slow" worker's own instance (worker.dispatch).
                std::thread::sleep(std::time::Duration::from_millis(msg.ctx.field("payload").u64_of("ms")));
                host.call("kv.set", json!(["slow_done", true]))?;
                Ok(Outcome::Done)
            }
            MsgKind::Event if msg.handler == "onCount" => {
                // Events arrive in batches: ctx.events holds every one.
                self.counted += msg.ctx.arr_of("events").len().max(1) as u64;
                Ok(Outcome::Done)
            }
            MsgKind::Event => {
                host.call("kv.set", json!(["event", msg.ctx.field("event").clone()]))?;
                Ok(Outcome::Done)
            }
            MsgKind::Deactivate => {
                host.call("kv.set", json!(["deactivated", true]))?;
                Ok(Outcome::Done)
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

impl Echo {
    fn action(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        let payload = msg.ctx.field("payload");
        match msg.ctx.path("action.id").as_str().unwrap_or("") {
            "echo" => Ok(Outcome::Value(json!({"echo": payload, "handler": msg.handler, "sequence": msg.sequence}))),
            "count" => Ok(Outcome::Value(json!(self.counted))),
            "kv" => {
                host.call("kv.set", json!(["value", payload]))?;
                let value = host.call("kv.get", json!(["value"]))?;
                Ok(Outcome::Value(value))
            }
            "fail" => bail!("echo failed on purpose"),
            "host_error" => {
                host.call("no.such.method", json!([]))?;
                Ok(Outcome::Done)
            }
            "panic" => panic!("echo panicked on purpose"),
            "crash" => std::process::abort(),
            "sleep" => {
                std::thread::sleep(std::time::Duration::from_millis(payload.u64_of("ms")));
                Ok(Outcome::Done)
            }
            "post" => {
                let host = host.clone();
                let value = payload.clone();
                std::thread::spawn(move || {
                    let _ = host.post(&value);
                });
                Ok(Outcome::Done)
            }
            "dispatch" => {
                host.call("worker.dispatch", json!(["slow", "onSlow", {"ms": payload.u64_of("ms")}]))?;
                Ok(Outcome::Done)
            }
            "timer" => {
                host.call("timer.setTimeout", json!(["echo_timer", payload.u64_of("ms").max(10), {"from": "echo"}]))?;
                Ok(Outcome::Done)
            }
            "host_call" => {
                // The raw result or error of any host method, so tests can
                // compare the worker's own answers with the host's.
                let method = payload.str_of("method");
                let args = payload.field("args").clone();
                Ok(Outcome::Value(match host.call(method, args) {
                    Ok(value) => json!({"value": value}),
                    Err(err) => json!({"error": err.message()}),
                }))
            }
            "call_from_thread" => {
                let host = host.clone();
                let result = std::thread::spawn(move || host.call("kv.get", json!(["value"])).err().map(|err| err.to_string()))
                    .join()
                    .unwrap_or(Some("thread panicked".to_string()));
                Ok(Outcome::Value(json!({"error": result})))
            }
            other => bail!("unknown echo action {other:?}"),
        }
    }
}

export_plugin!(Echo, "native_echo");

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::testing::MockHost;

    #[test]
    fn reconcile_counts_and_stores() {
        let mock = MockHost::new();
        let host = mock.host();
        let mut echo = Echo::create(&host, &json!({"plugin": {"id": "native_echo"}})).unwrap();
        echo.handle(&host, &Message::new(MsgKind::Reconcile, "onReconcile", json!({}))).unwrap();
        echo.handle(&host, &Message::new(MsgKind::Reconcile, "onReconcile", json!({}))).unwrap();
        assert_eq!(mock.calls_to("kv.set"), vec![json!(["reconciles", 1]), json!(["reconciles", 2])]);
    }

    #[test]
    fn echo_action_returns_payload() {
        let mock = MockHost::new();
        let host = mock.host();
        let mut echo = Echo::create(&host, &json!({})).unwrap();
        let ctx = json!({"action": {"id": "echo"}, "payload": {"x": 1}});
        match echo.handle(&host, &Message::new(MsgKind::Action, "onAction", ctx)).unwrap() {
            Outcome::Value(value) => assert_eq!(value["echo"], json!({"x": 1})),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    #[test]
    fn failing_action_reports_error() {
        let mock = MockHost::new();
        let host = mock.host();
        let mut echo = Echo::create(&host, &json!({})).unwrap();
        let ctx = json!({"action": {"id": "fail"}});
        let err = echo.handle(&host, &Message::new(MsgKind::Action, "onAction", ctx)).unwrap_err();
        assert!(err.to_string().contains("on purpose"));
    }
}
