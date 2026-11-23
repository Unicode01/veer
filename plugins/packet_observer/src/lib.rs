//! Packet Observer: the example plugin. Its eBPF object, pipeline hook,
//! resource, action and page are declared in plugin.json; the control side
//! only records the last apply request.

use veer_plugin::js::{self, get as g};
use veer_plugin::{export_plugin, json, Host, Message, Outcome, Plugin, Result, Value};

pub struct PacketObserver;

impl Plugin for PacketObserver {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(PacketObserver)
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        match msg.handler.as_str() {
            "onReconcile" => {
                host.call("log.info", json!(["control script loaded"]))?;
                Ok(Outcome::Done)
            }
            "onAction" => {
                let record = json!({
                    "action": g(g(&msg.ctx, "action"), "id"),
                    "payload": js::or(g(&msg.ctx, "payload"), &json!({})),
                    "updated_at": js::iso_now(),
                });
                host.kv_set("last_apply", &record)?;
                Ok(Outcome::Done)
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(PacketObserver, "packet_observer");

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::testing::{FakeHost, Harness};

    #[test]
    fn apply_records_the_request() {
        let mut h = Harness::<PacketObserver>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), FakeHost::new());
        h.reconcile().unwrap();
        h.action("apply", json!({"source": "test"})).unwrap();
        let record = h.fake.kv("last_apply").expect("last_apply");
        assert_eq!(record["data"]["action"], "apply");
        assert_eq!(record["data"]["payload"]["source"], "test");
        assert!(record["data"]["updated_at"].as_str().unwrap().ends_with('Z'));
    }
}
