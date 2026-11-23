//! FakeHost and Harness: the Rust counterpart of the old JavaScript test
//! host. Enabled with the `testing` feature.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::host::{Host, HostBackend, LogLevel};
use crate::{js, Message, MsgKind, Outcome, Plugin};

/// An adapter answers one host method in a test: it gets the call's
/// arguments and returns the result or an error message.
pub type Adapter = Box<dyn FnMut(&[Value]) -> Result<Value, String> + Send>;

#[derive(Default)]
struct FakeState {
    resources: BTreeMap<String, BTreeMap<String, Value>>,
    kv: BTreeMap<String, Value>,
    timers: BTreeMap<String, Value>,
    calls: Vec<(String, Value)>,
    logs: Vec<(LogLevel, String)>,
    posts: Vec<Value>,
    pending_applies: Vec<String>,
    dataplane_reconciles: u64,
    clock_ms: u64,
}

/// An in-memory host: resources, kv and timers behave like the real host's,
/// every call is recorded, and adapters model the rest (the kernel, other
/// plugins, processes).
pub struct FakeHost {
    state: Mutex<FakeState>,
    adapters: Mutex<HashMap<String, Adapter>>,
    runtime_updates: Mutex<HashMap<String, String>>,
    features: Mutex<Vec<String>>,
}

impl FakeHost {
    pub fn new() -> Arc<Self> {
        Arc::new(FakeHost {
            state: Mutex::new(FakeState { clock_ms: 1_700_000_000_000, ..FakeState::default() }),
            adapters: Mutex::new(HashMap::new()),
            runtime_updates: Mutex::new(HashMap::new()),
            features: Mutex::new(Vec::new()),
        })
    }

    pub fn host(self: &Arc<Self>) -> Host {
        Host::new(self.clone())
    }

    /// Answers `method` with `adapter(arguments)` instead of the built-in model.
    pub fn adapter(&self, method: &str, adapter: impl FnMut(&[Value]) -> Result<Value, String> + Send + 'static) {
        self.adapters.lock().unwrap().insert(method.to_string(), Box::new(adapter));
    }

    pub fn set_available_features(&self, features: &[&str]) {
        *self.features.lock().unwrap() = features.iter().map(|feature| feature.to_string()).collect();
    }

    pub fn calls(&self) -> Vec<(String, Value)> {
        self.state.lock().unwrap().calls.clone()
    }

    /// The names of the methods called, in order.
    pub fn call_names(&self) -> Vec<String> {
        self.state.lock().unwrap().calls.iter().map(|(name, _)| name.clone()).collect()
    }

    pub fn calls_to(&self, method: &str) -> Vec<Value> {
        self.state.lock().unwrap().calls.iter().filter(|(name, _)| name == method).map(|(_, args)| args.clone()).collect()
    }

    pub fn clear_calls(&self) {
        self.state.lock().unwrap().calls.clear();
    }

    pub fn logs(&self) -> Vec<(LogLevel, String)> {
        self.state.lock().unwrap().logs.clone()
    }

    pub fn posts(&self) -> Vec<Value> {
        self.state.lock().unwrap().posts.clone()
    }

    /// A stored record, or None.
    pub fn record(&self, resource: &str, key: &str) -> Option<Value> {
        self.state.lock().unwrap().resources.get(resource).and_then(|records| records.get(key)).cloned()
    }

    /// A stored record's data, or null.
    pub fn data(&self, resource: &str, key: &str) -> Value {
        self.record(resource, key).and_then(|record| record.get("data").cloned()).unwrap_or(Value::Null)
    }

    pub fn records(&self, resource: &str) -> Vec<Value> {
        self.state.lock().unwrap().resources.get(resource).map(|records| records.values().cloned().collect()).unwrap_or_default()
    }

    /// Stores a record as the host would, bumping its revision.
    pub fn put_record(&self, resource: &str, key: &str, data: Value, enabled: bool) {
        let mut state = self.state.lock().unwrap();
        Self::store(&mut state, resource, key, data, enabled);
    }

    /// Edits a stored record's data in place and bumps its revision.
    pub fn edit_record(&self, resource: &str, key: &str, edit: impl FnOnce(&mut Value)) {
        let mut state = self.state.lock().unwrap();
        state.clock_ms += 1;
        let clock = state.clock_ms;
        if let Some(record) = state.resources.get_mut(resource).and_then(|records| records.get_mut(key)) {
            if let Some(data) = record.get_mut("data") {
                edit(data);
            }
            let revision = record.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
            record["revision"] = json!(revision);
            record["updated_at"] = json!(format!("t{clock}"));
        }
    }

    pub fn delete_record(&self, resource: &str, key: &str) {
        if let Some(records) = self.state.lock().unwrap().resources.get_mut(resource) {
            records.remove(key);
        }
    }

    pub fn kv(&self, key: &str) -> Option<Value> {
        self.state.lock().unwrap().kv.get(key).cloned()
    }

    pub fn timers(&self) -> BTreeMap<String, Value> {
        self.state.lock().unwrap().timers.clone()
    }

    pub fn timer(&self, name: &str) -> Option<Value> {
        self.state.lock().unwrap().timers.get(name).cloned()
    }

    pub fn remove_timer(&self, name: &str) {
        self.state.lock().unwrap().timers.remove(name);
    }

    /// Changes a set timer in place, e.g. to tell a re-armed one apart.
    pub fn edit_timer(&self, name: &str, edit: impl FnOnce(&mut Value)) {
        if let Some(timer) = self.state.lock().unwrap().timers.get_mut(name) {
            edit(timer);
        }
    }

    /// Drops every timer, like a new host process.
    pub fn clear_timers(&self) {
        self.state.lock().unwrap().timers.clear();
    }

    pub fn advance_ms(&self, ms: u64) {
        self.state.lock().unwrap().clock_ms += ms;
    }

    /// How many writes to plugin_reconcile resources made the host
    /// reconcile the plugin's dataplane.
    pub fn dataplane_reconciles(&self) -> u64 {
        self.state.lock().unwrap().dataplane_reconciles
    }

    fn store(state: &mut FakeState, resource: &str, key: &str, data: Value, enabled: bool) {
        state.clock_ms += 1;
        let clock = state.clock_ms;
        let records = state.resources.entry(resource.to_string()).or_default();
        let revision = records.get(key).and_then(|record| record.get("revision")).and_then(Value::as_u64).unwrap_or(0) + 1;
        records.insert(
            key.to_string(),
            json!({"key": key, "data": data, "enabled": enabled, "revision": revision, "updated_at": format!("t{clock}")}),
        );
    }

    /// Runs the built-in model of `method`, for an adapter that only
    /// intercepts some calls (for example to fail one resource's writes).
    pub fn call_builtin(&self, method: &str, args: &[Value]) -> Result<Value, String> {
        self.builtin(method, args)
    }

    fn take_pending_applies(&self) -> Vec<String> {
        std::mem::take(&mut self.state.lock().unwrap().pending_applies)
    }

    fn builtin(&self, method: &str, args: &[Value]) -> Result<Value, String> {
        let arg = |index: usize| args.get(index).cloned().unwrap_or(Value::Null);
        let key_of = |index: usize| js::token(&arg(index));
        let mut state = self.state.lock().unwrap();
        match method {
            "resources.get" => Ok(state
                .resources
                .get(&js::text(&arg(0)))
                .and_then(|records| records.get(&key_of(1)))
                .cloned()
                .unwrap_or(Value::Null)),
            "resources.list" => Ok(Value::Array(
                state.resources.get(&js::text(&arg(0))).map(|records| records.values().cloned().collect()).unwrap_or_default(),
            )),
            "resources.set" => {
                let resource = js::text(&arg(0));
                let enabled = !js::is_false(&arg(3));
                Self::store(&mut state, &resource, &key_of(1), arg(2), enabled);
                if js::is_true(&arg(4)) {
                    state.pending_applies.push(resource);
                }
                Ok(Value::Null)
            }
            "resources.delete" => {
                let resource = js::text(&arg(0));
                if let Some(records) = state.resources.get_mut(&resource) {
                    records.remove(&key_of(1));
                }
                if js::is_true(&arg(2)) {
                    state.pending_applies.push(resource);
                }
                Ok(Value::Null)
            }
            "resources.transaction" => {
                let operations = js::array(&arg(0));
                if operations.is_empty() {
                    return Err("resources.transaction requires operations".to_string());
                }
                let backup = state.resources.clone();
                let mut touched: Vec<String> = Vec::new();
                for operation in &operations {
                    let resource = js::text(js::get(operation, "resource"));
                    let key = js::token(js::get(operation, "key"));
                    match js::lower(js::get(operation, "op")).as_str() {
                        "set" => {
                            let enabled = !js::is_false(js::get(operation, "enabled"));
                            Self::store(&mut state, &resource, &key, js::get(operation, "data").clone(), enabled)
                        }
                        "delete" => {
                            if let Some(records) = state.resources.get_mut(&resource) {
                                records.remove(&key);
                            }
                        }
                        other => {
                            state.resources = backup;
                            return Err(format!("unsupported resource transaction operation {other}"));
                        }
                    }
                    if !touched.contains(&resource) {
                        touched.push(resource);
                    }
                }
                let apply = js::is_true(js::get(&arg(1), "apply"));
                if apply {
                    state.pending_applies.extend(touched.iter().cloned());
                }
                Ok(json!({"status": "completed", "operations": operations.len(), "mutated_resources": touched.len(), "applied": apply}))
            }
            "kv.get" => Ok(state.kv.get(&key_of(0)).cloned().unwrap_or(Value::Null)),
            "kv.set" => {
                state.clock_ms += 1;
                let key = key_of(0);
                let record = json!({"key": key, "data": arg(1), "enabled": true, "revision": 1, "updated_at": format!("t{}", state.clock_ms)});
                state.kv.insert(key, record);
                Ok(Value::Null)
            }
            "kv.delete" => {
                state.kv.remove(&key_of(0));
                Ok(Value::Null)
            }
            "kv.list" => {
                // {limit, offset} pages through the records in key order.
                let page = arg(0);
                let offset = page.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
                let limit = page.get("limit").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(usize::MAX);
                Ok(Value::Array(state.kv.values().skip(offset).take(limit).cloned().collect()))
            }
            "timer.setTimeout" | "timer.setInterval" => {
                let name = key_of(0);
                let delay = js::number(&arg(1));
                if !(10.0..=86_400_000.0).contains(&delay) || delay != delay.trunc() {
                    return Err("timer delay is out of range".to_string());
                }
                let kind = if method == "timer.setInterval" { "interval" } else { "timeout" };
                let next_fire = state.clock_ms + delay as u64;
                let payload = if arg(2).is_null() { json!({}) } else { arg(2) };
                state.timers.insert(
                    name.clone(),
                    json!({"name": name, "kind": kind, "delay_ms": delay as u64, "payload": payload, "next_fire": next_fire}),
                );
                Ok(Value::Null)
            }
            "timer.clear" => {
                state.timers.remove(&key_of(0));
                Ok(Value::Null)
            }
            "timer.list" => Ok(Value::Array(state.timers.values().cloned().collect())),
            "log.info" | "log.warn" | "log.error" | "log.debug" => {
                let level = match method {
                    "log.warn" => LogLevel::Warn,
                    "log.error" => LogLevel::Error,
                    "log.debug" => LogLevel::Debug,
                    _ => LogLevel::Info,
                };
                state.logs.push((level, args.iter().map(js::string).collect::<Vec<_>>().join(" ")));
                Ok(Value::Null)
            }
            "plugin.host" => {
                drop(state);
                let features = self.features.lock().unwrap().clone();
                Ok(json!({"os": "linux", "arch": "amd64", "available_features": features, "features": []}))
            }
            _ => Err(format!("{method}: not modeled by the fake host")),
        }
    }
}

impl HostBackend for FakeHost {
    fn call(&self, method: &str, arguments: &[u8]) -> Result<Vec<u8>, String> {
        let args: Value = serde_json::from_slice(arguments).map_err(|err| err.to_string())?;
        let list = match &args {
            Value::Array(items) => items.clone(),
            _ => Vec::new(),
        };
        self.state.lock().unwrap().calls.push((method.to_string(), args));
        // Take the adapter out while it runs, so it may call back into the
        // fake host (for example to read a resource).
        let adapter = self.adapters.lock().unwrap().remove(method);
        let result = match adapter {
            Some(mut adapter) => {
                let result = adapter(&list);
                self.adapters.lock().unwrap().entry(method.to_string()).or_insert(adapter);
                result?
            }
            None => self.builtin(method, &list)?,
        };
        serde_json::to_vec(&result).map_err(|err| err.to_string())
    }

    fn log(&self, level: LogLevel, message: &str) {
        self.state.lock().unwrap().logs.push((level, message.to_string()));
    }

    fn post(&self, payload: &[u8]) -> Result<(), String> {
        let value: Value = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
        self.state.lock().unwrap().posts.push(value);
        Ok(())
    }

    fn monotonic_ns(&self) -> u64 {
        self.state.lock().unwrap().clock_ms * 1_000_000
    }
}

/// Runs a plugin against a [`FakeHost`] the way the real host does: it reads
/// the registration from plugin.json, builds handler contexts, delivers
/// events to matching subscriptions and applies the plugin's own
/// runtime_apply resources after the handler that changed them.
pub struct Harness<P: Plugin> {
    pub fake: Arc<FakeHost>,
    pub host: Host,
    pub plugin: P,
    manifest: Value,
    sequence: u64,
}

impl<P: Plugin> Harness<P> {
    /// Loads the plugin described by the plugin.json at `manifest_path`.
    pub fn load(manifest_path: &str, fake: Arc<FakeHost>) -> Self {
        let text = std::fs::read_to_string(manifest_path).unwrap_or_else(|err| panic!("read {manifest_path}: {err}"));
        let manifest: Value = serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {manifest_path}: {err}"));
        for resource in js::array(manifest.pointer("/control/register/resources").unwrap_or(&Value::Null)) {
            fake.runtime_updates
                .lock()
                .unwrap()
                .insert(js::text(js::get(&resource, "id")), js::text(js::get(&resource, "runtime_update")));
        }
        let host = fake.host();
        let config = json!({"plugin": {"id": manifest["id"], "name": manifest["name"], "version": manifest["version"]}, "root": "", "instance": 1});
        let plugin = P::create(&host, &config).unwrap_or_else(|err| panic!("create plugin: {err}"));
        Harness { fake, host, plugin, manifest, sequence: 0 }
    }

    fn context(&self, kind: &str, extra: Value) -> Value {
        let mut ctx = json!({
            "kind": kind,
            "plugin": {"id": self.manifest["id"], "name": self.manifest["name"], "version": self.manifest["version"]},
        });
        if let (Value::Object(target), Value::Object(fields)) = (&mut ctx, extra) {
            for (key, value) in fields {
                target.insert(key, value);
            }
        }
        ctx
    }

    /// Delivers one message, then the applies it left pending.
    pub fn run(&mut self, kind: MsgKind, handler: &str, ctx: Value) -> crate::Result<Outcome> {
        self.sequence += 1;
        let message = Message { kind, handler: handler.to_string(), sequence: self.sequence, ctx };
        let outcome = self.plugin.handle(&self.host, &message);
        for resource in self.fake.take_pending_applies() {
            self.apply_resource(&resource)?;
        }
        outcome
    }

    fn apply_resource(&mut self, resource: &str) -> crate::Result<()> {
        let update = self.fake.runtime_updates.lock().unwrap().get(resource).cloned().unwrap_or_default();
        match update.as_str() {
            // The host reconciles the dataplane (objects, hooks, rings) while
            // the write runs; the plugin gets no message for it.
            "plugin_reconcile" => {
                self.fake.state.lock().unwrap().dataplane_reconciles += 1;
            }
            "runtime_apply" => {
                let records = Value::Array(self.fake.records(resource));
                let ctx = self.context("resource_apply", json!({"resource": {"id": resource, "runtime_update": update}, "records": records}));
                self.run(MsgKind::ResourceApply, "onResourceApply", ctx)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn reconcile(&mut self) -> crate::Result<Outcome> {
        let ctx = self.context("reconcile", json!({}));
        self.run(MsgKind::Reconcile, "onReconcile", ctx)
    }

    pub fn deactivate(&mut self) -> crate::Result<Outcome> {
        let ctx = self.context("deactivate", json!({}));
        self.run(MsgKind::Deactivate, "onDeactivate", ctx)
    }

    /// Runs an action the manifest registers.
    pub fn action(&mut self, id: &str, payload: Value) -> crate::Result<Outcome> {
        let contract = js::array(self.manifest.pointer("/control/register/actions").unwrap_or(&Value::Null))
            .into_iter()
            .find(|action| js::text(js::get(action, "id")) == id)
            .unwrap_or_else(|| panic!("action {id} is not registered"));
        let ctx = self.context("action", json!({"action": {"id": id, "runtime_update": contract["runtime_update"]}, "payload": payload}));
        self.run(MsgKind::Action, "onAction", ctx)
    }

    /// The value an action returned; panics on errors.
    pub fn query(&mut self, id: &str, payload: Value) -> Value {
        match self.action(id, payload) {
            Ok(Outcome::Value(value)) => value,
            Ok(_) => Value::Null,
            Err(err) => panic!("action {id} failed: {err}"),
        }
    }

    /// Fires a set timer: a timeout is removed first, an interval rescheduled.
    pub fn fire_timer(&mut self, name: &str) -> crate::Result<Outcome> {
        let timer = self.fake.timer(name).unwrap_or_else(|| panic!("timer {name} is not set"));
        if js::text(js::get(&timer, "kind")) == "timeout" {
            self.fake.remove_timer(name);
        }
        let ctx = self.context("timer", json!({"timer": timer}));
        self.run(MsgKind::Timer, "onTimer", ctx)
    }

    /// Delivers one batch of ring buffer records (hex) to a registered ring
    /// subscription, shaped like the host's batches.
    pub fn ring(&mut self, subscription: &str, records: &[String]) -> crate::Result<Outcome> {
        let spec = js::array(self.manifest.pointer("/control/register/ring_subscriptions").unwrap_or(&Value::Null))
            .into_iter()
            .find(|item| js::text(js::get(item, "id")) == subscription)
            .unwrap_or_else(|| panic!("ring subscription {subscription} is not registered"));
        let records: Vec<Value> = records.iter().map(|data| json!({"data": data.to_lowercase(), "size": data.len() / 2, "remaining": 0})).collect();
        let bytes: usize = records.iter().map(|record| record["size"].as_u64().unwrap_or(0) as usize).sum();
        let payload = json!({
            "subscription": subscription, "object": spec["object"], "map": spec["map"], "records": records, "bytes": bytes,
            "dropped_records": 0, "remaining": 0, "limit_reached": false, "read_at": js::iso_now(),
        });
        let handler = js::text(js::get(&spec, "handler"));
        let ctx = self.context("worker", json!({"worker": {"name": "", "handler": handler}, "payload": payload}));
        self.run(MsgKind::Event, &handler, ctx)
    }

    /// Publishes an event to the plugin's matching subscriptions and returns
    /// how many received it.
    pub fn emit(&mut self, topic: &str, payload: Value) -> crate::Result<usize> {
        let mut delivered = 0;
        for subscription in js::array(self.manifest.pointer("/control/register/subscriptions").unwrap_or(&Value::Null)) {
            let wanted = js::text(js::get(&subscription, "topic"));
            let matched = if js::text(js::get(&subscription, "match")) == "prefix" {
                topic == wanted || topic.starts_with(&format!("{wanted}."))
            } else {
                topic == wanted
            };
            if !matched {
                continue;
            }
            self.sequence += 1;
            let event = json!({
                "topic": topic, "subscription": subscription["id"], "sequence": self.sequence, "published_at": "",
                "source_plugin": "veer", "target_plugin": self.manifest["id"],
                "resource": payload.get("resource_id").cloned().unwrap_or(json!("")),
                "schema_version": 1, "delivery": "volatile", "payload": payload,
            });
            let handler = js::text(js::get(&subscription, "handler"));
            let ctx = self.context(
                "event",
                json!({"worker": {"name": "", "handler": handler}, "payload": payload, "event": event, "events": [event]}),
            );
            self.run(MsgKind::Event, &handler, ctx)?;
            delivered += 1;
        }
        Ok(delivered)
    }
}
