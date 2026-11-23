//! A scriptable fake host for unit-testing plugins without a worker.
//!
//! ```ignore
//! let mock = MockHost::new();
//! mock.on("kv.get", |_args| Ok(json!(null)));
//! let host = mock.host();
//! let mut plugin = MyPlugin::create(&host, &json!({}))?;
//! plugin.handle(&host, &Message::new(MsgKind::Reconcile, "onReconcile", json!({})))?;
//! assert_eq!(mock.calls_to("kv.set").len(), 1);
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::host::{Host, HostBackend, LogLevel};

pub use crate::harness::{Adapter, FakeHost, Harness};

type Handler = Box<dyn FnMut(&Value) -> Result<Value, String> + Send>;
type Fallback = Box<dyn FnMut(&str, &Value) -> Result<Value, String> + Send>;

/// Records every call and answers from per-method handlers.
pub struct MockHost {
    handlers: Mutex<HashMap<String, Handler>>,
    fallback: Mutex<Option<Fallback>>,
    calls: Mutex<Vec<(String, Value)>>,
    logs: Mutex<Vec<(LogLevel, String)>>,
    posts: Mutex<Vec<Value>>,
    now_ns: AtomicU64,
}

impl MockHost {
    pub fn new() -> Arc<Self> {
        Arc::new(MockHost {
            handlers: Mutex::new(HashMap::new()),
            fallback: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
            logs: Mutex::new(Vec::new()),
            posts: Mutex::new(Vec::new()),
            now_ns: AtomicU64::new(1_000_000_000),
        })
    }

    pub fn host(self: &Arc<Self>) -> Host {
        Host::new(self.clone())
    }

    /// Answers `method` with `handler(arguments)`.
    pub fn on(&self, method: &str, handler: impl FnMut(&Value) -> Result<Value, String> + Send + 'static) {
        self.handlers.lock().unwrap().insert(method.to_string(), Box::new(handler));
    }

    /// Answers methods without a handler. Without a fallback they return null.
    pub fn fallback(&self, handler: impl FnMut(&str, &Value) -> Result<Value, String> + Send + 'static) {
        *self.fallback.lock().unwrap() = Some(Box::new(handler));
    }

    pub fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }

    pub fn calls_to(&self, method: &str) -> Vec<Value> {
        self.calls.lock().unwrap().iter().filter(|(name, _)| name == method).map(|(_, args)| args.clone()).collect()
    }

    pub fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    pub fn logs(&self) -> Vec<(LogLevel, String)> {
        self.logs.lock().unwrap().clone()
    }

    pub fn posts(&self) -> Vec<Value> {
        self.posts.lock().unwrap().clone()
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now_ns.fetch_add(ms * 1_000_000, Ordering::SeqCst);
    }
}

impl HostBackend for MockHost {
    fn call(&self, method: &str, arguments: &[u8]) -> Result<Vec<u8>, String> {
        let args: Value = serde_json::from_slice(arguments).map_err(|err| err.to_string())?;
        self.calls.lock().unwrap().push((method.to_string(), args.clone()));
        let mut handlers = self.handlers.lock().unwrap();
        let result = if let Some(handler) = handlers.get_mut(method) {
            handler(&args)
        } else {
            drop(handlers);
            let mut fallback = self.fallback.lock().unwrap();
            match fallback.as_mut() {
                Some(handler) => handler(method, &args),
                None => Ok(Value::Null),
            }
        }?;
        serde_json::to_vec(&result).map_err(|err| err.to_string())
    }

    fn log(&self, level: LogLevel, message: &str) {
        self.logs.lock().unwrap().push((level, message.to_string()));
    }

    fn post(&self, payload: &[u8]) -> Result<(), String> {
        let value: Value = serde_json::from_slice(payload).map_err(|err| err.to_string())?;
        self.posts.lock().unwrap().push(value);
        Ok(())
    }

    fn monotonic_ns(&self) -> u64 {
        self.now_ns.load(Ordering::SeqCst)
    }
}
