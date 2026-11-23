use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::sys;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn code(self) -> i32 {
        match self {
            LogLevel::Debug => sys::VEER_LOG_DEBUG,
            LogLevel::Info => sys::VEER_LOG_INFO,
            LogLevel::Warn => sys::VEER_LOG_WARN,
            LogLevel::Error => sys::VEER_LOG_ERROR,
        }
    }
}

/// What a [`Host`] forwards to. The worker's function table implements it in
/// production; `testing::MockHost` implements it in tests.
pub trait HostBackend: Send + Sync {
    /// Calls a host method. `arguments` and the result are JSON.
    fn call(&self, method: &str, arguments: &[u8]) -> std::result::Result<Vec<u8>, String>;
    fn log(&self, level: LogLevel, message: &str);
    fn post(&self, payload: &[u8]) -> std::result::Result<(), String>;
    fn monotonic_ns(&self) -> u64;
}

/// The plugin's handle to the Veer host API.
#[derive(Clone)]
pub struct Host {
    backend: Arc<dyn HostBackend>,
}

impl Host {
    pub fn new(backend: Arc<dyn HostBackend>) -> Self {
        Host { backend }
    }

    /// Calls a host API method. `arguments` must be a JSON array holding the
    /// method's arguments in order, e.g. `json!(["sessions", key, record])`
    /// for `resources.set`.
    pub fn call(&self, method: &str, arguments: Value) -> Result<Value> {
        let arguments = match arguments {
            Value::Array(_) => arguments,
            Value::Null => Value::Array(Vec::new()),
            other => Value::Array(vec![other]),
        };
        let request = serde_json::to_vec(&arguments)?;
        // Host errors already name the API ("net.link.delete: ..."), like the
        // exceptions JavaScript plugins saw.
        let reply = self.backend.call(method, &request).map_err(|message| {
            if message.is_empty() {
                Error::msg(format!("{method} failed"))
            } else {
                Error::msg(message)
            }
        })?;
        if reply.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&reply).map_err(|err| Error::msg(format!("{method}: decode result: {err}")))
    }

    /// Calls a host method and decodes the result into `T`.
    pub fn call_as<T: DeserializeOwned>(&self, method: &str, arguments: Value) -> Result<T> {
        let value = self.call(method, arguments)?;
        serde_json::from_value(value).map_err(|err| Error::msg(format!("{method}: decode result: {err}")))
    }

    pub fn log(&self, level: LogLevel, message: &str) {
        self.backend.log(level, message);
    }

    pub fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, message);
    }

    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, message);
    }

    pub fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, message);
    }

    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, message);
    }

    /// Queues a wake message for this instance. Safe on any thread.
    pub fn post(&self, payload: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(payload)?;
        self.backend.post(&bytes).map_err(Error::msg)
    }

    pub fn monotonic_ns(&self) -> u64 {
        self.backend.monotonic_ns()
    }

    pub fn monotonic_ms(&self) -> u64 {
        self.backend.monotonic_ns() / 1_000_000
    }
}

/// Forwards to the worker's `veer_host_v1` table.
pub(crate) struct FfiHost {
    table: *const sys::veer_host_v1,
}

// The worker makes log, post, buf_reserve and monotonic_ns safe on any
// thread, and rejects call() outside the dispatch thread.
unsafe impl Send for FfiHost {}
unsafe impl Sync for FfiHost {}

impl FfiHost {
    /// # Safety
    /// `table` must stay valid until the instance is destroyed.
    pub(crate) unsafe fn new(table: *const sys::veer_host_v1) -> Self {
        FfiHost { table }
    }

    fn release(&self, buf: &mut sys::veer_buf) {
        unsafe {
            if let Some(reserve) = (*self.table).buf_reserve {
                reserve((*self.table).ctx, buf, 0);
            }
        }
    }
}

impl HostBackend for FfiHost {
    fn call(&self, method: &str, arguments: &[u8]) -> std::result::Result<Vec<u8>, String> {
        unsafe {
            let call = (*self.table).call.ok_or_else(|| "host call is unavailable".to_string())?;
            let mut reply = sys::veer_buf { data: std::ptr::null_mut(), len: 0, cap: 0 };
            let status = call(
                (*self.table).ctx,
                sys::veer_slice::from_bytes(method.as_bytes()),
                sys::veer_slice::from_bytes(arguments),
                &mut reply,
            );
            let bytes = if reply.data.is_null() || reply.len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(reply.data, reply.len.min(reply.cap)).to_vec()
            };
            self.release(&mut reply);
            if status == sys::VEER_OK {
                Ok(bytes)
            } else {
                let message = String::from_utf8_lossy(&bytes).into_owned();
                Err(if message.is_empty() { format!("host call failed with status {status}") } else { message })
            }
        }
    }

    fn log(&self, level: LogLevel, message: &str) {
        unsafe {
            if let Some(log) = (*self.table).log {
                log((*self.table).ctx, level.code(), sys::veer_slice::from_bytes(message.as_bytes()));
            }
        }
    }

    fn post(&self, payload: &[u8]) -> std::result::Result<(), String> {
        unsafe {
            let post = (*self.table).post.ok_or_else(|| "host post is unavailable".to_string())?;
            let status = post((*self.table).ctx, sys::veer_slice::from_bytes(payload));
            if status == sys::VEER_OK {
                Ok(())
            } else {
                Err(format!("post failed with status {status}"))
            }
        }
    }

    fn monotonic_ns(&self) -> u64 {
        unsafe {
            match (*self.table).monotonic_ns {
                Some(now) => now((*self.table).ctx),
                None => 0,
            }
        }
    }
}
