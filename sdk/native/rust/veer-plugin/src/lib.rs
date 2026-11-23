//! Rust SDK for Veer native plugins.
//!
//! A plugin implements [`Plugin`] and exports it with [`export_plugin!`]:
//!
//! ```ignore
//! use veer_plugin::{export_plugin, json, Host, Message, Outcome, Plugin, Result, Value};
//!
//! struct Echo;
//!
//! impl Plugin for Echo {
//!     fn create(_host: &Host, _config: &Value) -> Result<Self> {
//!         Ok(Echo)
//!     }
//!
//!     fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
//!         match msg.handler.as_str() {
//!             "onAction" => Ok(Outcome::Value(msg.ctx["payload"].clone())),
//!             "onReconcile" => {
//!                 host.call("kv.set", json!(["seen", true]))?;
//!                 Ok(Outcome::Done)
//!             }
//!             _ => Ok(Outcome::Unhandled),
//!         }
//!     }
//! }
//!
//! export_plugin!(Echo, "echo");
//! ```
//!
//! Every host API method is reached through [`Host::call`] with the method
//! name and its arguments as a JSON array.

pub mod js;
pub mod netconf;
pub mod sys;

mod api;
mod error;
mod host;
mod json;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(any(test, feature = "testing"))]
mod harness;

pub use error::{Context, Error, Result};
pub use host::{Host, HostBackend, LogLevel};
pub use json::ValueExt;
pub use serde_json::{json, Map, Value};

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// The kind of a message, from `veer_msg_kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgKind {
    Reconcile,
    Deactivate,
    Event,
    Timer,
    Action,
    ResourceApply,
    ResourceMigrate,
    EbpfStateMigrate,
    UpgradeSnapshot,
    UpgradeRestore,
    Wake,
    Unknown(u32),
}

impl MsgKind {
    pub fn from_code(code: u32) -> Self {
        match code {
            1 => MsgKind::Reconcile,
            2 => MsgKind::Deactivate,
            3 => MsgKind::Event,
            4 => MsgKind::Timer,
            5 => MsgKind::Action,
            6 => MsgKind::ResourceApply,
            7 => MsgKind::ResourceMigrate,
            8 => MsgKind::EbpfStateMigrate,
            9 => MsgKind::UpgradeSnapshot,
            10 => MsgKind::UpgradeRestore,
            11 => MsgKind::Wake,
            other => MsgKind::Unknown(other),
        }
    }

    pub fn code(self) -> u32 {
        match self {
            MsgKind::Reconcile => 1,
            MsgKind::Deactivate => 2,
            MsgKind::Event => 3,
            MsgKind::Timer => 4,
            MsgKind::Action => 5,
            MsgKind::ResourceApply => 6,
            MsgKind::ResourceMigrate => 7,
            MsgKind::EbpfStateMigrate => 8,
            MsgKind::UpgradeSnapshot => 9,
            MsgKind::UpgradeRestore => 10,
            MsgKind::Wake => 11,
            MsgKind::Unknown(other) => other,
        }
    }
}

/// One message for a plugin instance.
#[derive(Clone, Debug)]
pub struct Message {
    pub kind: MsgKind,
    /// The handler name: `onReconcile`, `onAction`, `onTimer`, a subscription
    /// handler such as `onNetEvent`, and so on.
    pub handler: String,
    pub sequence: u64,
    /// The handler context, the same object a JavaScript handler received.
    pub ctx: Value,
}

impl Message {
    pub fn new(kind: MsgKind, handler: impl Into<String>, ctx: Value) -> Self {
        Message { kind, handler: handler.into(), sequence: 0, ctx }
    }
}

/// What a handler did.
#[derive(Debug)]
pub enum Outcome {
    /// Handled; no result value.
    Done,
    /// Handled with a result (query actions, snapshots, migrations).
    Value(Value),
    /// The plugin has no handler for this message.
    Unhandled,
}

/// A native plugin.
pub trait Plugin: Send + 'static {
    /// Creates the instance. `config` holds `plugin` (id, name, version),
    /// `root` (the plugin directory) and `instance` (a number).
    fn create(host: &Host, config: &Value) -> Result<Self>
    where
        Self: Sized;

    /// Handles one message. Never called concurrently for one instance.
    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome>;
}

#[doc(hidden)]
pub mod __export {
    use super::*;

    struct Instance<P: Plugin> {
        plugin: P,
        host: Host,
        ffi_table: *const sys::veer_host_v1,
        poisoned: bool,
    }

    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(text) = payload.downcast_ref::<&str>() {
            (*text).to_string()
        } else if let Some(text) = payload.downcast_ref::<String>() {
            text.clone()
        } else {
            "unknown panic".to_string()
        }
    }

    /// # Safety
    /// Called by the worker with a valid host table and config slice.
    pub unsafe fn create<P: Plugin>(table: *const sys::veer_host_v1, config: sys::veer_slice) -> *mut c_void {
        if table.is_null() || ((*table).struct_size as usize) < std::mem::size_of::<sys::veer_host_v1>() {
            return std::ptr::null_mut();
        }
        let config_bytes = config.as_bytes().to_vec();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let backend = Arc::new(host::FfiHost::new(table));
            let host = Host::new(backend);
            let config: Value = if config_bytes.is_empty() {
                Value::Object(Map::new())
            } else {
                match serde_json::from_slice(&config_bytes) {
                    Ok(value) => value,
                    Err(err) => {
                        host.error(&format!("plugin config is not valid JSON: {err}"));
                        return None;
                    }
                }
            };
            match P::create(&host, &config) {
                Ok(plugin) => Some(Box::new(Instance { plugin, host, ffi_table: table, poisoned: false })),
                Err(err) => {
                    host.error(&format!("plugin create failed: {err}"));
                    None
                }
            }
        }));
        match result {
            Ok(Some(instance)) => Box::into_raw(instance) as *mut c_void,
            _ => std::ptr::null_mut(),
        }
    }

    /// # Safety
    /// `instance` must come from `create::<P>` and not be used afterwards.
    pub unsafe fn destroy<P: Plugin>(instance: *mut c_void) {
        if instance.is_null() {
            return;
        }
        let instance = Box::from_raw(instance as *mut Instance<P>);
        let _ = catch_unwind(AssertUnwindSafe(move || drop(instance)));
    }

    /// # Safety
    /// Called by the worker with pointers it owns.
    pub unsafe fn handle<P: Plugin>(instance: *mut c_void, msg: *const sys::veer_msg, reply: *mut sys::veer_buf) -> i32 {
        if instance.is_null() || msg.is_null() {
            return sys::VEER_EINVAL;
        }
        let instance = &mut *(instance as *mut Instance<P>);
        let table = instance.ffi_table;
        if instance.poisoned {
            sys::write_buf(table, reply, b"plugin instance is unusable after a panic");
            return sys::VEER_ESHUTDOWN;
        }
        let raw = &*msg;
        let handler = String::from_utf8_lossy(raw.handler.as_bytes()).into_owned();
        let payload = raw.payload.as_bytes();
        let ctx: Value = if payload.is_empty() {
            Value::Object(Map::new())
        } else {
            match serde_json::from_slice(payload) {
                Ok(value) => value,
                Err(err) => {
                    sys::write_buf(table, reply, format!("message payload is not valid JSON: {err}").as_bytes());
                    return sys::VEER_EINVAL;
                }
            }
        };
        let message = Message { kind: MsgKind::from_code(raw.kind), handler, sequence: raw.sequence, ctx };
        let host = instance.host.clone();
        let plugin = &mut instance.plugin;
        match catch_unwind(AssertUnwindSafe(|| plugin.handle(&host, &message))) {
            Ok(Ok(Outcome::Done)) => sys::VEER_OK,
            Ok(Ok(Outcome::Value(value))) => match serde_json::to_vec(&value) {
                Ok(bytes) => sys::write_buf(table, reply, &bytes),
                Err(err) => {
                    sys::write_buf(table, reply, format!("encode result: {err}").as_bytes());
                    sys::VEER_ERROR
                }
            },
            Ok(Ok(Outcome::Unhandled)) => sys::VEER_UNHANDLED,
            Ok(Err(err)) => {
                let text = err.to_string();
                sys::write_buf(table, reply, if text.is_empty() { b"plugin handler failed" } else { text.as_bytes() });
                sys::VEER_ERROR
            }
            Err(panic) => {
                instance.poisoned = true;
                let text = format!("plugin panicked in {}: {}", message.handler, panic_message(panic.as_ref()));
                sys::write_buf(table, reply, text.as_bytes());
                sys::VEER_ESHUTDOWN
            }
        }
    }
}

/// Exports a [`Plugin`] type as the library's `veer_plugin_entry`.
#[macro_export]
macro_rules! export_plugin {
    ($plugin:ty, $id:literal) => {
        #[no_mangle]
        pub extern "C" fn veer_plugin_entry(host_abi_major: u16) -> *const $crate::sys::veer_plugin_v1 {
            unsafe extern "C" fn __veer_create(
                host: *const $crate::sys::veer_host_v1,
                config: $crate::sys::veer_slice,
            ) -> *mut ::std::ffi::c_void {
                $crate::__export::create::<$plugin>(host, config)
            }
            unsafe extern "C" fn __veer_destroy(instance: *mut ::std::ffi::c_void) {
                $crate::__export::destroy::<$plugin>(instance)
            }
            unsafe extern "C" fn __veer_handle(
                instance: *mut ::std::ffi::c_void,
                msg: *const $crate::sys::veer_msg,
                reply: *mut $crate::sys::veer_buf,
            ) -> i32 {
                $crate::__export::handle::<$plugin>(instance, msg, reply)
            }
            static TABLE: $crate::sys::veer_plugin_v1 = $crate::sys::veer_plugin_v1 {
                struct_size: ::std::mem::size_of::<$crate::sys::veer_plugin_v1>() as u32,
                abi_major: $crate::sys::VEER_PLUGIN_ABI_MAJOR,
                abi_minor: $crate::sys::VEER_PLUGIN_ABI_MINOR,
                id: concat!($id, "\0").as_ptr() as *const ::std::ffi::c_char,
                create: Some(__veer_create),
                destroy: Some(__veer_destroy),
                handle: Some(__veer_handle),
            };
            if host_abi_major != $crate::sys::VEER_PLUGIN_ABI_MAJOR {
                return ::std::ptr::null();
            }
            &TABLE
        }
    };
}
