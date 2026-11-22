//! Host methods the worker serves itself, inside the plugin's process.
//!
//! Plugins are native code running in a root worker, so a host method that is
//! only a system call (reading links, sending a frame, hashing bytes) costs a
//! round trip to the host for nothing. The worker answers those here, with the
//! same arguments, results, permission and net_access checks as the host.
//! Methods that need the host's state (storage, ownership of network objects,
//! the dataplane chain, managed processes, event delivery) still go to it.

pub mod policy;
pub mod rtattr;

mod crypto;
#[cfg(target_os = "linux")]
mod ethtool;
mod fields;
mod l2;
mod net;
mod udp;
#[cfg(target_os = "linux")]
mod rtnl;

use veer_plugin::sys::{VEER_ERROR, VEER_OK};
use veer_plugin::Value;

pub use policy::Policy;

/// A method failure, reported to the plugin the way the host reports one.
#[derive(Debug)]
pub struct Failure {
    pub status: i32,
    pub message: String,
}

impl Failure {
    pub fn error(message: impl Into<String>) -> Failure {
        Failure { status: VEER_ERROR, message: message.into() }
    }
}

pub type Outcome = Result<Value, Failure>;

/// A local method: None hands the call to the host after all (for instance a
/// network query for a namespace the host owns).
type Handler = fn(&Local, u32, &[Value]) -> Option<Outcome>;

/// Per-instance local state; only the dispatch thread uses it.
pub struct Local {
    policy: Policy,
    /// The methods the host lets this worker serve (worker_methods in the
    /// LOAD config): those whose host implementation is the plain system
    /// one. None (an older host) allows all.
    allowed: Option<Vec<String>>,
    /// The running handler's deadline (Unix ms; 0 when none), from the MSG.
    deadline_ms: std::cell::Cell<u64>,
    #[cfg(target_os = "linux")]
    rtnl: std::cell::RefCell<Option<rtnl::Rtnl>>,
}

impl Local {
    pub fn new(config: &Value) -> Local {
        let allowed = config.get("worker_methods").and_then(Value::as_array).map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect());
        Local {
            policy: Policy::from_config(config),
            allowed,
            deadline_ms: std::cell::Cell::new(0),
            #[cfg(target_os = "linux")]
            rtnl: std::cell::RefCell::new(None),
        }
    }

    pub fn set_deadline_ms(&self, deadline_ms: u64) {
        self.deadline_ms.set(deadline_ms);
    }

    /// boundedTransportTimeout: a wait never outlasts the handler's deadline.
    pub fn bounded_timeout(&self, timeout_ms: i64, api: &str) -> Result<i64, Failure> {
        let deadline = self.deadline_ms.get();
        if deadline == 0 {
            return Ok(timeout_ms);
        }
        let remaining = deadline as i64 - veer_plugin::js::now_ms() as i64;
        if remaining <= 1 {
            return Err(Failure::error(format!("{api}: plugin execution deadline exceeded")));
        }
        Ok(timeout_ms.min(remaining))
    }

    /// The instance's rtnetlink socket, opened on first use and dropped after
    /// an error.
    #[cfg(target_os = "linux")]
    pub fn with_rtnl<T>(&self, f: impl FnOnce(&mut rtnl::Rtnl) -> Result<T, String>) -> Result<T, String> {
        let mut slot = self.rtnl.borrow_mut();
        if slot.is_none() {
            *slot = Some(rtnl::Rtnl::open().map_err(|err| rtnl::errno_text(err.raw_os_error().unwrap_or(libc::EIO)))?);
        }
        let result = f(slot.as_mut().unwrap());
        if result.is_err() {
            *slot = None;
        }
        result
    }

    /// Serves `method` here when the worker implements it: Some(status,
    /// reply), with the reply JSON on success and the error text otherwise.
    /// `kind` is the message being handled (some phases refuse permissions).
    pub fn call(&self, kind: u32, method: &str, arguments: &[u8]) -> Option<(i32, Vec<u8>)> {
        if self.allowed.as_ref().is_some_and(|allowed| !allowed.iter().any(|name| name == method)) {
            return None;
        }
        let handler: Handler = match method {
            "crypto.md5" => |local, kind, args| Some(crypto::md5(local, kind, args)),
            "crypto.randomBytes" => |local, kind, args| Some(crypto::random_bytes(local, kind, args)),
            "net.link.get" => net::link_get,
            "net.link.list" => net::link_list,
            "net.link.getOffloads" => net::link_get_offloads,
            "net.l2.send" => l2::send,
            "net.l2.recv" => l2::recv,
            "net.l2.recvMany" => l2::recv_many,
            "net.l2.exchange" => l2::exchange,
            "net.l2.exchangeMany" => l2::exchange_many,
            "net.udp.send" => udp::send,
            "net.udp.recv" => udp::recv,
            "net.udp.exchange" => udp::exchange,
            _ => return None,
        };
        let args = match parse_arguments(method, arguments) {
            Ok(args) => args,
            Err(failure) => return Some((failure.status, failure.message.into_bytes())),
        };
        Some(match handler(self, kind, &args)? {
            Ok(value) => (VEER_OK, value.to_string().into_bytes()),
            Err(failure) => (failure.status, failure.message.into_bytes()),
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

fn parse_arguments(method: &str, arguments: &[u8]) -> Result<Vec<Value>, Failure> {
    let text = std::str::from_utf8(arguments).map_err(|_| invalid(format!("{method}: arguments are not UTF-8")))?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    match text.parse::<Value>() {
        Ok(Value::Array(items)) => Ok(items),
        Ok(_) => Err(invalid(format!("{method}: arguments must be a JSON array"))),
        Err(err) => Err(invalid(format!("{method}: arguments must be a JSON array: {err}"))),
    }
}

fn invalid(message: String) -> Failure {
    Failure { status: veer_plugin::sys::VEER_EINVAL, message }
}

/// The argument at `index`, or null when the plugin passed fewer.
pub fn arg(args: &[Value], index: usize) -> &Value {
    args.get(index).unwrap_or(&Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    fn local(permissions: &[&str]) -> Local {
        Local::new(&json!({"permissions": permissions}))
    }

    #[test]
    fn unknown_methods_go_to_the_host() {
        assert!(local(&[]).call(0, "resources.get", b"[\"a\"]").is_none());
    }

    #[test]
    fn the_host_chooses_what_stays_local() {
        let local = Local::new(&json!({"permissions": ["crypto"], "worker_methods": ["crypto.md5"]}));
        assert!(local.call(0, "crypto.md5", b"[\"a\"]").is_some());
        assert!(local.call(0, "crypto.randomBytes", b"[4]").is_none());
        assert!(Local::new(&json!({"permissions": ["crypto"]})).call(0, "crypto.randomBytes", b"[4]").is_some());
    }

    #[test]
    fn arguments_must_be_an_array() {
        let (status, reply) = local(&["crypto"]).call(0, "crypto.md5", b"{}").unwrap();
        assert_eq!(status, veer_plugin::sys::VEER_EINVAL);
        assert!(String::from_utf8(reply).unwrap().contains("JSON array"));
    }
}
