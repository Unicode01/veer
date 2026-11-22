//! The plugin's declared permissions and net_access, as the host applies them
//! (internal/app/plugin_control.go). In the worker they guard against plugin
//! mistakes; they are not a security boundary, since the plugin is native code
//! in the same process.

use std::net::IpAddr;

use veer_plugin::sys::VEER_EPERM;
use veer_plugin::Value;

use super::Failure;

// Message kinds whose host phases refuse permissions (veer_plugin.h).
const MSG_RESOURCE_MIGRATE: u32 = 7;
const MSG_EBPF_STATE_MIGRATE: u32 = 8;
const MSG_UPGRADE_SNAPSHOT: u32 = 9;
const MSG_UPGRADE_RESTORE: u32 = 10;

#[derive(Debug, Default, Clone)]
pub struct NetAccess {
    pub interfaces: Vec<String>,
    pub operations: Vec<String>,
    pub remote_hosts: Vec<String>,
    pub remote_cidrs: Vec<String>,
    pub remote_ports: Vec<i64>,
}

#[derive(Debug, Default)]
pub struct Policy {
    permissions: Vec<String>,
    net_access: Vec<NetAccess>,
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

impl Policy {
    pub fn from_config(config: &Value) -> Policy {
        let net_access = config
            .get("net_access")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| NetAccess {
                        interfaces: strings(&item["interfaces"]),
                        operations: strings(&item["operations"]),
                        remote_hosts: strings(&item["remote_hosts"]),
                        remote_cidrs: strings(&item["remote_cidrs"]),
                        remote_ports: item["remote_ports"].as_array().map(|ports| ports.iter().filter_map(Value::as_i64).collect()).unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Calls for named network namespaces go to the host, which checks
        // namespace_access and ownership itself.
        Policy { permissions: strings(&config["permissions"]), net_access }
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|value| value == permission)
    }

    /// The host's requirePermission: refused in some phases, then declared.
    pub fn require(&self, kind: u32, permission: &str) -> Result<(), Failure> {
        let phase = match kind {
            MSG_RESOURCE_MIGRATE => Some("plugin resource migration"),
            MSG_UPGRADE_SNAPSHOT | MSG_UPGRADE_RESTORE => Some("plugin upgrade snapshot/restore"),
            MSG_EBPF_STATE_MIGRATE if permission != "ebpf.map_read" && permission != "ebpf.map_write" => Some("eBPF state migration"),
            _ => None,
        };
        if let Some(phase) = phase {
            return Err(denied(format!("permission {permission} is unavailable during {phase}")));
        }
        if !self.has_permission(permission) {
            return Err(denied(format!("permission {permission} is required")));
        }
        Ok(())
    }

    pub fn has_net_access(&self, operation: &str, interface: &str) -> bool {
        self.net_access.iter().any(|access| has_operation(access, operation) && matches_interface(access, interface))
    }

    pub fn require_net_access(&self, operation: &str, interface: &str, api: &str) -> Result<(), Failure> {
        if self.has_net_access(operation, interface) {
            return Ok(());
        }
        Err(denied(format!("{api}: net_access operation {operation} on interface {interface} is not declared")))
    }

    pub fn has_any_net_access(&self, operation: &str) -> bool {
        self.net_access.iter().any(|access| has_operation(access, operation) && !access.interfaces.is_empty())
    }

    pub fn require_any_net_access(&self, operation: &str, api: &str) -> Result<(), Failure> {
        if self.has_any_net_access(operation) {
            return Ok(());
        }
        Err(denied(format!("{api}: net_access operation {operation} is not declared")))
    }

    /// The remote endpoint check of pluginControlNetEndpointPolicyFor.
    pub fn endpoint(&self, operation: &str, interface: &str, host: &str, ip: Option<IpAddr>, port: i64) -> Result<Endpoint, String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut endpoint = Endpoint::default();
        for access in &self.net_access {
            if !has_operation(access, operation) || !matches_interface(access, interface) {
                continue;
            }
            if !matches_remote_host(access, &host) || !matches_remote_port(access, port) {
                continue;
            }
            endpoint.authorized = true;
            if access.remote_cidrs.is_empty() {
                endpoint.any_ip = true;
                endpoint.prefixes.clear();
                break;
            }
            endpoint.prefixes.extend(access.remote_cidrs.iter().filter_map(|value| Prefix::parse(value)));
        }
        let label = endpoint_label(&host, ip, port);
        if !endpoint.authorized {
            return Err(format!("network endpoint access {operation} on interface {interface} for {label} is not declared"));
        }
        if let Some(ip) = ip {
            if !endpoint.allows(ip) {
                return Err(format!("network endpoint access {operation} on interface {interface} for {label} is outside remote_cidrs"));
            }
        }
        Ok(endpoint)
    }
}

fn denied(message: String) -> Failure {
    Failure { status: VEER_EPERM, message }
}

fn has_operation(access: &NetAccess, operation: &str) -> bool {
    access.operations.iter().any(|value| value == operation)
}

fn matches_interface(access: &NetAccess, interface: &str) -> bool {
    access.interfaces.iter().any(|pattern| interface_pattern_matches(pattern, interface))
}

fn matches_remote_host(access: &NetAccess, host: &str) -> bool {
    if access.remote_hosts.is_empty() {
        return true;
    }
    if host.is_empty() {
        return false;
    }
    access.remote_hosts.iter().any(|pattern| {
        if pattern == "*" || pattern == host {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            if suffix.starts_with('.') && host.len() > suffix.len() && host.ends_with(suffix) {
                return true;
            }
        }
        false
    })
}

fn matches_remote_port(access: &NetAccess, port: i64) -> bool {
    access.remote_ports.is_empty() || access.remote_ports.contains(&port)
}

/// pluginInterfacePatternMatches: '*' matches any run of characters.
pub fn interface_pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == name;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(index) = name[pos..].find(part) else {
            return false;
        };
        if i == 0 && !pattern.starts_with('*') && index != 0 {
            return false;
        }
        pos += index + part.len();
    }
    if !pattern.ends_with('*') {
        if let Some(last) = parts.iter().rev().find(|part| !part.is_empty()) {
            if !name.ends_with(last) {
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, Copy)]
pub struct Prefix {
    addr: IpAddr,
    bits: u8,
}

impl Prefix {
    pub fn parse(value: &str) -> Option<Prefix> {
        let (addr, bits) = value.trim().split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return None;
        }
        Some(Prefix { addr, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, unmap(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits) };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[derive(Debug, Default, Clone)]
pub struct Endpoint {
    pub authorized: bool,
    pub any_ip: bool,
    pub prefixes: Vec<Prefix>,
}

impl Endpoint {
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.authorized && (self.any_ip || self.prefixes.iter().any(|prefix| prefix.contains(ip)))
    }
}

fn endpoint_label(host: &str, ip: Option<IpAddr>, port: i64) -> String {
    let mut value = match ip {
        Some(ip) => ip.to_string(),
        None => host.to_string(),
    };
    if value.is_empty() {
        value = "<unspecified>".to_string();
    }
    if port > 0 {
        if value.contains(':') {
            return format!("[{value}]:{port}");
        }
        return format!("{value}:{port}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    #[test]
    fn patterns_match_like_the_host() {
        for (pattern, name, want) in [
            ("*", "eth0", true),
            ("eth0", "eth0", true),
            ("eth0", "eth1", false),
            ("veer*", "veerwg1", true),
            ("veer*", "xveer", false),
            ("*wg*", "veerwg1", true),
            ("br*0", "brlan0", true),
            ("br*0", "brlan1", false),
            ("*0", "eth0", true),
        ] {
            assert_eq!(interface_pattern_matches(pattern, name), want, "{pattern} vs {name}");
        }
    }

    #[test]
    fn permissions_and_phases() {
        let policy = Policy::from_config(&json!({"permissions": ["crypto", "ebpf.map_read"]}));
        assert!(policy.require(0, "crypto").is_ok());
        assert!(policy.require(0, "net.l2").unwrap_err().message.contains("is required"));
        assert!(policy.require(9, "crypto").unwrap_err().message.contains("upgrade"));
        assert!(policy.require(8, "crypto").unwrap_err().message.contains("eBPF state migration"));
        assert!(policy.require(8, "ebpf.map_read").is_ok());
    }

    #[test]
    fn net_access_and_endpoints() {
        let policy = Policy::from_config(&json!({"net_access": [
            {"interfaces": ["veerwg*"], "operations": ["http"], "remote_cidrs": ["203.0.113.0/24"], "remote_ports": [8080]},
            {"interfaces": ["*"], "operations": ["link.read"]},
        ]}));
        assert!(policy.has_net_access("link.read", "anything"));
        assert!(!policy.has_net_access("link.write", "eth0"));
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(policy.endpoint("http", "veerwg1", "", Some(ip), 8080).is_ok());
        assert!(policy.endpoint("http", "veerwg1", "", Some(ip), 80).unwrap_err().contains("not declared"));
        let outside: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(policy.endpoint("http", "veerwg1", "", Some(outside), 8080).unwrap_err().contains("outside remote_cidrs"));
        let mapped: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        assert!(policy.endpoint("http", "veerwg1", "", Some(mapped), 8080).is_ok());
    }

    #[test]
    fn remote_host_wildcards() {
        let access = NetAccess { remote_hosts: vec!["*.example.com".into()], ..Default::default() };
        assert!(matches_remote_host(&access, "a.example.com"));
        assert!(!matches_remote_host(&access, "example.com"));
        assert!(!matches_remote_host(&access, ""));
    }
}
