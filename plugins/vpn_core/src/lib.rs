//! VPN WAN: opt-in WAN adapters for kernel WireGuard, Mihomo, sing-box and
//! external TUN cores. Every driver shares the tunnel adapter. WireGuard
//! keeps its own WAN keys and netdev names (wg_<key>, vwg<key>,
//! veerwg<slot>) because Egress NAT selects them.
//!
//! Exits are checked when something changes, not on a polling tick: a link
//! event (the tunnel, the WAN boundary or a chained front going away, down or
//! being replaced) or a core process changing state arms EVENT_TIMER, which
//! checks the core, the tunnel, the boundary and the TC map entries of every
//! exit and repairs what differs. An exit that is still negotiating its TUN
//! offloads is checked again every PENDING_RETRY_MS, a failed repair with
//! backoff from RETRY_MIN_MS to RETRY_MAX_MS, and REPAIR_TIMER checks
//! everything every SAFETY_REPAIR_MS in case an event was lost. The TC map
//! entries have no event: MAP_TIMER reads them every MAP_CHECK_MS and puts
//! back what the last check or install wrote (two map reads per exit, no
//! link or record reads).

#![recursion_limit = "256"]

pub mod drivers;
pub mod health;
pub mod share;

use std::collections::BTreeMap;

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, export_plugin, json, Error, Host, Map, Message, Outcome, Plugin, Result, Value};

const IP: &str = "/usr/sbin/ip";
const WG: &str = "/usr/bin/wg";
const NFT: &str = "/usr/sbin/nft";
const SYSCTL: &str = "/usr/sbin/sysctl";
// A proxy exit may use another exit as its upstream; at most two exits in front.
const MAX_CHAIN: usize = 2;
const PROTOCOL: &str = "242"; // Used only when cleaning up leases from the old routing example.
const OBJECT: &str = "tunnel_adapter";
const MAP: &str = "tunnel_links";
const REPAIR_TIMER: &str = "tunnel_repair";
const EVENT_TIMER: &str = "tunnel_event";
const RETRY_TIMER: &str = "tunnel_retry";
const MAP_TIMER: &str = "tunnel_maps";
const HOOK_IN: &str = "tunnel-links";
const HOOK_DIRECT_OUT: &str = "tunnel-direct-out";
const SAFETY_REPAIR_MS: u64 = 300000;
const EVENT_REPAIR_DELAY_MS: u64 = 250;
const PENDING_RETRY_MS: u64 = 1000;
const MAP_CHECK_MS: u64 = 5000;
const RETRY_MIN_MS: u64 = 2000;
const RETRY_MAX_MS: u64 = 60000;
const KFUNCS_FEATURE: &str = "dataplane.kfuncs.handoff.v1";
const DIRECT_FEATURE: &str = "dataplane.kfuncs.handoff_ingress.v1";

/// Errors the page can explain start with a stable [code]; the WebUI
/// localizes the code and shows the English rest as the diagnostic.
pub fn fail(code: &str, message: &str) -> Error {
    Error::msg(format!("[{code}] {message}"))
}

/// The adapter entries last written for an exit and the ifindexes they
/// belong to.
struct Expected {
    tunnel: Value,
    pipeline: Value,
    entries: Vec<Value>,
}

pub struct VpnCore {
    /// Host capabilities, learned on the first message.
    features: Option<(bool, bool)>,
    changing: bool,
    /// Per exit key; dropped whenever the entries are withdrawn on purpose.
    expected_maps: BTreeMap<String, Expected>,
    /// Retry delay per exit key whose last repair failed.
    retry_delays: BTreeMap<String, u64>,
}

impl Plugin for VpnCore {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(VpnCore { features: None, changing: false, expected_maps: BTreeMap::new(), retry_delays: BTreeMap::new() })
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        if self.features.is_none() {
            let info = host.call("plugin.host", json!([])).unwrap_or(Value::Null);
            let has = |name: &str| js::array(g(&info, "available_features")).iter().any(|f| f.as_str() == Some(name));
            let kfuncs = has(KFUNCS_FEATURE);
            self.features = Some((kfuncs, kfuncs && has(DIRECT_FEATURE)));
        }
        let (kfuncs, direct) = self.features.unwrap();
        let mut ctx = Ctx { host, kfuncs, direct, st: self };
        let c = &msg.ctx;
        match msg.handler.as_str() {
            "onAction" => {
                let value = ctx.on_action(c)?;
                Ok(Outcome::Value(value))
            }
            "onReconcile" => {
                ctx.on_reconcile()?;
                Ok(Outcome::Done)
            }
            "onTimer" => {
                ctx.on_timer(&js::string(g(g(c, "timer"), "name")))?;
                Ok(Outcome::Done)
            }
            "onNetEvent" => {
                ctx.arm_event_check()?;
                Ok(Outcome::Done)
            }
            "onProcessEvent" => {
                let mut events = js::array(g(c, "events"));
                if events.is_empty() {
                    events.push(g(c, "event").clone());
                }
                if events.iter().any(|event| js::string(js::or(g(g(event, "payload"), "id"), &json!(""))).starts_with("vpn_")) {
                    ctx.arm_event_check()?;
                }
                Ok(Outcome::Done)
            }
            "onHealthProbe" => {
                ctx.health_run(js::or(g(c, "payload"), &json!({})))?;
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                ctx.on_deactivate()?;
                Ok(Outcome::Done)
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(VpnCore, "vpn_core");

pub struct Ctx<'a> {
    host: &'a Host,
    kfuncs: bool,
    direct: bool,
    st: &'a mut VpnCore,
}

/// A WAN boundary: the veth pair (or the dummy of a direct handoff).
struct Boundary {
    local: Value,
    peer: Value,
    direct: bool,
}

type Leases = BTreeMap<String, Value>;

// ------------------------------------------------------------ helpers

#[cfg(test)]
thread_local! {
    /// Tests move the plugin's clock forward with this.
    pub(crate) static CLOCK_SHIFT: std::cell::Cell<f64> = const { std::cell::Cell::new(0.0) };
}

pub(crate) fn now() -> f64 {
    let base = js::now_ms() as f64;
    #[cfg(test)]
    return base + CLOCK_SHIFT.with(|shift| shift.get());
    #[cfg(not(test))]
    base
}

fn text<'v>(value: &'v Value, key: &str) -> &'v str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn eq(a: &Value, b: &Value) -> bool {
    js::strict_eq(a, b)
}

fn flag(value: &Value, key: &str) -> bool {
    js::is_true(g(value, key))
}

fn is_up(link: &Value) -> bool {
    js::array(g(link, "flags")).iter().any(|f| f.as_str() == Some("UP"))
}

fn kind(link: &Value) -> &str {
    text(g(link, "linkinfo"), "info_kind")
}

fn driver_of(p: &Value) -> &str {
    let driver = text(p, "driver");
    if driver.is_empty() {
        "wireguard"
    } else {
        driver
    }
}

fn is_wireguard(p: &Value) -> bool {
    driver_of(p) == "wireguard"
}

fn is_legacy(lease: &Value) -> bool {
    truthy(lease) && truthy(g(g(lease, "plan"), "bindings"))
}

fn token(value: &Value) -> Result<String> {
    let text = js::string(js::or(value, &json!("")));
    let bytes = text.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_');
    if !ok {
        bail!("Invalid identifier");
    }
    Ok(text)
}

fn profile_key(value: &Value) -> Result<String> {
    let key = token(js::or(value, &json!("default")))?;
    if key.len() > 11 {
        bail!("Profile key must be at most 11 characters");
    }
    Ok(key)
}

fn integer(value: &Value, min: f64, max: f64, fallback: Option<f64>) -> Result<f64> {
    let n = if value.is_null() { fallback.unwrap_or(f64::NAN) } else { js::number(value) };
    if !n.is_finite() || n.floor() != n || n < min || n > max {
        bail!("Integer outside allowed range");
    }
    Ok(n)
}

fn iface(value: &Value) -> Result<String> {
    let name = js::string(js::or(value, &json!("")));
    let bytes = name.as_bytes();
    let ok = !bytes.is_empty()
        && bytes.len() <= 15
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if !ok {
        bail!("Invalid LAN interface");
    }
    Ok(name)
}

fn wg_key(value: &Value) -> Result<String> {
    let key = js::string(js::or(value, &json!(""))).trim().to_string();
    let bytes = key.as_bytes();
    let shape = bytes.len() == 44
        && bytes[..42].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
        && b"AEIMQUYcgkosw048".contains(&bytes[42])
        && bytes[43] == b'=';
    if !shape || key == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
        return Err(fail("wg_key_invalid", "Invalid WireGuard key"));
    }
    Ok(key)
}

fn list(value: &Value, min: usize, max: usize) -> Result<Vec<Value>> {
    match value {
        Value::Array(items) if items.len() >= min && items.len() <= max => Ok(items.clone()),
        _ => bail!("List outside allowed size"),
    }
}

fn decimal_octet(part: &str) -> bool {
    // ^(0|[1-9][0-9]{0,2})$
    part == "0" || (!part.is_empty() && part.len() <= 3 && part.as_bytes()[0] != b'0' && part.bytes().all(|b| b.is_ascii_digit()))
}

fn address(value: &Value) -> Result<Vec<u8>> {
    let text = js::string(value);
    if !text.contains(':') {
        let parts: Vec<&str> = text.split('.').collect();
        if parts.len() != 4 {
            bail!("Invalid IPv4 address");
        }
        let mut bytes = Vec::with_capacity(4);
        for part in parts {
            let n: u32 = part.parse().unwrap_or(999);
            if !decimal_octet(part) || n > 255 {
                bail!("Invalid IPv4 address");
            }
            bytes.push(n as u8);
        }
        return Ok(bytes);
    }
    if !text.chars().all(|c| c.is_ascii_hexdigit() || c == ':') || text.contains(":::") {
        bail!("Invalid IPv6 address");
    }
    let parts: Vec<&str> = text.split("::").collect();
    if parts.len() > 2 {
        bail!("Invalid IPv6 address");
    }
    let left: Vec<&str> = if parts[0].is_empty() { Vec::new() } else { parts[0].split(':').collect() };
    let right: Vec<&str> = if parts.len() == 2 && !parts[1].is_empty() { parts[1].split(':').collect() } else { Vec::new() };
    let count = left.len() + right.len();
    if (parts.len() == 1 && count != 8) || (parts.len() == 2 && count >= 8) {
        bail!("Invalid IPv6 address");
    }
    let mut groups = left.clone();
    if parts.len() == 2 {
        groups.extend(std::iter::repeat("0").take(8 - count));
    }
    groups.extend(right);
    let mut bytes = Vec::with_capacity(16);
    for group in groups {
        if group.is_empty() || group.len() > 4 || !group.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("Invalid IPv6 address");
        }
        let n = u16::from_str_radix(group, 16).unwrap_or(0);
        bytes.push((n >> 8) as u8);
        bytes.push((n & 255) as u8);
    }
    Ok(bytes)
}

fn address_text(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        return bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".");
    }
    (0..16).step_by(2).map(|i| format!("{:x}", ((bytes[i] as u16) << 8) | bytes[i + 1] as u16)).collect::<Vec<_>>().join(":")
}

#[derive(Clone, Debug)]
pub struct Prefix {
    pub text: String,
    pub bytes: Vec<u8>,
    pub bits: u32,
    pub family: char,
}

fn prefix(value: &Value, preserve_host: bool) -> Result<Prefix> {
    let raw = js::string(js::or(value, &json!("")));
    let parts: Vec<&str> = raw.split('/').collect();
    if parts.len() > 2 {
        bail!("Invalid CIDR");
    }
    let bytes = address(&json!(parts[0]))?;
    if parts.len() == 2 && !decimal_octet(parts[1]) {
        bail!("Invalid CIDR length");
    }
    let width = (bytes.len() * 8) as f64;
    let bits = integer(&if parts.len() == 2 { json!(parts[1]) } else { json!(width) }, 0.0, width, None)? as u32;
    let network: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let remain = bits as i64 - i as i64 * 8;
            if remain >= 8 {
                *b
            } else if remain <= 0 {
                0
            } else {
                b & (255u8 << (8 - remain))
            }
        })
        .collect();
    let shown = if preserve_host { &bytes } else { &network };
    Ok(Prefix { text: format!("{}/{}", address_text(shown), bits), bytes: network, bits, family: if bytes.len() == 4 { '4' } else { '6' } })
}

fn covers(a: &Prefix, b: &Prefix) -> bool {
    if a.family != b.family || a.bits > b.bits {
        return false;
    }
    for i in 0..a.bytes.len() {
        let remain = a.bits as i64 - i as i64 * 8;
        let mask: u8 = if remain >= 8 {
            255
        } else if remain <= 0 {
            0
        } else {
            255u8 << (8 - remain)
        };
        if a.bytes[i] & mask != b.bytes[i] & mask {
            return false;
        }
    }
    true
}

fn u32hex(n: u64) -> String {
    (0..4).map(|i| format!("{:02x}", (n >> (i * 8)) & 255)).collect()
}

fn mac_hex(value: &Value) -> Result<String> {
    let s = value.as_str().unwrap_or("");
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 || !parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
        bail!("Invalid WAN boundary MAC");
    }
    Ok(s.replace(':', "").to_lowercase())
}

/// Replaces runs that look like keys (42+ base64 characters and padding).
fn redact_keys(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let key_char = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
        if key_char(chars[i]) {
            let start = i;
            while i < chars.len() && key_char(chars[i]) {
                i += 1;
            }
            if i - start >= 42 {
                while i < chars.len() && chars[i] == '=' {
                    i += 1;
                }
                out.push_str("[redacted]");
            } else {
                out.extend(&chars[start..i]);
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn error_fields(e: &Error) -> (String, String) {
    let text = e.to_string();
    if let Some(rest) = text.strip_prefix('[') {
        if let Some(close) = rest.find("] ") {
            let code = &rest[..close];
            if !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return (rest[close + 2..].to_string(), code.to_string());
            }
        }
    }
    (text, "unknown".to_string())
}

fn process_summary(proc: &Value) -> Value {
    // Only supervisor facts: core output can carry credentials and stays in core_logs.
    if !truthy(proc) {
        return Value::Null;
    }
    json!({"state": proc.get("state"), "pid": proc.get("pid"), "starts": proc.get("starts"), "exit_code": proc.get("exit_code"), "started_at": proc.get("started_at")})
}

fn assert_no_leftovers(p: &Value, links: &[Option<String>], wan_records: bool) -> Result<()> {
    // Without a lease these belong to an interrupted cleanup or to someone else.
    // Name them so the administrator can inspect or remove exactly these.
    let mut names: Vec<String> = links.iter().flatten().cloned().collect();
    if wan_records {
        names.push(format!("WAN {}", text(p, "wan_id")));
    }
    if !names.is_empty() {
        return Err(fail("ownership_missing", &format!("Recorded ownership is missing; leftover: {}", names.join(", "))));
    }
    Ok(())
}

/// Builds an object from (key, value) pairs, leaving out nulls the way
/// JSON.stringify leaves out undefined fields.
fn object(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        if !value.is_null() {
            map.insert(key.to_string(), value);
        }
    }
    Value::Object(map)
}

impl<'a> Ctx<'a> {
    // -------------------------------------------------------- host calls

    fn kv_list(&self, offset: usize) -> Result<Vec<Value>> {
        Ok(js::array(&self.host.call("kv.list", json!([{"limit": 32, "offset": offset}]))?))
    }

    fn secret_get(&self, name: &str) -> Result<Option<String>> {
        let value = self.host.call("secret.get", json!([name]))?;
        Ok(match value {
            Value::String(text) => Some(text),
            Value::Null => None,
            other => Some(js::string(&other)),
        })
    }

    fn secret_set(&self, name: &str, value: &str) -> Result<()> {
        self.host.call("secret.set", json!([name, value]))?;
        Ok(())
    }

    fn secret_delete(&self, name: &str) -> Result<()> {
        self.host.call("secret.delete", json!([name]))?;
        Ok(())
    }

    fn status_record(&self, key: &str) -> Result<Option<Value>> {
        self.host.resources_get("status", key)
    }

    fn set_status(&self, key: &str, data: &Value, enabled: bool) -> Result<()> {
        self.host.call("resources.set", json!(["status", key, data, enabled]))?;
        Ok(())
    }

    fn proc_status(&self, key: &str) -> Result<Value> {
        self.host.call("process.status", json!([format!("vpn_{key}")]))
    }

    fn execute(&self, program: &str, args: &[String], stdin: &str) -> Result<Value> {
        let request = json!({"command": program, "args": args, "stdin": stdin, "timeout_ms": 2000});
        let result = match self.host.call("process.exec", json!([request])) {
            Ok(result) => result,
            Err(err) => {
                let message = err.to_string().to_lowercase();
                if message.contains("no such file") || message.contains("not found") {
                    return Err(fail("tool_missing", &format!("Required tool is not installed: {program}")));
                }
                return Err(err);
            }
        };
        if flag(&result, "timed_out") || flag(&result, "cancelled") || flag(&result, "truncated") {
            return Err(fail("command_failed", &format!("Command did not complete: {program}")));
        }
        Ok(result)
    }

    fn command(&self, program: &str, args: &[&str], stdin: &str) -> Result<String> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let result = self.execute(program, &args, stdin)?;
        if js::number(g(&result, "exit_code")) == 0.0 {
            return Ok(js::string(js::or(g(&result, "stdout"), &json!(""))));
        }
        let message = format!("Command failed: {program} {} (exit {})", args[0], js::string(g(&result, "exit_code")));
        // wg/nft diagnostics can quote their input, including keys: never
        // expose their stderr. ip never receives a key; keep its first line,
        // minus anything shaped like one.
        let reason = if program == IP {
            let stderr = js::string(js::or(g(&result, "stderr"), &json!("")));
            let first = stderr.split('\n').next().unwrap_or("").to_string();
            let redacted = redact_keys(&first);
            redacted.chars().take(160).collect::<String>().trim().to_string()
        } else {
            String::new()
        };
        if program == IP && args.iter().any(|a| a == "wireguard") {
            let lower = reason.to_lowercase();
            if lower.contains("unknown device type") || lower.contains("not supported") {
                return Err(fail("wireguard_unavailable", &format!("{message}: {reason}")));
            }
        }
        Err(fail("command_failed", &if reason.is_empty() { message } else { format!("{message}: {reason}") }))
    }

    fn ip(&self, args: &[&str]) -> Result<String> {
        self.command(IP, args, "")
    }

    fn json_ip(&self, args: &[&str]) -> Result<Value> {
        let mut full = vec!["-j"];
        full.extend_from_slice(args);
        let out = self.ip(&full)?;
        let text = if out.is_empty() { "[]" } else { out.as_str() };
        serde_json::from_str(text).map_err(|err| Error::msg(err.to_string()))
    }

    // -------------------------------------------------------- leases

    pub fn all_leases(&self) -> Result<Leases> {
        let mut out = Leases::new();
        let mut offset = 0;
        while offset < 1024 {
            let page = self.kv_list(offset)?;
            for record in &page {
                let key = js::string(g(record, "key"));
                let Some(name) = key.strip_prefix("lease_") else {
                    continue;
                };
                let mut lease = record.get("data").cloned().unwrap_or(Value::Null);
                // Leases written before 0.9.1 call the tunnel ifindex wg_ifindex; the next write drops it.
                if let Some(map) = lease.as_object_mut() {
                    if let Some(old) = map.remove("wg_ifindex") {
                        if old.is_null() {
                            // A null wg_ifindex was never a tunnel ifindex.
                        } else if map.get("tunnel_ifindex").map(Value::is_null).unwrap_or(true) {
                            map.insert("tunnel_ifindex".into(), old);
                        }
                    }
                }
                out.insert(name.to_string(), lease);
            }
            if page.len() < 32 {
                break;
            }
            offset += 32;
        }
        Ok(out)
    }

    fn set_lease(&self, key: &str, lease: &Value) -> Result<()> {
        self.host.kv_set(&format!("lease_{key}"), lease)
    }

    // -------------------------------------------------------- handlers

    fn on_action(&mut self, c: &Value) -> Result<Value> {
        let payload = js::or(g(c, "payload"), &json!({})).clone();
        let key = profile_key(g(&payload, "key"))?;
        let id = js::string(g(g(c, "action"), "id"));
        match id.as_str() {
            "health_status" => return self.health_all(),
            "health_settings" | "health_check" => {
                if self.host.resources_get("profiles", &key)?.is_none() {
                    return Err(fail("profile_not_saved", "请先保存出口配置"));
                }
                return if id == "health_settings" { self.health_configure(&key, g(&payload, "settings")) } else { self.health_start(&key) };
            }
            "core_status" | "core_install" | "core_select" | "core_rollback" | "core_remove" => {
                let driver = drivers::driver(g(&payload, "driver"))?;
                return match id.as_str() {
                    "core_status" => self.host.call("process.binaryStatus", json!([driver])),
                    "core_install" => {
                        let host = self.host.call("plugin.host", json!([]))?;
                        self.host.call("process.binaryInstall", json!([drivers::install(&payload, &host)?]))
                    }
                    "core_remove" => {
                        let version = js::string(js::or(g(&payload, "version"), &json!("")));
                        self.host.call("process.binaryRemove", json!([{"id": driver, "version": version}]))
                    }
                    _ => {
                        let version = if id == "core_rollback" {
                            js::string(js::or(g(&self.host.call("process.binaryStatus", json!([driver]))?, "previous"), &json!("")))
                        } else {
                            js::string(js::or(g(&payload, "version"), &json!("")))
                        };
                        if version.is_empty() {
                            bail!("No previous installed core version");
                        }
                        self.host.call("process.binarySelect", json!([{"id": driver, "version": version}]))
                    }
                };
            }
            "set_key" => {
                let value = wg_key(g(&payload, "value"))?;
                let name = if truthy(g(&payload, "name")) { token(g(&payload, "name"))? } else { format!("private_{key}") };
                let public_key =
                    if name == format!("private_{key}") { self.command(WG, &["pubkey"], &format!("{value}\n"))?.trim().to_string() } else { String::new() };
                self.secret_set(&name, &value)?;
                return Ok(json!({"stored": true, "name": name, "public_key": public_key}));
            }
            "set_core_config" => return self.set_core_config(&key, &payload),
            "core_form" => {
                let Some(record) = self.host.resources_get("profiles", &key)? else {
                    return Ok(json!({"mode": "empty"}));
                };
                let driver = text(g(&record, "data"), "driver").to_string();
                if driver != "mihomo" && driver != "sing_box" {
                    return Ok(json!({"mode": "empty"}));
                }
                let name = js::string(js::or(g(g(&record, "data"), "config_secret"), &json!(format!("core_{key}"))));
                let Some(saved) = self.secret_get(&name)?.filter(|s| !s.is_empty()) else {
                    return Ok(json!({"mode": "empty"}));
                };
                let parsed: Value = serde_json::from_str(&saved).map_err(|err| Error::msg(err.to_string()))?;
                let form = share::metadata(&parsed)?;
                if truthy(g(&form, "driver")) && text(&form, "driver") != driver {
                    return Err(fail("core_config_invalid", "Saved node configuration belongs to another core"));
                }
                return Ok(form);
            }
            "inspect" => return self.inspect(&key),
            "upstream_interfaces" => return Ok(json!({"items": self.upstream_interfaces()?})),
            "core_logs" => {
                let leases = self.all_leases()?;
                let driver = leases.get(&key).filter(|lease| truthy(lease)).map(|lease| text(g(lease, "plan"), "driver").to_string()).unwrap_or_default();
                if driver != "mihomo" && driver != "sing_box" {
                    bail!("No managed proxy core for this profile");
                }
                let logs = self.host.call("process.logs", json!([format!("vpn_{key}")]))?;
                // runtime_query has a 64 KiB JSON response bound, including escaping.
                let stdout = js::string(js::or(g(&logs, "stdout"), &json!("")));
                let stderr = js::string(js::or(g(&logs, "stderr"), &json!("")));
                let tail = |s: &str| {
                    let units: Vec<u16> = s.encode_utf16().collect();
                    let start = units.len().saturating_sub(4000);
                    String::from_utf16_lossy(&units[start..])
                };
                let truncated = flag(&logs, "truncated") || stdout.encode_utf16().count() > 4000 || stderr.encode_utf16().count() > 4000;
                return Ok(json!({"stdout": tail(&stdout), "stderr": tail(&stderr), "truncated": truncated}));
            }
            "teardown" => {
                self.assert_no_dependents(&key)?;
                self.teardown(&key)?;
                return Ok(json!({"phase": "down"}));
            }
            "delete_profile" => {
                self.assert_no_dependents(&key)?;
                return self.delete_profile(&key);
            }
            "apply" => {
                let record = self.host.resources_get("profiles", &key)?;
                let Some(record) = record.filter(|r| !js::is_false(g(r, "enabled"))) else {
                    return Err(fail("profile_not_saved", "Save and enable the profile first"));
                };
                let revision = g(&record, "revision").clone();
                return self.apply(&key, g(&record, "data"), true, &revision);
            }
            _ => bail!("Unsupported action"),
        }
    }

    fn set_core_config(&mut self, key: &str, payload: &Value) -> Result<Value> {
        let name = if truthy(g(payload, "name")) { token(g(payload, "name"))? } else { format!("core_{key}") };
        let format = g(payload, "format");
        if is_str(format, "links") {
            let driver = text(payload, "driver").to_string();
            let mut source = js::string(js::or(g(payload, "value"), &json!(""))).trim().to_string();
            if source.is_empty() {
                // A missing Secret parses as null, an unreadable one fails.
                let previous = match self.secret_get(&name)? {
                    None => Value::Null,
                    Some(text) => serde_json::from_str::<Value>(&text).map_err(|_| fail("links_required", "请先导入分享链接"))?,
                };
                if !truthy(&previous) || !eq(g(&previous, "veer_proxy"), &json!(1)) || !eq(g(&previous, "driver"), g(payload, "driver")) {
                    return Err(fail("links_required", "请为当前核心重新导入分享链接"));
                }
                source = js::string(g(&previous, "links"));
            }
            let imported = share::create(&driver, &json!(source), g(payload, "selected"), g(payload, "options"), g(payload, "via"))?;
            // Validate both parsing and generation before replacing any saved Secret.
            share::generate(&imported)?;
            self.secret_set(&name, &imported.to_string())?;
            return Ok(json!({"stored": true, "form": share::metadata(&imported)?}));
        }
        if truthy(format) && !is_str(format, "native") {
            return Err(fail("core_config_invalid", "Unsupported core configuration format"));
        }
        let config = js::string(js::or(g(payload, "value"), &json!("")));
        let parsed = serde_json::from_str::<Value>(&config).ok().filter(Value::is_object);
        let Some(parsed) = parsed else {
            return Err(fail("core_config_invalid", "Core configuration must be a JSON object"));
        };
        if !g(&parsed, "veer_proxy").is_null() {
            return Err(fail("core_config_invalid", "Use the sharing-link import format for managed node configurations"));
        }
        if config.len() > 768 * 1024 {
            return Err(fail("core_config_invalid", "Core configuration exceeds 768 KiB"));
        }
        self.secret_set(&name, &config)?;
        Ok(json!({"stored": true}))
    }

    fn on_reconcile(&mut self) -> Result<()> {
        if self.st.changing {
            return Ok(());
        }
        let mut errors = Vec::new();
        let mut failed = Vec::new();
        let leases = self.all_leases()?;
        for key in chain_order(&leases) {
            let lease = &leases[&key];
            let record = self.host.resources_get("profiles", &key)?;
            if !flag(lease, "active") {
                continue;
            }
            if record.as_ref().map(|r| js::is_false(g(r, "enabled"))).unwrap_or(true) {
                self.teardown(&key)?;
                continue;
            }
            if let Err(err) = self.apply(&key, g(lease, "settings"), false, &Value::Null) {
                errors.push(format!("{key}: {err}"));
                failed.push(key.clone());
                let status = self.error_status(&key, g(lease, "plan"), &err, Value::Null)?;
                self.set_status(&key, &status, true)?;
            }
        }
        self.arm_repair()?;
        if !errors.is_empty() {
            self.arm_retry(&failed)?;
            bail!("{}", errors.join("; "));
        }
        Ok(())
    }

    fn on_timer(&mut self, name: &str) -> Result<()> {
        if name == "vpn_health" {
            return self.health_tick();
        }
        if name == MAP_TIMER {
            return self.check_maps();
        }
        // Stop timers this version no longer arms, such as wg_repair from 0.9.0.
        if name != REPAIR_TIMER && name != EVENT_TIMER && name != RETRY_TIMER {
            if !name.is_empty() {
                self.host.timer_clear(name)?;
            }
            return Ok(());
        }
        let mut failed = Vec::new();
        let leases = self.all_leases()?;
        for key in chain_order(&leases) {
            let lease = leases[&key].clone();
            if !flag(&lease, "active") || is_legacy(&lease) {
                continue;
            }
            let p = g(&lease, "plan").clone();
            if !is_wireguard(&p) {
                if !self.repair_tun(&key, &lease)? {
                    failed.push(key.clone());
                }
                continue;
            }
            let outcome = (|| -> Result<()> {
                let wg = self.owned_link(&p, Some(&lease))?;
                let tunnel_ok = !flag(&lease, "pending")
                    && wg.as_ref().map(|wg| is_up(wg) && eq(g(wg, "mtu"), g(&p, "mtu")) && eq(g(wg, "ifindex"), g(&lease, "tunnel_ifindex"))).unwrap_or(false);
                let boundary = if tunnel_ok { self.boundary_links(&p, false)? } else { None };
                match (&wg, &boundary) {
                    (Some(wg), Some(b)) if tunnel_ok && eq(g(&b.local, "ifindex"), g(&lease, "local_ifindex")) && eq(g(&b.peer, "ifindex"), g(&lease, "pipeline_ifindex")) => {
                        self.repair_maps(&p, wg, b)?;
                    }
                    _ => {
                        self.clear_maps(&lease)?;
                        self.apply(&key, g(&lease, "settings"), false, &Value::Null)?;
                    }
                }
                Ok(())
            })();
            if let Err(err) = outcome {
                failed.push(key.clone());
                self.st.expected_maps.remove(&key);
                if let Err(cleanup) = self.clear_maps(&lease) {
                    self.host.error(&format!("Tunnel map cleanup failed: {cleanup}"));
                }
                let status = self.error_status(&key, &p, &err, Value::Null)?;
                self.set_status(&key, &status, true)?;
            }
        }
        self.arm_retry(&failed)
    }

    /// The check after a link or process event is armed once: later events
    /// of a burst, or a flapping interface elsewhere, cannot keep postponing it.
    fn arm_event_check(&mut self) -> Result<()> {
        if self.host.timer_pending(EVENT_TIMER)? {
            return Ok(());
        }
        self.host.timer_set_timeout(EVENT_TIMER, EVENT_REPAIR_DELAY_MS, &json!({}))
    }

    /// Puts back an exit's adapter entries when they differ from what was
    /// last written, as long as its lease still holds the same tunnel and
    /// boundary.
    fn check_maps(&mut self) -> Result<()> {
        let keys: Vec<String> = self.st.expected_maps.keys().cloned().collect();
        for key in keys {
            let want = &self.st.expected_maps[&key];
            // Hash-map reads may throw for absent keys.
            let intact = want.entries.iter().all(|entry| {
                self.host.call("ebpf.mapGet", json!([OBJECT, MAP, entry["key"]])).map(|value| eq(&value, &entry["value"])).unwrap_or(false)
            });
            if intact {
                continue;
            }
            let lease = self.host.kv_get(&format!("lease_{key}"))?.and_then(|record| record.get("data").cloned()).unwrap_or(Value::Null);
            let want = &self.st.expected_maps[&key];
            if !truthy(&lease)
                || !flag(&lease, "active")
                || flag(&lease, "pending")
                || !eq(g(&lease, "tunnel_ifindex"), &want.tunnel)
                || !eq(g(&lease, "pipeline_ifindex"), &want.pipeline)
            {
                self.st.expected_maps.remove(&key);
                continue;
            }
            if let Err(err) = self.host.call("ebpf.mapTransaction", json!([{"operations": want.entries}])) {
                self.host.error(&format!("Tunnel map repair failed: {err}"));
            }
        }
        Ok(())
    }

    /// An exit still negotiating its TUN offloads is checked again soon; a
    /// failed repair waits longer each time, since no event may follow it.
    /// Each exit backs off on its own.
    fn arm_retry(&mut self, failed: &[String]) -> Result<()> {
        let leases = self.all_leases()?;
        let pending = leases.values().any(|lease| flag(lease, "active") && flag(lease, "pending"));
        let mut next = BTreeMap::new();
        let mut delay = if pending { PENDING_RETRY_MS } else { 0 };
        for key in failed {
            let value = match self.st.retry_delays.get(key) {
                Some(previous) if *previous > 0 => (previous * 2).min(RETRY_MAX_MS),
                _ => RETRY_MIN_MS,
            };
            next.insert(key.clone(), value);
            delay = if delay > 0 { delay.min(value) } else { value };
        }
        self.st.retry_delays = next;
        if delay > 0 {
            self.host.timer_set_timeout(RETRY_TIMER, delay, &json!({}))
        } else {
            self.host.timer_clear(RETRY_TIMER)
        }
    }

    fn on_deactivate(&mut self) -> Result<()> {
        self.health_stop()?;
        for name in [REPAIR_TIMER, EVENT_TIMER, RETRY_TIMER, MAP_TIMER] {
            self.host.timer_clear(name)?;
        }
        self.st.expected_maps.clear();
        let mut failures = Vec::new();
        // Chained exits first, so no core keeps dialing through a removed front.
        let leases = self.all_leases()?;
        for key in chain_order(&leases).into_iter().rev() {
            if let Err(err) = self.teardown(&key) {
                failures.push(format!("{key}: {err}"));
            }
        }
        if !failures.is_empty() {
            bail!("VPN cleanup incomplete: {}", failures.join("; "));
        }
        Ok(())
    }

    fn arm_repair(&mut self) -> Result<()> {
        self.health_arm()?;
        let leases = self.all_leases()?;
        self.st.expected_maps.retain(|k, _| leases.get(k).map(|lease| flag(lease, "active")).unwrap_or(false));
        if leases.values().any(|lease| flag(lease, "active")) {
            self.host.timer_set_interval(REPAIR_TIMER, SAFETY_REPAIR_MS, &json!({}))?;
            self.host.timer_set_interval(MAP_TIMER, MAP_CHECK_MS, &json!({}))?;
            // Whatever was just applied gets one check soon: a TUN that is
            // still negotiating or an apply that failed is then retried from there.
            if leases.values().any(|lease| flag(lease, "active") && flag(lease, "pending")) {
                self.host.timer_set_timeout(RETRY_TIMER, PENDING_RETRY_MS, &json!({}))?;
            }
        } else {
            for name in [REPAIR_TIMER, EVENT_TIMER, RETRY_TIMER, MAP_TIMER] {
                self.host.timer_clear(name)?;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------- chains

    fn assert_no_dependents(&self, key: &str) -> Result<()> {
        let leases = self.all_leases()?;
        let users = dependents(key, &leases);
        if !users.is_empty() {
            return Err(fail(
                "upstream_in_use",
                &format!("Exit {key} is the upstream of {}; teardown those exits or change their upstream first", users.join(", ")),
            ));
        }
        Ok(())
    }

    /// Structural checks of an upstream that is another exit: never a tunnel
    /// or pipeline, no loop, at most MAX_CHAIN exits in front. Returns the
    /// front exit.
    fn upstream_chain(&self, p: &Value) -> Result<Option<(String, Value)>> {
        let leases = self.all_leases()?;
        let upstream = text(p, "upstream_interface");
        for (k, lease) in &leases {
            let other = g(lease, "plan");
            if k != text(p, "key") && truthy(other) && (text(other, "interface") == upstream || text(other, "pipeline") == upstream) {
                return Err(fail(
                    "upstream_invalid",
                    &format!("A VPN tunnel or pipeline cannot be the upstream; select the WAN boundary {} of exit {k}", text(other, "local")),
                ));
            }
        }
        let Some(front) = exit_by_boundary(upstream, &leases) else {
            if is_vpn_boundary_name(upstream) {
                return Err(fail("upstream_exit_down", &format!("Upstream VPN exit boundary {upstream} is not applied; apply that exit first")));
            }
            return Ok(None);
        };
        let mut cur = Some(front.clone());
        let mut depth = 1;
        while let Some((key, lease)) = cur {
            if key == text(p, "key") {
                return Err(fail("upstream_cycle", &format!("Upstream exits would form a loop through {}", text(p, "key"))));
            }
            if depth > MAX_CHAIN {
                return Err(fail("upstream_chain_too_long", &format!("At most {MAX_CHAIN} VPN exits can be chained in front of a proxy exit")));
            }
            let next = text(g(&lease, "plan"), "upstream_interface");
            cur = if next.is_empty() { None } else { exit_by_boundary(next, &leases) };
            depth += 1;
        }
        Ok(Some(front))
    }

    /// Before (re)starting a chained core: the front must be published, and
    /// its boundary must accept replies addressed to the core's own sockets.
    fn upstream_ready(&self, front: &(String, Value), p: &Value) -> Result<Value> {
        let status = self.status_record(&front.0)?;
        let boundary = self.link(text(p, "upstream_interface"))?;
        let applied = status.as_ref().map(|s| text(g(s, "data"), "phase") == "applied").unwrap_or(false);
        if flag(&front.1, "pending") || !applied || boundary.is_none() {
            return Err(fail("upstream_exit_down", &format!("Upstream VPN exit {} is not ready", front.0)));
        }
        self.loosen_reverse_path(text(p, "upstream_interface"))?;
        Ok(boundary.unwrap())
    }

    /// Replies to a chained core arrive on the front boundary, while the
    /// host's best route back to the node uses the physical uplink. Strict
    /// reverse-path filtering (rp_filter 1) drops them. The kernel uses
    /// max(all, interface), so loose mode on this plugin-owned boundary
    /// alone is enough.
    fn loosen_reverse_path(&self, name: &str) -> Result<()> {
        let outcome = (|| -> Result<()> {
            let value = |key: &str| -> Result<f64> { Ok(self.command(SYSCTL, &["-n", key], "")?.trim().parse::<f64>().unwrap_or(f64::NAN)) };
            let own = format!("net.ipv4.conf.{name}.rp_filter");
            let all = value("net.ipv4.conf.all.rp_filter")?;
            let mine = value(&own)?;
            if all.max(mine) != 1.0 {
                return Ok(());
            }
            self.command(SYSCTL, &["-q", "-w", &format!("{own}=2")], "")?;
            Ok(())
        })();
        outcome.map_err(|err| {
            fail("upstream_rp_filter", &format!("Strict reverse-path filtering on {name} drops replies to the chained core and could not be relaxed: {err}"))
        })
    }

    // -------------------------------------------------------- profiles

    fn normalize(&self, key: &str, raw: &Value) -> Result<Value> {
        let raw = if truthy(raw) { raw.clone() } else { json!({}) };
        if truthy(g(&raw, "upstream_ip")) && !is_str(g(&raw, "driver"), "sing_box") {
            return Err(fail("upstream_ip_singbox_only", "出站 IP 仅支持 sing-box"));
        }
        if truthy(g(&raw, "driver")) && !is_str(g(&raw, "driver"), "wireguard") {
            return self.normalize_tun(key, &raw);
        }
        if truthy(g(&raw, "bindings")) || !g(&raw, "masquerade").is_null() || truthy(g(&raw, "bypass_cidrs")) {
            bail!("Legacy routing profile: teardown the old profile, then configure a WAN and select it in Egress NAT");
        }
        let slot = integer(g(&raw, "slot"), 1.0, 8.0, Some(1.0))?;
        let mtu = integer(g(&raw, "mtu"), 1280.0, 9000.0, Some(1420.0))?;
        let listen_port = integer(g(&raw, "listen_port"), 0.0, 65535.0, Some(0.0))?;
        let mut addresses = Vec::new();
        for value in list(g(&raw, "addresses"), 1, 8)? {
            addresses.push(prefix(&value, true)?.text);
        }
        let mut has_v4 = false;
        for value in &addresses {
            if prefix(&json!(value), false)?.family == '4' {
                has_v4 = true;
            }
        }
        if !has_v4 {
            return Err(fail("wg_address_required", "A local IPv4 tunnel address is required for Veer Egress NAT"));
        }
        let mut peers = Vec::new();
        for peer in list(g(&raw, "peers"), 1, 8)? {
            let endpoint = js::string(js::or(g(&peer, "endpoint"), &json!("")));
            if !endpoint.is_empty() {
                let (host, port) = split_endpoint(&endpoint).ok_or_else(|| fail("endpoint_invalid", "Endpoint must be a numeric IP:port (bracket IPv6)"))?;
                address(&json!(host.replace(['[', ']'], "")))?;
                integer(&json!(port), 1.0, 65535.0, None)?;
            }
            let public_key = wg_key(g(&peer, "public_key"))?;
            let mut allowed = Vec::new();
            for value in list(g(&peer, "allowed_ips"), 1, 32)? {
                allowed.push(prefix(&value, false)?.text);
            }
            let keepalive = integer(g(&peer, "keepalive"), 0.0, 65535.0, Some(25.0))? as i64;
            let preshared = if truthy(g(&peer, "preshared_key_secret")) { token(g(&peer, "preshared_key_secret"))? } else { String::new() };
            peers.push(json!({"public_key": public_key, "endpoint": endpoint, "allowed_ips": allowed,
                "keepalive": keepalive, "preshared_key_secret": preshared}));
        }
        let mut seen_peers = Vec::new();
        let mut seen_prefixes = Vec::new();
        for peer in &peers {
            let public_key = text(peer, "public_key").to_string();
            if seen_peers.contains(&public_key) {
                return Err(fail("peer_invalid", "Duplicate peer public key"));
            }
            seen_peers.push(public_key);
            for v in js::array(&peer["allowed_ips"]) {
                let v = js::string(&v);
                if seen_prefixes.contains(&v) {
                    return Err(fail("peer_invalid", "AllowedIPs must not be duplicated across peers"));
                }
                seen_prefixes.push(v);
            }
            let endpoint = text(peer, "endpoint");
            if !endpoint.is_empty() {
                let endpoint_ip = endpoint_host(endpoint);
                let target = prefix(&json!(endpoint_ip), false)?;
                for v in &addresses {
                    if covers(&prefix(&json!(v), false)?, &target) {
                        return Err(fail("route_invalid", "Tunnel address route would capture a WireGuard endpoint"));
                    }
                }
            }
        }
        let mut remote_routes = Vec::new();
        for v in list(js::or(g(&raw, "remote_routes"), &json!([])), 0, 32)? {
            let cidr = prefix(&v, false)?;
            if cidr.bits == 0 {
                return Err(fail("route_invalid", "remote_routes cannot replace the host default route; select the WAN in Egress NAT instead"));
            }
            let mut covered = false;
            for peer in &peers {
                for a in js::array(&peer["allowed_ips"]) {
                    if covers(&prefix(&a, false)?, &cidr) {
                        covered = true;
                    }
                }
            }
            if !covered {
                return Err(fail("route_invalid", "Route is not covered by peer AllowedIPs"));
            }
            for peer in &peers {
                let endpoint = text(peer, "endpoint");
                if endpoint.is_empty() {
                    continue;
                }
                if covers(&cidr, &prefix(&json!(endpoint_host(endpoint)), false)?) {
                    return Err(fail("route_invalid", "Remote route would capture a WireGuard endpoint"));
                }
            }
            remote_routes.push(cidr.text);
        }
        let slot = slot as i64;
        Ok(json!({"driver": "wireguard", "key": key, "slot": slot, "interface": format!("vwg{key}"), "mtu": mtu as i64,
            "listen_port": listen_port as i64, "owner": format!("veer:vpn_core:{key}"), "wan_id": format!("wg_{key}"),
            "local": format!("veerwg{slot}"), "pipeline": format!("veerwgp{slot}"),
            "handoff_mode": if self.direct { "direct" } else { "segmented_veth" },
            "addresses": addresses, "peers": peers, "remote_routes": remote_routes}))
    }

    /// TUN drivers share the same WAN and TC adapter as kernel WireGuard.
    fn normalize_tun(&self, key: &str, raw: &Value) -> Result<Value> {
        let driver = js::string(g(raw, "driver"));
        if !["mihomo", "sing_box", "tun"].contains(&driver.as_str()) {
            bail!("Unsupported VPN driver");
        }
        if truthy(g(raw, "upstream_ip")) && driver != "sing_box" {
            return Err(fail("upstream_ip_singbox_only", "出站 IP 仅支持 sing-box"));
        }
        let slot = integer(g(raw, "slot"), 1.0, 8.0, Some(1.0))? as i64;
        let mtu = integer(g(raw, "mtu"), 1280.0, 9000.0, Some(1420.0))? as i64;
        let external = driver == "tun";
        let interface = if external { iface(g(raw, "tun_interface"))? } else { format!("vtun{key}") };
        if external && !truthy(g(raw, "tun_interface")) {
            return Err(fail("tun_config_invalid", "An external TUN interface is required"));
        }
        let owner = if external { js::string(js::or(g(raw, "tun_alias"), &json!(""))) } else { format!("veer:vpn_core:{key}") };
        if owner.is_empty() || crate::share::utf16_len(&owner) > 128 || owner.contains(['\r', '\n', '\0']) {
            return Err(fail("tun_config_invalid", "An external TUN requires an explicit tun_alias ownership marker"));
        }
        let local = format!("veervpn{slot}");
        let pipeline = format!("veervpnp{slot}");
        if interface == local || interface == pipeline {
            return Err(fail("tun_config_invalid", "TUN and WAN boundaries must differ"));
        }
        let mut addresses = Vec::new();
        for v in list(js::or(g(raw, "addresses"), &json!([])), 0, 8)? {
            let c = prefix(&v, true)?;
            if c.bits != if c.family == '4' { 32 } else { 128 } {
                return Err(fail("wan_address_invalid", "Proxy WAN addresses must be /32 or /128 to avoid changing host routes"));
            }
            addresses.push(c.text);
        }
        if !addresses.is_empty() {
            let mut v4 = false;
            for v in &addresses {
                if prefix(&json!(v), false)?.family == '4' {
                    v4 = true;
                }
            }
            if !v4 {
                return Err(fail("wan_address_invalid", "A local IPv4 WAN address is required"));
            }
        }
        if js::array(g(raw, "remote_routes")).len() > 0 {
            return Err(fail("route_invalid", "Select this WAN in Veer instead of installing host routes"));
        }
        let upstream = if external { String::new() } else { iface(g(raw, "upstream_interface"))? };
        if !external && (!truthy(g(raw, "upstream_interface")) || [&interface, &local, &pipeline].contains(&&upstream)) {
            return Err(fail("upstream_invalid", "Select a separate physical or PPPoE upstream_interface"));
        }
        let mut upstream_ip = js::string(js::or(g(raw, "upstream_ip"), &json!(""))).trim().to_string();
        if !upstream_ip.is_empty() {
            // Bind an address already owned by the selected uplink; never create
            // an address, route or NAT rule to make a source binding appear to work.
            upstream_ip = address_text(&address(&json!(upstream_ip))?);
            let link = self.host.call("net.link.get", json!([upstream]))?;
            let mut owned = false;
            for value in js::array(g(&link, "addresses")) {
                let text = js::string(&value);
                if address(&json!(text.split('/').next().unwrap_or(""))).map(|bytes| address_text(&bytes) == upstream_ip).unwrap_or(false) {
                    owned = true;
                    break;
                }
                // A malformed address in the list throws in the script too.
                address(&json!(text.split('/').next().unwrap_or("")))?;
            }
            if !owned {
                return Err(fail("upstream_ip_not_owned", "出站 IP 不属于所选出站接口"));
            }
        }
        let managed = if !external && !truthy(g(raw, "core_path")) { self.host.call("process.binaryStatus", json!([driver]))? } else { Value::Null };
        let core_path = if external {
            String::new()
        } else {
            let path = js::or(g(raw, "core_path"), if truthy(&managed) { g(&managed, "path") } else { &Value::Null }).clone();
            drivers::command(&driver, &path)?
        };
        let config_secret = if truthy(g(raw, "config_secret")) { token(g(raw, "config_secret"))? } else { format!("core_{key}") };
        let max_restarts = integer(g(raw, "max_restarts"), 0.0, 10.0, Some(3.0))? as i64;
        let startup_timeout = integer(g(raw, "startup_timeout_seconds"), 1.0, 300.0, Some(30.0))? as i64;
        let mut settings = json!({"driver": driver, "slot": slot, "mtu": mtu, "addresses": addresses, "upstream_interface": upstream,
            "core_path": core_path, "config_secret": config_secret, "max_restarts": max_restarts, "startup_timeout_seconds": startup_timeout});
        if !upstream_ip.is_empty() {
            settings["upstream_ip"] = json!(upstream_ip);
        }
        if external {
            settings["tun_interface"] = json!(interface);
            settings["tun_alias"] = json!(owner);
        }
        Ok(json!({"key": key, "driver": driver, "slot": slot, "mtu": mtu, "interface": interface, "owner": owner,
            "wan_id": format!("vpn_{key}"), "local": local, "pipeline": pipeline,
            "handoff_mode": if self.direct { "direct" } else { "segmented_veth" },
            "addresses": addresses, "remote_routes": [], "upstream_interface": upstream, "upstream_ip": upstream_ip,
            "core_path": core_path, "config_secret": config_secret, "max_restarts": max_restarts,
            "startup_timeout_seconds": startup_timeout, "settings": settings}))
    }

    // -------------------------------------------------------- links

    fn link(&self, name: &str) -> Result<Option<Value>> {
        // Prefer a bounded native lookup. Older hosts lack alias/TUN details,
        // so retain their exec path rather than weakening the ownership checks.
        match self.host.call("net.link.get", json!([name])) {
            Ok(info) => {
                if g(&info, "alias").is_string() && (text(&info, "kind") != "tuntap" || truthy(g(&info, "tun_mode"))) {
                    let info_kind = js::or(g(&info, "tun_mode"), g(&info, "kind")).clone();
                    return Ok(Some(object(vec![
                        ("ifname", info["name"].clone()),
                        ("ifindex", info.get("ifindex").cloned().unwrap_or(Value::Null)),
                        ("ifalias", info["alias"].clone()),
                        ("linkinfo", json!({"info_kind": info_kind})),
                        ("mtu", info.get("mtu").cloned().unwrap_or(Value::Null)),
                        ("address", info.get("mac").cloned().unwrap_or(Value::Null)),
                        ("flags", if flag(&info, "up") { json!(["UP"]) } else { json!([]) }),
                        ("link_index", info.get("peer_ifindex").cloned().unwrap_or(Value::Null)),
                        ("link", info.get("peer_name").cloned().unwrap_or(Value::Null)),
                        ("tun_vnet_hdr", json!(flag(&info, "tun_vnet_hdr"))),
                    ])));
                }
            }
            Err(err) => {
                if err.to_string().contains("link not found:") {
                    return Ok(None);
                }
                return Err(err);
            }
        }
        // Query only this device; dumping a PVE host's whole interface
        // inventory on every health check can exceed the exec output bound.
        let args: Vec<String> = ["-j", "-d", "link", "show", "dev", name].iter().map(|s| s.to_string()).collect();
        let result = self.execute(IP, &args, "")?;
        if js::number(g(&result, "exit_code")) != 0.0 {
            let stderr = js::string(js::or(g(&result, "stderr"), &json!("")));
            if stderr.contains("does not exist") || stderr.contains("Cannot find device") {
                return Ok(None);
            }
            bail!("Cannot inspect VPN interface");
        }
        let stdout = js::string(js::or(g(&result, "stdout"), &json!("")));
        let parsed: Value = serde_json::from_str(if stdout.is_empty() { "[]" } else { &stdout }).map_err(|err| Error::msg(err.to_string()))?;
        Ok(js::array(&parsed).into_iter().find(|l| text(l, "ifname") == name))
    }

    fn owned_link(&self, p: &Value, lease: Option<&Value>) -> Result<Option<Value>> {
        let current = self.link(text(p, "interface"))?;
        let looked_up;
        let lease = match lease {
            Some(lease) => lease.clone(),
            None => {
                looked_up = self.all_leases()?.get(text(p, "key")).cloned().unwrap_or(Value::Null);
                looked_up
            }
        };
        let Some(link) = current else {
            return Ok(None);
        };
        let created = truthy(&lease) && flag(&lease, "pending") && eq(g(&lease, "created_ifindex"), g(&link, "ifindex")) && !truthy(g(&link, "ifalias"));
        let want = if is_wireguard(p) { "wireguard" } else { "tun" };
        if (!eq(g(&link, "ifalias"), g(p, "owner")) && !created) || !truthy(g(&link, "linkinfo")) || kind(&link) != want {
            return Err(fail("unowned_interface", "Refusing to modify an existing unowned VPN interface"));
        }
        Ok(Some(link))
    }

    fn wan_record(&self, resource: &str, p: &Value) -> Result<Option<Value>> {
        let value = self.host.call("plugins.resources.get", json!(["wan_core", resource, p["wan_id"]]))?;
        Ok(if truthy(&value) { Some(value) } else { None })
    }

    fn clean_wan_state(&self, p: &Value) -> Result<bool> {
        let (Some(status), Some(session)) = (self.wan_record("status", p)?, self.wan_record("sessions", p)?) else {
            return Ok(false);
        };
        if !js::is_false(g(&status, "enabled")) || !js::is_false(g(&session, "enabled")) {
            return Ok(false);
        }
        let data = js::or(g(&status, "data"), &json!({})).clone();
        let owner = js::or(g(&session, "data"), &json!({})).clone();
        if text(&owner, "driver_plugin") != "vpn_core"
            || !eq(g(&owner, "profile_key"), g(p, "key"))
            || !eq(g(&owner, "wan_id"), g(p, "wan_id"))
            || !eq(g(&owner, "real_interface"), g(p, "interface"))
            || !eq(g(&data, "local_interface"), g(p, "local"))
            || !known_wan_pipeline(p, g(&data, "pipeline_interface"))
            || !js::array(g(&data, "cleanup_errors")).is_empty()
        {
            return Ok(false);
        }
        if text(&data, "phase") == "deleted" {
            return Ok(true);
        }
        // Older WAN Core versions replaced the teardown journal with "disabled"
        // during restart. Accept only its fully withdrawn, matching owner
        // state; the caller separately requires every managed interface to be absent.
        Ok(text(&data, "phase") == "disabled"
            && text(&data, "driver_plugin") == "vpn_core"
            && eq(g(&data, "profile_key"), g(p, "key"))
            && js::is_false(g(&data, "managed_link"))
            && !js::is_true(g(&data, "arp_disabled_by_plugin"))
            && !js::is_true(g(&data, "noarp_ready")))
    }

    fn assert_wan_owner(&self, p: &Value) -> Result<()> {
        let session = self.wan_record("sessions", p)?;
        for resource in ["sessions", "status"] {
            let Some(r) = self.wan_record(resource, p)? else {
                continue;
            };
            let data = g(&r, "data");
            if resource == "status" && truthy(data) && text(data, "phase") == "deleted" {
                if let Some(session) = &session {
                    let s = g(session, "data");
                    if js::is_false(g(session, "enabled"))
                        && text(s, "driver_plugin") == "vpn_core"
                        && eq(g(s, "profile_key"), g(p, "key"))
                        && eq(g(s, "real_interface"), g(p, "interface"))
                        && eq(g(data, "local_interface"), g(p, "local"))
                        && known_wan_pipeline(p, g(data, "pipeline_interface"))
                    {
                        return Ok(());
                    }
                }
            }
            if truthy(data) && text(data, "driver_plugin") != "vpn_core" {
                return Err(fail("wan_owned_by_other", "WAN key is already owned by another driver"));
            }
        }
        Ok(())
    }

    fn wan_call(&self, action: &str, payload: &Value) -> Result<Value> {
        self.host.call("plugins.services.call", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": "wan_core", "action": action, "payload": payload}]))
    }

    fn boundary_links(&self, p: &Value, previous_mode: bool) -> Result<Option<Boundary>> {
        let r = self.wan_record("status", p)?;
        let data = r.as_ref().map(|r| g(r, "data").clone()).unwrap_or(Value::Null);
        if !truthy(&data) || text(&data, "driver_plugin") != "vpn_core" || !eq(g(&data, "local_interface"), g(p, "local")) {
            return Ok(None);
        }
        let name = js::string(js::or(g(&data, "pipeline_interface"), &json!("")));
        let mismatch = if previous_mode { !name.is_empty() && name != text(p, "pipeline") } else { name != wan_pipeline(p) };
        if mismatch {
            return Ok(None);
        }
        let local = self.link(text(p, "local"))?;
        if name.is_empty() {
            let Some(local) = local else {
                return Ok(None);
            };
            if !truthy(g(&local, "linkinfo")) || kind(&local) != "dummy" || !eq(g(&data, "local_ifindex"), g(&local, "ifindex")) {
                return Ok(None);
            }
            return Ok(Some(Boundary { peer: local.clone(), local, direct: true }));
        }
        let peer = self.link(&name)?;
        let (Some(local), Some(peer)) = (local, peer) else {
            return Ok(None);
        };
        if kind(&local) != "veth" || kind(&peer) != "veth" {
            return Ok(None);
        }
        let linked = |a: &Value, b: &Value| eq(g(a, "link_index"), g(b, "ifindex")) || (g(a, "link").is_string() && eq(g(a, "link"), g(b, "ifname")));
        if !linked(&local, &peer) || !linked(&peer, &local) || !eq(g(&data, "local_ifindex"), g(&local, "ifindex")) || !eq(g(&data, "pipeline_ifindex"), g(&peer, "ifindex")) {
            return Ok(None);
        }
        Ok(Some(Boundary { local, peer, direct: false }))
    }

    fn bindings(&self, exclude: Option<&str>) -> Result<()> {
        let mut names = Vec::new();
        let mut outgoing = Vec::new();
        for (key, lease) in &self.all_leases()? {
            if Some(key.as_str()) != exclude && flag(lease, "active") && !is_legacy(lease) {
                let plan = g(lease, "plan");
                names.push(plan["interface"].clone());
                if text(plan, "handoff_mode") == "direct" {
                    outgoing.push(plan["local"].clone());
                } else {
                    names.push(plan["pipeline"].clone());
                }
            }
        }
        // Records for hooks this version no longer declares, such as the wg-*
        // hooks before 0.9.1, would otherwise fill the two-record resource.
        for record in js::array(&self.host.call("resources.list", json!(["hook_bindings", {"limit": 8}]))?) {
            let key = js::string(g(&record, "key"));
            if key != HOOK_IN && key != HOOK_DIRECT_OUT {
                self.host.resources_delete("hook_bindings", &key)?;
            }
        }
        let has_names = !names.is_empty();
        let has_outgoing = !outgoing.is_empty();
        self.host.call("resources.set", json!(["hook_bindings", HOOK_IN, {"hook_id": HOOK_IN, "interfaces": names}, has_names, true]))?;
        self.host.call("resources.set", json!(["hook_bindings", HOOK_DIRECT_OUT, {"hook_id": HOOK_DIRECT_OUT, "interfaces": outgoing}, has_outgoing, true]))?;
        Ok(())
    }

    fn clear_maps(&mut self, lease: &Value) -> Result<()> {
        if truthy(lease) && truthy(g(g(lease, "plan"), "key")) {
            self.st.expected_maps.remove(text(g(lease, "plan"), "key"));
        }
        for field in ["tunnel_ifindex", "pipeline_ifindex"] {
            let index = js::number(g(lease, field));
            if !(index.is_finite() && index != 0.0) {
                continue;
            }
            if let Err(err) = self.host.call("ebpf.mapDelete", json!([OBJECT, MAP, u32hex(index as u64)])) {
                if !err.to_string().contains("plugin runtime target is not loaded") {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    fn map_entries(&mut self, p: &Value, tunnel: &Value, boundary: &Boundary) -> Result<Vec<Value>> {
        let peer_index = js::number(g(&boundary.peer, "ifindex")) as u64;
        let tunnel_index = js::number(g(tunnel, "ifindex")) as u64;
        let mtu = js::number(g(p, "mtu")) as u64;
        let entries = vec![
            json!({"op": "put", "object": OBJECT, "map": MAP, "key": u32hex(peer_index),
                "value": format!("{}{}000000000000000000000000{}", u32hex(1), u32hex(tunnel_index), u32hex(mtu))}),
            json!({"op": "put", "object": OBJECT, "map": MAP, "key": u32hex(tunnel_index),
                "value": format!("{}{}{}{}{}", u32hex(if boundary.direct { 3 } else { 2 }), u32hex(peer_index), mac_hex(g(&boundary.peer, "address"))?,
                    mac_hex(g(&boundary.local, "address"))?, u32hex(mtu))}),
        ];
        // Every caller writes these or checks them against the map.
        if truthy(g(p, "key")) {
            self.st.expected_maps.insert(
                text(p, "key").to_string(),
                Expected { tunnel: tunnel["ifindex"].clone(), pipeline: boundary.peer["ifindex"].clone(), entries: entries.clone() },
            );
        }
        Ok(entries)
    }

    /// A dataplane replacement can lose private maps without replacing
    /// netdevs or the core. Restore only this WAN's two entries; leave live
    /// flows alone.
    fn repair_maps(&mut self, p: &Value, tunnel: &Value, boundary: &Boundary) -> Result<()> {
        let entries = self.map_entries(p, tunnel, boundary)?;
        let stale = entries.iter().any(|entry| {
            // Hash-map reads may throw for absent keys.
            self.host.call("ebpf.mapGet", json!([OBJECT, MAP, entry["key"]])).map(|value| !eq(&value, &entry["value"])).unwrap_or(true)
        });
        if stale {
            self.host.call("ebpf.mapTransaction", json!([{"operations": entries}]))?;
        }
        Ok(())
    }

    fn install_maps(&mut self, p: &Value, tunnel: &Value, boundary: &Boundary, old: &Value) -> Result<()> {
        let next = [js::number(g(tunnel, "ifindex")), js::number(g(&boundary.peer, "ifindex"))];
        let mut ops = Vec::new();
        for field in ["tunnel_ifindex", "pipeline_ifindex"] {
            let n = js::number(g(old, field));
            if n.is_finite() && n != 0.0 && !next.contains(&n) {
                ops.push(json!({"op": "delete", "object": OBJECT, "map": MAP, "key": u32hex(n as u64)}));
            }
        }
        ops.extend(self.map_entries(p, tunnel, boundary)?);
        self.host.call("ebpf.mapTransaction", json!([{"operations": ops}]))?;
        Ok(())
    }

    // -------------------------------------------------------- apply

    fn apply(&mut self, key: &str, raw: &Value, explicit: bool, revision: &Value) -> Result<Value> {
        if explicit {
            self.health_invalidate(key)?;
        }
        let before = self.st.changing;
        self.st.changing = true;
        let outcome = (|| -> Result<Value> {
            let tun = truthy(raw) && truthy(g(raw, "driver")) && !is_str(g(raw, "driver"), "wireguard");
            let result = if tun { self.apply_tun_profile(key, raw, explicit)? } else { self.apply_profile(key, raw, explicit)? };
            if explicit {
                self.record_applied(key, raw, revision)?;
            }
            self.annotate_status(key)?;
            Ok(result)
        })();
        self.st.changing = before;
        outcome
    }

    /// What the page compares with the draft: the profile revision and, for
    /// generated proxy configs, the node of the last explicit apply. Kept
    /// outside the lease, which the drivers rewrite as a whole.
    fn record_applied(&self, key: &str, raw: &Value, revision: &Value) -> Result<()> {
        let mut applied = json!({"profile_revision": if revision.is_number() { revision.clone() } else { json!(0) }, "node": null});
        let driver = text(raw, "driver");
        if driver == "mihomo" || driver == "sing_box" {
            let summary = (|| -> Option<Value> {
                let name = js::string(js::or(g(raw, "config_secret"), &json!(format!("core_{key}"))));
                let saved: Value = serde_json::from_str(&self.secret_get(&name).ok()??).ok()?;
                if !eq(g(&saved, "veer_proxy"), &json!(1)) {
                    return None;
                }
                let form = share::metadata(&saved).ok()?;
                let nodes = js::array(g(&form, "nodes"));
                let node = nodes.get(js::number(js::or(g(&form, "selected"), &json!(0))) as usize)?;
                let summary = |n: &Value| json!({"name": js::string(js::or(g(n, "name"), &json!(""))), "type": js::string(js::or(g(n, "type"), &json!("")))});
                let mut out = summary(node);
                // Front hops in dialing order, so the card can show the chain that was applied.
                let via = js::array(g(&form, "via"));
                if !via.is_empty() {
                    out["via"] = Value::Array(via.iter().map(|i| nodes.get(js::number(i) as usize).map(summary).unwrap_or(Value::Null)).collect());
                }
                Some(out)
            })();
            if let Some(node) = summary {
                applied["node"] = node;
            }
        }
        self.host.kv_set(&format!("applied_{key}"), &applied)
    }

    fn annotate_status(&self, key: &str) -> Result<()> {
        let status = self.status_record(key)?;
        let applied = self.host.kv_get(&format!("applied_{key}"))?.map(|r| r.get("data").cloned().unwrap_or(Value::Null)).unwrap_or(Value::Null);
        let Some(status) = status else {
            return Ok(());
        };
        if !truthy(g(&status, "data")) || !truthy(&applied) {
            return Ok(());
        }
        let mut data = status["data"].clone();
        let node = js::or(g(&applied, "node"), &Value::Null).clone();
        if eq(g(&data, "profile_revision"), g(&applied, "profile_revision")) && js::or(g(&data, "node"), &Value::Null).to_string() == node.to_string() {
            return Ok(());
        }
        data["profile_revision"] = applied.get("profile_revision").cloned().unwrap_or(Value::Null);
        data["node"] = node;
        self.set_status(key, &data, !js::is_false(g(&status, "enabled")))
    }

    fn settings_of(p: &Value) -> Value {
        if !is_wireguard(p) {
            return p["settings"].clone();
        }
        json!({"slot": p["slot"], "mtu": p["mtu"], "listen_port": p["listen_port"], "addresses": p["addresses"], "peers": p["peers"], "remote_routes": p["remote_routes"]})
    }

    fn wan_payload(&self, p: &Value, usable: bool) -> Result<Value> {
        // Kernel WireGuard segments GSO skbs itself, so its boundary keeps GSO
        // on both the helper and the plain BPF path; segmenting at the WAN
        // boundary would push every MTU-sized packet through the veth and TC
        // separately. A managed TUN must positively negotiate vnet headers and
        // offloads before accepting large skbs. Never carry a previous core
        // generation's capability into its prepared/restarting boundary.
        let gso = is_wireguard(p) || (usable && js::is_true(g(p, "tun_gso")));
        let mut ipv4 = None;
        for v in js::array(g(p, "addresses")) {
            if prefix(&v, false)?.family == '4' {
                ipv4 = Some(js::string(&v).split('/').next().unwrap_or("").to_string());
                break;
            }
        }
        let Some(ipv4) = ipv4 else {
            bail!("WAN has no IPv4 address");
        };
        let routes: Vec<Value> = js::array(g(p, "remote_routes")).iter().map(|dst| json!({"dst": dst, "dev": p["local"]})).collect();
        let mtu = js::number(g(p, "mtu"));
        Ok(json!({"wan_id": p["wan_id"], "key": p["wan_id"], "profile_key": p["key"], "driver": driver_of(p), "driver_plugin": "vpn_core",
            "state": if usable { "up" } else { "prepared" }, "usable": usable, "real_interface": p["interface"], "wan_interface": p["local"],
            "local_interface": p["local"], "pipeline_interface": wan_pipeline(p), "handoff_mode": js::or(g(p, "handoff_mode"), &json!("segmented_veth")),
            "mtu": p["mtu"], "ipv4": ipv4, "addresses": p["addresses"], "routes": routes,
            "install_default_route": false, "install_default_route_v6": false, "egress_nat_redirect_mode": "prepared_l2",
            "interface_preparation": {"local_gso": {"max_size": if gso { json!(65536) } else { js::num(mtu) }, "max_segs": if gso { 65535 } else { 1 }},
                "local_offloads": {"sg": gso, "tso": gso, "gso": gso}, "pipeline_offloads": {"gro": gso, "lro": false}}}))
    }

    fn dataplane(&self) -> &'static str {
        if self.kfuncs {
            "kfuncs"
        } else {
            "bpf"
        }
    }

    fn apply_profile(&mut self, key: &str, raw: &Value, explicit: bool) -> Result<Value> {
        let p = self.normalize(key, raw)?;
        let leases = self.all_leases()?;
        let old = leases.get(key).cloned().unwrap_or(Value::Null);
        if is_legacy(&old) {
            return Err(fail("teardown_required", "Teardown the legacy routing profile before creating a WireGuard WAN"));
        }
        if truthy(&old) && !is_wireguard(g(&old, "plan")) {
            return Err(fail("teardown_required", "Teardown before changing the driver"));
        }
        if truthy(&old) && !eq(g(g(&old, "plan"), "slot"), &p["slot"]) {
            return Err(fail("teardown_required", "Teardown before changing the slot"));
        }
        for (k, lease) in &leases {
            if k != key && eq(g(g(lease, "plan"), "slot"), &p["slot"]) {
                return Err(fail("slot_reserved", "Slot is already reserved by another profile"));
            }
        }
        self.host.call("plugins.services.resolve", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": "wan_core"}]))?;
        self.assert_wan_owner(&p)?;
        let mut wg = self.owned_link(&p, None)?;
        let config = self.configuration(&p)?;
        let previous_wan = self.wan_record("status", &p)?;
        let previous_session = self.wan_record("sessions", &p)?;
        let clean_wan = self.clean_wan_state(&p)?;
        if !truthy(&old) {
            let leftovers = [
                wg.as_ref().map(|_| text(&p, "interface").to_string()),
                self.link(text(&p, "local"))?.map(|_| text(&p, "local").to_string()),
                self.link(text(&p, "pipeline"))?.map(|_| text(&p, "pipeline").to_string()),
            ];
            assert_no_leftovers(&p, &leftovers, (previous_wan.is_some() || previous_session.is_some()) && !clean_wan)?;
        }
        let stable = self.boundary_links(&p, false)?;
        if !explicit && truthy(&old) && !flag(&old, "pending") {
            if let (Some(wg), Some(stable)) = (&wg, &stable) {
                if eq(g(wg, "ifindex"), g(&old, "tunnel_ifindex"))
                    && eq(g(wg, "mtu"), &p["mtu"])
                    && is_up(wg)
                    && eq(g(&stable.local, "ifindex"), g(&old, "local_ifindex"))
                    && eq(g(&stable.peer, "ifindex"), g(&old, "pipeline_ifindex"))
                {
                    self.bindings(None)?;
                    self.repair_maps(&p, wg, stable)?;
                    return Ok(self.status_record(key)?.map(|r| r["data"].clone()).unwrap_or(Value::Null));
                }
            }
        }
        self.set_lease(key, &object(vec![
            ("active", json!(true)), ("pending", json!(true)), ("settings", Self::settings_of(&p)), ("plan", p.clone()),
            ("created_ifindex", g(&old, "created_ifindex").clone()), ("tunnel_ifindex", g(&old, "tunnel_ifindex").clone()),
            ("local_ifindex", g(&old, "local_ifindex").clone()), ("pipeline_ifindex", g(&old, "pipeline_ifindex").clone()),
        ]))?;
        let outcome = (|| -> Result<Value> {
            if (self.link(text(&p, "local"))?.is_some() || self.link(text(&p, "pipeline"))?.is_some()) && self.boundary_links(&p, true)?.is_none() {
                return Err(fail("boundary_not_ready", "WAN boundary is not ready or no longer owned; inspect replaced interfaces"));
            }
            self.suspend_tun(&p, &old)?;
            self.wan_call("prepare_handoff", &self.wan_payload(&p, false)?)?;
            let interface = text(&p, "interface").to_string();
            let owner = text(&p, "owner").to_string();
            if wg.is_none() {
                self.ip(&["link", "add", "name", &interface, "alias", &owner, "type", "wireguard"])?;
                // Some iproute/kernel combinations ignore alias during RTM_NEWLINK.
                let created = self.link(&interface)?;
                let Some(created) = created.filter(|c| truthy(g(c, "linkinfo")) && kind(c) == "wireguard") else {
                    return Err(fail("wireguard_unavailable", "WireGuard creation did not return the expected link"));
                };
                let mut pending = self.all_leases()?.get(key).cloned().unwrap_or(json!({}));
                pending["created_ifindex"] = created["ifindex"].clone();
                self.set_lease(key, &pending)?;
            }
            self.ip(&["link", "set", "dev", &interface, "alias", &owner])?;
            self.command(WG, &["syncconf", &interface, "/dev/stdin"], &config)?;
            let mtu = js::string(&p["mtu"]);
            self.ip(&["link", "set", "dev", &interface, "mtu", &mtu, "up"])?;
            wg = self.owned_link(&p, None)?;
            let boundary = self.boundary_links(&p, false)?;
            let (Some(wg), Some(boundary)) = (&wg, boundary) else {
                return Err(fail("boundary_not_ready", "WAN boundary is not ready"));
            };
            self.bindings(None)?;
            self.install_maps(&p, wg, &boundary, &old)?;
            let usable = self.wan_payload(&p, true)?;
            self.host.call("plugins.resources.set", json!(["wan_core", "sessions", p["wan_id"], usable, true, true]))?;
            self.set_lease(key, &json!({"active": true, "settings": Self::settings_of(&p), "plan": p, "tunnel_ifindex": wg["ifindex"],
                "local_ifindex": boundary.local["ifindex"], "pipeline_ifindex": boundary.peer["ifindex"]}))?;
            let result = json!({"phase": "applied", "interface": p["interface"], "wan_id": p["wan_id"], "local_interface": p["local"],
                "pipeline_interface": wan_pipeline(&p), "handoff_mode": p["handoff_mode"], "egress_nat_interface": p["local"],
                "egress_nat_source_ip": usable["ipv4"], "egress_nat_redirect_mode": "prepared_l2", "tc_ready": true, "mtu": p["mtu"],
                "dataplane": self.dataplane(), "boundary_gso": true});
            self.set_status(key, &result, true)?;
            self.arm_repair()?;
            Ok(result)
        })();
        match outcome {
            Ok(result) => Ok(result),
            Err(err) => {
                let cleanup = (|| -> Result<()> {
                    self.clear_maps(&old)?;
                    if let Some(wg) = self.owned_link(&p, None)? {
                        self.clear_maps(&json!({"tunnel_ifindex": wg["ifindex"]}))?;
                    }
                    if let Some(partial) = self.boundary_links(&p, false)? {
                        self.clear_maps(&json!({"pipeline_ifindex": partial.peer["ifindex"]}))?;
                    }
                    Ok(())
                })();
                if let Err(cleanup) = cleanup {
                    self.host.error(&format!("Tunnel map cleanup failed: {cleanup}"));
                }
                let status = self.error_status(key, &p, &err, Value::Null)?;
                self.set_status(key, &status, true)?;
                Err(err)
            }
        }
    }

    fn configuration(&self, p: &Value) -> Result<String> {
        let private = self.secret_get(&format!("private_{}", text(p, "key")))?.filter(|s| !s.is_empty());
        let Some(private) = private else {
            return Err(fail("private_key_missing", "Save the local WireGuard private key before applying"));
        };
        let mut lines = vec!["[Interface]".to_string(), format!("PrivateKey = {}", wg_key(&json!(private))?), format!("ListenPort = {}", js::string(&p["listen_port"]))];
        for peer in js::array(g(p, "peers")) {
            let allowed: Vec<String> = js::array(&peer["allowed_ips"]).iter().map(js::string).collect();
            lines.push("[Peer]".to_string());
            lines.push(format!("PublicKey = {}", js::string(&peer["public_key"])));
            lines.push(format!("AllowedIPs = {}", allowed.join(", ")));
            lines.push(format!("PersistentKeepalive = {}", js::string(&peer["keepalive"])));
            if !text(&peer, "endpoint").is_empty() {
                lines.push(format!("Endpoint = {}", text(&peer, "endpoint")));
            }
            if !text(&peer, "preshared_key_secret").is_empty() {
                let psk = self.secret_get(text(&peer, "preshared_key_secret"))?;
                lines.push(format!("PresharedKey = {}", wg_key(&psk.map(Value::String).unwrap_or(Value::Null))?));
            }
        }
        Ok(lines.join("\n") + "\n")
    }

    fn resolve_wan_addresses(&self, p: &mut Value, old: &Value) -> Result<()> {
        // An explicit address keeps the existing API contract. Automatic
        // addresses are pinned in the applied lease, never recalculated on
        // healthy polling or recovery, so an existing NAT selection retains
        // its source address.
        let old_addresses = js::array(g(g(old, "plan"), "addresses"));
        if js::array(&p["addresses"]).is_empty() && truthy(old) && !old_addresses.is_empty() {
            p["addresses"] = Value::Array(old_addresses);
        }
        if js::array(&p["addresses"]).is_empty() {
            let mut occupied = Vec::new();
            let mut reserve = |values: Vec<Value>| -> Result<()> {
                for v in values {
                    occupied.push(prefix(&v, false)?);
                }
                Ok(())
            };
            for l in js::array(&self.host.call("net.link.list", json!([]))?) {
                reserve(js::array(g(&l, "addresses")))?;
            }
            let routes: Value = serde_json::from_str(&self.command(IP, &["-j", "-4", "route", "show", "table", "all"], "")?).map_err(|err| Error::msg(err.to_string()))?;
            for r in js::array(&routes) {
                let dst = g(&r, "dst");
                if truthy(dst) && !is_str(dst, "default") && prefix(dst, false)?.bits > 0 {
                    reserve(vec![dst.clone()])?;
                }
            }
            for r in js::array(&self.host.call("resources.list", json!(["profiles", {"limit": 8}]))?) {
                if text(&r, "key") != text(p, "key") {
                    reserve(js::array(g(g(&r, "data"), "addresses")))?;
                }
            }
            for (k, lease) in &self.all_leases()? {
                if k != text(p, "key") {
                    reserve(js::array(g(g(lease, "plan"), "addresses")))?;
                }
            }
            let slot = js::number(&p["slot"]) as i64;
            'pools: for pool in ["10.78.", "172.31.", "192.168.", "198.19."] {
                for n in 0..8 {
                    let candidate = prefix(&json!(format!("{pool}{}.1/32", slot + n * 8)), true)?;
                    if !occupied.iter().any(|v| covers(v, &candidate)) {
                        p["addresses"] = json!([candidate.text]);
                        break 'pools;
                    }
                }
            }
            if js::array(&p["addresses"]).is_empty() {
                return Err(fail("no_free_address", "No free internal WAN address; choose an unused /32 address in advanced settings"));
            }
        }
        p["settings"]["addresses"] = p["addresses"].clone();
        Ok(())
    }

    fn suspend_tun(&mut self, p: &Value, lease: &Value) -> Result<()> {
        if truthy(g(p, "key")) {
            self.st.expected_maps.remove(text(p, "key"));
        }
        self.clear_maps(lease)?;
        // Keep the selected WAN boundary, but withdraw availability. Never
        // fall back to the host's direct default route when a core is absent
        // or restarting.
        if self.wan_record("status", p)?.is_some() {
            self.host.call("plugins.resources.set", json!(["wan_core", "sessions", p["wan_id"], self.wan_payload(p, false)?, false, true]))?;
        }
        Ok(())
    }

    /// sing-box's Linux gVisor driver negotiates offloads itself and Mihomo
    /// does when its generated config sets gso. External TUN providers have
    /// their own contracts and retain the segmented boundary.
    fn tun_gso(&self, p: &Value, current: &Value) -> (bool, bool) {
        let driver = text(p, "driver");
        if (driver != "sing_box" && driver != "mihomo") || !js::is_true(g(current, "tun_vnet_hdr")) {
            return (false, false);
        }
        match self.host.call("net.link.getOffloads", json!([p["interface"]])) {
            Ok(features) => {
                let enabled = ["tx", "sg", "tso", "gso"].iter().all(|k| js::is_true(g(&features, k)));
                (enabled, !enabled)
            }
            Err(_) => {
                // Offload introspection is an optimization; missing ethtool must
                // not stop a working core.
                self.host.warn("TUN offload capability unavailable; using a segmented VPN boundary");
                (false, false)
            }
        }
    }

    fn start_core(&self, key: &str, p: &Value, spec: &Value) -> Result<Value> {
        self.host.call("process.start", json!([{"id": format!("vpn_{key}"), "command": spec["command"], "args": spec["args"], "config": spec["config"],
            "restart": "on-failure", "max_restarts": p["max_restarts"], "stop_timeout_ms": 1000}]))
    }

    fn apply_tun_profile(&mut self, key: &str, raw: &Value, explicit: bool) -> Result<Value> {
        let mut p = self.normalize_tun(key, raw)?;
        let leases = self.all_leases()?;
        let old = leases.get(key).cloned().unwrap_or(Value::Null);
        let managed = text(&p, "driver") != "tun";
        if truthy(&old) {
            let plan = g(&old, "plan");
            if driver_of(plan) != text(&p, "driver") || !eq(g(plan, "slot"), &p["slot"]) || !eq(g(plan, "interface"), &p["interface"]) {
                return Err(fail("teardown_required", "Teardown before changing the driver, slot or TUN interface"));
            }
        }
        for (k, lease) in &leases {
            let other = g(lease, "plan");
            if k != key && (eq(g(other, "slot"), &p["slot"]) || eq(g(other, "interface"), &p["interface"])) {
                return Err(fail("slot_reserved", "Slot or TUN is already reserved by another profile"));
            }
        }
        let front = if managed { self.upstream_chain(&p)? } else { None };
        let mut front_link = if front.is_some() { self.link(text(&p, "upstream_interface"))? } else { None };
        self.host.call("plugins.services.resolve", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": "wan_core"}]))?;
        self.assert_wan_owner(&p)?;
        self.resolve_wan_addresses(&mut p, &old)?;
        let mut current = self.link(text(&p, "interface"))?;
        let previous_wan = self.wan_record("status", &p)?;
        let previous_session = self.wan_record("sessions", &p)?;
        let clean_wan = self.clean_wan_state(&p)?;
        if !truthy(&old) {
            let leftovers = [
                if managed && current.is_some() { Some(text(&p, "interface").to_string()) } else { None },
                self.link(text(&p, "local"))?.map(|_| text(&p, "local").to_string()),
                self.link(text(&p, "pipeline"))?.map(|_| text(&p, "pipeline").to_string()),
            ];
            assert_no_leftovers(&p, &leftovers, (previous_wan.is_some() || previous_session.is_some()) && !clean_wan)?;
        }
        if !managed {
            self.owned_link(&p, None)?;
        }
        // Build and validate before changing any network state. Active core
        // configs are encrypted separately so draft edits do not change recovery.
        let mut spec = Value::Null;
        if managed {
            let active = if !explicit && truthy(&old) { self.secret_get(&format!("active_{key}"))?.unwrap_or_default() } else { String::new() };
            spec = if !active.is_empty() {
                let args = if text(&p, "driver") == "mihomo" { json!(["-d", ".", "-f", "{config}"]) } else { json!(["run", "-c", "{config}"]) };
                json!({"command": p["core_path"], "args": args, "config": active})
            } else {
                let saved = self.secret_get(text(&p, "config_secret"))?;
                drivers::build(&p, saved.as_deref())?
            };
        }
        // Reconciliation of a healthy WAN must not withdraw it or reprepare
        // the boundary: that would disturb unrelated live flows on every
        // inventory event.
        let stable_boundary = self.boundary_links(&p, false)?;
        let stable_process = if managed { self.proc_status(key)? } else { Value::Null };
        if !explicit && truthy(&old) && !flag(&old, "pending") {
            if let (Some(cur), Some(stable)) = (&current, &stable_boundary) {
                let healthy = kind(cur) == "tun"
                    && eq(g(cur, "ifalias"), &p["owner"])
                    && eq(g(cur, "ifindex"), g(&old, "tunnel_ifindex"))
                    && eq(g(cur, "mtu"), &p["mtu"])
                    && is_up(cur)
                    && eq(g(&stable.local, "ifindex"), g(&old, "local_ifindex"))
                    && eq(g(&stable.peer, "ifindex"), g(&old, "pipeline_ifindex"))
                    && (!managed || (text(&stable_process, "state") == "running" && eq(g(&stable_process, "started_at"), g(&old, "process_started_at"))))
                    && (front.is_none() || front_link.as_ref().map(|l| eq(g(l, "ifindex"), g(&old, "upstream_ifindex"))).unwrap_or(false));
                if healthy {
                    if managed {
                        self.start_core(key, &p, &spec)?;
                    }
                    self.bindings(None)?;
                    self.install_maps(&p, cur, stable, &old)?;
                    return Ok(self.status_record(key)?.map(|r| r["data"].clone()).unwrap_or(Value::Null));
                }
            }
        }
        // A chained core waits for its front; nothing changes until it is ready.
        if let Some(front) = &front {
            front_link = Some(self.upstream_ready(front, &p)?);
        }
        let mut lease = object(vec![
            ("active", json!(true)), ("pending", json!(true)), ("settings", p["settings"].clone()), ("plan", p.clone()),
            ("tunnel_ifindex", g(&old, "tunnel_ifindex").clone()), ("pipeline_ifindex", g(&old, "pipeline_ifindex").clone()),
            ("local_ifindex", g(&old, "local_ifindex").clone()), ("process_started_at", g(&old, "process_started_at").clone()),
        ]);
        lease["upstream_ifindex"] = front_link.as_ref().filter(|_| front.is_some()).map(|l| l["ifindex"].clone()).unwrap_or(Value::Null);
        self.set_lease(key, &lease)?;
        let outcome = (|| -> Result<Value> {
            self.suspend_tun(&p, &old)?;
            self.wan_call("prepare_handoff", &self.wan_payload(&p, false)?)?;
            let mut proc = Value::Null;
            let interface = text(&p, "interface").to_string();
            if managed {
                let id = format!("vpn_{key}");
                if explicit {
                    self.host.call("process.stop", json!([id]))?;
                    if self.link(&interface)?.is_some() {
                        return Err(fail("tun_external_remains", "TUN remains after core stop; refusing to take over an external interface"));
                    }
                    self.secret_set(&format!("active_{key}"), &js::string(&spec["config"]))?;
                }
                // A rebuilt front boundary has a new ifindex: restart the
                // chained core so no socket stays bound to the old one.
                // Stopping costs no restart budget.
                if !explicit && front.is_some() && truthy(&old) && !eq(g(&old, "upstream_ifindex"), front_link.as_ref().map(|l| &l["ifindex"]).unwrap_or(&Value::Null)) {
                    self.host.call("process.stop", json!([id]))?;
                }
                // A stopped owner generation can be restored; exited/failed entries retain their budget.
                if !explicit && text(&self.proc_status(key)?, "state") == "stopped" {
                    self.host.call("process.stop", json!([id]))?;
                }
                // An exhausted restart budget remains exhausted until an explicit apply.
                proc = self.start_core(key, &p, &spec)?;
                current = self.link(&interface)?;
                // Some cores keep running after their TUN is deleted. Restart
                // only a previously published generation, with the
                // supervisor's existing budget.
                let published = truthy(&old) && truthy(g(&old, "tunnel_ifindex")) && eq(g(&proc, "started_at"), g(&old, "process_started_at"));
                let overdue = now() - js::number(g(&proc, "started_at")) >= js::number(&p["startup_timeout_seconds"]) * 1000.0;
                if !explicit && current.is_none() && text(&proc, "state") == "running" && (published || overdue) {
                    proc = self.host.call("process.restart", json!([id]))?;
                }
                if text(&proc, "state") != "running" || current.is_none() {
                    let stopped = text(&proc, "state") == "exited" || text(&proc, "state") == "failed";
                    let mut waiting = json!({"phase": if stopped { "failed" } else { "starting" }, "driver": p["driver"], "interface": p["interface"],
                        "wan_id": p["wan_id"], "wan_addresses": p["addresses"], "process": process_summary(&proc),
                        "startup_timeout_seconds": p["startup_timeout_seconds"], "max_restarts": p["max_restarts"]});
                    // An exhausted budget stays failed until an explicit apply; say so.
                    if stopped {
                        waiting["error_code"] = json!("core_exited");
                        waiting["error"] = json!(format!("Core exited with code {} after {} start(s)", js::string(g(&proc, "exit_code")), js::string(g(&proc, "starts"))));
                    }
                    self.set_status(key, &waiting, true)?;
                    self.arm_repair()?;
                    return Ok(json!({"phase": "starting", "driver": p["driver"], "wan_id": p["wan_id"], "wan_addresses": p["addresses"], "process": proc}));
                }
                let cur = current.as_ref().unwrap();
                if !truthy(g(cur, "linkinfo")) || kind(cur) != "tun" {
                    return Err(fail("tun_not_created", "Core did not create a TUN interface"));
                }
                if !truthy(g(cur, "ifalias")) && (!truthy(&old) || !eq(g(&proc, "started_at"), g(&old, "process_started_at"))) {
                    self.ip(&["link", "set", "dev", &interface, "alias", text(&p, "owner")])?;
                }
            }
            current = self.owned_link(&p, None)?;
            if managed {
                if let Some(cur) = &current {
                    if !is_up(cur) || !eq(g(cur, "mtu"), &p["mtu"]) {
                        self.ip(&["link", "set", "dev", &interface, "mtu", &js::string(&p["mtu"]), "up"])?;
                        current = self.owned_link(&p, None)?;
                    }
                }
            }
            let Some(cur) = current.clone().filter(is_up) else {
                return Err(fail("tun_not_ready", "TUN interface is not ready"));
            };
            if !eq(g(&cur, "mtu"), &p["mtu"]) {
                return Err(fail("tun_mtu_mismatch", "TUN MTU does not match the WAN profile"));
            }
            // The TUN becomes visible before a core finishes TUNSETOFFLOAD. A
            // negative result at that instant is not its final capability.
            // Retry at most twice, one second apart, while keeping the WAN
            // unpublished and the maps empty.
            let generation = if truthy(&proc) { proc["started_at"].clone() } else { cur["ifindex"].clone() };
            let same_probe = truthy(&old) && eq(g(&old, "tun_probe_generation"), &generation);
            let waiting = same_probe && js::number(g(&old, "tun_probe_retry_at")) > now();
            let (enabled, retry) = if waiting { (false, true) } else { self.tun_gso(&p, &cur) };
            lease["tun_probe_generation"] = generation;
            let attempts = (if same_probe { js::number(js::or(g(&old, "tun_probe_attempts"), &json!(0))) } else { 0.0 }) + if waiting { 0.0 } else { 1.0 };
            lease["tun_probe_attempts"] = js::num(attempts);
            if waiting || (retry && attempts < 3.0) {
                lease["tun_probe_retry_at"] = if waiting { old["tun_probe_retry_at"].clone() } else { js::num(now() + 1000.0) };
                self.set_lease(key, &lease)?;
                let starting = json!({"phase": "starting", "driver": p["driver"], "interface": p["interface"], "wan_id": p["wan_id"],
                    "wan_addresses": p["addresses"], "process": proc});
                self.set_status(key, &starting, true)?;
                self.arm_repair()?;
                return Ok(starting);
            }
            p["tun_gso"] = json!(enabled);
            // Probe only while publishing this generation, never on healthy polling.
            let verified = self.owned_link(&p, None)?;
            let unchanged = verified.as_ref().map(|v| eq(g(v, "ifindex"), g(&cur, "ifindex")) && eq(g(v, "mtu"), &p["mtu"]) && is_up(v)).unwrap_or(false);
            if !unchanged {
                return Err(fail("core_restarted", "TUN changed while inspecting its capabilities"));
            }
            if enabled {
                // WAN Core persists the preparation in its profile, which takes
                // priority over later session fields. Update that profile before
                // publishing; otherwise its original segmented settings silently
                // override the probe.
                let mut prepared = self.wan_payload(&p, false)?;
                prepared["interface_preparation"] = self.wan_payload(&p, true)?["interface_preparation"].clone();
                self.wan_call("prepare_handoff", &prepared)?;
            }
            let Some(boundary) = self.boundary_links(&p, false)? else {
                return Err(fail("boundary_not_ready", "WAN boundary is not ready"));
            };
            lease["plan"] = p.clone();
            lease["tunnel_ifindex"] = cur["ifindex"].clone();
            lease["local_ifindex"] = boundary.local["ifindex"].clone();
            lease["pipeline_ifindex"] = boundary.peer["ifindex"].clone();
            self.set_lease(key, &lease)?;
            self.bindings(None)?;
            self.install_maps(&p, &cur, &boundary, &old)?;
            if managed {
                let now_status = self.proc_status(key)?;
                if text(&now_status, "state") != "running" || !eq(g(&now_status, "started_at"), g(&proc, "started_at")) {
                    return Err(fail("core_restarted", "Core restarted while publishing the WAN"));
                }
            }
            let usable = self.wan_payload(&p, true)?;
            self.host.call("plugins.resources.set", json!(["wan_core", "sessions", p["wan_id"], usable, true, true]))?;
            lease["pending"] = json!(false);
            lease["process_started_at"] = if truthy(&proc) { proc["started_at"].clone() } else { Value::Null };
            self.set_lease(key, &lease)?;
            let result = json!({"phase": "applied", "driver": p["driver"], "interface": p["interface"], "wan_id": p["wan_id"],
                "local_interface": p["local"], "pipeline_interface": wan_pipeline(&p), "handoff_mode": p["handoff_mode"], "egress_nat_interface": p["local"],
                "wan_addresses": p["addresses"], "egress_nat_source_ip": usable["ipv4"], "egress_nat_redirect_mode": "prepared_l2", "tc_ready": true,
                "process": if truthy(&proc) { process_summary(&proc) } else { proc.clone() }, "dataplane": self.dataplane(), "tun_gso": enabled, "boundary_gso": enabled});
            self.set_status(key, &result, true)?;
            self.arm_repair()?;
            Ok(result)
        })();
        match outcome {
            Ok(result) => Ok(result),
            Err(err) => {
                if self.suspend_tun(&p, &lease).is_err() {
                    self.host.error("VPN suspension failed");
                }
                // Core diagnostics may include credentials; never publish their output.
                let process = if managed { process_summary(&self.proc_status(key).unwrap_or(Value::Null)) } else { Value::Null };
                let status = self.error_status(key, &p, &err, json!({"process": process}))?;
                self.set_status(key, &status, true)?;
                self.arm_repair()?;
                Err(err)
            }
        }
    }

    /// Returns false when the exit could not be repaired.
    fn repair_tun(&mut self, key: &str, lease: &Value) -> Result<bool> {
        let p = g(lease, "plan").clone();
        let outcome = (|| -> Result<()> {
            let current = self.link(text(&p, "interface"))?;
            let proc = if text(&p, "driver") == "tun" { Value::Null } else { self.proc_status(key)? };
            let mut tunnel_ok = !flag(lease, "pending")
                && current
                    .as_ref()
                    .map(|cur| {
                        kind(cur) == "tun"
                            && eq(g(cur, "ifalias"), &p["owner"])
                            && eq(g(cur, "ifindex"), g(lease, "tunnel_ifindex"))
                            && eq(g(cur, "mtu"), &p["mtu"])
                            && is_up(cur)
                    })
                    .unwrap_or(false)
                && !(truthy(&proc) && (text(&proc, "state") != "running" || !eq(g(&proc, "started_at"), g(lease, "process_started_at"))));
            // A chained exit also needs the same front boundary it bound to.
            if tunnel_ok && !g(lease, "upstream_ifindex").is_null() {
                let front = self.link(text(&p, "upstream_interface"))?;
                tunnel_ok = front.map(|f| eq(g(&f, "ifindex"), g(lease, "upstream_ifindex"))).unwrap_or(false);
            }
            let boundary = if tunnel_ok { self.boundary_links(&p, false)? } else { None };
            match (&current, boundary) {
                (Some(cur), Some(b)) if tunnel_ok && eq(g(&b.local, "ifindex"), g(lease, "local_ifindex")) && eq(g(&b.peer, "ifindex"), g(lease, "pipeline_ifindex")) => {
                    self.repair_maps(&p, cur, &b)?;
                }
                _ => {
                    self.suspend_tun(&p, lease)?;
                    self.apply(key, g(lease, "settings"), false, &Value::Null)?;
                }
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => Ok(true),
            Err(err) => {
                if self.suspend_tun(&p, lease).is_err() {
                    self.host.error("VPN suspension failed");
                }
                let status = self.error_status(key, &p, &err, Value::Null)?;
                self.set_status(key, &status, true)?;
                Ok(false)
            }
        }
    }

    // -------------------------------------------------------- teardown

    fn teardown(&mut self, key: &str) -> Result<()> {
        self.health_invalidate(key)?;
        let before = self.st.changing;
        self.st.changing = true;
        let outcome = self.teardown_profile(key);
        self.st.changing = before;
        outcome
    }

    fn teardown_profile(&mut self, key: &str) -> Result<()> {
        let Some(lease) = self.all_leases()?.get(key).cloned() else {
            return Ok(());
        };
        let p = g(&lease, "plan").clone();
        if !is_wireguard(&p) {
            return self.teardown_tun(key, &lease);
        }
        self.owned_link(&p, None)?;
        if is_legacy(&lease) {
            let nft = self.table(&p)?;
            if truthy(g(&lease, "previous")) {
                self.remove_plan(&lease["previous"])?;
            }
            self.remove_plan(&p)?;
            if self.owned_link(&p, None)?.is_some() {
                self.ip(&["link", "del", "dev", text(&p, "interface")])?;
            }
            if nft.is_some() {
                self.command(NFT, &["delete", "table", "inet", text(&p, "nft")], "")?;
            }
        } else {
            self.assert_wan_owner(&p)?;
            self.clear_maps(&lease)?;
            self.bindings(Some(key))?;
            if self.owned_link(&p, None)?.is_some() {
                self.ip(&["link", "del", "dev", text(&p, "interface")])?;
            }
            if self.wan_record("status", &p)?.is_some() {
                self.wan_call("teardown", &self.wan_payload(&p, false)?)?;
                let status = self.wan_record("status", &p)?;
                if status.map(|s| text(g(&s, "data"), "phase") != "deleted").unwrap_or(true) {
                    return Err(fail("wan_cleanup_incomplete", "WAN cleanup incomplete; retry teardown"));
                }
            }
        }
        self.host.kv_delete(&format!("lease_{key}"))?;
        self.host.kv_delete(&format!("applied_{key}"))?;
        self.set_status(key, &json!({"phase": "down"}), false)?;
        self.arm_repair()
    }

    fn teardown_tun(&mut self, key: &str, lease: &Value) -> Result<()> {
        let p = g(lease, "plan").clone();
        self.assert_wan_owner(&p)?;
        self.suspend_tun(&p, lease)?;
        self.bindings(Some(key))?;
        // External TUN mode never deletes or reconfigures its provider's device.
        if text(&p, "driver") != "tun" {
            self.host.call("process.stop", json!([format!("vpn_{key}")]))?;
        }
        if self.wan_record("status", &p)?.is_some() {
            self.wan_call("teardown", &self.wan_payload(&p, false)?)?;
            let status = self.wan_record("status", &p)?;
            if status.map(|s| text(g(&s, "data"), "phase") != "deleted").unwrap_or(true) {
                return Err(fail("wan_cleanup_incomplete", "WAN cleanup incomplete; retry teardown"));
            }
        }
        self.host.kv_delete(&format!("lease_{key}"))?;
        self.host.kv_delete(&format!("applied_{key}"))?;
        self.secret_delete(&format!("active_{key}"))?;
        self.set_status(key, &json!({"phase": "down", "driver": p["driver"]}), false)?;
        self.arm_repair()
    }

    fn delete_profile(&mut self, key: &str) -> Result<Value> {
        let record = self.host.resources_get("profiles", key)?;
        let leases = self.all_leases()?;
        let lease = leases.get(key).cloned().unwrap_or(Value::Null);
        let mut names = profile_secrets(key, record.as_ref().map(|r| g(r, "data")).unwrap_or(&Value::Null));
        names.extend(profile_secrets(key, g(&lease, "settings")));
        let mut retained = Vec::new();
        for r in js::array(&self.host.call("resources.list", json!(["profiles", {"limit": 8}]))?) {
            if text(&r, "key") != key {
                retained.extend(profile_secrets(text(&r, "key"), g(&r, "data")));
            }
        }
        for (k, other) in &leases {
            if k != key {
                retained.extend(profile_secrets(k, g(other, "settings")));
            }
        }
        // Keep the retryable draft and credentials until network cleanup succeeds.
        self.teardown(key)?;
        for id in [format!("wg_{key}"), format!("vpn_{key}")] {
            let session = self.host.call("plugins.resources.get", json!(["wan_core", "sessions", id]))?;
            if !truthy(&session) || text(g(&session, "data"), "driver_plugin") != "vpn_core" || text(g(&session, "data"), "profile_key") != key {
                continue;
            }
            if !js::is_false(g(&session, "enabled")) {
                return Err(fail("wan_cleanup_incomplete", "WAN session is still active; retry teardown"));
            }
            self.wan_call("teardown", &json!({"key": id, "session": session["data"], "forget": true}))?;
            if truthy(&self.host.call("plugins.resources.get", json!(["wan_core", "sessions", id]))?) {
                return Err(fail("wan_cleanup_incomplete", "WAN records remain; retry deletion"));
            }
        }
        self.health_remove(key)?;
        for name in &names {
            if !retained.contains(name) {
                self.secret_delete(name)?;
            }
        }
        self.host.call("resources.transaction", json!([[{"op": "delete", "resource": "status", "key": key}, {"op": "delete", "resource": "profiles", "key": key}]]))?;
        self.arm_repair()?;
        Ok(json!({"phase": "deleted"}))
    }

    // -------------------------------------------------------- reads

    fn inspect(&mut self, key: &str) -> Result<Value> {
        let Some(lease) = self.all_leases()?.get(key).cloned() else {
            return Ok(json!({"phase": "down"}));
        };
        let p = g(&lease, "plan").clone();
        let applied = self.host.kv_get(&format!("applied_{key}"))?;
        let mut base = json!({"driver": driver_of(&p), "interface": p["interface"], "wan_id": p["wan_id"], "local_interface": p["local"],
            "handoff_mode": js::or(g(&p, "handoff_mode"), &json!("segmented_veth")), "dataplane": self.dataplane(), "traffic": self.traffic(text(&p, "interface"))});
        if !is_wireguard(&p) {
            let status = self.status_record(key)?;
            base["phase"] = status.as_ref().filter(|s| truthy(g(s, "data"))).map(|s| s["data"]["phase"].clone()).unwrap_or(json!("missing"));
            base["process"] = if text(&p, "driver") == "tun" { Value::Null } else { process_summary(&self.proc_status(key)?) };
            base["tun_gso"] = json!(js::is_true(g(&p, "tun_gso")));
            base["boundary_gso"] = json!(js::is_true(g(&p, "tun_gso")));
            base["node"] = applied.as_ref().filter(|a| truthy(g(a, "data"))).map(|a| js::or(g(&a["data"], "node"), &Value::Null).clone()).unwrap_or(Value::Null);
            return Ok(base);
        }
        if self.owned_link(&p, None)?.is_none() {
            base["phase"] = json!("missing");
            return Ok(base);
        }
        base["phase"] = json!("configured");
        base["boundary_gso"] = json!(true);
        base["public_key"] = json!(self.command(WG, &["show", text(&p, "interface"), "public-key"], "")?.trim());
        base["peers"] = self.wg_peers(&p)?;
        Ok(base)
    }

    fn upstream_interfaces(&self) -> Result<Vec<Value>> {
        // Suggestions only: the profile still accepts any name and apply
        // validates it. Leave out loopback, every VPN tunnel and boundary, and
        // hypervisor plumbing.
        let addresses = |l: &Value| -> Vec<Value> { js::array(g(l, "addresses")).into_iter().filter(|a| !js::string(a).to_lowercase().starts_with("fe80:")).collect() };
        let mut physical: Vec<Value> = js::array(&self.host.call("net.link.list", json!([]))?)
            .into_iter()
            .filter(|l| {
                let name = text(l, "name");
                !name.is_empty() && name != "lo" && !own_link_name(name) && !plumbing_name(name) && text(l, "kind") != "tuntap" && text(l, "kind") != "dummy"
            })
            .map(|l| json!({"name": l["name"], "kind": js::or(g(&l, "kind"), &json!("")), "up": js::is_true(g(&l, "up")), "addresses": addresses(&l)}))
            .collect();
        physical.sort_by(|a, b| {
            let up = |v: &Value| js::is_true(g(v, "up"));
            let has = |v: &Value| !js::array(g(v, "addresses")).is_empty();
            up(b).cmp(&up(a)).then(has(b).cmp(&has(a))).then(text(a, "name").cmp(text(b, "name")))
        });
        // Applied exits come last: choosing one chains this exit behind it.
        let leases = self.all_leases()?;
        for k in chain_order(&leases) {
            let lease = &leases[&k];
            let status = self.status_record(&k)?;
            let local = text(g(lease, "plan"), "local");
            let l = if local.is_empty() { None } else { self.host.call("net.link.get", json!([local])).ok() };
            let applied = status.as_ref().map(|s| text(g(s, "data"), "phase") == "applied").unwrap_or(false);
            let Some(l) = l.filter(|l| truthy(l)) else {
                continue;
            };
            if !flag(lease, "active") || is_legacy(lease) || !applied {
                continue;
            }
            physical.push(json!({"name": local, "kind": "vpn", "up": js::is_true(g(&l, "up")), "addresses": addresses(&l), "exit": k,
                "driver": driver_of(g(lease, "plan"))}));
        }
        Ok(physical)
    }

    fn traffic(&self, name: &str) -> Value {
        // Tunnel counters: the boundary's own may skip redirected packets.
        match self.host.call("net.link.get", json!([name])) {
            Ok(info) => {
                let stats = g(&info, "statistics");
                if truthy(stats) {
                    json!({"rx_bytes": stats.get("rx_bytes"), "tx_bytes": stats.get("tx_bytes"), "rx_packets": stats.get("rx_packets"), "tx_packets": stats.get("tx_packets")})
                } else {
                    Value::Null
                }
            }
            Err(_) => Value::Null,
        }
    }

    fn wg_peers(&self, p: &Value) -> Result<Value> {
        // Never `wg show dump`: its first line carries the private key.
        let interface = text(p, "interface");
        let rows = |field: &str| -> Result<Vec<Vec<String>>> {
            Ok(self
                .command(WG, &["show", interface, field], "")?
                .split('\n')
                .map(|line| line.split('\t').map(str::to_string).collect::<Vec<_>>())
                .filter(|cols| !cols[0].is_empty())
                .collect())
        };
        let mut order: Vec<String> = Vec::new();
        let mut peers: BTreeMap<String, Value> = BTreeMap::new();
        let mut peer = |key: &str, peers: &mut BTreeMap<String, Value>| {
            if !peers.contains_key(key) {
                order.push(key.to_string());
                peers.insert(key.to_string(), json!({"public_key": key, "endpoint": "", "latest_handshake": 0, "rx_bytes": 0, "tx_bytes": 0}));
            }
        };
        let number = |s: Option<&String>| js::num(s.and_then(|s| s.trim().parse::<f64>().ok()).filter(|n| n.is_finite()).unwrap_or(0.0));
        for c in rows("endpoints")? {
            peer(&c[0], &mut peers);
            let endpoint = c.get(1).filter(|e| !e.is_empty() && *e != "(none)").cloned().unwrap_or_default();
            peers.get_mut(&c[0]).unwrap()["endpoint"] = json!(endpoint);
        }
        for c in rows("latest-handshakes")? {
            peer(&c[0], &mut peers);
            peers.get_mut(&c[0]).unwrap()["latest_handshake"] = number(c.get(1));
        }
        for c in rows("transfer")? {
            peer(&c[0], &mut peers);
            let v = peers.get_mut(&c[0]).unwrap();
            v["rx_bytes"] = number(c.get(1));
            v["tx_bytes"] = number(c.get(2));
        }
        // Configured order first; a peer only the kernel knows still shows.
        let mut out = Vec::new();
        for configured in js::array(g(p, "peers")) {
            let key = js::string(&configured["public_key"]);
            peer(&key, &mut peers);
            out.push(peers.remove(&key).unwrap());
        }
        for key in order {
            if let Some(v) = peers.remove(&key) {
                out.push(v);
            }
        }
        Ok(Value::Array(out))
    }

    /// What a probe goes through: the boundary and source address of an
    /// applied exit, with a fingerprint of its link generation.
    pub fn health_path(&mut self, key: &str, worker_read: bool) -> Result<Value> {
        let leases = self.all_leases()?;
        let lease = leases.get(key).cloned().unwrap_or(Value::Null);
        let status = self.status_record(key)?;
        let applied = status.as_ref().map(|s| text(g(s, "data"), "phase") == "applied").unwrap_or(false);
        if !truthy(&lease) || !flag(&lease, "active") || flag(&lease, "pending") || is_legacy(&lease) || !applied {
            return Ok(Value::Null);
        }
        let p = g(&lease, "plan").clone();
        let tunnel = self.owned_link(&p, Some(&lease))?;
        let boundary = self.boundary_links(&p, false)?;
        let (Some(tunnel), Some(boundary)) = (tunnel, boundary) else {
            return Ok(Value::Null);
        };
        if !is_up(&tunnel)
            || !eq(g(&tunnel, "ifindex"), g(&lease, "tunnel_ifindex"))
            || !eq(g(&boundary.local, "ifindex"), g(&lease, "local_ifindex"))
            || !eq(g(&boundary.peer, "ifindex"), g(&lease, "pipeline_ifindex"))
        {
            return Ok(Value::Null);
        }
        let managed = !is_wireguard(&p) && text(&p, "driver") != "tun";
        let proc = if managed && !worker_read { self.proc_status(key)? } else { Value::Null };
        if truthy(&proc) && (text(&proc, "state") != "running" || !eq(g(&proc, "started_at"), g(&lease, "process_started_at"))) {
            return Ok(Value::Null);
        }
        let generation = self.host.kv_get(&format!("health_generation_{key}"))?.map(|r| r.get("data").cloned().unwrap_or(Value::Null)).unwrap_or(Value::Null);
        // Ordered primitives: explicit applies and settings already advance
        // the health generation.
        let fingerprint = json!([generation, tunnel["ifindex"], boundary.local["ifindex"], boundary.peer["ifindex"],
            if managed { g(&lease, "process_started_at").clone() } else { Value::Null }])
        .to_string();
        Ok(json!({"interface": p["local"], "source_ip": self.wan_payload(&p, true)?["ipv4"], "fingerprint": fingerprint}))
    }

    // -------------------------------------------------------- legacy 0.1.x

    /// Exact cleanup for previously applied 0.1.x routing leases.
    fn table(&self, p: &Value) -> Result<Option<Value>> {
        let name = text(p, "nft");
        let args: Vec<String> = ["-j", "list", "table", "inet", name].iter().map(|s| s.to_string()).collect();
        let result = self.execute(NFT, &args, "")?;
        if js::number(g(&result, "exit_code")) != 0.0 {
            if js::string(js::or(g(&result, "stderr"), &json!(""))).contains("No such file or directory") {
                return Ok(None);
            }
            bail!("Cannot inspect nftables ownership");
        }
        let parsed: Value = serde_json::from_str(&js::string(g(&result, "stdout"))).map_err(|err| Error::msg(err.to_string()))?;
        let existing = js::array(g(&parsed, "nftables")).into_iter().find(|v| truthy(g(v, "table")) && text(&v["table"], "name") == name);
        let mut owner = existing.as_ref().map(|e| e["table"].get("comment").cloned().unwrap_or(Value::Null)).unwrap_or(Value::Null);
        if existing.is_some() && owner.is_null() {
            // Older nft releases omit table comments from JSON. Require the
            // exact top-level comment, before any chain, from their canonical text output.
            let out = self.command(NFT, &["list", "table", "inet", name], "")?;
            let lines: Vec<&str> = out.split('\n').map(str::trim).filter(|l| !l.is_empty()).collect();
            if lines.first() == Some(&format!("table inet {name} {{").as_str()) && lines.get(1) == Some(&format!("comment \"{}\"", text(p, "owner")).as_str()) {
                owner = p["owner"].clone();
            }
        }
        match existing {
            Some(existing) if eq(&owner, &p["owner"]) => Ok(Some(existing["table"].clone())),
            _ => bail!("Reserved nftables table is owned by another configuration"),
        }
    }

    fn routes(&self, p: &Value, family: &str) -> Result<Vec<Value>> {
        let table = js::string(&p["table"]);
        let args: Vec<String> = vec!["-j".into(), format!("-{family}"), "route".into(), "show".into(), "table".into(), table];
        let result = self.execute(IP, &args, "")?;
        if js::number(g(&result, "exit_code")) != 0.0 {
            if js::string(js::or(g(&result, "stderr"), &json!(""))).contains("FIB table does not exist") {
                return Ok(Vec::new());
            }
            bail!("Cannot inspect routing table");
        }
        let stdout = js::string(js::or(g(&result, "stdout"), &json!("")));
        let parsed: Value = serde_json::from_str(if stdout.is_empty() { "[]" } else { &stdout }).map_err(|err| Error::msg(err.to_string()))?;
        Ok(js::array(&parsed))
    }

    fn remove_plan(&self, p: &Value) -> Result<()> {
        for b in js::array(g(p, "bindings")) {
            let family = text(&b, "family").to_string();
            let rules = self.json_ip(&[&format!("-{family}"), "rule", "show"])?;
            let mut matched = false;
            for r in js::array(&rules) {
                if rule_matches(&r, p, &b)? {
                    matched = true;
                    break;
                }
            }
            if matched {
                let mut args = vec![format!("-{family}"), "rule".into(), "del".into()];
                args.extend(rule_args(p, &b));
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                self.ip(&refs)?;
            }
        }
        for r in route_plan(p)? {
            let family = text(&r, "family").to_string();
            let mut matched = false;
            for v in self.routes(p, &family)? {
                if route_matches(&v, &r)? {
                    matched = true;
                    break;
                }
            }
            if matched {
                let mut args = vec![format!("-{family}"), "route".into(), "del".into()];
                args.extend(route_args(p, &r));
                let refs: Vec<&str> = args.iter().map(String::as_str).collect();
                self.ip(&refs)?;
            }
        }
        Ok(())
    }

    fn error_status(&self, key: &str, p: &Value, e: &Error, extra: Value) -> Result<Value> {
        let (error, code) = error_fields(e);
        let mut out = json!({"phase": "error", "driver": driver_of(p), "interface": p.get("interface"), "local_interface": p.get("local"),
            "wan_id": p.get("wan_id"), "failed_at": js::num(now()), "cleanup_required": true, "error": error, "error_code": code});
        // Repair retries every few seconds: keep the time the failure first appeared.
        if let Some(previous) = self.status_record(key)? {
            let data = g(&previous, "data");
            if truthy(data) && text(data, "phase") == "error" && eq(g(data, "error"), &out["error"]) && truthy(g(data, "failed_at")) {
                out["failed_at"] = data["failed_at"].clone();
            }
        }
        if let Value::Object(extra) = extra {
            for (k, v) in extra {
                if !v.is_null() {
                    out[k.as_str()] = v;
                }
            }
        }
        Ok(out)
    }
}

fn is_str(value: &Value, text: &str) -> bool {
    value.as_str() == Some(text)
}

fn wan_pipeline(p: &Value) -> Value {
    if text(p, "handoff_mode") == "direct" {
        json!("")
    } else {
        p.get("pipeline").cloned().unwrap_or(Value::Null)
    }
}

fn known_wan_pipeline(p: &Value, name: &Value) -> bool {
    !truthy(name) || eq(name, g(p, "pipeline"))
}

fn is_vpn_boundary_name(name: &str) -> bool {
    // ^veer(wg|vpn)[0-9]+$
    let Some(rest) = name.strip_prefix("veer") else {
        return false;
    };
    let digits = rest.strip_prefix("wg").or_else(|| rest.strip_prefix("vpn"));
    digits.map(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit())).unwrap_or(false)
}

fn own_link_name(name: &str) -> bool {
    // ^(veerwgp?|veervpnp?|vwg|vtun)[a-z0-9_]*$
    let rest = ["veerwgp", "veerwg", "veervpnp", "veervpn", "vwg", "vtun"].iter().find_map(|prefix| name.strip_prefix(prefix));
    rest.map(|r| r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')).unwrap_or(false)
}

fn plumbing_name(name: &str) -> bool {
    ["tap", "fwbr", "fwpr", "fwln", "veth"].iter().any(|p| name.starts_with(p))
}

fn exit_by_boundary(name: &str, leases: &Leases) -> Option<(String, Value)> {
    if name.is_empty() {
        return None;
    }
    leases
        .iter()
        .find(|(_, lease)| flag(lease, "active") && !is_legacy(lease) && text(g(lease, "plan"), "local") == name)
        .map(|(key, lease)| (key.clone(), lease.clone()))
}

fn chain_depth(key: &str, leases: &Leases) -> usize {
    let mut depth = 0;
    let mut seen = vec![key.to_string()];
    let mut cur = leases.get(key).cloned();
    while let Some(lease) = cur {
        let upstream = text(g(&lease, "plan"), "upstream_interface");
        if upstream.is_empty() {
            break;
        }
        let Some((front_key, front)) = exit_by_boundary(upstream, leases) else {
            break;
        };
        if seen.contains(&front_key) {
            break;
        }
        seen.push(front_key);
        depth += 1;
        cur = Some(front);
    }
    depth
}

/// Fronts before the exits chained behind them, then by key.
fn chain_order(leases: &Leases) -> Vec<String> {
    let mut keys: Vec<String> = leases.keys().cloned().collect();
    keys.sort_by(|a, b| chain_depth(a, leases).cmp(&chain_depth(b, leases)).then(a.cmp(b)));
    keys
}

fn dependents(key: &str, leases: &Leases) -> Vec<String> {
    let Some(lease) = leases.get(key) else {
        return Vec::new();
    };
    let local = text(g(lease, "plan"), "local");
    if local.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = leases
        .iter()
        .filter(|(k, other)| k.as_str() != key && flag(other, "active") && text(g(other, "plan"), "upstream_interface") == local)
        .map(|(k, _)| k.clone())
        .collect();
    out.sort();
    out
}

fn profile_secrets(key: &str, data: &Value) -> Vec<String> {
    let mut names = vec![format!("private_{key}"), format!("active_{key}"), format!("core_{key}"), format!("core_mihomo_{key}"), format!("core_sing_box_{key}")];
    if truthy(data) {
        if truthy(g(data, "config_secret")) {
            names.push(js::string(&data["config_secret"]));
        }
        for peer in js::array(g(data, "peers")) {
            if truthy(g(&peer, "preshared_key_secret")) {
                names.push(js::string(&peer["preshared_key_secret"]));
            }
        }
    }
    for i in 0..8 {
        names.push(format!("psk_{key}_{i}"));
    }
    names.retain(|name| token(&json!(name)).is_ok());
    names
}

/// "IP:port" or "[IPv6]:port" with a numeric address.
fn split_endpoint(endpoint: &str) -> Option<(String, String)> {
    // ^(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)$
    let colon = endpoint.rfind(':')?;
    let (host, port) = (&endpoint[..colon], &endpoint[colon + 1..]);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
    } else {
        !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    };
    if !ok {
        return None;
    }
    Some((host.to_string(), port.to_string()))
}

fn endpoint_host(endpoint: &str) -> String {
    if let Some(inner) = endpoint.strip_prefix('[') {
        return inner[..inner.find(']').unwrap_or(inner.len())].to_string();
    }
    endpoint.split(':').next().unwrap_or("").to_string()
}

fn rule_args(p: &Value, b: &Value) -> Vec<String> {
    vec![
        "priority".into(), js::string(&b["priority"]), "from".into(), js::string(&b["source"]), "to".into(), js::string(&b["destination"]),
        "iif".into(), js::string(&b["lan_interface"]), "table".into(), js::string(&p["table"]), "protocol".into(), PROTOCOL.into(),
    ]
}

fn rule_matches(r: &Value, p: &Value, b: &Value) -> Result<bool> {
    let normalized = |value: &Value, length: &Value| -> Result<String> {
        if !truthy(value) || is_str(value, "all") {
            return Ok(if text(b, "family") == "4" { "0.0.0.0/0".to_string() } else { prefix(&json!("::/0"), false)?.text });
        }
        let v = js::string(value);
        let full = if !v.contains('/') && !length.is_null() { format!("{v}/{}", js::string(length)) } else { v };
        Ok(prefix(&json!(full), false)?.text)
    };
    Ok(js::number(g(r, "priority")) == js::number(g(b, "priority"))
        && js::string(g(r, "protocol")) == PROTOCOL
        && js::number(g(r, "table")) == js::number(g(p, "table"))
        && eq(g(r, "iif"), g(b, "lan_interface"))
        && normalized(g(r, "src"), g(r, "srclen"))? == js::string(g(b, "source"))
        && normalized(g(r, "dst"), g(r, "dstlen"))? == js::string(g(b, "destination")))
}

fn route_matches(actual: &Value, planned: &Value) -> Result<bool> {
    let dst = if is_str(g(actual, "dst"), "default") {
        json!(if text(planned, "family") == "4" { "0.0.0.0/0" } else { "::/0" })
    } else {
        g(actual, "dst").clone()
    };
    if !truthy(&dst) {
        return Ok(false);
    }
    let planned_type = js::or(g(planned, "type"), &json!("unicast")).clone();
    let dev_want = if truthy(g(planned, "dev")) {
        js::string(&planned["dev"])
    } else if truthy(g(planned, "type")) && text(planned, "family") == "6" && text(actual, "dev") == "lo" {
        "lo".to_string()
    } else {
        String::new()
    };
    Ok(prefix(&dst, false)?.text == prefix(g(planned, "dst"), false)?.text
        && js::string(g(actual, "protocol")) == PROTOCOL
        && js::string(js::or(g(actual, "metric"), &json!(0))) == js::string(g(planned, "metric"))
        && eq(js::or(g(actual, "type"), &json!("unicast")), &planned_type)
        && js::string(js::or(g(actual, "dev"), &json!(""))) == dev_want
        && !truthy(g(actual, "gateway"))
        && !truthy(g(actual, "nexthops")))
}

fn route_plan(p: &Value) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for family in ["4", "6"] {
        if !js::array(g(p, "bindings")).iter().any(|b| text(b, "family") == family) {
            continue;
        }
        out.push(json!({"family": family, "type": "unreachable", "dst": if family == "4" { "0.0.0.0/0" } else { "::/0" }, "metric": "32760"}));
        let mut seen = Vec::new();
        for peer in js::array(g(p, "peers")) {
            for cidr in js::array(g(&peer, "allowed_ips")) {
                let text_cidr = js::string(&cidr);
                if prefix(&cidr, false)?.family.to_string() != family || seen.contains(&text_cidr) {
                    continue;
                }
                seen.push(text_cidr);
                out.push(json!({"family": family, "dst": cidr, "dev": p["interface"], "metric": "10"}));
            }
        }
        for cidr in js::array(g(p, "bypass")) {
            if prefix(&cidr, false)?.family.to_string() == family {
                out.push(json!({"family": family, "type": "throw", "dst": cidr, "metric": "1"}));
            }
        }
    }
    Ok(out)
}

fn route_args(p: &Value, r: &Value) -> Vec<String> {
    let mut args: Vec<String> = if truthy(g(r, "type")) {
        vec![js::string(&r["type"]), js::string(&r["dst"])]
    } else {
        vec![js::string(&r["dst"]), "dev".into(), js::string(&r["dev"])]
    };
    args.extend(["table".into(), js::string(&p["table"]), "metric".into(), js::string(&r["metric"]), "proto".into(), PROTOCOL.into()]);
    args
}

#[cfg(test)]
mod tests;
