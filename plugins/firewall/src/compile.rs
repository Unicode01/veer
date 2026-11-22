//! Turns firewall policies into the map entries firewall.bpf.c reads. Pure
//! functions, no host API: the control side writes the result, the unit
//! tests check it. Layouts must match the structs in firewall.bpf.c
//! (little-endian hosts).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, json, Result, Value};

pub const MAX_POLICY_SLOT: u32 = 255; // slots 1..255; slot 0 holds the trusted sources
pub const MAX_CLASSES: usize = 1023; // class ids 1..1023 (fw_class holds 1024 per generation)
pub const MAX_PORT_RANGES: usize = 64;
pub const MAX_DESTINATIONS: usize = 64;
pub const MAX_SOURCES: usize = 1024;
pub const MAX_TRUSTED: usize = 256;
// Per generation; each LPM map holds both generations.
pub const PORT_PREFIX_CAPACITY: usize = 8192;
pub const DST_CAPACITY: usize = 4096;
pub const SRC_CAPACITY: usize = 16384;

pub const PORT_WORDS: u32 = 1024;
pub const PORT_WORDS_PER_GEN: u32 = 2 * PORT_WORDS;
pub const CLASSES_PER_GEN: u32 = 1024;
pub const POLICIES_PER_GEN: u32 = 256;
pub const COUNTERS: u32 = 4;

// fw_ports proto byte; fw_port_bits covers TCP and UDP only.
pub const PROTO_TCP: u8 = 0;
pub const PROTO_UDP: u8 = 1;
pub const PROTO_ICMP: u8 = 2; // port: type << 8 | code
pub const PROTO_ICMPV6: u8 = 3; // port: type << 8 | code
pub const PROTO_IP: u8 = 4; // port: protocol << 8
pub const PROTO_NAMES: [&str; 5] = ["tcp", "udp", "icmp", "icmpv6", "ip"];
pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;

const POLICY_VALID: u8 = 1;
const POLICY_LIMIT: u8 = 2;

// fw_pext
const PX_NEW_ONLY: u8 = 1;
const PX_ADD_SET: u8 = 2;
pub const PX_SETS: usize = 4;
const MAX_ADD_SECONDS: i64 = 30 * 86400;

// fw_gcfg
const G_CT: u32 = 1;
const G_BOGON: u32 = 2;
const G_BAD_FLAGS: u32 = 4;
const G_DROP_FRAGS: u32 = 8;
const G_URPF_LOOSE: u32 = 16;
const G_URPF_STRICT: u32 = 32;
const G_PROTO: u32 = 64;
pub const BLOCK_SETS: usize = 4;

// fw_sets
pub const MAX_SETS: u32 = 255; // ids 1..255; 0xfff0 holds the bogon prefixes
pub const SET_BOGON: u32 = 0xfff0;
const MAX_SET_ELEMENTS: usize = 4096; // static elements of one set
const SET_STATIC_CAPACITY: usize = 32768;
pub const SET_KIND_STATIC: u32 = 1; // from the sets resource
pub const SET_KIND_API: u32 = 2; // added with the set_add action
pub const SET_KIND_POLICY: u32 = 3; // added by a policy's add_to_set

pub const BOGONS_RESERVED: [&str; 13] = [
    "0.0.0.0/8", "127.0.0.0/8", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
    "::/128", "::1/128", "100::/64", "2001:db8::/32", "ff00::/8",
];
pub const BOGONS_PRIVATE: [&str; 6] = ["10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];
const MAX_SYN_PER_WINDOW: i64 = 1_000_000;
const MAX_LIMIT_WINDOW_SECONDS: i64 = 3600;
const MAX_BAN_SECONDS: i64 = 7 * 86400;
const DEFAULT_LIMIT_IPV6_PREFIX: i64 = 64;

// fw_lstats: per policy slot; slot 0 counts the drop log.
pub const LCOUNTERS: u32 = 4;
pub const LCNT_BAN: u32 = 0;
pub const LCNT_RATE: u32 = 1;
pub const LCNT_LOGGED: u32 = 2;
pub const LCNT_LOST: u32 = 3;

// fw_gstats
pub const GCOUNTERS: [&str; 13] =
    ["established", "related", "essential", "blocklist", "bogon", "urpf", "tcp_flags", "fragment", "ct_new", "ct_full", "ct_short", "set_add", "set_full"];

pub const EVENT_BYTES: usize = 56;

pub fn pext_value_zero() -> String {
    "00".repeat(40)
}

pub fn gcfg_value_zero() -> String {
    "00".repeat(16)
}

pub fn limit_value_zero() -> String {
    "00".repeat(32)
}

fn reason_name(code: u64) -> &'static str {
    match code {
        1 => "acl",
        2 => "ban",
        3 => "rate",
        4 => "evasive",
        5 => "blocklist",
        6 => "bogon",
        7 => "urpf",
        8 => "tcp_flags",
        9 => "fragment",
        _ => "unknown",
    }
}

fn icmp_type(name: &str, v6: bool) -> Option<u32> {
    if v6 {
        match name {
            "destination-unreachable" => Some(1),
            "packet-too-big" => Some(2),
            "time-exceeded" => Some(3),
            "parameter-problem" => Some(4),
            "echo-request" => Some(128),
            "echo-reply" => Some(129),
            "router-solicitation" => Some(133),
            "router-advertisement" => Some(134),
            "neighbor-solicitation" => Some(135),
            "neighbor-advertisement" => Some(136),
            _ => None,
        }
    } else {
        match name {
            "echo-reply" => Some(0),
            "destination-unreachable" => Some(3),
            "redirect" => Some(5),
            "echo-request" => Some(8),
            "router-advertisement" => Some(9),
            "router-solicitation" => Some(10),
            "time-exceeded" => Some(11),
            "parameter-problem" => Some(12),
            "timestamp-request" => Some(13),
            "timestamp-reply" => Some(14),
            _ => None,
        }
    }
}

fn ip_protocol_number(name: &str) -> Option<u32> {
    match name {
        "igmp" => Some(2),
        "ipip" => Some(4),
        "ipv6" => Some(41),
        "gre" => Some(47),
        "esp" => Some(50),
        "ah" => Some(51),
        "ospf" => Some(89),
        "pim" => Some(103),
        "vrrp" => Some(112),
        "l2tp" => Some(115),
        "sctp" => Some(132),
        _ => None,
    }
}

// ---------------------------------------------------------------- hex helpers

pub fn hex_byte(value: u64) -> String {
    format!("{:02x}", value & 0xff)
}

pub fn u8h(value: u64) -> String {
    hex_byte(value)
}

pub fn u16le(value: u64) -> String {
    hex_byte(value) + &hex_byte(value >> 8)
}

pub fn u16be(value: u64) -> String {
    hex_byte(value >> 8) + &hex_byte(value)
}

pub fn u32le(value: u64) -> String {
    hex_byte(value) + &hex_byte(value >> 8) + &hex_byte(value >> 16) + &hex_byte(value >> 24)
}

pub fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// --------------------------------------------------------------- addresses

fn digits(text: &str, min: usize, max: usize) -> bool {
    !text.is_empty() && text.len() >= min && text.len() <= max && text.bytes().all(|b| b.is_ascii_digit())
}

fn parse_ipv4(text: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(4);
    for part in parts {
        // ^(0|[1-9][0-9]{0,2})$
        if !(part == "0" || (digits(part, 1, 3) && !part.starts_with('0'))) {
            return None;
        }
        let n: u32 = part.parse().ok()?;
        if n > 255 {
            return None;
        }
        out.push(n as u8);
    }
    Some(out)
}

fn parse_hex_groups(part: &str) -> Option<Vec<u32>> {
    if part.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for group in part.split(':') {
        if group.is_empty() || group.len() > 4 || !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u32::from_str_radix(group, 16).ok()?);
    }
    Some(out)
}

fn parse_ipv6(text: &str) -> Option<Vec<u8>> {
    if !text.contains(':') {
        return None;
    }
    let mut text = text.to_string();
    let mut tail: Vec<u32> = Vec::new();
    let last_colon = text.rfind(':')?;
    if text[last_colon + 1..].contains('.') {
        // An embedded IPv4 address supplies the last two groups.
        let v4 = parse_ipv4(&text[last_colon + 1..])?;
        tail = vec![((v4[0] as u32) << 8) | v4[1] as u32, ((v4[2] as u32) << 8) | v4[3] as u32];
        let before = text[..last_colon + 1].to_string();
        text = if before.ends_with("::") { before } else { text[..last_colon].to_string() };
    }
    let halves: Vec<&str> = text.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let head = parse_hex_groups(halves[0])?;
    let rest = if halves.len() == 2 { parse_hex_groups(halves[1])? } else { Vec::new() };
    let total = head.len() + rest.len() + tail.len();
    let mut groups = head;
    if halves.len() == 2 {
        if total > 7 {
            return None;
        }
        groups.extend(std::iter::repeat(0).take(8 - total));
    } else if total != 8 {
        return None;
    }
    groups.extend(rest);
    groups.extend(tail);
    let mut bytes = Vec::with_capacity(16);
    for group in groups.iter().take(8) {
        bytes.push((group >> 8) as u8);
        bytes.push((group & 0xff) as u8);
    }
    if bytes.len() != 16 {
        return None;
    }
    Some(bytes)
}

pub fn format_address(family: u8, bytes: &[u8]) -> String {
    if family == 4 {
        return bytes.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".");
    }
    let groups: Vec<String> = (0..16).step_by(2).map(|i| format!("{:x}", ((bytes[i] as u32) << 8) | bytes[i + 1] as u32)).collect();
    // Compress the longest run of zero groups (RFC 5952).
    let (mut best, mut best_len) = (-1i32, 0usize);
    let mut start = 0usize;
    while start < 8 {
        if groups[start] != "0" {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < 8 && groups[end] == "0" {
            end += 1;
        }
        if end - start > best_len && end - start > 1 {
            best = start as i32;
            best_len = end - start;
        }
        start = end;
    }
    if best < 0 {
        return groups.join(":");
    }
    let best = best as usize;
    format!("{}::{}", groups[..best].join(":"), groups[best + best_len..].join(":"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub family: u8,
    pub bytes: Vec<u8>,
    pub prefix: u32,
    pub text: String,
}

/// Parses "addr" or "addr/len" into a Cidr. Host bits are cleared and text
/// is the normalized form. IPv4-mapped IPv6 prefixes (::ffff:a.b.c.d/96 and
/// longer) become IPv4: the filter sees IPv4 packets.
pub fn parse_cidr(raw: &Value) -> Result<Cidr> {
    let Some(raw_text) = raw.as_str() else {
        bail!("地址必须是字符串");
    };
    parse_cidr_str(raw_text)
}

pub fn parse_cidr_str(raw: &str) -> Result<Cidr> {
    let text = raw.trim();
    if text.is_empty() || text.encode_utf16().count() > 64 {
        bail!("地址无效: {raw}");
    }
    let (addr, prefix_text) = match text.find('/') {
        Some(slash) => (&text[..slash], Some(&text[slash + 1..])),
        None => (text, None),
    };
    let (mut family, mut bytes) = match parse_ipv4(addr) {
        Some(bytes) => (4u8, bytes),
        None => match parse_ipv6(addr) {
            Some(bytes) => (6u8, bytes),
            None => bail!("地址无效: {raw}"),
        },
    };
    let max = if family == 4 { 32 } else { 128 };
    let mut prefix = max;
    if let Some(prefix_text) = prefix_text {
        if !digits(prefix_text, 1, 3) {
            bail!("前缀长度无效: {raw}");
        }
        prefix = prefix_text.parse::<u32>().unwrap_or(999);
        if prefix > max {
            bail!("前缀长度无效: {raw}");
        }
    }
    if family == 6 && prefix >= 96 {
        let mapped = bytes[..10].iter().all(|b| *b == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
        if mapped {
            family = 4;
            bytes = bytes[12..].to_vec();
            prefix -= 96;
        }
    }
    for (index, byte) in bytes.iter_mut().enumerate() {
        let keep = (prefix as i64 - index as i64 * 8).clamp(0, 8) as u32;
        *byte &= if keep == 0 { 0 } else { (0xffu32 << (8 - keep)) as u8 };
    }
    let text = format!("{}/{}", format_address(family, &bytes), prefix);
    Ok(Cidr { family, bytes, prefix, text })
}

pub fn cidr_overlap(a: &Cidr, b: &Cidr) -> bool {
    if a.family != b.family {
        return false;
    }
    let mut bits = a.prefix.min(b.prefix) as i64;
    let mut i = 0usize;
    while i < a.bytes.len() && bits > 0 {
        let mask: u8 = if bits >= 8 { 0xff } else { (0xffu32 << (8 - bits)) as u8 };
        if (a.bytes[i] & mask) != (b.bytes[i] & mask) {
            return false;
        }
        i += 1;
        bits -= 8;
    }
    true
}

// ------------------------------------------------------------------ policies

pub type Ranges = Vec<(u32, u32)>;

fn merge_ranges(mut ranges: Ranges) -> Ranges {
    ranges.sort_by_key(|range| range.0);
    let mut merged: Ranges = Vec::new();
    for (a, b) in ranges {
        match merged.last_mut() {
            Some(last) if a <= last.1 + 1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    merged
}

pub fn parse_port_ranges(list: &Value, label: &str) -> Result<Ranges> {
    let items = match list {
        Value::Array(items) if !items.is_empty() => items,
        _ => bail!("{label}: 至少需要一个端口"),
    };
    if items.len() > MAX_PORT_RANGES {
        bail!("{label}: 端口区间最多 {MAX_PORT_RANGES} 个");
    }
    let mut ranges = Vec::new();
    for item in items {
        let raw = js::string(item);
        let text = raw.trim();
        let (a, b) = match text.find('-') {
            None => (text, None),
            Some(dash) => (text[..dash].trim_end(), Some(text[dash + 1..].trim_start())),
        };
        let valid = digits(a, 1, 5) && b.map(|b| digits(b, 1, 5)).unwrap_or(true) && !a.ends_with(char::is_whitespace);
        if !valid {
            bail!("{label}: 端口无效: {raw}");
        }
        let a: u32 = a.parse().unwrap_or(0);
        let b: u32 = b.map(|b| b.parse().unwrap_or(0)).unwrap_or(a);
        if a < 1 || b > 65535 || a > b {
            bail!("{label}: 端口无效: {raw}");
        }
        ranges.push((a, b));
    }
    Ok(merge_ranges(ranges))
}

fn parse_action(value: &Value, label: &str) -> Result<u8> {
    match value.as_str() {
        Some("allow") => Ok(ACTION_PASS),
        Some("drop") => Ok(ACTION_DROP),
        _ => bail!("{label}: 动作必须是 allow 或 drop"),
    }
}

/// `intIn`: an integer in [min, max], or an error naming the field.
fn int_in(value: &Value, min: i64, max: i64, label: &str) -> Result<i64> {
    let number = js::number(value);
    let empty = value.is_null() || value.as_str() == Some("");
    if empty || !number.is_finite() || number.floor() != number || number < min as f64 || number > max as f64 {
        bail!("{label} 必须是 {min} 到 {max} 之间的整数");
    }
    Ok(number as i64)
}

fn present(value: &Value, key: &str) -> Option<Value> {
    value.as_object().and_then(|map| map.get(key)).cloned()
}

#[derive(Clone, Debug, PartialEq)]
pub struct SynLimit {
    pub max_new: i64,
    pub window_seconds: i64,
    pub ban_seconds: i64,
    pub ipv6_prefix: i64,
}

/// {max_new, window_seconds, ban_seconds, ipv6_prefix}: at most max_new new
/// TCP connections (SYNs) per window from one source prefix; over that, SYNs
/// are dropped and, with ban_seconds, the prefix is banned from the policy.
fn parse_syn_limit(value: Option<Value>, protocols: &[u8], label: &str) -> Result<Option<SynLimit>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(value) => value,
    };
    if !value.is_object() {
        bail!("{label}: syn_limit 必须是对象");
    }
    if !protocols.contains(&PROTO_TCP) {
        bail!("{label}: syn_limit 只限制 TCP 新连接，协议需要包含 tcp");
    }
    Ok(Some(SynLimit {
        max_new: int_in(g(&value, "max_new"), 1, MAX_SYN_PER_WINDOW, &format!("{label}: syn_limit.max_new"))?,
        window_seconds: int_in(g(&value, "window_seconds"), 1, MAX_LIMIT_WINDOW_SECONDS, &format!("{label}: syn_limit.window_seconds"))?,
        ban_seconds: match present(&value, "ban_seconds") {
            None => 0,
            Some(v) => int_in(&v, 0, MAX_BAN_SECONDS, &format!("{label}: syn_limit.ban_seconds"))?,
        },
        ipv6_prefix: match present(&value, "ipv6_prefix") {
            None => DEFAULT_LIMIT_IPV6_PREFIX,
            Some(v) => int_in(&v, 32, 128, &format!("{label}: syn_limit.ipv6_prefix"))?,
        },
    }))
}

/// The first `prefix` bits of 16 bytes set, as hex.
pub fn prefix_mask_hex(prefix: i64) -> String {
    (0..16)
        .map(|i| {
            let bits = (prefix - i * 8).clamp(0, 8) as u32;
            hex_byte(((0xffu32 << (8 - bits)) & 0xff) as u64)
        })
        .collect()
}

/// ICMP types as ranges over type << 8 | code: "8" or a name is every code
/// of the type, "3/4" one code. No list is every type.
pub fn parse_icmp_types(list: &Value, v6: bool, label: &str) -> Result<Ranges> {
    let items = match list {
        Value::Null => return Ok(vec![(0, 65535)]),
        Value::Array(items) if items.is_empty() => return Ok(vec![(0, 65535)]),
        Value::Array(items) => items,
        _ => bail!("{label}: icmp_types 必须是数组"),
    };
    if items.len() > MAX_PORT_RANGES {
        bail!("{label}: ICMP 类型最多 {MAX_PORT_RANGES} 个");
    }
    let mut ranges = Vec::new();
    for item in items {
        let raw = js::string(item);
        let text = raw.trim().to_lowercase();
        let (name, code) = match text.find('/') {
            Some(slash) => (&text[..slash], Some(&text[slash + 1..])),
            None => (text.as_str(), None),
        };
        let name_ok = !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !name_ok || code.map(|code| !digits(code, 1, 3)).unwrap_or(false) {
            bail!("{label}: ICMP 类型无效: {raw}");
        }
        let kind = if digits(name, 1, 3) { name.parse::<u32>().ok() } else { icmp_type(name, v6) };
        let Some(kind) = kind.filter(|kind| *kind <= 255) else {
            bail!("{label}: ICMP 类型无效: {raw}");
        };
        match code {
            None => ranges.push((kind * 256, kind * 256 + 255)),
            Some(code) => {
                let code: u32 = code.parse().unwrap_or(999);
                if code > 255 {
                    bail!("{label}: ICMP 代码无效: {raw}");
                }
                ranges.push((kind * 256 + code, kind * 256 + code));
            }
        }
    }
    Ok(merge_ranges(ranges))
}

/// IP protocol numbers as ranges over protocol << 8.
pub fn parse_ip_protocols(list: &Value, label: &str) -> Result<Ranges> {
    let items = match list {
        Value::Array(items) if !items.is_empty() => items,
        _ => bail!("{label}: ip 策略至少需要一个协议号（ip_protocols）"),
    };
    if items.len() > MAX_PORT_RANGES {
        bail!("{label}: 协议号最多 {MAX_PORT_RANGES} 个");
    }
    let mut ranges = Vec::new();
    for item in items {
        let raw = js::string(item);
        let text = raw.trim().to_lowercase();
        let number = if digits(&text, 1, 3) { text.parse::<u32>().ok() } else { ip_protocol_number(&text) };
        let Some(number) = number.filter(|n| *n <= 255) else {
            bail!("{label}: 协议号无效: {raw}");
        };
        if matches!(number, 1 | 6 | 17 | 58) {
            bail!("{label}: 协议 {number} 请用 icmp、tcp、udp 或 icmpv6 策略");
        }
        ranges.push((number * 256, number * 256 + 255));
    }
    Ok(merge_ranges(ranges))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Source {
    pub cidr: Cidr,
    pub action: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SourceSet {
    pub set: String,
    pub action: u8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddToSet {
    pub set: String,
    pub seconds: i64,
    pub ipv6_prefix: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    pub key: String,
    pub name: String,
    pub protocols: Vec<u8>,
    pub ranges: Ranges,
    /// Every fw_ports proto the policy covers, with its ranges.
    pub matches: BTreeMap<u8, Ranges>,
    pub any: bool,
    pub destinations: Vec<Cidr>,
    pub default_action: u8,
    pub sources: Vec<Source>,
    pub source_sets: Vec<SourceSet>,
    pub syn_limit: Option<SynLimit>,
    pub new_only: bool,
    pub add_to_set: Option<AddToSet>,
    pub slot: u32,
}

pub fn set_name_valid(name: &str) -> bool {
    // ^[a-z0-9][a-z0-9_-]{0,47}$
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 48
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

fn ranges_value_list(value: &Value) -> bool {
    value.is_array() && !value.as_array().unwrap().is_empty()
}

/// Validates one policy record and returns its normalized form. `sets`, when
/// given, lists the set keys sources and add_to_set may name.
pub fn normalize_policy(key: &str, data: &Value, sets: Option<&[String]>) -> Result<Policy> {
    if !data.is_object() {
        bail!("策略 {key}: 内容必须是对象");
    }
    let label = format!("策略 {}", if truthy(g(data, "name")) { js::string(g(data, "name")) } else { key.to_string() });
    let protocol = if truthy(g(data, "protocol")) { js::string(g(data, "protocol")) } else { "tcp".to_string() };
    let mut protocols = Vec::new();
    let mut matches = BTreeMap::new();
    let mut any = false;
    let has_ports = ranges_value_list(g(data, "ports"));
    let mut ranges = Vec::new();
    match protocol.as_str() {
        "tcp" | "udp" | "tcp+udp" => {
            protocols = match protocol.as_str() {
                "tcp" => vec![PROTO_TCP],
                "udp" => vec![PROTO_UDP],
                _ => vec![PROTO_TCP, PROTO_UDP],
            };
            ranges = parse_port_ranges(g(data, "ports"), &label)?;
            for proto in &protocols {
                matches.insert(*proto, ranges.clone());
            }
            if truthy(g(data, "icmp_types")) || truthy(g(data, "ip_protocols")) {
                bail!("{label}: tcp/udp 策略不能带 icmp_types 或 ip_protocols");
            }
        }
        "icmp" | "icmpv6" => {
            if has_ports || truthy(g(data, "ip_protocols")) {
                bail!("{label}: ICMP 策略按类型匹配，不能带端口或 ip_protocols");
            }
            let proto = if protocol == "icmp" { PROTO_ICMP } else { PROTO_ICMPV6 };
            protocols = vec![proto];
            matches.insert(proto, parse_icmp_types(g(data, "icmp_types"), protocol == "icmpv6", &label)?);
        }
        "ip" => {
            if has_ports || truthy(g(data, "icmp_types")) {
                bail!("{label}: ip 策略按协议号匹配，不能带端口或 icmp_types");
            }
            protocols = vec![PROTO_IP];
            matches.insert(PROTO_IP, parse_ip_protocols(g(data, "ip_protocols"), &label)?);
        }
        "any" => {
            if has_ports || truthy(g(data, "icmp_types")) || truthy(g(data, "ip_protocols")) {
                bail!("{label}: 全部流量策略不能带端口、icmp_types 或 ip_protocols");
            }
            any = true;
        }
        _ => bail!("{label}: 协议必须是 tcp、udp、tcp+udp、icmp、icmpv6、ip 或 any"),
    }
    let tcp = any || protocols.contains(&PROTO_TCP);
    let mut destinations = Vec::new();
    for raw in js::array(js::or(g(data, "destinations"), &json!([]))) {
        destinations.push(parse_cidr(&raw)?);
    }
    if destinations.len() > MAX_DESTINATIONS {
        bail!("{label}: 目标地址最多 {MAX_DESTINATIONS} 个");
    }
    // A missing name reads "undefined", as the script's message did.
    let known_set = |name: Option<Value>, what: &str| -> Result<String> {
        let Some(text) = name.as_ref().and_then(Value::as_str).filter(|text| set_name_valid(text)) else {
            let shown = name.as_ref().map(js::string).unwrap_or_else(|| "undefined".to_string());
            bail!("{label}: {what}的集合名无效: {shown}");
        };
        if let Some(sets) = sets {
            if !sets.iter().any(|set| set == text) {
                bail!("{label}: {what}引用的集合不存在: {text}");
            }
        }
        Ok(text.to_string())
    };
    let mut sources = Vec::new();
    let mut source_sets = Vec::new();
    for entry in js::array(js::or(g(data, "sources"), &json!([]))) {
        if !entry.is_object() {
            bail!("{label}: 来源条目必须是 {{cidr, action}} 或 {{set, action}}");
        }
        if let Some(set) = present(&entry, "set") {
            if present(&entry, "cidr").is_some() {
                bail!("{label}: 来源条目只能写 cidr 或 set 之一");
            }
            source_sets.push(SourceSet { set: known_set(Some(set), "来源")?, action: parse_action(g(&entry, "action"), &label)? });
        } else {
            sources.push(Source { cidr: parse_cidr(g(&entry, "cidr"))?, action: parse_action(g(&entry, "action"), &label)? });
        }
    }
    if sources.len() > MAX_SOURCES {
        bail!("{label}: 来源最多 {MAX_SOURCES} 个");
    }
    if source_sets.len() > PX_SETS {
        bail!("{label}: 来源集合最多 {PX_SETS} 个");
    }
    let mut seen = HashSet::new();
    for source in &sources {
        if !seen.insert(source.cidr.text.clone()) {
            bail!("{label}: 来源重复: {}", source.cidr.text);
        }
    }
    for source in &source_sets {
        if !seen.insert(format!("set:{}", source.set)) {
            bail!("{label}: 来源集合重复: {}", source.set);
        }
    }
    if let Some(value) = present(data, "tcp_new_only") {
        if !value.is_boolean() {
            bail!("{label}: tcp_new_only 必须是布尔值");
        }
    }
    let new_only = js::is_true(g(data, "tcp_new_only"));
    if new_only && !tcp {
        bail!("{label}: tcp_new_only 只作用于 TCP，协议需要包含 tcp");
    }
    let add_to_set = match present(data, "add_to_set") {
        None | Some(Value::Null) => None,
        Some(add) => {
            if !add.is_object() {
                bail!("{label}: add_to_set 必须是对象");
            }
            Some(AddToSet {
                set: known_set(present(&add, "set"), "写入")?,
                seconds: match g(&add, "timeout_seconds") {
                    Value::Null => 3600,
                    v => int_in(v, 0, MAX_ADD_SECONDS, &format!("{label}: add_to_set.timeout_seconds"))?,
                },
                ipv6_prefix: match g(&add, "ipv6_prefix") {
                    Value::Null => DEFAULT_LIMIT_IPV6_PREFIX,
                    v => int_in(v, 32, 128, &format!("{label}: add_to_set.ipv6_prefix"))?,
                },
            })
        }
    };
    let default_action = parse_action(js::or(g(data, "default_action"), &json!("drop")), &label)?;
    let syn_protocols = if tcp { vec![PROTO_TCP] } else { protocols.clone() };
    Ok(Policy {
        key: key.to_string(),
        name: if truthy(g(data, "name")) { js::string(g(data, "name")) } else { key.to_string() },
        syn_limit: parse_syn_limit(present(data, "syn_limit"), &syn_protocols, &label)?,
        protocols,
        ranges,
        matches,
        any,
        destinations,
        default_action,
        sources,
        source_sets,
        new_only,
        add_to_set,
        slot: 0,
    })
}

fn ranges_intersect(a: &Ranges, b: &Ranges) -> Option<u32> {
    for x in a {
        for y in b {
            if x.0 <= y.1 && y.0 <= x.1 {
                return Some(x.0.max(y.0));
            }
        }
    }
    None
}

fn match_text(proto: u8, value: u32) -> String {
    let name = PROTO_NAMES[proto as usize];
    match proto {
        PROTO_TCP | PROTO_UDP => format!("{name} 端口 {value}"),
        PROTO_IP => format!("IP 协议 {}", value >> 8),
        _ => format!("{name} 类型 {}/{}", value >> 8, value & 255),
    }
}

fn destinations_overlap(a: &Policy, b: &Policy) -> bool {
    if a.destinations.is_empty() || b.destinations.is_empty() {
        return true;
    }
    a.destinations.iter().any(|x| b.destinations.iter().any(|y| cidr_overlap(x, y)))
}

/// Two policies conflict when they match the same protocol and port (ICMP
/// type, IP protocol) and either names no destinations or their
/// destinations overlap. Two catch-all policies conflict the same way.
pub fn find_conflicts(policies: &[Policy]) -> Vec<String> {
    let mut errors = Vec::new();
    for i in 0..policies.len() {
        for j in i + 1..policies.len() {
            let (a, b) = (&policies[i], &policies[j]);
            if a.any || b.any {
                if a.any && b.any && destinations_overlap(a, b) {
                    errors.push(format!("策略 {} 和 {} 都是全部流量策略，作用于相同的目标地址", a.name, b.name));
                }
                continue;
            }
            for proto in 0..PROTO_NAMES.len() as u8 {
                let (Some(x), Some(y)) = (a.matches.get(&proto), b.matches.get(&proto)) else {
                    continue;
                };
                let Some(hit) = ranges_intersect(x, y) else {
                    continue;
                };
                if !destinations_overlap(a, b) {
                    continue;
                }
                errors.push(format!("策略 {} 和 {} 在 {} 上作用于相同的目标地址", a.name, b.name, match_text(proto, hit)));
                break;
            }
        }
    }
    errors
}

// ----------------------------------------------------------------- warnings

// Ports whose loss locks an administrator out. Veer's own port is whatever
// web_port says, which a plugin cannot read; 8080 is its default.
const MANAGEMENT_PORTS: [(u32, &str); 3] = [(22, "SSH"), (8006, "Proxmox VE"), (8080, "Veer 默认管理端口")];
// Replies to outbound connections arrive on these ports: Veer's egress NAT
// pool once the host's ephemeral ports are taken out of it, and Linux's
// default ip_local_port_range. The plugin cannot read the actual values.
const NAT_REPLY_PORTS: (u32, u32) = (20000, 32767);
const EPHEMERAL_REPLY_PORTS: (u32, u32) = (32768, 60999);

fn port_text(range: (u32, u32)) -> String {
    if range.0 == range.1 {
        range.0.to_string()
    } else {
        format!("{}-{}", range.0, range.1)
    }
}

/// The first part of ranges inside window; single ports skipped when ranges_only.
fn overlap_with(ranges: &Ranges, window: (u32, u32), ranges_only: bool) -> Option<(u32, u32)> {
    for range in ranges {
        if ranges_only && range.0 == range.1 {
            continue;
        }
        let lo = range.0.max(window.0);
        let hi = range.1.min(window.1);
        if lo <= hi {
            return Some((lo, hi));
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq)]
pub struct Warning {
    pub id: String,
    pub policy: Option<String>,
    pub message: String,
}

impl Warning {
    pub fn to_value(&self) -> Value {
        json!({"id": self.id, "policy": self.policy, "message": self.message})
    }
}

/// Rule sets that are valid but likely to cut off more than intended. Only
/// policies that drop unlisted sources can: one deciding a management port
/// with no trusted source (a port policy covering it, else a catch-all
/// policy), or one covering ports that replies to outbound connections use.
/// Without connection tracking a reply is just another packet from an
/// unlisted source; with it, TCP replies and those of UDP flows from
/// unprotected ports pass, and tcp_new_only lets every TCP reply through
/// even without it. A single port in the ephemeral range is left alone: a
/// local listener keeps the kernel from picking it.
pub fn find_warnings(policies: &[Policy], trusted: &[Cidr], ct: bool) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let tcp_port = |policy: &Policy, port: u32| policy.matches.get(&PROTO_TCP).map(|ranges| ranges.iter().any(|r| r.0 <= port && port <= r.1)).unwrap_or(false);
    for p in policies {
        if p.default_action != ACTION_DROP {
            continue;
        }
        let label = format!("策略 {}", p.name);
        if trusted.is_empty() && (p.any || p.matches.contains_key(&PROTO_TCP)) {
            let hit: Vec<&(u32, &str)> = MANAGEMENT_PORTS
                .iter()
                .filter(|(port, _)| if !p.any { tcp_port(p, *port) } else { !policies.iter().any(|other| !other.any && tcp_port(other, *port)) })
                .collect();
            if !hit.is_empty() {
                let ports = hit.iter().map(|(port, name)| format!("{port}（{name}）")).collect::<Vec<_>>().join("、");
                let new_only = if p.new_only { "它只判新连接，已经连着的会话不受影响，所以确认能成功，断开后才连不上。" } else { "" };
                warnings.push(Warning {
                    id: format!("lockout:{}", p.key),
                    policy: Some(p.key.clone()),
                    message: format!("{label} 默认丢弃 tcp {ports}，且没有信任来源：只有放行的来源还能连上。{new_only}"),
                });
            }
        }
        if p.any {
            if ct {
                continue;
            }
            warnings.push(Warning {
                id: format!("reply_all:{}", p.key),
                policy: Some(p.key.clone()),
                message: format!(
                    "{label} 是默认丢弃的全部流量策略，但没开连接跟踪：本机和经 Veer 出站的连接，回包都按来源判断，对端不在放行列表里时被丢弃。开启连接跟踪后回包自动放行。"
                ),
            });
            continue;
        }
        // Connection tracking only records UDP flows from ports no UDP
        // policy covers (a reply leaving a protected port must not open it),
        // so it never rescues a UDP policy over reply ports.
        let mut reply_ranges = Vec::new();
        if let Some(tcp) = p.matches.get(&PROTO_TCP) {
            if !p.new_only && !ct {
                reply_ranges.extend(tcp.iter().copied());
            }
        }
        if let Some(udp) = p.matches.get(&PROTO_UDP) {
            reply_ranges.extend(udp.iter().copied());
        }
        let nat = overlap_with(&reply_ranges, NAT_REPLY_PORTS, false);
        let ephemeral = overlap_with(&reply_ranges, EPHEMERAL_REPLY_PORTS, true);
        if nat.is_some() || ephemeral.is_some() {
            let mut parts = Vec::new();
            if let Some(nat) = nat {
                parts.push(format!("{} 在 Veer 出向 NAT 的端口池（默认 20000-32767）内", port_text(nat)));
            }
            if let Some(ephemeral) = ephemeral {
                parts.push(format!("{} 在宿主出站连接的临时端口（默认 32768-60999）内", port_text(ephemeral)));
            }
            let tail = if ct {
                "：连接跟踪不记录从受 UDP 策略保护的端口发出的 UDP 流，这些端口上出站 UDP 的回包仍按来源判断，对端不在放行列表里时被丢弃。把 UDP 策略限定在服务端口上可以避免。"
            } else {
                "：没开连接跟踪，出站连接的回包也会按来源判断，对端不在放行列表里时回包被丢弃，连接失败。开启连接跟踪，或者 TCP 策略打开“只判新连接”，可以避免。"
            };
            warnings.push(Warning {
                id: format!("reply_ports:{}", p.key),
                policy: Some(p.key.clone()),
                message: format!("{label} 的端口 {}{tail}", parts.join("，")),
            });
        }
    }
    warnings
}

/// Fingerprint of a warning list (FNV-1a); "" when there is none.
pub fn warnings_token(warnings: &[Warning]) -> String {
    if warnings.is_empty() {
        return String::new();
    }
    let mut lines: Vec<String> = warnings.iter().map(|w| format!("{}\n{}", w.id, w.message)).collect();
    lines.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    format!("{:08x}", js::fnv1a(&lines.join("\n\n")))
}

pub struct Assigned {
    pub ids: BTreeMap<String, u32>,
    pub fresh: Vec<u32>,
}

/// Keeps ids stable across applies so counters follow their owner. `held`
/// maps keys to the ids they had; returns the updated map and the ids
/// assigned now.
pub fn assign_stable(keys: &[String], held: &BTreeMap<String, u32>, max: u32, full: &str) -> Result<Assigned> {
    let mut next = BTreeMap::new();
    let mut used = BTreeSet::new();
    for key in keys {
        if let Some(id) = held.get(key) {
            if *id >= 1 && *id <= max && !used.contains(id) {
                next.insert(key.clone(), *id);
                used.insert(*id);
            }
        }
    }
    // Prefer ids nothing held before, so a new owner does not inherit the
    // counters of a deleted one.
    let previously: BTreeSet<u32> = held.values().copied().collect();
    let mut fresh = Vec::new();
    for key in keys {
        if next.contains_key(key) {
            continue;
        }
        let id = (1..=max)
            .find(|id| !used.contains(id) && !previously.contains(id))
            .or_else(|| (1..=max).find(|id| !used.contains(id)));
        let Some(id) = id else {
            bail!("{full}");
        };
        next.insert(key.clone(), id);
        used.insert(id);
        fresh.push(id);
    }
    Ok(Assigned { ids: next, fresh })
}

pub fn assign_slots(keys: &[String], slots: &BTreeMap<String, u32>) -> Result<Assigned> {
    assign_stable(keys, slots, MAX_POLICY_SLOT, &format!("策略最多 {MAX_POLICY_SLOT} 条"))
}

pub fn assign_set_ids(keys: &[String], ids: &BTreeMap<String, u32>) -> Result<Assigned> {
    assign_stable(keys, ids, MAX_SETS, &format!("集合最多 {MAX_SETS} 个"))
}

// ---------------------------------------------------------------- compiling

/// [a, b] as aligned power-of-two blocks over the 16-bit port space.
pub fn port_prefixes(mut a: u32, b: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    while a <= b {
        let mut size = 1u32;
        while size < 65536 && a % (size * 2) == 0 && a + size * 2 - 1 <= b {
            size *= 2;
        }
        let bits = size.trailing_zeros();
        out.push((a, 16 - bits));
        a += size;
    }
    out
}

fn port_key(generation: u32, proto: u8, port: u32, prefix: u32) -> String {
    u32le(16 + prefix as u64) + &u8h(generation as u64) + &u8h(proto as u64) + &u16be(port as u64)
}

fn addr_key(generation: u32, id: u32, cidr: &Cidr) -> String {
    u32le(32 + cidr.prefix as u64) + &u8h(generation as u64) + "00" + &u16be(id as u64) + &bytes_hex(&cidr.bytes)
}

#[derive(Clone, Debug, Default)]
pub struct Baseline {
    pub bogon_sources: String,
    pub invalid_tcp_flags: bool,
    pub drop_fragments: bool,
    pub urpf: String,
}

#[derive(Clone, Debug, Default)]
pub struct Settings {
    pub interfaces: Vec<String>,
    pub trusted: Vec<Cidr>,
    pub confirm_seconds: i64,
    pub log_per_second: i64,
    pub connection_tracking: bool,
    pub blocklists: Vec<String>,
    pub baseline: Baseline,
}

pub struct LpmEntry {
    pub key: String,
    pub value: String,
}

pub const ARRAY_MAPS: [&str; 6] = ["fw_port_bits", "fw_class", "fw_policy", "fw_limit", "fw_pext", "fw_gcfg"];
pub const LPM_MAPS: [&str; 5] = ["fw_ports", "fw_dst4", "fw_dst6", "fw_src4", "fw_src6"];

pub struct Compiled {
    /// index -> value hex, only non-zero entries, per array map.
    pub arrays: BTreeMap<&'static str, BTreeMap<u32, String>>,
    pub lpm: BTreeMap<&'static str, Vec<LpmEntry>>,
    pub active: bool,
    pub summary: Value,
}

struct Class {
    id: u32,
    any_policy: u32,
    scoped: Vec<usize>,
}

/// Compiles normalized policies (each with a slot) and trusted source CIDRs
/// into the entries of one generation.
pub fn compile_generation(policies: &[Policy], trusted: &[Cidr], generation: u32, set_ids: &BTreeMap<String, u32>, settings: &Settings) -> Result<Compiled> {
    if generation != 0 && generation != 1 {
        bail!("generation must be 0 or 1");
    }
    if trusted.len() > MAX_TRUSTED {
        bail!("信任来源最多 {MAX_TRUSTED} 个");
    }
    let set_id = |name: &str| -> Result<u32> {
        match set_ids.get(name) {
            Some(id) if *id != 0 => Ok(*id),
            _ => bail!("集合不存在: {name}"),
        }
    };
    let mut words = vec![vec![(0u32, 0u32); PORT_WORDS as usize]; 2];
    let mut class_index: HashMap<String, usize> = HashMap::new();
    let mut classes: Vec<Class> = Vec::new();
    let mut lpm: BTreeMap<&'static str, Vec<LpmEntry>> = LPM_MAPS.iter().map(|name| (*name, Vec::new())).collect();
    let mut class_for = |id: String, covering: &[usize], classes: &mut Vec<Class>| -> Result<u32> {
        if let Some(index) = class_index.get(&id) {
            return Ok(classes[*index].id);
        }
        if classes.len() >= MAX_CLASSES {
            bail!("端口划分过细：端口类超过 {MAX_CLASSES} 个");
        }
        let mut class = Class { id: classes.len() as u32 + 1, any_policy: 0, scoped: Vec::new() };
        for &index in covering {
            if policies[index].destinations.is_empty() {
                class.any_policy = policies[index].slot;
            } else {
                class.scoped.push(index);
            }
        }
        let class_id = class.id;
        class_index.insert(id, classes.len());
        classes.push(class);
        Ok(class_id)
    };

    for proto in 0..PROTO_NAMES.len() as u8 {
        let members: Vec<usize> = (0..policies.len()).filter(|i| policies[*i].matches.contains_key(&proto)).collect();
        let mut cuts = BTreeSet::new();
        for &index in &members {
            for range in &policies[index].matches[&proto] {
                cuts.insert(range.0);
                cuts.insert(range.1 + 1);
            }
        }
        let bounds: Vec<u32> = cuts.into_iter().collect();
        for window in bounds.windows(2) {
            let (lo, hi) = (window[0], window[1] - 1);
            let covering: Vec<usize> = members.iter().copied().filter(|i| policies[*i].matches[&proto].iter().any(|r| r.0 <= lo && lo <= r.1)).collect();
            if covering.is_empty() {
                continue;
            }
            let mut slots: Vec<u32> = covering.iter().map(|i| policies[*i].slot).collect();
            slots.sort_unstable();
            let key = slots.iter().map(|slot| slot.to_string()).collect::<Vec<_>>().join(",");
            let class_id = class_for(key, &covering, &mut classes)?;
            for (port, prefix) in port_prefixes(lo, hi) {
                lpm.get_mut("fw_ports").unwrap().push(LpmEntry { key: port_key(generation, proto, port, prefix), value: u32le(class_id as u64) });
            }
            if proto > PROTO_UDP {
                continue;
            }
            for port in lo..=hi {
                let word = &mut words[proto as usize][(port >> 6) as usize];
                let bit = port & 63;
                if bit < 32 {
                    word.0 |= 1 << bit;
                } else {
                    word.1 |= 1 << (bit - 32);
                }
            }
        }
    }
    if lpm["fw_ports"].len() > PORT_PREFIX_CAPACITY {
        bail!("端口前缀超过容量 {PORT_PREFIX_CAPACITY}");
    }
    // The catch-all policies share one class: packets no other class takes.
    let catch_all: Vec<usize> = (0..policies.len()).filter(|i| policies[*i].any).collect();
    let any_class = if catch_all.is_empty() {
        0
    } else {
        // JavaScript sorted the slots as strings here.
        let mut slots: Vec<String> = catch_all.iter().map(|i| policies[*i].slot.to_string()).collect();
        slots.sort();
        class_for(format!("any:{}", slots.join(",")), &catch_all, &mut classes)?
    };

    let mut arrays: BTreeMap<&'static str, BTreeMap<u32, String>> = ARRAY_MAPS.iter().map(|name| (*name, BTreeMap::new())).collect();
    for (bp, proto_words) in words.iter().enumerate() {
        for (wi, pair) in proto_words.iter().enumerate() {
            if pair.0 != 0 || pair.1 != 0 {
                let index = generation * PORT_WORDS_PER_GEN + bp as u32 * PORT_WORDS + wi as u32;
                arrays.get_mut("fw_port_bits").unwrap().insert(index, u32le(pair.0 as u64) + &u32le(pair.1 as u64));
            }
        }
    }
    for class in &classes {
        arrays
            .get_mut("fw_class")
            .unwrap()
            .insert(generation * CLASSES_PER_GEN + class.id, u16le(class.any_policy as u64) + &u8h(if class.scoped.is_empty() { 0 } else { 1 }) + "00");
        for &index in &class.scoped {
            let policy = &policies[index];
            for cidr in &policy.destinations {
                let map = if cidr.family == 4 { "fw_dst4" } else { "fw_dst6" };
                lpm.get_mut(map).unwrap().push(LpmEntry { key: addr_key(generation, class.id, cidr), value: u32le(policy.slot as u64) });
            }
        }
    }
    let mut proto2 = false;
    for policy in policies {
        let index = generation * POLICIES_PER_GEN + policy.slot;
        if policy.matches.contains_key(&PROTO_ICMP) || policy.matches.contains_key(&PROTO_ICMPV6) || policy.matches.contains_key(&PROTO_IP) {
            proto2 = true;
        }
        let flags = POLICY_VALID | if policy.syn_limit.is_some() { POLICY_LIMIT } else { 0 };
        arrays.get_mut("fw_policy").unwrap().insert(index, u8h(flags as u64) + &u8h(policy.default_action as u64) + "0000");
        if let Some(limit) = &policy.syn_limit {
            let value = u32le(limit.max_new as u64)
                + &u32le(limit.window_seconds as u64)
                + &u32le(limit.ban_seconds as u64)
                + &u8h(limit.ipv6_prefix as u64)
                + "000000"
                + &prefix_mask_hex(limit.ipv6_prefix);
            arrays.get_mut("fw_limit").unwrap().insert(index, value);
        }
        let ext = pext_hex(policy, &set_id)?;
        if ext != pext_value_zero() {
            arrays.get_mut("fw_pext").unwrap().insert(index, ext);
        }
        for source in &policy.sources {
            let map = if source.cidr.family == 4 { "fw_src4" } else { "fw_src6" };
            lpm.get_mut(map).unwrap().push(LpmEntry { key: addr_key(generation, policy.slot, &source.cidr), value: u8h(source.action as u64) + "000000" });
        }
    }
    for cidr in trusted {
        let map = if cidr.family == 4 { "fw_src4" } else { "fw_src6" };
        lpm.get_mut(map).unwrap().push(LpmEntry { key: addr_key(generation, 0, cidr), value: u8h(ACTION_PASS as u64) + "000000" });
    }
    for name in ["fw_dst4", "fw_dst6"] {
        if lpm[name].len() > DST_CAPACITY {
            bail!("目标地址条目超过容量 {DST_CAPACITY}");
        }
    }
    for name in ["fw_src4", "fw_src6"] {
        if lpm[name].len() > SRC_CAPACITY {
            bail!("来源条目超过容量 {SRC_CAPACITY}");
        }
    }

    let baseline = &settings.baseline;
    let gflags = (if settings.connection_tracking { G_CT } else { 0 })
        | (if !baseline.bogon_sources.is_empty() && baseline.bogon_sources != "off" { G_BOGON } else { 0 })
        | (if baseline.invalid_tcp_flags { G_BAD_FLAGS } else { 0 })
        | (if baseline.drop_fragments { G_DROP_FRAGS } else { 0 })
        | (if baseline.urpf == "loose" { G_URPF_LOOSE } else { 0 })
        | (if baseline.urpf == "strict" { G_URPF_STRICT } else { 0 })
        | (if proto2 { G_PROTO } else { 0 });
    let blocks = settings.blocklists.iter().map(|name| set_id(name)).collect::<Result<Vec<u32>>>()?;
    if blocks.len() > BLOCK_SETS {
        bail!("黑名单集合最多 {BLOCK_SETS} 个");
    }
    let mut gcfg = u32le(gflags as u64) + &u16le(any_class as u64) + &u8h(blocks.len() as u64) + "00";
    for b in 0..BLOCK_SETS {
        gcfg += &u16le(blocks.get(b).copied().unwrap_or(0) as u64);
    }
    if gcfg != gcfg_value_zero() {
        arrays.get_mut("fw_gcfg").unwrap().insert(generation, gcfg);
    }
    let summary = json!({
        "policies": policies.len(),
        "classes": classes.len(),
        "port_prefixes": lpm["fw_ports"].len(),
        "destinations": lpm["fw_dst4"].len() + lpm["fw_dst6"].len(),
        "sources": lpm["fw_src4"].len() + lpm["fw_src6"].len(),
        "syn_limited": policies.iter().filter(|p| p.syn_limit.is_some()).count(),
        "catch_all": catch_all.len(),
        "blocklists": blocks.len(),
    });
    Ok(Compiled { arrays, lpm, active: !policies.is_empty(), summary })
}

/// fw_pext of a policy: struct fw_pext in firewall.bpf.c (40 bytes).
pub fn pext_hex(policy: &Policy, set_id: &dyn Fn(&str) -> Result<u32>) -> Result<String> {
    let flags = (if policy.new_only { PX_NEW_ONLY } else { 0 }) | (if policy.add_to_set.is_some() { PX_ADD_SET } else { 0 });
    let add = policy.add_to_set.as_ref();
    let mut hex = u8h(flags as u64)
        + &u8h(policy.source_sets.len() as u64)
        + &u16le(match add {
            Some(add) => set_id(&add.set)? as u64,
            None => 0,
        })
        + &u32le(add.map(|add| add.seconds as u64).unwrap_or(0));
    for i in 0..PX_SETS {
        hex += &u16le(match policy.source_sets.get(i) {
            Some(source) => set_id(&source.set)? as u64,
            None => 0,
        });
    }
    for i in 0..PX_SETS {
        hex += &u8h(policy.source_sets.get(i).map(|source| source.action as u64).unwrap_or(0));
    }
    hex += &u8h(add.map(|add| add.ipv6_prefix as u64).unwrap_or(0));
    hex += "000000";
    hex += &match add {
        Some(add) => prefix_mask_hex(add.ipv6_prefix),
        None => "00".repeat(16),
    };
    Ok(hex)
}

// -------------------------------------------------------------------- sets

pub struct Set {
    pub key: String,
    pub name: String,
    pub elements: Vec<Cidr>,
    pub id: u32,
}

/// A sets record: its key, name and parsed elements.
pub fn normalize_set(key: &str, data: &Value) -> Result<Set> {
    if !set_name_valid(key) {
        bail!("集合名无效: {key}（小写字母、数字、- 和 _，最长 48）");
    }
    if !data.is_object() {
        bail!("集合 {key}: 内容必须是对象");
    }
    let label = format!("集合 {key}");
    let mut elements = Vec::new();
    for raw in js::array(js::or(g(data, "elements"), &json!([]))) {
        elements.push(parse_cidr(&raw)?);
    }
    if elements.len() > MAX_SET_ELEMENTS {
        bail!("{label}: 静态元素最多 {MAX_SET_ELEMENTS} 个");
    }
    let mut seen = HashSet::new();
    for cidr in &elements {
        if !seen.insert(cidr.text.clone()) {
            bail!("{label}: 元素重复: {}", cidr.text);
        }
    }
    Ok(Set {
        key: key.to_string(),
        name: if truthy(g(data, "name")) { js::string(g(data, "name")) } else { key.to_string() },
        elements,
        id: 0,
    })
}

/// fw_sets key: {prefixlen, family, pad, id (network order), addr[16]}.
pub fn set_key(id: u32, cidr: &Cidr) -> String {
    let mut addr = bytes_hex(&cidr.bytes);
    addr.push_str(&"0".repeat(32));
    addr.truncate(32);
    u32le(32 + cidr.prefix as u64) + &u8h(cidr.family as u64) + "00" + &u16be(id as u64) + &addr
}

/// A little-endian u64 of nanoseconds from milliseconds.
pub fn u64le_ns_from_ms(ms: f64) -> String {
    let ns = (ms.round() as u64).wrapping_mul(1_000_000);
    u32le(ns & 0xffff_ffff) + &u32le(ns >> 32)
}

/// fw_sets value: {expires_ns, kind}; expires_ms 0 = until removed.
pub fn set_value(expires_ms: f64, kind: u32) -> String {
    let expires = if expires_ms != 0.0 { u64le_ns_from_ms(expires_ms) } else { "0000000000000000".to_string() };
    expires + &u32le(kind as u64) + "00000000"
}

fn hex_slice(hex: &str, offset: usize, len: usize) -> &str {
    let start = offset.min(hex.len());
    let end = (offset + len).min(hex.len());
    &hex[start..end]
}

fn parse_hex(text: &str) -> u64 {
    u64::from_str_radix(text, 16).unwrap_or(0)
}

pub fn hex_u16le(hex: &str, offset: usize) -> u64 {
    parse_hex(&(hex_slice(hex, offset + 2, 2).to_string() + hex_slice(hex, offset, 2)))
}

pub fn hex_u16be(hex: &str, offset: usize) -> u64 {
    parse_hex(hex_slice(hex, offset, 4))
}

pub fn hex_u32le(hex: &str, offset: usize) -> u64 {
    hex_u16le(hex, offset) + hex_u16le(hex, offset + 4) * 65536
}

/// A little-endian u64 of nanoseconds, as milliseconds.
pub fn hex_u64le_ms(hex: &str, offset: usize) -> f64 {
    (hex_u32le(hex, offset) as f64 + hex_u32le(hex, offset + 8) as f64 * 4_294_967_296.0) / 1e6
}

fn address_from_hex(family: u8, hex: &str) -> String {
    let count = if family == 4 { 4 } else { 16 };
    let bytes: Vec<u8> = (0..count).map(|i| parse_hex(hex_slice(hex, i * 2, 2)) as u8).collect();
    format_address(family, &bytes)
}

pub struct SetKey {
    pub id: u64,
    pub family: u8,
    pub prefix: i64,
    pub cidr: String,
}

pub fn decode_set_key(key_hex: &str) -> Option<SetKey> {
    if key_hex.len() < 48 {
        return None;
    }
    let prefix = hex_u32le(key_hex, 0) as i64 - 32;
    let family = parse_hex(hex_slice(key_hex, 8, 2)) as u8;
    if (family != 4 && family != 6) || prefix < 0 || prefix > if family == 4 { 32 } else { 128 } {
        return None;
    }
    Some(SetKey { id: hex_u16be(key_hex, 12), family, prefix, cidr: format!("{}/{}", address_from_hex(family, &key_hex[16..]), prefix) })
}

pub struct SetValue {
    pub expires_ms: f64,
    pub kind: &'static str,
}

pub fn decode_set_value(value_hex: &str) -> Option<SetValue> {
    if value_hex.len() < 32 {
        return None;
    }
    let kind = match hex_u32le(value_hex, 16) {
        1 => "static",
        2 => "api",
        3 => "policy",
        _ => "unknown",
    };
    Some(SetValue { expires_ms: hex_u64le_ms(value_hex, 0), kind })
}

/// The static fw_sets entries of the sets (each with an id) and of the bogon
/// prefixes the baseline asks for: key -> value.
pub fn compile_sets(sets: &[Set], baseline: &Baseline) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut total = 0;
    for set in sets {
        for cidr in &set.elements {
            out.insert(set_key(set.id, cidr), set_value(0.0, SET_KIND_STATIC));
            total += 1;
        }
    }
    if total > SET_STATIC_CAPACITY {
        bail!("集合静态元素合计超过容量 {SET_STATIC_CAPACITY}");
    }
    let bogons = baseline.bogon_sources.as_str();
    if bogons == "reserved" || bogons == "all" {
        let mut list: Vec<&str> = BOGONS_RESERVED.to_vec();
        if bogons == "all" {
            list.extend(BOGONS_PRIVATE);
        }
        for text in list {
            out.insert(set_key(SET_BOGON, &parse_cidr_str(text)?), set_value(0.0, SET_KIND_STATIC));
        }
    }
    Ok(out)
}

// ------------------------------------------------------------ bans and log

pub struct LimitKey {
    pub family: u8,
    pub prefix: u64,
    pub slot: u64,
    pub source: String,
}

/// fw_ban / fw_rate key: {family u8, prefix u8, slot u16le, addr[16]}.
pub fn decode_limit_key(key_hex: &str) -> Option<LimitKey> {
    let family = parse_hex(hex_slice(key_hex, 0, 2)) as u8;
    let prefix = parse_hex(hex_slice(key_hex, 2, 2));
    if (family != 4 && family != 6) || key_hex.len() < 40 {
        return None;
    }
    Some(LimitKey { family, prefix, slot: hex_u16le(key_hex, 4), source: format!("{}/{}", address_from_hex(family, &key_hex[8..]), prefix) })
}

/// fw_ban value: the ban's end, ktime ns as milliseconds.
pub fn decode_ban_until_ms(value_hex: &str) -> f64 {
    hex_u64le_ms(value_hex, 0)
}

/// struct fw_event in firewall.bpf.c (56 bytes).
pub fn decode_event(hex: &str) -> Option<Value> {
    if hex.len() < EVENT_BYTES * 2 {
        return None;
    }
    let family = parse_hex(hex_slice(hex, 30, 2)) as u8;
    let proto = parse_hex(hex_slice(hex, 32, 2)) as usize;
    let port = hex_u16be(hex, 40);
    let mut event = json!({
        "time_ms": js::num(hex_u64le_ms(hex, 0)),
        "ifindex": hex_u32le(hex, 16),
        "slot": hex_u16le(hex, 24),
        "reason": reason_name(parse_hex(hex_slice(hex, 28, 2))),
        "protocol": PROTO_NAMES.get(proto).copied().unwrap_or(""),
        "source_port": hex_u16be(hex, 36),
        "port": port,
        "source": "",
        "destination": "",
    });
    // ICMP keeps type and code in the port field, other protocols their number.
    if proto == PROTO_ICMP as usize || proto == PROTO_ICMPV6 as usize {
        event["icmp_type"] = json!(port >> 8);
        event["icmp_code"] = json!(port & 255);
        event["port"] = json!(0);
        event["source_port"] = json!(0);
    } else if proto == PROTO_IP as usize {
        event["ip_protocol"] = json!(port >> 8);
        event["port"] = json!(0);
        event["source_port"] = json!(0);
    }
    if family == 4 || family == 6 {
        event["source"] = json!(address_from_hex(family, hex_slice(hex, 48, 32)));
        event["destination"] = json!(address_from_hex(family, hex_slice(hex, 80, 32)));
    }
    Some(event)
}

pub fn lstats_key(slot: u32, counter: u32) -> String {
    u32le((slot * LCOUNTERS + counter) as u64)
}

/// The generation byte of any key the LPM maps hold: right after prefixlen.
pub fn key_generation(key_hex: &str) -> u32 {
    parse_hex(hex_slice(key_hex, 8, 2)) as u32
}

pub fn gstats_key(counter: u32) -> String {
    u32le(counter as u64)
}

pub fn stats_key(slot: u32, counter: u32) -> String {
    u32le((slot * COUNTERS + counter) as u64)
}

/// Sums a per-CPU u64 value (array of little-endian hex strings).
pub fn sum_per_cpu(values: &Value) -> u64 {
    let mut total: u64 = 0;
    for hex in js::array(values) {
        let hex = js::string(&hex);
        let mut value: u64 = 0;
        let len = hex.len().min(16);
        let mut i = len as i64 - 2;
        while i >= 0 {
            value = value.wrapping_mul(256).wrapping_add(parse_hex(hex_slice(&hex, i as usize, 2)));
            i -= 2;
        }
        total = total.wrapping_add(value);
    }
    total
}
