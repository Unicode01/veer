//! Text, hex and packet helpers: PPPoE discovery and session frames, PPP
//! control packets and options, DHCPv6 messages, IPv6 UDP/ICMPv6 and their
//! checksums. Hex strings are lowercase, as the control script wrote them.

use veer_plugin::js::{self, get as g};
use veer_plugin::{bail, json, Result, Value};

pub const CODE_PADI: u64 = 0x09;
pub const CODE_PADO: u64 = 0x07;
pub const CODE_PADR: u64 = 0x19;
pub const CODE_PADS: u64 = 0x65;
pub const CODE_PADT: u64 = 0xa7;
pub const TAG_SERVICE_NAME: u64 = 0x0101;
pub const TAG_AC_NAME: u64 = 0x0102;
pub const TAG_HOST_UNIQ: u64 = 0x0103;
pub const TAG_AC_COOKIE: u64 = 0x0104;
pub const TAG_RELAY_SESSION_ID: u64 = 0x0110;
pub const PPP_IPV6: u64 = 0x0057;
pub const PPP_LCP: u64 = 0xc021;
pub const PPP_PAP: u64 = 0xc023;
pub const PPP_CHAP: u64 = 0xc223;
pub const PPP_IPCP: u64 = 0x8021;
pub const PPP_IPV6CP: u64 = 0x8057;
pub const DHCPV6_SOLICIT: u64 = 1;
pub const DHCPV6_ADVERTISE: u64 = 2;
pub const DHCPV6_REQUEST: u64 = 3;
pub const DHCPV6_RENEW: u64 = 5;
pub const DHCPV6_REBIND: u64 = 6;
pub const DHCPV6_REPLY: u64 = 7;
pub const DHCPV6_OPT_CLIENTID: u64 = 1;
pub const DHCPV6_OPT_SERVERID: u64 = 2;
pub const DHCPV6_OPT_IA_NA: u64 = 3;
pub const DHCPV6_OPT_IAADDR: u64 = 5;
pub const DHCPV6_OPT_ORO: u64 = 6;
pub const DHCPV6_OPT_ELAPSED_TIME: u64 = 8;
pub const DHCPV6_OPT_STATUS_CODE: u64 = 13;
pub const DHCPV6_OPT_DNS_SERVERS: u64 = 23;
pub const DHCPV6_OPT_IA_PD: u64 = 25;
pub const DHCPV6_OPT_IAPREFIX: u64 = 26;
pub const DHCPV6_OPT_CLIENT_FQDN: u64 = 39;

// ------------------------------------------------------------ text

/// `String(value == null ? '' : value).trim()`.
pub fn text(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    js::string(value).trim().to_string()
}

pub fn text_str(value: &str) -> String {
    value.trim().to_string()
}

/// `text(value).toLowerCase()`.
pub fn lower(value: &Value) -> String {
    text(value).to_lowercase()
}

/// A record key: lowercase, runs of other characters as '-', never empty.
pub fn token(value: &Value) -> String {
    let source = if js::truthy(value) { lower(value) } else { "default".to_string() };
    let mut out = String::new();
    let mut dash = false;
    for c in source.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed
    }
}

pub fn token_str(value: &str) -> String {
    token(&json!(value))
}

/// `parseInt(value, 10)` clamped to [min, max], or fallback when NaN.
pub fn clamp_int(value: &Value, min: f64, max: f64, fallback: f64) -> f64 {
    match js::parse_int(value) {
        Some(n) if n.is_finite() => n.max(min).min(max),
        _ => fallback,
    }
}

pub fn clamp(value: &Value, min: i64, max: i64, fallback: i64) -> i64 {
    clamp_int(value, min as f64, max as f64, fallback as f64) as i64
}

/// `parseInt` as a positive timestamp, or 0.
pub fn timestamp_ms(value: &Value) -> f64 {
    match js::parse_int(value) {
        Some(n) if n.is_finite() && n > 0.0 => n,
        _ => 0.0,
    }
}

/// `Number(value)` as a timestamp in (0, 2^53), floored, or fallback.
pub fn normalize_timestamp_ms(value: &Value, fallback: f64) -> f64 {
    let n = js::number(value);
    if !n.is_finite() || n <= 0.0 || n > 9007199254740991.0 {
        return fallback;
    }
    n.floor()
}

pub fn bool_of(value: &Value, fallback: bool) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::Null => fallback,
        Value::String(s) if s.is_empty() => fallback,
        other => match lower(other).as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => fallback,
        },
    }
}

/// The first value that is not null or ''.
pub fn first_defined<'a>(values: &[&'a Value]) -> &'a Value {
    static NULL: Value = Value::Null;
    for value in values {
        match value {
            Value::Null => continue,
            Value::String(s) if s.is_empty() => continue,
            _ => return value,
        }
    }
    &NULL
}

pub fn has_own(object: &Value, key: &str) -> bool {
    object.as_object().map(|map| map.contains_key(key)).unwrap_or(false)
}

/// Shallow `{...a, ...b}`.
pub fn merge(a: &Value, b: &Value) -> Value {
    js::merge(a, b)
}

pub fn utf8_len(value: &str) -> usize {
    value.len()
}

pub fn iface_name(value: &Value, label: &str) -> Result<String> {
    let value = text(value);
    if value.is_empty() || utf8_len(&value) > 15 || value.chars().any(|c| c == '/' || c == '\\' || c.is_whitespace() || c == '\0') {
        bail!("{label} contains invalid characters or exceeds 15 bytes");
    }
    Ok(value)
}

pub fn optional_iface_name(value: &Value, label: &str) -> Result<String> {
    let value = text(value);
    if value.is_empty() {
        return Ok(String::new());
    }
    iface_name(&json!(value), label)
}

pub fn unique_text_values(values: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for value in values {
        let value = text(value);
        if value.is_empty() || out.iter().any(|v| v.as_str() == Some(value.as_str())) {
            continue;
        }
        out.push(json!(value));
    }
    out
}

pub fn repeat_hex(value: &str, count: usize) -> String {
    value.repeat(count)
}

// ------------------------------------------------------------ hex

pub fn hex_byte(value: f64) -> String {
    let n = if value.is_finite() { (value as i64 & 0xff) as u8 } else { 0 };
    format!("{n:02x}")
}

pub fn hb(value: u64) -> String {
    format!("{:02x}", value & 0xff)
}

pub fn u16hex(value: u64) -> String {
    format!("{:04x}", value & 0xffff)
}

pub fn u32hex(value: u64) -> String {
    format!("{:08x}", value & 0xffff_ffff)
}

pub fn u16lehex(value: u64) -> String {
    let v = value & 0xffff;
    format!("{:02x}{:02x}", v & 0xff, v >> 8)
}

pub fn u32lehex(value: u64) -> String {
    let v = value & 0xffff_ffff;
    (0..4).map(|i| format!("{:02x}", (v >> (8 * i)) & 0xff)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let hex = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
    let digits: Vec<u8> = hex.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    digits
        .chunks(2)
        .filter(|pair| pair.len() == 2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn u16_at(bytes: &[u8], offset: usize) -> u64 {
    ((*bytes.get(offset).unwrap_or(&0) as u64) << 8) | *bytes.get(offset + 1).unwrap_or(&0) as u64
}

pub fn u32_at(bytes: &[u8], offset: usize) -> u64 {
    (0..4).fold(0u64, |acc, i| (acc << 8) | *bytes.get(offset + i).unwrap_or(&0) as u64)
}

pub fn u16le_at(bytes: &[u8], offset: usize) -> u64 {
    *bytes.get(offset).unwrap_or(&0) as u64 | ((*bytes.get(offset + 1).unwrap_or(&0) as u64) << 8)
}

pub fn u32le_at(bytes: &[u8], offset: usize) -> u64 {
    (0..4).fold(0u64, |acc, i| acc | ((*bytes.get(offset + i).unwrap_or(&0) as u64) << (8 * i)))
}

pub fn u64le_number(hex: &str) -> f64 {
    let bytes = hex_to_bytes(hex);
    let mut out = 0f64;
    let mut mul = 1f64;
    for b in bytes.iter().take(8) {
        out += *b as f64 * mul;
        mul *= 256.0;
    }
    out
}

/// UTF-16 code units as bytes; units above 255 become '?'.
pub fn string_hex(value: &str) -> String {
    value.encode_utf16().map(|unit| hb(if unit > 255 { 63 } else { unit as u64 })).collect()
}

/// Bytes as Latin-1 text.
pub fn hex_to_string(hex: &str) -> String {
    hex_to_bytes(hex).iter().map(|b| *b as char).collect()
}

/// Latin-1 text with each run of non-printable characters as one '.'.
pub fn hex_to_printable(hex: &str) -> String {
    let mut out = String::new();
    let mut run = false;
    for c in hex_to_string(hex).chars() {
        if ('\x20'..='\x7e').contains(&c) {
            out.push(c);
            run = false;
        } else if !run {
            out.push('.');
            run = true;
        }
    }
    out
}

// ------------------------------------------------------------ MAC / IPv6

pub fn mac_text(value: &Value) -> Result<String> {
    let value = text(value).to_lowercase();
    if value.is_empty() {
        return Ok(String::new());
    }
    let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        bail!("invalid mac address {value}");
    }
    Ok((0..12).step_by(2).map(|i| &hex[i..i + 2]).collect::<Vec<_>>().join(":"))
}

pub fn mac_str(value: &str) -> Result<String> {
    mac_text(&json!(value))
}

pub fn mac_hex(value: &str) -> Result<String> {
    Ok(mac_str(value)?.replace(':', ""))
}

pub fn mac_bytes_to_text(bytes: &[u8]) -> String {
    (0..6).map(|i| format!("{:02x}", bytes.get(i).copied().unwrap_or(0))).collect::<Vec<_>>().join(":")
}

pub fn iid_hex(value: &Value) -> Result<String> {
    let raw = if js::truthy(value) { js::string(value) } else { String::new() };
    let raw = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")).unwrap_or(&raw);
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_lowercase();
    if hex.is_empty() {
        return Ok(String::new());
    }
    if hex.len() != 16 {
        bail!("ipv6_iid must be 8 bytes");
    }
    Ok(hex)
}

/// Groups without leading zeros; the first run of two or more zero groups
/// becomes '::'.
pub fn ipv6_bytes_to_text(bytes: &[u8]) -> String {
    let groups: Vec<String> = (0..16).step_by(2).map(|i| format!("{:x}", u16_at(bytes, i))).collect();
    let mut start = None;
    let mut i = 0;
    while i < 8 {
        if groups[i] == "0" {
            let mut j = i;
            while j < 8 && groups[j] == "0" {
                j += 1;
            }
            if j - i >= 2 {
                start = Some((i, j));
                break;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    match start {
        None => groups.join(":"),
        Some((a, b)) => format!("{}::{}", groups[..a].join(":"), groups[b..].join(":")),
    }
}

pub fn ipv6_text_to_hex(value: &str) -> Result<String> {
    // Groups lose their leading zeros in text: joining "fe80::5cd:b06:..."
    // without padding each group gave another link-local address, so the
    // RS and DHCPv6 of about one IID in four left from an address the AC
    // never negotiated.
    match value.trim().parse::<std::net::Ipv6Addr>() {
        Ok(address) => Ok(bytes_to_hex(&address.octets())),
        Err(_) => bail!("unsupported IPv6 literal in PPPoE helper: {}", value.trim()),
    }
}

pub fn link_local_from_iid(iid: &str) -> Result<String> {
    let iid = iid_hex(&json!(iid))?;
    Ok(ipv6_bytes_to_text(&hex_to_bytes(&format!("fe80000000000000{iid}"))))
}

pub fn slaac_address(prefix_hex: &str, prefix_length: u64, iid: &str) -> Result<String> {
    let prefix_hex = prefix_hex.trim().to_lowercase();
    let iid = iid_hex(&json!(iid))?;
    if prefix_length != 64 || prefix_hex.len() != 32 || iid.is_empty() {
        return Ok(String::new());
    }
    Ok(ipv6_bytes_to_text(&hex_to_bytes(&format!("{}{iid}", &prefix_hex[..16]))))
}

// ------------------------------------------------------------ PPPoE / PPP

pub fn pppoe_discovery(code: u64, session_id: u64, tags: &[String]) -> String {
    let body: String = tags.concat();
    format!("11{}{}{}{}", hb(code), u16hex(session_id), u16hex((body.len() / 2) as u64), body)
}

pub fn pppoe_session(session_id: u64, payload_hex: &str) -> String {
    format!("1100{}{}{}", u16hex(session_id), u16hex((payload_hex.len() / 2) as u64), payload_hex)
}

pub fn cp_packet(code: u64, identifier: u64, data_hex: &str) -> String {
    format!("{}{}{}{}", hb(code), hb(identifier), u16hex(4 + (data_hex.len() / 2) as u64), data_hex)
}

pub fn tag_hex(ty: u64, value_hex: &str) -> String {
    format!("{}{}{}", u16hex(ty), u16hex((value_hex.len() / 2) as u64), value_hex)
}

pub fn tag_string(ty: u64, value: &str) -> String {
    tag_hex(ty, &string_hex(value))
}

pub fn cp_option_hex(ty: u64, value_hex: &str) -> String {
    format!("{}{}{}", hb(ty), hb(2 + (value_hex.len() / 2) as u64), value_hex)
}

pub fn cp_option_u16(ty: u64, value: u64) -> String {
    cp_option_hex(ty, &u16hex(value))
}

pub fn cp_option_ipv4(ty: u64, value: &str) -> String {
    let source = if value.is_empty() { "0.0.0.0" } else { value };
    let parts: Vec<&str> = source.split('.').collect();
    let hex: String = (0..4).map(|i| hex_byte(js::parse_int(&json!(parts.get(i).copied().unwrap_or("0"))).unwrap_or(f64::NAN))).collect();
    cp_option_hex(ty, &hex)
}

#[derive(Clone, Debug)]
pub struct Tag {
    pub ty: u64,
    pub value_hex: String,
}

#[derive(Clone, Debug)]
pub struct Discovery {
    pub code: u64,
    pub session_id: u64,
    pub length: u64,
    pub tags: Vec<Tag>,
}

pub fn parse_discovery_frame(frame: &Value) -> Result<Discovery> {
    let bytes = hex_to_bytes(&js::string(js::or(g(frame, "payload_hex"), &json!(""))));
    if bytes.len() < 6 || bytes[0] != 0x11 {
        bail!("invalid PPPoE discovery frame");
    }
    let length = u16_at(&bytes, 4);
    let end = bytes.len().min(6 + length as usize);
    let mut tags = Vec::new();
    let mut pos = 6;
    while pos + 4 <= end {
        let ty = u16_at(&bytes, pos);
        let size = u16_at(&bytes, pos + 2) as usize;
        pos += 4;
        if pos + size > end {
            break;
        }
        tags.push(Tag { ty, value_hex: bytes_to_hex(&bytes[pos..pos + size]) });
        pos += size;
    }
    Ok(Discovery { code: bytes[1] as u64, session_id: u16_at(&bytes, 2), length, tags })
}

pub fn first_tag_text(discovery: &Discovery, ty: u64) -> String {
    discovery.tags.iter().find(|t| t.ty == ty).map(|t| hex_to_string(&t.value_hex)).unwrap_or_default()
}

pub fn first_tag_hex(discovery: &Discovery, ty: u64) -> String {
    discovery.tags.iter().find(|t| t.ty == ty).map(|t| t.value_hex.clone()).unwrap_or_default()
}

pub fn append_forwarded_tag(out: &mut Vec<String>, discovery: &Discovery, ty: u64) {
    for tag in &discovery.tags {
        if tag.ty == ty {
            out.push(tag_hex(ty, &tag.value_hex));
        }
    }
}

pub fn tag_summary(tags: &[Tag]) -> Value {
    Value::Array(
        tags.iter()
            .map(|t| json!({"type": format!("0x{}", u16hex(t.ty)), "bytes": t.value_hex.len() / 2, "text": hex_to_printable(&t.value_hex)}))
            .collect(),
    )
}

#[derive(Clone, Debug)]
pub struct SessionFrame {
    pub session_id: u64,
    pub protocol: u64,
    pub payload: String,
}

pub fn parse_session_frame(frame: &Value) -> Result<SessionFrame> {
    let bytes = hex_to_bytes(&js::string(js::or(g(frame, "payload_hex"), &json!(""))));
    if bytes.len() < 8 || bytes[0] != 0x11 {
        bail!("invalid PPPoE session frame");
    }
    let length = u16_at(&bytes, 4) as usize;
    let payload = &bytes[6..bytes.len().min(6 + length)];
    if payload.len() < 2 {
        bail!("empty PPP session payload");
    }
    Ok(SessionFrame { session_id: u16_at(&bytes, 2), protocol: u16_at(payload, 0), payload: bytes_to_hex(&payload[2..]) })
}

#[derive(Clone, Debug, Default)]
pub struct Cp {
    pub code: u64,
    pub identifier: u64,
    pub length: u64,
    pub data_hex: String,
}

pub fn parse_cp(payload_hex: &str) -> Cp {
    let bytes = hex_to_bytes(payload_hex);
    if bytes.len() < 4 {
        return Cp::default();
    }
    let length = (u16_at(&bytes, 2) as usize).min(bytes.len());
    let data: &[u8] = if length > 4 { &bytes[4..length] } else { &[] };
    Cp { code: bytes[0] as u64, identifier: bytes[1] as u64, length: length as u64, data_hex: bytes_to_hex(data) }
}

#[derive(Clone, Debug)]
pub struct CpOption {
    pub ty: u64,
    pub length: u64,
    pub value_hex: String,
}

pub fn parse_cp_options(payload_hex: &str) -> Vec<CpOption> {
    let bytes = hex_to_bytes(payload_hex);
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 2 <= bytes.len() {
        let ty = bytes[pos] as u64;
        let len = bytes[pos + 1] as usize;
        if len < 2 || pos + len > bytes.len() {
            break;
        }
        out.push(CpOption { ty, length: len as u64, value_hex: bytes_to_hex(&bytes[pos + 2..pos + len]) });
        pos += len;
    }
    out
}

pub fn first_cp_hex_option(options: &[CpOption], ty: u64) -> String {
    options.iter().find(|o| o.ty == ty).map(|o| o.value_hex.clone()).unwrap_or_default()
}

pub fn first_cp_ipv4_option(options: &[CpOption], ty: u64) -> String {
    let bytes = hex_to_bytes(&first_cp_hex_option(options, ty));
    if bytes.len() < 4 {
        return String::new();
    }
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

pub fn cp_code_name(code: u64) -> String {
    match code {
        1 => "configure_request".into(),
        2 => "configure_ack".into(),
        3 => "configure_nak".into(),
        4 => "configure_reject".into(),
        5 => "terminate_request".into(),
        6 => "terminate_ack".into(),
        9 => "echo_request".into(),
        10 => "echo_reply".into(),
        other => format!("code_{other}"),
    }
}

pub fn ppp_control_protocol_name(protocol: u64) -> String {
    match protocol {
        PPP_LCP => "lcp".into(),
        PPP_IPCP => "ipcp".into(),
        PPP_IPV6CP => "ipv6cp".into(),
        other => format!("0x{}", u16hex(other)),
    }
}

// ------------------------------------------------------------ IPv6

fn ones_complement_checksum(bytes: &[u8]) -> u64 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let word = ((bytes[i] as u64) << 8) + *bytes.get(i + 1).unwrap_or(&0) as u64;
        sum += word;
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        i += 2;
    }
    !sum & 0xffff
}

pub fn ipv6_udp(src: &str, dst: &str, src_port: u64, dst_port: u64, payload_hex: &str) -> Result<String> {
    let src_hex = ipv6_text_to_hex(src)?;
    let dst_hex = ipv6_text_to_hex(dst)?;
    let udp_len = 8 + (payload_hex.len() / 2) as u64;
    let udp_no_checksum = format!("{}{}{}0000{payload_hex}", u16hex(src_port), u16hex(dst_port), u16hex(udp_len));
    let pseudo = format!("{src_hex}{dst_hex}{}00000011{udp_no_checksum}", u32hex(udp_len));
    let checksum = ones_complement_checksum(&hex_to_bytes(&pseudo));
    let udp = format!("{}{}{}{}{payload_hex}", u16hex(src_port), u16hex(dst_port), u16hex(udp_len), u16hex(checksum));
    Ok(format!("60000000{}1101{src_hex}{dst_hex}{udp}", u16hex(udp_len)))
}

pub fn ipv6_icmp(src: &str, dst: &str, ty: u64, code: u64, body_hex: &str, hop_limit: u64) -> Result<String> {
    let src_hex = ipv6_text_to_hex(src)?;
    let dst_hex = ipv6_text_to_hex(dst)?;
    let payload = format!("{}{}0000{body_hex}", hb(ty), hb(code));
    let payload_len = (payload.len() / 2) as u64;
    let pseudo = format!("{src_hex}{dst_hex}{}000000{}{payload}", u32hex(payload_len), hb(58));
    let checksum = ones_complement_checksum(&hex_to_bytes(&pseudo));
    let payload = format!("{}{}{}{body_hex}", hb(ty), hb(code), u16hex(checksum));
    Ok(format!("60000000{}3a{}{src_hex}{dst_hex}{payload}", u16hex(payload_len), hb(hop_limit.clamp(1, 255))))
}

#[derive(Clone, Debug)]
pub struct Udp6 {
    pub src: String,
    pub dst: String,
    pub src_port: u64,
    pub dst_port: u64,
    pub payload_hex: String,
}

pub fn parse_ipv6_udp(payload_hex: &str) -> Option<Udp6> {
    let bytes = hex_to_bytes(payload_hex);
    if bytes.len() < 48 || (bytes[0] >> 4) != 6 || bytes[6] != 17 {
        return None;
    }
    let payload_len = u16_at(&bytes, 4) as usize;
    let udp_len = u16_at(&bytes, 44) as usize;
    let end = bytes.len().min(40 + payload_len.min(udp_len));
    if end < 48 {
        return None;
    }
    Some(Udp6 {
        src: ipv6_bytes_to_text(&bytes[8..24]),
        dst: ipv6_bytes_to_text(&bytes[24..40]),
        src_port: u16_at(&bytes, 40),
        dst_port: u16_at(&bytes, 42),
        payload_hex: bytes_to_hex(&bytes[48..end]),
    })
}

#[derive(Clone, Debug)]
pub struct Icmp6 {
    pub src: String,
    pub dst: String,
    pub ty: u64,
    pub code: u64,
    pub body_hex: String,
}

pub fn parse_ipv6_icmp(payload_hex: &str) -> Option<Icmp6> {
    let bytes = hex_to_bytes(payload_hex);
    if bytes.len() < 44 || (bytes[0] >> 4) != 6 || bytes[6] != 58 {
        return None;
    }
    let payload_len = u16_at(&bytes, 4) as usize;
    let end = bytes.len().min(40 + payload_len);
    if end < 44 {
        return None;
    }
    Some(Icmp6 {
        src: ipv6_bytes_to_text(&bytes[8..24]),
        dst: ipv6_bytes_to_text(&bytes[24..40]),
        ty: bytes[40] as u64,
        code: bytes[41] as u64,
        body_hex: bytes_to_hex(&bytes[44..end]),
    })
}

// ------------------------------------------------------------ DHCPv6

pub fn dhcpv6_option(code: u64, value_hex: &str) -> String {
    format!("{}{}{}", u16hex(code), u16hex((value_hex.len() / 2) as u64), value_hex)
}

fn dhcpv6_oro() -> String {
    let codes = [21u64, 22, 23, 24, 31, 56, 64, 67, 94, 95, 96, 82];
    dhcpv6_option(DHCPV6_OPT_ORO, &codes.iter().map(|c| u16hex(*c)).collect::<String>())
}

fn dhcpv6_client_fqdn(name: &str) -> String {
    let mut encoded = "00".to_string();
    for label in name.trim().split('.') {
        let hex = string_hex(label);
        encoded.push_str(&hb((hex.len() / 2) as u64));
        encoded.push_str(&hex);
    }
    dhcpv6_option(DHCPV6_OPT_CLIENT_FQDN, &format!("{encoded}00"))
}

pub fn dhcpv6_client_id_value(mac: &str) -> Result<String> {
    Ok(format!("00030001{}", mac_hex(if mac.is_empty() { "02:00:00:00:00:01" } else { mac })?))
}

pub fn dhcpv6_solicit(xid: &str, client_id: &str, iaid: u64, request_address: bool, request_pd: bool) -> String {
    let mut identities = String::new();
    if request_address {
        identities.push_str(&dhcpv6_option(DHCPV6_OPT_IA_NA, &format!("{}{}{}", u32hex(iaid), u32hex(0), u32hex(0))));
    }
    if request_pd {
        identities.push_str(&dhcpv6_option(DHCPV6_OPT_IA_PD, &format!("{}{}{}", u32hex(iaid), u32hex(0), u32hex(0))));
    }
    format!(
        "{}{xid}{}{}{}{}{identities}",
        hb(DHCPV6_SOLICIT),
        dhcpv6_option(DHCPV6_OPT_ELAPSED_TIME, "0000"),
        dhcpv6_oro(),
        dhcpv6_option(DHCPV6_OPT_CLIENTID, client_id),
        dhcpv6_client_fqdn("OpenWrt")
    )
}

pub fn dhcpv6_stateful_request(message_type: u64, xid: &str, client_id: &str, server_id: &str, ia_na: &str, ia_pd: &str) -> String {
    let server = if server_id.is_empty() { String::new() } else { dhcpv6_option(DHCPV6_OPT_SERVERID, server_id) };
    let mut identities = String::new();
    if !ia_na.is_empty() {
        identities.push_str(&dhcpv6_option(DHCPV6_OPT_IA_NA, ia_na));
    }
    if !ia_pd.is_empty() {
        identities.push_str(&dhcpv6_option(DHCPV6_OPT_IA_PD, ia_pd));
    }
    format!(
        "{}{xid}{}{}{}{server}{}{identities}",
        hb(message_type),
        dhcpv6_option(DHCPV6_OPT_ELAPSED_TIME, "0000"),
        dhcpv6_oro(),
        dhcpv6_option(DHCPV6_OPT_CLIENTID, client_id),
        dhcpv6_client_fqdn("OpenWrt")
    )
}

#[derive(Clone, Debug)]
pub struct Dhcp6Option {
    pub code: u64,
    pub value_hex: String,
    pub options: Vec<Dhcp6Option>,
}

impl Dhcp6Option {
    pub fn to_value(&self) -> Value {
        json!({"code": self.code, "value_hex": self.value_hex, "options": self.options.iter().map(Dhcp6Option::to_value).collect::<Vec<_>>()})
    }
}

#[derive(Clone, Debug)]
pub struct Dhcp6 {
    pub message_type: u64,
    pub transaction_id: String,
    pub options: Vec<Dhcp6Option>,
}

pub fn parse_dhcpv6(payload_hex: &str) -> Dhcp6 {
    let bytes = hex_to_bytes(payload_hex);
    if bytes.len() < 4 {
        return Dhcp6 { message_type: 0, transaction_id: String::new(), options: Vec::new() };
    }
    Dhcp6 { message_type: bytes[0] as u64, transaction_id: bytes_to_hex(&bytes[1..4]), options: parse_dhcpv6_options(&bytes[4..]) }
}

pub fn parse_dhcpv6_options(bytes: &[u8]) -> Vec<Dhcp6Option> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 4 <= bytes.len() {
        let code = u16_at(bytes, pos);
        let len = u16_at(bytes, pos + 2) as usize;
        pos += 4;
        if pos + len > bytes.len() {
            break;
        }
        let value = &bytes[pos..pos + len];
        let nested = if (code == DHCPV6_OPT_IA_NA || code == DHCPV6_OPT_IA_PD) && value.len() >= 12 { parse_dhcpv6_options(&value[12..]) } else { Vec::new() };
        out.push(Dhcp6Option { code, value_hex: bytes_to_hex(value), options: nested });
        pos += len;
    }
    out
}

pub fn first_dhcpv6_option_hex(options: &[Dhcp6Option], code: u64) -> String {
    options.iter().find(|o| o.code == code).map(|o| o.value_hex.clone()).unwrap_or_default()
}

pub fn dhcpv6_message_phase(message_type: u64) -> String {
    match message_type {
        DHCPV6_ADVERTISE => "advertise".into(),
        DHCPV6_REPLY => "reply".into(),
        other => format!("message_{other}"),
    }
}

/// {code, message} of a status option, or None.
pub fn dhcpv6_top_level_status(options: &[Dhcp6Option]) -> Option<(i64, String)> {
    let option = options.iter().find(|o| o.code == DHCPV6_OPT_STATUS_CODE)?;
    let bytes = hex_to_bytes(&option.value_hex);
    if bytes.len() < 2 {
        return Some((-1, "truncated status option".to_string()));
    }
    Some((u16_at(&bytes, 0) as i64, hex_to_string(&bytes_to_hex(&bytes[2..]))))
}

fn minimum_lifetime(values: &[u64]) -> u64 {
    values.iter().copied().min().unwrap_or(0)
}

pub fn dhcpv6_ia_states(options: &[Dhcp6Option]) -> Vec<Value> {
    let mut out = Vec::new();
    for option in options {
        if option.code != DHCPV6_OPT_IA_NA && option.code != DHCPV6_OPT_IA_PD {
            continue;
        }
        let bytes = hex_to_bytes(&option.value_hex);
        if bytes.len() < 12 {
            continue;
        }
        let mut valid = Vec::new();
        let mut preferred = Vec::new();
        for nested in &option.options {
            let nb = hex_to_bytes(&nested.value_hex);
            if option.code == DHCPV6_OPT_IA_NA && nested.code == DHCPV6_OPT_IAADDR && nb.len() >= 24 {
                preferred.push(u32_at(&nb, 16));
                valid.push(u32_at(&nb, 20));
            }
            if option.code == DHCPV6_OPT_IA_PD && nested.code == DHCPV6_OPT_IAPREFIX && nb.len() >= 25 {
                preferred.push(u32_at(&nb, 0));
                valid.push(u32_at(&nb, 4));
            }
        }
        out.push(json!({
            "type": if option.code == DHCPV6_OPT_IA_NA { "ia_na" } else { "ia_pd" },
            "code": option.code,
            "iaid": u32_at(&bytes, 0), "t1": u32_at(&bytes, 4), "t2": u32_at(&bytes, 8),
            "preferred_lifetime": minimum_lifetime(&preferred), "valid_lifetime": minimum_lifetime(&valid),
            "value_hex": option.value_hex,
        }));
    }
    out
}

pub fn dhcpv6_ia_statuses(options: &[Dhcp6Option]) -> Vec<Value> {
    let mut out = Vec::new();
    for option in options {
        if option.code != DHCPV6_OPT_IA_NA && option.code != DHCPV6_OPT_IA_PD {
            continue;
        }
        if let Some((code, message)) = dhcpv6_top_level_status(&option.options) {
            out.push(json!({"type": if option.code == DHCPV6_OPT_IA_NA { "ia_na" } else { "ia_pd" }, "code": code, "message": message}));
        }
    }
    out
}

pub fn dhcpv6_addresses(options: &[Dhcp6Option]) -> Vec<Value> {
    let mut out = Vec::new();
    for option in options.iter().filter(|o| o.code == DHCPV6_OPT_IA_NA) {
        for nested in option.options.iter().filter(|n| n.code == DHCPV6_OPT_IAADDR) {
            let bytes = hex_to_bytes(&nested.value_hex);
            if bytes.len() < 24 {
                continue;
            }
            out.push(json!({"address": ipv6_bytes_to_text(&bytes[0..16]), "preferred_lifetime": u32_at(&bytes, 16), "valid_lifetime": u32_at(&bytes, 20)}));
        }
    }
    out
}

pub fn dhcpv6_dns_servers(options: &[Dhcp6Option]) -> Vec<Value> {
    let mut out = Vec::new();
    for option in options.iter().filter(|o| o.code == DHCPV6_OPT_DNS_SERVERS) {
        let bytes = hex_to_bytes(&option.value_hex);
        let mut pos = 0;
        while pos + 16 <= bytes.len() {
            out.push(json!(ipv6_bytes_to_text(&bytes[pos..pos + 16])));
            pos += 16;
        }
    }
    out
}

pub fn dhcpv6_prefixes(options: &[Dhcp6Option]) -> Vec<Value> {
    let mut out = Vec::new();
    for option in options.iter().filter(|o| o.code == DHCPV6_OPT_IA_PD) {
        for nested in option.options.iter().filter(|n| n.code == DHCPV6_OPT_IAPREFIX) {
            let bytes = hex_to_bytes(&nested.value_hex);
            if bytes.len() < 25 {
                continue;
            }
            let prefix = ipv6_bytes_to_text(&bytes[9..25]);
            out.push(json!({"prefix": format!("{prefix}/{}", bytes[8]), "preferred_lifetime": u32_at(&bytes, 0), "valid_lifetime": u32_at(&bytes, 4)}));
        }
    }
    out
}

pub fn dhcpv6_lease_data(options: &[Dhcp6Option]) -> Value {
    let addresses = dhcpv6_addresses(options);
    let prefixes = dhcpv6_prefixes(options);
    json!({
        "address": addresses.first().map(|a| a["address"].clone()).unwrap_or(json!("")),
        "addresses": addresses,
        "prefix": prefixes.first().map(|p| p["prefix"].clone()).unwrap_or(json!("")),
        "prefixes": prefixes,
        "dns_servers": dhcpv6_dns_servers(options),
        "ia_na_hex": first_dhcpv6_option_hex(options, DHCPV6_OPT_IA_NA),
        "ia_pd_hex": first_dhcpv6_option_hex(options, DHCPV6_OPT_IA_PD),
        "ia_states": dhcpv6_ia_states(options),
        "ia_statuses": dhcpv6_ia_statuses(options),
    })
}

/// The status of a lease IA type that failed, or None.
pub fn dhcpv6_ia_status_error(lease: &Value, ty: &str) -> Option<Value> {
    js::array(g(lease, "ia_statuses")).into_iter().find(|s| js::string(g(s, "type")) == ty && js::number(g(s, "code")) != 0.0)
}

pub fn dhcpv6_lease_has_binding(lease: &Value) -> bool {
    !js::array(g(lease, "addresses")).is_empty() || !js::array(g(lease, "prefixes")).is_empty()
}

/// Seconds until renew, rebind and expiry from the IA timers, or an error.
pub fn dhcpv6_lease_timing(lease: &Value) -> std::result::Result<(f64, f64, f64), String> {
    let states = js::array(g(lease, "ia_states"));
    let (mut renew, mut rebind, mut expires) = (Vec::new(), Vec::new(), Vec::new());
    const INFINITE: f64 = 4294967295.0;
    for state in &states {
        let valid = js::number(js::or(g(state, "valid_lifetime"), &json!(0)));
        if !valid.is_finite() || valid <= 0.0 {
            continue;
        }
        let mut t1 = js::number(js::or(g(state, "t1"), &json!(0)));
        let mut t2 = js::number(js::or(g(state, "t2"), &json!(0)));
        if t1 == 0.0 && valid != INFINITE {
            t1 = (valid / 2.0).floor().max(1.0);
        }
        if t2 == 0.0 && valid != INFINITE {
            t2 = (t1 + 1.0).max((valid * 4.0 / 5.0).floor());
        }
        let ty = js::string(g(state, "type"));
        if t1 > 0.0 && t2 > 0.0 && t1 > t2 {
            return Err(format!("{ty} has T1 greater than T2"));
        }
        if valid != INFINITE && ((t1 > 0.0 && t1 >= valid) || (t2 > 0.0 && t2 >= valid)) {
            return Err(format!("{ty} has renewal timers outside its valid lifetime"));
        }
        if t1 > 0.0 {
            renew.push(t1);
        }
        if t2 > 0.0 {
            rebind.push(t2);
        }
        if valid != INFINITE {
            expires.push(valid);
        }
    }
    let min_positive = |values: &[f64]| values.iter().copied().filter(|v| v.is_finite() && *v > 0.0).fold(0f64, |acc, v| if acc == 0.0 || v < acc { v } else { acc });
    if states.is_empty() || (renew.is_empty() && rebind.is_empty() && expires.is_empty()) {
        return Ok((0.0, 0.0, 0.0));
    }
    Ok((min_positive(&renew), min_positive(&rebind), min_positive(&expires)))
}

fn lease_deadline_ms(acquired_ms: f64, seconds: f64) -> f64 {
    let value = acquired_ms + seconds * 1000.0;
    if !value.is_finite() || value > 9007199254740991.0 {
        return 9007199254740991.0;
    }
    value.floor()
}

/// Adds the lease timers computed from acquired_ms.
pub fn stamp_dhcpv6_lease(mut lease: Value, acquired_ms: f64) -> Value {
    let acquired = normalize_timestamp_ms(&js::num(acquired_ms), acquired_ms);
    let timing = dhcpv6_lease_timing(&lease);
    let (renew, rebind, valid, error) = match &timing {
        Ok((r, b, v)) => (*r, *b, *v, String::new()),
        Err(e) => (0.0, 0.0, 0.0, e.clone()),
    };
    let at = |seconds: f64| if seconds > 0.0 { lease_deadline_ms(acquired, seconds) } else { 0.0 };
    let iso = |ms: f64| if ms > 0.0 { json!(js::iso_time(ms as u64)) } else { json!("") };
    lease["lease_acquired_ms"] = js::num(acquired);
    lease["lease_acquired_at"] = json!(js::iso_time(acquired as u64));
    lease["renew_seconds"] = js::num(renew);
    lease["rebind_seconds"] = js::num(rebind);
    lease["valid_seconds"] = js::num(valid);
    lease["renew_at_ms"] = js::num(at(renew));
    lease["rebind_at_ms"] = js::num(at(rebind));
    lease["expires_at_ms"] = js::num(at(valid));
    lease["renew_at"] = iso(at(renew));
    lease["rebind_at"] = iso(at(rebind));
    lease["expires_at"] = iso(at(valid));
    lease["lease_timer_error"] = json!(error);
    lease
}

pub fn merge_by_type(primary: &Value, fallback: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for item in js::array(primary).into_iter().chain(js::array(fallback)) {
        if !js::truthy(&item) {
            continue;
        }
        let ty = js::string(g(&item, "type"));
        if seen.contains(&ty) {
            continue;
        }
        seen.push(ty);
        out.push(item);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_text_compresses_the_first_zero_run() {
        let bytes = hex_to_bytes("fe800000000000000000000000000001");
        assert_eq!(ipv6_bytes_to_text(&bytes), "fe80::1");
        assert_eq!(ipv6_bytes_to_text(&hex_to_bytes("20010db8000000010000000000000000")), "2001:db8:0:1::");
        assert_eq!(ipv6_bytes_to_text(&hex_to_bytes("00000000000000000000000000000000")), "::");
        assert_eq!(ipv6_bytes_to_text(&hex_to_bytes("fe800000000000000001000000000000")), "fe80::1:0:0:0");
        assert_eq!(ipv6_bytes_to_text(&hex_to_bytes("00010000000100000000000000000001")), "1:0:1::1");
    }

    #[test]
    fn tokens_clamps_and_macs_follow_the_script() {
        assert_eq!(token(&json!("Home WAN!")), "home-wan");
        assert_eq!(token(&json!("")), "default");
        assert_eq!(token(&json!("--")), "default");
        assert_eq!(clamp_int(&json!("12abc"), 0.0, 100.0, 5.0), 12.0);
        assert_eq!(clamp_int(&json!(null), 0.0, 100.0, 5.0), 5.0);
        assert_eq!(clamp_int(&json!(1000), 0.0, 100.0, 5.0), 100.0);
        assert_eq!(mac_text(&json!("02-00-00-00-00-0A")).unwrap(), "02:00:00:00:00:0a");
        assert!(mac_text(&json!("02:00")).is_err());
        assert_eq!(string_hex("ab€"), "61623f");
        assert_eq!(hex_to_printable("41000102423f"), "A.B?");
    }
}
