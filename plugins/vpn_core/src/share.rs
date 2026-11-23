//! Share-link import, the Rust side of ui/share.js: parse, create, metadata
//! and generate. The page keeps its own copy for previews; both must accept
//! the same links and generate the same core configurations. The runtime has
//! no locale, so messages are the page's zh-CN ones.

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{json, Error, Map, Result, Value};

const LIMIT: usize = 256 * 1024;
const MAX_NODES: usize = 128;
pub const MAX_VIA: usize = 2;

fn msg(key: &str) -> String {
    match key {
        "urlEncoding" => "分享链接的 URL 编码无效",
        "base64" => "Base64 编码无效",
        "base64Text" => "Base64 内容不是有效 UTF-8 文本",
        "port" => "节点端口必须为 1–65535",
        "host" => "节点地址必须是有效 IP 或 ASCII 域名",
        "hostIP" => "节点 IP 地址无效",
        "bool" => "链接中的布尔参数无效",
        "uuid" => "节点 UUID 格式无效",
        "params" => "链接含暂不支持的参数，请使用高级栏中的原生 JSON",
        "duplicateParam" => "分享链接含重复或空参数",
        "format" => "分享链接格式无效",
        "credentials" => "分享链接缺少节点凭据",
        "address" => "节点地址或端口格式无效",
        "transport" => "此传输方式暂不支持链接导入，请使用原生 JSON",
        "tcpHeader" => "暂不支持 TCP 伪装头，请使用原生 JSON",
        "grpcMode" => "暂不支持此 gRPC 模式",
        "grpcAuthority" => "暂不支持 gRPC authority，请使用原生 JSON",
        "spiderX" => "暂不支持此 REALITY spiderX 参数，请使用原生 JSON",
        "path" => "传输路径无效",
        "grpcService" => "gRPC 服务名无效",
        "grpcServiceMissing" => "gRPC 链接缺少 serviceName",
        "mihomoTrojan" => "Mihomo Trojan 不支持此传输方式",
        "tlsType" => "此 TLS 类型暂不支持",
        "tlsNone" => "TLS 参数与 security=none 冲突",
        "alpn" => "ALPN 参数无效",
        "fingerprint" => "TLS 指纹暂不支持",
        "reality" => "REALITY 公钥或 short ID 无效",
        "realityInsecure" => "REALITY 不接受跳过证书验证",
        "realityConflict" => "REALITY 参数与 TLS 类型冲突",
        "vmessJSON" => "VMess Base64 JSON 无效",
        "vmessObject" => "VMess 配置必须是对象",
        "vmessCert" => "暂不支持此证书名称或指纹参数，请使用原生 JSON",
        "vmessAEAD" => "仅支持 VMess AEAD（alterId=0）",
        "vmessHeader" => "暂不支持 VMess 伪装头",
        "ssCredentials" => "Shadowsocks 凭据无效",
        "ssCipher" => "此 Shadowsocks 加密方式暂不支持链接导入",
        "ssCipherSingBox" => "sing-box 不支持此 Shadowsocks 加密方式",
        "vlessEncryption" => "VLESS encryption 暂不支持",
        "vlessFlow" => "此 VLESS flow 暂不支持",
        "vmessFlow" => "VMess 不接受 VLESS flow",
        "trojanParams" => "Trojan 链接包含其他协议参数",
        "trojanTLS" => "Trojan 必须启用 TLS",
        "vision" => "Vision 需要 TCP + TLS/REALITY",
        "anytlsSecurity" => "AnyTLS 仅支持 TLS，不支持此 security 参数",
        "anytlsTransport" => "AnyTLS 仅支持 TCP，不支持此传输方式",
        "anytlsHeader" => "AnyTLS 不支持 TCP 伪装头",
        "obfs" => "暂只支持 salamander 混淆",
        "obfsType" => "混淆密码缺少 obfs 类型",
        "protocol" => "支持 ss、vmess、vless、trojan、hysteria2 / hy2、anytls 分享链接；其他协议请使用原生 JSON",
        "portMissing" => "分享链接缺少节点端口",
        "vmessCipher" => "VMess 加密方式无效",
        "driver" => "请选择 Mihomo 或 sing-box",
        "size" => "分享内容不能为空，且不能超过 256 KiB",
        "count" => "一次可导入 1–128 个节点",
        "options" => "高级设置必须是对象",
        "ruleCount" => "每类分流规则最多 128 条",
        "cidr" => "直连网段必须是有效 CIDR",
        "dns" => "DNS 服务器请填写 IPv4 地址",
        "selected" => "请选择有效节点",
        "via" => "请选择有效的前置节点",
        "viaConflict" => "前置节点不能重复，也不能是所选节点",
        "summary" => "节点名称或高级规则摘要过大，请减少节点或规则",
        "label.ssPassword" => "Shadowsocks 密码",
        "label.trojanPassword" => "Trojan 密码",
        "label.anytlsPassword" => "AnyTLS 密码",
        "label.hy2Password" => "Hysteria2 密码",
        "label.obfsPassword" => "混淆密码",
        _ => key,
    }
    .to_string()
}

fn fail<T>(key: &str) -> Result<T> {
    Err(Error::msg(msg(key)))
}

fn invalid<T>(label: &str) -> Result<T> {
    Err(Error::msg(format!("{label}无效")))
}

/// JavaScript string length: UTF-16 code units.
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

fn has_control(text: &str) -> bool {
    text.chars().any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
}

fn strip_control(text: &str) -> String {
    text.chars().filter(|c| !((*c as u32) < 0x20 || *c as u32 == 0x7f)).collect()
}

/// The first `units` UTF-16 code units of text, never splitting a character.
fn slice_utf16(text: &str, units: usize) -> String {
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        used += c.len_utf16();
        if used > units {
            break;
        }
        out.push(c);
    }
    out
}

/// `decodeURIComponent`: %XX escapes must form UTF-8; '+' stays.
pub fn decode_uri_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |b: u8| (b as char).to_digit(16);
            let (Some(hi), Some(lo)) = (bytes.get(i + 1).and_then(|b| hex(*b)), bytes.get(i + 2).and_then(|b| hex(*b))) else {
                return None;
            };
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn decode(value: &str) -> Result<String> {
    decode_uri_component(value).map_or_else(|| fail("urlEncoding"), Ok)
}

fn is_js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_space)
}

/// The share format's Base64: URL-safe or standard, padded or not, as UTF-8 text.
pub fn base64(value: &str) -> Result<String> {
    let s: String = value.chars().filter(|c| !is_js_space(*c)).map(|c| if c == '-' { '+' } else if c == '_' { '/' } else { c }).collect();
    let body = s.trim_end_matches('=');
    let padding = s.len() - body.len();
    let shape = body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/') && padding <= 2;
    if s.is_empty() || utf16_len(&s) > LIMIT || !shape || body.len() % 4 == 1 || (s.contains('=') && s.len() % 4 != 0) {
        return fail("base64");
    }
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    for c in body.chars() {
        bits = (bits << 6) | alphabet.find(c).unwrap_or(0) as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 255) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bits != 0 {
        return fail("base64");
    }
    String::from_utf8(out).map_or_else(|_| fail("base64Text"), Ok)
}

fn all_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn port(value: &Value) -> Result<u32> {
    let text = js::string(value);
    let n = text.parse::<f64>().unwrap_or(f64::NAN);
    if !all_digits(&text) || !(1.0..=65535.0).contains(&n) {
        return fail("port");
    }
    Ok(n as u32)
}

pub fn ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            all_digits(part) && part.parse::<u64>().map(|n| n <= 255 && n.to_string() == *part).unwrap_or(false)
        })
}

pub fn ipv6(s: &str) -> bool {
    if !s.contains(':') || !s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') || s.contains(":::") {
        return false;
    }
    let groups: Vec<&str> = s.split("::").collect();
    if groups.len() > 2 {
        return false;
    }
    let parts: Vec<&str> = groups.iter().filter(|g| !g.is_empty()).flat_map(|g| g.split(':')).collect();
    parts.iter().all(|v| !v.is_empty() && v.len() <= 4 && v.chars().all(|c| c.is_ascii_hexdigit()))
        && if groups.len() == 2 { parts.len() < 8 } else { parts.len() == 8 }
}

pub fn ip(s: &str) -> bool {
    ipv4(s) || ipv6(s)
}

fn label_ok(label: &str) -> bool {
    // ^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

pub fn hostname(s: &str) -> Result<String> {
    if ip(s) {
        return Ok(s.to_string());
    }
    let trimmed = s.strip_suffix('.').unwrap_or(s);
    if utf16_len(s) > 253 || s.is_empty() || !trimmed.split('.').all(label_ok) {
        return fail("host");
    }
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return fail("hostIP");
    }
    Ok(s.to_string())
}

fn bool_param(value: &Value) -> Result<bool> {
    match value {
        Value::Null => Ok(false),
        Value::String(text) if text.is_empty() => Ok(false),
        Value::Bool(flag) => Ok(*flag),
        Value::Number(n) if n.as_f64() == Some(1.0) => Ok(true),
        Value::Number(n) if n.as_f64() == Some(0.0) => Ok(false),
        Value::String(text) if text == "1" || text == "true" => Ok(true),
        Value::String(text) if text == "0" || text == "false" => Ok(false),
        _ => fail("bool"),
    }
}

fn uuid(s: &str) -> Result<String> {
    let groups: Vec<&str> = s.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    let ok = groups.len() == 5 && groups.iter().zip(lengths).all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()));
    if !ok {
        return fail("uuid");
    }
    Ok(s.to_string())
}

fn text(value: &Value, label: &str) -> Result<String> {
    match value {
        Value::String(s) if !s.is_empty() && utf16_len(s) <= 4096 && !has_control(s) => Ok(s.clone()),
        _ => invalid(&msg(label)),
    }
}

fn allowed(object: &Map<String, Value>, keys: &[&str]) -> Result<()> {
    if object.keys().any(|key| !keys.contains(&key.as_str())) {
        return fail("params");
    }
    Ok(())
}

fn query(s: &str) -> Result<Map<String, Value>> {
    let mut out = Map::new();
    if s.is_empty() {
        return Ok(out);
    }
    for pair in s.split('&') {
        let (k, v) = match pair.find('=') {
            None => (decode(pair)?, decode("")?),
            Some(i) => (decode(&pair[..i])?, decode(&pair[i + 1..])?),
        };
        if k.is_empty() || out.contains_key(&k) {
            return fail("duplicateParam");
        }
        out.insert(k, Value::String(v));
    }
    Ok(out)
}

struct Uri {
    scheme: String,
    auth: String,
    server: String,
    port: Option<u32>,
    q: Map<String, Value>,
    name: String,
}

fn uri(line: &str) -> Result<Uri> {
    // ^([a-z0-9]+):\/\/([^?#]*)(?:\?([^#]*))?(?:#(.*))?$ (case-insensitive)
    let Some(sep) = line.find("://") else {
        return fail("format");
    };
    let scheme = &line[..sep];
    if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return fail("format");
    }
    let rest = &line[sep + 3..];
    let body_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let mut body = &rest[..body_end];
    let mut tail = &rest[body_end..];
    let mut query_text = None;
    if let Some(stripped) = tail.strip_prefix('?') {
        let end = stripped.find('#').unwrap_or(stripped.len());
        query_text = Some(&stripped[..end]);
        tail = &stripped[end..];
    }
    let fragment = tail.strip_prefix('#');
    if !tail.is_empty() && fragment.is_none() {
        return fail("format");
    }
    if let Some(stripped) = body.strip_suffix('/') {
        body = stripped;
    }
    let Some(at) = body.rfind('@') else {
        return fail("credentials");
    };
    // ^(?:\[([0-9a-fA-F:]+)\]|([^:/\s]+))(?::(\d+))?$
    let address = &body[at + 1..];
    let port_part = |rest: &'_ str| -> Option<Option<String>> {
        match rest {
            "" => Some(None),
            text => text.strip_prefix(':').filter(|digits| all_digits(digits)).map(|digits| Some(digits.to_string())),
        }
    };
    let bracketed = address.strip_prefix('[').and_then(|inner| {
        let close = inner.find(']')?;
        let host = &inner[..close];
        if host.is_empty() || !host.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
            return None;
        }
        port_part(&inner[close + 1..]).map(|port| (host.to_string(), port))
    });
    let (host, port_digits) = match bracketed {
        Some(found) => found,
        None => {
            let end = address.find(':').unwrap_or(address.len());
            let host = &address[..end];
            if host.is_empty() || host.chars().any(|c| c == '/' || is_js_space(c)) {
                return fail("address");
            }
            let Some(port) = port_part(&address[end..]) else {
                return fail("address");
            };
            (host.to_string(), port)
        }
    };
    let host = host.as_str();
    let auth = decode(&body[..at])?;
    let server = hostname(host)?;
    let port = match port_digits {
        Some(digits) => Some(port(&json!(digits))?),
        None => None,
    };
    let q = query(query_text.unwrap_or(""))?;
    let name = decode(fragment.unwrap_or(""))?;
    Ok(Uri { scheme: scheme.to_lowercase(), auth, server, port, q, name })
}

const COMMON: [&str; 19] = [
    "type", "security", "sni", "peer", "alpn", "fp", "pbk", "sid", "spx", "flow", "encryption", "path", "host", "serviceName", "mode", "authority",
    "headerType", "allowInsecure", "insecure",
];

fn qv<'a>(q: &'a Map<String, Value>, key: &str) -> &'a Value {
    q.get(key).unwrap_or(&Value::Null)
}

fn is(value: &Value, text: &str) -> bool {
    value.as_str() == Some(text)
}

fn transport(n: &mut Map<String, Value>, q: &Map<String, Value>, driver: &str) -> Result<()> {
    let ty = if is(qv(q, "type"), "raw") { json!("tcp") } else { js::or(qv(q, "type"), &json!("tcp")).clone() };
    if !["tcp", "ws", "grpc", "http", "h2"].iter().any(|t| is(&ty, t)) {
        return fail("transport");
    }
    let header = qv(q, "headerType");
    if truthy(header) && !is(header, "none") {
        return fail("tcpHeader");
    }
    let mode = qv(q, "mode");
    if truthy(mode) && !is(mode, "gun") {
        return fail("grpcMode");
    }
    if truthy(qv(q, "authority")) {
        return fail("grpcAuthority");
    }
    let spx = qv(q, "spx");
    if truthy(spx) && !is(spx, "/") {
        return fail("spiderX");
    }
    let ty = if is(&ty, "http") { json!("h2") } else { ty };
    let path = js::or(qv(q, "path"), &json!("/")).clone();
    let host = js::or(qv(q, "host"), &json!("")).clone();
    let service = js::or(qv(q, "serviceName"), &json!("")).clone();
    if path.as_str().map(|p| utf16_len(p) > 2048).unwrap_or(false) || has_control(&js::string(&path)) {
        return fail("path");
    }
    if truthy(&host) {
        hostname(&js::string(&host))?;
    }
    if truthy(&service) {
        let s = js::string(&service);
        let ok = !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'));
        if !ok {
            return fail("grpcService");
        }
    }
    if is(&ty, "grpc") && !truthy(&service) {
        return fail("grpcServiceMissing");
    }
    // The driver's protocol mapping is deliberately explicit, never silently TCP.
    if driver == "mihomo" && is(&n["type"], "trojan") && is(&ty, "h2") {
        return fail("mihomoTrojan");
    }
    n.insert("transport".into(), json!({"type": ty, "path": path, "host": host, "service": service}));
    Ok(())
}

const FINGERPRINTS: [&str; 10] = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];

fn tls(n: &mut Map<String, Value>, q: &Map<String, Value>, default_security: Option<&str>) -> Result<()> {
    let fallback = json!(default_security.unwrap_or("none"));
    let security = js::or(qv(q, "security"), &fallback).clone();
    if !["none", "tls", "reality"].iter().any(|s| is(&security, s)) {
        return fail("tlsType");
    }
    if is(&security, "none") {
        if ["pbk", "sid", "sni", "peer", "alpn", "fp"].iter().any(|k| truthy(qv(q, k))) || bool_param(qv(q, "allowInsecure"))? || bool_param(qv(q, "insecure"))? {
            return fail("tlsNone");
        }
        return Ok(());
    }
    let server_name = js::first(&[qv(q, "sni"), qv(q, "peer"), &n["server"]]).clone();
    let insecure = bool_param(qv(q, "allowInsecure"))? || bool_param(qv(q, "insecure"))?;
    let mut t = Map::new();
    t.insert("server_name".into(), server_name.clone());
    t.insert("insecure".into(), json!(insecure));
    hostname(&js::string(&server_name))?;
    if truthy(qv(q, "alpn")) {
        let list: Vec<String> = js::string(qv(q, "alpn")).split(',').map(str::to_string).collect();
        if list.iter().any(|v| v.is_empty() || utf16_len(v) > 64 || v.chars().any(|c| !('\x21'..='\x7e').contains(&c))) {
            return fail("alpn");
        }
        t.insert("alpn".into(), json!(list));
    }
    if truthy(qv(q, "fp")) {
        if !FINGERPRINTS.iter().any(|f| is(qv(q, "fp"), f)) {
            return fail("fingerprint");
        }
        t.insert("fingerprint".into(), qv(q, "fp").clone());
    }
    if is(&security, "reality") {
        let pbk = js::string(js::or(qv(q, "pbk"), &json!("")));
        let sid = js::string(js::or(qv(q, "sid"), &json!("")));
        let pbk_ok = pbk.len() == 43 && pbk.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        let sid_ok = sid.len() % 2 == 0 && sid.len() <= 16 && sid.chars().all(|c| c.is_ascii_hexdigit());
        if !is(&n["type"], "vless") || !pbk_ok || !sid_ok {
            return fail("reality");
        }
        if insecure {
            return fail("realityInsecure");
        }
        t.insert("reality".into(), json!({"public_key": qv(q, "pbk"), "short_id": js::or(qv(q, "sid"), &json!(""))}));
        if !truthy(t.get("fingerprint").unwrap_or(&Value::Null)) {
            t.insert("fingerprint".into(), json!("chrome"));
        }
    } else if truthy(qv(q, "pbk")) || truthy(qv(q, "sid")) {
        return fail("realityConflict");
    }
    n.insert("tls".into(), Value::Object(t));
    Ok(())
}

const SS_CIPHERS: [&str; 8] = [
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
];
const VMESS_KEYS: [&str; 19] =
    ["v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure", "insecure", "vcn", "pcs"];

fn starts_with_ci(text: &str, prefix: &str) -> bool {
    text.len() >= prefix.len() && text.is_char_boundary(prefix.len()) && text[..prefix.len()].eq_ignore_ascii_case(prefix)
}

fn parse_vmess_json(line: &str, driver: &str) -> Result<Map<String, Value>> {
    let parsed = base64(&line[8..]).ok().and_then(|text| serde_json::from_str::<Value>(&text).ok());
    let Some(v) = parsed else {
        return fail("vmessJSON");
    };
    let Value::Object(v) = v else {
        return fail("vmessObject");
    };
    allowed(&v, &VMESS_KEYS)?;
    let get = |key: &str| v.get(key).unwrap_or(&Value::Null);
    if truthy(get("vcn")) || truthy(get("pcs")) {
        return fail("vmessCert");
    }
    if !get("aid").is_null() && js::string(get("aid")) != "0" {
        return fail("vmessAEAD");
    }
    let mut n = Map::new();
    n.insert("type".into(), json!("vmess"));
    n.insert("name".into(), json!(js::string(js::or(get("ps"), &json!("")))));
    n.insert("server".into(), json!(hostname(&js::string(js::or(get("add"), &json!(""))))?));
    n.insert("port".into(), json!(port(get("port"))?));
    n.insert("uuid".into(), json!(uuid(&js::string(js::or(get("id"), &json!(""))))?));
    n.insert("cipher".into(), js::or(get("scy"), &json!("auto")).clone());
    let mut q = Map::new();
    q.insert("type".into(), js::or(get("net"), &json!("tcp")).clone());
    q.insert("path".into(), get("path").clone());
    q.insert("host".into(), get("host").clone());
    q.insert("security".into(), js::or(get("tls"), &json!("none")).clone());
    for key in ["sni", "alpn", "fp", "allowInsecure", "insecure"] {
        q.insert(key.into(), get(key).clone());
    }
    if truthy(get("type")) && !is(get("type"), "none") {
        return fail("vmessHeader");
    }
    if is(&q["type"], "grpc") {
        let path = q["path"].clone();
        q.insert("serviceName".into(), path);
        q.insert("path".into(), json!(""));
    }
    transport(&mut n, &q, driver)?;
    tls(&mut n, &q, None)?;
    Ok(n)
}

fn parse_one(line: &str, driver: &str) -> Result<Map<String, Value>> {
    let mut n;
    if starts_with_ci(line, "vmess://") && !line.contains('@') {
        n = parse_vmess_json(line, driver)?;
    } else {
        let mut line = line.to_string();
        // Legacy SS encodes the entire method:password@host:port authority.
        if starts_with_ci(&line, "ss://") {
            let rest = &line[5..];
            let hash = rest.find('#');
            let body = &rest[..hash.unwrap_or(rest.len())];
            if !body.is_empty() && !body.contains(['@', '?', '#']) {
                let tail = hash.map(|h| rest[h..].to_string()).unwrap_or_default();
                line = format!("ss://{}{}", base64(body)?, tail);
            }
        }
        let u = uri(&line)?;
        let q = &u.q;
        n = Map::new();
        let ty = if u.scheme == "hy2" { "hysteria2".to_string() } else { u.scheme.clone() };
        n.insert("type".into(), json!(ty));
        n.insert("name".into(), json!(u.name));
        n.insert("server".into(), json!(u.server));
        n.insert("port".into(), u.port.map(Value::from).unwrap_or(Value::Null));
        match ty.as_str() {
            "ss" => {
                allowed(q, &[])?;
                let mut auth = u.auth.clone();
                if !auth.contains(':') {
                    auth = base64(&auth)?;
                }
                let i = auth.find(':').unwrap_or(0);
                if i < 1 {
                    return fail("ssCredentials");
                }
                let method = auth[..i].to_string();
                n.insert("method".into(), json!(method));
                n.insert("password".into(), json!(text(&json!(&auth[i + 1..]), "label.ssPassword")?));
                if !SS_CIPHERS.contains(&method.as_str()) {
                    return fail("ssCipher");
                }
                if driver == "sing_box" && method == "aes-192-gcm" {
                    return fail("ssCipherSingBox");
                }
            }
            "vless" | "vmess" | "trojan" => {
                allowed(q, &COMMON)?;
                if ty == "trojan" {
                    n.insert("password".into(), json!(text(&json!(u.auth), "label.trojanPassword")?));
                } else {
                    n.insert("uuid".into(), json!(uuid(&u.auth)?));
                }
                let encryption = qv(q, "encryption");
                let flow = qv(q, "flow");
                if ty == "vless" {
                    if truthy(encryption) && !is(encryption, "none") {
                        return fail("vlessEncryption");
                    }
                    if truthy(flow) && !is(flow, "xtls-rprx-vision") {
                        return fail("vlessFlow");
                    }
                    if truthy(flow) {
                        n.insert("flow".into(), flow.clone());
                    }
                } else if ty == "vmess" {
                    if truthy(flow) {
                        return fail("vmessFlow");
                    }
                    n.insert("cipher".into(), js::or(encryption, &json!("auto")).clone());
                } else if truthy(flow) || truthy(encryption) {
                    return fail("trojanParams");
                }
                transport(&mut n, q, driver)?;
                tls(&mut n, q, Some(if ty == "trojan" { "tls" } else { "none" }))?;
                if ty == "trojan" && !n.contains_key("tls") {
                    return fail("trojanTLS");
                }
                if n.contains_key("flow") && (!n.contains_key("tls") || !is(&n["transport"]["type"], "tcp")) {
                    return fail("vision");
                }
            }
            "anytls" => {
                allowed(q, &["sni", "insecure", "allowInsecure", "alpn", "fp", "security", "type", "headerType"])?;
                let security = qv(q, "security");
                if truthy(security) && !is(security, "tls") {
                    return fail("anytlsSecurity");
                }
                let ty = qv(q, "type");
                if truthy(ty) && !is(ty, "tcp") && !is(ty, "raw") {
                    return fail("anytlsTransport");
                }
                let header = qv(q, "headerType");
                if truthy(header) && !is(header, "none") {
                    return fail("anytlsHeader");
                }
                if !truthy(&n["port"]) {
                    n.insert("port".into(), json!(443));
                }
                n.insert("password".into(), json!(text(&json!(u.auth), "label.anytlsPassword")?));
                tls(&mut n, q, Some("tls"))?;
            }
            "hysteria2" => {
                allowed(q, &["sni", "insecure", "obfs", "obfs-password"])?;
                if !truthy(&n["port"]) {
                    n.insert("port".into(), json!(443));
                }
                n.insert("password".into(), json!(text(&json!(u.auth), "label.hy2Password")?));
                let mut tq = Map::new();
                tq.insert("sni".into(), qv(q, "sni").clone());
                tq.insert("insecure".into(), qv(q, "insecure").clone());
                tls(&mut n, &tq, Some("tls"))?;
                let obfs = qv(q, "obfs");
                if truthy(obfs) {
                    if !is(obfs, "salamander") {
                        return fail("obfs");
                    }
                    let password = text(qv(q, "obfs-password"), "label.obfsPassword")?;
                    n.insert("obfs".into(), json!({"type": obfs, "password": password}));
                } else if truthy(qv(q, "obfs-password")) {
                    return fail("obfsType");
                }
            }
            _ => return fail("protocol"),
        }
        if !truthy(&n["port"]) {
            return fail("portMissing");
        }
    }
    if is(&n["type"], "vmess") && !["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"].iter().any(|c| is(&n["cipher"], c)) {
        return fail("vmessCipher");
    }
    let name = slice_utf16(&strip_control(&js::string(&n["name"])), 128);
    n.insert("name".into(), json!(name));
    Ok(n)
}

fn starts_like_uri(source: &str) -> bool {
    // ^[a-z][a-z0-9+.-]*:\/\/ (case-insensitive)
    let Some(sep) = source.find("://") else {
        return false;
    };
    let scheme = source[..sep].as_bytes();
    !scheme.is_empty() && scheme[0].is_ascii_alphabetic() && scheme.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

/// Every node of a share text (links, or Base64 of them).
pub fn parse(value: &Value, driver: &str) -> Result<Vec<Map<String, Value>>> {
    if driver != "mihomo" && driver != "sing_box" {
        return fail("driver");
    }
    let raw = js::string(js::or(value, &json!("")));
    let mut source = js_trim(&raw).to_string();
    if source.is_empty() || source.len() > LIMIT {
        return fail("size");
    }
    if !starts_like_uri(&source) {
        source = js_trim(&base64(&source)?).to_string();
    }
    let lines: Vec<&str> = source.split('\n').map(|line| js_trim(line.strip_suffix('\r').unwrap_or(line))).filter(|line| !line.is_empty()).collect();
    if lines.is_empty() || lines.len() > MAX_NODES {
        return fail("count");
    }
    let mut nodes = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        match parse_one(line, driver) {
            Ok(mut n) => {
                if js::string(&n["name"]).is_empty() {
                    let name = format!("{} {}", js::string(&n["type"]).to_uppercase(), i + 1);
                    n.insert("name".into(), json!(name));
                }
                nodes.push(n);
            }
            Err(err) => return Err(Error::msg(format!("第 {} 个节点：{}", i + 1, err))),
        }
    }
    Ok(nodes)
}

fn list(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        other => js::string(js::or(other, &json!("")))
            .split([',', '\n'])
            .map(|v| js_trim(v).to_string())
            .filter(|v| !v.is_empty())
            .map(Value::String)
            .collect(),
    }
}

/// The advanced settings with their defaults.
pub fn options(raw: &Value) -> Result<Value> {
    let raw = if truthy(raw) { raw.clone() } else { json!({}) };
    let Value::Object(map) = &raw else {
        return fail("options");
    };
    allowed(map, &["direct_cidrs", "direct_domains", "dns_hijack", "bootstrap_dns", "proxy_dns"])?;
    let cidrs = list(g(&raw, "direct_cidrs"));
    let domains = list(g(&raw, "direct_domains"));
    let dns_hijack = bool_param(g(&raw, "dns_hijack"))?;
    let bootstrap = js::or(g(&raw, "bootstrap_dns"), &json!("223.5.5.5")).clone();
    let proxy = js::or(g(&raw, "proxy_dns"), &json!("1.1.1.1")).clone();
    if cidrs.len() > 128 || domains.len() > 128 {
        return fail("ruleCount");
    }
    for cidr in &cidrs {
        let text = js::string(cidr);
        let parts: Vec<&str> = text.split('/').collect();
        let max = if parts[0].contains(':') { 128 } else { 32 };
        if parts.len() != 2 || !ip(parts[0]) || !all_digits(parts[1]) || parts[1].parse::<f64>().unwrap_or(f64::MAX) > max as f64 {
            return fail("cidr");
        }
    }
    let mut lowered = Vec::with_capacity(domains.len());
    for domain in &domains {
        let text = js::string(domain);
        // ^\.?\*?\.?
        let mut rest = text.as_str();
        rest = rest.strip_prefix('.').unwrap_or(rest);
        rest = rest.strip_prefix('*').unwrap_or(rest);
        rest = rest.strip_prefix('.').unwrap_or(rest);
        lowered.push(Value::String(hostname(rest)?.to_lowercase()));
    }
    if !ipv4(&js::string(&bootstrap)) || !bootstrap.is_string() || !ipv4(&js::string(&proxy)) || !proxy.is_string() {
        return fail("dns");
    }
    Ok(json!({"direct_cidrs": cidrs, "direct_domains": lowered, "dns_hijack": dns_hijack, "bootstrap_dns": bootstrap, "proxy_dns": proxy}))
}

/// Front hops in dialing order: via[0] is dialed from the uplink and the
/// selected node is reached through the last one.
pub fn via(raw: &Value, count: usize, selected: &Value) -> Result<Vec<usize>> {
    if raw.is_null() || is(raw, "") {
        return Ok(Vec::new());
    }
    let items = match raw {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    if items.len() > MAX_VIA {
        return Err(Error::msg(format!("最多可设置 {MAX_VIA} 个前置节点")));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        let text = js::string(item);
        let n = text.parse::<f64>().unwrap_or(f64::MAX);
        if !all_digits(&text) || n >= count as f64 {
            return fail("via");
        }
        out.push(n as usize);
    }
    let selected = js::number(selected);
    if out.iter().enumerate().any(|(i, v)| *v as f64 == selected || out.iter().position(|o| o == v) != Some(i)) {
        return fail("viaConflict");
    }
    Ok(out)
}

/// The saved form of an import: {veer_proxy: 1, driver, links, selected, via?, options}.
pub fn create(driver: &str, source: &Value, selected: &Value, raw_options: &Value, raw_via: &Value) -> Result<Value> {
    let nodes = parse(source, driver)?;
    let index = if selected.is_null() { 0.0 } else { js::number(selected) };
    if !index.is_finite() || index.floor() != index || index < 0.0 || index >= nodes.len() as f64 {
        return fail("selected");
    }
    let hops = via(raw_via, nodes.len(), &json!(index))?;
    let mut value = json!({"veer_proxy": 1, "driver": driver, "links": source, "selected": index as u64});
    if !hops.is_empty() {
        value["via"] = json!(hops);
    }
    value["options"] = options(raw_options)?;
    // runtime_query has a 64 KiB response bound, including JSON escaping.
    let summary = json!({"nodes": nodes.iter().map(|n| json!({"name": n["name"], "type": n["type"]})).collect::<Vec<_>>(), "options": value["options"]});
    let text = summary.to_string();
    // Go's JSON encoder additionally escapes HTML and line separators.
    let extra: usize = text.chars().map(|c| if matches!(c, '<' | '>' | '&' | '\u{2028}' | '\u{2029}') { 6usize.saturating_sub(c.len_utf8()) } else { 0 }).sum();
    if text.len() + extra > 48 * 1024 {
        return fail("summary");
    }
    Ok(value)
}

/// What the page shows of a saved configuration, without credentials.
pub fn metadata(value: &Value) -> Result<Value> {
    if !truthy(value) || !js::strict_eq(g(value, "veer_proxy"), &json!(1)) {
        return Ok(json!({"mode": "native"}));
    }
    let driver = js::string(g(value, "driver"));
    let nodes = parse(g(value, "links"), &driver)?;
    Ok(json!({
        "mode": "links",
        "driver": value["driver"],
        "nodes": nodes.iter().map(|n| json!({"name": n["name"], "type": n["type"]})).collect::<Vec<_>>(),
        "selected": value.get("selected").cloned().unwrap_or(Value::Null),
        "via": via(g(value, "via"), nodes.len(), g(value, "selected"))?,
        "options": options(g(value, "options"))?,
    }))
}

fn proxy(n: &Map<String, Value>, driver: &str, tag: &str) -> Value {
    let m = driver == "mihomo";
    let get = |key: &str| n.get(key).cloned().unwrap_or(Value::Null);
    let ty = js::string(&get("type"));
    let mut p = Map::new();
    if m {
        p.insert("name".into(), json!(tag));
        p.insert("type".into(), get("type"));
        p.insert("server".into(), get("server"));
        p.insert("port".into(), get("port"));
        p.insert("udp".into(), json!(true));
    } else {
        p.insert("tag".into(), json!(tag));
        p.insert("type".into(), if ty == "ss" { json!("shadowsocks") } else { get("type") });
        p.insert("server".into(), get("server"));
        p.insert("server_port".into(), get("port"));
    }
    match ty.as_str() {
        "ss" => {
            p.insert((if m { "cipher" } else { "method" }).into(), get("method"));
            p.insert("password".into(), get("password"));
        }
        "vmess" => {
            p.insert("uuid".into(), get("uuid"));
            p.insert((if m { "cipher" } else { "security" }).into(), get("cipher"));
            p.insert((if m { "alterId" } else { "alter_id" }).into(), json!(0));
        }
        "vless" => {
            p.insert("uuid".into(), get("uuid"));
            if truthy(&get("flow")) {
                p.insert("flow".into(), get("flow"));
            }
        }
        _ => {
            p.insert("password".into(), get("password"));
        }
    }
    let tls = get("tls");
    if truthy(&tls) {
        if m {
            if ty == "vmess" || ty == "vless" {
                p.insert("tls".into(), json!(true));
            }
            p.insert((if ty == "vmess" { "servername" } else { "sni" }).into(), tls["server_name"].clone());
            p.insert("skip-cert-verify".into(), tls["insecure"].clone());
            if truthy(g(&tls, "alpn")) {
                p.insert("alpn".into(), tls["alpn"].clone());
            }
            if truthy(g(&tls, "fingerprint")) {
                p.insert("client-fingerprint".into(), tls["fingerprint"].clone());
            }
            if truthy(g(&tls, "reality")) {
                p.insert("reality-opts".into(), json!({"public-key": tls["reality"]["public_key"], "short-id": tls["reality"]["short_id"]}));
            }
        } else {
            let mut t = json!({"enabled": true, "server_name": tls["server_name"], "insecure": tls["insecure"]});
            if truthy(g(&tls, "alpn")) {
                t["alpn"] = tls["alpn"].clone();
            }
            if truthy(g(&tls, "fingerprint")) {
                t["utls"] = json!({"enabled": true, "fingerprint": tls["fingerprint"]});
            }
            if truthy(g(&tls, "reality")) {
                t["reality"] = json!({"enabled": true, "public_key": tls["reality"]["public_key"], "short_id": tls["reality"]["short_id"]});
            }
            p.insert("tls".into(), t);
        }
    }
    let t = get("transport");
    if truthy(&t) && !is(&t["type"], "tcp") {
        let kind = js::string(&t["type"]);
        let host = &t["host"];
        if m {
            p.insert("network".into(), t["type"].clone());
            match kind.as_str() {
                "ws" => {
                    p.insert("ws-opts".into(), json!({"path": t["path"], "headers": if truthy(host) { json!({"Host": host}) } else { json!({}) }}));
                }
                "grpc" => {
                    p.insert("grpc-opts".into(), json!({"grpc-service-name": t["service"]}));
                }
                "h2" => {
                    p.insert("h2-opts".into(), json!({"path": t["path"], "host": if truthy(host) { json!([host]) } else { json!([]) }}));
                }
                _ => {}
            }
        } else {
            let mut out = json!({"type": if kind == "h2" { json!("http") } else { t["type"].clone() }});
            match kind.as_str() {
                "ws" => {
                    out["path"] = t["path"].clone();
                    if truthy(host) {
                        out["headers"] = json!({"Host": host});
                    }
                }
                "grpc" => out["service_name"] = t["service"].clone(),
                "h2" => {
                    out["path"] = t["path"].clone();
                    if truthy(host) {
                        out["host"] = json!([host]);
                    }
                }
                _ => {}
            }
            p.insert("transport".into(), out);
        }
    }
    let obfs = get("obfs");
    if truthy(&obfs) {
        if m {
            p.insert("obfs".into(), obfs["type"].clone());
            p.insert("obfs-password".into(), obfs["password"].clone());
        } else {
            p.insert("obfs".into(), obfs);
        }
    }
    Value::Object(p)
}

/// A chain dials veer-hop-1 from the uplink; each later hop and finally
/// veer-node connect through the previous hop (sing-box detour, Mihomo
/// dialer-proxy).
fn chain(nodes: &[Map<String, Value>], v: &Value) -> (Value, Vec<Value>) {
    let driver = js::string(&v["driver"]);
    let key = if driver == "mihomo" { "dialer-proxy" } else { "detour" };
    let mut hops = Vec::new();
    for (i, index) in js::array(g(v, "via")).iter().enumerate() {
        let mut p = proxy(&nodes[js::number(index) as usize], &driver, &format!("veer-hop-{}", i + 1));
        if i > 0 {
            p[key] = json!(format!("veer-hop-{i}"));
        }
        hops.push(p);
    }
    let mut main = proxy(&nodes[js::number(&v["selected"]) as usize], &driver, "veer-node");
    if !hops.is_empty() {
        main[key] = json!(format!("veer-hop-{}", hops.len()));
    }
    (main, hops)
}

/// The full core configuration of a saved import.
pub fn generate(value: &Value) -> Result<Value> {
    let driver = js::string(g(value, "driver"));
    let v = create(&driver, g(value, "links"), g(value, "selected"), g(value, "options"), g(value, "via"))?;
    let nodes = parse(&v["links"], &driver)?;
    let o = &v["options"];
    let (main, hops) = chain(&nodes, &v);
    let cidrs = js::array(&o["direct_cidrs"]);
    let domains = js::array(&o["direct_domains"]);
    let dns_hijack = js::is_true(&o["dns_hijack"]);
    if driver == "mihomo" {
        let mut proxies = vec![main];
        proxies.extend(hops);
        let nameserver = if dns_hijack { json!(format!("{}#veer-node", js::string(&o["proxy_dns"]))) } else { o["bootstrap_dns"].clone() };
        let mut c = json!({"mode": "rule", "log-level": "warning", "ipv6": true, "proxies": proxies, "rules": [], "dns": {
            "enable": true, "enhanced-mode": "redir-host", "default-nameserver": [o["bootstrap_dns"]],
            "proxy-server-nameserver": [o["bootstrap_dns"]], "nameserver": [nameserver]}});
        if !domains.is_empty() {
            c["sniffer"] = json!({"enable": true, "parse-pure-ip": true, "override-destination": false,
                "sniff": {"HTTP": {"ports": [80, 8080]}, "TLS": {"ports": [443]}, "QUIC": {"ports": [443]}}});
        }
        let mut rules = Vec::new();
        for cidr in &cidrs {
            let text = js::string(cidr);
            rules.push(json!(format!("{},{text},DIRECT,no-resolve", if text.contains(':') { "IP-CIDR6" } else { "IP-CIDR" })));
        }
        for domain in &domains {
            rules.push(json!(format!("DOMAIN-SUFFIX,{},DIRECT", js::string(domain))));
        }
        rules.push(json!("MATCH,veer-node"));
        c["rules"] = Value::Array(rules);
        if dns_hijack {
            c["tun"] = json!({"dns-hijack": ["any:53", "tcp://any:53"]});
        }
        return Ok(c);
    }
    let mut outbounds = vec![main, json!({"type": "direct", "tag": "direct"})];
    outbounds.extend(hops);
    let mut c = json!({"log": {"level": "warn"}, "outbounds": outbounds,
        "dns": {"servers": [{"type": "udp", "tag": "bootstrap", "server": o["bootstrap_dns"]}], "final": "bootstrap", "strategy": "ipv4_only"},
        "route": {"default_domain_resolver": "bootstrap", "final": "veer-node", "rules": []}});
    let mut rules = Vec::new();
    if !domains.is_empty() {
        rules.push(json!({"action": "sniff", "sniffer": ["http", "tls", "quic"], "timeout": "300ms"}));
    }
    if dns_hijack {
        c["dns"]["servers"].as_array_mut().unwrap().push(json!({"type": "udp", "tag": "remote", "server": o["proxy_dns"], "detour": "veer-node"}));
        c["dns"]["final"] = json!("remote");
        rules.push(json!({"port": 53, "action": "hijack-dns"}));
    }
    if !cidrs.is_empty() {
        rules.push(json!({"ip_cidr": cidrs, "action": "route", "outbound": "direct"}));
    }
    if !domains.is_empty() {
        rules.push(json!({"domain_suffix": domains, "action": "route", "outbound": "direct"}));
    }
    c["route"]["rules"] = Value::Array(rules);
    Ok(c)
}
