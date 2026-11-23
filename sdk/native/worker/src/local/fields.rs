//! Reading request objects the way the host's bindings read them
//! (objectField, requiredStringObjectField, parsePluginControlUint and friends
//! in internal/app/plugin_control_runtime.go), with Go's error texts.

use veer_plugin::{js, Value};

use super::Failure;

/// obj.Get(field): None when the field is missing or null.
pub fn field<'a>(object: &'a Value, name: &str) -> Option<&'a Value> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(value) => Some(value),
    }
}

/// value.String(), trimmed.
pub fn text(value: &Value) -> String {
    js::string(value).trim().to_string()
}

/// ToInteger: JavaScript Number(), truncated; NaN is 0.
pub fn integer(value: &Value) -> i64 {
    let number = js::number(value);
    if number.is_nan() {
        0
    } else {
        number.trunc().clamp(i64::MIN as f64, i64::MAX as f64) as i64
    }
}

/// requiredObjectArg: the host wraps a primitive in an object, whose fields
/// then read as missing.
pub fn required_object<'a>(args: &'a [Value], index: usize, name: &str) -> Result<&'a Value, Failure> {
    match args.get(index) {
        None | Some(Value::Null) => Err(Failure::error(format!("{name} is required"))),
        Some(value) => Ok(value),
    }
}

/// requiredStringObjectField.
pub fn required_string(object: &Value, name: &str) -> Result<String, Failure> {
    let Some(raw) = field(object, name) else {
        return Err(Failure::error(format!("{name} is required")));
    };
    let value = text(raw);
    if value.is_empty() || value.contains('\0') || value.len() > 64 {
        return Err(Failure::error(format!("{name} is required")));
    }
    Ok(value)
}

/// optionalStringObjectField.
pub fn optional_string(object: &Value, name: &str) -> String {
    field(object, name).map(text).unwrap_or_default()
}

/// strconv.Quote for the values these errors repeat.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// parsePluginControlUint: decimal or 0x hex, within `bits`, with
/// strconv.ParseUint's errors.
pub fn parse_uint(value: Option<&Value>, bits: u32) -> Result<u64, String> {
    let Some(value) = value else {
        return Err("value is required".to_string());
    };
    let raw = text(value);
    if raw.is_empty() {
        return Err("value is required".to_string());
    }
    let (digits, radix) = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(rest) => (rest, 16),
        None => (raw.as_str(), 10),
    };
    let syntax = || format!("strconv.ParseUint: parsing {}: invalid syntax", quote(digits));
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return Err(syntax());
    }
    let max = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
    match u64::from_str_radix(digits, radix) {
        Ok(parsed) if parsed <= max => Ok(parsed),
        _ => Err(format!("strconv.ParseUint: parsing {}: value out of range", quote(digits))),
    }
}

/// optionalUintObjectField.
pub fn optional_uint(object: &Value, name: &str, bits: u32) -> Result<Option<u64>, Failure> {
    let Some(value) = field(object, name) else {
        return Ok(None);
    };
    parse_uint(Some(value), bits).map(Some).map_err(|err| Failure::error(format!("{name}: {err}")))
}

/// parsePluginControlEtherType.
pub fn ethertype(value: Option<&Value>) -> Result<u16, String> {
    let parsed = parse_uint(value, 16)?;
    if parsed == 0 {
        return Err("ethertype must be non-zero".to_string());
    }
    Ok(parsed as u16)
}

/// net.ParseMAC, then the host's 6-byte check (parsePluginControlMAC).
pub fn parse_mac(value: &str) -> Result<[u8; 6], String> {
    let value = value.trim();
    let invalid = || format!("address {value}: invalid MAC address");
    let bytes = value.as_bytes();
    if bytes.len() < 14 {
        return Err(invalid());
    }
    let hex = |s: &[u8]| -> Option<u8> { std::str::from_utf8(s).ok().and_then(|text| u8::from_str_radix(text, 16).ok()).filter(|_| s.iter().all(u8::is_ascii_hexdigit)) };
    let mut out = Vec::new();
    if bytes[2] == b':' || bytes[2] == b'-' {
        if (bytes.len() + 1) % 3 != 0 {
            return Err(invalid());
        }
        let n = (bytes.len() + 1) / 3;
        if n != 6 && n != 8 && n != 20 {
            return Err(invalid());
        }
        for i in 0..n {
            let at = i * 3;
            out.push(hex(&bytes[at..at + 2]).ok_or_else(invalid)?);
            if i + 1 < n && bytes[at + 2] != bytes[2] {
                return Err(invalid());
            }
        }
    } else if bytes[4] == b'.' {
        if (bytes.len() + 1) % 5 != 0 {
            return Err(invalid());
        }
        let n = 2 * (bytes.len() + 1) / 5;
        if n != 6 && n != 8 && n != 20 {
            return Err(invalid());
        }
        for i in (0..n).step_by(2) {
            let at = i / 2 * 5;
            out.push(hex(&bytes[at..at + 2]).ok_or_else(invalid)?);
            out.push(hex(&bytes[at + 2..at + 4]).ok_or_else(invalid)?);
            if i + 2 < n && bytes[at + 4] != b'.' {
                return Err(invalid());
            }
        }
    } else {
        return Err(invalid());
    }
    <[u8; 6]>::try_from(out.as_slice()).map_err(|_| "expected 6-byte ethernet MAC".to_string())
}

/// HardwareAddr.String().
pub fn format_mac(mac: &[u8]) -> String {
    mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

/// decodePluginControlHexBytes with hex.DecodeString's errors.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    let value = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    let cleaned: Vec<char> = value.chars().filter(|c| !matches!(c, ' ' | '\t' | '\n' | '\r' | ':' | '-' | '_')).collect();
    if cleaned.is_empty() {
        return Err("empty hex string".to_string());
    }
    if cleaned.len() % 2 != 0 {
        return Err("hex string must contain an even number of characters".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.chunks(2) {
        let high = pair[0].to_digit(16).ok_or_else(|| invalid_byte(pair[0]))?;
        let low = pair[1].to_digit(16).ok_or_else(|| invalid_byte(pair[1]))?;
        out.push((high * 16 + low) as u8);
    }
    Ok(out)
}

/// hex.InvalidByteError: "%#U" of the byte.
fn invalid_byte(c: char) -> String {
    if c.is_control() {
        format!("encoding/hex: invalid byte: U+{:04X}", c as u32)
    } else {
        format!("encoding/hex: invalid byte: U+{:04X} '{c}'", c as u32)
    }
}

/// optionalHexObjectField: the first field present, decoded.
pub fn optional_hex(object: &Value, names: &[&str]) -> Result<Option<Vec<u8>>, Failure> {
    for name in names {
        let Some(value) = field(object, name) else {
            continue;
        };
        let raw = text(value);
        if raw.is_empty() {
            continue;
        }
        return decode_hex(&raw).map(Some).map_err(|err| Failure::error(format!("{name}: {err}")));
    }
    Ok(None)
}

pub fn hex(bytes: &[u8]) -> String {
    super::crypto::hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    #[test]
    fn macs_like_net_parse_mac() {
        assert_eq!(parse_mac("02:00:5e:10:00:01").unwrap(), [2, 0, 0x5e, 0x10, 0, 1]);
        assert_eq!(parse_mac("02-00-5E-10-00-01").unwrap(), [2, 0, 0x5e, 0x10, 0, 1]);
        assert_eq!(parse_mac("0200.5e10.0001").unwrap(), [2, 0, 0x5e, 0x10, 0, 1]);
        assert_eq!(parse_mac("ff:ff").unwrap_err(), "address ff:ff: invalid MAC address");
        assert_eq!(parse_mac("02:00:5e:10:00:00:00:01").unwrap_err(), "expected 6-byte ethernet MAC");
        assert!(parse_mac("02:00:5e:10:00-01").is_err());
    }

    #[test]
    fn uints_like_strconv() {
        assert_eq!(parse_uint(Some(&json!("0x8863")), 16).unwrap(), 0x8863);
        assert_eq!(parse_uint(Some(&json!(34916)), 16).unwrap(), 34916);
        assert_eq!(parse_uint(Some(&json!("70000")), 16).unwrap_err(), "strconv.ParseUint: parsing \"70000\": value out of range");
        assert_eq!(parse_uint(Some(&json!("x1")), 8).unwrap_err(), "strconv.ParseUint: parsing \"x1\": invalid syntax");
        assert_eq!(parse_uint(None, 8).unwrap_err(), "value is required");
        assert_eq!(ethertype(Some(&json!(0))).unwrap_err(), "ethertype must be non-zero");
    }

    #[test]
    fn hex_like_go() {
        assert_eq!(decode_hex("0x01:ff").unwrap(), vec![1, 255]);
        assert_eq!(decode_hex("zz").unwrap_err(), "encoding/hex: invalid byte: U+007A 'z'");
        assert_eq!(decode_hex("abc").unwrap_err(), "hex string must contain an even number of characters");
    }

    #[test]
    fn strings_and_objects() {
        let object = json!({"interface": " veer0 ", "blank": "  ", "n": 5});
        assert_eq!(required_string(&object, "interface").unwrap(), "veer0");
        assert_eq!(required_string(&object, "blank").unwrap_err().message, "blank is required");
        assert_eq!(required_string(&object, "missing").unwrap_err().message, "missing is required");
        assert_eq!(required_string(&object, "n").unwrap(), "5");
        assert!(required_object(&[json!(1)], 0, "request").is_ok());
        assert_eq!(required_object(&[], 0, "request").unwrap_err().message, "request is required");
    }
}
