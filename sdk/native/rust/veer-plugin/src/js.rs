//! JavaScript-compatible conversions for plugins ported from the old
//! JavaScript control scripts.
//!
//! Records, payloads and events are loosely typed JSON. These helpers give
//! the same answers the JavaScript code did (`String(v)`, `parseInt`,
//! truthiness, `a || b`), so a port keeps its behaviour on odd input.

use serde_json::{Map, Number, Value};

static NULL: Value = Value::Null;

/// JavaScript truthiness: false for null, false, 0, NaN and "".
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|f| f != 0.0 && !f.is_nan()).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `a || b`.
pub fn or<'a>(a: &'a Value, b: &'a Value) -> &'a Value {
    if truthy(a) {
        a
    } else {
        b
    }
}

/// The first truthy value, or null: `a || b || c`.
pub fn first<'a>(values: &[&'a Value]) -> &'a Value {
    for value in values {
        if truthy(value) {
            return value;
        }
    }
    values.last().copied().unwrap_or(&NULL)
}

/// `value === true`.
pub fn is_true(value: &Value) -> bool {
    matches!(value, Value::Bool(true))
}

/// `value === false`.
pub fn is_false(value: &Value) -> bool {
    matches!(value, Value::Bool(false))
}

/// `value == null` (null or missing).
pub fn is_nullish(value: &Value) -> bool {
    value.is_null()
}

/// `Array.isArray(value) ? value : []`, cloned.
pub fn array(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        _ => Vec::new(),
    }
}

/// `value && typeof value === 'object' && !Array.isArray(value)`.
pub fn is_object(value: &Value) -> bool {
    value.is_object()
}

/// `Object.prototype.hasOwnProperty.call(value, key)`.
pub fn has_own(value: &Value, key: &str) -> bool {
    value.as_object().map(|map| map.contains_key(key)).unwrap_or(false)
}

/// The field or null; JavaScript property access on anything.
pub fn get<'a>(value: &'a Value, key: &str) -> &'a Value {
    match value {
        Value::Object(map) => map.get(key).unwrap_or(&NULL),
        _ => &NULL,
    }
}

/// Formats a number the way `String(number)` does for the values plugins see.
pub fn number_string(number: &Number) -> String {
    if let Some(integer) = number.as_i64() {
        return integer.to_string();
    }
    if let Some(integer) = number.as_u64() {
        return integer.to_string();
    }
    float_string(number.as_f64().unwrap_or(0.0))
}

pub fn float_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_string();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() };
    }
    if value == value.trunc() && value.abs() < 1e21 {
        return format!("{}", value as i128);
    }
    format!("{value}")
}

/// `String(value)`.
pub fn string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number_string(number),
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| if item.is_null() { String::new() } else { string(item) })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// `String(value == null ? '' : value).trim()`.
pub fn text(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    string(value).trim().to_string()
}

/// `text(value).toLowerCase()`.
pub fn lower(value: &Value) -> String {
    text(value).to_lowercase()
}

/// `text` for a string slice.
pub fn text_str(value: &str) -> String {
    value.trim().to_string()
}

/// `parseInt(value, 10)`, or None for NaN.
pub fn parse_int(value: &Value) -> Option<f64> {
    let source = match value {
        Value::Number(number) => {
            // parseInt(String(n)): an integer, or a float's leading digits.
            if let Some(integer) = number.as_i64() {
                return Some(integer as f64);
            }
            if let Some(integer) = number.as_u64() {
                return Some(integer as f64);
            }
            float_string(number.as_f64().unwrap_or(f64::NAN))
        }
        other => string(other),
    };
    let trimmed = source.trim_start();
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let mut result = 0f64;
    let mut seen = false;
    for byte in digits.bytes() {
        if !byte.is_ascii_digit() {
            break;
        }
        seen = true;
        result = result * 10.0 + (byte - b'0') as f64;
    }
    if !seen {
        return None;
    }
    Some(if negative { -result } else { result })
}

/// `intValue(value, min, max, fallback)` from the scripts: parseInt, clamped.
pub fn int_value(value: &Value, min: i64, max: i64, fallback: i64) -> i64 {
    match parse_int(value) {
        None => fallback,
        Some(number) => {
            if number < min as f64 {
                min
            } else if number > max as f64 {
                max
            } else {
                number as i64
            }
        }
    }
}

/// `Number(value)`, or NaN.
pub fn number(value: &Value) -> f64 {
    match value {
        Value::Null => 0.0,
        Value::Bool(flag) => {
            if *flag {
                1.0
            } else {
                0.0
            }
        }
        Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                0.0
            } else if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).map(|v| v as f64).unwrap_or(f64::NAN)
            } else {
                trimmed.parse::<f64>().unwrap_or(f64::NAN)
            }
        }
        Value::Array(items) if items.is_empty() => 0.0,
        Value::Array(items) if items.len() == 1 => number(&items[0]),
        _ => f64::NAN,
    }
}

/// `bool(value, fallback)` from the scripts.
pub fn bool_value(value: &Value, fallback: bool) -> bool {
    match value {
        Value::Bool(flag) => *flag,
        Value::Null => fallback,
        Value::String(text) if text.is_empty() => fallback,
        other => match lower(other).as_str() {
            "true" | "1" | "yes" | "on" => true,
            "false" | "0" | "no" | "off" => false,
            _ => fallback,
        },
    }
}

/// `token(value)`: lower-case, runs of other characters become '-', no
/// leading or trailing '-', "default" when empty.
pub fn token(value: &Value) -> String {
    let source = if truthy(value) { lower(value) } else { "default".to_string() };
    token_str(&source)
}

pub fn token_str(source: &str) -> String {
    let source = source.trim().to_lowercase();
    let mut out = String::with_capacity(source.len());
    let mut dash = false;
    for ch in source.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '.' || ch == '-' {
            out.push(ch);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `merge(a, b)`: a shallow copy of a's fields, then b's.
pub fn merge(a: &Value, b: &Value) -> Value {
    let mut out = Map::new();
    if let Value::Object(map) = a {
        for (key, value) in map {
            out.insert(key.clone(), value.clone());
        }
    }
    if let Value::Object(map) = b {
        for (key, value) in map {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

/// A JS number as JSON the way `JSON.stringify` writes it: integral values
/// as integers (no ".0"), NaN and infinities as null.
pub fn num(value: f64) -> Value {
    if !value.is_finite() {
        return Value::Null;
    }
    if value == value.trunc() && value.abs() <= 9_007_199_254_740_992.0 {
        return Value::from(value as i64);
    }
    serde_json::Number::from_f64(value).map(Value::Number).unwrap_or(Value::Null)
}

/// `a === b`, with numbers compared by value.
pub fn strict_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

/// The number of UTF-8 bytes in a string.
pub fn utf8_len(value: &str) -> usize {
    value.len()
}

/// `JSON.stringify(sortObject(value))` minus `updated_at` fields: the form
/// the scripts used to decide whether a record changed.
pub fn stable_json(value: &Value) -> String {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().filter(|key| key.as_str() != "updated_at").collect();
                keys.sort();
                let mut out = Map::new();
                for key in keys {
                    out.insert(key.clone(), sort(&map[key]));
                }
                Value::Object(out)
            }
            Value::Number(number) => {
                // 1 and 1.0 are the same JavaScript number.
                match number.as_f64() {
                    Some(f) if f == f.trunc() && f.abs() < 9.0e15 => Value::from(f as i64),
                    _ => value.clone(),
                }
            }
            other => other.clone(),
        }
    }
    let mut value = value.clone();
    if let Value::String(text) = &value {
        if let Ok(parsed) = serde_json::from_str::<Value>(text) {
            value = parsed;
        }
    }
    serde_json::to_string(&sort(&value)).unwrap_or_default()
}

/// FNV-1a over UTF-16 code units, `Math.imul(hash, 16777619) >>> 0`.
pub fn fnv1a(value: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for unit in value.encode_utf16() {
        hash ^= unit as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

/// Milliseconds since the Unix epoch, like `Date.now()`.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|elapsed| elapsed.as_millis() as u64).unwrap_or(0)
}

/// `new Date().toISOString()`.
pub fn iso_now() -> String {
    iso_time(now_ms())
}

/// `new Date(ms).toISOString()`: UTC with milliseconds, e.g.
/// 2026-11-22T00:33:38.123Z.
pub fn iso_time(ms: u64) -> String {
    let seconds = ms / 1000;
    let millis = ms % 1000;
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn iso_times_match_javascript() {
        assert_eq!(super::iso_time(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(super::iso_time(1_795_306_418_123), "2026-11-22T00:13:38.123Z");
        assert_eq!(super::iso_time(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn strings_match_javascript() {
        assert_eq!(text(&json!(null)), "");
        assert_eq!(text(&json!(" a ")), "a");
        assert_eq!(text(&json!(12)), "12");
        assert_eq!(text(&json!(1.5)), "1.5");
        assert_eq!(text(&json!(true)), "true");
        assert_eq!(string(&json!([1, null, "x"])), "1,,x");
        assert_eq!(string(&json!({"a": 1})), "[object Object]");
    }

    #[test]
    fn parse_int_matches_javascript() {
        assert_eq!(int_value(&json!("42px"), 0, 100, 7), 42);
        assert_eq!(int_value(&json!(""), 0, 100, 7), 7);
        assert_eq!(int_value(&json!(null), 0, 100, 7), 7);
        assert_eq!(int_value(&json!(true), 0, 100, 7), 7);
        assert_eq!(int_value(&json!(1.9), 0, 100, 7), 1);
        assert_eq!(int_value(&json!(-5), 0, 100, 7), 0);
        assert_eq!(int_value(&json!("900"), 0, 100, 7), 100);
        assert_eq!(int_value(&json!(" 12 "), 0, 100, 7), 12);
    }

    #[test]
    fn tokens_match_javascript() {
        assert_eq!(token(&json!("My WAN!")), "my-wan");
        assert_eq!(token(&json!("")), "default");
        assert_eq!(token(&json!(null)), "default");
        assert_eq!(token(&json!("--a--")), "a");
        assert_eq!(token(&json!(0)), "default");
    }

    #[test]
    fn bools_match_javascript() {
        assert!(bool_value(&json!("yes"), false));
        assert!(!bool_value(&json!("off"), true));
        assert!(bool_value(&json!(null), true));
        assert!(!bool_value(&json!("maybe"), false));
    }

    #[test]
    fn stable_json_ignores_order_and_updated_at() {
        let a = json!({"b": 1, "a": {"updated_at": "x", "c": 2}, "updated_at": "y"});
        let b = json!({"a": {"c": 2.0}, "b": 1});
        assert_eq!(stable_json(&a), stable_json(&b));
    }

    #[test]
    fn fnv_matches_javascript() {
        // ('00000000' + hash.toString(16)).slice(-8) of "veerlocal0|default"
        assert_eq!(fnv1a(""), 2_166_136_261);
        assert_eq!(fnv1a("a"), 0xe40c292c);
    }
}
