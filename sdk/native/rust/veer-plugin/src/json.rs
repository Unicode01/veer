use serde_json::{Map, Value};

static EMPTY_ARRAY: Vec<Value> = Vec::new();
static NULL: Value = Value::Null;

/// Lenient accessors for JSON objects, in the spirit of JavaScript property
/// access: a missing or mistyped field reads as empty.
pub trait ValueExt {
    /// The field, or `null`.
    fn field(&self, key: &str) -> &Value;
    /// Follows a dotted path such as `"event.payload.ifname"`.
    fn path(&self, path: &str) -> &Value;
    /// The string field, or `""`.
    fn str_of(&self, key: &str) -> &str;
    fn opt_str(&self, key: &str) -> Option<&str>;
    /// The field as a string when it is a string, number or bool; `""` otherwise.
    fn text_of(&self, key: &str) -> String;
    fn bool_of(&self, key: &str) -> bool;
    fn i64_of(&self, key: &str) -> i64;
    fn u64_of(&self, key: &str) -> u64;
    fn f64_of(&self, key: &str) -> f64;
    /// The array field, or an empty slice.
    fn arr_of(&self, key: &str) -> &[Value];
    fn obj_of(&self, key: &str) -> Option<&Map<String, Value>>;
    /// True for null, false, 0, "" and empty arrays/objects: JavaScript-ish falsiness
    /// plus empty containers.
    fn is_empty_value(&self) -> bool;
}

impl ValueExt for Value {
    fn field(&self, key: &str) -> &Value {
        match self {
            Value::Object(map) => map.get(key).unwrap_or(&NULL),
            _ => &NULL,
        }
    }

    fn path(&self, path: &str) -> &Value {
        let mut current = self;
        for part in path.split('.') {
            current = current.field(part);
        }
        current
    }

    fn str_of(&self, key: &str) -> &str {
        self.field(key).as_str().unwrap_or("")
    }

    fn opt_str(&self, key: &str) -> Option<&str> {
        self.field(key).as_str()
    }

    fn text_of(&self, key: &str) -> String {
        match self.field(key) {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            _ => String::new(),
        }
    }

    fn bool_of(&self, key: &str) -> bool {
        self.field(key).as_bool().unwrap_or(false)
    }

    fn i64_of(&self, key: &str) -> i64 {
        let value = self.field(key);
        value.as_i64().or_else(|| value.as_f64().map(|f| f as i64)).unwrap_or(0)
    }

    fn u64_of(&self, key: &str) -> u64 {
        let value = self.field(key);
        value.as_u64().or_else(|| value.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64)).unwrap_or(0)
    }

    fn f64_of(&self, key: &str) -> f64 {
        self.field(key).as_f64().unwrap_or(0.0)
    }

    fn arr_of(&self, key: &str) -> &[Value] {
        match self.field(key) {
            Value::Array(items) => items.as_slice(),
            _ => EMPTY_ARRAY.as_slice(),
        }
    }

    fn obj_of(&self, key: &str) -> Option<&Map<String, Value>> {
        self.field(key).as_object()
    }

    fn is_empty_value(&self) -> bool {
        match self {
            Value::Null => true,
            Value::Bool(flag) => !flag,
            Value::Number(number) => number.as_f64() == Some(0.0),
            Value::String(text) => text.is_empty(),
            Value::Array(items) => items.is_empty(),
            Value::Object(map) => map.is_empty(),
        }
    }
}
