//! Shorthands for the host API methods most plugins use. Everything else is
//! reached with [`Host::call`] and the method name.

use serde_json::{json, Value};

use crate::{Host, Result};

impl Host {
    /// `resources.get(resource, key)`: the record, or None.
    pub fn resources_get(&self, resource: &str, key: &str) -> Result<Option<Value>> {
        let value = self.call("resources.get", json!([resource, key]))?;
        Ok(if value.is_null() { None } else { Some(value) })
    }

    /// `resources.get(resource, key).data`, or an empty object.
    pub fn resources_data(&self, resource: &str, key: &str) -> Result<Value> {
        Ok(match self.resources_get(resource, key)? {
            Some(record) => match record.get("data") {
                Some(data) if !data.is_null() => data.clone(),
                _ => json!({}),
            },
            None => json!({}),
        })
    }

    /// `resources.list(resource) || []`.
    pub fn resources_list(&self, resource: &str) -> Result<Vec<Value>> {
        Ok(match self.call("resources.list", json!([resource]))? {
            Value::Array(items) => items,
            _ => Vec::new(),
        })
    }

    /// `resources.set(resource, key, data, enabled)`.
    pub fn resources_set(&self, resource: &str, key: &str, data: &Value, enabled: bool) -> Result<()> {
        self.call("resources.set", json!([resource, key, data, enabled]))?;
        Ok(())
    }

    /// `resources.delete(resource, key)`.
    pub fn resources_delete(&self, resource: &str, key: &str) -> Result<()> {
        self.call("resources.delete", json!([resource, key]))?;
        Ok(())
    }

    /// `kv.get(key)`: the record, or None.
    pub fn kv_get(&self, key: &str) -> Result<Option<Value>> {
        let value = self.call("kv.get", json!([key]))?;
        Ok(if value.is_null() { None } else { Some(value) })
    }

    pub fn kv_set(&self, key: &str, value: &Value) -> Result<()> {
        self.call("kv.set", json!([key, value]))?;
        Ok(())
    }

    pub fn kv_delete(&self, key: &str) -> Result<()> {
        self.call("kv.delete", json!([key]))?;
        Ok(())
    }

    /// `timer.setTimeout(name, delayMs, payload)`.
    pub fn timer_set_timeout(&self, name: &str, delay_ms: u64, payload: &Value) -> Result<()> {
        self.call("timer.setTimeout", json!([name, delay_ms, payload]))?;
        Ok(())
    }

    /// `timer.setInterval(name, delayMs, payload)`.
    pub fn timer_set_interval(&self, name: &str, delay_ms: u64, payload: &Value) -> Result<()> {
        self.call("timer.setInterval", json!([name, delay_ms, payload]))?;
        Ok(())
    }

    pub fn timer_clear(&self, name: &str) -> Result<()> {
        self.call("timer.clear", json!([name]))?;
        Ok(())
    }

    /// `timer.list() || []`.
    pub fn timer_list(&self) -> Result<Vec<Value>> {
        Ok(match self.call("timer.list", json!([]))? {
            Value::Array(items) => items,
            _ => Vec::new(),
        })
    }

    /// True when a timer with this name is set.
    pub fn timer_pending(&self, name: &str) -> Result<bool> {
        Ok(self.timer_list()?.iter().any(|timer| timer.get("name").and_then(Value::as_str) == Some(name)))
    }
}
