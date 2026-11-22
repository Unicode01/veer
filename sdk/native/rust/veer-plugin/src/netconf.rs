//! Shared helpers for plugins that manage Linux links, addresses, routes,
//! rules and neighbors through the host's net.* API, and keep their state in
//! resources. They match the helpers the JavaScript plugins each carried.

use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Value};

use crate::js::{self, get as g, truthy};
use crate::{bail, Host, Result};

/// `text(a || b || ... || '')`.
pub fn first_text(values: &[&Value]) -> String {
    for value in values {
        if truthy(value) {
            return js::text(value);
        }
    }
    String::new()
}

/// `String(value || fallback)` as a key part.
pub fn key_part(value: &Value, fallback: &str) -> String {
    if truthy(value) {
        js::string(value)
    } else {
        fallback.to_string()
    }
}

/// Validates a Linux interface name: at most 15 bytes, no slashes,
/// whitespace or NUL.
pub fn iface_name(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 15 || value.chars().any(|ch| ch == '/' || ch == '\\' || ch.is_whitespace() || ch == '\0') {
        bail!("{label} contains invalid characters or exceeds 15 bytes");
    }
    Ok(value.to_string())
}

/// The interface name, or "" when it is missing or invalid.
pub fn safe_iface_name(value: &Value) -> String {
    let value = js::text(value);
    if value.is_empty() {
        return String::new();
    }
    iface_name(&value, "interface").unwrap_or_default()
}

/// A CIDR list from an array or a single value, trimmed, without blanks.
pub fn cidr_list(value: &Value) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::String(text) if text.is_empty() => Vec::new(),
        Value::Array(items) => items.iter().map(js::text).filter(|item| !item.is_empty()).collect(),
        other => {
            let item = js::text(other);
            if item.is_empty() {
                Vec::new()
            } else {
                vec![item]
            }
        }
    }
}

pub fn ipv4_host_cidr(value: &str) -> String {
    let value = value.trim();
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 || parts.iter().any(|part| part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit())) {
        return String::new();
    }
    if parts.iter().any(|part| part.parse::<u32>().map(|n| n > 255).unwrap_or(true)) {
        return String::new();
    }
    format!("{value}/32")
}

pub fn ipv6_host_cidr(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || !value.contains(':') || value.chars().any(|ch| ch.is_whitespace() || ch == '/') {
        return String::new();
    }
    format!("{value}/128")
}

pub fn is_default_route(dst: &Value) -> bool {
    let dst = js::lower(dst);
    dst.is_empty() || dst == "default" || dst == "0.0.0.0/0" || dst == "::/0"
}

pub fn route_scope(route: &Value, dst: &Value) -> i64 {
    let scope = g(route, "scope");
    if !scope.is_null() && scope != &json!("") {
        return js::int_value(scope, 0, 255, 0);
    }
    if truthy(g(route, "gateway")) || truthy(g(route, "gw")) || is_default_route(dst) {
        return 0;
    }
    253
}

/// The net.route request for a route record, or None when it has no
/// destination or device.
pub fn route_request(default_dev: &str, route: &Value) -> Option<Value> {
    let dst = js::first(&[g(route, "dst"), g(route, "destination"), g(route, "cidr")]);
    if !truthy(dst) {
        return None;
    }
    let dev = safe_iface_name(js::first(&[g(route, "dev"), g(route, "interface"), &json!(default_dev)]));
    if dev.is_empty() {
        return None;
    }
    Some(json!({
        "dst": js::text(dst),
        "dev": dev,
        "gateway": js::first(&[g(route, "gateway"), g(route, "gw"), &json!("")]),
        "src": js::first(&[g(route, "src"), g(route, "source"), &json!("")]),
        "table": js::int_value(g(route, "table"), 0, 2147483647, 0),
        "metric": js::int_value(g(route, "metric"), 0, 2147483647, 0),
        "scope": route_scope(route, dst),
    }))
}

pub fn route_key(request: &Value) -> String {
    [
        js::string(&request["dst"]),
        js::string(&request["dev"]),
        key_part(&request["gateway"], ""),
        key_part(&request["src"], ""),
        key_part(&request["table"], "0"),
        key_part(&request["metric"], "0"),
        key_part(&request["scope"], "0"),
    ]
    .join("|")
}

pub fn route_set(default_dev: &str, routes: &Value) -> HashSet<String> {
    js::array(routes).iter().filter_map(|route| route_request(default_dev, route)).map(|request| route_key(&request)).collect()
}

/// `Number(value) >>> 0`.
pub fn to_uint32(value: &Value) -> u32 {
    let number = js::number(value);
    if !number.is_finite() {
        return 0;
    }
    let truncated = number.trunc() % 4_294_967_296.0;
    let wrapped = if truncated < 0.0 { truncated + 4_294_967_296.0 } else { truncated };
    wrapped as u32
}

/// The net.rule request for a rule record, or None without a priority and table.
pub fn rule_request(rule: &Value) -> Option<Value> {
    let priority = js::int_value(js::or(g(rule, "priority"), g(rule, "pref")), 1, 32765, 0);
    let table = js::int_value(js::or(g(rule, "table"), g(rule, "table_id")), 1, 2147483647, 0);
    if priority == 0 || table == 0 {
        return None;
    }
    let mut request = json!({
        "family": js::lower(js::or(g(rule, "family"), &json!(""))),
        "priority": priority,
        "table": table,
        "src": first_text(&[g(rule, "src"), g(rule, "source"), g(rule, "from")]),
        "dst": first_text(&[g(rule, "dst"), g(rule, "destination"), g(rule, "to")]),
        "invert": js::is_true(g(rule, "invert")),
    });
    let iif = safe_iface_name(js::first(&[g(rule, "iif"), g(rule, "in_interface"), &json!("")]));
    let oif = safe_iface_name(js::first(&[g(rule, "oif"), g(rule, "out_interface"), &json!("")]));
    if !iif.is_empty() {
        request["iif"] = json!(iif);
    }
    if !oif.is_empty() {
        request["oif"] = json!(oif);
    }
    if !g(rule, "mark").is_null() || !g(rule, "fwmark").is_null() {
        let source = if !g(rule, "mark").is_null() { g(rule, "mark") } else { g(rule, "fwmark") };
        request["mark"] = json!(to_uint32(source));
    }
    if !g(rule, "mask").is_null() || !g(rule, "fwmask").is_null() {
        let source = if !g(rule, "mask").is_null() { g(rule, "mask") } else { g(rule, "fwmask") };
        request["mask"] = json!(to_uint32(source));
    }
    Some(request)
}

pub fn rule_key(request: &Value) -> String {
    [
        key_part(&request["family"], ""),
        js::string(&request["priority"]),
        js::string(&request["table"]),
        key_part(&request["src"], ""),
        key_part(&request["dst"], ""),
        key_part(&request["iif"], ""),
        key_part(&request["oif"], ""),
        if request["mark"].is_null() { String::new() } else { js::string(&request["mark"]) },
        if request["mask"].is_null() { String::new() } else { js::string(&request["mask"]) },
        if js::is_true(&request["invert"]) { "1".to_string() } else { "0".to_string() },
    ]
    .join("|")
}

pub fn rule_set(rules: &Value) -> HashSet<String> {
    js::array(rules).iter().filter_map(rule_request).map(|request| rule_key(&request)).collect()
}

/// The net.neigh request for a neighbor record, or None without an interface and IP.
pub fn neighbor_request(default_dev: &str, neighbor: &Value) -> Option<Value> {
    let iface = safe_iface_name(js::first(&[g(neighbor, "interface"), g(neighbor, "dev"), &json!(default_dev)]));
    let ip = first_text(&[g(neighbor, "ip"), g(neighbor, "address")]);
    if iface.is_empty() || ip.is_empty() {
        return None;
    }
    Some(json!({
        "interface": iface,
        "ip": ip,
        "mac": first_text(&[g(neighbor, "mac"), g(neighbor, "lladdr")]),
        "state": js::lower(js::or(g(neighbor, "state"), &json!("permanent"))),
        "vlan": js::int_value(g(neighbor, "vlan"), 0, 4095, 0),
    }))
}

pub fn neighbor_key(request: &Value) -> String {
    [
        js::string(&request["interface"]),
        js::string(&request["ip"]),
        key_part(&request["mac"], ""),
        key_part(&request["state"], ""),
        key_part(&request["vlan"], "0"),
    ]
    .join("|")
}

pub fn neighbor_set(default_dev: &str, neighbors: &Value) -> HashSet<String> {
    js::array(neighbors).iter().filter_map(|neighbor| neighbor_request(default_dev, neighbor)).map(|request| neighbor_key(&request)).collect()
}

pub fn replace_addrs(host: &Host, iface: &str, addrs: &[Value]) -> Result<()> {
    for cidr in addrs {
        host.call("net.addr.replace", json!([{"interface": iface, "cidr": cidr}]))?;
    }
    Ok(())
}

pub fn replace_routes(host: &Host, default_dev: &str, routes: &[Value]) -> Result<()> {
    for route in routes {
        if let Some(request) = route_request(default_dev, route) {
            host.call("net.route.replace", json!([request]))?;
        }
    }
    Ok(())
}

pub fn replace_rules(host: &Host, rules: &[Value]) -> Result<()> {
    for rule in rules {
        if let Some(request) = rule_request(rule) {
            host.call("net.rule.replace", json!([request]))?;
        }
    }
    Ok(())
}

pub fn replace_neighbors(host: &Host, default_dev: &str, neighbors: &[Value]) -> Result<()> {
    for neighbor in neighbors {
        if let Some(request) = neighbor_request(default_dev, neighbor) {
            host.call("net.neigh.replace", json!([request]))?;
        }
    }
    Ok(())
}

/// Deletes the previous addresses the next state no longer has.
pub fn cleanup_removed_addrs(host: &Host, iface: &Value, previous_addrs: &Value, next_iface: &Value, next_addrs: &Value, errors: &mut Vec<String>) {
    let iface = safe_iface_name(iface);
    if iface.is_empty() {
        return;
    }
    let previous = cidr_list(previous_addrs);
    if previous.is_empty() {
        return;
    }
    let next_iface = safe_iface_name(next_iface);
    let next: HashSet<String> = if iface == next_iface { cidr_list(next_addrs).into_iter().collect() } else { HashSet::new() };
    for cidr in previous {
        if next.contains(&cidr) {
            continue;
        }
        if let Err(err) = host.call("net.addr.delete", json!([{"interface": iface, "cidr": cidr}])) {
            errors.push(format!("addr {iface} {cidr}: {err}"));
        }
    }
}

pub fn cleanup_removed_routes(host: &Host, previous_dev: &Value, previous_routes: &Value, next_dev: &Value, next_routes: &Value, errors: &mut Vec<String>) {
    let previous = js::array(previous_routes);
    if previous.is_empty() {
        return;
    }
    let next = route_set(&js::text(next_dev), next_routes);
    for route in previous {
        let Some(request) = route_request(&js::text(previous_dev), &route) else {
            continue;
        };
        if next.contains(&route_key(&request)) {
            continue;
        }
        if let Err(err) = host.call("net.route.delete", json!([request])) {
            errors.push(format!("route {} dev {}: {err}", js::string(&request["dst"]), js::string(&request["dev"])));
        }
    }
}

pub fn cleanup_removed_rules(host: &Host, previous_rules: &Value, next_rules: &Value, errors: &mut Vec<String>) {
    let previous = js::array(previous_rules);
    if previous.is_empty() {
        return;
    }
    let next = rule_set(next_rules);
    for rule in previous {
        let Some(request) = rule_request(&rule) else {
            continue;
        };
        if next.contains(&rule_key(&request)) {
            continue;
        }
        if let Err(err) = host.call("net.rule.delete", json!([request])) {
            errors.push(format!("rule priority {}: {err}", js::string(&request["priority"])));
        }
    }
}

pub fn cleanup_removed_neighbors(host: &Host, previous_dev: &Value, previous_neighbors: &Value, next_dev: &Value, next_neighbors: &Value, errors: &mut Vec<String>) {
    let previous = js::array(previous_neighbors);
    if previous.is_empty() {
        return;
    }
    let next = neighbor_set(&js::text(next_dev), next_neighbors);
    for neighbor in previous {
        let Some(request) = neighbor_request(&js::text(previous_dev), &neighbor) else {
            continue;
        };
        if next.contains(&neighbor_key(&request)) {
            continue;
        }
        if let Err(err) = host.call("net.neigh.delete", json!([request])) {
            errors.push(format!("neighbor {} dev {}: {err}", js::string(&request["ip"]), js::string(&request["interface"])));
        }
    }
}

/// Writes a record unless the stored one already has the same data (ignoring
/// updated_at fields) and enabled flag.
pub fn set_record_if_changed(host: &Host, resource: &str, key: &str, data: &Value, enabled: bool) -> Result<()> {
    if let Some(current) = host.resources_get(resource, key)? {
        let current_data = js::or(g(&current, "data"), &Value::Null);
        let current_enabled = !js::is_false(g(&current, "enabled"));
        if current_enabled == enabled && js::stable_json(current_data) == js::stable_json(data) {
            return Ok(());
        }
    }
    host.resources_set(resource, key, data, enabled)
}

/// Records keyed by `token(record.key || 'default')`.
pub fn records_by_key(records: &[Value]) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        out.insert(record_token(record), record.clone());
    }
    out
}

/// `token(record.key || 'default')`.
pub fn record_token(record: &Value) -> String {
    js::token(js::or(g(record, "key"), &json!("default")))
}

/// The stored version of each record that has a revision (skipping those
/// deleted since), and records without one as the caller supplied them.
pub fn current_records(host: &Host, resource: &str, records: &[Value]) -> Result<Vec<Value>> {
    let mut out = Vec::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        if !(js::number(g(record, "revision")) > 0.0) {
            out.push(record.clone());
            continue;
        }
        if let Some(stored) = host.resources_get(resource, &js::text(g(record, "key")))? {
            out.push(stored);
        }
    }
    Ok(out)
}

/// The stored records with `records` replacing or appending by key.
pub fn merged_records(host: &Host, resource: &str, records: &[Value]) -> Result<Vec<Value>> {
    let mut out: Vec<Value> = Vec::new();
    let mut positions: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for stored in host.resources_list(resource)?.into_iter().filter(|record| !record.is_null()) {
        positions.insert(record_token(&stored), out.len());
        out.push(stored);
    }
    for record in records.iter().filter(|record| !record.is_null()) {
        let key = record_token(record);
        match positions.get(&key) {
            Some(position) => out[*position] = record.clone(),
            None => {
                positions.insert(key, out.len());
                out.push(record.clone());
            }
        }
    }
    Ok(out)
}

/// The events of a (possibly batched) event message: ctx.events, or
/// ctx.event alone.
pub fn events(ctx: &Value) -> Vec<Value> {
    match g(ctx, "events") {
        Value::Array(items) if !items.is_empty() => items.clone(),
        _ => vec![g(ctx, "event").clone()],
    }
}

/// Arms a one-shot timer unless it is already waiting, so the first event
/// of a burst sets when the repair runs.
pub fn arm_once(host: &Host, name: &str, delay_ms: u64) -> Result<()> {
    if host.timer_pending(name)? {
        return Ok(());
    }
    host.timer_set_timeout(name, delay_ms, &json!({}))
}
