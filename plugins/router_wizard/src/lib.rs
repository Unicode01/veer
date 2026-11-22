//! Router Wizard: one WAN/LAN router configuration. It owns no dataplane;
//! applying the configuration calls the WAN, PPPoE and LAN plugins through
//! their typed services, as a journaled operation that resumes after a
//! restart and rolls back on failure.

#![recursion_limit = "256"]

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::netconf::{iface_name, set_record_if_changed};
use veer_plugin::{bail, export_plugin, json, Error, Host, Message, Outcome, Plugin, Result, Value};

const CONFIG_RESOURCE: &str = "config";
const CONFIG_KEY: &str = "default";
const ROUTER_OPERATION_KEY: &str = "router_default";
const ROUTER_APPLY_OPERATION: &str = "router.apply";
const ROUTER_TEARDOWN_OPERATION: &str = "router.teardown";
const ROUTER_RECOVERY_TIMER: &str = "router_operation_recovery";

fn service_for(plugin_id: &str) -> Option<&'static str> {
    match plugin_id {
        "wan_core" => Some("wan.adapter"),
        "lan_core" => Some("lan.adapter"),
        "pppoe_client" => Some("pppoe.client"),
        "vtolocal" => Some("local.handoff"),
        _ => None,
    }
}

pub struct RouterWizard;

impl Plugin for RouterWizard {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(RouterWizard)
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        let ctx = &msg.ctx;
        match msg.handler.as_str() {
            "onReconcile" => {
                resume_router_operations(host)?;
                match stored_config(host)? {
                    None => {
                        let status = refresh_status(host, &default_config()?, "not_configured", &[])?;
                        set_record_if_changed(host, "status", CONFIG_KEY, &status, false)?;
                    }
                    Some(cfg) => {
                        let previous = previous_status(host);
                        let phase = js::text(js::or(g(&previous, "phase"), &json!("stored")));
                        let steps = js::array(g(&previous, "steps"));
                        let status = refresh_status(host, &cfg, &phase, &steps)?;
                        set_record_if_changed(host, "status", CONFIG_KEY, &status, true)?;
                    }
                }
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                cancel_active_router_operation(host, "router wizard deactivated")?;
                if let Some(cfg) = stored_config(host)? {
                    teardown_router_attempt(host, &cfg)?;
                }
                Ok(Outcome::Done)
            }
            "onTimer" => {
                if js::text(g(g(ctx, "timer"), "name")) == ROUTER_RECOVERY_TIMER {
                    resume_router_operations(host)?;
                }
                Ok(Outcome::Done)
            }
            "onAction" => {
                let payload = js::or(g(ctx, "payload"), &json!({})).clone();
                match js::text(g(g(ctx, "action"), "id")).as_str() {
                    "apply_router" => Ok(Outcome::Value(apply_router(host, &payload)?)),
                    "teardown_router" => Ok(Outcome::Value(teardown_router(host, &payload)?)),
                    "refresh_status" => {
                        let cfg = load_config_from_payload(host, &payload)?;
                        let status = refresh_status(host, &cfg, "refreshed", &[])?;
                        set_record_if_changed(host, "status", CONFIG_KEY, &status, true)?;
                        Ok(Outcome::Value(status))
                    }
                    other => bail!("unsupported action {other}"),
                }
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(RouterWizard, "router_wizard");

fn operations(host: &Host, method: &str, args: Value) -> Result<Value> {
    host.call(&format!("operations.{method}"), args)
}

fn apply_router(host: &Host, payload: &Value) -> Result<Value> {
    let cfg = load_config_from_payload(host, payload)?;
    let previous = stored_config_record(host);
    let operation = operations(
        host,
        "begin",
        json!([{"key": ROUTER_OPERATION_KEY, "kind": ROUTER_APPLY_OPERATION, "input": {"config": cfg, "previous": previous},
            "state": {"phase": "pending"}, "restart": true}]),
    )?;
    arm_router_operation_recovery(host)?;
    run_router_operation(host, &operation)
}

fn teardown_router(host: &Host, payload: &Value) -> Result<Value> {
    let cfg = load_config_from_payload(host, payload)?;
    let operation = operations(
        host,
        "begin",
        json!([{"key": ROUTER_OPERATION_KEY, "kind": ROUTER_TEARDOWN_OPERATION, "input": {"config": cfg},
            "state": {"phase": "pending"}, "restart": true}]),
    )?;
    arm_router_operation_recovery(host)?;
    run_router_operation(host, &operation)
}

struct Compensation {
    name: &'static str,
    plugin: &'static str,
    action: &'static str,
    /// The payload, or the error building it raised (the step's failure).
    payload: std::result::Result<Value, String>,
}

fn apply_router_attempt(host: &Host, cfg: &Value, previous: &Value) -> Result<Value> {
    let mut steps = Vec::new();
    let mut compensations = Vec::new();
    match apply_router_config(host, cfg, &mut steps, &mut compensations) {
        Ok(()) => {
            let status = refresh_status(host, cfg, "applied", &steps)?;
            set_record_if_changed(host, "status", CONFIG_KEY, &status, true)?;
            set_record_if_changed(host, CONFIG_RESOURCE, CONFIG_KEY, cfg, true)?;
            Ok(status)
        }
        Err(apply_error) => {
            let rollback_steps = run_compensations(host, &compensations);
            let mut restore_steps = Vec::new();
            let mut restore_rollback_steps = Vec::new();
            if let Some(previous_config) = enabled_config_from_record(previous) {
                let mut restore_compensations = Vec::new();
                if let Err(restore_error) = apply_router_config(host, &previous_config, &mut restore_steps, &mut restore_compensations) {
                    restore_rollback_steps = run_compensations(host, &restore_compensations);
                    restore_steps.push(failed_step("restore.previous", &restore_error));
                }
            }
            let rollback_failed = has_failed_step(&rollback_steps) || has_failed_step(&restore_steps) || has_failed_step(&restore_rollback_steps);
            let mut failure_status = refresh_status(host, cfg, if rollback_failed { "rollback_partial" } else { "rolled_back" }, &steps)?;
            failure_status["last_error"] = json!(apply_error.to_string());
            failure_status["rollback_steps"] = json!(rollback_steps);
            failure_status["restore_steps"] = json!(restore_steps);
            failure_status["restore_rollback_steps"] = json!(restore_rollback_steps);
            set_record_if_changed(host, "status", CONFIG_KEY, &failure_status, false)?;
            bail!("{}", router_apply_failure_message(&apply_error, &[&rollback_steps, &restore_steps, &restore_rollback_steps]))
        }
    }
}

fn apply_router_config(host: &Host, cfg: &Value, steps: &mut Vec<Value>, compensations: &mut Vec<Compensation>) -> Result<()> {
    if js::text(&cfg["wan"]["mode"]) == "pppoe" {
        compensations.push(Compensation { name: "wan_core.teardown", plugin: "wan_core", action: "teardown", payload: Ok(wan_core_payload(cfg)) });
        run_required_step(steps, "wan_core.prepare_handoff", || call_action(host, "wan_core", "prepare_handoff", &wan_core_prepare_payload(cfg)))?;
        let pppoe = pppoe_payload(cfg);
        compensations.push(Compensation {
            name: "pppoe_client.disconnect",
            plugin: "pppoe_client",
            action: "disconnect",
            payload: pppoe.as_ref().map(Value::clone).map_err(|err| err.to_string()),
        });
        run_required_step(steps, "pppoe_client.dial", || call_action(host, "pppoe_client", "dial", &pppoe?))?;
    } else {
        run_required_step(steps, "wan.existing", || {
            if !truthy(&cfg["wan"]["egress_interface"]) {
                bail!("WAN egress interface is required");
            }
            Ok(json!({"phase": "ok"}))
        })?;
    }
    let lan = lan_payload(cfg);
    compensations.push(Compensation {
        name: "lan_core.teardown",
        plugin: "lan_core",
        action: "teardown",
        payload: lan.as_ref().map(Value::clone).map_err(|err| err.to_string()),
    });
    run_required_step(steps, "lan_core.apply_network", || call_action(host, "lan_core", "apply_network", &lan?))?;
    Ok(())
}

fn teardown_router_attempt(host: &Host, cfg: &Value) -> Result<Value> {
    let mut steps = Vec::new();
    set_record_if_changed(host, CONFIG_RESOURCE, CONFIG_KEY, cfg, false)?;
    run_step(&mut steps, "lan_core.teardown", || call_action(host, "lan_core", "teardown", &lan_payload(cfg)?));
    if js::text(&cfg["wan"]["mode"]) == "pppoe" {
        run_step(&mut steps, "pppoe_client.disconnect", || call_action(host, "pppoe_client", "disconnect", &pppoe_payload(cfg)?));
        run_step(&mut steps, "wan_core.teardown", || call_action(host, "wan_core", "teardown", &wan_core_payload(cfg)));
    }
    let failed = has_failed_step(&steps);
    let status = refresh_status(host, cfg, if failed { "teardown_partial" } else { "deleted" }, &steps)?;
    set_record_if_changed(host, "status", CONFIG_KEY, &status, false)?;
    if failed {
        bail!("{}", first_failed_step_message(&steps));
    }
    Ok(status)
}

fn run_router_operation(host: &Host, operation: &Value) -> Result<Value> {
    if !truthy(g(operation, "id")) {
        bail!("router operation is unavailable");
    }
    if !truthy(g(operation, "resumable")) {
        if truthy(g(operation, "result")) {
            return Ok(operation["result"].clone());
        }
        let phase = js::text(js::or(g(operation, "status"), &json!("idle")));
        return refresh_status(host, &default_config()?, &phase, &[]);
    }
    let claimed = operations(host, "claim", json!([operation["id"], operation["revision"]]))?;
    let attempt = (|| -> Result<Value> {
        let input = js::or(g(&claimed, "input"), &json!({})).clone();
        let kind = js::text(g(&claimed, "kind"));
        let result = if kind == ROUTER_APPLY_OPERATION {
            let cfg = normalize_config(js::or(g(&input, "config"), &json!({})))?;
            apply_router_attempt(host, &cfg, js::or(g(&input, "previous"), &Value::Null))?
        } else if kind == ROUTER_TEARDOWN_OPERATION {
            teardown_router_attempt(host, &normalize_config(js::or(g(&input, "config"), &json!({})))?)?
        } else {
            bail!("unsupported router operation kind {kind}");
        };
        let completed = operations(host, "complete", json!([claimed["id"], claimed["revision"], js::or(&result, &json!({}))]))?;
        settle_router_operation_recovery(host)?;
        Ok(if truthy(g(&completed, "result")) { completed["result"].clone() } else { result })
    })();
    match attempt {
        Ok(result) => Ok(result),
        Err(error) => {
            let current = operations(host, "get", json!([claimed["id"]]))?;
            if js::text(g(&current, "status")) == "running" {
                let failure = json!({"phase": "failed", "state": {"failed_at": js::iso_now(), "error": error.to_string()}, "error": error.to_string()});
                if let Err(journal_error) = operations(host, "fail", json!([current["id"], current["revision"], failure])) {
                    bail!("{error}; persist router operation failure: {journal_error}");
                }
            }
            settle_router_operation_recovery(host)?;
            Err(error)
        }
    }
}

fn resume_router_operations(host: &Host) -> Result<()> {
    let pending = js::array(&operations(host, "list", json!([{"resumable": true, "limit": 8}]))?);
    if pending.is_empty() {
        return settle_router_operation_recovery(host);
    }
    arm_router_operation_recovery(host)?;
    for operation in &pending {
        if js::text(g(operation, "key")) != ROUTER_OPERATION_KEY {
            continue;
        }
        if let Err(error) = run_router_operation(host, operation) {
            host.call("log.warn", json!([format!("router operation recovery failed: {error}")]))?;
        }
    }
    settle_router_operation_recovery(host)
}

fn arm_router_operation_recovery(host: &Host) -> Result<()> {
    host.timer_set_interval(ROUTER_RECOVERY_TIMER, 2000, &json!({}))
}

fn settle_router_operation_recovery(host: &Host) -> Result<()> {
    let active = js::array(&operations(host, "list", json!([{"limit": 8}]))?).iter().any(|operation| {
        let status = js::text(g(operation, "status"));
        js::text(g(operation, "key")) == ROUTER_OPERATION_KEY && (status == "pending" || status == "running" || status == "retry_wait")
    });
    if !active {
        host.timer_clear(ROUTER_RECOVERY_TIMER)?;
    }
    Ok(())
}

fn cancel_active_router_operation(host: &Host, reason: &str) -> Result<()> {
    let operation = operations(host, "getByKey", json!([ROUTER_OPERATION_KEY]))?;
    let status = js::text(g(&operation, "status"));
    if !truthy(&operation) || (status != "pending" && status != "running") {
        return Ok(());
    }
    let cancelled = operations(host, "claim", json!([operation["id"], operation["revision"]])).and_then(|claimed| {
        operations(
            host,
            "cancel",
            json!([claimed["id"], claimed["revision"], {"phase": "cancelled", "state": {"cancelled_at": js::iso_now()}, "error": reason}]),
        )
    });
    if let Err(error) = cancelled {
        host.call("log.warn", json!([format!("cancel router operation failed: {error}")]))?;
    }
    settle_router_operation_recovery(host)
}

fn success_step(name: &str, result: &Value) -> Value {
    let detail = if truthy(g(result, "phase")) { result["phase"].clone() } else { json!("ok") };
    json!({"name": name, "ok": true, "detail": detail, "updated_at": js::iso_now()})
}

fn failed_step(name: &str, error: &Error) -> Value {
    json!({"name": name, "ok": false, "error": error.to_string(), "updated_at": js::iso_now()})
}

fn run_step(steps: &mut Vec<Value>, name: &str, step: impl FnOnce() -> Result<Value>) {
    match step() {
        Ok(result) => steps.push(success_step(name, &result)),
        Err(error) => steps.push(failed_step(name, &error)),
    }
}

fn run_required_step(steps: &mut Vec<Value>, name: &str, step: impl FnOnce() -> Result<Value>) -> Result<Value> {
    match step() {
        Ok(result) => {
            steps.push(success_step(name, &result));
            Ok(result)
        }
        Err(error) => {
            steps.push(failed_step(name, &error));
            Err(error)
        }
    }
}

fn run_compensations(host: &Host, compensations: &[Compensation]) -> Vec<Value> {
    compensations
        .iter()
        .rev()
        .map(|item| {
            let result = match &item.payload {
                Ok(payload) => call_action(host, item.plugin, item.action, payload),
                Err(message) => Err(Error::msg(message.clone())),
            };
            match result {
                Ok(result) => success_step(item.name, &result),
                Err(error) => failed_step(item.name, &error),
            }
        })
        .collect()
}

fn has_failed_step(steps: &[Value]) -> bool {
    steps.iter().any(|step| js::is_false(g(step, "ok")))
}

fn router_apply_failure_message(error: &Error, groups: &[&[Value]]) -> String {
    let failures: Vec<String> = groups
        .iter()
        .flat_map(|steps| steps.iter())
        .filter(|step| js::is_false(g(step, "ok")))
        .map(|step| format!("{}: {}", js::string(g(step, "name")), js::string(g(step, "error"))))
        .collect();
    let mut message = error.to_string();
    if !failures.is_empty() {
        message.push_str("; rollback: ");
        message.push_str(&failures.join("; "));
    }
    message
}

fn first_failed_step_message(steps: &[Value]) -> String {
    for step in steps {
        if js::is_false(g(step, "ok")) {
            return format!("{}: {}", js::string(g(step, "name")), js::string(g(step, "error")));
        }
    }
    "router wizard failed".to_string()
}

fn refresh_status(host: &Host, cfg: &Value, phase: &str, steps: &[Value]) -> Result<Value> {
    let wan_ref = js::text(&cfg["wan"]["ref"]);
    let lan_id = js::text(&cfg["lan"]["id"]);
    let pppoe = js::text(&cfg["wan"]["mode"]) == "pppoe";
    let wan_status = read_plugin_record(host, "wan_core", "status", &wan_ref);
    let lan_status = read_plugin_record(host, "lan_core", "status", &lan_id);
    let egress_plan = read_plugin_record(host, "lan_core", "egress_nat_plans", &lan_id);
    let pppoe_link = if pppoe { read_plugin_record(host, "pppoe_client", "wan_links", &wan_ref) } else { not_used_record("pppoe disabled") };
    let pppoe_last = if pppoe { read_plugin_record(host, "pppoe_client", "sessions", "last") } else { not_used_record("pppoe disabled") };
    Ok(json!({
        "phase": phase,
        "wan_mode": cfg["wan"]["mode"],
        "wan_ref": cfg["wan"]["ref"],
        "lan_id": cfg["lan"]["id"],
        "lan_bridge": cfg["lan"]["bridge"],
        "lan_ports": cfg["lan"]["ports"],
        "wan_egress_interface": effective_wan_interface(cfg, &wan_status, &pppoe_link),
        "auto_egress_nat": cfg["lan"]["auto_egress_nat"],
        "steps": steps,
        "downstream": {
            "wan_core": compact_record(&wan_status),
            "lan_core": compact_record(&lan_status),
            "egress_nat": compact_record(&egress_plan),
            "pppoe_link": compact_record(&pppoe_link),
            "pppoe_last": compact_record(&pppoe_last),
        },
        "updated_at": js::iso_now(),
    }))
}

fn read_plugin_record(host: &Host, plugin_id: &str, resource_id: &str, key: &str) -> Value {
    if key.is_empty() {
        return not_configured_record("empty record key");
    }
    let listed = require_service_endpoint(host, plugin_id, "resources", resource_id)
        .and_then(|_| host.call("plugins.resources.list", json!([plugin_id, resource_id, {"limit": 128, "offset": 0}])));
    match listed {
        Ok(records) => {
            let records = js::array(&records);
            if let Some(record) = records.iter().find(|record| js::text(g(record, "key")) == key && g(record, "key").is_string()) {
                return record.clone();
            }
            json!({"enabled": false, "data": {
                "phase": "not_configured", "configured": false, "record_key": key, "record_count_hint": records.len(),
                "note": "downstream plugin/resource is reachable, but this record does not exist yet",
            }})
        }
        Err(error) => unavailable_record(&error.to_string()),
    }
}

fn unavailable_record(message: &str) -> Value {
    json!({"enabled": false, "data": {"phase": "unavailable", "available": false, "last_error": message}})
}

fn not_configured_record(note: &str) -> Value {
    json!({"enabled": false, "data": {"phase": "not_configured", "configured": false, "note": note}})
}

fn not_used_record(note: &str) -> Value {
    json!({"enabled": false, "data": {"phase": "not_used", "configured": false, "note": note}})
}

fn first_text(values: &[&Value]) -> String {
    veer_plugin::netconf::first_text(values)
}

fn compact_record(record: &Value) -> Value {
    if !truthy(record) {
        return json!({"available": false, "configured": false, "phase": "unavailable"});
    }
    let data = js::or(g(record, "data"), &json!({})).clone();
    let phase = first_text(&[g(&data, "phase"), g(&data, "state")]);
    let plan_out = g(g(&data, "egress_nat_plan"), "out_interface");
    json!({
        "available": !js::is_false(g(&data, "available")),
        "configured": phase != "not_configured" && phase != "not_used" && phase != "unavailable",
        "enabled": !js::is_false(g(record, "enabled")),
        "phase": if phase.is_empty() { "available".to_string() } else { phase.clone() },
        "interface": first_text(&[g(&data, "interface"), g(&data, "local_interface"), g(&data, "wan_interface"), g(&data, "bridge"), g(&data, "out_interface")]),
        "parent_interface": first_text(&[g(&data, "veer_parent_interface"), g(&data, "egress_nat_parent_interface"), g(&data, "parent_interface")]),
        "out_interface": first_text(&[g(&data, "out_interface"), plan_out]),
        "source_ip": first_text(&[g(&data, "out_source_ip"), g(&data, "ipv4"), g(&data, "wan_egress_source_ip")]),
        "last_error": first_text(&[g(&data, "last_error"), g(&data, "error")]),
        "note": first_text(&[g(&data, "note")]),
        "updated_at": first_text(&[g(&data, "updated_at")]),
        "data": data,
    })
}

fn call_action(host: &Host, plugin_id: &str, action_id: &str, payload: &Value) -> Result<Value> {
    let service = require_service_endpoint(host, plugin_id, "actions", action_id)?;
    host.call(
        "plugins.services.call",
        json!([{"service": service["id"], "version": "^1.0.0", "provider": plugin_id, "action": action_id, "payload": js::or(payload, &json!({}))}]),
    )
}

fn require_service_endpoint(host: &Host, plugin_id: &str, endpoint_kind: &str, endpoint_id: &str) -> Result<Value> {
    let Some(service_id) = service_for(plugin_id) else {
        bail!("no typed service is declared for plugin {plugin_id}");
    };
    let provider = host.call("plugins.services.resolve", json!([{"service": service_id, "version": "^1.0.0", "provider": plugin_id}]))?;
    let service = g(&provider, "service");
    let exposed = match g(service, endpoint_kind) {
        Value::Array(endpoints) => endpoints.iter().any(|endpoint| endpoint.as_str() == Some(endpoint_id)),
        _ => false,
    };
    if !exposed {
        bail!("service {service_id} from {plugin_id} does not expose {endpoint_kind} endpoint {endpoint_id}");
    }
    Ok(service.clone())
}

fn load_config_from_payload(host: &Host, payload: &Value) -> Result<Value> {
    let previous = stored_config(host)?;
    let mut cfg = normalize_config(&js::merge(previous.as_ref().unwrap_or(&json!({})), payload))?;
    let wan = if truthy(g(payload, "wan")) { g(payload, "wan") } else { payload };
    let pppoe = js::or(g(wan, "pppoe"), &json!({})).clone();
    let password = first_defined(&[g(&pppoe, "password"), g(wan, "password"), g(payload, "pppoe_password"), g(payload, "password")]);
    let redacted = password.as_str() == Some("__redacted__");
    match &previous {
        Some(previous) if password.is_null() || redacted => {
            cfg["wan"]["pppoe"]["password"] = previous["wan"]["pppoe"]["password"].clone();
        }
        None if redacted => bail!("No saved PPPoE password is available"),
        _ => {}
    }
    Ok(cfg)
}

fn stored_config(host: &Host) -> Result<Option<Value>> {
    let record = stored_config_record(host);
    if truthy(g(&record, "data")) {
        Ok(Some(normalize_config(&record["data"])?))
    } else {
        Ok(None)
    }
}

fn stored_config_record(host: &Host) -> Value {
    host.resources_get(CONFIG_RESOURCE, CONFIG_KEY).ok().flatten().unwrap_or(Value::Null)
}

fn enabled_config_from_record(record: &Value) -> Option<Value> {
    if !truthy(record) || js::is_false(g(record, "enabled")) || !truthy(g(record, "data")) {
        return None;
    }
    normalize_config(&record["data"]).ok()
}

fn previous_status(host: &Host) -> Value {
    match host.resources_get("status", CONFIG_KEY) {
        Ok(Some(record)) if truthy(g(&record, "data")) => record["data"].clone(),
        _ => json!({}),
    }
}

fn default_config() -> Result<Value> {
    normalize_config(&json!({"lan": {"dhcpv4_enabled": true, "dns_mode": "auto"}}))
}

/// `firstDefined(...)`: the first value that is not undefined, null or "".
fn first_defined(values: &[&Value]) -> Value {
    for value in values {
        match value {
            Value::Null => {}
            Value::String(text) if text.is_empty() => {}
            other => return (*other).clone(),
        }
    }
    Value::Null
}

/// `value && typeof value === 'object' ? value : fallback`.
fn object_or<'a>(value: &'a Value, fallback: &'a Value) -> &'a Value {
    if value.is_object() || value.is_array() {
        value
    } else {
        fallback
    }
}

pub(crate) fn normalize_config(raw: &Value) -> Result<Value> {
    let empty = json!({});
    let raw = if raw.is_null() { &empty } else { raw };
    let wan = object_or(g(raw, "wan"), raw);
    let pppoe = object_or(g(wan, "pppoe"), &empty);
    let lan = object_or(g(raw, "lan"), raw);
    let mode = js::lower(js::first(&[g(wan, "mode"), g(raw, "wan_mode"), &json!("existing")]));
    if mode != "existing" && mode != "pppoe" {
        bail!("WAN mode must be existing or pppoe");
    }
    let bridge = iface_name(&js::text(js::first(&[g(lan, "bridge"), g(raw, "lan_bridge"), g(raw, "bridge"), &json!("br-lan")])), "LAN bridge")?;
    let manual_mac = truthy(js::first(&[g(pppoe, "mac_address"), g(wan, "mac_address"), g(raw, "pppoe_mac_address")]));
    let pick = |fields: &[&Value]| first_defined(fields);
    Ok(json!({
        "wan": {
            "mode": mode,
            "ref": js::token(js::first(&[g(wan, "ref"), g(raw, "wan_ref"), &json!("default")])),
            "egress_interface": optional_iface_name(js::first(&[g(wan, "egress_interface"), g(raw, "wan_egress_interface"), g(raw, "out_interface"), &json!("")]))?,
            "source_ip": first_text(&[g(wan, "source_ip"), g(raw, "wan_egress_source_ip"), g(raw, "out_source_ip")]),
            "local_interface": iface_name(&js::text(js::first(&[g(wan, "local_interface"), g(raw, "wan_local_interface"), &json!("veerlocal0")])), "WAN local interface")?,
            "mtu": js::int_value(js::first(&[g(wan, "mtu"), g(raw, "wan_mtu"), g(raw, "mru")]), 576, 65535, 1492),
            "pppoe": {
                "interface": optional_iface_name(&pick(&[g(pppoe, "interface"), g(wan, "pppoe_interface"), g(raw, "pppoe_interface"), g(raw, "interface")]))?,
                "mac_mode": normalize_mac_mode(&pick(&[g(pppoe, "mac_mode"), g(wan, "mac_mode"), g(raw, "pppoe_mac_mode"), &json!(if manual_mac { "manual" } else { "random" })]))?,
                "mac_address": js::text(&pick(&[g(pppoe, "mac_address"), g(wan, "mac_address"), g(raw, "pppoe_mac_address")])),
                "username": js::text(&pick(&[g(pppoe, "username"), g(wan, "username"), g(raw, "pppoe_username"), g(raw, "username")])),
                "password": js::text(&pick(&[g(pppoe, "password"), g(wan, "password"), g(raw, "pppoe_password"), g(raw, "password")])),
                "service": js::text(&pick(&[g(pppoe, "service"), g(wan, "service"), g(raw, "pppoe_service"), g(raw, "service")])),
                "auth": normalize_auth(&pick(&[g(pppoe, "auth"), g(wan, "auth"), g(raw, "pppoe_auth"), g(raw, "auth"), &json!("pap")]))?,
                "negotiate_ipv6": js::bool_value(&pick(&[g(pppoe, "negotiate_ipv6"), g(wan, "negotiate_ipv6"), g(raw, "pppoe_negotiate_ipv6")]), false),
                "request_ipv6_address": js::bool_value(&pick(&[g(pppoe, "request_ipv6_address"), g(wan, "request_ipv6_address"), g(raw, "pppoe_request_ipv6_address")]), true),
                "request_ipv6_router": js::bool_value(&pick(&[g(pppoe, "request_ipv6_router"), g(wan, "request_ipv6_router"), g(raw, "pppoe_request_ipv6_router")]), true),
                "request_pd": js::bool_value(&pick(&[g(pppoe, "request_pd"), g(wan, "request_pd"), g(raw, "pppoe_request_pd")]), false),
                "dhcpv6_timeout_ms": js::int_value(&pick(&[g(pppoe, "dhcpv6_timeout_ms"), g(wan, "dhcpv6_timeout_ms"), g(raw, "pppoe_dhcpv6_timeout_ms")]), 500, 30000, 5000),
                "dhcpv6_settle_ms": js::int_value(&pick(&[g(pppoe, "dhcpv6_settle_ms"), g(wan, "dhcpv6_settle_ms"), g(raw, "pppoe_dhcpv6_settle_ms")]), 0, 10000, 2000),
                "ipv6_ra_timeout_ms": js::int_value(&pick(&[g(pppoe, "ipv6_ra_timeout_ms"), g(wan, "ipv6_ra_timeout_ms"), g(raw, "pppoe_ipv6_ra_timeout_ms")]), 500, 30000, 5000),
                "install_tunnel": js::bool_value(&pick(&[g(pppoe, "install_tunnel"), g(wan, "install_tunnel"), g(raw, "pppoe_install_tunnel")]), true),
                "auto_redial": js::bool_value(&pick(&[g(pppoe, "auto_redial"), g(wan, "auto_redial"), g(raw, "pppoe_auto_redial")]), true),
                "keepalive_interval_ms": js::int_value(&pick(&[g(pppoe, "keepalive_interval_ms"), g(wan, "keepalive_interval_ms"), g(raw, "pppoe_keepalive_interval_ms")]), 0, 86400000, 15000),
                "keepalive_failure_threshold": js::int_value(&pick(&[g(pppoe, "keepalive_failure_threshold"), g(wan, "keepalive_failure_threshold"), g(raw, "pppoe_keepalive_failure_threshold")]), 1, 10, 5),
                "keepalive_failure_grace_ms": js::int_value(&pick(&[g(pppoe, "keepalive_failure_grace_ms"), g(wan, "keepalive_failure_grace_ms"), g(raw, "pppoe_keepalive_failure_grace_ms")]), 0, 3600000, 60000),
                "keepalive_confirm_timeout_ms": js::int_value(&pick(&[g(pppoe, "keepalive_confirm_timeout_ms"), g(wan, "keepalive_confirm_timeout_ms"), g(raw, "pppoe_keepalive_confirm_timeout_ms")]), 100, 30000, 5000),
            },
        },
        "lan": {
            "id": js::token(js::first(&[g(lan, "id"), g(raw, "lan_id"), &json!("default")])),
            "bridge": bridge,
            "ports": iface_list(js::first(&[g(lan, "ports"), g(raw, "lan_ports"), g(raw, "ports"), &json!([])]))?,
            "addresses": split_cidr_list(js::first(&[g(lan, "addresses"), g(raw, "lan_addresses"), g(raw, "addresses"), &json!("192.168.100.1/24")])),
            "mtu": js::int_value(js::first(&[g(lan, "mtu"), g(raw, "lan_mtu"), g(raw, "mtu")]), 576, 65535, 1500),
            "preserve_bridge": js::bool_value(&pick(&[g(lan, "preserve_bridge"), g(raw, "preserve_bridge")]), is_protected_bridge_name(&bridge)),
            "dhcpv4_enabled": js::bool_value(&pick(&[g(lan, "dhcpv4_enabled"), g(raw, "dhcpv4_enabled")]), false),
            "dns_mode": normalize_dns_mode(&pick(&[g(lan, "dns_mode"), g(raw, "dns_mode"), &json!("auto")]))?,
            "dns_servers": dns_server_list(&pick(&[g(lan, "dns_servers"), g(raw, "dns_servers"), &json!([])])),
            "auto_egress_nat": js::bool_value(&pick(&[g(lan, "auto_egress_nat"), g(raw, "auto_egress_nat")]), true),
            "protocol": normalize_protocol(js::first(&[g(lan, "protocol"), g(raw, "egress_nat_protocol"), g(raw, "protocol"), &json!("tcp+udp+icmp")]))?,
            "nat_type": first_text(&[g(lan, "nat_type"), g(raw, "egress_nat_type"), g(raw, "nat_type"), &json!("symmetric")]),
            "redirect_mode": normalize_redirect_mode(js::first(&[g(lan, "redirect_mode"), g(raw, "redirect_mode"), g(raw, "egress_nat_redirect_mode"), &json!("")])),
        },
    }))
}

fn pppoe_payload(cfg: &Value) -> Result<Value> {
    let pppoe = &cfg["wan"]["pppoe"];
    if !truthy(&pppoe["interface"]) {
        bail!("PPPoE interface is required");
    }
    if !truthy(&pppoe["username"]) {
        bail!("PPPoE username is required");
    }
    let ipv6 = js::is_true(&pppoe["negotiate_ipv6"]);
    Ok(json!({
        "profile_key": cfg["wan"]["ref"], "wan_id": cfg["wan"]["ref"], "interface": pppoe["interface"],
        "mac_mode": pppoe["mac_mode"], "mac_address": pppoe["mac_address"], "username": pppoe["username"], "password": pppoe["password"],
        "service": pppoe["service"], "auth": pppoe["auth"], "negotiate_ipv4": true, "negotiate_ipv6": pppoe["negotiate_ipv6"],
        "request_ipv6_address": ipv6 && js::is_true(&pppoe["request_ipv6_address"]),
        "request_ipv6_router": ipv6 && js::is_true(&pppoe["request_ipv6_router"]),
        "request_pd": pppoe["request_pd"], "dhcpv6_timeout_ms": pppoe["dhcpv6_timeout_ms"], "dhcpv6_settle_ms": pppoe["dhcpv6_settle_ms"],
        "ipv6_ra_timeout_ms": pppoe["ipv6_ra_timeout_ms"], "auto_redial": pppoe["auto_redial"],
        "keepalive_interval_ms": pppoe["keepalive_interval_ms"], "keepalive_failure_threshold": pppoe["keepalive_failure_threshold"],
        "keepalive_failure_grace_ms": pppoe["keepalive_failure_grace_ms"], "keepalive_confirm_timeout_ms": pppoe["keepalive_confirm_timeout_ms"],
        "install_tunnel": pppoe["install_tunnel"], "local_interface": cfg["wan"]["local_interface"],
        "wan_core_sync": true, "wan_core_apply": true, "wan_core_plugin": "wan_core", "send_padt": false,
    }))
}

fn wan_core_payload(cfg: &Value) -> Value {
    let pppoe = js::text(&cfg["wan"]["mode"]) == "pppoe";
    json!({
        "key": cfg["wan"]["ref"], "wan_id": cfg["wan"]["ref"], "profile_key": cfg["wan"]["ref"],
        "driver": if pppoe { "pppoe_client" } else { "existing" },
        "driver_plugin": if pppoe { "pppoe_client" } else { "router_wizard" },
        "state": "up", "usable": true,
        "real_interface": js::or(&cfg["wan"]["egress_interface"], &cfg["wan"]["pppoe"]["interface"]),
        "wan_interface": cfg["wan"]["local_interface"], "mtu": cfg["wan"]["mtu"], "local_interface": cfg["wan"]["local_interface"],
        "handoff_mode": if pppoe { "segmented_veth" } else { "direct" },
        "install_default_route": true, "install_default_route_v6": cfg["wan"]["pppoe"]["negotiate_ipv6"],
        "egress_nat_redirect_mode": "",
    })
}

fn wan_core_prepare_payload(cfg: &Value) -> Value {
    let mut payload = wan_core_payload(cfg);
    payload["state"] = json!("prepared");
    payload["usable"] = json!(false);
    payload
}

fn lan_payload(cfg: &Value) -> Result<Value> {
    let existing = js::text(&cfg["wan"]["mode"]) == "existing";
    if existing && !truthy(&cfg["wan"]["egress_interface"]) {
        bail!("WAN egress interface is required");
    }
    let lan = &cfg["lan"];
    Ok(json!({
        "key": lan["id"], "lan_id": lan["id"], "bridge": lan["bridge"], "ports": lan["ports"], "addresses": lan["addresses"],
        "mtu": lan["mtu"], "preserve_bridge": lan["preserve_bridge"], "dhcpv4_enabled": lan["dhcpv4_enabled"],
        "dns_mode": lan["dns_mode"], "dns_servers": lan["dns_servers"], "wan_ref": cfg["wan"]["ref"], "wan_plugin": "wan_core",
        "wan_egress_interface": if existing { cfg["wan"]["egress_interface"].clone() } else { json!("") },
        "wan_egress_source_ip": cfg["wan"]["source_ip"], "auto_egress_nat": lan["auto_egress_nat"], "protocol": lan["protocol"],
        "nat_type": lan["nat_type"],
        "redirect_mode": if existing { lan["redirect_mode"].clone() } else { json!("") },
    }))
}

fn effective_wan_interface(cfg: &Value, wan_status: &Value, pppoe_link: &Value) -> String {
    if truthy(&cfg["wan"]["egress_interface"]) {
        return js::text(&cfg["wan"]["egress_interface"]);
    }
    let wan_data = g(wan_status, "data");
    let link_data = g(pppoe_link, "data");
    let veer_core = g(wan_data, "veer_core");
    first_text(&[
        g(wan_data, "egress_nat_parent_interface"),
        g(veer_core, "egress_nat_interface"),
        g(wan_data, "veer_parent_interface"),
        g(veer_core, "parent_interface"),
        g(wan_data, "local_interface"),
        g(link_data, "local_interface"),
        g(link_data, "wan_interface"),
    ])
}

fn optional_iface_name(value: &Value) -> Result<String> {
    let text = js::text(value);
    if text.is_empty() {
        return Ok(String::new());
    }
    iface_name(&text, "interface")
}

fn iface_list(value: &Value) -> Result<Vec<String>> {
    let raw: Vec<Value> = match value {
        Value::Array(items) => items.clone(),
        other => js::text(other).split(',').map(|item| json!(item)).collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let name = optional_iface_name(&item)?;
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

fn split_cidr_list(value: &Value) -> Vec<String> {
    match value {
        Value::Null => Vec::new(),
        Value::String(text) if text.is_empty() => Vec::new(),
        Value::Array(items) => items.iter().map(js::text).filter(|item| !item.is_empty()).collect(),
        other => js::string(other).split(',').map(|item| item.trim().to_string()).filter(|item| !item.is_empty()).collect(),
    }
}

fn normalize_protocol(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("tcp+udp")));
    let mut seen = std::collections::HashSet::new();
    for part in value.split(|ch: char| !ch.is_ascii_lowercase() && !ch.is_ascii_digit()) {
        if part.is_empty() {
            continue;
        }
        if part != "tcp" && part != "udp" && part != "icmp" {
            bail!("protocol must include tcp, udp or icmp");
        }
        seen.insert(part.to_string());
    }
    let out: Vec<&str> = ["tcp", "udp", "icmp"].into_iter().filter(|name| seen.contains(*name)).collect();
    if out.is_empty() {
        bail!("protocol must include tcp, udp or icmp");
    }
    Ok(out.join("+"))
}

fn normalize_redirect_mode(value: &Value) -> &'static str {
    match js::lower(value).as_str() {
        "prepared_l2" | "raw_l2" | "vtap" => "prepared_l2",
        _ => "",
    }
}

fn normalize_dns_mode(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("auto")));
    match value.as_str() {
        "auto" | "manual" | "disabled" => Ok(value),
        _ => bail!("DNS mode must be auto, manual or disabled"),
    }
}

fn dns_server_list(value: &Value) -> Vec<String> {
    let raw: Vec<String> = match value {
        Value::Array(items) => items.iter().map(js::text).collect(),
        other => js::text(other).split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';').map(str::to_string).collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let item = item.trim().to_string();
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

fn normalize_auth(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("pap")));
    match value.as_str() {
        "pap" | "chap" => Ok(value),
        _ => bail!("PPPoE auth must be pap or chap"),
    }
}

fn normalize_mac_mode(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("random")));
    match value.as_str() {
        "random" | "manual" => Ok(value),
        _ => bail!("PPPoE MAC mode must be random or manual"),
    }
}

fn is_protected_bridge_name(value: &str) -> bool {
    value.trim().to_lowercase().starts_with("vmbr")
}

#[cfg(test)]
mod tests;
