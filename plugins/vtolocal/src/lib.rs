//! VToLocal: one Linux dummy interface as the L3 boundary for host egress and
//! Veer reply injection, with its addresses and routes.
//!
//! Repairs follow events: a link, address or route event on an interface
//! this plugin may touch (or a resync) arms one full repair, and
//! REPAIR_TIMER replays everything every SAFETY_REPAIR_MS in case an event
//! was lost without a resync. Nothing polls.

#![recursion_limit = "256"]

use veer_plugin::js::{self, get as g};
use veer_plugin::netconf::*;
use veer_plugin::{bail, export_plugin, json, Host, Message, Outcome, Plugin, Result, Value};

const REPAIR_TIMER: &str = "vtolocal_repair";
const EVENT_TIMER: &str = "vtolocal_event";
const SAFETY_REPAIR_MS: u64 = 300_000;
const EVENT_REPAIR_DELAY_MS: u64 = 250;

pub struct VToLocal;

impl Plugin for VToLocal {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(VToLocal)
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        let ctx = &msg.ctx;
        match msg.handler.as_str() {
            "onReconcile" => {
                apply_stored_links(host)?;
                arm_repair_timer(host, None)?;
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                host.timer_clear(REPAIR_TIMER)?;
                host.timer_clear(EVENT_TIMER)?;
                let mut failures = Vec::new();
                for record in host.resources_list("links")?.iter().filter(|record| !record.is_null()) {
                    let result = load_profile(host, &json!({"profile_key": g(record, "key")})).and_then(|profile| teardown_link(host, &profile));
                    if let Err(err) = result {
                        failures.push(format!("{}: {err}", record_token(record)));
                    }
                }
                if !failures.is_empty() {
                    bail!("VToLocal deactivate cleanup failed: {}", failures.join("; "));
                }
                Ok(Outcome::Done)
            }
            "onResourceApply" => {
                if js::text(g(g(ctx, "resource"), "id")) != "links" {
                    return Ok(Outcome::Done);
                }
                let records = current_records(host, "links", &js::array(g(ctx, "records")))?;
                let applied = apply_records(host, &records, true);
                arm_repair_timer(host, Some(&merged_records(host, "links", &records)?))?;
                applied?;
                Ok(Outcome::Done)
            }
            "onTimer" => {
                let name = js::text(g(g(ctx, "timer"), "name"));
                if name != REPAIR_TIMER && name != EVENT_TIMER {
                    return Ok(Outcome::Done);
                }
                apply_stored_links(host)?;
                arm_repair_timer(host, None)?;
                Ok(Outcome::Done)
            }
            "onNetEvent" => {
                if events(ctx).iter().any(|event| js::text(g(event, "topic")).starts_with("net.")) && has_enabled_links(host)? {
                    arm_once(host, EVENT_TIMER, EVENT_REPAIR_DELAY_MS)?;
                }
                Ok(Outcome::Done)
            }
            "onAction" => {
                let payload = js::or(g(ctx, "payload"), &json!({})).clone();
                match js::text(g(g(ctx, "action"), "id")).as_str() {
                    "apply" => {
                        let profile = load_profile(host, &payload)?;
                        set_record_if_changed(host, "links", &js::text(&profile["profile_key"]), &profile, true)?;
                        apply_profile(host, &profile)?;
                        arm_repair_timer(host, None)?;
                        Ok(Outcome::Done)
                    }
                    "teardown" => {
                        teardown_link(host, &load_profile(host, &payload)?)?;
                        arm_repair_timer(host, None)?;
                        Ok(Outcome::Done)
                    }
                    other => bail!("unsupported action {other}"),
                }
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(VToLocal, "vtolocal");

fn has_enabled_links(host: &Host) -> Result<bool> {
    Ok(host.resources_list("links")?.iter().any(|link| !link.is_null() && !js::is_false(g(link, "enabled"))))
}

fn teardown_link(host: &Host, teardown: &Value) -> Result<()> {
    let key = js::text(&teardown["profile_key"]);
    let previous = previous_status(host, &key)?;
    host.resources_set("links", &key, teardown, false)?;
    let previous_teardown = teardown_previous_state(&previous);
    let cleanup_errors = cleanup_managed_state(host, &previous_teardown, &teardown_profile(teardown));
    let mut delete_error = String::new();
    let delete_target = if managed_link_proven(&previous_teardown) { safe_iface_name(g(&previous_teardown, "local_interface")) } else { String::new() };
    let delete_skipped = delete_target.is_empty();
    if !delete_target.is_empty() {
        if let Err(err) = host.call("net.link.delete", json!([delete_target])) {
            delete_error = err.to_string();
        }
    }
    let mut status = json!({
        "phase": "deleted",
        "profile_key": key,
        "local_interface": if delete_target.is_empty() { teardown["local_interface"].clone() } else { json!(delete_target) },
        "cleanup_errors": cleanup_errors,
        "managed_link": js::is_true(g(&previous_teardown, "managed_link")) || !delete_target.is_empty(),
        "link_delete_skipped": delete_skipped,
    });
    if !delete_error.is_empty() {
        status["phase"] = json!("delete_failed");
        status["last_error"] = json!(delete_error);
    } else if delete_skipped {
        status["link_delete_skip_reason"] = json!(link_delete_skip_reason(&previous_teardown));
    } else if !cleanup_errors.is_empty() {
        status["phase"] = json!("delete_partial");
        status["last_error"] = json!(cleanup_errors.join("; "));
    }
    set_record_if_changed(host, "status", &key, &status, false)
}

fn apply_stored_links(host: &Host) -> Result<()> {
    apply_records(host, &host.resources_list("links")?, false)
}

fn arm_repair_timer(host: &Host, records: Option<&[Value]>) -> Result<()> {
    let owned;
    let links = match records {
        Some(records) => records,
        None => {
            owned = host.resources_list("links")?;
            &owned
        }
    };
    if links.iter().any(|link| !link.is_null() && !js::is_false(g(link, "enabled"))) {
        return host.timer_set_interval(REPAIR_TIMER, SAFETY_REPAIR_MS, &json!({}));
    }
    host.timer_clear(REPAIR_TIMER)?;
    host.timer_clear(EVENT_TIMER)
}

fn apply_records(host: &Host, records: &[Value], report_errors: bool) -> Result<()> {
    let mut failures = Vec::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        if js::is_false(g(record, "enabled")) {
            let key = record_token(record);
            teardown_link(host, &normalize_profile(&key, js::or(g(record, "data"), &json!({})))?)?;
            continue;
        }
        let result = normalize_profile(&js::text(g(record, "key")), js::or(g(record, "data"), &json!({}))).and_then(|profile| apply_profile(host, &profile));
        if let Err(err) = result {
            mark_apply_error(host, g(record, "key"), &err.to_string())?;
            failures.push(format!("{}: {err}", record_token(record)));
        }
    }
    if report_errors && !failures.is_empty() {
        bail!("failed to apply {} VToLocal link record(s): {}", failures.len(), failures.join("; "));
    }
    Ok(())
}

fn mark_apply_error(host: &Host, key: &Value, error: &str) -> Result<()> {
    let key = js::token(js::or(key, &json!("default")));
    let mut previous = previous_status(host, &key)?;
    if !previous.is_object() {
        previous = json!({});
    }
    previous["phase"] = json!("error");
    previous["profile_key"] = json!(key);
    previous["last_error"] = json!(error);
    set_record_if_changed(host, "status", &key, &previous, false)
}

fn load_profile(host: &Host, payload: &Value) -> Result<Value> {
    let key = js::token(js::first(&[g(payload, "profile_key"), g(payload, "profile"), g(payload, "key"), &json!("default")]));
    let data = host.resources_data("links", &key)?;
    normalize_profile(&key, &js::merge(&data, payload))
}

fn apply_profile(host: &Host, profile: &Value) -> Result<()> {
    let key = js::text(&profile["profile_key"]);
    let local_interface = js::text(&profile["local_interface"]);
    let previous = previous_status(host, &key)?;
    let result = host.call("net.link.ensureDummy", json!([{"name": local_interface, "mtu": profile["mtu"], "up": true}]))?;
    let same_managed_link = managed_link_proven(&previous) && safe_iface_name(g(&previous, "local_interface")) == local_interface;
    let mut cleanup_errors = cleanup_managed_state(host, &previous, profile);
    cleanup_errors.extend(cleanup_managed_link_replacement(host, &previous, profile));
    replace_addrs(host, &local_interface, &js::array(&profile["addresses"]))?;
    replace_routes(host, &local_interface, &js::array(&profile["routes"]))?;
    let status = json!({
        "phase": "applied",
        "profile_key": key,
        "local_interface": result["link"]["name"],
        "local_ifindex": result["link"]["ifindex"],
        "mtu": profile["mtu"],
        "addresses": profile["addresses"],
        "routes": profile["routes"],
        "cleanup_errors": cleanup_errors,
        "managed_link": js::is_true(g(&result, "created")) || same_managed_link,
        "route_count": js::array(&profile["routes"]).len(),
        "pipeline_ingress_interface": local_interface,
        "pipeline_egress_interface": local_interface,
    });
    set_record_if_changed(host, "status", &key, &status, true)
}

fn previous_status(host: &Host, key: &str) -> Result<Value> {
    host.resources_data("status", key)
}

fn cleanup_managed_state(host: &Host, previous: &Value, profile: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let phase = js::text(g(previous, "phase"));
    if phase != "applied" && phase != "error" {
        return errors;
    }
    cleanup_removed_addrs(host, g(previous, "local_interface"), g(previous, "addresses"), g(profile, "local_interface"), g(profile, "addresses"), &mut errors);
    cleanup_removed_routes(host, g(previous, "local_interface"), g(previous, "routes"), g(profile, "local_interface"), g(profile, "routes"), &mut errors);
    errors
}

fn cleanup_managed_link_replacement(host: &Host, previous: &Value, profile: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if !managed_link_proven(previous) || !managed_link_changed(previous, profile) {
        return errors;
    }
    let local = safe_iface_name(g(previous, "local_interface"));
    if local.is_empty() {
        return errors;
    }
    if let Err(err) = host.call("net.link.delete", json!([local])) {
        errors.push(format!("old dummy {local}: {err}"));
    }
    errors
}

fn managed_link_changed(previous: &Value, profile: &Value) -> bool {
    let previous_local = safe_iface_name(g(previous, "local_interface"));
    if previous_local.is_empty() {
        return false;
    }
    previous_local != safe_iface_name(g(profile, "local_interface"))
}

fn managed_link_proven(previous: &Value) -> bool {
    js::text(g(previous, "phase")) != "deleted" && js::is_true(g(previous, "managed_link"))
}

fn link_delete_skip_reason(previous: &Value) -> &'static str {
    if js::is_true(g(previous, "managed_link")) && js::text(g(previous, "phase")) == "deleted" {
        return "previous vtolocal status already deleted this plugin-managed dummy";
    }
    "no previous vtolocal status proves this dummy was plugin-managed"
}

fn teardown_profile(profile: &Value) -> Value {
    json!({"local_interface": profile["local_interface"], "addresses": [], "routes": []})
}

fn teardown_previous_state(previous: &Value) -> Value {
    json!({
        "phase": js::or(g(previous, "phase"), &json!("")),
        "managed_link": js::is_true(g(previous, "managed_link")),
        "local_interface": js::or(g(previous, "local_interface"), &json!("")),
        "addresses": js::array(g(previous, "addresses")),
        "routes": js::array(g(previous, "routes")),
    })
}

fn normalize_profile(key: &str, raw: &Value) -> Result<Value> {
    let local_interface = js::text(js::or(g(raw, "local_interface"), &json!("veerlocal0")));
    Ok(json!({
        "profile_key": key,
        "local_interface": iface_name(&local_interface, "local_interface")?,
        "mtu": js::int_value(g(raw, "mtu"), 576, 65535, 1492),
        "addresses": cidr_list(js::first(&[g(raw, "addresses"), g(raw, "local_addresses"), &json!([])])),
        "routes": js::array(g(raw, "routes")),
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use veer_plugin::testing::{FakeHost, Harness};

    use super::*;

    #[derive(Default)]
    struct Kernel {
        links: BTreeMap<String, (u64, i64, Vec<String>)>,
        routes: BTreeMap<String, Value>,
        next: u64,
    }

    fn fixture() -> (Arc<Mutex<Kernel>>, Harness<VToLocal>) {
        let fake = FakeHost::new();
        let k = Arc::new(Mutex::new(Kernel { next: 20, ..Kernel::default() }));
        let m = k.clone();
        fake.adapter("net.link.ensureDummy", move |args| {
            let mut k = m.lock().unwrap();
            let name = args[0]["name"].as_str().unwrap().to_string();
            let mtu = args[0]["mtu"].as_i64().unwrap();
            let created = !k.links.contains_key(&name);
            if created {
                let index = k.next;
                k.next += 1;
                k.links.insert(name.clone(), (index, mtu, Vec::new()));
            }
            let link = k.links.get_mut(&name).unwrap();
            link.1 = mtu;
            Ok(json!({"link": {"name": name, "ifindex": link.0, "mtu": mtu}, "created": created}))
        });
        let m = k.clone();
        fake.adapter("net.link.delete", move |args| {
            m.lock().unwrap().links.remove(args[0].as_str().unwrap()).map(|_| Value::Null).ok_or_else(|| "link not found".to_string())
        });
        let m = k.clone();
        fake.adapter("net.addr.replace", move |args| {
            let mut k = m.lock().unwrap();
            let link = k.links.get_mut(args[0]["interface"].as_str().unwrap()).ok_or("link not found")?;
            let cidr = args[0]["cidr"].as_str().unwrap().to_string();
            if !link.2.contains(&cidr) {
                link.2.push(cidr);
            }
            Ok(Value::Null)
        });
        let m = k.clone();
        fake.adapter("net.addr.delete", move |args| {
            let mut k = m.lock().unwrap();
            if let Some(link) = k.links.get_mut(args[0]["interface"].as_str().unwrap()) {
                link.2.retain(|cidr| cidr != args[0]["cidr"].as_str().unwrap());
            }
            Ok(Value::Null)
        });
        let m = k.clone();
        fake.adapter("net.route.replace", move |args| {
            m.lock().unwrap().routes.insert(js::text(&args[0]["dst"]), args[0].clone());
            Ok(Value::Null)
        });
        let m = k.clone();
        fake.adapter("net.route.delete", move |args| {
            m.lock().unwrap().routes.remove(&js::text(&args[0]["dst"]));
            Ok(Value::Null)
        });
        let h = Harness::<VToLocal>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
        (k, h)
    }

    #[test]
    fn apply_creates_the_dummy_with_addresses_and_routes() {
        let (k, mut h) = fixture();
        h.action("apply", json!({"profile_key": "lab", "local_interface": "veerl0", "addresses": ["169.254.1.1/32"], "routes": [{"dst": "10.9.0.0/24"}], "mtu": 1400})).unwrap();
        let link = k.lock().unwrap().links.get("veerl0").cloned().expect("dummy");
        assert_eq!(link.1, 1400);
        assert_eq!(link.2, vec!["169.254.1.1/32"]);
        assert!(k.lock().unwrap().routes.contains_key("10.9.0.0/24"));
        let status = h.fake.data("status", "lab");
        assert_eq!(status["phase"], "applied");
        assert_eq!(status["managed_link"], true);
        assert_eq!(h.fake.timer(REPAIR_TIMER).unwrap()["kind"], "interval");
        assert_eq!(h.fake.timer(REPAIR_TIMER).unwrap()["delay_ms"], json!(SAFETY_REPAIR_MS));
    }

    #[test]
    fn a_net_event_repairs_a_deleted_dummy() {
        let (k, mut h) = fixture();
        h.action("apply", json!({"profile_key": "lab", "local_interface": "veerl0", "addresses": ["169.254.1.1/32"]})).unwrap();
        k.lock().unwrap().links.remove("veerl0");
        h.emit("net.link", json!({"interface": "veerl0", "operation": "delete"})).unwrap();
        assert!(h.fake.timer(EVENT_TIMER).is_some(), "the event arms a repair");
        h.fire_timer(EVENT_TIMER).unwrap();
        assert!(k.lock().unwrap().links.contains_key("veerl0"));
        assert_eq!(k.lock().unwrap().links["veerl0"].2, vec!["169.254.1.1/32"]);
    }

    #[test]
    fn events_without_links_arm_nothing() {
        let (_, mut h) = fixture();
        h.emit("net.link", json!({"interface": "veerl0"})).unwrap();
        assert!(h.fake.timer(EVENT_TIMER).is_none());
    }

    #[test]
    fn teardown_deletes_only_a_managed_dummy_and_clears_timers() {
        let (k, mut h) = fixture();
        h.action("apply", json!({"profile_key": "lab", "local_interface": "veerl0", "routes": [{"dst": "10.9.0.0/24"}]})).unwrap();
        h.action("teardown", json!({"profile_key": "lab"})).unwrap();
        assert!(!k.lock().unwrap().links.contains_key("veerl0"));
        assert_eq!(h.fake.data("status", "lab")["phase"], "deleted");
        assert_eq!(h.fake.record("links", "lab").unwrap()["enabled"], false);
        assert!(h.fake.timers().is_empty());
        // A second teardown has no managed link left to delete.
        h.action("teardown", json!({"profile_key": "lab"})).unwrap();
        assert_eq!(h.fake.data("status", "lab")["link_delete_skipped"], true);
    }

    #[test]
    fn changing_the_interface_deletes_the_old_managed_dummy() {
        let (k, mut h) = fixture();
        h.action("apply", json!({"profile_key": "lab", "local_interface": "veerl0"})).unwrap();
        h.action("apply", json!({"profile_key": "lab", "local_interface": "veerl1"})).unwrap();
        let k = k.lock().unwrap();
        assert!(!k.links.contains_key("veerl0"));
        assert!(k.links.contains_key("veerl1"));
    }

    #[test]
    fn invalid_interface_names_are_reported() {
        let (_, mut h) = fixture();
        let err = h.action("apply", json!({"profile_key": "lab", "local_interface": "this-name-is-too-long"})).unwrap_err();
        assert!(err.to_string().contains("exceeds 15 bytes"), "{err}");
    }
}
