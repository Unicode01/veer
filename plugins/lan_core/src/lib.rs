//! LAN Core: a Linux bridge with member ports and gateway addresses, and the
//! plans the host turns into outbound NAT, DHCPv4 and routed IPv6 for it.
//!
//! Repairs follow events: a link or address event on the bridge or its
//! ports, or a change to the WAN Core status the plans derive from, arms one
//! full apply; REPAIR_TIMER replays everything every SAFETY_REPAIR_MS in
//! case an event was lost. Nothing polls.

#![recursion_limit = "512"]

use std::collections::{BTreeMap, BTreeSet};

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::netconf::{cidr_list, cleanup_removed_addrs, current_records, events, merged_records, record_token, replace_addrs, arm_once};
use veer_plugin::{bail, export_plugin, json, Error, Host, Message, Outcome, Plugin, Result, Value};

const REPAIR_TIMER: &str = "lan_repair";
const EVENT_TIMER: &str = "lan_event";
const SAFETY_REPAIR_MS: u64 = 300_000;
const EVENT_REPAIR_DELAY_MS: u64 = 250;

pub struct LanCore;

impl Plugin for LanCore {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(LanCore)
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        let ctx = &msg.ctx;
        match msg.handler.as_str() {
            "onReconcile" => {
                apply_stored_profiles(host)?;
                arm_repair_timer(host, None)?;
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                host.timer_clear(REPAIR_TIMER)?;
                host.timer_clear(EVENT_TIMER)?;
                let mut failures = Vec::new();
                for record in host.resources_list("profiles")?.iter().filter(|record| !record.is_null()) {
                    let payload = json!({"key": g(record, "key"), "profile": js::or(g(record, "data"), &json!({}))});
                    if let Err(err) = load_plan(host, &payload).and_then(|plan| teardown_network(host, &plan)) {
                        failures.push(format!("{}: {err}", record_token(record)));
                    }
                }
                if !failures.is_empty() {
                    bail!("LAN deactivate cleanup failed: {}", failures.join("; "));
                }
                Ok(Outcome::Done)
            }
            "onTimer" => {
                let name = js::text(g(g(ctx, "timer"), "name"));
                if name == REPAIR_TIMER || name == EVENT_TIMER {
                    apply_stored_profiles(host)?;
                    arm_repair_timer(host, None)?;
                }
                Ok(Outcome::Done)
            }
            "onResourceApply" => {
                if js::text(g(g(ctx, "resource"), "id")) != "profiles" {
                    return Ok(Outcome::Done);
                }
                let records = current_records(host, "profiles", &js::array(g(ctx, "records")))?;
                let applied = apply_records(host, &records, true);
                arm_repair_timer(host, Some(&merged_records(host, "profiles", &records)?))?;
                applied?;
                Ok(Outcome::Done)
            }
            "onNetEvent" => {
                if events(ctx).iter().any(|event| js::text(g(event, "topic")).starts_with("net.")) && has_enabled_profiles(host)? {
                    arm_once(host, EVENT_TIMER, EVENT_REPAIR_DELAY_MS)?;
                }
                Ok(Outcome::Done)
            }
            // A WAN Core status change moves the egress, DNS and delegated
            // prefix the plans derive from. This plugin's own records are
            // not news.
            "onRecordEvent" => {
                let wan_changed = events(ctx).iter().any(|event| {
                    let payload = g(event, "payload");
                    js::text(js::or(g(payload, "plugin_id"), g(event, "target_plugin"))) != "lan_core"
                        && js::text(js::or(g(event, "resource"), g(payload, "resource_id"))) == "status"
                });
                if wan_changed && has_enabled_profiles(host)? {
                    arm_once(host, EVENT_TIMER, EVENT_REPAIR_DELAY_MS)?;
                }
                Ok(Outcome::Done)
            }
            "onAction" => {
                let payload = js::or(g(ctx, "payload"), &json!({})).clone();
                match js::text(g(g(ctx, "action"), "id")).as_str() {
                    "traffic_stats" => Ok(Outcome::Value(read_traffic_stats(host, &payload)?)),
                    "apply_network" => {
                        let plan = load_plan(host, &payload)?;
                        set_record_if_changed_apply(host, "profiles", &plan.key, &plan.profile, true, false)?;
                        apply_network(host, &plan)?;
                        arm_repair_timer(host, None)?;
                        Ok(Outcome::Done)
                    }
                    "teardown" => {
                        teardown_network(host, &load_plan(host, &payload)?)?;
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

export_plugin!(LanCore, "lan_core");

fn has_enabled_profiles(host: &Host) -> Result<bool> {
    Ok(host.resources_list("profiles")?.iter().any(|profile| !profile.is_null() && !js::is_false(g(profile, "enabled"))))
}

fn first_text(values: &[&Value]) -> String {
    veer_plugin::netconf::first_text(values)
}

fn read_traffic_stats(host: &Host, payload: &Value) -> Result<Value> {
    let key = js::token(js::first(&[g(payload, "profile_key"), g(payload, "lan_id"), g(payload, "key"), &json!("default")]));
    let profile_record = host.resources_get("profiles", &key)?;
    let status_record = host.resources_get("status", &key)?;
    let profile = profile_record.as_ref().map(|record| js::or(g(record, "data"), &json!({})).clone()).unwrap_or(json!({}));
    let status = status_record.as_ref().map(|record| js::or(g(record, "data"), &json!({})).clone()).unwrap_or(json!({}));
    let bridge = safe_iface_name(js::first(&[g(payload, "bridge"), g(&status, "bridge"), g(&profile, "bridge"), g(&profile, "bridge_interface"), &json!("")]));
    let port_source = if status_record.is_some() && g(&status, "bridge_members").is_array() {
        status["bridge_members"].clone()
    } else if status_record.is_some() && g(&status, "ports").is_array() {
        status["ports"].clone()
    } else {
        js::or(g(&profile, "ports"), &json!([])).clone()
    };
    let ports = traffic_iface_list(&port_source).unwrap_or_default();
    let mut out = json!({
        "available": false, "profile_key": key, "sampled_at_ms": js::now_ms(), "counter_scope": "linux_link", "bridge": null, "ports": [],
    });
    if bridge.is_empty() {
        out["reason"] = json!("LAN bridge is not configured");
        return Ok(out);
    }
    out["bridge"] = read_link_traffic_stats(host, &bridge);
    out["ports"] = Value::Array(ports.iter().map(|port| read_link_traffic_stats(host, port)).collect());
    let bridge_stats = out["bridge"].clone();
    let available = truthy(&bridge_stats) && !truthy(g(&bridge_stats, "error")) && truthy(g(&bridge_stats, "statistics"));
    out["available"] = json!(available);
    if !available {
        out["reason"] = if truthy(g(&bridge_stats, "error")) { bridge_stats["error"].clone() } else { json!("link statistics are unavailable") };
    }
    Ok(out)
}

fn read_link_traffic_stats(host: &Host, name: &str) -> Value {
    match host.call("net.link.get", json!([name])) {
        Ok(link) => {
            let stats = g(&link, "statistics");
            let statistics = if truthy(stats) {
                let mut out = json!({});
                for field in ["rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"] {
                    out[field] = json!(traffic_counter(g(stats, field)));
                }
                out
            } else {
                Value::Null
            };
            json!({
                "name": name,
                "ifindex": js::int_value(g(&link, "ifindex"), 0, 2147483647, 0),
                "up": truthy(g(&link, "up")),
                "oper_state": first_text(&[g(&link, "oper_state")]),
                "statistics": statistics,
            })
        }
        Err(err) => json!({"name": name, "error": err.to_string(), "statistics": null}),
    }
}

fn traffic_counter(value: &Value) -> u64 {
    let number = js::number(value);
    if !number.is_finite() || number < 0.0 {
        0
    } else {
        number.floor() as u64
    }
}

fn traffic_iface_list(value: &Value) -> Result<Vec<String>> {
    let Value::Array(items) = value else {
        return iface_list(value);
    };
    let mut names = Vec::new();
    for item in items {
        let item = if item.is_object() { js::first(&[g(item, "name"), g(item, "interface"), g(item, "link"), &json!("")]).clone() } else { item.clone() };
        if !js::text(&item).is_empty() {
            names.push(item);
        }
    }
    iface_list(&Value::Array(names))
}

fn apply_stored_profiles(host: &Host) -> Result<()> {
    apply_records(host, &host.resources_list("profiles")?, false)
}

fn arm_repair_timer(host: &Host, records: Option<&[Value]>) -> Result<()> {
    let owned;
    let profiles = match records {
        Some(records) => records,
        None => {
            owned = host.resources_list("profiles")?;
            &owned
        }
    };
    if profiles.iter().any(|profile| !profile.is_null() && !js::is_false(g(profile, "enabled"))) {
        return host.timer_set_interval(REPAIR_TIMER, SAFETY_REPAIR_MS, &json!({}));
    }
    host.timer_clear(REPAIR_TIMER)?;
    host.timer_clear(EVENT_TIMER)
}

fn apply_records(host: &Host, records: &[Value], report_errors: bool) -> Result<()> {
    let mut failures = Vec::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        if js::is_false(g(record, "enabled")) {
            disable_profile_runtime(host, record)?;
            continue;
        }
        let payload = json!({"key": g(record, "key"), "profile": js::or(g(record, "data"), &json!({}))});
        if let Err(err) = load_plan(host, &payload).and_then(|plan| apply_network(host, &plan)) {
            mark_apply_error(host, g(record, "key"), &err)?;
            failures.push(format!("{}: {err}", record_token(record)));
        }
    }
    if report_errors && !failures.is_empty() {
        bail!("failed to apply {} LAN profile record(s): {}", failures.len(), failures.join("; "));
    }
    Ok(())
}

fn disable_profile_runtime(host: &Host, record: &Value) -> Result<()> {
    let key = record_token(record);
    let raw = js::or(g(record, "data"), &json!({})).clone();
    let mut previous = previous_status(host, &key)?;
    let gro_restore = restore_previous_member_gro(host, &previous);
    let parent = safe_iface_name(js::first(&[g(&raw, "bridge"), g(&raw, "bridge_interface"), &json!("")]));
    let plan = json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key,
        "parent_interface": parent, "child_interface": "",
        "out_interface": safe_iface_name(js::first(&[g(&raw, "wan_egress_interface"), g(&raw, "out_interface"), g(&raw, "wan_interface"), &json!("")])),
        "out_source_ip": first_text(&[g(&raw, "wan_egress_source_ip"), g(&raw, "out_source_ip"), g(&raw, "source_ip")]),
        "protocol": normalize_protocol(js::or(g(&raw, "protocol"), &json!("tcp+udp+icmp")))?,
        "nat_type": js::text(js::or(g(&raw, "nat_type"), &json!("symmetric"))),
        "redirect_mode": normalize_redirect_mode(js::first(&[g(&raw, "redirect_mode"), g(&raw, "egress_nat_redirect_mode"), &json!("")])),
        "enabled": false,
        "note": "disabled because lan_core profile is disabled",
    });
    set_record_if_changed_apply(host, "egress_nat_plans", &key, &plan, false, true)?;
    let note = "disabled because lan_core profile is disabled";
    set_record_if_changed_apply(host, "dhcpv4_plans", &key, &disabled_dhcpv4_plan(&key, &parent, note), false, true)?;
    set_record_if_changed_apply(host, "ipv6_assignment_plans", &key, &disabled_ipv6_assignment_plan(&key, &parent, note), false, true)?;
    if js::text(g(&previous, "phase")) == "deleted" && safe_iface_name(g(&previous, "bridge")) == parent {
        let bridge_mtu = js::or(g(&raw, "mtu"), g(&previous, "bridge_mtu")).clone();
        let mut cleanup_errors = js::array(g(&previous, "cleanup_errors"));
        cleanup_errors.extend(gro_restore.errors.iter().map(|err| json!(err)));
        previous["member_gro"] = disabled_member_gro_state(&bridge_mtu, &gro_restore);
        previous["cleanup_errors"] = Value::Array(cleanup_errors);
        return set_record_if_changed_apply(host, "status", &key, &previous, false, false);
    }
    let status = json!({
        "phase": "disabled",
        "lan_id": key,
        "bridge": parent,
        "wan_ref": js::token(js::or(g(&raw, "wan_ref"), g(&raw, "wan"))),
        "cleanup_errors": gro_restore.errors,
        "member_gro": disabled_member_gro_state(g(&raw, "mtu"), &gro_restore),
        "egress_nat_plan": plan,
    });
    set_record_if_changed_apply(host, "status", &key, &status, false, false)
}

fn mark_apply_error(host: &Host, key: &Value, error: &Error) -> Result<()> {
    let key = js::token(js::or(key, &json!("default")));
    let mut message = error.to_string();
    let previous = previous_status(host, &key)?;
    let gro_restore = restore_previous_member_gro(host, &previous);
    if !gro_restore.errors.is_empty() {
        message = format!("{message}; {}", gro_restore.errors.join("; "));
    }
    let failed = "disabled because lan_core failed to apply this profile";
    set_record_if_changed_apply(
        host,
        "egress_nat_plans",
        &key,
        &json!({"lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key, "enabled": false, "note": failed, "last_error": message}),
        false,
        true,
    )?;
    set_record_if_changed_apply(host, "dhcpv4_plans", &key, &disabled_dhcpv4_plan(&key, "", failed), false, true)?;
    set_record_if_changed_apply(host, "ipv6_assignment_plans", &key, &disabled_ipv6_assignment_plan(&key, "", failed), false, true)?;
    let status = json!({
        "phase": "error",
        "lan_id": key,
        "cleanup_errors": gro_restore.errors,
        "member_gro": disabled_member_gro_state(g(&previous, "bridge_mtu"), &gro_restore),
        "last_error": message,
    });
    set_record_if_changed_apply(host, "status", &key, &status, false, false)
}

struct Plan {
    key: String,
    profile: Value,
}

fn load_plan(host: &Host, payload: &Value) -> Result<Plan> {
    let inline = g(payload, "profile");
    let inline_identity = if truthy(inline) {
        js::first(&[g(inline, "lan_id"), g(inline, "network_id"), g(inline, "profile_key"), g(inline, "key")])
    } else {
        &Value::Null
    };
    let key = js::token(js::first(&[
        g(payload, "lan_id"),
        g(payload, "network_id"),
        g(payload, "profile_key"),
        g(payload, "key"),
        inline_identity,
        &json!("default"),
    ]));
    let stored = host.resources_data("profiles", &key)?;
    let source = if truthy(inline) { inline } else { payload };
    let raw = js::merge(&stored, source);
    Ok(Plan { profile: normalize_profile(&key, &raw)?, key })
}

fn apply_network(host: &Host, plan: &Plan) -> Result<()> {
    let profile = &plan.profile;
    let bridge_name = js::text(&profile["bridge"]);
    let previous = previous_status(host, &plan.key)?;
    let bridge_existed = link_exists(host, &bridge_name);
    let bridge = host.call("net.link.ensureBridge", json!([{"name": bridge_name, "mtu": profile["mtu"], "up": true}]))?;
    if js::is_true(&profile["preserve_bridge"]) && js::is_true(g(&bridge, "created")) {
        host.call("net.link.release", json!([bridge_name]))?;
    }
    let mut cleanup_errors = cleanup_managed_bridge_state(host, &previous, profile);
    cleanup_managed_ports(host, &previous, profile, &mut cleanup_errors);
    replace_addrs(host, &bridge_name, &js::array(&profile["addresses"]))?;

    let mut members = Vec::new();
    let mut missing_ports = Vec::new();
    let mut failed_ports = Vec::new();
    let mut managed_port_set = retained_managed_port_set(&previous, profile);
    let bridge_ifindex = js::or(g(&bridge, "ifindex"), &json!(0)).clone();
    for port in js::array(&profile["ports"]) {
        let port = js::text(&port);
        let current = match host.call("net.link.get", json!([port])) {
            Ok(current) => current,
            Err(_) => {
                missing_ports.push(port);
                continue;
            }
        };
        let was_member = js::text(g(&current, "master_name")) == bridge_name && g(&current, "master_name").is_string();
        let info = if !was_member || !js::is_true(g(&current, "up")) {
            match host.call("net.link.setMaster", json!([{"link": port, "master": bridge_name, "up": true}])) {
                Ok(info) => info,
                Err(err) => {
                    failed_ports.push(json!({"name": port, "error": err.to_string()}));
                    continue;
                }
            }
        } else {
            current.clone()
        };
        if !was_member {
            managed_port_set.insert(port.clone());
        }
        members.push(json!({
            "name": js::or(g(&info, "name"), &json!(port)),
            "ifindex": js::or(g(&info, "ifindex"), &json!(0)),
            "kind": js::or(g(&info, "kind"), &json!("")),
            "mac": js::or(g(&info, "mac"), &json!("")),
            "master_name": js::or(g(&info, "master_name"), &json!(bridge_name)),
            "master_ifindex": js::first(&[g(&info, "master_ifindex"), &bridge_ifindex, &json!(0)]),
            "managed": managed_port_set.contains(&port),
        }));
    }
    let managed_ports: Vec<String> = managed_port_set.iter().cloned().collect();
    let mut bridge_state = read_bridge_members(host, &bridge_name, &bridge_ifindex, &iface_set(&profile["ports"]), &managed_port_set, &members);
    let wan_egress = resolve_wan_egress(host, profile);
    let member_gro = reconcile_member_gro(host, &previous, profile, &mut bridge_state.members, &wan_egress);
    let dns_state = resolve_dns_state(profile, &wan_egress);
    let egress_plan = build_egress_nat_plan(&plan.key, profile, &wan_egress);
    let dhcpv4_plan = build_dhcpv4_plan(&plan.key, profile, &dns_state);
    let ipv6_plan = build_ipv6_assignment_plan(host, &plan.key, profile, &wan_egress, &dns_state);
    set_record_if_changed_apply(host, "egress_nat_plans", &plan.key, &egress_plan, js::is_true(&egress_plan["enabled"]), true)?;
    set_record_if_changed_apply(host, "dhcpv4_plans", &plan.key, &dhcpv4_plan, js::is_true(&dhcpv4_plan["enabled"]), true)?;
    set_record_if_changed_apply(host, "ipv6_assignment_plans", &plan.key, &ipv6_plan, js::is_true(&ipv6_plan["enabled"]), true)?;
    let gro_errors = js::array(&member_gro["errors"]);
    let phase = if !missing_ports.is_empty() || !failed_ports.is_empty() || !gro_errors.is_empty() { "partial" } else { "applied" };
    let bridge_created_by_this_plugin = bridge_created_by_plugin(&previous, profile, bridge_existed);
    let status = json!({
        "phase": phase,
        "lan_id": plan.key,
        "bridge": js::or(g(&bridge, "name"), &profile["bridge"]),
        "bridge_ifindex": bridge_ifindex,
        "bridge_mac": js::or(g(&bridge, "mac"), &json!("")),
        "bridge_mtu": js::or(g(&bridge, "mtu"), &profile["mtu"]),
        "bridge_created": bridge_created_by_this_plugin,
        "bridge_existing": bridge_existed,
        "bridge_addresses": profile["addresses"],
        "cleanup_errors": cleanup_errors,
        "preserve_bridge": profile["preserve_bridge"],
        "configured_ports": profile["ports"],
        "ports": members,
        "bridge_members": bridge_state.members,
        "bridge_members_error": bridge_state.error,
        "member_gro": member_gro,
        "managed_ports": managed_ports,
        "missing_ports": missing_ports,
        "failed_ports": failed_ports,
        "wan_ref": profile["wan_ref"],
        "wan_plugin": profile["wan_plugin"],
        "wan_egress": wan_egress,
        "dns": dns_state,
        "egress_nat_plan": egress_plan,
        "dhcpv4_plan": dhcpv4_plan,
        "ipv6_assignment_plan": ipv6_plan,
        "repair_timer": REPAIR_TIMER,
    });
    set_record_if_changed_apply(host, "status", &plan.key, &status, true, false)
}

fn previous_status(host: &Host, key: &str) -> Result<Value> {
    let data = host.resources_data("status", key)?;
    Ok(if data.is_object() { data } else { json!({}) })
}

fn bridge_created_by_plugin(previous: &Value, profile: &Value, bridge_existed: bool) -> bool {
    if !bridge_existed {
        return true;
    }
    if !truthy(g(previous, "bridge_created")) {
        return false;
    }
    safe_iface_name(g(previous, "bridge")) == safe_iface_name(&profile["bridge"])
}

fn cleanup_managed_bridge_state(host: &Host, previous: &Value, profile: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if js::text(g(previous, "phase")) == "deleted" {
        return errors;
    }
    cleanup_removed_addrs(host, g(previous, "bridge"), g(previous, "bridge_addresses"), &profile["bridge"], &profile["addresses"], &mut errors);
    errors
}

fn cleanup_managed_ports(host: &Host, previous: &Value, profile: &Value, errors: &mut Vec<String>) {
    let previous_bridge = safe_iface_name(g(previous, "bridge"));
    if previous_bridge.is_empty() {
        return;
    }
    let next_bridge = safe_iface_name(&profile["bridge"]);
    let next_ports = iface_set(&profile["ports"]);
    for port in managed_ports_from_previous(previous) {
        if previous_bridge == next_bridge && next_ports.contains(&port) {
            continue;
        }
        if let Err(err) = host.call("net.link.clearMaster", json!([port])) {
            errors.push(format!("port {port}: {err}"));
        }
    }
}

fn retained_managed_port_set(previous: &Value, profile: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if safe_iface_name(g(previous, "bridge")) != safe_iface_name(&profile["bridge"]) {
        return out;
    }
    let next_ports = iface_set(&profile["ports"]);
    for port in managed_ports_from_previous(previous) {
        if next_ports.contains(&port) {
            out.insert(port);
        }
    }
    out
}

fn managed_ports_from_previous(previous: &Value) -> Vec<String> {
    if js::text(g(previous, "phase")) == "deleted" {
        return Vec::new();
    }
    match g(previous, "managed_ports") {
        Value::Array(_) => iface_list(g(previous, "managed_ports")).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn teardown_network(host: &Host, plan: &Plan) -> Result<()> {
    let profile = &plan.profile;
    let bridge_name = js::text(&profile["bridge"]);
    let wan_egress = resolve_wan_egress(host, profile);
    let mut egress_plan = build_egress_nat_plan(&plan.key, profile, &wan_egress);
    egress_plan["enabled"] = json!(false);
    egress_plan["note"] = json!("disabled by lan_core teardown");
    host.resources_set("profiles", &plan.key, profile, false)?;
    set_record_if_changed_apply(host, "egress_nat_plans", &plan.key, &egress_plan, false, true)?;
    let note = "disabled by lan_core teardown";
    set_record_if_changed_apply(host, "dhcpv4_plans", &plan.key, &disabled_dhcpv4_plan(&plan.key, &bridge_name, note), false, true)?;
    set_record_if_changed_apply(host, "ipv6_assignment_plans", &plan.key, &disabled_ipv6_assignment_plan(&plan.key, &bridge_name, note), false, true)?;

    let previous = previous_status(host, &plan.key)?;
    let previous_bridge_state = json!({"bridge": js::or(g(&previous, "bridge"), &json!("")), "bridge_addresses": js::array(g(&previous, "bridge_addresses"))});
    let mut cleanup_errors = cleanup_managed_bridge_state(host, &previous_bridge_state, &json!({"bridge": bridge_name, "addresses": []}));
    let managed_ports = managed_ports_from_previous(&previous);
    let bridge_delete_allowed = should_delete_bridge(&previous, profile);
    let bridge_was_plugin_created = js::is_true(g(&previous, "bridge_created"));
    let mut failed_ports = Vec::new();
    for port in &managed_ports {
        if let Err(err) = host.call("net.link.clearMaster", json!([port])) {
            failed_ports.push(json!({"name": port, "error": err.to_string()}));
        }
    }
    let gro_restore = restore_previous_member_gro(host, &previous);
    cleanup_errors.extend(gro_restore.errors.iter().cloned());
    let mut bridge_error = String::new();
    let preserve = js::is_true(&profile["preserve_bridge"]);
    let bridge_delete_skipped = !preserve && !bridge_delete_allowed;
    if bridge_delete_allowed {
        if let Err(err) = host.call("net.link.delete", json!([bridge_name])) {
            bridge_error = err.to_string();
        }
    }
    let phase = if !failed_ports.is_empty() || !bridge_error.is_empty() { "delete_partial" } else { "deleted" };
    let bridge_ifindex = json!(js::int_value(g(&previous, "bridge_ifindex"), 0, 2147483647, 0));
    let bridge_state = read_bridge_members(host, &bridge_name, &bridge_ifindex, &iface_set(&profile["ports"]), &BTreeSet::new(), &[]);
    let mut status = json!({
        "phase": phase,
        "lan_id": plan.key,
        "bridge": profile["bridge"],
        "bridge_created": bridge_was_plugin_created,
        "bridge_preserved": profile["preserve_bridge"],
        "bridge_delete_skipped": bridge_delete_skipped,
        "cleanup_errors": cleanup_errors,
        "configured_ports": profile["ports"],
        "ports": profile["ports"],
        "bridge_members": bridge_state.members,
        "bridge_members_error": bridge_state.error,
        "member_gro": disabled_member_gro_state(&profile["mtu"], &gro_restore),
        "managed_ports": managed_ports,
        "failed_ports": failed_ports,
        "wan_ref": profile["wan_ref"],
    });
    if !bridge_error.is_empty() {
        status["bridge_error"] = json!(bridge_error);
        status["last_error"] = json!(bridge_error);
    } else if bridge_delete_skipped {
        status["bridge_delete_skip_reason"] = json!(bridge_delete_skip_reason(&previous));
    } else if !failed_ports.is_empty() {
        status["last_error"] = json!(format!("failed to detach {} LAN port(s)", failed_ports.len()));
    } else if !cleanup_errors.is_empty() {
        status["last_error"] = json!(cleanup_errors.join("; "));
    }
    set_record_if_changed_apply(host, "status", &plan.key, &status, false, false)
}

fn should_delete_bridge(previous: &Value, profile: &Value) -> bool {
    if js::text(g(previous, "phase")) == "deleted" || js::is_true(&profile["preserve_bridge"]) {
        return false;
    }
    if safe_iface_name(g(previous, "bridge")) != safe_iface_name(&profile["bridge"]) {
        return false;
    }
    js::is_true(g(previous, "bridge_created"))
}

fn bridge_delete_skip_reason(previous: &Value) -> &'static str {
    if js::is_true(g(previous, "bridge_created")) && js::text(g(previous, "phase")) == "deleted" {
        return "previous lan_core status already deleted this plugin-created bridge";
    }
    "no previous lan_core status proves this bridge was plugin-created"
}

fn iface_set(values: &Value) -> BTreeSet<String> {
    iface_list(values).unwrap_or_default().into_iter().collect()
}

struct BridgeState {
    members: Vec<Value>,
    error: String,
}

fn read_bridge_members(host: &Host, bridge_name: &str, bridge_ifindex: &Value, configured: &BTreeSet<String>, managed: &BTreeSet<String>, fallback: &[Value]) -> BridgeState {
    let bridge_name = safe_iface_name(&json!(bridge_name));
    let bridge_ifindex = js::int_value(bridge_ifindex, 0, 2147483647, 0);
    let mut members = Vec::new();
    match host.call("net.link.list", json!([])) {
        Ok(links) => {
            for info in js::array(&links) {
                let name = safe_iface_name(g(&info, "name"));
                if name.is_empty() {
                    continue;
                }
                let master_name = safe_iface_name(g(&info, "master_name"));
                let master_ifindex = js::int_value(g(&info, "master_ifindex"), 0, 2147483647, 0);
                if master_name != bridge_name && (bridge_ifindex == 0 || master_ifindex != bridge_ifindex) {
                    continue;
                }
                members.push(bridge_member_view(&info, &name, &bridge_name, bridge_ifindex, configured, managed));
            }
            sort_bridge_members(&mut members);
            BridgeState { members, error: String::new() }
        }
        Err(err) => {
            for info in fallback {
                let name = safe_iface_name(js::first(&[g(info, "name"), g(info, "interface"), info]));
                if name.is_empty() {
                    continue;
                }
                members.push(bridge_member_view(info, &name, &bridge_name, bridge_ifindex, configured, managed));
            }
            sort_bridge_members(&mut members);
            BridgeState { members, error: err.to_string() }
        }
    }
}

fn bridge_member_view(info: &Value, name: &str, bridge_name: &str, bridge_ifindex: i64, configured: &BTreeSet<String>, managed: &BTreeSet<String>) -> Value {
    let master_name = safe_iface_name(g(info, "master_name"));
    json!({
        "name": name,
        "ifindex": js::int_value(g(info, "ifindex"), 0, 2147483647, 0),
        "kind": first_text(&[g(info, "kind")]),
        "mac": first_text(&[g(info, "mac")]),
        "up": js::is_true(g(info, "up")),
        "oper_state": first_text(&[g(info, "oper_state")]),
        "master_name": if master_name.is_empty() { bridge_name.to_string() } else { master_name },
        "master_ifindex": js::int_value(g(info, "master_ifindex"), 0, 2147483647, bridge_ifindex),
        "configured": configured.contains(name),
        "managed": managed.contains(name),
    })
}

fn sort_bridge_members(members: &mut [Value]) {
    members.sort_by(|a, b| {
        let ai = js::int_value(g(a, "ifindex"), 0, 2147483647, 0);
        let bi = js::int_value(g(b, "ifindex"), 0, 2147483647, 0);
        match (ai, bi) {
            (0, 0) => js::text(g(a, "name")).cmp(&js::text(g(b, "name"))),
            (0, _) => std::cmp::Ordering::Greater,
            (_, 0) => std::cmp::Ordering::Less,
            _ if ai != bi => ai.cmp(&bi),
            _ => js::text(g(a, "name")).cmp(&js::text(g(b, "name"))),
        }
    });
}

fn reconcile_member_gro(host: &Host, previous: &Value, profile: &Value, members: &mut [Value], wan_egress: &Value) -> Value {
    let bridge_mtu = js::int_value(&profile["mtu"], 576, 65535, 1500);
    let wan_mtu = js::int_value(g(wan_egress, "mtu"), 0, 65535, 0);
    let required = js::is_true(&profile["auto_egress_nat"])
        && js::text(&profile["protocol"]).contains("tcp")
        && truthy(g(wan_egress, "interface"))
        && wan_mtu > 0
        && bridge_mtu > wan_mtu
        && !js::is_true(g(wan_egress, "segmentation_ready"));
    let previous_entries = js::array(g(g(previous, "member_gro"), "members"));
    let mut previous_by_name: BTreeMap<String, Value> = BTreeMap::new();
    for entry in &previous_entries {
        let name = safe_iface_name(g(entry, "name"));
        if !name.is_empty() {
            previous_by_name.insert(name, entry.clone());
        }
    }
    let current_names: BTreeSet<String> = members.iter().map(|member| safe_iface_name(g(member, "name"))).filter(|name| !name.is_empty()).collect();
    let mut active = Vec::new();
    let mut pending_restore = Vec::new();
    let mut errors = Vec::new();
    for stale in &previous_entries {
        let name = safe_iface_name(g(stale, "name"));
        if name.is_empty() || (required && current_names.contains(&name)) {
            continue;
        }
        if !restore_member_gro(host, stale, &mut errors) {
            pending_restore.push(stale.clone());
        }
    }
    if required {
        for member in members.iter_mut() {
            let name = safe_iface_name(g(member, "name"));
            if name.is_empty() {
                continue;
            }
            let old = previous_by_name.get(&name).cloned().unwrap_or(json!({}));
            let mut entry = json!({
                "name": name,
                "original_gro": if old["original_gro"].is_boolean() { old["original_gro"].clone() } else { json!(false) },
                "restore_gro": js::is_true(&old["restore_gro"]),
                "applied": false,
            });
            let result: Result<()> = (|| {
                let features = host.call("net.link.getOffloads", json!([name]))?;
                let gro = g(&features, "gro");
                if !gro.is_boolean() {
                    bail!("GRO state is unavailable");
                }
                if !old["original_gro"].is_boolean() {
                    entry["original_gro"] = gro.clone();
                }
                if js::is_true(gro) {
                    host.call("net.link.setOffloads", json!([name, {"gro": false}]))?;
                    entry["restore_gro"] = json!(js::is_true(&entry["original_gro"]));
                }
                entry["applied"] = json!(true);
                member["gro"] = json!(false);
                Ok(())
            })();
            if let Err(err) = result {
                errors.push(format!("GRO {name}: {err}"));
            }
            active.push(entry);
        }
    }
    let applied = required && errors.is_empty() && active.len() == members.len();
    let note = if required {
        "Compatibility fallback disables GRO because the lower-MTU WAN does not publish a segmentation boundary."
    } else if js::is_true(g(wan_egress, "segmentation_ready")) {
        "The WAN pipeline provides a kernel segmentation boundary; LAN GRO remains enabled."
    } else {
        "No lower-MTU WAN GRO adaptation is required."
    };
    pending_restore.extend(active);
    json!({
        "required": required, "applied": applied, "bridge_mtu": bridge_mtu, "wan_mtu": wan_mtu,
        "members": pending_restore, "errors": errors, "note": note,
    })
}

fn restore_member_gro(host: &Host, entry: &Value, errors: &mut Vec<String>) -> bool {
    if !js::is_true(g(entry, "restore_gro")) {
        return true;
    }
    let name = safe_iface_name(g(entry, "name"));
    if name.is_empty() {
        return true;
    }
    let result: Result<()> = (|| {
        let features = host.call("net.link.getOffloads", json!([name]))?;
        if js::is_false(g(&features, "gro")) {
            host.call("net.link.setOffloads", json!([name, {"gro": true}]))?;
        }
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(err) => {
            errors.push(format!("restore GRO {name}: {err}"));
            false
        }
    }
}

struct GroRestore {
    errors: Vec<String>,
    members: Vec<Value>,
}

fn restore_previous_member_gro(host: &Host, previous: &Value) -> GroRestore {
    let mut errors = Vec::new();
    let mut members = Vec::new();
    for entry in js::array(g(g(previous, "member_gro"), "members")) {
        if !restore_member_gro(host, &entry, &mut errors) {
            members.push(entry);
        }
    }
    GroRestore { errors, members }
}

fn disabled_member_gro_state(bridge_mtu: &Value, restore: &GroRestore) -> Value {
    json!({
        "required": false, "applied": false, "bridge_mtu": js::int_value(bridge_mtu, 0, 65535, 0), "wan_mtu": 0,
        "members": restore.members, "errors": restore.errors,
        "note": "LAN GRO adaptation is disabled and plugin-owned changes were restored.",
    })
}

pub(crate) fn normalize_profile(key: &str, raw: &Value) -> Result<Value> {
    let bridge = iface_name(&js::text(js::first(&[g(raw, "bridge"), g(raw, "bridge_interface"), &json!("br-lan")])), "bridge")?;
    let ports = iface_list(js::first(&[g(raw, "ports"), g(raw, "member_ports"), g(raw, "interfaces"), &json!([])]))?;
    if ports.iter().any(|port| *port == bridge) {
        bail!("LAN port must be different from bridge");
    }
    let addresses = cidr_list(js::first(&[g(raw, "addresses"), g(raw, "bridge_addresses"), g(raw, "ipv4_cidr"), &json!("192.168.100.1/24")]));
    let dns_mode = normalize_dns_mode(js::first(&[g(raw, "dns_mode"), g(raw, "dns"), &json!("auto")]))?;
    let manual_dns_servers = dns_server_list(js::first(&[g(raw, "dns_servers"), g(raw, "manual_dns_servers"), &json!([])]));
    if dns_mode == "manual" && manual_dns_servers.is_empty() {
        bail!("manual DNS mode requires at least one DNS server");
    }
    let first_v4 = first_ipv4_cidr(&addresses);
    Ok(json!({
        "profile_key": key,
        "bridge": bridge,
        "ports": ports,
        "mtu": js::int_value(js::or(g(raw, "mtu"), g(raw, "bridge_mtu")), 576, 65535, 1500),
        "addresses": addresses,
        "dhcpv4_enabled": js::bool_value(g(raw, "dhcpv4_enabled"), false),
        "dhcpv4_cidr": first_text(&[g(raw, "dhcpv4_cidr"), &json!(first_v4)]),
        "dhcpv4_gateway": first_text(&[g(raw, "dhcpv4_gateway")]),
        "dhcpv4_pool_start": first_text(&[g(raw, "dhcpv4_pool_start")]),
        "dhcpv4_pool_end": first_text(&[g(raw, "dhcpv4_pool_end")]),
        "dns_mode": dns_mode,
        "dns_servers": manual_dns_servers,
        "wan_ref": js::token(js::or(g(raw, "wan_ref"), g(raw, "wan"))),
        "wan_plugin": js::token(js::or(g(raw, "wan_plugin"), &json!("wan_core"))),
        "wan_egress_interface": optional_iface_name(js::first(&[g(raw, "wan_egress_interface"), g(raw, "out_interface"), g(raw, "wan_interface"), &json!("")]))?,
        "wan_egress_source_ip": first_text(&[g(raw, "wan_egress_source_ip"), g(raw, "out_source_ip"), g(raw, "source_ip")]),
        "auto_egress_nat": js::bool_value(g(raw, "auto_egress_nat"), true),
        "auto_ipv6_pd": js::bool_value(g(raw, "auto_ipv6_pd"), true),
        "ipv6_subnet_id": js::int_value(js::or(g(raw, "ipv6_subnet_id"), g(raw, "pd_subnet_id")), 0, 65535, 0),
        "nat_type": js::text(js::or(g(raw, "nat_type"), &json!("symmetric"))),
        "protocol": normalize_protocol(js::or(g(raw, "protocol"), &json!("tcp+udp+icmp")))?,
        "redirect_mode": normalize_redirect_mode(js::first(&[g(raw, "redirect_mode"), g(raw, "egress_nat_redirect_mode"), &json!("")])),
        "preserve_bridge": js::bool_value(g(raw, "preserve_bridge"), is_protected_bridge_name(&bridge)),
    }))
}

fn resolve_wan_egress(host: &Host, profile: &Value) -> Value {
    let explicit = truthy(&profile["wan_egress_interface"]);
    let mut result = json!({
        "plugin": profile["wan_plugin"],
        "ref": profile["wan_ref"],
        "interface": profile["wan_egress_interface"],
        "source_ip": profile["wan_egress_source_ip"],
        "mtu": interface_mtu(host, &profile["wan_egress_interface"]),
        "segmentation_ready": false,
        "redirect_mode": "",
        "pd_prefix": "",
        "pd_prefixes": [],
        "source": if explicit { "profile" } else { "wan_core" },
        "resolved": explicit,
        "available": explicit,
    });
    let wan_plugin = js::text(&profile["wan_plugin"]);
    let attempt: Result<Option<Value>> = (|| {
        let provider = host.call("plugins.services.resolve", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": wan_plugin}]))?;
        let exposes_status = js::array(g(g(&provider, "service"), "resources")).iter().any(|resource| resource.as_str() == Some("status"));
        if !exposes_status {
            bail!("WAN adapter service does not expose status");
        }
        host.call("plugins.resources.get", json!([wan_plugin, "status", profile["wan_ref"]])).map(Some)
    })();
    match attempt {
        Err(err) => {
            if !explicit {
                result["source"] = json!("error");
                result["last_error"] = json!(err.to_string());
            }
            result
        }
        Ok(record) => {
            let record = record.unwrap_or(Value::Null);
            let data = g(&record, "data");
            if truthy(data) {
                let veer_core = g(data, "veer_core");
                result["segmentation_ready"] = json!(js::is_true(g(data, "segmentation_ready")) || js::is_true(g(veer_core, "segmentation_ready")));
                result["handoff_mode"] = json!(first_text(&[g(data, "handoff_mode"), g(veer_core, "mode")]));
                result["redirect_mode"] = json!(normalize_redirect_mode(js::first(&[g(data, "egress_nat_redirect_mode"), g(veer_core, "egress_nat_redirect_mode"), &json!("")])));
                let current_mtu = js::int_value(&result["mtu"], 0, 65535, 0);
                result["mtu"] = json!(js::int_value(js::or(g(data, "mtu"), g(veer_core, "mtu")), 0, 65535, current_mtu));
                if !truthy(&result["interface"]) {
                    result["phase"] = json!(first_text(&[g(data, "phase")]));
                    let empty = json!("");
                    let candidate = js::first(&[
                        g(data, "egress_nat_parent_interface"),
                        g(veer_core, "egress_nat_interface"),
                        g(data, "veer_parent_interface"),
                        g(veer_core, "parent_interface"),
                        g(data, "host_interface"),
                        &empty,
                    ]);
                    result["interface"] = json!(optional_iface_name(candidate).unwrap_or_default());
                    result["source"] = json!("wan_core");
                }
                if !truthy(&result["mtu"]) {
                    result["mtu"] = json!(interface_mtu(host, &result["interface"]));
                }
                result["resolved"] = json!(truthy(&result["interface"]));
                if js::is_false(g(&record, "enabled")) {
                    result["available"] = json!(explicit);
                    if !explicit {
                        result["last_error"] = json!("WAN handoff is prepared but the WAN status is disabled");
                    }
                    return result;
                }
                result["available"] = json!(true);
                let pd_prefixes = js::array(g(data, "pd_prefixes"));
                result["pd_prefix"] = json!(first_text(&[g(data, "pd_prefix"), &json!(first_prefix_value(&pd_prefixes))]));
                result["pd_prefixes"] = Value::Array(pd_prefixes);
                result["dns_servers"] = json!(dns_server_list(js::first(&[g(data, "dns_servers"), g(veer_core, "dns_servers"), &json!([])])));
                if !truthy(&result["source_ip"]) {
                    let first_host = js::array(g(data, "host_addresses")).first().cloned().unwrap_or(json!(""));
                    result["source_ip"] = json!(ip_address(js::first(&[g(data, "ipv4"), &first_host, &json!("")])));
                }
                if !truthy(&result["resolved"]) {
                    result["last_error"] = json!("WAN status does not publish an egress interface");
                }
                return result;
            }
            if explicit {
                return result;
            }
            result["last_error"] = json!("WAN status record is unavailable or disabled");
            result
        }
    }
}

fn interface_mtu(host: &Host, name: &Value) -> i64 {
    let name = safe_iface_name(name);
    if name.is_empty() {
        return 0;
    }
    match host.call("net.link.get", json!([name])) {
        Ok(link) => js::int_value(g(&link, "mtu"), 0, 65535, 0),
        Err(_) => 0,
    }
}

fn resolve_dns_state(profile: &Value, wan_egress: &Value) -> Value {
    let source = js::text(&profile["dns_mode"]);
    let servers = match source.as_str() {
        "manual" => dns_server_list(&profile["dns_servers"]),
        "auto" => dns_server_list(js::or(g(wan_egress, "dns_servers"), &json!([]))),
        _ => Vec::new(),
    };
    let source_label = if source == "auto" { js::text(js::or(g(wan_egress, "source"), &json!("wan_core"))) } else { source.clone() };
    json!({
        "mode": source,
        "source": source_label,
        "servers": servers,
        "ipv4_servers": dns_servers_by_family(&servers, 4),
        "ipv6_servers": dns_servers_by_family(&servers, 6),
        "resolved": source == "disabled" || !servers.is_empty(),
        "note": if source == "auto" && servers.is_empty() { "WAN Core has not published usable DNS servers yet." } else { "" },
    })
}

fn build_dhcpv4_plan(key: &str, profile: &Value, dns_state: &Value) -> Value {
    let mut plan = json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key, "bridge": profile["bridge"],
        "ipv4_cidr": profile["dhcpv4_cidr"], "gateway": profile["dhcpv4_gateway"], "pool_start": profile["dhcpv4_pool_start"],
        "pool_end": profile["dhcpv4_pool_end"], "dns_mode": dns_state["mode"], "dns_servers": dns_state["ipv4_servers"],
        "enabled": false, "note": "",
    });
    if !js::is_true(&profile["dhcpv4_enabled"]) {
        plan["note"] = json!("DHCPv4 is disabled for this LAN profile.");
        return plan;
    }
    if !truthy(&plan["ipv4_cidr"]) {
        plan["note"] = json!("DHCPv4 requires an IPv4 gateway CIDR on the LAN bridge.");
        return plan;
    }
    plan["enabled"] = json!(true);
    plan["note"] = if truthy(&dns_state["note"]) {
        dns_state["note"].clone()
    } else {
        json!("Serve DHCPv4 on the existing LAN bridge and distribute the effective IPv4 DNS servers.")
    };
    plan
}

fn build_egress_nat_plan(key: &str, profile: &Value, wan_egress: &Value) -> Value {
    let available = !js::is_false(g(wan_egress, "available"));
    let interface = truthy(g(wan_egress, "interface"));
    let mut note = if interface && available {
        "Apply generated outbound NAT to core: parent_interface=LAN bridge, out_interface=WAN egress.".to_string()
    } else if interface {
        "WAN handoff exists but is not available; keep generated outbound NAT disabled until wan_core publishes an active status.".to_string()
    } else {
        "WAN egress interface is not set yet; keep generated outbound NAT disabled until wan_core publishes one.".to_string()
    };
    if truthy(g(wan_egress, "last_error")) {
        note = format!("{note} {}", js::string(g(wan_egress, "last_error")));
    }
    let redirect_mode = if truthy(&profile["redirect_mode"]) {
        profile["redirect_mode"].clone()
    } else {
        json!(normalize_redirect_mode(js::or(g(wan_egress, "redirect_mode"), &json!(""))))
    };
    json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key,
        "parent_interface": profile["bridge"], "child_interface": "",
        "out_interface": g(wan_egress, "interface"), "out_source_ip": g(wan_egress, "source_ip"),
        "protocol": profile["protocol"], "nat_type": profile["nat_type"], "redirect_mode": redirect_mode,
        "enabled": js::is_true(&profile["auto_egress_nat"]) && available && interface,
        "note": note,
    })
}

fn build_ipv6_assignment_plan(host: &Host, key: &str, profile: &Value, wan_egress: &Value, dns_state: &Value) -> Value {
    let mut plan = json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key,
        "parent_interface": g(wan_egress, "interface"), "target_interface": profile["bridge"],
        "parent_prefix": g(wan_egress, "pd_prefix"), "assigned_prefix": "", "subnet_index": profile["ipv6_subnet_id"],
        "upstream_routed": true, "configure_gateway": true, "reject_unassigned": true,
        "dns_mode": dns_state["mode"], "dns_servers": dns_state["ipv6_servers"], "enabled": false, "note": "",
    });
    if !js::is_true(&profile["auto_ipv6_pd"]) {
        plan["note"] = json!("Automatic IPv6 PD assignment is disabled for this LAN profile.");
        return plan;
    }
    if !truthy(&plan["parent_interface"]) || !truthy(&plan["parent_prefix"]) {
        let mut note = "WAN Core has not published both an egress interface and delegated IPv6 prefix yet.".to_string();
        if truthy(g(wan_egress, "last_error")) {
            note = format!("{note} {}", js::string(g(wan_egress, "last_error")));
        }
        plan["note"] = json!(note);
        return plan;
    }
    match host.call("net.prefix.subnet", json!([{"prefix": plan["parent_prefix"], "new_length": 64, "index": plan["subnet_index"]}])) {
        Ok(assigned) => {
            plan["assigned_prefix"] = assigned;
            plan["enabled"] = json!(true);
            plan["note"] = json!("Route and advertise the selected /64 on the LAN bridge; the upstream already routes the delegated parent prefix.");
        }
        Err(err) => {
            plan["last_error"] = json!(err.to_string());
            plan["note"] = json!("Delegated prefix cannot provide the selected /64.");
        }
    }
    plan
}

fn disabled_dhcpv4_plan(key: &str, bridge: &str, note: &str) -> Value {
    let key = js::token(&json!(key));
    json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key, "bridge": safe_iface_name(&json!(bridge)),
        "ipv4_cidr": "", "gateway": "", "pool_start": "", "pool_end": "", "dns_mode": "disabled", "dns_servers": [],
        "enabled": false, "note": if note.trim().is_empty() { "disabled" } else { note.trim() },
    })
}

fn disabled_ipv6_assignment_plan(key: &str, bridge: &str, note: &str) -> Value {
    let key = js::token(&json!(key));
    json!({
        "lan_id": key, "source": "lan_core", "owner_plugin": "lan_core", "owner_key": key, "parent_interface": "",
        "target_interface": safe_iface_name(&json!(bridge)), "parent_prefix": "", "assigned_prefix": "",
        "upstream_routed": true, "configure_gateway": true, "reject_unassigned": true,
        "enabled": false, "note": if note.trim().is_empty() { "disabled" } else { note.trim() },
    })
}

fn normalize_redirect_mode(value: &Value) -> &'static str {
    match js::lower(value).as_str() {
        "prepared_l2" | "raw_l2" | "vtap" => "prepared_l2",
        _ => "",
    }
}

/// Writes a record unless it is unchanged; plans are written with apply so
/// the host compiles them right away.
fn set_record_if_changed_apply(host: &Host, resource: &str, key: &str, data: &Value, enabled: bool, apply: bool) -> Result<()> {
    if let Some(current) = host.resources_get(resource, key)? {
        let current_data = js::or(g(&current, "data"), &Value::Null);
        let current_enabled = !js::is_false(g(&current, "enabled"));
        if current_enabled == enabled && js::stable_json(current_data) == js::stable_json(data) {
            return Ok(());
        }
    }
    host.call("resources.set", json!([resource, key, data, enabled, apply]))?;
    Ok(())
}

fn normalize_dns_mode(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("auto")));
    match value.as_str() {
        "auto" | "manual" | "disabled" => Ok(value),
        _ => bail!("dns_mode must be auto, manual or disabled"),
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
        if item.is_empty() || out.contains(&item) {
            continue;
        }
        out.push(item);
        if out.len() >= 8 {
            break;
        }
    }
    out
}

fn dns_servers_by_family(values: &[String], family: u8) -> Vec<String> {
    values.iter().filter(|value| value.contains(':') == (family == 6)).cloned().collect()
}

fn first_ipv4_cidr(values: &[String]) -> String {
    values.iter().find(|value| !value.contains(':')).cloned().unwrap_or_default()
}

fn first_prefix_value(values: &[Value]) -> String {
    match values.first() {
        None => String::new(),
        Some(first) if first.is_object() => first_text(&[g(first, "prefix"), g(first, "cidr")]),
        Some(first) => first_text(&[first]),
    }
}

fn ip_address(value: &Value) -> String {
    let text = js::text(value);
    match text.find('/') {
        Some(slash) => text[..slash].to_string(),
        None => text,
    }
}

fn optional_iface_name(value: &Value) -> Result<String> {
    let text = js::text(value);
    if text.is_empty() {
        return Ok(String::new());
    }
    iface_name(&text, "interface")
}

fn link_exists(host: &Host, name: &str) -> bool {
    let name = safe_iface_name(&json!(name));
    if name.is_empty() {
        return false;
    }
    host.call("net.link.get", json!([name])).map(|info| truthy(g(&info, "name"))).unwrap_or(false)
}

fn safe_iface_name(value: &Value) -> String {
    optional_iface_name(value).unwrap_or_default()
}

fn iface_name(value: &str, label: &str) -> Result<String> {
    veer_plugin::netconf::iface_name(value, label)
}

/// Interface names from an array or a comma list; every entry must be valid.
fn iface_list(value: &Value) -> Result<Vec<String>> {
    let raw: Vec<Value> = match value {
        Value::Array(items) => items.clone(),
        other => js::text(other).split(',').map(|item| json!(item)).collect(),
    };
    let mut out: Vec<String> = Vec::new();
    for item in raw {
        let name = iface_name(&js::text(&item), "port")?;
        if !out.contains(&name) {
            out.push(name);
        }
    }
    Ok(out)
}

fn normalize_protocol(value: &Value) -> Result<String> {
    let value = js::lower(js::or(value, &json!("tcp+udp+icmp")));
    if value.is_empty() {
        return Ok("tcp+udp+icmp".to_string());
    }
    let mut seen = BTreeSet::new();
    for part in value.split(|ch: char| !ch.is_ascii_lowercase() && !ch.is_ascii_digit()) {
        if part.is_empty() {
            continue;
        }
        if part != "tcp" && part != "udp" && part != "icmp" {
            bail!("protocol must include one or more of tcp, udp, icmp");
        }
        seen.insert(part.to_string());
    }
    let out: Vec<&str> = ["tcp", "udp", "icmp"].into_iter().filter(|name| seen.contains(*name)).collect();
    if out.is_empty() {
        bail!("protocol must include one or more of tcp, udp, icmp");
    }
    Ok(out.join("+"))
}

fn is_protected_bridge_name(value: &str) -> bool {
    value.trim().to_lowercase().starts_with("vmbr")
}

#[cfg(test)]
mod tests;
