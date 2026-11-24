use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{json, Value};

use super::*;

#[derive(Default)]
struct Net {
    links: BTreeMap<String, Value>,
    next: u64,
    gro: BTreeMap<String, bool>,
    /// Links whose delete fails.
    undeletable: std::collections::BTreeSet<String>,
}

fn fixture(wan_status: Option<Value>) -> (Arc<Mutex<Net>>, Harness<LanCore>) {
    let fake = FakeHost::new();
    let net = Arc::new(Mutex::new(Net { next: 30, ..Net::default() }));
    for port in ["lanp0", "lanp1"] {
        let mut n = net.lock().unwrap();
        let index = n.next;
        n.next += 1;
        n.links.insert(port.to_string(), json!({"name": port, "ifindex": index, "kind": "veth", "up": false, "mtu": 1500}));
        n.gro.insert(port.to_string(), true);
    }
    let m = net.clone();
    fake.adapter("net.link.get", move |args| m.lock().unwrap().links.get(args[0].as_str().unwrap()).cloned().ok_or_else(|| "link not found".to_string()));
    let m = net.clone();
    fake.adapter("net.link.list", move |_| Ok(Value::Array(m.lock().unwrap().links.values().cloned().collect())));
    let m = net.clone();
    fake.adapter("net.link.ensureBridge", move |args| {
        let mut n = m.lock().unwrap();
        let name = args[0]["name"].as_str().unwrap().to_string();
        let created = !n.links.contains_key(&name);
        if created {
            let index = n.next;
            n.next += 1;
            n.links.insert(name.clone(), json!({"name": name, "ifindex": index, "kind": "bridge", "up": true, "mtu": args[0]["mtu"]}));
        }
        let mut link = n.links[&name].clone();
        link["created"] = json!(created);
        Ok(link)
    });
    let m = net.clone();
    fake.adapter("net.link.setMaster", move |args| {
        let mut n = m.lock().unwrap();
        let master = args[0]["master"].as_str().unwrap().to_string();
        let master_index = n.links.get(&master).map(|link| link["ifindex"].clone()).unwrap_or(json!(0));
        let link = n.links.get_mut(args[0]["link"].as_str().unwrap()).ok_or("link not found")?;
        link["master_name"] = json!(master);
        link["master_ifindex"] = master_index;
        link["up"] = json!(true);
        Ok(link.clone())
    });
    let m = net.clone();
    fake.adapter("net.link.clearMaster", move |args| {
        let mut n = m.lock().unwrap();
        if let Some(link) = n.links.get_mut(args[0].as_str().unwrap()) {
            link.as_object_mut().unwrap().remove("master_name");
            link.as_object_mut().unwrap().remove("master_ifindex");
        }
        Ok(Value::Null)
    });
    let m = net.clone();
    fake.adapter("net.link.delete", move |args| {
        let mut n = m.lock().unwrap();
        let name = args[0].as_str().unwrap();
        if n.undeletable.contains(name) {
            return Err(format!("delete {name}: device or resource busy"));
        }
        n.links.remove(name);
        Ok(Value::Null)
    });
    let m = net.clone();
    fake.adapter("net.link.getOffloads", move |args| Ok(json!({"gro": m.lock().unwrap().gro.get(args[0].as_str().unwrap()).copied().unwrap_or(true)})));
    let m = net.clone();
    fake.adapter("net.link.setOffloads", move |args| {
        if let Some(gro) = args[1]["gro"].as_bool() {
            m.lock().unwrap().gro.insert(args[0].as_str().unwrap().to_string(), gro);
        }
        Ok(Value::Null)
    });
    fake.adapter("net.addr.replace", |_| Ok(Value::Null));
    fake.adapter("net.addr.delete", |_| Ok(Value::Null));
    fake.adapter("net.prefix.subnet", |args| Ok(json!(format!("{}#{}", args[0]["prefix"].as_str().unwrap(), args[0]["index"]))));
    fake.adapter("plugins.services.resolve", |_| Ok(json!({"service": {"id": "wan.adapter", "resources": ["profiles", "sessions", "status"]}})));
    fake.adapter("plugins.resources.get", move |_| Ok(wan_status.clone().unwrap_or(Value::Null)));
    let h = Harness::<LanCore>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
    (net, h)
}

#[test]
fn profiles_normalize_like_the_scripts() {
    let profile = normalize_profile("lan", &json!({"bridge": "br-lan", "ports": "lanp0, lanp1", "dns_mode": "manual", "dns_servers": "1.1.1.1 2606:4700::1111"})).unwrap();
    assert_eq!(profile["ports"], json!(["lanp0", "lanp1"]));
    assert_eq!(profile["addresses"], json!(["192.168.100.1/24"]));
    assert_eq!(profile["dhcpv4_cidr"], "192.168.100.1/24");
    assert_eq!(profile["protocol"], "tcp+udp+icmp");
    assert_eq!(profile["preserve_bridge"], false);
    assert_eq!(normalize_profile("lan", &json!({"bridge": "vmbr0"})).unwrap()["preserve_bridge"], true);
    assert!(normalize_profile("lan", &json!({"bridge": "br-lan", "ports": ["br-lan"]})).is_err());
    assert!(normalize_profile("lan", &json!({"dns_mode": "manual"})).unwrap_err().to_string().contains("at least one DNS server"));
}

#[test]
fn apply_network_builds_the_bridge_and_its_plans() {
    let wan = json!({"enabled": true, "data": {"phase": "applied", "egress_nat_parent_interface": "veerlocal0", "mtu": 1492,
        "segmentation_ready": true, "pd_prefix": "2001:db8:100::/56", "dns_servers": ["223.5.5.5", "2001:db8::53"], "ipv4": "198.51.100.2"}});
    let (net, mut h) = fixture(Some(wan));
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0", "lanp1"], "dhcpv4_enabled": true})).unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "applied", "{status}");
    assert_eq!(status["managed_ports"], json!(["lanp0", "lanp1"]));
    assert_eq!(status["bridge_members"].as_array().unwrap().len(), 2);
    let egress = h.fake.data("egress_nat_plans", "default");
    assert_eq!(egress["enabled"], true);
    assert_eq!(egress["out_interface"], "veerlocal0");
    assert_eq!(egress["out_source_ip"], "198.51.100.2");
    let dhcp = h.fake.data("dhcpv4_plans", "default");
    assert_eq!(dhcp["enabled"], true);
    assert_eq!(dhcp["dns_servers"], json!(["223.5.5.5"]));
    let ipv6 = h.fake.data("ipv6_assignment_plans", "default");
    assert_eq!(ipv6["enabled"], true);
    assert_eq!(ipv6["dns_servers"], json!(["2001:db8::53"]));
    assert!(ipv6.get("parent_valid_until_ms").is_none(), "no lease times, no deadline: {ipv6}");
    // A segmented WAN provides its own segmentation boundary: GRO stays on.
    assert_eq!(status["member_gro"]["required"], false);
    assert!(net.lock().unwrap().gro.values().all(|gro| *gro));
    assert_eq!(h.fake.timer(REPAIR_TIMER).unwrap()["delay_ms"], json!(SAFETY_REPAIR_MS));
}

#[test]
fn a_port_list_with_a_trailing_comma_or_blank_entries_is_accepted() {
    for ports in [json!("lanp0, lanp1,"), json!(" lanp0 ,, lanp1 "), json!(["lanp0", "", "  ", "lanp1"])] {
        let profile = normalize_profile("lan", &json!({"bridge": "br-lan", "ports": ports})).unwrap();
        assert_eq!(profile["ports"], json!(["lanp0", "lanp1"]), "ports {ports}");
    }
    assert_eq!(normalize_profile("lan", &json!({"ports": ","})).unwrap()["ports"], json!([]));
    assert!(normalize_profile("lan", &json!({"ports": "lan p0"})).is_err(), "a name with a space is still invalid");
}

#[test]
fn renaming_the_bridge_deletes_the_one_the_plugin_created() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    assert_eq!(h.fake.data("status", "default")["bridge_created"], true);

    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan1", "ports": ["lanp0"]})).unwrap();
    {
        let n = net.lock().unwrap();
        assert!(!n.links.contains_key("brlan0"), "the old plugin-created bridge is left behind");
        assert_eq!(n.links["lanp0"]["master_name"], "brlan1");
    }
    let status = h.fake.data("status", "default");
    assert_eq!(status["bridge"], "brlan1");
    assert_eq!(status["retired_bridges"], json!([]));

    // A pre-existing bridge is never deleted, renamed away from or not.
    net.lock().unwrap().links.insert("vmbr9".into(), json!({"name": "vmbr9", "ifindex": 90, "kind": "bridge", "up": true}));
    h.action("apply_network", json!({"lan_id": "default", "bridge": "vmbr9", "ports": ["lanp0"]})).unwrap();
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan2", "ports": ["lanp0"]})).unwrap();
    assert!(net.lock().unwrap().links.contains_key("vmbr9"));
    assert!(!net.lock().unwrap().links.contains_key("brlan1"), "brlan1 was deleted when the profile moved to vmbr9");
}

#[test]
fn a_retired_bridge_whose_delete_failed_is_deleted_later() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    net.lock().unwrap().undeletable.insert("brlan0".into());
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan1", "ports": ["lanp0"]})).unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["retired_bridges"], json!(["brlan0"]));
    assert!(js::text(&status["cleanup_errors"]).contains("retired bridge brlan0"), "{status}");

    net.lock().unwrap().undeletable.clear();
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan1", "ports": ["lanp0"]})).unwrap();
    assert!(!net.lock().unwrap().links.contains_key("brlan0"));
    assert_eq!(h.fake.data("status", "default")["retired_bridges"], json!([]));

    // A teardown deletes retired bridges too.
    net.lock().unwrap().undeletable.insert("brlan1".into());
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan2", "ports": ["lanp0"]})).unwrap();
    net.lock().unwrap().undeletable.clear();
    h.action("teardown", json!({"lan_id": "default"})).unwrap();
    let n = net.lock().unwrap();
    assert!(!n.links.contains_key("brlan1") && !n.links.contains_key("brlan2"), "links left: {:?}", n.links.keys());
}

#[test]
fn a_retired_bridge_another_profile_now_uses_is_left_alone() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    h.fake.put_record("profiles", "guest", json!({"bridge": "brlan0", "ports": []}), true);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan1", "ports": ["lanp0"]})).unwrap();
    assert!(net.lock().unwrap().links.contains_key("brlan0"));
    assert_eq!(h.fake.data("status", "default")["retired_bridges"], json!([]));
}

#[test]
fn the_ipv6_plan_keeps_within_the_delegated_prefix_lease() {
    let wan = json!({"enabled": true, "data": {"phase": "applied", "egress_nat_parent_interface": "veerlocal0", "segmentation_ready": true,
        "pd_prefix": "2001:db8:100::/56", "pd_prefixes": [
            {"prefix": "2001:db8:200::/56", "preferred_until_ms": 1.0, "valid_until_ms": 2.0},
            {"prefix": "2001:db8:100::/56", "preferred_until_ms": 1800000000000.0, "valid_until_ms": 1800003600000.0}]}});
    let (_net, mut h) = fixture(Some(wan));
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    let ipv6 = h.fake.data("ipv6_assignment_plans", "default");
    assert_eq!(ipv6["enabled"], true, "{ipv6}");
    assert_eq!(ipv6["parent_preferred_until_ms"], json!(1800000000000i64));
    assert_eq!(ipv6["parent_valid_until_ms"], json!(1800003600000i64));
}

#[test]
fn a_lower_mtu_wan_without_segmentation_turns_member_gro_off_and_teardown_restores_it() {
    let wan = json!({"enabled": true, "data": {"phase": "applied", "egress_nat_parent_interface": "veerlocal0", "mtu": 1400}});
    let (net, mut h) = fixture(Some(wan));
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"], "mtu": 1500})).unwrap();
    assert_eq!(h.fake.data("status", "default")["member_gro"]["required"], true);
    assert_eq!(net.lock().unwrap().gro["lanp0"], false);
    h.action("teardown", json!({"lan_id": "default"})).unwrap();
    assert_eq!(net.lock().unwrap().gro["lanp0"], true);
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "deleted");
    assert!(!net.lock().unwrap().links.contains_key("brlan0"), "a bridge this plugin created is deleted");
    assert!(h.fake.timers().is_empty());
}

#[test]
fn plans_stay_disabled_without_a_wan_egress() {
    let (_, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": []})).unwrap();
    let egress = h.fake.data("egress_nat_plans", "default");
    assert_eq!(egress["enabled"], false);
    assert!(egress["note"].as_str().unwrap().contains("WAN egress interface is not set yet"), "{egress}");
    assert_eq!(h.fake.record("egress_nat_plans", "default").unwrap()["enabled"], false);
}

#[test]
fn a_wan_status_change_arms_one_repair_and_own_records_do_not() {
    let (_, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0"})).unwrap();
    h.emit("resource.changed", json!({"plugin_id": "lan_core", "resource_id": "status", "operation": "update", "key": "default"})).unwrap();
    assert!(h.fake.timer(EVENT_TIMER).is_none(), "its own status is not news");
    h.emit("resource.changed", json!({"plugin_id": "wan_core", "resource_id": "status", "operation": "update", "key": "default"})).unwrap();
    assert!(h.fake.timer(EVENT_TIMER).is_some());
    h.fire_timer(EVENT_TIMER).unwrap();
    assert!(h.fake.timer(EVENT_TIMER).is_none());
}

/// Makes the host refuse an enabled DHCPv4 plan while `fail` is set, as it
/// does when the plan cannot be served (port 67 taken, a bad pool).
fn fail_dhcpv4_plans(h: &Harness<LanCore>) -> Arc<Mutex<bool>> {
    let fail = Arc::new(Mutex::new(true));
    let flag = fail.clone();
    let fake = h.fake.clone();
    h.fake.adapter("resources.set", move |args| {
        if *flag.lock().unwrap() && args[0] == "dhcpv4_plans" && args[2]["enabled"] == true {
            return Err("resources.set: apply dhcpv4_plans: port 67 is in use".to_string());
        }
        fake.call_builtin("resources.set", args)
    });
    fail
}

#[test]
fn a_failed_first_apply_still_owns_the_bridge_ports_and_gro_it_changed() {
    let wan = json!({"enabled": true, "data": {"phase": "applied", "egress_nat_parent_interface": "veerlocal0", "mtu": 1400}});
    let (net, mut h) = fixture(Some(wan));
    let fail = fail_dhcpv4_plans(&h);
    h.fake.put_record("profiles", "default", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"], "dhcpv4_enabled": true}), true);
    h.reconcile().unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "error", "{status}");
    assert_eq!(status["bridge_created"], true, "{status}");
    assert_eq!(status["managed_ports"], json!(["lanp0"]), "{status}");
    assert_eq!(net.lock().unwrap().gro["lanp0"], true, "GRO this attempt turned off is restored");

    *fail.lock().unwrap() = false;
    h.action("teardown", json!({"lan_id": "default"})).unwrap();
    let n = net.lock().unwrap();
    assert!(!n.links.contains_key("brlan0"), "the bridge the failed apply created is deleted");
    assert!(n.links["lanp0"].get("master_name").is_none(), "the port it attached is detached");
}

#[test]
fn an_error_after_a_good_apply_keeps_ownership_for_the_next_apply_and_teardown() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0", "lanp1"], "dhcpv4_enabled": true})).unwrap();
    assert_eq!(h.fake.data("status", "default")["bridge_created"], true);
    let fail = Arc::new(Mutex::new(true));
    let flag = fail.clone();
    h.fake.adapter("net.addr.replace", move |_| if *flag.lock().unwrap() { Err("net.addr.replace: file exists".to_string()) } else { Ok(Value::Null) });
    h.fire_timer(REPAIR_TIMER).unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "error", "{status}");
    assert_eq!(status["bridge_created"], true, "{status}");
    assert_eq!(status["managed_ports"], json!(["lanp0", "lanp1"]), "{status}");

    // The next good apply still knows the bridge and ports are its own.
    *fail.lock().unwrap() = false;
    h.fire_timer(REPAIR_TIMER).unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "applied", "{status}");
    assert_eq!(status["bridge_created"], true, "{status}");
    assert_eq!(status["managed_ports"], json!(["lanp0", "lanp1"]), "{status}");

    h.action("teardown", json!({"lan_id": "default"})).unwrap();
    let n = net.lock().unwrap();
    assert!(!n.links.contains_key("brlan0"));
    assert!(n.links["lanp0"].get("master_name").is_none());
    assert!(n.links["lanp1"].get("master_name").is_none());
}

#[test]
fn disabling_a_profile_keeps_ownership_for_a_later_teardown() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    let profile = h.fake.data("profiles", "default");
    h.fake.put_record("profiles", "default", profile, false);
    h.fire_timer(REPAIR_TIMER).unwrap();
    let status = h.fake.data("status", "default");
    assert_eq!(status["phase"], "disabled", "{status}");
    assert_eq!(status["bridge_created"], true, "{status}");
    h.action("teardown", json!({"lan_id": "default"})).unwrap();
    let n = net.lock().unwrap();
    assert!(!n.links.contains_key("brlan0"));
    assert!(n.links["lanp0"].get("master_name").is_none());
}

#[test]
fn traffic_stats_reads_bridge_and_member_counters() {
    let (net, mut h) = fixture(None);
    h.action("apply_network", json!({"lan_id": "default", "bridge": "brlan0", "ports": ["lanp0"]})).unwrap();
    net.lock().unwrap().links.get_mut("brlan0").unwrap()["statistics"] = json!({"rx_packets": 5, "tx_bytes": -1});
    let stats = h.query("traffic_stats", json!({"lan_id": "default"}));
    assert_eq!(stats["available"], true);
    assert_eq!(stats["bridge"]["statistics"]["rx_packets"], 5);
    assert_eq!(stats["bridge"]["statistics"]["tx_bytes"], 0);
    assert_eq!(stats["ports"][0]["name"], "lanp0");
}
