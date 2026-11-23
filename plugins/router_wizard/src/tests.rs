use std::sync::{Arc, Mutex};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{json, Value};

use super::*;

/// The payload the router page builds from its form (ui/index.html payload()).
fn form_payload(cfg: &Value, password: &str) -> Value {
    let pppoe = &cfg["wan"]["pppoe"];
    json!({
        "wan": {
            "mode": cfg["wan"]["mode"], "source_ip": cfg["wan"]["source_ip"], "egress_interface": "",
            "pppoe": {
                "interface": pppoe["interface"], "mac_mode": pppoe["mac_mode"], "mac_address": pppoe["mac_address"],
                "username": pppoe["username"], "password": password, "service": pppoe["service"], "auth": pppoe["auth"],
                "negotiate_ipv6": pppoe["negotiate_ipv6"], "request_pd": pppoe["request_pd"],
                "install_tunnel": pppoe["install_tunnel"], "auto_redial": pppoe["auto_redial"],
            },
        },
        "lan": {
            "bridge": cfg["lan"]["bridge"], "ports": cfg["lan"]["ports"], "addresses": cfg["lan"]["addresses"], "mtu": cfg["lan"]["mtu"],
            "auto_egress_nat": cfg["lan"]["auto_egress_nat"], "dhcpv4_enabled": cfg["lan"]["dhcpv4_enabled"],
            "dns_mode": cfg["lan"]["dns_mode"], "dns_servers": cfg["lan"]["dns_servers"], "protocol": "tcp+udp+icmp",
            "nat_type": cfg["lan"]["nat_type"], "redirect_mode": "",
        },
    })
}

#[test]
fn canonical_and_legacy_pppoe_settings_round_trip() {
    let input = json!({"wan": {"mode": "pppoe", "pppoe_interface": "eth0", "username": "alice", "password": "saved",
        "mac_mode": "manual", "mac_address": "02:00:00:00:00:01", "negotiate_ipv6": true, "request_pd": true,
        "install_tunnel": false, "auto_redial": false}});
    for config in [input.clone(), normalize_config(&input).unwrap()] {
        let normalized = normalize_config(&config).unwrap();
        let actual = &normalize_config(&form_payload(&normalized, "saved")).unwrap()["wan"]["pppoe"];
        assert_eq!(actual["interface"], "eth0");
        assert_eq!(actual["username"], "alice");
        assert_eq!(actual["password"], "saved");
        assert_eq!(actual["mac_mode"], "manual");
        assert_eq!(actual["mac_address"], "02:00:00:00:00:01");
        assert_eq!(actual["negotiate_ipv6"], true);
        assert_eq!(actual["request_pd"], true);
        assert_eq!(actual["install_tunnel"], false);
        assert_eq!(actual["auto_redial"], false);
    }
}

#[test]
fn invalid_settings_are_rejected() {
    assert!(normalize_config(&json!({"wan": {"mode": "dhcp"}})).unwrap_err().to_string().contains("existing or pppoe"));
    assert!(normalize_config(&json!({"lan": {"protocol": "sctp"}})).is_err());
    assert!(normalize_config(&json!({"lan": {"dns_mode": "weird"}})).is_err());
    assert!(normalize_config(&json!({"wan": {"pppoe": {"auth": "eap"}}})).is_err());
    let protected = normalize_config(&json!({"lan": {"bridge": "vmbr0"}})).unwrap();
    assert_eq!(protected["lan"]["preserve_bridge"], true);
    assert_eq!(normalize_config(&json!({"lan": {"protocol": "udp,tcp"}})).unwrap()["lan"]["protocol"], "tcp+udp");
}

fn wizard() -> Harness<RouterWizard> {
    Harness::<RouterWizard>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), FakeHost::new())
}

#[test]
fn a_saved_password_stays_out_of_the_form_and_survives_apply() {
    let h = wizard();
    let config = normalize_config(&json!({"wan": {"mode": "pppoe", "pppoe_interface": "eth0", "username": "alice", "password": "saved"}})).unwrap();
    h.fake.put_record(CONFIG_RESOURCE, CONFIG_KEY, config.clone(), true);
    let payload = form_payload(&config, "__redacted__");
    assert_eq!(load_config_from_payload(&h.host, &payload).unwrap()["wan"]["pppoe"]["password"], "saved");
    let replaced = form_payload(&config, "replacement");
    assert_eq!(load_config_from_payload(&h.host, &replaced).unwrap()["wan"]["pppoe"]["password"], "replacement");
    h.fake.delete_record(CONFIG_RESOURCE, CONFIG_KEY);
    let err = load_config_from_payload(&h.host, &payload).unwrap_err();
    assert!(err.to_string().contains("No saved PPPoE password"), "{err}");
}

/// Models the durable operations journal and the downstream plugin services.
struct Downstream {
    operations: Vec<Value>,
    calls: Vec<(String, String, Value)>,
    fail_action: Option<(String, String)>,
}

fn orchestrated() -> (Arc<Mutex<Downstream>>, Harness<RouterWizard>) {
    let fake = FakeHost::new();
    let d = Arc::new(Mutex::new(Downstream { operations: Vec::new(), calls: Vec::new(), fail_action: None }));
    let m = d.clone();
    fake.adapter("operations.begin", move |args| {
        let mut d = m.lock().unwrap();
        let id = format!("op{}", d.operations.len() + 1);
        let mut op = args[0].clone();
        op["id"] = json!(id);
        op["revision"] = json!(1);
        op["status"] = json!("pending");
        op["resumable"] = json!(true);
        d.operations.push(op.clone());
        Ok(op)
    });
    let update = |d: &mut Downstream, id: &Value, edit: &dyn Fn(&mut Value)| -> Result<Value, String> {
        let op = d.operations.iter_mut().find(|op| op["id"] == *id).ok_or("no such operation")?;
        edit(op);
        op["revision"] = json!(op["revision"].as_i64().unwrap() + 1);
        Ok(op.clone())
    };
    let m = d.clone();
    fake.adapter("operations.claim", move |args| {
        update(&mut m.lock().unwrap(), &args[0], &|op| {
            op["status"] = json!("running");
        })
    });
    let m = d.clone();
    fake.adapter("operations.complete", move |args| {
        let result = args[2].clone();
        update(&mut m.lock().unwrap(), &args[0], &move |op| {
            op["status"] = json!("completed");
            op["resumable"] = json!(false);
            op["result"] = result.clone();
        })
    });
    let m = d.clone();
    fake.adapter("operations.fail", move |args| {
        update(&mut m.lock().unwrap(), &args[0], &|op| {
            op["status"] = json!("failed");
            op["resumable"] = json!(false);
        })
    });
    let m = d.clone();
    fake.adapter("operations.get", move |args| Ok(m.lock().unwrap().operations.iter().find(|op| op["id"] == args[0]).cloned().unwrap_or(Value::Null)));
    let m = d.clone();
    fake.adapter("operations.list", move |args| {
        let resumable_only = args[0]["resumable"] == true;
        Ok(Value::Array(m.lock().unwrap().operations.iter().filter(|op| !resumable_only || op["resumable"] == true).cloned().collect()))
    });
    let m = d.clone();
    fake.adapter("operations.getByKey", move |args| Ok(m.lock().unwrap().operations.iter().rev().find(|op| op["key"] == args[0]).cloned().unwrap_or(Value::Null)));
    fake.adapter("plugins.services.resolve", |args| {
        let service = args[0]["service"].as_str().unwrap();
        let actions = match service {
            "wan.adapter" => json!(["apply_session", "prepare_handoff", "teardown"]),
            "lan.adapter" => json!(["apply_network", "teardown"]),
            "pppoe.client" => json!(["dial", "disconnect", "clear_state"]),
            _ => json!([]),
        };
        Ok(json!({"service": {"id": service, "actions": actions, "resources": ["status", "egress_nat_plans", "wan_links", "sessions"]}}))
    });
    let m = d.clone();
    fake.adapter("plugins.services.call", move |args| {
        let mut d = m.lock().unwrap();
        let provider = args[0]["provider"].as_str().unwrap().to_string();
        let action = args[0]["action"].as_str().unwrap().to_string();
        d.calls.push((provider.clone(), action.clone(), args[0]["payload"].clone()));
        if d.fail_action.as_ref() == Some(&(provider.clone(), action.clone())) {
            return Err(format!("{provider}.{action} failed"));
        }
        Ok(json!({"phase": "applied"}))
    });
    fake.adapter("plugins.resources.list", |_| Ok(json!([])));
    let h = Harness::<RouterWizard>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
    (d, h)
}

#[test]
fn apply_router_calls_lan_and_saves_the_config() {
    let (d, mut h) = orchestrated();
    let status = h.query("apply_router", json!({"wan": {"mode": "existing", "egress_interface": "eth0"}, "lan": {"bridge": "br-lan", "ports": ["eth1"]}}));
    assert_eq!(status["phase"], "applied");
    let steps: Vec<String> = status["steps"].as_array().unwrap().iter().map(|step| step["name"].as_str().unwrap().to_string()).collect();
    assert_eq!(steps, vec!["wan.existing", "lan_core.apply_network"]);
    assert_eq!(h.fake.data(CONFIG_RESOURCE, CONFIG_KEY)["lan"]["ports"], json!(["eth1"]));
    let d = d.lock().unwrap();
    assert_eq!(d.calls.len(), 1);
    assert_eq!(d.calls[0].2["wan_egress_interface"], "eth0");
    assert_eq!(d.operations[0]["status"], "completed");
    assert!(h.fake.timer(ROUTER_RECOVERY_TIMER).is_none(), "the recovery timer stops once nothing is active");
}

#[test]
fn a_failed_pppoe_dial_rolls_back_in_reverse_order() {
    let (d, mut h) = orchestrated();
    d.lock().unwrap().fail_action = Some(("pppoe_client".to_string(), "dial".to_string()));
    let err = h
        .action("apply_router", json!({"wan": {"mode": "pppoe", "pppoe": {"interface": "eth0", "username": "alice", "password": "pw"}}}))
        .unwrap_err();
    assert!(err.to_string().contains("pppoe_client.dial failed"), "{err}");
    let calls: Vec<String> = d.lock().unwrap().calls.iter().map(|(p, a, _)| format!("{p}.{a}")).collect();
    assert_eq!(calls, vec!["wan_core.prepare_handoff", "pppoe_client.dial", "pppoe_client.disconnect", "wan_core.teardown"]);
    let status = h.fake.data("status", CONFIG_KEY);
    assert_eq!(status["phase"], "rolled_back");
    assert_eq!(h.fake.record("status", CONFIG_KEY).unwrap()["enabled"], false);
    assert_eq!(d.lock().unwrap().operations[0]["status"], "failed");
}

#[test]
fn teardown_runs_every_step_and_reports_the_first_failure() {
    let (d, mut h) = orchestrated();
    h.query("apply_router", json!({"wan": {"mode": "existing", "egress_interface": "eth0"}}));
    d.lock().unwrap().fail_action = Some(("lan_core".to_string(), "teardown".to_string()));
    let err = h.action("teardown_router", json!({})).unwrap_err();
    assert!(err.to_string().starts_with("lan_core.teardown: "), "{err}");
    assert_eq!(h.fake.data("status", CONFIG_KEY)["phase"], "teardown_partial");
    assert_eq!(h.fake.record(CONFIG_RESOURCE, CONFIG_KEY).unwrap()["enabled"], false);
}

#[test]
fn reconcile_without_a_config_reports_not_configured() {
    let (_, mut h) = orchestrated();
    h.reconcile().unwrap();
    assert_eq!(h.fake.data("status", CONFIG_KEY)["phase"], "not_configured");
}
