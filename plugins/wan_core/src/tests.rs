use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{json, Value};

use super::*;

const LOCAL: &str = "veerlocal0";
const PIPE: &str = "veerpipe0";
const WRITES: &[&str] = &[
    "net.link.ensureVeth",
    "net.link.ensureDummy",
    "net.link.setARP",
    "net.link.setGSO",
    "net.link.setOffloads",
    "net.addr.replace",
    "net.route.replace",
    "net.rule.replace",
    "net.neigh.replace",
];

#[derive(Clone)]
struct Link {
    name: String,
    kind: String,
    ifindex: u64,
    mtu: i64,
    up: bool,
    arp: bool,
    addresses: Vec<String>,
    peer: Option<String>,
    gso_max_size: i64,
    gso_max_segs: i64,
    offloads: BTreeMap<String, bool>,
}

#[derive(Clone)]
enum Fail {
    Never,
    Always,
    Host(String),
}

/// A small kernel model: links with addresses, GSO limits and offloads,
/// plus route, rule and neighbor sets keyed the way wan_core replaces them.
struct Kernel {
    links: BTreeMap<String, Link>,
    routes: BTreeMap<String, Value>,
    rules: BTreeMap<String, Value>,
    neigh: BTreeMap<String, Value>,
    next: u64,
    fail_ensure: Fail,
    failures: u32,
    fail_delete: bool,
}

impl Kernel {
    fn info(&self, link: &Link) -> Value {
        let peer_ifindex = link.peer.as_ref().and_then(|peer| self.links.get(peer)).map(|peer| peer.ifindex).unwrap_or(0);
        json!({
            "name": link.name, "ifindex": link.ifindex, "kind": link.kind, "mtu": link.mtu, "up": link.up, "arp": link.arp,
            "addresses": link.addresses, "peer_ifindex": peer_ifindex, "peer_name": link.peer.clone().unwrap_or_default(),
            "mac": format!("02:00:00:00:00:{:x}", link.ifindex), "gso_max_size": link.gso_max_size, "gso_max_segs": link.gso_max_segs,
        })
    }

    fn add(&mut self, name: &str, kind: &str, mtu: i64, up: bool, peer: Option<&str>) {
        let ifindex = self.next;
        self.next += 1;
        let offloads = [("sg", true), ("tso", true), ("gso", true), ("gro", true), ("lro", false)].iter().map(|(k, v)| (k.to_string(), *v)).collect();
        self.links.insert(
            name.to_string(),
            Link {
                name: name.to_string(),
                kind: kind.to_string(),
                ifindex,
                mtu,
                up,
                arp: true,
                addresses: Vec::new(),
                peer: peer.map(str::to_string),
                gso_max_size: 65536,
                gso_max_segs: 65535,
                offloads,
            },
        );
    }

    fn need(&mut self, name: &str) -> Result<&mut Link, String> {
        self.links.get_mut(name).ok_or_else(|| format!("link not found: {name}"))
    }

    fn delete(&mut self, name: &str) -> Result<(), String> {
        if self.fail_delete {
            return Err("net.link.delete: link is owned by another plugin".to_string());
        }
        let link = self.links.remove(name).ok_or_else(|| format!("link not found: {name}"))?;
        if let Some(peer) = link.peer {
            self.links.remove(&peer);
        }
        self.routes.retain(|_, route| route["dev"] != json!(name));
        Ok(())
    }

    fn ensure_veth(&mut self, req: &Value) -> Result<Value, String> {
        let host = req["host"].as_str().unwrap_or("").to_string();
        let fail = match &self.fail_ensure {
            Fail::Never => false,
            Fail::Always => true,
            Fail::Host(name) => *name == host,
        };
        if fail {
            self.failures += 1;
            return Err("temporary veth failure".to_string());
        }
        let peer = req["peer"].as_str().unwrap_or("").to_string();
        let mtu = req["mtu"].as_i64().unwrap_or(0);
        let up = req["up"].as_bool().unwrap_or(false);
        let mut created = false;
        if !self.links.contains_key(&host) && !self.links.contains_key(&peer) {
            self.add(&host, "veth", mtu, up, Some(&peer));
            self.add(&peer, "veth", mtu, up, Some(&host));
            created = true;
        }
        for name in [&host, &peer] {
            let link = self.need(name)?;
            if mtu != 0 {
                link.mtu = mtu;
            }
            if up {
                link.up = true;
            }
        }
        let host_info = self.info(&self.links[&host]);
        let peer_info = self.info(&self.links[&peer]);
        Ok(json!({"host": host_info, "peer": peer_info, "created": created}))
    }
}

type SharedKernel = Arc<Mutex<Kernel>>;

fn kernel(fake: &Arc<FakeHost>) -> SharedKernel {
    let k: SharedKernel = Arc::new(Mutex::new(Kernel {
        links: BTreeMap::new(),
        routes: BTreeMap::new(),
        rules: BTreeMap::new(),
        neigh: BTreeMap::new(),
        next: 10,
        fail_ensure: Fail::Never,
        failures: 0,
        fail_delete: false,
    }));
    let m = k.clone();
    fake.adapter("net.link.get", move |args| {
        let mut k = m.lock().unwrap();
        let link = k.need(args[0].as_str().unwrap_or(""))?.clone();
        Ok(k.info(&link))
    });
    let m = k.clone();
    fake.adapter("net.link.ensureVeth", move |args| m.lock().unwrap().ensure_veth(&args[0]));
    let m = k.clone();
    fake.adapter("net.link.ensureDummy", move |args| {
        let mut k = m.lock().unwrap();
        let req = &args[0];
        let name = req["name"].as_str().unwrap_or("").to_string();
        let mut created = false;
        if !k.links.contains_key(&name) {
            k.add(&name, "dummy", req["mtu"].as_i64().unwrap_or(0), req["up"].as_bool().unwrap_or(false), None);
            created = true;
        }
        let link = k.need(&name)?;
        if let Some(mtu) = req["mtu"].as_i64().filter(|mtu| *mtu != 0) {
            link.mtu = mtu;
        }
        if req["up"].as_bool() == Some(true) {
            link.up = true;
        }
        let link = link.clone();
        Ok(json!({"link": k.info(&link), "created": created}))
    });
    let m = k.clone();
    fake.adapter("net.link.setARP", move |args| {
        let mut k = m.lock().unwrap();
        let link = k.need(args[0].as_str().unwrap_or(""))?;
        link.arp = args[1].as_bool().unwrap_or(false);
        let link = link.clone();
        Ok(k.info(&link))
    });
    let m = k.clone();
    fake.adapter("net.link.setGSO", move |args| {
        let mut k = m.lock().unwrap();
        let link = k.need(args[0].as_str().unwrap_or(""))?;
        link.gso_max_size = args[1]["max_size"].as_i64().unwrap_or(0);
        link.gso_max_segs = args[1]["max_segs"].as_i64().unwrap_or(0);
        let link = link.clone();
        Ok(k.info(&link))
    });
    let m = k.clone();
    fake.adapter("net.link.setOffloads", move |args| {
        let mut k = m.lock().unwrap();
        let link = k.need(args[0].as_str().unwrap_or(""))?;
        if let Some(features) = args[1].as_object() {
            for (name, value) in features {
                link.offloads.insert(name.clone(), value.as_bool().unwrap_or(false));
            }
        }
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.link.delete", move |args| m.lock().unwrap().delete(args[0].as_str().unwrap_or("")).map(|_| Value::Null));
    let m = k.clone();
    fake.adapter("net.addr.replace", move |args| {
        let mut k = m.lock().unwrap();
        let cidr = args[0]["cidr"].as_str().unwrap_or("").to_string();
        let link = k.need(args[0]["interface"].as_str().unwrap_or(""))?;
        if !link.addresses.contains(&cidr) {
            link.addresses.push(cidr);
        }
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.addr.delete", move |args| {
        let mut k = m.lock().unwrap();
        let cidr = args[0]["cidr"].as_str().unwrap_or("").to_string();
        let link = k.need(args[0]["interface"].as_str().unwrap_or(""))?;
        link.addresses.retain(|address| *address != cidr);
        Ok(Value::Null)
    });
    let key = |req: &Value, a: &str, b: &str| format!("{}|{}", js::string(&req[a]), js::string(&req[b]));
    let m = k.clone();
    fake.adapter("net.route.replace", move |args| {
        m.lock().unwrap().routes.insert(key(&args[0], "dst", "table"), args[0].clone());
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.route.delete", move |args| {
        m.lock().unwrap().routes.remove(&key(&args[0], "dst", "table"));
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.rule.replace", move |args| {
        m.lock().unwrap().rules.insert(key(&args[0], "family", "priority"), args[0].clone());
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.rule.delete", move |args| {
        m.lock().unwrap().rules.remove(&key(&args[0], "family", "priority"));
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.neigh.replace", move |args| {
        m.lock().unwrap().neigh.insert(key(&args[0], "interface", "ip"), args[0].clone());
        Ok(Value::Null)
    });
    let m = k.clone();
    fake.adapter("net.neigh.delete", move |args| {
        m.lock().unwrap().neigh.remove(&key(&args[0], "interface", "ip"));
        Ok(Value::Null)
    });
    k
}

fn session() -> Value {
    json!({
        "key": "default", "driver": "pppoe", "state": "up", "usable": true, "local_interface": LOCAL, "pipeline_interface": PIPE,
        "ipv4": "192.0.2.2", "ipv4_peer": "192.0.2.1", "ipv6": "2001:db8::2", "ipv6_link_local": "fe80::2", "ipv6_gateway": "fe80::1",
        "peer_mac": "02:00:00:00:00:01", "pd_prefix": "2001:db8:100::/56", "install_default_route_v6": true,
        "interface_preparation": {"local_gso": {"max_size": 1492, "max_segs": 1}, "local_offloads": {"sg": false, "tso": false, "gso": false},
            "pipeline_offloads": {"gro": false, "lro": false}},
    })
}

struct Fixture {
    k: SharedKernel,
    h: Harness<WanCore>,
}

impl Fixture {
    fn new(payload: Value) -> Self {
        let fake = FakeHost::new();
        let k = kernel(&fake);
        let mut h = Harness::<WanCore>::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
        h.action("apply_session", payload).expect("apply_session");
        h.fake.clear_calls();
        let mut fixture = Fixture { k, h };
        // Learn the record revisions, as the first repair after start does.
        fixture.safety();
        fixture.h.fake.clear_calls();
        fixture
    }

    fn calls(&self) -> Vec<String> {
        self.h.fake.call_names()
    }

    fn writes(&self) -> usize {
        self.calls().iter().filter(|name| WRITES.contains(&name.as_str())).count()
    }

    fn timers(&self) -> BTreeMap<String, Value> {
        self.h.fake.timers()
    }

    /// Delivers an event the way the host does, then runs the repair it armed.
    fn event(&mut self, topic: &str, payload: Value) -> Vec<String> {
        for name in [LIGHT_EVENT_TIMER, FULL_EVENT_TIMER] {
            self.h.fake.remove_timer(name);
        }
        self.h.emit(topic, payload).expect("emit");
        let armed: Vec<String> = [LIGHT_EVENT_TIMER, FULL_EVENT_TIMER].iter().filter(|name| self.h.fake.timer(name).is_some()).map(|s| s.to_string()).collect();
        for name in &armed {
            self.h.fire_timer(name).expect("fire event timer");
        }
        armed
    }

    fn link_event(&mut self, topic: &str) -> Vec<String> {
        self.event(topic, json!({"interface": LOCAL}))
    }

    fn safety(&mut self) {
        self.h.fire_timer(REPAIR_TIMER).expect("safety repair");
    }

    fn status(&self) -> Value {
        self.h.fake.data("status", "default")
    }

    fn link<R>(&self, name: &str, read: impl FnOnce(&Link) -> R) -> Option<R> {
        self.k.lock().unwrap().links.get(name).map(read)
    }
}

#[test]
fn nothing_polls_the_only_interval_is_the_safety_repair() {
    let mut f = Fixture::new(session());
    let intervals: Vec<(String, Value)> = f
        .timers()
        .values()
        .filter(|timer| timer["kind"] == "interval")
        .map(|timer| (timer["name"].as_str().unwrap().to_string(), timer["delay_ms"].clone()))
        .collect();
    assert_eq!(intervals, vec![("wan_repair".to_string(), json!(300000))]);
    // The safety repair replays every write; the host turns those that
    // change nothing into no-ops, so it arms no retry either.
    f.safety();
    assert_eq!(f.status()["phase"], "applied");
    assert!(!f.timers().contains_key("wan_retry"));
}

#[test]
fn every_network_event_but_a_dynamic_neighbor_runs_a_full_apply() {
    for topic in ["net.link", "net.addr", "net.route", "net.rule", "net.offload"] {
        let mut f = Fixture::new(session());
        assert_eq!(f.link_event(topic), vec!["wan_event_full"], "{topic}");
        assert!(f.calls().iter().any(|name| name == "net.route.replace"), "{topic}: routes were not replayed");
        assert_eq!(f.status()["phase"], "applied", "{topic}");
    }
    let mut f = Fixture::new(session());
    assert_eq!(f.event("net.link", json!({"operation": "resync", "reason": "netlink_resubscribe"})), vec!["wan_event_full"]);
}

#[test]
fn a_link_that_went_down_and_up_gets_its_flushed_routes_back() {
    let mut f = Fixture::new(session());
    let routes = f.k.lock().unwrap().routes.len();
    // The kernel flushes a link's IPv4 routes on down without a route event;
    // the link is healthy again by the time the repair runs.
    f.k.lock().unwrap().routes.clear();
    f.event("net.link", json!({"interface": LOCAL, "operation": "update", "admin_up": true}));
    assert_eq!(f.k.lock().unwrap().routes.len(), routes);
}

#[test]
fn a_burst_of_events_arms_the_repair_once_and_does_not_postpone_it() {
    let mut f = Fixture::new(session());
    f.h.emit("net.link", json!({"interface": LOCAL})).unwrap();
    let first = f.timers().get("wan_event_full").cloned().expect("the first event arms the repair");
    f.h.fake.advance_ms(50);
    for _ in 0..5 {
        f.h.emit("net.addr", json!({"interface": LOCAL})).unwrap();
    }
    assert_eq!(f.timers()["wan_event_full"]["next_fire"], first["next_fire"], "later events must not move it");
}

#[test]
fn the_full_apply_after_a_link_event_repairs_boundary_drift() {
    let drifts: Vec<(&str, Box<dyn Fn(&mut Kernel)>)> = vec![
        ("deleted", Box::new(|k| k.delete(LOCAL).unwrap())),
        ("local_down", Box::new(|k| k.links.get_mut(LOCAL).unwrap().up = false)),
        ("pipeline_down", Box::new(|k| k.links.get_mut(PIPE).unwrap().up = false)),
        ("mtu", Box::new(|k| k.links.get_mut(LOCAL).unwrap().mtu = 1400)),
        ("arp", Box::new(|k| k.links.get_mut(LOCAL).unwrap().arp = true)),
        ("address", Box::new(|k| k.links.get_mut(LOCAL).unwrap().addresses.retain(|a| a != "192.0.2.2/32"))),
        ("gso", Box::new(|k| k.links.get_mut(LOCAL).unwrap().gso_max_size = 65536)),
        (
            "replaced",
            Box::new(|k| {
                k.delete(LOCAL).unwrap();
                k.ensure_veth(&json!({"host": LOCAL, "peer": PIPE, "mtu": 1492, "up": true})).unwrap();
            }),
        ),
    ];
    for (name, drift) in drifts {
        let mut f = Fixture::new(session());
        drift(&mut f.k.lock().unwrap());
        f.link_event("net.link");
        assert!(f.calls().iter().any(|call| call == "net.link.ensureVeth"), "{name}: no full apply");
        let (local, pipe) = {
            let k = f.k.lock().unwrap();
            (k.links.get(LOCAL).cloned().expect(name), k.links.get(PIPE).cloned().expect(name))
        };
        assert!(local.up && pipe.up, "{name}");
        assert_eq!(local.mtu, 1492, "{name}");
        assert!(!local.arp, "{name}");
        assert_eq!(local.gso_max_size, 1492, "{name}");
        assert!(local.addresses.contains(&"192.0.2.2/32".to_string()), "{name}");
        assert_eq!(f.status()["local_ifindex"], json!(local.ifindex), "{name}");
        assert_eq!(f.status()["pipeline_ifindex"], json!(pipe.ifindex), "{name}");
        f.link_event("net.link");
        assert_eq!(f.status()["phase"], "applied", "{name}: the repair after the repair keeps it applied");
        assert_eq!(f.status()["local_ifindex"], json!(local.ifindex), "{name}: and changes nothing");
    }
}

#[test]
fn route_rule_static_neighbor_and_offload_events_run_a_full_apply() {
    type Check = Box<dyn Fn(&mut Kernel)>;
    type Probe = Box<dyn Fn(&Kernel) -> bool>;
    let drifts: Vec<(&str, Check, Probe)> = vec![
        ("net.route", Box::new(|k| k.routes.clear()), Box::new(|k| !k.routes.is_empty())),
        ("net.rule", Box::new(|k| k.rules.clear()), Box::new(|k| !k.rules.is_empty())),
        ("net.neigh", Box::new(|k| k.neigh.clear()), Box::new(|k| !k.neigh.is_empty())),
        (
            "net.offload",
            Box::new(|k| {
                k.links.get_mut(PIPE).unwrap().offloads.insert("gro".to_string(), true);
            }),
            Box::new(|k| k.links[PIPE].offloads["gro"] == false),
        ),
    ];
    for (topic, drift, repaired) in drifts {
        let mut f = Fixture::new(session());
        drift(&mut f.k.lock().unwrap());
        let payload = if topic == "net.neigh" { json!({"interface": LOCAL, "operation": "delete", "state": 0x80}) } else { json!({"interface": LOCAL}) };
        assert_eq!(f.event(topic, payload), vec!["wan_event_full"], "{topic}");
        assert!(repaired(&f.k.lock().unwrap()), "{topic} not repaired");
    }
}

#[test]
fn a_dynamic_neighbor_changing_state_arms_nothing() {
    let mut f = Fixture::new(session());
    assert!(f.event("net.neigh", json!({"interface": LOCAL, "operation": "update", "state": 0x02})).is_empty());
    assert!(f.event("net.neigh", json!({"interface": LOCAL, "operation": "update", "state": 0x04})).is_empty());
}

#[test]
fn the_safety_repair_replays_routes_rules_neighbors_and_offloads() {
    let mut f = Fixture::new(session());
    let (routes, rules, neigh) = {
        let k = f.k.lock().unwrap();
        (k.routes.len(), k.rules.len(), k.neigh.len())
    };
    assert!(routes > 0 && rules > 0 && neigh > 0);
    {
        let mut k = f.k.lock().unwrap();
        k.routes.clear();
        k.rules.clear();
        k.neigh.clear();
        k.links.get_mut(PIPE).unwrap().offloads.insert("gro".to_string(), true);
    }
    f.safety();
    let k = f.k.lock().unwrap();
    assert_eq!(k.routes.len(), routes);
    assert_eq!(k.rules.len(), rules);
    assert_eq!(k.neigh.len(), neigh);
    assert!(!k.links[PIPE].offloads["gro"]);
}

#[test]
fn a_changed_profile_is_applied_after_its_record_event() {
    let mut f = Fixture::new(session());
    f.h.fake.edit_record("profiles", "default", |data| data["mtu"] = json!(1480));
    assert!(
        f.event("resource.changed", json!({"plugin_id": "wan_core", "resource_id": "status", "operation": "update", "key": "default"})).is_empty(),
        "its own status records arm nothing"
    );
    assert_eq!(
        f.event("resource.changed", json!({"plugin_id": "wan_core", "resource_id": "profiles", "operation": "update", "key": "default"})),
        vec!["wan_event"]
    );
    assert_eq!(f.link(LOCAL, |link| link.mtu), Some(1480));
    assert_eq!(f.status()["mtu"], json!(1480));
}

#[test]
fn a_failed_apply_is_retried_with_backoff_until_it_succeeds() {
    let mut f = Fixture::new(session());
    {
        let mut k = f.k.lock().unwrap();
        k.fail_ensure = Fail::Always;
        k.delete(LOCAL).unwrap();
    }
    f.link_event("net.link");
    assert_eq!(f.k.lock().unwrap().failures, 1);
    assert_eq!(f.status()["phase"], "error");
    assert_eq!(f.timers()["wan_retry"]["delay_ms"], json!(2000));
    f.h.fire_timer("wan_retry").unwrap();
    assert_eq!(f.k.lock().unwrap().failures, 2);
    assert_eq!(f.timers()["wan_retry"]["delay_ms"], json!(4000), "the retry backs off");
    f.k.lock().unwrap().fail_ensure = Fail::Never;
    f.h.fire_timer("wan_retry").unwrap();
    assert_eq!(f.status()["phase"], "applied");
    assert!(f.link(LOCAL, |_| ()).is_some());
    assert!(!f.timers().contains_key("wan_retry"), "no retry once applied");
}

#[test]
fn direct_boundaries_check_the_single_dummy() {
    let mut f = Fixture::new(json!({"key": "default", "driver": "wireguard", "driver_plugin": "vpn_core", "state": "up", "usable": true,
        "local_interface": LOCAL, "handoff_mode": "direct", "ipv4": "10.77.0.1", "addresses": ["10.77.0.1/32"], "mtu": 1420}));
    // A profile edit runs the light check: a direct boundary reads one link.
    assert_eq!(f.event("resource.changed", json!({"resource_id": "profiles"})), vec!["wan_event"]);
    let net_calls: Vec<String> = f.calls().into_iter().filter(|name| name.starts_with("net.")).collect();
    assert_eq!(net_calls, vec!["net.link.get"]);
    f.k.lock().unwrap().links.get_mut(LOCAL).unwrap().up = false;
    f.link_event("net.link");
    assert_eq!(f.link(LOCAL, |link| link.up), Some(true));
}

#[test]
fn a_skipped_session_keeps_what_it_installed_for_the_next_apply_to_clean_up() {
    let mut f = Fixture::new(session());
    let applied = f.status();
    assert_eq!(applied["phase"], "applied");
    let has = |f: &Fixture, cidr: &str| f.link(LOCAL, |link| link.addresses.iter().any(|a| a.starts_with(cidr))).unwrap_or(false);
    assert!(has(&f, "192.0.2.2"), "{applied}");

    let mut down = session();
    down["usable"] = json!(false);
    down["state"] = json!("down");
    f.h.action("apply_session", down).unwrap();
    let skipped = f.status();
    assert_eq!(skipped["phase"], "skipped");
    for field in ["addresses", "routes", "rules", "neighbors"] {
        assert_eq!(skipped[field], applied[field], "{field} of the skipped status");
    }

    let mut renumbered = session();
    renumbered["ipv4"] = json!("192.0.2.3");
    f.h.action("apply_session", renumbered).unwrap();
    assert_eq!(f.status()["phase"], "applied");
    assert!(has(&f, "192.0.2.3"));
    assert!(!has(&f, "192.0.2.2"), "the address of the session before the skip is left behind");
}

#[test]
fn each_session_backs_off_on_its_own() {
    let mut f = Fixture::new(session());
    let mut second = session();
    second["key"] = json!("second");
    second["local_interface"] = json!("veerlocal1");
    second["pipeline_interface"] = json!("veerpipe1");
    f.h.action("apply_session", second).unwrap();
    // The default session keeps failing: its retries back off.
    {
        let mut k = f.k.lock().unwrap();
        k.fail_ensure = Fail::Host(LOCAL.to_string());
        k.delete(LOCAL).unwrap();
    }
    f.link_event("net.link");
    assert_eq!(f.timers()["wan_retry"]["delay_ms"], json!(2000));
    f.h.fire_timer("wan_retry").unwrap();
    f.h.fire_timer("wan_retry").unwrap();
    assert_eq!(f.timers()["wan_retry"]["delay_ms"], json!(8000));
    // A second session that starts failing is retried after 2 s, not 16 s.
    {
        let mut k = f.k.lock().unwrap();
        k.fail_ensure = Fail::Always;
        k.delete("veerlocal1").unwrap();
    }
    f.link_event("net.link");
    assert_eq!(f.timers()["wan_retry"]["delay_ms"], json!(2000));
}

#[test]
fn an_unfinished_teardown_keeps_naming_its_driver_so_the_driver_can_retry_it() {
    let mut driven = session();
    driven["driver"] = json!("wireguard");
    driven["driver_plugin"] = json!("vpn_core");
    driven["profile_key"] = json!("default");
    let mut f = Fixture::new(driven.clone());
    f.k.lock().unwrap().fail_delete = true;
    let mut down = driven.clone();
    down["state"] = json!("down");
    down["usable"] = json!(false);
    f.h.action("teardown", json!({"key": "default", "session": down})).unwrap();
    assert_eq!(f.status()["phase"], "delete_failed");
    assert_eq!(f.status()["driver_plugin"], "vpn_core");
    assert_eq!(f.status()["driver"], "wireguard");
    assert_eq!(f.status()["profile_key"], "default");
    assert!(!f.timers().contains_key("wan_event") && !f.timers().contains_key("wan_retry"), "nothing retries a failed delete on its own");
    f.k.lock().unwrap().fail_delete = false;
    f.h.action("teardown", json!({"key": "default", "session": down})).unwrap();
    assert_eq!(f.status()["phase"], "deleted");
    assert!(f.link(LOCAL, |_| ()).is_none());
}

#[test]
fn a_steady_session_writes_nothing_on_repair() {
    let mut f = Fixture::new(session());
    f.safety();
    let writes_before = f.writes();
    f.event("resource.changed", json!({"resource_id": "profiles"}));
    assert_eq!(f.writes(), writes_before, "a light check of a healthy session writes nothing");
}

#[test]
fn canonical_cidrs_match_go() {
    assert_eq!(canonical_cidr("2001:DB8:0:0:0:0:0:1/128"), "2001:db8::1/128");
    assert_eq!(canonical_cidr("fe80::2/64"), "fe80::2/64");
    assert_eq!(canonical_cidr("2001:db8:0:1:0:0:0:0/64"), "2001:db8:0:1::/64");
    assert_eq!(canonical_cidr("2001:db8:1:0:1:0:1:0/64"), "2001:db8:1:0:1:0:1:0/64");
    assert_eq!(canonical_cidr("010.000.000.001/032"), "10.0.0.1/32");
}

#[test]
fn derived_pipeline_names_match_the_scripts() {
    // Values the JavaScript implementation produced.
    assert_eq!(derived_pipeline_interface("veerlocal0", "default"), format!("veerp{:08x}", js::fnv1a("veerlocal0|default")));
    assert!(derived_pipeline_interface("veerlocal0", "default").len() <= 15);
}
