//! Ports of test-control.test.js and test-share.test.js. The fixture models
//! what the JavaScript test host did: links, WAN Core records and service
//! calls, the process supervisor, exec of ip/wg/sysctl, secrets, the adapter
//! map and durable operations.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{json, js, MsgKind, Outcome, Value};

use crate::{drivers, health, share, VpnCore, CLOCK_SHIFT};

// ------------------------------------------------------------ helpers

fn b64_with(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

fn b64(text: &str) -> String {
    b64_with(text.as_bytes(), b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true)
}

fn b64url(bytes: &[u8]) -> String {
    b64_with(bytes, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", false)
}

fn key_of(byte: u8) -> String {
    b64_with(&[byte; 32], b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true)
}

fn private() -> String {
    key_of(1)
}

fn public() -> String {
    key_of(2)
}

fn merge(base: Value, extra: Value) -> Value {
    js::merge(&base, &extra)
}

fn uri_encode(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn profile(extra: Value) -> Value {
    merge(
        json!({"slot": 1, "addresses": ["10.77.0.1/32"], "peers": [{"public_key": public(), "endpoint": "192.0.2.2:51820", "allowed_ips": ["0.0.0.0/0"]}]}),
        extra,
    )
}

type Pred = Arc<dyn Fn(&Value) -> bool + Send + Sync>;

#[derive(Default)]
struct World {
    links: Vec<Value>,
    sessions: BTreeMap<String, Value>,
    status: BTreeMap<String, Value>,
    calls: Vec<Value>,
    services: Vec<Value>,
    next: u64,
    config: String,
    fail: Option<Pred>,
    fail_stderr: String,
    sysctl: BTreeMap<String, f64>,
    ignore_create_alias: bool,
    inventory: Vec<Value>,
    routes: Value,
    offloads: Value,
    vnet_header: bool,
    legacy_net_info: bool,
    procs: BTreeMap<String, Value>,
    specs: Vec<Value>,
    delayed: bool,
    secrets: BTreeMap<String, String>,
    map: BTreeMap<String, String>,
    map_get_throws: bool,
    map_reads: usize,
    map_writes: usize,
    wan_reads: usize,
    link_reads: usize,
    operations: BTreeMap<String, Value>,
    op_seq: u64,
    dispatched: Vec<Value>,
    hold_dispatch: bool,
}

#[derive(Default)]
struct Opts {
    features: Option<Vec<&'static str>>,
    host_info: Value,
    vnet_header: bool,
    legacy_net_info: bool,
    offloads: Value,
    inventory: Vec<Value>,
    routes: Value,
    missing_key: bool,
    secrets: Vec<(String, String)>,
    resources: Value,
    delayed: bool,
    enabled: Option<bool>,
}

type W = Arc<Mutex<World>>;

fn tun_link(name: &str, ifindex: u64) -> Value {
    json!({"ifname": name, "ifindex": ifindex, "ifalias": "", "linkinfo": {"info_kind": "tun"}, "flags": ["UP"], "mtu": 1420})
}

fn install_adapters(fake: &FakeHost, w: &W, opts: &Opts) {
    let features = opts.features.clone().unwrap_or_default();
    let info = opts.host_info.clone();
    fake.adapter("plugin.host", move |_| {
        Ok(merge(json!({"os": "linux", "arch": "amd64", "available_features": features, "features": []}), info.clone()))
    });
    let s = w.clone();
    fake.adapter("net.link.list", move |_| Ok(json!(s.lock().unwrap().inventory)));
    let s = w.clone();
    fake.adapter("net.link.get", move |args| {
        let mut st = s.lock().unwrap();
        st.link_reads += 1;
        let name = js::string(&args[0]);
        let found = st.links.iter().find(|l| l["ifname"] == json!(name)).cloned().or_else(|| st.inventory.iter().find(|l| l["name"] == json!(name)).cloned());
        let Some(l) = found else {
            return Err(format!("net.link.get: link not found: {name}"));
        };
        let kind = l.pointer("/linkinfo/info_kind").cloned().unwrap_or(Value::Null);
        if st.legacy_net_info {
            return Ok(json!({"name": name, "kind": kind}));
        }
        Ok(json!({"name": name, "ifindex": l.get("ifindex"), "alias": js::string(js::or(&l["ifalias"], &json!(""))), "kind": kind, "mtu": l.get("mtu"),
            "mac": l.get("address"), "up": js::array(&l["flags"]).contains(&json!("UP")), "peer_ifindex": l.get("link_index"), "peer_name": l.get("link"),
            "addresses": js::or(&l["addresses"], &json!([])), "tun_vnet_hdr": st.vnet_header, "statistics": l.get("statistics")}))
    });
    let s = w.clone();
    fake.adapter("net.link.getOffloads", move |_| Ok(s.lock().unwrap().offloads.clone()));
    fake.adapter("process.binaryStatus", |args| Ok(json!({"id": args[0], "versions": []})));
    fake.adapter("plugins.services.resolve", |_| Ok(json!({"provider": "wan_core", "service": "wan.adapter", "version": "1.0.0"})));
    let s = w.clone();
    fake.adapter("plugins.resources.get", move |args| {
        let mut st = s.lock().unwrap();
        st.wan_reads += 1;
        let key = js::string(&args[2]);
        let table = if js::string(&args[1]) == "sessions" { &st.sessions } else { &st.status };
        Ok(table.get(&key).cloned().unwrap_or(Value::Null))
    });
    let s = w.clone();
    fake.adapter("plugins.resources.set", move |args| {
        let mut st = s.lock().unwrap();
        let key = js::string(&args[2]);
        let record = json!({"data": args[3], "enabled": args[4]});
        if js::string(&args[1]) == "sessions" {
            st.sessions.insert(key.clone(), record.clone());
            let mut status = st.status.get(&key).cloned().unwrap_or(json!({"data": {}}));
            status["data"] = merge(merge(status["data"].clone(), args[3].clone()), json!({"phase": "applied"}));
            st.status.insert(key, status);
        } else {
            st.status.insert(key, record.clone());
        }
        Ok(record)
    });
    let s = w.clone();
    fake.adapter("plugins.services.call", move |args| {
        let mut st = s.lock().unwrap();
        let request = args[0].clone();
        st.services.push(request.clone());
        let p = &request["payload"];
        let k = js::string(js::or(&p["wan_id"], &p["key"]));
        if request["action"] == "teardown" {
            if js::is_true(&p["forget"]) {
                st.sessions.remove(&k);
                st.status.remove(&k);
                return Ok(json!({}));
            }
            let (local, pipeline) = (p["local_interface"].clone(), p["pipeline_interface"].clone());
            st.links.retain(|l| l["ifname"] != local && l["ifname"] != pipeline);
            st.sessions.insert(k.clone(), json!({"data": p, "enabled": false}));
            st.status.insert(k, json!({"enabled": false, "data": {"phase": "deleted", "local_interface": local, "pipeline_interface": pipeline}}));
            return Ok(json!({}));
        }
        assert_eq!(request["action"], "prepare_handoff");
        let direct = p["handoff_mode"] == "direct";
        let mut local = st.links.iter().find(|l| l["ifname"] == p["local_interface"]).cloned();
        let mut peer = st.links.iter().find(|l| l["ifname"] == p["pipeline_interface"]).cloned();
        if let Some(l) = &local {
            if l.pointer("/linkinfo/info_kind") != Some(&json!(if direct { "dummy" } else { "veth" })) {
                let (old_peer, old_index) = (l["link_index"].clone(), l["ifindex"].clone());
                st.links.retain(|x| x["ifindex"] != old_index && (old_peer.is_null() || x["ifindex"] != old_peer));
                local = None;
                peer = None;
            }
        }
        if local.is_none() && peer.is_none() {
            let index = st.next;
            st.next += 1;
            let mut l = json!({"ifname": p["local_interface"], "ifindex": index, "address": "02:00:00:00:00:01", "linkinfo": {"info_kind": if direct { "dummy" } else { "veth" }}});
            if !direct {
                let pindex = st.next;
                st.next += 1;
                let pl = json!({"ifname": p["pipeline_interface"], "ifindex": pindex, "address": "02:00:00:00:00:02", "linkinfo": {"info_kind": "veth"}, "link_index": index});
                l["link_index"] = json!(pindex);
                st.links.push(l.clone());
                st.links.push(pl.clone());
                peer = Some(pl);
            } else {
                st.links.push(l.clone());
            }
            local = Some(l);
        }
        let local = local.unwrap();
        let data = merge(p.clone(), json!({"phase": "prepared", "local_ifindex": local["ifindex"], "pipeline_ifindex": peer.map(|p| p["ifindex"].clone()).unwrap_or(json!(0))}));
        st.status.insert(k, json!({"enabled": false, "data": data}));
        Ok(data)
    });
    let s = w.clone();
    fake.adapter("process.exec", move |args| {
        let mut st = s.lock().unwrap();
        let request = args[0].clone();
        st.calls.push(request.clone());
        let ok = |stdout: String| json!({"stdout": stdout, "stderr": "", "exit_code": 0});
        if st.fail.as_ref().map(|f| f(&request)).unwrap_or(false) {
            let stderr = if st.fail_stderr.is_empty() { private() } else { st.fail_stderr.clone() };
            return Ok(json!({"stdout": "", "stderr": stderr, "exit_code": 2}));
        }
        let a: Vec<String> = js::array(&request["args"]).iter().map(js::string).collect();
        let command = js::string(&request["command"]);
        if command.ends_with("/wg") {
            if a[0] == "syncconf" {
                st.config = js::string(&request["stdin"]);
            }
            assert!(a.get(2).map(|f| f != "dump" && f != "private-key").unwrap_or(true));
            return Ok(ok(if a[0] == "pubkey" || a.get(2).map(String::as_str) == Some("public-key") { public() } else { "peer\t123".to_string() }));
        }
        if command == "/usr/sbin/sysctl" {
            if a[0] == "-n" {
                return Ok(ok(format!("{}\n", st.sysctl.get(&a[1]).copied().unwrap_or(0.0))));
            }
            let last = a.last().unwrap();
            let (name, value) = last.split_once('=').unwrap();
            st.sysctl.insert(name.to_string(), value.parse().unwrap());
            return Ok(ok(String::new()));
        }
        assert!(command.ends_with("/ip"), "{command}");
        if a.contains(&"route".to_string()) {
            assert_eq!(a, ["-j", "-4", "route", "show", "table", "all"]);
            return Ok(ok(js::or(&st.routes, &json!([])).to_string()));
        }
        let args: Vec<&String> = a.iter().filter(|v| *v != "-j" && *v != "-d").collect();
        let field = |k: &str| args.iter().position(|v| *v == k).and_then(|i| args.get(i + 1)).map(|s| s.to_string()).unwrap_or_default();
        assert_eq!(args[0], "link");
        match args[1].as_str() {
            "show" => return Ok(ok(json!(st.links).to_string())),
            "add" => {
                let index = st.next;
                st.next += 1;
                let alias = if st.ignore_create_alias { String::new() } else { field("alias") };
                st.links.push(json!({"ifname": field("name"), "ifindex": index, "ifalias": alias, "linkinfo": {"info_kind": "wireguard"}, "flags": [], "mtu": 1420}));
            }
            "set" => {
                let dev = field("dev");
                let has_alias = args.iter().any(|v| *v == "alias");
                let (alias, mtu) = (field("alias"), field("mtu"));
                let l = st.links.iter_mut().find(|l| l["ifname"] == json!(dev)).expect("ip link set on a missing link");
                if has_alias {
                    l["ifalias"] = json!(alias);
                } else {
                    l["mtu"] = json!(mtu.parse::<u64>().unwrap());
                    l["flags"] = json!(["UP"]);
                }
            }
            "del" => {
                let dev = field("dev");
                st.links.retain(|l| l["ifname"] != json!(dev));
            }
            _ => {}
        }
        Ok(ok(String::new()))
    });
    let s = w.clone();
    fake.adapter("process.status", move |args| {
        let st = s.lock().unwrap();
        let id = js::string(&args[0]);
        Ok(st.procs.get(&id).cloned().unwrap_or(json!({"id": id, "state": "stopped", "started_at": 0})))
    });
    let s = w.clone();
    fake.adapter("process.stop", move |args| {
        let mut st = s.lock().unwrap();
        let id = js::string(&args[0]);
        if st.procs.remove(&id).is_some() {
            let name = format!("vtun{}", &id[4..]);
            st.links.retain(|l| l["ifname"] != json!(name));
        }
        Ok(json!({"id": id, "state": "stopped"}))
    });
    let s = w.clone();
    fake.adapter("process.start", move |args| {
        let mut st = s.lock().unwrap();
        let spec = args[0].clone();
        st.specs.push(spec.clone());
        let id = js::string(&spec["id"]);
        if !st.procs.contains_key(&id) {
            let started = 1000 * st.specs.len() as u64;
            st.procs.insert(id.clone(), json!({"id": id, "state": "running", "pid": 100, "starts": 1, "started_at": started}));
            if !st.delayed {
                let index = st.next;
                st.next += 1;
                st.links.push(tun_link(&format!("vtun{}", &id[4..]), index));
            }
        }
        Ok(st.procs[&id].clone())
    });
    let s = w.clone();
    fake.adapter("process.restart", move |args| {
        let mut st = s.lock().unwrap();
        let id = js::string(&args[0]);
        let mut p = st.procs[&id].clone();
        if js::number(&p["starts"]) >= 4.0 {
            return Err("restart budget exhausted".to_string());
        }
        p["starts"] = json!(js::number(&p["starts"]) as u64 + 1);
        p["started_at"] = json!(js::number(&p["started_at"]) as u64 + 1000);
        st.procs.insert(id.clone(), p.clone());
        let name = format!("vtun{}", &id[4..]);
        st.links.retain(|l| l["ifname"] != json!(name));
        let index = st.next;
        st.next += 1;
        st.links.push(tun_link(&name, index));
        Ok(merge(p, json!({"state": "restarting"})))
    });
    let s = w.clone();
    fake.adapter("secret.get", move |args| Ok(s.lock().unwrap().secrets.get(&js::string(&args[0])).map(|v| json!(v)).unwrap_or(Value::Null)));
    let s = w.clone();
    fake.adapter("secret.set", move |args| {
        s.lock().unwrap().secrets.insert(js::string(&args[0]), js::string(&args[1]));
        Ok(Value::Null)
    });
    let s = w.clone();
    fake.adapter("secret.delete", move |args| {
        s.lock().unwrap().secrets.remove(&js::string(&args[0]));
        Ok(Value::Null)
    });
    let s = w.clone();
    fake.adapter("ebpf.mapGet", move |args| {
        let mut st = s.lock().unwrap();
        st.map_reads += 1;
        match st.map.get(&js::string(&args[2])) {
            Some(value) => Ok(json!(value)),
            None if st.map_get_throws => Err("ebpf.mapGet: get map tunnel_links: lookup: key does not exist".to_string()),
            None => Ok(Value::Null),
        }
    });
    let s = w.clone();
    fake.adapter("ebpf.mapDelete", move |args| {
        s.lock().unwrap().map.remove(&js::string(&args[2]));
        Ok(Value::Null)
    });
    let s = w.clone();
    fake.adapter("ebpf.mapTransaction", move |args| {
        let mut st = s.lock().unwrap();
        for op in js::array(&args[0]["operations"]) {
            let key = js::string(&op["key"]);
            if op["op"] == "put" {
                st.map_writes += 1;
                st.map.insert(key, js::string(&op["value"]));
            } else {
                st.map.remove(&key);
            }
        }
        Ok(json!({}))
    });
    let s = w.clone();
    fake.adapter("operations.getByKey", move |args| Ok(s.lock().unwrap().operations.get(&js::string(&args[0])).cloned().unwrap_or(Value::Null)));
    let s = w.clone();
    fake.adapter("operations.get", move |args| {
        let st = s.lock().unwrap();
        Ok(st.operations.values().find(|op| op["id"] == args[0]).cloned().unwrap_or(Value::Null))
    });
    let s = w.clone();
    fake.adapter("operations.begin", move |args| {
        let mut st = s.lock().unwrap();
        let request = &args[0];
        let key = js::string(&request["key"]);
        if let Some(existing) = st.operations.get(&key).cloned() {
            let terminal = ["completed", "failed", "cancelled"].contains(&existing["status"].as_str().unwrap_or(""));
            if !js::is_true(&request["restart"]) || !terminal {
                return Ok(existing);
            }
            let mut restarted = existing.clone();
            for (k, v) in [("status", json!("pending")), ("input", request["input"].clone()), ("result", Value::Null), ("error", Value::Null)] {
                restarted[k] = v;
            }
            restarted["revision"] = json!(js::number(&existing["revision"]) as u64 + 1);
            st.operations.insert(key, restarted.clone());
            return Ok(restarted);
        }
        st.op_seq += 1;
        let item = json!({"id": format!("op{}", st.op_seq), "key": key, "kind": request["kind"], "status": "pending", "input": request["input"],
            "result": null, "error": null, "revision": 1});
        st.operations.insert(key, item.clone());
        Ok(item)
    });
    let transition = |w: &W, status: Option<&'static str>, need_running: bool| {
        let s = w.clone();
        move |args: &[Value]| -> Result<Value, String> {
            let mut st = s.lock().unwrap();
            let Some((key, item)) = st.operations.iter().find(|(_, op)| op["id"] == args[0]).map(|(k, v)| (k.clone(), v.clone())) else {
                return Err("operation was not found".to_string());
            };
            if item["revision"] != args[1] {
                return Err("operation is stale".to_string());
            }
            let state = item["status"].as_str().unwrap_or("").to_string();
            if need_running && state != "running" {
                return Err("operation is not running".to_string());
            }
            if !need_running && state != "pending" && state != "running" {
                return Err("operation is terminal".to_string());
            }
            let mut next = item.clone();
            next["status"] = json!(status.unwrap_or("running"));
            next["revision"] = json!(js::number(&item["revision"]) as u64 + 1);
            if status == Some("completed") {
                next["result"] = args[2].clone();
            }
            st.operations.insert(key, next.clone());
            Ok(next)
        }
    };
    fake.adapter("operations.claim", transition(w, None, false));
    fake.adapter("operations.complete", transition(w, Some("completed"), true));
    fake.adapter("operations.cancel", transition(w, Some("cancelled"), true));
    let s = w.clone();
    fake.adapter("operations.remove", move |args| {
        let mut st = s.lock().unwrap();
        let key = st.operations.iter().find(|(_, op)| op["id"] == args[0]).map(|(k, _)| k.clone());
        match key {
            Some(key) if ["completed", "failed", "cancelled"].contains(&st.operations[&key]["status"].as_str().unwrap_or("")) => {
                st.operations.remove(&key);
                Ok(Value::Null)
            }
            _ => Err("operations.remove: operation is missing or nonterminal".to_string()),
        }
    });
    let s = w.clone();
    fake.adapter("worker.dispatch", move |args| {
        s.lock().unwrap().dispatched.push(args[2].clone());
        Ok(json!({"queued": true, "worker": args[0], "handler": args[1]}))
    });
}

struct Env {
    h: Harness<VpnCore>,
    /// The health worker's own instance.
    worker: Harness<VpnCore>,
    w: W,
}

const MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json");

fn fixture_with(config: Value, opts: Opts) -> Env {
    CLOCK_SHIFT.with(|shift| shift.set(0.0));
    let fake = FakeHost::new();
    let world = World {
        next: 10,
        inventory: opts.inventory.clone(),
        routes: opts.routes.clone(),
        offloads: if opts.offloads.is_null() { json!({}) } else { opts.offloads.clone() },
        vnet_header: opts.vnet_header,
        legacy_net_info: opts.legacy_net_info,
        delayed: opts.delayed,
        ..World::default()
    };
    let w: W = Arc::new(Mutex::new(world));
    {
        let mut st = w.lock().unwrap();
        if !opts.missing_key {
            st.secrets.insert("private_default".into(), private());
        }
        for (k, v) in &opts.secrets {
            st.secrets.insert(k.clone(), v.clone());
        }
    }
    install_adapters(&fake, &w, &opts);
    fake.put_record("profiles", "default", config, opts.enabled.unwrap_or(true));
    if let Value::Object(resources) = &opts.resources {
        for (resource, records) in resources {
            for (key, record) in records.as_object().unwrap() {
                fake.put_record(resource, key, record["data"].clone(), !js::is_false(&record["enabled"]));
            }
        }
    }
    let worker = Harness::<VpnCore>::load(MANIFEST, fake.clone());
    let h = Harness::<VpnCore>::load(MANIFEST, fake);
    Env { h, worker, w }
}

fn fixture(config: Value) -> Env {
    fixture_with(config, Opts::default())
}

fn core_config(driver: &str) -> String {
    if driver == "mihomo" {
        json!({"proxies": [{"password": "sensitive-core-password"}], "tun": {"auto-route": true}}).to_string()
    } else {
        json!({"outbounds": [{"type": "direct", "tag": "direct"}]}).to_string()
    }
}

fn vpn_with(driver: &str, extra: Value, mut opts: Opts) -> Env {
    let config = merge(json!({"driver": driver, "slot": 1, "mtu": 1420, "addresses": ["10.78.0.1/32"], "upstream_interface": "eth0"}), extra);
    let config = Value::Object(config.as_object().unwrap().iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect());
    opts.secrets.insert(0, ("core_default".into(), core_config(driver)));
    fixture_with(config, opts)
}

fn vpn(driver: &str) -> Env {
    vpn_with(driver, json!({}), Opts::default())
}

impl Env {
    fn fake(&self) -> &FakeHost {
        &self.h.fake
    }

    fn st(&self) -> std::sync::MutexGuard<'_, World> {
        self.w.lock().unwrap()
    }

    /// Runs queued worker.dispatch jobs on the worker instance, as the host does.
    fn drain(&mut self) {
        loop {
            let job = {
                let mut st = self.w.lock().unwrap();
                if st.hold_dispatch || st.dispatched.is_empty() {
                    return;
                }
                st.dispatched.remove(0)
            };
            self.worker.run(MsgKind::Event, "onHealthProbe", json!({"kind": "worker", "payload": job})).unwrap();
        }
    }

    fn try_act(&mut self, id: &str, payload: Value) -> Result<Value, String> {
        let result = self.h.action(id, payload).map_err(|err| err.to_string());
        self.drain();
        match result? {
            Outcome::Value(value) => Ok(value),
            _ => Ok(Value::Null),
        }
    }

    fn act(&mut self, id: &str, payload: Value) -> Value {
        self.try_act(id, payload.clone()).unwrap_or_else(|err| panic!("action {id} {payload}: {err}"))
    }

    fn act_err(&mut self, id: &str, payload: Value) -> String {
        match self.try_act(id, payload) {
            Ok(value) => panic!("action {id} succeeded: {value}"),
            Err(err) => err,
        }
    }

    fn try_apply(&mut self) -> Result<Value, String> {
        self.try_act("apply", json!({"key": "default"}))
    }

    fn apply(&mut self) -> Value {
        self.try_apply().unwrap_or_else(|err| panic!("apply: {err}"))
    }

    fn apply_err(&mut self) -> String {
        match self.try_apply() {
            Ok(value) => panic!("apply succeeded: {value}"),
            Err(err) => err,
        }
    }

    fn try_reconcile(&mut self) -> Result<(), String> {
        let result = self.h.reconcile().map(|_| ()).map_err(|err| err.to_string());
        self.drain();
        result
    }

    fn reconcile(&mut self) {
        self.try_reconcile().unwrap();
    }

    fn timer(&mut self, name: &str) {
        let _ = self.h.run(MsgKind::Timer, "onTimer", json!({"kind": "timer", "timer": {"name": name}}));
        self.drain();
    }

    fn repair(&mut self) {
        self.timer("tunnel_repair");
    }

    fn deactivate(&mut self) -> Result<(), String> {
        self.h.deactivate().map(|_| ()).map_err(|err| err.to_string())
    }

    fn kv(&self, key: &str) -> Value {
        self.fake().kv(key).map(|r| r["data"].clone()).unwrap_or(Value::Null)
    }

    fn kv_set(&self, key: &str, value: Value) {
        self.h.host.kv_set(key, &value).unwrap();
    }

    fn lease(&self) -> Value {
        self.kv("lease_default")
    }

    fn status(&self, key: &str) -> Value {
        self.fake().data("status", key)
    }

    fn status_record(&self, key: &str) -> Value {
        self.fake().record("status", key).unwrap_or(Value::Null)
    }

    fn binding(&self, hook: &str) -> Value {
        self.fake().record("hook_bindings", hook).unwrap_or(Value::Null)
    }

    fn set_profile(&self, key: &str, data: Value, enabled: bool) {
        self.fake().put_record("profiles", key, data, enabled);
    }

    fn links(&self) -> usize {
        self.st().links.len()
    }

    fn link_mut(&self, name: &str, edit: impl FnOnce(&mut Value)) {
        let mut st = self.st();
        let link = st.links.iter_mut().find(|l| l["ifname"] == json!(name)).unwrap_or_else(|| panic!("no link {name}"));
        edit(link);
    }

    fn drop_link(&self, name: &str) {
        self.st().links.retain(|l| l["ifname"] != json!(name));
    }

    fn map_size(&self) -> usize {
        self.st().map.len()
    }

    fn session(&self, id: &str) -> Value {
        self.st().sessions.get(id).cloned().unwrap_or(Value::Null)
    }

    fn proc(&self, key: &str) -> Value {
        self.st().procs.get(&format!("vpn_{key}")).cloned().unwrap_or(Value::Null)
    }

    fn proc_mut(&self, key: &str, edit: impl FnOnce(&mut Value)) {
        let mut st = self.st();
        edit(st.procs.get_mut(&format!("vpn_{key}")).unwrap());
    }

    fn specs(&self) -> Vec<Value> {
        self.st().specs.clone()
    }

    fn calls(&self) -> Vec<Value> {
        self.st().calls.clone()
    }

    fn services(&self) -> Vec<Value> {
        self.st().services.clone()
    }

    fn fail(&self, pred: impl Fn(&Value) -> bool + Send + Sync + 'static) {
        self.st().fail = Some(Arc::new(pred));
    }

    fn unfail(&self) {
        self.st().fail = None;
    }

    fn secret(&self, name: &str) -> Option<String> {
        self.st().secrets.get(name).cloned()
    }

    fn timers(&self) -> BTreeMap<String, Value> {
        self.fake().timers()
    }
}

fn args_of(request: &Value) -> Vec<String> {
    js::array(&request["args"]).iter().map(js::string).collect()
}

fn shift_clock(ms: f64) {
    CLOCK_SHIFT.with(|shift| shift.set(shift.get() + ms));
}

// ------------------------------------------------------------ WireGuard

#[test]
fn wg_is_opt_in_and_registration_and_drafts_do_not_change_networking() {
    let mut h = fixture(profile(json!({})));
    h.reconcile();
    assert!(h.calls().is_empty());
    assert!(h.services().is_empty());
    assert!(h.binding("tunnel-links").is_null());
    let manifest: Value = serde_json::from_str(include_str!("../plugin.json")).unwrap();
    let hooks = js::array(&manifest["control"]["register"]["pipeline_attach"]);
    assert!(hooks.iter().all(|hook| hook["binding_required"] == true));
    assert!(js::array(&manifest["compatibility"]["features"]).contains(&json!("dataplane.hook_bindings.v1")));
    assert_eq!(manifest["kind"], "pipeline");
    assert_eq!(manifest["stability"], "lab");
}

#[test]
fn wg_publishes_a_segmented_wan_installs_both_directions_and_cleans_and_reapplies() {
    let mut h = fixture(profile(json!({})));
    h.act("set_key", json!({"value": private()}));
    let result = h.apply();
    assert_eq!(result["egress_nat_interface"], "veerwg1");
    assert_eq!(result["tc_ready"], true);
    let p = h.session("wg_default")["data"].clone();
    assert_eq!(p["egress_nat_redirect_mode"], "prepared_l2");
    assert_eq!(p["install_default_route"], false);
    assert_eq!(p["usable"], true);
    // Kernel WireGuard segments GSO skbs itself: the plain BPF boundary keeps GSO too.
    assert_eq!(p["interface_preparation"]["local_offloads"]["gso"], true);
    assert_eq!(p["interface_preparation"]["local_gso"]["max_segs"], 65535);
    assert_eq!(h.map_size(), 2);
    assert!(!h.calls().iter().any(|r| args_of(r).iter().any(|a| a.contains(&private()))));
    assert!(h.st().config.contains("PrivateKey = "));
    assert_eq!(h.act("inspect", json!({}))["public_key"], json!(public()));
    h.apply();
    assert_eq!(h.links(), 3);
    h.act("teardown", json!({}));
    assert_eq!(h.links(), 0);
    assert!(h.lease().is_null());
    h.apply();
    assert_eq!(h.links(), 3);
}

#[test]
fn wg_rejects_malformed_configuration_and_recursive_routes_before_mutation() {
    let changes = [
        json!({"bindings": []}),
        json!({"masquerade": false}),
        json!({"mtu": 1000}),
        json!({"slot": 9}),
        json!({"addresses": ["fd77::1/128"]}),
        json!({"addresses": ["192.168.01.1/24"]}),
        json!({"addresses": ["1.2.3.4\nPostUp=evil"]}),
        json!({"peers": [{"public_key": public(), "endpoint": "host.invalid:123", "allowed_ips": ["0.0.0.0/0"]}]}),
        json!({"peers": [{"public_key": public(), "endpoint": "1.2.3.4:123\nPostUp=evil", "allowed_ips": ["0.0.0.0/0"]}]}),
        json!({"addresses": ["192.0.2.1/24"]}),
        json!({"remote_routes": ["0.0.0.0/0"]}),
        json!({"remote_routes": ["192.0.2.0/24"]}),
        json!({"peers": [{"public_key": public(), "allowed_ips": ["10.0.0.0/8"]}], "remote_routes": ["192.168.20.0/24"]}),
    ];
    for change in changes {
        let mut h = fixture(profile(change.clone()));
        h.apply_err();
        assert!(h.calls().is_empty(), "{change}");
        assert!(h.services().is_empty(), "{change}");
    }
}

#[test]
fn wg_rejects_foreign_links_and_wan_records_and_validates_secrets_first() {
    for kind in ["link", "wan", "missing"] {
        let mut h = fixture_with(profile(json!({})), Opts { missing_key: kind == "missing", ..Opts::default() });
        if kind == "link" {
            h.st().links.push(json!({"ifname": "vwgdefault", "ifalias": "foreign", "linkinfo": {"info_kind": "wireguard"}}));
        }
        if kind == "wan" {
            h.st().sessions.insert("wg_default".into(), json!({"data": {"driver_plugin": "other"}, "enabled": true}));
        }
        h.apply_err();
        assert!(h.services().is_empty(), "{kind}");
        assert!(!h.calls().iter().any(|r| args_of(r).contains(&"add".to_string())), "{kind}");
    }
}

#[test]
fn wg_failure_does_not_expose_secrets_and_retry_recovers_the_journaled_wan() {
    let mut h = fixture(profile(json!({})));
    h.fail(|r| args_of(r).first().map(String::as_str) == Some("syncconf"));
    let err = h.apply_err();
    assert!(!err.contains(&private()) && err.contains("failed"), "{err}");
    assert_eq!(h.lease()["pending"], true);
    h.unfail();
    h.apply();
    assert_ne!(h.lease()["pending"], true);
    h.act("teardown", json!({}));
    assert_eq!(h.links(), 0);
}

#[test]
fn wg_pending_cleanup_retries_after_its_tunnel_is_already_gone() {
    for created in [None, Some(Value::Null)] {
        let mut h = fixture(profile(json!({})));
        h.apply();
        h.drop_link("vwgdefault");
        let mut lease = h.lease();
        lease["pending"] = json!(true);
        match &created {
            None => {
                lease.as_object_mut().unwrap().remove("created_ifindex");
            }
            Some(v) => lease["created_ifindex"] = v.clone(),
        }
        h.kv_set("lease_default", lease);
        h.act("teardown", json!({}));
        assert_eq!(h.links(), 0);
        assert!(h.lease().is_null());
        assert_eq!(h.map_size(), 0);
    }
}

#[test]
fn wg_repairs_ifindex_changes_and_restores_applied_settings_ignoring_draft_edits() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    h.drop_link("vwgdefault");
    h.repair();
    assert_eq!(h.links(), 3);
    h.set_profile("default", profile(json!({"slot": 2})), true);
    h.reconcile();
    assert_eq!(h.lease()["plan"]["slot"], 1);
    h.deactivate().unwrap();
    assert_eq!(h.links(), 0);
}

#[test]
fn vpn_0_9_0_leases_and_bindings_move_to_the_tunnel_adapter_without_rebuilding() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    let mut lease = h.lease();
    lease["wg_ifindex"] = lease["tunnel_ifindex"].clone();
    lease.as_object_mut().unwrap().remove("tunnel_ifindex");
    h.kv_set("lease_default", lease);
    h.fake().delete_record("hook_bindings", "tunnel-links");
    h.fake().delete_record("hook_bindings", "tunnel-direct-out");
    h.fake().put_record("hook_bindings", "wg-links", json!({"hook_id": "wg-links", "interfaces": ["vwgdefault", "veerwgp1"]}), true);
    h.fake().put_record("hook_bindings", "wg-direct-out", json!({"hook_id": "wg-direct-out", "interfaces": []}), false);
    let (calls, services) = (h.calls().len(), h.services().len());
    h.reconcile();
    assert!(!h.calls()[calls..].iter().any(|r| ["add", "del", "set", "syncconf"].iter().any(|a| args_of(r).contains(&a.to_string()))));
    assert_eq!(h.services().len(), services);
    let keys: Vec<String> = h.fake().records("hook_bindings").iter().map(|r| js::string(&r["key"])).collect();
    assert_eq!(keys, ["tunnel-direct-out", "tunnel-links"]);
    assert_eq!(h.binding("tunnel-links")["data"]["interfaces"], json!(["vwgdefault", "veerwgp1"]));
    assert_eq!(h.map_size(), 2);
    h.fake().edit_timer("wg_repair", |_| {});
    h.timer("wg_repair");
    assert!(h.timers().get("wg_repair").is_none());
    assert!(h.timers().contains_key("tunnel_repair"));
    h.apply();
    let lease = h.lease();
    assert!(lease.get("wg_ifindex").is_none());
    let ifindex = h.st().links.iter().find(|l| l["ifname"] == "vwgdefault").unwrap()["ifindex"].clone();
    assert_eq!(lease["tunnel_ifindex"], ifindex);
}

#[test]
fn wg_reserves_slots_and_refuses_teardown_of_an_externally_replaced_link() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    let mut other = h.lease();
    other["plan"]["key"] = json!("other");
    let mut second = fixture(profile(json!({})));
    second.kv_set("lease_other", other);
    assert!(second.apply_err().contains("reserved"));
    h.set_profile("default", profile(json!({"slot": 2})), true);
    assert!(h.apply_err().contains("changing the slot"));
    h.link_mut("vwgdefault", |l| l["ifalias"] = json!("foreign"));
    assert!(h.act_err("teardown", json!({})).contains("unowned"));
    assert_eq!(h.links(), 3);
}

#[test]
fn wg_recovers_an_alias_failure_using_the_journaled_creation_ifindex() {
    let mut h = fixture(profile(json!({})));
    h.st().ignore_create_alias = true;
    h.fail(|r| {
        let a = args_of(r);
        a.contains(&"alias".to_string()) && a.get(1).map(String::as_str) == Some("set")
    });
    assert!(h.apply_err().contains("failed"));
    assert!(js::number(&h.lease()["created_ifindex"]) > 0.0);
    assert_eq!(h.st().links.iter().find(|l| l["ifname"] == "vwgdefault").unwrap()["ifalias"], "");
    h.unfail();
    h.apply();
    assert_eq!(h.st().links.iter().find(|l| l["ifname"] == "vwgdefault").unwrap()["ifalias"], "veer:vpn_core:default");
}

#[test]
fn wg_multiple_wans_keep_their_own_maps_and_bindings() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    h.set_profile("second", profile(json!({"slot": 2})), true);
    h.act("set_key", json!({"key": "second", "value": private()}));
    h.act("apply", json!({"key": "second"}));
    assert_eq!(h.links(), 6);
    assert_eq!(h.map_size(), 4);
    h.act("teardown", json!({"key": "default"}));
    assert_eq!(h.links(), 3);
    assert_eq!(h.map_size(), 2);
    assert_eq!(h.binding("tunnel-links")["data"]["interfaces"], json!(["vwgsecond", "veerwgp2"]));
    h.act("teardown", json!({"key": "second"}));
    assert_eq!(h.links(), 0);
    assert_eq!(h.binding("tunnel-links")["enabled"], false);
    assert_eq!(h.binding("tunnel-links")["data"]["interfaces"], json!([]));
}

#[test]
fn wg_rejects_a_mismatched_veth_peer_without_enabling_forwarding() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    h.link_mut("veerwgp1", |l| l["link_index"] = json!(999));
    assert!(h.apply_err().contains("not ready"));
    assert_eq!(h.map_size(), 0);
}

#[test]
fn wg_disabled_profiles_are_torn_down_on_reconciliation() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    h.set_profile("default", profile(json!({})), false);
    h.reconcile();
    assert_eq!(h.links(), 0);
    assert!(h.lease().is_null());
}

#[test]
fn wg_legacy_cleanup_accepts_only_the_owned_nft_marker_and_never_flushes() {
    let plan = json!({"key": "default", "interface": "vwgdefault", "owner": "veer:vpn_core:default", "nft": "veer_wg_1", "table": 52001,
        "bindings": [{"family": "4", "priority": 22032, "lan_interface": "br-lan", "source": "192.168.10.0/24", "destination": "0.0.0.0/0"}],
        "peers": [{"allowed_ips": ["0.0.0.0/0"]}], "bypass": ["192.168.10.0/24"]});
    for owned in [true, false] {
        let mut h = fixture(profile(json!({})));
        h.kv_set("lease_default", json!({"active": true, "plan": plan}));
        let mutations = Arc::new(Mutex::new(Vec::<String>::new()));
        let m = mutations.clone();
        h.fake().adapter("net.link.get", |_| Ok(json!({})));
        h.fake().adapter("process.exec", move |args| {
            let r = &args[0];
            let a = args_of(r);
            let ok = |stdout: &str| json!({"stdout": stdout, "exit_code": 0});
            assert!(!a.contains(&"flush".to_string()));
            if js::string(&r["command"]).ends_with("/nft") {
                if a[0] == "-j" {
                    return Ok(ok(&json!({"nftables": [{"table": {"name": "veer_wg_1"}}]}).to_string()));
                }
                if a[0] == "list" {
                    return Ok(ok(if owned {
                        "table inet veer_wg_1 {\n comment \"veer:vpn_core:default\"\n chain forward {\n }\n}\n"
                    } else {
                        "table inet veer_wg_1 {\n chain forward {\n comment \"veer:vpn_core:default\"\n }\n}\n"
                    }));
                }
                m.lock().unwrap().push("nft".into());
                return Ok(ok(""));
            }
            if a.contains(&"link".to_string()) && a.contains(&"show".to_string()) {
                return Ok(ok(&json!([{"ifname": "vwgdefault", "ifindex": 10, "ifalias": "veer:vpn_core:default", "linkinfo": {"info_kind": "wireguard"}}]).to_string()));
            }
            if a.contains(&"show".to_string()) {
                return Ok(ok("[]"));
            }
            m.lock().unwrap().push("ip".into());
            Ok(ok(""))
        });
        let err = h.apply_err();
        assert!(err.to_lowercase().contains("legacy"), "{err}");
        if owned {
            h.act("teardown", json!({}));
            assert_eq!(*mutations.lock().unwrap(), ["ip", "nft"]);
            assert!(h.lease().is_null());
        } else {
            assert!(h.act_err("teardown", json!({})).contains("owned by another"));
            assert!(mutations.lock().unwrap().is_empty());
            assert!(!h.lease().is_null());
        }
    }
}

#[test]
fn the_manifest_selects_the_tunnel_object_by_host_capability() {
    let manifest: Value = serde_json::from_str(include_str!("../plugin.json")).unwrap();
    let objects = js::array(&manifest["control"]["register"]["ebpf_objects"]);
    let picks = |features: &[&str]| -> Vec<String> {
        objects
            .iter()
            .filter(|o| {
                let when = &o["when"];
                let has = |f: &Value| f.as_str().map(|f| features.contains(&f)).unwrap_or(true);
                (when["feature"].is_null() || has(&when["feature"])) && (when["not_feature"].is_null() || !has(&when["not_feature"]))
            })
            .map(|o| js::string(&o["path"]))
            .collect()
    };
    assert_eq!(picks(&[]), ["tunnel_adapter.o"]);
    assert_eq!(picks(&["dataplane.kfuncs.handoff.v1"]), ["tunnel_adapter-kfuncs.o"]);
    assert_eq!(picks(&["dataplane.kfuncs.handoff.v1", "dataplane.kfuncs.handoff_ingress.v1"]), ["tunnel_adapter-direct.o"]);
}

#[test]
fn wg_reports_its_dataplane_and_keeps_gso_on_both_objects() {
    for (features, dataplane) in [(vec!["dataplane.kfuncs.handoff.v1"], "kfuncs"), (vec![], "bpf")] {
        let mut h = fixture_with(profile(json!({})), Opts { features: Some(features), ..Opts::default() });
        h.apply();
        let request = h.session("wg_default")["data"]["interface_preparation"].clone();
        assert_eq!(request["local_gso"]["max_segs"], 65535);
        assert_eq!(request["local_offloads"]["gso"], true);
        assert_eq!(request["pipeline_offloads"]["gro"], true);
        assert_eq!(h.status("default")["dataplane"], dataplane);
    }
}

// ------------------------------------------------------------ handoff modes

const DIRECT: [&str; 2] = ["dataplane.kfuncs.handoff.v1", "dataplane.kfuncs.handoff_ingress.v1"];

fn any_fixture(driver: &str, opts: Opts) -> Env {
    if driver == "wireguard" {
        fixture_with(profile(json!({})), opts)
    } else {
        vpn_with(driver, json!({}), opts)
    }
}

#[test]
fn vpn_selects_a_single_boundary_with_the_ingress_handoff() {
    for driver in ["wireguard", "mihomo", "sing_box"] {
        let mut h = any_fixture(driver, Opts { features: Some(DIRECT.to_vec()), ..Opts::default() });
        let result = h.apply();
        let local = if driver == "wireguard" { "veerwg1" } else { "veervpn1" };
        assert_eq!(result["handoff_mode"], "direct", "{driver}");
        assert_eq!(result["pipeline_interface"], "");
        assert_eq!(h.links(), 2);
        assert_eq!(h.st().links.iter().find(|l| l["ifname"] == local).unwrap()["linkinfo"]["info_kind"], "dummy");
        assert_eq!(h.binding("tunnel-direct-out")["data"]["interfaces"], json!([local]));
        assert_eq!(h.binding("tunnel-links")["data"]["interfaces"], json!([result["interface"]]));
        assert_eq!(h.map_size(), 2);
        assert!(h.st().map.values().any(|v| v.starts_with("03000000")));
        let before = h.services().len();
        h.reconcile();
        assert_eq!(h.services().len(), before);
        h.act("teardown", json!({}));
        assert_eq!(h.links(), 0);
        assert_eq!(h.map_size(), 0);
        h.apply();
        assert_eq!(h.links(), 2);
    }
    let mut old = fixture_with(profile(json!({})), Opts { features: Some(DIRECT[..1].to_vec()), ..Opts::default() });
    old.apply();
    assert_eq!(old.links(), 3);
}

#[test]
fn vpn_reapplies_after_teardown_and_a_restart_that_replaced_the_cleanup_journal() {
    for driver in ["wireguard", "mihomo", "sing_box"] {
        let mut h = any_fixture(driver, Opts::default());
        h.apply();
        h.act("teardown", json!({}));
        let id = if driver == "wireguard" { "wg_default" } else { "vpn_default" };
        legacy_disabled_wan(&h, id);
        assert_eq!(h.links(), 0);
        assert!(h.lease().is_null());
        // Switching between proxy cores must accept the previous core's withdrawn WAN session.
        if driver != "wireguard" {
            let other = if driver == "mihomo" { "sing_box" } else { "mihomo" };
            h.set_profile("default", json!({"driver": other, "slot": 1, "mtu": 1420, "addresses": ["10.78.0.1/32"], "upstream_interface": "eth0"}), true);
            h.st().secrets.insert("core_default".into(), core_config(other));
        }
        assert_eq!(h.apply()["tc_ready"], true, "{driver}");
        assert_eq!(h.links(), 3);
    }
}

fn legacy_disabled_wan(h: &Env, id: &str) {
    let mut st = h.st();
    let status = st.status[id]["data"].clone();
    let session = st.sessions[id]["data"].clone();
    let data = merge(session, json!({"local_interface": status["local_interface"], "pipeline_interface": status["pipeline_interface"],
        "phase": "disabled", "managed_link": false, "arp_disabled_by_plugin": false, "noarp_ready": false, "cleanup_errors": []}));
    st.status.insert(id.to_string(), json!({"enabled": false, "data": data}));
}

#[test]
fn withdrawn_wan_recovery_rejects_missing_ownership_and_leftovers_before_mutation() {
    type Damage = Box<dyn Fn(&mut World)>;
    let mut damage: Vec<Damage> = vec![
        Box::new(|w| w.sessions.get_mut("vpn_default").unwrap()["enabled"] = json!(true)),
        Box::new(|w| {
            w.sessions.remove("vpn_default");
        }),
        Box::new(|w| {
            w.status.remove("vpn_default");
        }),
        Box::new(|w| w.sessions.get_mut("vpn_default").unwrap()["data"]["profile_key"] = json!("other")),
        Box::new(|w| w.sessions.get_mut("vpn_default").unwrap()["data"]["real_interface"] = json!("foreign0")),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["profile_key"] = json!("other")),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["cleanup_errors"] = json!(["route cleanup failed"])),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["managed_link"] = json!(true)),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["arp_disabled_by_plugin"] = json!(true)),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["noarp_ready"] = json!(true)),
        Box::new(|w| w.status.get_mut("vpn_default").unwrap()["data"]["phase"] = json!("delete_failed")),
    ];
    for name in ["vtundefault", "veervpn1", "veervpnp1"] {
        damage.push(Box::new(move |w| w.links.push(json!({"ifname": name, "ifindex": 99, "ifalias": "foreign", "linkinfo": {"info_kind": "tun"}}))));
    }
    for corrupt in damage {
        let mut h = vpn("mihomo");
        h.apply();
        h.act("teardown", json!({}));
        legacy_disabled_wan(&h, "vpn_default");
        corrupt(&mut h.st());
        let links = h.st().links.clone();
        let (services, specs) = (h.services().len(), h.specs().len());
        let err = h.apply_err();
        assert!(err.contains("ownership") || err.contains("owned"), "{err}");
        assert_eq!(h.st().links, links);
        assert_eq!(h.services().len(), services);
        assert_eq!(h.specs().len(), specs);
    }
}

#[test]
fn sing_box_binds_the_uplink_ip_for_concrete_outbounds_and_direct_dns() {
    let source = json!({"outbounds": [{"type": "selector", "tag": "pick", "outbounds": ["proxy"]}, {"type": "urltest", "tag": "test", "outbounds": ["proxy"]},
        {"type": "shadowsocks", "tag": "proxy"}, {"type": "direct", "tag": "direct"}, {"type": "socks", "tag": "chain", "detour": "proxy"}, {"type": "block", "tag": "block"}],
        "dns": {"servers": [{"type": "udp", "tag": "bootstrap", "server": "192.0.2.53"}, {"type": "udp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
            {"type": "hosts", "tag": "hosts", "predefined": {}}]}});
    for ip in ["192.0.2.9", "2001:db8::9"] {
        let p = json!({"driver": "sing_box", "slot": 1, "interface": "vtundefault", "mtu": 1420, "upstream_interface": "eth0", "upstream_ip": ip});
        let config: Value = serde_json::from_str(js::string(&drivers::build(&p, Some(&source.to_string())).unwrap()["config"]).as_str()).unwrap();
        let key = if ip.contains(':') { "inet6_bind_address" } else { "inet4_bind_address" };
        for v in [&config["outbounds"][2], &config["outbounds"][3], &config["dns"]["servers"][0]] {
            assert_eq!(v[key], ip);
            assert_eq!(v["bind_interface"], "eth0");
        }
        for v in [&config["outbounds"][0], &config["outbounds"][1], &config["outbounds"][4], &config["outbounds"][5], &config["dns"]["servers"][1], &config["dns"]["servers"][2]] {
            assert!(v.get(key).is_none());
        }
    }
    let mut h = vpn_with("sing_box", json!({"upstream_ip": "2001:db8::9"}), Opts {
        inventory: vec![json!({"name": "eth0", "addresses": ["2001:db8:0:0:0:0:0:9/64"]})],
        ..Opts::default()
    });
    h.apply();
    assert_eq!(h.lease()["settings"]["upstream_ip"], "2001:db8:0:0:0:0:0:9");
    let original = h.specs()[0]["config"].clone();
    let mut draft = h.fake().data("profiles", "default");
    draft["upstream_ip"] = json!("192.0.2.88");
    h.set_profile("default", draft, true);
    h.reconcile();
    assert_eq!(h.specs().last().unwrap()["config"], original, "recovery must ignore later drafts");
}

#[test]
fn vpn_rejects_invalid_non_local_and_wrong_driver_source_addresses() {
    let mut h = vpn_with("sing_box", json!({}), Opts { inventory: vec![json!({"name": "eth0", "addresses": ["192.0.2.1/24"]})], ..Opts::default() });
    h.apply();
    let links = h.st().links.clone();
    let specs = h.specs().len();
    for ip in ["192.0.2.1/24", "192.0.2.9", "0.0.0.0", "node.example", "192.00.2.1", "fe80::1%eth0"] {
        let mut draft = h.fake().data("profiles", "default");
        draft["upstream_ip"] = json!(ip);
        h.set_profile("default", draft, true);
        h.apply_err();
        assert_eq!(h.st().links, links, "{ip}");
        assert_eq!(h.specs().len(), specs);
    }
    let mut m = vpn_with("mihomo", json!({"upstream_ip": "192.0.2.1"}), Opts::default());
    assert!(m.apply_err().contains("仅支持 sing-box"));
    assert!(m.services().is_empty());
}

#[test]
fn vpn_deletes_only_after_owned_cleanup_and_retains_shared_credentials() {
    for driver in ["wireguard", "mihomo", "sing_box", "tun"] {
        let mut h = if driver == "tun" {
            vpn_with("tun", json!({"tun_interface": "tun0", "tun_alias": "external-owner"}), Opts::default())
        } else {
            any_fixture(driver, Opts::default())
        };
        if driver == "tun" {
            h.st().links.push(json!({"ifname": "tun0", "ifindex": 30, "ifalias": "external-owner", "linkinfo": {"info_kind": "tun"}, "flags": ["UP"], "mtu": 1420}));
        }
        h.apply();
        h.st().secrets.insert("core_default".into(), "shared".into());
        h.st().secrets.insert("psk_default_7".into(), private());
        h.set_profile("other", json!({"driver": "mihomo", "slot": 2, "config_secret": "core_default"}), false);
        h.act("health_settings", json!({"settings": {"enabled": true}}));
        assert_eq!(h.act("delete_profile", json!({}))["phase"], "deleted", "{driver}");
        assert!(h.fake().record("profiles", "default").is_none());
        assert!(h.fake().record("profiles", "other").is_some());
        assert!(h.fake().record("status", "default").is_none());
        assert!(h.secret("private_default").is_none());
        assert!(h.secret("psk_default_7").is_none());
        assert_eq!(h.secret("core_default").as_deref(), Some("shared"));
        for key in ["lease_default", "applied_default", "health_config_default", "health_generation_default", "health_result_default"] {
            assert!(h.kv(key).is_null(), "{driver} {key}");
        }
        assert_eq!(h.map_size(), 0);
        assert_eq!(h.links(), if driver == "tun" { 1 } else { 0 });
        assert!(h.st().sessions.is_empty());
        assert!(h.st().procs.is_empty());
        assert_eq!(h.act("delete_profile", json!({}))["phase"], "deleted", "retries are idempotent");
    }
}

#[test]
fn vpn_deletion_handles_drafts_delayed_health_workers_and_retryable_failures() {
    let mut draft = vpn("mihomo");
    draft.act("delete_profile", json!({}));
    assert!(draft.services().is_empty());
    assert!(draft.fake().records("profiles").is_empty());
    let mut h = vpn("mihomo");
    h.apply();
    h.st().hold_dispatch = true;
    h.act("health_check", json!({}));
    h.st().sessions.get_mut("vpn_default").unwrap()["data"]["driver_plugin"] = json!("foreign");
    assert!(h.act_err("delete_profile", json!({})).contains("another driver"));
    assert!(h.fake().record("profiles", "default").is_some());
    assert!(h.secret("core_default").is_some());
    h.st().sessions.get_mut("vpn_default").unwrap()["data"]["driver_plugin"] = json!("vpn_core");
    h.act("delete_profile", json!({}));
    h.st().hold_dispatch = false;
    h.drain();
    assert!(h.st().operations.is_empty());
    assert!(h.kv("health_result_default").is_null());
    assert!(h.fake().records("profiles").is_empty());
}

// ------------------------------------------------------------ health

fn health_state(h: &mut Env) -> Value {
    let items = js::array(&h.act("health_status", json!({}))["items"]);
    items.into_iter().find(|v| v["key"] == "default").unwrap()
}

fn health_tick(h: &mut Env) {
    h.timer("vpn_health");
}

#[test]
fn health_settings_are_bounded_and_reject_credentials_and_bad_urls() {
    assert_eq!(health::settings(&Value::Null).unwrap()["enabled"], false);
    let bad = [
        json!({"enabled": "yes"}),
        json!({"url": "http://user:secret@example.com/"}),
        json!({"url": "http://a..b/"}),
        json!({"url": "https://a/#secret"}),
        json!({"url": "https://a/\nheader"}),
        json!({"url": "ftp://example.com"}),
        json!({"url": "http://example.com:65536"}),
        json!({"resolver_ip": "127.00.0.1"}),
        json!({"resolver_ip": "300.1.1.1"}),
        json!({"interval_seconds": 14}),
        json!({"timeout_ms": 10001}),
        json!({"expected_status": 99}),
        json!({"extra": true}),
    ];
    for value in bad {
        assert!(health::settings(&value).is_err(), "{value}");
    }
    assert_eq!(health::settings(&json!({"expected_status": 0, "url": "http://192.168.20.1:8080/health"})).unwrap()["expected_status"], 0);
}

#[test]
fn health_uses_the_applied_wan_and_does_not_mutate_forwarding() {
    for driver in ["wireguard", "mihomo", "sing_box"] {
        let mut h = any_fixture(driver, Opts::default());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let r = requests.clone();
        h.fake().adapter("net.http.request", move |args| {
            r.lock().unwrap().push(args[0].clone());
            Ok(json!({"status_code": 204}))
        });
        assert!(h.act_err("health_check", json!({})).contains("尚未就绪"));
        h.apply();
        let links = h.st().links.clone();
        let specs = h.specs().len();
        assert_eq!(health_state(&mut h)["state"], "unknown");
        assert!(!h.timers().contains_key("vpn_health"));
        h.act("health_check", json!({}));
        health_tick(&mut h);
        let value = health_state(&mut h);
        assert_eq!(value["state"], "healthy", "{driver} {value}");
        assert_eq!(value["result"]["status_code"], 204);
        assert_eq!(value["result"]["consecutive_failures"], 0);
        assert!(js::number(&value["result"]["last_success_at"]) > 0.0);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["interface"], if driver == "wireguard" { "veerwg1" } else { "veervpn1" });
        assert_eq!(requests[0]["source_ip"], if driver == "wireguard" { "10.77.0.1" } else { "10.78.0.1" });
        assert_eq!(requests[0]["follow_redirects"], false);
        assert_eq!(requests[0]["resolver_ip"], "1.1.1.1");
        assert_eq!(h.st().links, links);
        assert_eq!(h.specs().len(), specs);
        assert!(!h.timers().contains_key("vpn_health"));
    }
}

#[test]
fn health_counts_failures_sanitizes_errors_and_recovers() {
    let mut h = vpn("mihomo");
    let response = Arc::new(Mutex::new(Err::<Value, String>("password=sensitive-core-password TLS certificate failed".into())));
    let r = response.clone();
    h.fake().adapter("net.http.request", move |_| r.lock().unwrap().clone());
    h.apply();
    let mut check = |h: &mut Env| {
        h.act("health_check", json!({}));
        health_tick(h);
        health_state(h)
    };
    assert_eq!(check(&mut h)["result"]["reason"], "tls");
    assert_eq!(check(&mut h)["result"]["consecutive_failures"], 2);
    assert!(!health_state(&mut h).to_string().contains("sensitive-core-password"));
    *response.lock().unwrap() = Ok(json!({"status_code": 302}));
    assert_eq!(check(&mut h)["result"]["reason"], "http_status");
    *response.lock().unwrap() = Err("deadline exceeded".into());
    assert_eq!(check(&mut h)["result"]["reason"], "timeout");
    *response.lock().unwrap() = Ok(json!({"status_code": 201}));
    h.act("health_settings", json!({"settings": {"expected_status": 0}}));
    assert_eq!(check(&mut h)["state"], "healthy");
    assert_eq!(health_state(&mut h)["result"]["consecutive_failures"], 0);
    assert_eq!(h.specs().len(), 1);
}

#[test]
fn health_deduplicates_queued_work_rejects_old_generations_and_expires_jobs() {
    let mut h = fixture(profile(json!({})));
    let requests = Arc::new(Mutex::new(0));
    let r = requests.clone();
    h.fake().adapter("net.http.request", move |_| {
        *r.lock().unwrap() += 1;
        Ok(json!({"status_code": 204}))
    });
    h.apply();
    h.st().hold_dispatch = true;
    h.act("health_check", json!({}));
    h.act("health_check", json!({}));
    assert_eq!(h.st().dispatched.len(), 1);
    h.act("health_settings", json!({"settings": {"url": "http://192.168.20.1/"}}));
    let first = h.st().dispatched[0].clone();
    h.worker.run(MsgKind::Event, "onHealthProbe", json!({"payload": first})).unwrap();
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 0);
    h.act("health_check", json!({}));
    h.st().operations.get_mut("health_default").unwrap()["input"]["started_at"] = json!(1);
    health_tick(&mut h);
    assert_eq!(health_state(&mut h)["result"]["reason"], "timeout");
    h.act("health_check", json!({}));
    let queued = h.st().dispatched.clone();
    let newest = queued.last().unwrap().clone();
    h.worker.run(MsgKind::Event, "onHealthProbe", json!({"payload": queued[1]})).unwrap();
    health_tick(&mut h);
    assert_eq!(health_state(&mut h)["state"], "checking");
    h.worker.run(MsgKind::Event, "onHealthProbe", json!({"payload": newest})).unwrap();
    health_tick(&mut h);
    assert_eq!(health_state(&mut h)["state"], "healthy");
    assert_eq!(h.st().operations.len(), 1, "repeated probes reuse one durable record");
}

#[test]
fn health_cannot_publish_success_after_a_link_or_core_generation_changes() {
    for change in ["link", "core"] {
        let mut h = vpn("mihomo");
        let w = h.w.clone();
        h.fake().adapter("net.http.request", move |_| {
            let mut st = w.lock().unwrap();
            if change == "link" {
                let link = st.links.iter_mut().find(|l| l["ifname"] == "vtundefault").unwrap();
                link["ifindex"] = json!(js::number(&link["ifindex"]) as u64 + 1);
            } else {
                let p = st.procs.get_mut("vpn_default").unwrap();
                p["started_at"] = json!(js::number(&p["started_at"]) as u64 + 1);
            }
            Ok(json!({"status_code": 204}))
        });
        h.apply();
        h.act("health_check", json!({}));
        health_tick(&mut h);
        let state = health_state(&mut h);
        assert!(["stale", "unavailable"].contains(&state["state"].as_str().unwrap()), "{change}: {state}");
        assert_ne!(state["result"]["state"], "healthy");
    }
}

#[test]
fn health_automatic_probes_are_opt_in_and_respect_cadence() {
    let mut h = fixture(profile(json!({})));
    let requests = Arc::new(Mutex::new(0));
    let r = requests.clone();
    h.fake().adapter("net.http.request", move |_| {
        *r.lock().unwrap() += 1;
        Ok(json!({"status_code": 204}))
    });
    h.apply();
    // Additional health records must not push applied leases beyond the first KV page.
    for i in 0..45 {
        h.kv_set(&format!("health_padding_{i}"), json!({}));
    }
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 0);
    h.act("health_check", json!({}));
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 1);
    h.act("health_settings", json!({"settings": {"enabled": true, "interval_seconds": 15}}));
    health_tick(&mut h);
    health_tick(&mut h);
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 2, "enabling auto probes must immediately check the new settings");
    let started = js::number(&h.st().operations["health_default"]["input"]["started_at"]);
    h.st().operations.get_mut("health_default").unwrap()["input"]["started_at"] = js::num(started - 16000.0);
    health_tick(&mut h);
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 3);
    h.act("health_settings", json!({"settings": {"enabled": false}}));
    health_tick(&mut h);
    assert_eq!(*requests.lock().unwrap(), 3);
    h.reconcile();
    assert_eq!(h.lease()["active"], true);
    h.deactivate().unwrap();
    assert!(!h.timers().contains_key("vpn_health"));
    assert_eq!(h.links(), 0);
}

// ------------------------------------------------------------ proxy cores

#[test]
fn vpn_allocates_its_wan_address_and_pins_it_across_reapply_and_recovery() {
    for driver in ["mihomo", "sing_box"] {
        let mut h = vpn_with(driver, json!({"addresses": null}), Opts::default());
        let applied = h.apply();
        let address = js::string(&applied["egress_nat_source_ip"]);
        assert!(!address.is_empty());
        assert_eq!(applied["wan_addresses"], json!([format!("{address}/32")]));
        assert_eq!(h.lease()["settings"]["addresses"], applied["wan_addresses"]);
        assert!(h.fake().data("profiles", "default").get("addresses").is_none(), "applying must not rewrite the draft");
        let route_reads = h.calls().iter().filter(|r| args_of(r).contains(&"route".to_string())).count();
        h.apply();
        h.reconcile();
        assert_eq!(h.session("vpn_default")["data"]["ipv4"], json!(address));
        assert_eq!(h.calls().iter().filter(|r| args_of(r).contains(&"route".to_string())).count(), route_reads);
        h.drop_link("vtundefault");
        h.repair();
        h.repair();
        assert_eq!(h.session("vpn_default")["data"]["ipv4"], json!(address));
    }
}

#[test]
fn vpn_allocation_avoids_host_networks_routes_drafts_and_active_leases() {
    let mut h = vpn_with("mihomo", json!({"addresses": null}), Opts {
        inventory: vec![json!({"name": "br-lan", "addresses": ["10.78.1.254/24"]})],
        routes: json!([{"dst": "default"}, {"dst": "10.78.9.1/32"}]),
        ..Opts::default()
    });
    h.set_profile("draft", json!({"driver": "wireguard", "slot": 2, "addresses": ["10.78.17.1/32"]}), false);
    h.kv_set("lease_running", json!({"active": true, "plan": {"slot": 3, "driver": "mihomo", "interface": "vtunrunning", "local": "veervpn3", "pipeline": "veervpnp3", "addresses": ["10.78.25.1/32"]}}));
    let result = h.apply();
    let ip = js::string(&result["egress_nat_source_ip"]);
    assert!(!["10.78.1.1", "10.78.9.1", "10.78.17.1", "10.78.25.1"].contains(&ip.as_str()), "{ip}");
    assert_eq!(h.session("vpn_default")["data"]["ipv4"], json!(ip));
}

#[test]
fn vpn_allocation_fails_before_mutation_when_inventory_fails_or_pools_conflict() {
    let mut full = vpn_with("mihomo", json!({"addresses": null}), Opts {
        inventory: vec![json!({"addresses": ["10.0.0.1/8", "172.16.0.1/12", "192.168.0.1/16", "198.18.0.1/15"]})],
        ..Opts::default()
    });
    assert!(full.apply_err().contains("No free internal WAN address"));
    let mut broken = vpn_with("mihomo", json!({"addresses": null}), Opts::default());
    broken.fake().adapter("net.link.list", |_| Err("inventory unavailable".into()));
    assert!(broken.apply_err().contains("inventory unavailable"));
    for h in [&full, &broken] {
        assert!(h.specs().is_empty());
        assert!(h.services().is_empty());
        assert!(h.lease().is_null());
    }
}

#[test]
fn vpn_installs_official_cores_in_the_background() {
    let mut h = vpn_with("mihomo", json!({}), Opts { host_info: json!({"os": "linux", "arch": "amd64"}), ..Opts::default() });
    let requests = Arc::new(Mutex::new(Vec::new()));
    let r = requests.clone();
    h.fake().adapter("process.binaryInstall", move |args| {
        r.lock().unwrap().push(args[0].clone());
        Ok(json!({"id": args[0]["id"], "versions": [], "install": {"state": "resolving"}}))
    });
    let result = h.act("core_install", json!({"driver": "mihomo", "version": "1.19.33"}));
    assert_eq!(result["install"]["state"], "resolving");
    assert!(h.services().is_empty());
    assert!(h.specs().is_empty());
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0]["release_url"], "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/v1.19.33");
        assert!(js::string(&requests[0]["asset"]).contains("amd64-compatible"));
        assert_eq!(requests[0]["check_args"], json!(["-v"]));
    }
    h.act("core_install", json!({"driver": "sing_box"}));
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests[1]["release_url"], "https://api.github.com/repos/SagerNet/sing-box/releases/latest");
        assert_eq!(requests[1]["archive_path"], "sing-box-{version}-linux-amd64/sing-box");
    }
    for payload in [json!({"driver": "wireguard"}), json!({"driver": "mihomo", "version": "../../tmp"}), json!({"driver": "mihomo", "sha256": "bad"})] {
        h.act_err("core_install", payload);
    }
}

#[test]
fn vpn_managed_default_updates_only_explicitly_reapplied_wans() {
    let mut h = vpn("mihomo");
    let selected = Arc::new(Mutex::new("/opt/veer/plugins.veer-state/cores/vpn_core/mihomo/linux-amd64/v1/mihomo".to_string()));
    let s = selected.clone();
    h.fake().adapter("process.binaryStatus", move |_| Ok(json!({"id": "mihomo", "path": *s.lock().unwrap(), "versions": []})));
    h.apply();
    let old = h.specs()[0]["command"].clone();
    assert_eq!(old, json!(*selected.lock().unwrap()));
    let next = selected.lock().unwrap().replace("/v1/", "/v2/");
    *selected.lock().unwrap() = next.clone();
    h.reconcile();
    assert_eq!(h.specs().last().unwrap()["command"], old);
    h.apply();
    assert_eq!(h.specs().last().unwrap()["command"], json!(next));
}

#[test]
fn vpn_core_rollback_chooses_the_previous_version_without_restarts() {
    let mut h = vpn("mihomo");
    let selected = Arc::new(Mutex::new(json!({"id": "mihomo", "version": "v2", "previous": "v1", "versions": []})));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let s = selected.clone();
    h.fake().adapter("process.binaryStatus", move |_| Ok(s.lock().unwrap().clone()));
    for method in ["process.binarySelect", "process.binaryRemove"] {
        let (c, s) = (calls.clone(), selected.clone());
        h.fake().adapter(method, move |args| {
            c.lock().unwrap().push(args[0].clone());
            Ok(s.lock().unwrap().clone())
        });
    }
    h.act("core_rollback", json!({"driver": "mihomo"}));
    h.act("core_select", json!({"driver": "mihomo", "version": "v3"}));
    h.act("core_remove", json!({"driver": "mihomo", "version": "v0"}));
    assert_eq!(*calls.lock().unwrap(), vec![json!({"id": "mihomo", "version": "v1"}), json!({"id": "mihomo", "version": "v3"}), json!({"id": "mihomo", "version": "v0"})]);
    assert!(h.services().is_empty());
    assert!(h.specs().is_empty());
    selected.lock().unwrap().as_object_mut().unwrap().remove("previous");
    assert!(h.act_err("core_rollback", json!({"driver": "mihomo"})).contains("No previous"));
}

#[test]
fn vpn_saves_the_core_configuration_to_the_selected_secret() {
    let mut h = vpn_with("sing_box", json!({"config_secret": "core_sing_box_default"}), Opts::default());
    let config = json!({"outbounds": [{"type": "direct", "tag": "selected-core"}]}).to_string();
    h.act("set_core_config", json!({"name": "core_sing_box_default", "value": config}));
    h.apply();
    let spec: Value = serde_json::from_str(&js::string(&h.specs()[0]["config"])).unwrap();
    assert_eq!(spec["outbounds"][0]["tag"], "selected-core");
    h.act("set_core_config", json!({"value": "{\"outbounds\":[]}"}));
    assert_eq!(h.secret("core_default").as_deref(), Some("{\"outbounds\":[]}"));
    assert!(h.act_err("set_core_config", json!({"name": "../../config", "value": config})).contains("identifier"));
}

fn proxies<'v>(config: &'v Value, driver: &str) -> &'v Value {
    &config[if driver == "mihomo" { "proxies" } else { "outbounds" }]
}

fn spec_config(spec: &Value) -> Value {
    serde_json::from_str(&js::string(&spec["config"])).unwrap()
}

#[test]
fn vpn_stores_imported_links_and_recovers_the_applied_snapshot() {
    for driver in ["mihomo", "sing_box"] {
        let mut h = vpn(driver);
        let source = format!("ss://{}@192.0.2.2:8388#first\ntrojan://another-secret@node.example:443?sni=example.com#second", b64url(b"aes-128-gcm:import-secret"));
        let saved = h.act("set_core_config", json!({"format": "links", "driver": driver, "value": b64(&source), "selected": 1, "options": {"direct_cidrs": ["10.0.0.0/8"]}}));
        assert_eq!(saved["stored"], true);
        assert_eq!(saved["form"]["selected"], 1);
        assert_eq!(js::array(&saved["form"]["nodes"]).iter().map(|n| js::string(&n["name"])).collect::<Vec<_>>(), ["first", "second"]);
        assert!(h.specs().is_empty());
        assert!(h.services().is_empty());
        let form = h.act("core_form", json!({}));
        assert_eq!(form, saved["form"]);
        for secret in ["import-secret", "another-secret", "192.0.2.2", "node.example"] {
            assert!(!form.to_string().contains(secret));
        }
        h.apply();
        let applied = h.specs()[0]["config"].clone();
        assert_eq!(proxies(&spec_config(&h.specs()[0]), driver)[0]["password"], "another-secret");
        h.act("set_core_config", json!({"format": "links", "driver": driver, "value": "", "selected": 0, "options": {"dns_hijack": true}}));
        assert_eq!(h.act("core_form", json!({}))["selected"], 0);
        h.st().procs.remove("vpn_default");
        h.drop_link("vtundefault");
        h.reconcile();
        assert_eq!(h.specs().last().unwrap()["config"], applied);
        h.apply();
        assert_eq!(proxies(&spec_config(h.specs().last().unwrap()), driver)[0]["password"], "import-secret");
        for resource in ["profiles", "status"] {
            assert!(!json!(h.fake().records(resource)).to_string().contains("import-secret"));
        }
    }
}

#[test]
fn vpn_stores_a_front_node_chain_and_shows_it_on_the_status() {
    for driver in ["mihomo", "sing_box"] {
        let m = driver == "mihomo";
        let mut h = vpn(driver);
        let source = format!("ss://{}@192.0.2.2:8388#front\ntrojan://exit-secret@node.example:443?sni=example.com#exit", b64url(b"aes-128-gcm:front-secret"));
        let saved = h.act("set_core_config", json!({"format": "links", "driver": driver, "value": source, "selected": 1, "via": [0]}));
        assert_eq!(saved["form"]["via"], json!([0]));
        assert_eq!(h.act("core_form", json!({}))["via"], json!([0]));
        h.apply();
        let config = spec_config(h.specs().last().unwrap());
        let list = js::array(proxies(&config, driver));
        let tag = |p: &Value| js::string(js::or(&p["name"], &p["tag"]));
        let main = list.iter().find(|p| tag(p) == "veer-node").unwrap();
        let hop = list.iter().find(|p| tag(p) == "veer-hop-1").unwrap();
        assert_eq!(main["password"], "exit-secret");
        assert_eq!(main[if m { "dialer-proxy" } else { "detour" }], "veer-hop-1");
        assert_eq!(hop["password"], "front-secret");
        let status = h.status("default");
        assert_eq!(status["node"], json!({"name": "exit", "type": "trojan", "via": [{"name": "front", "type": "ss"}]}));
        assert_eq!(h.act("inspect", json!({}))["node"], status["node"]);
        assert!(!status.to_string().contains("front-secret") && !status.to_string().contains("192.0.2.2"));
        assert!(h.act_err("set_core_config", json!({"format": "links", "driver": driver, "value": "", "selected": 1, "via": [1]})).contains("不能是所选节点"));
        assert_eq!(h.act("core_form", json!({}))["via"], json!([0]));
        h.act("set_core_config", json!({"format": "links", "driver": driver, "value": "", "selected": 1}));
        assert_eq!(h.act("core_form", json!({}))["via"], json!([]));
        h.apply();
        assert_eq!(h.status("default")["node"], json!({"name": "exit", "type": "trojan"}));
    }
}

#[test]
fn vpn_validates_the_entire_import_before_changing_a_saved_config() {
    for driver in ["mihomo", "sing_box"] {
        let mut h = vpn(driver);
        let source = format!("ss://{}@192.0.2.2:8388", b64url(b"aes-128-gcm:private-password"));
        h.act("set_core_config", json!({"format": "links", "driver": driver, "value": source}));
        let other = if driver == "mihomo" { "sing_box" } else { "mihomo" };
        for payload in [
            json!({"value": format!("{source}\ntrojan://private-password@host:0")}),
            json!({"selected": 100}),
            json!({"driver": other}),
            json!({"options": {"direct_cidrs": ["10.0.0.0/99"]}}),
        ] {
            let request = merge(json!({"format": "links", "driver": driver, "value": ""}), payload);
            let err = h.act_err("set_core_config", request);
            assert!(!err.contains("private-password"), "{err}");
            assert_eq!(h.act("core_form", json!({}))["selected"], 0);
        }
        assert!(h.specs().is_empty());
        assert!(h.services().is_empty());
        assert!(h.act_err("set_core_config", json!({"value": "{\"veer_proxy\":1}"})).contains("sharing-link"));
        h.apply();
        assert_eq!(proxies(&spec_config(h.specs().last().unwrap()), driver)[0]["password"], "private-password");
        let mut native = vpn(driver);
        assert_eq!(native.act("core_form", json!({}))["mode"], "native");
        assert!(native.act_err("set_core_config", json!({"format": "links", "driver": driver, "value": ""})).contains("重新导入"));
    }
}

#[test]
fn vpn_uses_a_managed_tun_wan_and_leaves_host_routing_to_the_upstream() {
    for driver in ["mihomo", "sing_box"] {
        let mut h = vpn(driver);
        let result = h.apply();
        assert_eq!(result["phase"], "applied");
        assert_eq!(result["egress_nat_interface"], "veervpn1");
        assert_eq!(result["egress_nat_redirect_mode"], "prepared_l2");
        assert_eq!(h.act("inspect", json!({}))["phase"], "applied");
        assert_eq!(h.map_size(), 2);
        let config = spec_config(&h.specs()[0]);
        if driver == "mihomo" {
            assert_eq!(config["tun"]["stack"], "gvisor");
            assert_eq!(config["tun"]["auto-route"], false);
            assert_eq!(config["tun"]["auto-redirect"], false);
            assert_eq!(config["interface-name"], "eth0");
            assert_eq!(config["tun"]["gso"], true);
            assert_eq!(config["tun"]["gso-max-size"], 65536);
        } else {
            assert_eq!(config["inbounds"][0]["stack"], "gvisor");
            assert_eq!(config["inbounds"][0]["auto_route"], false);
            assert_eq!(config["route"]["default_interface"], "eth0");
        }
        assert!(!json!(h.fake().records("status")).to_string().contains("sensitive-core-password"));
        h.act("teardown", json!({}));
        assert_eq!(h.links(), 0);
        assert!(h.st().procs.is_empty());
    }
}

#[test]
fn vpn_delayed_tun_is_withheld_until_ready_then_published_by_repair() {
    let mut h = vpn_with("mihomo", json!({}), Opts { delayed: true, ..Opts::default() });
    assert_eq!(h.apply()["phase"], "starting");
    assert_eq!(h.status_record("default")["enabled"], true);
    assert_ne!(h.st().status.get("vpn_default").map(|s| s["enabled"].clone()), Some(json!(true)));
    let index = h.st().next;
    h.st().next += 1;
    h.st().links.push(tun_link("vtundefault", index));
    h.repair();
    assert_eq!(h.status("default")["phase"], "applied");
    assert_eq!(h.st().links.iter().find(|l| l["ifname"] == "vtundefault").unwrap()["ifalias"], "veer:vpn_core:default");
}

#[test]
fn vpn_startup_without_a_tun_times_out_through_the_restart_budget() {
    let mut h = vpn_with("mihomo", json!({}), Opts { delayed: true, ..Opts::default() });
    h.apply();
    let now = crate::now();
    h.proc_mut("default", |p| p["started_at"] = js::num(now));
    h.repair();
    assert_eq!(h.proc("default")["starts"], 1);
    h.proc_mut("default", |p| p["started_at"] = js::num(now - 31000.0));
    h.repair();
    assert_eq!(h.proc("default")["starts"], 2);
    assert_eq!(h.session("vpn_default")["enabled"], false);
}

#[test]
fn vpn_core_death_withdraws_both_directions_and_keeps_an_exhausted_budget() {
    let mut h = vpn("mihomo");
    h.apply();
    h.proc_mut("default", |p| {
        p["state"] = json!("exited");
        p["exit_code"] = json!(2);
    });
    h.repair();
    assert_eq!(h.map_size(), 0);
    assert_eq!(h.session("vpn_default")["enabled"], false);
    assert_eq!(h.status("default")["phase"], "failed");
    assert_eq!(h.proc("default")["starts"], 1);
}

#[test]
fn vpn_deleted_tun_uses_bounded_recovery_and_drift_repairs_the_owned_link() {
    let mut h = vpn("mihomo");
    h.apply();
    h.link_mut("vtundefault", |l| {
        l["flags"] = json!([]);
        l["mtu"] = json!(1300);
    });
    h.repair();
    assert_eq!(h.st().links.iter().find(|l| l["ifname"] == "vtundefault").unwrap()["mtu"], 1420);
    assert_eq!(h.proc("default")["starts"], 1);
    h.drop_link("vtundefault");
    h.repair();
    assert_eq!(h.proc("default")["starts"], 2);
    h.repair();
    assert_eq!(h.status("default")["phase"], "applied");
    h.proc_mut("default", |p| p["starts"] = json!(4));
    h.drop_link("vtundefault");
    h.repair();
    assert!(js::string(&h.status("default")["error"]).contains("budget exhausted"));
    assert_eq!(h.map_size(), 0);
}

#[test]
fn vpn_recovery_restores_the_applied_configuration_and_ignores_newer_drafts() {
    let mut h = vpn("mihomo");
    h.apply();
    let applied = h.specs()[0]["config"].clone();
    h.act("set_core_config", json!({"value": json!({"proxies": [{"password": "new-draft"}]}).to_string()}));
    h.proc_mut("default", |p| p["started_at"] = json!(2000));
    h.drop_link("vtundefault");
    let index = h.st().next;
    h.st().next += 1;
    h.st().links.push(tun_link("vtundefault", index));
    h.repair();
    assert_eq!(h.specs().last().unwrap()["config"], applied);
    assert_eq!(h.status("default")["phase"], "applied");
}

#[test]
fn vpn_healthy_reconciliation_preserves_the_boundary_and_running_core() {
    let mut h = vpn("mihomo");
    h.apply();
    let preparations = h.services().len();
    h.reconcile();
    assert_eq!(h.services().len(), preparations);
    assert_eq!(h.proc("default")["starts"], 1);
    assert_eq!(h.session("vpn_default")["data"]["usable"], true);
    assert_eq!(h.status("default")["phase"], "applied");
}

#[test]
fn lost_or_corrupt_adapter_entries_are_repaired_without_touching_networking() {
    for driver in ["wireguard", "mihomo", "sing_box", "tun"] {
        let mut h = if driver == "tun" {
            vpn_with("tun", json!({"tun_interface": "vtundefault", "tun_alias": "veer:vpn_core:default"}), Opts::default())
        } else {
            any_fixture(driver, Opts::default())
        };
        if driver == "tun" {
            let index = h.st().next;
            h.st().next += 1;
            let mut link = tun_link("vtundefault", index);
            link["ifalias"] = json!("veer:vpn_core:default");
            h.st().links.push(link);
        }
        h.apply();
        h.st().map_get_throws = true;
        let expected = h.st().map.clone();
        let links = h.st().links.clone();
        let procs = h.st().procs.clone();
        let (lease, specs) = (h.lease(), h.specs().len());
        let tick = |h: &mut Env| {
            for _ in 0..5 {
                h.timer("tunnel_maps");
            }
        };
        h.st().map_writes = 0;
        tick(&mut h);
        assert_eq!(h.st().map_writes, 0, "healthy checks must not rewrite maps");
        let keys: Vec<String> = expected.keys().cloned().collect();
        for damage in ["empty", "missing-forward", "missing-reply", "corrupt-forward", "corrupt-reply"] {
            {
                let mut st = h.st();
                if damage == "empty" {
                    st.map.clear();
                } else {
                    let key = &keys[if damage.ends_with("forward") { 0 } else { 1 }];
                    if damage.starts_with("missing") {
                        st.map.remove(key);
                    } else {
                        st.map.insert(key.clone(), "00".repeat(24));
                    }
                }
            }
            tick(&mut h);
            assert_eq!(h.st().map, expected, "{driver} {damage}");
            let count = h.st().map_writes;
            tick(&mut h);
            assert_eq!(h.st().map_writes, count, "repair must stop writing after recovery");
            assert_eq!(h.st().links, links);
            assert_eq!(h.lease(), lease);
            assert_eq!(h.st().procs, procs);
            assert_eq!(h.specs().len(), specs);
        }
        // The five-minute check finds the same damage.
        h.st().map.clear();
        h.repair();
        assert_eq!(h.st().map, expected, "{driver} full check");
    }
}

#[test]
fn vpn_enables_gso_only_for_a_managed_tun_with_negotiated_capabilities() {
    let full = json!({"tx": true, "sg": true, "tso": true, "gso": true});
    let mut cases = vec![("sing_box", true, full.clone(), false, true), ("sing_box", false, full.clone(), false, false)];
    for k in ["tx", "sg", "tso", "gso"] {
        cases.push(("sing_box", true, merge(full.clone(), json!({k: false})), false, false));
    }
    cases.push(("sing_box", true, json!({}), false, false));
    cases.push(("mihomo", true, full.clone(), false, true));
    cases.push(("mihomo", false, full.clone(), false, false));
    cases.push(("mihomo", true, merge(full.clone(), json!({"tso": false})), false, false));
    cases.push(("sing_box", true, full.clone(), true, false));
    for (driver, vnet, offloads, legacy, want) in cases {
        let mut h = vpn_with(driver, json!({}), Opts { vnet_header: vnet, legacy_net_info: legacy, ..Opts::default() });
        let probes = Arc::new(Mutex::new(0));
        let (p, o) = (probes.clone(), offloads.clone());
        h.fake().adapter("net.link.getOffloads", move |_| {
            *p.lock().unwrap() += 1;
            Ok(o.clone())
        });
        let mut status = h.apply();
        for _ in 0..3 {
            if status["phase"] != "starting" {
                break;
            }
            shift_clock(1001.0);
            h.repair();
            status = h.act("inspect", json!({}));
        }
        assert_eq!(status["phase"], "applied", "{driver} {offloads}");
        let data = h.session("vpn_default")["data"].clone();
        assert_eq!(status["tun_gso"], want, "{driver} {vnet} {offloads} {legacy}");
        assert_eq!(data["interface_preparation"]["local_offloads"]["gso"], want);
        assert_eq!(data["interface_preparation"]["pipeline_offloads"]["gro"], want);
        assert_eq!(data["interface_preparation"]["local_gso"]["max_segs"], if want { 65535 } else { 1 });
        // WAN Core saves prepare_handoff settings as profile defaults: inspect the service call.
        let prepared = h.services().iter().rev().find(|r| r["action"] == "prepare_handoff").unwrap()["payload"].clone();
        assert_eq!(prepared["usable"], false);
        assert_eq!(prepared["interface_preparation"]["local_offloads"]["gso"], want);
        let before = *probes.lock().unwrap();
        h.repair();
        h.reconcile();
        assert_eq!(*probes.lock().unwrap(), before, "healthy polling/reconciliation must not probe");
    }
}

#[test]
fn vpn_waits_for_bounded_tun_offload_negotiation() {
    let mut h = vpn_with("sing_box", json!({}), Opts { vnet_header: true, ..Opts::default() });
    let probes = Arc::new(Mutex::new(0));
    let ready = Arc::new(Mutex::new(false));
    let (p, r) = (probes.clone(), ready.clone());
    h.fake().adapter("net.link.getOffloads", move |_| {
        *p.lock().unwrap() += 1;
        let ready = *r.lock().unwrap();
        Ok(json!({"tx": ready, "sg": ready, "tso": ready, "gso": ready}))
    });
    assert_eq!(h.apply()["phase"], "starting");
    assert_eq!(h.map_size(), 0);
    assert_ne!(h.session("vpn_default")["enabled"], true);
    h.reconcile();
    h.repair();
    assert_eq!(*probes.lock().unwrap(), 1);
    *ready.lock().unwrap() = true;
    shift_clock(1001.0);
    h.repair();
    assert_eq!(h.act("inspect", json!({}))["tun_gso"], true);
    assert_eq!(h.session("vpn_default")["enabled"], true);
    assert_eq!(*probes.lock().unwrap(), 2);
    for _ in 0..10 {
        h.repair();
    }
    assert_eq!(*probes.lock().unwrap(), 2);
}

#[test]
fn vpn_offload_query_failure_falls_back_and_a_new_core_reprobes() {
    let mut h = vpn_with("sing_box", json!({}), Opts { vnet_header: true, ..Opts::default() });
    let supported = Arc::new(Mutex::new(true));
    let probes = Arc::new(Mutex::new(0));
    let (s, p) = (supported.clone(), probes.clone());
    h.fake().adapter("net.link.getOffloads", move |_| {
        *p.lock().unwrap() += 1;
        if !*s.lock().unwrap() {
            return Err("ethtool unavailable".into());
        }
        Ok(json!({"tx": true, "sg": true, "tso": true, "gso": true}))
    });
    assert_eq!(h.apply()["tun_gso"], true);
    *supported.lock().unwrap() = false;
    h.drop_link("vtundefault");
    h.repair();
    assert_eq!(h.session("vpn_default")["enabled"], false);
    assert_eq!(h.session("vpn_default")["data"]["interface_preparation"]["local_offloads"]["gso"], false);
    h.repair();
    assert_eq!(h.status("default")["phase"], "applied");
    assert_eq!(h.session("vpn_default")["data"]["interface_preparation"]["local_offloads"]["gso"], false);
    assert_eq!(*probes.lock().unwrap(), 2);
}

#[test]
fn vpn_refuses_a_tun_replaced_during_capability_probing() {
    let mut h = vpn_with("sing_box", json!({}), Opts { vnet_header: true, ..Opts::default() });
    let w = h.w.clone();
    h.fake().adapter("net.link.getOffloads", move |_| {
        let mut st = w.lock().unwrap();
        let link = st.links.iter_mut().find(|l| l["ifname"] == "vtundefault").unwrap();
        link["ifindex"] = json!(js::number(&link["ifindex"]) as u64 + 1);
        Ok(json!({"tx": true, "sg": true, "tso": true, "gso": true}))
    });
    assert!(h.apply_err().contains("TUN changed"));
    assert_ne!(h.session("vpn_default")["enabled"], true);
    assert_eq!(h.map_size(), 0);
}

#[test]
fn vpn_healthy_polling_uses_native_reads_without_subprocesses() {
    let mut h = vpn("mihomo");
    h.apply();
    let map = h.st().map.clone();
    let (calls, preparations, kv) = (h.calls().len(), h.services().len(), h.lease());
    for _ in 0..10 {
        h.repair();
    }
    assert_eq!(h.calls().len(), calls);
    assert_eq!(h.services().len(), preparations);
    assert_eq!(h.specs().len(), 1);
    assert_eq!(h.lease(), kv);
    assert_eq!(h.st().map, map);
}

#[test]
fn vpn_older_native_metadata_falls_back_to_bounded_ip_queries() {
    let mut h = vpn_with("mihomo", json!({}), Opts { legacy_net_info: true, ..Opts::default() });
    h.apply();
    let before = h.calls().len();
    h.repair();
    let reads = h.calls()[before..].to_vec();
    assert_eq!(reads.len(), 3);
    for r in &reads {
        let a = args_of(r);
        assert_eq!(&a[..5], ["-j", "-d", "link", "show", "dev"]);
    }
    h.link_mut("vtundefault", |l| l["ifalias"] = json!("foreign"));
    h.repair();
    assert_eq!(h.session("vpn_default")["enabled"], false);
    assert!(js::string(&h.status("default")["error"]).contains("unowned"));
}

#[test]
fn vpn_native_lookup_errors_suspend_forwarding_without_exec() {
    let mut h = vpn("mihomo");
    h.apply();
    let calls = h.calls().len();
    h.fake().adapter("net.link.get", |_| Err("netlink permanent failure".into()));
    h.repair();
    assert_eq!(h.calls().len(), calls);
    assert_eq!(h.session("vpn_default")["enabled"], false);
    assert_eq!(h.map_size(), 0);
    assert!(js::string(&h.status("default")["error"]).contains("netlink permanent failure"));
}

#[test]
fn vpn_native_tuntap_metadata_distinguishes_tun_from_a_foreign_tap() {
    for mode in ["tun", "tap"] {
        let mut h = vpn_with("tun", json!({"tun_interface": "tun0", "tun_alias": "external-owner"}), Opts::default());
        h.st().links.push(json!({"ifname": "tun0", "ifindex": 30, "ifalias": "external-owner", "flags": ["UP"], "mtu": 1420}));
        let w = h.w.clone();
        h.fake().adapter("net.link.get", move |args| {
            let st = w.lock().unwrap();
            let name = js::string(&args[0]);
            let Some(l) = st.links.iter().find(|l| l["ifname"] == json!(name)) else {
                return Err(format!("link not found: {name}"));
            };
            let tun = name == "tun0";
            Ok(json!({"name": name, "ifindex": l["ifindex"], "alias": js::or(&l["ifalias"], &json!("")), "kind": if tun { json!("tuntap") } else { l["linkinfo"]["info_kind"].clone() },
                "tun_mode": if tun { mode } else { "" }, "mtu": l.get("mtu"), "mac": l.get("address"), "up": js::array(&l["flags"]).contains(&json!("UP")), "peer_ifindex": l.get("link_index")}))
        });
        if mode == "tap" {
            assert!(h.apply_err().contains("unowned"));
            assert!(h.services().is_empty());
        } else {
            assert_eq!(h.apply()["phase"], "applied");
        }
    }
}

#[test]
fn vpn_polling_withdraws_a_tap_even_with_a_matching_owner_and_ifindex() {
    let mut h = vpn("mihomo");
    h.apply();
    h.link_mut("vtundefault", |l| l["linkinfo"]["info_kind"] = json!("tap"));
    h.repair();
    assert_eq!(h.session("vpn_default")["enabled"], false);
    assert_eq!(h.map_size(), 0);
}

#[test]
fn vpn_logs_are_explicit_and_bounded() {
    let mut h = vpn("mihomo");
    h.fake().adapter("process.logs", |_| Ok(json!({"stdout": "x".repeat(64000), "stderr": "y".repeat(64000), "truncated": false})));
    h.apply();
    let logs = h.act("core_logs", json!({}));
    assert_eq!(js::string(&logs["stdout"]).len(), 4000);
    assert_eq!(js::string(&logs["stderr"]).len(), 4000);
    assert_eq!(logs["truncated"], true);
}

#[test]
fn vpn_rejects_recursive_upstreams_executable_injection_and_foreign_tuns() {
    for extra in [json!({"upstream_interface": "veervpn1"}), json!({"core_path": "/bin/sh"}), json!({"addresses": ["10.0.0.1/8"]}), json!({"remote_routes": ["0.0.0.0/0"]})] {
        let mut h = vpn_with("mihomo", extra.clone(), Opts::default());
        h.apply_err();
        assert!(h.services().is_empty(), "{extra}");
        assert!(h.specs().is_empty());
    }
    let mut h = vpn("mihomo");
    h.st().links.push(json!({"ifname": "vtundefault", "ifindex": 19, "ifalias": "foreign", "linkinfo": {"info_kind": "tun"}}));
    assert!(h.apply_err().contains("ownership"));
    assert!(h.specs().is_empty());
}

#[test]
fn vpn_external_tun_checks_ownership_and_leaves_the_device_intact() {
    let mut h = vpn_with("tun", json!({"tun_interface": "tun0", "tun_alias": "external-owner"}), Opts::default());
    h.st().links.push(json!({"ifname": "tun0", "ifindex": 30, "ifalias": "external-owner", "linkinfo": {"info_kind": "tun"}, "flags": ["UP"], "mtu": 1420}));
    h.apply();
    assert!(h.specs().is_empty());
    h.act("teardown", json!({}));
    let names: Vec<String> = h.st().links.iter().map(|l| js::string(&l["ifname"])).collect();
    assert_eq!(names, ["tun0"]);
}

#[test]
fn vpn_errors_carry_stable_codes_and_never_leak_keys() {
    // No private key saved: say so before touching the network.
    let mut missing = fixture_with(profile(json!({})), Opts { missing_key: true, ..Opts::default() });
    assert!(missing.apply_err().starts_with("[private_key_missing] "));
    assert!(missing.calls().is_empty());
    assert!(missing.services().is_empty());

    // ip explains why WireGuard could not be created; anything key-shaped is redacted.
    let mut h = fixture(profile(json!({})));
    h.act("set_key", json!({"value": private()}));
    h.fail(|r| args_of(r).contains(&"wireguard".to_string()));
    h.st().fail_stderr = format!("Error: Unknown device type. {}\nsecond line", private());
    assert_eq!(h.apply_err(), "[wireguard_unavailable] Command failed: /usr/sbin/ip link (exit 2): Error: Unknown device type. [redacted]");
    let status = h.status("default");
    assert_eq!(status["error_code"], "wireguard_unavailable");
    assert!(!status.to_string().contains(&private()));
    assert_eq!(status["driver"], "wireguard");
    assert_eq!(status["interface"], "vwgdefault");
    assert_eq!(status["local_interface"], "veerwg1");
    assert_eq!(status["wan_id"], "wg_default");
    assert!(!js::string(&status["error"]).starts_with('['));

    // wg never shows stderr: it can quote keys.
    h.fail(|r| args_of(r).first().map(String::as_str) == Some("syncconf"));
    h.st().fail_stderr = String::new();
    assert_eq!(h.apply_err(), "[command_failed] Command failed: /usr/bin/wg syncconf (exit 2)");

    // A repeating failure keeps the time it first appeared.
    let first = h.status("default")["failed_at"].clone();
    assert!(js::number(&first) > 0.0);
    shift_clock(5000.0);
    h.repair();
    assert_eq!(h.status("default")["failed_at"], first);
}

#[test]
fn vpn_names_leftover_interfaces_it_refuses_to_adopt() {
    let mut h = fixture(profile(json!({})));
    h.act("set_key", json!({"value": private()}));
    h.st().links.push(json!({"ifname": "veerwg1", "ifindex": 77, "ifalias": "", "linkinfo": {"info_kind": "veth"}}));
    assert_eq!(h.apply_err(), "[ownership_missing] Recorded ownership is missing; leftover: veerwg1");
    assert!(h.services().is_empty());
}

#[test]
fn vpn_reports_an_exhausted_core_with_supervisor_facts_only() {
    let mut h = vpn("mihomo");
    let failed = json!({"id": "vpn_default", "state": "failed", "pid": 0, "starts": 4, "exit_code": 1, "started_at": 5000});
    let f = failed.clone();
    h.fake().adapter("process.start", move |_| Ok(f.clone()));
    let f = failed.clone();
    h.fake().adapter("process.status", move |_| Ok(f.clone()));
    assert_eq!(h.apply()["phase"], "starting");
    let status = h.status("default");
    assert_eq!(status["phase"], "failed");
    assert_eq!(status["error_code"], "core_exited");
    assert_eq!(status["process"], json!({"state": "failed", "pid": 0, "starts": 4, "exit_code": 1, "started_at": 5000}));
    assert!(!status.to_string().contains("sensitive-core-password"));
}

#[test]
fn vpn_inspect_reports_wg_peers_and_traffic_without_the_private_key() {
    let mut h = fixture(profile(json!({})));
    h.apply();
    h.link_mut("vwgdefault", |l| l["statistics"] = json!({"rx_bytes": 2048, "tx_bytes": 1024, "rx_packets": 4, "tx_packets": 2}));
    let view = h.act("inspect", json!({}));
    assert_eq!(view["phase"], "configured");
    assert_eq!(view["driver"], "wireguard");
    assert_eq!(view["boundary_gso"], true);
    assert_eq!(view["handoff_mode"], "segmented_veth");
    assert_eq!(view["dataplane"], "bpf");
    assert_eq!(view["traffic"], json!({"rx_bytes": 2048, "tx_bytes": 1024, "rx_packets": 4, "tx_packets": 2}));
    // Configured peers come first, kernel-only ones after.
    let keys: Vec<String> = js::array(&view["peers"]).iter().map(|p| js::string(&p["public_key"])).collect();
    assert_eq!(keys, [public(), "peer".to_string()]);
    assert_eq!(view["peers"][1], json!({"public_key": "peer", "endpoint": "123", "latest_handshake": 123, "rx_bytes": 123, "tx_bytes": 0}));
    assert!(!view.to_string().contains(&private()));
    assert!(!h.calls().iter().any(|r| args_of(r).contains(&"dump".to_string())));
}

// ------------------------------------------------------------ chains

fn chain_fixture() -> Env {
    let mihomo = json!({"proxies": [{"name": "n", "type": "ss", "server": "192.0.2.9", "port": 8388, "cipher": "aes-128-gcm", "password": "chain-secret"}], "rules": ["MATCH,n"]});
    let proxy = |driver: &str, slot: u64, upstream: &str| {
        json!({"data": {"driver": driver, "slot": slot, "mtu": 1420, "upstream_interface": upstream, "config_secret": format!("core_{driver}_{slot}")}, "enabled": true})
    };
    let mut h = vpn_with("sing_box", json!({}), Opts {
        inventory: vec![json!({"name": "eth0", "ifindex": 2, "kind": "ethernet", "up": true, "addresses": ["192.0.2.1/24"]})],
        resources: json!({"profiles": {"bmid": proxy("sing_box", 2, "veerwg1"), "aback": proxy("mihomo", 3, "veervpn2"), "zfar": proxy("sing_box", 4, "veervpn3")}}),
        secrets: vec![
            ("core_sing_box_2".into(), json!({"outbounds": [{"type": "direct", "tag": "direct"}]}).to_string()),
            ("core_mihomo_3".into(), mihomo.to_string()),
            ("core_sing_box_4".into(), json!({"outbounds": []}).to_string()),
        ],
        ..Opts::default()
    });
    h.set_profile("default", profile(json!({})), true);
    h
}

#[test]
fn vpn_chains_proxy_exits_behind_applied_exits() {
    let mut h = chain_fixture();
    let apply = |h: &mut Env, key: &str| h.try_act("apply", json!({"key": key}));
    // A front that is not applied yet: nothing starts.
    assert!(apply(&mut h, "bmid").unwrap_err().contains("[upstream_exit_down]"));
    assert!(h.proc("bmid").is_null());
    h.act("set_key", json!({"value": private()}));
    apply(&mut h, "default").unwrap();
    // Strict reverse-path filtering would drop replies on the front boundary: loosen that boundary only.
    h.st().sysctl = BTreeMap::from([("net.ipv4.conf.all.rp_filter".to_string(), 1.0)]);
    assert_eq!(apply(&mut h, "bmid").unwrap()["phase"], "applied");
    assert_eq!(h.st().sysctl.get("net.ipv4.conf.veerwg1.rp_filter"), Some(&2.0));
    assert_eq!(h.st().sysctl.get("net.ipv4.conf.all.rp_filter"), Some(&1.0));
    let sing = spec_config(h.specs().iter().find(|s| s["id"] == "vpn_bmid").unwrap());
    assert_eq!(sing["route"]["default_interface"], "veerwg1");
    let front_index = h.st().links.iter().find(|l| l["ifname"] == "veerwg1").unwrap()["ifindex"].clone();
    assert_eq!(h.kv("lease_bmid")["upstream_ifindex"], front_index);
    // Loose already (2) or off (0) stays as it is.
    h.st().sysctl = BTreeMap::from([("net.ipv4.conf.all.rp_filter".to_string(), 2.0)]);
    assert_eq!(apply(&mut h, "aback").unwrap()["phase"], "applied");
    assert!(h.st().sysctl.get("net.ipv4.conf.veervpn2.rp_filter").is_none());
    assert_eq!(spec_config(h.specs().iter().find(|s| s["id"] == "vpn_aback").unwrap())["interface-name"], "veervpn2");
    // Three exits in front are too many.
    assert!(apply(&mut h, "zfar").unwrap_err().contains("[upstream_chain_too_long]"));
    assert!(h.proc("zfar").is_null());
    // Applied exits are offered as upstreams after the physical interfaces.
    let items = js::array(&h.act("upstream_interfaces", json!({}))["items"]);
    let names: Vec<(String, String)> = items.iter().map(|i| (js::string(&i["name"]), js::string(js::or(&i["exit"], &json!(""))))).collect();
    assert_eq!(names, [("eth0", ""), ("veerwg1", "default"), ("veervpn2", "bmid"), ("veervpn3", "aback")].map(|(a, b)| (a.to_string(), b.to_string())));
    assert_eq!(items[1]["driver"], "wireguard");
    assert_eq!(items[1]["kind"], "vpn");
    // A front in use cannot be torn down or deleted; its dependents can.
    for id in ["teardown", "delete_profile"] {
        let err = h.act_err(id, json!({"key": "bmid"}));
        assert!(err.contains("[upstream_in_use]") && err.contains("aback"), "{err}");
    }
    let err = h.act_err("teardown", json!({}));
    assert!(err.contains("[upstream_in_use]") && err.contains("bmid"));
    assert_eq!(h.status("bmid")["phase"], "applied");
    // A loop through applied exits is refused before anything changes.
    let mut front = h.fake().data("profiles", "bmid");
    front["upstream_interface"] = json!("veervpn3");
    h.set_profile("bmid", front.clone(), true);
    assert!(apply(&mut h, "bmid").unwrap_err().contains("[upstream_cycle]"));
    assert_eq!(h.status("bmid")["phase"], "applied");
    front["upstream_interface"] = json!("veerwg1");
    h.set_profile("bmid", front, true);
    // Tunnels and pipelines of other exits stay refused.
    for upstream in ["vtunbmid", "veervpnp2", "vwgdefault"] {
        let mut far = h.fake().data("profiles", "zfar");
        far["upstream_interface"] = json!(upstream);
        h.set_profile("zfar", far, true);
        assert!(apply(&mut h, "zfar").unwrap_err().contains("[upstream_invalid]"), "{upstream}");
    }
    h.act("teardown", json!({"key": "aback"}));
    h.act("teardown", json!({"key": "bmid"}));
    h.act("teardown", json!({}));
    for key in ["lease_default", "lease_bmid", "lease_aback", "lease_zfar"] {
        assert!(h.kv(key).is_null());
    }
}

#[test]
fn vpn_recovers_chained_exits_front_first_and_rebinds_on_a_rebuilt_front() {
    let mut h = chain_fixture();
    h.act("set_key", json!({"value": private()}));
    for key in ["default", "bmid", "aback"] {
        h.act("apply", json!({"key": key}));
    }
    // A rebuilt front boundary (new ifindex): the same full check repairs the
    // front, then stops and restarts the exit chained to it.
    let before = h.proc("aback")["started_at"].clone();
    let starts = h.specs().iter().filter(|s| s["id"] == "vpn_aback").count();
    let old = h.st().links.iter().find(|l| l["ifname"] == "veervpn2").unwrap().clone();
    h.st().links.retain(|l| l["ifname"] != "veervpn2" && l["ifindex"] != old["link_index"]);
    h.repair();
    let rebuilt = h.st().links.iter().find(|l| l["ifname"] == "veervpn2").unwrap().clone();
    assert_ne!(rebuilt["ifindex"], old["ifindex"]);
    assert_eq!(h.kv("lease_aback")["upstream_ifindex"], rebuilt["ifindex"]);
    assert_eq!(h.specs().iter().filter(|s| s["id"] == "vpn_aback").count(), starts + 1);
    assert_ne!(h.proc("aback")["started_at"], before);
    assert_eq!(h.status("bmid")["phase"], "applied");
    assert_eq!(h.status("aback")["phase"], "applied");
    // A cold daemon start: every link and core is gone. One reconcile restores
    // the WG front, then the exits behind it, although "aback" sorts first.
    h.st().links.clear();
    h.st().procs.clear();
    h.reconcile();
    for key in ["default", "bmid", "aback"] {
        assert_eq!(h.status(key)["phase"], "applied", "{key}");
    }
    // While a front cannot recover, the exits behind it wait without starting their cores.
    h.st().links.clear();
    h.st().procs.clear();
    h.fail(|r| js::string(&r["command"]).ends_with("/wg"));
    let err = h.try_reconcile().unwrap_err();
    assert!(err.contains("bmid: [upstream_exit_down]") && err.contains("aback: [upstream_exit_down]"), "{err}");
    assert!(h.proc("bmid").is_null());
    assert!(h.proc("aback").is_null());
    assert_eq!(h.status("bmid")["error_code"], "upstream_exit_down");
    // Once the front is back, the next reconcile restores the whole chain.
    h.unfail();
    h.reconcile();
    for key in ["default", "bmid", "aback"] {
        assert_eq!(h.status(key)["phase"], "applied", "{key}");
    }
}

#[test]
fn vpn_status_records_the_applied_revision_and_proxy_node() {
    let mut h = vpn("mihomo");
    let source = format!("ss://{}@192.0.2.2:8388#first\ntrojan://another-secret@node.example:443?sni=example.com#second", b64url(b"aes-128-gcm:import-secret"));
    h.act("set_core_config", json!({"format": "links", "driver": "mihomo", "value": source, "selected": 1}));
    let revision = h.fake().record("profiles", "default").unwrap()["revision"].clone();
    h.apply();
    let status = h.status("default");
    assert_eq!(status["profile_revision"], revision);
    assert_eq!(status["node"], json!({"name": "second", "type": "trojan"}));
    assert_eq!(status["boundary_gso"], false);
    assert!(!status.to_string().contains("another-secret"));
    assert_eq!(h.act("inspect", json!({}))["node"], json!({"name": "second", "type": "trojan"}));
    // Recovery keeps the facts of the last explicit apply.
    h.reconcile();
    h.repair();
    assert_eq!(h.status("default")["node"], json!({"name": "second", "type": "trojan"}));
    h.act("teardown", json!({}));
    assert!(h.kv("applied_default").is_null());
}

#[test]
fn exits_are_checked_after_events_not_polled() {
    for driver in ["wireguard", "mihomo"] {
        let mut h = any_fixture(driver, Opts::default());
        h.apply();
        // The intervals left: the five-minute safety check and the five-second map check.
        let mut intervals: Vec<(String, Value)> = h
            .timers()
            .values()
            .filter(|t| t["kind"] == "interval" && t["name"] != "vpn_health")
            .map(|t| (js::string(&t["name"]), t["delay_ms"].clone()))
            .collect();
        intervals.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(intervals, vec![("tunnel_maps".to_string(), json!(5000)), ("tunnel_repair".to_string(), json!(300000))]);
        let fire = |h: &mut Env, name: &str| {
            {
                let mut st = h.st();
                st.wan_reads = 0;
                st.link_reads = 0;
                st.map_reads = 0;
            }
            h.h.fire_timer(name).unwrap();
            let st = h.st();
            (st.wan_reads, st.link_reads, st.map_reads)
        };
        // A link event arms one check of the tunnel, the WAN Core boundary and both map entries.
        h.fake().remove_timer("tunnel_event");
        h.h.emit("net.link", json!({"name": "eth9", "ifindex": 99, "operation": "update"})).unwrap();
        assert_eq!(h.timers()["tunnel_event"]["kind"], "timeout");
        // Later events, a resync among them, do not postpone it.
        let armed = h.timers()["tunnel_event"]["next_fire"].clone();
        h.h.emit("net.link", json!({"name": "eth9", "ifindex": 99, "operation": "update"})).unwrap();
        h.h.emit("net.link", json!({"operation": "resync", "reason": "queue_overflow"})).unwrap();
        assert_eq!(h.timers()["tunnel_event"]["next_fire"], armed);
        let (wan, links, maps) = fire(&mut h, "tunnel_event");
        assert!(wan > 0);
        assert_eq!(maps, 2);
        assert_eq!(links, 3, "{driver}");
        assert!(!h.timers().contains_key("tunnel_retry"), "a healthy exit arms no retry");
        // The map check reads the two adapter entries and nothing else, and puts back a lost one.
        assert_eq!(fire(&mut h, "tunnel_maps"), (0, 0, 2));
        let (lost_key, lost_value) = h.st().map.iter().next().map(|(k, v)| (k.clone(), v.clone())).unwrap();
        h.st().map.remove(&lost_key);
        fire(&mut h, "tunnel_maps");
        assert_eq!(h.st().map.get(&lost_key), Some(&lost_value), "the map check must restore a lost entry");
        assert_eq!(fire(&mut h, "tunnel_maps"), (0, 0, 2));
        // A managed core changing state arms the check; other processes do not.
        if driver == "mihomo" || h.timers().contains_key("tunnel_event") {
            h.fake().remove_timer("tunnel_event");
        }
        let delivered = h.h.emit("process.state", json!({"id": "other", "state": "exited"})).unwrap();
        assert!(!h.timers().contains_key("tunnel_event"));
        if delivered > 0 {
            h.h.emit("process.state", json!({"id": "vpn_default", "state": "backoff"})).unwrap();
            assert!(h.timers().contains_key("tunnel_event"));
            h.fake().remove_timer("tunnel_event");
        }
        // A changed tunnel is re-applied by the check that follows its event.
        let before = h.services().len();
        if driver == "wireguard" {
            h.link_mut("vwgdefault", |l| l["mtu"] = json!(1300));
        } else {
            h.proc_mut("default", |p| p["started_at"] = json!(js::number(&p["started_at"]) as u64 + 1));
        }
        h.h.emit("net.link", json!({"name": "vwgdefault", "operation": "update"})).unwrap();
        fire(&mut h, "tunnel_event");
        assert!(h.services().len() > before, "the check after an event must re-apply a changed tunnel");
    }
}

// ------------------------------------------------------------ share links

const ID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

fn samples() -> Vec<String> {
    let ss = format!("ss://{}@192.0.2.2:8388#{}", b64("aes-128-gcm:p@ss:word"), uri_encode("测试节点"));
    let vmess = json!({"v": "2", "ps": "VMess", "add": "node.example", "port": "443", "id": ID, "aid": "0", "scy": "auto", "net": "ws", "path": "/proxy",
        "host": "cdn.example", "tls": "tls", "sni": "cdn.example", "alpn": "h2,http/1.1", "fp": "chrome"});
    vec![
        ss,
        format!("vmess://{}", b64(&vmess.to_string())),
        format!("vless://{ID}@node.example:443?security=reality&sni=example.com&fp=chrome&pbk={}&sid=ab12&flow=xtls-rprx-vision#Reality", b64url(&[1; 32])),
        "trojan://p%40ss%3Aword@[2001:db8::1]:443?sni=example.com&type=grpc&serviceName=proxy".to_string(),
        "hy2://user%3Apass@node.example/?sni=example.com&obfs=salamander&obfs-password=obfs-secret".to_string(),
        "anytls://p%40ss%3Aword%2B%E5%AF%86%E7%A0%81@node.example/?sni=example.com&alpn=h2,http%2F1.1&fp=chrome#AnyTLS".to_string(),
    ]
}

fn parse(text: &str, driver: &str) -> Vec<Value> {
    share::parse(&json!(text), driver).unwrap_or_else(|err| panic!("{text}: {err}")).into_iter().map(Value::Object).collect()
}

fn create(driver: &str, source: &str, selected: Value, options: Value, via: Value) -> Value {
    share::create(driver, &json!(source), &selected, &options, &via).unwrap()
}

fn generate(driver: &str, source: &str) -> Value {
    share::generate(&create(driver, source, Value::Null, Value::Null, Value::Null)).unwrap()
}

const DRIVERS: [&str; 2] = ["mihomo", "sing_box"];

#[test]
fn share_parses_plain_url_safe_and_wrapped_lists_without_losing_text() {
    for driver in DRIVERS {
        let all = samples().join("\r\n");
        let nodes = parse(&all, driver);
        assert_eq!(nodes.len(), 6);
        assert_eq!(nodes[0]["name"], "测试节点");
        assert_eq!(nodes[0]["password"], "p@ss:word");
        assert_eq!(parse(&b64url(samples().join("\n").as_bytes()), driver), nodes);
        let wrapped: String = b64(&samples().join("\n")).as_bytes().chunks(60).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("\n");
        assert_eq!(parse(&wrapped, driver), nodes);
        assert_eq!(parse(&format!("ss://{}#legacy", b64("aes-128-gcm:secret@[2001:db8::2]:1234")), driver)[0]["server"], "2001:db8::2");
        assert_eq!(parse("ss://2022-blake3-aes-128-gcm:p%2Bss%3D@host.example:443", driver)[0]["password"], "p+ss=");
        assert_eq!(nodes[3]["password"], "p@ss:word");
        assert_eq!(nodes[4]["password"], "user:pass");
        assert_eq!(nodes[4]["port"], 443);
    }
}

#[test]
fn share_preserves_anytls_passwords_and_tls_verification() {
    for driver in DRIVERS {
        let node = parse(&samples()[5], driver).remove(0);
        assert_eq!(node["type"], "anytls");
        assert_eq!(node["password"], "p@ss:word+密码");
        assert_eq!(node["port"], 443);
        assert_eq!(node["tls"], json!({"server_name": "example.com", "insecure": false, "alpn": ["h2", "http/1.1"], "fingerprint": "chrome"}));
        let config = generate(driver, &samples()[5]);
        let p = &proxies(&config, driver)[0];
        assert_eq!(p["type"], "anytls");
        assert_eq!(p["password"], node["password"]);
        if driver == "mihomo" {
            assert_eq!(p["sni"], "example.com");
            assert_eq!(p["skip-cert-verify"], false);
            assert_eq!(p["client-fingerprint"], "chrome");
            assert_eq!(p["udp"], true);
        } else {
            assert_eq!(p["tls"]["enabled"], true);
            assert_eq!(p["tls"]["insecure"], false);
            assert_eq!(p["tls"]["utls"]["fingerprint"], "chrome");
        }
        for flag in ["insecure", "allowInsecure"] {
            let n = parse(&format!("anytls://private-password@[2001:db8::1]:8443?{flag}=1"), driver).remove(0);
            assert_eq!(n["server"], "2001:db8::1");
            assert_eq!(n["port"], 8443);
            assert_eq!(n["tls"]["insecure"], true);
        }
        assert_eq!(parse("anytls://secret@192.0.2.2?insecure=0", driver)[0]["tls"]["insecure"], false);
        assert_eq!(parse("anytls://YWJjZA==@node.example", driver)[0]["password"], "YWJjZA==");
    }
}

#[test]
fn share_accepts_explicit_anytls_defaults_without_changing_the_config() {
    for driver in DRIVERS {
        let plain = "anytls://private-password@node.example?sni=example.com&insecure=0&allowInsecure=0";
        let suffix = "&security=tls&type=tcp&headerType=none";
        for link in [format!("{plain}{suffix}"), format!("{plain}{}", suffix.replace("type=tcp", "type=raw"))] {
            assert_eq!(parse(&link, driver), parse(plain, driver));
            assert_eq!(generate(driver, &link), generate(driver, plain));
            assert_eq!(parse(&b64(&link), driver), parse(plain, driver));
        }
    }
}

#[test]
fn share_generates_complete_configs_and_keeps_wan_topology_under_plugin_control() {
    for driver in DRIVERS {
        for link in samples() {
            let v = create(driver, &link, json!(0), json!({}), Value::Null);
            let config = share::generate(&v).unwrap();
            let p = json!({"driver": driver, "slot": 2, "interface": "vtunhome", "mtu": 1420, "upstream_interface": "eth0"});
            let spec = drivers::build(&p, Some(&v.to_string())).unwrap();
            let text = js::string(&spec["config"]);
            let built: Value = serde_json::from_str(&text).unwrap();
            assert!(!text.contains("veer_proxy"));
            assert_eq!(js::array(&share::metadata(&v).unwrap()["nodes"]).len(), 1);
            if driver == "mihomo" {
                assert_eq!(js::array(&config["rules"]).last().unwrap(), "MATCH,veer-node");
                assert_eq!(built["interface-name"], "eth0");
                assert_eq!(built["tun"]["auto-route"], false);
                assert_eq!(built["mixed-port"], 0);
            } else {
                assert_eq!(config["route"]["final"], "veer-node");
                assert_eq!(config["route"]["default_domain_resolver"], "bootstrap");
                assert_eq!(js::array(&built["inbounds"]).len(), 1);
                assert_eq!(built["route"]["default_interface"], "eth0");
                assert_eq!(built["inbounds"][0]["auto_route"], false);
            }
        }
        let other = if driver == "mihomo" { "sing_box" } else { "mihomo" };
        let err = drivers::build(&json!({"driver": other}), Some(&create(driver, &samples()[0], Value::Null, Value::Null, Value::Null).to_string())).unwrap_err();
        assert!(err.to_string().contains("another core"));
    }
}

#[test]
fn share_selects_nodes_and_creates_direct_exceptions_and_tunneled_dns() {
    for driver in DRIVERS {
        let v = create(driver, &samples().join("\n"), json!(3), json!({"direct_cidrs": ["10.0.0.0/8", "fd00::/8"], "direct_domains": "*.example.com\ninternal.example", "dns_hijack": true}), Value::Null);
        let config = share::generate(&v).unwrap();
        let meta = share::metadata(&v).unwrap();
        assert_eq!(meta["selected"], 3);
        assert_eq!(meta["options"]["direct_domains"], json!(["example.com", "internal.example"]));
        assert_eq!(proxies(&config, driver)[0]["password"], "p@ss:word");
        let public = meta.to_string();
        for secret in ["p@ss:word", "obfs-secret", "node.example", "2001:db8::1", ID] {
            assert!(!public.contains(secret));
        }
        if driver == "mihomo" {
            assert_eq!(config["tun"]["dns-hijack"], json!(["any:53", "tcp://any:53"]));
            assert_eq!(config["dns"]["nameserver"], json!(["1.1.1.1#veer-node"]));
            assert!(js::array(&config["rules"]).contains(&json!("IP-CIDR6,fd00::/8,DIRECT,no-resolve")));
            assert_eq!(config["sniffer"]["enable"], true);
        } else {
            assert_eq!(config["dns"]["final"], "remote");
            assert_eq!(config["dns"]["servers"][1]["detour"], "veer-node");
            assert!(js::array(&config["route"]["rules"]).iter().any(|r| r["action"] == "hijack-dns"));
        }
    }
}

#[test]
fn share_chains_the_selected_node_through_front_nodes() {
    for driver in DRIVERS {
        let source = samples().join("\n");
        let m = driver == "mihomo";
        let key = if m { "dialer-proxy" } else { "detour" };
        // Selected AnyTLS, reached through SS (dialed first) and then VLESS REALITY.
        let v = create(driver, &source, json!(5), json!({"dns_hijack": true}), json!([0, 2]));
        let config = share::generate(&v).unwrap();
        let list = js::array(proxies(&config, driver));
        assert_eq!(v["via"], json!([0, 2]));
        assert_eq!(share::metadata(&v).unwrap()["via"], json!([0, 2]));
        let tag = |p: &Value| js::string(&p[if m { "name" } else { "tag" }]);
        let by_tag: BTreeMap<String, Value> = list.iter().map(|p| (tag(p), p.clone())).collect();
        assert_eq!(tag(&list[0]), "veer-node");
        assert_eq!(list[0]["type"], "anytls");
        assert_eq!(list[0][key], "veer-hop-2");
        assert_eq!(by_tag["veer-hop-1"]["type"], if m { "ss" } else { "shadowsocks" });
        assert!(by_tag["veer-hop-1"].get(key).is_none());
        assert_eq!(by_tag["veer-hop-2"]["type"], "vless");
        assert_eq!(by_tag["veer-hop-2"][key], "veer-hop-1");
        if m {
            assert_eq!(js::array(&config["rules"]).last().unwrap(), "MATCH,veer-node");
            assert_eq!(config["dns"]["nameserver"], json!(["1.1.1.1#veer-node"]));
        } else {
            assert_eq!(config["route"]["final"], "veer-node");
            assert_eq!(config["dns"]["servers"][1]["detour"], "veer-node");
            // A source address binds the sockets the core opens itself: direct and the first hop.
            let p = json!({"driver": driver, "slot": 1, "interface": "vtunhome", "mtu": 1420, "upstream_interface": "eth0", "upstream_ip": "192.0.2.9"});
            let built: Value = serde_json::from_str(&js::string(&drivers::build(&p, Some(&v.to_string())).unwrap()["config"])).unwrap();
            let mut bound: Vec<String> = js::array(&built["outbounds"]).iter().filter(|o| o["bind_interface"] == "eth0").map(|o| js::string(&o["tag"])).collect();
            bound.sort();
            assert_eq!(bound, ["direct", "veer-hop-1"]);
            assert!(js::array(&built["outbounds"]).iter().find(|o| o["tag"] == "veer-node").unwrap().get("inet4_bind_address").is_none());
        }
        let public = share::metadata(&v).unwrap().to_string();
        for secret in ["p@ss:word", "node.example", ID] {
            assert!(!public.contains(secret));
        }
        // One front node; an empty chain keeps the stored form of earlier versions.
        let one = share::generate(&create(driver, &source, json!(1), json!({}), json!(["3"]))).unwrap();
        assert_eq!(proxies(&one, driver)[0][key], "veer-hop-1");
        assert!(create(driver, &source, json!(1), json!({}), json!([])).get("via").is_none());
        assert_eq!(share::metadata(&create(driver, &source, json!(1), Value::Null, Value::Null)).unwrap()["via"], json!([]));
        assert_eq!(
            share::generate(&create(driver, &source, json!(1), json!({}), json!([]))).unwrap(),
            share::generate(&create(driver, &source, json!(1), Value::Null, Value::Null)).unwrap()
        );
    }
}

#[test]
fn share_rejects_bad_front_nodes() {
    for driver in DRIVERS {
        let source = samples().join("\n");
        let fails = |selected: u64, via: Value| share::create(driver, &json!(source), &json!(selected), &json!({}), &via).unwrap_err().to_string();
        for bad in [json!([6]), json!([-1]), json!([1.5]), json!(["x"]), json!([null])] {
            assert!(fails(0, bad.clone()).contains("前置节点"), "{bad}");
        }
        assert!(fails(2, json!([2])).contains("不能是所选节点"));
        assert!(fails(0, json!([1, 1])).contains("不能重复"));
        assert!(fails(0, json!([1, 2, 3])).contains("最多可设置 2 个"));
        for bad in [json!([2]), json!([1, 1]), json!([1, 2, 3])] {
            let err = fails(2, bad);
            assert!(!err.contains("p@ss:word") && !err.contains(ID));
        }
        // A stored chain is checked again against its links.
        let stored = json!({"veer_proxy": 1, "driver": driver, "links": samples()[0], "selected": 0, "via": [1], "options": {}});
        assert!(share::metadata(&stored).unwrap_err().to_string().contains("前置节点"));
    }
}

#[test]
fn share_rejects_incomplete_or_unsupported_links_without_credentials_in_errors() {
    for driver in DRIVERS {
        let ss = samples()[0].clone();
        let vmess = json!({"add": "host", "port": 443, "id": ID, "aid": "10"});
        let mut invalid = vec![
            String::new(), "!!!!".into(), "Zg===".into(), "/w==".into(), "Zh==".into(), "abc".into(), "x".repeat(256 * 1024 + 1),
            vec![ss.clone(); 129].join("\n"), "https://subscription.example/secret".into(),
            format!("vless://{ID}@node.example:443?type=kcp"), format!("vless://{ID}@node.example:443?security=tls&security=none"),
            format!("vless://{ID}@node.example:0"), format!("vless://{ID}@node.example:70000"), format!("vless://{ID}@bad..domain:443"),
            format!("vless://{ID}@[:::]:443"), format!("vless://{ID}@host:443?security=reality&pbk=bad"), format!("vless://{ID}@host:443?flow=xtls-rprx-vision"),
            "trojan://private-password@host:443?security=none".into(), "trojan://private-password@host:443?security=tls&sni=%ZZ".into(),
            format!("ss://{}@host:443?plugin=unavailable", b64("aes-128-gcm:private-password")),
            format!("vmess://{}", b64(&vmess.to_string())), "hy2://private-password@host:443?pinSHA256=unknown".into(),
        ];
        for tail in ["@host", "private-password@host:0", "private-password@host?insecure=perhaps", "private-password@host?security=none",
            "private-password@host?security=reality", "private-password@host?pbk=unknown", "private-password@host?type=ws",
            "private-password@host?headerType=http", "private-password@host?sni=bad/host"]
        {
            invalid.push(format!("anytls://{tail}"));
        }
        for value in &invalid {
            let err = share::parse(&json!(value), driver).map(|_| ()).expect_err(value).to_string();
            assert!(!err.contains("private-password") && !err.contains(ID), "{value}: {err}");
        }
        for o in [json!({"direct_cidrs": ["10.0.0.0/999"]}), json!({"direct_cidrs": ["1.2.3.999/32"]}), json!({"direct_domains": "example.com\ninvalid/host"}),
            json!({"proxy_dns": "host.example"}), json!({"dns_hijack": "perhaps"}), json!({"__unknown": true})]
        {
            assert!(share::options(&o).is_err(), "{o}");
        }
        for selected in [json!(-1), json!(10), json!(1.5), json!("oops")] {
            assert!(share::create(driver, &json!(ss), &selected, &Value::Null, &Value::Null).is_err(), "{selected}");
        }
        let names = vec![format!("{}#{}", ss.split('#').next().unwrap(), "<".repeat(128)); 128].join("\n");
        assert!(share::create(driver, &json!(names), &Value::Null, &Value::Null, &Value::Null).unwrap_err().to_string().contains("摘要过大"));
    }
}

/// The privileged VPN gate supplies pinned core executables
/// (VEER_TEST_MIHOMO, VEER_TEST_SING_BOX); their native parsers check the
/// generated protocol, transport, DNS and routing fields.
#[test]
fn generated_configurations_pass_the_real_core_check() {
    for (driver, var) in [("mihomo", "VEER_TEST_MIHOMO"), ("sing_box", "VEER_TEST_SING_BOX")] {
        let Ok(binary) = std::env::var(var) else {
            continue;
        };
        let dir = std::env::temp_dir().join(format!("veer-import-config-{}-{driver}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut links: Vec<String> = samples();
        for ty in ["tcp", "ws", "grpc", "h2"] {
            for protocol in ["vless", "vmess"] {
                let service = if ty == "grpc" { "&serviceName=proxy" } else { "" };
                links.push(format!("{protocol}://{ID}@node.example:443?security=tls&type={ty}{service}&sni=example.com"));
            }
        }
        // Every protocol alone, plus chains where each kind of node is reached through two others.
        let mut cases: Vec<(String, u64, Value)> = links.iter().map(|l| (l.clone(), 0, Value::Null)).collect();
        let n = samples().len() as u64;
        for i in 0..n {
            cases.push((samples().join("\n"), i, json!([(i + 1) % n, (i + 2) % n])));
        }
        for (link, selected, via) in cases {
            for opts in [json!({}), json!({"dns_hijack": true, "direct_domains": ["example.com"], "direct_cidrs": ["10.0.0.0/8", "fd00::/8"]})] {
                let v = create(driver, &link, json!(selected), opts, via.clone());
                let p = json!({"driver": driver, "slot": 1, "interface": "vtuncheck", "mtu": 1420, "upstream_interface": "lo"});
                let config = js::string(&drivers::build(&p, Some(&v.to_string())).unwrap()["config"]);
                let file = dir.join("config.json");
                std::fs::write(&file, config).unwrap();
                let args: Vec<String> = if driver == "mihomo" {
                    vec!["-t".into(), "-d".into(), dir.display().to_string(), "-f".into(), file.display().to_string()]
                } else {
                    vec!["check".into(), "-c".into(), file.display().to_string()]
                };
                let out = std::process::Command::new(&binary).args(&args).current_dir(&dir).output().unwrap();
                assert!(out.status.success(), "{driver} {link}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
