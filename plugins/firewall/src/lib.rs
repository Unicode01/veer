//! Firewall: a source filter for the interfaces it is bound to, attached
//! through the Veer XDP dispatcher ahead of the TC dataplane. Policies match
//! TCP/UDP ports, ICMP types, IP protocols or everything else (catch-all);
//! global settings add blocklist sets, a security baseline and connection
//! tracking, whose tc_egress program records the connections this side
//! opens so their replies pass.
//!
//! Policies, sets and settings are drafts until "apply": it compiles them
//! into the generation of the maps the packets do not read, switches fw_cfg
//! to it, and starts a confirmation deadline. The page confirms once it can
//! still reach the API under the new rules; if it cannot, the deadline
//! restores the last confirmed rule set.
//!
//! Every map is declared preserve, so a Veer hot restart hands them to the
//! successor and filtering goes on without a gap. Snapshots of the applied
//! and confirmed rule sets rebuild the maps when they start empty: a cold
//! start, an older host, or a map layout that changed.
//!
//! Policies with a syn_limit also limit new TCP connections per source
//! prefix and ban sources over it (fw_rate, fw_ban; the bans/unban actions
//! list and lift them). Sets take elements at runtime too (set_add, or a
//! policy's add_to_set), which outlive applies. Drops are sampled into the
//! fw_events ring; this instance keeps the latest ones in memory for the
//! events action.

#![recursion_limit = "256"]

pub mod compile;

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use compile::{Cidr, Compiled, Policy, Settings};
use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, export_plugin, json, Error, Host, Map, Message, Outcome, Plugin, Result, Value};

const OBJECT: &str = "firewall";
const HOOK: &str = "wan-filter";
const CONFIRM_TIMER: &str = "confirm_deadline";
const SYNC_TIMER: &str = "sync_retry";
const PRUNE_TIMER: &str = "set_prune";
const STATE_KEY: &str = "state";
const GEN_ARRAYS_KEY: &str = "gen_arrays";
const IFACES_KEY: &str = "ifaces";
const DYN_KEY: &str = "dyn_sets";
const DEFAULT_CONFIRM_SECONDS: f64 = 120.0;
const SYNC_RETRY_MS: u64 = 3000;
const SYNC_RETRY_LIMIT: i64 = 20;
const PRUNE_MS: u64 = 60000;
const TX_LIMIT: usize = 256;
const CFG_HAS_L3: u64 = 1;
const CFG_ACTIVE: u64 = 2;
const CFG_LOADED: u64 = 4; // written by this plugin only, tells fresh maps apart
const IFACE_L3: u64 = 1;
const COUNTER_NAMES: [&str; 3] = ["pass", "drop", "trusted"];
const EVASIVE_COUNTER: usize = 3;
const DEFAULT_LOG_PER_SECOND: f64 = 10.0;
const LOG_KEEP: usize = 500;
const MAX_API_ELEMENTS: usize = 1024; // set_add elements kept in KV across cold starts
const MAX_SET_TIMEOUT: f64 = 30.0 * 86400.0;
const BOGON_MODES: [&str; 3] = ["off", "reserved", "all"];
const URPF_MODES: [&str; 3] = ["off", "loose", "strict"];
const TC_EGRESS_FEATURE: &str = "dataplane.xdp_tc_egress.v1";

fn array_zero(map: &str) -> String {
    match map {
        "fw_port_bits" => "0000000000000000".to_string(),
        "fw_class" | "fw_policy" => "00000000".to_string(),
        "fw_limit" => compile::limit_value_zero(),
        "fw_pext" => compile::pext_value_zero(),
        _ => compile::gcfg_value_zero(),
    }
}

fn array_size(map: &str) -> u32 {
    match map {
        "fw_port_bits" => 2 * compile::PORT_WORDS_PER_GEN,
        "fw_class" => 2 * compile::CLASSES_PER_GEN,
        "fw_gcfg" => 2,
        _ => 2 * compile::POLICIES_PER_GEN,
    }
}

pub struct Firewall {
    /// Whether the host runs the tc_egress program connection tracking
    /// needs; learned on the first message (host calls wait for handle()).
    tc_egress: Option<bool>,
    /// The latest sampled drops, oldest first.
    drop_log: VecDeque<Value>,
}

impl Plugin for Firewall {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(Firewall { tc_egress: None, drop_log: VecDeque::new() })
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        if self.tc_egress.is_none() {
            let info = host.call("plugin.host", json!([])).unwrap_or(Value::Null);
            self.tc_egress = Some(js::array(g(&info, "available_features")).iter().any(|feature| feature.as_str() == Some(TC_EGRESS_FEATURE)));
        }
        let fw = Fw { host, tc_egress: self.tc_egress.unwrap_or(false) };
        let ctx = &msg.ctx;
        match msg.handler.as_str() {
            "onReconcile" => {
                fw.sync()?;
                Ok(Outcome::Done)
            }
            "onTimer" => {
                match js::text(g(g(ctx, "timer"), "name")).as_str() {
                    CONFIRM_TIMER => fw.rollback("deadline")?,
                    SYNC_TIMER => fw.sync()?,
                    PRUNE_TIMER => {
                        fw.prune()?;
                    }
                    _ => {}
                }
                Ok(Outcome::Done)
            }
            "onDropEvents" => {
                for record in js::array(g(g(ctx, "payload"), "records")) {
                    if let Some(event) = compile::decode_event(&js::string(g(&record, "data"))) {
                        self.drop_log.push_back(event);
                    }
                }
                while self.drop_log.len() > LOG_KEEP {
                    self.drop_log.pop_front();
                }
                Ok(Outcome::Done)
            }
            "onAction" => {
                let payload = js::or(g(ctx, "payload"), &json!({})).clone();
                let id = js::text(g(g(ctx, "action"), "id"));
                let result = match id.as_str() {
                    "apply" => {
                        fw.apply(&payload)?;
                        Value::Null
                    }
                    "check" => {
                        let result = fw.check()?;
                        json!({"errors": result.errors, "warnings": result.warnings, "token": result.token})
                    }
                    "confirm" => {
                        fw.confirm()?;
                        Value::Null
                    }
                    "rollback" => {
                        fw.rollback("manual")?;
                        Value::Null
                    }
                    "status" => fw.status()?,
                    "interfaces" => fw.interfaces()?,
                    "bans" => fw.bans(&payload)?,
                    "unban" => fw.unban(&payload)?,
                    "events" => fw.events(&payload, &self.drop_log)?,
                    "set_add" => fw.set_add(&payload)?,
                    "set_del" => fw.set_del(&payload)?,
                    "set_flush" => fw.set_flush(&payload)?,
                    "set_list" => fw.set_list(&payload)?,
                    other => bail!("unknown action: {other}"),
                };
                Ok(if result.is_null() { Outcome::Done } else { Outcome::Value(result) })
            }
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(Firewall, "firewall");

/// A validated, compiled-ready rule set.
struct Ruleset {
    policies: Vec<Policy>,
    settings: Settings,
    sets: Vec<compile::Set>,
    slots: BTreeMap<String, u32>,
    fresh: Vec<u32>,
    set_ids: BTreeMap<String, u32>,
}

struct CheckResult {
    snapshot: Value,
    errors: Vec<String>,
    warnings: Vec<Value>,
    token: String,
}

/// Every problem a snapshot has, joined like the script's error.
struct RulesetErrors(Vec<String>);

impl From<RulesetErrors> for Error {
    fn from(errors: RulesetErrors) -> Self {
        Error::msg(errors.0.join("；"))
    }
}

struct Fw<'a> {
    host: &'a Host,
    tc_egress: bool,
}

fn now() -> f64 {
    js::now_ms() as f64
}

fn u32_map(value: &Value) -> BTreeMap<String, u32> {
    value
        .as_object()
        .map(|map| map.iter().filter_map(|(key, value)| value.as_f64().filter(|v| *v >= 0.0).map(|v| (key.clone(), v as u32))).collect())
        .unwrap_or_default()
}

fn u32_map_value(map: &BTreeMap<String, u32>) -> Value {
    Value::Object(map.iter().map(|(key, value)| (key.clone(), json!(value))).collect())
}

fn page_limit(value: &Value, fallback: u64, max: u64) -> u64 {
    let n = js::number(value);
    if n >= 1.0 && n <= max as f64 && n.floor() == n {
        n as u64
    } else {
        fallback
    }
}

fn is_l3_mac(mac: &str) -> bool {
    mac.is_empty() || mac == "00:00:00:00:00:00"
}

fn iface_name_valid(name: &str) -> bool {
    // ^[A-Za-z0-9_.:@-]{1,15}$
    !name.is_empty() && name.len() <= 15 && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'-'))
}

/// JSON with sorted keys: the host stores records canonically.
fn canonical_json(value: &Value) -> String {
    match value {
        Value::Array(items) => format!("[{}]", items.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter().map(|key| format!("{}:{}", serde_json_string(key), canonical_json(&map[*key]))).collect::<Vec<_>>().join(",")
            )
        }
        other => js::stable_json(other),
    }
}

fn serde_json_string(text: &str) -> String {
    Value::String(text.to_string()).to_string()
}

fn same_json(a: &Value, b: &Value) -> bool {
    canonical_json(a) == canonical_json(b)
}

fn normalize_baseline(data: &Value) -> Result<compile::Baseline> {
    // A missing field is off; anything but one of the mode strings is wrong.
    let mode = |field: &str, modes: &[&str]| -> Option<String> {
        match data.get(field) {
            None => Some("off".to_string()),
            Some(Value::String(text)) if modes.contains(&text.as_str()) => Some(text.clone()),
            Some(_) => None,
        }
    };
    let Some(bogon) = mode("bogon_sources", &BOGON_MODES) else {
        bail!("bogon_sources 必须是 off、reserved 或 all");
    };
    let Some(urpf) = mode("urpf", &URPF_MODES) else {
        bail!("urpf 必须是 off、loose 或 strict");
    };
    Ok(compile::Baseline {
        bogon_sources: bogon,
        invalid_tcp_flags: js::is_true(g(data, "invalid_tcp_flags")),
        drop_fragments: js::is_true(g(data, "drop_fragments")),
        urpf,
    })
}

fn normalize_settings(data: &Value) -> Result<Settings> {
    let mut interfaces: Vec<String> = Vec::new();
    for name in js::array(js::or(g(data, "interfaces"), &json!([]))) {
        let name = js::string(&name).trim().to_string();
        if !iface_name_valid(&name) {
            bail!("接口名无效: {name}");
        }
        if !interfaces.contains(&name) {
            interfaces.push(name);
        }
    }
    let mut trusted = Vec::new();
    for raw in js::array(js::or(g(data, "trusted_sources"), &json!([]))) {
        trusted.push(compile::parse_cidr(&raw)?);
    }
    let seconds = match data.get("confirm_timeout_seconds") {
        None => DEFAULT_CONFIRM_SECONDS,
        Some(value) => js::number(value),
    };
    if !(seconds >= 30.0 && seconds <= 600.0) {
        bail!("确认超时必须在 30 到 600 秒之间");
    }
    let log_rate = match data.get("log_per_second") {
        None => DEFAULT_LOG_PER_SECOND,
        Some(value) => js::number(value),
    };
    if !(log_rate >= 0.0 && log_rate <= 1000.0) || log_rate.floor() != log_rate {
        bail!("丢包日志速率必须是 0 到 1000 之间的整数");
    }
    let mut blocklists: Vec<String> = Vec::new();
    for name in js::array(js::or(g(data, "blocklists"), &json!([]))) {
        let name = js::string(&name);
        if !compile::set_name_valid(&name) {
            bail!("黑名单集合名无效: {name}");
        }
        if !blocklists.contains(&name) {
            blocklists.push(name);
        }
    }
    if blocklists.len() > compile::BLOCK_SETS {
        bail!("黑名单集合最多 {} 个", compile::BLOCK_SETS);
    }
    Ok(Settings {
        interfaces,
        trusted,
        confirm_seconds: seconds.floor() as i64,
        log_per_second: log_rate as i64,
        connection_tracking: js::is_true(g(data, "connection_tracking")),
        blocklists,
        baseline: normalize_baseline(js::or(g(data, "baseline"), &json!({})))?,
    })
}

/// fw_log_cfg: a GCRA allowing log_per_second events per CPU, in bursts of as many.
fn log_config_hex(log_per_second: i64) -> String {
    if log_per_second == 0 {
        return compile::u32le(0).repeat(4);
    }
    let interval = (1e9 / log_per_second as f64).floor() as u64;
    let tolerance = interval * (log_per_second as u64 - 1);
    compile::u32le(interval) + &compile::u32le(0) + &compile::u32le(tolerance) + &compile::u32le(0)
}

fn records_snapshot(records: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = records
        .iter()
        .map(|record| json!({"key": record["key"], "enabled": !js::is_false(g(record, "enabled")), "data": record.get("data").cloned().unwrap_or(Value::Null)}))
        .collect();
    out.sort_by(|a, b| js::string(&a["key"]).cmp(&js::string(&b["key"])));
    out
}

/// Snapshot form of a rule set: the policy and set records as stored, so
/// compiling a snapshot again gives the same maps.
fn snapshot_of(records: &[Value], settings: &Value, sets: &[Value]) -> Value {
    json!({
        "policies": records_snapshot(records),
        "settings": if truthy(settings) { settings.clone() } else { json!({}) },
        "sets": records_snapshot(sets),
    })
}

impl<'a> Fw<'a> {
    fn ebpf(&self, method: &str, args: Value) -> Result<Value> {
        self.host.call(&format!("ebpf.{method}"), args)
    }

    fn load_state(&self) -> Result<Value> {
        let record = self.host.kv_get(STATE_KEY)?;
        let mut st = record.and_then(|record| record.get("data").cloned()).filter(Value::is_object).unwrap_or(json!({}));
        let generation = g(&st, "generation");
        if !(js::strict_eq(generation, &json!(0)) || js::strict_eq(generation, &json!(1))) {
            st["generation"] = json!(0);
        }
        for field in ["slots", "set_ids", "baselines"] {
            if !g(&st, field).is_object() {
                st[field] = json!({});
            }
        }
        Ok(st)
    }

    fn save_state(&self, st: &Value) -> Result<()> {
        self.host.kv_set(STATE_KEY, st)
    }

    fn kv_data(&self, key: &str, fallback: Value) -> Result<Value> {
        Ok(match self.host.kv_get(key)? {
            Some(record) => match record.get("data") {
                Some(data) if !data.is_null() => data.clone(),
                _ => fallback,
            },
            None => fallback,
        })
    }

    fn list_all(&self, resource: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut offset = 0;
        loop {
            let page = js::array(&self.host.call("resources.list", json!([resource, {"limit": 256, "offset": offset}]))?);
            let len = page.len();
            out.extend(page);
            if len < 256 {
                return Ok(out);
            }
            offset += 256;
        }
    }

    fn settings_draft(&self) -> Result<Value> {
        self.host.resources_data("settings", "default")
    }

    fn draft_snapshot(&self) -> Result<Value> {
        Ok(snapshot_of(&self.list_all("policies")?, &self.settings_draft()?, &self.list_all("sets")?))
    }

    fn read_snapshot(&self, name: &str) -> Result<Option<Value>> {
        let Some(record) = self.host.resources_get("snapshots", name)? else {
            return Ok(None);
        };
        let mut data = record.get("data").cloned().unwrap_or(Value::Null);
        if !truthy(&data) || !g(&data, "policies").is_array() {
            return Ok(None);
        }
        // Snapshots of 1.0 have no sets.
        if !g(&data, "sets").is_array() {
            data["sets"] = json!([]);
        }
        Ok(Some(data))
    }

    fn write_snapshot(&self, name: &str, snapshot: &Value) -> Result<()> {
        self.host.call("resources.set", json!(["snapshots", name, snapshot, true, false]))?;
        Ok(())
    }

    /// Validates a snapshot and compiles it; fails with every problem found.
    fn build_ruleset(&self, snapshot: &Value, slots: &BTreeMap<String, u32>, set_ids: &BTreeMap<String, u32>) -> std::result::Result<Ruleset, RulesetErrors> {
        let mut errors = Vec::new();
        let mut sets = Vec::new();
        for set in js::array(g(snapshot, "sets")) {
            if !truthy(g(&set, "enabled")) {
                continue;
            }
            match compile::normalize_set(&js::string(g(&set, "key")), g(&set, "data")) {
                Ok(set) => sets.push(set),
                Err(err) => errors.push(err.to_string()),
            }
        }
        let set_keys: Vec<String> = sets.iter().map(|set| set.key.clone()).collect();
        let mut policies = Vec::new();
        for policy in js::array(g(snapshot, "policies")) {
            if !truthy(g(&policy, "enabled")) {
                continue;
            }
            match compile::normalize_policy(&js::string(g(&policy, "key")), g(&policy, "data"), Some(&set_keys)) {
                Ok(policy) => policies.push(policy),
                Err(err) => errors.push(err.to_string()),
            }
        }
        let settings = match normalize_settings(js::or(g(snapshot, "settings"), &json!({}))) {
            Ok(settings) => Some(settings),
            Err(err) => {
                errors.push(err.to_string());
                None
            }
        };
        if let Some(settings) = &settings {
            for name in &settings.blocklists {
                if !set_keys.contains(name) {
                    errors.push(format!("黑名单引用的集合不存在: {name}"));
                }
            }
            if settings.connection_tracking && !self.tc_egress {
                errors.push(format!("这个 Veer 不支持连接跟踪（缺少 {TC_EGRESS_FEATURE}），请升级 Veer 或关闭连接跟踪"));
            }
        }
        errors.extend(compile::find_conflicts(&policies));
        if !errors.is_empty() {
            return Err(RulesetErrors(errors));
        }
        let settings = settings.unwrap();
        let keys: Vec<String> = policies.iter().map(|policy| policy.key.clone()).collect();
        let assigned = compile::assign_slots(&keys, slots).map_err(|err| RulesetErrors(vec![err.to_string()]))?;
        for policy in &mut policies {
            policy.slot = assigned.ids[&policy.key];
        }
        let ids = compile::assign_set_ids(&set_keys, set_ids).map_err(|err| RulesetErrors(vec![err.to_string()]))?;
        for set in &mut sets {
            set.id = ids.ids[&set.key];
        }
        Ok(Ruleset { policies, settings, sets, slots: assigned.ids, fresh: assigned.fresh, set_ids: ids.ids })
    }

    fn transact(&self, ops: &[Value]) -> Result<()> {
        for chunk in ops.chunks(TX_LIMIT) {
            self.ebpf("mapTransaction", json!([{"operations": chunk}]))?;
        }
        Ok(())
    }

    /// Every entry of a map; scans are best-effort snapshots.
    fn scan_all(&self, map: &str, mut visit: impl FnMut(&Value)) -> Result<()> {
        let mut cursor = String::new();
        for _ in 0..4096 {
            let mut options = json!({"limit": 256});
            if !cursor.is_empty() {
                options["cursor"] = json!(cursor);
            }
            let page = self.ebpf("mapScan", json!([OBJECT, map, options]))?;
            let entries = js::array(g(&page, "entries"));
            for entry in &entries {
                visit(entry);
            }
            if truthy(g(&page, "done")) || entries.is_empty() {
                return Ok(());
            }
            cursor = js::string(g(&page, "cursor"));
        }
        Ok(())
    }

    fn scan_keys(&self, map: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        self.scan_all(map, |entry| keys.push(js::string(g(entry, "key"))))?;
        Ok(keys)
    }

    /// Writes a compiled rule set into one generation, which packets do not read.
    fn write_generation(&self, generation: u32, compiled: &Compiled) -> Result<()> {
        let mut ops = Vec::new();
        for map in compile::LPM_MAPS {
            for key in self.scan_keys(map)? {
                if compile::key_generation(&key) == generation {
                    ops.push(json!({"op": "delete", "object": OBJECT, "map": map, "key": key}));
                }
            }
        }
        self.transact(&ops)?;

        let mut ops = Vec::new();
        for map in compile::LPM_MAPS {
            for entry in &compiled.lpm[map] {
                ops.push(json!({"op": "put", "object": OBJECT, "map": map, "key": entry.key, "value": entry.value}));
            }
        }
        let mut tracked = self.kv_data(GEN_ARRAYS_KEY, json!({}))?;
        if !tracked.is_object() {
            tracked = json!({});
        }
        let previous = tracked.get(generation.to_string()).cloned().unwrap_or(Value::Null);
        let mut written = Map::new();
        for map in compile::ARRAY_MAPS {
            let desired = &compiled.arrays[map];
            let stale: Vec<u32> = match previous.get(map) {
                Some(Value::Array(items)) if truthy(&previous) => items.iter().filter_map(|v| v.as_f64()).map(|v| v as u32).collect(),
                _ => {
                    // Unknown earlier content: clear the whole generation.
                    let per = array_size(map) / 2;
                    (generation * per..(generation + 1) * per).collect()
                }
            };
            for index in stale {
                if !desired.contains_key(&index) {
                    ops.push(json!({"op": "put", "object": OBJECT, "map": map, "key": compile::u32le(index as u64), "value": array_zero(map)}));
                }
            }
            written.insert(map.to_string(), json!(desired.keys().collect::<Vec<_>>()));
            for (index, value) in desired {
                ops.push(json!({"op": "put", "object": OBJECT, "map": map, "key": compile::u32le(*index as u64), "value": value}));
            }
        }
        self.transact(&ops)?;
        tracked[generation.to_string()] = Value::Object(written);
        self.host.kv_set(GEN_ARRAYS_KEY, &tracked)
    }

    /// Marks the bound interfaces that carry no Ethernet header; true if any.
    fn sync_interfaces(&self, names: &[String]) -> Result<bool> {
        let mut l3: Vec<u64> = Vec::new();
        for name in names {
            let Ok(link) = self.host.call("net.link.get", json!([name])) else {
                continue;
            };
            let ifindex = js::number(g(&link, "ifindex"));
            if !truthy(&link) || !(ifindex > 0.0) {
                continue;
            }
            if is_l3_mac(&js::string(js::or(g(&link, "mac"), &json!("")))) {
                l3.push(ifindex as u64);
            }
        }
        let previous: Vec<u64> = js::array(&self.kv_data(IFACES_KEY, json!([]))?).iter().filter_map(Value::as_u64).collect();
        let mut ops = Vec::new();
        for ifindex in &previous {
            if !l3.contains(ifindex) {
                ops.push(json!({"op": "delete", "object": OBJECT, "map": "fw_ifaces", "key": compile::u32le(*ifindex)}));
            }
        }
        for ifindex in &l3 {
            ops.push(json!({"op": "put", "object": OBJECT, "map": "fw_ifaces", "key": compile::u32le(*ifindex), "value": compile::u32le(IFACE_L3)}));
        }
        if !ops.is_empty() {
            self.transact(&ops)?;
        }
        self.host.kv_set(IFACES_KEY, &json!(l3))?;
        Ok(!l3.is_empty())
    }

    /// Points the XDP hook at the interfaces; only a change touches the
    /// record. tc_egress turns the egress program on with connection tracking.
    fn bind_interfaces(&self, names: &[String], tracking: bool) -> Result<bool> {
        let current = self.host.resources_get("hook_bindings", HOOK)?;
        let data = json!({"hook_id": HOOK, "interfaces": names, "tc_egress": tracking && self.tc_egress});
        let enabled = !names.is_empty();
        if let Some(current) = &current {
            if js::strict_eq(g(current, "enabled"), &json!(enabled)) && same_json(g(current, "data"), &data) {
                return Ok(false);
            }
        }
        self.host.call("resources.set", json!(["hook_bindings", HOOK, data, enabled, true]))?;
        Ok(true)
    }

    fn read_config(&self) -> Result<(u64, u64)> {
        let hex = js::string(&self.ebpf("mapGet", json!([OBJECT, "fw_cfg", compile::u32le(0)]))?);
        if hex.len() < 16 {
            return Ok((0, 0));
        }
        Ok((compile::hex_u32le(&hex, 0), compile::hex_u32le(&hex, 8)))
    }

    /// fw_sets holds both what apply writes (static elements, the bogon
    /// prefixes) and what arrives at runtime (set_add, add_to_set); it is not
    /// per generation. Before the flip, the static elements of the new rule
    /// set go in, and set_add elements that a cold start lost come back from
    /// KV. Returns the keys to remove after the flip.
    fn sync_sets_before(&self, ruleset: &Ruleset) -> Result<Vec<String>> {
        let desired = compile::compile_sets(&ruleset.sets, &ruleset.settings.baseline)?;
        let mut known: HashSet<u64> = ruleset.sets.iter().map(|set| set.id as u64).collect();
        known.insert(compile::SET_BOGON as u64);
        let mut present = HashSet::new();
        let mut stale = Vec::new();
        self.scan_all("fw_sets", |entry| {
            let key_hex = js::string(g(entry, "key"));
            present.insert(key_hex.clone());
            let key = compile::decode_set_key(&key_hex);
            let value = compile::decode_set_value(&js::string(g(entry, "value")));
            match key {
                Some(key) if known.contains(&key.id) => {
                    if value.map(|value| value.kind == "static").unwrap_or(false) && !desired.contains_key(&key_hex) {
                        stale.push(key_hex);
                    }
                }
                _ => stale.push(key_hex),
            }
        })?;
        let mut ops: Vec<Value> = desired.iter().map(|(key, value)| json!({"op": "put", "object": OBJECT, "map": "fw_sets", "key": key, "value": value})).collect();
        ops.extend(self.restore_dynamic(ruleset, &desired, &present)?);
        self.transact(&ops)?;
        Ok(stale)
    }

    fn remove_stale(&self, map: &str, keys: &[String]) -> Result<()> {
        let ops: Vec<Value> = keys.iter().map(|key| json!({"op": "delete", "object": OBJECT, "map": map, "key": key})).collect();
        self.transact(&ops)
    }

    /// Writes a rule set into generation and makes packets read it.
    fn activate(&self, ruleset: &Ruleset, generation: u32) -> Result<Value> {
        let compiled = compile::compile_generation(&ruleset.policies, &ruleset.settings.trusted, generation, &ruleset.set_ids, &ruleset.settings)?;
        self.write_generation(generation, &compiled)?;
        let stale_sets = self.sync_sets_before(ruleset)?;
        let flags = CFG_LOADED | if compiled.active { CFG_ACTIVE } else { 0 } | if self.sync_interfaces(&ruleset.settings.interfaces)? { CFG_HAS_L3 } else { 0 };
        self.ebpf("mapPut", json!([OBJECT, "fw_log_cfg", compile::u32le(0), log_config_hex(ruleset.settings.log_per_second)]))?;
        self.ebpf("mapPut", json!([OBJECT, "fw_cfg", compile::u32le(0), compile::u32le(generation as u64) + &compile::u32le(flags)]))?;
        self.remove_stale("fw_sets", &stale_sets)?;
        if ruleset.policies.iter().any(|policy| policy.add_to_set.is_some()) || !self.dynamic_elements()?.is_empty() {
            self.arm_prune()?;
        }
        let mut summary = compiled.summary;
        summary["sets"] = json!(ruleset.sets.len());
        summary["connection_tracking"] = json!(ruleset.settings.connection_tracking);
        Ok(summary)
    }

    /// [pass, drop, trusted, evasive, ban, rate].
    fn counters(&self, slot: u32) -> Result<Vec<u64>> {
        let mut values = Vec::with_capacity(6);
        for counter in 0..4 {
            values.push(compile::sum_per_cpu(&self.ebpf("mapGetPerCPU", json!([OBJECT, "fw_stats", compile::stats_key(slot, counter)]))?));
        }
        for counter in [compile::LCNT_BAN, compile::LCNT_RATE] {
            values.push(compile::sum_per_cpu(&self.ebpf("mapGetPerCPU", json!([OBJECT, "fw_lstats", compile::lstats_key(slot, counter)]))?));
        }
        Ok(values)
    }

    fn global_counters(&self) -> Result<Value> {
        let mut out = Map::new();
        for (index, name) in compile::GCOUNTERS.iter().enumerate() {
            let value = compile::sum_per_cpu(&self.ebpf("mapGetPerCPU", json!([OBJECT, "fw_gstats", compile::gstats_key(index as u32)]))?);
            out.insert(name.to_string(), json!(value));
        }
        Ok(Value::Object(out))
    }

    /// New slots start their counters from what the slot shows now.
    fn reset_baselines(&self, st: &mut Value, fresh: &[u32]) {
        for slot in fresh {
            let values = self.counters(*slot).unwrap_or_else(|_| vec![0; 6]);
            st["baselines"][slot.to_string()] = json!(values);
        }
    }

    /// Forgets bans and SYN counts of slots that now belong to another policy.
    fn clear_limit_state(&self, slots: &[u32]) {
        if slots.is_empty() {
            return;
        }
        let wanted: HashSet<u64> = slots.iter().map(|slot| *slot as u64).collect();
        for map in ["fw_ban", "fw_rate"] {
            let mut stale = Vec::new();
            let scanned = self.scan_all(map, |entry| {
                let key = js::string(g(entry, "key"));
                if compile::decode_limit_key(&key).map(|decoded| wanted.contains(&decoded.slot)).unwrap_or(false) {
                    stale.push(key);
                }
            });
            if scanned.is_err() {
                continue;
            }
            for key in stale {
                let _ = self.ebpf("mapDelete", json!([OBJECT, map, key]));
            }
        }
    }

    fn schedule_sync(&self, st: &mut Value, error: &Error) -> Result<()> {
        st["dirty"] = json!(true);
        let attempts = js::number(g(st, "sync_attempts")).max(0.0) as i64 + 1;
        st["sync_attempts"] = json!(attempts);
        st["last_error"] = json!(error.to_string());
        if attempts <= SYNC_RETRY_LIMIT {
            self.host.timer_set_timeout(SYNC_TIMER, SYNC_RETRY_MS, &json!({}))?;
        }
        Ok(())
    }

    /// Writes the rule set into st.generation and switches packets to it. A
    /// failure (the object is not loaded until the hook has an interface)
    /// leaves the state dirty and retries.
    fn commit(&self, st: &mut Value, ruleset: &Ruleset) -> Result<()> {
        let generation = js::number(g(st, "generation")) as u32;
        match self.activate(ruleset, generation) {
            Ok(summary) => {
                st["summary"] = summary;
                st["dirty"] = json!(false);
                st["sync_attempts"] = json!(0);
                st["last_error"] = json!("");
                self.host.timer_clear(SYNC_TIMER)?;
            }
            Err(err) => {
                if ruleset.settings.interfaces.is_empty() {
                    // No interface: the hook is detached and nothing filters anyway.
                    st["dirty"] = json!(true);
                    st["last_error"] = json!("");
                    return Ok(());
                }
                self.schedule_sync(st, &err)?;
            }
        }
        Ok(())
    }

    /// Installs a snapshot: validates it, binds its interfaces, then lets
    /// change update the state and writes the maps. Binding comes before any
    /// state is read for writing: the binding's dataplane reconcile loads the
    /// object, so the state is loaded afterwards.
    fn install(&self, snapshot: &Value, change: impl FnOnce(&mut Value) -> Result<()>) -> Result<()> {
        let st = self.load_state()?;
        let check = self.build_ruleset(snapshot, &u32_map(&st["slots"]), &u32_map(&st["set_ids"]))?;
        self.bind_interfaces(&check.settings.interfaces, check.settings.connection_tracking)?;
        let mut st = self.load_state()?;
        change(&mut st)?;
        let ruleset = self.build_ruleset(snapshot, &u32_map(&st["slots"]), &u32_map(&st["set_ids"]))?;
        st["slots"] = u32_map_value(&ruleset.slots);
        st["set_ids"] = u32_map_value(&ruleset.set_ids);
        self.reset_baselines(&mut st, &ruleset.fresh);
        self.clear_limit_state(&ruleset.fresh);
        self.forget_gone_sets(&ruleset.set_ids)?;
        self.commit(&mut st, &ruleset)?;
        self.save_state(&st)
    }

    fn restore_confirmed(&self, reason: &str) -> Result<()> {
        let mut confirmed = self.read_snapshot("confirmed")?.unwrap_or_else(|| snapshot_of(&[], &json!({}), &[]));
        if self.build_ruleset(&confirmed, &BTreeMap::new(), &BTreeMap::new()).is_err() {
            // Never fails a rollback over a stored snapshot: keep its
            // interfaces and settings, no policies, sets or blocklists.
            let settings = js::or(g(&confirmed, "settings"), &json!({})).clone();
            let mut kept = settings.as_object().cloned().unwrap_or_default();
            kept.remove("blocklists");
            if !self.tc_egress {
                kept.remove("connection_tracking");
            }
            let mut kept = Value::Object(kept);
            if normalize_settings(&kept).is_err() {
                kept = json!({"interfaces": js::or(g(&settings, "interfaces"), &json!([]))});
            }
            confirmed = snapshot_of(&[], &kept, &[]);
        }
        let host = self.host;
        let applied = confirmed.clone();
        self.install(&confirmed, |st| {
            st["generation"] = json!(1 - js::number(g(st, "generation")) as i64);
            st["pending"] = Value::Null;
            st["rolled_back_at"] = js::num(now());
            st["rollback_reason"] = json!(reason);
            host.call("resources.set", json!(["snapshots", "applied", applied, true, false]))?;
            host.timer_clear(CONFIRM_TIMER)
        })
    }

    /// Validates the draft without touching anything: errors block an apply,
    /// warnings need their token passed back to apply as accept_warnings.
    fn check(&self) -> Result<CheckResult> {
        let snapshot = self.draft_snapshot()?;
        let st = self.load_state()?;
        let ruleset = match self.build_ruleset(&snapshot, &u32_map(&st["slots"]), &u32_map(&st["set_ids"])) {
            Ok(ruleset) => ruleset,
            Err(errors) => return Ok(CheckResult { snapshot, errors: errors.0, warnings: Vec::new(), token: String::new() }),
        };
        let mut warnings = compile::find_warnings(&ruleset.policies, &ruleset.settings.trusted, ruleset.settings.connection_tracking);
        if ruleset.settings.baseline.urpf == "strict" {
            warnings.push(compile::Warning {
                id: "urpf_strict".to_string(),
                policy: None,
                message: "严格反向路径检查要求回到来源的路由从收包的接口出去：多出口、非对称路由，以及 VLAN、PPPoE 帧（路由在子接口上）会被误丢，这些情况请用宽松模式。".to_string(),
            });
        }
        let token = compile::warnings_token(&warnings);
        Ok(CheckResult { snapshot, errors: Vec::new(), warnings: warnings.iter().map(compile::Warning::to_value).collect(), token })
    }

    fn apply(&self, payload: &Value) -> Result<()> {
        if truthy(g(&self.load_state()?, "pending")) {
            bail!("上一次应用还在等待确认：请先确认或回滚");
        }
        let result = self.check()?;
        if !result.errors.is_empty() {
            bail!("{}", result.errors.join("；"));
        }
        if !result.token.is_empty() && g(payload, "accept_warnings").as_str() != Some(result.token.as_str()) {
            let messages: Vec<String> = result.warnings.iter().map(|w| js::string(g(w, "message"))).collect();
            bail!("应用前需要确认以下提示（把 check 返回的 token 作为 accept_warnings 传给 apply）：{}", messages.join("；"));
        }
        let snapshot = result.snapshot;
        let settings = normalize_settings(js::or(g(&snapshot, "settings"), &json!({})))?;
        let host = self.host;
        let confirm_ms = settings.confirm_seconds as u64 * 1000;
        let applied = snapshot.clone();
        self.install(&snapshot, |st| {
            st["generation"] = json!(1 - js::number(g(st, "generation")) as i64);
            st["pending"] = json!({"deadline_ms": js::num(now() + confirm_ms as f64)});
            st["applied_at"] = js::num(now());
            host.call("resources.set", json!(["snapshots", "applied", applied, true, false]))?;
            host.timer_set_timeout(CONFIRM_TIMER, confirm_ms, &json!({}))
        })?;
        // The binding's dataplane reconcile has run by now. A hook the host
        // could not attach filters nothing, and the page would confirm it:
        // undo instead. With connection tracking the egress program must be
        // there too, or replies to this side's connections would be dropped.
        if settings.interfaces.is_empty() {
            return Ok(());
        }
        let Some(attach) = self.attachment_status(&settings.interfaces) else {
            return Ok(());
        };
        let error = js::string(g(&attach, "error"));
        let missing: Vec<String> = if error.is_empty() && settings.connection_tracking {
            js::array(g(&attach, "interfaces"))
                .iter()
                .filter(|i| js::is_true(g(i, "attached")) && !js::is_true(g(i, "egress")))
                .map(|i| js::string(g(i, "interface")))
                .collect()
        } else {
            Vec::new()
        };
        if !error.is_empty() || !missing.is_empty() {
            self.restore_confirmed("attach_failed")?;
            let reason = if !error.is_empty() { error } else { format!("连接跟踪的出向程序没挂上 {}", missing.join("、")) };
            bail!("防火墙没能挂载到接口，已回到上一次确认的规则：{reason}");
        }
        Ok(())
    }

    fn confirm(&self) -> Result<()> {
        let mut st = self.load_state()?;
        if !truthy(g(&st, "pending")) {
            return Ok(());
        }
        let applied = self.read_snapshot("applied")?.unwrap_or_else(|| snapshot_of(&[], &json!({}), &[]));
        self.write_snapshot("confirmed", &applied)?;
        st["pending"] = Value::Null;
        st["confirmed_at"] = js::num(now());
        self.host.timer_clear(CONFIRM_TIMER)?;
        self.save_state(&st)
    }

    fn rollback(&self, reason: &str) -> Result<()> {
        if !truthy(g(&self.load_state()?, "pending")) {
            return Ok(());
        }
        self.restore_confirmed(reason)
    }

    /// Brings the maps in line with the state: after a Veer restart (empty
    /// maps), after a write that failed, or when a deadline passed while Veer
    /// was down.
    fn sync(&self) -> Result<()> {
        let st = self.load_state()?;
        let Some(applied) = self.read_snapshot("applied")? else {
            return Ok(());
        };
        let pending = g(&st, "pending");
        if truthy(pending) && now() >= js::number(g(pending, "deadline_ms")) {
            return self.restore_confirmed("deadline");
        }
        if truthy(pending) {
            // Timers do not outlive the Veer process; a new one arms the
            // deadline again for the time that is left.
            let left = (js::number(g(pending, "deadline_ms")) - now()).max(1000.0);
            self.host.timer_set_timeout(CONFIRM_TIMER, left as u64, &json!({}))?;
        }
        let config = self.read_config().ok();
        let fresh = config.map(|(_, flags)| flags & CFG_LOADED == 0).unwrap_or(true);
        let dirty = truthy(g(&st, "dirty"));
        if fresh && truthy(pending) && !dirty {
            // Maps written once and now empty: a new Veer process that could
            // not keep them. The unconfirmed rule set is not restored, the
            // confirmed one is.
            return self.restore_confirmed("restart");
        }
        if let Some((generation, _)) = config {
            if !fresh && !dirty && generation as f64 == js::number(g(&st, "generation")) {
                // A binding written by 1.0 has no tc_egress, which the host
                // takes as on: add the field.
                if let Some(binding) = self.host.resources_get("hook_bindings", HOOK)? {
                    let data = g(&binding, "data");
                    if truthy(data) && data.get("tc_egress").is_none() {
                        let settings = normalize_settings(js::or(g(&applied, "settings"), &json!({}))).ok();
                        let tracking = settings.map(|s| s.connection_tracking).unwrap_or(false) && self.tc_egress;
                        let next = json!({"hook_id": HOOK, "interfaces": js::or(g(data, "interfaces"), &json!([])), "tc_egress": tracking});
                        self.host.call("resources.set", json!(["hook_bindings", HOOK, next, binding["enabled"], true]))?;
                    }
                }
                // Timers do not outlive the process either; one still
                // pending is left alone.
                let adding = js::array(g(&applied, "policies"))
                    .iter()
                    .any(|p| truthy(g(p, "enabled")) && truthy(g(p, "data")) && truthy(g(g(p, "data"), "add_to_set")));
                if !self.dynamic_elements()?.is_empty() || adding {
                    self.arm_prune_unless_pending()?;
                }
                return Ok(());
            }
        }
        self.install(&applied, |_| Ok(()))
    }

    fn status(&self) -> Result<Value> {
        let st = self.load_state()?;
        let applied = self.read_snapshot("applied")?;
        let draft = self.draft_snapshot()?;
        let mut loaded = true;
        let mut names: HashMap<String, Value> = HashMap::new();
        let mut limits: HashMap<String, Value> = HashMap::new();
        if let Some(applied) = &applied {
            for p in js::array(g(applied, "policies")) {
                let key = js::string(g(&p, "key"));
                let data = g(&p, "data");
                names.insert(key.clone(), if truthy(data) && truthy(g(data, "name")) { data["name"].clone() } else { json!(key) });
                if truthy(g(&p, "enabled")) && truthy(data) && truthy(g(data, "syn_limit")) {
                    limits.insert(key, data["syn_limit"].clone());
                }
            }
        }
        let slots = u32_map(&st["slots"]);
        let mut policies = Vec::new();
        for (key, slot) in &slots {
            let mut item = json!({
                "key": key, "name": names.get(key).cloned().unwrap_or(json!(key)), "slot": slot,
                "syn_limit": limits.get(key).cloned().unwrap_or(Value::Null), "counters": null,
            });
            if loaded {
                match self.counters(*slot) {
                    Ok(values) => {
                        let base: Vec<f64> = js::array(g(g(&st, "baselines"), &slot.to_string())).iter().map(js::number).collect();
                        let since = |i: usize| (values[i] as f64 - base.get(i).copied().unwrap_or(0.0)).max(0.0);
                        let mut counters = Map::new();
                        for (i, name) in COUNTER_NAMES.iter().enumerate() {
                            counters.insert(name.to_string(), js::num(since(i)));
                        }
                        counters.insert("banned".to_string(), js::num(since(4)));
                        counters.insert("rate_limited".to_string(), js::num(since(5)));
                        item["counters"] = Value::Object(counters);
                    }
                    Err(_) => loaded = false,
                }
            }
            policies.push(item);
        }
        let (mut evasive, mut log, mut global) = (Value::Null, Value::Null, Value::Null);
        if loaded {
            let read = (|| -> Result<(Value, Value, Value)> {
                let evasive = json!(self.counters(0)?[EVASIVE_COUNTER]);
                let logged = compile::sum_per_cpu(&self.ebpf("mapGetPerCPU", json!([OBJECT, "fw_lstats", compile::lstats_key(0, compile::LCNT_LOGGED)]))?);
                let lost = compile::sum_per_cpu(&self.ebpf("mapGetPerCPU", json!([OBJECT, "fw_lstats", compile::lstats_key(0, compile::LCNT_LOST)]))?);
                Ok((evasive, json!({"logged": logged, "lost": lost}), self.global_counters()?))
            })();
            match read {
                Ok((e, l, gl)) => {
                    evasive = e;
                    log = l;
                    global = gl;
                }
                Err(_) => loaded = false,
            }
        }
        let settings = applied.as_ref().and_then(|applied| normalize_settings(js::or(g(applied, "settings"), &json!({}))).ok());
        let set_ids = u32_map(&st["set_ids"]);
        let sets: Vec<Value> = applied
            .as_ref()
            .map(|applied| {
                js::array(g(applied, "sets"))
                    .iter()
                    .filter(|s| truthy(g(s, "enabled")))
                    .map(|s| {
                        let key = js::string(g(s, "key"));
                        let data = g(s, "data");
                        json!({
                            "key": key,
                            "name": if truthy(g(data, "name")) { data["name"].clone() } else { json!(key) },
                            "id": set_ids.get(&key).copied().map(Value::from).unwrap_or(Value::Null),
                            "static_elements": js::array(g(data, "elements")).len(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let pending = g(&st, "pending");
        let interfaces = settings.as_ref().map(|s| s.interfaces.clone()).unwrap_or_default();
        Ok(json!({
            "generation": st["generation"],
            "loaded": loaded,
            "pending": if truthy(pending) {
                let deadline = js::number(g(pending, "deadline_ms"));
                json!({"deadline_ms": pending["deadline_ms"], "remaining_seconds": js::num(((deadline - now()) / 1000.0).round().max(0.0))})
            } else { Value::Null },
            "applied_at": js::or(g(&st, "applied_at"), &Value::Null),
            "confirmed_at": js::or(g(&st, "confirmed_at"), &Value::Null),
            "rolled_back_at": js::or(g(&st, "rolled_back_at"), &Value::Null),
            "rollback_reason": js::or(g(&st, "rollback_reason"), &Value::Null),
            "last_error": js::or(g(&st, "last_error"), &json!("")),
            "dirty": truthy(g(&st, "dirty")),
            "interfaces": interfaces,
            "draft_changed": applied.as_ref().map(|applied| !same_json(&draft, applied)).unwrap_or(true),
            "summary": js::or(g(&st, "summary"), &Value::Null),
            "policies": policies,
            "sets": sets,
            "evasive_drops": evasive,
            "drop_log": log,
            "global": global,
            "connection_tracking": {"available": self.tc_egress, "enabled": settings.as_ref().map(|s| s.connection_tracking).unwrap_or(false)},
            "attachments": self.attachment_status(&interfaces).unwrap_or(Value::Null),
            "core": self.core_engine(),
        }))
    }

    /// How the hook sits on each bound interface, or None when the host
    /// cannot tell.
    fn attachment_status(&self, names: &[String]) -> Option<Value> {
        let runtime = self.host.call("plugin.attachments", json!([])).ok()?;
        let mut ingress: HashMap<String, Value> = HashMap::new();
        let mut egress: HashMap<String, Value> = HashMap::new();
        for a in js::array(g(&runtime, "attachments")) {
            if js::string(g(&a, "hook_id")) != HOOK || js::string(g(&a, "engine")) != "xdp" {
                continue;
            }
            let interface = js::string(g(&a, "interface"));
            if js::string(g(&a, "attach")) == "egress" {
                egress.insert(interface, a);
            } else {
                ingress.insert(interface, a);
            }
        }
        let interfaces: Vec<Value> = names
            .iter()
            .map(|name| {
                let e = egress.get(name);
                let mut out = json!({"interface": name, "attached": false, "mode": "", "error": "",
                    "egress": e.map(|e| js::string(g(e, "status")) == "attached").unwrap_or(false)});
                if let Some(a) = ingress.get(name) {
                    out["attached"] = json!(js::string(g(a, "status")) == "attached");
                    out["mode"] = js::or(g(a, "xdp_mode"), &json!("")).clone();
                    out["error"] = js::or(g(a, "error"), &json!("")).clone();
                }
                out
            })
            .collect();
        Some(json!({
            "error": js::or(g(&runtime, "error"), &json!("")),
            "reason": js::or(g(&runtime, "reason"), &json!("")),
            "interfaces": interfaces,
        }))
    }

    /// An active XDP plugin hook keeps the Veer core on its TC engine; worth
    /// a notice only where the configuration prefers the XDP engine.
    fn core_engine(&self) -> Value {
        let Ok(host) = self.host.call("plugin.host", json!([])) else {
            return Value::Null;
        };
        let order = g(&host, "kernel_engine_order");
        if !order.is_array() {
            return Value::Null;
        }
        let prefers_xdp = js::array(order).first().map(|first| first.as_str() == Some("xdp")).unwrap_or(false);
        json!({"engine_order": order, "prefers_xdp": prefers_xdp, "pinned_to_tc": prefers_xdp && js::is_true(g(&host, "core_engine_pinned_to_tc"))})
    }

    /// CLOCK_MONOTONIC in ms (the clock BPF ban times use), or None.
    fn monotonic_ms(&self) -> Option<f64> {
        self.ebpf("monotonicMs", json!([])).ok().map(|value| js::number(&value)).filter(|ms| ms.is_finite())
    }

    fn slot_policies(&self) -> Result<HashMap<u64, (String, Value)>> {
        let st = self.load_state()?;
        let applied = self.read_snapshot("applied")?;
        let mut names: HashMap<String, Value> = HashMap::new();
        if let Some(applied) = &applied {
            for p in js::array(g(applied, "policies")) {
                let key = js::string(g(&p, "key"));
                let data = g(&p, "data");
                names.insert(key.clone(), if truthy(data) && truthy(g(data, "name")) { data["name"].clone() } else { json!(key) });
            }
        }
        let mut by_slot = HashMap::new();
        for (key, slot) in u32_map(&st["slots"]) {
            let name = names.get(&key).cloned().unwrap_or(json!(key));
            by_slot.insert(slot as u64, (key, name));
        }
        Ok(by_slot)
    }

    /// One page of active bans: {items, cursor, done}; expired ones are skipped.
    fn bans(&self, payload: &Value) -> Result<Value> {
        let mut options = json!({"limit": page_limit(g(payload, "limit"), 100, 256)});
        if truthy(g(payload, "cursor")) {
            options["cursor"] = json!(js::string(g(payload, "cursor")));
        }
        let page = self.ebpf("mapScan", json!([OBJECT, "fw_ban", options]))?;
        let now_ms = self.monotonic_ms();
        let by_slot = self.slot_policies()?;
        let mut items = Vec::new();
        for entry in js::array(g(&page, "entries")) {
            let key_hex = js::string(g(&entry, "key"));
            let Some(key) = compile::decode_limit_key(&key_hex) else {
                continue;
            };
            let mut remaining = Value::Null;
            if let Some(now_ms) = now_ms {
                let left = ((compile::decode_ban_until_ms(&js::string(g(&entry, "value"))) - now_ms) / 1000.0).ceil();
                if left <= 0.0 {
                    continue;
                }
                remaining = js::num(left);
            }
            let policy = by_slot.get(&key.slot);
            items.push(json!({
                "key": key_hex, "source": key.source,
                "policy": policy.map(|p| json!(p.0)).unwrap_or(Value::Null),
                "policy_name": policy.map(|p| p.1.clone()).unwrap_or(Value::Null),
                "remaining_seconds": remaining,
            }));
        }
        Ok(json!({"items": items, "cursor": js::or(g(&page, "cursor"), &json!("")), "done": truthy(g(&page, "done")), "clock": now_ms.is_some()}))
    }

    /// Lifts bans: {key} one ban, {policy} every ban of a policy, {all: true} all.
    fn unban(&self, payload: &Value) -> Result<Value> {
        let mut keys = Vec::new();
        if let Some(key) = payload.get("key") {
            let key = js::string(key).to_lowercase();
            if key.len() != 40 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("封禁记录无效");
            }
            keys.push(key);
        } else if js::is_true(g(payload, "all")) || payload.get("policy").is_some() {
            let mut slot = None;
            if let Some(policy) = payload.get("policy") {
                let name = js::string(policy);
                let st = self.load_state()?;
                match u32_map(&st["slots"]).get(&name) {
                    Some(found) if *found != 0 => slot = Some(*found as u64),
                    _ => bail!("没有这条已应用的策略: {name}"),
                }
            }
            self.scan_all("fw_ban", |entry| {
                let key = js::string(g(entry, "key"));
                if let Some(decoded) = compile::decode_limit_key(&key) {
                    if slot.map(|slot| decoded.slot == slot).unwrap_or(true) {
                        keys.push(key);
                    }
                }
            })?;
        } else {
            bail!("需要 key、policy 或 all");
        }
        for key in &keys {
            // The SYN count goes too, or the next SYN would ban the source again.
            let _ = self.ebpf("mapDelete", json!([OBJECT, "fw_ban", key]));
            let _ = self.ebpf("mapDelete", json!([OBJECT, "fw_rate", key]));
        }
        Ok(json!({"removed": keys.len()}))
    }

    /// set_add elements kept for cold starts: {set: {cidr text: expires wall ms, 0 = until removed}}.
    fn dynamic_elements(&self) -> Result<Map<String, Value>> {
        Ok(self.kv_data(DYN_KEY, json!({}))?.as_object().cloned().unwrap_or_default())
    }

    /// The value of the longest fw_sets prefix covering key, or None.
    fn set_lookup(&self, key: &str) -> Option<String> {
        self.ebpf("mapGet", json!([OBJECT, "fw_sets", key])).ok().filter(truthy).map(|value| js::string(&value))
    }

    /// The id of an applied set, or an error naming what is wrong.
    fn applied_set_id(&self, name: &Value) -> Result<u32> {
        let name = if truthy(name) { js::string(name) } else { String::new() };
        let id = u32_map(&self.load_state()?["set_ids"]).get(&name).copied().unwrap_or(0);
        let exists = self
            .read_snapshot("applied")?
            .map(|applied| js::array(g(&applied, "sets")).iter().any(|s| js::string(g(s, "key")) == name && truthy(g(s, "enabled"))))
            .unwrap_or(false);
        if id == 0 || !exists {
            bail!("没有这个已应用的集合: {name}（新建或改名的集合要先应用）");
        }
        Ok(id)
    }

    fn element_list(payload: &Value) -> Result<Vec<Cidr>> {
        let list = match g(payload, "elements") {
            Value::String(text) => vec![json!(text)],
            Value::Array(items) if !items.is_empty() => items.clone(),
            _ => bail!("需要 elements"),
        };
        if list.len() > 256 {
            bail!("一次最多 256 个元素");
        }
        list.iter().map(|raw| compile::parse_cidr_str(&js::string(raw))).collect()
    }

    /// set_add: the elements go into the dataplane at once, until
    /// timeout_seconds pass (0 or none: until removed). They survive applies
    /// and hot restarts; a cold start restores them from KV.
    fn set_add(&self, payload: &Value) -> Result<Value> {
        let name = js::string(js::or(g(payload, "set"), &json!("")));
        let id = self.applied_set_id(&json!(name))?;
        let elements = Self::element_list(payload)?;
        let seconds = match payload.get("timeout_seconds") {
            None => 0.0,
            Some(value) => js::number(value),
        };
        if !(seconds >= 0.0 && seconds <= MAX_SET_TIMEOUT) || seconds.floor() != seconds {
            bail!("timeout_seconds 必须是 0 到 {} 之间的整数", MAX_SET_TIMEOUT as i64);
        }
        let mono = self.monotonic_ms();
        if seconds != 0.0 && mono.is_none() {
            bail!("这个 Veer 读不到单调时钟，不能设置超时");
        }
        let mut dyn_sets = self.dynamic_elements()?;
        let mut own = dyn_sets.get(&name).and_then(Value::as_object).cloned().unwrap_or_default();
        let mut total: usize = dyn_sets.values().map(|set| set.as_object().map(|m| m.len()).unwrap_or(0)).sum();
        let mut ops = Vec::new();
        let mut added = 0;
        for cidr in elements {
            let key = compile::set_key(id, &cidr);
            let decoded = self.set_lookup(&key).and_then(|value| compile::decode_set_value(&value));
            if decoded.map(|value| value.kind == "static").unwrap_or(false) {
                continue;
            }
            if !own.contains_key(&cidr.text) {
                total += 1;
            }
            if total > MAX_API_ELEMENTS {
                bail!("set_add 的元素合计最多 {MAX_API_ELEMENTS} 个");
            }
            own.insert(cidr.text.clone(), js::num(if seconds != 0.0 { now() + seconds * 1000.0 } else { 0.0 }));
            let expires = if seconds != 0.0 { mono.unwrap() + seconds * 1000.0 } else { 0.0 };
            ops.push(json!({"op": "put", "object": OBJECT, "map": "fw_sets", "key": key, "value": compile::set_value(expires, compile::SET_KIND_API)}));
            added += 1;
        }
        self.transact(&ops)?;
        dyn_sets.insert(name, Value::Object(own));
        self.host.kv_set(DYN_KEY, &Value::Object(dyn_sets))?;
        if seconds != 0.0 {
            self.arm_prune()?;
        }
        Ok(json!({"added": added}))
    }

    /// set_del: removes runtime elements (set_add or add_to_set); static ones stay.
    fn set_del(&self, payload: &Value) -> Result<Value> {
        let name = js::string(js::or(g(payload, "set"), &json!("")));
        let id = self.applied_set_id(&json!(name))?;
        let mut dyn_sets = self.dynamic_elements()?;
        let mut own = dyn_sets.get(&name).and_then(Value::as_object).cloned().unwrap_or_default();
        let mut removed = 0;
        for cidr in Self::element_list(payload)? {
            let key = compile::set_key(id, &cidr);
            let decoded = self.set_lookup(&key).and_then(|value| compile::decode_set_value(&value));
            own.remove(&cidr.text);
            match decoded {
                Some(value) if value.kind != "static" => {
                    if self.ebpf("mapDelete", json!([OBJECT, "fw_sets", key])).is_ok() {
                        removed += 1;
                    }
                }
                _ => {}
            }
        }
        dyn_sets.insert(name, Value::Object(own));
        self.host.kv_set(DYN_KEY, &Value::Object(dyn_sets))?;
        Ok(json!({"removed": removed}))
    }

    fn set_flush(&self, payload: &Value) -> Result<Value> {
        let name = js::string(js::or(g(payload, "set"), &json!("")));
        let id = self.applied_set_id(&json!(name))? as u64;
        let mut keys = Vec::new();
        self.scan_all("fw_sets", |entry| {
            let key_hex = js::string(g(entry, "key"));
            let key = compile::decode_set_key(&key_hex);
            let value = compile::decode_set_value(&js::string(g(entry, "value")));
            if let (Some(key), Some(value)) = (key, value) {
                if key.id == id && value.kind != "static" {
                    keys.push(key_hex);
                }
            }
        })?;
        for key in &keys {
            let _ = self.ebpf("mapDelete", json!([OBJECT, "fw_sets", key]));
        }
        let mut dyn_sets = self.dynamic_elements()?;
        dyn_sets.remove(&name);
        self.host.kv_set(DYN_KEY, &Value::Object(dyn_sets))?;
        Ok(json!({"removed": keys.len()}))
    }

    /// One page of a set's elements: {items: [{cidr, kind, remaining_seconds}], cursor, done}.
    fn set_list(&self, payload: &Value) -> Result<Value> {
        let id = self.applied_set_id(g(payload, "set"))? as u64;
        let mut options = json!({"limit": page_limit(g(payload, "limit"), 256, 256)});
        if truthy(g(payload, "cursor")) {
            options["cursor"] = json!(js::string(g(payload, "cursor")));
        }
        let page = self.ebpf("mapScan", json!([OBJECT, "fw_sets", options]))?;
        let mono = self.monotonic_ms();
        let mut items = Vec::new();
        for entry in js::array(g(&page, "entries")) {
            let key = compile::decode_set_key(&js::string(g(&entry, "key")));
            let value = compile::decode_set_value(&js::string(g(&entry, "value")));
            let (Some(key), Some(value)) = (key, value) else {
                continue;
            };
            if key.id != id {
                continue;
            }
            let mut remaining = Value::Null;
            if value.expires_ms != 0.0 {
                if let Some(mono) = mono {
                    let left = ((value.expires_ms - mono) / 1000.0).ceil();
                    if left <= 0.0 {
                        continue;
                    }
                    remaining = js::num(left);
                }
            }
            items.push(json!({"cidr": key.cidr, "kind": value.kind, "remaining_seconds": remaining}));
        }
        Ok(json!({"items": items, "cursor": js::or(g(&page, "cursor"), &json!("")), "done": truthy(g(&page, "done"))}))
    }

    /// set_add elements a cold start lost: ops putting back the unexpired ones
    /// that present lacks, timed from now.
    fn restore_dynamic(&self, ruleset: &Ruleset, desired: &BTreeMap<String, String>, present: &HashSet<String>) -> Result<Vec<Value>> {
        let dyn_sets = self.dynamic_elements()?;
        let mono = self.monotonic_ms();
        let wall = now();
        let mut ops = Vec::new();
        for set in &ruleset.sets {
            let Some(own) = dyn_sets.get(&set.key).and_then(Value::as_object) else {
                continue;
            };
            for (text, expires) in own {
                let expires = js::number(expires);
                if expires != 0.0 && (expires <= wall || mono.is_none()) {
                    continue;
                }
                let Ok(cidr) = compile::parse_cidr_str(text) else {
                    continue;
                };
                let key = compile::set_key(set.id, &cidr);
                if present.contains(&key) || desired.contains_key(&key) {
                    continue;
                }
                let at = if expires != 0.0 { mono.unwrap() + (expires - wall) } else { 0.0 };
                ops.push(json!({"op": "put", "object": OBJECT, "map": "fw_sets", "key": key, "value": compile::set_value(at, compile::SET_KIND_API)}));
            }
        }
        Ok(ops)
    }

    /// Drops the KV elements of sets that no longer exist.
    fn forget_gone_sets(&self, set_ids: &BTreeMap<String, u32>) -> Result<()> {
        let mut dyn_sets = self.dynamic_elements()?;
        let before = dyn_sets.len();
        dyn_sets.retain(|name, _| set_ids.get(name).copied().unwrap_or(0) != 0);
        if dyn_sets.len() != before {
            self.host.kv_set(DYN_KEY, &Value::Object(dyn_sets))?;
        }
        Ok(())
    }

    fn arm_prune(&self) -> Result<()> {
        self.host.timer_set_timeout(PRUNE_TIMER, PRUNE_MS, &json!({}))
    }

    fn arm_prune_unless_pending(&self) -> Result<()> {
        let pending = self.host.timer_pending(PRUNE_TIMER).unwrap_or(false);
        if !pending {
            self.arm_prune()?;
        }
        Ok(())
    }

    /// Removes expired runtime elements from fw_sets (the dataplane already
    /// ignores them) and from KV, then re-arms itself while any may expire.
    fn prune(&self) -> Result<Value> {
        let Some(mono) = self.monotonic_ms() else {
            return Ok(Value::Null);
        };
        let mut expired = Vec::new();
        let mut timed = false;
        self.scan_all("fw_sets", |entry| {
            let Some(value) = compile::decode_set_value(&js::string(g(entry, "value"))) else {
                return;
            };
            if value.expires_ms == 0.0 {
                return;
            }
            if value.expires_ms <= mono {
                expired.push(js::string(g(entry, "key")));
            } else {
                timed = true;
            }
        })?;
        for key in &expired {
            let _ = self.ebpf("mapDelete", json!([OBJECT, "fw_sets", key]));
        }
        let mut dyn_sets = self.dynamic_elements()?;
        let wall = now();
        let mut changed = false;
        for (_, own) in dyn_sets.iter_mut() {
            if let Some(own) = own.as_object_mut() {
                let before = own.len();
                own.retain(|_, expires| {
                    let expires = js::number(expires);
                    !(expires != 0.0 && expires <= wall)
                });
                changed |= own.len() != before;
            }
        }
        if changed {
            self.host.kv_set(DYN_KEY, &Value::Object(dyn_sets))?;
        }
        let adding = self
            .read_snapshot("applied")?
            .map(|applied| js::array(g(&applied, "policies")).iter().any(|p| truthy(g(p, "enabled")) && truthy(g(g(p, "data"), "add_to_set"))))
            .unwrap_or(false);
        if timed || adding {
            self.arm_prune()?;
        }
        Ok(json!({"removed": expired.len()}))
    }

    /// The latest sampled drops, newest first, with policy, set and interface names.
    fn events(&self, payload: &Value, drop_log: &VecDeque<Value>) -> Result<Value> {
        let limit = page_limit(g(payload, "limit"), 100, LOG_KEEP as u64) as usize;
        let by_slot = self.slot_policies()?;
        let set_names: HashMap<u64, String> = u32_map(&self.load_state()?["set_ids"]).into_iter().map(|(name, id)| (id as u64, name)).collect();
        let mut ifaces: HashMap<u64, String> = HashMap::new();
        if let Ok(links) = self.host.call("net.link.list", json!([])) {
            for link in js::array(&links) {
                ifaces.insert(js::number(g(&link, "ifindex")) as u64, js::string(g(&link, "name")));
            }
        }
        let now_mono = self.monotonic_ms();
        let wall = now();
        let items: Vec<Value> = drop_log
            .iter()
            .rev()
            .take(limit)
            .map(|event| {
                let mut event = event.clone();
                event["at_ms"] = match now_mono {
                    None => Value::Null,
                    Some(mono) => js::num((wall - (mono - js::number(g(&event, "time_ms")))).round()),
                };
                let slot = js::number(g(&event, "slot")) as u64;
                if js::string(g(&event, "reason")) == "blocklist" {
                    event["set"] = set_names.get(&slot).map(|name| json!(name)).unwrap_or(Value::Null);
                    event["policy"] = Value::Null;
                    event["policy_name"] = Value::Null;
                } else {
                    let policy = by_slot.get(&slot);
                    event["policy"] = policy.map(|p| json!(p.0)).unwrap_or(Value::Null);
                    event["policy_name"] = policy.map(|p| p.1.clone()).unwrap_or(Value::Null);
                }
                let ifindex = js::number(g(&event, "ifindex")) as u64;
                event["interface"] = json!(ifaces.get(&ifindex).cloned().unwrap_or_else(|| ifindex.to_string()));
                event
            })
            .collect();
        Ok(Value::Array(items))
    }

    fn interfaces(&self) -> Result<Value> {
        let links = js::array(&self.host.call("net.link.list", json!([]))?);
        Ok(Value::Array(
            links
                .iter()
                .filter(|l| truthy(g(l, "name")) && js::string(g(l, "name")) != "lo")
                .map(|l| {
                    let mac = js::string(js::or(g(l, "mac"), &json!("")));
                    json!({
                        "name": l["name"],
                        "kind": js::or(g(l, "kind"), &json!("")),
                        "up": truthy(g(l, "up")),
                        "master": js::or(g(l, "master_name"), &json!("")),
                        "l3": is_l3_mac(&mac),
                    })
                })
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests;
