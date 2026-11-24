//! WAN Core: a protocol-neutral WAN adapter. Drivers (pppoe_client,
//! vpn_core) publish normalized sessions; this plugin owns the Linux L3
//! boundary they hand off through (a dummy, a helper WAN device or a
//! segmented veth pair) with its addresses, routes, rules and neighbors.
//!
//! Repairs run when something changes, not on a polling tick. The host
//! delivers link, address, route, neighbor, rule and offload events for the
//! veer* interfaces this plugin may touch, a resync when events may have been
//! lost, and changes to its own records; each turns into a one-shot timer,
//! armed at most once, so a stream of events cannot keep postponing it:
//! - FULL_EVENT_TIMER, for any network event but a dynamic neighbor changing
//!   state, runs a full apply of every session: interfaces, addresses,
//!   routes, rules, neighbors and offloads. A link going down and up flushes
//!   its routes with no route event of its own, so a link event replays them.
//! - LIGHT_EVENT_TIMER, for a profile edit, reads every session's boundary
//!   links and compares them with its applied status and the record
//!   revisions it last applied; a session that differs gets a full apply.
//!
//! A full apply of a session that is in place writes nothing, so its own
//! changes echo back at most once. A session that did not reach its target
//! phase is retried with its own backoff from RETRY_MIN_MS to RETRY_MAX_MS,
//! and REPAIR_TIMER runs a full apply every SAFETY_REPAIR_MS in case an event
//! was lost without a resync.

#![recursion_limit = "512"]

use std::collections::{BTreeMap, HashMap};

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::netconf::*;
use veer_plugin::{bail, export_plugin, json, Error, Host, Map, Message, Outcome, Plugin, Result, Value};

const MAIN_ROUTE_TABLE: i64 = 254;
const AUTO_ROUTE_TABLE_BASE: i64 = 12000;
const AUTO_ROUTE_SLOT_COUNT: i64 = 8000;
const AUTO_RULE_PRIORITY_BASE: i64 = 10000;
const REPAIR_TIMER: &str = "wan_repair";
const LIGHT_EVENT_TIMER: &str = "wan_event";
const FULL_EVENT_TIMER: &str = "wan_event_full";
const RETRY_TIMER: &str = "wan_retry";
const SAFETY_REPAIR_MS: u64 = 300_000;
const EVENT_REPAIR_DELAY_MS: u64 = 250;
const RETRY_MIN_MS: u64 = 2000;
const RETRY_MAX_MS: u64 = 60_000;
// NUD_NOARP | NUD_PERMANENT: entries this plugin installs. Dynamic entries
// cycle through reachable and stale on their own and are not drift.
const NUD_STATIC: i64 = 0x40 | 0x80;

pub struct WanCore {
    /// Retry delay per session key that is not in its target phase yet.
    retry_delays: BTreeMap<String, u64>,
    repaired_revisions: HashMap<String, String>,
}

impl Plugin for WanCore {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(WanCore { retry_delays: BTreeMap::new(), repaired_revisions: HashMap::new() })
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        let ctx = &msg.ctx;
        match msg.handler.as_str() {
            "onReconcile" => {
                apply_records(host, &host.resources_list("sessions")?, false)?;
                self.remember_repair_revisions(host, None)?;
                arm_repair_timer(host, None)?;
                // A session that failed here is retried by the check, with backoff.
                host.timer_set_timeout(LIGHT_EVENT_TIMER, RETRY_MIN_MS, &json!({}))?;
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                self.on_deactivate(host)?;
                Ok(Outcome::Done)
            }
            "onResourceApply" => {
                self.on_resource_apply(host, ctx)?;
                Ok(Outcome::Done)
            }
            "onTimer" => {
                let name = js::text(g(g(ctx, "timer"), "name"));
                if name != REPAIR_TIMER && name != LIGHT_EVENT_TIMER && name != FULL_EVENT_TIMER && name != RETRY_TIMER {
                    return Ok(Outcome::Done);
                }
                let sessions = host.resources_list("sessions")?;
                let incomplete = self.repair_sessions(host, &sessions, name == REPAIR_TIMER || name == FULL_EVENT_TIMER)?;
                arm_repair_timer(host, Some(&sessions))?;
                self.arm_retry_timer(host, &incomplete)?;
                Ok(Outcome::Done)
            }
            // Map events to the repair they need. Events arrive in batches.
            "onNetEvent" => {
                if events(ctx).iter().any(|event| net_event_needs_repair(&js::text(g(event, "topic")), g(event, "payload"))) {
                    arm_once_event(host, FULL_EVENT_TIMER)?;
                }
                Ok(Outcome::Done)
            }
            // Session records arrive through onResourceApply and status
            // records are this plugin's own; a profile edit is applied by
            // comparing revisions.
            "onRecordEvent" => {
                let profile_changed = events(ctx).iter().any(|event| {
                    let resource = js::or(g(event, "resource"), g(g(event, "payload"), "resource_id"));
                    js::text(resource) == "profiles"
                });
                if profile_changed {
                    arm_once_event(host, LIGHT_EVENT_TIMER)?;
                }
                Ok(Outcome::Done)
            }
            "onAction" => self.on_action(host, ctx),
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(WanCore, "wan_core");


fn net_event_needs_repair(topic: &str, payload: &Value) -> bool {
    if topic == "net.neigh" {
        return js::text(g(payload, "operation")) == "delete" || (js::number(g(payload, "state")) as i64 & NUD_STATIC) != 0;
    }
    topic.starts_with("net.")
}

fn arm_once_event(host: &Host, name: &str) -> Result<()> {
    arm_once(host, name, EVENT_REPAIR_DELAY_MS)
}

impl WanCore {
    fn on_deactivate(&mut self, host: &Host) -> Result<()> {
        for name in [REPAIR_TIMER, LIGHT_EVENT_TIMER, FULL_EVENT_TIMER, RETRY_TIMER] {
            host.timer_clear(name)?;
        }
        let records = host.resources_list("sessions")?;
        let mut failures = Vec::new();
        for record in records.iter().filter(|record| !record.is_null()) {
            let payload = json!({"key": g(record, "key"), "session": js::or(g(record, "data"), &json!({}))});
            let result = load_plan(host, &payload).and_then(|plan| teardown_session(host, &plan));
            if let Err(err) = result {
                failures.push(format!("{}: {}", js::token(js::or(g(record, "key"), &json!("default"))), err));
            }
        }
        if !failures.is_empty() {
            bail!("WAN deactivate cleanup failed: {}", failures.join("; "));
        }
        Ok(())
    }

    fn on_resource_apply(&mut self, host: &Host, ctx: &Value) -> Result<()> {
        if js::text(g(g(ctx, "resource"), "id")) != "sessions" {
            return Ok(());
        }
        let records = current_records(host, "sessions", &js::array(g(ctx, "records")))?;
        let applied = apply_records(host, &records, true);
        self.remember_repair_revisions(host, Some(&stored_record_keys(&records)))?;
        let merged = merged_records(host, "sessions", &records)?;
        arm_repair_timer(host, Some(&merged))?;
        if applied.is_err() {
            let keys: Vec<String> = records_by_key(&records).into_keys().collect();
            self.arm_retry_timer(host, &keys)?;
        }
        applied
    }

    /// Applies the sessions that need it (all of them when full) and returns
    /// the keys of those that did not reach their target phase.
    fn repair_sessions(&mut self, host: &Host, sessions: &[Value], full: bool) -> Result<Vec<String>> {
        let profiles = records_by_key(&host.resources_list("profiles")?);
        let statuses = records_by_key(&host.resources_list("status")?);
        let mut next = HashMap::new();
        let mut incomplete = Vec::new();
        for record in sessions.iter().filter(|record| !record.is_null()) {
            let key = js::token(js::or(g(record, "key"), &json!("default")));
            let revisions = record_revisions(Some(record), profiles.get(&key), statuses.get(&key));
            if !full && self.repaired_revisions.get(&key) == Some(&revisions) && session_repair_healthy(host, &key, record, statuses.get(&key))? {
                next.insert(key, revisions);
                continue;
            }
            apply_records(host, std::slice::from_ref(record), false)?;
            let status = host.resources_get("status", &key)?;
            next.insert(key.clone(), record_revisions(Some(record), profiles.get(&key), status.as_ref()));
            if !session_in_target_phase(&key, record, status.as_ref())? {
                incomplete.push(key);
            }
        }
        self.repaired_revisions = next;
        Ok(incomplete)
    }

    /// A full apply outside the timer (reconcile, resource apply) lets the
    /// next ticks start with light checks. Only stored records count: a
    /// record the caller supplied as is may differ from the stored one, which
    /// the next tick then applies in full.
    fn remember_repair_revisions(&mut self, host: &Host, keys: Option<&BTreeMap<String, bool>>) -> Result<()> {
        let sessions = host.resources_list("sessions")?;
        let profiles = records_by_key(&host.resources_list("profiles")?);
        let statuses = records_by_key(&host.resources_list("status")?);
        for session in sessions.iter().filter(|record| !record.is_null()) {
            let key = js::token(js::or(g(session, "key"), &json!("default")));
            if let Some(keys) = keys {
                if !keys.contains_key(&key) {
                    continue;
                }
            }
            let revisions = record_revisions(Some(session), profiles.get(&key), statuses.get(&key));
            self.repaired_revisions.insert(key, revisions);
        }
        Ok(())
    }

    /// A session that is not in place yet (a failed apply, a boundary that
    /// is still coming up) is tried again with backoff: no event may follow.
    /// Each session backs off on its own, so one that keeps failing does not
    /// delay the first retry of another.
    fn arm_retry_timer(&mut self, host: &Host, incomplete: &[String]) -> Result<()> {
        let mut next = BTreeMap::new();
        let mut delay = 0u64;
        for key in incomplete {
            let value = match self.retry_delays.get(key) {
                Some(previous) if *previous > 0 => (previous * 2).min(RETRY_MAX_MS),
                _ => RETRY_MIN_MS,
            };
            next.insert(key.clone(), value);
            delay = if delay == 0 { value } else { delay.min(value) };
        }
        let waiting = !self.retry_delays.is_empty();
        self.retry_delays = next;
        if delay > 0 {
            host.timer_set_timeout(RETRY_TIMER, delay, &json!({}))?;
        } else if waiting {
            host.timer_clear(RETRY_TIMER)?;
        }
        Ok(())
    }

    fn on_action(&mut self, host: &Host, ctx: &Value) -> Result<Outcome> {
        let action = js::text(g(g(ctx, "action"), "id"));
        let payload = js::or(g(ctx, "payload"), &json!({})).clone();
        match action.as_str() {
            "apply_session" => {
                let plan = load_plan(host, &payload)?;
                set_record_if_changed(host, "profiles", &plan.key, &stored_profile(host, &plan, &payload)?, true)?;
                set_record_if_changed(host, "sessions", &plan.key, &plan.session, true)?;
                apply_session(host, &plan)?;
                arm_repair_timer(host, None)?;
                Ok(Outcome::Done)
            }
            "prepare_handoff" => {
                let plan = load_plan(host, &payload)?;
                set_record_if_changed(host, "profiles", &plan.key, &stored_profile(host, &plan, &payload)?, true)?;
                Ok(Outcome::Value(prepare_handoff(host, &plan)?))
            }
            "teardown" => {
                let plan = load_plan(host, &payload)?;
                teardown_session(host, &plan)?;
                arm_repair_timer(host, None)?;
                if js::is_true(g(&payload, "forget")) {
                    let deleted = previous_status(host, &plan.key)?;
                    if js::text(g(&deleted, "phase")) != "deleted" {
                        bail!("WAN cleanup incomplete; records retained for retry");
                    }
                    let operations: Vec<Value> = ["profiles", "sessions", "status"]
                        .iter()
                        .map(|id| json!({"op": "delete", "resource": id, "key": plan.key}))
                        .collect();
                    host.call("resources.transaction", json!([operations]))?;
                }
                Ok(Outcome::Done)
            }
            other => bail!("unsupported action {other}"),
        }
    }
}

// After an apply: did it leave the session in its target phase? The
// boundary was just written, so its status is enough.
fn session_in_target_phase(key: &str, record: &Value, status_record: Option<&Value>) -> Result<bool> {
    let status = status_record.map(|record| g(record, "data")).unwrap_or(&Value::Null);
    if !truthy(status) || !js::array(g(status, "cleanup_errors")).is_empty() {
        return Ok(false);
    }
    let phase = js::text(g(status, "phase"));
    if js::is_false(g(record, "enabled")) {
        return Ok(phase == "disabled" || phase == "deleted");
    }
    if !session_usable(&normalize_session(key, js::or(g(record, "data"), &json!({})))) {
        return Ok(phase == "skipped");
    }
    Ok(phase == "applied")
}

fn session_repair_healthy(host: &Host, key: &str, record: &Value, status_record: Option<&Value>) -> Result<bool> {
    let status = status_record.map(|record| g(record, "data")).unwrap_or(&Value::Null);
    if !truthy(status) || !js::array(g(status, "cleanup_errors")).is_empty() {
        return Ok(false);
    }
    let phase = js::text(g(status, "phase"));
    if js::is_false(g(record, "enabled")) {
        return Ok(phase == "disabled" || phase == "deleted");
    }
    if !session_usable(&normalize_session(key, js::or(g(record, "data"), &json!({})))) {
        return Ok(phase == "skipped");
    }
    Ok(phase == "applied" && boundary_healthy(host, status)?)
}

// Cheap link reads only: nothing here creates, changes or claims anything.
fn boundary_healthy(host: &Host, status: &Value) -> Result<bool> {
    let mode = previous_handoff_mode(status);
    let Some(local) = read_link(host, g(status, "local_interface")) else {
        return Ok(false);
    };
    if !js::strict_eq(g(&local, "ifindex"), g(status, "local_ifindex"))
        || !js::is_true(g(&local, "up"))
        || !js::strict_eq(g(&local, "mtu"), g(status, "mtu"))
    {
        return Ok(false);
    }
    let wanted_kind = match mode.as_str() {
        "segmented_veth" => "veth",
        "direct_gro" => "veerwan",
        _ => "dummy",
    };
    if js::text(g(&local, "kind")) != wanted_kind || !g(&local, "kind").is_string() {
        return Ok(false);
    }
    if js::is_true(g(status, "noarp_ready")) && !js::is_false(g(&local, "arp")) {
        return Ok(false);
    }
    let gso = g(g(status, "interface_preparation"), "local_gso");
    if truthy(gso)
        && (!js::strict_eq(g(&local, "gso_max_size"), g(gso, "max_size")) || !js::strict_eq(g(&local, "gso_max_segs"), g(gso, "max_segs")))
    {
        return Ok(false);
    }
    if !addresses_present(g(&local, "addresses"), g(status, "addresses")) {
        return Ok(false);
    }
    if mode != "segmented_veth" {
        return Ok(true);
    }
    let Some(peer) = read_link(host, g(status, "pipeline_interface")) else {
        return Ok(false);
    };
    if !js::strict_eq(g(&peer, "ifindex"), g(status, "pipeline_ifindex"))
        || !js::is_true(g(&peer, "up"))
        || !js::strict_eq(g(&peer, "mtu"), g(status, "mtu"))
    {
        return Ok(false);
    }
    Ok(!truthy(g(&local, "peer_ifindex")) || js::strict_eq(g(&local, "peer_ifindex"), g(&peer, "ifindex")))
}

fn read_link(host: &Host, name: &Value) -> Option<Value> {
    let name = safe_iface_name(name);
    if name.is_empty() {
        return None;
    }
    match host.call("net.link.get", json!([name])) {
        Ok(Value::Null) | Err(_) => None,
        Ok(link) => Some(link),
    }
}

fn addresses_present(actual: &Value, wanted: &Value) -> bool {
    let have: std::collections::HashSet<String> = js::array(actual).iter().map(|value| canonical_cidr(&js::lower(value))).collect();
    cidr_list(wanted).iter().all(|cidr| have.contains(&canonical_cidr(&cidr.to_lowercase())))
}

/// Matches Go's net.IPNet.String() for IPv4 and plain IPv6 addresses. A form
/// it does not recognize stays as written, so the check fails and a full
/// apply runs: slower, never wrong.
fn canonical_cidr(value: &str) -> String {
    let value = value.trim().to_lowercase();
    let Some(slash) = value.find('/') else {
        return value;
    };
    let (ip, bits) = (&value[..slash], &value[slash + 1..]);
    if bits.is_empty() || bits.len() > 3 || !bits.bytes().all(|b| b.is_ascii_digit()) {
        return value;
    }
    let bits = bits.parse::<u32>().unwrap_or(0).to_string();
    if !ipv4_host_cidr(ip).is_empty() {
        let parts: Vec<String> = ip.split('.').map(|part| part.parse::<u32>().unwrap_or(0).to_string()).collect();
        return format!("{}/{bits}", parts.join("."));
    }
    let Some(groups) = expand_ipv6(ip) else {
        return value;
    };
    let (mut best_start, mut best_length) = (-1i32, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if groups[i] != 0 {
            i += 1;
            continue;
        }
        let mut end = i;
        while end < 8 && groups[end] == 0 {
            end += 1;
        }
        if end - i > best_length {
            best_start = i as i32;
            best_length = end - i;
        }
        i = end + 1;
    }
    let hex: Vec<String> = groups.iter().map(|group| format!("{group:x}")).collect();
    if best_length < 2 {
        return format!("{}/{bits}", hex.join(":"));
    }
    let start = best_start as usize;
    format!("{}::{}/{bits}", hex[..start].join(":"), hex[start + best_length..].join(":"))
}

fn expand_ipv6(ip: &str) -> Option<Vec<u32>> {
    if !ip.contains(':') || ip.contains('.') || ip.contains('%') {
        return None;
    }
    let halves: Vec<&str> = ip.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let head: Vec<&str> = if halves[0].is_empty() { Vec::new() } else { halves[0].split(':').collect() };
    let tail: Vec<&str> = if halves.len() == 2 && !halves[1].is_empty() { halves[1].split(':').collect() } else { Vec::new() };
    let missing = 8i32 - head.len() as i32 - tail.len() as i32;
    if (halves.len() == 1 && missing != 0) || (halves.len() == 2 && missing < 1) {
        return None;
    }
    let mut parts: Vec<&str> = head;
    if halves.len() == 2 {
        parts.extend(std::iter::repeat("0").take(missing as usize));
    }
    parts.extend(tail);
    let mut out = Vec::with_capacity(8);
    for part in parts {
        if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(u32::from_str_radix(part, 16).ok()?);
    }
    if out.len() == 8 {
        Some(out)
    } else {
        None
    }
}

fn stored_record_keys(records: &[Value]) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        if js::number(g(record, "revision")) > 0.0 {
            out.insert(js::token(js::or(g(record, "key"), &json!("default"))), true);
        }
    }
    out
}


fn record_revisions(session: Option<&Value>, profile: Option<&Value>, status: Option<&Value>) -> String {
    [session, profile, status]
        .iter()
        .map(|record| match record {
            Some(record) if truthy(record) => format!(
                "{}/{}/{}",
                if g(record, "revision").is_null() { String::new() } else { js::string(g(record, "revision")) },
                !js::is_false(g(record, "enabled")),
                js::text(g(record, "updated_at"))
            ),
            _ => "-".to_string(),
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn arm_repair_timer(host: &Host, records: Option<&[Value]>) -> Result<()> {
    let owned;
    let sessions = match records {
        Some(records) => records,
        None => {
            owned = host.resources_list("sessions")?;
            &owned
        }
    };
    if sessions.iter().any(|session| !session.is_null() && !js::is_false(g(session, "enabled"))) {
        return host.timer_set_interval(REPAIR_TIMER, SAFETY_REPAIR_MS, &json!({}));
    }
    host.timer_clear(REPAIR_TIMER)
}



fn apply_records(host: &Host, records: &[Value], report_errors: bool) -> Result<()> {
    let mut failures = Vec::new();
    for record in records.iter().filter(|record| !record.is_null()) {
        if js::is_false(g(record, "enabled")) {
            disable_session_runtime(host, record)?;
            continue;
        }
        let payload = json!({"key": g(record, "key"), "session": js::or(g(record, "data"), &json!({}))});
        if let Err(err) = load_plan(host, &payload).and_then(|plan| apply_session(host, &plan)) {
            mark_apply_error(host, g(record, "key"), &err)?;
            failures.push(format!("{}: {}", js::token(js::or(g(record, "key"), &json!("default"))), err));
        }
    }
    if report_errors && !failures.is_empty() {
        bail!("failed to apply {} WAN session record(s): {}", failures.len(), failures.join("; "));
    }
    Ok(())
}

fn disable_session_runtime(host: &Host, record: &Value) -> Result<()> {
    let key = js::token(js::or(g(record, "key"), &json!("default")));
    // Teardown is a completed cleanup journal, not a suspended live session.
    // Reconciliation of its disabled record must preserve that proof across
    // restart so protocol drivers can safely recreate their WAN boundary.
    let previous = previous_status(host, &key)?;
    if js::text(g(&previous, "phase")) == "deleted" {
        return Ok(());
    }
    let raw = js::merge(js::or(g(record, "data"), &json!({})), &json!({"state": "down", "usable": false}));
    let plan = load_plan(host, &json!({"key": key, "session": raw}))?;
    let local_interface = safe_iface_name(js::first(&[g(&plan.profile, "local_interface"), g(&raw, "local_interface"), &json!("")]));
    let previous_managed = managed_link_proven(&previous) && previous_matches_interface(&previous, &local_interface);
    let previous_segmentation_ready = js::is_true(g(&previous, "noarp_ready")) && !managed_link_changed(&previous, &plan.profile);
    let cleanup_errors = if previous_managed { cleanup_managed_state(host, &previous, &plan.profile) } else { Vec::new() };
    let pipeline_interface = if previous_managed {
        json!(js::text(js::or(g(&previous, "pipeline_interface"), &json!(""))))
    } else {
        g(&plan.profile, "pipeline_interface").clone()
    };
    let handoff_mode = if previous_managed { json!(previous_handoff_mode(&previous)) } else { g(&plan.profile, "handoff_mode").clone() };
    let mut status = json!({
        "phase": "disabled",
        "wan_id": key,
        "profile_key": js::token(js::or(g(&raw, "profile_key"), &json!(key))),
        "state": first_text(&[g(&raw, "state"), g(&raw, "phase")]),
        "usable": false,
        "driver": first_text(&[g(&raw, "driver")]),
        "driver_plugin": first_text(&[g(&raw, "driver_plugin")]),
        "real_interface": first_text(&[g(&raw, "real_interface"), g(&raw, "interface")]),
        "wan_interface": first_text(&[g(&raw, "wan_interface"), g(&raw, "real_interface"), g(&raw, "interface")]),
        "local_interface": local_interface,
        "local_ifindex": js::or(g(&previous, "local_ifindex"), &json!(0)),
        "local_mac": js::or(g(&previous, "local_mac"), &json!("")),
        "pipeline_interface": pipeline_interface,
        "pipeline_ifindex": js::or(g(&previous, "pipeline_ifindex"), &json!(0)),
        "pipeline_mac": js::or(g(&previous, "pipeline_mac"), &json!("")),
        "handoff_mode": handoff_mode,
        "addresses": g(&plan.profile, "addresses"),
        "routes": g(&plan.profile, "routes"),
        "cleanup_errors": cleanup_errors,
        "managed_link": previous_managed,
        "original_arp": g(&previous, "original_arp"),
        "arp_disabled_by_plugin": js::is_true(g(&previous, "arp_disabled_by_plugin")) && previous_matches_interface(&previous, &local_interface),
        "noarp_ready": previous_segmentation_ready,
    });
    if !local_interface.is_empty() {
        let handoff_profile = json!({
            "local_interface": local_interface,
            "pipeline_interface": status["pipeline_interface"],
            "handoff_mode": status["handoff_mode"],
            "egress_nat_redirect_mode": "",
        });
        status["veer_core"] = veer_core_handoff(&handoff_profile, previous_segmentation_ready);
    }
    set_record_if_changed(host, "status", &key, &status, false)
}

fn mark_apply_error(host: &Host, key: &Value, error: &Error) -> Result<()> {
    let key = js::token(js::or(key, &json!("default")));
    let mut previous = previous_status(host, &key)?;
    if !previous.is_object() {
        previous = json!({});
    }
    previous["phase"] = json!("error");
    previous["wan_id"] = json!(key);
    previous["last_error"] = json!(error.to_string());
    set_record_if_changed(host, "status", &key, &previous, false)
}

/// A normalized session with its profile.
struct Plan {
    key: String,
    session: Value,
    profile: Value,
}

fn load_plan(host: &Host, payload: &Value) -> Result<Plan> {
    let inline_session = js::or(g(payload, "session"), g(payload, "link"));
    let inline_identity = if truthy(inline_session) { js::or(g(inline_session, "wan_id"), g(inline_session, "profile_key")) } else { &Value::Null };
    let key = js::token(js::first(&[
        g(payload, "wan_id"),
        g(payload, "profile_key"),
        g(payload, "profile"),
        g(payload, "key"),
        inline_identity,
        &json!("default"),
    ]));
    let session_base = host.resources_data("sessions", &key)?;
    let inline = if truthy(inline_session) { inline_session } else if truthy(payload) { payload } else { &Value::Null };
    let raw_session = js::merge(&session_base, inline);
    let session = normalize_session(&key, &raw_session);
    let profile_raw = js::merge(&js::merge(&raw_session, &load_profile(host, &key)?), payload);
    let profile = normalize_profile(host, &key, &session, &profile_raw)?;
    Ok(Plan { key, session, profile })
}

fn load_profile(host: &Host, key: &str) -> Result<Value> {
    host.resources_data("profiles", key)
}

fn stored_profile(host: &Host, plan: &Plan, payload: &Value) -> Result<Value> {
    let inline = js::or(js::or(g(payload, "session"), g(payload, "link")), &json!({})).clone();
    let previous = load_profile(host, &plan.key)?;
    let raw = js::merge(&js::merge(&previous, &inline), payload);
    let profile = &plan.profile;
    let mut out = json!({
        "profile_key": plan.key,
        "local_interface": profile["local_interface"],
        "pipeline_interface": profile["pipeline_interface"],
        "handoff_mode": profile["handoff_mode"],
        "mtu": profile["mtu"],
        "interface_preparation": profile["interface_preparation"],
        "addresses": cidr_list(js::first(&[g(&raw, "addresses"), g(&raw, "local_addresses"), &json!([])])),
        "routes": js::array(g(&raw, "routes")),
        "rules": js::array(g(&raw, "rules")),
        "neighbors": js::array(g(&raw, "neighbors")),
        "ipv6_route_table": profile["ipv6_route_table"],
        "ipv6_rule_priority": profile["ipv6_rule_priority"],
        "route_metric": profile["route_metric"],
        "route_metric_v6": profile["route_metric_v6"],
        "egress_nat_redirect_mode": profile["egress_nat_redirect_mode"],
    });
    for field in ["install_default_route", "install_default_route_v6"] {
        if js::has_own(&previous, field) || js::has_own(&inline, field) || js::has_own(payload, field) {
            out[field] = profile[field].clone();
        }
    }
    Ok(out)
}

fn apply_session(host: &Host, plan: &Plan) -> Result<()> {
    let previous = previous_status(host, &plan.key)?;
    let session = &plan.session;
    let profile = &plan.profile;
    if !session_usable(session) {
        let previous_segmentation_ready = js::is_true(g(&previous, "noarp_ready")) && !managed_link_changed(&previous, profile);
        let status = json!({
            "phase": "skipped",
            "reason": "wan session is not usable",
            "wan_id": plan.key,
            "state": session["state"],
            "usable": session["usable"],
            "driver": session["driver"],
            "driver_plugin": session["driver_plugin"],
            "real_interface": session["real_interface"],
            "wan_interface": session["wan_interface"],
            "local_interface": js::or(g(&previous, "local_interface"), &profile["local_interface"]),
            "local_ifindex": js::or(g(&previous, "local_ifindex"), &json!(0)),
            "local_mac": js::or(g(&previous, "local_mac"), &json!("")),
            "pipeline_interface": js::or(g(&previous, "pipeline_interface"), &profile["pipeline_interface"]),
            "pipeline_ifindex": js::or(g(&previous, "pipeline_ifindex"), &json!(0)),
            "pipeline_mac": js::or(g(&previous, "pipeline_mac"), &json!("")),
            "handoff_mode": previous_handoff_mode(&previous),
            "managed_link": managed_link_proven(&previous) && !managed_link_changed(&previous, profile),
            "original_arp": g(&previous, "original_arp"),
            "arp_disabled_by_plugin": js::is_true(g(&previous, "arp_disabled_by_plugin")),
            "segmentation_ready": previous_segmentation_ready,
            "noarp_ready": previous_segmentation_ready,
            "veer_core": veer_core_handoff(profile, previous_segmentation_ready),
            // Nothing is removed while the session is down. Keep the record
            // of what the last apply installed, so the next apply or a
            // teardown can remove what is no longer wanted.
            "addresses": g(&previous, "addresses"),
            "routes": g(&previous, "routes"),
            "rules": g(&previous, "rules"),
            "neighbors": g(&previous, "neighbors"),
            "ipv6_route_table": g(&previous, "ipv6_route_table"),
            "ipv6_rule_priority": g(&previous, "ipv6_rule_priority"),
        });
        return set_record_if_changed(host, "status", &plan.key, &status, false);
    }

    let replacement = replace_handoff_link(host, &previous, profile)?;
    let mut cleanup_errors = replacement.cleanup_errors;
    let link = replacement.link;
    let same_managed_link = managed_link_proven(&previous) && !managed_link_changed(&previous, profile);
    cleanup_errors.extend(cleanup_managed_state(host, &previous, profile));
    let local_interface = js::text(&profile["local_interface"]);
    replace_addrs(host, &local_interface, &js::array(&profile["addresses"]))?;
    replace_neighbors(host, &local_interface, &js::array(&profile["neighbors"]))?;
    replace_routes(host, &local_interface, &js::array(&profile["routes"]))?;
    replace_rules(host, &js::array(&profile["rules"]))?;
    let handoff = veer_core_handoff(profile, link.noarp_ready);
    let pipeline = link.pipeline.as_ref();
    let status = json!({
        "phase": "applied",
        "wan_id": plan.key,
        "profile_key": session["profile_key"],
        "driver": session["driver"],
        "driver_plugin": session["driver_plugin"],
        "state": session["state"],
        "usable": session["usable"],
        "real_interface": session["real_interface"],
        "wan_interface": session["wan_interface"],
        "local_interface": link.local["name"],
        "local_ifindex": link.local["ifindex"],
        "local_mac": link.local["mac"],
        "pipeline_interface": pipeline.map(|p| p["name"].clone()).unwrap_or(json!("")),
        "pipeline_ifindex": pipeline.map(|p| p["ifindex"].clone()).unwrap_or(json!(0)),
        "pipeline_mac": pipeline.map(|p| p["mac"].clone()).unwrap_or(json!("")),
        "handoff_mode": link.mode,
        "segmentation_ready": link.mode == "segmented_veth" && pipeline.is_some() && link.noarp_ready,
        "noarp_ready": link.noarp_ready,
        "original_arp": link.original_arp,
        "arp_disabled_by_plugin": link.arp_disabled_by_plugin,
        "mtu": profile["mtu"],
        "interface_preparation_request": profile["interface_preparation"],
        "interface_preparation": link.interface_preparation,
        "ipv4": session["ipv4"],
        "ipv4_peer": session["ipv4_peer"],
        "ipv6": session["ipv6"],
        "ipv6_addresses": session["ipv6_addresses"],
        "ipv6_link_local": session["ipv6_link_local"],
        "ipv6_peer_link_local": session["ipv6_peer_link_local"],
        "ipv6_gateway": session["ipv6_gateway"],
        "ipv6_prefix": session["ipv6_prefix"],
        "pd_prefix": session["pd_prefix"],
        "pd_prefixes": session["pd_prefixes"],
        "dns_servers": session["dns_servers"],
        "route_count": js::array(&profile["routes"]).len(),
        "rule_count": js::array(&profile["rules"]).len(),
        "neighbor_count": js::array(&profile["neighbors"]).len(),
        "addresses": profile["addresses"],
        "routes": profile["routes"],
        "rules": profile["rules"],
        "neighbors": profile["neighbors"],
        "ipv6_route_table": profile["ipv6_route_table"],
        "ipv6_rule_priority": profile["ipv6_rule_priority"],
        "cleanup_errors": cleanup_errors,
        "managed_link": link.created || same_managed_link,
        "veer_core": handoff,
        "veer_parent_interface": handoff["parent_interface"],
        "egress_nat_parent_interface": handoff["egress_nat_interface"],
        "egress_nat_redirect_mode": handoff["egress_nat_redirect_mode"],
        "egress_nat_virtual_source_ip": false,
    });
    set_record_if_changed(host, "status", &plan.key, &status, true)
}

fn previous_status(host: &Host, key: &str) -> Result<Value> {
    host.resources_data("status", key)
}

fn cleanup_managed_state(host: &Host, previous: &Value, profile: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    if !managed_link_proven(previous) || managed_link_changed(previous, profile) {
        return errors;
    }
    cleanup_removed_rules(host, g(previous, "rules"), g(profile, "rules"), &mut errors);
    cleanup_removed_addrs(host, g(previous, "local_interface"), g(previous, "addresses"), g(profile, "local_interface"), g(profile, "addresses"), &mut errors);
    cleanup_removed_routes(host, g(previous, "local_interface"), g(previous, "routes"), g(profile, "local_interface"), g(profile, "routes"), &mut errors);
    cleanup_removed_neighbors(host, g(previous, "local_interface"), g(previous, "neighbors"), g(profile, "local_interface"), g(profile, "neighbors"), &mut errors);
    errors
}

struct LinkReplacementCleanup {
    errors: Vec<String>,
    deleted: bool,
}

fn cleanup_managed_link_replacement(host: &Host, previous: &Value, profile: &Value) -> LinkReplacementCleanup {
    let mut result = LinkReplacementCleanup { errors: Vec::new(), deleted: false };
    if !managed_link_changed(previous, profile) {
        return result;
    }
    let local = safe_iface_name(g(previous, "local_interface"));
    if local.is_empty() {
        return result;
    }
    cleanup_removed_rules(host, g(previous, "rules"), g(profile, "rules"), &mut result.errors);
    if !managed_link_proven(previous) {
        restore_previous_arp(host, previous, &mut result.errors);
        return result;
    }
    match host.call("net.link.delete", json!([local])) {
        Ok(_) => result.deleted = true,
        Err(err) => result.errors.push(format!("old WAN handoff {local}: {err}")),
    }
    result
}

struct LinkReplacement {
    cleanup_errors: Vec<String>,
    link: HandoffLink,
}

fn replace_handoff_link(host: &Host, previous: &Value, profile: &Value) -> Result<LinkReplacement> {
    let cleanup = cleanup_managed_link_replacement(host, previous, profile);
    match ensure_handoff_link(host, profile, previous) {
        Ok(link) => Ok(LinkReplacement { cleanup_errors: cleanup.errors, link }),
        Err(err) => {
            if !cleanup.deleted {
                return Err(err);
            }
            let rollback_error = rollback_previous_handoff(host, previous, profile);
            if !rollback_error.is_empty() {
                bail!("{err}; previous WAN handoff rollback failed: {rollback_error}");
            }
            bail!("{err}; previous WAN handoff restored")
        }
    }
}

fn rollback_previous_handoff(host: &Host, previous: &Value, next_profile: &Value) -> String {
    let local = safe_iface_name(g(previous, "local_interface"));
    if local.is_empty() {
        return "previous local interface is unavailable".to_string();
    }
    let mode = previous_handoff_mode(previous);
    let pipeline = if mode == "segmented_veth" { safe_iface_name(g(previous, "pipeline_interface")) } else { String::new() };
    if mode == "segmented_veth" && pipeline.is_empty() {
        return "previous pipeline interface is unavailable".to_string();
    }
    let fallback_mtu = js::int_value(g(next_profile, "mtu"), 576, 65535, 1492);
    let profile = json!({
        "local_interface": local,
        "pipeline_interface": pipeline,
        "handoff_mode": mode,
        "mtu": js::int_value(g(previous, "mtu"), 576, 65535, fallback_mtu),
        "addresses": cidr_list(js::or(g(previous, "addresses"), &json!([]))),
        "routes": js::array(g(previous, "routes")),
        "rules": js::array(g(previous, "rules")),
        "neighbors": js::array(g(previous, "neighbors")),
        "interface_preparation": normalize_interface_preparation(g(previous, "interface_preparation_request"), g(previous, "mtu")),
    });
    let result: Result<()> = (|| {
        let restored = ensure_handoff_link(host, &profile, previous)?;
        replace_addrs(host, &local, &js::array(&profile["addresses"]))?;
        replace_neighbors(host, &local, &js::array(&profile["neighbors"]))?;
        replace_routes(host, &local, &js::array(&profile["routes"]))?;
        replace_rules(host, &js::array(&profile["rules"]))?;
        let mut updated = if previous.is_object() { previous.clone() } else { json!({}) };
        updated["local_ifindex"] = restored.local["ifindex"].clone();
        updated["local_mac"] = restored.local["mac"].clone();
        updated["pipeline_ifindex"] = restored.pipeline.as_ref().map(|p| p["ifindex"].clone()).unwrap_or(json!(0));
        updated["pipeline_mac"] = restored.pipeline.as_ref().map(|p| p["mac"].clone()).unwrap_or(json!(""));
        let key = js::token(js::or(g(previous, "wan_id"), g(previous, "profile_key")));
        set_record_if_changed(host, "status", &key, &updated, js::is_true(g(previous, "usable")))
    })();
    match result {
        Ok(()) => String::new(),
        Err(err) => err.to_string(),
    }
}

fn managed_link_changed(previous: &Value, profile: &Value) -> bool {
    let previous_local = safe_iface_name(g(previous, "local_interface"));
    if previous_local.is_empty() {
        return false;
    }
    if previous_local != safe_iface_name(g(profile, "local_interface")) {
        return true;
    }
    let previous_mode = previous_handoff_mode(previous);
    let next_mode = normalize_handoff_mode(js::or(g(profile, "handoff_mode"), &json!("direct")));
    if previous_mode != next_mode {
        return true;
    }
    if next_mode == "segmented_veth" {
        return safe_iface_name(g(previous, "pipeline_interface")) != safe_iface_name(g(profile, "pipeline_interface"));
    }
    false
}

fn previous_handoff_mode(previous: &Value) -> String {
    let veer_core = g(previous, "veer_core");
    let mode = js::lower(js::first(&[g(previous, "handoff_mode"), g(veer_core, "mode"), &json!("")]));
    if mode == "direct_gro" {
        return mode;
    }
    if mode == "segmented_veth" || mode == "vtap" {
        "segmented_veth".to_string()
    } else {
        "direct".to_string()
    }
}

fn managed_link_proven(previous: &Value) -> bool {
    if js::text(g(previous, "phase")) == "deleted" {
        return false;
    }
    js::is_true(g(previous, "managed_link"))
}

fn previous_matches_interface(previous: &Value, local_interface: &str) -> bool {
    let local_interface = safe_iface_name(&json!(local_interface));
    if local_interface.is_empty() {
        return false;
    }
    safe_iface_name(g(previous, "local_interface")) == local_interface
}

fn link_delete_skip_reason(previous: &Value) -> &'static str {
    if js::is_true(g(previous, "managed_link")) && js::text(g(previous, "phase")) == "deleted" {
        return "previous wan_core status already deleted this plugin-managed handoff";
    }
    "no previous wan_core status proves this handoff was plugin-managed"
}

fn teardown_profile(profile: &Value) -> Value {
    json!({
        "local_interface": profile["local_interface"],
        "pipeline_interface": profile["pipeline_interface"],
        "handoff_mode": profile["handoff_mode"],
        "addresses": [],
        "routes": [],
        "rules": [],
        "neighbors": [],
    })
}

fn teardown_previous_state(previous: &Value) -> Value {
    json!({
        "phase": js::or(g(previous, "phase"), &json!("")),
        "managed_link": js::is_true(g(previous, "managed_link")),
        "local_interface": js::or(g(previous, "local_interface"), &json!("")),
        "pipeline_interface": js::or(g(previous, "pipeline_interface"), &json!("")),
        "handoff_mode": previous_handoff_mode(previous),
        "original_arp": g(previous, "original_arp"),
        "arp_disabled_by_plugin": js::is_true(g(previous, "arp_disabled_by_plugin")),
        "noarp_ready": js::is_true(g(previous, "noarp_ready")),
        "interface_preparation_request": js::or(g(previous, "interface_preparation_request"), &Value::Null),
        "addresses": js::array(g(previous, "addresses")),
        "routes": js::array(g(previous, "routes")),
        "rules": js::array(g(previous, "rules")),
        "neighbors": js::array(g(previous, "neighbors")),
    })
}

fn teardown_session(host: &Host, plan: &Plan) -> Result<()> {
    let previous = previous_status(host, &plan.key)?;
    host.resources_set("sessions", &plan.key, &plan.session, false)?;
    let previous_teardown = teardown_previous_state(&previous);
    let mut cleanup_errors = cleanup_managed_state(host, &previous_teardown, &teardown_profile(&plan.profile));
    let mut delete_error = String::new();
    let delete_target = if managed_link_proven(&previous_teardown) { safe_iface_name(g(&previous_teardown, "local_interface")) } else { String::new() };
    let delete_skipped = delete_target.is_empty();
    let mut arp_restored = false;
    if !delete_target.is_empty() {
        if let Err(err) = host.call("net.link.delete", json!([delete_target])) {
            delete_error = err.to_string();
        }
    } else {
        arp_restored = restore_previous_arp(host, &previous_teardown, &mut cleanup_errors);
    }
    let link_deleted = !delete_target.is_empty() && delete_error.is_empty();
    let arp_disabled_before = js::is_true(g(&previous_teardown, "arp_disabled_by_plugin"));
    let arp_still_managed = if link_deleted {
        false
    } else if !delete_error.is_empty() {
        arp_disabled_before
    } else {
        !arp_restored && arp_disabled_before
    };
    // The driver stays named while the cleanup is unfinished: it checks the
    // status before it retries the teardown, and nothing may rewrite it first.
    let mut status = json!({
        "phase": "deleted",
        "wan_id": plan.key,
        "profile_key": plan.session["profile_key"],
        "driver": plan.session["driver"],
        "driver_plugin": plan.session["driver_plugin"],
        "local_interface": if delete_target.is_empty() { plan.profile["local_interface"].clone() } else { json!(delete_target) },
        "pipeline_interface": plan.profile["pipeline_interface"],
        "handoff_mode": plan.profile["handoff_mode"],
        "cleanup_errors": cleanup_errors,
        "managed_link": js::is_true(g(&previous_teardown, "managed_link")) || !delete_target.is_empty(),
        "original_arp": g(&previous_teardown, "original_arp"),
        "arp_disabled_by_plugin": arp_still_managed,
        "noarp_ready": arp_still_managed && js::is_true(g(&previous_teardown, "noarp_ready")),
        "arp_restored": arp_restored && arp_disabled_before,
        "link_delete_skipped": delete_skipped,
        "veer_core": veer_core_handoff(&plan.profile, false),
    });
    if !delete_error.is_empty() {
        status["phase"] = json!("delete_failed");
        status["last_error"] = json!(delete_error);
    } else if delete_skipped {
        status["link_delete_skip_reason"] = json!(link_delete_skip_reason(&previous_teardown));
    } else if !cleanup_errors_of(&status).is_empty() {
        status["phase"] = json!("delete_partial");
        status["last_error"] = json!(cleanup_errors_of(&status).join("; "));
    }
    set_record_if_changed(host, "status", &plan.key, &status, false)
}

fn cleanup_errors_of(status: &Value) -> Vec<String> {
    js::array(g(status, "cleanup_errors")).iter().map(js::text).collect()
}





fn session_usable(session: &Value) -> bool {
    if js::is_false(g(session, "usable")) {
        return false;
    }
    let state = js::lower(g(session, "state"));
    state.is_empty() || state == "up" || state == "ready" || state == "active"
}

fn prepare_handoff(host: &Host, plan: &Plan) -> Result<Value> {
    let previous = previous_status(host, &plan.key)?;
    let profile = &plan.profile;
    let replacement = replace_handoff_link(host, &previous, profile)?;
    let cleanup_errors = replacement.cleanup_errors;
    let link = replacement.link;
    let same_managed_link = managed_link_proven(&previous) && !managed_link_changed(&previous, profile);
    let handoff = veer_core_handoff(profile, link.noarp_ready);
    let pipeline = link.pipeline.as_ref();
    let mut status = json!({
        "phase": if cleanup_errors.is_empty() { "prepared" } else { "prepared_partial" },
        "wan_id": plan.key,
        "profile_key": plan.session["profile_key"],
        "driver": plan.session["driver"],
        "driver_plugin": plan.session["driver_plugin"],
        "state": js::or(&plan.session["state"], &json!("prepared")),
        "usable": false,
        "real_interface": plan.session["real_interface"],
        "wan_interface": plan.session["wan_interface"],
        "local_interface": link.local["name"],
        "local_ifindex": link.local["ifindex"],
        "local_mac": link.local["mac"],
        "pipeline_interface": pipeline.map(|p| p["name"].clone()).unwrap_or(json!("")),
        "pipeline_ifindex": pipeline.map(|p| p["ifindex"].clone()).unwrap_or(json!(0)),
        "pipeline_mac": pipeline.map(|p| p["mac"].clone()).unwrap_or(json!("")),
        "handoff_mode": link.mode,
        "segmentation_ready": link.mode == "segmented_veth" && pipeline.is_some() && link.noarp_ready,
        "noarp_ready": link.noarp_ready,
        "original_arp": link.original_arp,
        "arp_disabled_by_plugin": link.arp_disabled_by_plugin,
        "mtu": profile["mtu"],
        "interface_preparation_request": profile["interface_preparation"],
        "interface_preparation": link.interface_preparation,
        "addresses": profile["addresses"],
        "cleanup_errors": cleanup_errors,
        "managed_link": link.created || same_managed_link,
        "veer_core": handoff,
        "note": "The local boundary is prepared; WAN egress remains disabled until a usable session is applied.",
    });
    if !cleanup_errors.is_empty() {
        status["last_error"] = json!(cleanup_errors.join("; "));
    }
    set_record_if_changed(host, "status", &plan.key, &status, false)?;
    Ok(status)
}

struct HandoffLink {
    mode: String,
    local: Value,
    pipeline: Option<Value>,
    created: bool,
    noarp_ready: bool,
    original_arp: Value,
    arp_disabled_by_plugin: bool,
    interface_preparation: Value,
}

fn ensure_handoff_link(host: &Host, profile: &Value, previous: &Value) -> Result<HandoffLink> {
    let local_interface = js::text(g(profile, "local_interface"));
    if js::text(g(profile, "handoff_mode")) == "segmented_veth" {
        // The pipeline end is internal plumbing: hosts that understand the
        // flag keep it out of user interface lists.
        let pair = host.call(
            "net.link.ensureVeth",
            json!([{
                "host": profile["local_interface"],
                "peer": profile["pipeline_interface"],
                "mtu": profile["mtu"],
                "up": true,
                "peer_internal": true,
            }]),
        )?;
        let prepared = ensure_segmented_local_arp(host, &pair, previous, profile)
            .and_then(|arp| prepare_managed_handoff_interfaces(host, profile, Some(&arp.local), Some(g(&pair, "peer"))).map(|prep| (arp, prep)));
        let (arp, preparation) = match prepared {
            Ok(prepared) => prepared,
            Err(err) => {
                if js::is_true(g(&pair, "created")) {
                    if let Err(cleanup) = host.call("net.link.delete", json!([local_interface])) {
                        bail!("{err}; cleanup created veth: {cleanup}");
                    }
                }
                return Err(err);
            }
        };
        return Ok(HandoffLink {
            mode: "segmented_veth".to_string(),
            local: arp.local,
            pipeline: Some(g(&pair, "peer").clone()),
            created: js::is_true(g(&pair, "created")),
            noarp_ready: arp.noarp_ready,
            original_arp: json!(arp.original_arp),
            arp_disabled_by_plugin: arp.arp_disabled_by_plugin,
            interface_preparation: preparation,
        });
    }
    let method = if js::text(g(profile, "handoff_mode")) == "direct_gro" { "net.link.ensureHelperWAN" } else { "net.link.ensureDummy" };
    let dummy = host.call(method, json!([{"name": profile["local_interface"], "mtu": profile["mtu"], "up": true}]))?;
    let link = g(&dummy, "link").clone();
    match prepare_managed_handoff_interfaces(host, profile, Some(&link), None) {
        Ok(preparation) => Ok(HandoffLink {
            mode: js::text(g(profile, "handoff_mode")),
            original_arp: g(&link, "arp").clone(),
            local: link,
            pipeline: None,
            created: js::is_true(g(&dummy, "created")),
            noarp_ready: false,
            arp_disabled_by_plugin: false,
            interface_preparation: preparation,
        }),
        Err(err) => {
            if js::is_true(g(&dummy, "created")) {
                let _ = host.call("net.link.delete", json!([local_interface]));
            }
            Err(err)
        }
    }
}

fn prepare_managed_handoff_interfaces(host: &Host, profile: &Value, local: Option<&Value>, pipeline: Option<&Value>) -> Result<Value> {
    let request = g(profile, "interface_preparation");
    let mut result = json!({"applied": false, "local_gso": null, "local_offloads": null, "pipeline_offloads": null, "warnings": []});
    if !truthy(request) {
        return Ok(result);
    }
    let local_name = local.map(|link| g(link, "name")).filter(|name| truthy(name));
    if truthy(g(request, "local_gso")) {
        if let Some(name) = local_name {
            let gso = host.call("net.link.setGSO", json!([name, request["local_gso"]]))?;
            result["local_gso"] = json!({
                "interface": name,
                "max_size": js::or(g(&gso, "gso_max_size"), &request["local_gso"]["max_size"]),
                "max_segs": js::or(g(&gso, "gso_max_segs"), &request["local_gso"]["max_segs"]),
            });
        }
    }
    let mut warnings = Vec::new();
    result["local_offloads"] = prepare_managed_handoff_offloads(host, request, local, g(request, "local_offloads"), "local", &mut warnings)?;
    result["pipeline_offloads"] = prepare_managed_handoff_offloads(host, request, pipeline, g(request, "pipeline_offloads"), "pipeline", &mut warnings)?;
    result["warnings"] = Value::Array(warnings);
    result["applied"] = json!(true);
    Ok(result)
}

fn prepare_managed_handoff_offloads(host: &Host, request: &Value, link: Option<&Value>, features: &Value, role: &str, warnings: &mut Vec<Value>) -> Result<Value> {
    let Some(link) = link else {
        return Ok(Value::Null);
    };
    let name = g(link, "name");
    if !truthy(features) || !truthy(name) {
        return Ok(Value::Null);
    }
    match host.call("net.link.setOffloads", json!([name, features])) {
        Ok(_) => Ok(json!({"interface": name, "features": features})),
        Err(err) => {
            if !truthy(g(request, "allow_unsafe_offloads")) {
                bail!("prepare WAN handoff {role} offloads on {}: {err}", js::string(name));
            }
            warnings.push(json!({"interface": name, "role": role, "warning": err.to_string()}));
            Ok(Value::Null)
        }
    }
}

struct ArpState {
    local: Value,
    noarp_ready: bool,
    original_arp: bool,
    arp_disabled_by_plugin: bool,
}

fn ensure_segmented_local_arp(host: &Host, pair: &Value, previous: &Value, profile: &Value) -> Result<ArpState> {
    let mut local = js::or(g(pair, "host"), &json!({})).clone();
    let continued = !managed_link_changed(previous, profile)
        && safe_iface_name(g(previous, "local_interface")) == safe_iface_name(g(profile, "local_interface"))
        && previous_handoff_mode(previous) == "segmented_veth";
    let mut original_arp = !js::is_false(g(&local, "arp"));
    let mut disabled_by_plugin = false;
    if continued && js::is_true(g(previous, "arp_disabled_by_plugin")) {
        original_arp = !js::is_false(g(previous, "original_arp"));
        disabled_by_plugin = true;
    }
    if !js::is_false(g(&local, "arp")) {
        local = host.call("net.link.setARP", json!([profile["local_interface"], false]))?;
        disabled_by_plugin = original_arp;
    }
    if !truthy(&local) || !js::is_false(g(&local, "arp")) {
        bail!("segmented WAN local interface did not enter NOARP state");
    }
    Ok(ArpState { local, noarp_ready: true, original_arp, arp_disabled_by_plugin: disabled_by_plugin })
}

fn restore_previous_arp(host: &Host, previous: &Value, errors: &mut Vec<String>) -> bool {
    if !js::is_true(g(previous, "arp_disabled_by_plugin")) || !js::is_true(g(previous, "original_arp")) {
        return true;
    }
    let local = safe_iface_name(g(previous, "local_interface"));
    if local.is_empty() {
        return true;
    }
    match host.call("net.link.setARP", json!([local, true])) {
        Ok(_) => true,
        Err(err) => {
            errors.push(format!("restore ARP {local}: {err}"));
            false
        }
    }
}

fn veer_core_handoff(profile: &Value, segmentation_ready: bool) -> Value {
    let segmented = js::text(g(profile, "handoff_mode")) == "segmented_veth";
    json!({
        "mode": if segmented { "segmented_veth" } else { "single_local_boundary" },
        "parent_interface": g(profile, "local_interface"),
        "ingress_interface": g(profile, "local_interface"),
        "route_interface": g(profile, "local_interface"),
        "tunnel_interface": if segmented { g(profile, "pipeline_interface").clone() } else { json!("") },
        "egress_nat_interface": g(profile, "local_interface"),
        "egress_nat_redirect_mode": g(profile, "egress_nat_redirect_mode"),
        "segmentation_ready": segmented && segmentation_ready,
        "note": if segmented {
            "Veer/Egress NAT targets the local veth; the kernel segments GSO before the protocol plugin runs on the pipeline peer."
        } else {
            "Veer/Egress NAT redirects L3 traffic to the local boundary; the protocol plugin handles its TC hooks."
        },
    })
}


fn normalize_session(key: &str, raw: &Value) -> Value {
    let ipv6_addresses = js::array(g(raw, "ipv6_addresses"));
    let pd_prefixes = js::array(g(raw, "pd_prefixes"));
    let dns_servers = js::array(g(raw, "dns_servers"));
    let first_ipv6 = ipv6_addresses.first().map(|item| g(item, "address").clone()).unwrap_or(Value::Null);
    let first_pd = pd_prefixes.first().map(|item| g(item, "prefix").clone()).unwrap_or(Value::Null);
    json!({
        "wan_id": js::token(js::or(g(raw, "wan_id"), &json!(key))),
        "profile_key": js::token(js::or(g(raw, "profile_key"), &json!(key))),
        "driver": first_text(&[g(raw, "driver")]),
        "driver_plugin": first_text(&[g(raw, "driver_plugin")]),
        "state": first_text(&[g(raw, "state"), g(raw, "phase")]),
        "usable": js::bool_value(g(raw, "usable"), true),
        "real_interface": first_text(&[g(raw, "real_interface"), g(raw, "interface")]),
        "wan_interface": first_text(&[g(raw, "wan_interface"), g(raw, "real_interface"), g(raw, "interface")]),
        "peer_mac": first_text(&[g(raw, "peer_mac"), g(raw, "ac_mac"), g(raw, "wan_dst_mac")]),
        "ipv4": first_text(&[g(raw, "ipv4"), g(raw, "ipv4_address")]),
        "ipv4_peer": first_text(&[g(raw, "ipv4_peer"), g(raw, "peer_ipv4"), g(raw, "gateway")]),
        "ipv6": first_text(&[g(raw, "ipv6"), g(raw, "ipv6_address"), &first_ipv6]),
        "ipv6_addresses": ipv6_addresses,
        "ipv6_link_local": first_text(&[g(raw, "ipv6_link_local")]),
        "ipv6_peer_link_local": first_text(&[g(raw, "ipv6_peer_link_local"), g(raw, "peer_ipv6_link_local")]),
        "ipv6_gateway": first_text(&[g(raw, "ipv6_gateway"), g(raw, "ipv6_router")]),
        "ipv6_prefix": first_text(&[g(raw, "ipv6_prefix")]),
        "pd_prefix": first_text(&[g(raw, "pd_prefix"), &first_pd]),
        "pd_prefixes": pd_prefixes,
        "dns_servers": dns_servers,
        "install_default_route_v6": js::bool_value(g(raw, "install_default_route_v6"), false),
        "mtu": js::int_value(js::or(g(raw, "mtu"), g(raw, "mru")), 576, 65535, 1492),
        "session_id": js::int_value(g(raw, "session_id"), 0, 65535, 0),
        "updated_at": first_text(&[g(raw, "updated_at")]),
    })
}

fn normalize_profile(host: &Host, key: &str, session: &Value, raw: &Value) -> Result<Value> {
    let local_interface = js::text(js::or(g(raw, "local_interface"), &json!("veerlocal0")));
    let default_mode = {
        let driver = js::lower(js::first(&[g(session, "driver"), g(raw, "driver"), g(raw, "driver_plugin")]));
        if driver == "pppoe" || js::lower(g(raw, "driver_plugin")) == "pppoe_client" {
            "segmented_veth"
        } else {
            "direct"
        }
    };
    let handoff_mode = normalize_handoff_mode(js::first(&[g(raw, "handoff_mode"), g(raw, "pipeline_mode"), &json!(default_mode)]));
    let derived = if handoff_mode == "segmented_veth" { json!(derived_pipeline_interface(&local_interface, key)) } else { json!("") };
    let pipeline_interface = js::text(js::first(&[g(raw, "pipeline_interface"), g(raw, "tunnel_interface"), g(raw, "vtap_interface"), &derived]));
    if handoff_mode == "segmented_veth" && local_interface == pipeline_interface {
        bail!("local_interface and pipeline_interface must be different");
    }
    let mut addresses = cidr_list(js::first(&[g(raw, "addresses"), g(raw, "local_addresses"), &json!([])]));
    let mut routes = js::array(g(raw, "routes"));
    let mut rules = js::array(g(raw, "rules"));
    let mut neighbors = js::array(g(raw, "neighbors"));
    let install_default_route_v6 = js::bool_value(g(raw, "install_default_route_v6"), js::is_true(g(session, "install_default_route_v6")));
    let identity = allocate_ipv6_routing_identity(host, key, raw)?;
    if session_usable(session) {
        let ipv4 = js::text(g(session, "ipv4"));
        addresses = append_cidr_unique(addresses, &ipv4_host_cidr(&ipv4));
        addresses = append_cidr_unique(addresses, &ipv6_host_cidr(&js::text(g(session, "ipv6"))));
        addresses = append_cidr_unique(addresses, &ipv6_link_local_cidr(&js::text(g(session, "ipv6_link_local"))));
        let ipv4_peer_cidr = ipv4_host_cidr(&js::text(g(session, "ipv4_peer")));
        let segmented = handoff_mode == "segmented_veth" || handoff_mode == "direct_gro";
        if segmented && !ipv4.is_empty() && !ipv4_peer_cidr.is_empty() {
            // Different PPP sessions often share the same AC address. A route
            // in main would replace another WAN's route even with a
            // different dev/src.
            routes = append_route_unique(routes, json!({"dst": ipv4_peer_cidr, "dev": local_interface, "src": ipv4, "table": identity.table}));
            rules = append_rule_unique(
                rules,
                json!({"family": "ipv4", "priority": identity.priority, "table": identity.table, "src": ipv4_host_cidr(&ipv4), "dst": ipv4_peer_cidr}),
            );
        }
        if js::bool_value(g(raw, "install_default_route"), false) && !ipv4.is_empty() {
            routes = append_route_unique(
                routes,
                json!({"dst": "0.0.0.0/0", "dev": local_interface, "src": ipv4, "metric": js::int_value(g(raw, "route_metric"), 0, 2147483647, 0)}),
            );
        }
        if install_default_route_v6 {
            if segmented {
                let source_prefix = ipv6_route_source_prefix(session);
                let gateway = first_text(&[g(session, "ipv6_gateway"), g(session, "ipv6_peer_link_local")]);
                if source_prefix.is_empty() || gateway.is_empty() || !truthy(g(session, "peer_mac")) {
                    bail!("segmented IPv6 default route requires delegated/source prefix, IPv6 peer gateway and peer MAC");
                }
                routes = append_route_unique(
                    routes,
                    json!({"dst": "::/0", "dev": local_interface, "gateway": gateway, "table": identity.table,
                        "metric": js::int_value(g(raw, "route_metric_v6"), 0, 2147483647, 0)}),
                );
                rules = append_rule_unique(rules, json!({"family": "ipv6", "priority": identity.priority, "table": MAIN_ROUTE_TABLE, "dst": source_prefix}));
                rules = append_rule_unique(rules, json!({"family": "ipv6", "priority": identity.priority + 1, "table": identity.table, "src": source_prefix}));
                neighbors = append_neighbor_unique(neighbors, json!({"interface": local_interface, "ip": gateway, "mac": session["peer_mac"], "state": "permanent"}));
            } else if truthy(g(session, "ipv6")) {
                routes = append_route_unique(
                    routes,
                    json!({"dst": "::/0", "dev": local_interface, "src": session["ipv6"], "metric": js::int_value(g(raw, "route_metric_v6"), 0, 2147483647, 0)}),
                );
            }
        }
    }
    let mtu = js::int_value(js::or(g(raw, "mtu"), g(session, "mtu")), 576, 65535, 1492);
    Ok(json!({
        "profile_key": key,
        "local_interface": iface_name(&local_interface, "local_interface")?,
        "pipeline_interface": if handoff_mode == "segmented_veth" { iface_name(&pipeline_interface, "pipeline_interface")? } else { String::new() },
        "handoff_mode": handoff_mode,
        "mtu": mtu,
        "interface_preparation": normalize_interface_preparation(g(raw, "interface_preparation"), &json!(mtu)),
        "addresses": addresses,
        "routes": routes,
        "rules": rules,
        "neighbors": neighbors,
        "ipv6_route_table": identity.table,
        "ipv6_rule_priority": identity.priority,
        "install_default_route": js::bool_value(g(raw, "install_default_route"), false),
        "install_default_route_v6": install_default_route_v6,
        "route_metric": js::int_value(g(raw, "route_metric"), 0, 2147483647, 0),
        "route_metric_v6": js::int_value(g(raw, "route_metric_v6"), 0, 2147483647, 0),
        "egress_nat_redirect_mode": normalize_redirect_mode(js::first(&[g(raw, "egress_nat_redirect_mode"), g(raw, "redirect_mode"), &json!("")])),
    }))
}

struct RoutingIdentity {
    table: i64,
    priority: i64,
}

fn allocate_ipv6_routing_identity(host: &Host, key: &str, raw: &Value) -> Result<RoutingIdentity> {
    let explicit_table = js::int_value(js::or(g(raw, "ipv6_route_table"), g(raw, "route_table_v6")), 1, 2147483647, 0);
    let explicit_priority = js::int_value(js::or(g(raw, "ipv6_rule_priority"), g(raw, "rule_priority_v6")), 1, 32764, 0);
    let mut used_tables = std::collections::HashSet::new();
    let mut used_priorities = std::collections::HashSet::new();
    let mut records = host.resources_list("profiles")?;
    records.extend(host.resources_list("status")?);
    let own = js::token(&json!(key));
    for record in records.iter().filter(|record| !record.is_null()) {
        if js::token(js::or(g(record, "key"), &json!("default"))) == own {
            continue;
        }
        let data = g(record, "data");
        let table = js::int_value(js::or(g(data, "ipv6_route_table"), g(data, "route_table_v6")), 1, 2147483647, 0);
        let priority = js::int_value(js::or(g(data, "ipv6_rule_priority"), g(data, "rule_priority_v6")), 1, 32764, 0);
        if table != 0 {
            used_tables.insert(table);
        }
        if priority != 0 {
            used_priorities.insert(priority);
            used_priorities.insert(priority + 1);
        }
    }
    if explicit_table != 0 && used_tables.contains(&explicit_table) {
        bail!("ipv6_route_table is already assigned to another WAN profile");
    }
    if explicit_priority != 0 && (used_priorities.contains(&explicit_priority) || used_priorities.contains(&(explicit_priority + 1))) {
        bail!("ipv6_rule_priority overlaps another WAN profile");
    }
    if explicit_table != 0 && explicit_priority != 0 {
        return Ok(RoutingIdentity { table: explicit_table, priority: explicit_priority });
    }
    let start = stable_token_hash(key) as i64 % AUTO_ROUTE_SLOT_COUNT;
    for offset in 0..AUTO_ROUTE_SLOT_COUNT {
        let slot = (start + offset) % AUTO_ROUTE_SLOT_COUNT;
        let table = if explicit_table != 0 { explicit_table } else { AUTO_ROUTE_TABLE_BASE + slot };
        let priority = if explicit_priority != 0 { explicit_priority } else { AUTO_RULE_PRIORITY_BASE + slot * 2 };
        if used_tables.contains(&table) || used_priorities.contains(&priority) || used_priorities.contains(&(priority + 1)) {
            continue;
        }
        return Ok(RoutingIdentity { table, priority });
    }
    bail!("no free IPv6 WAN routing identity is available")
}

fn stable_token_hash(value: &str) -> u32 {
    js::fnv1a(&js::token(&json!(value)))
}

fn ipv6_route_source_prefix(session: &Value) -> String {
    let value = first_text(&[g(session, "pd_prefix"), g(session, "ipv6_prefix")]);
    if !value.is_empty() {
        return value;
    }
    let ipv6 = js::text(g(session, "ipv6"));
    if ipv6.is_empty() {
        String::new()
    } else {
        format!("{ipv6}/128")
    }
}

fn normalize_interface_preparation(value: &Value, mtu: &Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let local_gso = if g(value, "local_gso").is_object() {
        let gso = g(value, "local_gso");
        json!({
            "max_size": js::int_value(g(gso, "max_size"), 576, 65536, js::int_value(mtu, 576, 65536, 1492)),
            "max_segs": js::int_value(g(gso, "max_segs"), 1, 65535, 1),
        })
    } else {
        Value::Null
    };
    let local_offloads = normalize_offload_settings(g(value, "local_offloads"));
    let pipeline_offloads = normalize_offload_settings(g(value, "pipeline_offloads"));
    if local_gso.is_null() && local_offloads.is_null() && pipeline_offloads.is_null() {
        return Value::Null;
    }
    json!({
        "local_gso": local_gso,
        "local_offloads": local_offloads,
        "pipeline_offloads": pipeline_offloads,
        "allow_unsafe_offloads": js::bool_value(g(value, "allow_unsafe_offloads"), false),
    })
}

fn normalize_offload_settings(value: &Value) -> Value {
    let Some(map) = value.as_object() else {
        return Value::Null;
    };
    let mut out = Map::new();
    for name in ["rx", "tx", "sg", "tso", "ufo", "gso", "gro", "lro"] {
        if let Some(setting) = map.get(name) {
            out.insert(name.to_string(), json!(js::is_true(setting)));
        }
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Object(out)
    }
}

fn normalize_handoff_mode(value: &Value) -> String {
    let value = js::lower(value);
    match value.as_str() {
        "direct_gro" => value,
        "segmented" | "segmented_veth" | "veth" | "vtap" => "segmented_veth".to_string(),
        _ => "direct".to_string(),
    }
}

fn derived_pipeline_interface(local_interface: &str, key: &str) -> String {
    let seed = format!("{}|{}", local_interface.trim(), js::token(&json!(key)));
    format!("veerp{:08x}", js::fnv1a(&seed))
}




















fn append_cidr_unique(values: Vec<String>, cidr: &str) -> Vec<String> {
    let cidr = cidr.trim();
    if cidr.is_empty() || values.iter().any(|value| value == cidr) {
        return values;
    }
    let mut out = values;
    out.push(cidr.to_string());
    out
}



fn ipv6_link_local_cidr(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || !value.contains(':') || value.chars().any(|ch| ch.is_whitespace() || ch == '/') {
        return String::new();
    }
    format!("{value}/64")
}

fn append_route_unique(routes: Vec<Value>, route: Value) -> Vec<Value> {
    let dev = js::text(js::or(g(&route, "dev"), &json!("")));
    let wanted = route_request(&dev, &route).map(|request| route_key(&request));
    let mut out = routes;
    if let Some(wanted) = &wanted {
        if out.iter().any(|existing| route_request(&dev, existing).map(|request| &route_key(&request) == wanted).unwrap_or(false)) {
            return out;
        }
    }
    out.push(route);
    out
}

fn append_rule_unique(rules: Vec<Value>, rule: Value) -> Vec<Value> {
    let Some(wanted) = rule_request(&rule) else {
        return rules;
    };
    let wanted = rule_key(&wanted);
    let mut out = rules;
    if out.iter().any(|existing| rule_request(existing).map(|request| rule_key(&request) == wanted).unwrap_or(false)) {
        return out;
    }
    out.push(rule);
    out
}

fn append_neighbor_unique(neighbors: Vec<Value>, neighbor: Value) -> Vec<Value> {
    let dev = js::text(js::first(&[g(&neighbor, "interface"), g(&neighbor, "dev"), &json!("")]));
    let Some(wanted) = neighbor_request(&dev, &neighbor) else {
        return neighbors;
    };
    let wanted = neighbor_key(&wanted);
    let mut out = neighbors;
    if out.iter().any(|existing| neighbor_request(&dev, existing).map(|request| neighbor_key(&request) == wanted).unwrap_or(false)) {
        return out;
    }
    out.push(neighbor);
    out
}

fn normalize_redirect_mode(value: &Value) -> &'static str {
    match js::lower(value).as_str() {
        "prepared_l2" | "raw_l2" | "vtap" => "prepared_l2",
        _ => "",
    }
}



#[cfg(test)]
mod tests;
