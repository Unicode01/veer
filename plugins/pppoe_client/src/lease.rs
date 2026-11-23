//! Session timers: LCP keepalive and its confirmation, redial with backoff,
//! the post-dial control window and DHCPv6 lease renewal. Every timer
//! payload carries the session generation it belongs to, so a timer queued
//! before a disconnect or a redial cannot act on a newer session.

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, json, Result, Value};

use crate::codec::*;
use crate::{error_message, flag, iso_at, iso_now, now, num, s, Ctx, DHCPV6_LEASE_TIMER, DHCPV6_RETRY_MAX_MS, DHCPV6_RETRY_MIN_MS, MAX_TIMER_DELAY_MS, REDIAL_RETRY_TIMER};

pub fn timer_generation(value: &Value) -> String {
    let generation = lower(if truthy(value) { value } else { &Value::Null });
    if generation.len() == 16 && generation.chars().all(|c| c.is_ascii_hexdigit()) {
        generation
    } else {
        String::new()
    }
}

fn redial_resume_phase(phase: &Value) -> bool {
    matches!(lower(phase).as_str(), "redial_wait" | "redial_retry" | "redialing" | "handoff_error")
}

pub fn redial_session_failure(session: &Value) -> String {
    if !truthy(session) {
        return "PPPoE redial returned no session".to_string();
    }
    if truthy(g(session, "message")) {
        return text(&session["message"]);
    }
    if !truthy(g(session, "session_id")) {
        return "PPPoE redial did not allocate a session".to_string();
    }
    if truthy(g(session, "auth_sent")) && !flag(session, "auth_ok") {
        return "PPPoE redial authentication failed".to_string();
    }
    if !flag(session, "lcp_ready") {
        return "PPPoE redial did not reach LCP ready".to_string();
    }
    "PPPoE redial failed".to_string()
}

fn append_error(current: &str, next: &str) -> String {
    if next.is_empty() {
        return current.to_string();
    }
    if current.is_empty() {
        next.to_string()
    } else {
        format!("{current}; {next}")
    }
}

fn dhcpv6_lease_requested(profile: &Value) -> bool {
    flag(profile, "dhcpv6_request") && (flag(profile, "request_ipv6_address") || flag(profile, "request_pd"))
}

fn dhcpv6_next_timer_deadline(lease: &Value, now_ms: f64) -> f64 {
    let at = |key: &str| normalize_timestamp_ms(g(lease, key), 0.0);
    let retry = at("next_retry_at_ms");
    if retry > now_ms {
        return retry;
    }
    let (renew, rebind, expires) = (at("renew_at_ms"), at("rebind_at_ms"), at("expires_at_ms"));
    if renew > now_ms {
        return renew;
    }
    if rebind > now_ms && dhcpv6_lease_has_binding(lease) {
        return now_ms + 10.0;
    }
    if expires > now_ms && dhcpv6_lease_has_binding(lease) {
        return now_ms + 10.0;
    }
    if expires > 0.0 && expires <= now_ms {
        return now_ms + 10.0;
    }
    0.0
}

fn dhcpv6_lease_satisfies_profile(profile: &Value, lease: &Value) -> bool {
    if !truthy(lease) || truthy(g(lease, "lease_timer_error")) {
        return false;
    }
    let addresses = js::array(g(lease, "addresses"));
    let prefixes = js::array(g(lease, "prefixes"));
    if flag(profile, "request_pd") && prefixes.is_empty() {
        return false;
    }
    if flag(profile, "request_ipv6_address")
        && addresses.is_empty()
        && !(flag(profile, "request_pd") && !prefixes.is_empty() && dhcpv6_ia_status_error(lease, "ia_na").is_some())
    {
        return false;
    }
    dhcpv6_lease_has_binding(lease)
}

fn expired_dhcpv6_lease(lease: &Value, message: &str) -> Value {
    merge(
        lease,
        &json!({"phase": "reacquire_retry", "address": "", "addresses": [], "prefix": "", "prefixes": [], "advertise_addresses": [],
            "advertise_prefixes": [], "dns_servers": [], "ia_na_hex": "", "ia_pd_hex": "", "ia_states": [], "renew_seconds": 0, "rebind_seconds": 0,
            "valid_seconds": 0, "renew_at_ms": 0, "rebind_at_ms": 0, "expires_at_ms": 0, "renew_at": "", "rebind_at": "", "expires_at": "",
            "expired_at": iso_now(), "last_renew_error": message}),
    )
}

fn dhcpv6_retry_delay_ms(attempt: &Value) -> f64 {
    let attempt = clamp_int(attempt, 0.0, 30.0, 0.0);
    let exponent = attempt.min(8.0).max(0.0);
    DHCPV6_RETRY_MAX_MS.min(DHCPV6_RETRY_MIN_MS * 2f64.powf(exponent))
}

fn keepalive_failure_started_ms(payload: &Value, now_ms: f64) -> f64 {
    let started = normalize_timestamp_ms(g(payload, "keepalive_failure_started_ms"), 0.0);
    if started == 0.0 || started > now_ms {
        return now_ms;
    }
    started
}

pub fn keepalive_timer_payload(profile: &Value, session: &Value, failures: f64, failure_started_ms: f64) -> Value {
    let mut out = serde_json::Map::new();
    for key in [
        "profile_key", "interface", "mac_mode", "mac_address", "username", "service", "ac_name", "auth", "timeout_ms", "control_ack_timeout_ms",
        "control_idle_timeout_ms", "max_frames", "mru", "negotiate_ipv4", "negotiate_ipv6", "request_ipv6_address", "request_ipv6_router", "request_pd",
        "dhcpv6_request", "dhcpv6_timeout_ms", "ipv6_ra_timeout_ms", "ipv6_iid", "dhcpv6_iaid", "keepalive_interval_ms", "keepalive_failure_threshold",
        "keepalive_failure_grace_ms", "keepalive_confirm_timeout_ms",
    ] {
        if let Some(value) = profile.get(key) {
            out.insert(key.into(), value.clone());
        }
    }
    out.insert("keepalive_failures".into(), js::num(clamp_int(&js::num(failures), 0.0, 1000000.0, 0.0)));
    out.insert("keepalive_failure_started_ms".into(), js::num(normalize_timestamp_ms(&js::num(failure_started_ms), 0.0)));
    for key in [
        "auto_redial", "redial_clear_tunnel", "redial_send_padt", "redial_retry_initial_ms", "redial_retry_max_ms", "install_tunnel", "prepare_interfaces",
        "prepare_local_mtu", "prepare_wan_mtu", "mss_clamp_v4", "mss_clamp_v6", "prepare_offloads", "prepare_gso", "prepare_wan_offloads",
        "allow_unsafe_offloads", "sync_hook_bindings", "apply_hook_bindings", "post_session_control_ms", "decap_mode",
    ] {
        if let Some(value) = profile.get(key) {
            out.insert(key.into(), value.clone());
        }
    }
    out.insert("send_padt".into(), json!(false));
    for key in [
        "local_interface", "pipeline_interface", "wan_interface", "local_ifindex", "pipeline_ifindex", "wan_ifindex", "local_src_mac", "local_dst_mac",
        "wan_src_mac", "wan_dst_mac", "wan_core_sync", "wan_core_required", "wan_core_apply", "wan_core_plugin",
    ] {
        if let Some(value) = profile.get(key) {
            out.insert(key.into(), value.clone());
        }
    }
    if let Some(value) = session.get("session_id") {
        out.insert("session_id".into(), value.clone());
    }
    if let Some(value) = session.get("ac_mac") {
        out.insert("ac_mac".into(), value.clone());
    }
    out.insert("session_generation".into(), json!(timer_generation(g(session, "session_generation"))));
    Value::Object(out)
}

fn session_control_timer_payload(profile: &Value, session: &Value, remaining_ms: f64) -> Value {
    let timeout = num(profile, "timeout_ms");
    json!({"profile_key": profile.get("profile_key"), "interface": profile.get("interface"), "mac_mode": profile.get("mac_mode"),
        "mac_address": profile.get("mac_address"), "timeout_ms": js::num(timeout.min(500.0)), "control_ack_timeout_ms": profile.get("control_ack_timeout_ms"),
        "control_idle_timeout_ms": profile.get("control_idle_timeout_ms"), "max_frames": profile.get("max_frames"), "session_id": session.get("session_id"),
        "ac_mac": session.get("ac_mac"), "session_generation": timer_generation(g(session, "session_generation")), "remaining_ms": js::num(remaining_ms),
        "slice_ms": js::num(500f64.min(timeout.max(50.0)))})
}

impl<'a> Ctx<'a> {
    pub fn new_timer_generation(&self) -> Result<String> {
        self.random_hex(8)
    }

    pub fn persist_runtime_profile(&self, profile: &Value) -> Result<()> {
        let mut data = keepalive_timer_payload(profile, &json!({}), 0.0, 0.0);
        for key in ["wan_id", "disconnect_drain_ms", "dhcpv6_timeout_ms", "dhcpv6_settle_ms", "ipv6_ra_timeout_ms"] {
            data[key] = profile.get(key).cloned().unwrap_or(Value::Null);
        }
        if let Some(map) = data.as_object_mut() {
            for key in ["session_id", "ac_mac", "session_generation", "keepalive_failures"] {
                map.remove(key);
            }
        }
        self.res_set_enabled("profiles", &s(profile, "profile_key"), &data, true)
    }

    pub fn resume_session_timers(&self) -> Result<()> {
        for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER] {
            self.timer_clear(name)?;
        }
        let Some(mut last) = self.res_data("sessions", "last")? else {
            return Ok(());
        };
        let key = token(js::first(&[g(&last, "profile_key"), g(&last, "wan_id"), &json!("default")]));
        let record = self.res_get("profiles", &key)?;
        if record.as_ref().map(|r| js::is_false(g(r, "enabled")) || !truthy(g(r, "data"))).unwrap_or(true) {
            return Ok(());
        }
        let active = flag(&last, "lcp_ready") && !flag(&last, "padt_sent") && truthy(g(&last, "session_id")) && truthy(g(&last, "ac_mac"));
        let resume_redial = redial_resume_phase(g(&last, "phase"));
        if !active && !resume_redial {
            return Ok(());
        }
        if active && timer_generation(g(&last, "session_generation")).is_empty() {
            last = merge(&last, &json!({"session_generation": self.new_timer_generation()?, "desired_state": "up", "updated_at": iso_now()}));
            self.res_set("sessions", "last", &last)?;
        }
        let prepared = (|| -> Result<Option<Value>> {
            let mut profile = self.load_profile(&json!({"profile_key": key}))?;
            if !active && !flag(&profile, "auto_redial") {
                return Ok(None);
            }
            self.prepare_l2_identity(&mut profile)?;
            Ok(Some(profile))
        })();
        let profile = match prepared {
            Ok(Some(profile)) => profile,
            Ok(None) => return Ok(()),
            Err(err) => {
                self.info(&format!("pppoe session timer resume deferred for {key}: {}", error_message(&err)));
                return Ok(());
            }
        };
        if active {
            self.arm_dhcpv6_lease(&profile, &last)?;
            let interval = num(&profile, "keepalive_interval_ms");
            if interval > 0.0 {
                self.timer_timeout("lcp_echo", interval.min(250.0), &keepalive_timer_payload(&profile, &last, 0.0, 0.0))?;
            }
            return Ok(());
        }
        let waiting = self.schedule_redial_retry(
            &profile,
            &json!({"phase": "redial_wait", "profile_key": key, "interface": profile["interface"], "redial_attempted": true,
                "redial_trigger": "runtime_reconcile", "redial_started_at": iso_now(), "redial_generation": timer_generation(g(&last, "redial_generation")),
                "updated_at": iso_now()}),
            clamp_int(g(&last, "redial_next_attempt"), 1.0, 1000000.0, 1.0).max(1.0),
        )?;
        self.record_redial_status(&waiting, &Value::Null)
    }

    fn stored_last_session(&self) -> Result<Option<Value>> {
        self.res_data("sessions", "last")
    }

    pub fn active_stored_session(&self, profile_key: &str) -> Result<Option<Value>> {
        let Some(session) = self.stored_last_session()? else {
            return Ok(None);
        };
        if s(&session, "desired_state") == "down"
            || !flag(&session, "lcp_ready")
            || flag(&session, "padt_sent")
            || !truthy(g(&session, "session_id"))
            || !truthy(g(&session, "ac_mac"))
        {
            return Ok(None);
        }
        let expected = token_str(if profile_key.is_empty() { "default" } else { profile_key });
        let current = token(js::first(&[g(&session, "profile_key"), g(&session, "wan_id"), &json!("default")]));
        Ok(if current == expected { Some(session) } else { None })
    }

    pub fn session_timer_is_current(&self, payload: &Value) -> Result<bool> {
        let key = js::string(js::first(&[g(payload, "profile_key"), g(payload, "profile"), &json!("default")]));
        let Some(current) = self.active_stored_session(&key)? else {
            return Ok(false);
        };
        if clamp_int(g(&current, "session_id"), 1.0, 65535.0, 0.0) != clamp_int(g(payload, "session_id"), 1.0, 65535.0, 0.0) {
            return Ok(false);
        }
        let mac = |v: &Value| mac_text(js::first(&[g(v, "ac_mac"), g(v, "peer_mac"), &json!("")]));
        if mac(&current)? != mac(payload)? {
            return Ok(false);
        }
        Ok(timer_generation(g(&current, "session_generation")) == timer_generation(g(payload, "session_generation")))
    }

    fn redial_timer_is_current(&self, payload: &Value) -> Result<bool> {
        let Some(current) = self.stored_last_session()? else {
            return Ok(false);
        };
        if s(&current, "desired_state") == "down" || !redial_resume_phase(g(&current, "phase")) {
            return Ok(false);
        }
        let expected = token(js::first(&[g(payload, "profile_key"), g(payload, "profile"), &json!("default")]));
        let key = token(js::first(&[g(&current, "profile_key"), g(&current, "wan_id"), &json!("default")]));
        let generation = timer_generation(g(payload, "redial_generation"));
        Ok(key == expected && !generation.is_empty() && generation == timer_generation(g(&current, "redial_generation")))
    }

    pub fn arm_keepalive(&self, profile: &Value, session: &Value, failures: f64, failure_started_ms: f64) -> Result<()> {
        if num(profile, "keepalive_interval_ms") <= 0.0 || !truthy(session) || !truthy(g(session, "session_id")) || !truthy(g(session, "ac_mac")) {
            return self.timer_clear("lcp_echo");
        }
        self.timer_clear(REDIAL_RETRY_TIMER)?;
        self.timer_interval("lcp_echo", num(profile, "keepalive_interval_ms"), &keepalive_timer_payload(profile, session, failures, failure_started_ms))
    }

    pub fn arm_session_control(&self, profile: &Value, session: &Value) -> Result<()> {
        self.timer_clear("session_control")?;
        let control = num(profile, "post_session_control_ms");
        if flag(profile, "send_padt") || control <= 0.0 || !truthy(session) || !truthy(g(session, "session_id")) || !truthy(g(session, "ac_mac")) {
            return Ok(());
        }
        let mut payload = session_control_timer_payload(profile, session, control);
        payload["deadline_ms"] = js::num(now() + control);
        payload["started_at"] = json!(iso_now());
        self.timer_timeout("session_control", 10.0, &payload)
    }

    pub fn arm_dhcpv6_lease(&self, profile: &Value, session: &Value) -> Result<()> {
        self.timer_clear(DHCPV6_LEASE_TIMER)?;
        if !dhcpv6_lease_requested(profile)
            || !truthy(session)
            || flag(session, "padt_sent")
            || !flag(session, "lcp_ready")
            || !truthy(g(session, "session_id"))
            || !truthy(g(session, "ac_mac"))
        {
            return Ok(());
        }
        let lease = js::or(g(session, "dhcpv6_pd"), &json!({})).clone();
        if truthy(g(&lease, "lease_timer_error")) {
            return Ok(());
        }
        let now_ms = now();
        let mut deadline = dhcpv6_next_timer_deadline(&lease, now_ms);
        if deadline == 0.0 {
            if dhcpv6_lease_has_binding(&lease) {
                return Ok(());
            }
            deadline = now_ms + dhcpv6_retry_delay_ms(js::or(g(&lease, "reacquire_attempts"), &json!(0)));
        }
        let delay = 10f64.max(MAX_TIMER_DELAY_MS.min(deadline - now_ms));
        let mut payload = keepalive_timer_payload(profile, session, 0.0, 0.0);
        payload["local_mac"] = js::first(&[g(session, "local_mac"), g(profile, "mac_address"), &json!("")]).clone();
        self.timer_timeout(DHCPV6_LEASE_TIMER, delay, &payload)
    }

    pub fn service_dhcpv6_lease_timer(&self, payload: &Value) -> Result<()> {
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        let Some(session) = self.stored_last_session()? else {
            return Ok(());
        };
        let prepared = (|| -> Result<Value> {
            let mut profile = self.load_profile(payload)?;
            self.prepare_l2_identity(&mut profile)?;
            Ok(profile)
        })();
        let profile = match prepared {
            Ok(profile) => profile,
            Err(err) => return self.record_dhcpv6_lease_failure(None, &session, "prepare", &error_message(&err)),
        };
        if !dhcpv6_lease_requested(&profile) {
            return Ok(());
        }
        let lease = js::or(g(&session, "dhcpv6_pd"), &json!({})).clone();
        let now_ms = now();
        let at = |key: &str| normalize_timestamp_ms(g(&lease, key), 0.0);
        if at("next_retry_at_ms") > now_ms {
            return self.arm_dhcpv6_lease(&profile, &session);
        }
        let (expires, rebind, renew) = (at("expires_at_ms"), at("rebind_at_ms"), at("renew_at_ms"));
        let mut mode = "reacquire";
        if dhcpv6_lease_has_binding(&lease) && (expires == 0.0 || now_ms < expires) {
            if rebind > 0.0 && now_ms >= rebind {
                mode = "rebind";
            } else if renew == 0.0 || now_ms >= renew {
                mode = if truthy(g(&lease, "server_id")) { "renew" } else { "rebind" };
            } else {
                return self.arm_dhcpv6_lease(&profile, &session);
            }
        }
        let outcome = if mode == "reacquire" {
            let local = js::string(js::first(&[g(&session, "local_mac"), g(&profile, "mac_address"), g(payload, "local_mac"), &json!("")]));
            self.request_dhcpv6_pd(&profile, &s(&session, "ac_mac"), num(&session, "session_id") as u64, &local)
        } else {
            self.renew_dhcpv6_lease(&profile, &session, mode)
        };
        let mut result = match outcome {
            Ok(result) => result,
            Err(err) => return self.record_dhcpv6_lease_failure(Some(&profile), &session, mode, &error_message(&err)),
        };
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        if !dhcpv6_lease_satisfies_profile(&profile, &result) {
            let message = js::string(js::first(&[g(&result, "status_message"), g(&result, "message"), g(&result, "phase"),
                &json!("DHCPv6 exchange returned no usable binding")]));
            return self.record_dhcpv6_lease_failure(Some(&profile), &session, mode, &message);
        }
        result["phase"] = json!(match mode {
            "renew" => "renew_reply",
            "rebind" => "rebind_reply",
            _ => "reply",
        });
        for (key, value) in [("next_retry_at_ms", json!(0)), ("next_retry_at", json!("")), ("last_renew_error", json!("")), ("renew_attempts", json!(0)),
            ("rebind_attempts", json!(0)), ("reacquire_attempts", json!(0))]
        {
            result[key] = value;
        }
        let mut updated = merge(&session, &json!({"dhcpv6_pd": result, "updated_at": iso_now()}));
        self.res_set("sessions", "last", &updated)?;
        let link = self.publish_wan_link(&profile, &updated)?;
        let sync = g(&link, "wan_core_sync");
        let synced = truthy(sync) && s(sync, "status") == "synced" && flag(sync, "applied");
        if flag(&profile, "wan_core_required") && !synced {
            updated["dhcpv6_pd"]["wan_core_sync_error"] = if truthy(sync) {
                js::first(&[g(sync, "error"), g(sync, "reason"), g(sync, "status"), &json!("WAN core sync failed")]).clone()
            } else {
                json!("WAN core sync failed")
            };
            self.res_set("sessions", "last", &updated)?;
        }
        self.arm_dhcpv6_lease(&profile, &updated)
    }

    fn renew_dhcpv6_lease(&self, profile: &Value, session: &Value, mode: &str) -> Result<Value> {
        let previous = js::or(g(session, "dhcpv6_pd"), &json!({})).clone();
        let client_id = if truthy(g(&previous, "client_id")) {
            js::string(&previous["client_id"])
        } else {
            dhcpv6_client_id_value(&js::string(js::first(&[g(session, "local_mac"), g(profile, "mac_address"), &json!("02:00:00:00:00:01")])))?
        };
        let server_id = js::string(js::or(g(&previous, "server_id"), &json!("")));
        let mut mode = mode.to_string();
        if mode == "renew" && server_id.is_empty() {
            mode = "rebind".to_string();
        }
        if !truthy(g(&previous, "ia_na_hex")) && !truthy(g(&previous, "ia_pd_hex")) {
            bail!("DHCPv6 lease has no IA binding to renew");
        }
        let xid = self.random_hex(3)?;
        let ia_na = js::string(js::or(g(&previous, "ia_na_hex"), &json!("")));
        let ia_pd = js::string(js::or(g(&previous, "ia_pd_hex"), &json!("")));
        let request = if mode == "renew" {
            dhcpv6_stateful_request(DHCPV6_RENEW, &xid, &client_id, &server_id, &ia_na, &ia_pd)
        } else {
            dhcpv6_stateful_request(DHCPV6_REBIND, &xid, &client_id, "", &ia_na, &ia_pd)
        };
        let src = if truthy(g(&previous, "source_address")) {
            js::string(&previous["source_address"])
        } else {
            let iid = if s(profile, "ipv6_iid").is_empty() { self.random_hex(8)? } else { s(profile, "ipv6_iid") };
            link_local_from_iid(&iid)?
        };
        let Some(frame) = self.exchange_dhcpv6(profile, &s(session, "ac_mac"), num(session, "session_id") as u64, &src, "ff02::1:2", &request, &xid)? else {
            return Ok(json!({"phase": format!("{mode}_timeout"), "transaction_id": xid}));
        };
        let reply = match crate::session::parse_dhcpv6_reply_frame(&frame, &xid)? {
            Err(error) => return Ok(error),
            Ok(reply) => reply,
        };
        if reply.message_type != DHCPV6_REPLY {
            return Ok(json!({"phase": format!("{mode}_unexpected_message"), "message_type": reply.message_type, "transaction_id": xid}));
        }
        if let Some((code, message)) = dhcpv6_top_level_status(&reply.options) {
            if code != 0 {
                return Ok(json!({"phase": format!("{mode}_status_error"), "status_code": code, "status_message": message, "transaction_id": xid}));
            }
        }
        let leased = dhcpv6_lease_data(&reply.options);
        let has_addresses = !js::array(&leased["addresses"]).is_empty();
        let has_prefixes = !js::array(&leased["prefixes"]).is_empty();
        let reply_server = first_dhcpv6_option_hex(&reply.options, DHCPV6_OPT_SERVERID);
        let dns = if js::array(&leased["dns_servers"]).is_empty() { js::or(g(&previous, "dns_servers"), &json!([])).clone() } else { leased["dns_servers"].clone() };
        let result = json!({"phase": format!("{mode}_reply"), "transaction_id": xid, "server_id": if reply_server.is_empty() { server_id } else { reply_server },
            "client_id": client_id, "iaid": profile.get("dhcpv6_iaid"), "source_address": src, "address": js::or(g(&leased, "address"), &json!("")),
            "addresses": leased["addresses"], "prefix": js::or(g(&leased, "prefix"), &json!("")), "prefixes": leased["prefixes"], "dns_servers": dns,
            "ia_na_hex": if has_addresses { leased["ia_na_hex"].clone() } else { json!("") }, "ia_pd_hex": if has_prefixes { leased["ia_pd_hex"].clone() } else { json!("") },
            "ia_states": leased["ia_states"], "ia_statuses": merge_by_type(&leased["ia_statuses"], g(&previous, "ia_statuses")), "renewed_at": iso_now()});
        let mut result = stamp_dhcpv6_lease(result, now());
        crate::session::annotate_dhcpv6_partial_binding(profile, &mut result);
        if !crate::session::dhcpv6_iaids_match(profile, &result["ia_states"]) {
            return Ok(json!({"phase": format!("{mode}_iaid_mismatch"), "transaction_id": xid}));
        }
        Ok(result)
    }

    fn record_dhcpv6_lease_failure(&self, profile: Option<&Value>, session: &Value, mode: &str, message: &str) -> Result<()> {
        if !truthy(session) {
            return Ok(());
        }
        let loaded;
        let profile = match profile {
            Some(profile) => profile,
            None => match self.load_profile(&json!({"profile_key": js::first(&[g(session, "profile_key"), g(session, "wan_id"), &json!("default")])})) {
                Ok(profile) => {
                    loaded = profile;
                    &loaded
                }
                Err(_) => {
                    self.info(&format!("DHCPv6 lease retry deferred: {message}"));
                    return Ok(());
                }
            },
        };
        let now_ms = now();
        let mut lease = merge(js::or(g(session, "dhcpv6_pd"), &json!({})), &json!({"phase": format!("{mode}_retry"), "last_renew_error": message, "last_renew_error_at": iso_at(now_ms)}));
        let counter = match mode {
            "renew" => "renew_attempts",
            "rebind" => "rebind_attempts",
            _ => "reacquire_attempts",
        };
        lease[counter] = js::num(clamp_int(g(&lease, counter), 0.0, 1000000.0, 0.0) + 1.0);
        let expires = normalize_timestamp_ms(g(&lease, "expires_at_ms"), 0.0);
        if expires > 0.0 && now_ms >= expires {
            lease = expired_dhcpv6_lease(&lease, message);
        }
        let mut retry_at = now_ms + dhcpv6_retry_delay_ms(g(&lease, counter));
        let boundary = if mode == "renew" { normalize_timestamp_ms(g(&lease, "rebind_at_ms"), 0.0) } else { normalize_timestamp_ms(g(&lease, "expires_at_ms"), 0.0) };
        if boundary > now_ms && retry_at > boundary {
            retry_at = boundary;
        }
        lease["next_retry_at_ms"] = js::num(retry_at);
        lease["next_retry_at"] = json!(iso_at(retry_at));
        let updated = merge(session, &json!({"dhcpv6_pd": lease, "updated_at": iso_now()}));
        self.res_set("sessions", "last", &updated)?;
        if !dhcpv6_lease_has_binding(&updated["dhcpv6_pd"]) {
            self.publish_wan_link(profile, &updated)?;
        }
        self.arm_dhcpv6_lease(profile, &updated)
    }

    // -------------------------------------------------------- keepalive

    pub fn service_lcp_echo_timer(&self, payload: &Value) -> Result<()> {
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        let mut profile = self.load_profile(payload)?;
        let session_id = clamp_int(g(payload, "session_id"), 1.0, 65535.0, 0.0) as u64;
        let peer = mac_text(js::first(&[g(payload, "ac_mac"), g(payload, "peer_mac"), &json!("")]))?;
        if session_id == 0 || peer.is_empty() {
            bail!("lcp_echo timer requires session_id and ac_mac");
        }
        let mut result = match self.prepare_l2_identity(&mut profile).and_then(|_| self.send_lcp_echo(&profile, &peer, session_id)) {
            Ok(result) => result,
            Err(err) => crate::base_result(&profile, "keepalive_error", json!({"session_id": session_id, "ac_mac": peer, "message": error_message(&err)})),
        };
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        let mut failures = clamp_int(g(payload, "keepalive_failures"), 0.0, 1000000.0, 0.0);
        let threshold = num(&profile, "keepalive_failure_threshold");
        let grace = num(&profile, "keepalive_failure_grace_ms");
        if s(&result, "phase") == "keepalive_ok" {
            result["keepalive_failures"] = json!(0);
            result["keepalive_failure_threshold"] = profile["keepalive_failure_threshold"].clone();
            result["keepalive_failure_grace_ms"] = profile["keepalive_failure_grace_ms"].clone();
            self.arm_keepalive(&profile, payload, 0.0, 0.0)?;
        } else {
            let now_ms = now();
            let started = keepalive_failure_started_ms(payload, now_ms);
            failures += 1.0;
            let elapsed = (now_ms - started).max(0.0);
            result["keepalive_failures"] = js::num(failures);
            result["keepalive_failure_threshold"] = profile["keepalive_failure_threshold"].clone();
            result["keepalive_failure_started_at"] = json!(iso_at(started));
            result["keepalive_failure_elapsed_ms"] = js::num(elapsed);
            result["keepalive_failure_grace_ms"] = profile["keepalive_failure_grace_ms"].clone();
            result["keepalive_grace_remaining_ms"] = js::num((grace - elapsed).max(0.0));
            if failures >= threshold && elapsed >= grace {
                let confirmation = self.confirm_lcp_echo(&profile, &peer, session_id);
                if s(&confirmation, "phase") == "keepalive_ok" {
                    result = merge(&confirmation, &json!({"keepalive_failures": 0, "keepalive_failure_threshold": profile["keepalive_failure_threshold"],
                        "keepalive_failure_grace_ms": profile["keepalive_failure_grace_ms"], "keepalive_confirmation": "recovered",
                        "keepalive_recovered_after_failures": js::num(failures)}));
                    self.arm_keepalive(&profile, payload, 0.0, 0.0)?;
                } else {
                    result = merge(&result, &json!({"phase": confirmation["phase"], "keepalive_confirmation": confirmation,
                        "keepalive_confirm_timeout_ms": profile["keepalive_confirm_timeout_ms"]}));
                    if flag(&profile, "auto_redial") {
                        result = self.redial_after_keepalive_failure(&mut profile, &result, payload)?;
                    } else if flag(&profile, "redial_clear_tunnel") {
                        self.timer_clear("lcp_echo")?;
                        self.timer_clear(DHCPV6_LEASE_TIMER)?;
                        self.clear_tunnel_config()?;
                        self.mark_wan_link_down(&profile, payload, &s(&result, "phase"))?;
                    } else {
                        self.arm_keepalive(&profile, payload, failures, started)?;
                    }
                }
            } else {
                self.arm_keepalive(&profile, payload, failures, started)?;
            }
        }
        self.res_set("sessions", "keepalive", &result)
    }

    // -------------------------------------------------------- redial

    fn redial_after_keepalive_failure(&self, profile: &mut Value, keepalive: &Value, previous: &Value) -> Result<Value> {
        for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER] {
            self.timer_clear(name)?;
        }
        let mut base = merge(keepalive, &json!({"redial_attempted": true, "redial_started_at": iso_now(),
            "redial_trigger": js::or(g(keepalive, "phase"), &json!("keepalive_timeout"))}));
        if flag(profile, "redial_send_padt") {
            let peer = mac_text(js::or(g(previous, "ac_mac"), &json!("")));
            let id = clamp_int(g(previous, "session_id"), 1.0, 65535.0, 0.0) as u64;
            let outcome = peer.and_then(|peer| {
                if !peer.is_empty() && id != 0 {
                    self.send_padt(profile, &peer, id, 0.0)?;
                    return Ok(true);
                }
                Ok(false)
            });
            match outcome {
                Ok(true) => base["previous_session_padt_sent"] = json!(true),
                Ok(false) => {}
                Err(err) => base["previous_session_close_error"] = json!(error_message(&err)),
            }
        }
        if flag(profile, "redial_clear_tunnel") {
            self.clear_tunnel_config()?;
        }
        self.mark_wan_link_down(profile, if truthy(previous) { previous } else { &Value::Null }, "redial_wait")?;
        let waiting = self.schedule_redial_retry(profile, &base, 1.0)?;
        self.record_redial_status(&waiting, &Value::Null)?;
        self.record_redial_diagnostic(&waiting)?;
        Ok(waiting)
    }

    pub fn service_redial_retry_timer(&self, payload: &Value) -> Result<()> {
        if !self.redial_timer_is_current(payload)? {
            return Ok(());
        }
        let mut profile = self.load_profile(payload)?;
        let attempt = clamp_int(g(payload, "redial_attempt"), 1.0, 1000000.0, 1.0);
        let base = json!({"phase": "redialing", "profile_key": profile["profile_key"], "interface": profile["interface"], "mac_mode": profile["mac_mode"],
            "mac_address": js::or(g(&profile, "mac_address"), &json!("")), "service": profile["service"], "auth": profile["auth"], "redial_attempted": true,
            "redial_attempt": js::num(attempt), "redial_generation": timer_generation(g(payload, "redial_generation")),
            "redial_trigger": text(js::or(g(payload, "redial_trigger"), &json!("retry"))),
            "redial_started_at": text(&if truthy(g(payload, "redial_started_at")) { payload["redial_started_at"].clone() } else { json!(iso_now()) }),
            "updated_at": iso_now()});
        let result = self.attempt_redial(&mut profile, &base, attempt)?;
        self.res_set("sessions", "keepalive", &result)?;
        self.record_redial_diagnostic(&result)
    }

    fn attempt_redial(&self, profile: &mut Value, base: &Value, attempt: f64) -> Result<Value> {
        let mut session = Value::Null;
        let outcome = (|| -> Result<Value> {
            self.prepare_l2_identity(profile)?;
            profile["send_padt"] = json!(false);
            session = self.probe_session(profile)?;
            if !truthy(&session) || !truthy(g(&session, "session_id")) || !flag(&session, "lcp_ready") {
                bail!("{}", redial_session_failure(&session));
            }
            let recorded = self.record_session(profile, session.clone())?.1;
            session = recorded.clone();
            self.arm_session_control(profile, &recorded)?;
            self.arm_keepalive(profile, &recorded, 0.0, 0.0)?;
            self.arm_dhcpv6_lease(profile, &recorded)?;
            self.timer_clear(REDIAL_RETRY_TIMER)?;
            Ok(merge(base, &json!({"phase": "redial_ok", "redial_phase": js::or(g(&recorded, "phase"), &json!("unknown")),
                "redial_session_id": js::or(g(&recorded, "session_id"), &json!(0)), "redial_tunnel_installed": flag(&recorded, "tunnel_installed"),
                "redial_updated_at": iso_now()})))
        })();
        match outcome {
            Ok(result) => Ok(result),
            Err(err) => {
                let mut cleanup = self.cleanup_failed_redial_session(profile, &session);
                if let Err(clear) = self.clear_tunnel_config() {
                    cleanup = append_error(&cleanup, &format!("clear tunnel: {}", error_message(&clear)));
                }
                self.mark_wan_link_down(profile, if truthy(&session) { &session } else { &Value::Null }, "redial_retry")?;
                let failed = merge(base, &json!({"phase": "redial_retry", "redial_attempt": js::num(attempt),
                    "redial_phase": if truthy(&session) && truthy(g(&session, "phase")) { session["phase"].clone() } else { json!("error") },
                    "redial_error": error_message(&err), "redial_cleanup_error": cleanup, "redial_updated_at": iso_now()}));
                let waiting = self.schedule_redial_retry(profile, &failed, attempt + 1.0)?;
                self.record_redial_status(&waiting, &session)?;
                Ok(waiting)
            }
        }
    }

    fn cleanup_failed_redial_session(&self, profile: &Value, session: &Value) -> String {
        if !truthy(session) || !truthy(g(session, "session_id")) || !truthy(g(session, "ac_mac")) {
            return String::new();
        }
        match self.send_padt(profile, &s(session, "ac_mac"), num(session, "session_id") as u64, 0.0) {
            Ok(_) => String::new(),
            Err(err) => format!("close failed session: {}", error_message(&err)),
        }
    }

    fn schedule_redial_retry(&self, profile: &Value, result: &Value, attempt: f64) -> Result<Value> {
        let generation = timer_generation(g(result, "redial_generation"));
        let result = merge(if truthy(result) { result } else { &Value::Null }, &json!({"desired_state": "up",
            "redial_generation": if generation.is_empty() { self.new_timer_generation()? } else { generation }}));
        let exponent = (attempt - 1.0).max(0.0).min(16.0);
        let delay = num(profile, "redial_retry_max_ms").min(num(profile, "redial_retry_initial_ms") * 2f64.powf(exponent));
        let mut payload = keepalive_timer_payload(profile, &json!({}), 0.0, 0.0);
        payload["redial_attempt"] = js::num(attempt);
        payload["redial_generation"] = json!(timer_generation(g(&result, "redial_generation")));
        payload["redial_trigger"] = json!(text(js::or(g(&result, "redial_trigger"), &json!("retry"))));
        payload["redial_started_at"] = json!(text(&if truthy(g(&result, "redial_started_at")) { result["redial_started_at"].clone() } else { json!(iso_now()) }));
        self.timer_timeout(REDIAL_RETRY_TIMER, delay, &payload)?;
        Ok(merge(&result, &json!({"phase": "redial_wait", "redial_attempt": js::num((attempt - 1.0).max(0.0)), "redial_next_attempt": js::num(attempt),
            "redial_retry_in_ms": js::num(delay), "updated_at": iso_now()})))
    }

    fn record_redial_status(&self, result: &Value, session: &Value) -> Result<()> {
        let previous = self.res_data("sessions", "last")?.unwrap_or(json!({}));
        let mut status = merge(&previous, &json!({"phase": result.get("phase"), "lcp_ready": false, "tunnel_installed": false, "redial_attempted": true,
            "desired_state": "up", "redial_generation": timer_generation(g(result, "redial_generation")),
            "redial_attempt": js::or(g(result, "redial_attempt"), &json!(0)), "redial_next_attempt": js::or(g(result, "redial_next_attempt"), &json!(0)),
            "redial_retry_in_ms": js::or(g(result, "redial_retry_in_ms"), &json!(0)), "redial_error": js::or(g(result, "redial_error"), &json!("")),
            "redial_phase": js::or(g(result, "redial_phase"), &json!("")), "updated_at": iso_now()}));
        if truthy(session) && truthy(g(session, "message")) {
            status["message"] = session["message"].clone();
        }
        self.res_set("sessions", "last", &status)
    }

    fn record_redial_diagnostic(&self, result: &Value) -> Result<()> {
        let previous = self.res_data("sessions", "redial_last")?.unwrap_or(json!({}));
        let c = |v: &Value, key: &str, max: f64| clamp_int(g(v, key), 0.0, max, 0.0);
        let starting = c(result, "redial_attempt", 1000000.0) == 0.0 && c(result, "redial_next_attempt", 1000000.0) == 1.0;
        let pick = |values: &[&Value]| text(js::first(values));
        self.res_set("sessions", "redial_last", &json!({
            "count": js::num(c(&previous, "count", 1000000.0) + if starting { 1.0 } else { 0.0 }),
            "phase": text(js::or(g(result, "phase"), &json!("unknown"))),
            "trigger": pick(&[g(result, "redial_trigger"), g(&previous, "trigger"), &json!("")]),
            "attempt": js::num(c(result, "redial_attempt", 1000000.0)), "next_attempt": js::num(c(result, "redial_next_attempt", 1000000.0)),
            "retry_in_ms": js::num(c(result, "redial_retry_in_ms", 3600000.0)),
            "session_id": js::num(clamp_int(js::or(g(result, "redial_session_id"), g(result, "session_id")), 0.0, 65535.0, 0.0)),
            "error": text(js::or(g(result, "redial_error"), &json!(""))),
            "started_at": pick(&[g(result, "redial_started_at"), g(&previous, "started_at"), &json!("")]),
            "updated_at": text(&if truthy(js::or(g(result, "redial_updated_at"), g(result, "updated_at"))) {
                js::or(g(result, "redial_updated_at"), g(result, "updated_at")).clone()
            } else {
                json!(iso_now())
            }),
        }))
    }
}
