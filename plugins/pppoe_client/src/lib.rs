//! PPPoE Client: PPPoE discovery, PAP/CHAP authentication, IPCP/IPv6CP,
//! router advertisements and DHCPv6 address/prefix delegation over raw L2,
//! a bidirectional TC tunnel between the physical interface and one local
//! Linux L3 boundary, LCP keepalive with redial, and the WAN Core handoff.

#![recursion_limit = "256"]

pub mod codec;
mod lease;
mod session;

use codec::*;
use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, export_plugin, json, Error, Host, Message, Outcome, Plugin, Result, Value};

pub(crate) const ETH_P_PPP_DISC: &str = "0x8863";
pub(crate) const ETH_P_PPP_SESS: &str = "0x8864";
pub(crate) const TUNNEL_CONFIG_RESOURCE: &str = "tunnel_configs";
pub(crate) const TUNNEL_CONFIG_KEY: &str = "active";
pub(crate) const TUNNEL_REPAIR_TIMER: &str = "tunnel_repair";
pub(crate) const REDIAL_RETRY_TIMER: &str = "redial_retry";
pub(crate) const DHCPV6_LEASE_TIMER: &str = "dhcpv6_lease";
const LEGACY_TUNNEL_CONFIG_HEX_BYTES: usize = 48;
const TUNNEL_CONFIG_HEX_BYTES: usize = 52;
pub(crate) const MAX_L2_RECV_TIMEOUT_MS: f64 = 5000.0;
pub(crate) const MAX_TIMER_DELAY_MS: f64 = 86399999.0;
pub(crate) const DHCPV6_RETRY_MIN_MS: f64 = 1000.0;
pub(crate) const DHCPV6_RETRY_MAX_MS: f64 = 300000.0;
pub(crate) const L2_IDENTITY_RESOURCE: &str = "l2_identities";
const DEFAULT_KEEPALIVE_FAILURE_THRESHOLD: f64 = 5.0;
const DEFAULT_KEEPALIVE_FAILURE_GRACE_MS: f64 = 60000.0;
const DEFAULT_KEEPALIVE_CONFIRM_TIMEOUT_MS: f64 = 5000.0;
const TUNNEL_STATS_BUILD_NOTE: &str =
    "Per-packet tunnel counters are compiled out in the default object. Rebuild with PPPOE_TUNNEL_DIAG=1 to enable non-zero diagnostic counters.";
const KFUNCS_FEATURE: &str = "dataplane.kfuncs.handoff.v1";
const DIRECT_FEATURE: &str = "dataplane.kfuncs.wan.v1";

#[cfg(test)]
thread_local! {
    /// Tests move the plugin's clock forward with this.
    pub(crate) static CLOCK_SHIFT: std::cell::Cell<f64> = const { std::cell::Cell::new(0.0) };
}

pub(crate) fn now() -> f64 {
    let base = js::now_ms() as f64;
    #[cfg(test)]
    return base + CLOCK_SHIFT.with(|shift| shift.get());
    #[cfg(not(test))]
    base
}

pub(crate) fn iso_now() -> String {
    js::iso_time(now() as u64)
}

pub(crate) fn iso_at(ms: f64) -> String {
    js::iso_time(ms.max(0.0) as u64)
}

pub struct PppoeClient {
    /// (kfuncs, direct), learned on the first message.
    features: Option<(bool, bool)>,
}

impl Plugin for PppoeClient {
    fn create(_host: &Host, _config: &Value) -> Result<Self> {
        Ok(PppoeClient { features: None })
    }

    fn handle(&mut self, host: &Host, msg: &Message) -> Result<Outcome> {
        if self.features.is_none() {
            let info = host.call("plugin.host", json!([])).unwrap_or(Value::Null);
            let has = |name: &str| js::array(g(&info, "available_features")).iter().any(|f| f.as_str() == Some(name));
            let kfuncs = has(KFUNCS_FEATURE);
            self.features = Some((kfuncs, kfuncs && has(DIRECT_FEATURE)));
        }
        let (kfuncs, direct) = self.features.unwrap();
        let ctx = Ctx { host, kfuncs, direct };
        let c = &msg.ctx;
        match msg.handler.as_str() {
            "onUpgradeSnapshot" => {
                // Negotiated session state is persisted in resources and tunnel
                // maps. Opting into handoff keeps host-owned timers and sockets
                // attached to the new instance.
                Ok(Outcome::Value(json!({"schema_version": 1})))
            }
            "onUpgradeRestore" => {
                let state = g(g(c, "upgrade"), "state");
                if truthy(state) && !js::strict_eq(g(state, "schema_version"), &json!(1)) {
                    bail!("unsupported PPPoE upgrade state schema: {}", js::string(g(state, "schema_version")));
                }
                Ok(Outcome::Done)
            }
            "onReconcile" => {
                ctx.on_reconcile()?;
                Ok(Outcome::Done)
            }
            "onDeactivate" => {
                ctx.on_deactivate()?;
                Ok(Outcome::Done)
            }
            "onResourceApply" => {
                ctx.on_resource_apply(c)?;
                Ok(Outcome::Done)
            }
            "onTimer" => {
                ctx.on_timer(c)?;
                Ok(Outcome::Done)
            }
            "onAction" => match ctx.on_action(c)? {
                Some(value) => Ok(Outcome::Value(value)),
                None => Ok(Outcome::Done),
            },
            _ => Ok(Outcome::Unhandled),
        }
    }
}

export_plugin!(PppoeClient, "pppoe_client");

pub(crate) struct Ctx<'a> {
    pub host: &'a Host,
    pub kfuncs: bool,
    pub direct: bool,
}

/// The local boundary of the tunnel: a veth pair, or the direct helper netdev.
pub(crate) struct Boundary {
    pub mode: &'static str,
    pub local: Value,
    pub pipeline: Option<Value>,
}

pub(crate) fn s(value: &Value, key: &str) -> String {
    text(g(value, key))
}

pub(crate) fn num(value: &Value, key: &str) -> f64 {
    js::number(g(value, key))
}

pub(crate) fn flag(value: &Value, key: &str) -> bool {
    js::is_true(g(value, key))
}

pub(crate) fn error_message(err: &Error) -> String {
    err.to_string()
}

impl<'a> Ctx<'a> {
    // -------------------------------------------------------- host calls

    pub fn res_get(&self, resource: &str, key: &str) -> Result<Option<Value>> {
        self.host.resources_get(resource, key)
    }

    /// `record && record.data ? record.data : null`.
    pub fn res_data(&self, resource: &str, key: &str) -> Result<Option<Value>> {
        Ok(self.res_get(resource, key)?.and_then(|r| r.get("data").cloned()).filter(truthy))
    }

    pub fn res_set(&self, resource: &str, key: &str, data: &Value) -> Result<()> {
        self.host.call("resources.set", json!([resource, key, data]))?;
        Ok(())
    }

    pub fn res_set_enabled(&self, resource: &str, key: &str, data: &Value, enabled: bool) -> Result<()> {
        self.host.call("resources.set", json!([resource, key, data, enabled]))?;
        Ok(())
    }

    pub fn res_set_apply(&self, resource: &str, key: &str, data: &Value, enabled: bool, apply: bool) -> Result<()> {
        self.host.call("resources.set", json!([resource, key, data, enabled, apply]))?;
        Ok(())
    }

    pub fn res_delete(&self, resource: &str, key: &str) -> Result<()> {
        self.host.call("resources.delete", json!([resource, key]))?;
        Ok(())
    }

    pub fn res_list(&self, resource: &str) -> Result<Vec<Value>> {
        Ok(js::array(&self.host.call("resources.list", json!([resource]))?))
    }

    pub fn timer_clear(&self, name: &str) -> Result<()> {
        self.host.timer_clear(name)
    }

    pub fn timer_timeout(&self, name: &str, delay: f64, payload: &Value) -> Result<()> {
        self.host.call("timer.setTimeout", json!([name, js::num(delay), payload]))?;
        Ok(())
    }

    pub fn timer_interval(&self, name: &str, delay: f64, payload: &Value) -> Result<()> {
        self.host.call("timer.setInterval", json!([name, js::num(delay), payload]))?;
        Ok(())
    }

    pub fn link_get(&self, name: &str) -> Result<Value> {
        self.host.call("net.link.get", json!([name]))
    }

    pub fn random_hex(&self, length: u64) -> Result<String> {
        Ok(js::string(&self.host.call("crypto.randomBytes", json!([length]))?))
    }

    pub fn random_byte(&self) -> Result<u64> {
        Ok(u64::from_str_radix(&self.random_hex(1)?, 16).unwrap_or(0))
    }

    pub fn info(&self, message: &str) {
        self.host.info(message);
    }

    pub fn map_get(&self, map: &str, key: &str) -> Result<Value> {
        self.host.call("ebpf.mapGet", json!(["pppoe_tunnel", map, key]))
    }

    pub fn map_put(&self, map: &str, key: &str, value: &str) -> Result<()> {
        self.host.call("ebpf.mapPut", json!(["pppoe_tunnel", map, key, value]))?;
        Ok(())
    }

    fn dataplane(&self) -> &'static str {
        if self.kfuncs {
            "kfuncs"
        } else {
            "bpf"
        }
    }

    // -------------------------------------------------------- handlers

    fn on_reconcile(&self) -> Result<()> {
        if let Err(err) = self.apply_stored_tunnel_config(false) {
            self.info(&format!("pppoe tunnel config replay deferred: {}", error_message(&err)));
        }
        self.arm_tunnel_repair()?;
        self.resume_session_timers()
    }

    fn on_deactivate(&self) -> Result<()> {
        for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER, TUNNEL_REPAIR_TIMER] {
            self.timer_clear(name)?;
        }
        let mut failures = Vec::new();
        if let Err(err) = self.clear_tunnel_config() {
            failures.push(format!("clear tunnel: {}", error_message(&err)));
            if let Err(map_error) = self.clear_tunnel_map(false) {
                failures.push(format!("clear tunnel map: {}", error_message(&map_error)));
            }
        }
        if let Some(session) = self.res_data("sessions", "last")? {
            if truthy(g(&session, "session_id")) && truthy(g(&session, "ac_mac")) {
                let profile_key = token(js::first(&[g(&session, "profile_key"), g(&session, "wan_id"), &json!("default")]));
                let outcome = (|| -> Result<()> {
                    let mut profile = self.load_profile(&merge(&session, &json!({"profile_key": profile_key, "send_padt": true})))?;
                    self.resolve_l2_identity(&mut profile)?;
                    self.disconnect_session(&profile, &session)?;
                    Ok(())
                })();
                if let Err(err) = outcome {
                    failures.push(format!("disconnect {profile_key}: {}", error_message(&err)));
                    if let Err(sync) = self.fail_close_wan_core_from_stored(&profile_key, &session, "deactivated") {
                        failures.push(format!("fail-close {profile_key}: {}", error_message(&sync)));
                    }
                }
            }
        }
        for link in self.res_list("wan_links")? {
            if !truthy(&link) {
                continue;
            }
            let key = token(js::or(g(&link, "key"), &json!("default")));
            let outcome = (|| -> Result<()> {
                let data = js::or(g(&link, "data"), &json!({})).clone();
                self.fail_close_wan_core_from_stored(&key, &data, "deactivated")?;
                let down = merge(&data, &json!({"state": "down", "usable": false, "phase": "deactivated", "updated_at": iso_now()}));
                self.res_set_enabled("wan_links", &key, &down, false)
            })();
            if let Err(err) = outcome {
                failures.push(format!("WAN link {key}: {}", error_message(&err)));
            }
        }
        for identity in self.res_list(L2_IDENTITY_RESOURCE)? {
            if !truthy(&identity) {
                continue;
            }
            let key = token(js::or(g(&identity, "key"), &json!("default")));
            if let Err(err) = self.cleanup_l2_identity(&key, true) {
                failures.push(format!("L2 identity {key}: {}", error_message(&err)));
            }
        }
        if !failures.is_empty() {
            bail!("PPPoE deactivate cleanup failed: {}", failures.join("; "));
        }
        Ok(())
    }

    fn on_resource_apply(&self, c: &Value) -> Result<()> {
        if s(g(c, "resource"), "id") != TUNNEL_CONFIG_RESOURCE {
            return Ok(());
        }
        let records = self.current_tunnel_config_records(js::array(g(c, "records")))?;
        self.apply_tunnel_config_records(&records, true)?;
        self.arm_tunnel_repair()
    }

    fn on_timer(&self, c: &Value) -> Result<()> {
        let timer = g(c, "timer");
        if !truthy(timer) {
            return Ok(());
        }
        let payload = js::or(g(timer, "payload"), &json!({})).clone();
        match s(timer, "name").as_str() {
            TUNNEL_REPAIR_TIMER => {
                self.apply_stored_tunnel_config(false)?;
                self.arm_tunnel_repair()
            }
            "session_control" => self.service_session_control_timer(&payload),
            REDIAL_RETRY_TIMER => self.service_redial_retry_timer(&payload),
            DHCPV6_LEASE_TIMER => self.service_dhcpv6_lease_timer(&payload),
            "lcp_echo" => self.service_lcp_echo_timer(&payload),
            _ => Ok(()),
        }
    }

    fn on_action(&self, c: &Value) -> Result<Option<Value>> {
        let action = s(g(c, "action"), "id");
        let payload = js::or(g(c, "payload"), &json!({})).clone();
        if action == "clear_state" {
            let key = token(js::first(&[g(&payload, "profile_key"), g(&payload, "profile"), &json!("default")]));
            self.fail_close_wan_core_from_stored(&key, &payload, "cleared")?;
            for record in ["last", "keepalive", "control", "redial_last"] {
                self.res_delete("sessions", record)?;
            }
            self.res_delete("wan_links", &key)?;
            for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER, TUNNEL_REPAIR_TIMER] {
                self.timer_clear(name)?;
            }
            self.clear_tunnel_config()?;
            self.cleanup_l2_identity(&key, true)?;
            return Ok(None);
        }
        if action == "debug_stats" {
            self.res_set("sessions", "debug_stats", &json!({"phase": "debug_stats", "stats": self.read_tunnel_stats()}))?;
            return Ok(None);
        }
        if action == "traffic_stats" {
            return Ok(Some(self.read_traffic_stats(&payload)?));
        }
        let mut profile = self.load_profile(&payload)?;
        if action == "disconnect" {
            self.resolve_l2_identity(&mut profile)?;
        } else {
            self.prepare_l2_identity(&mut profile)?;
        }
        match action.as_str() {
            "discover" => {
                let discovery = self.discover(&profile)?;
                self.res_set("sessions", "last", &discovery)?;
            }
            "probe_session" => {
                let session = self.probe_session(&mut profile)?;
                self.record_session(&profile, session)?;
            }
            "traffic_probe" => {
                self.timer_clear(REDIAL_RETRY_TIMER)?;
                profile["install_tunnel"] = json!(true);
                if !has_own(&payload, "send_padt") {
                    profile["send_padt"] = json!(false);
                }
                self.persist_runtime_profile(&profile)?;
                let session = self.probe_session(&mut profile)?;
                let session = self.record_session(&profile, session)?.1;
                require_installed_tunnel(&session)?;
                self.arm_session_control(&profile, &session)?;
                self.arm_keepalive(&profile, &session, 0.0, 0.0)?;
                self.arm_dhcpv6_lease(&profile, &session)?;
            }
            "dial" => {
                self.timer_clear(REDIAL_RETRY_TIMER)?;
                if self.active_stored_session(&s(&profile, "profile_key"))?.is_some() {
                    return Ok(None);
                }
                if !has_own(&payload, "send_padt") {
                    profile["send_padt"] = json!(false);
                }
                self.persist_runtime_profile(&profile)?;
                let session = self.probe_session(&mut profile)?;
                let session = self.record_session(&profile, session)?.1;
                self.arm_session_control(&profile, &session)?;
                self.arm_keepalive(&profile, &session, 0.0, 0.0)?;
                self.arm_dhcpv6_lease(&profile, &session)?;
            }
            "disconnect" => {
                self.disconnect_session(&profile, &payload)?;
            }
            other => bail!("unsupported action {other}"),
        }
        Ok(None)
    }

    // -------------------------------------------------------- profiles

    pub fn load_profile(&self, payload: &Value) -> Result<Value> {
        let key = token(js::first(&[g(payload, "profile_key"), g(payload, "profile"), &json!("default")]));
        let data = self.res_data("profiles", &key)?.unwrap_or(json!({}));
        let mut p = merge(&data, if truthy(payload) { payload } else { &Value::Null });
        p["profile_key"] = json!(key);
        p["wan_id"] = json!(token(js::or(g(&p, "wan_id"), &json!(key))));
        p["interface"] = json!(iface_name(js::first(&[g(&p, "interface"), g(&p, "iface"), g(&p, "physical_interface"), &json!("")]), "interface")?);
        let default_mode = if truthy(g(&p, "mac_address")) { json!("manual") } else { json!("interface") };
        let mac_mode = lower(first_defined(&[g(&p, "mac_mode"), &default_mode]));
        if mac_mode != "interface" && mac_mode != "random" && mac_mode != "manual" {
            bail!("mac_mode must be interface, random or manual");
        }
        p["mac_mode"] = json!(mac_mode);
        p["mac_address"] = json!(mac_text(js::first(&[g(&p, "mac_address"), g(&p, "mac"), &json!("")]))?);
        if mac_mode == "manual" && s(&p, "mac_address").is_empty() {
            bail!("mac_address is required when mac_mode is manual");
        }
        p["username"] = json!(text(js::or(g(&p, "username"), &json!(""))));
        p["password"] = json!(text(js::or(g(&p, "password"), &json!(""))));
        p["password"] = json!(self.resolve_profile_password(&p));
        p["service"] = json!(text(js::or(g(&p, "service"), &json!(""))));
        p["ac_name"] = json!(text(js::or(g(&p, "ac_name"), &json!(""))));
        let auth = lower(js::or(g(&p, "auth"), &json!("auto")));
        if !["auto", "pap", "chap", "none"].contains(&auth.as_str()) {
            bail!("auth must be auto, pap, chap or none");
        }
        p["auth"] = json!(auth);
        let c = |p: &Value, values: &[&str], min: f64, max: f64, fallback: f64| -> Value {
            let refs: Vec<&Value> = values.iter().map(|k| g(p, k)).collect();
            js::num(clamp_int(first_defined(&refs), min, max, fallback))
        };
        let b = |p: &Value, values: &[&str], fallback: bool| -> Value {
            let refs: Vec<&Value> = values.iter().map(|k| g(p, k)).collect();
            json!(bool_of(first_defined(&refs), fallback))
        };
        p["timeout_ms"] = js::num(clamp_int(g(&p, "timeout_ms"), 50.0, 5000.0, 700.0));
        let timeout = num(&p, "timeout_ms");
        p["control_ack_timeout_ms"] = c(&p, &["control_ack_timeout_ms", "ack_exchange_timeout_ms"], 10.0, 250.0, timeout.min(80.0));
        p["control_idle_timeout_ms"] = c(&p, &["control_idle_timeout_ms", "l2_idle_timeout_ms"], 1.0, 250.0, 10.0);
        // Long enough for one resend of a peer Configure-Request lost between
        // receive windows: RFC 1661's default restart timer is 3 s.
        p["peer_configure_wait_ms"] = js::num(clamp_int(g(&p, "peer_configure_wait_ms"), 0.0, 10000.0, 3500.0));
        p["disconnect_drain_ms"] = c(&p, &["disconnect_drain_ms", "disconnect_control_ms"], 0.0, 2000.0, 350.0);
        p["max_frames"] = js::num(clamp_int(g(&p, "max_frames"), 1.0, 8.0, 4.0));
        p["mru"] = js::num(clamp_int(g(&p, "mru"), 576.0, 1492.0, 1492.0));
        p["negotiate_ipv4"] = b(&p, &["negotiate_ipv4", "ipcp", "ipv4"], true);
        p["negotiate_ipv6"] = b(&p, &["negotiate_ipv6", "ipv6cp", "ipv6"], false);
        p["request_pd"] = b(&p, &["request_pd", "ipv6_pd", "pd"], false);
        let v6 = flag(&p, "negotiate_ipv6");
        p["request_ipv6_address"] = b(&p, &["request_ipv6_address", "request_ia_na", "ia_na"], v6);
        p["request_ipv6_router"] = b(&p, &["request_ipv6_router", "request_ra", "ipv6_ra"], v6);
        if flag(&p, "request_pd") || flag(&p, "request_ipv6_address") {
            p["negotiate_ipv6"] = json!(true);
        }
        p["ipv6_iid"] = json!(iid_hex(js::first(&[g(&p, "ipv6_iid"), g(&p, "interface_id"), &json!("")]))?);
        p["dhcpv6_iaid"] = js::num(clamp_int(js::or(g(&p, "dhcpv6_iaid"), g(&p, "iaid")), 0.0, 4294967295.0, 1.0));
        p["dhcpv6_request"] = b(&p, &["dhcpv6_request", "request_dhcpv6_reply"], true);
        p["dhcpv6_timeout_ms"] = c(&p, &["dhcpv6_timeout_ms", "dhcpv6_exchange_timeout_ms"], 500.0, 30000.0, timeout.max(5000.0));
        p["dhcpv6_settle_ms"] = c(&p, &["dhcpv6_settle_ms", "dhcpv6_delay_ms"], 0.0, 10000.0, 2000.0);
        p["ipv6_ra_timeout_ms"] = c(&p, &["ipv6_ra_timeout_ms", "router_solicitation_timeout_ms"], 500.0, 30000.0, 5000.0);
        p["keepalive_interval_ms"] = js::num(clamp_int(g(&p, "keepalive_interval_ms"), 0.0, 86400000.0, 0.0));
        p["keepalive_failure_threshold"] =
            c(&p, &["keepalive_failure_threshold", "keepalive_failures_before_redial"], 1.0, 10.0, DEFAULT_KEEPALIVE_FAILURE_THRESHOLD);
        p["keepalive_failure_grace_ms"] = c(&p, &["keepalive_failure_grace_ms", "keepalive_grace_ms"], 0.0, 3600000.0, DEFAULT_KEEPALIVE_FAILURE_GRACE_MS);
        p["keepalive_confirm_timeout_ms"] =
            c(&p, &["keepalive_confirm_timeout_ms", "keepalive_final_timeout_ms"], 100.0, 30000.0, timeout.max(DEFAULT_KEEPALIVE_CONFIRM_TIMEOUT_MS));
        p["auto_redial"] = b(&p, &["auto_redial", "redial", "reconnect", "reconnect_on_timeout"], false);
        p["redial_clear_tunnel"] = b(&p, &["redial_clear_tunnel", "clear_tunnel_on_redial"], true);
        p["redial_send_padt"] = b(&p, &["redial_send_padt", "close_session_before_redial"], true);
        p["redial_retry_initial_ms"] = c(&p, &["redial_retry_initial_ms", "redial_retry_ms"], 250.0, 300000.0, 2000.0);
        let initial = num(&p, "redial_retry_initial_ms");
        p["redial_retry_max_ms"] = c(&p, &["redial_retry_max_ms", "redial_max_retry_ms"], initial, 3600000.0, initial.max(30000.0));
        p["install_tunnel"] = json!(bool_of(g(&p, "install_tunnel"), false));
        p["prepare_interfaces"] = b(&p, &["prepare_interfaces", "prepare_tunnel_interfaces"], true);
        p["prepare_local_mtu"] = b(&p, &["prepare_local_mtu", "set_local_mtu"], true);
        p["prepare_wan_mtu"] = b(&p, &["prepare_wan_mtu", "set_wan_mtu"], false);
        p["prepare_offloads"] = b(&p, &["prepare_offloads", "disable_offloads"], true);
        p["prepare_gso"] = b(&p, &["prepare_gso", "limit_gso"], true);
        p["prepare_wan_offloads"] = b(&p, &["prepare_wan_offloads", "disable_wan_offloads"], false);
        p["allow_unsafe_offloads"] = b(&p, &["allow_unsafe_offloads", "allow_offload_prepare_failure"], false);
        p["sync_hook_bindings"] = b(&p, &["sync_hook_bindings", "hook_bindings"], true);
        p["apply_hook_bindings"] = b(&p, &["apply_hook_bindings", "hook_bindings_apply"], true);
        let control_default = if flag(&p, "install_tunnel") { 3000.0 } else { 0.0 };
        p["post_session_control_ms"] = c(&p, &["post_session_control_ms", "post_dial_control_ms", "control_drain_ms"], 0.0, 10000.0, control_default);
        let decap = lower(first_defined(&[g(&p, "decap_mode"), g(&p, "pppoe_decap_mode"), &json!("auto")]));
        if decap != "manual" && decap != "auto" {
            bail!("decap_mode must be manual or auto");
        }
        p["decap_mode"] = json!(decap);
        p["manual_decap"] = json!(decap == "manual");
        let mru = num(&p, "mru");
        p["mss_clamp_v4"] = c(&p, &["mss_clamp_v4", "tcp_mss_v4", "mss_clamp"], 0.0, 65535.0, (mru - 40.0).max(536.0));
        p["mss_clamp_v6"] = c(&p, &["mss_clamp_v6", "tcp_mss_v6"], 0.0, 65535.0, (mru - 60.0).max(1220.0));
        p["send_padt"] = json!(bool_of(g(&p, "send_padt"), true));
        p["local_interface"] = json!(optional_iface_name(js::or(g(&p, "local_interface"), &json!("")), "local_interface")?);
        p["pipeline_interface"] = json!(optional_iface_name(js::first(&[g(&p, "pipeline_interface"), g(&p, "tunnel_interface"), &json!("")]), "pipeline_interface")?);
        let wan = optional_iface_name(js::or(g(&p, "wan_interface"), &json!("")), "wan_interface")?;
        p["wan_interface"] = if wan.is_empty() { p["interface"].clone() } else { json!(wan) };
        for key in ["local_ifindex", "pipeline_ifindex", "wan_ifindex"] {
            p[key] = js::num(clamp_int(g(&p, key), 0.0, 2147483647.0, 0.0));
        }
        p["local_src_mac"] = json!(mac_text(js::or(g(&p, "local_src_mac"), &json!("")))?);
        p["local_dst_mac"] = json!(mac_text(js::or(g(&p, "local_dst_mac"), &json!("")))?);
        p["wan_src_mac"] = json!(mac_text(js::or(g(&p, "wan_src_mac"), &json!("")))?);
        p["wan_dst_mac"] = json!(mac_text(js::first(&[g(&p, "wan_dst_mac"), g(&p, "ac_mac"), &json!("")]))?);
        let local = !s(&p, "local_interface").is_empty();
        p["wan_core_sync"] = b(&p, &["wan_core_sync", "sync_wan_core"], local);
        let sync = flag(&p, "wan_core_sync");
        p["wan_core_required"] = b(&p, &["wan_core_required", "require_wan_core"], sync);
        if flag(&p, "wan_core_required") && !sync {
            bail!("wan_core_required requires wan_core_sync");
        }
        p["wan_core_apply"] = b(&p, &["wan_core_apply", "apply_wan_core"], true);
        p["wan_core_plugin"] = json!(token(js::first(&[g(&p, "wan_core_plugin"), g(&p, "wan_core_plugin_id"), &json!("wan_core")])));
        Ok(p)
    }

    fn resolve_profile_password(&self, profile: &Value) -> String {
        let key = format!("pppoe-password-{}", token(js::or(g(profile, "profile_key"), &json!("default"))));
        let password = s(profile, "password");
        if !password.is_empty() {
            // A transient secret-store failure must not break the current dial.
            let _ = self.host.call("secret.set", json!([key, password]));
            return password;
        }
        match self.host.call("secret.get", json!([key])) {
            Ok(Value::Null) | Err(_) => String::new(),
            Ok(Value::String(stored)) => text_str(&stored),
            Ok(stored) if truthy(&stored) && !g(&stored, "password").is_null() => text(g(&stored, "password")),
            Ok(stored) => text(&stored),
        }
    }

    // -------------------------------------------------------- L2 identity

    pub fn prepare_l2_identity(&self, profile: &mut Value) -> Result<Value> {
        let key = token(js::or(g(profile, "profile_key"), &json!("default")));
        let iface = iface_name(g(profile, "interface"), "interface")?;
        let mut link = self.link_get(&iface)?;
        let interface_mac = unicast_mac_text(js::or(g(&link, "mac"), &json!("")))?;
        let mut previous = self.res_data(L2_IDENTITY_RESOURCE, &key)?;
        let mode = s(profile, "mac_mode");
        let mut mac = interface_mac.clone();
        if mode == "random" {
            mac = match &previous {
                Some(prev) if s(prev, "interface") == iface && truthy(g(prev, "mac_address")) => unicast_mac_text(g(prev, "mac_address"))?,
                _ => self.random_local_unicast_mac()?,
            };
        } else if mode == "manual" {
            mac = unicast_mac_text(g(profile, "mac_address"))?;
        }
        let custom = mac.to_lowercase() != interface_mac.to_lowercase();
        if let Some(prev) = &previous {
            if s(prev, "interface") != iface || lower(g(prev, "mac_address")) != mac.to_lowercase() {
                self.cleanup_l2_identity(&key, true)?;
                previous = None;
                link = self.link_get(&iface)?;
            }
        }
        let mut promisc_owner = previous.as_ref().map(|p| truthy(g(p, "promisc_enabled_by_plugin"))).unwrap_or(false);
        let original_promiscuous = match &previous {
            Some(prev) => flag(prev, "original_promiscuous"),
            None => flag(&link, "promiscuous"),
        };
        if custom && !flag(&link, "promiscuous") {
            self.host.call("net.link.setPromiscuous", json!([iface, true]))?;
            promisc_owner = true;
        }
        let mut record = json!({"profile_key": key, "interface": iface, "interface_mac": interface_mac, "mac_mode": mode, "mac_address": mac,
            "custom_mac": custom, "original_promiscuous": original_promiscuous, "promisc_enabled_by_plugin": promisc_owner, "state": "up"});
        if !same_l2_identity_record(previous.as_ref(), &record) {
            record["updated_at"] = json!(iso_now());
            self.res_set(L2_IDENTITY_RESOURCE, &key, &record)?;
        }
        apply_effective_l2_identity(profile, &record);
        Ok(record)
    }

    pub fn resolve_l2_identity(&self, profile: &mut Value) -> Result<Value> {
        let key = token(js::or(g(profile, "profile_key"), &json!("default")));
        let Some(mut data) = self.res_data(L2_IDENTITY_RESOURCE, &key)? else {
            return self.prepare_l2_identity(profile);
        };
        if s(&data, "interface") != s(profile, "interface") {
            bail!("stored L2 identity belongs to {}, want {}", s(&data, "interface"), s(profile, "interface"));
        }
        let link = self.link_get(&s(&data, "interface"))?;
        if truthy(g(&data, "custom_mac")) && !flag(&link, "promiscuous") {
            self.host.call("net.link.setPromiscuous", json!([data["interface"], true]))?;
            data["promisc_enabled_by_plugin"] = json!(true);
            self.res_set(L2_IDENTITY_RESOURCE, &key, &data)?;
        }
        apply_effective_l2_identity(profile, &data);
        Ok(data)
    }

    pub fn cleanup_l2_identity(&self, profile_key: &str, _force: bool) -> Result<Value> {
        let key = token(&json!(profile_key));
        let Some(data) = self.res_data(L2_IDENTITY_RESOURCE, &key)? else {
            return Ok(json!({"status": "not_configured"}));
        };
        let mut transferred = false;
        if truthy(g(&data, "promisc_enabled_by_plugin")) {
            for record in self.res_list(L2_IDENTITY_RESOURCE)? {
                if !truthy(&record) || token(js::or(g(&record, "key"), &json!("default"))) == key || js::is_false(g(&record, "enabled")) {
                    continue;
                }
                let mut other = js::or(g(&record, "data"), &json!({})).clone();
                if !js::strict_eq(g(&other, "interface"), g(&data, "interface")) || !flag(&other, "custom_mac") {
                    continue;
                }
                other["promisc_enabled_by_plugin"] = json!(true);
                other["original_promiscuous"] = json!(flag(&data, "original_promiscuous"));
                self.res_set_enabled(L2_IDENTITY_RESOURCE, &token(g(&record, "key")), &other, true)?;
                transferred = true;
                break;
            }
            if !transferred && !flag(&data, "original_promiscuous") {
                self.host.call("net.link.setPromiscuous", json!([data["interface"], false]))?;
            }
        }
        self.res_delete(L2_IDENTITY_RESOURCE, &key)?;
        Ok(json!({"status": if transferred { "ownership_transferred" } else { "released" }, "interface": data["interface"], "mac_address": data["mac_address"]}))
    }

    fn random_local_unicast_mac(&self) -> Result<String> {
        let mut bytes = hex_to_bytes(&self.random_hex(6)?);
        bytes.resize(6, 0);
        bytes[0] = (bytes[0] | 2) & 0xfe;
        Ok(mac_bytes_to_text(&bytes))
    }

    // -------------------------------------------------------- discovery

    fn discover(&self, profile: &Value) -> Result<Value> {
        let host_uniq = self.random_hex(4)?;
        let Some(pado_frame) = self.send_padi(profile, &host_uniq)? else {
            return Ok(base_result(profile, "timeout", json!({"message": "PADO timeout", "host_uniq": host_uniq})));
        };
        let pado = parse_discovery_frame(&pado_frame)?;
        if pado.code != CODE_PADO {
            bail!("expected PADO, got code 0x{}", hb(pado.code));
        }
        Ok(base_result(profile, "pado", json!({"host_uniq": host_uniq, "ac_mac": pado_frame["src_mac"],
            "ac_name": first_tag_text(&pado, TAG_AC_NAME), "service_name": first_tag_text(&pado, TAG_SERVICE_NAME), "tags": tag_summary(&pado.tags)})))
    }

    pub fn probe_session(&self, profile: &mut Value) -> Result<Value> {
        self.prepare_wan_core_tunnel_boundary(profile)?;
        let host_uniq = self.random_hex(4)?;
        let Some(pado_frame) = self.send_padi(profile, &host_uniq)? else {
            return Ok(base_result(profile, "timeout", json!({"message": "PADO timeout", "host_uniq": host_uniq})));
        };
        let pado = parse_discovery_frame(&pado_frame)?;
        if pado.code != CODE_PADO {
            bail!("expected PADO, got code 0x{}", hb(pado.code));
        }
        let service = s(profile, "service");
        let mut padr_tags = vec![
            tag_string(TAG_SERVICE_NAME, &if service.is_empty() { first_tag_text(&pado, TAG_SERVICE_NAME) } else { service }),
            tag_hex(TAG_HOST_UNIQ, &host_uniq),
        ];
        append_forwarded_tag(&mut padr_tags, &pado, TAG_AC_COOKIE);
        append_forwarded_tag(&mut padr_tags, &pado, TAG_RELAY_SESSION_ID);
        let pado_src = js::string(&pado_frame["src_mac"]);
        let Some(pads_frame) = self.send_padr(profile, &pado_src, &host_uniq, &padr_tags)? else {
            return Ok(base_result(profile, "timeout", json!({"message": "PADS timeout", "ac_mac": pado_src})));
        };
        let pads = parse_discovery_frame(&pads_frame)?;
        if pads.code != CODE_PADS {
            bail!("expected PADS, got code 0x{}", hb(pads.code));
        }
        if pads.session_id == 0 {
            bail!("PADS did not allocate a session id");
        }
        let ac_mac = js::string(&pads_frame["src_mac"]);
        let local_mac = js::string(&pads_frame["dst_mac"]);
        let frames = match self.run_session_probe(profile, &ac_mac, pads.session_id, &local_mac) {
            Ok(frames) => frames,
            Err(err) => {
                // PADS allocated the session: release it, or the AC keeps it
                // until its LCP gives up (about 30 s with pppd defaults) and
                // a single-session AC refuses the next dial meanwhile.
                if let Err(padt_err) = self.send_padt(profile, &ac_mac, pads.session_id, 0.0) {
                    self.info(&format!("pppoe PADT after a failed session probe skipped: {}", error_message(&padt_err)));
                }
                return Err(err);
            }
        };
        let mut tunnel = Value::Null;
        if flag(profile, "install_tunnel") {
            let installed = (|| -> Result<Value> {
                if !session::lcp_ready_for_network_cp(&frames) {
                    bail!("cannot install tunnel before LCP/auth is ready");
                }
                self.install_tunnel(profile, &pads_frame, pads.session_id)
            })();
            match installed {
                Ok(value) => tunnel = value,
                Err(err) => {
                    self.send_padt(profile, &ac_mac, pads.session_id, 0.0)?;
                    self.clear_tunnel_config()?;
                    return Err(err);
                }
            }
        }
        if flag(profile, "send_padt") {
            self.send_padt(profile, &ac_mac, pads.session_id, 0.0)?;
            if !tunnel.is_null() {
                self.clear_tunnel_config()?;
            }
        }
        let lcp_ready = session::lcp_ready_for_network_cp(&frames);
        Ok(base_result(profile, "session_probe", json!({
            "host_uniq": host_uniq, "ac_mac": ac_mac, "local_mac": local_mac,
            "ac_name": first_tag_text(&pado, TAG_AC_NAME), "service_name": first_tag_text(&pado, TAG_SERVICE_NAME),
            "session_id": pads.session_id, "session_id_hex": u16hex(pads.session_id),
            "lcp_magic": frames.get("lcp_magic"), "lcp_ack": frames.get("lcp_ack"), "lcp_ready": lcp_ready,
            "peer_lcp_ack_sent": frames.get("peer_lcp_ack_sent"), "peer_auth_method": frames.get("peer_auth_method"),
            "auth_sent": frames.get("auth_sent"), "auth_method": frames.get("auth_method"), "auth_ok": frames.get("auth_ok"),
            "ipcp": frames.get("ipcp"), "ipv6cp": frames.get("ipv6cp"), "ipv6_ra": frames.get("ipv6_ra"), "dhcpv6_pd": frames.get("dhcpv6_pd"),
            "frames": frames.get("items"),
            "post_session_control_armed": !flag(profile, "send_padt") && num(profile, "post_session_control_ms") > 0.0,
            "padt_sent": flag(profile, "send_padt"), "tunnel_installed": !tunnel.is_null(), "tunnel": tunnel,
        })))
    }

    // -------------------------------------------------------- WAN Core boundary

    fn prepare_wan_core_tunnel_boundary(&self, profile: &mut Value) -> Result<Value> {
        if !flag(profile, "install_tunnel") || !flag(profile, "wan_core_sync") {
            return Ok(Value::Null);
        }
        let preparation = self.wan_core_interface_preparation(profile);
        let payload = json!({"key": profile["wan_id"], "wan_id": profile["wan_id"], "profile_key": profile["profile_key"], "driver": "pppoe",
            "driver_plugin": "pppoe_client", "state": "prepared", "usable": false, "real_interface": profile["interface"],
            "wan_interface": profile["local_interface"], "local_interface": profile["local_interface"], "pipeline_interface": profile["pipeline_interface"],
            "handoff_mode": if self.direct { "direct_gro" } else { "segmented_veth" }, "mtu": js::num(tunnel_interface_mtu(profile)),
            "interface_preparation": preparation});
        let outcome = (|| -> Result<Value> {
            self.require_wan_core_service_endpoint(profile, "resources", "status")?;
            let response = self.host.call("plugins.services.call", json!([{"service": "wan.adapter", "version": "^1.0.0",
                "provider": profile["wan_core_plugin"], "action": "prepare_handoff", "payload": payload}]))?;
            let response = js::or(&response, &json!({})).clone();
            let record = self.host.call("plugins.resources.get", json!([profile["wan_core_plugin"], "status", profile["wan_id"]]))?;
            let status = if truthy(&record) && truthy(g(&record, "data")) { record["data"].clone() } else { js::or(g(&response, "result"), &json!({})).clone() };
            if !truthy(&status) || !truthy(g(&status, "local_interface")) {
                bail!("WAN core did not publish prepared handoff status");
            }
            if s(&status, "handoff_mode") == "direct_gro" {
                profile["pipeline_interface"] = json!("");
            }
            if truthy(g(&status, "pipeline_interface")) {
                profile["pipeline_interface"] = json!(optional_iface_name(g(&status, "pipeline_interface"), "wan_core pipeline_interface")?);
            }
            if !preparation.is_null() && (!truthy(g(&status, "interface_preparation")) || !flag(g(&status, "interface_preparation"), "applied")) {
                bail!("WAN core did not apply requested interface preparation");
            }
            let mode = s(&status, "handoff_mode");
            profile["wan_core_prepared_interfaces"] =
                json!(truthy(g(&status, "local_interface")) && (mode == "direct_gro" || (mode == "segmented_veth" && truthy(g(&status, "pipeline_interface")))));
            Ok(status)
        })();
        match outcome {
            Ok(status) => Ok(status),
            Err(err) => {
                if flag(profile, "wan_core_required") || s(profile, "pipeline_interface").is_empty() {
                    bail!("prepare WAN core handoff: {}", error_message(&err));
                }
                self.info(&format!("WAN core handoff preparation deferred: {}", error_message(&err)));
                Ok(Value::Null)
            }
        }
    }

    fn wan_core_interface_preparation(&self, profile: &Value) -> Value {
        if !flag(profile, "prepare_interfaces") {
            return Value::Null;
        }
        let mtu = tunnel_interface_mtu(profile);
        let local_gso = if flag(profile, "prepare_gso") {
            json!({"max_size": if self.kfuncs { json!(65536) } else { js::num(mtu) }, "max_segs": if self.kfuncs { 65535 } else { 1 }})
        } else {
            Value::Null
        };
        let offloads = flag(profile, "prepare_offloads");
        let request = json!({"local_gso": local_gso, "local_offloads": if offloads { self.tunnel_local_offloads() } else { Value::Null },
            "pipeline_offloads": if offloads { self.tunnel_pipeline_offloads() } else { Value::Null }, "allow_unsafe_offloads": flag(profile, "allow_unsafe_offloads")});
        if request["local_gso"].is_null() && request["local_offloads"].is_null() && request["pipeline_offloads"].is_null() {
            return Value::Null;
        }
        request
    }

    fn tunnel_local_offloads(&self) -> Value {
        let mut features = json!({"sg": self.kfuncs, "tso": self.kfuncs, "gso": self.kfuncs});
        if self.kfuncs {
            features["gro"] = json!(true);
        }
        features
    }

    fn tunnel_pipeline_offloads(&self) -> Value {
        let mut features = json!({"gro": self.kfuncs, "lro": false});
        // Decapsulated TCP enters local RX through this peer's TX. veth skips
        // TCP GRO on that path when the transmitting peer advertises TSO.
        if self.kfuncs {
            features["tso"] = json!(false);
        }
        features
    }

    // -------------------------------------------------------- tunnel

    fn install_tunnel(&self, profile: &mut Value, pads_frame: &Value, session_id: u64) -> Result<Value> {
        if s(profile, "local_interface").is_empty() {
            bail!("local_interface is required to install the TC tunnel");
        }
        let boundary = self.resolve_tunnel_boundary(profile)?;
        let direct = boundary.mode == "direct_gro";
        let wan_link = if s(profile, "wan_interface").is_empty() { Value::Null } else { self.link_get(&s(profile, "wan_interface"))? };
        let pick = |values: &[&Value]| js::number(js::first(values));
        let local_ifindex = pick(&[g(profile, "local_ifindex"), g(&boundary.local, "ifindex"), &json!(0)]);
        let pipeline_ifindex = if direct {
            local_ifindex
        } else {
            pick(&[g(profile, "pipeline_ifindex"), boundary.pipeline.as_ref().map(|p| g(p, "ifindex")).unwrap_or(&Value::Null), &json!(0)])
        };
        let wan_ifindex = pick(&[g(profile, "wan_ifindex"), g(&wan_link, "ifindex"), g(pads_frame, "ifindex"), &json!(0)]);
        let pick_text = |values: &[&Value]| js::string(js::first(values));
        let local_src_mac = pick_text(&[g(profile, "local_src_mac"), g(pads_frame, "src_mac"), &json!("")]);
        let local_dst_mac = pick_text(&[g(profile, "local_dst_mac"), g(&boundary.local, "mac"), &json!("")]);
        let wan_src_mac = pick_text(&[g(profile, "wan_src_mac"), g(&wan_link, "mac"), g(pads_frame, "dst_mac"), &json!("")]);
        let wan_dst_mac = pick_text(&[g(profile, "wan_dst_mac"), g(pads_frame, "src_mac"), &json!("")]);
        if !(local_ifindex > 0.0) {
            bail!("local_ifindex or local_interface is required to install the TC tunnel");
        }
        if !(pipeline_ifindex > 0.0) {
            bail!("pipeline_ifindex or pipeline_interface is required to install the TC tunnel");
        }
        if !(wan_ifindex > 0.0) {
            bail!("wan_ifindex is required to install the TC tunnel");
        }
        if local_src_mac.is_empty() {
            bail!("local_src_mac or AC MAC is required to install the TC tunnel");
        }
        if local_dst_mac.is_empty() {
            bail!("local_dst_mac or local_interface MAC is required to install the TC tunnel");
        }
        if wan_src_mac.is_empty() {
            bail!("wan_src_mac is required to install the TC tunnel");
        }
        if wan_dst_mac.is_empty() {
            bail!("wan_dst_mac/ac_mac is required to install the TC tunnel");
        }
        let preparation = self.prepare_tunnel_interfaces(profile, Some(&boundary))?;
        let hook_bindings = self.sync_tunnel_hook_bindings(profile, Some(&boundary))?;
        self.clear_tunnel_stats();
        let flags = if flag(profile, "manual_decap") { 2 } else { 0 };
        let value = tunnel_config_value_hex(&json!({"enabled": 1, "local_ifindex": js::num(local_ifindex), "pipeline_ifindex": js::num(pipeline_ifindex),
            "wan_ifindex": js::num(wan_ifindex), "session_id": session_id, "flags": flags, "mss_clamp_v4": profile["mss_clamp_v4"],
            "mss_clamp_v6": profile["mss_clamp_v6"], "local_src_mac": local_src_mac, "local_dst_mac": local_dst_mac, "wan_src_mac": wan_src_mac,
            "wan_dst_mac": wan_dst_mac, "lcp_magic": profile.get("lcp_magic")}))?;
        let pipeline_name = boundary.pipeline.as_ref().map(|p| js::string(&p["name"])).unwrap_or_default();
        let lcp_magic = normalize_lcp_magic_hex(g(profile, "lcp_magic"))?;
        let record = json!({
            "profile_key": profile["profile_key"], "object": "pppoe_tunnel", "map": "pppoe_tunnel_config", "value_hex": value,
            "dataplane": self.dataplane(), "mode": boundary.mode, "local_interface": profile["local_interface"], "pipeline_interface": pipeline_name,
            "wan_interface": profile["wan_interface"], "wan_link_mac": if truthy(&wan_link) { wan_link["mac"].clone() } else { json!("") },
            "local_dst_mac_explicit": truthy(g(profile, "local_dst_mac")),
            // Snapshot only non-secret preparation settings for this live
            // session. Editing a saved dial profile must not change an
            // established tunnel.
            "repair_preparation": {"tunnel_mtu": js::num(tunnel_interface_mtu(profile)), "prepare_interfaces": profile["prepare_interfaces"],
                "prepare_local_mtu": profile["prepare_local_mtu"], "prepare_wan_mtu": profile["prepare_wan_mtu"], "prepare_offloads": profile["prepare_offloads"],
                "prepare_gso": profile["prepare_gso"], "prepare_wan_offloads": profile["prepare_wan_offloads"], "allow_unsafe_offloads": profile["allow_unsafe_offloads"],
                "wan_id": profile["wan_id"], "wan_core_plugin": profile["wan_core_plugin"], "wan_core_prepared_interfaces": flag(profile, "wan_core_prepared_interfaces")},
            "local_ifindex": js::num(local_ifindex), "pipeline_ifindex": js::num(pipeline_ifindex), "wan_ifindex": js::num(wan_ifindex),
            "local_src_mac": local_src_mac, "local_dst_mac": local_dst_mac, "wan_src_mac": wan_src_mac, "wan_dst_mac": wan_dst_mac,
            "lcp_magic": lcp_magic, "session_id": session_id, "flags": flags, "mss_clamp_v4": profile["mss_clamp_v4"], "mss_clamp_v6": profile["mss_clamp_v6"],
            "decap_mode": profile["decap_mode"], "tunnel_repair_interval_ms": js::num(clamp_int(g(profile, "tunnel_repair_interval_ms"), 500.0, 86400000.0, 2000.0)),
            "updated_at": iso_now(),
        });
        if let Err(err) = self.res_set_apply(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, &record, true, true) {
            self.clear_tunnel_config()?;
            return Err(err);
        }
        self.arm_tunnel_repair()?;
        Ok(json!({
            "object": "pppoe_tunnel", "map": "pppoe_tunnel_config", "mode": boundary.mode, "requires_kernel_tc_prepared_l2": false,
            "local_interface": profile["local_interface"], "pipeline_interface": pipeline_name, "wan_interface": profile["wan_interface"],
            "local_ifindex": js::num(local_ifindex), "pipeline_ifindex": js::num(pipeline_ifindex), "wan_ifindex": js::num(wan_ifindex),
            "local_src_mac": local_src_mac, "local_dst_mac": local_dst_mac, "wan_src_mac": wan_src_mac, "wan_dst_mac": wan_dst_mac,
            "lcp_magic": lcp_magic, "mss_clamp_v4": profile["mss_clamp_v4"], "mss_clamp_v6": profile["mss_clamp_v6"],
            "interface_preparation": preparation, "hook_bindings": hook_bindings, "decap_mode": profile["decap_mode"],
        }))
    }

    fn resolve_tunnel_boundary(&self, profile: &Value) -> Result<Boundary> {
        let local_name = iface_name(g(profile, "local_interface"), "local_interface")?;
        let mut pipeline_name = optional_iface_name(js::or(g(profile, "pipeline_interface"), &json!("")), "pipeline_interface")?;
        if pipeline_name.is_empty() && flag(profile, "wan_core_sync") {
            self.require_wan_core_service_endpoint(profile, "resources", "status")?;
            let key = token(js::or(g(profile, "wan_id"), g(profile, "profile_key")));
            let record = self.host.call("plugins.resources.get", json!([profile["wan_core_plugin"], "status", key]))?;
            // A prepared WAN boundary is intentionally disabled until PPPoE succeeds.
            let status = if truthy(&record) && truthy(g(&record, "data")) { record["data"].clone() } else { json!({}) };
            let status_local = optional_iface_name(js::or(g(&status, "local_interface"), &json!("")), "wan_core local_interface")?;
            if !status_local.is_empty() && status_local != local_name {
                bail!("wan_core local interface {status_local} does not match PPPoE local interface {local_name}");
            }
            let veer_core = js::or(g(&status, "veer_core"), &json!({})).clone();
            pipeline_name = optional_iface_name(js::first(&[g(&status, "pipeline_interface"), g(&veer_core, "tunnel_interface"), &json!("")]), "wan_core pipeline_interface")?;
            if !pipeline_name.is_empty() && !flag(&status, "segmentation_ready") && !flag(&veer_core, "segmentation_ready") {
                bail!("wan_core pipeline boundary is not ready for segmentation");
            }
        }
        let local = self.link_get(&local_name)?;
        if lower(g(&local, "kind")) == "veerwan" {
            if !self.direct {
                bail!("PPPoE direct boundary requires dataplane.kfuncs.wan.v1; redial with a supported helper");
            }
            if !pipeline_name.is_empty() {
                bail!("PPPoE direct boundary must not name a pipeline peer");
            }
            return Ok(Boundary { mode: "direct_gro", local, pipeline: None });
        }
        if pipeline_name.is_empty() || pipeline_name == local_name {
            bail!("PPPoE tunnel requires a segmented WAN handoff with a distinct pipeline interface");
        }
        let pipeline = self.link_get(&pipeline_name)?;
        if lower(g(&local, "kind")) != "veth" || lower(g(&pipeline, "kind")) != "veth" {
            bail!("PPPoE segmented handoff must use a veth pair");
        }
        let peer_mismatch = |a: &Value, b: &Value| truthy(g(a, "peer_ifindex")) && !js::strict_eq(g(a, "peer_ifindex"), g(b, "ifindex"));
        if peer_mismatch(&local, &pipeline) || peer_mismatch(&pipeline, &local) {
            bail!("PPPoE segmented handoff interfaces are not peers");
        }
        Ok(Boundary { mode: "segmented_veth", local, pipeline: Some(pipeline) })
    }

    fn sync_tunnel_hook_bindings(&self, profile: &Value, boundary: Option<&Boundary>) -> Result<Value> {
        if !flag(profile, "sync_hook_bindings") {
            return Ok(json!({"status": "disabled"}));
        }
        let wan = js::string(js::first(&[g(profile, "wan_interface"), g(profile, "interface"), &json!("")]));
        let direct = boundary.map(|b| b.mode == "direct_gro").unwrap_or(false);
        let pipeline = match boundary {
            Some(b) if direct => js::string(&b.local["name"]),
            Some(b) => b.pipeline.as_ref().map(|p| js::string(&p["name"])).unwrap_or_default(),
            None => String::new(),
        };
        if wan.is_empty() || pipeline.is_empty() {
            return Ok(json!({"status": "skipped", "reason": "no hook interfaces"}));
        }
        let apply = flag(profile, "apply_hook_bindings");
        self.res_set_apply("hook_bindings", "pppoe-ingress", &json!({"hook_id": "pppoe-ingress", "interfaces": [wan]}), true, apply)?;
        self.res_set_apply("hook_bindings", "pppoe-egress", &json!({"hook_id": "pppoe-egress", "interfaces": if direct { json!([]) } else { json!([pipeline]) }}), !direct, apply)?;
        if self.kfuncs {
            let interfaces = if direct { json!([pipeline]) } else { json!([]) };
            self.res_set_apply("hook_bindings", "pppoe-local-egress", &json!({"hook_id": "pppoe-local-egress", "interfaces": interfaces}), direct, apply)?;
        }
        Ok(json!({"status": if apply { "applied" } else { "stored" }, "ingress": [wan], "egress": [pipeline], "applied": apply}))
    }

    fn prepare_tunnel_interfaces(&self, profile: &Value, boundary: Option<&Boundary>) -> Result<Value> {
        let mut result = json!({"enabled": false, "delegated_to_wan_core": false, "mtu": [], "gso": [], "offloads": [], "warnings": []});
        if !flag(profile, "prepare_interfaces") {
            return Ok(result);
        }
        result["enabled"] = json!(true);
        let local = match boundary {
            Some(b) if truthy(&b.local) => js::string(&b.local["name"]),
            _ => s(profile, "local_interface"),
        };
        let pipeline = boundary.and_then(|b| b.pipeline.as_ref()).map(|p| js::string(&p["name"])).unwrap_or_default();
        let wan = js::string(js::first(&[g(profile, "wan_interface"), g(profile, "interface"), &json!("")]));
        let mtu = tunnel_interface_mtu(profile);
        let mut prepared_mtu: Vec<String> = Vec::new();
        let mut prepared_offloads: Vec<String> = Vec::new();
        let delegated = flag(profile, "wan_core_prepared_interfaces");
        result["delegated_to_wan_core"] = json!(delegated);
        if flag(profile, "prepare_local_mtu") && !delegated {
            self.prepare_tunnel_mtu(&mut result, &mut prepared_mtu, &local, "local", mtu)?;
            self.prepare_tunnel_mtu(&mut result, &mut prepared_mtu, &pipeline, "pipeline", mtu)?;
        }
        if flag(profile, "prepare_gso") && !local.is_empty() && !delegated {
            let limits = json!({"max_size": if self.kfuncs { json!(65536) } else { js::num(mtu) }, "max_segs": if self.kfuncs { 65535 } else { 1 }});
            let gso = self.host.call("net.link.setGSO", json!([local, limits]))?;
            result["gso"].as_array_mut().unwrap().push(json!({"interface": local, "role": "local",
                "max_size": js::or(g(&gso, "gso_max_size"), &js::num(mtu)), "max_segs": js::or(g(&gso, "gso_max_segs"), &json!(1))}));
        }
        if flag(profile, "prepare_wan_mtu") && !wan.is_empty() {
            self.prepare_tunnel_mtu(&mut result, &mut prepared_mtu, &wan, "wan", mtu)?;
        }
        if flag(profile, "prepare_offloads") {
            if !delegated {
                self.prepare_tunnel_offloads(profile, &mut result, &mut prepared_offloads, &local, "local", self.tunnel_local_offloads())?;
                self.prepare_tunnel_offloads(profile, &mut result, &mut prepared_offloads, &pipeline, "pipeline", self.tunnel_pipeline_offloads())?;
            }
            if flag(profile, "prepare_wan_offloads") {
                let off = json!({"tx": false, "sg": false, "tso": false, "gso": false, "gro": false});
                self.prepare_tunnel_offloads(profile, &mut result, &mut prepared_offloads, &wan, "wan", off)?;
            }
        }
        Ok(result)
    }

    fn refresh_tunnel_preparation(&self, profile: &mut Value, boundary: &Boundary, session_id: &Value) -> Result<Value> {
        if flag(profile, "wan_core_prepared_interfaces") && !self.wan_core_interface_preparation(profile).is_null() {
            if !truthy(g(profile, "wan_core_plugin")) {
                profile["wan_core_plugin"] = json!("wan_core");
            }
            let key = js::or(g(profile, "wan_id"), g(profile, "profile_key")).clone();
            self.require_wan_core_service_endpoint(profile, "actions", "apply_session")?;
            let record = self.host.call("plugins.resources.get", json!([profile["wan_core_plugin"], "sessions", key]))?;
            let session = g(&record, "data");
            if !truthy(session)
                || js::is_false(g(&record, "enabled"))
                || !flag(session, "usable")
                || s(session, "driver_plugin") != "pppoe_client"
                || !js::strict_eq(g(session, "profile_key"), g(profile, "profile_key"))
                || !js::strict_eq(g(session, "session_id"), session_id)
                || !js::strict_eq(g(session, "real_interface"), g(profile, "wan_interface"))
            {
                bail!("WAN core session identity changed; redial is required");
            }
            // WAN Core owns the boundary's offload leases. Update its existing
            // profile through apply_session; prepare_handoff would mark an
            // online WAN unusable.
            self.host.call("plugins.services.call", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": profile["wan_core_plugin"],
                "action": "apply_session", "payload": {"key": key, "interface_preparation": self.wan_core_interface_preparation(profile)}}]))?;
            let status_record = self.host.call("plugins.resources.get", json!([profile["wan_core_plugin"], "status", key]))?;
            let status = g(&status_record, "data");
            let pipeline = boundary.pipeline.as_ref().map(|p| js::string(&p["name"])).unwrap_or_default();
            if !truthy(status)
                || !flag(status, "usable")
                || !js::strict_eq(g(status, "local_interface"), &boundary.local["name"])
                || js::string(js::or(g(status, "pipeline_interface"), &json!(""))) != pipeline
                || !truthy(g(status, "interface_preparation"))
                || !flag(g(status, "interface_preparation"), "applied")
            {
                bail!("WAN core did not prepare the live tunnel boundary");
            }
        }
        self.prepare_tunnel_interfaces(profile, Some(boundary))
    }

    fn prepare_tunnel_mtu(&self, result: &mut Value, prepared: &mut Vec<String>, iface: &str, role: &str, mtu: f64) -> Result<()> {
        if iface.is_empty() || prepared.iter().any(|p| p == iface) {
            return Ok(());
        }
        prepared.push(iface.to_string());
        self.host.call("net.link.setMTU", json!([iface, js::num(mtu)]))?;
        result["mtu"].as_array_mut().unwrap().push(json!({"interface": iface, "mtu": js::num(mtu), "role": role}));
        Ok(())
    }

    fn prepare_tunnel_offloads(&self, profile: &Value, result: &mut Value, prepared: &mut Vec<String>, iface: &str, role: &str, features: Value) -> Result<()> {
        if iface.is_empty() || prepared.iter().any(|p| p == iface) {
            return Ok(());
        }
        prepared.push(iface.to_string());
        match self.host.call("net.link.setOffloads", json!([iface, features])) {
            Ok(_) => result["offloads"].as_array_mut().unwrap().push(json!({"interface": iface, "role": role, "features": features})),
            Err(err) => {
                let message = error_message(&err);
                if !flag(profile, "allow_unsafe_offloads") {
                    bail!("prepare PPPoE tunnel offloads on {iface}: {message}");
                }
                result["warnings"].as_array_mut().unwrap().push(json!({"interface": iface, "role": role, "warning": message}));
            }
        }
        Ok(())
    }

    pub fn clear_tunnel_config(&self) -> Result<()> {
        let deleted = match self.host.call("resources.delete", json!([TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, true])) {
            Ok(_) => true,
            Err(err) => {
                self.info(&format!("pppoe tunnel config record clear skipped: {}", error_message(&err)));
                false
            }
        };
        if !deleted {
            self.clear_tunnel_map(false)?;
        }
        self.arm_tunnel_repair()
    }

    fn clear_tunnel_map(&self, report_errors: bool) -> Result<()> {
        let empty = zero_tunnel_config_hex();
        if let Ok(current) = self.map_get("pppoe_tunnel_config", &u32lehex(0)) {
            if lower(js::or(&current, &json!(""))) == empty {
                return Ok(());
            }
        }
        if let Err(err) = self.map_put("pppoe_tunnel_config", &u32lehex(0), &empty) {
            self.info(&format!("pppoe tunnel config clear skipped: {}", error_message(&err)));
            if report_errors {
                return Err(err);
            }
        }
        Ok(())
    }

    fn apply_stored_tunnel_config(&self, report_errors: bool) -> Result<()> {
        let records = self.res_list(TUNNEL_CONFIG_RESOURCE)?;
        self.apply_tunnel_config_records(&records, report_errors)
    }

    /// The host reads ctx.records before the event waits for this plugin's
    /// queue, so a disconnect or a dial may have run in between. Stored
    /// records carry a revision: apply the tunnel config as it is stored
    /// now. Records without a revision were supplied by the caller as is.
    fn current_tunnel_config_records(&self, records: Vec<Value>) -> Result<Vec<Value>> {
        if records.iter().any(|r| truthy(r) && !(num(r, "revision") > 0.0)) {
            return Ok(records);
        }
        self.res_list(TUNNEL_CONFIG_RESOURCE)
    }

    fn apply_tunnel_config_records(&self, records: &[Value], report_errors: bool) -> Result<()> {
        let Some(selected) = select_tunnel_config_record(records) else {
            return self.clear_tunnel_map(report_errors);
        };
        let mut failures = Vec::new();
        if let Err(err) = self.apply_tunnel_config_record(&selected) {
            failures.push(error_message(&err));
            // Retain desired state for retries, but deactivate stale interface indices.
            if let Err(clear) = self.clear_tunnel_map(true) {
                failures.push(error_message(&clear));
            }
        }
        let data = js::or(g(&selected, "data"), &json!({})).clone();
        let repair_error = failures.join("; ");
        if text(js::or(g(&data, "last_repair_error"), &json!(""))) != repair_error {
            if let Some(current) = self.res_get(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY)? {
                if !js::is_false(g(&current, "enabled")) {
                    let next = merge(js::or(g(&current, "data"), &json!({})), &json!({"last_repair_error": repair_error}));
                    self.res_set_apply(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, &next, true, false)?;
                }
            }
        }
        if report_errors && !failures.is_empty() {
            bail!("failed to apply PPPoE tunnel config: {}", failures.join("; "));
        }
        Ok(())
    }

    fn apply_tunnel_config_record(&self, record: &Value) -> Result<()> {
        let data = if truthy(record) && truthy(g(record, "data")) { record["data"].clone() } else { json!({}) };
        let source = if truthy(g(&data, "value_hex")) { js::string(&data["value_hex"]) } else { tunnel_config_value_hex(&data)? };
        let decoded = decode_tunnel_config_hex(&source)?;
        let boundary = self.resolve_tunnel_boundary(&json!({"local_interface": data.get("local_interface"), "pipeline_interface": data.get("pipeline_interface")}))?;
        let wan = self.link_get(&iface_name(js::or(g(&data, "wan_interface"), &json!("")), "wan_interface")?)?;
        if !flag(&boundary.local, "up") || boundary.pipeline.as_ref().map(|p| !flag(p, "up")).unwrap_or(false) || !flag(&wan, "up") {
            bail!("PPPoE tunnel endpoint is down");
        }
        if !truthy(g(&wan, "ifindex")) || !truthy(g(&boundary.local, "ifindex")) || boundary.pipeline.as_ref().map(|p| !truthy(g(p, "ifindex"))).unwrap_or(false) {
            bail!("PPPoE tunnel endpoint has no interface index");
        }
        if truthy(g(&data, "wan_link_mac")) && lower(g(&wan, "mac")) != lower(g(&data, "wan_link_mac")) {
            bail!("PPPoE WAN identity changed; redial is required");
        }
        let mut next = merge(&data, &decoded);
        next["local_ifindex"] = boundary.local["ifindex"].clone();
        next["pipeline_ifindex"] = boundary.pipeline.as_ref().map(|p| p["ifindex"].clone()).unwrap_or(boundary.local["ifindex"].clone());
        next["wan_ifindex"] = wan["ifindex"].clone();
        if js::is_false(g(&data, "local_dst_mac_explicit")) {
            next["local_dst_mac"] = boundary.local.get("mac").cloned().unwrap_or(Value::Null);
        }
        let decoded_hex = js::string(&decoded["value_hex"]);
        next["lcp_magic"] = if truthy(g(&data, "lcp_magic")) { data["lcp_magic"].clone() } else { json!(decoded_hex.get(96..104).unwrap_or("")) };
        next["value_hex"] = json!(tunnel_config_value_hex(&next)?);
        let changed = js::string(&next["value_hex"]) != decoded_hex;
        let dataplane = self.dataplane();
        let mode_changed = js::string(js::or(g(&data, "dataplane"), &json!("bpf"))) != dataplane;
        if changed || mode_changed {
            if !truthy(g(&data, "repair_preparation")) || !truthy(g(&data, "profile_key")) {
                bail!("Legacy PPPoE tunnel endpoints changed; redial is required");
            }
            let mut runtime_profile = merge(g(&data, "repair_preparation"), &json!({"profile_key": data["profile_key"], "interface": data.get("wan_interface"),
                "wan_interface": data.get("wan_interface"), "local_interface": data.get("local_interface"), "pipeline_interface": data.get("pipeline_interface"),
                "mac_mode": "manual", "mac_address": next.get("wan_src_mac")}));
            self.refresh_tunnel_preparation(&mut runtime_profile, &boundary, g(&next, "session_id"))?;
            let identity = self.resolve_l2_identity(&mut runtime_profile)?;
            if lower(g(&identity, "mac_address")) != lower(g(&next, "wan_src_mac")) {
                bail!("PPPoE client identity changed; redial is required");
            }
        }
        let current = self.map_get("pppoe_tunnel_config", &u32lehex(0)).map(|v| lower(js::or(&v, &json!("")))).unwrap_or_default();
        if current != js::string(&next["value_hex"]) {
            self.map_put("pppoe_tunnel_config", &u32lehex(0), &js::string(&next["value_hex"]))?;
        }
        if changed || mode_changed {
            next["dataplane"] = json!(dataplane);
            self.res_set_apply(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY, &next, true, false)?;
        }
        Ok(())
    }

    fn arm_tunnel_repair(&self) -> Result<()> {
        let record = self.res_get(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY)?;
        let Some(record) = record.filter(|r| !js::is_false(g(r, "enabled"))) else {
            return self.timer_clear(TUNNEL_REPAIR_TIMER);
        };
        let data = js::or(g(&record, "data"), &json!({})).clone();
        let interval = clamp_int(g(&data, "tunnel_repair_interval_ms"), 500.0, 86400000.0, 2000.0);
        self.timer_interval(TUNNEL_REPAIR_TIMER, interval, &json!({}))
    }

    fn clear_tunnel_stats(&self) {
        if let Err(err) = self.host.call("ebpf.mapClear", json!(["pppoe_tunnel", "pppoe_traffic_stats"])) {
            self.info(&format!("pppoe traffic stats clear skipped: {}", error_message(&err)));
        }
        for i in 0..24 {
            if let Err(err) = self.map_put("pppoe_tunnel_stats", &u32lehex(i), &"00".repeat(8)) {
                self.info(&format!("pppoe tunnel stats clear skipped: {}", error_message(&err)));
                return;
            }
        }
    }

    fn read_traffic_stats(&self, payload: &Value) -> Result<Value> {
        let sampled = now();
        let session = self.res_data("sessions", "last")?.unwrap_or(json!({}));
        let config = self.res_get(TUNNEL_CONFIG_RESOURCE, TUNNEL_CONFIG_KEY)?;
        let requested = text(js::first(&[g(payload, "profile_key"), g(payload, "profile"), &json!("")]));
        let active = text(js::first(&[g(&session, "profile_key"), g(&session, "wan_id"), &json!("")]));
        let mut out = json!({"available": false, "profile_key": active, "session_id": js::num(clamp_int(g(&session, "session_id"), 0.0, 65535.0, 0.0)),
            "sampled_at_ms": js::num(sampled), "counter_scope": "current_tunnel", "byte_scope": "inner_ip",
            "rx_packets": 0, "rx_bytes": 0, "tx_packets": 0, "tx_bytes": 0});
        if !requested.is_empty() && !active.is_empty() && token_str(&requested) != token_str(&active) {
            out["reason"] = json!("selected profile is not the active PPPoE session");
            return Ok(out);
        }
        if config.as_ref().map(|c| js::is_false(g(c, "enabled"))).unwrap_or(true) {
            out["reason"] = json!("PPPoE tunnel is not installed");
            return Ok(out);
        }
        match self.host.call("ebpf.mapGetPerCPU", json!(["pppoe_tunnel", "pppoe_traffic_stats", u32lehex(0)])) {
            Ok(values) => {
                let values = js::array(&values);
                let mut sums = [0f64; 4];
                for value in &values {
                    let value: String = lower(js::or(value, &json!(""))).chars().filter(|c| c.is_ascii_hexdigit()).collect();
                    if value.len() < 64 {
                        continue;
                    }
                    for (i, sum) in sums.iter_mut().enumerate() {
                        *sum += u64le_number(&value[i * 16..i * 16 + 16]);
                    }
                }
                for (i, key) in ["rx_packets", "rx_bytes", "tx_packets", "tx_bytes"].iter().enumerate() {
                    out[*key] = js::num(sums[i]);
                }
                out["available"] = json!(true);
                out["cpu_values"] = json!(values.len());
            }
            Err(err) => out["reason"] = json!(error_message(&err)),
        }
        Ok(out)
    }

    fn read_tunnel_stats(&self) -> Value {
        let names = [
            "unused", "local_encap_path", "decap_path", "pppoe_seen", "session_match", "adjust_room_fail", "store_local_eth_fail", "redirect_local_ok",
            "redirect_local_fail", "last_adjust_room_errno", "manual_decap_ok", "manual_decap_fail", "manual_decap_pull_fail", "manual_decap_bounds_fail",
            "manual_decap_copy_short", "manual_decap_trim_fail", "encap_parse_fail", "encap_adjust_room_fail", "encap_store_header_fail",
            "encap_store_eth_fail", "redirect_wan_ok", "redirect_wan_fail", "encap_l3_too_large", "reserved",
        ];
        let mut out = json!({"counter_build": "disabled_by_default", "note": TUNNEL_STATS_BUILD_NOTE});
        for (i, name) in names.iter().enumerate() {
            match self.map_get("pppoe_tunnel_stats", &u32lehex(i as u64)) {
                Ok(value) => out[*name] = js::num(u64le_number(&js::string(js::or(&value, &json!(""))))),
                Err(err) => {
                    out["error"] = json!(error_message(&err));
                    break;
                }
            }
        }
        match self.map_get("pppoe_tunnel_config", &u32lehex(0)).and_then(|hex| decode_tunnel_config_hex(&js::string(js::or(&hex, &json!(""))))) {
            Ok(config) => out["config"] = config,
            Err(err) => out["config_error"] = json!(error_message(&err)),
        }
        out
    }

    // -------------------------------------------------------- WAN links

    /// Stores the session and publishes its WAN; returns (link, session).
    pub fn record_session(&self, profile: &Value, mut session: Value) -> Result<(Value, Value)> {
        if !session.is_object() {
            session = json!({});
        }
        if truthy(g(&session, "session_id")) && truthy(g(&session, "ac_mac")) {
            let generation = lease::timer_generation(g(&session, "session_generation"));
            session["session_generation"] = json!(if generation.is_empty() { self.new_timer_generation()? } else { generation });
            session["desired_state"] = json!("up");
        }
        self.res_set("sessions", "last", &session)?;
        if !truthy(g(&session, "session_id")) {
            let phase = js::string(js::or(g(&session, "phase"), &json!("session_failed")));
            if let Err(err) = self.mark_wan_link_down(profile, &session, &phase) {
                self.info(&format!("PPPoE failed-session WAN cleanup deferred: {}", error_message(&err)));
            }
            bail!("{}", lease::redial_session_failure(&session));
        }
        let link = self.publish_wan_link(profile, &session)?;
        if !flag(profile, "wan_core_required") || wan_core_sync_succeeded(g(&link, "wan_core_sync")) {
            return Ok((link, session));
        }
        self.clear_tunnel_config()?;
        let sync = if truthy(g(&link, "wan_core_sync")) { link["wan_core_sync"].clone() } else { json!({"status": "missing"}) };
        let reason = js::string(js::first(&[g(&sync, "error"), g(&sync, "reason"), g(&sync, "status"), &json!("unknown error")]));
        let message = format!("required WAN core handoff failed: {reason}");
        let failed = merge(&session, &json!({"phase": "handoff_error", "tunnel_installed": false, "handoff_error": message, "updated_at": iso_now()}));
        self.res_set("sessions", "last", &failed)?;
        self.fail_close_wan_core_sync(profile, &link, &message)?;
        bail!("{message}")
    }

    pub fn publish_wan_link(&self, profile: &Value, session: &Value) -> Result<Value> {
        if !truthy(session) || !truthy(g(session, "session_id")) {
            return Ok(Value::Null);
        }
        let mut link = self.normalized_wan_link(profile, session);
        let sync = self.sync_wan_core(profile, &link)?;
        if !sync.is_null() {
            link["wan_core_sync"] = sync;
        }
        self.res_set("wan_links", &s(&link, "wan_id"), &link)?;
        Ok(link)
    }

    fn fail_close_wan_core_sync(&self, profile: &Value, link: &Value, message: &str) -> Result<()> {
        let base = if truthy(link) { link.clone() } else { self.normalized_wan_link(profile, &json!({})) };
        let mut link = merge(&base, &json!({"state": "down", "usable": false, "phase": "handoff_error", "handoff_error": message, "updated_at": iso_now()}));
        let sync = self.sync_wan_core(profile, &link)?;
        if !sync.is_null() {
            link["wan_core_sync"] = sync;
        }
        self.res_set_enabled("wan_links", &s(&link, "wan_id"), &link, false)
    }

    pub fn mark_wan_link_down(&self, profile: &Value, previous: &Value, phase: &str) -> Result<()> {
        let key = token(js::first(&[g(previous, "wan_id"), g(profile, "wan_id"), g(profile, "profile_key")]));
        let data = match self.res_data("wan_links", &key)? {
            Some(data) => data,
            None => self.normalized_wan_link(profile, if truthy(previous) { previous } else { &Value::Null }),
        };
        let phase = if phase.is_empty() { "down" } else { phase };
        let mut link = merge(&data, &json!({"state": "down", "usable": false, "phase": phase, "updated_at": iso_now()}));
        let sync = self.sync_wan_core(profile, &link)?;
        if !sync.is_null() {
            link["wan_core_sync"] = sync;
        }
        self.res_set_enabled("wan_links", &key, &link, false)
    }

    fn fail_close_wan_core_from_stored(&self, key: &str, payload: &Value, phase: &str) -> Result<Value> {
        let Some(data) = self.res_data("wan_links", key)? else {
            return Ok(Value::Null);
        };
        let profile = json!({"profile_key": key, "wan_id": key,
            "wan_core_sync": bool_of(first_defined(&[g(payload, "wan_core_sync"), g(payload, "sync_wan_core")]), true),
            "wan_core_apply": bool_of(first_defined(&[g(payload, "wan_core_apply"), g(payload, "apply_wan_core")]), true),
            "wan_core_plugin": token(js::first(&[g(payload, "wan_core_plugin"), g(payload, "wan_core_plugin_id"), &json!("wan_core")]))});
        let link = merge(&data, &json!({"state": "down", "usable": false, "phase": if phase.is_empty() { "down" } else { phase }, "updated_at": iso_now()}));
        self.sync_wan_core(&profile, &link)
    }

    fn normalized_wan_link(&self, profile: &Value, session: &Value) -> Value {
        let empty = json!({});
        let session = if truthy(session) { session } else { &empty };
        let ipcp = js::or(g(session, "ipcp"), &empty);
        let ipv6cp = js::or(g(session, "ipv6cp"), &empty);
        let ra = js::or(g(session, "ipv6_ra"), &empty);
        let pd = js::or(g(session, "dhcpv6_pd"), &empty);
        let addresses = js::array(g(pd, "addresses"));
        let prefixes = js::array(g(pd, "prefixes"));
        let open = !flag(session, "padt_sent") && flag(session, "lcp_ready");
        let state = if open {
            json!("up")
        } else if truthy(g(session, "padt_sent")) {
            json!("closed")
        } else {
            js::or(g(session, "phase"), &json!("unknown")).clone()
        };
        let tunnel = g(session, "tunnel");
        let pipeline = if truthy(tunnel) {
            js::or(g(tunnel, "pipeline_interface"), &json!("")).clone()
        } else if self.direct {
            json!("")
        } else {
            js::or(g(profile, "pipeline_interface"), &json!("")).clone()
        };
        let mode = if truthy(tunnel) && truthy(g(tunnel, "mode")) { tunnel["mode"].clone() } else { json!(if self.direct { "direct_gro" } else { "segmented_veth" }) };
        let first_address = addresses.first().map(|a| a["address"].clone()).unwrap_or(Value::Null);
        let ipv6 = js::first(&[g(pd, "address"), &first_address, g(ra, "address"), &json!("")]).clone();
        let first_prefix = prefixes.first().map(|p| p["prefix"].clone()).unwrap_or(Value::Null);
        let pd_prefix = js::first(&[g(pd, "prefix"), &first_prefix, &json!("")]).clone();
        let mut dns: Vec<Value> = js::array(g(ipcp, "dns_servers"));
        dns.extend(js::array(g(pd, "dns_servers")));
        dns.extend(js::array(g(ra, "dns_servers")));
        let local = js::or(g(profile, "local_interface"), &json!("")).clone();
        json!({
            "wan_id": token(js::first(&[g(session, "wan_id"), g(profile, "wan_id"), g(profile, "profile_key")])),
            "profile_key": profile.get("profile_key"), "driver": "pppoe", "driver_plugin": "pppoe_client", "state": state, "usable": open,
            "real_interface": profile.get("interface"), "physical_interface": profile.get("interface"),
            "wan_interface": local, "local_interface": local, "pipeline_interface": pipeline, "handoff_mode": mode,
            "mac_address": js::first(&[g(profile, "mac_address"), g(session, "local_mac"), &json!("")]),
            "local_mac": js::or(g(session, "local_mac"), &json!("")), "peer_mac": js::or(g(session, "ac_mac"), &json!("")),
            "ac_mac": js::or(g(session, "ac_mac"), &json!("")), "session_id": js::num(clamp_int(g(session, "session_id"), 0.0, 65535.0, 0.0)),
            "session_id_hex": js::or(g(session, "session_id_hex"), &json!("")), "auth": profile.get("auth"),
            "auth_method": js::or(g(session, "auth_method"), &json!("")), "mtu": profile.get("mru"),
            "ipv4": js::or(g(ipcp, "address"), &json!("")), "ipv4_peer": js::or(g(ipcp, "peer_address"), &json!("")),
            "ipv6": ipv6, "ipv6_address": ipv6, "ipv6_addresses": addresses,
            "ipv6_link_local": js::or(g(ipv6cp, "link_local"), &json!("")), "ipv6_peer_link_local": js::or(g(ipv6cp, "peer_link_local"), &json!("")),
            "ipv6_gateway": js::first(&[g(ra, "router"), g(ipv6cp, "peer_link_local"), &json!("")]), "ipv6_prefix": js::or(g(ra, "prefix"), &json!("")),
            "pd_prefix": pd_prefix, "pd_prefixes": prefixes,
            "install_default_route_v6": truthy(&pd_prefix) || truthy(g(session, "ipv6")),
            "dns_servers": unique_text_values(&dns), "tunnel": if truthy(tunnel) { tunnel.clone() } else { Value::Null },
            "handoff": {"preferred_mode": mode, "local_interface": local, "pipeline_interface": pipeline, "veer_core_parent_interface": local,
                "segmentation_ready": truthy(&pipeline), "requires_kernel_tc_prepared_l2": false},
            "updated_at": if truthy(g(session, "updated_at")) { session["updated_at"].clone() } else { json!(iso_now()) },
        })
    }

    fn sync_wan_core(&self, profile: &Value, link: &Value) -> Result<Value> {
        if !flag(profile, "wan_core_sync") {
            return Ok(Value::Null);
        }
        let enabled = flag(link, "usable");
        let outcome = (|| -> Result<()> {
            self.require_wan_core_service_endpoint(profile, "resources", "sessions")?;
            self.host.call("plugins.resources.set", json!([profile["wan_core_plugin"], "sessions", link["wan_id"], link, enabled, profile["wan_core_apply"]]))?;
            Ok(())
        })();
        Ok(match outcome {
            Ok(()) => json!({"status": "synced", "plugin": profile["wan_core_plugin"], "resource": "sessions", "key": link["wan_id"], "enabled": enabled,
                "applied": flag(profile, "wan_core_apply")}),
            Err(err) => json!({"status": "error", "plugin": profile["wan_core_plugin"], "resource": "sessions", "key": link["wan_id"], "error": error_message(&err)}),
        })
    }

    fn require_wan_core_service_endpoint(&self, profile: &Value, kind: &str, id: &str) -> Result<Value> {
        let provider = self.host.call("plugins.services.resolve", json!([{"service": "wan.adapter", "version": "^1.0.0", "provider": profile["wan_core_plugin"]}]))?;
        let endpoints = g(g(&provider, "service"), kind);
        if !js::array(endpoints).iter().any(|e| e.as_str() == Some(id)) || !endpoints.is_array() {
            bail!("WAN adapter service does not expose {kind} endpoint {id}");
        }
        Ok(provider["service"].clone())
    }

    pub fn disconnect_session(&self, profile: &Value, payload: &Value) -> Result<Value> {
        let data = self.res_data("sessions", "last")?.unwrap_or(json!({}));
        let session_id = clamp_int(js::or(g(payload, "session_id"), g(&data, "session_id")), 1.0, 65535.0, 0.0) as u64;
        let peer = mac_text(js::first(&[g(payload, "ac_mac"), g(&data, "ac_mac"), &json!("")]))?;
        let key = s(profile, "profile_key");
        if session_id == 0 || peer.is_empty() {
            for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER] {
                self.timer_clear(name)?;
            }
            self.clear_tunnel_config()?;
            let cleanup = self.cleanup_l2_identity(&key, false)?;
            let done = merge(&data, &json!({"phase": "disconnected", "desired_state": "down", "lcp_ready": false, "padt_sent": false,
                "disconnect_noop": true, "l2_identity_cleanup": cleanup, "updated_at": iso_now()}));
            self.res_set("sessions", "last", &done)?;
            self.mark_wan_link_down(profile, &done, "disconnected")?;
            return Ok(done);
        }
        let disconnecting = merge(&data, &json!({"phase": "disconnecting", "desired_state": "down", "lcp_ready": false, "redial_generation": "", "updated_at": iso_now()}));
        self.res_set("sessions", "last", &disconnecting)?;
        for name in ["lcp_echo", "session_control", REDIAL_RETRY_TIMER, DHCPV6_LEASE_TIMER] {
            self.timer_clear(name)?;
        }
        let started = now();
        let drain = num(profile, "disconnect_drain_ms");
        let frames = self.send_padt(profile, &peer, session_id, drain)?;
        let mut control = session::new_control_window_result(drain);
        let expected = json!({"terminate_request": true});
        self.consume_ppp_control_frames(profile, &peer, session_id, frames, &expected, &mut control)?;
        if drain > 0.0 && num(&control, "terminate_acks_sent") == 0.0 {
            let outcome = (|| -> Result<()> {
                let remaining = (drain - (now() - started)).max(0.0);
                if remaining > 0.0 {
                    let window = self.service_ppp_control_window(profile, &peer, session_id, remaining, &expected)?;
                    control = session::merge_control_window_result(Some(&control), &window);
                } else {
                    session::finish_control_window_result(&mut control, &expected);
                }
                Ok(())
            })();
            if let Err(err) = outcome {
                control["phase"] = json!("error");
                control["error"] = json!(error_message(&err));
            }
        }
        self.clear_tunnel_config()?;
        let cleanup = self.cleanup_l2_identity(&key, false)?;
        let disconnected = merge(&disconnecting, &json!({"phase": "disconnected", "padt_sent": true,
            "lcp_terminate_ack_sent": num(&control, "terminate_acks_sent") > 0.0, "disconnect_control": control,
            "l2_identity_cleanup": cleanup, "updated_at": iso_now()}));
        self.res_set("sessions", "last", &disconnected)?;
        self.mark_wan_link_down(profile, &disconnected, "disconnected")?;
        Ok(disconnected)
    }
}

pub(crate) fn base_result(profile: &Value, phase: &str, extra: Value) -> Value {
    let out = json!({"phase": phase, "profile_key": profile.get("profile_key"), "interface": profile.get("interface"), "mac_mode": profile.get("mac_mode"),
        "mac_address": js::or(g(profile, "mac_address"), &json!("")), "service": profile.get("service"), "auth": profile.get("auth"), "updated_at": iso_now()});
    merge(&out, &extra)
}

fn apply_effective_l2_identity(profile: &mut Value, data: &Value) {
    profile["interface"] = data["interface"].clone();
    profile["mac_address"] = data["mac_address"].clone();
    // Discovery, control, and tunneled data must use one PPPoE client
    // identity. A persisted wan_src_mac from an older interface/MAC mode
    // would otherwise create a valid session whose data packets are silently
    // rejected by the AC.
    profile["wan_src_mac"] = data["mac_address"].clone();
    profile["wan_interface"] = data["interface"].clone();
}

fn same_l2_identity_record(previous: Option<&Value>, next: &Value) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    let same = |key: &str| js::strict_eq(g(previous, key), g(next, key));
    same("profile_key")
        && same("interface")
        && lower(g(previous, "interface_mac")) == lower(g(next, "interface_mac"))
        && same("mac_mode")
        && lower(g(previous, "mac_address")) == lower(g(next, "mac_address"))
        && same("custom_mac")
        && same("original_promiscuous")
        && same("promisc_enabled_by_plugin")
        && same("state")
}

fn unicast_mac_text(value: &Value) -> Result<String> {
    let normalized = mac_text(value)?;
    if normalized.is_empty() {
        bail!("mac address is required");
    }
    let first = u8::from_str_radix(&normalized[..2], 16).unwrap_or(0);
    if first & 1 != 0 || normalized == "00:00:00:00:00:00" {
        bail!("mac address must be non-zero unicast");
    }
    Ok(normalized)
}

pub(crate) fn tunnel_interface_mtu(profile: &Value) -> f64 {
    clamp_int(first_defined(&[g(profile, "tunnel_mtu"), g(profile, "local_mtu"), g(profile, "mru")]), 576.0, 1492.0, 1492.0)
}

fn require_installed_tunnel(session: &Value) -> Result<()> {
    if !truthy(session) || !flag(session, "tunnel_installed") || !truthy(g(session, "tunnel")) {
        let phase = text(js::or(g(session, "phase"), &json!("unknown")));
        let message = if truthy(g(session, "message")) { format!(" message={}", js::string(&session["message"])) } else { String::new() };
        bail!("PPPoE traffic_probe did not install tunnel: phase={phase}{message}");
    }
    Ok(())
}

fn wan_core_sync_succeeded(sync: &Value) -> bool {
    truthy(sync) && s(sync, "status") == "synced" && flag(sync, "applied")
}

fn select_tunnel_config_record(records: &[Value]) -> Option<Value> {
    records
        .iter()
        .find(|r| truthy(r) && !js::is_false(g(r, "enabled")) && token(js::or(g(r, "key"), &json!(TUNNEL_CONFIG_KEY))) == TUNNEL_CONFIG_KEY)
        .cloned()
}

fn zero_tunnel_config_hex() -> String {
    repeat_hex("00", TUNNEL_CONFIG_HEX_BYTES)
}

pub(crate) fn normalize_lcp_magic_hex(value: &Value) -> Result<String> {
    let raw = lower(if truthy(value) { value } else { &Value::Null });
    let raw = raw.strip_prefix("0x").unwrap_or(&raw);
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() {
        return Ok(repeat_hex("00", 4));
    }
    if hex.len() != 8 {
        bail!("LCP magic must be 4 bytes");
    }
    Ok(hex)
}

fn tunnel_config_value_hex(data: &Value) -> Result<String> {
    let c = |key: &str, min: f64, max: f64, fallback: f64| clamp_int(g(data, key), min, max, fallback) as u64;
    let mac = |key: &str| -> Result<String> { mac_hex(&js::string(js::or(g(data, key), &json!("00:00:00:00:00:00")))) };
    Ok(format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}{}",
        u32lehex(c("enabled", 0.0, 1.0, 1.0)),
        u32lehex(c("local_ifindex", 0.0, 2147483647.0, 0.0)),
        u32lehex(c("pipeline_ifindex", 0.0, 2147483647.0, 0.0)),
        u32lehex(c("wan_ifindex", 0.0, 2147483647.0, 0.0)),
        u16lehex(c("session_id", 0.0, 65535.0, 0.0)),
        u16lehex(c("flags", 0.0, 65535.0, 0.0)),
        u16lehex(c("mss_clamp_v4", 0.0, 65535.0, 0.0)),
        u16lehex(c("mss_clamp_v6", 0.0, 65535.0, 0.0)),
        mac("local_src_mac")?,
        mac("local_dst_mac")?,
        mac("wan_src_mac")?,
        mac("wan_dst_mac")?,
        normalize_lcp_magic_hex(g(data, "lcp_magic"))?
    ))
}

fn normalize_tunnel_config_value_hex(value: &str) -> Result<String> {
    let value = value.trim().to_lowercase();
    let value = value.strip_prefix("0x").unwrap_or(&value);
    let hex: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() == LEGACY_TUNNEL_CONFIG_HEX_BYTES * 2 {
        return Ok(hex + &repeat_hex("00", TUNNEL_CONFIG_HEX_BYTES - LEGACY_TUNNEL_CONFIG_HEX_BYTES));
    }
    if hex.len() != TUNNEL_CONFIG_HEX_BYTES * 2 {
        bail!("tunnel config value_hex must be {TUNNEL_CONFIG_HEX_BYTES} bytes");
    }
    Ok(hex)
}

fn decode_tunnel_config_hex(hex: &str) -> Result<Value> {
    let hex = normalize_tunnel_config_value_hex(hex)?;
    let b = hex_to_bytes(&hex);
    Ok(json!({
        "enabled": u32le_at(&b, 0), "local_ifindex": u32le_at(&b, 4), "pipeline_ifindex": u32le_at(&b, 8), "wan_ifindex": u32le_at(&b, 12),
        "session_id": u16le_at(&b, 16), "flags": u16le_at(&b, 18), "mss_clamp_v4": u16le_at(&b, 20), "mss_clamp_v6": u16le_at(&b, 22),
        "local_src_mac": mac_bytes_to_text(&b[24..30]), "local_dst_mac": mac_bytes_to_text(&b[30..36]),
        "wan_src_mac": mac_bytes_to_text(&b[36..42]), "wan_dst_mac": mac_bytes_to_text(&b[42..48]), "value_hex": hex,
    }))
}

#[cfg(test)]
mod tests;
