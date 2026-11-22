//! Raw-L2 exchanges: PPPoE discovery, LCP and authentication, IPCP and
//! IPv6CP, router solicitation, DHCPv6, and the control windows that answer
//! the peer's requests while a session is up.

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, json, Result, Value};

use crate::codec::*;
use crate::{error_message, flag, num, s, Ctx, ETH_P_PPP_DISC, ETH_P_PPP_SESS, MAX_L2_RECV_TIMEOUT_MS};

const LCP_OPTION_AUTH_PROTOCOL: u64 = 3;
const CHAP_ALGORITHM_MD5: u8 = 5;
const IPCP_OPTION_IP_ADDRESS: u64 = 3;
const IPCP_OPTION_PRIMARY_DNS: u64 = 129;
const IPCP_OPTION_SECONDARY_DNS: u64 = 131;
const IPV6CP_OPTION_INTERFACE_ID: u64 = 1;
const ICMPV6_ROUTER_SOLICIT: u64 = 133;
const ICMPV6_ROUTER_ADVERT: u64 = 134;
const ND_OPT_PREFIX_INFORMATION: u8 = 3;
const ND_OPT_RDNSS: u8 = 25;

fn push(out: &mut Value, key: &str, item: Value) {
    if !out[key].is_array() {
        out[key] = json!([]);
    }
    out[key].as_array_mut().unwrap().push(item);
}

pub fn lcp_ready_for_network_cp(out: &Value) -> bool {
    if !flag(out, "lcp_ack") || !flag(out, "peer_lcp_ack_sent") {
        return false;
    }
    !flag(out, "auth_required") || flag(out, "auth_ok")
}

pub fn new_control_window_result(duration_ms: f64) -> Value {
    json!({"phase": "drained", "duration_ms": js::num(duration_ms), "polls": 0, "frames": 0, "skipped": 0, "timeouts": 0, "parse_errors": 0,
        "io_errors": 0, "configure_acks_sent": 0, "acked_protocols": {}, "echo_replies_sent": 0, "terminate_acks_sent": 0,
        "lcp_echo_reply": false, "lcp_echo_code": 0, "events": []})
}

fn incr(out: &mut Value, key: &str) {
    out[key] = js::num(num(out, key) + 1.0);
}

pub fn finish_control_window_result(out: &mut Value, expected: &Value) {
    if flag(expected, "terminate_request") && num(out, "terminate_acks_sent") == 0.0 {
        out["phase"] = json!("terminate_timeout");
    } else if !g(expected, "lcp_echo_identifier").is_null() && !flag(out, "lcp_echo_reply") {
        out["phase"] = json!("echo_timeout");
    } else if num(out, "frames") == 0.0 && num(out, "timeouts") > 0.0 {
        out["phase"] = json!("timeout");
    }
}

pub fn merge_control_window_result(previous: Option<&Value>, next: &Value) -> Value {
    let Some(previous) = previous.filter(|p| truthy(p) && js::strict_eq(g(p, "session_id"), g(next, "session_id"))) else {
        return next.clone();
    };
    let mut out = merge(
        previous,
        &json!({"phase": if num(next, "remaining_ms") > 0.0 { json!("active") } else { next["phase"].clone() }, "remaining_ms": next.get("remaining_ms"),
            "session_id": next.get("session_id"), "ac_mac": next.get("ac_mac"), "updated_at": next.get("updated_at")}),
    );
    let sum = |key: &str, max: f64| js::num(clamp_int(g(previous, key), 0.0, max, 0.0) + clamp_int(g(next, key), 0.0, max, 0.0));
    out["duration_ms"] = sum("duration_ms", 600000.0);
    for key in ["polls", "frames", "skipped", "timeouts", "parse_errors", "io_errors", "configure_acks_sent", "echo_replies_sent", "terminate_acks_sent"] {
        out[key] = sum(key, 1000000.0);
    }
    out["lcp_echo_reply"] = json!(truthy(g(previous, "lcp_echo_reply")) || truthy(g(next, "lcp_echo_reply")));
    out["lcp_echo_code"] = js::first(&[g(next, "lcp_echo_code"), g(previous, "lcp_echo_code"), &json!(0)]).clone();
    let mut events = js::array(g(previous, "events"));
    events.extend(js::array(g(next, "events")));
    if events.len() > 24 {
        events = events.split_off(events.len() - 24);
    }
    out["events"] = Value::Array(events);
    out
}

impl<'a> Ctx<'a> {
    // -------------------------------------------------------- l2 requests

    fn l2_many(&self, method: &str, request: &Value) -> Result<Vec<Value>> {
        Ok(js::array(&self.host.call(method, json!([request]))?))
    }

    fn l2_one(&self, method: &str, request: &Value) -> Result<Option<Value>> {
        let value = self.host.call(method, json!([request]))?;
        Ok(if value.is_null() { None } else { Some(value) })
    }

    fn apply_identity(&self, profile: &Value, req: &mut Value) -> Result<()> {
        let mac = if truthy(g(profile, "mac_address")) { mac_text(g(profile, "mac_address"))? } else { String::new() };
        if !mac.is_empty() {
            req["src_mac"] = json!(mac);
            req["recv_dst_mac"] = json!(mac);
        }
        Ok(())
    }

    fn discovery_filter(&self, mut req: Value, want_code: Option<u64>, peer: &str, profile: &Value) -> Result<Value> {
        self.apply_identity(profile, &mut req)?;
        if let Some(code) = want_code {
            req["pppoe_code"] = json!(code);
        }
        if !peer.is_empty() {
            req["recv_src_mac"] = json!(peer);
        }
        Ok(req)
    }

    fn session_filter(&self, mut req: Value, peer: &str, session_id: u64, profile: &Value) -> Result<Value> {
        self.apply_identity(profile, &mut req)?;
        if !peer.is_empty() {
            req["recv_src_mac"] = json!(peer);
        }
        if session_id != 0 {
            req["pppoe_session_id"] = json!(session_id);
        }
        req["pppoe_code"] = json!(0);
        Ok(req)
    }

    // -------------------------------------------------------- discovery

    pub fn send_padi(&self, profile: &Value, host_uniq: &str) -> Result<Option<Value>> {
        let padi = pppoe_discovery(CODE_PADI, 0, &[tag_string(TAG_SERVICE_NAME, &s(profile, "service")), tag_hex(TAG_HOST_UNIQ, host_uniq)]);
        self.exchange_discovery(profile, "ff:ff:ff:ff:ff:ff", &padi, CODE_PADO, host_uniq, "")
    }

    pub fn send_padr(&self, profile: &Value, peer: &str, host_uniq: &str, tags: &[String]) -> Result<Option<Value>> {
        self.exchange_discovery(profile, peer, &pppoe_discovery(CODE_PADR, 0, tags), CODE_PADS, host_uniq, peer)
    }

    fn exchange_discovery(&self, profile: &Value, dst: &str, payload: &str, want_code: u64, host_uniq: &str, peer: &str) -> Result<Option<Value>> {
        let timeout = num(profile, "timeout_ms");
        let deadline = crate::now() + timeout;
        let frame_limit = (num(profile, "max_frames") * 4.0).max(8.0).min(32.0);
        let ac_name = if want_code == CODE_PADO { s(profile, "ac_name") } else { String::new() };
        let req = self.discovery_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_DISC, "dst_mac": dst, "payload": payload, "timeout_ms": js::num(timeout),
                "max_bytes": 1500, "max_frames": js::num(frame_limit), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
            Some(want_code),
            peer,
            profile,
        )?;
        let first = self.l2_many("net.l2.exchangeMany", &req)?;
        if let Some(found) = find_discovery_frame(&first, want_code, host_uniq, peer, &ac_name)? {
            return Ok(Some(found));
        }
        while crate::now() < deadline {
            let remaining = timeout.min(deadline - crate::now()).max(1.0);
            let req = self.discovery_filter(
                json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_DISC, "timeout_ms": js::num(remaining), "max_bytes": 1500,
                    "max_frames": js::num(frame_limit), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
                Some(want_code),
                peer,
                profile,
            )?;
            let frames = self.l2_many("net.l2.recvMany", &req)?;
            if frames.is_empty() {
                break;
            }
            if let Some(found) = find_discovery_frame(&frames, want_code, host_uniq, peer, &ac_name)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    // -------------------------------------------------------- session probe

    pub fn run_session_probe(&self, profile: &mut Value, peer: &str, session_id: u64, local_mac: &str) -> Result<Value> {
        let identifier = self.random_byte()?;
        let magic = self.random_hex(4)?;
        profile["lcp_magic"] = json!(crate::normalize_lcp_magic_hex(&json!(magic))?);
        let lcp_request = cp_packet(1, identifier, &(cp_option_u16(1, num(profile, "mru") as u64) + &cp_option_hex(5, &s(profile, "lcp_magic"))));
        let mut out = json!({"items": [], "lcp_ack": false, "peer_lcp_ack_sent": false, "auth_required": false, "peer_auth_method": "",
            "auth_sent": false, "auth_method": "", "auth_ok": false, "ipcp": null, "ipv6cp": null, "dhcpv6_pd": null,
            "lcp_magic": profile["lcp_magic"], "peer_cp_acked": {}});
        let timeout = num(profile, "timeout_ms");
        let max_frames = num(profile, "max_frames");
        let first = self.exchange_ppp_control_frames(profile, peer, session_id, PPP_LCP, &lcp_request, timeout, max_frames)?;
        if first.is_empty() {
            push(&mut out, "items", json!({"protocol": "lcp", "event": "timeout"}));
            return Ok(out);
        }
        self.process_session_frames(profile, peer, session_id, &first, identifier, &mut out)?;
        for _ in 1..max_frames as u64 {
            if lcp_ready_for_network_cp(&out) {
                break;
            }
            let frames = self.recv_ppp_session_frames(profile, timeout, 1.0, peer, session_id)?;
            let Some(frame) = frames.into_iter().next() else {
                push(&mut out, "items", json!({"event": "timeout"}));
                break;
            };
            self.process_session_frame(profile, peer, session_id, &frame, identifier, &mut out)?;
        }
        if lcp_ready_for_network_cp(&out) && flag(profile, "negotiate_ipv4") {
            self.drain_peer_control_after_auth(profile, peer, session_id, &mut out)?;
            let mut acked = out["peer_cp_acked"].clone();
            let mut ipcp = self.run_ipcp(profile, peer, session_id, &mut acked)?;
            out["peer_cp_acked"] = acked;
            if truthy(g(&out, "peer_ipcp")) {
                ipcp["peer_address"] = js::or(g(g(&out, "peer_ipcp"), "address"), &json!("")).clone();
            }
            let phase = js::or(g(&ipcp, "phase"), &json!("complete")).clone();
            out["ipcp"] = ipcp;
            push(&mut out, "items", json!({"protocol": "ipcp", "event": phase}));
        }
        if lcp_ready_for_network_cp(&out) && flag(profile, "negotiate_ipv6") {
            self.drain_peer_control_after_auth(profile, peer, session_id, &mut out)?;
            let mut acked = out["peer_cp_acked"].clone();
            let mut ipv6cp = self.run_ipv6cp(profile, peer, session_id, &mut acked)?;
            out["peer_cp_acked"] = acked;
            if truthy(g(&out, "peer_ipv6cp")) {
                ipv6cp["peer_interface_id"] = js::or(g(g(&out, "peer_ipv6cp"), "interface_id"), &json!("")).clone();
                ipv6cp["peer_link_local"] = js::or(g(g(&out, "peer_ipv6cp"), "link_local"), &json!("")).clone();
            }
            let phase = js::or(g(&ipv6cp, "phase"), &json!("complete")).clone();
            out["ipv6cp"] = ipv6cp;
            push(&mut out, "items", json!({"protocol": "ipv6cp", "event": phase}));
        }
        let v6_up = truthy(g(&out, "ipv6cp")) && flag(&out["ipv6cp"], "up");
        if lcp_ready_for_network_cp(&out) && flag(profile, "request_ipv6_router") && v6_up {
            let ra = self.request_ipv6_router(profile, peer, session_id)?;
            let phase = js::or(g(&ra, "phase"), &json!("complete")).clone();
            out["ipv6_ra"] = ra;
            push(&mut out, "items", json!({"protocol": "icmpv6", "event": phase}));
        }
        if lcp_ready_for_network_cp(&out) && (flag(profile, "request_ipv6_address") || flag(profile, "request_pd")) && v6_up {
            let pd = self.request_dhcpv6_pd(profile, peer, session_id, local_mac)?;
            let phase = js::or(g(&pd, "phase"), &json!("complete")).clone();
            out["dhcpv6_pd"] = pd;
            push(&mut out, "items", json!({"protocol": "dhcpv6", "event": phase}));
        }
        Ok(out)
    }

    fn process_session_frame(&self, profile: &Value, peer: &str, session_id: u64, frame: &Value, our_lcp_id: u64, out: &mut Value) -> Result<()> {
        let parsed = parse_session_frame(frame)?;
        if parsed.session_id != session_id {
            push(out, "items", json!({"event": "skip_session", "session_id": parsed.session_id}));
            return Ok(());
        }
        self.handle_ppp_frame(profile, peer, session_id, &parsed, our_lcp_id, out)
    }

    fn process_session_frames(&self, profile: &Value, peer: &str, session_id: u64, frames: &[Value], our_lcp_id: u64, out: &mut Value) -> Result<()> {
        let limit = (num(profile, "max_frames") * 2.0).min(16.0) as usize;
        for frame in frames.iter().take(limit) {
            self.process_session_frame(profile, peer, session_id, frame, our_lcp_id, out)?;
        }
        Ok(())
    }

    fn handle_ppp_frame(&self, profile: &Value, peer: &str, session_id: u64, parsed: &SessionFrame, our_lcp_id: u64, out: &mut Value) -> Result<()> {
        let timeout = num(profile, "timeout_ms");
        let max_frames = num(profile, "max_frames");
        match parsed.protocol {
            PPP_LCP => {
                let lcp = parse_cp(&parsed.payload);
                push(out, "items", json!({"protocol": "lcp", "code": lcp.code, "identifier": lcp.identifier, "length": lcp.length}));
                if lcp.code == 1 {
                    self.record_peer_authentication_requirement(profile, &lcp, out)?;
                    let next = self.exchange_ppp_control_frames(profile, peer, session_id, PPP_LCP, &cp_packet(2, lcp.identifier, &lcp.data_hex), timeout, max_frames)?;
                    out["peer_lcp_ack_sent"] = json!(true);
                    push(out, "items", json!({"protocol": "lcp", "event": "configure_ack_sent", "identifier": lcp.identifier}));
                    if !next.is_empty() {
                        self.process_session_frames(profile, peer, session_id, &next, our_lcp_id, out)?;
                    }
                    self.maybe_send_pap(profile, peer, session_id, our_lcp_id, out)?;
                } else if lcp.code == 2 && lcp.identifier == our_lcp_id {
                    out["lcp_ack"] = json!(true);
                    push(out, "items", json!({"protocol": "lcp", "event": "local_configure_ack"}));
                    self.maybe_send_pap(profile, peer, session_id, our_lcp_id, out)?;
                }
            }
            PPP_CHAP => {
                let chap = parse_cp(&parsed.payload);
                push(out, "items", json!({"protocol": "chap", "code": chap.code, "identifier": chap.identifier, "length": chap.length}));
                if chap.code == 1 && authentication_method(profile, out, "chap") == "chap" && !flag(out, "auth_sent") {
                    require_authentication_credentials(profile, "chap")?;
                    let frames = self.send_chap_response_frames(profile, peer, session_id, &chap)?;
                    out["auth_sent"] = json!(true);
                    out["auth_method"] = json!("chap");
                    if frames.is_empty() {
                        push(out, "items", json!({"protocol": "chap", "event": "timeout"}));
                    } else {
                        self.process_session_frames(profile, peer, session_id, &frames, our_lcp_id, out)?;
                    }
                } else if chap.code == 3 {
                    out["auth_ok"] = json!(true);
                    out["auth_method"] = json!("chap");
                }
            }
            PPP_PAP => {
                let pap = parse_cp(&parsed.payload);
                push(out, "items", json!({"protocol": "pap", "code": pap.code, "identifier": pap.identifier, "length": pap.length}));
                if pap.code == 2 {
                    out["auth_ok"] = json!(true);
                    out["auth_method"] = json!("pap");
                }
            }
            PPP_IPCP | PPP_IPV6CP => self.handle_peer_network_control(profile, peer, session_id, parsed, out)?,
            other => push(out, "items", json!({"protocol": format!("0x{}", u16hex(other)), "length": parsed.payload.len() / 2})),
        }
        Ok(())
    }

    fn record_peer_authentication_requirement(&self, profile: &Value, lcp: &Cp, out: &mut Value) -> Result<()> {
        let mut requirement: Option<(String, u64)> = None;
        for option in parse_cp_options(&lcp.data_hex) {
            if option.ty != LCP_OPTION_AUTH_PROTOCOL {
                continue;
            }
            if requirement.is_some() {
                bail!("peer LCP contains multiple authentication protocol options");
            }
            requirement = Some(parse_lcp_authentication_option(&option)?);
        }
        let Some((method, _)) = requirement else {
            if !flag(out, "auth_required") {
                out["peer_auth_method"] = json!("none");
            }
            return Ok(());
        };
        let auth = s(profile, "auth");
        if auth != "auto" && auth != method {
            bail!("peer requires {method} authentication but profile auth is {auth}");
        }
        out["auth_required"] = json!(true);
        out["peer_auth_method"] = json!(method);
        out["auth_method"] = json!(method);
        require_authentication_credentials(profile, &method)?;
        push(out, "items", json!({"protocol": "lcp", "event": "authentication_required", "method": method}));
        Ok(())
    }

    fn maybe_send_pap(&self, profile: &Value, peer: &str, session_id: u64, our_lcp_id: u64, out: &mut Value) -> Result<()> {
        if !flag(out, "lcp_ack") || !flag(out, "peer_lcp_ack_sent") || flag(out, "auth_sent") || !flag(out, "auth_required") || s(out, "peer_auth_method") != "pap" {
            return Ok(());
        }
        require_authentication_credentials(profile, "pap")?;
        let frames = self.send_pap_frames(profile, peer, session_id)?;
        out["auth_sent"] = json!(true);
        out["auth_method"] = json!("pap");
        if frames.is_empty() {
            push(out, "items", json!({"protocol": "pap", "event": "timeout"}));
        } else {
            self.process_session_frames(profile, peer, session_id, &frames, our_lcp_id, out)?;
        }
        Ok(())
    }

    fn drain_peer_control_after_auth(&self, profile: &Value, peer: &str, session_id: u64, out: &mut Value) -> Result<()> {
        if flag(out, "peer_control_drained") {
            return Ok(());
        }
        out["peer_control_drained"] = json!(true);
        let result = self.service_ppp_control_window(profile, peer, session_id, num(profile, "control_ack_timeout_ms"), &Value::Null)?;
        if let Some(acked) = result["acked_protocols"].as_object() {
            for protocol in acked.keys() {
                out["peer_cp_acked"][protocol.as_str()] = json!(true);
            }
        }
        let busy = ["frames", "configure_acks_sent", "skipped", "parse_errors"].iter().any(|k| num(&result, k) != 0.0);
        if busy {
            push(out, "items", json!({"event": "peer_control_drained", "frames": result["frames"], "configure_acks_sent": result["configure_acks_sent"],
                "skipped": result["skipped"], "parse_errors": result["parse_errors"]}));
        }
        Ok(())
    }

    fn handle_peer_network_control(&self, profile: &Value, peer: &str, session_id: u64, parsed: &SessionFrame, out: &mut Value) -> Result<()> {
        let cp = parse_cp(&parsed.payload);
        let protocol = ppp_control_protocol_name(parsed.protocol);
        let mut event = json!({"protocol": protocol, "code": cp.code, "identifier": cp.identifier, "length": cp.length});
        annotate_peer_network_control(parsed.protocol, &cp, &mut event, Some(out))?;
        push(out, "items", event);
        if cp.code == 1 {
            self.send_ppp_control(profile, peer, session_id, parsed.protocol, &cp_packet(2, cp.identifier, &cp.data_hex))?;
            push(out, "items", json!({"protocol": protocol, "event": "configure_ack_sent", "identifier": cp.identifier}));
            if out["peer_cp_acked"].is_object() {
                out["peer_cp_acked"][protocol.as_str()] = json!(true);
            }
            return Ok(());
        }
        push(out, "items", json!({"protocol": protocol, "event": cp_code_name(cp.code), "identifier": cp.identifier}));
        Ok(())
    }

    fn send_pap_frames(&self, profile: &Value, peer: &str, session_id: u64) -> Result<Vec<Value>> {
        let user = string_hex(&s(profile, "username"));
        let pass = string_hex(&s(profile, "password"));
        let data = format!("{}{user}{}{pass}", hb((user.len() / 2) as u64), hb((pass.len() / 2) as u64));
        let id = self.random_byte()?;
        self.exchange_ppp_control_frames(profile, peer, session_id, PPP_PAP, &cp_packet(1, id, &data), num(profile, "timeout_ms"), num(profile, "max_frames"))
    }

    fn send_chap_response_frames(&self, profile: &Value, peer: &str, session_id: u64, challenge: &Cp) -> Result<Vec<Value>> {
        let bytes = hex_to_bytes(&challenge.data_hex);
        if bytes.is_empty() {
            bail!("empty CHAP challenge");
        }
        let size = bytes[0] as usize;
        let value_hex = bytes_to_hex(&bytes[1..(1 + size).min(bytes.len())]);
        let digest = js::string(&self.host.call("crypto.md5", json!([[challenge.identifier], s(profile, "password"), {"hex": value_hex}]))?);
        let data = format!("{}{digest}{}", hb(16), string_hex(&s(profile, "username")));
        self.exchange_ppp_control_frames(profile, peer, session_id, PPP_CHAP, &cp_packet(2, challenge.identifier, &data), num(profile, "timeout_ms"), num(profile, "max_frames"))
    }

    // -------------------------------------------------------- IPCP / IPv6CP

    fn run_ipcp(&self, profile: &Value, peer: &str, session_id: u64, acked: &mut Value) -> Result<Value> {
        let mut requested_ip = "0.0.0.0".to_string();
        let mut requested_dns = [("0.0.0.0".to_string(), IPCP_OPTION_PRIMARY_DNS), ("0.0.0.0".to_string(), IPCP_OPTION_SECONDARY_DNS)];
        let mut enabled_dns = [true, true];
        let mut last = Value::Null;
        for attempt in 0..num(profile, "max_frames") as u64 {
            let identifier = self.random_byte()?;
            let mut options = cp_option_ipv4(IPCP_OPTION_IP_ADDRESS, &requested_ip);
            for (i, (addr, ty)) in requested_dns.iter().enumerate() {
                if enabled_dns[i] {
                    options.push_str(&cp_option_ipv4(*ty, addr));
                }
            }
            let frame = self.exchange_ppp_control(profile, peer, session_id, PPP_IPCP, &cp_packet(1, identifier, &options), None)?;
            let result = self.complete_cp_negotiation(profile, peer, session_id, PPP_IPCP, identifier, frame, acked)?;
            let Some((protocol, cp)) = result else {
                return Ok(json!({"phase": "timeout", "requested_address": requested_ip}));
            };
            if protocol != PPP_IPCP {
                return Ok(json!({"phase": "unexpected_protocol", "protocol": format!("0x{}", u16hex(protocol)), "requested_address": requested_ip}));
            }
            let parsed = parse_cp_options(&cp.data_hex);
            let ip = first_cp_ipv4_option(&parsed, IPCP_OPTION_IP_ADDRESS);
            let primary_offer = first_cp_ipv4_option(&parsed, IPCP_OPTION_PRIMARY_DNS);
            let secondary_offer = first_cp_ipv4_option(&parsed, IPCP_OPTION_SECONDARY_DNS);
            let primary = if primary_offer.is_empty() { requested_dns[0].0.clone() } else { primary_offer.clone() };
            let secondary = if secondary_offer.is_empty() { requested_dns[1].0.clone() } else { secondary_offer.clone() };
            last = json!({"phase": cp_code_name(cp.code), "up": cp.code == 2, "code": cp.code, "identifier": cp.identifier,
                "address": if ip.is_empty() { requested_ip.clone() } else { ip.clone() }, "requested_address": requested_ip, "attempts": attempt + 1,
                "dns_servers": usable_ipcp_dns_servers(&enabled_dns, &primary, &secondary)});
            if cp.code == 2 {
                last["peer"] = self.ack_peer_configure_requests(profile, peer, session_id, PPP_IPCP, acked)?;
                return Ok(last);
            }
            if cp.code == 3 {
                if !ip.is_empty() {
                    requested_ip = ip;
                }
                if !primary_offer.is_empty() {
                    requested_dns[0].0 = primary;
                }
                if !secondary_offer.is_empty() {
                    requested_dns[1].0 = secondary;
                }
                continue;
            }
            if cp.code == 4 {
                let mut removed_dns = false;
                let mut rejected_address = false;
                for option in &parsed {
                    if option.ty == IPCP_OPTION_IP_ADDRESS {
                        rejected_address = true;
                    }
                    if option.ty == IPCP_OPTION_PRIMARY_DNS {
                        enabled_dns[0] = false;
                        removed_dns = true;
                    }
                    if option.ty == IPCP_OPTION_SECONDARY_DNS {
                        enabled_dns[1] = false;
                        removed_dns = true;
                    }
                }
                if removed_dns && !rejected_address {
                    continue;
                }
            }
            return Ok(last);
        }
        Ok(if last.is_null() { json!({"phase": "timeout", "requested_address": requested_ip}) } else { last })
    }

    fn run_ipv6cp(&self, profile: &mut Value, peer: &str, session_id: u64, acked: &mut Value) -> Result<Value> {
        let mut iid = s(profile, "ipv6_iid");
        if iid.is_empty() {
            iid = self.random_hex(8)?;
        }
        profile["ipv6_iid"] = json!(iid);
        let mut last = Value::Null;
        for attempt in 0..num(profile, "max_frames") as u64 {
            let identifier = self.random_byte()?;
            let req = cp_packet(1, identifier, &cp_option_hex(IPV6CP_OPTION_INTERFACE_ID, &iid));
            let frame = self.exchange_ppp_control(profile, peer, session_id, PPP_IPV6CP, &req, None)?;
            let Some((protocol, cp)) = self.complete_cp_negotiation(profile, peer, session_id, PPP_IPV6CP, identifier, frame, acked)? else {
                return Ok(json!({"phase": "timeout", "interface_id": iid}));
            };
            if protocol != PPP_IPV6CP {
                return Ok(json!({"phase": "unexpected_protocol", "protocol": format!("0x{}", u16hex(protocol)), "interface_id": iid}));
            }
            let suggested = first_cp_hex_option(&parse_cp_options(&cp.data_hex), IPV6CP_OPTION_INTERFACE_ID);
            let effective = if suggested.is_empty() { iid.clone() } else { suggested.clone() };
            last = json!({"phase": cp_code_name(cp.code), "up": cp.code == 2, "code": cp.code, "identifier": cp.identifier, "interface_id": effective,
                "link_local": link_local_from_iid(&effective)?, "requested_interface_id": iid, "attempts": attempt + 1});
            if cp.code == 2 || cp.code == 4 {
                last["peer"] = self.ack_peer_configure_requests(profile, peer, session_id, PPP_IPV6CP, acked)?;
                return Ok(last);
            }
            if cp.code == 3 && !suggested.is_empty() {
                iid = suggested;
                profile["ipv6_iid"] = json!(iid);
                continue;
            }
            return Ok(last);
        }
        Ok(if last.is_null() { json!({"phase": "timeout", "interface_id": iid}) } else { last })
    }

    fn request_ipv6_router(&self, profile: &Value, peer: &str, session_id: u64) -> Result<Value> {
        let iid = if s(profile, "ipv6_iid").is_empty() { self.random_hex(8)? } else { s(profile, "ipv6_iid") };
        let src = link_local_from_iid(&iid)?;
        let packet = ipv6_icmp(&src, "ff02::2", ICMPV6_ROUTER_SOLICIT, 0, "00000000", 255)?;
        let payload = pppoe_session(session_id, &(u16hex(PPP_IPV6) + &packet));
        let timeout = clamp_int(g(profile, "ipv6_ra_timeout_ms"), 500.0, 30000.0, 5000.0);
        let exchange_timeout = timeout.min(MAX_L2_RECV_TIMEOUT_MS);
        let deadline = crate::now() + timeout;
        let limit = (num(profile, "max_frames") * 4.0).max(8.0).min(32.0);
        let req = self.session_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer, "payload": payload, "timeout_ms": js::num(exchange_timeout),
                "max_bytes": 1500, "max_frames": js::num(limit), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
            peer,
            session_id,
            profile,
        )?;
        let frames = self.l2_many("net.l2.exchangeMany", &req)?;
        if let Some(found) = find_ipv6_router_advertisement(&frames, session_id, &iid)? {
            return Ok(found);
        }
        while crate::now() < deadline {
            let remaining = timeout.min(deadline - crate::now()).max(1.0);
            let frames = self.recv_ppp_session_frames(profile, remaining, limit, peer, session_id)?;
            if frames.is_empty() {
                break;
            }
            if let Some(found) = find_ipv6_router_advertisement(&frames, session_id, &iid)? {
                return Ok(found);
            }
        }
        Ok(json!({"phase": "timeout", "source": src}))
    }

    // -------------------------------------------------------- DHCPv6

    pub fn request_dhcpv6_pd(&self, profile: &Value, peer: &str, session_id: u64, local_mac: &str) -> Result<Value> {
        if num(profile, "dhcpv6_settle_ms") > 0.0 {
            self.service_ppp_control_window(profile, peer, session_id, num(profile, "dhcpv6_settle_ms"), &Value::Null)?;
        }
        let xid = self.random_hex(3)?;
        let iid = if s(profile, "ipv6_iid").is_empty() { self.random_hex(8)? } else { s(profile, "ipv6_iid") };
        let src = link_local_from_iid(&iid)?;
        let dst = "ff02::1:2";
        let client_id = dhcpv6_client_id_value(if local_mac.is_empty() { "02:00:00:00:00:01" } else { local_mac })?;
        let iaid = num(profile, "dhcpv6_iaid") as u64;
        let solicit = dhcpv6_solicit(&xid, &client_id, iaid, flag(profile, "request_ipv6_address"), flag(profile, "request_pd"));
        let Some(frame) = self.exchange_dhcpv6(profile, peer, session_id, &src, dst, &solicit, &xid)? else {
            return Ok(json!({"phase": "timeout", "transaction_id": xid}));
        };
        let reply = match parse_dhcpv6_reply_frame(&frame, &xid)? {
            Err(error) => return Ok(error),
            Ok(reply) => reply,
        };
        let offered = dhcpv6_lease_data(&reply.options);
        let server_id = first_dhcpv6_option_hex(&reply.options, DHCPV6_OPT_SERVERID);
        let result = merge(&json!({"phase": dhcpv6_message_phase(reply.message_type), "transaction_id": reply.transaction_id, "server_id": server_id}), &offered);
        if let Some((code, message)) = dhcpv6_top_level_status(&reply.options) {
            if code != 0 {
                return Ok(merge(&result, &json!({"phase": "advertise_status_error", "status_code": code, "status_message": message})));
            }
        }
        if reply.message_type != DHCPV6_ADVERTISE || !flag(profile, "dhcpv6_request") {
            return Ok(result);
        }
        let mut ia_na = s(&offered, "ia_na_hex");
        let mut ia_pd = s(&offered, "ia_pd_hex");
        if js::array(&offered["addresses"]).is_empty() && dhcpv6_ia_status_error(&offered, "ia_na").is_some() {
            ia_na.clear();
        }
        if js::array(&offered["prefixes"]).is_empty() && dhcpv6_ia_status_error(&offered, "ia_pd").is_some() {
            ia_pd.clear();
        }
        if server_id.is_empty() || (ia_na.is_empty() && ia_pd.is_empty()) {
            return Ok(merge(&result, &json!({"phase": "advertise_incomplete"})));
        }
        let request_xid = self.random_hex(3)?;
        let request = dhcpv6_stateful_request(DHCPV6_REQUEST, &request_xid, &client_id, &server_id, &ia_na, &ia_pd);
        let Some(request_frame) = self.exchange_dhcpv6(profile, peer, session_id, &src, dst, &request, &request_xid)? else {
            return Ok(merge(&result, &json!({"phase": "request_timeout", "request_transaction_id": request_xid})));
        };
        let final_reply = match parse_dhcpv6_reply_frame(&request_frame, &request_xid)? {
            Err(error) => return Ok(merge(&result, &error)),
            Ok(reply) => reply,
        };
        if final_reply.message_type != DHCPV6_REPLY {
            return Ok(merge(&result, &json!({"phase": "request_unexpected_message", "request_message_type": final_reply.message_type})));
        }
        if let Some((code, message)) = dhcpv6_top_level_status(&final_reply.options) {
            if code != 0 {
                return Ok(merge(&result, &json!({"phase": "request_status_error", "status_code": code, "status_message": message})));
            }
        }
        let leased = dhcpv6_lease_data(&final_reply.options);
        let or_list = |a: &Value, b: &Value| if js::array(a).is_empty() { b.clone() } else { a.clone() };
        let addresses = or_list(&leased["addresses"], &offered["addresses"]);
        let prefixes = or_list(&leased["prefixes"], &offered["prefixes"]);
        let has_addresses = !js::array(&addresses).is_empty();
        let has_prefixes = !js::array(&prefixes).is_empty();
        let final_server = first_dhcpv6_option_hex(&final_reply.options, DHCPV6_OPT_SERVERID);
        let bound = json!({
            "phase": dhcpv6_message_phase(final_reply.message_type), "transaction_id": final_reply.transaction_id, "advertise_transaction_id": reply.transaction_id,
            "server_id": if final_server.is_empty() { server_id.clone() } else { final_server }, "client_id": client_id, "iaid": iaid, "source_address": src,
            "address": if has_addresses { addresses[0]["address"].clone() } else { json!("") }, "addresses": addresses, "advertise_addresses": offered["addresses"],
            "prefix": if has_prefixes { prefixes[0]["prefix"].clone() } else { json!("") }, "prefixes": prefixes, "advertise_prefixes": offered["prefixes"],
            "dns_servers": or_list(&leased["dns_servers"], &offered["dns_servers"]),
            "ia_na_hex": if has_addresses { js::first(&[g(&leased, "ia_na_hex"), g(&offered, "ia_na_hex"), &json!("")]).clone() } else { json!("") },
            "ia_pd_hex": if has_prefixes { js::first(&[g(&leased, "ia_pd_hex"), g(&offered, "ia_pd_hex"), &json!("")]).clone() } else { json!("") },
            "ia_states": merge_by_type(&leased["ia_states"], &offered["ia_states"]),
            "ia_statuses": merge_by_type(&leased["ia_statuses"], &offered["ia_statuses"]),
            "renew_attempts": 0, "rebind_attempts": 0, "last_renew_error": "",
        });
        let mut bound = stamp_dhcpv6_lease(bound, crate::now());
        annotate_dhcpv6_partial_binding(profile, &mut bound);
        if !dhcpv6_iaids_match(profile, &bound["ia_states"]) {
            return Ok(json!({"phase": "request_iaid_mismatch", "transaction_id": final_reply.transaction_id, "server_id": bound["server_id"],
                "client_id": client_id, "message": "DHCPv6 Reply IAID does not match the requested IAID"}));
        }
        if truthy(g(&bound, "lease_timer_error")) {
            return Ok(json!({"phase": "request_invalid_lease_timers", "transaction_id": final_reply.transaction_id, "server_id": bound["server_id"],
                "client_id": client_id, "message": bound["lease_timer_error"]}));
        }
        Ok(bound)
    }

    pub fn exchange_dhcpv6(&self, profile: &Value, peer: &str, session_id: u64, src: &str, dst: &str, dhcp: &str, xid: &str) -> Result<Option<Value>> {
        let payload = pppoe_session(session_id, &(u16hex(PPP_IPV6) + &ipv6_udp(src, dst, 546, 547, dhcp)?));
        let timeout = clamp_int(g(profile, "dhcpv6_timeout_ms"), 500.0, 30000.0, num(profile, "timeout_ms").max(5000.0));
        let exchange_timeout = timeout.min(MAX_L2_RECV_TIMEOUT_MS);
        let deadline = crate::now() + timeout;
        let limit = (num(profile, "max_frames") * 4.0).max(8.0).min(32.0);
        let req = self.session_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer, "payload": payload, "timeout_ms": js::num(exchange_timeout),
                "max_bytes": 1500, "max_frames": js::num(limit), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
            peer,
            session_id,
            profile,
        )?;
        let first = self.l2_many("net.l2.exchangeMany", &req)?;
        if let Some(found) = find_dhcpv6_reply_frame(&first, session_id, xid) {
            return Ok(Some(found));
        }
        while crate::now() < deadline {
            let remaining = timeout.min(deadline - crate::now()).max(1.0);
            let frames = self.recv_ppp_session_frames(profile, remaining, limit, peer, session_id)?;
            if frames.is_empty() {
                break;
            }
            if let Some(found) = find_dhcpv6_reply_frame(&frames, session_id, xid) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    // -------------------------------------------------------- control

    /// Our request is acked; the peer's side opens once we ack its own
    /// Configure-Request. Each receive opens a new socket, so a request that
    /// came between two receives is lost until the peer resends it, by
    /// default 3 s later (RFC 1661). Until then the peer drops our packets of
    /// this protocol, so wait for the resend rather than report the link
    /// usable early.
    fn ack_peer_configure_requests(&self, profile: &Value, peer: &str, session_id: u64, protocol: u64, acked: &mut Value) -> Result<Value> {
        if !acked.is_object() {
            *acked = json!({});
        }
        let name = ppp_control_protocol_name(protocol);
        let (mut acks, mut target_acked, mut skipped, mut received) = (0u64, 0u64, 0u64, 0usize);
        let started = crate::now();
        let drain_timeout = clamp_int(g(profile, "peer_ack_timeout_ms"), 10.0, 250.0, num(profile, "control_ack_timeout_ms"));
        let wait = if flag(acked, &name) { 0.0 } else { num(profile, "peer_configure_wait_ms") };
        let deadline = started + drain_timeout.max(wait);
        let timeout_ms = num(profile, "timeout_ms");
        let max_frames = num(profile, "max_frames");
        // Bounds the loop when receives return at once, as LCP echoes make them do.
        let max_polls = 1.0 + (wait / timeout_ms).ceil() + max_frames;
        let mut timeout = drain_timeout;
        let mut poll = 0.0;
        while poll < max_polls {
            poll += 1.0;
            let mut frames = self.recv_ppp_session_frames(profile, timeout, max_frames.min(6.0), peer, session_id)?;
            received += frames.len();
            let limit = (max_frames * 2.0).min(16.0) as usize;
            let mut i = 0;
            while i < frames.len() && i < limit {
                let mut event = self.service_ppp_control_frame(profile, peer, session_id, &frames[i], &json!({}))?;
                append_control_event_frames(&mut frames, &mut event);
                i += 1;
                if s(&event, "event") == "configure_ack_sent" {
                    acks += 1;
                    acked[s(&event, "protocol").as_str()] = json!(true);
                    if s(&event, "protocol") == name {
                        target_acked += 1;
                    }
                    continue;
                }
                if s(&event, "protocol") != name {
                    skipped += 1;
                    continue;
                }
                if num(&event, "code") != 1.0 {
                    return Ok(json!({"phase": "complete", "acked": acks, "target_acked": target_acked, "code": event["code"], "identifier": event["identifier"],
                        "skipped": skipped, "waited_ms": js::num(crate::now() - started)}));
                }
            }
            if flag(acked, &name) {
                break;
            }
            let remaining = deadline - crate::now();
            if remaining <= 0.0 {
                break;
            }
            timeout = remaining.min(timeout_ms);
        }
        let waited = js::num(crate::now() - started);
        if received == 0 {
            return Ok(json!({"phase": "timeout", "acked": acks, "target_acked": target_acked, "skipped": skipped, "waited_ms": waited}));
        }
        Ok(json!({"phase": if acks > 0 { "acked" } else { "drained" }, "acked": acks, "target_acked": target_acked, "skipped": skipped, "waited_ms": waited}))
    }

    pub fn service_session_control_timer(&self, payload: &Value) -> Result<()> {
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        let mut profile = self.load_profile(payload)?;
        let session_id = clamp_int(g(payload, "session_id"), 1.0, 65535.0, 0.0) as u64;
        let peer = mac_text(js::first(&[g(payload, "ac_mac"), g(payload, "peer_mac"), &json!("")]))?;
        if session_id == 0 || peer.is_empty() {
            bail!("session_control timer requires session_id and ac_mac");
        }
        let deadline = timestamp_ms(g(payload, "deadline_ms"));
        let remaining = if deadline > 0.0 { (deadline - crate::now()).max(0.0) } else { clamp_int(g(payload, "remaining_ms"), 0.0, 10000.0, 0.0) };
        if remaining <= 0.0 {
            return Ok(());
        }
        let mut slice = clamp_int(g(payload, "slice_ms"), 10.0, 1500.0, remaining.min(num(&profile, "timeout_ms").max(50.0)));
        if slice > remaining {
            slice = remaining;
        }
        let started = crate::now();
        let outcome = self.resolve_l2_identity(&mut profile).and_then(|_| self.service_ppp_control_window(&profile, &peer, session_id, slice, &Value::Null));
        let mut result = match outcome {
            Ok(result) => result,
            Err(err) => {
                // A timeout timer is consumed before its handler runs. Preserve
                // the bounded control window across a temporary link/socket failure.
                let mut result = new_control_window_result(slice);
                result["phase"] = json!("io_error");
                result["io_errors"] = json!(1);
                push(&mut result, "events", json!({"event": "io_error", "message": error_message(&err)}));
                result
            }
        };
        if !self.session_timer_is_current(payload)? {
            return Ok(());
        }
        let elapsed = slice.max(crate::now() - started);
        let next_remaining = (remaining - elapsed).max(0.0);
        result["remaining_ms"] = js::num(next_remaining);
        result["session_id"] = json!(session_id);
        result["ac_mac"] = json!(peer);
        result["updated_at"] = json!(crate::iso_now());
        let current = self.res_data("sessions", "control")?;
        let merged = merge_control_window_result(current.as_ref(), &result);
        self.res_set("sessions", "control", &merged)?;
        if let Some(last) = self.res_data("sessions", "last")? {
            if clamp_int(g(&last, "session_id"), 1.0, 65535.0, 0.0) as u64 == session_id {
                self.res_set("sessions", "last", &merge(&last, &json!({"post_session_control": merged, "post_session_control_armed": next_remaining > 0.0})))?;
            }
        }
        if next_remaining > 0.0 {
            let next = merge(payload, &json!({"remaining_ms": js::num(next_remaining)}));
            self.timer_timeout("session_control", next_remaining.min(50.0), &next)
        } else {
            self.timer_clear("session_control")
        }
    }

    pub fn service_ppp_control_window(&self, profile: &Value, peer: &str, session_id: u64, duration_ms: f64, expected: &Value) -> Result<Value> {
        let duration = clamp_int(&js::num(duration_ms), 0.0, 10000.0, 0.0);
        let empty = json!({});
        let expected = if truthy(expected) { expected } else { &empty };
        let deadline = crate::now() + duration;
        let max_polls = clamp_int(g(profile, "control_max_polls"), 1.0, 128.0, 4f64.max(num(profile, "max_frames") * 8.0));
        let mut out = new_control_window_result(duration);
        if duration <= 0.0 {
            return Ok(out);
        }
        let mut i = 0.0;
        while i < max_polls && crate::now() < deadline {
            let timeout = num(profile, "timeout_ms").min((deadline - crate::now()).max(1.0));
            incr(&mut out, "polls");
            let frames = self.recv_ppp_session_frames(profile, timeout, 8f64.min((max_polls - i).max(1.0)), peer, session_id)?;
            i += 1.0;
            if frames.is_empty() {
                incr(&mut out, "timeouts");
                continue;
            }
            if self.consume_ppp_control_frames(profile, peer, session_id, frames, expected, &mut out)? {
                return Ok(out);
            }
        }
        finish_control_window_result(&mut out, expected);
        Ok(out)
    }

    /// Answers each frame; true once a terminate or the expected echo reply came.
    pub fn consume_ppp_control_frames(&self, profile: &Value, peer: &str, session_id: u64, mut frames: Vec<Value>, expected: &Value, out: &mut Value) -> Result<bool> {
        let mut j = 0;
        while j < frames.len() && j < 64 {
            incr(out, "frames");
            let mut event = self.service_ppp_control_frame(profile, peer, session_id, &frames[j], expected)?;
            append_control_event_frames(&mut frames, &mut event);
            j += 1;
            if js::array(&out["events"]).len() < 16 {
                push(out, "events", event.clone());
            }
            let name = s(&event, "event");
            if name == "configure_ack_sent" {
                incr(out, "configure_acks_sent");
                out["acked_protocols"][s(&event, "protocol").as_str()] = json!(true);
            }
            if name == "echo_reply_sent" {
                incr(out, "echo_replies_sent");
            }
            if name == "terminate_ack_sent" {
                incr(out, "terminate_acks_sent");
                out["phase"] = json!("terminated");
                return Ok(true);
            }
            if name == "lcp_echo_reply" {
                out["lcp_echo_reply"] = json!(true);
                out["lcp_echo_code"] = event["code"].clone();
                out["phase"] = json!("echo_reply");
                return Ok(true);
            }
            if name == "skip" || name == "skip_session" || name == "skip_peer" {
                incr(out, "skipped");
            }
            if name == "parse_error" {
                incr(out, "parse_errors");
            }
        }
        Ok(false)
    }

    pub fn recv_ppp_session_frames(&self, profile: &Value, timeout_ms: f64, max_frames: f64, peer: &str, session_id: u64) -> Result<Vec<Value>> {
        let timeout = clamp_int(&js::num(timeout_ms), 1.0, MAX_L2_RECV_TIMEOUT_MS, num(profile, "timeout_ms"));
        let frames = clamp_int(&js::num(max_frames), 1.0, 64.0, 1.0);
        let req = self.session_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "timeout_ms": js::num(timeout), "max_bytes": 1500,
                "max_frames": js::num(frames), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
            peer,
            session_id,
            profile,
        )?;
        self.l2_many("net.l2.recvMany", &req)
    }

    fn service_ppp_control_frame(&self, profile: &Value, peer: &str, session_id: u64, frame: &Value, expected: &Value) -> Result<Value> {
        if !peer.is_empty() && mac_text(js::or(g(frame, "src_mac"), &json!(""))).unwrap_or_default() != peer {
            return Ok(json!({"event": "skip_peer", "src_mac": js::or(g(frame, "src_mac"), &json!(""))}));
        }
        let parsed = match parse_session_frame(frame) {
            Ok(parsed) => parsed,
            Err(err) => return Ok(json!({"event": "parse_error", "message": error_message(&err)})),
        };
        if parsed.session_id != session_id {
            return Ok(json!({"event": "skip_session", "session_id": parsed.session_id}));
        }
        if parsed.protocol != PPP_LCP && parsed.protocol != PPP_IPCP && parsed.protocol != PPP_IPV6CP {
            return Ok(json!({"event": "skip", "protocol": format!("0x{}", u16hex(parsed.protocol)), "length": parsed.payload.len() / 2}));
        }
        let cp = parse_cp(&parsed.payload);
        if cp.code == 1 {
            let next = self.exchange_ppp_control_frames(profile, peer, session_id, parsed.protocol, &cp_packet(2, cp.identifier, &cp.data_hex),
                num(profile, "control_ack_timeout_ms"), num(profile, "max_frames"))?;
            let mut event = json!({"event": "configure_ack_sent", "protocol": ppp_control_protocol_name(parsed.protocol), "code": cp.code, "identifier": cp.identifier});
            annotate_peer_network_control(parsed.protocol, &cp, &mut event, None)?;
            if next.len() == 1 {
                event["next_frame"] = next[0].clone();
            }
            if next.len() > 1 {
                event["next_frames"] = Value::Array(next);
            }
            return Ok(event);
        }
        if parsed.protocol == PPP_LCP && cp.code == 9 {
            self.send_ppp_control(profile, peer, session_id, PPP_LCP, &cp_packet(10, cp.identifier, &cp.data_hex))?;
            return Ok(json!({"event": "echo_reply_sent", "protocol": "lcp", "code": cp.code, "identifier": cp.identifier}));
        }
        if parsed.protocol == PPP_LCP && cp.code == 5 {
            self.send_ppp_control(profile, peer, session_id, PPP_LCP, &cp_packet(6, cp.identifier, ""))?;
            return Ok(json!({"event": "terminate_ack_sent", "protocol": "lcp", "code": cp.code, "identifier": cp.identifier}));
        }
        if parsed.protocol == PPP_LCP && cp.code == 10 && js::strict_eq(g(expected, "lcp_echo_identifier"), &json!(cp.identifier)) {
            return Ok(json!({"event": "lcp_echo_reply", "protocol": "lcp", "code": cp.code, "identifier": cp.identifier}));
        }
        Ok(json!({"event": cp_code_name(cp.code), "protocol": ppp_control_protocol_name(parsed.protocol), "code": cp.code, "identifier": cp.identifier}))
    }

    fn send_ppp_control(&self, profile: &Value, peer: &str, session_id: u64, protocol: u64, cp_payload: &str) -> Result<()> {
        let mut req = json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer,
            "payload": pppoe_session(session_id, &(u16hex(protocol) + cp_payload))});
        self.apply_identity(profile, &mut req)?;
        self.host.call("net.l2.send", json!([req]))?;
        Ok(())
    }

    fn exchange_ppp_control(&self, profile: &Value, peer: &str, session_id: u64, protocol: u64, cp_payload: &str, timeout_ms: Option<f64>) -> Result<Option<Value>> {
        let timeout = clamp_int(&timeout_ms.map(js::num).unwrap_or(Value::Null), 1.0, MAX_L2_RECV_TIMEOUT_MS, num(profile, "timeout_ms"));
        let req = self.session_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer, "payload": pppoe_session(session_id, &(u16hex(protocol) + cp_payload)),
                "timeout_ms": js::num(timeout), "max_bytes": 1500}),
            peer,
            session_id,
            profile,
        )?;
        self.l2_one("net.l2.exchange", &req)
    }

    pub fn exchange_ppp_control_frames(&self, profile: &Value, peer: &str, session_id: u64, protocol: u64, cp_payload: &str, timeout_ms: f64, max_frames: f64) -> Result<Vec<Value>> {
        let timeout = clamp_int(&js::num(timeout_ms), 1.0, 5000.0, num(profile, "timeout_ms"));
        let limit = clamp_int(&js::num(max_frames), 1.0, 64.0, num(profile, "max_frames"));
        let deadline = crate::now() + timeout;
        let mut out = Vec::new();
        let req = self.session_filter(
            json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer, "payload": pppoe_session(session_id, &(u16hex(protocol) + cp_payload)),
                "timeout_ms": js::num(timeout), "max_bytes": 1500, "max_frames": js::num(64f64.min((limit * 4.0).max(limit))), "idle_timeout_ms": profile["control_idle_timeout_ms"]}),
            peer,
            session_id,
            profile,
        )?;
        let frames = self.l2_many("net.l2.exchangeMany", &req)?;
        append_matching_session_frames(&mut out, &frames, peer, session_id, limit as usize);
        if !out.is_empty() {
            return Ok(out);
        }
        while crate::now() < deadline && out.len() < limit as usize {
            let remaining = num(profile, "timeout_ms").min(deadline - crate::now()).max(1.0);
            let want = 64f64.min((((limit as usize - out.len()) * 4) as f64).max(4.0));
            let frames = self.recv_ppp_session_frames(profile, remaining, want, peer, session_id)?;
            if frames.is_empty() {
                break;
            }
            append_matching_session_frames(&mut out, &frames, peer, session_id, limit as usize);
        }
        Ok(out)
    }

    /// (protocol, packet) of the answer to our request, or None on timeout.
    fn complete_cp_negotiation(&self, profile: &Value, peer: &str, session_id: u64, protocol: u64, identifier: u64, first: Option<Value>, acked: &mut Value) -> Result<Option<(u64, Cp)>> {
        let mut frame = first;
        for _ in 0..num(profile, "max_frames") as u64 {
            let Some(current) = frame else {
                return Ok(None);
            };
            let parsed = parse_session_frame(&current)?;
            if parsed.protocol != protocol {
                return Ok(Some((parsed.protocol, Cp::default())));
            }
            let cp = parse_cp(&parsed.payload);
            if cp.code == 1 {
                if acked.is_object() {
                    acked[ppp_control_protocol_name(protocol).as_str()] = json!(true);
                }
                let req = self.session_filter(
                    json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "dst_mac": peer,
                        "payload": pppoe_session(session_id, &(u16hex(protocol) + &cp_packet(2, cp.identifier, &cp.data_hex))), "timeout_ms": profile["timeout_ms"], "max_bytes": 1500}),
                    peer,
                    session_id,
                    profile,
                )?;
                frame = self.l2_one("net.l2.exchange", &req)?;
                continue;
            }
            if cp.identifier == identifier || cp.code == 3 || cp.code == 4 {
                return Ok(Some((protocol, cp)));
            }
            let req = self.session_filter(
                json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_SESS, "timeout_ms": profile["timeout_ms"], "max_bytes": 1500}),
                peer,
                session_id,
                profile,
            )?;
            frame = self.l2_one("net.l2.recv", &req)?;
        }
        Ok(None)
    }

    pub fn send_padt(&self, profile: &Value, peer: &str, session_id: u64, receive_ms: f64) -> Result<Vec<Value>> {
        let mut req = json!({"interface": profile["interface"], "ethertype": ETH_P_PPP_DISC, "dst_mac": peer, "payload": pppoe_discovery(CODE_PADT, session_id, &[])});
        self.apply_identity(profile, &mut req)?;
        let receive = clamp_int(&js::num(receive_ms), 0.0, 2000.0, 0.0);
        if receive > 0.0 {
            req["recv_ethertype"] = json!(ETH_P_PPP_SESS);
            req["recv_src_mac"] = json!(peer);
            req["pppoe_code"] = json!(0);
            req["pppoe_session_id"] = json!(session_id);
            req["timeout_ms"] = js::num(receive);
            req["max_bytes"] = json!(1500);
            req["max_frames"] = profile["max_frames"].clone();
            req["idle_timeout_ms"] = profile["control_idle_timeout_ms"].clone();
            return self.l2_many("net.l2.exchangeMany", &req);
        }
        self.host.call("net.l2.send", json!([req]))?;
        Ok(Vec::new())
    }

    pub fn send_lcp_echo(&self, profile: &Value, peer: &str, session_id: u64) -> Result<Value> {
        let identifier = self.random_byte()?;
        let expected = json!({"lcp_echo_identifier": identifier});
        let started = crate::now();
        let timeout = num(profile, "timeout_ms");
        let frames = self.exchange_ppp_control_frames(profile, peer, session_id, PPP_LCP, &cp_packet(9, identifier, "00000000"), timeout, num(profile, "max_frames"))?;
        let mut serviced = new_control_window_result(timeout);
        self.consume_ppp_control_frames(profile, peer, session_id, frames, &expected, &mut serviced)?;
        if !flag(&serviced, "lcp_echo_reply") {
            let remaining = (timeout - (crate::now() - started)).max(0.0);
            if remaining > 0.0 {
                let window = self.service_ppp_control_window(profile, peer, session_id, remaining, &expected)?;
                serviced = merge_control_window_result(Some(&serviced), &window);
            } else {
                finish_control_window_result(&mut serviced, &expected);
            }
        }
        let phase = if flag(&serviced, "lcp_echo_reply") { "keepalive_ok" } else { "keepalive_timeout" };
        Ok(crate::base_result(profile, phase, json!({"session_id": session_id, "ac_mac": peer, "code": js::or(g(&serviced, "lcp_echo_code"), &json!(0)),
            "identifier": identifier, "control": serviced})))
    }

    pub fn confirm_lcp_echo(&self, profile: &Value, peer: &str, session_id: u64) -> Value {
        let mut confirm = merge(profile, &json!({"timeout_ms": profile["keepalive_confirm_timeout_ms"]}));
        let outcome = self.prepare_l2_identity(&mut confirm).and_then(|_| self.send_lcp_echo(&confirm, peer, session_id));
        match outcome {
            Ok(mut result) => {
                if s(&result, "phase") != "keepalive_ok" {
                    result["phase"] = json!("keepalive_confirm_timeout");
                }
                result
            }
            Err(err) => crate::base_result(profile, "keepalive_confirm_error", json!({"session_id": session_id, "ac_mac": peer, "message": error_message(&err)})),
        }
    }
}

fn find_discovery_frame(frames: &[Value], want_code: u64, host_uniq: &str, peer: &str, ac_name: &str) -> Result<Option<Value>> {
    let want_host_uniq = host_uniq.trim().to_lowercase();
    let want_peer = mac_str(peer)?;
    let want_ac = ac_name.trim();
    for frame in frames {
        if !want_peer.is_empty() && mac_text(js::or(g(frame, "src_mac"), &json!(""))).unwrap_or_default() != want_peer {
            continue;
        }
        let Ok(parsed) = parse_discovery_frame(frame) else {
            continue;
        };
        if parsed.code != want_code {
            continue;
        }
        let got = first_tag_hex(&parsed, TAG_HOST_UNIQ).to_lowercase();
        if !want_host_uniq.is_empty() && !got.is_empty() && got != want_host_uniq {
            continue;
        }
        if !want_ac.is_empty() && first_tag_text(&parsed, TAG_AC_NAME) != want_ac {
            continue;
        }
        return Ok(Some(frame.clone()));
    }
    Ok(None)
}

fn parse_lcp_authentication_option(option: &CpOption) -> Result<(String, u64)> {
    let bytes = hex_to_bytes(&option.value_hex);
    if bytes.len() < 2 {
        bail!("peer LCP authentication protocol option is malformed");
    }
    let protocol = u16_at(&bytes, 0);
    if protocol == PPP_PAP {
        if bytes.len() != 2 {
            bail!("peer PAP authentication protocol option is malformed");
        }
        return Ok(("pap".to_string(), protocol));
    }
    if protocol == PPP_CHAP {
        if bytes.len() != 3 {
            bail!("peer CHAP authentication protocol option is malformed");
        }
        if bytes[2] != CHAP_ALGORITHM_MD5 {
            bail!("peer requires unsupported CHAP algorithm {}", bytes[2]);
        }
        return Ok(("chap".to_string(), protocol));
    }
    bail!("peer requires unsupported authentication protocol 0x{}", u16hex(protocol))
}

fn authentication_method(profile: &Value, out: &mut Value, observed: &str) -> String {
    if flag(out, "auth_required") {
        return s(out, "peer_auth_method");
    }
    if s(profile, "auth") == "auto" && !observed.is_empty() {
        out["auth_required"] = json!(true);
        out["peer_auth_method"] = json!(observed);
        out["auth_method"] = json!(observed);
        return observed.to_string();
    }
    s(profile, "auth")
}

fn require_authentication_credentials(profile: &Value, method: &str) -> Result<()> {
    if s(profile, "username").is_empty() {
        bail!("{method} authentication requires username");
    }
    if method == "chap" && s(profile, "password").is_empty() {
        bail!("chap authentication requires password");
    }
    Ok(())
}

fn annotate_peer_network_control(protocol: u64, cp: &Cp, event: &mut Value, out: Option<&mut Value>) -> Result<()> {
    if cp.code != 1 {
        return Ok(());
    }
    let options = parse_cp_options(&cp.data_hex);
    if protocol == PPP_IPCP {
        let ip = first_cp_ipv4_option(&options, IPCP_OPTION_IP_ADDRESS);
        if ip.is_empty() {
            return Ok(());
        }
        event["address"] = json!(ip);
        if let Some(out) = out {
            out["peer_ipcp"] = json!({"address": ip});
        }
        return Ok(());
    }
    if protocol == PPP_IPV6CP {
        let iid = first_cp_hex_option(&options, IPV6CP_OPTION_INTERFACE_ID);
        if iid.is_empty() {
            return Ok(());
        }
        let link_local = link_local_from_iid(&iid)?;
        event["interface_id"] = json!(iid);
        event["link_local"] = json!(link_local);
        if let Some(out) = out {
            out["peer_ipv6cp"] = json!({"interface_id": iid, "link_local": link_local});
        }
    }
    Ok(())
}

fn usable_ipcp_dns_servers(enabled: &[bool; 2], primary: &str, secondary: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if enabled[0] && !primary.is_empty() && primary != "0.0.0.0" {
        out.push(json!(primary));
    }
    if enabled[1] && !secondary.is_empty() && secondary != "0.0.0.0" {
        out.push(json!(secondary));
    }
    unique_text_values(&out)
}

fn find_ipv6_router_advertisement(frames: &[Value], session_id: u64, iid: &str) -> Result<Option<Value>> {
    for frame in frames {
        let Ok(parsed) = parse_session_frame(frame) else {
            continue;
        };
        if parsed.session_id != session_id || parsed.protocol != PPP_IPV6 {
            continue;
        }
        let Some(packet) = parse_ipv6_icmp(&parsed.payload) else {
            continue;
        };
        if packet.ty != ICMPV6_ROUTER_ADVERT {
            continue;
        }
        return Ok(Some(parse_ipv6_router_advertisement(&packet, iid)?));
    }
    Ok(None)
}

fn parse_ipv6_router_advertisement(packet: &Icmp6, iid: &str) -> Result<Value> {
    let bytes = hex_to_bytes(&packet.body_hex);
    if bytes.len() < 12 {
        return Ok(json!({"phase": "invalid", "message": "router advertisement is truncated"}));
    }
    let lifetime = u16_at(&bytes, 2);
    let mut prefixes: Vec<Value> = Vec::new();
    let mut dns: Vec<Value> = Vec::new();
    let mut pos = 12;
    while pos + 2 <= bytes.len() {
        let ty = bytes[pos];
        let length = bytes[pos + 1] as usize * 8;
        if length < 8 || pos + length > bytes.len() {
            break;
        }
        if ty == ND_OPT_PREFIX_INFORMATION && length >= 32 {
            let prefix_length = bytes[pos + 2];
            let flags = bytes[pos + 3];
            prefixes.push(json!({"prefix": format!("{}/{prefix_length}", ipv6_bytes_to_text(&bytes[pos + 16..pos + 32])), "prefix_length": prefix_length,
                "on_link": flags & 0x80 != 0, "autonomous": flags & 0x40 != 0, "valid_lifetime": u32_at(&bytes, pos + 4),
                "preferred_lifetime": u32_at(&bytes, pos + 8), "prefix_hex": bytes_to_hex(&bytes[pos + 16..pos + 32])}));
        } else if ty == ND_OPT_RDNSS && length >= 24 {
            let mut at = pos + 8;
            while at + 16 <= pos + length {
                dns.push(json!(ipv6_bytes_to_text(&bytes[at..at + 16])));
                at += 16;
            }
        }
        pos += length;
    }
    let selected = prefixes.iter().find(|p| flag(p, "autonomous") && num(p, "prefix_length") == 64.0).cloned();
    let address = match &selected {
        Some(p) => slaac_address(&s(p, "prefix_hex"), num(p, "prefix_length") as u64, iid)?,
        None => String::new(),
    };
    Ok(json!({"phase": if selected.is_some() { "router_advertisement" } else { "router_advertisement_no_slaac" }, "router": packet.src, "router_lifetime": lifetime,
        "managed": bytes[1] & 0x80 != 0, "other_config": bytes[1] & 0x40 != 0, "prefix": selected.as_ref().map(|p| p["prefix"].clone()).unwrap_or(json!("")),
        "prefixes": prefixes, "address": address, "dns_servers": unique_text_values(&dns)}))
}

pub fn annotate_dhcpv6_partial_binding(profile: &Value, lease: &mut Value) {
    let mut missing = Vec::new();
    if flag(profile, "request_ipv6_address") && js::array(g(lease, "addresses")).is_empty() {
        missing.push("ia_na");
    }
    if flag(profile, "request_pd") && js::array(g(lease, "prefixes")).is_empty() {
        missing.push("ia_pd");
    }
    let partial = !missing.is_empty() && dhcpv6_lease_has_binding(lease);
    lease["partial_binding"] = json!(partial);
    lease["partial_ias"] = json!(missing);
    lease["partial_reason"] = json!("");
    if partial {
        let reasons: Vec<String> = missing
            .iter()
            .map(|ia| match dhcpv6_ia_status_error(lease, ia) {
                Some(status) => {
                    let message = js::string(&status["message"]);
                    format!("{ia}: {}", if message.is_empty() { format!("status {}", js::string(&status["code"])) } else { message })
                }
                None => format!("{ia} unavailable"),
            })
            .collect();
        lease["partial_reason"] = json!(reasons.join("; "));
    }
}

pub fn dhcpv6_iaids_match(profile: &Value, states: &Value) -> bool {
    js::array(states).iter().all(|state| js::number(g(state, "iaid")) == num(profile, "dhcpv6_iaid"))
}

/// Ok(reply) or Err(error result) for a frame found by its transaction id.
pub fn parse_dhcpv6_reply_frame(frame: &Value, xid: &str) -> Result<std::result::Result<Dhcp6, Value>> {
    let parsed = parse_session_frame(frame)?;
    if parsed.protocol != PPP_IPV6 {
        return Ok(Err(json!({"phase": "unexpected_protocol", "protocol": format!("0x{}", u16hex(parsed.protocol)), "transaction_id": xid})));
    }
    let Some(packet) = parse_ipv6_udp(&parsed.payload).filter(|p| p.dst_port == 546) else {
        return Ok(Err(json!({"phase": "unexpected_packet", "transaction_id": xid})));
    };
    let reply = parse_dhcpv6(&packet.payload_hex);
    if reply.transaction_id != xid {
        return Ok(Err(json!({"phase": "transaction_mismatch", "transaction_id": xid, "reply_transaction_id": reply.transaction_id})));
    }
    Ok(Ok(reply))
}

fn find_dhcpv6_reply_frame(frames: &[Value], session_id: u64, xid: &str) -> Option<Value> {
    for frame in frames {
        let Ok(parsed) = parse_session_frame(frame) else {
            continue;
        };
        if parsed.session_id != session_id || parsed.protocol != PPP_IPV6 {
            continue;
        }
        let Some(packet) = parse_ipv6_udp(&parsed.payload) else {
            continue;
        };
        if packet.src_port != 547 || packet.dst_port != 546 {
            continue;
        }
        if parse_dhcpv6(&packet.payload_hex).transaction_id == xid {
            return Some(frame.clone());
        }
    }
    None
}

fn append_matching_session_frames(out: &mut Vec<Value>, frames: &[Value], peer: &str, session_id: u64, limit: usize) {
    let want_peer = mac_str(peer).unwrap_or_default();
    for frame in frames {
        if out.len() >= limit {
            break;
        }
        if !want_peer.is_empty() && mac_text(js::or(g(frame, "src_mac"), &json!(""))).unwrap_or_default() != want_peer {
            continue;
        }
        match parse_session_frame(frame) {
            Ok(parsed) if parsed.session_id == session_id => out.push(frame.clone()),
            _ => continue,
        }
    }
}

fn append_control_event_frames(frames: &mut Vec<Value>, event: &mut Value) {
    let Some(map) = event.as_object_mut() else {
        return;
    };
    if let Some(next) = map.remove("next_frame") {
        if truthy(&next) {
            frames.push(next);
        }
    }
    if let Some(Value::Array(next)) = map.remove("next_frames") {
        frames.extend(next);
    }
}

