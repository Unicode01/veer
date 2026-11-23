//! Port of test-control-node.js. The fixture plays what the JavaScript test
//! host did: the access concentrator behind the raw-L2 calls, WAN Core's
//! wan.adapter service, the links, the eBPF maps, secrets and crypto.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{js, json, MsgKind, Outcome, Value};

use crate::codec::*;
use crate::{decode_tunnel_config_hex, PppoeClient, ETH_P_PPP_DISC as DISC, ETH_P_PPP_SESS as SESS};

const SESSION_ID: u64 = 0x0010;
const PEER_LCP_ID: u64 = 0x31;
const PEER_IPCP_ID: u64 = 0x61;
const PEER_IPV6CP_ID: u64 = 0x62;
const LOCAL_MAC: &str = "02:00:00:00:00:01";
const AC_MAC: &str = "02:00:00:00:00:02";
const LOCAL_BOUNDARY_MAC: &str = "02:00:00:00:10:01";
const PIPELINE: &str = "veerpipe0";
const PIPELINE_BOUNDARY_MAC: &str = "02:00:00:00:10:02";

fn zero() -> String {
    "00".repeat(52)
}

fn now() -> f64 {
    crate::now()
}

fn at(offset: f64) -> Value {
    js::num(now() + offset)
}

// ------------------------------------------------------------ MD5

/// MD5 for CHAP: the host's crypto.md5 and the concentrator's check.
fn md5(input: &[u8]) -> [u8; 16] {
    const SHIFT: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4294967296.0) as u32).collect();
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&((input.len() as u64).wrapping_mul(8)).to_le_bytes());
    for chunk in message.chunks(64) {
        let m: Vec<u32> = (0..16).map(|i| u32::from_le_bytes([chunk[4 * i], chunk[4 * i + 1], chunk[4 * i + 2], chunk[4 * i + 3]])).collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(k[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(SHIFT[(i / 16) * 4 + i % 4]));
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d]) {
            *slot = slot.wrapping_add(value);
        }
    }
    let mut out = [0u8; 16];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[test]
fn md5_matches_known_digests() {
    assert_eq!(bytes_to_hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(bytes_to_hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
}

// ------------------------------------------------------------ fixture

#[derive(Clone, Default)]
struct Opts {
    auth: &'static str,
    echo_replies: bool,
    echo_reply_sequence: Vec<bool>,
    ipcp_dns: bool,
    ipcp_reject_dns: bool,
    omit_iana: bool,
    dhcpv6_no_address: bool,
    dhcpv6_timeout_types: Vec<u64>,
    dhcpv6_t1: Option<u64>,
    dhcpv6_t2: Option<u64>,
    no_peer_network_requests: bool,
    lost_peer_ipcp_request: bool,
    terminate_on_padt: bool,
    pads_timeout: bool,
    // Fails PPP session frame exchanges (after PADS) with this error.
    session_exchange_error: &'static str,
    resource_set_error: &'static str,
    plugin_resource_error: &'static str,
    link_get_error: String,
    per_cpu_values: Vec<String>,
    kfuncs: bool,
    direct: bool,
}

fn auth(auth: &'static str) -> Opts {
    Opts { auth, ..Opts::default() }
}

fn link_info(name: &str) -> Value {
    match name {
        "eth0" => json!({"name": name, "ifindex": 7, "kind": "device", "mtu": 1500, "mac": LOCAL_MAC, "up": true, "promiscuous": false}),
        "veerlocal0" => json!({"name": name, "ifindex": 101, "kind": "veth", "mtu": 1492, "mac": LOCAL_BOUNDARY_MAC, "up": true, "promiscuous": false,
            "peer_name": PIPELINE, "peer_ifindex": 102}),
        PIPELINE => json!({"name": name, "ifindex": 102, "kind": "veth", "mtu": 1492, "mac": PIPELINE_BOUNDARY_MAC, "up": true, "promiscuous": false,
            "peer_name": "veerlocal0", "peer_ifindex": 101}),
        _ => json!({"name": name, "ifindex": 200, "kind": "device", "mtu": 1500, "mac": "02:00:00:00:20:00", "up": true, "promiscuous": false}),
    }
}

fn discovery_code(payload: &str) -> u64 {
    u64::from_str_radix(payload.get(2..4).unwrap_or(""), 16).unwrap_or(0)
}

fn discovery_frame(code: u64, session_id: u64, tags: &[String]) -> Value {
    json!({"interface": "eth0", "ifindex": 7, "ethertype": DISC, "src_mac": AC_MAC, "dst_mac": LOCAL_MAC,
        "payload_hex": pppoe_discovery(code, session_id, tags)})
}

fn session_frame(protocol: u64, payload_hex: &str) -> Value {
    json!({"interface": "eth0", "ifindex": 7, "ethertype": SESS, "src_mac": AC_MAC, "dst_mac": LOCAL_MAC,
        "payload_hex": pppoe_session(SESSION_ID, &format!("{}{payload_hex}", u16hex(protocol)))})
}

fn router_advertisement_frame() -> Value {
    let prefix = "20010db8cafe00010000000000000000";
    let prefix_info = format!("030440c0{}{}{}{prefix}", u32hex(7200), u32hex(3600), u32hex(0));
    let rdnss = format!("19030000{}20014860486000000000000000008888", u32hex(600));
    let body = format!("40000708{}{}{prefix_info}{rdnss}", u32hex(0), u32hex(0));
    session_frame(PPP_IPV6, &ipv6_icmp("fe80::2", "fe80::11:2233:4455:6677", 134, 0, &body, 255).unwrap())
}

fn has_option(message: &Dhcp6, code: u64) -> bool {
    message.options.iter().any(|option| option.code == code)
}

#[derive(Default)]
struct World {
    o: Opts,
    links: BTreeMap<String, Value>,
    plugin_records: BTreeMap<String, Value>,
    plugin_action_calls: Vec<Value>,
    secrets: BTreeMap<String, Value>,
    map_puts: Vec<Value>,
    map_values: BTreeMap<String, String>,
    l2_sends: Vec<Value>,
    l2_exchanges: Vec<Value>,
    l2_recvs: Vec<Value>,
    dhcpv6: Vec<Dhcp6>,
    net_calls: Vec<String>,
    random_byte: u64,
    last_echo_identifier: Option<u64>,
    ipcp_nak_sent: bool,
    peer_ncp_frames: Vec<Value>,
    peer_ipcp_resend: Option<(Value, u32)>,
    client_ipcp_acked: bool,
    recvs_at_client_ipcp_ack: usize,
    pending_terminate: Option<u64>,
    recv_error: String,
    missing_link: String,
    set_gso_error: String,
}

impl World {
    fn link(&self, name: &str) -> Value {
        self.links.get(name).cloned().unwrap_or_else(|| link_info(name))
    }

    fn link_mut(&mut self, name: &str) -> &mut Value {
        let link = self.link(name);
        self.links.entry(name.to_string()).or_insert(link)
    }

    fn set_gso(&mut self, name: &str, limits: &Value) -> Result<Value, String> {
        if !self.set_gso_error.is_empty() {
            return Err(self.set_gso_error.clone());
        }
        self.net_calls.push(format!("setGSO:{name}:{}:{}", js::string(&limits["max_size"]), js::string(&limits["max_segs"])));
        Ok(json!({"name": name, "gso_max_size": limits["max_size"], "gso_max_segs": limits["max_segs"]}))
    }

    fn set_offloads(&mut self, name: &str, features: &Value) {
        let mut parts: Vec<String> =
            features.as_object().map(|map| map.iter().map(|(key, value)| format!("{key}={}", js::string(value))).collect()).unwrap_or_default();
        parts.sort();
        self.net_calls.push(format!("setOffloads:{name}:{}", parts.join(",")));
    }

    fn plugin_record_data(&self, key: &str) -> Value {
        self.plugin_records.get(key).map(|record| record["data"].clone()).unwrap_or(Value::Null)
    }

    /// WAN Core's prepare_handoff and apply_session.
    fn plugin_action(&mut self, plugin: &str, action: &str, payload: &Value) -> Result<Value, String> {
        self.plugin_action_calls.push(json!({"plugin": plugin, "action": action, "payload": payload}));
        if plugin == "wan_core" && action == "apply_session" {
            let key = js::text(&payload["key"]);
            let status_key = format!("wan_core/status/{key}");
            let mut status = self.plugin_record_data(&status_key);
            let session = self.plugin_record_data(&format!("wan_core/sessions/{key}"));
            let request = &payload["interface_preparation"];
            if js::truthy(&request["local_gso"]) {
                self.set_gso(&js::text(&status["local_interface"]), &request["local_gso"])?;
            }
            if js::truthy(&request["local_offloads"]) {
                self.set_offloads(&js::text(&status["local_interface"]), &request["local_offloads"]);
            }
            if js::truthy(&request["pipeline_offloads"]) && js::truthy(&status["pipeline_interface"]) {
                self.set_offloads(&js::text(&status["pipeline_interface"]), &request["pipeline_offloads"]);
            }
            status["interface_preparation"] = json!({"applied": true});
            status["usable"] = session["usable"].clone();
            if let Some(record) = self.plugin_records.get_mut(&status_key) {
                record["data"] = status.clone();
            }
            return Ok(status);
        }
        if plugin != "wan_core" || action != "prepare_handoff" {
            return Err(format!("unexpected plugin action {plugin}/{action}"));
        }
        let key = js::string(js::first(&[&payload["wan_id"], &payload["profile_key"], &payload["key"], &json!("default")]));
        let local = js::string(js::first(&[&payload["local_interface"], &json!("veerlocal0")]));
        let pipeline = js::string(js::first(&[&payload["pipeline_interface"], &json!(PIPELINE)]));
        self.links.insert(local.clone(), link_info(&local));
        self.links.insert(pipeline.clone(), link_info(&pipeline));
        let preparation = &payload["interface_preparation"];
        let mut status = json!({
            "phase": "prepared", "wan_id": key, "usable": false,
            "local_interface": local, "local_ifindex": link_info(&local)["ifindex"],
            "pipeline_interface": pipeline, "pipeline_ifindex": link_info(&pipeline)["ifindex"],
            "handoff_mode": "segmented_veth", "segmentation_ready": true,
            "interface_preparation": if js::truthy(preparation) {
                json!({"applied": true, "local_gso": preparation["local_gso"], "local_offloads": preparation["local_offloads"],
                    "pipeline_offloads": preparation["pipeline_offloads"], "warnings": []})
            } else {
                json!({"applied": false, "warnings": []})
            },
            "veer_core": {"mode": "segmented_veth", "parent_interface": local, "tunnel_interface": pipeline, "segmentation_ready": true},
        });
        if js::text(&payload["handoff_mode"]) == "direct_gro" {
            let mut helper = link_info(&local);
            helper["kind"] = json!("veerwan");
            helper["peer_ifindex"] = json!(0);
            self.links.insert(local.clone(), helper);
            self.links.remove(&pipeline);
            status["handoff_mode"] = json!("direct_gro");
            status["pipeline_interface"] = json!("");
            status["pipeline_ifindex"] = json!(0);
            status["segmentation_ready"] = json!(false);
            status["veer_core"] = json!({"mode": "single_local_boundary", "parent_interface": local});
        }
        self.plugin_records.insert(format!("wan_core/status/{key}"), json!({"data": status, "enabled": false}));
        Ok(status)
    }

    fn session_exchange_error(&self, req: &Value) -> Result<(), String> {
        if !self.o.session_exchange_error.is_empty() && js::text(&req["ethertype"]) == SESS {
            return Err(self.o.session_exchange_error.to_string());
        }
        Ok(())
    }

    fn send(&mut self, req: &Value) {
        self.l2_sends.push(req.clone());
        let ethertype = js::text(&req["ethertype"]);
        let payload = js::text(&req["payload"]);
        if ethertype == SESS && !payload.is_empty() {
            if let Ok(parsed) = parse_session_frame(&json!({"payload_hex": payload})) {
                if parsed.protocol == PPP_LCP {
                    let cp = parse_cp(&parsed.payload);
                    if cp.code == 9 {
                        self.last_echo_identifier = Some(cp.identifier);
                    }
                }
            }
        }
        if self.o.terminate_on_padt && ethertype == DISC && !payload.is_empty() && discovery_code(&payload) == CODE_PADT {
            self.pending_terminate = Some(0x7e);
        }
    }

    // Like pppd, the peer sends its own IPCP and IPv6CP requests once it has
    // its LCP request acked. lost_peer_ipcp_request drops the first IPCP one,
    // as when it arrives between two of the client's receives.
    fn queue_peer_network_requests(&mut self) {
        self.client_ipcp_acked = false;
        self.peer_ipcp_resend = None;
        if self.o.no_peer_network_requests {
            self.peer_ncp_frames.clear();
            return;
        }
        let ipcp = session_frame(PPP_IPCP, &cp_packet(1, PEER_IPCP_ID, &cp_option_ipv4(3, "198.51.100.1")));
        let ipv6cp = session_frame(PPP_IPV6CP, &cp_packet(1, PEER_IPV6CP_ID, &cp_option_hex(1, "0200000000000001")));
        self.peer_ncp_frames = vec![ipv6cp];
        if self.o.lost_peer_ipcp_request {
            self.peer_ipcp_resend = Some((ipcp, 2));
        } else {
            self.peer_ncp_frames.insert(0, ipcp);
        }
    }

    fn dhcpv6_frame(&self, message_type: u64, xid: &str) -> Value {
        let (preferred, valid) = (3600, 7200);
        let t1 = self.o.dhcpv6_t1.unwrap_or(1800);
        let t2 = self.o.dhcpv6_t2.unwrap_or(2880);
        let ia_address = format!("20010db8abcd00000000000000000010{}{}", u32hex(preferred), u32hex(valid));
        let ia_na_data = if self.o.dhcpv6_no_address {
            dhcpv6_option(13, &format!("{}{}", u16hex(2), string_hex("NOADDRS-AVAIL")))
        } else {
            dhcpv6_option(5, &ia_address)
        };
        let ia_na = format!("{}{}{}{ia_na_data}", u32hex(1), u32hex(t1), u32hex(t2));
        let ia_prefix = format!("{}{}3820010db8123400000000000000000000", u32hex(preferred), u32hex(valid));
        let ia_pd = format!("{}{}{}{}", u32hex(1), u32hex(t1), u32hex(t2), dhcpv6_option(26, &ia_prefix));
        let dns = "2001486048600000000000000000888824003200000000000000000000000001";
        let iana = if self.o.omit_iana { String::new() } else { dhcpv6_option(3, &ia_na) };
        let payload = format!(
            "{}{xid}{}{iana}{}{}",
            hb(message_type),
            dhcpv6_option(2, "00030001020000000002"),
            dhcpv6_option(25, &ia_pd),
            dhcpv6_option(23, dns)
        );
        session_frame(PPP_IPV6, &ipv6_udp("fe80::2", "fe80::1", 547, 546, &payload).unwrap())
    }

    /// The access concentrator's answer to one exchange.
    fn exchange(&mut self, req: &Value) -> Vec<Value> {
        let ethertype = js::text(&req["ethertype"]);
        let payload = js::text(&req["payload"]);
        if ethertype == DISC {
            let code = discovery_code(&payload);
            let discovery = parse_discovery_frame(&json!({"payload_hex": payload})).unwrap();
            let host_uniq = first_tag_hex(&discovery, TAG_HOST_UNIQ);
            if code == CODE_PADT && self.o.terminate_on_padt {
                return vec![session_frame(PPP_LCP, &cp_packet(5, 0x7e, &string_hex("Received PADT")))];
            }
            let tags = [tag_string(TAG_SERVICE_NAME, ""), tag_string(TAG_AC_NAME, "test-ac"), tag_hex(TAG_HOST_UNIQ, &host_uniq)];
            if code == CODE_PADI {
                return vec![discovery_frame(CODE_PADO, 0, &tags)];
            }
            if self.o.pads_timeout {
                return vec![];
            }
            if code == CODE_PADR {
                return vec![discovery_frame(CODE_PADS, SESSION_ID, &tags)];
            }
            return vec![];
        }
        if ethertype != SESS || payload.is_empty() {
            return vec![];
        }
        let parsed = parse_session_frame(&json!({"payload_hex": payload})).unwrap();
        let cp = if parsed.protocol == PPP_IPV6 { Cp::default() } else { parse_cp(&parsed.payload) };
        if parsed.protocol == PPP_LCP && cp.code == 9 {
            let mut reply = self.o.echo_replies;
            if !self.o.echo_reply_sequence.is_empty() {
                reply = self.o.echo_reply_sequence.remove(0);
            }
            return if reply { vec![session_frame(PPP_LCP, &cp_packet(10, cp.identifier, "00000000"))] } else { vec![] };
        }
        if parsed.protocol == PPP_LCP && cp.code == 1 {
            let auth_option = match self.o.auth {
                "pap" | "pap-reject" => cp_option_hex(3, &u16hex(PPP_PAP)),
                "chap" => cp_option_hex(3, &format!("{}05", u16hex(PPP_CHAP))),
                "chap-unsupported" => cp_option_hex(3, &format!("{}80", u16hex(PPP_CHAP))),
                _ => String::new(),
            };
            let peer_request = cp_packet(1, PEER_LCP_ID, &format!("{}{auth_option}", cp_option_u16(1, 1492)));
            let mut frames = vec![session_frame(PPP_LCP, &peer_request), session_frame(PPP_LCP, &cp_packet(2, cp.identifier, &cp.data_hex))];
            if self.o.auth == "chap" {
                frames.push(session_frame(PPP_CHAP, &cp_packet(1, 0x42, &format!("04aabbccdd{}", string_hex("test-ac")))));
            }
            return frames;
        }
        if parsed.protocol == PPP_LCP && cp.code == 2 && cp.identifier == PEER_LCP_ID {
            self.queue_peer_network_requests();
            return vec![];
        }
        if parsed.protocol == PPP_PAP && cp.code == 1 {
            assert!(cp.data_hex.contains(&string_hex("user")), "PAP Authenticate-Request should include username");
            if self.o.auth == "pap-reject" {
                return vec![session_frame(PPP_PAP, &cp_packet(3, cp.identifier, &string_hex("denied")))];
            }
            return vec![session_frame(PPP_PAP, &cp_packet(2, cp.identifier, &string_hex("ok")))];
        }
        if parsed.protocol == PPP_CHAP && cp.code == 2 {
            let bytes = hex_to_bytes(&cp.data_hex);
            assert_eq!(bytes[0], 16, "CHAP Response value-size should be 16");
            let mut input = vec![cp.identifier as u8];
            input.extend_from_slice(b"chap-pass");
            input.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
            assert_eq!(bytes_to_hex(&bytes[1..17]), bytes_to_hex(&md5(&input)), "CHAP response digest should match MD5(ID + password + challenge)");
            return vec![session_frame(PPP_CHAP, &cp_packet(3, cp.identifier, &string_hex("ok")))];
        }
        if parsed.protocol == PPP_IPCP && cp.code == 1 {
            let requested = parse_cp_options(&cp.data_hex);
            if self.o.ipcp_dns && !self.ipcp_nak_sent {
                self.ipcp_nak_sent = true;
                assert!(requested.iter().any(|item| item.ty == 129), "IPCP should request primary DNS");
                assert!(requested.iter().any(|item| item.ty == 131), "IPCP should request secondary DNS");
                let nak = format!("{}{}{}", cp_option_ipv4(3, "198.51.100.10"), cp_option_ipv4(129, "223.5.5.5"), cp_option_ipv4(131, "1.1.1.1"));
                return vec![session_frame(PPP_IPCP, &cp_packet(3, cp.identifier, &nak))];
            }
            if self.o.ipcp_reject_dns && !self.ipcp_nak_sent {
                self.ipcp_nak_sent = true;
                let rejected: String =
                    requested.iter().filter(|item| item.ty == 129 || item.ty == 131).map(|item| cp_option_hex(item.ty, &item.value_hex)).collect();
                return vec![session_frame(PPP_IPCP, &cp_packet(4, cp.identifier, &rejected))];
            }
            self.client_ipcp_acked = true;
            self.recvs_at_client_ipcp_ack = self.l2_recvs.len();
            return vec![session_frame(PPP_IPCP, &cp_packet(2, cp.identifier, &cp.data_hex))];
        }
        if parsed.protocol == PPP_IPV6CP && cp.code == 1 {
            return vec![session_frame(PPP_IPV6CP, &cp_packet(2, cp.identifier, &cp.data_hex))];
        }
        if parsed.protocol == PPP_IPV6 {
            if parse_ipv6_icmp(&parsed.payload).is_some_and(|icmp| icmp.ty == 133) {
                return vec![router_advertisement_frame()];
            }
            let packet = parse_ipv6_udp(&parsed.payload).expect("DHCPv6 test path should send IPv6/UDP");
            let dhcp = parse_dhcpv6(&packet.payload_hex);
            self.dhcpv6.push(dhcp.clone());
            assert!(!has_option(&dhcp, 20), "unsupported Reconfigure Accept must not be sent");
            if dhcp.message_type == 1 || (!self.o.omit_iana && !self.o.dhcpv6_no_address) {
                assert!(has_option(&dhcp, 3), "DHCPv6 should request IA_NA");
            } else if self.o.dhcpv6_no_address {
                assert!(!has_option(&dhcp, 3), "failed IA_NA must be omitted after Solicit");
            }
            assert!(has_option(&dhcp, 25), "DHCPv6 should request IA_PD");
            if self.o.dhcpv6_timeout_types.contains(&dhcp.message_type) {
                return vec![];
            }
            match dhcp.message_type {
                1 => return vec![self.dhcpv6_frame(2, &dhcp.transaction_id)],
                3 => return vec![self.dhcpv6_frame(7, &dhcp.transaction_id)],
                5 => {
                    assert!(has_option(&dhcp, 2), "Renew must include Server Identifier");
                    return vec![self.dhcpv6_frame(7, &dhcp.transaction_id)];
                }
                6 => {
                    assert!(!has_option(&dhcp, 2), "Rebind must omit Server Identifier");
                    return vec![self.dhcpv6_frame(7, &dhcp.transaction_id)];
                }
                _ => {}
            }
        }
        vec![]
    }

    /// What the concentrator sends on its own between exchanges.
    fn recv(&mut self, req: &Value) -> Vec<Value> {
        if js::text(&req["ethertype"]) != SESS {
            return vec![];
        }
        if let Some(id) = self.pending_terminate.take() {
            return vec![session_frame(PPP_LCP, &cp_packet(5, id, &string_hex("Received PADT")))];
        }
        if !self.peer_ncp_frames.is_empty() {
            return std::mem::take(&mut self.peer_ncp_frames);
        }
        // The peer resends a lost IPCP request on its restart timer, after
        // the client's own request was acked and a few receives came back empty.
        if self.client_ipcp_acked {
            if let Some((frame, polls)) = self.peer_ipcp_resend.take() {
                if polls > 0 {
                    self.peer_ipcp_resend = Some((frame, polls - 1));
                    return vec![];
                }
                return vec![frame];
            }
        }
        if self.o.echo_replies {
            if let Some(id) = self.last_echo_identifier.take() {
                return vec![session_frame(PPP_LCP, &cp_packet(10, id, "00000000"))];
            }
        }
        vec![]
    }
}

type HostFn = fn(&mut World, &[Value]) -> Result<Value, String>;

fn arg(args: &[Value], index: usize) -> Value {
    args.get(index).cloned().unwrap_or(Value::Null)
}

fn check_wan_adapter(request: &Value) -> Result<(), String> {
    if js::text(&request["service"]) != "wan.adapter" || js::text(&request["provider"]) != "wan_core" {
        return Err("unexpected service resolution".to_string());
    }
    Ok(())
}

fn first_or_null(frames: Vec<Value>) -> Value {
    frames.into_iter().next().unwrap_or(Value::Null)
}

const HOST: &[(&str, HostFn)] = &[
    ("net.link.get", |w, a| {
        if !w.o.link_get_error.is_empty() {
            return Err(w.o.link_get_error.clone());
        }
        let name = js::text(&arg(a, 0));
        if !w.missing_link.is_empty() && name == w.missing_link {
            return Err("link not found".to_string());
        }
        Ok(w.link(&name))
    }),
    ("net.link.setPromiscuous", |w, a| {
        let name = js::text(&arg(a, 0));
        let enabled = js::truthy(&arg(a, 1));
        let link = w.link_mut(&name);
        link["promiscuous"] = json!(enabled);
        let link = link.clone();
        w.net_calls.push(format!("setPromiscuous:{name}:{enabled}"));
        Ok(link)
    }),
    ("net.link.setMTU", |w, a| {
        w.net_calls.push(format!("setMTU:{}:{}", js::text(&arg(a, 0)), js::string(&arg(a, 1))));
        Ok(Value::Null)
    }),
    ("net.link.setOffloads", |w, a| {
        w.set_offloads(&js::text(&arg(a, 0)), &arg(a, 1));
        Ok(Value::Null)
    }),
    ("net.link.setGSO", |w, a| w.set_gso(&js::text(&arg(a, 0)), &arg(a, 1))),
    ("ebpf.mapPut", |w, a| {
        let (object, map, key, value) = (js::text(&arg(a, 0)), js::text(&arg(a, 1)), js::text(&arg(a, 2)), js::text(&arg(a, 3)));
        w.map_values.insert(format!("{object}/{map}/{key}"), value.clone());
        w.map_puts.push(json!({"object": object, "map": map, "key": key, "value": value}));
        Ok(Value::Null)
    }),
    ("ebpf.mapGet", |w, a| {
        let key = format!("{}/{}/{}", js::text(&arg(a, 0)), js::text(&arg(a, 1)), js::text(&arg(a, 2)));
        Ok(json!(w.map_values.get(&key).cloned().unwrap_or_else(|| "00".repeat(8))))
    }),
    ("ebpf.mapGetPerCPU", |w, _| {
        Ok(if w.o.per_cpu_values.is_empty() { json!(["00".repeat(32)]) } else { json!(w.o.per_cpu_values) })
    }),
    ("ebpf.mapClear", |_, _| Ok(Value::Null)),
    ("plugins.resources.get", |w, a| {
        let key = format!("{}/{}/{}", js::text(&arg(a, 0)), js::text(&arg(a, 1)), js::text(&arg(a, 2)));
        Ok(w.plugin_records.get(&key).cloned().unwrap_or(Value::Null))
    }),
    ("plugins.resources.set", |w, a| {
        if !w.o.plugin_resource_error.is_empty() {
            return Err(w.o.plugin_resource_error.to_string());
        }
        let key = format!("{}/{}/{}", js::text(&arg(a, 0)), js::text(&arg(a, 1)), js::text(&arg(a, 2)));
        w.plugin_records.insert(key, json!({"data": arg(a, 3), "enabled": !js::is_false(&arg(a, 4)), "apply": js::is_true(&arg(a, 5))}));
        Ok(Value::Null)
    }),
    ("plugins.services.resolve", |_, a| {
        check_wan_adapter(&arg(a, 0))?;
        Ok(json!({"plugin_id": "wan_core", "service": {"id": "wan.adapter", "version": "1.0.0",
            "actions": ["apply_session", "prepare_handoff", "teardown"], "resources": ["profiles", "sessions", "status"]}}))
    }),
    ("plugins.services.call", |w, a| {
        let request = arg(a, 0);
        check_wan_adapter(&request)?;
        let payload = if request["payload"].is_null() { json!({}) } else { request["payload"].clone() };
        let result = w.plugin_action(&js::text(&request["provider"]), &js::text(&request["action"]), &payload)?;
        Ok(json!({"status": "completed", "plugin": request["provider"], "action": request["action"], "result": result}))
    }),
    ("secret.set", |w, a| {
        w.secrets.insert(js::text(&arg(a, 0)), arg(a, 1));
        Ok(Value::Null)
    }),
    ("secret.get", |w, a| Ok(w.secrets.get(&js::text(&arg(a, 0))).cloned().unwrap_or(Value::Null))),
    ("crypto.randomBytes", |w, a| {
        let mut out = String::new();
        for _ in 0..js::number(&arg(a, 0)) as usize {
            out.push_str(&hb(w.random_byte));
            w.random_byte += 1;
        }
        Ok(json!(out))
    }),
    ("crypto.md5", |_, a| {
        let mut input = Vec::new();
        for part in a {
            match part {
                Value::Array(items) => input.extend(items.iter().map(|item| js::number(item) as u8)),
                Value::Object(map) if map.contains_key("hex") => input.extend(hex_to_bytes(&js::string(&map["hex"]))),
                Value::Null => {}
                other => input.extend(js::string(other).into_bytes()),
            }
        }
        Ok(json!(bytes_to_hex(&md5(&input))))
    }),
    ("net.l2.send", |w, a| {
        w.send(&arg(a, 0));
        Ok(Value::Null)
    }),
    ("net.l2.exchange", |w, a| {
        w.l2_exchanges.push(arg(a, 0));
        w.session_exchange_error(&arg(a, 0))?;
        Ok(first_or_null(w.exchange(&arg(a, 0))))
    }),
    ("net.l2.exchangeMany", |w, a| {
        w.l2_exchanges.push(arg(a, 0));
        w.session_exchange_error(&arg(a, 0))?;
        Ok(Value::Array(w.exchange(&arg(a, 0))))
    }),
    ("net.l2.recv", |w, a| {
        if !w.recv_error.is_empty() {
            return Err(w.recv_error.clone());
        }
        w.l2_recvs.push(arg(a, 0));
        Ok(first_or_null(w.recv(&arg(a, 0))))
    }),
    ("net.l2.recvMany", |w, a| {
        if !w.recv_error.is_empty() {
            return Err(w.recv_error.clone());
        }
        w.l2_recvs.push(arg(a, 0));
        Ok(Value::Array(w.recv(&arg(a, 0))))
    }),
];

struct T {
    h: Harness<PppoeClient>,
    world: Arc<Mutex<World>>,
}

impl T {
    fn new(o: Opts) -> T {
        let fake = FakeHost::new();
        match (o.kfuncs, o.direct) {
            (true, true) => fake.set_available_features(&["dataplane.kfuncs.handoff.v1", "dataplane.kfuncs.wan.v1"]),
            (true, false) => fake.set_available_features(&["dataplane.kfuncs.handoff.v1"]),
            _ => {}
        }
        let world = Arc::new(Mutex::new(World { o, random_byte: 1, ..World::default() }));
        for &(method, handler) in HOST {
            let world = world.clone();
            fake.adapter(method, move |args| handler(&mut world.lock().unwrap(), args));
        }
        let weak = Arc::downgrade(&fake);
        let failing = world.clone();
        fake.adapter("resources.set", move |args| {
            let resource = js::text(&arg(args, 0));
            let error = failing.lock().unwrap().o.resource_set_error;
            if !error.is_empty() && error == resource {
                return Err(format!("resource set failed: {resource}"));
            }
            weak.upgrade().unwrap().call_builtin("resources.set", args)
        });
        let h = Harness::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
        T { h, world }
    }

    fn w(&self) -> MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    fn run(&mut self, id: &str, payload: Value) -> Value {
        match self.h.action(id, payload) {
            Ok(Outcome::Value(value)) => value,
            Ok(_) => Value::Null,
            Err(err) => panic!("action {id} failed: {err}"),
        }
    }

    fn fails(&mut self, id: &str, payload: Value) -> String {
        match self.h.action(id, payload) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("action {id} should fail"),
        }
    }

    fn timer(&mut self, name: &str, payload: Value) {
        let ctx = json!({"kind": "timer", "timer": {"name": name, "payload": payload}});
        if let Err(err) = self.h.run(MsgKind::Timer, "onTimer", ctx) {
            panic!("timer {name} failed: {err}");
        }
    }

    /// Fires a timer with the payload it is set with.
    fn refire(&mut self, name: &str) {
        let payload = self.timer_payload(name);
        self.timer(name, payload);
    }

    fn repair(&mut self) {
        self.timer("tunnel_repair", json!({}));
    }

    fn timer_payload(&self, name: &str) -> Value {
        self.h.fake.timer(name).unwrap_or_else(|| panic!("timer {name} is not set"))["payload"].clone()
    }

    fn has_timer(&self, name: &str) -> bool {
        self.h.fake.timer(name).is_some()
    }

    fn record(&self, resource: &str, key: &str) -> Value {
        self.h.fake.record(resource, key).unwrap_or_else(|| panic!("missing resource {resource}/{key}"))
    }

    fn data(&self, resource: &str, key: &str) -> Value {
        self.record(resource, key)["data"].clone()
    }

    fn has(&self, resource: &str, key: &str) -> bool {
        self.h.fake.record(resource, key).is_some()
    }

    fn set(&self, resource: &str, key: &str, data: Value) {
        self.h.fake.put_record(resource, key, data, true);
    }

    fn plugin_record(&self, key: &str) -> Option<Value> {
        self.w().plugin_records.get(key).cloned()
    }

    fn reconcile(&mut self) {
        self.h.reconcile().unwrap();
    }

    fn apply_tunnel_configs(&mut self, records: Value) {
        let ctx = json!({"kind": "resource_apply", "resource": {"id": "tunnel_configs", "runtime_update": "runtime_apply"}, "records": records});
        self.h.run(MsgKind::ResourceApply, "onResourceApply", ctx).unwrap();
    }

    fn l2_ops(&self) -> usize {
        let w = self.w();
        w.l2_sends.len() + w.l2_exchanges.len() + w.l2_recvs.len()
    }

    fn tunnel_puts(&self) -> Vec<String> {
        self.w()
            .map_puts
            .iter()
            .filter(|put| put["object"] == "pppoe_tunnel" && put["map"] == "pppoe_tunnel_config")
            .map(|put| js::text(&put["value"]))
            .collect()
    }

    fn last_put(&self) -> String {
        self.w().map_puts.last().map(|put| js::text(&put["value"])).unwrap_or_default()
    }

    fn net_call(&self, call: &str) -> bool {
        self.w().net_calls.iter().any(|item| item == call)
    }

    fn padt_sent(&self) -> bool {
        self.w().l2_sends.iter().any(|req| discovery_code(&js::text(&req["payload"])) == CODE_PADT)
    }

    /// Whether the client sent a control packet with this code and identifier.
    fn sent_control(&self, protocol: u64, code: u64, identifier: u64) -> bool {
        let w = self.w();
        w.l2_sends.iter().chain(w.l2_exchanges.iter()).any(|req| {
            let payload = js::text(&req["payload"]);
            if js::text(&req["ethertype"]) != SESS || payload.is_empty() {
                return false;
            }
            let Ok(parsed) = parse_session_frame(&json!({"payload_hex": payload})) else { return false };
            if parsed.protocol != protocol {
                return false;
            }
            let cp = parse_cp(&parsed.payload);
            cp.code == code && cp.identifier == identifier
        })
    }

    fn polls_since_client_ipcp_ack(&self) -> usize {
        let w = self.w();
        w.l2_recvs.len() - w.recvs_at_client_ipcp_ack
    }

    /// A session that is up, with its WAN link, as a dial leaves them.
    fn seed_up_session(&self, link: Value) {
        self.set("sessions", "last", json!({"phase": "session_probe", "session_id": SESSION_ID, "ac_mac": AC_MAC, "lcp_ready": true}));
        self.set(
            "wan_links",
            "default",
            js::merge(&json!({"wan_id": "default", "driver": "pppoe", "driver_plugin": "pppoe_client", "state": "up", "usable": true,
                "session_id": SESSION_ID, "ac_mac": AC_MAC}), &link),
        );
    }
}

fn is_hex(value: &Value, len: usize) -> bool {
    let text = js::text(value);
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn u64le(value: u64) -> String {
    bytes_to_hex(&value.to_le_bytes())
}

fn texts(value: &Value) -> Vec<String> {
    js::array(value).iter().map(js::text).collect()
}

fn dhcpv6_payload(extra: Value) -> Value {
    js::merge(
        &json!({
            "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
            "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": true, "ipv6_iid": "0011223344556677",
            "request_ipv6_address": true, "request_pd": true, "dhcpv6_timeout_ms": 8000, "ipv6_ra_timeout_ms": 8000, "dhcpv6_settle_ms": 0,
            "keepalive_interval_ms": 0, "auto_redial": true, "send_padt": false, "post_session_control_ms": 0, "local_interface": "veerlocal0",
            "prepare_interfaces": true, "prepare_local_mtu": true, "prepare_wan_mtu": false, "prepare_offloads": true,
            "wan_core_sync": true, "wan_core_apply": true,
        }),
        &extra,
    )
}

fn ipv4_dial(extra: Value) -> Value {
    js::merge(
        &json!({
            "interface": "eth0", "auth": "none", "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4,
            "negotiate_ipv4": true, "negotiate_ipv6": false, "send_padt": false, "keepalive_interval_ms": 0, "auto_redial": false,
            "install_tunnel": false, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE, "wan_core_sync": false,
        }),
        &extra,
    )
}

fn plain_dial(extra: Value) -> Value {
    js::merge(
        &json!({
            "interface": "eth0", "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4,
            "negotiate_ipv4": false, "negotiate_ipv6": false, "send_padt": false, "wan_core_sync": false,
        }),
        &extra,
    )
}

fn ipv4_tunnel_probe() -> Value {
    json!({
        "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
        "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": false, "send_padt": false,
        "post_session_control_ms": 0, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE, "wan_core_sync": false,
    })
}

/// An lcp_echo timer payload for a session that is up.
fn echo_payload(extra: Value) -> Value {
    js::merge(
        &json!({
            "profile_key": "default", "interface": "eth0", "auth": "none", "timeout_ms": 20, "control_ack_timeout_ms": 10,
            "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": false, "negotiate_ipv6": false, "request_pd": false,
            "keepalive_interval_ms": 1000, "session_id": SESSION_ID, "ac_mac": AC_MAC, "wan_core_sync": false,
        }),
        &extra,
    )
}

fn manifest() -> Value {
    serde_json::from_str(&std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json")).unwrap()).unwrap()
}

// ------------------------------------------------------------ registration

#[test]
fn registration_declares_the_tc_tunnel_and_actions() {
    let manifest = manifest();
    let register = &manifest["control"]["register"];
    let capabilities = texts(&register["capabilities"]);
    assert!(capabilities.iter().any(|item| item == "pppoe"), "pppoe capability should be registered");
    assert!(!capabilities.iter().any(|item| item == "xdp"), "PPPoE should not advertise the removed XDP receive path");
    assert!(js::array(&register["pipeline_nodes"]).iter().any(|item| item["id"] == "pppoe0"), "pppoe0 should be a logical pipeline node");
    let objects = js::array(&register["ebpf_objects"]);
    assert_eq!(objects.len(), 2, "one base and one kfuncs build of the tunnel");
    for object in &objects {
        assert_eq!(object["id"], "pppoe_tunnel");
        let programs = js::array(&object["programs"]);
        assert_eq!(programs.len(), 1, "PPPoE should register only the TC tunnel program");
        assert!(programs[0]["id"] == "tc_tunnel" && programs[0]["type"] == "tc");
    }
    let hooks = js::array(&register["pipeline_attach"]);
    let attach = |id: &str| hooks.iter().find(|hook| hook["id"] == id).map(|hook| js::text(&hook["attach"]));
    assert_eq!(attach("pppoe-ingress").as_deref(), Some("ingress"), "physical ingress hook should be registered");
    assert_eq!(attach("pppoe-egress").as_deref(), Some("ingress"), "segmented pipeline ingress hook should be registered");
    assert_eq!(attach("pppoe-local-egress").as_deref(), Some("egress"), "the direct helper hook runs on egress");
    for hook in &hooks {
        assert_eq!(hook["binding_required"], true, "{} must not run as a global hook before its binding exists", hook["id"]);
        assert_ne!(hook["engine"], "xdp", "PPPoE should not register an XDP hook");
    }
    let actions = js::array(&register["actions"]);
    assert!(actions.iter().any(|item| item["id"] == "traffic_probe"), "traffic_probe action should be registered");
    assert!(actions.iter().any(|item| item["id"] == "traffic_stats" && item["runtime_update"] == "runtime_query"));
    assert_eq!(register["ui"]["page"], "pppoe", "ui page should be registered");
}

#[test]
fn upgrade_lifecycle_checks_the_state_schema() {
    let mut t = T::new(auth("none"));
    match t.h.run(MsgKind::UpgradeSnapshot, "onUpgradeSnapshot", json!({"kind": "upgrade_snapshot"})).unwrap() {
        Outcome::Value(snapshot) => assert_eq!(snapshot["schema_version"].as_u64(), Some(1), "schema_version must be a number"),
        _ => panic!("onUpgradeSnapshot must return the state"),
    }
    t.h.run(MsgKind::UpgradeRestore, "onUpgradeRestore", json!({"upgrade": {"state": {"schema_version": 1}}})).unwrap();
    let err = match t.h.run(MsgKind::UpgradeRestore, "onUpgradeRestore", json!({"upgrade": {"state": {"schema_version": "1"}}})) {
        Err(err) => err.to_string(),
        Ok(_) => panic!("a string schema version must be refused"),
    };
    assert!(err.contains("unsupported PPPoE upgrade state schema"), "{err}");
}

// ------------------------------------------------------------ identity and reconcile

#[test]
fn raw_l2_random_identity_and_cleanup() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("chap") });
    let payload = json!({
        "profile_key": "secondary", "interface": "eth0", "mac_mode": "random", "wan_src_mac": "02:00:00:00:00:fe", "username": "chap-user",
        "password": "chap-pass", "auth": "chap", "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4,
        "negotiate_ipv4": false, "negotiate_ipv6": false, "request_pd": false, "send_padt": false, "keepalive_interval_ms": 1000,
        "install_tunnel": true, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE, "prepare_interfaces": true,
        "prepare_offloads": true, "wan_core_sync": false,
    });
    t.run("dial", payload.clone());
    let managed = t.data("l2_identities", "secondary");
    let mac = js::text(&managed["mac_address"]);
    assert_eq!(managed["interface"], "eth0");
    assert_eq!(managed["custom_mac"], true);
    assert_eq!(managed["promisc_enabled_by_plugin"], true);
    assert!(mac.starts_with("02:"), "random raw-L2 MAC should be locally administered unicast: {mac}");
    assert!(t.net_call("setPromiscuous:eth0:true"), "custom MAC should enable promiscuous mode without creating a netdev");
    let session = t.data("sessions", "last");
    assert_eq!(session["tunnel_installed"], true);
    assert_eq!(session["tunnel"]["wan_interface"], "eth0");
    assert_eq!(session["tunnel"]["local_interface"], "veerlocal0");
    assert_eq!(session["tunnel"]["wan_src_mac"], mac.as_str(), "TC encapsulation should replace a stale WAN source MAC with the raw-L2 identity");
    assert_eq!(texts(&t.data("hook_bindings", "pppoe-ingress")["interfaces"]), ["eth0"]);
    assert_eq!(texts(&t.data("hook_bindings", "pppoe-egress")["interfaces"]), [PIPELINE]);
    assert!(
        t.w().l2_exchanges.iter().any(|item| item["src_mac"] == mac.as_str() && item["recv_dst_mac"] == mac.as_str()),
        "raw-L2 requests must send and receive with the selected MAC"
    );
    assert!(!t.w().net_calls.iter().any(|item| item.starts_with("ensure") || item.starts_with("delete:")));

    let timer = t.timer_payload("lcp_echo");
    assert_eq!(timer["interface"], "eth0");
    assert_eq!(timer["wan_interface"], "eth0");
    assert_eq!(timer["prepare_wan_offloads"], false);
    t.timer("lcp_echo", timer);
    assert_eq!(t.data("l2_identities", "secondary")["mac_address"], mac.as_str(), "keepalive must reuse the random MAC");

    t.run("disconnect", payload);
    assert!(t.net_call("setPromiscuous:eth0:false"), "disconnect should restore plugin-owned promiscuous mode");
    assert!(!t.has("l2_identities", "secondary"), "disconnect should release the raw-L2 identity");
}

#[test]
fn reconcile_restores_only_active_control_state() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("none") });
    t.set("profiles", "default", json!({"interface": "eth0", "auth": "none", "keepalive_interval_ms": 1000, "keepalive_failure_threshold": 3,
        "auto_redial": true, "install_tunnel": true, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE, "wan_core_sync": false}));
    t.set("sessions", "last", json!({"phase": "session_probe", "profile_key": "default", "session_id": SESSION_ID, "ac_mac": AC_MAC,
        "lcp_ready": true, "padt_sent": false}));
    t.reconcile();
    let resumed = t.h.fake.timer("lcp_echo").expect("reconcile should promptly validate the active persisted session");
    assert_eq!(resumed["kind"], "timeout");
    assert_eq!(resumed["payload"]["session_id"], SESSION_ID);

    t.h.fake.clear_timers();
    t.set("sessions", "last", json!({"phase": "disconnected", "profile_key": "default", "session_id": SESSION_ID, "ac_mac": AC_MAC,
        "lcp_ready": false, "padt_sent": true}));
    t.reconcile();
    assert!(!t.has_timer("lcp_echo") && !t.has_timer("redial_retry"), "manual disconnect must remain down after reconcile");

    t.set("sessions", "last", json!({"phase": "redial_wait", "profile_key": "default", "lcp_ready": false, "redial_next_attempt": 2}));
    t.reconcile();
    assert_eq!(t.timer_payload("redial_retry")["redial_attempt"], 2, "reconcile should resume an interrupted redial sequence");
}

#[test]
fn profile_persistence_fails_before_dialing() {
    let mut t = T::new(Opts { resource_set_error: "profiles", ..auth("none") });
    let err = t.fails("dial", json!({"interface": "eth0", "auth": "none", "negotiate_ipv4": false, "negotiate_ipv6": false, "send_padt": false,
        "keepalive_interval_ms": 1000, "auto_redial": true, "wan_core_sync": false}));
    assert!(err.contains("resource set failed"), "{err}");
    assert_eq!(t.w().l2_exchanges.len(), 0, "profile persistence failure must happen before PADI");
}

#[test]
fn keepalive_redial_preserves_tunnel_preparation() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    t.run("traffic_probe", json!({
        "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
        "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": false, "send_padt": false,
        "post_session_control_ms": 0, "keepalive_interval_ms": 1000, "auto_redial": true, "local_interface": "veerlocal0",
        "pipeline_interface": PIPELINE, "prepare_interfaces": true, "prepare_local_mtu": true, "prepare_wan_mtu": false,
        "prepare_offloads": false, "allow_unsafe_offloads": true, "sync_hook_bindings": true, "apply_hook_bindings": true,
        "decap_mode": "manual", "wan_core_sync": false,
    }));
    let payload = t.timer_payload("lcp_echo");
    assert_eq!(payload["prepare_interfaces"], true);
    assert_eq!(payload["prepare_local_mtu"], true);
    assert_eq!(payload["prepare_wan_mtu"], false);
    assert_eq!(payload["prepare_offloads"], false);
    assert_eq!(payload["allow_unsafe_offloads"], true);
    assert_eq!(payload["sync_hook_bindings"], true);
    assert_eq!(payload["apply_hook_bindings"], true);
    assert_eq!(payload["decap_mode"], "manual");
}

#[test]
fn required_wan_core_sync_fails_closed() {
    let mut t = T::new(Opts { plugin_resource_error: "wan core apply failed", ..auth("none") });
    let err = t.fails("traffic_probe", json!({
        "interface": "eth0", "auth": "none", "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4,
        "negotiate_ipv4": false, "negotiate_ipv6": false, "send_padt": false, "post_session_control_ms": 0, "local_interface": "veerlocal0",
        "pipeline_interface": PIPELINE, "wan_core_sync": true, "wan_core_required": true,
    }));
    assert!(err.contains("required WAN core handoff failed: wan core apply failed"), "{err}");
    let session = t.data("sessions", "last");
    assert_eq!(session["phase"], "handoff_error");
    assert_eq!(session["tunnel_installed"], false);
    let link = t.data("wan_links", "default");
    assert_eq!(link["state"], "down");
    assert_eq!(link["usable"], false);
    assert!(t.tunnel_puts().contains(&zero()), "required WAN core failure should clear the tunnel map");
}

// ------------------------------------------------------------ IPv6 and DHCPv6

#[test]
fn pap_ipv6_pd_tunnel() {
    let mut t = T::new(Opts { echo_replies: true, ipcp_dns: true, ..auth("pap") });
    t.run("traffic_probe", json!({
        "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
        "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": true, "ipv6_iid": "0011223344556677",
        "request_pd": true, "dhcpv6_timeout_ms": 8000, "ipv6_ra_timeout_ms": 8000, "dhcpv6_settle_ms": 0, "keepalive_interval_ms": 1000,
        "auto_redial": true, "send_padt": false, "post_session_control_ms": 0, "local_interface": "veerlocal0", "prepare_interfaces": true,
        "prepare_local_mtu": true, "prepare_wan_mtu": false, "prepare_offloads": true, "wan_core_sync": true, "wan_core_apply": true,
    }));

    let session = t.data("sessions", "last");
    assert_eq!(session["phase"], "session_probe");
    assert_eq!(session["session_id"], SESSION_ID);
    assert!(is_hex(&session["lcp_magic"], 8));
    assert_eq!(session["lcp_ack"], true);
    assert_eq!(session["auth_sent"], true);
    assert_eq!(session["auth_method"], "pap");
    assert_eq!(session["auth_ok"], true);
    assert_eq!(session["ipcp"]["phase"], "configure_ack");
    assert_eq!(session["ipcp"]["address"], "198.51.100.10");
    assert_eq!(texts(&session["ipcp"]["dns_servers"]), ["223.5.5.5", "1.1.1.1"]);
    assert_eq!(session["ipv6cp"]["phase"], "configure_ack");
    assert_eq!(session["ipv6cp"]["up"], true);
    assert_eq!(session["ipv6_ra"]["phase"], "router_advertisement");
    assert_eq!(session["ipv6_ra"]["address"], "2001:db8:cafe:1:11:2233:4455:6677");
    assert_eq!(session["ipv6_ra"]["router"], "fe80::2");
    assert_eq!(session["dhcpv6_pd"]["phase"], "reply");
    assert_eq!(session["dhcpv6_pd"]["address"], "2001:db8:abcd::10");
    assert_eq!(session["dhcpv6_pd"]["prefix"], "2001:db8:1234::/56");
    assert_eq!(texts(&session["dhcpv6_pd"]["dns_servers"]), ["2001:4860:4860::8888", "2400:3200::1"]);
    assert_eq!(
        texts(&t.data("wan_links", "default")["dns_servers"]),
        ["223.5.5.5", "1.1.1.1", "2001:4860:4860::8888", "2400:3200::1"]
    );
    assert_eq!(session["tunnel_installed"], true);
    assert_eq!(session["tunnel"]["mode"], "segmented_veth");
    assert_eq!(session["tunnel"]["pipeline_interface"], PIPELINE);
    assert_eq!(session["tunnel"]["decap_mode"], "auto");

    let put = t.tunnel_puts().into_iter().find(|value| *value != zero()).expect("traffic_probe should install a non-zero tunnel config");
    assert_eq!(put.len(), 104, "tunnel config map value must stay ABI-sized");
    assert_eq!(&put[16..24], "66000000", "pipeline ifindex should be encoded after local ifindex");
    assert_eq!(&put[36..40], "0000", "default tunnel config should prefer automatic decapsulation");
    assert_eq!(&put[40..44], "ac05", "IPv4 TCP MSS clamp should default to 1452 for PPPoE MRU 1492");
    let record = t.record("tunnel_configs", "active");
    assert_eq!(record["enabled"], true, "traffic_probe should persist active tunnel config");
    assert_eq!(record["data"]["value_hex"], put.as_str(), "persisted tunnel config should match applied map value");
    assert!(is_hex(&record["data"]["lcp_magic"], 8), "active tunnel config should retain the negotiated LCP magic");
    assert_eq!(&put[96..], js::text(&record["data"]["lcp_magic"]), "eBPF tunnel config should include the local LCP magic");
    assert!(t.has_timer("tunnel_repair"), "active tunnel config should arm repair timer");
    assert!(t.has_timer("lcp_echo"), "traffic_probe should arm keepalive when requested");
    assert!(
        !t.w().net_calls.iter().any(|item| item.starts_with("setMTU:veerlocal0:")
            || item.starts_with("setGSO:veerlocal0:")
            || item.starts_with("setOffloads:veerlocal0:")
            || item.starts_with(&format!("setOffloads:{PIPELINE}:"))),
        "PPPoE must not modify WAN Core-owned handoff interfaces directly: {:?}",
        t.w().net_calls
    );
    assert!(
        t.w().l2_exchanges.iter().all(|item| !js::truthy(&item["timeout_ms"]) || js::number(&item["timeout_ms"]) <= 5000.0),
        "long IPv6 deadlines must use bounded L2 receive windows"
    );

    assert_eq!(texts(&t.data("hook_bindings", "pppoe-ingress")["interfaces"]), ["eth0"]);
    assert_eq!(texts(&t.data("hook_bindings", "pppoe-egress")["interfaces"]), [PIPELINE]);
    let prepare = t
        .w()
        .plugin_action_calls
        .iter()
        .find(|item| item["plugin"] == "wan_core" && item["action"] == "prepare_handoff")
        .cloned()
        .expect("WAN Core handoff should be prepared before dialing");
    let preparation = &prepare["payload"]["interface_preparation"];
    assert_eq!(preparation["local_gso"], json!({"max_size": 1492, "max_segs": 1}));
    assert_eq!(preparation["local_offloads"], json!({"sg": false, "tso": false, "gso": false}));
    assert_eq!(preparation["pipeline_offloads"], json!({"gro": false, "lro": false}));
    let sync = t.plugin_record("wan_core/sessions/default").expect("wan_core session handoff should be written through plugin.resource");
    assert_eq!(sync["data"]["driver"], "pppoe");
    assert_eq!(sync["data"]["usable"], true);
    assert_eq!(sync["data"]["ipv6"], "2001:db8:abcd::10");
}

fn edit_lease(t: &T, renew: f64, rebind: f64, expires: f64) -> Value {
    let mut session = t.data("sessions", "last");
    session["dhcpv6_pd"]["renew_at_ms"] = at(renew);
    session["dhcpv6_pd"]["rebind_at_ms"] = at(rebind);
    session["dhcpv6_pd"]["expires_at_ms"] = at(expires);
    session
}

#[test]
fn dhcpv6_renew_rebind_and_recovery() {
    let mut t = T::new(Opts { echo_replies: true, ipcp_dns: true, ..auth("pap") });
    t.run("traffic_probe", dhcpv6_payload(json!({})));

    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["renew_seconds"], 1800);
    assert_eq!(session["dhcpv6_pd"]["rebind_seconds"], 2880);
    assert_eq!(session["dhcpv6_pd"]["valid_seconds"], 7200);
    assert!(t.has_timer("dhcpv6_lease"), "active DHCPv6 binding should arm a lease timer");
    assert!(t.w().dhcpv6.iter().all(|message| !has_option(message, 20)), "client must not advertise Reconfigure Accept");

    let session = edit_lease(&t, -1.0, 60000.0, 120000.0);
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    assert_eq!(t.w().dhcpv6.last().unwrap().message_type, 5);
    assert_eq!(session["dhcpv6_pd"]["phase"], "renew_reply");
    assert_eq!(session["dhcpv6_pd"]["renew_attempts"], 0);
    assert!(t.has_timer("dhcpv6_lease"));

    let session = edit_lease(&t, -2000.0, -1.0, 120000.0);
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    {
        let w = t.w();
        let rebind = w.dhcpv6.last().unwrap();
        assert_eq!(rebind.message_type, 6);
        assert!(!has_option(rebind, 2), "Rebind must omit Server Identifier");
    }
    assert_eq!(session["dhcpv6_pd"]["phase"], "rebind_reply");

    t.w().o.dhcpv6_timeout_types = vec![5];
    let session = edit_lease(&t, -1.0, 60000.0, 120000.0);
    let retained = session["dhcpv6_pd"]["prefix"].clone();
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["phase"], "renew_retry");
    assert_eq!(session["dhcpv6_pd"]["prefix"], retained, "Renew timeout must retain a still-valid binding");
    assert!(js::number(&session["dhcpv6_pd"]["next_retry_at_ms"]) > now());
    assert!(t.has_timer("dhcpv6_lease"));

    t.w().o.dhcpv6_timeout_types = vec![1];
    let mut session = session;
    session["dhcpv6_pd"]["expires_at_ms"] = at(-1.0);
    session["dhcpv6_pd"]["next_retry_at_ms"] = json!(0);
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["phase"], "reacquire_retry");
    assert_eq!(session["dhcpv6_pd"]["prefix"], "", "expired delegated prefix must fail closed");
    assert_eq!(t.data("wan_links", "default")["pd_prefix"], "");

    t.w().o.dhcpv6_timeout_types = vec![];
    let mut session = session;
    session["dhcpv6_pd"]["next_retry_at_ms"] = at(-1.0);
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["phase"], "reply");
    assert_eq!(session["dhcpv6_pd"]["prefix"], "2001:db8:1234::/56");
    assert_eq!(session["dhcpv6_pd"]["reacquire_attempts"], 0);
}

#[test]
fn dhcpv6_partial_ia_na_status_keeps_the_pd_lease() {
    let mut t = T::new(Opts { echo_replies: true, dhcpv6_no_address: true, ..auth("pap") });
    t.run("traffic_probe", dhcpv6_payload(json!({})));
    let session = t.data("sessions", "last");
    let pd = &session["dhcpv6_pd"];
    assert_eq!(pd["phase"], "reply");
    assert_eq!(pd["address"], "");
    assert_eq!(pd["prefix"], "2001:db8:1234::/56");
    assert_eq!(pd["partial_binding"], true);
    assert_eq!(texts(&pd["partial_ias"]), ["ia_na"]);
    assert!(js::text(&pd["partial_reason"]).contains("NOADDRS-AVAIL"));
    assert_eq!(pd["ia_na_hex"], "", "failed IA_NA must not enter Renew");
    assert_eq!(pd["renew_seconds"], 1800);
    assert!(t.has_timer("dhcpv6_lease"), "a valid IA_PD must retain lease maintenance");
    {
        let w = t.w();
        let request = w.dhcpv6.iter().find(|message| message.message_type == 3).expect("partial Advertise must proceed to Request");
        assert!(!has_option(request, 3), "Request must not echo a failed IA_NA status");
    }

    let session = edit_lease(&t, -1.0, 60000.0, 120000.0);
    t.set("sessions", "last", session);
    t.refire("dhcpv6_lease");
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["phase"], "renew_reply");
    assert_eq!(session["dhcpv6_pd"]["prefix"], "2001:db8:1234::/56");
    assert!(t.has_timer("dhcpv6_lease"));
}

#[test]
fn dhcpv6_reconcile_restores_the_lease_timer_without_keepalive() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    t.run("traffic_probe", dhcpv6_payload(json!({"keepalive_interval_ms": 0})));
    assert!(!t.has_timer("lcp_echo"));
    assert!(t.has_timer("dhcpv6_lease"));

    t.h.fake.clear_timers();
    t.reconcile();
    assert!(!t.has_timer("lcp_echo"));
    assert!(t.has_timer("dhcpv6_lease"), "reconcile must restore DHCPv6 independently of LCP keepalive");

    let stale = t.timer_payload("dhcpv6_lease");
    let exchanges = t.w().dhcpv6.len();
    t.run("disconnect", json!({"profile_key": "default"}));
    assert!(!t.has_timer("dhcpv6_lease"), "disconnect must cancel DHCPv6 lease maintenance");
    t.timer("dhcpv6_lease", stale);
    assert_eq!(t.w().dhcpv6.len(), exchanges, "queued lease timer must not revive a disconnected session");
}

#[test]
fn dhcpv6_invalid_lease_timers_fail_closed() {
    let mut t = T::new(Opts { echo_replies: true, dhcpv6_t1: Some(3000), dhcpv6_t2: Some(2000), ..auth("pap") });
    t.run("traffic_probe", dhcpv6_payload(json!({})));
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["phase"], "request_invalid_lease_timers");
    assert!(session["dhcpv6_pd"].get("prefix").is_none());
    assert_eq!(t.data("wan_links", "default")["pd_prefix"], "");
    assert!(t.has_timer("dhcpv6_lease"), "invalid DHCPv6 reply should retry without redialing the PPPoE session");
}

#[test]
fn ra_driven_ipv6_without_ia_na() {
    let mut t = T::new(Opts { echo_replies: true, omit_iana: true, ..auth("none") });
    t.run("traffic_probe", json!({
        "interface": "eth0", "auth": "none", "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4,
        "negotiate_ipv4": false, "negotiate_ipv6": true, "ipv6_iid": "0011223344556677", "request_pd": true, "dhcpv6_settle_ms": 0,
        "send_padt": false, "post_session_control_ms": 0, "local_interface": "veerlocal0", "wan_core_sync": true, "wan_core_apply": true,
    }));
    let session = t.data("sessions", "last");
    assert_eq!(session["dhcpv6_pd"]["address"], "");
    assert_eq!(session["ipv6_ra"]["address"], "2001:db8:cafe:1:11:2233:4455:6677");
    let sync = t.plugin_record("wan_core/sessions/default").unwrap();
    assert_eq!(sync["data"]["ipv6"], "2001:db8:cafe:1:11:2233:4455:6677");
    assert_eq!(sync["data"]["ipv6_gateway"], "fe80::2");
}

// ------------------------------------------------------------ authentication and IPCP

#[test]
fn auto_auth_negotiates_pap() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    t.run("dial", plain_dial(json!({"username": "user", "password": "pass", "keepalive_interval_ms": 0})));
    let session = t.data("sessions", "last");
    assert_eq!(session["auth"], "auto");
    assert_eq!(session["peer_lcp_ack_sent"], true);
    assert_eq!(session["peer_auth_method"], "pap");
    assert_eq!(session["auth_method"], "pap");
    assert_eq!(session["auth_ok"], true);
    assert_eq!(session["lcp_ready"], true);
    assert_eq!(t.data("profiles", "default")["auth"], "auto");
}

#[test]
fn auto_auth_negotiates_chap() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("chap") });
    t.run("dial", plain_dial(json!({"username": "chap-user", "password": "chap-pass", "auth": "auto", "keepalive_interval_ms": 0})));
    let session = t.data("sessions", "last");
    assert_eq!(session["peer_auth_method"], "chap");
    assert_eq!(session["auth_method"], "chap");
    assert_eq!(session["auth_ok"], true);
    assert_eq!(session["lcp_ready"], true);
}

#[test]
fn explicit_auth_mismatch_fails_closed() {
    let mut t = T::new(auth("chap"));
    let err = t.fails("dial", plain_dial(json!({"username": "user", "password": "pass", "auth": "pap"})));
    assert!(err.contains("peer requires chap authentication but profile auth is pap"), "{err}");
}

#[test]
fn auto_auth_rejects_an_unsupported_chap_algorithm() {
    let mut t = T::new(auth("chap-unsupported"));
    let err = t.fails("dial", plain_dial(json!({"username": "user", "password": "pass", "auth": "auto"})));
    assert!(err.contains("unsupported CHAP algorithm"), "{err}");
}

#[test]
fn ipcp_dns_reject_falls_back() {
    let mut t = T::new(Opts { ipcp_reject_dns: true, ..auth("none") });
    t.run("traffic_probe", ipv4_dial(json!({})));
    let ipcp = t.data("sessions", "last")["ipcp"].clone();
    assert_eq!(ipcp["phase"], "configure_ack", "IPCP must continue when only DNS options are rejected");
    assert_eq!(ipcp["dns_servers"], json!([]));
}

// The peer's IPCP request, acked when it arrives after LCP opens, leaves
// nothing to wait for once the client's own request is acked.
#[test]
fn peer_ipcp_request_acked_after_lcp() {
    let mut t = T::new(auth("none"));
    t.run("traffic_probe", ipv4_dial(json!({})));
    assert_eq!(t.data("sessions", "last")["ipcp"]["up"], true);
    assert!(t.sent_control(PPP_IPCP, 2, PEER_IPCP_ID), "the peer IPCP request must be acked");
    assert!(t.sent_control(PPP_IPV6CP, 2, PEER_IPV6CP_ID), "the peer IPv6CP request must be acked");
    assert_eq!(t.polls_since_client_ipcp_ack(), 1, "an acked peer request must not be waited for");
}

// A peer IPCP request that came between two receives is lost; the session
// is not usable until the peer resends it and the client acks the resend.
#[test]
fn lost_peer_ipcp_request_waits_for_the_resend() {
    let mut t = T::new(Opts { lost_peer_ipcp_request: true, ..auth("none") });
    t.run("traffic_probe", ipv4_dial(json!({"peer_configure_wait_ms": 1000})));
    let ipcp = t.data("sessions", "last")["ipcp"].clone();
    assert_eq!(ipcp["up"], true);
    assert_eq!(ipcp["peer"]["target_acked"], 1, "the resent peer IPCP request must be acked: {}", ipcp["peer"]);
    assert!(t.sent_control(PPP_IPCP, 2, PEER_IPCP_ID));
    // Two empty receives, then the resend: the wait outlasted the first one.
    assert!(t.polls_since_client_ipcp_ack() >= 3, "the client must keep receiving until the resend");
}

// A peer that never sends its request still gets a usable session once the
// wait is over, and the wait does not spin on receives that return at once.
#[test]
fn missing_peer_ipcp_request_bounds_the_wait() {
    let mut t = T::new(Opts { no_peer_network_requests: true, ..auth("none") });
    t.run("traffic_probe", ipv4_dial(json!({"peer_configure_wait_ms": 300})));
    let ipcp = t.data("sessions", "last")["ipcp"].clone();
    assert_eq!(ipcp["up"], true);
    assert_eq!(ipcp["peer"]["phase"], "timeout");
    assert_eq!(ipcp["peer"]["target_acked"], 0);
    let polls = t.polls_since_client_ipcp_ack();
    assert!(polls <= 1 + 6 + 4, "wait polls = {polls}");
}

#[test]
fn manual_mac_uses_raw_l2_without_a_netdev() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    let manual = "02:00:00:00:00:99";
    t.run("traffic_probe", json!({
        "interface": "eth0", "mac_mode": "manual", "mac_address": manual, "username": "user", "password": "pass", "auth": "pap",
        "timeout_ms": 50, "control_ack_timeout_ms": 10, "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true,
        "negotiate_ipv6": false, "request_pd": false, "send_padt": false, "post_session_control_ms": 0, "local_interface": "veerlocal0",
        "pipeline_interface": PIPELINE, "prepare_interfaces": true, "prepare_local_mtu": true, "prepare_offloads": true, "wan_core_sync": false,
    }));
    let session = t.data("sessions", "last");
    assert_eq!(session["tunnel_installed"], true);
    assert_eq!(session["tunnel"]["wan_src_mac"], manual);
    assert!(
        t.w().l2_exchanges.iter().all(|item| item["src_mac"] == manual && item["recv_dst_mac"] == manual),
        "all PPPoE exchanges should use the manual MAC"
    );
    assert!(!t.w().net_calls.iter().any(|item| item.starts_with("ensure") || item.starts_with("delete:")));
}

// ------------------------------------------------------------ keepalive and redial

#[test]
fn chap_dial_keepalive_and_secret_boundary() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("chap") });
    t.run("dial", plain_dial(json!({"username": "chap-user", "password": "chap-pass", "auth": "chap", "request_pd": false,
        "keepalive_interval_ms": 1000})));
    let session = t.data("sessions", "last");
    assert_eq!(session["auth_sent"], true);
    assert_eq!(session["auth_method"], "chap");
    assert_eq!(session["auth_ok"], true);
    assert_eq!(t.w().secrets.get("pppoe-password-default"), Some(&json!("chap-pass")));
    let persisted = t.data("profiles", "default");
    assert_eq!(persisted["username"], "chap-user");
    assert_eq!(persisted["keepalive_failure_threshold"], 5);
    assert_eq!(persisted["keepalive_failure_grace_ms"], 60000);
    assert_eq!(persisted["keepalive_confirm_timeout_ms"], 5000);
    assert!(persisted.get("password").is_none(), "runtime profile must not persist plaintext credentials");
    let timer = t.timer_payload("lcp_echo");
    assert!(!timer.to_string().contains("chap-pass"), "keepalive timer payload must not contain the password");

    t.timer("lcp_echo", timer);
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "keepalive_ok");
    assert_eq!(keepalive["session_id"], SESSION_ID);
}

#[test]
fn keepalive_failure_threshold_recovers_without_redial() {
    let mut t = T::new(auth("none"));
    t.seed_up_session(json!({}));
    let payload = echo_payload(json!({"send_padt": false, "keepalive_failure_threshold": 3, "auto_redial": true, "redial_clear_tunnel": true}));
    t.timer("lcp_echo", payload);
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "keepalive_timeout");
    assert_eq!(keepalive["keepalive_failures"], 1);
    assert!(t.has_timer("lcp_echo"), "a single missed echo should keep the current session armed");
    assert!(!t.has_timer("redial_retry"), "a single missed echo must not trigger redial");
    assert_eq!(t.data("wan_links", "default")["state"], "up");

    t.w().o.echo_replies = true;
    t.refire("lcp_echo");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "keepalive_ok");
    assert_eq!(keepalive["keepalive_failures"], 0);
    assert_eq!(t.timer_payload("lcp_echo")["keepalive_failures"], 0);
    assert!(!t.padt_sent(), "recovered keepalive must not close the session");
}

#[test]
fn keepalive_grace_prevents_a_premature_redial() {
    let mut t = T::new(auth("none"));
    t.seed_up_session(json!({}));
    let started = now();
    t.timer("lcp_echo", echo_payload(json!({"keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 60000,
        "keepalive_confirm_timeout_ms": 100, "keepalive_failure_started_ms": js::num(started), "auto_redial": true})));
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "keepalive_timeout");
    assert!(js::number(&keepalive["keepalive_grace_remaining_ms"]) > 0.0, "failure grace should remain active");
    assert!(!t.has_timer("redial_retry"), "grace period must suppress redial");
    assert_eq!(js::number(&t.timer_payload("lcp_echo")["keepalive_failure_started_ms"]), started);
    assert_eq!(t.data("wan_links", "default")["state"], "up");
    assert!(!t.padt_sent());
}

#[test]
fn keepalive_final_confirmation_recovers_without_padt() {
    let mut t = T::new(Opts { echo_reply_sequence: vec![false, true], ..auth("none") });
    t.seed_up_session(json!({}));
    t.timer("lcp_echo", echo_payload(json!({"keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 0,
        "keepalive_confirm_timeout_ms": 100, "auto_redial": true})));
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "keepalive_ok");
    assert_eq!(keepalive["keepalive_confirmation"], "recovered");
    assert_eq!(keepalive["keepalive_recovered_after_failures"], 1);
    assert_eq!(t.timer_payload("lcp_echo")["keepalive_failures"], 0);
    assert!(!t.has_timer("redial_retry"));
    assert!(!t.has("sessions", "redial_last"));
    assert!(!t.padt_sent());
}

#[test]
fn disabled_auto_redial_honors_the_failure_grace() {
    let mut t = T::new(auth("none"));
    t.seed_up_session(json!({}));
    t.timer("lcp_echo", echo_payload(json!({"keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 60000, "auto_redial": false,
        "redial_clear_tunnel": true})));
    assert!(t.has_timer("lcp_echo"), "disabled redial must keep probing during grace");
    assert_eq!(t.data("wan_links", "default")["state"], "up");
    assert!(!t.tunnel_puts().contains(&zero()), "one timeout must not clear the tunnel when auto redial is disabled");
}

#[test]
fn keepalive_transport_error_keeps_the_retry_state() {
    let mut t = T::new(Opts { link_get_error: "link temporarily unavailable".to_string(), ..auth("none") });
    t.seed_up_session(json!({}));
    t.timer("lcp_echo", echo_payload(json!({"keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 0,
        "keepalive_confirm_timeout_ms": 100, "auto_redial": true, "redial_retry_initial_ms": 250})));
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "redial_wait");
    assert_eq!(keepalive["redial_trigger"], "keepalive_confirm_error");
    assert!(t.has_timer("redial_retry"));
    t.refire("redial_retry");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "redial_wait");
    assert!(js::text(&keepalive["redial_error"]).contains("link temporarily unavailable"));
    assert_eq!(keepalive["redial_next_attempt"], 2);
    assert!(t.has_timer("redial_retry"), "a retry-time link error must schedule the next attempt");
}

#[test]
fn session_control_recovers_after_a_link_failure() {
    for failure in ["receive", "link"] {
        let mut t = T::new(auth("none"));
        let payload = json!({"profile_key": "default", "interface": "eth0", "auth": "none", "timeout_ms": 20, "control_ack_timeout_ms": 10,
            "control_idle_timeout_ms": 1, "max_frames": 4, "session_id": SESSION_ID, "ac_mac": AC_MAC, "deadline_ms": at(2000.0),
            "slice_ms": 20});
        t.set("sessions", "last", json!({"phase": "session_probe", "session_id": SESSION_ID, "ac_mac": AC_MAC, "lcp_ready": true}));
        let sends = t.w().l2_sends.len();
        if failure == "receive" {
            t.w().recv_error = "network is down".to_string();
        } else {
            t.w().o.link_get_error = "network is down".to_string();
        }
        let fire = |t: &mut T, value: Value| {
            t.h.fake.remove_timer("session_control");
            t.timer("session_control", value);
        };
        fire(&mut t, payload.clone());
        let control = t.data("sessions", "control");
        assert_eq!(control["io_errors"], 1, "{failure}");
        assert!(js::text(&control["events"][0]["message"]).contains("network is down"));
        assert!(t.has_timer("session_control"), "link failure must rearm the consumed one-shot timer");
        let retry = t.timer_payload("session_control");
        assert_eq!(js::number(&retry["deadline_ms"]), js::number(&payload["deadline_ms"]), "retry must not extend the window");
        t.w().recv_error.clear();
        t.w().o.link_get_error.clear();
        fire(&mut t, retry.clone());
        let control = t.data("sessions", "control");
        assert_eq!(control["io_errors"], 1, "recovered poll must preserve the diagnostic count");
        assert!(js::number(&control["polls"]) > 0.0, "recovered timer must resume receiving control frames");
        assert!(t.has_timer("session_control"));
        assert_eq!(t.data("sessions", "last")["session_id"], SESSION_ID);
        assert_eq!(t.w().l2_sends.len(), sends, "a transient control-window failure must not transmit PADT or start discovery");
        let mut expired = retry;
        expired["deadline_ms"] = at(-1.0);
        fire(&mut t, expired);
        assert!(!t.has_timer("session_control"), "expired window must stop retrying");
    }
}

#[test]
fn auto_redial_after_a_keepalive_timeout() {
    let mut t = T::new(auth("none"));
    t.seed_up_session(json!({}));
    t.timer("lcp_echo", echo_payload(json!({"send_padt": false, "auto_redial": true, "keepalive_failure_threshold": 1,
        "keepalive_failure_grace_ms": 0, "keepalive_confirm_timeout_ms": 100, "redial_clear_tunnel": true, "redial_retry_initial_ms": 250})));
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["redial_attempted"], true);
    assert_eq!(keepalive["phase"], "redial_wait");
    assert_eq!(keepalive["redial_next_attempt"], 1);
    assert!(!t.has_timer("lcp_echo"), "failed session keepalive must stop before redial");
    assert!(t.has_timer("redial_retry"), "redial should use an independent retry timer");
    assert!(t.padt_sent(), "redial should close the stale session first");
    assert_eq!(t.data("sessions", "redial_last")["trigger"], "keepalive_confirm_timeout");

    t.refire("redial_retry");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "redial_ok");
    assert_eq!(keepalive["redial_session_id"], SESSION_ID);
    assert!(!t.has_timer("redial_retry"), "successful redial should clear retry state");
    assert!(t.has_timer("lcp_echo"), "successful redial should arm keepalive for the new session");
    let last = t.data("sessions", "last");
    assert_eq!(last["phase"], "session_probe");
    assert_eq!(last["padt_sent"], false);
}

#[test]
fn auto_redial_does_not_mask_an_auth_failure() {
    let mut t = T::new(auth("pap-reject"));
    t.seed_up_session(json!({}));
    t.timer("lcp_echo", echo_payload(json!({"username": "user", "password": "wrong-password", "auth": "pap", "send_padt": false,
        "auto_redial": true, "keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 0, "keepalive_confirm_timeout_ms": 100,
        "redial_clear_tunnel": true, "redial_retry_initial_ms": 250})));
    t.refire("redial_retry");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["redial_attempted"], true);
    assert_eq!(keepalive["phase"], "redial_wait");
    assert_eq!(keepalive["redial_phase"], "session_probe");
    assert!(js::text(&keepalive["redial_error"]).contains("authentication failed"), "{}", keepalive["redial_error"]);
    assert_eq!(keepalive["redial_next_attempt"], 2);
    assert!(t.has_timer("redial_retry"), "authentication failure should stay visible and retry with backoff");
    let last = t.data("sessions", "last");
    assert_eq!(last["lcp_ready"], false);
    assert_eq!(last["phase"], "redial_wait");
}

#[test]
fn redial_discovery_failure_retries_without_the_old_keepalive() {
    let mut t = T::new(Opts { pads_timeout: true, ..auth("none") });
    t.seed_up_session(json!({"local_interface": "veerlocal0"}));
    t.timer("lcp_echo", echo_payload(json!({"send_padt": false, "keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 0,
        "keepalive_confirm_timeout_ms": 100, "auto_redial": true, "redial_clear_tunnel": true, "redial_retry_initial_ms": 250,
        "redial_retry_max_ms": 1000, "local_interface": "veerlocal0", "wan_core_sync": true, "wan_core_required": true, "wan_core_apply": true})));
    t.refire("redial_retry");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "redial_wait");
    assert_eq!(keepalive["redial_next_attempt"], 2);
    assert!(js::text(&keepalive["redial_error"]).contains("PADS timeout"));
    assert!(!t.has_timer("lcp_echo"), "failed discovery must not resume the stale session keepalive");
    let wan = t.plugin_record("wan_core/sessions/default").expect("failed discovery should publish WAN Core");
    assert_eq!(wan["enabled"], false, "failed discovery should keep WAN Core fail-closed");

    t.w().o.pads_timeout = false;
    t.refire("redial_retry");
    let keepalive = t.data("sessions", "keepalive");
    assert_eq!(keepalive["phase"], "redial_ok");
    assert_eq!(keepalive["redial_attempt"], 2);
    assert!(t.has_timer("lcp_echo"), "recovered discovery should arm only the new session keepalive");
    assert!(!t.has_timer("redial_retry"));
    let wan = t.plugin_record("wan_core/sessions/default").unwrap();
    assert!(wan["enabled"] == true && wan["apply"] == true, "successful retry should republish WAN Core");
}

// ------------------------------------------------------------ disconnect and stale timers

#[test]
fn disconnect_clears_tunnel_and_wan_state() {
    let mut t = T::new(Opts { terminate_on_padt: true, ..auth("none") });
    t.seed_up_session(json!({}));
    t.set("sessions", "last", json!({"phase": "session_probe", "wan_id": "default", "session_id": SESSION_ID, "ac_mac": AC_MAC,
        "lcp_ready": true}));
    t.run("disconnect", json!({"interface": "eth0", "wan_core_sync": true, "wan_core_apply": true}));

    {
        let w = t.w();
        let padt = w.l2_sends.iter().chain(w.l2_exchanges.iter()).any(|req| {
            req["ethertype"] == DISC && discovery_code(&js::text(&req["payload"])) == CODE_PADT
        });
        assert!(padt, "disconnect should send PADT");
    }
    assert!(t.sent_control(PPP_LCP, 6, 0x7e), "disconnect should acknowledge the peer LCP Terminate-Request");
    let last = t.data("sessions", "last");
    assert_eq!(last["phase"], "disconnected");
    assert_eq!(last["padt_sent"], true);
    assert_eq!(last["lcp_terminate_ack_sent"], true);
    assert_eq!(last["disconnect_control"]["phase"], "terminated");
    assert_eq!(last["disconnect_control"]["terminate_acks_sent"], 1);
    let wan = t.record("wan_links", "default");
    assert_eq!(wan["enabled"], false);
    assert_eq!(wan["data"]["usable"], false);
    assert_eq!(wan["data"]["phase"], "disconnected");
    assert!(t.tunnel_puts().contains(&zero()), "disconnect should clear tunnel config");
    assert!(!t.has_timer("tunnel_repair"), "disconnect should clear tunnel repair timer");
}

#[test]
fn dial_is_idempotent_while_a_session_is_active() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("none") });
    t.run("dial", plain_dial(json!({"auth": "none", "request_pd": false, "keepalive_interval_ms": 1000, "post_session_control_ms": 0})));
    let first = t.data("sessions", "last");
    let exchanges = t.w().l2_exchanges.len();
    t.run("dial", json!({"profile_key": "default"}));
    let second = t.data("sessions", "last");
    assert_eq!(t.w().l2_exchanges.len(), exchanges, "dial on an active profile must not start another discovery");
    assert_eq!(second["session_id"], first["session_id"]);
    assert_eq!(second["session_generation"], first["session_generation"]);
    assert!(is_hex(&first["session_generation"], 16));
}

#[test]
fn queued_session_timers_cannot_revive_a_disconnected_session() {
    let mut t = T::new(Opts { echo_replies: true, terminate_on_padt: true, ..auth("none") });
    t.run("dial", plain_dial(json!({"auth": "none", "request_pd": false, "keepalive_interval_ms": 1000, "post_session_control_ms": 1000})));
    let stale_keepalive = t.timer_payload("lcp_echo");
    let stale_control = t.timer_payload("session_control");
    assert!(js::truthy(&stale_keepalive["session_generation"]), "keepalive must carry the active session generation");
    assert_eq!(stale_control["session_generation"], stale_keepalive["session_generation"]);

    t.run("disconnect", json!({"profile_key": "default"}));
    let ops = t.l2_ops();
    t.timer("lcp_echo", stale_keepalive.clone());
    t.timer("session_control", stale_control);
    let last = t.data("sessions", "last");
    assert_eq!(last["phase"], "disconnected");
    assert_eq!(last["desired_state"], "down");
    assert_eq!(t.l2_ops(), ops, "queued session timers must exit before any L2 operation");
    assert!(!t.has_timer("lcp_echo"));
    assert!(!t.has_timer("session_control"));
    assert!(!t.has_timer("redial_retry"));

    t.set("sessions", "last", json!({"phase": "session_probe", "profile_key": "default", "session_id": SESSION_ID, "ac_mac": AC_MAC,
        "session_generation": "ff".repeat(8), "desired_state": "up", "lcp_ready": true, "padt_sent": false}));
    t.timer("lcp_echo", stale_keepalive);
    assert_eq!(t.l2_ops(), ops, "a reused session id and AC MAC must still reject an older generation");
}

#[test]
fn queued_redial_cannot_run_after_disconnect() {
    let mut t = T::new(auth("none"));
    t.set("sessions", "last", json!({"phase": "session_probe", "profile_key": "default", "session_id": SESSION_ID, "ac_mac": AC_MAC,
        "lcp_ready": true}));
    t.set("wan_links", "default", json!({"wan_id": "default", "state": "up", "usable": true, "session_id": SESSION_ID, "ac_mac": AC_MAC}));
    t.timer("lcp_echo", echo_payload(json!({"keepalive_failure_threshold": 1, "keepalive_failure_grace_ms": 0,
        "keepalive_confirm_timeout_ms": 20, "auto_redial": true, "redial_clear_tunnel": true, "redial_retry_initial_ms": 250})));
    let stale = t.timer_payload("redial_retry");
    assert!(js::truthy(&stale["redial_generation"]), "redial retry must carry a cancellation generation");

    t.run("disconnect", json!({"profile_key": "default", "interface": "eth0", "auth": "none", "disconnect_drain_ms": 0,
        "session_id": SESSION_ID, "ac_mac": AC_MAC, "wan_core_sync": false}));
    let exchanges = t.w().l2_exchanges.len();
    t.timer("redial_retry", stale);
    assert_eq!(t.w().l2_exchanges.len(), exchanges, "queued redial must not send PADI after disconnect");
    assert_eq!(t.data("sessions", "last")["phase"], "disconnected");
    assert!(!t.has_timer("redial_retry"));
}

// ------------------------------------------------------------ tunnel config and repair

#[test]
fn tunnel_config_runtime_apply_replays_and_clears_the_map() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    t.run("traffic_probe", ipv4_tunnel_probe());
    let record = t.record("tunnel_configs", "active");
    let value = js::text(&record["data"]["value_hex"]);

    // A dataplane reload creates an empty map.
    t.w().map_puts.clear();
    t.w().map_values.clear();
    t.apply_tunnel_configs(json!([{"key": "active", "data": record["data"], "enabled": true}]));
    assert_eq!(t.tunnel_puts().first(), Some(&value), "runtime_apply should replay the tunnel config into the eBPF map");

    t.w().map_puts.clear();
    t.w().map_values.clear();
    let mut legacy = record["data"].clone();
    legacy["value_hex"] = json!(&value[..96]);
    for key in ["lcp_magic", "profile_key", "wan_link_mac", "local_dst_mac_explicit", "repair_preparation"] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    t.apply_tunnel_configs(json!([{"key": "active", "data": legacy, "enabled": true}]));
    assert_eq!(t.tunnel_puts().first(), Some(&format!("{}{}", &value[..96], "00".repeat(4))), "legacy tunnel config should gain a zero LCP magic");

    t.w().map_puts.clear();
    t.h.fake.delete_record("tunnel_configs", "active");
    t.apply_tunnel_configs(json!([]));
    assert_eq!(t.tunnel_puts().first(), Some(&zero()), "empty tunnel config apply should write the zero ABI value");
}

// The host reads a resource_apply snapshot before the event waits for the
// plugin's queue, so a disconnect or a dial can run in between.
#[test]
fn stale_tunnel_config_snapshots_follow_the_stored_record() {
    let mut t = T::new(Opts { echo_replies: true, ..auth("pap") });
    let map_key = "pppoe_tunnel/pppoe_tunnel_config/00000000";
    let empty = json!(t.h.fake.records("tunnel_configs"));
    t.run("traffic_probe", ipv4_tunnel_probe());
    let live = t.h.fake.records("tunnel_configs");
    assert_eq!(live.len(), 1, "traffic_probe should store the tunnel config");
    assert!(js::number(&live[0]["revision"]) > 0.0, "stored tunnel config should carry a revision");
    let tunnel = t.w().map_values.get(map_key).cloned().expect("traffic_probe should write the tunnel config");
    assert_ne!(tunnel, zero());

    // An empty snapshot taken before the session came up must not clear it.
    t.w().map_puts.clear();
    t.apply_tunnel_configs(empty);
    assert_eq!(t.w().map_values.get(map_key), Some(&tunnel), "stale empty snapshot must not clear a live tunnel");
    assert!(t.has_timer("tunnel_repair"), "live tunnel should keep its repair timer");

    t.run("disconnect", json!({"interface": "eth0", "profile_key": "default"}));
    assert!(!t.has("tunnel_configs", "active"), "disconnect should delete the tunnel config");
    assert_eq!(t.w().map_values.get(map_key), Some(&zero()), "disconnect should clear the tunnel map");
    assert!(!t.has_timer("tunnel_repair"), "disconnect should clear the repair timer");

    // A snapshot taken before the disconnect must not write the session back.
    t.w().map_puts.clear();
    t.apply_tunnel_configs(json!(live));
    assert_eq!(t.w().map_values.get(map_key), Some(&zero()), "stale live snapshot must not revive a disconnected tunnel");
    assert!(t.tunnel_puts().iter().all(|value| *value == zero()), "stale live snapshot must not write a tunnel config");
    assert!(!t.has_timer("tunnel_repair"), "stale live snapshot must not arm the repair timer");
    assert!(!t.has("tunnel_configs", "active"), "stale live snapshot must not recreate the record");
}

#[test]
fn tunnel_repair_follows_the_current_interfaces() {
    let mut t = T::new(auth("pap"));
    t.run("traffic_probe", json!({"interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50,
        "post_session_control_ms": 0, "send_padt": false, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE,
        "wan_core_sync": false}));
    t.w().map_puts.clear();
    t.repair();
    t.repair();
    assert_eq!(t.w().map_puts.len(), 0, "stable repair must not rewrite the map");
    t.set("profiles", "default", json!({"interface": "eth0", "mru": 1200, "mac_mode": "manual", "mac_address": "02:00:00:00:99:88"}));
    {
        let mut w = t.w();
        w.net_calls.clear();
        let mut local = w.link("veerlocal0");
        local["ifindex"] = json!(201);
        local["peer_ifindex"] = json!(202);
        local["mac"] = json!("02:00:00:00:21:01");
        let mut peer = w.link(PIPELINE);
        peer["ifindex"] = json!(202);
        peer["peer_ifindex"] = json!(201);
        w.links.insert("veerlocal0".to_string(), local);
        w.links.insert(PIPELINE.to_string(), peer);
    }
    t.repair();
    let repaired = t.data("tunnel_configs", "active");
    let value = decode_tunnel_config_hex(&js::text(&repaired["value_hex"])).unwrap();
    assert_eq!(value["local_ifindex"], 201);
    assert_eq!(value["pipeline_ifindex"], 202);
    assert_eq!(value["local_dst_mac"], "02:00:00:00:21:01");
    assert_eq!(value["session_id"], SESSION_ID, "handoff repair must preserve the PPP session");
    assert_eq!(value["wan_src_mac"], LOCAL_MAC, "repair must retain the live client identity");
    assert!(t.net_call("setGSO:veerlocal0:1492:1"), "repair must retain the live MTU despite profile edits");
    assert_eq!(t.data("l2_identities", "default")["mac_address"], LOCAL_MAC);

    t.w().missing_link = "veerlocal0".to_string();
    t.repair();
    assert_eq!(t.last_put(), zero(), "missing interface must deactivate the tunnel");
    assert!(js::text(&t.data("tunnel_configs", "active")["last_repair_error"]).contains("link not found"));
    let cleared = t.w().map_puts.len();
    t.repair();
    assert_eq!(t.w().map_puts.len(), cleared, "an already disabled tunnel needs no repeated map writes");
    t.w().missing_link.clear();
    t.repair();
    assert_eq!(t.last_put(), js::text(&repaired["value_hex"]));
    assert_eq!(t.data("tunnel_configs", "active")["last_repair_error"], "");

    t.w().link_mut("veerlocal0")["up"] = json!(false);
    t.repair();
    assert_eq!(t.last_put(), zero(), "a down endpoint must deactivate the tunnel");
    t.w().link_mut("veerlocal0")["up"] = json!(true);
    t.repair();
    assert_eq!(t.last_put(), js::text(&repaired["value_hex"]));
    t.w().link_mut(PIPELINE)["peer_ifindex"] = json!(999);
    t.repair();
    assert_eq!(t.last_put(), zero(), "unrelated veth must not be adopted");
    t.w().link_mut(PIPELINE)["peer_ifindex"] = json!(201);
    t.w().link_mut("eth0")["mac"] = json!("02:00:00:00:99:01");
    t.repair();
    assert!(js::text(&t.data("tunnel_configs", "active")["last_repair_error"]).contains("WAN identity changed"));
}

#[test]
fn tunnel_dataplane_switch_preserves_the_session() {
    let mut t = T::new(auth("pap"));
    t.run("traffic_probe", json!({"interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50,
        "post_session_control_ms": 0, "send_padt": false, "local_interface": "veerlocal0", "pipeline_interface": PIPELINE,
        "wan_core_sync": true}));
    let original = t.data("tunnel_configs", "active");
    assert_eq!(original["repair_preparation"]["wan_core_prepared_interfaces"], true);
    for enhanced in [true, false] {
        t.h.plugin.features = Some((enhanced, false));
        t.w().net_calls.clear();
        t.w().map_puts.clear();
        let sends = t.w().l2_sends.len();
        t.repair();
        let current = t.data("tunnel_configs", "active");
        assert_eq!(current["dataplane"], if enhanced { "kfuncs" } else { "bpf" });
        assert_eq!(current["session_id"], original["session_id"]);
        assert_eq!(current["value_hex"], original["value_hex"]);
        assert_eq!(t.w().map_puts.len(), 0, "mode switch must preserve tunnel ABI and indices");
        assert_eq!(t.w().l2_sends.len(), sends, "mode switch must not redial");
        assert_eq!(t.w().plugin_action_calls.last().unwrap()["action"], "apply_session", "WAN Core must update its own offload leases");
        assert_eq!(t.w().plugin_record_data("wan_core/status/default")["usable"], true);
        let calls = t.w().net_calls.clone();
        let expect = |call: &str| assert!(calls.iter().any(|item| item == call), "missing {call} in {calls:?}");
        expect(&format!("setGSO:veerlocal0:{}", if enhanced { "65536:65535" } else { "1492:1" }));
        expect(if enhanced { "setOffloads:veerlocal0:gro=true,gso=true,sg=true,tso=true" } else { "setOffloads:veerlocal0:gso=false,sg=false,tso=false" });
        expect(&if enhanced { format!("setOffloads:{PIPELINE}:gro=true,lro=false,tso=false") } else { format!("setOffloads:{PIPELINE}:gro=false,lro=false") });
        t.w().net_calls.clear();
        t.repair();
        assert_eq!(t.w().net_calls.len(), 0, "stable mode must not repeatedly reconfigure interfaces");
    }
    t.h.plugin.features = Some((true, false));
    t.w().set_gso_error = "GSO preparation failed".to_string();
    t.repair();
    assert_eq!(t.last_put(), zero(), "failed mode switch must stop forwarding");
    assert_eq!(t.data("tunnel_configs", "active")["dataplane"], "bpf");
    t.w().set_gso_error.clear();
    t.repair();
    assert_eq!(t.last_put(), js::text(&original["value_hex"]), "retry must restore the same session");
    assert_eq!(t.data("tunnel_configs", "active")["dataplane"], "kfuncs");
}

#[test]
fn traffic_probe_timeout_fails_closed() {
    let mut t = T::new(Opts { pads_timeout: true, ..auth("pap") });
    let err = t.fails("traffic_probe", json!({
        "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
        "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": false, "send_padt": false,
        "post_session_control_ms": 0, "local_interface": "veerlocal0", "wan_core_sync": false,
    }));
    assert!(err.contains("PADS timeout"), "{err}");
    let session = t.data("sessions", "last");
    assert_eq!(session["phase"], "timeout");
    assert_eq!(session["message"], "PADS timeout");
    assert!(!t.has("tunnel_configs", "active"), "failed traffic_probe must not persist tunnel config");
}

#[test]
fn traffic_probe_error_after_pads_releases_the_session() {
    // PADS allocated a session at the AC; an error in the session probe must
    // send PADT, or a single-session AC refuses the next dial until its LCP
    // gives up.
    let mut t = T::new(Opts { session_exchange_error: "network is down", ..auth("pap") });
    let err = t.fails("traffic_probe", json!({
        "interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50, "control_ack_timeout_ms": 10,
        "control_idle_timeout_ms": 1, "max_frames": 4, "negotiate_ipv4": true, "negotiate_ipv6": false, "send_padt": false,
        "post_session_control_ms": 0, "local_interface": "veerlocal0", "wan_core_sync": false,
    }));
    assert!(err.contains("network is down"), "{err}");
    assert!(t.padt_sent(), "a session probe error after PADS must send PADT");
    assert!(!t.has("tunnel_configs", "active"), "failed traffic_probe must not persist tunnel config");
}

#[test]
fn debug_stats_declare_the_counter_build_mode() {
    let mut t = T::new(auth("none"));
    t.run("debug_stats", json!({}));
    let stats = t.data("sessions", "debug_stats")["stats"].clone();
    assert_eq!(stats["counter_build"], "disabled_by_default");
    assert!(js::text(&stats["note"]).contains("PPPOE_TUNNEL_DIAG=1"), "debug stats should explain how to enable per-packet counters");
    assert_eq!(stats["local_encap_path"], 0);
    assert_eq!(stats["pppoe_seen"], 0);
}

#[test]
fn traffic_stats_aggregate_per_cpu_values() {
    let mut t = T::new(Opts {
        per_cpu_values: vec![
            format!("{}{}{}{}", u64le(1), u64le(100), u64le(2), u64le(200)),
            format!("{}{}{}{}", u64le(3), u64le(300), u64le(4), u64le(400)),
        ],
        ..auth("none")
    });
    t.set("sessions", "last", json!({"profile_key": "default", "session_id": SESSION_ID}));
    t.set("tunnel_configs", "active", json!({"session_id": SESSION_ID}));
    let stats = t.run("traffic_stats", json!({"profile_key": "default"}));
    assert_eq!(stats["available"], true);
    assert_eq!(stats["rx_packets"], 4);
    assert_eq!(stats["rx_bytes"], 400);
    assert_eq!(stats["tx_packets"], 6);
    assert_eq!(stats["tx_bytes"], 600);
    assert_eq!(stats["byte_scope"], "inner_ip");
}

#[test]
fn direct_helper_boundary() {
    let mut t = T::new(Opts { kfuncs: true, direct: true, ..auth("pap") });
    t.run("traffic_probe", json!({"interface": "eth0", "username": "user", "password": "pass", "auth": "pap", "timeout_ms": 50,
        "post_session_control_ms": 0, "send_padt": false, "local_interface": "veerlocal0", "wan_core_sync": true}));
    let original = t.data("tunnel_configs", "active");
    assert_eq!(original["mode"], "direct_gro");
    assert_eq!(original["pipeline_interface"], "");
    assert_eq!(original["pipeline_ifindex"], original["local_ifindex"]);
    assert_eq!(t.record("hook_bindings", "pppoe-egress")["enabled"], false);
    assert_eq!(texts(&t.data("hook_bindings", "pppoe-local-egress")["interfaces"]), ["veerlocal0"]);
    assert_eq!(t.data("wan_links", "default")["handoff_mode"], "direct_gro");
    let sends = t.w().l2_sends.len();
    for change in ["down", "wrong-kind", "missing-helper"] {
        {
            let mut w = t.w();
            let local = w.link_mut("veerlocal0");
            local["up"] = json!(change != "down");
            local["kind"] = json!(if change == "wrong-kind" { "dummy" } else { "veerwan" });
        }
        t.h.plugin.features = Some((true, change != "missing-helper"));
        t.repair();
        assert_eq!(t.last_put(), zero(), "{change} must stop this tunnel");
        {
            let mut w = t.w();
            let local = w.link_mut("veerlocal0");
            local["up"] = json!(true);
            local["kind"] = json!("veerwan");
        }
        t.h.plugin.features = Some((true, true));
        t.repair();
        assert_eq!(t.last_put(), js::text(&original["value_hex"]));
    }
    {
        let mut w = t.w();
        let local = w.link_mut("veerlocal0");
        local["ifindex"] = json!(301);
        local["mac"] = json!("02:00:00:00:21:01");
    }
    t.repair();
    let repaired = t.data("tunnel_configs", "active");
    assert_eq!(js::text(&repaired["last_repair_error"]), "");
    assert_eq!(repaired["local_ifindex"], 301);
    assert_eq!(repaired["pipeline_ifindex"], 301);
    assert_eq!(repaired["session_id"], original["session_id"]);
    assert_eq!(t.w().l2_sends.len(), sends, "boundary recovery must not redial");

    // Helper 1.0/1.1 (no direct feature) keeps the veth pair.
    let mut legacy = T::new(Opts { kfuncs: true, ..auth("none") });
    legacy.reconcile();
    assert_eq!(legacy.h.plugin.features, Some((true, false)), "helper 1.0/1.1 must keep veth");
}
