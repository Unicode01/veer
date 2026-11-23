//! Ports of test-compile.test.js and test-control.test.js.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use veer_plugin::testing::{FakeHost, Harness};
use veer_plugin::{json, js, Outcome, Value};

use crate::compile as c;
use crate::Firewall;

fn cidr(text: &str) -> c::Cidr {
    c::parse_cidr_str(text).unwrap_or_else(|err| panic!("{text}: {err}"))
}

fn pol(key: &str, data: Value) -> c::Policy {
    c::normalize_policy(key, &data, None).unwrap_or_else(|err| panic!("{key}: {err}"))
}

fn pol_sets(key: &str, data: Value, sets: &[&str]) -> veer_plugin::Result<c::Policy> {
    let sets: Vec<String> = sets.iter().map(|s| s.to_string()).collect();
    c::normalize_policy(key, &data, Some(&sets))
}

fn err_of<T>(result: veer_plugin::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(err) => err.to_string(),
    }
}

fn with(base: Value, extra: Value) -> Value {
    js::merge(&base, &extra)
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn no_sets() -> BTreeMap<String, u32> {
    BTreeMap::new()
}

// ------------------------------------------------------------ compile

#[test]
fn parse_cidr_normalizes_ipv4_ipv6_and_mapped_prefixes() {
    let cases = [
        ("10.1.2.3/8", 4, 8, "10.0.0.0/8", "0a000000"),
        ("192.0.2.10", 4, 32, "192.0.2.10/32", "c000020a"),
        ("2001:db8::1/64", 6, 64, "2001:db8::/64", "20010db8000000000000000000000000"),
        ("::1", 6, 128, "::1/128", "00000000000000000000000000000001"),
        ("::ffff:1.2.3.0/120", 4, 24, "1.2.3.0/24", "01020300"),
        ("64:ff9b::1.2.3.4", 6, 128, "64:ff9b::102:304/128", "0064ff9b000000000000000001020304"),
        ("1:2:3:4:5:6:1.2.3.4", 6, 128, "1:2:3:4:5:6:102:304/128", "00010002000300040005000601020304"),
        ("::/0", 6, 0, "::/0", "00000000000000000000000000000000"),
    ];
    for (input, family, prefix, text, hex) in cases {
        let got = cidr(input);
        assert_eq!(got.family, family, "{input}");
        assert_eq!(got.prefix, prefix, "{input}");
        assert_eq!(got.text, text, "{input}");
        assert_eq!(c::bytes_hex(&got.bytes), hex, "{input}");
    }
    for bad in ["1.2.3", "1.2.3.4/33", "01.2.3.4", "::1::2", "1:2:3:4:5:6:7:8:9", "g::1", "", "1.2.3.4/x"] {
        assert!(c::parse_cidr_str(bad).is_err(), "{bad}");
    }
}

#[test]
fn cidr_overlap_compares_the_shorter_prefix_only() {
    assert!(c::cidr_overlap(&cidr("10.0.0.0/8"), &cidr("10.1.0.0/16")));
    assert!(!c::cidr_overlap(&cidr("10.0.0.0/16"), &cidr("10.1.0.0/16")));
    assert!(!c::cidr_overlap(&cidr("10.0.0.0/8"), &cidr("::/0")));
    assert!(c::cidr_overlap(&cidr("2001:db8::/32"), &cidr("2001:db8:1::/48")));
}

#[test]
fn port_ranges_merge_and_decompose_into_aligned_prefixes() {
    assert_eq!(c::parse_port_ranges(&json!(["22", "20-25", 80, "81"]), "p").unwrap(), vec![(20, 25), (80, 81)]);
    for bad in [json!(["0"]), json!(["10-5"]), json!(["65536"])] {
        assert!(c::parse_port_ranges(&bad, "p").is_err(), "{bad}");
    }
    assert_eq!(c::port_prefixes(22, 22), vec![(22, 16)]);
    assert_eq!(c::port_prefixes(11100, 11200), vec![(11100, 14), (11104, 11), (11136, 10), (11200, 16)]);
    // Every port of 1-65535 is covered exactly once.
    let covered: u32 = c::port_prefixes(1, 65535).iter().map(|(_, prefix)| 1 << (16 - prefix)).sum();
    assert_eq!(covered, 65535);
}

#[test]
fn conflicting_policies_are_reported_disjoint_ones_are_not() {
    let p = |key: &str, data: Value| pol(key, with(json!({"ports": ["22"]}), data));
    assert_eq!(c::find_conflicts(&[p("a", json!({})), p("b", json!({"protocol": "udp"}))]).len(), 0);
    assert_eq!(c::find_conflicts(&[p("a", json!({})), p("b", json!({}))]).len(), 1);
    assert_eq!(c::find_conflicts(&[p("a", json!({"destinations": ["10.0.0.1"]})), p("b", json!({"destinations": ["10.0.0.2"]}))]).len(), 0);
    assert_eq!(c::find_conflicts(&[p("a", json!({"destinations": ["10.0.0.0/8"]})), p("b", json!({"destinations": ["10.1.0.1"]}))]).len(), 1);
    assert_eq!(c::find_conflicts(&[p("a", json!({"destinations": ["10.0.0.1"]})), p("b", json!({}))]).len(), 1);
    assert_eq!(c::find_conflicts(&[p("a", json!({"ports": ["1-100"]})), p("b", json!({"ports": ["100-200"]}))]).len(), 1);
    assert!(c::normalize_policy("x", &json!({"ports": ["22"], "protocol": "icmp"}), None).is_err());
    let dup = json!({"ports": ["22"], "sources": [{"cidr": "1.2.3.4", "action": "allow"}, {"cidr": "1.2.3.4/32", "action": "drop"}]});
    assert!(c::normalize_policy("x", &dup, None).is_err());
}

#[test]
fn slots_stay_with_their_policy_and_new_policies_avoid_freed_slots() {
    let first = c::assign_slots(&strings(&["a", "b", "c"]), &BTreeMap::new()).unwrap();
    assert_eq!(first.ids, BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2), ("c".to_string(), 3)]));
    assert_eq!(first.fresh, vec![1, 2, 3]);
    let second = c::assign_slots(&strings(&["c", "d"]), &first.ids).unwrap();
    assert_eq!(second.ids["c"], 3);
    assert_eq!(second.ids["d"], 4); // 1 and 2 were held by deleted policies
    assert_eq!(second.fresh, vec![4]);
}

fn lpm_map(out: &c::Compiled, map: &str) -> BTreeMap<String, String> {
    out.lpm[map].iter().map(|e| (e.key.clone(), e.value.clone())).collect()
}

fn lpm_pairs(out: &c::Compiled, map: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = out.lpm[map].iter().map(|e| (e.key.clone(), e.value.clone())).collect();
    pairs.sort();
    pairs
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

#[test]
fn compile_generation_lays_out_the_maps_the_program_reads() {
    let mut rdp = pol("rdp", json!({"protocol": "tcp", "ports": ["23390"], "default_action": "drop", "sources": [{"cidr": "203.0.113.0/24", "action": "allow"}]}));
    rdp.slot = 1;
    let mut ssh = pol(
        "ssh",
        json!({"protocol": "tcp+udp", "ports": ["22", "10022-10024"], "destinations": ["198.51.100.7"], "sources": [{"cidr": "2001:db8::/32", "action": "allow"}]}),
    );
    ssh.slot = 2;
    let out = c::compile_generation(&[rdp, ssh], &[cidr("192.0.2.10")], 1, &no_sets(), &c::Settings::default()).unwrap();
    assert!(out.active);
    let bits = &out.arrays["fw_port_bits"];
    // Port 22: word 0, bit 22, in generation 1 (index 2048) for TCP and 3072 for UDP.
    assert_eq!(bits[&2048], "0000400000000000");
    assert_eq!(bits[&3072], "0000400000000000");
    // 10022-10024: word 156, bits 38-40 (high half 0x1c0).
    assert_eq!(bits[&(2048 + 156)], "00000000c0010000");
    // 23390 is TCP only.
    assert_eq!(bits[&(2048 + 365)], "0000004000000000");
    assert!(!bits.contains_key(&(3072 + 365)));
    // Class 1: ports of ssh, scoped by destination; class 2: rdp for any destination.
    assert_eq!(out.arrays["fw_class"][&(1024 + 1)], "00000100");
    assert_eq!(out.arrays["fw_class"][&(1024 + 2)], "01000000");
    assert_eq!(out.arrays["fw_policy"][&(256 + 1)], "01010000");
    assert_eq!(out.arrays["fw_policy"][&(256 + 2)], "01010000");
    let ports = lpm_map(&out, "fw_ports");
    assert_eq!(ports["2000000001000016"], "01000000"); // tcp 22/16 -> class 1
    assert_eq!(ports["1f00000001002726"], "01000000"); // tcp 10022/15
    assert_eq!(ports["2000000001005b5e"], "02000000"); // tcp 23390 -> class 2
    assert_eq!(ports["2000000001010016"], "01000000"); // udp 22
    assert_eq!(lpm_pairs(&out, "fw_dst4"), vec![pair("4000000001000001c6336407", "02000000")]);
    assert_eq!(
        lpm_pairs(&out, "fw_src4"),
        vec![
            pair("3800000001000001cb007100", "00000000"), // rdp: 203.0.113.0/24 allow
            pair("4000000001000000c000020a", "00000000"), // trusted 192.0.2.10
        ]
    );
    assert_eq!(lpm_pairs(&out, "fw_src6"), vec![pair("400000000100000220010db8000000000000000000000000", "00000000")]);
    for map in c::LPM_MAPS {
        for e in &out.lpm[map] {
            assert_eq!(c::key_generation(&e.key), 1, "{map}");
        }
    }
}

#[test]
fn an_empty_rule_set_is_inactive_and_writes_nothing() {
    let out = c::compile_generation(&[], &[], 0, &no_sets(), &c::Settings::default()).unwrap();
    assert!(!out.active);
    for map in c::ARRAY_MAPS {
        assert!(out.arrays[map].is_empty(), "{map}");
    }
    for map in c::LPM_MAPS {
        assert!(out.lpm[map].is_empty(), "{map}");
    }
}

fn drop_policy(key: &str, data: Value) -> c::Policy {
    pol(key, with(json!({"protocol": "tcp", "default_action": "drop"}), data))
}

fn warning_ids(policies: &[c::Policy], trusted: &[c::Cidr], ct: bool) -> Vec<String> {
    c::find_warnings(policies, trusted, ct).into_iter().map(|w| w.id).collect()
}

#[test]
fn warnings_name_drop_policies_that_lock_out_or_drop_replies() {
    let trusted = [cidr("192.0.2.10")];
    let ids = |policies: &[c::Policy], t: &[c::Cidr]| warning_ids(policies, t, false);
    // Management ports, unless a trusted source still gets through.
    assert_eq!(ids(&[drop_policy("ssh", json!({"ports": ["22"]}))], &[]), ["lockout:ssh"]);
    assert!(ids(&[drop_policy("ssh", json!({"ports": ["22"]}))], &trusted).is_empty());
    assert_eq!(ids(&[drop_policy("web", json!({"ports": ["8000-8100"]}))], &[]), ["lockout:web"]);
    let web = c::find_warnings(&[drop_policy("web", json!({"ports": ["8000-8100"]}))], &[], false);
    let message = &web[0].message;
    assert!(message.find("8006").is_some_and(|at| message[at..].contains("8080")), "{message}");
    assert!(ids(&[drop_policy("dns", json!({"protocol": "udp", "ports": ["22"]}))], &[]).is_empty());
    assert!(ids(&[drop_policy("open", json!({"ports": ["22"], "default_action": "allow"}))], &[]).is_empty());
    // Reply ports: any port in the NAT pool, ranges in the ephemeral ports.
    assert_eq!(ids(&[drop_policy("game", json!({"ports": ["25565"]}))], &trusted), ["reply_ports:game"]);
    assert!(ids(&[drop_policy("wg", json!({"protocol": "udp", "ports": ["51820"]}))], &[]).is_empty());
    assert_eq!(ids(&[drop_policy("high", json!({"protocol": "udp", "ports": ["40000-40010"]}))], &[]), ["reply_ports:high"]);
    assert!(ids(&[drop_policy("low", json!({"ports": ["1000-19999"]}))], &trusted).is_empty());
    let all = c::find_warnings(&[drop_policy("all", json!({"ports": ["1-65535"]}))], &[], false);
    assert_eq!(all.iter().map(|w| w.id.as_str()).collect::<Vec<_>>(), ["lockout:all", "reply_ports:all"]);
    let text = &all[1].message;
    let nat = text.find("20000-32767 在 Veer 出向 NAT").expect(text);
    assert!(text[nat..].contains("32768-60999 在宿主"), "{text}");
}

#[test]
fn the_warnings_token_follows_the_warnings_not_their_order() {
    let one = c::find_warnings(&[drop_policy("ssh", json!({"ports": ["22"]}))], &[], false);
    let two = c::find_warnings(&[drop_policy("ssh", json!({"ports": ["22"]})), drop_policy("game", json!({"ports": ["25565"]}))], &[], false);
    assert_eq!(c::warnings_token(&[]), "");
    let token = c::warnings_token(&one);
    assert!(token.len() == 8 && token.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{token}");
    assert_ne!(c::warnings_token(&one), c::warnings_token(&two));
    let mut reversed = two.clone();
    reversed.reverse();
    assert_eq!(c::warnings_token(&two), c::warnings_token(&reversed));
}

#[test]
fn sum_per_cpu_adds_little_endian_u64_counters() {
    assert_eq!(c::sum_per_cpu(&json!(["0100000000000000", "ff00000000000000", "0001000000000000"])), 512);
    assert_eq!(c::sum_per_cpu(&Value::Null), 0);
}

#[test]
fn syn_limit_is_validated_defaulted_and_only_allowed_with_tcp() {
    let limited = |limit: Value, protocol: &str| {
        let mut data = json!({"protocol": protocol, "ports": ["22"], "default_action": "allow"});
        if !limit.is_null() {
            data["syn_limit"] = limit;
        }
        c::normalize_policy("p", &data, None)
    };
    let limit = |max_new, window_seconds, ban_seconds, ipv6_prefix| Some(c::SynLimit { max_new, window_seconds, ban_seconds, ipv6_prefix });
    assert_eq!(limited(json!({"max_new": 20, "window_seconds": 10}), "tcp").unwrap().syn_limit, limit(20, 10, 0, 64));
    assert_eq!(
        limited(json!({"max_new": 5, "window_seconds": 1, "ban_seconds": 600, "ipv6_prefix": 56}), "tcp+udp").unwrap().syn_limit,
        limit(5, 1, 600, 56)
    );
    assert_eq!(limited(Value::Null, "tcp").unwrap().syn_limit, None);
    assert!(err_of(limited(json!({"max_new": 5, "window_seconds": 1}), "udp")).contains("只限制 TCP"));
    assert!(err_of(limited(json!({"max_new": 0, "window_seconds": 1}), "tcp")).contains("max_new"));
    assert!(err_of(limited(json!({"max_new": 5}), "tcp")).contains("window_seconds"));
    assert!(err_of(limited(json!({"max_new": 5, "window_seconds": 1, "ipv6_prefix": 16}), "tcp")).contains("ipv6_prefix"));
    assert!(err_of(limited(json!({"max_new": 1.5, "window_seconds": 1}), "tcp")).contains("max_new"));
}

#[test]
fn prefix_masks_cover_whole_and_partial_bytes() {
    assert_eq!(c::prefix_mask_hex(64), "ff".repeat(8) + &"00".repeat(8));
    assert_eq!(c::prefix_mask_hex(60), "ff".repeat(7) + "f0" + &"00".repeat(8));
    assert_eq!(c::prefix_mask_hex(128), "ff".repeat(16));
    assert_eq!(c::prefix_mask_hex(32), "ff".repeat(4) + &"00".repeat(12));
}

#[test]
fn a_limited_policy_sets_its_flag_and_writes_fw_limit() {
    let mut ssh = pol(
        "ssh",
        json!({"protocol": "tcp", "ports": ["22"], "default_action": "allow", "syn_limit": {"max_new": 20, "window_seconds": 10, "ban_seconds": 300, "ipv6_prefix": 60}}),
    );
    let mut web = pol("web", json!({"protocol": "tcp", "ports": ["443"], "default_action": "allow"}));
    ssh.slot = 3;
    web.slot = 4;
    let out = c::compile_generation(&[ssh, web], &[], 1, &no_sets(), &c::Settings::default()).unwrap();
    assert_eq!(out.arrays["fw_policy"][&(256 + 3)], "03000000");
    assert_eq!(out.arrays["fw_policy"][&(256 + 4)], "01000000");
    let expected = c::u32le(20) + &c::u32le(10) + &c::u32le(300) + "3c000000" + &c::prefix_mask_hex(60);
    assert_eq!(out.arrays["fw_limit"][&(256 + 3)], expected);
    assert_eq!(out.arrays["fw_limit"][&(256 + 3)].len(), c::limit_value_zero().len());
    assert!(!out.arrays["fw_limit"].contains_key(&(256 + 4)));
    assert_eq!(out.summary["syn_limited"], json!(1));
}

fn limit_key_hex(family: u64, prefix: u64, slot: u64, addr_hex: &str) -> String {
    c::u8h(family) + &c::u8h(prefix) + &c::u16le(slot) + &(addr_hex.to_string() + &"0".repeat(32))[..32]
}

fn padded(addr_hex: &str) -> String {
    (addr_hex.to_string() + &"0".repeat(32))[..32].to_string()
}

#[test]
fn ban_keys_ban_ends_and_drop_events_decode() {
    let key = c::decode_limit_key(&limit_key_hex(4, 32, 3, "cb007105")).unwrap();
    assert_eq!((key.family, key.prefix, key.slot, key.source.as_str()), (4, 32, 3, "203.0.113.5/32"));
    let key = c::decode_limit_key(&limit_key_hex(6, 64, 1, "20010db8000000010000000000000000")).unwrap();
    assert_eq!((key.family, key.prefix, key.slot, key.source.as_str()), (6, 64, 1, "2001:db8:0:1::/64"));
    assert!(c::decode_limit_key(&"00".repeat(20)).is_none());
    assert_eq!(c::decode_ban_until_ms("00f2052a01000000"), 5000.0);

    let ev = c::u32le(2000000) + &c::u32le(0) + &c::u32le(7) + &c::u16le(3) + &c::u8h(3) + &c::u8h(4) + &c::u8h(0) + "00" + "9c40" + "0016" + "0000"
        + &padded("cb007105")
        + &padded("0a000001");
    assert_eq!(ev.len(), c::EVENT_BYTES * 2);
    assert_eq!(
        c::decode_event(&ev).unwrap(),
        json!({"time_ms": 2, "ifindex": 7, "slot": 3, "reason": "rate", "protocol": "tcp", "source_port": 40000, "port": 22,
            "source": "203.0.113.5", "destination": "10.0.0.1"})
    );
    assert!(c::decode_event("00").is_none());
}

#[test]
fn icmp_types_ip_protocols_and_catch_all_policies_normalize() {
    assert_eq!(c::parse_icmp_types(&Value::Null, false, "p").unwrap(), vec![(0, 65535)]);
    assert_eq!(c::parse_icmp_types(&json!(["echo-request", "3/4", "0"]), false, "p").unwrap(), vec![(0, 255), (772, 772), (2048, 2303)]);
    assert_eq!(c::parse_icmp_types(&json!(["echo-request"]), true, "p").unwrap(), vec![(128 * 256, 128 * 256 + 255)]);
    assert!(err_of(c::parse_icmp_types(&json!(["nope"]), false, "p")).contains("ICMP 类型无效"));
    assert!(err_of(c::parse_icmp_types(&json!(["3/300"]), false, "p")).contains("代码无效"));
    assert_eq!(c::parse_ip_protocols(&json!(["gre", 50]), "p").unwrap(), vec![(47 * 256, 47 * 256 + 255), (50 * 256, 50 * 256 + 255)]);
    assert!(err_of(c::parse_ip_protocols(&json!([6]), "p")).contains("tcp"));
    assert!(err_of(c::parse_ip_protocols(&json!([]), "p")).contains("至少"));

    let icmp = pol("ping", json!({"protocol": "icmp", "icmp_types": ["echo-request"]}));
    assert_eq!(icmp.matches.keys().copied().collect::<Vec<_>>(), vec![2]);
    assert!(icmp.ranges.is_empty());
    let any = pol("all", json!({"protocol": "any", "default_action": "drop"}));
    assert!(any.any);
    assert!(any.matches.is_empty());
    let fails = |data: Value, text: &str| {
        let message = err_of(c::normalize_policy("x", &data, None));
        assert!(message.contains(text), "{message}");
    };
    fails(json!({"protocol": "any", "ports": ["22"]}), "不能带端口");
    fails(json!({"protocol": "icmp", "ip_protocols": [47]}), "按类型匹配");
    fails(json!({"protocol": "sctp"}), "协议必须是");
    // syn_limit and tcp_new_only need TCP, which a catch-all policy covers.
    assert!(pol("x", json!({"protocol": "any", "tcp_new_only": true})).new_only);
    assert!(pol("x", json!({"protocol": "any", "syn_limit": {"max_new": 5, "window_seconds": 1}})).syn_limit.is_some());
    fails(json!({"protocol": "udp", "ports": ["53"], "tcp_new_only": true}), "只作用于 TCP");
    fails(json!({"protocol": "icmp", "syn_limit": {"max_new": 5, "window_seconds": 1}}), "只限制 TCP");
}

#[test]
fn conflicts_cover_icmp_types_ip_protocols_and_catch_all_policies() {
    let p = pol;
    assert!(c::find_conflicts(&[p("a", json!({"protocol": "icmp", "icmp_types": ["8"]})), p("b", json!({"protocol": "icmp", "icmp_types": ["0"]}))]).is_empty());
    let found = c::find_conflicts(&[p("a", json!({"protocol": "icmp"})), p("b", json!({"protocol": "icmp", "icmp_types": ["3/4"]}))]);
    assert!(found[0].contains("icmp 类型 3/4"), "{found:?}");
    assert!(c::find_conflicts(&[p("a", json!({"protocol": "icmp"})), p("b", json!({"protocol": "icmpv6"}))]).is_empty());
    let found = c::find_conflicts(&[p("a", json!({"protocol": "ip", "ip_protocols": ["gre"]})), p("b", json!({"protocol": "ip", "ip_protocols": [47, 50]}))]);
    assert!(found[0].contains("IP 协议 47"), "{found:?}");
    // A catch-all policy never conflicts with a specific one, only with another catch-all.
    assert!(c::find_conflicts(&[p("a", json!({"protocol": "any"})), p("b", json!({"ports": ["22"]}))]).is_empty());
    assert_eq!(c::find_conflicts(&[p("a", json!({"protocol": "any"})), p("b", json!({"protocol": "any"}))]).len(), 1);
    assert!(c::find_conflicts(&[
        p("a", json!({"protocol": "any", "destinations": ["10.0.0.1"]})),
        p("b", json!({"protocol": "any", "destinations": ["10.0.0.2"]}))
    ])
    .is_empty());
}

#[test]
fn sources_may_name_sets_and_add_to_set_defaults_its_timeout() {
    let p = pol_sets(
        "p",
        json!({"ports": ["22"], "sources": [{"set": "office", "action": "allow"}, {"cidr": "10.0.0.0/8", "action": "drop"}], "add_to_set": {"set": "scanners"}}),
        &["office", "scanners"],
    )
    .unwrap();
    assert_eq!(p.source_sets, vec![c::SourceSet { set: "office".to_string(), action: c::ACTION_PASS }]);
    assert_eq!(p.sources.len(), 1);
    assert_eq!(p.add_to_set, Some(c::AddToSet { set: "scanners".to_string(), seconds: 3600, ipv6_prefix: 64 }));
    let fails = |data: Value, sets: &[&str], text: &str| {
        let message = err_of(pol_sets("p", data, sets));
        assert!(message.contains(text), "{message}");
    };
    fails(json!({"ports": ["22"], "sources": [{"set": "gone", "action": "allow"}]}), &["office"], "不存在");
    fails(json!({"ports": ["22"], "sources": [{"set": "office", "cidr": "1.2.3.4", "action": "allow"}]}), &["office"], "之一");
    fails(json!({"ports": ["22"], "sources": [{"set": "office", "action": "allow"}, {"set": "office", "action": "drop"}]}), &["office"], "重复");
    let five = ["a", "b", "c", "d", "e"];
    let sources: Vec<Value> = five.iter().map(|s| json!({"set": s, "action": "allow"})).collect();
    fails(json!({"ports": ["22"], "sources": sources}), &five, "最多 4");
    fails(json!({"ports": ["22"], "add_to_set": {"set": "scanners", "timeout_seconds": 99999999}}), &["scanners"], "timeout_seconds");
}

#[test]
fn warnings_follow_connection_tracking_tcp_new_only_and_catch_all_policies() {
    let ids = |policies: &[c::Policy], ct: bool| warning_ids(policies, &[], ct);
    let game = drop_policy("game", json!({"ports": ["25565"]}));
    assert_eq!(ids(&[game.clone()], false), ["reply_ports:game"]);
    assert!(ids(&[game], true).is_empty());
    // Tracking never records UDP flows from covered ports: the warning stays.
    let udp_high = drop_policy("udphigh", json!({"protocol": "udp", "ports": ["1024-65535"]}));
    assert_eq!(ids(&[udp_high.clone()], true), ["reply_ports:udphigh"]);
    assert!(c::find_warnings(&[udp_high], &[], true)[0].message.contains("连接跟踪不记录"));
    assert_eq!(ids(&[drop_policy("both", json!({"protocol": "tcp+udp", "ports": ["25565"]}))], true), ["reply_ports:both"]);
    assert!(ids(&[drop_policy("game", json!({"ports": ["25565"], "tcp_new_only": true}))], false).is_empty());
    assert_eq!(ids(&[drop_policy("both", json!({"protocol": "tcp+udp", "ports": ["25565"], "tcp_new_only": true}))], false), ["reply_ports:both"]);
    let all = pol("all", json!({"protocol": "any", "default_action": "drop"}));
    assert_eq!(ids(&[all.clone()], false), ["lockout:all", "reply_all:all"]);
    assert_eq!(ids(&[all.clone()], true), ["lockout:all"]);
    // A port policy that allows the management ports decides them instead.
    let mgmt = pol("mgmt", json!({"ports": ["22", "8006", "8080"], "default_action": "allow"}));
    assert!(ids(&[all, mgmt], true).is_empty());
    assert!(c::find_warnings(&[drop_policy("ssh", json!({"ports": ["22"], "tcp_new_only": true}))], &[], false)[0].message.contains("只判新连接"));
}

#[test]
fn fw_pext_and_fw_gcfg_carry_the_new_policy_and_global_settings() {
    let mut ssh = pol_sets(
        "ssh",
        json!({"ports": ["22"], "tcp_new_only": true, "sources": [{"set": "office", "action": "allow"}, {"set": "bad", "action": "drop"}],
            "add_to_set": {"set": "scanners", "timeout_seconds": 600, "ipv6_prefix": 56}}),
        &["office", "bad", "scanners"],
    )
    .unwrap();
    ssh.slot = 2;
    let mut ping = pol("ping", json!({"protocol": "icmp", "icmp_types": ["echo-request"], "default_action": "allow"}));
    ping.slot = 3;
    let mut all = pol("all", json!({"protocol": "any", "default_action": "drop"}));
    all.slot = 4;
    let set_ids = BTreeMap::from([("office".to_string(), 1), ("bad".to_string(), 2), ("scanners".to_string(), 3), ("deny".to_string(), 4)]);
    let settings = c::Settings {
        connection_tracking: true,
        blocklists: strings(&["deny"]),
        baseline: c::Baseline { bogon_sources: "all".to_string(), invalid_tcp_flags: true, drop_fragments: false, urpf: "strict".to_string() },
        ..c::Settings::default()
    };
    let out = c::compile_generation(&[ssh, ping, all], &[], 0, &set_ids, &settings).unwrap();
    // flags 3 (new only + add to set), 2 sets, add set 3 for 600 s, sets 1 and 2 (allow, drop), /56.
    let pext = c::hex_byte(3) + "02" + "0300" + &c::u32le(600) + "0100" + "0200" + "0000" + "0000" + "00010000" + "38000000" + &c::prefix_mask_hex(56);
    assert_eq!(out.arrays["fw_pext"][&2], pext);
    assert_eq!(out.arrays["fw_pext"][&2].len(), c::pext_value_zero().len());
    assert!(!out.arrays["fw_pext"].contains_key(&3));
    // ICMP echo request: proto 2, type 8 /8 -> the ICMP policy's class.
    assert_eq!(lpm_map(&out, "fw_ports")["1800000000020800"], c::u32le(2));
    // gcfg: CT | BOGON | BAD_FLAGS | URPF_STRICT | PROTO = 1+2+4+32+64, catch-all class 3, one blocklist (set 4).
    assert_eq!(out.arrays["fw_gcfg"][&0], c::u32le(103) + &c::u16le(3) + "01" + "00" + "0400" + "0000" + "0000" + "0000");
    assert_eq!(out.arrays["fw_class"][&3], "04000000");
    assert_eq!(out.summary["catch_all"], json!(1));
    let gone = c::Settings { blocklists: strings(&["gone"]), ..c::Settings::default() };
    assert!(err_of(c::compile_generation(&[], &[], 0, &no_sets(), &gone)).contains("集合不存在"));
}

fn baseline(bogons: &str) -> c::Baseline {
    c::Baseline { bogon_sources: bogons.to_string(), urpf: "off".to_string(), ..c::Baseline::default() }
}

#[test]
fn sets_compile_to_fw_sets_entries_with_stable_ids_and_keys_decode() {
    let mut office = c::normalize_set("office", &json!({"elements": ["203.0.113.0/24", "2001:db8::/32"]})).unwrap();
    office.id = 5;
    let entries = c::compile_sets(&[office], &baseline("off")).unwrap();
    let expected = BTreeMap::from([
        ("38000000".to_string() + "04" + "00" + "0005" + "cb007100" + &"0".repeat(24), c::set_value(0.0, c::SET_KIND_STATIC)),
        ("40000000".to_string() + "06" + "00" + "0005" + "20010db8" + &"0".repeat(24), c::set_value(0.0, c::SET_KIND_STATIC)),
    ]);
    assert_eq!(entries, expected);
    assert_eq!(c::set_value(0.0, 1), "0000000000000000".to_string() + "01000000" + "00000000");
    assert_eq!(c::u64le_ns_from_ms(5000.0), "00f2052a01000000");
    let key = c::decode_set_key(&c::set_key(5, &cidr("203.0.113.0/24"))).unwrap();
    assert_eq!((key.id, key.family, key.prefix, key.cidr.as_str()), (5, 4, 24, "203.0.113.0/24"));
    let value = c::decode_set_value(&c::set_value(5000.0, c::SET_KIND_API)).unwrap();
    assert_eq!((value.expires_ms, value.kind), (5000.0, "api"));
    let reserved = c::compile_sets(&[], &baseline("reserved")).unwrap().len();
    assert_eq!(reserved, c::BOGONS_RESERVED.len());
    let all = c::compile_sets(&[], &baseline("all")).unwrap();
    assert_eq!(all.len(), reserved + c::BOGONS_PRIVATE.len());
    for key in all.keys() {
        assert_eq!(c::decode_set_key(key).unwrap().id, c::SET_BOGON as u64);
    }
    assert!(err_of(c::normalize_set("Bad Name", &json!({}))).contains("集合名无效"));
    assert!(err_of(c::normalize_set("dup", &json!({"elements": ["1.2.3.4", "1.2.3.4/32"]}))).contains("重复"));

    let first = c::assign_set_ids(&strings(&["a", "b"]), &BTreeMap::new()).unwrap();
    assert_eq!(first.ids, BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)]));
    let second = c::assign_set_ids(&strings(&["b", "c"]), &first.ids).unwrap();
    assert_eq!(second.ids, BTreeMap::from([("b".to_string(), 2), ("c".to_string(), 3)]));
    assert_eq!(second.fresh, vec![3]);
}

fn event_with(reason: u64, proto: u64, sport: &str, dport: &str) -> String {
    c::u32le(0) + &c::u32le(0) + &c::u32le(2) + &c::u16le(0) + &c::u8h(reason) + &c::u8h(4) + &c::u8h(proto) + "00" + sport + dport + "0000"
        + &padded("cb007105")
        + &padded("0a000001")
}

#[test]
fn drop_events_decode_icmp_other_protocols_and_the_new_reasons() {
    let icmp = c::decode_event(&event_with(5, 2, "1234", "0800")).unwrap();
    assert_eq!(icmp["reason"], "blocklist");
    assert_eq!(icmp["protocol"], "icmp");
    assert_eq!(icmp["icmp_type"], 8);
    assert_eq!(icmp["icmp_code"], 0);
    assert_eq!(icmp["port"], 0);
    let gre = c::decode_event(&event_with(6, 4, "0000", "2f00")).unwrap();
    assert_eq!(gre["reason"], "bogon");
    assert_eq!(gre["protocol"], "ip");
    assert_eq!(gre["ip_protocol"], 47);
    assert_eq!(c::decode_event(&event_with(9, 0, "0001", "0016")).unwrap()["reason"], "fragment");
}

// ------------------------------------------------------------ control

const TC_EGRESS: &str = "dataplane.xdp_tc_egress.v1";
const ALL_FEATURES: [&str; 3] = ["dataplane.xdp_pipeline.v1", "dataplane.xdp_tc_fallback.v1", TC_EGRESS];

type Maps = Arc<Mutex<BTreeMap<String, BTreeMap<String, String>>>>;
type Counters = Arc<Mutex<Box<dyn Fn(&str) -> Vec<String> + Send>>>;

fn links() -> Value {
    json!([
        {"name": "eth0", "ifindex": 2, "kind": "device", "mac": "02:00:00:00:00:02", "up": true},
        {"name": "eth1", "ifindex": 3, "kind": "device", "mac": "02:00:00:00:00:03", "up": true},
        {"name": "vmbr0", "ifindex": 4, "kind": "bridge", "mac": "02:00:00:00:00:04", "up": true},
        {"name": "wg0", "ifindex": 5, "kind": "wireguard", "mac": "", "up": true},
    ])
}

/// The firewall on a fake host whose eBPF maps are plain key/value maps.
struct Env {
    h: Harness<Firewall>,
    maps: Maps,
    counters: Counters,
    mono: Arc<Mutex<Option<f64>>>,
}

fn arg(args: &[Value], index: usize) -> String {
    args.get(index).map(js::string).unwrap_or_default().to_lowercase()
}

impl Env {
    fn new(resources: Value) -> Env {
        Self::with_features(resources, &ALL_FEATURES)
    }

    fn with_features(resources: Value, features: &[&str]) -> Env {
        let fake = FakeHost::new();
        fake.set_available_features(features);
        for (resource, records) in resources.as_object().cloned().unwrap_or_default() {
            for (key, record) in records.as_object().cloned().unwrap_or_default() {
                fake.put_record(&resource, &key, record["data"].clone(), !js::is_false(&record["enabled"]));
            }
        }
        let maps: Maps = Arc::default();
        let counters: Counters = Arc::new(Mutex::new(Box::new(|_| vec!["0000000000000000".to_string()])));
        let mono = Arc::new(Mutex::new(Some(1_000_000.0)));
        fake.adapter("net.link.get", |args| {
            let name = args.first().map(js::string).unwrap_or_default();
            Ok(js::array(&links()).into_iter().find(|link| link["name"] == json!(name)).unwrap_or(Value::Null))
        });
        fake.adapter("net.link.list", |_| Ok(links()));
        let m = maps.clone();
        fake.adapter("ebpf.mapGet", move |args| {
            Ok(m.lock().unwrap().get(&arg(args, 1)).and_then(|map| map.get(&arg(args, 2))).map(|v| json!(v)).unwrap_or(Value::Null))
        });
        let m = maps.clone();
        fake.adapter("ebpf.mapPut", move |args| {
            m.lock().unwrap().entry(arg(args, 1)).or_default().insert(arg(args, 2), arg(args, 3));
            Ok(Value::Null)
        });
        let m = maps.clone();
        fake.adapter("ebpf.mapDelete", move |args| {
            if let Some(map) = m.lock().unwrap().get_mut(&arg(args, 1)) {
                map.remove(&arg(args, 2));
            }
            Ok(Value::Null)
        });
        let m = maps.clone();
        fake.adapter("ebpf.mapTransaction", move |args| {
            let ops = js::array(&args[0]["operations"]);
            if ops.is_empty() || ops.len() > 256 {
                return Err("ebpf.mapTransaction operation count must be between 1 and 256".to_string());
            }
            let mut maps = m.lock().unwrap();
            for op in ops {
                let map = maps.entry(js::string(&op["map"])).or_default();
                let key = js::string(&op["key"]).to_lowercase();
                match op["op"].as_str() {
                    Some("put") => {
                        map.insert(key, js::string(&op["value"]).to_lowercase());
                    }
                    Some("delete") => {
                        map.remove(&key);
                    }
                    other => return Err(format!("bad op {other:?}")),
                }
            }
            Ok(json!({"status": "committed"}))
        });
        let m = maps.clone();
        fake.adapter("ebpf.mapScan", move |args| {
            let options = &args[2];
            let limit = js::number(&options["limit"]).max(1.0) as usize;
            let cursor = js::string(js::or(&options["cursor"], &json!(""))).to_lowercase();
            let maps = m.lock().unwrap();
            let records: Vec<(String, String)> = maps.get(&arg(args, 1)).map(|map| map.clone().into_iter().collect()).unwrap_or_default();
            let start = if cursor.is_empty() { 0 } else { records.iter().position(|(key, _)| *key > cursor).unwrap_or(records.len()) };
            let entries: Vec<Value> = records[start..].iter().take(limit).map(|(key, value)| json!({"key": key, "value": value})).collect();
            let done = start + entries.len() >= records.len();
            let cursor = if done || entries.is_empty() { json!("") } else { entries[entries.len() - 1]["key"].clone() };
            Ok(json!({"entries": entries, "cursor": cursor, "done": done}))
        });
        let counter = counters.clone();
        fake.adapter("ebpf.mapGetPerCPU", move |args| Ok(json!((counter.lock().unwrap())(&arg(args, 2)))));
        let clock = mono.clone();
        fake.adapter("ebpf.monotonicMs", move |_| match *clock.lock().unwrap() {
            Some(ms) => Ok(js::num(ms)),
            None => Err("not supported".to_string()),
        });
        let h = Harness::load(concat!(env!("CARGO_MANIFEST_DIR"), "/plugin.json"), fake);
        Env { h, maps, counters, mono }
    }

    fn fake(&self) -> &FakeHost {
        &self.h.fake
    }

    fn act(&mut self, id: &str, payload: Value) -> Value {
        self.h.query(id, payload)
    }

    fn act_err(&mut self, id: &str, payload: Value) -> String {
        match self.h.action(id, payload) {
            Ok(outcome) => panic!("action {id} succeeded: {outcome:?}"),
            Err(err) => err.to_string(),
        }
    }

    fn reconcile(&mut self) {
        self.h.reconcile().unwrap();
    }

    fn fire(&mut self, timer: &str) {
        self.h.fire_timer(timer).unwrap();
    }

    fn map(&self, name: &str) -> BTreeMap<String, String> {
        self.maps.lock().unwrap().get(name).cloned().unwrap_or_default()
    }

    fn seed(&self, name: &str, entries: &[(&str, &str)]) {
        let mut maps = self.maps.lock().unwrap();
        let map = maps.entry(name.to_string()).or_default();
        for (key, value) in entries {
            map.insert(key.to_string(), value.to_string());
        }
    }

    fn clear_maps(&self) {
        self.maps.lock().unwrap().clear();
    }

    /// (generation, flags) from fw_cfg.
    fn cfg(&self) -> Option<(u64, u64)> {
        let hex = self.map("fw_cfg").get("00000000")?.clone();
        Some((c::hex_u32le(&hex, 0), c::hex_u32le(&hex, 8)))
    }

    fn generation(&self) -> u32 {
        self.cfg().expect("fw_cfg is written").0 as u32
    }

    fn keys_of(&self, name: &str, generation: u32) -> Vec<String> {
        self.map(name).into_keys().filter(|key| c::key_generation(key) == generation).collect()
    }

    fn state(&self) -> Value {
        self.fake().kv("state").map(|record| record["data"].clone()).unwrap_or(Value::Null)
    }

    fn set_policy(&self, key: &str, data: Value) {
        self.fake().put_record("policies", key, with(json!({"protocol": "tcp", "default_action": "drop"}), data), true);
    }

    fn set_settings(&self, data: Value) {
        self.fake().put_record("settings", "default", data, true);
    }

    fn binding(&self) -> Value {
        self.fake().record("hook_bindings", "wan-filter").unwrap_or(Value::Null)
    }

    fn snapshot(&self, name: &str) -> Value {
        self.fake().data("snapshots", name)
    }

    fn timer(&self, name: &str) -> Option<Value> {
        self.fake().timer(name)
    }

    /// (id, cidr, kind) of every fw_sets entry, by id then cidr.
    fn set_entries(&self) -> Vec<(u64, String, String)> {
        let mut out: Vec<(u64, String, String)> = self
            .map("fw_sets")
            .iter()
            .map(|(key, value)| {
                let key = c::decode_set_key(key).unwrap();
                (key.id, key.cidr, c::decode_set_value(value).unwrap().kind.to_string())
            })
            .collect();
        out.sort();
        out
    }
}

fn policy(data: Value) -> Value {
    json!({"data": with(json!({"protocol": "tcp", "default_action": "drop"}), data), "enabled": true})
}

fn ssh() -> Value {
    policy(json!({"name": "SSH", "ports": ["22"], "sources": [{"cidr": "198.51.100.0/24", "action": "allow"}]}))
}

fn settings_data() -> Value {
    json!({"interfaces": ["eth0"], "trusted_sources": ["192.0.2.10"], "confirm_timeout_seconds": 60})
}

fn settings() -> Value {
    json!({"data": settings_data()})
}

fn settings_with(extra: Value) -> Value {
    json!({"data": with(settings_data(), extra)})
}

fn basic() -> Env {
    Env::new(json!({"policies": {"ssh": ssh()}, "settings": {"default": settings()}}))
}

#[test]
fn apply_writes_the_inactive_generation_binds_the_hook_and_waits() {
    let mut env = basic();
    env.act("apply", json!({}));
    assert_eq!(env.cfg(), Some((1, 2 | 4)));
    let binding = env.binding();
    assert_eq!(binding["data"], json!({"hook_id": "wan-filter", "interfaces": ["eth0"], "tc_egress": false}));
    assert_eq!(binding["enabled"], true);
    assert_eq!(env.keys_of("fw_ports", 1).len(), 1);
    assert_eq!(env.keys_of("fw_src4", 1), strings(&["3800000001000001c6336400", "4000000001000000c000020a"]));
    assert!(js::truthy(&env.state()["pending"]));
    assert_eq!(env.timer("confirm_deadline").unwrap()["delay_ms"], 60000);
    assert!(env.fake().dataplane_reconciles() >= 1);

    env.act("confirm", json!({}));
    assert!(env.state()["pending"].is_null());
    assert!(env.timer("confirm_deadline").is_none());
    assert_eq!(env.snapshot("confirmed"), env.snapshot("applied"));
}

#[test]
fn apply_refuses_while_an_earlier_apply_waits_and_on_invalid_drafts() {
    let mut env = basic();
    env.act("apply", json!({}));
    assert!(env.act_err("apply", json!({})).contains("等待确认"));
    env.act("confirm", json!({}));
    env.set_policy("dup", json!({"name": "dup", "ports": ["22"]}));
    let before = env.state();
    assert!(env.act_err("apply", json!({})).contains("作用于相同的目标地址"));
    assert_eq!(env.state(), before);
    env.set_policy("dup", json!({"name": "dup", "ports": ["22"], "sources": [{"cidr": "nonsense", "action": "allow"}]}));
    assert!(env.act_err("apply", json!({})).contains("地址无效"));
    assert_eq!(env.generation(), 1);
}

#[test]
fn the_deadline_restores_the_confirmed_rule_set_and_its_interfaces() {
    let mut env = basic();
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    // A new draft: another port and another interface, never confirmed.
    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    env.set_settings(with(settings_data(), json!({"interfaces": ["eth0", "eth1"]})));
    env.act("apply", json!({}));
    assert_eq!(env.generation(), 0);
    assert_eq!(env.binding()["data"]["interfaces"], json!(["eth0", "eth1"]));
    assert_eq!(env.keys_of("fw_ports", 0).len(), 2);

    env.fire("confirm_deadline");
    let st = env.state();
    assert!(st["pending"].is_null());
    assert_eq!(st["rollback_reason"], "deadline");
    assert_eq!(env.generation(), 1);
    assert_eq!(env.binding()["data"]["interfaces"], json!(["eth0"]));
    assert_eq!(env.snapshot("applied"), env.snapshot("confirmed"));
    // Generation 1 holds only the confirmed policy again.
    assert_eq!(env.keys_of("fw_ports", 1).len(), 1);
}

#[test]
fn rewriting_a_generation_removes_what_the_older_rule_set_left_there() {
    let web = policy(json!({"name": "web", "ports": ["8443"], "sources": [{"cidr": "10.0.0.0/8", "action": "allow"}]}));
    let mut env = Env::new(json!({"policies": {"ssh": ssh(), "web": web}, "settings": {"default": settings()}}));
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    let word8443 = c::u32le((c::PORT_WORDS_PER_GEN + (8443 >> 6)) as u64);
    assert_ne!(env.map("fw_port_bits")[&word8443], "0000000000000000");
    env.fake().delete_record("policies", "web");
    env.act("apply", json!({})); // generation 0
    env.act("confirm", json!({}));
    env.act("apply", json!({})); // generation 1 again, without web
    env.act("confirm", json!({}));
    assert_eq!(env.generation(), 1);
    assert_eq!(env.map("fw_port_bits")[&word8443], "0000000000000000");
    assert_eq!(env.keys_of("fw_ports", 1).len(), 1);
    assert!(!env.keys_of("fw_src4", 1).iter().any(|key| key.ends_with("0a000000")));
}

/// Applies the draft the way the page does once the user accepts its warnings.
fn apply_accepting(env: &mut Env) {
    let check = env.act("check", json!({}));
    assert_eq!(check["errors"], json!([]));
    let token = js::string(&check["token"]);
    env.act("apply", if token.is_empty() { json!({}) } else { json!({"accept_warnings": token}) });
}

fn ids_of(warnings: &Value) -> Vec<String> {
    js::array(warnings).iter().map(|w| js::string(&w["id"])).collect()
}

#[test]
fn apply_needs_the_warnings_the_check_reported_accepted_and_only_those() {
    let mut env = Env::new(json!({"policies": {"ssh": ssh()}, "settings": {"default": {"data": {"interfaces": ["eth0"]}}}}));
    let check = env.act("check", json!({}));
    assert_eq!(check["errors"], json!([]));
    assert_eq!(ids_of(&check["warnings"]), ["lockout:ssh"]);
    assert!(env.act_err("apply", json!({})).contains("应用前需要确认"));
    assert_eq!(env.cfg(), None);
    // The draft changed after the check: the old token does not cover it.
    env.set_policy("high", json!({"name": "high", "protocol": "udp", "ports": ["40000-40100"]}));
    assert!(env.act_err("apply", json!({"accept_warnings": check["token"]})).contains("应用前需要确认"));
    let again = env.act("check", json!({}));
    assert_eq!(ids_of(&again["warnings"]), ["reply_ports:high", "lockout:ssh"]);
    env.act("apply", json!({"accept_warnings": again["token"]}));
    assert!(js::truthy(&env.state()["pending"]));
    assert_eq!(env.cfg().unwrap().1 & 2, 2);
}

#[test]
fn check_reports_draft_errors_and_writes_nothing() {
    let mut env = basic();
    env.set_policy("dup", json!({"name": "dup", "ports": ["22"]}));
    env.set_policy("bad", json!({"name": "bad", "ports": ["70000"]}));
    let check = env.act("check", json!({}));
    let errors: Vec<String> = js::array(&check["errors"]).iter().map(js::string).collect();
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors.iter().any(|e| e.contains("端口无效")));
    assert!(errors.iter().any(|e| e.contains("作用于相同的目标地址")));
    assert_eq!(check["warnings"], json!([]));
    assert_eq!(check["token"], "");
    assert_eq!(env.cfg(), None);
    assert!(env.binding().is_null());
}

#[test]
fn an_l3_interface_is_marked_so_the_program_skips_ethernet_parsing() {
    let mut env = Env::new(json!({"policies": {"ssh": ssh()}, "settings": {"default": {"data": {"interfaces": ["eth0", "wg0"]}}}}));
    apply_accepting(&mut env);
    assert_eq!(env.cfg().unwrap().1 & 1, 1);
    assert_eq!(env.map("fw_ifaces"), BTreeMap::from([("05000000".to_string(), "01000000".to_string())]));
}

#[test]
fn after_a_restart_the_applied_rule_set_returns_an_unconfirmed_one_does_not() {
    let mut env = basic();
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    env.clear_maps(); // a new Veer process starts the plugin with empty maps
    env.reconcile();
    assert_eq!(env.cfg().unwrap().1 & 4, 4);
    assert_eq!(env.keys_of("fw_ports", env.generation()).len(), 1);

    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    env.act("apply", json!({}));
    assert!(js::truthy(&env.state()["pending"]));
    env.clear_maps();
    env.reconcile();
    let st = env.state();
    assert!(st["pending"].is_null());
    assert_eq!(st["rollback_reason"], "restart");
    assert_eq!(env.keys_of("fw_ports", env.generation()).len(), 1);
}

#[test]
fn a_hot_restart_that_kept_the_maps_keeps_a_pending_apply_and_arms_its_deadline_again() {
    let mut env = basic();
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    env.act("apply", json!({}));
    let before = env.maps.lock().unwrap().clone();
    // The new process has the maps (the host handed them over) but no timers.
    env.fake().clear_timers();
    env.reconcile();
    assert!(js::truthy(&env.state()["pending"]), "the pending apply is still pending");
    let deadline = env.timer("confirm_deadline").expect("the deadline is armed again");
    let delay = js::number(&deadline["delay_ms"]);
    assert!(delay > 0.0 && delay <= 60000.0, "{deadline}");
    assert_eq!(*env.maps.lock().unwrap(), before, "kept maps are not rewritten");
    env.fire("confirm_deadline");
    assert_eq!(env.state()["rollback_reason"], "deadline");
    assert_eq!(env.keys_of("fw_ports", env.generation()).len(), 1);
}

#[test]
fn status_reports_counters_from_where_a_policy_started() {
    let mut env = basic();
    let packets = Arc::new(Mutex::new(5u64));
    let shared = packets.clone();
    *env.counters.lock().unwrap() = Box::new(move |_| vec![c::u32le(*shared.lock().unwrap()) + "00000000"]);
    env.act("apply", json!({}));
    *packets.lock().unwrap() = 12;
    let status = env.act("status", json!({}));
    assert_eq!(status["loaded"], true);
    assert_eq!(status["generation"], 1);
    assert!(js::number(&status["pending"]["remaining_seconds"]) > 0.0);
    assert_eq!(
        status["policies"],
        json!([{"key": "ssh", "name": "SSH", "slot": 1, "syn_limit": null,
            "counters": {"pass": 7, "drop": 7, "trusted": 7, "banned": 7, "rate_limited": 7}}])
    );
    assert_eq!(status["draft_changed"], false);
    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    assert_eq!(env.act("status", json!({}))["draft_changed"], true);
}

fn sorted_keys(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sorted_keys).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            // serde_json maps keep insertion order with preserve_order; rebuild sorted.
            Value::Object(keys.into_iter().map(|key| (key.clone(), sorted_keys(&map[key]))).collect())
        }
        other => other.clone(),
    }
}

#[test]
fn an_applied_draft_counts_as_unchanged_after_the_host_stores_it_canonically() {
    let mut env = basic();
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    // The real host keeps records as canonical JSON: keys come back sorted.
    for resource in ["snapshots", "policies", "settings", "hook_bindings"] {
        for record in env.fake().records(resource) {
            let key = js::string(&record["key"]);
            env.fake().edit_record(resource, &key, |data| *data = sorted_keys(data));
        }
    }
    assert_eq!(env.act("status", json!({}))["draft_changed"], false);
    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    assert_eq!(env.act("status", json!({}))["draft_changed"], true);
}

#[test]
fn interfaces_lists_bindable_links_and_flags_l3_ones() {
    let mut env = Env::new(json!({}));
    let list = env.act("interfaces", json!({}));
    let got: Vec<(String, bool)> = js::array(&list).iter().map(|l| (js::string(&l["name"]), l["l3"] == true)).collect();
    assert_eq!(got, vec![("eth0".into(), false), ("eth1".into(), false), ("vmbr0".into(), false), ("wg0".into(), true)]);
}

fn limited() -> Value {
    policy(json!({"name": "SSH", "ports": ["22"], "default_action": "allow", "syn_limit": {"max_new": 20, "window_seconds": 10, "ban_seconds": 300}}))
}

fn limit_key(slot: u64, addr: &str) -> String {
    limit_key_hex(4, 32, slot, addr)
}

#[test]
fn apply_writes_syn_limits_and_the_drop_log_rate() {
    let mut env = Env::new(json!({"policies": {"ssh": limited()}, "settings": {"default": settings()}}));
    env.act("apply", json!({}));
    let index = env.generation() as u64 * c::POLICIES_PER_GEN as u64 + 1;
    assert_eq!(env.map("fw_policy")[&c::u32le(index)], "03000000");
    assert_eq!(&env.map("fw_limit")[&c::u32le(index)][..24], c::u32le(20) + &c::u32le(10) + &c::u32le(300));
    // 10 events/s per CPU in bursts of 10: interval 0.1 s, tolerance 0.9 s.
    assert_eq!(env.map("fw_log_cfg")["00000000"], c::u32le(100000000) + "00000000" + &c::u32le(900000000) + "00000000");
    assert_eq!(env.act("status", json!({}))["policies"][0]["syn_limit"], json!({"max_new": 20, "window_seconds": 10, "ban_seconds": 300}));

    env.act("confirm", json!({}));
    env.set_settings(with(settings_data(), json!({"log_per_second": 0})));
    let mut data = limited()["data"].clone();
    data.as_object_mut().unwrap().remove("syn_limit");
    env.fake().put_record("policies", "ssh", data, true);
    env.act("apply", json!({}));
    let index = env.generation() as u64 * c::POLICIES_PER_GEN as u64 + 1;
    assert_eq!(env.map("fw_log_cfg")["00000000"], "00".repeat(16));
    assert_eq!(env.map("fw_policy")[&c::u32le(index)], "01000000");
    assert_eq!(env.map("fw_limit")[&c::u32le(index)], c::limit_value_zero());
}

#[test]
fn bans_list_with_their_policy_and_unban_lifts_one_a_policy_or_all() {
    let web = policy(json!({"name": "web", "ports": ["443"], "syn_limit": {"max_new": 5, "window_seconds": 1}}));
    let mut env = Env::new(json!({"policies": {"ssh": limited(), "web": web}, "settings": {"default": settings()}}));
    *env.mono.lock().unwrap() = Some(1000.0); // ms on the clock BPF ban ends use
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    let status = env.act("status", json!({}));
    let slot = |key: &str| js::array(&status["policies"]).iter().find(|p| p["key"] == key).map(|p| p["slot"].as_u64().unwrap()).unwrap();
    let a = limit_key(slot("ssh"), "cb007105");
    let b = limit_key(slot("ssh"), "cb007106");
    let w = limit_key(slot("web"), "cb007107");
    let expired = limit_key(slot("ssh"), "cb007108");
    // Bans end at 5000 ms; the expired one at 500 ms.
    env.seed("fw_ban", &[(&a, "00f2052a01000000"), (&b, "00f2052a01000000"), (&w, "00f2052a01000000"), (&expired, "0065cd1d00000000")]);
    env.seed("fw_rate", &[(&a, &"00".repeat(16))]);

    let page = env.act("bans", json!({}));
    assert_eq!(page["done"], true);
    assert_eq!(page["clock"], true);
    let mut items: Vec<Value> = js::array(&page["items"])
        .iter()
        .map(|i| json!([i["source"], i["policy"], i["policy_name"], i["remaining_seconds"]]))
        .collect();
    items.sort_by_key(|item| item.to_string());
    assert_eq!(
        items,
        vec![json!(["203.0.113.5/32", "ssh", "SSH", 4]), json!(["203.0.113.6/32", "ssh", "SSH", 4]), json!(["203.0.113.7/32", "web", "web", 4])]
    );
    // A host that cannot tell the time: every ban, no remaining time.
    *env.mono.lock().unwrap() = None;
    let blind = env.act("bans", json!({}));
    assert_eq!(blind["clock"], false);
    assert_eq!(js::array(&blind["items"]).len(), 4);
    assert!(js::array(&blind["items"]).iter().all(|i| i["remaining_seconds"].is_null()));
    *env.mono.lock().unwrap() = Some(1000.0);
    env.maps.lock().unwrap().get_mut("fw_ban").unwrap().remove(&expired);

    assert_eq!(env.act("unban", json!({"key": a})), json!({"removed": 1}));
    assert!(!env.map("fw_ban").contains_key(&a));
    assert!(!env.map("fw_rate").contains_key(&a), "the SYN count goes with the ban");
    assert_eq!(env.act("unban", json!({"policy": "ssh"})), json!({"removed": 1}));
    assert_eq!(env.map("fw_ban").into_keys().collect::<Vec<_>>(), vec![w]);
    assert_eq!(env.act("unban", json!({"all": true})), json!({"removed": 1}));
    assert!(env.map("fw_ban").is_empty());
    assert!(env.act_err("unban", json!({"key": "zz"})).contains("封禁记录无效"));
    assert!(env.act_err("unban", json!({"policy": "nope"})).contains("没有这条已应用的策略"));
    assert!(env.act_err("unban", json!({})).contains("需要 key、policy 或 all"));
}

#[test]
fn a_policy_that_takes_over_a_slot_starts_without_its_bans() {
    let mut env = Env::new(json!({"policies": {"ssh": limited()}, "settings": {"default": settings()}}));
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    let old = limit_key(1, "cb007105");
    let other = limit_key(2, "cb007106");
    env.seed("fw_ban", &[(&old, "00f2052a01000000"), (&other, "00f2052a01000000")]);
    env.seed("fw_rate", &[(&other, &"00".repeat(16))]);
    env.fake().delete_record("policies", "ssh");
    env.set_policy("web", json!({"name": "web", "ports": ["443"], "syn_limit": {"max_new": 5, "window_seconds": 1}}));
    env.act("apply", json!({}));
    assert_eq!(env.act("status", json!({}))["policies"][0]["slot"], 2, "the new policy avoids the slot just freed");
    assert_eq!(env.map("fw_ban").into_keys().collect::<Vec<_>>(), vec![old]);
    assert!(env.map("fw_rate").is_empty());
}

fn event_hex(slot: u64, reason: u64, ifindex: u64, src: &str) -> String {
    c::u32le(5000000) + &c::u32le(0) + &c::u32le(ifindex) + &c::u16le(slot) + &c::u8h(reason) + &c::u8h(4) + &c::u8h(0) + "00" + "9c40" + "0016" + "0000"
        + &padded(src)
        + &padded("0a000001")
}

#[test]
fn sampled_drops_reach_the_plugin_and_come_back_newest_first() {
    let mut env = Env::new(json!({"policies": {"ssh": limited()}, "settings": {"default": settings()}}));
    *env.mono.lock().unwrap() = Some(10000.0);
    env.act("apply", json!({}));
    env.h.ring("drop_log", &[event_hex(1, 1, 2, "cb007105"), event_hex(1, 3, 2, "cb007106")]).unwrap();
    env.h.ring("drop_log", &[event_hex(0, 4, 3, "cb007107")]).unwrap();
    let items = js::array(&env.act("events", json!({"limit": 2})));
    let got: Vec<Value> = items.iter().map(|e| json!([e["reason"], e["source"], e["policy"], e["interface"]])).collect();
    assert_eq!(got, vec![json!(["evasive", "203.0.113.7", null, "eth1"]), json!(["rate", "203.0.113.6", "ssh", "eth0"])]);
    assert_eq!(items[1]["policy_name"], "SSH");
    // Logged at 5 ms on a clock now at 10000 ms: 9995 ms ago.
    let at = js::number(&items[1]["at_ms"]);
    assert!((at - (js::now_ms() as f64 - 9995.0)).abs() < 5000.0, "{at}");
    assert_eq!(js::array(&env.act("events", json!({}))).len(), 3);
    // The plugin keeps the latest 500.
    let batch: Vec<String> = (0..128).map(|_| event_hex(1, 1, 2, "cb007105")).collect();
    for _ in 0..5 {
        env.h.ring("drop_log", &batch).unwrap();
    }
    assert_eq!(js::array(&env.act("events", json!({"limit": 500}))).len(), 500);
}

fn host_info(fake: &FakeHost, extra: Value) {
    let features = ALL_FEATURES;
    fake.adapter("plugin.host", move |_| {
        Ok(with(json!({"os": "linux", "arch": "amd64", "available_features": features, "features": []}), extra.clone()))
    });
}

fn attachments_adapter(fake: &FakeHost, attachments: Arc<Mutex<Value>>) {
    fake.adapter("plugin.attachments", move |_| {
        let value = attachments.lock().unwrap().clone();
        let list = js::array(&value["attachments"]);
        Ok(json!({
            "mode": if list.is_empty() { "registered" } else { "dataplane" },
            "attached": !list.is_empty(),
            "error": js::or(&value["error"], &json!("")),
            "reason": js::or(&value["reason"], &json!("")),
            "attachments": list,
        }))
    });
}

#[test]
fn status_reports_how_the_hook_sits_on_each_interface_and_whether_the_core_left_xdp() {
    let attachments = json!({"attachments": [
        {"hook_id": "wan-filter", "engine": "xdp", "interface": "eth0", "status": "attached", "xdp_mode": "driver"},
        {"hook_id": "wan-filter", "engine": "xdp", "interface": "wg0", "status": "attached", "xdp_mode": "generic"},
        {"hook_id": "wan-filter", "engine": "xdp", "interface": "vmbr0", "status": "attached", "xdp_mode": "tc"},
        {"hook_id": "other", "engine": "xdp", "interface": "eth1", "status": "attached", "xdp_mode": "driver"},
    ]});
    let mut env = Env::new(json!({"policies": {"ssh": ssh()}, "settings": {"default": settings_with(json!({"interfaces": ["eth0", "eth1", "vmbr0", "wg0"]}))}}));
    attachments_adapter(env.fake(), Arc::new(Mutex::new(attachments)));
    host_info(env.fake(), json!({"kernel_engine_order": ["xdp", "tc"], "core_engine_pinned_to_tc": true}));
    env.act("apply", json!({}));
    let st = env.act("status", json!({}));
    assert_eq!(
        st["attachments"],
        json!({"error": "", "reason": "", "interfaces": [
            {"interface": "eth0", "attached": true, "mode": "driver", "error": "", "egress": false},
            {"interface": "eth1", "attached": false, "mode": "", "error": "", "egress": false},
            {"interface": "vmbr0", "attached": true, "mode": "tc", "error": "", "egress": false},
            {"interface": "wg0", "attached": true, "mode": "generic", "error": "", "egress": false},
        ]})
    );
    assert_eq!(st["core"], json!({"engine_order": ["xdp", "tc"], "prefers_xdp": true, "pinned_to_tc": true}));
}

#[test]
fn the_manifest_hook_carries_a_tc_fallback_and_an_egress_program_where_the_host_has_them() {
    let manifest: Value = serde_json::from_str(include_str!("../plugin.json")).unwrap();
    let register = &manifest["control"]["register"];
    let hooks = js::array(&register["hooks"]);
    assert_eq!(hooks.len(), 2);
    for hook in &hooks {
        assert_eq!(hook["id"], "wan-filter");
        assert_eq!(hook["engine"], "xdp");
        assert_eq!(hook["program"], "firewall:filter");
        assert_eq!(hook["tc_fallback"], "firewall:filter_tc");
    }
    let egress = hooks.iter().find(|hook| hook["when"]["feature"] == TC_EGRESS).expect("a hook for hosts with tc_egress");
    assert_eq!(egress["tc_egress"], "firewall:track");
    let plain = hooks.iter().find(|hook| hook["when"]["not_feature"] == TC_EGRESS).expect("a hook for older hosts");
    assert!(plain.get("tc_egress").is_none());
    let programs: Vec<Value> = js::array(&register["ebpf_objects"][0]["programs"]).iter().map(|p| json!([p["id"], p["section"], p["type"]])).collect();
    assert_eq!(
        programs,
        vec![json!(["filter", "xdp/veer/firewall", "xdp"]), json!(["filter_tc", "tc/veer/firewall", "tc"]), json!(["track", "tc/veer/firewall_egress", "tc"])]
    );
    // An older host: connection tracking is refused.
    let mut old = Env::with_features(
        json!({"settings": {"default": {"data": {"interfaces": ["eth0"], "connection_tracking": true}}}}),
        &["dataplane.xdp_pipeline.v1", "dataplane.xdp_tc_fallback.v1"],
    );
    let errors = old.act("check", json!({}))["errors"].to_string();
    assert!(errors.contains("不支持连接跟踪"), "{errors}");
}

#[test]
fn an_apply_the_host_cannot_attach_is_undone_and_status_passes_the_error_on() {
    let failure = Arc::new(Mutex::new(json!({})));
    let mut env = basic();
    attachments_adapter(env.fake(), failure.clone());
    host_info(env.fake(), json!({"kernel_engine_order": ["tc", "xdp"], "core_engine_pinned_to_tc": true}));
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    let confirmed = env.generation();
    env.set_policy("web", json!({"name": "web", "ports": ["8443"]}));
    *failure.lock().unwrap() = json!({"error": "eth0 already runs another XDP program"});
    let message = env.act_err("apply", json!({}));
    assert!(message.contains("没能挂载到接口") && message.contains("another XDP program"), "{message}");
    assert!(env.state()["pending"].is_null());
    assert_eq!(env.state()["rollback_reason"], "attach_failed");
    assert_eq!(env.generation(), confirmed, "back on the confirmed rules");
    assert_eq!(env.keys_of("fw_ports", env.generation()).len(), 1);
    let st = env.act("status", json!({}));
    assert_eq!(st["attachments"]["error"], "eth0 already runs another XDP program");
    assert_eq!(st["attachments"]["interfaces"], json!([{"interface": "eth0", "attached": false, "mode": "", "error": "", "egress": false}]));
    assert_eq!(st["core"], json!({"engine_order": ["tc", "xdp"], "prefers_xdp": false, "pinned_to_tc": false}));
}

fn set_record(elements: Value) -> Value {
    json!({"data": {"elements": elements}, "enabled": true})
}

#[test]
fn sets_reach_fw_sets_with_apply_and_removed_elements_leave_after_the_flip() {
    let mut env = Env::new(json!({
        "policies": {"ssh": policy(json!({"name": "SSH", "ports": ["22"], "sources": [{"set": "office", "action": "allow"}]}))},
        "sets": {"office": set_record(json!(["203.0.113.0/24", "2001:db8::/32"])), "deny": set_record(json!(["198.51.100.7"]))},
        "settings": {"default": settings_with(json!({"blocklists": ["deny"]}))},
    }));
    env.act("apply", json!({}));
    let ids = env.state()["set_ids"].clone();
    let mut names: Vec<String> = ids.as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(names, ["deny", "office"]);
    let id = |name: &str| ids[name].as_u64().unwrap();
    let mut expected = vec![
        (id("deny"), "198.51.100.7/32".to_string(), "static".to_string()),
        (id("office"), "2001:db8::/32".to_string(), "static".to_string()),
        (id("office"), "203.0.113.0/24".to_string(), "static".to_string()),
    ];
    expected.sort();
    assert_eq!(env.set_entries(), expected);
    // The blocklist and the policy's source set are in the generation.
    let gcfg = env.map("fw_gcfg")[&c::u32le(env.generation() as u64)].clone();
    assert_eq!(&gcfg[12..14], "01");
    assert_eq!(&gcfg[16..20], c::u16le(id("deny")));
    let slot = env.state()["slots"]["ssh"].as_u64().unwrap();
    let pext = env.map("fw_pext")[&c::u32le(env.generation() as u64 * 256 + slot)].clone();
    assert_eq!(&pext[2..4], "01");
    env.act("confirm", json!({}));

    // Drop the IPv6 element and the deny set.
    env.fake().put_record("sets", "office", json!({"elements": ["203.0.113.0/24"]}), true);
    env.fake().delete_record("sets", "deny");
    env.set_settings(settings_data());
    env.act("apply", json!({}));
    let got: Vec<(u64, String)> = env.set_entries().into_iter().map(|(id, cidr, _)| (id, cidr)).collect();
    assert_eq!(got, vec![(id("office"), "203.0.113.0/24".to_string())]);
    assert_eq!(env.state()["set_ids"]["office"], ids["office"], "the set keeps its id");
}

#[test]
fn a_policy_may_not_name_a_set_the_draft_lacks_nor_a_blocklist() {
    let mut env = Env::new(json!({
        "policies": {"ssh": policy(json!({"name": "SSH", "ports": ["22"], "sources": [{"set": "office", "action": "allow"}]}))},
        "settings": {"default": settings_with(json!({"blocklists": ["deny"]}))},
    }));
    let errors: Vec<String> = js::array(&env.act("check", json!({}))["errors"]).iter().map(js::string).collect();
    let errors = errors.join("；");
    assert!(errors.contains("引用的集合不存在: office"), "{errors}");
    assert!(errors.contains("黑名单引用的集合不存在: deny"), "{errors}");
}

#[test]
fn set_add_set_list_set_del_and_set_flush_change_an_applied_set_at_once() {
    let mut env = Env::new(json!({"policies": {"ssh": ssh()}, "sets": {"scanners": set_record(json!(["192.0.2.0/24"]))}, "settings": {"default": settings()}}));
    assert!(env.act_err("set_add", json!({"set": "scanners", "elements": ["198.51.100.1"]})).contains("已应用的集合"));
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    assert_eq!(env.act("set_add", json!({"set": "scanners", "elements": ["198.51.100.1", "192.0.2.0/24"], "timeout_seconds": 60})), json!({"added": 1}));
    assert_eq!(env.act("set_add", json!({"set": "scanners", "elements": "2001:db8::5"})), json!({"added": 1}));
    let list = env.act("set_list", json!({"set": "scanners"}));
    let mut items: Vec<Value> = js::array(&list["items"]).iter().map(|i| json!([i["cidr"], i["kind"], i["remaining_seconds"]])).collect();
    items.sort_by_key(|item| item.to_string());
    assert_eq!(items, vec![json!(["192.0.2.0/24", "static", null]), json!(["198.51.100.1/32", "api", 60]), json!(["2001:db8::5/128", "api", null])]);
    // A cold start loses fw_sets; the next reconcile restores the set_add elements from KV.
    env.clear_maps();
    env.reconcile();
    let got: Vec<(String, String)> = env.set_entries().into_iter().map(|(_, cidr, kind)| (cidr, kind)).collect();
    let mut got = got;
    got.sort();
    assert_eq!(
        got,
        vec![("192.0.2.0/24".into(), "static".into()), ("198.51.100.1/32".into(), "api".into()), ("2001:db8::5/128".into(), "api".into())]
    );
    assert_eq!(env.act("set_del", json!({"set": "scanners", "elements": ["2001:db8::5", "192.0.2.0/24"]})), json!({"removed": 1}));
    // Expired elements leave with the prune timer.
    assert!(env.timer("set_prune").is_some());
    *env.mono.lock().unwrap() = Some(1_000_000.0 + 61000.0);
    env.fire("set_prune");
    let cidrs: Vec<String> = env.set_entries().into_iter().map(|(_, cidr, _)| cidr).collect();
    assert_eq!(cidrs, ["192.0.2.0/24"]);
    env.act("set_add", json!({"set": "scanners", "elements": ["198.51.100.2"]}));
    assert_eq!(env.act("set_flush", json!({"set": "scanners"})), json!({"removed": 1}));
    let cidrs: Vec<String> = env.set_entries().into_iter().map(|(_, cidr, _)| cidr).collect();
    assert_eq!(cidrs, ["192.0.2.0/24"]);
    assert!(env.act_err("set_add", json!({"set": "scanners", "elements": ["1.2.3.4"], "timeout_seconds": -1})).contains("timeout_seconds"));
}

#[test]
fn connection_tracking_turns_on_the_egress_program_and_needs_it_attached() {
    let attachments = Arc::new(Mutex::new(json!({"attachments": [
        {"hook_id": "wan-filter", "engine": "xdp", "attach": "ingress", "interface": "eth0", "status": "attached", "xdp_mode": "driver"},
    ]})));
    let mut env = Env::new(json!({
        "policies": {"all": policy(json!({"name": "all", "protocol": "any"}))},
        "settings": {"default": settings_with(json!({"connection_tracking": true}))},
    }));
    attachments_adapter(env.fake(), attachments.clone());
    // Catch-all drop with tracking: only the lockout warning is left, and trusted sources clear it.
    assert_eq!(env.act("check", json!({}))["warnings"], json!([]));
    assert!(env.act_err("apply", json!({})).contains("出向程序没挂上 eth0"));
    assert_eq!(env.state()["rollback_reason"], "attach_failed");
    // Nothing was confirmed yet: the rollback unbinds.
    assert_eq!(env.binding()["data"], json!({"hook_id": "wan-filter", "interfaces": [], "tc_egress": false}));
    attachments.lock().unwrap()["attachments"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hook_id": "wan-filter", "engine": "xdp", "attach": "egress", "interface": "eth0", "status": "attached", "xdp_mode": "tc"}));
    env.act("apply", json!({}));
    assert_eq!(env.binding()["data"], json!({"hook_id": "wan-filter", "interfaces": ["eth0"], "tc_egress": true}));
    let gcfg = env.map("fw_gcfg")[&c::u32le(env.generation() as u64)].clone();
    assert_eq!(u8::from_str_radix(&gcfg[0..2], 16).unwrap() & 1, 1);
    assert_ne!(&gcfg[8..12], "0000", "the catch-all class");
    let st = env.act("status", json!({}));
    assert_eq!(st["connection_tracking"], json!({"available": true, "enabled": true}));
    assert_eq!(st["attachments"]["interfaces"], json!([{"interface": "eth0", "attached": true, "mode": "driver", "error": "", "egress": true}]));
}

#[test]
fn a_reconcile_over_kept_maps_fixes_a_1_0_binding_and_leaves_a_pending_prune_alone() {
    let mut env = Env::new(json!({
        "policies": {"ssh": policy(json!({"name": "SSH", "ports": ["22"], "add_to_set": {"set": "scanners"}}))},
        "sets": {"scanners": set_record(json!([]))},
        "settings": {"default": settings()},
    }));
    env.act("apply", json!({}));
    env.act("confirm", json!({}));
    // 1.0 wrote no tc_egress, which the host takes as on.
    env.fake().put_record("hook_bindings", "wan-filter", json!({"hook_id": "wan-filter", "interfaces": ["eth0"]}), true);
    assert!(env.timer("set_prune").is_some(), "apply arms the prune timer");
    env.fake().edit_timer("set_prune", |timer| timer["delay_ms"] = json!(1234)); // tells a re-armed timer apart
    env.reconcile();
    assert_eq!(env.binding()["data"], json!({"hook_id": "wan-filter", "interfaces": ["eth0"], "tc_egress": false}));
    assert_eq!(env.timer("set_prune").unwrap()["delay_ms"], 1234, "a pending prune is not pushed back");
    // A new process has no timers: the reconcile arms it again.
    env.fake().clear_timers();
    env.reconcile();
    assert_eq!(env.timer("set_prune").unwrap()["delay_ms"], 60000);
}

#[test]
fn baseline_settings_set_generation_flags_and_write_the_bogon_prefixes() {
    let mut env = Env::new(json!({
        "policies": {"ssh": ssh()},
        "settings": {"default": settings_with(json!({"baseline": {"bogon_sources": "all", "invalid_tcp_flags": true, "drop_fragments": true, "urpf": "strict"}}))},
    }));
    let checked = env.act("check", json!({}));
    assert_eq!(ids_of(&checked["warnings"]), ["urpf_strict"]);
    env.act("apply", json!({"accept_warnings": checked["token"]}));
    let gcfg = env.map("fw_gcfg")[&c::u32le(env.generation() as u64)].clone();
    assert_eq!(u8::from_str_radix(&gcfg[0..2], 16).unwrap(), 2 | 4 | 8 | 32);
    let bogons: Vec<String> = env.set_entries().into_iter().filter(|(id, _, _)| *id == c::SET_BOGON as u64).map(|(_, cidr, _)| cidr).collect();
    assert_eq!(bogons.len(), c::BOGONS_RESERVED.len() + c::BOGONS_PRIVATE.len());
    assert!(bogons.iter().any(|cidr| cidr == "10.0.0.0/8"));
    env.act("confirm", json!({}));
    // Back to reserved only: the private prefixes leave.
    env.set_settings(with(settings_data(), json!({"baseline": {"bogon_sources": "reserved"}})));
    env.act("apply", json!({}));
    let bogons = env.set_entries().into_iter().filter(|(id, _, _)| *id == c::SET_BOGON as u64).count();
    assert_eq!(bogons, c::BOGONS_RESERVED.len());
}

#[test]
fn baseline_modes_must_be_known_strings() {
    let mut env = Env::new(json!({"settings": {"default": settings_with(json!({"baseline": {"bogon_sources": ["all"]}}))}}));
    assert!(env.act("check", json!({}))["errors"].to_string().contains("bogon_sources"));
    env.set_settings(with(settings_data(), json!({"baseline": {"urpf": null}})));
    assert!(env.act("check", json!({}))["errors"].to_string().contains("urpf"));
}

#[test]
fn status_reports_the_global_counters() {
    let mut env = basic();
    *env.counters.lock().unwrap() = Box::new(|key| vec![c::u32le(u64::from_str_radix(&key[0..2], 16).unwrap() + 1) + "00000000"]);
    env.act("apply", json!({}));
    let st = env.act("status", json!({}));
    assert_eq!(st["global"]["established"], 1);
    assert_eq!(st["global"]["blocklist"], 4);
    let keys: Vec<String> = st["global"].as_object().unwrap().keys().cloned().collect();
    let mut expected: Vec<String> = c::GCOUNTERS.iter().map(|name| name.to_string()).collect();
    let mut sorted = keys.clone();
    sorted.sort();
    expected.sort();
    assert_eq!(sorted, expected);
}

#[test]
fn blocklist_drops_name_their_set() {
    let mut env = Env::new(json!({"sets": {"deny": set_record(json!(["198.51.100.7"]))}, "settings": {"default": settings_with(json!({"blocklists": ["deny"]}))}}));
    env.act("apply", json!({}));
    let id = env.state()["set_ids"]["deny"].as_u64().unwrap();
    env.h.ring("drop_log", &[event_hex(id, 5, 2, "c6336407")]).unwrap();
    let events = js::array(&env.act("events", json!({})));
    assert_eq!(events[0]["reason"], "blocklist");
    assert_eq!(events[0]["set"], "deny");
    assert!(events[0]["policy"].is_null());
}

#[test]
fn unknown_handlers_are_left_to_the_host() {
    let mut env = basic();
    let outcome = env.h.run(veer_plugin::MsgKind::Event, "onSomething", json!({})).unwrap();
    assert!(matches!(outcome, Outcome::Unhandled));
}
