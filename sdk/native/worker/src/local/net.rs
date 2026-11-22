//! net.link.get, net.link.list and net.link.getOffloads in the worker, with
//! the host's argument handling, checks, error texts and result shape
//! (netLinkGet / netLinkList / netLinkGetOffloads and
//! pluginControlNetLinkInfoMap in internal/app/plugin_control_net.go).
//!
//! Only the host network namespace is served here. A query for another
//! namespace goes to the host, which owns those namespaces and checks them.

use veer_plugin::{js, Map, Value};

use super::rtattr::{Addr, Link};
use super::{arg, Failure, Local, Outcome};

const INTERFACE_NAME_MAX_BYTES: usize = 15;

/// The namespace argument: absent, a name, or {namespace|netns}. None when it
/// names anything but the host namespace (the host serves those).
fn host_namespace(value: &Value) -> Option<()> {
    let namespace = match value {
        Value::Null => return Some(()),
        Value::Object(map) => ["namespace", "netns"]
            .iter()
            .map(|field| map.get(*field).map(js::string).unwrap_or_default().trim().to_string())
            .find(|text| !text.is_empty())
            .unwrap_or_default(),
        other => js::string(other).trim().to_string(),
    };
    let namespace = namespace.trim().to_ascii_lowercase();
    (namespace.is_empty() || namespace == "host").then_some(())
}

/// requiredNetStringArg.
fn interface_arg(args: &[Value], index: usize, field: &str) -> Result<String, Failure> {
    let value = arg(args, index);
    if value.is_null() {
        return Err(Failure::error(format!("{field} is required")));
    }
    let text = js::string(value).trim().to_string();
    validate_interface_name(&text, field)?;
    Ok(text)
}

fn validate_interface_name(value: &str, field: &str) -> Result<(), Failure> {
    if value.is_empty() {
        return Err(Failure::error(format!("{field} is required")));
    }
    if value.contains('\0') || value.contains(['/', '\\', ' ', '\t', '\r', '\n']) || value.len() > INTERFACE_NAME_MAX_BYTES {
        return Err(Failure::error(format!("{field} contains invalid characters or exceeds {INTERFACE_NAME_MAX_BYTES} bytes")));
    }
    Ok(())
}

/// pluginControlNetLinkInfoMap for a link read in the host namespace.
pub fn link_json(link: &Link, addresses: &[String], parent: &str, master: &str) -> Value {
    let mut out = Map::new();
    let is_veth = link.kind.as_deref() == Some("veth");
    out.insert("namespace".into(), Value::from("host"));
    out.insert("name".into(), Value::from(link.name.clone()));
    out.insert("alias".into(), Value::from(link.alias.clone()));
    out.insert("created".into(), Value::Bool(false));
    out.insert("ifindex".into(), Value::from(link.index));
    out.insert("kind".into(), Value::from(link.type_name()));
    out.insert("tun_mode".into(), Value::from(link.tun_mode()));
    out.insert("tun_vnet_hdr".into(), Value::Bool(link.tun_vnet_hdr));
    out.insert("parent".into(), Value::from(if link.parent_index > 0 { parent } else { "" }));
    out.insert("mtu".into(), Value::from(link.mtu));
    out.insert("mac".into(), Value::from(link.mac_text()));
    out.insert("up".into(), Value::Bool(link.flags & super::rtattr::IFF_UP != 0));
    out.insert("arp".into(), Value::Bool(link.flags & super::rtattr::IFF_NOARP == 0));
    out.insert("oper_state".into(), Value::from(link.oper_state_name()));
    // The host copies the list with append([]string(nil), ...): an empty one
    // reaches the plugin as null.
    out.insert(
        "addresses".into(),
        if addresses.is_empty() { Value::Null } else { Value::Array(addresses.iter().map(|text| Value::from(text.clone())).collect()) },
    );
    let peer = is_veth && link.parent_index > 0;
    out.insert("peer_name".into(), Value::from(if peer { parent } else { "" }));
    out.insert("peer_ifindex".into(), Value::from(if peer { link.parent_index } else { 0 }));
    out.insert("master_name".into(), Value::from(if link.master_index > 0 { master } else { "" }));
    out.insert("master_ifindex".into(), Value::from(link.master_index));
    out.insert("promiscuous".into(), Value::Bool(link.promiscuity > 0));
    out.insert("gso_max_size".into(), Value::from(link.gso_max_size));
    out.insert("gso_max_segs".into(), Value::from(link.gso_max_segs));
    out.insert("vlan_id".into(), Value::from(if link.kind.as_deref() == Some("vlan") { link.vlan_id } else { 0 }));
    out.insert("vlan_protocol".into(), Value::from(if link.kind.as_deref() == Some("vlan") { link.vlan_protocol_name() } else { String::new() }));
    out.insert("vrf_table".into(), Value::from(link.vrf_table));
    if let Some(stats) = link.stats {
        let names = ["rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"];
        let statistics: Map<String, Value> = names.iter().zip(stats.iter()).map(|(name, value)| (name.to_string(), Value::from(*value))).collect();
        out.insert("statistics".into(), Value::Object(statistics));
    }
    Value::Object(out)
}

fn addresses_of(addrs: &[Addr], index: i32) -> Vec<String> {
    addrs.iter().filter(|addr| addr.index as i32 == index).map(|addr| addr.text.clone()).collect()
}

pub fn link_get(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    let name = match interface_arg(args, 0, "name") {
        Ok(name) => name,
        Err(failure) => return Some(Err(failure)),
    };
    host_namespace(arg(args, 1))?;
    Some((|| {
        local.policy().require(kind, "net.admin")?;
        local.policy().require_net_access("link.read", &name, "net.link.get")?;
        system::link_get(local, &name).map_err(|err| Failure::error(format!("net.link.get: {err}")))
    })())
}

pub fn link_list(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    host_namespace(arg(args, 0))?;
    Some((|| {
        local.policy().require(kind, "net.admin")?;
        local.policy().require_any_net_access("link.read", "net.link.list")?;
        let links = system::link_list(local).map_err(|err| Failure::error(format!("net.link.list: {err}")))?;
        Ok(Value::Array(
            links.into_iter().filter(|link| local.policy().has_net_access("link.read", link["name"].as_str().unwrap_or(""))).collect(),
        ))
    })())
}

pub fn link_get_offloads(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    let name = match interface_arg(args, 0, "name") {
        Ok(name) => name,
        Err(failure) => return Some(Err(failure)),
    };
    host_namespace(arg(args, 1))?;
    Some((|| {
        local.policy().require(kind, "net.admin")?;
        local.policy().require_net_access("link.read", &name, "net.link.getOffloads")?;
        system::offloads(&name).map_err(|err| Failure::error(format!("net.link.getOffloads: {err}")))
    })())
}

#[cfg(target_os = "linux")]
mod system {
    use super::super::rtnl::{self, Rtnl};
    use super::*;

    fn with_rtnl<T>(local: &Local, f: impl FnOnce(&mut Rtnl) -> Result<T, String>) -> Result<T, String> {
        local.with_rtnl(f)
    }

    fn resolve(name: &str) -> Result<i32, String> {
        match rtnl::index_of(name) {
            Ok(Some(index)) => Ok(index),
            Ok(None) => Err(format!("link not found: {name}")),
            Err(code) => Err(format!("resolve link {name:?} index: {}", rtnl::errno_text(code))),
        }
    }

    fn name_of(rtnl: &mut Rtnl, index: i32) -> String {
        rtnl.link_by_index(index).map(|link| link.name).unwrap_or_default()
    }

    pub fn link_get(local: &Local, name: &str) -> Result<Value, String> {
        let index = resolve(name)?;
        with_rtnl(local, |rtnl| {
            let link = rtnl.link_by_index(index).map_err(|err| match err {
                rtnl::NlError::Errno(libc::ENODEV) => "Link not found".to_string(),
                other => other.to_string(),
            })?;
            let addrs = rtnl.addresses(Some(index as u32)).map_err(|err| err.to_string())?;
            let parent = if link.parent_index > 0 { name_of(rtnl, link.parent_index) } else { String::new() };
            let master = if link.master_index > 0 { name_of(rtnl, link.master_index) } else { String::new() };
            Ok(link_json(&link, &addresses_of(&addrs, link.index), &parent, &master))
        })
    }

    pub fn link_list(local: &Local) -> Result<Vec<Value>, String> {
        with_rtnl(local, |rtnl| {
            let links = rtnl.links().map_err(|err| err.to_string())?;
            let addrs = rtnl.addresses(None).map_err(|err| err.to_string())?;
            let names: std::collections::HashMap<i32, String> = links.iter().map(|link| (link.index, link.name.clone())).collect();
            let mut out = Vec::with_capacity(links.len());
            for link in &links {
                let mut lookup = |index: i32| names.get(&index).cloned().unwrap_or_else(|| name_of(rtnl, index));
                let parent = if link.parent_index > 0 { lookup(link.parent_index) } else { String::new() };
                let master = if link.master_index > 0 { lookup(link.master_index) } else { String::new() };
                out.push(link_json(link, &addresses_of(&addrs, link.index), &parent, &master));
            }
            Ok(out)
        })
    }

    pub fn offloads(name: &str) -> Result<Value, String> {
        resolve(name)?;
        super::super::ethtool::read(name)
    }
}

#[cfg(not(target_os = "linux"))]
mod system {
    use super::*;

    const UNSUPPORTED: &str = "network inventory is only available on Linux";

    pub fn link_get(_: &Local, _: &str) -> Result<Value, String> {
        Err(UNSUPPORTED.to_string())
    }

    pub fn link_list(_: &Local) -> Result<Vec<Value>, String> {
        Err(UNSUPPORTED.to_string())
    }

    pub fn offloads(_: &str) -> Result<Value, String> {
        Err(UNSUPPORTED.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    fn local(config: Value) -> Local {
        Local::new(&config)
    }

    #[test]
    fn other_namespaces_go_to_the_host() {
        let local = local(json!({"permissions": ["net.admin"], "net_access": [{"interfaces": ["*"], "operations": ["link.read"]}]}));
        assert!(link_get(&local, 0, &[json!("eth0"), json!("vpn")]).is_none());
        assert!(link_get(&local, 0, &[json!("eth0"), json!({"netns": "vpn"})]).is_none());
        assert!(link_list(&local, 0, &[json!("vpn")]).is_none());
        // The host namespace by any spelling stays here.
        assert!(link_get(&local, 0, &[json!("eth0"), json!("HOST")]).is_some());
        assert!(link_get(&local, 0, &[json!("eth0"), json!({"namespace": ""})]).is_some());
    }

    #[test]
    fn checks_in_the_host_order() {
        let none = local(json!({}));
        assert_eq!(link_get(&none, 0, &[]).unwrap().unwrap_err().message, "name is required");
        assert!(link_get(&none, 0, &[json!("a/b")]).unwrap().unwrap_err().message.contains("invalid characters"));
        assert_eq!(link_get(&none, 0, &[json!("eth0")]).unwrap().unwrap_err().message, "permission net.admin is required");
        let admin = local(json!({"permissions": ["net.admin"], "net_access": [{"interfaces": ["veer*"], "operations": ["link.read"]}]}));
        assert_eq!(
            link_get(&admin, 0, &[json!("eth0")]).unwrap().unwrap_err().message,
            "net.link.get: net_access operation link.read on interface eth0 is not declared"
        );
        assert!(link_list(&local(json!({"permissions": ["net.admin"]})), 0, &[]).unwrap().unwrap_err().message.contains("net.link.list: net_access operation link.read is not declared"));
        assert!(link_get_offloads(&admin, 9, &[json!("veer0")]).unwrap().unwrap_err().message.contains("upgrade"));
    }

    #[test]
    fn link_json_matches_the_host_shape() {
        let link = Link {
            index: 4,
            flags: super::super::rtattr::IFF_UP,
            name: "veerwg1".into(),
            mtu: 1420,
            kind: Some("veth".into()),
            parent_index: 5,
            oper_state: 6,
            stats: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            ..Default::default()
        };
        let value = link_json(&link, &[], "veerwg1p", "");
        assert_eq!(value["addresses"], Value::Null);
        assert_eq!(value["peer_name"], json!("veerwg1p"));
        assert_eq!(value["peer_ifindex"], json!(5));
        assert_eq!(value["parent"], json!("veerwg1p"));
        assert_eq!(value["arp"], json!(true));
        assert_eq!(value["namespace"], json!("host"));
        assert_eq!(value["statistics"]["tx_dropped"], json!(8));
        assert_eq!(value["vlan_protocol"], json!(""));
        assert_eq!(value.as_object().unwrap().len(), 26);
    }
}
