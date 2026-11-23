//! Core management and core configuration: core-manager.js and
//! core-drivers.js. Core-specific configuration ends here; the WAN and the
//! packet handoff are shared by every driver.

use veer_plugin::js::{self, get as g, truthy};
use veer_plugin::{bail, json, Map, Result, Value};

use crate::{fail, share};

pub fn driver(value: &Value) -> Result<String> {
    match value.as_str() {
        Some(name @ ("mihomo" | "sing_box")) => Ok(name.to_string()),
        _ => bail!("Core management supports Mihomo and sing-box"),
    }
}

fn release_version(version: &str) -> bool {
    // ^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-.][a-zA-Z0-9]+)*$
    let bytes = version.strip_prefix('v').unwrap_or(version).as_bytes();
    let mut i = 0;
    for part in 0..3 {
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
        if part < 2 {
            if i >= bytes.len() || bytes[i] != b'.' {
                return false;
            }
            i += 1;
        }
    }
    while i < bytes.len() {
        if bytes[i] != b'-' && bytes[i] != b'.' {
            return false;
        }
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphanumeric() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    true
}

/// The binary store request for an official core release.
pub fn install(payload: &Value, host: &Value) -> Result<Value> {
    let driver = driver(g(payload, "driver"))?;
    if js::string(g(host, "os")) != "linux" {
        bail!("VPN core installation requires Linux");
    }
    // Baseline amd64 and conservative ARM/MIPS builds avoid assuming CPU extensions.
    let arch = js::string(g(host, "arch"));
    let mapped = if driver == "mihomo" {
        match arch.as_str() {
            "amd64" => "amd64-compatible",
            "arm64" => "arm64",
            "arm" => "armv5",
            "386" => "386",
            "mips" => "mips-softfloat",
            "mipsle" => "mipsle-softfloat",
            "mips64" => "mips64",
            "mips64le" => "mips64le",
            "riscv64" => "riscv64",
            "loong64" => "loong64-abi2",
            _ => "",
        }
    } else {
        match arch.as_str() {
            "amd64" => "amd64",
            "arm64" => "arm64",
            "arm" => "armv5",
            "386" => "386",
            "mips" => "mips-softfloat",
            "mipsle" => "mipsle-softfloat",
            "mips64" => "mips64-softfloat",
            "mips64le" => "mips64le-softfloat",
            "riscv64" => "riscv64",
            "loong64" => "loong64",
            _ => "",
        }
    };
    if mapped.is_empty() {
        bail!("No official core build for host architecture {arch}");
    }
    let mut version = js::string(js::or(g(payload, "version"), &json!(""))).trim().to_string();
    if !version.is_empty() && !release_version(&version) {
        bail!("Use a release version such as v1.19.33, or leave blank for latest stable");
    }
    if !version.is_empty() && !version.starts_with('v') {
        version = format!("v{version}");
    }
    let mihomo = driver == "mihomo";
    let repo = if mihomo { "MetaCubeX/mihomo" } else { "SagerNet/sing-box" };
    let release = if version.is_empty() { "latest".to_string() } else { format!("tags/{version}") };
    let mut request = json!({
        "id": driver,
        "executable": if mihomo { "mihomo" } else { "sing-box" },
        "format": if mihomo { "gzip" } else { "tar.gz" },
        "release_url": format!("https://api.github.com/repos/{repo}/releases/{release}"),
        "asset": if mihomo { format!("mihomo-linux-{mapped}-{{tag}}.gz") } else { format!("sing-box-{{version}}-linux-{mapped}.tar.gz") },
        "check_args": if mihomo { json!(["-v"]) } else { json!(["version"]) },
    });
    if !mihomo {
        request["archive_path"] = json!(format!("sing-box-{{version}}-linux-{mapped}/sing-box"));
    }
    if truthy(g(payload, "sha256")) {
        let sum = js::string(g(payload, "sha256"));
        if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("SHA256 must contain 64 hexadecimal characters");
        }
        request["sha256"] = json!(sum.to_lowercase());
    }
    Ok(request)
}

fn object<'a>(value: &'a mut Value, label: &str) -> Result<&'a mut Map<String, Value>> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(fail("core_config_invalid", &format!("{label} must be a JSON object"))),
    }
}

fn bind_source(config: &mut Value, p: &Value) -> Result<()> {
    let upstream_ip = js::string(js::or(g(p, "upstream_ip"), &json!("")));
    if upstream_ip.is_empty() {
        return Ok(());
    }
    let key = if upstream_ip.contains(':') { "inet6_bind_address" } else { "inet4_bind_address" };
    let bind = |value: &mut Map<String, Value>| {
        if truthy(value.get("detour").unwrap_or(&Value::Null)) {
            return; // The last outbound in the chain owns the socket.
        }
        // A source address disables sing-box's default_interface inheritance.
        // Bind both explicitly to retain the selected physical uplink.
        value.insert("bind_interface".into(), p["upstream_interface"].clone());
        value.insert(key.into(), json!(upstream_ip));
    };
    if let Some(outbounds) = config.get_mut("outbounds").and_then(Value::as_array_mut) {
        for value in outbounds.iter_mut() {
            let value = object(value, "Outbound")?;
            let ty = js::string(value.get("type").unwrap_or(&Value::Null));
            if !["selector", "urltest", "block", "dns"].contains(&ty.as_str()) {
                bind(value);
            }
        }
    }
    // Bootstrap DNS also creates physical sockets; DNS sent through a proxy
    // inherits that proxy's binding instead of binding the inner connection.
    if let Some(servers) = config.get_mut("dns").and_then(|dns| dns.get_mut("servers")).and_then(Value::as_array_mut) {
        for value in servers.iter_mut() {
            if let Value::Object(server) = value {
                let ty = js::string(server.get("type").unwrap_or(&Value::Null));
                if ["local", "udp", "tcp", "tls", "quic", "https", "h3", "dhcp", "mdns"].contains(&ty.as_str()) {
                    bind(server);
                }
            }
        }
    }
    Ok(())
}

/// The core executable: a locally installed mihomo or sing-box binary.
pub fn command(driver: &str, path: &Value) -> Result<String> {
    let name = if driver == "mihomo" { "mihomo" } else { "sing-box" };
    let path = if truthy(path) { js::string(path) } else { format!("/usr/local/bin/{name}") };
    let suffix_ok = path.ends_with(&format!("/{name}"));
    let chars_ok = path.starts_with('/') && path.len() > 1 && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'/' | b'-'));
    // /(\.\.?)(\/|$)
    let dots = path.split('/').any(|part| part == "." || part == "..");
    if !suffix_ok || !chars_ok || dots {
        return Err(fail("core_path_invalid", &format!("Core executable must be a locally installed {name} binary")));
    }
    Ok(path)
}

/// The process start spec for a core: {command, args, config}.
pub fn build(p: &Value, text: Option<&str>) -> Result<Value> {
    let parsed = text.and_then(|text| serde_json::from_str::<Value>(text).ok()).filter(Value::is_object);
    let Some(mut config) = parsed else {
        return Err(fail("core_config_invalid", "Core configuration must be valid JSON"));
    };
    let driver = js::string(g(p, "driver"));
    if js::strict_eq(g(&config, "veer_proxy"), &json!(1)) {
        if !js::strict_eq(g(&config, "driver"), g(p, "driver")) {
            return Err(fail("core_config_invalid", "Saved node configuration belongs to another core"));
        }
        config = share::generate(&config)?;
    }
    let tun_address = format!("198.18.{}.1/30", js::string(g(p, "slot")));
    if driver == "mihomo" {
        // Mihomo negotiates TUN offloads only when asked (gso). The plugin keeps
        // the segmented boundary unless the kernel then reports vnet headers and
        // TSO/GSO on the TUN, so a core that ignores the option stays per-packet.
        let hijack = {
            let tun = g(&config, "tun");
            js::or(if truthy(tun) { g(tun, "dns-hijack") } else { &Value::Null }, &json!([])).clone()
        };
        config["tun"] = json!({"enable": true, "device": p["interface"], "stack": "gvisor", "mtu": p["mtu"],
            "inet4-address": [tun_address], "auto-route": false, "auto-redirect": false,
            "auto-detect-interface": false, "dns-mode": "disabled", "gso": true, "gso-max-size": 65536,
            "dns-hijack": hijack});
        config["interface-name"] = p["upstream_interface"].clone();
        config["find-process-mode"] = json!("off");
        // This plugin exposes a WAN, not additional network-facing proxy/API ports.
        for key in ["port", "socks-port", "mixed-port", "redir-port", "tproxy-port"] {
            config[key] = json!(0);
        }
        let map = config.as_object_mut().unwrap();
        for key in ["listeners", "tunnels", "external-controller", "external-controller-tls", "external-controller-unix", "external-ui", "external-doh-server"] {
            map.remove(key);
        }
        if truthy(map.get("dns").unwrap_or(&Value::Null)) {
            object(map.get_mut("dns").unwrap(), "DNS configuration")?.remove("listen");
        }
        let core = command(&driver, g(p, "core_path"))?;
        return Ok(json!({"command": core, "args": ["-d", ".", "-f", "{config}"], "config": config.to_string()}));
    }
    config["inbounds"] = json!([{"type": "tun", "tag": "veer-vpn", "interface_name": p["interface"], "address": [tun_address],
        "mtu": p["mtu"], "stack": "gvisor", "auto_route": false, "auto_redirect": false}]);
    if !truthy(g(&config, "route")) {
        config["route"] = json!({});
    }
    {
        let route = object(config.get_mut("route").unwrap(), "Route configuration")?;
        route.insert("auto_detect_interface".into(), json!(false));
        route.insert("default_interface".into(), p["upstream_interface"].clone());
    }
    bind_source(&mut config, p)?;
    // A core must not create a second privileged network topology behind this WAN.
    if js::array(g(&config, "endpoints")).len() > 0 || g(&config, "endpoints").as_str().map(|s| !s.is_empty()).unwrap_or(false) {
        return Err(fail("core_config_invalid", "Use outbound proxies; managed VPN cores do not accept additional endpoints"));
    }
    config.as_object_mut().unwrap().remove("experimental");
    let core = command(&driver, g(p, "core_path"))?;
    Ok(json!({"command": core, "args": ["run", "-c", "{config}"], "config": config.to_string()}))
}
