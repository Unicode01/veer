//! Reading a link's offload features through SIOCETHTOOL, as the host does
//! (internal/app/plugin_control_net_offloads_linux.go).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use veer_plugin::{Map, Value};

const SIOCETHTOOL: libc::c_ulong = 0x8946;
const ETHTOOL_GRXCSUM: u32 = 0x14;
const ETHTOOL_GTXCSUM: u32 = 0x16;
const ETHTOOL_GSG: u32 = 0x18;
const ETHTOOL_GTSO: u32 = 0x1e;
const ETHTOOL_GUFO: u32 = 0x21;
const ETHTOOL_GGSO: u32 = 0x23;
const ETHTOOL_GFLAGS: u32 = 0x25;
const ETHTOOL_GGRO: u32 = 0x2b;
const ETH_FLAG_LRO: u32 = 1 << 15;

const GROUPS: [(&str, u32); 7] = [
    ("rx", ETHTOOL_GRXCSUM),
    ("tx", ETHTOOL_GTXCSUM),
    ("sg", ETHTOOL_GSG),
    ("tso", ETHTOOL_GTSO),
    ("ufo", ETHTOOL_GUFO),
    ("gso", ETHTOOL_GGSO),
    ("gro", ETHTOOL_GGRO),
];

#[repr(C)]
struct EthtoolValue {
    cmd: u32,
    data: u32,
}

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    data: *mut EthtoolValue,
    _pad: [u8; 16],
}

fn ethtool(fd: &OwnedFd, name: &[u8; 16], cmd: u32) -> Result<u32, i32> {
    let mut value = EthtoolValue { cmd, data: 0 };
    let mut request = Ifreq { name: *name, data: &mut value, _pad: [0; 16] };
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), SIOCETHTOOL as _, &mut request as *mut Ifreq) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
    }
    Ok(value.data)
}

/// The host's pluginOffloadDevice.read: each group, ufo skipped when the
/// kernel has none, then lro from the flags.
pub fn read(name: &str) -> Result<Value, String> {
    if name.is_empty() || name.len() >= 16 {
        return Err(format!("invalid interface name {name:?}"));
    }
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(format!("open ethtool socket: {}", super::rtnl::errno_text(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut ifname = [0u8; 16];
    ifname[..name.len()].copy_from_slice(name.as_bytes());
    let mut out = Map::new();
    let mut first_err: Option<i32> = None;
    let mut readable = 0;
    for (group, cmd) in GROUPS {
        match ethtool(&fd, &ifname, cmd) {
            Ok(value) => {
                out.insert(group.to_string(), Value::Bool(value != 0));
                readable += 1;
            }
            Err(code) if cmd == ETHTOOL_GUFO && code == libc::EOPNOTSUPP => {}
            Err(code) => {
                first_err.get_or_insert(code);
                out.insert(group.to_string(), Value::Bool(false));
            }
        }
    }
    match ethtool(&fd, &ifname, ETHTOOL_GFLAGS) {
        Ok(flags) => {
            out.insert("lro".to_string(), Value::Bool(flags & ETH_FLAG_LRO != 0));
            readable += 1;
        }
        Err(code) => {
            first_err.get_or_insert(code);
            out.insert("lro".to_string(), Value::Bool(false));
        }
    }
    if readable == 0 {
        if first_err == Some(libc::ENODEV) {
            return Err(format!("link not found: {name}"));
        }
        let detail = first_err.map(super::rtnl::errno_text).unwrap_or_else(|| "<nil>".to_string());
        return Err(format!("no offload information for {name}: {detail}"));
    }
    Ok(Value::Object(out))
}
