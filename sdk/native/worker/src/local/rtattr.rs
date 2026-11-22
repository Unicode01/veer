//! rtnetlink messages: building requests and parsing the link and address
//! replies, with no system calls, so it builds and tests on any host.
//!
//! The parsed view follows what the host's Go side reads through
//! vishvananda/netlink (internal/app/plugin_control_net_linux.go,
//! pluginControlNetLinkInfoWith), so a plugin sees the same JSON from either.

pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_DUMP_INTR: u16 = 16;
pub const NLM_F_ROOT: u16 = 0x100;
pub const NLM_F_MATCH: u16 = 0x200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_NEWADDR: u16 = 20;
pub const RTM_GETADDR: u16 = 22;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_STATS: u16 = 7;
const IFLA_MASTER: u16 = 10;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_IFALIAS: u16 = 20;
const IFLA_STATS64: u16 = 23;
const IFLA_PROMISCUITY: u16 = 30;
const IFLA_GSO_MAX_SEGS: u16 = 40;
const IFLA_GSO_MAX_SIZE: u16 = 41;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_VLAN_ID: u16 = 1;
const IFLA_VLAN_PROTOCOL: u16 = 5;
const IFLA_VRF_TABLE: u16 = 1;
const IFLA_TUN_TYPE: u16 = 3;
const IFLA_TUN_VNET_HDR: u16 = 5;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

pub const IFF_UP: u32 = 0x1;
pub const IFF_NOARP: u32 = 0x80;

const NLA_TYPE_MASK: u16 = 0x3fff;

/// One netlink message from a reply buffer.
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// Splits a receive buffer into messages.
pub fn messages(buffer: &[u8]) -> Result<Vec<Message<'_>>, String> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDRLEN <= buffer.len() {
        let len = u32::from_ne_bytes(buffer[offset..offset + 4].try_into().unwrap()) as usize;
        if len < NLMSG_HDRLEN || offset + len > buffer.len() {
            return Err("malformed netlink message".to_string());
        }
        out.push(Message {
            kind: u16::from_ne_bytes(buffer[offset + 4..offset + 6].try_into().unwrap()),
            flags: u16::from_ne_bytes(buffer[offset + 6..offset + 8].try_into().unwrap()),
            seq: u32::from_ne_bytes(buffer[offset + 8..offset + 12].try_into().unwrap()),
            payload: &buffer[offset + NLMSG_HDRLEN..offset + len],
        });
        offset += align(len);
    }
    Ok(out)
}

/// A request: header, fixed payload, then attributes.
pub fn request(kind: u16, flags: u16, seq: u32, body: &[u8], attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = vec![0u8; NLMSG_HDRLEN];
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    for (kind, value) in attrs {
        let len = 4 + value.len();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }
    let total = out.len() as u32;
    out[0..4].copy_from_slice(&total.to_ne_bytes());
    out[4..6].copy_from_slice(&kind.to_ne_bytes());
    out[6..8].copy_from_slice(&flags.to_ne_bytes());
    out[8..12].copy_from_slice(&seq.to_ne_bytes());
    out
}

/// struct ifinfomsg with a family and an index.
pub fn ifinfomsg(family: u8, index: i32) -> [u8; 16] {
    let mut body = [0u8; 16];
    body[0] = family;
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body
}

/// struct ifaddrmsg with a family and an index (0: every link).
pub fn ifaddrmsg(family: u8, index: u32) -> [u8; 8] {
    let mut body = [0u8; 8];
    body[0] = family;
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    body
}

/// The errno of an NLMSG_ERROR payload (0 is an ACK).
pub fn error_code(payload: &[u8]) -> i32 {
    if payload.len() < 4 {
        return 0;
    }
    -i32::from_ne_bytes(payload[0..4].try_into().unwrap())
}

pub fn attributes(mut data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let kind = u16::from_ne_bytes([data[2], data[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > data.len() {
            break;
        }
        out.push((kind, &data[4..len]));
        let next = align(len).min(data.len());
        data = &data[next..];
    }
    out
}

fn u32_of(value: &[u8]) -> u32 {
    if value.len() >= 4 {
        u32::from_ne_bytes(value[0..4].try_into().unwrap())
    } else {
        0
    }
}

fn string_of(value: &[u8]) -> String {
    let end = value.iter().position(|byte| *byte == 0).unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).into_owned()
}

/// A link as the plugin API reports it, before names are resolved.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Link {
    pub index: i32,
    pub flags: u32,
    pub name: String,
    pub alias: String,
    pub mtu: u32,
    pub mac: Vec<u8>,
    pub oper_state: u8,
    pub parent_index: i32,
    pub master_index: i32,
    pub promiscuity: u32,
    pub gso_max_size: u32,
    pub gso_max_segs: u32,
    pub kind: Option<String>,
    pub vlan_id: u16,
    pub vlan_protocol: u16,
    pub vrf_table: u32,
    pub tun_type: u8,
    pub tun_vnet_hdr: bool,
    pub stats: Option<[u64; 8]>,
}

/// Parses an RTM_NEWLINK payload.
pub fn parse_link(payload: &[u8]) -> Option<Link> {
    if payload.len() < 16 {
        return None;
    }
    let mut link = Link {
        index: i32::from_ne_bytes(payload[4..8].try_into().unwrap()),
        flags: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
        ..Default::default()
    };
    for (kind, value) in attributes(&payload[16..]) {
        match kind {
            IFLA_ADDRESS => link.mac = value.to_vec(),
            IFLA_IFNAME => link.name = string_of(value),
            IFLA_MTU => link.mtu = u32_of(value),
            IFLA_LINK => link.parent_index = u32_of(value) as i32,
            IFLA_MASTER => link.master_index = u32_of(value) as i32,
            IFLA_OPERSTATE => link.oper_state = value.first().copied().unwrap_or(0),
            IFLA_IFALIAS => link.alias = string_of(value),
            IFLA_PROMISCUITY => link.promiscuity = u32_of(value),
            IFLA_GSO_MAX_SEGS => link.gso_max_segs = u32_of(value),
            IFLA_GSO_MAX_SIZE => link.gso_max_size = u32_of(value),
            IFLA_STATS64 if value.len() >= 64 => {
                let mut stats = [0u64; 8];
                for (i, slot) in stats.iter_mut().enumerate() {
                    *slot = u64::from_ne_bytes(value[i * 8..i * 8 + 8].try_into().unwrap());
                }
                link.stats = Some(stats);
            }
            IFLA_STATS if value.len() >= 32 && link.stats.is_none() => {
                let mut stats = [0u64; 8];
                for (i, slot) in stats.iter_mut().enumerate() {
                    *slot = u32_of(&value[i * 4..i * 4 + 4]) as u64;
                }
                link.stats = Some(stats);
            }
            IFLA_LINKINFO => parse_link_info(&mut link, value),
            _ => {}
        }
    }
    Some(link)
}

fn parse_link_info(link: &mut Link, value: &[u8]) {
    let info = attributes(value);
    for (kind, data) in &info {
        if *kind == IFLA_INFO_KIND {
            link.kind = Some(string_of(data));
        }
    }
    let Some(data) = info.iter().find(|(kind, _)| *kind == IFLA_INFO_DATA).map(|(_, data)| *data) else {
        return;
    };
    match link.kind.as_deref() {
        Some("vlan") => {
            for (kind, value) in attributes(data) {
                match kind {
                    IFLA_VLAN_ID if value.len() >= 2 => link.vlan_id = u16::from_ne_bytes([value[0], value[1]]),
                    IFLA_VLAN_PROTOCOL if value.len() >= 2 => link.vlan_protocol = u16::from_be_bytes([value[0], value[1]]),
                    _ => {}
                }
            }
        }
        Some("vrf") => {
            for (kind, value) in attributes(data) {
                if kind == IFLA_VRF_TABLE {
                    link.vrf_table = u32_of(value);
                }
            }
        }
        Some("tun") => {
            for (kind, value) in attributes(data) {
                match kind {
                    IFLA_TUN_TYPE => link.tun_type = value.first().copied().unwrap_or(0),
                    IFLA_TUN_VNET_HDR => link.tun_vnet_hdr = value.first() == Some(&1),
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

impl Link {
    /// vishvananda's Link.Type(): the kind, "tuntap" for tun, "device" for
    /// a link with no kind.
    pub fn type_name(&self) -> String {
        match self.kind.as_deref() {
            None | Some("") => "device".to_string(),
            Some("tun") => "tuntap".to_string(),
            Some(kind) => kind.to_string(),
        }
    }

    pub fn oper_state_name(&self) -> &'static str {
        match self.oper_state {
            1 => "not-present",
            2 => "down",
            3 => "lower-layer-down",
            4 => "testing",
            5 => "dormant",
            6 => "up",
            _ => "unknown",
        }
    }

    /// vishvananda keeps IFLA_ADDRESS only when a byte is non-zero, so the
    /// loopback reads as no address.
    pub fn mac_text(&self) -> String {
        if self.mac.iter().all(|byte| *byte == 0) {
            return String::new();
        }
        self.mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
    }

    pub fn vlan_protocol_name(&self) -> String {
        match self.vlan_protocol {
            0x8100 => "802.1q".to_string(),
            0x88a8 => "802.1ad".to_string(),
            other => format!("VlanProtocol({other})"),
        }
    }

    pub fn tun_mode(&self) -> &'static str {
        match self.tun_type {
            1 => "tun",
            2 => "tap",
            _ => "",
        }
    }
}

/// An interface address: its link and its text (address/prefix).
#[derive(Debug, Clone, PartialEq)]
pub struct Addr {
    pub index: u32,
    pub text: String,
}

/// Parses an RTM_NEWADDR payload: IFA_LOCAL when present, else IFA_ADDRESS,
/// as vishvananda's parseAddr picks the address of the IPNet.
pub fn parse_addr(payload: &[u8]) -> Option<Addr> {
    if payload.len() < 8 {
        return None;
    }
    let family = payload[0];
    let prefix = payload[1];
    let index = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
    let mut address = None;
    let mut local = None;
    for (kind, value) in attributes(&payload[8..]) {
        match kind {
            IFA_ADDRESS => address = Some(value),
            IFA_LOCAL => local = Some(value),
            _ => {}
        }
    }
    let bytes = local.or(address)?;
    let ip = match (family, bytes.len()) {
        (2, 4) => std::net::IpAddr::from(<[u8; 4]>::try_from(bytes).ok()?),
        (10, 16) => std::net::IpAddr::from(<[u8; 16]>::try_from(bytes).ok()?),
        _ => return None,
    };
    Some(Addr { index, text: format!("{ip}/{prefix}") })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    pub fn link_payload(index: i32, flags: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = ifinfomsg(0, index).to_vec();
        out[8..12].copy_from_slice(&flags.to_ne_bytes());
        for a in attrs {
            out.extend_from_slice(a);
        }
        out
    }

    #[test]
    fn parses_a_vlan_link() {
        let vlan_data = [attr(IFLA_VLAN_ID, &42u16.to_ne_bytes()), attr(IFLA_VLAN_PROTOCOL, &0x8100u16.to_be_bytes())].concat();
        let info = [attr(IFLA_INFO_KIND, b"vlan\0"), attr(IFLA_INFO_DATA, &vlan_data)].concat();
        let payload = link_payload(
            7,
            IFF_UP | IFF_NOARP,
            &[
                attr(IFLA_IFNAME, b"eth0.42\0"),
                attr(IFLA_MTU, &1500u32.to_ne_bytes()),
                attr(IFLA_ADDRESS, &[0x02, 0, 0, 0, 0, 0x2a]),
                attr(IFLA_LINK, &2u32.to_ne_bytes()),
                attr(IFLA_OPERSTATE, &[6]),
                attr(IFLA_LINKINFO, &info),
                attr(IFLA_GSO_MAX_SIZE, &65536u32.to_ne_bytes()),
            ],
        );
        let link = parse_link(&payload).unwrap();
        assert_eq!(link.index, 7);
        assert_eq!(link.name, "eth0.42");
        assert_eq!(link.type_name(), "vlan");
        assert_eq!(link.vlan_id, 42);
        assert_eq!(link.vlan_protocol_name(), "802.1q");
        assert_eq!(link.mac_text(), "02:00:00:00:00:2a");
        assert_eq!(link.oper_state_name(), "up");
        assert_eq!(link.parent_index, 2);
        assert_eq!(link.gso_max_size, 65536);
        assert!(link.stats.is_none());
    }

    #[test]
    fn kinds_follow_vishvananda() {
        let device = parse_link(&link_payload(1, 0, &[attr(IFLA_IFNAME, b"eth0\0")])).unwrap();
        assert_eq!(device.type_name(), "device");
        assert_eq!(device.mac_text(), "");
        let tun_data = [attr(IFLA_TUN_TYPE, &[1]), attr(IFLA_TUN_VNET_HDR, &[1])].concat();
        let info = [attr(IFLA_INFO_KIND, b"tun\0"), attr(IFLA_INFO_DATA, &tun_data)].concat();
        let tun = parse_link(&link_payload(3, 0, &[attr(IFLA_LINKINFO, &info)])).unwrap();
        assert_eq!(tun.type_name(), "tuntap");
        assert_eq!(tun.tun_mode(), "tun");
        assert!(tun.tun_vnet_hdr);
    }

    #[test]
    fn parses_addresses() {
        let mut v4 = ifaddrmsg(2, 5).to_vec();
        v4[1] = 24;
        v4.extend_from_slice(&attr(IFA_ADDRESS, &[10, 0, 0, 2]));
        v4.extend_from_slice(&attr(IFA_LOCAL, &[10, 0, 0, 1]));
        assert_eq!(parse_addr(&v4).unwrap(), Addr { index: 5, text: "10.0.0.1/24".to_string() });
        let mut v6 = ifaddrmsg(10, 5).to_vec();
        v6[1] = 64;
        let mut ip = [0u8; 16];
        ip[0] = 0xfe;
        ip[1] = 0x80;
        ip[15] = 1;
        v6.extend_from_slice(&attr(IFA_ADDRESS, &ip));
        assert_eq!(parse_addr(&v6).unwrap().text, "fe80::1/64");
    }

    #[test]
    fn splits_messages() {
        const NLM_F_MULTI: u16 = 2;
        let first = request(RTM_NEWLINK, NLM_F_MULTI, 9, &ifinfomsg(0, 1), &[(IFLA_IFNAME, b"lo\0")]);
        let second = request(NLMSG_DONE, NLM_F_MULTI, 9, &0i32.to_ne_bytes(), &[]);
        let buffer = [first, second].concat();
        let parsed = messages(&buffer).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, RTM_NEWLINK);
        assert_eq!(parsed[1].kind, NLMSG_DONE);
        assert_eq!(parse_link(parsed[0].payload).unwrap().name, "lo");
    }
}
