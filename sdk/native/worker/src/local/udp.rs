//! net.udp.* in the worker: one datagram socket per call, bound to the
//! interface, as the host's udpSend/udpRecv/udpExchange do
//! (internal/app/plugin_control_runtime.go, plugin_control_udp_linux.go).

use std::net::{IpAddr, SocketAddr};

use veer_plugin::{Map, Value};

use super::fields::{self, field};
use super::{Failure, Local, Outcome};

const MAX_PAYLOAD_BYTES: usize = 64 << 10;
const DEFAULT_TIMEOUT_MS: i64 = 1000;
const MAX_TIMEOUT_MS: i64 = 30_000;

#[derive(Debug, Clone, Default)]
pub struct SendRequest {
    pub interface: String,
    pub local_ip: Option<IpAddr>,
    pub local_port: u16,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct RecvRequest {
    pub interface: String,
    pub local_ip: Option<IpAddr>,
    pub local_port: u16,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: u16,
    pub has_remote_filter: bool,
    pub timeout_ms: i64,
    pub max_bytes: usize,
}

/// Go's To4() != nil: IPv4, or IPv4-mapped IPv6.
fn is_v4(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    }
}

fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// net.IP.String().
pub fn ip_text(ip: IpAddr) -> String {
    unmapped(ip).to_string()
}

/// net.UDPAddr.String() of an address that may have no IP.
fn addr_text(ip: Option<IpAddr>, port: u16) -> String {
    match ip.map(unmapped) {
        None => format!(":{port}"),
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Some(v4) => format!("{v4}:{port}"),
    }
}

fn host_namespace(object: &Value) -> Option<()> {
    let namespace = ["namespace", "netns"].iter().map(|name| fields::optional_string(object, name)).find(|text| !text.is_empty()).unwrap_or_default();
    let namespace = namespace.to_ascii_lowercase();
    (namespace.is_empty() || namespace == "host").then_some(())
}

/// optionalUDPInterfaceObjectField.
fn interface_field(object: &Value, fallback: &str) -> Result<String, Failure> {
    let mut value = fallback.trim().to_string();
    let current = fields::optional_string(object, "interface");
    if !current.is_empty() {
        value = current;
    }
    if value.is_empty() {
        return Err(Failure::error("interface is required"));
    }
    if value.contains('\0') || value.contains(['/', '\\', ' ', '\t', '\r', '\n']) || value.len() > 15 {
        return Err(Failure::error("interface contains invalid characters or exceeds 15 bytes"));
    }
    Ok(value)
}

/// optionalIPObjectFieldWithDefault.
fn ip_field(object: &Value, fallback: Option<IpAddr>, names: &[&str]) -> Result<Option<IpAddr>, Failure> {
    for name in names {
        let raw = fields::optional_string(object, name);
        if raw.is_empty() {
            continue;
        }
        return raw.parse::<IpAddr>().map(Some).map_err(|_| Failure::error(format!("{name} must be a valid IP address")));
    }
    Ok(fallback)
}

/// optionalPortObjectField.
fn port_field(object: &Value, fallback: u16, names: &[&str]) -> Result<u16, Failure> {
    for name in names {
        let Some(raw) = field(object, name) else {
            continue;
        };
        let value = fields::integer(raw);
        if !(0..=65535).contains(&value) {
            return Err(Failure::error(format!("{name} must be between 0 and 65535")));
        }
        return Ok(value as u16);
    }
    Ok(fallback)
}

/// udpTimeoutObjectField.
fn timeout_field(local: &Local, object: &Value) -> Result<i64, Failure> {
    let mut timeout = DEFAULT_TIMEOUT_MS;
    if let Some(raw) = field(object, "timeout_ms") {
        timeout = fields::integer(raw);
        if timeout <= 0 || timeout > MAX_TIMEOUT_MS {
            return Err(Failure::error(format!("net.udp timeout_ms must be between 1 and {MAX_TIMEOUT_MS}")));
        }
    }
    local.bounded_timeout(timeout, "net.udp")
}

fn send_request(local: &Local, object: &Value) -> Result<SendRequest, Failure> {
    let payload = fields::optional_hex(object, &["payload", "payload_hex"])?.unwrap_or_default();
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Failure::error(format!("net.udp.send: payload exceeds {MAX_PAYLOAD_BYTES} bytes")));
    }
    let interface = interface_field(object, "")?;
    let local_ip = ip_field(object, None, &["local_ip", "bind_ip", "source_ip"])?;
    let local_port = port_field(object, 0, &["local_port", "bind_port", "source_port"])?;
    let remote_ip = ip_field(object, None, &["remote_ip", "dst_ip", "target_ip"])?;
    if remote_ip.is_none() {
        return Err(Failure::error("remote_ip is required"));
    }
    let remote_port = port_field(object, 0, &["remote_port", "dst_port", "target_port", "port"])?;
    if remote_port == 0 {
        return Err(Failure::error("remote_port is required"));
    }
    // Validated like the host; a datagram send does not wait.
    timeout_field(local, object)?;
    Ok(SendRequest { interface, local_ip, local_port, remote_ip, remote_port, payload })
}

/// udpRecvRequestFromObjectWithDefaults.
fn recv_request(local: &Local, object: &Value, defaults: (&str, Option<IpAddr>, u16), require_local_port: bool, allow_port_alias: bool) -> Result<RecvRequest, Failure> {
    let mut max_bytes = 2048i64;
    if let Some(raw) = field(object, "max_bytes") {
        max_bytes = fields::integer(raw);
        if !(1..=MAX_PAYLOAD_BYTES as i64).contains(&max_bytes) {
            return Err(Failure::error(format!("net.udp.recv max_bytes must be between 1 and {MAX_PAYLOAD_BYTES}")));
        }
    }
    let mut port_fields = vec!["local_port", "bind_port"];
    if allow_port_alias {
        port_fields.push("port");
    }
    let local_port = port_field(object, defaults.2, &port_fields)?;
    if require_local_port && local_port == 0 {
        return Err(Failure::error("net.udp.recv: local_port is required"));
    }
    let interface = interface_field(object, defaults.0)?;
    let local_ip = ip_field(object, defaults.1, &["local_ip", "bind_ip"])?;
    let timeout_ms = timeout_field(local, object)?;
    let mut request = RecvRequest { interface, local_ip, local_port, timeout_ms, max_bytes: max_bytes as usize, ..Default::default() };
    if let Some(ip) = ip_field(object, None, &["remote_ip", "src_ip", "peer_ip"])? {
        request.remote_ip = Some(ip);
        request.has_remote_filter = true;
    }
    let remote_port = port_field(object, 0, &["remote_port", "src_port", "peer_port"])?;
    if remote_port > 0 {
        request.remote_port = remote_port;
        request.has_remote_filter = true;
    }
    Ok(request)
}

fn endpoint_check(local: &Local, interface: &str, ip: Option<IpAddr>, port: u16, api: &str) -> Result<(), Failure> {
    local.policy().endpoint("udp", interface, "", ip, port as i64).map(|_| ()).map_err(|err| Failure::error(format!("{api}: {err}")))
}

pub struct Datagram {
    pub interface: String,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub payload: Vec<u8>,
}

fn addresses(out: &mut Map<String, Value>, local: SocketAddr, remote: SocketAddr) {
    out.insert("local_ip".into(), Value::from(ip_text(local.ip())));
    out.insert("local_port".into(), Value::from(local.port()));
    out.insert("local_addr".into(), Value::from(addr_text(Some(local.ip()), local.port())));
    out.insert("remote_ip".into(), Value::from(ip_text(remote.ip())));
    out.insert("remote_port".into(), Value::from(remote.port()));
    out.insert("remote_addr".into(), Value::from(addr_text(Some(remote.ip()), remote.port())));
}

/// udpDatagramObject.
fn datagram_json(datagram: &Datagram) -> Value {
    let mut out = Map::new();
    out.insert("namespace".into(), Value::from("host"));
    out.insert("interface".into(), Value::from(datagram.interface.clone()));
    out.insert("payload_hex".into(), Value::from(fields::hex(&datagram.payload)));
    out.insert("bytes".into(), Value::from(datagram.payload.len()));
    addresses(&mut out, datagram.local, datagram.remote);
    Value::Object(out)
}

macro_rules! prepare {
    ($local:expr, $kind:expr, $args:expr) => {{
        if let Err(failure) = $local.policy().require($kind, "net.udp") {
            return Some(Err(failure));
        }
        let object = match fields::required_object($args, 0, "request") {
            Ok(object) => object,
            Err(failure) => return Some(Err(failure)),
        };
        host_namespace(object)?;
        object
    }};
}

pub fn send(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    let object = prepare!(local, kind, args);
    Some((|| {
        let request = send_request(local, object)?;
        local.policy().require_net_access("udp", &request.interface, "net.udp.send")?;
        endpoint_check(local, &request.interface, request.remote_ip, request.remote_port, "net.udp.send")?;
        let (local_addr, remote, bytes) = system::send(&request).map_err(|err| Failure::error(format!("net.udp.send: {err}")))?;
        let mut out = Map::new();
        out.insert("namespace".into(), Value::from("host"));
        out.insert("interface".into(), Value::from(request.interface.clone()));
        out.insert("bytes".into(), Value::from(bytes));
        addresses(&mut out, local_addr, remote);
        Ok(Value::Object(out))
    })())
}

pub fn recv(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    let object = prepare!(local, kind, args);
    Some((|| {
        let request = recv_request(local, object, ("", None, 0), true, true)?;
        local.policy().require_net_access("udp", &request.interface, "net.udp.recv")?;
        if request.has_remote_filter {
            endpoint_check(local, &request.interface, request.remote_ip, request.remote_port, "net.udp.recv")?;
        }
        let Some(datagram) = system::recv(&request, None).map_err(|err| Failure::error(format!("net.udp.recv: {err}")))? else {
            return Ok(Value::Null);
        };
        endpoint_check(local, &request.interface, Some(datagram.remote.ip()), datagram.remote.port(), "net.udp.recv")?;
        Ok(datagram_json(&datagram))
    })())
}

pub fn exchange(local: &Local, kind: u32, args: &[Value]) -> Option<Outcome> {
    let object = prepare!(local, kind, args);
    Some((|| {
        let send = send_request(local, object)?;
        let mut recv = recv_request(local, object, (&send.interface, send.local_ip, send.local_port), false, false)?;
        if recv.remote_ip.is_none() {
            recv.remote_ip = send.remote_ip;
        }
        if recv.remote_port == 0 {
            recv.remote_port = send.remote_port;
        }
        recv.has_remote_filter = true;
        if send.interface != recv.interface {
            return Err(Failure::error("net.udp.exchange: send and receive interface must match"));
        }
        local.policy().require_net_access("udp", &send.interface, "net.udp.exchange")?;
        endpoint_check(local, &send.interface, send.remote_ip, send.remote_port, "net.udp.exchange")?;
        let Some(datagram) = system::recv(&recv, Some(&send)).map_err(|err| Failure::error(format!("net.udp.exchange: {err}")))? else {
            return Ok(Value::Null);
        };
        endpoint_check(local, &send.interface, Some(datagram.remote.ip()), datagram.remote.port(), "net.udp.exchange")?;
        Ok(datagram_json(&datagram))
    })())
}

#[cfg(target_os = "linux")]
mod system {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use super::super::rtnl::errno_text;
    use super::*;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
    }

    fn sockaddr(addr: SocketAddr, v6: bool) -> (libc::sockaddr_storage, u32) {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        if v6 {
            let ip = match addr.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let sin6 = unsafe { &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as u16;
            sin6.sin6_port = addr.port().to_be();
            sin6.sin6_addr.s6_addr = ip.octets();
            (storage, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        } else {
            let ip = match unmapped(addr.ip()) {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };
            let sin = unsafe { &mut *(&mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as u16;
            sin.sin_port = addr.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
            (storage, std::mem::size_of::<libc::sockaddr_in>() as u32)
        }
    }

    fn from_sockaddr(storage: &libc::sockaddr_storage) -> SocketAddr {
        unsafe {
            if storage.ss_family as i32 == libc::AF_INET6 {
                let sin6 = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6);
                let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                SocketAddr::new(unmapped(IpAddr::V6(ip)), u16::from_be(sin6.sin6_port))
            } else {
                let sin = &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in);
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())), u16::from_be(sin.sin_port))
            }
        }
    }

    struct Socket {
        fd: OwnedFd,
        v6: bool,
        network: &'static str,
    }

    impl Socket {
        fn local(&self) -> SocketAddr {
            let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            unsafe { libc::getsockname(self.fd.as_raw_fd(), &mut storage as *mut libc::sockaddr_storage as *mut libc::sockaddr, &mut len) };
            from_sockaddr(&storage)
        }
    }

    /// listenPluginControlUDP with Go's datagram defaults: broadcast on,
    /// IPV6_V6ONLY for udp6, then SO_BINDTODEVICE and bind.
    fn listen(interface: &str, local_ip: Option<IpAddr>, local_port: u16, remote_ip: Option<IpAddr>) -> Result<Socket, String> {
        let v6 = remote_ip.is_some_and(|ip| !is_v4(ip)) || local_ip.is_some_and(|ip| !is_v4(ip));
        let network = if v6 { "udp6" } else { "udp4" };
        let label = format!("listen {network} {}", addr_text(local_ip, local_port));
        let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let raw = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(format!("{label}: socket: {}", errno_text(errno())));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let one: libc::c_int = 1;
        let set = |level: libc::c_int, option: libc::c_int, value: *const libc::c_void, len: u32| unsafe { libc::setsockopt(fd.as_raw_fd(), level, option, value, len) };
        let int_len = std::mem::size_of::<libc::c_int>() as u32;
        if v6 && set(libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &one as *const libc::c_int as *const libc::c_void, int_len) < 0 {
            return Err(format!("{label}: setsockopt: {}", errno_text(errno())));
        }
        if set(libc::SOL_SOCKET, libc::SO_BROADCAST, &one as *const libc::c_int as *const libc::c_void, int_len) < 0 {
            return Err(format!("{label}: setsockopt: {}", errno_text(errno())));
        }
        if !interface.is_empty() && set(libc::SOL_SOCKET, libc::SO_BINDTODEVICE, interface.as_ptr() as *const libc::c_void, interface.len() as u32) < 0 {
            return Err(format!("{label}: setsockopt: {}", errno_text(errno())));
        }
        let bind_ip = local_ip.unwrap_or(if v6 { IpAddr::V6(Ipv6Addr::UNSPECIFIED) } else { IpAddr::V4(Ipv4Addr::UNSPECIFIED) });
        let (address, len) = sockaddr(SocketAddr::new(bind_ip, local_port), v6);
        if unsafe { libc::bind(fd.as_raw_fd(), &address as *const libc::sockaddr_storage as *const libc::sockaddr, len) } < 0 {
            return Err(format!("{label}: bind: {}", errno_text(errno())));
        }
        Ok(Socket { fd, v6, network })
    }

    fn write(socket: &Socket, remote: SocketAddr, payload: &[u8]) -> Result<usize, String> {
        let (address, len) = sockaddr(remote, socket.v6);
        let sent = unsafe {
            libc::sendto(socket.fd.as_raw_fd(), payload.as_ptr() as *const libc::c_void, payload.len(), 0, &address as *const libc::sockaddr_storage as *const libc::sockaddr, len)
        };
        if sent < 0 {
            let local = socket.local();
            return Err(format!(
                "write {} {}->{}: sendto: {}",
                socket.network,
                addr_text(Some(local.ip()), local.port()),
                addr_text(Some(remote.ip()), remote.port()),
                errno_text(errno())
            ));
        }
        Ok(sent as usize)
    }

    fn remote_of(request: &SendRequest) -> SocketAddr {
        SocketAddr::new(request.remote_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), request.remote_port)
    }

    pub fn send(request: &SendRequest) -> Result<(SocketAddr, SocketAddr, usize), String> {
        let socket = listen(&request.interface, request.local_ip, request.local_port, request.remote_ip)?;
        let remote = remote_of(request);
        let sent = write(&socket, remote, &request.payload)?;
        Ok((socket.local(), SocketAddr::new(unmapped(remote.ip()), remote.port()), sent))
    }

    /// recvPluginControlUDPDatagram, after an optional send on the socket.
    pub fn recv(request: &RecvRequest, send: Option<&SendRequest>) -> Result<Option<Datagram>, String> {
        let socket = match send {
            Some(send) => listen(&send.interface, send.local_ip, send.local_port, send.remote_ip)?,
            None => listen(&request.interface, request.local_ip, request.local_port, request.remote_ip)?,
        };
        if let Some(send) = send {
            write(&socket, remote_of(send), &send.payload)?;
        }
        let until = Instant::now() + Duration::from_millis(request.timeout_ms as u64);
        let mut buffer = vec![0u8; request.max_bytes];
        loop {
            let remaining = until.saturating_duration_since(Instant::now()).as_millis() as i64;
            if remaining <= 0 {
                return Ok(None);
            }
            let mut poll = libc::pollfd { fd: socket.fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let ready = unsafe { libc::poll(&mut poll, 1, remaining.min(i32::MAX as i64) as i32) };
            if ready < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return Err(format!("read {}: poll: {}", socket.network, errno_text(errno())));
            }
            if ready == 0 {
                return Ok(None);
            }
            let mut from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut from_len = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            let read = unsafe {
                libc::recvfrom(socket.fd.as_raw_fd(), buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0, &mut from as *mut libc::sockaddr_storage as *mut libc::sockaddr, &mut from_len)
            };
            if read < 0 {
                match errno() {
                    libc::EINTR | libc::EAGAIN => continue,
                    code => {
                        let local = socket.local();
                        return Err(format!("read {} {}: recvfrom: {}", socket.network, addr_text(Some(local.ip()), local.port()), errno_text(code)));
                    }
                }
            }
            let remote = from_sockaddr(&from);
            if request.has_remote_filter {
                if request.remote_ip.is_some_and(|ip| unmapped(ip) != remote.ip()) {
                    continue;
                }
                if request.remote_port > 0 && request.remote_port != remote.port() {
                    continue;
                }
            }
            return Ok(Some(Datagram { interface: request.interface.clone(), local: socket.local(), remote, payload: buffer[..read as usize].to_vec() }));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod system {
    use super::*;

    pub fn send(_: &SendRequest) -> Result<(SocketAddr, SocketAddr, usize), String> {
        Err("udp sockets are only available on Linux".to_string())
    }

    pub fn recv(_: &RecvRequest, _: Option<&SendRequest>) -> Result<Option<Datagram>, String> {
        Err("udp sockets are only available on Linux".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    fn local() -> Local {
        Local::new(&json!({"permissions": ["net.udp"], "net_access": [{"interfaces": ["lo"], "operations": ["udp"], "remote_cidrs": ["127.0.0.0/8"], "remote_ports": [53]}]}))
    }

    #[test]
    fn requests_parse_like_the_host() {
        let local = local();
        let send = send_request(&local, &json!({"interface": "lo", "dst_ip": "127.0.0.1", "port": 53, "payload_hex": "0a"})).unwrap();
        assert_eq!(send.remote_port, 53);
        assert_eq!(send.payload, vec![10]);
        assert!(send_request(&local, &json!({"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 53, "timeout_ms": 0})).is_err());
        assert_eq!(send_request(&local, &json!({"interface": "lo", "remote_port": 53})).unwrap_err().message, "remote_ip is required");
        assert_eq!(send_request(&local, &json!({"interface": "lo", "remote_ip": "x"})).unwrap_err().message, "remote_ip must be a valid IP address");
        assert_eq!(send_request(&local, &json!({"remote_ip": "127.0.0.1"})).unwrap_err().message, "interface is required");
        assert_eq!(recv_request(&local, &json!({"interface": "lo"}), ("", None, 0), true, true).unwrap_err().message, "net.udp.recv: local_port is required");
        let recv = recv_request(&local, &json!({"interface": "lo", "port": 5353, "src_ip": "127.0.0.1"}), ("", None, 0), true, true).unwrap();
        assert_eq!(recv.local_port, 5353);
        assert!(recv.has_remote_filter);
        assert_eq!(addr_text(None, 0), ":0");
        assert_eq!(addr_text(Some("::1".parse().unwrap()), 53), "[::1]:53");
    }

    #[test]
    fn endpoints_are_checked() {
        let local = local();
        let request = json!({"interface": "lo", "remote_ip": "10.0.0.1", "remote_port": 53});
        assert!(send(&local, 0, &[request]).unwrap().unwrap_err().message.contains("outside remote_cidrs"));
        let request = json!({"interface": "lo", "remote_ip": "127.0.0.1", "remote_port": 54});
        assert!(send(&local, 0, &[request]).unwrap().unwrap_err().message.contains("not declared"));
        assert!(send(&local, 0, &[json!({"interface": "lo", "netns": "dns"})]).is_none());
    }
}
