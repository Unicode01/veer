//! An rtnetlink socket per plugin instance, for the read-only link and
//! address queries the worker answers itself.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::rtattr::{self, Addr, Link};

const SOL_NETLINK: libc::c_int = 270;
const NETLINK_GET_STRICT_CHK: libc::c_int = 12;
const MAX_DUMP_ATTEMPTS: usize = 10;
const RTEXT_FILTER_VF: u32 = 1;
const IFLA_EXT_MASK: u16 = 29;

#[derive(Debug)]
pub enum NlError {
    Errno(i32),
    Malformed(String),
    Interrupted,
}

impl std::fmt::Display for NlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NlError::Errno(code) => f.write_str(&errno_text(*code)),
            NlError::Malformed(text) => f.write_str(text),
            NlError::Interrupted => f.write_str("netlink dump was interrupted too many times"),
        }
    }
}

/// An errno the way Go prints it ("no such device"), so error texts match the
/// host's.
pub fn errno_text(code: i32) -> String {
    let text = io::Error::from_raw_os_error(code).to_string();
    let text = match text.rfind(" (os error") {
        Some(end) => text[..end].to_string(),
        None => text,
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().collect::<String>() + chars.as_str(),
        None => text,
    }
}

pub struct Rtnl {
    fd: OwnedFd,
    seq: u32,
    strict: bool,
    buffer: Vec<u8>,
}

impl Rtnl {
    pub fn open() -> io::Result<Rtnl> {
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let bound = unsafe {
            libc::bind(fd.as_raw_fd(), &address as *const libc::sockaddr_nl as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_nl>() as u32)
        };
        if bound < 0 {
            return Err(io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let strict = unsafe {
            libc::setsockopt(fd.as_raw_fd(), SOL_NETLINK, NETLINK_GET_STRICT_CHK, &one as *const libc::c_int as *const libc::c_void, std::mem::size_of::<libc::c_int>() as u32)
        } == 0;
        Ok(Rtnl { fd, seq: 0, strict, buffer: vec![0u8; 64 << 10] })
    }

    /// Sends one request and collects the payloads of its replies, dumping
    /// again when the kernel marks a dump interrupted.
    fn exchange(&mut self, kind: u16, flags: u16, body: &[u8], attrs: &[(u16, &[u8])], reply_kind: u16) -> Result<Vec<Vec<u8>>, NlError> {
        for _ in 0..MAX_DUMP_ATTEMPTS {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            let message = rtattr::request(kind, flags | rtattr::NLM_F_REQUEST, seq, body, attrs);
            let sent = unsafe { libc::send(self.fd.as_raw_fd(), message.as_ptr() as *const libc::c_void, message.len(), 0) };
            if sent < 0 {
                return Err(NlError::Errno(io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)));
            }
            let dump = flags & rtattr::NLM_F_DUMP != 0;
            let mut out = Vec::new();
            let mut interrupted = false;
            'receive: loop {
                let received = unsafe { libc::recv(self.fd.as_raw_fd(), self.buffer.as_mut_ptr() as *mut libc::c_void, self.buffer.len(), 0) };
                if received < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(NlError::Errno(err.raw_os_error().unwrap_or(libc::EIO)));
                }
                let chunk = &self.buffer[..received as usize];
                for message in rtattr::messages(chunk).map_err(NlError::Malformed)? {
                    if message.seq != seq {
                        continue;
                    }
                    if message.flags & rtattr::NLM_F_DUMP_INTR != 0 {
                        interrupted = true;
                    }
                    match message.kind {
                        rtattr::NLMSG_DONE => break 'receive,
                        rtattr::NLMSG_ERROR => {
                            let code = rtattr::error_code(message.payload);
                            if code != 0 {
                                return Err(NlError::Errno(code));
                            }
                            break 'receive;
                        }
                        other if other == reply_kind => {
                            out.push(message.payload.to_vec());
                            if !dump {
                                break 'receive;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if !interrupted {
                return Ok(out);
            }
        }
        Err(NlError::Interrupted)
    }

    pub fn link_by_index(&mut self, index: i32) -> Result<Link, NlError> {
        let body = rtattr::ifinfomsg(libc::AF_UNSPEC as u8, index);
        let mask = RTEXT_FILTER_VF.to_ne_bytes();
        let replies = self.exchange(rtattr::RTM_GETLINK, 0, &body, &[(IFLA_EXT_MASK, &mask)], rtattr::RTM_NEWLINK)?;
        replies
            .first()
            .and_then(|payload| rtattr::parse_link(payload))
            .ok_or_else(|| NlError::Malformed("no link in the netlink reply".to_string()))
    }

    pub fn links(&mut self) -> Result<Vec<Link>, NlError> {
        let body = rtattr::ifinfomsg(libc::AF_UNSPEC as u8, 0);
        let mask = RTEXT_FILTER_VF.to_ne_bytes();
        let replies = self.exchange(rtattr::RTM_GETLINK, rtattr::NLM_F_DUMP, &body, &[(IFLA_EXT_MASK, &mask)], rtattr::RTM_NEWLINK)?;
        Ok(replies.iter().filter_map(|payload| rtattr::parse_link(payload)).collect())
    }

    /// Addresses of one link (or of every link), in kernel order. A strict
    /// socket filters in the kernel; otherwise the dump is filtered here.
    pub fn addresses(&mut self, index: Option<u32>) -> Result<Vec<Addr>, NlError> {
        let filter = if self.strict { index.unwrap_or(0) } else { 0 };
        let body = rtattr::ifaddrmsg(libc::AF_UNSPEC as u8, filter);
        let replies = self.exchange(rtattr::RTM_GETADDR, rtattr::NLM_F_DUMP, &body, &[], rtattr::RTM_NEWADDR)?;
        Ok(replies
            .iter()
            .filter_map(|payload| rtattr::parse_addr(payload))
            .filter(|addr| index.is_none_or(|want| addr.index == want))
            .collect())
    }
}

/// if_nametoindex, with ENODEV/ENXIO as None.
pub fn index_of(name: &str) -> Result<Option<i32>, i32> {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return Ok(None);
    };
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index != 0 {
        return Ok(Some(index as i32));
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODEV) | Some(libc::ENXIO) => Ok(None),
        Some(code) => Err(code),
        None => Ok(None),
    }
}
