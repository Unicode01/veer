//! Worker process: one control socket to the host (fd 3), plus one socket
//! per plugin instance that the host passes along with each LOAD frame.
//!
//! The control socket carries LOAD and SHUTDOWN from the host, and HELLO,
//! POST and LOG to it. Each instance socket is request/response only: the
//! host writes MSG, CALL_REPLY and UNLOAD; the instance's dispatch thread
//! writes LOADED, RESULT, CALL and UNLOADED. A message therefore costs one
//! wake-up in each direction, with no thread in between.

use std::collections::{HashMap, VecDeque};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io::{self, BufReader, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

use veer_plugin::sys::*;
use veer_plugin::Value;

use crate::frame::{self, Frame};
use crate::local::Local;

const MAX_HOST_FRAME: usize = 72 << 20;
const MAX_KEPT_REPLY_BUFFER: usize = 256 << 10;
const RTLD_NOW: c_int = 2;
const PR_SET_PDEATHSIG: c_int = 1;
const PR_SET_NO_NEW_PRIVS: c_int = 38;
const SIGKILL: u64 = 9;
const CLOCK_MONOTONIC: c_int = 1;
const SOL_SOCKET: c_int = 1;
const SCM_RIGHTS: c_int = 1;
const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
const EINTR: i32 = 4;

#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct Iovec {
    base: *mut c_void,
    len: usize,
}

// The 64-bit little-endian glibc and musl layouts agree: musl's int-sized
// length fields are followed by zero padding.
#[repr(C)]
struct Msghdr {
    name: *mut c_void,
    namelen: u32,
    iov: *mut Iovec,
    iovlen: usize,
    control: *mut c_void,
    controllen: usize,
    flags: c_int,
}

#[repr(C)]
struct Cmsghdr {
    len: usize,
    level: c_int,
    kind: c_int,
}

extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *mut c_char;
    fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn prctl(option: c_int, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> c_int;
    fn clock_gettime(clock: c_int, out: *mut Timespec) -> c_int;
    fn getpid() -> c_int;
    fn recvmsg(fd: c_int, msg: *mut Msghdr, flags: c_int) -> isize;
    fn close(fd: c_int) -> c_int;
}

// glibc before 2.34 keeps dlopen in libdl; musl has it in libc.
#[cfg(target_env = "gnu")]
#[link(name = "dl")]
extern "C" {}

/// The control socket writer; POST and LOG may come from any thread.
struct Control {
    stream: Mutex<UnixStream>,
}

impl Control {
    fn send(&self, kind: u8, instance: u32, status: i32, payload: &[u8]) -> bool {
        let bytes = frame::encode(kind, instance, 0, 0, status, b"", payload);
        let mut stream = self.stream.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        stream.write_all(&bytes).is_ok()
    }
}

/// Reads frames from the control socket with recvmsg, collecting the
/// descriptors the host attaches to LOAD frames in arrival order.
struct ControlReader {
    fd: RawFd,
    buffer: Vec<u8>,
    start: usize,
    fds: VecDeque<RawFd>,
}

impl ControlReader {
    fn fill(&mut self) -> io::Result<()> {
        if self.start > 0 && self.start == self.buffer.len() {
            self.buffer.clear();
            self.start = 0;
        }
        let mut chunk = vec![0u8; 64 << 10];
        let mut control = [0u64; 32];
        loop {
            let mut iov = Iovec { base: chunk.as_mut_ptr() as *mut c_void, len: chunk.len() };
            let mut header = Msghdr {
                name: std::ptr::null_mut(),
                namelen: 0,
                iov: &mut iov,
                iovlen: 1,
                control: control.as_mut_ptr() as *mut c_void,
                controllen: std::mem::size_of_val(&control),
                flags: 0,
            };
            let received = unsafe { recvmsg(self.fd, &mut header, MSG_CMSG_CLOEXEC) };
            if received < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(EINTR) {
                    continue;
                }
                return Err(err);
            }
            if received == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "host closed the control socket"));
            }
            self.collect_fds(&header, control.as_ptr() as *const u8);
            self.buffer.extend_from_slice(&chunk[..received as usize]);
            return Ok(());
        }
    }

    fn collect_fds(&mut self, header: &Msghdr, control: *const u8) {
        let header_len = std::mem::size_of::<Cmsghdr>();
        let mut offset = 0usize;
        while offset + header_len <= header.controllen {
            let cmsg = unsafe { &*(control.add(offset) as *const Cmsghdr) };
            if cmsg.len < header_len {
                break;
            }
            if cmsg.level == SOL_SOCKET && cmsg.kind == SCM_RIGHTS {
                let count = (cmsg.len - header_len) / std::mem::size_of::<c_int>();
                for i in 0..count {
                    let fd = unsafe { *(control.add(offset + header_len + i * 4) as *const c_int) };
                    self.fds.push_back(fd);
                }
            }
            offset += (cmsg.len + 7) & !7;
        }
    }

    fn read_frame(&mut self) -> io::Result<Frame> {
        loop {
            let available = &self.buffer[self.start..];
            if available.len() >= 4 {
                let length = u32::from_le_bytes(available[0..4].try_into().unwrap()) as usize;
                if !(frame::HEADER_LEN..=MAX_HOST_FRAME).contains(&length) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, format!("control frame length {length} is out of range")));
                }
                if available.len() >= 4 + length {
                    let mut slice = &available[..4 + length];
                    let parsed = frame::read_frame(&mut slice, MAX_HOST_FRAME)?;
                    self.start += 4 + length;
                    return Ok(parsed);
                }
            }
            self.fill()?;
        }
    }
}

pub fn run() -> i32 {
    unsafe {
        // Die with the host, and never gain privileges through exec.
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }
    let fd: RawFd = std::env::var("VEER_PLUGIN_WORKER_FD").ok().and_then(|value| value.parse().ok()).unwrap_or(3);
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let control = Arc::new(Control { stream: Mutex::new(stream) });
    if !control.send(frame::HELLO, 0, 0, hello_payload().as_bytes()) {
        eprintln!("veer-plugin-worker: host socket is closed");
        return 1;
    }
    let libraries: Libraries = Arc::new(Mutex::new(HashMap::new()));
    let mut reader = ControlReader { fd, buffer: Vec::new(), start: 0, fds: VecDeque::new() };
    loop {
        let incoming = match reader.read_frame() {
            Ok(incoming) => incoming,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return 0,
            Err(err) => {
                eprintln!("veer-plugin-worker: read control frame: {err}");
                return 1;
            }
        };
        match incoming.kind {
            frame::LOAD => {
                let Some(instance_fd) = reader.fds.pop_front() else {
                    eprintln!("veer-plugin-worker: LOAD frame without an instance socket");
                    return 1;
                };
                let socket = unsafe { UnixStream::from_raw_fd(instance_fd) };
                let instance = incoming.instance;
                let thread_control = control.clone();
                let thread_libraries = libraries.clone();
                let spawned = thread::Builder::new()
                    .name(format!("veer-plugin-{instance}"))
                    .spawn(move || run_instance(incoming, socket, thread_control, thread_libraries));
                if let Err(err) = spawned {
                    eprintln!("veer-plugin-worker: spawn instance thread: {err}");
                }
            }
            frame::SHUTDOWN => return 0,
            other => {
                eprintln!("veer-plugin-worker: unexpected control frame type {other}");
                return 1;
            }
        }
        // Descriptors that arrived without a LOAD frame are not ours to keep.
        while reader.fds.len() > 64 {
            if let Some(stray) = reader.fds.pop_front() {
                unsafe { close(stray) };
            }
        }
    }
}

fn hello_payload() -> String {
    let pid = unsafe { getpid() };
    veer_plugin::json!({
        "abi_major": VEER_PLUGIN_ABI_MAJOR,
        "abi_minor": VEER_PLUGIN_ABI_MINOR,
        "version": env!("CARGO_PKG_VERSION"),
        "pid": pid,
    })
    .to_string()
}

/// The instance socket, used only by the dispatch thread.
struct Channel {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Channel {
    fn send(&mut self, kind: u8, instance: u32, id: u64, reference: u64, status: i32, name: &[u8], payload: &[u8]) -> bool {
        let bytes = frame::encode(kind, instance, id, reference, status, name, payload);
        self.writer.write_all(&bytes).is_ok()
    }

    fn receive(&mut self) -> io::Result<Frame> {
        frame::read_frame(&mut self.reader, MAX_HOST_FRAME)
    }
}

/// Per-instance state the host table points at. `channel`, `current_request`,
/// `current_kind`, `next_call`, `deferred`, `unloading` and `local` are only
/// touched on the dispatch thread; log and post, which any thread may call,
/// only use `control`.
struct HostCtx {
    instance: u32,
    control: Arc<Control>,
    channel: std::cell::RefCell<Channel>,
    dispatch_thread: ThreadId,
    current_request: std::cell::Cell<u64>,
    current_kind: std::cell::Cell<u32>,
    next_call: std::cell::Cell<u64>,
    deferred: std::cell::RefCell<VecDeque<Frame>>,
    unloading: std::cell::Cell<bool>,
    local: Local,
}

unsafe impl Sync for HostCtx {}
unsafe impl Send for HostCtx {}

struct Glue {
    table: veer_host_v1,
    ctx: HostCtx,
}

type Libraries = Arc<Mutex<HashMap<String, String>>>;

unsafe fn reserve(buf: *mut veer_buf, cap: usize) -> i32 {
    if buf.is_null() {
        return VEER_EINVAL;
    }
    if cap == 0 {
        if !(*buf).data.is_null() {
            free((*buf).data as *mut c_void);
        }
        (*buf).data = std::ptr::null_mut();
        (*buf).len = 0;
        (*buf).cap = 0;
        return VEER_OK;
    }
    if cap <= (*buf).cap && !(*buf).data.is_null() {
        return VEER_OK;
    }
    let grown = realloc((*buf).data as *mut c_void, cap) as *mut u8;
    if grown.is_null() {
        return VEER_ENOMEM;
    }
    (*buf).data = grown;
    (*buf).cap = cap;
    if (*buf).len > cap {
        (*buf).len = cap;
    }
    VEER_OK
}

unsafe fn fill(buf: *mut veer_buf, bytes: &[u8]) -> i32 {
    if buf.is_null() {
        return VEER_EINVAL;
    }
    if bytes.is_empty() {
        (*buf).len = 0;
        return VEER_OK;
    }
    let status = reserve(buf, bytes.len());
    if status != VEER_OK {
        return status;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*buf).data, bytes.len());
    (*buf).len = bytes.len();
    VEER_OK
}

unsafe extern "C" fn host_call(ctx: *mut c_void, method: veer_slice, arguments: veer_slice, reply: *mut veer_buf) -> i32 {
    let ctx = &*(ctx as *const HostCtx);
    if thread::current().id() != ctx.dispatch_thread || ctx.current_request.get() == 0 {
        fill(reply, b"host calls are only allowed inside handle() on the dispatch thread");
        return VEER_EPERM;
    }
    if ctx.unloading.get() {
        fill(reply, b"plugin instance is unloading");
        return VEER_ESHUTDOWN;
    }
    // Methods that are only system calls run here, without the host.
    if let Ok(name) = std::str::from_utf8(method.as_bytes()) {
        if let Some((status, bytes)) = ctx.local.call(ctx.current_kind.get(), name, arguments.as_bytes()) {
            let filled = fill(reply, &bytes);
            return if filled != VEER_OK { filled } else { status };
        }
    }
    let call_id = ctx.next_call.get() + 1;
    ctx.next_call.set(call_id);
    let mut channel = ctx.channel.borrow_mut();
    if !channel.send(frame::CALL, ctx.instance, call_id, ctx.current_request.get(), 0, method.as_bytes(), arguments.as_bytes()) {
        fill(reply, b"host connection closed");
        return VEER_ESHUTDOWN;
    }
    loop {
        let incoming = match channel.receive() {
            Ok(incoming) => incoming,
            Err(_) => {
                fill(reply, b"host connection closed");
                return VEER_ESHUTDOWN;
            }
        };
        match incoming.kind {
            frame::CALL_REPLY if incoming.reference == call_id => {
                let status = fill(reply, &incoming.payload);
                return if status != VEER_OK { status } else { incoming.status };
            }
            frame::CALL_REPLY => {}
            frame::MSG => {
                // The host never nests messages for a native instance.
                channel.send(frame::RESULT, ctx.instance, 0, incoming.id, VEER_EPERM, b"", b"nested messages are not supported");
            }
            frame::UNLOAD => {
                ctx.unloading.set(true);
                ctx.deferred.borrow_mut().push_back(incoming);
                fill(reply, b"plugin instance is unloading");
                return VEER_ESHUTDOWN;
            }
            _ => {}
        }
    }
}

unsafe extern "C" fn host_log(ctx: *mut c_void, level: i32, message: veer_slice) {
    let ctx = &*(ctx as *const HostCtx);
    ctx.control.send(frame::LOG, ctx.instance, level, message.as_bytes());
}

unsafe extern "C" fn host_post(ctx: *mut c_void, payload: veer_slice) -> i32 {
    let ctx = &*(ctx as *const HostCtx);
    if ctx.control.send(frame::POST, ctx.instance, 0, payload.as_bytes()) {
        VEER_OK
    } else {
        VEER_ESHUTDOWN
    }
}

unsafe extern "C" fn host_buf_reserve(_ctx: *mut c_void, buf: *mut veer_buf, cap: usize) -> i32 {
    reserve(buf, cap)
}

unsafe extern "C" fn host_monotonic_ns(_ctx: *mut c_void) -> u64 {
    let mut now = Timespec { tv_sec: 0, tv_nsec: 0 };
    if clock_gettime(CLOCK_MONOTONIC, &mut now) != 0 {
        return 0;
    }
    (now.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(now.tv_nsec as u64)
}

fn dl_error() -> String {
    unsafe {
        let text = dlerror();
        if text.is_null() {
            "unknown dynamic loader error".to_string()
        } else {
            CStr::from_ptr(text).to_string_lossy().into_owned()
        }
    }
}

/// Status the host reads as "restart this worker": a library file changed
/// after this process already mapped an older copy of it.
const STATUS_RESTART_REQUIRED: i32 = VEER_ESHUTDOWN;

fn load_library(path: &str, digest: &str, libraries: &Libraries) -> Result<*const veer_plugin_v1, (i32, String)> {
    {
        let loaded = libraries.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(previous) = loaded.get(path) {
            if previous != digest {
                return Err((STATUS_RESTART_REQUIRED, format!("{path} changed after this worker loaded it")));
            }
        }
    }
    let c_path = CString::new(path).map_err(|_| (VEER_EINVAL, "library path contains NUL".to_string()))?;
    let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_NOW) };
    if handle.is_null() {
        return Err((VEER_ERROR, format!("dlopen {path}: {}", dl_error())));
    }
    let symbol = unsafe { dlsym(handle, c"veer_plugin_entry".as_ptr()) };
    if symbol.is_null() {
        return Err((VEER_ERROR, format!("{path} does not export veer_plugin_entry")));
    }
    let entry: veer_plugin_entry_fn = unsafe { std::mem::transmute::<*mut c_void, veer_plugin_entry_fn>(symbol) };
    let table = unsafe { entry(VEER_PLUGIN_ABI_MAJOR) };
    if table.is_null() {
        return Err((VEER_ERROR, format!("{path} does not support plugin ABI {VEER_PLUGIN_ABI_MAJOR}")));
    }
    let table_ref = unsafe { &*table };
    if (table_ref.struct_size as usize) < std::mem::size_of::<veer_plugin_v1>() || table_ref.abi_major != VEER_PLUGIN_ABI_MAJOR {
        return Err((VEER_ERROR, format!("{path} returned an incompatible plugin table")));
    }
    if table_ref.create.is_none() || table_ref.destroy.is_none() || table_ref.handle.is_none() {
        return Err((VEER_ERROR, format!("{path} plugin table is incomplete")));
    }
    libraries.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).insert(path.to_string(), digest.to_string());
    Ok(table)
}

fn run_instance(load: Frame, socket: UnixStream, control: Arc<Control>, libraries: Libraries) {
    let instance = load.instance;
    let writer = match socket.try_clone() {
        Ok(writer) => writer,
        Err(err) => {
            eprintln!("veer-plugin-worker: duplicate instance socket: {err}");
            return;
        }
    };
    let mut channel = Channel { reader: BufReader::with_capacity(16 << 10, socket), writer };
    let path = String::from_utf8_lossy(&load.name).into_owned();
    let config: Value = parse_json(&load.payload);
    let expected_id = config.pointer("/plugin/id").and_then(Value::as_str).unwrap_or("").to_string();
    let digest = config.get("library_sha256").and_then(Value::as_str).unwrap_or("").to_string();

    let table = match load_library(&path, &digest, &libraries) {
        Ok(table) => table,
        Err((status, message)) => {
            channel.send(frame::LOADED, instance, 0, load.id, status, b"", message.as_bytes());
            return;
        }
    };
    let plugin = unsafe { &*table };
    let plugin_id = if plugin.id.is_null() {
        String::new()
    } else {
        unsafe { CStr::from_ptr(plugin.id) }.to_string_lossy().into_owned()
    };
    if !expected_id.is_empty() && plugin_id != expected_id {
        let message = format!("{path} implements plugin {plugin_id:?}, manifest expects {expected_id:?}");
        channel.send(frame::LOADED, instance, 0, load.id, VEER_EINVAL, b"", message.as_bytes());
        return;
    }
    let create = plugin.create.unwrap();
    let destroy = plugin.destroy.unwrap();
    let handle = plugin.handle.unwrap();

    let glue = Box::into_raw(Box::new(Glue {
        table: veer_host_v1 {
            struct_size: std::mem::size_of::<veer_host_v1>() as u32,
            abi_major: VEER_PLUGIN_ABI_MAJOR,
            abi_minor: VEER_PLUGIN_ABI_MINOR,
            ctx: std::ptr::null_mut(),
            call: Some(host_call),
            log: Some(host_log),
            post: Some(host_post),
            buf_reserve: Some(host_buf_reserve),
            monotonic_ns: Some(host_monotonic_ns),
        },
        ctx: HostCtx {
            instance,
            control,
            channel: std::cell::RefCell::new(channel),
            dispatch_thread: thread::current().id(),
            current_request: std::cell::Cell::new(0),
            current_kind: std::cell::Cell::new(0),
            next_call: std::cell::Cell::new(0),
            deferred: std::cell::RefCell::new(VecDeque::new()),
            unloading: std::cell::Cell::new(false),
            local: Local::new(&config),
        },
    }));
    unsafe {
        (*glue).table.ctx = &(*glue).ctx as *const HostCtx as *mut c_void;
    }
    let ctx = unsafe { &(*glue).ctx };
    let host_table = unsafe { &(*glue).table as *const veer_host_v1 };

    let state = unsafe { create(host_table, veer_slice::from_bytes(&load.payload)) };
    if state.is_null() {
        ctx.channel.borrow_mut().send(frame::LOADED, instance, 0, load.id, VEER_ERROR, b"", b"plugin create() failed; see the plugin log");
        unsafe { drop(Box::from_raw(glue)) };
        return;
    }
    if !ctx.channel.borrow_mut().send(frame::LOADED, instance, 0, load.id, VEER_OK, b"", b"") {
        unsafe {
            destroy(state);
            drop(Box::from_raw(glue));
        }
        return;
    }

    let mut reply = veer_buf { data: std::ptr::null_mut(), len: 0, cap: 0 };
    let mut sequence = 0u64;
    loop {
        let next = ctx.deferred.borrow_mut().pop_front();
        let incoming = match next {
            Some(incoming) => incoming,
            None => match ctx.channel.borrow_mut().receive() {
                Ok(incoming) => incoming,
                Err(_) => break,
            },
        };
        match incoming.kind {
            frame::MSG => {
                if ctx.unloading.get() {
                    ctx.channel.borrow_mut().send(frame::RESULT, instance, 0, incoming.id, VEER_ESHUTDOWN, b"", b"plugin instance is unloading");
                    continue;
                }
                sequence += 1;
                let message = veer_msg {
                    struct_size: std::mem::size_of::<veer_msg>() as u32,
                    kind: incoming.status as u32,
                    sequence,
                    handler: veer_slice::from_bytes(&incoming.name),
                    payload: veer_slice::from_bytes(&incoming.payload),
                };
                reply.len = 0;
                ctx.current_request.set(incoming.id);
                ctx.current_kind.set(message.kind);
                // A MSG's ref carries the handler's deadline (Unix ms).
                ctx.local.set_deadline_ms(incoming.reference);
                let status = unsafe { handle(state, &message, &mut reply) };
                ctx.current_request.set(0);
                ctx.current_kind.set(0);
                ctx.local.set_deadline_ms(0);
                let bytes: &[u8] = if reply.data.is_null() || reply.len == 0 {
                    &[]
                } else {
                    unsafe { std::slice::from_raw_parts(reply.data, reply.len.min(reply.cap)) }
                };
                if !ctx.channel.borrow_mut().send(frame::RESULT, instance, 0, incoming.id, status, b"", bytes) {
                    break;
                }
                if reply.cap > MAX_KEPT_REPLY_BUFFER {
                    unsafe { reserve(&mut reply, 0) };
                }
            }
            frame::UNLOAD => {
                unsafe {
                    destroy(state);
                    reserve(&mut reply, 0);
                }
                ctx.channel.borrow_mut().send(frame::UNLOADED, instance, 0, incoming.id, VEER_OK, b"", b"");
                unsafe { drop(Box::from_raw(glue)) };
                return;
            }
            _ => {}
        }
    }
    // The host closed this instance's socket.
    unsafe {
        destroy(state);
        reserve(&mut reply, 0);
        drop(Box::from_raw(glue));
    }
}

fn parse_json(bytes: &[u8]) -> Value {
    std::str::from_utf8(bytes).ok().and_then(|text| text.parse::<Value>().ok()).unwrap_or(Value::Null)
}
