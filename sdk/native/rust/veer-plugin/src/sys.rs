//! Raw declarations matching `sdk/native/include/veer_plugin.h`.
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_void};

pub const VEER_PLUGIN_ABI_MAJOR: u16 = 1;
pub const VEER_PLUGIN_ABI_MINOR: u16 = 0;

pub const VEER_OK: i32 = 0;
pub const VEER_UNHANDLED: i32 = 1;
pub const VEER_ERROR: i32 = -1;
pub const VEER_EINVAL: i32 = -2;
pub const VEER_EPERM: i32 = -3;
pub const VEER_ESHUTDOWN: i32 = -4;
pub const VEER_ENOMEM: i32 = -5;

pub const VEER_LOG_DEBUG: i32 = 0;
pub const VEER_LOG_INFO: i32 = 1;
pub const VEER_LOG_WARN: i32 = 2;
pub const VEER_LOG_ERROR: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct veer_slice {
    pub data: *const u8,
    pub len: usize,
}

impl veer_slice {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        veer_slice { data: bytes.as_ptr(), len: bytes.len() }
    }

    /// # Safety
    /// `data` must point to `len` readable bytes that outlive the returned slice.
    pub unsafe fn as_bytes<'a>(&self) -> &'a [u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(self.data, self.len)
        }
    }
}

#[repr(C)]
pub struct veer_buf {
    pub data: *mut u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(C)]
pub struct veer_msg {
    pub struct_size: u32,
    pub kind: u32,
    pub sequence: u64,
    pub handler: veer_slice,
    pub payload: veer_slice,
}

#[repr(C)]
pub struct veer_host_v1 {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub ctx: *mut c_void,
    pub call: Option<unsafe extern "C" fn(*mut c_void, veer_slice, veer_slice, *mut veer_buf) -> i32>,
    pub log: Option<unsafe extern "C" fn(*mut c_void, i32, veer_slice)>,
    pub post: Option<unsafe extern "C" fn(*mut c_void, veer_slice) -> i32>,
    pub buf_reserve: Option<unsafe extern "C" fn(*mut c_void, *mut veer_buf, usize) -> i32>,
    pub monotonic_ns: Option<unsafe extern "C" fn(*mut c_void) -> u64>,
}

#[repr(C)]
pub struct veer_plugin_v1 {
    pub struct_size: u32,
    pub abi_major: u16,
    pub abi_minor: u16,
    pub id: *const c_char,
    pub create: Option<unsafe extern "C" fn(*const veer_host_v1, veer_slice) -> *mut c_void>,
    pub destroy: Option<unsafe extern "C" fn(*mut c_void)>,
    pub handle: Option<unsafe extern "C" fn(*mut c_void, *const veer_msg, *mut veer_buf) -> i32>,
}

// The table only holds function pointers and a static string.
unsafe impl Sync for veer_plugin_v1 {}

pub type veer_plugin_entry_fn = unsafe extern "C" fn(u16) -> *const veer_plugin_v1;

/// Writes `bytes` into a worker-owned buffer through `buf_reserve`.
///
/// # Safety
/// `host` and `buf` must be the valid pointers the worker handed out.
pub unsafe fn write_buf(host: *const veer_host_v1, buf: *mut veer_buf, bytes: &[u8]) -> i32 {
    if host.is_null() || buf.is_null() {
        return VEER_EINVAL;
    }
    let reserve = match (*host).buf_reserve {
        Some(reserve) => reserve,
        None => return VEER_EINVAL,
    };
    let status = reserve((*host).ctx, buf, bytes.len());
    if status != VEER_OK {
        return status;
    }
    if (*buf).cap < bytes.len() || ((*buf).data.is_null() && !bytes.is_empty()) {
        return VEER_ENOMEM;
    }
    if !bytes.is_empty() {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*buf).data, bytes.len());
    }
    (*buf).len = bytes.len();
    VEER_OK
}
