//! Frames between the Veer host and a plugin worker.
//!
//! Every frame is a little-endian u32 length followed by that many bytes:
//!
//! ```text
//! u8  type      u8 flags (unused, 0)   u16 reserved
//! u32 instance
//! u64 id        request or call id chosen by the sender
//! u64 ref       the id this frame answers or belongs to; on MSG, the
//!               handler's deadline (Unix ms, 0: none)
//! i32 status    status code, message kind or log level
//! u32 name_len
//! name bytes, then payload bytes (the rest of the frame)
//! ```
//!
//! The Go side lives in internal/app/plugin_native_protocol.go and must
//! stay identical.

use std::io::{self, Read};

pub const HEADER_LEN: usize = 32;

/// worker -> host: the worker is ready. payload: JSON description.
pub const HELLO: u8 = 1;
/// host -> worker: load a plugin. name: library path, payload: config JSON.
pub const LOAD: u8 = 2;
/// worker -> host: load result. status: VEER_* code, payload: error text.
pub const LOADED: u8 = 3;
/// host -> worker: deliver a message. status: kind, name: handler, payload: ctx JSON.
pub const MSG: u8 = 4;
/// worker -> host: handler result. status: VEER_* code, payload: reply.
pub const RESULT: u8 = 5;
/// worker -> host: host API call. ref: the MSG id, name: method, payload: arguments JSON.
pub const CALL: u8 = 6;
/// host -> worker: call result. ref: the CALL id, status: VEER_* code, payload: JSON or error.
pub const CALL_REPLY: u8 = 7;
/// host -> worker: destroy an instance.
pub const UNLOAD: u8 = 8;
/// worker -> host: the instance was destroyed.
pub const UNLOADED: u8 = 9;
/// worker -> host: the plugin posted a wake message. payload: JSON.
pub const POST: u8 = 10;
/// worker -> host: a log line. status: level, payload: text.
pub const LOG: u8 = 11;
/// host -> worker: exit now.
pub const SHUTDOWN: u8 = 12;

#[derive(Debug, Default, Clone)]
pub struct Frame {
    pub kind: u8,
    pub instance: u32,
    pub id: u64,
    pub reference: u64,
    pub status: i32,
    pub name: Vec<u8>,
    pub payload: Vec<u8>,
}

pub fn read_frame(reader: &mut impl Read, max_len: usize) -> io::Result<Frame> {
    let mut length = [0u8; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length < HEADER_LEN || length > max_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("frame length {length} is out of range")));
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    let name_len = u32::from_le_bytes(body[28..32].try_into().unwrap()) as usize;
    if name_len > length - HEADER_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame name exceeds frame"));
    }
    let payload = body.split_off(HEADER_LEN + name_len);
    let name = body[HEADER_LEN..].to_vec();
    Ok(Frame {
        kind: body[0],
        instance: u32::from_le_bytes(body[4..8].try_into().unwrap()),
        id: u64::from_le_bytes(body[8..16].try_into().unwrap()),
        reference: u64::from_le_bytes(body[16..24].try_into().unwrap()),
        status: i32::from_le_bytes(body[24..28].try_into().unwrap()),
        name,
        payload,
    })
}

/// Encodes a frame into one buffer so it goes out in a single write.
#[allow(clippy::too_many_arguments)]
pub fn encode(kind: u8, instance: u32, id: u64, reference: u64, status: i32, name: &[u8], payload: &[u8]) -> Vec<u8> {
    let length = HEADER_LEN + name.len() + payload.len();
    let mut out = Vec::with_capacity(4 + length);
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.push(kind);
    out.push(0);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&instance.to_le_bytes());
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&reference.to_le_bytes());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes = encode(MSG, 7, 42, 9, -3, b"onAction", b"{\"a\":1}");
        let frame = read_frame(&mut bytes.as_slice(), 1 << 20).unwrap();
        assert_eq!(frame.kind, MSG);
        assert_eq!(frame.instance, 7);
        assert_eq!(frame.id, 42);
        assert_eq!(frame.reference, 9);
        assert_eq!(frame.status, -3);
        assert_eq!(frame.name, b"onAction");
        assert_eq!(frame.payload, b"{\"a\":1}");
    }

    #[test]
    fn rejects_oversized_name() {
        let mut bytes = encode(MSG, 1, 1, 0, 0, b"ab", b"");
        bytes[4 + 28] = 200;
        assert!(read_frame(&mut bytes.as_slice(), 1 << 20).is_err());
    }
}
