//! crypto.md5 and crypto.randomBytes, as the host implements them
//! (cryptoMD5 / cryptoRandomBytes in internal/app/plugin_control_runtime.go).
//! crypto.sha256File stays with the host: it resolves paths in the plugin's
//! directory, and nothing calls it often.

use md5::{Digest, Md5};
use veer_plugin::Value;

use super::{arg, Failure, Local, Outcome};

const MAX_RANDOM_BYTES: i64 = 1024;

pub fn md5(local: &Local, kind: u32, args: &[Value]) -> Outcome {
    local.policy().require(kind, "crypto")?;
    if args.is_empty() {
        return Err(Failure::error("crypto.md5: at least one value is required"));
    }
    let mut hash = Md5::new();
    for (i, value) in args.iter().enumerate() {
        let part = bytes_from_arg(value).map_err(|err| Failure::error(format!("crypto.md5 argument {}: {err}", i + 1)))?;
        hash.update(&part);
    }
    Ok(Value::String(hex(&hash.finalize())))
}

pub fn random_bytes(local: &Local, kind: u32, args: &[Value]) -> Outcome {
    local.policy().require(kind, "crypto")?;
    let length = arg(args, 0);
    if length.is_null() {
        return Err(Failure::error("crypto.randomBytes: length is required"));
    }
    // ToInteger, as the host's value model converts it.
    let number = veer_plugin::js::number(length);
    let length = if number.is_finite() { number.trunc() as i64 } else { 0 };
    if length <= 0 || length > MAX_RANDOM_BYTES {
        return Err(Failure::error(format!("crypto.randomBytes: length must be between 1 and {MAX_RANDOM_BYTES}")));
    }
    let mut out = vec![0u8; length as usize];
    fill_random(&mut out).map_err(|err| Failure::error(format!("crypto.randomBytes: {err}")))?;
    Ok(Value::String(hex(&out)))
}

/// bytesFromCryptoArg: a string's bytes, a byte array, {hex} or {text}.
pub fn bytes_from_arg(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::Null => Err("value is required".to_string()),
        Value::String(text) => Ok(text.as_bytes().to_vec()),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, item)| match item.as_f64() {
                Some(number) if number.fract() == 0.0 && (0.0..=255.0).contains(&number) => Ok(number as u8),
                _ => Err(format!("byte array item {i} must be an integer between 0 and 255")),
            })
            .collect(),
        Value::Object(map) => {
            if let Some(raw) = map.get("hex") {
                return super::fields::decode_hex(&display(raw));
            }
            if let Some(raw) = map.get("text") {
                return Ok(display(raw).into_bytes());
            }
            Err("object must contain hex or text".to_string())
        }
        Value::Bool(_) => Err("unsupported value type bool".to_string()),
        Value::Number(_) => Err("unsupported value type float64".to_string()),
    }
}

/// fmt.Sprint of a decoded JSON value, for the hex and text fields.
fn display(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

#[cfg(target_os = "linux")]
pub fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    // getrandom(2) through syscall(): the glibc 2.17 builds have no wrapper.
    let mut filled = 0usize;
    while filled < out.len() {
        let read = unsafe { libc::syscall(libc::SYS_getrandom, out[filled..].as_mut_ptr(), out.len() - filled, 0) };
        if read < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        filled += read as usize;
    }
    Ok(())
}

/// The worker only runs on Linux; this keeps its tests building elsewhere.
#[cfg(not(target_os = "linux"))]
pub fn fill_random(out: &mut [u8]) -> std::io::Result<()> {
    use std::hash::{BuildHasher, Hasher};
    let state = std::collections::hash_map::RandomState::new();
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut hasher = state.build_hasher();
        hasher.write_usize(i);
        chunk.copy_from_slice(&hasher.finish().to_le_bytes()[..chunk.len()]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use veer_plugin::json;

    fn local() -> Local {
        Local::new(&json!({"permissions": ["crypto"]}))
    }

    #[test]
    fn md5_matches_the_host() {
        // CHAP: id byte, secret, challenge, as pppoe_client passes them.
        let value = md5(&local(), 0, &[json!({"hex": "01"}), json!("secret"), json!([1, 2, 3])]).unwrap();
        let mut hash = Md5::new();
        hash.update([1u8]);
        hash.update(b"secret");
        hash.update([1u8, 2, 3]);
        assert_eq!(value, Value::String(hex(&hash.finalize())));
        assert_eq!(md5(&local(), 0, &[json!("")]).unwrap(), json!("d41d8cd98f00b204e9800998ecf8427e"));
    }

    #[test]
    fn md5_rejects_what_the_host_rejects() {
        assert!(md5(&local(), 0, &[]).unwrap_err().message.contains("at least one value"));
        assert!(md5(&local(), 0, &[json!([256])]).unwrap_err().message.contains("argument 1"));
        assert!(md5(&local(), 0, &[json!({"other": 1})]).unwrap_err().message.contains("hex or text"));
        assert!(md5(&Local::new(&json!({})), 0, &[json!("x")]).unwrap_err().message.contains("permission crypto"));
    }

    #[test]
    fn hex_decoding() {
        use super::super::fields::decode_hex;
        assert_eq!(decode_hex("0x01:ff-0a").unwrap(), vec![1, 255, 10]);
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn random_bytes_length() {
        let value = random_bytes(&local(), 0, &[json!(16)]).unwrap();
        assert_eq!(value.as_str().unwrap().len(), 32);
        assert!(random_bytes(&local(), 0, &[json!(0)]).is_err());
        assert!(random_bytes(&local(), 0, &[json!(1025)]).is_err());
        assert!(random_bytes(&local(), 0, &[]).is_err());
    }
}
