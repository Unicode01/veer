//! The process keeper's messages: one JSON object per line on a unix stream
//! socket. The daemon's side lives in internal/app/plugin_process_keeper.go
//! (pluginKeeperMessage) and must stay compatible: byte fields are base64
//! strings, as Go encodes []byte, and every message carries "version".

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const PROTOCOL_VERSION: i64 = 1;
/// The longest message line either side accepts (pluginKeeperMessageLimit).
pub const MESSAGE_LIMIT: usize = 4 << 20;
/// An attach request must fit in this many bytes.
pub const ATTACH_LIMIT: usize = 4096;
/// Output the keeper keeps per stream for a successor
/// (pluginExecMaxOutputBytes).
pub const LOG_LIMIT: usize = 64 << 10;

/// A request from the daemon: start, stop and detach on the control
/// connection, attach from a successor.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct Request {
    #[serde(deserialize_with = "nullable")]
    pub version: i64,
    #[serde(deserialize_with = "nullable")]
    pub op: String,
    #[serde(deserialize_with = "nullable")]
    pub command: String,
    #[serde(deserialize_with = "nullable")]
    pub args: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub env: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub dir: String,
    #[serde(deserialize_with = "nullable")]
    pub stdin: String,
    #[serde(deserialize_with = "nullable")]
    pub timeout_ms: i64,
    #[serde(deserialize_with = "nullable")]
    pub name: String,
    #[serde(deserialize_with = "nullable")]
    pub token: String,
}

fn nullable<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// Parses one request line. A line that is not a request of this protocol
/// version yields None; the caller treats it as a broken connection, as the
/// Go keeper did.
pub fn parse_request(line: &[u8]) -> Option<Request> {
    let request: Request = serde_json::from_slice(line).ok()?;
    (request.version == PROTOCOL_VERSION).then_some(request)
}

/// An event for the daemon. Empty fields are left out, as Go's omitempty
/// does; "code" is always present.
#[derive(Serialize, Default)]
pub struct Event<'a> {
    pub version: i64,
    pub event: &'a str,
    #[serde(skip_serializing_if = "is_zero")]
    pub pid: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub started_at: i64,
    #[serde(skip_serializing_if = "is_false")]
    pub running: bool,
    pub code: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub stream: &'a str,
    #[serde(skip_serializing_if = "<[u8]>::is_empty", serialize_with = "as_base64")]
    pub data: &'a [u8],
    #[serde(skip_serializing_if = "<[u8]>::is_empty", serialize_with = "as_base64")]
    pub stdout: &'a [u8],
    #[serde(skip_serializing_if = "<[u8]>::is_empty", serialize_with = "as_base64")]
    pub stderr: &'a [u8],
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub error: &'a str,
}

impl<'a> Event<'a> {
    pub fn new(event: &'a str) -> Event<'a> {
        Event { version: PROTOCOL_VERSION, event, ..Event::default() }
    }

    /// The event as one line, newline included.
    pub fn line(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).expect("keeper events always serialize");
        line.push(b'\n');
        line
    }
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn as_base64<S: Serializer>(data: &&[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&base64(data))
}

/// Standard base64 with padding, which Go's encoding/json expects for []byte.
pub fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Splits a byte stream into lines of at most `limit` bytes.
pub struct Lines {
    buffer: Vec<u8>,
    // Bytes of buffer known to hold no newline.
    scanned: usize,
    limit: usize,
}

/// A line grew past the limit without ending.
#[derive(Debug, PartialEq)]
pub struct TooLong;

impl Lines {
    pub fn new(limit: usize) -> Lines {
        Lines { buffer: Vec::new(), scanned: 0, limit }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// The next complete line without its newline, None while it is still
    /// incomplete.
    pub fn next_line(&mut self) -> Result<Option<Vec<u8>>, TooLong> {
        let found = self.buffer[self.scanned..].iter().position(|&b| b == b'\n').map(|at| self.scanned + at);
        self.scanned = found.unwrap_or(self.buffer.len());
        match found {
            Some(end) if end <= self.limit => {
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                line.pop();
                self.scanned = 0;
                Ok(Some(line))
            }
            Some(_) => Err(TooLong),
            None if self.buffer.len() > self.limit => Err(TooLong),
            None => Ok(None),
        }
    }

    /// Bytes received after the last complete line.
    pub fn into_rest(self) -> Vec<u8> {
        self.buffer
    }
}

/// The last LOG_LIMIT bytes of one output stream.
#[derive(Default)]
pub struct OutputLog {
    data: Vec<u8>,
    truncated: bool,
}

impl OutputLog {
    /// Appends output, dropping the oldest bytes beyond the limit
    /// (pluginProcessLog.Write).
    pub fn write(&mut self, data: &[u8]) {
        if data.len() >= LOG_LIMIT {
            self.data.clear();
            self.data.extend_from_slice(&data[data.len() - LOG_LIMIT..]);
            self.truncated = true;
            return;
        }
        let excess = (self.data.len() + data.len()).saturating_sub(LOG_LIMIT);
        if excess > 0 {
            self.data.drain(..excess);
            self.truncated = true;
        }
        self.data.extend_from_slice(data);
    }

    /// The kept output as valid UTF-8 and whether older output was dropped.
    pub fn snapshot(&self) -> (String, bool) {
        (to_valid_utf8(&self.data), self.truncated)
    }
}

/// Replaces each run of invalid UTF-8 with one U+FFFD, as Go's
/// strings.ToValidUTF8 does.
pub fn to_valid_utf8(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len());
    let mut replaced = false;
    for chunk in data.utf8_chunks() {
        if !chunk.valid().is_empty() {
            out.push_str(chunk.valid());
            replaced = false;
        }
        if !chunk.invalid().is_empty() && !replaced {
            out.push('\u{FFFD}');
            replaced = true;
        }
    }
    out
}

/// Compares an attach token without stopping at the first differing byte.
pub fn token_matches(given: &str, want: &str) -> bool {
    !want.is_empty()
        && given.len() == want.len()
        && given.bytes().zip(want.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_encoding() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (&[0xfb, 0xff, 0xbf], "+/+/"),
        ];
        for (data, want) in cases {
            assert_eq!(base64(data), want);
        }
    }

    #[test]
    fn events_have_the_shape_the_daemon_reads() {
        let started = Event { pid: 42, started_at: 1700000000123, ..Event::new("started") };
        assert_eq!(
            String::from_utf8(started.line()).unwrap(),
            "{\"version\":1,\"event\":\"started\",\"pid\":42,\"started_at\":1700000000123,\"code\":0}\n"
        );
        let output = Event { stream: "stderr", data: b"hi\n", ..Event::new("output") };
        assert_eq!(
            String::from_utf8(output.line()).unwrap(),
            "{\"version\":1,\"event\":\"output\",\"code\":0,\"stream\":\"stderr\",\"data\":\"aGkK\"}\n"
        );
        let attached = Event {
            pid: 7,
            started_at: 9,
            running: true,
            code: -1,
            stdout: b"ready\n",
            truncated: true,
            ..Event::new("attached")
        };
        let value: serde_json::Value = serde_json::from_slice(&attached.line()).unwrap();
        assert_eq!(value["running"], true);
        assert_eq!(value["code"], -1);
        assert_eq!(value["stdout"], "cmVhZHkK");
        assert!(value.get("stderr").is_none());
        let exited = Event { code: 9, ..Event::new("exited") };
        assert_eq!(String::from_utf8(exited.line()).unwrap(), "{\"version\":1,\"event\":\"exited\",\"code\":9}\n");
    }

    #[test]
    fn requests_parse_like_the_go_keeper() {
        let start = parse_request(
            br#"{"version":1,"op":"start","command":"/bin/sh","args":["-c","echo hi"],"env":["PATH=/bin"],"dir":"/tmp","stdin":"in","code":0}"#,
        )
        .unwrap();
        assert_eq!(start.op, "start");
        assert_eq!(start.args, ["-c", "echo hi"]);
        assert_eq!(start.env, ["PATH=/bin"]);
        assert_eq!((start.dir.as_str(), start.stdin.as_str()), ("/tmp", "in"));
        let detach = parse_request(br#"{"version":1,"op":"detach","name":"veer-keeper-x","token":"abc","timeout_ms":90000,"args":null,"code":0}"#).unwrap();
        assert_eq!((detach.name.as_str(), detach.token.as_str(), detach.timeout_ms), ("veer-keeper-x", "abc", 90000));
        assert!(detach.args.is_empty());
        assert!(parse_request(br#"{"version":2,"op":"stop"}"#).is_none());
        assert!(parse_request(br#"{"op":"stop"}"#).is_none());
        assert!(parse_request(b"not json").is_none());
        assert!(parse_request(b"").is_none());
    }

    #[test]
    fn lines_split_and_enforce_the_limit() {
        let mut lines = Lines::new(8);
        lines.push(b"one\ntw");
        assert_eq!(lines.next_line(), Ok(Some(b"one".to_vec())));
        assert_eq!(lines.next_line(), Ok(None));
        lines.push(b"o\nthree");
        assert_eq!(lines.next_line(), Ok(Some(b"two".to_vec())));
        assert_eq!(lines.next_line(), Ok(None));
        assert_eq!(lines.into_rest(), b"three");

        let mut long = Lines::new(4);
        long.push(b"12345");
        assert_eq!(long.next_line(), Err(TooLong));
        let mut long_ended = Lines::new(4);
        long_ended.push(b"12345\n");
        assert_eq!(long_ended.next_line(), Err(TooLong));
        let mut exact = Lines::new(4);
        exact.push(b"1234\n");
        assert_eq!(exact.next_line(), Ok(Some(b"1234".to_vec())));
    }

    #[test]
    fn output_log_keeps_the_newest_bytes() {
        let mut log = OutputLog::default();
        log.write(b"hello ");
        log.write(b"world");
        assert_eq!(log.snapshot(), ("hello world".to_string(), false));
        let mut big = vec![b'a'; LOG_LIMIT - 1];
        big.push(b'z');
        log.write(&big);
        let (text, truncated) = log.snapshot();
        assert!(truncated);
        assert_eq!(text.len(), LOG_LIMIT);
        assert!(text.ends_with('z'));
        log.write(b"!");
        let (text, _) = log.snapshot();
        assert_eq!(text.len(), LOG_LIMIT);
        assert!(text.ends_with("z!"));
        let mut huge = OutputLog::default();
        huge.write(&vec![b'q'; LOG_LIMIT + 10]);
        assert_eq!(huge.snapshot().0.len(), LOG_LIMIT);
        assert!(huge.snapshot().1);
    }

    #[test]
    fn invalid_utf8_runs_become_one_replacement() {
        assert_eq!(to_valid_utf8(b"ok"), "ok");
        assert_eq!(to_valid_utf8(b"a\xff\xfeb"), "a\u{FFFD}b");
        assert_eq!(to_valid_utf8(b"\xe4\xb8"), "\u{FFFD}");
        assert_eq!(to_valid_utf8("中\u{FFFD}".as_bytes()), "中\u{FFFD}");
        assert_eq!(to_valid_utf8(b"\x80x\x80"), "\u{FFFD}x\u{FFFD}");
    }

    #[test]
    fn tokens_must_match_exactly_and_be_set() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abd", "abc"));
        assert!(!token_matches("ab", "abc"));
        assert!(!token_matches("", ""));
    }
}
