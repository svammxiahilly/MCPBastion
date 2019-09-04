//! Structured audit events.
//!
//! Every decision the gateway makes emits exactly one audit event as a single
//! line of JSON to the audit sink (stderr by default, or a file). The console
//! viewer in `../console` consumes these lines. Events are hand-serialised with
//! the standard library only, so the schema below is the single source of
//! truth.
//!
//! Event schema (all fields always present unless noted):
//! ```json
//! {
//!   "ts_ms":        1234,        // milliseconds since process start
//!   "seq":          1,           // monotonically increasing line counter
//!   "decision":     "forward",   // forward | deny | drop | error
//!   "reason":       "allow_tool read_file",
//!   "method":       "tools/call",// extracted, or null
//!   "tool":         "read_file", // extracted for tools/call, or null
//!   "id":           "7",         // raw id span text, or null
//!   "bytes_in":     128,
//!   "bytes_out":    120,         // 0 when not forwarded
//!   "redacted":     ["token"],   // redacted argument keys
//!   "balanced":     true,        // structural balance of the input
//!   "max_depth":    3
//! }
//! ```

/// The decision recorded for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Forward,
    Deny,
    Drop,
    Error,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Forward => "forward",
            Decision::Deny => "deny",
            Decision::Drop => "drop",
            Decision::Error => "error",
        }
    }
}

/// A single audit event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub ts_ms: u64,
    pub seq: u64,
    pub decision: Decision,
    pub reason: String,
    pub method: Option<String>,
    pub tool: Option<String>,
    pub id: Option<String>,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub redacted: Vec<String>,
    pub balanced: bool,
    pub max_depth: usize,
}

impl AuditEvent {
    /// Serialise to a single-line JSON string (no trailing newline).
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        push_num(&mut s, "ts_ms", self.ts_ms);
        s.push(',');
        push_num(&mut s, "seq", self.seq);
        s.push(',');
        push_str(&mut s, "decision", self.decision.as_str());
        s.push(',');
        push_str(&mut s, "reason", &self.reason);
        s.push(',');
        push_opt_str(&mut s, "method", self.method.as_deref());
        s.push(',');
        push_opt_str(&mut s, "tool", self.tool.as_deref());
        s.push(',');
        push_opt_str(&mut s, "id", self.id.as_deref());
        s.push(',');
        push_num(&mut s, "bytes_in", self.bytes_in as u64);
        s.push(',');
        push_num(&mut s, "bytes_out", self.bytes_out as u64);
        s.push(',');
        push_str_array(&mut s, "redacted", &self.redacted);
        s.push(',');
        push_bool(&mut s, "balanced", self.balanced);
        s.push(',');
        push_num(&mut s, "max_depth", self.max_depth as u64);
        s.push('}');
        s
    }
}

fn push_key(s: &mut String, key: &str) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":");
}

fn push_num(s: &mut String, key: &str, v: u64) {
    push_key(s, key);
    s.push_str(&v.to_string());
}

fn push_bool(s: &mut String, key: &str, v: bool) {
