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
    push_key(s, key);
    s.push_str(if v { "true" } else { "false" });
}

fn push_str(s: &mut String, key: &str, v: &str) {
    push_key(s, key);
    push_json_string(s, v);
}

fn push_opt_str(s: &mut String, key: &str, v: Option<&str>) {
    push_key(s, key);
    match v {
        Some(x) => push_json_string(s, x),
        None => s.push_str("null"),
    }
}

fn push_str_array(s: &mut String, key: &str, items: &[String]) {
    push_key(s, key);
    s.push('[');
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        push_json_string(s, it);
    }
    s.push(']');
}

/// Append a JSON-escaped string literal (with quotes).
pub fn push_json_string(s: &mut String, v: &str) {
    s.push('"');
    for ch in v.chars() {
        match ch {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\u{0008}' => s.push_str("\\b"),
            '\u{000C}' => s.push_str("\\f"),
            c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AuditEvent {
        AuditEvent {
            ts_ms: 12,
            seq: 1,
            decision: Decision::Forward,
            reason: "allow_tool read_file".into(),
            method: Some("tools/call".into()),
            tool: Some("read_file".into()),
            id: Some("7".into()),
            bytes_in: 100,
            bytes_out: 90,
            redacted: vec!["token".into()],
            balanced: true,
            max_depth: 3,
        }
    }

    #[test]
    fn serialises_expected_fields() {
        let j = sample().to_json();
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains(r#""decision":"forward""#));
        assert!(j.contains(r#""method":"tools/call""#));
        assert!(j.contains(r#""tool":"read_file""#));
        assert!(j.contains(r#""redacted":["token"]"#));
        assert!(j.contains(r#""balanced":true"#));
        assert!(j.contains(r#""max_depth":3"#));
    }

    #[test]
    fn nulls_are_emitted_for_absent_fields() {
        let mut e = sample();
        e.method = None;
        e.tool = None;
        e.id = None;
        let j = e.to_json();
        assert!(j.contains(r#""method":null"#));
        assert!(j.contains(r#""tool":null"#));
        assert!(j.contains(r#""id":null"#));
    }

    #[test]
    fn escapes_reason() {
        let mut e = sample();
        e.reason = "he said \"no\"\n".into();
        let j = e.to_json();
        assert!(j.contains(r#""reason":"he said \"no\"\n""#));
    }

    #[test]
    fn empty_redacted_is_empty_array() {
        let mut e = sample();
        e.redacted.clear();
        let j = e.to_json();
        assert!(j.contains(r#""redacted":[]"#));
    }
}
