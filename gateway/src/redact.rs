//! Argument redaction.
//!
//! Given a raw MCP `tools/call` message, replace the *values* of any argument
//! keys matched by the policy's `redact_arg` patterns with the redaction mask,
//! leaving the rest of the message byte-for-byte intact.
//!
//! We locate `params.arguments` (an object) with the honest scanner, then walk
//! its immediate members. For each member whose key matches a redaction
//! pattern, we splice the mask (encoded as a JSON string) in place of the raw
//! value span. Because we only ever replace complete value spans returned by
//! the scanner, the surrounding structure is preserved exactly.
//!
//! If the message does not contain `params.arguments` as an object, no changes
//! are made and the original bytes are returned.

use crate::json_scan::{self, ValueKind};
use crate::policy::Policy;

/// Outcome of a redaction pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionResult {
    /// The (possibly rewritten) message bytes.
    pub bytes: Vec<u8>,
    /// Argument keys that were redacted, in the order encountered.
    pub redacted_keys: Vec<String>,
}

/// Encode a Rust string as a minimal JSON string literal (with surrounding
/// quotes and the mandatory escapes). Used for the redaction mask.
pub fn json_encode_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Apply redaction to `message` according to `policy`.
pub fn redact_message(message: &[u8], policy: &Policy) -> RedactionResult {
    let no_change = || RedactionResult {
        bytes: message.to_vec(),
        redacted_keys: Vec::new(),
    };

    if policy.redact_args.is_empty() {
        return no_change();
    }

    // Locate params (object).
    let params = match json_scan::top_level_span(message, "params") {
        Some(s) if s.kind == ValueKind::Object => s,
        _ => return no_change(),
    };
    // Locate params.arguments (object).
    let args = match json_scan::find_key_in_object(message, params.start, "arguments") {
        Some(s) if s.kind == ValueKind::Object => s,
        _ => return no_change(),
    };

    // Collect the (key, value-span) members of the arguments object that match
    // a redaction pattern. We gather ranges first, then splice from the end so
    // earlier offsets remain valid.
    let members = object_members(message, args.start);
    let mask_literal = json_encode_string(&policy.redaction_mask);

    let mut edits: Vec<(usize, usize)> = Vec::new(); // (value_start, value_end)
    let mut redacted_keys: Vec<String> = Vec::new();
    for m in &members {
        if policy.should_redact(&m.key) {
            edits.push((m.value_start, m.value_end));
            redacted_keys.push(m.key.clone());
        }
    }

    if edits.is_empty() {
        return no_change();
    }

    // Splice from the end so indices stay valid.
    let mut bytes = message.to_vec();
    edits.sort_by_key(|a| std::cmp::Reverse(a.0));
    for (start, end) in edits {
        bytes.splice(start..end, mask_literal.bytes());
    }

    RedactionResult {
        bytes,
        redacted_keys,
    }
}

struct Member {
    key: String,
    value_start: usize,
    value_end: usize,
}

/// Enumerate the immediate members of the object beginning at `obj_start`.
fn object_members(bytes: &[u8], obj_start: usize) -> Vec<Member> {
    let mut out = Vec::new();
    let mut i = skip_ws(bytes, obj_start);
    if bytes.get(i) != Some(&b'{') {
        return out;
    }
    i = skip_ws(bytes, i + 1);
    if bytes.get(i) == Some(&b'}') {
        return out;
    }
    loop {
        if bytes.get(i) != Some(&b'"') {
            return out;
        }
        let key_end = match scan_string(bytes, i) {
            Some(e) => e,
            None => return out,
        };
        let key = match json_scan::decode_string(bytes, i, key_end) {
            Some(k) => k,
            None => return out,
        };
        let colon = skip_ws(bytes, key_end);
        if bytes.get(colon) != Some(&b':') {
            return out;
        }
        let val_start = skip_ws(bytes, colon + 1);
        let val_end = match scan_value_end(bytes, val_start) {
            Some(e) => e,
            None => return out,
        };
        out.push(Member {
            key,
            value_start: val_start,
            value_end: val_end,
        });
        let after = skip_ws(bytes, val_end);
        match bytes.get(after) {
            Some(b',') => i = skip_ws(bytes, after + 1),
            _ => return out,
        }
    }
}

// The following helpers mirror those in `json_scan` but are kept private here
// so `json_scan` can expose a minimal public surface. They are exercised via
// the integration tests below and in `json_scan`'s own unit tests.

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            _ => break,
        }
    }
    i
}

fn scan_string(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => {
                if bytes.get(j + 1) == Some(&b'u') {
                    j += 6;
                } else {
                    j += 2;
                }
            }
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

fn scan_value_end(bytes: &[u8], i: usize) -> Option<usize> {
    let i = skip_ws(bytes, i);
    match bytes.get(i)? {
        b'"' => scan_string(bytes, i),
        b'{' => scan_container(bytes, i, b'{', b'}'),
        b'[' => scan_container(bytes, i, b'[', b']'),
        _ => {
            let mut j = i;
            while j < bytes.len() {
                match bytes[j] {
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n' => break,
                    _ => j += 1,
                }
            }
            if j == i {
                None
            } else {
                Some(j)
            }
        }
    }
}

fn scan_container(bytes: &[u8], i: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut j = i;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b'"' {
            j = scan_string(bytes, j)?;
            continue;
        }
        if b == open {
