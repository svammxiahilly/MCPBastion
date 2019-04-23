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
