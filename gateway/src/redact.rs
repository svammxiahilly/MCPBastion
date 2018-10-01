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

