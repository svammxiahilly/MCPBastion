//! The gateway engine: turn one raw input line into a decision, an optional
//! forwarded message, and an audit event.
//!
//! This module is deliberately pure — it does no I/O — so it can be tested
//! exhaustively. `main` wires it to stdin/stdout/audit-sink and the clock.

use crate::audit::{AuditEvent, Decision};
use crate::json_scan::{self, ValueKind};
use crate::policy::{Policy, RateLimiter};
use crate::redact;

/// The result of processing one input line.
pub struct Processed {
    /// Bytes to write to stdout, if the message is forwarded.
    pub forward: Option<Vec<u8>>,
    /// The audit event describing what happened.
    pub event: AuditEvent,
}

/// Process a single, trimmed input line.
///
/// `seq` is the 1-based line counter; `now_ms` is the current timestamp used
/// for rate limiting and the event; `limiter` is mutated when a message is
/// accepted for forwarding.
pub fn process_line(
    line: &[u8],
    policy: &Policy,
    limiter: &mut RateLimiter,
    seq: u64,
    now_ms: u64,
) -> Processed {
    let structure = json_scan::structure_report(line);
    let method = json_scan::top_level_string(line, "method");
    let id = id_text(line);

    // Extract the tool name for tools/call requests (params.name).
    let tool = extract_tool(line);

    let mut ev = AuditEvent {
        ts_ms: now_ms,
        seq,
        decision: Decision::Deny,
        reason: String::new(),
        method: method.clone(),
        tool: tool.clone(),
        id,
        bytes_in: line.len(),
        bytes_out: 0,
        redacted: Vec::new(),
        balanced: structure.balanced,
        max_depth: structure.max_depth,
    };

    // 1. Size limit.
    if line.len() > policy.max_bytes {
        ev.decision = Decision::Drop;
        ev.reason = format!(
            "size limit exceeded ({} > max_bytes {})",
            line.len(),
            policy.max_bytes
        );
        return Processed {
