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
            forward: None,
            event: ev,
        };
    }

    // 2. Structural sanity. We do not reject on imbalance (we are not a full
    //    parser), but a message that is not even minimally object-shaped is
    //    something we refuse to forward, because we cannot reason about it.
    if !looks_like_object(line) {
        ev.decision = Decision::Drop;
        ev.reason = "input is not a JSON object".to_string();
        return Processed {
            forward: None,
            event: ev,
        };
    }

    // 3. Tool authorization (only for tools/call). Other methods are governed
    //    by the default decision so an operator can lock the gateway down to
    //    tools/call-only if desired.
    let decision = match method.as_deref() {
        Some("tools/call") => match &tool {
            Some(name) => policy.decide_tool(name),
            None => {
                // A tools/call without an extractable name is suspicious.
                ev.decision = Decision::Deny;
                ev.reason = "tools/call missing extractable params.name".to_string();
                return Processed {
                    forward: None,
                    event: ev,
                };
            }
        },
        _ => {
            // Non tool-call: apply default policy as a coarse gate.
            if policy.default_allow {
                crate::policy::ToolDecision::Allow {
                    rule: "default allow (non tools/call)".into(),
                }
            } else {
                crate::policy::ToolDecision::Deny {
                    rule: "default deny (non tools/call)".into(),
                }
            }
        }
    };

    if !decision.is_allow() {
        ev.decision = Decision::Deny;
        ev.reason = decision.rule().to_string();
        return Processed {
            forward: None,
            event: ev,
        };
    }

    // 4. Rate limit — only counts messages we would otherwise forward.
    if !limiter.check(now_ms) {
        ev.decision = Decision::Drop;
        ev.reason = format!(
            "rate limit exceeded ({} per {} ms)",
            policy.rate_limit, policy.rate_window_ms
        );
        return Processed {
            forward: None,
            event: ev,
        };
    }

    // 5. Redaction.
    let red = redact::redact_message(line, policy);
    ev.redacted = red.redacted_keys;
    ev.bytes_out = red.bytes.len();
    ev.decision = Decision::Forward;
    ev.reason = decision.rule().to_string();

    Processed {
        forward: Some(red.bytes),
        event: ev,
    }
}

/// A message must at minimum start (after whitespace) with `{` to be treated as
/// a JSON-RPC object we can reason about.
fn looks_like_object(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            b'{' => return true,
            _ => return false,
        }
    }
    false
}

/// Extract the tool name of a `tools/call` request: `params.name` (a string).
fn extract_tool(bytes: &[u8]) -> Option<String> {
    let params = json_scan::top_level_span(bytes, "params")?;
    if params.kind != ValueKind::Object {
        return None;
    }
    let name = json_scan::find_key_in_object(bytes, params.start, "name")?;
    if name.kind != ValueKind::String {
        return None;
    }
    json_scan::decode_string(bytes, name.start, name.end)
}

/// Return the raw textual form of the top-level `id`, whatever its type.
fn id_text(bytes: &[u8]) -> Option<String> {
    let span = json_scan::top_level_span(bytes, "id")?;
    match span.kind {
        ValueKind::String => json_scan::decode_string(bytes, span.start, span.end),
        _ => std::str::from_utf8(&bytes[span.start..span.end])
            .ok()
            .map(|s| s.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

