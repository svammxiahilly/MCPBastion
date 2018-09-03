//! Policy model and evaluation for the MCP Bastion gateway.
//!
//! Policies are expressed in a tiny, line-oriented, dependency-free format so
//! the whole gateway can rely solely on the Rust standard library. Every
//! directive is `key = value` or `key value` on its own line. Lines beginning
//! with `#` are comments; blank lines are ignored.
//!
//! Supported directives (see `docs/POLICY.md` for the authoritative reference):
//!
//! ```text
//! default            = deny            # deny | allow  (fallback decision)
//! allow_tool         = read_file       # may be repeated
//! deny_tool          = shell.exec      # may be repeated; deny wins over allow
//! redact_arg         = token           # redact this argument key in tools/call
//! redact_arg         = *password*      # `*` wildcards are supported
//! max_bytes          = 65536           # reject messages larger than this
//! max_depth          = 32              # audit-flag messages nested deeper
//! rate_limit         = 20              # max forwarded messages per window
//! rate_window_ms     = 1000            # sliding window length
//! redaction_mask     = «redacted»      # replacement text for redacted values
//! ```
//!
//! The `allow_tool` / `deny_tool` lists match the `name` field of MCP
//! `tools/call` requests. `deny` always beats `allow`. If a tool is on neither
//! list, the `default` decision applies.

use std::collections::HashMap;

/// A fully-resolved policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub default_allow: bool,
