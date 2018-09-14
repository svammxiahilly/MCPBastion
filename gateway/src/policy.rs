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
    pub allow_tools: Vec<Pattern>,
    pub deny_tools: Vec<Pattern>,
    pub redact_args: Vec<Pattern>,
    pub max_bytes: usize,
    pub max_depth: usize,
    pub rate_limit: u32,
    pub rate_window_ms: u64,
    pub redaction_mask: String,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            default_allow: false,
            allow_tools: Vec::new(),
            deny_tools: Vec::new(),
            redact_args: Vec::new(),
            max_bytes: 256 * 1024,
            max_depth: 64,
            rate_limit: 0, // 0 == unlimited
            rate_window_ms: 1000,
            redaction_mask: "«redacted»".to_string(),
        }
    }
}

/// A simple case-sensitive glob supporting `*` wildcards (any run of chars).
#[derive(Debug, Clone)]
pub struct Pattern {
    raw: String,
    /// Literal segments that must appear in order; `None` markers between them
    /// represent `*`. `anchored_start`/`anchored_end` say whether the pattern
