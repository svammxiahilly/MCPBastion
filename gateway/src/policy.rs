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
    /// touches the respective boundary.
    parts: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

impl Pattern {
    pub fn new(raw: &str) -> Pattern {
        let anchored_start = !raw.starts_with('*');
        let anchored_end = !raw.ends_with('*');
        let parts: Vec<String> = raw
            .split('*')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Pattern {
            raw: raw.to_string(),
            parts,
            anchored_start,
            anchored_end,
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Does this pattern match the whole of `text`?
    pub fn matches(&self, text: &str) -> bool {
        if self.parts.is_empty() {
            // Pattern was "" or "*" or "***" -> matches everything.
            return true;
        }
        let mut pos = 0usize;
        for (idx, part) in self.parts.iter().enumerate() {
            let is_first = idx == 0;
            let is_last = idx == self.parts.len() - 1;
            if is_first && self.anchored_start {
                if !text[pos..].starts_with(part.as_str()) {
                    return false;
                }
                pos += part.len();
            } else {
                match text[pos..].find(part.as_str()) {
                    Some(rel) => pos += rel + part.len(),
                    None => return false,
                }
            }
            if is_last && self.anchored_end {
                // The final literal must land exactly at the end.
                return pos == text.len();
            }
        }
        true
    }
}

/// Errors that can occur while loading a policy file.
#[derive(Debug)]
pub enum PolicyError {
    UnknownDirective {
        line: usize,
        key: String,
    },
    BadValue {
        line: usize,
        key: String,
        value: String,
    },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnknownDirective { line, key } => {
                write!(f, "line {line}: unknown directive '{key}'")
            }
            PolicyError::BadValue { line, key, value } => {
                write!(f, "line {line}: invalid value '{value}' for '{key}'")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    /// Parse a policy from its textual representation.
    pub fn parse(text: &str) -> Result<Policy, PolicyError> {
        let mut p = Policy::default();
        for (idx, raw_line) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = split_directive(line);
            let key = key.trim();
            let value = value.trim();
            match key {
                "default" => match value {
                    "allow" => p.default_allow = true,
                    "deny" => p.default_allow = false,
                    other => {
                        return Err(PolicyError::BadValue {
                            line: line_no,
                            key: key.to_string(),
                            value: other.to_string(),
                        })
                    }
                },
                "allow_tool" => p.allow_tools.push(Pattern::new(value)),
                "deny_tool" => p.deny_tools.push(Pattern::new(value)),
                "redact_arg" => p.redact_args.push(Pattern::new(value)),
                "max_bytes" => p.max_bytes = parse_usize(value, key, line_no)?,
                "max_depth" => p.max_depth = parse_usize(value, key, line_no)?,
                "rate_limit" => p.rate_limit = parse_u32(value, key, line_no)?,
                "rate_window_ms" => p.rate_window_ms = parse_u64(value, key, line_no)?,
                "redaction_mask" => p.redaction_mask = unquote(value),
                other => {
                    return Err(PolicyError::UnknownDirective {
                        line: line_no,
                        key: other.to_string(),
                    })
                }
            }
        }
        Ok(p)
    }

    /// Decide whether a named tool is permitted. `deny` beats `allow`; unknown
    /// tools fall back to `default_allow`.
    pub fn decide_tool(&self, tool: &str) -> ToolDecision {
        if let Some(pat) = self.deny_tools.iter().find(|p| p.matches(tool)) {
            return ToolDecision::Deny {
                rule: format!("deny_tool {}", pat.raw()),
            };
        }
        if let Some(pat) = self.allow_tools.iter().find(|p| p.matches(tool)) {
            return ToolDecision::Allow {
                rule: format!("allow_tool {}", pat.raw()),
            };
        }
        if self.default_allow {
            ToolDecision::Allow {
                rule: "default allow".to_string(),
            }
        } else {
            ToolDecision::Deny {
                rule: "default deny".to_string(),
            }
        }
    }

    /// Should this argument key be redacted?
    pub fn should_redact(&self, arg_key: &str) -> bool {
        self.redact_args.iter().any(|p| p.matches(arg_key))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDecision {
    Allow { rule: String },
    Deny { rule: String },
}

impl ToolDecision {
    pub fn is_allow(&self) -> bool {
        matches!(self, ToolDecision::Allow { .. })
    }
    pub fn rule(&self) -> &str {
        match self {
            ToolDecision::Allow { rule } | ToolDecision::Deny { rule } => rule,
        }
    }
}

fn strip_comment(line: &str) -> &str {
    // A `#` outside of any quoting starts a comment. Our directives never
    // contain `#` except possibly inside a quoted redaction_mask, which we
    // handle by only splitting on the first unquoted `#`.
    let bytes = line.as_bytes();
    let mut in_quote = false;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'#' if !in_quote => return &line[..i],
            _ => {}
        }
    }
    line
}

fn split_directive(line: &str) -> (&str, &str) {
    if let Some(eq) = line.find('=') {
        (&line[..eq], &line[eq + 1..])
    } else if let Some(sp) = line.find(char::is_whitespace) {
        (&line[..sp], &line[sp + 1..])
    } else {
        (line, "")
    }
}

fn unquote(value: &str) -> String {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

fn parse_usize(value: &str, key: &str, line: usize) -> Result<usize, PolicyError> {
    value.parse::<usize>().map_err(|_| PolicyError::BadValue {
        line,
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_u32(value: &str, key: &str, line: usize) -> Result<u32, PolicyError> {
    value.parse::<u32>().map_err(|_| PolicyError::BadValue {
        line,
        key: key.to_string(),
        value: value.to_string(),
    })
}

fn parse_u64(value: &str, key: &str, line: usize) -> Result<u64, PolicyError> {
    value.parse::<u64>().map_err(|_| PolicyError::BadValue {
        line,
        key: key.to_string(),
        value: value.to_string(),
    })
}

/// A sliding-window rate limiter keyed by nothing (global) — the gateway
/// processes a single session, so one counter suffices.
#[derive(Debug)]
pub struct RateLimiter {
    limit: u32,
    window_ms: u64,
    /// Timestamps (ms since an arbitrary epoch) of recent allowed messages.
    events: Vec<u64>,
}

impl RateLimiter {
    pub fn new(limit: u32, window_ms: u64) -> RateLimiter {
        RateLimiter {
            limit,
            window_ms,
            events: Vec::new(),
        }
    }

    /// Returns `true` if an event at `now_ms` is within the limit. When
    /// accepted, the event is recorded. `limit == 0` means unlimited.
    pub fn check(&mut self, now_ms: u64) -> bool {
        if self.limit == 0 {
            return true;
        }
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.events.retain(|&t| t >= cutoff);
        if (self.events.len() as u32) < self.limit {
            self.events.push(now_ms);
            true
        } else {
            false
        }
    }

    /// Current count of live events within the window at `now_ms`.
    pub fn current(&self, now_ms: u64) -> usize {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        self.events.iter().filter(|&&t| t >= cutoff).count()
    }
}

/// Tracks per-tool statistics reported by the counters map for auditing.
pub type ToolCounts = HashMap<String, u64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_exact() {
        let p = Pattern::new("read_file");
        assert!(p.matches("read_file"));
        assert!(!p.matches("read_files"));
        assert!(!p.matches("xread_file"));
    }

    #[test]
    fn pattern_prefix() {
        let p = Pattern::new("shell.*");
        assert!(p.matches("shell.exec"));
        assert!(p.matches("shell."));
        assert!(!p.matches("shel"));
    }

    #[test]
    fn pattern_contains() {
        let p = Pattern::new("*password*");
        assert!(p.matches("db_password"));
        assert!(p.matches("password"));
        assert!(p.matches("user_password_hash"));
        assert!(!p.matches("passwrd"));
    }

    #[test]
    fn pattern_suffix() {
        let p = Pattern::new("*_token");
        assert!(p.matches("auth_token"));
        assert!(!p.matches("token_value"));
    }

    #[test]
    fn parse_basic_policy() {
        let text = "\
# sample
default = deny
allow_tool = read_file
allow_tool = list_dir
deny_tool = shell.*
redact_arg = *token*
max_bytes = 1024
rate_limit = 5
rate_window_ms = 2000
redaction_mask = \"[hidden]\"
";
        let p = Policy::parse(text).unwrap();
        assert!(!p.default_allow);
        assert_eq!(p.allow_tools.len(), 2);
        assert_eq!(p.deny_tools.len(), 1);
        assert_eq!(p.max_bytes, 1024);
        assert_eq!(p.rate_limit, 5);
        assert_eq!(p.rate_window_ms, 2000);
        assert_eq!(p.redaction_mask, "[hidden]");
    }

    #[test]
    fn deny_beats_allow() {
        let p = Policy::parse("allow_tool = shell.exec\ndeny_tool = shell.*\n").unwrap();
        let d = p.decide_tool("shell.exec");
        assert!(!d.is_allow());
    }

    #[test]
    fn default_deny_unknown_tool() {
        let p = Policy::parse("default = deny\nallow_tool = read_file\n").unwrap();
        assert!(!p.decide_tool("delete_all").is_allow());
        assert!(p.decide_tool("read_file").is_allow());
    }

    #[test]
    fn unknown_directive_errors() {
        let err = Policy::parse("wat = 1\n").unwrap_err();
        matches!(err, PolicyError::UnknownDirective { .. });
    }

    #[test]
    fn bad_number_errors() {
        let err = Policy::parse("max_bytes = notanumber\n").unwrap_err();
        matches!(err, PolicyError::BadValue { .. });
    }

    #[test]
    fn rate_limiter_windowing() {
        let mut rl = RateLimiter::new(2, 1000);
        assert!(rl.check(0));
        assert!(rl.check(100));
        assert!(!rl.check(200)); // third within window rejected
        assert!(rl.check(1200)); // first has aged out
    }

    #[test]
    fn rate_limiter_unlimited() {
        let mut rl = RateLimiter::new(0, 1000);
        for t in 0..100 {
            assert!(rl.check(t));
        }
    }

    #[test]
    fn comment_stripping_respects_quotes() {
        let p = Policy::parse("redaction_mask = \"a#b\" # trailing\n").unwrap();
        assert_eq!(p.redaction_mask, "a#b");
    }
}
