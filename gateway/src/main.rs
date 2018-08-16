//! `mcp-bastion` — the command-line entry point.
//!
//! Reads newline-delimited JSON-RPC messages from stdin, evaluates each against
//! a policy, forwards permitted (and redacted) messages to stdout, and writes a
//! one-line JSON audit event per message to the audit sink.
//!
//! Usage:
//! ```text
//! mcp-bastion --policy <FILE> [--audit <FILE>] [--stats] [--epoch-ms <N>]
//! mcp-bastion --help
//! mcp-bastion --version
//! ```
//!
//! Flags:
//!   --policy   <FILE>   Path to a policy file (required).
//!   --audit    <FILE>   Write audit events here instead of stderr.
//!   --stats             Print a summary line to the audit sink at EOF.
//!   --epoch-ms <N>      Use a fixed starting timestamp (for deterministic
//!                       demos/tests). Defaults to a monotonic clock.
//!
//! Exit codes: 0 on clean EOF, 2 on usage error, 3 on policy load error.

use std::collections::BTreeMap;
use std::fs;
