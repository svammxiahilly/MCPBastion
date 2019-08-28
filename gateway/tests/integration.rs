//! End-to-end integration tests over the public library surface.
//!
//! These complement the per-module unit tests by exercising the whole decision
//! pipeline the way `main` does, but without touching real I/O.

use mcp_bastion::audit::Decision;
use mcp_bastion::engine::process_line;
use mcp_bastion::policy::{Policy, RateLimiter};

fn policy() -> Policy {
    Policy::parse(
        "\
default = deny
allow_tool = read_file
allow_tool = list_dir
deny_tool = shell.*
deny_tool = fs.delete
redact_arg = *token*
redact_arg = password
redact_arg = *secret*
max_bytes = 4096
rate_limit = 5
rate_window_ms = 1000
redaction_mask = \"[REDACTED]\"
",
    )
    .unwrap()
}

#[test]
fn full_allow_flow_with_redaction() {
