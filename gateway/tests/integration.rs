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
