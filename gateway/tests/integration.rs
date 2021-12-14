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
    let p = policy();
    let mut rl = RateLimiter::new(p.rate_limit, p.rate_window_ms);
    let msg = br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts","password":"hunter2","note":"ok"}}}"#;
    let out = process_line(msg, &p, &mut rl, 1, 0);
    assert_eq!(out.event.decision, Decision::Forward);
    let fwd = String::from_utf8(out.forward.unwrap()).unwrap();
    assert!(fwd.contains(r#""password":"[REDACTED]""#), "got: {fwd}");
    assert!(fwd.contains(r#""path":"/etc/hosts""#));
    assert!(fwd.contains(r#""note":"ok""#));
    assert_eq!(out.event.id.as_deref(), Some("10"));
    assert_eq!(out.event.tool.as_deref(), Some("read_file"));
    assert_eq!(out.event.redacted, vec!["password".to_string()]);
}

#[test]
fn deny_wildcard_tool() {
    let p = policy();
    let mut rl = RateLimiter::new(p.rate_limit, p.rate_window_ms);
