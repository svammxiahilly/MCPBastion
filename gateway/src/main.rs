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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::ExitCode;
use std::time::Instant;

use mcp_bastion::audit::Decision;
use mcp_bastion::engine::{self};
use mcp_bastion::policy::{Policy, RateLimiter};

const USAGE: &str = "\
mcp-bastion — a local zero-trust MCP JSON-RPC gateway

USAGE:
    mcp-bastion --policy <FILE> [--audit <FILE>] [--stats] [--epoch-ms <N>]
    mcp-bastion --help | --version

FLAGS:
    --policy   <FILE>   Path to the policy file (required)
    --audit    <FILE>   Write audit events to FILE (default: stderr)
    --stats             Emit a summary object at EOF
    --epoch-ms <N>      Fixed base timestamp in ms (deterministic mode)
    --help              Show this help
    --version           Show version

Reads newline-delimited JSON-RPC from stdin; forwards allowed, redacted
messages to stdout; emits one JSON audit event per message to the audit sink.
";

struct Args {
    policy_path: Option<String>,
    audit_path: Option<String>,
    stats: bool,
    epoch_ms: Option<u64>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        policy_path: None,
        audit_path: None,
        stats: false,
        epoch_ms: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("mcp-bastion {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--policy" => {
                a.policy_path = Some(it.next().ok_or("--policy requires a value")?);
            }
            "--audit" => {
                a.audit_path = Some(it.next().ok_or("--audit requires a value")?);
            }
            "--stats" => a.stats = true,
            "--epoch-ms" => {
                let v = it.next().ok_or("--epoch-ms requires a value")?;
                a.epoch_ms = Some(
                    v.parse::<u64>()
                        .map_err(|_| "--epoch-ms must be an integer")?,
                );
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let policy_path = match &args.policy_path {
        Some(p) => p,
        None => {
            eprintln!("error: --policy is required\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let policy_text = match fs::read_to_string(policy_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: cannot read policy '{policy_path}': {e}");
            return ExitCode::from(3);
        }
    };
    let policy = match Policy::parse(&policy_text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: invalid policy '{policy_path}': {e}");
            return ExitCode::from(3);
        }
    };

    // Audit sink: file or stderr.
    let mut audit_sink: Box<dyn Write> = match &args.audit_path {
        Some(path) => match fs::File::create(path) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("error: cannot create audit file '{path}': {e}");
                return ExitCode::from(3);
            }
        },
        None => Box::new(io::stderr()),
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let run = run_session(
        &policy,
        stdin.lock(),
        &mut out,
        audit_sink.as_mut(),
        args.epoch_ms,
        args.stats,
    );

    if let Err(e) = run {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Drive a whole session. Broken out so it is testable with in-memory buffers.
fn run_session<R: Read>(
    policy: &Policy,
    reader: R,
    out: &mut dyn Write,
    audit: &mut dyn Write,
    epoch_ms: Option<u64>,
    stats: bool,
) -> io::Result<()> {
    let mut limiter = RateLimiter::new(policy.rate_limit, policy.rate_window_ms);
    let start = Instant::now();
    let base = epoch_ms.unwrap_or(0);

    let mut seq: u64 = 0;
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();

    let buf = BufReader::new(reader);
    for line_res in buf.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        seq += 1;

        // Timestamp: fixed base + monotonic offset. In deterministic mode
        // (epoch given) we still add the elapsed offset so rate windows behave,
        // but demos pin epoch_ms and feed small inputs so ordering is stable.
        let now_ms = base + elapsed_ms(&start);

        let processed = engine::process_line(trimmed.as_bytes(), policy, &mut limiter, seq, now_ms);

        if let Some(bytes) = &processed.forward {
            out.write_all(bytes)?;
            out.write_all(b"\n")?;
            out.flush()?;
        }

        let ev = processed.event;
        *counts.entry(ev.decision.as_str()).or_insert(0) += 1;
        writeln!(audit, "{}", ev.to_json())?;
        audit.flush()?;
    }

    if stats {
        let summary = format!(
            "{{\"summary\":true,\"total\":{},\"forward\":{},\"deny\":{},\"drop\":{},\"error\":{}}}",
            seq,
            counts.get(Decision::Forward.as_str()).copied().unwrap_or(0),
            counts.get(Decision::Deny.as_str()).copied().unwrap_or(0),
            counts.get(Decision::Drop.as_str()).copied().unwrap_or(0),
            counts.get(Decision::Error.as_str()).copied().unwrap_or(0),
        );
        writeln!(audit, "{summary}")?;
        audit.flush()?;
    }

    Ok(())
}

fn elapsed_ms(start: &Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "\
default = deny
allow_tool = read_file
deny_tool = shell.*
redact_arg = *token*
max_bytes = 8192
rate_limit = 0
redaction_mask = \"***\"
";

    fn session(input: &str) -> (String, String) {
        let policy = Policy::parse(POLICY).unwrap();
        let mut out = Vec::new();
        let mut audit = Vec::new();
        run_session(
            &policy,
            input.as_bytes(),
            &mut out,
            &mut audit,
            Some(1000),
            true,
        )
        .unwrap();
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(audit).unwrap(),
        )
    }

    #[test]
    fn forwards_allowed_redacts_and_denies() {
        let input = concat!(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/x","auth_token":"abc"}}}"#,
            "\n",
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell.exec","arguments":{"cmd":"whoami"}}}"#,
            "\n",
        );
        let (out, audit) = session(input);
        // Only the allowed message is forwarded, with redaction applied.
        let fwd_lines: Vec<&str> = out.lines().collect();
        assert_eq!(fwd_lines.len(), 1);
        assert!(fwd_lines[0].contains(r#""auth_token":"***""#));
        // Audit has two events plus a summary line.
        let audit_lines: Vec<&str> = audit.lines().collect();
        assert_eq!(audit_lines.len(), 3);
        assert!(audit_lines[0].contains(r#""decision":"forward""#));
        assert!(audit_lines[1].contains(r#""decision":"deny""#));
        assert!(audit_lines[2].contains(r#""summary":true"#));
        assert!(audit_lines[2].contains(r#""forward":1"#));
        assert!(audit_lines[2].contains(r#""deny":1"#));
    }

    #[test]
    fn blank_lines_are_skipped() {
        let input = "\n\n   \n";
        let (out, audit) = session(input);
        assert!(out.is_empty());
        // Only the summary line is present.
        assert_eq!(audit.lines().count(), 1);
        assert!(audit.contains(r#""total":0"#));
    }
}
