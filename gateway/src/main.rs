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
