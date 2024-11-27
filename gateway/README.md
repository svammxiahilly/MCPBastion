# mcp-bastion (gateway)

The Rust component of [MCP Bastion](../README.md): a `std`-only CLI that gates
MCP JSON-RPC traffic.

## Build & test

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

The release binary is `target/release/mcp-bastion`.

## Usage

```text
mcp-bastion --policy <FILE> [--audit <FILE>] [--stats] [--epoch-ms <N>]
mcp-bastion --help | --version
```

| Flag           | Meaning                                                     |
|----------------|-------------------------------------------------------------|
| `--policy`     | Path to a policy file (required). See [POLICY.md](../docs/POLICY.md). |
| `--audit`      | Write audit events to a file instead of stderr.             |
| `--stats`      | Append a summary object at EOF.                             |
| `--epoch-ms`   | Fixed base timestamp for deterministic demos/tests.         |

Reads newline-delimited JSON-RPC from stdin, forwards permitted (redacted)
messages to stdout, and writes one JSON audit event per message to the audit
sink.

## Modules

| Module        | Responsibility                                             |
