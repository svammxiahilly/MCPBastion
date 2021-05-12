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

