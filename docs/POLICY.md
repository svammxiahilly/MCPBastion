# Policy Reference

The MCP Bastion gateway is configured by a single, line-oriented policy file.
The format is deliberately tiny so the gateway can parse it with the Rust
standard library alone. The authoritative implementation lives in
