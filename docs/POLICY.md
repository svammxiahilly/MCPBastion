# Policy Reference

The MCP Bastion gateway is configured by a single, line-oriented policy file.
The format is deliberately tiny so the gateway can parse it with the Rust
standard library alone. The authoritative implementation lives in
[`gateway/src/policy.rs`](../gateway/src/policy.rs); the console's read-only
parser in [`console/src/policy.ts`](../console/src/policy.ts) mirrors it for
display and linting.

## Syntax

- One directive per line.
- A directive is `key = value` **or** `key value` (the first `=` or run of
  whitespace separates key from value).
- Blank lines are ignored.
