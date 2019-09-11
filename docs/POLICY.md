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
- `#` starts a comment and runs to end of line, **unless** it appears inside a
  double-quoted value (so a `redaction_mask` may contain `#`).
- Values may be optionally double-quoted; the quotes are stripped. This is the
  only way to include leading/trailing spaces or a literal `#`.

## Directives

| Directive         | Value           | Default      | Meaning |
|-------------------|-----------------|--------------|---------|
| `default`         | `allow`\|`deny` | `deny`       | Decision when a tool matches no list, and the gate for non-`tools/call` methods. |
