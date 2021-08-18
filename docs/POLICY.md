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
| `allow_tool`      | glob            | (none)       | Permit a tool by name. May repeat. |
| `deny_tool`       | glob            | (none)       | Forbid a tool by name. May repeat. **Deny beats allow.** |
| `redact_arg`      | glob            | (none)       | Redact the value of matching argument keys in `tools/call`. May repeat. |
| `max_bytes`       | integer         | `262144`     | Messages larger than this are dropped. |
| `max_depth`       | integer         | `64`         | Advisory nesting depth; recorded in audit metadata (not enforced as a reject). |
| `rate_limit`      | integer         | `0`          | Max forwarded messages per window. `0` = unlimited. |
| `rate_window_ms`  | integer         | `1000`       | Rolling window length in milliseconds. |
| `redaction_mask`  | string          | `«redacted»` | Replacement text spliced in place of redacted values. |

## Globs

Globs use `*` as a wildcard that matches any run of characters (including the
empty string). Everything else is a literal. There is no `?` or character
class. Matching is case-sensitive and must cover the **whole** string.

Examples:

| Pattern       | Matches                         | Does not match     |
|---------------|----------------------------------|--------------------|
| `read_file`   | `read_file`                      | `read_files`       |
