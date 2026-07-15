# Protocol & I/O Contract

MCP Bastion sits between an MCP **client** and an MCP **server**, on the
`stdio` transport that MCP defines. It is a byte-level relay with policy:

```
client ──stdin──▶ mcp-bastion ──stdout──▶ server
                      │
                      └──audit (stderr or file)
```

## Message framing

- Input and output are **newline-delimited JSON** (`\n`). Each non-empty line
  is treated as one JSON-RPC message. `\r\n` is tolerated (the trailing `\r`
  is trimmed).
- Blank lines are skipped and never forwarded.
- The gateway forwards each **permitted** message as a single line followed by
  `\n`. Redacted messages are re-emitted with only the redacted value spans
  replaced; all other bytes are preserved exactly.

This matches the line-based framing used by common MCP stdio clients. The
gateway does not implement the HTTP/SSE transport.

## What the gateway understands about JSON — honestly

The gateway does **not** contain a full JSON parser and does not claim to.
Instead it uses a small, single-pass **field extractor**
([`gateway/src/json_scan.rs`](../gateway/src/json_scan.rs)) that understands
exactly enough of the grammar to be safe:

- It correctly **skips string literals**, including `\"`, `\\`, and `\uXXXX`
  escapes, so structural characters inside strings (`{`, `}`, `,`, `:`) are
  never mistaken for structure. This is the property that matters for a
  security relay.
- It tracks object/array **nesting depth** and can return the **raw byte span**
  of the value following a matched key.
- It can **decode** a JSON string literal (including surrogate pairs) when it
  needs the textual value of a field such as `method` or `params.name`.

It deliberately does **not**:

- validate that the whole message is well-formed JSON,
- build a document tree or decode numbers/booleans,
- normalise duplicate keys.

Consequences, by design:

- The gateway only inspects the fields it needs: top-level `method` and `id`,
  and `params.name` / `params.arguments` for `tools/call`.
- If it cannot confidently extract a needed field (e.g. a `tools/call` whose
  `params.name` is missing or not a string), it **fails closed** and denies the
  message rather than guessing.
- A structural balance check is run purely to populate audit metadata
  (`balanced`, `max_depth`); it never rejects a message on its own.

## Fields consulted

| Field              | Used for                                             |
|--------------------|------------------------------------------------------|
| `method`           | Classify the message; only `tools/call` is tool-gated.|
| `id`               | Recorded verbatim in the audit event.                |
| `params.name`      | The tool name matched against allow/deny lists.      |
| `params.arguments` | The object whose member values are redacted.         |

## Audit event schema

Every processed message emits exactly one JSON object, one per line, to the
audit sink (`stderr` by default, or `--audit <file>`). Serialisation is in
[`gateway/src/audit.rs`](../gateway/src/audit.rs); the consumer is
[`console/src/audit.ts`](../console/src/audit.ts).

```json
{
  "ts_ms":     4,
  "seq":       3,
  "decision":  "forward",
  "reason":    "allow_tool read_file",
  "method":    "tools/call",
  "tool":      "read_file",
  "id":        "3",
  "bytes_in":  110,
  "bytes_out": 110,
  "redacted":  ["auth_token"],
  "balanced":  true,
  "max_depth": 3
}
```

| Field       | Type              | Notes |
|-------------|-------------------|-------|
| `ts_ms`     | number            | Milliseconds since process start (plus `--epoch-ms` base). |
| `seq`       | number            | 1-based counter of non-empty input lines. |
| `decision`  | string            | `forward` \| `deny` \| `drop` \| `error`. |
| `reason`    | string            | Human-readable rule that produced the decision. |
| `method`    | string \| null    | Extracted `method`, or null. |
| `tool`      | string \| null    | Extracted `params.name` for `tools/call`, else null. |
| `id`        | string \| null    | Raw text of the top-level `id`, or null. |
| `bytes_in`  | number            | Length of the input line in bytes. |
| `bytes_out` | number            | Length of the forwarded message, or 0. |
| `redacted`  | string[]          | Argument keys whose values were redacted. |
| `balanced`  | boolean           | Whether brackets/quotes balanced across the input. |
| `max_depth` | number            | Maximum nesting depth observed. |

### Decisions

| Decision  | Meaning                                                        |
|-----------|----------------------------------------------------------------|
| `forward` | Permitted (after any redaction); written to stdout.            |
| `deny`    | Blocked by an allow/deny rule or fail-closed extraction.       |
| `drop`    | Discarded by a limit (size / rate) or because it is not an object. |
| `error`   | Reserved for internal processing errors (none emitted in 0.1). |

### Summary line

With `--stats`, a final object is appended to the audit sink:

```json
{"summary":true,"total":10,"forward":4,"deny":6,"drop":0,"error":0}
```

The console cross-checks this against its own recount and exits non-zero from
`report` if they disagree — a cheap integrity check across the two languages.

## Exit codes

| Code | Meaning                        |
|------|--------------------------------|
| 0    | Clean EOF.                     |
| 1    | I/O error during the session.  |
| 2    | Usage error (bad arguments).   |
| 3    | Policy could not be loaded.    |
