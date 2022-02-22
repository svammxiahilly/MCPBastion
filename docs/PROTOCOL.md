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

