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
