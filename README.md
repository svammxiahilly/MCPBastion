# MCP Bastion

> **03:14 — a session you didn't fully trust just asked a tool server to run `shell.exec { "cmd": "rm -rf /" }`.**
> The client thought it was fine. The server would have obeyed. Between them sat one process reading the line off `stdin`, matching `shell.*` against a deny rule, writing nothing to `stdout`, and dropping a single JSON audit event that says exactly why. That process is MCP Bastion.

MCP Bastion is a **local zero-trust checkpoint** for the [Model Context Protocol](https://modelcontextprotocol.io). It reads newline-delimited JSON-RPC from `stdin`, decides each message against a policy — allow / deny / redact — and writes only what survives to `stdout`. Every message, forwarded or not, leaves a one-line audit record. It runs entirely on your machine, uses **no third-party runtime dependencies**, and **fails closed**: anything it cannot confidently authorise is denied or dropped, never forwarded.

![Requests moving through the allow, deny and redact gates](docs/assets/gates.svg)

## What this actually is (and is not)

Read this before anything else — the honesty here is the whole point.

- **It is** a line-oriented relay that sits on the MCP `stdio` transport, inspects a handful of JSON-RPC fields, and enforces a policy on `tools/call`.
- **It is not** a transport proxy. It does **not** speak HTTP or SSE, does **not** open sockets, does **not** manage the MCP handshake, and does **not** spawn the downstream server for you. It moves bytes between one `stdin` and one `stdout`, framed as one JSON object per `\n`-terminated line. That is the entire I/O contract.
- **It is not** a JSON validator. There is no full parser inside. There is a small, single-pass **field extractor** (`gateway/src/json_scan.rs`) that reads exactly four fields — `method`, `id`, `params.name`, `params.arguments` — while correctly skipping string literals so a `{` or `"` inside a value can never be mistaken for structure. When it cannot confidently extract a field it needs, it stops guessing and denies.

Two components, two languages, zero runtime deps:

| Component | Language | Role |
|-----------|----------|------|
