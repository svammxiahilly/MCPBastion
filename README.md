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
| `gateway/` | Rust (`std` only) | The enforcement point. Reads, decides, redacts, forwards, audits. |
| `console/` | TypeScript (Node stdlib only) | The read-side. Aggregates audit logs, tails events, lints policies. |

## Control-room index

- [What this actually is (and is not)](#what-this-actually-is-and-is-not)
- [The checkpoint, message by message](#the-checkpoint-message-by-message)
- [Standing up the gateway](#standing-up-the-gateway)
- [The demo session, replayed](#the-demo-session-replayed)
- [Policy routing](#policy-routing)
- [The redaction pipeline](#the-redaction-pipeline)
- [Rate, size and depth controls](#rate-size-and-depth-controls)
- [The audit console](#the-audit-console)
- [The JSON extractor: honesty and limits](#the-json-extractor-honesty-and-limits)
- [Fail-closed behaviour](#fail-closed-behaviour)
- [Operational recipes](#operational-recipes) · [Exit behaviour](#exit-behaviour) · [Troubleshooting](#troubleshooting) · [Roadmap](#roadmap)

## The checkpoint, message by message

Every non-empty input line runs the same gauntlet, in this order. The first gate that fires decides the message; nothing downstream of it runs. This is the pipeline in `gateway/src/engine.rs::process_line`:

1. **Size.** If the raw line is longer than `max_bytes`, it is **dropped** — before any parsing. A huge line never gets the chance to be interesting.
2. **Shape.** If, after leading whitespace, the line does not begin with `{`, it is **dropped** as "not a JSON object".
3. **Classify.** The top-level `method` is extracted. Only `tools/call` is tool-gated; every other method (`initialize`, `tools/list`, …) is governed solely by the `default` decision, so `default = deny` locks the checkpoint down to an audited allow-list of tool calls.
4. **Name.** For a `tools/call`, `params.name` is extracted. A `tools/call` with no extractable string name is **denied** — reason `tools/call missing extractable params.name`.
5. **Deny list.** If the name matches any `deny_tool` glob → **deny**. Deny always beats allow.
6. **Allow list.** Else if it matches any `allow_tool` glob → continue. Else apply `default`.
7. **Rate.** A would-be-forwarded message arriving while the rolling window is full is **dropped**. Only forwarded messages count against the window.
8. **Redact & forward.** Matching argument values are spliced with the mask, and the message — every other byte intact — is written to `stdout`.

Whatever the outcome, one audit event is emitted describing it.

## Standing up the gateway

Prerequisites: a Rust toolchain (`cargo`) and Node.js ≥ 18.

```sh
make build          # cargo build --release  +  npm install && npm run build
make demo           # runs the whole gauntlet end-to-end and prints the report
```

`make demo` is the fastest way to see the checkpoint work; it is the exact command below, wired to the shipped sample session so the whole thing is self-contained and deterministic:

```sh
