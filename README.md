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
cat sessions/demo-session.jsonl \
  | gateway/target/release/mcp-bastion \
      --policy policies/default.policy \
      --audit sessions/demo-audit.jsonl \
      --stats --epoch-ms 0 \
  > sessions/demo-forwarded.jsonl
```

The flags, precisely:

| Flag | Meaning |
|------|---------|
| `--policy <FILE>` | **Required.** The policy to enforce. |
| `--audit <FILE>` | Write audit events here instead of `stderr`. |
| `--stats` | Append a `{"summary":true,…}` line at EOF. |
| `--epoch-ms <N>` | Pin the base timestamp for deterministic demos/tests. |
| `--help` / `--version` | Print usage or version and exit. |

### Placing it inline (the honest way)

In real use the checkpoint belongs *in the pipe* between your client and your MCP server, framed as newline JSON both ways. Because the gateway is strictly a `stdin → stdout` relay, you compose it with the shell (or your client's launch config), not with a built-in "wrap this server" flag:

```sh
your-mcp-client \
  | mcp-bastion --policy policies/default.policy --audit audit.jsonl \
  | some-mcp-server
```

This repo ships the single-direction *replay* form (`cat session | mcp-bastion > forwarded`) so the demo needs no live server. There is no reverse channel management, no request/response correlation, and no transport translation — don't read more into it than that.

## The demo session, replayed

The sample [`sessions/demo-session.jsonl`](sessions/demo-session.jsonl) is ten messages: a handshake, a `tools/list`, six real tool calls, a couple of dangerous ones, and one malformed `tools/call` with no `name`. Under [`policies/default.policy`](policies/default.policy) (deny-by-default, read-only allow-list, credential redaction) it yields **4 forwarded, 6 denied, 0 dropped**.

What comes out on `stdout` is the four survivors, with credentials — and nothing else — replaced. Note how the `{brace}` and escaped `"quotes"` inside the `note` string ride through untouched: proof the extractor respects string boundaries.

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"search_files","arguments":{"query":"password","access_token":"«redacted»","note":"contains a {brace} and \"quotes\""}}}
```

The six that never reach the server, and why:

| id | tool / method | decision | reason |
|----|---------------|----------|--------|
| 1 | `initialize` | deny | default deny (non `tools/call`) |
| 2 | `tools/list` | deny | default deny (non `tools/call`) |
| 6 | `shell.exec` | deny | `deny_tool shell.*` |
| 7 | `fs.delete` | deny | `deny_tool fs.delete` |
| 8 | `format_disk` | deny | default deny (not on allow-list) |
| 10 | *(missing name)* | deny | `tools/call missing extractable params.name` |

Everything the gateway wrote to the audit sink for this run is captured verbatim in [`sessions/demo-audit.jsonl`](sessions/demo-audit.jsonl), and the forwarded stream in [`sessions/demo-forwarded.jsonl`](sessions/demo-forwarded.jsonl).

## Policy routing

A policy is a tiny, line-oriented file (`key = value` or `key value`; `#` comments; blank lines ignored). The [`default.policy`](policies/default.policy) posture reads like a checkpoint duty roster:

```text
default = deny

allow_tool = read_file
allow_tool = list_dir
allow_tool = search_files
allow_tool = get_metadata

deny_tool  = shell.*
deny_tool  = fs.delete
deny_tool  = net.*

redact_arg = *token*
redact_arg = *secret*
redact_arg = api_key
redact_arg = authorization

max_bytes      = 65536
rate_limit     = 20
rate_window_ms = 1000
redaction_mask = "«redacted»"
```

Routing rules that matter:

- **Deny wins.** If a tool matches both an `allow_tool` and a `deny_tool`, it is denied.
- **Globs are literal + `*`.** `*` matches any run of characters (including empty); there is no `?` or character class. Matching is case-sensitive and must cover the whole name. So `shell.*` catches `shell.exec` but not `shellx`, and `*token*` catches `auth_token`, `token`, and `x_token_y`.
- **`default` is also the gate for non-`tools/call` methods.** With `default = deny`, an `initialize` or `tools/list` is denied unless you flip the default.

Three sample postures ship in [`policies/`](policies):
