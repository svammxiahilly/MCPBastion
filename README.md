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

| File | Posture |
|------|---------|
| [`default.policy`](policies/default.policy) | Deny by default; read-only allow-list; credential redaction. |
| [`strict.policy`](policies/strict.policy) | A single allowed tool (`read_file`); aggressive redaction; `max_bytes 8192`, `rate_limit 5`. |
| [`permissive.policy`](policies/permissive.policy) | Allow by default; a small deny-list; light redaction — **dev only.** |

The authoritative format reference is [`docs/POLICY.md`](docs/POLICY.md).

## The redaction pipeline

Redaction is surgical, not cosmetic. Given a forwarded `tools/call`, the gateway locates `params.arguments` (an object) with the extractor, walks its **immediate** members, and for each key matching a `redact_arg` glob it replaces *only that value's byte span* with the mask encoded as a JSON string. Everything outside those spans is relayed verbatim (`gateway/src/redact.rs`).

- Splices are applied from the end of the line backwards, so earlier byte offsets stay valid.
- A non-string value redacts wholesale: `{"creds":{"k":"v"}}` with `redact_arg = creds` becomes `{"creds":"«redacted»"}`.
- The redacted key names (not the values) are recorded in the audit event's `redacted` array, so you can prove *what* was masked without ever logging the secret itself.
- If there is no `params.arguments` object, nothing changes and the original bytes pass through.

In the demo, `api_key`, `access_token`, and `authorization` are masked across three messages — visible as `bytes_out < bytes_in` on those audit lines.

## Rate, size and depth controls

Three independent limiters, each with a distinct job and a distinct outcome:

- **`max_bytes`** — a hard ceiling checked *first*, before parsing. Over-limit lines are **dropped** (`decision: drop`). Default `262144`.
- **`rate_limit` / `rate_window_ms`** — a sliding-window counter over *forwarded* messages only. When the window is full, the next would-be-forwarded message is **dropped**. `rate_limit = 0` means unlimited. Denied messages never consume the budget.
- **`max_depth`** — **advisory only.** The structural scan records the maximum nesting depth per message into the audit field `max_depth`, but a deep message is **not** rejected on that basis. It is a signal for the console, not a gate. (The `balanced` audit field is similarly advisory.)

## The audit console

The TypeScript console never touches the wire; it reads the audit log the gateway wrote. Three subcommands, all Node-stdlib-only:

![Audit console: decision radar and live event terminal](docs/assets/console.svg)

```sh
node console/dist/cli.js report <audit.jsonl> [--json] [--decision D] [--tool S]
node console/dist/cli.js tail   <audit.jsonl> [--decision D]
node console/dist/cli.js policy <policy-file>
```

`report` on the demo log:

```text
MCP Bastion — Audit Report
==========================

Total messages : 10
Bytes in/out   : 1204 / 582
Redaction events: 3
Unbalanced msgs : 0
Max depth seen  : 3
Gateway summary : MATCHES

Decisions
---------
  forward      4 ################........
  deny         6 ########################
  drop         0 ........................
  error        0 ........................
```

- **`report`** aggregates decisions, per-tool activity, redacted-key tallies, byte totals, and top reasons. `--json` emits the machine form; `--decision`/`--tool` narrow the per-event listing.
- **`tail`** prints one compact line per event — `#3 FORWARD read_file  allow_tool read_file`, with `[redacted: …]` appended when values were masked.
- **`policy`** parses, summarises, and **lints** a policy: unknown directives and non-integer numbers are errors; a `deny_tool` shadowing an `allow_tool`, or a redundant allow-list under `default = allow`, are warnings.

**`Gateway summary : MATCHES`** is the load-bearing line. With `--stats` the Rust gateway appends its own count of forward/deny/drop/error; the console independently recounts the log and compares. Agreement is a cheap cross-language integrity check — and `report` **exits non-zero** if they disagree.

## The JSON extractor: honesty and limits

The security of this checkpoint rests on one modest promise: *the extractor never mistakes the inside of a string for structure.* It keeps that promise (`gateway/src/json_scan.rs`) and makes no larger claim.

**It will:**

- Skip string literals correctly, honouring `\"`, `\\`, and `\uXXXX` escapes, so `{`, `}`, `,`, `:` inside a string are inert.
- Track object/array nesting so a key is matched only at the depth you asked for — a nested `"method"` inside `params` never shadows the top-level one.
- Return the raw byte span of a value, and decode a string field (including surrogate pairs) when it needs the text of `method` or `params.name`.

**It will not:**

- Validate that the whole line is well-formed JSON.
- Build a document tree, or decode numbers, booleans, or `null` into typed values.
- Normalise or de-duplicate repeated keys, or care about key ordering.

The consequence is deliberate and safe: the gateway reads the *minimum* needed for a decision, shrinking the attack surface versus a full parser, and when it cannot confidently extract a needed field it **fails closed** rather than improvising. It never pretends to understand more of your traffic than it does.

## Fail-closed behaviour

The default answer is "no." Concretely, a message is refused (denied or dropped) rather than forwarded whenever:

- it exceeds `max_bytes` (drop);
- it is not a JSON object (drop);
- it is a `tools/call` whose `params.name` cannot be extracted as a string (deny);
- its tool matches a `deny_tool` (deny);
- its tool is on no list and `default = deny` (deny);
- a non-`tools/call` method arrives under `default = deny` (deny);
- the rate window is full (drop).

There is no path in which uncertainty resolves to "forward." If the checkpoint cannot articulate a positive reason to pass a message, it does not pass it.

## Operational recipes

```sh
# Watch only what got blocked, live
node console/dist/cli.js tail audit.jsonl --decision deny

# Machine-readable rollup for a dashboard or CI gate
node console/dist/cli.js report audit.jsonl --json

# Everything a single tool did across a session
node console/dist/cli.js report audit.jsonl --tool read_file

# Lint a policy before you trust it (exits non-zero on errors)
node console/dist/cli.js policy policies/strict.policy

# Send audit to stderr (no --audit) and keep only the forwarded stream
cat session.jsonl | mcp-bastion --policy p.policy 2>/dev/null > forwarded.jsonl
```

## Exit behaviour

Streams:

- **stdout** — permitted, redacted messages, one per line. Flushed after every write.
- **audit sink** — one JSON event per input line; `stderr` by default, or the `--audit` file. Also flushed per write.
- **stderr** — errors and, absent `--audit`, the audit events themselves.

Exit codes (from `gateway/src/main.rs`):

| Code | Meaning |
|------|---------|
| `0` | Clean EOF — the session ended normally. |
| `1` | I/O error during the session. |
| `2` | Usage error (bad or missing arguments). |
| `3` | Policy could not be read or parsed. |

`error` as an audit *decision* is reserved and not emitted in 0.1 — the pipeline maps every message to forward, deny, or drop.

## Troubleshooting

- **`report` exits non-zero with `Gateway summary : MISMATCH!`** — the gateway's `--stats` counts and the console's recount disagree. Confirm you ran the gateway *with* `--stats`, and that the audit file wasn't truncated or appended to across runs (the gateway *creates* the file fresh with `--audit`).
- **Everything is denied, including `initialize`.** Expected under `default = deny`: non-`tools/call` methods are gated by `default`. Set `default = allow` if you want the handshake through, or scope with explicit rules.
- **A tool call I allowed is still denied.** Check for a `deny_tool` glob that also matches it — deny wins. Also confirm the match is case-sensitive and whole-string (`read_file` ≠ `read_files`).
- **Nothing was redacted although a secret went through.** The value's key must match a `redact_arg` glob *and* sit directly inside `params.arguments`. A secret nested deeper, or under another key, won't match — widen the pattern (e.g. `*token*`) or add the key.
- **A large message vanished with no deny reason.** It was likely **dropped** by `max_bytes` (checked before anything else) or by the rate limiter — look for `decision: drop` in the audit line.
- **`policy` reports lint errors and exits non-zero.** Fix unknown directives and non-integer numeric values; those are hard errors. Shadowed allows and redundant allow-lists are only warnings.

## Roadmap

0.1 is intentionally small and honest. Out of scope for now:

- **Response-side inspection.** Today the checkpoint reasons about requests; correlating and gating responses/results is future work.
- **Richer matching.** `?` and character-class globs, and per-tool argument schemas, are candidates beyond the current literal-plus-`*` matcher.
- **Live transport adapters.** The `stdin/stdout` JSONL contract is fixed by design; any HTTP/SSE bridging would be a separate, clearly-scoped component — not implied here.
- **The `error` decision.** Reserved in the schema; wiring internal processing faults to it is planned.

See [`CHANGELOG.md`](CHANGELOG.md) for what 0.1.0 actually shipped.

## Repository layout

```
mcp-bastion/
├── gateway/            Rust std-only gateway CLI (the enforcement point)
│   └── src/            json_scan · policy · redact · audit · engine · main
├── console/            TypeScript, Node-stdlib-only audit & policy viewer
│   └── src/            audit · report · policy · render · cli (+ node:test)
├── policies/           default · strict · permissive samples
├── sessions/           demo session + captured forwarded/audit output
├── docs/               POLICY.md, PROTOCOL.md, assets/ (SVGs)
├── Makefile            build / test / lint / demo orchestration
└── .github/workflows/  CI across both languages + integration
```

## License

[MIT](LICENSE).
