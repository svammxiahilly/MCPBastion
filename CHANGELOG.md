# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Docs

- One-line pointer from the console guide to the gateway reference.

## [Unreleased]

### Docs

- Worked redact example in the README and in the console guide.

## [0.1.0] - 2026-08-31

### Added

- **Rust gateway (`gateway/`)** — a `std`-only CLI, `mcp-bastion`, that reads
  newline-delimited JSON-RPC from stdin, evaluates each message against a
  policy, and forwards permitted (and redacted) messages to stdout.
  - Honest single-pass JSON field extractor (`json_scan`) that skips string
    literals, tracks nesting, and returns raw value spans. It is explicitly
    **not** a full JSON parser and never claims to be.
  - Line-oriented policy format (`policy`) with `allow_tool` / `deny_tool`
    glob rules (deny wins), `redact_arg` patterns, `max_bytes`, `max_depth`,
    `rate_limit` / `rate_window_ms`, and a configurable `redaction_mask`.
  - Sliding-window rate limiter.
  - Argument-value redaction (`redact`) that preserves surrounding bytes.
  - Structured, one-line-per-event JSON audit records (`audit`).
  - Pure decision pipeline (`engine`) covered by unit and integration tests.
  - `--stats` summary line and deterministic `--epoch-ms` mode for demos.
- **TypeScript console (`console/`)** — a dependency-free (Node standard
  library only) viewer:
  - `report` — aggregate an audit log into decision counts, per-tool stats,
    redaction tallies, and a byte summary; cross-checks the gateway's own
    summary line. `--json` for machine output; `--decision`/`--tool` filters.
  - `tail` — one compact line per event.
  - `policy` — parse, summarise, and lint a policy file (unknown directives,
    shadowed allows, bad numbers).
- **Samples** — three policies (`default`, `permissive`, `strict`), a demo
  session, and the exact forwarded/audit output the gateway produces for it.
- **Docs** — `README.md` with Mermaid diagrams and a runnable demo,
  `docs/POLICY.md`, `docs/PROTOCOL.md`.
- **Tooling** — `Makefile`, GitHub Actions CI building/testing both languages,
  `LICENSE` (MIT), `.gitignore`.

[0.1.0]: https://github.com/example/mcp-bastion/releases/tag/v0.1.0
