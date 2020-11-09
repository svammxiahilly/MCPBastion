# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-31

### Added

- **Rust gateway (`gateway/`)** — a `std`-only CLI, `mcp-bastion`, that reads
  newline-delimited JSON-RPC from stdin, evaluates each message against a
  policy, and forwards permitted (and redacted) messages to stdout.
  - Honest single-pass JSON field extractor (`json_scan`) that skips string
    literals, tracks nesting, and returns raw value spans. It is explicitly
    **not** a full JSON parser and never claims to be.
  - Line-oriented policy format (`policy`) with `allow_tool` / `deny_tool`
