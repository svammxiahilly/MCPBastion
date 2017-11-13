#!/usr/bin/env node
/**
 * mcp-bastion-console — a dependency-free viewer for MCP Bastion.
 *
 * Subcommands:
 *   report  <audit.jsonl> [--json] [--decision D] [--tool SUBSTR]
 *       Aggregate an audit log and print a report (or JSON with --json).
 *       Filters narrow the per-event listing that follows the summary.
 *
 *   policy  <policy-file>
 *       Parse and lint a policy file, printing a summary.
 *
 *   tail    <audit.jsonl> [--decision D]
 *       Print one compact line per event (good for eyeballing a session).
 *
 * Reads files with `node:fs`; no third-party dependencies.
 */

import { readFileSync } from "node:fs";
