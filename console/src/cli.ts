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
import process from "node:process";

import { parseAuditLog } from "./audit.js";
import type { Decision } from "./audit.js";
import { aggregate, filterEvents } from "./report.js";
import { parsePolicy } from "./policy.js";
import { renderReport, renderReportJson, renderPolicy } from "./render.js";

const VALID_DECISIONS: readonly Decision[] = ["forward", "deny", "drop", "error"];

const USAGE = `mcp-bastion-console — audit & policy viewer

USAGE:
  mcp-bastion-console report <audit.jsonl> [--json] [--decision D] [--tool S]
  mcp-bastion-console tail   <audit.jsonl> [--decision D]
  mcp-bastion-console policy <policy-file>
  mcp-bastion-console --help

D is one of: forward | deny | drop | error
