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
`;

interface Flags {
  positional: string[];
  json: boolean;
  decision: Decision | undefined;
  tool: string | undefined;
}

function parseFlags(argv: string[]): Flags {
  const flags: Flags = { positional: [], json: false, decision: undefined, tool: undefined };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--json") flags.json = true;
    else if (a === "--decision") {
      const v = argv[++i];
      if (v === undefined || !VALID_DECISIONS.includes(v as Decision)) {
        fail(`--decision must be one of ${VALID_DECISIONS.join(", ")}`);
      }
      flags.decision = v as Decision;
    } else if (a === "--tool") {
      const v = argv[++i];
      if (v === undefined) fail("--tool requires a value");
      flags.tool = v;
    } else if (a.startsWith("--")) {
      fail(`unknown flag: ${a}`);
    } else {
      flags.positional.push(a);
    }
  }
  return flags;
}

function fail(message: string): never {
  process.stderr.write(`error: ${message}\n`);
  process.exit(2);
}

function readFileOrFail(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    return fail(`cannot read '${path}': ${(err as Error).message}`);
  }
}

function buildFilter(flags: Flags): { decision?: Decision; tool?: string } {
  const f: { decision?: Decision; tool?: string } = {};
  if (flags.decision !== undefined) f.decision = flags.decision;
  if (flags.tool !== undefined) f.tool = flags.tool;
  return f;
}

function cmdReport(flags: Flags): number {
  const path = flags.positional[0];
  if (path === undefined) fail("report requires an <audit.jsonl> path");
  const body = readFileOrFail(path);
  const report = parseAuditLog(body);
  const agg = aggregate(report);

  if (flags.json) {
    process.stdout.write(renderReportJson(agg) + "\n");
  } else {
    process.stdout.write(renderReport(agg) + "\n");
    const filtered = filterEvents(report.events, buildFilter(flags));
    if (flags.decision !== undefined || flags.tool !== undefined) {
      process.stdout.write("\nFiltered events\n---------------\n");
      for (const ev of filtered) {
        process.stdout.write(
          `  #${ev.seq} ${ev.decision} ${ev.tool ?? ev.method ?? "?"} — ${ev.reason}\n`,
        );
      }
    }
    if (report.errors.length > 0) {
      process.stdout.write(`\nParse errors (${report.errors.length}):\n`);
      for (const e of report.errors) {
