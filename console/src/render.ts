/**
 * Rendering helpers: turn aggregates and policies into plain-text reports.
 *
 * Output is deliberately ASCII and colour-free so it is stable across
 * terminals, easy to snapshot in tests, and safe to paste into logs.
 */

import type { Aggregate } from "./report.js";
import { sortedEntries } from "./report.js";
import type { ParsedPolicy, PolicyIssue } from "./policy.js";

function bar(count: number, max: number, width = 24): string {
  if (max <= 0) return "";
  const filled = Math.round((count / max) * width);
  return "#".repeat(filled) + ".".repeat(Math.max(0, width - filled));
}

function pad(s: string, n: number): string {
  return s.length >= n ? s : s + " ".repeat(n - s.length);
}

function padLeft(s: string, n: number): string {
  return s.length >= n ? s : " ".repeat(n - s.length) + s;
}

/** Render the aggregate as a human-readable multi-line report. */
export function renderReport(agg: Aggregate): string {
  const lines: string[] = [];
  lines.push("MCP Bastion — Audit Report");
  lines.push("==========================");
  lines.push("");
  lines.push(`Total messages : ${agg.total}`);
  lines.push(`Bytes in/out   : ${agg.bytesIn} / ${agg.bytesOut}`);
  lines.push(`Redaction events: ${agg.redactionEvents}`);
  lines.push(`Unbalanced msgs : ${agg.unbalanced}`);
