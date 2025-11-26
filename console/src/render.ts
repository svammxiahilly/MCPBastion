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
  lines.push(`Max depth seen  : ${agg.maxDepthSeen}`);
  if (agg.summaryMatches !== null) {
    lines.push(`Gateway summary : ${agg.summaryMatches ? "MATCHES" : "MISMATCH!"}`);
  }
  lines.push("");

  lines.push("Decisions");
  lines.push("---------");
  const decMax = Math.max(
    agg.counts.forward,
    agg.counts.deny,
    agg.counts.drop,
    agg.counts.error,
    1,
  );
  for (const [name, count] of [
    ["forward", agg.counts.forward],
    ["deny", agg.counts.deny],
    ["drop", agg.counts.drop],
    ["error", agg.counts.error],
  ] as const) {
    lines.push(`  ${pad(name, 8)} ${padLeft(String(count), 5)} ${bar(count, decMax)}`);
  }
  lines.push("");

  if (agg.tools.length > 0) {
    lines.push("Per-tool activity");
    lines.push("-----------------");
    lines.push(
      `  ${pad("tool", 20)} ${padLeft("total", 6)} ${padLeft("fwd", 5)} ${padLeft("deny", 5)} ${padLeft("drop", 5)}`,
    );
    for (const t of agg.tools) {
      lines.push(
        `  ${pad(t.tool, 20)} ${padLeft(String(t.total), 6)} ${padLeft(String(t.forwarded), 5)} ${padLeft(String(t.denied), 5)} ${padLeft(String(t.dropped), 5)}`,
      );
    }
    lines.push("");
  }

  if (agg.redactedKeyCounts.size > 0) {
    lines.push("Redacted argument keys");
    lines.push("----------------------");
    for (const [key, count] of sortedEntries(agg.redactedKeyCounts)) {
      lines.push(`  ${pad(key, 24)} ${padLeft(String(count), 5)}`);
    }
    lines.push("");
  }

  lines.push("Top reasons");
  lines.push("-----------");
  for (const [reason, count] of sortedEntries(agg.reasonCounts).slice(0, 10)) {
    lines.push(`  ${padLeft(String(count), 5)}  ${reason}`);
  }

  return lines.join("\n");
}

/** Render a compact machine-readable JSON aggregate. */
export function renderReportJson(agg: Aggregate): string {
  const obj = {
    total: agg.total,
    counts: agg.counts,
    bytesIn: agg.bytesIn,
    bytesOut: agg.bytesOut,
    redactionEvents: agg.redactionEvents,
    unbalanced: agg.unbalanced,
    maxDepthSeen: agg.maxDepthSeen,
    summaryMatches: agg.summaryMatches,
    redactedKeyCounts: Object.fromEntries(agg.redactedKeyCounts),
    reasonCounts: Object.fromEntries(agg.reasonCounts),
    tools: agg.tools,
  };
  return JSON.stringify(obj, null, 2);
}

/** Render a policy summary with any lint issues. */
export function renderPolicy(policy: ParsedPolicy, issues: readonly PolicyIssue[]): string {
  const lines: string[] = [];
  lines.push("MCP Bastion — Policy Summary");
  lines.push("============================");
  lines.push("");
  lines.push(`Default decision : ${policy.defaultAllow ? "ALLOW" : "DENY"}`);
  lines.push(`Max bytes        : ${policy.maxBytes}`);
  lines.push(`Max depth        : ${policy.maxDepth}`);
  lines.push(
    `Rate limit       : ${policy.rateLimit === 0 ? "unlimited" : `${policy.rateLimit} / ${policy.rateWindowMs} ms`}`,
  );
  lines.push(`Redaction mask   : ${policy.redactionMask}`);
  lines.push("");
  lines.push(`Allowed tools (${policy.allowTools.length}):`);
  for (const t of policy.allowTools) lines.push(`  + ${t}`);
  lines.push(`Denied tools (${policy.denyTools.length}):`);
  for (const t of policy.denyTools) lines.push(`  - ${t}`);
  lines.push(`Redacted args (${policy.redactArgs.length}):`);
  for (const t of policy.redactArgs) lines.push(`  ~ ${t}`);
  lines.push("");

  if (issues.length === 0) {
    lines.push("Lint: no issues.");
  } else {
    lines.push(`Lint: ${issues.length} issue(s)`);
    for (const iss of issues) {
      const where = iss.line > 0 ? `line ${iss.line}` : "policy";
      lines.push(`  [${iss.severity}] ${where}: ${iss.message}`);
    }
  }
  return lines.join("\n");
}
