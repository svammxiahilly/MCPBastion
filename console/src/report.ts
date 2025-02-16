/**
 * Aggregation and reporting over parsed audit events.
 *
 * All computation here is pure so it can be unit-tested without I/O. Rendering
 * to text/JSON lives in `render.ts`.
 */

import type { AuditEvent, Decision, ParseReport } from "./audit.js";

export interface DecisionCounts {
  forward: number;
  deny: number;
  drop: number;
  error: number;
}

export interface ToolStat {
  readonly tool: string;
  readonly total: number;
  readonly forwarded: number;
  readonly denied: number;
  readonly dropped: number;
}

export interface Aggregate {
  readonly total: number;
  readonly counts: DecisionCounts;
  readonly bytesIn: number;
  readonly bytesOut: number;
  readonly redactionEvents: number;
  readonly redactedKeyCounts: ReadonlyMap<string, number>;
  readonly reasonCounts: ReadonlyMap<string, number>;
  readonly tools: readonly ToolStat[];
  readonly unbalanced: number;
  readonly maxDepthSeen: number;
  /** Consistency check against the gateway's own summary line, if present. */
  readonly summaryMatches: boolean | null;
}

function emptyCounts(): DecisionCounts {
  return { forward: 0, deny: 0, drop: 0, error: 0 };
}

function bump(counts: DecisionCounts, d: Decision): void {
  counts[d] += 1;
}

/** Compute the full aggregate from a parse report. */
export function aggregate(report: ParseReport): Aggregate {
  const counts = emptyCounts();
  let bytesIn = 0;
  let bytesOut = 0;
  let redactionEvents = 0;
  let unbalanced = 0;
  let maxDepthSeen = 0;

  const redactedKeyCounts = new Map<string, number>();
  const reasonCounts = new Map<string, number>();
  const toolAgg = new Map<string, ToolStat & { mutable: true }>();

  for (const ev of report.events) {
    bump(counts, ev.decision);
    bytesIn += ev.bytesIn;
    bytesOut += ev.bytesOut;
    if (ev.redacted.length > 0) redactionEvents += 1;
    if (!ev.balanced) unbalanced += 1;
    if (ev.maxDepth > maxDepthSeen) maxDepthSeen = ev.maxDepth;

    for (const key of ev.redacted) {
      redactedKeyCounts.set(key, (redactedKeyCounts.get(key) ?? 0) + 1);
    }
    reasonCounts.set(ev.reason, (reasonCounts.get(ev.reason) ?? 0) + 1);

    if (ev.tool !== null) {
      const prev =
        toolAgg.get(ev.tool) ??
        ({
          tool: ev.tool,
          total: 0,
          forwarded: 0,
          denied: 0,
          dropped: 0,
          mutable: true,
        } as ToolStat & { mutable: true });
      const next = {
        ...prev,
        total: prev.total + 1,
        forwarded: prev.forwarded + (ev.decision === "forward" ? 1 : 0),
        denied: prev.denied + (ev.decision === "deny" ? 1 : 0),
        dropped: prev.dropped + (ev.decision === "drop" ? 1 : 0),
      };
      toolAgg.set(ev.tool, next);
    }
  }

  const tools = [...toolAgg.values()]
    .map(({ mutable: _mutable, ...rest }) => rest)
    .sort((a, b) => b.total - a.total || a.tool.localeCompare(b.tool));

  let summaryMatches: boolean | null = null;
  if (report.summary) {
    const s = report.summary;
    summaryMatches =
      s.total === report.events.length &&
      s.forward === counts.forward &&
      s.deny === counts.deny &&
