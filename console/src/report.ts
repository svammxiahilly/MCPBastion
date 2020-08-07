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
