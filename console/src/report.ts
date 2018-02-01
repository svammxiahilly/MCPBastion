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
