/**
 * Audit event model shared with the Rust gateway.
 *
 * The gateway emits one JSON object per line (see `../../gateway/src/audit.rs`
 * and `../../docs/PROTOCOL.md`). This module defines the TypeScript view of that
 * schema and a small, defensive parser that validates each field. We use only
 * `JSON.parse` from the standard library — no third-party dependencies.
 */

/** The decision recorded for a message. */
export type Decision = "forward" | "deny" | "drop" | "error";

const DECISIONS: readonly Decision[] = ["forward", "deny", "drop", "error"];

/** A single audit event as produced by the gateway. */
export interface AuditEvent {
  readonly tsMs: number;
  readonly seq: number;
  readonly decision: Decision;
  readonly reason: string;
  readonly method: string | null;
  readonly tool: string | null;
  readonly id: string | null;
  readonly bytesIn: number;
  readonly bytesOut: number;
  readonly redacted: readonly string[];
  readonly balanced: boolean;
  readonly maxDepth: number;
}

/** The optional summary line the gateway emits at EOF when `--stats` is set. */
export interface SummaryLine {
  readonly summary: true;
  readonly total: number;
  readonly forward: number;
  readonly deny: number;
  readonly drop: number;
  readonly error: number;
}

/** Discriminated result of parsing one line. */
export type ParsedLine =
  | { readonly kind: "event"; readonly event: AuditEvent }
  | { readonly kind: "summary"; readonly summary: SummaryLine }
  | { readonly kind: "error"; readonly line: number; readonly message: string };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function asNumber(o: Record<string, unknown>, key: string): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new Error(`field '${key}' must be a finite number`);
  }
  return v;
}

function asBool(o: Record<string, unknown>, key: string): boolean {
  const v = o[key];
  if (typeof v !== "boolean") {
    throw new Error(`field '${key}' must be a boolean`);
  }
  return v;
}

function asString(o: Record<string, unknown>, key: string): string {
  const v = o[key];
  if (typeof v !== "string") {
    throw new Error(`field '${key}' must be a string`);
  }
  return v;
}

function asStringOrNull(o: Record<string, unknown>, key: string): string | null {
  const v = o[key];
  if (v === null) return null;
  if (typeof v !== "string") {
    throw new Error(`field '${key}' must be a string or null`);
  }
  return v;
}

function asStringArray(o: Record<string, unknown>, key: string): string[] {
  const v = o[key];
  if (!Array.isArray(v)) {
    throw new Error(`field '${key}' must be an array`);
  }
