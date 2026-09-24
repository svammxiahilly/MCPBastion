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
  const out: string[] = [];
  for (const item of v) {
    if (typeof item !== "string") {
      throw new Error(`field '${key}' must contain only strings`);
    }
    out.push(item);
  }
  return out;
}

function asDecision(o: Record<string, unknown>, key: string): Decision {
  const v = asString(o, key);
  if (!(DECISIONS as readonly string[]).includes(v)) {
    throw new Error(`field '${key}' has invalid decision '${v}'`);
  }
  return v as Decision;
}

/** Parse a single trimmed line into an event, summary, or error record. */
export function parseLine(raw: string, lineNo: number): ParsedLine {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch (err) {
    return {
      kind: "error",
      line: lineNo,
      message: `invalid JSON: ${(err as Error).message}`,
    };
  }
  if (!isRecord(value)) {
    return { kind: "error", line: lineNo, message: "line is not a JSON object" };
  }
  try {
    if (value["summary"] === true) {
      return {
        kind: "summary",
        summary: {
          summary: true,
          total: asNumber(value, "total"),
          forward: asNumber(value, "forward"),
          deny: asNumber(value, "deny"),
          drop: asNumber(value, "drop"),
          error: asNumber(value, "error"),
        },
      };
    }
    const event: AuditEvent = {
      tsMs: asNumber(value, "ts_ms"),
      seq: asNumber(value, "seq"),
      decision: asDecision(value, "decision"),
      reason: asString(value, "reason"),
      method: asStringOrNull(value, "method"),
      tool: asStringOrNull(value, "tool"),
      id: asStringOrNull(value, "id"),
      bytesIn: asNumber(value, "bytes_in"),
      bytesOut: asNumber(value, "bytes_out"),
      redacted: asStringArray(value, "redacted"),
      balanced: asBool(value, "balanced"),
      maxDepth: asNumber(value, "max_depth"),
    };
    return { kind: "event", event };
  } catch (err) {
    return { kind: "error", line: lineNo, message: (err as Error).message };
  }
}

/** Result of parsing a whole audit log. */
export interface ParseReport {
  readonly events: AuditEvent[];
  readonly summary: SummaryLine | null;
  readonly errors: { readonly line: number; readonly message: string }[];
}

/** Parse an entire audit log body (newline-delimited). */
export function parseAuditLog(body: string): ParseReport {
  const events: AuditEvent[] = [];
  const errors: { line: number; message: string }[] = [];
  let summary: SummaryLine | null = null;

  const lines = body.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i]!.trim();
    if (trimmed.length === 0) continue;
    const parsed = parseLine(trimmed, i + 1);
    switch (parsed.kind) {
      case "event":
        events.push(parsed.event);
        break;
      case "summary":
        summary = parsed.summary;
        break;
      case "error":
        errors.push({ line: parsed.line, message: parsed.message });
        break;
    }
  }
  return { events, summary, errors };
}
