/**
 * A read-only parser and summariser for the MCP Bastion policy format.
 *
 * This mirrors the grammar implemented authoritatively in the Rust gateway
 * (`../../gateway/src/policy.rs`) so the console can *display* and lint a policy
 * without shelling out. It intentionally does not evaluate messages — that is
 * the gateway's job — but it validates directive names and value shapes so an
 * operator can sanity-check a policy file before deploying it.
 */

export interface ParsedPolicy {
  defaultAllow: boolean;
  allowTools: string[];
  denyTools: string[];
  redactArgs: string[];
  maxBytes: number;
  maxDepth: number;
  rateLimit: number;
  rateWindowMs: number;
  redactionMask: string;
}

export interface PolicyIssue {
  readonly line: number;
  readonly severity: "error" | "warning";
  readonly message: string;
}

export interface PolicyParseResult {
  readonly policy: ParsedPolicy;
  readonly issues: readonly PolicyIssue[];
}

const KNOWN_DIRECTIVES = new Set([
  "default",
  "allow_tool",
  "deny_tool",
  "redact_arg",
  "max_bytes",
  "max_depth",
  "rate_limit",
  "rate_window_ms",
  "redaction_mask",
]);

function defaults(): ParsedPolicy {
  return {
    defaultAllow: false,
    allowTools: [],
    denyTools: [],
    redactArgs: [],
    maxBytes: 262144,
    maxDepth: 64,
    rateLimit: 0,
    rateWindowMs: 1000,
    redactionMask: "«redacted»",
  };
}

function stripComment(line: string): string {
  let inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') inQuote = !inQuote;
    else if (c === "#" && !inQuote) return line.slice(0, i);
  }
  return line;
}

function splitDirective(line: string): [string, string] {
  const eq = line.indexOf("=");
  if (eq >= 0) return [line.slice(0, eq).trim(), line.slice(eq + 1).trim()];
  const sp = line.search(/\s/);
  if (sp >= 0) return [line.slice(0, sp).trim(), line.slice(sp + 1).trim()];
  return [line.trim(), ""];
}

function unquote(v: string): string {
  const t = v.trim();
  if (t.length >= 2 && t.startsWith('"') && t.endsWith('"')) {
    return t.slice(1, -1);
  }
  return t;
}
