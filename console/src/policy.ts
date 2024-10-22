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

function parseIntStrict(v: string): number | null {
  if (!/^\d+$/.test(v)) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) ? n : null;
}

/** Parse policy text, collecting issues without throwing. */
export function parsePolicy(text: string): PolicyParseResult {
  const policy = defaults();
  const issues: PolicyIssue[] = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const line = stripComment(lines[i]!).trim();
    if (line.length === 0) continue;
    const [key, value] = splitDirective(line);

    if (!KNOWN_DIRECTIVES.has(key)) {
      issues.push({
        line: lineNo,
        severity: "error",
        message: `unknown directive '${key}'`,
      });
      continue;
    }

    switch (key) {
      case "default":
        if (value === "allow") policy.defaultAllow = true;
        else if (value === "deny") policy.defaultAllow = false;
        else
          issues.push({
            line: lineNo,
            severity: "error",
            message: `default must be 'allow' or 'deny', got '${value}'`,
          });
        break;
      case "allow_tool":
        policy.allowTools.push(value);
        break;
      case "deny_tool":
        policy.denyTools.push(value);
        break;
      case "redact_arg":
        policy.redactArgs.push(value);
        break;
      case "max_bytes": {
        const n = parseIntStrict(value);
        if (n === null)
          issues.push({ line: lineNo, severity: "error", message: `max_bytes must be an integer` });
        else policy.maxBytes = n;
        break;
      }
      case "max_depth": {
        const n = parseIntStrict(value);
        if (n === null)
          issues.push({ line: lineNo, severity: "error", message: `max_depth must be an integer` });
        else policy.maxDepth = n;
        break;
      }
      case "rate_limit": {
        const n = parseIntStrict(value);
        if (n === null)
          issues.push({ line: lineNo, severity: "error", message: `rate_limit must be an integer` });
        else policy.rateLimit = n;
        break;
      }
      case "rate_window_ms": {
        const n = parseIntStrict(value);
        if (n === null)
          issues.push({
            line: lineNo,
            severity: "error",
            message: `rate_window_ms must be an integer`,
          });
        else policy.rateWindowMs = n;
        break;
      }
      case "redaction_mask":
        policy.redactionMask = unquote(value);
        break;
    }
  }
