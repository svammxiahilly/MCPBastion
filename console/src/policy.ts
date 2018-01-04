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
