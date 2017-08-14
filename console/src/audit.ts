/**
 * Audit event model shared with the Rust gateway.
 *
 * The gateway emits one JSON object per line (see `../../gateway/src/audit.rs`
 * and `../../docs/PROTOCOL.md`). This module defines the TypeScript view of that
 * schema and a small, defensive parser that validates each field. We use only
 * `JSON.parse` from the standard library — no third-party dependencies.
 */

