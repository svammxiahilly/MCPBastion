//! MCP Bastion — a local zero-trust MCP JSON-RPC gateway library.
//!
//! The binary in `main.rs` is a thin I/O shell around these modules:
//!   * [`json_scan`] — the honest, single-pass JSON field extractor;
//!   * [`policy`]    — the line-oriented policy format, matcher and rate limiter;
//!   * [`redact`]    — argument-value redaction that preserves message bytes;
//!   * [`audit`]     — structured, one-line-per-event JSON audit records;
//!   * [`engine`]    — the pure per-message decision pipeline.
//!
//! Everything here depends solely on the Rust standard library.

pub mod audit;
pub mod engine;
pub mod json_scan;
pub mod policy;
pub mod redact;
