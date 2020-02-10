//! MCP Bastion — a local zero-trust MCP JSON-RPC gateway library.
//!
//! The binary in `main.rs` is a thin I/O shell around these modules:
//!   * [`json_scan`] — the honest, single-pass JSON field extractor;
