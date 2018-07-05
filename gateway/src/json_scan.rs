//! A small, honest JSON field extractor.
//!
//! This is **not** a full JSON parser and it does not build a document tree.
//! It is a single-pass scanner that understands just enough JSON grammar to:
//!
//!   * correctly skip over string literals (including escape sequences and
//!     `\uXXXX` units) so that structural characters inside strings are never
//!     mistaken for real structure;
//!   * track object/array nesting depth so that a requested key is only matched
//!     at the depth the caller expects;
//!   * return the *raw byte span* of a value that follows a matched key.
//!
//! What it deliberately does NOT do:
//!   * validate that the whole document is well-formed JSON,
//!   * decode numbers, booleans or unicode escapes into Rust values,
//!   * normalise duplicate keys or key ordering.
//!
//! Callers therefore get honest, conservative behaviour: if the scanner cannot
//! confidently locate a value it returns `None` and the gateway treats the
//! message accordingly (see `policy` and `main`). This keeps the security
//! surface small and auditable — we never pretend to understand more of the
//! message than we actually do.

/// The kind of a scanned JSON value, as far as the scanner can tell from the
/// first significant byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    String,
    Object,
    Array,
    /// number, `true`, `false` or `null` — anything not covered above.
    Scalar,
}

/// A located value: its kind and the byte range `[start, end)` in the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueSpan {
    pub kind: ValueKind,
    pub start: usize,
    pub end: usize,
