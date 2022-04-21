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
}

/// Result of scanning a whole message for structural sanity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructureReport {
    /// `true` if brackets/braces/quotes are balanced across the input.
    pub balanced: bool,
    /// Maximum nesting depth encountered (objects + arrays).
    pub max_depth: usize,
}

/// Skip whitespace starting at `i`, returning the next non-whitespace index.
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b'\r' | b'\n' => i += 1,
            _ => break,
        }
    }
    i
}

/// Given `i` pointing at the opening quote of a JSON string, return the index
/// just past the closing quote, or `None` if the string is unterminated.
///
/// Handles `\"`, `\\`, and `\uXXXX` correctly so that an escaped quote does not
/// prematurely end the string.
fn scan_string(bytes: &[u8], i: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(i).copied(), Some(b'"'));
    let mut j = i + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => {
                // Skip the escape introducer and the escaped byte. For `\u`
                // we additionally skip the 4 hex digits (bounds-checked).
                if bytes.get(j + 1) == Some(&b'u') {
                    j += 6;
                } else {
                    j += 2;
                }
            }
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// Decode a JSON string literal (whose raw span is `bytes[start..end]`,
/// including the surrounding quotes) into a Rust `String`.
///
/// Supports the standard JSON escapes and `\uXXXX` (including surrogate pairs).
/// Returns `None` if the span is not a well-formed string literal.
pub fn decode_string(bytes: &[u8], start: usize, end: usize) -> Option<String> {
    if end <= start || bytes.get(start) != Some(&b'"') || bytes.get(end - 1) != Some(&b'"') {
        return None;
    }
    let inner = &bytes[start + 1..end - 1];
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        let b = inner[i];
        if b != b'\\' {
            out.push(b as char);
            i += 1;
            continue;
        }
        i += 1;
        let esc = *inner.get(i)?;
        match esc {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000C}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let cp = read_hex4(inner, i + 1)?;
                i += 4; // consumed the 4 hex digits (plus the `u` below)
                if (0xD800..=0xDBFF).contains(&cp) {
                    // High surrogate: expect a following `\uXXXX` low surrogate.
                    if inner.get(i + 1) == Some(&b'\\') && inner.get(i + 2) == Some(&b'u') {
                        let low = read_hex4(inner, i + 3)?;
                        if (0xDC00..=0xDFFF).contains(&low) {
                            let c = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                            out.push(char::from_u32(c)?);
                            i += 6;
                        } else {
                            return None;
                        }
                    } else {
                        return None;
                    }
                } else {
                    out.push(char::from_u32(cp)?);
                }
            }
            _ => return None,
        }
        i += 1;
    }
    // The `as char` cast above only handles ASCII; re-decode as UTF-8 for the
    // non-escaped bytes to preserve multibyte characters faithfully.
    // To keep this simple and correct we redo decoding using a UTF-8 aware path
    // when any non-ASCII byte was present.
    if inner.iter().any(|&b| b >= 0x80) {
        return decode_string_utf8(inner);
    }
    Some(out)
}

/// UTF-8 aware fallback decoder used when the raw bytes contain multibyte
/// sequences. Escapes are handled identically to `decode_string`.
fn decode_string_utf8(inner: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == b'\\' {
            i += 1;
            let esc = *inner.get(i)?;
            match esc {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let cp = read_hex4(inner, i + 1)?;
                    i += 4;
                    if (0xD800..=0xDBFF).contains(&cp) {
                        if inner.get(i + 1) == Some(&b'\\') && inner.get(i + 2) == Some(&b'u') {
                            let low = read_hex4(inner, i + 3)?;
                            if (0xDC00..=0xDFFF).contains(&low) {
                                let c = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                                out.push(char::from_u32(c)?);
                                i += 6;
                            } else {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    } else {
                        out.push(char::from_u32(cp)?);
                    }
                }
                _ => return None,
            }
            i += 1;
        } else {
            // Decode one UTF-8 scalar.
            let len = utf8_len(inner[i]);
            if len == 0 || i + len > inner.len() {
                return None;
            }
            let s = std::str::from_utf8(&inner[i..i + len]).ok()?;
            out.push_str(s);
            i += len;
        }
    }
    Some(out)
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 0,
    }
}

fn read_hex4(bytes: &[u8], i: usize) -> Option<u32> {
    let mut v = 0u32;
    for k in 0..4 {
        let c = *bytes.get(i + k)?;
        let d = match c {
            b'0'..=b'9' => (c - b'0') as u32,
            b'a'..=b'f' => (c - b'a' + 10) as u32,
            b'A'..=b'F' => (c - b'A' + 10) as u32,
            _ => return None,
        };
        v = (v << 4) | d;
    }
    Some(v)
}

/// Given `i` pointing at the first byte of a JSON value, return the byte index
/// just past the end of that value. Supports objects, arrays, strings and
/// scalars. Returns `None` on malformed / truncated input.
fn scan_value_end(bytes: &[u8], i: usize) -> Option<usize> {
    let i = skip_ws(bytes, i);
    match bytes.get(i)? {
        b'"' => scan_string(bytes, i),
        b'{' => scan_container(bytes, i, b'{', b'}'),
        b'[' => scan_container(bytes, i, b'[', b']'),
        _ => {
            // Scalar: read until a structural terminator at the current level.
            let mut j = i;
