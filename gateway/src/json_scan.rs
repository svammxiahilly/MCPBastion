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
            while j < bytes.len() {
                match bytes[j] {
                    b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n' => break,
                    _ => j += 1,
                }
            }
            if j == i {
                None
            } else {
                Some(j)
            }
        }
    }
}

/// Scan a balanced container (`{...}` or `[...]`) starting at the opener, being
/// careful to skip nested strings so their contents cannot unbalance the count.
fn scan_container(bytes: &[u8], i: usize, open: u8, close: u8) -> Option<usize> {
    debug_assert_eq!(bytes.get(i).copied(), Some(open));
    let mut depth = 0usize;
    let mut j = i;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b'"' {
            j = scan_string(bytes, j)?;
            continue;
        }
        if b == open {
            depth += 1;
        } else if b == close {
            depth -= 1;
            if depth == 0 {
                return Some(j + 1);
            }
        }
        j += 1;
    }
    None
}

/// Locate the value associated with `key` inside the object that starts at
/// `obj_start` (which must point at `{`). Only keys at the *immediate* level of
/// that object are considered — nested objects are skipped over wholesale.
///
/// Returns the span of the value (kind + byte range) or `None` if the key is
/// absent, or the object is malformed.
pub fn find_key_in_object(bytes: &[u8], obj_start: usize, key: &str) -> Option<ValueSpan> {
    let start = skip_ws(bytes, obj_start);
    if bytes.get(start) != Some(&b'{') {
        return None;
    }
    let mut i = skip_ws(bytes, start + 1);
    if bytes.get(i) == Some(&b'}') {
        return None; // empty object
    }
    loop {
        // Expect a string key.
        if bytes.get(i) != Some(&b'"') {
            return None;
        }
        let key_end = scan_string(bytes, i)?;
        let this_key = decode_string(bytes, i, key_end)?;
        // Expect a colon.
        let colon = skip_ws(bytes, key_end);
        if bytes.get(colon) != Some(&b':') {
            return None;
        }
        let val_start = skip_ws(bytes, colon + 1);
        let val_end = scan_value_end(bytes, val_start)?;
        if this_key == key {
            let vs = skip_ws(bytes, val_start);
            let kind = match bytes.get(vs) {
                Some(b'"') => ValueKind::String,
                Some(b'{') => ValueKind::Object,
                Some(b'[') => ValueKind::Array,
                _ => ValueKind::Scalar,
            };
            return Some(ValueSpan {
                kind,
                start: vs,
                end: val_end,
            });
        }
        // Move to the next member.
        let after = skip_ws(bytes, val_end);
        match bytes.get(after) {
            Some(b',') => {
                i = skip_ws(bytes, after + 1);
            }
            Some(b'}') => return None,
            _ => return None,
        }
    }
}

/// Convenience: find a top-level key's value in a message and, if it is a
/// string, decode it.
pub fn top_level_string(bytes: &[u8], key: &str) -> Option<String> {
    let start = skip_ws(bytes, 0);
    let span = find_key_in_object(bytes, start, key)?;
    if span.kind != ValueKind::String {
        return None;
    }
    decode_string(bytes, span.start, span.end)
}

/// Convenience: find a top-level key and return its raw byte span regardless of
/// kind.
pub fn top_level_span(bytes: &[u8], key: &str) -> Option<ValueSpan> {
    let start = skip_ws(bytes, 0);
    find_key_in_object(bytes, start, key)
}

/// Perform a cheap structural balance/depth check over the whole input. This is
/// used purely for audit metadata; it never rejects a message on its own.
pub fn structure_report(bytes: &[u8]) -> StructureReport {
    let mut depth: isize = 0;
    let mut max_depth: usize = 0;
    let mut i = 0;
    let mut ok = true;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => match scan_string(bytes, i) {
                Some(next) => {
                    i = next;
                    continue;
                }
                None => {
                    ok = false;
                    break;
                }
            },
            b'{' | b'[' => {
                depth += 1;
                if depth as usize > max_depth {
                    max_depth = depth as usize;
                }
            }
            b'}' | b']' => {
                depth -= 1;
                if depth < 0 {
                    ok = false;
                    break;
                }
            }
            _ => {}
        }
        i += 1;
    }
    StructureReport {
        balanced: ok && depth == 0,
        max_depth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_top_level_string() {
        let s = br#"{"jsonrpc":"2.0","method":"tools/call","id":7}"#;
        assert_eq!(top_level_string(s, "method").as_deref(), Some("tools/call"));
        assert_eq!(top_level_string(s, "jsonrpc").as_deref(), Some("2.0"));
    }

    #[test]
    fn ignores_braces_inside_strings() {
        let s = br#"{"method":"a{b}c","note":"}}}"}"#;
        assert_eq!(top_level_string(s, "method").as_deref(), Some("a{b}c"));
        assert_eq!(top_level_string(s, "note").as_deref(), Some("}}}"));
    }

    #[test]
    fn handles_escaped_quotes() {
        let s = br#"{"method":"say \"hi\"","id":1}"#;
        assert_eq!(top_level_string(s, "method").as_deref(), Some("say \"hi\""));
    }

    #[test]
    fn nested_key_not_matched_at_top_level() {
        let s = br#"{"params":{"method":"inner"},"method":"outer"}"#;
        assert_eq!(top_level_string(s, "method").as_deref(), Some("outer"));
    }

    #[test]
    fn finds_nested_object_then_key() {
        let s = br#"{"params":{"name":"read_file"}}"#;
        let params = top_level_span(s, "params").unwrap();
        assert_eq!(params.kind, ValueKind::Object);
        let name = find_key_in_object(s, params.start, "name").unwrap();
        assert_eq!(name.kind, ValueKind::String);
        assert_eq!(
            decode_string(s, name.start, name.end).as_deref(),
            Some("read_file")
        );
    }

    #[test]
    fn unicode_escape_decodes() {
        let s = br#"{"m":"caf\u00e9"}"#;
        assert_eq!(top_level_string(s, "m").as_deref(), Some("café"));
    }

    #[test]
    fn surrogate_pair_decodes() {
        let s = br#"{"m":"\ud83d\ude00"}"#; // 😀
        assert_eq!(top_level_string(s, "m").as_deref(), Some("😀"));
    }

    #[test]
    fn utf8_passthrough() {
        let s = "{\"m\":\"héllo wörld\"}".as_bytes();
        assert_eq!(top_level_string(s, "m").as_deref(), Some("héllo wörld"));
    }

    #[test]
    fn structure_balanced_and_depth() {
        let s = br#"{"a":[1,2,{"b":3}]}"#;
        let r = structure_report(s);
        assert!(r.balanced);
        assert_eq!(r.max_depth, 3);
    }

    #[test]
    fn structure_unbalanced_detected() {
        let s = br#"{"a":[1,2}"#;
        let r = structure_report(s);
        assert!(!r.balanced);
    }

    #[test]
    fn missing_key_returns_none() {
        let s = br#"{"a":1}"#;
        assert!(top_level_string(s, "zzz").is_none());
    }

    #[test]
    fn scalar_span_is_not_string() {
        let s = br#"{"id":42}"#;
        let span = top_level_span(s, "id").unwrap();
        assert_eq!(span.kind, ValueKind::Scalar);
        assert_eq!(&s[span.start..span.end], b"42");
    }
}
