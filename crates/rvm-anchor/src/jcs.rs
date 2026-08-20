//! Minimal JSON model with RFC 8785 (JCS) canonical serialization.
//!
//! The witness/receipt contract constrains the JSON that can appear in a
//! record (contract §2): fractional values are decimal *strings*, never
//! binary floats, and `NaN` / `±Infinity` / negative zero are forbidden
//! anywhere. Within that domain, RFC 8785 number serialization reduces to
//! plain integer formatting, so this module accepts **integers only** and
//! rejects any number with a fraction, an exponent, or a negative-zero
//! form. That is deliberately fail-closed: a record carrying a float is
//! non-conforming before canonicalization even matters, and refusing to
//! parse it is cheaper and safer than reimplementing ECMAScript number
//! formatting in the hypervisor tree.
//!
//! Everything else follows RFC 8785: object keys sorted by UTF-16 code
//! units, minimal string escaping (the `JSON.stringify` table), no
//! insignificant whitespace.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// A parsed JSON value, restricted to the contract's number domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` / `false`.
    Bool(bool),
    /// An integer. Fractions and exponents are rejected at parse time.
    Int(i64),
    /// A string (unescaped).
    Str(String),
    /// An array.
    Arr(Vec<Json>),
    /// An object as parsed pairs. Duplicate keys are rejected at parse
    /// time; key order is irrelevant and re-sorted at serialization.
    Obj(Vec<(String, Json)>),
}

/// Why a document failed to parse into the contract's JSON domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// Malformed JSON syntax.
    Syntax,
    /// A number with a fraction, exponent, out-of-range magnitude, or
    /// negative-zero form (forbidden by contract §2).
    NonConformingNumber,
    /// The same key appears twice in one object.
    DuplicateKey,
    /// Bytes after the end of the top-level value.
    TrailingData,
    /// Invalid `\u` escape or lone surrogate.
    BadEscape,
}

impl core::fmt::Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Syntax => write!(f, "malformed JSON"),
            Self::NonConformingNumber => {
                write!(f, "non-conforming number (contract forbids floats and -0)")
            }
            Self::DuplicateKey => write!(f, "duplicate object key"),
            Self::TrailingData => write!(f, "trailing data after JSON value"),
            Self::BadEscape => write!(f, "invalid string escape"),
        }
    }
}

impl Json {
    /// Parse a JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`JsonError`] for malformed input, duplicate keys, or any
    /// number outside the contract's integer domain.
    pub fn parse(text: &str) -> Result<Self, JsonError> {
        let bytes = text.as_bytes();
        let mut pos = 0;
        let value = parse_value(bytes, &mut pos)?;
        skip_ws(bytes, &mut pos);
        if pos != bytes.len() {
            return Err(JsonError::TrailingData);
        }
        Ok(value)
    }

    /// Look up a key in an object. `None` for absent keys or non-objects.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Obj(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The value as a string slice, if it is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The value as an integer, if it is one.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The value as a bool, if it is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The value's array items, if it is an array.
    #[must_use]
    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Self::Arr(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    /// The value's object pairs, if it is an object.
    #[must_use]
    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Obj(pairs) => Some(pairs.as_slice()),
            _ => None,
        }
    }

    /// RFC 8785 canonical serialization (JCS).
    #[must_use]
    pub fn canonicalize(&self) -> String {
        let mut out = String::new();
        write_canonical(self, &mut out);
        out
    }
}

/// Compare two strings by UTF-16 code units, the JCS key order.
fn utf16_cmp(a: &str, b: &str) -> core::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_canonical(value: &Json, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Json::Str(s) => write_escaped(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Json::Obj(pairs) => {
            let mut sorted: Vec<&(String, Json)> = pairs.iter().collect();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, v)) in sorted.iter().map(|p| (&p.0, &p.1)).enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_escaped(k, out);
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
    }
}

/// Escape a string per the `JSON.stringify` table RFC 8785 mandates.
fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn skip_ws(bytes: &[u8], pos: &mut usize) {
    while *pos < bytes.len() && matches!(bytes[*pos], b' ' | b'\t' | b'\n' | b'\r') {
        *pos += 1;
    }
}

fn parse_value(bytes: &[u8], pos: &mut usize) -> Result<Json, JsonError> {
    skip_ws(bytes, pos);
    match bytes.get(*pos) {
        Some(b'{') => parse_object(bytes, pos),
        Some(b'[') => parse_array(bytes, pos),
        Some(b'"') => Ok(Json::Str(parse_string(bytes, pos)?)),
        Some(b't') => parse_literal(bytes, pos, b"true", Json::Bool(true)),
        Some(b'f') => parse_literal(bytes, pos, b"false", Json::Bool(false)),
        Some(b'n') => parse_literal(bytes, pos, b"null", Json::Null),
        Some(b'-' | b'0'..=b'9') => parse_number(bytes, pos),
        _ => Err(JsonError::Syntax),
    }
}

fn parse_literal(
    bytes: &[u8],
    pos: &mut usize,
    literal: &[u8],
    value: Json,
) -> Result<Json, JsonError> {
    if bytes.len() >= *pos + literal.len() && &bytes[*pos..*pos + literal.len()] == literal {
        *pos += literal.len();
        Ok(value)
    } else {
        Err(JsonError::Syntax)
    }
}

fn parse_number(bytes: &[u8], pos: &mut usize) -> Result<Json, JsonError> {
    let start = *pos;
    if bytes.get(*pos) == Some(&b'-') {
        *pos += 1;
    }
    let digits_start = *pos;
    while matches!(bytes.get(*pos), Some(b'0'..=b'9')) {
        *pos += 1;
    }
    if *pos == digits_start {
        return Err(JsonError::Syntax);
    }
    // Leading zeros are invalid JSON except for a bare 0.
    if bytes[digits_start] == b'0' && *pos - digits_start > 1 {
        return Err(JsonError::Syntax);
    }
    // Fractions and exponents are floats: forbidden by the contract.
    if matches!(bytes.get(*pos), Some(b'.' | b'e' | b'E')) {
        return Err(JsonError::NonConformingNumber);
    }
    let text = core::str::from_utf8(&bytes[start..*pos]).map_err(|_| JsonError::Syntax)?;
    // "-0" is negative zero: forbidden by contract §2 rule 1.
    if text == "-0" {
        return Err(JsonError::NonConformingNumber);
    }
    let value: i64 = text.parse().map_err(|_| JsonError::NonConformingNumber)?;
    Ok(Json::Int(value))
}

fn parse_string(bytes: &[u8], pos: &mut usize) -> Result<String, JsonError> {
    debug_assert_eq!(bytes.get(*pos), Some(&b'"'));
    *pos += 1;
    let mut out = String::new();
    loop {
        match bytes.get(*pos) {
            None => return Err(JsonError::Syntax),
            Some(b'"') => {
                *pos += 1;
                return Ok(out);
            }
            Some(b'\\') => {
                *pos += 1;
                match bytes.get(*pos) {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{08}'),
                    Some(b'f') => out.push('\u{0C}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        *pos += 1;
                        let unit = parse_hex4(bytes, pos)?;
                        let c = if (0xD800..=0xDBFF).contains(&unit) {
                            // High surrogate: require a low surrogate pair.
                            if bytes.get(*pos) != Some(&b'\\') || bytes.get(*pos + 1) != Some(&b'u')
                            {
                                return Err(JsonError::BadEscape);
                            }
                            *pos += 2;
                            let low = parse_hex4(bytes, pos)?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return Err(JsonError::BadEscape);
                            }
                            let code =
                                0x10000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                            char::from_u32(code).ok_or(JsonError::BadEscape)?
                        } else if (0xDC00..=0xDFFF).contains(&unit) {
                            return Err(JsonError::BadEscape);
                        } else {
                            char::from_u32(u32::from(unit)).ok_or(JsonError::BadEscape)?
                        };
                        out.push(c);
                        continue;
                    }
                    _ => return Err(JsonError::BadEscape),
                }
                *pos += 1;
            }
            Some(&b) if b < 0x20 => return Err(JsonError::Syntax),
            Some(_) => {
                // Consume one UTF-8 encoded character.
                let rest = core::str::from_utf8(&bytes[*pos..]).map_err(|_| JsonError::Syntax)?;
                let c = rest.chars().next().ok_or(JsonError::Syntax)?;
                out.push(c);
                *pos += c.len_utf8();
            }
        }
    }
}

fn parse_hex4(bytes: &[u8], pos: &mut usize) -> Result<u16, JsonError> {
    let mut value: u16 = 0;
    for _ in 0..4 {
        let digit = match bytes.get(*pos) {
            Some(b @ b'0'..=b'9') => b - b'0',
            Some(b @ b'a'..=b'f') => b - b'a' + 10,
            Some(b @ b'A'..=b'F') => b - b'A' + 10,
            _ => return Err(JsonError::BadEscape),
        };
        value = (value << 4) | u16::from(digit);
        *pos += 1;
    }
    Ok(value)
}

fn parse_array(bytes: &[u8], pos: &mut usize) -> Result<Json, JsonError> {
    debug_assert_eq!(bytes.get(*pos), Some(&b'['));
    *pos += 1;
    let mut items = Vec::new();
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b']') {
        *pos += 1;
        return Ok(Json::Arr(items));
    }
    loop {
        items.push(parse_value(bytes, pos)?);
        skip_ws(bytes, pos);
        match bytes.get(*pos) {
            Some(b',') => *pos += 1,
            Some(b']') => {
                *pos += 1;
                return Ok(Json::Arr(items));
            }
            _ => return Err(JsonError::Syntax),
        }
    }
}

fn parse_object(bytes: &[u8], pos: &mut usize) -> Result<Json, JsonError> {
    debug_assert_eq!(bytes.get(*pos), Some(&b'{'));
    *pos += 1;
    let mut pairs: Vec<(String, Json)> = Vec::new();
    skip_ws(bytes, pos);
    if bytes.get(*pos) == Some(&b'}') {
        *pos += 1;
        return Ok(Json::Obj(pairs));
    }
    loop {
        skip_ws(bytes, pos);
        if bytes.get(*pos) != Some(&b'"') {
            return Err(JsonError::Syntax);
        }
        let key = parse_string(bytes, pos)?;
        if pairs.iter().any(|(k, _)| *k == key) {
            return Err(JsonError::DuplicateKey);
        }
        skip_ws(bytes, pos);
        if bytes.get(*pos) != Some(&b':') {
            return Err(JsonError::Syntax);
        }
        *pos += 1;
        let value = parse_value(bytes, pos)?;
        pairs.push((key, value));
        skip_ws(bytes, pos);
        match bytes.get(*pos) {
            Some(b',') => *pos += 1,
            Some(b'}') => {
                *pos += 1;
                return Ok(Json::Obj(pairs));
            }
            _ => return Err(JsonError::Syntax),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalization_sorts_keys_and_strips_whitespace() {
        let parsed = Json::parse("{ \"b\" : 1 , \"a\" : [ true , null ] }").unwrap();
        assert_eq!(parsed.canonicalize(), "{\"a\":[true,null],\"b\":1}");
    }

    #[test]
    fn key_reordering_yields_identical_canonical_bytes() {
        let a = Json::parse(r#"{"x":1,"y":{"p":"q","r":"s"}}"#).unwrap();
        let b = Json::parse(r#"{"y":{"r":"s","p":"q"},"x":1}"#).unwrap();
        assert_eq!(a.canonicalize(), b.canonicalize());
    }

    #[test]
    fn floats_are_rejected() {
        assert_eq!(Json::parse("1.5"), Err(JsonError::NonConformingNumber));
        assert_eq!(Json::parse("1e3"), Err(JsonError::NonConformingNumber));
        assert_eq!(Json::parse("-0"), Err(JsonError::NonConformingNumber));
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert_eq!(
            Json::parse(r#"{"a":1,"a":2}"#),
            Err(JsonError::DuplicateKey)
        );
    }

    #[test]
    fn control_characters_escape_per_stringify_table() {
        let value = Json::Str(String::from("a\"b\\c\n\u{01}"));
        assert_eq!(value.canonicalize(), "\"a\\\"b\\\\c\\n\\u0001\"");
    }
}
