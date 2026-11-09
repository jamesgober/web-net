//! Request paths: percent-decoding once, dot segments, the one canonical
//! spelling, and the trailing-slash policy.
//!
//! Every path a route sees is canonical: decoded once and re-encoded in one
//! way, with no dot segments and no empty segments. A request whose path is
//! spelled any other way is answered with a redirect to the canonical
//! spelling, so two spellings of one path can never reach different routes,
//! and a route literal compares with a segment byte for byte.

use std::borrow::Cow;
use std::fmt;

/// What a request path was refused for (answered with 400).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    /// The path does not start with `/` (and is not the `*` of `OPTIONS *`).
    NotAbsolute,
    /// A `%` not followed by two hex digits.
    BadEscape,
    /// An encoded slash (`%2F`): it would let one segment pose as two.
    EncodedSlash,
    /// An encoded backslash (`%5C`): a path separator on some systems.
    Backslash,
    /// A decoded control byte (`%00` to `%1F`, `%7F`).
    Control,
    /// The decoded bytes are not UTF-8.
    NotUtf8,
    /// More segments than the limit.
    TooManySegments,
}

impl UrlError {
    /// A stable code for logs and events.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotAbsolute => "url.not_absolute",
            Self::BadEscape => "url.bad_escape",
            Self::EncodedSlash => "url.encoded_slash",
            Self::Backslash => "url.backslash",
            Self::Control => "url.control",
            Self::NotUtf8 => "url.not_utf8",
            Self::TooManySegments => "url.too_many_segments",
        }
    }
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            Self::NotAbsolute => "the path does not start with a slash",
            Self::BadEscape => "a percent sign is not followed by two hex digits",
            Self::EncodedSlash => "the path holds an encoded slash",
            Self::Backslash => "the path holds an encoded backslash",
            Self::Control => "the path decodes to a control character",
            Self::NotUtf8 => "the path does not decode to UTF-8",
            Self::TooManySegments => "the path has too many segments",
        };
        f.write_str(what)
    }
}

impl std::error::Error for UrlError {}

/// What a site does with a trailing slash. One policy per site, so a page has
/// one address.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrailingSlash {
    /// `/a/` is redirected to `/a` (the default). The site root keeps its
    /// slash.
    #[default]
    Strip,
    /// `/a` is redirected to `/a/`, except when the last segment holds a dot
    /// (`/style.css` stays as it is).
    Add,
    /// Both spellings reach the same route and neither is redirected.
    Ignore,
}

/// The most segments a path may have.
pub(crate) const MAX_SEGMENTS: usize = 256;

#[inline]
const fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Bytes written as they are in a canonical path segment: RFC 3986 `pchar`
/// without `%` (unreserved, sub-delims, `:` and `@`). Every other byte is
/// percent-encoded with upper-case hex.
#[inline]
pub(crate) const fn is_plain(b: u8) -> bool {
    matches!(b,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'-' | b'.' | b'_' | b'~'
        | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        | b':' | b'@')
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Appends `bytes` to `out` in canonical segment encoding.
pub(crate) fn encode_segment(bytes: &[u8], out: &mut String) {
    for &b in bytes {
        if is_plain(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
}

/// Decodes a canonical segment (or several, joined by `/`). Canonical input
/// always decodes to UTF-8; anything that does not is returned unchanged.
pub(crate) fn decode(raw: &str) -> Cow<'_, str> {
    if !raw.contains('%') {
        return Cow::Borrowed(raw);
    }
    let b = raw.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => Cow::Owned(s),
        Err(_) => Cow::Borrowed(raw),
    }
}

/// Whether `raw` is already canonical as far as decoding and dot segments
/// go: no `%`, no empty segment, no `.` or `..` segment, and (with
/// `lowercase`) no upper-case letter. The common case; no allocation.
fn plain_path(raw: &[u8], lowercase: bool) -> bool {
    let mut seg_start = 1;
    let mut segments = 0usize;
    for i in 1..=raw.len() {
        let end = i == raw.len();
        if end || raw[i] == b'/' {
            let seg = &raw[seg_start..i];
            // An empty segment is fine only as the trailing slash.
            if (seg.is_empty() && !end) || seg == b"." || seg == b".." {
                return false;
            }
            segments += 1;
            seg_start = i + 1;
            continue;
        }
        let b = raw[i];
        if !is_plain(b) || (lowercase && b.is_ascii_uppercase()) {
            return false;
        }
    }
    segments <= MAX_SEGMENTS
}

/// Normalizes a request path: percent-escapes decoded once and re-encoded in
/// the canonical way, dot segments removed (never above the root), empty
/// segments dropped, letters lowered when `lowercase`. A trailing slash is
/// kept; the site's [`TrailingSlash`] policy is applied later, after the
/// base path.
///
/// Returns the input itself when it is canonical already.
///
/// # Errors
///
/// [`UrlError`] for a path that is refused rather than repaired.
pub(crate) fn normalize(raw: &str, lowercase: bool) -> Result<Cow<'_, str>, UrlError> {
    let b = raw.as_bytes();
    if b.first() != Some(&b'/') {
        return Err(UrlError::NotAbsolute);
    }
    if plain_path(b, lowercase) {
        return Ok(Cow::Borrowed(raw));
    }
    // Slow path: decode every segment into one buffer, keeping where each
    // kept segment starts and ends.
    let mut buf: Vec<u8> = Vec::with_capacity(b.len());
    let mut segs: Vec<(usize, usize)> = Vec::new();
    let mut trailing = false;
    let last_index = b[1..].iter().filter(|&&c| c == b'/').count();
    if last_index >= MAX_SEGMENTS * 2 {
        return Err(UrlError::TooManySegments);
    }
    for (n, seg) in b[1..].split(|&c| c == b'/').enumerate() {
        let start = buf.len();
        let mut i = 0;
        while i < seg.len() {
            let c = seg[i];
            let byte = if c == b'%' {
                let (Some(h), Some(l)) = (
                    seg.get(i + 1).copied().and_then(hex),
                    seg.get(i + 2).copied().and_then(hex),
                ) else {
                    return Err(UrlError::BadEscape);
                };
                i += 3;
                let d = (h << 4) | l;
                match d {
                    b'/' => return Err(UrlError::EncodedSlash),
                    b'\\' => return Err(UrlError::Backslash),
                    0..=0x1f | 0x7f => return Err(UrlError::Control),
                    _ => d,
                }
            } else {
                i += 1;
                if c == b'\\' {
                    return Err(UrlError::Backslash);
                }
                if c < 0x20 || c == 0x7f {
                    return Err(UrlError::Control);
                }
                c
            };
            buf.push(if lowercase {
                byte.to_ascii_lowercase()
            } else {
                byte
            });
        }
        let decoded = &buf[start..];
        let last = n == last_index;
        match decoded {
            b"" => {
                buf.truncate(start);
                trailing = last;
            }
            b"." => {
                buf.truncate(start);
                trailing = last;
            }
            b".." => {
                buf.truncate(start);
                if let Some((s, _)) = segs.pop() {
                    buf.truncate(s);
                }
                trailing = last;
            }
            _ => {
                if core::str::from_utf8(decoded).is_err() {
                    return Err(UrlError::NotUtf8);
                }
                segs.push((start, buf.len()));
                trailing = false;
            }
        }
    }
    if segs.len() > MAX_SEGMENTS {
        return Err(UrlError::TooManySegments);
    }
    let mut out = String::with_capacity(b.len());
    for &(s, e) in &segs {
        out.push('/');
        encode_segment(&buf[s..e], &mut out);
    }
    if out.is_empty() || trailing {
        out.push('/');
    }
    if out == raw {
        Ok(Cow::Borrowed(raw))
    } else {
        Ok(Cow::Owned(out))
    }
}

/// Canonical encoding of a route literal segment (written decoded by the
/// programmer).
pub(crate) fn canonical_literal(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    encode_segment(segment.as_bytes(), &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(p: &str) -> Result<String, UrlError> {
        normalize(p, false).map(Cow::into_owned)
    }

    #[test]
    fn test_plain_paths_are_borrowed() {
        for p in [
            "/",
            "/a",
            "/a/b",
            "/a/b/",
            "/a-b_c.d~e",
            "/a:b@c!$&'()*+,;=",
        ] {
            assert!(matches!(normalize(p, false), Ok(Cow::Borrowed(_))), "{p}");
        }
    }

    #[test]
    fn test_dot_segments_removed() {
        assert_eq!(n("/a/./b/../c").unwrap(), "/a/c");
        assert_eq!(n("/a/b/..").unwrap(), "/a/");
        assert_eq!(n("/a/b/.").unwrap(), "/a/b/");
        assert_eq!(n("/../../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(n("/..").unwrap(), "/");
        assert_eq!(n("/%2e%2E/x").unwrap(), "/x");
        assert_eq!(n("/a/%2e/b").unwrap(), "/a/b");
    }

    #[test]
    fn test_empty_segments_collapse() {
        assert_eq!(n("//a///b").unwrap(), "/a/b");
        assert_eq!(n("/a//").unwrap(), "/a/");
        assert_eq!(n("//").unwrap(), "/");
    }

    #[test]
    fn test_escapes_canonical() {
        assert_eq!(n("/%41%62c").unwrap(), "/Abc");
        assert_eq!(n("/caf%c3%a9").unwrap(), "/caf%C3%A9");
        assert_eq!(n("/caf%C3%A9").unwrap(), "/caf%C3%A9");
        assert_eq!(n("/a%20b").unwrap(), "/a%20b");
        assert_eq!(n("/a%3Ab").unwrap(), "/a:b");
        assert_eq!(n("/a%25b").unwrap(), "/a%25b");
        assert!(matches!(normalize("/a%20b", false), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn test_refusals() {
        assert_eq!(n("a"), Err(UrlError::NotAbsolute));
        assert_eq!(n(""), Err(UrlError::NotAbsolute));
        assert_eq!(n("/a%2Fb"), Err(UrlError::EncodedSlash));
        assert_eq!(n("/a%2fb"), Err(UrlError::EncodedSlash));
        assert_eq!(n("/a%5Cb"), Err(UrlError::Backslash));
        assert_eq!(n("/a%00"), Err(UrlError::Control));
        assert_eq!(n("/a%0d%0a"), Err(UrlError::Control));
        assert_eq!(n("/a%7f"), Err(UrlError::Control));
        assert_eq!(n("/a%zz"), Err(UrlError::BadEscape));
        assert_eq!(n("/a%4"), Err(UrlError::BadEscape));
        assert_eq!(n("/a%ff"), Err(UrlError::NotUtf8));
        assert_eq!(n("/%c3"), Err(UrlError::NotUtf8));
    }

    #[test]
    fn test_lowercase() {
        assert_eq!(normalize("/About/Us", true).unwrap(), "/about/us");
        assert_eq!(normalize("/%41", true).unwrap(), "/a");
        assert!(matches!(normalize("/about", true), Ok(Cow::Borrowed(_))));
    }

    #[test]
    fn test_normalize_is_idempotent() {
        for p in [
            "/a/./b/../c",
            "//x//y/",
            "/%41%2e%2e/b",
            "/caf%c3%a9/",
            "/a%20b/..",
        ] {
            let once = n(p).unwrap();
            assert_eq!(n(&once).unwrap(), once, "{p}");
        }
    }

    #[test]
    fn test_decode() {
        assert_eq!(decode("caf%C3%A9"), "café");
        assert_eq!(decode("a%20b"), "a b");
        assert_eq!(decode("plain"), "plain");
    }

    #[test]
    fn test_too_many_segments() {
        let long = "/a".repeat(MAX_SEGMENTS + 1);
        assert_eq!(n(&long), Err(UrlError::TooManySegments));
        let ok = "/a".repeat(MAX_SEGMENTS);
        assert!(n(&ok).is_ok());
    }
}
