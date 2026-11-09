//! Static files: served before routing, from a folder, never outside it.
//!
//! A request under a mount (`/static/...`) is answered here, before the gate
//! and the router run. The path is canonical already (no dot segments, no
//! encoded slash), and every segment is checked again for what file systems
//! read specially: a leading dot (hidden files such as `.env` or `.git`), a
//! colon (Windows alternate data streams and drive letters), a trailing dot
//! or space (stripped by Windows, so `secret.txt.` would open `secret.txt`),
//! and Windows device names (`CON`, `NUL`, `COM1`, ...). The joined path is
//! then resolved and must still be inside the folder, so a symbolic link
//! cannot lead out of it.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use parse_net::{ByteRange, EntityTag, HttpDate, RangeOutcome};
use serve_net::{HttpReply, HttpRequest, Method, Outcome};

use crate::url;

/// Files up to this size are read whole into the reply; larger ones are sent
/// in parts.
pub const INLINE_LIMIT: u64 = 1 << 20;

/// The size of one part of a file sent in parts.
const PART: usize = 64 << 10;

/// A folder served under a mount path.
///
/// ```no_run
/// use web_net::{App, Assets};
///
/// let app = App::builder()
///     .assets(Assets::new("/static", "./public").cache_control("public, max-age=31536000, immutable"))
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Debug)]
pub struct Assets {
    pub(crate) mount: String,
    pub(crate) dir: PathBuf,
    pub(crate) root: PathBuf,
    pub(crate) cache_control: Box<str>,
    pub(crate) index: Option<Box<str>>,
    pub(crate) precompressed: bool,
    pub(crate) hidden: bool,
}

impl Assets {
    /// Serves `dir` under `mount` (`/static`). The folder must exist when the
    /// application is built.
    #[must_use]
    pub fn new(mount: &str, dir: impl Into<PathBuf>) -> Self {
        Self {
            mount: mount.trim_end_matches('/').to_owned(),
            dir: dir.into(),
            root: PathBuf::new(),
            cache_control: "no-cache".into(),
            index: None,
            precompressed: true,
            hidden: false,
        }
    }

    /// The `Cache-Control` value (default `no-cache`: the browser keeps the
    /// file and revalidates it, which a matching `ETag` answers with 304).
    /// For files whose names change with their content:
    /// `public, max-age=31536000, immutable`.
    #[must_use]
    pub fn cache_control(mut self, value: &str) -> Self {
        self.cache_control = value.into();
        self
    }

    /// The file served for a folder (`index.html`). Without one, a folder
    /// is a 404: there are never listings.
    #[must_use]
    pub fn index(mut self, name: &str) -> Self {
        self.index = Some(name.into());
        self
    }

    /// Whether `file.br` and `file.gz` next to a file are served to clients
    /// that accept them (default on).
    #[must_use]
    pub fn precompressed(mut self, on: bool) -> Self {
        self.precompressed = on;
        self
    }

    /// Serve names that start with a dot (default off: `.env`, `.git`,
    /// `.htaccess` are 404).
    #[must_use]
    pub fn hidden_files(mut self, on: bool) -> Self {
        self.hidden = on;
        self
    }

    /// The part of `path` under this mount: `/static/a.css` gives `/a.css`,
    /// `/static` gives `` (the mount itself).
    pub(crate) fn strip<'p>(&self, path: &'p str) -> Option<&'p str> {
        let rest = path.strip_prefix(self.mount.as_str())?;
        (rest.is_empty() || rest.starts_with('/')).then_some(rest)
    }
}

/// Windows device names, refused everywhere so a site behaves the same on
/// every system.
fn is_device_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit())
}

/// Whether a decoded segment may name a file.
fn safe_segment(seg: &str, hidden: bool) -> bool {
    !seg.is_empty()
        && (hidden || !seg.starts_with('.'))
        && !seg.contains([':', '\\', '/', '\0'])
        && !seg.ends_with(['.', ' '])
        && !is_device_name(seg)
}

/// A file found for a request.
pub(crate) struct Found {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    encoding: Option<&'static str>,
    mime: &'static str,
    vary: bool,
}

/// Resolves `rel` (the path under the mount, canonical) to a file inside the
/// root, or `None` for 404.
pub(crate) fn find(assets: &Assets, rel: &str, accept_encoding: Option<&[u8]>) -> Option<Found> {
    let mut path = assets.root.clone();
    for raw in rel.split('/').filter(|s| !s.is_empty()) {
        let seg = url::decode(raw);
        if !safe_segment(&seg, assets.hidden) {
            return None;
        }
        path.push(seg.as_ref());
    }
    let mut meta = inside(&assets.root, &path)?;
    if meta.1.is_dir() {
        let index = assets.index.as_deref()?;
        path = meta.0.join(index);
        meta = inside(&assets.root, &path)?;
    }
    let (file, md) = meta;
    if !md.is_file() {
        return None;
    }
    let mime = mime_for(&file);
    let mut found = Found {
        len: md.len(),
        modified: md.modified().ok(),
        path: file,
        encoding: None,
        mime,
        vary: false,
    };
    if assets.precompressed {
        found.vary = true;
        let offers = ["br", "gzip", "identity"];
        // No Accept-Encoding: the plain file (RFC 9110 allows any coding,
        // but clients that send none are rarely ready for one).
        let pick = accept_encoding.and_then(|v| parse_net::best_encoding(Some(v), &offers));
        let ext = match pick {
            Some(0) => Some(("br", "br")),
            Some(1) => Some(("gzip", "gz")),
            _ => None,
        };
        if let Some((coding, ext)) = ext {
            let mut alt = found.path.clone().into_os_string();
            alt.push(".");
            alt.push(ext);
            if let Some((p, m)) = inside(&assets.root, Path::new(&alt)) {
                if m.is_file() {
                    found.path = p;
                    found.len = m.len();
                    found.modified = m.modified().ok();
                    found.encoding = Some(coding);
                }
            }
        }
    }
    Some(found)
}

/// Resolves `path` and checks it is still under `root` (both canonical).
fn inside(root: &Path, path: &Path) -> Option<(PathBuf, std::fs::Metadata)> {
    let real = std::fs::canonicalize(path).ok()?;
    if !real.starts_with(root) {
        return None;
    }
    let md = std::fs::metadata(&real).ok()?;
    Some((real, md))
}

/// The entity tag: length and modification time, and the coding, so each
/// representation has its own.
fn etag(found: &Found) -> String {
    let nanos = found
        .modified
        .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos());
    let coding = match found.encoding {
        Some("br") => "-br",
        Some(_) => "-gz",
        None => "",
    };
    format!("\"{:x}-{:x}{coding}\"", found.len, nanos)
}

/// Answers a request for a file.
pub(crate) fn serve(
    assets: &Assets,
    found: &Found,
    req: &HttpRequest<'_>,
    reply: &mut HttpReply,
) -> Outcome {
    let tag = etag(found);
    let opaque = &tag.as_bytes()[1..tag.len() - 1];
    let current = EntityTag::strong(opaque).ok();
    let last_modified = found
        .modified
        .and_then(|m| HttpDate::from_system_time(m).ok());

    let head = |reply: &mut HttpReply, status: u16| {
        reply
            .status(status)
            .header("etag", tag.as_bytes())
            .header("cache-control", assets.cache_control.as_bytes())
            .header("x-content-type-options", "nosniff");
        if let Some(d) = last_modified {
            reply.header("last-modified", d.format());
        }
        if found.vary {
            reply.header("vary", "accept-encoding");
        }
    };

    // Conditional requests (RFC 9110 section 13.2.2).
    if let (Some(inm), Some(cur)) = (req.header("if-none-match"), current.as_ref()) {
        if parse_net::if_none_match(inm, cur).unwrap_or(false) {
            head(reply, 304);
            return Outcome::Done;
        }
    } else if let (Some(ims), Some(lm)) = (req.header("if-modified-since"), last_modified) {
        if let Ok(since) = parse_net::http_date(ims) {
            if lm <= since {
                head(reply, 304);
                return Outcome::Done;
            }
        }
    }

    // One range, when it applies (multiple ranges get the whole file).
    let mut range: Option<ByteRange> = None;
    if req.method() == Method::Get {
        if let Some(value) = req.header("range") {
            let if_range_ok = match req.header("if-range") {
                None => true,
                Some(v) => parse_net::range::parse_if_range(v)
                    .map(|ir| ir.matches(current.as_ref(), last_modified))
                    .unwrap_or(false),
            };
            if if_range_ok {
                let mut out = [ByteRange { start: 0, end: 0 }];
                match parse_net::byte_ranges(value, found.len, &mut out) {
                    Ok(RangeOutcome::Ranges(1)) => range = Some(out[0]),
                    Ok(RangeOutcome::Unsatisfiable) => {
                        head(reply, 416);
                        reply.header("content-range", format!("bytes */{}", found.len));
                        return Outcome::Done;
                    }
                    _ => {}
                }
            }
        }
    }

    let (status, start, len) = match range {
        Some(r) => (206, r.start, r.end - r.start + 1),
        None => (200, 0, found.len),
    };
    head(reply, status);
    reply
        .header("content-type", found.mime)
        .header("accept-ranges", "bytes");
    if let Some(c) = found.encoding {
        reply.header("content-encoding", c);
    }
    if let Some(r) = range {
        reply.header(
            "content-range",
            format!("bytes {}-{}/{}", r.start, r.end, found.len),
        );
    }
    if req.method() == Method::Head {
        // The length is the body's: read nothing for a small file's HEAD
        // beyond what the GET would send.
        if len <= INLINE_LIMIT {
            return match read_at(&found.path, start, len as usize) {
                Some(bytes) => {
                    reply.body(&bytes);
                    Outcome::Done
                }
                None => fail(reply),
            };
        }
        reply.stream();
        return Outcome::Done;
    }
    if len <= INLINE_LIMIT {
        return match read_at(&found.path, start, len as usize) {
            Some(bytes) => {
                reply.body(&bytes);
                Outcome::Done
            }
            None => fail(reply),
        };
    }
    // Sent in parts: serve-net calls again for each part, with the same
    // request; `sent` says where the next part starts. The status and fields
    // set above leave with the first part only.
    let sent = reply.stream().sent();
    send_part(found, start, len, sent, reply)
}

fn send_part(found: &Found, start: u64, len: u64, sent: u64, reply: &mut HttpReply) -> Outcome {
    if sent >= len {
        return Outcome::Done;
    }
    let want = (len - sent).min(PART as u64) as usize;
    let Some(bytes) = read_at(&found.path, start + sent, want) else {
        return Outcome::Close;
    };
    if bytes.len() != want {
        // Shorter than its length now: the file changed under the reply.
        return Outcome::Close;
    }
    reply.stream().send(&bytes);
    if sent + want as u64 >= len {
        Outcome::Done
    } else {
        Outcome::More
    }
}

fn read_at(path: &Path, start: u64, len: usize) -> Option<Vec<u8>> {
    let mut f = File::open(path).ok()?;
    if start > 0 {
        f.seek(SeekFrom::Start(start)).ok()?;
    }
    let mut buf = Vec::with_capacity(len);
    f.take(len as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn fail(reply: &mut HttpReply) -> Outcome {
    reply.text(500, "the file could not be read");
    Outcome::Done
}

/// The media type for a file name, by extension. Text types carry UTF-8.
#[must_use]
pub fn mime_for(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "webmanifest" => "application/manifest+json",
        "rss" => "application/rss+xml",
        "atom" => "application/atom+xml",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsafe_segments() {
        for bad in [
            ".env",
            ".git",
            "a:b",
            "file.txt::$DATA",
            "c:",
            "x.",
            "x ",
            "CON",
            "con.txt",
            "Nul",
            "COM1",
            "lpt9.log",
            "a\\b",
            "",
        ] {
            assert!(!safe_segment(bad, false), "{bad:?}");
        }
        for ok in [
            "a.css",
            "index.html",
            "COM",
            "COM10",
            "console.js",
            "a b.txt",
        ] {
            assert!(safe_segment(ok, false), "{ok:?}");
        }
        assert!(safe_segment(".well-known", true));
    }

    #[test]
    fn test_mime() {
        assert_eq!(mime_for(Path::new("a/B.CSS")), "text/css; charset=utf-8");
        assert_eq!(mime_for(Path::new("x")), "application/octet-stream");
        assert_eq!(mime_for(Path::new("x.woff2")), "font/woff2");
    }

    #[test]
    fn test_strip() {
        let a = Assets::new("/static/", ".");
        assert_eq!(a.strip("/static/a.css"), Some("/a.css"));
        assert_eq!(a.strip("/static"), Some(""));
        assert_eq!(a.strip("/statics/a"), None);
    }
}
