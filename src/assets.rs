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

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, Instant, SystemTime};

use parse_net::{ByteRange, EntityTag, HttpDate, RangeOutcome};
use serve_net::{HttpReply, HttpRequest, Method, Outcome};

use crate::url;

/// Files up to this size are read whole into the reply; larger ones are sent
/// in parts.
///
/// ```
/// // Files up to 1 MiB go out in one piece.
/// assert_eq!(web_net::INLINE_LIMIT, 1024 * 1024);
/// ```
pub const INLINE_LIMIT: u64 = 1 << 20;

/// The size of one part of a file sent in parts.
const PART: usize = 256 << 10;

/// How a reply in parts that cannot finish ends: serve-net answers a
/// `Deferred` without `reply.defer()` with a refusal, and a refusal once
/// the head has left closes the connection abortively, so the client sees
/// a cut-short body and never a clean end with the wrong bytes.
/// (`Outcome::Close` would end the chunked body cleanly.) serve-net is
/// asked for an explicit abort (PLAN O-7).
const ABORT: Outcome = Outcome::Deferred;

/// A request whose large file is going out in parts: its connection and
/// request number.
pub(crate) type StreamKey = (u64, u32);

/// The most replies in parts one application follows at once. Past it a
/// new one is refused with 503 and `Retry-After`; a reply in progress is
/// never forgotten (a forgotten one would restart mid-body).
pub(crate) const MAX_STREAMS: usize = 16 * 1024;

/// One large file going out in parts: the file resolved for the first
/// part, what it was then, and the bytes of it the reply carries.
pub(crate) struct Stream {
    path: Arc<Path>,
    len: u64,
    modified: Option<SystemTime>,
    start: u64,
    total: u64,
}

/// The replies in parts of one application, by connection and request.
/// Each record lives from the first part to the last, or until serve-net
/// says the request is done (`HttpService::done`), so a download the client
/// dropped frees its record too.
#[derive(Default)]
pub(crate) struct Streams(Mutex<HashMap<StreamKey, Stream>>);

impl Streams {
    fn lock(&self) -> MutexGuard<'_, HashMap<StreamKey, Stream>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The record of a reply whose first part went out, taken out for this
    /// part (put back with [`keep`](Self::keep) when more follow).
    pub(crate) fn take(&self, key: StreamKey) -> Option<Stream> {
        self.lock().remove(&key)
    }

    /// Starts following a reply; `false` when the table is full.
    fn start(&self, key: StreamKey, stream: Stream) -> bool {
        let mut m = self.lock();
        if m.len() >= MAX_STREAMS {
            return false;
        }
        m.insert(key, stream);
        true
    }

    fn keep(&self, key: StreamKey, stream: Stream) {
        self.lock().insert(key, stream);
    }

    /// The request is done: whatever it held goes.
    pub(crate) fn remove(&self, key: StreamKey) {
        let mut m = self.lock();
        if !m.is_empty() {
            m.remove(&key);
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

thread_local! {
    /// The buffer a part is read into, reused between parts and requests.
    static PART_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// The next part of a reply in parts. The file is opened again by its
/// resolved path and must still be what it was for the first part (same
/// length and modification time); if not, or if it cannot be read, the
/// connection ends, never the reply.
pub(crate) fn next_part(
    streams: &Streams,
    key: StreamKey,
    stream: Stream,
    reply: &mut HttpReply,
) -> Outcome {
    let sent = reply.stream().sent();
    let outcome = send_part(&stream, sent, reply);
    if outcome == Outcome::More {
        streams.keep(key, stream);
    }
    outcome
}

/// Whether the request's `If-Range` (if any) holds for the file.
fn if_range_holds(found: &Found<'_>, tag: &str, req: &HttpRequest<'_>) -> bool {
    let Some(v) = req.header("if-range") else {
        return true;
    };
    let current = EntityTag::strong(&tag.as_bytes()[1..tag.len() - 1]).ok();
    let modified = found
        .modified
        .and_then(|m| HttpDate::from_system_time(m).ok());
    parse_net::range::parse_if_range(v)
        .map(|ir| ir.matches(current.as_ref(), modified))
        .unwrap_or(false)
}

/// Resolved files of one mount, by request path and then encoding pick
/// (`br`, `gzip`, none), kept for [`REVALIDATE`]: a hit costs one metadata
/// call, not a resolution. Small files keep their bytes too, used while
/// the file's length and modification time are unchanged.
#[derive(Default)]
pub(crate) struct Cache {
    map: RwLock<HashMap<Box<str>, [Option<Cached>; 3]>>,
    /// Bytes of file contents held, across the mount.
    held: std::sync::atomic::AtomicUsize,
}

#[derive(Clone)]
struct Cached {
    path: Arc<Path>,
    encoding: Option<&'static str>,
    mime: &'static str,
    vary: bool,
    at: Instant,
    content: Option<Content>,
}

/// A small file's bytes, and the length and time they were read at.
#[derive(Clone)]
struct Content {
    len: u64,
    modified: Option<SystemTime>,
    bytes: Arc<[u8]>,
}

/// Files up to this size keep their bytes in the cache.
const CONTENT_LIMIT: u64 = 64 << 10;

/// The most file bytes one mount holds in its cache.
const HELD_LIMIT: usize = 32 << 20;

impl Cache {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<Box<str>, [Option<Cached>; 3]>> {
        self.map.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<Box<str>, [Option<Cached>; 3]>> {
        self.map.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps a small file's bytes beside its resolution.
    fn keep_content(&self, rel: &str, pick: u8, content: Content) {
        use std::sync::atomic::Ordering;
        let size = content.bytes.len();
        if self.held.load(Ordering::Relaxed) + size > HELD_LIMIT {
            return;
        }
        let mut map = self.write();
        if let Some(Some(c)) = map.get_mut(rel).map(|slots| &mut slots[pick as usize]) {
            if c.content.is_none() {
                self.held.fetch_add(size, Ordering::Relaxed);
            }
            c.content = Some(content);
        }
    }
}

/// How long a resolution is trusted before the path is resolved again (a
/// new precompressed variant, a link changed inside the folder).
const REVALIDATE: Duration = Duration::from_secs(2);

/// The most resolutions one mount keeps; past it the cache starts over.
const CACHE_LIMIT: usize = 4096;

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cache")
    }
}

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
    pub(crate) cache: Arc<Cache>,
}

impl Assets {
    /// Serves `dir` under `mount` (`/static`). The folder must exist when the
    /// application is built.
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-assets-new");
    /// std::fs::create_dir_all(&dir)?;
    /// std::fs::write(dir.join("site.css"), "body { margin: 0 }")?;
    ///
    /// let app = App::builder().assets(Assets::new("/static", &dir)).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /static/site.css HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("content-type"), Some(&b"text/css; charset=utf-8"[..]));
    /// assert_eq!(r.text(), "body { margin: 0 }");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
            cache: Arc::default(),
        }
    }

    /// The `Cache-Control` value (default `no-cache`: the browser keeps the
    /// file and revalidates it, which a matching `ETag` answers with 304).
    /// For files whose names change with their content:
    /// `public, max-age=31536000, immutable`.
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-assets-cache");
    /// std::fs::create_dir_all(&dir)?;
    /// std::fs::write(dir.join("app.3f9a.js"), "let x = 1;")?;
    ///
    /// let app = App::builder()
    ///     .assets(Assets::new("/static", &dir).cache_control("public, max-age=31536000, immutable"))
    ///     .build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /static/app.3f9a.js HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.header("cache-control"), Some(&b"public, max-age=31536000, immutable"[..]));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn cache_control(mut self, value: &str) -> Self {
        self.cache_control = value.into();
        self
    }

    /// The file served for a folder (`index.html`). Without one, a folder
    /// is a 404: there are never listings.
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-assets-index");
    /// std::fs::create_dir_all(dir.join("guide"))?;
    /// std::fs::write(dir.join("guide").join("index.html"), "<h1>Guide</h1>")?;
    ///
    /// let app = App::builder().assets(Assets::new("/docs", &dir).index("index.html")).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /docs/guide HTTP/1.1\r\nHost: localhost\r\n\r\n");
    /// assert_eq!(r.text(), "<h1>Guide</h1>");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn index(mut self, name: &str) -> Self {
        self.index = Some(name.into());
        self
    }

    /// Whether `file.br` and `file.gz` next to a file are served to clients
    /// that accept them (default on).
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-assets-precompressed");
    /// std::fs::create_dir_all(&dir)?;
    /// std::fs::write(dir.join("app.js"), "let x = 1;")?;
    /// std::fs::write(dir.join("app.js.gz"), b"not used")?;
    ///
    /// let app = App::builder().assets(Assets::new("/static", &dir).precompressed(false)).build()?;
    /// let r = serve_net::testing::respond(&app, b"GET /static/app.js HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip\r\n\r\n");
    /// assert_eq!((r.text(), r.header("content-encoding")), ("let x = 1;", None));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn precompressed(mut self, on: bool) -> Self {
        self.precompressed = on;
        self
    }

    /// Serve names that start with a dot (default off: `.env`, `.git`,
    /// `.htaccess` are 404).
    ///
    /// ```
    /// use web_net::{App, Assets};
    ///
    /// let dir = std::env::temp_dir().join("web-net-doc-assets-hidden");
    /// std::fs::create_dir_all(&dir)?;
    /// std::fs::write(dir.join(".about.txt"), "hidden")?;
    ///
    /// let shown = App::builder().assets(Assets::new("/static", &dir).hidden_files(true)).build()?;
    /// let kept = App::builder().assets(Assets::new("/static", &dir)).build()?;
    /// let req = b"GET /static/.about.txt HTTP/1.1\r\nHost: localhost\r\n\r\n";
    /// assert_eq!(serve_net::testing::respond(&shown, req).status, 200);
    /// assert_eq!(serve_net::testing::respond(&kept, req).status, 404);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
    // Windows ignores spaces before the extension (`CON .txt`) and takes
    // superscript digits as port numbers (`COM¹`).
    let stem = seg
        .split('.')
        .next()
        .unwrap_or(seg)
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(port) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = port.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '¹' | '²' | '³'), None)
    )
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
pub(crate) struct Found<'r> {
    path: Arc<Path>,
    len: u64,
    modified: Option<SystemTime>,
    encoding: Option<&'static str>,
    mime: &'static str,
    vary: bool,
    /// The cached bytes, when they are still the file's.
    bytes: Option<Arc<[u8]>>,
    /// Where it sits in the mount's cache.
    rel: &'r str,
    pick: u8,
}

/// Resolves `rel` (the path under the mount, canonical) to a file inside the
/// root, or `None` for 404. A resolution made in the last [`REVALIDATE`] is
/// reused when the file it found is still a plain file.
pub(crate) fn find<'r>(
    assets: &Assets,
    rel: &'r str,
    accept_encoding: Option<&[u8]>,
) -> Option<Found<'r>> {
    let pick = if assets.precompressed {
        let offers = ["br", "gzip", "identity"];
        // No Accept-Encoding: the plain file (RFC 9110 allows any coding,
        // but clients that send none are rarely ready for one).
        match accept_encoding.and_then(|v| parse_net::best_encoding(Some(v), &offers)) {
            Some(0) => 0,
            Some(1) => 1,
            _ => 2,
        }
    } else {
        2
    };
    let hit = assets
        .cache
        .read()
        .get(rel)
        .and_then(|slots| slots[pick as usize].as_ref())
        .filter(|c| c.at.elapsed() < REVALIDATE)
        .cloned();
    if let Some(c) = hit {
        // Not followed: a file replaced by a link is resolved again.
        if let Ok(md) = std::fs::symlink_metadata(&c.path) {
            if md.is_file() {
                let (len, modified) = (md.len(), md.modified().ok());
                let bytes = c
                    .content
                    .filter(|k| k.len == len && k.modified == modified)
                    .map(|k| k.bytes);
                return Some(Found {
                    path: c.path,
                    len,
                    modified,
                    encoding: c.encoding,
                    mime: c.mime,
                    vary: c.vary,
                    bytes,
                    rel,
                    pick,
                });
            }
        }
    }
    let found = resolve(assets, rel, pick)?;
    let mut cache = assets.cache.write();
    if cache.len() >= CACHE_LIMIT {
        cache.clear();
        assets
            .cache
            .held
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
    let slots = cache.entry(rel.into()).or_default();
    if let Some(old) = slots[pick as usize].take() {
        if let Some(k) = old.content {
            assets
                .cache
                .held
                .fetch_sub(k.bytes.len(), std::sync::atomic::Ordering::Relaxed);
        }
    }
    slots[pick as usize] = Some(Cached {
        path: Arc::clone(&found.path),
        encoding: found.encoding,
        mime: found.mime,
        vary: found.vary,
        at: Instant::now(),
        content: None,
    });
    Some(found)
}

/// Resolves `rel` the whole way: every segment checked, the path made
/// canonical and checked to be inside the root, the variant for `pick`
/// (0 `br`, 1 `gzip`, 2 none) looked for.
fn resolve<'r>(assets: &Assets, rel: &'r str, pick: u8) -> Option<Found<'r>> {
    let mut path = assets.root.clone();
    for raw in rel.split('/').filter(|s| !s.is_empty()) {
        let seg = url::decode(raw);
        if !safe_segment(&seg, assets.hidden) {
            return None;
        }
        path.push(seg.as_ref());
    }
    let mut meta = inside(&assets.root, &path, assets.hidden)?;
    if meta.1.is_dir() {
        let index = assets.index.as_deref()?;
        path = meta.0.join(index);
        meta = inside(&assets.root, &path, assets.hidden)?;
    }
    let (file, md) = meta;
    if !md.is_file() {
        return None;
    }
    let mime = mime_for(&file);
    let mut found = Found {
        len: md.len(),
        modified: md.modified().ok(),
        path: Arc::from(file),
        encoding: None,
        mime,
        vary: assets.precompressed,
        bytes: None,
        rel,
        pick,
    };
    let ext = match pick {
        0 => Some(("br", "br")),
        1 => Some(("gzip", "gz")),
        _ => None,
    };
    if let Some((coding, ext)) = ext {
        let mut alt = found.path.as_os_str().to_owned();
        alt.push(".");
        alt.push(ext);
        if let Some((p, m)) = inside(&assets.root, Path::new(&alt), assets.hidden) {
            if m.is_file() {
                found.path = Arc::from(p);
                found.len = m.len();
                found.modified = m.modified().ok();
                found.encoding = Some(coding);
            }
        }
    }
    Some(found)
}

/// Resolves `path` and checks it is still under `root` (both canonical).
fn inside(root: &Path, path: &Path, hidden: bool) -> Option<(PathBuf, std::fs::Metadata)> {
    let real = std::fs::canonicalize(path).ok()?;
    let below = real.strip_prefix(root).ok()?;
    // The resolved names are checked again: a request may name a file by
    // another spelling the file system resolves (a Windows 8.3 short name
    // such as `ENVSEC~1` for `.envsecret`, or a link inside the folder).
    for part in below.components() {
        let std::path::Component::Normal(name) = part else {
            return None;
        };
        if !name.to_str().is_some_and(|n| safe_segment(n, hidden)) {
            return None;
        }
    }
    let md = std::fs::metadata(&real).ok()?;
    Some((real, md))
}

/// The entity tag: length and modification time, and the coding, so each
/// representation has its own.
fn etag(found: &Found<'_>) -> String {
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

/// Why a file could not be answered (nothing was written).
pub(crate) enum Unserved {
    /// It could not be read: 500.
    Unreadable,
    /// The application follows [`MAX_STREAMS`] large replies already: 503.
    Busy,
}

/// Answers a request for a file.
pub(crate) fn serve(
    assets: &Assets,
    found: &Found<'_>,
    streams: &Streams,
    key: StreamKey,
    req: &HttpRequest<'_>,
    reply: &mut HttpReply,
) -> Result<Outcome, Unserved> {
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
            return Ok(Outcome::Done);
        }
    } else if let (Some(ims), Some(lm)) = (req.header("if-modified-since"), last_modified) {
        if let Ok(since) = parse_net::http_date(ims) {
            if lm <= since {
                head(reply, 304);
                return Ok(Outcome::Done);
            }
        }
    }

    // One range, when it applies (multiple ranges get the whole file).
    let mut range: Option<ByteRange> = None;
    if req.method() == Method::Get {
        if let Some(value) = req.header("range") {
            if if_range_holds(found, &tag, req) {
                let mut out = [ByteRange { start: 0, end: 0 }];
                match parse_net::byte_ranges(value, found.len, &mut out) {
                    Ok(RangeOutcome::Ranges(1)) => range = Some(out[0]),
                    Ok(RangeOutcome::Unsatisfiable) => {
                        head(reply, 416);
                        reply.header("content-range", format!("bytes */{}", found.len));
                        return Ok(Outcome::Done);
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
    let stream = Stream {
        path: Arc::clone(&found.path),
        len: found.len,
        modified: found.modified,
        start,
        total: len,
    };
    let fields = |reply: &mut HttpReply| {
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
    };
    // A small file goes whole (for HEAD too: its length is the body's). It
    // is read before any field is written, so a file that cannot be read
    // leaves an empty reply for the 500.
    if let Some(bytes) = &found.bytes {
        // Cached and unchanged: no file is opened.
        let from = start as usize;
        fields(reply);
        reply.body(&bytes[from..from + len as usize]);
        return Ok(Outcome::Done);
    }
    if len <= INLINE_LIMIT {
        return PART_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            read_into(&stream, start, len as usize, &mut buf).ok_or(Unserved::Unreadable)?;
            fields(reply);
            reply.body(&buf);
            if start == 0 && len == found.len && len <= CONTENT_LIMIT {
                assets.cache.keep_content(
                    found.rel,
                    found.pick,
                    Content {
                        len: found.len,
                        modified: found.modified,
                        bytes: Arc::from(&buf[..]),
                    },
                );
            }
            shrink(&mut buf);
            Ok(Outcome::Done)
        });
    }
    // Large: the file must open and still be what was found.
    open_same(&stream).ok_or(Unserved::Unreadable)?;
    if req.method() == Method::Head {
        fields(reply);
        reply.stream();
        return Ok(Outcome::Done);
    }
    // Sent in parts: serve-net calls again for each part, with the same
    // request; `sent` says where the next part starts. The status and fields
    // set above leave with the first part only. The record is made before
    // anything is written, so a full table is a clean 503.
    if !streams.start(key, stream) {
        return Err(Unserved::Busy);
    }
    fields(reply);
    let Some(stream) = streams.take(key) else {
        return Ok(ABORT);
    };
    Ok(next_part(streams, key, stream, reply))
}

fn send_part(stream: &Stream, sent: u64, reply: &mut HttpReply) -> Outcome {
    if sent >= stream.total {
        return Outcome::Done;
    }
    let want = (stream.total - sent).min(PART as u64) as usize;
    PART_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        if read_into(stream, stream.start + sent, want, &mut buf).is_none() {
            return ABORT;
        }
        reply.stream().send(&buf);
        if sent + want as u64 >= stream.total {
            Outcome::Done
        } else {
            Outcome::More
        }
    })
}

/// Opens the file and checks it is still the one found: the same length and
/// modification time.
fn open_same(stream: &Stream) -> Option<File> {
    let f = File::open(&stream.path).ok()?;
    let md = f.metadata().ok()?;
    (md.is_file() && md.len() == stream.len && md.modified().ok() == stream.modified).then_some(f)
}

/// Reads exactly `len` bytes at `start` into `buf`, from the file as it was
/// found; `None` when it changed or cannot be read.
fn read_into(stream: &Stream, start: u64, len: usize, buf: &mut Vec<u8>) -> Option<()> {
    let mut f = open_same(stream)?;
    if start > 0 {
        f.seek(SeekFrom::Start(start)).ok()?;
    }
    buf.clear();
    buf.reserve(len);
    f.take(len as u64).read_to_end(buf).ok()?;
    (buf.len() == len).then_some(())
}

/// Buffers bigger than one part are not kept between requests.
fn shrink(buf: &mut Vec<u8>) {
    if buf.capacity() > PART {
        *buf = Vec::new();
    }
}

/// The media type for a file name, by extension. Text types carry UTF-8.
///
/// ```
/// use std::path::Path;
/// use web_net::mime_for;
///
/// assert_eq!(mime_for(Path::new("site.css")), "text/css; charset=utf-8");
/// assert_eq!(mime_for(Path::new("photo.JPG")), "image/jpeg");
/// assert_eq!(mime_for(Path::new("data.bin")), "application/octet-stream");
/// ```
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

    fn stream() -> Stream {
        Stream {
            path: Arc::from(Path::new("x")),
            len: 1,
            modified: None,
            start: 0,
            total: 1,
        }
    }

    #[test]
    fn test_streams_full_refuses_new_never_forgets_old() {
        let s = Streams::default();
        for i in 0..MAX_STREAMS as u32 {
            assert!(s.start((1, i), stream()));
        }
        assert!(!s.start((2, 0), stream()), "a full table refuses");
        assert_eq!(s.len(), MAX_STREAMS);
        // Every reply in progress is still there.
        assert!(s.take((1, 0)).is_some());
        assert!(s.take((1, MAX_STREAMS as u32 - 1)).is_some());
        // A request that is done frees its slot.
        s.remove((1, 5));
        assert_eq!(s.len(), MAX_STREAMS - 3);
        assert!(s.start((2, 0), stream()));
    }

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
