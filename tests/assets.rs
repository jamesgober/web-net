//! Static files, health paths, security headers, cookies out, and the 304
//! fast path.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serve_net::Scheme;
use serve_net::testing::{TestReply, TestRequest, respond};
use web_net::{App, Assets, SecurityHeaders, get};

/// A fresh folder under the system temp folder, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "web-net-test-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join("sub")).unwrap();
        std::fs::write(p.join("a.css"), b"body{color:red}").unwrap();
        std::fs::write(p.join("a.css.br"), b"BROTLI").unwrap();
        std::fs::write(p.join("a.css.gz"), b"GZIP").unwrap();
        std::fs::write(p.join("data.txt"), b"0123456789").unwrap();
        std::fs::write(p.join(".env"), b"SECRET=1").unwrap();
        std::fs::write(p.join("sub").join("index.html"), b"<h1>sub</h1>").unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn app(dir: &Dir) -> App {
    App::builder()
        .assets(Assets::new("/static", &dir.0))
        .assets(
            Assets::new("/docs", &dir.0)
                .index("index.html")
                .precompressed(false),
        )
        .health("/healthz")
        .route(get("/", |cx| cx.text(200, "home")).public())
        .build()
        .unwrap()
}

fn send(app: &App, head: &str) -> TestReply {
    respond(app, format!("{head}\r\n\r\n").as_bytes())
}

fn h<'a>(r: &'a TestReply, name: &str) -> &'a str {
    r.header(name)
        .map(|v| std::str::from_utf8(v).unwrap())
        .unwrap_or("")
}

#[test]
fn test_serves_a_file_with_validators() {
    let d = Dir::new("validators");
    let app = app(&d);
    let r = send(&app, "GET /static/data.txt HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.text()), (200, "0123456789"));
    assert_eq!(h(&r, "content-type"), "text/plain; charset=utf-8");
    assert_eq!(h(&r, "accept-ranges"), "bytes");
    assert_eq!(h(&r, "cache-control"), "no-cache");
    assert!(!h(&r, "last-modified").is_empty());
    let tag = h(&r, "etag").to_owned();
    assert!(tag.starts_with('"'));

    let r = send(
        &app,
        &format!("GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {tag}"),
    );
    assert_eq!(r.status, 304);
    assert!(r.body.is_empty());
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"other\"",
    );
    assert_eq!(r.status, 200);

    let lm = {
        let r = send(&app, "GET /static/data.txt HTTP/1.1\r\nHost: localhost");
        h(&r, "last-modified").to_owned()
    };
    let r = send(
        &app,
        &format!("GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: {lm}"),
    );
    assert_eq!(r.status, 304);
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nIf-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT",
    );
    assert_eq!(r.status, 200);

    let r = send(&app, "HEAD /static/data.txt HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.body.len()), (200, 0));
    assert_eq!(h(&r, "content-length"), "10");
}

#[test]
fn test_ranges() {
    let d = Dir::new("ranges");
    let app = app(&d);
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-4",
    );
    assert_eq!((r.status, r.text()), (206, "234"));
    assert_eq!(h(&r, "content-range"), "bytes 2-4/10");
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=-3",
    );
    assert_eq!(r.text(), "789");
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=50-60",
    );
    assert_eq!((r.status, h(&r, "content-range")), (416, "bytes */10"));
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=0-0, 5-5",
    );
    assert_eq!((r.status, r.text()), (200, "0123456789"));
    let r = send(
        &app,
        "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-4\r\nIf-Range: \"stale\"",
    );
    assert_eq!(r.status, 200);
    let tag = h(
        &send(&app, "GET /static/data.txt HTTP/1.1\r\nHost: localhost"),
        "etag",
    )
    .to_owned();
    let r = send(
        &app,
        &format!(
            "GET /static/data.txt HTTP/1.1\r\nHost: localhost\r\nRange: bytes=2-4\r\nIf-Range: {tag}"
        ),
    );
    assert_eq!(r.status, 206);
}

#[test]
fn test_precompressed_variants() {
    let d = Dir::new("precompressed");
    let app = app(&d);
    let r = send(
        &app,
        "GET /static/a.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip, br",
    );
    assert_eq!((r.text(), h(&r, "content-encoding")), ("BROTLI", "br"));
    assert_eq!(h(&r, "vary"), "accept-encoding");
    assert_eq!(h(&r, "content-type"), "text/css; charset=utf-8");
    let br_tag = h(&r, "etag").to_owned();
    let r = send(
        &app,
        "GET /static/a.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip",
    );
    assert_eq!((r.text(), h(&r, "content-encoding")), ("GZIP", "gzip"));
    assert_ne!(h(&r, "etag"), br_tag);
    let r = send(&app, "GET /static/a.css HTTP/1.1\r\nHost: localhost");
    assert_eq!(
        (r.text(), h(&r, "content-encoding")),
        ("body{color:red}", "")
    );
    let r = send(
        &app,
        "GET /static/a.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br;q=0, gzip;q=0",
    );
    assert_eq!(r.text(), "body{color:red}");
    // Off for this mount.
    let r = send(
        &app,
        "GET /docs/a.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br",
    );
    assert_eq!((r.text(), h(&r, "vary")), ("body{color:red}", ""));
}

#[test]
fn test_refused_names_and_folders() {
    let d = Dir::new("refused");
    let app = app(&d);
    for p in [
        "/static/.env",
        "/static/a.css::$DATA",
        "/static/data.txt.",
        "/static/data.txt%20",
        "/static/CON",
        "/static/nul.txt",
        "/static/sub",
        "/static/missing.txt",
        "/static",
    ] {
        let r = send(&app, &format!("GET {p} HTTP/1.1\r\nHost: localhost"));
        assert_eq!(r.status, 404, "{p}");
    }
    // Paths that climb are canonicalized before the mount is even looked at.
    let r = send(
        &app,
        "GET /static/../static/data.txt HTTP/1.1\r\nHost: localhost",
    );
    assert_eq!((r.status, h(&r, "location")), (301, "/static/data.txt"));
    let r = send(
        &app,
        "GET /static/..%2f..%2fetc HTTP/1.1\r\nHost: localhost",
    );
    assert_eq!(r.status, 400);
    // An index file for a folder where the mount has one.
    assert_eq!(
        send(&app, "GET /docs/sub HTTP/1.1\r\nHost: localhost").text(),
        "<h1>sub</h1>"
    );
    assert_eq!(
        send(&app, "GET /docs HTTP/1.1\r\nHost: localhost").status,
        404
    );
    // Files take GET and HEAD only.
    let r = send(
        &app,
        "POST /static/data.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0",
    );
    assert_eq!((r.status, h(&r, "allow")), (405, "GET, HEAD, OPTIONS"));
}

/// Windows answers a file by its 8.3 short name too (`ENVSEC~1` for
/// `.envsecret`); the resolved name is what is checked. Skipped on volumes
/// that make no short names.
#[cfg(windows)]
#[test]
fn test_short_names_do_not_reach_hidden_files() {
    let d = Dir::new("shortnames");
    std::fs::write(d.0.join(".envsecret"), b"SECRET").unwrap();
    let app = app(&d);
    for short in ["ENVSEC~1", "envsec~1"] {
        if std::fs::canonicalize(d.0.join(short)).is_err() {
            continue;
        }
        let r = send(
            &app,
            &format!("GET /static/{short} HTTP/1.1\r\nHost: localhost"),
        );
        assert_eq!(r.status, 404, "{short}");
    }
}

#[test]
fn test_more_device_names() {
    let d = Dir::new("devices");
    let app = app(&d);
    for p in [
        "/static/COM%C2%B9",
        "/static/lpt%C2%B3.log",
        "/static/CON%20.txt",
    ] {
        assert_eq!(
            send(&app, &format!("GET {p} HTTP/1.1\r\nHost: localhost")).status,
            404,
            "{p}"
        );
    }
}

#[cfg(unix)]
#[test]
fn test_unreadable_file_is_a_clean_500() {
    use std::os::unix::fs::PermissionsExt;
    let d = Dir::new("unreadable");
    let f = d.0.join("locked.txt");
    std::fs::write(&f, b"x").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&f).is_ok() {
        return; // running as root: the file is readable anyway
    }
    let app = app(&d);
    let r = send(&app, "GET /static/locked.txt HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.status, 500);
    assert_eq!(h(&r, "etag"), "");
    assert_eq!(h(&r, "cache-control"), "no-store");
    assert_eq!(
        r.headers
            .iter()
            .filter(|(n, _)| n == "content-type")
            .count(),
        1
    );
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
#[test]
fn test_symlink_out_of_the_root_is_refused() {
    let d = Dir::new("symlink");
    let outside = Dir::new("symlink-outside");
    std::os::unix::fs::symlink(outside.0.join("data.txt"), d.0.join("leak.txt")).unwrap();
    std::os::unix::fs::symlink(d.0.join("data.txt"), d.0.join("inside.txt")).unwrap();
    let app = app(&d);
    assert_eq!(
        send(&app, "GET /static/leak.txt HTTP/1.1\r\nHost: localhost").status,
        404
    );
    assert_eq!(
        send(&app, "GET /static/inside.txt HTTP/1.1\r\nHost: localhost").status,
        200
    );
}

/// Sends one request on a test connection and returns the status and the
/// body with chunked framing removed (`TestReply` reads only length-framed
/// bodies).
fn raw(app: App, head: &str) -> (u16, Vec<u8>) {
    let mut conn = serve_net::testing::TestConnection::new(app);
    let mut out = Vec::new();
    conn.send_into(format!("{head}\r\n\r\n").as_bytes(), &mut out);
    let end = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a head");
    let head_text = std::str::from_utf8(&out[..end])
        .unwrap()
        .to_ascii_lowercase();
    let status: u16 = head_text[9..12].parse().unwrap();
    assert!(
        head_text.contains("transfer-encoding: chunked"),
        "{head_text}"
    );
    let mut body = Vec::new();
    let mut rest = &out[end + 4..];
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("a chunk size line");
        let size =
            usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap(), 16).unwrap();
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    (status, body)
}

#[test]
fn test_large_file_in_parts() {
    let d = Dir::new("large");
    let big: Vec<u8> = (0..(3 << 20) + 17).map(|i| (i % 251) as u8).collect();
    std::fs::write(d.0.join("big.bin"), &big).unwrap();
    let (status, body) = raw(app(&d), "GET /static/big.bin HTTP/1.1\r\nHost: localhost");
    assert_eq!((status, body.len()), (200, big.len()));
    assert!(body == big);
    let (status, body) = raw(
        app(&d),
        "GET /static/big.bin HTTP/1.1\r\nHost: localhost\r\nRange: bytes=1048570-3145740",
    );
    assert_eq!(status, 206);
    assert!(body == big[1_048_570..=3_145_740]);
}

#[test]
fn test_health_and_ready() {
    let up = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&up);
    let app = App::builder()
        .health("/healthz")
        .ready("/readyz", move || flag.load(Ordering::Relaxed))
        .build()
        .unwrap();
    let r = send(&app, "GET /healthz HTTP/1.1\r\nHost: localhost");
    assert_eq!(
        (r.status, r.text(), h(&r, "cache-control")),
        (200, "ok", "no-store")
    );
    assert_eq!(
        send(&app, "GET /readyz HTTP/1.1\r\nHost: localhost").status,
        503
    );
    up.store(true, Ordering::Relaxed);
    assert_eq!(
        send(&app, "GET /readyz HTTP/1.1\r\nHost: localhost").text(),
        "ready"
    );
}

#[test]
fn test_security_headers() {
    let app = App::builder()
        .host("example.com")
        .route(get("/", |cx| cx.text(200, "x")).public())
        .route(
            get("/framed", |cx| {
                cx.set_header("x-frame-options", "SAMEORIGIN");
                cx.text(200, "x")
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: example.com");
    assert_eq!(h(&r, "x-frame-options"), "DENY");
    assert_eq!(h(&r, "content-security-policy"), web_net::DEFAULT_CSP);
    assert_eq!(h(&r, "referrer-policy"), "strict-origin-when-cross-origin");
    assert_eq!(h(&r, "x-content-type-options"), "nosniff");
    assert_eq!(
        h(&r, "strict-transport-security"),
        "",
        "no HSTS over plain HTTP"
    );
    let r = TestRequest::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .scheme(Scheme::Https)
        .send(&app);
    assert_eq!(h(&r, "strict-transport-security"), "max-age=31536000");
    let r = send(&app, "GET /framed HTTP/1.1\r\nHost: example.com");
    assert_eq!(h(&r, "x-frame-options"), "SAMEORIGIN");
    // Error pages carry them too.
    let r = send(&app, "GET /nope HTTP/1.1\r\nHost: example.com");
    assert_eq!(h(&r, "x-frame-options"), "DENY");

    let bare = App::builder()
        .security_headers(SecurityHeaders::none())
        .route(get("/", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let r = send(&bare, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!(
        (h(&r, "x-frame-options"), h(&r, "x-content-type-options")),
        ("", "nosniff")
    );
}

#[test]
fn test_no_hsts_for_development_hosts() {
    let app = App::builder()
        .host("example.com")
        .development()
        .route(get("/", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let r = TestRequest::new(b"GET / HTTP/1.1\r\nHost: localhost:8443\r\n\r\n")
        .scheme(Scheme::Https)
        .send(&app);
    assert_eq!(h(&r, "strict-transport-security"), "");
}

#[test]
fn test_build_checks_for_assets() {
    let e = App::builder()
        .assets(Assets::new("/static", "/definitely/not/here/web-net"))
        .assets(Assets::new("static", "."))
        .route(get("/static/x", |cx| cx.text(200, "x")).public())
        .health("health")
        .build()
        .unwrap_err();
    assert_eq!(e.problems().len(), 4, "{e}");
}
