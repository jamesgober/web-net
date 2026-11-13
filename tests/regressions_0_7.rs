//! Bugs fixed in 0.7: each case failed
//! before its fix.

use std::sync::atomic::{AtomicU32, Ordering};

use serve_net::testing::{TestConnection, TestReply, respond};
use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
use web_net::{App, Assets, Context, Cors, Denial, Gate, Identity, Request, TrailingSlash, get};

fn send(app: &impl HttpService, raw: &str) -> TestReply {
    respond(app, format!("{raw}\r\n\r\n").as_bytes())
}

fn h<'a>(r: &'a TestReply, name: &str) -> &'a str {
    r.header(name)
        .map(|v| std::str::from_utf8(v).unwrap())
        .unwrap_or("")
}

/// A large file replaced between two parts of its reply: the connection
/// ends; the reply never finishes cleanly with the wrong bytes.
#[test]
fn test_file_changed_between_parts_ends_the_connection() {
    let dir = std::env::temp_dir().join(format!("web-net-regressions-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("big.bin");
    std::fs::write(&file, vec![1u8; 3 << 20]).unwrap();

    struct Swap {
        app: App,
        file: std::path::PathBuf,
        calls: AtomicU32,
    }
    impl HttpService for Swap {
        fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 1 {
                std::fs::write(&self.file, vec![2u8; 100]).unwrap();
            }
            self.app.respond(req, env, None, reply).outcome
        }
    }
    let swap = Swap {
        app: App::builder()
            .assets(Assets::new("/s", &dir))
            .build()
            .unwrap(),
        file,
        calls: AtomicU32::new(0),
    };
    let mut conn = TestConnection::new(swap);
    let mut out = Vec::new();
    conn.send_into(
        b"GET /s/big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n",
        &mut out,
    );
    assert!(out.starts_with(b"HTTP/1.1 200"));
    assert!(
        !out.ends_with(b"0\r\n\r\n"),
        "the reply ended as if complete"
    );
    assert!(!conn.is_open());
    let _ = std::fs::remove_dir_all(&dir);
}

const CLEAR: &str = "sid=; Max-Age=0; Path=/";

struct Stale;

impl Identity for Stale {
    fn is_guest(&self) -> bool {
        true
    }
    fn set_cookie(&self) -> Option<&str> {
        Some(CLEAR)
    }
}

struct StaleGate;

impl Gate for StaleGate {
    type Identity = Stale;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Stale, Denial> {
        if req.header("x-deny").is_some() {
            return Err(Denial::forbidden("test.deny"));
        }
        Ok(Stale)
    }
    fn authorize(&self, _: &Stale, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Ok(())
    }
}

fn stale() -> App<StaleGate> {
    App::with_gate(StaleGate)
        .route(
            get("/signin", |cx: &mut Context<'_, Stale>| {
                cx.set_header("set-cookie", "sid=fresh; Path=/; HttpOnly");
                cx.text(200, "in")
            })
            .public(),
        )
        .route(
            get("/page", |cx: &mut Context<'_, Stale>| {
                cx.set_header("cache-control", "public, max-age=600");
                cx.text(200, "page")
            })
            .public(),
        )
        .route(
            get("/api", |cx: &mut Context<'_, Stale>| cx.text(200, "api"))
                .public()
                .cors(Cors::new().origin("https://app.example")),
        )
        .build()
        .unwrap()
}

/// The handler's fresh session cookie is not cancelled by the gate's clear.
#[test]
fn test_handler_cookie_beats_the_gate_clear() {
    let r = send(&stale(), "GET /signin HTTP/1.1\r\nHost: localhost");
    let sids: Vec<&[u8]> = r
        .headers
        .iter()
        .filter(|(n, _)| n == "set-cookie")
        .map(|(_, v)| v.as_slice())
        .collect();
    assert_eq!(sids, [&b"sid=fresh; Path=/; HttpOnly"[..]]);
}

/// A reply that sets a cookie is never public, even when the handler said so.
#[test]
fn test_pending_cookie_overrides_public_cache_control() {
    let r = send(&stale(), "GET /page HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "cache-control"), "private, no-store");
    assert_eq!(h(&r, "set-cookie"), CLEAR);
}

/// Health paths answer under every trailing-slash policy.
#[test]
fn test_health_under_add() {
    let app = App::builder()
        .trailing_slash(TrailingSlash::Add)
        .health("/healthz")
        .ready("/readyz", || true)
        .build()
        .unwrap();
    assert_eq!(
        send(&app, "GET /healthz HTTP/1.1\r\nHost: localhost").status,
        200
    );
    assert_eq!(
        send(&app, "GET /readyz HTTP/1.1\r\nHost: localhost").text(),
        "ready"
    );
}

/// Preflights are answered before the gate: a gate that refuses
/// credential-less requests does not break CORS.
#[test]
fn test_preflight_before_the_gate() {
    let r = send(
        &stale(),
        "OPTIONS /api HTTP/1.1\r\nHost: localhost\r\nX-Deny: 1\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET",
    );
    assert_eq!(r.status, 204);
    assert_eq!(h(&r, "access-control-allow-origin"), "https://app.example");
    assert!(r.header("set-cookie").is_none());
}
