//! The Tier 1 surface: a route, a handler, and a served site, each in a line
//! or two.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serve_net::testing::{TestReply, respond};
use web_net::{App, Denial, Gate, Identity, Request, Sites, get, post};

fn send(app: &impl serve_net::HttpService, raw: &str) -> TestReply {
    respond(app, format!("{raw}\r\n\r\n").as_bytes())
}

#[test]
fn test_open_gate_route_without_access_is_public() {
    let app = App::builder()
        .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
        .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.text()), (200, "<h1>Hello</h1>"));
    let r = send(&app, "GET /posts/caf%C3%A9 HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.text()), (200, "café"));
}

struct Members;
struct Member;
impl Identity for Member {
    fn is_guest(&self) -> bool {
        false
    }
}
impl Gate for Members {
    type Identity = Member;
    type Rule = ();
    fn authenticate(&self, _: &Request<'_>) -> Result<Member, Denial> {
        Ok(Member)
    }
    fn authorize(&self, _: &Member, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Err(Denial::forbidden("test.never"))
    }
}

#[test]
fn test_gate_with_rules_route_without_access_does_not_build() {
    let err = App::with_gate(Members)
        .route(get("/", |cx| cx.text(200, "x")))
        .build()
        .unwrap_err();
    assert_eq!(err.problems().len(), 1);
    assert!(err.to_string().contains("declares no access"), "{err}");
}

#[test]
fn test_param_unknown_name_is_500() {
    let app = App::builder()
        .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("id")?)))
        .build()
        .unwrap();
    assert_eq!(
        send(&app, "GET /posts/a HTTP/1.1\r\nHost: localhost").status,
        500
    );
}

#[test]
fn test_param_as_bad_value_is_404_unknown_name_is_500() {
    let app = App::builder()
        .route(get("/u/:id", |cx| {
            let id: u32 = cx.param_as("id")?;
            cx.text(200, &id.to_string())
        }))
        .route(get("/v/:id", |cx| {
            let id: u32 = cx.param_as("nope")?;
            cx.text(200, &id.to_string())
        }))
        .build()
        .unwrap();
    assert_eq!(
        send(&app, "GET /u/7 HTTP/1.1\r\nHost: localhost").text(),
        "7"
    );
    assert_eq!(
        send(&app, "GET /u/x HTTP/1.1\r\nHost: localhost").status,
        404
    );
    assert_eq!(
        send(&app, "GET /v/7 HTTP/1.1\r\nHost: localhost").status,
        500
    );
}

#[test]
fn test_bytes_sets_status_type_and_body() {
    let app = App::builder()
        .route(get("/a", |cx| cx.bytes(201, "image/png", &[1, 2, 3])))
        .route(get("/b", |cx| {
            cx.set_header("content-type", "application/x-mine");
            cx.bytes(200, "image/png", b"x")
        }))
        .build()
        .unwrap();
    let r = send(&app, "GET /a HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.status, 201);
    assert_eq!(r.header("content-type"), Some(&b"image/png"[..]));
    assert_eq!(r.body, [1, 2, 3]);
    let r = send(&app, "GET /b HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.header("content-type"), Some(&b"application/x-mine"[..]));
}

#[test]
fn test_writers_end_a_handler_and_chain_with_question_mark() {
    let app = App::builder()
        .route(get("/", |cx| {
            cx.text(200, "first")?;
            cx.html(404, "<p>second wins</p>")
        }))
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.text()), (404, "<p>second wins</p>"));
    // The first writer set text/plain; a later writer does not add a second
    // content-type.
    assert_eq!(
        r.header("content-type"),
        Some(&b"text/plain; charset=utf-8"[..])
    );
}

#[test]
fn test_redirect_303_after_post() {
    let app = App::builder()
        .route(post("/f", |cx| cx.redirect(303, "/done")).csrf_exempt("test"))
        .build()
        .unwrap();
    let r = send(
        &app,
        "POST /f HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0",
    );
    assert_eq!((r.status, r.header("location")), (303, Some(&b"/done"[..])));
}

#[test]
fn test_accept_and_accept_language() {
    let app = App::builder()
        .route(get("/", |cx| {
            let media = cx.accept(&["text/html", "application/json"]).unwrap_or("-");
            let lang = cx.accept_language(&["en", "de"]).unwrap_or("-");
            cx.text(200, &format!("{media} {lang}"))
        }))
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nAccept-Language: de",
    );
    assert_eq!(r.text(), "application/json de");
}

fn get_over_tcp(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn test_listen_serves_over_tcp() {
    let server = App::builder()
        .route(get("/", |cx| cx.text(200, "over tcp")))
        .build()
        .unwrap()
        .listen("127.0.0.1:0")
        .unwrap();
    let addr = server.local_addr().unwrap();
    let reply = get_over_tcp(addr, "/");
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    assert!(reply.ends_with("over tcp"), "{reply}");
    server.drain(Duration::from_secs(5));
}

#[test]
fn test_sites_listen_serves_over_tcp() {
    let app = App::builder()
        .route(get("/", |cx| cx.text(200, "site")))
        .build()
        .unwrap();
    let server = Sites::new().site(app).listen("127.0.0.1:0").unwrap();
    let reply = get_over_tcp(server.local_addr().unwrap(), "/");
    assert!(reply.ends_with("site"), "{reply}");
    server.drain(Duration::from_secs(5));
}

#[test]
fn test_listen_unresolvable_address_is_an_error() {
    let app = App::builder()
        .route(get("/", |cx| cx.text(200, "x")))
        .build()
        .unwrap();
    assert!(app.listen("256.0.0.1:80").is_err());
}

/// A gate whose store is down fails closed with a retryable 503.
struct Down(Denial);
impl Gate for Down {
    type Identity = Member;
    type Rule = ();
    fn authenticate(&self, _: &Request<'_>) -> Result<Member, Denial> {
        Err(self.0.clone())
    }
    fn authorize(&self, _: &Member, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Ok(())
    }
}

#[test]
fn test_unavailable_gate_answers_503_with_retry_after() {
    let app = App::with_gate(Down(Denial::unavailable("gate.unavailable").retry_after(5)))
        .route(get("/", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.status, 503);
    assert_eq!(r.header("retry-after"), Some(&b"5"[..]));
    assert_eq!(r.header("cache-control"), Some(&b"no-store"[..]));

    // Retry-After only goes with the statuses a client retries.
    let app = App::with_gate(Down(Denial::forbidden("gate.banned").retry_after(5)))
        .route(get("/", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, r.header("retry-after")), (403, None));
}
