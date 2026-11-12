//! Regression tests for the second independent review (of 0.9.0). Each test
//! failed before its fix.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use serve_net::testing::{TestReply, respond};
use serve_net::{Envelope, Verdict};
use web_net::{
    App, Checkpoint, Denial, ErrorPage, Event, EventKind, Events, Gate, Identity, Output, Render,
    RenderError, Request, Stage, TemplateId, get,
};

fn send(app: &impl serve_net::HttpService, raw: &str) -> TestReply {
    respond(app, format!("{raw}\r\n\r\n").as_bytes())
}

struct Member;
impl Identity for Member {
    fn is_guest(&self) -> bool {
        false
    }
}

#[derive(Default)]
struct Log(Mutex<Vec<(EventKind, u16, &'static str)>>);
impl Events for &'static Log {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push((e.kind, e.status, e.code));
    }
}
fn log() -> &'static Log {
    Box::leak(Box::default())
}

// ---------------------------------------------------------------- F-2

/// Panics where the test says, on a cookie the gate does not expect.
struct PanicGate {
    in_authorize: bool,
}
impl Gate for PanicGate {
    type Identity = Member;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Member, Denial> {
        if !self.in_authorize && req.cookie("sid").ok().flatten() == Some("x") {
            panic!("the gate sliced a short cookie");
        }
        Ok(Member)
    }
    fn authorize(&self, _: &Member, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        assert!(!self.in_authorize, "authorize failed");
        Ok(())
    }
}

#[test]
fn test_f2_gate_panic_is_answered_500_and_reported() {
    for in_authorize in [false, true] {
        let log = log();
        let app = App::with_gate(PanicGate { in_authorize })
            .events(log)
            .route(get("/", |cx| cx.text(200, "ok")).allow(()))
            .build()
            .unwrap();
        let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost\r\nCookie: sid=x");
        assert_eq!(r.status, 500, "in_authorize {in_authorize}");
        assert!(r.text().contains("Reference:"));
        let seen = log.0.lock().unwrap();
        assert!(
            seen.iter()
                .any(|&(k, s, _)| k == EventKind::Panicked && s == 500),
            "{seen:?}"
        );
    }
}

struct PanicCheckpoint;
impl Checkpoint for PanicCheckpoint {
    fn check(&self, _: &Envelope, _: Stage) -> Verdict {
        panic!("the revocation store failed");
    }
}

#[test]
fn test_f2_checkpoint_panic_is_answered_500() {
    let app = App::builder()
        .checkpoint(PanicCheckpoint)
        .route(get("/", |cx| cx.text(200, "ok")))
        .build()
        .unwrap();
    assert_eq!(send(&app, "GET / HTTP/1.1\r\nHost: localhost").status, 500);
}

struct PanicEvents;
impl Events for PanicEvents {
    fn event(&self, _: &Event<'_>) {
        panic!("the event sink failed");
    }
}

#[test]
fn test_f2_events_panic_does_not_take_the_reply() {
    let app = App::builder()
        .events(PanicEvents)
        .route(get("/", |cx| cx.text(200, "ok")))
        .build()
        .unwrap();
    assert_eq!(
        send(&app, "GET /nope HTTP/1.1\r\nHost: localhost").status,
        404
    );
}

struct PanicErrorPage;
impl Render for PanicErrorPage {
    type View<'a> = str;
    fn template(&self, _: &str) -> Option<TemplateId> {
        None
    }
    fn render(&self, _: TemplateId, _: &str, _: &mut Output<'_>) -> Result<(), RenderError> {
        Ok(())
    }
    fn error_page(&self, _: &ErrorPage<'_>, out: &mut Output<'_>) -> Result<bool, RenderError> {
        out.write_str("half a page")?;
        panic!("the error template failed");
    }
}

#[test]
fn test_f2_error_page_panic_gives_the_builtin_page() {
    let log = log();
    let app = App::builder()
        .render(PanicErrorPage)
        .events(log)
        .route(get("/", |cx| cx.text(200, "ok")))
        .build()
        .unwrap();
    let r = send(&app, "GET /nope HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.status, 404);
    assert!(!r.text().contains("half a page"));
    assert!(r.text().contains("Reference:"));
    assert!(
        log.0
            .lock()
            .unwrap()
            .iter()
            .any(|&(k, _, c)| k == EventKind::Panicked && c == "render.error_page_panic")
    );
}

#[test]
fn test_f2_ready_check_panic_is_answered_500() {
    let app = App::builder()
        .ready("/readyz", || panic!("the readiness probe failed"))
        .build()
        .unwrap();
    assert_eq!(
        send(&app, "GET /readyz HTTP/1.1\r\nHost: localhost").status,
        500
    );
}

#[test]
fn test_f2_handler_panic_still_500() {
    let counter: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
    let app = App::builder()
        .route(get("/", move |_cx| {
            counter.fetch_add(1, Ordering::Relaxed);
            panic!("the handler failed")
        }))
        .build()
        .unwrap();
    assert_eq!(send(&app, "GET / HTTP/1.1\r\nHost: localhost").status, 500);
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

// ---------------------------------------------------------------- lows

#[derive(Clone, Copy, PartialEq)]
enum Role {
    Admin,
    Owner,
}

/// `sid=admin` is an admin, `sid=owner` an owner, anyone else a guest.
struct Roles;
struct Who(Option<Role>);
impl Identity for Who {
    fn is_guest(&self) -> bool {
        self.0.is_none()
    }
}
impl Gate for Roles {
    type Identity = Who;
    type Rule = Role;
    fn authenticate(&self, req: &Request<'_>) -> Result<Who, Denial> {
        Ok(Who(match req.cookie("sid").ok().flatten() {
            Some("admin") => Some(Role::Admin),
            Some("owner") => Some(Role::Owner),
            _ => None,
        }))
    }
    fn authorize(&self, who: &Who, rule: &Role, _: &Request<'_>) -> Result<(), Denial> {
        if who.0 == Some(*rule) {
            Ok(())
        } else {
            Err(Denial::hidden("roles.hidden"))
        }
    }
}

/// F-4: a route the gate hides reads as missing for every method.
#[test]
fn test_f4_method_check_does_not_reveal_hidden_routes() {
    let app = App::with_gate(Roles)
        .route(get("/admin/users", |cx| cx.text(200, "users")).allow(Role::Admin))
        .route(get("/open", |cx| cx.text(200, "open")).public())
        .build()
        .unwrap();
    for m in ["GET", "PUT", "OPTIONS", "DELETE"] {
        let r = send(
            &app,
            &format!("{m} /admin/users HTTP/1.1\r\nHost: localhost"),
        );
        assert_eq!((r.status, r.header("allow")), (404, None), "{m} as a guest");
    }
    // The admin sees the method answers; a public route shows them to all.
    let r = send(
        &app,
        "PUT /admin/users HTTP/1.1\r\nHost: localhost\r\nCookie: sid=admin",
    );
    assert_eq!(r.status, 405);
    assert!(r.header("allow").is_some());
    assert_eq!(
        send(&app, "PUT /open HTTP/1.1\r\nHost: localhost").status,
        405
    );
}

/// F-5: with no host declared, only development hosts are the site.
#[test]
fn test_f5_no_host_declared_answers_development_hosts_only() {
    let app = App::builder()
        .route(get("/", |cx| cx.text(200, "x")))
        .build()
        .unwrap();
    for host in [
        "localhost",
        "127.0.0.1",
        "[::1]",
        "app.localhost",
        "localhost:8080",
    ] {
        let r = send(&app, &format!("GET / HTTP/1.1\r\nHost: {host}"));
        assert_eq!(r.status, 200, "{host}");
    }
    for host in ["rebind.attacker.example", "10.0.0.5", "example.com"] {
        let r = send(&app, &format!("GET / HTTP/1.1\r\nHost: {host}"));
        assert_eq!(r.status, 421, "{host}");
    }
    let any = App::builder()
        .any_host()
        .route(get("/", |cx| cx.text(200, "x")))
        .build()
        .unwrap();
    assert_eq!(
        send(&any, "GET / HTTP/1.1\r\nHost: anything.example").status,
        200
    );
}

/// F-6: an upper-case literal under `lowercase_paths` could never match.
#[test]
fn test_f6_uppercase_literal_with_lowercase_paths_does_not_build() {
    let err = App::builder()
        .lowercase_paths()
        .route(get("/About", |cx| cx.text(200, "x")))
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("lower case"), "{err}");
    // Parameters and lower-case literals are fine.
    assert!(
        App::builder()
            .lowercase_paths()
            .route(get("/about/:Name", |cx| cx.text(200, "x")))
            .build()
            .is_ok()
    );
}

/// F-7: `Context::url` builds links inside the site only.
#[test]
fn test_f7_url_refuses_other_hosts_and_url_path_encodes() {
    let app = App::builder()
        .route(get("/back", |cx| {
            let to = cx.query("to")?.unwrap_or_default();
            let link = cx.url(&to)?;
            cx.text(200, &link)
        }))
        .route(get("/tag", |cx| {
            let tag = cx.query("t")?.unwrap_or_default();
            cx.text(200, &cx.url_path(&["tags", &tag]))
        }))
        .build()
        .unwrap();
    for to in [
        "//evil.example/x",
        "/%5Cevil.example",
        "https://evil.example",
        "x",
    ] {
        let r = send(
            &app,
            &format!("GET /back?to={to} HTTP/1.1\r\nHost: localhost"),
        );
        assert_eq!(r.status, 500, "{to}");
    }
    let r = send(&app, "GET /back?to=/a/b HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.text(), "/a/b");
    let r = send(
        &app,
        "GET /tag?t=a%3Fb%23c%2F..%2Fd HTTP/1.1\r\nHost: localhost",
    );
    assert_eq!(r.text(), "/tags/a%3Fb%23c%2F..%2Fd");
}

/// F-8: compression keeps the handler's `Vary` and adds `accept-encoding`.
#[test]
fn test_f8_compression_adds_accept_encoding_to_vary() {
    let app = App::builder()
        .compress(web_net::Compression::default())
        .route(get("/", |cx| {
            cx.set_header("vary", "cookie");
            cx.html(200, &"<p>compress me</p>".repeat(200))
        }))
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip",
    );
    assert_eq!(r.header("content-encoding"), Some(&b"gzip"[..]));
    let vary = String::from_utf8_lossy(r.header("vary").unwrap_or(b"")).to_ascii_lowercase();
    assert!(
        vary.contains("cookie") && vary.contains("accept-encoding"),
        "{vary}"
    );
}

struct Deny(u16);
impl Checkpoint for Deny {
    fn check(&self, _: &Envelope, _: Stage) -> Verdict {
        Verdict::Deny { status: self.0 }
    }
}

/// F-10: a checkpoint cannot answer a revoked visitor with a success.
#[test]
fn test_f10_checkpoint_deny_status_is_clamped() {
    for (given, sent) in [(200, 403), (302, 403), (600, 403), (429, 429), (503, 503)] {
        let app = App::builder()
            .checkpoint(Deny(given))
            .route(get("/", |cx| cx.text(200, "x")))
            .build()
            .unwrap();
        assert_eq!(
            send(&app, "GET / HTTP/1.1\r\nHost: localhost").status,
            sent,
            "{given}"
        );
    }
}

/// F-11: a group's rule holds for every route in it; a route's own rule
/// adds to it, and a public route inside a group with a rule is refused.
#[test]
fn test_f11_group_rule_and_route_rule_both_hold() {
    let app = App::with_gate(Roles)
        .group(
            web_net::Group::at("/admin")
                .allow(Role::Admin)
                .route(get("/report", |cx| cx.text(200, "report")).allow(Role::Owner))
                .route(get("/plain", |cx| cx.text(200, "plain"))),
        )
        .build()
        .unwrap();
    // An owner who is not an admin does not get into the admin area.
    let r = send(
        &app,
        "GET /admin/report HTTP/1.1\r\nHost: localhost\r\nCookie: sid=owner",
    );
    assert_eq!(r.status, 404);
    // An admin who is not an owner does not get past the route's own rule.
    let r = send(
        &app,
        "GET /admin/report HTTP/1.1\r\nHost: localhost\r\nCookie: sid=admin",
    );
    assert_eq!(r.status, 404);
    let r = send(
        &app,
        "GET /admin/plain HTTP/1.1\r\nHost: localhost\r\nCookie: sid=admin",
    );
    assert_eq!(r.status, 200);

    let err = App::with_gate(Roles)
        .group(
            web_net::Group::at("/admin")
                .allow(Role::Admin)
                .route(get("/open", |cx| cx.text(200, "x")).public()),
        )
        .build()
        .unwrap_err();
    assert!(err.to_string().contains("public inside a group"), "{err}");
}

/// Several `Cookie` fields are one cookie header split into crumbs
/// (HTTP/2 and HTTP/3 send them so): read together, and a name in two of
/// them is as ambiguous as a name twice in one.
#[test]
fn test_cookie_fields_are_read_as_one() {
    let app = App::builder()
        .route(get("/", |cx| {
            let text = match cx.request().cookie("sid") {
                Ok(Some(v)) => format!("sid={v}"),
                Ok(None) => "none".to_owned(),
                Err(_) => "ambiguous".to_owned(),
            };
            cx.text(200, &text)
        }))
        .build()
        .unwrap();
    let at = |cookies: &str| {
        send(&app, &format!("GET / HTTP/1.1\r\nHost: localhost{cookies}"))
            .text()
            .to_owned()
    };
    assert_eq!(
        at("\r\nCookie: theme=dark\r\nCookie: sid=t0k3n"),
        "sid=t0k3n"
    );
    assert_eq!(
        at("\r\nCookie: sid=t0k3n\r\nCookie: theme=dark"),
        "sid=t0k3n"
    );
    assert_eq!(at("\r\nCookie: theme=dark\r\nCookie: lang=fr"), "none");
    assert_eq!(at("\r\nCookie: sid=a\r\nCookie: sid=b"), "ambiguous");
    assert_eq!(at("\r\nCookie: sid=a; sid=b"), "ambiguous");
    assert_eq!(at(""), "none");
}
