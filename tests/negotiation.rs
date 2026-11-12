//! Negotiation, CORS, compression, cache policies and the cacheability
//! report, hooks before render, and several sites.

use std::sync::Mutex;

use serve_net::testing::{TestReply, respond};
use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
use web_net::{
    App, CachePolicy, Cacheable, Compression, Context, Cors, Denial, Gate, Group, Hook, Identity,
    Output, Render, RenderError, Request, Routes, Served, TemplateId, Value, View, get, post,
};

fn send(app: &impl HttpService, raw: &str) -> TestReply {
    respond(app, format!("{raw}\r\n\r\n").as_bytes())
}

fn h<'a>(r: &'a TestReply, name: &str) -> &'a str {
    r.header(name)
        .map(|v| std::str::from_utf8(v).unwrap())
        .unwrap_or("")
}

#[test]
fn test_json_error_replies() {
    let app = App::builder()
        .route(get("/", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nAccept: application/json",
    );
    assert_eq!(r.status, 404);
    assert_eq!(h(&r, "content-type"), "application/json");
    assert!(
        r.text()
            .starts_with("{\"status\":404,\"title\":\"Not Found\""),
        "{}",
        r.text()
    );
    let r = send(
        &app,
        "GET /nope HTTP/1.1\r\nHost: localhost\r\nAccept: text/html, application/json;q=0.5",
    );
    assert_eq!(h(&r, "content-type"), "text/html; charset=utf-8");
    let r = send(&app, "GET /nope HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "content-type"), "text/html; charset=utf-8");
}

#[test]
fn test_language_and_media() {
    let app = App::builder()
        .route(
            get("/", |cx| {
                let lang = cx.accept_language(&["en", "fr"]).unwrap_or("en");
                let media = cx.accept(&["text/html", "application/json"]).unwrap_or("-");
                cx.text(200, &format!("{lang} {media}"))
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Language: fr-CA, en;q=0.5\r\nAccept: application/json",
    );
    assert_eq!(r.text(), "fr application/json");
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!(r.text(), "en text/html");
}

fn api() -> App {
    App::builder()
        .group(
            Group::at("/api")
                .public()
                .cors(
                    Cors::new()
                        .origin("https://app.example")
                        .headers(&["content-type"])
                        .credentials()
                        .max_age(60),
                )
                .route(get("/items", |cx| cx.text(200, "items")))
                .route(post("/items", |cx| cx.text(201, "made")).csrf_exempt("bearer API")),
        )
        .route(get("/private", |cx| cx.text(200, "p")).public())
        .build()
        .unwrap()
}

#[test]
fn test_cors_preflight() {
    let app = api();
    let r = send(
        &app,
        "OPTIONS /api/items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: Content-Type",
    );
    assert_eq!(r.status, 204);
    assert_eq!(h(&r, "access-control-allow-origin"), "https://app.example");
    assert_eq!(h(&r, "access-control-allow-methods"), "GET, HEAD, POST");
    assert_eq!(h(&r, "access-control-allow-headers"), "content-type");
    assert_eq!(h(&r, "access-control-allow-credentials"), "true");
    assert_eq!(h(&r, "access-control-max-age"), "60");
    assert_eq!(h(&r, "vary"), "origin");

    for bad in [
        "Origin: https://evil.example\r\nAccess-Control-Request-Method: POST",
        "Origin: https://app.example\r\nAccess-Control-Request-Method: DELETE",
        "Origin: https://app.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: x-secret",
    ] {
        let r = send(
            &app,
            &format!("OPTIONS /api/items HTTP/1.1\r\nHost: localhost\r\n{bad}"),
        );
        assert_eq!(r.status, 204, "{bad}");
        assert_eq!(h(&r, "access-control-allow-origin"), "", "{bad}");
    }
    // A route without a policy answers no preflight.
    let r = send(
        &app,
        "OPTIONS /private HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_cors_actual_replies() {
    let app = api();
    let r = send(
        &app,
        "GET /api/items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "https://app.example");
    assert_eq!(h(&r, "access-control-allow-credentials"), "true");
    let r = send(
        &app,
        "GET /api/items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://evil.example",
    );
    assert_eq!(
        (h(&r, "access-control-allow-origin"), h(&r, "vary")),
        ("", "origin")
    );
    let r = send(
        &app,
        "GET /private HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_preflight_lists_only_methods_under_the_policy() {
    let app = App::builder()
        .route(
            get("/items", |cx| cx.text(200, "items"))
                .public()
                .cors(Cors::new().origin("https://app.example")),
        )
        .route(
            web_net::delete("/items", |cx| cx.text(200, "gone"))
                .public()
                .csrf_exempt("test"),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "OPTIONS /items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET",
    );
    assert_eq!(h(&r, "access-control-allow-methods"), "GET, HEAD");
    let r = send(
        &app,
        "OPTIONS /items HTTP/1.1\r\nHost: localhost\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: DELETE",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_cors_policy_checked_at_build() {
    let e = App::builder()
        .route(
            get("/", |cx| cx.text(200, "x"))
                .public()
                .cors(Cors::new().any_origin().credentials()),
        )
        .build()
        .unwrap_err();
    assert_eq!(e.problems().len(), 1);
}

#[test]
fn test_compression() {
    let page = "<p>hello, compressible world</p>".repeat(100);
    let small = "tiny".to_owned();
    let app = App::builder()
        .compress(Compression::default())
        .route(get("/", move |cx| cx.html(200, &page)).public())
        .route(get("/small", move |cx| cx.html(200, &small)).public())
        .route(get("/png", |cx| cx.bytes(200, "image/png", &[0u8; 4096])).public())
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip, br",
    );
    assert_eq!(
        (h(&r, "content-encoding"), h(&r, "vary")),
        ("gzip", "accept-encoding")
    );
    let plain = compress_lib::gzip::decompress(&r.body).unwrap();
    assert_eq!(
        plain,
        "<p>hello, compressible world</p>".repeat(100).as_bytes()
    );
    assert!(r.body.len() < 400);
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!(
        (h(&r, "content-encoding"), h(&r, "vary")),
        ("", "accept-encoding")
    );
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip;q=0",
    );
    assert_eq!(h(&r, "content-encoding"), "");
    let r = send(
        &app,
        "GET /small HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip",
    );
    assert_eq!(h(&r, "content-encoding"), "");
    let r = send(
        &app,
        "GET /png HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: gzip",
    );
    assert_eq!((h(&r, "content-encoding"), h(&r, "vary")), ("", ""));
}

struct Member {
    signed_in: bool,
}

impl Identity for Member {
    fn is_guest(&self) -> bool {
        !self.signed_in
    }
}

struct CookieGate;

impl Gate for CookieGate {
    type Identity = Member;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Member, Denial> {
        Ok(Member {
            signed_in: req.cookie("sid").ok().flatten().is_some(),
        })
    }
    fn authorize(&self, _: &Member, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Ok(())
    }
}

struct Front {
    app: App<CookieGate>,
    seen: Mutex<Vec<Served>>,
}

impl HttpService for Front {
    fn call(&self, request: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        let served = self.app.respond(request, env, None, reply);
        self.seen.lock().unwrap().push(served);
        served.outcome
    }
}

#[test]
fn test_cache_policy_and_report() {
    let front = Front {
        app: App::with_gate(CookieGate)
            .route(
                get("/news", |cx: &mut Context<'_, Member>| cx.text(200, "news"))
                    .public()
                    .cache(CachePolicy::Guests { max_age: 120 }),
            )
            .route(
                get("/cookie", |cx: &mut Context<'_, Member>| {
                    cx.set_header("set-cookie", "a=1");
                    cx.text(200, "c")
                })
                .public()
                .cache(CachePolicy::Guests { max_age: 120 }),
            )
            .route(
                get("/me", |cx: &mut Context<'_, Member>| cx.text(200, "me"))
                    .public()
                    .cache(CachePolicy::NoStore),
            )
            .route(
                get("/own", |cx: &mut Context<'_, Member>| {
                    cx.set_header("cache-control", "max-age=5");
                    cx.text(200, "own")
                })
                .public()
                .cache(CachePolicy::Public { max_age: 60 }),
            )
            .build()
            .unwrap(),
        seen: Mutex::new(Vec::new()),
    };
    let r = send(&front, "GET /news HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "cache-control"), "public, max-age=120");
    let r = send(
        &front,
        "GET /news HTTP/1.1\r\nHost: localhost\r\nCookie: sid=x",
    );
    assert_eq!(h(&r, "cache-control"), "private, no-store");
    // A reply with a cookie is never public, whatever the policy says.
    let r = send(&front, "GET /cookie HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "cache-control"), "private, no-store");
    let r = send(&front, "GET /me HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "cache-control"), "no-store");
    let r = send(&front, "GET /own HTTP/1.1\r\nHost: localhost");
    assert_eq!(h(&r, "cache-control"), "max-age=5");
    let _ = send(&front, "GET /missing HTTP/1.1\r\nHost: localhost");
    let seen = front.seen.lock().unwrap();
    let caches: Vec<Cacheable> = seen.iter().map(|s| s.cache).collect();
    assert_eq!(
        caches,
        [
            Cacheable::Guests { max_age: 120 },
            Cacheable::No,
            Cacheable::No,
            Cacheable::No,
            // The handler set its own Cache-Control: not the policy's
            // public value, so never reported keepable.
            Cacheable::No,
            Cacheable::No,
        ]
    );
    assert!(seen[0].route.is_some() && seen[5].route.is_none());
}

/// Writes the view's `variant` and `title`.
struct Two;

impl Render for Two {
    type View<'a> = dyn View + 'a;

    fn template(&self, name: &str) -> Option<TemplateId> {
        match name {
            "a" => Some(TemplateId(0)),
            "b" => Some(TemplateId(1)),
            _ => None,
        }
    }
    fn render(
        &self,
        t: TemplateId,
        view: &(dyn View + '_),
        out: &mut Output<'_>,
    ) -> Result<(), RenderError> {
        let title = view.shape().key("title").map(|k| view.get(k));
        let Some(Value::Text(title)) = title else {
            return Err(RenderError::new("two.title"));
        };
        out.write_str(if t.0 == 0 { "A:" } else { "B:" })?;
        out.write_str(title)
    }
}

#[test]
fn test_before_render_hook() {
    let app = App::builder()
        .render(Two)
        .hook(Hook::BeforeRender, Routes::all(), |cx| {
            cx.set_header("x-rendered", "1");
            Ok(())
        })
        .route(
            get("/", |cx| {
                cx.render_view(&web_net::Fields(&[("title", Value::Text("t"))]))
            })
            .public()
            .template("a"),
        )
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.text(), h(&r, "x-rendered")), ("A:t", "1"));
}

#[test]
fn test_sites_pick_by_host_and_base() {
    let mk = |host: Option<&str>, base: &str, text: &'static str| {
        let mut b = App::builder();
        b = match host {
            Some(h) => b.host(h),
            // The fallback answers any host, as a catch-all must say.
            None => b.any_host(),
        };
        b.base(base)
            .route(get("/", move |cx| cx.text(200, text)).public())
            .build()
            .unwrap()
    };
    let sites = web_net::Sites::new()
        .site(mk(None, "", "fallback"))
        .site(mk(Some("example.com"), "", "root"))
        .site(mk(Some("example.com"), "/blog", "blog"))
        .site(mk(Some("example.com"), "/blog/deep", "deep"));
    let at = |host: &str, path: &str| {
        send(&sites, &format!("GET {path} HTTP/1.1\r\nHost: {host}"))
            .text()
            .to_owned()
    };
    assert_eq!(at("example.com", "/"), "root");
    assert_eq!(at("example.com", "/blog/"), "blog");
    assert_eq!(at("example.com", "/blog/deep/"), "deep");
    // Not the blog's: the root site answers it (and has no such page).
    assert!(at("example.com", "/blogger").contains("Not Found"));
    assert_eq!(at("other.example", "/"), "fallback");
}

#[test]
fn test_sites_lowercase_site_claims_its_upper_case_paths() {
    let main = App::builder()
        .route(get("/", |cx| cx.text(200, "main")).public())
        .build()
        .unwrap();
    let blog = App::builder()
        .base("/blog")
        .lowercase_paths()
        .route(get("/x", |cx| cx.text(200, "x")).public())
        .build()
        .unwrap();
    let sites = web_net::Sites::new().site(main).site(blog);
    let r = send(&sites, "GET /BLOG/X HTTP/1.1\r\nHost: localhost");
    assert_eq!((r.status, h(&r, "location")), (301, "/blog/x"));
}
