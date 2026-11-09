//! Negotiation, CORS, compression, cache policies and the cacheability
//! report, hooks before render, and several sites.

use std::sync::Mutex;

use serve_net::testing::{TestReply, respond};
use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
use web_net::{
    App, CachePolicy, Cacheable, Compression, Cors, Cx, Denial, Gate, Group, Hook, Identity,
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
        .route(
            get("/", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET /nope HTTP/1.1\r\nHost: a\r\nAccept: application/json",
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
        "GET /nope HTTP/1.1\r\nHost: a\r\nAccept: text/html, application/json;q=0.5",
    );
    assert_eq!(h(&r, "content-type"), "text/html; charset=utf-8");
    let r = send(&app, "GET /nope HTTP/1.1\r\nHost: a");
    assert_eq!(h(&r, "content-type"), "text/html; charset=utf-8");
}

#[test]
fn test_language_and_media() {
    let app = App::builder()
        .route(
            get("/", |cx| {
                let lang = cx.language(&["en", "fr"]).unwrap_or("en");
                let media = cx.media(&["text/html", "application/json"]).unwrap_or("-");
                cx.text(200, &format!("{lang} {media}"));
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: a\r\nAccept-Language: fr-CA, en;q=0.5\r\nAccept: application/json",
    );
    assert_eq!(r.text(), "fr application/json");
    let r = send(&app, "GET / HTTP/1.1\r\nHost: a");
    assert_eq!(r.text(), "en text/html");
}

fn api() -> App {
    App::builder()
        .group(
            Group::new("/api")
                .public()
                .cors(
                    Cors::new()
                        .origin("https://app.example")
                        .headers(&["content-type"])
                        .credentials()
                        .max_age(60),
                )
                .route(get("/items", |cx| {
                    cx.text(200, "items");
                    Ok(())
                }))
                .route(
                    post("/items", |cx| {
                        cx.text(201, "made");
                        Ok(())
                    })
                    .csrf_exempt("bearer API"),
                ),
        )
        .route(
            get("/private", |cx| {
                cx.text(200, "p");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap()
}

#[test]
fn test_cors_preflight() {
    let app = api();
    let r = send(
        &app,
        "OPTIONS /api/items HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: Content-Type",
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
            &format!("OPTIONS /api/items HTTP/1.1\r\nHost: a\r\n{bad}"),
        );
        assert_eq!(r.status, 204, "{bad}");
        assert_eq!(h(&r, "access-control-allow-origin"), "", "{bad}");
    }
    // A route without a policy answers no preflight.
    let r = send(
        &app,
        "OPTIONS /private HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_cors_actual_replies() {
    let app = api();
    let r = send(
        &app,
        "GET /api/items HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "https://app.example");
    assert_eq!(h(&r, "access-control-allow-credentials"), "true");
    let r = send(
        &app,
        "GET /api/items HTTP/1.1\r\nHost: a\r\nOrigin: https://evil.example",
    );
    assert_eq!(
        (h(&r, "access-control-allow-origin"), h(&r, "vary")),
        ("", "origin")
    );
    let r = send(
        &app,
        "GET /private HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_preflight_lists_only_methods_under_the_policy() {
    let app = App::builder()
        .route(
            get("/items", |cx| {
                cx.text(200, "items");
                Ok(())
            })
            .public()
            .cors(Cors::new().origin("https://app.example")),
        )
        .route(
            web_net::delete("/items", |cx| {
                cx.text(200, "gone");
                Ok(())
            })
            .public()
            .csrf_exempt("test"),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "OPTIONS /items HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: GET",
    );
    assert_eq!(h(&r, "access-control-allow-methods"), "GET, HEAD");
    let r = send(
        &app,
        "OPTIONS /items HTTP/1.1\r\nHost: a\r\nOrigin: https://app.example\r\nAccess-Control-Request-Method: DELETE",
    );
    assert_eq!(h(&r, "access-control-allow-origin"), "");
}

#[test]
fn test_cors_policy_checked_at_build() {
    let e = App::builder()
        .route(
            get("/", |cx| {
                cx.text(200, "x");
                Ok(())
            })
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
        .route(
            get("/", move |cx| {
                cx.html(200, &page);
                Ok(())
            })
            .public(),
        )
        .route(
            get("/small", move |cx| {
                cx.html(200, &small);
                Ok(())
            })
            .public(),
        )
        .route(
            get("/png", |cx| {
                cx.set_header("content-type", "image/png");
                cx.body_bytes(&[0u8; 4096]);
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip, br",
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
    let r = send(&app, "GET / HTTP/1.1\r\nHost: a");
    assert_eq!(
        (h(&r, "content-encoding"), h(&r, "vary")),
        ("", "accept-encoding")
    );
    let r = send(
        &app,
        "GET / HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip;q=0",
    );
    assert_eq!(h(&r, "content-encoding"), "");
    let r = send(
        &app,
        "GET /small HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip",
    );
    assert_eq!(h(&r, "content-encoding"), "");
    let r = send(
        &app,
        "GET /png HTTP/1.1\r\nHost: a\r\nAccept-Encoding: gzip",
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
        let served = self.app.serve(request, env, None, reply);
        self.seen.lock().unwrap().push(served);
        served.outcome
    }
}

#[test]
fn test_cache_policy_and_report() {
    let front = Front {
        app: App::with_gate(CookieGate)
            .route(
                get("/news", |cx: &mut Cx<'_, Member>| {
                    cx.text(200, "news");
                    Ok(())
                })
                .public()
                .cache(CachePolicy::Guests { max_age: 120 }),
            )
            .route(
                get("/cookie", |cx: &mut Cx<'_, Member>| {
                    cx.set_header("set-cookie", "a=1");
                    cx.text(200, "c");
                    Ok(())
                })
                .public()
                .cache(CachePolicy::Guests { max_age: 120 }),
            )
            .route(
                get("/me", |cx: &mut Cx<'_, Member>| {
                    cx.text(200, "me");
                    Ok(())
                })
                .public()
                .cache(CachePolicy::NoStore),
            )
            .route(
                get("/own", |cx: &mut Cx<'_, Member>| {
                    cx.set_header("cache-control", "max-age=5");
                    cx.text(200, "own");
                    Ok(())
                })
                .public()
                .cache(CachePolicy::Public { max_age: 60 }),
            )
            .build()
            .unwrap(),
        seen: Mutex::new(Vec::new()),
    };
    let r = send(&front, "GET /news HTTP/1.1\r\nHost: a");
    assert_eq!(h(&r, "cache-control"), "public, max-age=120");
    let r = send(&front, "GET /news HTTP/1.1\r\nHost: a\r\nCookie: sid=x");
    assert_eq!(h(&r, "cache-control"), "private, no-store");
    // A reply with a cookie is never public, whatever the policy says.
    let r = send(&front, "GET /cookie HTTP/1.1\r\nHost: a");
    assert_eq!(h(&r, "cache-control"), "private, no-store");
    let r = send(&front, "GET /me HTTP/1.1\r\nHost: a");
    assert_eq!(h(&r, "cache-control"), "no-store");
    let r = send(&front, "GET /own HTTP/1.1\r\nHost: a");
    assert_eq!(h(&r, "cache-control"), "max-age=5");
    let _ = send(&front, "GET /missing HTTP/1.1\r\nHost: a");
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
        view: &dyn View,
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
                cx.render(&web_net::Fields(&[("title", Value::Text("t"))]))
            })
            .public()
            .template("a"),
        )
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: a");
    assert_eq!((r.text(), h(&r, "x-rendered")), ("A:t", "1"));
}

#[test]
fn test_sites_pick_by_host_and_base() {
    let mk = |host: Option<&str>, base: &str, text: &'static str| {
        let mut b = App::builder();
        if let Some(h) = host {
            b = b.host(h);
        }
        b.base(base)
            .route(
                get("/", move |cx| {
                    cx.text(200, text);
                    Ok(())
                })
                .public(),
            )
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
