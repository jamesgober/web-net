//! The request pipeline end to end, driven in memory through serve-net's
//! testing helpers: no sockets.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use serve_net::testing::{TestReply, TestRequest, respond};
use serve_net::{Envelope, Scheme, Verdict};
use web_net::{
    App, Checkpoint, Cx, Denial, Error, Event, EventKind, Events, Gate, Group, Hook, Identity,
    Output, Render, RenderError, Request, Route, Routes, Stage, TemplateId, TrailingSlash, Value,
    View, get, post,
};

fn req(app: &impl serve_net::HttpService, raw: &str) -> TestReply {
    respond(app, raw.as_bytes())
}

fn get_req(app: &impl serve_net::HttpService, path: &str) -> TestReply {
    req(app, &format!("GET {path} HTTP/1.1\r\nHost: a.test\r\n\r\n"))
}

fn loc(r: &TestReply) -> &str {
    r.header("location")
        .map(|v| std::str::from_utf8(v).unwrap())
        .unwrap_or("")
}

fn hello() -> App {
    App::builder()
        .route(
            get("/", |cx| {
                cx.text(200, "home");
                Ok(())
            })
            .public(),
        )
        .route(
            Route::at("/form")
                .get(|cx| {
                    cx.text(200, "form");
                    Ok(())
                })
                .post(|cx| cx.see_other("/form/done"))
                .public()
                .csrf_exempt("pipeline tests have no sessions; CSRF is tested in tests/actions.rs"),
        )
        .route(
            get("/users/:id", |cx| {
                let id: u32 = cx.param_as("id")?;
                cx.text(200, &format!("user {id}"));
                Ok(())
            })
            .public(),
        )
        .route(
            get("/files/*rest", |cx| {
                let rest = cx.param("rest").unwrap_or_default().into_owned();
                cx.text(200, &rest);
                Ok(())
            })
            .public(),
        )
        .route(
            get("/q", |cx| {
                let v = cx.query("v")?.unwrap_or_default().into_owned();
                cx.text(200, &v);
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap()
}

// ---------------------------------------------------------------- routing

#[test]
fn test_routes_and_params() {
    let app = hello();
    assert_eq!(get_req(&app, "/").text(), "home");
    assert_eq!(get_req(&app, "/users/42").text(), "user 42");
    assert_eq!(get_req(&app, "/users/x").status, 404);
    assert_eq!(get_req(&app, "/files/a/b%20c.txt").text(), "a/b c.txt");
    assert_eq!(get_req(&app, "/nope").status, 404);
}

#[test]
fn test_method_rules() {
    let app = hello();
    let r = req(&app, "DELETE /form HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow"), Some(&b"GET, HEAD, POST, OPTIONS"[..]));

    let r = req(&app, "OPTIONS /form HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.status, 204);
    assert_eq!(r.header("allow"), Some(&b"GET, HEAD, POST, OPTIONS"[..]));

    let r = req(&app, "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.status, 204);

    let r = req(&app, "BREW /form HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.status, 501);

    let r = req(
        &app,
        "POST /form HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!((r.status, loc(&r)), (303, "/form/done"));
}

#[test]
fn test_head_follows_get_without_body() {
    let app = hello();
    let g = get_req(&app, "/");
    let h = req(&app, "HEAD / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(h.status, 200);
    assert!(h.body.is_empty(), "HEAD carries no body");
    assert_eq!(h.header("content-length"), g.header("content-length"));
}

#[test]
fn test_query() {
    let app = hello();
    assert_eq!(get_req(&app, "/q?v=a+b%21").text(), "a b!");
    assert_eq!(get_req(&app, "/q?v=1&v=2").status, 400);
    assert_eq!(get_req(&app, "/q?v=%ff").status, 400);
    assert_eq!(get_req(&app, "/q").text(), "");
}

// ---------------------------------------------------------------- urls

#[test]
fn test_canonical_redirects() {
    let app = hello();
    for (from, to) in [
        ("/users/7/", "/users/7"),
        ("//users///7", "/users/7"),
        ("/users/./7", "/users/7"),
        ("/x/../users/7", "/users/7"),
        ("/%75sers/7", "/users/7"),
        ("/q/?v=1", "/q?v=1"),
    ] {
        let r = get_req(&app, from);
        assert_eq!((r.status, loc(&r)), (301, to), "{from}");
    }
    let r = req(
        &app,
        "POST /form/ HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n",
    );
    assert_eq!((r.status, loc(&r)), (308, "/form"));
}

#[test]
fn test_refused_paths() {
    let app = hello();
    for p in ["/files/a%2Fb", "/files/a%00", "/files/%5c..", "/files/%ff"] {
        assert_eq!(get_req(&app, p).status, 400, "{p}");
    }
}

#[test]
fn test_trailing_slash_policies() {
    let mk = |p| {
        App::builder()
            .trailing_slash(p)
            .route(
                get("/a", |cx| {
                    cx.text(200, "a");
                    Ok(())
                })
                .public(),
            )
            .route(
                get("/s.css", |cx| {
                    cx.text(200, "css");
                    Ok(())
                })
                .public(),
            )
            .build()
            .unwrap()
    };
    let add = mk(TrailingSlash::Add);
    let r = get_req(&add, "/a");
    assert_eq!((r.status, loc(&r)), (301, "/a/"));
    assert_eq!(get_req(&add, "/a/").text(), "a");
    assert_eq!(get_req(&add, "/s.css").text(), "css");
    // A file-like path has one spelling under Add too: no slash.
    let r = get_req(&add, "/s.css/");
    assert_eq!((r.status, loc(&r)), (301, "/s.css"));

    let ignore = mk(TrailingSlash::Ignore);
    assert_eq!(get_req(&ignore, "/a").text(), "a");
    assert_eq!(get_req(&ignore, "/a/").text(), "a");
}

#[test]
fn test_lowercase_paths() {
    let app = App::builder()
        .lowercase_paths()
        .route(
            get("/about", |cx| {
                cx.text(200, "about");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = get_req(&app, "/About");
    assert_eq!((r.status, loc(&r)), (301, "/about"));
}

// ---------------------------------------------------------------- sites

fn site() -> App {
    App::builder()
        .host("example.com")
        .alias("www.example.com")
        .base("/blog")
        .route(
            get("/", |cx| {
                cx.text(200, &cx.url("/"));
                Ok(())
            })
            .public(),
        )
        .route(get("/post", |cx| cx.see_other("/")).public())
        .build()
        .unwrap()
}

fn host(app: &App, h: &str, path: &str) -> TestReply {
    req(app, &format!("GET {path} HTTP/1.1\r\nHost: {h}\r\n\r\n"))
}

#[test]
fn test_site_in_a_folder() {
    let app = site();
    assert_eq!(host(&app, "example.com", "/blog/").text(), "/blog/");
    let r = host(&app, "example.com", "/blog");
    assert_eq!((r.status, loc(&r)), (301, "/blog/"));
    assert_eq!(loc(&host(&app, "example.com", "/blog/post")), "/blog/");
    assert_eq!(host(&app, "example.com", "/other").status, 404);
    assert_eq!(host(&app, "example.com", "/blogger").status, 404);
}

#[test]
fn test_hosts() {
    let app = site();
    assert_eq!(host(&app, "EXAMPLE.com", "/blog/").status, 200);
    assert_eq!(host(&app, "example.com.", "/blog/").status, 200);
    assert_eq!(host(&app, "example.com:8443", "/blog/").status, 200);
    let r = host(&app, "www.example.com", "/blog/post?x=1");
    assert_eq!(
        (r.status, loc(&r)),
        (301, "http://example.com/blog/post?x=1")
    );
    assert_eq!(host(&app, "evil.example", "/blog/").status, 421);
    assert_eq!(host(&app, "localhost", "/blog/").status, 421);
}

#[test]
fn test_development_hosts() {
    let app = App::builder()
        .host("example.com")
        .development()
        .https_only()
        .route(
            get("/", |cx| {
                cx.text(200, "ok");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    for h in ["localhost:8080", "127.0.0.1", "[::1]:3000", "app.localhost"] {
        assert_eq!(host(&app, h, "/").status, 200, "{h}");
    }
    // A real host over plain HTTP still goes to HTTPS.
    let r = host(&app, "example.com", "/");
    assert_eq!((r.status, loc(&r)), (301, "https://example.com/"));
}

#[test]
fn test_https_only() {
    let app = App::builder()
        .host("example.com")
        .https_only()
        .route(
            get("/", |cx| {
                cx.text(200, "ok");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = host(&app, "example.com", "/?a=b");
    assert_eq!(loc(&r), "https://example.com/?a=b");
    let r = TestRequest::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .scheme(Scheme::Https)
        .send(&app);
    assert_eq!(r.status, 200);
}

// ---------------------------------------------------------------- gates

struct User {
    name: &'static str,
}

impl Identity for User {
    fn is_guest(&self) -> bool {
        self.name.is_empty()
    }
}

enum Rule {
    SignedIn,
    Admin,
    Hidden,
}

struct Demo {
    authenticated: AtomicU32,
}

impl Gate for Demo {
    type Identity = User;
    type Rule = Rule;

    fn authenticate(&self, req: &Request<'_>) -> Result<User, Denial> {
        self.authenticated.fetch_add(1, Ordering::Relaxed);
        match req.cookie("sid") {
            Ok(Some("banned")) => Err(Denial::forbidden("demo.banned")),
            Ok(Some("admin")) => Ok(User { name: "admin" }),
            Ok(Some("ann")) => Ok(User { name: "ann" }),
            Ok(_) => Ok(User { name: "" }),
            Err(_) => Err(Denial::status(400, "demo.cookie_twice")),
        }
    }

    fn authorize(&self, who: &User, rule: &Rule, req: &Request<'_>) -> Result<(), Denial> {
        assert!(req.route().is_some());
        match rule {
            Rule::SignedIn if !who.is_guest() => Ok(()),
            Rule::SignedIn => Err(Denial::sign_in("demo.guest")),
            Rule::Admin if who.name == "admin" => Ok(()),
            Rule::Admin => Err(Denial::forbidden("demo.not_admin")),
            Rule::Hidden => Err(Denial::hidden("demo.hidden")),
        }
    }
}

#[derive(Default)]
struct Log(Mutex<Vec<(EventKind, u16, &'static str)>>);

impl Events for &'static Log {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push((e.kind, e.status, e.code));
    }
}

fn gated(log: &'static Log) -> App<Demo> {
    App::with_gate(Demo {
        authenticated: AtomicU32::new(0),
    })
    .sign_in("/login")
    .events(log)
    .route(
        get("/", |cx: &mut Cx<'_, User>| {
            let who = cx.identity().name;
            cx.text(200, if who.is_empty() { "guest" } else { who });
            Ok(())
        })
        .public(),
    )
    .route(
        get("/account", |cx: &mut Cx<'_, User>| {
            cx.text(200, cx.identity().name);
            Ok(())
        })
        .allow(Rule::SignedIn),
    )
    .route(
        post("/account", |cx| cx.see_other("/account"))
            .allow(Rule::SignedIn)
            .csrf_exempt("gate tests; CSRF is tested in tests/actions.rs"),
    )
    .group(
        Group::new("/admin")
            .allow(Rule::Admin)
            .route(get("/", |cx| {
                cx.text(200, "panel");
                Ok(())
            }))
            .route(
                get("/open", |cx| {
                    cx.text(200, "open");
                    Ok(())
                })
                .public(),
            ),
    )
    .route(
        get("/secret", |cx| {
            cx.text(200, "x");
            Ok(())
        })
        .allow(Rule::Hidden),
    )
    .build()
    .unwrap()
}

fn as_user(app: &App<Demo>, method: &str, path: &str, sid: Option<&str>) -> TestReply {
    let cookie = sid
        .map(|s| format!("Cookie: sid={s}\r\n"))
        .unwrap_or_default();
    req(
        app,
        &format!("{method} {path} HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n{cookie}\r\n"),
    )
}

#[test]
fn test_gate_authenticates_and_authorizes() {
    let log: &'static Log = Box::leak(Box::default());
    let app = gated(log);
    assert_eq!(as_user(&app, "GET", "/", None).text(), "guest");
    assert_eq!(as_user(&app, "GET", "/", Some("ann")).text(), "ann");
    assert_eq!(as_user(&app, "GET", "/account", Some("ann")).text(), "ann");
    assert_eq!(
        as_user(&app, "GET", "/admin", Some("admin")).text(),
        "panel"
    );
    assert_eq!(as_user(&app, "GET", "/admin", Some("ann")).status, 403);
    assert_eq!(as_user(&app, "GET", "/admin/open", None).text(), "open");
    assert_eq!(as_user(&app, "GET", "/secret", Some("admin")).status, 404);
    assert_eq!(as_user(&app, "GET", "/", Some("banned")).status, 403);
    let r = req(
        &app,
        "GET / HTTP/1.1\r\nHost: a\r\nCookie: sid=ann; sid=admin\r\n\r\n",
    );
    assert_eq!(r.status, 400);
    let r = req(
        &app,
        "GET / HTTP/1.1\r\nHost: a\r\nCookie: sid=ann\r\nCookie: x=1\r\n\r\n",
    );
    assert_eq!(r.status, 400);

    let codes: Vec<_> = log.0.lock().unwrap().iter().map(|e| e.2).collect();
    for c in [
        "demo.not_admin",
        "demo.hidden",
        "demo.banned",
        "demo.cookie_twice",
    ] {
        assert!(codes.contains(&c), "{c} in {codes:?}");
    }
}

#[test]
fn test_sign_in_redirect_and_challenge() {
    let log: &'static Log = Box::leak(Box::default());
    let app = gated(log);
    let r = as_user(&app, "GET", "/account?tab=1", None);
    assert_eq!((r.status, loc(&r)), (303, "/login?next=/account%3Ftab%3D1"));
    let r = as_user(&app, "POST", "/account", None);
    assert_eq!(r.status, 401);
    assert_eq!(r.header("www-authenticate"), Some(&b"Session"[..]));
}

#[test]
fn test_respond_identified_skips_authentication() {
    struct Core(App<Demo>);
    impl serve_net::HttpService for Core {
        fn call(
            &self,
            request: &serve_net::HttpRequest<'_>,
            env: &Envelope,
            reply: &mut serve_net::HttpReply,
        ) -> serve_net::Outcome {
            self.0
                .respond_identified(request, env, &User { name: "admin" }, reply)
        }
    }
    let log: &'static Log = Box::leak(Box::default());
    let core = Core(gated(log));
    let r = req(
        &core,
        "GET /admin HTTP/1.1\r\nHost: a\r\nCookie: sid=banned\r\n\r\n",
    );
    assert_eq!(r.text(), "panel");
    assert_eq!(core.0.gate().authenticated.load(Ordering::Relaxed), 0);
}

#[test]
fn test_build_refuses_undeclared_access() {
    let e = App::builder()
        .route(get("/", |cx| {
            cx.text(200, "x");
            Ok(())
        }))
        .route(
            get("/b", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .route(
            get("/b", |cx| {
                cx.text(200, "y");
                Ok(())
            })
            .public(),
        )
        .route(
            get("bad", |cx| {
                cx.text(200, "y");
                Ok(())
            })
            .public(),
        )
        .route(Route::at("/none").public())
        .route(
            get("/t", |cx| {
                cx.text(200, "y");
                Ok(())
            })
            .public()
            .template("page"),
        )
        .base("blog")
        .https_only()
        .build()
        .unwrap_err();
    let subjects: Vec<&str> = e.problems().iter().map(|p| p.subject.as_str()).collect();
    assert_eq!(e.problems().len(), 7, "{e}");
    for s in ["/", "GET /b", "bad", "/none", "/t", "base", "https_only"] {
        assert!(subjects.contains(&s), "{s} in {subjects:?}");
    }
}

// ---------------------------------------------------------------- errors

#[test]
fn test_errors_replace_the_reply() {
    let log: &'static Log = Box::leak(Box::default());
    let app = App::builder()
        .events(log)
        .route(
            get("/fail", |cx| {
                cx.set_header("set-cookie", "leak=1");
                Err(Error::internal("demo.db").with_source(std::io::Error::other("disk")))
            })
            .public(),
        )
        .route(
            get("/panic", |cx| {
                cx.set_header("set-cookie", "leak=1");
                panic!("handler bug");
            })
            .public(),
        )
        .route(
            get("/badfield", |cx| {
                cx.set_header("x", "a\r\nb");
                Ok(())
            })
            .public(),
        )
        .route(
            get("/framing", |cx| {
                cx.set_header("content-length", "9");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    for (p, kind, code) in [
        ("/fail", EventKind::Failed, "demo.db"),
        ("/panic", EventKind::Panicked, "handler.panic"),
        ("/badfield", EventKind::Failed, "reply.invalid_field"),
        ("/framing", EventKind::Failed, "reply.invalid_field"),
    ] {
        let r = get_req(&app, p);
        assert_eq!(r.status, 500, "{p}");
        assert!(r.header("set-cookie").is_none(), "{p}");
        let text = r.text();
        assert!(text.contains("Reference: "), "{p}");
        assert!(!text.contains("disk") && !text.contains("demo.") && !text.contains("bug"));
        let last = *log.0.lock().unwrap().last().unwrap();
        assert_eq!(last, (kind, 500, code), "{p}");
    }
    let r = get_req(&app, "/nope");
    assert_eq!(r.header("cache-control"), Some(&b"no-store"[..]));
}

// ---------------------------------------------------------------- hooks

#[test]
fn test_hooks_run_for_their_routes_only() {
    let app = App::builder()
        .hook(Hook::Routed, Routes::prefix("/blog"), |cx| {
            if cx.query("stop")?.is_some() {
                return Err(Error::forbidden("hook.stop"));
            }
            Ok(())
        })
        .hook(Hook::Finish, Routes::named(&["home"]), |cx| {
            cx.set_header("x-home", "1");
            Ok(())
        })
        .route(
            get("/", |cx| {
                cx.text(200, "home");
                Ok(())
            })
            .public()
            .name("home"),
        )
        .route(
            get("/blog/:slug", |cx| {
                cx.text(200, "post");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    assert_eq!(get_req(&app, "/").header("x-home"), Some(&b"1"[..]));
    assert!(get_req(&app, "/blog/a").header("x-home").is_none());
    assert_eq!(get_req(&app, "/blog/a?stop=1").status, 403);
    assert_eq!(get_req(&app, "/?stop=1").status, 200);
}

// ---------------------------------------------------------------- render

/// A test engine: template 0 writes `<h1>{title}</h1>`, escaping `<`;
/// `error/404` writes `missing {reference}`.
struct Mini;

impl Render for Mini {
    fn template(&self, name: &str) -> Option<TemplateId> {
        match name {
            "page" => Some(TemplateId(0)),
            "error/404" => Some(TemplateId(1)),
            _ => None,
        }
    }

    fn render(
        &self,
        t: TemplateId,
        view: &dyn View,
        out: &mut Output<'_>,
    ) -> Result<(), RenderError> {
        let field = |name| view.shape().key(name).map(|k| view.get(k));
        match t.0 {
            0 => {
                let Some(Value::Text(title)) = field("title") else {
                    return Err(RenderError::new("mini.no_title"));
                };
                out.write_str("<h1>")?;
                out.write_str(&title.replace('<', "&lt;"))?;
                out.write_str("</h1>")
            }
            _ => {
                let Some(Value::Text(r)) = field("reference") else {
                    return Err(RenderError::new("mini.no_ref"));
                };
                out.write_str("missing ")?;
                out.write_str(r)
            }
        }
    }
}

#[test]
fn test_render_through_the_view() {
    let app = App::builder()
        .render(Mini)
        .page_limit(64)
        .route(
            get("/", |cx| {
                cx.render(&web_net::Fields(&[("title", Value::Text("Hi <you>"))]))
            })
            .public()
            .template("page"),
        )
        .route(
            get("/broken", |cx| cx.render(&web_net::Fields(&[])))
                .public()
                .template("page"),
        )
        .route(
            get("/big", |cx| {
                let t = "x".repeat(100);
                cx.render(&web_net::Fields(&[("title", Value::Text(&t))]))
            })
            .public()
            .template("page"),
        )
        .build()
        .unwrap();
    let r = get_req(&app, "/");
    assert_eq!(r.text(), "<h1>Hi &lt;you></h1>");
    assert_eq!(
        r.header("content-type"),
        Some(&b"text/html; charset=utf-8"[..])
    );
    assert_eq!(get_req(&app, "/broken").status, 500);
    assert_eq!(get_req(&app, "/big").status, 500);
    let r = get_req(&app, "/nope");
    assert_eq!(r.status, 404);
    assert!(r.text().starts_with("missing "), "{}", r.text());
}

// ---------------------------------------------------------------- checkpoint

struct Revoke;

impl Checkpoint for Revoke {
    fn check(&self, _env: &Envelope, at: Stage) -> Verdict {
        match at {
            Stage::BeforeRender => Verdict::Deny { status: 403 },
            _ => Verdict::Pass,
        }
    }
}

#[test]
fn test_checkpoint_stops_render() {
    let app = App::builder()
        .render(Mini)
        .checkpoint(Revoke)
        .route(
            get("/", |cx| {
                cx.render(&web_net::Fields(&[("title", Value::Text("x"))]))
            })
            .public()
            .template("page"),
        )
        .route(
            get("/plain", |cx| {
                cx.text(200, "ok");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    assert_eq!(get_req(&app, "/").status, 403);
    assert_eq!(get_req(&app, "/plain").status, 200);
}

// ---------------------------------------------------------------- classify

#[test]
fn test_classify() {
    struct Front {
        app: App,
        seen: Mutex<Vec<web_net::Classified>>,
    }
    impl serve_net::HttpService for Front {
        fn head(
            &self,
            head: &serve_net::HttpHead<'_>,
            _env: &mut Envelope,
        ) -> serve_net::HeadAction {
            self.seen.lock().unwrap().push(self.app.classify(head));
            serve_net::HeadAction::Proceed
        }
        fn call(
            &self,
            request: &serve_net::HttpRequest<'_>,
            env: &Envelope,
            reply: &mut serve_net::HttpReply,
        ) -> serve_net::Outcome {
            self.app.respond(request, env, reply)
        }
    }
    let front = Front {
        app: App::builder()
            .route(
                get("/report", |cx| {
                    cx.text(200, "r");
                    Ok(())
                })
                .public()
                .work(serve_net::WorkClass::Cpu),
            )
            .build()
            .unwrap(),
        seen: Mutex::new(Vec::new()),
    };
    assert_eq!(get_req(&front, "/report").text(), "r");
    let _ = get_req(&front, "/nope");
    let _ = get_req(&front, "/report/");
    let seen = front.seen.lock().unwrap();
    assert_eq!(seen[0].work, serve_net::WorkClass::Cpu);
    assert!(seen[0].route.is_some());
    assert!(seen[1].route.is_none());
    assert!(seen[2].route.is_none(), "a redirect runs no route");
}
