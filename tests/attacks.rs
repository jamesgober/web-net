//! One attack per threat in `dev/PLAN.md` section 13. Each must fail. The
//! ids are the ones `docs/SECURITY.md` lists.

use serve_net::Scheme;
use serve_net::testing::{TestReply, TestRequest, respond};
use web_net::{
    App, Assets, Cors, Cx, Denial, Error, Gate, Group, Identity, Request, SecurityHeaders, get,
    post,
};

fn send(app: &impl serve_net::HttpService, raw: &str) -> TestReply {
    respond(app, format!("{raw}\r\n\r\n").as_bytes())
}

fn h<'a>(r: &'a TestReply, name: &str) -> &'a str {
    r.header(name)
        .map(|v| std::str::from_utf8(v).unwrap())
        .unwrap_or("")
}

struct Who {
    admin: bool,
}

impl Identity for Who {
    fn is_guest(&self) -> bool {
        !self.admin
    }
}

struct AdminCookie;

impl Gate for AdminCookie {
    type Identity = Who;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Who, Denial> {
        Ok(Who {
            admin: matches!(req.cookie("sid"), Ok(Some("admin"))),
        })
    }
    fn authorize(&self, who: &Who, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        if who.admin {
            Ok(())
        } else {
            Err(Denial::forbidden("attack.not_admin"))
        }
    }
}

fn guarded() -> App<AdminCookie> {
    App::with_gate(AdminCookie)
        .host("example.com")
        .route(
            get("/", |cx: &mut Cx<'_, Who>| {
                cx.text(200, "home");
                Ok(())
            })
            .public(),
        )
        .group(
            Group::new("/admin")
                .allow(())
                .route(get("/", |cx: &mut Cx<'_, Who>| {
                    cx.text(200, "ADMIN");
                    Ok(())
                }))
                .route(get("/users/:id", |cx: &mut Cx<'_, Who>| {
                    cx.text(200, "ADMIN");
                    Ok(())
                })),
        )
        .route(
            get("/files/*rest", |cx: &mut Cx<'_, Who>| {
                cx.text(200, "file");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap()
}

/// T-1: no spelling of a protected path reaches it without the gate.
#[test]
fn t01_path_tricks_never_bypass_the_gate() {
    let app = guarded();
    for p in [
        "/admin",
        "/admin/",
        "//admin",
        "/./admin",
        "/x/../admin",
        "/%61dmin",
        "/%2e/admin",
        "/files/../admin",
        "/files/%2e%2e/admin",
        "/ADMIN",
        "/admin;x",
        "/admin%20",
        "/admin.",
        "/admin%2F",
        "/admin%00",
        "/admin%5c",
        "/admin/users/1/..",
        "/admin//users/1",
        "/files/..%2fadmin",
        "/%C0%AEadmin",
    ] {
        let r = send(&app, &format!("GET {p} HTTP/1.1\r\nHost: example.com"));
        assert_ne!(r.text(), "ADMIN", "{p} reached the admin page");
        // Following a redirect still meets the gate.
        if matches!(r.status, 301 | 308) {
            let to = h(&r, "location").to_owned();
            let r2 = send(&app, &format!("GET {to} HTTP/1.1\r\nHost: example.com"));
            assert_ne!(r2.text(), "ADMIN", "{p} -> {to}");
            assert!(
                !matches!(r2.status, 301 | 308),
                "{p} -> {to} redirected again"
            );
        }
    }
    let r = send(
        &app,
        "GET /admin HTTP/1.1\r\nHost: example.com\r\nCookie: sid=admin",
    );
    assert_eq!(r.text(), "ADMIN");
}

/// T-2: a route that forgot its access does not exist.
#[test]
fn t02_forgotten_authorization_does_not_build() {
    assert!(
        App::builder()
            .route(get("/secret", |cx| {
                cx.text(200, "x");
                Ok(())
            }))
            .build()
            .is_err()
    );
}

/// T-3: a forged Host never reaches a site, nor a redirect's Location.
#[test]
fn t03_host_header_poisoning() {
    let app = App::builder()
        .host("example.com")
        .alias("www.example.com")
        .https_only()
        .route(
            get("/", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    for host in [
        "evil.example",
        "example.com.evil.example",
        "evilexample.com",
        "example.com@evil",
    ] {
        let r = send(&app, &format!("GET / HTTP/1.1\r\nHost: {host}"));
        assert!(!h(&r, "location").contains("evil"), "{host}");
        assert_ne!(r.status, 200, "{host}");
    }
    // The absolute form's authority wins over Host, and is checked the same.
    let r = send(
        &app,
        "GET http://evil.example/ HTTP/1.1\r\nHost: example.com",
    );
    assert!(!h(&r, "location").contains("evil"));
    assert_ne!(r.status, 200);
    // `OPTIONS *` meets the host check too.
    let r = send(&app, "OPTIONS * HTTP/1.1\r\nHost: evil.example");
    assert_eq!(r.status, 421);
    // An empty Host is as unknown as any other.
    let r = send(&app, "GET / HTTP/1.1\r\nHost:");
    assert_eq!(r.status, 421);
    // Redirects go to the declared host only.
    let r = send(&app, "GET / HTTP/1.1\r\nHost: www.example.com");
    assert_eq!(h(&r, "location"), "https://example.com/");
}

/// T-4: handlers cannot be made into open redirects.
#[test]
fn t04_open_redirects() {
    let app = App::builder()
        .redirect_hosts(&["accounts.example.com"])
        .route(
            get("/go", |cx| {
                let to = cx.query("to")?.unwrap_or_default().into_owned();
                cx.see_other(&to)
            })
            .public(),
        )
        .route(
            get("/out", |cx| {
                let to = cx.query("to")?.unwrap_or_default().into_owned();
                cx.redirect_external(302, &to)
            })
            .public(),
        )
        .build()
        .unwrap();
    for to in [
        "//evil.example",
        "/\\evil.example",
        "https://evil.example",
        "%2F%2Fevil.example",
        "/%0d%0aSet-Cookie:x",
    ] {
        let r = send(&app, &format!("GET /go?to={to} HTTP/1.1\r\nHost: a"));
        assert!(!h(&r, "location").contains("evil"), "{to}");
        assert!(r.header("set-cookie").is_none(), "{to}");
    }
    for to in [
        "https://evil.example/",
        "https://accounts.example.com@evil.example/",
        "javascript:alert(1)",
    ] {
        let r = send(&app, &format!("GET /out?to={to} HTTP/1.1\r\nHost: a"));
        assert_eq!(r.status, 500, "{to}");
    }
}

/// T-5: nothing internal leaks through an error page.
#[test]
fn t05_errors_leak_nothing() {
    let app = App::builder()
        .route(
            get("/db", |_| {
                Err(Error::internal("db.password_rejected")
                    .with_source(std::io::Error::other("user=root password=hunter2")))
            })
            .public(),
        )
        .route(get("/panic", |_| panic!("secret panic text")).public())
        .build()
        .unwrap();
    for (p, accept) in [
        ("/db", "text/html"),
        ("/db", "application/json"),
        ("/panic", "text/html"),
    ] {
        let r = send(
            &app,
            &format!("GET {p} HTTP/1.1\r\nHost: a\r\nAccept: {accept}"),
        );
        assert_eq!(r.status, 500);
        let t = r.text();
        for leak in ["hunter2", "root", "db.", "secret", "panic text"] {
            assert!(!t.contains(leak), "{p} {accept} leaked {leak}");
        }
    }
}

/// T-6: a failing handler sends none of what it wrote.
#[test]
fn t06_no_half_replies() {
    let app = App::builder()
        .route(
            get("/", |cx| {
                cx.set_header("set-cookie", "session=stolen")
                    .set_header("location", "https://evil.example");
                Err(Error::forbidden("nope"))
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(&app, "GET / HTTP/1.1\r\nHost: a");
    assert_eq!(r.status, 403);
    assert!(r.header("set-cookie").is_none() && r.header("location").is_none());
}

/// T-7: reply fields cannot be split or smuggled.
#[test]
fn t07_header_injection() {
    let app = App::builder()
        .route(
            get("/", |cx| {
                let v = cx.query("v")?.unwrap_or_default().into_owned();
                cx.set_header("x-echo", v);
                cx.text(200, "ok");
                Ok(())
            })
            .public(),
        )
        .route(
            get("/len", |cx| {
                cx.set_header("Transfer-Encoding", "chunked");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(&app, "GET /?v=a%0d%0aSet-Cookie:%20x=1 HTTP/1.1\r\nHost: a");
    assert_eq!(r.status, 500);
    assert!(r.header("set-cookie").is_none());
    assert_eq!(send(&app, "GET /len HTTP/1.1\r\nHost: a").status, 500);
}

/// T-8 and T-9: ambiguity is refused, never resolved by picking.
#[test]
fn t08_t09_pollution_and_cookie_tossing() {
    let app = guarded();
    let r = send(
        &app,
        "GET /admin HTTP/1.1\r\nHost: example.com\r\nCookie: sid=guest; sid=admin",
    );
    assert_ne!(r.text(), "ADMIN");
    let r = send(
        &app,
        "GET /admin HTTP/1.1\r\nHost: example.com\r\nCookie: sid=admin\r\nCookie: sid=guest",
    );
    assert_ne!(r.text(), "ADMIN");
    let q = App::builder()
        .route(
            get("/", |cx| {
                let v = cx.query("role")?.unwrap_or_default().into_owned();
                cx.text(200, &v);
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    assert_eq!(
        send(&q, "GET /?role=user&role=admin HTTP/1.1\r\nHost: a").status,
        400
    );
}

/// T-10: a forged cross-site POST does nothing.
#[test]
fn t10_csrf() {
    struct S;
    struct V;
    impl Identity for V {
        fn is_guest(&self) -> bool {
            false
        }
        fn csrf_binding(&self) -> Option<&[u8]> {
            Some(b"session-1")
        }
    }
    impl Gate for S {
        type Identity = V;
        type Rule = ();
        fn authenticate(&self, _: &Request<'_>) -> Result<V, Denial> {
            Ok(V)
        }
        fn authorize(&self, _: &V, _: &(), _: &Request<'_>) -> Result<(), Denial> {
            Ok(())
        }
    }
    let app = App::with_gate(S)
        .csrf(web_net::csrf_sec::Csrf::new(*b"attack test csrf key, 32 bytes!!").unwrap())
        .route(
            post("/transfer", |cx: &mut Cx<'_, V>| {
                cx.text(200, "MOVED");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    for extra in [
        "Origin: https://evil.example\r\nSec-Fetch-Site: cross-site",
        "Sec-Fetch-Site: same-site",
        "",
        "X-CSRF-Token: forged",
    ] {
        let r = send(
            &app,
            &format!(
                "POST /transfer HTTP/1.1\r\nHost: a\r\n{extra}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 12\r\n\r\namount=1000&"
            ),
        );
        assert_ne!(r.text(), "MOVED", "{extra}");
        assert_eq!(r.status, 403, "{extra}");
    }
}

/// T-11 and T-12: files never come from outside the folder, nor special
/// files from inside it.
#[test]
fn t11_t12_traversal_and_special_files() {
    let dir = std::env::temp_dir().join(format!("web-net-attack-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("pub")).unwrap();
    std::fs::write(dir.join("secret.txt"), b"SECRET").unwrap();
    std::fs::write(dir.join("pub").join("ok.txt"), b"ok").unwrap();
    std::fs::write(dir.join("pub").join(".env"), b"SECRET").unwrap();
    let app = App::builder()
        .assets(Assets::new("/s", dir.join("pub")))
        .build()
        .unwrap();
    for p in [
        "/s/../secret.txt",
        "/s/..%2fsecret.txt",
        "/s/%2e%2e/secret.txt",
        "/s/..%5csecret.txt",
        "/s/.env",
        "/s/ok.txt::$DATA",
        "/s/ok.txt.",
        "/s/ok.txt%20",
        "/s/CON",
        "/s/%c0%ae%c0%ae/secret.txt",
    ] {
        let r = send(&app, &format!("GET {p} HTTP/1.1\r\nHost: a"));
        assert_ne!(r.text(), "SECRET", "{p}");
        if matches!(r.status, 301 | 308) {
            let to = h(&r, "location").to_owned();
            assert_ne!(
                send(&app, &format!("GET {to} HTTP/1.1\r\nHost: a")).text(),
                "SECRET",
                "{p} -> {to}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// T-13: protocol downgrade and framing: HSTS on HTTPS, frames refused.
#[test]
fn t13_hsts_and_frames() {
    let app = App::builder()
        .host("example.com")
        .route(
            get("/", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = TestRequest::new(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .scheme(Scheme::Https)
        .send(&app);
    assert!(h(&r, "strict-transport-security").starts_with("max-age="));
    assert_eq!(h(&r, "x-frame-options"), "DENY");
    assert!(h(&r, "content-security-policy").contains("frame-ancestors 'none'"));
    let _ = SecurityHeaders::default();
}

/// T-14: another origin's script cannot read a route without a policy, and
/// a policy never pairs `*` with credentials.
#[test]
fn t14_cross_origin_reads() {
    let app = App::builder()
        .route(
            get("/me", |cx| {
                cx.text(200, "me");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let r = send(
        &app,
        "GET /me HTTP/1.1\r\nHost: a\r\nOrigin: https://evil.example",
    );
    assert!(r.header("access-control-allow-origin").is_none());
    assert!(
        App::builder()
            .route(
                get("/", |cx| {
                    cx.text(200, "x");
                    Ok(())
                })
                .public()
                .cors(Cors::new().any_origin().credentials())
            )
            .build()
            .is_err()
    );
}

/// T-15: resource budgets hold.
#[test]
fn t15_budgets() {
    let app = App::builder()
        .page_limit(16)
        .route(
            get("/*rest", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let deep = "/a".repeat(300);
    assert_eq!(
        send(&app, &format!("GET {deep} HTTP/1.1\r\nHost: a")).status,
        400
    );
    let many = App::builder()
        .route(
            get("/", |cx| {
                for i in 0..100 {
                    cx.set_header("x-n", i.to_string());
                }
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    assert_eq!(send(&many, "GET / HTTP/1.1\r\nHost: a").status, 500);
}
