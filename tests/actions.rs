//! Actions: forms, uploads, CSRF, external redirects, and preconditions.

use std::sync::Mutex;

use serve_net::testing::{TestReply, respond};
use web_net::csrf_sec::Csrf;
use web_net::form_net::{self, FormError, FromForm};
use web_net::{
    App, Cx, Denial, Error, Event, EventKind, Events, Gate, Identity, Request, Route, get, post,
};

const KEY: [u8; 32] = *b"web-net actions test key 32 byte";

/// A session from the `sid` cookie; guests have none (and no binding).
struct Visitor {
    sid: Option<String>,
}

impl Identity for Visitor {
    fn is_guest(&self) -> bool {
        self.sid.is_none()
    }
    fn csrf_binding(&self) -> Option<&[u8]> {
        self.sid.as_deref().map(str::as_bytes)
    }
}

struct Sessions;

impl Gate for Sessions {
    type Identity = Visitor;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Visitor, Denial> {
        Ok(Visitor {
            sid: req.cookie("sid").ok().flatten().map(str::to_owned),
        })
    }
    fn authorize(&self, _: &Visitor, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Ok(())
    }
}

form_net::form! {
    #[derive(Debug)]
    struct Email {
        email: String,
    }
    ignore = ["csrf_token"];
}

#[derive(Default)]
struct Log(Mutex<Vec<(EventKind, u16, &'static str)>>);

impl Events for &'static Log {
    fn event(&self, e: &Event<'_>) {
        self.0.lock().unwrap().push((e.kind, e.status, e.code));
    }
}

fn app(log: &'static Log) -> App<Sessions> {
    App::with_gate(Sessions)
        .csrf(Csrf::new(KEY).unwrap())
        .events(log)
        .redirect_hosts(&["accounts.example.com"])
        .route(
            get("/token", |cx: &mut Cx<'_, Visitor>| {
                let t = cx.csrf_token()?;
                cx.text(200, &t);
                Ok(())
            })
            .public(),
        )
        .route(
            post("/email", |cx: &mut Cx<'_, Visitor>| {
                match cx.form::<Email>() {
                    Ok(f) => {
                        cx.text(200, &f.email);
                        Ok(())
                    }
                    // The action pattern: a form with errors comes back with 422.
                    Err(e) if e.status_hint() == 422 || e.status_hint() == 400 => {
                        cx.status(422).html(422, "<p>check the form</p>");
                        Ok(())
                    }
                    Err(e) => Err(e.into()),
                }
            })
            .public(),
        )
        .route(
            post("/api", |cx: &mut Cx<'_, Visitor>| {
                let n = cx.body()?.len();
                cx.text(200, &n.to_string());
                Ok(())
            })
            .public(),
        )
        .route(
            post("/lazy", |cx: &mut Cx<'_, Visitor>| {
                // Never reads its body: under multipart, the reply must not leave.
                cx.set_header("set-cookie", "changed=1");
                cx.text(200, "changed");
                Ok(())
            })
            .public(),
        )
        .route(
            post("/raw", |cx: &mut Cx<'_, Visitor>| {
                let b = cx.body()?;
                cx.text(200, &b.len().to_string());
                Ok(())
            })
            .public(),
        )
        .route(
            post("/hook", |cx: &mut Cx<'_, Visitor>| {
                cx.text(200, "hook");
                Ok(())
            })
            .public()
            .csrf_exempt("signed by the sender"),
        )
        .route(
            get("/away", |cx: &mut Cx<'_, Visitor>| {
                let to = cx.query("to")?.unwrap_or_default().into_owned();
                cx.redirect_external(303, &to)
            })
            .public(),
        )
        .route(
            Route::at("/doc")
                .put(|cx: &mut Cx<'_, Visitor>| {
                    cx.precondition(Some("v2"), None)?;
                    cx.text(200, "saved");
                    Ok(())
                })
                .public(),
        )
        .build()
        .unwrap()
}

fn token(app: &App<Sessions>, sid: &str) -> String {
    let r = respond(
        app,
        format!("GET /token HTTP/1.1\r\nHost: a\r\nCookie: sid={sid}\r\n\r\n").as_bytes(),
    );
    assert_eq!(r.status, 200);
    r.text().to_owned()
}

fn post_to(
    app: &App<Sessions>,
    path: &str,
    sid: Option<&str>,
    extra: &str,
    ct: &str,
    body: &[u8],
) -> TestReply {
    let cookie = sid
        .map(|s| format!("Cookie: sid={s}\r\n"))
        .unwrap_or_default();
    let mut raw = format!(
        "POST {path} HTTP/1.1\r\nHost: a\r\n{cookie}{extra}Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    raw.extend_from_slice(body);
    respond(app, &raw)
}

const FORM: &str = "application/x-www-form-urlencoded";

#[test]
fn test_build_requires_csrf_or_an_exemption() {
    let e = App::builder()
        .route(
            post("/a", |cx| {
                cx.text(200, "a");
                Ok(())
            })
            .public(),
        )
        .route(
            post("/b", |cx| {
                cx.text(200, "b");
                Ok(())
            })
            .public()
            .csrf_exempt("  "),
        )
        .route(
            post("/c", |cx| {
                cx.text(200, "c");
                Ok(())
            })
            .public()
            .csrf_exempt("a webhook"),
        )
        .build()
        .unwrap_err();
    let subjects: Vec<&str> = e.problems().iter().map(|p| p.subject.as_str()).collect();
    // The empty reason is refused; it still counts as exempt, so /b has no
    // second problem.
    assert_eq!(subjects, ["POST /a", "/b"], "{e}");
}

#[test]
fn test_urlencoded_token_is_checked_before_the_handler() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let t = token(&app, "s1");
    let good = format!("csrf_token={t}&email=a%40b.example");
    let r = post_to(&app, "/email", Some("s1"), "", FORM, good.as_bytes());
    assert_eq!((r.status, r.text()), (200, "a@b.example"));

    for (sid, body, code) in [
        (
            Some("s1"),
            "csrf_token=forged&email=x".to_owned(),
            "csrf.malformed",
        ),
        (Some("s1"), "email=x".to_owned(), "csrf.missing"),
        (
            Some("s1"),
            format!("csrf_token={t}&csrf_token={t}&email=x"),
            "csrf.duplicate",
        ),
        // A token for another session. (Each refusal is a Denied event from
        // the CSRF step: no handler ran.)
        (Some("s2"), good.clone(), "csrf.bad_mac"),
        (None, good.clone(), "csrf.no_binding"),
    ] {
        let r = post_to(&app, "/email", sid, "", FORM, body.as_bytes());
        assert_eq!(r.status, 403, "{body}");
        let last = *log.0.lock().unwrap().last().unwrap();
        assert_eq!(last.0, EventKind::Denied);
        assert_eq!(last.2, code, "{body}");
    }
}

#[test]
fn test_header_token_and_origin_policy() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let t = token(&app, "s1");
    let hdr = format!("X-CSRF-Token: {t}\r\n");
    let r = post_to(&app, "/api", Some("s1"), &hdr, "application/json", b"{}");
    assert_eq!((r.status, r.text()), (200, "2"));
    let r = post_to(&app, "/api", Some("s1"), "", "application/json", b"{}");
    assert_eq!(r.status, 403);
    // A cross-site request is refused before the token is looked at.
    let cross = format!("{hdr}Sec-Fetch-Site: cross-site\r\n");
    assert_eq!(
        post_to(&app, "/api", Some("s1"), &cross, "application/json", b"{}").status,
        403
    );
    let other = format!("{hdr}Origin: https://evil.example\r\n");
    assert_eq!(
        post_to(&app, "/api", Some("s1"), &other, "application/json", b"{}").status,
        403
    );
    let same = format!("{hdr}Origin: http://a\r\nSec-Fetch-Site: same-origin\r\n");
    assert_eq!(
        post_to(&app, "/api", Some("s1"), &same, "application/json", b"{}").status,
        200
    );
    let codes: Vec<&str> = log.0.lock().unwrap().iter().map(|e| e.2).collect();
    assert!(codes.contains(&"csrf.cross_site"), "{codes:?}");
    // Exempt routes take no token.
    assert_eq!(
        post_to(&app, "/hook", None, "", "application/json", b"{}").status,
        200
    );
}

fn multipart(token: &str, file: bool) -> Vec<u8> {
    let mut b = format!(
        "--B\r\nContent-Disposition: form-data; name=csrf_token\r\n\r\n{token}\r\n--B\r\nContent-Disposition: form-data; name=email\r\n\r\nm@b.example\r\n"
    )
    .into_bytes();
    if file {
        b.extend_from_slice(
            b"--B\r\nContent-Disposition: form-data; name=doc; filename=a.txt\r\n\r\nhello\r\n",
        );
    }
    b.extend_from_slice(b"--B--");
    b
}

const MP: &str = "multipart/form-data; boundary=B";

#[test]
fn test_multipart_token_is_checked_before_the_handler() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let t = token(&app, "s1");
    let r = post_to(&app, "/email", Some("s1"), "", MP, &multipart(&t, false));
    assert_eq!((r.status, r.text()), (200, "m@b.example"));
    // A handler that never reads its body runs only with a verified token.
    let r = post_to(&app, "/lazy", Some("s1"), "", MP, &multipart(&t, true));
    assert_eq!((r.status, r.text()), (200, "changed"));
    let r = post_to(&app, "/raw", Some("s1"), "", MP, &multipart(&t, false));
    assert_eq!(r.status, 200);
    // Forged, missing, or after a file: refused before the handler runs, so
    // a handler with side effects (a delete) never starts.
    let no_token = b"--B\r\nContent-Disposition: form-data; name=x\r\n\r\ny\r\n--B--".to_vec();
    let file_first = {
        let mut b =
            b"--B\r\nContent-Disposition: form-data; name=doc; filename=a.txt\r\n\r\nhello\r\n"
                .to_vec();
        b.extend_from_slice(
            format!("--B\r\nContent-Disposition: form-data; name=csrf_token\r\n\r\n{t}\r\n--B--")
                .as_bytes(),
        );
        b
    };
    // A valid token, then a second one: refused, as on the urlencoded and
    // header paths (form-net's review).
    let two_tokens = format!(
        "--B\r\nContent-Disposition: form-data; name=csrf_token\r\n\r\n{t}\r\n--B\r\nContent-Disposition: form-data; name=csrf_token\r\n\r\nOTHER\r\n--B\r\nContent-Disposition: form-data; name=doc; filename=a.txt\r\n\r\nhi\r\n--B--"
    )
    .into_bytes();
    for (body, code) in [
        (multipart("forged", false), "csrf.malformed"),
        (no_token, "csrf.missing"),
        (b"--B--".to_vec(), "csrf.missing"),
        (file_first, "csrf.missing"),
        (two_tokens, "csrf.duplicate"),
    ] {
        let r = post_to(&app, "/lazy", Some("s1"), "", MP, &body);
        assert_eq!(r.status, 403, "{code}");
        assert!(r.header("set-cookie").is_none());
        let last = *log.0.lock().unwrap().last().unwrap();
        assert_eq!(last, (EventKind::Denied, 403, code));
    }
}

#[test]
fn test_invalid_form_comes_back_with_422() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let t = token(&app, "s1");
    let body = format!("csrf_token={t}&email=a&extra=1");
    let r = post_to(&app, "/email", Some("s1"), "", FORM, body.as_bytes());
    assert_eq!((r.status, r.text()), (422, "<p>check the form</p>"));
}

#[test]
fn test_external_redirects_are_allowlisted() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let go = |to: &str| {
        respond(
            &app,
            format!("GET /away?to={to} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes(),
        )
    };
    let r = go("https://accounts.example.com/login");
    assert_eq!(
        (r.status, r.header("location")),
        (303, Some(&b"https://accounts.example.com/login"[..]))
    );
    for bad in [
        "https://evil.example/",
        "https://accounts.example.com.evil.example/",
        "https://evil.example@accounts.example.com/",
        "javascript:alert(1)",
        "//accounts.example.com/",
        "https://accounts.example.com%252F@evil.example/",
    ] {
        assert_eq!(go(bad).status, 500, "{bad}");
    }
}

#[test]
fn test_preconditions() {
    let log: &'static Log = Box::leak(Box::default());
    let app = app(log);
    let t = token(&app, "s1");
    let hdr = |extra: &str| format!("X-CSRF-Token: {t}\r\n{extra}");
    let put = |extra: &str| {
        let raw = format!(
            "PUT /doc HTTP/1.1\r\nHost: a\r\nCookie: sid=s1\r\n{}Content-Length: 0\r\n\r\n",
            hdr(extra)
        );
        respond(&app, raw.as_bytes())
    };
    assert_eq!(put("").status, 200);
    assert_eq!(put("If-Match: \"v2\"\r\n").status, 200);
    assert_eq!(put("If-Match: \"v1\"\r\n").status, 412);
    assert_eq!(put("If-Match: W/\"v2\"\r\n").status, 412);
    assert_eq!(put("If-Match: *\r\n").status, 200);
}

#[test]
fn test_form_error_maps_to_its_status() {
    let e: Error = FormError::UnsupportedMediaType.into();
    assert_eq!(e.status(), 415);
    let _ = Email::from_urlencoded(b"email=x");
}

#[cfg(feature = "uploads")]
#[test]
fn test_uploads_check_the_token_before_storing() {
    use form_net::Store;
    let dir = std::env::temp_dir().join(format!("web-net-upload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: &'static Store =
        Box::leak(Box::new(Store::in_dir(&dir).unwrap().memory_threshold(0)));
    let app = App::with_gate(Sessions)
        .csrf(Csrf::new(KEY).unwrap())
        .route(
            get("/token", |cx: &mut Cx<'_, Visitor>| {
                let t = cx.csrf_token()?;
                cx.text(200, &t);
                Ok(())
            })
            .public(),
        )
        .route(
            post("/upload", move |cx: &mut Cx<'_, Visitor>| {
                let up = cx.upload(store)?;
                let n = up.files("doc").count();
                cx.text(200, &n.to_string());
                Ok(())
            })
            .public(),
        )
        .build()
        .unwrap();
    let t = token(&app, "s1");
    let r = post_to(&app, "/upload", Some("s1"), "", MP, &multipart(&t, true));
    assert_eq!((r.status, r.text()), (200, "1"));
    let r = post_to(
        &app,
        "/upload",
        Some("s1"),
        "",
        MP,
        &multipart("forged", true),
    );
    assert_eq!(r.status, 403);
    assert_eq!(store.stats().files_on_disk, 0);
    let _ = std::fs::remove_dir_all(&dir);
}
