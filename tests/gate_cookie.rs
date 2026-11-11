//! A cookie the gate sets during authentication leaves on every exit of
//! `respond`, once; `respond` with an identity leaves it to its caller.

use serve_net::testing::{TestReply, respond};
use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
use web_net::{App, Cx, Denial, Gate, Identity, Request, get};

const CLEAR: &str = "__Host-sid=; Max-Age=0; Path=/; Secure; HttpOnly";

struct Dead;

impl Identity for Dead {
    fn is_guest(&self) -> bool {
        true
    }
    fn set_cookie(&self) -> Option<&str> {
        Some(CLEAR)
    }
}

struct G;

impl Gate for G {
    type Identity = Dead;
    type Rule = ();
    fn authenticate(&self, req: &Request<'_>) -> Result<Dead, Denial> {
        if req.header("x-banned").is_some() {
            return Err(Denial::forbidden("test.banned").with_cookie(CLEAR));
        }
        Ok(Dead)
    }
    fn authorize(&self, _: &Dead, _: &(), _: &Request<'_>) -> Result<(), Denial> {
        Err(Denial::sign_in("test.sign_in"))
    }
}

fn app() -> App<G> {
    App::with_gate(G)
        .sign_in("/login")
        .route(get("/", |cx: &mut Cx<'_, Dead>| cx.text(200, "x")).public())
        .route(
            get("/fail", |_: &mut Cx<'_, Dead>| {
                Err(web_net::Error::internal("x"))
            })
            .public(),
        )
        .route(get("/private", |cx: &mut Cx<'_, Dead>| cx.text(200, "p")).allow(()))
        .build()
        .unwrap()
}

fn cookies(r: &TestReply) -> usize {
    r.headers
        .iter()
        .filter(|(n, v)| n == "set-cookie" && v == CLEAR.as_bytes())
        .count()
}

#[test]
fn test_gate_cookie_on_every_exit() {
    let app = app();
    for raw in [
        "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /fail HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /nope HTTP/1.1\r\nHost: a\r\n\r\n",
        "DELETE / HTTP/1.1\r\nHost: a\r\n\r\n",
        "OPTIONS / HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET /private HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nX-Banned: 1\r\n\r\n",
    ] {
        let r = respond(&app, raw.as_bytes());
        assert_eq!(cookies(&r), 1, "{raw:?} -> {}", r.status);
    }
}

#[test]
fn test_respond_with_identity_leaves_the_cookie_to_its_caller() {
    struct Core(App<G>);
    impl HttpService for Core {
        fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
            self.0.respond(req, env, Some(&Dead), reply).outcome
        }
    }
    let r = respond(&Core(app()), b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!((r.status, cookies(&r)), (200, 0));
}
