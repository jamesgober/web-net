//! The application every fuzz target drives: a gate, groups, parameters, a
//! wildcard, CSRF, forms, CORS, hooks, a base path, and hosts.

use std::sync::OnceLock;

use web_net::csrf_sec::Csrf;
use web_net::{App, Cors, Cx, Denial, Gate, Group, Hook, Identity, Request, Route, Routes, get};

pub struct Visitor {
    sid: Option<String>,
    admin: bool,
}

impl Identity for Visitor {
    fn is_guest(&self) -> bool {
        self.sid.is_none()
    }
    fn csrf_binding(&self) -> Option<&[u8]> {
        self.sid.as_deref().map(str::as_bytes)
    }
}

pub enum Rule {
    SignedIn,
    Admin,
}

pub struct FuzzGate;

impl Gate for FuzzGate {
    type Identity = Visitor;
    type Rule = Rule;
    fn authenticate(&self, req: &Request<'_>) -> Result<Visitor, Denial> {
        let sid = req.cookie("sid").map_err(|_| Denial::with_status(400, "fuzz.cookie"))?;
        Ok(Visitor {
            admin: sid == Some("admin"),
            sid: sid.map(str::to_owned),
        })
    }
    fn authorize(&self, who: &Visitor, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        match rule {
            Rule::SignedIn if !who.is_guest() => Ok(()),
            Rule::SignedIn => Err(Denial::sign_in("fuzz.guest")),
            Rule::Admin if who.admin => Ok(()),
            Rule::Admin => Err(Denial::hidden("fuzz.admin")),
        }
    }
}

web_net::form_net::form! {
    pub struct Email { pub email: String }
    ignore = ["csrf_token"];
}

/// The shared application, built once.
pub fn app() -> &'static App<FuzzGate> {
    static APP: OnceLock<App<FuzzGate>> = OnceLock::new();
    APP.get_or_init(|| {
        App::with_gate(FuzzGate)
            .host("a")
            .alias("www.a")
            .development()
            .base("/site")
            .sign_in("/login")
            .csrf(Csrf::new(*b"web-net fuzz key, 32 bytes long!").expect("key"))
            .hook(Hook::Routed, Routes::prefix("/blog"), |cx: &mut Cx<'_, Visitor>| {
                let _ = cx.query("lang")?;
                Ok(())
            })
            .route(get("/", |cx: &mut Cx<'_, Visitor>| {
                cx.text(200, "home")
            }).public())
            .route(get("/login", |cx: &mut Cx<'_, Visitor>| {
                let next = cx.query("next")?.unwrap_or_default().into_owned();
                cx.text(200, &next)
            }).public())
            .group(
                Group::at("/blog")
                    .public()
                    .cors(Cors::new().origin("https://app.a").headers(&["content-type"]))
                    .route(get("/", |cx: &mut Cx<'_, Visitor>| {
                        cx.text(200, "blog")
                    }))
                    .route(get("/:slug", |cx: &mut Cx<'_, Visitor>| {
                        let s = cx.param("slug")?.into_owned();
                        cx.text(200, &s)
                    }))
                    .route(get("/:year/:slug", |cx: &mut Cx<'_, Visitor>| {
                        let y: u16 = cx.param_as("year")?;
                        cx.text(200, &y.to_string())
                    })),
            )
            .route(get("/files/*rest", |cx: &mut Cx<'_, Visitor>| {
                let r = cx.param("rest")?.into_owned();
                cx.text(200, &r)
            }).public())
            .route(
                Route::at("/account")
                    .get(|cx: &mut Cx<'_, Visitor>| {
                        let t = cx.csrf_token()?;
                        cx.text(200, &t)
                    })
                    .post(|cx: &mut Cx<'_, Visitor>| {
                        let f: Email = cx.form()?;
                        cx.text(200, &f.email)
                    })
                    .allow(Rule::SignedIn),
            )
            .route(get("/admin", |cx: &mut Cx<'_, Visitor>| {
                // A field no echoing route can set: the fuzz targets look for it.
                cx.set_header("x-admin-page", "1");
                cx.text(200, "admin")
            }).allow(Rule::Admin))
            .build()
            .expect("fuzz app")
    })
}
