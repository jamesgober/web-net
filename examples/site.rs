//! A small site end to end: sessions with a pre-session id for guests,
//! sign-in and sign-out with CSRF, a page only for signed-in visitors, an
//! upload, static files, health paths, and pages rendered by Luminess.
//!
//! ```text
//! cargo run --example site --features uploads
//! open http://127.0.0.1:8092/  (sign in as demo / demo)
//! ```
//!
//! The gate here keeps sessions in a map and compares passwords in plain
//! text: it shows where a real gate plugs in, and is not one.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use web_net::csrf_sec::{Csrf, OsRandom, RandomSource};
use web_net::form_net::{self, Store};
use web_net::{App, Assets, Context, Denial, Error, Gate, Identity, Request, Route, get, post};

// ---------------------------------------------------------------- the gate

/// A visitor: signed in (a session) or a guest with a pre-session id.
struct Visitor {
    user: Option<String>,
    /// The session id, or the guest's pre-session id: what CSRF tokens bind to.
    id: String,
    /// A `Set-Cookie` for a pre-session id made on this request.
    fresh: Option<String>,
}

impl Identity for Visitor {
    fn is_guest(&self) -> bool {
        self.user.is_none()
    }
    fn csrf_binding(&self) -> Option<&[u8]> {
        Some(self.id.as_bytes())
    }
    fn set_cookie(&self) -> Option<&str> {
        self.fresh.as_deref()
    }
}

enum Rule {
    SignedIn,
}

#[derive(Default)]
struct Sessions {
    by_id: Mutex<HashMap<String, String>>,
}

fn random_id() -> Result<String, Error> {
    let mut b = [0u8; 24];
    OsRandom
        .fill(&mut b)
        .map_err(|e| Error::internal("site.random").with_source(e))?;
    Ok(b.iter().fold(String::with_capacity(48), |mut s, x| {
        use std::fmt::Write as _;
        let _ = write!(s, "{x:02x}");
        s
    }))
}

impl Gate for &'static Sessions {
    type Identity = Visitor;
    type Rule = Rule;

    fn authenticate(&self, req: &Request<'_>) -> Result<Visitor, Denial> {
        let sid = req
            .cookie("sid")
            .map_err(|_| Denial::with_status(400, "site.cookie_twice"))?;
        if let Some(sid) = sid {
            if let Some(user) = self.by_id.lock().ok().and_then(|m| m.get(sid).cloned()) {
                return Ok(Visitor {
                    user: Some(user),
                    id: sid.to_owned(),
                    fresh: None,
                });
            }
        }
        let pre = req
            .cookie("pre")
            .map_err(|_| Denial::with_status(400, "site.cookie_twice"))?;
        match pre.filter(|p| p.len() == 48 && p.bytes().all(|b| b.is_ascii_hexdigit())) {
            Some(p) => Ok(Visitor {
                user: None,
                id: p.to_owned(),
                fresh: None,
            }),
            None => {
                let id = random_id().map_err(|_| Denial::with_status(503, "site.random"))?;
                let cookie = format!("pre={id}; Path=/; HttpOnly; SameSite=Lax");
                Ok(Visitor {
                    user: None,
                    id,
                    fresh: Some(cookie),
                })
            }
        }
    }

    fn authorize(&self, who: &Visitor, rule: &Rule, _req: &Request<'_>) -> Result<(), Denial> {
        match rule {
            Rule::SignedIn if who.user.is_some() => Ok(()),
            Rule::SignedIn => Err(Denial::sign_in("site.guest")),
        }
    }
}

// ---------------------------------------------------------------- pages

struct Page {
    title: String,
    user: String,
    token: String,
    message: String,
}

luminess::view!(Page as "page" { title: text, user: text, token: text, message: text });

const LAYOUT: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{{ page.title }}</title><link rel="stylesheet" href="/static/site.css"></head><body>"#;

fn engine() -> luminess::Engine<Page> {
    let home = format!(
        r#"{LAYOUT}<h1>{{{{ page.title }}}}</h1>{{% if page.user %}}<p>Signed in as {{{{ page.user }}}}. <a href="/account">Account</a></p><form method="post" action="/logout"><input type="hidden" name="csrf_token" value="{{{{ page.token }}}}"><button>Sign out</button></form>{{% else %}}<p><a href="/login">Sign in</a></p>{{% endif %}}</body></html>"#
    );
    let login = format!(
        r#"{LAYOUT}<h1>Sign in</h1><p>{{{{ page.message }}}}</p><form method="post" action="/login"><input type="hidden" name="csrf_token" value="{{{{ page.token }}}}"><label>User <input name="user"></label><label>Password <input type="password" name="password"></label><button>Sign in</button></form></body></html>"#
    );
    let account = format!(
        r#"{LAYOUT}<h1>{{{{ page.user }}}}</h1><p>{{{{ page.message }}}}</p><form method="post" action="/account/avatar" enctype="multipart/form-data"><input type="hidden" name="csrf_token" value="{{{{ page.token }}}}"><input type="file" name="avatar"><button>Upload</button></form></body></html>"#
    );
    luminess::Engine::<Page>::builder()
        .template("home", home.as_str())
        .template("login", login.as_str())
        .template("account", account.as_str())
        .build()
        .expect("templates compile")
}

fn render(
    cx: &mut Context<'_, Visitor>,
    engine: &luminess::Engine<Page>,
    name: &str,
    message: &str,
) -> web_net::Result {
    let page = Page {
        title: "web-net example".into(),
        user: cx.identity().user.clone().unwrap_or_default(),
        token: cx.csrf_token()?,
        message: message.into(),
    };
    engine
        .render(name, &page, cx.reply_buffer())
        .map_err(|e| Error::internal("site.render").with_source(e))?;
    cx.set_header("content-type", "text/html; charset=utf-8");
    Ok(())
}

form_net::form! {
    struct Login {
        user: String,
        password: form_net::Secret,
    }
    ignore = ["csrf_token"];
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sessions: &'static Sessions = Box::leak(Box::default());
    let engine: &'static luminess::Engine<Page> = Box::leak(Box::new(engine()));
    let public = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/site");
    let uploads = std::env::temp_dir().join("web-net-example-uploads");
    std::fs::create_dir_all(&uploads)?;
    let store: &'static Store = Box::leak(Box::new(Store::in_dir(&uploads)?));
    // A real site loads a persisted key; a fresh one per start means every
    // open form fails after a restart.
    let mut key = [0u8; 32];
    OsRandom.fill(&mut key)?;

    let app = App::with_gate(sessions)
        .host("127.0.0.1:8092")
        .development()
        .sign_in("/login")
        .csrf(Csrf::new(key)?)
        .assets(Assets::new("/static", public))
        .health("/healthz")
        .route(
            get("/", |cx: &mut Context<'_, Visitor>| {
                render(cx, engine, "home", "")
            })
            .public(),
        )
        .route(
            Route::at("/login")
                .get(|cx: &mut Context<'_, Visitor>| render(cx, engine, "login", ""))
                .post(move |cx: &mut Context<'_, Visitor>| {
                    let form: Login = cx.form()?;
                    if form.user == "demo" && form.password.expose() == "demo" {
                        let sid = random_id()?;
                        if let Ok(mut m) = sessions.by_id.lock() {
                            let _ = m.insert(sid.clone(), form.user);
                        }
                        cx.set_header(
                            "set-cookie",
                            format!("sid={sid}; Path=/; HttpOnly; SameSite=Lax"),
                        );
                        return cx.redirect(303, "/");
                    }
                    cx.status(422);
                    render(cx, engine, "login", "Wrong user or password.")
                })
                .public(),
        )
        .route(
            post("/logout", move |cx: &mut Context<'_, Visitor>| {
                let id = cx.identity().id.clone();
                if let Ok(mut m) = sessions.by_id.lock() {
                    let _ = m.remove(&id);
                }
                cx.set_header("set-cookie", "sid=; Path=/; Max-Age=0");
                cx.redirect(303, "/")
            })
            .public(),
        )
        .route(
            get("/account", |cx: &mut Context<'_, Visitor>| {
                render(cx, engine, "account", "")
            })
            .allow(Rule::SignedIn),
        )
        .route(
            post("/account/avatar", move |cx: &mut Context<'_, Visitor>| {
                let upload = cx.upload(store)?;
                let n = upload.files("avatar").count();
                render(cx, engine, "account", &format!("Received {n} file(s)."))
            })
            .allow(Rule::SignedIn),
        )
        .build()?;

    println!("listening on http://127.0.0.1:8092/");
    app.listen("127.0.0.1:8092")?.wait();
    Ok(())
}
